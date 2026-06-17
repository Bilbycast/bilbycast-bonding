//! Public `BondSocket` API.
//!
//! Mirrors the shape of `rist_transport::RistSocket` so consumers
//! that already integrate RIST can treat bonding the same way:
//!
//! ```ignore
//! let socket = BondSocket::sender(cfg, scheduler).await?;
//! socket.send(data, hints).await?;
//!
//! let mut socket = BondSocket::receiver(cfg).await?;
//! while let Some(payload) = socket.recv().await { /* ... */ }
//! ```
//!
//! The sender takes any `BondScheduler` impl — the caller owns
//! scheduling policy. Edge's media-aware scheduler, a
//! `RoundRobinScheduler`, a `WeightedRttScheduler`, or a custom one
//! for a specific field deployment all plug in identically.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use bonding_protocol::events::{PathEvent, PathEventKind, PathRebuildReason};
use bonding_protocol::protocol::scheduler::{BondScheduler, PacketHints, PathId};
use bonding_protocol::stats::{BondConnStats, PathStats};

use crate::config::{BondSocketConfig, PathTransport};
use crate::crypto::BondCrypto;
use crate::path::{Path, PathError, UdpPath, UdpWatchHandle, WatchTarget};
use crate::receiver::{ReceiverHandle, spawn_receiver};
use crate::sender::{OutboundMessage, SenderHandle, spawn_sender};

/// Capacity of the path-event broadcast channel. Events are emitted
/// only on lifecycle transitions (alive↔dead, aggregate bond state
/// crossings), so a handful at peak is typical; 64 leaves ample
/// headroom for slow subscribers without materially wasting memory.
const PATH_EVENT_CHANNEL_CAPACITY: usize = 64;

/// Interface-watcher cadence. Churn (USB-dongle re-plug, NIC
/// re-enumeration, DHCP renumber) is detected within one tick; the
/// per-tick cost is one name→index syscall or one throwaway local
/// bind per watched path.
const WATCHER_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum BondSocketError {
    #[error("path error: {0}")]
    Path(#[from] PathError),
    #[error("no paths configured")]
    NoPaths,
    #[error("socket is not in sender mode")]
    NotSender,
    #[error("socket is not in receiver mode")]
    NotReceiver,
    #[error("send channel closed")]
    SendClosed,
    #[error("path transport `{0}` not implemented in phase 2")]
    UnimplementedTransport(&'static str),
}

pub type BondResult<T> = std::result::Result<T, BondSocketError>;

pub struct BondSocket {
    sender: Option<SenderHandle>,
    receiver: Option<Mutex<ReceiverHandle>>,
    conn_stats: Arc<BondConnStats>,
    path_stats: Vec<Arc<PathStats>>,
    path_ids: Vec<PathId>,
    /// Rebuild/watch handles for UDP paths (paired with their stats).
    /// Survive the move of the `Path`s into the sender/receiver task
    /// so the interface watcher and `rebuild_udp_path` can reach them.
    udp_handles: Vec<(UdpWatchHandle, Arc<PathStats>)>,
    events_tx: broadcast::Sender<PathEvent>,
    cancel: CancellationToken,
    _tasks: Vec<JoinHandle<()>>,
}

impl BondSocket {
    /// Create a sender socket that transmits bonded packets across
    /// all configured paths using the supplied scheduler.
    pub async fn sender<S>(cfg: BondSocketConfig, scheduler: S) -> BondResult<Self>
    where
        S: BondScheduler + Send + 'static,
    {
        if cfg.paths.is_empty() {
            return Err(BondSocketError::NoPaths);
        }
        let (paths, path_stats, path_ids, path_names) = build_paths(&cfg, true).await?;
        let conn_stats = BondConnStats::new();
        let cancel = CancellationToken::new();
        let (events_tx, _) = broadcast::channel(PATH_EVENT_CHANNEL_CAPACITY);

        let udp_handles = collect_udp_handles(&paths, &path_stats);

        let (sender_handle, task) = spawn_sender(
            cfg.flow_id,
            paths,
            scheduler,
            conn_stats.clone(),
            path_stats.clone(),
            path_names,
            cfg.keepalive_interval,
            cfg.keepalive_miss_threshold,
            cfg.retransmit_capacity,
            cfg.fec,
            events_tx.clone(),
            cancel.clone(),
        );
        let mut tasks = vec![task];
        if let Some(w) = spawn_interface_watcher(&udp_handles, events_tx.clone(), cancel.clone()) {
            tasks.push(w);
        }

        Ok(Self {
            sender: Some(sender_handle),
            receiver: None,
            conn_stats,
            path_stats,
            path_ids,
            udp_handles,
            events_tx,
            cancel,
            _tasks: tasks,
        })
    }

    /// Create a receiver socket listening on all configured paths.
    pub async fn receiver(cfg: BondSocketConfig) -> BondResult<Self> {
        if cfg.paths.is_empty() {
            return Err(BondSocketError::NoPaths);
        }
        let (paths, path_stats, path_ids, path_names) = build_paths(&cfg, false).await?;
        let conn_stats = BondConnStats::new();
        let cancel = CancellationToken::new();
        let (events_tx, _) = broadcast::channel(PATH_EVENT_CHANNEL_CAPACITY);

        let udp_handles = collect_udp_handles(&paths, &path_stats);

        let (recv_handle, task) = spawn_receiver(
            cfg.flow_id,
            paths,
            cfg.hold_time,
            cfg.hold_max,
            conn_stats.clone(),
            path_stats.clone(),
            path_names,
            cfg.keepalive_interval,
            cfg.keepalive_miss_threshold,
            events_tx.clone(),
            cancel.clone(),
            cfg.nack_delay,
            cfg.max_nack_retries,
            cfg.fec,
        );
        let mut tasks = vec![task];
        if let Some(w) = spawn_interface_watcher(&udp_handles, events_tx.clone(), cancel.clone()) {
            tasks.push(w);
        }

        Ok(Self {
            sender: None,
            receiver: Some(Mutex::new(recv_handle)),
            conn_stats,
            path_stats,
            path_ids,
            udp_handles,
            events_tx,
            cancel,
            _tasks: tasks,
        })
    }

    /// Queue `data` for transmission with the supplied scheduling
    /// hints. The underlying send is async and may apply back-pressure
    /// if the scheduler queue fills.
    pub async fn send(&self, data: Bytes, hints: PacketHints) -> BondResult<()> {
        let sender = self.sender.as_ref().ok_or(BondSocketError::NotSender)?;
        sender
            .tx
            .send(OutboundMessage { data, hints })
            .await
            .map_err(|_| BondSocketError::SendClosed)
    }

    /// Receive the next bonded payload in bond-seq order. Returns
    /// `None` when the socket is being shut down.
    pub async fn recv(&self) -> Option<Bytes> {
        let recv = self.receiver.as_ref()?;
        let mut guard = recv.lock().await;
        guard.rx.recv().await
    }

    /// Aggregate connection-level stats.
    pub fn stats(&self) -> Arc<BondConnStats> {
        self.conn_stats.clone()
    }

    /// Per-path stats handle for path `id`. Returns None if no such
    /// path is registered.
    pub fn path_stats(&self, id: PathId) -> Option<Arc<PathStats>> {
        self.path_ids
            .iter()
            .position(|p| *p == id)
            .and_then(|i| self.path_stats.get(i).cloned())
    }

    /// All registered path IDs.
    pub fn path_ids(&self) -> &[PathId] {
        &self.path_ids
    }

    /// Subscribe to the bonding lifecycle event stream.
    ///
    /// Events are emitted once per transition — path alive ↔ dead,
    /// bond aggregate up ↔ degraded ↔ down. No periodic ticks, so
    /// a subscriber that misses an event by lagging (the broadcast
    /// channel drops old items under pressure) should reconcile by
    /// inspecting [`PathStats::dead`] afterwards.
    pub fn subscribe_events(&self) -> broadcast::Receiver<PathEvent> {
        self.events_tx.subscribe()
    }

    /// Force an in-place socket rebuild on a UDP path. Operator /
    /// test surface — the interface watcher and the sender's
    /// send-error trigger run the same machinery automatically.
    /// Bumps the path's `rebuilds` counter; emits no `PathRebuilt`
    /// event (the event reasons are reserved for automatic
    /// triggers). Errors for unknown / non-UDP paths and on bind
    /// failure (the old socket stays in place).
    pub fn rebuild_udp_path(&self, id: PathId) -> BondResult<()> {
        let Some((h, ps)) = self.udp_handles.iter().find(|(h, _)| h.path_id == id) else {
            return Err(BondSocketError::Path(PathError::Other(format!(
                "path {id} is not a rebuildable UDP path"
            ))));
        };
        match h.rebuilder.try_rebuild(Duration::ZERO) {
            Some(Ok(())) => {
                note_rebuilt(ps, h);
                Ok(())
            }
            Some(Err(e)) => Err(BondSocketError::Path(e)),
            // Another rebuild is in flight — the socket is being
            // replaced either way.
            None => Ok(()),
        }
    }

    /// Signal shutdown. Background tasks observe the cancel token
    /// and exit cleanly.
    pub fn close(&self) {
        self.cancel.cancel();
    }
}

impl Drop for BondSocket {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn build_paths(
    cfg: &BondSocketConfig,
    sender_mode: bool,
) -> BondResult<(Vec<Path>, Vec<Arc<PathStats>>, Vec<PathId>, Vec<String>)> {
    let mut paths = Vec::with_capacity(cfg.paths.len());
    let mut stats = Vec::with_capacity(cfg.paths.len());
    let mut ids = Vec::with_capacity(cfg.paths.len());
    let mut names = Vec::with_capacity(cfg.paths.len());
    // Build the AEAD once and share it across every path on this bond.
    let crypto = match &cfg.encryption_key {
        Some(key) => Some(BondCrypto::new(key).map_err(|e| {
            BondSocketError::Path(PathError::Other(format!("bond encryption key: {e}")))
        })?),
        None => None,
    };
    for p in &cfg.paths {
        let path = build_one_path(p, sender_mode, crypto.clone()).await?;
        let ps = PathStats::new();
        // Record which NIC-pin mechanism (if any) actually bound this
        // path so the resolved value reaches telemetry.
        let code = path
            .pin_mechanism()
            .map(|m| m.stats_code())
            .unwrap_or(bonding_protocol::stats::PIN_NONE);
        ps.pin_mechanism
            .store(code, std::sync::atomic::Ordering::Relaxed);
        stats.push(ps);
        ids.push(p.id);
        names.push(p.name.clone());
        paths.push(path);
    }
    Ok((paths, stats, ids, names))
}

/// Pair every UDP path's rebuild/watch handle with its stats slot.
/// `paths` and `path_stats` are index-aligned by construction.
fn collect_udp_handles(
    paths: &[Path],
    path_stats: &[Arc<PathStats>],
) -> Vec<(UdpWatchHandle, Arc<PathStats>)> {
    paths
        .iter()
        .zip(path_stats.iter())
        .filter_map(|(p, ps)| p.udp_watch_handle().map(|h| (h, ps.clone())))
        .collect()
}

/// Mirror a completed socket rebuild into the path's telemetry: bump
/// the counter and refresh the pin-mechanism code (the mechanism can
/// differ across rebuilds — e.g. CAP_NET_RAW granted since startup).
fn note_rebuilt(ps: &PathStats, h: &UdpWatchHandle) {
    ps.rebuilds
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let code = h
        .rebuilder
        .pin_mechanism()
        .map(|m| m.stats_code())
        .unwrap_or(bonding_protocol::stats::PIN_NONE);
    ps.pin_mechanism
        .store(code, std::sync::atomic::Ordering::Relaxed);
}

// ─── Interface watcher (UDP paths only) ──────────────────────────
//
// NIC pins capture the ifindex at socket creation; gateway-mode
// routes are programmed at flow start. A USB-dongle re-plug, NIC
// re-enumeration (ifindex change) or DHCP renumber therefore kills
// the leg permanently without intervention — plain link-flap on the
// SAME ifindex already self-heals via keepalive liveness and needs
// no rebuild. The watcher polls every watched path each
// `WATCHER_INTERVAL` and rebuilds the socket when the target
// vanishes-and-returns or changes index. QUIC / RIST legs manage
// their own connections and are not watched.

/// Watcher decision for one path on one tick. Pure function of the
/// resolved target state so it is unit-testable without real NICs;
/// `resolved` comes from an injectable lookup ([`resolve_watch_target`]
/// in production).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchVerdict {
    NoChange,
    /// Target vanished — emit `InterfaceLost` once, keep polling.
    Lost,
    Rebuild(PathRebuildReason),
}

fn watch_verdict(resolved: Option<u32>, bound_ifindex: u32, was_absent: bool) -> WatchVerdict {
    match resolved {
        None if was_absent => WatchVerdict::NoChange,
        None => WatchVerdict::Lost,
        Some(_) if was_absent => WatchVerdict::Rebuild(PathRebuildReason::InterfaceRestored),
        // The index comparison only applies when the build recorded
        // one (interface-pinned paths). Source-IP targets resolve to
        // a synthetic 0 and bind with bound_ifindex 0 — presence is
        // their only signal.
        Some(idx) if bound_ifindex != 0 && idx != bound_ifindex => {
            WatchVerdict::Rebuild(PathRebuildReason::InterfaceChanged)
        }
        Some(_) => WatchVerdict::NoChange,
    }
}

/// Production lookup: name → current ifindex for interface pins;
/// presence (as synthetic index 0) for source-bound paths.
fn resolve_watch_target(target: &WatchTarget) -> Option<u32> {
    match target {
        WatchTarget::Interface(name) => crate::path::udp::resolve_ifindex(name),
        WatchTarget::SourceIp(ip) => crate::path::udp::source_ip_present(*ip).then_some(0),
    }
}

/// Spawn the per-bond watcher over every UDP path that has an
/// interface pin or a specific source bind. `None` when nothing
/// needs watching (no task spawned).
fn spawn_interface_watcher(
    handles: &[(UdpWatchHandle, Arc<PathStats>)],
    events_tx: broadcast::Sender<PathEvent>,
    cancel: CancellationToken,
) -> Option<JoinHandle<()>> {
    let entries: Vec<(UdpWatchHandle, Arc<PathStats>)> = handles
        .iter()
        .filter(|(h, _)| h.target.is_some())
        .cloned()
        .collect();
    if entries.is_empty() {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut absent: Vec<bool> = vec![false; entries.len()];
        let mut tick = tokio::time::interval(WATCHER_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Swallow the immediate first tick; it fires at t=0.
        tick.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tick.tick() => {}
            }
            for (i, (h, ps)) in entries.iter().enumerate() {
                let Some(target) = &h.target else { continue };
                let resolved = resolve_watch_target(target);
                match watch_verdict(resolved, h.rebuilder.bound_ifindex(), absent[i]) {
                    WatchVerdict::NoChange => {}
                    WatchVerdict::Lost => {
                        absent[i] = true;
                        log::warn!(
                            "bond path '{}': watch target {target:?} disappeared",
                            h.name
                        );
                        let _ = events_tx.send(PathEvent {
                            path_id: h.path_id,
                            path_name: h.name.clone(),
                            kind: PathEventKind::InterfaceLost,
                        });
                    }
                    WatchVerdict::Rebuild(reason) => {
                        // The tick cadence is the rate limit here;
                        // zero min-interval so a recent send-error
                        // rebuild can't starve an interface-change
                        // rebuild.
                        match h.rebuilder.try_rebuild(Duration::ZERO) {
                            Some(Ok(())) => {
                                absent[i] = false;
                                note_rebuilt(ps, h);
                                log::info!(
                                    "bond path '{}': socket rebuilt ({})",
                                    h.name,
                                    reason.as_str()
                                );
                                let _ = events_tx.send(PathEvent {
                                    path_id: h.path_id,
                                    path_name: h.name.clone(),
                                    kind: PathEventKind::PathRebuilt { reason },
                                });
                            }
                            Some(Err(e)) => {
                                // State unchanged so the next tick
                                // retries: Restored stays absent;
                                // Changed re-detects the mismatch
                                // (bound_ifindex only moves on a
                                // successful rebuild).
                                log::warn!(
                                    "bond path '{}': socket rebuild failed ({}): {e}",
                                    h.name,
                                    reason.as_str()
                                );
                            }
                            None => {} // rebuild already in flight
                        }
                    }
                }
            }
        }
    }))
}

async fn build_one_path(
    p: &crate::config::PathConfig,
    sender_mode: bool,
    crypto: Option<std::sync::Arc<BondCrypto>>,
) -> BondResult<Path> {
    match &p.transport {
        PathTransport::Udp {
            bind,
            remote,
            interface,
        } => {
            let iface = interface.as_deref();
            let udp = match (bind, remote, sender_mode) {
                (Some(b), _, _) => {
                    UdpPath::bind(p.id, p.name.clone(), *b, *remote, iface, crypto.clone()).await?
                }
                (None, Some(r), true) => {
                    UdpPath::bind_ephemeral(p.id, p.name.clone(), *r, iface, crypto.clone()).await?
                }
                (None, _, false) => {
                    return Err(BondSocketError::Path(PathError::Other(
                        "receiver-mode UDP path requires an explicit bind address".into(),
                    )));
                }
                (None, None, true) => {
                    return Err(BondSocketError::Path(PathError::Other(
                        "sender-mode UDP path requires at least a remote or bind address".into(),
                    )));
                }
            };
            Ok(Path::Udp(udp))
        }
        #[cfg(feature = "path-rist")]
        PathTransport::Rist {
            role,
            remote,
            local_bind,
            buffer_ms,
        } => {
            use crate::config::RistRole;
            use crate::path::RistPath;
            let rp = match role {
                RistRole::Sender => {
                    let r = remote.ok_or_else(|| {
                        BondSocketError::Path(PathError::Other(
                            "RIST sender role requires `remote`".into(),
                        ))
                    })?;
                    RistPath::sender(p.id, p.name.clone(), r, *local_bind, *buffer_ms).await?
                }
                RistRole::Receiver => {
                    let b = local_bind.ok_or_else(|| {
                        BondSocketError::Path(PathError::Other(
                            "RIST receiver role requires `local_bind`".into(),
                        ))
                    })?;
                    RistPath::receiver(p.id, p.name.clone(), b, *buffer_ms).await?
                }
            };
            let _ = sender_mode; // RIST role is self-contained
            Ok(Path::Rist(rp))
        }
        #[cfg(feature = "path-quic")]
        PathTransport::Quic {
            role,
            addr,
            server_name,
            tls,
            bind,
            interface,
        } => {
            use crate::config::{QuicRole, QuicTlsMode};
            use crate::path::quic::QuicTls;
            use crate::path::QuicPath;
            let tls_inner = match tls {
                QuicTlsMode::SelfSigned => QuicTls::SelfSigned,
                QuicTlsMode::Pem {
                    cert_chain,
                    private_key,
                    client_trust_root,
                } => QuicTls::Pem {
                    cert_chain: cert_chain.clone(),
                    private_key: private_key.clone(),
                    client_trust_root: client_trust_root.clone(),
                },
            };
            let qp = match role {
                QuicRole::Client => {
                    QuicPath::client(
                        p.id,
                        p.name.clone(),
                        *addr,
                        server_name,
                        tls_inner,
                        *bind,
                        interface.as_deref(),
                    )
                    .await?
                }
                QuicRole::Server => {
                    QuicPath::server(
                        p.id,
                        p.name.clone(),
                        *addr,
                        tls_inner,
                        interface.as_deref(),
                    )
                    .await?
                }
            };
            let _ = sender_mode;
            Ok(Path::Quic(qp))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Mimics the watcher loop's per-path state handling around the
    /// pure `watch_verdict`: `absent` set on Lost, cleared on a
    /// (simulated-successful) rebuild, which also adopts the new
    /// ifindex — exactly what `UdpRebuilder::try_rebuild` records.
    struct Sim {
        bound: u32,
        absent: bool,
    }

    impl Sim {
        fn new(bound: u32) -> Self {
            Self {
                bound,
                absent: false,
            }
        }

        fn tick(&mut self, resolved: Option<u32>) -> WatchVerdict {
            let v = watch_verdict(resolved, self.bound, self.absent);
            match v {
                WatchVerdict::Lost => self.absent = true,
                WatchVerdict::Rebuild(_) => {
                    self.absent = false;
                    if let Some(idx) = resolved {
                        self.bound = idx;
                    }
                }
                WatchVerdict::NoChange => {}
            }
            v
        }
    }

    /// Injected ifindex map standing in for the kernel's name→index
    /// table — the watcher decision logic never touches a real NIC.
    fn lookup(map: &HashMap<&str, u32>, name: &str) -> Option<u32> {
        map.get(name).copied()
    }

    #[test]
    fn interface_gone_emits_lost_once_then_keeps_polling() {
        let mut map: HashMap<&str, u32> = HashMap::from([("wwan0", 5)]);
        let mut sim = Sim::new(5);
        assert_eq!(sim.tick(lookup(&map, "wwan0")), WatchVerdict::NoChange);
        map.remove("wwan0");
        assert_eq!(sim.tick(lookup(&map, "wwan0")), WatchVerdict::Lost);
        // Still gone — no repeat event.
        assert_eq!(sim.tick(lookup(&map, "wwan0")), WatchVerdict::NoChange);
        assert_eq!(sim.tick(lookup(&map, "wwan0")), WatchVerdict::NoChange);
    }

    #[test]
    fn ifindex_change_triggers_rebuild() {
        // USB re-plug: same name, new index — no absence observed
        // between ticks.
        let mut map: HashMap<&str, u32> = HashMap::from([("wwan0", 5)]);
        let mut sim = Sim::new(5);
        assert_eq!(sim.tick(lookup(&map, "wwan0")), WatchVerdict::NoChange);
        map.insert("wwan0", 9);
        assert_eq!(
            sim.tick(lookup(&map, "wwan0")),
            WatchVerdict::Rebuild(PathRebuildReason::InterfaceChanged)
        );
        // Rebuild adopted index 9 — steady state again.
        assert_eq!(sim.tick(lookup(&map, "wwan0")), WatchVerdict::NoChange);
    }

    #[test]
    fn interface_restored_triggers_rebuild() {
        let mut map: HashMap<&str, u32> = HashMap::from([("wwan0", 5)]);
        let mut sim = Sim::new(5);
        map.remove("wwan0");
        assert_eq!(sim.tick(lookup(&map, "wwan0")), WatchVerdict::Lost);
        // Re-plug lands on a new index; restoration wins regardless.
        map.insert("wwan0", 7);
        assert_eq!(
            sim.tick(lookup(&map, "wwan0")),
            WatchVerdict::Rebuild(PathRebuildReason::InterfaceRestored)
        );
        assert_eq!(sim.tick(lookup(&map, "wwan0")), WatchVerdict::NoChange);
    }

    #[test]
    fn source_ip_target_presence_only() {
        // Source-IP targets: synthetic index 0, bound 0 — only the
        // gone/restored transitions can fire, never InterfaceChanged.
        let mut sim = Sim::new(0);
        assert_eq!(sim.tick(Some(0)), WatchVerdict::NoChange);
        assert_eq!(sim.tick(None), WatchVerdict::Lost);
        assert_eq!(sim.tick(None), WatchVerdict::NoChange);
        assert_eq!(
            sim.tick(Some(0)),
            WatchVerdict::Rebuild(PathRebuildReason::InterfaceRestored)
        );
        assert_eq!(sim.tick(Some(0)), WatchVerdict::NoChange);
    }
}
