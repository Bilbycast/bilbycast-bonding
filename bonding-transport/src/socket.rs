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

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use bonding_protocol::events::PathEvent;
use bonding_protocol::protocol::scheduler::{BondScheduler, PacketHints, PathId};
use bonding_protocol::stats::{BondConnStats, PathStats};

use crate::config::{BondSocketConfig, PathTransport};
use crate::path::{Path, PathError, UdpPath};
use crate::receiver::{ReceiverHandle, spawn_receiver};
use crate::sender::{OutboundMessage, SenderHandle, spawn_sender};

/// Capacity of the path-event broadcast channel. Events are emitted
/// only on lifecycle transitions (alive↔dead, aggregate bond state
/// crossings), so a handful at peak is typical; 64 leaves ample
/// headroom for slow subscribers without materially wasting memory.
const PATH_EVENT_CHANNEL_CAPACITY: usize = 64;

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
            events_tx.clone(),
            cancel.clone(),
        );

        Ok(Self {
            sender: Some(sender_handle),
            receiver: None,
            conn_stats,
            path_stats,
            path_ids,
            events_tx,
            cancel,
            _tasks: vec![task],
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

        let (recv_handle, task) = spawn_receiver(
            cfg.flow_id,
            paths,
            cfg.hold_time,
            conn_stats.clone(),
            path_stats.clone(),
            path_names,
            cfg.keepalive_interval,
            cfg.keepalive_miss_threshold,
            events_tx.clone(),
            cancel.clone(),
            cfg.nack_delay,
            cfg.max_nack_retries,
        );

        Ok(Self {
            sender: None,
            receiver: Some(Mutex::new(recv_handle)),
            conn_stats,
            path_stats,
            path_ids,
            events_tx,
            cancel,
            _tasks: vec![task],
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
    for p in &cfg.paths {
        let path = build_one_path(p, sender_mode).await?;
        stats.push(PathStats::new());
        ids.push(p.id);
        names.push(p.name.clone());
        paths.push(path);
    }
    Ok((paths, stats, ids, names))
}

async fn build_one_path(
    p: &crate::config::PathConfig,
    sender_mode: bool,
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
                    UdpPath::bind(p.id, p.name.clone(), *b, *remote, iface).await?
                }
                (None, Some(r), true) => {
                    UdpPath::bind_ephemeral(p.id, p.name.clone(), *r, iface).await?
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
                    QuicPath::client(p.id, p.name.clone(), *addr, server_name, tls_inner).await?
                }
                QuicRole::Server => {
                    QuicPath::server(p.id, p.name.clone(), *addr, tls_inner).await?
                }
            };
            let _ = sender_mode;
            Ok(Path::Quic(qp))
        }
    }
}
