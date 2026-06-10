//! UDP path adapter.
//!
//! A [`UdpPath`] wraps a single `tokio::net::UdpSocket`. On the
//! sender side the socket is bound locally (ephemeral port if
//! unspecified) and has a primary remote peer configured; on the
//! receiver side the socket is bound to a known local port and
//! learns the sender's address from the first inbound packet.
//!
//! Each path owns a long-running receive loop that reads datagrams
//! into a bounded `mpsc` channel. The sender / receiver tasks
//! higher up read from that channel, parse either the bond data
//! header (`0xBC`) or the control header (`0xBE`), and dispatch.
//!
//! Lock-free on the hot path: the receive loop calls
//! `socket.recv_from` directly (zero copies before the `Bytes`
//! clone), and outbound `send_to` skips the channel layer entirely
//! so the scheduler's decision hits the wire with a single syscall
//! per packet.
//!
//! ## Interface-churn recovery (UDP paths only)
//!
//! `SO_BINDTODEVICE` / `IP_UNICAST_IF` capture the **ifindex** at
//! socket creation. A USB-dongle re-plug, NIC re-enumeration or DHCP
//! renumber leaves the socket pinned to a dead index — packets
//! blackhole until the socket is rebuilt. The build parameters live
//! in a shared [`UdpRebuilder`]; a rebuild re-creates + re-pins the
//! socket and swaps it in via lock-free `ArcSwap`. The recv loop
//! reads on the current snapshot with a bounded timeout
//! ([`SOCKET_SWAP_POLL`]) so a swap is picked up within ~100 ms
//! without poll-spinning. QUIC / RIST legs manage their own
//! connections and are never rebuilt here.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use socket2::{Domain, Protocol as SockProto, Socket as Sock2, Type};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use bonding_protocol::protocol::scheduler::PathId;

use crate::crypto::BondCrypto;

use super::{PathDatagram, PathError, PathResult};

/// Default socket buffer sizes (2 MB). The kernel may cap these but
/// requesting large buffers matters for high-bitrate media on
/// congested links.
const DEFAULT_SOCK_BUF: usize = 2 * 1024 * 1024;

/// Maximum UDP datagram we'll accept.
const MAX_DATAGRAM: usize = 2048;

/// Upper bound on how long the recv loop reads a stale socket
/// snapshot after a rebuild swap.
const SOCKET_SWAP_POLL: Duration = Duration::from_millis(100);

/// Consecutive route/device send errors before the sender-side
/// trigger rebuilds the socket.
const SEND_ERR_REBUILD_THRESHOLD: u64 = 50;

/// Minimum spacing between send-error-triggered rebuild attempts.
const SEND_ERR_REBUILD_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Cap on the send-error rebuild backoff exponent: spacing doubles per
/// rebuild that fails to clear the error run, up to
/// `SEND_ERR_REBUILD_MIN_INTERVAL << SEND_ERR_REBUILD_MAX_BACKOFF_EXP`
/// (64 s). A rebuild fixes socket-level staleness (stale ifindex pin,
/// vanished bind address), not a dead next-hop — EHOSTUNREACH /
/// ENETUNREACH persist across rebuilds, and without backoff a downed
/// gateway costs one pointless rebuild (fresh ephemeral source port =
/// NAT-mapping churn) plus one `PathRebuilt` warning per interval,
/// indefinitely. Any successful send resets the exponent.
const SEND_ERR_REBUILD_MAX_BACKOFF_EXP: u32 = 6;

/// Which kernel primitive actually pinned this path's egress to the
/// requested NIC. Surfaced so telemetry can show whether a path got
/// the hard device bind or the unprivileged egress hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMechanism {
    /// `SO_BINDTODEVICE` (Linux/Android) — hard TX+RX bind to the
    /// device. Needs `CAP_NET_RAW`.
    SoBindToDevice,
    /// `IP_UNICAST_IF` / `IPV6_UNICAST_IF` — unprivileged per-socket
    /// egress interface hint. Used as the automatic fallback when
    /// `SO_BINDTODEVICE` is denied (no `CAP_NET_RAW`). TX-only: it
    /// steers the route lookup but does not hard-bind receive.
    UnicastIf,
    /// `IP_BOUND_IF` / `IPV6_BOUND_IF` (Apple / *BSD / Fuchsia) —
    /// unprivileged device bind.
    BoundIf,
}

impl PinMechanism {
    /// Stable lowercase label for stats / Prometheus.
    pub fn as_str(&self) -> &'static str {
        match self {
            PinMechanism::SoBindToDevice => "so_bindtodevice",
            PinMechanism::UnicastIf => "ip_unicast_if",
            PinMechanism::BoundIf => "ip_bound_if",
        }
    }

    /// `bonding_protocol::stats::PIN_*` code for this mechanism.
    pub fn stats_code(self) -> u64 {
        match self {
            PinMechanism::SoBindToDevice => bonding_protocol::stats::PIN_SO_BINDTODEVICE,
            PinMechanism::UnicastIf => bonding_protocol::stats::PIN_IP_UNICAST_IF,
            PinMechanism::BoundIf => bonding_protocol::stats::PIN_IP_BOUND_IF,
        }
    }

    fn from_stats_code(code: u64) -> Option<Self> {
        match code {
            bonding_protocol::stats::PIN_SO_BINDTODEVICE => Some(PinMechanism::SoBindToDevice),
            bonding_protocol::stats::PIN_IP_UNICAST_IF => Some(PinMechanism::UnicastIf),
            bonding_protocol::stats::PIN_IP_BOUND_IF => Some(PinMechanism::BoundIf),
            _ => None,
        }
    }
}

/// What the per-bond interface watcher polls for a UDP path.
#[derive(Debug, Clone)]
pub(crate) enum WatchTarget {
    /// `interface`-pinned path — watch the name → ifindex mapping
    /// (gone / changed / returned).
    Interface(String),
    /// Source-bound path (specific local IP, no interface pin) —
    /// watch the address's presence (DHCP renumber, device gone).
    SourceIp(IpAddr),
}

/// Per-path handle the bond keeps after the `Path` itself moves into
/// the sender / receiver task: rebuild state plus the watch target
/// derived from the path's config.
#[derive(Clone)]
pub(crate) struct UdpWatchHandle {
    pub(crate) path_id: PathId,
    pub(crate) name: String,
    /// `None` = nothing to watch (wildcard bind, no interface pin);
    /// the path still supports manual / send-error rebuilds.
    pub(crate) target: Option<WatchTarget>,
    pub(crate) rebuilder: Arc<UdpRebuilder>,
}

/// Shared, lock-free rebuild state for one UDP path: the swappable
/// socket plus the build parameters needed to re-create it. Shared
/// between the `UdpPath` handle, its recv loop, the per-bond
/// interface watcher and the sender's send-error trigger.
pub(crate) struct UdpRebuilder {
    /// Original *requested* bind. Port 0 (sender-mode) takes a fresh
    /// ephemeral port on every rebuild; receiver-mode re-binds its
    /// configured port (`SO_REUSEADDR` covers the ≤100 ms window in
    /// which the recv loop still holds the old snapshot).
    local: SocketAddr,
    interface: Option<String>,
    socket: ArcSwap<UdpSocket>,
    /// `PIN_*` code of the mechanism on the CURRENT socket — can
    /// differ across rebuilds (capability granted/revoked between).
    pin_code: AtomicU64,
    /// ifindex the current socket pinned to (0 = unpinned/unknown).
    bound_ifindex: AtomicU64,
    /// Successful rebuilds. Mirrored into `PathStats.rebuilds` by the
    /// caller that triggered the rebuild.
    rebuilds: AtomicU64,
    /// Consecutive route/device send errors (sender-side trigger).
    consec_send_errs: AtomicU64,
    /// Send-error rebuilds since the last successful send — the
    /// backoff exponent for [`SEND_ERR_REBUILD_MIN_INTERVAL`] (capped
    /// at [`SEND_ERR_REBUILD_MAX_BACKOFF_EXP`]). Nonzero means the
    /// last rebuild did not clear the error run.
    send_rebuild_backoff: AtomicU64,
    /// Single-flight gate — watcher and sender trigger may race.
    rebuild_gate: AtomicBool,
    /// Milliseconds since `created` of the last rebuild *attempt*
    /// (success or failure); `u64::MAX` = never attempted.
    last_attempt_ms: AtomicU64,
    created: Instant,
}

impl UdpRebuilder {
    /// Initial build. Same socket recipe as every rebuild.
    fn create(local: SocketAddr, interface: Option<&str>) -> PathResult<Arc<Self>> {
        let (socket, pin, ifindex) = build_socket(local, interface)?;
        Ok(Arc::new(Self {
            local,
            interface: interface.map(str::to_owned),
            socket: ArcSwap::from(socket),
            pin_code: AtomicU64::new(
                pin.map(PinMechanism::stats_code)
                    .unwrap_or(bonding_protocol::stats::PIN_NONE),
            ),
            bound_ifindex: AtomicU64::new(ifindex as u64),
            rebuilds: AtomicU64::new(0),
            consec_send_errs: AtomicU64::new(0),
            send_rebuild_backoff: AtomicU64::new(0),
            rebuild_gate: AtomicBool::new(false),
            last_attempt_ms: AtomicU64::new(u64::MAX),
            created: Instant::now(),
        }))
    }

    /// Current socket snapshot. One refcount bump per call — cheap
    /// and lock-free; the UDP syscall dominates.
    #[inline]
    pub(crate) fn current(&self) -> Arc<UdpSocket> {
        self.socket.load_full()
    }

    pub(crate) fn pin_mechanism(&self) -> Option<PinMechanism> {
        PinMechanism::from_stats_code(self.pin_code.load(Ordering::Relaxed))
    }

    pub(crate) fn bound_ifindex(&self) -> u32 {
        self.bound_ifindex.load(Ordering::Relaxed) as u32
    }

    pub(crate) fn rebuild_count(&self) -> u64 {
        self.rebuilds.load(Ordering::Relaxed)
    }

    /// Re-create + re-pin the socket from the stored parameters and
    /// swap it in atomically. Must run inside a tokio runtime (the
    /// new socket registers with the reactor).
    ///
    /// `None` = skipped (another rebuild in flight, or the last
    /// attempt was less than `min_interval` ago). `Some(Ok)` = the
    /// new socket is live; the recv loop picks it up within
    /// [`SOCKET_SWAP_POLL`]. `Some(Err)` = build failed, the old
    /// socket stays in place and the caller may retry later.
    pub(crate) fn try_rebuild(&self, min_interval: Duration) -> Option<PathResult<()>> {
        if self.rebuild_gate.swap(true, Ordering::AcqRel) {
            return None;
        }
        let now_ms = self.created.elapsed().as_millis() as u64;
        let last = self.last_attempt_ms.load(Ordering::Relaxed);
        if last != u64::MAX && now_ms.saturating_sub(last) < min_interval.as_millis() as u64 {
            self.rebuild_gate.store(false, Ordering::Release);
            return None;
        }
        self.last_attempt_ms.store(now_ms, Ordering::Relaxed);
        let result = match build_socket(self.local, self.interface.as_deref()) {
            Ok((socket, pin, ifindex)) => {
                self.socket.store(socket);
                self.pin_code.store(
                    pin.map(PinMechanism::stats_code)
                        .unwrap_or(bonding_protocol::stats::PIN_NONE),
                    Ordering::Relaxed,
                );
                self.bound_ifindex.store(ifindex as u64, Ordering::Relaxed);
                self.rebuilds.fetch_add(1, Ordering::Relaxed);
                self.consec_send_errs.store(0, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(e),
        };
        self.rebuild_gate.store(false, Ordering::Release);
        Some(result)
    }

    /// Hot-path bookkeeping: clear the consecutive-error run (and the
    /// rebuild backoff — a delivered packet proves the leg works
    /// again). Loads first so the common case is two relaxed reads.
    #[inline]
    fn note_send_ok(&self) {
        if self.consec_send_errs.load(Ordering::Relaxed) != 0 {
            self.consec_send_errs.store(0, Ordering::Relaxed);
        }
        if self.send_rebuild_backoff.load(Ordering::Relaxed) != 0 {
            self.send_rebuild_backoff.store(0, Ordering::Relaxed);
        }
    }

    /// Classify a send error; at [`SEND_ERR_REBUILD_THRESHOLD`]
    /// consecutive route/device errors, rebuild — rate-limited to one
    /// attempt per [`SEND_ERR_REBUILD_MIN_INTERVAL`], doubling per
    /// rebuild that failed to clear the run (see
    /// [`SEND_ERR_REBUILD_MAX_BACKOFF_EXP`]). Returns `true` when a
    /// rebuild was performed. A non-route error breaks the run —
    /// "consecutive" means an unbroken run of the listed errnos.
    fn note_send_error(&self, err: &PathError) -> bool {
        let route_err = match err {
            PathError::Send(io) => is_route_errno(io),
            _ => false,
        };
        if !route_err {
            self.note_send_ok();
            return false;
        }
        let run = self.consec_send_errs.fetch_add(1, Ordering::Relaxed) + 1;
        if run < SEND_ERR_REBUILD_THRESHOLD {
            return false;
        }
        let exp = (self.send_rebuild_backoff.load(Ordering::Relaxed) as u32)
            .min(SEND_ERR_REBUILD_MAX_BACKOFF_EXP);
        match self.try_rebuild(SEND_ERR_REBUILD_MIN_INTERVAL * (1u32 << exp)) {
            Some(Ok(())) => {
                self.send_rebuild_backoff.fetch_add(1, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }
}

pub struct UdpPath {
    id: PathId,
    name: String,
    /// Swappable socket + rebuild parameters (see module docs).
    shared: Arc<UdpRebuilder>,
    primary_peer: Arc<Mutex<Option<SocketAddr>>>,
    /// Cached copy of the primary peer as a pair of atomics for the
    /// send hot path — avoids taking the Mutex on every
    /// outbound packet. Stored as raw IPv6-mapped u128 + port u16
    /// packed into two AtomicU64.
    primary_ip_hi: AtomicU64,
    primary_ip_lo: AtomicU64,
    primary_port: AtomicU64, // high bit = set flag
    rx: Mutex<Option<mpsc::Receiver<PathDatagram>>>,
    /// Optional AEAD — when set, every outbound datagram is sealed and
    /// every inbound datagram is opened (and dropped on auth failure).
    crypto: Option<Arc<BondCrypto>>,
    _recv_task: tokio::task::JoinHandle<()>,
    _cancel: CancellationToken,
}

impl UdpPath {
    /// Build a path with an explicit bind address. Used when the
    /// caller needs to pin the local port (receiver mode) or when
    /// firewall policy requires a specific source port.
    ///
    /// `interface` optionally pins the socket to a specific NIC
    /// (see `docs/nic-pinning.md`). `None` leaves egress selection
    /// to the kernel routing table.
    pub async fn bind(
        id: PathId,
        name: impl Into<String>,
        local: SocketAddr,
        primary_peer: Option<SocketAddr>,
        interface: Option<&str>,
        crypto: Option<Arc<BondCrypto>>,
    ) -> PathResult<Self> {
        let shared = UdpRebuilder::create(local, interface)?;
        Ok(Self::from_shared(
            id,
            name.into(),
            shared,
            primary_peer,
            crypto,
        ))
    }

    /// Bind on an ephemeral local port (sender-mode convenience).
    pub async fn bind_ephemeral(
        id: PathId,
        name: impl Into<String>,
        primary_peer: SocketAddr,
        interface: Option<&str>,
        crypto: Option<Arc<BondCrypto>>,
    ) -> PathResult<Self> {
        let local: SocketAddr = if primary_peer.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        Self::bind(id, name, local, Some(primary_peer), interface, crypto).await
    }

    /// Which NIC-pin mechanism this path is using, if an `interface`
    /// was requested. `None` = no pin (kernel routing decides egress).
    /// Reflects the CURRENT socket — may change across rebuilds.
    pub fn pin_mechanism(&self) -> Option<PinMechanism> {
        self.shared.pin_mechanism()
    }

    /// Force an in-place socket rebuild (no rate limit). Testing /
    /// operator-triggered recovery; the watcher and send-error
    /// trigger go through `UdpRebuilder::try_rebuild` directly.
    pub fn rebuild(&self) -> PathResult<()> {
        match self.shared.try_rebuild(Duration::ZERO) {
            Some(r) => r,
            // Another rebuild is in flight — treat as success, the
            // socket is being replaced either way.
            None => Ok(()),
        }
    }

    /// Successful rebuilds on this path.
    pub fn rebuild_count(&self) -> u64 {
        self.shared.rebuild_count()
    }

    /// Sender hot-path hook — clear the consecutive send-error run.
    #[inline]
    pub fn note_send_ok(&self) {
        self.shared.note_send_ok();
    }

    /// Sender hot-path hook — classify a send error and rebuild the
    /// socket after [`SEND_ERR_REBUILD_THRESHOLD`] consecutive
    /// route/device errors (≥1 s between attempts). Returns `true`
    /// when a rebuild was performed so the caller can emit
    /// `PathRebuilt { reason: SendErrors }`.
    pub fn note_send_error(&self, err: &PathError) -> bool {
        let rebuilt = self.shared.note_send_error(err);
        if rebuilt {
            log::warn!(
                "bond udp path '{}': rebuilt socket after {} consecutive route/device send errors",
                self.name,
                SEND_ERR_REBUILD_THRESHOLD
            );
        }
        rebuilt
    }

    /// Handle for the per-bond interface watcher / manual rebuilds.
    /// Survives the move of the `Path` into the sender/receiver task.
    pub(crate) fn watch_handle(&self) -> UdpWatchHandle {
        let target = match (&self.shared.interface, self.shared.local.ip()) {
            // An interface pin subsumes the source-bind watch: the
            // ifindex is the churn signal. Address-gone with a stable
            // iface surfaces as send errors instead.
            (Some(iface), _) => Some(WatchTarget::Interface(iface.clone())),
            (None, ip) if !ip.is_unspecified() => Some(WatchTarget::SourceIp(ip)),
            _ => None,
        };
        UdpWatchHandle {
            path_id: self.id,
            name: self.name.clone(),
            target,
            rebuilder: self.shared.clone(),
        }
    }

    fn from_shared(
        id: PathId,
        name: String,
        shared: Arc<UdpRebuilder>,
        primary_peer: Option<SocketAddr>,
        crypto: Option<Arc<BondCrypto>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<PathDatagram>(1024);
        let cancel = CancellationToken::new();
        let recv_task = spawn_recv_loop(shared.clone(), tx, cancel.clone(), crypto.clone());

        let me = Self {
            id,
            name,
            shared,
            primary_peer: Arc::new(Mutex::new(primary_peer)),
            primary_ip_hi: AtomicU64::new(0),
            primary_ip_lo: AtomicU64::new(0),
            primary_port: AtomicU64::new(0),
            rx: Mutex::new(Some(rx)),
            crypto,
            _recv_task: recv_task,
            _cancel: cancel,
        };
        if let Some(p) = primary_peer {
            me.store_primary_atomics(p);
        }
        me
    }

    fn store_primary_atomics(&self, peer: SocketAddr) {
        let (hi, lo) = match peer.ip() {
            std::net::IpAddr::V4(a) => {
                let octets = a.octets();
                let v = u32::from_be_bytes(octets) as u64;
                (0u64, v)
            }
            std::net::IpAddr::V6(a) => {
                let seg = a.octets();
                let hi = u64::from_be_bytes(seg[..8].try_into().unwrap());
                let lo = u64::from_be_bytes(seg[8..].try_into().unwrap());
                (hi, lo)
            }
        };
        self.primary_ip_hi.store(hi, Ordering::Release);
        self.primary_ip_lo.store(lo, Ordering::Release);
        // High bit = "set" flag; low 16 = port.
        let port = peer.port() as u64 | (1u64 << 63);
        self.primary_port.store(port, Ordering::Release);
    }

    pub fn id(&self) -> PathId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_primary_peer(&self, peer: SocketAddr) {
        // Fast path: update atomics. Mutex is bookkeeping-only.
        self.store_primary_atomics(peer);
        // Intentionally not awaiting the lock — `primary_peer` is a
        // slow-path read used by `primary_peer()` accessor; on
        // contention the hot-path atomics are always current.
        if let Ok(mut guard) = self.primary_peer.try_lock() {
            *guard = Some(peer);
        }
    }

    pub fn primary_peer(&self) -> Option<SocketAddr> {
        let port_word = self.primary_port.load(Ordering::Acquire);
        if port_word & (1u64 << 63) == 0 {
            return None;
        }
        let port = (port_word & 0xFFFF) as u16;
        let hi = self.primary_ip_hi.load(Ordering::Acquire);
        let lo = self.primary_ip_lo.load(Ordering::Acquire);
        if hi == 0 {
            // IPv4
            let v = lo as u32;
            let a = std::net::Ipv4Addr::from(v.to_be_bytes());
            Some(SocketAddr::new(std::net::IpAddr::V4(a), port))
        } else {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&hi.to_be_bytes());
            bytes[8..].copy_from_slice(&lo.to_be_bytes());
            let a = std::net::Ipv6Addr::from(bytes);
            Some(SocketAddr::new(std::net::IpAddr::V6(a), port))
        }
    }

    pub async fn send(&self, data: &[u8]) -> PathResult<()> {
        match self.primary_peer() {
            Some(peer) => self.send_to(data, peer).await,
            None => Err(PathError::Other(format!(
                "path {} has no primary peer",
                self.name
            ))),
        }
    }

    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> PathResult<()> {
        // Snapshot of the current socket — lock-free; a rebuild swaps
        // the next send onto the new socket.
        let socket = self.shared.current();
        if let Some(crypto) = &self.crypto {
            let mut sealed = Vec::with_capacity(data.len() + crate::crypto::ENVELOPE_OVERHEAD);
            crypto
                .seal(data, &mut sealed)
                .map_err(|e| PathError::Other(format!("bond seal: {e}")))?;
            return socket
                .send_to(&sealed, to)
                .await
                .map(|_| ())
                .map_err(PathError::Send);
        }
        socket
            .send_to(data, to)
            .await
            .map(|_| ())
            .map_err(PathError::Send)
    }

    pub fn take_rx(&mut self) -> Option<mpsc::Receiver<PathDatagram>> {
        self.rx.get_mut().take()
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.shared.current().local_addr()
    }
}

/// Socket build recipe shared by the initial bind and every rebuild.
/// Returns the resolved pin mechanism plus the ifindex the pin bound
/// to (0 when unpinned / unresolved) so the watcher can compare it
/// against the live name → index mapping later.
fn build_socket(
    local: SocketAddr,
    interface: Option<&str>,
) -> PathResult<(Arc<UdpSocket>, Option<PinMechanism>, u32)> {
    let domain = if local.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Sock2::new(domain, Type::DGRAM, Some(SockProto::UDP)).map_err(|e| {
        PathError::Bind {
            addr: local.to_string(),
            source: e,
        }
    })?;
    sock.set_reuse_address(true).ok();
    sock.set_nonblocking(true).ok();
    let _ = sock.set_recv_buffer_size(DEFAULT_SOCK_BUF);
    let _ = sock.set_send_buffer_size(DEFAULT_SOCK_BUF);
    // NIC pin first — some platforms require it before bind.
    let (pin_mechanism, ifindex) = if let Some(iface) = interface {
        let mech =
            bind_to_interface(&sock, iface, local.is_ipv6()).map_err(|e| {
                PathError::BindInterface {
                    interface: iface.to_string(),
                    source: e,
                }
            })?;
        log::info!(
            "bond udp path pinned to interface '{}' via {}",
            iface,
            mech.as_str()
        );
        // The pin just succeeded, so the iface exists; a 0 here means
        // it vanished in the microseconds since — the watcher
        // self-corrects on its next tick either way.
        (Some(mech), resolve_ifindex(iface).unwrap_or(0))
    } else {
        (None, 0)
    };
    sock.bind(&local.into()).map_err(|e| PathError::Bind {
        addr: local.to_string(),
        source: e,
    })?;
    let udp = UdpSocket::from_std(sock.into()).map_err(|e| PathError::Bind {
        addr: local.to_string(),
        source: e,
    })?;
    Ok((Arc::new(udp), pin_mechanism, ifindex))
}

fn spawn_recv_loop(
    shared: Arc<UdpRebuilder>,
    tx: mpsc::Sender<PathDatagram>,
    cancel: CancellationToken,
    crypto: Option<Arc<BondCrypto>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut plain = Vec::with_capacity(MAX_DATAGRAM);
        loop {
            // Re-load the socket snapshot each pass; the bounded recv
            // timeout guarantees a rebuild swap is noticed within
            // SOCKET_SWAP_POLL without poll-spinning. Datagrams that
            // land on the old socket inside that window are lost with
            // it — bond ARQ recovers them like any path loss.
            let socket = shared.current();
            tokio::select! {
                _ = cancel.cancelled() => break,
                r = tokio::time::timeout(SOCKET_SWAP_POLL, socket.recv_from(&mut buf)) => match r {
                    Err(_elapsed) => continue,
                    Ok(Ok((len, from))) => {
                        let data = if let Some(crypto) = &crypto {
                            // Drop any datagram that fails authentication —
                            // a wrong-key or tampered/stray packet never
                            // reaches the bond protocol decoder.
                            match crypto.open(&buf[..len], &mut plain) {
                                Ok(()) => Bytes::copy_from_slice(&plain),
                                Err(e) => {
                                    log::debug!("bond udp path: drop undecryptable datagram: {e}");
                                    continue;
                                }
                            }
                        } else {
                            Bytes::copy_from_slice(&buf[..len])
                        };
                        if tx.try_send(PathDatagram { data, from }).is_err() {
                            // Receiver is backed up — drop rather than
                            // stall the reactor. Stats at the higher
                            // layer will record it.
                            log::debug!("UDP path rx drop (channel full)");
                        }
                    }
                    Ok(Err(e)) => {
                        log::warn!("UDP path recv error: {e}");
                        // A dying socket (device gone) can return errors
                        // in a tight loop — back off briefly; the watcher
                        // / send-error trigger rebuilds it.
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                },
            }
        }
    })
}

impl std::fmt::Debug for UdpPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPath")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("local", &self.local_addr().ok())
            .field("primary_peer", &self.primary_peer())
            .finish()
    }
}

// ─── Interface-churn probes ──────────────────────────────────────
//
// Used by the per-bond interface watcher (socket.rs). Both probes
// are cheap enough for a 2 s poll: one name→index syscall, or one
// throwaway local bind.

/// Current kernel ifindex for `iface`; `None` when the interface
/// doesn't (currently) exist or the platform has no lookup.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "fuchsia",
))]
pub(crate) fn resolve_ifindex(iface: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(iface).ok()?;
    // SAFETY: `cname` is a valid NUL-terminated C string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    (idx != 0).then_some(idx)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "fuchsia",
)))]
pub(crate) fn resolve_ifindex(_iface: &str) -> Option<u32> {
    None
}

/// Is `ip` currently assigned to some interface? Probed by binding a
/// throwaway UDP socket to `ip:0` — EADDRNOTAVAIL means the address
/// is gone (DHCP renumber, device removed).
pub(crate) fn source_ip_present(ip: IpAddr) -> bool {
    std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// Errnos that mean "the route/device under this socket is gone" —
/// the signal for a send-error-triggered rebuild. Anything else
/// (buffer pressure, perms, message size) is not churn.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "fuchsia",
))]
fn is_route_errno(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENODEV)
            | Some(libc::EADDRNOTAVAIL)
            | Some(libc::ENETUNREACH)
            | Some(libc::EHOSTUNREACH)
    )
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "fuchsia",
)))]
fn is_route_errno(_e: &std::io::Error) -> bool {
    false
}

// ─── NIC pinning ─────────────────────────────────────────────────
//
// On Linux/Android: prefer SO_BINDTODEVICE (hard TX+RX bind, needs
//   CAP_NET_RAW); on EPERM/EACCES fall back to the unprivileged
//   IP_UNICAST_IF / IPV6_UNICAST_IF egress hint so a non-privileged
//   field box can still steer each path onto its own NIC.
// On Apple / FreeBSD / Fuchsia: IP_BOUND_IF / IPV6_BOUND_IF by
//   interface index, unprivileged.
// Elsewhere: return Unsupported so operators get a clear error
//   instead of silent fall-through to the default route.

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_to_interface(sock: &Sock2, iface: &str, is_ipv6: bool) -> std::io::Result<PinMechanism> {
    match sock.bind_device(Some(iface.as_bytes())) {
        Ok(()) => Ok(PinMechanism::SoBindToDevice),
        Err(e)
            if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) =>
        {
            // No CAP_NET_RAW — degrade to the unprivileged egress hint.
            set_unicast_if(sock, iface, is_ipv6)?;
            log::info!(
                "bond udp: SO_BINDTODEVICE('{iface}') denied (no CAP_NET_RAW); \
                 using unprivileged IP_UNICAST_IF"
            );
            Ok(PinMechanism::UnicastIf)
        }
        Err(e) => Err(e),
    }
}

/// Set `IP_UNICAST_IF` (IPv4) / `IPV6_UNICAST_IF` (IPv6) — an
/// unprivileged per-socket egress-interface hint. Note the IPv4
/// option takes the interface index in **network byte order** (a
/// long-standing kernel quirk); the IPv6 option takes **host order**.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_unicast_if(sock: &Sock2, iface: &str, is_ipv6: bool) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let cname = std::ffi::CString::new(iface).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name contains NUL byte",
        )
    })?;
    // SAFETY: `cname` is a valid NUL-terminated C string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface '{iface}' not found (if_nametoindex returned 0)"),
        ));
    }
    let (level, optname, optval) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_IF, idx as libc::c_int)
    } else {
        // network byte order for IPv4 IP_UNICAST_IF.
        (libc::IPPROTO_IP, libc::IP_UNICAST_IF, idx.to_be() as libc::c_int)
    };
    // SAFETY: `optval` is a valid `c_int` and `optlen` matches its size.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            optname,
            &optval as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(target_vendor = "apple", target_os = "freebsd", target_os = "fuchsia"))]
fn bind_to_interface(sock: &Sock2, iface: &str, is_ipv6: bool) -> std::io::Result<PinMechanism> {
    let cname = std::ffi::CString::new(iface).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name contains NUL byte",
        )
    })?;
    // SAFETY: `cname` is a valid NUL-terminated C string.
    let idx_raw = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    let idx = std::num::NonZeroU32::new(idx_raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface '{iface}' not found (if_nametoindex returned 0)"),
        )
    })?;
    if is_ipv6 {
        sock.bind_device_by_index_v6(Some(idx))?;
    } else {
        sock.bind_device_by_index_v4(Some(idx))?;
    }
    Ok(PinMechanism::BoundIf)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "fuchsia",
)))]
fn bind_to_interface(_sock: &Sock2, iface: &str, _is_ipv6: bool) -> std::io::Result<PinMechanism> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "NIC pinning (interface='{iface}') is not supported on this platform; \
             use source-IP binding + policy routing instead"
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinning to the loopback interface must succeed and report a
    /// concrete mechanism. Without `CAP_NET_RAW` (the usual test
    /// environment) `SO_BINDTODEVICE` is denied and we expect the
    /// automatic `IP_UNICAST_IF` fallback; with the cap we get the
    /// hard bind. Either is a pass — the point is no silent failure.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn pin_to_loopback_reports_a_mechanism() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let path = UdpPath::bind(0, "lo-test", local, None, Some("lo"), None)
            .await
            .expect("bind+pin to lo should succeed");
        let mech = path.pin_mechanism().expect("a pin mechanism was requested");
        assert!(
            matches!(mech, PinMechanism::SoBindToDevice | PinMechanism::UnicastIf),
            "expected SO_BINDTODEVICE or IP_UNICAST_IF, got {mech:?}"
        );
    }

    /// No interface requested → no pin mechanism recorded.
    #[tokio::test]
    async fn no_interface_no_mechanism() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let path = UdpPath::bind(0, "no-pin", local, None, None, None)
            .await
            .expect("plain bind should succeed");
        assert!(path.pin_mechanism().is_none());
    }

    /// A bogus interface name must error, not silently fall through to
    /// the default route (that would collapse all paths onto one link).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn pin_to_missing_interface_errors() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let res = UdpPath::bind(0, "bad", local, None, Some("definitely-not-a-nic0"), None).await;
        assert!(res.is_err(), "pinning to a nonexistent NIC must fail loudly");
    }

    /// Rebuild swaps in a fresh socket: an ephemeral (:0) bind takes a
    /// new port and the rebuild counter advances. Datagrams sent after
    /// the rebuild land on the recv channel (the recv loop notices the
    /// swap within SOCKET_SWAP_POLL).
    #[tokio::test]
    async fn rebuild_swaps_socket_and_keeps_receiving() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut path = UdpPath::bind(7, "rebuild", local, None, None, None)
            .await
            .expect("bind");
        let mut rx = path.take_rx().expect("rx");
        let before = path.local_addr().expect("local addr");

        path.rebuild().expect("rebuild should succeed");
        assert_eq!(path.rebuild_count(), 1);
        let after = path.local_addr().expect("local addr after rebuild");
        assert_ne!(
            before.port(),
            after.port(),
            "an ephemeral bind must take a fresh port on rebuild"
        );

        // Give the recv loop one SOCKET_SWAP_POLL to adopt the swap,
        // then prove traffic flows into the same channel.
        tokio::time::sleep(SOCKET_SWAP_POLL + Duration::from_millis(20)).await;
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        probe.send_to(b"post-rebuild", after).await.unwrap();
        let dg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("datagram within 2s")
            .expect("channel open");
        assert_eq!(&dg.data[..], b"post-rebuild");
    }

    /// Send-error trigger: 50 consecutive route/device errnos rebuild
    /// the socket once; the run resets and the next burst inside the
    /// 1 s rate limit does NOT rebuild again.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "fuchsia",
    ))]
    #[tokio::test]
    async fn send_error_run_triggers_one_rebuild() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let path = UdpPath::bind(8, "errs", local, None, None, None)
            .await
            .expect("bind");
        let route_err =
            || PathError::Send(std::io::Error::from_raw_os_error(libc::ENETUNREACH));

        for i in 1..SEND_ERR_REBUILD_THRESHOLD {
            assert!(!path.note_send_error(&route_err()), "no rebuild at {i}");
        }
        assert!(
            path.note_send_error(&route_err()),
            "50th consecutive route error must rebuild"
        );
        assert_eq!(path.rebuild_count(), 1);

        // Counter was reset by the rebuild; a second burst trips the
        // threshold again but is inside the 1 s rate limit → skipped.
        for _ in 0..SEND_ERR_REBUILD_THRESHOLD + 5 {
            assert!(!path.note_send_error(&route_err()));
        }
        assert_eq!(path.rebuild_count(), 1, "rate limit must hold");
    }

    /// Backoff: a rebuild that fails to clear the error run doubles
    /// the spacing to the next attempt (a downed gateway persists
    /// across rebuilds — without backoff it costs one rebuild + one
    /// warning event + a source-port churn per second, forever). A
    /// successful send resets the exponent.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "fuchsia",
    ))]
    #[tokio::test]
    async fn send_error_rebuild_backs_off_until_a_send_succeeds() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let path = UdpPath::bind(10, "backoff", local, None, None, None)
            .await
            .expect("bind");
        let route_err =
            || PathError::Send(std::io::Error::from_raw_os_error(libc::EHOSTUNREACH));

        let burst = |path: &UdpPath| -> bool {
            let mut rebuilt = false;
            for _ in 0..SEND_ERR_REBUILD_THRESHOLD {
                rebuilt |= path.note_send_error(&route_err());
            }
            rebuilt
        };

        assert!(burst(&path), "first threshold crossing rebuilds");
        assert_eq!(path.rebuild_count(), 1);

        // Past the base 1 s interval but inside the doubled 2 s one:
        // the errors never stopped, so the next attempt is held back.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!burst(&path), "backoff must hold the second rebuild");
        assert_eq!(path.rebuild_count(), 1);

        // One delivered packet proves the leg works → exponent resets,
        // and the base interval (already elapsed) permits a rebuild on
        // the next threshold crossing.
        path.note_send_ok();
        assert!(burst(&path), "post-recovery crossing rebuilds at the base interval");
        assert_eq!(path.rebuild_count(), 2);
    }

    /// A successful send (or a non-route error) breaks the run.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "fuchsia",
    ))]
    #[tokio::test]
    async fn send_error_run_resets_on_success_and_foreign_errno() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let path = UdpPath::bind(9, "reset", local, None, None, None)
            .await
            .expect("bind");
        let route_err =
            || PathError::Send(std::io::Error::from_raw_os_error(libc::ENETUNREACH));

        for _ in 0..SEND_ERR_REBUILD_THRESHOLD - 1 {
            path.note_send_error(&route_err());
        }
        path.note_send_ok();
        for i in 1..SEND_ERR_REBUILD_THRESHOLD {
            assert!(!path.note_send_error(&route_err()), "run restarted at {i}");
        }
        // Foreign errno also breaks the run.
        let foreign = PathError::Send(std::io::Error::from_raw_os_error(libc::EPERM));
        assert!(!path.note_send_error(&foreign));
        for i in 1..SEND_ERR_REBUILD_THRESHOLD {
            assert!(!path.note_send_error(&route_err()), "run restarted at {i}");
        }
        assert_eq!(path.rebuild_count(), 0);
    }

    /// Watch-target derivation: interface pin wins, then source-bind,
    /// wildcard binds aren't watched.
    #[tokio::test]
    async fn watch_handle_targets() {
        let wild: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let p = UdpPath::bind(1, "wild", wild, None, None, None).await.unwrap();
        assert!(p.watch_handle().target.is_none());

        let src: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let p = UdpPath::bind(2, "src", src, None, None, None).await.unwrap();
        assert!(matches!(
            p.watch_handle().target,
            Some(WatchTarget::SourceIp(ip)) if ip == "127.0.0.1".parse::<IpAddr>().unwrap()
        ));
    }

    /// The loopback address is always present; a TEST-NET-1 address is
    /// never assigned locally.
    #[test]
    fn source_ip_probe() {
        assert!(source_ip_present("127.0.0.1".parse().unwrap()));
        assert!(!source_ip_present("192.0.2.123".parse().unwrap()));
    }
}
