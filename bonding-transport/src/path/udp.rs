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

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
}

pub struct UdpPath {
    id: PathId,
    name: String,
    socket: Arc<UdpSocket>,
    /// `Some` when an `interface` pin was requested; records which
    /// kernel mechanism actually succeeded (hard bind vs the
    /// unprivileged hint fallback).
    pin_mechanism: Option<PinMechanism>,
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
        let (socket, pin_mechanism) = Self::build_socket(local, interface).await?;
        Ok(Self::from_socket(
            id,
            name.into(),
            socket,
            primary_peer,
            pin_mechanism,
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

    async fn build_socket(
        local: SocketAddr,
        interface: Option<&str>,
    ) -> PathResult<(Arc<UdpSocket>, Option<PinMechanism>)> {
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
        let pin_mechanism = if let Some(iface) = interface {
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
            Some(mech)
        } else {
            None
        };
        sock.bind(&local.into()).map_err(|e| PathError::Bind {
            addr: local.to_string(),
            source: e,
        })?;
        let udp = UdpSocket::from_std(sock.into()).map_err(|e| PathError::Bind {
            addr: local.to_string(),
            source: e,
        })?;
        Ok((Arc::new(udp), pin_mechanism))
    }

    /// Which NIC-pin mechanism this path is using, if an `interface`
    /// was requested. `None` = no pin (kernel routing decides egress).
    pub fn pin_mechanism(&self) -> Option<PinMechanism> {
        self.pin_mechanism
    }

    fn from_socket(
        id: PathId,
        name: String,
        socket: Arc<UdpSocket>,
        primary_peer: Option<SocketAddr>,
        pin_mechanism: Option<PinMechanism>,
        crypto: Option<Arc<BondCrypto>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<PathDatagram>(1024);
        let cancel = CancellationToken::new();
        let recv_task = spawn_recv_loop(socket.clone(), tx, cancel.clone(), crypto.clone());

        let me = Self {
            id,
            name,
            socket,
            pin_mechanism,
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
        if let Some(crypto) = &self.crypto {
            let mut sealed = Vec::with_capacity(data.len() + crate::crypto::ENVELOPE_OVERHEAD);
            crypto
                .seal(data, &mut sealed)
                .map_err(|e| PathError::Other(format!("bond seal: {e}")))?;
            return self
                .socket
                .send_to(&sealed, to)
                .await
                .map(|_| ())
                .map_err(PathError::Send);
        }
        self.socket
            .send_to(data, to)
            .await
            .map(|_| ())
            .map_err(PathError::Send)
    }

    pub fn take_rx(&mut self) -> Option<mpsc::Receiver<PathDatagram>> {
        self.rx.get_mut().take()
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

fn spawn_recv_loop(
    socket: Arc<UdpSocket>,
    tx: mpsc::Sender<PathDatagram>,
    cancel: CancellationToken,
    crypto: Option<Arc<BondCrypto>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut plain = Vec::with_capacity(MAX_DATAGRAM);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                r = socket.recv_from(&mut buf) => match r {
                    Ok((len, from)) => {
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
                    Err(e) => {
                        log::warn!("UDP path recv error: {e}");
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
            .field("local", &self.socket.local_addr().ok())
            .field("primary_peer", &self.primary_peer())
            .finish()
    }
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
}
