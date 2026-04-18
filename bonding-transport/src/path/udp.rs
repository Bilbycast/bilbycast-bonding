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

use super::{PathDatagram, PathError, PathResult};

/// Default socket buffer sizes (2 MB). The kernel may cap these but
/// requesting large buffers matters for high-bitrate media on
/// congested links.
const DEFAULT_SOCK_BUF: usize = 2 * 1024 * 1024;

/// Maximum UDP datagram we'll accept.
const MAX_DATAGRAM: usize = 2048;

pub struct UdpPath {
    id: PathId,
    name: String,
    socket: Arc<UdpSocket>,
    primary_peer: Arc<Mutex<Option<SocketAddr>>>,
    /// Cached copy of the primary peer as a pair of atomics for the
    /// send hot path — avoids taking the Mutex on every
    /// outbound packet. Stored as raw IPv6-mapped u128 + port u16
    /// packed into two AtomicU64.
    primary_ip_hi: AtomicU64,
    primary_ip_lo: AtomicU64,
    primary_port: AtomicU64, // high bit = set flag
    rx: Mutex<Option<mpsc::Receiver<PathDatagram>>>,
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
    ) -> PathResult<Self> {
        let socket = Self::build_socket(local, interface).await?;
        Ok(Self::from_socket(id, name.into(), socket, primary_peer))
    }

    /// Bind on an ephemeral local port (sender-mode convenience).
    pub async fn bind_ephemeral(
        id: PathId,
        name: impl Into<String>,
        primary_peer: SocketAddr,
        interface: Option<&str>,
    ) -> PathResult<Self> {
        let local: SocketAddr = if primary_peer.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        Self::bind(id, name, local, Some(primary_peer), interface).await
    }

    async fn build_socket(
        local: SocketAddr,
        interface: Option<&str>,
    ) -> PathResult<Arc<UdpSocket>> {
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
        if let Some(iface) = interface {
            bind_to_interface(&sock, iface, local.is_ipv6()).map_err(|e| {
                PathError::BindInterface {
                    interface: iface.to_string(),
                    source: e,
                }
            })?;
        }
        sock.bind(&local.into()).map_err(|e| PathError::Bind {
            addr: local.to_string(),
            source: e,
        })?;
        let udp = UdpSocket::from_std(sock.into()).map_err(|e| PathError::Bind {
            addr: local.to_string(),
            source: e,
        })?;
        Ok(Arc::new(udp))
    }

    fn from_socket(
        id: PathId,
        name: String,
        socket: Arc<UdpSocket>,
        primary_peer: Option<SocketAddr>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<PathDatagram>(1024);
        let cancel = CancellationToken::new();
        let recv_task = spawn_recv_loop(socket.clone(), tx, cancel.clone());

        let me = Self {
            id,
            name,
            socket,
            primary_peer: Arc::new(Mutex::new(primary_peer)),
            primary_ip_hi: AtomicU64::new(0),
            primary_ip_lo: AtomicU64::new(0),
            primary_port: AtomicU64::new(0),
            rx: Mutex::new(Some(rx)),
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
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                r = socket.recv_from(&mut buf) => match r {
                    Ok((len, from)) => {
                        let data = Bytes::copy_from_slice(&buf[..len]);
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
// On Linux/Android: SO_BINDTODEVICE, needs CAP_NET_RAW.
// On Apple / FreeBSD / Fuchsia: IP_BOUND_IF / IPV6_BOUND_IF by
// interface index, unprivileged.
// Elsewhere: return Unsupported so operators get a clear error
// instead of silent fall-through to the default route.

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_to_interface(sock: &Sock2, iface: &str, _is_ipv6: bool) -> std::io::Result<()> {
    sock.bind_device(Some(iface.as_bytes()))
}

#[cfg(any(target_vendor = "apple", target_os = "freebsd", target_os = "fuchsia"))]
fn bind_to_interface(sock: &Sock2, iface: &str, is_ipv6: bool) -> std::io::Result<()> {
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
        sock.bind_device_by_index_v6(Some(idx))
    } else {
        sock.bind_device_by_index_v4(Some(idx))
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "fuchsia",
)))]
fn bind_to_interface(_sock: &Sock2, iface: &str, _is_ipv6: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "NIC pinning (interface='{iface}') is not supported on this platform; \
             use source-IP binding + policy routing instead"
        ),
    ))
}
