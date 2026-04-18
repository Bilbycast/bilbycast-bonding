//! RIST Simple Profile path adapter.
//!
//! Wraps a `rist_transport::RistSocket` as a bond [`Path`]. RIST is
//! semantically **unidirectional** at the data-payload layer (RTP
//! goes sender → receiver; RTCP goes the other way but is internal
//! to the RIST stack). So a [`RistPath`] is either:
//!
//! - **Send-only** ([`RistPath::sender`]): transmits bond frames out
//!   as RIST RTP payload. Cannot carry inbound control for the bond.
//! - **Receive-only** ([`RistPath::receiver`]): delivers bond frames
//!   into the bond loop. Cannot transmit reply control.
//!
//! This isn't a design flaw — bond tolerates it natively. The receiver's
//! NACK router picks "the lowest-RTT alive path with a learned peer",
//! which naturally skips recv-only RIST paths (they never learn a
//! bond-level peer address). If you want bond-level ARQ over RIST
//! links, pair the RIST path with a UDP or QUIC path in the
//! opposite direction.
//!
//! When ALL paths in a bond are RIST, bond-level recovery is
//! unavailable but RIST's own per-leg ARQ keeps doing its job — the
//! worst case is that each path individually behaves the same as
//! today's RIST deployment.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use rist_transport::{RistSocket, RistSocketConfig};

use bonding_protocol::protocol::scheduler::PathId;

use super::{PathDatagram, PathError, PathResult};

#[derive(Clone, Copy, Debug)]
enum Mode {
    Sender,
    Receiver,
}

pub struct RistPath {
    id: PathId,
    name: String,
    mode: Mode,
    /// Present in sender mode. `RistSocket::send` takes `&self` so an
    /// `Arc` is enough — no inner locking on the send hot path.
    tx_socket: Option<Arc<RistSocket>>,
    /// Set on sender mode, None on receiver mode (learned internally
    /// by the RistSocket itself, not exposed to bond).
    configured_remote: Option<SocketAddr>,
    rx: Mutex<Option<mpsc::Receiver<PathDatagram>>>,
    cancel: CancellationToken,
    _task: tokio::task::JoinHandle<()>,
}

impl RistPath {
    /// Send-only RIST path. Binds locally and sends to `remote`
    /// (port must be even). `buffer_ms` sizes RIST's own retransmit
    /// buffer (default 1000 ms).
    pub async fn sender(
        id: PathId,
        name: impl Into<String>,
        remote: SocketAddr,
        local_bind: Option<SocketAddr>,
        buffer_ms: Option<u32>,
    ) -> PathResult<Self> {
        if remote.port() & 1 != 0 {
            return Err(PathError::Other(format!(
                "RIST path remote port must be even, got {}",
                remote.port()
            )));
        }
        let mut cfg = RistSocketConfig::default();
        cfg.local_addr = match local_bind {
            Some(b) => b,
            None => ephemeral_even_bind(remote),
        };
        if let Some(ms) = buffer_ms {
            cfg.buffer_size = Duration::from_millis(ms as u64);
        }
        let socket = RistSocket::sender(cfg, remote)
            .await
            .map_err(|e| PathError::Other(format!("RIST sender bind failed: {e}")))?;

        let cancel = CancellationToken::new();
        // No rx on sender-mode — bond-level control comes in via a
        // different path. Spawn a minimal idle task so the cancel
        // token has a lifetime partner.
        let cancel_child = cancel.clone();
        let task = tokio::spawn(async move {
            cancel_child.cancelled().await;
        });

        Ok(Self {
            id,
            name: name.into(),
            mode: Mode::Sender,
            tx_socket: Some(Arc::new(socket)),
            configured_remote: Some(remote),
            rx: Mutex::new(None),
            cancel,
            _task: task,
        })
    }

    /// Receive-only RIST path. Binds on `local_bind` (port must be
    /// even) and forwards every RIST-delivered payload into the
    /// bond-layer mpsc.
    pub async fn receiver(
        id: PathId,
        name: impl Into<String>,
        local_bind: SocketAddr,
        buffer_ms: Option<u32>,
    ) -> PathResult<Self> {
        if local_bind.port() & 1 != 0 {
            return Err(PathError::Other(format!(
                "RIST path local port must be even, got {}",
                local_bind.port()
            )));
        }
        let mut cfg = RistSocketConfig::default();
        cfg.local_addr = local_bind;
        if let Some(ms) = buffer_ms {
            cfg.buffer_size = Duration::from_millis(ms as u64);
        }
        let mut socket = RistSocket::receiver(cfg)
            .await
            .map_err(|e| PathError::Other(format!("RIST receiver bind failed: {e}")))?;

        let (tx, rx) = mpsc::channel::<PathDatagram>(1024);
        let cancel = CancellationToken::new();
        let cancel_child = cancel.clone();
        // The RistSocket's own peer address is internal. Bond
        // delivers the payload without a routable `from` — which is
        // fine because bond treats RIST-receive paths as
        // non-reply-capable (see crate docs).
        let dummy_from: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_child.cancelled() => break,
                    maybe = socket.recv() => match maybe {
                        Some(payload) => {
                            if tx.try_send(PathDatagram { data: payload, from: dummy_from }).is_err() {
                                log::debug!("RIST recv path mpsc full, dropping");
                            }
                        }
                        None => break,
                    },
                }
            }
        });

        Ok(Self {
            id,
            name: name.into(),
            mode: Mode::Receiver,
            tx_socket: None,
            configured_remote: None,
            rx: Mutex::new(Some(rx)),
            cancel,
            _task: task,
        })
    }

    pub fn id(&self) -> PathId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// For RIST: send-only paths expose their configured remote as
    /// the peer. Receive-only paths have no bond-routable peer
    /// (RIST learns its own peer internally for RTCP, but that isn't
    /// useful at the bond layer). Returning `None` causes the bond
    /// receiver's NACK router to skip this path, which is exactly
    /// what we want.
    pub fn primary_peer(&self) -> Option<SocketAddr> {
        match self.mode {
            Mode::Sender => self.configured_remote,
            Mode::Receiver => None,
        }
    }

    pub fn set_primary_peer(&self, _peer: SocketAddr) {
        // RIST sockets own their peer internally; bond-level updates
        // are no-ops here.
    }

    /// Send a bond frame over this path's RIST socket. Returns an
    /// error if the path is receive-only.
    pub async fn send(&self, data: &[u8]) -> PathResult<()> {
        let socket = self
            .tx_socket
            .as_ref()
            .ok_or_else(|| PathError::Other("RIST path is receive-only".into()))?;
        socket
            .send(Bytes::copy_from_slice(data))
            .await
            .map_err(|_| PathError::Other("RIST send channel closed".into()))
    }

    pub async fn send_to(&self, data: &[u8], _to: SocketAddr) -> PathResult<()> {
        // `to` is ignored — the RIST socket has a fixed remote.
        self.send(data).await
    }

    pub fn take_rx(&mut self) -> Option<mpsc::Receiver<PathDatagram>> {
        self.rx.get_mut().take()
    }
}

impl Drop for RistPath {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Pick an ephemeral even local port in the IANA dynamic range. The
/// upstream `RistSocket::sender` doesn't retry binds, so we accept a
/// small risk of port collision — callers who need determinism
/// should pass `local_bind` explicitly.
fn ephemeral_even_bind(remote: SocketAddr) -> SocketAddr {
    let ip = if remote.is_ipv4() { "0.0.0.0" } else { "[::]" };
    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u16)
        .unwrap_or(0);
    let port = ((entropy as u32) % 8192 * 2 + 49152) as u16;
    let port = port & !1;
    format!("{ip}:{port}").parse().unwrap()
}
