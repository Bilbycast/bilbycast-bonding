//! In-process "attached" path adapter.
//!
//! An [`AttachedPath`] mirrors [`super::udp::UdpPath`]'s surface, but its
//! transport is a pair of in-process `mpsc` channels to an edge-owned bridge
//! rather than a `UdpSocket`. It exists for a **relayed bonded leg**: the edge
//! bridge owns the relay socket (Register/keepalive rendezvous + failover) and
//! the 16-byte `tunnel_id` prefix; the bond hands it framed datagrams in
//! process — no `127.0.0.1` loopback round-trip, no second congestion
//! controller.
//!
//! Crypto contract — identical layering to the UDP path:
//! - `send_to` seals the bond `0xBD` AEAD envelope (when a [`BondCrypto`] is
//!   set), then `try_send`s the sealed bytes to the bridge **drop-on-full**
//!   (never `await` — an awaiting channel injects backpressure the UDP path
//!   never had and stalls the bond sender).
//! - the recv loop opens the `0xBD` envelope (dropping on auth failure) before
//!   delivering the inner datagram to the bond receiver — exactly like
//!   `udp::spawn_recv_loop`.
//!
//! The tunnel-level 16-byte prefix and (when the bond is *unkeyed*) the per-leg
//! tunnel AEAD are added by the bridge, OUTSIDE the bond's accounting — so
//! [`AttachedPath::wire_overhead_per_datagram`] reports only the bond-crypto
//! envelope, matching the UDP path.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use bonding_protocol::protocol::scheduler::PathId;

use crate::crypto::BondCrypto;

use super::{PathDatagram, PathError, PathResult};

/// Bridge channel capacity. Drop-on-full both directions — the bond owns all
/// recovery (cross-leg ARQ + FEC), so a full bridge channel is path loss like
/// any other and never blocks the reactor. Matches the UDP path's recv depth.
const ATTACHED_CHANNEL_CAPACITY: usize = 1024;

/// The **path-side** endpoints of an attached leg, handed into
/// [`AttachedPath::new`] (via the socket builder's `attachments` map).
///
/// Created together with the bridge-side [`AttachedBridgeEnds`] by
/// [`AttachedChannels::new`] so the channel element type (`Bytes`) lives in one
/// place. Non-`Clone` (it owns an `mpsc::Receiver`), which is exactly why these
/// travel in a separate argument from the `Clone + Debug` `PathConfig`.
pub struct AttachedChannels {
    /// Bond → bridge: the (optionally `0xBD`-sealed) bond datagram the
    /// scheduler emitted on this leg. The bridge drains the paired receiver,
    /// adds the tunnel prefix (+ tunnel AEAD when the bond is unkeyed), and
    /// writes the relay socket.
    outbound: mpsc::Sender<Bytes>,
    /// Bridge → bond: a datagram just arrived from the relay (still
    /// `0xBD`-sealed when the bond is keyed — the recv loop opens it). Drained
    /// by the path recv loop.
    inbound: mpsc::Receiver<Bytes>,
}

/// The **bridge-side** endpoints of an attached leg, handed to the edge's
/// relay bridge. See [`AttachedChannels`].
pub struct AttachedBridgeEnds {
    /// Bridge → bond: `try_send` inbound relay datagrams here (drop-on-full).
    pub to_bond: mpsc::Sender<Bytes>,
    /// Bond → bridge: drain outbound leg datagrams from here.
    pub from_bond: mpsc::Receiver<Bytes>,
}

impl AttachedChannels {
    /// Create a linked channel pair: the path side ([`AttachedChannels`]) and
    /// the bridge side ([`AttachedBridgeEnds`]). Both directions are bounded
    /// and meant to be `try_send`'d (never `await`'d) — drop-on-full.
    pub fn new() -> (AttachedChannels, AttachedBridgeEnds) {
        let (out_tx, out_rx) = mpsc::channel::<Bytes>(ATTACHED_CHANNEL_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(ATTACHED_CHANNEL_CAPACITY);
        (
            AttachedChannels {
                outbound: out_tx,
                inbound: in_rx,
            },
            AttachedBridgeEnds {
                to_bond: in_tx,
                from_bond: out_rx,
            },
        )
    }
}

impl Default for AttachedChannels {
    fn default() -> Self {
        Self::new().0
    }
}

/// A bond leg whose carrier is an in-process bridge, not a socket.
pub struct AttachedPath {
    id: PathId,
    name: String,
    /// Synthetic peer address. The bridge owns the single real relay peer, so
    /// `send_to` ignores its `to` arg — but `primary_peer` MUST return `Some`
    /// or the sender's keepalive loop silently skips this leg (and the
    /// receiver's NACK/keepalive-ack back-channel breaks).
    synthetic_peer: SocketAddr,
    /// Bond → bridge sender. `send_to` seals (`0xBD`) then `try_send`s here.
    outbound: mpsc::Sender<Bytes>,
    /// Internal plaintext datagram queue (post-`0xBD`-open) for the bond
    /// receiver task. Returned once by [`take_rx`](Self::take_rx).
    rx: Mutex<Option<mpsc::Receiver<PathDatagram>>>,
    /// Optional bond AEAD — sealed on send, opened on recv. Identical to the
    /// UDP path (and built from the SAME shared [`BondCrypto`]).
    crypto: Option<Arc<BondCrypto>>,
    _recv_task: JoinHandle<()>,
    _cancel: CancellationToken,
}

impl AttachedPath {
    /// Build an attached path over a bridge channel pair. `synthetic_peer` is
    /// the placeholder address `primary_peer` reports; `crypto` is the shared
    /// bond AEAD (must be the same one the UDP legs got).
    pub fn new(
        id: PathId,
        name: impl Into<String>,
        channels: AttachedChannels,
        synthetic_peer: SocketAddr,
        crypto: Option<Arc<BondCrypto>>,
    ) -> Self {
        let AttachedChannels { outbound, inbound } = channels;
        let (tx, rx) = mpsc::channel::<PathDatagram>(ATTACHED_CHANNEL_CAPACITY);
        let cancel = CancellationToken::new();
        let recv_task = spawn_recv_loop(
            inbound,
            tx,
            synthetic_peer,
            cancel.clone(),
            crypto.clone(),
        );
        Self {
            id,
            name: name.into(),
            synthetic_peer,
            outbound,
            rx: Mutex::new(Some(rx)),
            crypto,
            _recv_task: recv_task,
            _cancel: cancel,
        }
    }

    pub fn id(&self) -> PathId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Send a pre-framed bond datagram to the bridge. The `to` argument is
    /// **ignored** — the bridge owns the single relay peer. Seals the bond
    /// `0xBD` envelope when keyed (exactly like the UDP path), then
    /// `try_send`s drop-on-full (NEVER `await`s).
    pub async fn send_to(&self, data: &[u8], _to: SocketAddr) -> PathResult<()> {
        let frame: Bytes = if let Some(crypto) = &self.crypto {
            let mut sealed = Vec::with_capacity(data.len() + crate::crypto::ENVELOPE_OVERHEAD);
            crypto
                .seal(data, &mut sealed)
                .map_err(|e| PathError::Other(format!("bond seal: {e}")))?;
            Bytes::from(sealed)
        } else {
            Bytes::copy_from_slice(data)
        };
        match self.outbound.try_send(frame) {
            Ok(()) => Ok(()),
            // Bridge backed up — drop, matching every path's loss-on-pressure
            // contract. The bond's ARQ/FEC recovers it.
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            // The bridge task is gone (relay leg torn down): surface so the
            // sender's error path can react. Not a route error → no rebuild.
            Err(mpsc::error::TrySendError::Closed(_)) => Err(PathError::Other(format!(
                "attached path '{}' bridge channel closed",
                self.name
            ))),
        }
    }

    pub async fn send(&self, data: &[u8]) -> PathResult<()> {
        self.send_to(data, self.synthetic_peer).await
    }

    /// Always `Some` — the synthetic peer keeps the keepalive + back-channel
    /// machinery treating this leg as live (a `None` here drops the leg from
    /// aggregation at `sender.rs`'s keepalive gate).
    pub fn primary_peer(&self) -> Option<SocketAddr> {
        Some(self.synthetic_peer)
    }

    /// No-op — the bridge owns the real relay peer; the bond's learned address
    /// is irrelevant because `send_to` ignores its `to`.
    pub fn set_primary_peer(&self, _peer: SocketAddr) {}

    /// Only the bond `0xBD` envelope counts here. The tunnel 16-byte prefix +
    /// per-leg AEAD live below this in the bridge (outside the bond's
    /// accounting), so we report the same overhead as the UDP path: `0` unless
    /// the bond is keyed.
    #[inline]
    pub fn wire_overhead_per_datagram(&self) -> usize {
        if self.crypto.is_some() {
            crate::crypto::ENVELOPE_OVERHEAD
        } else {
            0
        }
    }

    pub fn take_rx(&mut self) -> Option<mpsc::Receiver<PathDatagram>> {
        self.rx.get_mut().take()
    }
}

/// Drain inbound bridge datagrams, open the bond `0xBD` envelope when keyed,
/// and deliver plaintext [`PathDatagram`]s to the bond receiver — mirrors
/// `udp::spawn_recv_loop` with the bridge channel standing in for the socket.
fn spawn_recv_loop(
    mut inbound: mpsc::Receiver<Bytes>,
    tx: mpsc::Sender<PathDatagram>,
    from: SocketAddr,
    cancel: CancellationToken,
    crypto: Option<Arc<BondCrypto>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut plain = Vec::with_capacity(2048);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                maybe = inbound.recv() => {
                    let Some(buf) = maybe else {
                        // Bridge dropped its sender — leg gone.
                        break;
                    };
                    let data = if let Some(crypto) = &crypto {
                        // Drop any datagram that fails authentication — a
                        // wrong-key / tampered / stray packet never reaches the
                        // bond decoder.
                        match crypto.open(&buf, &mut plain) {
                            Ok(()) => Bytes::copy_from_slice(&plain),
                            Err(e) => {
                                log::debug!("attached path: drop undecryptable datagram: {e}");
                                continue;
                            }
                        }
                    } else {
                        buf
                    };
                    if tx.try_send(PathDatagram { data, from }).is_err() {
                        // Bond receiver backed up — drop rather than stall.
                        log::debug!("attached path rx drop (channel full)");
                    }
                }
            }
        }
    })
}

impl std::fmt::Debug for AttachedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachedPath")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("synthetic_peer", &self.synthetic_peer)
            .field("encrypted", &self.crypto.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth() -> SocketAddr {
        "127.0.0.1:9".parse().unwrap()
    }

    fn bond_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(5).wrapping_add(1);
        }
        k
    }

    /// `primary_peer` is always `Some` (the leg must not be skipped at the
    /// keepalive gate), and `send_to` ignores its `to` arg.
    #[tokio::test]
    async fn primary_peer_is_some_and_send_ignores_to() {
        let (chans, mut bridge) = AttachedChannels::new();
        let path = AttachedPath::new(3, "relay-leg", chans, synth(), None);
        assert_eq!(path.primary_peer(), Some(synth()));

        // A wildly different `to` is ignored; the frame still reaches the bridge.
        let bogus: SocketAddr = "203.0.113.99:1234".parse().unwrap();
        path.send_to(b"\xBChello", bogus).await.unwrap();
        let got = bridge.from_bond.recv().await.expect("bridge receives frame");
        assert_eq!(&got[..], b"\xBChello");
    }

    /// Inbound bridge datagrams surface on `take_rx`, tagged with the synthetic
    /// peer so the back-channel reply target is stable.
    #[tokio::test]
    async fn take_rx_delivers_inbound() {
        let (chans, bridge) = AttachedChannels::new();
        let mut path = AttachedPath::new(1, "leg", chans, synth(), None);
        let mut rx = path.take_rx().expect("rx");

        bridge
            .to_bond
            .try_send(Bytes::from_static(b"\xBEcontrol-ack"))
            .unwrap();
        let dg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("within 2s")
            .expect("channel open");
        assert_eq!(&dg.data[..], b"\xBEcontrol-ack");
        assert_eq!(dg.from, synth());
        // Second take is None.
        assert!(path.take_rx().is_none());
    }

    /// 0xBD roundtrip: send_to seals, the bridge carries the sealed bytes, the
    /// recv loop opens them back to the original plaintext.
    #[tokio::test]
    async fn bond_crypto_roundtrip_through_bridge() {
        let crypto = BondCrypto::new(&bond_key()).unwrap();
        // Sender path seals into the bridge.
        let (tx_chans, mut tx_bridge) = AttachedChannels::new();
        let tx_path = AttachedPath::new(0, "tx", tx_chans, synth(), Some(crypto.clone()));
        let msg = b"\xBC\x10\x00\x05inner bond frame";
        tx_path.send_to(msg, synth()).await.unwrap();
        let sealed = tx_bridge.from_bond.recv().await.expect("sealed frame");
        assert_eq!(sealed[0], crate::crypto::ENVELOPE_MAGIC, "sealed 0xBD on the wire");
        assert_ne!(&sealed[..], &msg[..], "ciphertext differs from plaintext");

        // Receiver path opens what the bridge delivers.
        let (rx_chans, rx_bridge) = AttachedChannels::new();
        let mut rx_path = AttachedPath::new(0, "rx", rx_chans, synth(), Some(crypto));
        let mut rx = rx_path.take_rx().expect("rx");
        rx_bridge.to_bond.try_send(sealed).unwrap();
        let dg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("within 2s")
            .expect("channel open");
        assert_eq!(&dg.data[..], msg, "opened back to original plaintext");

        // wire_overhead reflects the bond envelope only.
        assert_eq!(rx_path.wire_overhead_per_datagram(), crate::crypto::ENVELOPE_OVERHEAD);
    }

    /// An undecryptable inbound datagram (wrong key) is dropped, never
    /// delivered to the bond.
    #[tokio::test]
    async fn wrong_key_inbound_is_dropped() {
        let good = BondCrypto::new(&bond_key()).unwrap();
        let mut wrong = bond_key();
        wrong[0] ^= 0xFF;
        let wrong = BondCrypto::new(&wrong).unwrap();

        // Seal with the wrong key, deliver to a path holding the good key.
        let mut sealed = Vec::new();
        wrong.seal(b"\xBCnope", &mut sealed).unwrap();

        let (chans, bridge) = AttachedChannels::new();
        let mut path = AttachedPath::new(0, "leg", chans, synth(), Some(good));
        let mut rx = path.take_rx().expect("rx");
        bridge.to_bond.try_send(Bytes::from(sealed)).unwrap();
        // Nothing decodable arrives.
        let r = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        assert!(r.is_err(), "undecryptable datagram must not be delivered");
    }

    /// `send_to` never blocks when the bridge channel is full — it drops and
    /// returns Ok (drop-on-full), never `await`s.
    #[tokio::test]
    async fn send_to_drops_on_full_never_blocks() {
        let (chans, _bridge) = AttachedChannels::new();
        let path = AttachedPath::new(0, "leg", chans, synth(), None);
        // Fill the channel beyond capacity without draining `_bridge.from_bond`.
        for _ in 0..(ATTACHED_CHANNEL_CAPACITY + 64) {
            // Each call must complete promptly (drop-on-full), never hang.
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                path.send_to(b"\xBCx", synth()),
            )
            .await
            .expect("send_to must not block")
            .expect("send_to returns Ok on full (drop)");
        }
    }
}
