//! Session-epoch + ARQ-correctness integration tests for `BondSocket`.
//!
//! Exercises the sender → receiver pipeline on localhost and validates:
//!
//! - A restarted sender (fresh random session epoch on the same paths)
//!   triggers exactly one receiver-side session reset and delivery
//!   resumes — instead of every new-instance packet dropping as stale
//!   against the old reassembly anchor.
//! - A single spoofed keepalive bearing a foreign epoch does NOT reset
//!   the session (2 consecutive control packets are required, and the
//!   real sender's keepalives clear the candidate in between).
//! - A scheduler `Drop` selection consumes no bond_seq: the keepalive
//!   tip equals the highest actually-sent seq, so the receiver never
//!   NACKs (nor ages out as lost) packets that never existed.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use bonding_protocol::control::{CtrlHeader, CtrlPacket, CtrlType, KeepaliveBody, NackBody};
use bonding_transport::{
    BondScheduler, BondSocket, BondSocketConfig, PacketHints, PathConfig, PathEventKind,
    PathId, PathSelection, PathTransport, WeightedRttScheduler,
};

/// Find an available local UDP port by binding ephemerally. The
/// returned address is safe to re-bind immediately within the test
/// because `SO_REUSEADDR` is set on every path socket.
async fn free_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.local_addr().unwrap().port()
}

fn udp_recv_path(id: PathId, name: &str, bind: SocketAddr) -> PathConfig {
    PathConfig {
        id,
        name: name.into(),
        weight_hint: 1,
        transport: PathTransport::Udp {
            bind: Some(bind),
            remote: None,
            interface: None,
        },
    }
}

fn udp_send_path(id: PathId, name: &str, remote: SocketAddr) -> PathConfig {
    PathConfig {
        id,
        name: name.into(),
        weight_hint: 1,
        transport: PathTransport::Udp {
            bind: None,
            remote: Some(remote),
            interface: None,
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sender_restart_resets_session_and_resumes() {
    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let rx_b: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 7,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_recv_path(0, "a", rx_a), udp_recv_path(1, "b", rx_b)],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();
    // Subscribe before the restart so the SessionReset event is captured.
    let mut events = receiver.subscribe_events();

    let tx_cfg = BondSocketConfig {
        flow_id: 7,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_send_path(0, "a", rx_a), udp_send_path(1, "b", rx_b)],
        ..Default::default()
    };

    // ── Session 1: traffic flows, first epoch adopted with NO reset ──
    let sender1 = BondSocket::sender(tx_cfg.clone(), WeightedRttScheduler::new(vec![0, 1]))
        .await
        .unwrap();
    const N: u32 = 50;
    // Let the very first packet anchor the reassembly buffer before
    // bursting: with two paths racing on a multi-thread runtime, seq 1
    // can beat seq 0 and the buffer anchors past it (pre-existing
    // first-arrival anchoring, same artifact the lossy e2e test
    // tolerates). Not what this test is probing.
    sender1
        .send(Bytes::from(format!("s1-{:06}", 0)), PacketHints::default())
        .await
        .unwrap();
    sleep(Duration::from_millis(50)).await;
    for i in 1..N {
        sender1
            .send(Bytes::from(format!("s1-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }
    for _ in 0..N {
        timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("session-1 recv timed out")
            .expect("channel closed");
    }
    assert_eq!(
        receiver.stats().snapshot().session_resets,
        0,
        "adopting the first epoch must not count as a reset"
    );

    // ── Restart: drop sender 1, bring up sender 2 on the same paths ──
    sender1.close();
    drop(sender1);
    sleep(Duration::from_millis(100)).await;

    let sender2 = BondSocket::sender(tx_cfg, WeightedRttScheduler::new(vec![0, 1]))
        .await
        .unwrap();

    // Keep offering traffic; the receiver must adopt the new epoch
    // (2 consecutive keepalives), re-anchor, and resume delivery
    // within ~2 s. Without the reset every new-instance packet is
    // stale against the old anchor (seq ~49 vs fresh seq 0) forever.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut resumed = false;
    let mut i = 0u32;
    while Instant::now() < deadline {
        sender2
            .send(Bytes::from(format!("s2-{i:06}")), PacketHints::default())
            .await
            .unwrap();
        i += 1;
        if let Ok(Some(b)) = timeout(Duration::from_millis(50), receiver.recv()).await {
            if b.starts_with(b"s2-") {
                resumed = true;
                break;
            }
        }
    }
    assert!(resumed, "delivery did not resume within 2 s of sender restart");

    let stats = receiver.stats().snapshot();
    assert_eq!(stats.session_resets, 1, "exactly one session reset expected");
    // Hold telemetry mirrors the configured (fixed) hold time.
    assert_eq!(stats.current_hold_ms, 100);

    let mut saw_reset = false;
    while let Ok(ev) = events.try_recv() {
        if matches!(ev.kind, PathEventKind::SessionReset { .. }) {
            saw_reset = true;
        }
    }
    assert!(saw_reset, "SessionReset event not observed on the event bus");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_spurious_epoch_keepalive_does_not_reset() {
    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 9,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_recv_path(0, "a", rx_a)],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    let tx_cfg = BondSocketConfig {
        flow_id: 9,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_send_path(0, "a", rx_a)],
        ..Default::default()
    };
    let sender = BondSocket::sender(tx_cfg, WeightedRttScheduler::new(vec![0]))
        .await
        .unwrap();

    const N: u32 = 20;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("p-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }
    for _ in 0..N {
        timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
    }

    // Forge ONE keepalive bearing a foreign epoch (a stray datagram
    // from a dead process, a port-scan echo, …). The real sender's
    // keepalives (every 100 ms, genuine epoch) clear the candidate, so
    // no second consecutive foreign-epoch packet can ever accumulate.
    let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = CtrlPacket::Keepalive {
        header: CtrlHeader::new(CtrlType::Keepalive, 0, 9),
        body: KeepaliveBody {
            stamp_us: 1,
            packets_sent_on_path: 0,
            highest_bond_seq_sent: 0,
            bytes_sent_on_path: 0,
            session_epoch: 0x7e57_e90c,
            mode_flags: 0,
        },
    };
    let mut buf = BytesMut::new();
    pkt.serialize(&mut buf);
    spoof.send_to(&buf, rx_a).await.unwrap();

    // A few real keepalive intervals so the candidate is cleared.
    sleep(Duration::from_millis(400)).await;

    // Traffic still flows in order on the original session.
    for i in 0..N {
        sender
            .send(Bytes::from(format!("q-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }
    for i in 0..N {
        let b = timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("post-spoof recv timed out")
            .expect("channel closed");
        assert_eq!(b.as_ref(), format!("q-{i:06}").as_bytes());
    }
    assert_eq!(
        receiver.stats().snapshot().session_resets,
        0,
        "one spoofed keepalive must not reset the session"
    );
}

/// Two forged keepalives sent back-to-back must NOT hijack the session.
///
/// The corroboration rule used to be "two *consecutive* control packets
/// carrying the same new epoch", with no timing constraint: a burst of
/// two forged keepalives ~1 µs apart (≈82 bytes, no key, no state) beat
/// the real sender's 100–200 ms keepalive cadence every time. Adoption
/// then retired the genuine sender's epoch into a **permanent**
/// quarantine, so its keepalives hit a no-op and were dropped before the
/// ack — the sender missed `keepalive_miss_threshold` acks on every leg,
/// marked them all dead, and the scheduler dropped every packet:
/// permanent media outage on a live bonded input.
///
/// Adoption now also requires the pair to straddle a keepalive interval,
/// which the live sender's own keepalives interrupt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_keepalive_burst_does_not_hijack_the_session() {
    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 23,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_recv_path(0, "a", rx_a)],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    let tx_cfg = BondSocketConfig {
        flow_id: 23,
        keepalive_interval: Duration::from_millis(100),
        keepalive_miss_threshold: 3,
        paths: vec![udp_send_path(0, "a", rx_a)],
        ..Default::default()
    };
    let sender = BondSocket::sender(tx_cfg, WeightedRttScheduler::new(vec![0]))
        .await
        .unwrap();

    const N: u32 = 20;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("p-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }
    for _ in 0..N {
        timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
    }

    // The attack: two identical forged keepalives, one flush apart.
    let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = CtrlPacket::Keepalive {
        header: CtrlHeader::new(CtrlType::Keepalive, 0, 23),
        body: KeepaliveBody {
            stamp_us: 1,
            packets_sent_on_path: 0,
            highest_bond_seq_sent: 900_000,
            bytes_sent_on_path: 0,
            session_epoch: 0x1337_c0de,
            mode_flags: 0,
        },
    };
    let mut buf = BytesMut::new();
    pkt.serialize(&mut buf);
    spoof.send_to(&buf, rx_a).await.unwrap();
    spoof.send_to(&buf, rx_a).await.unwrap();

    // Long enough for the sender to have missed 3 keepalive-acks had the
    // hijack landed (3 × 100 ms), plus margin.
    sleep(Duration::from_millis(700)).await;

    for i in 0..N {
        sender
            .send(Bytes::from(format!("q-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }
    for i in 0..N {
        let b = timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("post-forgery recv timed out — the bond went silent")
            .expect("channel closed");
        assert_eq!(b.as_ref(), format!("q-{i:06}").as_bytes());
    }
    assert_eq!(
        receiver.stats().snapshot().session_resets,
        0,
        "a forged keepalive burst hijacked the session epoch"
    );
    // The sender's leg must still be alive — that is the mechanism that
    // turned the hijack into a total outage.
    assert!(
        !sender.path_stats(0).unwrap().snapshot().dead,
        "sender leg died: the receiver stopped acking the genuine keepalives"
    );
}

/// A stray control-magic byte must not repoint NACK carriage.
///
/// The receiver used to call `set_primary_peer(dg.from)` for every
/// inbound datagram that passed `is_control()` — a **one-byte magic
/// test**, before any parse, flow_id check or epoch check. NACKs are
/// carried to `primary_peer`, so anyone able to send `0xBE` at the leg's
/// port could repoint the whole ARQ back-channel at themselves and
/// silently blackhole retransmit requests: loss stops being recovered
/// while every counter still looks healthy. Peer learning is now gated
/// on a datagram that parses as a keepalive for our flow bearing our
/// session epoch.
///
/// Topology: sender → shim (drops every 10th forward packet) → receiver,
/// with a third socket spraying `0xBE` at the receiver's leg throughout.
/// Every payload must still arrive, which requires the NACKs to have
/// reached the real sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stray_control_byte_does_not_steal_nack_carriage() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let shim_addr: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    // Bidirectional shim: forward drops every 10th data-ish datagram so
    // real gaps appear; the reverse direction (NACKs) is forwarded
    // verbatim to whoever last sent forward traffic.
    let stop = Arc::new(AtomicBool::new(false));
    let shim = Arc::new(UdpSocket::bind(shim_addr).await.unwrap());
    {
        let shim = shim.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut client: Option<SocketAddr> = None;
            let mut n: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                let Ok(Ok((len, from))) =
                    timeout(Duration::from_millis(50), shim.recv_from(&mut buf)).await
                else {
                    continue;
                };
                if from == rx_a {
                    if let Some(c) = client {
                        let _ = shim.send_to(&buf[..len], c).await;
                    }
                    continue;
                }
                client = Some(from);
                // Only shed fresh media (0xBC, not RETRANSMIT-flagged);
                // never a keepalive or a resend, or the test measures
                // liveness/ARQ-retry instead of NACK carriage.
                let is_fresh_data = buf[0] == 0xBC && (buf[1] & 0x0F) & 0x1 == 0;
                if is_fresh_data {
                    n += 1;
                    if n.is_multiple_of(10) {
                        continue;
                    }
                }
                let _ = shim.send_to(&buf[..len], rx_a).await;
            }
        });
    }

    // Spray a bare control-magic byte at the receiver's leg for the whole
    // run — the old code adopted the sprayer as the NACK peer.
    {
        let stop = stop.clone();
        tokio::spawn(async move {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            while !stop.load(Ordering::Relaxed) {
                let _ = sock.send_to(&[0xBEu8], rx_a).await;
                sleep(Duration::from_millis(1)).await;
            }
        });
    }

    let rx_cfg = BondSocketConfig {
        flow_id: 29,
        hold_time: Duration::from_millis(2000),
        nack_delay: Duration::from_millis(30),
        max_nack_retries: 16,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_recv_path(0, "a", rx_a)],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    let tx_cfg = BondSocketConfig {
        flow_id: 29,
        keepalive_interval: Duration::from_millis(100),
        retransmit_capacity: 4096,
        paths: vec![udp_send_path(0, "a", shim_addr)],
        ..Default::default()
    };
    let sender = BondSocket::sender(tx_cfg, WeightedRttScheduler::new(vec![0]))
        .await
        .unwrap();

    const N: u32 = 200;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("n-{i:06}")), PacketHints::default())
            .await
            .unwrap();
        sleep(Duration::from_millis(2)).await;
    }
    for i in 0..N {
        let b = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("payload {i} never arrived — NACKs went to the sprayer"))
            .expect("channel closed");
        assert_eq!(b.as_ref(), format!("n-{i:06}").as_bytes());
    }
    stop.store(true, Ordering::Relaxed);
    let rx_stats = receiver.stats().snapshot();
    assert_eq!(rx_stats.gaps_lost, 0, "gaps aged out unrecovered");
    assert!(
        sender.stats().snapshot().packets_retransmitted > 0,
        "the shim never shed anything — test would be vacuous"
    );
}

/// A NACK bearing a foreign `flow_id` must drive no retransmits.
///
/// The sender matched `Ok(CtrlPacket::Nack { body, .. })` and discarded
/// the header, so any datagram that parsed as a NACK was served for
/// whatever flow this sender happened to be running — the mirror image
/// of a check the receiver has always applied to inbound keepalives. A
/// NACK carries no session epoch, so `flow_id` is the only thing there
/// is to reject it with: forged ones drive real resends, debit the
/// congestion controller's token bucket for bandwidth nobody asked for,
/// and inflate `packets_retransmitted`. The same header check now
/// guards `KeepaliveAck`, which feeds `ack_delivery` and can revive a
/// leg the sender had correctly written off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_flow_id_nack_drives_no_retransmits() {
    const FLOW: u32 = 31;
    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    // The sender binds a known port so the forgery has somewhere to go.
    let tx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: FLOW,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_recv_path(0, "a", rx_a)],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    let tx_cfg = BondSocketConfig {
        flow_id: FLOW,
        keepalive_interval: Duration::from_millis(100),
        retransmit_capacity: 1024,
        paths: vec![PathConfig {
            id: 0,
            name: "a".into(),
            weight_hint: 1,
            transport: PathTransport::Udp {
                bind: Some(tx_a),
                remote: Some(rx_a),
                interface: None,
            },
        }],
        ..Default::default()
    };
    let sender = BondSocket::sender(tx_cfg, WeightedRttScheduler::new(vec![0]))
        .await
        .unwrap();

    const N: u32 = 32;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("r-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }
    for _ in 0..N {
        timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
    }
    assert_eq!(
        sender.stats().snapshot().packets_retransmitted,
        0,
        "loopback shed packets — the test cannot attribute retransmits"
    );

    let forge = |flow: u32| {
        let mut buf = BytesMut::new();
        CtrlPacket::Nack {
            header: CtrlHeader::new(CtrlType::Nack, 0, flow),
            body: NackBody { missing: (0..8).collect() },
        }
        .serialize(&mut buf);
        buf
    };
    let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Someone else's flow: every one of these must be dropped.
    let foreign = forge(FLOW ^ 0xFFFF);
    for _ in 0..5 {
        spoof.send_to(&foreign, tx_a).await.unwrap();
        sleep(Duration::from_millis(20)).await;
    }
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        sender.stats().snapshot().packets_retransmitted,
        0,
        "a NACK for a foreign flow_id drove retransmits on this one"
    );

    // Our flow, same seqs: served — otherwise the assertion above only
    // proves ARQ is broken.
    let ours = forge(FLOW);
    spoof.send_to(&ours, tx_a).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut served = 0;
    while Instant::now() < deadline {
        served = sender.stats().snapshot().packets_retransmitted;
        if served > 0 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(served > 0, "ARQ is dead: our own flow's NACK was ignored too");
}

/// Drops every second packet at the scheduler — emulates the capacity
/// scheduler shedding under over-subscription.
struct DropEveryOther {
    ctr: u64,
}

impl BondScheduler for DropEveryOther {
    fn path_ids(&self) -> Vec<PathId> {
        vec![0]
    }
    fn schedule(&mut self, _hints: &PacketHints) -> PathSelection {
        self.ctr += 1;
        if self.ctr % 2 == 0 {
            PathSelection::Drop
        } else {
            PathSelection::Single(0)
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_selection_consumes_no_seq() {
    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 11,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(100),
        nack_delay: Duration::from_millis(30),
        paths: vec![udp_recv_path(0, "a", rx_a)],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    let tx_cfg = BondSocketConfig {
        flow_id: 11,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_send_path(0, "a", rx_a)],
        ..Default::default()
    };
    let sender = BondSocket::sender(tx_cfg, DropEveryOther { ctr: 0 })
        .await
        .unwrap();

    const N: u32 = 100;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("d-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }

    // Exactly the odd schedule() calls (payloads 0, 2, 4, …) were sent;
    // they must arrive gap-free because dropped packets consumed no seq.
    for i in (0..N).step_by(2) {
        let b = timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert_eq!(b.as_ref(), format!("d-{i:06}").as_bytes());
    }

    // Give the keepalive tail-gap machinery time to misfire if the
    // advertised tip included consumed-but-never-sent seqs (the old
    // bug: tip 99 vs highest-sent 49 → 50 phantom gaps, 8 NACK rounds
    // each, then 50 gaps_lost after the hold).
    sleep(Duration::from_millis(700)).await;

    let rx_stats = receiver.stats().snapshot();
    assert_eq!(rx_stats.packets_delivered, (N / 2) as u64);
    assert_eq!(
        rx_stats.gaps_lost, 0,
        "dropped packets must not age out as phantom losses"
    );
    let rx_path = receiver.path_stats(0).unwrap().snapshot();
    assert!(
        rx_path.nacks_sent <= 8,
        "phantom-gap NACK storm: nacks_sent={} (expected ~0, the old bug produced ~400)",
        rx_path.nacks_sent
    );

    let tx_stats = sender.stats().snapshot();
    assert_eq!(tx_stats.packets_dropped_no_path, (N / 2) as u64);
    assert_eq!(tx_stats.packets_sent, (N / 2) as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn epochless_anchor_then_epoched_sender_resets() {
    use bonding_protocol::packet::{BondHeader, Priority, write_packet};

    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 13,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_recv_path(0, "a", rx_a)],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    // Epoch-less "v2" sender: raw data packets anchored HIGH in the
    // bond_seq space (a long-lived instance days into its uptime).
    // The rolling-upgrade order this guards: receiver upgraded first
    // (fresh, epoch 0), v2 sender anchors it high, then the sender is
    // upgraded — its v3 instance restarts bond_seq near 0 and carries
    // the first nonzero epoch the receiver has ever seen.
    let v2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut raw = BytesMut::new();
    for i in 0..20u32 {
        let header = BondHeader::new(13, 500_000_000 + i, 0, Priority::Normal);
        write_packet(&header, format!("v2-{i:06}").as_bytes(), &mut raw);
        v2.send_to(&raw, rx_a).await.unwrap();
    }
    for _ in 0..20 {
        timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("v2 recv timed out")
            .expect("channel closed");
    }

    // The upgraded sender: fresh epoch, seqs near 0 — every packet is
    // stale against the 500M anchor unless the first-epoch path runs
    // the reset machinery (silent adoption bricks the bond for days).
    let tx_cfg = BondSocketConfig {
        flow_id: 13,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_send_path(0, "a", rx_a)],
        ..Default::default()
    };
    let sender = BondSocket::sender(tx_cfg, WeightedRttScheduler::new(vec![0]))
        .await
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut resumed = false;
    let mut i = 0u32;
    while Instant::now() < deadline {
        sender
            .send(Bytes::from(format!("s3-{i:06}")), PacketHints::default())
            .await
            .unwrap();
        i += 1;
        if let Ok(Some(b)) = timeout(Duration::from_millis(50), receiver.recv()).await {
            if b.starts_with(b"s3-") {
                resumed = true;
                break;
            }
        }
    }
    assert!(resumed, "delivery did not resume within 2 s of the v2->v3 sender upgrade");
    assert_eq!(
        receiver.stats().snapshot().session_resets,
        1,
        "first epoch over a foreign anchor must reset, not silently adopt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_epoch_keepalives_after_reset_are_quarantined() {
    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 17,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(100),
        nack_delay: Duration::from_millis(30),
        paths: vec![udp_recv_path(0, "a", rx_a)],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();
    let mut events = receiver.subscribe_events();

    let tx_cfg = BondSocketConfig {
        flow_id: 17,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_send_path(0, "a", rx_a)],
        ..Default::default()
    };

    // Session 1 → restart → session 2 (one genuine reset).
    let sender1 = BondSocket::sender(tx_cfg.clone(), WeightedRttScheduler::new(vec![0]))
        .await
        .unwrap();
    for i in 0..20u32 {
        sender1
            .send(Bytes::from(format!("s1-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }
    for _ in 0..20 {
        timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("session-1 recv timed out")
            .expect("channel closed");
    }
    sender1.close();
    drop(sender1);
    sleep(Duration::from_millis(100)).await;

    let sender2 = BondSocket::sender(tx_cfg, WeightedRttScheduler::new(vec![0]))
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut resumed = false;
    let mut i = 0u32;
    while Instant::now() < deadline {
        sender2
            .send(Bytes::from(format!("s2-{i:06}")), PacketHints::default())
            .await
            .unwrap();
        i += 1;
        if let Ok(Some(b)) = timeout(Duration::from_millis(50), receiver.recv()).await {
            if b.starts_with(b"s2-") {
                resumed = true;
                break;
            }
        }
    }
    assert!(resumed, "delivery did not resume after restart");

    // Learn the retired epoch from the SessionReset event.
    let mut old_epoch = 0u32;
    while let Ok(ev) = events.try_recv() {
        if let PathEventKind::SessionReset { old_epoch: o, .. } = ev.kind {
            old_epoch = o;
        }
    }
    assert_ne!(old_epoch, 0, "no SessionReset observed for the restart");

    // A bufferbloated leg drains TWO queued old-instance keepalives in
    // a burst, carrying the retired epoch and the old (high) tip.
    // Neither may flip the session back, and the foreign tip must not
    // reach advance_to_peer_tip (it would expose ~50k phantom gaps and
    // a NACK storm against seqs the live sender never produced).
    let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = CtrlPacket::Keepalive {
        header: CtrlHeader::new(CtrlType::Keepalive, 0, 17),
        body: KeepaliveBody {
            stamp_us: 1,
            packets_sent_on_path: 9999,
            highest_bond_seq_sent: 50_000,
            bytes_sent_on_path: 0,
            session_epoch: old_epoch,
            mode_flags: 0,
        },
    };
    let mut buf = BytesMut::new();
    pkt.serialize(&mut buf);
    spoof.send_to(&buf, rx_a).await.unwrap();
    spoof.send_to(&buf, rx_a).await.unwrap();

    // Let NACK scheduling fire if the tip leaked through.
    sleep(Duration::from_millis(500)).await;

    // Traffic still flows on session 2; no second reset; no storm.
    for i in 0..20u32 {
        sender2
            .send(Bytes::from(format!("q2-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }
    let mut got = 0;
    while got < 20 {
        let b = timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("post-spoof recv timed out")
            .expect("channel closed");
        if b.starts_with(b"q2-") {
            got += 1;
        }
    }
    let stats = receiver.stats().snapshot();
    assert_eq!(stats.session_resets, 1, "stale-epoch burst flipped the session back");
    let rx_path = receiver.path_stats(0).unwrap().snapshot();
    assert!(
        rx_path.nacks_sent <= 8,
        "foreign-epoch tip poisoned the buffer: nacks_sent={}",
        rx_path.nacks_sent
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_flood_forces_reanchor_on_sender_rollback() {
    use bonding_protocol::packet::{BondHeader, Priority, write_packet};

    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 19,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_recv_path(0, "a", rx_a)],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    // v3 session: receiver adopts an epoch, anchors near 0.
    let tx_cfg = BondSocketConfig {
        flow_id: 19,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![udp_send_path(0, "a", rx_a)],
        ..Default::default()
    };
    let sender = BondSocket::sender(tx_cfg, WeightedRttScheduler::new(vec![0]))
        .await
        .unwrap();
    for i in 0..20u32 {
        sender
            .send(Bytes::from(format!("s1-{i:06}")), PacketHints::default())
            .await
            .unwrap();
    }
    for _ in 0..20 {
        timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
    }
    sender.close();
    drop(sender);
    sleep(Duration::from_millis(100)).await;

    // Rollback: an epoch-less "v2" build comes back in a FOREIGN seq
    // space (behind the anchor) — every insert is stale and, with
    // epoch 0 on its keepalives, the epoch reset path can never fire.
    // The stale-flood watchdog (3 s / 100 packets of 100% stale) must
    // force a re-anchor instead of staying bricked.
    let v2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut raw = BytesMut::new();
    let mut delivered = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seq: u32 = 3_000_000_000;
    let recv_pump = async {
        loop {
            if let Some(b) = receiver.recv().await {
                if b.starts_with(b"v2-") {
                    return true;
                }
            } else {
                return false;
            }
        }
    };
    tokio::pin!(recv_pump);
    while Instant::now() < deadline {
        let header = BondHeader::new(19, seq, 0, Priority::Normal);
        write_packet(&header, format!("v2-{seq:010}").as_bytes(), &mut raw);
        v2.send_to(&raw, rx_a).await.unwrap();
        seq = seq.wrapping_add(1);
        tokio::select! {
            ok = &mut recv_pump => {
                delivered = ok;
                break;
            }
            _ = sleep(Duration::from_millis(20)) => {}
        }
    }
    assert!(
        delivered,
        "rollback sender never delivered — stale-flood watchdog did not re-anchor"
    );
    let stats = receiver.stats().snapshot();
    assert_eq!(stats.session_resets, 1, "expected exactly the forced re-anchor reset");
}
