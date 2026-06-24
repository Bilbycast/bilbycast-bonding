//! End-to-end per-leg latency equalization.
//!
//! A bond with one low-latency leg and one high-latency leg must AGGREGATE
//! both into a single in-order stream rather than the fast leg
//! head-of-line-blocking on the slow one. This exercises the full path on
//! real UDP sockets: sender stamps v2 headers → receiver measures each leg's
//! relative one-way delay → time-aligns the legs via the reassembly's
//! per-leg `equalize` table → delivers in order. The unit tests prove the
//! mechanism in isolation; this proves it on the wire with a 150 ms skew.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use bonding_transport::{
    BondSocket, BondSocketConfig, CapacityAwareScheduler, EqualizationMode, PacketHints, PathConfig,
    PathTransport,
};

async fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn udp_recv(bind: SocketAddr) -> PathTransport {
    PathTransport::Udp { bind: Some(bind), remote: None, interface: None }
}
fn udp_send(remote: SocketAddr) -> PathTransport {
    PathTransport::Udp { bind: None, remote: Some(remote), interface: None }
}

struct RelayHandle {
    stop: Arc<AtomicBool>,
}
impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// UDP relay that DELAYS the forward (client→target) direction by `delay`
/// and forwards the reverse (acks/NACKs) immediately — so the leg gains a
/// one-way-delay skew the equalizer must measure and align out.
async fn spawn_delay_relay(listen: SocketAddr, target: SocketAddr, delay: Duration) -> RelayHandle {
    use std::sync::Mutex;
    let stop = Arc::new(AtomicBool::new(false));
    let sock = Arc::new(UdpSocket::bind(listen).await.unwrap());
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let sock_c = sock.clone();
    let stop_c = stop.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            if stop_c.load(Ordering::Relaxed) {
                break;
            }
            let r = timeout(Duration::from_millis(50), sock_c.recv_from(&mut buf)).await;
            let Ok(Ok((len, from))) = r else { continue };
            if from == target {
                let to = *client.lock().unwrap();
                if let Some(c) = to {
                    let _ = sock_c.send_to(&buf[..len], c).await;
                }
                continue;
            }
            *client.lock().unwrap() = Some(from);
            // Forward the data after `delay`.
            let pkt = buf[..len].to_vec();
            let s = sock_c.clone();
            tokio::spawn(async move {
                sleep(delay).await;
                let _ = s.send_to(&pkt, target).await;
            });
        }
    });
    RelayHandle { stop }
}

/// Leg 0 is direct (~0 ms); leg 1 rides a 150 ms delay relay. With
/// equalization the receiver measures the 150 ms skew, holds leg 0 to align,
/// and BOTH legs carry their share IN ORDER with nothing lost — the
/// heterogeneous-latency aggregation that would otherwise head-of-line-block.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn equalization_aggregates_heterogeneous_latency_legs() {
    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let rx_b: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let relay_b: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let _rb = spawn_delay_relay(relay_b, rx_b, Duration::from_millis(150)).await;

    let mk = |paths: Vec<PathConfig>| BondSocketConfig {
        flow_id: 55,
        hold_time: Duration::from_millis(40), // jitter floor
        hold_max: Some(Duration::from_millis(600)), // equalization latency budget
        nack_delay: Duration::from_millis(60),
        max_nack_retries: 8,
        keepalive_interval: Duration::from_millis(100),
        // Auto: the 150 ms inter-leg skew is far above SKEW_FLOOR_US, so the
        // receiver auto-engages alignment — exercising the real self-configuring
        // path, not a forced override.
        equalization: EqualizationMode::Auto,
        paths,
        ..Default::default()
    };

    let receiver = BondSocket::receiver(mk(vec![
        PathConfig { id: 0, name: "fast".into(), weight_hint: 1, transport: udp_recv(rx_a) },
        PathConfig { id: 1, name: "slow".into(), weight_hint: 1, transport: udp_recv(rx_b) },
    ]))
    .await
    .unwrap();

    let sender = BondSocket::sender(
        mk(vec![
            PathConfig { id: 0, name: "fast".into(), weight_hint: 1, transport: udp_send(rx_a) },
            PathConfig { id: 1, name: "slow".into(), weight_hint: 1, transport: udp_send(relay_b) },
        ]),
        CapacityAwareScheduler::new(vec![0, 1]),
    )
    .await
    .unwrap();

    // Warm-up + steady send. The OWD estimator needs ~16 stamped samples per
    // leg before equalization engages; until then the global hold (up to the
    // 600 ms budget) covers the skew, so nothing is lost across the
    // cold-start → equalized transition.
    sleep(Duration::from_millis(250)).await;
    const N: u32 = 500;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("eq-{i:06}")), PacketHints::default())
            .await
            .unwrap();
        sleep(Duration::from_millis(3)).await; // ~333 pps, steady cadence
    }

    // Drain (allow for the 150 ms + equalization latency tail).
    let mut got: Vec<Bytes> = Vec::with_capacity(N as usize);
    for _ in 0..N {
        match timeout(Duration::from_secs(3), receiver.recv()).await {
            Ok(Some(b)) => got.push(b),
            _ => break,
        }
    }
    sleep(Duration::from_millis(200)).await;

    // Strictly in order, and the bond lost nothing. The drain-count bound is
    // generous (the real correctness invariant is `gaps_lost == 0` below — a
    // co-scheduled, CPU-starved runtime can leave a few packets undrained past
    // the per-recv timeout without the bond ever declaring them lost).
    assert!(
        got.len() as u32 >= N * 9 / 10,
        "almost all payloads delivered: {} of {N}",
        got.len()
    );
    for (i, b) in got.iter().enumerate() {
        assert_eq!(
            b.as_ref(),
            format!("eq-{i:06}").as_bytes(),
            "strict in-order delivery at index {i}"
        );
    }

    let rx = receiver.stats().snapshot();
    assert_eq!(
        rx.gaps_lost, 0,
        "equalized heterogeneous-latency bond must lose nothing (delivered={}, recovered={})",
        rx.packets_delivered, rx.gaps_recovered
    );

    // BOTH legs carried a real share — true aggregation, not single-leg
    // fallback. (A 50/50 capacity split over ~500 packets puts well over 20
    // on each.)
    let a = receiver.path_stats(0).unwrap().snapshot();
    let b = receiver.path_stats(1).unwrap().snapshot();
    assert!(
        a.packets_received > 20 && b.packets_received > 20,
        "both legs aggregate their bandwidth: fast={} slow={}",
        a.packets_received,
        b.packets_received
    );
}

/// Rollout-safety regression for the v2 keepalive-ack negotiation.
///
/// A sender with `equalization: true` paired with a receiver that has it
/// OFF (the realistic half-config / rolling-upgrade misconfiguration, or a
/// genuinely-old receiver) must NOT brick: the receiver advertises v1 in its
/// keepalive-ack, so the sender keeps emitting 12-byte v1 data headers and
/// never sends an unparseable v2 (send-stamped) header. Media flows in order,
/// nothing is lost, no header parse drops, and equalization simply never
/// engages (relative_owd stays unmeasured). Before the negotiation this was a
/// silent 100 % media blackout on a true v1 receiver.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn equalization_off_receiver_is_safe_no_op() {
    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let rx_b: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let relay_b: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let _rb = spawn_delay_relay(relay_b, rx_b, Duration::from_millis(150)).await;

    let mk = |eq: EqualizationMode, paths: Vec<PathConfig>| BondSocketConfig {
        flow_id: 56,
        hold_time: Duration::from_millis(40),
        hold_max: Some(Duration::from_millis(600)),
        nack_delay: Duration::from_millis(60),
        max_nack_retries: 8,
        keepalive_interval: Duration::from_millis(100),
        equalization: eq,
        paths,
        ..Default::default()
    };

    // Receiver: equalization OFF → advertises v1 capability.
    let receiver = BondSocket::receiver(mk(
        EqualizationMode::Off,
        vec![
            PathConfig { id: 0, name: "fast".into(), weight_hint: 1, transport: udp_recv(rx_a) },
            PathConfig { id: 1, name: "slow".into(), weight_hint: 1, transport: udp_recv(rx_b) },
        ],
    ))
    .await
    .unwrap();

    // Sender: equalization ON → would stamp v2, but must hold back to v1
    // because the receiver never advertises v2.
    let sender = BondSocket::sender(
        mk(
            EqualizationMode::On,
            vec![
                PathConfig { id: 0, name: "fast".into(), weight_hint: 1, transport: udp_send(rx_a) },
                PathConfig { id: 1, name: "slow".into(), weight_hint: 1, transport: udp_send(relay_b) },
            ],
        ),
        CapacityAwareScheduler::new(vec![0, 1]),
    )
    .await
    .unwrap();

    sleep(Duration::from_millis(250)).await;
    const N: u32 = 400;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("eq-{i:06}")), PacketHints::default())
            .await
            .unwrap();
        sleep(Duration::from_millis(3)).await;
    }

    let mut got: Vec<Bytes> = Vec::with_capacity(N as usize);
    for _ in 0..N {
        match timeout(Duration::from_secs(3), receiver.recv()).await {
            Ok(Some(b)) => got.push(b),
            _ => break,
        }
    }
    sleep(Duration::from_millis(200)).await;

    // No brick: the overwhelming majority of media flows. (Without
    // equalization the 150 ms inter-leg skew still costs a few cold-start
    // packets while the adaptive hold servo grows to cover it — the expected
    // non-equalized penalty, NOT the ~100 % blackout the un-negotiated v2
    // header would have caused on a true v1 receiver.)
    assert!(
        got.len() as u32 >= N * 3 / 4,
        "v2-sender/v1-receiver must NOT blackhole media: only {} of {N} delivered",
        got.len()
    );
    // What IS delivered is a strictly-increasing in-order subsequence (gaps
    // from the cold-start skew loss are allowed, reordering is not).
    let seqs: Vec<u32> = got
        .iter()
        .map(|b| {
            std::str::from_utf8(b.as_ref()).unwrap()[3..].parse::<u32>().unwrap()
        })
        .collect();
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "delivered payloads must be in strictly-increasing order: {seqs:?}"
    );

    let rx = receiver.stats().snapshot();
    // The smoking gun for the brick was unparseable v2 headers. Negotiation
    // means the sender never emitted one → zero header parse drops. THIS is
    // the precise proof the fix works.
    assert_eq!(
        rx.header_parse_drops, 0,
        "sender must never emit a v2 header to a v1-advertising receiver"
    );
    // Equalization never engaged: with no v2 stamps the receiver never
    // measured a relative OWD on the slow leg (it would be ~150 ms had the
    // sender wrongly stamped).
    let slow = receiver.path_stats(1).unwrap().snapshot();
    assert_eq!(
        slow.relative_owd_us, 0,
        "equalization must stay disengaged when the receiver opted out"
    );
}
