//! End-to-end tests for the capacity-aware adaptive bond + encryption.
//!
//! These exercise the *full feedback loop* over real UDP sockets:
//! sender schedules → receiver counts delivered bytes → v2 keepalive
//! ack → sender derives windowed delivered-rate/loss → congestion
//! controller updates per-path capacity → token buckets re-weight the
//! split. The unit tests in `capacity_scheduler` prove the control law
//! in isolation; these prove it end-to-end on the wire, with optional
//! ChaCha20-Poly1305 sealing on every datagram.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use bonding_transport::{
    BondSocket, BondSocketConfig, CapacityAwareScheduler, CongestionConfig, FecParams,
    PacketHints, PathConfig, PathPrior, PathTransport,
};

async fn free_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.local_addr().unwrap().port()
}

fn udp_recv(bind: SocketAddr) -> PathTransport {
    PathTransport::Udp {
        bind: Some(bind),
        remote: None,
        interface: None,
    }
}

fn udp_send(remote: SocketAddr) -> PathTransport {
    PathTransport::Udp {
        bind: None,
        remote: Some(remote),
        interface: None,
    }
}

/// A 32-byte test key.
fn test_key() -> Vec<u8> {
    (0..32u8).map(|i| i.wrapping_mul(5).wrapping_add(1)).collect()
}

struct RelayHandle {
    stop: Arc<AtomicBool>,
}
impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// UDP relay that **shapes** the forward (client→target) direction to a
/// token-bucket bitrate, dropping data packets that exceed it. Small
/// datagrams (≤ 64 B — keepalives / acks / NACKs) always pass so the
/// link stays *alive but capacity-limited* rather than flapping dead.
/// The reverse direction (target→client) is never shaped so control
/// feedback always gets home.
async fn spawn_shaped_relay(
    listen: SocketAddr,
    target: SocketAddr,
    data_rate_bps: u64,
    forward_loss: f32,
) -> RelayHandle {
    use std::sync::Mutex;
    let stop = Arc::new(AtomicBool::new(false));
    let sock = Arc::new(UdpSocket::bind(listen).await.unwrap());
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let sock_c = sock.clone();
    let stop_c = stop.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        // Token bucket (bytes), ~250 ms burst.
        let burst = (data_rate_bps as f64 / 8.0) * 0.25;
        let mut tokens = burst;
        let mut last = Instant::now();
        loop {
            if stop_c.load(Ordering::Relaxed) {
                break;
            }
            let r = timeout(Duration::from_millis(50), sock_c.recv_from(&mut buf)).await;
            let Ok(Ok((len, from))) = r else { continue };
            if from == target {
                // Reverse path — always forward.
                let to = *client.lock().unwrap();
                if let Some(c) = to {
                    let _ = sock_c.send_to(&buf[..len], c).await;
                }
                continue;
            }
            // Forward path.
            *client.lock().unwrap() = Some(from);
            // Refill tokens.
            let now = Instant::now();
            tokens = (tokens + (data_rate_bps as f64 / 8.0) * now.duration_since(last).as_secs_f64())
                .min(burst);
            last = now;
            // Control-sized datagrams always pass.
            if len > 64 {
                if forward_loss > 0.0 {
                    let roll: f32 = {
                        use rand::RngExt;
                        rand::rng().random()
                    };
                    if roll < forward_loss {
                        continue;
                    }
                }
                if tokens < len as f64 {
                    continue; // over the shaped rate — drop
                }
                tokens -= len as f64;
            }
            let _ = sock_c.send_to(&buf[..len], target).await;
        }
    });
    RelayHandle { stop }
}

/// UDP relay that drops every `drop_every`-th **media data** datagram
/// (bond magic `0xBC`, FEC flag clear) and forwards everything else —
/// FEC repair packets, control, and the reverse direction all pass. Used
/// to prove FEC recovery in isolation.
async fn spawn_fec_drop_relay(
    listen: SocketAddr,
    target: SocketAddr,
    drop_every: u32,
) -> RelayHandle {
    use std::sync::Mutex;
    let stop = Arc::new(AtomicBool::new(false));
    let sock = Arc::new(UdpSocket::bind(listen).await.unwrap());
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let sock_c = sock.clone();
    let stop_c = stop.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut data_count: u32 = 0;
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
            // 0xBC = bond data magic; byte1 low nibble bit 3 (0x08) = FEC.
            let is_media = len >= 2 && buf[0] == 0xBC && (buf[1] & 0x08) == 0;
            if is_media {
                data_count += 1;
                if data_count % drop_every == 0 {
                    continue; // drop this media packet — FEC must recover it
                }
            }
            let _ = sock_c.send_to(&buf[..len], target).await;
        }
    });
    RelayHandle { stop }
}

/// FEC recovers sparse loss with **ARQ disabled** — the only way a
/// dropped packet reaches the app is the XOR repair. One media drop per
/// 16-packet block lands in a rotating column, so every loss is
/// recoverable; assert zero unrecovered gaps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fec_recovers_sparse_loss_without_arq() {
    let rx = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let relay: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    // Drop every 13th media packet → ~1 per 16-packet block, each in a
    // different column (13 mod 4 rotates), all FEC-recoverable.
    let _r = spawn_fec_drop_relay(relay, rx, 13).await;

    let fec = Some(FecParams { columns: 4, rows: 4 });
    let receiver = BondSocket::receiver(BondSocketConfig {
        flow_id: 99,
        hold_time: Duration::from_millis(500),
        keepalive_interval: Duration::from_millis(120),
        max_nack_retries: 0, // ARQ OFF — recovery can only be FEC
        nack_delay: Duration::from_secs(3600),
        fec,
        paths: vec![PathConfig { id: 0, name: "p".into(), weight_hint: 1, transport: udp_recv(rx) }],
        ..Default::default()
    })
    .await
    .unwrap();

    let sender = BondSocket::sender(
        BondSocketConfig {
            flow_id: 99,
            keepalive_interval: Duration::from_millis(120),
            max_nack_retries: 0,
            fec,
            paths: vec![PathConfig { id: 0, name: "p".into(), weight_hint: 1, transport: udp_send(relay) }],
            ..Default::default()
        },
        CapacityAwareScheduler::new(vec![0]),
    )
    .await
    .unwrap();

    sleep(Duration::from_millis(200)).await;
    const N: u32 = 256;
    for i in 0..N {
        sender.send(Bytes::from(format!("fec-{i:06}")), PacketHints::default()).await.unwrap();
        sleep(Duration::from_millis(1)).await; // pace so repairs arrive within hold
    }
    // Drain.
    let mut got = 0u32;
    while got < N {
        match timeout(Duration::from_secs(3), receiver.recv()).await {
            Ok(Some(_)) => got += 1,
            _ => break,
        }
    }
    sleep(Duration::from_millis(200)).await;

    let s = receiver.stats().snapshot();
    assert!(s.gaps_recovered > 0, "FEC should have recovered drops, got {}", s.gaps_recovered);
    assert_eq!(
        s.gaps_lost, 0,
        "with 1 recoverable loss/block + FEC, nothing should be lost (recovered={}, lost={}, delivered={})",
        s.gaps_recovered, s.gaps_lost, s.packets_delivered
    );
}

/// UDP relay that drops a single BURST of `burst` consecutive media
/// datagrams once `skip` media packets have passed — a leg outage / Starlink
/// handoff. FEC repairs (FEC flag set) and control always pass through.
async fn spawn_fec_burst_relay(
    listen: SocketAddr,
    target: SocketAddr,
    skip: u32,
    burst: u32,
) -> RelayHandle {
    use std::sync::Mutex;
    let stop = Arc::new(AtomicBool::new(false));
    let sock = Arc::new(UdpSocket::bind(listen).await.unwrap());
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let sock_c = sock.clone();
    let stop_c = stop.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut data_count: u32 = 0;
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
            let is_media = len >= 2 && buf[0] == 0xBC && (buf[1] & 0x08) == 0;
            if is_media {
                data_count += 1;
                if data_count > skip && data_count <= skip + burst {
                    continue; // drop the burst — per-leg FEC must recover it
                }
            }
            let _ = sock_c.send_to(&buf[..len], target).await;
        }
    });
    RelayHandle { stop }
}

/// Per-leg FEC recovers a *consecutive burst* on a leg with ARQ disabled —
/// the case combined FEC struggles with, since a single leg's burst
/// clusters in the global striped stream and overruns one column. Per-leg
/// interleave (`columns` ≥ burst) lands each dropped packet in its own
/// column, all XOR-recoverable. `max_nack_retries: 0` so the ONLY recovery
/// path is the per-leg repair riding the same leg.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_leg_fec_recovers_leg_burst_without_arq() {
    let rx = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let relay: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    // After 40 media packets, drop a burst of 6 consecutive ones.
    let _r = spawn_fec_burst_relay(relay, rx, 40, 6).await;

    let params = FecParams { columns: 8, rows: 4 };
    let mut per_path_fec = std::collections::HashMap::new();
    per_path_fec.insert(0u8, params);

    let receiver = BondSocket::receiver(BondSocketConfig {
        flow_id: 77,
        hold_time: Duration::from_millis(800),
        keepalive_interval: Duration::from_millis(120),
        max_nack_retries: 0, // ARQ OFF — recovery can only be per-leg FEC
        nack_delay: Duration::from_secs(3600),
        per_path_fec: per_path_fec.clone(),
        paths: vec![PathConfig {
            id: 0,
            name: "starlink".into(),
            weight_hint: 1,
            transport: udp_recv(rx),
        }],
        ..Default::default()
    })
    .await
    .unwrap();

    let sender = BondSocket::sender(
        BondSocketConfig {
            flow_id: 77,
            keepalive_interval: Duration::from_millis(120),
            max_nack_retries: 0,
            per_path_fec,
            paths: vec![PathConfig {
                id: 0,
                name: "starlink".into(),
                weight_hint: 1,
                transport: udp_send(relay),
            }],
            ..Default::default()
        },
        CapacityAwareScheduler::new(vec![0]),
    )
    .await
    .unwrap();

    sleep(Duration::from_millis(200)).await;
    const N: u32 = 256;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("pl-{i:06}")), PacketHints::default())
            .await
            .unwrap();
        sleep(Duration::from_millis(1)).await; // pace so repairs arrive within hold
    }
    let mut got = 0u32;
    while got < N {
        match timeout(Duration::from_secs(3), receiver.recv()).await {
            Ok(Some(_)) => got += 1,
            _ => break,
        }
    }
    sleep(Duration::from_millis(200)).await;

    let s = receiver.stats().snapshot();
    assert!(
        s.gaps_recovered >= 6,
        "per-leg FEC should recover the 6-packet leg burst, got recovered={}",
        s.gaps_recovered
    );
    assert_eq!(
        s.gaps_lost, 0,
        "a burst within `columns` is fully recoverable per-leg (recovered={}, lost={}, delivered={})",
        s.gaps_recovered, s.gaps_lost, s.packets_delivered
    );
}

/// Two-path encrypted bond delivers in order with the adaptive
/// scheduler; both paths carry traffic and nothing is lost on a clean
/// link. Proves crypto integrates with the capacity scheduler e2e.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_adaptive_bond_delivers_in_order() {
    let rx_a = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let rx_b = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let mk = |paths: Vec<PathConfig>, key: bool| BondSocketConfig {
        flow_id: 77,
        hold_time: Duration::from_millis(120),
        nack_delay: Duration::from_millis(40),
        keepalive_interval: Duration::from_millis(120),
        encryption_key: key.then(test_key),
        paths,
        ..Default::default()
    };

    let receiver = BondSocket::receiver(mk(
        vec![
            PathConfig { id: 0, name: "a".into(), weight_hint: 1, transport: udp_recv(rx_a) },
            PathConfig { id: 1, name: "b".into(), weight_hint: 1, transport: udp_recv(rx_b) },
        ],
        true,
    ))
    .await
    .unwrap();

    let sched = CapacityAwareScheduler::new(vec![0, 1]);
    let sender = BondSocket::sender(
        mk(
            vec![
                PathConfig { id: 0, name: "a".into(), weight_hint: 1, transport: udp_send(rx_a) },
                PathConfig { id: 1, name: "b".into(), weight_hint: 1, transport: udp_send(rx_b) },
            ],
            true,
        ),
        sched,
    )
    .await
    .unwrap();

    const N: u32 = 300;
    for i in 0..N {
        let payload = Bytes::from(format!("enc-{i:06}"));
        sender.send(payload, PacketHints::default()).await.unwrap();
        if i % 20 == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }

    let mut got = Vec::with_capacity(N as usize);
    for _ in 0..N {
        match timeout(Duration::from_secs(5), receiver.recv()).await {
            Ok(Some(b)) => got.push(b),
            _ => break,
        }
    }

    assert_eq!(got.len(), N as usize, "all encrypted payloads must arrive");
    for (i, b) in got.iter().enumerate() {
        assert_eq!(b.as_ref(), format!("enc-{i:06}").as_bytes(), "order at {i}");
    }
    let rx = receiver.stats().snapshot();
    assert_eq!(rx.gaps_lost, 0);
    let s0 = sender.path_stats(0).unwrap().snapshot();
    let s1 = sender.path_stats(1).unwrap().snapshot();
    assert!(s0.packets_sent > 0 && s1.packets_sent > 0, "both paths carry: {s0:?} {s1:?}");
}

/// The headline behaviour: with one link shaped to a low bitrate and one
/// unshaped, the adaptive scheduler discovers the asymmetry over the
/// wire and shifts the **majority** of traffic onto the high-capacity
/// link — capacity-proportional, not the RTT-blind 50/50 the old
/// scheduler produced. Both links stay alive (no failover).
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn adaptive_split_favors_higher_capacity_link() {
    let rx_a = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let rx_b = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let relay_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let relay_b: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    // Path A: shaped to ~2 Mbps. Path B: shaped to ~16 Mbps (effectively
    // unconstrained for this offered load). No artificial loss — the
    // capacity asymmetry alone must drive the split.
    let _ra = spawn_shaped_relay(relay_a, rx_a, 2_000_000, 0.0).await;
    let _rb = spawn_shaped_relay(relay_b, rx_b, 16_000_000, 0.0).await;

    let receiver = BondSocket::receiver(BondSocketConfig {
        flow_id: 88,
        hold_time: Duration::from_millis(300),
        nack_delay: Duration::from_millis(30),
        max_nack_retries: 12,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![
            PathConfig { id: 0, name: "lte".into(), weight_hint: 1, transport: udp_recv(rx_a) },
            PathConfig { id: 1, name: "starlink".into(), weight_hint: 1, transport: udp_recv(rx_b) },
        ],
        ..Default::default()
    })
    .await
    .unwrap();

    // Fast-reacting controller so the test converges in a few seconds.
    let cong = CongestionConfig {
        start_rate_bps: 3_000_000,
        ..Default::default()
    };
    let sched = CapacityAwareScheduler::with_paths(
        vec![
            PathPrior { id: 0, weight_hint: 1, ceiling_bps: None },
            PathPrior { id: 1, weight_hint: 1, ceiling_bps: None },
        ],
        cong,
    );
    let sender = BondSocket::sender(
        BondSocketConfig {
            flow_id: 88,
            keepalive_interval: Duration::from_millis(100),
            retransmit_capacity: 8192,
            paths: vec![
                PathConfig { id: 0, name: "lte".into(), weight_hint: 1, transport: udp_send(relay_a) },
                PathConfig { id: 1, name: "starlink".into(), weight_hint: 1, transport: udp_send(relay_b) },
            ],
            ..Default::default()
        },
        sched,
    )
    .await
    .unwrap();

    // Drain delivered payloads in the background so the receiver app
    // channel never backs up.
    let recv_arc = Arc::new(receiver);
    let recv_bg = recv_arc.clone();
    let drained = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let drained_bg = drained.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();
    tokio::spawn(async move {
        while !stop_bg.load(Ordering::Relaxed) {
            match timeout(Duration::from_millis(200), recv_bg.recv()).await {
                Ok(Some(_)) => {
                    drained_bg.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => break,
                Err(_) => {}
            }
        }
    });

    // Offer ~14 Mbps — well above path A's 2 Mbps cap so an even split
    // would over-drive A and force the controller to shift load to B.
    // Batches of 8 × 1200 B every ~5.5 ms (timer slop included).
    let payload = Bytes::from(vec![0xABu8; 1200]);
    let offer = |dur: Duration| {
        let sender = &sender;
        let payload = payload.clone();
        async move {
            let start = Instant::now();
            let mut sent = 0u64;
            while start.elapsed() < dur {
                for _ in 0..8 {
                    if sender.send(payload.clone(), PacketHints::default()).await.is_ok() {
                        sent += 1;
                    }
                }
                sleep(Duration::from_micros(5500)).await;
            }
            sent
        }
    };

    // Warm up + converge: keepalives establish peers, the controller
    // discovers A is capped (loss/over-rate) and B has headroom.
    sleep(Duration::from_millis(400)).await;
    let _ = offer(Duration::from_millis(2500)).await;

    // Steady-state window: measure the split here, after convergence,
    // so the cold-start even-rotation transient doesn't skew the result.
    let a0 = recv_arc.path_stats(0).unwrap().snapshot().bytes_received;
    let b0 = recv_arc.path_stats(1).unwrap().snapshot().bytes_received;
    let sent = offer(Duration::from_millis(3000)).await;
    sleep(Duration::from_millis(400)).await;
    stop.store(true, Ordering::Relaxed);

    let a = recv_arc.path_stats(0).unwrap().snapshot();
    let b = recv_arc.path_stats(1).unwrap().snapshot();
    let da = a.bytes_received - a0;
    let db = b.bytes_received - b0;

    // Both links stayed alive and carried traffic (no failover).
    assert!(!a.dead, "shaped LTE link should stay alive (keepalives exempt)");
    assert!(!b.dead, "starlink link should stay alive");
    assert!(da > 0, "LTE link should still carry its (capped) share");
    assert!(db > 0, "starlink link should carry traffic");

    // The high-capacity link must carry the clear majority in steady
    // state — proof the split tracks *measured capacity*, not the
    // RTT-blind even rotation the old scheduler produced.
    assert!(
        db > da * 2,
        "high-capacity link should dominate the steady-state split: \
         lte={da} B, starlink={db} B (sent {sent}, drained {})",
        drained.load(Ordering::Relaxed),
    );

    // The capped link's steady-state delivered rate should sit near its
    // 2 Mbps shaped ceiling (≈ 750 KB over the 3 s window), confirming
    // the controller filled it to — but not wildly past — capacity.
    let a_mbps = (da as f64 * 8.0) / 3.0 / 1e6;
    assert!(
        a_mbps < 4.0,
        "capped link should not exceed ~its 2 Mbps ceiling, got {a_mbps:.1} Mbps"
    );
}
