//! End-to-end integration tests for `BondSocket`.
//!
//! Exercises the sender → receiver pipeline on localhost across two
//! UDP paths, with optional synthetic packet loss inserted into a
//! UDP tee proxy. Validates:
//!
//! - Packets flow across both paths and are re-delivered in
//!   bond-seq order at the receiver.
//! - Under random loss the NACK machinery recovers missing
//!   datagrams so every payload reaches the app.
//! - Per-path stats counters advance as expected.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use bonding_transport::{
    BondSocket, BondSocketConfig, PacketHints, PathConfig, PathTransport, Priority,
    WeightedRttScheduler,
};

/// Find an available local UDP port by binding ephemerally. The
/// returned address is safe to re-bind immediately within the test
/// because `SO_REUSEADDR` is set on every path socket.
async fn free_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.local_addr().unwrap().port()
}

/// Naive UDP relay: forward client ↔ target traffic verbatim, with
/// optional forward-direction loss. Returned handle holds the
/// listening socket so the test can tear it down cleanly.
#[derive(Clone)]
struct RelayHandle {
    stop: Arc<AtomicBool>,
}

async fn spawn_lossy_relay(
    listen: SocketAddr,
    target: SocketAddr,
    forward_loss: f32,
) -> RelayHandle {
    use std::sync::Mutex;
    let stop = Arc::new(AtomicBool::new(false));
    let sock = Arc::new(UdpSocket::bind(listen).await.unwrap());
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let sock_clone = sock.clone();
    let stop_clone = stop.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            let r = tokio::time::timeout(Duration::from_millis(50), sock_clone.recv_from(&mut buf)).await;
            let Ok(Ok((len, from))) = r else { continue };
            let pkt = &buf[..len];
            if from == target {
                // Reverse: target → client
                let to = {
                    let g = client.lock().unwrap();
                    *g
                };
                if let Some(c) = to {
                    let _ = sock_clone.send_to(pkt, c).await;
                }
            } else {
                // Forward: client → target (with optional loss)
                {
                    let mut g = client.lock().unwrap();
                    *g = Some(from);
                }
                if forward_loss > 0.0 {
                    let roll: f32 = {
                        use rand::Rng;
                        rand::rng().random()
                    };
                    if roll < forward_loss {
                        continue;
                    }
                }
                let _ = sock_clone.send_to(pkt, target).await;
            }
        }
    });
    RelayHandle { stop }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn two_path_bond_clean_delivers_in_order() {
    // Two receiver-side ports, two sender targets (direct, no relay).
    let rx_a_port = free_port().await;
    let rx_b_port = free_port().await;
    let rx_a: SocketAddr = format!("127.0.0.1:{rx_a_port}").parse().unwrap();
    let rx_b: SocketAddr = format!("127.0.0.1:{rx_b_port}").parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 1,
        hold_time: Duration::from_millis(100),
        nack_delay: Duration::from_millis(40),
        keepalive_interval: Duration::from_millis(150),
        paths: vec![
            PathConfig {
                id: 0,
                name: "a".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: Some(rx_a),
                    remote: None,
                    interface: None,
                },
            },
            PathConfig {
                id: 1,
                name: "b".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: Some(rx_b),
                    remote: None,
                    interface: None,
                },
            },
        ],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    let tx_cfg = BondSocketConfig {
        flow_id: 1,
        keepalive_interval: Duration::from_millis(150),
        paths: vec![
            PathConfig {
                id: 0,
                name: "a".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: None,
                    remote: Some(rx_a),
                    interface: None,
                },
            },
            PathConfig {
                id: 1,
                name: "b".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: None,
                    remote: Some(rx_b),
                    interface: None,
                },
            },
        ],
        ..Default::default()
    };
    let sched = WeightedRttScheduler::new(vec![0, 1]);
    let sender = BondSocket::sender(tx_cfg, sched).await.unwrap();

    // Burst of 200 payloads.
    const N: u32 = 200;
    for i in 0..N {
        let payload = Bytes::from(format!("payload-{i:06}"));
        sender
            .send(payload, PacketHints::default())
            .await
            .unwrap();
    }

    // Receive all of them within a bounded wait.
    let mut got: Vec<Bytes> = Vec::with_capacity(N as usize);
    for _ in 0..N {
        let r = timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        got.push(r);
    }

    // Strict ordering check.
    for (i, b) in got.iter().enumerate() {
        let expected = format!("payload-{i:06}");
        assert_eq!(
            b.as_ref(),
            expected.as_bytes(),
            "mismatch at index {i}"
        );
    }

    let rx_stats = receiver.stats().snapshot();
    assert!(rx_stats.packets_delivered >= N as u64);
    assert_eq!(rx_stats.gaps_lost, 0);

    let tx_stats = sender.stats().snapshot();
    assert_eq!(tx_stats.packets_dropped_no_path, 0);

    // Both paths should have carried traffic (weighted scheduler
    // rotates because RTTs start equal).
    let s0 = sender.path_stats(0).unwrap().snapshot();
    let s1 = sender.path_stats(1).unwrap().snapshot();
    assert!(
        s0.packets_sent > 0 && s1.packets_sent > 0,
        "both paths should carry traffic: {s0:?} / {s1:?}"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn nack_recovers_losses_across_paths() {
    // Topology:
    //
    //   sender ──path A──► relay_a (10% forward loss) ──► rx_a
    //          ──path B──► relay_b (10% forward loss) ──► rx_b
    //
    // With 10% loss on each path, ~1% of packets end up missing on
    // BOTH paths and require NACK recovery. Test succeeds iff every
    // payload eventually reaches the app.
    let rx_a_port = free_port().await;
    let rx_b_port = free_port().await;
    let relay_a_port = free_port().await;
    let relay_b_port = free_port().await;
    let rx_a: SocketAddr = format!("127.0.0.1:{rx_a_port}").parse().unwrap();
    let rx_b: SocketAddr = format!("127.0.0.1:{rx_b_port}").parse().unwrap();
    let relay_a: SocketAddr = format!("127.0.0.1:{relay_a_port}").parse().unwrap();
    let relay_b: SocketAddr = format!("127.0.0.1:{relay_b_port}").parse().unwrap();

    let _ra = spawn_lossy_relay(relay_a, rx_a, 0.10).await;
    let _rb = spawn_lossy_relay(relay_b, rx_b, 0.10).await;

    let rx_cfg = BondSocketConfig {
        flow_id: 2,
        hold_time: Duration::from_millis(400),
        nack_delay: Duration::from_millis(30),
        max_nack_retries: 16,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![
            PathConfig {
                id: 0,
                name: "a".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: Some(rx_a),
                    remote: None,
                    interface: None,
                },
            },
            PathConfig {
                id: 1,
                name: "b".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: Some(rx_b),
                    remote: None,
                    interface: None,
                },
            },
        ],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    let tx_cfg = BondSocketConfig {
        flow_id: 2,
        keepalive_interval: Duration::from_millis(100),
        retransmit_capacity: 4096,
        paths: vec![
            PathConfig {
                id: 0,
                name: "a".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: None,
                    remote: Some(relay_a),
                    interface: None,
                },
            },
            PathConfig {
                id: 1,
                name: "b".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: None,
                    remote: Some(relay_b),
                    interface: None,
                },
            },
        ],
        ..Default::default()
    };
    let sched = WeightedRttScheduler::new(vec![0, 1]);
    let sender = BondSocket::sender(tx_cfg, sched).await.unwrap();

    // Pre-warm: give keepalive time to establish path peers on
    // receiver side so NACKs have a learned return address.
    sleep(Duration::from_millis(200)).await;

    const N: u32 = 500;
    for i in 0..N {
        let payload = Bytes::from(format!("p-{i:06}"));
        sender.send(payload, PacketHints::default()).await.unwrap();
        // Gentle pacing so bursts don't overflow the UDP receive
        // queue under loopback — not a realistic delivery pattern
        // but keeps the test deterministic across machines.
        if i % 50 == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }

    // Collect with a generous deadline — NACK round-trip + retransmit
    // can take several milliseconds per lost packet on a busy CI.
    let mut got: Vec<Bytes> = Vec::with_capacity(N as usize);
    for _ in 0..N {
        let r = timeout(Duration::from_secs(10), receiver.recv()).await;
        match r {
            Ok(Some(b)) => got.push(b),
            _ => break,
        }
    }

    let stats = receiver.stats().snapshot();
    let tx_stats = sender.stats().snapshot();

    // Must have delivered every payload.
    assert_eq!(
        got.len(),
        N as usize,
        "got {} of {N}, gaps_lost={}, gaps_recovered={}, retransmits={}",
        got.len(),
        stats.gaps_lost,
        stats.gaps_recovered,
        tx_stats.packets_retransmitted
    );
    // Strict ordering.
    for (i, b) in got.iter().enumerate() {
        assert_eq!(b.as_ref(), format!("p-{i:06}").as_bytes());
    }
    // ARQ actually did work — some NACKs + some retransmits observed.
    assert!(
        tx_stats.packets_retransmitted > 0,
        "expected retransmits under loss, got 0"
    );
    assert_eq!(stats.gaps_lost, 0, "all gaps should recover");
}
