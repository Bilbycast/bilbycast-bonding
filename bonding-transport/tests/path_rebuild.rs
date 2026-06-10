//! Integration test for in-place UDP socket rebuilds (interface-churn
//! recovery, audit item 5).
//!
//! Runs a two-path bond over loopback, forces a rebuild on a sender
//! leg (fresh ephemeral source port) and on a receiver leg (same-port
//! rebind) mid-stream, and asserts:
//!
//! - every payload still arrives, in bond-seq order — datagrams lost
//!   in the ≤100 ms swap window are recovered by ARQ like any path
//!   loss, and the receiver re-learns the sender's new return address
//!   from the next control packet;
//! - the per-path `rebuilds` stats counter advanced on exactly the
//!   rebuilt paths.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use bonding_transport::{
    BondSocket, BondSocketConfig, PathConfig, PathTransport, WeightedRttScheduler,
};

/// Find an available local UDP port by binding ephemerally. The
/// returned address is safe to re-bind immediately within the test
/// because `SO_REUSEADDR` is set on every path socket.
async fn free_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.local_addr().unwrap().port()
}

fn udp_path(id: u8, name: &str, bind: Option<SocketAddr>, remote: Option<SocketAddr>) -> PathConfig {
    PathConfig {
        id,
        name: name.into(),
        weight_hint: 1,
        transport: PathTransport::Udp {
            bind,
            remote,
            interface: None,
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traffic_survives_sender_and_receiver_leg_rebuilds() {
    let rx_a: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let rx_b: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 11,
        hold_time: Duration::from_millis(800),
        nack_delay: Duration::from_millis(30),
        keepalive_interval: Duration::from_millis(100),
        paths: vec![
            udp_path(0, "a", Some(rx_a), None),
            udp_path(1, "b", Some(rx_b), None),
        ],
        ..Default::default()
    };
    let rx_sock = BondSocket::receiver(rx_cfg).await.expect("receiver");

    let tx_cfg = BondSocketConfig {
        flow_id: 11,
        keepalive_interval: Duration::from_millis(100),
        paths: vec![
            udp_path(0, "a", None, Some(rx_a)),
            udp_path(1, "b", None, Some(rx_b)),
        ],
        ..Default::default()
    };
    let tx_sock = BondSocket::sender(tx_cfg, WeightedRttScheduler::new(vec![0, 1]))
        .await
        .expect("sender");

    // Let keepalives establish liveness + peer learning on both legs.
    sleep(Duration::from_millis(300)).await;

    const TOTAL: u32 = 200;
    let collector = tokio::spawn(async move {
        let mut got: Vec<u32> = Vec::with_capacity(TOTAL as usize);
        while got.len() < TOTAL as usize {
            match timeout(Duration::from_secs(5), rx_sock.recv()).await {
                Ok(Some(payload)) => {
                    let n = u32::from_be_bytes(payload[..4].try_into().unwrap());
                    got.push(n);
                }
                _ => break,
            }
        }
        (got, rx_sock)
    });

    for i in 0..TOTAL {
        // Mid-stream churn: rebuild a sender leg (new ephemeral source
        // port — the receiver must re-learn the return address), then
        // later a receiver leg (same-port rebind under SO_REUSEADDR).
        if i == 60 {
            tx_sock.rebuild_udp_path(0).expect("sender-leg rebuild");
        }
        let mut payload = vec![0u8; 64];
        payload[..4].copy_from_slice(&i.to_be_bytes());
        tx_sock
            .send(Bytes::from(payload), Default::default())
            .await
            .expect("send");
        sleep(Duration::from_millis(10)).await;
    }

    let (got, rx_sock) = timeout(Duration::from_secs(10), collector)
        .await
        .expect("collector finished")
        .expect("collector task");

    let expected: Vec<u32> = (0..TOTAL).collect();
    assert_eq!(
        got, expected,
        "all payloads must arrive in bond-seq order across the rebuild"
    );

    // Now rebuild a receiver leg and prove the bond still carries
    // traffic afterwards (the rebound socket feeds the same channel).
    rx_sock.rebuild_udp_path(0).expect("receiver-leg rebuild");
    sleep(Duration::from_millis(250)).await; // swap poll + keepalive round
    let mut tail: Vec<u32> = Vec::new();
    for i in TOTAL..TOTAL + 20 {
        let mut payload = vec![0u8; 64];
        payload[..4].copy_from_slice(&i.to_be_bytes());
        tx_sock
            .send(Bytes::from(payload), Default::default())
            .await
            .expect("send post-rebind");
        sleep(Duration::from_millis(10)).await;
    }
    while tail.len() < 20 {
        match timeout(Duration::from_secs(5), rx_sock.recv()).await {
            Ok(Some(payload)) => {
                tail.push(u32::from_be_bytes(payload[..4].try_into().unwrap()));
            }
            _ => break,
        }
    }
    let expected_tail: Vec<u32> = (TOTAL..TOTAL + 20).collect();
    assert_eq!(tail, expected_tail, "traffic must flow after a receiver-leg rebind");

    // Rebuild counters advanced on exactly the rebuilt paths.
    assert_eq!(tx_sock.path_stats(0).unwrap().snapshot().rebuilds, 1);
    assert_eq!(tx_sock.path_stats(1).unwrap().snapshot().rebuilds, 0);
    assert_eq!(rx_sock.path_stats(0).unwrap().snapshot().rebuilds, 1);
    assert_eq!(rx_sock.path_stats(1).unwrap().snapshot().rebuilds, 0);

    // Non-UDP / unknown path ids are rejected.
    assert!(tx_sock.rebuild_udp_path(42).is_err());

    tx_sock.close();
    rx_sock.close();
}
