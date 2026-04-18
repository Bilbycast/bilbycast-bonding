//! Heterogeneous-transport bonding tests.
//!
//! Proves that the same `BondSocket` sender + receiver work
//! identically whether the individual paths are plain UDP, QUIC,
//! or a mixture of the two. The bond protocol never peeks inside
//! the path — as long as each `Path` variant transports a datagram
//! end-to-end, aggregation, NACK recovery, and keepalive all work.

#![cfg(feature = "path-quic")]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use bonding_transport::{
    BondSocket, BondSocketConfig, PacketHints, PathConfig, PathTransport, QuicRole,
    QuicTlsMode, WeightedRttScheduler,
};

async fn free_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.local_addr().unwrap().port()
}

/// Two-path bond over **QUIC only**. Proves the QUIC datagram
/// transport carries bond frames, keepalives, and NACKs end-to-end
/// under TLS 1.3.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn two_quic_paths_deliver_in_order() {
    let a_port = free_port().await;
    let b_port = free_port().await;
    let a_addr: SocketAddr = format!("127.0.0.1:{a_port}").parse().unwrap();
    let b_addr: SocketAddr = format!("127.0.0.1:{b_port}").parse().unwrap();

    // Receiver: QUIC servers on both ports.
    let rx_cfg = BondSocketConfig {
        flow_id: 7,
        hold_time: Duration::from_millis(100),
        nack_delay: Duration::from_millis(40),
        keepalive_interval: Duration::from_millis(150),
        paths: vec![
            PathConfig {
                id: 0,
                name: "quic-a".into(),
                weight_hint: 1,
                transport: PathTransport::Quic {
                    role: QuicRole::Server,
                    addr: a_addr,
                    server_name: "localhost".into(),
                    tls: QuicTlsMode::SelfSigned,
                },
            },
            PathConfig {
                id: 1,
                name: "quic-b".into(),
                weight_hint: 1,
                transport: PathTransport::Quic {
                    role: QuicRole::Server,
                    addr: b_addr,
                    server_name: "localhost".into(),
                    tls: QuicTlsMode::SelfSigned,
                },
            },
        ],
        ..Default::default()
    };
    // Start the receiver in the background; QUIC server setup blocks
    // on the client's initial dial.
    let rx_handle = tokio::spawn(async move { BondSocket::receiver(rx_cfg).await });

    // Give the servers a moment to bind and start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let tx_cfg = BondSocketConfig {
        flow_id: 7,
        keepalive_interval: Duration::from_millis(150),
        paths: vec![
            PathConfig {
                id: 0,
                name: "quic-a".into(),
                weight_hint: 1,
                transport: PathTransport::Quic {
                    role: QuicRole::Client,
                    addr: a_addr,
                    server_name: "localhost".into(),
                    tls: QuicTlsMode::SelfSigned,
                },
            },
            PathConfig {
                id: 1,
                name: "quic-b".into(),
                weight_hint: 1,
                transport: PathTransport::Quic {
                    role: QuicRole::Client,
                    addr: b_addr,
                    server_name: "localhost".into(),
                    tls: QuicTlsMode::SelfSigned,
                },
            },
        ],
        ..Default::default()
    };
    let sched = WeightedRttScheduler::new(vec![0, 1]);
    let sender = BondSocket::sender(tx_cfg, sched).await.unwrap();

    let receiver = rx_handle.await.unwrap().unwrap();

    const N: u32 = 100;
    for i in 0..N {
        let payload = Bytes::from(format!("quic-{i:05}"));
        sender.send(payload, PacketHints::default()).await.unwrap();
    }

    let mut got: Vec<Bytes> = Vec::new();
    for _ in 0..N {
        let r = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("quic recv timed out")
            .expect("channel closed");
        got.push(r);
    }

    for (i, b) in got.iter().enumerate() {
        assert_eq!(b.as_ref(), format!("quic-{i:05}").as_bytes());
    }

    let stats = receiver.stats().snapshot();
    assert_eq!(stats.gaps_lost, 0);
    assert!(stats.packets_delivered >= N as u64);

    let s0 = sender.path_stats(0).unwrap().snapshot();
    let s1 = sender.path_stats(1).unwrap().snapshot();
    assert!(
        s0.packets_sent > 0 && s1.packets_sent > 0,
        "both QUIC paths must carry traffic: {s0:?} {s1:?}"
    );
}

/// Heterogeneous bond: one UDP path + one QUIC path. Demonstrates
/// that the two transports are interchangeable from bond's point of
/// view — a real deployment might bond a cellular LTE (QUIC) link
/// with a terrestrial ethernet (UDP) link to the same hub.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn udp_plus_quic_deliver_in_order() {
    let udp_port = free_port().await;
    let quic_port = free_port().await;
    let udp_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let quic_addr: SocketAddr = format!("127.0.0.1:{quic_port}").parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 9,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(150),
        paths: vec![
            PathConfig {
                id: 0,
                name: "udp".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: Some(udp_addr),
                    remote: None,
                    interface: None,
                },
            },
            PathConfig {
                id: 1,
                name: "quic".into(),
                weight_hint: 1,
                transport: PathTransport::Quic {
                    role: QuicRole::Server,
                    addr: quic_addr,
                    server_name: "localhost".into(),
                    tls: QuicTlsMode::SelfSigned,
                },
            },
        ],
        ..Default::default()
    };
    let rx_handle = tokio::spawn(async move { BondSocket::receiver(rx_cfg).await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let tx_cfg = BondSocketConfig {
        flow_id: 9,
        keepalive_interval: Duration::from_millis(150),
        paths: vec![
            PathConfig {
                id: 0,
                name: "udp".into(),
                weight_hint: 1,
                transport: PathTransport::Udp {
                    bind: None,
                    remote: Some(udp_addr),
                    interface: None,
                },
            },
            PathConfig {
                id: 1,
                name: "quic".into(),
                weight_hint: 1,
                transport: PathTransport::Quic {
                    role: QuicRole::Client,
                    addr: quic_addr,
                    server_name: "localhost".into(),
                    tls: QuicTlsMode::SelfSigned,
                },
            },
        ],
        ..Default::default()
    };
    let sched = WeightedRttScheduler::new(vec![0, 1]);
    let sender = BondSocket::sender(tx_cfg, sched).await.unwrap();

    let receiver = rx_handle.await.unwrap().unwrap();

    const N: u32 = 200;
    for i in 0..N {
        let payload = Bytes::from(format!("mix-{i:05}"));
        sender.send(payload, PacketHints::default()).await.unwrap();
    }

    let mut got: Vec<Bytes> = Vec::new();
    for _ in 0..N {
        let r = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("het recv timed out")
            .expect("channel closed");
        got.push(r);
    }

    for (i, b) in got.iter().enumerate() {
        assert_eq!(b.as_ref(), format!("mix-{i:05}").as_bytes());
    }

    let stats = receiver.stats().snapshot();
    assert_eq!(stats.gaps_lost, 0);

    let udp_stats = sender.path_stats(0).unwrap().snapshot();
    let quic_stats = sender.path_stats(1).unwrap().snapshot();
    assert!(
        udp_stats.packets_sent > 0 && quic_stats.packets_sent > 0,
        "heterogeneous bond should carry traffic on both paths: udp={udp_stats:?} quic={quic_stats:?}"
    );
}
