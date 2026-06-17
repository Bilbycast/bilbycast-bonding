//! RIST-leg bonding tests.
//!
//! Closes the bond-level coverage gap for the RIST Simple-Profile path
//! adapter (`path/rist.rs`). Until this file, only the underlying
//! `rist-transport` crate and the QUIC/UDP legs (`bond_heterogeneous.rs`)
//! had end-to-end bond tests; RIST legs were exercised only by their own
//! crate's unit tests, never carried through a real `BondSocket`.
//!
//! RIST is **unidirectional at the bond layer** (see the module docs in
//! `src/path/rist.rs`): a RIST *receiver* leg cannot transmit bond-level
//! control, so an all-RIST bond has no back-channel for keepalive-acks /
//! NACKs and relies on in-order reassembly drain plus RIST's own per-leg
//! ARQ. The realistic production pattern pairs a one-way RIST data leg
//! with a bidirectional UDP (or QUIC) leg that carries the bond
//! back-channel — that is what `udp_plus_rist_deliver_in_order` proves.

#![cfg(feature = "path-rist")]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use bonding_transport::{
    BondSocket, BondSocketConfig, PacketHints, PathConfig, PathTransport, RistRole,
    WeightedRttScheduler,
};

/// A free **even** loopback UDP port. RIST Simple Profile uses an even
/// RTP port plus the adjacent odd RTCP port, so we confirm both bind
/// cleanly before handing the port to a RIST leg.
async fn free_even_port() -> u16 {
    loop {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p = probe.local_addr().unwrap().port();
        drop(probe);
        let even = p & !1;
        if even < 1024 {
            continue;
        }
        let a = UdpSocket::bind(format!("127.0.0.1:{even}")).await;
        let b = UdpSocket::bind(format!("127.0.0.1:{}", even + 1)).await;
        if a.is_ok() && b.is_ok() {
            return even;
        }
    }
}

async fn free_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.local_addr().unwrap().port()
}

/// **Documented production pattern**: one bidirectional UDP leg + one
/// one-way RIST data leg to the same hub. The UDP leg carries the bond
/// back-channel (keepalive-acks / NACKs) while the RIST leg adds an
/// independently ARQ-protected data path. Proves the RIST leg adapter
/// carries bonded frames end-to-end and that both legs share the load.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn udp_plus_rist_deliver_in_order() {
    let udp_port = free_port().await;
    let rist_port = free_even_port().await;
    let udp_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let rist_addr: SocketAddr = format!("127.0.0.1:{rist_port}").parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 21,
        hold_time: Duration::from_millis(300),
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
                name: "rist".into(),
                weight_hint: 1,
                transport: PathTransport::Rist {
                    role: RistRole::Receiver,
                    remote: None,
                    local_bind: Some(rist_addr),
                    buffer_ms: Some(100),
                },
            },
        ],
        ..Default::default()
    };
    let rx_handle = tokio::spawn(async move { BondSocket::receiver(rx_cfg).await });

    tokio::time::sleep(Duration::from_millis(80)).await;

    let tx_cfg = BondSocketConfig {
        flow_id: 21,
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
                name: "rist".into(),
                weight_hint: 1,
                transport: PathTransport::Rist {
                    role: RistRole::Sender,
                    remote: Some(rist_addr),
                    local_bind: None,
                    buffer_ms: Some(100),
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
        let payload = Bytes::from(format!("udprist-{i:05}"));
        sender.send(payload, PacketHints::default()).await.unwrap();
    }

    let mut got: Vec<Bytes> = Vec::new();
    for _ in 0..N {
        let r = timeout(Duration::from_secs(10), receiver.recv())
            .await
            .expect("udp+rist recv timed out")
            .expect("channel closed");
        got.push(r);
    }

    for (i, b) in got.iter().enumerate() {
        assert_eq!(b.as_ref(), format!("udprist-{i:05}").as_bytes());
    }

    let stats = receiver.stats().snapshot();
    assert_eq!(stats.gaps_lost, 0, "no gaps should be lost on loopback");

    let udp_stats = sender.path_stats(0).unwrap().snapshot();
    let rist_stats = sender.path_stats(1).unwrap().snapshot();
    assert!(
        udp_stats.packets_sent > 0 && rist_stats.packets_sent > 0,
        "both legs must carry traffic: udp={udp_stats:?} rist={rist_stats:?}"
    );
}

/// **All-RIST bond.** Two one-way RIST data legs with no bond
/// back-channel. Proves the RIST leg adapter carries bonded frames and
/// the receiver drains them in bond-seq order even without bond-level
/// keepalive-acks / NACKs (recovery is RIST's own per-leg ARQ). The
/// keepalive interval is set long enough that the sender's liveness
/// sweep (`miss_threshold × keepalive_interval`) cannot fire mid-burst —
/// an all-RIST bond left idle would otherwise eventually mark its
/// ack-less legs dead, which is the documented reason to pair RIST with
/// a bidirectional control leg.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn two_rist_paths_deliver_in_order() {
    let port_a = free_even_port().await;
    let port_b = free_even_port().await;
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 22,
        hold_time: Duration::from_millis(300),
        keepalive_interval: Duration::from_secs(3),
        paths: vec![
            PathConfig {
                id: 0,
                name: "rist-a".into(),
                weight_hint: 1,
                transport: PathTransport::Rist {
                    role: RistRole::Receiver,
                    remote: None,
                    local_bind: Some(addr_a),
                    buffer_ms: Some(100),
                },
            },
            PathConfig {
                id: 1,
                name: "rist-b".into(),
                weight_hint: 1,
                transport: PathTransport::Rist {
                    role: RistRole::Receiver,
                    remote: None,
                    local_bind: Some(addr_b),
                    buffer_ms: Some(100),
                },
            },
        ],
        ..Default::default()
    };
    let rx_handle = tokio::spawn(async move { BondSocket::receiver(rx_cfg).await });

    tokio::time::sleep(Duration::from_millis(80)).await;

    let tx_cfg = BondSocketConfig {
        flow_id: 22,
        keepalive_interval: Duration::from_secs(3),
        paths: vec![
            PathConfig {
                id: 0,
                name: "rist-a".into(),
                weight_hint: 1,
                transport: PathTransport::Rist {
                    role: RistRole::Sender,
                    remote: Some(addr_a),
                    local_bind: None,
                    buffer_ms: Some(100),
                },
            },
            PathConfig {
                id: 1,
                name: "rist-b".into(),
                weight_hint: 1,
                transport: PathTransport::Rist {
                    role: RistRole::Sender,
                    remote: Some(addr_b),
                    local_bind: None,
                    buffer_ms: Some(100),
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
        let payload = Bytes::from(format!("rist-{i:05}"));
        sender.send(payload, PacketHints::default()).await.unwrap();
    }

    let mut got: Vec<Bytes> = Vec::new();
    for _ in 0..N {
        let r = timeout(Duration::from_secs(10), receiver.recv())
            .await
            .expect("all-rist recv timed out")
            .expect("channel closed");
        got.push(r);
    }

    for (i, b) in got.iter().enumerate() {
        assert_eq!(b.as_ref(), format!("rist-{i:05}").as_bytes());
    }

    let stats = receiver.stats().snapshot();
    assert_eq!(stats.gaps_lost, 0, "no gaps should be lost on loopback");

    let a = sender.path_stats(0).unwrap().snapshot();
    let b = sender.path_stats(1).unwrap().snapshot();
    assert!(
        a.packets_sent > 0 && b.packets_sent > 0,
        "both RIST legs must carry traffic: a={a:?} b={b:?}"
    );
}
