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
    BondSocket, BondSocketConfig, PacketHints, PathConfig, PathEventKind, PathTransport,
    QuicRole, QuicTlsMode, WeightedRttScheduler,
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
                    bind: None,
                    interface: None,
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
                    bind: None,
                    interface: None,
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
                    bind: None,
                    interface: None,
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
                    bind: None,
                    interface: None,
                },
            },
        ],
        ..Default::default()
    };
    let sched = WeightedRttScheduler::new(vec![0, 1]);
    let sender = BondSocket::sender(tx_cfg, sched).await.unwrap();

    let receiver = rx_handle.await.unwrap().unwrap();

    // QUIC client legs dial in the background (non-blocking build), so give
    // them a moment to connect before the counted stream — a cold leg drops
    // packets sent before its handshake completes.
    tokio::time::sleep(Duration::from_millis(600)).await;

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

    // Both legs must still be ALIVE at the end. That is what this test is
    // actually about: the bond stood up two transports and neither fell over.
    //
    // Deliberately NOT asserted: that each leg carried at least one *data*
    // packet. Which leg gets a packet is the scheduler's call, and none of
    // the schedulers here promise to touch every leg — over a short burst the
    // first leg to establish a capacity estimate can legitimately win all of
    // it. Asserting otherwise made this test fail roughly 1 run in 10
    // (measured: the identical binary, no source change between runs, passed
    // 9/10), and on the failing runs the idle leg was plainly healthy —
    // connected, keepalives flowing both ways, `dead == false`. Delivery,
    // ordering and zero-loss are asserted above; those are the real contract.
    assert!(!s0.dead, "QUIC path 0 died during the test: {s0:?}");
    assert!(!s1.dead, "QUIC path 1 died during the test: {s1:?}");
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
                    bind: None,
                    interface: None,
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
                    bind: None,
                    interface: None,
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

    // Liveness, not leg-selection — same reasoning as
    // `two_quic_paths_deliver_in_order` above. The heterogeneous point of
    // this test is that a UDP leg and a QUIC leg coexist in one bond and the
    // stream arrives intact; the split between them is scheduler policy.
    assert!(!udp_stats.dead, "UDP path died during the test: {udp_stats:?}");
    assert!(!quic_stats.dead, "QUIC path died during the test: {quic_stats:?}");
}

/// QUIC client with an **explicit source bind** (`bind: Some(...)`).
/// Exercises the per-leg pinning path added for multi-homed senders —
/// the client endpoint is built on a socket bound to a chosen source
/// address (here loopback) via `build_pinned_std_socket` rather than
/// the default `0.0.0.0:0`. Proves the pinned-socket path connects and
/// carries bond frames end-to-end. (Interface pinning itself needs
/// CAP_NET_RAW and a real NIC, so it isn't asserted here.)
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn quic_client_with_explicit_bind_delivers() {
    let s_port = free_port().await;
    let s_addr: SocketAddr = format!("127.0.0.1:{s_port}").parse().unwrap();

    let rx_cfg = BondSocketConfig {
        flow_id: 11,
        hold_time: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(150),
        paths: vec![PathConfig {
            id: 0,
            name: "quic".into(),
            weight_hint: 1,
            transport: PathTransport::Quic {
                role: QuicRole::Server,
                addr: s_addr,
                server_name: "localhost".into(),
                tls: QuicTlsMode::SelfSigned,
                bind: None,
                interface: None,
            },
        }],
        ..Default::default()
    };
    let rx_handle = tokio::spawn(async move { BondSocket::receiver(rx_cfg).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let tx_cfg = BondSocketConfig {
        flow_id: 11,
        keepalive_interval: Duration::from_millis(150),
        paths: vec![PathConfig {
            id: 0,
            name: "quic".into(),
            weight_hint: 1,
            transport: PathTransport::Quic {
                role: QuicRole::Client,
                addr: s_addr,
                server_name: "localhost".into(),
                tls: QuicTlsMode::SelfSigned,
                // The new per-leg source bind — pin egress to loopback.
                bind: Some("127.0.0.1:0".parse().unwrap()),
                interface: None,
            },
        }],
        ..Default::default()
    };
    let sched = WeightedRttScheduler::new(vec![0]);
    let sender = BondSocket::sender(tx_cfg, sched).await.unwrap();
    let receiver = rx_handle.await.unwrap().unwrap();

    // Non-blocking client: let the background dial connect before the counted
    // send (a cold leg drops packets sent before its handshake completes).
    tokio::time::sleep(Duration::from_millis(600)).await;

    const N: u32 = 50;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("bind-{i:05}")), PacketHints::default())
            .await
            .unwrap();
    }
    for i in 0..N {
        let r = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("bound-quic recv timed out")
            .expect("channel closed");
        assert_eq!(r.as_ref(), format!("bind-{i:05}").as_bytes());
    }

    let s0 = sender.path_stats(0).unwrap().snapshot();
    assert!(s0.packets_sent > 0, "bound QUIC client must carry traffic: {s0:?}");

    let rstats = receiver.stats().snapshot();
    assert_eq!(rstats.gaps_lost, 0);
}

/// PR1 regression guard + late-join proof. A QUIC **client** leg whose server
/// is DOWN at build time must NOT block the bond build — it used to block on
/// the handshake (~25s idle timeout). The build returns immediately; the leg
/// re-dials in the background and, once the server appears, JOINS the live
/// bond and carries traffic with no rebuild/restart. This is the "turn on the
/// flow and the leg comes up on its own / rejoins after a drop" behaviour.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn quic_client_late_join_does_not_block_build() {
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // Build the client sender while NO server is listening on `addr`.
    let tx_cfg = BondSocketConfig {
        flow_id: 21,
        keepalive_interval: Duration::from_millis(150),
        paths: vec![PathConfig {
            id: 0,
            name: "quic-late".into(),
            weight_hint: 1,
            transport: PathTransport::Quic {
                role: QuicRole::Client,
                addr,
                server_name: "localhost".into(),
                tls: QuicTlsMode::SelfSigned,
                bind: None,
                interface: None,
            },
        }],
        ..Default::default()
    };
    let sched = WeightedRttScheduler::new(vec![0]);

    let start = std::time::Instant::now();
    let sender = BondSocket::sender(tx_cfg, sched).await.unwrap();
    let build_elapsed = start.elapsed();
    // Non-blocking: the build must NOT wait on the (failing) handshake. Before
    // PR1 this blocked ~25s; even the bounded dial alone would be 6s. Under 2s
    // proves the build doesn't dial inline.
    assert!(
        build_elapsed < Duration::from_secs(2),
        "client build blocked on a down leg: {build_elapsed:?} (should be instant)"
    );

    // Subscribe BEFORE the down period so we catch the self-redial events.
    let mut events = sender.subscribe_events();

    // Keep the server down long enough for the first dial to fail (bounded at
    // 6s) so the leg records its cause and a liveness tick surfaces it. A leg
    // that was already up and *drops* records the cause immediately; a
    // down-at-start leg only knows the cause once the first handshake times
    // out, which is the slower path we deliberately exercise here.
    tokio::time::sleep(Duration::from_millis(8000)).await;

    // PR2: the background re-dial must surface a PathReconnecting event
    // carrying the SPECIFIC cause, so an operator sees WHY the leg is down.
    let mut saw_reconnecting_cause: Option<String> = None;
    while let Ok(ev) = events.try_recv() {
        if let PathEventKind::PathReconnecting { reason } = ev.kind {
            saw_reconnecting_cause = Some(reason);
        }
    }
    let cause = saw_reconnecting_cause
        .expect("self-redial must emit PathReconnecting while the server is down");
    assert!(
        !cause.is_empty(),
        "PathReconnecting must carry a non-empty cause"
    );

    let rx_cfg = BondSocketConfig {
        flow_id: 21,
        hold_time: Duration::from_millis(200),
        nack_delay: Duration::from_millis(40),
        keepalive_interval: Duration::from_millis(150),
        paths: vec![PathConfig {
            id: 0,
            name: "quic-late".into(),
            weight_hint: 1,
            transport: PathTransport::Quic {
                role: QuicRole::Server,
                addr,
                server_name: "localhost".into(),
                tls: QuicTlsMode::SelfSigned,
                bind: None,
                interface: None,
            },
        }],
        ..Default::default()
    };
    let receiver = BondSocket::receiver(rx_cfg).await.unwrap();

    // Let the client's background dial find the now-up server and join.
    tokio::time::sleep(Duration::from_millis(4000)).await;

    // The leg has joined the live bond — traffic now flows end to end.
    const N: u32 = 50;
    for i in 0..N {
        sender
            .send(Bytes::from(format!("late-{i:05}")), PacketHints::default())
            .await
            .unwrap();
    }
    for i in 0..N {
        let r = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("late-join recv timed out — leg did not rejoin")
            .expect("channel closed");
        assert_eq!(r.as_ref(), format!("late-{i:05}").as_bytes());
    }

    let s0 = sender.path_stats(0).unwrap().snapshot();
    assert!(
        s0.packets_sent > 0,
        "late-joined QUIC leg must carry traffic: {s0:?}"
    );
}
