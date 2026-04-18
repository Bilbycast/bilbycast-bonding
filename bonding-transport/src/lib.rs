//! Async bonding transport: path managers, sender/receiver tasks,
//! scheduler wiring, stats publication.
//!
//! Phase 2: UDP path + `BondSocket` sender/receiver with end-to-end
//! NACK-based recovery and per-path keepalive-driven RTT/loss.
//! Phase 3 adds QUIC / SRT / RIST path adapters.
//!
//! ## Example
//!
//! ```ignore
//! use bonding_transport::{
//!     BondSocket, BondSocketConfig, PathConfig, PathTransport,
//!     WeightedRttScheduler,
//! };
//!
//! let cfg = BondSocketConfig {
//!     flow_id: 42,
//!     paths: vec![
//!         PathConfig {
//!             id: 0,
//!             name: "lte-0".into(),
//!             weight_hint: 1,
//!             transport: PathTransport::Udp {
//!                 bind: None,
//!                 remote: Some("203.0.113.5:7000".parse().unwrap()),
//!                 interface: Some("wwan0".into()),
//!             },
//!         },
//!         PathConfig {
//!             id: 1,
//!             name: "ethernet".into(),
//!             weight_hint: 1,
//!             transport: PathTransport::Udp {
//!                 bind: None,
//!                 remote: Some("203.0.113.5:7002".parse().unwrap()),
//!                 interface: Some("eth0".into()),
//!             },
//!         },
//!     ],
//!     ..Default::default()
//! };
//! let sched = WeightedRttScheduler::new(vec![0, 1]);
//! let socket = BondSocket::sender(cfg, sched).await?;
//! socket.send(payload, Default::default()).await?;
//! # Ok::<(), bonding_transport::BondSocketError>(())
//! ```

pub mod config;
pub(crate) mod health;
pub mod path;
pub mod receiver;
pub mod sender;
pub mod socket;

pub use bonding_protocol::{
    events::{PathDeadReason, PathEvent, PathEventKind},
    packet::{BondHeader, Priority},
    protocol::{
        path_health::PathHealth,
        scheduler::{
            BondScheduler, PacketHints, PathId, PathSelection, RoundRobinScheduler,
            WeightedRttScheduler,
        },
    },
    stats::{BondConnStats, BondConnStatsSnapshot, PathStats, PathStatsSnapshot},
};
pub use config::{BondSocketConfig, PathConfig, PathTransport};
#[cfg(feature = "path-quic")]
pub use config::{QuicRole, QuicTlsMode};
#[cfg(feature = "path-rist")]
pub use config::RistRole;
pub use socket::{BondSocket, BondSocketError, BondResult};
