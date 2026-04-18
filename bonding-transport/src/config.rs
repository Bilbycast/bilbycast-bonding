//! Configuration for `BondSocket` and path managers.

use std::net::SocketAddr;
use std::time::Duration;

use bonding_protocol::protocol::scheduler::PathId;

/// Top-level socket config. A bond socket binds N paths and either
/// sends or receives bonded traffic.
#[derive(Debug, Clone)]
pub struct BondSocketConfig {
    /// Unique flow identifier — matched between sender and receiver.
    pub flow_id: u32,
    /// Reassembly hold time (receiver only). 32-bit seq space lets
    /// this go large without wrap concerns; 500 ms is a reasonable
    /// baseline for multi-path broadcast links.
    pub hold_time: Duration,
    /// Periodic keepalive interval across every path.
    pub keepalive_interval: Duration,
    /// Max missed keepalives before a path is declared dead.
    pub keepalive_miss_threshold: u32,
    /// Sender retransmit buffer capacity in packets. Sized by caller
    /// against their send rate × longest acceptable NACK round-trip.
    pub retransmit_capacity: usize,
    /// Base delay before the first NACK for a given gap (receiver
    /// side). Extra paths / out-of-order arrivals fill gaps within
    /// this window without triggering a retransmit.
    pub nack_delay: Duration,
    /// Max NACK retries per gap before the receiver gives up and the
    /// gap is reported as lost.
    pub max_nack_retries: u32,
    /// Paths registered on this socket.
    pub paths: Vec<PathConfig>,
}

impl Default for BondSocketConfig {
    fn default() -> Self {
        Self {
            flow_id: 0,
            hold_time: Duration::from_millis(500),
            keepalive_interval: Duration::from_millis(200),
            keepalive_miss_threshold: 5,
            retransmit_capacity: 8192,
            nack_delay: Duration::from_millis(30),
            max_nack_retries: 8,
            paths: Vec::new(),
        }
    }
}

/// A single path definition.
#[derive(Debug, Clone)]
pub struct PathConfig {
    pub id: PathId,
    pub name: String,
    pub transport: PathTransport,
    /// Priority weight hint (1 = default). Higher weights get more
    /// traffic from weighted schedulers during steady state.
    pub weight_hint: u32,
}

/// Transport flavour for a path.
#[derive(Debug, Clone)]
pub enum PathTransport {
    /// Raw UDP — simplest path, fully bidirectional. Local bind is
    /// optional on the sender side (ephemeral port) and required on
    /// the receiver side. `remote` is the primary peer on the sender
    /// side and the expected peer on the receiver side (`None` =
    /// learn on first packet).
    Udp {
        bind: Option<SocketAddr>,
        remote: Option<SocketAddr>,
    },
    /// RIST Simple Profile — unidirectional at the bond layer.
    /// `role` decides whether this leg transmits or receives bond
    /// frames; bond automatically skips recv-role RIST paths when
    /// routing NACKs. Requires port parity (even).
    #[cfg(feature = "path-rist")]
    Rist {
        role: RistRole,
        /// Sender-role: the remote RIST receiver. Receiver-role: unused.
        remote: Option<SocketAddr>,
        /// Sender-role: optional local bind. Receiver-role: required.
        local_bind: Option<SocketAddr>,
        buffer_ms: Option<u32>,
    },
    /// QUIC path (TLS 1.3 + DATAGRAM extension). Full-duplex.
    /// `role` distinguishes the dialing client from the listening
    /// server; both ends must use the same `tls_mode`.
    #[cfg(feature = "path-quic")]
    Quic {
        role: QuicRole,
        /// Client: remote `host:port`. Server: local `bind:port`.
        addr: SocketAddr,
        /// Client: server name for SNI / ALPN. Ignored on server.
        server_name: String,
        tls: QuicTlsMode,
    },
}

/// RIST path role.
#[cfg(feature = "path-rist")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RistRole {
    Sender,
    Receiver,
}

/// QUIC path role.
#[cfg(feature = "path-quic")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicRole {
    Client,
    Server,
}

/// QUIC TLS material — mirrors [`crate::path::quic::QuicTls`] at the
/// config layer.
#[cfg(feature = "path-quic")]
#[derive(Debug, Clone)]
pub enum QuicTlsMode {
    /// Self-signed in-process (loopback / trusted LAN). Client
    /// skips verification; server generates a fresh cert.
    SelfSigned,
    /// PEM cert chain + private key (production).
    Pem {
        cert_chain: Vec<u8>,
        private_key: Vec<u8>,
        client_trust_root: Option<Vec<u8>>,
    },
}
