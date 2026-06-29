//! Configuration for `BondSocket` and path managers.

use std::net::SocketAddr;
use std::time::Duration;

use bonding_protocol::protocol::fec::FecParams;
use bonding_protocol::protocol::scheduler::PathId;

/// Top-level socket config. A bond socket binds N paths and either
/// sends or receives bonded traffic.
#[derive(Debug, Clone)]
pub struct BondSocketConfig {
    /// Unique flow identifier — matched between sender and receiver.
    pub flow_id: u32,
    /// Reassembly hold time (receiver only). 32-bit seq space lets
    /// this go large without wrap concerns; 500 ms is a reasonable
    /// baseline for multi-path broadcast links. When `hold_max` is set
    /// this is the **floor** the adaptive servo grows up from.
    pub hold_time: Duration,
    /// Optional ceiling for adaptive hold-time (receiver only). When set
    /// above `hold_time`, the receiver grows the reorder/recovery budget
    /// toward the realized recovery latency (×1.5) within
    /// `[hold_time, hold_max]` and decays back when the network calms —
    /// so latency tracks the links instead of a fixed guess. `None` =
    /// fixed `hold_time` (default, unchanged behaviour).
    pub hold_max: Option<Duration>,
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
    /// Optional 32-byte AEAD key. When set, every UDP/RIST datagram on
    /// this bond is ChaCha20-Poly1305 sealed (both ends must share the
    /// key). QUIC paths are already TLS-encrypted and ignore this.
    pub encryption_key: Option<Vec<u8>>,
    /// Optional **combined** proactive FEC geometry. `None` = off (default).
    /// When set, the sender emits XOR repair packets over the *global* bond
    /// sequence and the receiver recovers sparse loss without a NACK
    /// round-trip. Both ends must agree. Mutually exclusive with
    /// [`Self::per_path_fec`] (combined protects the striped stream; per-leg
    /// protects each leg independently — you pick one model per bond).
    pub fec: Option<FecParams>,
    /// Optional **per-leg** proactive FEC, keyed by `PathId`. When non-empty,
    /// each listed leg runs its own FEC over only the packets it carries, so
    /// a burst on one leg (e.g. a Starlink handoff) is recovered locally
    /// before it pollutes the combined reassembler, and each leg's FEC
    /// budget is dedicated. Activating this (non-empty) selects per-leg mode
    /// and the combined [`Self::fec`] is ignored. Both ends must list the
    /// same algorithm + geometry for a leg. ARQ stays combined + cross-leg.
    pub per_path_fec: std::collections::HashMap<PathId, PerLegFecKind>,
    /// Per-leg latency/jitter **equalization** mode (see
    /// `docs/per-leg-equalization.md`). Controls whether the SENDER stamps
    /// each data packet with a v2 (16-byte) header send-timestamp and whether
    /// the RECEIVER time-aligns legs so heterogeneous high-latency/jitter legs
    /// AGGREGATE their bandwidth instead of head-of-line-blocking. See
    /// [`EqualizationMode`]. `Off` by default → v1 headers, byte-for-byte the
    /// pre-equalization path.
    pub equalization: EqualizationMode,
    /// Sender-only: this bond replicates ALL traffic across legs (ride-fastest
    /// / duplicate-all redundancy), so the receiver must NOT time-align legs
    /// (holding the fast copy to align a slow duplicate defeats the point).
    /// Signalled to the receiver on the keepalive; ignored on a receiver
    /// socket. Default `false`. `EqualizationMode::On` overrides it.
    pub align_suppress: bool,
    /// Paths registered on this socket.
    pub paths: Vec<PathConfig>,
}

/// Per-leg equalization mode for a bonded socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EqualizationMode {
    /// Never stamp, never measure, never align — byte-for-byte the legacy
    /// aggregate-but-never-align path. The latency-critical escape hatch:
    /// a slow leg's reorder is recovered by ARQ/FEC rather than absorbed by
    /// alignment latency.
    #[default]
    Off,
    /// Stamp + measure one-way delay ALWAYS; engage alignment only when the
    /// measured inter-leg skew exceeds a non-trivial floor, fits the latency
    /// budget, and the sender isn't signalling ride-fastest. A homogeneous
    /// bond therefore measures ~zero skew and stays a no-op; a heterogeneous
    /// bond (cellular + Starlink) aligns itself. The self-configuring default
    /// for the aggregation use case.
    Auto,
    /// Force-engage alignment whenever any leg is warm — overrides the
    /// ride-fastest suppression (for a time-aligned downstream consumer of a
    /// duplicate-all bond).
    On,
}

impl EqualizationMode {
    /// Whether this mode stamps v2 headers / advertises v2 capability /
    /// measures OWD. `Off` does none of it.
    #[inline]
    pub fn measures(&self) -> bool {
        !matches!(self, EqualizationMode::Off)
    }
}

impl Default for BondSocketConfig {
    fn default() -> Self {
        Self {
            flow_id: 0,
            hold_time: Duration::from_millis(500),
            hold_max: None,
            keepalive_interval: Duration::from_millis(200),
            keepalive_miss_threshold: 5,
            retransmit_capacity: 8192,
            nack_delay: Duration::from_millis(30),
            max_nack_retries: 8,
            encryption_key: None,
            fec: None,
            per_path_fec: std::collections::HashMap::new(),
            equalization: EqualizationMode::Off,
            align_suppress: false,
            paths: Vec::new(),
        }
    }
}

/// Per-leg FEC algorithm + geometry for one leg.
#[derive(Debug, Clone, Copy)]
pub enum PerLegFecKind {
    /// Interleaved XOR (SMPTE 2022-1 column model) — recovers one loss per
    /// column; a burst up to `columns` consecutive leg packets.
    Xor(FecParams),
    /// Reed-Solomon — recovers up to `parity` losses among each
    /// `data + parity` block. Stronger for a chronically-lossy leg, at
    /// `parity/data` overhead. `data + parity ≤ 256`. When `parity_max >
    /// parity` the parity is **adaptive** — it scales between
    /// `[parity, parity_max]` with the leg's recent loss; equal = fixed.
    ReedSolomon {
        data: u16,
        parity: u16,
        parity_max: u16,
    },
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
    ///
    /// `interface` pins egress traffic to a specific NIC (e.g.
    /// `"eth0"`, `"wwan0"`). `None` leaves selection to the kernel
    /// routing table. See `docs/nic-pinning.md` for platform detail
    /// (Linux prefers `SO_BINDTODEVICE` under `CAP_NET_RAW` and
    /// falls back to the unprivileged `IP_UNICAST_IF` egress hint;
    /// macOS / FreeBSD are unprivileged).
    ///
    /// Paths with an `interface` pin or a specific (non-wildcard)
    /// `bind` IP are covered by the per-bond interface watcher:
    /// on USB-dongle re-plug, ifindex change or DHCP renumber the
    /// socket is rebuilt and re-pinned in place (`PathRebuilt` /
    /// `InterfaceLost` events). UDP only — QUIC / RIST legs manage
    /// their own connections.
    Udp {
        bind: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        interface: Option<String>,
    },
    /// In-process **attached** leg — a relayed bonded leg whose carrier is an
    /// `mpsc` bridge owned by the host (the edge) rather than a socket. The
    /// host bridge owns the relay socket (Register/keepalive rendezvous +
    /// failover) and the tunnel framing; the bond hands it datagrams in
    /// process with no loopback hop. `primary_peer` is a synthetic placeholder
    /// (the bridge owns the real relay peer) so the keepalive + NACK
    /// back-channel machinery treats the leg as live.
    ///
    /// The channel endpoints can't live here (the enum is `Clone + Debug`,
    /// `mpsc::Receiver` is neither) — they travel in the separate
    /// `attachments` argument to
    /// [`BondSocket::sender_attached`](crate::socket::BondSocket::sender_attached)
    /// / [`receiver_attached`](crate::socket::BondSocket::receiver_attached),
    /// keyed by `PathId`.
    Attached { primary_peer: SocketAddr },
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
        /// Client-only local source bind (`ip:port`, port usually 0).
        /// Without it the client endpoint binds `0.0.0.0:0` and the
        /// kernel routing table picks the egress NIC — so on a
        /// multi-homed host (several modems) every QUIC leg collapses
        /// onto the default route and the bond is cosmetic. Set this to
        /// a source IP that policy-routes out the intended uplink.
        /// Ignored on the server side (it binds `addr`).
        bind: Option<SocketAddr>,
        /// Optional NIC pin (e.g. `"wwan0"`, `"eno4"`) — same mechanism
        /// as the UDP leg (`SO_BINDTODEVICE` under `CAP_NET_RAW`,
        /// falling back to the unprivileged `IP_UNICAST_IF` egress
        /// hint). Applies to both client and server endpoints. `None`
        /// leaves egress to the routing table / `bind`.
        interface: Option<String>,
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
