//! JSON configuration for `bilbycast-bonder`.
//!
//! Minimal shape — one file describes a complete bonder role
//! (sender or receiver). The config is stable enough to check into
//! git; fields are optional where sensible so short configs stay
//! short. Example (sender):
//!
//! ```json
//! {
//!   "flow_id": 42,
//!   "role": "sender",
//!   "input": { "type": "udp", "bind": "0.0.0.0:5555" },
//!   "scheduler": "weighted_rtt",
//!   "paths": [
//!     { "id": 0, "name": "lte-0",
//!       "transport": { "type": "udp", "remote": "hub.example.com:7000",
//!                      "interface": "wwan0" } },
//!     { "id": 1, "name": "ether",
//!       "transport": { "type": "udp", "remote": "hub.example.com:7001",
//!                      "interface": "eth0" } }
//!   ]
//! }
//! ```
//!
//! The optional `interface` pins egress to a specific NIC — see
//! `docs/nic-pinning.md` for platform requirements. Omit it to let
//! the kernel routing table decide.

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use bonding_transport::{
    BondSocketConfig, PathConfig as TxPathConfig, PathTransport as TxPathTransport,
};

#[cfg(feature = "path-quic")]
use bonding_transport::{QuicRole, QuicTlsMode};

#[cfg(feature = "path-rist")]
use bonding_transport::RistRole;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BonderConfig {
    /// Unique flow identifier — must match between sender and receiver.
    pub flow_id: u32,
    /// Bonder role.
    pub role: BonderRole,
    /// Ingress (sender role only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<IoEndpoint>,
    /// Egress (receiver role only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<IoEndpoint>,
    /// Scheduling policy. Default: `weighted_rtt`.
    #[serde(default)]
    pub scheduler: SchedulerKind,
    /// Registered paths — one entry per bond leg.
    pub paths: Vec<PathSpec>,
    /// Optional BondSocketConfig overrides.
    #[serde(default)]
    pub tuning: Tuning,
    /// Bridge role only: the EGRESS bond (toward edge B). The top-level
    /// `flow_id` / `paths` / `scheduler` / `tuning` describe the INGRESS bond
    /// (the legs arriving from edge A, terminated here as a receiver); this
    /// block describes the re-originated bond/single path toward edge B.
    /// Must use a DIFFERENT `flow_id` from the ingress side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_egress: Option<BridgeEgress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BonderRole {
    Sender,
    Receiver,
    /// Relay-hosted bond bridge: terminate the ingress bond from edge A
    /// (full ARQ/FEC/reorder recovery), then re-originate a fresh bond /
    /// single path to edge B. Lets a public relay host aggregate edge A's
    /// 5G/Starlink legs into one recovered stream, then forward to edge B.
    Bridge,
}

/// Egress side of a [`BonderRole::Bridge`] — a fresh bond toward edge B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeEgress {
    /// Flow id for the egress bond. MUST differ from the ingress `flow_id`.
    pub flow_id: u32,
    /// Scheduling policy for the egress bond. Default: `weighted_rtt`.
    #[serde(default)]
    pub scheduler: SchedulerKind,
    /// Egress bond legs (one entry = a single forward path; multiple = a bond).
    pub paths: Vec<PathSpec>,
    /// Optional BondSocketConfig overrides for the egress bond.
    #[serde(default)]
    pub tuning: Tuning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IoEndpoint {
    /// UDP ingress (sender side) or egress (receiver side).
    Udp {
        /// Sender side: local bind address that upstream ffmpeg /
        /// camera / encoder sends into.
        /// Receiver side: destination address for the reassembled
        /// stream.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bind: Option<SocketAddr>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dest: Option<SocketAddr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerKind {
    WeightedRtt,
    RoundRobin,
}

impl Default for SchedulerKind {
    fn default() -> Self {
        SchedulerKind::WeightedRtt
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSpec {
    pub id: u8,
    pub name: String,
    pub transport: PathTransportSpec,
    #[serde(default = "default_weight")]
    pub weight_hint: u32,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PathTransportSpec {
    /// Raw UDP — simplest path, works anywhere UDP does.
    ///
    /// `interface` optionally pins egress traffic to a specific NIC
    /// (`"eth0"`, `"wwan0"`, …) so paths don't all collapse onto the
    /// default route. See `docs/nic-pinning.md` — on Linux this needs
    /// `CAP_NET_RAW`; on macOS / FreeBSD it is unprivileged.
    Udp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bind: Option<SocketAddr>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remote: Option<SocketAddr>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
    },
    /// RIST Simple Profile leg. `role` MUST match the sender / receiver
    /// intent: senders use RIST-sender legs, receivers use
    /// RIST-receiver legs. Bond automatically skips non-reply-capable
    /// RIST paths when routing NACKs.
    #[cfg(feature = "path-rist")]
    Rist {
        #[serde(rename = "rist_role")]
        role: RistRoleCfg,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remote: Option<SocketAddr>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local_bind: Option<SocketAddr>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        buffer_ms: Option<u32>,
    },
    /// QUIC path (TLS 1.3). `role` is `client` (dials) or `server`
    /// (listens).
    #[cfg(feature = "path-quic")]
    Quic {
        #[serde(rename = "quic_role")]
        role: QuicRoleCfg,
        addr: SocketAddr,
        server_name: String,
        tls: TlsCfg,
        /// Client-only local source bind (`ip:port`, port usually 0) so a
        /// multi-homed host can policy-route this leg out a chosen uplink.
        /// Ignored on the server side (it binds `addr`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bind: Option<SocketAddr>,
        /// Optional NIC pin (`"wwan0"`, `"eno4"`…) — same mechanism as the
        /// UDP leg. See `docs/nic-pinning.md`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
    },
}

#[cfg(feature = "path-rist")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RistRoleCfg {
    Sender,
    Receiver,
}

#[cfg(feature = "path-quic")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicRoleCfg {
    Client,
    Server,
}

#[cfg(feature = "path-quic")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TlsCfg {
    /// Self-signed in-process. Dev / loopback / trusted LAN.
    SelfSigned,
    /// Load PEM cert + key from on-disk paths.
    Pem {
        cert_chain_path: String,
        private_key_path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_trust_root_path: Option<String>,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tuning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nack_delay_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nack_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retransmit_capacity: Option<usize>,
}

impl BonderConfig {
    /// Translate the INGRESS side (top-level fields) to a `BondSocketConfig`
    /// suitable for `BondSocket::sender` or `BondSocket::receiver`.
    pub fn to_socket_config(&self) -> anyhow::Result<BondSocketConfig> {
        build_socket_config(self.flow_id, &self.paths, &self.tuning)
    }

    /// Bridge role: the EGRESS `BondSocketConfig` (toward edge B).
    pub fn egress_socket_config(&self) -> anyhow::Result<BondSocketConfig> {
        let eg = self
            .bridge_egress
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("bridge role requires `bridge_egress`"))?;
        if eg.flow_id == self.flow_id {
            anyhow::bail!(
                "bridge_egress.flow_id ({}) must differ from the ingress flow_id",
                eg.flow_id
            );
        }
        build_socket_config(eg.flow_id, &eg.paths, &eg.tuning)
    }
}

/// Build a `BondSocketConfig` from a flow id + path set + tuning. Shared by the
/// sender / receiver / bridge roles.
fn build_socket_config(
    flow_id: u32,
    paths: &[PathSpec],
    tuning: &Tuning,
) -> anyhow::Result<BondSocketConfig> {
    let mut cfg = BondSocketConfig {
        flow_id,
        paths: Vec::with_capacity(paths.len()),
        ..Default::default()
    };
    if let Some(ms) = tuning.hold_ms {
        cfg.hold_time = Duration::from_millis(ms as u64);
    }
    if let Some(ms) = tuning.keepalive_ms {
        cfg.keepalive_interval = Duration::from_millis(ms as u64);
    }
    if let Some(ms) = tuning.nack_delay_ms {
        cfg.nack_delay = Duration::from_millis(ms as u64);
    }
    if let Some(n) = tuning.max_nack_retries {
        cfg.max_nack_retries = n;
    }
    if let Some(n) = tuning.retransmit_capacity {
        cfg.retransmit_capacity = n;
    }
    for p in paths {
        cfg.paths.push(TxPathConfig {
            id: p.id,
            name: p.name.clone(),
            transport: translate_transport(&p.transport)?,
            weight_hint: p.weight_hint,
        });
    }
    Ok(cfg)
}

fn translate_transport(t: &PathTransportSpec) -> anyhow::Result<TxPathTransport> {
    Ok(match t {
        PathTransportSpec::Udp {
            bind,
            remote,
            interface,
        } => TxPathTransport::Udp {
            bind: *bind,
            remote: *remote,
            interface: interface.clone(),
        },
        #[cfg(feature = "path-rist")]
        PathTransportSpec::Rist {
            role,
            remote,
            local_bind,
            buffer_ms,
        } => TxPathTransport::Rist {
            role: match role {
                RistRoleCfg::Sender => RistRole::Sender,
                RistRoleCfg::Receiver => RistRole::Receiver,
            },
            remote: *remote,
            local_bind: *local_bind,
            buffer_ms: *buffer_ms,
        },
        #[cfg(feature = "path-quic")]
        PathTransportSpec::Quic {
            role,
            addr,
            server_name,
            tls,
            bind,
            interface,
        } => {
            let tls_mode = match tls {
                TlsCfg::SelfSigned => QuicTlsMode::SelfSigned,
                TlsCfg::Pem {
                    cert_chain_path,
                    private_key_path,
                    client_trust_root_path,
                } => {
                    let cert_chain = std::fs::read(cert_chain_path)
                        .map_err(|e| anyhow::anyhow!("read cert chain: {e}"))?;
                    let private_key = std::fs::read(private_key_path)
                        .map_err(|e| anyhow::anyhow!("read private key: {e}"))?;
                    let client_trust_root = match client_trust_root_path {
                        Some(p) => Some(
                            std::fs::read(p)
                                .map_err(|e| anyhow::anyhow!("read trust root: {e}"))?,
                        ),
                        None => None,
                    };
                    QuicTlsMode::Pem {
                        cert_chain,
                        private_key,
                        client_trust_root,
                    }
                }
            };
            TxPathTransport::Quic {
                role: match role {
                    QuicRoleCfg::Client => QuicRole::Client,
                    QuicRoleCfg::Server => QuicRole::Server,
                },
                addr: *addr,
                server_name: server_name.clone(),
                tls: tls_mode,
                bind: *bind,
                interface: interface.clone(),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BRIDGE_JSON: &str = r#"{
        "flow_id": 42, "role": "bridge",
        "paths": [
            { "id": 0, "name": "legA", "transport": { "type": "udp", "bind": "127.0.0.1:17000" } },
            { "id": 1, "name": "legB", "transport": { "type": "udp", "bind": "127.0.0.1:17002" } }
        ],
        "bridge_egress": {
            "flow_id": 99,
            "paths": [ { "id": 0, "name": "eg", "transport": { "type": "udp", "remote": "127.0.0.1:17010" } } ]
        }
    }"#;

    #[test]
    fn bridge_config_parses_and_builds_both_sides() {
        let cfg: BonderConfig = serde_json::from_str(BRIDGE_JSON).unwrap();
        assert_eq!(cfg.role, BonderRole::Bridge);
        // Ingress (top-level) bond: flow 42, two legs.
        let in_cfg = cfg.to_socket_config().unwrap();
        assert_eq!(in_cfg.flow_id, 42);
        assert_eq!(in_cfg.paths.len(), 2);
        // Egress bond: flow 99, one leg.
        let eg_cfg = cfg.egress_socket_config().unwrap();
        assert_eq!(eg_cfg.flow_id, 99);
        assert_eq!(eg_cfg.paths.len(), 1);
    }

    #[test]
    fn bridge_rejects_same_flow_id_on_both_hops() {
        // Re-using one flow_id across both bonds would cross-wire keepalives.
        let mut cfg: BonderConfig = serde_json::from_str(BRIDGE_JSON).unwrap();
        cfg.bridge_egress.as_mut().unwrap().flow_id = cfg.flow_id;
        assert!(cfg.egress_socket_config().is_err());
    }

    #[test]
    fn bridge_without_egress_is_an_error() {
        let mut cfg: BonderConfig = serde_json::from_str(BRIDGE_JSON).unwrap();
        cfg.bridge_egress = None;
        assert!(cfg.egress_socket_config().is_err());
    }
}
