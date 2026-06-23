//! QUIC path adapter (quinn + rustls + ring).
//!
//! Each QUIC-backed bond path is a single QUIC connection. Bond
//! frames ride the [QUIC DATAGRAM extension] (RFC 9221) — unreliable
//! unordered datagrams carried inside the QUIC flow. Bond's own
//! reassembly buffer and NACK layer own reliability; QUIC gives us
//! TLS 1.3 encryption, multiplexing, and path validation for free.
//!
//! [QUIC DATAGRAM extension]: https://datatracker.ietf.org/doc/rfc9221/
//!
//! ## ALPN
//!
//! `bilbycast-bond`. Both ends MUST negotiate this ALPN; other
//! protocols riding the same UDP port (HTTP/3, bilbycast-relay's own
//! tunnels) stay isolated.
//!
//! ## Cert handling
//!
//! - **Self-signed** is generated in-process when no cert is supplied,
//!   used for loopback tests and trusted-network trials. The self-
//!   signed cert is advertised to the client as a trust anchor so
//!   the connection succeeds without a real CA.
//! - **File-based** loads a PEM cert + key pair, and optionally a
//!   custom root store — the production mode.
//!
//! ## Bidirectionality
//!
//! A single QUIC connection is full-duplex. The server side receives
//! a connection from the client; thereafter both sides send QUIC
//! datagrams in either direction. Bond's sender loop can push data
//! outbound, and the receiver's NACK / keepalive-ack path can push
//! back in — no path asymmetry to work around, unlike RIST.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig, TokioRuntime,
    TransportConfig, crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use arc_swap::ArcSwapOption;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use bonding_protocol::protocol::scheduler::PathId;

use super::{PathDatagram, PathError, PathResult};

/// ALPN protocol identifier. Must match on both ends.
pub const BOND_ALPN: &[u8] = b"bilbycast-bond";

/// TLS material for a QUIC path. Self-signed mode is convenient for
/// loopback tests and trusted-LAN links; production deployments pass
/// `Pem` with a real cert chain.
#[derive(Clone)]
pub enum QuicTls {
    /// Generate a single self-signed cert in-process (dev / loopback).
    /// Both client and server use the same generated cert so there
    /// is no CA step to configure.
    SelfSigned,
    /// Load cert chain + private key from PEM byte slices.
    Pem {
        cert_chain: Vec<u8>,
        private_key: Vec<u8>,
        /// Optional custom trust root for client-side verification.
        client_trust_root: Option<Vec<u8>>,
    },
}

pub struct QuicPath {
    id: PathId,
    name: String,
    /// Retained so the endpoint outlives the connection and can accept
    /// further connections (server mode). Client mode uses it to
    /// open the initial connection.
    endpoint: Endpoint,
    // Shared with the rx-pump task so a server path can swap in a fresh
    // connection on re-accept (and `send()` then follows it). Lock-free
    // (`ArcSwapOption`, mirroring the UDP leg's socket hot-swap) so the
    // per-datagram send path never takes a blocking lock — the rx-pump
    // `store()`s a new connection on re-accept, the next send `load()`s it.
    conn: Arc<ArcSwapOption<Connection>>,
    primary_peer: Arc<Mutex<Option<SocketAddr>>>,
    // Lock-free "why is this leg not connected" reason. `None` while
    // connected; `Some(cause)` while the rx-pump is (re)dialing after a
    // failure/drop — e.g. "handshake timed out". Read by the sender to emit
    // a `PathReconnecting` event so operators see the specific cause.
    link_reason: Arc<ArcSwapOption<String>>,
    rx: Mutex<Option<mpsc::Receiver<PathDatagram>>>,
    cancel: CancellationToken,
    _task: tokio::task::JoinHandle<()>,
}

impl QuicPath {
    /// Client: dial `remote`, present the supplied TLS material,
    /// negotiate ALPN `bilbycast-bond`, and start pumping datagrams.
    ///
    /// `bind` sets the local source `ip:port` (port usually 0) and
    /// `interface` pins egress to a NIC — both required to keep two
    /// QUIC legs on a multi-homed host from collapsing onto the default
    /// route (see the `PathTransport::Quic` docs). `bind = None` ⇒
    /// `0.0.0.0:0` / `[::]:0`; `interface = None` ⇒ routing-table egress.
    pub async fn client(
        id: PathId,
        name: impl Into<String>,
        remote: SocketAddr,
        server_name: &str,
        tls: QuicTls,
        bind: Option<SocketAddr>,
        interface: Option<&str>,
    ) -> PathResult<Self> {
        install_default_crypto_provider();
        let bind_addr: SocketAddr = bind.unwrap_or_else(|| {
            if remote.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            }
        });
        // Pin the underlying UDP socket the same way the UDP leg does
        // (SO_BINDTODEVICE → IP_UNICAST_IF fallback), then hand it to a
        // client-only quinn endpoint.
        let (std_socket, _pin) = crate::path::udp::build_pinned_std_socket(bind_addr, interface)?;
        let client_cfg = build_client_config(&tls)?;
        let mut endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            std_socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|e| PathError::Other(format!("quic client endpoint: {e}")))?;
        endpoint.set_default_client_config(client_cfg);
        // Non-blocking: do NOT await the handshake here. The dial runs in the
        // background pump (`Reconnect::ClientDial`) so building a bonded output
        // never stalls ~25s on a leg whose uplink is down — and a leg that
        // drops mid-stream (e.g. a Starlink satellite handover) re-dials itself
        // and rejoins the LIVE bond, with no flow restart. The send path
        // already tolerates a not-yet-connected leg (`send()` errors → the
        // scheduler treats it as dead until the keepalive-ack revives it).
        Ok(Self::spawn_rx_pump(
            id,
            name.into(),
            endpoint,
            Some(remote),
            Reconnect::ClientDial {
                remote,
                server_name: server_name.to_string(),
            },
        ))
    }

    /// Server: bind to `local`, then accept the first client (and
    /// re-accept on loss) in the **background** pump. Binding the endpoint
    /// is all that's needed to build the path.
    ///
    /// Crucially this does **not** block on `accept()`. A bonded receiver
    /// builds all its legs (`BondSocket::receiver` → `build_paths`) before
    /// its receive loop starts; blocking here on a client that connects
    /// late — or, for an over-provisioned receiver with more server legs
    /// than the sender dials, *never* — would stall the entire bond build
    /// forever, leaving every leg dead. Unlike UDP (which only binds), the
    /// old blocking-accept made QUIC legs fragile to leg-count mismatch and
    /// startup ordering.
    pub async fn server(
        id: PathId,
        name: impl Into<String>,
        local: SocketAddr,
        tls: QuicTls,
        interface: Option<&str>,
    ) -> PathResult<Self> {
        install_default_crypto_provider();
        let server_cfg = build_server_config(&tls)?;
        let endpoint_cfg = EndpointConfig::default();
        // Optional NIC pin on the listen socket too (symmetry with the
        // client); `interface = None` ⇒ a plain bind to `local`.
        let (std_socket, _pin) = crate::path::udp::build_pinned_std_socket(local, interface)?;
        let endpoint = Endpoint::new(
            endpoint_cfg,
            Some(server_cfg),
            std_socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|e| PathError::Other(format!("quic endpoint: {e}")))?;

        Ok(Self::spawn_rx_pump(
            id,
            name.into(),
            endpoint,
            None, // server: peer is learned on accept
            Reconnect::ServerAccept,
        ))
    }

    /// Spawn the background pump that owns this path's connection lifecycle:
    /// (re)establish per [`Reconnect`], then pump inbound datagrams into the
    /// mpsc. Establishing in this task (never in `client()` / `server()`) is
    /// what keeps `BondSocket::{sender,receiver}` from blocking on a slow or
    /// down leg; the re-establish-on-drop loop is what lets a dropped leg
    /// rejoin the live bond with no flow restart — both roles self-heal
    /// (server re-accepts, client re-dials with backoff).
    fn spawn_rx_pump(
        id: PathId,
        name: String,
        endpoint: Endpoint,
        primary_peer: Option<SocketAddr>,
        reconnect: Reconnect,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<PathDatagram>(1024);
        let cancel = CancellationToken::new();
        let shared_conn: Arc<ArcSwapOption<Connection>> = Arc::new(ArcSwapOption::from(None));
        let shared_peer = Arc::new(Mutex::new(primary_peer));
        let shared_reason: Arc<ArcSwapOption<String>> = Arc::new(ArcSwapOption::from(None));
        let cancel_child = cancel.clone();
        let task_conn = shared_conn.clone();
        let task_peer = shared_peer.clone();
        let task_reason = shared_reason.clone();
        let task_ep = endpoint.clone();
        let task_name = name.clone();
        let task = tokio::spawn(async move {
            let mut current: Option<Connection> = None;
            // 0 = (re)establish immediately (first attempt / right after a
            // clean handoff); grows on repeated failure (client dial backoff).
            let mut backoff = Duration::ZERO;
            loop {
                let active = match current.clone() {
                    Some(c) => c,
                    None => {
                        if !backoff.is_zero() {
                            tokio::select! {
                                _ = cancel_child.cancelled() => break,
                                _ = tokio::time::sleep(backoff) => {}
                            }
                        }
                        let established = match &reconnect {
                            Reconnect::ServerAccept => {
                                tokio::select! {
                                    _ = cancel_child.cancelled() => break,
                                    res = accept_next(&task_ep) => res,
                                }
                            }
                            Reconnect::ClientDial { remote, server_name } => {
                                tokio::select! {
                                    _ = cancel_child.cancelled() => break,
                                    res = dial(&task_ep, *remote, server_name) => res,
                                }
                            }
                        };
                        match established {
                            Ok(new_conn) => {
                                let peer = new_conn.remote_address();
                                *task_peer.lock().await = Some(peer);
                                task_conn.store(Some(Arc::new(new_conn.clone())));
                                task_reason.store(None); // connected — clear the down reason
                                log::info!("quic path '{task_name}' connected ({peer})");
                                current = Some(new_conn);
                                backoff = Duration::ZERO;
                                continue;
                            }
                            Err(e) => {
                                task_reason.store(Some(Arc::new(e.clone())));
                                backoff = next_backoff(backoff);
                                log::warn!(
                                    "quic path '{task_name}' (re)connect failed: {e}; retry in {backoff:?}"
                                );
                                continue;
                            }
                        }
                    }
                };
                let peer_for_from = active.remote_address();
                tokio::select! {
                    _ = cancel_child.cancelled() => break,
                    r = active.read_datagram() => match r {
                        Ok(data) => {
                            let dg = PathDatagram { data, from: peer_for_from };
                            if tx.try_send(dg).is_err() {
                                log::debug!("quic path rx drop (mpsc full)");
                            }
                        }
                        Err(e) => {
                            // Connection ended — drop it and re-establish
                            // (both roles). A small initial delay avoids a hot
                            // loop when the remote is hard-down; the bond
                            // keepalive marks the leg dead within ~1s meanwhile.
                            task_conn.store(None);
                            task_reason.store(Some(Arc::new(format!("connection ended: {e}"))));
                            current = None;
                            backoff = Duration::from_millis(250);
                            log::info!(
                                "quic path '{task_name}' connection ended ({e}); re-establishing"
                            );
                        }
                    }
                }
            }
        });

        Self {
            id,
            name,
            endpoint,
            conn: shared_conn,
            primary_peer: shared_peer,
            link_reason: shared_reason,
            rx: Mutex::new(Some(rx)),
            cancel,
            _task: task,
        }
    }

    /// The most recent link-down/failure cause while this path is not
    /// connected (e.g. "handshake timed out"), or `None` when connected.
    /// Read by the sender to emit a `PathReconnecting` event so operators
    /// see *why* a leg won't come up.
    pub fn reconnect_reason(&self) -> Option<String> {
        self.link_reason.load().as_ref().map(|s| s.to_string())
    }

    pub fn id(&self) -> PathId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn primary_peer(&self) -> Option<SocketAddr> {
        self.primary_peer.try_lock().ok().and_then(|g| *g)
    }

    pub fn set_primary_peer(&self, peer: SocketAddr) {
        if let Ok(mut g) = self.primary_peer.try_lock() {
            *g = Some(peer);
        }
    }

    /// Send a QUIC datagram. Fails if the connection's datagram MTU
    /// is below the payload — bond chunking should account for QUIC
    /// overhead (~35 bytes vs raw UDP).
    pub async fn send(&self, data: &[u8]) -> PathResult<()> {
        // Lock-free snapshot of the current connection — no await on a
        // mutex on the per-datagram hot path. A re-accept swaps the next
        // send onto the fresh connection.
        let guard = self.conn.load();
        let Some(conn) = guard.as_ref() else {
            return Err(PathError::Other("quic connection closed".into()));
        };
        conn.send_datagram(Bytes::copy_from_slice(data))
            .map_err(|e| PathError::Other(format!("quic send datagram: {e}")))
    }

    pub async fn send_to(&self, data: &[u8], _to: SocketAddr) -> PathResult<()> {
        // Ignored — QUIC datagrams go to whichever endpoint this
        // connection terminates at.
        self.send(data).await
    }

    pub fn take_rx(&mut self) -> Option<mpsc::Receiver<PathDatagram>> {
        self.rx.get_mut().take()
    }

    /// Expose the bound local address — useful for tests that need to
    /// discover the ephemeral server port.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
}

impl Drop for QuicPath {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(conn) = self.conn.swap(None) {
            conn.close(0u32.into(), b"bond path closed");
        }
        self.endpoint.close(0u32.into(), b"bond path closed");
    }
}

// ── Connection lifecycle ────────────────────────────────────────────────────

/// How a path (re)establishes its QUIC connection from the background pump.
/// Both roles self-heal: a server re-accepts, a client re-dials with backoff.
enum Reconnect {
    /// Server leg: accept inbound connections on the endpoint (and re-accept
    /// after a drop, so one closed connection doesn't poison the leg).
    ServerAccept,
    /// Client leg: dial `remote` presenting `server_name`, and re-dial with
    /// backoff after a failure or drop — so a leg that's down at flow start,
    /// or drops mid-stream (Starlink satellite handover), comes up / rejoins
    /// the LIVE bond on its own, with no flow restart and no ~25s build stall.
    ClientDial {
        remote: SocketAddr,
        server_name: String,
    },
}

/// Client re-dial backoff: 250 ms → 8 s, doubling. A handful of legs don't
/// warrant full jitter; the doubling alone keeps a hard-down remote from
/// being hammered.
fn next_backoff(cur: Duration) -> Duration {
    if cur.is_zero() {
        Duration::from_millis(250)
    } else {
        std::cmp::min(cur.saturating_mul(2), Duration::from_secs(8))
    }
}

/// Dial a client connection with a bounded handshake timeout — well under the
/// 25 s `max_idle_timeout` — so a dead remote fails fast and the bond's
/// keepalive dead-detect can flip the scheduler off the leg promptly, rather
/// than the leg sitting in a long handshake.
async fn dial(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
) -> std::result::Result<Connection, String> {
    let connecting = endpoint
        .connect(remote, server_name)
        .map_err(|e| format!("connect: {e}"))?;
    match tokio::time::timeout(Duration::from_secs(6), connecting).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(format!("handshake: {e}")),
        Err(_) => Err("handshake timed out (6s)".to_string()),
    }
}

// ── TLS configuration helpers ───────────────────────────────────────────────

/// Accept the next inbound connection on a server endpoint and finish its
/// handshake. Used by the server rx pump to re-attach a dropped leg
/// instead of dying after the first connection ends.
async fn accept_next(endpoint: &Endpoint) -> std::result::Result<Connection, String> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| "endpoint closed".to_string())?;
    incoming.await.map_err(|e| format!("accept handshake: {e}"))
}

fn install_default_crypto_provider() {
    // rustls 0.23 requires an explicit default crypto provider. Install
    // `ring` once — idempotent across callers.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn build_client_config(tls: &QuicTls) -> PathResult<ClientConfig> {
    let cfg = match tls {
        QuicTls::SelfSigned => {
            // Dev mode: accept any server cert and negotiate bond ALPN.
            // This mirrors `bilbycast-relay`'s loopback-test path.
            use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
            use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
            use rustls::{DigitallySignedStruct, SignatureScheme};

            #[derive(Debug)]
            struct SkipVerify;
            impl rustls::client::danger::ServerCertVerifier for SkipVerify {
                fn verify_server_cert(
                    &self,
                    _end_entity: &CertificateDer<'_>,
                    _intermediates: &[CertificateDer<'_>],
                    _server_name: &ServerName<'_>,
                    _ocsp_response: &[u8],
                    _now: UnixTime,
                ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                    Ok(ServerCertVerified::assertion())
                }
                fn verify_tls12_signature(
                    &self,
                    _message: &[u8],
                    _cert: &CertificateDer<'_>,
                    _dss: &DigitallySignedStruct,
                ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                    Ok(HandshakeSignatureValid::assertion())
                }
                fn verify_tls13_signature(
                    &self,
                    _message: &[u8],
                    _cert: &CertificateDer<'_>,
                    _dss: &DigitallySignedStruct,
                ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                    Ok(HandshakeSignatureValid::assertion())
                }
                fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                    vec![
                        SignatureScheme::RSA_PKCS1_SHA256,
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                        SignatureScheme::ED25519,
                        SignatureScheme::RSA_PSS_SHA256,
                    ]
                }
            }

            let mut tls_cfg = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipVerify))
                .with_no_client_auth();
            tls_cfg.alpn_protocols = vec![BOND_ALPN.to_vec()];
            let quic = QuicClientConfig::try_from(tls_cfg)
                .map_err(|e| PathError::Other(format!("quic client cfg: {e}")))?;
            let mut cfg = ClientConfig::new(Arc::new(quic));
            cfg.transport_config(Arc::new(build_transport_config()));
            cfg
        }
        QuicTls::Pem {
            client_trust_root, ..
        } => {
            use rustls::pki_types::CertificateDer;
            let mut roots = rustls::RootCertStore::empty();
            if let Some(pem) = client_trust_root {
                let mut cursor = std::io::Cursor::new(pem);
                let certs: Vec<CertificateDer<'static>> =
                    rustls_pemfile::certs(&mut cursor)
                        .collect::<std::result::Result<_, _>>()
                        .map_err(|e| PathError::Other(format!("parse trust root: {e}")))?;
                for c in certs {
                    roots.add(c).map_err(|e| {
                        PathError::Other(format!("add trust root: {e}"))
                    })?;
                }
            }
            let mut tls_cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            tls_cfg.alpn_protocols = vec![BOND_ALPN.to_vec()];
            let quic = QuicClientConfig::try_from(tls_cfg)
                .map_err(|e| PathError::Other(format!("quic client cfg: {e}")))?;
            let mut cfg = ClientConfig::new(Arc::new(quic));
            cfg.transport_config(Arc::new(build_transport_config()));
            cfg
        }
    };
    Ok(cfg)
}

fn build_server_config(tls: &QuicTls) -> PathResult<ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let (cert_chain, private_key) = match tls {
        QuicTls::SelfSigned => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .map_err(|e| PathError::Other(format!("self-sign cert: {e}")))?;
            let cert_der = CertificateDer::from(cert.cert.der().to_vec());
            let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
                .map_err(|e| PathError::Other(format!("self-sign key: {e}")))?;
            (vec![cert_der], key_der)
        }
        QuicTls::Pem {
            cert_chain,
            private_key,
            ..
        } => {
            let mut c = std::io::Cursor::new(cert_chain);
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut c)
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| PathError::Other(format!("parse cert chain: {e}")))?;
            let mut k = std::io::Cursor::new(private_key);
            let key = rustls_pemfile::private_key(&mut k)
                .map_err(|e| PathError::Other(format!("parse key: {e}")))?
                .ok_or_else(|| PathError::Other("no private key found".into()))?;
            (certs, key)
        }
    };
    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| PathError::Other(format!("tls server cfg: {e}")))?;
    tls_cfg.alpn_protocols = vec![BOND_ALPN.to_vec()];
    let quic = QuicServerConfig::try_from(tls_cfg)
        .map_err(|e| PathError::Other(format!("quic server cfg: {e}")))?;
    let mut cfg = ServerConfig::with_crypto(Arc::new(quic));
    cfg.transport_config(Arc::new(build_transport_config()));
    Ok(cfg)
}

/// Transport tuning. Matches bilbycast-relay's mobile-friendly
/// defaults so bonding over Starlink / 5G stays alive under brief
/// outages.
fn build_transport_config() -> TransportConfig {
    let mut tc = TransportConfig::default();
    tc.keep_alive_interval(Some(Duration::from_secs(5)));
    tc.max_idle_timeout(Some(Duration::from_secs(25).try_into().unwrap()));
    // Large datagram queue so bond bursts don't immediately trip
    // backpressure.
    tc.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    tc.datagram_send_buffer_size(8 * 1024 * 1024);
    tc
}
