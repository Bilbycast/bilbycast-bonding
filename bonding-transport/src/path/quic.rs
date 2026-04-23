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
    conn: Mutex<Option<Connection>>,
    primary_peer: Mutex<Option<SocketAddr>>,
    rx: Mutex<Option<mpsc::Receiver<PathDatagram>>>,
    cancel: CancellationToken,
    _task: tokio::task::JoinHandle<()>,
}

impl QuicPath {
    /// Client: dial `remote`, present the supplied TLS material,
    /// negotiate ALPN `bilbycast-bond`, and start pumping datagrams.
    pub async fn client(
        id: PathId,
        name: impl Into<String>,
        remote: SocketAddr,
        server_name: &str,
        tls: QuicTls,
    ) -> PathResult<Self> {
        install_default_crypto_provider();
        let bind: SocketAddr = if remote.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let mut endpoint = Endpoint::client(bind)
            .map_err(|e| PathError::Other(format!("quic client bind: {e}")))?;
        let client_cfg = build_client_config(&tls)?;
        endpoint.set_default_client_config(client_cfg);
        let connecting = endpoint
            .connect(remote, server_name)
            .map_err(|e| PathError::Other(format!("quic connect: {e}")))?;
        let conn = connecting
            .await
            .map_err(|e| PathError::Other(format!("quic handshake: {e}")))?;

        Ok(Self::spawn_rx_pump(
            id,
            name.into(),
            endpoint,
            conn,
            Some(remote),
        ))
    }

    /// Server: bind to `local`, accept one connection, then pump
    /// its datagrams into the bond loop. Only one connection is
    /// accepted per path — additional connections go to fresh paths.
    pub async fn server(
        id: PathId,
        name: impl Into<String>,
        local: SocketAddr,
        tls: QuicTls,
    ) -> PathResult<Self> {
        install_default_crypto_provider();
        let server_cfg = build_server_config(&tls)?;
        let endpoint_cfg = EndpointConfig::default();
        let std_socket = std::net::UdpSocket::bind(local)
            .map_err(|e| PathError::Other(format!("quic server bind: {e}")))?;
        let endpoint = Endpoint::new(
            endpoint_cfg,
            Some(server_cfg),
            std_socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|e| PathError::Other(format!("quic endpoint: {e}")))?;

        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| PathError::Other("quic endpoint closed before accept".into()))?;
        let conn = incoming
            .await
            .map_err(|e| PathError::Other(format!("quic accept handshake: {e}")))?;
        let peer = conn.remote_address();

        Ok(Self::spawn_rx_pump(
            id,
            name.into(),
            endpoint,
            conn,
            Some(peer),
        ))
    }

    fn spawn_rx_pump(
        id: PathId,
        name: String,
        endpoint: Endpoint,
        conn: Connection,
        primary_peer: Option<SocketAddr>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<PathDatagram>(1024);
        let cancel = CancellationToken::new();
        let conn_clone = conn.clone();
        let cancel_child = cancel.clone();
        let peer_for_from = primary_peer.unwrap_or_else(|| conn.remote_address());
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_child.cancelled() => break,
                    r = conn_clone.read_datagram() => match r {
                        Ok(data) => {
                            let dg = PathDatagram {
                                data,
                                from: peer_for_from,
                            };
                            if tx.try_send(dg).is_err() {
                                log::debug!("quic path rx drop (mpsc full)");
                            }
                        }
                        Err(e) => {
                            log::info!("quic path rx stream ended: {e}");
                            break;
                        }
                    }
                }
            }
        });

        Self {
            id,
            name,
            endpoint,
            conn: Mutex::new(Some(conn)),
            primary_peer: Mutex::new(primary_peer),
            rx: Mutex::new(Some(rx)),
            cancel,
            _task: task,
        }
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
        let guard = self.conn.lock().await;
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
        if let Ok(mut g) = self.conn.try_lock() {
            if let Some(conn) = g.take() {
                conn.close(0u32.into(), b"bond path closed");
            }
        }
        self.endpoint.close(0u32.into(), b"bond path closed");
    }
}

// ── TLS configuration helpers ───────────────────────────────────────────────

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
