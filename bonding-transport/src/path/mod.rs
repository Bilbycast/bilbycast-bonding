//! Path adapters — uniform surface over concrete transports.
//!
//! A `BondPath` is the small contract the sender and receiver tasks
//! need from every transport (UDP, QUIC, SRT, RIST): send a
//! pre-framed datagram, receive the next one, report liveness, close
//! cleanly. Framing is done above the path — paths are content-blind
//! and simply carry bytes.
//!
//! ## Why a concrete enum instead of a `dyn BondPath`?
//!
//! Trait objects would force every send and recv through a vtable
//! indirection on the hot path. Instead we wrap the concrete paths in
//! a [`Path`] enum and dispatch by match — the compiler inlines,
//! there's no allocation per packet, and adding a new transport is
//! still a one-liner on the enum. Matches the `bilbycast-edge` engine
//! convention of enum-dispatched inputs/outputs.

pub mod udp;

#[cfg(feature = "path-rist")]
pub mod rist;

#[cfg(feature = "path-quic")]
pub mod quic;

use std::net::SocketAddr;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::mpsc;

use bonding_protocol::protocol::scheduler::PathId;

pub use udp::UdpPath;

#[cfg(feature = "path-rist")]
pub use rist::RistPath;

#[cfg(feature = "path-quic")]
pub use quic::QuicPath;

#[derive(Debug, Error)]
pub enum PathError {
    #[error("path send failed: {0}")]
    Send(std::io::Error),
    #[error("path recv failed: {0}")]
    Recv(std::io::Error),
    #[error("path bind failed on {addr}: {source}")]
    Bind {
        addr: String,
        source: std::io::Error,
    },
    #[error("path pin to interface '{interface}' failed: {source}")]
    BindInterface {
        interface: String,
        source: std::io::Error,
    },
    #[error("{0}")]
    Other(String),
}

pub type PathResult<T> = std::result::Result<T, PathError>;

/// An arrived datagram plus the peer address that sent it. Control
/// replies (pongs, NACKs) are routed back to the same address.
#[derive(Debug)]
pub struct PathDatagram {
    pub data: Bytes,
    pub from: SocketAddr,
}

/// Bonded path, dispatched by variant at build time. New transports
/// are added as additional enum arms — single place to update and
/// the compiler inlines every dispatch.
pub enum Path {
    Udp(UdpPath),
    #[cfg(feature = "path-rist")]
    Rist(RistPath),
    #[cfg(feature = "path-quic")]
    Quic(QuicPath),
}

impl Path {
    #[inline]
    pub fn id(&self) -> PathId {
        match self {
            Path::Udp(p) => p.id(),
            #[cfg(feature = "path-rist")]
            Path::Rist(p) => p.id(),
            #[cfg(feature = "path-quic")]
            Path::Quic(p) => p.id(),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Path::Udp(p) => p.name(),
            #[cfg(feature = "path-rist")]
            Path::Rist(p) => p.name(),
            #[cfg(feature = "path-quic")]
            Path::Quic(p) => p.name(),
        }
    }

    /// Send a pre-framed datagram. The `to` argument is honoured by
    /// UDP paths (which learn peers dynamically); RIST and QUIC
    /// paths have a fixed peer configured at path creation and
    /// ignore it.
    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> PathResult<()> {
        match self {
            Path::Udp(p) => p.send_to(data, to).await,
            #[cfg(feature = "path-rist")]
            Path::Rist(p) => p.send_to(data, to).await,
            #[cfg(feature = "path-quic")]
            Path::Quic(p) => p.send_to(data, to).await,
        }
    }

    pub async fn send(&self, data: &[u8]) -> PathResult<()> {
        match self {
            Path::Udp(p) => p.send(data).await,
            #[cfg(feature = "path-rist")]
            Path::Rist(p) => p.send(data).await,
            #[cfg(feature = "path-quic")]
            Path::Quic(p) => p.send(data).await,
        }
    }

    pub fn take_rx(&mut self) -> Option<mpsc::Receiver<PathDatagram>> {
        match self {
            Path::Udp(p) => p.take_rx(),
            #[cfg(feature = "path-rist")]
            Path::Rist(p) => p.take_rx(),
            #[cfg(feature = "path-quic")]
            Path::Quic(p) => p.take_rx(),
        }
    }

    pub fn set_primary_peer(&self, peer: SocketAddr) {
        match self {
            Path::Udp(p) => p.set_primary_peer(peer),
            #[cfg(feature = "path-rist")]
            Path::Rist(p) => p.set_primary_peer(peer),
            #[cfg(feature = "path-quic")]
            Path::Quic(p) => p.set_primary_peer(peer),
        }
    }

    pub fn primary_peer(&self) -> Option<SocketAddr> {
        match self {
            Path::Udp(p) => p.primary_peer(),
            #[cfg(feature = "path-rist")]
            Path::Rist(p) => p.primary_peer(),
            #[cfg(feature = "path-quic")]
            Path::Quic(p) => p.primary_peer(),
        }
    }
}
