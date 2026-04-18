//! Pure-Rust packet-bonding protocol for broadcast media transport.
//!
//! `bonding-protocol` is the I/O-free core of the bilbycast bonding stack.
//! It owns:
//!
//! - The wire header that frames every bonded payload ([`packet::BondHeader`]).
//! - The receiver-side reassembly / jitter buffer
//!   ([`protocol::reassembly::ReassemblyBuffer`]) that sorts packets by
//!   bond sequence across N paths and ages gaps out.
//! - The [`protocol::scheduler::BondScheduler`] trait plus two built-in
//!   implementations (round-robin and weighted-RTT) so a bonding node can
//!   run out of the box without media hints.
//! - Lock-free [`stats`] counters populated by the transport layer.
//!
//! **This crate has zero async / I/O dependencies.** The async networking
//! layer (path managers, QUIC/SRT/RIST transport adapters, reassembly
//! task) lives in `bonding-transport`. Consumers who only want to
//! understand the wire format or run protocol-level unit tests can depend
//! on this crate alone.
//!
//! ## Design principles
//!
//! 1. **Media-awareness is external.** The scheduler sees opaque
//!    [`protocol::scheduler::PacketHints`]; it never parses NAL units or
//!    MPEG-TS. The caller (e.g. `bilbycast-edge`) supplies priority hints
//!    derived from its own media analysis. A dedicated bonding-only box
//!    can leave hints at their default and still get weighted-RTT
//!    aggregation.
//! 2. **Transport-agnostic.** The bond header wraps arbitrary payload
//!    bytes. Paths can ride QUIC, SRT, RIST, or raw UDP independently.
//! 3. **Lock-free hot path.** Stats use `AtomicU64`; the reassembly
//!    buffer is a single-writer flat ring indexed by `bond_seq %
//!    capacity`.
//! 4. **Mirror `bilbycast-rist`.** Same protocol/transport split, same
//!    test conventions, same integration shape — so `bilbycast-edge`
//!    treats it like any other transport crate.

pub mod control;
pub mod error;
pub mod events;
pub mod packet;
pub mod protocol;
pub mod stats;

pub use error::{BondError, Result};
pub use events::{PathDeadReason, PathEvent, PathEventKind};
