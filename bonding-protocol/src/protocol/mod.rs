//! Bond protocol state machines.
//!
//! Pure logic — no async, no I/O. The transport layer drives these
//! types: receiver feeds arrivals into [`reassembly::ReassemblyBuffer`]
//! and drains ready packets; sender consults
//! [`scheduler::BondScheduler`] to pick which path each outbound packet
//! rides.

pub mod path_health;
pub mod reassembly;
pub mod retransmit;
pub mod scheduler;
