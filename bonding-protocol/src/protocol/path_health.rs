//! Per-path health snapshot consumed by the scheduler.
//!
//! Populated by the transport layer (RTT estimator, loss accounting,
//! keepalive tracker) and fed into [`super::scheduler::BondScheduler::on_path_update`].
//! Exists in `bonding-protocol` so the scheduler trait can be
//! implemented by downstream crates without pulling in tokio.

use std::time::Duration;

/// Instantaneous health of a single path.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathHealth {
    /// Smoothed round-trip time, if a sample has been collected.
    pub rtt: Option<Duration>,
    /// Interarrival jitter, microseconds.
    pub jitter_us: u64,
    /// Fraction of packets lost in the latest measurement window
    /// (0.0 = no loss, 1.0 = total loss).
    pub loss_rate: f32,
    /// Most recent measured throughput in bits per second.
    pub throughput_bps: u64,
    /// Send queue depth, packets. Useful for detecting a stalled path
    /// before RTT catches up.
    pub queue_depth: u32,
    /// Receiver-measured relative one-way delay for this leg, microseconds
    /// (how much later this leg's packets land than the fastest eligible
    /// leg) — echoed from the v4 keepalive-ack for per-leg equalization.
    /// `u32::MAX` = un-measured (cold-start, a v1/v2/v3 receiver, or
    /// equalization off); the scheduler then leaves the budget-demote
    /// inactive and falls back to its local jitter heuristic. (`Default`
    /// gives 0 — "fastest leg" — which likewise never trips the demote.)
    pub relative_owd_us: u32,
}
