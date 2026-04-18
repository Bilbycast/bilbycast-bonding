//! Lock-free connection + per-path counters.
//!
//! Same pattern as `rist_transport::RistConnStats`: `Arc<AtomicU64>`
//! everywhere on the hot path, snapshot conversion for exporters.
//!
//! Two structs:
//! - [`BondConnStats`] — aggregate-across-paths counters (total
//!   packets, total bytes, reassembled-in-order, recovered, lost).
//! - [`PathStats`] — one per path, covering bytes/packets on the
//!   wire, RTT, loss, keepalive state.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Aggregate-across-paths counters.
#[derive(Debug, Default)]
pub struct BondConnStats {
    // Sender side
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub packets_retransmitted: AtomicU64,
    pub packets_duplicated: AtomicU64,
    pub packets_dropped_no_path: AtomicU64,

    // Receiver side
    pub packets_received: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_delivered: AtomicU64,
    pub gaps_recovered: AtomicU64,
    pub gaps_lost: AtomicU64,
    pub duplicates_received: AtomicU64,
    pub reassembly_overflow: AtomicU64,
}

impl BondConnStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn snapshot(&self) -> BondConnStatsSnapshot {
        BondConnStatsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            packets_retransmitted: self.packets_retransmitted.load(Ordering::Relaxed),
            packets_duplicated: self.packets_duplicated.load(Ordering::Relaxed),
            packets_dropped_no_path: self.packets_dropped_no_path.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_delivered: self.packets_delivered.load(Ordering::Relaxed),
            gaps_recovered: self.gaps_recovered.load(Ordering::Relaxed),
            gaps_lost: self.gaps_lost.load(Ordering::Relaxed),
            duplicates_received: self.duplicates_received.load(Ordering::Relaxed),
            reassembly_overflow: self.reassembly_overflow.load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot for external consumers (edge API, Prometheus).
#[derive(Debug, Clone, Default)]
pub struct BondConnStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_retransmitted: u64,
    pub packets_duplicated: u64,
    pub packets_dropped_no_path: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub packets_delivered: u64,
    pub gaps_recovered: u64,
    pub gaps_lost: u64,
    pub duplicates_received: u64,
    pub reassembly_overflow: u64,
}

/// Per-path counters. One instance per registered path.
#[derive(Debug, Default)]
pub struct PathStats {
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_received: AtomicU64,
    pub nacks_sent: AtomicU64,
    pub nacks_received: AtomicU64,
    pub retransmits_sent: AtomicU64,
    pub retransmits_received: AtomicU64,
    pub keepalives_sent: AtomicU64,
    pub keepalives_received: AtomicU64,
    /// Smoothed RTT in microseconds (0 when no sample).
    pub rtt_us: AtomicU64,
    /// Jitter (RFC 3550 A.8 style) in microseconds.
    pub jitter_us: AtomicU64,
    /// Last-observed loss rate scaled by 1 000 000 (ppm).
    pub loss_ppm: AtomicU64,
    /// Latest throughput sample, bits per second.
    pub throughput_bps: AtomicU64,
    /// Current send-queue depth, packets.
    pub queue_depth: AtomicU64,
    /// 1 when the path is currently declared dead, 0 when alive.
    pub dead: AtomicU64,
}

impl PathStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn snapshot(&self) -> PathStatsSnapshot {
        PathStatsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            nacks_sent: self.nacks_sent.load(Ordering::Relaxed),
            nacks_received: self.nacks_received.load(Ordering::Relaxed),
            retransmits_sent: self.retransmits_sent.load(Ordering::Relaxed),
            retransmits_received: self.retransmits_received.load(Ordering::Relaxed),
            keepalives_sent: self.keepalives_sent.load(Ordering::Relaxed),
            keepalives_received: self.keepalives_received.load(Ordering::Relaxed),
            rtt_us: self.rtt_us.load(Ordering::Relaxed),
            jitter_us: self.jitter_us.load(Ordering::Relaxed),
            loss_ppm: self.loss_ppm.load(Ordering::Relaxed),
            throughput_bps: self.throughput_bps.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            dead: self.dead.load(Ordering::Relaxed) != 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PathStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub nacks_sent: u64,
    pub nacks_received: u64,
    pub retransmits_sent: u64,
    pub retransmits_received: u64,
    pub keepalives_sent: u64,
    pub keepalives_received: u64,
    pub rtt_us: u64,
    pub jitter_us: u64,
    pub loss_ppm: u64,
    pub throughput_bps: u64,
    pub queue_depth: u64,
    pub dead: bool,
}

impl PathStatsSnapshot {
    pub fn rtt_ms(&self) -> f64 {
        self.rtt_us as f64 / 1000.0
    }
    pub fn loss_fraction(&self) -> f64 {
        self.loss_ppm as f64 / 1_000_000.0
    }
}
