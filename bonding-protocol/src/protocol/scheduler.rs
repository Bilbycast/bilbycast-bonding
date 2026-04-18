//! Path-selection trait plus two built-in implementations.
//!
//! The scheduler is the library's extensibility seam. A dedicated
//! bonding-only binary uses [`WeightedRttScheduler`] and never touches
//! the trait. `bilbycast-edge` provides its own `MediaAwareScheduler`
//! (owned by edge, not this crate) that reads NAL / TS context out of
//! [`PacketHints`] and promotes IDR frames to duplication.
//!
//! The trait is intentionally minimal:
//! - `schedule` runs once per outbound packet. Must be O(N) in path
//!   count at worst; paths are expected to be ≤ 16 in realistic
//!   broadcast deployments.
//! - `on_path_update` runs once per path-health tick (≤ 1 Hz).
//! - No async, no locks — the transport layer owns the scheduler
//!   exclusively and calls it from the sender task.

use std::time::Duration;

use crate::packet::Priority;

use super::path_health::PathHealth;

/// Stable identifier for a path. Assigned by the caller when paths are
/// registered; echoed in [`crate::packet::BondHeader::path_id`] for the
/// receiver's per-path stats.
pub type PathId = u8;

/// Hints the caller provides with each outbound packet. All fields are
/// opaque to built-in schedulers except `priority`, which they use to
/// decide duplication.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketHints {
    pub priority: Priority,
    /// Payload length in bytes, before the bond header. Built-in
    /// schedulers use this to avoid pushing oversized packets onto
    /// narrow paths.
    pub size: usize,
    /// Caller-set marker (typically end of media frame).
    pub marker: bool,
    /// Extensible opaque value so media-aware callers can encode
    /// their own signals (NAL type, TS PID, programme number, …)
    /// without extending the trait. Built-ins ignore this.
    pub custom: u32,
}

/// Result of a scheduling decision.
#[derive(Debug, Clone)]
pub enum PathSelection {
    /// Transmit on exactly one path.
    Single(PathId),
    /// Transmit the same packet on multiple paths. Used for
    /// critical-priority packets or when explicit redundancy is
    /// configured. The first entry is treated as the primary — its
    /// path's `packets_sent` counter advances; secondary paths count
    /// duplicates.
    Duplicate(Vec<PathId>),
    /// Drop this packet (e.g. congestion, no healthy paths).
    Drop,
}

impl PathSelection {
    #[inline]
    pub fn primary(&self) -> Option<PathId> {
        match self {
            PathSelection::Single(p) => Some(*p),
            PathSelection::Duplicate(ps) => ps.first().copied(),
            PathSelection::Drop => None,
        }
    }
}

/// Scheduler trait. Implementors own mutable per-scheduler state and
/// are driven by the bonding transport sender task.
pub trait BondScheduler: Send {
    /// Return the full list of registered paths.
    fn path_ids(&self) -> Vec<PathId>;

    /// Called once per outbound packet.
    fn schedule(&mut self, hints: &PacketHints) -> PathSelection;

    /// Called when a path's health snapshot changes (≤ 1 Hz).
    ///
    /// Built-in weighted schedulers use this to rebalance weights
    /// against current RTT and loss. Default impl is a no-op so
    /// static schedulers (round-robin) don't need to override.
    fn on_path_update(&mut self, _path_id: PathId, _health: &PathHealth) {}

    /// Called when a path is declared dead (consecutive keepalive
    /// misses, transport error). Default impl is a no-op; weighted
    /// schedulers override to zero the path's weight.
    fn on_path_dead(&mut self, _path_id: PathId) {}

    /// Called when a previously-dead path is revived.
    fn on_path_alive(&mut self, _path_id: PathId) {}
}

// ── Built-in: RoundRobinScheduler ───────────────────────────────────────────

/// Equal-weight rotation across all registered paths. `Critical`-
/// priority packets are duplicated across the two lowest indices (or
/// all paths if fewer than two are registered), matching
/// [`WeightedRttScheduler`]'s behaviour so callers can swap the two.
#[derive(Debug)]
pub struct RoundRobinScheduler {
    paths: Vec<PathId>,
    dead: Vec<bool>,
    cursor: usize,
}

impl RoundRobinScheduler {
    pub fn new(paths: Vec<PathId>) -> Self {
        let n = paths.len();
        Self {
            paths,
            dead: vec![false; n],
            cursor: 0,
        }
    }

    fn next_alive(&mut self) -> Option<PathId> {
        if self.paths.is_empty() {
            return None;
        }
        for _ in 0..self.paths.len() {
            let idx = self.cursor % self.paths.len();
            self.cursor = self.cursor.wrapping_add(1);
            if !self.dead[idx] {
                return Some(self.paths[idx]);
            }
        }
        None
    }

    fn lowest_two_alive(&self) -> Vec<PathId> {
        self.paths
            .iter()
            .enumerate()
            .filter_map(|(i, p)| if !self.dead[i] { Some(*p) } else { None })
            .take(2)
            .collect()
    }
}

impl BondScheduler for RoundRobinScheduler {
    fn path_ids(&self) -> Vec<PathId> {
        self.paths.clone()
    }

    fn schedule(&mut self, hints: &PacketHints) -> PathSelection {
        if hints.priority == Priority::Critical {
            let dup = self.lowest_two_alive();
            if dup.is_empty() {
                return PathSelection::Drop;
            }
            if dup.len() == 1 {
                return PathSelection::Single(dup[0]);
            }
            return PathSelection::Duplicate(dup);
        }
        match self.next_alive() {
            Some(p) => PathSelection::Single(p),
            None => PathSelection::Drop,
        }
    }

    fn on_path_dead(&mut self, path_id: PathId) {
        if let Some(i) = self.paths.iter().position(|p| *p == path_id) {
            self.dead[i] = true;
        }
    }

    fn on_path_alive(&mut self, path_id: PathId) {
        if let Some(i) = self.paths.iter().position(|p| *p == path_id) {
            self.dead[i] = false;
        }
    }
}

// ── Built-in: WeightedRttScheduler ──────────────────────────────────────────

/// RTT-aware weighted scheduler. Per-path weight defaults to 1 and is
/// rebalanced every `on_path_update` call against `1 / rtt` (capped).
/// `Critical`-priority packets always duplicate across the two
/// lowest-RTT alive paths. Drops when every path is dead.
///
/// Internal scheduling runs a token-based draw: each path accumulates
/// tokens proportional to its weight; the path with the most tokens
/// wins and pays `sum(weights)` tokens. Smooth, allocation-free, and
/// matches WRR semantics without floating-point per-packet.
#[derive(Debug)]
pub struct WeightedRttScheduler {
    paths: Vec<PathId>,
    weights: Vec<u32>,
    dead: Vec<bool>,
    tokens: Vec<i64>,
    /// Minimum weight to assign to any live path so no path is
    /// permanently starved even if its RTT is terrible.
    min_weight: u32,
    /// Maximum weight (tuned for a 4-path bond — 1 000 lets a path
    /// with 5 ms RTT dominate a 500 ms path ~100:1).
    max_weight: u32,
}

impl WeightedRttScheduler {
    pub fn new(paths: Vec<PathId>) -> Self {
        let n = paths.len();
        Self {
            paths,
            weights: vec![1; n],
            dead: vec![false; n],
            tokens: vec![0i64; n],
            min_weight: 1,
            max_weight: 1_000,
        }
    }

    fn sum_weights(&self) -> i64 {
        self.weights
            .iter()
            .zip(self.dead.iter())
            .map(|(w, d)| if *d { 0 } else { *w as i64 })
            .sum()
    }

    fn best_alive(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_tokens: i64 = i64::MIN;
        for (i, d) in self.dead.iter().enumerate() {
            if *d {
                continue;
            }
            if self.tokens[i] > best_tokens {
                best_tokens = self.tokens[i];
                best = Some(i);
            }
        }
        best
    }

    fn lowest_rtt_alive(&self, n: usize) -> Vec<PathId> {
        // Higher weight == lower RTT (roughly), so sort by weight desc.
        let mut indexed: Vec<(usize, u32)> = self
            .weights
            .iter()
            .enumerate()
            .filter_map(|(i, w)| if !self.dead[i] { Some((i, *w)) } else { None })
            .collect();
        indexed.sort_by(|a, b| b.1.cmp(&a.1));
        indexed
            .into_iter()
            .take(n)
            .map(|(i, _)| self.paths[i])
            .collect()
    }
}

impl BondScheduler for WeightedRttScheduler {
    fn path_ids(&self) -> Vec<PathId> {
        self.paths.clone()
    }

    fn schedule(&mut self, hints: &PacketHints) -> PathSelection {
        if self.paths.is_empty() {
            return PathSelection::Drop;
        }

        if hints.priority == Priority::Critical {
            let dup = self.lowest_rtt_alive(2);
            if dup.is_empty() {
                return PathSelection::Drop;
            }
            if dup.len() == 1 {
                return PathSelection::Single(dup[0]);
            }
            return PathSelection::Duplicate(dup);
        }

        let sum = self.sum_weights();
        if sum <= 0 {
            return PathSelection::Drop;
        }

        // Advance token pool: every path gains `weight` tokens per call.
        for (i, d) in self.dead.iter().enumerate() {
            if !*d {
                self.tokens[i] += self.weights[i] as i64;
            }
        }

        let idx = match self.best_alive() {
            Some(i) => i,
            None => return PathSelection::Drop,
        };
        self.tokens[idx] -= sum;
        PathSelection::Single(self.paths[idx])
    }

    fn on_path_update(&mut self, path_id: PathId, health: &PathHealth) {
        let Some(i) = self.paths.iter().position(|p| *p == path_id) else {
            return;
        };
        // Weight ~ 1/rtt: at 10 ms RTT weight ≈ 1000; at 500 ms weight ≈ 20.
        // Clamp to [min_weight, max_weight] so a brief RTT spike can't
        // permanently starve a path.
        let rtt_ms = health.rtt.unwrap_or(Duration::from_millis(500)).as_millis() as u64;
        let rtt_ms = rtt_ms.max(1);
        let raw = (10_000u64 / rtt_ms) as u32;
        let loss_discount = if health.loss_rate > 0.20 {
            // Heavy loss halves the effective weight.
            2
        } else {
            1
        };
        let w = (raw / loss_discount).clamp(self.min_weight, self.max_weight);
        self.weights[i] = w;
    }

    fn on_path_dead(&mut self, path_id: PathId) {
        if let Some(i) = self.paths.iter().position(|p| *p == path_id) {
            self.dead[i] = true;
            self.tokens[i] = 0;
        }
    }

    fn on_path_alive(&mut self, path_id: PathId) {
        if let Some(i) = self.paths.iter().position(|p| *p == path_id) {
            self.dead[i] = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_rotates_alive_paths() {
        let mut s = RoundRobinScheduler::new(vec![0, 1, 2]);
        let pick = |s: &mut RoundRobinScheduler| match s.schedule(&PacketHints::default()) {
            PathSelection::Single(p) => p,
            other => panic!("expected Single, got {other:?}"),
        };
        assert_eq!(pick(&mut s), 0);
        assert_eq!(pick(&mut s), 1);
        assert_eq!(pick(&mut s), 2);
        assert_eq!(pick(&mut s), 0);

        s.on_path_dead(1);
        assert_eq!(pick(&mut s), 2);
        assert_eq!(pick(&mut s), 0);
        assert_eq!(pick(&mut s), 2);
    }

    #[test]
    fn round_robin_drops_when_all_dead() {
        let mut s = RoundRobinScheduler::new(vec![0, 1]);
        s.on_path_dead(0);
        s.on_path_dead(1);
        match s.schedule(&PacketHints::default()) {
            PathSelection::Drop => {}
            other => panic!("expected Drop, got {other:?}"),
        }
    }

    #[test]
    fn critical_packets_duplicate() {
        let mut s = RoundRobinScheduler::new(vec![0, 1, 2]);
        let hints = PacketHints {
            priority: Priority::Critical,
            ..Default::default()
        };
        match s.schedule(&hints) {
            PathSelection::Duplicate(paths) => assert_eq!(paths, vec![0, 1]),
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    #[test]
    fn weighted_scheduler_prefers_low_rtt() {
        let mut s = WeightedRttScheduler::new(vec![0, 1]);
        s.on_path_update(
            0,
            &PathHealth {
                rtt: Some(Duration::from_millis(10)),
                loss_rate: 0.0,
                ..Default::default()
            },
        );
        s.on_path_update(
            1,
            &PathHealth {
                rtt: Some(Duration::from_millis(200)),
                loss_rate: 0.0,
                ..Default::default()
            },
        );

        let mut counts = [0u32; 2];
        for _ in 0..1000 {
            match s.schedule(&PacketHints::default()) {
                PathSelection::Single(p) => counts[p as usize] += 1,
                other => panic!("unexpected: {other:?}"),
            }
        }
        // Low-RTT path should win the large majority.
        assert!(counts[0] > counts[1] * 3, "counts: {:?}", counts);
    }

    #[test]
    fn weighted_critical_picks_lowest_two_rtt() {
        let mut s = WeightedRttScheduler::new(vec![0, 1, 2, 3]);
        s.on_path_update(
            0,
            &PathHealth {
                rtt: Some(Duration::from_millis(200)),
                ..Default::default()
            },
        );
        s.on_path_update(
            1,
            &PathHealth {
                rtt: Some(Duration::from_millis(50)),
                ..Default::default()
            },
        );
        s.on_path_update(
            2,
            &PathHealth {
                rtt: Some(Duration::from_millis(20)),
                ..Default::default()
            },
        );
        s.on_path_update(
            3,
            &PathHealth {
                rtt: Some(Duration::from_millis(400)),
                ..Default::default()
            },
        );

        let hints = PacketHints {
            priority: Priority::Critical,
            ..Default::default()
        };
        match s.schedule(&hints) {
            PathSelection::Duplicate(ps) => {
                // Lowest-RTT pair: path 2 (20 ms) and path 1 (50 ms).
                assert!(ps.contains(&2));
                assert!(ps.contains(&1));
                assert_eq!(ps.len(), 2);
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    #[test]
    fn weighted_drops_when_all_dead() {
        let mut s = WeightedRttScheduler::new(vec![0, 1]);
        s.on_path_dead(0);
        s.on_path_dead(1);
        match s.schedule(&PacketHints::default()) {
            PathSelection::Drop => {}
            other => panic!("expected Drop, got {other:?}"),
        }
    }
}
