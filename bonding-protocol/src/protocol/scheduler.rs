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

use std::time::{Duration, Instant};

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

/// How aggressively to replicate packets across legs for reliability.
/// Replication trades bandwidth for loss-resilience: a packet sent on N
/// legs survives as long as **any one** of them delivers it — the strongest
/// recovery available, at the cost of N× the bandwidth for the replicated
/// traffic. Orthogonal to FEC + ARQ (those recover *after* a loss; this
/// avoids the loss in the first place for the packets that matter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedundancyMode {
    /// No extra replication. The scheduler's own keyframe handling still
    /// applies (Critical/IDR packets duplicate across the 2 best legs).
    /// Default — no added bandwidth.
    Off,
    /// Replicate **every** packet across the N best legs.
    All,
    /// Replicate packets whose priority is **at or above** this threshold
    /// (by [`Priority::rank`]). E.g. `AtOrAbove(High)` replicates High +
    /// Critical and leaves Normal/Low single.
    AtOrAbove(Priority),
}

/// Redundancy policy: a [`RedundancyMode`] plus how many legs to spread the
/// replicas across.
#[derive(Debug, Clone, Copy)]
pub struct RedundancyPolicy {
    pub mode: RedundancyMode,
    /// Number of legs to replicate across (the N best). Clamped at runtime
    /// to `[2, live_path_count]`.
    pub replicas: usize,
}

impl Default for RedundancyPolicy {
    fn default() -> Self {
        Self {
            mode: RedundancyMode::Off,
            replicas: 2,
        }
    }
}

impl RedundancyPolicy {
    /// Whether a packet of this priority should be replicated under this
    /// policy. Independent of the always-on Critical/IDR duplication.
    #[inline]
    pub fn triggers(&self, priority: Priority) -> bool {
        match self.mode {
            RedundancyMode::Off => false,
            RedundancyMode::All => true,
            RedundancyMode::AtOrAbove(t) => priority.rank() >= t.rank(),
        }
    }

    /// Effective replica count, clamped to `[2, live]`.
    #[inline]
    pub fn replicas_clamped(&self, live: usize) -> usize {
        self.replicas.max(2).min(live.max(1))
    }
}

/// Scheduler trait. Implementors own mutable per-scheduler state and
/// are driven by the bonding transport sender task.
pub trait BondScheduler: Send {
    /// Return the full list of registered paths.
    fn path_ids(&self) -> Vec<PathId>;

    /// Called once per outbound packet.
    fn schedule(&mut self, hints: &PacketHints) -> PathSelection;

    /// Configure redundant replication. Default: no-op (a scheduler that
    /// doesn't support it ignores the policy; Critical-dup still applies).
    fn set_redundancy(&mut self, _policy: RedundancyPolicy) {}

    /// Called when a path's health snapshot changes (≤ 1 Hz).
    ///
    /// Built-in weighted schedulers use this to rebalance weights
    /// against current RTT and loss. Default impl is a no-op so
    /// static schedulers (round-robin) don't need to override.
    fn on_path_update(&mut self, _path_id: PathId, _health: &PathHealth) {}

    /// Called periodically by the transport with the current monotonic
    /// instant. Rate-paced schedulers (e.g. the capacity-aware one) use
    /// it to refill per-path token buckets so liveness/telemetry stay
    /// fresh even during a quiet period with no outbound packets.
    /// Default impl is a no-op. Schedulers MUST NOT rely on a fixed
    /// cadence — refill against the supplied instant.
    fn on_tick(&mut self, _now: Instant) {}

    /// Called when a path is declared dead (consecutive keepalive
    /// misses, transport error). Default impl is a no-op; weighted
    /// schedulers override to zero the path's weight.
    fn on_path_dead(&mut self, _path_id: PathId) {}

    /// Called when a previously-dead path is revived.
    fn on_path_alive(&mut self, _path_id: PathId) {}

    /// Debit a specific path's congestion budget by `bytes` of wire payload
    /// WITHOUT selecting it. Used to charge out-of-band traffic that the
    /// scheduler did not route — notably per-leg FEC parity, which rides a
    /// fixed leg directly — against that leg's token bucket, so the
    /// controller accounts for it as offered load instead of over-committing
    /// fresh media on top of invisible parity. Default impl is a no-op for
    /// schedulers without a per-path capacity budget.
    fn charge_path(&mut self, _path_id: PathId, _bytes: usize) {}
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
    redundancy: RedundancyPolicy,
}

impl RoundRobinScheduler {
    pub fn new(paths: Vec<PathId>) -> Self {
        let n = paths.len();
        Self {
            paths,
            dead: vec![false; n],
            cursor: 0,
            redundancy: RedundancyPolicy::default(),
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

    fn lowest_n_alive(&self, n: usize) -> Vec<PathId> {
        self.paths
            .iter()
            .enumerate()
            .filter_map(|(i, p)| if !self.dead[i] { Some(*p) } else { None })
            .take(n.max(1))
            .collect()
    }
}

impl BondScheduler for RoundRobinScheduler {
    fn path_ids(&self) -> Vec<PathId> {
        self.paths.clone()
    }

    fn schedule(&mut self, hints: &PacketHints) -> PathSelection {
        // Explicit redundancy: replicate across the N best alive legs.
        if self.redundancy.triggers(hints.priority) {
            let live = self.dead.iter().filter(|d| !**d).count();
            let dup = self.lowest_n_alive(self.redundancy.replicas_clamped(live));
            return match dup.len() {
                0 => PathSelection::Drop,
                1 => PathSelection::Single(dup[0]),
                _ => PathSelection::Duplicate(dup),
            };
        }
        if hints.priority == Priority::Critical {
            let dup = self.lowest_n_alive(2);
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

    fn set_redundancy(&mut self, policy: RedundancyPolicy) {
        self.redundancy = policy;
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
    redundancy: RedundancyPolicy,
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
            redundancy: RedundancyPolicy::default(),
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

        // Explicit redundancy: replicate across the N lowest-RTT alive legs.
        if self.redundancy.triggers(hints.priority) {
            let live = self.dead.iter().filter(|d| !**d).count();
            let dup = self.lowest_rtt_alive(self.redundancy.replicas_clamped(live));
            return match dup.len() {
                0 => PathSelection::Drop,
                1 => PathSelection::Single(dup[0]),
                _ => PathSelection::Duplicate(dup),
            };
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

    fn set_redundancy(&mut self, policy: RedundancyPolicy) {
        self.redundancy = policy;
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
    fn redundancy_policy_triggers_by_priority() {
        let p = RedundancyPolicy {
            mode: RedundancyMode::AtOrAbove(Priority::High),
            replicas: 3,
        };
        assert!(!p.triggers(Priority::Low));
        assert!(!p.triggers(Priority::Normal));
        assert!(p.triggers(Priority::High));
        assert!(p.triggers(Priority::Critical));
        let all = RedundancyPolicy { mode: RedundancyMode::All, replicas: 2 };
        assert!(all.triggers(Priority::Normal) && all.triggers(Priority::Low));
        let off = RedundancyPolicy::default();
        assert!(!off.triggers(Priority::Critical), "off never triggers extra dup");
        assert_eq!(off.replicas_clamped(3), 2, "clamps up to a 2-leg minimum");
        assert_eq!(all.replicas_clamped(1), 1, "clamps down to live count");
    }

    #[test]
    fn redundancy_all_replicates_normal_packets() {
        // Off → a Normal packet goes single.
        let mut s = RoundRobinScheduler::new(vec![0, 1, 2]);
        let normal = PacketHints { priority: Priority::Normal, ..Default::default() };
        assert!(matches!(s.schedule(&normal), PathSelection::Single(_)));

        // All across 3 → the same Normal packet replicates across 3 legs.
        s.set_redundancy(RedundancyPolicy { mode: RedundancyMode::All, replicas: 3 });
        match s.schedule(&normal) {
            PathSelection::Duplicate(paths) => assert_eq!(paths, vec![0, 1, 2]),
            other => panic!("expected Duplicate across 3, got {other:?}"),
        }
    }

    #[test]
    fn redundancy_threshold_leaves_normal_single_dups_high() {
        let mut s = WeightedRttScheduler::new(vec![0, 1, 2]);
        s.set_redundancy(RedundancyPolicy {
            mode: RedundancyMode::AtOrAbove(Priority::High),
            replicas: 2,
        });
        let normal = PacketHints { priority: Priority::Normal, ..Default::default() };
        let high = PacketHints { priority: Priority::High, ..Default::default() };
        assert!(matches!(s.schedule(&normal), PathSelection::Single(_)), "Normal stays single");
        match s.schedule(&high) {
            PathSelection::Duplicate(p) => assert_eq!(p.len(), 2),
            other => panic!("expected High to duplicate, got {other:?}"),
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
