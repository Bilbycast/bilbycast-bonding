//! Capacity-aware, congestion-controlled bonding scheduler.
//!
//! The two built-in schedulers in [`super::scheduler`] split traffic by
//! RTT alone. That is actively wrong for a heterogeneous contribution
//! bond (e.g. several 4G/5G modems + Starlink): a low-RTT cellular link
//! gets *over*-driven past its capacity into loss, while a high-RTT but
//! high-bandwidth satellite link sits under-used. Neither knows how much
//! a link can actually carry.
//!
//! [`CapacityAwareScheduler`] fixes that. Each path runs a small
//! congestion controller that continuously **discovers the link's usable
//! capacity** from delivered-rate, loss, and RTT-inflation feedback, and
//! a **token bucket** refilled at that capacity. Per packet the scheduler
//! distributes to the path with the most spare capacity and best quality;
//! when a link saturates, the next packet spills to a link with headroom.
//! The split is therefore proportional to *measured capacity*, capped at
//! each link's discovered (or operator-configured) ceiling, with smooth
//! quality deweighting — exactly the "use an acceptable amount on each
//! link and shift the rest" behaviour a production bond needs.
//!
//! ## Control loop
//!
//! - [`BondScheduler::on_path_update`] runs on every health sample (a
//!   keepalive-ack round, ~5 Hz). It steps the per-path capacity
//!   estimate: probe **up** while the link is clean (low loss, no RTT
//!   inflation), back **off** toward the delivered rate the moment loss
//!   or queue-building delay appears.
//! - [`BondScheduler::on_tick`] / [`BondScheduler::schedule`] refill the
//!   token buckets from the current capacity estimate (time-based, so the
//!   caller does not have to tick on a fixed cadence).
//!
//! No async, no locks — same constraints as the rest of `bonding-protocol`.
//! [`std::time::Instant`] is the only time source (already used by the
//! reassembly buffer).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::packet::Priority;

use super::path_health::PathHealth;
use super::scheduler::{BondScheduler, PacketHints, PathId, PathSelection};

/// Approximate per-packet wire overhead (bond header) charged against a
/// path's token bucket in addition to the payload size. Keeps the
/// capacity accounting honest without the scheduler knowing the exact
/// framing.
pub const TOKEN_OVERHEAD_BYTES: usize = 12;

/// Tuning for the per-path congestion controller. Defaults are chosen
/// for a cellular + satellite contribution bond; every field is
/// overridable from edge config.
#[derive(Debug, Clone, Copy)]
pub struct CongestionConfig {
    /// Floor a path's capacity estimate never drops below, bits/sec. A
    /// quiet or recovering link keeps this much allowance so it can
    /// re-prove itself. Default 250 kbps.
    pub min_rate_bps: u64,
    /// Starting capacity estimate for a path with no measurement and a
    /// `weight_hint` of 1, bits/sec. Multiplied by `weight_hint`.
    /// Default 2 Mbps.
    pub start_rate_bps: u64,
    /// Loss fraction below which a path is "clean" and probes up.
    /// Default 0.5 %.
    pub loss_low: f32,
    /// Loss fraction at/above which a path backs off hard. Default 3 %.
    pub loss_high: f32,
    /// RTT inflation over the path's own minimum that is treated as
    /// queue-building congestion (delay-based signal — catches
    /// bufferbloat before loss on cellular/Starlink). Default 40 ms.
    pub delay_inflation: Duration,
    /// Multiplicative capacity increase per clean control step.
    /// Default 1.04 (gentle probe).
    pub increase: f32,
    /// Multiplicative back-off applied to the delivered rate on
    /// congestion. Default 0.85.
    pub decrease: f32,
    /// Token-bucket burst depth, in seconds of capacity. Absorbs the
    /// per-frame arrival burst of a media feed. Default 0.25 s.
    pub burst_secs: f32,
    /// EWMA factor for the smoothed RTT (0..1, higher = snappier).
    /// Default 0.2.
    pub rtt_ewma: f32,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            min_rate_bps: 250_000,
            start_rate_bps: 2_000_000,
            loss_low: 0.005,
            loss_high: 0.03,
            delay_inflation: Duration::from_millis(40),
            increase: 1.04,
            decrease: 0.85,
            burst_secs: 0.25,
            rtt_ewma: 0.2,
        }
    }
}

/// Per-path controller + token-bucket state.
#[derive(Debug)]
struct PathCc {
    id: PathId,
    alive: bool,
    /// Hard operator ceiling, bits/sec (`f64::INFINITY` when unset).
    ceiling_bps: f64,
    /// Relative capacity prior from `weight_hint` (1.0 = default).
    weight: f64,
    /// Discovered usable capacity, bits/sec.
    capacity_bps: f64,
    /// Token bucket, bytes. May go transiently negative (bounded debt)
    /// so a momentary over-subscription overflows the best link rather
    /// than hard-dropping.
    tokens: f64,
    last_refill: Instant,
    // ── measurements (fed by on_path_update) ──
    /// Smoothed RTT, seconds (0 = no sample yet).
    rtt: f64,
    /// Minimum RTT seen, seconds (the delay-based baseline).
    rtt_min: f64,
    /// Latest windowed loss fraction.
    loss: f32,
    /// Latest interarrival jitter, microseconds.
    jitter_us: u64,
    /// Latest measured delivered rate at the receiver, bits/sec
    /// (0 = no measurement yet).
    delivery_bps: f64,
}

impl PathCc {
    fn new(id: PathId, weight: f64, ceiling_bps: f64, start_bps: f64, now: Instant) -> Self {
        let cap = (start_bps * weight).max(1.0).min(ceiling_bps);
        Self {
            id,
            alive: true,
            ceiling_bps,
            weight,
            capacity_bps: cap,
            tokens: 0.0,
            last_refill: now,
            rtt: 0.0,
            rtt_min: 0.0,
            loss: 0.0,
            jitter_us: 0,
            delivery_bps: 0.0,
        }
    }

    /// Token-bucket burst depth in bytes for the current capacity.
    #[inline]
    fn burst_bytes(&self, burst_secs: f32) -> f64 {
        (self.capacity_bps / 8.0) * burst_secs as f64
    }

    /// Refill the bucket for the elapsed time since the last refill,
    /// capped at the burst depth. Dead paths neither refill nor drain.
    fn refill(&mut self, now: Instant, burst_secs: f32) {
        let dt = now.saturating_duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        if !self.alive {
            self.tokens = 0.0;
            return;
        }
        let burst = self.burst_bytes(burst_secs);
        self.tokens = (self.tokens + (self.capacity_bps / 8.0) * dt).min(burst);
    }

    /// Quality factor in (0, 1]: loss and RTT-inflation deweight a path
    /// smoothly so a degrading link bleeds traffic continuously rather
    /// than only at a hard cliff.
    fn quality(&self) -> f64 {
        let loss_q = (1.0 - self.loss.min(1.0) as f64).max(0.05);
        let rtt_q = if self.rtt > 0.0 && self.rtt_min > 0.0 {
            (self.rtt_min / self.rtt).clamp(0.1, 1.0)
        } else {
            1.0
        };
        loss_q * rtt_q
    }

    /// Headroom in (0, 1]: full bucket → 1, empty → 0.5, max debt → ~0.
    /// Drives capacity-proportional spreading — a high-capacity link
    /// refills faster and so keeps a higher headroom between packets.
    fn headroom(&self, burst_secs: f32) -> f64 {
        let burst = self.burst_bytes(burst_secs).max(1.0);
        (((self.tokens / burst) + 1.0) / 2.0).clamp(0.0, 1.0)
    }

    /// Combined selection score.
    #[inline]
    fn score(&self, burst_secs: f32) -> f64 {
        self.headroom(burst_secs) * self.quality()
    }
}

/// Capacity-aware, congestion-controlled scheduler.
#[derive(Debug)]
pub struct CapacityAwareScheduler {
    paths: Vec<PathCc>,
    cfg: CongestionConfig,
    // ── telemetry counters (read by the transport for stats) ──
    oversubscribed_drops: u64,
    /// Shared, per-path live capacity estimate (bits/sec). Cloned out via
    /// [`Self::capacity_handles`] so the edge can publish it as telemetry
    /// after the scheduler is moved into the sender task.
    capacity_pub: Vec<Arc<AtomicU64>>,
}

impl CapacityAwareScheduler {
    /// Build with default congestion tuning and unit weights / no
    /// ceilings. Use [`Self::with_paths`] to supply per-path priors.
    pub fn new(paths: Vec<PathId>) -> Self {
        let priors = paths
            .into_iter()
            .map(|id| PathPrior {
                id,
                weight_hint: 1,
                ceiling_bps: None,
            })
            .collect();
        Self::with_paths(priors, CongestionConfig::default())
    }

    /// Build from per-path priors (weight hint + optional hard ceiling)
    /// and explicit congestion tuning.
    pub fn with_paths(priors: Vec<PathPrior>, cfg: CongestionConfig) -> Self {
        let now = Instant::now();
        let start = cfg.start_rate_bps as f64;
        let paths: Vec<PathCc> = priors
            .into_iter()
            .map(|p| {
                let weight = (p.weight_hint.max(1)) as f64;
                let ceiling = p.ceiling_bps.map(|c| c as f64).unwrap_or(f64::INFINITY);
                PathCc::new(p.id, weight, ceiling, start, now)
            })
            .collect();
        let capacity_pub = paths
            .iter()
            .map(|p| Arc::new(AtomicU64::new(p.capacity_bps as u64)))
            .collect();
        Self {
            paths,
            cfg,
            oversubscribed_drops: 0,
            capacity_pub,
        }
    }

    /// Shared handles to each path's live discovered capacity estimate
    /// (bits/sec), keyed by path id. Grab these before moving the
    /// scheduler into the sender so the edge can surface them on
    /// per-path telemetry.
    pub fn capacity_handles(&self) -> Vec<(PathId, Arc<AtomicU64>)> {
        self.paths
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id, self.capacity_pub[i].clone()))
            .collect()
    }

    /// Mirror path `i`'s current capacity estimate into its shared atomic.
    #[inline]
    fn publish(&self, i: usize) {
        if let Some(a) = self.capacity_pub.get(i) {
            a.store(self.paths[i].capacity_bps as u64, Ordering::Relaxed);
        }
    }

    /// Total packets dropped because every path's bucket was in deep
    /// debt (genuine over-subscription: offered load > aggregate
    /// capacity). Surfaced as telemetry so an operator sees the bond is
    /// out of headroom.
    pub fn oversubscribed_drops(&self) -> u64 {
        self.oversubscribed_drops
    }

    /// Current discovered capacity estimate for a path, bits/sec.
    pub fn capacity_bps(&self, id: PathId) -> Option<u64> {
        self.paths
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.capacity_bps as u64)
    }

    fn idx(&self, id: PathId) -> Option<usize> {
        self.paths.iter().position(|p| p.id == id)
    }

    fn refill_all(&mut self, now: Instant) {
        let burst = self.cfg.burst_secs;
        for p in &mut self.paths {
            p.refill(now, burst);
        }
    }

    /// Best-scoring alive path, optionally requiring it can afford
    /// `need` bytes and optionally excluding one id.
    fn best(&self, need: f64, require_afford: bool, exclude: Option<PathId>) -> Option<usize> {
        let burst = self.cfg.burst_secs;
        let mut best: Option<usize> = None;
        let mut best_score = f64::NEG_INFINITY;
        for (i, p) in self.paths.iter().enumerate() {
            if !p.alive || Some(p.id) == exclude {
                continue;
            }
            if require_afford && p.tokens < need {
                continue;
            }
            let s = p.score(burst);
            if s > best_score {
                best_score = s;
                best = Some(i);
            }
        }
        best
    }

    /// Path with the most tokens (least debt) among alive, for the
    /// over-subscription fallback.
    fn least_debt(&self, exclude: Option<PathId>) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_tokens = f64::NEG_INFINITY;
        for (i, p) in self.paths.iter().enumerate() {
            if !p.alive || Some(p.id) == exclude {
                continue;
            }
            if p.tokens > best_tokens {
                best_tokens = p.tokens;
                best = Some(i);
            }
        }
        best
    }

    #[inline]
    fn need_bytes(&self, hints: &PacketHints) -> f64 {
        (hints.size + TOKEN_OVERHEAD_BYTES) as f64
    }

    /// Selection with an explicit monotonic instant — refills buckets to
    /// `now` first, then decides. The trait [`BondScheduler::schedule`]
    /// calls this with `Instant::now()`; tests drive it with controlled
    /// time so the rate-paced refill is deterministic.
    pub fn schedule_at(&mut self, hints: &PacketHints, now: Instant) -> PathSelection {
        self.refill_all(now);

        let need = self.need_bytes(hints);

        if hints.priority == Priority::Critical {
            // Duplicate across the two best paths for keyframe-grade
            // resilience — but stay budget-aware: only spend the second
            // copy if a second path can actually afford it, so we never
            // worsen congestion to duplicate.
            let primary = self.best(need, true, None).or_else(|| self.least_debt(None));
            let Some(pi) = primary else {
                self.oversubscribed_drops += 1;
                return PathSelection::Drop;
            };
            let pid = self.paths[pi].id;
            // Second copy: best *affordable* other path only.
            let secondary = self.best(need, true, Some(pid));
            self.paths[pi].tokens -= need;
            if let Some(si) = secondary {
                let sid = self.paths[si].id;
                self.paths[si].tokens -= need;
                return PathSelection::Duplicate(vec![pid, sid]);
            }
            return PathSelection::Single(pid);
        }

        self.pick_single(need, hints.priority)
    }

    /// Pick a single path for a non-critical packet, deduct its tokens,
    /// and return the selection. Handles spill (best affordable) and
    /// bounded over-subscription (overflow the least-debt link, or Drop).
    fn pick_single(&mut self, need: f64, priority: Priority) -> PathSelection {
        // 1. Prefer the best path that can afford the packet outright —
        //    this is the spill mechanism: a saturated link has no tokens
        //    so the next best with headroom wins.
        if let Some(i) = self.best(need, true, None) {
            self.paths[i].tokens -= need;
            return PathSelection::Single(self.paths[i].id);
        }
        // 2. Every bucket is dry. `Low` traffic is discard-first.
        if priority == Priority::Low {
            self.oversubscribed_drops += 1;
            return PathSelection::Drop;
        }
        // 3. Overflow the least-loaded link, but only into bounded debt
        //    so a sustained over-subscription can't build unbounded
        //    bufferbloat — past −burst we drop and flag it.
        if let Some(i) = self.least_debt(None) {
            let burst = self.paths[i].burst_bytes(self.cfg.burst_secs);
            if self.paths[i].tokens > -burst {
                self.paths[i].tokens -= need;
                return PathSelection::Single(self.paths[i].id);
            }
        }
        self.oversubscribed_drops += 1;
        PathSelection::Drop
    }
}

/// Per-path prior supplied at construction: the operator's relative
/// `weight_hint` and an optional hard bits/sec ceiling.
#[derive(Debug, Clone, Copy)]
pub struct PathPrior {
    pub id: PathId,
    pub weight_hint: u32,
    pub ceiling_bps: Option<u64>,
}

impl BondScheduler for CapacityAwareScheduler {
    fn path_ids(&self) -> Vec<PathId> {
        self.paths.iter().map(|p| p.id).collect()
    }

    fn schedule(&mut self, hints: &PacketHints) -> PathSelection {
        // Lazily refill against the real clock so the caller doesn't have
        // to tick on a fixed cadence — the dt-based refill is idempotent
        // with on_tick.
        self.schedule_at(hints, Instant::now())
    }

    fn on_path_update(&mut self, path_id: PathId, health: &PathHealth) {
        let cfg = self.cfg;
        let Some(i) = self.idx(path_id) else { return };
        let p = &mut self.paths[i];

        if let Some(rtt) = health.rtt {
            let s = rtt.as_secs_f64();
            if p.rtt == 0.0 {
                p.rtt = s;
                p.rtt_min = s;
            } else {
                p.rtt = p.rtt * (1.0 - cfg.rtt_ewma as f64) + s * cfg.rtt_ewma as f64;
                if s < p.rtt_min || p.rtt_min == 0.0 {
                    p.rtt_min = s;
                }
            }
        }
        p.loss = health.loss_rate;
        p.jitter_us = health.jitter_us;
        if health.throughput_bps > 0 {
            p.delivery_bps = health.throughput_bps as f64;
        }

        // Capacity control step.
        let inflation = (p.rtt - p.rtt_min).max(0.0);
        let delay_thresh = cfg.delay_inflation.as_secs_f64();
        let congested = p.loss > cfg.loss_high || inflation > delay_thresh;
        let clean = p.loss < cfg.loss_low && inflation < delay_thresh * 0.5;

        if congested {
            // Back off toward what's actually getting through.
            let base = if p.delivery_bps > 0.0 {
                p.delivery_bps
            } else {
                p.capacity_bps
            };
            p.capacity_bps = base * cfg.decrease as f64;
        } else if clean {
            // Probe up, but never claim less than the measured delivered
            // rate (we know at least that much fits).
            let probed = p.capacity_bps * cfg.increase as f64;
            p.capacity_bps = probed.max(p.delivery_bps);
        }
        p.capacity_bps = p
            .capacity_bps
            .clamp(cfg.min_rate_bps as f64, p.ceiling_bps);
        self.publish(i);
    }

    fn on_tick(&mut self, now: Instant) {
        self.refill_all(now);
    }

    fn on_path_dead(&mut self, path_id: PathId) {
        if let Some(i) = self.idx(path_id) {
            self.paths[i].alive = false;
            self.paths[i].tokens = 0.0;
        }
    }

    fn on_path_alive(&mut self, path_id: PathId) {
        if let Some(i) = self.idx(path_id) {
            let p = &mut self.paths[i];
            p.alive = true;
            // Re-probe from the floor (scaled by the operator prior) so a
            // revived link earns its share back rather than instantly
            // reclaiming a stale high estimate.
            p.capacity_bps = (self.cfg.min_rate_bps as f64 * p.weight)
                .clamp(self.cfg.min_rate_bps as f64, p.ceiling_bps);
            p.rtt = 0.0;
            p.rtt_min = 0.0;
            p.loss = 0.0;
            p.tokens = 0.0;
            self.publish(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(rtt_ms: u64, loss: f32, delivery_bps: u64) -> PathHealth {
        PathHealth {
            rtt: Some(Duration::from_millis(rtt_ms)),
            jitter_us: 0,
            loss_rate: loss,
            throughput_bps: delivery_bps,
            queue_depth: 0,
        }
    }

    fn hints(size: usize) -> PacketHints {
        PacketHints {
            size,
            ..Default::default()
        }
    }

    /// A clean path's capacity estimate probes upward over successive
    /// health samples.
    #[test]
    fn clean_path_probes_capacity_up() {
        let mut s = CapacityAwareScheduler::new(vec![0]);
        let start = s.capacity_bps(0).unwrap();
        for _ in 0..20 {
            s.on_path_update(0, &health(20, 0.0, 0));
        }
        let after = s.capacity_bps(0).unwrap();
        assert!(after > start, "clean path should probe up: {start} -> {after}");
    }

    /// A lossy path backs its capacity estimate down toward the
    /// delivered rate.
    #[test]
    fn lossy_path_backs_off() {
        let mut s = CapacityAwareScheduler::new(vec![0]);
        // Establish a high estimate first.
        for _ in 0..30 {
            s.on_path_update(0, &health(20, 0.0, 10_000_000));
        }
        let high = s.capacity_bps(0).unwrap();
        // Now it starts losing badly with a low delivered rate.
        for _ in 0..10 {
            s.on_path_update(0, &health(20, 0.20, 3_000_000));
        }
        let low = s.capacity_bps(0).unwrap();
        assert!(low < high, "lossy path should back off: {high} -> {low}");
        assert!(low >= 250_000, "but never below the floor: {low}");
    }

    /// Delay inflation (queue building) backs a path off even with zero
    /// loss — the delay-based congestion signal.
    #[test]
    fn delay_inflation_backs_off_without_loss() {
        let mut s = CapacityAwareScheduler::new(vec![0]);
        for _ in 0..20 {
            s.on_path_update(0, &health(20, 0.0, 8_000_000));
        }
        let high = s.capacity_bps(0).unwrap();
        // RTT jumps from 20ms baseline to 120ms (100ms inflation) — the
        // queue is building, back off though loss is still 0.
        for _ in 0..8 {
            s.on_path_update(0, &health(120, 0.0, 8_000_000));
        }
        let low = s.capacity_bps(0).unwrap();
        assert!(
            low < high,
            "delay inflation should back off without loss: {high} -> {low}"
        );
    }

    /// Two clean paths with very different capacities split traffic in
    /// proportion to capacity, not RTT.
    #[test]
    fn split_is_capacity_proportional() {
        let priors = vec![
            PathPrior { id: 0, weight_hint: 1, ceiling_bps: Some(2_000_000) },
            PathPrior { id: 1, weight_hint: 1, ceiling_bps: Some(20_000_000) },
        ];
        let mut s = CapacityAwareScheduler::with_paths(priors, CongestionConfig::default());
        // Both deliver cleanly at their ceiling; estimates converge to
        // the ceilings.
        for _ in 0..200 {
            s.on_path_update(0, &health(30, 0.0, 2_000_000));
            s.on_path_update(1, &health(30, 0.0, 20_000_000));
        }
        // Drive a stream of 1316-byte packets at a deterministic cadence
        // that offers ~1.5x the aggregate capacity, so both buckets stay
        // drained and the split is governed by refill rate (= capacity).
        let base = Instant::now();
        let interval = Duration::from_micros(300);
        let mut counts = [0u64; 2];
        for i in 0..5000u32 {
            let now = base + interval * i;
            match s.schedule_at(&hints(1316), now) {
                PathSelection::Single(p) => counts[p as usize] += 1,
                PathSelection::Duplicate(v) => counts[v[0] as usize] += 1,
                PathSelection::Drop => {}
            }
        }
        // Path 1 (10x capacity) must carry the large majority. Exact
        // ratio depends on refill timing, but it must clearly dominate.
        assert!(
            counts[1] > counts[0] * 2,
            "high-capacity path should dominate: {counts:?}"
        );
        assert!(counts[0] > 0, "low-capacity path still carries some: {counts:?}");
    }

    /// `Low`-priority traffic is dropped first when every bucket is dry;
    /// higher priorities overflow into bounded debt instead.
    #[test]
    fn low_priority_dropped_first_under_oversubscription() {
        let priors = vec![PathPrior { id: 0, weight_hint: 1, ceiling_bps: Some(250_000) }];
        let mut s = CapacityAwareScheduler::with_paths(priors, CongestionConfig::default());
        // Tiny capacity, large packets, fired back to back — buckets dry
        // out immediately.
        let mut low_drops = 0;
        let mut low_sent = 0;
        for _ in 0..50 {
            let h = PacketHints { size: 1316, priority: Priority::Low, ..Default::default() };
            match s.schedule(&h) {
                PathSelection::Drop => low_drops += 1,
                _ => low_sent += 1,
            }
        }
        assert!(low_drops > low_sent, "Low should be dropped first: sent={low_sent} drops={low_drops}");
    }

    /// Critical packets duplicate across two paths when both can afford
    /// it, and collapse to single when only one has headroom.
    #[test]
    fn critical_duplicates_when_headroom_allows() {
        let priors = vec![
            PathPrior { id: 0, weight_hint: 1, ceiling_bps: Some(20_000_000) },
            PathPrior { id: 1, weight_hint: 1, ceiling_bps: Some(20_000_000) },
        ];
        let mut s = CapacityAwareScheduler::with_paths(priors, CongestionConfig::default());
        for _ in 0..100 {
            s.on_path_update(0, &health(20, 0.0, 20_000_000));
            s.on_path_update(1, &health(20, 0.0, 20_000_000));
        }
        // Let both buckets fill (a second of idle) so both can afford the
        // duplicate.
        let when = Instant::now() + Duration::from_secs(1);
        let h = PacketHints { size: 1316, priority: Priority::Critical, ..Default::default() };
        match s.schedule_at(&h, when) {
            PathSelection::Duplicate(v) => {
                assert_eq!(v.len(), 2);
                assert_ne!(v[0], v[1]);
            }
            other => panic!("expected Duplicate with two healthy paths, got {other:?}"),
        }
    }

    /// A dead path carries no traffic; reviving it lets it earn share
    /// back from the floor.
    #[test]
    fn dead_path_excluded_then_revived() {
        let mut s = CapacityAwareScheduler::new(vec![0, 1]);
        for _ in 0..50 {
            s.on_path_update(0, &health(20, 0.0, 5_000_000));
            s.on_path_update(1, &health(20, 0.0, 5_000_000));
        }
        s.on_path_dead(1);
        for _ in 0..200 {
            match s.schedule(&hints(1316)) {
                PathSelection::Single(p) => assert_eq!(p, 0, "all traffic on the live path"),
                PathSelection::Duplicate(_) => {}
                PathSelection::Drop => {}
            }
        }
        s.on_path_alive(1);
        // Capacity reset to floor on revival.
        assert_eq!(s.capacity_bps(1).unwrap(), 250_000);
    }

    /// All paths dead → Drop.
    #[test]
    fn all_dead_drops() {
        let mut s = CapacityAwareScheduler::new(vec![0, 1]);
        s.on_path_dead(0);
        s.on_path_dead(1);
        assert!(matches!(s.schedule(&hints(1316)), PathSelection::Drop));
    }
}
