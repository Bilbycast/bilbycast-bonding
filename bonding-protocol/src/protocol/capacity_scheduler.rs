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
//! ## Estimator + selection hardening
//!
//! - **Windowed min-RTT** (BBR-style): the delay baseline `rtt_min` is the
//!   minimum over the last [`CongestionConfig::rtt_min_window`], not a
//!   lifetime latch — a permanent RTT baseline shift (5G handover,
//!   Starlink reroute) ages out of the window instead of reading as
//!   perpetual congestion that pins the leg at `min_rate_bps`.
//! - **Evidence-bound probing**: a clean leg probes up only while a
//!   delivered rate is measured, and the estimate is capped at
//!   `delivery_bps × probe_cap_mult` — an idle or undersubscribed bond
//!   holds its estimate instead of inflating it without bound. The cap
//!   lifts (and probing switches to slow-start doubling) while the leg
//!   is under *clean demand pressure* — bucket in debt with no loss /
//!   inflation — so a surviving leg absorbs a dead sibling's share
//!   within ~1 s of control rounds instead of staying pinned at a
//!   multiple of its old traffic share.
//! - **Fair tie-break**: path scans start from a cursor rotated once per
//!   scheduled packet, so exact score ties round-robin across alive legs
//!   (keeping failover legs warm) instead of concentrating all traffic on
//!   the lowest index.
//! - **Jitter deweight**: interarrival jitter above 20 ms deweights a
//!   path's quality (down to ×0.5) alongside loss and RTT inflation.
//!   Jitter is only re-measured at the receiver while data flows, so a
//!   starved leg's stale sample decays every control round — a bad
//!   reading deweights the leg but can never pin it out of the bond.
//!
//! No async, no locks — same constraints as the rest of `bonding-protocol`.
//! [`std::time::Instant`] is the only time source (already used by the
//! reassembly buffer).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::packet::Priority;

use super::path_health::PathHealth;
use super::scheduler::{
    BondScheduler, PacketHints, PathId, PathSelection, RedundancyPolicy,
};

/// Approximate per-packet wire overhead (bond header) charged against a
/// path's token bucket in addition to the payload size. Keeps the
/// capacity accounting honest without the scheduler knowing the exact
/// framing.
pub const TOKEN_OVERHEAD_BYTES: usize = 12;

/// Capacity growth multiplier per clean control round while the leg is
/// under demand pressure (token bucket in debt: offered load exceeds
/// the current estimate). Slow-start-style doubling so a surviving leg
/// absorbs a dead sibling's share within a handful of keepalive-ack
/// rounds (~1 s at 5 Hz) instead of riding the gentle `increase` probe
/// from a delivery-bounded estimate (1 → 10 Mbps at 1.04×/round is
/// ~12 s of shedding a leg that was capable the whole time). Bounded
/// by the same congestion feedback as the gentle probe: one round of
/// loss / RTT inflation backs the estimate off toward the delivered
/// rate.
const DEMAND_SLOW_START_MULT: f64 = 2.0;

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
    /// Evidence bound on the probed capacity: once a delivered rate has
    /// been measured, the estimate never exceeds `delivery_bps ×
    /// probe_cap_mult`. Bounds undersubscribed-bond inflation while
    /// still letting the estimate grow exponentially as the realized
    /// rate rises after a failover. Default 2.0.
    pub probe_cap_mult: f64,
    /// Window over which the per-path minimum RTT is tracked
    /// (BBR-style). A baseline shift larger than `delay_inflation`
    /// ages out of the window instead of reading as permanent
    /// congestion. Default 10 s.
    pub rtt_min_window: Duration,
    /// Token-bucket burst depth, in seconds of capacity. Absorbs the
    /// per-frame arrival burst of a media feed. Default 0.25 s.
    pub burst_secs: f32,
    /// EWMA factor for the smoothed RTT (0..1, higher = snappier).
    /// Default 0.2.
    pub rtt_ewma: f32,
    /// Auto-derive the queue-building delay threshold per leg from its
    /// own windowed baseline RTT instead of using the fixed
    /// `delay_inflation`. A high-baseline link (bufferbloated cellular)
    /// gets a proportionally looser threshold — auto-deriving the value
    /// such links otherwise need hand-tuned — while a low-baseline
    /// terrestrial link keeps the tight `delay_inflation` floor. The
    /// derived threshold is `rtt_min × DELAY_AUTO_FRAC`, clamped to
    /// `[delay_inflation, DELAY_AUTO_CEILING]`. Opt-in (default `false`)
    /// so existing fixed-threshold deployments are unchanged. Default
    /// `false`.
    pub delay_inflation_auto: bool,
}

/// Auto delay-threshold = baseline RTT × this fraction. 0.7 places a
/// ~360 ms cellular baseline at ~250 ms (the value such links need
/// hand-tuned today) and a ~22 ms terrestrial baseline below the floor.
const DELAY_AUTO_FRAC: f64 = 0.7;
/// Hard ceiling on the auto-derived threshold (seconds) so a
/// pathological baseline can't blind the controller to real congestion.
const DELAY_AUTO_CEILING_SECS: f64 = 1.0;

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
            probe_cap_mult: 2.0,
            rtt_min_window: Duration::from_secs(10),
            burst_secs: 0.25,
            rtt_ewma: 0.2,
            delay_inflation_auto: false,
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
    /// Windowed minimum RTT, seconds (the delay-based baseline;
    /// 0 = no sample yet).
    rtt_min: f64,
    /// When `rtt_min` was last adopted — drives the
    /// [`CongestionConfig::rtt_min_window`] aging so a permanent
    /// baseline shift cannot read as congestion forever.
    rtt_min_at: Instant,
    /// Latest windowed loss fraction.
    loss: f32,
    /// Latest interarrival jitter, microseconds. Decayed while the leg
    /// is starved (see `on_path_update`) — the receiver can't re-measure
    /// jitter on a leg that carries nothing.
    jitter_us: u64,
    /// Whether this path was selected for at least one packet since its
    /// last health update — distinguishes a starved leg (stale jitter)
    /// from one with a fresh measurement.
    picked_since_update: bool,
    /// Scheduler `sched_serial` at this path's last health update; if it
    /// hasn't advanced, the bond was idle and nothing was starved.
    last_update_serial: u64,
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
            rtt_min_at: now,
            loss: 0.0,
            jitter_us: 0,
            picked_since_update: false,
            last_update_serial: 0,
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

    /// Quality factor in (0, 1]: loss, RTT-inflation, and interarrival
    /// jitter deweight a path smoothly so a degrading link bleeds
    /// traffic continuously rather than only at a hard cliff.
    fn quality(&self, delay_thresh: f64) -> f64 {
        let loss_q = (1.0 - self.loss.min(1.0) as f64).max(0.05);
        // Inflation over the windowed min, scaled by the congestion
        // threshold (1.0 at zero inflation, 0.5 at the threshold) — a
        // raw min/rtt ratio would over-punish low-RTT paths, where
        // sub-millisecond scheduler noise reads as a large ratio.
        let rtt_q = if self.rtt > 0.0 && self.rtt_min > 0.0 && delay_thresh > 0.0 {
            let inflation = (self.rtt - self.rtt_min).max(0.0);
            (delay_thresh / (delay_thresh + inflation)).clamp(0.1, 1.0)
        } else {
            1.0
        };
        // ≤20 ms of jitter is free; beyond that deweight down to ×0.5 so
        // a jittery leg loses ties but is never starved outright.
        let jitter_q = if self.jitter_us <= 20_000 {
            1.0
        } else {
            (20_000.0 / self.jitter_us as f64).clamp(0.5, 1.0)
        };
        loss_q * rtt_q * jitter_q
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
    fn score(&self, burst_secs: f32, delay_thresh: f64) -> f64 {
        self.headroom(burst_secs) * self.quality(delay_thresh)
    }

    /// The queue-building delay threshold for this leg, in seconds.
    /// Fixed `delay_inflation` by default; when `delay_inflation_auto`
    /// is set (and a baseline RTT has been measured) it scales with the
    /// leg's own windowed `rtt_min` so a bufferbloated cellular link
    /// gets a proportionally looser threshold while a terrestrial link
    /// keeps the tight floor. Bounded to `[delay_inflation, ceiling]`.
    #[inline]
    fn effective_delay_thresh(&self, cfg: &CongestionConfig) -> f64 {
        let fixed = cfg.delay_inflation.as_secs_f64();
        if !cfg.delay_inflation_auto || self.rtt_min <= 0.0 {
            return fixed;
        }
        (self.rtt_min * DELAY_AUTO_FRAC).clamp(fixed, DELAY_AUTO_CEILING_SECS)
    }
}

/// Capacity-aware, congestion-controlled scheduler.
#[derive(Debug)]
pub struct CapacityAwareScheduler {
    paths: Vec<PathCc>,
    cfg: CongestionConfig,
    /// Rotating scan origin for `best` / `least_debt`, advanced once per
    /// scheduled packet — exact score ties round-robin across alive legs
    /// instead of always landing on the lowest index (winner-takes-all
    /// would leave failover legs cold).
    rr_cursor: usize,
    /// Monotonic per-packet serial; lets `on_path_update` tell a starved
    /// leg (traffic offered, none scheduled to it) from an idle bond.
    sched_serial: u64,
    // ── telemetry counters (read by the transport for stats) ──
    oversubscribed_drops: u64,
    /// Shared, per-path live capacity estimate (bits/sec). Cloned out via
    /// [`Self::capacity_handles`] so the edge can publish it as telemetry
    /// after the scheduler is moved into the sender task.
    capacity_pub: Vec<Arc<AtomicU64>>,
    /// Operator redundancy policy (replicate across N best legs).
    redundancy: RedundancyPolicy,
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
            rr_cursor: 0,
            sched_serial: 0,
            oversubscribed_drops: 0,
            capacity_pub,
            redundancy: RedundancyPolicy::default(),
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
    /// `need` bytes and optionally excluding one id. Scans from the
    /// rotating cursor with strict `>` so genuinely better scores still
    /// win but exact ties round-robin instead of pinning to index 0.
    fn best(&self, need: f64, require_afford: bool, exclude: Option<PathId>) -> Option<usize> {
        let len = self.paths.len();
        if len == 0 {
            return None;
        }
        let burst = self.cfg.burst_secs;
        let mut best: Option<usize> = None;
        let mut best_score = f64::NEG_INFINITY;
        for k in 0..len {
            let i = (self.rr_cursor + k) % len;
            let p = &self.paths[i];
            if !p.alive || Some(p.id) == exclude {
                continue;
            }
            if require_afford && p.tokens < need {
                continue;
            }
            // Per-leg threshold: with delay_inflation_auto it scales with
            // each leg's own baseline RTT (see effective_delay_thresh).
            let s = p.score(burst, p.effective_delay_thresh(&self.cfg));
            if s > best_score {
                best_score = s;
                best = Some(i);
            }
        }
        best
    }

    /// The `n` best alive legs by score (best-first), for explicit
    /// redundancy. Not afford-gated — replication is a deliberate bandwidth
    /// spend — but the caller still debits each leg's token bucket so the
    /// controller sees the added load.
    fn best_n_alive(&self, n: usize) -> Vec<usize> {
        let burst = self.cfg.burst_secs;
        let mut scored: Vec<(usize, f64)> = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, p)| p.alive)
            .map(|(i, p)| (i, p.score(burst, p.effective_delay_thresh(&self.cfg))))
            .collect();
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.into_iter().take(n.max(1)).map(|(i, _)| i).collect()
    }

    /// Path with the most tokens (least debt) among alive, for the
    /// over-subscription fallback. Same rotating-cursor tie-break as
    /// [`Self::best`].
    fn least_debt(&self, exclude: Option<PathId>) -> Option<usize> {
        let len = self.paths.len();
        if len == 0 {
            return None;
        }
        let mut best: Option<usize> = None;
        let mut best_tokens = f64::NEG_INFINITY;
        for k in 0..len {
            let i = (self.rr_cursor + k) % len;
            let p = &self.paths[i];
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
        // Advance the tie-break cursor once per packet so equal-scoring
        // legs alternate, and the serial so starvation is observable.
        self.rr_cursor = self.rr_cursor.wrapping_add(1);
        self.sched_serial = self.sched_serial.wrapping_add(1);

        let need = self.need_bytes(hints);

        // Explicit redundancy: replicate across the N best alive legs. Takes
        // precedence over the always-on Critical/IDR dup below.
        if self.redundancy.triggers(hints.priority) {
            let live = self.paths.iter().filter(|p| p.alive).count();
            let idxs = self.best_n_alive(self.redundancy.replicas_clamped(live));
            if idxs.is_empty() {
                self.oversubscribed_drops += 1;
                return PathSelection::Drop;
            }
            let mut ids = Vec::with_capacity(idxs.len());
            for &i in &idxs {
                self.paths[i].tokens -= need;
                self.paths[i].picked_since_update = true;
                ids.push(self.paths[i].id);
            }
            return if ids.len() == 1 {
                PathSelection::Single(ids[0])
            } else {
                PathSelection::Duplicate(ids)
            };
        }

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
            self.paths[pi].picked_since_update = true;
            if let Some(si) = secondary {
                let sid = self.paths[si].id;
                self.paths[si].tokens -= need;
                self.paths[si].picked_since_update = true;
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
            self.paths[i].picked_since_update = true;
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
                self.paths[i].picked_since_update = true;
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

    fn set_redundancy(&mut self, policy: RedundancyPolicy) {
        self.redundancy = policy;
    }

    fn on_path_update(&mut self, path_id: PathId, health: &PathHealth) {
        let cfg = self.cfg;
        let serial = self.sched_serial;
        let Some(i) = self.idx(path_id) else { return };
        let p = &mut self.paths[i];

        // Control path (~5 Hz keepalive-ack rounds), not the packet
        // hot path — a direct `Instant::now()` is acceptable here.
        let now = Instant::now();

        if let Some(rtt) = health.rtt {
            let s = rtt.as_secs_f64();
            if p.rtt == 0.0 {
                p.rtt = s;
            } else {
                p.rtt = p.rtt * (1.0 - cfg.rtt_ewma as f64) + s * cfg.rtt_ewma as f64;
            }
            // Windowed minimum (BBR-style): adopt the sample when it ties
            // or beats the current min, or when the min has aged out of
            // `rtt_min_window` — a permanent baseline shift (5G handover,
            // Starlink reroute) must not read as congestion forever.
            if p.rtt_min == 0.0
                || s <= p.rtt_min
                || now.saturating_duration_since(p.rtt_min_at) > cfg.rtt_min_window
            {
                p.rtt_min = s;
                p.rtt_min_at = now;
            }
        }
        p.loss = health.loss_rate;
        // Jitter is only re-measured at the receiver while data flows on
        // the leg, so a starved leg (packets were scheduled this round
        // but none to it) keeps echoing its last sample. Decay the
        // stored value while starved — a stale high reading deweights
        // the leg but must not pin it out of the bond forever; if
        // traffic resumes and the jitter is real, the fresh sample
        // restores the deweight.
        let starved = !p.picked_since_update && serial != p.last_update_serial;
        p.jitter_us = if starved {
            p.jitter_us.min(health.jitter_us) / 2
        } else {
            health.jitter_us
        };
        p.picked_since_update = false;
        p.last_update_serial = serial;
        if health.throughput_bps > 0 {
            p.delivery_bps = health.throughput_bps as f64;
        }

        // Capacity control step.
        let inflation = (p.rtt - p.rtt_min).max(0.0);
        let delay_thresh = p.effective_delay_thresh(&cfg);
        let congested = p.loss > cfg.loss_high || inflation > delay_thresh;
        let clean = p.loss < cfg.loss_low && inflation < delay_thresh * 0.5;
        // Demand pressure: the bucket is in debt at the control step —
        // offered load exceeds the current estimate. Distinguishes "no
        // demand" (undersubscribed leg whose delivered rate is its small
        // traffic share, not its capacity) from "no capacity". Refill
        // first so a bond gone idle since the last schedule() can't read
        // a stale negative bucket as demand and inflate on nothing.
        p.refill(now, cfg.burst_secs);
        let demand_pressure = p.tokens < 0.0;

        if congested {
            // Back off toward what's actually getting through.
            let base = if p.delivery_bps > 0.0 {
                p.delivery_bps
            } else {
                p.capacity_bps
            };
            p.capacity_bps = base * cfg.decrease as f64;
        } else if clean && p.delivery_bps > 0.0 {
            // Probe up, but never claim less than the measured delivered
            // rate (we know at least that much fits). Under clean demand
            // pressure (sibling died, surviving leg's bucket exhausted)
            // grow slow-start style — see `DEMAND_SLOW_START_MULT`. No
            // delivered-rate evidence (idle bond) → hold the estimate:
            // probing on nothing would inflate it to fiction.
            let mult = if demand_pressure {
                DEMAND_SLOW_START_MULT
            } else {
                cfg.increase as f64
            };
            let probed = p.capacity_bps * mult;
            p.capacity_bps = probed.max(p.delivery_bps);
        }
        p.capacity_bps = p
            .capacity_bps
            .clamp(cfg.min_rate_bps as f64, p.ceiling_bps);
        if p.delivery_bps > 0.0 && !(clean && demand_pressure) {
            // Evidence bound: never estimate more than probe_cap_mult ×
            // what the leg has recently proven it can deliver. The bound
            // rises with the realized rate, so post-failover growth is
            // still exponential. Suspended while clean demand pressure
            // holds — on an undersubscribed bond, delivery measures the
            // leg's share, and pinning the estimate at probe_cap_mult ×
            // that share would turn an instant failover into seconds of
            // sender-side shedding. The min_rate floor stays
            // authoritative so a leg can always re-prove itself.
            p.capacity_bps = p
                .capacity_bps
                .min(p.delivery_bps * cfg.probe_cap_mult)
                .max(cfg.min_rate_bps as f64);
        }
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
            p.rtt_min_at = Instant::now();
            p.loss = 0.0;
            p.jitter_us = 0;
            p.picked_since_update = false;
            p.tokens = 0.0;
            self.publish(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(rtt_ms: u64, loss: f32, delivery_bps: u64) -> PathHealth {
        health_j(rtt_ms, loss, delivery_bps, 0)
    }

    fn health_j(rtt_ms: u64, loss: f32, delivery_bps: u64, jitter_us: u64) -> PathHealth {
        PathHealth {
            rtt: Some(Duration::from_millis(rtt_ms)),
            jitter_us,
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

    /// A clean path with a measured delivered rate probes its capacity
    /// Redundancy `All` replicates a Normal packet across the N best legs on
    /// the production (capacity-aware) scheduler.
    #[test]
    fn capacity_redundancy_all_replicates() {
        let mut s = CapacityAwareScheduler::new(vec![0, 1, 2]);
        let normal = PacketHints { priority: Priority::Normal, ..Default::default() };
        assert!(matches!(s.schedule(&normal), PathSelection::Single(_)), "off → single");
        s.set_redundancy(RedundancyPolicy {
            mode: crate::protocol::scheduler::RedundancyMode::All,
            replicas: 3,
        });
        match s.schedule(&normal) {
            PathSelection::Duplicate(ids) => {
                assert_eq!(ids.len(), 3, "replicates across all 3 legs");
                let mut sorted = ids.clone();
                sorted.sort();
                assert_eq!(sorted, vec![0, 1, 2], "distinct legs");
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    /// estimate upward over successive health samples.
    #[test]
    fn clean_path_probes_capacity_up() {
        let mut s = CapacityAwareScheduler::new(vec![0]);
        let start = s.capacity_bps(0).unwrap();
        for _ in 0..20 {
            s.on_path_update(0, &health(20, 0.0, 10_000_000));
        }
        let after = s.capacity_bps(0).unwrap();
        assert!(after > start, "clean path should probe up: {start} -> {after}");
    }

    /// A clean path with no delivered-rate evidence holds its estimate —
    /// an idle bond must not inflate capacity on nothing.
    #[test]
    fn idle_path_holds_estimate() {
        let mut s = CapacityAwareScheduler::new(vec![0]);
        let start = s.capacity_bps(0).unwrap();
        for _ in 0..50 {
            s.on_path_update(0, &health(20, 0.0, 0));
        }
        let after = s.capacity_bps(0).unwrap();
        assert_eq!(after, start, "no delivery evidence → estimate held: {start} -> {after}");
    }

    /// The estimate never exceeds probe_cap_mult × the delivered rate —
    /// an undersubscribed bond can't inflate estimates to fiction.
    #[test]
    fn undersubscribed_capacity_bounded_by_delivery() {
        let mut s = CapacityAwareScheduler::new(vec![0]);
        for _ in 0..500 {
            s.on_path_update(0, &health(20, 0.0, 3_000_000));
        }
        let cap = s.capacity_bps(0).unwrap();
        let bound = (3_000_000.0 * CongestionConfig::default().probe_cap_mult) as u64;
        assert!(cap <= bound, "estimate bounded by evidence: {cap} > {bound}");
        assert!(cap > 3_000_000, "probing above the delivered rate is still allowed: {cap}");
    }

    /// Failover ramp: an undersubscribed backup leg (delivered rate ==
    /// its small traffic share) must not stay pinned at probe_cap_mult
    /// × that share when its sibling dies. Clean demand pressure
    /// (bucket in debt, no loss / inflation) lifts the evidence bound
    /// and grows the estimate slow-start style, so a 95/5 split bond
    /// absorbs the full feed on the survivor within ~1 s of control
    /// rounds (5 × 200 ms) of the death.
    #[test]
    fn failover_ramps_within_a_second_of_control_rounds() {
        let mut s = CapacityAwareScheduler::new(vec![0, 1]);
        // Converge a ~10 Mbps feed split 95/5: backup's estimate is
        // evidence-bounded near 2 × 500 kbps.
        for _ in 0..50 {
            s.on_path_update(0, &health(20, 0.0, 9_500_000));
            s.on_path_update(1, &health(30, 0.0, 500_000));
        }
        let backup_before = s.capacity_bps(1).unwrap();
        assert!(
            backup_before <= 1_100_000,
            "undersubscribed backup should be evidence-bounded: {backup_before}"
        );

        // Primary dies; keep offering the full feed. 263 × 950-byte
        // packets per 200 ms control round ≈ 10 Mbps, with a clean
        // health sample (delivered = what the round actually carried)
        // fed back each round — the receiver-echo loop in miniature.
        s.on_path_dead(0);
        let pkt = 950usize;
        let per_round = 263u64;
        let mut now = Instant::now();
        let mut recovered_round = None;
        for round in 1..=25u32 {
            let mut sent = 0u64;
            for _ in 0..per_round {
                now += Duration::from_micros(760);
                if matches!(s.schedule_at(&hints(pkt), now), PathSelection::Single(_)) {
                    sent += 1;
                }
            }
            let delivered_bps = sent * (pkt as u64 + TOKEN_OVERHEAD_BYTES as u64) * 8 * 5;
            s.on_path_update(1, &health(30, 0.0, delivered_bps));
            if sent == per_round && recovered_round.is_none() {
                recovered_round = Some(round);
            }
        }
        let recovered = recovered_round.expect("survivor never carried the full feed");
        assert!(
            recovered <= 5,
            "failover took {recovered} control rounds (> ~1 s at 5 Hz)"
        );
        assert!(
            s.capacity_bps(1).unwrap() >= 9_000_000,
            "survivor estimate did not ramp: {}",
            s.capacity_bps(1).unwrap()
        );
    }

    /// A permanent RTT baseline shift (5G handover / Starlink reroute)
    /// first reads as inflation and backs off, then ages out of the
    /// min-RTT window and the estimate recovers — instead of pinning at
    /// the floor forever.
    #[test]
    fn rtt_baseline_shift_recovers_after_window() {
        let cfg = CongestionConfig {
            rtt_min_window: Duration::from_millis(50),
            ..CongestionConfig::default()
        };
        let priors = vec![PathPrior { id: 0, weight_hint: 1, ceiling_bps: None }];
        let mut s = CapacityAwareScheduler::with_paths(priors, cfg);
        for _ in 0..30 {
            s.on_path_update(0, &health(20, 0.0, 10_000_000));
        }
        let high = s.capacity_bps(0).unwrap();
        // +60 ms permanent shift, zero loss — initially indistinguishable
        // from queue build-up, so the path backs off.
        for _ in 0..15 {
            s.on_path_update(0, &health(80, 0.0, 10_000_000));
        }
        let backed_off = s.capacity_bps(0).unwrap();
        assert!(backed_off < high, "shift should back off first: {high} -> {backed_off}");
        // Once the old 20 ms min ages out of the window, 80 ms becomes
        // the new baseline, inflation reads zero, and probing resumes.
        std::thread::sleep(Duration::from_millis(60));
        for _ in 0..30 {
            s.on_path_update(0, &health(80, 0.0, 10_000_000));
        }
        let recovered = s.capacity_bps(0).unwrap();
        assert!(
            recovered > backed_off,
            "estimate should recover after the window: {backed_off} -> {recovered}"
        );
        assert!(
            recovered >= 10_000_000,
            "recovery should reach at least the delivered rate: {recovered}"
        );
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

    #[test]
    fn auto_delay_threshold_tolerates_high_baseline_inflation() {
        // A cellular-like leg with a ~360 ms baseline. With the fixed
        // 40 ms threshold a 100 ms inflation reads as congestion and the
        // leg backs off — the exact false-backoff the live cellular test
        // had to hand-tune `delay_inflation_ms: 250` around. With
        // `delay_inflation_auto` the threshold derives to ~0.7×360 ≈
        // 252 ms, so the same inflation stays "clean" and the leg holds
        // its capacity instead of collapsing.
        fn run(auto: bool) -> (u64, u64) {
            let cfg = CongestionConfig {
                delay_inflation_auto: auto,
                ..Default::default()
            };
            let priors = vec![PathPrior {
                id: 0,
                weight_hint: 1,
                ceiling_bps: Some(20_000_000),
            }];
            let mut s = CapacityAwareScheduler::with_paths(priors, cfg);
            for _ in 0..20 {
                s.on_path_update(0, &health(360, 0.0, 8_000_000));
            }
            let base = s.capacity_bps(0).unwrap();
            for _ in 0..8 {
                // +100 ms over the 360 ms baseline.
                s.on_path_update(0, &health(460, 0.0, 8_000_000));
            }
            (base, s.capacity_bps(0).unwrap())
        }
        let (fixed_base, fixed_after) = run(false);
        let (auto_base, auto_after) = run(true);
        assert!(
            fixed_after < fixed_base,
            "fixed 40ms threshold should back off on 100ms inflation: {fixed_base} -> {fixed_after}"
        );
        assert!(
            auto_after >= auto_base,
            "auto threshold (~252ms) should tolerate 100ms inflation: {auto_base} -> {auto_after}"
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

    /// Two identical legs with full buckets (exact score ties) share the
    /// traffic via the rotating tie-break instead of concentrating on
    /// the lowest index — winner-takes-all would leave the second leg
    /// cold for failover.
    #[test]
    fn equal_legs_share_on_ties() {
        let mut s = CapacityAwareScheduler::new(vec![0, 1]);
        for _ in 0..100 {
            s.on_path_update(0, &health(20, 0.0, 20_000_000));
            s.on_path_update(1, &health(20, 0.0, 20_000_000));
        }
        // A second of idle fills both buckets; the offered rate is far
        // below capacity so refill restores the tie before each packet.
        let base = Instant::now() + Duration::from_secs(1);
        let interval = Duration::from_millis(10);
        let mut counts = [0u64; 2];
        for i in 0..1000u32 {
            match s.schedule_at(&hints(1316), base + interval * i) {
                PathSelection::Single(p) => counts[p as usize] += 1,
                PathSelection::Duplicate(v) => counts[v[0] as usize] += 1,
                PathSelection::Drop => {}
            }
        }
        let total = counts[0] + counts[1];
        assert!(counts[0] * 10 >= total * 3, "leg 0 should carry >=30%: {counts:?}");
        assert!(counts[1] * 10 >= total * 3, "leg 1 should carry >=30%: {counts:?}");
    }

    /// High interarrival jitter deweights a path's quality: the clean
    /// leg of an otherwise-identical pair carries the strict majority.
    #[test]
    fn jitter_deweights_path() {
        let mut s = CapacityAwareScheduler::new(vec![0, 1]);
        for _ in 0..100 {
            s.on_path_update(0, &health(20, 0.0, 20_000_000));
            s.on_path_update(1, &health_j(20, 0.0, 20_000_000, 200_000));
        }
        let base = Instant::now() + Duration::from_secs(1);
        let interval = Duration::from_millis(1);
        let mut counts = [0u64; 2];
        for i in 0..1000u32 {
            match s.schedule_at(&hints(1316), base + interval * i) {
                PathSelection::Single(p) => counts[p as usize] += 1,
                PathSelection::Duplicate(v) => counts[v[0] as usize] += 1,
                PathSelection::Drop => {}
            }
        }
        assert!(
            counts[0] > counts[1],
            "clean leg should carry the strict majority over the jittery one: {counts:?}"
        );
    }

    /// A starved leg's stale jitter sample decays across control rounds
    /// so the leg re-earns traffic — the receiver can only re-measure
    /// jitter on a leg that carries data, so without decay one bad
    /// sample would pin the leg out of the bond forever.
    #[test]
    fn stale_jitter_decays_on_starved_path() {
        let mut s = CapacityAwareScheduler::new(vec![0, 1]);
        for _ in 0..50 {
            s.on_path_update(0, &health_j(20, 0.0, 20_000_000, 200_000));
            s.on_path_update(1, &health(20, 0.0, 20_000_000));
        }
        // Deweighted leg 0 starves while leg 1 carries everything.
        let base = Instant::now() + Duration::from_secs(1);
        let mut t = base;
        for _ in 0..100 {
            t += Duration::from_millis(1);
            assert!(matches!(s.schedule_at(&hints(1316), t), PathSelection::Single(1)));
        }
        // Health rounds keep echoing the frozen 200 ms sample (no data
        // on leg 0 → no fresh measurement). The decay must let leg 0
        // win selections again within a few rounds.
        let mut counts = [0u64; 2];
        for _ in 0..10 {
            s.on_path_update(0, &health_j(20, 0.0, 20_000_000, 200_000));
            s.on_path_update(1, &health(20, 0.0, 20_000_000));
            for _ in 0..5 {
                t += Duration::from_millis(1);
                match s.schedule_at(&hints(1316), t) {
                    PathSelection::Single(p) => counts[p as usize] += 1,
                    PathSelection::Duplicate(v) => counts[v[0] as usize] += 1,
                    PathSelection::Drop => {}
                }
            }
        }
        assert!(
            counts[0] > 0,
            "starved leg should recover once the stale deweight decays: {counts:?}"
        );
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
