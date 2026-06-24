//! Bond receiver task.
//!
//! Multiplexes N path RX channels into a single
//! `bonding_protocol::protocol::reassembly::ReassemblyBuffer`, drains
//! ready packets to the app, detects gaps, and NACKs them back to the
//! sender over the most-recently-heard-from alive path (rotating among
//! equally fresh ones — a pure receiver never measures RTT, so inbound
//! freshness is the only honest liveness signal for the return route).
//! Responds to keepalive pings with pongs carrying per-path counters
//! so the sender can compute loss without extra round-trips.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use bonding_protocol::control::{
    CtrlHeader, CtrlPacket, CtrlType, KeepaliveAckBody, NackBody, is_control,
};
use bonding_protocol::events::{PathDeadReason, PathEvent, PathEventKind};
use bonding_protocol::packet::BondHeader;
use bonding_protocol::protocol::fec::{
    FecDecoder, FecParams, FecRepair, PerLegFecDecoder, PerLegRepair,
};
use bonding_protocol::protocol::rs::{PerLegRsDecoder, PerLegRsRepair};

use crate::config::PerLegFecKind;

/// A FEC-enabled leg's decoder — XOR or Reed-Solomon, per config.
enum LegDec {
    Xor(PerLegFecDecoder),
    Rs(PerLegRsDecoder),
}
use bonding_protocol::protocol::reassembly::{DrainItem, ReassemblyBuffer};
use bonding_protocol::protocol::scheduler::PathId;
use bonding_protocol::stats::{BondConnStats, PathStats};

use crate::health::BondHealthMonitor;
use crate::path::{Path, PathDatagram};

/// Stale-flood watchdog bounds: force a session re-anchor when EVERY
/// insert has been rejected as stale for at least this long *and* at
/// least this many packets — an unbroken all-stale run of that depth
/// can only be an anchor from a dead seq space (any healthy bond lands
/// in-window packets continuously, breaking the run). Covers the
/// sender rolling back to an epoch-less (v2) build after this receiver
/// adopted an epoch, where the epoch reset path can never fire.
const STALE_FLOOD_WINDOW: Duration = Duration::from_secs(3);
const STALE_FLOOD_MIN_PACKETS: u64 = 100;

/// Per-leg hold: a recovery whose filling leg has smoothed interarrival
/// jitter above this is NOT allowed to ratchet the adaptive hold servo's
/// `hold_window_max`. A catastrophically-jittery leg (a bufferbloated modem
/// at 300 ms+) otherwise drags the whole flow's reorder budget — and hence
/// its delivery latency — up toward `hold_max_ms`, taxing the healthy legs
/// for a leg that, after sender-side jitter demotion, carries only
/// redundancy/FEC copies whose late loss is harmless. Mirrors the sender's
/// `CongestionConfig::jitter_demote_us` default so both ends agree on what
/// "too jittery to gate latency on" means.
const HOLD_JITTER_EXCLUDE_US: u64 = 150_000;

pub(crate) struct ReceiverHandle {
    pub rx: mpsc::Receiver<Bytes>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_receiver(
    flow_id: u32,
    mut paths: Vec<Path>,
    hold_time: Duration,
    hold_max: Option<Duration>,
    conn_stats: Arc<BondConnStats>,
    path_stats: Vec<Arc<PathStats>>,
    path_names: Vec<String>,
    keepalive_interval: Duration,
    keepalive_miss_threshold: u32,
    events_tx: broadcast::Sender<PathEvent>,
    cancel: CancellationToken,
    nack_delay: Duration,
    max_nack_retries: u32,
    fec: Option<FecParams>,
    per_path_fec: std::collections::HashMap<PathId, PerLegFecKind>,
    equalization: crate::config::EqualizationMode,
) -> (ReceiverHandle, JoinHandle<()>) {
    let (app_tx, app_rx) = mpsc::channel::<Bytes>(1024);

    // Collect per-path rx channels into a single stream. Each
    // forwarder task pushes (path_id, datagram) into one mpsc.
    let (mux_tx, mux_rx) = mpsc::channel::<(PathId, PathDatagram)>(1024);
    for p in paths.iter_mut() {
        let path_id = p.id();
        let Some(mut path_rx) = p.take_rx() else {
            continue;
        };
        let mux_tx = mux_tx.clone();
        tokio::spawn(async move {
            while let Some(dg) = path_rx.recv().await {
                // Blocking handoff into the receiver-loop mux is deliberate
                // on the MEDIA path: `.send().await` lets the 1024-deep mux
                // (plus each path's 1024-deep rx) absorb a transient
                // receiver-loop stall *losslessly*, whereas a drop-on-full
                // `try_send` would shed media for a brief scheduler hiccup.
                // The head-of-line coupling this trades away only bites
                // under *sustained* overload, where loss is unavoidable
                // anyway and the protocol's ARQ/FEC recover it. Keep this
                // blocking — don't "optimise" it to try_send.
                if mux_tx.send((path_id, dg)).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(mux_tx);

    let join = tokio::spawn(async move {
        if let Err(e) = receiver_loop(
            flow_id,
            paths,
            hold_time,
            hold_max,
            conn_stats,
            path_stats,
            path_names,
            keepalive_interval,
            keepalive_miss_threshold,
            events_tx,
            app_tx,
            mux_rx,
            cancel,
            nack_delay,
            max_nack_retries,
            fec,
            per_path_fec,
            equalization,
        )
        .await
        {
            log::error!("bond receiver loop exited: {e}");
        }
    });

    (ReceiverHandle { rx: app_rx }, join)
}

/// Per-missing-seq state for NACK scheduling. Give-up is bounded by
/// `nacks_sent >= max_nack_retries`; hold-time loss is enforced by the
/// reassembly buffer and clears the entry via `DrainItem::Lost`.
#[derive(Debug)]
struct PendingNack {
    next_nack_at: Instant,
    nacks_sent: u32,
    /// When the most recent NACK for this seq went on the wire. `None`
    /// until the first send; a RETRANSMIT-flagged arrival for this seq
    /// samples `now - last_sent_at` into the retx-RTT estimate.
    last_sent_at: Option<Instant>,
}

/// Window over which a leg's minimum one-way-delay sample is held before
/// it can be re-baselined (BBR RTprop style). A permanent OWD shift (5G
/// handover, Starlink reroute, slow clock-rate skew) ages out instead of
/// latching a stale floor. Mirrors the scheduler's `rtt_min_window`.
const OWD_MIN_WINDOW: Duration = Duration::from_secs(10);
/// Stamped samples a leg needs before its measured OWD is trusted for
/// equalization. Until then the leg's offset is 0 (no equalization), so a
/// freshly-joined leg never injects a bogus spread.
const OWD_COLD_START_SAMPLES: u32 = 16;
/// A leg that hasn't delivered a stamped data packet within this window is
/// excluded from the equalization target — so when the slowest (target) leg
/// dies, fast legs stop over-holding for it within one window (the dead-leg
/// recompute) instead of waiting on the slower keepalive liveness timer.
const EQ_LEG_STALE: Duration = Duration::from_millis(800);
/// In `Auto` mode, alignment engages only when the measured inter-leg OWD
/// **skew** (slowest eligible leg − fastest) exceeds this floor — below it the
/// jitter hold already absorbs the spread and time-aligning would only add
/// latency for no aggregation benefit, so a homogeneous bond stays a no-op.
/// Hysteresis: engage above the floor, disengage below half. **This value is
/// the live-tunable knob** — it must be validated against real cellular +
/// Starlink jitter (too low → engages on noise; too high → a genuinely skewed
/// bond never aligns). `On` mode ignores it; `Off` never measures.
const SKEW_FLOOR_US: u32 = 20_000;
/// Grace window after the first stamp during which the loss_deadline covers the
/// full equalization budget — long enough for every alive leg to warm
/// (`OWD_COLD_START_SAMPLES`) and the engage decision to settle, so a high-skew
/// leg's gaps survive cold-start. After it, a bond that never engaged (low
/// skew) drops its loss_deadline back to the adaptive jitter-hold.
const COLD_START_GRACE: Duration = Duration::from_secs(3);

/// Per-leg relative one-way-delay estimator (receiver side). Built from the
/// v2 header `send_stamp_us`: `raw = arrival_us − send_stamp_us` carries the
/// true OWD plus a constant (sender-epoch − receiver-epoch) offset that
/// cancels when two legs' minima are differenced. Only the windowed MIN is
/// kept; everything above the floor is jitter and discarded.
#[derive(Debug, Clone, Copy)]
struct LegDelay {
    /// Windowed-min raw sample, wrapping u32 microseconds (`owd + const`).
    owd_min: u32,
    /// When `owd_min` was last (re)adopted — drives `OWD_MIN_WINDOW` aging.
    owd_min_at: Instant,
    /// When the last stamped data packet was observed — drives the dead-leg
    /// staleness exclusion (`EQ_LEG_STALE`).
    last_at: Instant,
    /// Stamped samples seen (cold-start gate).
    samples: u32,
}

impl LegDelay {
    fn new(now: Instant) -> Self {
        Self { owd_min: 0, owd_min_at: now, last_at: now, samples: 0 }
    }
    /// Feed a raw sample; windowed-min with wrap-safe comparison + aging.
    fn observe(&mut self, raw: u32, now: Instant) {
        if self.samples == 0
            || (raw.wrapping_sub(self.owd_min) as i32) < 0
            || now.saturating_duration_since(self.owd_min_at) > OWD_MIN_WINDOW
        {
            self.owd_min = raw;
            self.owd_min_at = now;
        }
        self.last_at = now;
        self.samples = self.samples.saturating_add(1);
    }
    /// Has this leg produced enough stamped samples to trust its OWD?
    #[inline]
    fn warm(&self) -> bool {
        self.samples >= OWD_COLD_START_SAMPLES
    }
    /// Warm AND not stale — eligible to participate in / define the
    /// equalization target.
    #[inline]
    fn eq_eligible(&self, now: Instant) -> bool {
        self.warm() && now.saturating_duration_since(self.last_at) < EQ_LEG_STALE
    }
}

/// Reset the receiver-local equalization mirror on a session reset (sender
/// restart). The sender's `send_stamp` origin (process boot) just reset, so
/// every `leg_owd` baseline was measured against the OLD sender epoch and is
/// now stale — and the windowed-min would hold it for up to `OWD_MIN_WINDOW`,
/// feeding bogus inter-leg skew into the recompute. `reassembly.reset()` already
/// clears the buffer's `equalize` table; this clears the source of truth that
/// re-drives it, so the next session re-measures from scratch and the
/// cold-start grace re-arms for the new instance.
#[allow(clippy::too_many_arguments)]
fn reset_equalization_state(
    leg_owd: &mut [LegDelay],
    rx_epoch: Instant,
    eq_active: &mut bool,
    eq_engaged: &mut bool,
    eq_active_since: &mut Option<Instant>,
    peer_align_suppress: &mut bool,
) {
    for l in leg_owd.iter_mut() {
        *l = LegDelay::new(rx_epoch);
    }
    *eq_active = false;
    *eq_engaged = false;
    *eq_active_since = None;
    *peer_align_suppress = false;
}

/// Relative OWD (µs) of leg `idx` vs the fastest WARM leg — how much later
/// this leg's packets land. `u32::MAX` = un-measured (cold-start / no
/// stamps / index out of range). Wrap-safe via `wrapping_sub`-as-`i32`.
fn leg_relative_owd_us(legs: &[LegDelay], idx: Option<usize>, now: Instant) -> u32 {
    let Some(i) = idx else { return u32::MAX };
    let Some(leg) = legs.get(i) else { return u32::MAX };
    if !leg.eq_eligible(now) {
        return u32::MAX;
    }
    let min = legs
        .iter()
        .filter(|l| l.eq_eligible(now))
        .map(|l| l.owd_min)
        .fold(None, |acc: Option<u32>, v| {
            Some(match acc {
                None => v,
                Some(m) if (v.wrapping_sub(m) as i32) < 0 => v,
                Some(m) => m,
            })
        });
    match min {
        Some(m) => (leg.owd_min.wrapping_sub(m) as i32).max(0) as u32,
        None => u32::MAX,
    }
}

#[allow(clippy::too_many_arguments)]
async fn receiver_loop(
    flow_id: u32,
    paths: Vec<Path>,
    hold_time: Duration,
    hold_max: Option<Duration>,
    conn_stats: Arc<BondConnStats>,
    path_stats: Vec<Arc<PathStats>>,
    path_names: Vec<String>,
    keepalive_interval: Duration,
    keepalive_miss_threshold: u32,
    events_tx: broadcast::Sender<PathEvent>,
    app_tx: mpsc::Sender<Bytes>,
    mut mux_rx: mpsc::Receiver<(PathId, PathDatagram)>,
    cancel: CancellationToken,
    nack_delay: Duration,
    max_nack_retries: u32,
    fec: Option<FecParams>,
    per_path_fec: std::collections::HashMap<PathId, PerLegFecKind>,
    equalization: crate::config::EqualizationMode,
) -> anyhow::Result<()> {
    use crate::config::EqualizationMode;
    let mut reassembly = ReassemblyBuffer::new(hold_time);
    // Advertise v2-data-header capability to the sender only when THIS receiver
    // measures (Auto/On). The sender gates its 16-byte send-stamped v2 headers
    // on seeing this — so an equalization-off (or genuinely-old) receiver keeps
    // the bond on v1 headers it can parse, never bricked by unparseable v2.
    let advertised_version: u16 = if equalization.measures() {
        bonding_protocol::packet::PROTOCOL_VERSION_V2 as u16
    } else {
        bonding_protocol::packet::PROTOCOL_VERSION as u16
    };
    // Sender-signalled ride-fastest (duplicate-all): suppress alignment in Auto
    // mode (On overrides). Learned from the keepalive `mode_flags`; updated on
    // every keepalive so a redundancy-mode change propagates within one tick.
    let mut peer_align_suppress = false;
    // Rate-limit for the header-parse-drop warning (an UnsupportedVersion
    // blackout would otherwise be invisible — see header_parse_drops).
    let mut last_parse_drop_warn: Option<Instant> = None;
    // Proactive FEC decoder (opt-in). Recovers a sparse loss from the
    // column's XOR repair with no NACK round-trip; recovered packets are
    // inserted into the reassembly buffer like a late path arrival.
    let mut fec_decoder: Option<FecDecoder> = fec.map(FecDecoder::new);

    // Per-leg FEC decoders (mutually exclusive with combined `fec`): one per
    // FEC-enabled leg, index-aligned to `paths`. A non-empty map selects
    // per-leg mode; each leg's decoder recovers a loss on that leg from the
    // repairs that rode the same leg, then re-injects the packet under its
    // real bond_seq into the shared reassembler.
    let per_leg_mode = !per_path_fec.is_empty();
    let mut per_leg_decoders: Vec<Option<LegDec>> = paths
        .iter()
        .map(|p| {
            per_path_fec.get(&p.id()).map(|kind| match kind {
                PerLegFecKind::Xor(prm) => LegDec::Xor(PerLegFecDecoder::new(*prm)),
                PerLegFecKind::ReedSolomon { data, parity, parity_max } => {
                    // Size the decoder for the largest block it may see.
                    LegDec::Rs(PerLegRsDecoder::new(*data, (*parity).max(*parity_max)))
                }
            })
        })
        .collect();

    // Adaptive hold-time servo (opt-in via hold_max > hold_time). Grows
    // the reorder/recovery budget toward the realized recovery latency
    // and decays back when the network calms, bounded by the floor and
    // ceiling — so end-to-end latency tracks the links.
    let hold_floor = hold_time;
    let hold_autogrow = hold_max.filter(|m| *m > hold_floor);
    let mut hold_cur = hold_time;
    let mut hold_window_max = Duration::ZERO;
    let mut hold_last_adjust = Instant::now();
    // Telemetry mirror of the (possibly adaptive) hold budget — written
    // on init and every retarget so exporters see it breathe.
    conn_stats
        .current_hold_ms
        .store(hold_cur.as_millis() as u64, Ordering::Relaxed);

    // ── Per-leg equalization state (L2/L3, see docs/per-leg-equalization.md).
    // Auto-activates when a v2 sender starts stamping data packets; with no
    // stamps `leg_owd` stays cold, `eq_active` false, and the reassembly's
    // equalize table stays zero → byte-for-byte the pre-equalization path.
    // `rx_epoch` is a receiver-local monotonic origin; only inter-leg
    // DIFFERENCES of (arrival − send_stamp) are physically meaningful, so the
    // unknown sender/receiver epoch offset cancels.
    let rx_epoch = Instant::now();
    let mut leg_owd: Vec<LegDelay> = vec![LegDelay::new(rx_epoch); paths.len()];
    // `eq_active` = ≥1 stamped packet seen (attempt recompute). `eq_engaged`
    // = the recompute has actually applied per-leg offsets (legs warm). The
    // servo runs until `eq_engaged` — so during cold-start (stamps seen but
    // legs not yet warm) the global hold still grows to cover the spread and
    // nothing is lost across the cold-start → equalized transition.
    let mut eq_active = false;
    let mut eq_engaged = false;
    // When the first stamp arrived. During the cold-start grace after this, the
    // loss_deadline covers the full budget so a high-skew leg's gaps aren't
    // declared lost before the legs warm + alignment engages (the servo can't
    // bootstrap that — a gap declared lost is never seen as a long recovery, so
    // the hold never grows). After the grace, a confirmed low-skew bond that
    // never engaged drops its loss_deadline back to the servo'd jitter-hold.
    let mut eq_active_since: Option<Instant> = None;
    // The equalization latency budget = the operator's hold ceiling when set,
    // else the static hold. loss_deadline is pinned to it while equalizing so
    // a NACK/FEC round-trip on the slowest aligned leg still lands before a
    // gap ages out.
    let eq_budget = hold_max.unwrap_or(hold_time).max(hold_time);
    let mut eq_last_recompute = Instant::now();

    // Session epoch adoption (sender-restart detection). 0 = none seen
    // yet (fresh receiver, or a v1/v2 peer that doesn't send epochs).
    let mut current_epoch: u32 = 0;
    // Candidate epoch + consecutive-control-packet count. Two
    // consecutive control packets bearing the same NEW epoch are
    // required before a session reset, so one stray late datagram
    // from an old process can't nuke a healthy bond.
    let mut pending_epoch: u32 = 0;
    let mut pending_epoch_count: u32 = 0;
    // Epoch retired by the most recent session reset. A congested leg
    // can drain queued old-instance keepalives in a burst seconds after
    // the reset; epochs are random per instance, so the retired value
    // can only be stale traffic — never a candidate again (two of them
    // must not flip the session backward).
    let mut abandoned_epoch: u32 = 0;
    // Stale-flood watchdog: an anchored buffer rejecting EVERY insert
    // for a sustained window means the anchor is from a dead seq space
    // and no epoch-based reset is coming (e.g. the sender rolled back
    // to an epoch-less v2 build after this receiver adopted an epoch).
    // Force a re-anchor rather than stay bricked until manual restart.
    let mut stale_run_start: Option<Instant> = None;
    let mut stale_run_count: u64 = 0;

    // Bond-level NACK→retransmit RTT estimate (EWMA, see
    // `ewma_retx_rtt`). Drives the NACK retry cadence; `None` until
    // the first retransmit is matched against a sent NACK.
    let mut retx_rtt: Option<Duration> = None;

    // `bond_seq -> pending NACK state`. Grows only as gaps appear;
    // cleared on recovery or drain-as-lost.
    let mut pending_nacks: HashMap<u32, PendingNack> = HashMap::new();

    // Most recent inbound datagram per path (by `paths` index). The
    // NACK carrier prefers the freshest path: on a CGNAT / cellular
    // leg, the most recently heard-from path is the one whose NAT
    // mapping is known to be open (a pure receiver never sends
    // keepalive pings, so `PathStats.rtt_us` is always 0 here).
    let mut last_rx: Vec<Option<Instant>> = vec![None; paths.len()];
    let mut nack_carrier_rr: usize = 0;

    // Per-path counters for the keepalive echo response.
    let mut path_recv_counter: HashMap<PathId, u64> = HashMap::new();
    // Per-path received byte counter — echoed so the sender can compute
    // a windowed delivered bitrate (the capacity controller's ground
    // truth).
    let mut path_recv_bytes: HashMap<PathId, u64> = HashMap::new();
    // Per-path interarrival jitter estimator: (last_arrival, mean_gap_us,
    // jitter_us), RFC 3550 A.8-style smoothing. Reported in the ack so a
    // jittery link is deweighted by the scheduler.
    let mut path_jitter: HashMap<PathId, (Instant, f64, f64)> = HashMap::new();

    let mut drain_scratch: Vec<DrainItem> = Vec::with_capacity(64);
    let mut ctrl_scratch = BytesMut::with_capacity(512);

    // Short pump interval: drains reassembly + fires any due NACKs.
    let mut pump = tokio::time::interval(Duration::from_millis(10));

    let path_index_by_id = |id: PathId| -> Option<usize> { paths.iter().position(|p| p.id() == id) };
    let path_stats_for = |idx: usize| -> Option<&Arc<PathStats>> { path_stats.get(idx) };

    // Receiver-side liveness: any inbound datagram (data or control)
    // counts as activity on a path. A path with no activity for
    // `keepalive_miss_threshold * keepalive_interval` flips to dead.
    let liveness_timeout =
        keepalive_interval.saturating_mul(keepalive_miss_threshold.max(1));
    let now_start = Instant::now();
    let monitor_inputs: Vec<(PathId, String, Arc<PathStats>)> = paths
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let name = path_names.get(i).cloned().unwrap_or_default();
            (p.id(), name, path_stats[i].clone())
        })
        .collect();
    let mut monitor = BondHealthMonitor::new(monitor_inputs, liveness_timeout, now_start);
    let mut liveness_tick = tokio::time::interval(liveness_timeout);
    liveness_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    liveness_tick.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                log::info!("bond receiver: shutdown");
                return Ok(());
            }

            maybe = mux_rx.recv() => {
                let Some((path_id, dg)) = maybe else {
                    log::info!("bond receiver: all path rx channels closed");
                    return Ok(());
                };
                let path_idx = path_index_by_id(path_id);
                let rx_now = Instant::now();
                // Any inbound datagram — even a keepalive — counts as
                // a liveness signal. Emit revival events if this path
                // was previously dead.
                for ev in monitor.record_activity(path_id, rx_now) {
                    let _ = events_tx.send(ev);
                }
                if let Some(idx) = path_idx {
                    last_rx[idx] = Some(rx_now);
                }
                if is_control(&dg.data) {
                    // Remember peer before handling control so the
                    // echo goes back to the right address even if the
                    // inbound is the very first packet on this path.
                    if let Some(idx) = path_idx {
                        if let Some(path) = paths.get(idx) {
                            path.set_primary_peer(dg.from);
                        }
                    }
                    // Inline keepalive handling: we need access to the
                    // reassembly buffer (for tail-tip advance) and
                    // pending_nacks, both owned by this loop.
                    match CtrlPacket::parse(&dg.data) {
                        Ok(CtrlPacket::Keepalive { header, body }) if header.flow_id == flow_id => {
                            // Ride-fastest (duplicate-all) signal from the
                            // sender — suppresses alignment in Auto mode.
                            peer_align_suppress = body.align_suppressed();
                            // Session-epoch handling. A restarted sender
                            // re-anchors bond_seq near 0; an anchored
                            // reassembly buffer would reject its every
                            // packet as stale forever. The FIRST nonzero
                            // epoch is adopted without a reset only when
                            // the anchor demonstrably belongs to this
                            // sender (un-anchored, or its advertised tip
                            // lands inside the anchored seq window — the
                            // mid-stream-join case). An anchored buffer
                            // whose anchor is from a foreign seq space
                            // (e.g. an epoch-less v2 sender fed this
                            // receiver, then restarted as v3 with seqs
                            // near 0) must treat the first epoch like
                            // any other new epoch — 2 consecutive
                            // control packets → full reset — or every
                            // new-instance packet drops as stale until
                            // manual restart.
                            let epoch = body.session_epoch;
                            if epoch != 0 {
                                if epoch == current_epoch {
                                    // A control packet carrying the
                                    // adopted epoch clears any candidate
                                    // — one stray datagram bearing a
                                    // foreign epoch must never creep
                                    // toward a reset.
                                    pending_epoch = 0;
                                    pending_epoch_count = 0;
                                } else if current_epoch == 0
                                    && reassembly.tip_in_window(body.highest_bond_seq_sent)
                                {
                                    current_epoch = epoch;
                                } else if epoch == abandoned_epoch {
                                    // Queued traffic from the instance a
                                    // reset already retired — never a
                                    // candidate (quarantined below).
                                } else {
                                    if epoch == pending_epoch {
                                        pending_epoch_count += 1;
                                    } else {
                                        pending_epoch = epoch;
                                        pending_epoch_count = 1;
                                    }
                                    if pending_epoch_count >= 2 {
                                        let old_epoch = current_epoch;
                                        current_epoch = epoch;
                                        abandoned_epoch = old_epoch;
                                        pending_epoch = 0;
                                        pending_epoch_count = 0;
                                        // Drop everything keyed on the old
                                        // seq space; the next data packet
                                        // re-anchors fresh.
                                        reassembly.reset();
                                        reset_equalization_state(
                                            &mut leg_owd,
                                            rx_epoch,
                                            &mut eq_active,
                                            &mut eq_engaged,
                                            &mut eq_active_since,
                                            &mut peer_align_suppress,
                                        );
                                        pending_nacks.clear();
                                        retx_rtt = None;
                                        stale_run_start = None;
                                        stale_run_count = 0;
                                        if let Some(dec) = fec_decoder.as_mut() {
                                            dec.reset();
                                        }
                                        for d in per_leg_decoders.iter_mut().flatten() {
                                            match d {
                                                LegDec::Xor(dec) => dec.reset(),
                                                LegDec::Rs(dec) => dec.reset(),
                                            }
                                        }
                                        conn_stats
                                            .session_resets
                                            .fetch_add(1, Ordering::Relaxed);
                                        let path_name = path_idx
                                            .and_then(|i| path_names.get(i).cloned())
                                            .unwrap_or_default();
                                        let _ = events_tx.send(PathEvent {
                                            path_id,
                                            path_name,
                                            kind: PathEventKind::SessionReset {
                                                old_epoch,
                                                new_epoch: epoch,
                                            },
                                        });
                                        log::info!(
                                            "bond receiver: sender restart detected, \
                                             session reset (epoch {old_epoch} -> {epoch})"
                                        );
                                    }
                                }
                            }
                            // Quarantine: a keepalive whose epoch field
                            // differs from the adopted value (0 = an
                            // epoch-less peer) carries counters and a
                            // `highest_bond_seq_sent` from a foreign seq
                            // space — a late old-instance keepalive
                            // draining off a bufferbloated leg, in either
                            // direction (epoch-0 after a v2→v3 reset, or
                            // a retired nonzero epoch). Feeding that tip
                            // to `advance_to_peer_tip` would expose up to
                            // capacity-1 phantom gaps (and NACK storms
                            // against seqs the live sender never
                            // produced) — process only the epoch
                            // candidate logic above and drop the body.
                            // Adoption in this same iteration updates
                            // `current_epoch` first, so a just-adopted
                            // keepalive processes normally.
                            if epoch != current_epoch {
                                continue;
                            }
                            let received_on_path = *path_recv_counter.get(&path_id).unwrap_or(&0);
                            let bytes_received_on_path =
                                *path_recv_bytes.get(&path_id).unwrap_or(&0);
                            let jitter_us = path_jitter
                                .get(&path_id)
                                .map(|(_, _, j)| *j as u32)
                                .unwrap_or(0);
                            let sent_on_path = body.packets_sent_on_path;
                            let ack_header =
                                CtrlHeader::new(CtrlType::KeepaliveAck, path_id, flow_id);
                            // Per-leg relative OWD (v4) — how much later this
                            // leg's packets land than the fastest eligible leg.
                            // u32::MAX = un-measured (cold-start / v1 sender,
                            // no send-timestamps). The sender uses it for the
                            // equalization-budget demote (L4).
                            let relative_owd_us =
                                leg_relative_owd_us(&leg_owd, path_idx, Instant::now());
                            let ack_body = KeepaliveAckBody {
                                stamp_us: body.stamp_us,
                                packets_sent_on_path: sent_on_path,
                                packets_received_on_path: received_on_path,
                                bytes_received_on_path,
                                jitter_us,
                                session_epoch: current_epoch,
                                relative_owd_us,
                                recv_protocol_version: advertised_version,
                            };
                            let ack = CtrlPacket::KeepaliveAck {
                                header: ack_header,
                                body: ack_body,
                            };
                            ack.serialize(&mut ctrl_scratch);
                            if let Some(idx) = path_idx {
                                if let Some(path) = paths.get(idx) {
                                    let _ = path.send_to(&ctrl_scratch, dg.from).await;
                                    if let Some(ps) = path_stats_for(idx) {
                                        ps.keepalives_received
                                            .fetch_add(1, Ordering::Relaxed);
                                        ps.keepalives_sent.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            // Tail-gap discovery — if the sender's
                            // advertised tip is ahead of our highest
                            // seen seq, register the missing tail as
                            // NACK candidates.
                            let mut tail_gaps: Vec<u32> = Vec::new();
                            reassembly.advance_to_peer_tip(
                                body.highest_bond_seq_sent,
                                Instant::now(),
                                &mut tail_gaps,
                            );
                            if !tail_gaps.is_empty() {
                                let now2 = Instant::now();
                                for g in &tail_gaps {
                                    pending_nacks.entry(*g).or_insert(PendingNack {
                                        next_nack_at: now2 + nack_delay,
                                        nacks_sent: 0,
                                        last_sent_at: None,
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                // Data packet
                let (header, consumed) = match BondHeader::parse(&dg.data) {
                    Ok(v) => v,
                    Err(e) => {
                        // A non-zero, growing header_parse_drops on an
                        // otherwise-alive leg is a version-mismatch blackout
                        // (e.g. a v2 send-stamped header reaching a build that
                        // can't parse it), not line noise. Count it always;
                        // warn (rate-limited) loudly on UnsupportedVersion,
                        // which uniquely signals a peer-version problem.
                        conn_stats.header_parse_drops.fetch_add(1, Ordering::Relaxed);
                        if matches!(e, bonding_protocol::error::BondError::UnsupportedVersion(_)) {
                            let now = Instant::now();
                            let due = last_parse_drop_warn
                                .map(|t| now.saturating_duration_since(t) >= Duration::from_secs(5))
                                .unwrap_or(true);
                            if due {
                                last_parse_drop_warn = Some(now);
                                log::warn!(
                                    "bond receiver flow {flow_id}: dropping data packets with \
                                     unparseable header ({e}) — likely a peer emitting a newer \
                                     bond data-header version this build can't parse (total \
                                     header_parse_drops={})",
                                    conn_stats.header_parse_drops.load(Ordering::Relaxed)
                                );
                            }
                        }
                        continue;
                    }
                };
                if header.flow_id != flow_id {
                    continue;
                }
                // Record peer so NACKs + pongs can go back to it.
                if let Some(idx) = path_idx {
                    if let Some(path) = paths.get(idx) {
                        if path.primary_peer().is_none() {
                            path.set_primary_peer(dg.from);
                        }
                    }
                }
                let payload = dg.data.slice(consumed..);

                // FEC repair packet → decoder, never the media reassembly
                // buffer (it carries no media bond_seq). Recovered packets
                // are inserted as late path arrivals.
                if header.is_fec() {
                    let fnow = Instant::now();
                    // Per-leg repairs are parsed + decoded against THIS leg's
                    // decoder (the repair rode the leg it protects); combined
                    // repairs go to the single global decoder. Either way the
                    // recovered packets carry their real bond_seq and insert
                    // into the shared reassembler as late path arrivals.
                    let recoveries: Vec<(u32, bytes::Bytes)> = if per_leg_mode {
                        // Parse the repair as this leg's configured algorithm.
                        match path_idx.and_then(|idx| {
                            per_leg_decoders[idx].as_mut().map(|d| (idx, d))
                        }) {
                            Some((_, LegDec::Xor(dec))) => {
                                PerLegRepair::parse(&payload)
                                    .map(|rep| dec.push_repair(rep))
                                    .unwrap_or_default()
                            }
                            Some((_, LegDec::Rs(dec))) => {
                                PerLegRsRepair::parse(&payload)
                                    .map(|rep| dec.push_repair(rep))
                                    .unwrap_or_default()
                            }
                            None => Vec::new(),
                        }
                    } else {
                        match (fec_decoder.as_mut(), FecRepair::parse(&payload)) {
                            (Some(dec), Some(rep)) => dec.push_repair(rep),
                            _ => Vec::new(),
                        }
                    };
                    for (rseq, rpayload) in recoveries {
                        let o = reassembly.insert(rseq, rpayload, path_id, fnow);
                        if o.recovered {
                            conn_stats.gaps_recovered.fetch_add(1, Ordering::Relaxed);
                            // Per-leg FEC recovery — credit THIS leg so the
                            // operator sees each leg's proactive recovery.
                            if per_leg_mode {
                                if let Some(ps) = path_idx.and_then(|i| path_stats.get(i)) {
                                    ps.fec_recovered.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            pending_nacks.remove(&rseq);
                            if let Some(age) = o.recovered_age {
                                // Per-leg hold: a catastrophically-jittery leg
                                // must not ratchet the global reorder budget.
                                let leg_jitter =
                                    path_jitter.get(&path_id).map(|e| e.2 as u64).unwrap_or(0);
                                if leg_jitter <= HOLD_JITTER_EXCLUDE_US && age > hold_window_max {
                                    hold_window_max = age;
                                }
                            }
                        }
                    }
                    continue;
                }

                conn_stats.packets_received.fetch_add(1, Ordering::Relaxed);
                conn_stats
                    .bytes_received
                    .fetch_add(dg.data.len() as u64, Ordering::Relaxed);
                if let Some(idx) = path_idx {
                    if let Some(ps) = path_stats_for(idx) {
                        ps.packets_received.fetch_add(1, Ordering::Relaxed);
                        ps.bytes_received
                            .fetch_add(dg.data.len() as u64, Ordering::Relaxed);
                        if header.is_retransmit() {
                            ps.retransmits_received.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                *path_recv_counter.entry(path_id).or_insert(0) += 1;
                *path_recv_bytes.entry(path_id).or_insert(0) += dg.data.len() as u64;
                // Interarrival jitter (RFC 3550 A.8-style): smooth the
                // absolute deviation of the inter-packet gap from its
                // running mean. A bursty/jittery link reports higher and
                // the capacity scheduler deweights it.
                // Smoothed interarrival jitter for THIS leg, captured into
                // scope so the hold servo below can ignore a recovery that
                // came via a catastrophically-jittery leg (per-leg hold: one
                // bad leg must not ratchet the global reorder budget — and
                // hence the latency — for the healthy legs).
                let cur_jitter_us = {
                    let arrival = Instant::now();
                    let jitter_us = {
                        let e = path_jitter.entry(path_id).or_insert((arrival, 0.0, 0.0));
                        let gap = arrival.saturating_duration_since(e.0).as_micros() as f64;
                        e.0 = arrival;
                        if e.1 == 0.0 {
                            e.1 = gap;
                        } else {
                            let d = (gap - e.1).abs();
                            e.2 += (d - e.2) / 16.0;
                            e.1 += (gap - e.1) / 16.0;
                        }
                        e.2 as u64
                    };
                    if let Some(idx) = path_idx {
                        if let Some(ps) = path_stats_for(idx) {
                            ps.jitter_us.store(jitter_us, Ordering::Relaxed);
                        }
                    }
                    jitter_us
                };

                // Per-leg OWD measurement (L2): a v2 sender stamps each data
                // packet with its monotonic emit time. raw = arrival − stamp
                // (wrapping u32 µs) = true OWD + a constant epoch offset that
                // cancels in the inter-leg difference. Only FRESH data packets
                // (not retransmits, whose latency is the NACK loop, not the
                // path OWD) feed the estimator.
                if let (Some(stamp), Some(idx)) = (header.send_stamp_us, path_idx) {
                    if !header.is_retransmit() {
                        let arrival_us = rx_now.saturating_duration_since(rx_epoch).as_micros() as u32;
                        let raw = arrival_us.wrapping_sub(stamp);
                        if let Some(leg) = leg_owd.get_mut(idx) {
                            leg.observe(raw, rx_now);
                            eq_active = true;
                            if eq_active_since.is_none() {
                                eq_active_since = Some(rx_now);
                            }
                        }
                    }
                }

                // NACK→retransmit RTT sample: a RETRANSMIT-flagged
                // arrival for a seq with an outstanding NACK measures
                // the full NACK→resend loop. EWMA'd into the retry
                // cadence so high-RTT legs aren't re-NACKed before the
                // first retransmit could possibly have arrived.
                if header.is_retransmit() {
                    if let Some(sent_at) = pending_nacks
                        .get(&header.bond_seq)
                        .and_then(|pn| pn.last_sent_at)
                    {
                        let sample = rx_now.saturating_duration_since(sent_at);
                        retx_rtt = Some(ewma_retx_rtt(retx_rtt, sample));
                    }
                }

                let outcome =
                    reassembly.insert(header.bond_seq, payload.clone(), path_id, Instant::now());
                if outcome.stale {
                    conn_stats
                        .late_stale_drops
                        .fetch_add(1, Ordering::Relaxed);
                    // Stale-flood watchdog (see the constants' doc):
                    // an unbroken all-stale run this deep means the
                    // anchor is from a dead seq space and no epoch
                    // reset is coming — force a re-anchor.
                    stale_run_count += 1;
                    let started = *stale_run_start.get_or_insert(rx_now);
                    if stale_run_count >= STALE_FLOOD_MIN_PACKETS
                        && rx_now.saturating_duration_since(started) >= STALE_FLOOD_WINDOW
                    {
                        let old_epoch = current_epoch;
                        // Re-arm first-epoch adoption: the next sender
                        // instance may be epoch-less (v2) or epoched
                        // (v3); both re-anchor cleanly from here.
                        current_epoch = 0;
                        abandoned_epoch = 0;
                        pending_epoch = 0;
                        pending_epoch_count = 0;
                        reassembly.reset();
                        reset_equalization_state(
                            &mut leg_owd,
                            rx_epoch,
                            &mut eq_active,
                            &mut eq_engaged,
                            &mut eq_active_since,
                            &mut peer_align_suppress,
                        );
                        pending_nacks.clear();
                        retx_rtt = None;
                        if let Some(dec) = fec_decoder.as_mut() {
                            dec.reset();
                        }
                        for d in per_leg_decoders.iter_mut().flatten() {
                            match d {
                                LegDec::Xor(dec) => dec.reset(),
                                LegDec::Rs(dec) => dec.reset(),
                            }
                        }
                        conn_stats.session_resets.fetch_add(1, Ordering::Relaxed);
                        stale_run_start = None;
                        stale_run_count = 0;
                        let path_name = path_idx
                            .and_then(|i| path_names.get(i).cloned())
                            .unwrap_or_default();
                        let _ = events_tx.send(PathEvent {
                            path_id,
                            path_name,
                            kind: PathEventKind::SessionReset {
                                old_epoch,
                                new_epoch: 0,
                            },
                        });
                        log::warn!(
                            "bond receiver: every insert stale for \
                             {STALE_FLOOD_WINDOW:?} (epoch {old_epoch}) — \
                             forcing session re-anchor"
                        );
                    }
                } else {
                    stale_run_start = None;
                    stale_run_count = 0;
                }
                if outcome.duplicate {
                    conn_stats
                        .duplicates_received
                        .fetch_add(1, Ordering::Relaxed);
                }
                if outcome.recovered {
                    conn_stats.gaps_recovered.fetch_add(1, Ordering::Relaxed);
                    pending_nacks.remove(&header.bond_seq);
                    if let Some(age) = outcome.recovered_age {
                        // Per-leg hold: a catastrophically-jittery leg's slow
                        // recovery must not ratchet the global reorder budget
                        // (and hence the healthy legs' delivery latency).
                        if cur_jitter_us <= HOLD_JITTER_EXCLUDE_US && age > hold_window_max {
                            hold_window_max = age;
                        }
                    }
                }
                // Register every newly-exposed gap in the NACK
                // scheduler so the pump tick can flush due NACKs. The
                // first NACK is delayed by `nack_delay` so natural
                // out-of-order arrivals on other paths have a chance
                // to fill the gap without a retransmit round-trip.
                if !outcome.new_gap_seqs.is_empty() {
                    let now2 = Instant::now();
                    for gap_seq in &outcome.new_gap_seqs {
                        pending_nacks.entry(*gap_seq).or_insert(PendingNack {
                            next_nack_at: now2 + nack_delay,
                            nacks_sent: 0,
                            last_sent_at: None,
                        });
                    }
                }

                // Feed the FEC decoder so a later repair (or a sibling
                // source) can recover a loss in this column with no NACK.
                // Per-leg: feed THIS leg's decoder (it only protects this
                // leg's packets); combined: feed the single global decoder.
                let fec_recoveries: Vec<(u32, bytes::Bytes)> = if per_leg_mode {
                    match path_idx.and_then(|idx| per_leg_decoders[idx].as_mut()) {
                        Some(LegDec::Xor(dec)) => dec.push_source(header.bond_seq, &payload),
                        Some(LegDec::Rs(dec)) => dec.push_source(header.bond_seq, &payload),
                        None => Vec::new(),
                    }
                } else {
                    match fec_decoder.as_mut() {
                        Some(dec) => dec.push_source(header.bond_seq, &payload),
                        None => Vec::new(),
                    }
                };
                if !fec_recoveries.is_empty() {
                    let fnow = Instant::now();
                    for (rseq, rpayload) in fec_recoveries {
                        let o = reassembly.insert(rseq, rpayload, path_id, fnow);
                        if o.recovered {
                            conn_stats.gaps_recovered.fetch_add(1, Ordering::Relaxed);
                            if per_leg_mode {
                                if let Some(ps) = path_idx.and_then(|i| path_stats.get(i)) {
                                    ps.fec_recovered.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            pending_nacks.remove(&rseq);
                            if let Some(age) = o.recovered_age {
                                // Per-leg hold (see HOLD_JITTER_EXCLUDE_US).
                                if cur_jitter_us <= HOLD_JITTER_EXCLUDE_US && age > hold_window_max {
                                    hold_window_max = age;
                                }
                            }
                        }
                    }
                }

                // Opportunistic in-order release: hand any now-contiguous,
                // hold-satisfied head to the application immediately rather
                // than waiting for the next pump tick. This removes the
                // 0..pump-interval delivery-jitter that otherwise clumped
                // egress into ~10 ms bursts. hold_time (the reorder budget)
                // is still honoured; gap-loss + NACKs stay on the pump.
                drain_reassembly(
                    &mut reassembly,
                    &app_tx,
                    &conn_stats,
                    &mut drain_scratch,
                    Instant::now(),
                    &mut pending_nacks,
                    false,
                );
            }

            _ = liveness_tick.tick() => {
                for ev in monitor.check_timeouts(Instant::now(), PathDeadReason::ReceiveTimeout) {
                    let _ = events_tx.send(ev);
                }
            }

            _ = pump.tick() => {
                let now = Instant::now();
                drain_reassembly(&mut reassembly, &app_tx, &conn_stats, &mut drain_scratch, now, &mut pending_nacks, true);

                // Per-leg equalization recompute (~5 Hz; L3). Align every
                // eligible (warm + fresh) leg to the SLOWEST eligible one so
                // all legs deliver time-aligned — the jitter-hold then only
                // covers residual jitter. A silent/dead leg drops out of
                // `eq_eligible` within EQ_LEG_STALE, immediately shrinking the
                // others' offsets (the dead-leg recompute). loss_deadline is
                // pinned to the budget so a NACK/FEC round-trip on the slowest
                // aligned leg still lands before a gap ages out. Inert until a
                // v2 sender's stamps warm the estimator.
                if eq_active && now.saturating_duration_since(eq_last_recompute)
                    >= Duration::from_millis(200)
                {
                    eq_last_recompute = now;
                    // Slowest + fastest eligible leg owd_min (wrap-safe).
                    let mut max_owd: Option<u32> = None;
                    let mut min_owd: Option<u32> = None;
                    for l in leg_owd.iter().filter(|l| l.eq_eligible(now)) {
                        let v = l.owd_min;
                        max_owd = Some(match max_owd {
                            None => v,
                            Some(m) if (v.wrapping_sub(m) as i32) > 0 => v,
                            Some(m) => m,
                        });
                        min_owd = Some(match min_owd {
                            None => v,
                            Some(m) if (v.wrapping_sub(m) as i32) < 0 => v,
                            Some(m) => m,
                        });
                    }
                    // Refresh per-leg relative-OWD telemetry every recompute so
                    // an operator sees the measured spread whether or not
                    // alignment engages (e.g. to see skew building toward the
                    // floor on Auto, or staying below it on a homogeneous bond).
                    for (idx, _) in leg_owd.iter().enumerate() {
                        if let Some(ps) = path_stats.get(idx) {
                            let rel = leg_relative_owd_us(&leg_owd, Some(idx), now);
                            ps.relative_owd_us.store(
                                if rel == u32::MAX { 0 } else { rel as u64 },
                                Ordering::Relaxed,
                            );
                        }
                    }
                    if let (Some(max_owd), Some(min_owd)) = (max_owd, min_owd) {
                        // The inter-leg skew the equalizer would align out.
                        let skew_us = (max_owd.wrapping_sub(min_owd) as i32).max(0) as u32;
                        // Engage decision. `On` force-engages (and overrides the
                        // sender's ride-fastest suppression). `Auto` engages only
                        // when the skew is worth the latency AND the sender isn't
                        // ride-fastest. Hysteresis (engage above the floor,
                        // disengage below half) stops a near-floor skew flapping.
                        let force = matches!(equalization, EqualizationMode::On);
                        let suppressed = peer_align_suppress && !force;
                        let skew_threshold =
                            if eq_engaged { SKEW_FLOOR_US / 2 } else { SKEW_FLOOR_US };
                        let should_engage = !suppressed && (force || skew_us > skew_threshold);
                        if should_engage {
                            let budget_us = eq_budget.as_micros().min(u32::MAX as u128) as u32;
                            for (idx, leg) in leg_owd.iter().enumerate() {
                                let offset_us = if leg.eq_eligible(now) {
                                    ((max_owd.wrapping_sub(leg.owd_min) as i32).max(0) as u32)
                                        .min(budget_us)
                                } else {
                                    0
                                };
                                if let Some(p) = paths.get(idx) {
                                    reassembly.set_equalization(
                                        p.id(),
                                        Duration::from_micros(offset_us as u64),
                                    );
                                }
                            }
                            // jitter_hold pinned to the static floor while
                            // equalizing: the per-leg offsets already cover the
                            // inter-leg spread, so the in-order hold only needs
                            // to cover residual jitter, and the equalized leg's
                            // late fill no longer ratchets the global hold up.
                            reassembly.set_hold_time(hold_floor);
                            // Equalization now drives the hold — the adaptive
                            // servo stands down. loss_deadline is owned by the
                            // single rule at the end of the pump tick.
                            eq_engaged = true;
                        } else if eq_engaged {
                            // Was aligning; skew dropped below the floor or the
                            // sender went ride-fastest → stand down: clear the
                            // per-leg offsets so the adaptive hold servo (gated on
                            // !eq_engaged) takes back over for residual jitter.
                            reassembly.clear_equalization();
                            eq_engaged = false;
                        }
                    } else if eq_engaged {
                        // No eligible legs at all (every leg fresh-data-stale —
                        // e.g. a brief total-uplink stall). Without this, the
                        // engage/disengage block above is skipped entirely:
                        // eq_engaged would latch ON forever, the stale per-leg
                        // offsets would persist (the fast leg returning first
                        // carries a dead leg's offset → a latency spike), the
                        // servo would stay gated off, and loss_deadline would
                        // stay pinned at the full budget. Stand down.
                        reassembly.clear_equalization();
                        eq_engaged = false;
                    }
                }

                // Any NACKs due? Retry cadence is RTT-aware — re-asking
                // before a retransmit could possibly arrive only buys
                // duplicate resends (see `nack_retry_interval`).
                let retry_after = nack_retry_interval(retx_rtt, nack_delay);
                let due: Vec<u32> = pending_nacks
                    .iter_mut()
                    .filter_map(|(seq, pn)| {
                        if now >= pn.next_nack_at {
                            if pn.nacks_sent >= max_nack_retries {
                                return None;
                            }
                            pn.nacks_sent += 1;
                            pn.next_nack_at = now + retry_after;
                            pn.last_sent_at = Some(now);
                            Some(*seq)
                        } else {
                            None
                        }
                    })
                    .collect();

                if !due.is_empty() {
                    // Emit one NACK message per datagram, up to cap.
                    send_nacks(
                        flow_id,
                        &paths,
                        &path_stats,
                        &due,
                        &mut ctrl_scratch,
                        &last_rx,
                        &mut nack_carrier_rr,
                    )
                    .await;
                }

                // Prune retried-to-death entries so the map doesn't grow.
                pending_nacks.retain(|_, pn| pn.nacks_sent < max_nack_retries);

                // Adaptive hold-time (opt-in): ~1 Hz, retarget toward the
                // realized recovery latency (×1.5) within [floor, max],
                // decaying toward the floor when nothing needed recovery
                // so latency drops back as the links calm. Suspended only
                // once equalization is ENGAGED (offsets applied) — during
                // cold-start it still runs so the global hold covers the
                // spread until the per-leg offsets take over.
                if !eq_engaged {
                if let Some(hmax) = hold_autogrow {
                    if now.saturating_duration_since(hold_last_adjust) >= Duration::from_secs(1) {
                        let target = if hold_window_max > Duration::ZERO {
                            hold_window_max.mul_f32(1.5).clamp(hold_floor, hmax)
                        } else {
                            hold_cur.mul_f32(0.9).max(hold_floor)
                        };
                        if target != hold_cur {
                            hold_cur = target;
                            reassembly.set_hold_time(hold_cur);
                            conn_stats
                                .current_hold_ms
                                .store(hold_cur.as_millis() as u64, Ordering::Relaxed);
                        }
                        hold_window_max = Duration::ZERO;
                        hold_last_adjust = now;
                    }
                }
                }

                // loss_deadline rule (single owner). Cover the equalization
                // budget while alignment is ENGAGED (the aligned slowest leg +
                // a NACK/FEC round-trip), AND during the cold-start grace after
                // the first stamp (so a high-skew leg's gaps survive while the
                // legs warm and the engage decision settles — the servo can't
                // bootstrap that). Otherwise — a confirmed low-skew bond that
                // measured but never engaged, or a non-equalized bond — track
                // the servo'd jitter-hold so a clean bond keeps a SMALL gap-to-
                // Lost deadline instead of being pinned to the full budget. This
                // is the fix for the eq_active-pins-budget-on-first-stamp bug.
                let in_cold_start_grace = eq_active_since
                    .map(|t| now.saturating_duration_since(t) < COLD_START_GRACE)
                    .unwrap_or(false);
                let target_loss = if eq_engaged || in_cold_start_grace {
                    eq_budget
                } else {
                    reassembly.hold_time()
                };
                reassembly.set_loss_deadline(target_loss);
            }
        }
    }
}

/// Move the deliverable reassembly prefix to the application.
///
/// `declare_lost` selects the drain mode:
/// - `true` (the timed pump): aged-out gaps are force-advanced as `Lost`
///   and NACK bookkeeping is reconciled — the authoritative loss/recovery
///   cadence, and the path that flushes a stream that has gone idle.
/// - `false` (per data-packet arrival): deliver only the in-order,
///   hold-satisfied prefix; never give up on a missing seq. Called on
///   every data packet so a contiguous head is released within an
///   inter-packet gap of its hold-time expiry rather than waiting up to a
///   full pump tick — that pump quantisation is what clumped delivery into
///   bursty ~10 ms batches. Delivery still respects `hold_time`.
///
/// Synchronous: there is no await on this path (delivery is a non-blocking
/// `try_send`), so it is cheap to call once per packet.
fn drain_reassembly(
    reassembly: &mut ReassemblyBuffer,
    app_tx: &mpsc::Sender<Bytes>,
    conn_stats: &Arc<BondConnStats>,
    scratch: &mut Vec<DrainItem>,
    now: Instant,
    pending_nacks: &mut HashMap<u32, PendingNack>,
    declare_lost: bool,
) {
    scratch.clear();
    if declare_lost {
        reassembly.drain_ready(now, scratch);
    } else {
        reassembly.deliver_ready(now, scratch);
    }
    for item in scratch.drain(..) {
        match item {
            DrainItem::Delivered { data, bond_seq, .. } => {
                pending_nacks.remove(&bond_seq);
                conn_stats.packets_delivered.fetch_add(1, Ordering::Relaxed);
                if app_tx.try_send(data).is_err() {
                    // App consumer backed up — drop rather than block
                    // the reassembly pump. Bookkeeping at higher layer.
                }
            }
            DrainItem::Lost { bond_seq } => {
                pending_nacks.remove(&bond_seq);
                conn_stats.gaps_lost.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Paths whose last inbound datagram is within this window of the
/// freshest path's are "equally fresh" for NACK carriage — the carrier
/// rotates among them so reverse-control traffic doesn't all ride (and
/// die with) a single leg.
const NACK_CARRIER_FRESH_WINDOW: Duration = Duration::from_millis(50);

#[allow(clippy::too_many_arguments)]
async fn send_nacks(
    flow_id: u32,
    paths: &[Path],
    path_stats: &[Arc<PathStats>],
    due: &[u32],
    scratch: &mut BytesMut,
    last_rx: &[Option<Instant>],
    carrier_rr: &mut usize,
) {
    // Pick the NACK carrier by inbound freshness. A pure receiver never
    // sends keepalive pings, so sender-measured RTT (`PathStats.rtt_us`)
    // is always 0 on this side — the most recently heard-from path is
    // the one whose return route (and NAT mapping) is known-good.
    let candidates: Vec<usize> = (0..paths.len())
        .filter(|i| {
            paths[*i].primary_peer().is_some()
                && path_stats
                    .get(*i)
                    .map(|ps| ps.dead.load(Ordering::Relaxed) == 0)
                    .unwrap_or(true)
        })
        .collect();
    if candidates.is_empty() {
        return;
    }
    let freshest = candidates
        .iter()
        .filter_map(|i| last_rx.get(*i).copied().flatten())
        .max();
    // Rotate among the paths within the freshness window; if nothing
    // has been heard yet on any candidate, rotate among all of them.
    let fresh: Vec<usize> = match freshest {
        Some(f) => candidates
            .iter()
            .copied()
            .filter(|i| {
                last_rx.get(*i).copied().flatten().is_some_and(|t| {
                    f.saturating_duration_since(t) <= NACK_CARRIER_FRESH_WINDOW
                })
            })
            .collect(),
        None => candidates.clone(),
    };
    let pool = if fresh.is_empty() { &candidates } else { &fresh };
    let idx = pool[*carrier_rr % pool.len()];
    *carrier_rr = carrier_rr.wrapping_add(1);
    let path = &paths[idx];
    let Some(peer) = path.primary_peer() else {
        return;
    };

    // Chunk into NACK-sized messages.
    for chunk in due.chunks(NackBody::MAX_NACK_ENTRIES) {
        let header = CtrlHeader::new(CtrlType::Nack, path.id(), flow_id);
        let body = NackBody {
            missing: chunk.to_vec(),
        };
        let pkt = CtrlPacket::Nack { header, body };
        pkt.serialize(scratch);
        let _ = path.send_to(scratch, peer).await;
        if let Some(ps) = path_stats.get(idx) {
            ps.nacks_sent
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    }
}

/// Hard cap on the NACK retry interval — waiting longer than a quarter
/// second between retries risks blowing the hold budget on even the
/// highest-RTT legs this bond targets (Starlink, intercontinental
/// cellular; geostationary is out of scope).
const NACK_RETRY_MAX: Duration = Duration::from_millis(250);

/// Retry cadence for an outstanding NACK. Once a NACK→retransmit
/// round-trip has been measured: 1.5× the smoothed retx RTT, floored
/// at `nack_delay`, capped at [`NACK_RETRY_MAX`]. Before the first
/// sample: 2× `nack_delay` — the old fixed `nack_delay` cadence
/// re-asked every 30 ms and produced 2-3× duplicate retransmits per
/// loss on any leg with RTT above that.
fn nack_retry_interval(retx_rtt: Option<Duration>, nack_delay: Duration) -> Duration {
    match retx_rtt {
        Some(rtt) => {
            let lo = nack_delay;
            // An operator nack_delay above the cap wins (no inverted clamp).
            let hi = NACK_RETRY_MAX.max(lo);
            rtt.mul_f64(1.5).clamp(lo, hi)
        }
        None => nack_delay.saturating_mul(2),
    }
}

/// Smooth a NACK→retransmit RTT sample into the running estimate.
/// EWMA α = 0.25 — converges within ~4 samples after a path change
/// without chasing single outliers.
fn ewma_retx_rtt(prev: Option<Duration>, sample: Duration) -> Duration {
    match prev {
        Some(p) => p.mul_f64(0.75) + sample.mul_f64(0.25),
        None => sample,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nack_retry_interval_before_first_sample_is_two_base_delays() {
        let base = Duration::from_millis(30);
        assert_eq!(nack_retry_interval(None, base), Duration::from_millis(60));
    }

    #[test]
    fn nack_retry_interval_tracks_measured_rtt() {
        let base = Duration::from_millis(30);
        // 100 ms retx RTT → 150 ms retry.
        assert_eq!(
            nack_retry_interval(Some(Duration::from_millis(100)), base),
            Duration::from_millis(150)
        );
        // Tiny RTT floors at nack_delay.
        assert_eq!(
            nack_retry_interval(Some(Duration::from_millis(2)), base),
            base
        );
        // Huge RTT caps at NACK_RETRY_MAX.
        assert_eq!(
            nack_retry_interval(Some(Duration::from_secs(1)), base),
            NACK_RETRY_MAX
        );
        // nack_delay above the cap: no inverted-clamp panic, floor wins.
        let big = Duration::from_millis(400);
        assert_eq!(nack_retry_interval(Some(Duration::from_secs(1)), big), big);
    }

    #[test]
    fn ewma_retx_rtt_converges() {
        let mut est: Option<Duration> = None;
        est = Some(ewma_retx_rtt(est, Duration::from_millis(100)));
        assert_eq!(est, Some(Duration::from_millis(100)));
        est = Some(ewma_retx_rtt(est, Duration::from_millis(200)));
        // 100 × 0.75 + 200 × 0.25 = 125.
        assert_eq!(est, Some(Duration::from_millis(125)));
    }
}

