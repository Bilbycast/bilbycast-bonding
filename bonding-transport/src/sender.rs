//! Bond sender task.
//!
//! One task per `BondSocket::sender`. Owns:
//! - N [`path::Path`] handles (one per configured remote).
//! - The scheduler (trait-object, chosen by the caller).
//! - The sender-side retransmit buffer so NACKs can be answered.
//! - Per-path keepalive timers feeding RTT into `PathStats`.
//!
//! The sender is driven from three sources: the app's outbound mpsc,
//! the keepalive interval, and inbound control messages (keepalive
//! acks, NACKs) multiplexed off each path's receive channel.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use bonding_protocol::control::{
    CtrlHeader, CtrlPacket, CtrlType, KeepaliveBody, is_control,
};
use bonding_protocol::events::{PathDeadReason, PathEvent, PathEventKind, PathRebuildReason};
use bonding_protocol::packet::{BondHeader, Priority, write_packet};
use bonding_protocol::protocol::fec::{FecEncoder, FecParams, PerLegFecEncoder};
use bonding_protocol::protocol::rs::PerLegRsEncoder;

use crate::config::PerLegFecKind;

/// A FEC-enabled leg's encoder — XOR or Reed-Solomon, per config.
enum LegEnc {
    Xor(PerLegFecEncoder),
    Rs(PerLegRsEncoder),
}
use bonding_protocol::protocol::path_health::PathHealth;
use bonding_protocol::protocol::retransmit::RetransmitBuffer;
use bonding_protocol::protocol::scheduler::{
    BondScheduler, PacketHints, PathId, PathSelection,
};
use bonding_protocol::stats::{BondConnStats, PathStats};

use crate::health::BondHealthMonitor;
use crate::path::{Path, PathDatagram};

/// App-facing outbound message.
pub(crate) struct OutboundMessage {
    pub data: Bytes,
    pub hints: PacketHints,
}

/// Last keepalive-ack sample retained per path so the sender can derive
/// a **windowed** loss fraction and delivered bitrate by differencing
/// successive acks — the lifetime-cumulative ratio the old code used is
/// far too sluggish to drive a congestion controller (a path that runs
/// clean for an hour then degrades shows a diluted average for minutes).
#[derive(Clone, Copy)]
struct AckSample {
    /// Echoed sender-side packet count at the ping this ack answers.
    sent: u64,
    /// Receiver-side packet count for this path.
    received: u64,
    /// Receiver-side byte count for this path.
    bytes_received: u64,
    /// Sender-side SEND instant of the keepalive probe this ack answers —
    /// NOT the ack's arrival time. The receiver sampled `bytes_received`
    /// when it processed that probe, so the delta between two probes' send
    /// instants is the interval those bytes accumulated over. Differencing on
    /// the send clock (instead of ack arrival) makes the delivered-rate
    /// immune to return-path jitter/reordering — see [`ack_delivery`].
    probe_sent_at: Instant,
}

/// Coarse absurd-value backstop for a single leg's measured delivered rate,
/// bits/sec. No real bonded leg (cellular / satellite / ethernet) delivers
/// above this over a keepalive window, so a higher figure is a measurement
/// artifact, not headroom to probe into. Defence-in-depth on top of the
/// send-clock differencing in [`ack_delivery`]: it caps what feeds the
/// scheduler's capacity evidence bound (`delivery × probe_cap_mult`) so a
/// stray sample can never switch congestion control off.
const MAX_PLAUSIBLE_LEG_BPS: f64 = 10_000_000_000.0;

/// Windowed loss fraction + delivered bitrate from two successive
/// keepalive-acks on ONE path.
///
/// Both quantities are differenced on the probe **send** clock
/// (`probe_sent_at`): the numerator (`bytes_received` delta) is measured at
/// the receiver when it saw each probe, and the matching denominator is the
/// send-time gap between those probes — the two stay on the same monotonic
/// clock regardless of when the acks came back. Using the ack *arrival* delta
/// instead (the original bug) let a reordered/late ack pair a near-zero
/// denominator with a full window of bytes and report a multi-Gbps delivered
/// rate; that lifted the scheduler's capacity evidence bound
/// (`delivery × probe_cap_mult`) to garbage and disabled congestion control
/// during exactly the loss storm it needed to throttle.
///
/// Returns `None` for a non-advancing ack (`cur` not strictly newer than
/// `prev` — an out-of-order or duplicate ack): its receiver counters are a
/// stale snapshot that must neither fabricate a rate nor regress the baseline.
fn ack_delivery(prev: &AckSample, cur: &AckSample) -> Option<(f32, u64)> {
    if cur.probe_sent_at <= prev.probe_sent_at {
        return None;
    }
    let dt = cur
        .probe_sent_at
        .duration_since(prev.probe_sent_at)
        .as_secs_f64();
    let sent_d = cur.sent.saturating_sub(prev.sent);
    let recv_d = cur.received.saturating_sub(prev.received);
    let bytes_d = cur.bytes_received.saturating_sub(prev.bytes_received);
    let loss = if sent_d > 0 {
        (sent_d.saturating_sub(recv_d) as f32 / sent_d as f32).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let bps = if dt > 1e-6 {
        ((bytes_d as f64 * 8.0 / dt).min(MAX_PLAUSIBLE_LEG_BPS)) as u64
    } else {
        0
    };
    Some((loss, bps))
}

/// Handle retained by `BondSocket::sender`.
pub(crate) struct SenderHandle {
    pub tx: mpsc::Sender<OutboundMessage>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_sender<S>(
    flow_id: u32,
    mut paths: Vec<Path>,
    scheduler: S,
    conn_stats: Arc<BondConnStats>,
    path_stats: Vec<Arc<PathStats>>,
    path_names: Vec<String>,
    keepalive_interval: Duration,
    keepalive_miss_threshold: u32,
    retransmit_capacity: usize,
    fec: Option<FecParams>,
    per_path_fec: std::collections::HashMap<PathId, PerLegFecKind>,
    equalization: crate::config::EqualizationMode,
    align_suppress: bool,
    events_tx: broadcast::Sender<PathEvent>,
    cancel: CancellationToken,
) -> (SenderHandle, JoinHandle<()>)
where
    S: BondScheduler + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<OutboundMessage>(512);

    // Nonzero random epoch identifying THIS sender instance, carried on
    // every keepalive. A receiver anchored to a previous instance's seq
    // space detects the change and re-anchors instead of dropping every
    // packet of the new instance as stale.
    let session_epoch = random_session_epoch();

    // Lift per-path rx channels out of the paths so we can multiplex
    // them through a single mpsc into the sender loop. Control
    // messages (acks, NACKs) land here and never block the hot send
    // path.
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<(PathId, PathDatagram)>(512);
    for p in paths.iter_mut() {
        let path_id = p.id();
        let Some(mut path_rx) = p.take_rx() else {
            continue;
        };
        let ctrl_tx = ctrl_tx.clone();
        tokio::spawn(async move {
            while let Some(dg) = path_rx.recv().await {
                if ctrl_tx.send((path_id, dg)).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(ctrl_tx);

    let join = tokio::spawn(async move {
        if let Err(e) = sender_loop(
            flow_id,
            session_epoch,
            paths,
            scheduler,
            conn_stats,
            path_stats,
            path_names,
            keepalive_interval,
            keepalive_miss_threshold,
            retransmit_capacity,
            fec,
            per_path_fec,
            equalization,
            align_suppress,
            events_tx,
            rx,
            ctrl_rx,
            cancel,
        )
        .await
        {
            log::error!("bond sender loop exited: {e}");
        }
    });

    (SenderHandle { tx }, join)
}

#[allow(clippy::too_many_arguments)]
async fn sender_loop<S>(
    flow_id: u32,
    session_epoch: u32,
    paths: Vec<Path>,
    mut scheduler: S,
    conn_stats: Arc<BondConnStats>,
    path_stats: Vec<Arc<PathStats>>,
    path_names: Vec<String>,
    keepalive_interval: Duration,
    keepalive_miss_threshold: u32,
    retransmit_capacity: usize,
    fec: Option<FecParams>,
    per_path_fec: std::collections::HashMap<PathId, PerLegFecKind>,
    equalization: crate::config::EqualizationMode,
    align_suppress: bool,
    events_tx: broadcast::Sender<PathEvent>,
    mut app_rx: mpsc::Receiver<OutboundMessage>,
    mut ctrl_rx: mpsc::Receiver<(PathId, PathDatagram)>,
    cancel: CancellationToken,
) -> anyhow::Result<()>
where
    S: BondScheduler,
{
    let mut retx_buf = RetransmitBuffer::new(retransmit_capacity);
    let mut next_seq: u32 = 0;
    let mut frame_scratch = BytesMut::with_capacity(1600);
    let mut ctrl_scratch = BytesMut::with_capacity(128);
    // Proactive FEC encoder (opt-in). Emits XOR repair packets at column
    // completion; repairs ride FEC-flagged bond datagrams and do not
    // consume media bond_seq space.
    let mut fec_encoder: Option<FecEncoder> = fec.map(FecEncoder::new);
    let mut fec_payload = BytesMut::with_capacity(1600);
    let mut fec_frame = BytesMut::with_capacity(1700);

    // Per-leg FEC (mutually exclusive with combined `fec`): one encoder per
    // FEC-enabled leg, index-aligned to `paths`. A non-empty map selects
    // per-leg mode and the combined encoder is left idle. Each leg's encoder
    // protects only the packets that leg carries, so a leg burst is
    // recovered locally before it reaches the combined reassembler.
    let per_leg_mode = !per_path_fec.is_empty();
    let mut per_leg_encoders: Vec<Option<LegEnc>> = paths
        .iter()
        .map(|p| {
            per_path_fec.get(&p.id()).map(|kind| match kind {
                PerLegFecKind::Xor(prm) => LegEnc::Xor(PerLegFecEncoder::new(*prm)),
                PerLegFecKind::ReedSolomon { data, parity, parity_max } => {
                    LegEnc::Rs(PerLegRsEncoder::new_adaptive(*data, *parity, *parity_max))
                }
            })
        })
        .collect();

    let mut ka_interval = tokio::time::interval(keepalive_interval);
    // Skip (not Burst) missed keepalive ticks: if the sender task stalls
    // across one or more intervals (runtime starvation under a loss storm),
    // the default Burst would fire the backlog back-to-back, emitting probes
    // whose `probe_sent_at` stamps are only microseconds apart. `ack_delivery`
    // would then divide a full interval of forward-delayed receiver bytes by
    // that sub-ms send gap and fabricate a multi-Gbps delivered rate — the
    // same capacity-estimate blowup the send-clock differencing exists to
    // prevent, just via coalesced sends instead of return-path reorder. Skip
    // fires a single probe after a stall and resumes on cadence, so
    // consecutive `probe_sent_at` gaps stay ~`keepalive_interval`.
    ka_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Track in-flight keepalive stamps per path for RTT computation.
    // Per-path keepalive RTT tracking. On paths where `path_rtt >
    // keepalive_interval` there are multiple KAs in flight at any
    // moment, so we must match acks by stamp instead of storing a
    // single "last-sent" slot. The deque is bounded to
    // `MAX_OUTSTANDING_KA` so a chronically silent path can't grow
    // its pending set without bound.
    const MAX_OUTSTANDING_KA: usize = 16;
    let mut pending_ka: Vec<std::collections::VecDeque<(u64, Instant)>> =
        (0..paths.len())
            .map(|_| std::collections::VecDeque::with_capacity(MAX_OUTSTANDING_KA))
            .collect();
    // Track per-path sent packets so keepalive body can advertise it.
    let mut path_sent_counter: Vec<u64> = vec![0; paths.len()];
    // Previous ack sample per path for windowed loss + delivered-rate.
    let mut last_ack: Vec<Option<AckSample>> = vec![None; paths.len()];

    let path_index_by_id = |id: PathId| -> Option<usize> { paths.iter().position(|p| p.id() == id) };
    let path_stats_for = |idx: usize| -> Option<&Arc<PathStats>> { path_stats.get(idx) };

    // Liveness monitor — fires a KA timeout once no ack has been seen
    // for `keepalive_miss_threshold * keepalive_interval`. A keepalive
    // ack on any path counts as that path's activity.
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

    // Fires at the liveness-timeout cadence so timeouts are detected
    // with a bounded latency even during a quiet period where no app
    // traffic is flowing.
    let mut liveness_tick = tokio::time::interval(liveness_timeout);
    liveness_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Swallow the immediate first tick; it fires at t=0.
    liveness_tick.tick().await;

    // Whether the control-rx multiplex still has live senders. An
    // all-send-only bond (e.g. every leg is a RIST *sender* path, which
    // cannot carry a bond back-channel) has no control paths at all, so
    // `ctrl_rx` closes immediately. That is NOT a shutdown condition —
    // we disable the branch and keep pushing data, relying on RIST's own
    // per-leg ARQ. Shutdown is driven by `app_rx` close or `cancel`.
    let mut ctrl_open = true;

    // Per-path edge-trigger so a QUIC leg's background re-dial surfaces ONE
    // `PathReconnecting{reason}` event per down-episode (not one per retry).
    let mut was_reconnecting: std::collections::HashMap<PathId, bool> =
        std::collections::HashMap::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                log::info!("bond sender: shutdown");
                return Ok(());
            }

            // Outbound app data
            maybe_msg = app_rx.recv() => {
                let Some(msg) = maybe_msg else {
                    log::info!("bond sender: app channel closed");
                    return Ok(());
                };
                let selection = scheduler.schedule(&PacketHints {
                    size: msg.data.len(),
                    ..msg.hints
                });
                // Capture which leg(s) this packet rides so per-leg FEC can
                // protect each leg's own stream (borrow ends before the
                // by-value match below moves `selection`).
                let sel_legs: Vec<PathId> = match &selection {
                    PathSelection::Single(p) => vec![*p],
                    PathSelection::Duplicate(v) => v.clone(),
                    PathSelection::Drop => Vec::new(),
                };
                // bond_seq is assigned only AFTER a non-Drop selection.
                // A dropped packet must consume no seq: the keepalive
                // tip advertises `next_seq - 1`, and a consumed-but-
                // never-sent seq makes the receiver NACK a packet that
                // never existed (up to max_nack_retries), then count it
                // lost after a full hold-time.
                // One emit-timestamp per message (shared by all copies of a
                // duplicate so each leg measures its own OWD against the same
                // send instant). `None` unless equalization measures (Auto/On)
                // → v1 header, no wire change. send_on_path additionally gates
                // the actual stamp on the per-leg receiver having advertised v2.
                let send_stamp = equalization
                    .measures()
                    .then(|| Instant::now().elapsed_since_boot_us() as u32);
                let sent_seq = match selection {
                    PathSelection::Drop => {
                        conn_stats.packets_dropped_no_path.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                    PathSelection::Single(path_id) => {
                        let seq = next_seq;
                        next_seq = next_seq.wrapping_add(1);
                        let rebuilt = send_on_path(
                            flow_id, seq, path_id, msg.hints.priority, msg.hints.marker, false,
                            send_stamp, &msg.data, &paths, &path_stats, &mut frame_scratch,
                            &conn_stats, &mut path_sent_counter,
                        ).await;
                        if rebuilt {
                            note_send_error_rebuild(&events_tx, &paths, &path_names, &path_stats, path_id);
                        }
                        retx_buf.insert(seq, frame_scratch.clone().freeze());
                        Some(seq)
                    }
                    PathSelection::Duplicate(path_ids) => {
                        // One seq shared by every copy — the receiver
                        // dedups on it.
                        let seq = next_seq;
                        next_seq = next_seq.wrapping_add(1);
                        let mut first = true;
                        for pid in &path_ids {
                            let duplicated = !first;
                            let rebuilt = send_on_path(
                                flow_id, seq, *pid, msg.hints.priority, msg.hints.marker, duplicated,
                                send_stamp, &msg.data, &paths, &path_stats, &mut frame_scratch,
                                &conn_stats, &mut path_sent_counter,
                            ).await;
                            if rebuilt {
                                note_send_error_rebuild(&events_tx, &paths, &path_names, &path_stats, *pid);
                            }
                            if duplicated {
                                conn_stats.packets_duplicated.fetch_add(1, Ordering::Relaxed);
                            }
                            first = false;
                        }
                        // Stash the *primary* copy for retransmit.
                        retx_buf.insert(seq, frame_scratch.clone().freeze());
                        Some(seq)
                    }
                };

                // Proactive FEC. Per-leg mode protects each leg's own wire
                // stream — a repair rides the SAME leg it protects, so a leg's
                // FEC is self-contained and a leg burst recovers locally
                // before it reaches the combined reassembler. Combined mode
                // protects the global striped stream (legacy). Mutually
                // exclusive; per-leg takes precedence. Repairs ride
                // FEC-flagged datagrams and consume no media bond_seq.
                if let Some(seq) = sent_seq {
                    if per_leg_mode {
                        for &pid in &sel_legs {
                            let Some(idx) = path_index_by_id(pid) else { continue };
                            // XOR emits ≤1 repair per packet (column fill); RS
                            // emits `parity` repairs when a block fills. Each
                            // rides the SAME leg it protects. bond_seq is
                            // informational on a FEC datagram — the receiver
                            // routes by the flag + the repair's own seq list.
                            match per_leg_encoders[idx].as_mut() {
                                Some(LegEnc::Xor(enc)) => {
                                    if let Some(rep) = enc.push(seq, &msg.data) {
                                        rep.serialize(&mut fec_payload);
                                        send_fec_frame(
                                            flow_id, seq, pid, idx, &fec_payload,
                                            &mut fec_frame, &paths, &path_stats,
                                        )
                                        .await;
                                        // Charge the parity against the leg it
                                        // rides so the controller sees it as
                                        // offered load (else it over-commits
                                        // media on top of invisible FEC).
                                        scheduler.charge_path(pid, fec_payload.len());
                                    }
                                }
                                Some(LegEnc::Rs(enc)) => {
                                    for rep in enc.push(seq, &msg.data) {
                                        rep.serialize(&mut fec_payload);
                                        send_fec_frame(
                                            flow_id, seq, pid, idx, &fec_payload,
                                            &mut fec_frame, &paths, &path_stats,
                                        )
                                        .await;
                                        scheduler.charge_path(pid, fec_payload.len());
                                    }
                                }
                                None => {}
                            }
                        }
                    } else if let Some(enc) = fec_encoder.as_mut() {
                        for rep in enc.push(seq, &msg.data) {
                            rep.serialize(&mut fec_payload);
                            let sel = scheduler.schedule(&PacketHints {
                                size: fec_payload.len(),
                                ..Default::default()
                            });
                            let pid = match sel {
                                PathSelection::Single(p) => Some(p),
                                PathSelection::Duplicate(v) => v.first().copied(),
                                PathSelection::Drop => None,
                            };
                            if let Some(pid) = pid {
                                if let Some(pos) = path_index_by_id(pid) {
                                    let mut header = BondHeader::new(
                                        flow_id, rep.base_seq, pid, Priority::Normal,
                                    );
                                    header.set_fec();
                                    write_packet(&header, &fec_payload, &mut fec_frame);
                                    if let Some(path) = paths.get(pos) {
                                        // FEC bytes are NOT counted in the
                                        // per-path media byte counter — that
                                        // would read as loss to the controller
                                        // (sent > delivered) and trigger false
                                        // backoff. The token-bucket deduction
                                        // above already charges FEC bandwidth.
                                        let _ = match path.primary_peer() {
                                            Some(peer) => path.send_to(&fec_frame, peer).await,
                                            None => path.send(&fec_frame).await,
                                        };
                                        // Surface the repair as redundancy
                                        // overhead: fec_bytes_sent (separate from
                                        // the media counter / controller) and the
                                        // leg's true-wire total.
                                        if let Some(ps) = path_stats.get(pos) {
                                            let wire = (fec_frame.len()
                                                + path.wire_overhead_per_datagram())
                                                as u64;
                                            ps.fec_bytes_sent.fetch_add(wire, Ordering::Relaxed);
                                            ps.wire_bytes_sent.fetch_add(wire, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Control messages arriving on any path (keepalive acks, NACKs).
            // Once the control channel has no live senders we disable this
            // branch rather than exit — see `ctrl_open` above. A bond with
            // no rx-bearing leg (all-RIST / all-send-only) must still push
            // data; real shutdown comes from `app_rx` close or `cancel`.
            maybe_ctrl = ctrl_rx.recv(), if ctrl_open => {
                let Some((path_id, dg)) = maybe_ctrl else {
                    log::debug!("bond sender: control rx closed (no rx-bearing legs); disabling branch");
                    ctrl_open = false;
                    continue;
                };
                if !is_control(&dg.data) {
                    // The sender side shouldn't normally receive data
                    // datagrams, but ignore gracefully if a peer mis-routes.
                    continue;
                }
                match CtrlPacket::parse(&dg.data) {
                    Ok(CtrlPacket::KeepaliveAck { body, .. }) => {
                        if let Some(idx) = path_index_by_id(path_id) {
                            // Match by stamp — find and remove the
                            // in-flight entry with the same stamp.
                            // Out-of-order / late acks still count;
                            // this is what makes RTT estimation work
                            // on paths where keepalive_interval is
                            // shorter than RTT.
                            let matched = pending_ka[idx]
                                .iter()
                                .position(|(s, _)| *s == body.stamp_us)
                                .and_then(|p| pending_ka[idx].remove(p));
                            if let Some((stamp, sent_at)) = matched {
                                if body.stamp_us == stamp {
                                    let now = Instant::now();
                                    let rtt = sent_at.elapsed();

                                    // Windowed loss + delivered bitrate:
                                    // diff this ack against the previous one
                                    // for THIS path, on the probe SEND clock
                                    // (`sent_at`, matched from `pending_ka`).
                                    // Lifetime ratios dilute bursts and never
                                    // drive a congestion controller usefully;
                                    // the ack ARRIVAL clock fabricates rates
                                    // under return-path jitter — see
                                    // [`ack_delivery`].
                                    let cur = AckSample {
                                        sent: body.packets_sent_on_path,
                                        received: body.packets_received_on_path,
                                        bytes_received: body.bytes_received_on_path,
                                        probe_sent_at: sent_at,
                                    };
                                    // `None` = an out-of-order / duplicate ack
                                    // (still counted for RTT + liveness below,
                                    // but its stale receiver snapshot must not
                                    // regress the baseline or feed a bogus
                                    // rate). First ack has no prior → 0/0.
                                    let measurement = match &last_ack[idx] {
                                        Some(prev) => ack_delivery(prev, &cur),
                                        None => Some((0.0, 0)),
                                    };
                                    if measurement.is_some() {
                                        last_ack[idx] = Some(cur);
                                    }

                                    // RTT, peer version + keepalive count are
                                    // per-probe and order-independent → always
                                    // record. Loss / throughput / jitter only
                                    // advance on a fresh (newer) measurement.
                                    if let Some(ps) = path_stats_for(idx) {
                                        ps.rtt_us.store(rtt.as_micros() as u64, Ordering::Relaxed);
                                        // v5 negotiation: record the receiver's
                                        // advertised data-header version for this
                                        // leg. send_on_path gates v2 (send-stamped)
                                        // headers on this being >= v2, so we never
                                        // brick a pre-v2 / equalization-off receiver.
                                        ps.peer_protocol_version.store(
                                            body.recv_protocol_version as u64,
                                            Ordering::Relaxed,
                                        );
                                        ps.keepalives_received.fetch_add(1, Ordering::Relaxed);
                                        if let Some((loss_rate, delivery_bps)) = measurement {
                                            ps.loss_ppm.store(
                                                (loss_rate * 1_000_000.0) as u64,
                                                Ordering::Relaxed,
                                            );
                                            ps.throughput_bps
                                                .store(delivery_bps, Ordering::Relaxed);
                                            ps.jitter_us
                                                .store(body.jitter_us as u64, Ordering::Relaxed);
                                        }
                                    }

                                    // Feed the scheduler a full health snapshot
                                    // only on a fresh measurement — an
                                    // out-of-order ack carries a stale delivered
                                    // rate that would disturb the windowed
                                    // capacity control.
                                    if let Some((loss_rate, delivery_bps)) = measurement {
                                        let health = PathHealth {
                                            rtt: Some(rtt),
                                            loss_rate,
                                            throughput_bps: delivery_bps,
                                            jitter_us: body.jitter_us as u64,
                                            queue_depth: 0,
                                            // v4 keepalive-ack: this leg's
                                            // receiver-measured relative one-way
                                            // delay, for the equalization
                                            // budget-demote (u32::MAX on an older
                                            // peer → demote stays jitter-only).
                                            relative_owd_us: body.relative_owd_us,
                                        };
                                        scheduler.on_path_update(path_id, &health);
                                        // Publish the discovered aggregate capacity
                                        // (sum of alive legs) so operators can read
                                        // the bond's currently-usable bitrate and
                                        // provision a fixed external encoder under it.
                                        conn_stats.aggregate_capacity_bps.store(
                                            scheduler.aggregate_capacity_bps(),
                                            Ordering::Relaxed,
                                        );
                                        // Adaptive per-leg RS: scale this leg's
                                        // parity with its measured loss.
                                        if let Some(Some(LegEnc::Rs(enc))) =
                                            per_leg_encoders.get_mut(idx)
                                        {
                                            enc.set_loss(loss_rate);
                                        }
                                    }
                                    // Liveness: a fresh ack revives this
                                    // path if it was dead. Also tell the
                                    // scheduler so weights restore.
                                    for ev in monitor.record_activity(path_id, now) {
                                        if matches!(ev.kind, PathEventKind::PathAlive { .. }) {
                                            scheduler.on_path_alive(path_id);
                                        }
                                        let _ = events_tx.send(ev);
                                    }
                                }
                            }
                        }
                    }
                    Ok(CtrlPacket::Nack { body, .. }) => {
                        let now = Instant::now();
                        for lost_seq in &body.missing {
                            // Dedup: receivers re-NACK on their retry
                            // cadence and duplicate seqs can land in a
                            // burst — one resend per seq per
                            // RETRANSMIT_DEDUP window.
                            if let Some(pkt) = retx_buf.get_for_retransmit(*lost_seq, now).cloned() {
                                // Charge the retransmit's REAL size against the
                                // token bucket. With the default `size: 0` the
                                // scheduler debited only TOKEN_OVERHEAD_BYTES, so
                                // ARQ bandwidth was ~uncounted against discovered
                                // capacity — under congestion that turns NACK
                                // storms into self-amplifying load on the very
                                // leg that's already dropping.
                                let selection = scheduler.schedule(&PacketHints {
                                    priority: Priority::High,
                                    size: pkt.len(),
                                    ..Default::default()
                                });
                                let pid = match selection {
                                    PathSelection::Single(p) => Some(p),
                                    PathSelection::Duplicate(v) => v.first().copied(),
                                    PathSelection::Drop => None,
                                };
                                if let Some(pid) = pid {
                                    if let Some(pos) = path_index_by_id(pid) {
                                        // Flip the RETRANSMIT flag and rewrite the
                                        // path_id byte so the receiver credits the
                                        // retransmit to the new path.
                                        let mut retx = BytesMut::from(&pkt[..]);
                                        // Byte 1: ver(high4) | flags(low4).
                                        // Set RETRANSMIT in the low nibble.
                                        retx[1] |= bonding_protocol::packet::flags::RETRANSMIT;
                                        // Byte 2: path_id.
                                        retx[2] = pid;
                                        if let Some(path) = paths.get(pos) {
                                            let _ = path.send(&retx).await;
                                            if let Some(ps) = path_stats_for(pos) {
                                                ps.retransmits_sent.fetch_add(1, Ordering::Relaxed);
                                                ps.bytes_sent
                                                    .fetch_add(retx.len() as u64, Ordering::Relaxed);
                                                // Retransmits ride the media counter
                                                // (recovery, not pure overhead) but still
                                                // add to the leg's true wire total.
                                                ps.wire_bytes_sent.fetch_add(
                                                    (retx.len()
                                                        + path.wire_overhead_per_datagram())
                                                        as u64,
                                                    Ordering::Relaxed,
                                                );
                                            }
                                            conn_stats
                                                .packets_retransmitted
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(idx) = path_index_by_id(path_id) {
                            if let Some(ps) = path_stats_for(idx) {
                                ps.nacks_received
                                    .fetch_add(body.missing.len() as u64, Ordering::Relaxed);
                            }
                        }
                    }
                    Ok(_) | Err(_) => { /* ignore goodbye + parse errors */ }
                }
            }

            // Periodic liveness sweep — flip paths to dead after
            // `keepalive_miss_threshold` intervals with no ack and
            // emit both the per-path PathDead and any bond
            // aggregate transition (Degraded / Down).
            _ = liveness_tick.tick() => {
                for ev in monitor.check_timeouts(Instant::now(), PathDeadReason::KeepaliveTimeout) {
                    if let PathEventKind::PathDead { .. } = &ev.kind {
                        scheduler.on_path_dead(ev.path_id);
                    }
                    let _ = events_tx.send(ev);
                }
                // Surface QUIC self-redial: one PathReconnecting{reason} per
                // down-episode so operators see WHY a leg won't come up (e.g.
                // "handshake timed out"), beyond the generic PathDead.
                for p in paths.iter() {
                    let id = p.id();
                    match p.reconnect_reason() {
                        Some(reason) => {
                            if !was_reconnecting.get(&id).copied().unwrap_or(false) {
                                was_reconnecting.insert(id, true);
                                let _ = events_tx.send(PathEvent {
                                    path_id: id,
                                    path_name: p.name().to_string(),
                                    kind: PathEventKind::PathReconnecting { reason },
                                });
                            }
                        }
                        None => {
                            was_reconnecting.insert(id, false);
                        }
                    }
                }
            }

            // Periodic keepalives
            _ = ka_interval.tick() => {
                let now = Instant::now();
                // Keep capacity estimates / token buckets fresh during a
                // quiet period when no app packets are driving schedule().
                scheduler.on_tick(now);
                let stamp = (now.elapsed_since_boot_us()) as u64;
                // `next_seq` is the NEXT seq we'd assign; the highest
                // already-sent is `next_seq - 1`. If nothing has been
                // sent yet, advertise 0 (receiver ignores a tip
                // that's below its own highest).
                let highest = next_seq.wrapping_sub(1);
                for (idx, path) in paths.iter().enumerate() {
                    let peer = match path.primary_peer() {
                        Some(p) => p,
                        None => continue,
                    };
                    let header = CtrlHeader::new(CtrlType::Keepalive, path.id(), flow_id);
                    let body = KeepaliveBody {
                        stamp_us: stamp,
                        packets_sent_on_path: path_sent_counter[idx],
                        highest_bond_seq_sent: highest,
                        bytes_sent_on_path: path_stats
                            .get(idx)
                            .map(|ps| ps.bytes_sent.load(Ordering::Relaxed))
                            .unwrap_or(0),
                        session_epoch,
                        // Ride-fastest (duplicate-all) → tell the receiver to
                        // suppress per-leg alignment. Computed at spawn from the
                        // redundancy policy.
                        mode_flags: if align_suppress {
                            bonding_protocol::control::KA_FLAG_ALIGN_SUPPRESS
                        } else {
                            0
                        },
                    };
                    let pkt = CtrlPacket::Keepalive { header, body };
                    pkt.serialize(&mut ctrl_scratch);
                    match path.send_to(&ctrl_scratch, peer).await {
                        Ok(()) => {
                            path.note_send_ok();
                            // Record the in-flight KA. Cap the deque so
                            // a dead path can't grow its pending set
                            // forever — drop the oldest when full.
                            if pending_ka[idx].len() >= MAX_OUTSTANDING_KA {
                                pending_ka[idx].pop_front();
                            }
                            pending_ka[idx].push_back((stamp, now));
                            if let Some(ps) = path_stats_for(idx) {
                                ps.keepalives_sent.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        // Keepalives keep probing during quiet periods,
                        // so route/device errors trip the rebuild even
                        // with no app traffic flowing.
                        Err(e) => {
                            if path.note_send_error(&e) {
                                note_send_error_rebuild(
                                    &events_tx, &paths, &path_names, &path_stats, path.id(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Send one per-leg FEC repair on a specific leg. FEC bytes are NOT counted
/// in the per-path media byte counter (that would read as loss to the
/// congestion controller and trigger false backoff).
#[allow(clippy::too_many_arguments)]
async fn send_fec_frame(
    flow_id: u32,
    seq: u32,
    pid: PathId,
    idx: usize,
    payload: &[u8],
    frame: &mut BytesMut,
    paths: &[Path],
    path_stats: &[Arc<PathStats>],
) {
    let mut header = BondHeader::new(flow_id, seq, pid, Priority::Normal);
    header.set_fec();
    write_packet(&header, payload, frame);
    if let Some(path) = paths.get(idx) {
        let _ = match path.primary_peer() {
            Some(peer) => path.send_to(frame, peer).await,
            None => path.send(frame).await,
        };
        // Redundancy-overhead telemetry only — never folded into the
        // media `bytes_sent` counter the controller differences.
        if let Some(ps) = path_stats.get(idx) {
            let wire = (frame.len() + path.wire_overhead_per_datagram()) as u64;
            ps.fec_bytes_sent.fetch_add(wire, Ordering::Relaxed);
            ps.wire_bytes_sent.fetch_add(wire, Ordering::Relaxed);
        }
    }
}

/// Small helper — write a bond data packet and dispatch on the chosen
/// path. Updates per-path + aggregate counters. Leaves the frame in
/// `frame_scratch` so callers that want to stash in the retransmit
/// buffer can `.freeze()` it. Returns `true` when the send error run
/// just triggered a socket rebuild (caller emits the event).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn send_on_path(
    flow_id: u32,
    bond_seq: u32,
    path_id: PathId,
    priority: Priority,
    marker: bool,
    duplicated: bool,
    send_stamp_us: Option<u32>,
    payload: &[u8],
    paths: &[Path],
    path_stats: &[Arc<PathStats>],
    frame_scratch: &mut BytesMut,
    conn_stats: &Arc<BondConnStats>,
    path_sent_counter: &mut [u64],
) -> bool {
    let Some(idx) = paths.iter().position(|p| p.id() == path_id) else {
        return false;
    };
    let mut header = BondHeader::new(flow_id, bond_seq, path_id, priority);
    if marker {
        header.set_marker();
    }
    if duplicated {
        header.set_duplicated();
    }
    // Per-leg equalization: a v2 header carries the sender's monotonic emit
    // time so the receiver can derive this leg's relative one-way delay.
    // GATE on negotiation — only stamp (emit v2) once this leg's receiver has
    // advertised v2 capability in a keepalive-ack. A pre-v2 / equalization-off
    // receiver advertises v1 (or nothing → defaults to v1), so we keep emitting
    // 12-byte v1 headers it can parse and never silently blackhole its media.
    if let Some(stamp) = send_stamp_us {
        let peer_v2 = path_stats
            .get(idx)
            .map(|ps| {
                ps.peer_protocol_version.load(Ordering::Relaxed)
                    >= bonding_protocol::packet::PROTOCOL_VERSION_V2 as u64
            })
            .unwrap_or(false);
        if peer_v2 {
            header.set_send_stamp(stamp);
        }
    }
    write_packet(&header, payload, frame_scratch);

    let path = &paths[idx];
    let peer = path.primary_peer();
    let send_result = match peer {
        Some(p) => path.send_to(frame_scratch, p).await,
        None => path.send(frame_scratch).await,
    };
    match &send_result {
        Ok(()) => {
            path.note_send_ok();
            conn_stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            conn_stats
                .bytes_sent
                .fetch_add(frame_scratch.len() as u64, Ordering::Relaxed);
            if let Some(ps) = path_stats.get(idx) {
                ps.packets_sent.fetch_add(1, Ordering::Relaxed);
                ps.bytes_sent
                    .fetch_add(frame_scratch.len() as u64, Ordering::Relaxed);
                // True wire bytes: the media frame plus the AEAD envelope
                // an encrypted leg adds after the media counter is taken.
                ps.wire_bytes_sent.fetch_add(
                    (frame_scratch.len() + path.wire_overhead_per_datagram()) as u64,
                    Ordering::Relaxed,
                );
            }
            path_sent_counter[idx] = path_sent_counter[idx].wrapping_add(1);
            false
        }
        // Route/device errors accumulate toward a UDP socket rebuild
        // (interface-churn recovery, see path/udp.rs).
        Err(e) => path.note_send_error(e),
    }
}

/// Bookkeeping for a send-error-triggered socket rebuild: mirror the
/// rebuild into `PathStats`, refresh the (possibly changed) pin code,
/// and broadcast `PathRebuilt`. The rebuild itself already happened
/// inside `note_send_error`. A sender-leg rebuild takes a fresh
/// ephemeral source port; the receiver re-learns the return address
/// from the next control packet it sees.
fn note_send_error_rebuild(
    events_tx: &broadcast::Sender<PathEvent>,
    paths: &[Path],
    path_names: &[String],
    path_stats: &[Arc<PathStats>],
    path_id: PathId,
) {
    let Some(idx) = paths.iter().position(|p| p.id() == path_id) else {
        return;
    };
    let mut already_dead = false;
    if let Some(ps) = path_stats.get(idx) {
        ps.rebuilds.fetch_add(1, Ordering::Relaxed);
        let code = paths[idx]
            .pin_mechanism()
            .map(|m| m.stats_code())
            .unwrap_or(bonding_protocol::stats::PIN_NONE);
        ps.pin_mechanism.store(code, Ordering::Relaxed);
        already_dead = ps.dead.load(Ordering::Relaxed) != 0;
    }
    // A path already declared dead is still keepalive-probed, so a
    // persistent route failure (downed gateway: EHOSTUNREACH survives
    // any rebuild) would otherwise emit a PathRebuilt warning per
    // backoff interval forever — PathDead/PathAlive transitions are the
    // operator's signal there. Stats above stay accurate either way.
    if already_dead {
        return;
    }
    let _ = events_tx.send(PathEvent {
        path_id,
        path_name: path_names.get(idx).cloned().unwrap_or_default(),
        kind: PathEventKind::PathRebuilt {
            reason: PathRebuildReason::SendErrors,
        },
    });
}

/// Nonzero random session epoch, fresh per sender instance. Uses
/// ring's `SystemRandom` (already in the dependency tree for the bond
/// AEAD); 0 is reserved on the wire for "no epoch" (legacy peer), so
/// retry on the 2^-32 zero draw. The fallback (OS RNG failure — not a
/// real failure mode) degrades to the std hasher's per-process random
/// seed rather than panicking on the data path's setup.
fn random_session_epoch() -> u32 {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    for _ in 0..4 {
        if rng.fill(&mut buf).is_ok() {
            let v = u32::from_le_bytes(buf);
            if v != 0 {
                return v;
            }
        }
    }
    use std::hash::{BuildHasher, Hasher};
    let h = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let v = (h ^ (h >> 32)) as u32;
    if v != 0 { v } else { 1 }
}

/// Portable "elapsed since process boot" in microseconds. Good enough
/// for an opaque keepalive stamp; the field never crosses machines.
trait ElapsedSinceBoot {
    fn elapsed_since_boot_us(&self) -> u128;
}

impl ElapsedSinceBoot for Instant {
    fn elapsed_since_boot_us(&self) -> u128 {
        // `Instant` has no Unix epoch anchor, but subtracting a
        // process-start-time reference gives a monotonic, local-only
        // value that's fine for pong matching.
        static BOOT: once_cell_sync::Lazy = once_cell_sync::Lazy::new();
        let boot = BOOT.get_or_init();
        self.saturating_duration_since(boot).as_micros()
    }
}

/// Minimal `once_cell::sync::Lazy` replacement for the single global
/// `BOOT` reference, avoiding a new top-level dependency.
mod once_cell_sync {
    use std::sync::OnceLock;
    use std::time::Instant;

    pub struct Lazy {
        inner: OnceLock<Instant>,
    }
    impl Lazy {
        pub const fn new() -> Self {
            Self {
                inner: OnceLock::new(),
            }
        }
        pub fn get_or_init(&self) -> Instant {
            *self.inner.get_or_init(Instant::now)
        }
    }
}

#[cfg(test)]
mod ack_delivery_tests {
    use super::{ack_delivery, AckSample, MAX_PLAUSIBLE_LEG_BPS};
    use std::time::{Duration, Instant};

    fn sample(sent: u64, received: u64, bytes: u64, probe_sent_at: Instant) -> AckSample {
        AckSample {
            sent,
            received,
            bytes_received: bytes,
            probe_sent_at,
        }
    }

    #[test]
    fn in_order_reports_true_rate_and_loss() {
        let t0 = Instant::now();
        // 250 kB delivered over a 200 ms send interval = 10 Mbps.
        // 20 of 200 packets lost = 10% loss.
        let prev = sample(0, 0, 0, t0);
        let cur = sample(200, 180, 250_000, t0 + Duration::from_millis(200));
        let (loss, bps) = ack_delivery(&prev, &cur).expect("newer ack yields a measurement");
        assert!((loss - 0.10).abs() < 1e-4, "loss={loss}");
        assert_eq!(bps, 10_000_000, "250000 B * 8 / 0.2 s");
    }

    #[test]
    fn out_of_order_ack_is_rejected_not_a_blowup() {
        // The bug: a late/reordered ack processed after a newer one. Its
        // receiver snapshot is OLDER (fewer bytes) and its probe was sent
        // EARLIER. On the arrival clock this paired a near-zero dt with a
        // backwards byte delta and fabricated a huge rate; on the send clock
        // it is simply not newer, so no measurement is produced.
        let t0 = Instant::now();
        let newer = sample(400, 400, 500_000, t0 + Duration::from_millis(400));
        let older = sample(200, 200, 250_000, t0 + Duration::from_millis(200));
        assert!(
            ack_delivery(&newer, &older).is_none(),
            "an ack not strictly newer than the baseline must yield no rate"
        );
        // Equal send-time (same-stamp duplicate) is also rejected.
        assert!(ack_delivery(&newer, &newer).is_none());
    }

    #[test]
    fn send_clock_denominator_ignores_return_path_jitter() {
        // Two probes sent 400 ms apart carrying 500 kB of receiver bytes =
        // 10 Mbps, REGARDLESS of how bunched their acks arrived. Under the old
        // arrival-clock code, acks arriving 5 ms apart would have computed
        // 500000*8/0.005 = 800 Mbps. The send clock pins it to the truth.
        let t0 = Instant::now();
        let prev = sample(0, 0, 0, t0);
        let cur = sample(400, 400, 500_000, t0 + Duration::from_millis(400));
        let (_, bps) = ack_delivery(&prev, &cur).unwrap();
        assert_eq!(bps, 10_000_000, "rate keys off the 400 ms SEND gap, not ack arrival");
    }

    #[test]
    fn absurd_byte_delta_is_clamped() {
        // Defence-in-depth: even a pathological byte delta over a real
        // interval cannot report a rate that would switch congestion control
        // off — it is capped at the plausible-leg ceiling.
        let t0 = Instant::now();
        let prev = sample(0, 0, 0, t0);
        let cur = sample(1, 1, u64::MAX / 16, t0 + Duration::from_millis(200));
        let (_, bps) = ack_delivery(&prev, &cur).unwrap();
        assert_eq!(bps, MAX_PLAUSIBLE_LEG_BPS as u64);
    }

    #[test]
    fn sub_microsecond_interval_yields_zero_rate() {
        let t0 = Instant::now();
        let prev = sample(0, 0, 0, t0);
        let cur = sample(10, 10, 100_000, t0 + Duration::from_nanos(500));
        let (_, bps) = ack_delivery(&prev, &cur).unwrap();
        assert_eq!(bps, 0, "an unmeasurably short interval is not trusted");
    }

    #[test]
    fn zero_sent_delta_reports_no_loss() {
        let t0 = Instant::now();
        let prev = sample(100, 90, 100_000, t0);
        let cur = sample(100, 90, 100_000, t0 + Duration::from_millis(200));
        let (loss, _) = ack_delivery(&prev, &cur).unwrap();
        assert_eq!(loss, 0.0, "no packets sent in the interval => loss undefined => 0");
    }
}
