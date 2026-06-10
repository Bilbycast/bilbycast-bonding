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
use bonding_protocol::protocol::fec::{FecDecoder, FecParams, FecRepair};
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
) -> anyhow::Result<()> {
    let mut reassembly = ReassemblyBuffer::new(hold_time);
    // Proactive FEC decoder (opt-in). Recovers a sparse loss from the
    // column's XOR repair with no NACK round-trip; recovered packets are
    // inserted into the reassembly buffer like a late path arrival.
    let mut fec_decoder: Option<FecDecoder> = fec.map(FecDecoder::new);

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
                                        pending_nacks.clear();
                                        retx_rtt = None;
                                        stale_run_start = None;
                                        stale_run_count = 0;
                                        if let Some(dec) = fec_decoder.as_mut() {
                                            dec.reset();
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
                            let ack_body = KeepaliveAckBody {
                                stamp_us: body.stamp_us,
                                packets_sent_on_path: sent_on_path,
                                packets_received_on_path: received_on_path,
                                bytes_received_on_path,
                                jitter_us,
                                session_epoch: current_epoch,
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
                    Err(_) => continue,
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
                    if let Some(dec) = fec_decoder.as_mut() {
                        if let Some(rep) = FecRepair::parse(&payload) {
                            let fnow = Instant::now();
                            for (rseq, rpayload) in dec.push_repair(rep) {
                                let o = reassembly.insert(rseq, rpayload, path_id, fnow);
                                if o.recovered {
                                    conn_stats.gaps_recovered.fetch_add(1, Ordering::Relaxed);
                                    pending_nacks.remove(&rseq);
                                    if let Some(age) = o.recovered_age {
                                        if age > hold_window_max {
                                            hold_window_max = age;
                                        }
                                    }
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
                {
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
                        .reassembly_overflow
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
                        pending_nacks.clear();
                        retx_rtt = None;
                        if let Some(dec) = fec_decoder.as_mut() {
                            dec.reset();
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
                        if age > hold_window_max {
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
                if let Some(dec) = fec_decoder.as_mut() {
                    let fnow = Instant::now();
                    for (rseq, rpayload) in dec.push_source(header.bond_seq, &payload) {
                        let o = reassembly.insert(rseq, rpayload, path_id, fnow);
                        if o.recovered {
                            conn_stats.gaps_recovered.fetch_add(1, Ordering::Relaxed);
                            pending_nacks.remove(&rseq);
                            if let Some(age) = o.recovered_age {
                                if age > hold_window_max {
                                    hold_window_max = age;
                                }
                            }
                        }
                    }
                }
            }

            _ = liveness_tick.tick() => {
                for ev in monitor.check_timeouts(Instant::now(), PathDeadReason::ReceiveTimeout) {
                    let _ = events_tx.send(ev);
                }
            }

            _ = pump.tick() => {
                let now = Instant::now();
                drain_reassembly(&mut reassembly, &app_tx, &conn_stats, &mut drain_scratch, now, &mut pending_nacks).await;

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
                // so latency drops back as the links calm.
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
        }
    }
}

async fn drain_reassembly(
    reassembly: &mut ReassemblyBuffer,
    app_tx: &mpsc::Sender<Bytes>,
    conn_stats: &Arc<BondConnStats>,
    scratch: &mut Vec<DrainItem>,
    now: Instant,
    pending_nacks: &mut HashMap<u32, PendingNack>,
) {
    scratch.clear();
    reassembly.drain_ready(now, scratch);
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

