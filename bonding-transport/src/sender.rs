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
    /// Sender-side arrival instant of this ack.
    at: Instant,
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
                            &msg.data, &paths, &path_stats, &mut frame_scratch,
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
                                &msg.data, &paths, &path_stats, &mut frame_scratch,
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
                                    // diff this ack against the previous
                                    // one for THIS path. Lifetime ratios
                                    // dilute bursts and never drive a
                                    // congestion controller usefully.
                                    let cur = AckSample {
                                        sent: body.packets_sent_on_path,
                                        received: body.packets_received_on_path,
                                        bytes_received: body.bytes_received_on_path,
                                        at: now,
                                    };
                                    let (loss_rate, delivery_bps) = match last_ack[idx] {
                                        Some(prev) => {
                                            let dt = now
                                                .saturating_duration_since(prev.at)
                                                .as_secs_f64();
                                            let sent_d = cur.sent.saturating_sub(prev.sent);
                                            let recv_d = cur.received.saturating_sub(prev.received);
                                            let bytes_d =
                                                cur.bytes_received.saturating_sub(prev.bytes_received);
                                            let loss = if sent_d > 0 {
                                                sent_d.saturating_sub(recv_d) as f32 / sent_d as f32
                                            } else {
                                                0.0
                                            };
                                            let bps = if dt > 1e-6 {
                                                (bytes_d as f64 * 8.0 / dt) as u64
                                            } else {
                                                0
                                            };
                                            (loss.clamp(0.0, 1.0), bps)
                                        }
                                        None => (0.0, 0),
                                    };
                                    last_ack[idx] = Some(cur);

                                    if let Some(ps) = path_stats_for(idx) {
                                        ps.rtt_us.store(rtt.as_micros() as u64, Ordering::Relaxed);
                                        ps.loss_ppm.store(
                                            (loss_rate * 1_000_000.0) as u64,
                                            Ordering::Relaxed,
                                        );
                                        ps.throughput_bps.store(delivery_bps, Ordering::Relaxed);
                                        ps.jitter_us
                                            .store(body.jitter_us as u64, Ordering::Relaxed);
                                        ps.keepalives_received.fetch_add(1, Ordering::Relaxed);
                                    }

                                    // Feed the scheduler a full health
                                    // snapshot — RTT, windowed loss,
                                    // delivered bitrate, jitter.
                                    let health = PathHealth {
                                        rtt: Some(rtt),
                                        loss_rate,
                                        throughput_bps: delivery_bps,
                                        jitter_us: body.jitter_us as u64,
                                        queue_depth: 0,
                                    };
                                    scheduler.on_path_update(path_id, &health);
                                    // Adaptive per-leg RS: scale this leg's
                                    // parity with its measured loss.
                                    if let Some(Some(LegEnc::Rs(enc))) =
                                        per_leg_encoders.get_mut(idx)
                                    {
                                        enc.set_loss(loss_rate);
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
                                let selection = scheduler.schedule(&PacketHints {
                                    priority: Priority::High,
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
async fn send_on_path(
    flow_id: u32,
    bond_seq: u32,
    path_id: PathId,
    priority: Priority,
    marker: bool,
    duplicated: bool,
    payload: &[u8],
    paths: &[Path],
    path_stats: &[Arc<PathStats>],
    frame_scratch: &mut BytesMut,
    conn_stats: &Arc<BondConnStats>,
    path_sent_counter: &mut [u64],
) -> bool {
    let mut header = BondHeader::new(flow_id, bond_seq, path_id, priority);
    if marker {
        header.set_marker();
    }
    if duplicated {
        header.set_duplicated();
    }
    write_packet(&header, payload, frame_scratch);

    let Some(idx) = paths.iter().position(|p| p.id() == path_id) else {
        return false;
    };
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
