//! Bond receiver task.
//!
//! Multiplexes N path RX channels into a single
//! `bonding_protocol::protocol::reassembly::ReassemblyBuffer`, drains
//! ready packets to the app, detects gaps, and NACKs them back to
//! the sender over the lowest-RTT alive path. Responds to keepalive
//! pings with pongs carrying per-path counters so the sender can
//! compute loss without extra round-trips.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use bonding_protocol::control::{
    CtrlHeader, CtrlPacket, CtrlType, KeepaliveAckBody, NackBody, is_control,
};
use bonding_protocol::packet::BondHeader;
use bonding_protocol::protocol::reassembly::{DrainItem, ReassemblyBuffer};
use bonding_protocol::protocol::scheduler::PathId;
use bonding_protocol::stats::{BondConnStats, PathStats};

use crate::path::{Path, PathDatagram};

pub(crate) struct ReceiverHandle {
    pub rx: mpsc::Receiver<Bytes>,
}

pub(crate) fn spawn_receiver(
    flow_id: u32,
    mut paths: Vec<Path>,
    hold_time: Duration,
    conn_stats: Arc<BondConnStats>,
    path_stats: Vec<Arc<PathStats>>,
    cancel: CancellationToken,
    nack_delay: Duration,
    max_nack_retries: u32,
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
            conn_stats,
            path_stats,
            app_tx,
            mux_rx,
            cancel,
            nack_delay,
            max_nack_retries,
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
}

#[allow(clippy::too_many_arguments)]
async fn receiver_loop(
    flow_id: u32,
    paths: Vec<Path>,
    hold_time: Duration,
    conn_stats: Arc<BondConnStats>,
    path_stats: Vec<Arc<PathStats>>,
    app_tx: mpsc::Sender<Bytes>,
    mut mux_rx: mpsc::Receiver<(PathId, PathDatagram)>,
    cancel: CancellationToken,
    nack_delay: Duration,
    max_nack_retries: u32,
) -> anyhow::Result<()> {
    let mut reassembly = ReassemblyBuffer::new(hold_time);

    // `bond_seq -> pending NACK state`. Grows only as gaps appear;
    // cleared on recovery or drain-as-lost.
    let mut pending_nacks: HashMap<u32, PendingNack> = HashMap::new();

    // Per-path counters for the keepalive echo response.
    let mut path_recv_counter: HashMap<PathId, u64> = HashMap::new();

    let mut drain_scratch: Vec<DrainItem> = Vec::with_capacity(64);
    let mut ctrl_scratch = BytesMut::with_capacity(512);

    // Short pump interval: drains reassembly + fires any due NACKs.
    let mut pump = tokio::time::interval(Duration::from_millis(10));

    let path_index_by_id = |id: PathId| -> Option<usize> { paths.iter().position(|p| p.id() == id) };
    let path_stats_for = |idx: usize| -> Option<&Arc<PathStats>> { path_stats.get(idx) };

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
                            let received_on_path = *path_recv_counter.get(&path_id).unwrap_or(&0);
                            let sent_on_path = body.packets_sent_on_path;
                            let ack_header =
                                CtrlHeader::new(CtrlType::KeepaliveAck, path_id, flow_id);
                            let ack_body = KeepaliveAckBody {
                                stamp_us: body.stamp_us,
                                packets_sent_on_path: sent_on_path,
                                packets_received_on_path: received_on_path,
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

                let outcome = reassembly.insert(header.bond_seq, payload, path_id, Instant::now());
                if outcome.stale {
                    conn_stats
                        .reassembly_overflow
                        .fetch_add(1, Ordering::Relaxed);
                }
                if outcome.duplicate {
                    conn_stats
                        .duplicates_received
                        .fetch_add(1, Ordering::Relaxed);
                }
                if outcome.recovered {
                    conn_stats.gaps_recovered.fetch_add(1, Ordering::Relaxed);
                    pending_nacks.remove(&header.bond_seq);
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
                        });
                    }
                }
            }

            _ = pump.tick() => {
                let now = Instant::now();
                drain_reassembly(&mut reassembly, &app_tx, &conn_stats, &mut drain_scratch, now, &mut pending_nacks).await;

                // Any NACKs due?
                let due: Vec<u32> = pending_nacks
                    .iter_mut()
                    .filter_map(|(seq, pn)| {
                        if now >= pn.next_nack_at {
                            if pn.nacks_sent >= max_nack_retries {
                                return None;
                            }
                            pn.nacks_sent += 1;
                            pn.next_nack_at = now + nack_delay;
                            Some(*seq)
                        } else {
                            None
                        }
                    })
                    .collect();

                if !due.is_empty() {
                    // Emit one NACK message per datagram, up to cap.
                    send_nacks(flow_id, &paths, &path_stats, &due, &mut ctrl_scratch).await;
                }

                // Prune retried-to-death entries so the map doesn't grow.
                pending_nacks.retain(|_, pn| pn.nacks_sent < max_nack_retries);
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

async fn send_nacks(
    flow_id: u32,
    paths: &[Path],
    path_stats: &[Arc<PathStats>],
    due: &[u32],
    scratch: &mut BytesMut,
) {
    // Pick the lowest-RTT alive path as the NACK carrier.
    let pick = paths
        .iter()
        .enumerate()
        .filter(|(i, p)| {
            p.primary_peer().is_some()
                && path_stats
                    .get(*i)
                    .map(|ps| ps.dead.load(Ordering::Relaxed) == 0)
                    .unwrap_or(true)
        })
        .min_by_key(|(i, _)| {
            path_stats
                .get(*i)
                .map(|ps| ps.rtt_us.load(Ordering::Relaxed))
                .unwrap_or(u64::MAX)
        });
    let Some((idx, path)) = pick else {
        return;
    };
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

