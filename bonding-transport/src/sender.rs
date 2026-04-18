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
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use bonding_protocol::control::{
    CtrlHeader, CtrlPacket, CtrlType, KeepaliveBody, is_control,
};
use bonding_protocol::packet::{BondHeader, Priority, write_packet};
use bonding_protocol::protocol::path_health::PathHealth;
use bonding_protocol::protocol::retransmit::RetransmitBuffer;
use bonding_protocol::protocol::scheduler::{
    BondScheduler, PacketHints, PathId, PathSelection,
};
use bonding_protocol::stats::{BondConnStats, PathStats};

use crate::path::{Path, PathDatagram};

/// App-facing outbound message.
pub(crate) struct OutboundMessage {
    pub data: Bytes,
    pub hints: PacketHints,
}

/// Handle retained by `BondSocket::sender`.
pub(crate) struct SenderHandle {
    pub tx: mpsc::Sender<OutboundMessage>,
}

pub(crate) fn spawn_sender<S>(
    flow_id: u32,
    mut paths: Vec<Path>,
    scheduler: S,
    conn_stats: Arc<BondConnStats>,
    path_stats: Vec<Arc<PathStats>>,
    keepalive_interval: Duration,
    retransmit_capacity: usize,
    cancel: CancellationToken,
) -> (SenderHandle, JoinHandle<()>)
where
    S: BondScheduler + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<OutboundMessage>(512);

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
            paths,
            scheduler,
            conn_stats,
            path_stats,
            keepalive_interval,
            retransmit_capacity,
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
    paths: Vec<Path>,
    mut scheduler: S,
    conn_stats: Arc<BondConnStats>,
    path_stats: Vec<Arc<PathStats>>,
    keepalive_interval: Duration,
    retransmit_capacity: usize,
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

    let path_index_by_id = |id: PathId| -> Option<usize> { paths.iter().position(|p| p.id() == id) };
    let path_stats_for = |idx: usize| -> Option<&Arc<PathStats>> { path_stats.get(idx) };

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
                let seq = next_seq;
                next_seq = next_seq.wrapping_add(1);

                let selection = scheduler.schedule(&PacketHints {
                    size: msg.data.len(),
                    ..msg.hints
                });
                match selection {
                    PathSelection::Drop => {
                        conn_stats.packets_dropped_no_path.fetch_add(1, Ordering::Relaxed);
                    }
                    PathSelection::Single(path_id) => {
                        send_on_path(
                            flow_id, seq, path_id, msg.hints.priority, msg.hints.marker, false,
                            &msg.data, &paths, &path_stats, &mut frame_scratch,
                            &conn_stats, &mut path_sent_counter,
                        ).await;
                        retx_buf.insert(seq, frame_scratch.clone().freeze());
                    }
                    PathSelection::Duplicate(path_ids) => {
                        let mut first = true;
                        for pid in &path_ids {
                            let duplicated = !first;
                            send_on_path(
                                flow_id, seq, *pid, msg.hints.priority, msg.hints.marker, duplicated,
                                &msg.data, &paths, &path_stats, &mut frame_scratch,
                                &conn_stats, &mut path_sent_counter,
                            ).await;
                            if duplicated {
                                conn_stats.packets_duplicated.fetch_add(1, Ordering::Relaxed);
                            }
                            first = false;
                        }
                        // Stash the *primary* copy for retransmit.
                        retx_buf.insert(seq, frame_scratch.clone().freeze());
                    }
                }
            }

            // Control messages arriving on any path (keepalive acks, NACKs)
            maybe_ctrl = ctrl_rx.recv() => {
                let Some((path_id, dg)) = maybe_ctrl else {
                    log::info!("bond sender: all path rx channels closed");
                    return Ok(());
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
                                    let rtt = sent_at.elapsed();
                                    if let Some(ps) = path_stats_for(idx) {
                                        ps.rtt_us.store(rtt.as_micros() as u64, Ordering::Relaxed);
                                        let lost = body
                                            .packets_sent_on_path
                                            .saturating_sub(body.packets_received_on_path);
                                        let loss_ppm = if body.packets_sent_on_path == 0 {
                                            0
                                        } else {
                                            ((lost as u128 * 1_000_000u128)
                                                / body.packets_sent_on_path as u128) as u64
                                        };
                                        ps.loss_ppm.store(loss_ppm, Ordering::Relaxed);
                                        ps.keepalives_received.fetch_add(1, Ordering::Relaxed);
                                    }
                                    // Feed scheduler an updated health.
                                    let health = PathHealth {
                                        rtt: Some(rtt),
                                        loss_rate: if body.packets_sent_on_path == 0 {
                                            0.0
                                        } else {
                                            (body.packets_sent_on_path
                                                .saturating_sub(body.packets_received_on_path))
                                                as f32
                                                / body.packets_sent_on_path as f32
                                        },
                                        ..Default::default()
                                    };
                                    scheduler.on_path_update(path_id, &health);
                                }
                            }
                        }
                    }
                    Ok(CtrlPacket::Nack { body, .. }) => {
                        for lost_seq in &body.missing {
                            if let Some(pkt) = retx_buf.get(*lost_seq).cloned() {
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

            // Periodic keepalives
            _ = ka_interval.tick() => {
                let now = Instant::now();
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
                    };
                    let pkt = CtrlPacket::Keepalive { header, body };
                    pkt.serialize(&mut ctrl_scratch);
                    if path.send_to(&ctrl_scratch, peer).await.is_ok() {
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
                }
            }
        }
    }
}

/// Small helper — write a bond data packet and dispatch on the chosen
/// path. Updates per-path + aggregate counters. Leaves the frame in
/// `frame_scratch` so callers that want to stash in the retransmit
/// buffer can `.freeze()` it.
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
) {
    let mut header = BondHeader::new(flow_id, bond_seq, path_id, priority);
    if marker {
        header.set_marker();
    }
    if duplicated {
        header.set_duplicated();
    }
    write_packet(&header, payload, frame_scratch);

    let Some(idx) = paths.iter().position(|p| p.id() == path_id) else {
        return;
    };
    let path = &paths[idx];
    let peer = path.primary_peer();
    let send_result = match peer {
        Some(p) => path.send_to(frame_scratch, p).await,
        None => path.send(frame_scratch).await,
    };
    if send_result.is_ok() {
        conn_stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        conn_stats
            .bytes_sent
            .fetch_add(frame_scratch.len() as u64, Ordering::Relaxed);
        if let Some(ps) = path_stats.get(idx) {
            ps.packets_sent.fetch_add(1, Ordering::Relaxed);
            ps.bytes_sent
                .fetch_add(frame_scratch.len() as u64, Ordering::Relaxed);
        }
        path_sent_counter[idx] = path_sent_counter[idx].wrapping_add(1);
    }
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
