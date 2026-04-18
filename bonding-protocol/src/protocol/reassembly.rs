//! Receiver-side reassembly / jitter buffer, keyed on the 32-bit
//! `bond_seq`.
//!
//! Packets arrive from N paths with interleaved ordering. The
//! reassembly buffer sorts them back into strict bond-sequence order,
//! holds each arrival for `hold_time` so slightly-late path arrivals
//! still land in order, and ages gaps out as lost when no path
//! delivered them in time.
//!
//! Shares the flat-ring design of `rist_protocol::protocol::reorder`
//! but with:
//!
//! - **32-bit sequence space** (vs. 16-bit for RIST) — broadcast flows
//!   at 20 Mbps won't wrap for days.
//! - **Per-path duplicate suppression** — duplicated packets from
//!   multiple paths are delivered once, and the first arrival's path
//!   id is remembered so stats can credit it.
//!
//! ## Design
//!
//! Bounded capacity, indexed by `bond_seq & (capacity - 1)`. Capacity
//! defaults to 64 k slots — at 15 kpps that's ~4 seconds of headroom,
//! enough for a multi-path RTT ceiling of a few hundred ms plus jitter.

use std::time::{Duration, Instant};

use bytes::Bytes;

const DEFAULT_CAPACITY: usize = 65_536;

#[derive(Clone)]
struct Slot {
    seq: u32,
    state: SlotState,
}

#[derive(Clone)]
enum SlotState {
    Empty,
    Gap { first_noticed: Instant },
    Filled {
        data: Bytes,
        arrival: Instant,
        path_id: u8,
    },
}

/// Outcome of `insert`.
///
/// `new_gap_seqs` carries the actual sequence numbers newly flagged as
/// gaps so callers can schedule NACKs without scanning the ring —
/// bounded by the arrival burst size, usually empty, never larger than
/// the forward jump.
#[derive(Debug, Clone, Default)]
pub struct InsertOutcome {
    /// Packet's `bond_seq` is before the current delivery base (already
    /// delivered or timed out).
    pub stale: bool,
    /// A packet for this `bond_seq` was already buffered — dropped.
    pub duplicate: bool,
    /// This packet filled a position that had been noticed as a gap —
    /// i.e. it was genuinely recovered (NACK or a second path catching
    /// up). Duplicates against an already-Filled slot do NOT set this.
    pub recovered: bool,
    /// Sequence numbers newly exposed as gaps because this packet
    /// pushed `highest_seq` forward across empty positions. Empty on
    /// the hot path (in-order arrivals).
    pub new_gap_seqs: Vec<u32>,
    /// `path_id` that this insert accepted (the first delivery wins).
    pub accepted_path: u8,
}

impl InsertOutcome {
    /// Count of newly-exposed gaps — convenience for tests and stats
    /// paths that don't want to own the gap-seq Vec.
    #[inline]
    pub fn new_gaps(&self) -> u32 {
        self.new_gap_seqs.len() as u32
    }
}

/// Item produced by `drain_ready`.
#[derive(Debug)]
pub enum DrainItem {
    /// Payload ready for delivery in-order.
    Delivered { data: Bytes, bond_seq: u32, path_id: u8 },
    /// Gap timed out — deliver the loss to downstream bookkeeping.
    Lost { bond_seq: u32 },
}

/// Receiver-side reassembly buffer.
pub struct ReassemblyBuffer {
    slots: Vec<Slot>,
    capacity: usize,
    mask: usize,
    hold_time: Duration,
    base_seq: Option<u32>,
    highest_seq: Option<u32>,
}

impl ReassemblyBuffer {
    pub fn new(hold_time: Duration) -> Self {
        Self::with_capacity(hold_time, DEFAULT_CAPACITY)
    }

    pub fn with_capacity(hold_time: Duration, capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two().max(256);
        let empty = Slot {
            seq: 0,
            state: SlotState::Empty,
        };
        Self {
            slots: vec![empty; capacity],
            capacity,
            mask: capacity - 1,
            hold_time,
            base_seq: None,
            highest_seq: None,
        }
    }

    #[inline]
    pub fn hold_time(&self) -> Duration {
        self.hold_time
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Insert an arriving packet. `now` is the monotonic arrival time;
    /// `path_id` is echoed back in [`InsertOutcome::accepted_path`] for
    /// stats.
    pub fn insert(
        &mut self,
        seq: u32,
        data: Bytes,
        path_id: u8,
        now: Instant,
    ) -> InsertOutcome {
        let mut outcome = InsertOutcome {
            accepted_path: path_id,
            ..Default::default()
        };

        let (base, highest) = match (self.base_seq, self.highest_seq) {
            (Some(b), Some(h)) => (b, h),
            _ => {
                let idx = (seq as usize) & self.mask;
                self.slots[idx] = Slot {
                    seq,
                    state: SlotState::Filled {
                        data,
                        arrival: now,
                        path_id,
                    },
                };
                self.base_seq = Some(seq);
                self.highest_seq = Some(seq);
                return outcome;
            }
        };

        // Signed-wrap comparison across the 32-bit sequence space.
        let from_base = seq.wrapping_sub(base) as i32;
        if from_base < 0 {
            outcome.stale = true;
            return outcome;
        }

        // Don't accept packets so far ahead that they'd overwrite an
        // in-flight entry at the same ring index.
        let ahead_capacity = self.capacity as u32 - 1;
        if (from_base as u32) > ahead_capacity {
            outcome.stale = true;
            return outcome;
        }

        let idx = (seq as usize) & self.mask;

        if self.slots[idx].seq == seq {
            match self.slots[idx].state {
                SlotState::Filled { .. } => {
                    outcome.duplicate = true;
                    return outcome;
                }
                SlotState::Gap { .. } => {
                    outcome.recovered = true;
                    self.slots[idx].state = SlotState::Filled {
                        data,
                        arrival: now,
                        path_id,
                    };
                }
                SlotState::Empty => {
                    self.slots[idx].state = SlotState::Filled {
                        data,
                        arrival: now,
                        path_id,
                    };
                }
            }
        } else {
            // Stale slot from an earlier cycle — overwrite.
            self.slots[idx] = Slot {
                seq,
                state: SlotState::Filled {
                    data,
                    arrival: now,
                    path_id,
                },
            };
        }

        // Advance highest_seq, marking any newly exposed positions as
        // gaps so `drain_ready` can time them out.
        let diff = seq.wrapping_sub(highest) as i32;
        if diff > 0 {
            for i in 1..=(diff as u32) {
                let gap_seq = highest.wrapping_add(i);
                if gap_seq == seq {
                    continue;
                }
                let gidx = (gap_seq as usize) & self.mask;
                let slot = &mut self.slots[gidx];
                let fresh = matches!(slot.state, SlotState::Empty) || slot.seq != gap_seq;
                if fresh {
                    *slot = Slot {
                        seq: gap_seq,
                        state: SlotState::Gap { first_noticed: now },
                    };
                    outcome.new_gap_seqs.push(gap_seq);
                }
            }
            self.highest_seq = Some(seq);
        }

        outcome
    }

    /// Drain packets whose `hold_time` has elapsed, in strict
    /// bond-sequence order. Gaps that aged past the budget come out as
    /// `DrainItem::Lost` so stats and downstream consumers see the same
    /// sequence-number skip.
    pub fn drain_ready(&mut self, now: Instant, out: &mut Vec<DrainItem>) {
        loop {
            let base = match self.base_seq {
                Some(b) => b,
                None => return,
            };
            match self.highest_seq {
                Some(h) if (base.wrapping_sub(h) as i32) > 0 => return,
                None => return,
                _ => {}
            }
            let idx = (base as usize) & self.mask;
            let slot = &mut self.slots[idx];
            if slot.seq != base {
                *slot = Slot {
                    seq: 0,
                    state: SlotState::Empty,
                };
                out.push(DrainItem::Lost { bond_seq: base });
                self.base_seq = Some(base.wrapping_add(1));
                continue;
            }
            match &slot.state {
                SlotState::Filled { arrival, .. } => {
                    if now.saturating_duration_since(*arrival) >= self.hold_time {
                        let (data, path_id) =
                            match std::mem::replace(&mut slot.state, SlotState::Empty) {
                                SlotState::Filled { data, path_id, .. } => (data, path_id),
                                _ => unreachable!(),
                            };
                        out.push(DrainItem::Delivered {
                            data,
                            bond_seq: base,
                            path_id,
                        });
                        self.base_seq = Some(base.wrapping_add(1));
                        continue;
                    }
                    return;
                }
                SlotState::Gap { first_noticed } => {
                    if now.saturating_duration_since(*first_noticed) >= self.hold_time {
                        slot.state = SlotState::Empty;
                        out.push(DrainItem::Lost { bond_seq: base });
                        self.base_seq = Some(base.wrapping_add(1));
                        continue;
                    }
                    return;
                }
                SlotState::Empty => return,
            }
        }
    }

    /// Inform the buffer about the sender's current tip even though
    /// no data packet has pushed us there yet. Used by keepalive
    /// handlers to expose *tail* gaps — when the last N packets of a
    /// burst are all lost, the receiver would never notice without
    /// an out-of-band signal because no later arrival advances
    /// `highest_seq`.
    ///
    /// Any seq in `(highest_seq, peer_tip]` that isn't already
    /// Filled becomes a `Gap` and is returned so the caller can
    /// register it with the NACK scheduler. If `peer_tip` trails or
    /// equals the local highest, this is a no-op.
    pub fn advance_to_peer_tip(&mut self, peer_tip: u32, now: Instant, out: &mut Vec<u32>) {
        let base = match self.base_seq {
            Some(b) => b,
            None => return,
        };
        let local_high = match self.highest_seq {
            Some(h) => h,
            None => return,
        };
        let diff = peer_tip.wrapping_sub(local_high) as i32;
        if diff <= 0 {
            return;
        }
        // Bound the advance so we never mark more than the ring can
        // physically hold.
        let ahead_capacity = self.capacity as u32 - 1;
        let max_ahead = (ahead_capacity.saturating_sub(local_high.wrapping_sub(base))).min(diff as u32);
        for i in 1..=max_ahead {
            let gap_seq = local_high.wrapping_add(i);
            let gidx = (gap_seq as usize) & self.mask;
            let slot = &mut self.slots[gidx];
            let fresh = matches!(slot.state, SlotState::Empty) || slot.seq != gap_seq;
            if fresh {
                *slot = Slot {
                    seq: gap_seq,
                    state: SlotState::Gap { first_noticed: now },
                };
                out.push(gap_seq);
            }
        }
        self.highest_seq = Some(local_high.wrapping_add(max_ahead));
    }

    /// Earliest time at which `drain_ready` will produce output. Used
    /// by the transport layer to arm a timer rather than fast-polling.
    pub fn next_drain_time(&self) -> Option<Instant> {
        let base = self.base_seq?;
        let idx = (base as usize) & self.mask;
        let slot = &self.slots[idx];
        if slot.seq != base {
            return Some(Instant::now());
        }
        match &slot.state {
            SlotState::Filled { arrival, .. } => Some(*arrival + self.hold_time),
            SlotState::Gap { first_noticed } => Some(*first_noticed + self.hold_time),
            SlotState::Empty => None,
        }
    }
}

impl std::fmt::Debug for ReassemblyBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReassemblyBuffer")
            .field("capacity", &self.capacity)
            .field("hold_time", &self.hold_time)
            .field("base_seq", &self.base_seq)
            .field("highest_seq", &self.highest_seq)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: u8) -> Bytes {
        Bytes::from(vec![n])
    }

    fn drain(buf: &mut ReassemblyBuffer, now: Instant) -> Vec<DrainItem> {
        let mut v = Vec::new();
        buf.drain_ready(now, &mut v);
        v
    }

    fn delivered_only(items: &[DrainItem]) -> Vec<(u32, u8, u8)> {
        items
            .iter()
            .filter_map(|i| match i {
                DrainItem::Delivered { bond_seq, path_id, data } => {
                    Some((*bond_seq, *path_id, data[0]))
                }
                DrainItem::Lost { .. } => None,
            })
            .collect()
    }

    #[test]
    fn in_order_hold() {
        let mut buf = ReassemblyBuffer::new(Duration::from_millis(50));
        let t0 = Instant::now();
        buf.insert(1000, b(1), 0, t0);
        buf.insert(1001, b(2), 0, t0);
        assert!(drain(&mut buf, t0).is_empty());
        let out = drain(&mut buf, t0 + Duration::from_millis(60));
        assert_eq!(
            delivered_only(&out),
            vec![(1000, 0, 1), (1001, 0, 2)]
        );
    }

    #[test]
    fn gap_filled_by_second_path() {
        let mut buf = ReassemblyBuffer::new(Duration::from_millis(100));
        let t0 = Instant::now();
        buf.insert(100, b(1), 0, t0);
        buf.insert(102, b(3), 0, t0); // gap at 101

        // seq 101 arrives on a different path before timeout
        let out = buf.insert(101, b(2), 1, t0 + Duration::from_millis(30));
        assert!(out.recovered);
        assert_eq!(out.accepted_path, 1);

        let drained = drain(&mut buf, t0 + Duration::from_millis(200));
        assert_eq!(
            delivered_only(&drained),
            vec![(100, 0, 1), (101, 1, 2), (102, 0, 3)]
        );
    }

    #[test]
    fn gap_timeout_produces_lost_marker() {
        let mut buf = ReassemblyBuffer::new(Duration::from_millis(50));
        let t0 = Instant::now();
        buf.insert(10, b(1), 0, t0);
        buf.insert(12, b(3), 0, t0);

        let drained = drain(&mut buf, t0 + Duration::from_millis(200));
        let mut iter = drained.iter();
        match iter.next() {
            Some(DrainItem::Delivered { bond_seq: 10, .. }) => {}
            o => panic!("expected Delivered(10), got {o:?}"),
        }
        match iter.next() {
            Some(DrainItem::Lost { bond_seq: 11 }) => {}
            o => panic!("expected Lost(11), got {o:?}"),
        }
        match iter.next() {
            Some(DrainItem::Delivered { bond_seq: 12, .. }) => {}
            o => panic!("expected Delivered(12), got {o:?}"),
        }
    }

    #[test]
    fn duplicate_from_duplicated_path() {
        let mut buf = ReassemblyBuffer::new(Duration::from_millis(5));
        let t0 = Instant::now();
        buf.insert(500, b(7), 0, t0);
        let dup = buf.insert(500, b(7), 1, t0 + Duration::from_millis(1));
        assert!(dup.duplicate);
        // accepted_path reflects the attempted insert, not the first winner —
        // stats use it to count which path delivered duplicates.
        assert_eq!(dup.accepted_path, 1);
        let drained = drain(&mut buf, t0 + Duration::from_millis(10));
        let items = delivered_only(&drained);
        assert_eq!(items.len(), 1);
        // First-win semantics: the delivered packet is tagged with path 0.
        assert_eq!(items[0].1, 0);
    }

    #[test]
    fn stale_after_delivery() {
        let mut buf = ReassemblyBuffer::new(Duration::from_millis(20));
        let t0 = Instant::now();
        buf.insert(1, b(1), 0, t0);
        buf.insert(2, b(2), 0, t0);
        let _ = drain(&mut buf, t0 + Duration::from_millis(30));

        let late = buf.insert(1, b(1), 0, t0 + Duration::from_millis(40));
        assert!(late.stale);
    }

    #[test]
    fn wraparound_u32() {
        let mut buf = ReassemblyBuffer::new(Duration::from_millis(5));
        let t0 = Instant::now();
        buf.insert(u32::MAX - 1, b(1), 0, t0);
        buf.insert(u32::MAX, b(2), 0, t0);
        buf.insert(0, b(3), 0, t0);
        buf.insert(1, b(4), 0, t0);

        let drained = drain(&mut buf, t0 + Duration::from_millis(10));
        let vals: Vec<u8> = delivered_only(&drained).into_iter().map(|x| x.2).collect();
        assert_eq!(vals, vec![1, 2, 3, 4]);
    }

    #[test]
    fn advance_to_peer_tip_exposes_tail_gaps() {
        let mut buf = ReassemblyBuffer::new(Duration::from_millis(50));
        let t0 = Instant::now();
        buf.insert(100, b(1), 0, t0);
        buf.insert(101, b(2), 0, t0);

        // Peer says tip is 105; seqs 102, 103, 104, 105 are tail gaps.
        let mut new_gaps = Vec::new();
        buf.advance_to_peer_tip(105, t0, &mut new_gaps);
        assert_eq!(new_gaps, vec![102, 103, 104, 105]);

        // Drain after hold time: 100 + 101 Delivered, tail Lost.
        let drained = drain(&mut buf, t0 + Duration::from_millis(100));
        let kinds: Vec<(&'static str, u32)> = drained
            .iter()
            .map(|i| match i {
                DrainItem::Delivered { bond_seq, .. } => ("D", *bond_seq),
                DrainItem::Lost { bond_seq } => ("L", *bond_seq),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![("D", 100), ("D", 101), ("L", 102), ("L", 103), ("L", 104), ("L", 105)]
        );
    }

    #[test]
    fn advance_to_peer_tip_noop_when_not_ahead() {
        let mut buf = ReassemblyBuffer::new(Duration::from_millis(50));
        let t0 = Instant::now();
        buf.insert(10, b(1), 0, t0);
        let mut new_gaps = Vec::new();
        buf.advance_to_peer_tip(5, t0, &mut new_gaps);
        assert!(new_gaps.is_empty());
        buf.advance_to_peer_tip(10, t0, &mut new_gaps);
        assert!(new_gaps.is_empty());
    }
}
