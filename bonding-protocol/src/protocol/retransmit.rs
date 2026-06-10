//! Sender-side retransmit buffer.
//!
//! Ring-buffer of recently-sent bonded datagrams keyed by `bond_seq`,
//! indexed with a power-of-two modulo mask. Same shape as
//! `rist_protocol::protocol::nack_tracker::RetransmitBuffer` but with
//! a 32-bit sequence space (matching the bond header) and a
//! capacity-in-packets that the caller sizes against their send rate.
//!
//! Typical usage: size capacity to `rate_pps × buffer_time_seconds`
//! rounded up to the next power of two. At 15 kpps × 2 s that's
//! 32 768 slots — ~32 MB at 1316-byte payloads, well within budget.

use std::time::{Duration, Instant};

use bytes::Bytes;

#[derive(Clone, Debug)]
struct Slot {
    seq: u32,
    data: Option<Bytes>,
    /// When this seq last went out as a retransmit — anchors the dedup
    /// window in [`RetransmitBuffer::get_for_retransmit`].
    last_retx: Option<Instant>,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            seq: 0,
            data: None,
            last_retx: None,
        }
    }
}

/// O(1) insert / O(1) lookup retransmit buffer. Stale slot detection
/// via the stored `seq` — a lookup mismatch means the slot's been
/// overwritten by a later packet and the data has aged out.
#[derive(Debug)]
pub struct RetransmitBuffer {
    slots: Vec<Slot>,
    capacity: usize,
    mask: usize,
}

impl RetransmitBuffer {
    /// Build a buffer with `capacity` slots rounded up to a power of
    /// two (minimum 256).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two().max(256);
        Self {
            slots: vec![Slot::default(); capacity],
            capacity,
            mask: capacity - 1,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Minimum spacing between retransmits of the same seq. Receivers
    /// retry on an RTT-aware cadence, but duplicate seqs still land in
    /// bursts (multiple NACK datagrams, pump-tick jitter, a stale and
    /// a fresh retry crossing on the wire); one resend per window keeps
    /// recovery bandwidth linear in actual losses instead of NACK
    /// arrivals.
    pub const RETRANSMIT_DEDUP: Duration = Duration::from_millis(25);

    /// Store a packet. Overwrites any stale slot at the same index.
    #[inline]
    pub fn insert(&mut self, seq: u32, data: Bytes) {
        let idx = (seq as usize) & self.mask;
        self.slots[idx] = Slot {
            seq,
            data: Some(data),
            last_retx: None,
        };
    }

    /// Look up a packet. Returns `None` if the slot has been
    /// overwritten by a newer sequence number (common under high
    /// packet rate and long NACK delay).
    #[inline]
    pub fn get(&self, seq: u32) -> Option<&Bytes> {
        let idx = (seq as usize) & self.mask;
        let slot = &self.slots[idx];
        if slot.seq == seq {
            slot.data.as_ref()
        } else {
            None
        }
    }

    /// Look up a packet for retransmission. Same staleness rules as
    /// [`Self::get`], plus dedup: returns `None` when this seq was
    /// already retransmitted within [`Self::RETRANSMIT_DEDUP`]. On a
    /// hit the slot is stamped with `now` so the next request inside
    /// the window is suppressed.
    pub fn get_for_retransmit(&mut self, seq: u32, now: Instant) -> Option<&Bytes> {
        let idx = (seq as usize) & self.mask;
        let slot = &mut self.slots[idx];
        if slot.seq != seq || slot.data.is_none() {
            return None;
        }
        if let Some(last) = slot.last_retx {
            if now.saturating_duration_since(last) < Self::RETRANSMIT_DEDUP {
                return None;
            }
        }
        slot.last_retx = Some(now);
        slot.data.as_ref()
    }

    /// Drop the packet at `seq` — useful after the receiver has
    /// confirmed delivery or the slot is definitely too stale to help.
    pub fn forget(&mut self, seq: u32) {
        let idx = (seq as usize) & self.mask;
        if self.slots[idx].seq == seq {
            self.slots[idx].data = None;
        }
    }
}

impl Default for RetransmitBuffer {
    fn default() -> Self {
        Self::new(2048)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut buf = RetransmitBuffer::new(4);
        assert_eq!(buf.capacity(), 256); // minimum floor
        buf.insert(10, Bytes::from_static(b"ten"));
        buf.insert(11, Bytes::from_static(b"eleven"));
        assert_eq!(buf.get(10).unwrap().as_ref(), b"ten");
        assert_eq!(buf.get(11).unwrap().as_ref(), b"eleven");
        assert!(buf.get(12).is_none());
    }

    #[test]
    fn capacity_rounds_up_power_of_two() {
        let buf = RetransmitBuffer::new(500);
        assert_eq!(buf.capacity(), 512);
        let buf2 = RetransmitBuffer::new(513);
        assert_eq!(buf2.capacity(), 1024);
    }

    #[test]
    fn overwritten_slot_returns_none() {
        let mut buf = RetransmitBuffer::new(256);
        buf.insert(0, Bytes::from_static(b"a"));
        // seq 256 hashes to same index with cap=256
        buf.insert(256, Bytes::from_static(b"b"));
        assert!(buf.get(0).is_none());
        assert_eq!(buf.get(256).unwrap().as_ref(), b"b");
    }

    #[test]
    fn forget_clears_slot() {
        let mut buf = RetransmitBuffer::new(256);
        buf.insert(5, Bytes::from_static(b"five"));
        buf.forget(5);
        assert!(buf.get(5).is_none());
    }

    #[test]
    fn retransmit_dedup_suppresses_burst_duplicates() {
        let mut buf = RetransmitBuffer::new(256);
        buf.insert(7, Bytes::from_static(b"seven"));
        let t0 = Instant::now();
        assert!(buf.get_for_retransmit(7, t0).is_some());
        // Second request inside the window — suppressed.
        assert!(
            buf.get_for_retransmit(7, t0 + Duration::from_millis(10))
                .is_none()
        );
        // Past the window — allowed again.
        assert!(
            buf.get_for_retransmit(7, t0 + RetransmitBuffer::RETRANSMIT_DEDUP)
                .is_some()
        );
        // Plain `get` is unaffected by dedup state.
        assert!(buf.get(7).is_some());
        // Re-inserting (slot reuse on a later cycle) clears the stamp.
        buf.insert(7, Bytes::from_static(b"seven'"));
        assert!(
            buf.get_for_retransmit(7, t0 + Duration::from_millis(1))
                .is_some()
        );
        // Stale / absent seqs still return None.
        assert!(buf.get_for_retransmit(8, t0).is_none());
    }

    #[test]
    fn u32_wraparound() {
        let mut buf = RetransmitBuffer::new(1024);
        buf.insert(u32::MAX, Bytes::from_static(b"max"));
        buf.insert(0, Bytes::from_static(b"zero"));
        buf.insert(1, Bytes::from_static(b"one"));
        assert_eq!(buf.get(u32::MAX).unwrap().as_ref(), b"max");
        assert_eq!(buf.get(0).unwrap().as_ref(), b"zero");
        assert_eq!(buf.get(1).unwrap().as_ref(), b"one");
    }
}
