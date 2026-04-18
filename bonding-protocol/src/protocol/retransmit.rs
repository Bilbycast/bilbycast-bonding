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

use bytes::Bytes;

#[derive(Clone, Debug)]
struct Slot {
    seq: u32,
    data: Option<Bytes>,
}

impl Default for Slot {
    fn default() -> Self {
        Self { seq: 0, data: None }
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

    /// Store a packet. Overwrites any stale slot at the same index.
    #[inline]
    pub fn insert(&mut self, seq: u32, data: Bytes) {
        let idx = (seq as usize) & self.mask;
        self.slots[idx] = Slot {
            seq,
            data: Some(data),
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
