//! Bond wire header format.
//!
//! Every bonded packet rides a fixed 12-byte header followed by the
//! opaque payload. Paths only carry payload bytes; the reassembly side
//! uses the header to sort across paths and detect gaps.
//!
//! ## Layout (12 bytes, network byte order)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     0xBC      |  Ver  |Flag |   Path ID     |    Priority   |
//! +---------------+---------------+-------------------------------+
//! |                           flow_id                             |
//! +---------------------------------------------------------------+
//! |                           bond_seq                            |
//! +---------------------------------------------------------------+
//! ```
//!
//! - Byte 0 — **magic** `0xBC` (bilbycast): cheap signature so a bond
//!   frame never collides with a stray raw-TS (`0x47`) or RTP (top bits
//!   `10`) packet landing on the same socket.
//! - Byte 1 — **version (4 bits)** + **flags (4 bits)**. Version is
//!   [`PROTOCOL_VERSION`]. Flags are defined in the [`flags`] module.
//! - Byte 2 — **path_id**: which path the packet was emitted on.
//!   Echoed in NACK feedback so the sender knows which path lost it.
//! - Byte 3 — **priority**: scheduler hint set by the caller, opaque
//!   to the library. See [`Priority`].
//! - Bytes 4–7 — **flow_id**: u32 BE, ties a bond packet to a logical
//!   flow. Multiple flows can share a set of paths.
//! - Bytes 8–11 — **bond_seq**: u32 BE, monotonically increasing
//!   across all paths. 32 bits so a 20 Mbps / 15 kpps broadcast never
//!   wraps within the reassembly budget.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::{BondError, Result};

/// Fixed bond header length in bytes.
pub const BOND_HEADER_SIZE: usize = 12;

/// Magic first byte. `0xBC` = "bilbycast".
pub const MAGIC: u8 = 0xBC;

/// Current protocol version (top 4 bits of byte 1).
pub const PROTOCOL_VERSION: u8 = 1;

/// Flag bit constants. Occupy the low 4 bits of byte 1.
pub mod flags {
    /// Packet is a retransmit (sent in response to a NACK).
    pub const RETRANSMIT: u8 = 0b0001;
    /// Packet was intentionally duplicated across paths by the scheduler.
    pub const DUPLICATED: u8 = 0b0010;
    /// Marker bit — caller-defined boundary (typically end of a media frame).
    pub const MARKER: u8 = 0b0100;
    /// Reserved for future use. Senders MUST set 0; receivers MUST ignore.
    pub const RESERVED: u8 = 0b1000;
}

/// Priority hint attached to a bond packet.
///
/// Set by the caller (e.g. `bilbycast-edge`'s media-aware scheduler
/// would promote IDR NAL units to `Critical`). The bonding library does
/// not interpret priority beyond passing it through; schedulers MAY use
/// it to choose duplication or path selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Priority {
    /// Standard traffic — default.
    Normal = 0,
    /// Elevated importance (e.g. PAT/PMT, P-frames).
    High = 1,
    /// Must-deliver (e.g. IDR frames, sync frames).
    Critical = 2,
    /// Lower than Normal — discard first under congestion.
    Low = 3,
}

impl Priority {
    #[inline]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Priority::High,
            2 => Priority::Critical,
            3 => Priority::Low,
            _ => Priority::Normal,
        }
    }
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}

/// Parsed bond header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondHeader {
    pub version: u8,
    pub flags: u8,
    pub path_id: u8,
    pub priority: Priority,
    pub flow_id: u32,
    pub bond_seq: u32,
}

impl BondHeader {
    /// Build a fresh header for a packet emitted on the given path.
    pub fn new(flow_id: u32, bond_seq: u32, path_id: u8, priority: Priority) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags: 0,
            path_id,
            priority,
            flow_id,
            bond_seq,
        }
    }

    /// Mark this header as a retransmit.
    #[inline]
    pub fn set_retransmit(&mut self) -> &mut Self {
        self.flags |= flags::RETRANSMIT;
        self
    }

    /// Mark this header as duplicated across paths.
    #[inline]
    pub fn set_duplicated(&mut self) -> &mut Self {
        self.flags |= flags::DUPLICATED;
        self
    }

    /// Set the marker bit.
    #[inline]
    pub fn set_marker(&mut self) -> &mut Self {
        self.flags |= flags::MARKER;
        self
    }

    #[inline]
    pub fn is_retransmit(&self) -> bool {
        self.flags & flags::RETRANSMIT != 0
    }

    #[inline]
    pub fn is_duplicated(&self) -> bool {
        self.flags & flags::DUPLICATED != 0
    }

    #[inline]
    pub fn is_marker(&self) -> bool {
        self.flags & flags::MARKER != 0
    }

    /// Parse a 12-byte header from `buf`. Returns the header and the
    /// number of bytes consumed so the caller can slice the payload.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < BOND_HEADER_SIZE {
            return Err(BondError::PacketTooShort {
                expected: BOND_HEADER_SIZE,
                actual: buf.len(),
            });
        }
        let mut r = &buf[..BOND_HEADER_SIZE];
        let magic = r.get_u8();
        if magic != MAGIC {
            return Err(BondError::InvalidMagic {
                expected: MAGIC as u32,
                actual: magic as u32,
            });
        }
        let ver_flags = r.get_u8();
        let version = (ver_flags >> 4) & 0x0F;
        let flags_byte = ver_flags & 0x0F;
        if version != PROTOCOL_VERSION {
            return Err(BondError::UnsupportedVersion(version));
        }
        let path_id = r.get_u8();
        let priority = Priority::from_u8(r.get_u8());
        let flow_id = r.get_u32();
        let bond_seq = r.get_u32();

        Ok((
            Self {
                version,
                flags: flags_byte,
                path_id,
                priority,
                flow_id,
                bond_seq,
            },
            BOND_HEADER_SIZE,
        ))
    }

    /// Serialise into an existing buffer. The buffer is extended — no
    /// allocation if it has capacity for 12 bytes.
    pub fn write_to(&self, out: &mut BytesMut) {
        out.put_u8(MAGIC);
        out.put_u8(((self.version & 0x0F) << 4) | (self.flags & 0x0F));
        out.put_u8(self.path_id);
        out.put_u8(self.priority as u8);
        out.put_u32(self.flow_id);
        out.put_u32(self.bond_seq);
    }
}

/// Build a full bonded datagram in-place: header + payload.
/// `out` is cleared first, then extended — zero heap alloc when `out`
/// already has capacity.
pub fn write_packet(header: &BondHeader, payload: &[u8], out: &mut BytesMut) {
    out.clear();
    out.reserve(BOND_HEADER_SIZE + payload.len());
    header.write_to(out);
    out.put_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let mut h = BondHeader::new(0xdead_beef, 1_234_567_890, 3, Priority::Critical);
        h.set_retransmit().set_duplicated().set_marker();

        let mut buf = BytesMut::with_capacity(BOND_HEADER_SIZE);
        h.write_to(&mut buf);
        assert_eq!(buf.len(), BOND_HEADER_SIZE);

        let (parsed, consumed) = BondHeader::parse(&buf).unwrap();
        assert_eq!(consumed, BOND_HEADER_SIZE);
        assert_eq!(parsed, h);
        assert!(parsed.is_retransmit());
        assert!(parsed.is_duplicated());
        assert!(parsed.is_marker());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = BytesMut::from(&[0x47u8; BOND_HEADER_SIZE][..]);
        // Force not-magic
        buf[0] = 0x47;
        let err = BondHeader::parse(&buf).unwrap_err();
        match err {
            BondError::InvalidMagic { .. } => {}
            e => panic!("expected InvalidMagic, got {e:?}"),
        }
    }

    #[test]
    fn rejects_bad_version() {
        let h = BondHeader::new(1, 2, 0, Priority::Normal);
        let mut buf = BytesMut::with_capacity(BOND_HEADER_SIZE);
        h.write_to(&mut buf);
        // Corrupt version to 2
        buf[1] = (2 << 4) | (buf[1] & 0x0F);
        let err = BondHeader::parse(&buf).unwrap_err();
        match err {
            BondError::UnsupportedVersion(2) => {}
            e => panic!("expected UnsupportedVersion(2), got {e:?}"),
        }
    }

    #[test]
    fn short_buffer_errors() {
        let buf = [0xBCu8, 0x10, 0x00];
        let err = BondHeader::parse(&buf).unwrap_err();
        match err {
            BondError::PacketTooShort { expected, actual } => {
                assert_eq!(expected, BOND_HEADER_SIZE);
                assert_eq!(actual, 3);
            }
            e => panic!("expected PacketTooShort, got {e:?}"),
        }
    }

    #[test]
    fn write_packet_frames_payload() {
        let header = BondHeader::new(100, 42, 1, Priority::High);
        let mut out = BytesMut::new();
        write_packet(&header, b"hello", &mut out);
        assert_eq!(out.len(), BOND_HEADER_SIZE + 5);

        let (parsed, consumed) = BondHeader::parse(&out).unwrap();
        assert_eq!(parsed, header);
        assert_eq!(&out[consumed..], b"hello");
    }

    #[test]
    fn priority_roundtrip() {
        for p in [Priority::Normal, Priority::High, Priority::Critical, Priority::Low] {
            let h = BondHeader::new(1, 2, 3, p);
            let mut buf = BytesMut::new();
            h.write_to(&mut buf);
            let (parsed, _) = BondHeader::parse(&buf).unwrap();
            assert_eq!(parsed.priority, p);
        }
    }
}
