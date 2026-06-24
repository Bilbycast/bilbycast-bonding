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

/// Base (v1) bond header length in bytes.
pub const BOND_HEADER_SIZE: usize = 12;

/// v2 header length: the v1 header plus a 4-byte `send_stamp_us` trailer
/// used for per-leg latency equalization (see `docs/per-leg-equalization.md`).
pub const BOND_HEADER_SIZE_V2: usize = 16;

/// Magic first byte. `0xBC` = "bilbycast".
pub const MAGIC: u8 = 0xBC;

/// Baseline protocol version (top 4 bits of byte 1). A v1 header is 12
/// bytes and carries no send-timestamp. Emitted by default and whenever
/// the peer has not yet been confirmed to speak v2.
pub const PROTOCOL_VERSION: u8 = 1;

/// Equalization-capable protocol version. A v2 header is 16 bytes — the v1
/// fields plus `send_stamp_us` (sender monotonic microseconds, wrapping).
/// A v2 receiver parses BOTH; a sender only EMITS v2 once the keepalive-ack
/// has confirmed the receiver speaks v2 (graceful rolling upgrade).
pub const PROTOCOL_VERSION_V2: u8 = 2;

/// Flag bit constants. Occupy the low 4 bits of byte 1.
pub mod flags {
    /// Packet is a retransmit (sent in response to a NACK).
    pub const RETRANSMIT: u8 = 0b0001;
    /// Packet was intentionally duplicated across paths by the scheduler.
    pub const DUPLICATED: u8 = 0b0010;
    /// Marker bit — caller-defined boundary (typically end of a media frame).
    pub const MARKER: u8 = 0b0100;
    /// This datagram carries a FEC **repair** packet (its payload is a
    /// `protocol::fec::FecRepair`, not media bytes). The receiver routes
    /// it to the FEC decoder and does NOT treat its `bond_seq` as a media
    /// sequence number.
    pub const FEC: u8 = 0b1000;
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

    /// Importance rank for redundancy thresholds: `Low < Normal < High <
    /// Critical`. Distinct from the wire discriminant (`Low = 3`), which is
    /// an enum tag, not an ordering.
    #[inline]
    pub fn rank(self) -> u8 {
        match self {
            Priority::Low => 0,
            Priority::Normal => 1,
            Priority::High => 2,
            Priority::Critical => 3,
        }
    }
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}

/// Parsed bond header.
///
/// `send_stamp_us` is `Some` only on a v2 (16-byte) header; it is the
/// sender's monotonic-microsecond emit time (wrapping u32) used by the
/// receiver to derive per-leg relative one-way delay for equalization.
/// `None` on a v1 (12-byte) header — the field's presence is what
/// distinguishes the two wire versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondHeader {
    pub version: u8,
    pub flags: u8,
    pub path_id: u8,
    pub priority: Priority,
    pub flow_id: u32,
    pub bond_seq: u32,
    pub send_stamp_us: Option<u32>,
}

impl BondHeader {
    /// Build a fresh v1 header (no send-timestamp) for a packet emitted on
    /// the given path. Byte-identical to pre-equalization behaviour.
    pub fn new(flow_id: u32, bond_seq: u32, path_id: u8, priority: Priority) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags: 0,
            path_id,
            priority,
            flow_id,
            bond_seq,
            send_stamp_us: None,
        }
    }

    /// Attach a send-timestamp, promoting this header to v2 (16 bytes on the
    /// wire). The sender calls this only on legs whose receiver has been
    /// confirmed v2 via keepalive-ack negotiation.
    #[inline]
    pub fn set_send_stamp(&mut self, us: u32) -> &mut Self {
        self.version = PROTOCOL_VERSION_V2;
        self.send_stamp_us = Some(us);
        self
    }

    /// Wire length of this header: 16 bytes when a send-timestamp is present
    /// (v2), else 12 (v1).
    #[inline]
    pub fn header_len(&self) -> usize {
        if self.send_stamp_us.is_some() {
            BOND_HEADER_SIZE_V2
        } else {
            BOND_HEADER_SIZE
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

    /// Mark this datagram as a FEC repair packet.
    #[inline]
    pub fn set_fec(&mut self) -> &mut Self {
        self.flags |= flags::FEC;
        self
    }

    #[inline]
    pub fn is_fec(&self) -> bool {
        self.flags & flags::FEC != 0
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

    /// Parse a bond header from `buf`. Version-gated: a v1 header consumes
    /// 12 bytes (`send_stamp_us = None`); a v2 header consumes 16 bytes and
    /// carries `send_stamp_us = Some(_)`. Returns the header and the number
    /// of bytes consumed so the caller can slice the payload. Both versions
    /// are accepted so a v2 receiver interoperates with a v1 sender mid
    /// rolling-upgrade.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < BOND_HEADER_SIZE {
            return Err(BondError::PacketTooShort {
                expected: BOND_HEADER_SIZE,
                actual: buf.len(),
            });
        }
        // Peek magic + version before committing to a length.
        if buf[0] != MAGIC {
            return Err(BondError::InvalidMagic {
                expected: MAGIC as u32,
                actual: buf[0] as u32,
            });
        }
        let version = (buf[1] >> 4) & 0x0F;
        let hdr_len = match version {
            PROTOCOL_VERSION => BOND_HEADER_SIZE,
            PROTOCOL_VERSION_V2 => BOND_HEADER_SIZE_V2,
            other => return Err(BondError::UnsupportedVersion(other)),
        };
        if buf.len() < hdr_len {
            return Err(BondError::PacketTooShort {
                expected: hdr_len,
                actual: buf.len(),
            });
        }
        let mut r = &buf[..hdr_len];
        let _magic = r.get_u8();
        let ver_flags = r.get_u8();
        let flags_byte = ver_flags & 0x0F;
        let path_id = r.get_u8();
        let priority = Priority::from_u8(r.get_u8());
        let flow_id = r.get_u32();
        let bond_seq = r.get_u32();
        let send_stamp_us = if version == PROTOCOL_VERSION_V2 {
            Some(r.get_u32())
        } else {
            None
        };

        Ok((
            Self {
                version,
                flags: flags_byte,
                path_id,
                priority,
                flow_id,
                bond_seq,
                send_stamp_us,
            },
            hdr_len,
        ))
    }

    /// Serialise into an existing buffer. Emits 12 bytes (v1) or 16 bytes
    /// (v2, when `send_stamp_us` is set). The buffer is extended — no
    /// allocation if it already has capacity for [`Self::header_len`].
    pub fn write_to(&self, out: &mut BytesMut) {
        let version = if self.send_stamp_us.is_some() {
            PROTOCOL_VERSION_V2
        } else {
            PROTOCOL_VERSION
        };
        out.put_u8(MAGIC);
        out.put_u8(((version & 0x0F) << 4) | (self.flags & 0x0F));
        out.put_u8(self.path_id);
        out.put_u8(self.priority as u8);
        out.put_u32(self.flow_id);
        out.put_u32(self.bond_seq);
        if let Some(stamp) = self.send_stamp_us {
            out.put_u32(stamp);
        }
    }
}

/// Build a full bonded datagram in-place: header + payload.
/// `out` is cleared first, then extended — zero heap alloc when `out`
/// already has capacity.
pub fn write_packet(header: &BondHeader, payload: &[u8], out: &mut BytesMut) {
    out.clear();
    out.reserve(header.header_len() + payload.len());
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
        // Corrupt version to 5 (neither v1 nor v2 — genuinely unsupported).
        buf[1] = (5 << 4) | (buf[1] & 0x0F);
        let err = BondHeader::parse(&buf).unwrap_err();
        match err {
            BondError::UnsupportedVersion(5) => {}
            e => panic!("expected UnsupportedVersion(5), got {e:?}"),
        }
    }

    #[test]
    fn v1_header_is_12_bytes_and_unstamped() {
        let h = BondHeader::new(0xabcd, 99, 2, Priority::High);
        assert_eq!(h.header_len(), BOND_HEADER_SIZE);
        assert_eq!(h.send_stamp_us, None);
        let mut buf = BytesMut::new();
        h.write_to(&mut buf);
        assert_eq!(buf.len(), BOND_HEADER_SIZE, "v1 stays byte-identical to today");
        assert_eq!((buf[1] >> 4) & 0x0F, PROTOCOL_VERSION);
        let (p, n) = BondHeader::parse(&buf).unwrap();
        assert_eq!(n, BOND_HEADER_SIZE);
        assert_eq!(p, h);
        assert_eq!(p.send_stamp_us, None);
    }

    #[test]
    fn v2_header_roundtrips_the_stamp() {
        let mut h = BondHeader::new(0xdead_beef, 1_234_567_890, 3, Priority::Critical);
        h.set_marker().set_send_stamp(0xCAFE_F00D);
        assert_eq!(h.header_len(), BOND_HEADER_SIZE_V2);
        let mut buf = BytesMut::new();
        h.write_to(&mut buf);
        assert_eq!(buf.len(), BOND_HEADER_SIZE_V2);
        assert_eq!((buf[1] >> 4) & 0x0F, PROTOCOL_VERSION_V2);
        let (p, n) = BondHeader::parse(&buf).unwrap();
        assert_eq!(n, BOND_HEADER_SIZE_V2);
        assert_eq!(p.send_stamp_us, Some(0xCAFE_F00D));
        assert!(p.is_marker());
        assert_eq!(p.flow_id, 0xdead_beef);
        assert_eq!(p.bond_seq, 1_234_567_890);
    }

    #[test]
    fn v2_payload_slices_after_16_bytes() {
        let mut h = BondHeader::new(1, 2, 0, Priority::Normal);
        h.set_send_stamp(42);
        let mut out = BytesMut::new();
        write_packet(&h, b"payload", &mut out);
        assert_eq!(out.len(), BOND_HEADER_SIZE_V2 + 7);
        let (_p, consumed) = BondHeader::parse(&out).unwrap();
        assert_eq!(consumed, BOND_HEADER_SIZE_V2);
        assert_eq!(&out[consumed..], b"payload");
    }

    #[test]
    fn v2_header_truncated_to_12_is_too_short() {
        let mut h = BondHeader::new(1, 2, 0, Priority::Normal);
        h.set_send_stamp(7);
        let mut buf = BytesMut::new();
        h.write_to(&mut buf);
        // A v2 magic+version with only 12 bytes present must report it needs 16.
        let truncated = &buf[..BOND_HEADER_SIZE];
        match BondHeader::parse(truncated).unwrap_err() {
            BondError::PacketTooShort { expected, actual } => {
                assert_eq!(expected, BOND_HEADER_SIZE_V2);
                assert_eq!(actual, BOND_HEADER_SIZE);
            }
            e => panic!("expected PacketTooShort(16), got {e:?}"),
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
