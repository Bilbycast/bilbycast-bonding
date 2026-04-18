//! Control-channel wire format.
//!
//! Data packets and control packets share the same UDP socket but are
//! disambiguated by the first byte ("magic"): [`crate::packet::MAGIC`]
//! (`0xBC`) for bonded data, [`CTRL_MAGIC`] (`0xBE`) for control.
//! A parser peeks byte 0 and dispatches — neither shape ever gets fed
//! to the wrong decoder.
//!
//! ## Message catalogue
//!
//! | Type            | ID  | Purpose                                           |
//! |-----------------|-----|---------------------------------------------------|
//! | Keepalive       | 1   | Liveness + RTT probe, carries echoable timestamp  |
//! | KeepaliveAck    | 2   | Mirror of the ping plus path counters             |
//! | Nack            | 3   | Receiver-driven NACK (list of missing bond_seqs)  |
//! | Goodbye         | 4   | Clean shutdown notice on a path                   |

use bytes::{Buf, BufMut, BytesMut};

use crate::error::{BondError, Result};

/// First byte of every control datagram. Intentionally distinct from
/// the data magic `0xBC` so receivers can peek byte 0 to dispatch.
pub const CTRL_MAGIC: u8 = 0xBE;

/// Control protocol version (top 4 bits of byte 1; low 4 bits are
/// reserved for per-message flags).
pub const CTRL_VERSION: u8 = 1;

/// Control message type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtrlType {
    Keepalive = 1,
    KeepaliveAck = 2,
    Nack = 3,
    Goodbye = 4,
}

impl CtrlType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(CtrlType::Keepalive),
            2 => Some(CtrlType::KeepaliveAck),
            3 => Some(CtrlType::Nack),
            4 => Some(CtrlType::Goodbye),
            _ => None,
        }
    }
}

/// Common 8-byte control header: magic, ver+flags, type, path_id, flow_id.
/// The remaining body is type-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrlHeader {
    pub version: u8,
    pub flags: u8,
    pub ctype: CtrlType,
    /// Path this control message was sent on (echoed in NACK/KA for
    /// per-path book-keeping even if multiple paths carry the same
    /// flow).
    pub path_id: u8,
    pub flow_id: u32,
}

impl CtrlHeader {
    pub const SIZE: usize = 8;

    pub fn new(ctype: CtrlType, path_id: u8, flow_id: u32) -> Self {
        Self {
            version: CTRL_VERSION,
            flags: 0,
            ctype,
            path_id,
            flow_id,
        }
    }

    pub fn write_to(&self, out: &mut BytesMut) {
        out.put_u8(CTRL_MAGIC);
        out.put_u8(((self.version & 0x0F) << 4) | (self.flags & 0x0F));
        out.put_u8(self.ctype as u8);
        out.put_u8(self.path_id);
        out.put_u32(self.flow_id);
    }

    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < Self::SIZE {
            return Err(BondError::PacketTooShort {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        let mut r = &buf[..Self::SIZE];
        let magic = r.get_u8();
        if magic != CTRL_MAGIC {
            return Err(BondError::InvalidMagic {
                expected: CTRL_MAGIC as u32,
                actual: magic as u32,
            });
        }
        let vf = r.get_u8();
        let version = (vf >> 4) & 0x0F;
        let flags = vf & 0x0F;
        if version != CTRL_VERSION {
            return Err(BondError::UnsupportedVersion(version));
        }
        let ctype_raw = r.get_u8();
        let ctype = CtrlType::from_u8(ctype_raw)
            .ok_or_else(|| BondError::Other(format!("unknown ctrl type {}", ctype_raw)))?;
        let path_id = r.get_u8();
        let flow_id = r.get_u32();
        Ok((
            Self {
                version,
                flags,
                ctype,
                path_id,
                flow_id,
            },
            Self::SIZE,
        ))
    }
}

// ── Keepalive ───────────────────────────────────────────────────────────────

/// Keepalive ping body (after [`CtrlHeader`]).
///
/// - `stamp_us` — opaque monotonic microsecond counter chosen by the
///   sender, echoed verbatim in the Ack so the sender can compute RTT.
/// - `packets_sent_on_path` — total data packets emitted on this path.
///   Subtracting the receiver-side counter (in the Ack) gives loss.
/// - `highest_bond_seq_sent` — the sender's current tip of the
///   bond_seq space, across all paths. Critical for tail-gap
///   detection: if no new data arrives and the receiver's highest
///   seen seq trails this value, the receiver NACKs the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveBody {
    pub stamp_us: u64,
    pub packets_sent_on_path: u64,
    pub highest_bond_seq_sent: u32,
}

impl KeepaliveBody {
    pub const SIZE: usize = 20;

    pub fn write_to(&self, out: &mut BytesMut) {
        out.put_u64(self.stamp_us);
        out.put_u64(self.packets_sent_on_path);
        out.put_u32(self.highest_bond_seq_sent);
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(BondError::PacketTooShort {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        let mut r = &buf[..Self::SIZE];
        Ok(Self {
            stamp_us: r.get_u64(),
            packets_sent_on_path: r.get_u64(),
            highest_bond_seq_sent: r.get_u32(),
        })
    }
}

/// Keepalive acknowledgement body.
///
/// Echoes `stamp_us` so the sender can compute one-way + RTT.
/// `packets_received_on_path` is the receiver's counter; subtracting
/// the ping's `packets_sent_on_path` gives instantaneous loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveAckBody {
    pub stamp_us: u64,
    pub packets_sent_on_path: u64,
    pub packets_received_on_path: u64,
}

impl KeepaliveAckBody {
    pub const SIZE: usize = 24;

    pub fn write_to(&self, out: &mut BytesMut) {
        out.put_u64(self.stamp_us);
        out.put_u64(self.packets_sent_on_path);
        out.put_u64(self.packets_received_on_path);
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(BondError::PacketTooShort {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        let mut r = &buf[..Self::SIZE];
        Ok(Self {
            stamp_us: r.get_u64(),
            packets_sent_on_path: r.get_u64(),
            packets_received_on_path: r.get_u64(),
        })
    }
}

// ── NACK ────────────────────────────────────────────────────────────────────

/// NACK body: count + list of missing bond_seqs.
///
/// Receiver emits this when a gap ages past its NACK timer. Sender
/// looks each seq up in its retransmit buffer and re-emits via the
/// scheduler's current path selection. Up to `MAX_NACK_ENTRIES` seqs
/// per message to keep datagrams sane on narrow paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NackBody {
    pub missing: Vec<u32>,
}

impl NackBody {
    /// Cap on seqs per NACK message. One datagram carries up to this
    /// many — receivers that want more emit multiple messages.
    pub const MAX_NACK_ENTRIES: usize = 128;

    /// Size in bytes on the wire: 2-byte count + 4 bytes per entry.
    pub fn wire_size(&self) -> usize {
        2 + 4 * self.missing.len()
    }

    pub fn write_to(&self, out: &mut BytesMut) {
        let count = self.missing.len().min(u16::MAX as usize) as u16;
        out.put_u16(count);
        for seq in self.missing.iter().take(count as usize) {
            out.put_u32(*seq);
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(BondError::PacketTooShort {
                expected: 2,
                actual: buf.len(),
            });
        }
        let mut r = &buf[..];
        let count = r.get_u16() as usize;
        let needed = count * 4;
        if r.remaining() < needed {
            return Err(BondError::PacketTooShort {
                expected: 2 + needed,
                actual: buf.len(),
            });
        }
        let mut missing = Vec::with_capacity(count);
        for _ in 0..count {
            missing.push(r.get_u32());
        }
        Ok(Self { missing })
    }
}

// ── Framing helpers ─────────────────────────────────────────────────────────

/// High-level control packet. Construct, call [`serialize`], put on
/// the wire. Construct from a parsed header + body via [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtrlPacket {
    Keepalive {
        header: CtrlHeader,
        body: KeepaliveBody,
    },
    KeepaliveAck {
        header: CtrlHeader,
        body: KeepaliveAckBody,
    },
    Nack {
        header: CtrlHeader,
        body: NackBody,
    },
    Goodbye {
        header: CtrlHeader,
    },
}

impl CtrlPacket {
    pub fn serialize(&self, out: &mut BytesMut) {
        out.clear();
        match self {
            CtrlPacket::Keepalive { header, body } => {
                out.reserve(CtrlHeader::SIZE + KeepaliveBody::SIZE);
                header.write_to(out);
                body.write_to(out);
            }
            CtrlPacket::KeepaliveAck { header, body } => {
                out.reserve(CtrlHeader::SIZE + KeepaliveAckBody::SIZE);
                header.write_to(out);
                body.write_to(out);
            }
            CtrlPacket::Nack { header, body } => {
                out.reserve(CtrlHeader::SIZE + body.wire_size());
                header.write_to(out);
                body.write_to(out);
            }
            CtrlPacket::Goodbye { header } => {
                out.reserve(CtrlHeader::SIZE);
                header.write_to(out);
            }
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        let (header, consumed) = CtrlHeader::parse(buf)?;
        let body_buf = &buf[consumed..];
        match header.ctype {
            CtrlType::Keepalive => Ok(CtrlPacket::Keepalive {
                header,
                body: KeepaliveBody::parse(body_buf)?,
            }),
            CtrlType::KeepaliveAck => Ok(CtrlPacket::KeepaliveAck {
                header,
                body: KeepaliveAckBody::parse(body_buf)?,
            }),
            CtrlType::Nack => Ok(CtrlPacket::Nack {
                header,
                body: NackBody::parse(body_buf)?,
            }),
            CtrlType::Goodbye => Ok(CtrlPacket::Goodbye { header }),
        }
    }
}

/// Peek at the first byte to decide whether a datagram is bond data
/// (`0xBC`) or bond control (`0xBE`). Returns `true` for control.
#[inline]
pub fn is_control(buf: &[u8]) -> bool {
    buf.first().copied() == Some(CTRL_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_roundtrip() {
        let header = CtrlHeader::new(CtrlType::Keepalive, 2, 0xdead_beef);
        let body = KeepaliveBody {
            stamp_us: 123_456_789,
            packets_sent_on_path: 10_000,
            highest_bond_seq_sent: 12_345_678,
        };
        let pkt = CtrlPacket::Keepalive { header, body };

        let mut buf = BytesMut::new();
        pkt.serialize(&mut buf);
        assert_eq!(buf.len(), CtrlHeader::SIZE + KeepaliveBody::SIZE);
        assert_eq!(buf[0], CTRL_MAGIC);

        let parsed = CtrlPacket::parse(&buf).unwrap();
        assert_eq!(parsed, pkt);
        assert!(is_control(&buf));
    }

    #[test]
    fn keepalive_ack_roundtrip() {
        let header = CtrlHeader::new(CtrlType::KeepaliveAck, 1, 42);
        let body = KeepaliveAckBody {
            stamp_us: 999,
            packets_sent_on_path: 1000,
            packets_received_on_path: 995,
        };
        let pkt = CtrlPacket::KeepaliveAck { header, body };
        let mut buf = BytesMut::new();
        pkt.serialize(&mut buf);
        let parsed = CtrlPacket::parse(&buf).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn nack_roundtrip() {
        let header = CtrlHeader::new(CtrlType::Nack, 3, 7);
        let body = NackBody {
            missing: vec![100, 101, 102, 200, 300, u32::MAX - 1],
        };
        let pkt = CtrlPacket::Nack { header, body };
        let mut buf = BytesMut::new();
        pkt.serialize(&mut buf);
        let parsed = CtrlPacket::parse(&buf).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn goodbye_roundtrip() {
        let header = CtrlHeader::new(CtrlType::Goodbye, 0, 0);
        let pkt = CtrlPacket::Goodbye { header };
        let mut buf = BytesMut::new();
        pkt.serialize(&mut buf);
        assert_eq!(buf.len(), CtrlHeader::SIZE);
        let parsed = CtrlPacket::parse(&buf).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn data_vs_control_magic_disjoint() {
        let data_magic = crate::packet::MAGIC;
        assert_ne!(data_magic, CTRL_MAGIC);
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = [0xBCu8; CtrlHeader::SIZE];
        let err = CtrlHeader::parse(&buf).unwrap_err();
        match err {
            BondError::InvalidMagic { .. } => {}
            e => panic!("expected InvalidMagic, got {e:?}"),
        }
    }

    #[test]
    fn rejects_bad_ctrl_type() {
        let mut buf = BytesMut::new();
        let h = CtrlHeader::new(CtrlType::Keepalive, 0, 0);
        h.write_to(&mut buf);
        // Corrupt the ctype byte
        buf[2] = 99;
        let err = CtrlHeader::parse(&buf).unwrap_err();
        match err {
            BondError::Other(_) => {}
            e => panic!("expected Other, got {e:?}"),
        }
    }
}
