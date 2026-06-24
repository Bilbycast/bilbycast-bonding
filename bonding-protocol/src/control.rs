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
    /// Total data **bytes** emitted on this path (v2 extension). Diffed
    /// against the receiver echo so the sender can compute a windowed
    /// delivered-bitrate per path for the capacity controller. 0 on a
    /// v1 peer that doesn't carry the field.
    pub bytes_sent_on_path: u64,
    /// Sender session epoch (v3 extension). Nonzero random u32 chosen
    /// once per sender instance. A receiver anchored to a previous
    /// instance's seq space adopts a *different* nonzero epoch (after
    /// 2 consecutive control packets carry it) by resetting its
    /// reassembly state — otherwise a restarted sender's seqs drop as
    /// stale forever. 0 on a v1/v2 peer.
    pub session_epoch: u32,
    /// Sender→receiver mode flags (v4 extension). Bit
    /// [`KA_FLAG_ALIGN_SUPPRESS`]: this bond is in a *ride-fastest*
    /// (duplicate-all redundancy) mode, so the receiver MUST NOT
    /// time-align legs — holding the fast copy to align a slow duplicate
    /// defeats the whole point. The sender owns the redundancy policy;
    /// the receiver applies alignment; so the intent has to ride the
    /// keepalive. 0 on a v1/v2/v3 peer (→ align as normal).
    pub mode_flags: u8,
}

/// [`KeepaliveBody::mode_flags`] bit: suppress receiver-side per-leg
/// equalization (ride-fastest / duplicate-all redundancy).
pub const KA_FLAG_ALIGN_SUPPRESS: u8 = 0x01;

impl KeepaliveBody {
    /// Base (v1) wire size; the v2 byte-counter is appended after this
    /// and parsed defensively so a mixed-version bond never desyncs.
    pub const SIZE: usize = 20;
    /// v2 wire size (base + `bytes_sent_on_path`).
    pub const SIZE_V2: usize = 28;
    /// Full v3 wire size (v2 + `session_epoch`).
    pub const SIZE_V3: usize = 32;
    /// v4 wire size (v3 + `mode_flags`).
    pub const SIZE_V4: usize = 33;

    pub fn write_to(&self, out: &mut BytesMut) {
        out.put_u64(self.stamp_us);
        out.put_u64(self.packets_sent_on_path);
        out.put_u32(self.highest_bond_seq_sent);
        out.put_u64(self.bytes_sent_on_path);
        out.put_u32(self.session_epoch);
        out.put_u8(self.mode_flags);
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(BondError::PacketTooShort {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        let mut r = &buf[..];
        let stamp_us = r.get_u64();
        let packets_sent_on_path = r.get_u64();
        let highest_bond_seq_sent = r.get_u32();
        // v2/v3/v4 extensions — present iff the peer wrote them.
        let bytes_sent_on_path = if r.remaining() >= 8 { r.get_u64() } else { 0 };
        let session_epoch = if r.remaining() >= 4 { r.get_u32() } else { 0 };
        let mode_flags = if r.remaining() >= 1 { r.get_u8() } else { 0 };
        Ok(Self {
            stamp_us,
            packets_sent_on_path,
            highest_bond_seq_sent,
            bytes_sent_on_path,
            session_epoch,
            mode_flags,
        })
    }

    /// True when the sender signalled ride-fastest (duplicate-all) — the
    /// receiver suppresses per-leg equalization.
    #[inline]
    pub fn align_suppressed(&self) -> bool {
        self.mode_flags & KA_FLAG_ALIGN_SUPPRESS != 0
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
    /// Total data **bytes** received on this path (v2 extension). With
    /// the ping's `bytes_sent_on_path` and successive-ack diffing this
    /// yields a windowed per-path delivered bitrate. 0 on a v1 peer.
    pub bytes_received_on_path: u64,
    /// Receiver-measured interarrival jitter on this path, microseconds
    /// (RFC 3550 A.8 style, v2 extension). 0 on a v1 peer.
    pub jitter_us: u32,
    /// Echo of the receiver's currently-adopted session epoch (v3
    /// extension) — diagnostic mirror of [`KeepaliveBody::session_epoch`]
    /// so a sender can observe adoption. 0 until adopted / on a v1/v2
    /// peer.
    pub session_epoch: u32,
    /// Receiver-measured **relative one-way delay** for this path, in
    /// microseconds (v4 extension, per-leg equalization). This is the
    /// leg's windowed-min OWD *minus the fastest eligible leg's* — i.e.
    /// how much later this leg's packets land than the quickest leg, the
    /// equalization the sender must account for. `u32::MAX` is a sentinel
    /// for "un-equalizable / not measured". 0 on a v1/v2/v3 peer (the
    /// sender then falls back to its local jitter heuristic).
    pub relative_owd_us: u32,
    /// The **receiver's** advertised bond data-header version (v5
    /// extension, per-leg equalization rollout safety). The receiver
    /// sets this to [`crate::packet::PROTOCOL_VERSION_V2`] only when it
    /// both speaks v2 *and* has equalization enabled — i.e. "you may
    /// send me v2 (16-byte, send-stamped) data headers on this leg".
    /// A sender MUST NOT emit v2 data headers until it has seen a
    /// keepalive-ack reporting `>= PROTOCOL_VERSION_V2` on that leg;
    /// otherwise a genuinely-old (pre-v2) receiver hits
    /// `BondError::UnsupportedVersion` and silently drops every media
    /// packet. Defaults to [`crate::packet::PROTOCOL_VERSION`] (1) on a
    /// v1/v2/v3/v4 peer that never wrote the field — keeping the bond on
    /// v1 headers, which every build can parse.
    pub recv_protocol_version: u16,
}

impl KeepaliveAckBody {
    /// Base (v1) wire size; v2/v3/v4 fields are appended and parsed
    /// defensively.
    pub const SIZE: usize = 24;
    /// v2 wire size (base + bytes + jitter).
    pub const SIZE_V2: usize = 36;
    /// v3 wire size (v2 + `session_epoch`).
    pub const SIZE_V3: usize = 40;
    /// v4 wire size (v3 + `relative_owd_us`).
    pub const SIZE_V4: usize = 44;
    /// v5 wire size (v4 + `recv_protocol_version`).
    pub const SIZE_V5: usize = 46;

    pub fn write_to(&self, out: &mut BytesMut) {
        out.put_u64(self.stamp_us);
        out.put_u64(self.packets_sent_on_path);
        out.put_u64(self.packets_received_on_path);
        out.put_u64(self.bytes_received_on_path);
        out.put_u32(self.jitter_us);
        out.put_u32(self.session_epoch);
        out.put_u32(self.relative_owd_us);
        out.put_u16(self.recv_protocol_version);
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(BondError::PacketTooShort {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        let mut r = &buf[..];
        let stamp_us = r.get_u64();
        let packets_sent_on_path = r.get_u64();
        let packets_received_on_path = r.get_u64();
        // v2/v3/v4 extensions — present iff the peer wrote them.
        let bytes_received_on_path = if r.remaining() >= 8 { r.get_u64() } else { 0 };
        let jitter_us = if r.remaining() >= 4 { r.get_u32() } else { 0 };
        let session_epoch = if r.remaining() >= 4 { r.get_u32() } else { 0 };
        let relative_owd_us = if r.remaining() >= 4 { r.get_u32() } else { 0 };
        // v5: a peer that never wrote this field is pre-equalization (or
        // equalization-disabled) — default it to v1 so the sender keeps
        // emitting v1 data headers and never bricks an old receiver.
        let recv_protocol_version = if r.remaining() >= 2 {
            r.get_u16()
        } else {
            crate::packet::PROTOCOL_VERSION as u16
        };
        Ok(Self {
            stamp_us,
            packets_sent_on_path,
            packets_received_on_path,
            bytes_received_on_path,
            jitter_us,
            session_epoch,
            relative_owd_us,
            recv_protocol_version,
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
                out.reserve(CtrlHeader::SIZE + KeepaliveBody::SIZE_V4);
                header.write_to(out);
                body.write_to(out);
            }
            CtrlPacket::KeepaliveAck { header, body } => {
                out.reserve(CtrlHeader::SIZE + KeepaliveAckBody::SIZE_V5);
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
            bytes_sent_on_path: 13_160_000,
            session_epoch: 0x5e55_10e9,
            mode_flags: KA_FLAG_ALIGN_SUPPRESS,
        };
        let pkt = CtrlPacket::Keepalive { header, body };

        let mut buf = BytesMut::new();
        pkt.serialize(&mut buf);
        assert_eq!(buf.len(), CtrlHeader::SIZE + KeepaliveBody::SIZE_V4);
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
            bytes_received_on_path: 1_311_400,
            jitter_us: 1234,
            session_epoch: 0xfeed_f00d,
            relative_owd_us: 173_000,
            recv_protocol_version: crate::packet::PROTOCOL_VERSION_V2 as u16,
        };
        let pkt = CtrlPacket::KeepaliveAck { header, body };
        let mut buf = BytesMut::new();
        pkt.serialize(&mut buf);
        let parsed = CtrlPacket::parse(&buf).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn older_bodies_parse_without_extensions() {
        // A v1/v2 peer ships only its known fields; truncating a
        // serialized v3 body to those lengths must parse with the newer
        // fields defaulting to 0 (forward/backward compatibility — both
        // ends are edge but a mixed-version rollout must never desync).
        let ka = KeepaliveBody {
            stamp_us: 1,
            packets_sent_on_path: 2,
            highest_bond_seq_sent: 3,
            bytes_sent_on_path: 4,
            session_epoch: 5,
            mode_flags: KA_FLAG_ALIGN_SUPPRESS,
        };
        let mut buf = BytesMut::new();
        ka.write_to(&mut buf);
        let v1 = KeepaliveBody::parse(&buf[..KeepaliveBody::SIZE]).unwrap();
        assert_eq!(v1.bytes_sent_on_path, 0);
        assert_eq!(v1.session_epoch, 0);
        assert_eq!(v1.packets_sent_on_path, 2);
        assert_eq!(v1.mode_flags, 0);
        let v2 = KeepaliveBody::parse(&buf[..KeepaliveBody::SIZE_V2]).unwrap();
        assert_eq!(v2.bytes_sent_on_path, 4);
        assert_eq!(v2.session_epoch, 0);
        assert_eq!(v2.mode_flags, 0);
        let v3 = KeepaliveBody::parse(&buf[..KeepaliveBody::SIZE_V3]).unwrap();
        assert_eq!(v3.bytes_sent_on_path, 4);
        assert_eq!(v3.session_epoch, 5);
        assert_eq!(v3.mode_flags, 0, "v3 peer doesn't carry the v4 mode_flags");
        let v4 = KeepaliveBody::parse(&buf).unwrap();
        assert_eq!(v4.session_epoch, 5);
        assert!(v4.align_suppressed());

        let ack = KeepaliveAckBody {
            stamp_us: 9,
            packets_sent_on_path: 10,
            packets_received_on_path: 11,
            bytes_received_on_path: 12,
            jitter_us: 13,
            session_epoch: 14,
            relative_owd_us: 15,
            recv_protocol_version: crate::packet::PROTOCOL_VERSION_V2 as u16,
        };
        let mut abuf = BytesMut::new();
        ack.write_to(&mut abuf);
        let a1 = KeepaliveAckBody::parse(&abuf[..KeepaliveAckBody::SIZE]).unwrap();
        assert_eq!(a1.bytes_received_on_path, 0);
        assert_eq!(a1.jitter_us, 0);
        assert_eq!(a1.session_epoch, 0);
        assert_eq!(a1.relative_owd_us, 0);
        assert_eq!(a1.packets_received_on_path, 11);
        // A pre-v5 peer never wrote recv_protocol_version → defaults to v1,
        // so a sender keeps emitting v1 data headers and never bricks it.
        assert_eq!(a1.recv_protocol_version, crate::packet::PROTOCOL_VERSION as u16);
        let a2 = KeepaliveAckBody::parse(&abuf[..KeepaliveAckBody::SIZE_V2]).unwrap();
        assert_eq!(a2.bytes_received_on_path, 12);
        assert_eq!(a2.jitter_us, 13);
        assert_eq!(a2.session_epoch, 0);
        assert_eq!(a2.relative_owd_us, 0);
        assert_eq!(a2.recv_protocol_version, crate::packet::PROTOCOL_VERSION as u16);
        let a3 = KeepaliveAckBody::parse(&abuf[..KeepaliveAckBody::SIZE_V3]).unwrap();
        assert_eq!(a3.jitter_us, 13);
        assert_eq!(a3.session_epoch, 14);
        assert_eq!(a3.relative_owd_us, 0, "v3 peer doesn't carry the v4 field");
        assert_eq!(a3.recv_protocol_version, crate::packet::PROTOCOL_VERSION as u16);
        let a4 = KeepaliveAckBody::parse(&abuf[..KeepaliveAckBody::SIZE_V4]).unwrap();
        assert_eq!(a4.session_epoch, 14);
        assert_eq!(a4.relative_owd_us, 15);
        assert_eq!(
            a4.recv_protocol_version,
            crate::packet::PROTOCOL_VERSION as u16,
            "v4 peer doesn't carry the v5 field"
        );
        let a5 = KeepaliveAckBody::parse(&abuf).unwrap();
        assert_eq!(a5.session_epoch, 14);
        assert_eq!(a5.relative_owd_us, 15);
        assert_eq!(
            a5.recv_protocol_version,
            crate::packet::PROTOCOL_VERSION_V2 as u16
        );
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
