//! Proactive forward-error-correction for the bond — interleaved XOR
//! parity (SMPTE 2022-1 column model).
//!
//! ARQ recovers losses but costs a NACK round-trip; on a high-RTT
//! Starlink leg that can exceed the reassembly hold-time. FEC adds a
//! *proactive* repair layer so sparse loss is recovered with **no**
//! round-trip. It is **opt-in / off by default** — multi-path diversity
//! + ARQ + IDR-duplication already cover most cases, and FEC trades
//! bandwidth (overhead `1/rows`) for latency.
//!
//! ## Scheme
//!
//! Source packets in a block of `columns × rows` are arranged column-
//! major. One XOR **repair** packet is emitted per column, covering the
//! `rows` source packets at stride `columns`:
//!
//! ```text
//! columns = 4, rows = 3   (block = 12 source seqs, base B)
//!   col 0:  B+0  B+4  B+8     -> repair(col 0)
//!   col 1:  B+1  B+5  B+9     -> repair(col 1)
//!   col 2:  B+2  B+6  B+10    -> repair(col 2)
//!   col 3:  B+3  B+7  B+11    -> repair(col 3)
//! ```
//!
//! Any **single** loss within a column is recovered by XOR. Because
//! columns interleave the seq space, a *burst* of up to `columns`
//! consecutive losses hits at most one packet per column and is fully
//! recovered. Two losses in the same column fall through to ARQ.
//!
//! Repair packets ride the normal bond datagram with the FEC header
//! flag set; they do **not** consume media `bond_seq` space (the
//! receiver routes them to the decoder before the reassembly buffer).
//!
//! Pure / no-I-O — lives in `bonding-protocol` like the reassembly
//! buffer. The transport feeds originals in, emits repairs, and pushes
//! recovered packets into the reassembly buffer as late arrivals.

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// FEC geometry. `columns` = interleave depth (burst tolerance);
/// `rows` = packets per column (overhead is `1/rows`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecParams {
    pub columns: u16,
    pub rows: u16,
}

impl FecParams {
    /// Block size in source packets.
    #[inline]
    pub fn block(&self) -> u32 {
        self.columns as u32 * self.rows as u32
    }
    /// Valid geometry: both ≥ 1, rows ≥ 2 (a 1-row "column" can't
    /// recover anything), block bounded so a stalled block can't pin
    /// unbounded memory.
    pub fn is_valid(&self) -> bool {
        self.columns >= 1 && self.rows >= 2 && self.block() <= 4096
    }
}

/// A parsed repair packet (after the bond header, FEC flag set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecRepair {
    pub base_seq: u32,
    pub columns: u16,
    pub rows: u16,
    pub column: u16,
    /// XOR of the column's source blocks. Length is `block_len` =
    /// `2 + max_source_payload_len` in the group.
    pub block: Bytes,
}

impl FecRepair {
    /// Wire header bytes before the XOR block.
    const HDR: usize = 4 + 2 + 2 + 2 + 2;

    pub fn serialize(&self, out: &mut BytesMut) {
        out.clear();
        out.reserve(Self::HDR + self.block.len());
        out.put_u32(self.base_seq);
        out.put_u16(self.columns);
        out.put_u16(self.rows);
        out.put_u16(self.column);
        out.put_u16(self.block.len() as u16);
        out.put_slice(&self.block);
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::HDR {
            return None;
        }
        let mut r = &buf[..Self::HDR];
        let base_seq = r.get_u32();
        let columns = r.get_u16();
        let rows = r.get_u16();
        let column = r.get_u16();
        let block_len = r.get_u16() as usize;
        if buf.len() < Self::HDR + block_len {
            return None;
        }
        Some(Self {
            base_seq,
            columns,
            rows,
            column,
            block: Bytes::copy_from_slice(&buf[Self::HDR..Self::HDR + block_len]),
        })
    }
}

/// Build the fixed-size XOR block for one source packet:
/// `[u16 payload_len][payload][zero pad to block_len]`.
fn source_block(payload: &[u8], block_len: usize, out: &mut [u8]) {
    debug_assert!(block_len >= 2 + payload.len());
    for b in out.iter_mut() {
        *b = 0;
    }
    out[0] = (payload.len() >> 8) as u8;
    out[1] = (payload.len() & 0xFF) as u8;
    out[2..2 + payload.len()].copy_from_slice(payload);
}

#[inline]
fn xor_into(acc: &mut [u8], other: &[u8]) {
    for (a, b) in acc.iter_mut().zip(other.iter()) {
        *a ^= *b;
    }
}

// ── Encoder ──────────────────────────────────────────────────────────────────

/// Sender-side FEC encoder. Feed it each original `(seq, payload)` in
/// ascending seq order (originals only — not retransmits); it returns
/// repair packets at column completion. Blocks anchor at multiples of
/// `block()` (the bond's media seq starts at 0).
pub struct FecEncoder {
    params: FecParams,
    block_base: u32,
    /// Per-column accumulated source payloads for the current block.
    columns: Vec<Vec<Bytes>>,
    /// Whether the column's repair has already been emitted this block.
    emitted: Vec<bool>,
    started: bool,
}

impl FecEncoder {
    pub fn new(params: FecParams) -> Self {
        let l = params.columns as usize;
        Self {
            params,
            block_base: 0,
            columns: vec![Vec::with_capacity(params.rows as usize); l],
            emitted: vec![false; l],
            started: false,
        }
    }

    fn reset_block(&mut self, base: u32) {
        self.block_base = base;
        for c in &mut self.columns {
            c.clear();
        }
        for e in &mut self.emitted {
            *e = false;
        }
    }

    /// Push one original packet; returns any repair packets that became
    /// complete. Usually empty; one repair when a column fills.
    pub fn push(&mut self, seq: u32, payload: &Bytes) -> Vec<FecRepair> {
        let block = self.params.block();
        if !self.started {
            self.started = true;
            // Anchor to the block containing this seq.
            self.reset_block(seq - (seq % block));
        }
        // Discontinuity (gap or rollover) — restart cleanly on this seq's
        // block rather than mis-attribute it.
        let off = seq.wrapping_sub(self.block_base);
        if off >= block {
            self.reset_block(seq - (seq % block));
        }
        let off = (seq - self.block_base) as usize;
        let col = off % self.params.columns as usize;
        let mut out = Vec::new();
        self.columns[col].push(payload.clone());

        if self.columns[col].len() == self.params.rows as usize && !self.emitted[col] {
            self.emitted[col] = true;
            out.push(self.build_repair(col));
        }

        // Advance to the next block once every column has emitted.
        if self.emitted.iter().all(|&e| e) {
            self.reset_block(self.block_base.wrapping_add(block));
        }
        out
    }

    fn build_repair(&self, col: usize) -> FecRepair {
        let max_payload = self.columns[col].iter().map(|b| b.len()).max().unwrap_or(0);
        let block_len = 2 + max_payload;
        let mut acc = vec![0u8; block_len];
        let mut scratch = vec![0u8; block_len];
        for p in &self.columns[col] {
            source_block(p, block_len, &mut scratch);
            xor_into(&mut acc, &scratch);
        }
        FecRepair {
            base_seq: self.block_base,
            columns: self.params.columns,
            rows: self.params.rows,
            column: col as u16,
            block: Bytes::from(acc),
        }
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

struct BlockState {
    columns: u16,
    rows: u16,
    /// Source payloads present, keyed by their offset-within-block.
    sources: std::collections::HashMap<u32, Bytes>,
    /// Repair block per column.
    repairs: std::collections::HashMap<u16, Bytes>,
    /// Offsets already recovered/emitted so we don't double-emit.
    recovered: std::collections::HashSet<u32>,
}

/// Receiver-side FEC decoder. Feed every arriving original to
/// [`Self::push_source`] and every repair to [`Self::push_repair`];
/// both return any `(seq, payload)` recovered as a side effect. Keeps a
/// bounded window of recent blocks.
pub struct FecDecoder {
    params: FecParams,
    blocks: std::collections::BTreeMap<u32, BlockState>,
    max_blocks: usize,
}

impl FecDecoder {
    pub fn new(params: FecParams) -> Self {
        Self {
            params,
            blocks: std::collections::BTreeMap::new(),
            max_blocks: 8,
        }
    }

    #[inline]
    fn base_of(&self, seq: u32) -> u32 {
        let block = self.params.block();
        seq - (seq % block)
    }

    /// Drop all in-flight block state — the session-reset path for a
    /// restarted sender. Blocks keyed on the old seq space would never
    /// complete, and a late recovery against them would emit wrong
    /// seqs into the freshly re-anchored reassembly buffer.
    pub fn reset(&mut self) {
        self.blocks.clear();
    }

    fn block_mut(&mut self, base: u32, columns: u16, rows: u16) -> &mut BlockState {
        self.blocks.entry(base).or_insert_with(|| BlockState {
            columns,
            rows,
            sources: std::collections::HashMap::new(),
            repairs: std::collections::HashMap::new(),
            recovered: std::collections::HashSet::new(),
        })
    }

    /// Drop the oldest blocks once the window is exceeded.
    fn prune(&mut self) {
        while self.blocks.len() > self.max_blocks {
            let oldest = *self.blocks.keys().next().unwrap();
            self.blocks.remove(&oldest);
        }
    }

    /// Record an arriving original. Returns any packet recovered because
    /// this arrival completed a column that had its repair.
    pub fn push_source(&mut self, seq: u32, payload: &Bytes) -> Vec<(u32, Bytes)> {
        let base = self.base_of(seq);
        let cols = self.params.columns;
        let rows = self.params.rows;
        let off = seq - base;
        let col = (off % cols as u32) as u16;
        {
            let b = self.block_mut(base, cols, rows);
            b.sources.insert(off, payload.clone());
        }
        let out = self.attempt(base, col);
        self.prune();
        out
    }

    /// Record an arriving repair. Returns any packet it recovers.
    pub fn push_repair(&mut self, r: FecRepair) -> Vec<(u32, Bytes)> {
        // Only accept repairs matching our configured geometry.
        if r.columns != self.params.columns || r.rows != self.params.rows {
            return Vec::new();
        }
        let base = r.base_seq;
        let col = r.column;
        {
            let b = self.block_mut(base, r.columns, r.rows);
            b.repairs.insert(col, r.block);
        }
        let out = self.attempt(base, col);
        self.prune();
        out
    }

    /// Try to recover the single missing source in `(base, col)`.
    fn attempt(&mut self, base: u32, col: u16) -> Vec<(u32, Bytes)> {
        let Some(b) = self.blocks.get(&base) else {
            return Vec::new();
        };
        let Some(repair) = b.repairs.get(&col).cloned() else {
            return Vec::new();
        };
        let cols = b.columns as u32;
        let rows = b.rows as u32;
        let block_len = repair.len();

        // Offsets of the `rows` sources in this column.
        let mut present: Vec<(u32, Bytes)> = Vec::new();
        let mut missing: Vec<u32> = Vec::new();
        for k in 0..rows {
            let off = col as u32 + k * cols;
            match b.sources.get(&off) {
                Some(p) => present.push((off, p.clone())),
                None => missing.push(off),
            }
        }
        // Exactly one missing and not already recovered → XOR it back.
        if missing.len() != 1 || b.recovered.contains(&missing[0]) {
            return Vec::new();
        }
        let miss_off = missing[0];
        // Guard: a present source longer than the repair block can't be
        // a valid group member — bail rather than corrupt.
        if present.iter().any(|(_, p)| 2 + p.len() > block_len) {
            return Vec::new();
        }

        let mut acc = repair.to_vec();
        let mut scratch = vec![0u8; block_len];
        for (_, p) in &present {
            source_block(p, block_len, &mut scratch);
            xor_into(&mut acc, &scratch);
        }
        // acc now holds [u16 len][payload][pad] for the missing source.
        let len = ((acc[0] as usize) << 8) | acc[1] as usize;
        if 2 + len > block_len {
            return Vec::new();
        }
        let payload = Bytes::copy_from_slice(&acc[2..2 + len]);
        let recovered_seq = base.wrapping_add(miss_off);

        let b = self.blocks.get_mut(&base).unwrap();
        b.recovered.insert(miss_off);
        b.sources.insert(miss_off, payload.clone());
        vec![(recovered_seq, payload)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(n: u8, len: usize) -> Bytes {
        Bytes::from(vec![n; len])
    }

    /// Encode a block, drop one source, recover it via the repair.
    #[test]
    fn recovers_single_loss_in_column() {
        let params = FecParams { columns: 3, rows: 3 };
        let mut enc = FecEncoder::new(params);
        let mut dec = FecDecoder::new(params);

        // Block = 9 packets, seqs 0..9.
        let mut repairs = Vec::new();
        let payloads: Vec<Bytes> = (0..9).map(|i| pkt(i as u8 + 1, 50 + i)).collect();
        for (seq, p) in payloads.iter().enumerate() {
            repairs.extend(enc.push(seq as u32, p));
        }
        assert_eq!(repairs.len(), 3, "one repair per column");

        // Deliver all sources EXCEPT seq 4 (column 1, row 1).
        for (seq, p) in payloads.iter().enumerate() {
            if seq == 4 {
                continue;
            }
            let rec = dec.push_source(seq as u32, p);
            assert!(rec.is_empty(), "no recovery before the repair / while complete");
        }
        // Now feed the repair for column 1 → seq 4 recovered.
        let col1 = repairs.iter().find(|r| r.column == 1).unwrap().clone();
        let rec = dec.push_repair(col1);
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].0, 4);
        assert_eq!(rec[0].1, payloads[4], "recovered payload matches original");
    }

    /// A burst of `columns` consecutive losses is fully recovered
    /// (interleaving puts each in a different column).
    #[test]
    fn recovers_consecutive_burst_up_to_columns() {
        let params = FecParams { columns: 4, rows: 3 };
        let mut enc = FecEncoder::new(params);
        let mut dec = FecDecoder::new(params);
        let payloads: Vec<Bytes> = (0..12).map(|i| pkt(i as u8 + 1, 40)).collect();
        let mut repairs = Vec::new();
        for (seq, p) in payloads.iter().enumerate() {
            repairs.extend(enc.push(seq as u32, p));
        }
        // Drop seqs 4,5,6,7 (one per column) — deliver the rest + all repairs.
        let dropped = [4u32, 5, 6, 7];
        for (seq, p) in payloads.iter().enumerate() {
            if dropped.contains(&(seq as u32)) {
                continue;
            }
            dec.push_source(seq as u32, p);
        }
        let mut recovered = std::collections::HashMap::new();
        for r in repairs {
            for (s, pl) in dec.push_repair(r) {
                recovered.insert(s, pl);
            }
        }
        for d in dropped {
            assert_eq!(
                recovered.get(&d),
                Some(&payloads[d as usize]),
                "burst seq {d} should recover"
            );
        }
    }

    /// Two losses in the same column are NOT recoverable (fall through
    /// to ARQ) — the other column still recovers its single loss.
    #[test]
    fn two_in_one_column_unrecoverable() {
        let params = FecParams { columns: 3, rows: 3 };
        let mut enc = FecEncoder::new(params);
        let mut dec = FecDecoder::new(params);
        let payloads: Vec<Bytes> = (0..9).map(|i| pkt(i as u8 + 1, 30)).collect();
        let mut repairs = Vec::new();
        for (seq, p) in payloads.iter().enumerate() {
            repairs.extend(enc.push(seq as u32, p));
        }
        // Drop seqs 0 and 3 (both column 0) + seq 1 (column 1).
        let dropped = [0u32, 3, 1];
        for (seq, p) in payloads.iter().enumerate() {
            if dropped.contains(&(seq as u32)) {
                continue;
            }
            dec.push_source(seq as u32, p);
        }
        let mut recovered = std::collections::HashMap::new();
        for r in repairs {
            for (s, pl) in dec.push_repair(r) {
                recovered.insert(s, pl);
            }
        }
        // Column 1's single loss (seq 1) recovers.
        assert_eq!(recovered.get(&1), Some(&payloads[1]));
        // Column 0's double loss does NOT.
        assert!(recovered.get(&0).is_none() && recovered.get(&3).is_none());
    }

    /// `reset` drops in-flight block state so a stale repair from the
    /// old session can't recover into the new seq space.
    #[test]
    fn decoder_reset_clears_inflight_blocks() {
        let params = FecParams { columns: 3, rows: 3 };
        let mut enc = FecEncoder::new(params);
        let mut dec = FecDecoder::new(params);
        let payloads: Vec<Bytes> = (0..9).map(|i| pkt(i as u8 + 1, 30)).collect();
        let mut repairs = Vec::new();
        for (seq, p) in payloads.iter().enumerate() {
            repairs.extend(enc.push(seq as u32, p));
        }
        // All sources except seq 4 delivered, then a session reset.
        for (seq, p) in payloads.iter().enumerate() {
            if seq != 4 {
                dec.push_source(seq as u32, p);
            }
        }
        dec.reset();
        // Without the pre-reset sources, the old block's repair finds
        // 3 missing in its column and recovers nothing.
        let col1 = repairs.iter().find(|r| r.column == 1).unwrap().clone();
        assert!(dec.push_repair(col1).is_empty());
    }

    #[test]
    fn repair_wire_roundtrip() {
        let r = FecRepair {
            base_seq: 12_000,
            columns: 5,
            rows: 4,
            column: 3,
            block: Bytes::from(vec![1, 2, 3, 4, 5, 6, 7]),
        };
        let mut buf = BytesMut::new();
        r.serialize(&mut buf);
        let parsed = FecRepair::parse(&buf).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn params_validation() {
        assert!(FecParams { columns: 10, rows: 10 }.is_valid());
        assert!(!FecParams { columns: 10, rows: 1 }.is_valid()); // rows<2 useless
        assert!(!FecParams { columns: 100, rows: 100 }.is_valid()); // block too big
    }
}
