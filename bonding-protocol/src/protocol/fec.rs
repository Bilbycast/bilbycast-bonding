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
        // `build_repair` always emits `2 + max_payload` bytes, so a block
        // shorter than the 2-byte length prefix is malformed — reject it here
        // rather than let `attempt` read `acc[0..2]` out of range.
        if block_len < 2 || buf.len() < Self::HDR + block_len {
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

// ── Per-leg FEC ────────────────────────────────────────────────────────────
//
// Combined FEC (above) protects the *global* bond sequence after the
// scheduler has already striped packets across legs. A burst loss on one
// leg (e.g. a Starlink satellite handoff) lands on the subset of bond_seqs
// that travelled that leg — a dense, correlated pattern in the global
// stream that readily puts 2+ losses in one column and falls through to
// ARQ. And one shared FEC budget means the worst leg starves every leg's
// protection.
//
// PER-LEG FEC fixes both: each leg runs its own encoder/decoder over only
// the packets that leg carries, so a leg burst is consecutive *in that
// leg's stream* → interleaved one-per-column → recovered locally, before it
// ever enters the combined reassembler. Each leg's FEC budget is dedicated;
// overhead goes where the loss is (heavy on Starlink, light on a clean ISP
// leg). ARQ stays combined + cross-leg for whatever per-leg FEC misses.
//
// Unlike combined FEC, the media packets are **unchanged on the wire** — a
// per-leg repair enumerates the exact `bond_seq`s it protects, so the
// receiver needs no per-leg sequence on every datagram and the hot send
// path (incl. retransmits / duplicates) is untouched. The receiver recovers
// the missing payload by XOR against the other members it has cached, then
// re-injects it into reassembly under its real `bond_seq`.

/// A per-leg repair packet: the XOR of one interleave column's members,
/// carrying the explicit `bond_seq`s it covers (the column's `rows`
/// members). Rides a normal FEC-flagged bond datagram on its own leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerLegRepair {
    pub columns: u16,
    pub rows: u16,
    /// The `bond_seq`s this repair protects (one interleave column).
    pub seqs: Vec<u32>,
    /// XOR of the members' `source_block`s. Length `2 + max_member_len`.
    pub block: Bytes,
}

impl PerLegRepair {
    /// `[u16 columns][u16 rows][u16 count][count×u32 seq][u16 block_len][block]`
    const FIXED_HDR: usize = 2 + 2 + 2;

    pub fn serialize(&self, out: &mut BytesMut) {
        out.clear();
        out.reserve(Self::FIXED_HDR + self.seqs.len() * 4 + 2 + self.block.len());
        out.put_u16(self.columns);
        out.put_u16(self.rows);
        out.put_u16(self.seqs.len() as u16);
        for s in &self.seqs {
            out.put_u32(*s);
        }
        out.put_u16(self.block.len() as u16);
        out.put_slice(&self.block);
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::FIXED_HDR {
            return None;
        }
        let mut r = &buf[..Self::FIXED_HDR];
        let columns = r.get_u16();
        let rows = r.get_u16();
        let count = r.get_u16() as usize;
        let mut off = Self::FIXED_HDR;
        if buf.len() < off + count * 4 + 2 {
            return None;
        }
        let mut seqs = Vec::with_capacity(count);
        for _ in 0..count {
            let mut s = &buf[off..off + 4];
            seqs.push(s.get_u32());
            off += 4;
        }
        let mut bl = &buf[off..off + 2];
        let block_len = bl.get_u16() as usize;
        off += 2;
        // Structural bounds. `build_per_leg_repair` emits a block of
        // `2 + max_member_len` (so >= 2) bytes and a group of exactly `rows`
        // members — and `rows >= 2` both by `FecParams::is_valid` and by the
        // edge's own config validation, which caps rows to [2, 64].
        //
        // `count < 2`, not `count == 0`: a zero-member repair is inert (the
        // `missing?` short-circuit drops it), but a ONE-member repair is the
        // actual primitive — with no other member to XOR against, it hands
        // `try_recover` a fully attacker-chosen (bond_seq, payload) pair that
        // the receiver then inserts into the reassembler as if it were
        // recovered media. Rejecting `block_len < 2` alone does not close it.
        if count < 2 || block_len < 2 || buf.len() < off + block_len {
            return None;
        }
        Some(Self {
            columns,
            rows,
            seqs,
            block: Bytes::copy_from_slice(&buf[off..off + block_len]),
        })
    }
}

/// Per-leg sender-side encoder. Feed it every packet sent on *this leg*
/// (originals, retransmits, duplicates alike — it protects the leg's wire
/// stream). Round-robins packets into `columns` interleave columns; emits a
/// repair when a column accumulates `rows` members.
pub struct PerLegFecEncoder {
    columns: u16,
    rows: u16,
    cols: Vec<Vec<(u32, Bytes)>>,
    idx: u32,
}

impl PerLegFecEncoder {
    pub fn new(params: FecParams) -> Self {
        let l = params.columns.max(1) as usize;
        Self {
            columns: params.columns,
            rows: params.rows,
            cols: vec![Vec::with_capacity(params.rows as usize); l],
            idx: 0,
        }
    }

    /// Feed one packet carried on this leg. Returns a repair once a column
    /// fills (usually `None`).
    pub fn push(&mut self, bond_seq: u32, payload: &Bytes) -> Option<PerLegRepair> {
        let c = (self.idx % self.columns.max(1) as u32) as usize;
        self.idx = self.idx.wrapping_add(1);
        self.cols[c].push((bond_seq, payload.clone()));
        if self.cols[c].len() >= self.rows as usize {
            let group = std::mem::take(&mut self.cols[c]);
            self.cols[c] = Vec::with_capacity(self.rows as usize);
            Some(build_per_leg_repair(self.columns, self.rows, &group))
        } else {
            None
        }
    }
}

fn build_per_leg_repair(columns: u16, rows: u16, group: &[(u32, Bytes)]) -> PerLegRepair {
    let max_payload = group.iter().map(|(_, b)| b.len()).max().unwrap_or(0);
    let block_len = 2 + max_payload;
    let mut acc = vec![0u8; block_len];
    let mut scratch = vec![0u8; block_len];
    for (_, p) in group {
        source_block(p, block_len, &mut scratch);
        xor_into(&mut acc, &scratch);
    }
    PerLegRepair {
        columns,
        rows,
        seqs: group.iter().map(|(s, _)| *s).collect(),
        block: Bytes::from(acc),
    }
}

/// Per-leg receiver-side decoder (one per FEC-enabled leg). Feed every
/// media packet arriving on *this leg* to [`Self::push_source`] and every
/// per-leg repair to [`Self::push_repair`]; both return any `(bond_seq,
/// payload)` recovered, ready to insert into the combined reassembler.
pub struct PerLegFecDecoder {
    /// Recent member payloads seen on this leg, for XOR reconstruction.
    seen: std::collections::HashMap<u32, Bytes>,
    order: std::collections::VecDeque<u32>,
    seen_cap: usize,
    /// Repairs that had >1 missing member when received — retried as the
    /// members trickle in. Bounded so a permanently-incomplete column
    /// can't pin memory.
    pending: std::collections::VecDeque<PerLegRepair>,
    pending_cap: usize,
    recovered: std::collections::HashSet<u32>,
}

impl PerLegFecDecoder {
    pub fn new(params: FecParams) -> Self {
        // Hold enough members to cover a column whose `rows` entries are
        // spread `columns` apart in the leg stream, with margin for
        // reordering across a few blocks.
        let span = (params.columns as usize) * (params.rows as usize);
        Self {
            seen: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            seen_cap: (span * 4).max(256),
            pending: std::collections::VecDeque::new(),
            pending_cap: 32,
            recovered: std::collections::HashSet::new(),
        }
    }

    /// Session-reset: drop all cached state so a stale repair from the old
    /// seq space can't recover wrong bytes into the re-anchored buffer.
    pub fn reset(&mut self) {
        self.seen.clear();
        self.order.clear();
        self.pending.clear();
        self.recovered.clear();
    }

    fn remember(&mut self, seq: u32, payload: Bytes) {
        if self.seen.insert(seq, payload).is_none() {
            self.order.push_back(seq);
            while self.order.len() > self.seen_cap {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                    self.recovered.remove(&old);
                }
            }
        }
    }

    /// Record a media packet seen on this leg. Returns any packet a pending
    /// repair can now recover because this arrival left it with a single
    /// hole.
    pub fn push_source(&mut self, bond_seq: u32, payload: &Bytes) -> Vec<(u32, Bytes)> {
        self.remember(bond_seq, payload.clone());
        self.retry_pending()
    }

    /// Record a per-leg repair arriving on this leg. Returns the recovered
    /// packet if exactly one member is missing, else stashes it for retry.
    pub fn push_repair(&mut self, r: PerLegRepair) -> Vec<(u32, Bytes)> {
        match self.try_recover(&r) {
            Some((seq, payload)) => {
                self.recovered.insert(seq);
                self.remember(seq, payload.clone());
                let mut out = vec![(seq, payload)];
                out.extend(self.retry_pending());
                out
            }
            None => {
                if self.pending.len() >= self.pending_cap {
                    self.pending.pop_front();
                }
                self.pending.push_back(r);
                Vec::new()
            }
        }
    }

    /// Re-evaluate stashed repairs (a freshly-arrived member may have made
    /// one recoverable). Cascades so a recovery that fills another repair's
    /// last hole also resolves.
    fn retry_pending(&mut self) -> Vec<(u32, Bytes)> {
        let mut out = Vec::new();
        loop {
            let mut progressed = false;
            let mut i = 0;
            while i < self.pending.len() {
                let r = self.pending[i].clone();
                if let Some((seq, payload)) = self.try_recover(&r) {
                    self.pending.remove(i);
                    self.recovered.insert(seq);
                    self.remember(seq, payload.clone());
                    out.push((seq, payload));
                    progressed = true;
                } else if r.seqs.iter().all(|s| self.seen.contains_key(s)) {
                    // Fully present (or already recovered) — nothing to do.
                    self.pending.remove(i);
                } else {
                    i += 1;
                }
            }
            if !progressed {
                break;
            }
        }
        out
    }

    fn try_recover(&self, r: &PerLegRepair) -> Option<(u32, Bytes)> {
        let mut present: Vec<&Bytes> = Vec::with_capacity(r.seqs.len());
        let mut missing: Option<u32> = None;
        for &s in &r.seqs {
            match self.seen.get(&s) {
                Some(p) => present.push(p),
                None => {
                    if missing.is_some() {
                        return None; // ≥2 missing — unrecoverable for now
                    }
                    missing = Some(s);
                }
            }
        }
        let miss = missing?;
        if self.recovered.contains(&miss) {
            return None;
        }
        let block_len = r.block.len();
        if present.iter().any(|p| 2 + p.len() > block_len) {
            return None;
        }
        let mut acc = r.block.to_vec();
        let mut scratch = vec![0u8; block_len];
        for p in &present {
            source_block(p, block_len, &mut scratch);
            xor_into(&mut acc, &scratch);
        }
        let len = ((acc[0] as usize) << 8) | acc[1] as usize;
        if 2 + len > block_len {
            return None;
        }
        Some((miss, Bytes::copy_from_slice(&acc[2..2 + len])))
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

    // ── Per-leg FEC ──────────────────────────────────────────────────────

    /// Per-leg repair survives the wire round-trip including its seq list.
    #[test]
    fn per_leg_repair_wire_roundtrip() {
        let r = PerLegRepair {
            columns: 5,
            rows: 4,
            seqs: vec![7, 99, 100_000, 4_000_000_000],
            block: Bytes::from(vec![9, 8, 7, 6, 5]),
        };
        let mut buf = BytesMut::new();
        r.serialize(&mut buf);
        assert_eq!(PerLegRepair::parse(&buf).unwrap(), r);
    }

    /// A single loss on a leg is recovered via its repair — and crucially
    /// the leg's bond_seqs are NON-contiguous (the leg only carries a
    /// subset of the global stream), which the combined encoder can't do.
    #[test]
    fn per_leg_recovers_single_loss_noncontiguous_seqs() {
        let params = FecParams { columns: 3, rows: 3 };
        let mut enc = PerLegFecEncoder::new(params);
        let mut dec = PerLegFecDecoder::new(params);

        // Global bond_seqs this leg happened to carry (every ~3rd seq).
        let seqs = [2u32, 5, 8, 11, 14, 17, 20, 23, 26];
        let payloads: Vec<Bytes> = (0..9).map(|i| pkt(i as u8 + 1, 40 + i)).collect();
        let mut repairs = Vec::new();
        for (i, &s) in seqs.iter().enumerate() {
            if let Some(r) = enc.push(s, &payloads[i]) {
                repairs.push(r);
            }
        }
        assert_eq!(repairs.len(), 3, "one repair per column");

        // Deliver every member except seqs[4] (=14), which lands in col 1.
        for (i, &s) in seqs.iter().enumerate() {
            if i == 4 {
                continue;
            }
            assert!(dec.push_source(s, &payloads[i]).is_empty());
        }
        // The repair whose seq list contains 14 recovers it.
        let r = repairs.iter().find(|r| r.seqs.contains(&14)).unwrap().clone();
        let rec = dec.push_repair(r);
        assert_eq!(rec, vec![(14u32, payloads[4].clone())]);
    }

    /// A burst of `columns` consecutive *leg* packets lost is fully
    /// recovered — the per-leg interleave spreads it one-per-column. This
    /// is the Starlink-handoff case the feature targets.
    #[test]
    fn per_leg_recovers_consecutive_leg_burst() {
        let params = FecParams { columns: 4, rows: 3 };
        let mut enc = PerLegFecEncoder::new(params);
        let mut dec = PerLegFecDecoder::new(params);
        // 12 packets on this leg, arbitrary growing bond_seqs.
        let seqs: Vec<u32> = (0..12).map(|i| 1000 + i * 7).collect();
        let payloads: Vec<Bytes> = (0..12).map(|i| pkt(i as u8 + 1, 50)).collect();
        let mut repairs = Vec::new();
        for (i, &s) in seqs.iter().enumerate() {
            if let Some(r) = enc.push(s, &payloads[i]) {
                repairs.push(r);
            }
        }
        // Drop a burst of 4 consecutive leg packets (indices 4..8).
        let dropped: Vec<u32> = (4..8).map(|i| seqs[i]).collect();
        for (i, &s) in seqs.iter().enumerate() {
            if (4..8).contains(&i) {
                continue;
            }
            dec.push_source(s, &payloads[i]);
        }
        let mut recovered = std::collections::HashMap::new();
        for r in repairs {
            for (s, p) in dec.push_repair(r) {
                recovered.insert(s, p);
            }
        }
        for (i, s) in dropped.iter().enumerate() {
            assert_eq!(
                recovered.get(s),
                Some(&payloads[4 + i]),
                "burst seq {s} should recover"
            );
        }
    }

    /// A repair arriving BEFORE its last missing member is stashed and
    /// fires when that member finally lands (out-of-order resilience).
    #[test]
    fn per_leg_repair_before_source_recovers_on_arrival() {
        let params = FecParams { columns: 2, rows: 2 };
        let mut enc = PerLegFecEncoder::new(params);
        let mut dec = PerLegFecDecoder::new(params);
        let seqs = [10u32, 11, 12, 13]; // col0: 10,12 ; col1: 11,13
        let payloads: Vec<Bytes> = (0..4).map(|i| pkt(i as u8 + 1, 30)).collect();
        let mut repairs = Vec::new();
        for (i, &s) in seqs.iter().enumerate() {
            if let Some(r) = enc.push(s, &payloads[i]) {
                repairs.push(r);
            }
        }
        // col0 repair covers {10,12}. Feed the repair first with NEITHER
        // member present → stashed as pending (2 holes). Then member 10
        // arrives, leaving 12 as the sole hole → the stashed repair fires.
        let col0 = repairs.iter().find(|r| r.seqs.contains(&10)).unwrap().clone();
        assert!(dec.push_repair(col0).is_empty(), "2 missing → stashed");
        let rec = dec.push_source(10, &payloads[0]);
        assert_eq!(rec, vec![(12u32, payloads[2].clone())], "arrival of 10 recovers 12");
    }

    /// Every field of a wire repair is attacker-chosen. A repair carrying a
    /// block shorter than the 2-byte length prefix (or no member seqs at all)
    /// is structurally impossible from `build_per_leg_repair` and must be
    /// rejected at parse — with `count == 1` nothing else bounds the
    /// `acc[0..2]` read in `try_recover`.
    #[test]
    fn per_leg_parse_rejects_short_block_and_empty_seq_list() {
        let wire = |count: u16, seqs: &[u32], block_len: u16| {
            let mut b = BytesMut::new();
            b.put_u16(2); // columns
            b.put_u16(2); // rows
            b.put_u16(count);
            for s in seqs {
                b.put_u32(*s);
            }
            b.put_u16(block_len);
            b.put_slice(&vec![0u8; block_len as usize]);
            b
        };
        assert!(PerLegRepair::parse(&wire(1, &[u32::MAX], 0)).is_none(), "0-byte block");
        assert!(PerLegRepair::parse(&wire(1, &[u32::MAX], 1)).is_none(), "1-byte block");
        assert!(PerLegRepair::parse(&wire(0, &[], 4)).is_none(), "no member seqs");
        // THE attack shape: a single-member repair with a well-formed block.
        // Nothing else in the pipeline bounds it, and `try_recover` would hand
        // the reassembler an entirely attacker-chosen (bond_seq, payload).
        assert!(
            PerLegRepair::parse(&wire(1, &[u32::MAX], 4)).is_none(),
            "one-member repair is an injection primitive, not a repair"
        );
        assert!(PerLegRepair::parse(&wire(2, &[1, 2], 4)).is_some(), "well-formed still parses");
    }

    /// Same shape for the combined repair: `FecDecoder::attempt` reads the
    /// length prefix out of the XOR accumulator.
    #[test]
    fn combined_parse_rejects_short_block() {
        let wire = |block_len: u16| {
            let mut b = BytesMut::new();
            b.put_u32(0);
            b.put_u16(2);
            b.put_u16(2);
            b.put_u16(0);
            b.put_u16(block_len);
            b.put_slice(&vec![0u8; block_len as usize]);
            b
        };
        assert!(FecRepair::parse(&wire(0)).is_none());
        assert!(FecRepair::parse(&wire(1)).is_none());
        assert!(FecRepair::parse(&wire(2)).is_some());
    }

    /// reset() drops cached members + pending repairs so a stale repair
    /// can't recover into a re-anchored session.
    #[test]
    fn per_leg_reset_clears_state() {
        let params = FecParams { columns: 2, rows: 2 };
        let mut enc = PerLegFecEncoder::new(params);
        let mut dec = PerLegFecDecoder::new(params);
        let seqs = [10u32, 11, 12, 13];
        let payloads: Vec<Bytes> = (0..4).map(|i| pkt(i as u8 + 1, 30)).collect();
        let mut repairs = Vec::new();
        for (i, &s) in seqs.iter().enumerate() {
            if let Some(r) = enc.push(s, &payloads[i]) {
                repairs.push(r);
            }
        }
        dec.push_source(10, &payloads[0]); // col0 member present
        dec.reset();
        let col0 = repairs.iter().find(|r| r.seqs.contains(&10)).unwrap().clone();
        // Both members now unknown post-reset → unrecoverable.
        assert!(dec.push_repair(col0).is_empty());
    }
}
