//! Reed-Solomon erasure coding over GF(256), Cauchy systematic form.
//!
//! Hand-rolled (no external dependency) to keep `bonding-protocol` lean —
//! same philosophy as the XOR FEC and the rest of the wire codecs. Used by
//! the **per-leg RS FEC**: a block of `k` data packets gets `m` parity
//! packets, and the receiver recovers **up to `m` lost packets per block**
//! (versus XOR's one-per-column). The right code for a chronically-lossy leg
//! (e.g. a Starlink handoff dropping several packets at once).
//!
//! A Cauchy generator matrix is used because every square submatrix of a
//! Cauchy matrix is invertible over GF(2^n) — so any `k` of the `k+m` shards
//! reconstruct the originals, with no Vandermonde edge cases.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::sync::OnceLock;

// ── GF(256): primitive polynomial 0x11d, generator α = 2 ─────────────────────

struct Gf {
    /// `exp[i] = α^i`, doubled to length 510 so `log[a]+log[b]` (≤ 508)
    /// indexes without a modulo.
    exp: [u8; 512],
    log: [u8; 256],
}

fn gf() -> &'static Gf {
    static G: OnceLock<Gf> = OnceLock::new();
    G.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..510 {
            exp[i] = exp[i - 255];
        }
        Gf { exp, log }
    })
}

#[inline]
fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let g = gf();
    g.exp[g.log[a as usize] as usize + g.log[b as usize] as usize]
}

/// Multiplicative inverse. `a` must be non-zero.
#[inline]
fn inv(a: u8) -> u8 {
    let g = gf();
    g.exp[255 - g.log[a as usize] as usize]
}

/// Cauchy coefficient for parity row `i` (0..m) and data column `j` (0..k):
/// `1 / (x_i ⊕ y_j)` with `x_i = i`, `y_j = m + j` — disjoint ranges, so the
/// XOR is always non-zero (invertible). Requires `m + k ≤ 256`.
#[inline]
fn cauchy(i: usize, j: usize, m: usize) -> u8 {
    inv((i as u8) ^ ((m + j) as u8))
}

/// Max supported block: `k + m ≤ 256` (GF(256) element budget).
pub const RS_MAX_BLOCK: usize = 256;

// ── Encode ───────────────────────────────────────────────────────────────────

/// Systematic RS encode: `k` equal-length data shards → `m` parity shards.
pub fn rs_encode(k: usize, m: usize, data: &[Vec<u8>], shard_len: usize) -> Vec<Vec<u8>> {
    let mut parity = vec![vec![0u8; shard_len]; m];
    for (i, par) in parity.iter_mut().enumerate() {
        for (j, dj) in data.iter().enumerate().take(k) {
            let c = cauchy(i, j, m);
            if c == 0 {
                continue;
            }
            for b in 0..shard_len {
                par[b] ^= mul(c, dj[b]);
            }
        }
    }
    parity
}

// ── Reconstruct (erasure decode) ─────────────────────────────────────────────

/// Recover the missing **data** shards in `shards` (layout: `0..k` data,
/// `k..k+m` parity; `None` = lost). Returns `true` and fills the missing data
/// slots when enough shards are present (≥ `k` total, ≥ `missing` parity).
pub fn rs_reconstruct(
    k: usize,
    m: usize,
    shards: &mut [Option<Vec<u8>>],
    shard_len: usize,
) -> bool {
    // Dimension contract, checked once per block (never per packet): the
    // array must hold `k + m` slots and every present shard must be exactly
    // `shard_len` bytes, or the Gauss-Jordan below indexes / copies out of
    // range. Callers inside this crate always satisfy it; this is the guard
    // for the public API and for a shard assembled from wire-supplied
    // lengths.
    if shards.len() < k + m || shards.iter().flatten().any(|s| s.len() != shard_len) {
        return false;
    }
    let missing: Vec<usize> = (0..k).filter(|&j| shards[j].is_none()).collect();
    if missing.is_empty() {
        return true;
    }
    let present_data: Vec<usize> = (0..k).filter(|&j| shards[j].is_some()).collect();
    let present_parity: Vec<usize> = (0..m).filter(|&i| shards[k + i].is_some()).collect();
    let r = missing.len();
    if present_parity.len() < r {
        return false; // not enough parity to cover the erasures
    }
    let use_parity: Vec<usize> = present_parity.into_iter().take(r).collect();

    // Build the r×r system A·x = rhs over GF(256). Unknowns x are the missing
    // data shards (each a byte vector); coefficients are Cauchy scalars.
    let mut a = vec![vec![0u8; r]; r];
    let mut rhs: Vec<Vec<u8>> = vec![vec![0u8; shard_len]; r];
    for (ai, &pi) in use_parity.iter().enumerate() {
        // rhs starts as the parity shard, minus the known (present-data)
        // contributions to that parity equation.
        rhs[ai].copy_from_slice(shards[k + pi].as_ref().unwrap());
        for &j in &present_data {
            let c = cauchy(pi, j, m);
            if c == 0 {
                continue;
            }
            let dj = shards[j].as_ref().unwrap();
            for b in 0..shard_len {
                rhs[ai][b] ^= mul(c, dj[b]);
            }
        }
        for (bi, &j) in missing.iter().enumerate() {
            a[ai][bi] = cauchy(pi, j, m);
        }
    }

    if !gf_solve(&mut a, &mut rhs, r, shard_len) {
        return false;
    }
    for (bi, &j) in missing.iter().enumerate() {
        shards[j] = Some(std::mem::take(&mut rhs[bi]));
    }
    true
}

/// Gauss-Jordan elimination of an `r×r` GF(256) system whose right-hand sides
/// are byte vectors of length `len`. Returns `false` if the matrix is
/// singular (never happens for a Cauchy submatrix, but guarded).
fn gf_solve(a: &mut [Vec<u8>], rhs: &mut [Vec<u8>], r: usize, len: usize) -> bool {
    for col in 0..r {
        let Some(piv) = (col..r).find(|&row| a[row][col] != 0) else {
            return false;
        };
        a.swap(col, piv);
        rhs.swap(col, piv);
        let inv_p = inv(a[col][col]);
        for c in col..r {
            a[col][c] = mul(a[col][c], inv_p);
        }
        for b in 0..len {
            rhs[col][b] = mul(rhs[col][b], inv_p);
        }
        for row in 0..r {
            if row == col {
                continue;
            }
            let f = a[row][col];
            if f == 0 {
                continue;
            }
            for c in col..r {
                a[row][c] ^= mul(f, a[col][c]);
            }
            for b in 0..len {
                rhs[row][b] ^= mul(f, rhs[col][b]);
            }
        }
    }
    true
}

// ── Per-leg RS FEC ───────────────────────────────────────────────────────────
//
// Mirrors the per-leg XOR FEC (`fec::PerLeg*`) but with an RS block: a repair
// enumerates the `k` bond_seqs of its block plus a parity index, so media
// packets stay unchanged on the wire and the leg can carry a non-contiguous
// subset of the global stream. Recovers up to `m` losses per `k`-packet block.

/// One RS parity shard for a per-leg block. `m` of these are emitted per
/// block (parity_index `0..m`); any `k` of the `k+m` shards reconstruct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerLegRsRepair {
    pub data_shards: u16,   // k
    pub parity_shards: u16, // m
    pub parity_index: u16,  // 0..m
    pub shard_len: u16,
    /// The block's `k` data `bond_seq`s, in shard order.
    pub seqs: Vec<u32>,
    pub parity: Bytes,
}

impl PerLegRsRepair {
    const FIXED_HDR: usize = 2 + 2 + 2 + 2 + 2; // k, m, idx, shard_len, count

    pub fn serialize(&self, out: &mut BytesMut) {
        out.clear();
        out.reserve(Self::FIXED_HDR + self.seqs.len() * 4 + self.parity.len());
        out.put_u16(self.data_shards);
        out.put_u16(self.parity_shards);
        out.put_u16(self.parity_index);
        out.put_u16(self.shard_len);
        out.put_u16(self.seqs.len() as u16);
        for s in &self.seqs {
            out.put_u32(*s);
        }
        out.put_slice(&self.parity);
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::FIXED_HDR {
            return None;
        }
        let mut r = &buf[..Self::FIXED_HDR];
        let data_shards = r.get_u16();
        let parity_shards = r.get_u16();
        let parity_index = r.get_u16();
        let shard_len = r.get_u16();
        let count = r.get_u16() as usize;
        // Structural bounds, enforced here so `PerLegRsDecoder` never has to
        // defend each index. Every one of these is fixed by the encoder
        // (`PerLegRsEncoder::push`): k ≥ 1 and m ≥ 1, exactly one `bond_seq`
        // per data shard, a parity index addressing a real parity slot, a
        // shard of `2 + max_payload` (so ≥ 2) bytes, and a block inside the
        // GF(256) element budget. A repair violating any of them cannot have
        // been produced by a peer running this protocol.
        if data_shards == 0
            || parity_shards == 0
            || parity_index >= parity_shards
            || shard_len < 2
            || count != data_shards as usize
            || data_shards as usize + parity_shards as usize > RS_MAX_BLOCK
        {
            return None;
        }
        let mut off = Self::FIXED_HDR;
        if buf.len() < off + count * 4 + shard_len as usize {
            return None;
        }
        let mut seqs = Vec::with_capacity(count);
        for _ in 0..count {
            let mut s = &buf[off..off + 4];
            seqs.push(s.get_u32());
            off += 4;
        }
        Some(Self {
            data_shards,
            parity_shards,
            parity_index,
            shard_len,
            seqs,
            parity: Bytes::copy_from_slice(&buf[off..off + shard_len as usize]),
        })
    }
}

/// Pad a payload into an RS shard: `[u16 len][payload][zero pad]` to
/// `shard_len`. Mirrors the XOR `source_block` so lengths recover exactly.
fn pad_shard(payload: &[u8], shard_len: usize) -> Vec<u8> {
    let mut s = vec![0u8; shard_len];
    s[0] = (payload.len() >> 8) as u8;
    s[1] = (payload.len() & 0xFF) as u8;
    s[2..2 + payload.len()].copy_from_slice(payload);
    s
}

fn unpad_shard(shard: &[u8]) -> Option<Bytes> {
    if shard.len() < 2 {
        return None;
    }
    let len = ((shard[0] as usize) << 8) | shard[1] as usize;
    if 2 + len > shard.len() {
        return None;
    }
    Some(Bytes::copy_from_slice(&shard[2..2 + len]))
}

/// Per-leg loss fraction (0..1) at/above which an adaptive RS encoder uses
/// its maximum parity. Below it, parity interpolates from the minimum.
const ADAPT_FULL_LOSS: f32 = 0.10;

/// Per-leg RS sender-side encoder. Feed every packet sent on this leg; emits
/// `m` repairs once a `k`-packet block fills. When `m_max > m_min`, `m` is
/// **adaptive** — it scales with the leg's recent loss via [`Self::set_loss`].
pub struct PerLegRsEncoder {
    k: usize,
    m_min: usize,
    m_max: usize,
    m_cur: usize,
    block: Vec<(u32, Bytes)>,
}

impl PerLegRsEncoder {
    /// Fixed-parity RS: `data` = k (≥ 1), `parity` = m (≥ 1), `k + m ≤ 256`.
    pub fn new(data: u16, parity: u16) -> Self {
        Self::new_adaptive(data, parity, parity)
    }

    /// Adaptive RS: parity scales in `[parity_min, parity_max]` with the leg's
    /// recent loss (see [`Self::set_loss`]). `parity_max == parity_min` is the
    /// fixed case.
    pub fn new_adaptive(data: u16, parity_min: u16, parity_max: u16) -> Self {
        let lo = parity_min.max(1) as usize;
        let hi = (parity_max.max(parity_min)).max(1) as usize;
        Self {
            k: (data.max(1)) as usize,
            m_min: lo,
            m_max: hi,
            m_cur: lo,
            block: Vec::with_capacity(data as usize),
        }
    }

    /// Update the parity strength from the leg's recent loss fraction. No-op
    /// for a fixed encoder. Higher loss → more parity (more recoverable
    /// losses per block), bounded by the operator's `[min, max]` envelope.
    pub fn set_loss(&mut self, loss: f32) {
        if self.m_max <= self.m_min {
            return;
        }
        let frac = (loss.max(0.0) / ADAPT_FULL_LOSS).min(1.0);
        let span = (self.m_max - self.m_min) as f32;
        self.m_cur = self.m_min + (span * frac).round() as usize;
    }

    pub fn push(&mut self, bond_seq: u32, payload: &Bytes) -> Vec<PerLegRsRepair> {
        self.block.push((bond_seq, payload.clone()));
        if self.block.len() < self.k {
            return Vec::new();
        }
        let group = std::mem::take(&mut self.block);
        self.block = Vec::with_capacity(self.k);
        let m = self.m_cur.clamp(self.m_min, self.m_max);
        let max_payload = group.iter().map(|(_, p)| p.len()).max().unwrap_or(0);
        let shard_len = 2 + max_payload;
        let data: Vec<Vec<u8>> = group.iter().map(|(_, p)| pad_shard(p, shard_len)).collect();
        let parity = rs_encode(self.k, m, &data, shard_len);
        let seqs: Vec<u32> = group.iter().map(|(s, _)| *s).collect();
        parity
            .into_iter()
            .enumerate()
            .map(|(idx, par)| PerLegRsRepair {
                data_shards: self.k as u16,
                parity_shards: m as u16,
                parity_index: idx as u16,
                shard_len: shard_len as u16,
                seqs: seqs.clone(),
                parity: Bytes::from(par),
            })
            .collect()
    }
}

struct RsBlock {
    k: usize,
    m: usize,
    shard_len: usize,
    seqs: Vec<u32>,
    parity: std::collections::HashMap<u16, Bytes>,
    done: bool,
}

/// Per-leg RS receiver-side decoder (one per FEC-enabled leg). Feed media
/// packets to [`Self::push_source`] and repairs to [`Self::push_repair`];
/// both return any recovered `(bond_seq, payload)` once a block has ≥ `k`
/// shards with ≤ `m` data losses.
pub struct PerLegRsDecoder {
    seen: std::collections::HashMap<u32, Bytes>,
    order: std::collections::VecDeque<u32>,
    seen_cap: usize,
    blocks: std::collections::HashMap<u32, RsBlock>,
    block_order: std::collections::VecDeque<u32>,
    block_cap: usize,
}

impl PerLegRsDecoder {
    pub fn new(data: u16, parity: u16) -> Self {
        let span = (data.max(1) as usize) + (parity.max(1) as usize);
        Self {
            seen: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            seen_cap: (span * 8).max(256),
            blocks: std::collections::HashMap::new(),
            block_order: std::collections::VecDeque::new(),
            block_cap: 16,
        }
    }

    pub fn reset(&mut self) {
        self.seen.clear();
        self.order.clear();
        self.blocks.clear();
        self.block_order.clear();
    }

    fn remember(&mut self, seq: u32, payload: Bytes) {
        if self.seen.insert(seq, payload).is_none() {
            self.order.push_back(seq);
            while self.order.len() > self.seen_cap {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }

    pub fn push_source(&mut self, bond_seq: u32, payload: &Bytes) -> Vec<(u32, Bytes)> {
        self.remember(bond_seq, payload.clone());
        // A late source can complete a block that was waiting on it.
        self.retry_all()
    }

    pub fn push_repair(&mut self, r: PerLegRsRepair) -> Vec<(u32, Bytes)> {
        // `PerLegRsRepair` has public fields and this is a public entry point,
        // so `parse`'s bounds are NOT an invariant of the type — bilbycast-edge
        // depends on this crate directly and could hand us a hand-built value.
        // Without this, `seqs[j]` and `shards[k + idx]` are indexed with
        // attacker- or caller-chosen values. Cost is one branch per FEC
        // datagram; this is not the media path.
        if r.data_shards == 0
            || r.parity_shards == 0
            || r.parity_index >= r.parity_shards
            || r.shard_len < 2
            || r.seqs.len() != r.data_shards as usize
            || r.parity.len() != r.shard_len as usize
            || r.data_shards as usize + r.parity_shards as usize > RS_MAX_BLOCK
        {
            return Vec::new();
        }
        let key = match r.seqs.first() {
            Some(s) => *s,
            None => return Vec::new(),
        };
        // Every repair of one block is emitted by a single `PerLegRsEncoder::
        // push` and therefore agrees on geometry, shard length and member
        // list. A repair that disagrees with the block it would join is stale
        // or forged; accepting it would let its parity shard be indexed and
        // length-matched against a different block's dimensions.
        if let Some(b) = self.blocks.get(&key)
            && (b.k != r.data_shards as usize
                || b.m != r.parity_shards as usize
                || b.shard_len != r.shard_len as usize
                || b.seqs != r.seqs)
        {
            return Vec::new();
        }
        if !self.blocks.contains_key(&key) {
            if self.blocks.len() >= self.block_cap {
                if let Some(old) = self.block_order.pop_front() {
                    self.blocks.remove(&old);
                }
            }
            self.block_order.push_back(key);
            self.blocks.insert(
                key,
                RsBlock {
                    k: r.data_shards as usize,
                    m: r.parity_shards as usize,
                    shard_len: r.shard_len as usize,
                    seqs: r.seqs.clone(),
                    parity: std::collections::HashMap::new(),
                    done: false,
                },
            );
        }
        if let Some(b) = self.blocks.get_mut(&key) {
            b.parity.insert(r.parity_index, r.parity);
        }
        self.try_block(key)
    }

    fn retry_all(&mut self) -> Vec<(u32, Bytes)> {
        let keys: Vec<u32> = self.blocks.keys().copied().collect();
        let mut out = Vec::new();
        for k in keys {
            out.extend(self.try_block(k));
        }
        out
    }

    fn try_block(&mut self, key: u32) -> Vec<(u32, Bytes)> {
        let Some(b) = self.blocks.get(&key) else {
            return Vec::new();
        };
        if b.done {
            return Vec::new();
        }
        let k = b.k;
        let m = b.m;
        let shard_len = b.shard_len;
        let seqs = b.seqs.clone();

        let missing: Vec<usize> = (0..k).filter(|&j| !self.seen.contains_key(&seqs[j])).collect();
        if missing.is_empty() {
            self.blocks.get_mut(&key).unwrap().done = true;
            return Vec::new(); // nothing lost
        }
        let parity_have = b.parity.len();
        if parity_have < missing.len() {
            return Vec::new(); // wait for more shards
        }

        // Assemble the k+m shard array.
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; k + m];
        for (j, sq) in seqs.iter().enumerate().take(k) {
            if let Some(p) = self.seen.get(sq) {
                // A member that doesn't fit the block's shard can't belong to
                // it — bail rather than pad out of range or reconstruct
                // garbage. Mirrors the same guard in `fec::FecDecoder::attempt`
                // and `fec::PerLegFecDecoder::try_recover`.
                if 2 + p.len() > shard_len {
                    return Vec::new();
                }
                shards[j] = Some(pad_shard(p, shard_len));
            }
        }
        let b = self.blocks.get(&key).unwrap();
        for (idx, par) in &b.parity {
            shards[k + *idx as usize] = Some(par.to_vec());
        }

        if !rs_reconstruct(k, m, &mut shards, shard_len) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for &j in &missing {
            if let Some(shard) = &shards[j] {
                if let Some(payload) = unpad_shard(shard) {
                    self.remember(seqs[j], payload.clone());
                    out.push((seqs[j], payload));
                }
            }
        }
        self.blocks.get_mut(&key).unwrap().done = true;
        out
    }
}

#[cfg(test)]
mod tests {

    /// `PerLegRsRepair` has public fields, so `parse`'s structural bounds are
    /// not an invariant of the type — bilbycast-edge depends on this crate
    /// directly. `push_repair` must defend itself. Each case below indexed out
    /// of range before the guard: `parity_index` past the parity slots,
    /// `seqs.len()` disagreeing with `data_shards`, and a parity buffer
    /// shorter than the declared shard length.
    #[test]
    fn push_repair_rejects_hand_built_out_of_range_repairs() {
        let bad = |f: &dyn Fn(&mut PerLegRsRepair)| {
            let mut r = PerLegRsRepair {
                data_shards: 2,
                parity_shards: 1,
                parity_index: 0,
                shard_len: 4,
                seqs: vec![1, 2],
                parity: Bytes::from_static(&[0u8; 4]),
            };
            f(&mut r);
            let mut dec = PerLegRsDecoder::new(2, 1);
            assert!(dec.push_repair(r).is_empty());
        };

        bad(&|r| r.parity_index = 999);
        bad(&|r| r.parity_index = r.parity_shards);
        bad(&|r| r.data_shards = 0);
        bad(&|r| r.parity_shards = 0);
        bad(&|r| r.shard_len = 1);
        bad(&|r| r.seqs = vec![1]);
        bad(&|r| r.parity = Bytes::from_static(&[0u8; 2]));
        bad(&|r| {
            r.data_shards = 200;
            r.parity_shards = 200;
        });
    }
    use super::*;

    fn shard(byte: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| byte.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn rs_recovers_up_to_m_losses() {
        let (k, m, len) = (6usize, 3usize, 40usize);
        let data: Vec<Vec<u8>> = (0..k).map(|i| shard(i as u8 + 1, len)).collect();
        let parity = rs_encode(k, m, &data, len);

        // Drop 3 data shards (= m) — recoverable.
        let mut shards: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        shards.extend(parity.iter().cloned().map(Some));
        shards[1] = None;
        shards[3] = None;
        shards[5] = None;
        assert!(rs_reconstruct(k, m, &mut shards, len));
        for (j, orig) in data.iter().enumerate() {
            assert_eq!(shards[j].as_ref().unwrap(), orig, "shard {j} mismatch");
        }
    }

    #[test]
    fn rs_recovers_mixed_data_and_parity_loss() {
        let (k, m, len) = (8usize, 4usize, 33usize);
        let data: Vec<Vec<u8>> = (0..k).map(|i| shard(i as u8 * 7 + 1, len)).collect();
        let parity = rs_encode(k, m, &data, len);
        let mut shards: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        shards.extend(parity.iter().cloned().map(Some));
        // Lose 2 data + 2 parity (4 total, 2 data erasures, 2 parity left ≥ 2).
        shards[2] = None;
        shards[6] = None;
        shards[k] = None; // parity 0
        shards[k + 1] = None; // parity 1
        assert!(rs_reconstruct(k, m, &mut shards, len));
        assert_eq!(shards[2].as_ref().unwrap(), &data[2]);
        assert_eq!(shards[6].as_ref().unwrap(), &data[6]);
    }

    #[test]
    fn rs_too_many_losses_fails() {
        let (k, m, len) = (5usize, 2usize, 20usize);
        let data: Vec<Vec<u8>> = (0..k).map(|i| shard(i as u8 + 9, len)).collect();
        let parity = rs_encode(k, m, &data, len);
        let mut shards: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        shards.extend(parity.iter().cloned().map(Some));
        // 3 data losses with only m=2 parity → unrecoverable.
        shards[0] = None;
        shards[2] = None;
        shards[4] = None;
        assert!(!rs_reconstruct(k, m, &mut shards, len));
    }

    #[test]
    fn gf_inverse_roundtrip() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1, "inv({a}) wrong");
        }
    }

    #[test]
    fn per_leg_rs_repair_roundtrip() {
        let r = PerLegRsRepair {
            data_shards: 8,
            parity_shards: 3,
            parity_index: 2,
            shard_len: 7,
            seqs: vec![5, 9, 100_000, 4_000_000_000, 1, 2, 3, 4],
            parity: Bytes::from(vec![1u8, 2, 3, 4, 5, 6, 7]),
        };
        let mut buf = BytesMut::new();
        r.serialize(&mut buf);
        assert_eq!(PerLegRsRepair::parse(&buf).unwrap(), r);
    }

    // ── Malformed-repair rejection (remote-input hardening) ──────────────
    //
    // Every value in a `PerLegRsRepair` is attacker-chosen on the wire. These
    // pin the structural contract `parse` enforces, and the two use-site
    // guards that structure alone cannot express.

    /// Assemble a raw `PerLegRsRepair` wire image from arbitrary field values.
    fn rs_wire(k: u16, m: u16, idx: u16, shard_len: u16, seqs: &[u32]) -> BytesMut {
        let mut b = BytesMut::new();
        b.put_u16(k);
        b.put_u16(m);
        b.put_u16(idx);
        b.put_u16(shard_len);
        b.put_u16(seqs.len() as u16);
        for s in seqs {
            b.put_u32(*s);
        }
        b.put_slice(&vec![0u8; shard_len as usize]);
        b
    }

    #[test]
    fn rs_parse_rejects_out_of_range_fields() {
        // parity_index ≥ parity_shards → would index shards[k + idx] OOB.
        assert!(PerLegRsRepair::parse(&rs_wire(1, 1, 999, 10, &[7])).is_none());
        // count < data_shards → would index seqs[j] OOB in try_block.
        assert!(PerLegRsRepair::parse(&rs_wire(5, 1, 0, 4, &[7])).is_none());
        // shard_len < 2 → no room for pad_shard's length prefix.
        assert!(PerLegRsRepair::parse(&rs_wire(1, 1, 0, 0, &[7])).is_none());
        assert!(PerLegRsRepair::parse(&rs_wire(1, 1, 0, 1, &[7])).is_none());
        // Zero shard counts.
        assert!(PerLegRsRepair::parse(&rs_wire(0, 1, 0, 4, &[])).is_none());
        assert!(PerLegRsRepair::parse(&rs_wire(1, 0, 0, 4, &[7])).is_none());
        // k + m past the GF(256) element budget.
        assert!(PerLegRsRepair::parse(&rs_wire(200, 200, 0, 4, &[7; 200])).is_none());
        // ...and a well-formed one still parses.
        assert!(PerLegRsRepair::parse(&rs_wire(2, 1, 0, 4, &[7, 8])).is_some());
    }

    #[test]
    fn rs_decoder_bails_on_member_larger_than_shard() {
        // A repair claiming a 4-byte shard while a real 1316-byte member of
        // its block is cached must bail, not pad out of range.
        let mut dec = PerLegRsDecoder::new(8, 4);
        dec.push_source(100, &Bytes::from(vec![0xAA; 1316]));
        let r = PerLegRsRepair::parse(&rs_wire(2, 1, 0, 4, &[100, 101])).unwrap();
        assert!(dec.push_repair(r).is_empty());
    }

    #[test]
    fn rs_decoder_rejects_repair_disagreeing_with_its_block() {
        // Two repairs keyed to the same block with different shard_len would
        // put mismatched-length parity into one reconstruction.
        let mut dec = PerLegRsDecoder::new(8, 4);
        let a = PerLegRsRepair::parse(&rs_wire(2, 2, 0, 8, &[500, 501])).unwrap();
        let b = PerLegRsRepair::parse(&rs_wire(2, 2, 1, 40, &[500, 501])).unwrap();
        assert!(dec.push_repair(a).is_empty());
        assert!(dec.push_repair(b).is_empty());
    }

    #[test]
    fn rs_reconstruct_rejects_inconsistent_shard_dimensions() {
        let mut short: Vec<Option<Vec<u8>>> = vec![None, Some(vec![0u8; 4])];
        assert!(!rs_reconstruct(1, 1, &mut short, 8), "wrong shard length");
        let mut small: Vec<Option<Vec<u8>>> = vec![None];
        assert!(!rs_reconstruct(1, 1, &mut small, 8), "array shorter than k + m");
    }

    #[test]
    fn adaptive_rs_scales_parity_with_loss() {
        // parity envelope [2, 6]; at 0 loss use min, at ≥10% loss use max.
        let mut enc = PerLegRsEncoder::new_adaptive(8, 2, 6);
        let pkts: Vec<Bytes> = (0..8).map(|i| Bytes::from(vec![i as u8; 20])).collect();
        // No loss yet → 2 parity.
        let mut reps = Vec::new();
        for (i, p) in pkts.iter().enumerate() {
            reps.extend(enc.push(1000 + i as u32, p));
        }
        assert_eq!(reps.len(), 2, "min parity at zero loss");
        // Heavy loss → climbs to max parity.
        enc.set_loss(0.20);
        let mut reps2 = Vec::new();
        for (i, p) in pkts.iter().enumerate() {
            reps2.extend(enc.push(2000 + i as u32, p));
        }
        assert_eq!(reps2.len(), 6, "max parity under heavy loss");
        // The decoder (sized for the max) recovers the larger block too.
        let mut dec = PerLegRsDecoder::new(8, 6);
        for (i, p) in pkts.iter().enumerate() {
            if (2..7).contains(&i) {
                continue; // drop 5 — within max parity 6
            }
            dec.push_source(2000 + i as u32, p);
        }
        let mut recovered = std::collections::HashMap::new();
        for r in reps2 {
            for (s, pl) in dec.push_repair(r) {
                recovered.insert(s, pl);
            }
        }
        for i in 2..7 {
            assert_eq!(recovered.get(&(2000 + i as u32)), Some(&pkts[i]), "seq {i} recovered");
        }
    }

    #[test]
    fn per_leg_rs_recovers_multi_loss_block() {
        // k=6, m=3 → up to 3 losses per block recoverable on one leg.
        let mut enc = PerLegRsEncoder::new(6, 3);
        let mut dec = PerLegRsDecoder::new(6, 3);
        let seqs = [10u32, 20, 30, 40, 50, 60]; // non-contiguous leg subset
        let payloads: Vec<Bytes> = (0..6).map(|i| Bytes::from(vec![i as u8 + 1; 30 + i])).collect();
        let mut repairs = Vec::new();
        for (i, &s) in seqs.iter().enumerate() {
            repairs.extend(enc.push(s, &payloads[i]));
        }
        assert_eq!(repairs.len(), 3, "m parity repairs");
        // Deliver only 3 of the 6 data packets (lose 20, 40, 60).
        for (i, &s) in seqs.iter().enumerate() {
            if matches!(s, 20 | 40 | 60) {
                continue;
            }
            assert!(dec.push_source(s, &payloads[i]).is_empty());
        }
        // Feed the 3 parity repairs → the 3 losses reconstruct.
        let mut recovered = std::collections::HashMap::new();
        for r in repairs {
            for (s, p) in dec.push_repair(r) {
                recovered.insert(s, p);
            }
        }
        assert_eq!(recovered.get(&20), Some(&payloads[1]));
        assert_eq!(recovered.get(&40), Some(&payloads[3]));
        assert_eq!(recovered.get(&60), Some(&payloads[5]));
    }
}
