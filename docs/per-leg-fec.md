# Per-Leg FEC

A bond aggregates heterogeneous links — a couple of 5G modems, a Starlink
dish, maybe a fibre or ISP drop. These legs fail in **very different ways**.
A Starlink leg does a satellite handoff roughly every 15 seconds and drops a
short *burst* of packets; a 5G modem jitters; a fibre leg barely loses
anything. **Per-leg FEC** lets each leg carry its own forward-error-correction
sized to its own loss profile, so a burst on one leg is repaired *on that leg*
before it ever reaches the combined reassembler.

This is the model proven by SpeedFusion / Dejero / LiveU: per-tunnel error
correction underneath, cross-tunnel reorder + retransmit on top. bilbycast's
ARQ already works cross-leg; per-leg FEC adds the per-tunnel half.

## TL;DR

Put a `fec` block on each leg that needs it. Heavier on the bursty links,
light or none on the clean ones. Set the **same geometry for the same leg on
both ends**.

```json
// bonded OUTPUT (sender) and bonded INPUT (receiver) — matching legs
{
  "paths": [
    { "id": 0, "name": "starlink",
      "fec": { "columns": 16, "rows": 10 },
      "transport": { "type": "quic", "addr": "hub:7400", "interface": "wlan0" } },
    { "id": 1, "name": "5g-a",
      "fec": { "columns": 8, "rows": 10 },
      "transport": { "type": "quic", "addr": "hub:7401", "interface": "wwan0" } },
    { "id": 2, "name": "fibre",
      "transport": { "type": "quic", "addr": "hub:7402", "interface": "eth0" } }
  ]
}
```

- `columns` = interleave depth = how long a loss **burst** on this leg it can
  ride over. `rows` = packets per column = the overhead knob (overhead ≈
  `1/rows`). Bounds: `columns ∈ [1, 64]`, `rows ∈ [2, 64]`, `columns × rows ≤
  4096`.
- A leg with no `fec` runs no FEC (relies on cross-leg ARQ + multi-path
  diversity, as before).
- **Mutually exclusive** with the bond-wide combined `fec` — a bond uses one
  model or the other. Validation rejects setting both.

In the manager UI the controls are **Per-leg FEC Columns / Rows** on each bond
leg row (both the bonded input and bonded output forms).

## Why not just the combined FEC?

The bond already had a *combined* FEC (`docs`-less, see `protocol/fec.rs`
`FecEncoder`/`FecDecoder`): one XOR repair stream over the **global** bond
sequence, with the repair packets scattered across the legs. It works well
when loss is roughly uniform. It struggles on heterogeneous legs for two
structural reasons:

1. **A leg burst clusters in the global stream.** The scheduler stripes the
   bond sequence across legs by capacity, so the packets a single leg carries
   are a *subset* of the global `bond_seq` space. When that leg drops a burst,
   the losses land on that correlated subset — a dense pattern that readily
   puts **two losses in one column**, which the column-XOR can't recover
   (it falls through to ARQ, and on a high-RTT leg the retransmit can miss the
   reassembly hold).

2. **One shared FEC budget.** All legs share a single repair stream, so the
   *worst* leg's burst consumes the parity that should have been protecting
   the good legs too. One bad leg starves everyone's protection.

Per-leg FEC fixes both: a leg's burst is **consecutive in that leg's own
stream**, so the interleave puts it one-per-column and recovers it; and each
leg's FEC budget is **dedicated**, so a flaky Starlink leg can't degrade the
clean fibre leg's protection. Overhead lands only where the loss is.

```
         combined FEC                         per-leg FEC
   global seq striped to legs           each leg encodes its own stream

   leg A: 0   2   4   6  ...            leg A (Starlink): a0 a1 a2 a3 ...  ──► A's repairs
   leg B: 1   3   5   7  ...            leg B (5G):       b0 b1 b2 b3 ...  ──► B's repairs
          \________________/            leg C (fibre):    c0 c1 ...        (no FEC)
        one repair stream, scattered    repairs ride the leg they protect
        → A's burst = clustered loss    → A's burst = consecutive in A,
          in the merged column model       interleaved one-per-column
```

## The model

- **Sender:** for each leg that has `fec`, a `PerLegFecEncoder` is fed every
  packet that leg actually transmits (originals, retransmits, and duplicates
  alike — it protects the leg's *wire stream*). It round-robins packets into
  `columns` interleave columns; when a column accumulates `rows` members it
  emits one XOR **repair**, which is sent **on that same leg**.
- **Receiver:** for each FEC leg, a `PerLegFecDecoder`. Every media packet
  arriving on the leg is cached; every repair arriving on the leg is decoded.
  When a repair's column has exactly one missing member, the decoder XORs the
  others against the repair block to reconstruct it, and re-injects it into
  the **shared** reassembly buffer under its **real `bond_seq`** — exactly like
  a late path arrival. Reassembly, ordering, ARQ, and delivery are otherwise
  unchanged.
- **ARQ stays combined and cross-leg.** Whatever per-leg FEC doesn't recover
  is NACKed against the global sequence and retransmitted on the healthiest
  leg, as it always was.

### Media packets are unchanged on the wire

The defining property of this design: **a per-leg repair enumerates the exact
`bond_seq`s it protects**, so the receiver needs no extra per-leg sequence on
every media datagram. Media frames are byte-identical to a non-FEC bond — the
hot send path (`send_on_path`, retransmit framing, duplication) is completely
untouched, and there is no protocol-version bump for media. Only the *repair*
datagram is new.

## Wire format

A per-leg repair rides a normal bond datagram with the FEC flag set in the
12-byte `BondHeader` (flag bit `0x08`, the same bit combined repairs use — the
receiver disambiguates by config, see *Interop* below). The header's
`bond_seq` is informational on a FEC datagram; the receiver routes by the flag
and reads the repair's own seq list.

The payload after the bond header is a `PerLegRepair`:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------------------------------+
|            columns            |             rows              |   geometry (sanity check)
+-------------------------------+-------------------------------+
|            count              |   seq[0] (u32, big-endian)   ...   `count` = the column's members
+-------------------------------+-------------------------------+
...  seq[1] ... seq[count-1] ...                                |
+-------------------------------+-------------------------------+
|          block_len            |   block[0..block_len] ...      |   XOR of the members' source blocks
+-------------------------------+-------------------------------+
```

- `count` is the number of `bond_seq`s this repair covers — normally `rows`.
- `block` is the XOR of each member's `source_block`, where one source block is
  `[u16 payload_len][payload][zero pad to block_len]` and
  `block_len = 2 + max(member payload length)`. This is the same XOR primitive
  the combined FEC uses (`source_block` / `xor_into` in `protocol/fec.rs`), so
  variable-length payloads recover correctly.
- **Minimums, enforced at parse.** `PerLegRepair::parse` rejects `count < 2` or
  `block_len < 2` outright — the datagram is dropped, never decoded.
  `block_len < 2` is the structural floor: the block always opens with the
  2-byte payload-length prefix. `count < 2` is the security floor: a one-member
  repair has no other member to XOR against, so "recovering" it would hand the
  reassembler a `(bond_seq, payload)` pair chosen entirely by whoever sent the
  datagram — and a bond leg is an unconnected UDP socket, so that is an
  injection primitive, not an edge case. Rejecting `block_len < 2` alone does
  not close it. No shipped sender emits either shape: `build_per_leg_repair`
  always covers exactly `rows` members with a `2 + max(member payload length)`
  block, and `rows >= 2` is enforced both by `FecParams::is_valid` and by the
  edge's own config validation, where the XOR branch requires `fec.rows` in
  [2, 64] (the per-leg Reed-Solomon branch allows `rows = 1`, but Reed-Solomon
  never emits a `PerLegRepair` — `PerLegFecEncoder` is only ever constructed
  for `PerLegFecKind::Xor`). The combined `FecRepair` carries the same
  `block_len >= 2` floor.

Compared with the combined `FecRepair`, which carries
`[base_seq][columns][rows][column][block_len][block]` and relies on the
receiver computing column membership from the contiguous global seq space, the
per-leg repair is **self-describing** — it lists its members explicitly, which
is what lets the leg carry a non-contiguous subset of the global stream.

## Recovery semantics & limits

- **Single loss per column** is recovered (XOR). A burst of up to `columns`
  consecutive *leg* packets lands one-per-column and is fully recovered — this
  is the Starlink-handoff case.
- **Two losses in one column** are not recoverable by FEC and fall through to
  cross-leg ARQ, exactly like combined FEC.
- **Out-of-order resilience:** a repair that arrives before its last missing
  member is stashed and fires the moment that member lands. Recoveries cascade
  — filling one column's last hole can complete another's.
- **Decoder cache window:** the decoder keeps a bounded ring of recent member
  payloads (~`columns × rows × 4`, floor 256) to XOR against. If a member was
  delivered and evicted long before its column's repair arrives, recovering a
  *different* member of that group can fail. In practice the repair for a
  column trails its members by `< columns × rows` packets, well inside the
  window; the reassembly hold-time keeps the relevant packets live regardless.
- **Partial tail columns** (a column that never fills because the leg went
  idle) are not protected until they fill. This is sparse-loss FEC, not a
  flush-on-idle scheme — same behaviour as the combined encoder.
- **Overhead** is `1/rows` of *that leg's* traffic, charged against that leg's
  capacity. FEC bytes are deliberately excluded from the per-path media byte
  counter so the congestion controller doesn't read them as loss.
- **Session reset:** on a sender-restart re-anchor, every per-leg decoder's
  cache and pending repairs are cleared alongside the combined decoder and the
  reassembly buffer, so a stale repair can't reconstruct wrong bytes into the
  new seq space.

## Tuning guidance

Pick per leg, by how it loses:

| Leg type | Suggested `columns` | `rows` | Why |
|----------|--------------------:|-------:|-----|
| Starlink / satellite | 16–20 | 10 | Wide interleave to ride a handoff burst; ~10% overhead. |
| 5G / LTE modem | 8–12 | 10 | Moderate burst tolerance; ~10% overhead. |
| Bonded cellular on a metered plan | 8 | 16–20 | Cheaper (≈5–6% overhead) where data costs money. |
| Clean fibre / wired ISP | *(omit)* | — | Diversity + ARQ already cover its rare loss. |

Wider `columns` survives longer bursts but means the column's repair trails
its members further (more recovery latency, more cache pressure). More `rows`
is cheaper but recovers fewer losses per block. When unsure, `16 × 10` on the
satellite leg and `8 × 10` on each modem is a sane starting point; leave clean
legs bare.

This composes with the reassembly hold (`hold_ms` / `hold_max_ms`): FEC
recovers *proactively* with no round-trip, so it shrinks how often the hold has
to wait on a cross-leg retransmit — but the hold still needs to cover the worst
leg's delivery latency for the losses FEC can't catch.

## Algorithm: XOR vs Reed-Solomon

Each leg picks its own algorithm (`PerLegFecKind` / edge `path.fec.algorithm`):

- **XOR** (default, SMPTE 2022-1 column model) — recovers **one loss per
  column**. A burst of up to `columns` consecutive leg packets is recovered
  because the interleave spreads it one-per-column; but **two losses in the
  same column fall through to ARQ**. Cheap and ideal for a leg whose loss is
  sparse or a single clean burst.
- **Reed-Solomon** — recovers **up to `parity` losses among each `data +
  parity` block**, *regardless of where they land*. The right code for a
  chronically-lossy leg that drops several packets at once (a Starlink handoff,
  a deep cellular fade). Costs a little more CPU and `parity/data` overhead.

For RS, the geometry fields are reinterpreted: `columns` = **data shards (k)**,
`rows` = **parity shards (m)**. So `8 × 4` RS is a 12-packet block recovering
any 4 losses, at 50% overhead; `16 × 4` is a 20-packet block recovering any 4,
at 25% overhead. The wire repair is self-describing (it carries `k`, `m`, its
parity index, and the block's `bond_seq`s), so the receiver handles each block
independently — and media packets stay byte-identical, exactly as for XOR.

The codec is a hand-rolled GF(256) Cauchy-RS (`protocol/rs.rs`) — every square
submatrix of a Cauchy matrix is invertible over GF(2⁸), so any `k` of the
`k+m` shards reconstruct the originals.

| Leg behaviour | Use | Example |
|---------------|-----|---------|
| Sparse loss, occasional single burst | **XOR** | `columns 8–16, rows 10` |
| Several losses clustered in time (Starlink handoff, fade) | **Reed-Solomon** | `data 16, parity 4` |
| Metered, want minimum overhead | **RS, wide block** | `data 32, parity 4` (≈12%) |

### Adaptive RS parity

RS can scale its parity **automatically with the leg's measured loss** —
light protection when the leg is clean, ramping up as it degrades. Set
`parity_max` above the `parity` floor (edge: `path.fec.parity_max`); the
encoder then chooses `m` in `[parity, parity_max]` from the leg's recent
windowed loss fraction (the same signal that drives the congestion
controller), at/above `ADAPT_FULL_LOSS` (10%) using the ceiling.

This means a Starlink leg spends almost no FEC overhead in clear sky and
ramps protection the instant it starts dropping, with **no operator
intervention** — bounded by the `[parity, parity_max]` envelope you set, so
it can never over- or under-protect beyond your limits. The repair carries
its `m`, so the receiver (sized for `parity_max`) decodes the varying block
size transparently. `parity_max == parity` (or unset) = fixed parity.

A good adaptive starting point for a swingy leg: `data 16, parity 2,
parity_max 6` — ≈12% overhead clean, climbing to ≈37% under heavy loss.

## Interop & compatibility

- **Both ends must list the same geometry for the same leg.** The encoder
  (bonded output) and decoder (bonded input) are keyed by `PathId`; a mismatch
  means the decoder never recognises the repairs.
- **Per-leg and combined FEC are mutually exclusive per bond.** Both use the
  same FEC datagram flag, and the receiver decides which parser to use from its
  config (per-leg mode is active iff any leg has `fec`). The edge's validation
  rejects configuring both `fec` (combined) and any `path.fec` (per-leg) on the
  same bonded input/output.
- **Proprietary, both-ends-bilbycast** — like the rest of the `0xBC` bond. No
  third-party interop is implied or affected.

## Code map

| Concern | Location |
|--------|----------|
| Codec (`PerLegFecEncoder` / `PerLegFecDecoder` / `PerLegRepair`) | `bonding-protocol/src/protocol/fec.rs` |
| Config field (`per_path_fec: HashMap<PathId, PerLegFecKind>`) | `bonding-transport/src/config.rs` (`BondSocketConfig`) |
| Sender (per-leg encoders, repairs on their own leg) | `bonding-transport/src/sender.rs` |
| Receiver (per-leg decoders, recover → reassemble, session reset) | `bonding-transport/src/receiver.rs` |
| Edge config (`BondPathConfig.fec`) + validation (bounds + exclusivity) | `bilbycast-edge/src/config/{models,validation}.rs` |
| Edge wiring (`BondFecConfig` → `per_path_fec`) | `bilbycast-edge/src/engine/{input_bonded,output_bonded}.rs` |
| Manager UI (per-leg Columns/Rows on each leg) | `bilbycast-manager` `ui/static/js/config/bonding.js`, `ui/static/js/shared/bond_info.js` |

## Tests

- Codec units in `bonding-protocol/src/protocol/fec.rs` (`per_leg_*`): wire
  round-trip, single-loss with **non-contiguous** seqs (proves a leg can carry
  a subset of the global stream), consecutive leg-burst recovery, repair-before-
  source out-of-order recovery, and `reset()` clearing state.
- End-to-end in `bonding-transport/tests/bond_adaptive.rs`
  (`per_leg_fec_recovers_leg_burst_without_arq`): a relay drops a 6-packet
  burst on a leg with **ARQ disabled**, asserting the only recovery path — the
  per-leg repair — rebuilds the burst (`gaps_recovered ≥ 6`, `gaps_lost == 0`).
