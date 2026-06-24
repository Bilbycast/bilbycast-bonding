# Packet Redundancy

FEC and ARQ *recover* a packet after it's lost. **Redundancy** avoids the loss
in the first place: send the same packet on **N legs**, and a copy survives as
long as *any one* of them delivers it. It's the strongest loss-resilience a
bond can offer — at the cost of N× the bandwidth for the replicated traffic.
This is the model behind SpeedFusion's "WAN Smoothing" and the duplicate-on-air
modes broadcasters reach for when a moment absolutely cannot drop.

It is **sender-side only** — the receiver already de-dups replicated packets by
`bond_seq`, so there's no wire-format or receiver change, and you can turn it on
per bonded output without touching the other end.

## Modes

Configured on the bonded **output** (edge: `output.redundancy`), applied to
whichever scheduler the bond uses:

- **Off** (default) — no extra replication. The scheduler still duplicates
  `Critical`/IDR keyframes across the two best legs (a baked-in keyframe
  protection that costs little). **No added bandwidth.**
- **Duplicate everything** (`all`) — every packet is sent on the N best legs.
  Bulletproof; uses N× the bandwidth. For a low-bitrate must-not-drop feed
  over several legs this is entirely affordable (a 3 Mbps feed × 2 legs = 6
  Mbps).
- **Threshold** (`threshold` + `min_priority`) — replicate only packets at or
  above a priority (`normal` / `high` / `critical`), leaving the rest single.
  The middle ground: with the media-aware scheduler tagging parameter sets +
  keyframes as `Critical` and elevating other important packets, a
  `high`-and-above threshold protects the frames a decoder can't lose without a
  visible glitch while sparing the cost of duplicating every P-frame.

`replicas` (2–8, clamped to the live leg count) sets **how many** of the best
legs each replicated packet rides. `2` = primary + one backup; raise it only
when two legs can plausibly fail at once.

## How it picks legs

The replicas go to the **N best alive legs** by the active scheduler's own
ranking — the capacity-aware scheduler scores by spare capacity × quality, the
RTT scheduler by lowest RTT. The token-bucket debit is recorded for every
replica so the congestion controller sees the added load (replication is a
deliberate bandwidth spend, so the legs aren't afford-gated — but the cost is
accounted).

## When to use it (and when not to)

| Situation | Reach for |
|-----------|-----------|
| Low-bitrate contribution that *cannot* drop, bandwidth to spare | **Duplicate everything**, replicas 2–3 |
| Important-but-not-trivial feed, want keyframe-grade safety cheaply | **Threshold (High)**, replicas 2 |
| Normal bond, bandwidth matters | **Off** — lean on per-leg FEC + cross-leg ARQ |

Redundancy is **orthogonal** to FEC and ARQ — it stacks with both. The usual
ladder of cost vs. resilience:

1. **Multi-path diversity + cross-leg ARQ** (always on) — cheapest.
2. **Per-leg FEC** ([`per-leg-fec.md`](per-leg-fec.md)) — proactive, no
   round-trip, modest overhead.
3. **Redundancy** — the most robust, the most bandwidth. Use it for the
   packets (or feeds) that truly can't drop.

## Code map

| Concern | Location |
|--------|----------|
| `RedundancyMode` / `RedundancyPolicy` / `Priority::rank` | `bonding-protocol/src/protocol/scheduler.rs`, `packet.rs` |
| `BondScheduler::set_redundancy` + per-scheduler application | `scheduler.rs` (RoundRobin, WeightedRtt), `capacity_scheduler.rs` |
| Edge config (`BondedOutputConfig.redundancy`) + validation | `bilbycast-edge/src/config/{models,validation}.rs` |
| Edge wiring (`build_redundancy` → `set_redundancy`) | `bilbycast-edge/src/engine/output_bonded.rs` |
| Manager UI (mode / replicas / threshold) | `bilbycast-manager` `ui/static/js/config/outputs.js` |
