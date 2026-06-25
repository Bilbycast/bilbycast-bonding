# Per-Leg Latency/Jitter Equalization (aggregation of heterogeneous legs)

Status: **BUILT + e2e-proven + edge-integrated + adversarially reviewed +
self-configuring (`auto` by default).** A bond is always multi-path and the
dominant case is heterogeneous aggregation (cellular + Starlink + ISP), so
equalization is no longer an on/off flag the operator must set — it is an
**automatic behaviour with one latency knob**.

**Settings model (as-built).** Operator-facing surface on a bonded input/output:
- `equalization: "auto" | "off" | "on"` (default **`auto`**; serde-accepts the
  legacy boolean, `true`→`auto`, `false`→`off`).
  - **`auto`** — stamp + measure one-way delay ALWAYS; *engage* alignment only
    when the measured inter-leg skew exceeds the engage floor (hysteresis: engage
    above the floor, disengage below half, plus an `EQ_ENGAGE_DEBOUNCE` /
    `EQ_DISENGAGE_DEBOUNCE` of 3 consecutive recomputes), fits the budget, and the
    sender isn't ride-fastest. The floor is *derived from the jitter hold*
    (`SKEW_FLOOR_HOLD_NUM/DEN` = 3/4 × hold, clamped to
    `[SKEW_FLOOR_MIN_US, SKEW_FLOOR_MAX_US]` = 20–200 ms), not a fixed constant.
    A homogeneous bond measures ~zero skew → no-op; a heterogeneous bond aligns
    itself. Self-configuring.
  - **`off`** — never stamp/measure/align: the legacy aggregate-but-never-align
    path (the latency-critical escape hatch — a slow leg's reorder is
    ARQ/FEC-recovered rather than absorbed by alignment latency). The single
    budget knob can't express this, which is why the mode survives.
  - **`on`** — force-engage whenever a leg is warm; overrides ride-fastest
    suppression (for a time-aligned downstream consumer of a duplicate-all bond).
- `max_bonding_latency_ms` (default **1000**) — the **single** latency budget,
  set the same on both ends. Fans out to the receiver's alignment ceiling +
  loss-recovery deadline (`hold_max`/`eq_budget`) and the sender's L4 demote
  threshold. `hold_ms` (the jitter floor) stays a *separate* axis.
- **Redundancy suppression:** a duplicate-all (`redundancy.mode = "all"`) sender
  sets the keepalive `KA_FLAG_ALIGN_SUPPRESS` bit so the receiver suppresses
  alignment (ride-fastest intent). Threshold redundancy keeps alignment on (the
  un-duplicated bulk still aggregates).

**Mechanism.** L1a wire header v2 (16-byte, `send_stamp_us`); L1b keepalive-ack
`relative_owd_us` (SIZE_V4) + the v2 negotiation field `recv_protocol_version`
(SIZE_V5); keepalive `mode_flags`/`KA_FLAG_ALIGN_SUPPRESS` (SIZE_V4). L2 receiver
windowed-min OWD. L3 skew-gated engage + per-leg `equalize` table + dead-leg
staleness recompute + cold-start servo handover. L4 sender-side budget-demote.

**loss_deadline (the fix).** Covers the budget while alignment is **engaged**
*and* during a `COLD_START_GRACE` (3 s) after the first stamp (so a high-skew
leg's gaps survive while legs warm and the engage decision settles — the servo
can't bootstrap that); otherwise a confirmed low-skew bond that never engaged
tracks the servo'd jitter-hold, so a clean bond keeps a SMALL gap-to-Lost
deadline instead of being pinned to the full budget on the first stamp.

**Negotiation / rollout safety (kept as the alarm basis).** The sender NEVER
emits v2 until the far receiver advertised v2 capability in its keepalive-ack
(`recv_protocol_version >= 2`), advertised only when the receiver's mode
measures (auto/on). A receiver that's `off`/old advertises v1 → the sender stays
on v1 → no brick, no wasted stamps. A per-leg `bond_protocol_version_mismatch`
Warning (edge `category::BOND`) + the `header_parse_drops` / `UnsupportedVersion`
counter make a version mismatch visible instead of silent.

**Tests:** reassembly + control + packet unit tests; `tests/bond_equalization.rs`
(`auto` aggregation happy-path + the v2-sender/v1-receiver no-brick regression);
edge `bonded` lib tests (mode mapping, single-budget derivation, align-suppress).
Full bonding suite green. Live: 2-leg (OTD500 + TRM500) previously verified at
relative_owd 19–37 ms, both legs aggregating, CC-clean.

**Post-review hardening (adversarial review, 12 agents).** Confirmed-real fixes
applied: (1) on a **session reset / sender restart** the receiver-local OWD
estimator + eq state (`leg_owd`, `eq_active`, `eq_engaged`, `eq_active_since`,
`peer_align_suppress`) is reset in lockstep with `reassembly.reset()` — the
sender's `send_stamp` origin (process boot) just reset, so the old baselines were
stale and would feed bogus inter-leg skew for up to `OWD_MIN_WINDOW`; (2) when
**every leg goes fresh-data-stale** (a brief total-uplink stall) the recompute now
**disengages** (clear offsets, `eq_engaged=false`) instead of latching ON with
stale offsets pinned (which spiked the fast leg's latency on recovery + kept the
servo gated off); (3) edge validation now rejects `max_bonding_latency_ms <
hold_ms`; (4) the `equalization` field is `skip_serializing_if` (no `null`
rewrite); (5) the MTU/oversize budget accounts for the 16-byte v2 header when
stamping; (6) both ends log their effective latency budget so a cross-end
mismatch (the single knob set differently per node) is visible.

**Behavior change (by design — auto default).** A bonded input/output that omits
`equalization` now defaults to **`auto`** (was effectively off), so it measures
OWD and stamps the 16-byte v2 header once the peer advertises v2. On a
homogeneous bond this never *engages* alignment (skew < floor → no-op), so the
only change is +4 bytes/packet of header + measurement; on a heterogeneous bond
it self-aligns. Set `equalization: "off"` to keep the legacy aggregate-but-never-
align (and v1-header) path. The live edge1/edge6 configs carry explicit
`equalization: true` (→ `auto`) so they are unaffected.

**Remaining (NOT done):** a sender-restart-with-equalization e2e test is a known
coverage gap. (The fixed-20 ms engage floor was live-validated on the 3-leg
5G+Starlink+ISP gate 2026-06-25 — it flapped dead-centre in the real ~12–24 ms
skew band, which is why the floor is now *derived from the hold* (3/4 × hold,
clamped 20–200 ms) with an engage/disengage debounce; see `SKEW_FLOOR_*` /
`EQ_*_DEBOUNCE` in `receiver.rs`.)

Authoritative spec for turning the bonding
receiver from "ride the cleanest leg" into "aggregate N heterogeneous legs (different
one-way delay + jitter + bandwidth) into one in-order pipe", the capability needed to
carry multiple production feeds over e.g. real 5G + Starlink. SpeedFusion-class.

This spec resolves the conflicts and **all hazards** found by the design review
(`workflows/.../bond-per-leg-equalization-design`). Every item the adversarial reviewers
flagged as "must fix before build" is addressed here with a named subsection.

## The problem

Legs have different one-way delays (OWD). A packet on a 30 ms leg and a packet on a
200 ms leg with adjacent `bond_seq`s arrive ~170 ms apart, so the fast leg's packet
head-of-line-waits for the slow one. To aggregate ALL legs you must cover the inter-leg
delay **spread**. The current code instead demotes any >150 ms-jitter leg off the media
path (quality protection), which is correct for a pathological retail modem but
*prevents aggregation* of a high-bandwidth high-latency-stable leg.

Per-leg equalization time-aligns every leg to the slowest **eligible** leg, so all legs
deliver as if they shared one latency; the in-order reassembly then only holds for
residual jitter, and a leg is benched only when aligning it would exceed an operator
**latency budget** (or its delivered rate collapses) — not on raw jitter.

## Resolved architecture (4 layers)

```
 sender                                   receiver
 ──────                                   ────────
 [L1 wire] stamp each DATA pkt with        measure per-leg relative OWD  [L2 measure]
   send_stamp_us (v2 header, negotiated)     owd_min[leg] (windowed min)
                                            eq_offset[leg]=max_elig_owd-owd[leg]
 [L4 demote] media_eligible flips on    ◄── equalizability verdict       [L3 equalize]
   receiver verdict (v4 keepalive-ack)      per-slot release_at in ring
   OR sender-local fallback                  + jitter-hold / loss-deadline split
```

- **L1 Wire** — per-packet send-timestamp (measurement source) + a keepalive-ack field
  (demote coordination), both version-negotiated and back-compatible.
- **L2 Measurement** — receiver derives each leg's relative OWD as a windowed minimum.
- **L3 Equalization + hold split** — per-slot `release_at` in the reassembly ring aligns
  legs; the loss-recovery deadline is split from the in-order jitter-hold.
- **L4 Demote redesign** — `media_eligible` flips on "un-equalizable within budget OR
  rate-collapsed", coordinated receiver→sender, with a sender-local fallback.

Everything defaults to **today's behaviour** (equalization OFF, no header growth emitted)
so every existing config stays byte-valid and every v1 peer keeps working.

---

## L1 — Wire protocol (back-compatible, version-negotiated)

### 1a. Data-header send-timestamp — `PROTOCOL_VERSION` 1 → 2

`packet.rs`: the 12-byte header grows to **16 bytes at version 2** by appending
`send_stamp_us: u32` (sender monotonic microseconds, wrapping ~71 min — only *differences*
within a seconds-scale window are ever taken, so wrap is harmless).

- `BondHeader::parse` is version-gated: `ver==1` → read 12 bytes, `send_stamp_us=0`,
  `has_stamp=false`; `ver==2` → read 16 bytes, `has_stamp=true`. (Resolves the reviewers'
  "parse() is not length-tolerant" + "all 4 flag bits already used, no spare flag" — we
  use the **version nibble**, not a flag bit.)
- `BondHeader::write_to` emits 16 bytes only when the sender has negotiated v2 for that
  leg (below); otherwise 12 bytes, byte-identical to today.

**HAZARD: rolling-upgrade / v1↔v2 interop.** A v1 receiver rejects a v2 packet
(`packet.rs` rejects unknown version). So the **sender must not emit v2 until it knows the
receiver speaks v2.** Negotiation rides the existing keepalive-ack `protocol_version`
(`control.rs`): the sender emits v1 (12 B, no stamp, equalization disabled) until the first
keepalive-ack reports `protocol_version >= 2`, then switches that leg to v2. A receiver
always *parses* both. This makes a mixed-version bond degrade to today's behaviour during
the upgrade window instead of breaking — and the bond is proprietary both-ends so the
window is short.

### 1b. Keepalive-ack equalizability field — `KeepaliveAckBody` SIZE_V3 → SIZE_V4

`control.rs`: append `equalizability: u32` to `KeepaliveAckBody` (one byte of bitflags per
leg id is too small for >8 legs; use a compact `(path_id<<1)|eligible` list OR a single
`u32` budget-headroom hint — **decision: a per-leg `relative_owd_us` the receiver measured
for the leg this ack is about**, plus 1 status bit "exceeds budget"). Parse **defensively**
(`if r.remaining() >= 4 { ... } else { 0 }`, mirroring the existing v2/v3 tolerant parse).
Older peers ignore it; absence → sender falls back to local jitter_demote (L4).

---

## L2 — Per-leg relative OWD measurement (receiver)

`receiver.rs`, in the DATA-packet block (NOT control, NOT FEC repairs — repairs carry a
foreign seq + their own latency).

Per leg, `LegDelay { owd_min_us, owd_min_at, samples }`:

```
raw = arrival_us.wrapping_sub(header.send_stamp_us)   // const sender+rx offset + leg OWD + jitter
// windowed MIN (BBR RTprop), aged like scheduler rtt_min:
if raw < owd_min_us || now - owd_min_at > OWD_MIN_WINDOW (10 s):
    owd_min_us = raw; owd_min_at = now
```

Only **differences** between legs are physically meaningful:
`relative_owd(i) = owd_min[i] - min over eligible legs(owd_min)`. The constant sender-Instant
and receiver-Instant epochs both appear additively in every `raw`, so they **cancel exactly**
in the subtraction (handles reviewers' "offset cancels only in the spread / Instant has no
common epoch").

**HAZARD: clock RATE skew** (cellular CPE under thermal load, tens of ppm). Bounded by the
windowed-min aging: a slow drift re-baselines every `OWD_MIN_WINDOW`. **HAZARD: u32 wrap** —
`wrapping_sub`, and the genuine OWD spread (≪ 71 min) never spans a wrap within the window.
**HAZARD: cold-start** — until `samples >= COLD_START_SAMPLES` (16) the leg's `eq_offset = 0`
(equalize-nothing = today's full-spread global hold), then ramp in; no forward time
discontinuity because eq_offset only ever *grows* a fast leg's hold (delays delivery), never
shortens it. **HAZARD: pre-mux queueing** (receiver.rs blocking mux) inflates `arrival` — but
it inflates ALL legs equally and the windowed *min* discards transient queueing, so the
inter-leg *difference* is unaffected in steady state.

---

## L3 — Equalization mechanism + hold/recovery split (reassembly)

**Resolved: per-slot `release_at` folded into `drain_inner` (Dim 2), NOT a pre-reassembly
delay line (Dim 3).** Rationale: keeps the single-writer flat ring and its wrap-safety,
adds NO second time-ordered structure, NO extra `select!` wakeup, NO second writer — the
reviewers' biggest correctness worries about a delay line (corrupting the `arrival` stamp,
blocking, single-writer violation, seq-wrap in a second buffer) all evaporate.

`reassembly.rs` — **IMPLEMENTED** (build refinements vs the original Dim-2 sketch):

- **Per-leg hold is computed at DRAIN time from a `equalize: [Duration; 256]` table, NOT
  frozen as a `release_at` on the slot.** This is strictly better for the dead-leg hazard:
  when the receiver recomputes `equalize[leg]` downward (slowest leg died), already-buffered
  fast-leg packets are released sooner on the very next drain — a frozen `release_at` would
  keep over-holding them. `SlotState::Filled` is unchanged ({data, arrival, path_id}).
- **The hold is ADDITIVE: `filled_hold = jitter_hold + equalize[path_id]`** (saturating), not
  `max(jitter_hold, offset)`. The offset aligns a fast leg's *arrival* to the slowest leg's;
  the jitter-hold then covers the slowest leg's residual jitter *on top* of that alignment.
- Original sketch (kept for reference): `SlotState::Filled { data, arrival, path_id, release_at }`.
- `ReassemblyBuffer`: add `jitter_hold: Duration` (the post-equalization in-order hold; the
  servo target), `loss_deadline: Duration` (the gap→Lost deadline; ≥ slowest-eligible-leg
  recovery RTT), and `equalize: [Duration; 256]` (path_id-indexed offset, default ZERO).
  Replace the single `hold_time` with these. `set_equalization(path_id, offset)`,
  `set_jitter_hold(d)`, `set_loss_deadline(d)`.
- `insert`: at each `Filled` construction, `release_at = now + equalize[path_id]`
  (saturating; offset is always ≥ 0 since it's `max_owd - this_owd`).
- `drain_inner` Filled head: release when `now >= release_at AND now - arrival >= jitter_hold`.
  Gap→Lost and never-arrived-base paths use **`loss_deadline`** (not jitter_hold).
- `next_drain_time`: Filled arm → `max(release_at, arrival + jitter_hold)`; Gap arm →
  `first_noticed + loss_deadline`.

Why this aggregates + smooths: a fast leg's packet gets a *later* `release_at` (delayed to
the slow-leg timeline), so by the time the in-order head reaches it the slow leg's
adjacent-seq packet has already arrived → the contiguous head advances one packet per
source-cadence interval = **smooth delivery** (kills the HOL-burst jerkiness), and
`jitter_hold` only needs to cover residual jitter.

**HAZARD: hold-vs-recovery coupling.** Split into two budgets: `jitter_hold` governs
in-order release; `loss_deadline = max(jitter_hold + max_eq_offset, slowest_eligible_leg
recovery RTT + FEC margin)` governs gap→Lost so a NACK round-trip on the slow leg still
lands before the gap ages out. **HAZARD: recovered_age feedback loop** — a late fill on an
equalized leg reports `recovered_age` that now includes the artificial `eq_offset`;
**subtract `eq_offset[accepted_path]` from `recovered_age` before it feeds `hold_window_max`**
(receiver.rs servo) so equalization delay can't ratchet the hold upward. **HAZARD: leg dies
mid-equalization** — `on_path_dead` (and the receiver liveness monitor) must recompute
`max_eligible_owd` DOWNWARD and re-push `set_equalization` for every leg immediately, so
fast legs stop over-holding for a leg that's gone (prevents the failover latency spike);
add a receiver-side failover test (the existing `failover_ramps_within_a_second` is
sender-only). **HAZARD: session reset** — flush `equalize[]` + `LegDelay` state on
`reassembly.reset()` / epoch change so a restarted sender's stale delays are discarded.
**HAZARD: stale after equalize** — a delayed fast-leg packet must not land after `base_seq`
advanced past it; `eq_offset` is clamped to `≤ hold_max` (the budget) and `jitter_hold`
covers the residual, so a packet is never delayed past its own delivery deadline.

---

## L4 — Demote redesign (capacity_scheduler) + coordination

Keep `media_eligible` as the exact scheduler output (no change to best/best_n_alive/
pick_single) and keep `jitter_demote_us` as a back-compat opt-out switch — change only
**what flips the flag**. A leg loses `media_eligible` after `JITTER_DEMOTE_ROUNDS` fresh
rounds where EITHER:

- **(A) Un-equalizable**: `equalization_cost_us(leg) > max_bonding_latency_us` — i.e.
  aligning this leg to the others would blow the operator latency budget. The
  authoritative cost is the **receiver's** measured relative OWD, fed back over the v4
  keepalive-ack (L1b). Sender-local fallback when the field is absent (v1/v2/v3 peer):
  estimate from the leg's own `rtt + JITTER_HOLD_MULT × jitter` vs budget.
- **(B) Rate-collapsed**: `delivery_bps < rate_collapse_frac × demanded_share` despite
  demand (the leg's radio has failed, not merely slowed).

`CongestionConfig`: add `max_bonding_latency_us` (default 1_000_000 = 1 s) and
`rate_collapse_frac` (0.25). `PathCc`: add `latency_budget_us` + consume the keepalive-ack
verdict in `on_path_update`. Re-admit with the existing hysteresis when both clauses clear.

**HAZARD: split-brain.** Receiver owns the budget verdict (it measures OWD); sender owns the
flag. The v4 keepalive-ack carries the verdict receiver→sender. Without it the two ends use
their independent jitter heuristics (today's behaviour) — degraded but not broken. A
demoted leg keeps carrying redundancy/FEC (best_n_alive) so it stays *measured* and can
re-admit when its radio recovers.

---

## Config surface (edge, manager-configurable per the no-env rule)

`BondedInputConfig` + `BondedOutputConfig` (edge `config/models.rs`):

- `equalization: Option<bool>` — default **false** (opt-in; defaults to today's behaviour).
- `max_bonding_latency_ms: Option<u32>` — the latency budget (default 1000; bounds the hold
  and the demote). Validated `[hold_ms, 5000]`.

Maps to `CongestionConfig.max_bonding_latency_us` and the receiver's `loss_deadline` /
`hold_max`. Both ends must agree on `equalization`; mismatched ends fall back to no-eq.

---

## Build order (each step compiles + tests green before the next)

1. **L1a wire**: header v2 + version-gated parse/write + version negotiation; unit tests
   (round-trip v1/v2, v1-receiver-tolerance, wrap). NO behaviour change yet (sender still
   emits v1 until negotiation lands).
2. **L1b control**: keepalive-ack v4 field, defensive parse; unit tests (v3/v4 tolerance).
3. **L2 measurement**: receiver per-leg `owd_min`; unit tests (offset-cancel, windowed-min
   aging, cold-start, wrap).
4. **L3 reassembly**: `release_at` + jitter_hold/loss_deadline split; reassembly unit tests
   (existing release/loss tests stay green + new equalization tests).
5. **L3 receiver wiring**: compute eq_offset, push to reassembly, dead-leg recompute,
   recovered_age de-bias, session-reset flush.
6. **L4 demote**: predicate redesign + keepalive-ack consume + sender-local fallback.
7. **edge config** + validation + manager UI surface.
8. **e2e**: shaped heterogeneous-aggregation test (30 ms + 200 ms legs both carry their
   bandwidth share, in-order, within budget) + receiver-side failover test; keep
   `bond_heterogeneous` / `bond_adaptive` / reassembly unit tests green.

## Regression gates (must stay green)

`reassembly.rs` release/loss unit tests; `capacity_scheduler.rs` `failover_ramps_within_a_
second_of_control_rounds`, `rtt_baseline_shift_recovers_after_window`; `control.rs` compat
test; `bond_adaptive.rs` (split + FEC recover) and `bond_heterogeneous.rs` (gaps_lost==0).
Plus the session-1 work this builds on: jitter_demote/media_eligible, per-leg hold
(`HOLD_JITTER_EXCLUDE_US`), metered per-leg FEC.
