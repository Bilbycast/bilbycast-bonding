# Shared-Leg Broker — Priority Reservation for Bonds That Share an Uplink

Status: **IMPLEMENTED, priority model** (2026-07-04). Edge: `engine::bond_leg_broker`
(registry + priority-tier allocator + 100 ms tick + aggregate adaptive capacity
controller + guaranteed-breach alarm), `AppConfig.bond_uplinks` (optional),
`BondedOutputConfig.priority`, health `bond_leg_contention`. Bonding:
`CapacityAwareScheduler` reads a live per-leg ceiling atomic (`ceiling_sub` /
`ceiling_handles()`) that throttles its token bucket while leaving `capacity_bps`
as the uncapped demand signal. **ON by default**; a lone flow on a leg is left
unconstrained, so the broker is a no-op until two flows actually share a leg.

> This supersedes the original "declare each uplink's capacity, divide it by
> weighted max-min fairness" spec. Operators rejected typing capacity numbers
> (a 5G/Starlink/ISP top rate you can't know and that varies constantly). The
> model is now: **auto-discover capacity, reserve it by per-flow priority.**

---

## 1. The problem it solves

A single bonded flow works fine on its own. The issue is **N bonded flows
sharing the same physical uplink** — e.g. three bonds all pinned to one 5G
modem, or six camera flows over three shared legs.

Each bonded flow runs its own `CapacityAwareScheduler` with private per-leg
congestion controllers. When several of them push over the *same* NIC, each one
independently discovers "this link carries ~C" and tries to use C — so the link
is over-subscribed, and because independent MIMD controllers **don't converge to
a fair split** (Chiu & Jain, 1989), it divides by first-mover-wins, not by
importance. One flow hogs the modem; another starves and pixelates *even though
"there's enough bandwidth."*

No single flow's scheduler can fix this — it can't see the other flows. Only a
host-level coordinator with a cross-flow view can.

---

## 2. Two layers — scheduler vs broker

They are **not** alternatives. They work together at different layers, and
removing either breaks a different thing.

```
   ┌─ BROKER (host-level, cross-flow) ─────────────────────────┐
   │  "eno4 carries ~10 Mbps. Flow A (Critical) may use up to   │
   │   6, Flow B (Best-effort) up to 4."      → writes a CEILING │
   └───────────────┬───────────────────────────────────────────┘
                   │ per-(flow, leg) ceiling atomic
                   ▼
   ┌─ SCHEDULER (per-flow, cross-leg) — CapacityAwareScheduler ─┐
   │  "Within Flow A's ceiling, split its packets across eno4 +  │
   │   wwan1 + Starlink by each leg's live capacity; duplicate   │
   │   IDR frames on the two best legs; ARQ/FEC/reorder."        │
   └────────────────────────────────────────────────────────────┘
```

- **The scheduler is the bonding.** It aggregates the legs — routes each packet,
  discovers per-leg capacity, shifts traffic off a lossy leg, duplicates IDR
  frames, drives ARQ/FEC. It does 100% of the packet work it always did.
- **The broker touches no packets.** It answers the one question the scheduler
  structurally cannot: *when two different flows both want eno4, how much does
  each get?* It writes each flow a **ceiling** per shared leg; the scheduler then
  aggregates *within* that ceiling.

| | Scheduler | Broker |
|---|---|---|
| Scope | one flow, across its legs | one host, across flows on a shared leg |
| Job | split packets, recover loss, aggregate | divide a shared leg by priority |
| Touches packets? | yes (hot path) | no (100 ms timer, one atomic write) |
| Remove it and… | bonding stops entirely | flows fight over shared uplinks again |

- **One bond, dedicated legs** → the broker writes "no constraint" and is inert.
  Identical to pre-broker behaviour.
- **Multiple bonds sharing a leg** → the scheduler still does all the
  aggregation; the broker just caps how much of the shared leg each flow may
  fill, so they stop fighting.

---

## 3. The priority model

Every bonded output carries a **priority tier** (`BondedOutputConfig.priority`,
default `best_effort`):

| Tier | Meaning |
|---|---|
| `critical` | Reserved first. Gets its measured demand before anything else. The main programme feed. |
| `normal` | Guaranteed too, but yields to `critical` under contention. |
| `best_effort` (default) | Takes only the spare capacity the guaranteed tiers leave. Previews, confidence feeds, file transfers. |

Capacity is handed out **tier by tier, strict priority between tiers, weighted
max-min within a tier**:

```
remaining = leg_capacity
for tier in [Critical, Normal, BestEffort]:
    members = flows in this tier on this leg
    caps    = [ min(demand_i, hard_cap_i) for i in members ]   # demand = VBR peak
    alloc   = weighted_maxmin(weights, caps, remaining)         # fair within tier
    assign alloc; remaining -= Σ alloc
```

So all `critical` demand is satisfied (up to capacity) before any `normal`, and
all `normal` before any `best_effort`. `weight_hint` only breaks ties **within**
a tier — it does not cross tier boundaries.

**No bandwidth number is ever typed.** The broker *measures* each flow's demand
live, so it adapts to CBR and VBR automatically.

### VBR handling

A guaranteed flow reserves its **smoothed recent peak** rate, not its
instantaneous rate (`Member.peak_demand_bps = max(demand, peak × PEAK_DECAY)`,
`PEAK_DECAY = 0.985`/tick ≈ 4.6 s half-life). So its reservation holds through
the troughs of a variable-bitrate stream instead of being surrendered every time
the instantaneous rate dips. The peak-hold is tied to the activity-grace window:
a flow that has gone genuinely idle (grace drained, ~3 s of silence) releases its
peak immediately so a dead flow can't hoard a reservation it isn't using.

---

## 4. Where capacity comes from — auto-discovered, not declared

**Default (and correct for 5G / Starlink / ISP): don't declare anything.** The
broker runs one aggregate loss+delivered-rate controller per physical leg
(`adapt_capacity`): probe up ~+5 %/tick while the aggregate is clean, back off
~−10 % toward the delivered rate the moment aggregate loss appears. On a link
whose top rate swings 8→30→12 Mbps it *tracks the variation live* — which is
exactly the number a human can't type.

**Policy cap (`bond_uplinks`, optional).** The only reason to give a number is a
fixed limit the broker **cannot see as packet loss**, because it's a business
rule, not physics:

- a **metered data plan** (the modem can push 50 Mbps but your plan bills/shapes
  past 10 — exceeding it costs money, it doesn't drop packets);
- a **contracted rate** (CIR / SLA sold at N Mbps);
- **reserving headroom** for other traffic on a shared line.

Those are numbers you know from a contract, not from measuring. Auto-discovery is
blind to them precisely because they don't cause loss. That's the *only* thing a
`bond_uplinks` entry is for — a ceiling the aggregate controller never probes
past. It is **not** "the link speed" and you should **not** measure and enter it.

---

## 5. Do I need to configure anything?

Usually **no**. The workflow is:

1. Create the bonded link (wizard, as always).
2. Set each flow's **priority** on its bonded output (default `best_effort`).
3. Done.

The broker is on, auto-discovers capacity, and only engages when two flows share
a leg. You touch `bond_uplinks` (the "policy cap" panel) *only* for a
metered/contracted link.

### The all-equal case (e.g. 5 cameras, all Critical)

If every flow is the same tier, the priority *tiers* do nothing — there's no
differentiation to make. But the broker still earns its keep: the tier-by-tier
allocator collapses to a single **weighted-fair division**, so the cameras share
the modem *evenly* instead of first-mover-wins random starvation. Marking them
all `critical` additionally makes the over-subscription **alarm** fire when the
links genuinely can't carry them. So even with everything critical you get: even
division + an honest "you're over capacity" signal. The priority tiers only pay
off the day you add a genuinely sacrificable flow (preview, return/IFB feed,
replay/file upload) sharing the same uplink.

---

## 6. Honest limits

The broker **cannot manufacture bandwidth.** If the `critical` + `normal` flows
together need more than a shared link can physically carry, priority can't
conjure the difference — someone is squeezed. What the broker does then is
**protect the guaranteed flows in priority order and raise an alarm on the
shortfall** (`bond_leg_oversubscribed`, with `guaranteed_unmet_bps`), so the
degradation is *predictable and visible* instead of a random camera breaking up.
The real fix for genuine under-provisioning is provisioning: dedicated legs, more
capacity, or lower per-camera bitrate.

Best-effort shortfall is **by design** and does **not** alarm — a best-effort
flow yielding to a guaranteed one is the system working, not a fault.

---

## 7. Config surface

| Field | Location | Meaning |
|---|---|---|
| `priority` | `BondedOutputConfig` (**the knob**) | `critical` / `normal` / `best_effort` (default). Sender-side only. |
| `weight_hint` | `BondPathConfig` (exists) | intra-tier fair-share tiebreaker + capacity prior. Does **not** cross tiers. |
| `max_bitrate_bps` | `BondPathConfig` (exists) | per-flow-per-leg hard cap the broker never exceeds. |
| `bond_uplinks[]` | AppConfig root (**optional**) | `{ interface, capacity_bps, min_viable_bps?, demand_active_bps? }` — a **policy cap** for a metered link, keyed by NIC. Skip on un-metered links. |
| `shared_leg_broker` | AppConfig root (optional bool) | **unset → ON** (default). `false` reverts to uncoordinated per-bond contention. |

`capacity_bps` validation: `[100_000, 400_000_000_000]`. `min_viable_bps` /
`demand_active_bps` are advanced floors in `(0, capacity_bps]` (defaults 200 k /
50 k). No wire-format change, no receiver change, no per-flow-scheduler algorithm
change beyond reading a live ceiling.

**Why a policy cap is keyed by NIC, not by flow:** a shared modem's cap is a
property of the *shared resource*. Two flows on `eno4` can't each own "eno4 ≤ 10
Mbps" — there's no coherent per-flow place to say "these two flows *together* ≤
10". `bond_uplinks[interface]` is the one place that expresses a shared limit
once. (A per-flow cap on *one* flow's leg is `max_bitrate_bps`, a different
thing.)

---

## 8. Telemetry — `bond_leg_contention`

Emitted on health when any leg is shared (edge advertises the `bond-broker`
capability). Per physical leg:

- `leg_key`, `capacity_bps` (discovered), `member_count`
- `oversubscribed` — a **guaranteed** flow is starved below its reserved demand
  (best-effort shortfall does **not** set this)
- `unmet_bps` (all tiers) + `guaranteed_unmet_bps` (Critical+Normal shortfall)
- per member `{ flow_id, path_id, weight, priority, demand_bps, allocation_bps,
  protected }` — `protected` = got ≈ its full demand this tick

The manager renders this as the node-detail **Shared Uplink Contention** card and
in the config-form live block: a Critical/Normal/Best-effort pill per flow, a
protected ✓ / degraded ⚠ indicator, and a "PRIORITY BREACH" vs "PRIORITIES
HONOURED" leg badge. This is the operator's *shared-leg* view (every other stat
is per-flow, which hides the contention).

---

## 9. Non-blocking contract

All broker arithmetic runs on a single 100 ms timer task, never on a packet path.
The only data-path interaction is the scheduler's one relaxed `AtomicU64::load`
of its ceiling per refill (in `capacity_scheduler::refill_all`) — same cost as
the existing `capacity_pub` store. The registry is a `DashMap`; a leg's `Mutex`
is held only during the tick computation or a flow start/stop, never contended by
the hot path. Feature off / lone flow → ceilings are `u64::MAX` (unconstrained) =
byte-identical to pre-broker behaviour.

---

## 10. Failure modes

- **Broker off / lone flow / dedicated legs** → `u64::MAX` ceilings; zero
  regression, scheduler unaffected.
- **Broker task stalls** → ceilings freeze at last value (bounded, safe) —
  strictly safer than un-clamping.
- **Idle/dead flow** → its peak-demand collapses once activity-grace drains, so
  it releases its share and can't hoard allocation (unblocks the aggregate
  probe-up).
- **Capacity mis-discovered high** → induces aggregate loss, the controller backs
  off toward delivered rate within a few ticks; self-healing.
- **Guaranteed over-commit** → protect Critical, then Normal, in order; alarm the
  shortfall; best-effort gets the remainder. No collapse, no silent starvation.
- **Alarm flap** → hysteresis on the guaranteed shortfall (enter > 2 % of
  capacity, leave < 0.5 %) so a VBR flow grazing its reservation edge doesn't
  toggle the alarm every tick.

---

## 11. Code map

- `bilbycast-edge/src/engine/bond_leg_broker.rs` — registry, `allocate()`
  (tier-by-tier), `tick_leg` (VBR peak + guaranteed-breach), `adapt_capacity`
  (aggregate controller), `contention_snapshot`, `configure` (default-on).
- `bilbycast-edge/src/config/models.rs` — `BondPriority` enum,
  `BondedOutputConfig.priority`, `BondUplinkConfig`, `AppConfig.bond_uplinks` /
  `shared_leg_broker`.
- `bilbycast-edge/src/engine/output_bonded.rs` — registers each leg with the
  broker (threads `config.priority`).
- `bilbycast-edge/src/manager/client.rs` — `set_bond_uplinks` command; health
  `bond_leg_contention`; `update_config` re-`configure()` + persists
  `bond_uplinks` / `shared_leg_broker`.
- `bonding-protocol/src/protocol/capacity_scheduler.rs` — `ceiling_sub` /
  `ceiling_handles()`, `broker_ceiling_bps`, `effective_bps()`.
- Manager UI: `config/outputs.js` (priority dropdown), `config/bond_uplinks.js`
  (policy-cap panel + live block), `detail/flows.js` (contention card),
  `shared/bond_info.js` (`bond_priority` popover), `device-edge/src/lib.rs`
  (wizard `priority` field), `manager-core/src/ai/knowledge/media/bonding.rs`.
