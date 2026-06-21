# Bond leg testing — pre-flight usability + capacity

Operator-facing answer to *"does each leg have enough bandwidth to be used, and is
it usable?"* — a deliberate, per-leg test the operator triggers from the manager UI,
distinct from the always-on adaptive capacity discovery the running bond already does.

> **Hard requirement (the whole design bottom-lines on this):** a leg test must
> **never affect the performance of live traffic in any way.** Every mechanism below is
> chosen to make that true *by construction*, not by best-effort.

## Why this exists (what the bond does *not* already tell you)

The `CapacityAwareScheduler` (default `Adaptive`) continuously estimates each leg's
usable capacity — but the estimate is **passive and demand-bound**:

- It is learned only from *live media already flowing*, and bounded to
  `delivered_bps × probe_cap_mult` (default `2.0`). An idle/undersubscribed leg just
  *holds* its estimate (`capacity_scheduler.rs`: *"probing on nothing would inflate it
  to fiction"*). So if you push 5 Mbps over a bond you only ever learn ~5–10 Mbps of
  capacity — you cannot know whether it would carry 20 Mbps until you try it live.
- A too-small or **mis-wired** leg is never flagged — it is silently under-allocated
  down to the `min_rate_bps` floor (250 kbps). When `delivered_bps` is low the scheduler
  cannot tell you *why* (small link? wrong NIC binding? dead SIM? `rp_filter`? source
  bind wrong?).

So two genuinely new questions need a deliberate test:

1. **Usability / wiring** — is this leg physically up, bound to the intended interface,
   egressing the right NIC/gateway, with the source address present? (commissioning
   confidence; catches the dominant misconfiguration class.)
2. **Capacity** — roughly how many Mbps can this leg carry *right now*? (capacity
   planning before committing a target bitrate.)

## Two situations, one invariant

The zero-impact requirement splits the problem cleanly by leg state, which the edge
already knows (a leg is "live" iff a running flow's `BondSocket` owns it):

| Leg state | What a test may do | Why it's zero-impact |
|-----------|--------------------|----------------------|
| **Idle** (no running flow uses it) | Full active test — usability (Phase 1) + optional capacity probe (Phase 2) | There is no live traffic on the leg to affect. |
| **Live** (carrying a flow now) | **Usability checks only** (Phase 1 — emits zero packets), **plus a passive read-out** of the scheduler's existing `capacity_bps` / `delivered_bps` / RTT / loss | No new packets, no shared sockets/buckets/routes touched. An active capacity ramp is **refused** on a live leg — saturating a shared physical link would, by definition, affect the feed. |

This is enforced server-side: the edge resolves liveness before running anything and
degrades/refuses accordingly. The operator never has to remember the rule.

## Phase 1 — Pre-flight usability check (zero packets on the wire)

**Status: implemented.** Edge module `engine/bond_leg_test.rs`; WS command
`test_bond_leg`; capability `bond-leg-test`.

Phase 1 is **zero-impact by construction**: it puts *nothing* on the wire. It only
introspects the host and uses the one OS trick that reveals routing without sending —
**`connect()` on a UDP socket performs the kernel route lookup but transmits no
datagram**, so `getsockname()` afterward reveals the source IP / interface the leg
*would actually* egress on.

Checks performed (each returns `pass` / `warn` / `fail` / `skipped` + detail):

| Check | What it proves | How (no packets) |
|-------|----------------|------------------|
| `interface_link` | The pinned NIC exists and carrier is up; reports MTU + link speed | `util::network_interfaces::enumerate()` (sysfs) |
| `source_ip` | The gateway-mode `source` address is actually present on a NIC | enumerate + address match |
| `bind` | A socket can bind exactly as the leg will (strict `SO_BINDTODEVICE`, or source bind for gateway-mode) | build an ephemeral `socket2` socket; **never sent on** |
| `egress_route` | *interface-mode / default-route:* the leg egresses the intended NIC and does **not** collapse onto the kernel default route (the classic "cosmetic bond" trap) | `connect()` + `getsockname()` → map source IP → NIC |
| `first_hop` | *gateway-mode:* the next-hop router is reachable | read the kernel neighbor table (`/proc/net/arp`) — pure read |

Notes:
- **gateway-mode `egress_route` is intentionally `skipped` when idle** — the per-leg
  policy route is only programmed at *flow start* (`output_bonded::program_gateway_paths`),
  so a route lookup while idle would (correctly) follow the default route and mislead.
  gateway-mode usability is proven instead by `source_ip` + `first_hop`; the live egress
  is then visible on the flow's Traffic-Shaping telemetry once running.
- Strict `SO_BINDTODEVICE` needs `CAP_NET_RAW`; if unavailable the check `warn`s and notes
  the leg will fall back to the unprivileged `IP_UNICAST_IF` source-bind path (matches the
  bond's own fallback).
- Catches, at commissioning time, the exact failures that recur in this testbed: wrong
  interface binding, missing/changed cellular source IP, NO-CARRIER uplinks, legs silently
  collapsing onto the default route.

What Phase 1 does **not** do: it does not measure throughput. For a *live* leg the
report points the operator at the existing `capacity_bps` telemetry; for an *idle* leg it
reports "capacity unknown — run the active probe (Phase 2)".

## Phase 2 — Active capacity probe

**Status: implemented.** Edge module `engine/bond_leg_probe.rs` (responder + client +
idle-safety registry); commands `test_bond_leg { mode: reachability|capacity }`,
`start_bond_probe_responder`, `stop_bond_probe_responder`; capabilities
`bond-leg-capacity` + `bond-probe-responder`; manager UI "Measure capacity" button.

Measures real Mbps/loss/RTT per leg by driving synthetic traffic to a cooperating peer
and reading back delivered-rate — the same signal the v2 keepalive-ack mechanism already
carries, but over a **dedicated, isolated probe path** so it cannot couple to live media.

Zero-impact gating (all enforced edge-side):

1. **Idle-only.** Refused (`error_code: bond_leg_test_unsafe_link_busy`) if the target
   leg — *or any other bonded I/O sharing the same interface/source/gateway* — is live.
   Authoritative: running bonded outputs/inputs register their legs via
   `register_active_legs` (RAII guard, freed on flow stop); `capacity_conflict` checks the
   leg under test against that `busy_keys()` snapshot. Saturating a shared physical link is
   the one thing that *would* affect traffic, so it is never done while traffic exists.
2. **Dedicated probe socket + port**, never the production `BondSocket`, scheduler, or
   token buckets. Honours the leg's interface binding (reuses Phase 1's `bind_leg_socket`);
   for gateway-mode it programs a *temporary* policy route under a reserved
   `__bond_probe__` slot and tears it down after.
3. **Bounded + cancellable**: hard duration cap (default 8 s over the generic command
   path, max 60 s; manager raises the ACK budget to 75 s for `test_bond_leg`), and a
   `max_bitrate_bps`/`HARD_MAX_BPS` ceiling so a metered cellular leg is never over-driven.
4. **Off the hot path**: ordinary Tokio tasks; `handle_manager_message` already runs each
   command in its own `tokio::spawn`, so the probe never blocks the WS loop.

Peer-participation model (resolved): the far end is always a bilbycast edge (proprietary
`0xBC` wire) — you cannot iperf to a generic server. The flow is **browser-orchestrated**
over the existing generic `/command` endpoint: (1) `start_bond_probe_responder` on the
peer node spins up an **ephemeral, stateless echo responder** on its own socket (auto-expires);
(2) `test_bond_leg { mode: capacity }` on the initiator ramps a controlled rate over the
leg to `peerIP:responderPort`; the responder echoes cumulative receive counters; the
initiator computes the delivered-rate knee (loss/RTT onset); (3) `stop_bond_probe_responder`.
The probe targets a **dedicated responder port**, never the leg's media port, so it can't
land in a live input's accounting. Wire shape: a dedicated `BPRB` probe magic, distinct
from the `0xBC` data and `0xBE` control magics.

Ramp modes:
- **reachability** (cheap, ~tens of KB): confirm the peer responder answers + measure
  RTT/baseline loss. Safe even adjacent to live traffic (negligible, rate-capped).
- **capacity** (idle-only): increasing rate until the loss/RTT-inflation knee; report the
  knee as usable Mbps. This is the existing congestion-controller logic driven by a
  synthetic source instead of waiting for media demand.

Caveat surfaced to the operator: a capacity number is point-in-time. Cellular/Starlink
capacity varies; the test answers "is this leg usable and roughly how fat," not "it will
hold for the next hour."

## Command surface

Rides the existing generic node-command passthrough — **no new REST route, no
`WS_PROTOCOL_VERSION` bump** (additive string-dispatched command, like
`test_cellular_uplink`). Old edges reply `unknown_action`; the UI gates the control on the
`bond-leg-test` capability.

```jsonc
// POST /api/v1/nodes/{id}/command   →  WS command to edge
{
  "action": {
    "type": "test_bond_leg",
    "transport": { "type": "udp", "interface": "eno4",
                   "remote": "203.0.113.7:7400" },   // a BondPathTransportConfig
    "leg_live": false,                                // optional hint (Phase 2 gate)
    "mode": "usability"                               // "usability" (P1) | "reachability" | "capacity" (P2)
  }
}
```

Response (`command_ack.data` = `LegTestReport`):

```jsonc
{
  "ok": true,
  "transport": "udp", "mode": "interface",
  "interface": "eno4", "source_ip": null, "remote": "203.0.113.7:7400",
  "chosen_egress_interface": "eno4",
  "mtu": 1500, "link_speed_mbps": 1000, "leg_live": false,
  "checks": [
    { "name": "interface_link", "status": "pass", "detail": "eno4 up, MTU 1500, 1000 Mbps" },
    { "name": "bind",           "status": "pass", "detail": "bound with SO_BINDTODEVICE(eno4)" },
    { "name": "egress_route",   "status": "pass", "detail": "egresses eno4 (no default-route collapse)" }
  ],
  "note": "Usability only. Capacity: run the active probe (Phase 2) on an idle leg, or read the flow's Traffic-Shaping card while live."
}
```

## File map

| Layer | File | Change |
|-------|------|--------|
| edge | `src/engine/bond_leg_test.rs` | **new** — Phase 1 `test_leg()` + report; shared `bind_leg_socket` / `normalize` |
| edge | `src/engine/bond_leg_probe.rs` | **new** — Phase 2 responder + capacity/reachability client + active-leg registry |
| edge | `src/engine/mod.rs` | `pub mod bond_leg_test; pub mod bond_leg_probe;` |
| edge | `src/engine/output_bonded.rs`, `input_bonded.rs` | `register_active_legs(...)` RAII guard on run (idle-safety gate) |
| edge | `src/manager/client.rs` | `test_bond_leg { mode }` + `start/stop_bond_probe_responder` arms; caps `bond-leg-test` / `bond-leg-capacity` / `bond-probe-responder` |
| manager | `crates/device-edge/src/lib.rs` | allow `test_bond_leg` + responder commands in `EDGE_COMMANDS` |
| manager | `crates/manager-server/src/api/nodes.rs` | 75 s ACK budget for `test_bond_leg` (multi-second probe) |
| manager | `ui/static/js/config/bonding.js` | per-leg "Test leg" + "Measure capacity" buttons (browser-orchestrates responder→probe→stop) |

## Live verification (2026-06-21, firewall hairpin, ms02)

Verified over a real WAN hairpin (out to the public IP, DNAT'd back) with two
standalone edges — rig + method in `testbed/bond-hairpin-live/`:

- **Capacity probe (Phase 2) over the real WAN path**: 20/20 reachability echoes,
  0% loss, ~1.4 ms RTT, clean capacity ramp to **44.5 Mbps measured** (0% loss to
  the 80 Mbps offered ceiling). Loopback end-to-end test also green in unit tests.
- **Bonded A/V steady state** (4.79 Mbps, 2-leg adaptive split, FEC 10×5):
  **0 CC discontinuities**, PCR pacing jitter **p99 ≈ 0.41 ms**, decodes clean.
- **Single-leg failover**: with the **defaults** (`hold_ms=500`) a leg kill cost
  22 CC discontinuities + an 8.86 ms PCR blip (recoverable, self-heals — *not*
  hitless). **Tuned hitless** (`hold_ms=1500`, `hold_max_ms=3000`,
  `keepalive_ms=100` → 500 ms dead-detect, `nack_delay_ms=3`,
  `max_nack_retries=20`): **0 CC discontinuities**, PCR jitter max 1.07 ms, no
  freeze, full bitrate held — at the cost of ~1.5 s added latency (the recovery
  buffer). **Takeaway: hitless leg failover is a hold-buffer/keepalive tuning
  trade-off, not a default.**

Caveats: both legs egressed one physical uplink (different ports) — validates the
protocol/scheduler/ARQ/FEC/failover logic, not multi-uplink aggregation; host had
no `CAP_SYS_NICE` (wire-emit SCHED_OTHER, ms-range PCR_AC floor); the capacity
probe ran via the edge probe code over the hairpin, not the manager WS/UI path.

## Validation & security

- `transport` is deserialised into the existing `BondPathTransportConfig` and runs through
  the same validation as a real leg (interface name shape, address parsing).
- Phase 1 binds an ephemeral socket and emits zero packets; Phase 2 is idle-gated +
  rate-capped + duration-bounded.
- Operator-permission gated like every other node command; the Phase 2 capacity probe is a
  mutation-class action for audit purposes (it generates real, if bounded, traffic).
