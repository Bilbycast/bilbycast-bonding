# CLAUDE.md — bilbycast-bonding

Media-aware packet-bonding stack for broadcast: aggregate N heterogeneous
paths (cellular, ethernet, satellite, anything IP) into one reliable
low-latency flow. Target: outperform Peplink SpeedFusion on the axes that
matter to broadcast — frame-accurate failover, media-aware scheduling,
broadcast-grade telemetry, open-standard egress.

## What Is bilbycast-bonding

Standalone workspace, sibling of `bilbycast-rist` / `bilbycast-srt`. Split
into two crates following the same pattern:

| Crate | Role |
|-------|------|
| **bonding-protocol** | Pure I/O-free core: wire header, reassembly buffer, scheduler trait + built-in implementations, stats types. |
| **bonding-transport** | Async wiring on tokio: path adapters (UDP / RIST / QUIC), sender/receiver tasks, `BondSocket` API. |

## Design Principles

1. **Media-awareness is external.** The scheduler sees opaque `PacketHints`
   (priority, size, marker, custom u32). `bilbycast-edge` supplies a
   `MediaAwareScheduler` that promotes IDR NAL units to `Priority::Critical`;
   the library itself parses nothing about the payload. A dedicated
   bonding-only binary uses the built-in `WeightedRttScheduler` and still
   gets RTT-aware aggregation.
2. **Transport-agnostic.** The 12-byte bond header wraps arbitrary bytes.
   Paths can ride any datagram-ish transport independently; the header
   stays the same. Adapters: QUIC, RIST, raw UDP. (No SRT leg — see the
   implementation-status table for the rationale.)
3. **Lock-free hot path.** Stats are `AtomicU64`; reassembly is a flat
   ring indexed by `bond_seq % capacity`. Same constraints as the edge
   data plane.
4. **Mirror `bilbycast-rist`.** Same split, same test style, same
   integration shape — `bilbycast-edge` treats it like any other transport
   crate.

## Wire Format

Each bonded packet is a 12-byte header followed by opaque payload:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     0xBC      |  Ver  |Flag |   Path ID     |    Priority   |
+---------------+---------------+-------------------------------+
|                           flow_id                             |
+---------------------------------------------------------------+
|                           bond_seq                            |
+---------------------------------------------------------------+
```

- **flow_id (u32)** — identifies the bonded flow; multiple flows can share
  a set of paths.
- **bond_seq (u32)** — monotonic across all paths. 32 bits so a
  20 Mbps / 15 kpps stream won't wrap within the reassembly budget.
- **path_id (u8)** — the path this packet was emitted on; echoed in
  NACKs so senders know which path to fault.
- **priority (u8)** — scheduler hint (Normal / High / Critical / Low).
  `Critical` causes built-in schedulers to duplicate across the two
  lowest-RTT paths.
- **flags (4 bits)** — `RETRANSMIT`, `DUPLICATED`, `MARKER`, one reserved.
- **version (4 bits)** — currently `1`. Parsers reject mismatched versions.

## Module Map

### bonding-protocol
- `packet.rs` — wire header, priority enum, flags.
- `control.rs` — control-channel messages (NACK / keepalive) shared by
  sender and receiver.
- `protocol/reassembly.rs` — `ReassemblyBuffer` (32-bit seq, per-path
  accounting, gap timeout).
- `protocol/retransmit.rs` — retransmit buffer + NACK-driven resend
  bookkeeping.
- `protocol/scheduler.rs` — `BondScheduler` trait (`schedule` /
  `on_path_update` / `on_tick` / `on_path_{dead,alive}`),
  `RoundRobinScheduler`, `WeightedRttScheduler`.
- `protocol/capacity_scheduler.rs` — `CapacityAwareScheduler` +
  `CongestionConfig` + `PathPrior`: per-path congestion controller,
  token-bucket capacity-proportional split, quality deweighting.
- `protocol/path_health.rs` — `PathHealth` snapshot driven into the
  scheduler once per health tick.
- `stats.rs` — `BondConnStats` (aggregate) + `PathStats` (per-path),
  both `Arc<AtomicU64>` patterned, with snapshot types for exporters.
- `events.rs` — `PathEvent` types broadcast to subscribers.
- `error.rs` — `BondError`.

### bonding-transport
- `config.rs` — `BondSocketConfig`, `PathConfig`, `PathTransport` enum
  (`Udp` / `Rist` / `Quic` variants).
- `path/` — uniform `BondPath` trait (`mod.rs`) plus the concrete
  adapters: `udp.rs`, `rist.rs`, `quic.rs`.
- `sender.rs` — outbound task: consults scheduler, frames header,
  writes to selected path(s).
- `receiver.rs` — inbound task: multiplexes N paths into a
  `ReassemblyBuffer`, drains in bond-seq order.
- `health.rs` — per-path health tracking / `PathHealth` snapshots fed
  to the scheduler.
- `crypto.rs` — `BondCrypto`: optional per-datagram ChaCha20-Poly1305
  AEAD (`0xBD` envelope), applied at the UDP path.
- `socket.rs` — public `BondSocket::sender()` / `::receiver()` API,
  plus `send` / `recv` / `stats` / `path_stats` / `path_ids` /
  `subscribe_events` / `close`.

## Implementation Status

| Area | Status |
|------|--------|
| Wire header encode/parse | Done, round-trip tested |
| Reassembly buffer (32-bit seq) | Done, gap-fill + timeout tested |
| `BondScheduler` trait (`schedule` / `on_path_update` / `on_tick` / `on_path_{dead,alive}`) | Done |
| `RoundRobinScheduler` (default for bonding-only boxes) | Done |
| `WeightedRttScheduler` (RTT-aware, Critical-duplicates) | Done |
| **`CapacityAwareScheduler`** (congestion-controlled, capacity-proportional split) | **Done** — `protocol/capacity_scheduler.rs`, unit + e2e tested. See "Adaptive scheduling" below. |
| **Windowed per-path feedback** (delivered-rate + windowed loss + jitter) | **Done** — v2 keepalive (`control.rs`), populated into `PathStats` / `PathHealth` by `sender.rs` / `receiver.rs` |
| **Optional AEAD encryption** (ChaCha20-Poly1305 per datagram) | **Done** — `crypto.rs`, applied at the UDP path; `0xBD` envelope, tamper/wrong-key tested |
| Stats + snapshots | Done (`throughput_bps` / `jitter_us` now written from real feedback) |
| QUIC path adapter | Done (`path/quic.rs`, `path-quic` default feature; already TLS-encrypted) |
| Raw UDP path adapter | Done (`path/udp.rs`, `path-udp` default feature; optional `BondCrypto`) |
| RIST path adapter (via bilbycast-rist) | Library adapter exists (`path/rist.rs`, `path-rist` default feature) — but **NOT a real aggregation leg, and excluded from the manager UI (UDP + QUIC only).** RIST is unidirectional at the bond layer (send-only / receive-only), so a send-only leg can't carry the keepalive back-channel, the sender can't confirm it alive, and the scheduler won't aggregate over it (verified on the live cellular bond — see `manager`'s `bonding.js`). Only useful paired with a UDP/QUIC leg in the opposite direction. **The real, product-exposed aggregation legs are UDP + QUIC.** |
| SRT leg path adapter | **Not planned (decided 2026-06-22).** The bond aggregates **UDP + QUIC** legs only — raw + optional ChaCha20 (UDP), and TLS 1.3 + congestion-control + NAT (QUIC). Both are *unreliable* carriers by design: the bond owns ALL recovery via its cross-leg NACK ARQ + optional XOR FEC (there is **no per-leg ARQ in the product** — the RIST adapter above is not an aggregation leg). SRT adds nothing the bond needs and actively fights it: its TSBPD latency-window delivery + TLPKTDROP hold and late-drop datagrams that the bond's cross-leg reassembly must reorder/recover itself; it gives **no** 3rd-party interop (the `0xBC` bond is proprietary at both ends); and it would drag the heavy libsrt/OpenSSL/CMake build chain into the deliberately-lean bonder. For SRT bonding **to a 3rd party**, use libsrt **socket-group bonding** (Broadcast/Backup groups) on the edge's SRT I/O — that already ships. If per-leg recovery is ever genuinely wanted, the path is the bond's FEC (exists) or a properly *bidirectional* reliable leg — not SRT. |
| `BondSocket::sender` / `::receiver` (+ `send` / `recv` / `stats` / `path_stats` / `path_ids` / `subscribe_events` / `close`) | Done (`socket.rs`; `BondSocketConfig::encryption_key` threads the AEAD) |
| Bonding-only binary (`bilbycast-bonder`) | Done (workspace member, `bilbycast-bonder/src/main.rs`) |
| **Bond bridge role** (`BonderRole::Bridge`) | **Done** — relay-hosted aggregation: terminate edge A's ingress bond (receiver, full ARQ/FEC/reorder recovery) → re-originate a fresh egress bond/single-path to edge B (sender), pumped receiver→sender in one process. **Zero changes to `bonding-protocol`/`bonding-transport`** — wires the existing `BondSocket::{receiver,sender}`. Config: top-level `flow_id`/`paths`/`scheduler`/`tuning` = ingress; new `bridge_egress { flow_id, paths, scheduler, tuning }` = egress (MUST use a different `flow_id`). `bilbycast-bonder/src/main.rs::run_bridge`, `config.rs::{egress_socket_config,build_socket_config}`. Example: `bilbycast-bonder/examples/bridge-relay.json`. Loopback E2E verified (sender→bridge→receiver, 1000 pkts, zero loss, in-order); **live multi-uplink (5G/Starlink) gate deferred to hardware.** This is "bonding via relay" — run it co-located with a public `bilbycast-relay`. Latency budgets STACK across the two hops (size `hold_ms` accordingly). |
| **Edge integration** (`input_bonded`, `output_bonded`) | **Done** — live in `bilbycast-edge`; `Adaptive` scheduler is the edge default, telemetry on `OutputStats.bond_stats` |
| `MediaAwareScheduler` (edge-side, parses NAL) | Done (edge-side, `engine/bonded_scheduler.rs`; layered over WeightedRtt or CapacityAware) |
| **Proactive FEC** (interleaved XOR) | **Done (opt-in, off by default)** — `protocol/fec.rs`, FEC-flagged repair datagrams; sender emits, receiver recovers into reassembly. Codec + e2e (recover-without-ARQ) tested. Complements ARQ + IDR-dup + multi-path. |
| **Per-leg FEC** (per path: XOR or Reed-Solomon, adaptive) | **Done (opt-in)** — `PerLeg{Fec,Rs}Encoder`/`Decoder` in `protocol/fec.rs` + `protocol/rs.rs`; each FEC-enabled leg protects only its own stream so a leg burst (e.g. a Starlink handoff) recovers locally instead of clustering in the combined column model. Per leg: **XOR** (1 loss/column) or **Reed-Solomon** (hand-rolled GF(256) Cauchy-RS, up to `m` losses per `k+m` block), with **adaptive RS parity** that scales with measured leg loss (`parity_max`). Repairs enumerate their `bond_seq`s, so media packets are unchanged on the wire. Selected by `BondSocketConfig.per_path_fec` (`PerLegFecKind`), mutually exclusive with the combined `fec`. Codec units + leg-burst + RS-multi-loss + adaptive e2e tested. **Design + wire format: [`docs/per-leg-fec.md`](docs/per-leg-fec.md).** |
| **Packet redundancy** (replicate across N best legs) | **Done (opt-in, off by default)** — `RedundancyPolicy` in `protocol/scheduler.rs` + `BondScheduler::set_redundancy` on all three schedulers. Sends a packet on the N best legs so a copy survives any single leg loss — strongest resilience, N× bandwidth. Modes: off / duplicate-all / priority-threshold. Sender-side only (receiver de-dups by `bond_seq`). Unit-tested. **Design: [`docs/redundancy.md`](docs/redundancy.md).** |
| **Per-leg latency/jitter equalization** (aggregate heterogeneous legs) | **Done — self-configuring (`EqualizationMode` default `Off` at the lib, `Auto` at the edge)** — time-aligns legs by their measured one-way delay so heterogeneous high-latency/jitter legs (5G + Starlink + ISP) AGGREGATE in-order instead of head-of-line-blocking. v2 16-byte header (`send_stamp_us`); receiver measures windowed-min OWD and, in `Auto`, engages alignment only when the inter-leg skew clears `SKEW_FLOOR_US` within the `max_bonding_latency_ms` budget (no-op on a homogeneous bond); `On` forces, `Off` is the legacy aggregate-but-never-align path. Duplicate-all redundancy suppresses alignment via the keepalive `KA_FLAG_ALIGN_SUPPRESS` bit. Sender stamps only after the receiver advertises v2 (`recv_protocol_version` keepalive-ack negotiation) → no brick / no wasted bytes; a version mismatch raises an edge alarm, not a gate. Unit + e2e tested (auto aggregation + no-brick regression); adversarially reviewed + hardened. **LIVE cellular+Starlink gate not yet re-run.** **Design + as-built: [`docs/per-leg-equalization.md`](docs/per-leg-equalization.md).** |

## Adaptive scheduling, congestion control & encryption

The headline capability for a heterogeneous contribution bond (several
4G/5G modems + Starlink). The RTT-only `WeightedRttScheduler` over-drives
a low-RTT cellular link past its capacity while under-using a high-RTT
satellite link; `CapacityAwareScheduler` fixes that with a closed loop.

- **Per-path congestion controller** (`capacity_scheduler.rs`): each leg
  runs a hybrid loss + delay (RTT-inflation) controller that *discovers*
  the link's usable bitrate — probe up while clean, back off toward the
  delivered rate the moment loss or queue-building delay appears. The
  estimate is clamped to `[min_rate, operator_ceiling]`; `weight_hint`
  seeds the initial prior, `CongestionConfig` tunes the law.
- **Token-bucket distribution**: each leg has a bucket refilled at its
  discovered capacity. Per packet the scheduler picks the best-scoring
  eligible leg (headroom × quality), so the split is **proportional to
  measured capacity**, a saturated leg spills to one with headroom, and
  `Low`-priority traffic is dropped first under genuine over-subscription.
  Critical (IDR) packets duplicate across the two best affordable legs.
- **The feedback loop**: the receiver echoes per-path **byte** counters +
  measured jitter in the **v2 keepalive ack** (`control.rs`, length-
  tolerant so it interops with a v1 peer). The sender differences
  successive acks into a *windowed* loss fraction + delivered bitrate
  (the old lifetime-cumulative ratio was far too sluggish) and feeds a
  full `PathHealth` into the controller each ack round (~5 Hz). Those
  values also populate the previously-dead `PathStats.throughput_bps` /
  `jitter_us` telemetry.
- **Time is injectable**: `CapacityAwareScheduler::schedule_at(hints,
  now)` does the real work (token refill is `now`-based, like the
  reassembly buffer); the trait `schedule` calls it with `Instant::now()`.
  Tests drive controlled time for deterministic rate-paced refill.
- **Optional encryption** (`crypto.rs`, `BondCrypto`): per-datagram
  ChaCha20-Poly1305 with a clear `0xBD` envelope `[0xBD][12B nonce][sealed
  inner + 16B tag]` — the receiver peeks `0xBD`, opens, then dispatches
  the inner `0xBC`/`0xBE` magic (header authenticated). 32-byte key via
  `BondSocketConfig::encryption_key`, shared by both edges. Applied at the
  UDP path; QUIC legs are already TLS. Wrong-key / tampered datagrams are
  dropped before the protocol decoder.

End-to-end proof: `tests/bond_adaptive.rs` shapes one UDP path to 2 Mbps
and another to 16 Mbps over loopback and asserts the adaptive scheduler
shifts the **majority** of traffic to the high-capacity link (both stay
alive) — i.e. the full sender→receiver→ack→controller→bucket loop works
on the wire, with the encrypted variant proven alongside.

## Inter-Project Dependencies

```
bilbycast-edge           (Phase 4)
  └── compiles against: bonding-transport (path dep, always on)

bilbycast-bonder         (Phase 5)
  └── compiles against: bonding-transport (standalone binary,
                                           no libav / no fdk-aac)

bonding-transport
  ├── compiles against: bonding-protocol
  ├── compiles against: tokio
  └── optionally wraps: bilbycast-relay (QUIC), bilbycast-rist (RIST)

bonding-protocol         (pure Rust, no async)
```

## Build & Test

```bash
cd bilbycast-bonding
cargo build          # debug, both crates
cargo test           # all unit tests in bonding-protocol
cargo build --release
```

## NIC Pinning

Each UDP path accepts an optional `interface` field (e.g. `"wwan0"`,
`"eth0"`) that pins egress to a specific NIC regardless of the
kernel routing table. Without it, multiple paths to the same
destination collapse onto the default route and the bond is
cosmetic.

- Linux / Android → `SO_BINDTODEVICE`, needs `CAP_NET_RAW` (grant via
  `setcap cap_net_raw+ep <bin>` or systemd `AmbientCapabilities`).
- macOS / FreeBSD / Fuchsia → `IP_BOUND_IF` / `IPV6_BOUND_IF`,
  unprivileged.
- Other platforms → not implemented; fall back to source-IP binding
  + policy routing.

Full reference (capability grants, systemd snippet, policy-routing
fallback, troubleshooting): [`docs/nic-pinning.md`](docs/nic-pinning.md).

## Key Design Decisions

1. **32-bit bond_seq, not 16.** 16-bit wraps in ~4 s at 15 kpps which
   is tight for bonding's buffer-time-plus-reordering budget. 32 bits
   is days and costs nothing.
2. **Priority is a protocol-level field, not a scheduler concern.**
   `Critical` is in the header so a receiver's downstream consumer
   (e.g. TR-101290 analyzer) can see which packets the sender flagged.
3. **No generic "tunnel" abstraction.** Each path is a concrete
   transport with its own NACK/RTT semantics. A uniform trait lives
   in `bonding-transport::path` but doesn't leak into the protocol.
4. **Scheduler trait lives in `bonding-protocol`.** So downstream
   crates (like edge's media-aware scheduler) can implement it without
   pulling in tokio.
5. **Reassembly buffer is single-writer.** The receiver task owns it.
   No locks, no `RwLock`. Matches edge's data-plane conventions.
