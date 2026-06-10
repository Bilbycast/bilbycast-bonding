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
   stays the same. Current adapters: QUIC, RIST, raw UDP. SRT is a Phase 3
   target — see the implementation-status table below.
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
  (`Udp` / `Rist` / `Quic` variants today; `Srt` not yet wired).
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
| RIST path adapter (via bilbycast-rist) | Done (`path/rist.rs`, `path-rist` default feature) |
| SRT path adapter (via bilbycast-libsrt-rs) | Outstanding — `path-srt` feature + `srt-transport` dep declared, but no `Srt` config variant or `path/srt.rs` yet |
| `BondSocket::sender` / `::receiver` (+ `send` / `recv` / `stats` / `path_stats` / `path_ids` / `subscribe_events` / `close`) | Done (`socket.rs`; `BondSocketConfig::encryption_key` threads the AEAD) |
| Bonding-only binary (`bilbycast-bonder`) | Done (workspace member, `bilbycast-bonder/src/main.rs`) |
| **Edge integration** (`input_bonded`, `output_bonded`) | **Done** — live in `bilbycast-edge`; `Adaptive` scheduler is the edge default, telemetry on `OutputStats.bond_stats` |
| `MediaAwareScheduler` (edge-side, parses NAL) | Done (edge-side, `engine/bonded_scheduler.rs`; layered over WeightedRtt or CapacityAware) |
| Proactive FEC (interleaved XOR) | Outstanding — resilience today is ARQ + IDR-duplication + multi-path diversity |

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
  └── optionally wraps: bilbycast-relay (QUIC), bilbycast-libsrt-rs (SRT),
                        bilbycast-rist (RIST)

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
