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
| **bonding-transport** | Async wiring on tokio: path adapters, sender/receiver tasks, `BondSocket` API. (Phase 2.) |

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
- `packet/` — wire header, priority enum, flags.
- `protocol/reassembly.rs` — `ReassemblyBuffer` (32-bit seq, per-path
  accounting, gap timeout).
- `protocol/scheduler.rs` — `BondScheduler` trait, `RoundRobinScheduler`,
  `WeightedRttScheduler`.
- `protocol/path_health.rs` — `PathHealth` snapshot driven into the
  scheduler once per health tick.
- `stats.rs` — `BondConnStats` (aggregate) + `PathStats` (per-path),
  both `Arc<AtomicU64>` patterned, with snapshot types for exporters.
- `error.rs` — `BondError`.

### bonding-transport *(Phase 2)*
- `config.rs` — `BondSocketConfig`, `PathConfig`, `PathTransport` enum
  (QUIC / UDP / SRT / RIST variants).
- `path.rs` — uniform `BondPath` trait wrapping each transport.
- `sender.rs` — outbound task: consults scheduler, frames header,
  writes to selected path(s).
- `receiver.rs` — inbound task: multiplexes N paths into a
  `ReassemblyBuffer`, drains in bond-seq order.
- `socket.rs` — public `BondSocket::sender()` / `::receiver()` API.

## Implementation Status

| Area | Status |
|------|--------|
| Wire header encode/parse | Done, round-trip tested |
| Reassembly buffer (32-bit seq) | Done, gap-fill + timeout tested |
| `BondScheduler` trait | Done |
| `RoundRobinScheduler` (default for bonding-only boxes) | Done |
| `WeightedRttScheduler` (RTT-aware, Critical-duplicates) | Done |
| Stats + snapshots | Done |
| QUIC path adapter | Phase 2 |
| Raw UDP path adapter | Phase 2 |
| SRT path adapter (via bilbycast-libsrt-rs) | Phase 3 |
| RIST path adapter (via bilbycast-rist) | Phase 3 |
| `BondSocket::sender` / `::receiver` | Phase 2 |
| Edge integration (input_bonded, output_bonded) | Phase 4 |
| `MediaAwareScheduler` (edge-side, parses NAL) | Phase 4 |
| Bonding-only binary (`bilbycast-bonder`) | Phase 5 |

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
