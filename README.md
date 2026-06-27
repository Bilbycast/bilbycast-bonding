# bilbycast-bonding

Media-aware packet-bonding stack for broadcast. Aggregate multiple
heterogeneous IP paths (LTE, ethernet, satellite, Wi-Fi) into a single
low-latency stream with frame-accurate failover, designed to outperform
general-purpose bonding appliances (Peplink SpeedFusion, Dispatch,
etc.) on the axes that broadcast actually cares about.

## Workspace

| Crate | Role |
|-------|------|
| **bonding-protocol** | Pure Rust, I/O-free. Wire header, reassembly buffer, scheduler trait, stats. |
| **bonding-transport** | Async tokio layer: path adapters, sender/receiver tasks, public `BondSocket` API. |

## Use cases

- **Inside `bilbycast-edge`** — `bonded_input` / `bonded_output` types
  (live). Edge's media-aware scheduler promotes IDR frames to
  `Priority::Critical` for automatic duplication across the two best
  paths (lowest-RTT under the RTT scheduler; best capacity score under
  the default capacity-aware scheduler).
- **Standalone `bilbycast-bonder` binary** — small appliance that does
  nothing but bond, without pulling in libavcodec or fdk-aac. Built
  against the same crates.

## Status

Wire format, reassembly buffer, the scheduler trait, all three built-in
schedulers — round-robin, weighted-RTT, and the headline capacity-aware /
congestion-controlled `CapacityAwareScheduler` — and stats are complete.
The async transport layer is done too: UDP, RIST, and QUIC path adapters,
optional per-datagram ChaCha20-Poly1305, the sender/receiver tasks, the
public `BondSocket` API, and the standalone `bilbycast-bonder` binary all
ship today. **Edge integration is live** — `bilbycast-edge` exposes
bonded inputs/outputs with the `Adaptive` (capacity-aware) scheduler as
its default and bond telemetry on `OutputStats.bond_stats`. `cargo test`
green.

No SRT leg adapter is planned (decided 2026-06-22): the bond aggregates
**UDP + QUIC** legs only and owns all recovery itself via cross-leg ARQ +
optional FEC. SRT's TSBPD delivery fights that and adds no interop on a
both-ends-proprietary bond; for SRT bonding to a 3rd party, use libsrt
socket-group bonding on the edge's SRT I/O instead. (The RIST adapter
exists but is unidirectional at the bond layer, so it is not a real
aggregation leg and is excluded from the manager UI.)

See [`CLAUDE.md`](CLAUDE.md) for the full module map, design
principles, and implementation-status table.
