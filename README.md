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

- **Inside `bilbycast-edge`** — new `bonded_input` / `bonded_output`
  types. Edge's media-aware scheduler promotes IDR frames to
  `Priority::Critical` for automatic duplication across the two
  lowest-RTT paths.
- **Standalone `bilbycast-bonder` binary** — small appliance that does
  nothing but bond, without pulling in libavcodec or fdk-aac. Built
  against the same crates.

## Status

Phase 1 complete: wire format, reassembly buffer, scheduler trait,
built-in schedulers, stats. `cargo test` green.

See [`CLAUDE.md`](CLAUDE.md) for the full module map, design
principles, and phased build-out plan.
