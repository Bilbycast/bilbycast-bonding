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

Wire format, reassembly buffer, scheduler trait, built-in schedulers,
and stats are complete. The async transport layer is also done: UDP,
RIST, and QUIC path adapters, the sender/receiver tasks, the public
`BondSocket` API, and the standalone `bilbycast-bonder` binary all ship
today. `cargo test` green.

Remaining: the SRT path adapter (the `path-srt` feature and
`srt-transport` dependency are declared, but the `Srt` config variant
and adapter aren't wired yet) and edge integration
(`bonded_input` / `bonded_output` plus the edge-side
`MediaAwareScheduler`).

See [`CLAUDE.md`](CLAUDE.md) for the full module map, design
principles, and implementation-status table.
