//! Path / bond lifecycle events.
//!
//! Emitted by the transport layer when a path transitions between
//! alive and dead, or when the aggregate bond crosses a health
//! threshold (fully up → degraded → down). Consumers (edge, bonder
//! binary, tests) subscribe via `BondSocket::subscribe_events()`.
//!
//! Pure types only — no async / tokio dependency.

use crate::protocol::scheduler::PathId;

/// Per-path or bond-aggregate lifecycle kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEventKind {
    /// A previously-dead path has come back. `alive_count` / `total`
    /// reflect the bond state *after* this transition.
    PathAlive {
        alive_count: usize,
        total: usize,
    },
    /// A previously-alive path has been declared dead.
    PathDead {
        reason: PathDeadReason,
        alive_count: usize,
        total: usize,
    },
    /// Bond dropped to exactly one alive path (from ≥ 2 alive).
    /// Fired once per transition into the degraded state.
    BondDegraded {
        alive_count: usize,
        total: usize,
    },
    /// Every path is dead. Data plane cannot carry media until at
    /// least one path is revived.
    BondDown { total: usize },
    /// Bond recovered back to ≥ 2 alive paths from a degraded or
    /// down state. `alive_count` / `total` reflect the post-recovery
    /// state.
    BondRecovered {
        alive_count: usize,
        total: usize,
    },
    /// The sender restarted: a *different* nonzero session epoch
    /// arrived on 2 consecutive control packets and the receiver
    /// dropped its reassembly anchor, pending NACKs and FEC state.
    /// `old_epoch` is what was previously adopted (0 = none yet);
    /// the event's `path_id` is the path whose control packet
    /// completed adoption.
    SessionReset {
        old_epoch: u32,
        new_epoch: u32,
    },
    /// A UDP path's socket was re-created, re-pinned and swapped in
    /// place (interface churn or a run of route/device send errors).
    /// A sender-leg rebuild takes a fresh ephemeral source port — the
    /// receiver re-learns the return address from the next control
    /// packet. UDP paths only; QUIC / RIST legs are never rebuilt.
    PathRebuilt { reason: PathRebuildReason },
    /// The pinned interface (or bound source address) disappeared
    /// out from under a UDP path. Emitted once per disappearance;
    /// the watcher keeps polling and fires
    /// `PathRebuilt { InterfaceRestored }` when it returns.
    InterfaceLost,
}

/// Why a UDP path's socket was torn down and rebuilt in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRebuildReason {
    /// The pinned interface's ifindex changed under the socket (USB
    /// dongle re-plug, NIC re-enumeration) — the old device bind /
    /// egress hint points at a dead index and blackholes.
    InterfaceChanged,
    /// The pinned interface (or bound source address) came back
    /// after an absence signalled by `InterfaceLost`.
    InterfaceRestored,
    /// A run of consecutive route/device errors on send (ENODEV,
    /// EADDRNOTAVAIL, ENETUNREACH, EHOSTUNREACH).
    SendErrors,
}

impl PathRebuildReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            PathRebuildReason::InterfaceChanged => "interface changed",
            PathRebuildReason::InterfaceRestored => "interface restored",
            PathRebuildReason::SendErrors => "send errors",
        }
    }
}

/// Why a path was declared dead. Used for operator-facing event
/// messages so an alarm says something more useful than "path dead".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathDeadReason {
    /// No keepalive ack received within the timeout window.
    KeepaliveTimeout,
    /// No inbound packet (data or control) on this path within the
    /// receiver-side liveness window.
    ReceiveTimeout,
    /// Socket or transport-level I/O error tore the path down.
    TransportError,
}

impl PathDeadReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            PathDeadReason::KeepaliveTimeout => "keepalive timeout",
            PathDeadReason::ReceiveTimeout => "no data received",
            PathDeadReason::TransportError => "transport error",
        }
    }
}

/// A single lifecycle event. Emitted once per transition — the
/// transport never repeats the same kind for the same path until the
/// opposite transition has fired.
#[derive(Debug, Clone)]
pub struct PathEvent {
    /// The path this event is about. For `BondDown` / `BondDegraded`
    /// / `BondRecovered` this is the path whose transition *caused*
    /// the aggregate state change — useful for operators who want to
    /// trace the root cause.
    pub path_id: PathId,
    /// Human-friendly path label (from `PathConfig.name`). Empty if
    /// unknown.
    pub path_name: String,
    pub kind: PathEventKind,
}

impl PathEvent {
    /// Is this a bond-aggregate event (as opposed to a per-path one)?
    pub fn is_aggregate(&self) -> bool {
        matches!(
            self.kind,
            PathEventKind::BondDegraded { .. }
                | PathEventKind::BondDown { .. }
                | PathEventKind::BondRecovered { .. }
                | PathEventKind::SessionReset { .. }
        )
    }
}
