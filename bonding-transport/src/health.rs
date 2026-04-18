//! Per-path liveness + bond-aggregate health monitor.
//!
//! Owned by sender / receiver loops. Tracks last-activity time per
//! path, flips the path's `alive` bit when the liveness window
//! expires, and produces [`PathEvent`]s on every transition. Also
//! derives the bond-aggregate state (`Up` / `Degraded` / `Down`) and
//! fires the matching aggregate event when it changes.
//!
//! Pure logic — no sockets, no broadcast channel. The caller owns
//! publication.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bonding_protocol::events::{PathDeadReason, PathEvent, PathEventKind};
use bonding_protocol::protocol::scheduler::PathId;
use bonding_protocol::stats::PathStats;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BondAggregateState {
    /// Two or more paths alive — fully redundant.
    Up,
    /// Exactly one path alive.
    Degraded,
    /// No paths alive.
    Down,
}

impl BondAggregateState {
    fn from_alive(alive: usize, total: usize) -> Self {
        if alive == 0 {
            BondAggregateState::Down
        } else if alive == 1 && total >= 2 {
            BondAggregateState::Degraded
        } else {
            // alive >= 2, OR total == 1 and the one path is alive.
            BondAggregateState::Up
        }
    }
}

struct PathEntry {
    id: PathId,
    name: String,
    last_activity: Instant,
    alive: bool,
    stats: Arc<PathStats>,
}

pub(crate) struct BondHealthMonitor {
    paths: Vec<PathEntry>,
    aggregate: BondAggregateState,
    liveness_timeout: Duration,
}

impl BondHealthMonitor {
    /// Build a monitor over `paths`. All paths start `alive = true`.
    /// `liveness_timeout` is the window without activity after which
    /// a path is considered dead.
    pub(crate) fn new(
        paths: Vec<(PathId, String, Arc<PathStats>)>,
        liveness_timeout: Duration,
        now: Instant,
    ) -> Self {
        let entries: Vec<PathEntry> = paths
            .into_iter()
            .map(|(id, name, stats)| {
                stats.dead.store(0, Ordering::Relaxed);
                PathEntry {
                    id,
                    name,
                    last_activity: now,
                    alive: true,
                    stats,
                }
            })
            .collect();
        let total = entries.len();
        let alive = entries.iter().filter(|e| e.alive).count();
        Self {
            paths: entries,
            aggregate: BondAggregateState::from_alive(alive, total),
            liveness_timeout,
        }
    }

    fn entry_mut(&mut self, id: PathId) -> Option<&mut PathEntry> {
        self.paths.iter_mut().find(|e| e.id == id)
    }

    fn alive_count(&self) -> usize {
        self.paths.iter().filter(|e| e.alive).count()
    }

    fn total(&self) -> usize {
        self.paths.len()
    }

    /// Record activity (a keepalive ack, a data packet, whatever) on
    /// `path_id`. If the path was previously dead, emits a `PathAlive`
    /// event and — if the aggregate health threshold moved — a bond
    /// `Recovered` event. Returns all events produced by this call.
    pub(crate) fn record_activity(
        &mut self,
        path_id: PathId,
        now: Instant,
    ) -> Vec<PathEvent> {
        let mut events = Vec::new();
        let total = self.total();

        let Some(entry) = self.entry_mut(path_id) else {
            return events;
        };
        entry.last_activity = now;
        let was_dead = !entry.alive;
        if was_dead {
            entry.alive = true;
            entry.stats.dead.store(0, Ordering::Relaxed);
            let path_id = entry.id;
            let path_name = entry.name.clone();
            let alive_count = self.alive_count();
            events.push(PathEvent {
                path_id,
                path_name: path_name.clone(),
                kind: PathEventKind::PathAlive {
                    alive_count,
                    total,
                },
            });
            if let Some(agg) = self.update_aggregate(alive_count, total, path_id, &path_name)
            {
                events.push(agg);
            }
        }
        events
    }

    /// Scan for paths whose last activity is older than the liveness
    /// window and flip them to dead. Produces a `PathDead` + any
    /// aggregate transition in the return vector.
    pub(crate) fn check_timeouts(
        &mut self,
        now: Instant,
        reason: PathDeadReason,
    ) -> Vec<PathEvent> {
        let mut events = Vec::new();
        let total = self.total();
        let timeout = self.liveness_timeout;

        // Collect IDs to kill without mutably borrowing self while
        // iterating (we mutate entries in place below).
        let to_kill: Vec<(PathId, String)> = self
            .paths
            .iter()
            .filter_map(|e| {
                if e.alive && now.saturating_duration_since(e.last_activity) > timeout {
                    Some((e.id, e.name.clone()))
                } else {
                    None
                }
            })
            .collect();

        for (pid, pname) in to_kill {
            if let Some(entry) = self.entry_mut(pid) {
                entry.alive = false;
                entry.stats.dead.store(1, Ordering::Relaxed);
            }
            let alive_count = self.alive_count();
            events.push(PathEvent {
                path_id: pid,
                path_name: pname.clone(),
                kind: PathEventKind::PathDead {
                    reason: reason.clone(),
                    alive_count,
                    total,
                },
            });
            if let Some(agg) = self.update_aggregate(alive_count, total, pid, &pname) {
                events.push(agg);
            }
        }

        events
    }

    /// Recompute the aggregate state; emit a transition event if it
    /// moved. Returns `Some(PathEvent)` on transition, `None`
    /// otherwise.
    fn update_aggregate(
        &mut self,
        alive_count: usize,
        total: usize,
        path_id: PathId,
        path_name: &str,
    ) -> Option<PathEvent> {
        let next = BondAggregateState::from_alive(alive_count, total);
        if next == self.aggregate {
            return None;
        }
        let prev = self.aggregate;
        self.aggregate = next;
        let kind = match (prev, next) {
            (_, BondAggregateState::Down) => PathEventKind::BondDown { total },
            (_, BondAggregateState::Degraded) => PathEventKind::BondDegraded {
                alive_count,
                total,
            },
            (BondAggregateState::Down | BondAggregateState::Degraded, BondAggregateState::Up) => {
                PathEventKind::BondRecovered {
                    alive_count,
                    total,
                }
            }
            // Up → Up can't happen (we returned early on no change);
            // cover the match exhaustively so future states fail loudly.
            (BondAggregateState::Up, BondAggregateState::Up) => return None,
        };
        Some(PathEvent {
            path_id,
            path_name: path_name.to_string(),
            kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(id: PathId, name: &str) -> (PathId, String, Arc<PathStats>) {
        (id, name.to_string(), PathStats::new())
    }

    fn kinds(evs: &[PathEvent]) -> Vec<&PathEventKind> {
        evs.iter().map(|e| &e.kind).collect()
    }

    #[test]
    fn single_path_dead_then_alive_no_aggregate_degraded() {
        // Single-path bond: losing it fires BondDown; reviving fires
        // BondRecovered. Never fires BondDegraded (no redundancy to
        // drop to).
        let now = Instant::now();
        let mut m = BondHealthMonitor::new(
            vec![mk(0, "path-0")],
            Duration::from_millis(100),
            now,
        );
        let t1 = now + Duration::from_millis(250);
        let evs = m.check_timeouts(t1, PathDeadReason::KeepaliveTimeout);
        let k = kinds(&evs);
        assert!(matches!(k[0], PathEventKind::PathDead { .. }));
        assert!(matches!(k[1], PathEventKind::BondDown { total: 1 }));

        let t2 = t1 + Duration::from_millis(10);
        let evs = m.record_activity(0, t2);
        let k = kinds(&evs);
        assert!(matches!(k[0], PathEventKind::PathAlive { .. }));
        assert!(matches!(
            k[1],
            PathEventKind::BondRecovered {
                alive_count: 1,
                total: 1
            }
        ));
    }

    #[test]
    fn two_paths_one_dies_fires_degraded_not_down() {
        let now = Instant::now();
        let mut m = BondHealthMonitor::new(
            vec![mk(0, "a"), mk(1, "b")],
            Duration::from_millis(100),
            now,
        );
        // Keep path 1 alive while 0 times out.
        let t1 = now + Duration::from_millis(50);
        m.record_activity(1, t1);
        let t2 = now + Duration::from_millis(250);
        let evs = m.check_timeouts(t2, PathDeadReason::KeepaliveTimeout);
        let k = kinds(&evs);
        assert!(matches!(k[0], PathEventKind::PathDead { .. }));
        assert!(matches!(
            k[1],
            PathEventKind::BondDegraded {
                alive_count: 1,
                total: 2
            }
        ));
    }

    #[test]
    fn two_paths_both_die_fires_down_once() {
        let now = Instant::now();
        let mut m = BondHealthMonitor::new(
            vec![mk(0, "a"), mk(1, "b")],
            Duration::from_millis(100),
            now,
        );
        let t1 = now + Duration::from_millis(250);
        let evs = m.check_timeouts(t1, PathDeadReason::KeepaliveTimeout);
        // Two PathDead + one BondDegraded + one BondDown.
        let k = kinds(&evs);
        assert_eq!(
            k.iter()
                .filter(|kd| matches!(kd, PathEventKind::PathDead { .. }))
                .count(),
            2
        );
        assert_eq!(
            k.iter()
                .filter(|kd| matches!(kd, PathEventKind::BondDown { .. }))
                .count(),
            1
        );
        // No BondRecovered emitted.
        assert!(!k.iter().any(|kd| matches!(kd, PathEventKind::BondRecovered { .. })));
    }

    #[test]
    fn recovery_from_down_needs_two_alive_for_bond_recovered() {
        let now = Instant::now();
        let mut m = BondHealthMonitor::new(
            vec![mk(0, "a"), mk(1, "b")],
            Duration::from_millis(100),
            now,
        );
        let t1 = now + Duration::from_millis(250);
        let _ = m.check_timeouts(t1, PathDeadReason::KeepaliveTimeout);
        // Revive path 0 — aggregate should go Down → Degraded, NOT
        // Down → Up.
        let t2 = t1 + Duration::from_millis(10);
        let evs = m.record_activity(0, t2);
        let k = kinds(&evs);
        assert!(matches!(k[0], PathEventKind::PathAlive { .. }));
        assert!(matches!(
            k[1],
            PathEventKind::BondDegraded {
                alive_count: 1,
                total: 2
            }
        ));
        // Now revive path 1 — aggregate should go Degraded → Up.
        let t3 = t2 + Duration::from_millis(10);
        let evs = m.record_activity(1, t3);
        let k = kinds(&evs);
        assert!(matches!(k[0], PathEventKind::PathAlive { .. }));
        assert!(matches!(
            k[1],
            PathEventKind::BondRecovered {
                alive_count: 2,
                total: 2
            }
        ));
    }

    #[test]
    fn activity_before_timeout_keeps_path_alive() {
        let now = Instant::now();
        let mut m = BondHealthMonitor::new(
            vec![mk(0, "a")],
            Duration::from_millis(100),
            now,
        );
        // Heartbeat just before the window expires — no transition.
        let t1 = now + Duration::from_millis(90);
        let evs = m.record_activity(0, t1);
        assert!(evs.is_empty());
        let t2 = t1 + Duration::from_millis(50);
        let evs = m.check_timeouts(t2, PathDeadReason::KeepaliveTimeout);
        assert!(evs.is_empty());
    }

    #[test]
    fn stats_dead_flag_mirrors_monitor_state() {
        let now = Instant::now();
        let stats_a = PathStats::new();
        let stats_b = PathStats::new();
        let mut m = BondHealthMonitor::new(
            vec![
                (0, "a".into(), stats_a.clone()),
                (1, "b".into(), stats_b.clone()),
            ],
            Duration::from_millis(100),
            now,
        );
        assert_eq!(stats_a.dead.load(Ordering::Relaxed), 0);
        let t1 = now + Duration::from_millis(250);
        let _ = m.check_timeouts(t1, PathDeadReason::KeepaliveTimeout);
        assert_eq!(stats_a.dead.load(Ordering::Relaxed), 1);
        assert_eq!(stats_b.dead.load(Ordering::Relaxed), 1);
        let t2 = t1 + Duration::from_millis(10);
        let _ = m.record_activity(0, t2);
        assert_eq!(stats_a.dead.load(Ordering::Relaxed), 0);
        assert_eq!(stats_b.dead.load(Ordering::Relaxed), 1);
    }
}
