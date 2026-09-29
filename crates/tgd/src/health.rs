//! The node's health (ADR-0015) -- and the separation from ADR-0019.
//!
//! What is written here is a line one easily writes the other way round, and the
//! other direction would be expensive: **quorum loss makes `tgd` not ready, not
//! dead.** If the liveness hung on the quorum, a partition would hit the whole
//! minority side with restarts -- and with them the workloads ADR-0019 expressly
//! lets run on.
//!
//! The watchdog therefore sits at the **Raft loop** and measures only whether it
//! delivers metrics. It does that without a quorum too.

use std::time::Duration;

use openraft::Raft;
use tg_consensus::net::PeerAddrs;
use tg_consensus::{NodeId, TypeConfig};
use tg_telemetry::probes::{Health, Readiness};

const TOLERANCE: Duration = Duration::from_mins(5);

const WATCH: &str = "raft";

pub(crate) const SCHEDULER: &str = "scheduler";

pub(crate) const PROJECTION: &str = "projection";

pub(crate) const SCHEDULER_TOLERANCE: Duration = Duration::from_mins(5);

#[must_use]
pub fn spawn(raft: &Raft<TypeConfig>, peers: PeerAddrs, own: NodeId) -> Health {
    let health = Health::new();
    health.watch(WATCH, TOLERANCE, now());
    // **The scheduler loop too.** It reports itself; it is registered here so
    // that a watchdog does not arise only after its first round -- the same reason
    // this function runs before the loops.
    health.watch(SCHEDULER, SCHEDULER_TOLERANCE, now());

    // At startup expressly **not ready**. A node that reported itself as ready
    // between the process start and the first election would get work in exactly
    // the window in which it cannot accept it.
    health.set(WATCH, Readiness::down("no metrics yet"));

    // **The peer coverage is recomputed in the scrape** (ADR-0088). The loop
    // below does set it at every movement of the log -- but in a quiet cluster the
    // log does not move for hours, and with the gauge expiry the number would
    // vanish together with its alarm. It is computed from the same source as in
    // the loop: the live Raft metrics. A remembered value would be a second place
    // for the same fact.
    let live = raft.metrics();
    let listed = peers.clone();
    health.on_scrape(tg_telemetry::names::PEERS_MISSING, move || {
        let voters: Vec<NodeId> = live.borrow().membership_config.voter_ids().collect();
        set_missing(&listed, &voters, own);
    });

    // **Who leads, in the scrape** (ADR-0088) -- and that is the condition under
    // which a leader-owned metric can carry an alarm rule at all: a leader that
    // has stepped down keeps its series for up to fifteen minutes, and its own `0`
    // stands here **at once**, because it arises in the scrape instead of in a
    // loop.
    let leading = raft.metrics();
    health.on_scrape(tg_telemetry::names::RAFT_LEADER, move || {
        let leader = leading.borrow().current_leader == Some(own);
        metrics::gauge!(tg_telemetry::names::RAFT_LEADER).set(f64::from(u8::from(leader)));
    });

    let mut metrics = raft.metrics();
    let watched = health.clone();
    // The last reported shortfall: the warning comes on a **change**, not at
    // every state -- the metrics move often.
    let mut reported: Vec<NodeId> = Vec::new();

    tokio::spawn(async move {
        loop {
            // `borrow_and_update`, not `borrow`: the rationale stands in
            // `session.rs`. Measured it is **no** hot loop -- `changed()` marks
            // itself -- but the shape that carries with `has_changed()` too
            // (`tgd/tests/watch_marking.rs`).
            let (state, voters) = {
                let metrics = metrics.borrow_and_update();
                let voters: Vec<NodeId> = metrics.membership_config.voter_ids().collect();
                (
                    Snapshot {
                        leader: metrics.current_leader,
                        voters: voters.len(),
                        // **The same source as the admin service's answer**
                        // (`admin::reaching`). Two versions would be two
                        // opportunities to count differently -- and then `/readyz`
                        // would say something other than `tgctl`.
                        reachable: crate::admin::reaching(&metrics, own).len(),
                    },
                    voters,
                )
            };

            // **Does our own list cover the membership?** Here, because this loop
            // reads the membership anyway and hangs on `raft.metrics()` -- a change
            // therefore leads to the check immediately, without a polling
            // interval.
            report_missing(&peers, &voters, own, &mut reported);

            watched.beat(WATCH, now());
            watched.set(WATCH, verdict(&state));

            if metrics.changed().await.is_err() {
                // The sender is gone -- Raft has been shut down. From here no
                // beat comes any more, and the liveness tips over after the
                // tolerance. That is right: this process can no longer fulfil its
                // task, and a restart helps.
                break;
            }
        }
    });

    health
}

struct Snapshot {
    leader: Option<u64>,
    voters: usize,
    reachable: usize,
}

fn set_missing(peers: &PeerAddrs, voters: &[NodeId], own: NodeId) -> Vec<NodeId> {
    let missing = peers.missing(voters.iter().copied(), own);
    metrics::gauge!(tg_telemetry::names::PEERS_MISSING)
        .set(f64::from(u32::try_from(missing.len()).unwrap_or(u32::MAX)));
    missing
}

fn verdict(state: &Snapshot) -> Readiness {
    if state.leader.is_none() {
        return Readiness::down("no leader");
    }

    // The majority of five is three (ADR-0031). Computed and not inserted, so that
    // a cluster of a different size is not silently judged wrongly.
    let quorum = state.voters / 2 + 1;
    if state.voters > 0 && state.reachable < quorum {
        return Readiness::down(format!(
            "no quorum: {} of {} reachable, {quorum} are needed",
            state.reachable, state.voters
        ));
    }

    Readiness::up()
}

pub(crate) fn now() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

fn report_missing(peers: &PeerAddrs, voters: &[NodeId], own: NodeId, reported: &mut Vec<NodeId>) {
    let missing = set_missing(peers, voters, own);

    if missing == *reported {
        return;
    }

    if missing.is_empty() {
        // The return is said too -- otherwise the warning would stay standing in
        // the log while the situation has long been in order.
        if !reported.is_empty() {
            tracing::info!("all voters have an address");
        }
    } else {
        tracing::warn!(
            ?missing,
            "voters without an address in --peer: this node cannot replicate to \
             them when it takes over the leadership (ADR-0005)"
        );
    }

    reported.clear();
    reported.extend(missing);
}

#[cfg(test)]
mod tests {
    use super::{Snapshot, verdict};

    #[test]
    fn a_node_with_a_leader_and_a_majority_is_ready() {
        assert!(
            verdict(&Snapshot {
                leader: Some(1),
                voters: 5,
                reachable: 3,
            })
            .ready
        );
    }

    #[test]
    fn a_minority_is_not_ready_and_says_so() {
        let state = verdict(&Snapshot {
            leader: Some(1),
            voters: 5,
            reachable: 2,
        });

        assert!(!state.ready);
        assert!(state.detail.contains("2 of 5"), "{}", state.detail);
        assert!(state.detail.contains("3 are needed"), "{}", state.detail);
    }

    #[test]
    fn the_majority_is_computed_from_the_actual_cluster_size() {
        assert!(
            verdict(&Snapshot {
                leader: Some(1),
                voters: 3,
                reachable: 2,
            })
            .ready
        );
    }

    #[test]
    fn without_a_leader_a_node_is_not_ready() {
        let state = verdict(&Snapshot {
            leader: None,
            voters: 5,
            reachable: 5,
        });

        assert!(!state.ready);
        assert!(state.detail.contains("no leader"), "{}", state.detail);
    }

    #[test]
    fn without_a_quorum_a_leader_is_not_ready() {
        let state = verdict(&Snapshot {
            leader: Some(1),
            voters: 5,
            reachable: 2,
        });

        assert!(!state.ready);
        assert!(
            state.detail.contains("2 of 5") && state.detail.contains("3 are needed"),
            "the message does not name both numbers and the majority: {}",
            state.detail
        );

        // **The computation, at the three sizes that count.** Exactly at the
        // majority a node is ready, one below it not -- without the first half a
        // rule that always refuses would be green too.
        for (voters, quorum) in [(3_usize, 2_usize), (4, 3), (5, 3)] {
            assert!(
                verdict(&Snapshot {
                    leader: Some(1),
                    voters,
                    reachable: quorum,
                })
                .ready,
                "with {voters} voters {quorum} must suffice"
            );
            assert!(
                !verdict(&Snapshot {
                    leader: Some(1),
                    voters,
                    reachable: quorum - 1,
                })
                .ready,
                "with {voters} voters {} must not suffice",
                quorum - 1
            );
        }
    }

    #[test]
    fn the_reachability_comes_from_one_place() {
        let source = include_str!("health.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);

        assert!(
            production.contains("crate::admin::reaching("),
            "the reachability belongs from `admin::reaching` -- otherwise \
             `/readyz` and `tgctl` count differently"
        );
        assert!(
            !production.contains(".replication"),
            "this file must not read `metrics.replication` itself: that would \
             be the second version of the same computation"
        );
    }
}
