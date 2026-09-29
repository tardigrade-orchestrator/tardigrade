//! Membership and snapshots under faults (phase 5d).
//!
//! `crates/tgd/tests/membership.rs` shows that it works over real processes.
//! Here stands the other question: does it work **when the network does not play
//! along**? A membership change is a log entry like any other — it needs a
//! quorum, and the intermediate configuration of joint consensus even needs two
//! majorities. Exactly there arise the errors one does not find by hand.
//!
//! ADR-0005 names membership changes and snapshots as "our own responsibility";
//! CLAUDE.md demands a DST case for such paths instead of only a happy path.

use std::time::Duration;

use tg_consensus::{ClusterState, Command, NodeId, Outcome};
use tg_dst::{Cluster, Faults, Setup, seeds};

fn document(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\">\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

fn upsert(name: &str) -> Command {
    Command::UpsertWorkload {
        document: document(name),
    }
}

fn assert_all_agree(states: &std::collections::BTreeMap<NodeId, ClusterState>, seed: u64) {
    let mut iter = states.iter();
    let (first_id, first) = iter.next().expect("at least one node");
    let reference = tg_consensus::wire::encode_state(first).expect("encodable");

    for (id, state) in iter {
        assert_eq!(
            tg_consensus::wire::encode_state(state).expect("encodable"),
            reference,
            "seed {seed}: node {id} deviates from node {first_id}"
        );
    }
}

/// A membership change gets through even when every fifth message is lost.
///
/// The change is no special path: it runs through the same log as every other
/// entry and is therefore repeated until it is committed. What is checked is
/// that this really holds — and that afterwards all five nodes have the same
/// state.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_membership_change_survives_message_loss() {
    for seed in seeds() {
        let cluster = Cluster::start_with(Setup::new(seed).with_voters(3))
            .await
            .expect("start");
        cluster
            .write_to_leader(upsert("vorher"))
            .await
            .expect("write");

        cluster.inject(
            Faults::none()
                .with_jitter(Duration::from_millis(30))
                .with_loss_permille(200),
        );

        cluster.add_learner(4).await.expect("learner 4");
        cluster.add_learner(5).await.expect("learner 5");

        let voters = cluster
            .set_voters(&[1, 2, 3, 4, 5])
            .await
            .unwrap_or_else(|err| panic!("seed {seed}: change failed: {err}"));
        assert_eq!(voters, vec![1, 2, 3, 4, 5], "seed {seed}");

        // And the larger cluster carries on.
        assert_eq!(
            cluster
                .write_to_leader(upsert("nachher"))
                .await
                .expect("write"),
            Outcome::Applied,
            "seed {seed}"
        );

        cluster.bus().heal();
        cluster.wait_for_convergence().await.expect("convergence");

        let states = cluster.stop_and_read().await.expect("read");
        assert_all_agree(&states, seed);
        for (id, state) in &states {
            assert!(
                state.workload("vorher").is_some() && state.workload("nachher").is_some(),
                "seed {seed}: node {id} is missing something"
            );
        }
    }
}

/// **A newly added node catches up by snapshot.**
///
/// Forced, not hoped for: the log is kept so short that compaction bites before
/// the new one joins. The early entries then no longer exist — whoever knows them
/// nevertheless has got a snapshot.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_new_node_catches_up_by_snapshot() {
    for seed in seeds() {
        let cluster = Cluster::start_with(Setup::new(seed).with_voters(3).with_short_log(4, 1))
            .await
            .expect("start");

        for index in 0..8 {
            cluster
                .write_to_leader(upsert(&format!("w{index}")))
                .await
                .expect("write");
        }

        let leader = cluster.wait_for_leader().await.expect("leader");
        let purged = cluster
            .wait_for_compaction(leader)
            .await
            .unwrap_or_else(|err| panic!("seed {seed}: no compaction: {err}"));

        // The condition that matters: the new one needs entry 1, and that is
        // purged. The log path is thereby barred for it — only a snapshot
        // remains.
        assert!(
            purged >= 1,
            "seed {seed}: nothing purged — the snapshot path would stay \
             unchecked"
        );

        // The new one demonstrably has nothing.
        assert!(cluster.snapshot(4).is_none(), "seed {seed}");

        cluster.add_learner(4).await.expect("learner");
        // Node 5 runs but is not a member — it catches up on nothing and
        // therefore does not belong in the comparison.
        cluster
            .wait_for_convergence_among(&[1, 2, 3, 4])
            .await
            .expect("convergence of the members");

        assert!(
            cluster.snapshot(4).is_some(),
            "seed {seed}: node 4 carries no snapshot"
        );

        let states = cluster.stop_and_read().await.expect("read");
        let newcomer = states.get(&4).expect("node 4");
        for index in 0..8 {
            assert!(
                newcomer.workload(&format!("w{index}")).is_some(),
                "seed {seed}: the new one does not know w{index} — the entries \
                 were purged, so nothing arrived by snapshot"
            );
        }

        // Compared are the members; node 5 stood beside them.
        let members: std::collections::BTreeMap<NodeId, ClusterState> =
            states.into_iter().filter(|(id, _)| *id != 5).collect();
        assert_all_agree(&members, seed);
    }
}

/// A node that was away for a long time catches up by snapshot after its return.
///
/// The difference from the test above: this one was already a member. The way is
/// the same — its position lies below the purged range, so it gets a snapshot
/// instead of the missing entries.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_long_absent_node_is_caught_up_by_snapshot() {
    for seed in seeds() {
        let mut cluster = Cluster::start_with(Setup::new(seed).with_short_log(4, 1))
            .await
            .expect("start");

        cluster
            .write_to_leader(upsert("before-the-pause"))
            .await
            .expect("write");
        let before = cluster
            .wait_for_convergence()
            .await
            .expect("position before the pause");
        cluster.stop(5).await.expect("halt node 5");

        for index in 0..10 {
            cluster
                .write_to_leader(upsert(&format!("waehrend-{index}")))
                .await
                .expect("write");
        }

        let leader = cluster.wait_for_leader().await.expect("leader");
        // The returner stands at `before` and needs `before + 1` next. It waits
        // until exactly that one is purged — then there is no log path left for
        // it, only a snapshot.
        cluster
            .wait_for_compaction_beyond(leader, before)
            .await
            .unwrap_or_else(|err| {
                panic!("seed {seed}: the log was not purged beyond {before}: {err}")
            });

        cluster.restart(5).await.expect("node 5 back");
        cluster.wait_for_convergence().await.expect("convergence");

        let states = cluster.stop_and_read().await.expect("read");
        assert_all_agree(&states, seed);
        let returned = states.get(&5).expect("node 5");
        for index in 0..10 {
            assert!(
                returned.workload(&format!("waehrend-{index}")).is_some(),
                "seed {seed}: the returner has not caught up on waehrend-{index}"
            );
        }
    }
}

/// Without a quorum no membership change gets through.
///
/// The most important safeguard of the change: it is a cluster-wide mutation and
/// thereby quorum-bound (ADR-0010, ADR-0019). If it got through on a minority
/// side, the quorum could be redefined from an island — and that is split-brain
/// with on-board means.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_membership_change_without_a_quorum_does_not_pass() {
    for seed in seeds() {
        let cluster = Cluster::start_with(Setup::new(seed).with_voters(5))
            .await
            .expect("start");
        cluster
            .write_to_leader(upsert("vorher"))
            .await
            .expect("write");

        // No side has three nodes.
        cluster.inject(Faults::none().with_partition([&[1, 2][..], &[3, 4][..], &[5][..]]));

        let refused = cluster.set_voters(&[1, 2]).await;
        assert!(
            refused.is_err(),
            "seed {seed}: the quorum was redefined without a majority — {refused:?}"
        );

        cluster.bus().heal();
        cluster.wait_for_leader().await.expect("leader");
        cluster.wait_for_convergence().await.expect("convergence");

        let states = cluster.stop_and_read().await.expect("read");
        assert_all_agree(&states, seed);
        for state in states.values() {
            assert!(state.workload("vorher").is_some(), "seed {seed}");
        }
    }
}
