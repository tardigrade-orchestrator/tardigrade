//! Placement under faults (phase 6, ADR-0011 with ADR-0010/0019).
//!
//! `crates/tgd/tests/scheduling.rs` shows that the scheduler places over real
//! processes. Here stands the question that cannot be posed there: **what
//! happens when the quorum is missing?**
//!
//! ADR-0011 says it briefly: "only with a quorum present; otherwise the autonomy
//! boundary from ADR-0010 bites". A placement is a cluster-wide mutation. If it
//! got through on a minority side, the same workload would in the end run twice
//! — on the island and on the majority side —, and with a single writer that
//! would be exactly the double writer the whole fencing model is meant to
//! exclude.

use std::time::Duration;

use tg_consensus::{ClusterState, Command, Outcome, Resources, Topology, schedule};
use tg_dst::{Cluster, Faults, Setup, seeds};

fn document(name: &str, replicas: u32) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\">\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         <placement replicas=\"{replicas}\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

fn upsert(name: &str, replicas: u32) -> Command {
    Command::UpsertWorkload {
        document: document(name, replicas),
    }
}

fn target(name: &str, rack: &str) -> Command {
    Command::UpsertNode {
        name: name.to_owned(),
        topology: Topology {
            site: "fra".to_owned(),
            hall: "h1".to_owned(),
            rack: rack.to_owned(),
        },
        capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
        reserved: tg_consensus::Resources::default(),
        source: tg_consensus::Origin::Operator,
    }
}

/// The scheduler step, computed on the leader and written over it.
///
/// In operation the loop in `tgd` does that; here it stands written out so that
/// the scenario determines the point in time.
async fn schedule_once(cluster: &Cluster) -> Result<usize, String> {
    let leader = cluster.wait_for_leader().await.map_err(|e| e.to_string())?;
    let state = cluster.state(leader).ok_or("the leader has no state")?;
    let step = schedule::step(&state);

    let count = step.commands.len();
    for command in step.commands {
        // Over `write_to_leader`, not over the node on which it was computed:
        // after a change another one leads, and the plan is the same on both
        // (see `every_node_would_compute_the_same_plan`). Precisely for that
        // reason the step is a pure function.
        cluster
            .write_to_leader(command)
            .await
            .map_err(|err| err.to_string())?;
    }

    Ok(count)
}

fn placements(state: &ClusterState, workload: &str) -> Vec<(u32, String)> {
    state
        .instances(workload)
        .into_iter()
        .map(|(instance, node)| (instance, node.to_owned()))
        .collect()
}

/// A cluster with three placement targets in three racks.
async fn prepared(seed: u64) -> Cluster {
    let cluster = Cluster::start_with(Setup::new(seed)).await.expect("start");

    for (name, rack) in [("rack-a", "r1"), ("rack-b", "r2"), ("rack-c", "r3")] {
        cluster
            .write_to_leader(target(name, rack))
            .await
            .expect("enter target");
    }

    cluster
}

/// Placement gets through even when every fifth message is lost — and all five
/// nodes see the same assignments afterwards.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn placement_survives_message_loss() {
    for seed in seeds() {
        let cluster = prepared(seed).await;
        cluster
            .write_to_leader(upsert("api", 3))
            .await
            .expect("definition");

        cluster.inject(
            Faults::none()
                .with_jitter(Duration::from_millis(30))
                .with_loss_permille(200),
        );

        let written = schedule_once(&cluster)
            .await
            .unwrap_or_else(|err| panic!("seed {seed}: {err}"));
        assert_eq!(written, 3, "seed {seed}");

        cluster.bus().heal();
        cluster.wait_for_convergence().await.expect("convergence");

        let states = cluster.stop_and_read().await.expect("read");
        let reference = placements(states.get(&1).expect("node 1"), "api");
        assert_eq!(reference.len(), 3, "seed {seed}");

        for (id, state) in &states {
            assert_eq!(
                placements(state, "api"),
                reference,
                "seed {seed}: node {id} sees different assignments"
            );
        }

        // And they lie in three different racks.
        let nodes: std::collections::BTreeSet<&str> =
            reference.iter().map(|(_, node)| node.as_str()).collect();
        assert_eq!(nodes.len(), 3, "seed {seed}: {reference:?}");
    }
}

/// **Without a quorum nothing is placed.**
///
/// The core of the autonomy boundary (ADR-0010, ADR-0019) on the placement path.
/// What is checked is not that the scheduler holds back — on an island it might
/// well not — but that its result is **not committed**. And afterwards that the
/// state is intact: no half placement, no remainder.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn without_a_quorum_nothing_is_placed() {
    for seed in seeds() {
        let cluster = prepared(seed).await;
        cluster
            .write_to_leader(upsert("api", 2))
            .await
            .expect("definition");

        // 2/2/1 — no side has three nodes.
        cluster.inject(Faults::none().with_partition([&[1, 2][..], &[3, 4][..], &[5][..]]));

        let refused = schedule_once(&cluster).await;
        assert!(
            refused.is_err(),
            "seed {seed}: it placed without a majority — {refused:?}"
        );

        cluster.bus().heal();
        cluster.wait_for_leader().await.expect("leader");
        cluster.wait_for_convergence().await.expect("convergence");

        // The state after healing: the definition stands, nothing is placed. The
        // running workloads would have stayed untouched by this (ADR-0019) —
        // here it is visible that nothing new arose either.
        let leader = cluster.wait_for_leader().await.expect("leader");
        let state = cluster.state(leader).expect("state");
        assert!(state.workload("api").is_some(), "seed {seed}");
        assert!(
            placements(&state, "api").is_empty(),
            "seed {seed}: it placed after all: {:?}",
            placements(&state, "api")
        );

        // And with the quorum regained it works.
        let written = schedule_once(&cluster)
            .await
            .unwrap_or_else(|err| panic!("seed {seed}: after healing: {err}"));
        assert_eq!(written, 2, "seed {seed}");
    }
}

/// **Every node would compute the same plan.**
///
/// The property that makes a leader change harmless: the new one sees the same
/// state and comes to the same result. Without it every change would resort the
/// cluster — and every move of a single writer is a fencing operation
/// (ADR-0010).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn every_node_would_compute_the_same_plan() {
    for seed in seeds() {
        let cluster = prepared(seed).await;
        cluster
            .write_to_leader(upsert("api", 2))
            .await
            .expect("api");
        cluster.write_to_leader(upsert("db", 3)).await.expect("db");
        cluster.wait_for_convergence().await.expect("convergence");

        let reference: Vec<Command> = {
            let state = cluster.state(1).expect("state");
            schedule::step(&state).commands
        };
        assert!(!reference.is_empty(), "seed {seed}");

        for id in 2..=5_u64 {
            let state = cluster.state(id).expect("state");
            assert_eq!(
                schedule::step(&state).commands,
                reference,
                "seed {seed}: node {id} would plan differently"
            );
        }
    }
}

/// A node fails, the quorum holds: the lost instance is replaced, the surviving
/// one not touched.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_lost_target_is_replaced_while_the_quorum_holds() {
    for seed in seeds() {
        let cluster = prepared(seed).await;
        cluster
            .write_to_leader(upsert("api", 2))
            .await
            .expect("api");
        schedule_once(&cluster).await.expect("first placement");
        cluster.wait_for_convergence().await.expect("convergence");

        let leader = cluster.wait_for_leader().await.expect("leader");
        let before = placements(&cluster.state(leader).expect("state"), "api");
        assert_eq!(before.len(), 2, "seed {seed}");
        let lost = before[0].1.clone();
        let survivor = before[1].1.clone();

        cluster
            .write_to_leader(Command::RemoveNode { name: lost.clone() })
            .await
            .expect("remove target");

        let written = schedule_once(&cluster).await.expect("replacement");
        assert_eq!(written, 1, "seed {seed}: only the lost instance");

        cluster.wait_for_convergence().await.expect("convergence");
        let leader = cluster.wait_for_leader().await.expect("leader");
        let after = placements(&cluster.state(leader).expect("state"), "api");

        let nodes: Vec<&str> = after.iter().map(|(_, node)| node.as_str()).collect();
        assert!(nodes.contains(&survivor.as_str()), "seed {seed}: {after:?}");
        assert!(!nodes.contains(&lost.as_str()), "seed {seed}: {after:?}");
        assert_eq!(
            nodes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2,
            "seed {seed}: both instances on one node: {after:?}"
        );
    }
}

/// A target that no longer exists is no reason to refuse the whole planning: the
/// rest is placed nevertheless.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn one_impossible_workload_does_not_block_the_others() {
    let seed = seeds()[0];
    let cluster = prepared(seed).await;

    cluster
        .write_to_leader(upsert("passt", 2))
        .await
        .expect("passt");
    cluster
        .write_to_leader(upsert("zu-gross", 9))
        .await
        .expect("zu-gross");

    schedule_once(&cluster).await.expect("planning");
    cluster.wait_for_convergence().await.expect("convergence");

    let leader = cluster.wait_for_leader().await.expect("leader");
    let state = cluster.state(leader).expect("state");

    assert_eq!(placements(&state, "passt").len(), 2);
    assert_eq!(
        placements(&state, "zu-gross").len(),
        3,
        "the three possible instances belong placed, even if six are missing"
    );

    let step = schedule::step(&state);
    assert!(!step.rejected.is_empty(), "the refusal is missing");
    // **`RemoveWorkload` and not `ClearPlacement`**: that one has been retired
    // and is without effect since ADR-0112 — and the refusal names exactly this
    // substitute. Cleared away is thereby the declaration together with its
    // assignments, which is what was meant here.
    assert_eq!(
        cluster
            .write_to_leader(Command::RemoveWorkload {
                name: "zu-gross".to_owned()
            })
            .await
            .expect("clean up"),
        Outcome::Applied
    );
}

/// After a leader change the new one does not re-plan.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_leader_change_does_not_reshuffle_anything() {
    for seed in seeds() {
        let mut cluster = prepared(seed).await;
        cluster
            .write_to_leader(upsert("api", 3))
            .await
            .expect("api");
        schedule_once(&cluster).await.expect("placement");
        cluster.wait_for_convergence().await.expect("convergence");

        let first = cluster.wait_for_leader().await.expect("leader");
        let before = placements(&cluster.state(first).expect("state"), "api");

        cluster.stop(first).await.expect("halt the leader");
        let second = cluster.wait_for_leader().await.expect("new leader");
        assert_ne!(second, first, "seed {seed}");

        // The new one computes — and has nothing to do.
        let written = schedule_once(&cluster).await.expect("planning");
        assert_eq!(
            written, 0,
            "seed {seed}: the new leader re-planned instead of doing nothing"
        );

        let after = placements(&cluster.state(second).expect("state"), "api");
        assert_eq!(after, before, "seed {seed}");
    }
}
