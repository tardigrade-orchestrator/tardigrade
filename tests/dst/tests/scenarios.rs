//! The scenarios of phase 5b — here most of the criteria from PLAN.md fall.
//!
//! Every case runs over the seeds from [`tg_dst::seeds`] and reports on failure
//! the seed from which it arose. `TG_DST_SEED=<n>` reproduces a reported run
//! (ADR-0020: exportable evidence).
//!
//! **What "no split-brain mutation" means here.** Not: "never do two nodes
//! consider themselves the leader". That occurs in Raft and is harmless — a
//! cut-off leader **believes** for a while that it still leads, until its
//! timeout deposes it. What is decisive is that in that time it **can commit
//! nothing**, because it lacks the majority. What is checked is therefore the
//! mutation, not the opinion: what was attempted on the minority side must
//! afterwards stand in **none** of the five state machines.

use std::collections::BTreeMap;
use std::time::Duration;

use tg_consensus::{ClusterState, Command, NodeId, Outcome, Topology, UtcMillis};
use tg_dst::{Cluster, Faults, seeds};

// --- Building blocks --------------------------------------------------------

fn document(name: &str, class: Option<&str>) -> String {
    let class = class.map_or(String::new(), |c| format!(" class=\"{c}\""));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\"{class}>\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

fn upsert(name: &str) -> Command {
    Command::UpsertWorkload {
        document: document(name, None),
    }
}

fn single_writer(name: &str) -> Command {
    Command::UpsertWorkload {
        document: document(name, Some("single-writer")),
    }
}

fn node(name: &str) -> Command {
    Command::UpsertNode {
        name: name.to_owned(),
        topology: Topology {
            site: "fra".to_owned(),
            hall: "h1".to_owned(),
            rack: "r7".to_owned(),
        },
        capacity: tg_consensus::Resources::default(),
        reserved: tg_consensus::Resources::default(),
        source: tg_consensus::Origin::Operator,
    }
}

/// All five state machines are byte for byte the same.
///
/// Byte for byte, not "in content": ADR-0030 builds the projection per node from
/// the log, and it is a shared view only if the state beneath yields the same
/// document on every node.
fn assert_all_agree(states: &BTreeMap<NodeId, ClusterState>, seed: u64) {
    let mut iter = states.iter();
    let (first_id, first) = iter.next().expect("at least one node");
    let reference = tg_consensus::wire::encode_state(first).expect("encodable");

    for (id, state) in iter {
        let bytes = tg_consensus::wire::encode_state(state).expect("encodable");
        assert_eq!(
            bytes, reference,
            "seed {seed}: node {id} deviates from node {first_id}"
        );
    }
}

/// No node knows this workload — the form in which "no split-brain mutation"
/// becomes checkable.
fn assert_nobody_has(states: &BTreeMap<NodeId, ClusterState>, name: &str, seed: u64) {
    for (id, state) in states {
        assert!(
            state.workload(name).is_none(),
            "seed {seed}: node {id} applied '{name}' although there was never a quorum for it"
        );
    }
}

// --- Election and basic operation -------------------------------------------

/// Five nodes elect a leader and commit (ADR-0031).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn five_nodes_elect_a_leader_and_commit() {
    for seed in seeds() {
        let cluster = Cluster::start(seed, 5).await.expect("start");

        let leader = cluster.wait_for_leader().await.expect("leader");
        assert!((1..=5).contains(&leader), "seed {seed}");

        assert_eq!(
            cluster
                .write_to_leader(node("node-a"))
                .await
                .expect("write"),
            Outcome::Applied,
            "seed {seed}"
        );
        cluster.wait_for_convergence().await.expect("convergence");

        let states = cluster.stop_and_read().await.expect("read");
        assert_all_agree(&states, seed);
        for state in states.values() {
            assert!(state.node("node-a").is_some(), "seed {seed}");
        }
    }
}

// --- Quorum boundary (ADR-0031: five nodes, quorum three) -------------------

/// The loss of **two** nodes keeps the quorum.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn losing_two_nodes_keeps_the_quorum() {
    for seed in seeds() {
        let mut cluster = Cluster::start(seed, 5).await.expect("start");
        cluster
            .write_to_leader(upsert("vorher"))
            .await
            .expect("write");

        cluster.stop(5).await.expect("halt node 5");
        cluster.stop(4).await.expect("halt node 4");

        // Three of five is exactly the majority threshold.
        assert_eq!(cluster.running().len(), 3, "seed {seed}");
        assert_eq!(
            cluster
                .write_to_leader(upsert("nachher"))
                .await
                .expect("with three nodes writing has to be possible"),
            Outcome::Applied,
            "seed {seed}"
        );

        let states = cluster.stop_and_read().await.expect("read");
        for id in [1, 2, 3] {
            let state = states.get(&id).expect("node");
            assert!(
                state.workload("nachher").is_some(),
                "seed {seed}, node {id}"
            );
        }
    }
}

/// The third failure breaks it: no election, no commit.
///
/// And — the actual point of ADR-0019 — that is **no outage but a change
/// freeze**: the remaining nodes carry on, they merely mutate nothing any more.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_third_loss_breaks_the_quorum() {
    for seed in seeds() {
        let mut cluster = Cluster::start(seed, 5).await.expect("start");
        cluster
            .write_to_leader(upsert("vorher"))
            .await
            .expect("write");

        for id in [5, 4, 3] {
            cluster.stop(id).await.expect("halt");
        }
        assert_eq!(cluster.running().len(), 2, "seed {seed}");

        // The old leader **does not step down** — `openraft` lets it run ("the
        // leader just run as long as it wants to", `raft_state/mod.rs`), and
        // that is right: a cut-off leader is harmless as long as it can commit
        // nothing. What is checked is therefore the mutation, not the opinion.
        let refused = cluster.write(1, upsert("verboten")).await;
        assert!(
            refused.is_err(),
            "seed {seed}: it wrote without a quorum — {refused:?}"
        );

        let states = cluster.stop_and_read().await.expect("read");
        assert_nobody_has(&states, "verboten", seed);
        for id in [1, 2] {
            assert!(
                states.get(&id).expect("node").workload("vorher").is_some(),
                "seed {seed}: the position before the freeze is lost"
            );
        }
    }
}

// --- Partition --------------------------------------------------------------

/// The minority side of a partition does not mutate, the majority side carries
/// on — and after healing all five are the same.
///
/// The cut-off old leader deliberately lies in the minority: node 1 has the
/// shortest election timeout and therefore leads at the start.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_minority_side_of_a_partition_cannot_mutate() {
    for seed in seeds() {
        let cluster = Cluster::start(seed, 5).await.expect("start");
        assert_eq!(cluster.leader(), Some(1), "seed {seed}: node 1 leads");

        cluster.inject(Faults::none().with_partition([&[1, 2][..], &[3, 4, 5][..]]));

        // Majority side: elects anew and writes.
        let majority = cluster
            .wait_for_leader_among(&[3, 4, 5])
            .await
            .expect("the majority side elects");
        assert!([3, 4, 5].contains(&majority), "seed {seed}");
        assert_eq!(
            cluster
                .write(majority, upsert("mehrheit"))
                .await
                .expect("the majority has to be able to write"),
            Outcome::Applied,
            "seed {seed}"
        );

        // Minority side: what it attempts does not get through.
        let refused = cluster.write(1, upsert("minderheit")).await;
        assert!(
            refused.is_err(),
            "seed {seed}: the minority wrote — {refused:?}"
        );

        cluster.bus().heal();
        cluster
            .wait_for_leader()
            .await
            .expect("leader after healing");
        cluster.wait_for_convergence().await.expect("convergence");

        let states = cluster.stop_and_read().await.expect("read");
        assert_all_agree(&states, seed);
        assert_nobody_has(&states, "minderheit", seed);
        for (id, state) in &states {
            assert!(
                state.workload("mehrheit").is_some(),
                "seed {seed}: node {id} is missing the majority's decision"
            );
        }
    }
}

/// A partition without a majority side (2/2/1) freezes the whole cluster.
///
/// No side has three nodes, so **none** may commit anything. That is the case in
/// which a sloppy implementation lets two leaders arise that both mutate "only
/// their side".
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_partition_without_a_majority_freezes_everything() {
    for seed in seeds() {
        let cluster = Cluster::start(seed, 5).await.expect("start");
        cluster
            .write_to_leader(upsert("vorher"))
            .await
            .expect("write");

        cluster.inject(Faults::none().with_partition([&[1, 2][..], &[3, 4][..], &[5][..]]));

        // On each of the three islands a write is attempted. Who considers
        // themselves the leader is irrelevant: without three nodes behind them
        // nobody commits.
        for id in [1, 3, 5] {
            let refused = cluster.write(id, upsert(&format!("insel-{id}"))).await;
            assert!(
                refused.is_err(),
                "seed {seed}: node {id} wrote on its island — {refused:?}"
            );
        }

        cluster.bus().heal();
        cluster
            .wait_for_leader()
            .await
            .expect("leader after healing");
        cluster.wait_for_convergence().await.expect("convergence");

        let states = cluster.stop_and_read().await.expect("read");
        assert_all_agree(&states, seed);
        for id in [1, 3, 5] {
            assert_nobody_has(&states, &format!("insel-{id}"), seed);
        }
        for state in states.values() {
            assert!(state.workload("vorher").is_some(), "seed {seed}");
        }
    }
}

// --- Reordering and loss ----------------------------------------------------

/// A network that lets messages overtake each other and loses every tenth does
/// not stop the cluster — it only slows it down.
///
/// The reordering arises from spread latencies: whoever is sent later and draws
/// less arrives earlier.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reordering_and_loss_do_not_break_convergence() {
    for seed in seeds() {
        let cluster = Cluster::start(seed, 5).await.expect("start");

        cluster.inject(
            Faults::none()
                .with_base_delay(Duration::from_millis(2))
                .with_jitter(Duration::from_millis(40))
                .with_loss_permille(200),
        );

        for index in 0..8 {
            cluster
                .write_to_leader(upsert(&format!("w{index}")))
                .await
                .unwrap_or_else(|err| panic!("seed {seed}, write {index}: {err}"));
        }

        // Carry on under loss for a while before healing.
        //
        // Not cosmetics: the probe below claims that the injector really struck,
        // and that claim was at first statistical. A sweep over 250 seeds found
        // the case (seed 98706598451883118) in which a short run at 10 % loss
        // got through by chance without a single loss — the suite ran red
        // without anything being wrong at the consensus. With around 80 messages
        // from this second's heartbeats and a 20 % loss rate the probability of
        // a loss-free run lies at about 1e-8.
        tokio::time::sleep(Duration::from_secs(1)).await;

        cluster.bus().heal();
        cluster.wait_for_convergence().await.expect("convergence");

        let trace = cluster.bus().trace();
        assert!(
            trace.dropped() > 0,
            "seed {seed}: at 20 % loss over one second nothing was lost — the \
             injector does not bite"
        );

        let states = cluster.stop_and_read().await.expect("read");
        assert_all_agree(&states, seed);
        for index in 0..8 {
            for (id, state) in &states {
                assert!(
                    state.workload(&format!("w{index}")).is_some(),
                    "seed {seed}: node {id} is missing w{index}"
                );
            }
        }
    }
}

// --- Clock skew (ADR-0024) --------------------------------------------------

/// Offset clocks of the proposers do **not** lead to different state machines.
///
/// ADR-0024 separates two time sources, and ADR-0004/0010 uses the first: the
/// traceable UTC travels **in the command**. The comparison `now >= expires_at`
/// is thereby part of the log and not of the environment — every node computes
/// with the same number, even if the number comes from a wrong clock.
///
/// The monotonic side is additionally shifted here — over asymmetric latencies
/// and the per-node offset election timeouts. A real monotonic clock shifted per
/// node is not representable in the harness (see `tg_dst`'s module header), and
/// that limit stands here expressly, so that a green run does not claim more
/// than it checked.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn clock_skew_between_proposers_does_not_diverge_the_nodes() {
    for seed in seeds() {
        let cluster = Cluster::start(seed, 5).await.expect("start");

        cluster.write_to_leader(node("node-1")).await.expect("node");
        cluster
            .write_to_leader(single_writer("ledger"))
            .await
            .expect("workload");

        // Every node believes a different time — up to two seconds apart. The
        // requests nevertheless all go through the same log. The latencies stay
        // below the replication timeout — see
        // `a_link_slower_than_the_heartbeat_never_replicates` for the case above
        // it and the conclusion from it.
        cluster.inject(
            Faults::none()
                .with_node_delay(2, Duration::from_millis(10))
                .with_node_delay(5, Duration::from_millis(30)),
        );

        let skews: [u64; 5] = [0, 500, 1_000, 1_500, 2_000];
        let mut granted = Vec::new();

        for (index, skew) in skews.iter().enumerate() {
            let now = UtcMillis::new(10_000 + skew);
            let expires_at = UtcMillis::new(10_000 + skew + 15_000);
            let outcome = cluster
                .write_to_leader(Command::GrantLease {
                    workload: "ledger".to_owned(),
                    node: "node-1".to_owned(),
                    now,
                    expires_at,
                })
                .await
                .unwrap_or_else(|err| panic!("seed {seed}, request {index}: {err}"));
            granted.push(outcome);
        }

        // All requests concern the same holder — so granted, every time with a
        // higher epoch, never refused.
        for (index, outcome) in granted.iter().enumerate() {
            assert!(
                matches!(outcome, Outcome::LeaseGranted { .. }),
                "seed {seed}, request {index}: {outcome:?}"
            );
        }

        cluster.bus().heal();
        cluster.wait_for_convergence().await.expect("convergence");

        let states = cluster.stop_and_read().await.expect("read");
        assert_all_agree(&states, seed);

        // And the expiry follows the number in the log, not a clock on the node:
        // the last granted lease expires at the last proposer's point in time,
        // the same on every node.
        for (id, state) in &states {
            let lease = state.lease("ledger").expect("lease");
            assert_eq!(lease.holder(), "node-1", "seed {seed}, node {id}");
            assert_eq!(
                lease.expires_at(),
                UtcMillis::new(10_000 + 2_000 + 15_000),
                "seed {seed}, node {id}"
            );
        }
    }
}

/// A path slower than the heartbeat replicates **not at all**.
///
/// That is a finding of the harness, not a test artifact: `openraft` sets the
/// timeout of the `append_entries` call in `replication/mod.rs` to
/// `Config::heartbeat_interval` — here 50 ms. A single latency above that means
/// that **every** replication attempt expires before the answer is there. The
/// node does not fail, it merely never catches up again.
///
/// The conclusion belongs to phase 5c and to ADR-0031: the cluster is spread over
/// at least three failure domains, and `heartbeat_interval` has to lie above the
/// latency between them. With `openraft`'s default (50 ms) a domain that stands
/// further away is permanently cut off — and quietly at that, because the quorum
/// is held by the other four.
///
/// The test records both: that it happens, and that it can be healed.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_link_slower_than_the_heartbeat_never_replicates() {
    let seed = 0x51_0770;
    let cluster = Cluster::start(seed, 5).await.expect("start");

    let slow = Duration::from_millis(tg_dst::HEARTBEAT_MS + 20);
    cluster.inject(Faults::none().with_node_delay(5, slow));

    for index in 0..3 {
        cluster
            .write_to_leader(upsert(&format!("w{index}")))
            .await
            .expect("the other four hold the quorum");
    }

    // Four of five suffice — the cluster notices nothing.
    let stalled = cluster.wait_for_convergence_among(&[1, 2, 3, 4]).await;
    assert!(stalled.is_ok(), "the fast majority has to converge");
    assert!(
        cluster.wait_for_convergence().await.is_err(),
        "node 5 should not have caught up at {slow:?} of single latency"
    );

    // And as soon as the path is faster than the heartbeat, it catches up.
    cluster.inject(Faults::none());
    cluster
        .wait_for_convergence()
        .await
        .expect("after healing node 5 catches up");

    let states = cluster.stop_and_read().await.expect("read");
    assert_all_agree(&states, seed);
}

// --- Node loss and return ---------------------------------------------------

/// A node fails, misses decisions and catches up after its return.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_returning_node_catches_up() {
    for seed in seeds() {
        let mut cluster = Cluster::start(seed, 5).await.expect("start");

        cluster.stop(4).await.expect("halt node 4");
        for index in 0..4 {
            cluster
                .write_to_leader(upsert(&format!("waehrend-{index}")))
                .await
                .expect("write");
        }

        cluster.restart(4).await.expect("node 4 back");
        cluster.wait_for_convergence().await.expect("convergence");

        let states = cluster.stop_and_read().await.expect("read");
        assert_all_agree(&states, seed);

        let returned = states.get(&4).expect("node 4");
        for index in 0..4 {
            assert!(
                returned.workload(&format!("waehrend-{index}")).is_some(),
                "seed {seed}: the returned node has not caught up on waehrend-{index}"
            );
        }
    }
}

/// The leader fails; another takes over without anything being lost.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn killing_the_leader_hands_over_without_loss() {
    for seed in seeds() {
        let mut cluster = Cluster::start(seed, 5).await.expect("start");
        let first = cluster.wait_for_leader().await.expect("leader");
        cluster
            .write_to_leader(upsert("before-the-change"))
            .await
            .expect("write");

        cluster.stop(first).await.expect("halt the leader");

        let second = cluster.wait_for_leader().await.expect("new leader");
        assert_ne!(second, first, "seed {seed}");
        assert_eq!(
            cluster
                .write_to_leader(upsert("after-the-change"))
                .await
                .expect("write"),
            Outcome::Applied,
            "seed {seed}"
        );

        let states = cluster.stop_and_read().await.expect("read");
        for (id, state) in &states {
            if *id == first {
                continue;
            }
            assert!(
                state.workload("before-the-change").is_some(),
                "seed {seed}: node {id} has lost the position before the change"
            );
        }
    }
}

// --- Reproducibility (ADR-0020) ---------------------------------------------

/// The same seed yields the same run.
///
/// Compared are the bus's **decisions**, not their points in time: which message
/// on which path was delivered or discarded. That is the quantity that follows
/// from the seed — the points in time additionally hang on when `openraft` let
/// its tasks run and would hide the actual comparison behind noise.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_same_seed_reproduces_the_run() {
    let seed = 0x0DD_BA11;

    let first = run_for_trace(seed).await;
    let second = run_for_trace(seed).await;

    assert_eq!(
        first.0, second.0,
        "the same seed yielded two different runs"
    );
    assert_eq!(first.1, second.1, "different end states");

    let other = run_for_trace(seed ^ 0xFFFF).await;
    assert_ne!(
        first.0, other.0,
        "two different seeds yielded the same run — the seed is without effect"
    );
}

/// A short, disturbed run; back come the bus's decisions and the end state.
async fn run_for_trace(seed: u64) -> (Vec<u8>, Vec<u8>) {
    let cluster = Cluster::start(seed, 5).await.expect("start");
    cluster.inject(
        Faults::none()
            .with_jitter(Duration::from_millis(20))
            .with_loss_permille(150),
    );

    for index in 0..4 {
        cluster
            .write_to_leader(upsert(&format!("w{index}")))
            .await
            .expect("write");
    }
    cluster.bus().heal();
    cluster.wait_for_convergence().await.expect("convergence");

    let decisions = format!("{:?}", cluster.bus().trace().decisions()).into_bytes();
    let states = cluster.stop_and_read().await.expect("read");
    let state =
        tg_consensus::wire::encode_state(states.get(&1).expect("node 1")).expect("encodable");

    (decisions, state)
}

/// The trace can be printed as JSON — the format in which a DST run goes out of
/// the house as evidence per ADR-0020.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_run_exports_its_evidence() {
    let cluster = Cluster::start(4711, 5).await.expect("start");
    cluster.inject(Faults::none().with_loss_permille(200));
    cluster.write_to_leader(upsert("api")).await.expect("write");
    cluster.bus().heal();
    cluster.wait_for_convergence().await.expect("convergence");

    let json = cluster.bus().trace().to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("readable JSON");

    assert_eq!(parsed["seed"], 4711);
    assert!(parsed["events"].as_array().expect("list").len() > 5);
    assert!(parsed["dropped"].as_u64().expect("number") > 0);
    assert!(json.contains("append_entries"));
}
