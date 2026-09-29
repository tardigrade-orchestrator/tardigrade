//! The bus in operation: does the injection bite on real nodes?
//!
//! `tests/faults.rs` checks the injector as a pure function. That does not
//! suffice: between "the verdict is discard" and "the message really does not
//! arrive" lies the whole bus. A wiring error there — a forgotten branch, a
//! verdict that is obtained and then ignored — would let every scenario run
//! green without a fault ever having been injected.
//!
//! ADR-0032 names exactly that as the counter-measure to the home-grown bus:
//! "does it really lose messages when it should?"

use std::time::Duration;

use tg_consensus::{Command, Topology};
use tg_dst::{Cluster, Faults};

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

/// With total loss the cluster comes to a standstill.
///
/// The sharpest proof that the injection bites: a cluster that could write a
/// moment ago can no longer — and **only** because the bus drops everything.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn total_loss_stops_the_cluster() {
    let cluster = Cluster::start(1, 5).await.expect("start");
    cluster
        .write_to_leader(node("vorher"))
        .await
        .expect("write");

    cluster.inject(Faults::none().with_loss_permille(1000));

    let refused = cluster.write(1, node("waehrend")).await;
    assert!(
        refused.is_err(),
        "at 100 % loss something was committed — the bus delivers: {refused:?}"
    );

    let trace = cluster.bus().trace();
    assert!(trace.dropped() > 0, "not a single message discarded");

    // And afterwards it works again — the loss was the cause, not a broken
    // cluster.
    cluster.inject(Faults::none());
    cluster
        .write_to_leader(node("danach"))
        .await
        .expect("after healing writing has to be possible again");

    let states = cluster.stop_and_read().await.expect("read");
    for state in states.values() {
        assert!(state.node("waehrend").is_none());
    }
}

/// The trace counts along — and both outcomes, delivery and loss.
///
/// Without this probe a `trace.dropped() > 0` in the scenarios would be
/// worthless: a trace that records nothing does not break the claim, it makes it
/// uncheckable.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_trace_counts_both_outcomes() {
    let cluster = Cluster::start(9, 5).await.expect("start");

    let quiet = cluster.bus().trace();
    assert!(quiet.delivered() > 0, "at rest nothing arrived");
    assert_eq!(quiet.dropped(), 0, "at rest something was lost");
    assert_eq!(quiet.seed(), 9);

    cluster.inject(Faults::none().with_loss_permille(500));
    let _ = cluster.write(1, node("egal")).await;

    let noisy = cluster.bus().trace();
    assert!(noisy.dropped() > 0, "at 50 % loss nothing was lost");
    assert!(
        noisy.events().len() > quiet.events().len(),
        "the trace has not grown"
    );

    // Every event carries sender, receiver and a number — otherwise the evidence
    // per ADR-0020 is not traceable.
    for event in noisy.events() {
        assert!((1..=5).contains(&event.from));
        assert!((1..=5).contains(&event.to));
        assert_ne!(event.from, event.to, "a node sends itself nothing");
    }
}

/// A message flying into a partition gets lost.
///
/// The case a bus overlooks that only checks at sending: the path was open when
/// the message took off and is no longer open at arrival. A bus that delivers it
/// nevertheless makes partitions permeable — at exactly the moment that matters.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_message_flying_into_a_partition_is_lost() {
    let cluster = Cluster::start(3, 5).await.expect("start");

    // A long latency so that every message is in flight for a while — but below
    // the replication timeout, otherwise `openraft` discards the delivery itself
    // and there would be no arrival left to check.
    let slow = Faults::none().with_base_delay(Duration::from_millis(40));
    cluster.inject(slow.clone());

    // First let the heartbeat get going, then partition **between** two beats.
    // The offset is the point: if the partition falls exactly on a heartbeat,
    // the order of the timers decides whether the message takes off at all — and
    // the case this test looks for would not arise in the first place. At 50 ms
    // spacing and 40 ms latency the gap lies at a multiple of 50 plus about 25.
    tokio::time::sleep(Duration::from_millis(175)).await;

    cluster.inject(slow.with_partition([&[1, 2][..], &[3, 4, 5][..]]));
    tokio::time::sleep(Duration::from_millis(120)).await;

    let trace = cluster.bus().trace();
    let lost_in_flight = trace
        .events()
        .iter()
        .filter(|event| matches!(event.outcome, tg_dst::Outcome::LostInFlight))
        .count();

    assert!(
        lost_in_flight > 0,
        "no message was lost in flight — the bus checks only at sending. \
         Delivered {}, discarded {}, events {}",
        trace.delivered(),
        trace.dropped(),
        trace.events().len()
    );
}

/// A halted node receives nothing any more — not even from a message that took
/// off before the halt.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_stopped_node_receives_nothing() {
    let mut cluster = Cluster::start(5, 5).await.expect("start");
    cluster.inject(Faults::none().with_base_delay(Duration::from_millis(20)));

    cluster.stop(4).await.expect("halt node 4");
    let before = cluster.bus().trace().events().len();

    cluster
        .write_to_leader(node("after-the-stop"))
        .await
        .expect("four nodes hold the quorum");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let trace = cluster.bus().trace();
    let delivered_to_four = trace
        .events()
        .iter()
        .skip(before)
        .filter(|event| event.to == 4 && matches!(event.outcome, tg_dst::Outcome::Delivered { .. }))
        .count();

    assert_eq!(delivered_to_four, 0, "a halted node was delivered to");
}

/// The bus delays in **virtual** time.
///
/// A harness that waits real seconds does not get used: a partition over two
/// election timeouts then costs seconds per case, and the suite disappears from
/// the test run. The proof belongs here, because it can otherwise tip unnoticed
/// — a single call on the real clock suffices.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn delays_cost_no_wall_clock() {
    let started = std::time::Instant::now();

    let cluster = Cluster::start(7, 5).await.expect("start");
    cluster.inject(
        Faults::none()
            .with_base_delay(Duration::from_millis(30))
            .with_jitter(Duration::from_millis(15)),
    );
    for index in 0..5 {
        cluster
            .write_to_leader(node(&format!("n{index}")))
            .await
            .expect("write");
    }
    cluster.wait_for_convergence().await.expect("convergence");

    let wall = started.elapsed();
    assert!(
        wall < Duration::from_secs(5),
        "the run cost {wall:?} of wall clock — time does not run virtually"
    );
}
