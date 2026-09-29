//! The fault injector itself — the tests ADR-0032 expressly demands.
//!
//! "The bus is home-grown and has to be correct itself — it is tested along, but
//! an error there feigns correctness. Counter-measure: the bus gets tests of its
//! own against its *expected* misbehaviour (does it really lose messages when it
//! should?)."
//!
//! Hence the reversal of the usual test direction: what is checked is not that
//! nothing breaks but that **what should break does break**. A bus that delivers
//! at `loss = 100 %` makes every scenario above it worthless.
//!
//! The injector is a pure function `(seed, path, message number) → verdict`. No
//! shared random generator: otherwise the verdict about message 7 on path 1→2
//! would depend on how many messages have meanwhile flowed between entirely
//! different nodes — and thereby on the executor's task order instead of on the
//! seed.

use std::time::Duration;

use tg_dst::{Faults, Verdict};

/// A path over which a fixed number of messages runs.
fn verdicts(faults: &Faults, seed: u64, from: u64, to: u64, count: u64) -> Vec<Verdict> {
    (0..count)
        .map(|seq| faults.decide(seed, from, to, seq))
        .collect()
}

fn delivered(verdicts: &[Verdict]) -> usize {
    verdicts
        .iter()
        .filter(|verdict| matches!(verdict, Verdict::Deliver { .. }))
        .count()
}

// --- The initial state ------------------------------------------------------

/// Without an injected fault everything arrives, without delay.
///
/// The counter-proof to everything that follows: if the bus stayed lossy at rest
/// too, it would not be distinguishable whether a scenario fails at the
/// injection or at the bus.
#[test]
fn a_quiet_bus_delivers_everything_at_once() {
    let faults = Faults::none();
    let verdicts = verdicts(&faults, 42, 1, 2, 200);

    assert_eq!(delivered(&verdicts), 200);
    for verdict in &verdicts {
        assert_eq!(
            *verdict,
            Verdict::Deliver {
                delay: Duration::ZERO
            }
        );
    }
}

// --- Loss -------------------------------------------------------------------

/// At total loss **nothing** arrives. That is the test ADR-0032 means: does it
/// really lose when it should?
#[test]
fn total_loss_delivers_nothing() {
    let faults = Faults::none().with_loss_permille(1000);

    assert_eq!(delivered(&verdicts(&faults, 7, 1, 2, 500)), 0);
}

/// And at loss zero nothing gets lost — the other edge of the same scale.
#[test]
fn zero_loss_drops_nothing() {
    let faults = Faults::none().with_loss_permille(0);

    assert_eq!(delivered(&verdicts(&faults, 7, 1, 2, 500)), 500);
}

/// In between the rate roughly hits its target — it is a roll, not a counter,
/// but an injector that at 30 % never or always loses would be broken.
///
/// The bound is deliberately wide: what is checked is the order of magnitude,
/// not the quality of the generator.
#[test]
fn a_partial_loss_rate_lands_near_its_target() {
    for permille in [100, 300, 500, 900] {
        let faults = Faults::none().with_loss_permille(permille);
        let count: u64 = 4_000;
        let kept = u64::try_from(delivered(&verdicts(&faults, 99, 1, 2, count))).expect("fits");
        let dropped = count - kept;

        let expected = count * u64::from(permille) / 1000;
        let deviation = dropped.abs_diff(expected);
        assert!(
            deviation * 10 < count,
            "{permille} per mille: {dropped} of {count} lost, expected ~{expected}"
        );
    }
}

// --- Partition --------------------------------------------------------------

/// Nothing crosses a partition boundary, everything within a side does.
///
/// Both directions: a partition that cuts only one direction would be no
/// partition but a one-way street — and a scenario "the minority cannot write"
/// would run green wrongly, because the answers still get through.
#[test]
fn a_partition_cuts_both_directions_and_only_across_the_line() {
    let faults = Faults::none().with_partition([&[1, 2, 3][..], &[4, 5][..]]);

    for (from, to) in [(1, 4), (4, 1), (2, 5), (5, 2), (3, 4), (4, 3)] {
        assert_eq!(
            delivered(&verdicts(&faults, 1, from, to, 50)),
            0,
            "{from} -> {to} should have been separated"
        );
    }

    for (from, to) in [(1, 2), (2, 1), (2, 3), (3, 1), (4, 5), (5, 4)] {
        assert_eq!(
            delivered(&verdicts(&faults, 1, from, to, 50)),
            50,
            "{from} -> {to} lies on one side and should have got through"
        );
    }
}

/// Three sides are a partition too. The quorum boundary from ADR-0031 cannot
/// otherwise be posed: 2/2/1 has **no** majority side.
#[test]
fn three_way_partitions_isolate_every_side() {
    let faults = Faults::none().with_partition([&[1, 2][..], &[3, 4][..], &[5][..]]);

    for (from, to) in [(1, 3), (3, 5), (5, 1), (2, 4), (4, 5)] {
        assert_eq!(delivered(&verdicts(&faults, 1, from, to, 20)), 0);
    }
    for (from, to) in [(1, 2), (3, 4)] {
        assert_eq!(delivered(&verdicts(&faults, 1, from, to, 20)), 20);
    }
}

/// A node named in no group stays with all the other unpartitioned ones —
/// otherwise every scenario would have to enumerate all five nodes.
#[test]
fn unnamed_nodes_stay_together() {
    let faults = Faults::none().with_partition([&[5][..]]);

    assert_eq!(delivered(&verdicts(&faults, 1, 1, 2, 20)), 20);
    assert_eq!(delivered(&verdicts(&faults, 1, 2, 3, 20)), 20);
    assert_eq!(delivered(&verdicts(&faults, 1, 1, 5, 20)), 0);
    assert_eq!(delivered(&verdicts(&faults, 1, 5, 4, 20)), 0);
}

/// A node always talks to itself — `openraft` sends itself no RPCs, but an
/// injector that partitioned the own identifier would be a trap for every later
/// scenario.
#[test]
fn a_node_always_reaches_itself() {
    let faults = Faults::none()
        .with_partition([&[1][..], &[2, 3, 4, 5][..]])
        .with_loss_permille(1000);

    assert!(matches!(faults.decide(1, 1, 1, 0), Verdict::Deliver { .. }));
}

// --- Node failure -----------------------------------------------------------

/// A failed node neither sends nor receives.
///
/// The difference from a partition: a partition has two sides that each carry on
/// for themselves. A failure has only one.
#[test]
fn a_downed_node_neither_sends_nor_receives() {
    let faults = Faults::none().with_down([3]);

    assert_eq!(delivered(&verdicts(&faults, 1, 3, 1, 20)), 0);
    assert_eq!(delivered(&verdicts(&faults, 1, 1, 3, 20)), 0);
    assert_eq!(delivered(&verdicts(&faults, 1, 1, 2, 20)), 20);
    assert!(matches!(faults.decide(1, 3, 3, 0), Verdict::Drop));
}

// --- Latency and reordering -------------------------------------------------

/// Without a spread the delay is the same on every message — then they arrive in
/// the order in which they were sent.
#[test]
fn without_jitter_every_message_takes_the_same_time() {
    let faults = Faults::none().with_base_delay(Duration::from_millis(5));

    for verdict in verdicts(&faults, 3, 1, 2, 100) {
        assert_eq!(
            verdict,
            Verdict::Deliver {
                delay: Duration::from_millis(5)
            }
        );
    }
}

/// With a spread the latencies differ — and precisely out of that reordering
/// arises.
///
/// Reordering is no switch of its own here but the consequence: whoever is sent
/// later and draws less latency arrives earlier. A separate "reorder" switch
/// would model the same thing a second time and could contradict it.
#[test]
fn jitter_makes_messages_overtake_each_other() {
    let faults = Faults::none()
        .with_base_delay(Duration::from_millis(1))
        .with_jitter(Duration::from_millis(50));

    let delays: Vec<Duration> = verdicts(&faults, 11, 1, 2, 200)
        .into_iter()
        .map(|verdict| match verdict {
            Verdict::Deliver { delay } => delay,
            Verdict::Drop => panic!("without loss nothing may drop"),
        })
        .collect();

    let distinct: std::collections::BTreeSet<Duration> = delays.iter().copied().collect();
    assert!(
        distinct.len() > 10,
        "hardly any spread: {} values",
        distinct.len()
    );

    // At least once a later message overtakes an earlier one: arrival = sending
    // time (here: the number) + latency.
    let overtakes = delays
        .windows(2)
        .filter(|pair| pair[1] + Duration::from_millis(1) < pair[0])
        .count();
    assert!(overtakes > 0, "no reordering arose");

    // And the spread stays within its bounds.
    for delay in delays {
        assert!(delay >= Duration::from_millis(1));
        assert!(delay < Duration::from_millis(51));
    }
}

/// A node can carry an additional latency of its own — asymmetric paths.
///
/// That is the network side of the clock skew: a node whose messages
/// systematically arrive later behaves for the election like one whose clock is
/// slow (ADR-0024 separates the two time sources; the DST can really shift only
/// one — see `tests/scenarios.rs`).
#[test]
fn a_slow_node_slows_both_of_its_directions() {
    let faults = Faults::none().with_node_delay(4, Duration::from_millis(20));

    let out = faults.decide(1, 4, 1, 0);
    let back = faults.decide(1, 1, 4, 0);
    let other = faults.decide(1, 1, 2, 0);

    assert_eq!(
        out,
        Verdict::Deliver {
            delay: Duration::from_millis(20)
        }
    );
    assert_eq!(
        back,
        Verdict::Deliver {
            delay: Duration::from_millis(20)
        }
    );
    assert_eq!(
        other,
        Verdict::Deliver {
            delay: Duration::ZERO
        }
    );
}

// --- Determinism ------------------------------------------------------------

/// The same seed yields the same sequence of verdicts — the basis of the
/// reproducibility from ADR-0020.
#[test]
fn the_same_seed_yields_the_same_verdicts() {
    let faults = Faults::none()
        .with_loss_permille(250)
        .with_jitter(Duration::from_millis(30));

    let first = verdicts(&faults, 0xDEAD_BEEF, 2, 5, 1_000);
    let second = verdicts(&faults, 0xDEAD_BEEF, 2, 5, 1_000);

    assert_eq!(first, second);
}

/// A different seed yields a different run — otherwise the seed would be
/// ornament and a sweep over many seeds would always check the same thing.
#[test]
fn a_different_seed_yields_a_different_run() {
    let faults = Faults::none()
        .with_loss_permille(250)
        .with_jitter(Duration::from_millis(30));

    let first = verdicts(&faults, 1, 2, 5, 1_000);
    let second = verdicts(&faults, 2, 2, 5, 1_000);

    assert_ne!(first, second);
}

/// Every path draws its own sequence. That is the property that makes the run
/// immune to the executor's task order: what happens on 1→2 does not hang on how
/// much has meanwhile run on 3→4.
#[test]
fn every_link_draws_its_own_sequence() {
    let faults = Faults::none().with_jitter(Duration::from_millis(30));

    let one_two = verdicts(&faults, 5, 1, 2, 100);
    let three_four = verdicts(&faults, 5, 3, 4, 100);
    let two_one = verdicts(&faults, 5, 2, 1, 100);

    assert_ne!(one_two, three_four, "different paths, same sequence");
    assert_ne!(
        one_two, two_one,
        "the outbound and return direction are two paths"
    );
}

/// The verdict about the nth message of a path hangs only on n, not on whether
/// the previous ones were queried. Without that property the injector would be
/// stateful and the run no longer reconstructible from the seed.
#[test]
fn a_verdict_depends_only_on_its_own_number() {
    let faults = Faults::none()
        .with_loss_permille(400)
        .with_jitter(Duration::from_millis(15));

    let sequential = verdicts(&faults, 77, 1, 2, 50);
    let out_of_order: Vec<Verdict> = (0..50)
        .rev()
        .map(|seq| faults.decide(77, 1, 2, seq))
        .collect();

    assert_eq!(
        sequential,
        out_of_order.into_iter().rev().collect::<Vec<_>>()
    );
}

// --- Interplay of the switches ----------------------------------------------

/// Separating causes take precedence: a failed node behind a partition stays
/// away, whatever the loss rate says.
#[test]
fn a_hard_cut_beats_a_probabilistic_one() {
    let faults = Faults::none()
        .with_partition([&[1, 2, 3][..], &[4, 5][..]])
        .with_down([2])
        .with_loss_permille(0);

    assert_eq!(delivered(&verdicts(&faults, 1, 1, 4, 20)), 0);
    assert_eq!(delivered(&verdicts(&faults, 1, 1, 2, 20)), 0);
    assert_eq!(delivered(&verdicts(&faults, 1, 1, 3, 20)), 20);
}

/// A healed partition lets everything through again — the basis of every
/// scenario that checks convergence after the disturbance.
#[test]
fn healing_restores_every_link() {
    let cut = Faults::none().with_partition([&[1, 2, 3][..], &[4, 5][..]]);
    let healed = cut.healed();

    for (from, to) in [(1, 4), (4, 1), (2, 5), (5, 3)] {
        assert_eq!(delivered(&verdicts(&cut, 1, from, to, 10)), 0);
        assert_eq!(delivered(&verdicts(&healed, 1, from, to, 10)), 10);
    }
}
