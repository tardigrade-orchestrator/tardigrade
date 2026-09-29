//! The rotation policy as a **time window** (ADR-0057, determination 5).
//!
//! Written before the implementation. Pure logic — CLAUDE.md demands tests
//! first here, and the reason is tangible at this place: the policy writes into
//! the log of its own accord, and otherwise nobody sees its rejection paths.

use tg_model::keys::{KeyKind, RotationPolicy};

/// Without a rule nothing rotates.
///
/// The same direction as "without a rule no capacity" (ADR-0049): what an
/// operator has not decreed does not happen.
#[test]
fn without_a_rule_nothing_rotates() {
    let policy = RotationPolicy::default();

    assert_eq!(policy.wanted("node-1", KeyKind::Underlay, 10_000), None);
}

/// With a rule the generation rises with time — **monotonically**.
#[test]
fn the_generation_grows_with_time() {
    let policy = RotationPolicy::default().with(KeyKind::Underlay, 90);

    let early = policy
        .wanted("node-1", KeyKind::Underlay, 0)
        .expect("with a rule");
    let later = policy
        .wanted("node-1", KeyKind::Underlay, 10_000)
        .expect("with a rule");

    assert!(later > early, "the generation has to rise with time");
}

/// **Within one window it stays the same.**
///
/// Otherwise the policy would write at every tick — and the log would get one
/// rotation per hour instead of per period.
#[test]
fn within_one_period_it_stays_put() {
    let policy = RotationPolicy::default().with(KeyKind::Underlay, 90);

    let first = policy.wanted("node-1", KeyKind::Underlay, 1_000);
    for day in 1_001..1_010 {
        assert_eq!(
            policy.wanted("node-1", KeyKind::Underlay, day),
            first,
            "day {day} lies in the same window and has to give the same generation"
        );
    }
}

/// **The two kinds are independent.**
///
/// A rule for the underlay does not rotate the identity along — they rotate for
/// different reasons (ADR-0055).
#[test]
fn the_two_kinds_are_independent() {
    let policy = RotationPolicy::default().with(KeyKind::Underlay, 90);

    assert!(policy.wanted("node-1", KeyKind::Underlay, 500).is_some());
    assert_eq!(policy.wanted("node-1", KeyKind::Identity, 500), None);
}

/// **The offset spreads the nodes**, and it is no ornament: without it all
/// tunnels re-key on the same day.
///
/// What is checked is that there is a day at all on which two nodes carry
/// different generations — not which one. An assurance on a particular day
/// would be one about the hash function and not about the property.
#[test]
fn the_offset_spreads_the_nodes() {
    let policy = RotationPolicy::default().with(KeyKind::Underlay, 90);

    let spread = (0..90).any(|day| {
        policy.wanted("node-a", KeyKind::Underlay, day)
            != policy.wanted("node-b", KeyKind::Underlay, day)
    });

    assert!(
        spread,
        "all nodes rotate on the same day — the offset takes no effect"
    );
}

/// The same node always gets the same offset.
///
/// Otherwise its rotation day would wander at every restart of the leader, and
/// the policy would write outside its period.
#[test]
fn the_offset_is_stable_for_a_name() {
    let policy = RotationPolicy::default().with(KeyKind::Underlay, 90);

    for _ in 0..5 {
        assert_eq!(
            policy.wanted("node-a", KeyKind::Underlay, 4_711),
            policy.wanted("node-a", KeyKind::Underlay, 4_711)
        );
    }
}

/// **A period of zero is no rotation.**
///
/// It stands for "switched off" — and a division by zero would be the
/// alternative.
#[test]
fn a_period_of_zero_is_off() {
    let policy = RotationPolicy::default().with(KeyKind::Underlay, 0);

    assert_eq!(policy.wanted("node-1", KeyKind::Underlay, 10_000), None);
}
