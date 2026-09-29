//! The generation of a declaration (ADR-0071) — pure logic, tests first.

use tg_model::rollout::Generations;

/// **The default is zero**, and on that hangs that an upgrade triggers no
/// restart (ADR-0071, determination 5).
#[test]
fn nothing_ordered_means_generation_zero() {
    let generations = Generations::default();

    assert!(generations.is_empty());
    assert_eq!(generations.wanted(0), 0);
    assert_eq!(generations.wanted(7), 0);
}

/// A decree for **all** applies to every instance — including one that did not
/// yet exist when the decree was made.
#[test]
fn an_order_for_all_covers_instances_that_come_later() {
    let mut generations = Generations::default();
    generations.set(None, 3);

    assert_eq!(generations.wanted(0), 3);
    assert_eq!(generations.wanted(99), 3);
}

/// **The maximum, not "the more specific one wins".**
///
/// Otherwise a single decree would take back a general one — a restart somebody
/// decreed and that does not happen.
#[test]
fn the_effective_generation_is_the_maximum_of_both_levels() {
    let mut generations = Generations::default();
    generations.set(None, 5);
    generations.set(Some(0), 2);

    assert_eq!(
        generations.wanted(0),
        5,
        "the older single decree must not turn the general one back"
    );

    generations.set(Some(1), 9);
    assert_eq!(generations.wanted(1), 9, "and the newer one raises it");
    assert_eq!(
        generations.wanted(2),
        5,
        "without a single decree the general one applies"
    );
}

/// **What a new decree has to exceed** is the *effective* generation.
///
/// A number below it would be accepted and without effect — the outcome an
/// operator recognizes least easily.
#[test]
fn the_bar_for_a_single_instance_is_its_effective_generation() {
    let mut generations = Generations::default();
    generations.set(None, 5);

    assert_eq!(
        generations.at(Some(0)),
        5,
        "a 3 for instance 0 would be accepted and without effect"
    );
    assert_eq!(
        generations.at(None),
        5,
        "for all of them the general level counts"
    );

    generations.set(Some(0), 8);
    assert_eq!(generations.at(Some(0)), 8);
    assert_eq!(
        generations.at(None),
        5,
        "a single decree does not raise the general bar"
    );
}
