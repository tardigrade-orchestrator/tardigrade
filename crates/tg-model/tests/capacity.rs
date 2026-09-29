//! Reported capacity becomes usable capacity (ADR-0049).
//!
//! Pure logic, therefore **tests first** (CLAUDE.md). What is checked here is
//! the computation — that the report never reaches the planner is a property of
//! the wiring and stands in `crates/tgd/tests/`.

use tg_model::capacity::{CapacityPolicy, Rule};
use tg_model::placement::Resources;

const CPU: &str = Resources::CPU_MILLICORES;

fn rule(subtract: u64, percent: u32, cap: Option<u64>, reserve: u64) -> Rule {
    Rule {
        subtract,
        percent,
        cap,
        reserve,
    }
}

fn reported(millicores: u64) -> Resources {
    Resources::default().with(CPU, millicores)
}

/// **The order is fixed: first subtract, then share, then cap.**
///
/// It is so because `subtract` means something other than `percent`: "two cores
/// for the operating system" are two cores of the **machine**, not two cores of
/// our share.
#[test]
fn the_order_is_subtract_then_share_then_cap() {
    // 8000 − 2000 = 6000, of which 50 % = 3000.
    assert_eq!(rule(2000, 50, None, 0).apply(8000), 3000);

    // Computed the other way round it would be (8000 · 50 %) − 2000 = 2000.
    // The test records that it is **not** computed that way.
    assert_ne!(rule(2000, 50, None, 0).apply(8000), 2000);

    // And the cap comes last.
    assert_eq!(rule(2000, 50, Some(1000), 0).apply(8000), 1000);
}

/// Without settings the rule is transparent: a hundred percent, nothing off,
/// no bound.
#[test]
fn a_hundred_percent_passes_through() {
    assert_eq!(rule(0, 100, None, 0).apply(8000), 8000);
}

/// **Over a hundred percent is permitted** and means overbooking — a decision
/// an operator may take. It then stands in the log, and that is the difference
/// from an overbooking out of an arithmetic error.
#[test]
fn overcommitment_is_allowed_and_visible() {
    assert_eq!(rule(0, 200, None, 0).apply(4000), 8000);
}

/// Subtracting more than there is yields zero, no overflow.
#[test]
fn subtracting_more_than_reported_saturates_at_zero() {
    assert_eq!(rule(u64::MAX, 100, None, 0).apply(4000), 0);
}

/// And a nonsensical share yields a large number, no overflow that makes
/// little out of much.
#[test]
fn an_absurd_percentage_saturates_instead_of_wrapping() {
    assert_eq!(rule(0, u32::MAX, None, u64::MAX).apply(u64::MAX), u64::MAX);
}

/// **Without a rule no capacity.**
///
/// The same direction as deny-by-default in ADR-0025: an accelerator a node
/// reports and for which nobody has written a rule is not distributed
/// silently.
#[test]
fn a_resource_without_a_rule_is_not_passed_through() {
    let policy = CapacityPolicy::default().with(CPU, rule(0, 50, None, 0));
    let report = reported(4000).with("gpu", 2);

    let (capacity, _) = policy.apply(&report);

    assert_eq!(capacity.get(CPU), 2000);
    assert_eq!(capacity.get("gpu"), 0, "the GPU was distributed silently");
}

/// An empty policy yields a node without capacity — and thereby one on which
/// nothing is placed (ADR-0034). That is the safe direction.
#[test]
fn an_empty_policy_yields_nothing_usable() {
    let (capacity, reserved) = CapacityPolicy::default().apply(&reported(8000));

    assert!(capacity.is_empty());
    assert!(reserved.is_empty());
}

/// The reserve from ADR-0047 comes from the same rule — and both numbers arise
/// together, because a reserve without the capacity it comes from is no
/// statement.
///
/// **The share is deliberately not 100 %.** A policy that passes everything
/// through looks exactly like one that is not applied at all — and a test that
/// does not tell those apart records only that something comes out. Noticed at
/// a counter-check in which almost all tests of this file stayed green although
/// the rule was skipped.
#[test]
fn the_reserve_comes_from_the_same_rule() {
    let policy = CapacityPolicy::default().with(CPU, rule(0, 75, None, 1000));

    let (capacity, reserved) = policy.apply(&reported(8000));

    assert_eq!(capacity.get(CPU), 6000);
    assert_eq!(reserved.get(CPU), 1000);
}

/// **More reserve than capacity is clamped.** Otherwise a node would arise that
/// accepts nothing — and that is `cordon` and no reserve.
#[test]
fn a_reserve_larger_than_the_capacity_is_clamped() {
    let policy = CapacityPolicy::default().with(CPU, rule(0, 50, None, 9999));

    let (capacity, reserved) = policy.apply(&reported(4000));

    assert_eq!(capacity.get(CPU), 2000);
    assert_eq!(reserved.get(CPU), 2000);
}

/// Without a reserve the resource does not stand in the reserve map. A
/// `gpu = 0` beside it would be a statement about something nobody decided.
#[test]
fn no_reserve_means_no_entry() {
    let policy = CapacityPolicy::default().with(CPU, rule(0, 100, None, 0));

    let (_, reserved) = policy.apply(&reported(8000));

    assert!(reserved.is_empty(), "{reserved:?}");
}

/// The same report and the same policy yield the same result — the property on
/// which the threshold in the leader rests: writing happens only when something
/// **changes**.
#[test]
fn the_same_input_yields_the_same_output() {
    let policy = CapacityPolicy::default().with(CPU, rule(500, 80, Some(9000), 250));

    assert_eq!(policy.apply(&reported(8000)), policy.apply(&reported(8000)));
}
