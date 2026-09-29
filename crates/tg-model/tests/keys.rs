//! The rotation policy, as far as it is checkable without a cluster (ADR-0055,
//! ADR-0057).
//!
//! The **selection** of the due rotations (`rotations`) lies in `tgd` and is
//! checked there; here stands what `tg-model` itself carries. Until this cut
//! only the policy had a witness of the two — the **conversion** of a Unix
//! second into the day it computes with stood in the scheduler and had none.

/// **A day is 86,400 seconds** — the conversion `wanted` expects.
///
/// It stood as `secs / 86_400` in the scheduler and had no witness; with the
/// second consumer (`tgctl node rotate` warns against the calendar) it would
/// otherwise have been guessed twice.
///
/// What is assured is the **relation** and not a day number: a test against
/// "today is day 20,700" would be wrong tomorrow.
#[test]
fn a_day_is_eighty_six_four_hundred_seconds() {
    use tg_model::keys::day_of;

    assert_eq!(day_of(0), 0, "the epoch itself is day 0");
    assert_eq!(day_of(86_399), 0, "one second before midnight");
    assert_eq!(day_of(86_400), 1, "and midnight is the next day");

    // And over an arbitrary point: N days later is day + N.
    let start = 1_756_000_000_u64;
    for days in [1_u64, 7, 90, 365] {
        assert_eq!(
            day_of(start + days * 86_400),
            day_of(start) + days,
            "{days} days later has to be {days} days later"
        );
    }
}
