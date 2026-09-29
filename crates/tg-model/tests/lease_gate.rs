//! The active role hangs on a valid lease (ADR-0010, ADR-0064).
//!
//! Written **before** the implementation.
//!
//! # Why this is pure logic
//!
//! The question reads: may this instance run now? It has three inputs — the
//! workload's class, the lease (if there is one) and the **local** clock. No
//! cluster, no container, no runtime. A rule one can check only with a running
//! agent is one whose omissions nobody has ever seen.
//!
//! # The local clock is no negligence
//!
//! Measurement happens against the deadline from the **last** slice (ADR-0064,
//! determination 5). A deadline only the leader knows would not help the
//! minority side — and it is precisely that one that has to self-fence.

use tg_defs::WorkloadClass;
use tg_model::lease::Held;
use tg_model::lease::{FENCE_MARGIN_MILLIS, LEASE_MILLIS, skew_at};
use tg_model::lease::{Role, role_of};

const NOW: u64 = 10_000;

fn held(expires_at: u64) -> Held {
    Held {
        epoch: 7,
        expires_at,
    }
}

/// **A replicated workload runs without a lease** (determination 7).
///
/// It has no active role. Binding it to a lease would mean shutting it down
/// without quorum — the opposite of ADR-0019.
#[test]
fn a_replicated_workload_needs_no_lease() {
    assert_eq!(
        role_of(WorkloadClass::Replicated, None, 0, 0, NOW, 0),
        Role::Run,
        "a replicated workload needs no lease"
    );
}

/// **A single writer without a lease does not start up** (determination 4).
///
/// That is ADR-0010's "activation needs a lease grant from the quorum" and the
/// place at which the minority side fails.
#[test]
fn a_single_writer_without_a_lease_waits() {
    assert_eq!(
        role_of(WorkloadClass::SingleWriter, None, 0, 0, NOW, 0),
        Role::Wait
    );
}

/// With a valid lease it runs.
#[test]
fn a_valid_lease_activates() {
    assert_eq!(
        role_of(
            WorkloadClass::SingleWriter,
            Some(held(NOW + 1)),
            0,
            0,
            NOW,
            0
        ),
        Role::Run
    );
}

/// **If it expires, it fences itself** (determination 5).
///
/// Autonomously and locally: precisely then it cannot ask the cluster.
#[test]
fn an_expired_lease_fences() {
    assert_eq!(
        role_of(WorkloadClass::SingleWriter, Some(held(NOW)), 0, 0, NOW, 0),
        Role::Fence,
        "the expiry is inclusive — in that one millisecond lies the doubled \
         writer"
    );
}

/// **Without a decree instance 0 carries the active role**
/// (determination 8).
///
/// The rest are warm standbys (ADR-0010) and run without a lease — precisely
/// that is why they can take over quickly.
#[test]
fn a_standby_instance_runs_without_the_lease() {
    assert_eq!(
        role_of(WorkloadClass::SingleWriter, None, 1, 0, NOW, 0),
        Role::Run
    );
}

// ------------------------------------------- The safety margin

/// **The holder fences itself before the lease expires** (ADR-0064,
/// determination 7).
///
/// # The calculation behind it
///
/// The lease runs 15 s. The agent notices the expiry only at the next pass
/// (default 10 s), and then it stops with a grace period of 10 s (ADR-0058).
/// Without a margin the old holder would therefore keep running **up to twenty
/// seconds after the expiry** — while the leader has already granted the lease
/// to the new one at expiry.
///
/// Twenty seconds with two active writers are exactly what this lease is meant
/// to prevent.
#[test]
fn the_holder_fences_before_the_lease_expires() {
    // The lease still applies for 5 s — but the margin is 20 s.
    let margin = 20_000;

    assert_eq!(
        role_of(
            WorkloadClass::SingleWriter,
            Some(held(NOW + 5_000)),
            0,
            0,
            NOW,
            margin
        ),
        Role::Fence,
        "within the safety margin fencing has to happen"
    );
}

/// And outside it keeps running.
///
/// The counter-check: without it a margin that **always** fences would be just
/// as green — and a single writer would never run.
#[test]
fn outside_the_margin_the_instance_keeps_running() {
    let margin = 20_000;

    assert_eq!(
        role_of(
            WorkloadClass::SingleWriter,
            Some(held(NOW + 25_000)),
            0,
            0,
            NOW,
            margin
        ),
        Role::Run
    );
}

/// **A standby is untouched by the margin** — it has no active role.
#[test]
fn the_margin_does_not_touch_a_standby() {
    assert_eq!(
        role_of(WorkloadClass::SingleWriter, None, 1, 0, NOW, 20_000),
        Role::Run
    );
}

/// **A freshly granted lease carries** — and this test expressly says
/// **nothing** about the steady state.
///
/// It checks `role_of` at **one** point in time: immediately after the
/// granting. That is a meaningful statement about the function and was once the
/// substantiation for an ordering condition that did not carry — here stood
///
/// ```text
/// assert!(margin_holds(12_000), "the defaults have to satisfy the condition");
/// ```
///
/// and with this line the margin from "interval 10 s + grace period 2 s"
/// counted as bearable. Measured, a healthy single writer thereby flapped two
/// thirds of the time (ADR-0076): the remaining time falls in the cycle down to
/// `lease/2 − tick`, and above that the holder fences in **every** round.
///
/// The line is withdrawn. What substantiates the cycle is
/// [`a_holder_never_fences_across_a_renewal_cycle`] — **an assurance at one
/// point in time is no substantiation over a cycle.**
#[test]
fn a_freshly_granted_lease_must_survive_the_margin() {
    let lease = tg_model::lease::LEASE_MILLIS;

    // A margin just under the deadline carries **at this point in time** — and
    // `margin_holds` refuses it nevertheless, because it does not survive the
    // cycle. The difference is the subject of this test.
    assert_eq!(
        role_of(
            WorkloadClass::SingleWriter,
            Some(held(NOW + lease)),
            0,
            0,
            NOW,
            lease - 1
        ),
        Role::Run,
        "immediately after the granting every margin under the deadline carries"
    );
    assert!(
        !tg_model::lease::margin_holds(lease - 1),
        "bearable it is not thereby — that is the gap ADR-0076 closes"
    );

    // And the margin from ADR-0076 carries in both.
    let margin = tg_model::lease::FENCE_MARGIN_MILLIS;
    assert!(tg_model::lease::margin_holds(margin));
    assert_eq!(
        role_of(
            WorkloadClass::SingleWriter,
            Some(held(NOW + lease)),
            0,
            0,
            NOW,
            margin
        ),
        Role::Run,
    );
}

/// **The margin has to be smaller than the remaining time in the valley**
/// (ADR-0076).
///
/// The condition from ADR-0064 determination 7 read "detection latency +
/// stopping time < lease deadline" and was **necessary and not sufficient**.
/// Measured, a healthy single writer with the defaults counted as fenced two
/// thirds of the time:
///
/// - the leader renews only at a remaining time of `≤ lease/2` — every renewal
///   is a log entry ADR-0020 keeps forever;
/// - it notices that at the earliest at the next tick, so in the steady state
///   the remaining time falls down to `lease/2 − tick`;
/// - the holder fences at `remaining time ≤ margin`.
///
/// If the margin is larger than this valley, it fences in **every** cycle
/// without anything having failed.
#[test]
fn the_margin_is_smaller_than_the_valley() {
    let lease = tg_model::lease::LEASE_MILLIS;
    let tick = tg_model::lease::LEASE_TICK_MILLIS;
    let valley = lease / 2 - tick;

    // The last bearable margin carries, the first unbearable one does not —
    // both directions, because an off-by-one once sat here.
    assert!(tg_model::lease::margin_holds(valley - 1));
    assert!(!tg_model::lease::margin_holds(valley));

    // And the **old** condition would be green here: it compared against the
    // whole deadline. The margin the agent formed with the defaults (interval
    // 10 s + grace period 2 s) lies below it and above the valley.
    assert!(12_000 < lease, "the old condition was satisfied");
    assert!(
        !tg_model::lease::margin_holds(12_000),
        "the margin from the reconcile interval must no longer carry"
    );
}

/// **A holder never fences across a whole renewal cycle** — the
/// substantiation a test at one point in time cannot give (ADR-0076,
/// determination 7).
///
/// What was measured is re-enacted: the granting, the leader's tick, the rule
/// "only in the second half", and a holder that evaluates close to its
/// threshold. Over 100 seconds no point in time may yield `Fence`.
///
/// The slice arrives **immediately** here: it arises as soon as the log moves
/// (ADR-0040). What the test thereby checks is the arithmetic between the
/// valley and the margin — and that is the cause of the finding.
#[test]
fn a_holder_never_fences_across_a_renewal_cycle() {
    let lease = tg_model::lease::LEASE_MILLIS;
    let tick = tg_model::lease::LEASE_TICK_MILLIS;
    let margin = tg_model::lease::FENCE_MARGIN_MILLIS;

    let fenced_at = |margin: u64| -> Option<u64> {
        // Granted at t = 0, as the leader does it on a tick.
        let mut expires = lease;
        let mut first = None;
        for step in 0..=1000_u64 {
            let now = step * 100;
            // The leader: on every tick, and only in the second half.
            if now % tick == 0 && expires.saturating_sub(now) <= lease / 2 {
                expires = now + lease;
            }
            // The holder: it wakes close to its threshold (ADR-0076,
            // determination 1), so evaluation happens here on a fine grid —
            // every point in time has to carry.
            if role_of(
                WorkloadClass::SingleWriter,
                Some(held(NOW + now + (expires - now))),
                0,
                0,
                NOW + now,
                margin,
            ) == Role::Fence
                && first.is_none()
            {
                first = Some(now);
            }
        }
        first
    };

    assert_eq!(
        fenced_at(margin),
        None,
        "the margin from ADR-0076 must never fence in the steady state"
    );

    // **The counter-check, and it is the measured finding**: the old margin
    // from the reconcile interval fences — and already in the first cycle.
    let old = fenced_at(12_000).expect("the old margin has to fence");
    assert!(
        old < lease,
        "the old margin fences in the first cycle, not only later: {old}"
    );
}

/// **A lease that reaches further than a lease can reach is not carried**
/// (ADR-0078, determination 3).
///
/// It is granted for `LEASE_MILLIS` (ADR-0064). If it reaches further than
/// twice that in **this** node's time, its clock lies at least a whole lease
/// behind the leader's — that is, five times the safety margin (ADR-0076) —,
/// and the calculation on which the active role rests no longer applies: the
/// node would hold the role while the leader has long passed it on. **Two
/// writers** on one volume, and precisely that is what this lease prevents.
///
/// The direction is the safe one: fencing happens, believing does not.
#[test]
fn a_lease_reaching_further_than_a_lease_can_is_not_trusted() {
    let now = 1_000_000;
    let implausible = Held {
        epoch: 7,
        expires_at: now + 2 * LEASE_MILLIS + 1,
    };

    assert_eq!(
        role_of(
            WorkloadClass::SingleWriter,
            Some(implausible),
            0,
            0,
            now,
            FENCE_MARGIN_MILLIS,
        ),
        Role::Fence,
        "a lease from a far-running-ahead clock was carried"
    );
}

/// **And the bound is generous, deliberately.**
///
/// That is the half of the assurance: a tight bolt would take the role from a
/// **healthy** single writer. The estimation error is real — the time since the
/// granting is unknown, and the leader renews in the second half (ADR-0076) —,
/// so a lease that reaches exactly one lease far has to carry as a matter of
/// course.
///
/// Without this test a bolt that refuses **every** lease would be just as
/// green, and no single writer would start up any more.
#[test]
fn a_plausible_lease_still_runs() {
    let now = 1_000_000;
    for reach in [1, LEASE_MILLIS, 2 * LEASE_MILLIS] {
        assert_eq!(
            role_of(
                WorkloadClass::SingleWriter,
                Some(Held {
                    epoch: 7,
                    expires_at: now + reach,
                }),
                0,
                0,
                now,
                FENCE_MARGIN_MILLIS,
            ),
            if reach > FENCE_MARGIN_MILLIS {
                Role::Run
            } else {
                Role::Fence
            },
            "a lease that reaches {reach} ms far was judged wrongly"
        );
    }
}

/// **The observed clock skew is a lower bound** (ADR-0078, determination 4).
///
/// It is formed from `expires_at − now − LEASE`, and the time since the
/// granting subtracts from it: it is unknown and positive. The value thereby
/// **underestimates**, and that is the right direction for a number somebody
/// puts an alert rule on — it never claims more skew than there is.
///
/// Both directions in one test: a fresh lease without skew yields **zero** and
/// not "a little". Without this half a computation that always reports
/// something would be just as green.
#[test]
fn the_observed_skew_is_a_lower_bound() {
    let now = 1_000_000;

    assert_eq!(
        skew_at(now, now + LEASE_MILLIS),
        0,
        "a fresh lease without skew reported one"
    );
    assert_eq!(
        skew_at(now, now + LEASE_MILLIS - 5_000),
        0,
        "a half-expired lease reported a negative skew"
    );
    assert_eq!(
        skew_at(now, now + LEASE_MILLIS + 4_000),
        4_000,
        "the skew was not recognized"
    );
}

// ------------------------------------------- The promotion (ADR-0111)

/// **The roles swap with the decree.**
///
/// Both directions in one test, because the statement is one about the
/// **pair**: after a promotion the one waits for its lease and the other runs
/// warm — and before, exactly the other way round. Two separate tests would let
/// through the case in which **both** do the same.
#[test]
fn promoting_swaps_which_instance_waits_for_the_lease() {
    // Before: the zeroth is the designated active one.
    assert_eq!(
        role_of(WorkloadClass::SingleWriter, None, 0, 0, NOW, 0),
        Role::Wait
    );
    assert_eq!(
        role_of(WorkloadClass::SingleWriter, None, 1, 0, NOW, 0),
        Role::Run
    );

    // Afterwards: exactly one thing different.
    assert_eq!(
        role_of(WorkloadClass::SingleWriter, None, 0, 1, NOW, 0),
        Role::Run,
        "the relieved instance is a warm standby and runs (ADR-0010)"
    );
    assert_eq!(
        role_of(WorkloadClass::SingleWriter, None, 1, 1, NOW, 0),
        Role::Wait,
        "the promoted instance does not start up without a lease (ADR-0064)"
    );
}

/// **The promoted instance fences itself, the relieved one does not.**
///
/// The self-fence hangs on the role and not on the number — otherwise the wrong
/// one would fence after a promotion.
#[test]
fn only_the_promoted_instance_fences() {
    let expired = Some(Held {
        epoch: 7,
        expires_at: NOW,
    });

    assert_eq!(
        role_of(WorkloadClass::SingleWriter, expired, 1, 1, NOW, 0),
        Role::Fence
    );
    assert_eq!(
        role_of(WorkloadClass::SingleWriter, expired, 0, 1, NOW, 0),
        Role::Run,
        "a standby does not fence — it does not hold the role at all"
    );
}

/// **A replicated workload stays untouched** (determination 8).
///
/// The decree applies to single writers; for everything else it is without
/// effect, whatever number stands there.
#[test]
fn a_replicated_workload_ignores_the_decree() {
    for active in [0, 1, 7] {
        assert_eq!(
            role_of(WorkloadClass::Replicated, None, 0, active, NOW, 0),
            Role::Run
        );
    }
}
