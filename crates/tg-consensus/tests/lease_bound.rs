//! **A lease cannot apply longer than `LEASE`.**
//!
//! # Why the state machine checks this
//!
//! Because a lease leaves the state again **only over `RemoveWorkload`** —
//! measured, the only place in the tree that calls `leases.remove`. There is
//! no command that lifts a lease directly; the way back is to remove the
//! workload. A single deadline of ten years would thereby hold the active
//! role permanently at its holder.
//!
//! The first witness here shows exactly this outcome — **without** the bolt it
//! would be green, and that is the point.
//!
//! # Deterministic, without a clock
//!
//! `now` and `expires_at` both stand in the command, so every replica computes
//! the same. A local clock in the `apply` would let the replicas drift apart,
//! because each would read its own idea of the current time instead of the
//! value carried in the command.

use tg_consensus::state::ClusterState;
use tg_model::command::{Command, Outcome, Rejection, UtcMillis};
use tg_model::lease::LEASE_MILLIS;

/// One single writer and two nodes — the minimum for a role change.
fn populated() -> ClusterState {
    let mut state = ClusterState::default();
    for node in ["node-1", "node-2"] {
        let applied = state.apply(&Command::UpsertNode {
            name: node.to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r7".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        });
        assert_eq!(applied, Outcome::Applied, "the setup must stand");
    }
    let applied = state.apply(&Command::UpsertWorkload {
        document: SINGLE_WRITER.to_owned(),
    });
    assert_eq!(applied, Outcome::Applied, "the setup must stand");
    state
}

const SINGLE_WRITER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="ledger" kind="service" class="single-writer">
    <image reference="example.com/ledger:1"/>
  </workload>
</workloads>"#;

/// **The outcome the bolt is built against.**
///
/// A grant with a deadline of ten years, then the attempt to give the role to
/// another node. Without the bolt `LeaseHeld` would stand here until the end of
/// the deadline — an active role stuck on a node that may long be gone.
#[test]
fn a_runaway_lease_cannot_lock_the_active_role() {
    let mut state = populated();
    let now = UtcMillis::new(1_000_000);
    let decade = UtcMillis::new(now.get() + 10 * 365 * 24 * 60 * 60 * 1_000);

    let outcome = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now,
        expires_at: decade,
    });

    match outcome {
        Outcome::Rejected(Rejection::ImplausibleLease {
            workload,
            granted_millis,
            limit_millis,
        }) => {
            assert_eq!(workload, "ledger");
            assert_eq!(limit_millis, LEASE_MILLIS);
            assert!(granted_millis > LEASE_MILLIS);
        }
        other => panic!("a deadline of ten years was accepted: {other:?}"),
    }

    // **And the place stayed free.** That is the actual assurance: the rejection
    // is of use only if another node can get the role afterwards.
    let second = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-2".to_owned(),
        now,
        expires_at: UtcMillis::new(now.get() + LEASE_MILLIS),
    });
    assert!(
        matches!(second, Outcome::LeaseGranted { .. }),
        "after the rejection the role must be grantable: {second:?}"
    );
}

/// **The limit is inclusive** — exactly `LEASE` goes through.
///
/// The scheduler forms `expires_at = now + LEASE` from **one** reading; an
/// exclusive comparison would thereby refuse the normal case.
#[test]
fn exactly_one_lease_is_allowed_and_one_millisecond_more_is_not() {
    let now = UtcMillis::new(500);

    let mut state = populated();
    let exact = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now,
        expires_at: UtcMillis::new(now.get() + LEASE_MILLIS),
    });
    assert!(
        matches!(exact, Outcome::LeaseGranted { .. }),
        "exactly LEASE is the normal case: {exact:?}"
    );

    // **Only one thing different**, to isolate the boundary: one millisecond.
    let mut state = populated();
    let over = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now,
        expires_at: UtcMillis::new(now.get() + LEASE_MILLIS + 1),
    });
    assert!(
        matches!(over, Outcome::Rejected(Rejection::ImplausibleLease { .. })),
        "one millisecond over LEASE must be refused: {over:?}"
    );
}

/// **The renewal is the frequent path and is checked likewise.**
///
/// A grant happens only at every role change, while `renew_lease` runs every
/// five seconds per single writer. If only the grant checked the deadline and
/// `renew_lease` set `expires_at` unseen, the bolt would guard the rare path
/// and leave the frequent one open.
#[test]
fn a_renewal_cannot_stretch_the_lease_either() {
    let mut state = populated();
    let now = UtcMillis::new(1_000);
    let granted = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now,
        expires_at: UtcMillis::new(now.get() + LEASE_MILLIS),
    });
    assert!(matches!(granted, Outcome::LeaseGranted { .. }));

    let later = UtcMillis::new(now.get() + LEASE_MILLIS / 2);
    let stretched = state.apply(&Command::RenewLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: later,
        expires_at: UtcMillis::new(later.get() + 10 * LEASE_MILLIS),
    });
    assert!(
        matches!(
            stretched,
            Outcome::Rejected(Rejection::ImplausibleLease { .. })
        ),
        "a renewal by a factor of ten was accepted: {stretched:?}"
    );

    // **The counter-check:** the ordinary renewal holds. Without it the run
    // above would merely prove that something or other is refused.
    let ordinary = state.apply(&Command::RenewLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: later,
        expires_at: UtcMillis::new(later.get() + LEASE_MILLIS),
    });
    assert!(
        matches!(ordinary, Outcome::LeaseRenewed { .. }),
        "the ordinary renewal must go through: {ordinary:?}"
    );
}

/// **A deadline in the past is expressly *not* refused.**
///
/// It costs an epoch and nothing else — the next pass grants anew. A bolt
/// downwards would be a **second** rule beside the upper bound this module
/// enforces, and adding one silently would mean deciding on it in passing
/// rather than as a deliberate, documented choice.
#[test]
fn a_lease_that_is_already_over_is_not_this_rules_business() {
    let mut state = populated();
    let outcome = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(10_000),
        expires_at: UtcMillis::new(5_000),
    });

    assert!(
        matches!(outcome, Outcome::LeaseGranted { .. }),
        "the upper-bound check has nothing to say about a deadline in the past: {outcome:?}"
    );
}

/// **The same input, the same verdict** — the bolt reads no clock.
///
/// Both numbers stand in the command. Were it to read the local time instead,
/// the same log would yield two different states on two replicas, since each
/// would apply the command against its own clock instead of the values it
/// carries.
#[test]
fn the_verdict_comes_from_the_command_and_not_from_a_clock() {
    let command = Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(7),
        expires_at: UtcMillis::new(7 + LEASE_MILLIS * 3),
    };

    let mut first = populated();
    let mut second = populated();
    std::thread::sleep(std::time::Duration::from_millis(5));

    assert_eq!(
        format!("{:?}", first.apply(&command)),
        format!("{:?}", second.apply(&command)),
        "two replicas must judge the same"
    );
}
