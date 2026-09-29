//! The active-role lease, from the node's view (ADR-0010, ADR-0064).
//!
//! The cluster grants it, the node **learns** it in the slice and thereby
//! decides locally whether an instance may carry the active role. This file is
//! exactly that decision and nothing else: a pure function whose inputs are the
//! class, the lease and the **local** clock.
//!
//! # Why locally
//!
//! The self-fence from ADR-0010 has to take effect precisely when the node
//! **cannot** reach the cluster — there it stands on the list of autonomous
//! actions. A deadline only the leader knows would not help the minority side.

use tg_defs::WorkloadClass;

pub const LEASE_SECONDS: i64 = 15;

pub const LEASE_MILLIS: u64 = LEASE_SECONDS.unsigned_abs() * 1_000;

pub const LEASE_TICK_MILLIS: u64 = LEASE_MILLIS / 5;

pub const FENCE_MARGIN_MILLIS: u64 = FENCE_WAKE_FLOOR_MILLIS + FENCE_GRACE_MILLIS;

pub const FENCE_GRACE_MILLIS: u64 = 2_000;

pub const FENCE_WAKE_FLOOR_MILLIS: u64 = 1_000;

#[must_use]
pub const fn margin_holds(margin: u64) -> bool {
    margin < LEASE_MILLIS / 2 - LEASE_TICK_MILLIS
}

const _: () = assert!(
    margin_holds(FENCE_MARGIN_MILLIS),
    "the safety margin has to be smaller than the remaining time in the valley (ADR-0076)"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Held {
    pub epoch: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Run,
    Wait,
    Fence,
}

#[must_use]
pub fn role_of(
    class: WorkloadClass,
    lease: Option<Held>,
    instance: u32,
    active: u32,
    now: u64,
    margin: u64,
) -> Role {
    // **Only single writers, only the active instance** (ADR-0064,
    // determination 8; ADR-0111). A replicated workload has no active role, and
    // a single writer's remaining instances are warm standbys — precisely that
    // is why they can take over quickly (ADR-0010).
    //
    // Here `instance != 0` stood. The zero was one of three places at which it
    // stood as a constant and nowhere in the state; since ADR-0111 an operator
    // says which instance carries the role, and **without a decree it is still
    // the zeroth**. The caller passes the number, because only it has seen the
    // slice.
    if class != WorkloadClass::SingleWriter || instance != active {
        return Role::Run;
    }

    match lease {
        // **A lease that reaches further than a lease can reach is not
        // believed** (ADR-0078, determination 3). It is granted for
        // `LEASE_MILLIS`; if it reaches further than twice that in *this*
        // node's time, its clock lies at least a whole lease behind the
        // leader's — five times the margin —, and the calculation above no
        // longer applies: it would hold the role while the leader passes it on.
        //
        // The bound is **deliberately generous**: the observed skew is only a
        // lower bound (see `skew_at`), and a tight bolt would take the role
        // from a healthy single writer. What is caught is the grotesque case —
        // a machine without time synchronization, a clock put back, a restored
        // VM.
        Some(held) if held.expires_at > now.saturating_add(2 * LEASE_MILLIS) => Role::Fence,
        // `saturating_add`: a margin that exceeds the deadline fences at once —
        // right, and better than an overflow that would let it run forever.
        Some(held) if now.saturating_add(margin) < held.expires_at => Role::Run,
        Some(_) => Role::Fence,
        // No lease means **not** "expired": the node never got the active role.
        // The difference counts for the report — it has fenced nothing.
        None => Role::Wait,
    }
}

#[must_use]
pub const fn skew_at(now: u64, expires_at: u64) -> u64 {
    expires_at.saturating_sub(now).saturating_sub(LEASE_MILLIS)
}
