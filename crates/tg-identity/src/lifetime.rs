//! An SVID's time windows: TTL, rotation lead time, soft-fail grace.
//!
//! The values stand in ADR-0014 ("tight profile"), the ordering conditions too --
//! and here they are **checked**, not presupposed. A configuration that violates
//! them is no tighter setting but a broken one.
//!
//! # The grace belongs to the holder, not to the certificate
//!
//! That is the distinction on which ADR-0019's soft fail hangs and that is easy to
//! build wrongly. The grace does **not** extend the certificate's validity: in the
//! X.509 stands `notAfter`, and a counterpart that checks sees exactly that. What
//! the grace allows is that the **holder** keeps using a just-expired SVID for a
//! short while instead of losing its connections immediately while the rotation
//! catches up.
//!
//! Were it in the certificate, it would be a second validity period -- and the hard
//! expiry ADR-0014 expressly wants enforced would no longer exist.

use std::fmt;
use std::time::Duration;

pub type UnixSeconds = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetime {
    pub ttl: Duration,
    pub rotate_after: Duration,
    pub grace: Duration,
}

pub const SOFT_FAIL_GRACE: Duration = Duration::from_mins(2);

pub const SVID_TTL: Duration = Duration::from_mins(15);

pub const SVID_ROTATE_AFTER: Duration = Duration::from_mins(7);

const _: () = assert!(
    SOFT_FAIL_GRACE.as_secs() * 4 <= SVID_TTL.as_secs(),
    "the soft-fail grace reaches a quarter of the SVID lifetime -- it would be a \
     second validity period, no soft fail (ADR-0014)"
);
const _: () = assert!(
    SVID_ROTATE_AFTER.as_secs() < SVID_TTL.as_secs(),
    "the rotation lead time does not lie before the expiry -- no second attempt \
     was left (ADR-0014)"
);

impl Default for Lifetime {
    fn default() -> Self {
        Self {
            ttl: SVID_TTL,
            rotate_after: SVID_ROTATE_AFTER,
            grace: SOFT_FAIL_GRACE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifetimeError {
    detail: String,
}

impl fmt::Display for LifetimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the time windows are unusable: {}", self.detail)
    }
}

impl std::error::Error for LifetimeError {}

impl Lifetime {
    pub fn validate(self) -> Result<(), LifetimeError> {
        let fail = |detail: String| Err(LifetimeError { detail });

        if self.ttl.is_zero() {
            return fail("the TTL is zero".to_owned());
        }
        if self.rotate_after >= self.ttl {
            return fail(format!(
                "rotation after {:?} does not lie before the expiry ({:?}) -- no \
                 time would be left for a second attempt (ADR-0014)",
                self.rotate_after, self.ttl
            ));
        }
        if self.grace >= self.ttl {
            return fail(format!(
                "the grace ({:?}) reaches the TTL ({:?}) -- it would be a second \
                 validity period, no soft fail (ADR-0014/0019)",
                self.grace, self.ttl
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Fresh,
    Due,
    Grace,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    issued_at: UnixSeconds,
    lifetime: Lifetime,
}

impl Validity {
    #[must_use]
    pub fn issued_at(issued_at: UnixSeconds, lifetime: Lifetime) -> Self {
        Self {
            issued_at,
            lifetime,
        }
    }

    #[must_use]
    pub fn not_before(self) -> UnixSeconds {
        self.issued_at
    }

    #[must_use]
    pub fn not_after(self) -> UnixSeconds {
        self.issued_at + seconds(self.lifetime.ttl)
    }

    #[must_use]
    pub fn state_at(self, now: UnixSeconds) -> State {
        let age = now - self.issued_at;

        if age < seconds(self.lifetime.rotate_after) {
            State::Fresh
        } else if age < seconds(self.lifetime.ttl) {
            State::Due
        } else if age < seconds(self.lifetime.ttl) + seconds(self.lifetime.grace) {
            State::Grace
        } else {
            State::Expired
        }
    }

    #[must_use]
    pub fn is_usable_at(self, now: UnixSeconds) -> bool {
        !matches!(self.state_at(now), State::Expired)
    }

    #[must_use]
    pub fn is_within_certificate_at(self, now: UnixSeconds) -> bool {
        now >= self.not_before() && now < self.not_after()
    }

    #[must_use]
    pub fn should_rotate_at(self, now: UnixSeconds) -> bool {
        !matches!(self.state_at(now), State::Fresh)
    }
}

fn seconds(duration: Duration) -> UnixSeconds {
    UnixSeconds::try_from(duration.as_secs()).unwrap_or(UnixSeconds::MAX)
}
