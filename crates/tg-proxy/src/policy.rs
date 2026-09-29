//! The locally enforced reachability policy (ADR-0025, ADR-0019).
//!
//! # Three properties, and why each of them is built this way
//!
//! **deny-by-default.** The starting state is "nobody may talk with nobody".
//! That is no switch but the empty set: a fresh instance has no edges, and
//! without an edge there is no permission. An error in the delivery thereby
//! leads to less traffic, never to more.
//!
//! **Enforced locally.** [`PolicyCache::allows`] asks nobody. ADR-0019 forbids
//! the control-plane call in the hot path of workload communication, and this
//! is precisely that place: it lies in every connection setup.
//!
//! **Fail-static.** The cache has **no expiry date**. If the control plane is
//! gone, the last known policy applies on -- not fail-open and expressly not
//! fail-closed on existing traffic (ADR-0025). The backstop against an
//! identity that ought to be gone is not here but in the SVID TTL: the
//! certificate expires after 15 minutes (ADR-0014), and there is no way past
//! that.
//!
//! # The revocation window
//!
//! An edge withdrawal must end **existing** connections too. Two ways lead
//! there, and both are built:
//!
//! 1. **The new state.** If a snapshot with a higher version arrives, every
//!    connection is re-evaluated at the next look. That is the normal case and
//!    practically immediate.
//! 2. **The window.** If nothing arrives at all, re-evaluation nevertheless
//!    happens at the latest after the target time from ADR-0014 (~60 s). That
//!    is the case for which the window exists -- not normal operation but the
//!    failure of the delivery.
//!
//! # What is **not** decided here
//!
//! ADR-0025 names authorization at L4 -- "identity **and** port/proto". The
//! command set from phase 5a carries only `from` and `to` on a `may_talk`
//! edge; port and protocol would have to go into the Raft log, and that is a
//! change to the audit substrate (ADR-0020) and none to this file.
//! Authorization therefore happens by identity. The restriction stands in the
//! plan.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use tg_identity::{Role, SpiffeId};

use crate::selector::{Selector, SelectorError};

pub type UnixSeconds = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationWindow {
    pub target: Duration,
    pub staleness: Duration,
}

impl RevocationWindow {
    #[must_use]
    pub fn adr_0014() -> Self {
        Self {
            target: Duration::from_mins(1),
            staleness: Duration::from_mins(15),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Selector {
        edge: String,
        source: SelectorError,
    },
    Stale {
        have: u64,
        offered: u64,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selector { edge, source } => write!(
                f,
                "the edge '{edge}' is not readable: {source}. The previous state \
                 stays in force -- a typo in one edge must not put all the others \
                 out of force"
            ),
            Self::Stale { have, offered } => write!(
                f,
                "the state {offered} is no newer than {have} and is not taken \
                 over -- a state that falls back would let a withdrawn edge come \
                 alive again"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    NoEdge,
    NotAWorkload,
    ForeignTrustDomain,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEdge => f.write_str("no may_talk edge"),
            Self::NotAWorkload => f.write_str("no workload identity"),
            Self::ForeignTrustDomain => f.write_str("a foreign trust domain"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    version: u64,
    edges: BTreeSet<(String, String)>,
}

impl Snapshot {
    pub fn from_edges<I>(version: u64, edges: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        Self {
            version,
            edges: edges.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Edge {
    from: Selector,
    to: Selector,
}

#[derive(Debug)]
pub struct PolicyCache {
    edges: Vec<Edge>,
    version: u64,
    refreshed_at: UnixSeconds,
    window: RevocationWindow,
}

impl PolicyCache {
    #[must_use]
    pub fn new(window: RevocationWindow) -> Self {
        Self {
            edges: Vec::new(),
            version: 0,
            refreshed_at: 0,
            window,
        }
    }

    pub fn apply(&mut self, snapshot: &Snapshot, at: UnixSeconds) -> Result<(), PolicyError> {
        if snapshot.version <= self.version && self.version != 0 {
            return Err(PolicyError::Stale {
                have: self.version,
                offered: snapshot.version,
            });
        }

        let mut edges = Vec::with_capacity(snapshot.edges.len());
        for (from, to) in &snapshot.edges {
            let parse = |raw: &str| {
                Selector::parse(raw).map_err(|source| PolicyError::Selector {
                    edge: format!("{from} -> {to}"),
                    source,
                })
            };
            edges.push(Edge {
                from: parse(from)?,
                to: parse(to)?,
            });
        }

        self.edges = edges;
        self.version = snapshot.version;
        self.refreshed_at = at;

        Ok(())
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn refreshed_at(&self) -> UnixSeconds {
        self.refreshed_at
    }

    #[must_use]
    pub fn age(&self, now: UnixSeconds) -> Duration {
        let seconds = now.saturating_sub(self.refreshed_at).max(0);

        Duration::from_secs(u64::try_from(seconds).unwrap_or(0))
    }

    #[must_use]
    pub fn is_stale(&self, now: UnixSeconds) -> bool {
        self.age(now) >= self.window.staleness
    }

    #[must_use]
    pub fn allows(&self, from: &SpiffeId, to: &SpiffeId) -> Decision {
        if from.role() != Role::Workload || to.role() != Role::Workload {
            return Decision::Deny(DenyReason::NotAWorkload);
        }
        if from.trust_domain() != to.trust_domain() {
            return Decision::Deny(DenyReason::ForeignTrustDomain);
        }

        if self
            .edges
            .iter()
            .any(|edge| edge.from.matches(from) && edge.to.matches(to))
        {
            return Decision::Allow;
        }

        Decision::Deny(DenyReason::NoEdge)
    }

    // **`allows_within` stood here** -- the same check against a *known
    // local* trust domain, and it fell away without replacement. It had no
    // caller and no witness, and `tg_proxy::verify::authorize` makes the same
    // decision: first the role, then the domain against one's own, then the
    // edge.
    //
    // Two ways to one security decision are two opportunities to disagree --
    // and these two **did** already: the one here did **not** check the role,
    // so it would have let a sidecar or a node through where `authorize`
    // refuses. Whoever needs it again calls the place that enforces it.
    //
    // What `allows` achieves beside it is something else and stays: that the
    // **two IDs** stem from the same domain (ADR-0025 knows no federation).
    // Only somebody who knows *our* domain can pin against it -- and that is
    // the verifier.

    #[must_use]
    pub fn review(&self, connection: &Established, now: UnixSeconds) -> Review {
        let due_at =
            connection.checked_at + i64::try_from(self.window.target.as_secs()).unwrap_or(i64::MAX);
        let changed = self.version != connection.version_seen;

        if !changed && now < due_at {
            return Review::Keep { next_check: due_at };
        }

        let (from, to) = connection.ordered();
        match self.allows(from, to) {
            Decision::Allow => Review::Keep {
                next_check: now + i64::try_from(self.window.target.as_secs()).unwrap_or(i64::MAX),
            },
            Decision::Deny(reason) => Review::Close { reason },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Established {
    pub local: SpiffeId,
    pub peer: SpiffeId,
    pub direction: Direction,
    pub version_seen: u64,
    pub checked_at: UnixSeconds,
}

impl Established {
    #[must_use]
    fn ordered(&self) -> (&SpiffeId, &SpiffeId) {
        match self.direction {
            Direction::Inbound => (&self.peer, &self.local),
            Direction::Outbound => (&self.local, &self.peer),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Review {
    Keep {
        next_check: UnixSeconds,
    },
    Close {
        reason: DenyReason,
    },
}

#[derive(Debug)]
pub enum Refresh {
    Applied,
    Unreadable {
        detail: String,
    },
    Malformed {
        detail: String,
    },
    Rejected {
        detail: String,
    },
}

#[must_use]
pub fn refresh(
    policy: &crate::verify::SharedPolicy,
    path: &std::path::Path,
    version: u64,
    at: UnixSeconds,
) -> Refresh {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            return Refresh::Unreadable {
                detail: err.to_string(),
            };
        }
    };

    let edges = match crate::options::edges_from_text(&text) {
        Ok(edges) => edges,
        Err(err) => {
            return Refresh::Malformed {
                detail: err.to_string(),
            };
        }
    };

    match policy.apply(&Snapshot::from_edges(version, edges), at) {
        Ok(()) => Refresh::Applied,
        Err(err) => Refresh::Rejected {
            detail: err.to_string(),
        },
    }
}

pub fn report(policy: &crate::verify::SharedPolicy, at: UnixSeconds) {
    let Ok(cache) = policy.handle().read() else {
        return;
    };

    #[expect(
        clippy::cast_precision_loss,
        reason = "a Prometheus metric is an f64; it would become imprecise \
                  beyond 2^53 seconds"
    )]
    let refreshed_at = cache.refreshed_at() as f64;
    metrics::gauge!(tg_telemetry::names::PROXY_POLICY_REFRESHED_AT).set(refreshed_at);

    if cache.is_stale(at) {
        // `warn!` and not `error!`: the sidecar carries on working and
        // enforces what it last knew -- that is the assurance, not the error
        // (ADR-0019). The error is that nobody delivers any more.
        tracing::warn!(
            age_seconds = cache.age(at).as_secs(),
            version = cache.version(),
            "the policy state counts as stale -- it is enforced on"
        );
    }
}
