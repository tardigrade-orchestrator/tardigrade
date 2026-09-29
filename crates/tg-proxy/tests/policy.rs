//! Reachability authorization (ADR-0025, ADR-0019 -- phase 8a).
//!
//! mTLS answers **who** the peer is. This layer answers whether they may talk.
//! ADR-0025 names three properties, and all three stand on the test rig here:
//!
//! - **deny-by-default** -- without an edge no traffic,
//! - **enforced locally** -- no control-plane call per connection (ADR-0019),
//! - **fail-static** -- if the control plane is gone, the last known policy
//!   applies on. Not fail-open, and expressly **not** fail-closed on existing
//!   traffic.

use std::time::Duration;

use tg_identity::{SpiffeId, TrustDomain};
use tg_proxy::policy::{
    Decision, DenyReason, Direction, Established, PolicyCache, PolicyError, Review,
    RevocationWindow, Snapshot,
};

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

fn id(name: &str) -> SpiffeId {
    SpiffeId::for_workload(&domain(), name).expect("the ID")
}

fn window() -> RevocationWindow {
    // The numbers from ADR-0014: ~60 s target, backstop = SVID TTL.
    RevocationWindow::adr_0014()
}

fn cache_with(edges: &[(&str, &str)]) -> PolicyCache {
    let mut cache = PolicyCache::new(window());
    let snapshot = Snapshot::from_edges(
        1,
        edges
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned())),
    );
    cache.apply(&snapshot, 1_000).expect("the snapshot");

    cache
}

/// **Without an edge no traffic.** A fresh instance's starting state is
/// "nobody may talk with nobody".
#[test]
fn an_empty_cache_denies_everything() {
    let cache = PolicyCache::new(window());

    assert_eq!(
        cache.allows(&id("api"), &id("ledger")),
        Decision::Deny(DenyReason::NoEdge),
        "deny-by-default is the starting state, not a setting"
    );
}

/// An edge permits exactly its own direction.
#[test]
fn an_edge_allows_exactly_its_own_direction() {
    let cache = cache_with(&[("api", "ledger")]);

    assert_eq!(cache.allows(&id("api"), &id("ledger")), Decision::Allow);
    assert_eq!(
        cache.allows(&id("ledger"), &id("api")),
        Decision::Deny(DenyReason::NoEdge),
        "may_talk is directed (ADR-0025) -- the reverse direction is an edge of its own"
    );
}

/// A third party does not come along merely because two others may talk.
#[test]
fn an_unrelated_workload_is_not_covered_by_someone_elses_edge() {
    let cache = cache_with(&[("api", "ledger")]);

    assert_eq!(
        cache.allows(&id("attacker"), &id("ledger")),
        Decision::Deny(DenyReason::NoEdge)
    );
}

/// A node ID is no workload and may do nothing over these edges.
///
/// The role separation from ADR-0006 holds here too: a node is called
/// `/node/api`, a workload `/workload/api`, and the edge `api -> ledger`
/// applies only to the workload.
#[test]
fn a_node_identity_does_not_inherit_a_workloads_edges() {
    let cache = cache_with(&[("api", "ledger")]);
    let node = SpiffeId::for_node(&domain(), "api").expect("the ID");

    assert_eq!(
        cache.allows(&node, &id("ledger")),
        Decision::Deny(DenyReason::NotAWorkload)
    );
}

/// A foreign trust domain is refused, even when the name fits.
#[test]
fn a_foreign_trust_domain_is_denied() {
    let cache = cache_with(&[("api", "ledger")]);
    let foreign = SpiffeId::for_workload(
        &TrustDomain::new("elsewhere.example").expect("the domain"),
        "api",
    )
    .expect("the ID");

    assert_eq!(
        cache.allows(&foreign, &id("ledger")),
        Decision::Deny(DenyReason::ForeignTrustDomain)
    );
}

/// The prefix selector bundles edges without maintaining them individually.
#[test]
fn a_prefix_selector_covers_a_family_of_names() {
    let cache = cache_with(&[("ledger-*", "audit")]);

    assert_eq!(
        cache.allows(&id("ledger-read"), &id("audit")),
        Decision::Allow
    );
    assert_eq!(
        cache.allows(&id("ledger-write"), &id("audit")),
        Decision::Allow
    );
    assert_eq!(
        cache.allows(&id("ledgerless"), &id("audit")),
        Decision::Deny(DenyReason::NoEdge),
        "the hyphen belongs to the prefix -- 'ledgerless' does not begin with \
         'ledger-'"
    );
    assert_eq!(
        cache.allows(&id("other"), &id("audit")),
        Decision::Deny(DenyReason::NoEdge)
    );
}

/// **The prefix is a string, no name component** -- and that is the place at
/// which an operator cuts themselves.
///
/// `ledger*` without a hyphen covers `ledgerless` too, which need have nothing
/// to do with the ledger services. The test holds that fast so that nobody
/// takes it for an error and "repairs" it: a prefix rule that held at name
/// boundaries would first have to define what a name boundary is -- and that
/// is a hierarchy ADR-0006 did not give the IDs.
#[test]
fn a_prefix_without_a_separator_reaches_further_than_one_might_expect() {
    let cache = cache_with(&[("ledger*", "audit")]);

    assert_eq!(
        cache.allows(&id("ledger-read"), &id("audit")),
        Decision::Allow
    );
    assert_eq!(
        cache.allows(&id("ledgerless"), &id("audit")),
        Decision::Allow,
        "a pure string prefix, documented in tg_proxy::selector"
    );
}

/// The complete SPIFFE ID is permissible as a selector -- and means exactly it.
#[test]
fn a_full_spiffe_id_is_an_exact_selector() {
    let cache = cache_with(&[("spiffe://cluster.local/workload/api", "ledger")]);

    assert_eq!(cache.allows(&id("api"), &id("ledger")), Decision::Allow);
    assert_eq!(
        cache.allows(&id("api-2"), &id("ledger")),
        Decision::Deny(DenyReason::NoEdge)
    );
}

/// A selector that is neither a name nor an ID nor a prefix is reported at
/// the take-over of the snapshot -- not at the first connection attempt.
///
/// A silently ignored selector would be an edge the operator believes they set
/// and that does not exist.
#[test]
fn an_unparsable_selector_is_reported_when_the_snapshot_is_taken() {
    let mut cache = PolicyCache::new(window());
    let snapshot = Snapshot::from_edges(1, [("Capital Letters".to_owned(), "ledger".to_owned())]);

    let err = cache.apply(&snapshot, 1_000).expect_err("unusable");

    assert!(matches!(err, PolicyError::Selector { .. }), "{err}");
}

/// A refused snapshot leaves the old state **untouched**.
///
/// Otherwise a typo in one edge would be an outage of all the others.
#[test]
fn a_rejected_snapshot_leaves_the_previous_one_in_force() {
    let mut cache = cache_with(&[("api", "ledger")]);
    let broken = Snapshot::from_edges(2, [("!!".to_owned(), "ledger".to_owned())]);

    assert!(cache.apply(&broken, 2_000).is_err());
    assert_eq!(
        cache.allows(&id("api"), &id("ledger")),
        Decision::Allow,
        "the old state must stay standing"
    );
    assert_eq!(cache.version(), 1);
}

/// An older snapshot is not taken over.
///
/// The projection can arrive delayed; a state that falls back would mean
/// letting a withdrawn edge come alive again.
#[test]
fn an_older_snapshot_is_not_applied() {
    let mut cache = cache_with(&[("api", "ledger")]);
    let older = Snapshot::from_edges(0, []);

    assert!(matches!(
        cache.apply(&older, 2_000),
        Err(PolicyError::Stale { .. })
    ));
    assert_eq!(cache.allows(&id("api"), &id("ledger")), Decision::Allow);
}

// ------------------------------------------------------------ fail-static

/// **The acceptance criterion "control plane gone" at the policy layer:** a
/// stale policy applies on.
///
/// There is deliberately **no** expiry date on the cache. ADR-0025: "the last
/// known good policy stays valid". The backstop against an identity that ought
/// to be gone is the SVID TTL -- the certificate expires, and that is a bound
/// nobody has to set here.
#[test]
fn a_stale_cache_keeps_enforcing_what_it_last_knew() {
    let cache = cache_with(&[("api", "ledger")]);
    let much_later = 1_000 + 30 * 24 * 3_600;

    assert!(
        cache.age(much_later) > Duration::from_hours(24),
        "the cache is to know its age"
    );
    assert!(cache.is_stale(much_later), "and report it too");

    assert_eq!(
        cache.allows(&id("api"), &id("ledger")),
        Decision::Allow,
        "fail-static: stale does not mean invalid (ADR-0019/0025)"
    );
    assert_eq!(
        cache.allows(&id("ledger"), &id("api")),
        Decision::Deny(DenyReason::NoEdge),
        "and stale means fail-open even less"
    );
}

// ----------------------------------------------------------- revocation

/// **An edge withdrawn: an existing connection is ended.**
///
/// The withdrawal takes effect as soon as the new state is there -- the
/// connection is closed at the next look, not only at the SVID's expiry.
#[test]
fn revoking_an_edge_closes_an_established_connection() {
    let mut cache = cache_with(&[("api", "ledger")]);
    let live = Established {
        local: id("ledger"),
        peer: id("api"),
        direction: Direction::Inbound,
        version_seen: cache.version(),
        checked_at: 1_000,
    };

    assert!(matches!(cache.review(&live, 1_001), Review::Keep { .. }));

    cache
        .apply(&Snapshot::from_edges(2, []), 1_002)
        .expect("the withdrawal");

    assert_eq!(
        cache.review(&live, 1_003),
        Review::Close {
            reason: DenyReason::NoEdge
        },
        "a state with a new version is re-evaluated immediately"
    );
}

/// If the new state does not arrive at all, the **window** bites: at the
/// latest after the target time from ADR-0014 re-evaluation happens anyway.
///
/// That is the case the window exists for at all -- not the normal case but
/// the one in which the delivery has failed.
#[test]
fn the_window_forces_a_recheck_even_without_a_new_snapshot() {
    let cache = cache_with(&[("api", "ledger")]);
    let live = Established {
        local: id("ledger"),
        peer: id("api"),
        direction: Direction::Inbound,
        version_seen: cache.version(),
        checked_at: 1_000,
    };

    let Review::Keep { next_check } = cache.review(&live, 1_000) else {
        panic!("permitted must stay permitted");
    };

    assert_eq!(
        next_check - 1_000,
        i64::try_from(window().target.as_secs()).expect("fits"),
        "the next check lies one window further (ADR-0014: ~60 s)"
    );
}

/// **Existing permitted traffic does not break** when the control plane is
/// gone -- the second acceptance criterion from "control plane gone".
///
/// The connection is checked, again and again, and stays in existence every
/// time. An abort after the expiry of a deadline would be fail-closed and
/// precisely what ADR-0019 forbids.
#[test]
fn established_allowed_traffic_survives_a_missing_control_plane() {
    let cache = cache_with(&[("api", "ledger")]);
    let mut live = Established {
        local: id("ledger"),
        peer: id("api"),
        direction: Direction::Inbound,
        version_seen: cache.version(),
        checked_at: 1_000,
    };

    // An hour without a single new snapshot.
    let mut now = 1_000;
    for _ in 0..60 {
        now += 60;
        match cache.review(&live, now) {
            Review::Keep { next_check } => live.checked_at = next_check.max(now),
            other @ Review::Close { .. } => {
                panic!("the connection was ended at {now}: {other:?}")
            }
        }
    }
}

/// The direction is evaluated at the review just as at the setup.
///
/// Without that a connection's reverse direction would suddenly be permitted
/// after the first window.
#[test]
fn the_direction_is_honoured_on_review_as_well() {
    let cache = cache_with(&[("api", "ledger")]);
    let outbound_the_wrong_way = Established {
        local: id("ledger"),
        peer: id("api"),
        direction: Direction::Outbound,
        version_seen: cache.version(),
        checked_at: 1_000,
    };

    assert_eq!(
        cache.review(&outbound_the_wrong_way, 2_000),
        Review::Close {
            reason: DenyReason::NoEdge
        },
        "ledger -> api does not exist"
    );
}

/// **The reported state is a point in time, no age** (ADR-0025).
///
/// It was an age, and that is the construction against which this project
/// itself wrote down the rule at `tg_node_last_report`: *an age must be
/// carried forward by somebody and is wrong between two carryings-forward --
/// and in the dangerous direction, it looks fresh.*
///
/// Measured, precisely that was the case: `report_age` was called **only**
/// from the refresh loop. If the task dies, the number freezes on its last
/// value -- sixty seconds, forever, and a sidecar that has not read its edges
/// for days looks like one that has just read them.
///
/// The assertion is therefore the property that distinguishes a point in time
/// from an age: **it does not change when only the clock runs on.**
#[test]
fn the_reported_state_does_not_move_with_the_clock() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let refreshed_at = 1_000_i64;
    let policy = tg_proxy::verify::SharedPolicy::new(cache_with(&[("api", "ledger")]));

    let seen: Vec<f64> = metrics::with_local_recorder(&recorder, || {
        // Report twice, and an hour passes in between -- nothing about the
        // state changes, nothing new came after all.
        for at in [refreshed_at + 5, refreshed_at + 3_600] {
            tg_proxy::policy::report(&policy, at);
        }

        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter_map(|(key, _, _, value)| {
                (key.key().name() == tg_telemetry::names::PROXY_POLICY_REFRESHED_AT)
                    .then_some(value)
            })
            .map(|value| match value {
                DebugValue::Gauge(seen) => seen.into_inner(),
                other => panic!("no gauge: {other:?}"),
            })
            .collect()
    });

    assert!(!seen.is_empty(), "the state must be reported");
    for value in seen {
        // On the **value**, not on the presence.
        assert!(
            (value - 1_000.0).abs() < 1.0,
            "{value} instead of the point in time 1000 -- that is an age, and \
             a frozen writer would thereby look fresh"
        );
    }
}
