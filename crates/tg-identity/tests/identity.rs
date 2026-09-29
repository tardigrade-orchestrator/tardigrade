//! The pure logic of the identity (ADR-0006, ADR-0014, phase 7a).
//!
//! Written before the implementation. Three things stand here, and all three are pure
//! functions -- without a clock, without a network, without a disk:
//!
//! 1. **The SPIFFE ID** is derived from the definition, not assigned. ADR-0006:
//!    "registration is automatically derived ... a structural advantage of identity
//!    and orchestration being the same system."
//! 2. **The time windows** (TTL, rotation lead time, soft-fail grace) are the metrics
//!    from ADR-0014 and their ordering conditions.
//! 3. **The attestation** assigns a requesting process to a workload.

use std::time::Duration;

use tg_identity::{Attestation, Lifetime, SpiffeId, TrustDomain, Validity};

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("a valid trust domain")
}

// --- The SPIFFE ID ----------------------------------------------------------

/// The ID follows from the name -- the same definition yields the same ID, on every
/// node and at every time.
#[test]
fn the_id_is_derived_from_the_workload_name() {
    let id = SpiffeId::for_workload(&domain(), "api").expect("a valid name");

    assert_eq!(id.to_string(), "spiffe://cluster.local/workload/api");
    assert_eq!(id.trust_domain().as_str(), "cluster.local");
    assert_eq!(id.workload(), Some("api"));
}

/// Derived twice is twice the same.
#[test]
fn deriving_twice_yields_the_same_id() {
    let first = SpiffeId::for_workload(&domain(), "api").expect("valid");
    let second = SpiffeId::for_workload(&domain(), "api").expect("valid");

    assert_eq!(first, second);
}

/// Different workloads have different IDs, and the trust domain separates two
/// clusters with equal workload names.
#[test]
fn different_workloads_and_domains_yield_different_ids() {
    let api = SpiffeId::for_workload(&domain(), "api").expect("valid");
    let db = SpiffeId::for_workload(&domain(), "db").expect("valid");
    let other = SpiffeId::for_workload(&TrustDomain::new("other.cluster").expect("valid"), "api")
        .expect("valid");

    assert_ne!(api, db);
    assert_ne!(api, other);
}

/// A node likewise gets an ID -- the control plane dogfoods its own system
/// (ADR-0006).
#[test]
fn a_node_has_an_id_of_its_own_shape() {
    let id = SpiffeId::for_node(&domain(), "node-1").expect("valid");

    assert_eq!(id.to_string(), "spiffe://cluster.local/node/node-1");
    assert_eq!(id.workload(), None, "a node is no workload");
}

/// A workload name and a node name do not collide, even when they read the same.
///
/// Without the separation in the path a workload named `node-1` could assume the
/// identity of the node `node-1` -- and thereby its authority to mint SVIDs.
#[test]
fn a_workload_cannot_impersonate_a_node_of_the_same_name() {
    let workload = SpiffeId::for_workload(&domain(), "node-1").expect("valid");
    let node = SpiffeId::for_node(&domain(), "node-1").expect("valid");

    assert_ne!(workload, node);
    assert_ne!(workload.to_string(), node.to_string());
}

/// The ID goes through text and comes back the same -- it travels in the URI SAN.
#[test]
fn an_id_survives_the_round_trip_through_text() {
    let id = SpiffeId::for_workload(&domain(), "api").expect("valid");
    let parsed: SpiffeId = id.to_string().parse().expect("readable");

    assert_eq!(parsed, id);
}

/// Unusable IDs are refused, not bent into shape.
///
/// The decoder reads what stands in a foreign certificate (ADR-0007 builds on that).
/// What it accepts counts as an identity -- that is why every leniency here is a
/// gap.
#[test]
fn hostile_ids_are_rejected() {
    for raw in [
        "",
        "cluster.local/workload/api",
        "https://cluster.local/workload/api",
        "spiffe://",
        "spiffe:///workload/api",
        "spiffe://cluster.local",
        "spiffe://cluster.local/",
        "spiffe://CLUSTER.local/workload/api",
        "spiffe://cluster.local/workload/",
        "spiffe://cluster.local/workload/../node/node-1",
        "spiffe://cluster.local/workload/api/extra",
        "spiffe://cluster.local:8443/workload/api",
        "spiffe://user@cluster.local/workload/api",
        "spiffe://cluster.local/workload/api?x=1",
        "spiffe://cluster.local/workload/api#frag",
        "spiffe://cluster.local/workload/API",
        &format!("spiffe://cluster.local/workload/{}", "a".repeat(300)),
    ] {
        assert!(raw.parse::<SpiffeId>().is_err(), "'{raw}' was accepted");
    }
}

/// A name the schema does not permit yields no ID.
#[test]
fn an_invalid_workload_name_yields_no_id() {
    for name in ["", "API", "-api", "a/b", "../etc", "a".repeat(64).as_str()] {
        assert!(
            SpiffeId::for_workload(&domain(), name).is_err(),
            "'{name}' was accepted"
        );
    }
}

/// An unusable trust domain likewise.
#[test]
fn an_invalid_trust_domain_is_rejected() {
    for raw in [
        "",
        "CLUSTER.local",
        "cluster local",
        "cluster.local/",
        "a".repeat(256).as_str(),
    ] {
        assert!(TrustDomain::new(raw).is_err(), "'{raw}' was accepted");
    }
}

// --- The time windows (ADR-0014) --------------------------------------------

/// The tight profile from ADR-0014, as the default.
#[test]
fn the_default_lifetime_is_the_tight_profile_from_adr_0014() {
    let lifetime = Lifetime::default();

    assert_eq!(lifetime.ttl, Duration::from_mins(15));
    assert_eq!(lifetime.rotate_after, Duration::from_mins(7));
    assert_eq!(lifetime.grace, Duration::from_mins(2));
}

/// The ordering conditions from ADR-0014 are checked, not presupposed.
///
/// There they stand as "hard rules": soft fail << TTL, rotation before expiry. A
/// configuration that violates them is no tighter setting but a broken one -- a
/// soft-fail window above the TTL would be a second validity period.
#[test]
fn a_lifetime_that_breaks_the_ordering_is_rejected() {
    let base = Lifetime::default();

    let cases = [
        Lifetime {
            rotate_after: base.ttl,
            ..base
        },
        Lifetime {
            rotate_after: base.ttl + Duration::from_secs(1),
            ..base
        },
        Lifetime {
            grace: base.ttl,
            ..base
        },
        Lifetime {
            grace: base.ttl + Duration::from_secs(1),
            ..base
        },
        Lifetime {
            ttl: Duration::ZERO,
            ..base
        },
    ];

    for lifetime in cases {
        assert!(
            lifetime.validate().is_err(),
            "{lifetime:?} should have been refused"
        );
    }

    assert!(base.validate().is_ok());
}

/// Freshly issued: valid, no rotation due, not in the grace.
#[test]
fn a_fresh_svid_is_valid_and_not_due() {
    let lifetime = Lifetime::default();
    let validity = Validity::issued_at(0, lifetime);

    assert_eq!(validity.state_at(0), tg_identity::State::Fresh);
    assert!(validity.is_usable_at(0));
    assert!(!validity.should_rotate_at(0));
}

/// After the rotation lead time the renewal falls due -- **before** the expiry.
///
/// That is the point of the lead time: there is still time for several attempts
/// before the certificate becomes worthless.
#[test]
fn rotation_falls_due_well_before_expiry() {
    let lifetime = Lifetime::default();
    let validity = Validity::issued_at(1_000, lifetime);

    assert!(!validity.should_rotate_at(1_000 + 7 * 60 - 1));
    assert!(validity.should_rotate_at(1_000 + 7 * 60));
    assert!(validity.is_usable_at(1_000 + 7 * 60), "due, but valid");
    assert!(validity.should_rotate_at(1_000 + 14 * 60));
}

/// **The grace from ADR-0019: still usable after expiry, but only briefly.**
///
/// The case "the CA is briefly gone". A late rotation shall not tear existing
/// connections immediately -- but the hard expiry stays: after the grace it is over,
/// and that without exception.
#[test]
fn the_grace_window_tolerates_a_late_rotation_but_not_more() {
    let lifetime = Lifetime::default();
    let validity = Validity::issued_at(0, lifetime);

    let ttl = 15 * 60;
    let grace = 2 * 60;

    assert_eq!(validity.state_at(ttl - 1), tg_identity::State::Due);
    assert!(validity.is_usable_at(ttl - 1));

    // Exactly at the expiry: no longer fresh, but in the grace.
    assert_eq!(validity.state_at(ttl), tg_identity::State::Grace);
    assert!(validity.is_usable_at(ttl));
    assert!(validity.is_usable_at(ttl + grace - 1));

    // And then hard over.
    assert_eq!(validity.state_at(ttl + grace), tg_identity::State::Expired);
    assert!(!validity.is_usable_at(ttl + grace));
    assert!(!validity.is_usable_at(ttl + grace + 1));
}

/// The grace is **no** second validity period: it does not extend what a counterpart
/// checks.
///
/// The distinction is the heart of the soft fail: the **holder** may still use an
/// expired SVID in the grace instead of losing the connection immediately; the
/// **verifier** sees an expired certificate and refuses. The certificate itself
/// carries the grace nowhere.
#[test]
fn the_grace_window_does_not_extend_the_certificate() {
    let lifetime = Lifetime::default();
    let validity = Validity::issued_at(0, lifetime);

    assert_eq!(validity.not_after(), 15 * 60);
    assert!(validity.is_usable_at(15 * 60 + 60));
    assert!(
        !validity.is_within_certificate_at(15 * 60 + 60),
        "the grace must not extend the certificate's validity"
    );
}

/// A clock that jumps backwards does not invalidate an SVID.
///
/// ADR-0024 separates traceable UTC from the monotonic source; here the first one
/// counts, and that can be corrected by NTP. An SVID that thereby stems "from the
/// future" is no attack but a correction.
#[test]
fn a_clock_that_jumps_backwards_does_not_invalidate_an_svid() {
    let validity = Validity::issued_at(1_000, Lifetime::default());

    assert!(validity.is_usable_at(900));
    assert_eq!(validity.state_at(900), tg_identity::State::Fresh);
}

// --- The attestation --------------------------------------------------------

/// From a process's cgroup path the container arises.
///
/// **The container, not the workload** (ADR-0065): whom it belongs to is said by the
/// node's stock. Backwards it would not be determinable from `tg-api-3` whether
/// instance 3 of `api` or instance 0 of `api-3` is meant.
#[test]
fn a_cgroup_path_identifies_the_container() {
    let attestation = Attestation::from_socket("tg-api").expect("recognized");

    assert_eq!(attestation.container_id(), "tg-api");
}

/// **A process outside a container gets nothing.**
///
/// The attestation's actual statement. Without it every process on the node would get
/// an SVID -- one that only found the socket too.
#[test]
fn a_process_outside_a_container_is_not_attested() {
    // Since ADR-0081 the input is the **socket's identifier** and no longer a cgroup
    // line: the cases that check a parser (nested paths, `12:pids:`) have fallen away
    // with it. What remains is the form check -- it costs nothing and stands where an
    // identity arises.
    for raw in ["", "foreign-api", "tg-", "system.slice/tg-api", "/tg-api"] {
        assert!(
            Attestation::from_socket(raw).is_none(),
            "{raw:?} was attested"
        );
    }
}

/// A name that looks like a container but can be none is refused -- the schema's facet
/// applies here too.
#[test]
fn a_container_name_that_cannot_be_a_workload_is_rejected() {
    // Here once stood `is_none() || container_id() != "tg-.."`, and the second half
    // was **dead**: none of these inputs *is* `tg-..`, so it was trivially true for
    // every accepted one -- the witness let it through that `tg-a b` and `tg--` are
    // attested. Measured, each of the five is refused; assured from here on is the
    // refusal, as the name says.
    for raw in ["tg-API", "tg-../etc", "tg-a b", "tg--", "tg-.."] {
        assert!(
            Attestation::from_socket(raw).is_none(),
            "{raw:?} was attested"
        );
    }
}

/// The attestation alone does not suffice: the workload must also be assigned to this
/// node.
///
/// ADR-0006 calls it authority binding -- "an agent may mint SVIDs only for workloads
/// that were placed on its node -> a bounded blast radius at a node compromise".
/// Without that second check a compromised node could assume the identity of **every**
/// workload in the cluster.
#[test]
fn attestation_alone_does_not_authorise_minting() {
    let attestation = Attestation::from_socket("tg-api").expect("recognized");
    let known = |names: &[&str]| -> std::collections::BTreeMap<String, String> {
        names
            .iter()
            .map(|name| {
                (
                    tg_runtime::bundle::container_id(name, 0),
                    (*name).to_owned(),
                )
            })
            .collect()
    };

    assert_eq!(attestation.resolve(&known(&["api", "db"])), Some("api"));
    assert_eq!(attestation.resolve(&known(&["db"])), None);
    assert_eq!(
        attestation.resolve(&std::collections::BTreeMap::new()),
        None
    );
}
