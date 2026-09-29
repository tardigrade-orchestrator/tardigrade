//! Service discovery.
//!
//! The governing principle: discovery delivers **only** name → endpoint(s).
//! The identity is checked by the mTLS handshake via the SPIFFE ID, and the
//! permission comes from the `may_talk` edges.
//!
//! That is a statement about what does **not** belong here, and it is easy to
//! violate: a resolution that returns only what the asker may also address
//! looks like an additional line of defence. It is, however, a displacement —
//! enforcement would then sit in two places, and the one (DNS) is the weaker,
//! because a container can guess the address without resolution too. That is
//! why this file has an express test for discovery **not** authorizing.
//!
//! The second axis is the distinction that steers DNS caches: **NXDOMAIN**
//! means "this name does not exist", **NODATA** means "the name exists, right
//! now nothing is healthy". Whoever collapses both into NXDOMAIN lets resolvers
//! cache a negative result that is immediately wrong again — a workload that is
//! still starting would stay unreachable until the cache expires.

use std::net::Ipv4Addr;

use tg_net::discovery::{
    Answer, Domain, Endpoint, Health, NEGATIVE_TTL_SECONDS, Registry, TTL_SECONDS,
};

/// Builds the fixture zone used across this test file.
///
/// # Returns
/// The domain `tardigrade.internal`.
fn domain() -> Domain {
    Domain::new("tardigrade.internal").expect("valid domain")
}

/// Builds a fixture endpoint on the `10.42.1.0/24` test subnet.
///
/// # Parameters
/// - `workload`: the workload name the endpoint belongs to.
/// - `instance`: the instance number within the workload.
/// - `last`: the last octet of the fixture address.
/// - `health`: the health state to report for the endpoint.
///
/// # Returns
/// The constructed endpoint.
fn endpoint(workload: &str, instance: u32, last: u8, health: Health) -> Endpoint {
    Endpoint {
        workload: workload.to_owned(),
        instance,
        address: Ipv4Addr::new(10, 42, 1, last),
        health,
    }
}

/// Builds the fixture registry used by most tests in this file: two healthy
/// `api` instances, one healthy `ledger` instance and one unhealthy `cache`
/// instance.
///
/// # Returns
/// The constructed registry.
fn registry() -> Registry {
    Registry::new(
        domain(),
        vec![
            endpoint("api", 0, 10, Health::Healthy),
            endpoint("api", 1, 11, Health::Healthy),
            endpoint("ledger", 0, 20, Health::Healthy),
            endpoint("cache", 0, 30, Health::Unhealthy),
        ],
    )
}

// ------------------------------------------------------------------ Resolution

/// A service name resolves to the addresses of all its healthy instances.
#[test]
fn a_service_name_resolves_to_all_healthy_instances() {
    let answer = registry().resolve("api.tardigrade.internal");

    assert_eq!(
        answer,
        Answer::Addresses(vec![
            Ipv4Addr::new(10, 42, 1, 10),
            Ipv4Addr::new(10, 42, 1, 11),
        ])
    );
}

/// The order is fixed, not random. A resolver that sorts differently on every
/// query makes every error report irreproducible — and load distribution is
/// not its task anyway: discovery is address resolution, nothing else.
#[test]
fn the_answer_is_ordered_deterministically() {
    let scrambled = Registry::new(
        domain(),
        vec![
            endpoint("api", 2, 12, Health::Healthy),
            endpoint("api", 0, 10, Health::Healthy),
            endpoint("api", 1, 11, Health::Healthy),
        ],
    );

    for _ in 0..8 {
        assert_eq!(
            scrambled.resolve("api.tardigrade.internal"),
            Answer::Addresses(vec![
                Ipv4Addr::new(10, 42, 1, 10),
                Ipv4Addr::new(10, 42, 1, 11),
                Ipv4Addr::new(10, 42, 1, 12),
            ])
        );
    }
}

/// An unhealthy instance is left out of the resolved address list.
#[test]
fn an_unhealthy_instance_is_left_out() {
    let mixed = Registry::new(
        domain(),
        vec![
            endpoint("api", 0, 10, Health::Healthy),
            endpoint("api", 1, 11, Health::Unhealthy),
        ],
    );

    assert_eq!(
        mixed.resolve("api.tardigrade.internal"),
        Answer::Addresses(vec![Ipv4Addr::new(10, 42, 1, 10)])
    );
}

/// The difference that steers the negative caches: `cache` exists, but right
/// now no instance is healthy. That is NODATA, not NXDOMAIN.
#[test]
fn a_known_name_without_a_healthy_instance_answers_nodata_not_nxdomain() {
    assert_eq!(
        registry().resolve("cache.tardigrade.internal"),
        Answer::NoData
    );
}

/// A name that does not exist inside the zone answers NXDOMAIN.
#[test]
fn an_unknown_name_inside_the_domain_answers_nxdomain() {
    assert_eq!(
        registry().resolve("doesnotexist.tardigrade.internal"),
        Answer::NxDomain
    );
}

/// The resolver is authoritative for one zone and nothing else. A query for
/// `example.com` it does not answer — and it does not forward it either. A
/// container that wants to resolve into the internet asks its second resolver;
/// a forwarder here would be an open resolver in the mesh.
#[test]
fn a_name_outside_the_domain_is_refused_not_forwarded() {
    assert_eq!(registry().resolve("example.com"), Answer::Refused);
    assert_eq!(registry().resolve("api.example.com"), Answer::Refused);
}

/// A find of the fuzz run, nailed down deterministically here.
///
/// `internaltardigrade.internal` **ends with** the zone and nevertheless does
/// not lie within it — the zone ends at a label boundary, not at a character
/// boundary. Whoever checks that with `ends_with` turns every name a stranger
/// lets end in `-tardigrade.internal` into a name of our own zone:
/// `evil-tardigrade.internal` would then resolve this cluster's services.
#[test]
fn a_name_that_merely_ends_with_the_domain_is_not_in_it() {
    for outsider in [
        "api.internaltardigrade.internal",
        "api.evil-tardigrade.internal",
        "eviltardigrade.internal",
        "api0.api.internaltardigrade.internal",
    ] {
        assert_eq!(
            registry().resolve(outsider),
            Answer::Refused,
            "'{outsider}' was treated as a name of our own zone"
        );
    }
}

/// The bare domain itself is no service.
#[test]
fn the_domain_itself_is_not_a_service() {
    assert_eq!(registry().resolve("tardigrade.internal"), Answer::NxDomain);
}

// ------------------------------------------------------- Names per instance

/// Beside the service name every instance carries one of its own. Whoever
/// means a **particular** instance needs it — a single writer, say, for
/// which "any one of the three" would be the wrong answer.
#[test]
fn an_instance_has_a_name_of_its_own() {
    assert_eq!(
        registry().resolve("1.api.tardigrade.internal"),
        Answer::Addresses(vec![Ipv4Addr::new(10, 42, 1, 11)])
    );
}

/// An instance number that does not exist answers NXDOMAIN.
#[test]
fn an_instance_that_does_not_exist_answers_nxdomain() {
    assert_eq!(
        registry().resolve("9.api.tardigrade.internal"),
        Answer::NxDomain
    );
}

/// Here too the separation applies: the instance exists, it is merely not
/// healthy.
#[test]
fn an_unhealthy_instance_asked_for_by_name_answers_nodata() {
    assert_eq!(
        registry().resolve("0.cache.tardigrade.internal"),
        Answer::NoData
    );
}

/// Second find of the fuzz run, nailed down deterministically.
///
/// `"00".parse::<u32>()` is `Ok(0)`. So without a counter-check the same
/// instance carries arbitrarily many names — `0`, `00`, `000` —, and every one
/// of them resolves. That breaks every cache key and every later comparison
/// that builds on a name. Only the canonical spelling resolves.
#[test]
fn only_the_canonical_spelling_of_an_instance_number_resolves() {
    let registry = registry();

    assert_eq!(
        registry.resolve("0.api.tardigrade.internal"),
        Answer::Addresses(vec![Ipv4Addr::new(10, 42, 1, 10)])
    );

    for padded in ["00", "000", "0000000001", "01"] {
        assert_eq!(
            registry.resolve(&format!("{padded}.api.tardigrade.internal")),
            Answer::NxDomain,
            "'{padded}' was accepted as an instance number"
        );
    }
}

// ------------------------------------------------------- DNS peculiarities

/// Name matching ignores case.
#[test]
fn names_are_matched_case_insensitively() {
    assert_eq!(
        registry().resolve("API.Tardigrade.INTERNAL"),
        registry().resolve("api.tardigrade.internal")
    );
}

/// A trailing dot denotes the same name as without it.
#[test]
fn a_trailing_dot_is_the_same_name() {
    assert_eq!(
        registry().resolve("api.tardigrade.internal."),
        registry().resolve("api.tardigrade.internal")
    );
}

// ------------------------------------------ Discovery is not authorization

/// `ledger` resolves regardless of whether the asker has a `may_talk` edge to
/// it — the permission is checked by the mTLS sidecar, and only there. This
/// test stands here so that nobody later filters the resolution "to be safe":
/// that would shift the enforcement to the weaker place, for an address can
/// be guessed without resolution too.
#[test]
fn resolving_a_name_is_not_permission_to_talk_to_it() {
    let answer = registry().resolve("ledger.tardigrade.internal");

    assert_eq!(
        answer,
        Answer::Addresses(vec![Ipv4Addr::new(10, 42, 1, 20)])
    );
    // The registry knows no edges. Had it any, this test would be the place at
    // which it stood out.
}

// ------------------------------------------------------------------------ TTL

/// The positive TTL has to stay well below the staleness window of the
/// active-role lease.
///
/// The upper bound is set by the lease duration: 15 s. Caching for longer
/// would mean that after a failover a client still holds the old address when
/// the new holder has long stood. 5 s is a third of that — short enough that
/// every failover sees at least two resolutions.
#[test]
fn the_positive_ttl_stays_well_below_the_lease() {
    assert_eq!(TTL_SECONDS, 5);
    // As a `const` block: the relation of two constants belongs checked by the
    // compiler, not by the test run. Whoever violates it breaks the build.
    const {
        assert!(TTL_SECONDS * 3 <= 15, "three TTLs have to fit in one lease");
    }
}

/// Negative is cached for shorter still: a `Wants` edge does **not** order
/// startup, so a client may start before its target and asks legitimately too
/// early — an NXDOMAIN held for longer would make the service unreachable
/// although it is running by now.
#[test]
fn the_negative_ttl_is_shorter_still() {
    assert_eq!(NEGATIVE_TTL_SECONDS, 1);
    const {
        assert!(NEGATIVE_TTL_SECONDS < TTL_SECONDS);
    }
}

// ------------------------------------------------- Malicious and broken names

/// The names come from containers. That is a trust boundary, and these inputs
/// must neither slip through nor kill the resolver.
#[test]
fn malformed_and_malicious_names_are_refused_without_panicking() {
    let registry = registry();

    let cases = [
        "",
        ".",
        "..",
        "api..tardigrade.internal",
        ".api.tardigrade.internal",
        "api.tardigrade.internal..",
        "api tardigrade internal",
        "api/../ledger.tardigrade.internal",
        "api;DROP TABLE.tardigrade.internal",
        "api\0.tardigrade.internal",
        "api\n.tardigrade.internal",
        "-api.tardigrade.internal",
        "api-.tardigrade.internal",
        "*.tardigrade.internal",
        "api.tardigrade.internal.evil.example.com",
    ];

    for name in cases {
        let answer = registry.resolve(name);
        assert!(
            matches!(answer, Answer::NxDomain | Answer::Refused),
            "'{}' was answered with {answer:?}",
            name.escape_debug()
        );
    }
}

/// A label longer than 63 bytes is refused.
#[test]
fn an_oversized_label_is_refused() {
    let label = "a".repeat(64);
    assert_eq!(
        registry().resolve(&format!("{label}.tardigrade.internal")),
        Answer::NxDomain
    );
}

/// A full name longer than 253 bytes is refused.
#[test]
fn an_oversized_name_is_refused() {
    let name = format!("{}.tardigrade.internal", vec!["a"; 200].join("."));
    assert!(name.len() > 253);
    assert_eq!(registry().resolve(&name), Answer::NxDomain);
}

// --------------------------------------------------------------------- Domain

/// A domain must itself be a syntactically valid DNS name.
#[test]
fn a_domain_must_itself_be_a_valid_name() {
    for bad in ["", ".", "a..b", "-a.b", "a.b-", &"a".repeat(64)] {
        assert!(
            Domain::new(bad).is_err(),
            "'{}' should have been refused",
            bad.escape_debug()
        );
    }
}

/// A domain is normalized to lowercase on construction.
#[test]
fn a_domain_is_stored_lowercased() {
    assert_eq!(
        Domain::new("Tardigrade.INTERNAL").expect("valid").as_str(),
        "tardigrade.internal"
    );
}

/// **A valid zone can make every resolution impossible** — and silently.
///
/// The zone is checked for itself; only the query is `<name>.<zone>` and then
/// tears through the 253 from RFC 1035. The resolver then answers **NXDOMAIN
/// for everything**, and that looks like "the service does not exist".
#[test]
fn a_valid_zone_can_still_leave_no_room_for_a_name() {
    // 251 bytes, every label under 63 — valid in itself.
    let raw: String = (0..4).map(|_| "a".repeat(62)).collect::<Vec<_>>().join(".");
    assert_eq!(raw.len(), 251);
    let zone = Domain::new(&raw).expect("the zone itself is valid");

    assert_eq!(
        zone.longest_workload_name(),
        Some(1),
        "in this zone only a name of one character fits"
    );

    // And that is no calculation into the blue: a container's query really
    // fails.
    let registry = Registry::new(zone, Vec::new());
    assert!(
        matches!(registry.resolve(&format!("api.{raw}")), Answer::NxDomain),
        "a query in this zone should fail on the name length"
    );
}

/// The counter-direction: an ordinary zone carries the **whole** facet.
///
/// Without it a calculation that always comes out tight would be just as green
/// — and the agent would warn at every start.
#[test]
fn an_ordinary_zone_carries_the_whole_facet() {
    let zone = Domain::new("tardigrade.internal").expect("valid");
    assert_eq!(
        zone.longest_workload_name(),
        Some(63),
        "the default zone has to carry the whole name facet"
    );
}

/// A zone that carries no name any more yields `None`.
///
/// **Both edge cases**, and the second is the one at issue: at **253** the
/// subtraction underflows, and `checked_sub` gives `None` anyway. Only at
/// **252** is the remainder exactly zero — there `Some(0)` is decided against
/// `None`, and only there does the filter take effect.
///
/// My first fixture took only the 253; the counter-check (removing the filter)
/// did **not** hit it, because that branch never ran. A `Some(0)` would let the
/// agent report "only names up to 0 characters" — a number nobody can act on.
#[test]
fn a_zone_with_no_room_left_yields_nothing() {
    let base: String = (0..4).map(|_| "a".repeat(62)).collect::<Vec<_>>().join(".");
    assert_eq!(base.len(), 251, "construction of the fixture");

    for (raw, expect) in [
        (format!("{base}z"), None),  // 252: remainder exactly zero
        (format!("{base}.z"), None), // 253: checked_sub underflows
        (base.clone(), Some(1)),     // 251: one character fits
    ] {
        let bytes = raw.len();
        let zone = Domain::new(&raw).expect("valid");
        assert_eq!(
            zone.longest_workload_name(),
            expect,
            "zone with {bytes} bytes"
        );
    }
}
