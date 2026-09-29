//! **The test "the CA is briefly gone"** (ADR-0019, phase 7).
//!
//! The phase's acceptance criterion verbatim: "existing connections do not break
//! within the grace; the hard expiry stays enforced."
//!
//! Both stand here, and both are a statement about **different** parties:
//!
//! - The **agent** goes on minting as long as its intermediate applies -- even when
//!   the control plane is gone. That is the static stability from ADR-0019: the
//!   failure of the riskiest component does not hold the workload up.
//! - The **holder** may go on using a just-expired SVID in the grace instead of
//!   losing its connections.
//! - The **verifier** sees nothing of it. For it expired is expired -- checked in
//!   `tests/svid.rs` with the real verifier.
//!
//! And the buffer has an end: after the intermediate's expiry no more minting
//! happens. Without that end a cut-off agent would issue identities nobody can revoke
//! any more.

use std::time::Duration;

use tg_identity::{
    Attestation, Authority, IntermediateProfile, Lifetime, LocalSigner, Minter, Refusal,
    TrustDomain, self_signed_ca,
};

const HOUR: i64 = 60 * 60;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

fn attestation() -> Attestation {
    Attestation::from_socket("tg-api").expect("attested")
}

/// An issuing service whose intermediate expires at the given point in time.
///
/// Since 7c the [`Authority`] owns its CA and its signer (ADR-0035: the gRPC service
/// demands `'static`), so every call builds its own. That is no loss: the tests here
/// share nothing with each other anyway.
fn minter(intermediate_until: i64) -> Minter<LocalSigner> {
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, 365 * 24 * HOUR).expect("intermediate");
    let authority = Authority::new(ca, signer, Lifetime::default()).expect("issuer");

    Minter::new(authority, domain(), intermediate_until, assigned(&["api"]))
}

/// What the node hands the issuing service (ADR-0065): container identifier ->
/// workload, formed with **the same** function that assigns the identifiers in
/// operation.
fn assigned(names: &[&str]) -> std::collections::BTreeMap<String, String> {
    names
        .iter()
        .map(|name| {
            (
                tg_runtime::bundle::container_id(name, 0),
                (*name).to_owned(),
            )
        })
        .collect()
}

/// **The control plane is gone -- the agent goes on minting.**
///
/// Twelve hours of intermediate (ADR-0014), and in that time nobody asks the control
/// plane. Every request gets a valid SVID.
#[test]
fn the_agent_keeps_minting_while_the_control_plane_is_gone() {
    let mut minter = minter(12 * HOUR);
    let attested = attestation();

    // Over the intermediate's whole lifetime, in hourly steps.
    for hour in 0..12 {
        let now = hour * HOUR;
        let svid = minter
            .svid_for(&attested, now)
            .unwrap_or_else(|err| panic!("hour {hour}: {err}"));

        assert!(
            svid.validity().is_usable_at(now),
            "hour {hour}: the issued SVID is not usable"
        );
        assert_eq!(svid.id().workload(), Some("api"));
    }
}

/// Between two requests no new minting happens as long as the SVID is fresh -- and
/// afterwards it does.
///
/// Without the first every request would be an issuance: more load, more certificates
/// in circulation, and none of them valid longer than the previous one.
#[test]
fn a_fresh_svid_is_reused_and_a_due_one_is_rotated() {
    let mut minter = minter(12 * HOUR);
    let attested = attestation();

    let first = minter
        .svid_for(&attested, 0)
        .expect("SVID")
        .certificate_pem()
        .to_owned();
    let again = minter
        .svid_for(&attested, 60)
        .expect("SVID")
        .certificate_pem()
        .to_owned();
    assert_eq!(first, again, "a fresh SVID was replaced without need");

    // After the rotation lead time (7 min, ADR-0014).
    let rotated = minter
        .svid_for(&attested, 7 * 60 + 1)
        .expect("SVID")
        .certificate_pem()
        .to_owned();
    assert_ne!(first, rotated, "the due rotation stayed out");
}

/// **Inside the grace nothing breaks.**
///
/// The intermediate is expired, no more minting can happen -- the holder gets its
/// existing SVID all the same as long as the grace runs. That is the heart of the
/// criterion: a briefly absent CA tears no connection.
#[test]
fn nothing_breaks_inside_the_grace_window() {
    // The intermediate expires shortly after the first SVID is issued.
    let mut minter = minter(60);
    let attested = attestation();

    let issued = minter
        .svid_for(&attested, 0)
        .expect("SVID")
        .certificate_pem()
        .to_owned();

    // From here on no more minting can happen.
    assert!(!minter.can_mint_at(120));

    // During the validity: unchanged the same SVID.
    let during = minter.svid_for(&attested, 10 * 60).expect("SVID");
    assert_eq!(during.certificate_pem(), issued);

    // After the expiry, but in the grace (15 min TTL + 2 min grace): still the same,
    // and the holder may use it.
    let ttl = 15 * 60;
    let in_grace = minter
        .svid_for(&attested, ttl + 60)
        .expect("in the grace there must still be something");
    assert_eq!(in_grace.certificate_pem(), issued);
    assert!(in_grace.validity().is_usable_at(ttl + 60));
    assert!(
        !in_grace.validity().is_within_certificate_at(ttl + 60),
        "the grace would have extended the certificate"
    );
}

/// **After the grace it is over.**
///
/// The buffer ends, and that hard. An agent that went on minting afterwards would
/// issue identities nobody can revoke any more -- and the ordering condition from
/// ADR-0014 ("intermediate lifetime > expected outage window") would be a number
/// without effect.
#[test]
fn after_the_grace_window_the_agent_refuses() {
    let mut minter = minter(60);
    let attested = attestation();

    minter.svid_for(&attested, 0).expect("the first SVID");

    let past_everything = 15 * 60 + 2 * 60 + 1;
    let refused = minter.svid_for(&attested, past_everything);

    assert!(
        matches!(refused, Err(Refusal::IntermediateExpired { .. })),
        "{refused:?}"
    );
}

/// If the control plane comes back, it goes on -- without a restart.
#[test]
fn a_returning_control_plane_resumes_minting() {
    let mut minter = minter(60);
    let attested = attestation();

    minter.svid_for(&attested, 0).expect("the first SVID");
    let too_late = 15 * 60 + 2 * 60 + 1;
    assert!(minter.svid_for(&attested, too_late).is_err());

    // The control plane delivers a new intermediate -- **with a fresh key**, as the
    // renewal path from ADR-0037 does. Merely moving the deadline would be no image
    // of operation: the material changes along with it.
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, 365 * 24 * HOUR).expect("intermediate");
    let fresh = Authority::new(ca, signer, Lifetime::default()).expect("issuer");
    minter.adopt(fresh, too_late + 12 * HOUR);

    let svid = minter
        .svid_for(&attested, too_late + 1)
        .expect("after the renewal it must work again");
    assert!(svid.validity().is_usable_at(too_late + 1));
}

/// **The authority binding applies without a control plane too.**
///
/// An agent without a quorum does not become more generous. If it were, a cut-off
/// node would have more rights than a connected one -- and a partition would be a way
/// to gain authority.
#[test]
fn the_authority_binding_holds_without_a_control_plane() {
    let mut minter = minter(12 * HOUR);

    let foreign = Attestation::from_socket("tg-db").expect("attested");
    let refused = minter.svid_for(&foreign, 0);

    // Since ADR-0065 the refusal names the **identifier** instead of a name:
    // backwards no workload can be determined from `tg-db`, and a guessed name in the
    // message would send an operator to the wrong place.
    assert!(
        matches!(refused, Err(Refusal::UnknownContainer { .. })),
        "{refused:?}"
    );
}

/// If the assignment changes, the authority changes -- in both directions.
#[test]
fn a_changed_assignment_changes_what_may_be_minted() {
    let mut minter = minter(12 * HOUR);
    let db = Attestation::from_socket("tg-db").expect("attested");

    assert!(minter.svid_for(&db, 0).is_err());

    minter.set_assigned(assigned(&["db"]));
    assert!(minter.svid_for(&db, 0).is_ok());

    minter.set_assigned(std::collections::BTreeMap::new());
    assert!(minter.svid_for(&db, 0).is_err());
}

/// **The soft-fail grace is one number, not two.**
///
/// ADR-0014 names it once (2 min, "tolerance for a late rotation"), and measured it
/// stood **twice** in the tree: here in the `Lifetime` default and **invented inline**
/// at the one place that issues an agent intermediate (`tgd::identity`). It applies to
/// every time window because it describes not the thing but the behaviour at its
/// expiry (ADR-0019).
///
/// The witness nails the number down **and** the order it stands in: without the
/// second half a grace that reaches the TTL would be green here and red only in
/// `validate` -- and that is the state the build assurance in `lifetime.rs`
/// abolishes.
#[test]
fn the_soft_fail_grace_is_one_number_for_every_window() {
    use tg_identity::lifetime::{SOFT_FAIL_GRACE, SVID_ROTATE_AFTER, SVID_TTL};

    assert_eq!(SOFT_FAIL_GRACE, Duration::from_mins(2));
    assert_eq!(SVID_TTL, Duration::from_mins(15));
    assert_eq!(SVID_ROTATE_AFTER, Duration::from_mins(7));

    // The default reads them -- so they exist only once.
    let lifetime = Lifetime::default();
    assert_eq!(lifetime.grace, SOFT_FAIL_GRACE);
    assert_eq!(lifetime.ttl, SVID_TTL);
    assert_eq!(lifetime.rotate_after, SVID_ROTATE_AFTER);
    assert!(lifetime.validate().is_ok());

    // And the order from ADR-0014: grace and lead time lie before the expiry.
    assert!(SOFT_FAIL_GRACE < SVID_ROTATE_AFTER);
    assert!(SVID_ROTATE_AFTER < SVID_TTL);
}

/// The intermediate's profile from ADR-0014 keeps its ordering condition.
#[test]
fn the_intermediate_profile_keeps_its_ordering() {
    let profile = IntermediateProfile::default();

    assert_eq!(profile.ttl, Duration::from_hours(12));
    assert_eq!(profile.renew_after, Duration::from_hours(3));
    assert!(profile.validate().is_ok());

    // A renewal shortly before the expiry leaves only one attempt.
    let tight = IntermediateProfile {
        ttl: Duration::from_hours(12),
        renew_after: Duration::from_hours(11),
    };
    assert!(tight.validate().is_err());
}

/// **The way over the name checks the assignment too** (ADR-0006).
///
/// `svid_for` checks it itself and then calls `svid_named` -- which checks it **once
/// more**. Two layers, and the test for the outer one covers the inner: a mutation run
/// removed the check in `svid_named`, and no target turned red.
///
/// It counts because there is a **second** caller: the workload API's delegation path
/// (ADR-0036). There the name has already gone through `tg_model::mesh::delegations`,
/// so the check here is defence in depth -- and exactly the sort of layer a rebuild
/// takes away without anybody noticing.
#[test]
fn minting_by_name_also_requires_the_assignment() {
    let mut minter = minter(12 * HOUR);

    let refused = minter.svid_named("foreign", 0);

    assert!(
        matches!(refused, Err(Refusal::NotAssigned { ref workload }) if workload == "foreign"),
        "{refused:?}"
    );
}

/// The counter-check: the assigned name gets its SVID.
///
/// Without it the test above would be green even if `svid_named` refused everybody on
/// principle.
#[test]
fn minting_by_name_works_for_an_assigned_workload() {
    let mut minter = minter(12 * HOUR);

    assert!(minter.svid_named("api", 0).is_ok());
}
