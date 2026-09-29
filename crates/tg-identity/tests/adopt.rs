//! The agent takes over a **freshly fetched** intermediate (ADR-0006/0037).
//!
//! The agent mints the workload SVIDs locally from a short-lived agent intermediate
//! -- 12 h lifetime, renewal every 3 h (ADR-0014). The renewal path from ADR-0037
//! writes **fresh** material to the disk in the process, with a new key per round.
//!
//! The issuing service must take that over. If it does not, it goes on minting from
//! an expired intermediate after twelve hours -- and **none** of the issued SVIDs is
//! accepted any more, because every verifier checks the chain. The error then shows
//! itself not at the issuance but at the first connection.

use tg_identity::{Authority, Ca, Lifetime, LocalSigner, Minter, TrustDomain, self_signed_ca};

const YEAR: i64 = 365 * 24 * 60 * 60;
const HOUR: i64 = 60 * 60;
const NOW: i64 = 1_800_000_000;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

/// An issuer with its own key and a known validity.
fn authority(not_after: i64) -> Authority<LocalSigner> {
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, not_after).expect("CA");
    Authority::new(ca, signer, Lifetime::default()).expect("issuer")
}

fn minter(not_after: i64) -> Minter<LocalSigner> {
    Minter::new(
        authority(not_after),
        domain(),
        not_after,
        assigned(&["api"]),
    )
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

/// The deadline stands **in the certificate** -- it need not be written beside it.
///
/// Until here the agent set it as `i64::MAX` and thereby made the check
/// `can_mint_at` without effect. ADR-0014, however, expressly demands that the hard
/// expiry stay enforced.
#[test]
fn a_ca_certificate_knows_when_it_expires() {
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, 12 * HOUR).expect("CA");

    assert_eq!(ca.not_after(), 12 * HOUR);
}

/// The same for a certificate that comes from outside -- the agent's way.
#[test]
fn a_loaded_ca_certificate_knows_when_it_expires() {
    let signer = LocalSigner::generate().expect("key");
    let pem = self_signed_ca(&domain(), &signer, 0, 5 * YEAR)
        .expect("CA")
        .certificate_pem();

    let loaded = Ca::from_pem(&pem).expect("readable");

    assert_eq!(loaded.not_after(), 5 * YEAR);
}

/// After the take-over the service mints from the **new** material.
#[test]
fn adopting_fresh_material_changes_the_chain() {
    let mut minter = minter(NOW + 12 * HOUR);
    let before = minter.chain_pem().to_owned();

    minter.adopt(authority(NOW + 24 * HOUR), NOW + 24 * HOUR);

    assert_ne!(
        minter.chain_pem(),
        before,
        "the chain must follow the new intermediate"
    );
}

/// And the deadline moves along.
#[test]
fn adopting_fresh_material_moves_the_deadline() {
    let mut minter = minter(NOW + HOUR);
    assert!(!minter.can_mint_at(NOW + 2 * HOUR), "expired beforehand");

    minter.adopt(authority(NOW + 24 * HOUR), NOW + 24 * HOUR);

    assert!(
        minter.can_mint_at(NOW + 2 * HOUR),
        "after the take-over the new intermediate carries"
    );
}

/// **The heart of the matter: the cache must be emptied.**
///
/// The chain is read freshly from the issuer at every request, the SVID however from
/// the cache. If an old SVID stayed lying in it, it would go out with the **new**
/// chain -- and would not be covered by it. The result would be worse than an expired
/// certificate: a chain that does not fit together, and that immediately instead of
/// after twelve hours.
#[test]
fn adopting_fresh_material_discards_svids_of_the_old_chain() {
    let mut minter = minter(NOW + 12 * HOUR);
    let old = minter
        .svid_named("api", NOW)
        .expect("SVID")
        .certificate_der()
        .to_vec();

    minter.adopt(authority(NOW + 24 * HOUR), NOW + 24 * HOUR);
    let new = minter.svid_named("api", NOW).expect("SVID");

    assert_ne!(
        new.certificate_der(),
        old.as_slice(),
        "an SVID of the old chain must not go out with the new chain"
    );
}
