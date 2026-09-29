//! The minting and the validity of an SVID (ADR-0006, ADR-0014, phase 7a).
//!
//! Here the chain is **verified**, not asserted: `rustls-webpki` is the same verifier
//! the data plane will use in phase 8 (ADR-0007). A test that only checks that a
//! certificate arose says nothing about whether anybody would accept it.
//!
//! On that hangs the phase's third acceptance criterion: **the hard expiry stays
//! enforced.** The soft-fail grace belongs to the holder (see
//! `tg_identity::lifetime`); a verifier does not see it and must not see it.

use std::time::Duration;

use rustls_pki_types::{CertificateDer, UnixTime};
use tg_identity::{Authority, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};

const YEAR: i64 = 365 * 24 * 60 * 60;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

/// Verifies an SVID against the trust bundle at a point in time.
fn verify(svid_der: &[u8], ca_der: &[u8], at: i64) -> Result<(), webpki::Error> {
    let ca = CertificateDer::from(ca_der.to_vec());
    let anchor = webpki::anchor_from_trusted_cert(&ca).expect("anchor");
    let leaf = CertificateDer::from(svid_der.to_vec());
    let cert = webpki::EndEntityCert::try_from(&leaf).expect("a readable certificate");

    cert.verify_for_usage(
        &[webpki::ring::ED25519],
        &[anchor],
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(at).expect("not before 1970"),
        )),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .map(|_| ())
}

struct Fixture {
    ca_der: Vec<u8>,
    authority: Authority<LocalSigner>,
}

impl Fixture {
    fn authority(&self) -> &Authority<LocalSigner> {
        &self.authority
    }

    fn ca_der(&self) -> &[u8] {
        &self.ca_der
    }
}

fn fixture() -> Fixture {
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("CA");
    let ca_der = ca.certificate_der().to_vec();
    let authority = Authority::new(ca, signer, Lifetime::default()).expect("issuer");

    Fixture { ca_der, authority }
}

/// **The container receives a deterministic SPIFFE ID** -- and it stands in the
/// certificate.
#[test]
fn an_svid_carries_the_derived_spiffe_id() {
    let fixture = fixture();
    let authority = fixture.authority();
    let id = SpiffeId::for_workload(&domain(), "api").expect("ID");

    let svid = authority.issue(&id, 1_000).expect("SVID");

    assert_eq!(svid.id(), &id);
    let text = String::from_utf8_lossy(svid.certificate_der());
    assert!(
        text.contains("spiffe://cluster.local/workload/api"),
        "the ID does not stand in the certificate"
    );
    assert!(
        !text.contains("spiffe://cluster.local/workload/db"),
        "a foreign ID stands in the certificate"
    );
}

/// Issued twice yields the same identity -- but **not** the same key.
///
/// The identity is derived and thereby stable; the key material is not and must not
/// be. A rotated SVID with the same key would be a rotation that rotates nothing.
#[test]
fn reissuing_keeps_the_identity_and_changes_the_key() {
    let fixture = fixture();
    let authority = fixture.authority();
    let id = SpiffeId::for_workload(&domain(), "api").expect("ID");

    let first = authority.issue(&id, 1_000).expect("SVID");
    let second = authority.issue(&id, 2_000).expect("SVID");

    assert_eq!(first.id(), second.id());
    assert_ne!(
        first.private_key_pem(),
        second.private_key_pem(),
        "the rotation reused the same key"
    );
    assert_ne!(first.certificate_pem(), second.certificate_pem());
}

/// The SVID verifies against the trust bundle.
#[test]
fn an_svid_verifies_against_the_trust_bundle() {
    let fixture = fixture();
    let authority = fixture.authority();
    let id = SpiffeId::for_workload(&domain(), "api").expect("ID");
    let svid = authority.issue(&id, 100_000).expect("SVID");

    verify(svid.certificate_der(), fixture.ca_der(), 100_060).expect("must verify");
}

/// **The hard expiry stays enforced.**
///
/// The third acceptance criterion. The holder may still use an expired SVID in the
/// grace -- a verifier refuses it all the same. Exactly that asymmetry is the
/// soft fail from ADR-0019, and it is a security statement only if the second half
/// really holds.
#[test]
fn expiry_is_enforced_by_the_verifier_even_inside_the_grace_window() {
    let fixture = fixture();
    let authority = fixture.authority();
    let id = SpiffeId::for_workload(&domain(), "api").expect("ID");

    let issued_at = 100_000;
    let svid = authority.issue(&id, issued_at).expect("SVID");
    let ttl = 15 * 60;
    let grace = 60;

    // Shortly before expiry: the verifier takes it.
    verify(
        svid.certificate_der(),
        fixture.ca_der(),
        issued_at + ttl - 10,
    )
    .expect("valid before expiry");

    // In the grace: the holder may still use it ...
    assert!(
        svid.validity().is_usable_at(issued_at + ttl + grace),
        "the grace does not bite"
    );

    // ... but the verifier no longer takes it.
    let refused = verify(
        svid.certificate_der(),
        fixture.ca_der(),
        issued_at + ttl + grace,
    );
    assert!(
        refused.is_err(),
        "an expired SVID was accepted in the grace -- the hard expiry is not \
         enforced"
    );
}

/// An SVID of a foreign CA does not verify.
///
/// The counter-proof to the chain check: without it it would stay open whether the
/// verifier checks anything at all.
#[test]
fn an_svid_from_a_foreign_ca_does_not_verify() {
    let ours = fixture();
    let theirs = fixture();

    let authority = theirs.authority();
    let id = SpiffeId::for_workload(&domain(), "api").expect("ID");
    let svid = authority.issue(&id, 100_000).expect("SVID");

    assert!(
        verify(svid.certificate_der(), ours.ca_der(), 100_060).is_err(),
        "a foreign SVID was accepted against our bundle"
    );
}

/// An SVID may sign nothing further -- it is an end certificate.
///
/// Without that determination a compromised workload could mint for every other one,
/// and the authority binding from ADR-0006 would be worthless.
#[test]
fn an_svid_is_not_a_ca() {
    let fixture = fixture();
    let authority = fixture.authority();
    let id = SpiffeId::for_workload(&domain(), "api").expect("ID");
    let svid = authority.issue(&id, 100_000).expect("SVID");

    // Taking an end certificate as an anchor must fail.
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());
    let as_anchor = webpki::anchor_from_trusted_cert(&leaf);
    let second = authority
        .issue(
            &SpiffeId::for_workload(&domain(), "db").expect("ID"),
            100_000,
        )
        .expect("SVID");

    if let Ok(anchor) = as_anchor {
        let other = CertificateDer::from(second.certificate_der().to_vec());
        let cert = webpki::EndEntityCert::try_from(&other).expect("readable");
        assert!(
            cert.verify_for_usage(
                &[webpki::ring::ED25519],
                &[anchor],
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(100_060)),
                webpki::KeyUsage::client_auth(),
                None,
                None,
            )
            .is_err(),
            "an SVID served as a CA for another SVID"
        );
    }
}

/// Time windows that violate the ordering conditions are refused at the build-up --
/// not only at the first workload.
#[test]
fn an_authority_with_broken_lifetimes_is_refused() {
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("CA");
    let broken = Lifetime {
        ttl: Duration::from_mins(1),
        rotate_after: Duration::from_mins(2),
        grace: Duration::from_secs(30),
    };

    assert!(Authority::new(ca, signer, broken).is_err());
}
