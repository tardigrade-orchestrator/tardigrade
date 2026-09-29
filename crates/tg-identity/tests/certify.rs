//! The certification of a foreign key (ADR-0037).
//!
//! The difference from minting is the whole point of the bootstrap: here the CA
//! produces **no** key, it confirms one. The applicant's private key never leaves it
//! -- and exactly for that reason it is, per ADR-0037, the node's identity and not the
//! certificate over it.

use std::time::Duration;

use rustls_pki_types::{CertificateDer, UnixTime};
use tg_identity::{
    Authority, Lifetime, LocalSigner, Purpose, SpiffeId, TrustDomain, self_signed_ca,
};

const YEAR: i64 = 365 * 24 * 60 * 60;
const NOW: i64 = 1_800_000_000;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

/// A CA and an applicant with its own key.
struct Fixture {
    anchor: Vec<u8>,
    authority: Authority<LocalSigner>,
    applicant: rcgen::KeyPair,
}

fn fixture() -> Fixture {
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("CA");
    let anchor = ca.certificate_der().to_vec();
    let authority = Authority::new(ca, signer, Lifetime::default()).expect("issuer");

    Fixture {
        anchor,
        authority,
        // The applicant produces its key itself -- here as in operation
        // (ADR-0037).
        applicant: rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key"),
    }
}

fn verify(leaf: &[u8], anchor: &[u8], at: i64, usage: webpki::KeyUsage) -> Result<(), String> {
    let anchor_der = CertificateDer::from(anchor.to_vec());
    let trust = webpki::anchor_from_trusted_cert(&anchor_der).map_err(|err| err.to_string())?;
    let leaf_der = CertificateDer::from(leaf.to_vec());
    let cert = webpki::EndEntityCert::try_from(&leaf_der).map_err(|err| err.to_string())?;

    cert.verify_for_usage(
        &[webpki::ring::ED25519],
        &[trust],
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(u64::try_from(at).expect("after 1970"))),
        usage,
        None,
        None,
    )
    .map(|_| ())
    .map_err(|err| err.to_string())
}

/// **The applicant keeps its key** -- the certificate carries none.
///
/// A type that gave a private key along here would be an invitation to build the
/// bootstrap wrongly.
#[test]
fn a_certificate_over_a_foreign_key_carries_no_private_key() {
    let fixture = fixture();
    let id = SpiffeId::for_node(&domain(), "node-1").expect("ID");

    let certified = fixture
        .authority
        .certify(
            &id,
            &rcgen::PublicKeyData::subject_public_key_info(&fixture.applicant),
            Purpose::Leaf,
            Lifetime::default(),
            NOW,
        )
        .expect("certified");

    assert_eq!(certified.id(), &id);
    // The certificate belongs to the applicant's key -- and the chain carries up to
    // the anchor.
    verify(
        certified.certificate_der(),
        &fixture.anchor,
        NOW + 60,
        webpki::KeyUsage::client_auth(),
    )
    .expect("the chain must carry");
}

/// **An intermediate may issue leaves -- and no further CA.**
///
/// `pathlen = 0`. An agent that could issue intermediates would be an agent that
/// invents nodes for itself.
#[test]
fn an_intermediate_may_sign_leaves_but_not_another_ca() {
    let fixture = fixture();
    let agent_id = SpiffeId::for_node(&domain(), "node-1").expect("ID");

    let intermediate = fixture
        .authority
        .certify(
            &agent_id,
            &rcgen::PublicKeyData::subject_public_key_info(&fixture.applicant),
            Purpose::Intermediate,
            Lifetime {
                ttl: Duration::from_hours(12),
                rotate_after: Duration::from_hours(3),
                grace: Duration::from_mins(2),
            },
            NOW,
        )
        .expect("certified");

    // The agent mints a workload SVID from it locally -- the path from 7a, only with
    // an intermediate that now really comes from the control plane.
    let ca = tg_identity::Ca::from_pem(intermediate.certificate_pem()).expect("CA");
    let signer = LocalSigner::from_pem(&fixture.applicant.serialize_pem()).expect("key");
    let agent = Authority::new(ca, signer, Lifetime::default()).expect("issuer");
    let svid = agent
        .issue(&SpiffeId::for_workload(&domain(), "api").expect("ID"), NOW)
        .expect("SVID");

    // And the whole chain carries up to the control plane's anchor.
    let anchor_der = CertificateDer::from(fixture.anchor.clone());
    let trust = webpki::anchor_from_trusted_cert(&anchor_der).expect("anchor");
    let leaf_der = CertificateDer::from(svid.certificate_der().to_vec());
    let cert = webpki::EndEntityCert::try_from(&leaf_der).expect("readable");
    let chain = [CertificateDer::from(
        intermediate.certificate_der().to_vec(),
    )];

    cert.verify_for_usage(
        &[webpki::ring::ED25519],
        &[trust],
        &chain,
        UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(NOW + 60).expect("after 1970"),
        )),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .expect("leaf -> agent intermediate -> anchor must carry");
}

/// A leaf may sign **nothing** -- the chain breaks when it tries.
#[test]
fn a_leaf_cannot_act_as_a_ca() {
    let fixture = fixture();
    let leaf = fixture
        .authority
        .certify(
            &SpiffeId::for_node(&domain(), "node-1").expect("ID"),
            &rcgen::PublicKeyData::subject_public_key_info(&fixture.applicant),
            Purpose::Leaf,
            Lifetime::default(),
            NOW,
        )
        .expect("certified");

    let ca = tg_identity::Ca::from_pem(leaf.certificate_pem()).expect("readable");
    let signer = LocalSigner::from_pem(&fixture.applicant.serialize_pem()).expect("key");
    let pretender = Authority::new(ca, signer, Lifetime::default()).expect("issuer");
    let svid = pretender
        .issue(&SpiffeId::for_workload(&domain(), "api").expect("ID"), NOW)
        .expect("technically issuable");

    // Much can be issued. Not verified.
    let anchor_der = CertificateDer::from(fixture.anchor.clone());
    let trust = webpki::anchor_from_trusted_cert(&anchor_der).expect("anchor");
    let leaf_der = CertificateDer::from(svid.certificate_der().to_vec());
    let cert = webpki::EndEntityCert::try_from(&leaf_der).expect("readable");
    let chain = [CertificateDer::from(leaf.certificate_der().to_vec())];

    assert!(
        cert.verify_for_usage(
            &[webpki::ring::ED25519],
            &[trust],
            &chain,
            UnixTime::since_unix_epoch(Duration::from_secs(
                u64::try_from(NOW + 60).expect("after 1970")
            )),
            webpki::KeyUsage::client_auth(),
            None,
            None,
        )
        .is_err(),
        "a leaf as a CA must not get through"
    );
}

/// An unreadable SPKI is refused, not certified.
#[test]
fn an_unreadable_public_key_is_refused() {
    let fixture = fixture();

    assert!(
        fixture
            .authority
            .certify(
                &SpiffeId::for_node(&domain(), "node-1").expect("ID"),
                b"that is no SPKI",
                Purpose::Leaf,
                Lifetime::default(),
                NOW,
            )
            .is_err()
    );
}
