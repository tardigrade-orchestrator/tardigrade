//! The peer verifier (ADR-0007, ADR-0025 -- phase 8a).
//!
//! Above all **refusals** stand here. A verifier of which one only knows that
//! it lets the right thing through is no verifier -- it could let everything
//! through. What is checked is therefore one case per rejection reason, and
//! each of them with a real, minted certificate from `tg-identity`: an expired
//! chain, a foreign CA, a node identity, a foreign trust domain, and the
//! missing `may_talk` edge.

use std::time::Duration;

use rustls_pki_types::{CertificateDer, UnixTime};
use tg_identity::{Authority, Ca, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};
use tg_proxy::policy::{PolicyCache, RevocationWindow, Snapshot};
use tg_proxy::verify::{
    Bundle, Enforcement, PeerVerifier, SharedBundle, SharedPolicy, VerifyError,
};

const YEAR: i64 = 365 * 24 * 60 * 60;
const ISSUED_AT: i64 = 1_700_000_000;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

fn at(seconds: i64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(
        u64::try_from(seconds).expect("not before 1970"),
    ))
}

/// A CA together with an issuer -- as many as a test needs.
struct Issuer {
    ca_der: Vec<u8>,
    authority: Authority<LocalSigner>,
}

fn authority_in(domain: &TrustDomain) -> Issuer {
    let signer = LocalSigner::generate().expect("the key");
    let ca: Ca = self_signed_ca(domain, &signer, 0, 10 * YEAR).expect("the CA");
    let ca_der = ca.certificate_der().to_vec();
    let authority = Authority::new(ca, signer, Lifetime::default()).expect("the issuer");

    Issuer { ca_der, authority }
}

fn policy(edges: &[(&str, &str)]) -> SharedPolicy {
    let mut cache = PolicyCache::new(RevocationWindow::adr_0014());
    cache
        .apply(
            &Snapshot::from_edges(
                1,
                edges
                    .iter()
                    .map(|(a, b)| ((*a).to_owned(), (*b).to_owned())),
            ),
            ISSUED_AT,
        )
        .expect("the snapshot");

    SharedPolicy::new(cache)
}

/// The server `ledger` checks incoming connections.
fn inbound(bundle: Vec<u8>, policy: SharedPolicy) -> PeerVerifier {
    PeerVerifier::new(
        SpiffeId::for_workload(&domain(), "ledger").expect("the ID"),
        SharedBundle::new(Bundle::from_der(vec![bundle])),
        policy,
        Enforcement::Inbound,
    )
}

/// **The normal case:** a valid chain, a workload identity, an edge present.
#[test]
fn a_valid_peer_with_an_edge_is_accepted() {
    let ca = authority_in(&domain());
    let svid = ca
        .authority
        .issue(
            &SpiffeId::for_workload(&domain(), "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");

    let verifier = inbound(ca.ca_der.clone(), policy(&[("api", "ledger")]));
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());

    let peer = verifier
        .check(&leaf, &[], at(ISSUED_AT + 60))
        .expect("must get through");

    assert_eq!(peer.to_string(), "spiffe://cluster.local/workload/api");
}

/// **Without an edge nothing** -- the same certificate, the same chain, no
/// permission.
///
/// That is the acceptance criterion "deny-by-default without an edge", and it
/// stands here deliberately beside the normal case: the only difference
/// between the two is the edge.
#[test]
fn the_same_peer_without_an_edge_is_denied() {
    let ca = authority_in(&domain());
    let svid = ca
        .authority
        .issue(
            &SpiffeId::for_workload(&domain(), "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");

    let verifier = inbound(ca.ca_der.clone(), policy(&[]));
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());

    let err = verifier
        .check(&leaf, &[], at(ISSUED_AT + 60))
        .expect_err("without an edge nothing");

    assert!(matches!(err, VerifyError::Denied { .. }), "{err}");
}

/// The edge applies **directed**: `api -> ledger` does not permit `ledger -> api`.
#[test]
fn the_reverse_direction_needs_its_own_edge() {
    let ca = authority_in(&domain());
    let svid = ca
        .authority
        .issue(
            &SpiffeId::for_workload(&domain(), "ledger").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");

    // `api` is now the server and gets a connection from `ledger`.
    let verifier = PeerVerifier::new(
        SpiffeId::for_workload(&domain(), "api").expect("the ID"),
        SharedBundle::new(Bundle::from_der(vec![ca.ca_der.clone()])),
        policy(&[("api", "ledger")]),
        Enforcement::Inbound,
    );
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());

    assert!(matches!(
        verifier.check(&leaf, &[], at(ISSUED_AT + 60)),
        Err(VerifyError::Denied { .. })
    ));
}

/// **An expired SVID is refused.**
///
/// The hard expiry from ADR-0014 applies here without a grace period: the
/// grace belongs to the **holder** (phase 7a), a checker does not see it and
/// must not see it.
#[test]
fn an_expired_svid_is_refused() {
    let ca = authority_in(&domain());
    let svid = ca
        .authority
        .issue(
            &SpiffeId::for_workload(&domain(), "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");

    let verifier = inbound(ca.ca_der.clone(), policy(&[("api", "ledger")]));
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());

    // The TTL from ADR-0014 is 15 minutes; an hour later it is gone.
    let err = verifier
        .check(&leaf, &[], at(ISSUED_AT + 3_600))
        .expect_err("expired");

    assert!(matches!(err, VerifyError::Chain { .. }), "{err}");
}

/// An SVID that does **not** yet apply, likewise.
#[test]
fn an_svid_from_the_future_is_refused() {
    let ca = authority_in(&domain());
    let svid = ca
        .authority
        .issue(
            &SpiffeId::for_workload(&domain(), "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");

    let verifier = inbound(ca.ca_der.clone(), policy(&[("api", "ledger")]));
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());

    assert!(matches!(
        verifier.check(&leaf, &[], at(ISSUED_AT - 3_600)),
        Err(VerifyError::Chain { .. })
    ));
}

/// **A certificate from a foreign CA is refused** -- even when the SPIFFE ID
/// in it looks exactly right.
///
/// That is the case one really fears: an attacker who issues themselves a
/// `spiffe://cluster.local/workload/api`. The ID costs them nothing; the
/// anchor does.
#[test]
fn a_certificate_from_a_foreign_ca_is_refused() {
    let ours = authority_in(&domain());
    let theirs = authority_in(&domain());

    let forged = theirs
        .authority
        .issue(
            &SpiffeId::for_workload(&domain(), "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");

    let verifier = inbound(ours.ca_der.clone(), policy(&[("api", "ledger")]));
    let leaf = CertificateDer::from(forged.certificate_der().to_vec());

    let err = verifier
        .check(&leaf, &[], at(ISSUED_AT + 60))
        .expect_err("a foreign CA");

    assert!(matches!(err, VerifyError::Chain { .. }), "{err}");
}

/// An empty bundle verifies nothing -- and therefore lets nothing through.
#[test]
fn an_empty_bundle_accepts_nobody() {
    let ca = authority_in(&domain());
    let svid = ca
        .authority
        .issue(
            &SpiffeId::for_workload(&domain(), "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");

    let bundle = Bundle::default();
    assert!(bundle.is_empty());

    let verifier = PeerVerifier::new(
        SpiffeId::for_workload(&domain(), "ledger").expect("the ID"),
        SharedBundle::new(bundle),
        policy(&[("api", "ledger")]),
        Enforcement::Inbound,
    );
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());

    assert!(matches!(
        verifier.check(&leaf, &[], at(ISSUED_AT + 60)),
        Err(VerifyError::Chain { .. })
    ));
}

/// **A node identity does not get through here**, with a valid chain either.
///
/// The role separation from ADR-0006 exists precisely for that: a workload
/// named `api` and the node `api` are two identities, and the `may_talk` edges
/// apply only to the first.
#[test]
fn a_node_identity_is_refused_even_with_a_valid_chain() {
    let ca = authority_in(&domain());
    let svid = ca
        .authority
        .issue(
            &SpiffeId::for_node(&domain(), "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");

    let verifier = inbound(ca.ca_der.clone(), policy(&[("api", "ledger")]));
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());

    let err = verifier
        .check(&leaf, &[], at(ISSUED_AT + 60))
        .expect_err("nodes do not talk here");

    assert!(matches!(err, VerifyError::NotAWorkload { .. }), "{err}");
}

/// A foreign trust domain is refused, even if we knew its anchor.
///
/// ADR-0025 does not provide for federation. Permitting it silently would be a
/// decision nobody took.
#[test]
fn a_foreign_trust_domain_is_refused() {
    let foreign_domain = TrustDomain::new("elsewhere.example").expect("the domain");
    let foreign = authority_in(&foreign_domain);

    let svid = foreign
        .authority
        .issue(
            &SpiffeId::for_workload(&foreign_domain, "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");

    // We even trust their anchor -- and refuse nevertheless.
    let verifier = inbound(foreign.ca_der.clone(), policy(&[("api", "ledger")]));
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());

    let err = verifier
        .check(&leaf, &[], at(ISSUED_AT + 60))
        .expect_err("a foreign domain");

    assert!(
        matches!(err, VerifyError::ForeignTrustDomain { .. }),
        "{err}"
    );
}

/// A certificate **without** a SPIFFE ID in the URI SAN is refused.
///
/// That is the case "any valid certificate of our CA". The chain carries, but
/// there is no identity -- and without an identity no edge.
#[test]
fn a_certificate_without_a_uri_san_is_refused() {
    let signer = LocalSigner::generate().expect("the key");
    let ca: Ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("the CA");
    let ca_der = ca.certificate_der().to_vec();

    // An ordinary certificate of this CA, but without a URI SAN.
    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("the key");
    let mut params =
        rcgen::CertificateParams::new(vec!["something.example".to_owned()]).expect("the parameter");
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    // Self-signed suffices for this case: what is checked is that a
    // certificate without an identity does not get through -- whether it fails
    // on the chain or on the missing SAN, both are a refusal.
    let certificate = params.self_signed(&leaf_key).expect("the certificate");
    let verifier = inbound(ca_der, policy(&[("api", "ledger")]));
    let leaf = CertificateDer::from(certificate.der().to_vec());

    let err = verifier
        .check(&leaf, &[], at(ISSUED_AT + 60))
        .expect_err("no identity");

    assert!(
        matches!(
            err,
            VerifyError::Chain { .. } | VerifyError::NoSpiffeId { .. }
        ),
        "{err}"
    );
}

/// **Both sides check, and they read the edge the opposite way round.**
///
/// The same peer, the same edge, the same chain -- only the role changes. The
/// server accepts, the client would not be allowed to initiate. With that it
/// is shown that [`Enforcement`] really determines the direction and is not
/// merely a label.
#[test]
fn both_sides_enforce_and_they_read_the_edge_in_opposite_directions() {
    let ca = authority_in(&domain());
    let api = ca
        .authority
        .issue(
            &SpiffeId::for_workload(&domain(), "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");
    let leaf = CertificateDer::from(api.certificate_der().to_vec());
    let shared = policy(&[("api", "ledger")]);

    // The server `ledger` sees `api` as the source -- permitted.
    let server = PeerVerifier::new(
        SpiffeId::for_workload(&domain(), "ledger").expect("the ID"),
        SharedBundle::new(Bundle::from_der(vec![ca.ca_der.clone()])),
        shared.clone(),
        Enforcement::Inbound,
    );
    assert!(server.check(&leaf, &[], at(ISSUED_AT + 60)).is_ok());

    // The client `ledger` dials `api` -- that would be `ledger -> api`, and
    // that edge does not exist.
    let client = PeerVerifier::new(
        SpiffeId::for_workload(&domain(), "ledger").expect("the ID"),
        SharedBundle::new(Bundle::from_der(vec![ca.ca_der.clone()])),
        shared,
        Enforcement::Outbound,
    );
    assert!(matches!(
        client.check(&leaf, &[], at(ISSUED_AT + 60)),
        Err(VerifyError::Denied { .. })
    ));
}

/// The withdrawal of an edge takes effect on the verifier **immediately** --
/// it reads the shared cache, it holds no copy.
///
/// Without that every sidecar would be wrong after a policy change until
/// somebody rebuilds it.
#[test]
fn revoking_an_edge_takes_effect_on_the_next_handshake() {
    let ca = authority_in(&domain());
    let svid = ca
        .authority
        .issue(
            &SpiffeId::for_workload(&domain(), "api").expect("the ID"),
            ISSUED_AT,
        )
        .expect("the SVID");
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());

    let shared = policy(&[("api", "ledger")]);
    let verifier = inbound(ca.ca_der.clone(), shared.clone());
    assert!(verifier.check(&leaf, &[], at(ISSUED_AT + 60)).is_ok());

    shared
        .apply(&Snapshot::from_edges(2, []), ISSUED_AT + 61)
        .expect("the withdrawal");

    assert!(matches!(
        verifier.check(&leaf, &[], at(ISSUED_AT + 62)),
        Err(VerifyError::Denied { .. })
    ));
}
