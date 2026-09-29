//! The credential on the cluster transports (ADR-0043).
//!
//! Pure logic: a presented leaf, a registration, a verdict. No network, no clock, no
//! CA -- exactly that is the assurance from determination 1.
//!
//! The emphasis lies on what must **not** get through. A verifier whose refusal paths
//! nobody has ever seen is one that is used for the first time in an emergency.

use rustls_pki_types::CertificateDer;
use tg_identity::cluster::{ClusterVerifyError, NodeTrust, check, node_leaf};
use tg_identity::{Role, SpiffeId, TrustDomain};

/// A node with its own key and a self-issued leaf.
struct Node {
    id: SpiffeId,
    key: rcgen::KeyPair,
    leaf: Vec<u8>,
}

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("trust domain")
}

fn node(name: &str) -> Node {
    let domain = domain();
    let id = SpiffeId::for_node(&domain, name).expect("node ID");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let leaf = node_leaf(&key, &id).expect("leaf");

    Node { id, key, leaf }
}

fn workload(name: &str) -> Node {
    let domain = domain();
    let id = SpiffeId::for_workload(&domain, name).expect("workload ID");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let leaf = node_leaf(&key, &id).expect("leaf");

    Node { id, key, leaf }
}

fn spki(key: &rcgen::KeyPair) -> Vec<u8> {
    use rcgen::PublicKeyData as _;

    key.subject_public_key_info()
}

fn der(leaf: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from(leaf.to_vec())
}

fn registry(nodes: &[&Node]) -> NodeTrust {
    let mut trust = NodeTrust::new();
    for entry in nodes {
        let name = entry.id.node().expect("node role");
        trust.insert(name, spki(&entry.key));
    }
    trust
}

// --- The normal case --------------------------------------------------------

/// A registered node is accepted, and `check` returns its identity -- the name thereby
/// comes from the connection (ADR-0040, determination 8).
#[test]
fn a_registered_node_is_accepted_and_names_itself() {
    let peer = node("node-1");
    let trust = registry(&[&peer]);

    let seen = check(&der(&peer.leaf), Role::Node, &domain(), &trust, None).expect("accepted");

    assert_eq!(seen, peer.id);
    assert_eq!(seen.node(), Some("node-1"));
    assert_eq!(seen.role(), Role::Node);
}

/// If the caller expects a particular counter-node and gets it, it is good. That is
/// the client side: it knows whom it dialled.
#[test]
fn the_expected_peer_is_accepted() {
    let peer = node("node-2");
    let trust = registry(&[&peer]);

    let seen = check(
        &der(&peer.leaf),
        Role::Node,
        &domain(),
        &trust,
        Some("node-2"),
    )
    .expect("accepted");

    assert_eq!(seen.node(), Some("node-2"));
}

/// Several registrations do not disturb each other: each is recognized as itself.
#[test]
fn several_registered_nodes_are_told_apart() {
    let one = node("node-1");
    let two = node("node-2");
    let trust = registry(&[&one, &two]);

    assert_eq!(
        check(&der(&one.leaf), Role::Node, &domain(), &trust, None)
            .expect("one")
            .node(),
        Some("node-1")
    );
    assert_eq!(
        check(&der(&two.leaf), Role::Node, &domain(), &trust, None)
            .expect("two")
            .node(),
        Some("node-2")
    );
}

// --- The refusals -----------------------------------------------------------

/// **The heart of the matter:** the same name, a different key.
///
/// That is what the attack determination 1 wards off looks like -- the name in the SAN
/// is an index and no proof. Whoever names another's name must hold its key.
#[test]
fn the_right_name_with_the_wrong_key_is_refused() {
    let real = node("node-1");
    let trust = registry(&[&real]);

    // An attacker with its own key that calls itself node-1.
    let forged = node("node-1");
    assert_ne!(spki(&forged.key), spki(&real.key));

    let err = check(&der(&forged.leaf), Role::Node, &domain(), &trust, None).expect_err("refused");

    assert!(
        matches!(&err, ClusterVerifyError::KeyMismatch { node } if node == "node-1"),
        "expected KeyMismatch, was {err:?}"
    );
    assert!(
        err.to_string().contains("node-1"),
        "the message does not name the node: {err}"
    );
}

/// A node nobody admitted does not get through -- even when its leaf is perfectly in
/// order. Deny-by-default.
#[test]
fn an_unregistered_node_is_refused() {
    let known = node("node-1");
    let stranger = node("node-9");
    let trust = registry(&[&known]);

    let err =
        check(&der(&stranger.leaf), Role::Node, &domain(), &trust, None).expect_err("refused");

    assert!(
        matches!(&err, ClusterVerifyError::Unregistered { node } if node == "node-9"),
        "expected Unregistered, was {err:?}"
    );
}

/// An empty registration lets nobody through. The case counts because it is the state
/// at the start: a misconfiguration must not tip over into "everything permitted".
#[test]
fn an_empty_registry_refuses_everyone() {
    let peer = node("node-1");

    let err = check(
        &der(&peer.leaf),
        Role::Node,
        &domain(),
        &NodeTrust::new(),
        None,
    )
    .expect_err("refused");

    assert!(
        matches!(err, ClusterVerifyError::Unregistered { .. }),
        "erwartet Unregistered, war {err:?}"
    );
}

/// The client side caught a different one from the one it dialled. The peer is real
/// and registered -- and the wrong one all the same.
#[test]
fn a_registered_but_unexpected_peer_is_refused() {
    let one = node("node-1");
    let two = node("node-2");
    let trust = registry(&[&one, &two]);

    let err = check(
        &der(&two.leaf),
        Role::Node,
        &domain(),
        &trust,
        Some("node-1"),
    )
    .expect_err("refused");

    assert!(
        matches!(
            &err,
            ClusterVerifyError::Unexpected { expected, got }
                if expected == "node-1" && got == "node-2"
        ),
        "expected Unexpected, was {err:?}"
    );
}

/// A workload SVID is no node credential. The role is checked, not merely the name --
/// otherwise a container with a valid SVID would get onto the consensus port.
#[test]
fn a_workload_svid_is_not_a_node_credential() {
    let sidecar = workload("api");
    let mut trust = NodeTrust::new();
    // Even if its key were entered under the name.
    trust.insert("api", spki(&sidecar.key));

    let err = check(&der(&sidecar.leaf), Role::Node, &domain(), &trust, None).expect_err("refused");

    assert!(
        matches!(
            err,
            ClusterVerifyError::WrongRole {
                expected: "node",
                ..
            }
        ),
        "expected WrongRole{{node}}, was {err:?}"
    );
}

/// A foreign trust domain is refused, even with a matching name and a matching key.
/// Otherwise a cluster beside it would suffice.
#[test]
fn a_foreign_trust_domain_is_refused() {
    let foreign = TrustDomain::new("other.cluster").expect("trust domain");
    let id = SpiffeId::for_node(&foreign, "node-1").expect("ID");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let leaf = node_leaf(&key, &id).expect("leaf");

    let mut trust = NodeTrust::new();
    trust.insert("node-1", spki(&key));

    let err = check(&der(&leaf), Role::Node, &domain(), &trust, None).expect_err("refused");

    assert!(
        matches!(
            &err,
            ClusterVerifyError::ForeignTrustDomain { expected, got }
                if expected == "cluster.local" && got == "other.cluster"
        ),
        "expected ForeignTrustDomain, was {err:?}"
    );
}

/// A leaf without a URI SAN carries no identity.
#[test]
fn a_leaf_without_a_uri_san_is_refused() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let leaf = params
        .self_signed(&key)
        .expect("self-issued")
        .der()
        .to_vec();

    let mut trust = NodeTrust::new();
    trust.insert("node-1", spki(&key));

    let err = check(&der(&leaf), Role::Node, &domain(), &trust, None).expect_err("refused");

    assert!(
        matches!(err, ClusterVerifyError::NoSpiffeId { .. }),
        "expected NoSpiffeId, was {err:?}"
    );
}

/// Unreadable bytes are a refusal and no crash. They come from the counterpart, that
/// is, from the network.
#[test]
fn unreadable_bytes_are_refused_not_fatal() {
    let cases: [&[u8]; 5] = [
        b"",
        b"\x00",
        b"not the breath of a certificate",
        &[0x30, 0x82, 0xff, 0xff],
        &[0x30; 64],
    ];

    for raw in cases {
        let err = check(
            &CertificateDer::from(raw.to_vec()),
            Role::Node,
            &domain(),
            &NodeTrust::new(),
            None,
        )
        .expect_err("refused");

        assert!(
            matches!(err, ClusterVerifyError::Unreadable { .. }),
            "expected Unreadable for {raw:?}, was {err:?}"
        );
    }
}

// --- Intentions one could later take for errors ------------------------------

/// **An expired leaf is accepted, and that is deliberate.**
///
/// ADR-0043, determination 1: what is checked is the key against the registration, not
/// the chain against a CA and not the deadline against a clock. If the admission hung
/// on a deadline, it could expire while the instance that would have to extend it lies
/// there without a quorum -- the circle from the ADR.
///
/// The test stands here so that nobody can later "repair" it without building the
/// circle back in.
#[test]
fn an_expired_leaf_is_still_accepted_on_purpose() {
    use time::OffsetDateTime;

    let domain = domain();
    let id = SpiffeId::for_node(&domain, "node-1").expect("ID");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");

    let mut params = rcgen::CertificateParams::default();
    params.not_before = OffsetDateTime::from_unix_timestamp(1_000_000).expect("time");
    params.not_after = OffsetDateTime::from_unix_timestamp(1_000_060).expect("time");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.subject_alt_names = vec![rcgen::SanType::URI(id.to_string().try_into().expect("URI"))];
    let leaf = params
        .self_signed(&key)
        .expect("self-issued")
        .der()
        .to_vec();

    let mut trust = NodeTrust::new();
    trust.insert("node-1", spki(&key));

    let seen =
        check(&der(&leaf), Role::Node, &domain, &trust, None).expect("accepted although expired");

    assert_eq!(seen.node(), Some("node-1"));
}

/// The revocation is the removal from the registration -- and it takes effect
/// immediately.
#[test]
fn removing_a_node_from_the_registry_refuses_it() {
    let peer = node("node-1");
    let mut trust = registry(&[&peer]);

    check(&der(&peer.leaf), Role::Node, &domain(), &trust, None).expect("accepted at first");

    trust.remove("node-1");

    let err = check(&der(&peer.leaf), Role::Node, &domain(), &trust, None)
        .expect_err("refused afterwards");
    assert!(
        matches!(err, ClusterVerifyError::Unregistered { .. }),
        "expected Unregistered, was {err:?}"
    );
}

// --- The registration itself ------------------------------------------------

/// base64 entries are read, unusable ones refused. They come from the log or from the
/// disk, that is, from outside.
#[test]
fn the_registry_reads_base64_and_refuses_rubbish() {
    let peer = node("node-1");
    let encoded = tg_identity::control::base64(&spki(&peer.key));

    let trust = NodeTrust::from_base64([("node-1", encoded.as_str())]).expect("read");
    assert_eq!(trust.len(), 1);
    check(&der(&peer.leaf), Role::Node, &domain(), &trust, None).expect("accepted");

    for bad in ["", "!!!!", "AAA", "ä"] {
        assert!(
            NodeTrust::from_base64([("node-1", bad)]).is_err(),
            "'{bad}' should have been refused"
        );
    }
}

/// An empty name is no name. It would come from a log entry nobody meant that way, and
/// it would fit a leaf that does not carry it.
#[test]
fn an_empty_node_name_is_refused_by_the_registry() {
    let peer = node("node-1");
    let encoded = tg_identity::control::base64(&spki(&peer.key));

    assert!(
        NodeTrust::from_base64([("", encoded.as_str())]).is_err(),
        "an empty name should have been refused"
    );
}

/// **The leaf's time window is usable for foreign tools.**
///
/// [`check`] does not look at it (see above), and exactly for that reason it can be
/// wrong unnoticed: the first attempt set it to the Unix epoch, that is 1970 to 1980,
/// and `openssl s_client` reported "certificate has expired". It stood out at a
/// counter-check with foreign code, not at a test of our own -- that is why one stands
/// here now.
#[test]
fn the_leaf_is_valid_now_for_tools_that_do_look_at_the_clock() {
    let peer = node("node-1");
    let (_, parsed) = x509_parser::parse_x509_certificate(&peer.leaf).expect("readable");

    let validity = parsed.validity();
    assert!(
        validity.is_valid(),
        "the leaf does not apply now: {} to {}",
        validity.not_before,
        validity.not_after
    );

    // And it applies long enough that an operator does not go looking for it.
    let years = (validity.not_after.timestamp() - validity.not_before.timestamp()) / 31_536_000;
    assert!(years >= 9, "the window is only {years} years wide");
}
