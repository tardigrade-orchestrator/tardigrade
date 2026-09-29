//! **No `Debug` shows a secret** (ADR-0014, ADR-0037, ADR-0095).
//!
//! The occasion is a measurement: `NodeIdentity`'s derived `Debug` printed the
//! private node key in the clear -- 1895 bytes with `-----BEGIN PRIVATE KEY-----` in
//! it. It was printed nowhere, but this repo's house rules demand `Debug` on every
//! type, and whoever lays a `NodeIdentity` into a derived type brings it into every
//! log line that carries this type along in passing.
//!
//! The tree's libraries show how: `rcgen::KeyPair` prints
//! `serialized_der: "[secret key elided]"`, `frost`'s `SigningShare` `"<redacted>"`.
//! It leaked where we **took** the material out of its type and laid it in a naked
//! `String` or `Vec<u8>`.
//!
//! The bolt is a **manual** `Debug`: a later `#[derive(Debug)]` is afterwards a
//! compile error and no quiet change. The witnesses here hold the effect fast -- that
//! it is there is seen by the compiler.

use tg_identity::{
    Authority, Lifetime, LocalSigner, NodeIdentity, SpiffeId, TrustDomain, self_signed_ca,
};

/// An Ed25519 key together with its PEM form.
fn keypair() -> (rcgen::KeyPair, String) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let pem = key.serialize_pem();
    (key, pem)
}

/// The key's bytes, without the PEM frame lines.
fn body(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

#[test]
fn a_node_identity_does_not_print_its_key() {
    let (key, pem) = keypair();
    let domain = TrustDomain::new("cluster.local").expect("domain");
    let id = SpiffeId::for_node(&domain, "tgd-1").expect("identifier");
    let identity = NodeIdentity::new(&key, id).expect("identity");

    let text = format!("{identity:?}");
    assert!(
        !text.contains("PRIVATE KEY"),
        "the Debug prints the key: {text}"
    );
    assert!(
        !text.contains(&body(&pem)),
        "the Debug prints the key bytes"
    );
    // And the counter-direction: it nevertheless says **whose** identity it is -- a
    // `Debug` that shows nothing helps with no diagnosis.
    assert!(text.contains("tgd-1"), "{text}");
}

#[test]
fn an_svid_does_not_print_its_key() {
    let domain = TrustDomain::new("cluster.local").expect("domain");
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain, &signer, 0, 10 * 365 * 24 * 60 * 60).expect("CA");
    let authority = Authority::new(ca, signer, Lifetime::default()).expect("issuer");
    let id = SpiffeId::for_workload(&domain, "api").expect("identifier");
    let svid = authority.issue(&id, 1_800_000_000).expect("SVID");

    let text = format!("{svid:?}");
    assert!(
        !text.contains("PRIVATE KEY"),
        "the Debug prints the key: {text}"
    );
    assert!(
        !text.contains(&body(svid.private_key_pem())),
        "the Debug prints the key bytes"
    );
    assert!(text.contains("api"), "{text}");
}

#[test]
fn a_join_request_does_not_print_its_token() {
    let request = tg_identity::control::JoinRequest {
        node: "tgd-4".to_owned(),
        token: "a-very-secret-token-of-256-bits".to_owned(),
        spki: "AAAA".to_owned(),
        underlay: None,
    };

    let text = format!("{request:?}");
    assert!(
        !text.contains("a-very-secret-token"),
        "the Debug prints the token: {text}"
    );
    assert!(text.contains("tgd-4"), "{text}");
}
