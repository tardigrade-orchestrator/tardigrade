//! **The sidecar's `Debug` does not show its key material.**
//!
//! The witness for a deliberate safeguard in `tg_proxy::identity`: `Identity`
//! holds the PKCS#8 material of the SVID this sidecar puts on the wire -- in
//! a naked `Vec<u8>`, that is, without the protection `rcgen::KeyPair` and
//! `frost`'s `SigningShare` bring along of their own accord.
//!
//! The occasion is a measurement at a comparable place elsewhere in the
//! tree: a node identity type's derived `Debug` printed the private node key
//! in plaintext. It was printed nowhere -- but this repo's house rules
//! demand `Debug` on every type, and whoever puts an `Identity` into a
//! derived one brings it into every log line that takes this type along in
//! passing. And in the sidecar such a line is especially likely: all
//! rejection paths report there.

use tg_identity::{Authority, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};
use tg_proxy::identity::Identity;

/// Verifies that `Identity`'s `Debug` output stays short and never contains
/// the private key bytes, while still naming the workload it belongs to.
#[test]
fn the_sidecar_identity_does_not_print_its_key() {
    let domain = TrustDomain::new("cluster.local").expect("the domain");
    let signer = LocalSigner::generate().expect("the key");
    let ca = self_signed_ca(&domain, &signer, 0, 10 * 365 * 24 * 60 * 60).expect("the CA");
    let authority = Authority::new(ca, signer, Lifetime::default()).expect("the issuer");
    let id = SpiffeId::for_workload(&domain, "api").expect("the identifier");
    let svid = authority.issue(&id, 1_800_000_000).expect("the SVID");

    let identity = Identity::new(
        &id.to_string(),
        vec![svid.certificate_der().to_vec()],
        svid.private_key_der().to_vec(),
    )
    .expect("the identity");

    let text = format!("{identity:?}");
    // The key as DER, hex -- the form in which a `Vec<u8>` is printed is a
    // number sequence; what is checked is therefore the **first** value of the
    // material and that the output stays short.
    assert!(
        text.len() < 200,
        "the Debug is so long that material stands in it: {text}"
    );
    let bytes = svid.private_key_der();
    let head = format!("{}, {}, {}", bytes[0], bytes[1], bytes[2]);
    assert!(
        !text.contains(&head),
        "the Debug prints the key bytes: {text}"
    );
    // The counter direction: it says nevertheless whose identity it is -- a
    // `Debug` that shows nothing helps with no diagnosis.
    assert!(text.contains("api"), "{text}");
}
