//! What a renewal request's signature covers (ADR-0042, ADR-0046).
//!
//! Until ADR-0042 it covered **only the nonce**. That sufficed against replay and no
//! longer suffices as soon as the request carries a setting that has an effect.
//! ADR-0042 thereupon **enumerated** the scope and overlooked `intermediate_spki`;
//! ADR-0046 turns the enumeration into a property.
//!
//! The test this file carries is therefore
//! [`every_field_of_the_request_is_covered`]: it runs over the request's **own**
//! fields. The others record individual properties that cannot be read off it.
//!
//! Pure logic, therefore **tests first** (CLAUDE.md).

use tg_identity::control::{RenewRequest, Underlay, renew_message};

fn underlay(key: &str, endpoint: &str) -> Underlay {
    Underlay {
        key: key.to_owned(),
        endpoint: endpoint.to_owned(),
    }
}

/// A request as the agent makes it.
fn request(nonce: &str, underlay: Option<Underlay>) -> RenewRequest {
    RenewRequest {
        node: "tgd-2".to_owned(),
        nonce: nonce.to_owned(),
        signature: "ZmFrZQ==".to_owned(),
        intermediate_spki: "aW50ZXJtZWRpYXRl".to_owned(),
        // ADR-0055: the new node key's SPKI, when a rotation happens.
        next_node_spki: Some("bmV1ZXItc2NobHVlc3NlbA==".to_owned()),
        underlay,
    }
}

/// **Every field of the request is covered -- except the signature itself.**
///
/// The test ADR-0046 is about, and it deliberately does **not** enumerate. It
/// serializes the request, runs over its own keys and alters one after the other;
/// every alteration must yield different bytes to be signed.
///
/// With that the assurance applies to fields that do not exist yet: whoever adds one
/// and does not touch `renew_message` makes this test red. A second list in the test
/// would be a second opportunity to forget the same thing.
#[test]
fn every_field_of_the_request_is_covered() {
    let original = request("bm9uY2U=", Some(underlay("k", "10.0.0.1:51820")));
    let baseline = renew_message(&original);

    let json = serde_json::to_value(&original).expect("request");
    let fields: Vec<String> = json
        .as_object()
        .expect("object")
        .keys()
        .map(String::clone)
        .collect();
    assert!(
        fields.len() >= 5,
        "the request has unexpectedly few fields: {fields:?}"
    );

    for field in &fields {
        let mut mutated = json.clone();
        let slot = mutated
            .as_object_mut()
            .expect("object")
            .get_mut(field)
            .expect("field");
        // What is altered is the value, not its shape: from one string another,
        // from the announcement one with a different endpoint. A type change would
        // fail at the read-in already and would prove nothing.
        *slot = match slot {
            serde_json::Value::String(text) => serde_json::Value::String(format!("{text}-altered")),
            serde_json::Value::Object(_) => {
                serde_json::to_value(underlay("k", "10.0.0.99:51820")).expect("announcement")
            }
            other => panic!("an unexpected field type in '{field}': {other}"),
        };

        let changed: RenewRequest = serde_json::from_value(mutated).expect("request");
        let message = renew_message(&changed);

        if field == "signature" {
            assert_eq!(
                message, baseline,
                "the signature covers itself -- that would yield a circle"
            );
        } else {
            assert_ne!(
                message, baseline,
                "the field '{field}' is not covered by the signature"
            );
        }
    }
}

/// **`intermediate_spki` is covered** (ADR-0046).
///
/// The ADR's occasion, and it stands here on its own because the test above sees it
/// only as one of many fields. It is the key for which `tgd` issues the agent
/// intermediate -- the authority to mint workload SVIDs (ADR-0006). ADR-0042
/// overlooked it although it already stood in the request then.
#[test]
fn changing_the_intermediate_key_changes_what_is_signed() {
    let mut tampered = request("bm9uY2U=", None);
    tampered.intermediate_spki = "ZnJlbWQ=".to_owned();

    assert_ne!(
        renew_message(&request("bm9uY2U=", None)),
        renew_message(&tampered)
    );
}

/// The node name is covered likewise. It is harmless -- it selects the key against
/// which the check happens, so a wrong setting fails at that. It is covered along all
/// the same: leaving a field out because one has just reasoned out its harmlessness is
/// the way of thinking ADR-0046 arose from.
#[test]
fn the_node_name_is_covered_although_it_is_harmless() {
    let mut other = request("bm9uY2U=", None);
    other.node = "tgd-3".to_owned();

    assert_ne!(
        renew_message(&request("bm9uY2U=", None)),
        renew_message(&other)
    );
}

/// **The endpoint is covered along.**
///
/// The test at issue. Whoever intercepted a `Renew` call and swapped the endpoint
/// would thereby have steered the whole cluster traffic for this node to a foreign
/// address -- encrypted, but to the wrong party. Without this assurance the signature
/// would stay valid in the process.
#[test]
fn changing_the_endpoint_changes_what_is_signed() {
    let nonce = "bm9uY2U=";

    let honest = renew_message(&request(nonce, Some(underlay("k", "10.0.0.1:51820"))));
    let tampered = renew_message(&request(nonce, Some(underlay("k", "10.0.0.99:51820"))));

    assert_ne!(honest, tampered);
}

/// The key likewise.
#[test]
fn changing_the_key_changes_what_is_signed() {
    let nonce = "bm9uY2U=";

    assert_ne!(
        renew_message(&request(nonce, Some(underlay("k1", "10.0.0.1:51820")))),
        renew_message(&request(nonce, Some(underlay("k2", "10.0.0.1:51820"))))
    );
}

/// The nonce likewise -- the replay barrier from ADR-0037 stays.
#[test]
fn the_nonce_is_still_covered() {
    let announcement = underlay("k", "10.0.0.1:51820");

    assert_ne!(
        renew_message(&request("one", Some(announcement.clone()))),
        renew_message(&request("two", Some(announcement.clone())))
    );
}

/// **An announcement cannot be removed without breaking the signature.**
///
/// A request without an announcement and one with an announcement are two different
/// statements. If the absence did not count along, the announcement could be struck
/// from an intercepted request -- and the node would lose its underlay without
/// anybody noticing.
#[test]
fn an_announcement_cannot_be_stripped_silently() {
    let nonce = "bm9uY2U=";

    assert_ne!(
        renew_message(&request(nonce, Some(underlay("k", "10.0.0.1:51820")))),
        renew_message(&request(nonce, None))
    );
}

/// **Content cannot be shifted from one field into the next.**
///
/// Without a length prefix `key="ab", endpoint="c"` and `key="a", endpoint="bc"` would
/// yield the same bytes -- and a signature over the one request would apply to the
/// other. The same consideration as at the audit digest from phase 11a.
#[test]
fn content_cannot_be_shifted_between_fields() {
    let nonce = "n";

    assert_ne!(
        renew_message(&request(nonce, Some(underlay("ab", "c")))),
        renew_message(&request(nonce, Some(underlay("a", "bc"))))
    );
}

/// And not between nonce and announcement either.
#[test]
fn content_cannot_be_shifted_out_of_the_nonce() {
    assert_ne!(
        renew_message(&request("ab", Some(underlay("c", "d")))),
        renew_message(&request("a", Some(underlay("bc", "d"))))
    );
}

/// The same input yields the same bytes -- otherwise nobody could check what was
/// signed.
#[test]
fn the_same_input_yields_the_same_bytes() {
    let announcement = underlay("k", "10.0.0.1:51820");

    assert_eq!(
        renew_message(&request("n", Some(announcement.clone()))),
        renew_message(&request("n", Some(announcement.clone())))
    );
}

/// **The old form is no longer valid.**
///
/// ADR-0042 is a protocol break and no additive supplement: a node that goes on
/// signing only the nonce is refused. That stands so in the ADR's consequences, and
/// here it stands as a test -- so that nobody later takes the break for an
/// oversight.
#[test]
fn signing_the_bare_nonce_is_no_longer_the_message() {
    let nonce = "bm9uY2U=";

    assert_ne!(renew_message(&request(nonce, None)), nonce.as_bytes());
}
