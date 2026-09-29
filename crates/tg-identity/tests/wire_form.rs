//! The wire format of the credential path, nailed down (ADR-0037, ADR-0042).
//!
//! # Why it exists
//!
//! Two of this project's five format breaks lie here: ADR-0042 changed the scope of
//! the signature and introduced the announcement, ADR-0046 took `next_node_spki`
//! under the signature. Both were found by thinking about the types, not by a test --
//! and the plan carries them as a "coordinated transition", that is, as operations
//! work with an outage window.
//!
//! Then the moment at which a break **arises** is the most important one. Exactly that
//! is what this test makes visible.
//!
//! # What is to be done when it turns red
//!
//! Do not pull the expected string along. Red means: a format break arises here, it
//! belongs in the plan with the others, and the question is whether a
//! `#[serde(default)]` avoids it.
//!
//! **For `RenewRequest` a second question comes along**, and it weighs more heavily:
//! does [`tg_identity::control::renew_message`] cover the new field? The test beside
//! it (`renew_message.rs`) answers it by running over the request's own fields -- the
//! construction from ADR-0046.

use tg_identity::control::{JoinRequest, RenewRequest, Underlay};

/// **The join request has a fixed shape.**
#[test]
fn the_join_request_has_a_pinned_wire_form() {
    let request = JoinRequest {
        node: "node-2".to_owned(),
        token: "secret".to_owned(),
        spki: "AAAA".to_owned(),
        underlay: Some(Underlay {
            key: "BBBB".to_owned(),
            endpoint: "10.0.0.2:51820".to_owned(),
        }),
    };

    assert_eq!(
        serde_json::to_string(&request).expect("encodable"),
        r#"{"node":"node-2","token":"secret","spki":"AAAA","underlay":{"key":"BBBB","endpoint":"10.0.0.2:51820"}}"#,
        "the join's wire format has changed -- see the module head"
    );
}

/// **The renewal request likewise** -- with **every** field filled.
///
/// An empty field would conceal the question at issue: whether it appears on the wire
/// at all and what it is called.
#[test]
fn the_renew_request_has_a_pinned_wire_form() {
    let request = RenewRequest {
        node: "node-2".to_owned(),
        nonce: "CCCC".to_owned(),
        signature: "DDDD".to_owned(),
        intermediate_spki: "EEEE".to_owned(),
        next_node_spki: Some("FFFF".to_owned()),
        underlay: Some(Underlay {
            key: "BBBB".to_owned(),
            endpoint: "10.0.0.2:51820".to_owned(),
        }),
    };

    assert_eq!(
        serde_json::to_string(&request).expect("encodable"),
        r#"{"node":"node-2","nonce":"CCCC","signature":"DDDD","intermediate_spki":"EEEE","next_node_spki":"FFFF","underlay":{"key":"BBBB","endpoint":"10.0.0.2:51820"}}"#,
        "the renewal's wire format has changed -- see the module head"
    );
}

/// **A request without a rotation leaves the field out**, instead of writing `null`.
///
/// `skip_serializing_if` is no formalism here: the signature covers the **request**
/// (ADR-0046), and a field that is sometimes `null` and sometimes absent would yield
/// two byte sequences for the same state of affairs.
#[test]
fn a_request_without_a_rotation_omits_the_field() {
    let request = RenewRequest {
        node: "node-2".to_owned(),
        nonce: "CCCC".to_owned(),
        signature: "DDDD".to_owned(),
        intermediate_spki: "EEEE".to_owned(),
        next_node_spki: None,
        underlay: None,
    };

    assert_eq!(
        serde_json::to_string(&request).expect("encodable"),
        r#"{"node":"node-2","nonce":"CCCC","signature":"DDDD","intermediate_spki":"EEEE","underlay":null}"#
    );
}

/// And back -- otherwise the request would be writable but not readable.
#[test]
fn the_requests_survive_a_round_trip() {
    let join = JoinRequest {
        node: "node-2".to_owned(),
        token: "secret".to_owned(),
        spki: "AAAA".to_owned(),
        underlay: None,
    };
    let encoded = serde_json::to_string(&join).expect("encodable");
    let decoded: JoinRequest = serde_json::from_str(&encoded).expect("decodable");
    assert_eq!(decoded, join);
}

/// **Every serialized type of the signer port is strict** (ADR-0072, ADR-0097).
///
/// The same rule as for the session and for the admin service (ADR-0083), and here it
/// weighs most: over this port go **shares and commitments**. A seat that half
/// understands a message hands out a nonce that belongs to something else -- the place
/// ADR-0014 calls the most dangerous of this system.
///
/// Measured, the state was already so (19 of 19); what was missing is the assurance.
/// There is **no** `serde(default)` there, so every extension is a break in **both**
/// directions -- measured at `CommitRequest.epoch`:
///
/// ```text
/// a new message -> an old reader:  unknown field `epoch`
/// an old message -> a new reader:  missing field `epoch`
/// ```
///
/// The guard reads the **source**: Rust cannot enumerate its types, and a list in the
/// test would be the construction this tree has measured four times as a source of
/// error.
#[test]
fn every_signer_message_is_strict() {
    let source = include_str!("../src/threshold/wire.rs");
    let mut seen = 0;
    let mut lax = Vec::new();

    // **What is asked for is `Deserialize`, not `pub struct`.** A type without it
    // has nothing to do with the wire -- my first attempt objected to `GrpcLink`, the
    // client.
    let mut derives = false;
    let mut strict = false;
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        if line.contains("derive(") && line.contains("Deserialize") {
            derives = true;
            continue;
        }
        if line.contains("deny_unknown_fields") {
            strict = true;
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("pub struct ")
            .or_else(|| line.strip_prefix("pub enum "))
        {
            if derives {
                seen += 1;
                if !strict {
                    let name = rest.split([' ', '{', '(', ';']).next().unwrap_or(rest);
                    lax.push(name.to_owned());
                }
            }
            derives = false;
            strict = false;
            continue;
        }
        // Every other line ends the attribute sequence above a declaration.
        if !line.starts_with("#[") && !line.starts_with("///") && !line.is_empty() {
            derives = false;
            strict = false;
        }
    }

    // **The bound grows along** -- it is measured, not guessed: after the eight RTS
    // messages from ADR-0108 there are 26. A bound that lies on the measured number
    // would be the trap this tree has already paid for once at a fuzz coverage;
    // therefore 20.
    assert!(
        seen > 20,
        "only {seen} serialized types were found -- the guard does not read"
    );
    assert!(
        lax.is_empty(),
        "these messages of the signer port are lenient: {lax:?}"
    );
}
