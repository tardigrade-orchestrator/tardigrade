//! The shared codec.
//!
//! Pure logic: bytes in, bytes out, and a `Status` when it does not work. The
//! emphasis lies on what can **go wrong** — the bytes come from the peer of a
//! gRPC call.
//!
//! Before this crate the codec existed three times, and the three had
//! **diverged**: one reported an unreadable foreign message as `internal`
//! instead of `invalid_argument`, and two of three quoted the objected value
//! unabridged. Both are properties one notices only if a test claims them.

use serde::{Deserialize, Serialize};
use tg_wire::{MAX_DETAIL, from_bytes, to_bytes};
use tonic::Code;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    name: String,
    number: u64,
}

/// Builds the example message used across the tests in this file.
///
/// # Returns
///
/// A fixed [`Message`] value.
fn example() -> Message {
    Message {
        name: "node-1".to_owned(),
        number: 42,
    }
}

// --- The normal case --------------------------------------------------------

/// Checks that a message decoded after encoding equals the original.
#[test]
fn a_message_survives_the_round_trip() {
    let bytes = to_bytes(&example()).expect("encodable");
    let back: Message = from_bytes(&bytes).expect("readable");

    assert_eq!(back, example());
}

/// Checks that the encoded payload is plain, human-readable JSON — a capture
/// is readable without our binary, the same property the audit log demands and
/// that this codec carries onto the wire.
#[test]
fn the_payload_is_readable_json() {
    let bytes = to_bytes(&example()).expect("encodable");
    let text = String::from_utf8(bytes).expect("UTF-8");

    assert!(text.contains("\"name\":\"node-1\""), "was: {text}");
    assert!(text.contains("\"number\":42"), "was: {text}");
}

// --- The refusals -----------------------------------------------------------

/// Checks that an unreadable foreign message is refused as `invalid_argument`,
/// never as `internal`.
///
/// `internal` means "something is broken at my end", and an operator then looks
/// at us. The bytes came from the peer, though — a node that sends something we
/// cannot read speaks a different version, and that is its business.
#[test]
fn an_unreadable_message_is_the_senders_fault() {
    for bad in [
        &b""[..],
        b"no JSON",
        b"{",
        b"[]",
        b"{\"name\":\"a\"}",
        b"{\"name\":\"a\",\"number\":42,\"unknown\":1}",
        b"\x00\x01\x02",
    ] {
        let err = from_bytes::<Message>(bad).expect_err("refused");

        assert_eq!(
            err.code(),
            Code::InvalidArgument,
            "for {bad:?} the code was {:?}",
            err.code()
        );
        assert!(!err.message().is_empty(), "refusal without a message");
    }
}

/// Checks that a hostile sender cannot determine the size of our output.
///
/// `serde_json` quotes the objected value on a type error. Without a bound a
/// 200 kB string would stand in full in the answer **and in every log line that
/// records it**. On the identity port that weighs especially: it demands no
/// client certificate.
#[test]
fn a_hostile_sender_cannot_choose_how_long_our_error_is() {
    let huge = "A".repeat(200_000);
    let payload = format!("{{\"name\":{huge:?},\"number\":\"not a number\"}}");

    let err = from_bytes::<Message>(payload.as_bytes()).expect_err("refused");

    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(
        err.message().chars().count() <= MAX_DETAIL + 64,
        "the message is {} characters long",
        err.message().chars().count()
    );
}

/// Checks that the truncation cut lands on a **character** boundary, not on a
/// byte boundary — otherwise `&text[..cut]` panics.
#[test]
fn the_cut_lands_on_a_character_boundary() {
    // The multi-byte character stands in the **quoted** value -- `serde_json`
    // repeats it on a type error, so the bound really falls inside it.
    let payload = format!("{{\"name\":\"n\",\"number\":\"{}\"}}", "ä".repeat(4_000));

    let err = from_bytes::<Message>(payload.as_bytes()).expect_err("refused");

    assert!(err.message().is_char_boundary(err.message().len()));
    assert!(err.message().chars().count() <= MAX_DETAIL + 64);
}

/// Checks that a message below the bound is **not** mutilated — otherwise an
/// operator would look for the missing remainder.
#[test]
fn a_short_message_is_left_alone() {
    let err = from_bytes::<Message>(b"{").expect_err("refused");

    assert!(
        !err.message().contains("[…]"),
        "short message truncated: {}",
        err.message()
    );
}

/// Checks that a value `serde_json` cannot write is reported as **our** error:
/// `internal`.
#[test]
fn a_value_we_cannot_encode_is_our_fault() {
    use std::collections::BTreeMap;

    // A map key that is not a string — JSON does not know that.
    let mut map: BTreeMap<(u8, u8), u8> = BTreeMap::new();
    map.insert((1, 2), 3);

    let err = to_bytes(&map).expect_err("not encodable");

    assert_eq!(err.code(), Code::Internal);
    assert!(!err.message().is_empty(), "error without a message");
}
