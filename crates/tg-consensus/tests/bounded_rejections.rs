//! A rejection quotes boundedly.
//!
//! # Why this is more than cosmetics
//!
//! A rejection goes into the **log**, and that is kept — and it lies in
//! addition in the sealed payload of the audit archive. A value that
//! determines the size of the rejection thereby determines the size of the
//! archive, and permanently at that: what once stands in it is not deleted.
//!
//! For the **document** a bound was decided and built (`MAX_DETAIL`, with the
//! rationale that the truncation belongs to the consensus behaviour). Measured,
//! it did **not** apply to the remaining rejections: a 100 kB name came through
//! unabridged while the same document ended at 141 bytes.
//!
//! The cut lies on a **character boundary** and is thereby the same on every
//! node — a rejection that differs between nodes would be a break of determinism,
//! even when only the text is affected.

use tg_consensus::command::Class;
use tg_consensus::{ClusterState, Command, Outcome};

/// How large a command's rejection becomes on the wire.
///
/// # Parameters
/// - `command`: the command expected to be refused.
///
/// # Returns
/// The byte length of the JSON-encoded outcome.
///
/// # Panics
/// Panics if the command is not rejected, or if the outcome cannot be
/// JSON-encoded.
fn size_of(command: &Command) -> usize {
    let mut state = ClusterState::default();
    let outcome = state.apply(command);
    assert!(
        matches!(outcome, Outcome::Rejected(_)),
        "the command must be refused, otherwise the test checks nothing: {outcome:?}"
    );
    serde_json::to_string(&outcome).expect("encodable").len()
}

/// A value nobody types by hand.
///
/// # Returns
/// A 100,000-character string, far larger than any legitimate input.
fn huge() -> String {
    "x".repeat(100_000)
}

/// **A secret name does not determine the size of the rejection.**
///
/// On the node the name becomes a file name, so it is checked — and the rejection
/// quotes it. Until here in full.
#[test]
fn a_huge_secret_name_does_not_reach_the_log() {
    let size = size_of(&Command::PutSecret {
        name: format!("../{}", huge()),
        value: tg_identity::secrets::Sealed {
            nonce: vec![0; 12],
            ciphertext: vec![0; 4],
        },
    });

    assert!(
        size < 2_000,
        "the rejection is {size} bytes -- the sender determines the size of the log entry"
    );
}

/// **And an operator name just as little.**
#[test]
fn a_huge_operator_name_does_not_reach_the_log() {
    let size = size_of(&Command::EnrolOperator {
        operator: huge(),
        spki: "AAAA".to_owned(),
        classes: Class::ALL.to_vec(),
    });

    assert!(size < 2_000, "the rejection is {size} bytes");
}

/// **And an address plan.**
#[test]
fn a_huge_cidr_does_not_reach_the_log() {
    let size = size_of(&Command::SetClusterNetwork {
        cidr: huge(),
        node_prefix: 24,
    });

    assert!(size < 2_000, "the rejection is {size} bytes");
}

/// **And an underlay key.**
///
/// The interesting one of them all: it comes from the **credential path**, that
/// is, from this system's least authenticated boundary — the join and renewal
/// exchange, which demands no client certificate of its own.
#[test]
fn a_huge_underlay_key_does_not_reach_the_log() {
    let size = size_of(&Command::AnnounceUnderlay {
        node: "node-1".to_owned(),
        key: huge(),
        endpoint: "10.0.0.1:51820".to_owned(),
        at: 0,
    });

    assert!(size < 2_000, "the rejection is {size} bytes");
}

/// **The counter-check: an ordinary value comes through unharmed.**
///
/// Without it a truncation that cuts every name to zero would be just as green —
/// and a rejection that no longer names the objected value helps nobody.
#[test]
fn an_ordinary_name_survives_unchanged() {
    let mut state = ClusterState::default();
    let outcome = state.apply(&Command::PutSecret {
        name: "../etc/passwd".to_owned(),
        value: tg_identity::secrets::Sealed {
            nonce: vec![0; 12],
            ciphertext: vec![0; 4],
        },
    });

    let wire = serde_json::to_string(&outcome).expect("encodable");
    assert!(
        wire.contains("../etc/passwd"),
        "the objected name belongs in the rejection: {wire}"
    );
}

/// **The cut lies on a character boundary**, not on a byte boundary.
///
/// Otherwise it would cut a multi-byte character apart, and the result would be
/// no valid UTF-8 — with a name that goes into the log and stays there
/// forever.
#[test]
fn the_cut_lands_on_a_character_boundary() {
    let mut state = ClusterState::default();
    let outcome = state.apply(&Command::EnrolOperator {
        // A character that needs three bytes, repeated often enough.
        operator: "ä".repeat(10_000),
        spki: "AAAA".to_owned(),
        classes: Class::ALL.to_vec(),
    });

    let wire = serde_json::to_string(&outcome).expect("encodable");
    assert!(wire.len() < 4_000, "{} bytes", wire.len());
}
