//! The wire format: encoder, decoder and their errors.
//!
//! `tests/command_set.rs` nails the command form down, `tests/fuzz_wire.rs`
//! throws randomness at it. Here stands the rest of the module: the result side
//! (`Outcome`/`Rejection`), the state as the snapshot format, and the error type
//! itself — which in operation is the only information about why a node
//! stops.

use tg_consensus::wire::{
    self, decode_command, decode_entry, decode_state, encode_command, encode_entry, encode_state,
};
use tg_consensus::{ClusterState, Command, Epoch, Outcome, Rejection, Topology, UtcMillis};

fn document(name: &str, class: Option<&str>) -> String {
    let class = class.map_or(String::new(), |c| format!(" class=\"{c}\""));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\"{class}>\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

fn populated() -> ClusterState {
    let mut state = ClusterState::default();
    for command in [
        Command::UpsertWorkload {
            document: document("api", None),
        },
        Command::UpsertWorkload {
            document: document("ledger", Some("single-writer")),
        },
        Command::UpsertNode {
            name: "node-1".to_owned(),
            topology: Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r7".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
        Command::AllowTraffic {
            from: "api".to_owned(),
            to: "ledger".to_owned(),
        },
        Command::AssignPlacement {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        },
        Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(15_000),
        },
        // Here stood `RegisterTrust`, retired since ADR-0112. The state shall
        // be **populated**; for that a command that takes effect is needed —
        // the trust column is now filled by the way that fills it in operation
        // too (ADR-0037).
        Command::InviteNode {
            node: "node-2".to_owned(),
            digest: "abc123".to_owned(),
            expires_at: 1_800_000_900,
        },
        Command::AdmitNode {
            node: "node-2".to_owned(),
            spki: "anchor".to_owned(),
            at: 1_800_000_000,
        },
    ] {
        assert!(!matches!(state.apply(&command), Outcome::Rejected(_)));
    }
    state
}

// --- The result side --------------------------------------------------------

/// Every result and rejection variant, character for character.
///
/// The `Outcome` does not stand in the log — it goes to the caller as `C::R` and
/// from 5c on over the network. It is nevertheless nailed down here: a caller
/// shall be able to **react** to a rejection (ADR-0010 distinguishes autonomous
/// from quorum-bound actions by exactly such reasons), and for that the reason
/// must be stably named and not a string that changes at the next rebuild.
#[test]
fn every_outcome_has_a_pinned_wire_form() {
    let epoch = Epoch::default();
    let cases = [
        (Outcome::Applied, r#""applied""#),
        (
            Outcome::LeaseGranted { epoch },
            r#"{"lease_granted":{"epoch":0}}"#,
        ),
        (
            Outcome::LeaseRenewed { epoch },
            r#"{"lease_renewed":{"epoch":0}}"#,
        ),
        (
            Outcome::Rejected(Rejection::MalformedDocument {
                detail: "x".to_owned(),
            }),
            r#"{"rejected":{"malformed_document":{"detail":"x"}}}"#,
        ),
        (
            Outcome::Rejected(Rejection::UnknownWorkload {
                name: "a".to_owned(),
            }),
            r#"{"rejected":{"unknown_workload":{"name":"a"}}}"#,
        ),
        (
            Outcome::Rejected(Rejection::UnknownNode {
                name: "n".to_owned(),
            }),
            r#"{"rejected":{"unknown_node":{"name":"n"}}}"#,
        ),
        (
            Outcome::Rejected(Rejection::NotSingleWriter {
                workload: "a".to_owned(),
            }),
            r#"{"rejected":{"not_single_writer":{"workload":"a"}}}"#,
        ),
        (
            Outcome::Rejected(Rejection::LeaseHeld {
                workload: "a".to_owned(),
                holder: "n".to_owned(),
                epoch,
            }),
            r#"{"rejected":{"lease_held":{"workload":"a","holder":"n","epoch":0}}}"#,
        ),
        (
            Outcome::Rejected(Rejection::NoLease {
                workload: "a".to_owned(),
            }),
            r#"{"rejected":{"no_lease":{"workload":"a"}}}"#,
        ),
        (
            Outcome::Rejected(Rejection::NotHolder {
                workload: "a".to_owned(),
                holder: "n".to_owned(),
            }),
            r#"{"rejected":{"not_holder":{"workload":"a","holder":"n"}}}"#,
        ),
        (
            Outcome::Rejected(Rejection::LeaseExpired {
                workload: "a".to_owned(),
            }),
            r#"{"rejected":{"lease_expired":{"workload":"a"}}}"#,
        ),
    ];

    for (outcome, expected) in &cases {
        let encoded = serde_json::to_string(outcome).expect("encodable");
        assert_eq!(&encoded.as_str(), expected);

        let restored: Outcome = serde_json::from_str(&encoded).expect("decodable");
        assert_eq!(&restored, outcome);
    }
}

// --- The state --------------------------------------------------------------

/// Two nodes that create the same entries in their collections in **different**
/// order produce the same snapshot.
///
/// That is the property for whose sake `BTree*` and not `Hash*` stands in
/// `ClusterState`: a snapshot whose bytes depend on the insertion order is of
/// no use as a basis for comparison between nodes — and from 5d on exactly that
/// hangs on it.
#[test]
fn the_snapshot_bytes_do_not_depend_on_insertion_order() {
    let commands = |names: [&str; 3]| {
        names
            .into_iter()
            .map(|name| Command::UpsertWorkload {
                document: document(name, None),
            })
            .collect::<Vec<_>>()
    };

    let mut forward = ClusterState::default();
    for command in commands(["alpha", "middle", "zeta"]) {
        assert_eq!(forward.apply(&command), Outcome::Applied);
    }

    let mut backward = ClusterState::default();
    for command in commands(["zeta", "middle", "alpha"]) {
        assert_eq!(backward.apply(&command), Outcome::Applied);
    }

    assert_eq!(forward, backward);
    assert_eq!(
        encode_state(&forward).expect("encodable"),
        encode_state(&backward).expect("encodable")
    );
}

/// The full state — with lease, edges, placement and trust — survives the round
/// trip unchanged. A field that is lost when encoding would not stand out at
/// the empty state.
#[test]
fn a_populated_state_survives_the_round_trip() {
    let state = populated();
    let bytes = encode_state(&state).expect("encodable");
    let restored = decode_state(&bytes).expect("decodable");

    assert_eq!(state, restored);
    assert_eq!(restored.lease("ledger").expect("lease").holder(), "node-1");
    assert_eq!(restored.placement("ledger"), Some("node-1"));
    // `node-2`, not `node-1`: the trust now comes via invitation and admission
    // (ADR-0037), and those apply to the admitted node.
    assert_eq!(restored.trust("node-2"), Some("anchor"));
    assert!(restored.may_talk("api", "ledger"));
    assert_eq!(encode_state(&restored).expect("encodable"), bytes);
}

/// The empty state is a valid snapshot too. A freshly started node has no
/// other.
#[test]
fn the_empty_state_is_a_valid_snapshot() {
    let bytes = encode_state(&ClusterState::default()).expect("encodable");
    assert_eq!(
        decode_state(&bytes).expect("decodable"),
        ClusterState::default()
    );
}

/// A state with a **missing** field is refused.
///
/// The counter-direction to `deny_unknown_fields`: a snapshot from an older
/// version that lacks a field expected today must not pass through as a default
/// value. A node that installs half a state takes itself for caught up and is
/// not.
#[test]
fn a_state_with_a_missing_field_is_rejected() {
    let full = encode_state(&populated()).expect("encodable");
    let value: serde_json::Value = serde_json::from_slice(&full).expect("JSON");

    for field in [
        "workloads",
        "traffic",
        "nodes",
        "placements",
        "leases",
        "trust",
        "next_epoch",
    ] {
        let mut reduced = value.clone();
        reduced
            .as_object_mut()
            .expect("object")
            .remove(field)
            .unwrap_or_else(|| panic!("the field {field} must exist"));

        let bytes = serde_json::to_vec(&reduced).expect("encodable");
        assert!(
            decode_state(&bytes).is_err(),
            "a state without '{field}' was accepted"
        );
    }

    // The counter-proof: unchanged it gets through. Otherwise the test would be
    // green even if the decoder refused everything.
    assert!(decode_state(&full).is_ok());
}

// --- The error type ---------------------------------------------------------

/// The message names **what** was unreadable, and the serialization layer's
/// reason behind it. Without the first a parser error without a subject stands
/// in the log, without the second a statement without a cause.
#[test]
fn a_wire_error_names_the_subject_and_the_cause() {
    let command = decode_command("{").expect_err("broken");
    let text = command.to_string();
    assert!(
        text.starts_with("command is not in the expected format:"),
        "{text}"
    );
    assert!(
        text.len() > "command is not in the expected format:".len(),
        "{text}"
    );

    let entry = decode_entry(b"{").expect_err("broken");
    assert!(
        entry
            .to_string()
            .starts_with("log entry is not in the expected format:"),
        "{entry}"
    );

    let state = decode_state(b"{").expect_err("broken");
    assert!(
        state
            .to_string()
            .starts_with("state is not in the expected format:"),
        "{state}"
    );
}

/// The error is a `std::error::Error` and meaningful in the `Debug` form —
/// that is the form in which `openraft`'s `StorageError` carries it on.
#[test]
fn a_wire_error_is_a_standard_error() {
    let err = decode_state(b"[]").expect_err("broken");

    let as_dyn: &dyn std::error::Error = &err;
    assert!(as_dyn.source().is_none());
    assert!(format!("{err:?}").contains("state"), "{err:?}");
}

/// The three decoders do not confuse their formats.
///
/// A state is no command and a command no log entry. Without this separation a
/// snapshot could be applied as an entry — and that would be no error one sees
/// later.
#[test]
fn the_three_decoders_do_not_accept_each_others_documents() {
    let command = encode_command(&Command::SetActiveInstance {
        workload: "ledger".to_owned(),
        instance: 1,
    })
    .expect("encodable");
    let state = encode_state(&populated()).expect("encodable");

    assert!(decode_state(command.as_bytes()).is_err());
    assert!(decode_entry(command.as_bytes()).is_err());
    assert!(decode_command(std::str::from_utf8(&state).expect("utf-8")).is_err());
    assert!(decode_entry(&state).is_err());
}

/// A log entry goes through encoder and decoder and stays the same — together
/// with the `log_id` by which `openraft` recognizes it again.
#[test]
fn an_entry_survives_the_round_trip_with_its_log_id() {
    let entry: wire::Entry = openraft::Entry {
        log_id: openraft::testing::log_id(3, 1, 42),
        payload: openraft::EntryPayload::Normal(
            Command::RemoveWorkload {
                name: "api".to_owned(),
            }
            .into(),
        ),
    };

    let bytes = encode_entry(&entry).expect("encodable");
    let restored = decode_entry(&bytes).expect("decodable");

    assert_eq!(restored.log_id, entry.log_id);
    assert_eq!(encode_entry(&restored).expect("encodable"), bytes);
    match restored.payload {
        openraft::EntryPayload::Normal(submission) => {
            assert_eq!(submission.command.kind(), "remove_workload");
        }
        other => panic!("payload lost: {other:?}"),
    }
}

/// A blank entry and a membership entry get through as well. `openraft`
/// produces both itself — a log that can read only its own commands is
/// unreadable at the first leader change.
#[test]
fn blank_and_membership_entries_survive_the_round_trip() {
    let blank: wire::Entry = openraft::Entry {
        log_id: openraft::testing::log_id(1, 1, 1),
        payload: openraft::EntryPayload::Blank,
    };
    let membership: wire::Entry = openraft::Entry {
        log_id: openraft::testing::log_id(1, 1, 2),
        payload: openraft::EntryPayload::Membership(openraft::Membership::new(
            vec![[1, 2, 3, 4, 5].into_iter().collect()],
            None,
        )),
    };

    for entry in [blank, membership] {
        let bytes = encode_entry(&entry).expect("encodable");
        let restored = decode_entry(&bytes).expect("decodable");
        assert_eq!(restored.log_id, entry.log_id);
        assert_eq!(encode_entry(&restored).expect("encodable"), bytes);
    }
}

/// **The Raft port demands a credential, and its module head says so too**
/// (ADR-0043).
///
/// # Why a test over a piece of documentation
///
/// Because a withdrawal was logged here twice that **never landed in the
/// source**. The commit for ADR-0043 writes "the sentence is withdrawn",
/// `plans/PLAN.md` writes it likewise — measured, that commit changed **one**
/// line in this file, namely the `pub use`. The correction went into another
/// module (`tg_agent::underlay`) while the wrong sentence stayed standing:
///
/// - *"Security: this port is not authenticated"* — right until ADR-0043, not
///   afterwards. Whoever reads that takes a failed certificate check for an
///   error and the port for a hole.
/// - *"After phase 9 the Raft traffic runs over an authenticated, encrypted
///   underlay"* — measured wrong, and exactly the sentence whose withdrawal
///   twice stood only in the changelog.
///
/// The same construction as the guard over the `--keep-logs` note in `tgd`: it
/// demands the promise that **applies**, and that the old sentence does not come
/// back. A warning that is no longer right costs the credibility of all the
/// others next time.
#[test]
fn the_raft_transport_does_not_claim_to_be_unauthenticated() {
    let source = include_str!("../src/net/mod.rs");
    let head: String = source
        .lines()
        .take_while(|line| line.starts_with("//!") || line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    // Without this assurance the test would check nothing as soon as the head
    // looks different: an empty text contains no wrong claim.
    assert!(
        head.len() > 500,
        "the module head was not read: {} characters",
        head.len()
    );

    // **The promise that applies** — and in its substance at that. Here stood
    // `head.contains("demands")`, and the counter-check did **not** hit: the
    // word also stands in the paragraph about the loopback default. An assurance
    // that looks for a catch-all word checks nothing.
    for promise in ["client certificate", "peers/", "ADR-0043"] {
        assert!(
            head.contains(promise),
            "the head must carry the promise ('{promise}' is missing):\n{head}"
        );
    }

    // **And the two sentences that must not come back** — as a statement, not
    // as a classification: the head may quote them (it does, with quotation
    // marks), but not claim them.
    for stale in [
        "//! # Security: this port is not authenticated",
        "//!   Raft traffic then runs over an authenticated, encrypted",
    ] {
        assert!(
            !source.contains(stale),
            "a withdrawn sentence is back: '{stale}'"
        );
    }
}
