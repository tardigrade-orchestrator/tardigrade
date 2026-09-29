//! The codec of the Raft transport (phase 5c).
//!
//! The decoder is a **trust boundary**: what it reads comes from another node
//! over the network. Since **ADR-0043** the port demands a client certificate
//! and checks the key in it against `peers/<id>.pem` — the decoder nevertheless
//! stays a boundary: a registered node can be compromised. (Here stood "neither
//! encrypted nor authenticated"; that was right before ADR-0043 and has not been
//! since.) What is asserted is therefore the same as for the decoders of the log
//! in `tests/hostile_input.rs`: no crash, a typed rejection, no output whose size
//! the sender determines.
//!
//! A fuzz run of its own deliberately does **not** stand here. The payload goes
//! through the same `serde_json` path `tests/fuzz_wire.rs` already bombards with
//! a fresh seed; the codec only adds the gRPC frame, and `tonic` builds that. A
//! second fuzz over the same layer would cost run time and bring no new
//! statement.

use openraft::raft::{AppendEntriesRequest, VoteRequest};
use openraft::testing::log_id;
use openraft::{EntryPayload, Vote};
use tg_consensus::net::{from_bytes, to_bytes};
use tg_consensus::{Command, NodeId, TypeConfig};

/// Encodes the payload as the codec does.
fn encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
    to_bytes(value).expect("encodable")
}

/// Reads the payload as the codec does.
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, tonic::Status> {
    from_bytes(bytes)
}

fn append_entries() -> AppendEntriesRequest<TypeConfig> {
    AppendEntriesRequest {
        vote: Vote::new_committed(3, 1),
        prev_log_id: Some(log_id(2, 1, 7)),
        entries: vec![openraft::Entry {
            log_id: log_id(3, 1, 8),
            payload: EntryPayload::Normal(
                Command::RemoveWorkload {
                    name: "api".to_owned(),
                }
                .into(),
            ),
        }],
        leader_commit: Some(log_id(2, 1, 7)),
    }
}

/// Every message of the Raft protocol survives the round trip.
///
/// The test without which a cluster stands out only in operation: a message that
/// loses a field on the way is accepted by the other side all the same — and then
/// answers something other than what was asked.
#[test]
fn every_raft_message_survives_the_round_trip() {
    let request = append_entries();
    let bytes = encode(&request);
    let restored: AppendEntriesRequest<TypeConfig> = decode(&bytes).expect("decodable");

    assert_eq!(restored.vote, request.vote);
    assert_eq!(restored.prev_log_id, request.prev_log_id);
    assert_eq!(restored.leader_commit, request.leader_commit);
    assert_eq!(restored.entries.len(), 1);
    assert_eq!(restored.entries[0].log_id, request.entries[0].log_id);

    let vote = VoteRequest::<NodeId>::new(Vote::new(4, 2), Some(log_id(3, 1, 9)));
    let bytes = encode(&vote);
    let restored: VoteRequest<NodeId> = decode(&bytes).expect("decodable");
    assert_eq!(restored.vote, vote.vote);
    assert_eq!(restored.last_log_id, vote.last_log_id);
}

/// Unusable bytes yield a gRPC status, not a crash.
///
/// The error class is `invalid_argument` and not `internal`: the bytes came from
/// the other side. A node that sends something we cannot read speaks a different
/// version — that is its business. Reported as `internal` it would look as though
/// something were broken at our end.
#[test]
fn hostile_bytes_are_rejected_as_invalid_argument() {
    let cases: Vec<Vec<u8>> = vec![
        b"not even JSON".to_vec(),
        b"{".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        b"{\"vote\":42}".to_vec(),
        // Truncated in the middle of the document.
        encode(&append_entries())[..20].to_vec(),
        // Valid JSON, wrong message.
        serde_json::to_vec(&Command::SetActiveInstance {
            workload: "ledger".to_owned(),
            instance: 1,
        })
        .expect("encodable"),
        // Deep nesting.
        format!("{}{}", "[".repeat(2_000), "]".repeat(2_000)).into_bytes(),
        // Not UTF-8.
        vec![0xFF, 0xFE, 0xFD, 0x00],
    ];

    for bytes in cases {
        let status = decode::<AppendEntriesRequest<TypeConfig>>(&bytes)
            .expect_err("should have been refused");
        assert_eq!(
            status.code(),
            tonic::Code::InvalidArgument,
            "wrong error class for {:?}",
            String::from_utf8_lossy(&bytes[..bytes.len().min(24)])
        );
    }
}

/// The rejection message stays bounded, however large the input was.
///
/// Otherwise the sender determines the size of our log lines — the same thought
/// as with `MAX_DETAIL` in the state machine, here on the network side.
/// `serde_json` names line and column, not the content; the test nails down that
/// it stays that way.
#[test]
fn a_rejection_message_stays_bounded() {
    let huge = format!("{{\"vote\":\"{}\"}}", "A".repeat(200_000)).into_bytes();

    let status = decode::<AppendEntriesRequest<TypeConfig>>(&huge).expect_err("refused");

    assert!(
        status.message().len() < 1_000,
        "the message is {} characters long",
        status.message().len()
    );
    assert!(status.message().ends_with("[…]"), "{}", status.message());

    // And the counter-proof: a short message is not truncated.
    let short = decode::<AppendEntriesRequest<TypeConfig>>(b"{").expect_err("refused");
    assert!(!short.message().contains("[…]"), "{}", short.message());
}

/// The encoder writes exactly the bytes the log writes too.
///
/// That is the property for whose sake the codec speaks JSON at all: a captured
/// packet is readable without our binary, like the log per ADR-0020. Were it to
/// fall away, the advantage would be gone and the choice against Protobuf no
/// longer justified.
#[test]
fn the_wire_bytes_are_the_same_as_the_logs() {
    let command = Command::RemoveWorkload {
        name: "api".to_owned(),
    };

    let over_the_wire = encode(&command);
    let in_the_log = tg_consensus::wire::encode_command(&command).expect("encodable");

    assert_eq!(over_the_wire, in_the_log.as_bytes());
    assert!(
        std::str::from_utf8(&over_the_wire)
            .expect("utf-8")
            .contains("remove_workload")
    );
}

/// A value that cannot be encoded is reported as `internal` — this error lies
/// at our end, not with the caller.
#[test]
fn an_unencodable_value_is_reported_as_internal() {
    // A map with composite keys: JSON knows only strings as keys. Nothing like
    // this occurs in the Raft protocol -- the error class shall be right before
    // anybody needs it.
    let mut map = std::collections::BTreeMap::new();
    map.insert((1_u8, 2_u8), 3_u8);

    let status = to_bytes(&map).expect_err("not encodable");

    assert_eq!(status.code(), tonic::Code::Internal);
}

/// The `CommittedLeaderId` — the part of the vote on which Raft hangs who may
/// lead — arrives unchanged.
#[test]
fn the_leader_identity_survives_the_wire() {
    let vote = Vote::<NodeId>::new_committed(7, 4);
    let bytes = encode(&vote);
    let restored: Vote<NodeId> = decode(&bytes).expect("decodable");

    assert_eq!(restored, vote);
    assert!(restored.is_committed());
}

/// **The message limit covers a snapshot chunk.**
///
/// The ordering condition of this transport, and it is computed: `openraft`
/// chunks a snapshot at `snapshot_max_chunk_size`, and `serde_json` encodes
/// `Vec<u8>` as a **sequence of numbers** — at most four characters per byte
/// (`255,`). Without `MAX_MESSAGE >= chunk * 4` the receiver refuses a chunk of
/// the default size, `openraft` repeats it, and a node that must catch up
/// **never** catches up (phase 5d) — quietly, for the rest hold the quorum.
#[test]
fn the_message_limit_covers_a_snapshot_chunk() {
    let chunk = openraft::Config::default().snapshot_max_chunk_size;
    let needed = usize::try_from(chunk).expect("size") * 4;

    assert!(
        tg_wire::MAX_MESSAGE >= needed,
        "MAX_MESSAGE ({}) does not cover a chunk of {chunk} bytes ({needed} \
         would be needed)",
        tg_wire::MAX_MESSAGE
    );
}

/// **And `tonic`'s default does not cover it** — that is why the number exists.
///
/// Measured instead of asserted: the factor lies at 3.57 for uniformly
/// distributed bytes, so a chunk of the default size at 10.7 MiB against a 4 MiB
/// limit. Without this test `MAX_MESSAGE` would be a number whose occasion
/// nobody can reconstruct.
#[test]
fn the_tonic_default_would_not_cover_it() {
    const TONIC_DEFAULT: usize = 4 * 1024 * 1024;

    let chunk = usize::try_from(openraft::Config::default().snapshot_max_chunk_size).expect("size");
    let data: Vec<u8> = (0..chunk)
        .map(|at| u8::try_from(at % 256).unwrap_or(0))
        .collect();
    let encoded = to_bytes(&data).expect("encodable");

    assert!(
        encoded.len() > TONIC_DEFAULT,
        "a chunk of {chunk} bytes yields {} bytes of JSON -- that would lie \
         below the default, and then MAX_MESSAGE would not be needed",
        encoded.len()
    );
    assert!(
        encoded.len() <= chunk * 4,
        "the inflation lies above the factor four ({} of {chunk}) -- then the \
         ordering condition is too tight",
        encoded.len()
    );
}
