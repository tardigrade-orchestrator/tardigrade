//! Hostile inputs at this crate's trust boundaries.
//!
//! There are two boundaries here, and both take bytes from outside:
//!
//! 1. **The definition document** in [`Command::UpsertWorkload`]. It comes from
//!    an XML file a human wrote, or maybe did not.
//! 2. **The wire format** in [`wire`]. A log entry can stem from another node,
//!    from an older version, or come from the disk that damaged it.
//!
//! Both must refuse, not pass through. And the refusal must be the same on every
//! node — an input that fails on four nodes and goes through on the fifth is a
//! break of determinism and thereby worse than a crash.

use tg_consensus::{ClusterState, Command, Outcome, Rejection, wire};

/// Builds an XML workload document with the given (possibly invalid) name.
///
/// # Parameters
/// - `name`: the workload name to embed, unescaped.
///
/// # Returns
/// The XML document as a string.
fn with_name(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\
         <workload name=\"{name}\" kind=\"service\">\
         <image reference=\"example.com/a:1\"/>\
         </workload></workloads>"
    )
}

/// Applies an `UpsertWorkload` of the given document to a fresh cluster state.
///
/// # Parameters
/// - `document`: the XML workload document to upsert.
///
/// # Returns
/// The resulting state and the outcome of the apply.
fn apply(document: &str) -> (ClusterState, Outcome) {
    let mut state = ClusterState::default();
    let outcome = state.apply(&Command::UpsertWorkload {
        document: document.to_owned(),
    });

    (state, outcome)
}

/// Asserts that applying `document` is rejected as malformed and leaves the
/// state unchanged.
///
/// # Parameters
/// - `label`: a short description of the case, used in failure messages.
/// - `document`: the XML workload document expected to be refused.
///
/// # Panics
/// Panics if the document is applied, or if it is rejected for a reason
/// other than `MalformedDocument`, or if it mutates the state.
fn assert_rejected(label: &str, document: &str) {
    let (state, outcome) = apply(document);

    assert!(
        matches!(
            outcome,
            Outcome::Rejected(Rejection::MalformedDocument { .. })
        ),
        "{label}: a rejection was expected, got {outcome:?}"
    );
    assert_eq!(
        state,
        ClusterState::default(),
        "{label}: refused, but the state changed"
    );
}

/// Entity expansion ("billion laughs").
///
/// `quick-xml` expands **no** self-defined entities and refuses the reference as
/// unknown. The class is thereby structurally out, not caught by a limit — that
/// is the reason why no number stands here at which it tips over.
#[test]
fn entity_expansion_is_rejected() {
    assert_rejected(
        "billion laughs",
        concat!(
            "<?xml version=\"1.0\"?>",
            "<!DOCTYPE workloads [",
            "<!ENTITY a \"aaaaaaaaaa\">",
            "<!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">",
            "<!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">",
            "]>",
            "<workloads xmlns=\"urn:tardigrade:workload:v1\">",
            "<workload name=\"api\" kind=\"service\">",
            "<image reference=\"&c;\"/>",
            "</workload></workloads>"
        ),
    );
}

/// XXE: an external entity onto a local file.
///
/// The node agent that would resolve this reference runs privileged, so a
/// successful expansion could read any file on the node. That too falls
/// under "unknown entity".
#[test]
fn an_external_entity_is_rejected() {
    let document = concat!(
        "<?xml version=\"1.0\"?>",
        "<!DOCTYPE workloads [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        "<workloads xmlns=\"urn:tardigrade:workload:v1\">",
        "<workload name=\"api\" kind=\"service\">",
        "<image reference=\"&xxe;\"/>",
        "</workload></workloads>"
    );
    assert_rejected("xxe", document);

    let (_, outcome) = apply(document);
    let Outcome::Rejected(Rejection::MalformedDocument { detail }) = outcome else {
        panic!("a rejection was expected");
    };
    assert!(
        !detail.contains("root:"),
        "the message carries file content: {detail}"
    );
}

/// Path traversal in the workload name.
///
/// The name becomes the directory name in the node's local cache. The facet
/// `[a-z][a-z0-9-]{0,62}` in the XSD is the defence; here it is checked that it
/// really takes hold in the log path and not only somewhere further down.
#[test]
fn path_traversal_in_a_name_is_rejected() {
    assert_rejected("traversal", &with_name("../../etc/passwd"));
    assert_rejected("absolute", &with_name("/etc/shadow"));
}

/// Injection patterns in the name.
///
/// The name lands in keys of the `may_talk` set, in DNS names, and in nftables
/// rules. None of these places may rely on later escaping.
#[test]
fn injection_patterns_in_a_name_are_rejected() {
    assert_rejected("sql", &with_name("a'; DROP TABLE x;--"));
    assert_rejected("shell", &with_name("a$(id)"));
    assert_rejected("script", &with_name("<script>"));
    assert_rejected("newline", &with_name("a\nb"));
    assert_rejected("nul", &with_name("a\u{0}b"));
}

/// A name over the facet length and one exactly on it.
///
/// The number comes from `tg_model::mesh::MAX_NAME` and not from the hand: it is
/// the XSD's upper bound, and a guard holds it there against the schema
/// (`schema_drift`). Written hard it would stand here a third time — and a facet
/// somebody raises would turn this witness into a statement about a limit that no
/// longer exists.
#[test]
fn a_name_at_and_over_the_limit() {
    let limit = tg_model::mesh::MAX_NAME;

    let (_, at_limit) = apply(&with_name(&format!("a{}", "b".repeat(limit - 1))));
    assert_eq!(
        at_limit,
        Outcome::Applied,
        "{limit} characters are permitted"
    );

    assert_rejected(
        "one too many",
        &with_name(&format!("a{}", "b".repeat(limit))),
    );
}

/// Oversized inputs.
///
/// In addition: the rejection rationale stays bounded. Otherwise the input
/// determines the output size — every log line that writes the answer along then
/// grows with the attacker.
#[test]
fn an_oversized_value_is_rejected_with_a_bounded_message() {
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\
         <workload name=\"api\" kind=\"service\">\
         <image reference=\"{}\"/>\
         </workload></workloads>",
        "x".repeat(100_000)
    );

    assert_rejected("oversized", &document);

    let (_, outcome) = apply(&document);
    let Outcome::Rejected(Rejection::MalformedDocument { detail }) = outcome else {
        panic!("a rejection was expected");
    };
    assert!(
        detail.chars().count() <= 600,
        "the message is {} characters long",
        detail.chars().count()
    );
}

/// Deeply nested structure — no crash, no recursion avalanche.
#[test]
fn deep_nesting_is_rejected() {
    let document = format!("{}{}", "<a>".repeat(10_000), "</a>".repeat(10_000));
    assert_rejected("nested", &document);
}

/// Empty and whitespace only.
#[test]
fn empty_and_blank_documents_are_rejected() {
    assert_rejected("empty", "");
    assert_rejected("whitespace", "   \n\t  ");
}

/// The message names no paths from the process environment.
///
/// The loader knows two origins: a file or `<input>`. Over the log path always
/// the second comes; if a file path stood here, somebody would inadvertently have
/// built in `from_path` and the audit trail would carry internals.
#[test]
fn a_rejection_leaks_no_internals() {
    let (_, outcome) = apply("<broken");
    let Outcome::Rejected(Rejection::MalformedDocument { detail }) = outcome else {
        panic!("a rejection was expected");
    };

    assert!(!detail.contains("/root"), "{detail}");
    assert!(!detail.contains("/home"), "{detail}");
    assert!(!detail.contains(".cargo"), "{detail}");
    assert!(!detail.contains("src/"), "{detail}");
}

// --- Wire format -----------------------------------------------------------

/// Broken, truncated and type-wrong commands.
#[test]
fn a_broken_command_is_rejected() {
    for (label, json) in [
        ("empty", ""),
        ("whitespace", "  "),
        ("truncated", r#"{"remove_workload":{"name":"api""#),
        ("array", r#"["remove_workload"]"#),
        ("null", "null"),
        ("number", "42"),
        ("wrong type", r#"{"remove_workload":{"name":42}}"#),
        (
            "mandatory field missing",
            r#"{"allow_traffic":{"from":"api"}}"#,
        ),
        (
            "two variants",
            r#"{"remove_workload":{"name":"a"},"remove_node":{"name":"b"}}"#,
        ),
        (
            "epoch negative",
            r#"{"grant_lease":{"workload":"a","node":"b","now":-1,"expires_at":1}}"#,
        ),
        (
            "epoch too large",
            r#"{"grant_lease":{"workload":"a","node":"b","now":1,"expires_at":18446744073709551616}}"#,
        ),
    ] {
        assert!(
            wire::decode_command(json).is_err(),
            "{label}: should have been refused"
        );
    }
}

/// A log entry that is none. Bytes from the disk or from the network.
#[test]
fn a_broken_entry_is_rejected() {
    for (label, bytes) in [
        ("empty", b"".as_slice()),
        ("not UTF-8", b"\xff\xfe\x00\x01".as_slice()),
        ("JSON, but no entry", b"{}".as_slice()),
        (
            "payload missing",
            br#"{"log_id":{"leader_id":{"term":1,"node_id":1},"index":1}}"#,
        ),
    ] {
        assert!(
            wire::decode_entry(bytes).is_err(),
            "{label}: should have been refused"
        );
    }
}

/// A snapshot that is none.
///
/// `deny_unknown_fields` on [`ClusterState`] is the point here: a snapshot from a
/// newer version with an additional field is refused. Silently taking over what
/// one does not understand would yield a node that takes itself for caught up and
/// is not.
#[test]
fn a_broken_snapshot_is_rejected() {
    for (label, bytes) in [
        ("empty", b"".as_slice()),
        ("not UTF-8", b"\xff\xfe".as_slice()),
        ("array", b"[]".as_slice()),
        (
            "unknown field",
            br#"{"workloads":{},"traffic":[],"nodes":{},"placements":{},"leases":{},"trust":{},"next_epoch":0,"future":true}"#,
        ),
    ] {
        assert!(
            wire::decode_state(bytes).is_err(),
            "{label}: should have been refused"
        );
    }
}

/// And the counter-proof: the format we write ourselves goes through. Otherwise
/// the test above would stay green with a broken encoder too.
#[test]
fn a_snapshot_we_wrote_ourselves_is_accepted() {
    let bytes = wire::encode_state(&ClusterState::default()).expect("encodable");

    assert_eq!(
        wire::decode_state(&bytes).expect("decodable"),
        ClusterState::default()
    );
}
