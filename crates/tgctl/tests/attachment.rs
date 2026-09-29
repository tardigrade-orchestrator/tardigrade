//! `tgctl node detach|attach` over a real socket (ADR-0054).
//!
//! A provided server, for the same reason as at `invite`: what is checked is
//! the **client**, and a one-node cluster cannot answer `ForwardTo` at all —
//! the branch that warns an operator standing at the wrong node would otherwise
//! stay unseen.

use std::process::Command as OsCommand;

use tg_admin::WriteResult;
use tg_model::command::Outcome;
use tg_model::command::{Attachment, Command, Rejection};

mod support;

use support::{Served, serve};

fn applied() -> WriteResult {
    WriteResult::Applied {
        outcome: Outcome::Applied,
        lints: Vec::new(),
    }
}

fn node(served: &Served, args: &[&str]) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(served.dir.path())
        .arg("node")
        .args(args)
        .output()
        .expect("tgctl is startable")
}

/// **Detach sends exactly `SetAttachment`** — and nothing about placeability.
///
/// The two lie on different axes (ADR-0054); a client that put both into one
/// command would take the distinction from the log.
#[tokio::test(flavor = "multi_thread")]
async fn detach_sends_exactly_one_command_on_its_own_axis() {
    let served = serve(1, applied());

    let output = node(&served, &["detach", "node-7"]);
    assert!(output.status.success(), "detach must succeed");

    let seen = served.seen.lock().expect("mutex").clone();
    assert_eq!(seen.len(), 1, "exactly one command: {seen:?}");
    match &seen[0] {
        Command::SetAttachment { node, mode } => {
            assert_eq!(node, "node-7");
            assert_eq!(*mode, Attachment::Detached);
        }
        other => panic!("wrong command: {other:?}"),
    }
}

/// `attach` takes it back — the same state, the other value.
#[tokio::test(flavor = "multi_thread")]
async fn attach_takes_it_back() {
    let served = serve(1, applied());

    let output = node(&served, &["attach", "node-7"]);
    assert!(output.status.success());

    let seen = served.seen.lock().expect("mutex").clone();
    match &seen[0] {
        Command::SetAttachment { mode, .. } => assert_eq!(*mode, Attachment::Attached),
        other => panic!("wrong command: {other:?}"),
    }
}

/// **What goes with it and what stays is said.**
///
/// An operator who detaches must know two things: that the ordinal and the
/// trust stay (otherwise they take it for `RemoveNode`), and that a writable
/// volume stays lying (ADR-0027) — then the detachment **never** finishes.
#[tokio::test(flavor = "multi_thread")]
async fn detach_says_what_stays_behind() {
    let served = serve(1, applied());

    let complaint =
        String::from_utf8_lossy(&node(&served, &["detach", "node-7"]).stderr).to_string();

    assert!(
        complaint.contains("ordinal") && complaint.contains("trust"),
        "the difference from RemoveNode is not named: {complaint}"
    );
    assert!(
        complaint.contains("volume"),
        "the case that never finishes is not named: {complaint}"
    );

    // Counter-check: `attach` takes nothing away and therefore does not say so.
    let back = String::from_utf8_lossy(&node(&served, &["attach", "node-7"]).stderr).to_string();
    assert!(
        !back.contains("ordinal"),
        "at the bringing back the hint does not belong: {back}"
    );
}

/// **An unknown node ends with a failure status.**
///
/// The state machine refuses (an exception to rule 1), and the client must not
/// report that as a success: "detached" on something that does not exist would
/// let an operator walk on reassured.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_node_is_not_reported_as_success() {
    let served = serve(
        1,
        WriteResult::Applied {
            outcome: Outcome::Rejected(Rejection::UnknownNode {
                name: "node-7".to_owned(),
            }),
            lints: Vec::new(),
        },
    );

    let output = node(&served, &["detach", "node-7"]);

    assert!(
        !output.status.success(),
        "a rejection was reported as a success"
    );
}

/// Here too a follower names the leader instead of silently doing nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_follower_names_the_leader() {
    let served = serve(1, WriteResult::ForwardTo { leader: Some(4) });

    let output = node(&served, &["detach", "node-7"]);

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("node 4"),
        "the leader must be named"
    );
}

/// **Revoke trust** (ADR-0043, ADR-0054).
///
/// ADR-0054 expressly names `RevokeTrust` as the answer to a compromised key:
/// "whoever wants the key dead takes `RevokeTrust`". The command had no
/// producer — the documented answer was not issuable.
#[tokio::test(flavor = "multi_thread")]
async fn trust_can_be_revoked() {
    let served = serve(1, applied());

    let out = node(&served, &["revoke-trust", "node-2"]);

    assert!(out.status.success(), "{out:?}");
    let seen = served.seen.lock().expect("commands");
    assert!(
        matches!(&seen[0], tg_model::command::Command::RevokeTrust { node } if node == "node-2"),
        "{seen:?}"
    );
}

/// **Remove a node** (ADR-0039).
///
/// An ordinal is freed **only** by that — a failure does not do it, and a
/// `RevokeTrust` does not either: revoking a key is a security action,
/// renumbering a subnet a topology change.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_can_be_removed() {
    let served = serve(1, applied());

    let out = node(&served, &["remove", "node-2"]);

    assert!(out.status.success(), "{out:?}");
    let seen = served.seen.lock().expect("commands");
    assert!(
        matches!(&seen[0], tg_model::command::Command::RemoveNode { name } if name == "node-2"),
        "{seen:?}"
    );
}

/// **A removed node keeps the data key** (ADR-0095, ADR-0100).
///
/// `RemoveNode` takes trust and ordinal — not the disk. On it lies
/// `identity/secrets.key`, the **one** key with which every secret of the
/// cluster is sealed; and the ciphertext stands in the log and thereby in the
/// audit archive, which is retained (ADR-0020, measured). Whoever gets both
/// into their hands reads every secret of its period of validity.
///
/// The way out has existed since ADR-0100 — up to here nobody said so.
#[tokio::test(flavor = "multi_thread")]
async fn removing_a_node_warns_about_the_data_key() {
    let served = support::serve_writing_with_secrets(
        1,
        applied(),
        tg_admin::SecretsResponse {
            id: 1,
            last_applied: Some(7),
            names: vec![("s3-key".to_owned(), 32)],
            grants: Vec::new(),
            registries: Vec::new(),
        },
    );

    let out = node(&served, &["remove", "node-2"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "{out:?}");
    assert!(
        stderr.contains("data key"),
        "the hint about the key is missing: {stderr}"
    );
    assert!(
        stderr.contains("rekey"),
        "a warning without a way out is read past: {stderr}"
    );
}

/// **And without secrets it stays away.**
///
/// The other half of the promise: a cluster without secrets has nothing to
/// protect, and a warning that appears at **every** removal is read past where
/// it counts. The same consideration as at `cluster remove`, which looks into
/// the projection beforehand.
#[tokio::test(flavor = "multi_thread")]
async fn without_secrets_the_removal_stays_quiet() {
    let served = support::serve_writing_with_secrets(
        1,
        applied(),
        tg_admin::SecretsResponse {
            id: 1,
            last_applied: Some(7),
            names: Vec::new(),
            grants: Vec::new(),
            registries: Vec::new(),
        },
    );

    let out = node(&served, &["remove", "node-2"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "{out:?}");
    assert!(
        !stderr.contains("data key"),
        "without secrets there is nothing to warn about: {stderr}"
    );
    assert!(
        stderr.contains("ordinal"),
        "the ordinary hint must stay: {stderr}"
    );
}
