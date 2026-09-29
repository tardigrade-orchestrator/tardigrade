//! `tgctl node invite` over a real socket (ADR-0037, ADR-0044).
//!
//! # Why a provided server stands here and not a `tgd`
//!
//! What is checked is the **path this cut built**: find the socket, connect,
//! send `InviteNode`, and distinguish the three answers. The server side is
//! checked in `tgd`; starting it again here would prove it a second time and
//! would for that leave out exactly the case that matters: **`ForwardTo`**. A
//! one-node cluster is always the leader and cannot give this answer at all —
//! the branch that warns an operator standing at the wrong node would stay
//! unseen.
//!
//! The provided server cannot diverge: path (`tg_admin::WRITE`), request and
//! response type are the **same elements** `tgd` uses. What it does not rebuild
//! is the gate from ADR-0044 — that needs `SO_PEERCRED`, and `tgd` checks that
//! itself.

use std::path::Path;
use std::process::Command as OsCommand;

use tg_admin::WriteResult;
use tg_model::command::Command;
use tg_model::command::Outcome;

mod support;

use support::serve;

/// Calls `tgctl node invite` against the directory.
fn invite(data_dir: &Path, args: &[&str]) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(data_dir)
        .args(["node", "invite"])
        .args(args)
        .output()
        .expect("tgctl is startable")
}

/// **The token stands on standard output and nowhere else.**
///
/// With that `tgctl node invite api > join-token` is the file the agent redeems
/// (it trims the line break). An accompanying line in it would be a token that
/// is not right — and the error would show up only hours later on the new
/// node.
#[tokio::test(flavor = "multi_thread")]
async fn the_token_is_the_whole_standard_output() {
    let served = serve(
        1,
        WriteResult::Applied {
            outcome: Outcome::Applied,
            lints: Vec::new(),
        },
    );

    let out = invite(served.dir.path(), &["tgd-2"]);

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let token = stdout.trim_end();
    assert_eq!(token.len(), 64, "no 256-bit token: {stdout:?}");
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "{token}");
    assert_eq!(stdout, format!("{token}\n"), "more than the token");
}

/// The hash that arrives at the server belongs to the printed token — over a
/// real socket, not merely in the same function.
#[tokio::test(flavor = "multi_thread")]
async fn the_digest_that_arrives_belongs_to_the_printed_token() {
    let served = serve(
        1,
        WriteResult::Applied {
            outcome: Outcome::Applied,
            lints: Vec::new(),
        },
    );

    let out = invite(served.dir.path(), &["tgd-2"]);
    let token = String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_owned();

    let seen = served.seen.lock().expect("mutex").clone();
    match seen.as_slice() {
        [Command::InviteNode { node, digest, .. }] => {
            assert_eq!(node, "tgd-2");
            assert_eq!(*digest, tg_identity::join::token_digest(&token));
        }
        other => panic!("not exactly one invitation: {other:?}"),
    }
}

/// **The token itself never reaches the server.** It is a bearer secret, and
/// the log is subject to retention (ADR-0020).
#[tokio::test(flavor = "multi_thread")]
async fn the_token_itself_never_leaves_the_client() {
    let served = serve(
        1,
        WriteResult::Applied {
            outcome: Outcome::Applied,
            lints: Vec::new(),
        },
    );

    let out = invite(served.dir.path(), &["tgd-2"]);
    let token = String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_owned();

    let seen = format!("{:?}", served.seen.lock().expect("mutex"));
    assert!(
        !seen.contains(&token),
        "the token stood in the command: {seen}"
    );
}

/// **On a follower there is no token.** The socket is node-local; forwarding
/// would mean reaching another machine's socket. So the leader is named and the
/// call aborts — and above all: **no** token is issued that the log does not
/// know.
#[tokio::test(flavor = "multi_thread")]
async fn a_follower_names_the_leader_and_issues_nothing() {
    let served = serve(1, WriteResult::ForwardTo { leader: Some(4) });

    let out = invite(served.dir.path(), &["tgd-2"]);

    assert!(!out.status.success(), "the call counted as a success");
    assert!(out.stdout.is_empty(), "a token without a log: {out:?}");
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    assert!(stderr.contains('4'), "the leader is not named: {stderr}");
}

/// If the node knows no leader, it says so — and likewise issues nothing.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_known_leader_nothing_is_issued_either() {
    let served = serve(1, WriteResult::ForwardTo { leader: None });

    let out = invite(served.dir.path(), &["tgd-2"]);

    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    assert!(stderr.to_lowercase().contains("leader"), "{stderr}");
}

/// A **refused** invitation hands out no token. Otherwise an operator would
/// hold a secret in their hand that applies nowhere, would file it away, and
/// the join would fail on the new node with "wrong token".
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_invitation_issues_nothing() {
    let served = serve(
        1,
        WriteResult::Failed {
            detail: "not invited".to_owned(),
        },
    );

    let out = invite(served.dir.path(), &["tgd-2"]);

    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "a token without an invitation: {out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not invited"),
        "{out:?}"
    );
}

/// Without a socket the directory is named and **nothing** is produced. A
/// token that never arrived at the cluster must not look like one that
/// applies.
#[test]
fn without_a_socket_nothing_is_issued() {
    let dir = tempfile::tempdir().expect("tempdir");

    let out = invite(dir.path(), &["tgd-2"]);

    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        stderr.contains(&dir.path().display().to_string()),
        "{stderr}"
    );
}

/// With `--node-id` the named node is addressed, not the other one.
#[tokio::test(flavor = "multi_thread")]
async fn an_explicit_node_id_picks_that_socket() {
    let served = serve(
        7,
        WriteResult::Applied {
            outcome: Outcome::Applied,
            lints: Vec::new(),
        },
    );
    // A second socket nobody listens on: were `tgctl` to choose it, the call
    // would abort — and the test would see the difference.
    let _ = tokio::net::UnixListener::bind(tg_admin::socket_path(served.dir.path(), 2))
        .expect("second socket");

    let out = invite(served.dir.path(), &["tgd-2", "--node-id", "7"]);

    assert!(out.status.success(), "{out:?}");
    assert_eq!(served.seen.lock().expect("mutex").len(), 1);
}

/// **An invitation the *cluster* refuses issues no token** (ADR-0037).
///
/// Not the same as [`a_rejected_invitation_issues_nothing`] above: that is
/// `WriteResult::Failed`, that is, the **service's** answer. Here the service
/// says "applied" and the **state machine** says no.
///
/// The fifth outcome, and it was missing: `WriteResult::Applied` also encloses
/// a **rejection** — the answer means "the cluster applied the command", not
/// "it accepted it". The branch printed the token anyway, wrote the rejection
/// to stderr and ended with **0**.
///
/// What that costs stands in this command's rationale: `tgctl node invite
/// tgd-2 > join-token` is the file the agent redeems. A token the log does not
/// know thereby lands on the disk, the script carries on, and the error shows
/// up hours later on the new node as "wrong token".
///
/// **Not triggerable today** — `InviteNode` always returns `Applied` in the
/// state machine (measured). It was the **one** of sixteen writes in `tgctl`
/// without this check, and the only one at which a future rejection writes a
/// secret into a file.
#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_the_cluster_rejects_issues_nothing() {
    let served = serve(
        1,
        WriteResult::Applied {
            outcome: Outcome::Rejected(tg_model::command::Rejection::UnknownNode {
                name: "tgd-2".to_owned(),
            }),
            lints: Vec::new(),
        },
    );

    let out = invite(served.dir.path(), &["tgd-2"]);

    assert!(!out.status.success(), "the call counted as a success");
    assert!(
        out.stdout.is_empty(),
        "a token for a refused invitation: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        stderr.contains("tgd-2"),
        "the rejection does not name the node: {stderr}"
    );
}
