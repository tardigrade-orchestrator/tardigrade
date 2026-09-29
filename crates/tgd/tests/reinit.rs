//! A node started with `--init` comes up again with it.
//!
//! `--init` creates the initial membership (phase 5d), and the manual says
//! "exactly once in a cluster's life". Only a unit file is written **once** and
//! used every time afterwards: the switch stays, and the second start is the
//! normal case.
//!
//! # The finding
//!
//! `Node::initialize` wanted to catch exactly that and did not. The arm read
//! `err.to_string().contains("already initialized")` -- and that string occurs
//! **nowhere** in `openraft` 0.9.25, only in three comments. Measured, the second
//! start ended with
//!
//! ```text
//! tgd ended, error: "initialize: not allowed to initialize due to
//! current raft state: last_log_id: Some(...) vote: T1-N1:committed"
//! ```
//!
//! So: **a node with `--init` in the unit file did not come up again after a
//! restart**, and the message pointed at `openraft` instead of at the switch.
//! With five nodes that costs one per reboot until somebody changes the unit.
//!
//! What is checked is therefore the **effect** at two real processes on one data
//! directory. The variant (`InitializeError::NotAllowed`) is checked by the
//! compiler; that it hits the case is checked only by a run.

use std::process::{Command as OsCommand, Stdio};
use std::time::Duration;

use support::Running;

mod support;

/// Starts a node on a given directory -- always with `--init`.
fn start(dir: &std::path::Path, name: &str) -> (Running, std::path::PathBuf) {
    start_with(dir, name, &[])
}

/// The same, with additional settings.
fn start_with(dir: &std::path::Path, name: &str, extra: &[&str]) -> (Running, std::path::PathBuf) {
    let port = support::free_port();
    let cluster = support::free_port();
    let session = support::free_port();

    let child = OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
        .args([
            "--telemetry-addr",
            "off",
            "--id",
            "1",
            "--node",
            "tgd-1",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--cluster-listen",
            &format!("127.0.0.1:{cluster}"),
            "--node-listen",
            &format!("127.0.0.1:{session}"),
            "--data-dir",
            dir.to_str().expect("path"),
            "--peer",
            &format!("1=http://127.0.0.1:{cluster}"),
            "--init",
        ])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(support::log(name))
        .spawn()
        .expect("tgd startable");

    (Running(child), support::log_path(name))
}

/// Waits until the log contains a line -- and returns it.
fn await_line(path: &std::path::Path, needle: &str, name: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "'{needle}' did not appear in {name}'s log:\n{}",
        std::fs::read_to_string(path).unwrap_or_default()
    );
}

/// **Twice `--init` on the same directory, and the second comes up.**
///
/// The first start creates the membership (`fresh=true`), the second finds it
/// there (`fresh=false`) -- and listens. Without the first half the second would
/// say nothing: "comes up" this setup would get from a node that does not
/// evaluate `--init` at all either.
#[test]
fn a_second_start_with_init_comes_up_again() {
    support::sweep_old_logs();
    let dir = tempfile::tempdir().expect("tempdir");
    support::cluster_material(dir.path(), &[1]);

    let (first, first_log) = start(dir.path(), "reinit-1");
    let text = await_line(&first_log, "the node is listening", "reinit-1");
    assert!(
        text.contains("\"fresh\":true"),
        "the first start must create the membership:\n{text}"
    );
    drop(first);

    let (second, second_log) = start(dir.path(), "reinit-2");
    let text = await_line(&second_log, "the node is listening", "reinit-2");
    assert!(
        text.contains("\"fresh\":false"),
        "the second start must find it there instead of creating it:\n{text}"
    );
    assert!(
        !text.contains("tgd ended"),
        "the second start must not end:\n{text}"
    );
    drop(second);
}

/// **And `NotInMembers` stays an error.**
///
/// That is the counter-direction to the swallowing above: **one** rejection is
/// swallowed and not every one. `NotInMembers` means that this node does not
/// occur in the named membership -- a setting of the operator's that is not
/// right.
///
/// Measured with a `RaftError::APIError(_)` arm instead of the variant: the node
/// carried on and reported `fresh=false`, **with an empty membership** -- a
/// process that listens and belongs to no cluster. The message it gives now, by
/// contrast, names the cause: "node 1 has to be a member".
#[test]
fn a_node_outside_its_own_membership_still_fails() {
    support::sweep_old_logs();
    let dir = tempfile::tempdir().expect("tempdir");
    support::cluster_material(dir.path(), &[1]);

    let peer = support::free_port();
    let (node, log) = start_with(
        dir.path(),
        "reinit-3",
        &[
            "--peer",
            &format!("2=http://127.0.0.1:{peer}"),
            "--init-voters",
            "2",
        ],
    );
    let text = await_line(&log, "tgd ended", "reinit-3");
    assert!(
        text.contains("has to be a member"),
        "the message must name the cause:\n{text}"
    );
    assert!(
        !text.contains("the node is listening"),
        "and the node must not listen:\n{text}"
    );
    drop(node);
}
