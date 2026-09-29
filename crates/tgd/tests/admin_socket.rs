//! The access to the admin socket (ADR-0044).
//!
//! On this socket lies not a part of the control but the whole of it -- `Write`
//! with 36 command kinds, plus `ChangeMembership`. Until ADR-0044 it lay on an
//! unauthenticated TCP port.
//!
//! # What is checked here, and what is not
//!
//! The actual access is the **file permissions**: mode `0700` on the socket. This
//! test can only read them, not outwit them -- for that it would need a second
//! user, and `cargo test` runs as one.
//!
//! What is therefore checked is what is checkable and carries the counter-check
//! from determination 2: the rule itself as a pure function, the mode of the
//! created socket, and that a call **without** credentials is refused. The case
//! "foreign UID" is thereby not substantiated, and that stands here instead of
//! being claimed.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command as OsCommand, Stdio};
use std::time::{Duration, Instant};
use tg_model::egress::Transport;

use support::Running;
use tgd::admin::{self, AdminClient, PeerCredentials, WriteResult, may_administer};

mod support;

const PATIENCE: Duration = Duration::from_secs(20);

/// Writes until the cluster has **applied** the command -- and on expiry names the
/// **last outcome**.
///
/// "The node took nothing" does not say whether nobody answered or the state
/// machine **refused** -- and the second case stands in the answer. Measured, that
/// cost me a round: a test document without an XML namespace was refused, the test
/// ran into its patience, and the message did not name the reason.
///
/// Returns the lints (ADR-0048) so that a caller can check them.
async fn write_applied(client: &AdminClient, command: tg_consensus::Command) -> Vec<String> {
    let deadline = Instant::now() + PATIENCE;
    let mut last = String::from("no answer");
    loop {
        assert!(
            Instant::now() < deadline,
            "the node did not take the command, last: {last}"
        );
        match client.write(command.clone()).await {
            Ok(WriteResult::Applied { outcome, lints }) => {
                if matches!(outcome, tg_consensus::Outcome::Applied) {
                    return lints;
                }
                // **The outcome, not the variant**: `Applied` also encloses a
                // rejection (ADR-0045).
                last = format!("{outcome:?}");
            }
            Ok(other) => last = format!("{other:?}"),
            Err(status) => last = status.to_string(),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A running node together with its data directory.
///
/// **The order of the fields is the assurance**, and it is measured: Rust drops
/// fields in declaration order, so the process dies (`Running::drop` = kill +
/// wait) **before** the directory is deleted.
///
/// As a tuple it was the other way round. Local bindings fall in **reverse**
/// order, so with a `let (node, directory) = node()` the directory first -- and
/// then `remove_dir_all` races a process that is still writing. Measured with a
/// program of our own:
///
/// ```text
/// let (a, b) = pair():       drop DIR     -> drop PROCESS   <-- wrong
/// struct { process, dir }:   drop PROCESS -> drop DIR       <-- right
/// ```
///
/// The five fixtures of this crate that give a **struct** (`Server`, `Cluster`,
/// `Node` in `telemetry.rs`) were never affected.
///
/// **What this rearrangement does not substantiate:** a workspace run once left
/// thirteen complete data directories under `/tmp`, and the wrong order was the
/// obvious suspicion. Three runs afterwards leave **zero** each -- with the new
/// order, with the old one, and with an emptied incremental cache. The phenomenon
/// is thereby not reconstructible, and the order is fixed independently of it: the
/// race between `remove_dir_all` and a running process is real, even if it does
/// not explain these thirteen. What is recorded is the **shape** -- complete data
/// directories of `tgd` (`admin-1.sock`, `raft-1.redb`) and `tg-agent`
/// (`agent.lock`, `desired`) --, so that the next occurrence can be classified
/// instead of investigated anew.
struct Node {
    /// **Never read, and that is the purpose**: the field keeps the process
    /// alive, and its `Drop` (kill + wait) runs before the directory's. Whoever
    /// removes it because clippy calls it unused brings back the race the doc
    /// block above describes.
    #[allow(dead_code, reason = "exists for its Drop, see above")]
    running: Running,
    dir: tempfile::TempDir,
}

impl Node {
    /// The node's data directory.
    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

/// Starts a node and returns its directory -- **ready**.
///
/// The setup waits for the admin socket itself, and that is the answer to a
/// measured wobble: `await_socket` did not check whether the process was still
/// **alive**, therefore waited out its whole twenty seconds and reported "the
/// socket did not come up" -- that is, the wrong cause, where `tgd` had died on a
/// port conflict. The finding had stood in the tree since `cluster.rs`
/// (`assert_all_alive`), and the fix did not travel here.
///
/// **At one place and not at twenty**: the callers want a node they can address,
/// and not one they still have to wait for afterwards.
fn node() -> Node {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = support::free_port();
    let cluster = support::free_port();
    let session = support::free_port();
    support::cluster_material(dir.path(), &[1]);

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
            dir.path().to_str().expect("path"),
            "--peer",
            &format!("1=http://127.0.0.1:{cluster}"),
            "--init",
        ])
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    let mut running = Running(child);
    support::await_file(&mut running.0, &admin::socket_path(dir.path(), 1), PATIENCE);

    Node { running, dir }
}

// --- The rule as a pure function --------------------------------------------

/// Our own user and `root` may, nobody else.
///
/// `peer: None` is here no carelessness but the statement: the admin path
/// authorizes over the **uid** and does not need the handle from ADR-0053. The
/// kernel lower bound from there applies to the identity path.
#[test]
fn only_the_own_user_and_root_may_administer() {
    let own = rustix::process::getuid().as_raw();

    assert!(may_administer(&PeerCredentials {
        container: None,
        uid: own,
        gid: 0
    }));
    assert!(may_administer(&PeerCredentials {
        container: None,
        uid: 0,
        gid: 0
    }));

    // A foreign UID -- the number is arbitrary, only not our own and not 0.
    let stranger = own.wrapping_add(1_000).max(1_000);
    assert_ne!(stranger, own);
    assert!(
        !may_administer(&PeerCredentials {
            container: None,
            uid: stranger,
            gid: 0
        }),
        "a foreign UID must not administer"
    );
}

// --- The socket at the running node -----------------------------------------

/// **The socket carries mode `0700`.**
///
/// That is the actual gate (ADR-0044, determination 2). A test that checks only
/// the successful call checks the happy path -- this one reads the permissions
/// that matter.
#[test]
fn the_socket_is_not_readable_by_anyone_else() {
    let node = node();
    let path = admin::socket_path(node.path(), 1);

    let mode = std::fs::metadata(&path)
        .expect("socket")
        .permissions()
        .mode();

    assert_eq!(
        mode & 0o777,
        0o700,
        "the socket stands open with {:o}",
        mode & 0o777
    );
}

/// And a call gets through over it -- otherwise the test above would mean nothing.
#[tokio::test]
async fn the_operator_reaches_the_cluster_through_the_socket() {
    let node = node();
    let path = admin::socket_path(node.path(), 1);

    let admin = AdminClient::connect_unix(&path).expect("admin socket");

    let deadline = Instant::now() + PATIENCE;
    loop {
        if let Ok(status) = admin.status().await
            && status.leader == Some(1)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the node did not take over the leadership"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// **The admin service no longer listens on `--listen`.**
///
/// Since ADR-0044 the port carries only identity.
///
/// # Why it is checked on `Unimplemented` and not on "fails"
///
/// This test's first attempt checked only that the call fails -- and it was
/// **green although the service still hung on the TCP port.** There the
/// connection's credentials are missing, so the gate from determination 2 refuses,
/// and the test passed for the wrong reason. It stood out only at a counter-check
/// that deliberately mounted the service again.
///
/// The two cases can be distinguished by the status code:
///
/// * **not mounted** -- `tonic`'s router answers `Unimplemented`.
/// * **mounted, but refused** -- the gate answers `PermissionDenied`.
///
/// It is therefore checked on `Unimplemented`. That the gate holds even when
/// somebody mounts the service again is checked by the test below.
#[tokio::test]
async fn the_admin_service_is_gone_from_the_tcp_port() {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = support::free_port();
    let cluster = support::free_port();
    let session = support::free_port();
    support::cluster_material(dir.path(), &[1]);

    let _node = Running(
        OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
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
                dir.path().to_str().expect("path"),
                "--peer",
                &format!("1=http://127.0.0.1:{cluster}"),
                "--init",
            ])
            .stdout(support::log("tgd"))
            .stderr(support::log("tgd"))
            .spawn()
            .expect("tgd startable"),
    );

    // Wait first until the node really lives -- otherwise the test only checks
    // that nothing listens yet.
    let socket = admin::socket_path(dir.path(), 1);
    let over_socket = AdminClient::connect_unix(&socket).expect("Admin-Socket");
    let deadline = Instant::now() + PATIENCE;
    loop {
        if over_socket.status().await.is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "the node is not alive");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // And now the same call over TCP, with the anchor that applies for identity:
    // there admin is no longer mounted.
    let leaf = support::await_leaf(dir.path());
    let over_tcp = AdminClient::with_channel(support::open_channel(
        &format!("http://127.0.0.1:{port}"),
        &leaf,
    ));

    let refused = over_tcp.status().await.expect_err("must not get through");
    assert_eq!(
        refused.code(),
        tonic::Code::Unimplemented,
        "expected Unimplemented (not mounted), was {:?}: {}",
        refused.code(),
        refused.message()
    );
}

/// **And the gate holds even when the service is mounted elsewhere.**
///
/// Defence in depth to the test above: there it is about the surface, here about
/// the rule. A request **without** the connection's credentials -- that is, over
/// any transport that delivers none -- does not get through.
///
/// Checked at [`admin::admitted`] and not at the whole service: the rule was
/// pulled out for that, because a test that needs a running Raft is one nobody
/// writes for the rejection path.
#[test]
fn a_call_without_peer_credentials_is_refused() {
    let own = rustix::process::getuid().as_raw();

    // Empty: the state a TCP transport **without a certificate** produces.
    //
    // Here stood "that a TCP transport produces", and that no longer holds since
    // ADR-0103: the operator port carries one, and then the registration is the
    // certificate. The sentence is withdrawn instead of left standing -- a comment
    // that no longer holds costs the credibility of all the others next time.
    let empty = http::Extensions::new();
    assert!(
        !admin::admitted(&empty),
        "without credentials nothing may get through"
    );

    // With matching ones: through.
    let mut mine = http::Extensions::new();
    mine.insert(PeerCredentials {
        container: None,
        uid: own,
        gid: 0,
    });
    assert!(admin::admitted(&mine));

    // With foreign ones: not through.
    let mut stranger = http::Extensions::new();
    stranger.insert(PeerCredentials {
        container: None,
        uid: own.wrapping_add(1_000).max(1_000),
        gid: 0,
    });
    assert!(
        !admin::admitted(&stranger),
        "a foreign UID must not get through"
    );
}

/// **A lint reaches whoever wrote** (ADR-0048).
///
/// The linter warning from ADR-0009 had existed since phase 3 and reached only
/// `tgctl apply`, the node-local way. Whoever submitted over the cluster -- which
/// until recently nobody could -- saw nothing.
///
/// Checked with a single writer without a second instance: it has no warm standby
/// and thereby loses the fast failover from ADR-0010.
#[tokio::test(flavor = "multi_thread")]
async fn a_lint_reaches_the_writer() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let single_writer = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"ledger\" kind=\"service\" class=\"single-writer\">\n\
         <image reference=\"example.com/ledger:1\"/>\n\
         </workload>\n\
         </workloads>\n";

    let deadline = Instant::now() + PATIENCE;
    let mut lints = Vec::new();
    while Instant::now() < deadline {
        match client
            .write(tg_consensus::Command::UpsertWorkload {
                document: single_writer.to_owned(),
            })
            .await
        {
            // **The subject is the lints, not the outcome** (ADR-0048): they
            // travel in the answer and not in the log, so their presence says
            // everything here.
            Ok(WriteResult::Applied { lints: seen, .. }) if !seen.is_empty() => {
                lints = seen;
                break;
            }
            // Shortly after the start nobody leads yet; that is the normal case
            // and no error.
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    assert!(
        lints.iter().any(|lint| lint.contains("ledger")),
        "no lint about the single writer: {lints:?}"
    );
    assert!(
        lints.iter().any(|lint| lint.contains("replicas")),
        "the lint does not say how it is done: {lints:?}"
    );
}

/// **And a sound set yields no lint.** Without this counter-check the test above
/// would only record that something is reported.
#[tokio::test(flavor = "multi_thread")]
async fn a_sound_definition_yields_no_lint() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let plain = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"example.com/api:1\"/>\n\
         </workload>\n\
         </workloads>\n";

    let lints = write_applied(
        &client,
        tg_consensus::Command::UpsertWorkload {
            document: plain.to_owned(),
        },
    )
    .await;
    assert!(lints.is_empty(), "unexpected lint: {lints:?}");
}

/// **The standing query sees the same state** (ADR-0048, determination 2).
///
/// The point of the separation: a lint belongs to the **set**. Here it is
/// triggered by a *different* write from the one that caused it -- exactly the
/// situation in which the answer at the write is of no use.
#[tokio::test(flavor = "multi_thread")]
async fn the_standing_query_sees_the_same_state() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    // Before: nothing declared, nothing to report.
    let deadline = Instant::now() + PATIENCE;
    loop {
        assert!(Instant::now() < deadline, "no answer");
        if let Ok(answer) = client.lints().await {
            assert!(answer.lints.is_empty(), "{answer:?}");
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let single_writer = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"ledger\" kind=\"service\" class=\"single-writer\">\n\
         <image reference=\"example.com/ledger:1\"/>\n\
         </workload>\n\
         </workloads>\n";

    write_applied(
        &client,
        tg_consensus::Command::UpsertWorkload {
            document: single_writer.to_owned(),
        },
    )
    .await;

    let answer = client.lints().await.expect("query");

    assert!(
        answer.lints.iter().any(|lint| lint.contains("ledger")),
        "the query does not see the state: {answer:?}"
    );
    assert!(
        answer.last_applied.is_some(),
        "without a state the statement cannot be classified: {answer:?}"
    );
}

/// **Whoever writes over the socket stands in the audit archive** (ADR-0050).
///
/// The peer credential is no identity -- a uid is no human being, and ADR-0050
/// expressly rejects it as a basis for authorization. As **information** it is
/// true, and a file mode gives no more: the difference is the one between "who
/// may" and "who was".
///
/// Checked at the archive and not at an answer: there it lands **sealed**
/// (ADR-0045), and that is the statement that is of use to an auditor.
#[tokio::test(flavor = "multi_thread")]
async fn the_peer_credential_reaches_the_audit_archive() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let plain = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"example.com/api:1\"/>\n\
         </workload>\n\
         </workloads>\n";

    write_applied(
        &client,
        tg_consensus::Command::UpsertWorkload {
            document: plain.to_owned(),
        },
    )
    .await;

    let own = rustix::process::getuid().as_raw();
    let archive = node.path().join("audit-1.jsonl");
    let deadline = Instant::now() + PATIENCE;
    let mut found = false;
    while !found && Instant::now() < deadline {
        let records = tg_consensus::audit::read(&archive).unwrap_or_default();
        found = records.iter().any(|record| {
            serde_json::from_str::<tg_consensus::audit::Event>(&record.payload)
                .ok()
                .and_then(|event| event.actor)
                == Some(tg_consensus::Actor::LocalUid(own))
        });
        if !found {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    assert!(found, "the peer credential does not stand in the archive");
}

/// **What the cluster itself writes has no actor.**
///
/// The counter-check without which the test above would only show that a uid
/// stands somewhere: the scheduler and the capacity policy decree nothing, they
/// compute (ADR-0011, ADR-0049). An actor there would be an invented statement.
#[tokio::test(flavor = "multi_thread")]
async fn what_the_cluster_writes_itself_has_no_actor() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    // A node with capacity and a workload: the planner places, and that is an
    // entry no human issued.
    write_applied(
        &client,
        tg_consensus::Command::UpsertNode {
            name: "node".to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r1".to_owned(),
            },
            capacity: tg_consensus::Resources::default()
                .with(tg_consensus::Resources::CPU_MILLICORES, 4000),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
    )
    .await;
    // **And the outcome is checked**, not discarded: a `let _ =
    // client.write(...)` stood here. If the workload is refused, the test
    // afterwards waits up to the deadline for an `assign_placement` entry that
    // will never exist -- and then reports the wrong finding.
    write_applied(
        &client,
        tg_consensus::Command::UpsertWorkload {
            document: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
                 <workload name=\"api\" kind=\"service\">\n\
                 <image reference=\"example.com/api:1\"/>\n\
                 </workload>\n\
                 </workloads>\n"
                .to_owned(),
        },
    )
    .await;

    let archive = node.path().join("audit-1.jsonl");
    let deadline = Instant::now() + PATIENCE;
    let mut unattributed = false;
    while !unattributed && Instant::now() < deadline {
        let records = tg_consensus::audit::read(&archive).unwrap_or_default();
        unattributed = records.iter().any(|record| {
            record.kind == "assign_placement"
                && serde_json::from_str::<tg_consensus::audit::Event>(&record.payload)
                    .ok()
                    .and_then(|event| event.actor)
                    .is_none()
        });
        if !unattributed {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    assert!(unattributed, "the planner's placement carried an actor");
}

/// **A second `tgd` on the same data directory does not take the first one's
/// socket away** (ADR-0043, ADR-0044).
///
/// `bind_admin_socket` removes a socket left lying before it binds -- otherwise a
/// crashed predecessor would never come up again. The comment beside it justified
/// that with "no race with a running process -- that one would hold the path".
/// **That is the wrong reason:** a running process holds the *inode*, not the
/// path, and `remove_file` unlinks it nevertheless. The first one would afterwards
/// never get a connection again, and silently at that.
///
/// It is protected nevertheless, but by something entirely different: **`redb`
/// takes an exclusive lock** on the Raft storage, and that is opened **before**
/// any listener arises. The second process ends with "Database already open".
///
/// Exactly this chain is an assumption about foreign code that was noted nowhere
/// -- the same shape as the mitigation that turned out in ADR-0043 to be
/// non-existent. That is why it stands here as a test.
///
/// What is checked is the **effect**: the first process's recovery path is still
/// usable afterwards. A test that reads only the second one's exit code would say
/// nothing about that.
#[test]
fn a_second_node_on_the_same_data_dir_leaves_the_socket_alone() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);

    let second = OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
        .args([
            "--telemetry-addr",
            "off",
            "--id",
            "1",
            "--node",
            "tgd-1",
            "--listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--cluster-listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--node-listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--data-dir",
            node.path().to_str().expect("path"),
            "--peer",
            &format!("1=http://127.0.0.1:{}", support::free_port()),
        ])
        .stdout(support::log("tgd"))
        .stderr(Stdio::piped())
        .spawn()
        .expect("tgd startable");

    // **With a deadline, not with `output()`.** That waits until the child ends
    // -- and if it does *not* end, exactly that is the finding. A test that hangs
    // is worse than one that fails (the finding from 11b); the counter-check to
    // this test demonstrated it.
    let second = await_exit(second, PATIENCE);

    assert!(
        !second.status.success(),
        "a second node on the same data directory must not start up"
    );
    let said = String::from_utf8_lossy(&second.stderr);
    assert!(
        said.contains("Cannot acquire lock") || said.contains("already open"),
        "the reason is not the storage lock -- then this test no longer carries \
         what it claims: {said}"
    );

    // **The actual assertion.** The first process must still be reachable;
    // without it the test would only show that something failed.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let client = AdminClient::connect_unix(&socket)
            .expect("the recovery path must survive the second start");
        client.status().await.expect("status");
    });
}

/// Waits for a child's end -- and ends it when the deadline breaks.
///
/// `output()` would be wrong here: it waits until the child ends, and when it does
/// **not** end, the test hangs instead of failing.
fn await_exit(mut child: Child, patience: Duration) -> std::process::Output {
    let deadline = Instant::now() + patience;

    while Instant::now() < deadline {
        if child.try_wait().expect("child status").is_some() {
            return child.wait_with_output().expect("output");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    let _ = child.wait();
    panic!("the second node carried on instead of ending at the storage lock");
}

/// Waits until the **view** knows a workload.
///
/// `WriteResult::Applied` means "applied in the log", not "visible in the
/// projection": the view is tracked by a task of its own that hangs on the
/// `metrics()` channel (ADR-0030). Whoever grabs immediately afterwards races it
/// -- measured, that falls in about one run in three, and the message ("api stands
/// in the log") points at the log instead of at the view.
///
/// What is waited for is the **presence** of the workload, never the property the
/// caller checks: otherwise the test would wait for its own assertion.
async fn await_workload(client: &AdminClient, name: &str) -> admin::ProjectedWorkload {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let view = client.projection().await.expect("view");
        if let Some(workload) = view.workloads.into_iter().find(|w| w.name == name) {
            return workload;
        }
        assert!(
            Instant::now() < deadline,
            "the view does not know '{name}' (state {:?})",
            client.projection().await.ok().and_then(|v| v.last_applied)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// **The decreed generation comes from the log into the read view** (ADR-0071).
///
/// It is desired state and therefore stands not in the projection but in the state
/// -- this test is the seam between them. The test rig in `tgctl` cannot see it:
/// there the admin service is provided, and the answer is filed instead of read.
///
/// Without a read path an operator learned the current number only from a
/// **rejection** -- `restart` demands it, and backwards it is refused.
#[tokio::test(flavor = "multi_thread")]
async fn the_ordered_generation_reaches_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let document = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"example.com/api:1\"/>\n\
         </workload>\n\
         </workloads>\n";

    write_applied(
        &client,
        tg_consensus::Command::UpsertWorkload {
            document: document.to_owned(),
        },
    )
    .await;

    // Without a decree the generation is zero -- half the assertion, for a view
    // that always names a number would say nothing.
    let api = await_workload(&client, "api").await;
    assert!(
        api.ordered.is_empty(),
        "without a decree nothing may stand there: {:?}",
        api.ordered
    );

    // **Two levels**: for all, and beyond that for one instance.
    for command in [
        tg_consensus::Command::SetWorkloadGeneration {
            workload: "api".to_owned(),
            instance: None,
            generation: 2,
        },
        tg_consensus::Command::SetWorkloadGeneration {
            workload: "api".to_owned(),
            instance: Some(1),
            generation: 5,
        },
    ] {
        let written = client.write(command).await.expect("write");
        assert!(
            matches!(
                written,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "the decree did not arrive: {written:?}"
        );
    }

    // The same seam a second time: the decrees are in the log, the view catches
    // up. What is waited for is until **something** stands there; **what** is
    // checked by the assertion afterwards -- a waiting condition on the content
    // would let the test wait for its own result.
    let api = {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let workload = await_workload(&client, "api").await;
            if !workload.ordered.is_empty() {
                break workload;
            }
            assert!(
                Instant::now() < deadline,
                "the decrees did not reach the view"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    assert_eq!(api.ordered.all, 2);
    assert_eq!(api.ordered.instances.get(&1).copied(), Some(5));
    assert_eq!(
        api.ordered.wanted(1),
        5,
        "the effective generation is the maximum of both levels"
    );
    assert_eq!(
        api.ordered.wanted(0),
        2,
        "without a per-instance decree the general one applies"
    );
}

/// **A node without an address is refused, not waited out** (ADR-0005).
///
/// # The finding
///
/// `MembershipChange` carries **no address**, and the doc comment beside it has
/// said since phase 5d what follows from that: "whoever admits a node must have
/// made it reachable beforehand." **Nobody checked that.**
///
/// Measured at a real `tgd`, an `AddLearner` on an identifier without an address
/// answers **`Changed`** -- it succeeds, and immediately at that. An operator
/// afterwards promotes a node that will never answer, and a voter without an
/// address raises the quorum without being able to answer: exactly what the
/// two-step procedure is supposed to prevent.
///
/// # Why the rule is pure
///
/// The same justification as at [`may_administer`]: a precondition one can only
/// check with a running Raft is one whose rejection path nobody sees.
#[test]
fn a_node_without_an_address_is_refused() {
    let peers = tg_consensus::net::PeerAddrs::new()
        .with(1, "http://127.0.0.1:1")
        .with(2, "http://127.0.0.1:2");

    // Entered: no finding.
    assert!(
        admin::unreachable(
            &admin::MembershipChange::AddLearner {
                id: 2,
                blocking: true
            },
            &peers,
            1
        )
        .is_none()
    );

    // Not entered: refused, and the message names the identifier **and** where
    // the address belongs.
    let detail = admin::unreachable(
        &admin::MembershipChange::AddLearner {
            id: 6,
            blocking: true,
        },
        &peers,
        1,
    )
    .expect("without an address it must be refused");
    assert!(detail.contains('6'), "{detail}");
    assert!(detail.contains("--peer"), "{detail}");

    // **The voters too**, and that is the most expensive case.
    let detail = admin::unreachable(
        &admin::MembershipChange::SetVoters {
            ids: vec![1, 2, 6],
            retain: false,
        },
        &peers,
        1,
    )
    .expect("a voter without an address must be refused");
    assert!(detail.contains('6'), "{detail}");

    // **Our own identifier does not count.** A node does not dial itself;
    // demanding its address in its own `--peer` would mean enforcing a setting
    // that has no effect.
    let bare = tg_consensus::net::PeerAddrs::new().with(2, "http://127.0.0.1:2");
    assert!(
        admin::unreachable(
            &admin::MembershipChange::SetVoters {
                ids: vec![1, 2],
                retain: false
            },
            &bare,
            1
        )
        .is_none(),
        "our own identifier needs no address"
    );
}

/// **The strictness of the admin protocol is an assurance, not an attribute**
/// (ADR-0083).
///
/// # What it means
///
/// A counterpart that does not understand a message fully does **not** process it.
/// The case at issue is `MembershipChange`: a field an old `tgd` discards means,
/// with `blocking`, promoting a learner that knows nothing yet -- exactly the
/// situation the two-step procedure from phase 5d is built against.
///
/// Until ADR-0083 **one** of eleven types carried the attribute, while the payload
/// within it (`Command`, `Submission`) is strict: strict the cargo, lenient the
/// envelope.
///
/// # The positive control is half the assurance
///
/// This measurement's first attempt used `AddLearner` instead of `add_learner`
/// (`rename_all = "snake_case"`) and reported a rejection that came from the
/// **variant name**. Without the control that would have become a finding that
/// does not exist -- and a test that checks a rejection would have got it on a typo
/// too.
#[test]
fn an_unknown_field_is_refused_across_the_admin_protocol() {
    use tgd::admin::{MembershipChange, ProjectionResponse, StatusRequest, StatusResponse};

    // Control: the same message **without** the foreign field must carry.
    let clean = r#"{"add_learner":{"id":42,"blocking":true}}"#;
    assert!(
        serde_json::from_str::<MembershipChange>(clean).is_ok(),
        "the control does not carry -- then the case below checks nothing"
    );

    // The decree: it carries `blocking` and decides over the quorum.
    let extra = r#"{"add_learner":{"id":42,"blocking":true,"something_new":1}}"#;
    let refused = serde_json::from_str::<MembershipChange>(extra);
    assert!(
        refused.is_err(),
        "a membership change with an unknown field must be refused"
    );
    assert!(
        format!("{}", refused.expect_err("refused")).contains("something_new"),
        "and the message must name the field"
    );

    // The **empty** request too. It accepted `{"something":1}` -- that cost
    // nothing and said nothing, but a reader has to classify an exception.
    assert!(
        serde_json::from_str::<StatusRequest>(r#"{"something_new":1}"#).is_err(),
        "an empty request is strict too -- otherwise the rule would be one with holes"
    );

    // And the counter-direction: what `tgd` answers. Lenient would mean that an old
    // `tgctl` shows a silently truncated picture in the recovery case -- and
    // precisely then nobody can check it (ADR-0083, D2).
    let status = r#"{"id":1,"is_leader":true,"last_applied":null,"voters":[1],"something_new":1}"#;
    assert!(
        serde_json::from_str::<StatusResponse>(status).is_err(),
        "the answer is strict too"
    );
    let projection = r#"{"workloads":[],"nodes":[],"applied":null,"something_new":1}"#;
    assert!(
        serde_json::from_str::<ProjectionResponse>(projection).is_err(),
        "the projection answer is strict too"
    );
}

/// **And every serialized type carries it** (ADR-0083, determination 3).
///
/// The test above checks five types; this one checks that none is forgotten.
/// Without it a new type would be silently exempt -- exactly the state ADR-0083
/// arose from: eleven types, written individually, one with the attribute.
///
/// What is read is the **source**: Rust cannot enumerate its types, and a list in
/// the test would be the shape this tree has measured four times as a source of
/// error.
#[test]
fn every_serialised_admin_type_is_strict() {
    // **The protocol has lain in `tg-admin` since ADR-0134.** The service stayed
    // here; the serialized types moved along, and with them this check.
    let source = include_str!("../../tg-admin/src/lib.rs");

    let mut findings = Vec::new();
    let mut checked = 0_usize;
    let mut attrs: Vec<&str> = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[") {
            attrs.push(trimmed);
            continue;
        }
        let declaration = trimmed
            .strip_prefix("pub struct ")
            .or_else(|| trimmed.strip_prefix("pub enum "));
        if let Some(rest) = declaration {
            let name = rest
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or_default();
            // Only what goes over the wire.
            if attrs.iter().any(|attr| attr.contains("Deserialize")) {
                checked += 1;
                if !attrs
                    .iter()
                    .any(|attr| attr.contains("deny_unknown_fields"))
                {
                    findings.push(name.to_owned());
                }
            }
        }
        if !trimmed.is_empty() && !trimmed.starts_with("///") && !trimmed.starts_with("//") {
            attrs.clear();
        }
    }

    // A guard that found nothing confirms everything.
    assert!(
        checked >= 10,
        "only {checked} serialized types found -- the source was not read"
    );
    assert!(
        findings.is_empty(),
        "these admin types are lenient (ADR-0083): {findings:?}"
    );
}

/// **A message over 4 MiB arrives.**
///
/// Without a setting `tonic` allows 4 MiB. Measured, that breaks first at the
/// snapshot: openraft chunks at 3 MiB, and `serde_json` encodes `Vec<u8>` as a
/// sequence of numbers -- factor **3.57**, so 10.7 MiB per piece. A node that has
/// to catch up thereby **never** caught up (phase 5d), and quietly at that: the
/// receiver refuses, openraft repeats.
///
/// What is checked here is the **limit**, not the snapshot: a call over the admin
/// socket with a 6 MiB document. That it returns a *verdict* -- and no transport
/// error -- means that the bytes came through encoder and decoder. The snapshot
/// path needs the same limit at the same place (`tg_wire::server`) but demands a
/// cluster with the corresponding state; the ordering condition for that stands as
/// a test in `tg-consensus`.
///
/// The document is deliberately **not** valid XML: what is checked is the
/// transport, and a rejection of the content is the proof that the content
/// arrived.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_over_four_mebibytes_arrives() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let big = "x".repeat(6 * 1024 * 1024);
    assert!(
        big.len() > 4 * 1024 * 1024,
        "the document must lie above the default"
    );

    let deadline = Instant::now() + PATIENCE;
    let mut answer = None;
    while Instant::now() < deadline {
        match client
            .write(tg_consensus::Command::UpsertWorkload {
                document: big.clone(),
            })
            .await
        {
            Ok(result) => {
                answer = Some(result);
                break;
            }
            // Shortly after the start nobody leads yet.
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    let Some(result) = answer else {
        panic!("no answer -- a message over 4 MiB did not get through");
    };
    // **A verdict, not a transport error.** Which one is the same here: that the
    // state machine saw the document is the statement.
    assert!(
        matches!(result, WriteResult::Applied { .. }),
        "the message did not reach the state machine: {result:?}"
    );
}

/// **A node's capacity reaches the read path** (ADR-0034, ADR-0049).
///
/// # The finding
///
/// `ProjectedNode` carried **no** capacity -- neither the wanted one the planner
/// computes with nor the reported one a capacity policy computes on. For an
/// operator that means: `NoRoom` is not reconstructible (`tg_scheduler_domain_*`
/// gives sums per **domain**), and a policy per ADR-0049 is written **blind** --
/// its input was nowhere to be seen, not even as a metric.
///
/// # Why against a real node
///
/// The wanted number stands in the **state** (`NodeEntry`), the reported one in
/// the **projection** -- this test is the seam between them. The test rig in
/// `tgctl` cannot see it: there the admin service is provided and the answer filed
/// instead of read.
///
/// **Nothing** is reported here -- for that a `tg-agent` with a session would be
/// needed, and that belongs in its test rig. What counts here is the distinction:
/// the wanted number stands there, and "nothing heard yet" is said as `None` and
/// not invented as zero.
#[tokio::test(flavor = "multi_thread")]
async fn the_capacity_of_a_node_reaches_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    write_applied(
        &client,
        tg_consensus::Command::UpsertNode {
            name: "node-9".to_owned(),
            topology: tg_model::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r1".to_owned(),
            },
            capacity: tg_model::Resources::default()
                .with(tg_model::Resources::CPU_MILLICORES, 4000),
            reserved: tg_model::Resources::default()
                .with(tg_model::Resources::CPU_MILLICORES, 1000),
            source: tg_consensus::Origin::default(),
        },
    )
    .await;

    let deadline = Instant::now() + PATIENCE;
    let node = loop {
        let view = client.projection().await.expect("view");
        if let Some(node) = view.nodes.into_iter().find(|n| n.name == "node-9") {
            break node;
        }
        assert!(
            Instant::now() < deadline,
            "the view does not know 'node-9' (state {:?})",
            client.projection().await.ok().and_then(|v| v.last_applied)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    assert_eq!(
        node.capacity,
        vec![(tg_model::Resources::CPU_MILLICORES.to_owned(), 4000)],
        "the wanted capacity must reach the read path"
    );
    assert_eq!(
        node.reserved,
        vec![(tg_model::Resources::CPU_MILLICORES.to_owned(), 1000)],
        "and the reserve beside it (ADR-0047)"
    );
    // **Separate, and the absence is a statement** (ADR-0004): without a report
    // there is no measured number, and a zero would be an invented one -- the same
    // rule as with the generations and at
    // `tg_node_last_report_timestamp_seconds`.
    assert_eq!(
        node.reported_capacity, None,
        "without a report no measured capacity may stand there: {:?}",
        node.reported_capacity
    );
}

/// **Egress and placement reach the read path** (ADR-0041, ADR-0011).
///
/// # The finding
///
/// `ProjectedWorkload` carried `edges` -- who may talk to whom in the mesh -- and
/// **not** the egress permissions. Both are deny-by-default (ADR-0025, ADR-0041),
/// both are written by `tgctl cluster allow…`, and only the one half was readable.
/// A permission one cannot enumerate one cannot check (ADR-0020) -- and "where may
/// this workload phone" is exactly the question an auditor asks.
///
/// Plus the placement: **where** an instance is to lie stood nowhere.
///
/// # Why against a real node
///
/// Both are **desired state** and come from the replicated state, not from the
/// projection -- this test is the seam. The test rig in `tgctl` files the answer
/// and cannot see it.
#[tokio::test(flavor = "multi_thread")]
async fn egress_and_placement_reach_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let document = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"example.com/api:1\"/>\n\
         </workload>\n\
         </workloads>\n";

    // In turn, and **every outcome is asserted**: `Applied` also encloses a
    // rejection (the finding from the path of the control plane to the node), and
    // a refused placement would turn the test into a statement about nothing.
    for command in [
        tg_consensus::Command::UpsertWorkload {
            document: document.to_owned(),
        },
        tg_consensus::Command::UpsertNode {
            name: "node-1".to_owned(),
            topology: tg_model::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r1".to_owned(),
            },
            capacity: tg_model::Resources::default(),
            reserved: tg_model::Resources::default(),
            source: tg_consensus::Origin::default(),
        },
        tg_consensus::Command::AssignPlacement {
            workload: "api".to_owned(),
            instance: 0,
            node: "node-1".to_owned(),
        },
        tg_consensus::Command::AllowEgress {
            workload: "api".to_owned(),
            host: "s3.example.com".to_owned(),
            port: 443,
            transport: Transport::Tcp,
        },
    ] {
        let kind = command.kind();
        let deadline = Instant::now() + PATIENCE;
        loop {
            assert!(Instant::now() < deadline, "{kind} did not get through");
            match client.write(command.clone()).await {
                Ok(WriteResult::Applied { outcome, .. }) => {
                    assert!(
                        !matches!(outcome, tg_consensus::Outcome::Rejected(_)),
                        "{kind} was refused: {outcome:?}"
                    );
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    let api = await_workload(&client, "api").await;
    assert_eq!(
        api.egress,
        vec![("s3.example.com".to_owned(), 443, "tcp".to_owned())],
        "the egress permission must reach the read path"
    );
    assert_eq!(
        api.placed,
        vec![(0, "node-1".to_owned())],
        "the placement must reach the read path"
    );
    // An ordinary workload has no active role (ADR-0064, D8) -- half the
    // assertion, for a view that always names a holder would say nothing.
    assert_eq!(
        api.lease, None,
        "a replicated workload holds no lease: {:?}",
        api.lease
    );
    // **And the class says why that is the normal case** (ADR-0010). Written out,
    // not `{:?}`: a renamed variant would otherwise change the wire format without
    // anybody noticing at the rename.
    assert_eq!(
        api.class, "replicated",
        "the class must reach the read path"
    );
}

/// **The canonical document reaches the read path** (ADR-0008).
///
/// What lies in the log is what the **loader** understood -- not the file an
/// operator submitted. Exactly that this test checks: the submitted document is
/// **not** indented like the returned one, and the assertion lies on the
/// **canonical** form, not on a comparison with the input.
///
/// And a name the cluster does not know yields `None` -- not an empty string:
/// "does not exist" and "is empty" are two statements.
#[tokio::test(flavor = "multi_thread")]
async fn the_canonical_document_reaches_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let document = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"example.com/api:1\"/>\n\
         </workload>\n\
         </workloads>\n";

    write_applied(
        &client,
        tg_consensus::Command::UpsertWorkload {
            document: document.to_owned(),
        },
    )
    .await;

    let answer = client.document("api").await.expect("document");
    let stored = answer.document.expect("the cluster knows 'api'");
    // The **canonical** document: the same statement, not the same bytes. Whoever
    // asserted on the input here would check not the loader but a string.
    assert!(
        stored.contains("name=\"api\"") && stored.contains("example.com/api:1"),
        "the document does not carry the declaration: {stored}"
    );
    // And it is readable again -- the assurance for whose sake the call exists:
    // `tgctl cluster get … > api.xml` must yield a file `tgctl cluster apply`
    // accepts.
    assert!(
        tg_defs::from_str(&stored).is_ok(),
        "the returned document does not parse: {stored}"
    );

    // "Does not exist" is `None` and not an empty string -- half the assertion,
    // for an answer that always names a document would say nothing.
    let unknown = client.document("does-not-exist").await.expect("answer");
    assert_eq!(
        unknown.document, None,
        "an unknown name must yield `None`: {:?}",
        unknown.document
    );
}

/// What holds cluster-wide comes back from the **replicated state**.
///
/// Four settings hold for the whole cluster -- address plan (ADR-0069), sidecar
/// overhead (ADR-0067), capacity policy (ADR-0049) and rotation policy (ADR-0057).
/// All four are written by `tgctl`, and **none** was readable. For the two policies
/// that weighs double, because `Set…Policy` **replaces** the whole policy: whoever
/// wants to add a rule must know the existing ones -- and could not see them.
///
/// The witness stands here and not only in `tgctl`'s test rig: that one provides
/// the admin service and cannot see the **seam** -- command into the log, state,
/// answer -- at all. And the counter-direction carries half the assurance: before
/// the write nothing is set, and the answer must say that too.
#[tokio::test(flavor = "multi_thread")]
async fn what_holds_cluster_wide_reaches_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    // Before the write: nothing set. Without this half an answer that always
    // names something would be just as green.
    let deadline = Instant::now() + PATIENCE;
    let empty = loop {
        assert!(Instant::now() < deadline, "the node did not answer");
        if let Ok(answer) = client.settings().await {
            break answer;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(empty.network, None, "a fresh cluster has no network");
    assert!(
        empty.capacity.is_empty() && empty.rotation.is_empty(),
        "a fresh cluster has no policy"
    );

    let commands = [
        tg_consensus::Command::SetClusterNetwork {
            cidr: "10.49.0.0/16".to_owned(),
            node_prefix: 24,
        },
        tg_consensus::Command::SetSidecarOverhead {
            resources: tg_model::Resources::default().with("millicores", 50),
        },
        tg_consensus::Command::SetCapacityPolicy {
            policy: tg_model::capacity::CapacityPolicy::default().with(
                "millicores",
                tg_model::capacity::Rule {
                    subtract: 2000,
                    percent: 80,
                    cap: Some(64_000),
                    reserve: 1000,
                },
            ),
        },
        tg_consensus::Command::SetRotationPolicy {
            policy: tg_model::RotationPolicy::default().with(tg_model::KeyKind::Underlay, 90),
        },
    ];

    for command in commands {
        write_applied(&client, command.clone()).await;
    }

    let answer = client.settings().await.expect("settings");
    assert_eq!(
        answer.network,
        Some(("10.49.0.0/16".to_owned(), 24)),
        "the address plan is missing"
    );
    assert_eq!(
        answer.sidecar_overhead,
        vec![("millicores".to_owned(), 50)],
        "the sidecar overhead is missing"
    );
    let (resource, rule) = answer.capacity.first().expect("one capacity rule");
    assert_eq!(resource, "millicores");
    assert_eq!(
        (rule.subtract, rule.percent, rule.cap, rule.reserve),
        (2000, 80, Some(64_000), 1000),
        "the rule did not come back intact"
    );
    assert_eq!(
        answer.rotation,
        vec![(tg_model::KeyKind::Underlay, 90)],
        "the rotation policy is missing"
    );
}

/// **The ordinal reaches the read path** (ADR-0039).
///
/// # The finding
///
/// From the ordinal follows a node's subnet and from that every route, every
/// nftables rule and every `AllowedIP` (phase 9a) -- on a network problem the first
/// number an operator looks for. `ProjectedNode` did not carry it, and `tgctl`
/// could show it nowhere.
///
/// # Why against a real node
///
/// The number arises in the **same apply** that checks the invitation (ADR-0039)
/// -- it hangs on `AdmitNode` and not on `UpsertNode`. The test rig in `tgctl`
/// files a `ProjectedNode` and cannot see this seam at all; measured, it stays
/// green when one cuts it.
///
/// Both directions, and the second carries half the assurance: **`AdmitNode` takes
/// up only trust, no capacity** (ADR-0037), so there is an entered node without an
/// ordinal -- and it must say so instead of inventing a zero.
#[tokio::test(flavor = "multi_thread")]
async fn the_ordinal_of_a_node_reaches_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let upsert = |name: &str| tg_consensus::Command::UpsertNode {
        name: name.to_owned(),
        topology: tg_model::Topology {
            site: "fra".to_owned(),
            hall: "h1".to_owned(),
            rack: "r1".to_owned(),
        },
        capacity: tg_model::Resources::default(),
        reserved: tg_model::Resources::default(),
        source: tg_consensus::Origin::default(),
    };

    let commands = [
        upsert("with-subnet"),
        upsert("without-subnet"),
        tg_consensus::Command::InviteNode {
            node: "with-subnet".to_owned(),
            digest: "00".repeat(32),
            expires_at: 4_102_444_800,
        },
        tg_consensus::Command::AdmitNode {
            node: "with-subnet".to_owned(),
            spki: "AAAA".to_owned(),
            at: 1_800_000_000,
        },
    ];

    for command in commands {
        write_applied(&client, command.clone()).await;
    }

    let deadline = Instant::now() + PATIENCE;
    let nodes = loop {
        let view = client.projection().await.expect("view");
        if view.nodes.len() >= 2 {
            break view.nodes;
        }
        assert!(
            Instant::now() < deadline,
            "the view does not know the nodes"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let admitted = nodes
        .iter()
        .find(|n| n.name == "with-subnet")
        .expect("the admitted node");
    assert!(
        admitted.ordinal.is_some(),
        "an admitted node has an ordinal: {:?}",
        admitted.ordinal
    );

    let plain = nodes
        .iter()
        .find(|n| n.name == "without-subnet")
        .expect("the entered node");
    assert_eq!(
        plain.ordinal, None,
        "without admission there is no subnet: {:?}",
        plain.ordinal
    );
}

/// **Who may be a node reaches the read path** (ADR-0037, ADR-0043).
///
/// # The finding
///
/// `trust` is the list that decides who may identify themselves as a node in this
/// cluster -- **the key is the credential**. It is written by `AdmitNode`,
/// `RotateTrust` and `RevokeTrust`; in production code it was read only by the
/// check itself. An operator could not see it, and with that the effect of a
/// **security action** was not ascertainable: `RevokeTrust` is the documented
/// answer to a compromised key (ADR-0054).
///
/// The same for the underlay announcement (ADR-0039, ADR-0042) -- without it a node
/// gets **no tunnel** -- and for the open invitations: every one is a standing
/// admission credential with a deadline.
///
/// # Why against a real node
///
/// All three come from the **replicated state** and not from the projection
/// (ADR-0004); the test rig in `tgctl` files the answer and cannot see this seam.
///
/// And the counter-direction carries half the assurance: a **revocation** takes the
/// node out again. Without it the test would only show that something stands in the
/// list.
#[tokio::test(flavor = "multi_thread")]
async fn who_may_be_a_node_reaches_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let write = async |command: tg_consensus::Command| {
        write_applied(&client, command).await;
    };

    write(tg_consensus::Command::InviteNode {
        node: "admitted".to_owned(),
        digest: "00".repeat(32),
        expires_at: 4_102_444_800,
    })
    .await;
    write(tg_consensus::Command::AdmitNode {
        node: "admitted".to_owned(),
        spki: "MCowBQYDK2VwAyEAtest".to_owned(),
        at: 1_800_000_000,
    })
    .await;
    write(tg_consensus::Command::AnnounceUnderlay {
        node: "admitted".to_owned(),
        key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_owned(),
        endpoint: "10.0.0.1:51820".to_owned(),
        at: 1_800_000_000,
    })
    .await;
    // An invitation that stays **open**: it is the standing credential for whose
    // sake the enumeration exists.
    write(tg_consensus::Command::InviteNode {
        node: "invited".to_owned(),
        digest: "11".repeat(32),
        expires_at: 4_102_444_800,
    })
    .await;

    let answer = client.trust().await.expect("trust list");
    let admitted = answer
        .nodes
        .iter()
        .find(|n| n.name == "admitted")
        .expect("the admitted node");
    assert_eq!(
        admitted.spki, "MCowBQYDK2VwAyEAtest",
        "the SPKI must reach the read path"
    );
    assert!(
        admitted.ordinal.is_some(),
        "an admission assigns an ordinal (ADR-0039)"
    );
    assert_eq!(
        admitted.underlay,
        Some((
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_owned(),
            "10.0.0.1:51820".to_owned()
        )),
        "the announcement is missing"
    );
    assert_eq!(
        answer.invitations,
        vec![("invited".to_owned(), 4_102_444_800)],
        "the open invitation is missing -- and the consumed one must no longer \
         stand there"
    );

    // **The counter-direction**: a revocation takes it out. That is the effect for
    // whose sake an operator reads the list at all.
    write(tg_consensus::Command::RevokeTrust {
        node: "admitted".to_owned(),
    })
    .await;
    let answer = client.trust().await.expect("trust list");
    assert!(
        !answer.nodes.iter().any(|n| n.name == "admitted"),
        "a revocation must be visible in the read path: {:?}",
        answer.nodes
    );
}

/// **A tombstone reaches the read path, and the metric counts it** (ADR-0042).
///
/// # The finding
///
/// `DeleteVolume` is the only **destructive** command (ADR-0027) and the decision,
/// not the deed: the node carries it out when it sees the tombstone in the slice.
/// Whether it did so nobody could look up -- a node that has been away for days has
/// not.
///
/// In addition, tombstones are the **only collection in the replicated state** that
/// grows without anything clearing it away: one disappears only when the same
/// volume is declared again. The retention period is named as open in ADR-0042 --
/// until then the number is what an operator has.
///
/// # The counter-direction
///
/// If the volume is **declared again**, the tombstone is obsolete and disappears --
/// on all nodes (ADR-0042). Without this half the test would only show that
/// something stands there at some point.
#[tokio::test(flavor = "multi_thread")]
async fn a_tombstone_reaches_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let write = async |command: tg_consensus::Command| {
        write_applied(&client, command).await;
    };

    write(tg_consensus::Command::DeleteVolume {
        volume: "archive".to_owned(),
        node: "node-9".to_owned(),
        at: 1_800_000_000,
    })
    .await;

    let answer = client.volumes().await.expect("tombstones");
    assert_eq!(
        answer.tombstones,
        vec![("node-9".to_owned(), vec!["archive".to_owned()])],
        "the tombstone must reach the read path"
    );

    // Declared again means obsolete -- and then the list is empty.
    let document = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"storage\" kind=\"service\">\n\
         <image reference=\"example.com/storage:1\"/>\n\
         <volumes><volume name=\"archive\" path=\"/data\" mode=\"readWrite\" size=\"8388608\"/></volumes>\n\
         </workload>\n\
         </workloads>\n";
    write(tg_consensus::Command::UpsertWorkload {
        document: document.to_owned(),
    })
    .await;

    let answer = client.volumes().await.expect("tombstones");
    assert!(
        answer.tombstones.is_empty(),
        "a volume declared again clears its tombstone: {:?}",
        answer.tombstones
    );
}

/// **Which secrets exist and who may read them reaches the read path** (ADR-0016,
/// ADR-0096).
///
/// Against a **real** `tgd`: the answer comes from the replicated state (ADR-0004),
/// and the test rig in `tgctl` provides the service and cannot see this seam at
/// all.
///
/// The counter-check stands **in the same test**: before the write the answer is
/// empty. Without it one that always names something would be just as green.
#[tokio::test(flavor = "multi_thread")]
async fn the_secrets_and_their_readers_reach_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let deadline = Instant::now() + PATIENCE;
    let empty = loop {
        assert!(Instant::now() < deadline, "the node did not answer");
        if let Ok(answer) = client.secrets().await {
            break answer;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        empty.names.is_empty() && empty.grants.is_empty() && empty.registries.is_empty(),
        "a fresh cluster has no secrets: {empty:?}"
    );

    let workload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"registry.test/api:1\"/>\n\
         </workload>\n\
         </workloads>\n";
    let commands = [
        tg_consensus::Command::UpsertWorkload {
            document: workload.to_owned(),
        },
        tg_consensus::Command::PutSecret {
            name: "reg-key".to_owned(),
            value: tg_identity::secrets::Sealed {
                // An invented ciphertext -- it is never opened here. Its
                // **length** is the statement: 16 bytes of tag plus five bytes of
                // plaintext, and exactly those five the answer must name.
                ciphertext: vec![7; 21],
                nonce: vec![4, 5, 6],
            },
        },
        tg_consensus::Command::AllowSecret {
            workload: "api".to_owned(),
            secret: "reg-key".to_owned(),
        },
        tg_consensus::Command::SetRegistryCredential {
            registry: "registry.test".to_owned(),
            secret: "reg-key".to_owned(),
        },
    ];

    for command in commands {
        write_applied(&client, command.clone()).await;
    }

    let deadline = Instant::now() + PATIENCE;
    let answer = loop {
        assert!(Instant::now() < deadline, "the view knows nothing of it");
        let answer = client.secrets().await.expect("answer");
        if !answer.names.is_empty() {
            break answer;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    assert_eq!(
        answer.names,
        vec![("reg-key".to_owned(), 5)],
        "the answer does not name the size of the plaintext -- the one number \
         with which an operator finds a secret above the limit"
    );
    assert_eq!(
        answer.grants,
        vec![("api".to_owned(), "reg-key".to_owned())],
        "the permission is missing -- that is the line that explains a refused \
         deletion"
    );
    assert_eq!(
        answer.registries,
        vec![("registry.test".to_owned(), "reg-key".to_owned())]
    );

    // **And the value does not travel along** (ADR-0096): a read path that sent it
    // along would bring ciphertext into every log in which such an answer lands.
    let serialized = serde_json::to_string(&answer).expect("serializable");
    assert!(
        !serialized.contains("ciphertext"),
        "the sealed value travels along in the read path: {serialized}"
    );
}

/// **The role in the leaf decides who is an operator** (ADR-0103,
/// determination 2).
///
/// Checked at [`admin::operator_of`] and not at the service: `TlsConnectInfo` has
/// no public constructor, so the wiring is not producible without a real port --
/// the **interpretation** very much is, and that is where the decision falls.
///
/// The carrying assertion is the second: a **node** leaf yields no name here.
/// Without it an SPKI in the wrong list would let a node administer, and the blast
/// radius from ADR-0037 would no longer be the promised one.
#[test]
fn only_an_operator_leaf_names_an_operator() {
    let domain = tg_identity::TrustDomain::new("cluster.local").expect("domain");

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let as_operator = tg_identity::SpiffeId::for_operator(&domain, "dana").expect("identifier");
    let leaf = tg_identity::cluster::node_leaf(&key, &as_operator).expect("leaf");
    assert_eq!(
        admin::operator_of(&rustls_pki_types::CertificateDer::from(leaf)),
        Some("dana".to_owned())
    );

    // **The same SPKI, a different role** -- and thereby no operator.
    let as_node = tg_identity::SpiffeId::for_node(&domain, "dana").expect("identifier");
    let leaf = tg_identity::cluster::node_leaf(&key, &as_node).expect("leaf");
    assert_eq!(
        admin::operator_of(&rustls_pki_types::CertificateDer::from(leaf)),
        None,
        "a node leaf must not yield an operator name"
    );

    // And what is no certificate yields none either.
    assert_eq!(
        admin::operator_of(&rustls_pki_types::CertificateDer::from(vec![0x30; 32])),
        None
    );
}

/// Starts a node **with** an operator port and returns that port.
///
/// A function of its own because the test would otherwise grow past the line limit
/// -- and because it differs from [`node`] only in the fourth listener.
fn node_with_operator_port() -> (Node, u16) {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = support::free_port();
    let cluster = support::free_port();
    let session = support::free_port();
    let operator = support::free_port();
    support::cluster_material(dir.path(), &[1]);

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
            "--operator-listen",
            &format!("127.0.0.1:{operator}"),
            "--data-dir",
            dir.path().to_str().expect("path"),
            "--peer",
            &format!("1=http://127.0.0.1:{cluster}"),
            "--init",
        ])
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    (
        Node {
            running: Running(child),
            dir,
        },
        operator,
    )
}

/// **The operator port carries an operator -- and only a registered one**
/// (ADR-0103).
///
/// A real `tgd`, a real port, a real mTLS. The statement sits in the
/// **difference**: the same key, the same connection, and the call succeeds only
/// after `EnrolOperator` has run over the socket.
///
/// Without the first half the second would say nothing: "it works" this setup
/// would get from a port that accepts everybody too.
///
/// And the actor in the log is the third half: it must be the **name** and no uid
/// -- otherwise the registration would be an access rule without attribution
/// (ADR-0050).
#[test]
fn only_a_registered_operator_reaches_the_operator_port() {
    let (node, operator) = node_with_operator_port();

    // This operator's credential: they generate it themselves, and only the SPKI
    // travels (ADR-0103, determination 3).
    let (key_pem, spki) = tg_identity::cluster::operator_keys().expect("key pair");
    let key_path = node.path().join("dana.key.pem");
    std::fs::write(&key_path, &key_pem).expect("key");

    // The anchors: the cluster leaf `tgd` files itself.
    let anchors = node.path().join("anchors.pem");
    std::fs::write(&anchors, support::await_leaf(node.path())).expect("anchor");

    let socket = admin::socket_path(node.path(), 1);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    runtime.block_on(async {
        let over_port = || {
            AdminClient::connect_operator(
                &format!("127.0.0.1:{operator}"),
                "dana",
                &key_path,
                &anchors,
                "cluster.local",
            )
            .expect("client")
        };

        // **Not registered: nothing.** The handshake fails because the SPKI stands
        // in no list -- and that is half the assurance.
        let refused = over_port().status().await;
        assert!(
            refused.is_err(),
            "an unregistered key must not carry the port: {refused:?}"
        );

        // Registration happens over the **socket** -- the bootstrap
        // (determination 3).
        let over_socket = AdminClient::connect_unix(&socket).expect("client");
        let outcome = over_socket
            .write(tg_consensus::Command::EnrolOperator {
                operator: "dana".to_owned(),
                spki: spki.clone(),
                // **The full set**, because this witness checks the *transport*
                // (ADR-0103) and not the classes (ADR-0105): a registration that
                // fails on a class would look here like one that fails on the
                // key.
                classes: tg_consensus::Class::ALL.to_vec(),
            })
            .await
            .expect("answer");
        assert!(
            matches!(
                outcome,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "the registration must be applied: {outcome:?}"
        );

        // **And now the same key carries.** The admission list follows the log, so
        // no restart is needed -- the refresher hangs on the same metrics as the
        // projection (ADR-0040).
        let deadline = Instant::now() + PATIENCE;
        let mut carried = false;
        while Instant::now() < deadline {
            if over_port().status().await.is_ok() {
                carried = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            carried,
            "after `EnrolOperator` the same key must carry the port -- the \
             reason stands in the log under {}",
            support::log_path("tgd").display()
        );

        // **The actor is the name and no uid** (ADR-0050): the write goes over the
        // port, and what is read is what the cluster knows about it.
        let outcome = over_port()
            .write(tg_consensus::Command::SetClusterNetwork {
                cidr: "10.42.0.0/16".to_owned(),
                node_prefix: 24,
            })
            .await
            .expect("answer");
        assert!(
            matches!(
                outcome,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "a registered operator must be allowed to write: {outcome:?}"
        );

        // And the classes: a second operator that holds `read` and `write` and
        // **not** `operators` (ADR-0105). Pulled out because this test would
        // otherwise grow past the line limit -- and because it is a statement of
        // its own: the transport carries (above), and *what* it carries is decided
        // by the classes (below).
        classes_bite(operator, node.path(), &anchors, &spki, &over_port).await;
    });
}

/// The classes at the **running** port (ADR-0105).
///
/// Two levels in one setup, and the counter-checks hit **different** assertions --
/// that is the statement: the gate checks the **path**, `WriteSvc` the **body**.
///
/// `over_port` is the operator with the full set; it carries the second
/// registration so that it need not run over the socket -- then it would be
/// unchecked whether an operator with `operators` may write it at all.
async fn classes_bite(
    operator: u16,
    dir: &Path,
    anchors: &Path,
    spki: &str,
    over_port: &impl Fn() -> AdminClient,
) {
    let (ci_pem, ci_spki) = tg_identity::cluster::operator_keys().expect("key pair");
    let ci_spki_again = ci_spki.clone();
    let ci_key = dir.join("ci.key.pem");
    std::fs::write(&ci_key, &ci_pem).expect("key");

    let outcome = over_port()
        .write(tg_consensus::Command::EnrolOperator {
            operator: "ci".to_owned(),
            spki: ci_spki,
            classes: vec![tg_consensus::Class::Read, tg_consensus::Class::Write],
        })
        .await
        .expect("answer");
    assert!(
        matches!(
            outcome,
            WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                ..
            }
        ),
        "the second registration must be applied: {outcome:?}"
    );

    let as_ci = || {
        AdminClient::connect_operator(
            &format!("127.0.0.1:{operator}"),
            "ci",
            &ci_key,
            anchors,
            "cluster.local",
        )
        .expect("client")
    };

    // **The counter-direction first**, otherwise every rejection below says
    // nothing: "does not work" this setup would get from a key the port does not
    // carry at all too.
    let deadline = Instant::now() + PATIENCE;
    let mut reads = false;
    while Instant::now() < deadline {
        if as_ci().status().await.is_ok() {
            reads = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        reads,
        "a registration with `read` must be allowed to read -- the reason \
             stands in the log under {}",
        support::log_path("tgd").display()
    );

    // And it may write too: `write` stands in its classes.
    let outcome = as_ci()
        .write(tg_consensus::Command::SetSidecarOverhead {
            resources: tg_consensus::Resources::default(),
        })
        .await
        .expect("answer");
    assert!(
        matches!(outcome, WriteResult::Applied { .. }),
        "with `write` the command set must work: {outcome:?}"
    );

    // **The ADR's finding, at the running port:** the same path, the same client --
    // and `EnrolOperator` is refused because it demands `operators`. That is the
    // level the **body** decides: the gate let the path through.
    let refused = as_ci()
        .write(tg_consensus::Command::EnrolOperator {
            operator: "on-its-own-authority".to_owned(),
            spki: spki.to_owned(),
            classes: tg_consensus::Class::ALL.to_vec(),
        })
        .await;
    let err = refused.expect_err("`EnrolOperator` without the class must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert!(
        err.message().contains("operators"),
        "the rejection must name the missing class: {}",
        err.message()
    );

    // And the other level: the **path**. `RekeyMaterial` hands out every ciphertext
    // (ADR-0100) and is therefore not `read`.
    let refused = as_ci().rekey_material().await;
    let err = refused.expect_err("`RekeyMaterial` without `secrets` must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");

    narrowing_bites(&as_ci, over_port, ci_spki_again).await;
}

/// The classes are read **per request** (ADR-0105, determination 1).
///
/// Checked with a **narrowing** and not with a revocation: the same key stays
/// registered, so the handshake still carries -- and a call that worked a moment
/// ago is refused. After a revocation the handshake already falls (ADR-0103), and
/// then the rejection would say nothing about this gate.
///
/// What a **revocation** holds stands as a pure witness in `operator_gate.rs`: at
/// the running port it is reachable only over an existing connection.
async fn narrowing_bites(
    as_ci: &impl Fn() -> AdminClient,
    over_port: &impl Fn() -> AdminClient,
    ci_spki_again: String,
) {
    let outcome = over_port()
        .write(tg_consensus::Command::EnrolOperator {
            operator: "ci".to_owned(),
            spki: ci_spki_again,
            classes: vec![tg_consensus::Class::Read],
        })
        .await
        .expect("answer");
    assert!(
        matches!(
            outcome,
            WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                ..
            }
        ),
        "the narrowing must be applied: {outcome:?}"
    );

    let refused = as_ci()
        .write(tg_consensus::Command::SetSidecarOverhead {
            resources: tg_consensus::Resources::default(),
        })
        .await;
    let err = refused.expect_err("after the narrowing `write` must no longer work");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert!(
        err.message().contains("read") && !err.message().contains("write"),
        "the rejection must name what the registration still holds: {}",
        err.message()
    );

    // And it may still read -- otherwise the test above would only show that
    // something refuses the client.
    as_ci().status().await.expect("`read` stays");
}

/// A data directory whose admin socket does not fit into `sun_path` is refused
/// **by name** -- not with `std`'s message.
///
/// The socket is the recovery path (ADR-0044) and the only access `tgctl` has.
/// Without this bolt the start fails with "path must be shorter than `SUN_LEN`":
/// no path, no number, no remedy.
///
/// **The file-system path is not the limit**, and that is the reason this case
/// occurs at all: `PATH_MAX` is 4096 bytes, so the storage opens without
/// complaint, and only the socket falls. An operator thereby really sees this
/// message and no other one before it.
///
/// **Both** are asserted: that it does not start up, and that the message carries
/// the three pieces of information for whose sake it exists -- path, number and
/// remedy. Without the second half `std`'s message would be green too.
#[test]
fn a_data_dir_whose_admin_socket_does_not_fit_is_refused_by_name() {
    // 108 bytes for the socket: the measured first byte above the limit.
    // **Computed and not typed**, because `TMPDIR` does not belong to us: were the
    // number a constant, the fixture would lie beside the limit on another machine
    // -- and the test would then say nothing.
    let temp = std::env::temp_dir();
    let suffix = "/admin-1.sock".len() + 1;
    let dir = temp.join("x".repeat(108 - suffix - temp.as_os_str().len()));
    std::fs::create_dir_all(&dir).expect("directory creatable");
    let socket = admin::socket_path(&dir, 1);
    assert_eq!(
        socket.as_os_str().len(),
        108,
        "the fixture does not lie on the first byte above the limit: {}",
        socket.display()
    );

    let child = OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
        .args([
            "--telemetry-addr",
            "off",
            "--id",
            "1",
            "--node",
            "tgd-1",
            "--listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--cluster-listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--node-listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--data-dir",
            dir.to_str().expect("path"),
            "--peer",
            &format!("1=http://127.0.0.1:{}", support::free_port()),
        ])
        .stdout(support::log("tgd"))
        .stderr(Stdio::piped())
        .spawn()
        .expect("tgd startable");

    let done = await_exit(child, PATIENCE);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !done.status.success(),
        "a node whose admin socket does not fit must not start up"
    );
    let said = String::from_utf8_lossy(&done.stderr);
    assert!(
        said.contains("admin socket") && said.contains("108") && said.contains("--data-dir"),
        "the message does not name path, number and remedy: {said}"
    );
    // **And the budget is recomputed, not believed.** The path is
    // `<dir>/admin-1.sock`, so 13 bytes above the directory: 94 remain. A number in
    // the text nobody recomputes is the next one that is off by one -- in the
    // manual 93 stood at first.
    assert!(
        said.contains("94 bytes remain"),
        "the message does not name the budget or names it wrongly: {said}"
    );
}

/// **Whom the leader reaches stands in the answer** -- and its own identifier
/// stands in it.
///
/// # Why the second half carries
///
/// `change_membership` needs a **quorum**, and `Raft::initialize` is only for a
/// fresh log (`NotAllowed` as soon as one is there). A `SetVoters` onto a set whose
/// majority does not answer is thereby a **dead end**: the admin socket is the
/// recovery path (ADR-0044), but the command itself needs exactly the quorum that
/// is missing afterwards. Whoever wants to avoid that must see beforehand whom the
/// leader reaches -- and for that there was no way.
///
/// That its **own** identifier always stands in it is no cosmetics: only thereby is
/// an empty list structurally impossible, and only thereby may `tgctl` read it as
/// "this version does not say" (`serde(default)`). Without the assurance a new
/// `tgctl` against an old `tgd` would report **every** node as mute, and in the
/// alarming direction at that.
///
/// # The setup
///
/// Membership `{1,2}` with both addresses -- and node 2 does **not** run. A
/// one-node cluster could not show the second assurance: there `voters` and
/// `reachable` are the same set, and a `reachable` that simply returns the
/// membership would look the same. (Counter-checked: `reachable: voters` makes the
/// second assertion red.)
///
/// # What it does not distinguish
///
/// Whether `reaching` takes the **replicating** peers or all entries of the map
/// (`at.map(..)` against `map(..)`). Measured, `metrics.replication` is `None`
/// without a leader, and without a quorum none arises -- the map is therefore empty
/// in this setup, and both versions deliver the same. A witness for that would need
/// a leader that afterwards loses the majority.
#[tokio::test(flavor = "multi_thread")]
async fn the_status_names_whom_the_leader_reaches() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cluster = support::free_port();
    let absent = support::free_port();
    support::cluster_material(dir.path(), &[1, 2]);

    let child = OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
        .args([
            "--telemetry-addr",
            "off",
            "--id",
            "1",
            "--node",
            "tgd-1",
            "--listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--cluster-listen",
            &format!("127.0.0.1:{cluster}"),
            "--node-listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--data-dir",
            dir.path().to_str().expect("path"),
            "--peer",
            &format!("1=http://127.0.0.1:{cluster}"),
            "--peer",
            &format!("2=http://127.0.0.1:{absent}"),
            "--init",
            "--init-voters",
            "1,2",
        ])
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    let mut node = Running(child);
    support::await_file(&mut node.0, &admin::socket_path(dir.path(), 1), PATIENCE);

    let client =
        AdminClient::connect_unix(&admin::socket_path(dir.path(), 1)).expect("socket reachable");
    let status = client.status().await.expect("status");

    // The set knows both -- without that the assertion below would say nothing.
    assert_eq!(
        status.voters,
        vec![1, 2],
        "the membership must know both voters"
    );

    // First assurance: its own identifier. `is_empty` in `tgctl` rests on it.
    assert!(
        status.reachable.contains(&1),
        "the node must reach itself -- an empty list would otherwise confuse \
         \"nobody\" with \"does not say\": {:?}",
        status.reachable
    );

    // Second assurance: the dead one is missing.
    assert!(
        !status.reachable.contains(&2),
        "node 2 does not run and must not count as reachable: {:?}",
        status.reachable
    );
}

/// The **denominator of the placement** reaches the read path (ADR-0011,
/// ADR-0034).
///
/// The number comes from the **state** and not from the projection: `replicas`
/// stands in the declaration that lies in the log. `tgctl`'s test rig **provides**
/// the admin service and files the answer -- it cannot see this seam at all;
/// without this witness it is uncovered.
///
/// Both directions: **without** `<placement>` it is one instance -- the same
/// derivation the planner uses --, and **with** it the declared number. Without the
/// first half a view that always names zero would be just as green, and the alarm
/// rule beside it would fire for every workload.
#[tokio::test(flavor = "multi_thread")]
async fn the_declared_replicas_reach_the_read_path() {
    let node = node();
    let socket = admin::socket_path(node.path(), 1);
    let client = AdminClient::connect_unix(&socket).expect("client");

    let document = |placement: &str| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
             <workload name=\"api\" kind=\"service\">\n\
             <image reference=\"example.com/api:1\"/>\n\
             {placement}\
             </workload>\n\
             </workloads>\n"
        )
    };

    write_applied(
        &client,
        tg_consensus::Command::UpsertWorkload {
            document: document(""),
        },
    )
    .await;

    let api = await_workload(&client, "api").await;
    assert_eq!(
        api.replicas, 1,
        "without <placement> it is one instance -- the planner's default"
    );

    write_applied(
        &client,
        tg_consensus::Command::UpsertWorkload {
            document: document("<placement replicas=\"4\"/>\n"),
        },
    )
    .await;

    let deadline = Instant::now() + PATIENCE;
    let mut seen = 0;
    while seen != 4 && Instant::now() < deadline {
        seen = await_workload(&client, "api").await.replicas;
        if seen != 4 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert_eq!(
        seen, 4,
        "the declared number must reach the read path -- without it a partially \
         placed declaration cannot be distinguished from a complete one"
    );
}

/// **Whoever removes a registry credential learns whom it hits** (ADR-0125,
/// determination 3).
///
/// # The finding
///
/// `ClearRegistryCredential` checked nothing and gave `Applied`. The next pull then
/// runs `RegistryAuth::Anonymous`, fails with `401`, lands in `report.failed` --
/// and per ADR-0061 a `failed` pulls every dependant down with it. Weeks can lie
/// between the action and the effect: only once the image no longer lies locally.
///
/// **It is nevertheless not refused**, unlike at `RemoveSecret`: there a dangling
/// reference would arise, here a valid state -- "this registry is pulled from
/// anonymously" is the normal case for every public one. The lint travels in the
/// answer (ADR-0048) and not in the log.
///
/// The counter-check is the second half: if nobody pulls from this registry,
/// **nothing** stands there. Without it a lint that always appears would be just as
/// green -- and a lint that always stands there is none.
#[tokio::test]
async fn clearing_a_registry_credential_says_who_pulls_anonymously() {
    use tg_consensus::Command;

    const DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"registry.example.com/api:1\"/>\n\
         </workload>\n\
         </workloads>\n";

    let node = node();
    let admin = AdminClient::connect_unix(&admin::socket_path(node.path(), 1)).expect("socket");

    write_applied(
        &admin,
        Command::UpsertWorkload {
            document: DOCUMENT.to_owned(),
        },
    )
    .await;
    write_applied(
        &admin,
        Command::PutSecret {
            name: "reg".to_owned(),
            value: tg_identity::secrets::DataKey::generate()
                .expect("key")
                .seal(b"basic dXNlcjpwdw==")
                .expect("sealable"),
        },
    )
    .await;
    // **Set with capital letters** (ADR-0125, determination 1): the host is
    // lower-cased at ingest, otherwise the credential would fall out silently on a
    // letter.
    write_applied(
        &admin,
        Command::SetRegistryCredential {
            registry: "REGISTRY.example.com".to_owned(),
            secret: "reg".to_owned(),
        },
    )
    .await;

    let lints = write_applied(
        &admin,
        Command::ClearRegistryCredential {
            registry: "registry.example.com".to_owned(),
        },
    )
    .await;

    assert!(
        lints.iter().any(|note| note.contains("api")),
        "the lint does not name who pulls anonymously from now on: {lints:?}"
    );
    assert!(
        lints
            .iter()
            .any(|note| note.contains("registry.example.com")),
        "and not from which registry: {lints:?}"
    );

    // **The counter-check**: a registry nobody pulls from is mute.
    let quiet = write_applied(
        &admin,
        Command::ClearRegistryCredential {
            registry: "other.example.com".to_owned(),
        },
    )
    .await;
    assert!(
        !quiet.iter().any(|note| note.contains("anonymously")),
        "a lint that always stands there is none: {quiet:?}"
    );
}
