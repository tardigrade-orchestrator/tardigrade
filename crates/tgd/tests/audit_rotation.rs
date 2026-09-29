//! Segments one can move into the archive (ADR-0020).
//!
//! The open point from phase 11a reads "the way of the file outwards", and part
//! of it is no operations work but a missing build deliverable: **nobody gets at
//! a file that is permanently open for appending.** An operator who copies it
//! into the WORM archive races the writer; a sealed segment they can move
//! without a race.
//!
//! What is checked here at the **running node** is that the switch is wired and
//! that the chain holds across the seam. The seam itself is checked in
//! `tg-consensus/tests/audit_archive.rs` -- there without a process, here with.

use std::process::Command as OsCommand;
use std::time::{Duration, Instant};

use support::Running;
use tg_consensus::{Command, Resources, Topology};
use tgd::admin::{self, WriteResult};

mod support;

const PATIENCE: Duration = Duration::from_secs(20);

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
/// order, with the old one, and with an emptied incremental cache. The
/// phenomenon is thereby not reconstructible, and the order is fixed
/// independently of it: the race between `remove_dir_all` and a running process
/// is real, even if it does not explain these thirteen. What is recorded is the
/// **shape** -- complete data directories of `tgd` (`admin-1.sock`,
/// `raft-1.redb`) and `tg-agent` (`agent.lock`, `desired`) --, so that the next
/// occurrence can be classified instead of investigated anew.
struct Node {
    running: Running,
    dir: tempfile::TempDir,
}

impl Node {
    /// The node's data directory.
    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

/// Starts a node that rotates after **two** records.
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
            "--audit-rotate",
            "2",
            "--init",
        ])
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    Node {
        running: Running(child),
        dir,
    }
}

/// A topology as an operator would enter it.
fn topology() -> Topology {
    Topology {
        site: "fra".to_owned(),
        hall: "h1".to_owned(),
        rack: "r1".to_owned(),
    }
}

/// **A running node seals segments, and the chain holds across them.**
///
/// What is written goes over the admin socket, that is, over the way an operator
/// takes -- not into the state machine. What lies on the disk afterwards is what
/// would go into the archive.
#[tokio::test(flavor = "multi_thread")]
async fn a_running_node_seals_segments_that_chain() {
    let mut node = node();
    let socket = admin::socket_path(node.path(), 1);
    // **One version instead of two** (`support::await_admin`): the one here saw
    // only `path.exists()` and reported after its whole patience "the socket did
    // not come up" -- even when the process had died on a port conflict. The
    // other has checked it all along; two versions are two opportunities to make
    // them differently strict.
    let client = support::await_admin(&socket, &mut [&mut node.running.0]);

    // Enter six nodes -- six log entries, so six records in the archive. At two
    // per segment that is three files.
    let deadline = Instant::now() + PATIENCE;
    let mut written = 0;
    while written < 6 && Instant::now() < deadline {
        let result = client
            .write(Command::UpsertNode {
                name: format!("node-{written}"),
                capacity: Resources::default(),
                reserved: tg_consensus::Resources::default(),
                source: tg_consensus::Origin::Operator,
                topology: topology(),
            })
            .await;
        match result {
            // **Here the variant counts and not the outcome**, and that is
            // substantiated: what is counted are **records in the archive**, and
            // what is rejected is archived likewise (phase 11a -- "a futile
            // attempt is exactly the event an auditor looks for").
            Ok(WriteResult::Applied { .. }) => written += 1,
            // The node does not lead yet; that is the normal case shortly
            // after the start and no error.
            Ok(_) | Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    assert_eq!(written, 6, "the node took no commands");

    let base = node.path().join("audit-1.jsonl");
    let deadline = Instant::now() + PATIENCE;
    while tg_consensus::audit::sealed(&base).len() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }

    let sealed = tg_consensus::audit::sealed(&base);
    assert!(
        sealed.len() >= 2,
        "it did not rotate: {sealed:?} -- the switch is not wired"
    );

    let all = tg_consensus::audit::segments(&base);
    let chain = tg_consensus::audit::verify_chain(&all, tg_telemetry::audit::GENESIS)
        .expect("the chain carries across the segments");
    assert!(chain.records >= 6, "{chain:?}");
    assert_eq!(chain.segments, all.len());

    // **A sealed segment no longer grows.** That is the whole purpose: what an
    // operator copies no longer changes in the process.
    let first = &sealed[0];
    let before = std::fs::read_to_string(first).expect("read");
    for index in 0..4 {
        let _ = client
            .write(Command::UpsertNode {
                name: format!("later-{index}"),
                capacity: Resources::default(),
                reserved: tg_consensus::Resources::default(),
                source: tg_consensus::Origin::Operator,
                topology: topology(),
            })
            .await;
    }
    let after = std::fs::read_to_string(first).expect("read");
    assert_eq!(before, after, "a sealed segment has changed");
}
