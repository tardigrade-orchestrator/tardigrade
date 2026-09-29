//! The orders the slice leaves behind (ADR-0110).
//!
//! What is checked is the **reading** -- what the reconciler finds when the
//! files are missing, when they are unreadable and when they carry -- and the
//! **execution**, as far as it is measurable without privileges.
//!
//! And that is more than it looks: measured, `delete` succeeds on a declared
//! volume **without** a loop device, because nothing is mounted. The whole
//! deletion path is thereby checkable here; what `cargo xtask storage` needs
//! is solely the copy of a real image (ADR-0099).

use tg_runtime::{NodePaths, orders};

/// Lays out a data directory with the network subdirectory.
fn paths() -> (tempfile::TempDir, NodePaths) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = NodePaths::new(dir.path());
    std::fs::create_dir_all(paths.network_dir()).expect("network dir");
    (dir, paths)
}

/// Collects a call's messages.
fn logged(run: impl FnOnce()) -> String {
    let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let sink = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || Writer(sink.clone()))
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let bytes = buffer.lock().expect("lock").clone();
    String::from_utf8(bytes).expect("utf-8")
}

struct Writer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// **Without the files there is nothing to do -- and nothing to report.**
///
/// That is the normal case of every pass on a node that has had no deletion
/// and no snapshot decreed. A message about it would appear every ten seconds,
/// and an operator would learn to read past it.
#[test]
fn without_the_files_there_is_nothing_to_do() {
    let (_dir, paths) = paths();

    let mut found = None;
    let log = logged(|| found = Some(orders::read(&paths)));
    let found = found.expect("read");

    assert!(found.tombstones.is_empty(), "{:?}", found.tombstones);
    assert!(found.snapshots.is_empty(), "{:?}", found.snapshots);
    assert!(log.is_empty(), "missing files are no finding: {log}");
}

/// Both lists get through.
#[test]
fn both_lists_come_through() {
    let (_dir, paths) = paths();
    std::fs::write(paths.tombstones(), r#"["old","older"]"#).expect("tombstones");
    std::fs::write(paths.snapshot_orders(), r#"[["journal",7]]"#).expect("snapshots");

    let found = orders::read(&paths);

    assert_eq!(found.tombstones, vec!["old".to_owned(), "older".to_owned()]);
    assert_eq!(found.snapshots, vec![("journal".to_owned(), 7)]);
}

/// **Unreadable is a finding, and the other list carries nevertheless.**
///
/// "Missing" and "unreadable" are two statements: one is the normal case, the
/// other means that a decreed deletion does not arrive on this node -- and
/// without the message an operator would see it only at
/// `tg_cluster_volume_tombstones`, while the cause lies here.
#[test]
fn an_unreadable_list_is_named_and_the_other_still_carries() {
    let (_dir, paths) = paths();
    // A directory at the file's place fails on reading as `root` too --
    // unlike a permission bit.
    std::fs::create_dir(paths.tombstones()).expect("directory");
    std::fs::write(paths.snapshot_orders(), r#"[["journal",7]]"#).expect("snapshots");

    let mut found = None;
    let log = logged(|| found = Some(orders::read(&paths)));
    let found = found.expect("read");

    assert!(found.tombstones.is_empty(), "{:?}", found.tombstones);
    assert!(
        log.contains("the tombstones"),
        "the unreadable list is not named: {log}"
    );
    assert_eq!(
        found.snapshots,
        vec![("journal".to_owned(), 7)],
        "the other list must carry nevertheless"
    );
}

/// A list that is no JSON is the same finding.
#[test]
fn a_broken_list_is_named() {
    let (_dir, paths) = paths();
    std::fs::write(paths.snapshot_orders(), "no json").expect("snapshots");

    let mut found = None;
    let log = logged(|| found = Some(orders::read(&paths)));

    assert!(found.expect("read").snapshots.is_empty());
    assert!(
        log.contains("snapshot"),
        "the broken list is not named: {log}"
    );
}

/// **A tombstone really deletes** (ADR-0042, ADR-0110 determination 2).
///
/// The effect and not the intention: `execute` returns no `Result` -- a
/// witness that checked only its call would not be distinguishable from an
/// `execute` that does nothing.
///
/// The counter-direction stands beside it and carries it: a volume that is
/// **not** named stays. "Delete" must never follow from an absence (ADR-0027,
/// ADR-0040 determination 6).
#[test]
fn a_tombstone_removes_its_volume_and_leaves_the_others() {
    let (dir, paths) = paths();
    let store = tg_runtime::volume::VolumeStore::open(dir.path()).expect("the store");
    store
        .declare("gone", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    store
        .declare("stays", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    orders::execute(
        &paths,
        3,
        &orders::Orders {
            tombstones: vec!["gone".to_owned()],
            snapshots: Vec::new(),
        },
    );

    assert!(!store.exists("gone"), "the volume still lies there");
    assert!(
        store.exists("stays"),
        "a volume that was not named was deleted"
    );
}

/// **A tombstone for a volume that never existed here is done.**
///
/// Not failed: the instruction reads "this volume shall no longer be here"
/// (ADR-0104), and that is fulfilled. Measured, the store gives
/// `VolumeError::Unknown` for it.
///
/// What is asserted is the **silence**. A message about it would appear at
/// every pass as long as the tombstone stands -- and it stands until the
/// leader clears it away, so for at least one report. An operator would learn
/// to read past it.
#[test]
fn a_tombstone_for_an_unknown_volume_is_done_not_failed() {
    let (_dir, paths) = paths();

    let log = logged(|| {
        orders::execute(
            &paths,
            3,
            &orders::Orders {
                tombstones: vec!["never-existed".to_owned()],
                snapshots: Vec::new(),
            },
        );
    });

    assert!(
        !log.contains("was not deleted"),
        "a tombstone without a volume was reported as a failure: {log}"
    );
}

/// **A failure ends nothing** (ADR-0110, determination 3).
///
/// The core of the decision, and the assurance that was missing before: until
/// ADR-0110 a failed `losetup` propagated through `apply` into the session
/// loop, ended the **session** and sent the agent to a different endpoint
/// (ADR-0077) -- for an error that has nothing to do with the control plane.
///
/// Checked at two orders of which the first fails: a snapshot without an image
/// gives `VolumeError::Disk`, measured. The second must be attempted
/// nevertheless -- **both** names stand in the log afterwards. Without the
/// second half an `execute` that returns at the first error would be green
/// too.
#[test]
fn a_failed_order_does_not_stop_the_next_one() {
    let (dir, paths) = paths();
    let store = tg_runtime::volume::VolumeStore::open(dir.path()).expect("the store");
    store
        .declare("first", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    store
        .declare("then", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    let log = logged(|| {
        orders::execute(
            &paths,
            3,
            &orders::Orders {
                tombstones: Vec::new(),
                snapshots: vec![("first".to_owned(), 1), ("then".to_owned(), 1)],
            },
        );
    });

    for volume in ["first", "then"] {
        assert!(log.contains(volume), "'{volume}' was not attempted: {log}");
    }
}

/// **The marker prevents repeated work** (ADR-0099).
///
/// Without it every pass would lay the same snapshot out anew -- and since
/// ADR-0110 the execution runs at the reconcile cadence instead of per slice,
/// that is, every ten seconds instead of at a log movement. A copy of a whole
/// image at that cadence would be no refinement but a permanent load.
///
/// Checked in **both** directions: a generation that does not exceed the
/// marker is not attempted at all (generation 0 is the default "no rotation
/// wanted", the marker of a volume without a snapshot is 0, measured); one
/// that does exceed it very much is. Without the second half an `execute` that
/// skips **every** snapshot would be green too.
#[test]
fn a_generation_at_the_mark_is_not_attempted_again() {
    let (dir, paths) = paths();
    let store = tg_runtime::volume::VolumeStore::open(dir.path()).expect("the store");
    store
        .declare("old-stock", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    let quiet = logged(|| {
        orders::execute(
            &paths,
            3,
            &orders::Orders {
                tombstones: Vec::new(),
                snapshots: vec![("old-stock".to_owned(), 0)],
            },
        );
    });
    assert!(
        !quiet.contains("old-stock"),
        "a generation at the marker was attempted again: {quiet}"
    );

    let attempted = logged(|| {
        orders::execute(
            &paths,
            3,
            &orders::Orders {
                tombstones: Vec::new(),
                snapshots: vec![("old-stock".to_owned(), 1)],
            },
        );
    });
    assert!(
        attempted.contains("old-stock"),
        "a generation above the marker was not attempted: {attempted}"
    );
}

/// The self-fence stands **before** the execution of the orders (ADR-0110).
///
/// # Why the order is the answer
///
/// ADR-0110 noted an **ordering condition** between `TOOL_TIMEOUT` and the
/// fence margin as an open point. Measured, none can be set up: a snapshot
/// calls `fsfreeze` (bounded) **and** `std::fs::copy` -- a syscall without any
/// deadline -- and the number of orders is unbounded. The delay is thereby not
/// `N x 60 s` but arbitrary.
///
/// What carries is therefore the **position**. Before the fence a copy holds
/// *this* pass's self-fence up, and the holder fences too late while the
/// leader passes the lease on at `expires_at` -- two writers, exactly what
/// ADR-0064 determination 7 prevents. Behind it, it holds only the **next**
/// pass up, and that one has nothing left to fence.
///
/// # Why a source guard
///
/// The order of two calls in **one** function is not observable from outside
/// without having taken the decision already -- the same rationale as with
/// `the_probe_runs_after_the_gate` in `dependency_gate.rs` (ADR-0089), which
/// nails the probe down one step further.
#[test]
fn the_orders_run_after_the_fence() {
    const SOURCE: &str = include_str!("../src/reconcile.rs");

    // **The search text does not hang on the formatting.** `"active(runtime,"`
    // stood here, and when the call got an argument (ADR-0111), `rustfmt`
    // wrapped it -- the guard no longer found its own place and reported "the
    // self-fence stands in `once`" for a fence that stood there unchanged. A
    // source guard that a line break topples reports the same next time, and
    // then nobody believes it.
    let fence = SOURCE
        .find("!active(")
        .expect("the self-fence stands in `once`");
    let orders = SOURCE
        .find("orders::execute(")
        .expect("the execution stands in `once`");

    assert!(
        fence < orders,
        "the orders must stand behind the self-fence (ADR-0110): otherwise a \
         volume copy holds this pass's fence up, and the leader passes the \
         lease on at `expires_at` -- two writers (ADR-0064, determination 7). \
         The fence at {fence}, the orders at {orders}"
    );
}

/// An **emptied** node executes its tombstones nevertheless (ADR-0110).
///
/// That is the assurance an early `return` on an empty assignment carried
/// before: a node whose workloads are all withdrawn has `assigned` empty --
/// and that is exactly the situation in which a deletion arises.
///
/// # Why ignored
///
/// It calls `once` and needs an `OciRuntime` for that, that is, `youki` or
/// `crun` in the PATH -- the only prerequisite it has: with an **empty**
/// assignment no container is touched, `reap` asks only the empty state
/// directory. Measured, it runs in 0.00 s. Without `#[ignore]` it would be the
/// first test of the ordinary suite that demands an OCI runtime.
#[tokio::test]
#[ignore = "demands an OCI runtime in the PATH (youki or crun)"]
async fn a_drained_node_still_executes_its_orders() {
    let (_dir, paths) = paths();
    std::fs::create_dir_all(paths.runtime_root()).expect("runtime root");

    let store = tg_runtime::volume::VolumeStore::open(paths.data_dir()).expect("the store");
    store
        .declare("gone", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    assert!(store.exists("gone"), "the setup must bite");

    std::fs::write(paths.tombstones(), r#"["gone"]"#).expect("the tombstone");

    let runtime = tg_runtime::oci::OciRuntime::discover(
        tg_runtime::oci::DEFAULT_RUNTIMES,
        paths.runtime_root(),
    )
    .expect("no OCI runtime");

    let context = tg_runtime::reconcile::Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        now: &|| 0,
        fence_margin: 0,
        wake: None,
        keep_snapshots: 3,
        quorum: tg_model::Quorum::Available,
        network: None,
        mesh: None,
        workload_api: None,
        secrets: None,
        credentials: None,
        // **Emptied**, not "nothing heard yet": that is the situation in
        // which a deletion arises (ADR-0058, determination 3).
        empty: &|| tg_runtime::reconcile::EmptyMeans::NothingWanted,
    };

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("the pass carries");

    assert!(report.is_clean(), "no finding expected: {report:?}");
    assert!(
        !store.exists("gone"),
        "the tombstone was not executed -- an emptied node never deletes"
    );
}
