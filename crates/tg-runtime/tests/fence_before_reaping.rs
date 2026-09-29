//! The self-fence does not wait for the clearing away (ADR-0129).
//!
//! Measured, **one** container that does not listen to `SIGTERM` cost the pass
//! 10.16 s -- and the self-fence stood behind it, in the `start_order` loop.
//! `FENCE_MARGIN`, by contrast, reckons with **three** seconds (the wake-up
//! floor plus the fence grace period, ADR-0076), and what the pass does before
//! it did not go into the calculation. With a lease of fifteen seconds the
//! ordering condition from ADR-0064 determination 7 thereby broke, and its
//! violation means literally: **two writers.**
//!
//! What is measured here is therefore **time**, not an order in the report:
//! the report says only *that* it was fenced, not *when*. An observer beside
//! the pass sees the container stop and writes down how long it took.
//!
//! The order in the source is additionally guarded by
//! `the_self_fence_stands_before_the_reaping` in `tg-syscall` -- the one here
//! runs only privileged, and an assurance that stands only in the privileged
//! lane is one nobody sees red in everyday operation.
//!
//! `#[ignore]`: demands `CAP_SYS_ADMIN` (overlayfs) and an OCI runtime. Run
//! with `cargo xtask storage`.

use std::path::Path;
use std::time::{Duration, Instant};

mod support;
use support::{Fixture, build_layer};

use tg_defs::WorkloadExt as _;
use tg_runtime::network::Extras;
use tg_runtime::oci::{DEFAULT_RUNTIMES, OciRuntime};
use tg_runtime::reconcile::{Context, EmptyMeans};
use tg_runtime::resolved::ResolvedImage;
use tg_runtime::state::DesiredState;

/// The orderly stop's grace period (ADR-0058/0129, determination 3).
///
/// Copied because it is private -- and that is why it stands here **once** and
/// is only computed with in the assertions.
const GRACE: Duration = Duration::from_secs(10);

/// The single writer whose lease has just expired.
const TILL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="f129-till" kind="service" class="single-writer">
    <image reference="registry.invalid/till:1"/>
  </workload>
</workloads>"#;

fn context(now: u64) -> Context<'static> {
    Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        keep_snapshots: 3,
        quorum: tg_model::Quorum::Available,
        network: None,
        mesh: None,
        workload_api: None,
        secrets: None,
        credentials: None,
        // **Occupied**, not "nothing heard yet": only that way does the
        // clearer clear anything away at all (ADR-0058, determination 3).
        empty: &|| EmptyMeans::NothingWanted,
        now: Box::leak(Box::new(move || now)),
        fence_margin: 0,
        wake: None,
    }
}

/// Starts a container by hand.
///
/// `entrypoint` decides whether it hangs: `sh` with `trap "" TERM` ignores its
/// `SIGTERM` and thereby costs the full grace period -- exactly the case from
/// the measurement. A `sleep`, by contrast, ends immediately.
async fn launch(
    dir: &Path,
    paths: &tg_runtime::NodePaths,
    runtime: &OciRuntime,
    workload: &tg_defs::generated::WorkloadType,
    entrypoint: &[&str],
) -> Fixture {
    let id = tg_runtime::bundle::container_id(workload.name(), 0);
    let mut fixture = Fixture {
        id: id.clone(),
        root: paths.runtime_root().clone(),
        rootfs: None,
    };

    let layer = dir.join("layer");
    if !layer.exists() {
        build_layer(&layer);
    }
    let built = tg_runtime::bundle::build(
        &paths.bundles_dir(),
        workload,
        &id,
        &[layer],
        &ResolvedImage {
            reference: "registry.invalid/x:1".to_owned(),
            layers: Vec::new(),
            entrypoint: entrypoint.iter().map(|part| (*part).to_owned()).collect(),
            env: vec!["PATH=/bin".to_owned()],
        },
        &[],
        Extras::default(),
    )
    .expect("the bundle");
    fixture.rootfs = Some(built.rootfs().to_owned());

    runtime.create(&id, built.dir()).await.expect("lay out");
    runtime.start(&id).await.expect("start");
    assert!(
        runtime.status(&id).await.expect("the state").is_running(),
        "{id} is not running -- the test would otherwise prove nothing"
    );

    fixture
}

/// A container that ignores its `SIGTERM`.
///
/// `trap "" TERM` in the shell, and with a second command behind it: with a
/// single command `sh -c` replaces itself with it, and then the process would
/// no longer carry the handling at all.
const STUCK: [&str; 3] = ["/bin/sh", "-c", "trap '' TERM; sleep 600"];

fn declaration(name: &str) -> tg_defs::generated::WorkloadType {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="{name}" kind="service">
    <image reference="registry.invalid/x:1"/>
  </workload>
</workloads>"#
    );
    tg_defs::from_str(&xml)
        .expect("the definition parses")
        .workloads()[0]
        .clone()
}

/// **The fence stands before the clearing away** (ADR-0129,
/// determination 1).
///
/// In the same pass: an expired lease and a hanging container nobody wants any
/// more. The pass therefore lasts a full grace period -- the fence must
/// **not** wait it out too.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn the_fence_does_not_wait_for_the_reaper() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime =
        OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root()).expect("no OCI runtime");

    let desired = DesiredState::open(dir.path()).expect("the desired state");
    let set = tg_defs::from_str(TILL).expect("the definition parses");
    let till = set.workloads()[0].clone();
    desired.put(&till).expect("file it");
    desired.assign("f129-till", &[0]).expect("assign");
    // Expired: the holder is node 7, the deadline ended at 10 000.
    desired
        .set_lease("f129-till", Some((7, 10_000)))
        .expect("the lease");

    let _till = launch(dir.path(), &paths, &runtime, &till, &["/bin/sleep", "600"]).await;
    // It stands **not** in the desired state -- so the clearer clears it
    // away, and it hangs the full deadline in the process.
    let _hanger = launch(
        dir.path(),
        &paths,
        &runtime,
        &declaration("f129-hanger"),
        &STUCK,
    )
    .await;

    let fenced = tg_runtime::bundle::container_id("f129-till", 0);
    let root = paths.runtime_root().clone();
    let start = Instant::now();

    // The observer runs **beside** the pass and has its own runtime
    // connection: the pass borrows `runtime`.
    let watcher = tokio::spawn(async move {
        let runtime = OciRuntime::discover(DEFAULT_RUNTIMES, &root).expect("no OCI runtime");
        loop {
            if !matches!(runtime.status(&fenced).await, Ok(status) if status.is_running()) {
                return start.elapsed();
            }
            if start.elapsed() > GRACE * 3 {
                return start.elapsed();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context(10_000))
        .await
        .expect("the pass");
    let pass = start.elapsed();
    let until_fenced = watcher.await.expect("the observer");

    assert_eq!(
        report.fenced.len(),
        1,
        "the instance should have fenced itself: {report:?}"
    );
    assert!(
        pass >= GRACE,
        "the pass lasted only {pass:?} -- then the hanger did not cost its \
         grace period, and the test measures nothing"
    );
    assert!(
        until_fenced < GRACE,
        "the fence came only after {until_fenced:?}, the pass lasted \
         {pass:?}: it waited for the clearing away (ADR-0129, determination 1)"
    );
}

/// **All the unwanted share one grace period** (ADR-0129, determination 2).
///
/// Two hanging containers, sequentially twenty seconds. Together it stays at
/// one deadline.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn all_unwanted_containers_share_one_grace_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime =
        OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root()).expect("no OCI runtime");

    let mut ids = Vec::new();
    let mut fixtures = Vec::new();
    for name in ["f129-two-a", "f129-two-b"] {
        let fixture = launch(dir.path(), &paths, &runtime, &declaration(name), &STUCK).await;
        ids.push(fixture.id.clone());
        fixtures.push(fixture);
    }

    let start = Instant::now();
    let report = tg_runtime::reconcile::once(&paths, &runtime, &context(0))
        .await
        .expect("the pass");
    let pass = start.elapsed();

    let mut reaped = report.reaped.clone();
    reaped.sort();
    assert_eq!(
        reaped, ids,
        "both should have been cleared away: {report:?}"
    );
    assert!(
        pass >= GRACE,
        "only {pass:?} -- then the containers did not ignore their SIGTERM, \
         and the test measures nothing"
    );
    assert!(
        pass < GRACE * 2,
        "the pass took {pass:?}: the grace periods ran one after another \
         (ADR-0129, determination 2)"
    );
}
