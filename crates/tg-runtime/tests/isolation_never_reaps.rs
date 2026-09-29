//! An incomplete desired state clears nothing away (ADR-0062,
//! determination 4).
//!
//! That is that ADR's sharpest security statement:
//!
//! > An unreadable document names no workload, so its container was missing
//! > from the set of what is wanted -- and the clearer ended it. **A file
//! > error must never cost a running workload.**
//!
//! # Why this test exists
//!
//! The determination was built. **It was not guarded:** a mutation run over
//! the security-critical single lines removed the condition, and not a single
//! target turned red. The tests from ADR-0062 check that the agent **lives**
//! and that the healthy workload is still reconciled -- none checks that a
//! **running container** survives the finding.
//!
//! It is checked at a real container, for that is exactly the point. A test on
//! `report.reaped.is_empty()` would be weaker: the list is empty too when
//! there was nothing to clear away.
//!
//! `#[ignore]`: demands `CAP_SYS_ADMIN` (overlayfs) and an OCI runtime. Run
//! with `cargo xtask storage`.

use std::path::Path;

mod support;
use support::{Fixture, build_layer};

use tg_runtime::network::Extras;
use tg_runtime::oci::{DEFAULT_RUNTIMES, OciRuntime};
use tg_runtime::reconcile::{Context, EmptyMeans};
use tg_runtime::resolved::ResolvedImage;

/// The workload whose container runs and that **nobody** names any more.
///
/// It is filed in the cache and is about to be removed from it -- that is the
/// situation in which the clearer strikes (ADR-0058).
const RUNNING: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="NAME" kind="service">
    <image reference="registry.invalid/api:1"/>
  </workload>
</workloads>"#;

fn context<'a>() -> Context<'a> {
    Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        // ADR-0064: the local clock for the active-role lease.
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
        // **Occupied**, not "nothing heard yet": only that way does the
        // clearer clear anything away at all (ADR-0058, determination 3). Were
        // it otherwise, the container would stay alive for the wrong reason,
        // and the test would prove nothing.
        empty: &|| EmptyMeans::NothingWanted,
    }
}

/// Lays out a running container whose definition disappears afterwards.
/// `name` differs per test, and that is **no** cosmetic: the spec sets
/// `cgroupsPath = /tardigrade/<container-id>` (ADR-0006), and the container
/// name follows the workload name. Two containers of the same name would claim
/// the same cgroup -- measured, the second fails with `BrokenChannel`, and the
/// test would look like a runtime error. The same rule as with the address
/// spaces of the agent tests (phase 10a).
async fn arrange(dir: &Path, name: &str) -> (Fixture, tg_runtime::NodePaths, OciRuntime) {
    let paths = tg_runtime::NodePaths::new(dir);
    let runtime =
        OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root()).expect("no OCI runtime");

    let set = tg_defs::from_str(&RUNNING.replace("NAME", name)).expect("the definition parses");
    let workload = &set.workloads()[0];
    let id = tg_runtime::bundle::container_id(name, 0);

    let mut fixture = Fixture {
        id: id.clone(),
        root: paths.runtime_root().clone(),
        rootfs: None,
    };

    let layer = dir.join("layer");
    build_layer(&layer);
    let built = tg_runtime::bundle::build(
        &paths.bundles_dir(),
        workload,
        &id,
        &[layer],
        &ResolvedImage {
            reference: "registry.invalid/api:1".to_owned(),
            layers: Vec::new(),
            entrypoint: vec!["/bin/sleep".to_owned(), "600".to_owned()],
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
        "the container is not running -- the test would otherwise prove nothing"
    );

    (fixture, paths, runtime)
}

/// **An unreadable entry halts the clearer** (ADR-0062, determination 4).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn an_isolated_entry_stops_the_reaper() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime) = arrange(dir.path(), "tg-iso-halt").await;

    // The cluster no longer names this workload -- and **at the same time**
    // another entry is unreadable. Without the second it would be cleared
    // away.
    std::fs::create_dir_all(dir.path().join("desired")).expect("the directory");
    std::fs::write(dir.path().join("desired").join("broken.xml"), "<not").expect("broken");

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context())
        .await
        .expect("the pass must not fail (ADR-0062, determination 1)");

    assert_eq!(
        report.isolated.len(),
        1,
        "the broken entry must appear as isolated: {report:?}"
    );
    assert!(
        runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "a file error cost a running workload"
    );
}

/// **The counter-check: without the finding it very much does clear away.**
///
/// Without it the test above would only show that something holds the clearer
/// up -- including a clearer that does nothing on principle.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn without_the_finding_the_reaper_does_its_work() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime) = arrange(dir.path(), "tg-iso-reap").await;

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context())
        .await
        .expect("the pass");

    assert!(
        report.isolated.is_empty(),
        "nothing must be isolated here: {report:?}"
    );
    assert!(
        !runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "without a finding the clearer must end the container"
    );
}
