//! The requirement edge takes effect (ADR-0009, ADR-0061).
//!
//! The pure logic lies in `tg-model` and is checked there -- `cascade_stop`
//! since phase 3. What is checked here is the **wiring**: that the reconciler
//! calls it, and that a running container really stops because of it. Exactly
//! that was missing, and since phase 3 at that.
//!
//! `#[ignore]`: demands `CAP_SYS_ADMIN` (overlayfs) and an OCI runtime. Run
//! with `cargo xtask storage` -- this test needs no network.

use std::path::Path;

mod support;
use support::{Fixture, build_layer};

use tg_runtime::network::Extras;
use tg_runtime::oci::{DEFAULT_RUNTIMES, OciRuntime};
use tg_runtime::reconcile::{Context, EmptyMeans};
use tg_runtime::resolved::ResolvedImage;
use tg_runtime::state::DesiredState;

/// A target whose image does **not exist**: per RFC 2606 `.invalid` never
/// resolves, so the reconcile fails fast and without a network.
const TARGET: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="tg-gate-dbSUF" kind="service">
    <image reference="registry.invalid/db:1"/>
  </workload>
</workloads>"#;

/// The dependant. `KIND` becomes `requires` or `wants` -- that is the **one**
/// thing that differs between the test and its counter-check.
///
/// The second edge points at a workload this node does **not have** -- in a
/// cluster the normal case, because the scheduler places independently
/// (ADR-0011) and the slice gives a node only its own definitions (ADR-0040).
/// It stands here because both tests would otherwise not take place at all:
/// with the strict view `from_workloads` would give `UnknownTarget`, the error
/// would go out of `once`, `run_with` would abort -- and the agent would end
/// (ADR-0061, determination 1). The assertion for that is the `expect` on the
/// pass itself.
const DEPENDENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="tg-gate-apiSUF" kind="service">
    <image reference="registry.invalid/api:1"/>
    <dependencies>
      <after ref="tg-gate-dbSUF"/>
      <KIND ref="tg-gate-dbSUF"/>
      <after ref="tg-gate-elsewhereSUF"/>
      <requires ref="tg-gate-elsewhereSUF"/>
    </dependencies>
  </workload>
</workloads>"#;

/// The setup: the dependant **runs**, the target is wanted and its image does
/// not exist.
///
/// The container is started by hand here and not over a pass: its image would
/// otherwise not exist either. What is to be checked is what happens to a
/// **running** container.
/// `suffix` distinguishes the names per test, and that is **no** cosmetic: the
/// spec sets `cgroupsPath = /tardigrade/<container-id>` (ADR-0006), and the
/// container name follows the workload name. Two containers of the same name
/// would claim the same cgroup -- measured, the second failed with
/// `BrokenChannel`, in **two of six** runs. The same rule as with the address
/// spaces of the agent tests (phase 10a).
async fn arrange(
    dir: &Path,
    kind: &str,
    suffix: &str,
) -> (Fixture, tg_runtime::NodePaths, OciRuntime) {
    let paths = tg_runtime::NodePaths::new(dir);
    let runtime =
        OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root()).expect("no OCI runtime");

    let desired = DesiredState::open(dir).expect("the desired state");
    for xml in [
        TARGET.replace("SUF", suffix),
        DEPENDENT.replace("KIND", kind).replace("SUF", suffix),
    ] {
        let set = tg_defs::from_str(&xml).expect("the definition parses");
        let workload = &set.workloads()[0];
        desired.put(workload).expect("file it");
        desired
            .assign(tg_defs::WorkloadExt::name(workload), &[0])
            .expect("assign");
    }

    let set =
        tg_defs::from_str(&DEPENDENT.replace("KIND", kind).replace("SUF", suffix)).expect("parses");
    let workload = &set.workloads()[0];
    let id = tg_runtime::bundle::container_id(&format!("tg-gate-api{suffix}"), 0);

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
        empty: &|| EmptyMeans::NothingWanted,
    }
}

/// **A failed `requires` target tears its dependant along** (ADR-0009,
/// ADR-0061 determination 2).
///
/// Up to here it did not: `cascade_stop` was built, checked and had no caller.
/// The dependant carried on while its hard dependency was not there.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn a_failed_requires_target_stops_its_dependent() {
    // The recorder is global; if the installation fails, another test in the
    // same binary has already set it -- then its snapshotter counts, and the
    // metric assertion below can say nothing. Under `cargo xtask storage` the
    // targets run with `--test-threads=1`.
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("the recorder");

    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime) = arrange(dir.path(), "requires", "-r").await;

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context())
        .await
        .expect("the pass itself must not fail");

    let failed: Vec<String> = report.failed.iter().map(ToString::to_string).collect();
    assert!(
        failed.iter().any(|name| name.starts_with("tg-gate-db")),
        "the target should have failed, what failed is {failed:?}"
    );

    // **And the reason travels along** (`Failure`). Up to here it stood only
    // in the log: a test that asserts `is_clean()` could not say *why* an
    // instance fell -- measured at the socket witness, where the cause had to
    // be fetched out of the reconciler with an `eprintln!`.
    //
    // **Both** parts are checked: the enumerable class that is usable as a
    // metric label, and the text that names the image. Without the text a
    // class without content would be green too; without the class a label from
    // the payload would be the next step, and the cardinality rule forbids
    // that (ADR-0015).
    let target = report
        .failed
        .iter()
        .find(|failure| failure.instance.workload.starts_with("tg-gate-db"))
        .expect("the target stands among the failed");
    assert_eq!(
        target.class, "pull",
        "the class does not name where to look: {target}"
    );
    assert!(
        target.reason.contains("registry.invalid"),
        "the reason does not name the image: {target}"
    );

    // **And the class is queryable** (ADR-0015). It is the half that reaches
    // the cluster: the text stays in the node's log, the class becomes a
    // metric with enumerable labels.
    //
    // **One** snapshot: the `DebuggingRecorder` empties itself on reading
    // (measured in `lease_path`).
    let counted = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| key.key().name() == tg_telemetry::names::WORKLOAD_FAILURES)
        .filter_map(|(key, _, _, value)| {
            let class = key
                .key()
                .labels()
                .find(|label| label.key() == "class")?
                .value()
                .to_owned();
            match value {
                metrics_util::debugging::DebugValue::Counter(seen) => Some((class, seen)),
                _ => None,
            }
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        counted.get("pull").copied(),
        Some(1),
        "the class does not stand there as a metric -- seen: {counted:?}"
    );

    let held: Vec<String> = report.held.iter().map(ToString::to_string).collect();
    assert!(
        held.iter().any(|name| name.starts_with("tg-gate-api")),
        "the dependant should have been held back, what is held back is {held:?}"
    );

    assert!(
        !runtime
            .status(&fixture.id)
            .await
            .is_ok_and(tg_runtime::oci::ContainerStatus::is_running),
        "the dependant is still running -- held back means ended, not merely reported"
    );
}

/// **The counter-check: `wants` tears nothing along** (ADR-0009).
///
/// The same setup, and **one** thing is different -- the edge. Without it the
/// test above would only show that something is ended; with it it shows that
/// the separation of axes from ADR-0009 is really carried.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn a_failed_wants_target_leaves_its_dependent_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime) = arrange(dir.path(), "wants", "-w").await;

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context())
        .await
        .expect("the pass itself must not fail");

    assert!(
        report.held.is_empty(),
        "a soft edge must hold nothing back: {:?}",
        report.held
    );
    assert!(
        runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "the dependant was ended although the edge is soft"
    );
}

// **The class witness lies in `tg_runtime::error`**, not here.
//
// It stood at this place and checks **all fifteen** variants there instead of
// five: measured, `Unmappable` got through with the class `runtime` without a
// single target of this crate turning red -- that is, exactly the way its own
// doc block named as the most frequent (a copied `match` arm). At `cases()` it
// lies right: a new variant demands the message **and** the class at the same
// place there.

/// The probe runs **after** the gate, and that is part of the decision.
///
/// **ADR-0089, determination 3.** The gate evaluates against the outcome of
/// the same pass (ADR-0061, determination 2); the readiness probe runs behind
/// the loop over `start_order`, because an instance this pass is just
/// **starting** cannot answer beforehand.
///
/// A gate that read readiness would therefore get the stand of the
/// **previous** pass -- edge-driven on stale state, exactly what ADR-0061
/// avoids. Whoever pulls the probe in front makes this input possible and must
/// take the decision anew. Hence a guard and no prose.
///
/// Checked at the source: the order of two calls in **one** function is not
/// observable from outside without having taken the decision already.
#[test]
fn the_probe_runs_after_the_gate() {
    const SOURCE: &str = include_str!("../src/reconcile.rs");

    let gate = SOURCE
        .find("graph.cascade_stop(")
        .expect("the gate stands in `once`");
    let probe = SOURCE
        .find("probe_readiness(")
        .expect("the probe stands in `once`");

    assert!(
        gate < probe,
        "the probe must stand behind the gate (ADR-0089): before it, it would \
         let the gate read readiness, and that of the previous pass at that"
    );
}
