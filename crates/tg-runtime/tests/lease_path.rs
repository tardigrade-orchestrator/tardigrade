//! The active-role lease takes effect on a real container (ADR-0010,
//! ADR-0064).
//!
//! The **rule** lies in `tg-model` and is checked there without a runtime.
//! What is checked here is the **wiring** -- that the reconciler calls it, and
//! that a running container really stops because of it. Exactly that was
//! missing: `Action::SelfFence` had stood in the list of autonomous actions
//! since phase 4 and had **zero producers**.
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

/// A single writer. Its image does not exist (`.invalid`) -- so the reconcile
/// fails fast and without a network, and that suffices: what is checked is
/// whether it is **attempted** at all.
const TILL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="tg-lease-till" kind="service" class="single-writer">
    <image reference="registry.invalid/till:1"/>
  </workload>
</workloads>"#;

fn context_with(now: u64, fence_margin: u64) -> Context<'static> {
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
        empty: &|| EmptyMeans::NothingWanted,
        now: Box::leak(Box::new(move || now)),
        fence_margin,
        wake: None,
    }
}

/// Without a safety margin -- the remaining tests check the rule without
/// it.
fn context(now: u64) -> Context<'static> {
    context_with(now, 0)
}

/// Files the workload and starts a container for it **by hand**.
///
/// By hand, because its image does not exist: what is to be checked is what
/// happens to a **running** container.
async fn arrange(dir: &Path) -> (Fixture, tg_runtime::NodePaths, OciRuntime, DesiredState) {
    let paths = tg_runtime::NodePaths::new(dir);
    let runtime =
        OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root()).expect("no OCI runtime");

    let desired = DesiredState::open(dir).expect("the desired state");
    let set = tg_defs::from_str(TILL).expect("the definition parses");
    let workload = &set.workloads()[0];
    desired.put(workload).expect("file it");
    desired.assign("tg-lease-till", &[0]).expect("assign");

    let id = tg_runtime::bundle::container_id("tg-lease-till", 0);
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
            reference: "registry.invalid/till:1".to_owned(),
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

    (fixture, paths, runtime, desired)
}

/// **An expired lease ends the instance** (ADR-0010, section 3).
///
/// That is the self-fence, and it is **autonomous**: it must bite when the
/// node does not reach the cluster -- precisely then it cannot ask it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn an_expired_lease_fences_a_running_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime, desired) = arrange(dir.path()).await;

    desired
        .set_lease("tg-lease-till", Some((7, 10_000)))
        .expect("the lease");

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context(10_000))
        .await
        .expect("the pass");

    assert_eq!(
        report.fenced.len(),
        1,
        "the instance should have fenced itself: {report:?}"
    );
    assert!(
        !runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "the instance is still running although its lease has expired"
    );
}

/// **The counter-check: with a valid lease it carries on.**
///
/// Without it the test above would only show that something ends the container
/// -- including a reconciler that clears it away on principle.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn a_valid_lease_leaves_the_instance_running() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime, desired) = arrange(dir.path()).await;

    desired
        .set_lease("tg-lease-till", Some((7, 20_000)))
        .expect("the lease");

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context(10_000))
        .await
        .expect("the pass");

    assert!(report.fenced.is_empty(), "{report:?}");
    assert!(
        runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "a valid lease must not cost the instance"
    );
}

/// **Without a lease a single writer does not start up at all** (ADR-0010).
///
/// The activation needs the quorum. There is no running container here -- what
/// is checked is that the reconciler does **not** start it and reports it as
/// waiting, not as a failure.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn without_a_lease_a_single_writer_does_not_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime =
        OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root()).expect("no OCI runtime");

    let desired = DesiredState::open(dir.path()).expect("the desired state");
    let set = tg_defs::from_str(TILL).expect("the definition parses");
    desired.put(&set.workloads()[0]).expect("file it");
    desired.assign("tg-lease-till", &[0]).expect("assign");

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context(10_000))
        .await
        .expect("the pass");

    assert_eq!(report.waiting.len(), 1, "{report:?}");
    assert!(
        report.failed.is_empty(),
        "waiting is no failure: {report:?}"
    );
}

/// **A lease that is still valid fences nevertheless -- if it lies within the
/// safety margin** (ADR-0064, determination 7).
///
/// That is the case the calculation demands: the holder needs up to one pass
/// to notice the expiry, and then the grace period to stop. If it waited until
/// the expiry, it would run for up to twenty seconds **afterwards** -- while
/// the new holder is already running.
///
/// Here the lease is valid for another five seconds, the margin is twenty.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn a_lease_inside_the_margin_fences_although_it_is_still_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime, desired) = arrange(dir.path()).await;

    desired
        .set_lease("tg-lease-till", Some((7, 15_000)))
        .expect("the lease");

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context_with(10_000, 20_000))
        .await
        .expect("the pass");

    assert_eq!(report.fenced.len(), 1, "{report:?}");
    assert!(
        !runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "the instance is still running although its lease lies within the safety margin"
    );
}

/// **Without an active role the metric stands at zero** (ADR-0064,
/// ADR-0057).
///
/// A fenced single writer appears in the projection as `Stopped` --
/// indistinguishable from any other standstill. ADR-0064 expressly accepts the
/// availability cost ("a single writer without a reachable leader no longer
/// runs after the expiry"); an operator must be able to **see** it, otherwise
/// they look for the error at the workload.
///
/// Both directions in one test, because they are one statement: with a valid
/// lease `1`, without `0`. Only the first half would be green too if the
/// number were always `1`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn the_active_role_is_visible_as_a_number() {
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    // The recorder is global; if the installation fails, another test in the
    // same binary has already set it -- then its snapshotter counts, and this
    // test can say nothing.
    recorder.install().expect("the recorder");

    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime, desired) = arrange(dir.path()).await;

    // A valid **and plausible** lease: the role stands, and the skew is zero.
    // `u64::MAX` stood here, and since ADR-0078 that is no longer "very
    // valid" but a lease from a clock that runs far ahead.
    let now = 1_000;
    desired
        .set_lease(
            "tg-lease-till",
            Some((7, now + tg_model::lease::LEASE_MILLIS - 1)),
        )
        .expect("the lease");
    let _ = tg_runtime::reconcile::once(&paths, &runtime, &context(now)).await;
    let seen = gauges(&snapshotter, "tg-lease-till");
    assert_eq!(
        seen.get(tg_telemetry::names::ACTIVE_ROLE).copied(),
        Some(1.0),
        "with a valid lease the role stands"
    );
    assert_eq!(
        seen.get(tg_telemetry::names::LEASE_CLOCK_SKEW).copied(),
        Some(0.0),
        "without a clock skew the zero must be visible -- a metric that appears \
         only in the error case is not distinguishable from a missing one"
    );

    // None: it does not stand.
    desired.set_lease("tg-lease-till", None).expect("the lease");
    let _ = tg_runtime::reconcile::once(&paths, &runtime, &context(now)).await;
    let seen = gauges(&snapshotter, "tg-lease-till");
    assert_eq!(
        seen.get(tg_telemetry::names::ACTIVE_ROLE).copied(),
        Some(0.0),
        "without a lease the zero must be visible"
    );

    // **And a lease from a clock that runs far ahead** (ADR-0078,
    // determinations 3 and 4): it is **not** carried, and the skew stands
    // there. Both together are the statement -- the role alone would not say
    // *why* it does not stand, and the skew alone not that a consequence was
    // drawn from it.
    let skewed = now + 2 * tg_model::lease::LEASE_MILLIS + 5_000;
    desired
        .set_lease("tg-lease-till", Some((7, skewed)))
        .expect("the lease");
    let _ = tg_runtime::reconcile::once(&paths, &runtime, &context(now)).await;
    let seen = gauges(&snapshotter, "tg-lease-till");
    assert_eq!(
        seen.get(tg_telemetry::names::ACTIVE_ROLE).copied(),
        Some(0.0),
        "a lease from a clock that runs far ahead carried the role"
    );
    #[expect(
        clippy::cast_precision_loss,
        reason = "a constant in milliseconds against the metric's seconds"
    )]
    let expected = (tg_model::lease::LEASE_MILLIS + 5_000) as f64 / 1000.0;
    assert_eq!(
        seen.get(tg_telemetry::names::LEASE_CLOCK_SKEW).copied(),
        Some(expected),
        "the clock skew does not stand in the metric"
    );
    let _ = fixture;
}

/// This workload's metrics, from **one** snapshot.
///
/// # Why one per stage and not one per assertion
///
/// **The snapshotter empties itself on reading** -- measured in a trial run of
/// its own: the same gauge reads its value at the first `snapshot()` and
/// **zero** at the second. A helper that takes a snapshot per assertion
/// thereby never measures the second metric -- it cleared it away with the
/// first.
///
/// Exactly that is what this test fell for when it grew from one assertion to
/// two: the measuring instrument changed what it was to measure. So **one**
/// snapshot per stage, and read from it.
fn gauges(
    snapshotter: &metrics_util::debugging::Snapshotter,
    workload: &str,
) -> std::collections::BTreeMap<String, f64> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| {
            key.key()
                .labels()
                .any(|label| label.key() == "workload" && label.value() == workload)
        })
        .filter_map(|(key, _, _, value)| match value {
            metrics_util::debugging::DebugValue::Gauge(seen) => {
                Some((key.key().name().to_owned(), seen.into_inner()))
            }
            _ => None,
        })
        .collect()
}

/// **The reconcile's sleep follows the next fence threshold** (ADR-0076,
/// determination 1).
///
/// The detection latency stood in the safety margin here: `--interval` plus
/// the grace period. With the default of ten seconds the margin became larger
/// than the remaining time in the trough, and a **healthy** single writer
/// counted as fenced two thirds of the time.
///
/// Built the other way round: the margin is a small floor, and the reconcile
/// wakes **close to the threshold**. This computation is the seam for it -- it
/// is pure, so checkable without a process.
#[test]
fn the_nap_follows_the_next_fence() {
    use tg_runtime::reconcile::nap_for;
    let interval = std::time::Duration::from_secs(10);
    let floor = std::time::Duration::from_millis(tg_model::lease::FENCE_WAKE_FLOOR_MILLIS);

    // Without a single writer the interval applies -- a node without an
    // active role does not wake more often than the operator demanded.
    assert_eq!(nap_for(interval, None, 1_000), interval);

    // A threshold beyond the interval changes nothing.
    assert_eq!(nap_for(interval, Some(1_000 + 30_000), 1_000), interval);

    // A threshold **within** the interval brings the sleep forward: exactly
    // that is the point, for otherwise the detection latency would carry the
    // interval.
    assert_eq!(
        nap_for(interval, Some(1_000 + 4_000), 1_000),
        std::time::Duration::from_secs(4)
    );

    // And the floor holds: a threshold immediately before it -- or one that
    // is already past -- must not yield a hot loop.
    assert_eq!(nap_for(interval, Some(1_050), 1_000), floor);
    assert_eq!(nap_for(interval, Some(500), 1_000), floor);

    // An interval **below** the floor stays decisive: whoever sets
    // `--interval 0` gets no artificially lengthened sleep.
    let tight = std::time::Duration::from_millis(200);
    assert_eq!(nap_for(tight, Some(1_050), 1_000), tight);
}
