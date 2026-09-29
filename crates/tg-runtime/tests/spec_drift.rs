//! A changed declaration does not reach a running container -- and **that is
//! said** (ADR-0070).
//!
//! # The finding this fixes
//!
//! `step` returned immediately at `ContainerStatus::Running` and put the
//! instance into `untouched`. Nothing in the tree compared a running container
//! with its declaration. Measured at a real container:
//!
//! ```text
//! cache contains api:2:      true
//! report:                    untouched: [tg-probe-drift/0]
//! config.json contains 600:  true    contains 900: false
//! ```
//!
//! So a new image tag never reached the container -- not even an attempt --
//! and the report called the instance `untouched`. That is formally right and
//! keeps the situation quiet: `tgctl cluster show` says "runs", and an
//! operator holds their change to be delivered.
//!
//! # What is checked here
//!
//! Both halves of the decision: the container **carries on** (ADR-0019,
//! ADR-0063 -- a number in the XML must not be a restart trigger), and the
//! deviation **appears**. In addition the property a pot of its own would have
//! destroyed: the instance stands **also** in `untouched`, for the resolution
//! in the resolver and the report to the leader hang on that.
//!
//! # And the case in which we do not know the state (ADR-0122)
//!
//! The same assurance from the other side: "not touched" must apply when the
//! runtime does not tell us what the container does too. Measured, it did not
//! -- `Unknown` fell together with `Absent`, and the path led into `start`:
//!
//! ```text
//! mounted before:      true
//! build: Ok -- the rootfs was unmounted under the running container
//! mounted afterwards:  true        (with the new layer)
//! still running:       Ok(Running)
//! create: Err -- container already exists
//! upper exists:        true        (new and empty -- the old one is gone)
//! ```
//!
//! The witness for that stands below and needs the same apparatus: a real
//! container on a real mount.
//!
//! `#[ignore]`: demands `CAP_SYS_ADMIN` (overlayfs) and an OCI runtime. Run
//! with `cargo xtask storage`.

use std::path::Path;

mod support;
use support::{Fixture, build_layer};

use tg_runtime::content::{ContentStore, Digest256};
use tg_runtime::network::Extras;
use tg_runtime::oci::{DEFAULT_RUNTIMES, OciRuntime};
use tg_runtime::reconcile::{Context, EmptyMeans};
use tg_runtime::resolved::ResolvedImage;
use tg_runtime::state::DesiredState;

/// The declaration the running container was built from.
const BEFORE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="NAME" kind="service">
    <image reference="registry.invalid/api:1"/>
    <command>
      <arg>/bin/sleep</arg>
      <arg>600</arg>
    </command>
  </workload>
</workloads>"#;

/// The same unit, a new tag and a new command.
const AFTER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="NAME" kind="service">
    <image reference="registry.invalid/api:2"/>
    <command>
      <arg>/bin/sleep</arg>
      <arg>900</arg>
    </command>
  </workload>
</workloads>"#;

fn context<'a>() -> Context<'a> {
    Context {
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
        empty: &|| EmptyMeans::NothingWanted,
    }
}

/// A running container from [`BEFORE`], with a matching desired state.
///
/// `name` differs per test: the spec sets
/// `cgroupsPath = /tardigrade/<container-id>` (ADR-0006), and two containers
/// of the same name would claim the same cgroup -- the second failed with
/// `BrokenChannel`, and the test would look like a runtime error.
async fn arrange(
    dir: &Path,
    name: &str,
) -> (
    Fixture,
    tg_runtime::NodePaths,
    OciRuntime,
    DesiredState,
    std::path::PathBuf,
) {
    let paths = tg_runtime::NodePaths::new(dir);
    let runtime =
        OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root()).expect("no OCI runtime");

    let set = tg_defs::from_str(&BEFORE.replace("NAME", name)).expect("the definition parses");
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
    let config = built.dir().join("config.json");

    runtime.create(&id, built.dir()).await.expect("lay out");
    runtime.start(&id).await.expect("start");
    assert!(
        runtime.status(&id).await.expect("the state").is_running(),
        "the container is not running -- the test would otherwise prove nothing"
    );

    let state = DesiredState::open(dir).expect("the cache");
    state.put(workload).expect("the desired state");
    state.assign(name, &[0]).expect("assign");

    (fixture, paths, runtime, state, config)
}

/// Lays an image into the content store, **without a registry**.
///
/// ADR-0019: if it lies locally, it is taken locally. The layer is the one
/// [`build_layer`] has already laid out -- as a tar, because the store is
/// content-addressed and `unpack_layer` wants a blob.
fn seed(store: &ContentStore, reference: &str, layer: &Path, command: &[&str]) {
    let mut archive = tar::Builder::new(Vec::new());
    archive
        .append_dir_all(".", layer)
        .expect("the layer as a tar");
    let blob = archive.into_inner().expect("the archive");

    let digest = Digest256::of(&blob);
    store.verify_blob(&digest, &blob).expect("the blob");
    store
        .unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", &blob)
        .expect("unpack");

    ResolvedImage {
        reference: reference.to_owned(),
        layers: vec![digest],
        entrypoint: command.iter().map(|arg| (*arg).to_owned()).collect(),
        env: vec!["PATH=/bin".to_owned()],
    }
    .save(store)
    .expect("the record");
}

/// **A decree restarts, and afterwards the deviation is gone** (ADR-0071).
///
/// The test carries the node's whole chain: the generation from the cache, the
/// comparison with the marker in the bundle, the stop with a grace period and
/// the start from the **current** declaration. That `stale` is empty
/// afterwards is the statement: the decree did what it is there for.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn an_ordered_restart_replaces_the_container_with_the_current_declaration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let name = "tg-drift-order";
    let (fixture, paths, runtime, state, config) = arrange(dir.path(), name).await;

    // **The container writes into its ephemeral volume** (ADR-0027). What
    // happens to it is half this test's assurance: it belongs to the layers it
    // lies over and must not survive a different image (ADR-0120,
    // determination 2).
    let rootfs = fixture.rootfs.clone().expect("the rootfs");
    std::fs::write(rootfs.join("scratch.txt"), "from-the-container").expect("write access");

    // **An image with different content**, and that is the point: until
    // ADR-0120 this test seeded the "new" image with the **same** layer
    // directory as the old one. Even with a correct remount the content would
    // have been identical -- the witness could not see the finding.
    let store = ContentStore::open(paths.content_dir()).expect("the store");
    let second_layer = dir.path().join("layer-2");
    build_layer(&second_layer);
    std::fs::write(second_layer.join("generation.txt"), "two").expect("the file");
    seed(
        &store,
        "registry.invalid/api:2",
        &second_layer,
        &["/bin/sleep", "900"],
    );
    let changed = tg_defs::from_str(&AFTER.replace("NAME", name)).expect("the definition parses");
    state
        .put(&changed.workloads()[0])
        .expect("the desired state");

    // **The decree**: generation 1 for instance 0. The bundle carries
    // zero.
    state
        .set_generations(name, &[(0, 1)])
        .expect("the generation");

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context())
        .await
        .expect("the pass");

    assert!(report.failed.is_empty(), "the restart failed: {report:?}");
    assert_eq!(
        report.reconciled.len(),
        1,
        "the instance must have been replaced: {report:?}"
    );
    assert!(
        report.stale.is_empty(),
        "after the restart no deviation must be open any more: {report:?}"
    );
    assert!(
        runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "the container is not running after the restart"
    );

    let text = std::fs::read_to_string(&config).expect("config.json");
    assert!(
        text.contains("900") && !text.contains("\"600\""),
        "the bundle carries the old declaration: {text}"
    );

    // **And the rootfs carries the new image** (ADR-0120, determination 1).
    //
    // That is the assurance that was missing up to here: measured, `build`
    // took the **existing** mount, and that carries the old `lowerdir`. A
    // changed image thereby reached the `config.json` and **not** the file
    // system -- a security update in a base image never arrived at the
    // workload.
    assert!(
        rootfs.join("generation.txt").exists(),
        "the rootfs shows the old image: the mount was not renewed"
    );

    // **And the ephemeral volume is gone** (determination 2). A writable layer
    // of image A over image B would lay itself over exactly the files somebody
    // once touched -- the new generation would be invisible there.
    assert!(
        !rootfs.join("scratch.txt").exists(),
        "the old image's `upper` lies over the new one"
    );

    // And the marker now carries the decreed generation -- otherwise the next
    // pass would restart again, and the reconciler would turn in circles.
    assert_eq!(
        tg_runtime::bundle::built_generation(&paths.bundles_dir(), &changed.workloads()[0]),
        1
    );
}

/// **The change is reported and nothing is touched** (ADR-0070).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn a_changed_declaration_is_reported_and_leaves_the_container_alone() {
    // **Before the pass**, and that is no formality: the recorder is global
    // and is installed lazily (`OnceLock`). Whoever wakes it only afterwards
    // has none during the pass -- the gauge went into nothing, and the
    // snapshot was empty (measured).
    let dir = tempfile::tempdir().expect("tempdir");
    let name = "tg-drift-said";
    assert_eq!(seen(name).stale, None, "before the run nothing is reported");
    let (fixture, paths, runtime, state, config) = arrange(dir.path(), name).await;

    let changed = tg_defs::from_str(&AFTER.replace("NAME", name)).expect("the definition parses");
    state
        .put(&changed.workloads()[0])
        .expect("the desired state");

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context())
        .await
        .expect("the pass");

    assert_eq!(
        report.stale.len(),
        1,
        "the deviation must appear: {report:?}"
    );
    assert_eq!(report.stale[0].workload, name);
    assert_eq!(report.stale[0].instance, 0);

    // **And it stands in `untouched` too.** The resolution in the resolver
    // and the report to the leader hang on that; a pot of its own would have
    // taken the instance out of DNS through four call sites.
    assert!(
        report.untouched.contains(&report.stale[0]),
        "stale means running (ADR-0070, determination 5): {report:?}"
    );
    assert!(
        report.is_clean(),
        "stale is no finding and must yield no error status: {report:?}"
    );

    // Nothing touched: the same container, the same bundle.
    assert!(
        runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "a changed declaration cost a running container"
    );
    let text = std::fs::read_to_string(&config).expect("config.json");
    assert!(
        text.contains("600") && !text.contains("900"),
        "the bundle was rebuilt although it was not allowed to be"
    );

    // **And the metric says so too** (ADR-0070, determination 2). The
    // `report.stale` above is the way into the report; `tg_workload_stale` is
    // the way to the alarm rule (`TardigradeDeclarationOutstanding`), and a
    // rule on a metric nobody sets fires **never**.
    assert_eq!(
        seen(name).stale,
        Some(1.0),
        "the metric does not report the deviation -- then the alarm rule \
         stands on a time series that does not exist"
    );
}

/// **The counter-check: an unchanged declaration is not stale.**
///
/// Without it a comparison that always says "stale" would be green too -- and
/// the metric would stand permanently at `1` for every workload of this
/// cluster.
///
/// The metric is **set to zero** in the process, not left out: a time series
/// that appears only on a finding is not distinguishable from a missing one --
/// and `TardigradeDeclarationOutstanding` would then see a cluster in which
/// nothing is outstanding just like one in which the reporter is switched
/// off.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn an_unchanged_declaration_is_not_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let name = "tg-drift-quiet";
    // As with the witness above: the recorder belongs **before** the pass.
    assert_eq!(seen(name).stale, None, "before the run nothing is reported");
    let (fixture, paths, runtime, _state, _config) = arrange(dir.path(), name).await;

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context())
        .await
        .expect("the pass");

    assert!(
        report.stale.is_empty(),
        "nobody changed anything here: {report:?}"
    );
    assert_eq!(report.untouched.len(), 1, "{report:?}");
    assert!(
        runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running()
    );

    // A **zero**, not the absence of the time series.
    assert_eq!(
        seen(name).stale,
        Some(0.0),
        "the metric is missing or reports a deviation that does not exist"
    );
}

// **A seam, no path** (ADR-0081): the socket is per instance, and whoever
// has reached it is in its container. The test provides it so that the
// assertion below checks the **mount** and not the binding.
struct OneSocket(std::path::PathBuf);

impl tg_runtime::network::Sockets for OneSocket {
    fn ensure(&self, container: &str) -> Result<std::path::PathBuf, String> {
        let path = self.0.join(format!("{container}.sock"));
        std::fs::write(&path, b"").map_err(|err| err.to_string())?;
        Ok(path)
    }

    fn held(&self) -> Vec<String> {
        Vec::new()
    }

    fn release(&self, _container: &str) {}
}

/// **Every workload container gets the workload API socket** (ADR-0079).
///
/// # What hung on it
///
/// The mount arose in `apply.rs` **only** in the `principal.is_some()` arm --
/// that is, for the derived unit (ADR-0059). The sidecar was thereby the only
/// one that could reach the socket, and a SPIFFE-capable application did not
/// get to its identity although ADR-0035 built the standardized surface for
/// exactly that. `<mesh>` does not help there: it identifies the *sidecar*,
/// not the workload (ADR-0036).
///
/// # Why at the `config.json`
///
/// The assembly of the mounts lies in `apply.rs` and is not callable from
/// outside; it becomes observable at the spec a **real** run writes. The
/// witness thereby goes through the same path as operation.
///
/// **Both directions in one test**, and the second carries: without the
/// setting the mount does **not** stand there. Otherwise an `apply` that
/// appends it unconditionally would be green too -- and `tgctl apply` (the
/// node-local way without an agent, phase 2) would point at a socket nobody
/// listens on.
#[tokio::test]
#[ignore = "starts a real container (cargo xtask storage)"]
async fn a_workload_container_gets_the_workload_api_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let name = "tg-drift-socket";
    let (fixture, paths, runtime, state, config) = arrange(dir.path(), name).await;

    // Without the setting: nothing.
    let text = std::fs::read_to_string(&config).expect("config.json");
    assert!(
        !text.contains(tg_model::mesh::SOCKET_IN_CONTAINER),
        "without the setting the mount must not stand there"
    );

    let socket = OneSocket(dir.path().to_path_buf());

    // Rebuild the same container: the declaration stays, only the setting
    // comes along. So decree a restart (ADR-0071).
    //
    // And the image must lie **in the store** for that: `arrange` builds the
    // bundle immediately, without filling the store -- a restart by the
    // reconciler would otherwise pull it from a registry that does not exist
    // (measured: `error sending request for url https://registry.invalid/...`).
    let store = ContentStore::open(paths.content_dir()).expect("the store");
    seed(
        &store,
        "registry.invalid/api:1",
        &dir.path().join("layer"),
        &["/bin/sleep", "600"],
    );
    state
        .set_generations(name, &[(0, 1)])
        .expect("the generation");
    let with = Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        workload_api: Some(&socket),
        secrets: None,
        credentials: None,
        ..context()
    };
    let report = tg_runtime::reconcile::once(&paths, &runtime, &with)
        .await
        .expect("the pass");
    assert!(
        report.is_clean(),
        "the pass did not finish cleanly: {report:?}"
    );

    let text = std::fs::read_to_string(&config).expect("config.json");
    assert!(
        text.contains(tg_model::mesh::SOCKET_IN_CONTAINER),
        "the socket is missing from the workload container's spec: {text}"
    );
    // And **once**, not twice: two mounts onto the same target would be a spec
    // no runtime accepts.
    assert_eq!(
        text.matches(tg_model::mesh::SOCKET_IN_CONTAINER).count(),
        1,
        "the mount stands there several times"
    );

    // **And the source is THIS container's socket** (ADR-0081,
    // determination 3).
    //
    // That is the error the ADR names as the price: since ADR-0081 the
    // security hangs on our mount and no longer on the cgroup -- whoever lays
    // it wrongly gives a container another's identity. The ADR argues that a
    // mismatch is not constructible because the mount and the identifier arise
    // from **one** derivation; here stands the witness for it instead of a
    // claim.
    let id = tg_runtime::bundle::container_id(name, 0);
    assert!(
        text.contains(&format!("{id}.sock")),
        "the source does not name {id}'s socket: {text}"
    );

    // **And no way leads into the socket directory** -- only the one file.
    //
    // That answers the question about *foreign* sockets, and for any number of
    // instances instead of for two: the directory in which all the instances'
    // sockets lie appears nowhere in the spec. A foreign socket is thereby
    // **not addressable** in the mount namespace -- not because the
    // permissions forbid it (they do not, ADR-0081 determination 2) but
    // because the path does not exist there.
    //
    // Were the directory mounted, a prefix without a file name would stand in
    // the spec. What is therefore checked is the **directory path** and not
    // the absence of foreign identifiers: those do not stand in it anyway, and
    // a test on that would be green without showing anything.
    let sockets_dir = socket.0.to_string_lossy().into_owned();
    assert!(
        !text.contains(&format!("{sockets_dir}\"")),
        "the socket directory is mounted: {text}"
    );
    let _ = fixture;
}

// ---------------------------- a decree against a restart loop

/// This test binary's recorder.
///
/// **Global and not thread-local**, and that is measured to be necessary:
/// these tests run on `multi_thread`, and an `await` can continue on another
/// worker -- `with_local_recorder` applies to **one** thread and would be gone
/// after the first `await`.
///
/// This file's tests run concurrently and thereby book onto the same recorder.
/// They are distinguished by the label `workload`: every test has its own
/// name.
fn recorder() -> &'static metrics_util::debugging::Snapshotter {
    use std::sync::OnceLock;
    static SNAP: OnceLock<metrics_util::debugging::Snapshotter> = OnceLock::new();
    SNAP.get_or_init(|| {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // A second call fails; `OnceLock` permits none.
        metrics::set_global_recorder(recorder).expect("the recorder");
        snapshotter
    })
}

/// What the collector knows about a workload.
#[derive(Default, Clone, Copy)]
struct Seen {
    /// Restarts, **summed** over all the snapshots.
    restarts: u64,
    /// Whether the instance counted as stale at the last report (ADR-0070).
    stale: Option<f64>,
    /// Passes in which the state was unknown (ADR-0122) -- **summed**, like
    /// the restarts.
    unclear: u64,
}

/// Reads **both** of this file's metrics and collects them per workload.
///
/// `Snapshotter::snapshot` **empties** the recorder on reading. A helper that
/// reads only the last snapshot therefore sees a zero at every second call --
/// the same pitfall ADR-0078 has already cost once. Counting therefore happens
/// in a collector that keeps the values read.
///
/// **And that is why there is exactly one reader.** A second one -- say one
/// only for `tg_workload_stale` -- would take the first one's counters,
/// because both empty the same snapshotter. The counter is added, the gauge
/// replaced: that is the difference between "how often" and "how is it
/// now".
fn seen(workload: &str) -> Seen {
    use metrics_util::MetricKind;
    use metrics_util::debugging::DebugValue;
    use std::sync::Mutex;

    static TOTAL: Mutex<Option<std::collections::BTreeMap<String, Seen>>> = Mutex::new(None);

    let mut guard = TOTAL.lock().expect("the collector");
    let total = guard.get_or_insert_with(std::collections::BTreeMap::new);

    for (key, _, _, value) in recorder().snapshot().into_vec() {
        let name = key.key().name().to_owned();
        let of = key
            .key()
            .labels()
            .find(|label| label.key() == "workload")
            .map(|label| label.value().to_owned())
            .unwrap_or_default();
        let entry = total.entry(of).or_default();
        match (key.kind(), name.as_str(), value) {
            (MetricKind::Counter, n, DebugValue::Counter(count))
                if n == tg_telemetry::names::WORKLOAD_RESTARTS =>
            {
                entry.restarts += count;
            }
            (MetricKind::Counter, n, DebugValue::Counter(count))
                if n == tg_telemetry::names::WORKLOAD_UNCLEAR =>
            {
                entry.unclear += count;
            }
            (MetricKind::Gauge, n, DebugValue::Gauge(number))
                if n == tg_telemetry::names::WORKLOAD_STALE =>
            {
                entry.stale = Some(number.into_inner());
            }
            _ => {}
        }
    }

    total.get(workload).copied().unwrap_or_default()
}

/// How often this workload was restarted -- **summed**.
fn restarts(workload: &str) -> u64 {
    seen(workload).restarts
}

/// **A container that no longer runs is counted as a restart** -- a decree is
/// not.
///
/// # The finding
///
/// `reconcile_one` returned `Outcome::Replaced` for both cases: for a
/// **running** container an operator had replaced (ADR-0071), and for an
/// **ended** one the pass restarts because it is ended. The one is a human's
/// decision, the other an error.
///
/// Both were counted only by
/// `tg_agent_reconcile_total{outcome="reconciled"}` -- aggregated over the
/// whole node, in one pot with every first start. **Which** workload does not
/// come up was said by the log alone, and a restart loop is the most frequent
/// operational disturbance of all (ADR-0015: incident-relevant events must be
/// queryable).
///
/// Both halves stand here, because the assurance is the **distinction**: if
/// the pass counted every replacement, the first part would be green too.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn a_restart_is_counted_and_an_ordered_replacement_is_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let name = "tg-drift-loop";
    let (fixture, paths, runtime, state, _config) = arrange(dir.path(), name).await;

    let store = ContentStore::open(paths.content_dir()).expect("the store");
    seed(
        &store,
        "registry.invalid/api:1",
        &dir.path().join("layer"),
        &["/bin/sleep", "600"],
    );

    assert_eq!(restarts(name), 0, "before the run nothing must be counted");

    // End the running container **without** removing it: afterwards its state
    // is `Stopped`, and exactly that is what a pass sees with a workload that
    // crashes at startup. Removed it would be `Absent`, and that is a first
    // start and no restart.
    runtime.kill(&fixture.id, "SIGKILL").await.expect("end it");
    for _ in 0..50 {
        if !runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        !runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "the container is still running -- the test would otherwise check the wrong arm"
    );

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context())
        .await
        .expect("the pass");
    assert!(report.failed.is_empty(), "the restart failed: {report:?}");
    assert!(
        runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "the container is not running after the restart"
    );
    assert_eq!(
        restarts(name),
        1,
        "a container that was not running must be counted as a restart"
    );

    // The other half: a **decree** on the now running container is no restart.
    // Without it a pass that counts every replacement would be green too --
    // and a restart loop would not be distinguishable from a rolling
    // update.
    state
        .set_generations(name, &[(0, 1)])
        .expect("the generation");
    let report = tg_runtime::reconcile::once(&paths, &runtime, &context())
        .await
        .expect("the pass");
    assert_eq!(
        report.reconciled.len(),
        1,
        "the decree must have replaced the instance: {report:?}"
    );
    assert_eq!(
        restarts(name),
        1,
        "a decree is a human's decision and no restart"
    );
}

/// **An unknown state unmounts nothing** (ADR-0122).
///
/// The witness against the measured defect: `Unknown` fell together with
/// `Absent`, and `start` -> `bundle::build` unmounted the rootfs **under a
/// running container** and deleted its ephemeral volume -- with `Ok`. Only the
/// subsequent `create` became visible, and its message ("container already
/// exists") reads like a harmless remnant.
///
/// The case is set up as it arises: a real container on a real mount, then a
/// runtime that reports a state this version does not know. What is checked is
/// what is **still there** afterwards.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; cargo xtask storage"]
async fn an_unknown_state_unmounts_nothing() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let name = "tg-drift-unclear";
    // **Woken before the pass**, as in the neighbouring tests: the recorder is
    // installed lazily, and whoever wakes it only afterwards had none during
    // the run -- the metric would go into nothing (measured).
    assert_eq!(seen(name).unclear, 0, "before the run nothing is counted");
    let (fixture, paths, runtime, state, _config) = arrange(dir.path(), name).await;

    // What the container wrote into its ephemeral volume (ADR-0027).
    let upper = paths.bundles_dir().join(name).join("upper");
    std::fs::write(upper.join("scratch.txt"), b"from-the-container").expect("the file");
    let rootfs = paths.bundles_dir().join(name).join("rootfs");
    assert!(
        tg_syscall::mount::is_overlay_mounted(&rootfs),
        "without a mount the test would prove nothing"
    );

    // **The declaration changes, and the new image lies ready** -- that is
    // the condition under which `build` remounts (ADR-0120, determination 1).
    // Without the image `start` would already fail on the resolution, and the
    // witness would not see the finding: measured, the mount then stayed
    // standing **with** the defect too.
    let store = ContentStore::open(paths.content_dir()).expect("the store");
    let second_layer = dir.path().join("layer-2");
    build_layer(&second_layer);
    std::fs::write(second_layer.join("generation.txt"), "two").expect("the file");
    seed(
        &store,
        "registry.invalid/api:2",
        &second_layer,
        &["/bin/sleep", "900"],
    );
    let changed = tg_defs::from_str(&AFTER.replace("NAME", name)).expect("the definition parses");
    state
        .put(&changed.workloads()[0])
        .expect("the desired state");

    // A runtime that reports a state this version does not know. The **real**
    // container carries on beside it -- exactly the situation at issue.
    let bin = dir.path().join("tg-fake-runtime");
    std::fs::write(
        &bin,
        "#!/bin/sh\nfor arg in \"$@\"; do\n\
         if [ \"$arg\" = state ]; then printf '%s' '{\"id\":\"x\",\"status\":\"zombie\"}'; exit 0; fi\n\
         done\nexit 0\n",
    )
    .expect("the script");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("executable");
    let blind = tg_runtime::oci::OciRuntime::discover(
        &[bin.to_str().expect("the path")],
        paths.runtime_root().clone(),
    )
    .expect("the fake runtime");

    let report = tg_runtime::reconcile::once(&paths, &blind, &context())
        .await
        .expect("the pass");

    // **The core first**: what the defect destroyed must still be there. The
    // bookkeeping below is the consequence -- an assertion that checks the pot
    // first falls on the bookkeeping in the counter-proof and not on what it
    // is about.
    assert!(
        tg_syscall::mount::is_overlay_mounted(&rootfs),
        "the rootfs was unmounted under a running container"
    );
    // **And it still carries the old image.** The mount alone says nothing:
    // the defect unmounts **and mounts again**, so `is_overlay_mounted` is
    // just as true afterwards (measured). What gives it away is the content.
    assert!(
        !rootfs.join("generation.txt").exists(),
        "a running container's rootfs was swapped (ADR-0120/0122)"
    );
    assert_eq!(
        std::fs::read_to_string(upper.join("scratch.txt")).ok(),
        Some("from-the-container".to_owned()),
        "a running container's ephemeral volume was deleted (ADR-0027)"
    );
    assert!(
        runtime
            .status(&fixture.id)
            .await
            .expect("the state")
            .is_running(),
        "and the container itself must carry on (ADR-0019)"
    );

    // **And the metric says so.** Without it the safe direction would be a
    // silence: nothing happens, nothing fails, and an operator looks for the
    // error where it is not (ADR-0122, determination 6).
    // `TardigradeStateUnknown` stands on it, and a rule on a metric nobody
    // sets fires never.
    assert_eq!(seen(name).unclear, 1, "the unknown state was not counted");

    // And the bookkeeping: a pot of its own, no failure, no health.
    assert_eq!(
        report.unclear.len(),
        1,
        "an unknown state belongs in its own pot: {report:?}"
    );
    assert_eq!(report.unclear[0].instance.workload, name);
    assert!(
        report.failed.is_empty(),
        "not knowing is no failure -- a `failed` would tear the dependants \
         along (ADR-0061): {report:?}"
    );
    assert!(
        !report.untouched.iter().any(|which| which.workload == name),
        "not knowing is no health -- otherwise the resolver would offer it \
         (ADR-0013): {report:?}"
    );
    assert!(
        report.is_clean(),
        "a pass that touched nothing is no finding: {report:?}"
    );
}
