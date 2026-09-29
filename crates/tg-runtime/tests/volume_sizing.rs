//! A volume's declared size takes effect.
//!
//! Written **before** the implementation.
//!
//! # The finding
//!
//! For an existing volume `declare` gave the stored information back and
//! discarded the declared size. Measured:
//!
//! ```text
//! declared=BASE    -> BASE
//! declared=+64MiB  -> BASE
//! declared=smaller -> BASE
//! ```
//!
//! **After the creation the size was ornament.** `VolumeStore::resize` had
//! been built and checked for a long time -- and had no caller in production
//! code.
//!
//! # What is checked here and what is not
//!
//! The **decision** -- created, unchanged, grown, shrinking refused -- is pure
//! logic and stands here. That a file system is really larger afterwards
//! demands loop devices and `resize2fs`; that stands in `cargo xtask storage`
//! (`volumes.rs`).

use tg_runtime::volume::{Sizing, VolumeStore};

const MIB: u64 = 1024 * 1024;

/// The reference point of the sizes here.
///
/// **Not eight mebibytes** -- a LUKS header lies below the file system.
/// Copied, the number would be wrong again next time -- it therefore comes
/// from the same source as the check.
const BASE: u64 = tg_runtime::volume::MIN_BYTES;

/// Opens a volume store keyed with a fixed per-volume passphrase.
///
/// # Parameters
/// - `dir`: the directory to open the store in.
///
/// # Returns
/// The opened, keyed [`VolumeStore`].
fn store(dir: &std::path::Path) -> VolumeStore {
    VolumeStore::open(dir)
        .expect("the store")
        // Every writable volume is encrypted; without a derivation none
        // arises.
        .keyed(Some(std::sync::Arc::new(|volume: &str| {
            Some(tg_runtime::volume::Passphrases {
            current: format!("passphrase-for-{volume}"),
            previous: None,
        })
        })))
}

/// A new volume is created -- and says so too.
#[test]
fn a_new_volume_is_created() {
    let dir = tempfile::tempdir().expect("the directory");
    let store = store(dir.path());

    let (info, sizing) = store.provision("data", BASE).expect("lay out");

    assert_eq!(info.bytes, BASE);
    assert_eq!(sizing, Sizing::Created);
}

/// The same size once more is no action.
///
/// The reconciler calls this at every start; a volume that reported "grown"
/// every time in the process would not be distinguishable from one that really
/// grows.
#[test]
fn the_same_size_is_no_action() {
    let dir = tempfile::tempdir().expect("the directory");
    let store = store(dir.path());
    store.provision("data", BASE).expect("lay out");

    let (info, sizing) = store.provision("data", BASE).expect("again");

    assert_eq!(info.bytes, BASE);
    assert_eq!(sizing, Sizing::Unchanged);
}

/// **A raised size takes effect.**
#[test]
fn a_larger_declaration_grows_the_volume() {
    let dir = tempfile::tempdir().expect("the directory");
    let store = store(dir.path());
    store.provision("data", BASE).expect("lay out");

    let (info, sizing) = store.provision("data", BASE + 64 * MIB).expect("grow");

    assert_eq!(info.bytes, BASE + 64 * MIB, "the declared size must apply");
    assert_eq!(
        sizing,
        Sizing::Grown {
            from: BASE,
            to: (BASE + 64 * MIB)
        }
    );
}

/// **It is never shrunk.**
///
/// And without an error at that: making an outage out of a typo helps nobody.
/// The volume keeps its size, the workload runs.
#[test]
fn a_smaller_declaration_is_refused_without_failing() {
    let dir = tempfile::tempdir().expect("the directory");
    let store = store(dir.path());
    store.provision("data", BASE + 64 * MIB).expect("lay out");

    let (info, sizing) = store.provision("data", BASE).expect("no error");

    assert_eq!(info.bytes, BASE + 64 * MIB, "the volume keeps its size");
    assert_eq!(
        sizing,
        Sizing::ShrinkRefused {
            actual: BASE + 64 * MIB,
            declared: BASE
        }
    );
}

/// The name is the trust boundary and is checked first.
///
/// A malicious name must not fail on a size error -- otherwise the same name
/// would get through with a plausible size.
#[test]
fn the_name_is_checked_before_the_size() {
    let dir = tempfile::tempdir().expect("the directory");
    let store = store(dir.path());

    let refused = store.provision("../escape", 1);

    assert!(
        matches!(
            refused,
            Err(tg_runtime::volume::VolumeError::IllegalName { .. })
        ),
        "{refused:?}"
    );
}

/// A **new** volume that is too small stays an error.
///
/// Unlike the shrinking: here there is nothing one could run on.
#[test]
fn a_new_volume_below_the_minimum_still_fails() {
    let dir = tempfile::tempdir().expect("the directory");
    let store = store(dir.path());

    let refused = store.provision("data", 1);

    assert!(
        matches!(
            refused,
            Err(tg_runtime::volume::VolumeError::TooSmall { .. })
        ),
        "{refused:?}"
    );
}

// ------------------------------------------------- The report, per pass

/// The two sizes are reported **without** a start.
///
/// **The finding:** `provision` runs only when an instance is really
/// started. Since gauges expire after 15 minutes,
/// `tg_volume_declared_bytes` and `tg_volume_size_bytes` would thereby have
/// disappeared a quarter of an hour after the start -- and with them
/// `TardigradeVolumeSizeIneffective`, that is, exactly the alarm for a size
/// that does **not** take effect.
///
/// It is checked without privileges: `declare` writes the record from which
/// `info` reads the actual size -- `mkfs` and loop devices are not needed for
/// that, and the report reads only the record.
#[test]
fn the_sizes_are_reported_without_a_start() {
    use metrics_util::MetricKind;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let dir = tempfile::tempdir().expect("temp");
    let local = store(dir.path());
    // The state after a failed growth: declared are 64 MiB, actually 8 lie
    // there. Exactly the case the two numbers are to show -- the instance is
    // **not** stale in the process, for the declaration agrees with the
    // bundle.
    local.declare("data-0", BASE).expect("lay out");

    let set = tg_defs::from_str(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service" class="replicated">
    <image reference="registry.test/api:1"/>
    <volumes>
      <volume name="data" path="/data" mode="readWrite" size="67108864"/>
    </volumes>
  </workload>
</workloads>"#,
    )
    .expect("the definition");
    let workload = &set.workloads()[0];

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        tg_runtime::volume::report_declared(dir.path(), workload, 0);
    });

    let mut seen: Vec<(String, String, f64)> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| key.kind() == MetricKind::Gauge)
        .map(|(key, _, _, value)| {
            let name = key.key().name().to_owned();
            let label = key
                .key()
                .labels()
                .find(|label| label.key() == "volume")
                .map(|label| label.value().to_owned())
                .unwrap_or_default();
            let seen = match value {
                DebugValue::Gauge(seen) => seen.into_inner(),
                other => panic!("no gauge: {other:?}"),
            };
            (name, label, seen)
        })
        .collect();
    seen.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));

    assert_eq!(
        seen,
        vec![
            (
                tg_telemetry::names::VOLUME_DECLARED.to_owned(),
                "data-0".to_owned(),
                f64::from(64 * 1024 * 1024_u32)
            ),
            (
                tg_telemetry::names::VOLUME_SIZE.to_owned(),
                "data-0".to_owned(),
                // **The lower bound, not eight mebibytes** -- a LUKS header
                // lies below the file system, and the number comes from the
                // same source as the check.
                min_bytes_as_f64()
            ),
        ],
        "both numbers must stand there without a start, and on the instance's name"
    );
}

/// What does not exist is not half reported.
///
/// Two cases in one, because they carry the same assurance: a volume that is
/// not laid out yet has no actual size -- the declared number alone would be
/// half of a pair, and a ratio on it would lie. And a **read-only** volume has
/// no declared size at all -- what is distributed has the size of its
/// content, not a declared size.
///
/// Without this counter-check a report that outputs something for every
/// declared volume would be green too.
#[test]
fn an_absent_or_read_only_volume_is_not_reported() {
    use metrics_util::debugging::DebuggingRecorder;

    let dir = tempfile::tempdir().expect("temp");
    let _ = store(dir.path());

    let set = tg_defs::from_str(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service" class="replicated">
    <image reference="registry.test/api:1"/>
    <volumes>
      <volume name="missing" path="/missing" mode="readWrite" size="67108864"/>
      <volume name="stock" path="/stock" mode="readOnly" source="registry.test/ref:1"/>
    </volumes>
  </workload>
</workloads>"#,
    )
    .expect("the definition");

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        tg_runtime::volume::report_declared(dir.path(), &set.workloads()[0], 0);
    });

    assert!(
        snapshotter.snapshot().into_vec().is_empty(),
        "without a laid-out volume neither of the two numbers must stand there"
    );
}

/// The reconcile reports them -- **per pass**, not per start.
///
/// Checked at the source, and the boundary stands with it: a behavioural test
/// would need a running container, a real loop device and a second pass, that
/// is, `cargo xtask storage`. What it would check is the **seam** -- that
/// `reconcile_one` calls the report at all -- and neither of the two tests
/// above covers that: they call `report_declared` themselves.
///
/// That the report stands **before** the status query is the whole point.
/// Behind it the `Running` arm returns first, and for a running container it
/// would never run -- that is, precisely in the case for whose sake it
/// exists.
#[test]
fn the_reconciler_reports_the_sizes_every_pass() {
    const SOURCE: &str = include_str!("../src/apply.rs");

    // **The anchor without a `?`:** a failed call is no longer passed
    // through there but is "no information". What this guard checks is
    // unchanged -- the order.
    let (before, after) = SOURCE
        .split_once("runtime.status(&id).await")
        .expect("`reconcile_one` asks for the status");
    assert!(
        before.contains("report_declared("),
        "the report must stand **before** the status query -- behind it the \
         `Running` arm returns first, and a running container would never report"
    );
    assert!(
        !after.contains("report_declared("),
        "a second reporting place would be a second opportunity to count differently"
    );
}

/// The lower bound as an `f64` -- the form in which a metric carries it.
///
/// # Returns
/// [`BASE`] converted to `f64`.
#[expect(
    clippy::cast_precision_loss,
    reason = "a Prometheus metric is an f64; the lower bound lies far below \
              2^53, the conversion is exact"
)]
fn min_bytes_as_f64() -> f64 {
    BASE as f64
}
