//! What the exporter does with a time series nobody sets any more.
//!
//! The measurement **ADR-0088** rests on — and it concerns foreign code:
//! without an `idle_timeout`, `metrics-exporter-prometheus` keeps every series
//! until the process ends. A `tg_workload_ready{workload="api"} 0` of a
//! withdrawn workload then fires forever, and the alert could only be silenced
//! by restarting the node.
//!
//! Checked with a deadline of **one second** instead of the 15 minutes from
//! `init::GAUGE_IDLE_SECONDS`: the property is the same, and a test that waits
//! a quarter of an hour is one nobody runs. What the default is, `args.rs`
//! nails down.

use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;

/// A gauge disappears after the deadline — and comes back when set.
///
/// Three assertions, and the third carries the decision: did it **not** come
/// back, the decay would be data loss and not a cleanup.
#[test]
fn an_idle_gauge_decays_and_returns() {
    let recorder = PrometheusBuilder::new()
        .idle_timeout(MetricKindMask::GAUGE, Some(Duration::from_secs(1)))
        .build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        metrics::gauge!("tg_probe_gauge", "workload" => "api").set(7.0);
    });

    let fresh = handle.render();
    assert!(
        fresh.contains("tg_probe_gauge"),
        "freshly set, the series has to stand there:\n{fresh}"
    );

    std::thread::sleep(Duration::from_millis(1_300));
    handle.run_upkeep();

    let stale = handle.render();
    assert!(
        !stale.contains("tg_probe_gauge"),
        "after the deadline the series has to be gone, otherwise its alert fires forever:\n{stale}"
    );

    metrics::with_local_recorder(&recorder, || {
        metrics::gauge!("tg_probe_gauge", "workload" => "api").set(9.0);
    });

    let again = handle.render();
    assert!(
        again.contains("tg_probe_gauge") && again.contains(" 9"),
        "on the next set it has to come back — otherwise the decay would be data loss:\n{again}"
    );
}

/// A counter does **not** decay.
///
/// The other half of the mask, and it is no symmetry exercise: disappearing and
/// returning reads to `rate()` as a reset — a counter that decays thus produces
/// a spike that never happened. Without this test `MetricKindMask::ALL` would
/// be an obvious change that nobody makes red.
#[test]
fn an_idle_counter_survives() {
    let recorder = PrometheusBuilder::new()
        .idle_timeout(MetricKindMask::GAUGE, Some(Duration::from_secs(1)))
        .build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        metrics::counter!("tg_probe_total", "outcome" => "deny").increment(3);
    });

    std::thread::sleep(Duration::from_millis(1_300));
    handle.run_upkeep();

    let stale = handle.render();
    assert!(
        stale.contains("tg_probe_total") && stale.contains(" 3"),
        "a counter has to keep its value, otherwise `rate()` reads a reset:\n{stale}"
    );
}
