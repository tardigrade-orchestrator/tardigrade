//! What a sidecar really sees in operation, in terms of connection counts.
//!
//! A benchmark's assumed connection count per shard needs to be backed by a
//! real reporting mechanism rather than left as an unverified guess, so this
//! module tests the metric that reports it.
//!
//! **Only the refresher stands here.** The witnesses at real sockets lie in
//! the test module of `sidecar.rs`: `accept_until` is `pub(crate)`, and making
//! the listener for it public would mean widening a crate's surface for a
//! test.

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

/// Reads the connection-count gauge's current value for one named listener.
///
/// # Parameters
/// - `snapshotter`: the metrics snapshotter to read the current gauge values from.
/// - `listener`: the label value identifying which listener's gauge to look up.
///
/// # Returns
/// The gauge's value for the given listener, or `None` if no matching gauge
/// value was recorded.
fn live(snapshotter: &Snapshotter, listener: &str) -> Option<f64> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .find_map(|(key, _, _, value)| {
            let matches = key.key().name() == tg_telemetry::names::PROXY_CONNECTIONS
                && key
                    .key()
                    .labels()
                    .any(|label| label.key() == "listener" && label.value() == listener);
            match value {
                DebugValue::Gauge(seen) if matches => Some(seen.into_inner()),
                _ => None,
            }
        })
}

/// Verifies that the refresher writes a value for every listener, including
/// idle ones: a sidecar with long-standing, unchanging connections does not
/// set the gauge for hours, and without this registration the metric series
/// would expire and read as missing data instead of as a stable value.
#[test]
fn the_refresher_writes_every_listener() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    metrics::with_local_recorder(&recorder, tg_proxy::sidecar::refresh_connections);

    for listener in ["mesh_inbound", "mesh_redirect", "mesh_outbound", "egress"] {
        assert_eq!(
            live(&snapshotter, listener),
            Some(0.0),
            "`{listener}` reports no refresh -- its series expires after a \
             quarter of an hour (ADR-0088)"
        );
    }
}
