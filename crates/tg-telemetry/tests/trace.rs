//! The context of a trace across a process boundary (ADR-0133).
//!
//! What is checked here is the **boundary**: what arrives comes over the network,
//! and an observation must cost no operation (ADR-0019).

/// **Without a tracer there is no trace — and that is no error.**
///
/// The normal case: without `--otlp-endpoint` nobody exports, and then the slice
/// carries no field. A witness that expected something here would check an
/// environment instead of a behaviour.
#[test]
fn without_a_tracer_there_is_no_context() {
    let span = tracing::info_span!("harness");
    assert_eq!(tg_telemetry::trace::of(&span), None);
    assert_eq!(tg_telemetry::trace::current(), None);
}

/// **An unreadable `traceparent` costs a parent, not an operation.**
///
/// The value comes over the wire (ADR-0133, determination 5). A parser that
/// aborted on it would halt a node's reconcile pass because an **observation** is
/// broken — the reversal of ADR-0019.
#[test]
fn rubbish_is_ignored_instead_of_costing_a_pass() {
    for value in [
        None,
        Some(""),
        Some("quatsch"),
        Some("00-zzzz-zzzz-01"),
        // The right shape, but a null trace id: `traceparent` expressly names it
        // as invalid.
        Some("00-00000000000000000000000000000000-0000000000000000-01"),
        // And one that is well-formed.
        Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    ] {
        let span = tracing::info_span!("harness");
        tg_telemetry::trace::adopt(&span, value);
    }
}
