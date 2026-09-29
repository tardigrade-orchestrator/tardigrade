//! The context of a trace, across a process boundary (ADR-0133).
//!
//! It lies here and not with the callers because `opentelemetry` is a dependency
//! of this crate and shall stay one: the two places that need the context — the
//! session's server in `tgd` and the reconcile in the agent — shall **hand** it
//! over and not format it themselves. Two formattings would be two
//! opportunities to format differently (ADR-0069).
//!
//! What goes on the wire is a W3C `traceparent` (`00-<32 hex>-<16 hex>-<2 hex>`),
//! not a format of our own — every tool of the ecosystem reads it (ADR-0133,
//! determination 5).
//!
//! **A broken trace costs no pass.** [`adopt`] silently does not accept an
//! unreadable value: then the span simply has no parent. The value comes over the
//! network, and an observation that could halt a reconcile would be the reversal
//! of ADR-0019.

use std::collections::HashMap;

use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

const TRACEPARENT: &str = "traceparent";

#[must_use]
pub fn current() -> Option<String> {
    of(&tracing::Span::current())
}

#[must_use]
pub fn of(span: &tracing::Span) -> Option<String> {
    let mut carrier: HashMap<String, String> = HashMap::new();
    TraceContextPropagator::new().inject_context(&span.context(), &mut carrier);
    carrier.remove(TRACEPARENT)
}

pub fn adopt(span: &tracing::Span, traceparent: Option<&str>) {
    let Some(traceparent) = traceparent else {
        return;
    };
    let carrier: HashMap<String, String> =
        HashMap::from([(TRACEPARENT.to_owned(), traceparent.to_owned())]);
    let context = TraceContextPropagator::new().extract(&carrier);
    span.set_parent(context);
}
