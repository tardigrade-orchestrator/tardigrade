# ADR-0015: Observability (metrics, tracing, probes)

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

The orchestrator has to be observable — and in a REMIT/DORA context telemetry is
compliance-critical: incident detection feeds the DORA reporting deadlines.

## Decision

- **Tracing:** `tracing` with OTLP export (`tracing-opentelemetry`).
- **Metrics:** the `metrics` crate with Prometheus exposition.
- **Probes:** liveness/readiness/health per workload and per system component.
- **Logging:** structured (JSON), correlatable through trace IDs.
- **Topology:** per-node local export with aggregation — deliberately decoupled
  from failure (static stability, ADR-0019): telemetry must not hang on central
  reachability.
- **Timestamps** from the traceable time source (ADR-0024).

## Consequences

**Positive**
- A standard ecosystem (OTLP/Prometheus); incident signals for DORA are present.
- Failure-decoupled through local export.

**Negative / Costs**
- The telemetry pipeline plus retention is operational effort of its own.

**Risks & Open Points**
- ~~Metric cardinality/retention; a sampling strategy for tracing.~~
  **All three decided**, and differently:
  - **Cardinality** in phase 11b: *a label may only take values whose number the
    cluster bounds*, written out in `tg_telemetry::names`. A prose enumeration
    fell behind reality there — it named seven, thirteen were set (`f623ac1`);
    since then `LABELS` is the list, and a guard keeps it together with the
    places that set them.
  - **Retention** with **ADR-0088** (`b72c993`): gauges expire after 15 minutes,
    counters do not — a counter that disappears and comes back reads like a
    reset to `rate()`. Whoever sets rarely registers a refresh in the scrape.
  - **Sampling** with **ADR-0133** — **rejected** rather than open: this control
    plane's rate is structurally bounded, the data plane gets no spans at all,
    and a sample next to a retention-obliged audit trail would be missing
    exactly the transaction an auditor is looking for.

## Related ADRs

- Time: ADR-0024. Audit (separate, stronger): ADR-0020. Resilience: ADR-0019.
