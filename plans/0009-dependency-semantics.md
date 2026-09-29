# ADR-0009: Startup Dependency Semantics (systemd-analogous) as a Graph

- **Status:** accepted — orthogonal axes
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

The orchestrator needs dependency and ordering management analogous to systemd
(`Wants`, `Requires`, `After`/`Before` …). Two things must be kept apart, as
systemd deliberately does: **ordering** (when things start relative to one
another) and **requirement** (whether a failure drags the dependent workload
down). The relations live in the SurrealDB graph (ADR-0004).

## Decision Drivers

- Familiar, proven semantics (the systemd model) instead of reinvention.
- Dependencies are a graph → SurrealDB `RELATE` is the natural storage.
- Ordering must be deterministic and cycle-safe.

## Options Considered

- **A: adopt systemd's relation types 1:1.** A rich, battle-tested set, but with
  some overlaps/pitfalls (e.g. `Wants` without `After`).
- **B: a reduced, orthogonal set.** Separate axes: *ordering* vs. *requirement*,
  plus `Conflicts`. Fewer traps, some relearning.
- **C: `depends_on` only (Compose style).** Too coarse (it conflates ordering and
  requirement).

## Decision

Chosen: **Option B** with systemd-like names, as typed edges:

Ordering (sequence only, no error propagation):
- `After` / `Before` (stored inversely as one directed edge).

Requirement (failure/lifecycle coupling):
- `Requires` — the target must be running; if it fails, the dependent is stopped.
- `Wants` — soft coupling; a target outage does **not** stop the dependent.
- `BindsTo` — harder than `Requires`: bound to the target's exact active state.
- `Conflicts` — must not be active at the same time.

Rules:
- **Requirement implies no ordering** (as with systemd) — ordering must be set
  explicitly; a linter warns on `Requires` without `After`.
- **Start order** = a topological sort of the ordering subgraph.
- **Cycles** in the ordering graph are a hard validation error (at definition
  ingest, ADR-0008 / when persisting to SurrealDB).
- **Query:** resolution by SurrealDB graph traversal (`->After->` etc.) instead
  of rebuilding it in the application.
- **Sidecar coupling (ADR-0007):** the mTLS sidecar is modelled as `BindsTo` plus
  `After` of the workload — if the identity goes, the workload goes.

## Consequences

**Positive**
- Orthogonal axes avoid the classic systemd misunderstandings.
- The graph DB carries traversal and cycle checking; little logic of our own.
- Error propagation is testable as a graph rule.

**Negative / Costs**
- The reconciler has to evaluate requirement edges at runtime (health →
  cascades), not just at start → coupling to the reconciliation model (proposed).
- Deviating from exact systemd semantics = documentation and learning effort.

**Risks & Open Points**
- ~~The exact behaviour on restart/backoff and how far cascades may run (damping
  against flapping) — to be nailed down in the reconciliation ADR (proposed).~~ —
  **done:** ADR-0061.

## Related ADRs

- Storage: ADR-0004 (the SurrealDB graph).
- Ingest/validation: ADR-0008.
- Runtime evaluation: the reconciliation ADR (proposed).
- Special case sidecar: ADR-0007.
