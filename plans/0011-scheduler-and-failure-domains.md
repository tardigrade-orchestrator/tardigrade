# ADR-0011: Scheduler & Failure Domains

- **Status:** accepted — declarative-explicit, no auto-rebalancing
- **Date:** 2026-08-12
- **Deciders:** Core team
- **Covers:** ADR-0021 (failure domains & topology)

## Context and Problem Statement

ADR-0010 delegates warm-standby placement and anti-affinity to the scheduler.
To be settled: by what model placement happens, whether running workloads are
redistributed automatically, and how failure domains are modelled.

## Decision Drivers

- Predictability and auditability (an auditor must be able to see *why* workload
  X runs on node Y).
- No surprise churn — in particular no unplanned single-writer fencing dance
  (ADR-0010).
- Warm-standby anti-affinity across failure domains; quorum spreading (ADR-0019).
- Scheduling is leader/quorum-bound (ADR-0010).

## Decision

### Placement model: declarative-explicit

The workload definition (ADR-0008) carries **placement constraints** (permitted/
required failure domains, pins). The scheduler **validates** the constraints,
picks a concrete node **within** the permitted domains, and rejects unsatisfiable
constraints at ingest already. **No opaque scoring.**

### Rebalancing: none automatically

The scheduler places only **new** and **failed** workloads. Running ones are
**never moved unprompted**. Moves are **explicitly operator-triggered**
(drain/cordon). Single-writer moves always go through the controlled fencing
dance (ADR-0010).

### Failure-domain model (covers ADR-0021)

- The hierarchy **site → room/hall → rack → host**, as labels in the node
  definition (no cloud/K8s topology provider).
- **Warm-standby anti-affinity:** a standby **must** lie in a different failure
  domain than its primary; the governing level (rack vs. hall) is configurable
  per workload — a hard constraint.
- **Quorum spreading:** control-plane nodes are distributed across independent
  domains (ADR-0019).

### Sequence

Scheduling runs in the **leader** (quorum), writes assignments into the Raft log
(ADR-0004/0005/0010). Level-triggered: on node loss the leader re-places the
affected workloads per their constraints — **only with quorum present**;
otherwise the autonomy boundary from ADR-0010 applies.

## Consequences

**Positive**
- Every placement is traceable from constraints plus the assignment in the Raft
  log (audit).
- Deterministic, no churn; single-writer failover only through controlled fences.
- Anti-affinity structurally → losing one failure domain preserves workload
  availability.

**Negative / Costs**
- Declarative = more manual constraint maintenance and worse automatic
  utilization than scoring. A deliberate trade-off: predictability > packing
  density.
- No auto-rebalancing → utilization drift over time; needs operator tooling
  (drain, a planned rebalance campaign).
- A warm standby ties up reserved capacity in another domain.

**Risks & Open Points**
- ~~The expressiveness of the constraint language — part of the XSD subset (ADR-0008).~~
  **Decided in ADR-0034:** `<placement>` with `replicas`, `spread`, `<domain>`
  and `<pin>`; same level OR, different levels AND.
- ~~The resource/capacity model (CPU/RAM reservation) is still to be specified.~~
  **Decided in ADR-0034:** a generic resource map on the node, so that the
  `device` type from ADR-0028 fits without rework.
- ~~Fix the default granularity of anti-affinity (rack vs. hall).~~
  **Decided in ADR-0034:** `rack`, raisable per workload.
- ~~What stays open: drain/cordon as an operator tool, reserved capacity for
  warm standbys, and who reports a node's capacity (ADR-0034).~~ — **done:**
  drain/cordon built, ADR-0047 (the reserve), ADR-0049 (the report).

## Related ADRs

- Serves: ADR-0010 (standby placement, autonomy), ADR-0019 (quorum spreading).
- Assignment in Raft: ADR-0004/0005. Constraints in the definition: ADR-0008.
- Subsumes: ADR-0021.
