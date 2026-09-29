# ADR-0019: Availability and Resilience Model (static stability)

- **Status:** accepted — the **keystone** (binds 0006, 0007, 0010, 0011, 0025)
- **Date:** 2026-08-12
- **Deciders:** Core team
- **Operational context:** a REMIT/DORA-regulated environment, target workload
  availability 99.99 %–99.999 % (4-9 to 5-9).

## Context and Problem Statement

The availability target applies to the **workloads**, not to the control layer.
The riskiest components of this system are precisely the newly built ones: the
Raft control plane (ADR-0005) and the SPIFFE CA (ADR-0006). If workload
availability were coupled to the availability of those components, the
availability target would be tied to the least mature part of the system — a
sure way to miss 5-9.

What has to be decided is the fundamental reliability model that binds all
runtime ADRs (0006, 0007, 0010, 0011).

## Decision Drivers

- Workload availability 4-9/5-9; the control plane must **not** be a single
  point of failure for running workloads.
- DORA: operational resilience, demonstrable resilience tests, a tamper-evident
  audit trail, manageable third-party/concentration risk.
- REMIT: complete, timestamped records subject to retention.
- Deterministic behaviour under network partition (no split brain, no dangerous
  autonomous actions).

## Options Considered

- **A: the control plane in the critical path.** Workloads/proxy query the
  control plane live. Simpler, but then workload SLO = control-plane SLO.
  Rejected.
- **B: static stability.** Agents are locally authoritative from a persisted
  desired-state cache. The control plane only changes *desired state*; it does
  **not** keep the running state alive. The data plane (running containers plus
  mTLS) survives a complete control-plane outage. SVIDs and policy are cached
  locally with a soft-fail window.
- **C: a hybrid** with individual live-dependent operations — admissible only
  where quorum is mandatory (see below).

## Decision

Chosen: **Option B (static stability), with tightly circumscribed C exceptions.**

**SLO decoupling**
- Workload availability target: 4-9/5-9.
- Control-plane availability target: **deliberately lower** (e.g. 3-9/4-9) and
  decoupled. A control-plane outage is a *change freeze*, not an outage.

**Fail-static principles (the data plane)**
- Running containers are **never** stopped because quorum or the control plane
  was lost. No dead-man switch on liveness.
- `tg-agent` reconciles exclusively against its **persisted local desired-state
  cache**, without control-plane reachability.
- No control-plane call on the hot path of workload communication.

**The autonomy boundary under partition (the C exceptions)**
- The agent **preserves** existing workloads and restarts crashed instances per
  the local desired state.
- The agent makes **no** new placement decisions and no cluster-wide mutations
  without quorum (that stays leader/Raft-bound, ADR-0005) → this prevents
  split-brain scheduling.

**Identity & policy under outage (binds 0006/0007)**
- The SVID TTL plus rotation lead time are dimensioned to exceed the expected
  control-plane recovery by a clear margin; a **soft-fail grace period** so that
  a late rotation does not tear existing connections. Hard expiry stays enforced
  as the security floor.
- From this follows a hard operational rule: **CA availability must exceed the
  rotation cadence** (feeds into the PKI/CA ADR, proposed).
- The mTLS authorization policy is cached locally and enforced locally; updates
  are best-effort pushes.

**Audit & retention (binds compliance)**
- The **Raft log is the append-only, ordered, replicated record of decisions** →
  designated as the tamper-evident audit substrate. Retention per REMIT/DORA.
  SurrealDB is the queryable projection, **not** the audit truth. Details in the
  audit/retention ADR (proposed).

**Evidence (binds DORA testing)**
- Consensus (0005) and failover are validated by **deterministic simulation
  testing** (partition, clock skew, node loss, message reorder). The DST runs
  serve double duty as evidence for the DORA resilience tests.

**Blast radius**
- Quorum members **and** workloads are spread across independent failure domains
  (on-prem: rooms/racks/power/network). Anti-affinity is a first-class
  constraint in the scheduler (ADR-0011). Details in the failure-domain ADR
  (proposed).

## Consequences

**Positive**
- Workload availability is decoupled from the riskiest (newly built) component.
- Partition-safe without split brain.
- The audit substrate and the resilience test evidence fall out as a by-product →
  compliance becomes structural rather than retrofitted.

**Negative / Costs**
- Agents need **durable local state** and clean cache-staleness semantics
  ("desired state changed but the control plane is unreachable" = a window).
- SVID soft-fail is a deliberately dimensioned security/availability trade-off.
- A higher testing burden (DST) — which, however, amortizes as compliance evidence.

**Risks & Open Points**
- ~~The size of the SVID soft-fail window: too large = weakened security, too
  small = an availability risk. Must be quantified and justified.~~ — **done:**
  ADR-0014 — 2 min; the **evidence** stands as a point of its own.
- ~~Protecting the local desired-state cache against tampering.~~ — **decided:
  ADR-0115.** Measured, the question was beside the point: against tampering the
  **umask** was doing the work (unwritten and unguarded), and against **reading**
  nothing was — every local user read the desired state, the edges, the egress
  permissions, the peers and the address plan.
- ~~Nail down the exact list of "autonomously permitted" vs. "quorum-obliged"
  agent actions (feeds into ADR-0010).~~ — **done:** ADR-0010 section 3,
  supplemented by ADR-0058 and ADR-0061.

## Related ADRs

- Binds: ADR-0006, ADR-0007, ADR-0010, ADR-0011.
- Tightens: ADR-0005 (DST as an obligation).
- Opens: the audit/retention ADR, the failure-domain ADR, the data-plane runtime
  ADR, the time-source ADR (all proposed).
