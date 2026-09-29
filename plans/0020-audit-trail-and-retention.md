# ADR-0020: Audit Trail & Data Retention

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

REMIT/DORA demand tamper-evident, retention-obliged evidence of what the system
has decided. That role was already assigned to the Raft log in
ADR-0019/0005/0004; here it is formalized.

## Decision

- **The Raft log is the append-only, ordered, replicated audit substrate.**
  Every control-plane mutation (placement, lease/epoch, membership, trust
  registration, `may_talk` edges, secret access policy, hardening relaxations)
  is an audit event.
- **SurrealDB is the queryable projection, not the audit truth.**
- **Retention** per REMIT/DORA deadlines; the log is periodically exported to a
  WORM-capable long-term archive (snapshot plus log segments) before compaction
  bites.
- **Timestamps** traceable to the reference time (ADR-0024).
- **Access/enforcement decisions** in the data plane (allow/deny, sampled) are
  additionally kept as audit events (ADR-0025).

## Consequences

**Positive**
- The audit trail falls out structurally (no retrofitted bolt-on).
- Tamper evidence through the ordered, replicated nature of the log.

**Negative / Costs**
- Long-term export before compaction is an operational process.
- The retention volume can become large → an archive strategy is needed.

**Risks & Open Points**
- Concrete retention periods per event type (compliance input).
- ~~The WORM archive target and the integrity proof (a signature/hash chain over
  the segments).~~ — **done:** the integrity proof in 11a/ADR-0045 — the
  **archive target** stands as a point of its own.

## Related ADRs

- Substrate: ADR-0005 (Raft), ADR-0004 (the projection). Time: ADR-0024.
- Event sources: ADR-0010/0011/0014/0016/0017/0025.
