# ADR-0005: Cluster Consensus, Leader Election and HA

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

The "clustering/HA-capable" requirement needs a primitive for: (1) exactly one
scheduler leader at a time (avoiding split brain), (2) replicated, linearizable
cluster state (what runs where, leases, assignments), (3) surviving node
outages without losing control-plane state.

From ADR-0004: SurrealDB OSS is single-node and does **not** supply this
primitive. So a consensus layer of our own is needed — in pure Rust.

## Decision Drivers

- Pure Rust, no external daemon (no etcd/Consul as a foreign process would be
  ideal, since both are Go and contradict the "self-contained" claim).
- Linearizable state plus reliable leader election with fencing.
- Operable on 3/5 control-plane nodes (Raft quorum).
- Regulated context (REMIT/DORA, 4-9/5-9): correctness must be **demonstrably**
  tested (deterministic simulation testing) — the test evidence also serves the
  DORA resilience-testing obligation. See ADR-0019.

## Options Considered

- **A: embed `openraft`.** A pure async-Rust Raft implementation. The control
  plane becomes the consensus cluster itself; the state machine replicates
  desired and critical actual state; leader election comes for free. SurrealDB
  is materialized per node from the Raft log (ADR-0004 option B).
- **B: embed `raft-rs` (TiKV).** A proven Raft core (consensus only, no
  storage/transport) — more to build around it than with openraft.
- **C: SurrealDS (enterprise) as a consistent backend.** No Raft of our own, but
  a licence plus a Kubernetes binding; leader election/leases would still have
  to be modelled on top (SurrealDS is storage consensus, not a coordination
  service).
- **D: an external coordination service (etcd).** Mature, but a foreign Go
  daemon → breaks "pure Rust / self-contained".

## Decision

Chosen: **Option A — embed `openraft`.**

Grounds for exclusion (the project's hard guard rails):
- **Option C (etcd) rejected:** an external Go daemon — unacceptable ("no Go").
- **Option B (SurrealDS enterprise) rejected:** bound to Kubernetes and requiring
  a licence — unacceptable ("no Kubernetes").
- **Option D (raft-rs)** remains a technical fallback should `openraft` show
  limits in operation; openraft is preferred for its higher level of abstraction
  (storage/network as traits, less to build ourselves).

Therefore:
- The control plane (`tgd`) is itself the Raft cluster (size fixed in ADR-0031:
  five nodes, quorum three).
- The Raft state machine is the **truth** for critical actual/cluster state
  (leader, leases, assignments, membership).
- SurrealDB is, per node, the **deterministically materialized**,
  graph-queryable projection of the Raft log (ADR-0004, option B) — not the
  consensus backend.

The main remaining risk: Raft operational details (snapshots, membership
changes, log compaction, restore) are our own responsibility — the single
largest risk item in the project. Countermeasure: test the storage/network
trait implementations early and in isolation (property/Jepsen-style fault
injection), before scheduler and reconciler build on them.

## Consequences

**Positive**
- One primitive covers election plus state replication.
- No foreign daemons, no Go, no Kubernetes; deployment stays
  "tgd/tg-agent/tgctl plus an embedded SurrealDB per node".

**Negative / Costs**
- Raft operational details (membership, snapshotting) are our own responsibility.
- Two state representations (Raft SM ↔ SurrealDB projection) have to stay
  deterministically in sync.

**Risks & Open Points**
- ~~Check the maturity/version of `openraft`; plan the storage and network trait impls.~~
  **Decided in ADR-0032:** 0.9.25, log on `redb`, our own bus for the DST.
- ~~Decide: what exactly goes into the Raft log vs. what may run async?~~
  **Decided in ADR-0004** (the desired/actual boundary); the concrete command
  set emerges in phase 5a.
- ~~Fix the number of control-plane nodes (3 vs. 5) and the quorum policy.~~
  **Decided in ADR-0031:** five nodes, quorum three.

## Related ADRs

- Tightly coupled with: ADR-0004.
- Blocks: the scheduler ADR (proposed), the reconciliation ADR (proposed).
