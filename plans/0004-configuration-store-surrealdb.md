# ADR-0004: Configuration Store on SurrealDB (Role & Limits)

- **Status:** accepted — Option B, fixed by ADR-0005 (openraft)
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

SurrealDB is set as the config/graph store. It is multi-model (document +
graph), a single Rust binary, with ACID (snapshot isolation, immediate
consistency after commit) and LIVE queries (change feeds). The graph part fits
the systemd-style dependencies (ADR-0009) excellently.

**But:** the HA research shows a hard limit. Distributed HA exists only through
**SurrealDS** (enterprise/cloud, bound to K8s, quorum consensus over object
storage). The open-source single binary with RocksDB/SurrealKV is
**single-node**. SurrealDB is therefore a very good *state/config store*, but
**not** a control-plane consensus primitive (no linearizable leases, no watch
with fencing the way etcd has it). That role is deliberately separated
(ADR-0005).

## Decision Drivers

- Requirement: config in a graph DB (SurrealDB).
- Requirement: cluster/HA (in tension with the OSS single-node reality).
- A dependency definition is a graph by nature → this is where SurrealDB plays to its strength.

## Options Considered (SurrealDB's role only; consensus in ADR-0005)

- **A: SurrealDB = the sole truth store, cluster state included.**
  Requires SurrealDS (enterprise) for HA — licence plus K8s. Or single-node = SPOF.
- **B: A two-layer model.**
  SurrealDB = *desired state* (definitions, dependency graph, policies,
  topology). *Runtime/cluster state* (leader, leases, assignments, health)
  lives in the replicated, consented layer from ADR-0005. The reconciler
  materializes desired → actual.
- **C: SurrealDB as cache/read model only,** the truth in the consensus log —
  SurrealDB as a projected view for queries and graph traversal.

## Decision

Chosen: **Option B.** (With the openraft decision in ADR-0005 this is no longer
an option but settled: Raft is the truth, SurrealDB the per-node materialized,
graph-queryable projection.)

- **SurrealDB (desired state):** workload definitions, dependency graph
  (`RELATE` edges), trust-domain/policy config, desired topology.
  Used: graph `RELATE`, `SELECT ... FETCH`, LIVE queries for UI/watches.
- **Consensus layer (actual/cluster state):** see ADR-0005.
- **SurrealDB deployment:** the OSS single binary per control-plane node, its
  content filled deterministically from the replicated desired state
  (ADR-0005) — i.e. SurrealDB is reproducible per node and **not** itself the
  consensus backend. (SurrealDS remains documented as a "buy" option should
  enterprise/K8s become acceptable.)

### The desired/actual boundary (decided)

The pattern: **read-eventual, write-linearizable.** The reconciler (ADR-0010)
reads desired from the projection and actual from the eventual status, and
writes its decisions back through the Raft log.

**Raft log** (authoritative, linearizable, audit substrate, ADR-0005/0020):
- Desired state: workload specs, dependency graph, `may_talk` authz edges (0025),
  topology.
- Consensus-critical cluster state: placement assignments, active-role leases
  plus fencing epochs (0010), membership, trust registration plus bundle (0006/0014).

**SurrealDB directly** (eventual, reported by agents):
- Observational/actual status: running/crashed, health, metrics, last seen.
  High-frequency, with no need for linearizability.

**SurrealDB as a read projection:**
- A materialized, graph-queryable view of the Raft-authoritative state → reads
  and traversals without touching Raft.

## Consequences

**Positive**
- Graph queries for dependency resolution are first class rather than hand-built.
- LIVE queries give cheap watch semantics for the UI/CLI.
- No enterprise obligation; HA comes from ADR-0005, not from SurrealDB.

**Negative / Costs**
- Two data paths (desired vs. actual) = a clear boundary is required, otherwise consistency bugs.
- The SurrealDB schema has to be derived from the XSD model (ADR-0008) → one more mapping.

**Risks & Open Points**
- ~~The exact desired/actual boundary~~ **decided** (see above). What remains:
  mapping rules XSD types → SurrealDB records, and the Raft state schema in detail.

## Related ADRs

- **Store choice superseded by ADR-0030:** SurrealDB is dropped; the projection
  lives in-process. The **two-layer model of this ADR stays valid** — Raft is
  the truth, the projection is the derived, throwaway view. It is ADR-0030 that
  makes exactly this statement literally true.
- **Historic, made moot by ADR-0030:** ADR-0029 recorded that SurrealDB is
  under BSL 1.1 and that the label "OSS single binary" above was therefore
  imprecise.

- Tightly coupled with: ADR-0005 (consensus).
- Related to: ADR-0008 (XSD→schema), ADR-0009 (dependency graph).
