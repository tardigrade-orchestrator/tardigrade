# ADR-0032: Consensus implementation — version, log storage, simulation approach

- **Status:** accepted
- **Date:** 2026-08-21
- **Deciders:** Core team
- **Technical context:** `tg-consensus`, `tests/dst/`
- **Closes the remaining open points from:** ADR-0005

## Context and Problem Statement

ADR-0005 chose `openraft` and left three points open: "check the
maturity/version of `openraft`; plan the storage and network trait impls", plus
the question of what exactly belongs in the Raft log. ADR-0031 settled the
cluster size, ADR-0004 the desired/actual boundary. What remains are three
implementation questions that phase 5 cannot leave open.

ADR-0005 itself calls the Raft operational details "the single largest risk item
in the project" and requires the trait implementations to be tested **early and
in isolation**, before the scheduler and reconciler build on them. That shapes
not only the tool choice but the order of the work.

## Decisions

### 1. `openraft` 0.9.25, not the 0.10 alpha

| Line | State | Downloads per release |
|------|-------|-----------------------|
| 0.9.25 | 2026-07-28 | ~48,000 |
| 0.10.0-alpha.34 | 2026-08-14 | ~77 |

The 0.9 line is **still maintained** — 0.9.25 is three weeks old. An alpha in
the consensus core of a REMIT/DORA-regulated system would be hard to justify,
and 34 alphas suggest a still-moving surface.

The trait surface of 0.9 is therefore fixed: **`RaftLogStorage`** and
**`RaftStateMachine`** (the combined `RaftStorage` is deprecated there), plus
**`RaftNetwork`** with a separate **`RaftNetworkFactory`**.

**Cost:** moving to 0.10 will later be a migration. It is foreseeable and
deliberately accepted; the timing is to be chosen once 0.10 is stable and the
DST suite from phase 5 can back the migration.

### 2. The Raft log on `redb`

The Raft log is **not** the projection. It is the truth (ADR-0005) and at the
same time the tamper-evident audit substrate (ADR-0020) — it has to be durable.

That makes the reservation from ADR-0030 apply verbatim: "Should persistence
become necessary after all, `redb` (3 crates) is to be taken — a proven engine.
**Do not write our own.**" Here the case has arisen.

`redb`: 3 crates, MIT/Apache-2.0, actively maintained. Our own segment files are
explicitly rejected — a crash-safe on-disk format is exactly the kind of problem
one does not solve in passing, and a corrupted Raft log is not recoverable.

### 3. Our own message bus for the DST, no simulation framework

`turmoil` (Tokio's own framework) and `madsim` were considered.

Chosen: **our own in-process bus** that implements `RaftNetwork` and makes
partition, delay, reordering and loss injectable.

Rationale: we have to implement `RaftNetwork` anyway. A simulation framework
simulates the **network layer beneath it** — which does not exist in the DST at
all, because there all nodes run in one process. The bus is small, brings no
dependency, and controls exactly the level at which the faults are to be
injected.

Determinism through seeded randomness and controlled time; a seed reproduces a
run completely. That is not convenience but the requirement from ADR-0020: DST
runs are exportable evidence for the DORA resilience-testing obligation and must
be reproducible.

## Consequences

**Positive**
- No alpha in the consensus core; the supply chain grows by exactly 3 crates.
- The DST harness hangs on no foreign framework and can inject faults exactly
  where `openraft` hands the messages over.
- Reproducible runs as a compliance artefact.

**Negative / Costs**
- A foreseeable migration to `openraft` 0.10.
- The bus is home-grown and has to be correct itself — it is tested along the
  way, but a bug in it fakes correctness. Countermeasure: the bus gets its own
  tests against its *expected* misbehaviour (does it really lose messages when
  it should?).

**Risks & Open Points**
- ~~Simulating clock skew deterministically requires control over the time
  `openraft` sees. Whether `tokio::time::pause` suffices or a time source has to
  be injected is to be clarified in 5b.~~
  **Answered in ADR-0033:** `tokio::time::pause` suffices for time, but not for
  skew — the virtual clock is global. Skew is simulated where ADR-0024 locates
  it: in the traceable UTC that travels in the command. ADR-0033 additionally
  records two findings from 5b that reach beyond the harness (unseeded election
  randomness; `heartbeat_interval` as the RPC timeout of replication).
- ~~The exact log command set (what is an entry?) emerges in 5a along the
  boundary from ADR-0004.~~ **Done in phase 5a:** thirteen commands in two
  layers — the file lay in `tg-consensus` then and has been
  `crates/tg-model/src/command.rs` since ADR-0135.

## Related ADRs

- Closes the remaining open points from: ADR-0005.
- Applies: ADR-0030 (`redb` as the answer when persistence becomes necessary).
- Serves: ADR-0020 (reproducible DST runs as evidence), ADR-0031 (cluster size
  five in the DST scenarios), ADR-0024 (the time source).
