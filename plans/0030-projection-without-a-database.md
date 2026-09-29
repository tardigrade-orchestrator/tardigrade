# ADR-0030: A projection without a database — replacing SurrealDB

- **Status:** accepted — the guard rail resolved as an implementation assumption
- **Date:** 2026-08-20
- **Deciders:** Core team
- **Technical context:** `tg-store`, `tg-model`, `deny.toml`
- **Supersedes:** ADR-0004 (the store choice only; the two-layer model stands),
  ADR-0029 (thereby moot)

## Context and Problem Statement

ADR-0004 chose SurrealDB as the graph-queryable projection. Phase 4 built it —
and in doing so made three things measurable that were not on the table when the
decision was taken.

**First, the size.**

| | Crates |
|---|---|
| Workspace before phase 4 | 274 |
| Workspace after | 566 |
| **SurrealDB's share** | **292** |

SurrealDB supplies more than half the dependency tree.

**Second, the licence.** BSL 1.1, source-available rather than open source, six
crates without a `license` field, change date 2030-01-01. ADR-0029 justified
accepting it and entered seven named exceptions. Within two days an unmaintained
advisory (RUSTSEC-2025-0141, `bincode`) arrived from the same subtree — with no
fix, outside our reach.

**Third, and decisively: what the projection actually does.**

```
Called:    materialize(), report_actual()
Read by:   nothing
```

`workloads()`, `targets_of()` and `actual_states()` are used exclusively by
their own tests. Of 324 lines in `projection.rs`, **31** are actual database
calls; the rest is types and documentation.

At the same time `tg-model::graph` — 473 lines, **zero** dependencies, 20 tests —
already answers every graph question: topological sort, cycle checking,
cascades, conflicts. The graph is built on every reconcile anyway.

To be fair: the readers only arrive with ADR-0018 from phase 8. So the question
is not "is it used", but **whether the future readers justify 292 crates**.

## Decision Drivers

- **DORA third-party risk.** 292 crates from a single vendor under commercial
  pressure are a concentration risk that ADR-0023 is supposed to keep
  manageable. The BSL is the symptom of that pressure, not the cause.
- **Ongoing governance burden.** Every transitive advisory in a 465-crate subtree
  becomes a case with an assessment and a review date.
- **Proportionality.** The order of magnitude is hundreds to a few thousand
  workloads per cluster. That is a hashmap, not a database problem.
- **Reversibility.** Adding a database later is cheaper than removing one later.
  Today the removal costs a day; from phase 8 on, with readers, watches and
  migration paths, it costs a multiple of that.
- **Taking ADR-0004 at its word.** It says the projection holds "nothing whose
  loss hurts" and is materialized deterministically from the truth. So far that
  is an assertion — an in-memory projection makes it true.

## Options Considered

- **A: keep SurrealDB and govern it.** ADR-0029 to `accepted`, plus `cargo vet`,
  vendoring, `cargo-auditable`. Manages the risk, does not reduce it.
- **B: put the projection behind a trait.** Defers the decision to phase 8; the
  292 crates stay until then.
- **C: an in-process projection.** The graph from `tg-model`, state in a
  `BTreeMap`, watches over tokio broadcast and gRPC streams, no persistence.
- **D: another embedded store.** Measured:

  | Candidate | Crates | Licence | Assessment |
  |-----------|--------|---------|------------|
  | `redb` | 3 | MIT/Apache | KV, no graph |
  | `petgraph` | 15 | MIT/Apache | in-memory graph, no persistence |
  | `fjall` | 48 | MIT/Apache | LSM KV |
  | `indradb` | 52 | MPL-2.0 | a real graph, but a tiny project |
  | `oxigraph` | 90 | MIT/Apache | RDF/SPARQL — a conceptual break |
  | `cozo` | — | MPL-2.0 | no release since Dec. 2023 |
  | *surrealdb* | *465* | *BSL 1.1* | |

## Decision

Chosen: **Option C**, with an explicit limit.

**We build the query logic, not the storage engine.** That is the difference
between proportionate and the classic "not invented here" mistake. Traversing a
`BTreeMap` is trivial; writing a crash-safe on-disk format is not — and we need
none:

1. **Desired state** is materialized from the Raft log (ADR-0004), or until phase
   5 from the local cache (ADR-0019). Both sources are durable.
2. **Actual state** is reported by the agents. It is volatile by nature and
   re-observable at any time — losing it costs one reconcile cycle.

The projection therefore lives **in memory** and is rebuilt at startup.

Should persistence become necessary after all, `redb` (3 crates) is to be taken —
a proven engine. **Do not write our own.**

Replacements for what goes away:

| before | henceforth |
|--------|-----------|
| graph traversal by `RELATE` | `tg-model::DependencyGraph`, already present |
| structured queries | gRPC methods (ADR-0018) |
| LIVE queries | tokio broadcast plus gRPC server streams (ADR-0002 chose tonic for exactly this) |
| ad-hoc SurrealQL | **dropped outright** |

## On the product guard rail — decided

The README listed as a requirement "config storage in a graph DB (SurrealDB)".
This ADR contradicted it.

The core team decided: **naming SurrealDB was an implementation assumption, not
a product requirement.** What the guard rail actually meant — dependencies are a
graph and are modelled as a graph — remains in force and is satisfied in
`tg-model`.

That agrees with the finding that **ADR-0004 had already left the literal
reading anyway**: there the config lives in the Raft log, SurrealDB was only the
projection. The contradiction has existed since ADR-0004, unnoticed until now.

The guard rail in `README.md` is reworded accordingly.

## Consequences

**Positive**
- The dependency tree goes from 566 to roughly 280 crates; no BSL, no named
  licence exceptions, no `bincode` advisory.
- ADR-0004's core statement — Raft is the truth, the projection is disposable —
  becomes literally true instead of merely asserted.
- One less read path that bypasses authorization and audit. In a REMIT/DORA
  context, free query access into the control-plane internals is more of a
  burden than a benefit (ADR-0020 wants demonstrable auditability).

**Negative / Costs**
- Ad-hoc queries go away. Every new evaluation needs a gRPC method.
- The projection is empty after a restart until it is re-materialized; a watch
  client then briefly sees no data.
- We carry the query logic ourselves — but that is 31 lines replaced by
  `BTreeMap` operations, not a database.

**Risks & Open Points**
- The scaling assumption: hundreds to a few thousand workloads. At six-figure
  numbers this would have to be reassessed — but then with `redb` as the store,
  not with an embedded database.
- Watch semantics (broadcast lag, missed events with slow clients) is to be
  clarified in phase 8, not here.
- ~~`cargo vet` as a systematic supply-chain attestation remains sensible
  independently of this decision and is not yet set up (ADR-0023).~~ —
  **decided: ADR-0134**, and with a **rejection**: `cargo vet` attests through
  people, not through tools, and for 386 crates that is a staffing question — an
  attestation nobody performs looks like a statement. What is held instead:
  `cargo deny` in the gate, `Cargo.lock` checked in, vendoring on finding
  (ADR-0026) — and from here on the **bill of materials** (`cargo xtask sbom`),
  which did not exist until then even though ADR-0023 names it as its first
  deliverable.

## Related ADRs

- Supersedes the store choice from: ADR-0004 (the two-layer model stays valid).
- Makes moot: ADR-0029 (the BSL acceptance), now `superseded`.
- Depends on: ADR-0018 (gRPC as the read path), ADR-0002 (tonic streams for
  watches), ADR-0023 (concentration risk, exit strategy).
- Precedent: ADR-0026 (a supply-chain finding in the gate instead of a waiver).
