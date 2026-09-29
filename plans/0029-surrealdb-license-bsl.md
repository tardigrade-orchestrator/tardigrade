# ADR-0029: SurrealDB under BSL 1.1 — accepting the licence

- **Status:** superseded by ADR-0030
- **Date:** 2026-08-20
- **Deciders:** Core team
- **Technical context:** `tg-store`, `deny.toml`
- **Supplements:** ADR-0004 (the role of SurrealDB), ADR-0023 (supply-chain governance)

> **Moot since ADR-0030.** With SurrealDB removed, the BSL acceptance falls away
> together with the seven licence exceptions in `deny.toml`. This ADR remains as
> decision history: it documents *why* the licence question arose at all, and it
> was one of the triggers for ADR-0030.

## Context and Problem Statement

While implementing phase 4, `cargo deny check licenses` failed on SurrealDB:

```
error[unlicensed]: surrealdb = 3.2.4 is unlicensed
error[unlicensed]: surrealdb-core = 3.2.4 is unlicensed
error[unlicensed]: surrealdb-types = 3.2.4 is unlicensed
error[unlicensed]: surrealdb-types-derive = 3.2.4 is unlicensed
error[unlicensed]: surrealdb-strand = 3.2.4 is unlicensed
error[unlicensed]: surrealdb-collections = 3.2.4 is unlicensed
```

A seventh, `surrealdb-protocol`, declares `license = "BUSL-1.1"` properly and is
therefore not reported as unlicensed but simply rejected. `surrealkv` (the
storage engine) is unremarkable.

The cause is two-stage. First, the six crates named above carry **no** `license`
field in their manifest at all — they ship only a licence file, which is why
cargo-deny cannot derive an SPDX expression and treats them as unlicensed.
Second, the licence behind it is the **Business Source License 1.1**:

| Parameter | Value |
|-----------|-------|
| Licensor | SurrealDB Ltd. |
| Additional Use Grant | use permitted, **not** as a "Database Service" for third parties |
| Change Date | 2030-01-01 |

BSL 1.1 is **source-available, not open source**. ADR-0004 describes SurrealDB
as an "OSS single binary per control-plane node". The "no enterprise obligation"
part is accurate, the label "OSS" is not — that is corrected here, without
touching the decision itself.

## Decision Drivers

- ADR-0023 requires a licence compliance check; letting a gate error through
  would be the opposite of that.
- DORA: a licence with usage restrictions and a conversion date is a third-party
  governance item with a review date, not a build setting.
- "Config storage in a graph DB (SurrealDB)" is a **product guard rail**, not
  merely an ADR decision — a switch would not be up for debate.
- The decision history should carry the acceptance, not a comment in `deny.toml`.

## Options Considered

- **A: accept the licence, narrowly bounded and documented.** An exception only
  for the six SurrealDB crates, with a justified review date.
- **B: an exception in `deny.toml` only.** Faster, but then the acceptance would
  live in a build configuration instead of in the decision history.
- **C: allow the licence globally.** `BUSL-1.1` into the allowlist — this would
  silently let future BSL dependencies through.
- **D: switch stores.** Contradicts the product guard rail.

## Decision

Chosen: **Option A.**

1. **Usage assessment.** Tardigrade embeds SurrealDB as a **projection** in its
   own control plane (ADR-0004: Raft is the truth, SurrealDB the materialized,
   graph-queryable view). No database function is offered to third parties, no
   capability is granted to create or manage schemas or tables. The Additional
   Use Grant covers this use.
2. **A narrowly bounded exception.** In `deny.toml` the six crates without a
   licence field get the expression `BUSL-1.1` through `[[licenses.clarify]]`;
   all seven receive permission by name through `[[licenses.exceptions]]`.
   `BUSL-1.1` does **not** move into the global allowlist — a future BSL
   dependency should stand out again.
3. **Review date.** To be checked at every SurrealDB major, and at the latest
   before the **Change Date 2030-01-01**, from which the licence converts to an
   open one. If SurrealDB Ltd. changes the Additional Use Grant, this decision
   has to be taken anew.
4. **A correction to ADR-0004.** SurrealDB is source-available under BSL 1.1, not
   OSS. The role decision from ADR-0004 is untouched.

## Consequences

**Positive**
- The licence gate stays sharp: no softened allowlist entry, only a named
  exception with a rationale and an expiry horizon.
- The acceptance is auditable — exactly what ADR-0023 requires for DORA.

**Negative / Costs**
- A non-open licence on the product path, with the residual risk that the
  licensor changes the terms before the Change Date.
- Maintenance effort: the exception has to be re-checked on every SurrealDB
  update, because it hangs on crate names, not on versions.

**Risks & Open Points**
- ~~Whether a legal/compliance review confirms the assessment under point 1 is
  **not** decided here — this ADR records the technical assessment, not a legal
  opinion.~~ — **done:** moot — ADR-0029 is `superseded by 0030`.
- ~~If the assessment comes out differently, it collides with the product guard
  rail "graph DB (SurrealDB)" and forces a fundamental decision.~~ — **done:**
  moot — ADR-0029 is `superseded by 0030`.

## Related ADRs

- Supplements: ADR-0004 (the role and deployment of SurrealDB), ADR-0023
  (licence compliance, concentration risk).
- Related to: ADR-0026 (precedent: a supply-chain finding in the gate instead of
  a waiver).
