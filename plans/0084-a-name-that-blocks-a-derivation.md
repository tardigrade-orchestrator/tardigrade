# ADR-0084: A name that blocks a derivation

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-model::mesh`, `tg-runtime::reconcile`,
  `tg-consensus::state`, `tgctl cluster apply`, ADR-0059, ADR-0062

## Context and Problem Statement

The node derives a mesh member's sidecar (ADR-0059); it is called
`<workload>-proxy`. If an operator declares a workload of their own with that name
alongside, `mesh::expand` refuses the derivation — rightly, because a written
definition must not be overwritten.

**Only what happens then is the finding.** Measured against a real `tg-agent` with
three workloads in the cache (`api` with `<mesh>`, `api-proxy`, and an uninvolved
`harmlos`):

```text
INFO  {"workloads":3,"runtime":"youki"}
ERROR "pass failed, will retry"
      error: "workload '<sidecar>' cannot be mapped: the sidecar of 'api' would be
              called 'api-proxy', and that workload already exists…"
```

**None of the three is reconciled**, `harmlos` included, and that repeats every
second. The node lives, reports, holds its socket — and does nothing: nothing is
started, nothing restarted after a crash, nothing reaped, no probe made, and **no
single writer fenced** (ADR-0064), because the pass does not get that far.

Three lines above stands the comment that names the rule for the neighbouring case:

> **An unreadable entry costs its workload, not the node** (ADR-0062).

And the documentation of `once` says: *"An error in **one** workload does not end the
pass: the others are reconciled anyway."* For this case it is not true.

**The trigger is an ordinary operator action.** The cluster accepts both workloads —
`mesh::expand` does not run in the state machine — the slice carries them, and
**every** node with `--proxy-image` set fails afterwards on every pass.

## Decision Drivers

- **ADR-0062, determination 2:** the node view **cannot fail, it isolates**. That ADR
  enumerates four cases; this one is not among them — and ADR-0046 named the
  enumeration as the cause of errors.
- **ADR-0019:** a partial failure must not be a total failure. Here a choice of name
  costs a node's whole reconciliation.
- **ADR-0064:** the self-fence is a security promise and hangs on the pass.
- **ADR-0059:** a written definition is never overwritten. That stays.
- **The log is retained** (ADR-0020): what is in it once reaches every node — including
  one that joins later.

## Options Considered

- **Option A — everything stays.** The pass fails, the operator tidies up.
- **Option B — the node isolates.** The mesh member is not reconciled, all the others
  are.
- **Option C — B, plus refusal at ingest**, so that the pair never reaches the log.
- **Option D — isolate the declared `api-proxy`** instead of the mesh member, so that
  `api` gets its sidecar.

## Decision

Chosen: **Option C.**

### Determination 1 — the node view isolates here too

`reconcile::expand` no longer returns an error when a derivation fails on a name. The
affected **mesh member** moves into `Report::isolated` and is thereby neither started
nor stopped (ADR-0062, determination 3); the other workloads go through the same pass
as always.

What is isolated is the **mesh member** and not the declared workload (option D): the
latter's definition is complete and correct in itself, while `api` demands a
derivation that cannot take place. That is no guessing as with the duplicate name in
ADR-0062 — here there is a rule, and it names the side.

The price stands with it: whoever names a workload `<x>-proxy` silences `<x>`. That is
a pitfall and not a trust boundary — both come from the same operator through the same
log — and the affected one is **named** (`tg_node_isolated_entries`,
`TardigradeBrokenDeclaration`).

### Determination 2 — the state machine refuses the pair

Like volume exclusivity (ADR-0027) and `Conflicts` (ADR-0061, determination 6): a
statement about the **set** that requires no referential integrity and is therefore
checkable there. The refusal is `UnplaceableDefinition` — the variant that already
carries this class; a new one would be a format break for a statement that is the
same.

The check is **name-based**, without `SidecarSpec`: which image a sidecar carries is a
per-node setting (ADR-0059) and is not known in consensus. That is no loss — in the
**log** a derived sidecar never stands, because it arises on the node.

### Determination 3 — and the client checks before writing for the first time

The same place and the same reason as with the cycle: *"a set with a cycle must not
reach the cluster half-way in the first place"*. An operator gets the refusal before
half of their file stands in the log.

### Determination 4 — one rule, three users

`tg_model::mesh::validate_names` carries it, and `expand` uses it too — two versions
would be two opportunities to disagree. The difference between ingest and derivation
is **one parameter**: with `SidecarSpec` an entry demonstrably our derived sidecar
does not count as a collision; without it the name alone counts.

## Consequences

**Positive**

- A name conflict costs a workload, not a node's reconciliation — and therefore no
  longer the fence, the restart and the reaping of all the others.
- The documentation of `once` is true again.
- New pairs do not reach the log; old ones are isolated instead of blocking.
- The operator learns of it when issuing and not at a node.

**Negative / Costs**

- **From here on an upsert can fail on an *other* workload.** That has held for
  volumes and `Conflicts` since ADR-0027 and ADR-0061; what is new is the reason.
- Whoever declares `<x>-proxy` while `<x>` takes part in the mesh silences `<x>` —
  visibly, but it is an effect nobody intended.
- Existing pairs in the log stay there. They are isolated and reported; tidying up is
  done by hand.

**Risks & Open Points**

- **The name is still the address and not the credential** (ADR-0036): who gets a
  delegation is decided by four conditions. This decision changes nothing about that,
  it only prevents two units from fighting over a name.
- Whether a workload whose derived name would be too long (> 63 characters, ADR-0013)
  deserves the same treatment: it gets it, because it is the same rule — but the
  operator sees only at ingest that their name is too long, although the schema
  permits it.

## Related ADRs

- Depends on: ADR-0059 (the derivation), ADR-0062 (isolate instead of fail),
  ADR-0027/ADR-0061 (the same construction at ingest)
- Affects: ADR-0062 (a fifth case of the node view)
