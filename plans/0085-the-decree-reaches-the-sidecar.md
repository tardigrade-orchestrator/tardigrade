# ADR-0085: The decree reaches the sidecar

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-runtime::reconcile`, `tg-agent::session`, ADR-0059,
  ADR-0066, ADR-0070, ADR-0071

## Context and Problem Statement

**ADR-0071** built the trigger for a changed declaration: a **generation** per
workload and instance, monotonic, named by the operator. The reconciler restarts an
instance when the decreed generation lies above the one its bundle was built with.

**ADR-0059** decided that the sidecar is derived on the **node** and stands in no log.
Together the two produce a gap nobody decided:

```text
api generation:       7
api-proxy generation: 0
```

Measured against a `DesiredState` in which generation 7 is decreed for `api`: for the
derived sidecar `generation` returns **zero**, and forever. The generations come from
`slice.instances` (ADR-0040), and a derived sidecar is never there.

> **`tgctl cluster restart api` restarts `api` and leaves `api-proxy` standing.**

### Why that is more than an incompleteness

The derived command line hangs on the workload's declaration. The heaviest is the
**class**: `mesh::build` appends `--single-writer` exactly when the workload carries
`class="single-writer"` (evidenced by a test with a counter-check).

If an operator changes the class from `replicated` to `single-writer` and decrees a
restart, then `api` runs as a single writer from that moment — and its sidecar does
**not** bridle it, because it lacks `--single-writer`. The enforcement from ADR-0066
does not bite, and nobody sees it: the workload runs, the mesh carries, the active-role
lease is granted and is without effect.

The same gap, milder, for the other statements of the derived line: a changed
`--proxy-image` (ADR-0059) and a changed `<mesh port>` never reach a running sidecar.

## Decision Drivers

- **ADR-0066** is a security promise; it must not depend on somebody ending a
  container by hand.
- **ADR-0071, determination 1:** the trigger is a **human's decree**. That should stay.
- **ADR-0070:** no autonomous restart merely because a declaration has changed.
- **ADR-0059:** the sidecar exists **only** for its workload; it shares namespace,
  address and placement with it.

## Options Considered

- **Option A — the sidecar inherits its principal's generation.** A decree for `api`
  restarts `api` and `api-proxy`.
- **Option B — the sidecar restarts when its own declaration has changed** (the digest
  from ADR-0070).
- **Option C — a decree of its own for the sidecar**, i.e. `RestartWorkload` on a name
  that stands in no log.

## Decision

Chosen: **Option A.**

### Determination 1 — the principal's generation applies to the sidecar

The reconciler reads the generation under the **principal's** name when there is one.
That makes `tgctl cluster restart api` mean what an operator means: the unit `api`
together with what the node derives for it.

The generations are available per instance, and the sidecar shares its principal's
instance numbers (ADR-0059) — so the association is well defined and requires no second
source.

### Determination 2 — option B is rejected, and from ADR-0070

It would be an **autonomous** restart: the declaration changes and the node acts.
Precisely that ADR-0070 rejected — *"a number in the XML would be a restart trigger"* —
and for the sidecar it holds just as much: a changed `--proxy-image` on a node would
otherwise restart every sidecar there without anybody having decreed it.

The price stands with it: a change that concerns **only** the sidecar still needs a
decree for its workload. That is no restriction but the same action — there is no
reason to restart the sidecar without its workload.

### Determination 3 — option C is rejected

A decree on `api-proxy` would be a `RestartWorkload` on a name the state machine does
not know (ADR-0059: the sidecar arises on the node). It would be refused as an
"unknown workload" — or one would take it into the log, and then it would no longer be
a derivation.

## Consequences

**Positive**

- A class change takes full effect: the workload runs as a single writer, and its
  sidecar bridles it (ADR-0066).
- A change of proxy image or mesh port becomes executable — with the same decree an
  operator works with anyway.
- The staleness from ADR-0070 becomes manageable for the sidecar: it was visible and
  not remediable.

**Negative / Costs**

- **A decree's blast radius grows by the sidecar.** That is intended and still a
  behavioural change: from here on `tgctl cluster restart api` also tears the mTLS
  connections running through its sidecar. The sidecar is drained, not torn down
  (ADR-0058, SIGTERM and drain).
- A sidecar whose bundle stems from an older generation restarts **once** on the next
  pass once this change is shipped — provided a generation was ever decreed for its
  workload.

**Risks & Open Points**

- **A change only to the sidecar stays without a trigger of its own** (determination
  2). Whoever changes `--proxy-image` on a node has to decree a generation for every
  mesh workload — the same "action per node" ADR-0059 already accepts.
- ~~**Changing a running workload's class stays delicate**: between the upsert and the
  decree it runs as a single writer without a bridle. Whether ingest should permit a
  class change at all is not decided.~~ — **decided: ADR-0117.** Ingest refuses it as
  long as the workload is **placed**. Measured, it came through in both directions,
  and immediately afterwards the cluster granted an active-role lease that the running
  sidecar did not enforce — with green indicators.

## Related ADRs

- Depends on: ADR-0059 (the derivation), ADR-0071 (the generation), ADR-0066 (what
  hangs on it)
- Affects: ADR-0070 (the sidecar's staleness becomes remediable)
- Supplemented by: **ADR-0117** (the class change this ADR left open)
