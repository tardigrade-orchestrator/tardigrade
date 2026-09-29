# ADR-0047: Reserved capacity — a reserve for the outage, not for the standby

- **Status:** accepted
- **Date:** 2026-08-24
- **Deciders:** Core team
- **Technical context:** `tg-model` (`placement`), `tg-consensus` (the command
  set), ADR-0011, ADR-0010, ADR-0034

## Context and Problem Statement

ADR-0011 leaves one point open: *"reserved capacity for warm standbys"*. It has
stood there since adoption and is one of the last three from phase 6.

## The finding that shifts the question

**Warm-standby placement is built, and the capacity for it is long since bound.**
Checked:

- A warm standby with us is a **running** instance. ADR-0010 says so explicitly
  as a cost item: *"A warm standby costs double the resources for single-writer
  workloads."*
- It arises through `replicas` and `spread`. The hard anti-affinity from ADR-0011
  — *"a standby must lie in a different failure domain than its primary"* — is
  exactly what `spread` enforces with the default `rack` (ADR-0034).
- A running instance is placed, and a placed instance **consumes** capacity in
  the scheduler. There is nothing additional to reserve.

What ADR-0011 notes as a cost item — *"a warm standby ties up reserved capacity
in another domain"* — therefore describes an effect that already occurs. The open
point is thus not what its name says.

**What really is missing is the reserve for the outage.** If a failure domain
fails, the scheduler carries its instances elsewhere — evidenced by
`losing_a_rack_keeps_the_survivor_and_replaces_the_lost_instance`. Whether there
is *room* there nobody checks beforehand. If there is none, the instances stay
unplaced and the scheduler reports `NoRoom`: **at the moment of the outage**,
i.e. exactly when the report is of no more use.

A second finding belongs with it, because it puts the urgency in perspective:
**losing a domain costs more than its share.** Because of anti-affinity the
instances of a workload lie in different domains; after one of them fails the
survivors not only have to take on the load but have to do it **without** the
lost domain as a target — the spread target shrinks with it.

## Decision Drivers

- **ADR-0011: "predictability > packing density".** A reserve one computes has to
  be explainable.
- **ADR-0011: no opaque scoring**, the selection rule is "explainable in one
  sentence". What arises here must not soften that.
- **ADR-0034: a generic resource map.** What belongs to capacity belongs in the
  same map — otherwise the `device` type from ADR-0028 will not fit later.
- **The report has to come before the outage.** A capacity statement one reads
  only during the incident is none.

## Options Considered

- **A — nothing.** Capacity planning stays operational work outside the system;
  the scheduler reports `NoRoom` when the time comes.
- **B — a reserve per node.** Part of the capacity is not there for the
  scheduler: `schedulable = capacity − reserved`.
- **C — a domain reserve, computed.** The scheduler ensures that the surviving
  domains could absorb the largest domain (N+1 across domains).
- **D — the reserve as a declared dummy workload.** An operator declares
  workloads that demand resources and never start.

### Why not C

It is the answer that really answers the question, and it costs the scheduler its
explainability. "Least occupied first, ties broken by the alphabetically first
name" would become "least occupied first, provided everything would still fit
after a simulated domain removal". That is no longer a sentence but a procedure,
and ADR-0011 decided against exactly that kind of procedure.

On top of that, the simulation requires a **choice** nobody has made: which
domain fails? The largest? Each one individually? Two? Without that input it
computes something nobody ordered.

### Why not D

It needs no new mechanism, and that is its only merit. A reserve that appears as
a workload turns up in the projection, in the dependency graph, in service
discovery and in the audit trail — everywhere as what it is not. An operator
reading the workload list reads an untruth.

### Why not A

Defensible as long as somebody keeps the account outside. The objection is not
that it would be wrong but that it is **invisible**: nothing in the system says
whether the account works out, and the first hint of it is an incident.

## Decision

Chosen: **Option B**, and the question of *sufficiency* is explicitly **not**
answered by the scheduler but reported.

### 1. A node carries a reserve in the same resource map

`UpsertNode` gains a `reserved` next to `capacity` — the same generic map
(ADR-0034), so that the `device` type from ADR-0028 fits without a rebuild. The
scheduler computes with `capacity − reserved`; below zero it clamps to zero
instead of underflowing.

That is a **setting** and not a computation: an operator decrees how much air
remains. That makes it explainable, auditable (it stands in the log, ADR-0020)
and predictable — the three properties for whose sake ADR-0011 forgoes packing
density.

### 2. The reserve is not bound to the standby

It belongs to the **node**, not to a workload. A warm standby is a running
instance and consumes its place itself; what is reserved is air for what is **not
yet** there. Binding the reserve to a workload would mean counting it twice.

### 3. Whether the reserve suffices is said by a metric — not by the scheduler

The scheduler stays what it is: `state → commands`, a pure function with a rule
in one sentence. The question "does the cluster survive the loss of this domain?"
is answered **next to** it, as a metric per failure domain (ADR-0015): how much
free capacity lies outside a domain, compared with what runs inside it.

That is this ADR's decisive separation. A metric may compute what a scheduler
should not: it **decides nothing**, it shows. If it gets tight, an operational
rule set alarms (phase 11b names exactly that as open) — and **before** the
outage.

### 4. What does not happen: automatic clearing

If the reserve is undercut, nobody moves anything. ADR-0011 says "no
auto-rebalancing", and the way to empty a node is built and is called `drain`
(phase 6). A reserve that makes room by itself would be auto-rebalancing under a
different name.

An existing placement is therefore **not** displaced by a subsequently raised
reserve; it acts on what is placed next. Anything else would mean that a number
in a configuration halts a running container.

## Consequences

**Positive**
- The reserve is a declared setting: visible, in the log, without simulation.
- The scheduler keeps its one-sentence rule and its purity.
- The question "is it enough?" gets an answer **before** the incident instead of
  an error message in the middle of it.

**Negative / Costs**
- **A human still keeps the account.** The system says how things stand; how much
  reserve is right it does not say. That is option A with a metric — and the
  difference is exactly the metric.
- One more field in the command set and in the state.
- Reserve and capacity come from the same hand, and whoever maintains only one of
  them has a number that no longer holds. It shares that with `capacity` (the
  open point from ADR-0034: who reports the capacity).

**Risks & Open Points**
- ~~**The per-domain metric is to be built**, together with the question of which
  outages it computes through (one domain? two?). This decision fixes that it
  **reports** and does not decide — what exactly it reports belongs to the
  implementation.~~ — **done:** built — `docs/alerts.yml`, rules
  `TardigradeReserveRunningOut` and `TardigradeDomainNotAbsorbable`.
- ~~**An alerting rule set is missing** (the open point from phase 11b). Without
  it the metric is queryable and not reported.~~ **It exists** (`docs/alerts.yml`,
  `1f74e17`): **direction** and **`for:` duration** stand in it, because both
  follow from the ADRs or from this system's cadences. What stays open are the
  **thresholds** — they belong to operations, because they differ per
  installation. The same sentence "it is missing" has stood in nine places in
  this tree; this is the last.
- ~~Who writes the reserve shares the open spot with `capacity`.~~ — **done:**
  ADR-0049 (the leader writes) and ADR-0105 (who may decree).

## Related ADRs

- Depends on: ADR-0011 (scheduler, failure domains), ADR-0034 (the resource map),
  ADR-0010 (the warm standby as a running instance)
- Affects: ADR-0011 — the open point "reserved capacity for warm standbys" is
  thereby answered, and differently than its name suggests; ADR-0015 (a metric is
  added)
