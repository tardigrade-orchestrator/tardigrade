# ADR-0127: How Full a Node Is

- **Status:** accepted
- **Date:** 2026-09-13
- **Concerns:** ADR-0069 (the open point), ADR-0109 (the pressure), ADR-0011
  (the planner decides, the number does not), ADR-0047 (the reserve and its
  metrics), ADR-0015 (cardinality)

## Context and Problem Statement

ADR-0069 left an open point:

> **The capacity is not a metric.** How close a cluster is to its limit is
> reported by nobody; an operator notices it from a rejection by the planner.

On inspection that is true, and the situation has the same shape as the content
store in ADR-0126: **the first signal comes when it is too late.**

- **No number about utilization exists.** `tg_cluster_ordinals_capacity` sounds
  like it but means the subnets in the cluster CIDR — how many *nodes* fit in,
  not how full they are. The metrics from ADR-0047
  (`tg_scheduler_domain_at_risk`, `…_elsewhere`) answer the **failure**
  question: is there enough if one domain drops out. Not the fill question.
- **The first signal is a rejection.** `tg_scheduler_unplaceable` jumps when a
  placement has already failed. A node at 99 % therefore reports exactly the
  same as one at 1 %: nothing.
- **And the number has long been there.** ADR-0109 introduced the **pressure**
  — `occupied / capacity` of the scarcest resource, in millionths — and
  `placement::pressure` computes it at **every** placement in order to sort
  candidates. It is computed and thrown away.

### The place at which it can go wrong

The consumption map per node arises today **twice**: in `placement::plan`
(step 2, then carried forward while placing) and in `placement::headroom`. They
are not identical — `plan` computes over the **retained** assignments and knows
the nodes, `headroom` over the ones handed to it. A metric beside them would be
the **third** derivation, and then it would say something about a cluster the
planner does not know.

Exactly this justification already stands in `schedule::inputs`: *"Two
derivations would be two opportunities to count differently — and then the
metric would say something about a cluster the planner does not know."*

## Decision Drivers

- **Information before the outage** instead of a rejection in the middle of it
  — that is verbatim the justification with which ADR-0047 got its metrics.
- **The number the planner uses**, and no second one that resembles it.
- **It decides nothing.** ADR-0011 excludes auto-rebalancing; a metric may
  compute what a planner should not, because it does nothing.
- **And it costs nothing**: the value lies in memory at the end of a planning
  run anyway.

## Options Considered

- **A — report the raw numbers** (`occupied` and `capacity` per node and
  resource). Complete, and the operator computes the pressure themselves —
  hence a fourth place at which someone forms `occupied / capacity`, possibly
  over the **raw** rather than the schedulable capacity (ADR-0047 subtracts the
  reserve).
- **B — only the pressure** per node. One number that the planner itself uses,
  and it does not say **which** resource is scarce.
- **C — both, but one number per question**: the pressure says *how full*, the
  free space per resource says *what there is still room for*.

Chosen is **C**, and both come from **one** map: the one `plan` has at the end.

## Decision

### Determination 1 — the plan carries its occupancy out

`placement::plan` returns the consumption map it keeps anyway — after the
placement, that is, the state this planning step produced.

With that the metric is **not** a derivation of its own but the same result:
what the planner considered full when it decided. A map computed beside it
would, on any divergence, be a metric about a different cluster.

`headroom` stays as it is. Merging the two is work of its own with risk of its
own, and they answer different questions.

### Determination 2 — two metrics, two questions

- **`tg_node_pressure{node}`** — the pressure from ADR-0109 as a ratio: the
  utilization of the **scarcest** resource, `0` to `1`. That is the number by
  which the planner sorts.
- **`tg_node_free{node,resource}`** — what is still free on this node, per
  resource, in the resource's unit.

The denominator in both cases is the **schedulable** capacity
(`schedulable_capacity`, that is, minus the reserve from ADR-0047) — the same
one the planner checks against. Taking the raw one would yield a number that is
smaller than the truth, and precisely in the direction that reassures.

Labels: `node` is permitted (five, ADR-0031), `resource` likewise (ADR-0034 — a
map with declared names). Both already stand in `LABELS`.

### Determination 3 — only the leader reports

As with `report_headroom` and for the same reason: only it plans, so only it
knows the state these numbers say something about. Five nodes all reporting the
same would be five sources for one fact.

### Determination 4 — it decides nothing

Nothing is moved because of it (ADR-0011, no auto-rebalancing), and no planning
step reads it. It is information **before** the `NoRoom` instead of a `NoRoom`
in the middle of it.

### Determination 5 — no alert rule, and the reason stands beside it

As with ADR-0118 and ADR-0123: there is no threshold that belongs to us. **How
full is too full** depends on how much headroom an operator wants — and they
have already said that once with the reserve from ADR-0047.

A rule at `pressure >= 1` would be the rejection that already exists, only
named earlier: at that point the node is full. What is missing is the advance
warning, and its margin belongs to operations.

## Consequences

**Positive**

- **A cluster that is filling up is visible before it is full.** Until now the
  first sign was a failed placement.
- **It is the planner's number**, not one that resembles it — the same
  discipline as in ADR-0069, ADR-0124 and ADR-0125.
- **`pressure` gets its second reader.** ADR-0109 introduced it and used it
  only for sorting; whoever reads it now sees the same ordering by which
  placement happens.
- **Free of charge**: the value lies in memory at the end of every planning run.

**Negative / costs**

- **`Plan` gets a field**, and every place that builds a `Plan` must fill it —
  in this tree's tests the majority of the call sites.
- **Two metric families more**, with `node` × `resource` as cardinality.
  Bounded, and nevertheless: they are series somebody stores.
- **The number applies to the moment of planning.** Between two steps the
  occupancy does not change by itself — but a node that fails does not make
  another's number new. It is as fresh as the last planning step, and that is
  exactly the state on which the decision was made.

**Risks & open points**

- **`plan` and `headroom` still compute two maps.** This decision does not add
  the third and does not merge the two; that they answer different questions is
  the reason, and that they compute over different sets stays a difference
  nobody has checked.
- **The reported consumption is the *declared* one, not the measured one.**
  What a container really needs is said by ADR-0118; what the planner books
  stands in `<resources>`. Seeing the two diverge is possible only with both
  numbers — and remains a task for the operator.
- **The sidecar surcharge counts along** (ADR-0067), because the planner books
  it. That is right and makes the number larger than the sum of the
  `<resources>` settings.

## Related ADRs

- **Redeems:** **ADR-0069**, open point *"The capacity is not a metric"*.
- **Gives a second reader to:** **ADR-0109** (the pressure), **ADR-0047** (the
  schedulable capacity is the denominator).
- **Applies:** **ADR-0011** (the number decides nothing), **ADR-0015/11b**
  (cardinality), **ADR-0069** (one computation, one place).
- **Touches:** **ADR-0118** (the *measured* consumption — the other half of the
  question), **ADR-0067** (the surcharge counts along).
