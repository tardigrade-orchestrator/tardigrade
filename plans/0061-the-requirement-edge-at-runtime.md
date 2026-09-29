# ADR-0061: The requirement edge at runtime

- **Status:** accepted
- **Date:** 2026-08-28
- **Deciders:** Core team
- **Technical context:** `tg-model::graph`, `tg-runtime::reconcile`,
  `tg-consensus::state`, ADR-0009, ADR-0010, ADR-0019, ADR-0011, ADR-0040,
  ADR-0058

## Context and Problem Statement

ADR-0009 separates two axes: **ordering** (when things start relative to one
another) and **requirement** (whether a failure drags the dependent down). The
ordering axis takes effect. The requirement axis does **not** — not at all.

Measured against the code, not against the note:

| Edge | Promise in ADR-0009 | Effect today |
|---|---|---|
| `After`/`Before` | start order | **works** (`start_order`) |
| `Requires` | "the target must be running; if it fails, the dependent is stopped" | **none** |
| `BindsTo` | harder than `Requires`, bound to the active state | **none** |
| `Wants` | soft, no coupling | none — rightly so |
| `Conflicts` | "must not be active at the same time" | **none** |

`DependencyGraph::cascade_stop` and `DependencyGraph::may_be_active_together` are
built, tested and have **not a single caller** in production code — the eighth
occurrence of the same pattern in this project (most recently
`WorkloadApi::set_assigned`). Outside `graph.rs` **nothing** reads a requirement
edge: the reconciler calls only `start_order()`.

### And a second finding that weighs more

`DependencyGraph::from_workloads` requires **referential integrity**: an edge to a
name not in the set is `UnknownTarget`. The reconciler builds the graph over the
**locally assigned** workloads and passes the error through with `?` — `once`
returns `Err`, `run_with` breaks the loop, and the agent **ends**.

Measured:

```text
Workload 'api' declares <after> on 'db', which does not exist
```

An edge across the node boundary is the **normal case** in a cluster: the
scheduler places `api` and `db` independently (ADR-0011), and the slice from
ADR-0040 gives a node only its own definitions — the counterpart's name, nothing
more. A single such workload silences the agent, and does so again on every
restart. In an environment with a target availability of 4-9 to 5-9 that is this
ADR's most expensive finding, and it shares only the location with the actual
question.

### Why this is a decision and not a commit

Three reasons, all per invariant 6:

1. **ADR-0009 left it open itself** and delegated: *"The exact behaviour on
   restart/backoff and how far cascades may run (damping against flapping) — to be
   nailed down in the reconciliation ADR."* The reconciliation ADR is ADR-0010,
   and it mentions cascades with **not a word** (measured: zero hits for cascade,
   Requires, BindsTo, flapping, backoff). The open point has been open since phase
   3 and was never closed.
2. **ADR-0010 section 3 enumerates** what an agent may and may not do without
   quorum. "Stop a dependent whose requirement target is gone" stands in
   **neither** of the two lists — the same situation as with ADR-0058, and the same
   cause ADR-0046 named: the enumeration is the trap.
3. **ADR-0019 says running containers are never stopped** — with the addition "for
   loss of quorum/the control plane". ADR-0009 says a dependent is stopped. Both
   are valid; where the boundary runs is the question, and it can be answered
   wrongly in both directions.

## Decision Drivers

- **ADR-0009:** the separation of axes and the table of who reacts to which
  inactivity. It is not changed here but applied for the first time.
- **ADR-0010:** level-triggered, without an event queue. A restarted agent is,
  after one pass, as far along as one that has been running.
- **ADR-0019:** workload availability does not hang on the control plane. Nothing
  is stopped because somebody is unreachable.
- **ADR-0040 determination 6:** the node concludes from the **content** of a slice,
  never from its absence.
- **Phase 3, "Not included":** cluster-wide evaluation and health cascades **across
  nodes** are explicitly out.
- **ADR-0011:** declarative-explicit, no auto-rebalancing — the reconciler picks no
  winners.

## Options Considered

- **A — a condition per pass**, evaluated against the outcome of **the same** pass.
- **B — an event with a grace period:** a target must be inactive for N passes
  before the dependent falls.
- **C — only hold back, never drag along:** the edge acts only at start-up.
- **D — keep doing nothing.**

### Why not B

Because the grace period requires a **counter per instance**, i.e. remembered state
— and a restart of the agent loses that. The cascade would thereby be edge-driven,
against ADR-0010. Its purpose is moreover already fulfilled: the damping it is
meant to protect against arises in A without a counter, because a crash that the
same pass fixes never counts as a trigger in the first place.

### Why not C

Because it would have to **replace** ADR-0009's sentence "if it fails, the
dependent is stopped", and for `Requires` **and** `BindsTo`. That would largely
collapse the distinction between `Wants` and `Requires` — the separation of axes
for whose sake ADR-0009 chose option B. Whoever wants to change the semantics
writes an ADR that explicitly supersedes ADR-0009 on this point; undermining it
silently is the drift invariant 6 forbids.

### Why not D

Because `<requires>` and `<bindsTo>` stand in the schema, are parsed, appear in the
read model and have a linter. An operator who writes them may assume they do
something. An edge that has no effect is worse than one that does not exist.

## Decision

Chosen: **Option A**, in seven determinations.

### 1. An edge to a workload this node does not have is mute

It orders nothing and it drags nothing along. It is **not an error**.

The node does not know a foreign workload's state, and it cannot even distinguish
whether it does not exist or runs elsewhere — the slice carries the name and
nothing else (ADR-0040). Deriving an effect from not knowing would be wrong in
every direction: dragging along would mean reading a placement decision as an
outage; ordering would mean waiting for something that never comes here.

The strict path stays where it belongs: `from_workloads` still checks referential
integrity and thereby carries the ingest of `tgctl apply` and the linter. For the
node view a **separate, named** entry point is added that drops foreign targets.
Two constructors, one rule, and the difference stands in the name — instead of a
flag one sets in the wrong place.

The dropping is reported at `debug!` and no louder. It is the normal case of a
cluster; a warning on every pass would teach operators to skim past warnings.

### 2. The requirement edge is a condition, not an event

Every pass evaluates it anew. There is no queue, no counter, no backoff and
nothing a restart could lose. A dependent whose condition is false is **not
started**; if it is still running, it is ended. If the condition becomes true
again, the same mechanism starts it that starts every other workload.

That is ADR-0010 verbatim: level-triggered, against the observed state.

### 3. Evaluation is against the outcome of the same pass

The trigger is **only** a target this pass returns as `failed` — i.e. one whose
restart was attempted and failed.

Explicitly **not** triggers are:

- **`reconciled`** — the reconciler has just brought it back. Here lies all the
  damping: a crashed container that comes up again in the same pass **never**
  moves its dependent. That is the frequent case, and it costs nothing.
- **`deferred`** — without quorum things are deferred (ADR-0010). If that could
  drag along, a loss of the control plane would stop running workloads. That is
  precisely what ADR-0019 forbids, and as its keystone.
- **`untouched`** — it is running.
- **foreign** — determination 1.

**Per workload, not per instance.** A target counts as inactive if **none** of its
instances is active on this node and at least one has failed. Three replicas, one
of which fails and two of which run, drag nothing along — the target is reachable,
and one failure out of three replicas must not produce a second failure.

The flip side stands in the consequences: if a target's instances are spread across
nodes, every node judges only its own share. A dependent can therefore be stopped
although its target runs elsewhere and would be reachable over DNS (ADR-0013). That
is the boundary from phase 3 — health cascades **across nodes** are explicitly not
included — and the price of a node having to be able to judge without a control
plane (ADR-0019).

### 4. Who reacts to which inactivity stands in ADR-0009

| Edge | reacts to |
|---|---|
| `bindsTo` | any inactivity of the target |
| `requires` | only failure of the target |
| `wants` | not at all |

This table is not reinvented; it is ADR-0009's and has lain in `cascade_stop`
since phase 3. This ADR gives it a caller.

### 5. One dragged along counts as stopped, not as failed

Otherwise a single crash would run arbitrarily far along `Requires` chains. The
distinction from determination 4 thereby acts in depth: a `bindsTo` chain carries
on, a `requires` chain ends after one step.

### 6. `Conflicts` is refused at ingest, not enforced at runtime

Two simultaneously wanted workloads, one of which excludes the other, are a
contradiction in **intent** — and that belongs where the intent arises. Enforcing
it at runtime would mean picking a winner, and a winner rule is a policy
(ADR-0011: declarative-explicit, no auto-rebalancing; ADR-0057: what a policy may
read).

The check sits in the **state machine** and not on the document — the same
construction and the same reason as with volume exclusivity from phase 10a: the
two workloads arrive as **two** log entries, and between them lies an arbitrary
amount of time. Whoever looks only at the submitted document lets both through.

It requires **no** referential integrity: a conflict with a workload that does not
exist is inconsequential, and an upsert must not fail because a sibling document
points at something not yet applied. That is also the reason the state machine
builds no graph to this day — one workload per log entry (ADR-0004), and the set is
complete only at the end.

### 7. The gate is autonomous (a supplement to ADR-0010 section 3)

The list of actions permitted without quorum gains a fifth entry:

> **do not start, or end, a dependent whose requirement target has failed on this
> node.**

Justified like `SelfFence` and like the teardown from ADR-0058: the inputs are the
local cache and the locally observed state, both available without a control plane
(ADR-0019). Two agents on two sides of a partition cannot diverge in doing so —
each judges only what it runs itself. And because `deferred` explicitly does not
drag along (determination 3), a loss of quorum can stop nothing this way.

The autonomy check nevertheless stands at the place, even though today it can never
defer — as with ADR-0058: a later reclassification then takes effect instead of
being forgotten.

## Consequences

**Positive**

- ADR-0009's requirement axis takes effect for the first time. What an operator
  writes does something.
- The agent survives an edge across the node boundary. That is not a side effect of
  this ADR but its precondition: without determination 1 there would be no pass in
  which a condition could be evaluated.
- No new state on disk, no counter, no queue.
- `Conflicts` is refused where it arises, instead of needing a winner later.

**Negative / Costs**

- **It is a behavioural change.** A dependent that used to run while its target
  failed will no longer run. That is the promise from ADR-0009, and for whoever
  wrote the edge by accident it is an outage. The linter from phase 3 has always
  warned about the half form (`Requires` without `After`); it does not warn about
  the edge itself.
- **An `Upsert` that used to pass can be refused** — the conflict case. It was
  declared without effect before.
- **Nothing takes effect across node boundaries**, and from the inside that looks
  like a bug. A `requires` on a workload the scheduler put elsewhere is mute. That
  is phase 3's explicit boundary, but it belongs in the operations manual, because
  it disappoints the expectation.
- **A distributed target is judged locally.** A `requires` on a workload with
  replicas on several nodes can stop a dependent although the target runs
  elsewhere. Whoever does not want that uses `wants` — or lays both out with the
  same instance count and the same `spread`, so that the local view is the right
  one.
- The evaluation follows the start order. Without `After` a target can come up
  **after** its dependent in the same pass; the condition then bites only one pass
  later. Level-triggering converges that — and it is exactly the case the linter
  warns about.

**Risks & Open Points**

- ~~**Health beyond "the container runs"** does not exist. A target that runs and
  does not answer counts as active. Liveness/readiness per workload is not built
  (ADR-0015 knows them for the orchestrator's processes, not for workloads).~~ —
  **done:** ADR-0080 and ADR-0102.
- **Cluster-wide cascades** stay out (phase 3). Whether they should ever come is not
  decided.
- **`Conflicts` at runtime** stays undecided: two workloads already in the state
  before this ADR applies are not checked retroactively.
- ~~**A cycle in the local desired state still ends the agent.** Determination 1 is
  explicitly lenient only towards **foreign targets**; an ordering cycle stays a
  hard error, and `once` passes it through — measured with
  `cycle in the start order: a -> b -> a`. That is reachable only around `tgctl`,
  because both client paths refuse beforehand; but "presupposes a client" is
  exactly the kind of assumption ADR-0043 and ADR-0046 have already exposed as
  false. What a hard error should cost at this place — the pass, the affected
  workloads or nothing — is a decision of its own and deliberately not taken
  here.~~ — **done:** ADR-0062.

## Related ADRs

- Semantics and the open point: ADR-0009.
- Level-triggering and the autonomy boundary: ADR-0010 (section 3 supplemented).
- What an outage must not trigger: ADR-0019.
- The same construction for ending: ADR-0058.
- Ingest check over the set: phase 10a, ADR-0027.
- No winner rule: ADR-0011, ADR-0057.
