# ADR-0034: Placement model — instances, capacity, the anti-affinity default

- **Status:** accepted
- **Date:** 2026-08-21
- **Deciders:** Core team
- **Technical context:** `schema/`, `tg-defs`, `tg-model`, `tg-consensus`, `tgd`
- **Closes the open points from:** ADR-0011

## Context and Problem Statement

ADR-0011 decided the placement model — declarative-explicit, no auto-rebalancing,
anti-affinity as a hard constraint — and left three questions open under "Risks &
Open Points":

> - The expressiveness of the constraint language — part of the XSD subset (ADR-0008).
> - The resource/capacity model (CPU/RAM reservation) is still to be specified.
> - Fix the default granularity of anti-affinity (rack vs. hall).

Phase 6 builds the scheduler and can leave none of them open. The second is
additionally a precondition for ADR-0028 ("the precondition is the capacity model
from ADR-0011").

## Decision Drivers

- **Auditability** (ADR-0011): an auditor must see *why* workload X runs on node
  Y. That rules out scoring and requires the rule to be written down.
- **Taking ADR-0027 at its word:** a workload with a writable local volume is not
  movable; HA runs through a replica with its own volume.
- **Readability of the log format** (ADR-0020): the log is an audit substrate
  subject to retention. An extension must not render old entries unreadable.
- **Serving ADR-0028 without a rebuild:** the generic `device` resource type
  should fit later without breaking the model open (PLAN.md, phase 6).

## Decision 1: Instances are part of the command set

A workload carries `<placement replicas="n">`; the log command `AssignPlacement`
gains an **instance number**, and the replicated state maps
`workload → instance → node`.

Only that makes the formulation from ADR-0011 — "a standby **must** lie in a
different failure domain than its primary" — expressible at all: anti-affinity
applies between the instances of **one** workload.

The alternative of carrying a standby as its own workload with its own name was
rejected. It would have left the command set untouched, but "two instances of
the same service" would not be representable in the model, and the operator
would maintain two definitions that belong together only by a naming convention.

**The lease stays per workload, not per instance.** Per ADR-0010, single writer
means: at most **one** active instance cluster-wide. A lease per instance would
mean each of them could be active — which would abolish exactly the property the
lease exists for.

**On the compatibility of the log.** The new fields (`instance` on the
assignment, `capacity` on the node) carry `#[serde(default)]`. An entry from
phase 5a stays readable and means the same as before: instance `0`, no known
capacity. Without that precaution a schema extension would have devalued the log
as evidence (ADR-0020); `tests/command_set.rs` checks it against the verbatim
pins from back then.

## Decision 2: Capacity as a generic resource map

`UpsertNode` carries, next to the topology, a capacity as a mapping
**name → quantity**. Currently carried: `cpu-millicores` and `memory-bytes`. A
device per ADR-0028 would be `device/nvidia.com-gpu` — the same structure, no
rebuild.

The scheduler sums the reservations per node and rejects what does not fit. **A
resource a node does not carry counts as absent** — otherwise "has no GPU" would
be the same as "has arbitrarily many".

Rejected: fixed fields for CPU and memory. They would be easier to read but
would require, for ADR-0028, exactly the rebuild PLAN.md wants to avoid.

**The selection rule is written down, it is not a score:** among the nodes that
satisfy all constraints, the **least occupied** wins, with the alphabetically
first name breaking ties. That is explainable in one sentence and deterministic
— ADR-0011 demands both.

## Decision 3: The anti-affinity default is `rack`

Without a setting, instances of the same workload must lie in **different
racks**. Raisable per workload to `hall` or `site`.

Rack is the smallest level with a genuine shared failure — power, switch,
cooling. It is also satisfiable in a cluster with only one hall and requires no
reserve capacity at a second site.

The alternative `hall` protects more but makes **every** placement with a standby
unsatisfiable in a single-hall cluster: the scheduler would reject where rack
would have sufficed. A default that never bites in a small installation teaches
people to override it — and then it no longer bites in the large one either.

**Domains are fully qualified.** Two racks `r1` in different halls are **two**
domains. Without that qualification, anti-affinity would take them for the same
one and leave two instances standing where they ought to lie apart.

## Decision 4: The constraint language

In the XSD (an extension per the process in `schema/README.md`, with fixtures):

```xml
<placement replicas="3" spread="hall">
  <domain level="site" value="fra"/>
  <domain level="rack" value="r1"/>
  <domain level="rack" value="r2"/>
  <pin node="node-7"/>
</placement>
```

- Entries at the **same** level are a choice list (OR), entries at **different**
  levels apply together (AND). The rule lives in `tg-model`, because the XSD
  cannot express it.
- `<pin>` nails to one node (ADR-0027) and is **contradictory** with
  `replicas > 1` — that is the one case the ingest check per ADR-0011 ("rejects
  unsatisfiable constraints at ingest already") can decide without knowing the
  cluster. That too few racks are free today, by contrast, is a question of the
  day and belongs to the scheduler, not to ingest.
- Default values live in the domain layer, not as `xs:default` — that is what
  `schema/README.md` wants, and that way they stand in one place instead of two.

## Consequences

**Positive**
- Anti-affinity is expressible and is enforced hard; losing one failure domain
  preserves availability.
- The scheduler step is a **pure function** `state → commands`. From that
  follows both things ADR-0011 demands: it is auditable (the placement follows
  from the state of the time) and it is drivable in the harness — the same step
  runs in `tgd` and in `tests/dst/`.
- A leader change re-sorts nothing: the new one sees the same state and arrives
  at the same result.
- ADR-0028 is unblocked.

**Negative / Costs**
- The command set from phase 5a grows by two fields; the wire format has to be
  re-pinned. Old entries stay readable, but compatibility is from now on a
  property one has to maintain.
- The state format (`ClusterState`) has changed. It is derivable from the log —
  a snapshot from an older version is not. As long as the cluster is not running
  in production this is inconsequential; after that a format change needs a
  migration path.
- Declarative constraints mean more maintenance and worse packing density than
  scoring. That is the deliberate trade-off from ADR-0011.

**Risks & Open Points**
- ~~**Who writes the capacity?** Today an operator, through `UpsertNode`. Having
  a node report it itself presupposes an authenticated agent connection
  (ADR-0006, phase 7) — before that it would be a place where anyone could
  influence the cluster's placement.~~ — **done:** ADR-0049.
- ~~**Drain/cordon** is named by ADR-0011 as an operator tool for intentional
  moves. It is missing: today a node can only be removed, and that is a coarse
  lever.~~ — **done:** built — cordon and drain.
- ~~**Reserved capacity for warm standbys** is not modelled. A standby instance
  today occupies capacity like any other.~~ — **done:** ADR-0047.

## Related ADRs

- Closes the open points from: ADR-0011 (which subsumes ADR-0021).
- Applies: ADR-0027 (node pinning), ADR-0010 (a lease per workload, the autonomy
  boundary), ADR-0008/`schema/README.md` (schema extension).
- Unblocks: ADR-0028 (the generic `device` resource type).
- Serves: ADR-0019 (loss of a failure domain), ADR-0020 (readability of old log
  entries).
