# ADR-0067: The sidecar in the capacity calculation

- **Status:** accepted
- **Date:** 2026-08-31
- **Deciders:** Architecture
- **Technical context:** `tg-consensus` (`schedule`), `tg-model` (`placement`),
  `tgctl`

## Context and Problem Statement

ADR-0059 names it as an open point: *"The sidecar consumes capacity nobody booked.
The scheduler computes with the workload's resource map (ADR-0034); the sidecar
runs alongside."*

Measured, the scheduler is **blind** to it: `Demand::from_workload` reads
exclusively the workload's `<resources>` element, and the derived unit does not
stand in the log at all — it arises on the node (ADR-0059, determination 1). So the
scheduler cannot see it, even if it wanted to.

The consequence goes in the dangerous direction:

- **The scheduler overpacks.** Every mesh workload brings along a second process
  per instance that nobody booked.
- **The reserve from ADR-0047 is too optimistic** — by exactly the sidecars' share.
- **And the metric lies in the same direction.** `tg_scheduler_domain_elsewhere`
  reports more room than really exists when a domain fails. It has been accurate
  since "A bit has no almost" — but it is systematically biased.

## Decision Drivers

- **The scheduler has to stay deterministic** (ADR-0011). A measured quantity lives
  in the projection, is eventual and at a different state on every node — a new
  leader would arrive at a different result. That is the justification with which
  ADR-0049 keeps the reported capacity away from the scheduler.
- **The derived unit is not visible in the log** (ADR-0059). Writing it in there
  would be a policy, and `UpsertWorkload` is not on the list from ADR-0057.
- **A sidecar is the same everywhere.** One image per node (ADR-0059), one program,
  the same command line. A number per workload would be one an operator copies
  everywhere.
- **An upgrade must not lose capacity.** The same rule as with `reserved`
  (ADR-0047): an invented number would retroactively take room away from the
  scheduler.

## Options Considered

- **A — the derived unit into the log.** The scheduler would see it as an ordinary
  workload. Contradicts ADR-0059 (the node derives) and would bring back the
  co-location problem that ADR just solved: the scheduler works per workload, `api`
  and `api-proxy` would land independently.
- **B — the node reports what its sidecars consume.** Accurate, and **eventual** —
  the scheduler would lose its determinism (ADR-0049).
- **C — a deduction in the capacity policy** (`subtract`, ADR-0049). Present and
  wrong: it is per node and static, so it knows nothing about how many mesh
  instances land there.
- **D — a cluster-wide surcharge per mesh instance**, in the log, added by the
  scheduler to the demand.

## Decision

Chosen: **Option D**.

### 1. One surcharge, cluster-wide, in the log

`SetSidecarOverhead { resources }` — the same generic resource map as everywhere
(ADR-0034), so it also fits a `device` type without rework (ADR-0028).

In the log, because the scheduler reads only replicated desired state.
Cluster-wide, because the sidecar is the same program everywhere.

### 2. It applies per **instance** of a mesh member

The criterion is `<mesh>` — exactly what ADR-0059 anchors the derivation on. Two
derivations of the same criterion would be two opportunities to disagree.

Per instance and not per workload: every instance gets its own sidecar, because it
moves into its network namespace (ADR-0059, ADR-0060). The scheduler places per
instance anyway, and `Demand::resources` is the demand of **one** instance — so the
surcharge lands in the right place by itself.

### 3. The default is zero

A cluster in which nobody has declared anything computes as before. An invented
number would retroactively take room away from the scheduler and, after an upgrade,
leave workloads lying that ran before — the same consideration as with `reserved`
(ADR-0047).

### 4. It is a **setting**, not a measurement

What a sidecar consumes depends on the connection count and throughput. A number
the cluster determined itself would be eventual (option B) and would make the
scheduler non-deterministic. An operator measures it once on a running sidecar and
declares it.

## Consequences

**Positive**

- The scheduler no longer overpacks by the sidecars' share.
- The reserve from ADR-0047 and the numbers from `headroom` become honest — they
  compute with the same demand.
- No new mechanism: a resource map, a command, an addition.

**Negative / Costs**

- **An operator has to know the number.** It stands in no definition and cannot be
  derived; without it the bias remains.
- **A behavioural change as soon as it is set:** the same cluster afterwards takes
  on less. That is the point — but it is a difference.
- One more command in the alphabet, which is append-only.

**Risks & Open Points**

- **The surcharge is coarse.** A sidecar in front of a quiet workload consumes less
  than one in front of a loud one; the number is the same for both. That is the
  same compromise the resource map makes anyway.
- **It counts for instances that are not yet running too.** That is right for a
  scheduler looking for room for what is wanted, and makes the calculation slightly
  **conservative** against actual consumption — in the safe direction.

## Related ADRs

- Redeems: ADR-0059 ("the sidecar consumes capacity nobody booked")
- Depends on: ADR-0034 (the generic resource map), ADR-0011 (a deterministic
  scheduler)
- Adjacent: ADR-0047 (the reserve computes with the same demand), ADR-0049 (why a
  measurement does not reach the scheduler)
