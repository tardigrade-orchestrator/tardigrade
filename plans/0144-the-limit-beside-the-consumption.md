# ADR-0144: The Limit Beside the Consumption

- **Status:** accepted
- **Date:** 2026-09-15
- **Decider:** Dana Schlifka
- **Technical context:** `tg-runtime` (`reconcile::report_consumption`),
  `tg-telemetry` (`names`), `docs/alerts.yml`

## Context and Problem Statement

ADR-0118 made a container's consumption into a metric, ADR-0123 put the peak
beside it — and left an open point:

> **The limit itself is not exported.** A ratio "consumption to limit" could be
> alerted on without a threshold; it would arise from the surcharge (ADR-0067)
> and the `<resources>` declaration, and both lie elsewhere. Not decided here.

As long as it is missing, `tg_container_memory_bytes` and
`tg_container_memory_peak_bytes` are **numbers without a scale**. 800 MiB is a
lot for a container with one gigabyte and nothing for one with eight, and which
of the two it is no time series says. Every alert rule on them therefore needs a
threshold per workload — that is, exactly what ADR-0015 leaves to operations and
what in practice nobody maintains.

## The measured state

**The sentence "both lie elsewhere" does not carry.** The limit lies exactly
where the consumption is already read — in the same cgroup, one `read` further:

```text
/sys/fs/cgroup/<path>/memory.current   12288
/sys/fs/cgroup/<path>/memory.peak      1310720
/sys/fs/cgroup/<path>/memory.max       max
/sys/fs/cgroup/<path>/cpu.stat         usage_usec 3371
/sys/fs/cgroup/<path>/cpu.max          max 100000
```

`report_consumption` opens this directory anyway per instance and per pass. The
two missing numbers therefore cost **two further `read`s on a virtual file
system** — the same order of magnitude ADR-0123 already weighed for the existing
ones.

And they are not only cheaper to fetch than the declaration but **something
else**: the cgroup names the limit the kernel **enforces**, the declaration the
one somebody demanded. This tree has two decisions that make the two diverge:

- **ADR-0063**: a changed size takes effect at the **next start**.
- **ADR-0070**: a changed declaration reaches a running container only at the
  next start; until then the instance is visibly *stale*.

A ratio from the **declaration** would therefore be wrong precisely when it
matters: for a workload whose limit has just been raised and that has not
restarted yet, it would report headroom the kernel does not know about.

The same resolution with the sidecar: ADR-0086 builds its memory limit from the
surcharge (ADR-0067), read per pass from a file. In its cgroup it stands ready —
one source covers both cases, and the question "which of the two applies" no
longer arises.

## Decision Drivers

- **A metric without a scale invites a threshold per workload**, and an alert
  rule nobody maintains is one that gets switched off (ADR-0088 measured the
  same mechanism from the other side).
- **One source, not two.** Declaration and enforcement must not both lay claim
  to the same statement.
- **No new read path, no new operational prerequisite** — the restraint with
  which ADR-0118 and ADR-0123 are built.

## Options Considered

- **Option A — export the ratio.** One number instead of two. It loses the
  starting values and is undefined when a limit is missing.
- **Option B — take the limit from the declaration** (the way ADR-0123
  presumed). It is at hand, but it is the **demanded** one and not the enforced
  one.
- **Option C — take the limit from the cgroup**, as its own time series beside
  the consumption.

Chosen: **option C**.

## Decision

### Determination 1 — the limit comes from the cgroup, not from the declaration

What is read is `memory.max` and `cpu.max` in the same directory from which
`report_consumption` already reads `memory.current`, `memory.peak` and
`cpu.stat`.

That is the number the **kernel enforces**. The declaration says what somebody
demanded; between the two lie ADR-0063 and ADR-0070, and precisely in that gap a
ratio from the declaration would be wrong.

**The surcharge from ADR-0067 is thereby not read** — it stands in the sidecar's
cgroup, because ADR-0086 wrote it there. One source for both cases.

### Determination 2 — two numbers, no ratio

`tg_container_memory_limit_bytes` and `tg_container_cpu_limit_cores`, with the
same labels as the neighbours (`workload`, `replica`).

An exported ratio would lose the starting values — and an operator who sees that
a container stands at 95 % next wants to know 95 % **of what**. The division is
done by Prometheus; that is the reason labels exist.

The CPU limit is kept in **cores** and not as quota/period: `cpu.max` names
`<quota> <period>` in microseconds, and the ratio of the two is the number that
matches `<cpu millicores>` in the declaration and the rate of
`tg_container_cpu_seconds_total` beside it. Exporting two raw values would mean
letting every rule do the division itself.

### Determination 3 — no limit means **no time series**

`memory.max` carries `max` when nothing is limited; `cpu.max` carries
`max <period>`. In both cases **nothing is set**.

That is the same rule with which ADR-0123 handles a missing value: a zero would
be a statement, and the wrong one. And an `+Inf` would be the kind of number
that silently becomes a ratio of zero in a division — a container without a
limit would then look like one with infinite headroom, and it is that only until
the node is full.

A workload without `<resources>` therefore has no limit series. That is right:
that it has none is a statement about the **declaration** and does not belong in
a measurement of the kernel.

### Determination 4 — and thereby an alert rule **without a threshold**

That was the purpose, and it is redeemed:

```promql
tg_container_memory_peak_bytes >= tg_container_memory_limit_bytes
```

This rule carries **no number anyone would have to choose**. It says: this
container has touched its ceiling — and the next allocation above it is the OOM
killer. That is not a threshold but a fact, and it is exactly the information
from which ADR-0086 has a sidecar's memory limit set.

The rule stands in `docs/alerts.yml` with a `for:` duration and **without** a
threshold. What belongs to operations stays there: at which utilization *below*
the ceiling somebody wants to intervene is a number per installation.

**The CPU gets no such rule.** Reaching a CFS quota is the normal case of a
busy workload and not an incident — the damage is slowness, not loss (the
argument from ADR-0086). The number stands there nevertheless, because without
it the rate beside it has no scale.

### Determination 5 — the same cadence, no refresher

It is set per reconcile pass, like the neighbours. With that the 15-minute
period from ADR-0088 does not bite, and **no** registration in the scrape is
needed: a limit that is no longer set belongs to a container that no longer
exists — and then the series should expire.

## Consequences

**Positive**

- **The two existing metrics get a scale.** "800 MiB" becomes "80 % of one
  gigabyte", and that without a number anyone has to maintain.
- **An alert rule without a threshold** — the first in this tree that concerns a
  resource limit.
- **Zero new read paths, zero operational prerequisites.** The same directory,
  two `read`s more.
- The question "declaration or enforcement" is **decided** instead of open; it
  would have arisen with the first rule that computes from it.

**Negative / costs**

- **Two metrics more** per container. The cardinality does not change — the same
  labels as the neighbours, and those are bounded by the declarations
  (ADR-0015).
- **A container without a limit has no series**, and a rule that connects both
  time series stays silent for it. That is intended and belongs in the manual:
  whoever wants to be alerted declares a limit.
- **The CPU limit in cores is a derivation** from two numbers of the cgroup. It
  is the same computation as in `bundle::linux_resources`, only backwards — a
  second place with the same arithmetic.

**Risks & open points**

- **A node's limit is still missing.** What a container may do stands there from
  here; what a **node** has ADR-0127 says as pressure — pulling the two together
  would be a third view and is not decided here.
- **`memory.max` is not the only ceiling.** `memory.high` throttles before `max`
  kills, and this tree sets it nowhere. Should it ever be set, it belongs beside
  it.
- **No witness on a container that really touches its ceiling.** The rule from
  determination 4 is computed; a witness for it would have to run a container
  into the OOM killer, and whether that is defensible in this suite is a
  question of its own.

## Related ADRs

- **Redeems the open point from ADR-0123** ("the limit itself is not exported")
  — and corrects its presumption that it lay elsewhere.
- **ADR-0118** — the consumption, at whose setting site this hangs.
- **ADR-0086** — the sidecar's memory limit, whose number becomes visible here;
  and the reason why the CPU gets no rule.
- **ADR-0067** — the surcharge from which that limit stems.
- **ADR-0063 / ADR-0070** — why the declaration is not the enforcement.
- **ADR-0015 / ADR-0088** — cardinality and cadence.
