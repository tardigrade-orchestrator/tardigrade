# ADR-0118: What a Container Consumes

- **Status:** accepted
- **Date:** 2026-09-11
- **Concerns:** ADR-0086 (what the sidecar may consume), ADR-0067 (the
  surcharge), ADR-0015 (observability), ADR-0072 (the format window)

## Context and Problem Statement

ADR-0086 gave the sidecar a memory limit and refused a CFS quota, and in doing
so left an open point:

> **What a sidecar really consumes is reported by nobody.** A metric for it
> would have to read the cgroup; whether the agent should do so is not decided.

Since the quota measurement for ADR-0114 this point is no longer one among
several but **the condition** on which two decisions hang:

- A CFS quota is measured to be a **cliff**: as long as it does not bite, it
  costs nothing; when it bites, p99.9 jumps by a factor of 70 to 120. Such a
  setting is only made with known headroom above it — and headroom can only be
  chosen over a measured consumption.
- The surcharge per mesh instance (ADR-0067, `SetSidecarOverhead`) stands at
  **zero** and is thereby guessed by every operator. Since ADR-0086 the kernel
  enforces it as a memory limit — a guessed number is from then on not merely
  imprecise but the OOM killer.

Measured, **nobody** reads a container: `tg_agent::capacity` reads the
machine's totals (`available_parallelism`, `MemTotal`), and there is nothing
else.

## What the measurement finds

**The cgroup path belongs to us.** `bundle::cgroups_path` writes
`/tardigrade/<container-id>` expressly into the spec — because ADR-0006 bound
identity to the cgroup and `youki` would otherwise create `/:youki:tg-api`,
that is, a segment without our prefix. There is therefore nothing to search for
and nothing to guess; the place is a constant of this system.

On a real running container:

```text
/sys/fs/cgroup/tardigrade/tg-tg-probe-drift/
  memory.current 0
  usage_usec 7863
```

Both files are there and read without privileges beyond those the agent has
anyway.

## Decision Drivers

- **`instance` is a forbidden label name.** `tg_telemetry::names::LABELS`
  excludes it, with a reason: "that is set by Prometheus and not by this code".
- **The cardinality rule from 11b** applies: a label may take only values whose
  number the cluster bounds.
- **Every extension of the report is a format break** (ADR-0072) and belongs in
  the bundled window.
- **A pass must not cost what it need not** (ADR-0110): what stands in the
  reconciler holds the reconciler up.

## Options Considered

- **A — do nothing.** The consumption stays unknown, the surcharge guessed.
- **B — a metric per container**, read by the agent from the cgroup.
- **C — a field in the report** (ADR-0040), so the leader keeps it in the
  projection and `tgctl cluster show` displays it.
- **D — only for sidecars**, because only there is the declaration missing.

## Decision

Chosen: **B**.

### Determination 1 — a metric, not a field in the report

Option C is rejected, and the reason is not the effort: since ADR-0072 the
report is an expensive place. Every extension is a format break, goes into a
bundled window and demands a coordinated transition on all nodes. That is the
right price for a **decree** — for an observation one looks at, it is wrong.

Added to that is where the question is asked: "what does a sidecar consume" is
a question for a dashboard, not for the state machine. The planner must never
see the number anyway (ADR-0049, determination 2) — it is `actual`, and the
determinism from ADR-0011 hangs on it staying so.

ADR-0086 itself calls it a **metric**.

### Determination 2 — per container, with a new label `replica`

What is measured is what the cgroup yields, and that belongs to a container. A
sum over the instances of a workload would be wrong for the question this
number exists for: the limit applies **per container** (ADR-0086), so the
number must stand per container. Two instances on one node are rare and not
excluded (ADR-0060 names the case); a sum would then be double what is sought.

`instance` is blocked as a name — Prometheus sets it. The label is therefore
called **`replica`** and carries the instance number. The rule from 11b is
satisfied: its values are bounded by `replicas` of the declaration, that is, by
a number in the log.

### Determination 3 — two series, and the second is a counter

- `tg_container_memory_bytes` — **gauge**, from `memory.current`. The number
  ADR-0086's memory limit means, and the only one whose exceedance costs a
  node.
- `tg_container_cpu_seconds_total` — **counter**, from `cpu.stat usage_usec`.

A gauge for the CPU would be wrong: the cgroup keeps a cumulative time, not a
utilization. What an operator wants to see is the **rate** — the same shape as
with `tg_workload_restarts_total`.

**The counter jumps to zero on a restart**, because the container gets a new
cgroup. That is not a defect: `rate()` recognizes a reset. An attempt to carry
the number forward across restarts would require state somewhere — and that
would be a second source for a fact that stands in the kernel.

### Determination 4 — every container, not just the sidecar

Option D is rejected. It is the same code, the same cgroup and the same
question: on what number does the limit rest that this container gets. For the
sidecar it comes from the surcharge (ADR-0067), for the declared workload from
`<resources>` — in both cases it is today chosen by someone who does not see
the actual number.

The cardinality does not grow appreciably as a result: the sidecars are already
workloads with their own name (ADR-0059), so they would stand beside the
declared ones anyway.

### Determination 5 — a missing cgroup is not an error

Between the pass and the reading a container can be gone — ended, cleared away
(ADR-0058), crashed. An `ENOENT` is then the normal case and not worth
reporting. What is reported is what is **unexpected**: a cgroup that is there
and cannot be read.

And what could not be read is **not set**. A zero would be a statement, and the
wrong one: "this container consumes nothing" reads like a measurement.

### Determination 6 — in the reconciler, without a tick of its own

Reading happens once per pass, where the instances are traversed anyway. No
ticker of its own: a second tick would be a second place at which someone
chooses the period, and the period is already chosen (`--interval`).

Two files per container are a `read` on a virtual file system — that is the
order of magnitude ADR-0110 has in view, and it lies far below it.

## Consequences

**Positive**

- The condition from ADR-0086 is satisfied: from here the surcharge can be
  **chosen** instead of guessed, and a quota would for the first time be
  settable with known headroom.
- The memory limit from ADR-0086 gets its input. Until now it was a number an
  operator set without a reference point — and underestimating it costs the
  node.
- Zero format breaks, zero new crates, zero new settings.

**Negative / costs**

- **A new label.** `LABELS` is a short list with a rule behind it; every entry
  makes it longer. `replica` is the first since 11b.
- **The number is node-local.** The leader does not see it, `tgctl cluster
  show` does not display it. Whoever sets the surcharge cluster-wide looks at
  the nodes individually — via Prometheus, where aggregation belongs.
- **Two `read`s per container and pass.** At a one-second interval and twenty
  containers that is forty reads per second on a virtual file system.
  Defensible and not zero.

**Risks & open points**

- ~~**An empty cgroup directory is left behind after the container** —
  measured on `tg-tg-probe-drift` after a run. It costs little and piles up;
  and the leftover checker from `xtask` knows loop devices and device mapper,
  but no cgroups. That is a finding of its own and only noted here.~~ **Done**
  (`37f8521`, "The leftover guard now also sees cgroups"):
  `xtask/src/leftovers.rs` reads `/sys/fs/cgroup/tardigrade` and carries its
  own justification ("And why the cgroups"). What is measured there at the same
  time is that the **normal** way leaves no remainder — five container tests,
  no leftover directory; the guard catches the case in which it does after all.
- **What the number says about a sidecar hangs on its workload's traffic.** A
  surcharge that fits a quiet workload does not fit a loud one — ADR-0067 names
  exactly that as the price of its one number. The metric makes the price
  visible, it does not take it away.
- ~~**The peak values are missing.** `memory.current` is the instantaneous
  value; what the container needed at a peak stands in `memory.peak`
  (Linux ≥ 5.19). For a limit the peak is the more correct number — reading it
  here would be one more kernel lower bound, and this ADR does not carry that.
  Whoever sets the limit should look at the rate over time and not at one
  value.~~ — **done: ADR-0123.** The first half is true and larger than the
  note: measured, a cgroup that went to 200 MiB stands half a second later at
  0.5 MiB — **factor 425** — and a scrape every fifteen seconds does not see a
  peak between two measurements at all. The second half is **false**: a kernel
  lower bound does not arise, because `read_number` already returns an `Option`
  and determination 5 of this ADR says what follows from it — a missing file
  costs a time series, not an operational prerequisite.
  `tg_container_memory_peak_bytes` stands **beside** the instantaneous value
  from ADR-0123 on; the limit from ADR-0086 is set from the peak.

## Related ADRs

- **Redeems:** **ADR-0086**, open point *"What a sidecar really consumes is
  reported by nobody"* — and thereby the condition under which its
  determination 1 (no CFS quota) would ever be posed anew.
- **Provides an input for:** **ADR-0067** (the surcharge, today zero and
  guessed), **ADR-0086** (the memory limit that follows from it).
- **Applies:** **ADR-0015/11b** (cardinality as a rule, not as a feeling),
  **ADR-0088** (counters do not expire, gauges do), **ADR-0072** (the report is
  an expensive place), **ADR-0110** (what stands in the pass holds it up).
- **Touches:** **ADR-0006** (the cgroup path is specified — that is why it is
  readable), **ADR-0049** (the number is `actual` and never reaches the
  planner), **ADR-0059** (the sidecar is a workload with its own name).
