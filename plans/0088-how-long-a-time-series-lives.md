# ADR-0088: How long a time series lives

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture
- **Technical context:** `tg-telemetry`, `tgd`, `tg-agent`, `tg-proxy`, ADR-0015

## Context and Problem Statement

ADR-0015 names **cardinality** as an open point, and 11b answered it: a label may only
take values whose number the cluster bounds. The second half of the same question was
never asked: **how long does a time series live whose subject no longer exists?**

Measured: **forever**. The Prometheus exporter holds every series until the process
ends; nobody sets an `idle_timeout`. Concretely that means:

| After | remains |
|---|---|
| `tgctl cluster remove api` | `tg_workload_ready{workload="api"} 0` |
| the same for a single writer | `tg_workload_active_role{workload="api"} 0` |
| `tgctl node remove node-9` | `tg_node_attached{node="node-9"} 0` |
| a leader change | the **old** leader's `tg_cluster_*` numbers |

The consequences stand in `docs/alerts.yml`: `TardigradeWorkloadNotReady` and
`TardigradeSingleWriterWithoutActiveRole` (the latter `critical`) therefore fire
**permanently** for a workload an operator deliberately withdrew — and the series can only be deleted by
restarting the process. An alerting rule one can no longer silence is one that gets
switched off.

## Decision Drivers

- An alarm that keeps firing after a **deliberate** action teaches people to ignore
  alarms — in a REMIT/DORA environment that is the most expensive kind of side effect.
- A **counter** that disappears and comes back reads like a reset to `rate()`. What is
  right for a gauge is wrong for a counter.
- Four gauges are set **rarely or once** (`tg_task_alive` exactly twice in a process's
  life). An expiry that hits them would take away exactly the alarms that count.
- The tree already has the right place: `sample_process` takes the descriptor numbers
  **in the scrape**, with the justification "a gauge that a task has to keep updating
  freezes when that task dies".

## Options Considered

- **Option A — leave everything.** The alarms stay unsilenceable.
- **Option B — expiry for everything.** Hits the counters and thereby `rate()`.
- **Option C — expiry only for gauges, and every gauge gets a known cadence.** Whoever
  sets rarely is re-set in the **scrape**.

## Decision

Chosen: **Option C.**

1. **The expiry applies only to gauges**: `idle_timeout(MetricKindMask::GAUGE, …)`.
   Measured, that leaves counters and histograms untouched — a gauge disappears after
   the deadline and **comes back on the next set**.
2. **The deadline is 15 minutes.** It is bounded above by an operator's patience (that
   is how long an alarm keeps firing after a withdrawal) and below by the slowest
   legitimate cadence. Prometheus typically scrapes every 15–60 s; the deadline
   therefore lies far above any scrape interval, and a living subject's series does
   not lapse.
3. **Every gauge has a known cadence.** Whoever does not set it at least once per
   deadline anyway **registers** a refresh that runs in the scrape:
   `Health::on_scrape`. That is the same place and the same justification as with
   `sample_process` — in the scrape no intermediate state arises that could go stale.
4. **Whoever introduces a new gauge answers the question along with it.** Either it is
   set at a cadence well below the deadline, or it is registered. That stands at the
   constants block in `tg_telemetry::names`.

## Consequences

**Positive**

- An alarm about something that no longer exists falls silent after 15 minutes instead
  of never.
- A **replaced leader** stops asserting cluster-wide numbers. That is a quiet
  improvement: until now it carried its last values on indefinitely.
- `tg_task_alive` goes from an edge to a **heartbeat** — from here on it says "this
  task is alive now" and not "it was alive when somebody looked".

**Negative / Costs**

- A gauge nobody sets and nobody registers disappears **silently**. That is the price
  of point 4, and a guard against it could not be written: gauges are not enumerable.
- 15 minutes is a number. Whoever wants quiet sooner lowers it and checks the cadences
  in doing so.

**Risks & Open Points**

- A scrape interval above 15 minutes would let all registered gauges lapse. That would
  be monitoring that no longer monitors anything anyway.
- The `tg-proxy` refreshes its timestamps every minute and therefore needs no
  registration. Should that cadence ever fall away, point 4 applies.

## Related ADRs

- **ADR-0015** — observability; cardinality was the first part of the same question.
- **ADR-0057** — timestamps instead of age: the same family of findings.
