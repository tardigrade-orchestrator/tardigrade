# ADR-0101: The Active-Role Lease and Readiness

- **Status:** accepted
- **Date:** 2026-09-06
- **Concerns:** ADR-0064 (active-role lease), ADR-0080 (readiness),
  ADR-0010 (reconciliation/fencing), ADR-0019 (static stability),
  ADR-0078 (clock of the lease), ADR-0089 (readiness and the requirement edge)

## Context and Problem Statement

ADR-0080 names it outright:

> Binding **the active-role lease** to the probe is the **most dangerous
> coupling** and is not decided.

Today the leader renews the lease when it has a **report** from the holder
(ADR-0064): the node is alive and talks to the cluster. Whether the workload
**answers** does not enter into it — even though the projection has known
since ADR-0080 (`report_unready`). It would be one line in `leases()`.

The case at issue: a single writer runs, its node reports, and the process
does not answer. It holds the role, and the warm standby beside it does not
take over — exactly the situation for which ADR-0010 provided the warm
standby.

## Decision Drivers

- The lease is the tool with which this system guarantees **exactly one
  writer** (ADR-0010). What hangs on it is data integrity.
- A failover of a single writer is **not** without consequence: the standby
  has its **own** volume (ADR-0027) and starts up on a different data set.
- A probe is overload-sensitive (ADR-0080, determination 7).
- The lease already carries three numbers in an ordering condition (ADR-0076)
  and a clock assumption (ADR-0078).

## Options Considered

**A — The lease hangs on readiness.** The leader renews only when the holder
**and** its probe answer.

**B — A third axis.** The lease stays on the report, but an **unready** holder
loses it after its own, longer deadline.

**C — It stays as it is.** The lease hangs on the report; readiness is
visible, and a human decrees. Chosen.

## Decision

### 1. The lease stays on the report, not on the probe

Four reasons, and the first is the load-bearing one.

**The lease is a safety tool, not an availability tool.** Its purpose is
"exactly one writer", and the property on which that rests is the
**reachability of the leader**: whoever cannot reach it fences itself
(ADR-0064, ADR-0010). That is the statement that structurally excludes split
brain — and a probe adds nothing to it. It adds an *availability* argument,
and for that the lease is the wrong tool: it would then be responsible for two
things, and the check that is supposed to carry the fencing would hang on a
TCP connect.

**A failover here costs data, not just a restart.** A warm standby has its
**own** volume — ADR-0027 expressly does not permit volume migration, and HA
runs "via replica with its own volume". Whoever switches the role therefore
starts up on a different data set. That is right for a workload with its own
replication (a database) and a data tear for everything else. A
**misreading** must not trigger that.

**A probe is overload-sensitive, and the result would be flapping.** An
overloaded primary does not answer, loses the role, the standby takes over,
gets the same load, loses it too. In the end nobody works, and the cause is
recorded nowhere. Exactly this argument is what ADR-0080 determination 7 made
for the restart; for a role change it weighs more, because that is more
expensive.

**And the condition does not carry a fourth number.** ADR-0076 bound three to
one another — lease, tick, safety margin — and ADR-0078 added a clock
assumption. The probe has its own deadline (250 ms, concurrent, ADR-0080).
Pulling it into the same condition would mean making the safety statement
depend on a fourth value that an operator sets per workload.

**Option B is rejected for the same reason**, only more slowly: it makes the
flapping rarer, not impossible, and it adds a second deadline to the lease —
that is, exactly the fourth number.

### 2. What an operator has instead

The same answer as with ADR-0057 (auto-detach) and ADR-0080 (restart):
**visibility, and a human decrees.**

- `tg_workload_ready` / `tg_workload_probed` say that the holder does not
  answer (ADR-0080).
- `tg_workload_active_role` says that it holds the role (ADR-0076).
- **Both together are the incident**, and the alert rule on it is writable:
  role held and probe silent.
- `tgctl cluster restart <workload> <generation>` is the action (ADR-0071) —
  and afterwards the audit trail records **who** decreed it (ADR-0050).

A restart of the instance does not take the role from it: it stays instance 0,
the lease runs on, and it comes back with the same volume. That is the
difference from a role change — and in almost all cases what an operator
wants.

### 3. The guard is a tripwire, not a prohibition

`leases()` reads `reporting` and nothing else. A guard over the source code
records that it stays that way: whoever pulls readiness in there makes it red
— and thereby has this conversation instead of adding a line.

Same construction as `the_probe_runs_after_the_gate` (ADR-0089): it is not
about a prohibition but about **requested attention** at a place where the
change is one line and the consequence is a data tear.

## Consequences

**Positive.** The safety statement of the lease stays on **one** property
(reachability of the leader), and a misjudgement by the probe cannot trigger a
role change. The ordering condition from ADR-0076 stays at three numbers.

**Negative, and it is the cost side that counts.** A single writer that runs
and does not answer holds the role until a human acts. The warm standby stands
beside it. At a target availability of 4-9 to 5-9 that is a span of time an
operations team must fill — with an alert rule and an on-call rota, not with
automation.

**This is a deliberate choice against automation at exactly one place**, and
it fits the three neighbours: no auto-detach (ADR-0057), no restart on a probe
(ADR-0080), no readiness in the dependency gate (ADR-0089). In all four cases
the input is unreliable and the consequence expensive.

## Related ADRs

- **ADR-0064** stays unchanged; this ADR answers the question ADR-0080 put to
  it.
- **ADR-0080** gets its most dangerous open question answered.
- **ADR-0089** is the sister decision: there the dependency gate stays at
  "runs", here the lease stays on the report.
- **ADR-0076/0078** carry the ordering condition that is not to take on a
  fourth number.
- **ADR-0027** carries the cost argument: the standby has its own volume.
