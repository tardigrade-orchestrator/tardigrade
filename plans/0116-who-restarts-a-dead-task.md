# ADR-0116: Who Restarts a Dead Task

- **Status:** accepted
- **Date:** 2026-09-11
- **Concerns:** ADR-0082 (release profile), ADR-0010 (autonomy boundary),
  ADR-0015 (observability), ADR-0019 (static stability)

## Context and Problem Statement

ADR-0082 fixed the panic strategy at `unwind`: a panic costs **its task**, not
the node. In addition it switched on `overflow-checks` in the release profile,
whereby an arithmetic error **is** a panic instead of a silent wrong number.

The price stood in the same ADR as an open point:

> **Nobody restarts a dead task.** The panic path now reports, but the restart
> is missing — for `keep_fresh` that is the most expensive case: fifteen
> minutes later every handshake fails (ADR-0014).

And `tg_telemetry::probes::supervise` has carried the justification for why it
does not do so since ADR-0082:

> **What it does not do: restart.** A task that dies of a permanent cause dies
> again on the second attempt, and a restart from that would be a hot loop.

## The measurement

**Five tasks are under observation.** Four of them **cannot** end normally at
all:

| Task | Return | End possible through |
|---|---|---|
| `identity-refresh` (`join::keep_fresh`) | `()`, but `loop { … }` | only panic |
| `cluster-session` (`session::keep_open`) | `()`, but `loop { … }` | only panic |
| `resolver-udp` (`resolver::serve_udp`) | `Infallible` | only panic |
| `resolver-tcp` (`resolver::serve_tcp`) | `Infallible` | only panic |
| `projection` (`tgd`) | `()` | panic **or** an end of the Raft channel |

For the first four, "ended" therefore always means **panicked**. The fifth has
a second exit, and it is legitimate: `while metrics.changed().await.is_ok()`
ends when the sender drops — that is process shutdown.

**What a death costs**, reckoned against the ADRs and not estimated:

| Task | Consequence |
|---|---|
| `identity-refresh` | workload SVIDs no longer rotate (15 min lifetime, 2 min grace), and after twelve hours no SVID of this node is accepted any more (ADR-0014) |
| `cluster-session` | no more slice: no withdrawal of an edge (ADR-0025), every single writer fences (ADR-0064), tombstones stay lying (ADR-0042) — the same list ADR-0077 measured for the lost leader |
| `resolver-*` | no container of this node resolves a name any more (ADR-0013) |
| `projection` | the leader no longer keeps its view up to date (ADR-0030) |

### The objection from the code is half wrong

"Dies again on the second attempt" applies to a **permanent** cause — a file
that is missing; an assumption that was never true. But ADR-0082 has just
created the other sort: an overflow panic hangs on **one input**. A clock jump,
a skewed measurement, a packet — the next round would have been fine. For those
the sentence is not true, and they are the case ADR-0082 wanted to make
visible.

### And an inconsistency that weighs more than both arguments

ADR-0010 section 3 enumerates what a node may do **without quorum**:

> restart its own assigned, crashed instances according to the local cache

So the agent restarts the crashed **container** of a foreign workload — a
process with its own network, its own volume and its own identity — and not its
own crashed task, although that is the less dangerous of the two. That was
decided nowhere; it is the gap ADR-0082 left behind.

ADR-0057 does not stand in the way. There it is about **policies that write
into the log**, and about the rule that a policy must not read an absence. A
task restart writes nothing, concerns only this process and reads no silence
but an **event**: this task has just died.

## Options Considered

- **A — leave it.** Report, and a human restarts the process.
- **B — restart on a panic, with backoff and a ceiling.**
- **C — like B, but give up for good after N attempts.**
- **D — catch the panic in the body** (`catch_unwind`) instead of restarting
  the task.

## Decision

Chosen: **B**.

### Determination 1 — the restart is on a panic, not on a return

Whoever returns `Ok(())` has decided to be finished. For the projection that
means the Raft no longer exists — a restart would spin idle there, and
precisely during shutdown, where nobody is looking.

The distinction is not an exception for a single case but the rule that follows
from the measurement: for the four tasks that cannot return, "ended" is
synonymous with "panicked", and for the fifth it is not. `JoinError::is_panic()`
says so, and it is already in the code.

A cancellation (`is_cancelled`) is likewise **not** restarted: cancellation
comes from inside, during shutdown.

### Determination 2 — `supervise` gets a factory instead of a handle

A `JoinHandle` cannot be restarted. The observer therefore takes a function
that **creates** the task, and starts it itself the first time.

That is more than a signature change: it makes visible where a restart is
**not** possible. Whoever wants to observe a task whose ingredients are
consumed must write the factory — and notices in doing so that they cannot.
Measured, all four tasks of the agent can be reconstructed: three from cloned
values, the resolvers by binding anew (the sockets belong to the task and fall
with it).

### Determination 3 — backoff with a ceiling, no hard giving up

After a panic there is a wait, and the wait grows: doubling from one second up
to one minute. A success — a task that runs for a while again — resets it.

With that option C is rejected. A cap ("after five attempts never again") would
turn a **fixable** situation into one that only a process restart solves: a file
an operator puts back, a peer that returns, a file descriptor that becomes
free. The ceiling of one minute is not a hot loop — it is a heartbeat — and
determination 4 takes over the visibility instead of a cap.

Option D (`catch_unwind` in the body) is rejected: a panic in the middle of a
pass leaves the task's state in a shape nobody has thought about. A restart
from the beginning has a defined input — the local cache and the disk — the
same choice as with the container in ADR-0010.

### Determination 4 — a counter, because the gauge now comes back

`tg_task_alive` goes `1 → 0 → 1` from here. A brief death therefore no longer
alarms, and that is right; a **flapping** task would, however, be invisible, and
it is the worse state: in every window it leaves a piece undone.

So a counter `tg_task_restarts_total{task}`. Counters do not expire (ADR-0088),
and what counts is the **rate** — the same justification as with
`tg_workload_restarts_total`: a single restart is normal, one per minute means
"it does not come up".

The text of `TardigradeTaskDied` thereby becomes wrong ("nobody restarts it, so
only a restart of the process helps") and belongs changed. The rule itself
stays: a task that does not run for a minute is worth an alert, even if someone
is trying to restart it.

### Determination 5 — readiness follows the task, liveness does not

Unchanged from 11b, and expressly confirmed here: a dead task withdraws the
**readiness**, not the sign of life. The other way round would produce exactly
the process restarts ADR-0082 abolished — and with them the workload outages
against which ADR-0019 protects the node.

## Consequences

**Positive**

- The most expensive case from ADR-0082 is closed: an overflow panic in
  `identity-refresh` now costs one second instead of twelve hours.
- The inconsistency with ADR-0010 disappears: the same treatment for a crashed
  container and a crashed task of one's own.
- A transient panic heals by itself; a permanent one stays visible.
- The factory is a seam with a purpose: it makes nameable the tasks that
  **cannot** be reconstructed.

**Negative / costs**

- **A bug becomes quieter.** A panic that previously stopped a task forever and
  thereby stood out now expresses itself as a number in a counter. That is the
  trade, and it is intended — but it demands that the alert rule on the rate
  really exists and does not merely know the direction (the thresholds belong
  to operations, ADR-0047).
- **A restart is not a repair.** A task that panics again after every minute
  leaves a piece undone in every window, and the consequences above occur
  proportionally. The counter says so; a human must heal it.
- The observer turns from a spectator into a participant: it holds the factory,
  so that lives as long as it lives. A handle a caller throws away therefore
  takes more with it than before — `#[must_use]` stays.

**Risks & open points**

- **A watchdog per task stays open** (ADR-0082), and this ADR expressly does
  not close it. It is a different question: a death is an **event**, a hang an
  **absence** — and whose silence may count for how long differs per task. The
  only watchdog of this tree therefore sits to this day on the reconcile loop
  and means the process (11b).
- **The backoff numbers are starting values** (1 s to 1 min, doubling). They
  are measured against no panic, because there is none one would want to
  trigger for it; the order of magnitude follows the deadlines that hang on it
  (SVID rotation 15 min, lease 15 s).
- **A task that fails at creation** instead of panicking during the run is not
  covered by this ADR: the factory returns a `JoinHandle`, so it must succeed.
  Where creation can fail (a bind that does not work), the failure belongs
  **inside** the task.

## Related ADRs

- **Redeems:** **ADR-0082**, open point *"Nobody restarts a dead task"*.
- **Applies:** **ADR-0010** (section 3 — the restart of a crashed instance is
  autonomous, and this here is the smaller case), **ADR-0088** (counters do not
  expire, gauges do), **ADR-0019/11b** (not ready does not mean dead).
- **Delimits against:** **ADR-0057** (a policy must not read an absence — a
  death is an event), **ADR-0071** (only an operator replaces a *running*
  container; here it is about one that is no longer running).
- **Touches:** **ADR-0015** (one metric more), **ADR-0014/0025/0042/0064** (the
  deadlines that hang on `identity-refresh` and `cluster-session`).
