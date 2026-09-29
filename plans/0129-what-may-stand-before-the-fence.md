# ADR-0129: What May Stand Before the Fence

- **Status:** accepted
- **Date:** 2026-09-13
- **Concerns:** ADR-0058 (the clearing away and its deadline), ADR-0064 (the
  lease and its ordering condition), ADR-0076 (the detection latency),
  ADR-0066 (the second layer), ADR-0110 (what stands in the pass holds it up)

## Context and Problem Statement

ADR-0058 built the clearing away and left behind a number that is noted as
uncovered in the code itself:

> The number is **not** from an ADR: `terminationGrace` per workload is an open
> point from ADR-0058.

Measured, the number is not the problem. Its **position in the pass** is.

### The measurement

A container the desired state no longer names and that does not react to
`SIGTERM`, against a runtime that permanently reports it as running:

```text
one hanging container: the pass took 10.156235394s (GRACE = 10s)
  report: reaped=["tg-forgotten"] failed=0
```

Stopping is **sequential** (`for id in existing { … stop(…).await }`), so every
further hanging container costs a further ten seconds.

### Why that is more than a long cleanup time

The order in the pass is: `reap_unless_incomplete`, then `start_order` — and
the **self-fence sits in the `start_order` loop**. The safety stop thus waits
for the housekeeping.

Against that, `FENCE_MARGIN` reckons with **three seconds**: one second
wake-up floor (ADR-0076) plus two seconds fence grace. Both concern the
**waking** and the fence stop itself. What the pass does *before* that does
**not** enter the computation.

With a lease of fifteen seconds a single hanging, no-longer-wanted container
therefore suffices to break the ordering condition from ADR-0064
determination 7 — and its violation means, verbatim: **two writers.**

The trigger is not a special case but an operations action: a **drain** makes
many workloads on a node unwanted, and the same node can hold active roles.

### What defuses the situation, and what does not

**The second layer holds** (ADR-0066): the sidecar refuses mesh traffic as long
as its workload does not hold the lease, and it reads the role file in a task
of **its own** (`session::keep_open`) — not in the reconcile pass. A workload
that fences too late therefore does not talk after all.

**What remains** is the path no sidecar sees: a single writer writes into its
**volume**. That is exactly what the lease exists for (ADR-0027: volume
migration is excluded, HA runs via a replica with its own volume).

### What about it is clean and stays so

`FENCE_GRACE` is deliberately shorter than the ordinary deadline (two instead
of ten seconds) and is derived from `tg_model::lease` via
`const _: () = assert!` — with a comment recording that a copied
`from_secs(5)` there left all 124 witnesses green. The care applied to the
fence stop. The time **before** it nobody considered.

## Decision Drivers

- **A safety stop waits for nothing.** It happens because an instance may no
  longer write; everything that stands before it is a deadline it does not
  have.
- **The ordering condition must be complete.** A condition that does not know
  part of the path is none.
- **But the deadline itself is right.** Ten seconds for an orderly stop is not
  waste; shortening it would hit every workload in order to defuse a case that
  depends on a failed `SIGTERM`.

## Options Considered

- **A — shorten the grace period** until it fits into the safety margin
  (computed, under three seconds). Hits every workload so that a hanging one
  does no damage — and takes the time to clean up from a service that really
  does.
- **B — the fence in a strand of its own.** Clean against any duration in the
  pass, and it would have to agree with the pass about the same container. Two
  strands that can both start and stop the same container are a class of error
  this tree has so far avoided.
- **C — the fence to the front and the clearing away concurrent.** Takes the
  waiting away from the fence **in this** pass entirely and bounds the duration
  of a pass to **one** grace period instead of N.

Chosen is **C**; the rest stands in the risks.

## Decision

### Determination 1 — the self-fence is the first thing in the pass

Before the clearing away, before the starting, before everything else that
costs time.

ADR-0058 justifies "clear away first, then start" with a conflict over
addresses and namespaces — that applies to the **starting**. A fence is neither
a start nor housekeeping: it takes the write right from an instance, and the
deadline for it was set by the leader, not by this pass.

### Determination 2 — stopping is concurrent

All containers the desired state no longer names get their `SIGTERM`
**together**, and the grace period runs for all at once. `N × GRACE` becomes
`GRACE`.

They are independent of one another — that was never different sequentially, it
was only slower. The order of clearing away carries no statement.

### Determination 3 — the grace period stays as it is

Ten seconds for an orderly stop. Shortening it would hit every workload in
order to defuse a case that depends on a container ignoring its `SIGTERM` — and
the price would be a service that gets a `SIGKILL` in the middle of cleaning
up.

`FENCE_GRACE` stays separate from it and shorter, as ADR-0064 requires.

### Determination 4 — the condition is written out

What stands before the self-fence in the pass enters the detection latency and
must fit into `FENCE_MARGIN`. With determination 1 the set is **empty**, and
that is precisely the assertion: a guard records that the fence stands before
the clearing away.

A comment at the place does not suffice — this tree has measured three times
what becomes of an order that only somebody wrote down.

### Determination 5 — `terminationGrace` per workload stays open, with a new reason

The open point from ADR-0058 remains. What changes is its content: it is **no
longer** a safety question, since the fence stands before the clearing away and
a pass lasts at most one grace period. It is a schema question — which workload
gets how much time to clean up — and that goes its own way
(`schema/README.md`).

## Consequences

**Positive**

- **The fence no longer waits for anything** this pass otherwise does. The
  ordering condition from ADR-0064 determination 7 applies again to the path it
  describes.
- **A drain costs one grace period, not N.** Measured, that is ten seconds
  instead of ten per hanging container.
- **The deadline stays for the case it exists for** — a service that closes its
  connections.
- No new strand, no second place at which a container is started or stopped.

**Negative / costs**

- **A pass can still last ten seconds**, and a fence that falls due *during*
  such a pass comes correspondingly later. What catches it is the second layer
  (ADR-0066) — and the rest stands below.
- **Concurrent means: all at once.** A node clearing away a hundred containers
  sends a hundred `SIGTERM`s in one go. That is the point, and on a node with a
  hundred containers it is load that was previously spread out.
- **The order in the report changes**: `reaped` no longer stands in the order
  of the state directory. It carried no statement, and a test that relies on it
  was checking something other than it meant.

**Risks & open points**

- **The strand of its own for the fence stays the more thorough answer**
  (option B) and is not built. What speaks against it stands above: two strands
  that can touch the same container. What speaks for it stays true: only then
  does the fence latency hang on nothing at all.
- **A single writer that fences too late keeps writing into its volume.** The
  sidecar stops the mesh traffic (ADR-0066, its own task), the volume it does
  not see. That is the remainder of the risk, and it is the reason why option B
  is not off the table.
- **How long a pass otherwise takes is not measured** — the content GC
  (ADR-0126) at 378 µs is the only number available for it. What `apply`
  carries in orders ADR-0110 measured at up to 60 s per volume and moved **out**
  of the session arm into the reconciler; that it raises the same question
  there stands here and is not decided.

## Related ADRs

- **Redeems:** the safety half of the open point from **ADR-0058**;
  `terminationGrace` per workload stays, with a new reason (determination 5).
- **Restores:** **ADR-0064** determination 7 and **ADR-0076** — the ordering
  condition applies again to the path it describes.
- **Rests on:** **ADR-0066** (the sidecar stops the mesh traffic, in a task of
  its own) — that is the reason why the remainder is bearable.
- **Continues:** **ADR-0110** (what stands in the pass holds it up) — there it
  was about the session arm, here about the fence.
