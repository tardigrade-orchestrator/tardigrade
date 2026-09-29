# ADR-0114: The Tail of the Data Plane, Measured

- **Status:** accepted
- **Date:** 2026-09-11
- **Concerns:** ADR-0022 (data-plane runtime), ADR-0007 (sidecar)

## Context and Problem Statement

ADR-0022 decided the runtime of the data plane — tokio in the thread-per-core
model — and left two things open in doing so, both of which hang on the same
number:

> **Upgrade path:** dedicated io_uring (monoio/glommio) only
> **benchmark-driven**, if measurements show that the tail really needs it.

> **Risks & open points:** a benchmark that validates the tokio-tpc variant
> against the tail target (and triggers or rejects the io_uring upgrade path).

The justification of the decision rests on a figure from the literature:

> Thread-per-core brings a real ~1.5–2× tail/throughput advantage over
> work-stealing; the sidecar is the classic per-connection shardable case.

This figure has **never been measured** in this tree. That is no longer a
trifle: four further notes now hang on the same missing benchmark — the pinning
(ADR-0022 itself), the overflow checking of the data plane (ADR-0082), the
sidecar's CFS quota (ADR-0086) and the latency of splicing (ADR-0041); plus the
flow limits from ADR-0094. A third of this tree's open points was waiting for
**one** measuring instrument.

It is built now: `cargo xtask bench`
(`crates/tg-proxy/tests/tail_latency.rs`). This ADR records what it produced
and draws the consequences.

## The measurement

The same path that phase 8b substantiated, under closed-loop load:

```text
  Load ──plaintext──▶ api sidecar ──mTLS──▶ ledger sidecar ──plaintext──▶ Echo
```

What is measured is the **steady-state round trip** on a standing connection —
512 B out, 512 B back, 2 000 round trips per connection after 50 warm-up
rounds, 16 connections on 4 shards. Five runs per variant, driven **round
robin**, and the whole set repeated six times. Between two variants exactly one
thing is different — the discipline from 8b.

Machine: 8 visible cores (AMD Ryzen 9 9950X3D, VM), loopback, release profile.
Load and echo service share the machine with the shards.

Range of the run medians over six sets, in µs:

| Variant | p50 | p99 | p99.9 |
|---|---|---|---|
| work-stealing | 139–152 | 320–557 | 617–841 |
| thread-per-core | 128–152 | 384–514 | 564–792 |
| thread-per-core, pinned | 129–151 | 371–494 | 654–1088 |

**Three findings.**

1. **At the tail the three variants are indistinguishable.** The ranges overlap
   completely, and the ordering changes from set to set. The ~1.5–2× advantage
   on which ADR-0022's justification rests **is not reproducible here** — not
   as a smaller advantage, but not at all.
2. **At the median thread-per-core is about 5 % ahead.** That is a real but
   small difference — and it is not a tail argument. ADR-0022 expressly decided
   for the tail, not for the median.
3. **Pinning shows no gain.** In one of the six sets a marked p99.9 penalty
   (1 088 µs against 564 and 632 µs). The outlier alone would carry nothing;
   together with the absent gain in the other five it carries.

A fourth finding falls out along the way and belongs to ADR-0082: **the same
round trip costs about 250 µs in the debug profile and about 130 µs in the
release profile.** The factor between the profiles is larger than any
difference between the variants. A benchmark of the data plane in the debug
profile measures `rustls` and `ring` being unoptimized.

## What the measurement cannot see

This belongs in this ADR and not in a footnote, because it bounds precisely the
statement it makes:

- **No NIC.** The traffic runs over loopback. The locality from which the
  thread-per-core advantage stems in the literature — RSS queue, interrupt and
  application thread on the same core — does not exist here at all. A setup
  that had it could show the advantage this one does not.
- **Eight cores, shared.** Load and echo service run on the same machine. A
  real sidecar shares its machine with its workload (ADR-0059), so that is not
  wrong — but it is one installation and not a series of measurements over
  installations.
- **Sixteen connections.** Thread-per-core gains with the number of
  connections. A sidecar carries the connections of **one** workload; the order
  of magnitude is plausible and not substantiated.

From that follows the cut of the decision: the measurement **rejects an
upgrade**, it does not overturn a choice.

## Options Considered

- **A — back to work-stealing.** The measured justification for
  thread-per-core does not carry, so take the simpler way.
- **B — keep thread-per-core and pin**, as ADR-0022 writes.
- **C — keep thread-per-core; pinning as an explicit setting per node, default
  off.**
- **D — io_uring** (monoio/glommio), the upgrade path from ADR-0022.

## Decision

Chosen: **C**.

### Determination 1 — thread-per-core stays, with a more honest justification

Not because the measurement shows an advantage — it shows none. But because it
also shows **no disadvantage**, and the other reasons from ADR-0022 are
untouched by it: sharding via `SO_REUSEPORT` needs no coordinator (8b), a
connection stays with its TLS state on its shard, and a shard that panics does
not take the others with it (ADR-0082). A rollback would cost work and risk for
a measured difference of zero.

The justification in ADR-0022 — "~1.5–2× tail advantage" — counts from here as
**unsubstantiated**, not as false: this setup cannot show it (see above), and a
different one might.

### Determination 2 — `io_uring` is rejected, not deferred

The condition of the upgrade path reads "if measurements show that the tail
really needs it". It has been checked and is **not satisfied**. Switching to an
immature, safety-critical runtime with its own IO abstraction in order to
improve a tail one cannot show would be the inversion of ADR-0022's own
argument.

The question is reopened only by a measurement that lifts these limits: **a
real network card, target hardware, and a load shape from operations.** That
stands here as a condition so that the point is not simply reopened because
someone reads a number in a blog.

### Determination 3 — pinning becomes a setting, not a default

ADR-0022 writes "one current-thread runtime per core, **pinned**" — as part of
the decision, so without a choice. It was never built, and the code has said
since 8b why: without a measurement it would be a setting one makes because it
stands in a document.

The measurement is here, and it says **not** "never" but "not like this". That
is why the default becomes an **explicit setting per node with default off** —
the same construction as the user namespace in ADR-0091 and for the same
reason: there are situations in which it is right, and it is not the general
one.

Three reasons for the cut:

1. **Whoever is the only one nailed down loses.** In the benchmark load and
   echo service run unpinned beside the shards; a pinned shard on an occupied
   core cannot move aside, an unpinned one can. That is the direction in which
   the one measured outlier points (p99.9 of 1 088 µs against 564 and 632 µs).
2. **In operation the neighbour is one's own workload.** The sidecar shares
   machine and namespace with it (ADR-0059). Pinning to computed cores would
   with some probability put it exactly where its workload is computing.
3. **But the intent behind it is right.** A connection that changes core loses
   L1/L2 together with TLS state and buffers — and "latency determinism" stands
   in ADR-0022's title. Whoever has partitioned their node CPUs (`cpuset.cpus`
   for the sidecar; `cpu.max` expressly stays out per ADR-0086) wants exactly
   this behaviour and shall get it.

**The cores come from the cgroup, not from a computation.** Pinning is done
round robin over the set `sched_getaffinity` returns — that is what the node
grants this process. `available_parallelism` would be the wrong source here: it
delivers a number, and a number does not say **which** cores are permitted. So
the setting does the intended thing on a partitioned node and, on an
unpartitioned one, what the measurement warns about — and that is then an
operator's explicit choice and not silent behaviour.

**The seam stays where it is.** `Shards::on_start` carries the pinning; the
benchmark still runs both variants. A pinning that stood only in an ADR would
be a claim in a year's time.

### Determination 4 — the benchmark belongs to the promise, and it has no threshold

`cargo xtask bench` runs **release** and asserts no limit value. There is none:
`plans/README.md` names availability (4-9 to 5-9), not microseconds, and
ADR-0022 derives no latency bound from it. A bound in the test would be
invented and would then fall with the machine on which it runs.

What is asserted is that **measurement happened**: every round trip came back,
the sample has its size. That is the same protection as with the DST evidence
from 11c — a sample that loses half of it still prints a nice p99.

### Determination 5 — the dependent points have a measuring instrument from here

ADR-0082 (overflow checking in the data plane), ADR-0086 (the sidecar's CFS
quota), ADR-0041 (latency of splicing) and ADR-0094 (flow limits) stay **open**
— but no longer for want of a setup. *(Addendum: the first three have since
been measured; ADR-0094 remains.)* They are measured in the same run, with the
same cut: one thing different, five runs round robin, median **and** range.

## Consequences

**Positive**

- The oldest open point of the data plane is closed, and with a number rather
  than a deferral.
- The `io_uring` path is closed, with a named condition for reopening it. Until
  now it was a permanently open promise.
- A divergence between ADR and code disappears: "pinned" stood written and was
  not built. Per invariant 6 that was one of the two cases that must not exist.
- An operator who partitions their node CPUs gets the behaviour ADR-0022 meant
  — and as a decision they make, rather than a default they do not see.
- Four further points have from here a setup in which they are measurable.

**Negative / costs**

- **The numbers apply to one machine.** Another node measures differently, and
  this ADR does not claim it would not. What it does claim is the
  **comparison** — and that is the same setup on every machine.
- The run saturates the machine for about ten seconds and therefore does not
  belong in the normal suite; on a shared CI runner a number would arise that
  says nothing about this system.
- `rustix` is added with the feature `thread` as a **dev** dependency in
  `tg-proxy` (for `sched_setaffinity` in the test path). No new crate — it is
  in the tree anyway — but one edge more in the development path.

**Risks & open points**

- **The measurement on a real network card is missing**, and with it the only
  situation in which the thread-per-core advantage could arise at all. It is
  the condition from determination 2 and belongs on target hardware, not here.
- **The number of connections is an assumption.** Four per shard are plausible
  for a sidecar and not substantiated; a workload with a thousand counterparts
  would be a different measurement.
- ~~**What a sidecar really sees in operation is reported by nobody** — the
  metric from ADR-0086. As long as it is missing, this benchmark's load shape
  is a choice and not a derivation.~~ **Built:**
  `tg_proxy_connections{listener}` (what is currently present) and
  `tg_proxy_connections_total{listener}` (what arrived). Both together, because
  a sidecar with permanently **one** connection and one with a thousand short
  ones look the same in the gauge — and for the tail target from ADR-0022 they
  are two different situations.

  **Per listener and not per shard.** The distribution over the shards is the
  property of `SO_REUSEPORT` that 8b already substantiated; the listener
  separates four load shapes that have nothing to do with one another — and in
  counting it turned out that there are **four** and not three: beside mesh
  ingress, mesh redirect and egress stands the older outgoing path to a
  declared route.

  The gauge registers its refresh in the scrape (ADR-0088): a sidecar with four
  standing connections does not set it for hours, and the series would expire
  after a quarter of an hour.

  **The number above nevertheless remains an assumption** — it is now
  *measurable* and not measured. What four per shard really means will be said
  by the first cluster under load.
- ~~**The benchmark measures the mesh path**, not the egress (ADR-0041) and not
  QUIC (ADR-0094). Both go through the same process, but not through the same
  code.~~ — **half done:** the egress has its own measurement in the same run
  (`the_egress_splice_is_measured_against_a_direct_connection`), as a
  difference from the direct connection; the numbers stand in ADR-0041. QUIC
  stays unmeasured (ADR-0094).
- ~~Determination 5 names ADR-0082 and ADR-0086 as the first consumers of the
  measuring instrument.~~ **Both measured.** The overflow checking of the data
  plane costs nothing measurable on this path (difference below the spread, at
  the median with the wrong sign) and +0.74 % binary size; the way there stands
  in ADR-0082. The CFS quota is a **cliff**: up to 100 % indistinguishable from
  unthrottled, and as soon as it bites, p99.9 jumps by a factor of 70 to 120 —
  added to ADR-0086.

  That leaves as consumers the splice latency (ADR-0041) and the flow limits
  (ADR-0094). **The splice latency has since been measured too** — the splice
  costs roughly a doubling of the round trip (+82 µs at p50, +150 µs at p99.9),
  and connection establishment over it two and a half times as much. The flow
  limits remain.
- **The gain of pinning on a partitioned node is unsubstantiated.**
  Determination 3 makes it reachable and does not claim it; whoever sets the
  setting should have the run on their own installation beside it. **Creating**
  a `cpuset` for the sidecar is expressly not part of this decision — that
  would be a partitioning of the node CPUs and thereby a question for
  ADR-0034/0109 (what capacity a node has) and for ADR-0086 (what the sidecar
  may consume).

## Related ADRs

- **Changes:** **ADR-0022** — determination 3 turns "pinned" into a setting,
  determination 2 closes the upgrade path, determination 1 downgrades the
  justification "~1.5–2× tail advantage" to unsubstantiated. The choice of
  runtime stays.
- **Redeems:** **ADR-0022**, open point *"a benchmark that validates the
  tokio-tpc variant against the tail target"*.
- **Provides a measuring instrument for:** **ADR-0082** (overflow checking),
  **ADR-0086** (CFS quota), **ADR-0041** (splice latency), **ADR-0094** (flow
  limits).
- **Applies:** **ADR-0023** (no `criterion` — every crate is a decision),
  **ADR-0020** (a measurement shows, it does not decide).
- **Built like:** **ADR-0091** (explicit setting with default off, because
  measured not generally sustainable) — the same form, the same reason.
- **Touches:** **ADR-0059** (the sidecar shares its workload's machine — the
  argument against pinning by default), **ADR-0086** (`cpu.max` stays out,
  `cpuset.cpus` is a different knob), **ADR-0007** (the path that is measured).
