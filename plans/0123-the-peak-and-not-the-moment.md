# ADR-0123: The Peak, and Not Only the Moment

- **Status:** accepted
- **Date:** 2026-09-12
- **Concerns:** ADR-0118 (the metrics per container), ADR-0086/0067 (the memory
  limit and the surcharge from which it is set), ADR-0019 (the keystone),
  ADR-0015/0088 (cardinality and lifetime)

## Context and Problem Statement

ADR-0118 built the metrics per container and left an open point:

> **The peak values are missing.** `memory.current` is the instantaneous value;
> what the container needed at a peak stands in `memory.peak` (Linux ≥ 5.19).
> For a limit the peak is the more correct number — reading it here would be
> one more kernel lower bound, and this ADR does not carry that.

Both halves have been measured. The first is true and larger than the note; the
second is false.

### The measurement

A real cgroup, a process that goes to 200 MiB and releases again, read half a
second later:

```text
current: 602112        (  0.5 MiB)
peak:    214040576     (204.1 MiB)
                       factor 425
```

**The number an operator reads today is the wrong one — and in the direction
that kills.** `memory.current` is an instantaneous value, and a scrape every
fifteen seconds does not see a peak between two measurements at all. Whoever
derives the memory limit from ADR-0086 from it sets it below the actual demand
— and that limit exists because a sidecar under the OOM killer takes its node's
workloads with it (ADR-0019).

The case is not constructed. ADR-0121 has just given the same operator a
computation — 9.2 MiB for 512 QUIC flows in the worst case — and the metric
beside it can undershoot that by two orders of magnitude. Precisely such a
demand is bursty: it arises when many connections are established at once, and
is gone again a minute later (`IDLE`).

### The justification for the deferral does not carry

"One more kernel lower bound" — measured, it costs none. `read_number` returns
an `Option`, and ADR-0118 determination 5 itself says what follows from it:

> What could not be read is **not set**. A zero would be a statement, and the
> wrong one.

That is the same path that already takes effect today when the `memory`
controller is not enabled in the parent — then `memory.current` is missing just
the same. A missing file on a kernel below 5.19 costs **one time series, not an
operational prerequisite**. The only kernel lower bound of this tree remains the
one from ADR-0053/0081, and it applies to the identity path.

## Decision Drivers

- **The metric should answer the question it exists for.** ADR-0118 names it
  itself: "an underestimate is, from ADR-0086 on, no longer imprecise but the
  OOM killer." For a limit the peak is the number, not the moment.
- **What costs nothing is not omitted out of caution.** The deferral rested on
  a price that does not exist.
- **Two questions, two numbers.** "What does it need now" and "what did it ever
  need" are not the same, and neither replaces the other.

## Options Considered

- **A — stay with the instantaneous value** (today). The number an operator
  needs for the limit then still remains missing.
- **B — replace `memory.current` with `memory.peak`.** Cheaper in cardinality
  and loses the information "is it growing right now": a peak that was reached
  once says nothing about now.
- **C — both.** One time series per container more, and each answers its own
  question.

Chosen is **C**.

## Decision

### Determination 1 — `memory.peak` is added, replaces nothing

A metric of its own beside `tg_container_memory_bytes`, with the same labels
(`workload`, `replica`) and read from the same loop. The cardinality doubles for
this container block and stays bounded — by the number of definitions and the
`replicas` (ADR-0015/11b).

Replacing would be cheaper and would take the other information away: the
instantaneous value is the number by which one sees whether a container is
growing **right now**; the peak is the one from which one sets a limit.

### Determination 2 — a missing file is a missing time series, not a prerequisite

Unchanged, the rule from ADR-0118, determination 5, and here it is the whole
answer to the open point: under Linux 5.19 the file does not exist, then nothing
is set. A node on which it is missing reports the instantaneous value as before
and nothing else.

**No new operational prerequisite**, and that is said in the manual rather than
presupposed.

### Determination 3 — it is not reset

Since Linux 6.x `memory.peak` can be reset by writing. That is **not** done.

Reset, the number would be "the peak since the last pass" — a different
statement, and a fragile one: it would hang on our cadence rather than on the
container, and a second reader that reset it likewise would take the value from
us. What is to stand here is "what this container has ever needed".

### Determination 4 — it is a gauge, and it falls only on restart

Over the cgroup's lifetime it rises and does not fall. On restart the container
gets a fresh cgroup (ADR-0006 specifies the path), and the number begins anew —
the same shape as the reset of `tg_container_cpu_seconds_total`, and for the
same reason: the number stands in the kernel, and we do not keep a second one
beside it.

A counter it would not be: `rate()` over a peak yields nothing anyone wants to
read.

### Determination 5 — no alert rule, and the reason stands beside it

As with the two metrics from ADR-0118: there is no threshold that belongs to
us. What is too much is known only by whoever set the limit.

What is added is the **guidance**: the limit is set from the peak, not from the
instantaneous value, and the gap between the two is the reason why that is not
the same thing.

## Consequences

**Positive**

- **The number from which a limit arises is from here the right one.** The
  measured gap of a factor of 425 is exactly the underestimate ADR-0086
  describes as the OOM killer.
- **A bursty load becomes visible**, even if no scrape hits it — and bursty is
  the normal case for everything to do with connection establishment
  (ADR-0121).
- **No new crate, no new file, no new prerequisite.** One line beside the one
  that already exists.
- The open point from ADR-0118 is closed, and its justification error is
  written down — that is the part that counts next time.

**Negative / costs**

- **One time series per container more.** On a node with many instances that is
  the doubling of this block; the bound stays the same as for the existing one
  (ADR-0015/11b).
- **The peak does not age.** A one-off spike stays visible until the container
  restarts — for "what did it ever need" that is right and for "is something
  going on right now" wrong. For that the instantaneous value stands beside it.
- **On a kernel below 5.19 it is missing**, without anything being broken.
  Whoever builds a rule on it builds it on a time series that does not appear
  there — the same already applies today when the controller is not enabled.

**Risks & open points**

- **A foreign reader that resets takes the value from us.** On a node with a
  second agent or a tool that writes `memory.peak`, the number would be smaller
  than the truth. That is the same operating error as two agents on one data
  directory and is not treated here.
- **`cpu.stat` has no counterpart.** A peak load on the CPU can be seen with
  the rate over time and needs no peak value; a memory spike is invisible
  between two scrapes, a CPU spike is not. The asymmetry is deliberate.
- ~~**The limit itself is not exported.** A ratio "consumption to limit" could
  be alerted on without a threshold; it would arise from the surcharge
  (ADR-0067) and the `<resources>` declaration, and both lie elsewhere. Not
  decided here.~~ **Decided and built: ADR-0144** — and the presumption was
  false. The limit does **not** lie elsewhere but in the same cgroup from which
  the consumption is already read (`memory.max`, `cpu.max`): two `read`s more
  in a directory `report_consumption` opens anyway.

  More important than the price is the difference: the cgroup names what the
  kernel **enforces**, the declaration what someone demanded — and between the
  two lie ADR-0063 and ADR-0070. A ratio from the declaration would be wrong
  precisely when it matters.

  With that the rule for whose sake this point was noted is here, and it is the
  **first of this tree without a threshold**:
  `tg_container_memory_peak_bytes >= tg_container_memory_limit_bytes`.

## Related ADRs

- **Redeems:** **ADR-0118**, open point *"The peak values are missing"* — and
  corrects its justification: a kernel lower bound does not arise, because the
  reading is already an `Option`.
- **Serves:** **ADR-0086/0067** — the limit is set from the peak; **ADR-0121**,
  whose computation is a bursty one.
- **Applies:** **ADR-0118** (determination 5: rather nothing than a zero),
  **ADR-0015/11b** (cardinality), **ADR-0088** (the gauge is set per pass, so
  it does not expire), **ADR-0006** (the cgroup path is specified).
- **Touches:** **ADR-0019** — the OOM killer on a sidecar is the case against
  which the number is set.
