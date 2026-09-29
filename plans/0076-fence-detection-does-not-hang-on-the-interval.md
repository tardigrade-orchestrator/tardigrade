# ADR-0076: Fence detection does not hang on the reconcile interval

- **Status:** accepted
- **Date:** 2026-09-03
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-model` (`lease`), `tg-runtime` (`reconcile`),
  `tg-agent`, ADR-0064, ADR-0058, ADR-0010, ADR-0014

## Context and Problem Statement

ADR-0064 gives the holder of an active-role lease a **safety margin**: fencing
happens at `expires_at − margin`, not at `expires_at`, so that the old holder has
really stopped before a new one starts. The margin is the detection latency plus the
stop time, and the detection latency was **one reconcile pass** — i.e. `--interval`.

That ADR moreover establishes an ordering condition (determination 7):

> detection latency + stop time **<** lease period.

With the default values that is `10 s + 2 s = 12 s < 15 s`. The condition holds, and
`tg_model::lease::margin_holds` checks it at startup.

**Measured, it is necessary and not sufficient.** A real `tgd`, a real `tg-agent`, a
single writer, `tg_workload_active_role` sampled once a second:

| `--interval` | Margin | Result over 45–60 s |
|---|---|---|
| 1 s | 3 s | continuously `1` |
| 4 s | 6 s | continuously `1` |
| 6 s | 8 s | 6 of 45 samples `0` |
| **10 s (default)** | **12 s** | **`0` about two thirds of the time** |

With the **default configuration** a healthy single writer therefore counts as
fenced most of the time: its container is stopped (ADR-0058) and started again on
the next pass. A flapping single writer is exactly what ADR-0064 was supposed to
prevent.

## The finding: two numbers that know nothing of one another

The cause is arithmetic between two controls that no ADR has bound together:

- **The leader renews late.** `leases()` renews only when the remaining time is
  `≤ lease/2` — for good reason: every renewal is a log entry ADR-0020 retains
  forever, and the rate should be a property of the lease and not of a foreign
  timer.
- **It ticks every `lease/3`.** So in the steady state the remaining time falls
  deterministically to `lease − 2·lease/3 = 5 s` before renewal (15 → 10 → 5 →
  renewed).
- **The holder fences at `remaining ≤ margin`.** If `margin` is larger than the
  remaining time in the trough, it fences in **every** cycle — without anything
  having failed.

The load-bearing condition is therefore not `margin < lease` but
`margin < remaining time in the trough`. That remaining time hangs on the renewal
rule and on the leader's tick, plus on the slice's latency — on three numbers, then,
that live in two other crates and were chosen for other reasons.

**A condition that relates three foreign controls is one that somebody eventually
violates.** That is exactly what happened, and in the default configuration.

### A correction to our own work

At this place stood a hand-computed cap `MARGIN_CEILING = 12_000`, and with the
default values the agent reported as an **ERROR**: "single writers do not start with
this interval". That note was classified as *wrong* and removed, on the grounds that
a margin of exactly that number holds — evidenced by a test of `role_of` at **one**
point in time.

The test proved the wrong thing: that a **freshly granted** lease does not fence. It
said nothing about the steady state. The removed note was substantively right, and
the replacement turned a true warning into a green light. That belongs here, because
the lesson is more general than the case: **an assertion at a point in time is no
evidence about a cycle.**

## Decision Drivers

- A single writer must **not** flap in normal operation; its container is the one
  that writes data exclusively (ADR-0027).
- The security property from ADR-0064 stays untouched: there must never be two
  active writers. The margin does not become smaller than the stop needs.
- The default configuration has to hold. A default that requires an operator's
  decree in order to work at all is no default.
- No condition between controls that live in different crates chosen for different
  reasons.

## Options Considered

### A — decouple detection from the interval (chosen)

The reconciliation wakes **lease-aware**: after every pass it is known when the
earliest fence threshold falls; it sleeps until then, but at most `--interval`. The
detection latency is thereby a small fixed floor instead of `--interval`, and the
margin is `grace period + floor` — independent of any setting.

### Why not B — tighten the condition and refuse the default

`margin < lease/2 − lease/3` would be the honest form of the condition, and with
default values it would trip: the agent would refuse and demand `--interval 2`. That
is a default that does not run, and it merely shifts the coupling onto the operator
— they would have to keep two numbers in two crates against each other in their
head.

### Why not C — lower the default interval

`--interval 2` as the default would make the condition true and changes a number
concerning **the whole reconciliation**: five times the rate for all workloads,
because of a property only single writers have. The same rejection as in ADR-0064,
where the same move was already up for debate.

### Why not D — renew earlier

If the leader renewed at `remaining ≤ 3/4·lease`, the trough would be higher — and
the renewal rate would double, because it is `1/(lease − threshold)`. Those are log
entries ADR-0020 retains **forever**, for a property a faster **tick** also produces:
that costs nothing in the log, because the rate is determined by the "second half"
rule and not by the tick. Hence determination 4 instead of this option.

### Why not E — lengthen the lease

The fifteen seconds are the failover time from ADR-0014. Lengthening them in order
to cover a detection error would pay for the security property with availability in
the wrong place.

## Decision

**Option A.**

1. **The detection latency is a floor, not a setting.** The reconciliation sleeps
   until the earliest fence threshold of its single writers, at most `--interval`, at
   least `FENCE_WAKE_FLOOR`. A pass's report carries that threshold; it arises where
   `role_of` is evaluated anyway, and not in a second derivation.

2. **The margin is `FENCE_GRACE + FENCE_WAKE_FLOOR`** and hangs on no command-line
   setting. With today's numbers that is `2 s + 1 s = 3 s`.

3. **The ordering condition becomes the load-bearing one** and stands with **all
   three numbers** in `tg_model::lease`:

   > `margin < lease/2 − tick`
   >
   > — the margin has to be smaller than the remaining time in the trough: the
   > remaining time at which the leader renews (`lease/2`), minus its tick, because
   > it sees it at the next tick at the earliest.

   It is a build assertion: whoever sets one of the numbers wrongly gets no binary.
   That replaces the condition from ADR-0064 determination 7, which was necessary
   and not sufficient.

4. **The leader's tick is a sampling rate, not a rate limiter**, and becomes
   `lease/5` instead of `lease/3`. It determines only how quickly the leader
   **notices** a due renewal; how often it writes is determined solely by the "second
   half" rule — and that stays. The log therefore does **not** grow, and the trough
   rises from `lease/6` (2.5 s) to `3·lease/10` (4.5 s).

   With `lease/3` the condition would not hold: a 2.5 s trough against a 3 s margin.
   The obvious alternative — renew earlier — would have raised the trough just as
   much and would have increased the number of log entries ADR-0020 retains
   **forever**. The price here is a scheduler pass every three instead of every five
   seconds, and it writes nothing (ADR-0049: level-triggered).

   The number therefore lies with the other two in `tg_model::lease`; `tgd`
   re-exports it. Separated they would be two places for one condition.

5. **The fence stays with the holder and in the reconciliation.** A second path that
   stops containers would be a second writer onto the same state. The reconciliation
   merely wakes earlier.

6. **No fallback to `--interval` for detection.** Whoever raises the interval slows
   the reconciliation and **not** the fence. That is the whole point: the security
   property must not hang on a number chosen for another reason.

7. **An arriving slice wakes the reconciliation.** That is the mirror case and the
   same mistake: if the holder notices an expiring lease only at the next pass, it
   notices an **arriving** one just as late. Measured, a single writer with
   `--interval 60` needed a full sixty seconds to take up its long-granted role — the
   slice lay on the disk, and the loop slept.

   The path for it already exists: the session already wakes the renewer (ADR-0042).
   A second wake-up, from applying the slice to the reconciliation, costs no
   listening port and no polling interval.

8. **The evidence is a time series, not a point in time.** `role_of` is checked over
   a simulated cycle — grant, the leader's tick, renewal in the second half — and in
   it must **never** say `Fence`. A test at a point in time let this bug through; a
   test over the cycle catches it.

## Consequences

- **Positive:** the default configuration carries a single writer without an
  operator setting anything.
- **Positive:** the security property from ADR-0064 becomes **stronger**, not
  weaker: the margin shrinks from 12 s to 3 s, so the holder fences later and keeps
  its role longer — and because it evaluates closer to the threshold, the time
  between "deadline passed" and "really stopped" is shorter than before.
- **Positive:** `--interval` again means one thing — how often reconciliation
  happens.
- **Positive:** a node takes up its active role as soon as it arrives instead of at
  the next pass — with a large `--interval` that is the difference between seconds
  and minutes.
- **Negative:** the reconciliation wakes more often than `--interval` for a single
  writer, and a slice triggers a pass. Measured that is one pass per renewal cycle,
  i.e. roughly every 7.5 s instead of every 10 s; for nodes without single writers
  nothing changes.
- **Negative:** the ordering condition now names three numbers instead of two. But it
  stands in **one** place and is checked at compile time — the difference from the
  old situation is that nobody has to keep it in their head.

## Risks & Open Points

- **The slice's latency does not enter the condition.** If the leader renews in time
  but the slice takes longer than the trough, the holder fences rightly — it knows
  nothing new. The slice arises as soon as the log moves (ADR-0040), i.e. immediately
  after the renewal; with a 4.5 s trough against a 3 s margin, 1.5 s remain for the
  round trip. If it gets slower, the fence is the **intended** answer and not a bug.
- **`FENCE_WAKE_FLOOR` is a number with a justification, not a measurement.** One
  second is chosen so that a failure does not become a hot loop.
- **The figures from ADR-0014 stay unevidenced** (lease 15 s): the condition holds
  for every lease, but whether fifteen seconds is the right number is still decided
  by a measurement that only exists with a running cluster.

## Related ADRs

- **Replaces** the ordering condition from ADR-0064, determination 7 — it was
  necessary and not sufficient. That ADR's decision (the leader grants, the holder
  fences autonomously) stays unchanged.
- Applies: ADR-0058 (the grace period when stopping), ADR-0010 (the fence is
  autonomous), ADR-0020 (every renewal is a log entry).
- Depends on: ADR-0014 (the lease period), ADR-0066 (the sidecar reads the same
  deadline and is unaffected: it has its own tick).
