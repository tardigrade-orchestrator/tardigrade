# ADR-0078: The clock a lease holds against

- **Status:** accepted
- **Date:** 2026-09-03
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-model::lease`, `tgd::scheduler`,
  `tg-consensus::state`, ADR-0024, ADR-0064, ADR-0076, ADR-0010, ADR-0019

## Context and Problem Statement

ADR-0024 separates the two time sources and is explicit about it:

> **Monotonic vs. wall clock kept apart:** lease/timeout logic (0010) uses
> monotonic clocks (immune to wall-clock jumps); audit/REMIT timestamps use
> traceable UTC.

**Measured, the active-role lease uses the wall clock — on both sides.** The leader
forms `expires_at` from `SystemTime::now()` (as `UtcMillis` in the log command), and
the node compares with its own `SystemTime::now()`. The doc comment on `role_of`
claims that `now` and `expires_at` come "from the same clock" — they come from
**two**.

The deviation went unnoticed for one and a half ADRs: ADR-0024 has been there from
the start, ADR-0064 built the lease, ADR-0076 its safety margin — and none of the
three asked the question.

### Why the prescription is not satisfiable as written

A monotonic clock has **no common zero point**: an `Instant` on node A means nothing
on node B. A lease that goes over the wire as an **absolute** point in time can
therefore not be monotonic — and absolute it has to be, because the security
statement from ADR-0064 reads: *the leader grants anew at expiry, and the old holder
has stopped by then.* Both sides have to mean the same point in time.

ADR-0024 supplies exactly that in the same breath: a **traceable, synchronized** UTC
(PTP-capable, chrony). So the sentence about monotonic clocks hits what it describes
— the *local* timeouts of ADR-0005 and ADR-0010 — and not a lease two machines share.

### What hangs on it

The security statement of ADR-0064/0076 therefore rests on an assumption written
down **nowhere**: that both sides' clocks lie close together. Computed with
`skew = clock(leader) − clock(node)`:

| Case | Consequence |
|---|---|
| node **ahead of** the leader | the lease looks shorter, it fences **early** — availability, self-healing |
| node **behind** the leader, `skew < margin` | unchanged, safe |
| node **behind** the leader, `skew ≥ margin` | it holds the role while the leader passes it on — **two writers** |

The last case is exactly the one the lease is meant to prevent. And there was **no**
place at which a skew stands out: no comparison, no metric, no note. The state
machine does not even check `expires_at` against the `now` of the same command.

## Options Considered

1. **The wall clock, explicitly — with an ordering condition and a fail-safe.**
2. **A relative duration instead of an absolute point in time** ("valid 15 s from
   receipt"), measured monotonically by the node.
3. **A monotonic clock, as ADR-0024 reads.**
4. **Leave it as it is.**

## Decision

**Option 1.** The active-role lease holds against the **wall clock**, and the
ordering condition for it is written out instead of assumed.

### Determination 1: the wall clock, and the reason stands with it

`expires_at` and `now` are UTC milliseconds. The doc comment on `role_of` no longer
says "the same clock" but names the **two** clocks and the condition between them.
ADR-0024 stays valid; its sentence about monotonic clocks concerns local timeouts
(ADR-0005, ADR-0010), not this lease.

### Determination 2: the ordering condition

> **max. tolerated clock skew < `FENCE_MARGIN_MILLIS`**

Computed: the node stops at node time `expires_at − margin`, i.e. at leader time
`expires_at − margin + skew`. That is safe exactly when `skew < margin`. With
today's numbers that is **three seconds** — with chrony or PTP (ADR-0024) ample,
without time synchronization not.

Time synchronization is thereby an **operational precondition for single writers**,
and it stands as such in the manual.

### Determination 3: an implausible lease is not believed

If a lease reaches further than `2 × LEASE_MILLIS` into **this** node's future, it is
not honoured: the instance fences, and the reason is named. No legitimate lease can
do that — it is granted for `LEASE_MILLIS`, and the rest is skew.

The bound is **deliberately generous** (a whole lease of skew, i.e. five times the
margin). The reason is the estimation error from determination 4: a tight bar would
take a healthy single writer's role away, and an availability loss from a
mismeasurement is the worse outcome than a gross skew that stands out only here.

What it catches is the **grotesque** case — a machine without time synchronization, a
clock set back, a restored VM. What it does **not** catch is the range between
`margin` and `LEASE`; for that determination 2 is the promise and determination 4 the
eye.

### Determination 4: the skew becomes visible

`tg_lease_clock_skew_seconds` carries `max(0, expires_at − now − LEASE)` — a **lower
bound** on how far this node lies behind the leader.

A lower bound, because the time since the grant is unknown and positive: it
subtracts. The value therefore fluctuates by up to `LEASE_TICK` (three seconds), and
that stands on the metric. For the purpose it suffices — what is sought is the gross
skew, and that is larger than the noise.

The other direction (node **ahead of** the leader) needs no number of its own: it
fences early, and that is visible in `tg_workload_active_role` (ADR-0064).

## Why not the other options

**Option 2 (a relative duration)** moves the clock to the right place and **breaks
the security statement**: the node would start counting when it *receives* the lease,
and the leader does not know when that was. The chain "the leader grants anew at
expiry, and the old one has stopped by then" then has no common end — the transit
time would extend the old holder's lease, unobserved.

**Option 3 (a monotonic clock)** is not buildable: see above, there is no common zero
point. An attempt at it would mean satisfying a prescription by giving up the
property for whose sake it stands there.

**Option 4 (leave it)** is the option we were in, and it is rejected for exactly that
reason: this system's security statement rested on an assumption nobody had noted.
This tree has measured such assumptions as **false** twice (ADR-0043: the mitigation
the Raft port invoked did not exist; ADR-0046: the signature covered less than was
enumerated). A third unnoted assumption at the place where it is about two writers on
one volume is not tenable.

## Consequences

**Positive:**

- The condition on which ADR-0064 rests is **written out** and checkable in an
  ordering condition — like those from ADR-0033 and ADR-0076.
- The gross case fences instead of overlapping: the safe direction.
- An operator sees the skew before it bites.
- ADR-0024 is **not** rewritten; its statement is placed in context.

**Negative / Costs:**

- **Time synchronization becomes an operational precondition** for single writers. It
  already was one in fact; from here on it stands written.
- The range between `margin` and `LEASE` stays unsafe **and undetected** — the metric
  is too imprecise to cover it. Named instead of concealed: whoever wants to cover it
  needs an explicit timestamp in the slice, i.e. another format break (ADR-0072).
- A grotesque skew costs the active role until the clock is fixed. That is intended
  (the alternative is two writers) and still an availability loss.

## Risks & Open Points

- ~~**The leader has the same problem in the other direction.** If *its* clock jumps
  back, it grants leases that expire earlier than it thinks — harmless; if it jumps
  forward, every lease in the cluster becomes longer. A bar against that would be a
  check in the state machine (`expires_at − now ≤ LEASE`), and it is **not** built
  here: it belongs to the log and therefore to the command set, and its refusal would
  be a new `Rejection`.~~ **Built** — `Rejection::ImplausibleLease`, in `grant_lease`
  **and** in `renew_lease`.

  > **The justification did not hold, the measure does.** Measured, the scheduler
  > forms `expires_at = now + LEASE` from **one** reading (`scheduler.rs:855`). If the
  > leader's clock jumps forward, both numbers move with it, and the difference stays
  > `LEASE` — so the bar catches a clock jump **not at all**. What does become longer
  > is the lease as seen by the *nodes* whose clock has not jumped, and for that there
  > is the bar on the node side (the determination above: a lease over `2 × LEASE` is
  > not believed).
  >
  > What it **really** catches is a declared duration above `LEASE` — from a wrong
  > parameter, a bug in the producer, or from somebody reaching the admin service with
  > `write`; the same class ADR-0112 named for `RegisterTrust`.
  >
  > And it is **more expensive to omit** than this note suggested: measured, a lease
  > leaves the state **only through `RemoveWorkload`** — the only place in the tree
  > with `leases.remove` — and `RevokeLease` has not existed since ADR-0111. A single
  > deadline of ten years would therefore hold the active role **permanently** with
  > its holder: the fence refuses every other node as long as it is valid. The way
  > back would be to remove the workload and create it anew. A witness shows exactly
  > this outcome.
  >
  > Two things are decided beyond the note and stand as such: **`renew_lease` gets it
  > too** (it set `expires_at` unexamined and is the *frequent* path), and **there is
  > no bar downwards** — a deadline in the past costs an epoch and nothing else, and a
  > second rule does not belong in the same commit.
  >
  > Price: a new `Rejection` variant, i.e. a format break between `tgctl` and `tgd`
  > (ADR-0083 is strict everywhere). It belongs in the same coordinated window as the
  > others.
- **An explicit timestamp in the slice** would make the skew exactly measurable
  (`skew = leader_now − now`, without an estimation error). It is a field and
  therefore a format break; whether it is worth it is open.
- **No witness for the ordering condition itself.** That three seconds of skew is safe
  is computed and not measured; a proof would need two machines with adjusted clocks.

## Related ADRs

- **ADR-0024** — it requires a monotonic clock for leases; this ADR places the
  sentence in context without rewriting it (invariant 6).
- **ADR-0064** — the active-role lease, whose deadline **has to be** absolute.
- **ADR-0076** — the safety margin against which the skew is computed.
- **ADR-0020** — the audit trail's timestamps hang on the same clock.
