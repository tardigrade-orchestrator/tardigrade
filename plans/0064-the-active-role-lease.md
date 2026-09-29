# ADR-0064: How the active-role lease reaches the log

- **Status:** accepted
- **Date:** 2026-08-30
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tgd` (scheduler), `tg-store` (the slice),
  `tg-agent`/`tg-runtime` (reconciler), ADR-0010, ADR-0040, ADR-0057

## Context and Problem Statement

ADR-0010 makes the active-role lease the core of its autonomy boundary:

> **The active role = a quorum-backed lease with a fencing epoch.** The minority
> side cannot renew → self-fence. On the majority side: a warm, pre-placed
> standby takes a lease with a higher epoch from the quorum → activates
> **quickly**.

Measured, only one half of that is there. The state machine knows `Lease` with an
epoch and a deadline, knows `GrantLease`, `RenewLease` and `RevokeLease` (the last
struck by ADR-0111 — it lifted the fence) and has their refusals (`LeaseHeld`,
`NotHolder`, `LeaseExpired`, `NoLease`). The other
half is entirely missing:

- **Nobody produces the three commands** — in production code they appear only in
  their own `match` arms.
- **The lease does not travel in the slice** (ADR-0040); a node never learns
  whether it has the active role.
- **`Action::SelfFence` has zero producers**, although it stands in the list of
  autonomous actions.

Fast failover for single-writer workloads is therefore a promise without
mechanics — and precisely the promise for whose sake ADR-0010 drew the autonomy
boundary the way it did.

**The real question is not whether to build but how a lease request reaches the
log.** An agent cannot write into the log: ADR-0040 determination 7 lets the
session's return direction carry **observed state** and no log entries, and
ADR-0042 therefore chose the credential path for the underlay announcement. That
one carries every three hours; a lease carries fifteen seconds (ADR-0014).

## Decision Drivers

- **ADR-0040 determination 7** stays untouched: no log entry at a node's request.
- **ADR-0057:** a policy may only read inputs that an **outage does not produce**.
  Present observations and the clock yes, **absence** no.
- **ADR-0019:** a running workload is not stopped for loss of quorum — with the
  explicit exception ADR-0010 itself names: a single-writer instance **must**
  self-fence, because two writers are worse than none.
- **Split-brain safety:** the minority side must not be able to renew.
- The figure from ADR-0014: lease 15 s.

## Options Considered

- **Option A — the node asks.** A new call on the session or a port of its own
  through which an agent requests `GrantLease`/`RenewLease`. Closest to ADR-0010's
  wording ("the standby takes a lease"), but it breaks ADR-0040 determination 7
  and gives a compromised node a write path into the log.
- **Option B — the leader grants and renews.** The leader computes from the
  replicated state and the **present** reports who has the active role, and writes
  `GrantLease`/`RenewLease` itself — the same construction as the scheduler with
  `AssignPlacement` and the capacity policy with `UpsertNode` (ADR-0049). The lease
  travels back in the slice.
- **Option C — the lease is purely local.** The agent decides for itself. Falls
  away: a lease without quorum is no fencing, and the minority side would give
  itself the active role.

## Decision

Chosen: **Option B**.

1. **The leader grants, the node learns.** An agent requests nothing. The leader
   writes `GrantLease` for the node holding the placement of instance 0 of a
   single-writer workload, and `RenewLease` as long as that node **reports**.
   ADR-0040 determination 7 stays untouched.

2. **Renewal happens on an observation, not on an absence** (ADR-0057). A report is
   there or not there; it is read only when it is there. **Expiry is time, not
   silence:** a lease nobody renews lapses by itself. The leader does not have to
   detect silence, and a network glitch produces no decree.

3. **The lease travels in the slice** — as an entry of its own with epoch and
   deadline, and **only its own**: who holds the active role elsewhere is no
   business of a node (ADR-0040, least privilege).

4. **Without a valid lease a single-writer instance does not start.** That is
   ADR-0010's "activation needs a lease grant from the quorum" and the place where
   the minority side fails.

5. **Self-fence is autonomous and local** (ADR-0010, section 3). If the lease
   expires, the agent stops the instance — **without** asking the cluster, because
   that is precisely when it cannot ask. Measurement is against the **local clock**
   against the deadline from the last slice; a deadline only the leader knows would
   not help the minority side.

6. **A self-fenced workload counts as stopped, not as failed.** It did what it was
   supposed to. A `failed` would moreover trigger the requirement cascade from
   ADR-0061 and drag dependents along — for an orderly role change that would be
   wrong.

7. **The holder fences itself *before* the lease expires** — not at its expiry.

   **Added after the build, because determination 5 as written does not hold.**
   Computed: the lease runs 15 s, the agent notices the expiry only at the next pass
   (default 10 s), and then it stops with a grace period of 10 s (ADR-0058). The old
   holder can therefore still be running **up to 20 seconds after expiry** — while
   the leader has already granted the lease to the new holder at expiry. Twenty
   seconds with two active writers are exactly what this lease is meant to prevent;
   the line "the price of there never being two writers" under costs was therefore
   wrong.

   Measurement is therefore against `expires_at − safety margin`, and the margin
   covers what the holder knows about itself: **detection latency (one pass) plus
   stop time (the grace period)**. Both are local and known — unlike the leader's
   clock or the network's latency.

   **The holder carries the obligation, not the leader.** Making it wait before
   granting anew would be the other construction and the worse one: only the holder
   knows when it really stopped, and only it can guarantee it. A leader that waits
   out a deadline relies on an assumption about a foreign process.

   Activation therefore still takes one lease period; what changes is that the old
   holder is **gone beforehand**.

   **And from that follows an ordering condition**, as ADR-0033 established one for
   consensus:

   > detection latency + stop time **<** lease period.

   It is not a subtlety but the condition for a single writer running at all: if it
   does not hold, every freshly granted lease already lies within the margin, and
   the instance fences itself immediately after every grant.

   **Measured, it did not hold with the default values** — a reconcile interval of
   10 s plus a grace period of 10 s (ADR-0058) yields a 20 s margin against a 15 s
   lease (ADR-0014). With the safety margin alone the active role would therefore
   **never** have started.

   Decided: **a fenced container gets a short deadline of its own** instead of the
   grace period from ADR-0058. A fence is not an orderly shutdown but a **safety
   stop** — it happens precisely because the instance may no longer write. Two
   seconds suffice for closing open connections and leave the ordering condition
   room (10 + 2 = 12 < 15).

   The alternative would have been to shorten the reconcile interval. It was
   rejected: changing a number that concerns the whole reconciliation because of a
   property only single writers have would shift the cost onto everyone.

   **The condition is checked, not assumed.** If it does not hold — e.g. because an
   operator sets `--interval 30` — the agent reports it at startup. A single writer
   that silently never starts is the worse outcome.

8. **Only `kind="singleWriter"`, only instance 0.** A replicated workload has no
   active role and needs no lease; binding it to one would mean shutting it down
   without quorum — the opposite of ADR-0019.

## Consequences

**Positive**

- The core of ADR-0010 is built instead of promised: the minority side fences
  itself, the majority side activates.
- No new write path into the log, no listening port on the agent, no softening of
  ADR-0040.
- The construction is the third of its kind (scheduler, capacity policy, rotation
  policy): a pure function `state → commands` in the leader.

**Negative / Costs**

- **Activation takes at least one lease period.** The standby starts only once the
  old lease has expired and the leader has written the new one. Fifteen seconds are
  the price of there never being two writers — **and that price is only really paid
  through determination 7.** Without the safety margin old and new holder would
  overlap by up to twenty seconds.
- **A single writer without a reachable leader no longer runs after expiry.** That
  is the exception to ADR-0019 that ADR-0010 wants, and still an availability loss
  an operator has to know about.
- The slice grows by a field; old nodes do not read it (`serde` `default`), new
  nodes at an old leader get no lease and do not start their single writers. A
  coordinated switchover, the fifth after ADR-0042, -0046, -0050 and -0055.

**Risks & Open Points**

- ~~**Downstream enforcement is not part of this decision.** ADR-0010 names as a
  refinement that sidecars refuse a stale epoch. That requires the epoch on the
  wire and is a cut of its own; without it the fencing bites at the **holder** and
  not at the counterpart.~~ — **done:** ADR-0066.
- **The period is a number in the code** (15 s, ADR-0014). Whether it should be
  configurable per workload is not decided.
- ~~**The safety margin from determination 7 has to fit the period.** With a pass
  interval above 5 s nothing is left of the 15 s, and the holder would fence itself
  immediately after every grant. The agent has to **report** that instead of
  accepting it; a check at startup would be the better place and is not built.~~ —
  **done:** ADR-0076 — the margin is `grace period + floor` and hangs on no setting.
- A leader change restarts the renewal; the lease meanwhile runs on, because it
  stands in the log. With a very long election it can expire and the workload fences
  itself — correct, but it couples single-writer availability to the election time
  (ADR-0033).

## Related ADRs

- **ADR-0010** — reconciliation and the autonomy boundary; this ADR redeems its
  section 4.
- **ADR-0040** — determination 7 stays untouched; the lease travels in the slice.
- **ADR-0057** — the boundary of a policy; renewal happens on an observation,
  expiry is time.
- **ADR-0019** — the explicit exception for single writers.
- **ADR-0061** — a self-fenced workload is stopped, not failed.
