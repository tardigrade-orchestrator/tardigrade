# ADR-0049: Who reports a node's capacity — and who decides it

- **Status:** accepted
- **Date:** 2026-08-25
- **Deciders:** Core team
- **Technical context:** `tg-store` (`session`), `tgd` (`session`, `scheduler`),
  `tg-consensus` (the command set), ADR-0034, ADR-0011, ADR-0040, ADR-0004

## Context and Problem Statement

ADR-0034 leaves open **who writes a node's capacity**: *"Today an operator;
having the node report it itself presupposes the authenticated agent connection
from phase 7."* That precondition has been met since ADR-0043 — the node session
is mTLS-authenticated, and the server takes the node name from the certificate.

It is the last point from the numbered list in `plans/README.md` that still needs
a decision.

## The finding

**There is no tool with which an operator sets the capacity.**
`Command::UpsertNode` does not appear in `tgctl`; the only path is a direct
`AdminClient::write`, and nothing calls it. "Today an operator" therefore
describes not a practice but a gap.

With ADR-0047 a **second** number has arrived: `reserved`. Both share the same
gap, and both are of different natures — which makes the decision easier rather
than harder.

## The separation that matters

The question sounds like one and is two:

| | What it is | Who knows it |
|---|---|---|
| **Reported** capacity | a fact about the machine | **only the node** |
| **Usable** capacity | a decision about it | **only an operator** |

Nobody else can count a node's cores; and no node can know how much of it the
cluster should take — that depends on what else runs on the machine, on
maintenance windows, on contracts.

That separation is not a new one: it is the one from **ADR-0004**. Reported
capacity is `actual` — observed, eventual, in the projection. Usable is `desired`
— in the log, consensus-backed, auditable (ADR-0020).

## Decision Drivers

- **The scheduler is a pure function of the replicated state** (ADR-0011). Every
  node computes the same thing; a new leader arrives at the same result.
- **ADR-0040 determination 7:** the session's return direction carries **observed
  state, no log entries**.
- **The blast radius of a compromised node**, as ADR-0037 describes it: *"Joining
  enters **only trust**, no capacity. […] the blast radius of a stolen token is
  therefore a node onto which nothing is placed."*
- **The gap should get smaller, not look different.** A solution in which an
  operator still types numbers per node saves them the lookup and nothing else.

## Options Considered

Two questions, and they are independent.

**Where does the reported number come from?**

- **M1 — not at all.** It stays a setting.
- **M2 — over the session.** `NodeReport` carries it; it lands in the leader's
  projection.

**How does the usable one arise from it?**

- **E1 — an absolute number per node.** An operator enters it, the report stands
  next to it for reference.
- **E2 — a share per node.** "80 % of the reported cores."
- **E3 — a policy in the cluster, the leader writes.** The operator deposits a
  rule once; the leader turns report plus rule into an ordinary `UpsertNode`.

### Why the report must never reach the scheduler

That is the determination everything hangs on, and it rules out a whole family of
designs: **`min(reported, permitted)` in the scheduler** would be the obvious
construction and the wrong one.

- **Determinism.** A report lives in the projection, is eventual and at a
  different state on every node. If the scheduler computed with it, a new leader
  would arrive at a different result than the old one — precisely the property
  ADR-0011 builds on would be gone.
- **Trust.** If the report binds, ADR-0037's sentence no longer holds: a
  compromised node reports a thousand cores and attracts every workload. The
  blast radius would grow from "a node onto which nothing is placed" to "all
  workloads".
- **Calm.** Reports come and go; placements that hang on them flicker with them.

### Why not E2

A share really does save the work — and pays for it with a number that changes
**without anybody having changed it**. Whoever adds RAM has more capacity in the
cluster the next day without having taken a decision. In itself that would be
defensible; combined with the blast-radius argument it is not: the share makes
the report **indirectly** binding, and a compromised node then simply reports
more cores.

## Decision

Chosen: **M2 + E3**, with a hard boundary in between.

### 1. The node reports what it has — as observed state

`NodeReport` carries its capacity along. It already carries `applied` and
`states` (the observed state per instance); a resource map next to that is the
same kind of statement and goes the same way. **ADR-0040 determination 7 stays
untouched:** what travels is observation, not a log command.

The report lands in the leader's projection and **nowhere else**. It is
information: it appears in `tgctl`, it appears in a metric, and it is what a
policy can refer to.

### 2. The scheduler never sees it

The boundary from the section above, as a determination: `placement::plan`
receives **exclusively** numbers from the replicated state. There is no
`min(reported, permitted)`, no fallback to the projection, no exception for "only
if nothing is entered".

A node without entered capacity therefore stays a node onto which nothing is
placed — exactly as today, and for exactly the reason ADR-0037 names.

### 3. Out of report and policy the **leader** makes a log entry

The operator deposits a rule — a new command `SetCapacityPolicy` (a working name)
with a share, a deduction and an upper bound per resource, cluster-wide or per
topology level. The leader applies it to the reported numbers and writes the
result as an ordinary `UpsertNode` into the log.

With that everything as before still holds:

- The log contains a **consensus-backed** number, as before.
- The scheduler stays pure and deterministic.
- Nobody types numbers per node.
- It is **not** the node that writes into the log but the leader on the basis of
  a policy — the same construction as the scheduler writing `AssignPlacement`
  (ADR-0011), and therefore no break of ADR-0040.

**The price belongs spelled out:** in the audit trail an `UpsertNode` appears
that no human issued. Whoever reads it in two years would otherwise look for an
operator who did not exist. The command therefore carries its origin visibly, and
the policy itself stands as a separate command, issued by a human, before it in
the log — the decision is auditable, and so then is its application.

### 4. Without a policy it stays a setting

E3 does not replace E1, it builds on it. A node without a policy keeps the
capacity somebody entered; whoever sets no policy notices nothing of this
decision. That matters, because the policy is a conjecture about a machine, and
there are machines about which one does not want to conjecture.

### 5. `reserved` follows the same rule

The reserve from ADR-0047 is likewise a decision, not an observation, and the
policy can set it along (e.g. "two cores of reserve per node"). A node reports no
reserve — it does not know what one wants to keep it free for.

### 6. And a tool for the operator

`tgctl node upsert` and `tgctl node policy` (working names) over the admin socket
from ADR-0044. Without them this decision too is only a description: the gap from
the finding is not the policy but that nobody can issue `UpsertNode` today.

## Consequences

**Positive**
- The separation lies where ADR-0004 draws it anyway: observed against desired.
- The scheduler stays a pure function of the replicated state.
- The blast radius from ADR-0037 stays what it is: a compromised node can report
  what it likes and thereby attracts no work.
- ADR-0040 determination 7 is not softened.

**Negative / Costs**
- **An `UpsertNode` without a human sender** in the audit trail. Mitigated by the
  origin on the command and the policy before it, but it remains an entry that
  arose from an observation.
- **Three more commands** in the command-set vicinity (set policy, withdraw
  policy, plus the report in the report) and two subcommands in `tgctl`.
- The policy is a conjecture about machines. Whoever sets it too generously
  overbooks — and notices only at the `NoRoom` or at the metric from ADR-0047.

**Risks & Open Points**
- ~~**How often the leader writes.** A report changes on every restart of a node;
  writing a log entry every time would be noise in the audit substrate. It needs
  a threshold ("only on a change of more than X") or a comparison against the log
  state. That belongs to the implementation.~~ — **done:** built —
  `Scheduler::apply_capacity_policy` writes only what changes.
- **What a node can report at all** is platform-dependent: cores and RAM are
  easy, a `device` from ADR-0028 is not.
- ~~**Who may set the policy** is the authorization question from ADR-0044: today
  anyone who reaches the socket may do everything.~~ — **done:** ADR-0105.

## Related ADRs

- Depends on: ADR-0004 (desired/actual), ADR-0011 (a pure scheduler), ADR-0034
  (the resource map), ADR-0037 (blast radius), ADR-0040 (the session), ADR-0043
  (the session is authenticated), ADR-0047 (the reserve)
- Affects: ADR-0034 — the open point "who reports the capacity" is thereby
  answered; ADR-0018 (two more subcommands)
