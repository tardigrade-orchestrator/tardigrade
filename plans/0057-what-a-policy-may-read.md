# ADR-0057: What a policy may read

- **Status:** accepted
- **Date:** 2026-08-26
- **Deciders:** Core team
- **Technical context:** `tgd::scheduler`, `tgd::session`, ADR-0049, ADR-0054,
  ADR-0055, ADR-0011, ADR-0019, ADR-0004, ADR-0050

## Context and Problem Statement

Three times the same parked decision stands in this project: "whether a
**policy** should do that is not decided here".

| Case | The rule that was meant | State |
|---|---|---|
| Capacity (ADR-0049) | "take 80 % of the reported cores" | **built** |
| Detachment (ADR-0054, D3) | "detach what has been silent for N hours" | parked |
| Rotation (ADR-0055, D6) | "rotate every 90 days" | parked |

All three have the same construction: an operator deposits a rule, the **leader**
computes an ordinary log command from it with `Origin::Policy` (ADR-0050). And
all three pay the same price: in the audit trail there stands an entry **without
a human sender**.

Three times "not decided" is not a decision but an open question that gets asked
again with every new case. It belongs answered once.

## The finding: the three read different things

Measured against the one that is built: `apply_capacity_policy` **skips** a node
for which no report is present (`continue`). An outage therefore makes the policy
**fall silent**.

That is exactly the reverse with detachment: there the **absence** of a report is
the input. An outage **produces** it — and not one at a time: a switch takes a
whole rack out of view, and the policy would hit all the nodes in it
simultaneously.

Rotation reads neither, but the **clock**. No outage makes keys age faster.

## Decision Drivers

- **ADR-0011:** declarative-explicit, no auto-rebalancing.
- **ADR-0019:** workload availability is decoupled from the control plane;
  nothing is stopped for reachability.
- **ADR-0004:** intent into the log, observation into the projection.
- **ADR-0050:** whoever caused an entry stands on the entry.
- **ADR-0037:** the blast radius of a compromised node is "a node onto which
  nothing is placed".

## Options Considered

- **A — a rule about the inputs:** a policy may only read what an outage does
  **not produce**.
- **B — no clock:** policies read only observations.
- **C — permit everything**, with limits and damping (hysteresis, a minimum
  quorum, rate limiting).
- **D — keep deciding case by case.**

### Why not B

It forbids the most harmless of the three cases and permits none of the dangerous
ones. The clock is not the problem: it is the only input an outage is guaranteed
**not** to influence. What a rotation by age risks is a missing sender in the
audit trail — not a chain reaction.

### Why not C

Because damping shifts the question instead of answering it. A policy that
detaches "only" two nodes on a rack outage has detached two nodes too many; and a
minimum quorum is a number that is wrong in an emergency precisely when it
matters. This project has rejected the same kind of solution three times already
(ADR-0011, ADR-0049, the liveness separation in 11b).

### Why not D

Because the question then starts over with the fourth case — and because the three
cases, once laid side by side, differ **clearly**.

## Decision

Chosen: **Option A.**

### 1. The rule

> **A policy may only read inputs that an outage does not produce.**

Permitted are therefore **present observations** (a report a node has sent) and
the **clock**. Forbidden is the **absence** of an observation — silence, a missing
heartbeat, a cut cable.

The reason in one sentence: what an outage itself produces must not amplify it. A
policy on present reports falls silent during an outage; a policy on absence is
**driven** by it, and simultaneously for all nodes behind the same disturbance.

### 2. What a policy may never do

Independently of its input. It may write **no** command that

- **places or displaces** workloads (that is the scheduler, ADR-0011),
- **revokes trust** (`RevokeTrust` is a security action),
- **removes** a node (`RemoveNode` frees the ordinal, ADR-0039),
- **deletes data** (`DeleteVolume` requires an explicit action, ADR-0027).

**Added during the build, and the exhaustive `match` forced it:** the list stands
on the **command set** (`Command::may_be_policy`), and what is permitted there is
**exactly the two decided cases** — `UpsertNode` (ADR-0049) and
`SetKeyGeneration` (ADR-0055). Everything else is forbidden, including what was
not enumerated above:

- **A policy changes no policy.** My first draft had permitted
  `SetCapacityPolicy` — with that a policy could have extended its own powers.
- **Cordoning and detaching are likewise forbidden.** With that determination 3 is
  not merely a rule about the input but **structurally** enforced: auto-detach
  cannot be built without touching this list — and whoever touches it holds the
  conversation.
- **Admission, definitions and authorization** are declared by a human. A policy
  that could grant edges or egress destinations would be a hole in deny by
  default.

Permitted here therefore means **decided**, not "looks harmless".

This list is the actual barrier. It keeps the blast radius of every future policy
small without having to know the policy itself — and it is the reason why the rule
in determination 1 suffices, instead of checking every policy individually.

### 3. Auto-detach: no, and not "later"

The rule excludes it, and that is the right answer and not a deferral. A
detachment after silence turns a network glitch into a topology change; with a
disturbance affecting several nodes it does so for all of them at once. That
detachment includes emptying anyway (ADR-0054, determination 5) makes it worse:
the scheduler carries the instances away while the cluster is busy surviving
something else.

Whoever wants a silent node detached decrees it — the action takes one command.

### 4. Silence must therefore be **visible**

A refusal that gives the operator nothing to work with is cheap. Measured,
**nobody** today knows how long a node has been silent: the projection holds its
report but not its time.

So: the leader records per node **when** it last reported, and turns that into a
metric. It decides nothing (ADR-0011), it shows — and an alerting rule may sit on
it that wakes a human. That is the division of labour this project has chosen at
every comparable place.

**In the projection, not in the log** (ADR-0004): a timestamp from an observation
is observed. And it lives per leader — after a failover the measurement starts
anew, which is right: the new leader really has not heard anything from this node
yet.

### 5. Rotation by age: yes, as a time window

Permitted, because the clock is not an outage input. It is built **without new
state**: the desired generation is a function of time.

```text
desired = (days_since_epoch + offset(node)) / period
```

With that nobody has to keep a "last rotated on" — it would be a second place for
a fact that can be computed (the same consideration as with the `AllowedIPs` in
ADR-0039). The generation is monotonic by construction, and `SetKeyGeneration`
refuses backward steps anyway (ADR-0055).

**The per-node offset is not decoration.** Without it all nodes rotate on the same
day, and all tunnels rekey simultaneously. With it the changes lie apart,
deterministically derived from the name.

**A manual rotation wins.** If a human sets a higher generation, it lies above the
time window, and the policy writes nothing — until the window overtakes it. No
dispute between human and clock.

### 6. The price stays the one from ADR-0049

In the audit trail there stands an entry without a human sender. Mitigated as
there: the origin stands on the command (`Origin::Policy`, ADR-0050), and the
policy itself is a command issued by a human standing **before** it in the log. An
auditor can read the chain: here somebody decreed a rule, and afterwards the rule
took effect.

The price is not new, and that is why it is not weighed a second time here — it is
only named.

## Consequences

**Positive**
- The question is answered once and not open three times.
- The dangerous case is **excluded**, not damped — and instead of the automation
  the operator gets what they really need: visibility.
- The prohibition list in determination 2 makes every future policy checkable
  without knowing it.
- The rotation policy comes without new state and without a format change.

**Negative / Costs**
- An operator who wants auto-detach does not get it. That is deliberate, and it is
  a restriction.
- Rotation by age produces log entries without a sender — the price from ADR-0049.
- An offset derived from the name means: a renamed node rotates once outside its
  rhythm. Inconsequential, but surprising.
- The metric for silence lives per leader. After a failover it is young, and an
  alerting rule on it has to know that.

**Risks & Open Points**
- ~~**Who may set a policy?** Today: whoever reaches the admin socket (ADR-0044).
  For a rule that writes into the log by itself that weighs more than for a single
  command.~~ — **done:** ADR-0105.
- **The period and the offset** are numbers an operator supplies; a default ("90
  days") is a figure and not architecture — it belongs in the implementation, not
  here.
- **Whether further cases follow** (capacity is built, rotation is coming) is
  open; the rule applies to them in advance.

## Related ADRs

- Depends on: ADR-0049 (the first policy, and its price), ADR-0004, ADR-0011,
  ADR-0019, ADR-0050
- Answers the parked point in: ADR-0054 (determination 3, **rejected**) and
  ADR-0055 (determination 6, **permitted**)
