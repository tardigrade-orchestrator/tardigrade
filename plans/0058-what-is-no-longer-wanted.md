# ADR-0058: What is no longer wanted

- **Status:** accepted
- **Date:** 2026-08-27
- **Deciders:** Core team
- **Technical context:** `tg-runtime::reconcile`, `tg-runtime::oci`,
  `tg-agent::network`, ADR-0010, ADR-0019, ADR-0040, ADR-0027, ADR-0042,
  ADR-0003

## Context and Problem Statement

The node reconciler brings to life what the local desired state names. What it
does **not** name it leaves alone — even when it is running.

Measured against the code, not against the note:

| Action | What happens | What the operator expects |
|---|---|---|
| `tgctl cluster remove api` | the definition disappears from the cache | the container ends |
| `tgctl node drain n1` | the placements disappear from the slice | the node becomes empty |
| `replicas="3"` → `"1"` | instances 1 and 2 disappear from the assignment | two containers end |

In all three cases the container keeps running **forever**: it holds its address,
keeps its volume mounted, stands in DNS and answers.

`OciRuntime::kill` has **not a single caller** in production code — the sixth
occurrence of the same pattern in this project (built, tested, unused; most
recently `HostRules`). And `session::absorb` removes the definition from the cache
before anyone could use it for tearing down: after the slice the node knows
**nothing at all** about this workload any more.

"A drain that does not drain" is, in a REMIT/DORA environment, not a blemish. A
decommissioned workload that keeps accepting traffic is exactly the state an
auditor looks for.

## Why this is a decision and not a commit

Two reasons, and both per invariant 6:

1. **ADR-0010 section 3 enumerates** what an agent may and may not do without
   quorum. "Stop a workload the cluster has withdrawn" stands in **neither** of
   the two lists. The same root cause ADR-0046 named: the enumeration is the trap,
   not the individual field.
2. **ADR-0019 says "running containers are never stopped"** — with the addition
   "for loss of quorum/the control plane". Where exactly that boundary runs is
   this ADR's real question, and it can be answered wrongly in both directions.

## Decision Drivers

- **ADR-0010:** level-triggered, without an event queue; the autonomy boundary is
  the place where split brain arises or does not.
- **ADR-0019:** workload availability does not hang on the control plane; nothing
  is stopped because somebody is unreachable.
- **ADR-0040 determination 6:** the node concludes from the **content** of an
  arrived slice, never from the absence of messages.
- **ADR-0027 / ADR-0042:** a volume outlives its workload; it is deleted only by a
  separate, protected command.
- **ADR-0003:** youki with crun as a configurable fallback — switching between the
  two is foreseen.

## Options Considered

- **A — the reconciler tears down**, level-triggered, against what the runtime
  really has running.
- **B — the slice tears down:** `session::absorb` stops what it removes from the
  cache.
- **C — a tombstone per workload**, as with the volumes (ADR-0042).
- **D — do not tear down at all**, an operator stops by hand.

### Why not B

Because it is edge-driven. A slice arriving while the agent happens to be
restarting is missed — and nobody comes back to it. That is exactly what ADR-0010
built level-triggering against: "a restarted agent is, after one pass, exactly as
far along as one that has been running." A teardown that hangs on a message is a
teardown one can lose.

### Why not C

A tombstone is the right answer when the **absence** is ambiguous — with a volume
it is, because "no longer placed here" and "should go" are two different things
(ADR-0027). With a running container it is not: what this node should run is said
completely by the slice. A tombstone would be a second enumeration of the same
fact, with a retention period of its own — and the open point "how long does a
node hold a tombstone" is already inherited from ADR-0042.

### Why not D

That is today's state. It was measured because it stood out.

## Decision

Chosen: **Option A**, with five determinations.

### 1. The reconciler tears down what the local desired state does not name

Level-triggered like everything else (ADR-0010). No event, no memory, no queue:
every pass compares what runs with what should run and reconciles the difference
in **both** directions. Until now the reconciliation was one-sided, and that was
the entire bug.

### 2. What runs is said by the runtime — not by a memory

The reconciler asks the runtime for the containers under **our** state directory
(`--root`, ADR-0003). An agent that had to remember what it had started would have
exactly the event list ADR-0010 does not want — and would lose it on restart, i.e.
in the most important case.

What is read is the **directory**, not the output of `list`. Measured:
`crun list -q` prints only identifiers, `youki list -q` prints a table **with a
header**; a parser would therefore be runtime-specific, and ADR-0003 explicitly
allows switching between the two. Both create, under `--root`, one directory per
container named after its identifier. The directory is ours: we supply it, and
nothing else writes into it.

### 3. Teardown happens only against an occupied desired state

**An empty cache tears down nothing.** "Nothing wanted" and "nothing heard yet"
look the same from the inside, and the safe reading is ADR-0019: fail-static. A
data directory that has been lost must not cost running containers.

The desired state is occupied if **one** of the two holds:

- the cache names at least one workload, or
- the node has applied at least one slice (the marker from ADR-0040).

With that a fully drained node really tears down to empty (the marker is there),
and a node with a lost data directory touches nothing.

### 4. Execution is autonomous — a supplement to ADR-0010, section 3

The list of actions permitted without quorum gains a fourth entry:

> **end a container that the local desired state no longer names.**

Justified like `SelfFence`: it is the **safe direction**. The decision itself had
quorum when it went into the log; here it is only executed, and two agents on two
sides of a partition cannot arrive at different results in doing so — the one that
has seen the slice tears down, the other lets it run. The reverse direction stays
forbidden: a container is never stopped **because** nobody is reachable.

### 5. The network goes with it, the volume does not

With the container its network namespace, its veth pair and its address disappear
— they belong to the instance and to nobody else.

Its **volume stays**. That is ADR-0027 and ADR-0042 in one sentence: a workload can
leave this node without its data being meant to go, and deleting is a separate,
protected command.

## Consequences

**Positive**

- A drain drains, a withdrawal withdraws, and `replicas` downwards takes effect.
  All three are silent today.
- Namespace, veth and address get a way back for the first time: `link::detach`,
  `netns::delete` and `Leases::release` had no caller.
- The reconciliation is level-triggered in both directions — an agent that sleeps
  through a slice catches up on the teardown in the next pass.

**Negative / Costs**

- The reconciler reads one more directory per pass. At the number of containers on
  a node that is not measurable.
- The coupling to the runtime's state layout is new. It is confined to **one**
  module (`tg-runtime::oci`) and checked against the real runtimes; the
  alternative would have been a parser per runtime.
- An operator who, on the node-local path (phase 2), takes their **last** workload
  out of the cache does not get it torn down: the cache is then empty, and
  determination 3 applies. Deliberately accepted — the reverse mistake costs
  running containers.

**Risks & Open Points**

- **The bundle stays mounted.** `bundles/<name>/rootfs` is an overlayfs and is not
  unmounted: the path is not instance-specific (a known open point), and an
  unmount would tear the rootfs away from a sibling instance. The number of mounts
  is bounded by the number of workload names placed here, so it does not grow
  without bound.

  **No longer applies: ADR-0119.** The sibling instance cannot exist on one node
  at all — `DomainLevel` knows only `site`, `hall` and `rack`, a pin with several
  instances is refused at ingest, and `.owner` catches the rest (ADR-0071, with a
  witness). The bundle is released during teardown: first unmounted, then removed,
  at the same place as network, socket and secrets. Without that the ephemeral
  volume outlived the workload, and a name that came back inherited its
  predecessor's writable layer.
- **The deadline is a number without an ADR.** Stopping happens with `SIGTERM`,
  then a fixed deadline is waited out, then removal follows (which means
  `SIGKILL`). Making the deadline configurable per workload (`terminationGrace` in
  the schema) is a question of its own and is not decided here.

  **And it is no formality, measured:** a container whose entrypoint does not
  handle `SIGTERM` runs the deadline **out in full** and dies only at the
  `SIGKILL`. The reason is not a broken runtime — `kill` reports success — but the
  rule for PID 1 in its own PID namespace: without an installed handler the kernel
  does not apply the default disposition. A lean image with `exec sleep` as its
  entrypoint is therefore **always** this case, and without the backstop it would
  stand there forever.

  **The point stays, its content does not: ADR-0129.** The number was never the
  problem — its **position in the pass** was. Measured, a single hanging container
  cost the pass 10.16 s, and the self-fence stood behind it, in the `start_order`
  loop; `FENCE_MARGIN`, by contrast, reckons with three seconds, so with a
  fifteen-second lease the ordering condition from ADR-0064 determination 7 broke
  — **two writers**, triggered by an operational action (a drain). Since ADR-0129
  the fence stands **before** the teardown, and stopping happens concurrently:
  measured 20.15 s sequentially against 11 s together for two hanging containers,
  and in the same situation the fence falls after fractions of a second instead of
  after 12.18 s. The deadline itself stays at ten seconds (ADR-0129,
  determination 3). `terminationGrace` per workload is therefore a **schema**
  question and no longer a security question; it takes the path from
  `schema/README.md`.
- Whether a torn-down container should appear in the audit trail couples to
  ADR-0020: it is observed state and per ADR-0004 does not belong in the log.

## Related ADRs

- **Supplements ADR-0010** (section 3, the list of autonomous actions) —
  additively, not replacing.
- **Draws the boundary to ADR-0019:** the trigger is content, never absence.
- **Builds on ADR-0040** (determination 6 and the marker) and **ADR-0003**
  (runtime and state directory).
- **Delimits itself against ADR-0027 / ADR-0042:** volumes do not go with it.
