# ADR-0070: A changed declaration and a running container

- **Status:** accepted
- **Date:** 2026-09-01
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-runtime` (`apply`, `bundle`, `reconcile`), ADR-0010,
  ADR-0019, ADR-0063, ADR-0011

## Context and Problem Statement

An operator changes a workload's declaration — a new image tag, a different
command, different resources — and submits it with `tgctl cluster apply`. What
happens to the **running** container is decided nowhere. ADR-0010 describes
level-triggered convergence, ADR-0019 forbids disturbing running workloads without
need, and ADR-0063 decided for **one** field (a volume's size) that it takes effect
at the next start. For the declaration as a whole the answer is missing.

Measured, today's situation is not "undecided" but **mute**. A trial run against a
real container: declaration A (`api:1`, `sleep 600`) runs, then declaration B
(`api:2`, `sleep 900`) is put into the desired state, then one reconcile pass:

```text
cache contains api:2:  true
report:                untouched: [tg-probe-drift/0]
config.json contains 600: true    contains 900: false
container running:     true
```

`reconcile_one` returns immediately with `Outcome::AlreadyRunning` on
`ContainerStatus::Running`, and **nothing** in the tree compares a running
container with its declaration. The consequence: the new tag never reaches the
container — not even as an attempt — and the report calls the instance
`untouched`. That is formally correct and conceals the situation: `tgctl cluster
show` says "running", and an operator believes their change is delivered.

The question is therefore not *whether* a changed declaration should take effect
but **what its taking effect may cost** — and what holds while it has not taken
effect.

## Decision Drivers

- **ADR-0019 (keystone):** the availability of a running workload must not hang on
  a statement an operator has just typed.
- **ADR-0010:** what the agent may do autonomously is an **enumerated** list.
  "End a running container because its document has changed" is not on it.
- **ADR-0063 is the precedent** and has answered the core question once already:
  *"if it were on it, a number in the XML would be a restart trigger."* For an image
  tag the same sentence holds.
- **ADR-0011:** declarative-explicit, no auto-rebalancing. Disruptive movement
  starts from a decree, not from a derivation.
- **There is no health gate per workload.** ADR-0015 knows liveness/readiness for
  the **orchestrator's processes**, not for workloads; "healthy" here means "the
  container runs" (ADR-0061). A rolling update without that gate is a restart with
  hope.
- **Nothing happens silently** — the rule by which this finding came to light at all.

## Options Considered

- **Option A — an autonomous restart on divergence.** The reconciler compares and
  restarts. Convergent in the sense of ADR-0010 and what an operator expects of an
  orchestrator. Cost: a typo in the XML is an outage; and the movement is
  **uncoordinated** — with `replicas="2"` on two nodes both nodes see the new slice
  within one round trip and restart simultaneously. There is no surge, no order and
  no health gate with which to brake it.
- **Option B — no autonomous restart; the divergence becomes visible.** The
  declaration takes effect at the next start (as in ADR-0063), and as long as it has
  not taken effect the node reports the instance as **stale**. The trigger stays an
  action.
- **Option C — declarable per workload** (`updateStrategy="immediate"` against
  `"onRestart"`). A schema change with a process of its own, and the default would
  again be A or B — the question is thereby not answered but doubled.
- **Option D — refuse at ingest.** An `UpsertWorkload` changing a document whose
  instances are running is refused. But the state machine does not know what is
  running (that is `actual`, ADR-0004), and a cluster in which one cannot change a
  running definition is unusable.

## Decision

Chosen: **Option B**.

1. **No autonomous restart.** A changed declaration ends no running container. It
   takes effect at the **next start** of the instance — exactly like the declared
   size of a volume (ADR-0063), and for the same reason: the list of autonomous
   actions in ADR-0010 section 3 stays untouched.
2. **The divergence becomes visible, per pass.** An instance's bundle carries the
   digest of the canonical declaration it was built from; the reconciler compares it
   with the current one and reports the instance as **stale** — in the report, in the
   log and as a metric. With that the mute non-execution becomes a loud one.
3. **What is compared is the declaration, not the resolved image.** The digest
   covers the canonical document (`tg_defs::workload_to_xml`) — the same bytes that
   lie in the log and in the local cache. A **moving tag** (`pullPolicy="always"` on
   `:latest`) is therefore explicitly **not** covered: the number should say what an
   operator changed, not what a registry did.
4. **The trigger is not part of this decision.** Today there are two, and both are
   deliberate: `tgctl node drain` (the instance moves away and starts at the new
   place from the current declaration) and ending the container by hand (the
   reconciler restarts it from it). A decree of its own — a **generation in the log**
   in the form of ADR-0055 — is the obvious shape and needs a decision of its own,
   because with it come the questions of surge, order and a health gate.
5. **Stale is not a failure state.** The instance still counts as running
   (ADR-0019), does not count as failed and drags nothing along over a `requires`
   edge (ADR-0061). It carries information, not a diagnosis.

## Consequences

**Positive**

- A typo in the XML costs no running workload, and `apply` stays a harmless action.
- The non-execution is observable: a metric per workload says that a change is
  pending, instead of an operator noticing it from behaviour that has not changed.
- The list of autonomous actions from ADR-0010 stays as it is — and with it the
  argument on which ADR-0019 rests.
- The model is the same as with the volume size. An operator has to remember **one**
  rule: a declaration takes effect at the next start.

**Negative / Costs**

- **An update requires two actions.** `apply` deposits the intent, a second brings
  it into effect. That is the price of the second being a decree.
- Until then the cluster runs in a state in which desired and actual lie apart —
  visible, but apart.
- The digest lies in the bundle, and the bundle path is not instance-specific (a
  known open point). That two instances of a workload do not get in each other's way
  here hangs on `.owner`, which refuses the second.

**Risks & Open Points**

- ~~**The decree is missing** (determination 4). Until it is decided, drain and a
  restart by hand are the only paths — for a cluster with many workloads that is
  operational work.~~ — **done:** ADR-0071.
- **A moving tag stays invisible** (determination 3). Whoever runs `:latest` with
  `pullPolicy="always"` gets no information from this number; whether the resolved
  digest deserves a second number is open.
- ~~**The metric is node-local.** It stands at the agent's endpoint; the leader and
  therefore `tgctl cluster show` do not see the divergence. Whether the observed
  state should carry it (ADR-0040 determination 7 permits it) is open.~~ — **done:**
  built — `stale` travels in the report and `tgctl cluster show` names it.

## Related ADRs

- Depends on: ADR-0010, ADR-0019, ADR-0063
- Affects: ADR-0011 (the decree from determination 4 would be a placement and
  ordering question), ADR-0055 (the model for the form of a generation in the log)
