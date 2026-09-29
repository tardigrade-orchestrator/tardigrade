# ADR-0071: The decree that makes a declaration effective

- **Status:** accepted
- **Date:** 2026-09-01
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-consensus` (the command set), `tg-store` (the slice),
  `tg-runtime` (`apply`, `bundle`, `reconcile`), `tgctl`, ADR-0070, ADR-0055,
  ADR-0010, ADR-0020

## Context and Problem Statement

ADR-0070 decided that a changed declaration ends **no** running container: it takes
effect at the next start, and until then the instance is visibly stale.
Determination 4 there explicitly leaves the **trigger** open — "a decree of its
own … needs a decision of its own, because with it come the questions of surge,
order and a health gate."

Without it there are two paths, and both are measurably insufficient:

- **`tgctl node drain`** moves the instance to another node, where it starts from
  the current declaration. For a workload with a **writable volume** that does not
  work: it is node-pinned (ADR-0027), stays put and is reported. For exactly the
  workloads that matter most in a regulated environment, drain is no delivery path.
- **Ending the container by hand.** It works, requires a human on the node and
  leaves **nothing** in the audit trail (ADR-0020). "Who restarted production" is
  precisely the question an auditor asks.

An orchestrator in which a new version of a stateful workload can only be delivered
by hand and without a trace has no delivery path.

## Decision Drivers

- **ADR-0042:** the slice carries a **snapshot**, not an event. "Restart now" would
  be lost if the node happens to be away.
- **ADR-0055 is the form:** a **generation** in the log, monotonic, named by the
  operator. Whoever was away reads it on return; two operators decreeing
  simultaneously would both arrive at the same number under a computed "current +
  1", and one would lose silently.
- **ADR-0020:** a disruptive action on production belongs in the log — with an actor
  (ADR-0050).
- **ADR-0011:** declarative-explicit. Who restarts when is a decree and not a
  derivation.
- **There is no health gate per workload** (ADR-0015, ADR-0061). A system that picks
  the order itself cannot check whether the first restart went well — so it must not
  pick the order itself.
- **ADR-0070, determination 1** stays untouched: without a decree nothing is
  restarted.

## Options Considered

- **Option A — a generation in the log, per workload and optionally per instance.**
  `SetWorkloadGeneration { workload, instance, generation }`; the node restarts an
  instance whose bundle carries a lower generation. The instance field is the surge
  control: the operator rolls it themselves.
- **Option B — a generation in the log, per workload only.** Simpler, and all
  instances restart simultaneously. For `replicas="2"` that means: the service is
  gone during the restart — the same danger ADR-0070 rejected for the automatic
  case, only triggered by the operator.
- **Option C — a node-local `tgctl restart`.** Small, no log command, no format
  growth. But without a trace in the audit trail, only with a human on the node, and
  not reachable from the leader.
- **Option D — a rolling update the system drives itself.** Presupposes a health
  gate per workload that does not exist (ADR-0015 knows liveness/readiness for the
  orchestrator's processes). Without it, it is a restart with hope.

## Decision

Chosen: **Option A**.

1. **`SetWorkloadGeneration { workload, instance, generation }`** — a monotonic
   number in the log, in the form of ADR-0055. Backwards is refused, equal is done;
   an unknown workload is **refused**, not idempotently done (as with cordon:
   "restarted" on something that does not exist would look to an operator like
   "restarted").
2. **The number comes from the caller**, not from a "current + 1" (ADR-0055).
3. **`instance` is the surge control.** `None` applies to all instances of the
   workload, `Some(n)` only to one; an instance's effective generation is the
   **maximum** of the two. With that an operator rolls it themselves — and the
   system does not have to pick an order it cannot check.
4. **The node compares what its bundle carries.** At build time the effective
   generation is stored next to the digest from ADR-0070; if the desired one is
   higher, the instance is **replaced** — ended and restarted from the current
   declaration. Level-triggered: the intent stands in the desired state, not in an
   event, and a missed pass costs nothing.
5. **A bundle without a generation marker counts as generation zero.** An upgrade
   therefore triggers no restart as long as nobody has decreed one.
6. **Execution is autonomous** (`Action::RestartOnOrder`), for the same reason as
   `StopUnwanted` (ADR-0058, determination 4): the decision had quorum when it went
   into the log; here it is executed. ADR-0010 section 3 thereby gains a seventh
   entry. The price is the same as with every restart: with `pullPolicy="always"` it
   hangs on a reachable registry — that holds for a crashed instance
   (`RestartAssigned`) since ADR-0010 just as much and is not to be charged to this
   decree.
7. **`RemoveWorkload` takes the generations with it**, like placement, lease, edges
   and egress permissions. A leftover counter would be a restart that eventually
   hits a later workload of the same name.
8. **`UpsertWorkload` does not raise them.** Declaration and decree are two things —
   that is precisely the decision from ADR-0070.

## Consequences

**Positive**

- A stateful workload has for the first time a delivery path that does not move it
  and requires no human on the node.
- The action stands in the log, with an actor (ADR-0050) and in the audit archive
  (ADR-0020). "Who restarted" is answerable.
- The order lies with the human, and with it the responsibility for availability
  during the restart. The system claims no safety it does not have without a health
  gate.
- Together with ADR-0070 it forms a pair explainable in one sentence: **the
  declaration says what should hold; the generation says when it takes effect.**

**Negative / Costs**

- **Two actions per delivery**, and with `replicas > 1` one per instance. That is
  operational work — and the alternative would be an automatic procedure without a
  checkpoint.
- A format growth on the slice and one more command in the log. The growth is **no**
  break: the new field carries `serde(default)`.
- The operator has to know the number. Without a read path that means: they count
  themselves.

**Risks & Open Points**

- ~~**There is no read path for the generations.** `tgctl cluster show` does not
  name them; whoever does not know the current number guesses. A refused decree says
  what did not work, but not what holds.~~ — **done:** built — `tgctl cluster show`
  names the generation per instance.
- **No health gate**, hence also no assurance that the new generation comes up. It
  is started; whether it runs is said by the actual state.
- ~~**The bundle path is not instance-specific** (an open point since ADR-0027).
  That two instances of a workload do not get in each other's way here hangs on
  `.owner`.~~ — **measured, and the assurance now has a witness.** It hung on a
  function **without** a test: `BundleTaken` had exactly one producer in the whole
  tree and no check. All three outcomes of `claim` are now tested — a foreign owner
  refused (with **both** identifiers in the message), the same one permitted again
  (a restart), no marker permitted (an upgrade) — plus that a refused claim does
  **not** rewrite the marker.

  The structural half was already guarded and has been re-measured: `DomainLevel`
  knows only `site`, `hall`, `rack` — there is no level that would leave two
  instances on one node — `Demand::validate` refuses a pin with several instances,
  and `instances_of_a_workload_never_share_a_rack` as well as
  `more_instances_than_domains_are_rejected_not_collapsed` pin both down. `.owner`
  is therefore the backstop and not the only barrier.

  **The path stays as it is**: making it instance-specific would move the bundles of
  all running containers — the same upgrade pitfall as with the container name in
  10c.
- **`Quorum` in the agent is a command-line setting**, not a state derived from the
  session — measured while scoping this decision. A quorum-obliged classification of
  the execution would therefore have been an assurance without an input; with
  determination 6 it is also not needed in substance. That the input is missing is
  an open point of its own and older than this ADR.

## Related ADRs

- Depends on: ADR-0070 (the visibility), ADR-0055 (the form of a generation),
  ADR-0042 (state instead of event), ADR-0058 (the justification for autonomous
  execution)
- Affects: ADR-0010 (a seventh autonomous entry), ADR-0020 (the action in the
  archive)
