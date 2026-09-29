# ADR-0117: The Class of a Placed Workload

- **Status:** accepted
- **Date:** 2026-09-11
- **Concerns:** ADR-0085 (the decree reaches the sidecar), ADR-0066
  (enforcement of the active role), ADR-0070 (changed declaration), ADR-0064
  (the lease)

## Context and Problem Statement

ADR-0085 hung the sidecar on the generation of its principal and left an open
point:

> **Changing the class of a running workload stays delicate**: between the
> upsert and the decree it runs as a single writer without reins. Whether the
> ingest should permit a class change at all is not decided.

Measured against the state machine, on a **placed** workload:

```text
before single_writer=Some(false)  outcome=Applied  after=Some(true)  placements=1
GrantLease after the change: LeaseGranted { epoch: Epoch(0) }
back to replicated: Applied
```

The change is accepted in **both** directions, and the lease follows
immediately. `upsert_workload` carries seven ingest checks, and none of them
looks at the previous class; it simply says
`single_writer: workload.class().is_single_writer()`.

### Why that is more than a late effect

Three decisions already taken interlock:

- **ADR-0070**: a changed declaration reaches a running container only at the
  **next start**.
- **ADR-0085**: the sidecar inherits its principal's generation — a **decree**
  is needed for it to restart.
- **ADR-0066**: the sidecar is the enforcer, and whether it is affected stands
  as `--single-writer` in the command line, derived from the document **at
  start time**.

From that it follows for `replicated → single-writer`: the leader grants an
active-role lease, the state machine accepts `GrantLease` and
`SetActiveInstance`, `tgctl cluster show` shows a role — and the running
sidecar reins in nothing, because it lacks the flag.

**The cluster believes it is fencing, and nothing is fenced.** That is the
inversion of what ADR-0066 exists for, and it is **invisible**: every display
shows green. Two writers on one volume are exactly the outcome ADR-0010 calls
"structurally excluded".

The opposite direction is the availability case: after
`single-writer → replicated` the leader grants no more leases, but the running
sidecar still carries its `--single-writer` — and thereby refuses traffic in
both directions (ADR-0066). The workload falls silent without anyone having
stopped anything.

## Options Considered

- **A — leave it** and write in the operations manual that a class change must
  be followed immediately by a decree.
- **B — reject at ingest** as long as the workload is placed.
- **C — the leader jumps itself**: a class change automatically raises the
  generation, the execution is then the one from ADR-0071.
- **D — the lease follows the running class** instead of the declared one.

## Decision

Chosen: **B**.

### Determination 1 — a class change on a placed workload is rejected

`UpsertWorkload` checks the class against the stored one. If they differ **and**
the workload carries at least one placement, the command is rejected.

The way is stated in the rejection: **withdraw, then declare anew.** That is
not a detour but the honest form. A single writer may not start up at all
without a valid lease (ADR-0064, determination 5); the class is therefore not a
property one flips during operation but one that determines the start. Whoever
changes it changes what this workload **is**.

### Determination 2 — "placed" and not "declared"

The barrier is the narrowest that can be decided **from the log alone**. The
state machine must not read observed state (ADR-0004, ADR-0049) — "runs" is
exactly that, and it would not be available to it without giving up the
determinism on which ADR-0011 rests.

Placement is desired state and thus admissible. It is an **overestimate** of
"runs": a placed workload may not be running yet. The overestimate is the safe
direction — it rejects more than it would have to, and never less.

Not placed means: nothing can be running, so there is no gap. An operator who
corrects a class seconds after the first upsert gets through, and so they
should.

### Determination 3 — no new rejection variant

The rejection is `UnplaceableDefinition { workload, detail }`. The variant
already carries this class of ingest findings (unsatisfiable constraints,
storage rules, `Conflicts`, mesh names, the stranded active instance); a new one
would be a **format break for the same statement** — the argument from
ADR-0084.

### Determination 4 — the leader does not jump itself

Option C is rejected. A leader that computes a log command from a state is a
**policy**, and ADR-0057 enumerates exhaustively what a policy may write:
`UpsertNode` and `SetKeyGeneration`. A generation belongs expressly to the
operator per ADR-0071 — it is the place at which the audit trail records **who**
restarted production.

And it would not even solve the problem: between the upsert and the execution
on the node would lie the same gap, only shorter. A safety promise that depends
on a round-trip time is none.

### Determination 5 — the lease follows the declaration, not the run

Option D is rejected. The leader does not know the running class; it knows the
report, and that is observed state (ADR-0004). Hanging the lease on it would
mean basing a safety decision on an eventually consistent view — and a node
that is currently silent would thereby help determine who may write.

## Consequences

**Positive**

- The gap is **structurally** closed: there is no longer a state in which the
  cluster carries an active role and the sidecar does not enforce it.
- The rejection is deterministic and decidable from the log — it comes out the
  same on every node, in the test harness too.
- The finding was invisible; the rejection is not. An operator learns on
  issuing what is to be done instead of never learning it.

**Negative / costs**

- **A class change costs a withdrawal from here on**, hence an interruption.
  That is the price, and it is the right one: the same workload as a single
  writer is a different workload — it hangs on a lease, its sidecar reins in,
  and its standby does not take over by itself.
- A **volume** survives the withdrawal (deletion happens only with
  `DeleteVolume`, ADR-0027/0042), but the instance numbers are reassigned and a
  decreed active instance goes with it. Whoever wants it back issues
  `tgctl cluster promote` again.
- The ingest thereby reads an **eighth** condition. It is the cheapest of them
  all — a comparison of two bits against the stored entry, without parsing the
  document, which is parsed anyway.

**Risks & open points**

- **The gap stays open for the unplaced case**, and deliberately so: if a
  workload is reclassified between upsert and first placement, nothing is
  started, and the planner works with what is there then.
- **A class change across a withdrawal is not atomic.** Between
  `RemoveWorkload` and the new `UpsertWorkload` there is a moment in which the
  workload is wanted nowhere — the sweeper (ADR-0058) ends it in that moment.
  That is the point and nevertheless an operations action one prepares for.
- **What concerns `kind` and other fields is not decided along with it.** The
  class is the only setting on which a **safety** promise hangs; other changes
  take effect at the next start and have been visible since ADR-0070. Whether
  there are further ones whose change during a run is dangerous is a question
  this decision does not pose.

## Related ADRs

- **Redeems:** **ADR-0085**, open point *"Changing the class of a running
  workload stays delicate … Whether the ingest should permit a class change at
  all is not decided."*
- **Protects:** **ADR-0066** (the sidecar enforces — without this check it
  could not), **ADR-0064** (the lease), **ADR-0010** (split brain structurally
  excluded).
- **Applies:** **ADR-0061** (reject at ingest instead of enforcing at runtime —
  the same choice as with `Conflicts`), **ADR-0084** (no new variant for the
  same statement), **ADR-0004/0049** (no observed state in the state machine),
  **ADR-0057** (no leader that invents a decree).
- **Touches:** **ADR-0070** (the late effect that produces the finding),
  **ADR-0071** (the generation stays a human's action), **ADR-0027** (a volume
  survives the withdrawal).
