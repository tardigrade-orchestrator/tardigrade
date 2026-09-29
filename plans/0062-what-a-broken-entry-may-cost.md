# ADR-0062: What a broken entry may cost

- **Status:** accepted
- **Date:** 2026-08-28
- **Deciders:** Core team
- **Technical context:** `tg-runtime::reconcile`, `tg-runtime::state`,
  `tg-model::graph`, `tg-agent`, ADR-0019, ADR-0010, ADR-0058, ADR-0061,
  ADR-0015, ADR-0014

## Context and Problem Statement

While correcting a note on ADR-0061 it became apparent that an ordering cycle in
the local desired state ends the pass. Measured, that is the **smallest** case of
a whole family — and the most expensive one is trivial to trigger.

A single unreadable entry in the desired-state cache, measured against a real
`tg-agent`:

```text
ERROR tg-agent terminated: workload '…/desired/broken.xml' cannot be mapped:
entry in the desired-state cache is unreadable
EXITCODE: 1
```

And the same entry, arriving **during operation**, kills the running process:

```text
WARN  not reconciled, will retry            failed=1 interval=1s
ERROR tg-agent terminated: …/desired/late.xml … is invalid
EXITCODE: 1
```

Under any supervisor the exit code turns that into a **crash loop**: the process
starts, reads the same entry, dies.

### Why this hits ADR-0019 at its most sensitive point

The agent is not the containers' parent process; they keep running. What dies with
it is everything else:

- **The workload API socket.** It hangs on the same runtime. SVIDs carry 15 min
  with a 2 min grace period (ADR-0014) — after a good quarter of an hour **every
  mTLS connection on this node** breaks, while the containers run.
- **The resolver.** Names no longer resolve (ADR-0013).
- **The reconcile loop.** A crashed instance is no longer restarted — the one
  autonomous action ADR-0010 explicitly permits.
- **The session to the control plane** (ADR-0040) and with it every correction
  that would come from there.

That is the inversion of the keystone: ADR-0019 decouples workload availability
from the control plane, and here it hangs on the well-formedness of **one file**.

### How reachable that is

The write path is durable (`put`: temp, `fsync`, `rename`, directory `fsync`), so a
half-written file does not arise there. It remains reachable nonetheless:

- **A rollback to an older version of the agent.** A document using a newer schema
  version is unreadable to the older loader. This project already carries four
  format breaks with a "coordinated switchover" — exactly this case.
- **A cycle needs no corruption at all.** `tgctl` refuses it on both client paths, a
  direct `AdminClient::write` does not — and per ADR-0044 whoever reaches the socket
  may do so.
- **Handwork in the data directory**, an incompletely restored backup, a filesystem
  error.
- **A doubly declared name** from a hand-placed file with several workloads.

None of these paths is everyday. All of them end in the worst possible state, and
none is recognizable to an operator before it happens.

### Why this is a decision and not a commit

Because the question is not "is this a bug" but **how much a single broken entry
may cost** — and there are three defensible answers to that with very different
costs. ADR-0019 says what must not happen; ADR-0058 drew the same boundary for the
teardown and needed an ADR of its own for it. This is its counterpart: there it was
about when something **may** be ended, here about when something **must not** take
place.

And it touches ADR-0061 determination 1 directly: the node view is lenient towards
foreign targets and hard on cycles. That "hard" costs the process did not stand
there — it is added here and decided here.

## Decision Drivers

- **ADR-0019:** workload availability is decoupled from everything above it.
  Nothing is stopped because something else is unavailable.
- **ADR-0010:** level-triggered. A pass that fails costs nothing if the next one
  sees the same state.
- **ADR-0058 determination 3:** "nothing wanted" and "nothing heard yet" look the
  same from the inside, and the difference costs running containers.
- **ADR-0015 / phase 11b:** liveness and readiness are separate. A node that
  **cannot** work is not-ready, not dead.
- **ADR-0061:** the node view tolerates foreign targets; cycles stay hard.

## Options Considered

- **A — the process dies** (today).
- **B — the process lives, the pass dies:** `run_with` no longer aborts, reports and
  tries again in the next tick.
- **C — the process lives, and what can be isolated is isolated:** a broken entry
  costs its workload, the rest is reconciled.
- **D — skip broken entries silently.**

### Why not A

See above: the price is a crash loop and the loss of identity, resolution and
reconciliation — for an error concerning exactly one workload.

### Why B does not suffice

B fixes the worst and leaves a remainder that counts in this environment: a single
broken entry freezes the reconciliation of the **whole node**. A crashed instance
of a completely unrelated workload would then no longer be restarted — at a target
availability of 4-9 to 5-9 that is not an acceptable resting state. B is half the
answer and is contained in C.

### Why not D

Because a skipped entry would be indistinguishable from an absent one — and that is
exactly the confusion ADR-0058 determination 3 is built against. A silently skipped
workload would look to the teardown like "no longer wanted".

## Decision

Chosen: **Option C**, in six determinations.

### 1. No error of a pass ends the agent

`run_with` no longer passes `once` outwards. A failed pass is reported, and the
next tick tries again — that is level-triggered (ADR-0010) and it is self-healing:
if the entry is corrected, the node recovers without intervention.

The agent is ended only from outside. What previously made it fail **at startup** is
therefore no longer a reason either: startup reads the cache, and a cache with a
broken entry is a state, not a startup error.

### 2. What can be isolated costs its workload — not the node

Isolated are:

| Finding | What is isolated |
|---|---|
| document not readable | this entry |
| doubly declared name | **all** carriers of this name |
| self-reference | this workload |
| ordering cycle | the members of the cycle |

With a duplicate name **both** are deliberately isolated: nobody knows which was
meant, and taking one of them would be guessing. The cycle is resolved by removing
its members and searching again — every round removes at least one, so it
terminates.

All other workloads are reconciled entirely normally.

### 3. Isolated means neither started nor stopped

An isolated workload is not touched. If its container runs, it keeps running
(ADR-0019). It is reported as failed, because something is wrong with its
definition and an operator has to act — but "I cannot place you" is not "nobody
wants you any more".

### 4. An incompletely formed desired state does not tear down

If anything was isolated in a pass, **nothing is torn down** in that pass (an
extension of ADR-0058 determination 3).

The reason is the same as there and it is compelling: an unreadable document names
no workload, so its container is missing from the set of what is wanted — and the
teardown would end it. A file error must never cost a running workload. The price
stands in the consequences: as long as something is isolated, what should go stays
lying on this node. That is the safe direction, and it is visible.

### 5. The watchdog is struck, readiness is withdrawn

A node that cannot reconcile is **not-ready**, not dead — the same separation as
with loss of quorum in phase 11b, and for the same reason: if liveness hung on it,
the finding would produce exactly the restarts determination 1 has just abolished.

The strike therefore stays in the **per-pass callback** (phase 11b: "a strike from a
timer of its own would attest the timer") and the callback is invoked even when the
pass has failed. Its parameter therefore becomes a result: the caller sees what
happened instead of inferring it from an absence.

### 6. None of this is done silently

Every isolated entry is named — with its name and the reason — and the report is not
clean as long as something is isolated. A node that does not understand half its
desired state while looking calm would be worse than one that dies.

## Consequences

**Positive**

- A broken entry costs its workload. Identity, resolution, session and the
  reconciliation of all other workloads carry on — that is the promise from
  ADR-0019, for the first time also against this case.
- No more crash loop, and none an operator recognizes only from an exit code.
- Self-healing: a corrected file takes effect at the next tick, without anybody
  restarting anything.
- The cycle from ADR-0061's open point is settled along with it, without softening
  the strictness of the check: it stays an error, it just no longer costs the node.

**Negative / Costs**

- **As long as something is isolated, nothing is torn down on this node.** A
  permanently broken entry thereby keeps containers alive that the cluster has
  withdrawn. Visible, safe, and a reason to fix the finding.
- **The agent no longer ends by itself.** Whoever has relied on an exit code
  indicating a configuration error has to look at readiness and at the finding in
  future. That is a behavioural change for operations and automation.
- **`--once` stays as it was:** it still returns an error status if the pass was not
  clean. A one-shot invocation is a tool and not a loop; its caller wants the
  verdict.

**Risks & Open Points**

- ~~**How an operator learns of an isolated entry** is thereby reported but not
  alerted — the same open alerting rule set as since phase 11b.~~ — **done:**
  `docs/alerts.yml`, rule `TardigradeBrokenDeclaration`.
- **A cycle is resolved by removal, not by selection.** Nobody says which workload
  is "at fault"; the cycle is named as a whole.
- **A read error never triggers a deletion** — the agent does not remove an
  unreadable document itself, nor does it move it to quarantine.

  It nevertheless does not lie there forever, and that came out while building: the
  slice tidies up anyway what the cluster no longer names (ADR-0040, determination
  6), and that decision is made by the **name** — which the file name carries
  (`DesiredState::put` stores it that way by construction). The cleanup path
  therefore asks for the file names and not for the content. With that the node
  heals itself in both directions: what the cluster no longer wants disappears —
  readable or not; and what it still wants is rewritten with the next slice.

  The side effect is explicitly intended and was previously impossible: until now
  the cleanup path itself failed on the unreadable document it could have cleared
  away.

## Related ADRs

- The keystone: ADR-0019.
- Level-triggering: ADR-0010.
- The boundary of teardown: ADR-0058 (determination 3 extended).
- The node view and its strictness: ADR-0061 (open point closed).
- Liveness against readiness: ADR-0015, phase 11b.
