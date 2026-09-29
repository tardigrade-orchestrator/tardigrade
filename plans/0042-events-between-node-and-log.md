# ADR-0042: Events between node and log

- **Status:** accepted
- **Date:** 2026-08-23
- **Deciders:** Core team
- **Technical context:** `tg-consensus` (command set, state), `tg-store` (the
  slice), `tg-identity` (join/renew), `tg-agent`, `tgd`

## Context and Problem Statement

ADR-0040 built the path between control plane and node, and since then it
carries three things that were missing before. While wiring up the last open
points from phases 9 and 10 it turned out that **two** of them do not get
through, and for **one** reason:

- The agent cannot announce its WireGuard underlay (open from 9d).
- The agent does not learn that a volume was deleted (open from 10b).

The slice from ADR-0040 is a **snapshot of the desired state**. Both cases need
something a snapshot cannot express: an **event** — once from the node into the
log, once from the log to the node.

The line in `PLAN.md` read for a phase and a half "the call is missing, not the
path". On inspection that is wrong: `NodeMessage` knows exactly `Hello` and
`Report`, and ADR-0040 determination 7 says explicitly that the return direction
carries **observed state and no log entries**. The path is missing, not the call.

## Decision Drivers

- **ADR-0040 determination 7 stays valid.** Status noise does not belong in a
  substrate with a retention period (ADR-0020). What is decided here must not
  soften that boundary but must respect it.
- **A node may only speak about itself.** The name in `Hello` is to this day a
  **self-declaration** — mTLS on the stream has been missing since phase 5c. Any
  path on which a node gets something into the log has to hold independently of
  that.
- **Deletion is destructive and explicit** (ADR-0027). "Delete" must never follow
  from absence — neither from the failure of a message to arrive nor from a name
  missing in the slice.
- **No second mechanism for the same thing.** ADR-0040 was written because three
  building sites had the same cause. This decision should not put a fourth next
  to them.
- **Rotation must work without a ceremony.** ADR-0039 names key rotation as an
  open point; a path that makes every rotation manual prevents it in practice.

## Options Considered

### For the path from the node into the log

- **A** — the agent becomes a consensus client and writes itself through the
  admin API.
- **B** — a new `NodeMessage` variant on the stream from ADR-0040; the leader
  writes on its behalf.
- **C** — an operator enters the public key, as they enter the capacity today.
- **D** — the join/renew path from ADR-0037 carries it along.

### For the path of an event to the node

- **E** — the slice carries a list of deleted volumes; the state keeps tombstones.
- **F** — the node deletes what no workload declares any more.
- **G** — the log records the decision, a human executes it locally.

### Why not A

An agent that uses the admin API can write **any** command. The blast radius of a
compromised node would be the whole cluster: it could remove workloads, set
placements, revoke leases. Least privilege (ADR-0025, ADR-0017) demands the
opposite, and the admin service explicitly calls itself not that API.

### Why not B

Tempting, because the stream already stands — and dangerous for exactly that
reason. It would become a path on which a node causes log entries, and the only
credential on it today is the self-declared name from `Hello`. A node could
announce another's key and divert its traffic to itself.

That could be healed with mTLS — but then the decision would hang on work that
has been open for five phases. And even with mTLS the structural objection would
remain: ADR-0040 deliberately restricted the return direction to observed state.
Softening that boundary for a single command means softening it for all future
ones.

### Why not C

The X25519 key arises **on the node** and never leaves it (ADR-0039); only its
public part is announced. An operator could copy it out — once per node and once
per rotation. That would make every rotation a ceremony, and ADR-0039 wants it as
routine. A procedure that makes rotation expensive leads to no rotation
happening.

### Why not F

Absence is not a command. A workload can leave a node without its volume being
meant to disappear — during a move, when scaling down an instance, in any
partition where a slice looks incomplete. ADR-0027 makes deletion explicit and
protected, and the same line in ADR-0040 determination 6 says it for the slice: a
withdrawal comes as a **change**, never as an omission.

### Why not G

Honest, and wrong nonetheless. A deletion that only happens when somebody goes
there is one that silently does not happen. Both the freed space and the
fulfilled deletion obligation are **cluster facts**, and an auditor who finds a
`delete_volume` in the log and the volume on the disk has a finding, not a
misunderstanding.

## Decision

Chosen: **D** for the direction node → log, **E** for the direction log → node.
Both respect the boundary from ADR-0040 determination 7 instead of moving it.

### 1. A node speaks over the path on which it already identifies itself

Since ADR-0037 the agent has exactly **one** authenticated path to the control
plane: `Join` the first time, then `Challenge` + `Renew` every three hours. On it
it identifies itself with the key that **is** its identity, and the control plane
writes to the log there anyway (`AdmitNode`).

The underlay announcement travels on this path. `JoinRequest` and `RenewRequest`
gain the public X25519 key and the UDP endpoint; `tgd` appends `AnnounceUnderlay`
to the log from them — **after** checking the signature, and exclusively for the
node that produced it.

With that the authorization is not reinvented but is the same one ADR-0037
already carries: the blast radius of a stolen node key grows by **exactly one**
statement — its own underlay — and not by the command set.

And the rotation from ADR-0039 becomes routine: it happens at the next renewal,
without anybody doing anything.

### 2. The signature covers what it authorizes

Today the node signs **only the nonce** (ADR-0037). That suffices against replay
and does **not** suffice once the message carries a statement that has an effect:
whoever intercepts a `Renew` call would otherwise swap the endpoint, and the
signature would stay valid. All cluster traffic for that node would afterwards
run over a foreign address — encrypted, but to the wrong party.

What is signed is therefore **nonce ‖ key ‖ endpoint**, length-prefixed as in the
audit digest (phase 11a) and for the same reason: without length prefixes two
different requests could be brought to the same bytes to sign.

That is a change to ADR-0037 and is noted there as such, instead of happening
silently here.

### 3. A deletion leaves a tombstone in the state

`delete_volume` today only checks and writes nothing. Henceforth it records in
the state that this volume on this node **is** deleted — with the log index of
the decision.

The tombstone is not a makeshift but the fact itself: "this volume no longer
exists" is desired state, just like "this workload should run". It disappears
when a workload declares the same volume again — then the fact is superseded.

### 4. The slice carries this node's tombstones

Like everything else in the slice: **only its own**. The agent deletes what
stands in it, with `VolumeStore::delete` and the confirmation it forms itself.

That the confirmation does not stand in the log stays that way (phase 10b): a
confirmation field in the log would be a string one can copy. The explicit action
lies in issuing the command, not in executing it.

### 5. Deleting is idempotent, and failure is a report

A tombstone for a volume that does not exist locally is done. A deletion that
fails — a busy mount, an I/O error — is **reported and retried**, not concealed:
the tombstone stays in the slice until the node reports the corresponding index
as applied.

That is the same return channel as for the remaining observed state (ADR-0040
determination 7) — no new mechanism.

### 6. What the tombstones cost is spelled out

They grow with the number of **distinct** volume names ever deleted, not with the
number of deletions. A tombstone is a few dozen bytes; at the order of magnitude
of a five-node cluster that is negligible, and it is at the same time material an
auditor wants to see (ADR-0020).

A retention period for them belongs in the same place as that of the archive and
is **not** decided here.

## Consequences

**Positive**

- The path from the node into the log is **one**, and it is the one on which the
  node identifies itself anyway. No second auth system, no listening port, no
  softening of ADR-0040 determination 7.
- The blast radius of a compromised node stays the node.
- Key rotation (ADR-0039) happens at the renewal cadence, without a ceremony.
- Deletions reach the node over the existing slice and the existing return
  channel.
- The tombstones are at the same time audit material: what was deleted is a fact
  that cannot be reconstructed later.

**Negative / Costs**

- ADR-0037 changes: the signature covers more than the nonce. That is a protocol
  change and needs a coordinated switchover — a node with the old and a `tgd`
  with the new behaviour talk past one another.
- The announcement hangs on the renewal cadence (three hours). An endpoint change
  does not take effect at once. For a move that is long; the countermeasure is an
  out-of-schedule `Renew`, not a second path.
- The state grows by the tombstones, and the snapshots with it.

**Risks & Open Points**

- **A node without renewal announces nothing.** If the identity path fails, the
  underlay ages too. That is fail-static in the sense of ADR-0019 — the existing
  tunnels stay — but a new node would not get in.
- ~~**The retention period of the tombstones** couples to ADR-0020 and is open.~~
  — **done:** ADR-0104 — no period, a tombstone lives until it is carried out.
- ~~**An out-of-schedule `Renew`** is not yet foreseen; today the agent renews by
  the clock.~~ — **done:** built — the reconciliation in the slice wakes the
  renewer (`tg_agent::session`).
- ~~**mTLS on the stream** stays open as it has since 5c. This decision does not
  make it more urgent — it is built precisely so that it does not need it.~~ —
  **done:** ADR-0043.

## Related ADRs

- Depends on: ADR-0037 (node attestation; changed by determination 2), ADR-0040
  (the path to the node), ADR-0039 (the underlay), ADR-0027 (volumes).
- Affects: ADR-0004 (the desired/actual boundary — the tombstones are desired),
  ADR-0020 (retention).
