# ADR-0054: Detach and attach — a node leaves the data plane

- **Status:** accepted
- **Date:** 2026-08-26
- **Deciders:** Core team
- **Technical context:** `tg-consensus` (command set, state), `tg-store` (the
  slice), `tg-agent` (`underlay`), ADR-0039, ADR-0040, ADR-0019, ADR-0011,
  ADR-0027, ADR-0037

## Context and Problem Statement

ADR-0039 left key rotation as an open point. On measuring it turned out that the
question is not "how does one rotate" but **"what does one do with a node that
does not currently belong"** — and that had so far only a passive answer: it keeps
its old key and rotates on return.

That is right and it is not sufficient. A rotation without further precaution has
a **window**: the node changes its key, and until every peer has read the new one
from the slice, each of them holds a stale one. `WireGuard` cannot carry two keys
for the same `AllowedIPs`, so that node's tunnel stands still during that time. A
state one has to endure should become an action somebody wanted — the same
movement cordon made for placement.

On top of that comes the occasion that exists without rotation: a node goes to
the workshop, a node has been away for days and all the others keep trying to
reach it. Today there is **no** state expressing "not in the data plane". There is
only:

| State | What it says |
|---|---|
| `cordoned` | nothing new here, what runs stays |
| `draining` | nothing new, what runs moves away |
| `RevokeTrust` | key dead, ordinal kept — it cannot come back |
| `RemoveNode` | gone, ordinal freed |

Between `draining` and `RemoveNode` lies a gap, and in it sits every operational
case that is meant to be reversible.

**The precondition has only now been met.** The content of "detached" is not
being in the data plane — and that did not exist until the tunnel was connected:
`wireguard::configure` had no caller. A detach before that would have been a state
nothing applies.

## Decision Drivers

- **ADR-0019:** a node without a control plane carries on; nothing is stopped for
  reachability.
- **ADR-0011:** declarative-explicit, no auto-rebalancing. Failure detection must
  not change topology.
- **ADR-0004:** intent into the log, observation into the projection.
- **ADR-0039:** the ordinal is not a position in a list.
- **ADR-0027:** a writable volume is node-pinned.

## Options Considered

- **A — an axis of its own** `attached` / `detached`, orthogonal to
  placeability, with a fixed interaction.
- **B — a fourth value in `Schedulability`.**
- **C — no new state:** `RemoveNode` and re-admission.
- **D — nothing;** rotation lives with its window.

### Why not B

`Schedulability` answers one question: may things be placed here. "Not in the data
plane" is another, and the two are **not** the same: a node can be cordoned and
fully in the mesh — that is the normal case before an update. A fourth value would
turn the type into a ranking in which every value means something else in
addition, and the type's name would no longer hold.

### Why not C

`RemoveNode` frees the **ordinal**. A node that rejoins gets a different one, its
subnet changes, and its addresses are no longer addresses of this node (`restore`
throws the ledger away, and rightly so). For "three hours in the workshop" that is
a renumbering with a run-up. And for rotation it would be the largest conceivable
movement for the smallest change.

### Why not D

Because the window cannot be *managed*. It lasts as long as the last peer needs —
and who the last one is nobody knows.

## Decision

Chosen: **Option A.**

### 1. One intent in the log, one field

`SetAttachment { node, mode }` with `Attached | Detached`, stored on the node like
placeability. **No** progress, **no** intermediate stage, **no** acknowledgement
in the log: "detached" is desired state like "this workload should run".

A command of its own and not an extension of `UpsertNode` — the same
justification as with cordon: detach is an **operational action**, upsert an
inventory statement, and whoever merges the two overwrites topology and capacity
from a stale view.

### 2. Two convergences, independent of one another

- **The peers** drop a detached node from their peer list. That does not need its
  participation — they stop trying. The slice from ADR-0040 carries the list
  anyway; it just gets narrower.
- **The node itself** sees "detached" in its own slice (it stays in the session,
  see determination 4) and tears down its underlay.

Both against the same field, both level-triggered (ADR-0010), **no order between
them**. A node that is away converges later — and that is exactly why this design
needs no catch-up protocol. That is the answer to the question on which the
obvious construction fails.

### 3. No timeout turns an observation into an intent

There is **no** auto-detach after missed heartbeats. That is the determination
whose violation would make this design dangerous: it would turn a network glitch
into a topology change. This project has rejected the construction three times —
ADR-0011 ("no auto-rebalancing"), ADR-0049 ("the report never reaches the
scheduler") and the liveness separation in 11b ("loss of quorum makes a node
not-ready, not dead").

Whoever wants a silent node detached decrees it — by hand or through a declared
policy standing as a command in the log (the construction from ADR-0049). What a
node has **actually** done stands in the projection and never in the log.

### 4. Detach takes neither the ordinal nor the trust

- **Not the ordinal.** Otherwise subnets renumber, and every route, every
  nftables rule and every `AllowedIP` afterwards points into the void, with no
  error appearing anywhere (the finding from 9a). It is still freed only by
  `RemoveNode`.
- **Not the trust.** A detached node keeps renewing its credential and keeps its
  session — otherwise it could not come back by itself, and "attach" would be a
  re-admission procedure instead of a state change. Whoever wants the key **dead**
  takes `RevokeTrust`; for an absent node that means it does not return, and that
  is then deliberate.

Detach is therefore explicitly **not** a security action. It is a statement about
the data plane.

### 5. Detach includes emptying — and can fail at it

A node without a mesh but with running workloads is worse than either: the
containers run and reach nothing. For the scheduler `detached` therefore acts like
`draining` **and additionally** as an exclusion from any placement, independently
of placeability. The interaction is thereby fixed and not left to the caller:
**detached beats placeable.**

And there is the case in which it is **never finished**: a workload with a
writable volume is node-pinned (ADR-0027) and cannot move. The node then stays
half in. That has to be reported **loudly** — "this node is not detachable without
giving up these volumes" — with the same justification as with drain: whoever
empties a node has to learn what does not come along, and a silent exception here
is worse than a loud one.

What is explicitly **not** decided is that detach waits until it is finished.
There is no state "detaching" in the log; how far it has got is said by the
projection.

### 6. The detached node stops no containers

It tears down its underlay, not its workloads. What the scheduler carries away
disappears by the ordinary path; what stays behind keeps running — including what
is no longer reachable. That is ADR-0019, and it is the difference between "not in
the cluster" and "off".

### 7. Rotation falls out, without mechanics of its own

Detach → rotate → attach. During the rotation **nobody** holds a key of this
node, so there is no window with stale keys but a named absence. What rotation
then still needs is a trigger for the key change itself — and that belongs in the
same desired state (a generation per node), not in an event.

**That is work for an ADR of its own**, and this one does not pre-empt it. It only
removes its hardest part.

## Consequences

**Positive**
- The operational case "this node does not currently belong" is expressible,
  reversible and costs no renumbering.
- Peers stop calling an absent node — and because somebody decreed it, not because
  a clock ran out.
- The reconciliation of a returning node is not a mechanism of its own: it reads
  the slice and converges.
- Rotation loses its window.

**Negative / Costs**
- One more state an operator has to understand — and one has to know the
  interaction with `Schedulability` (determination 5). The output has to name the
  reason: "detached" and "cordoned" send an operator to different places.
- A detached node with a pinned volume stays a half-state. It is visible, but it
  is there.
- Detach without attach is a trap: a node nobody brings back keeps running
  unnoticed without a mesh. That belongs on a metric.

**Risks & Open Points**
- ~~**Who may detach?** Today: whoever reaches the admin socket (ADR-0044, open
  point). Detach is therefore authorized like cordon.~~ — **done:** ADR-0105.
- ~~**The policy from determination 3** — "detach what has been silent for N
  hours" — is the construction from ADR-0049 and explicitly **not** decided here.
  As long as it is missing, a human detaches.~~ — **done:** ADR-0057 —
  auto-detach permanently rejected.
- ~~**Whether `attach` forces an announcement.** A node coming back has to have
  its key in the log again; the reconciliation from ADR-0042 already does that,
  but the order (attach first, then announce, or the other way round) is
  untested.~~ — **done:** built — if the announcement is missing from the slice,
  the node wakes the renewal (`tg_agent::session`).
- ~~**The proof needs two nodes with real tunnels.** What is to be checked here —
  the peer disappears from the *other* node's kernel — works only in the netns
  lane.~~ — **done:** ADR-0054 is evidenced at the kernel.

## Related ADRs

- Depends on: ADR-0039 (underlay, ordinal), ADR-0040 (the slice), ADR-0019
  (fail-static), ADR-0011 (no auto-rebalancing), ADR-0027 (node-pinned volumes),
  ADR-0037 (admission and trust)
- Supplements: ADR-0039 — key rotation thereby becomes buildable, but is not the
  subject of this ADR
