# ADR-0040: The path from the control plane to the node

- **Status:** accepted
- **Date:** 2026-08-22
- **Deciders:** Core team
- **Technical context:** `tgd` (the node service), `tg-agent`, `tg-proxy`,
  `tg-net`, ADR-0002, ADR-0004, ADR-0005, ADR-0018, ADR-0019, ADR-0025,
  ADR-0030, ADR-0037, ADR-0039.

## Context and Problem Statement

Three building sites stand open, and they have **one** cause. The plan records
them in three places:

| What is missing | Today's makeshift | Since |
|---|---|---|
| `may_talk` edges in the sidecar | a **text file** next to the process | phase 8b |
| The desired state of a node | `tgctl apply` writes locally into the directory | phase 2 |
| The `WireGuard` peer list | nothing at all | phase 9d |

Every time the answer was the same: "that is the same missing path control plane
→ node". Building it three times separately would mean building it three times —
with three formats, three error models and three opportunities to violate the
fail-static promise from ADR-0019.

ADR-0018 and ADR-0030 have already sketched the **transport** ("streaming
(watches) natively over gRPC", "tokio broadcast plus gRPC server streams"). What
neither says: who establishes the connection, what a node gets to see at all,
what happens on a tear-down, and where the observed state flows back to.

## Decision Drivers

- **ADR-0019, invariant 4:** no control-plane call on the hot path, and the agent
  stays locally authoritative from **persisted** state. A path that became a
  precondition of operation would be exactly the mistake the reliability model
  excludes.
- **ADR-0004:** desired is consensus-critical, actual is eventual. The two
  directions are **not** symmetric and must not be treated as such.
- **ADR-0025:** an edge withdrawal has to arrive within the revocation window
  (~60 s, ADR-0014). That is a time bound on this path.
- **ADR-0037:** nodes have had an identity since admission — a key and an SVID. A
  new path that bypassed it would be a second auth system.
- **Least privilege (ADR-0017 in spirit):** a compromised node should not hand
  out the topology of the whole cluster.
- **ADR-0020:** what goes into the log is retained. High-frequency status traffic
  does not belong in it.

## Options Considered

- **Option A — polling.** The agent periodically fetches the full state.
- **Option B — push to the node.** The control plane calls the agent.
- **Option C — a session, established by the node.** A bidirectional gRPC
  stream: the node establishes it, receives changes over it and reports its
  state over it.

### Why not A

The time bound from ADR-0025 would force an interval well below the revocation
window; transferring the whole state on every pass would be waste, and deltas
without a stream need a progress marker again — then one has rebuilt half the
session without having its properties.

### Why not B

A call from outside requires a listening port on every node. That is new attack
surface at exactly the place ADR-0017 marks as privileged, and it requires the
control plane to be able to reach every node — a directional assumption that
firewalls and NAT do not always grant.

## Decision

Chosen: **Option C.** A service of its own in `tgd`, a bidirectional stream,
established by the node.

```
rpc Session(stream NodeMessage) returns (stream ControlMessage)
```

Plus eight determinations.

### 1. A service **of its own**, not the API from ADR-0018

An operator and a node are different callers with different rights and different
needs. Putting them into one surface would mean building an RBAC surface for two
tenants with nothing in common — and ADR-0018 itself names RBAC granularity as an
open point. The node service gets its own, small surface: **one** method.

### 2. The node establishes, the control plane pushes

The stream originates at the node. That way no agent needs a listening port, and
a change reaches it in one round trip instead of one polling interval — that is
what makes the bound from ADR-0025 satisfiable.

### 3. To the leader, and followers refer onward

A node talks to the leader. A follower answers with a referral — the same pattern
`Credentials::ForwardTo` already uses in ADR-0037.

That is the less convenient of the two possibilities, and it is chosen
deliberately. The reason lies in the **return direction**: per ADR-0004 the
observed state does not belong in the log, and since ADR-0030 the projection lies
**per node in memory**. So the scheduler would never see a report sent to a
follower. Reading from the follower and reporting to the leader would be two
connections with two lifetimes for one thing.

The price is load on the leader and a gap during every election. Both are
bearable because a failure of this path **halts nothing** (determination 6), and
because ADR-0031 fixes the cluster size at five. The way out, should it ever get
tight, is open: read from the follower, report to the leader — the supplied log
index (determination 4) makes staleness visible in doing so.

### 4. The whole slice on every change, with a log index

Every message carries the **complete** slice for this node and the log index it
comes from. No deltas.

The first draft of this ADR foresaw "a snapshot, then changes" — the usual thing.
Two findings from the code speak against it, and they stand here because a
decision one deviates from while building is not one:

1. **The projection knows no changes.** `Projection::materialize` replaces the
   entire content, and deliberately so (ADR-0004/0030: the view is disposable and
   re-materializable at any time). Sending deltas would mean first building a
   change tracking that exists nowhere — and with it a state that can drift from
   the log. That is exactly what ADR-0030 wanted to be rid of.
2. **The slice is small.** It carries the instances of *one* node, the edges that
   touch them, and with five nodes (ADR-0031) four peers. That is kilobytes, and
   they flow only when something changes.

The log index stays and carries everything it was meant for: it makes the order
checkable, it makes staleness visible, and on re-establishment the node names its
last one — the server then sends only what is newer.

**The node discards what goes backwards.** A slice with an index below the last
applied one is not applied. Without that rule a change of conversation partner
could lay an old state over a new one.

### 5. A node sees its slice, not the cluster

Delivered are:

- the instances **it** is to carry, with their definitions,
- the `may_talk` edges that touch one of these workloads (ADR-0025),
- the underlay peers: ordinal, public key, endpoint (ADR-0039),
- its own ordinal and the cluster's network parameters.

Not delivered is what it does not need: other nodes' leases, open invitations,
foreign capacities, definitions of workloads that run elsewhere. A compromised
node should not be the blueprint of the cluster.

The peer list is the honest exception: a full mesh per ADR-0012 means every node
knows every other. That is the price of that decision and no negligence here.

**The slice follows from the identity, not from the request.** Which node is
speaking is stated by its SVID; a field in the message would be a
self-declaration and thereby the opportunity to demand another's slice.

### 6. The stream is a **refresh**, not a dependency

What arrives lands in the local, persisted state — the cache the agent has worked
from since phase 2 anyway. The reconcile loop **never** reads from the network.
If the stream tears, the node carries on with what it has and re-establishes it
in the background.

That is the place where ADR-0019 is kept or violated, and that is why it stands
as a determination of its own. A path that became a precondition would be a
regression against today's makeshift — the text file at least works without a
network.

From this also follows what a node may conclude from **absence**: **nothing.**
Withdrawals come as an explicit change, never as an omission.

### 7. The observed state flows back, but not into the log

On the same stream the node reports what it sees: which instances are running,
which have failed. That goes into the leader's projection and **explicitly not**
into the Raft log — ADR-0004 calls actual "high-frequency, observational, with no
need for linearizability", and ADR-0020 retains the log. Status noise with a
retention period would be the opposite of a usable audit trail.

It reports when something has changed, and otherwise a sign of life at the
reconcile cadence. The existing stream **is** the sign of life: if it tears, the
control plane knows it will hear nothing more from this node — without a second
mechanism for it.

### 8. mTLS with the node SVID, and the same format as in the log

The stream runs over mTLS with the certificates from ADR-0037. That is not a new
auth system but the existing one — and it dogfoods identity just as ADR-0018
foresees for the operator API.

As the payload format the same JSON codec applies as on the Raft path (phase 5c).
The slice consists of types whose wire representation is already fixed and tested
character by character; a second representation would be a second thing to keep
in step.

## Consequences

**Positive**

- **One** path instead of three. `may_talk`, desired state and peer list come
  over the same link, with the same error model.
- The time bound from ADR-0025 becomes satisfiable without polling.
- No listening port on the agent; no second auth system.
- The observed state finally reaches the scheduler — to this day it reads
  capacities an operator entered (the open point from phase 6).
- The fail-static promise becomes **checkable**: "stream gone" is a test case
  like "control plane gone" in every phase since 4.
- The cluster CIDR gets a home. It is the same number cluster-wide and today a
  per-node setting (the open point from phase 9d); it belongs in the log and
  travels in the slice.

**Negative / Costs**

- **Load and dependency at the leader.** Every election interrupts all sessions.
  Bearable only because the tear-down halts nothing.
- One more state machine on both sides: re-establishment, discarding old indices,
  reconciling with the local cache.
- **The whole slice per change** is waste as soon as a node carries many
  workloads. The threshold is measurable (determination 4), but it is not
  measured today.
- The per-node slice has to be **computed** on the leader. With many nodes that is
  work an "everything to everyone" solution would not have — deliberately paid for
  least privilege.
- One more format on the wire that wants maintaining (mitigated by reusing the
  log format).

**Risks & Open Points**

- ~~**Backpressure with slow nodes.** ADR-0030 already names it ("broadcast lag,
  missed events with slow clients"). The answer here is the snapshot: whoever
  cannot keep up gets the stream cut and starts anew. The threshold is to be
  chosen.~~ — **done:** ADR-0068.
- ~~**How long the control plane retains changes** before it can only give
  snapshots — that couples to the log compaction from phase 5d.~~ — **done:**
  moot — ADR-0040 determination 4 was changed to snapshots before adoption, there
  are no retained changes.
- ~~**mTLS on the Raft port** stays open as it has since 5c. It is the same
  material and the same mechanics; that it is not decided along with this is a
  question of scope, not of substance.~~ — **done:** ADR-0043.
- ~~**What an agent does that receives a slice it cannot carry** (an image that
  does not exist; a resource that is missing) — today it reports it back and
  keeps trying. Whether an upper bound is needed is to be decided with the
  scheduler.~~ — **done:** ADR-0062 (isolate instead of fail) and ADR-0070
  (visible in the report).
- ~~**Versioning** of the surface: ADR-0018 names it as an open point, and for
  this service it weighs more, because agent and control plane are updated
  separately.~~ — **done for this service**, and by **ADR-0072** and what hangs
  on it. Measured:

  - **All eight wire types of the session are strict** (`deny_unknown_fields`).
    The four remaining types of the module (`Lease`, `ClusterView`,
    `InstanceState`, `SessionClient`) derive no `Serialize` at all — they appear
    on no wire.
  - **The version stands at the Prometheus endpoint of both sides**
    (`tg_process_protocol_fields`, counted from the types themselves), and an
    alerting rule reports when two values run at the same time. That is the one
    piece of information a version mismatch does **not** break — anything that
    ran over the session would be exactly what it breaks.
  - **The window stands in the manual**, with order and number.

  What remains of ADR-0018's point has no subject here: the **public** API of
  that ADR does not exist — the admin service says in its own module header that
  it is **not** it. A versioning policy for a surface nobody speaks would be a
  mechanism without a caller: the mistake ADR-0044 named.

## Related ADRs

- Executes: ADR-0018 (gRPC streams), ADR-0030 (watches over streams).
- Depends on: ADR-0004 (the desired/actual boundary), ADR-0019 (fail-static),
  ADR-0037 (node identity), ADR-0005 (the leader).
- Supplemented by: **ADR-0042** — the slice is a snapshot and carries no
  **event**. Determination 7 stays untouched in this: the announcement goes
  **not** over this stream but over the credential path from ADR-0037.
- Serves: ADR-0025 (`may_talk` in the sidecar), ADR-0039 (the peer list),
  ADR-0011 (capacity and observed state for the scheduler).
