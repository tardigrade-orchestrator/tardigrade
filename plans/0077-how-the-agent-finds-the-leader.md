# ADR-0077: How the agent finds the leader

- **Status:** accepted
- **Date:** 2026-09-03
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-agent` (`session`, `join`), ADR-0040, ADR-0037,
  ADR-0031, ADR-0025, ADR-0064

## Context and Problem Statement

Both paths from the node to the control plane go to the **leader**:

- the session over which the slice arrives (ADR-0040, determination 3), and
- the credential path over which a node joins and renews (ADR-0037),

and both see a follower do the same thing: it answers with a **referral** —
`ControlMessage::ForwardTo` or `Credentials::ForwardTo`. ADR-0040 names the price of
that choice explicitly: "load on the leader and a **gap during every election**".

**Measured, the gap is not a gap but permanent.** The referral carries an
`Option<NodeId>` — an **identifier**, not an address — and the agent knows exactly
**one** address per path (`--node-session`, `--control-plane`, both
`Option<String>`). It ends the session with the message "this node is not the
leader; the leader is 3" and afterwards tries **the same** address again.

Two real `tgd` processes, membership `{1,2}`, a real `tg-agent` whose
`--node-session` points at the follower:

```text
MEASUREMENT leader 1, follower 2
MEASUREMENT slice arrived at the follower: false
```

Twenty-five seconds, no slice. The node stays without desired state, and nobody in
the cluster sees the reason: its **reports** do not reach the leader either, so in
`tgctl cluster nodes` it looks like a mute node.

### What hangs on that

A node whose address no longer names the leader loses more than currency:

- **A withdrawal never reaches it.** `may_talk` and the egress permissions come from
  the slice (ADR-0040), and the sidecar holds fail-static to the last state
  (ADR-0019). The revocation window from ADR-0025 is thereby **unbounded** — a
  withdrawn edge still holds.
- **Every single writer on it fences.** The active-role lease travels in the slice
  (ADR-0064); if none arrives, it expires, and the holder stops itself autonomously
  — permanently.
- **Tombstones are not executed** (ADR-0042): a deleted volume stays on the disk.
- **The credential path dies slowly.** Without renewal the agent intermediate
  expires after twelve hours (ADR-0014), and after that **no** SVID of this node is
  accepted any more.

And the trigger is not an incident but normal operation: every election, every
rolling restart — which ADR-0031 explicitly foresees with five nodes — and every node
loss changes the leader.

## Decision Drivers

- A leader change is an **expected** event and must not require an operator action.
- No new format on the wire: the session messages are strict (ADR-0072), and every
  extension is a format break belonging in a coordinated window.
- No infrastructure precondition the manual does not name. This system is
  self-contained (ADR-0001).
- The shape from ADR-0040 determination 3 stays: **one** connection to the leader,
  not reading here and reporting there.

## Options Considered

### A — a list of endpoints, and the referral moves on (chosen)

`--control-plane` and `--node-session` become **repeatable**. The agent starts at the
first entry and moves on when a session ends. A referral with a known leader is
thereby **information and not a failure**: it moves on at once instead of sitting out
a wait.

### Why not B — the referral carries the address

That would be the direct answer and costs two things. First a field on
`ControlMessage`/`Credentials`, i.e. the seventh format break (ADR-0072). Second: a
node knows the **cluster** addresses of its peers (`--peer`), not their session or
identity addresses. It would additionally have to be told them — the same list, only
in five places instead of one.

### Why not C — the follower relays

ADR-0040 already rejected this shape, and the justification holds unchanged: "reading
from the follower and reporting to the leader would be two connections with two
lifetimes for one thing."

### Why not D — a load balancer in front

It even works: every re-establishment lands on a different node, and eventually on
the leader. It is just a **silent precondition** on the environment — an operator
entering an address learns nowhere that it has to have several targets. And for a
cluster meant to run without foreign daemons, a dependence on foreign infrastructure
is the wrong price.

### Why not E — learn the endpoints from the cluster

The slice could bring the peers' session addresses along, and in the steady state
that would be the prettiest solution: a list that maintains itself. But it does not
solve the bootstrap problem — the **first** connection needs an address — and it
costs a field on the wire again. It stays as a refinement should the list ever become
inconvenient.

## Decision

**Option A.**

1. **Both settings become repeatable.** `--control-plane` and `--node-session` take
   several addresses; the order is the operator's. **All** nodes of the control plane
   should be named — just as `--peer` on `tgd` already names all of them.

2. **A referral moves on at once.** If the referral names a leader, it is clear that
   this endpoint is the wrong one: the next is tried without a wait. With five nodes
   the leader is therefore found in at most four round trips — milliseconds instead of
   minutes.

3. **Every other outcome moves on too, but after the wait.** An endpoint that does
   not answer may be the crashed old leader; staying there would mean prolonging the
   outage. If the referral names **no** leader, there is nobody to reach — then the
   wait applies too, otherwise the agent would run in circles during an election.

4. **The identifier in the referral stays diagnostic.** A mapping identifier →
   address in the agent would be a second place where the cluster's identity lives;
   with five endpoints, moving on is cheaper than an association that can be wrong.

5. **The rotation is a pure function** and tested without a process. It applies to
   both paths — a second version would be two opportunities to interpret it
   differently.

6. **The anchor has to cover all endpoints.** That came out while building and is the
   second half of the finding: the agent checks the control plane against
   `identity/control-plane.pem` (ADR-0043), and with **one** node's leaf the handshake
   to any other fails with `invalid peer certificate: UnknownIssuer` — the list of
   addresses would be ineffective without the leaves to go with it.

   **Nothing changes in the code**, and that is the good news: `anchors_from_pem` has
   read **several** PEM blocks since ADR-0043. What was missing is the instruction —
   ADR-0043 names the file in the singular. It holds the leaves of **all** nodes of
   the control plane, concatenated, and that now stands in the operations manual.

7. **A single address stays valid.** Whoever names one gets exactly today's
   behaviour; moving on then lands back at it. No operational break.

## Consequences

- **Positive:** a leader change costs round trips instead of an operator action.
  Withdrawals, leases and tombstones reach the node again, and the credential path
  survives.
- **Positive:** no field on the wire, hence no format break.
- **Negative:** the operator has to name all addresses **and** all anchors. Two lists
  for one fact — it is already one today, because `--peer` on `tgd` and
  `peers/<id>.pem` are the same pair.
- **Negative:** the operator has to name all addresses. If they forget a node, the
  cluster is unreachable for that agent for as long as the forgotten one leads — rarer
  than today, but more confusing.
- **Negative:** on a network problem towards the leader the agent can move **away**
  from it and has to walk the list again. With five entries that is milliseconds.

## Risks & Open Points

- **The list is static.** A membership change (ADR-0005, phase 5d) does not change it
  along; a newly admitted node stands in no agent configuration. That is operational
  work — and the reason option E is noted as a refinement.
- **Order as a load question:** if all agents name the same order, after an election
  they land together at the next entry. With five nodes and one session per agent that
  is no issue; with many nodes it would be one.
- **The referral stays an identifier.** Whoever wants the address there needs option B
  and a window (ADR-0072).

## Related ADRs

- **ADR-0040** — the session goes to the leader; the price ("a gap during every
  election") stands there and was measured to be permanent.
- **ADR-0037** — the credential path goes to the leader too.
- **ADR-0043** — the anchors: a list of addresses without the peer leaves to go with
  it is ineffective.
- **ADR-0005** — a membership change does not change the list along.
- **ADR-0072** — option B would need a format window.
