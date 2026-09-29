# ADR-0050: The identity of an operator — and who stands in the log

- **Status:** accepted
- **Date:** 2026-08-25
- **Deciders:** Core team
- **Technical context:** `tgd` (`admin`), `tg-identity` (`id`, `cluster`),
  `tg-consensus` (the command set), ADR-0044, ADR-0018, ADR-0020, ADR-0043

## Context and Problem Statement

ADR-0044 **fixed the authorization and did not build it**, with an explicit
reason: there was no caller. What is fixed there is the role `operator` with the
path form `spiffe://<domain>/operator/<name>` and authorization per command class
— `read`, `write`, `membership`.

Since then the caller has been built, fourfold: `tgctl node invite`,
`node cordon|drain`, `node upsert|policy` and `cluster apply|lint`. Whoever
reaches the socket may today submit workloads, set capacity and capacity policy,
cordon, drain and invite nodes — and call `ChangeMembership`, which ADR-0044
itself names as the sharpest: *"change the membership to a single foreign node,
and the cluster belongs to somebody else."*

The gate is a file mode. It is the project's last decided, unbuilt point.

## The finding that widens the question

While checking what would even be possible for an identity, a second, larger gap
comes to light: **the log does not say who did something.**

`Command` carries *what* is to happen. ADR-0049, with `Origin::{Operator,
Policy}`, answered the question "was a human here, or did the cluster compute?" —
but `Operator` is not a *who*. An auditor per ADR-0020 therefore reads: "at index
4711 the membership was changed, by a human." Which one stands nowhere.

As long as there is no operator identity that is not a gap but a fact: there
**is** nobody one could name. With the identity the possibility arises — and with
it the question of whether to use it. Both in one ADR, because it is the same
statement.

## Decision Drivers

- **ADR-0043's pattern:** what is checked is the **key** against a registration,
  not the chain against a CA. The justification there: *"the CA hangs on the
  leader and the leader on the Raft port — a check against it would be a circle."*
- **A recovery must not presuppose what it restores** (ADR-0043, ADR-0044). The
  Unix socket stays.
- **The state machine is pure** (ADR-0004/0005). It sees the command and nothing
  else — not even who sent it.
- **ADR-0020 retains the log.** What goes into it stays; a name is a statement
  about a human with a retention period.
- **No foreign daemons** (invariant 1, ADR-0023: concentration risk).

## Options Considered

**Where does the identity come from?**

- **H1 — nothing.** The file mode stays the authorization.
- **H2 — the user id is the identity.** `SO_PEERCRED` supplies it; a local file
  maps uid → classes.
- **H3 — the cluster registers operator keys**, as it registers nodes
  (ADR-0037/0043): a command puts `name → spki → classes` into the log, the admin
  port checks the client certificate against it.
- **H4 — the root from ADR-0014 issues operator certificates.** A ceremony per
  human, `tgd` checks against the anchor.
- **H5 — a foreign identity provider** (OIDC).

**Does the operator stand in the log?**

- **A1 — no.** Attribution only in the admin service's telemetry.
- **A2 — yes, as a field per command.** Every variant gains a statement.
- **A3 — yes, as an envelope around the command.** The log entry becomes
  `{ actor, command }`.

### Why not H5

An identity provider is a foreign daemon in the critical path of an operational
action, and ADR-0023 names concentration risk as a DORA requirement. On top of
that: whoever has to get the cluster running again because it has stopped needs
no provider that may be running on that very cluster.

### Why not H4

It is the strictest variant and the most unusable. An operator joining would need
a ceremony at the air-gapped root — and an operator leaving the house a
revocation for which there is no path. ADR-0014 deliberately keeps the root away
from the runtime path; waking it for staff changes inverts that.

### Why not H2

Tempting, because it manages without a PKI and is already half there
(`may_administer` reads the uid). Three objections, and the third decides:

- **A uid is not a human.** Shared accounts and `sudo` turn five people into one
  id; the log would say "1000".
- **It is node-local.** Five nodes would have five mappings that diverge — and
  the cluster has a log for that sort of thing.
- **It is good only for the socket.** Over a network port there is no peer
  credential, and ADR-0044 names network access as what comes later.

### Why not A2

It would be the obvious path and the most expensive: twenty-two variants gain a
field, and every future one has to remember it. Exactly this construction
ADR-0046 named as the cause of a bug — an enumeration somebody has to maintain is
one somebody forgets.

## Decision

Chosen: **H3 and A3** — with a separation that came to light while scoping the
build and was added here rather than circumvented in the code.

### 0. The two halves are built separately, and only one now

**Authorization only bites on a transport that authenticates.** Determination 2
explicitly exempts the Unix socket, and there is no other path: `tgctl` runs on
the node and finds the socket in the data directory. A registration with classes
would therefore be **a mechanism without a caller** — exactly what ADR-0044 named
as the mistake, and not seen while writing this ADR.

The **attribution** does not hang on that: whoever writes over the socket leaves
a peer credential, and that is the best statement available there.

What is built now is therefore determinations 4 and 5 — the envelope and the
actor. Determinations 1 and 3 — registration and classes — get built **when**
there is a transport that authenticates an operator. That is the same rule as in
ADR-0044, applied to this ADR.

### 1. An operator is a registered key

`EnrolOperator { name, spki, classes }` puts them into the log; `RevokeOperator
{ name }` withdraws them. What is checked at the admin port is the **client
certificate against the registration** — the key, not the chain, exactly as with
the nodes (ADR-0043).

With that there is no second CA, no circle through the leader and no issuance
path that can fail. An operator generates their key pair themselves; the private
part never leaves them — the same property for whose sake `Authority::certify`
certifies a **foreign** key (ADR-0037).

The path form has stood since ADR-0044: `spiffe://<domain>/operator/<name>`.
`Role` gains a third variant.

### 2. The socket stays and is the bootstrap

Whoever enters the first operator has no identity yet. The Unix socket is the way
for that — and the same way stays for recovery, as ADR-0044 determined.

On the socket the file mode still applies as the gate, and **`operator` classes
are not checked there**. That is not an exception out of convenience: whoever
reaches `0700` on a node's data directory can halt the process and read the disk
anyway. A class check there would protect against nothing and would let a
recovery fail on a registration that may well be the problem.

**The difference is reach:** the socket lies on **one** node, the network port is
the way from anywhere. What ADR-0044 called bearable was the socket — not a port.

### 3. Three classes, and the boundaries lie where the damage jumps

Unchanged from ADR-0044: `read` (`Status`, `Projection`, `Lints`) · `write` (the
command set) · `membership` (`AddLearner`, `ChangeMembership`). A registration
names a subset of them.

`Lints` is added and belongs to `read`: it is a statement about the state and
changes nothing.

**No finer granularity**, and that is a decision against the obvious extension.
"This operator may `UpsertWorkload` but not `DeleteVolume`" sounds sensible and is
a rights administration — that wants maintaining, and unmaintained it is worse
than three classes, because it claims a security nobody keeps up. Three classes a
human can keep in their head.

### 4. The log entry gains an envelope, not a field per variant

The entry becomes `Entry { actor: Option<Actor>, command: Command }`.

- **One change, not twenty-two.** A new command inherits the envelope without
  anybody having to remember (the lesson from ADR-0046).
- **The state machine stays pure.** It reads `command` and ignores `actor` — it is
  not part of the decision but of its origin. Two nodes still arrive at the same
  result (ADR-0004).
- **The audit archive gets it for free.** It seals the payload (ADR-0045), and
  the actor is part of it. From here on an auditor reads "who" without anything
  being changed in the archive.
- **`Option`, because there are entries without humans:** what the leader writes
  from a policy (ADR-0049), what the scheduler places, what a node triggers over
  the credential path (ADR-0042). `Origin` from ADR-0049 stays where it is — it
  answers "human or computation", the actor answers "which human", and merging
  the two would mean reading an empty statement as "computed".

### 4b. What an actor can be today

Two shapes, and the names say what they are:

- **`Actor::Operator(name)`** — a registered operator. That is the form from
  determination 1 and arises only with the transport.
- **`Actor::LocalUid(uid)`** — the Unix socket's peer credential
  (`SO_PEERCRED`). It is **not** an identity in the sense of determination 1 — a
  uid is not a human, that is the objection to H2 — but as **information** it is
  true: on a machine with per-person accounts it is the person, and on one with a
  shared account it says exactly that.

The difference is the one between "who may" and "who was". For the first a uid is
no good; for the second it is the best a file mode affords — and considerably
more than nothing.

### 5. A name in the log is a statement with a retention period

That belongs spoken out loud rather than left to operations: the actor is a
**name from a registration**, not a legal name, not an identifier from a
directory, not an address. It is to be retained as long as the log (ADR-0020),
and whoever has to weigh a deletion obligation against a retention obligation is
weighing between a name like `ops-3` and the audit trail — not between a
personnel file and it.

That the registration maps the name to a person is a question **outside** this
log.

## Consequences

**Positive**
- The last decided, unbuilt point becomes buildable, without a new CA and without
  a foreign daemon.
- From here on an auditor per ADR-0020 reads "who", and sealed at that.
- One change to the entry format covers all present and future commands.

**Negative / Costs**
- **A format break on the log**, and this time on the entry itself. It belongs
  together with the two from ADR-0042 and ADR-0046 in **one** coordinated
  switchover; three separate ones would be three outage windows.
- Two more commands and one more role in `tg-identity`.
- **The network port is therefore not built**, and the authorization consequently
  not either (determination 0). What arises now is the **attribution**; on the
  socket it is a uid and with the transport it becomes an operator name, without
  anything further to change in the format.

**Risks & Open Points**
- **Revocation takes effect at the next handshake**, not at once: a running
  connection stays. For an admin channel that is bearable (the connections are
  short), but it is not the same as the revocation window from ADR-0014.
- **The first operator comes over the socket**, i.e. over the file mode. Whoever
  has that can enter themselves — that is the root of the trust and not a gap,
  but it belongs in the operations manual.
- **How an actor becomes a human** this ADR does not decide. The mapping lies
  outside.

## Related ADRs

- Depends on: ADR-0044 (role, classes, the socket stays), ADR-0043 (the key is
  the credential), ADR-0036 (path form), ADR-0020 (retention), ADR-0004 (purity)
- Affects: ADR-0018 (the surface gains an authorization), ADR-0020 (the trail
  gains an actor), ADR-0049 (`Origin` stays but gains a neighbour)
