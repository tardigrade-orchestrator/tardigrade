# ADR-0103: The Transport of an Operator

- **Status:** accepted
- **Date:** 2026-09-06
- **Concerns:** ADR-0050 (who stands in the log), ADR-0044 (operator
  interface), ADR-0043 (mTLS on the cluster transports), ADR-0018 (API
  surface), ADR-0036 (form of the SPIFFE path), ADR-0020 (retention)

## Context and Problem Statement

ADR-0050 decided the identity of an operator — **a registered key, like a
node** — and expressly separated its implementation:

> **Authorization only bites on a transport that authenticates.**
> Determination 2 expressly excludes the Unix socket, and there is no other
> way: `tgctl` runs on the node and finds the socket in the data directory. A
> registration together with classes would therefore be **a mechanism without
> a caller**.

The transport is thus the precondition of four notes, and all four have been
waiting for it since ADR-0044:

| Note | Where |
|---|---|
| Role `operator` and authorization per command class | ADR-0044, open point |
| Registration and classes (determinations 1 and 3) | ADR-0050, open point |
| `Role::Operator` missing in `tg-identity` | ADR-0050, open point |
| `tgctl` is not a cluster client | ADR-0044, open point |

**Measured, the state is exactly as described.** `EnrolOperator` and
`Role::Operator` occur **zero** times in the whole tree; `Actor::Operator`
exists and is never created. Whoever reaches the Unix socket may do anything,
and the audit trail contains a uid.

What that costs is not the authorization — that is a separate question — and
not the attribution either, for a uid is true. It is the **reach**:

- **`tgctl` reaches its node, not the cluster.** The socket lies in the data
  directory, so every command needs a session on exactly the machine on which
  the leader currently runs — and when that moves, on another one. `ForwardTo`
  names the leader and aborts (ADR-0044); it cannot do more.
- **Whoever may administer must be on the node.** That is right for recovery
  and an imposition for operations: an invitation, a restart, a capacity
  policy all require shell access to a control-plane machine — and thereby an
  access that can do everything anyway (ADR-0044: "whoever reaches `0700` can
  stop the process and read the disk").

The question of this ADR is therefore: **by what does a control plane
recognize an operator who is not sitting on its machine?**

## Decision Drivers

- **ADR-0043's pattern carries here just as well.** What is checked is the
  **key** against a registration, not the chain against a CA. The reason is
  the same and even sharper: the CA hangs on the signing group (ADR-0097), and
  an operator who has to restore consensus cannot presuppose that it is
  reachable.
- **The Unix socket stays** (ADR-0044, ADR-0050 determination 2). A recovery
  must not presuppose what it restores — and the **registration of the first
  operator** is exactly that case: it goes over the socket, otherwise there
  would be no end to the chicken-and-egg.
- **The registration lies in the log.** A revocation must apply cluster-wide,
  and a list per node would be five sources for one fact — the same finding as
  with the nodes' trust list (ADR-0043).
- **ADR-0020 retains the log.** What goes in stays: a name is a statement
  about a human with a retention period, and a **key** is public material
  without a secret (the same trade-off as with the join token, ADR-0037: only
  the hash stands in the log).
- **The state machine stays pure** (ADR-0004/0005). It sees the command and
  the actor; who *may* is decided by the service in front of it.
- **Invariant 3.** `rustls`, and the verifier structure already exists.

## Options Considered

### T1 — Its own port with mTLS against a registration in the log

The form of ADR-0043, with a third role. `EnrolOperator { name, spki }` puts a
key into the log, a verifier checks every handshake against the list, and the
**name from the certificate** becomes `Actor::Operator`.

- **For:** the same construction, the same building blocks (`NodeTrust`,
  `NodeVerifier`, `spiffe_id_of`), no circle via the CA, a revocation takes
  effect on the next connection, and the attribution arises **in the service**
  and never in the message (ADR-0050).
- **Against:** a fourth listening port in `tgd`, and an operator must hold a
  key.

### T2 — SPIFFE mTLS against the CA (ADR-0018's original intent)

An operator gets an SVID from the signing group.

- **For:** dogfoods our own identity, as ADR-0018 conceived it; short lifetime
  instead of a long-lived key.
- **Against:** **the circle.** Whoever has to restore consensus needs an
  access that does not hang on the CA — and the CA hangs on the leader
  (ADR-0043) and, since ADR-0097, on a group with a threshold. On top of that
  the question of **who** issues an SVID to a human: there is no attestation
  of humans here, and inventing one would be a system of its own.

### T3 — A bearer token per operator

Like a node's invitation (ADR-0037), only without consumption.

- **For:** no key material at the operator, a copy suffices.
- **Against:** a secret with a retention period. Its hash would stand in the
  log, the secret itself on the wire — and an intercepted call would be
  replayable. Exactly the property for the sake of which ADR-0037 has the
  nonce, and which a key brings along for free.

### T4 — Ride along on the node port

Reuse the existing `--node-session` port.

- **For:** no new port.
- **Against:** the trust lists would be the same, so a compromised **node**
  could administer. That is an extension of the blast radius from ADR-0037
  ("only trust is admitted, not capacity") to "may do anything" — and the
  separation of seat and identity that ADR-0097 drew for the same reason would
  be lost here.

## Decision

Chosen: **T1.**

### 1. Its own port, its own list

`--operator-listen <address>` in `tgd`, mTLS in both directions. What is
checked is the **SPKI** of the client certificate against the registration in
the log, and the SPIFFE ID in it must carry the role `operator` and read the
registered name.

Its **own** list and not the nodes' (against T4): whoever takes over a node
does not thereby obtain an operator's authority. The blast radius stays as
ADR-0037 promised.

The port is **optional**. Without the setting it stays exactly at what
ADR-0044 built — the same choice as with `--signer-listen` (ADR-0097) and
`with_egress` (ADR-0041): a port that opens an access arises only when an
operator names it.

### 2. `Role::Operator` as a third role

`spiffe://<domain>/operator/<name>`, in the form of ADR-0036. The role is what
distinguishes the operator from the node, and it stands **in the certificate**
— not in a setting beside it: a leaf with a `node` role is rejected at the
operator port even if its SPKI were in the list.

### 3. Registration goes over the socket, and that is no detour

`EnrolOperator { name, spki }` and `RevokeOperator { name }` go over the way
that is there anyway (ADR-0044). That is the answer to the chicken-and-egg:

- **The first operator** is registered by someone who is on the node — and
  whoever is there can do everything anyway.
- **Every further one** can be registered over the port, because
  `EnrolOperator` is an ordinary command.
- **The socket remains the recovery path.** Whoever has locked themselves out
  — key lost, registration revoked by mistake — comes back over it without
  needing the cluster.

An operator generates their key **themselves** (`tgctl operator keygen`), and
only the SPKI travels. The private part never leaves their machine — the same
property that `Authority::certify` has for a node (ADR-0037), and the reason
why no secret stands in the log.

### 4. The actor arises in the service, never in the message

At the operator port it is `Actor::Operator(<name from the certificate>)`, at
the socket it stays `Actor::LocalUid`. **Nothing changes in the protocol for
clients** — that is the promise from ADR-0050, and it holds: a field a client
fills would be a self-declaration, and ADR-0043 removed that from
`NodeMessage::Hello` without replacement.

### 5. A revocation takes effect on the next connection

The list follows the log and is read at **every** handshake (`SharedTrust` in
the form of ADR-0043). A `RevokeOperator` therefore needs no restart — unlike
the revocation on the Raft port, which is an operations action because its
list must lie **before** consensus.

Existing connections remain. That is the same edge as everywhere (ADR-0025's
revocation window applies to the data plane) and defensible here because an
admin call is short; whoever wants to cut immediately restarts `tgd`.

### 6. Authorization per command class is **not** part of this ADR

What ADR-0044 and ADR-0050 determination 3 laid down on that stays laid down
and unbuilt. The reason is the same with which ADR-0050 separated the halves,
only one level further: **a class needs a second operator to mean anything.**
As long as every registered operator may do everything, the class is a setting
without effect — and whether it becomes classes, roles or a list per command
is a question answered by an operation with more than one human, and not by
this ADR.

What arises now is the **foundation**: from here there is a name against which
a rule could decide.

## Consequences

**Positive**

- `tgctl` can reach the cluster, not just its node. With that the open point
  from ADR-0044 is closed, and `ForwardTo` turns from a refusal into
  information a client can follow.
- The audit trail carries **a name** instead of a uid — and because the
  archive seals the whole payload (ADR-0045), a rewritten actor is a finding.
- A revocation is a consensus action and takes effect cluster-wide on the next
  connection.
- **Zero new crates.** `rustls`, `NodeVerifier`, `NodeTrust` and
  `spiffe_id_of` are in the tree.
- The blast radius of a compromised node does **not** grow (against T4).

**Negative / costs**

- **A fourth listening port in `tgd`**, and the most dangerous one: whoever
  reaches it with a registered key may do anything (determination 6). It is
  therefore optional, and its default is **off**.
- **An operator holds key material.** If they lose it, they come back only
  over the socket; if it is stolen, a `RevokeOperator` is needed — and until
  then the thief is an operator. There is no expiry date (the same open spot
  as with the node key, ADR-0043).
- **The name stands permanently in the log** (ADR-0020). That is a statement
  about a human with a retention period, and it is intended: without it there
  would be no attribution. A pseudonym is the answer if an installation needs
  one — and then the mapping must be kept elsewhere.
- **Existing connections survive a revocation.**

## Related ADRs

- **Redeems:** ADR-0050 determination 1 (registration) and the precondition of
  its determination 0; ADR-0044's open point "`tgctl` is not a cluster
  client"; ADR-0018's intent of an authenticated access — with a different
  answer than presumed there (key instead of SVID, and the reason is the
  circle).
- **Applies:** ADR-0043 (key against registration, anchor depending on
  position relative to consensus), ADR-0036 (path form), ADR-0044 (the socket
  stays), ADR-0050 (actor in the service).
- **Does not touch:** ADR-0050 determination 3 and ADR-0044's authorization
  per command class — both stay laid down and unbuilt (determination 6).
- **Presupposes:** nothing. The socket is the bootstrap.
