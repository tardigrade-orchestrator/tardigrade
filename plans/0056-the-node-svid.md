# ADR-0056: The node SVID without a task

- **Status:** accepted
- **Date:** 2026-08-26
- **Deciders:** Core team
- **Technical context:** `tg-agent::join`, `tgd::identity`, `tg-identity`,
  ADR-0006, ADR-0014, ADR-0043

## Context and Problem Statement

After ADR-0043 the following stood as an open point: "**The node SVID stays
without a task.** It is written and read by nothing." Measured, the situation is
sharper:

| | |
|---|---|
| written by | `tg-agent::join` to `identity/node.svid.pem` |
| read by | **nothing** in production code |
| lifetime | **15 min** (`Lifetime::default`, the tight profile from ADR-0014) |
| renewed every | **3 hours** |

The file is therefore **expired for 165 of 180 minutes** — 92 % of the time. Its
only checker is a test (`attestation.rs` verifies the chain against the anchor).

**That is more than a dead remnant.** In a REMIT/DORA environment an expired
certificate on disk is exactly what an auditor or an operator finds and takes for
a finding. It is a **false signal** at the place one is most likely to look.

## Why it has no consumer, and why that is right

Not out of forgetfulness. ADR-0043 decided that on the cluster transports the
**key** is checked against a registration and not a chain against a CA — "the CA
hangs on the leader and the leader on the Raft port, a check against it would be a
circle". There the node puts a **self-signed** leaf on the wire
(`node.leaf.pem`) carrying its SPIFFE identifier.

So there are two certificates over the same key and the same identifier: one is
used and is self-signed, one is CA-signed and is not used.

And it should not get one either: a certificate with a 15-minute lifetime on the
Raft port would mean that restoring consensus presupposes the CA — exactly the
circle ADR-0043 avoided.

## Options Considered

- **A — the file goes away.** The agent still receives the SVID in the response
  and does **not** store it.
- **B — remove it from the protocol.** `Credentials::Issued` loses the field.
- **C — align the lifetime** (12 h like the intermediate) and keep the file.
- **D — nothing.**

### Why not B

Two reasons. First it is a **fifth** format break next to ADR-0042, 0046, 0050 and
0055, and those four are already waiting for a coordinated switchover — for a gain
consisting of "one field fewer".

Second, and this weighs more: the field is the **only** place where the issuance
of a node leaf is checked at all. Remove it and the CA's `Purpose::Leaf` path for
nodes is untested — and the promise from ADR-0006 that the chain carries from the
control plane would have no evidence any more.

### Why not C

It makes the certificate true and the question no smaller: something would still
lie on disk that nothing reads and whose purpose nobody can explain. And it would
move a figure from ADR-0014 for a certificate class that has no exposure — a
change with a burden of justification and no effect.

### Why not D

Because a permanently expired certificate in the data directory of a regulated
system is not a state one wants to explain.

## Decision

Chosen: **Option A.** The agent does **not** store the node SVID.

### 1. What disappears is the file — not the SVID

`Credentials::Issued` still carries it, the server still issues it, and the tests
still verify the chain against the anchor. What falls away is exclusively the
write to `identity/node.svid.pem`.

The promise from ADR-0006 is thereby evidenced as before, and the false signal on
disk is gone.

### 2. That it is discarded stands at the place

At the receiving site stands **why** nothing is written here — otherwise somebody
adds it back as an oversight on the next reading. The reason is the one from
ADR-0043: the node identifies itself with its **key**, not with a chain, and a
stored leaf with a 15-minute lifetime would be a finding without a cause 92 % of
the time.

### 3. The operator loses nothing they had

An expired certificate answers no question. Whoever wants to know whether this
node's chain carries looks at its **agent intermediate** — that is the material
minting happens from, it lives 12 hours and is renewed every 3 hours, so in normal
operation it is valid.

## Consequences

**Positive**
- No permanently expired certificate in the data directory.
- One artefact fewer whose purpose nobody can explain.
- No format break, no figure from ADR-0014 touched.

**Negative / Costs**
- The agent receives material it discards. That is a smell, and it is named rather
  than hidden: the alternative would be a fifth format break or an untested
  issuance path.
- Whoever reads `node.svid.pem` in an operational script today no longer finds the
  file. It was expired 92 % of the time; a script that built on it was already
  broken.

**Risks & Open Points**
- **As soon as something puts a node SVID on the wire**, the file belongs back —
  and then with a lifetime that fits its renewal. That would be a new decision and
  not a rollback of this one.
- Whether the `Purpose::Leaf` path for nodes deserves a **test of its own**,
  instead of only being checked along with the response, stays open. As long as
  the response carries it, it is not untested.

## Related ADRs

- Depends on: ADR-0043 (the key is the credential), ADR-0006 (the chain),
  ADR-0014 (the time windows)
- Closes the open point "the node SVID stays without a task" from ADR-0043
