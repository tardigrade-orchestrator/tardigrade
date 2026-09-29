# ADR-0107: Proactive Refresh of the Signer Shares

- **Status:** accepted
- **Date:** 2026-09-07
- **Deciders:** Architecture
- **Concerns:** ADR-0014 (PKI/threshold CA), ADR-0097 (control path of the
  group), ADR-0055 (rotation as desired state), ADR-0100 (two keys at once),
  ADR-0057 (what a policy may read)

## Context and Problem Statement

ADR-0014 sub-decision 3 names four points, and three are built: the group is
decoupled from the Raft membership, t = 3 of 5 stands, and the replacement of
a seat runs via RTS. The fourth is open, and the ADR says itself that nothing
is missing from it but the decision:

> **Open: proactive refresh** (point 4 of sub-decision 3). It is not in the
> deliverables of phase 7b and is not built. `frost::keys::refresh` is ready;
> the cadence is an operations question.

What hangs on this is not completeness but the only answer this system has to
a **betrayed** share. Measured, there is no other:

| Share is … | Answer today |
|---|---|
| lost (disk gone) | RTS (`keys::repairable`) — the same share comes back |
| betrayed (copied) | **none** — it stays valid forever |

RTS **restores** a share; it does not invalidate it. A copied share therefore
remains valid until the next ceremony (new DKG, new group key, new
intermediate from the air-gapped root, ADR-0014 D5). At t = 3 that means:
whoever compromises two seats over two years needs only one more — and time
works for them. The refresh is the mechanism that **bounds a compromise in
time**.

The occasion is that there is now a place for it: **ADR-0097** built the
control path between the seats, and `ThresholdSigner` is connected to `tgd`.
Before that a refresh would have been a mechanism without a caller.

## Decision Drivers

- **The purpose of the refresh is that two epochs cannot be combined.** What
  removes that property is not an implementation of the refresh but a way
  around it.
- **Changing N is a ceremony** (ADR-0014 D5). A periodic procedure must not be
  able to change N — not even accidentally.
- **The group key must survive**, otherwise the intermediate from the root is
  gone and it *is* a ceremony.
- **The group is decoupled from consensus** (ADR-0014 D1, ADR-0097): a seat is
  not necessarily a Raft member. What the seats coordinate cannot run over the
  log.
- **Signing must not fail**, neither during nor after a refresh.

## The six measurements on which the decision rests

Against `frost-core` 3.0.0, on a real five-seat group:

| Measurement | Result |
|---|---|
| group key after a refresh | **byte-identical** |
| refresh with 3 of 5 identifiers (dealer way) | **accepted**; `verifying_shares` 5 → 3 |
| the two omitted seats afterwards | `UnknownIdentifier` — out of the group |
| signing with mixed epochs | `InvalidSignatureShare { culprits: [the old seat] }` |
| DKG refresh with fewer than all | `IncorrectNumberOfPackages` |
| DKG refresh with wrong t | `InvalidMinSigners` — only in round 3 |

**The second row is the finding.** A refresh that does not name all five
identifiers is not a refresh with fewer participants but a **silent shrinking
of the group** — the library says so in its documentation (*"the refresh
procedure will effectively remove the missing participants"*) and does not
reject it: `validate_num_of_signers` only requires `>= t`. Afterwards the
group is 3 of 3 and tolerates **zero** failures where ADR-0014 D2 promises
two. And because the group key stays the same, nothing breaks visibly: it
shows up at the **next** failure.

The fourth row determines the form of the transition, and it is more
unpleasant than it sounds: the aggregation accuses the one **left behind**. An
operator reads "seat 3 is broken" while in truth a refresh has half run.

## Options Considered

### R1 — Trusted-dealer refresh (`compute_refreshing_shares`)

One process draws a zero polynomial and gives each seat its delta; each adds
it to its share. **One** round, and measured the dealer needs only the
**public** group key — it sees no share.

Rejected, for two reasons. First: it knows **all the deltas**. Whoever takes
it over and records along can convert a share of the new epoch into one of the
old and vice versa — and with that exactly the property for the sake of which
the refresh runs is gone. A dealer does not hold the key, but it holds the
**bridge between the epochs**, and that is functionally the same violation of
ADR-0014's "no node ever holds the full key".

Second, and this is the reason that carries without an attacker: **this way
can shrink the group.** Row 2 of the measurement is not an edge case but the
documented behaviour, and a periodic procedure must not change N (ADR-0014
D5).

### R2 — DKG refresh (`refresh_dkg_part1/part2/shares`), chosen

Each seat draws its own zero polynomial; three rounds; no dealer, and no
process knows all the deltas.

The price is that all five must participate — and measured that is **no
additional price**: a refresh with fewer than all is not permitted anyway, and
the dealer way saves no availability requirement, only two rounds. What the
DKG way additionally achieves is that it **cannot** make the error from row 2:
`IncorrectNumberOfPackages` is the library's answer, not our check.

### R3 — No refresh; a betrayed share stays a ceremony

Honest, and not bearable for a REMIT/DORA environment: the only answer to a
compromise would be an intervention at the air-gapped root, that is, one that
gets postponed. The refresh turns a rare ceremony into a routine procedure,
and that is exactly what ADR-0014 D4 names as its purpose.

## Decision

### 1. The way is the DKG, not the dealer

Three rounds over the control path from ADR-0097. No process of this system
sees more than its own delta — the same promise as with signing itself.

### 2. All five or none

A refresh with fewer than all seats is not run. The library enforces it
(`IncorrectNumberOfPackages`), and the coordinator aborts before it begins the
first round if not all seats answer — with that the message is "seat 4
unreachable" and not "round 3 failed".

An aborted refresh **changes nothing**: the decreed epoch stays, and a staged
result that not all have is not used.

### 3. Two shares at once, as ADR-0100 has two keys

After a refresh a seat holds **both** epochs: the active and the new one. The
reason stands in row 4 of the measurement — mixed epochs do not sign, and the
one left behind is accused. Without the overlap every refresh would be a
window in which the group does not sign.

Rejected is a transition via a mark in the log: the group is decoupled from
consensus (ADR-0014 D1); a seat need not see the log at all.

### 4. The coordinator names the epoch

`commit` and `sign` carry it. A seat that does not hold it answers with an
error of its own instead of with a share from a different epoch — the
rejection is thereby ours and not `InvalidSignatureShare` in the aggregation.

The coordinator takes the highest epoch **it itself** holds, and falls back to
the previous one if it cannot assemble t seats for it. Because only two are
held, that is one attempt and one fallback, not a loop.

### 5. The epoch is a number beside the share, not a log entry

It lies in the material on disk (`share.<epoch>`), for the same reason as
determination 3: consensus is not responsible for the group. If it is missing
— material from before this ADR — it is **epoch 0**; an invented number would
take an existing group's shares from it.

### 6. The old epoch is discarded when all five have the new one

And not earlier: as long as one seat has only the old one, that is the only
one in which t can be assembled. Whoever discards it earlier takes the
fallback epoch from determination 4 away from the group.

### 7. The cadence is a policy over the clock, and it comes later

ADR-0057 permits it: a calendar does not fail. It is **not** part of this cut
— the mechanism first, as with ADR-0092 (D7) and for the same reason: a
cadence on a mechanism nobody has run is a number without an object.

Until then the trigger is a human. For "on suspicion of a compromised share"
(ADR-0014 D4) that is the only possible one anyway.

## Consequences

**Positive.** A betrayed share is from here bounded in time rather than
permanent, and the answer to it is a procedure instead of a ceremony at the
air-gapped root. The group key survives, so the intermediate stays valid and
no verifier notices anything. And the silent shrinking from row 2 of the
measurement is structurally excluded: the chosen way cannot do it.

**Negative, and deliberately borne.** A refresh requires **all five** seats,
while signing requires three — the availability requirement of the maintenance
procedure is thereby stricter than that of operations. That is the right
direction (a refresh that does not run costs nothing; one that shrinks the
group costs the fault tolerance), but it means: a permanently failed seat must
first be replaced via RTS before a refresh is possible again.

**A protocol growth on the signer port.** `CommitRequest` and `SignRequest`
carry the epoch, and both are strict (ADR-0072). The port is between `tgd`
processes of **one** cluster, and the seats are upgraded together — it is the
same coordinated transition in which the others lie.

**What this ADR does not solve.** The TPM sealing of the shares stays open
(ADR-0014); a refresh puts the new shares where the old ones lay, and
`PlainCustody` still carries in its name that it is not the model. A share
betrayed between two refresh runs is valid until the next one — the period is
the cadence, and that is not yet decided.

## Related ADRs

- **Redeems:** ADR-0014, sub-decision 3, point 4.
- **Builds on:** ADR-0097 (the control path between the seats), ADR-0014 D1
  (the group is decoupled from consensus — hence no mark in the log).
- **Follows the form of:** ADR-0100 (two keys at once, so that the rotation
  has no window), ADR-0055 (rotation as state, not as a shout).
- **Defers to:** ADR-0057 (the cadence as a policy over the clock).
