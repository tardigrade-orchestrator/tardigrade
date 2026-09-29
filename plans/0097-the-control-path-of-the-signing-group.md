# ADR-0097: The control path of the signing group

- **Status:** accepted — its own port, its own trust list, the seat assignment as a
  setting
- **Date:** 2026-09-06
- **Deciders:** Core team

## Context and Problem Statement

ADR-0014 decides: *"the root in the HSM, runtime shares TPM-sealed"* and *"no node ever
holds the full key"*. Phase 7b built the mechanics — DKG, two-round signing,
`NonceVault`, RTS replacement — and named two seams: `ShareCustody` (the TPM) and
`SignerLink` (the network).

**Measured, neither of them is connected**, and the consequence contradicts the decision
directly:

```
tgd/src/identity.rs:70   authority: Authority<LocalSigner>
tgd/src/identity.rs:88   LocalSigner::from_pem(key_pem)
ThresholdSigner in tgd/, tg-agent/:  0 mentions
```

`tgd` runs a **single Ed25519 key**, read from `<data-dir>/signing/ca.key.pem`. Every
control-plane node therefore holds the full CA key as a file — in a REMIT/DORA
environment exactly what an auditor reads as a finding, and the opposite of ADR-0014's
core statement.

What ADR-0014 has **already** decided about it stays untouched here: five seats with
t = 3, replacement via RTS, and *"the seat assignment (identifier → node) is from here
on an operational setting like the peer addresses and does **not** belong in the Raft
membership — otherwise the two would be coupled again."*

Open is the **control path**: where the signer service listens, who may reach it, where
the group material lies, and how it arises.

## Decision Drivers

- **Whoever reaches the signer port can order a group signature.** That is the central
  property: an attacker who reaches t seats has a message of their choice signed — and
  the group signature *is* the CA (ADR-0014). The port **must** authenticate.
- **The decoupling from the Raft membership has to hold** (ADR-0014). A transport using
  the Raft identity reintroduces it at the network level.
- **ADR-0019:** threshold signing concerns the rare upper level (agent intermediates,
  every three hours). A failure of the group costs no workload availability as long as
  the intermediates carry — ADR-0014 names that explicitly as a reason to choose them
  conservatively.
- **An existing cluster has to stay upgradable** (ADR-0031: rolling updates must not take
  fault tolerance to zero).

## Options Considered

**A — the signer service on the cluster port** (`--cluster-listen`, auth against
`peers/<id>.pem`). No fourth port, no fourth trust basis, and today the seats lie on the
five `tgd` nodes anyway.

Rejected: the signer identity would thereby be the **Raft** identity, and a seat could
lie only where a Raft node is. An RTS replacement (ADR-0014, sub-decision 3: *"without a
ceremony"*) would be bound to a membership change — exactly the coupling ADR-0014
dissolved.

**B — its own port, its own trust list.** Chosen.

**C — no transport: all five seats in the leader process.** That is what `LocalLink`
does today, and it is not threshold signing: one process holds all shares, i.e. the full
key. It would be `LocalSigner` with more steps.

## Decision

1. **A listener of its own** (`--signer-listen`) carries the signer service, and the seat
   assignment is a repeatable setting:

   ```
   --signer <seat>=<url>      # e.g. --signer 3=https://tgd-3.fra:7947
   ```

   Seat and Raft identifier are thereby independent. A node with Raft ID 1 can hold seat
   4, and a seat change is not a membership change.

   **Which seat this process holds does not stand in a setting but in the share.** The
   first draft had a `--seat`; measured, the mapping seat ↔ FROST `Identifier` is
   invertible (`Seat::from_identifier`), so the seat stands in the `KeyPackage`. A
   setting next to it would be a second source for the same fact — and the dangerous
   direction: a node announcing itself as seat 3 while holding seat 2's share would let
   the group believe the threshold was reached when it was not. Corrected **before** the
   build.

2. **mTLS against `<data-dir>/signers/<seat>.pem`**, in the construction of ADR-0043: what
   is checked is the **key** against a deposited list, not a chain against a CA. The
   reason is the same as there and here compelling: the CA *is* the group — a check
   against it would be a circle, and a rebuild of the group would presuppose it.

   **Whoever has no leaf in the list gets no commitment and no share.** That is the
   statement everything hangs on.

3. **The group material lies under `<data-dir>/signing/`**, next to the signing CA it
   replaces:

   | File | Content |
   |---|---|
   | `share` | this seat's sealed share (`SealedShare`) |
   | `group` | the group public key (`PublicKeyPackage`) |
   | `ca.pem` | the signing intermediate **for the group key** |
   | `bundle.pem` | the anchors, as today |

   **Without an extension, and that is measured:** `frost-core` 3.0 serializes both
   packages **byte-wise** — `PublicKeyPackage` 360 bytes, `KeyPackage` 134 bytes, in no
   case text. The first draft of this ADR called the file `group.json`; that was
   corrected **before** the build, because a name promising JSON sends the next reader in
   the wrong direction.

   `ca.key.pem` falls away in this mode — there is no private group key in one place.
   That is the property at issue, and it is readable from the **absence of a file**.

4. **The share goes through `ShareCustody`**, and the default stays `PlainCustody` —
   with the note it carries in its name. The TPM sealing from ADR-0014 steps into the
   same place without a line of the control path changing; it is the refinement, not the
   precondition.

   **The gain stands even without it:** a stolen node gives **one share**, and a share
   below the threshold is worthless (ADR-0014). Today the same node gives the full key.

5. **The DKG stays a ceremony** (ADR-0014, bootstrap). For the development path
   `cargo xtask threshold` produces material for all five seats — and **one process sees
   all shares** in doing so, which explicitly does not make it the model. The same
   placement as `cargo xtask identity` for the CA (ADR-0023: a tool that produces keys
   does not belong in a shipped binary).

   The **distributed** DKG over the signer port stays open. It is a three-round protocol
   over five parties, and its benefit lies solely in the bootstrap, which ADR-0014
   describes as a networkless transfer anyway.

6. **If the group material is missing, `tgd` still runs `LocalSigner`** — and says so.
   Anything else would make this ADR a break for every existing cluster: it would come up
   after the upgrade without a CA, and thereby without agent intermediates and within
   twelve hours without SVIDs (ADR-0014).

   **Which signer runs is a metric** (`tg_identity_signer`). Otherwise this ADR's most
   important property — that the full key is **not** on the disk — would not be
   determinable from outside, and a node whose material is missing would look like a
   hardened one.

7. **A seat that does not answer costs no availability as long as t stays reachable.**
   `ThresholdSigner` already provides that (it collects up to the threshold). What a
   **permanently** failed seat costs stays the open question from ADR-0014 — and the
   answer to it is, per ADR-0057, no automatism: a policy must not read an **absence**,
   and an RTS replacement is an intervention with security weight. It becomes visible
   (`tg_identity_signer_seats`), it is decreed by a human.

## Consequences

**Positive**

- **No node holds the full CA key any more.** ADR-0014's core statement is thereby
  redeemed, not merely resolved.
- A stolen control-plane node gives one share instead of the CA.
- The seam from 7a holds: `Authority<S: rcgen::SigningKey>` is generic, and not a line of
  the SVID path changes.
- Seat and Raft identifier are decoupled, as ADR-0014 requires.

**Negative / Costs**

- **A fourth listener and a fourth trust list.** Operational work:
  `--signer-listen`, `--signer` per seat, and distributing the leaves to
  `signers/<seat>.pem` — the same manual work as with `peers/` (ADR-0043).
- **Issuing an agent intermediate now needs t = 3 reachable seats.** Until now the leader
  sufficed. That is carried by ADR-0019: the minting of workload SVIDs stays local to the
  agent, and an existing intermediate carries twelve hours.
- **Two signer modes** are two code paths. The choice stands in one place (an enum
  implementing `rcgen::SigningKey`), and it is a metric.

**Risks & Open Points**

- **`PlainCustody` is not the custody model** (ADR-0014). The share lies unprotected on
  the disk; whoever has it has it. The gain remains that it is **one** share.
- **The distributed DKG is missing.** The dev tool sees all five shares; for production
  ADR-0014's networkless transfer applies.
- ~~**A permanently failed seat** becomes visible and is not replaced — the open question
  from ADR-0014, only placed in context here.~~ — **done:** ADR-0108 — the lost seat
  coordinates its replacement.
- **No witness across five machines.** What is evidenced is the link over five processes
  on one host; that it holds across five failure domains requires a latency measurement
  (the same open spot as ADR-0033).
- **The rotation of the group key** is ADR-0014's ceremony and is not touched here.

## Related ADRs

- **Redeems ADR-0014** (the custody model, "no node ever holds the full key") and answers
  its open point about the transport.
- **Authentication construction: ADR-0043** (a key against a list, not a chain against a
  CA).
- **Seam: ADR-0006/7a** (`rcgen::SigningKey`), **ADR-0035** (the SVID path stays
  untouched).
- **Availability: ADR-0019** (the upper level is rare, the hot path local).
- **No automatism on seat failure: ADR-0057.**
- **A tool, not a shipped binary: ADR-0023.**
