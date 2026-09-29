# ADR-0108: The Replacement of a Signer Seat (RTS)

- **Status:** accepted
- **Date:** 2026-09-08
- **Deciders:** Architecture
- **Concerns:** ADR-0014 (PKI/threshold CA, determination 3), ADR-0097
  (control path of the group), ADR-0107 (proactive refresh), ADR-0057 (what a
  policy may read), ADR-0044 (operator access)

## Context and Problem Statement

ADR-0014 determination 3 says: *"Replacement of a signer runs via RTS, not via
a ceremony. If a signer fails permanently, another node takes its seat: t
helpers restore the share, the group public key stays, the intermediate stays
valid."*

Phase 7b built the **mechanics** (`repair::helper_deltas`, `combine_deltas`,
`restore`, `restore_seat`), and it is backed by ten witnesses — including the
finding that `repair_share_part3` does not count the sigmas and, with too few,
delivers a *valid-looking, wrong* share (against which the check against the
group key has stood since then).

What is missing is the **transport and the caller**: `restore_seat` runs all
three steps in **one** process, and that is expressly a property of the test
harness, not of the model — there all helper shares lie side by side, which is
never the case in operation. Without the transport, the only answer to a lost
share remains the ceremony at the air-gapped root, that is, exactly what
determination 3 wanted to avoid.

Two questions are to be decided: **who coordinates** the three rounds, and
**who may trigger** a replacement.

## Decision Drivers

- No process may see more than it needs in order to participate (ADR-0014: no
  node ever holds the full key — and a restored share is a share).
- The intervention has security weight and must not run on a timeout
  (ADR-0014, open point; ADR-0057: a failure must not create a decree).
- The transport exists (ADR-0097): one port per seat, mTLS, the key is checked
  against `signers/<seat>.pem`.
- No new auth system, no new packages (ADR-0023).

## The measurement that forces the decision

Measured against the real library, with five seats from a real DKG:

```text
MEASUREMENT relayed deltas yield the share: true
MEASUREMENT relayed sigmas yield the share: true
MEASUREMENT one helper produces 3 deltas for 3 helpers
```

Both lines are grounds for exclusion, and the second is the sharper one:

- A coordinator that **relays step 1** sees all deltas of all helpers — and
  thereby exactly the input of `restore_seat`. The same reckoning as with
  ADR-0107 round 2, where a relaying coordinator could interpolate every
  seat's delta.
- A coordinator that **relays only the sigmas** does not need the deltas at
  all: the sigmas *are* the input of step 3.

**With that the circle of those entitled to see is fixed at exactly one
process** — the one that is to receive the share. And because it **must** see
the sigmas, it must coordinate.

## Options Considered

- **Option A** — any seat coordinates and relays. Per the measurement,
  identical to "one seat obtains another's share".
- **Option B** — the **lost seat** coordinates; the deltas go from seat to
  seat, the sigmas go to it.
- **Option C** — a ceremony at the root (the state before this ADR).

## Decision

Chosen: **Option B.**

1. **The lost seat coordinates**, and nobody else. Per the measurement it is
   the only one that may see the sigmas, and it is the one that needs the
   result.

   That it **can** is a property of ADR-0097: the credential on the signer
   port is the **node key**, not the share. A seat that has lost its share
   still identifies itself.

2. **The deltas go from seat to seat**, not via the coordinator — verbatim the
   same construction as ADR-0107 determination 2: the helper **delivers
   itself** and returns when it has delivered to all others. Afterwards the
   coordinator knows that everyone has everything **without having seen a
   delta**.

3. **A helper delivers its sigma only to the seat it concerns.** The signer
   port knows the caller's seat from the connection's credential (ADR-0097); a
   sigma for seat `N` it hands out only if the caller is seat `N`. That is the
   one new authorization rule of this ADR, and it needs no new auth system —
   just a comparison.

4. **All t or none, and no state beyond the run.** As with the refresh
   (ADR-0107, determination 3): a helper that does not participate aborts the
   run, and a second start discards the first. Leftover state from an aborted
   run must not block a new one.

5. **It is triggered by a human** (`tgctl signer repair`), on the node
   of the affected seat, with the helpers' addresses as a setting. No guard,
   no timeout, no policy — ADR-0057 expressly forbids it: the input would be
   an **absence**.

   The occasion is visible in `tg_identity_signer_seats` (ADR-0097) and in
   `tg_identity_signer_group_info`; whoever acts is an operator.

6. **The result is checked before it is stored.** `repair::restore` compares
   the restored share against the `verifying_share` from the group key — the
   finding from phase 7b. Only afterwards is material written, and into the
   **generation** the group key names (ADR-0107): a share without its epoch
   would be one nobody can place.

7. **The client runs on the affected node and puts material in place** — the
   same role as `cargo xtask threshold` in the ceremony: it creates the files,
   and `tgd` reads them at startup. A `tgd` that starts without a share in a
   repair state is rejected: it would be a process that opens a signer port and
   holds no seat, and the number of available seats
   (`tg_identity_signer_seats`) would then say something false.

## Consequences

**Positive**

- ADR-0014 determination 3 is redeemed: a lost share no longer costs a
  ceremony at the root, and the group key stays — certificates, chains and the
  intermediate remain valid.
- **No process sees more than its own delta**, and that is measured, not
  argued.
- No new auth system and no new packages: the port, the credential and the
  admission list are those from ADR-0097.
- The open point from ADR-0014 ("who holds the seat assignment?") is thereby
  fully answered: `--signer <n>=<url>` and `signers/<seat>.pem` have held it
  since ADR-0097, and the repair names the helpers as a setting.

**Negative / costs**

- **One manual step per replacement**, on the right node and with the helpers'
  addresses. That is the cost side of determination 5 and intended.
- **Three methods more on `SignerLink`** — the trait thereby has thirteen, and
  it is two protocols in one. It stays one because every seat does both and
  both halves hang on the **same** nonce vault and the same epoch; two traits
  would be two trait objects on the same thing.
- **A seat can fetch its own share anew** even if it has it. Harmless (it
  would get what it has), but it is a call nobody needs.

**Risks & open points**

- **The client needs the helpers' addresses as a setting.** They stand in the
  node's unit file (`--signer`), and `tgctl` does not read foreign arguments.
  An operator who names a wrong address gets an abort and not half a share
  (determination 4).
- **The restored share is byte-identical.** RTS restores, it does not
  invalidate — whoever copied the old one still has it afterwards. The answer
  to that is ADR-0107 (refresh), not this ADR, and the manual names the order:
  repair first, then refresh.
- ~~**Custody stays a seam.** The material lands on disk under `PlainCustody`;
  the TPM sealing from ADR-0014 is still outstanding.~~ **Done with
  ADR-0140:** the restored share goes to disk **sealed**. The custody arises in
  the coordinator itself (`seats.rs`) and not at the caller — it runs beside
  `tgd`, and a second way of choosing it would be a second way of forgetting
  it. Without a TPM it stays at `PlainCustody`, with the same message as
  everywhere (ADR-0140: no silent fallback).
  **The case thereby becomes more frequent, not rarer:** with a lost TPM
  binding, `signing/share` is there and merely cannot be opened — so exactly an
  RTS case, and the only one in which `tgd` is certainly running.
- **No audit entry.** The group is decoupled from consensus (ADR-0014,
  determination 1), so there is no log into which a repair would go. It is
  visible in the helpers' logs and in the generation on disk; an entry in the
  audit trail (ADR-0020) would require a path from the group into consensus
  that ADR-0014 expressly does not want.

## Related ADRs

- **Changes** — none. It redeems ADR-0014 determination 3 and answers its open
  point on the seat assignment.
- **Applies** — ADR-0097 (port, credential, admission list), ADR-0107
  (seat-to-seat in round 2, "all or none", generations), ADR-0057 (no policy
  on an absence), ADR-0044 (the operator acts).
- **Presupposes** — ADR-0014 (the group, the threshold, the custody model),
  ADR-0023 (no new packages).
