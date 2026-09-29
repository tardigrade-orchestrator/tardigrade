# ADR-0100: The Rotation of the Data Key

- **Status:** accepted
- **Date:** 2026-09-06
- **Concerns:** ADR-0095 (data key), ADR-0016 (secrets), ADR-0055
  (rotation as a number), ADR-0020 (retention), ADR-0044
  (recovery path)

## Context and Problem Statement

ADR-0095 decided the cluster-wide data key and expressly left one point
open:

> **Rotation is a cluster event** and requires setting every value anew. The
> generation machinery from ADR-0055 fits for that, but the re-encryption
> needs the plaintext and therefore a human. **Not decided and not built.**

And in the same ADR: *"It is the only determination of ADR-0016 that this ADR
does not reach."* ADR-0016 names rotation propagation among its open points;
in a REMIT/DORA environment a key that can never rotate is an audit
finding — and one for which there is no remedy other than setting every
secret anew.

**That sentence was too narrow, and that is the finding from which this ADR
arises.** Measured against the crypto as built:

```text
MEASUREMENT re-encryptable without humans: the secret
MEASUREMENT wrong key fails: the ciphertext does not belong to
            this key or was altered
```

The plaintext **is** in the ciphertext, merely locked. Whoever holds the old
key opens every value and seals it anew — no human needs to know a secret.
And because AEAD authenticates, a wrong key fails **detectably**: an opener
can try two keys in turn without guessing.

Rotation is therefore buildable. What remains to be decided is **where** the
re-encryption happens and **what** the order looks like.

## Decision Drivers

- **No window in which a container cannot open its secret.** The dangerous
  part of a key rotation is not the crypto but the order.
- The key must **never** enter the log (ADR-0095, determination 1).
- The plaintext should not see more places than it does today.
- An operator must know **when** they are done — otherwise the old key stays
  lying around forever and the rotation has achieved nothing.

## Options Considered

**A — A human sets every value anew.** What ADR-0095 hinted at. Rejected:
measured unnecessary, and not feasible for a cluster with dozens of secrets —
what is not feasible does not get done.

**B — The leader re-encrypts.** It has the state and the old key. Rejected on
the question of where it gets the **new** one: not from the log
(determination 1), so it would need a second channel into the control plane,
and there is none.

**C — An envelope per secret (KEK/DEK).** The finer construction: one data
key per value, sealed with the cluster key; rotating the cluster key means
only the envelopes get rewritten. Rejected because the envelope lies **with
the value** — it is the same number of writes into the log. The gain would be
that long values stay untouched; secrets are passwords and tokens.

**D — Two keys at once, re-encryption in the client.** Chosen.

## Decision

### 1. The cluster holds two keys: one for sealing, both for opening

`identity/secrets.key` is the **primary** — it is used for sealing.
`identity/secrets.key.previous` is the **outgoing** one — it is used only for
opening. If it is absent, there is nothing to retire; that is the normal case.

Both travel to the agent on the credential path (ADR-0095, determination 2),
and the opener tries them in turn: the primary first, then the outgoing one. A
wrong key fails detectably, so this is not guessing.

**There is therefore no window.** As long as both are present, it does not
matter which one a value was sealed with — every container opens its secret.
That is the entire purpose of the two-key phase and the reason why the order
below works.

### 2. Re-encryption happens in the client

`tgctl cluster secret rekey` reads every ciphertext, opens it (both keys),
seals it with the primary and issues an ordinary `PutSecret`. That is the same
place at which ADR-0095 determination 4 already seals: the client is the place
where key and plaintext come together, and in doing so it sees no plaintext it
would not be allowed to see anyway.

**A new read path hands out the ciphertexts** (`rekey_material`), and only
this one. The existing read path (`tgctl cluster secrets`) stays without
values — it is enumerated, and ciphertext in every answer would be ciphertext
in every log. The new call is on the admin socket, and whoever reaches that
reads the key from disk anyway (ADR-0044).

### 3. The order is the whole art, and it lies with the operator

1. Generate a new key (`tgctl secret keygen`).
2. On **every** `tgd`: the old one to `secrets.key.previous`, the new one to
   `secrets.key`. Restart the process.
   → From here the cluster seals with the new one and opens with both. The
   agents get both at their next renewal.
3. `tgctl cluster secret rekey` — every value is resealed.
4. Wait until `tg_cluster_secrets_previous` stands at **zero**.
5. Remove `secrets.key.previous` on every `tgd`. Restart the process.

**Step 4 is not ornamentation.** Without it an operator does not know when
they may remove the old key — and if they remove it too early, every value
that `rekey` did not reach is **unreadable**. The number makes the rotation
closable.

It counts at the **leader**, which has both keys: how many secrets cannot be
opened with the primary. `0` means done.

### 4. No generation in the log

Unlike with the node keys (ADR-0055) and the snapshots (ADR-0099), the
rotation is **not** a decree in the log, and that has two reasons.

The key itself must not go in (determination 1), so a generation could only
say "rotate now" — and then the recipient lacks exactly what it needs. And the
re-encryption produces a log entry per value anyway: `PutSecret` is audited
and carries its actor (ADR-0050). **The audit trail is thereby complete
without a second mechanism standing beside it.**

### 5. No policy

`SetSecret`-style commands are not on the allowlist from ADR-0057, and `rekey`
is not a log command. A cadence ("every 90 days") would be a decision about a
procedure with five steps, three of which a human performs on every node — it
could not be automated without putting the key into the cluster.

### 6. The fingerprint remains the visibility

`tg_identity_data_key` (ADR-0095) shows which key applies per process; the
alert rule on it catches two `tgd` with different keys. During a rotation an
offset is **expected** — that is why its `for:` duration is generous, and why
step 2 says "on every `tgd`" with a restart in the order.

New beside it: `tg_cluster_secrets_previous` (determination 3).

## Consequences

**Positive.** The last open determination of ADR-0016 is redeemed. The
rotation needs **no** human for any value — it is thereby feasible, and what
is feasible gets done. There is no window in which a container cannot open its
secret, and the procedure is closable on a number.

**Negative.** Five steps, three of them by hand on every node. The plaintext
of every secret passes through `tgctl`'s memory in the process — more than
today, where only the one an operator sets does. An operator who forgets step
5 has the old key lying around forever; the only sign of it is that the file is
there.

**And the log grows.** Every value gets a new `PutSecret` entry, and the old
one stays retained (ADR-0020) — with a ciphertext that the retired key opens.
Whoever ever gets hold of the old key reads the values that applied during its
validity. That is the flip side of a retention-bound log and no peculiarity of
this rotation; whoever wants more needs deletion in the log, and that is not
compatible with ADR-0020.

## Related ADRs

- **ADR-0095** is supplemented: its open point is redeemed, and its sentence
  about the human is measured too narrow. The ADR itself stays as it is
  (invariant 6); the classification is in the plan.
- **ADR-0016** gets its last determination.
- **ADR-0055** does not supply the form: there rotation is a number in the
  log, here it cannot be (determination 4).
- **ADR-0044** carries the access: `rekey` runs over the admin socket.
- **ADR-0020** carries the cost side: the old ciphertext stays in the log.
