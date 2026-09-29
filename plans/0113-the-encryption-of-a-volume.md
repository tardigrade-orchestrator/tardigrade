# ADR-0113: The Encryption of a Volume

- **Status:** accepted
- **Date:** 2026-09-10
- **Decider:** Dana Schlifka
- **Technical context:** `tg-runtime` (`volume`), `tg-agent`, `tg-identity`
  (`secrets`), `tgctl`

## Context and Problem Statement

ADR-0027 requires **at-rest encryption per volume (LUKS/fs-level) with the key
from the secrets service** and at the same time carries among its open points
the question that blocked it: *"custody of the volume encryption key
(0014/0016)."*

To this day only the **seam** is built. `tg_runtime::volume` says it itself:

> A bare directory would be simpler and could not do three things that
> ADR-0027 requires: have a **size**, be **grown**, and offer a seam for
> **at-rest encryption**. A LUKS container lies exactly where the naked file
> system lies today.

The blocker is gone: **ADR-0095** decided and built a cluster-wide data key,
and its own consequences name this goal — *"ADR-0016 is unblocked, and with it
… the at-rest encryption of the volumes (ADR-0027)."* The key reaches the node
level-triggered on the credential path and lies in `identity/`.

What is missing is the decision: **which key, when, and what the case costs in
which it is gone.**

## Decision Drivers

- **ADR-0027** — the mandate, and the custody question as its open point.
- **ADR-0095, determination 5** — what a data key protects is a disk that
  **leaves** the cluster; not a compromised node. And determination 6: the key
  is backup-critical material.
- **ADR-0019** — the availability of the workloads must not hang on the control
  plane.
- **ADR-0017** — hardening is the default, relaxation explicit and audited.
- **ADR-0038 / ADR-0039** — the cheapest licence-clean boundary: a GPL tool is
  **called**, not linked.
- **The pitfall from 9d** — *"Using the same key in two protocols is a known
  pitfall."* There it was two key pairs per node, expressly separated.

## The measured state

| | |
|---|---|
| `cryptsetup` | 2.8.7 present, GPL-2 — the same boundary as `nft`, `losetup`, `mkfs.ext4` |
| `ring::hkdf` | in `ring` 0.17.14, and `ring` lies in `tg-identity` — **zero new crates** |
| The seam | `volume::declare` creates, `volume::mount` mounts |
| The tool call | `volume::run(program, args)` knows **only argv**, no stdin path |
| The layers | `tg-runtime` depends on `tg-model`, **not** on `tg-identity` |

The last row decides along: whoever put the derivation into `tg-runtime` would
pull key knowledge and `ring` into the crate that starts containers.

## Options Considered

**Which key:**

- **A — the data key from ADR-0095 directly** as the LUKS passphrase. Cheapest
  variant, one custody model. But the same 32 bytes would be both AEAD key and
  passphrase, and a compromised volume would give away every other one's
  passphrase.
- **B — a separate cluster-wide volume key**, delivered on the same path. Clean
  separation, but a second piece of backup-critical material, a second rotation
  path, a second manual step in the manual.
- **C — derived per volume** from the data key.

**When:**

- **D — a setting in the declaration** (`<volume encrypted="…">`).
- **E — always**, for every newly created writable volume.

**With what:**

- **F — fs-level** (fscrypt/ext4). Requires file-system support and does not
  encrypt metadata.
- **G — LUKS2** on the loop device.

## Decision

Chosen: **C, E and G.**

### Determination 1 — LUKS2 on the loop device

The container lies exactly where `volume.rs` named the seam: between loop
device and file system. `cryptsetup` is **called**, not linked — the same
boundary and the same justification as with `nft` (ADR-0038), `losetup` and
`mkfs.ext4`. It thereby becomes an operational prerequisite, like those.

Against fs-level speaks that it requires file-system support and leaves the
metadata open; here there is a block device anyway.

### Determination 2 — the key is **derived**, not reused

A volume's passphrase is

```text
HKDF-SHA256(ikm = DataKey, info = "tardigrade:volume:v1:" ‖ <volume>)
```

That holds both: **one** custody model, **one** backup obligation, **one**
rotation path — and nevertheless domain separation. The data key is never
itself a passphrase, and one volume's passphrase opens no other.

Option A is thereby rejected, with the justification from 9d: the same key in
two uses is a pitfall, even when both are symmetric. Option B likewise, but
from the other direction: a second piece of backup-critical material is a
second one someone forgets.

**The generation number stands in the `info` string.** Without it a later
change of procedure would be indistinguishable from outside.

### Determination 3 — the passphrase goes over stdin, never over argv

`volume::run` today knows only argv, and argv appears in the process list. The
call therefore gets a sibling path that writes stdin
(`cryptsetup --key-file -`). It never lies on disk — the same promise as in
ADR-0098, where a secret's plaintext never leaves the agent.

### Determination 4 — the derivation lies with the **agent**

It holds the data key anyway (ADR-0095) and builds the reconciler's `Context`.
`tg-runtime` gets an opaque passphrase per volume and does not know where it
comes from — just as it does not know the XSD layer.

Otherwise the crate that starts containers would depend on `tg-identity` and on
`ring`.

### Determination 5 — **every newly created writable volume** is encrypted

No setting in the declaration. A switch would mean that "unencrypted" is a
choosable state, and the failure would be **silent**: an operator who forgets
it gets a plaintext disk and no signal. That is the construction ADR-0017
("hardening default-on") and ADR-0090 ("for every container, escape only at the
node") both chose.

Shared RO volumes stay out of it: they are content-addressed distributed
reference data (ADR-0027, phase 10c), and their content is the same as in the
image store — encrypting it would protect nothing that the layer beside it did
not disclose.

### Determination 6 — existing plaintext volumes remain, and become **visible**

No silent conversion. It would be a data migration without a way back, and it
would hit exactly the volumes at which a failure is most expensive.

Instead the difference is **reported** — a metric per node and a column in
`tgctl cluster volumes`. The way to encryption is the one ADR-0099 built
anyway: snapshot, new volume, restore. That is operations work and belongs in
the manual, not in an automatism.

The same movement as with auto-detach (ADR-0057) and the changed declaration
(ADR-0070): where an automatism would have to decide too much, the deviation is
made visible and the action stays with the human.

### Determination 7 — rotation is a keyslot swap, not a re-encryption

LUKS encrypts the data with a **master key** in the header; the passphrase only
opens a keyslot. A change of the data key (ADR-0100) is therefore `luksAddKey`
with the new derived passphrase and `luksRemoveKey` for the old one — seconds
per volume instead of a copy of the content.

That fits ADR-0100's window without any effort: there **two** keys are valid at
once, here **two keyslots** are occupied during that time. And it is
level-triggered like everything else: the reconcile checks whether the keyslot
matches the applicable generation and catches up.

### Determination 8 — what it protects, and what not

**Protected** is a disk that leaves the cluster: a decommissioned node, a drive
in RMA, a stolen server. That is exactly what ADR-0095 warns about today with a
sentence in `tgctl node remove` — *"the disk of a removed node belongs
wiped"* — and this determination turns the warning into a property.

**Not protected** is a compromised node. It must be able to mount the volume,
so it holds the key. That is not a gap in the procedure but the boundary of the
model from ADR-0016, and it stands here because otherwise someone takes it for
one.

### Determination 9 — from here the key is backup-critical material **with data
attached**

ADR-0095 determination 6 says: if all nodes lose their disk, all secrets are
lost. From here more applies — an operator can set a secret anew, a volume not.
The loss of the data key is therefore tantamount to the loss of **all writable
volumes** of the cluster.

That changes not the procedure but the urgency of the backup, and it belongs in
the manual with the same sharpness as the CA root (ADR-0014).

## Consequences

**Positive**

- ADR-0027's mandate is redeemed, and its open point on custody answered.
- A decommissioned storage device no longer carries readable workload state —
  the at-rest threat that matters to an auditor under REMIT/DORA.
- No second custody model, no second piece of backup-critical material, no
  second rotation path.
- Rotation costs a keyslot swap, not a copy.
- **Zero new crates.** `ring` lies in `tg-identity`; `cryptsetup` is a process.

**Negative / costs**

- **`cryptsetup` becomes an operational prerequisite**, like `nft` and
  `losetup`.
- **A node without a data key cannot create a writable volume.** It gets it at
  join and at every renewal (ADR-0095, determination 2), so it is locally
  present after the first admission — but the **first** start of a workload
  with a volume thereby hangs on the credential path. That is defensible,
  because a node without admission gets no slice and hence no workload anyway
  (ADR-0043).
- **dm-crypt costs throughput and latency.** How much is expressly **not**
  stated here: there is no measurement in this tree, and a number nobody can
  substantiate does not belong in an ADR. It belongs on the same list as the
  tail benchmark from ADR-0022 — "real hardware".
- **Two sorts of volume** for the duration of the changeover, and the second
  disappears only through operator work.

**Risks & open points**

- ~~**The keyslot reconcile from determination 7 is built as soon as a change
  of data key requires it.** Until then a volume carries exactly one keyslot; a
  change without catching up would make it **unopenable**, and that is why the
  reconcile belongs in the same step as the encryption itself and not later.~~
  — **done:** built — `VolumeStore::ensure_keyslot`, called from `mount` and
  `resize`.
- **`resize2fs` works behind the mapper from here on.** The path from ADR-0063
  (grow at startup, never shrink) gets one step more: `cryptsetup resize` before
  `resize2fs`. If it is forgotten, the image grows and the file system does not
  — visible, but ineffective.
- **A snapshot is from here a copy of the ciphertext** (ADR-0099 copies the
  image). That is the right direction — a snapshot that carried the plaintext
  would have just undone the promise — but a restore on a cluster with a
  different data key fails. That is not a regression but the point; it belongs
  in the manual.

## Related ADRs

- Depends on: **ADR-0095** (the data key and its path), **ADR-0100** (its
  rotation), **ADR-0027** (the mandate)
- Redeems: **ADR-0027**, open point *"custody of the volume encryption key"*;
  **ADR-0016**, at-rest for volumes
- Applies: **ADR-0038/0039** (foreign programs, arm's length), **ADR-0017**
  (hardening as the default), **ADR-0057/0070** (make visible instead of
  deciding automatically)
- Touches: **ADR-0063** (resize behind the mapper), **ADR-0099** (a snapshot
  carries ciphertext), **ADR-0019** (the first start hangs on the credential
  path)
