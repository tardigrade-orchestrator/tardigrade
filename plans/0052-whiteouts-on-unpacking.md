# ADR-0052: Whiteouts on unpacking — deleted files that reappear

- **Status:** accepted
- **Date:** 2026-08-25
- **Deciders:** Core team
- **Technical context:** `tg-runtime` (`content`, `bundle`, `volume`), ADR-0003,
  ADR-0027, ADR-0017, invariant 2

## Context and Problem Statement

Phase 10c built shared, read-only volumes as an overlayfs over the
content-addressed layers — literally with the same store as the images
(ADR-0027: *"distributed to the nodes content-addressed (like the image content
store, 0003)"*). There the following stands as an open point:

> **Whiteouts are not evaluated.** A layer that deletes a file of the one beneath
> it (`.wh.`) is treated as an ordinary file. For reference data from a tar that
> is inconsequential; for a multi-layer image it would be wrong. To be decided
> whether that is a reason to refuse multi-layer sources.

## The finding: it is not a volume question

Checked who calls `Content::unpack_layer`: **the same store serves the volumes
and the container images.** That was precisely the point of 10c — no second
store, no second mechanism. And both sides mount the layers as overlayfs
`lowerdir=` (`bundle.rs` for the rootfs, `volume.rs` for the volume).

The open point therefore applies **not** to exotic volume sources but to **every
multi-layer container image since phase 2.** A base image that removes a file in
a later layer still shows it — and next to it a file called `.wh.<name>`.

The question from 10c of whether multi-layer sources should be refused is
therefore none: almost all images are multi-layer. What is up for debate is not
the whether but the how.

**The weight is not cosmetic.** Removal is a common operation in images with a
security intent: a package-manager cache with credentials, a setuid binary, a key
that lay in a build layer. Whoever deletes it in a later layer and trusts that has
deleted nothing with us. The layer beneath still lies in the store, and the
container sees it.

A second case belongs with it: **`.wh..wh..opq`**, the opaque directory marker. A
layer that replaces a whole directory instead of supplementing it says so with
that marker — and with us a file with that name appears instead, while the old
content shines through.

## Decision Drivers

- **ADR-0003 leaves the semantics to the kernel and the runtime.** Overlayfs
  knows whiteouts natively; rebuilding them would mean writing filesystem
  semantics in Rust.
- **The store is keyed by digest and is shared** — a layer lies there once and
  serves several images. That is the purpose of the store.
- **Invariant 2:** `#![forbid(unsafe_code)]` except in `tg-syscall`.
- **ADR-0017: the agent is privileged.** What needs privileges it may do; what it
  cannot do must stand out.
- **The `.complete` marker already exists** and protects against half-unpacked
  layers.

## Options Considered

- **A — translate on unpacking.** `.wh.<name>` becomes the overlayfs whiteout (a
  character device 0:0), `.wh..wh..opq` becomes the xattr
  `trusted.overlay.opaque`.
- **B — flatten on unpacking.** All layers of an image into **one** directory,
  really executing the deletions. One `lowerdir`, no whiteouts.
- **C — refuse layers with whiteouts.** Reject them at fetch time, with a clear
  message.
- **D — nothing.** Document the finding.

### Why not B

It is the simplest semantics and it costs the store its purpose. The blob
download would stay shared, the **unpacked** form would be per image — ten images
on the same base would have ten copies of the base on disk. ADR-0003 built the
content store for exactly that, and 10c repeated it verbatim: *"A layer an image
has already brought is not fetched again."*

Besides: executing deletions in the filesystem means rebuilding the order of the
layers in Rust — including opaque directories and special cases overlayfs has
known for years.

### Why not C

It would be honest and unusable: multi-layer images with whiteouts are the normal
case, not the exception. An orchestrator that refuses `debian:stable` is not one.

### Why not D

The finding is a silent falsehood with security weight. What somebody believes
they deleted is there.

## Decision

Chosen: **Option A** — translation happens on **unpacking**, and the semantics
stay with the kernel.

### 1. On unpacking, not on mounting

From here on the store holds **overlayfs-native** layers. `lowerdir=` stays
untouched, `bundle.rs` and `volume.rs` do not change — the semantics are the
kernel's, as ADR-0003 foresees for the runtime.

At mount time the information would be gone anyway: a `.wh.foo` is then a file
called `.wh.foo` and indistinguishable from a real one. The tar convention is
read where the tar is read.

### 2. Two translations, and the marker is not unpacked with them

- `.wh.<name>` → a character device `0:0` called `<name>`; the marker itself is
  **not** created.
- `.wh..wh..opq` → the xattr `trusted.overlay.opaque="y"` on the containing
  directory; the marker itself is **not** created.

If the marker stayed, the container would see a file that does not exist in the
image.

### 3. Position-independent, because the store is shared

The obvious refinement would be to omit whiteouts in the **bottom** layer — there
is nothing to obscure there, and a character device 0:0 would be visible where a
file is expected.

**That does not work, and the reason is the purpose of the store:**
`unpack_layer` unpacks **one** layer, keyed by its digest, without knowing in
which image it lies at which position. The same layer can lie at the bottom in
one image and above in another. A position-dependent translation would mean two
different unpackings of the same digest — and therefore the end of sharing.

Translation therefore happens **always and identically**. The price is the named
special case: a whiteout in the bottom layer becomes a visible character device.
In a real image it does not exist — the bottom layer has nothing it could delete
— and the price is worth the sharing.

### 4. Safe wrappers, no `unsafe`

`rustix::fs::mknodat` and `rustix::fs::setxattr` are safe functions; `rustix` is
in the tree. Invariant 2 is untouched, and `tg-syscall` stays the only place with
`unsafe`.

### 5. Whoever may not, does not unpack

A character device requires `CAP_MKNOD`, a `trusted.` xattr requires
`CAP_SYS_ADMIN`. The agent has both (ADR-0017). **If they are missing, unpacking
fails** — it is not skipped.

A skipped whiteout would be exactly the state this ADR abolishes, and then in a
run nobody recognizes as special. The `.complete` marker carries that along: it
arises only after complete unpacking, so a failed layer is re-unpacked on the
next attempt and not read as finished.

### 6. The marker is input, not a statement

*Added during the build, and the reason is a finding, not caution.*

The name comes from a tar a **registry** delivered. Stripping `.wh.` and
appending the result is therefore not enough:

- `.wh...` yields `..` after the prefix — a whiteout **above** the layer
  directory. On the way there lies a `remove_dir_all`, and for a layer at the
  root that would be the node's entire unpacked layer store. Triggered by a file
  name in an image.
- `.wh.` alone yields the empty name, i.e. the layer directory itself.

Both are valid names in a tar. What is translated is therefore only a **single,
ordinary path component**; everything else refuses the **layer**, not the entry —
a registry delivering such a thing is broken or malicious, and in both cases
carrying on is the worse answer. Likewise refused is the form `.wh..wh.<…>`,
reserved by the convention for its own purposes, except opacity itself: giving it
a meaning would mean inventing one.

The decision at this boundary is a **pure function**. That is not a matter of
style: from outside only `unpack_layer` leads in, and that creates character
devices — a fuzz run over it counted every marker as a refusal when unprivileged
and confirmed itself. The effect is checked deterministically and privileged next
to it.

### 7. The convention is ambiguous, and we follow it nonetheless

A tar containing a real file called `.wh.foo` is from here on misinterpreted.
That is inherent in the OCI convention and not curable: it encodes metadata in
the file name. Whoever puts reference data into a volume must not name a file
that way — and that is an easier restriction to bear than images whose deletions
have no effect.

## Consequences

**Positive**
- **Deletions take effect.** What an image removes is removed — including what
  was removed for security reasons.
- Opaque directories behave as the image says.
- The store stays shared; no layer is unpacked twice.
- `bundle.rs` and `volume.rs` stay untouched: the semantics lie with the kernel.

**Negative / Costs**
- ~~**Already unpacked layers are wrong** and are not re-unpacked automatically.~~
  **Fixed, see the addendum:** the marker carries a version number, and a layer
  from before is re-unpacked by itself. The manual step in the operations manual
  falls away.
- A whiteout in the bottom layer becomes a visible character device
  (determination 3).
- A layer with an unusable marker is refused **entirely** (determination 6). An
  image that used to run can thereby stop running — and that is intended: until
  now it ran because the marker had no effect.
- A real file with a `.wh.` prefix is misinterpreted (determination 7).
- Unpacking from here on needs privileges it did not need before. On the agent
  they are there (ADR-0017); a test that runs without them has to know it.

**Risks & Open Points**
- ~~**Checkable only with privileges.** A test needing `mknod` and `trusted.`
  xattrs belongs in the lane that already runs with rights (`cargo xtask
  net`/`storage`), not in a unit test.~~ — **done:** built —
  `crates/tg-runtime/tests/layers.rs` checks the character device and
  `trusted.overlay.opaque` on real files.
- ~~**Hard links across layers**~~ — **measured, and it is not a silent
  falsehood:** a hard link to a target whose layer it does not bring along makes
  unpacking **fail**, and the layer does not count as finished. The OCI
  convention requires a hard link to stay within its layer anyway. Pinned as a
  test so that the loud failure does not become a quiet one.
- ~~Whether the store needs a **version number**~~ — **it does, see the
  addendum.**

## Addendum: the version number

*Added while closing the open points.*

The marker said "fully unpacked" and not **by which procedure**. Layers from
before this ADR therefore still lay in the store and showed files an image had
deleted — remedied only by a manual step an operator *has* to take. Exactly the
kind of seam somebody eventually does not observe.

The marker therefore carries a **version** (`tardigrade-layer 2`), and
`has_layer` requires it. A layer of the old form counts as absent and is
re-unpacked on the next access; that costs work once and saves the manual step.

The counter-check belongs with it and stands as a test of its own: a layer of the
**current** version is **not** unpacked again. A version check that always
re-unpacks would take the store's purpose away — and would be distinguishable
from a correct one only by that assertion.

## Related ADRs

- Depends on: ADR-0003 (the content store, semantics with the kernel), ADR-0027
  (shared volumes over the same store), ADR-0017 (a privileged agent),
  invariant 2
- Affects: ADR-0003 — from here on the store holds overlayfs-native layers
  instead of raw tar extracts
