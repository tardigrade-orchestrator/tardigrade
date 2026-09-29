# ADR-0120: A New Image Reaches the Rootfs

- **Status:** accepted
- **Date:** 2026-09-12
- **Concerns:** ADR-0070 (the changed declaration), ADR-0071 (the decree),
  ADR-0027 (the ephemeral volume), ADR-0119 (the release on clearing away)

## Context and Problem Statement

ADR-0119 left the open point whether a **restart** should get a fresh `upper` —
ADR-0027 and phase 2 say the `upper` is the ephemeral volume and dies with the
container.

On measuring it turned out that something bigger lies at the same place.

### The measurement

`apply` stops the container and calls `start` → `bundle::build`. There stands:

```rust
let mount = if is_overlay_mounted(&rootfs) {
    OverlayMount::already_mounted(&rootfs)
} else {
    mount_overlay(&lower, &upper, &work, &rootfs)?
};
```

Since ADR-0119 a bundle is released on **clearing away**; on a **restart** it
is not. The rootfs therefore stays mounted, and `build` takes the existing
mount — with the **old** `lowerdir`. Reproduced against the kernel:

```text
1. mount with layer A → rootfs/file.txt = "from-A"
2. container writes rootfs/scratch.txt
3. already mounted → build does NOT remount
4. rootfs still shows: from-A   (layer B would be "from-B")
5. scratch survives: from-the-container
```

**A changed image reaches the `config.json` but not the file system.**
`tgctl cluster restart` after a new image tag starts the container with the new
command line and the old rootfs. With that the promise from ADR-0070/0071 — "it
takes effect at the next start" — is false for everything that sits in the
image: programs, libraries, configuration, security updates.

### Why no witness noticed it

`an_ordered_restart_replaces_the_container_with_the_current_declaration` checks
the `config.json` (`900` instead of `600`) — and seeds the "new" image with
**the same** layer directory as the old one. Even with a correct remount the
content would have been identical. The test cannot see the finding.

### And the `upper` belongs to the same question

If only the mount were renewed and the `upper` kept, image A's writable layer
would lie over image B. Exactly those files the old container once wrote would
stay visible in the old version — the new one would be invisible there. Half an
upgrade is worse than none, because it looks like one.

## Decision Drivers

- **ADR-0070/0071 promise an effect** that does not exist.
- **ADR-0027 says the `upper` dies with the container** — today it dies neither
  with it nor with its declaration.
- **A crash restart is the one autonomous action** ADR-0010 permits. What makes
  it more expensive or riskier is paid at the worst place.
- **`OverlayMount` deliberately has no `Drop`** (ADR-0019): a running container
  outlives the agent.

## Options Considered

- **A — remount at every start.** Simple and loud; but it also hits the case in
  which the runtime reports `Unknown` and a container is still running.
- **B — remount when the declaration has changed**, and then discard the
  `upper` too.
- **C — a fresh `upper` at every restart**, as ADR-0027 read literally
  suggests.
- **D — leave it** and note in ADR-0070 that an image change needs a restart of
  the agent. (It would not even need one — the mount survives that too.)

## Decision

Chosen: **B**.

### Determination 1 — a changed declaration remounts

If the digest of the canonical declaration differs from the one with which the
bundle was built (`.spec`, ADR-0070), then it is unmounted and mounted anew
with the current layers.

The trigger is the same one on which ADR-0070 hung the **report**. Two triggers
for the same fact would be two opportunities to answer it differently — and
then the report would announce a deviation that the start does not fix, or vice
versa.

### Determination 2 — and discards the `upper` in doing so

With the unmount go `upper` and `work`. A writable layer belongs to the layers
over which it lies; putting it on a different image is not a saving but an
error that concerns exactly those files someone once touched.

With that the promise from ADR-0027 gets a precise version: **the ephemeral
volume dies with the workload (ADR-0119) and with its declaration** — not with
every process.

### Determination 3 — an unchanged declaration keeps both

Option C is rejected. A crash restart runs on the same layers; the mount is
correct, and there is nothing to correct. Making it more expensive by a
`remove_dir_all` — during the restart, the moment in which a workload is
missing anyway — and destroying the traces of the crash in doing so would be
the wrong trade.

Whoever wants a fresh `upper` changes the declaration or withdraws the
workload. Both are a human's actions, and both are visible.

### Determination 4 — the unmount happens only in the start path

`build` runs exclusively from `start`, and `start` runs after `apply` has ended
the container or because there is none. A running container does not pass
through there — the exception stands as an open point below.

With that option A is rejected: it would unmount even when there is nothing to
correct, and would enlarge the window for exactly this edge case without any
return.

### Determination 5 — `OverlayMount` stays without a `Drop`

Unchanged from ADR-0119, and confirmed here: the mount ends through an
**action**, not through a lifetime. A `Drop` unmount would take the rootfs from
every running container as soon as the agent restarts (ADR-0019).

## Consequences

**Positive**

- **An image change takes effect.** The promise from ADR-0070/0071 applies from
  here to the whole bundle and not just to the `config.json`.
- A security update in a base image reaches the workload with one decree —
  until now not at all.
- The ephemeral volume from ADR-0027 has a version that is true.

**Negative / costs**

- **A decreed change costs the scratch area from here on.** That is the
  intention and nevertheless new: whoever until now issued
  `tgctl cluster restart` after a change kept their `upper`. It belongs in the
  manual.
- **The start takes longer** if much lies in the `upper`: a `remove_dir_all`
  over what the container wrote. It hits the case of a decreed change, not the
  restart after a crash.
- A change that does **not** touch the image (a different port, a different
  limit) discards the `upper` anyway. Splitting the digest per component would
  be a second truth about the same declaration; ADR-0070 decided for **one**
  digest, and this decision inherits it.

**Risks & open points**

- ~~**`ContainerStatus::Unknown` stays an edge case.** If the runtime reports
  `Unknown` while a container is running, the path leads into `start` — and
  with determination 1 into an unmount under a running process. The risk exists
  at this place even before this decision (the start built a new bundle there
  anyway); it is named here and not treated.~~ — **done: ADR-0122**, and it was
  not an edge case but a directional decision that was never made: `Unknown`
  coincided with `Absent`, so "I do not know what it is doing" meant "it does
  not exist". Measured against a real container, `build` returned **`Ok`** in
  the process — rootfs swapped, ephemeral volume deleted, container still
  running — and what became visible was only the subsequent `create` with
  "container already exists". Every subsequent pass ended in `failed`, and a
  `failed` drags every dependent with it per ADR-0061. From ADR-0122 on,
  `Unknown` has a branch of its own: nothing touched, not resolved, no cascade,
  visible with a reason — and the precondition of this ADR is thereby an
  exhaustive `match` instead of a comment.
- **A moving tag stays invisible** (ADR-0070, open point). Whoever runs
  `:latest` with `pullPolicy="always"` does not change their declaration — the
  digest stays the same, and no remount happens. This decision makes it neither
  worse nor better.
- **An abort between unmount and mount** leaves a bundle without a mount
  behind. The next pass mounts it — it is level-triggered (ADR-0010), and an
  `umount` without a mount does nothing.

## Related ADRs

- **Redeems:** the promise from **ADR-0070/0071** ("takes effect at the next
  start"), which did not apply to the image's content; and the open point from
  **ADR-0119** (fresh `upper` on restart).
- **Refines:** **ADR-0027** — the ephemeral volume dies with the workload and
  with its declaration.
- **Applies:** **ADR-0070** (one digest, one trigger), **ADR-0010**
  (level-triggered), **ADR-0019** (no `Drop` unmount).
- **Touches:** **ADR-0003** (the layers that are then no longer held),
  **ADR-0119** (the same release, a different occasion).
