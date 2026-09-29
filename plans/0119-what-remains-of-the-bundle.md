# ADR-0119: What Remains of the Bundle When a Workload Is No Longer Wanted

- **Status:** accepted
- **Date:** 2026-09-11
- **Concerns:** ADR-0058 (clearing away), ADR-0027 (the ephemeral volume),
  ADR-0019 (fail-static), ADR-0003 (content store)

## Context and Problem Statement

ADR-0058 has the reconciler clear away what the desired state no longer names,
and writes in its consequences:

> **The bundle stays mounted.** `bundles/<name>/rootfs` is an overlayfs and is
> not unmounted: the path is not instance-precise (known open point), and an
> unmount would tear the rootfs away from a sibling instance.

**This sibling instance cannot exist.** Measured while closing the `.owner`
point from ADR-0071: `DomainLevel` knows only `site`, `hall` and `rack` — there
is no level that would leave two instances of a workload on one node —
`Demand::validate` rejects a pin with several instances, and `.owner` catches
the rest as a backstop (with witnesses since the last step).

The justification therefore no longer carries. What it carried nevertheless
remained.

## What the measurement finds

- **`unmount_overlay` has exactly one caller in the whole tree, and it is a
  test guard** (`tests/layers.rs`). The production path **never** unmounts.
- **No production code ever removes a bundle directory.** Neither on stopping
  nor on clearing away nor otherwise.
- **`reap` releases network, socket and secrets** — each with the same shape
  and the same justification ("what is left behind is …"). The bundle is not in
  that list.

After `tgctl cluster remove api` there therefore remains on the node:

```text
bundles/api/rootfs   overlayfs, mounted
bundles/api/upper    the ephemeral volume, together with everything the container wrote
bundles/api/.owner   .spec   .generation
```

### Three consequences, and the first is the unpleasant one

**1. The ephemeral volume outlives the workload.** ADR-0027 and phase 2 say the
`upper` is the ephemeral volume and *dies with the container*. Measured, it
does not die: it outlives the container, and it outlives the withdrawal of the
workload. If the same name is later placed on this node again, the new
container inherits its predecessor's writable layer — files, state, possibly
intermediate results from a different generation.

That is not a saving but an omission: nobody decided it, and the explanation in
the plan says the opposite.

**2. The mount holds the layers.** As long as an overlayfs points at
`lowerdir=`, the content store cannot release those directories. The image GC
from ADR-0003 is open — it would be ineffective for the layers of every bundle
left lying around.

**3. It grows over time.** ADR-0058 names the bound as "the number per workload
name placed here". That is a bound over a **monotone** set: renamed, moved,
withdrawn — every name that ever lay here stays in it.

## Options Considered

- **A — leave it.** Strike the justification, keep the consequence.
- **B — release on clearing away**: unmount, then remove the directory — where
  `reap` already releases network, socket and secrets.
- **C — additionally on every restart**, so that the ephemeral volume really
  dies with the container.
- **D — a sweep** that collects bundles without containers.

## Decision

Chosen: **B**.

### Determination 1 — the bundle is released where the others are

In `reap`, at the same place and in the same shape as the network (ADR-0012),
the socket (ADR-0081) and the secrets (ADR-0098). The list was incomplete, and
that is the whole finding: four things hang on a container, three were
released.

The same condition therefore applies as for the other three — what is released
is **only** what the desired state no longer names, and only if it counts as
populated (ADR-0058, determination 3). A lost data directory still costs
nothing.

### Determination 2 — unmount first, then remove; and only in that order

If the unmount fails, **nothing** is removed. Deleting a directory under an
existing mount is worse than a remainder: the mount stays, its path points into
nothing, and nobody finds it any more by the name under which it arose.

### Determination 3 — fail-soft, level-triggered

A bundle that cannot be released costs **its** bundle and not the pass
(ADR-0062). It is reported; the next pass sees the same situation and tries
again (ADR-0010). It is not kept quiet — a remainder nobody names is the state
out of which ADR-0058 arose.

### Determination 4 — not on restart and not on the fence

Option C is **not** decided along with it. A fence is a safety stop and not a
clearing away (ADR-0064): the instance stays wanted, its rootfs stays. And a
restart within a pass builds the same container anew from the same bundle.

Whether a **restart** should get a fresh `upper` is the question consequence 1
above raises — and it is a different one: it changes the behaviour of a
**running** workload, not the cleanup after a withdrawn one. It stands below as
an open point.

### Determination 5 — `OverlayMount` stays without a `Drop`

The release is an **action**, not a lifetime. A `Drop` unmount would unmount
the rootfs of a running container as soon as the agent drops its `Bundle`
value — and an agent restart would take every container with it. That is
ADR-0019, and it stays as it is; the comment on `OverlayMount` has always said
so.

Option D (a sweep over all bundles without containers) is rejected: it would
decide from **absence** (ADR-0057) and would hit a bundle that is just coming
into being. The reconciler, by contrast, knows what is wanted.

## Consequences

**Positive**

- The ephemeral volume dies with the workload — which ADR-0027 promises
  anyway. A name that comes back later inherits nothing.
- The image GC from ADR-0003 becomes possible: without mounts left lying
  around, nothing holds layers that nobody needs.
- The fourth line in `reap` is where the other three are — and the next
  resource somebody forgets will stand out at the same place.

**Negative / costs**

- **A withdrawn workload loses its scratch area irrevocably.** That is the
  promise from ADR-0027 and nevertheless a behaviour change: whoever has until
  now used `remove` and `apply` as a detour for a restart gets an empty `upper`
  from now on. It belongs in the manual.
- **One mount fewer means one mount operation more.** If a workload comes back,
  its rootfs is mounted anew. That is one syscall and lies far below what
  `prepare` does anyway.
- An abort **between** unmount and removal leaves a directory without a mount
  behind. The next pass clears it — it is idempotent, because an unmount
  without a mount does nothing.

**Risks & open points**

- ~~**Whether a restart should get a fresh `upper`** is not decided.~~ —
  **decided: ADR-0120**, and the question was bigger than it looked: measured,
  `build` took the **existing** mount, so a changed image reached the
  `config.json` and not the file system. A new mount happens on a changed
  **declaration**, and the `upper` goes with it; an unchanged one keeps both.
- ~~**The image GC is thereby possible and not built** (ADR-0003).~~ —
  **built: ADR-0126**, and on exactly this promise: without mounts left lying
  around there are no layers a GC could pull out from under a running
  container. A bundle left lying around is the third guard there — then nothing
  is released.
- **A bundle that never became a container** is affected by this decision too —
  the same situation as with the network and the socket, and the same answer:
  what the desired state does not name goes away.

## Related ADRs

- **Changes:** **ADR-0058** — the consequence "the bundle stays mounted" no
  longer applies; its justification (the sibling instance) was measured moot.
- **Redeems:** the promise from **ADR-0027** and phase 2 that the ephemeral
  volume dies with the container — for the case of the withdrawn workload.
- **Enables:** **ADR-0003**, open point *image GC*.
- **Applies:** **ADR-0010** (level-triggered), **ADR-0062** (a failure costs
  its object), **ADR-0057** (do not decide from absence), **ADR-0019** (no
  `Drop` unmount).
- **Touches:** **ADR-0071** (`.owner`, with witnesses since the last step),
  **ADR-0064** (a fence does not clear away).
