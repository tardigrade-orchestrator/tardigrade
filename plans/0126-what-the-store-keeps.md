# ADR-0126: What the Store Keeps

- **Status:** accepted
- **Date:** 2026-09-13
- **Concerns:** ADR-0003 (content store and image GC), ADR-0119 (the release of
  the bundle that makes it possible), ADR-0058 (clearing away as the second
  direction of the same reconcile), ADR-0062 (what an incomplete desired state
  may do), ADR-0019 (the keystone), ADR-0122 (in doubt touch nothing)

## Context and Problem Statement

ADR-0003 has named "image GC" as an open point since phase 2; ADR-0119 made it
**possible** and expressly did not build it. Measured, the situation is:

```text
after api:1  blobs   5268992  layers   5259628  total  10528771 B
after api:2  blobs  10537984  layers  10519256  total  21057542 B
after api:5  blobs  26344960  layers  26298140  total  52643855 B
```

**Linear and without a way back.** Every tag that was ever pulled keeps its
blob, its unpacked layer and its record — forever. A node on which a workload
gets a new image weekly fills its disk as a function of time, and when it is
full, nothing starts any more. That is an outage from housekeeping nobody could
do.

### Half of it is dead weight

`blobs/` is written and in the production path **never read again** — outside
`content.rs` exactly one *test* accesses `blob_path`. And an existing blob does
not even save a download: `Client::pull` fetches all layers **before** anything
asks the store; `put_blob` gets the bytes that are already in memory.

What the function exists for stands in the code itself:

> With that `ContentStore::put_blob` becomes a real check at the trust boundary
> to the registry instead of a comparison of the bytes with their own hash
> (ADR-0023).

That is the **check**. The file that arises in the process is a by-product, and
it costs the compressed size of every layer ever pulled.

### Two things make the GC safer than it sounds

- **`ResolvedImage::load` already demands complete layers today.** If one is
  missing, the record counts as unusable and a pull happens. A mistake by the
  GC therefore degrades to another pull and not to an empty rootfs.
- **Since ADR-0119 no mounts lie around** that nobody wants any more. That is
  exactly what that ADR deferred the GC on.

## Decision Drivers

- **A cache without eviction is a leak.** The store is a cache: what it holds
  can be re-obtained.
- **But it is also independence from the registry** (ADR-0019: if it is stored
  locally, it is taken locally). What it throws away costs a pull on
  recurrence — and that can fail.
- **The safety question is the same as in ADR-0058**: distinguishing "wanted by
  nobody" from "not yet heard". An incompletely formed desired state must
  delete nothing.
- **And the same as in ADR-0122**: where the situation is unclear, nothing is
  touched.

## Options Considered

- **A — a tool for the operator** (`tgctl node gc`). Safe and ineffective: a
  disk that fills up is an outage, and a system with 4-9 as a target must not
  make it depend on somebody remembering.
- **B — an age limit** ("layers nobody needed for 30 days"). A deadline is the
  same wrong answer here as with the tombstone in ADR-0104: it deletes by the
  clock rather than by the desired state, and it needs a number nobody can
  justify.
- **C — a fill-level limit.** Shifts the decision onto a second setting that
  must fit together with the disk size.
- **D — the second direction of the same reconcile**, as ADR-0058 built it for
  containers: what the local desired state no longer names goes away.

Chosen is **D**, with the guards from ADR-0058 and ADR-0062, and before it
determination 1, which settles half the problem without any reachability
computation.

## Decision

### Determination 1 — the blob is checked, not retained

`put_blob` becomes what it does: it checks the bytes against the **declared**
identifier and writes nothing. The `blobs/` directory is dropped; an existing
one is cleared away by determination 4.

That is not a saving on a security feature: the check at the trust boundary
stays word for word what it was. What is dropped is a copy nobody reads and
that saves no pull.

### Determination 2 — the GC is a step of the reconcile

Not a tool and not a schedule: it runs in the reconciler, level-triggered, and
**after** the clearing away from ADR-0058 and the release from ADR-0119. The
order is part of the decision — what this pass releases, the same pass may
collect.

Reachable is what the **local desired state** names: the image references of
its workloads and the sources of its shared volumes (ADR-0027). A record nobody
names goes away; a layer that no remaining record names goes away.

**The computation happens in every pass**, and that is a correction to this
determination that arose before the build. The first draft said "only when the
reachable set has changed" — that is true (a layer becomes unreachable only
through a change to the desired state) and is not worth the optimization:
measured, a pass **without a find costs 378 µs** at 200 layers and 50 records,
so two `read_dir`s and a few small files. That is the same order of magnitude
with which ADR-0118 justified its cgroup readings, and lies far below what
ADR-0110 has in view.

What the saving would have cost is a **remembered state** beside the state —
exactly the shape ADR-0058 rejected for the actual side.

### Determination 3 — three guards, and each costs only a postponement

The GC does **not** run when

1. the desired state is empty and this node has not heard anything yet
   (`EmptyMeans::NothingHeard`) — verbatim ADR-0058, determination 3;
2. the node view has **isolated** (ADR-0062): an unreadable document names no
   reference, and its layers would look unreachable;
3. a **bundle** is standing there that the desired state does not name. Then
   the release from ADR-0119 did not get through, and removing layers under a
   mount would be the damage from ADR-0122.

Each of these cases defers the GC to the next pass. A deferred GC costs space;
a premature one costs a rootfs.

### Determination 4 — what it removes, and what it never touches

Removed are records in `manifests/`, directories in `layers/` and — once and
completely — `blobs/`.

**Never touched** are `bundles/`, `volumes/` and everything outside the content
store. The GC is a statement about a cache and about nothing else.

### Determination 5 — no deadline and no grace period

What the desired state no longer names is not kept. If it comes back, a pull
happens — `ResolvedImage::load` ensures that this stands out instead of
mounting half an image.

The price stands in the consequences: a workload that comes back needs the
registry. A deadline would turn it into a number without a justification
(ADR-0104), and a "keep what ran yesterday" would be a memory — hence the state
beside the state that ADR-0058 rejected.

### Determination 6 — what it has done is counted

A counter over the released bytes and one over the removed layers (ADR-0015,
without a label — there is one store per node). Without them a disk that no
longer grows would be indistinguishable from a GC that never runs; and the
three guards from determination 3 are exactly the cases in which it does
**not** run without anything being broken.

## Consequences

**Positive**

- **Half the store falls away immediately**, without a reachability computation
  and without risk: measured 26.3 of 52.6 MB at five tags.
- **The rest no longer grows beyond the desired state.** A node that renews an
  image weekly from here holds one image and not fifty-one.
- The oldest open point of ADR-0003 is closed — since phase 2.
- **No new crate, no new setting, no new caller**: the GC hangs on the loop
  that runs anyway.

**Negative / costs**

- **A workload that comes back needs the registry.** That is the departure from
  "if it is stored locally, it is taken locally" (ADR-0019) for the case in
  which the desired state did not name it in between. Whoever does not want
  that does not take the workload out of the desired state.
- **A rollback to the previous tag pulls anew.** After `tgctl cluster apply`
  with a new tag the old one is unreachable and gone; the way back costs a
  pull.
- **`blobs/` is no longer a piece of evidence from this state on.** It was not
  one either — no ADR names it as such — but whoever wanted to check the
  delivered content against its digest retroactively could no longer do so from
  here. What remains is the reference together with the digest in the record
  and the log entry that declared it (ADR-0020).
- **Three guards mean: the GC sometimes does not run**, and precisely when
  something else is not right. The metric from determination 6 is the only way
  to see that.

**Risks & open points**

- **A layer two nodes share is decided per node.** The store is node-local
  (ADR-0003); there is no cluster-wide view of it, and there shall be none.
- **The shared volumes hang on the same store** (ADR-0027, 10c). Their sources
  are roots like the images; a volume the desired state no longer names loses
  its layers — the same promise and the same cost side.
- **The GC runs in the reconciler and blocks there** (ADR-0110). A very large
  store makes a pass longer; that is not measured, and the frequency from
  determination 2 bounds it to the passes in which something changed.
- **Layer dedup across images** was never an open point and is not one now
  either: the store is content-addressed, identical layers lie there once
  anyway.

## Related ADRs

- **Redeems:** **ADR-0003**, open point *image GC* — the oldest of this tree;
  **ADR-0119**, which enabled and deferred it.
- **Applies:** **ADR-0058** (the second direction of the same reconcile, and
  "an empty desired state does not clear away"), **ADR-0062** (an incomplete
  desired state does not clear away), **ADR-0122** (in doubt touch nothing),
  **ADR-0104** (a deadline is the wrong answer).
- **Touches:** **ADR-0019** (what the store holds is independence from the
  registry), **ADR-0027** (shared volumes lie in the same store), **ADR-0023**
  (the check at the trust boundary stays), **ADR-0110** (what stands in the
  pass holds it up).
