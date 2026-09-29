# ADR-0063: The declared size of a volume

- **Status:** accepted
- **Date:** 2026-08-29
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-runtime` (`volume`, `apply`), ADR-0027, ADR-0010,
  ADR-0019

## Context and Problem Statement

A writable volume declares its size (`<volume … size="…"/>`, phase 10c). ADR-0027
carries the local PV lifecycle — "provision/resize/delete" — under **Risks & Open
Points**; when a resize takes place and what it may cost is decided nowhere.

Measured against `VolumeStore::provision`, the situation is not "undecided" but
**without effect**: for an existing volume `declare` returns the stored information
and discards the declared size. A trial run:

```text
declared=8MiB  -> 8388608
declared=64MiB -> 8388608
declared=1MiB  -> 8388608
```

**After creation the declared size is decoration.** An operator raises it, applies,
gets not a word — and the workload keeps running on the old volume.
`VolumeStore::resize` has been built and tested since phase 10b and has **no caller
in production code**.

The question is therefore not *whether* the size should take effect but **when** it
may. Because `resize` requires an unmounted volume, and a running container keeps it
mounted.

## Decision Drivers

- **ADR-0027:** resize belongs to the lifecycle; **shrinking never happens** — that
  is the operation that eats data when it goes wrong.
- **ADR-0019 (keystone):** the availability of a running workload must not hang on a
  figure an operator has just typed.
- **ADR-0010:** what the agent may do autonomously is an **enumerated** list.
  Stopping a running container in order to grow its volume is not on it — and if it
  were, a number in the XML would be a restart trigger.
- **Level-triggered instead of edge-driven:** the intent stands in the desired
  state, not in an event a restart would lose.
- **Nothing happens silently** — the rule by which this finding came to light at all.

## Options Considered

- **Option A — at start, before mounting.** When an instance is started or
  restarted, the agent first brings its volume to the declared size. A running
  container is not touched; the increase takes effect at the next restart, which a
  human or the reconciler triggers anyway.
- **Option B — at once, with a stop.** The agent halts the container, grows it and
  restarts. Takes effect without intervention, but makes a number in the XML a
  restart trigger and extends the list from ADR-0010 by a **disruptive** action.
- **Option C — online.** Grow the loop device under the running filesystem.
  Technically possible (`losetup -c`, `resize2fs` online), but it requires exactly
  the kind of intervention on a mounted filesystem that phase 10b deliberately
  excluded.
- **Option D — refuse at ingest.** Do not accept a changed size in the first place.
  That would mean striking resize from ADR-0027, and the state machine does not know
  the actual size at all — it is node-local.

## Decision

Chosen: **Option A**.

1. **The declared size takes effect at the start of an instance, before mounting.**
   That is the only moment in which the volume is certainly not mounted, and it
   comes about without a single additional intervention.

2. **No autonomous stop.** The agent halts no running container in order to grow a
   volume. The list from ADR-0010 section 3 stays untouched: a number in a
   definition must not trigger a restart. Whoever wants the increase at once
   restarts the workload — an action a human is responsible for.

3. **Shrinking never happens.** A declared size **below** the actual one is refused
   and reported; the volume keeps its size and the workload runs. Turning a typo
   into an outage helps nobody, and the data would be the first thing lost.

4. **A failed growth does not cost the start.** An **existing** volume that does not
   reach its declared size — no space on disk, a missing tool — is mounted at the
   size it has, and the finding is reported. The workload ran with it before; not
   starting it now gets it no space (ADR-0019). **A new volume that cannot be
   created still makes the start fail** — there is nothing there to run on.

5. **The outcome is named.** Created, unchanged, grown, shrink refused, growth
   failed — five distinguishable cases, and the last three appear in the log. A size
   that does not take effect must not look like one that does.

## Consequences

**Positive**

- The declared size is no longer decoration; ADR-0027's lifecycle point is redeemed
  for provision **and** resize.
- No new trigger for restarts, no extension of the autonomy list, no intervention on
  a mounted filesystem.
- The path is level-triggered: the intent stands in the desired state and is lost
  through no restart.

**Negative / Costs**

- **The increase takes effect with a delay**, namely at the instance's next start.
  For a long-lived workload that means: only when somebody restarts it. That is the
  price of a number in the XML not triggering a restart.
- **Between declaration and effect nobody says so.** As long as the container runs,
  the divergence is not checked — the resize path runs only at start. An operator who
  raises the size and does not restart sees nothing. See the open points.
- An operator who accidentally shrinks gets a message and no effect — right, but it
  is a divergence between declaration and reality that persists until they correct
  it.

**Risks & Open Points**

- ~~**Visibility before the restart** is not built. … it is a question of its own
  whether an **observed divergence from the desired state** that the agent may not
  remedy belongs in the report to the control plane (ADR-0040 determination 7).~~
  **The question is answered: ADR-0070, with yes** — and the answer covers this case
  along with it, without anybody comparing the size specifically.
  `bundle::spec_digest` hashes the **canonical form of the whole declaration**; a
  changed `size` changes it, and the instance is thereby visibly `stale` — in the
  report and as a metric per workload.

  What ADR-0070 does **not** change is the determination above it: it still takes
  effect at the next start, and nobody restarts autonomously for it.
- ~~**Encrypted volumes** (ADR-0016, not built) would have a LUKS container between
  image and filesystem; a resize would gain a third step there. The seam stays the
  same.~~ **Built: ADR-0113** (`ab5d219`) — LUKS2 on the loop device, a passphrase
  per volume derived from the data key. The seam was the same as conjectured here,
  and `resize2fs` has since worked behind the mapper (noted there as a consequence).
- **Snapshot/backup** from ADR-0027 is unaffected by this and still open.

## Related ADRs

- **ADR-0027** — storage & volumes; carries the PV lifecycle as an open point and
  forbids shrinking. This ADR redeems the resize part.
- **ADR-0010** — reconciliation & the autonomy boundary; determination 2 keeps the
  list of autonomous actions untouched.
- **ADR-0019** — static stability; determinations 3 and 4 follow from it.
- **ADR-0058** — teardown; the same construction: the desired state takes effect
  where it can take effect without harm.
