# ADR-0099: Snapshot and restore of a volume

- **Status:** accepted
- **Date:** 2026-09-06
- **Concerns:** ADR-0027 (storage & volumes), ADR-0020 (audit/retention), ADR-0010
  (reconciliation), ADR-0019 (static stability), ADR-0044 (the recovery path), ADR-0071
  (a generation as the trigger)

## Context and Problem Statement

ADR-0027 carries under *negative/costs* a sentence unfulfilled since phase 10:

> A snapshot/backup mechanism is needed for DR (decoupled from the failover path).

And under *risks & open points*:

> Snapshot/backup/DR mechanics and retention periods (coupling to 0020).

The ADR is `accepted`, the mechanics are **not built**. Measured,
`tg_runtime::volume` today knows `declare`, `provision`, `mount`, `unmount`, `resize`,
`delete`, `info` and `list` — no `snapshot`, no `restore`.

That weighs more than a missing convenience, and the reason stands in ADR-0027 itself: a
writable volume is **exclusive and node-pinned**, and high availability runs through a
replica with its **own** volume, never through volume migration. So the answer to "the
node is gone" for a single-instance workload with a writable volume is explicitly
**not** failover but *"a single instance with snapshot/restore DR (non-instantaneous
recovery)"* — and that recovery did not exist. `StatefulNodeGone` refuses a re-placement
(phase 10a, rightly so: it would silently give the data up), and an operator afterwards
had no tool.

To be decided is the **mechanism**, its **consistency promise**, who **triggers** it and
where the boundary to **retention** lies.

## Decision Drivers

- A snapshot has to be usable: mountable, with the data in it.
- It must not measurably halt the running workload (ADR-0019).
- It must entail no new supply-chain decision (ADR-0023).
- A restore overwrites data — the degree of friction has to match that.
- What an auditor wants to see is **who** decreed it (ADR-0020, ADR-0050).
- The orchestrator provides **no** object store (ADR-0027).

## Options Considered

**A — a filesystem snapshot (LVM/btrfs/ZFS).** The technically strongest path and
rejected: it requires volume management beneath our image that does not exist in this
model, and it would make the node's filesystem an operational precondition for a core
capability.

**B — the workload does it itself** (`pg_dump` to S3). For application-consistent
backups that is the right way anyway, and the orchestrator already carries it: the
egress path (ADR-0041) is built. As the **only** answer it is none: a workload without
its own dump mechanism would have none, and ADR-0027 demands the mechanism from the
orchestrator.

**C — a copy of the image.** A volume with us is a file with a filesystem in it (phase
10b) — a copy of it is a complete point-in-time state. Chosen.

## Decision

### 1. A snapshot is a copy of the image, with `std::fs::copy`

No foreign program. Measured, `std::fs::copy` uses `copy_file_range(2)`, and on a host
with reflink support the kernel turns it into a **copy-on-write copy**: 256 MiB in one
call, **zero** blocks occupied. On a filesystem without reflink the same call falls back
to a real copy, without the caller doing anything differently.

The path over `cp --reflink=auto` would be a third process dependency for the same
result (measured: `cp --reflink=never` occupies 263 MB where `std::fs::copy` occupies
zero).

### 2. Frozen when mounted

Before the copy the filesystem in the volume is frozen (`fsfreeze`, util-linux — the same
arm's-length boundary as `losetup`, `mkfs.ext4` and `resize2fs`, and the same package),
and released afterwards. That is not polish but the promise itself. Measured on a volume
under write load:

| | Files in the snapshot | `e2fsck -fn` |
|---|---|---|
| without freeze | **12** of 412 | `orphan_present is set` |
| with freeze | **412** | clean |

Without the freeze the snapshot is not merely inconsistent, it is **nearly empty** — the
image on the disk lies far behind what the application did.

The price is a write block for the duration of the copy. On a host with reflink that is
milliseconds (measured: 74 ms for 512 MiB); without reflink it grows with the size, and
that belongs in the operations manual. The freeze is **not** optional: a snapshot
without it is none.

If the release fails, that is a **hard** error with a message of its own — a filesystem
that stays frozen halts every writer of the workload, and that situation must not
disappear into a generic error message.

### 3. Crash-consistent, not application-consistent — and it says so

A frozen ext4 yields a state as after a **clean power failure**: the journal is flushed,
there is no half transaction in the filesystem. What the snapshot **cannot** provide is
consistency at the application level — a database in the middle of a transaction sees it
like a crash and rolls back when opening.

That is the model every database **has to** cope with, and for anything beyond it option
B is the way: the workload makes its own dump and sends it out over the egress path.

### 4. The snapshot lies locally; the way out is operational work

`<data-dir>/volumes/<name>/snapshots/<generation>`, next to the image. A snapshot
**next to** the volume is not yet DR in itself — the same disk, the same node. What the
orchestrator provides is the **consistent point-in-time state as a closed file**; where
it goes is decided by operations.

That is the same boundary ADR-0020 draws for the audit archive, and it is here
additionally prescribed by ADR-0027: *"the orchestrator provides NO object store."* An
S3 client in the agent would be a supply-chain decision (ADR-0023) for a path ADR-0027
explicitly sees as external.

A closed file is half the work in this: an operator gets at it **without a race** — the
same consideration with which the audit segments rotate.

### 5. Triggered through the log, as a generation

`SnapshotVolume { volume, node, generation }` — monotonic, level-triggered, in the form
of ADR-0055 and ADR-0071. The node sees the desired generation in the slice (ADR-0040),
compares it with its marker next to the volume and makes a snapshot if it is lower.

With that three things hold without new mechanics: the audit trail says **who** decreed
it (ADR-0050); a node that was away catches up on its return (ADR-0010); and an operator
does not have to know which node the volume lies on.

**No policy.** A cadence ("daily at three") would be admissible per ADR-0057 — the clock
is an input an outage does not produce — but a snapshot consumes space on a disk the
leader does not know, and ADR-0027 names no cadence. `SnapshotVolume` therefore does
**not** stand on the permission list from ADR-0057.

### 6. Restore is node-local and not in the log

The asymmetry is this ADR's actual decision.

A snapshot is **additive**: doing it twice costs space and nothing else. A restore is
**destructive**: it overwrites the volume. A level-triggered decree in the log would
mean that a node whose marker is lost **restores again** — and overwrites what the
application has written since the snapshot. That is a data loss nobody sees coming.

A restore therefore runs through `tgctl` on the node, with the same two bars as `delete`:
it requires an **unmounted** volume and an **explicit confirmation** (`Confirmation`,
ADR-0027 — "explicit and protected, because destructive").

The price is named: there is no log entry about who restored. It is mitigated by the
restore backing up the **overwritten** state beforehand — the operation is thereby
reversible, and the before-snapshot is the trace it leaves.

### 7. How many snapshots stay is a setting per node

`--keep-snapshots <n>`, default 3, `0` means "keep all". The number belongs to the node,
because the disk belongs to it — the same layer as `--audit-rotate`. What is reaped are
the **oldest** by generation, and **after** creating the new one: otherwise after a
failed snapshot there would be less there than before.

**Only what that number requires is deleted.** The **period** — how long a snapshot is to
be retained — stays open and couples to ADR-0020, like every other retention question in
this system.

### 8. Visibility

`tg_volume_snapshots{volume}` (how many lie there) and
`tg_volume_snapshot_timestamp_seconds{volume}` (when the most recent arose) — a
**timestamp** and not an age, for the reason ADR-0057 and ADR-0088 wrote down. On that
the rule a DR concept needs can be written: *no snapshot for N days.*

## Consequences

**Positive.** The open point from ADR-0027 is closed, with a mechanism that brings no new
dependency (a program from the package that supplies `losetup` anyway) and whose
consistency promise is **measured** rather than asserted. The trigger is auditable, and
the recovery does not hang on the cluster — it is available exactly when it is needed.

**Negative.** A snapshot blocks writers for the duration of the copy; on a host without
reflink that is not a millisecond. In the worst case it doubles a volume's space
requirement per retained generation. Application consistency stays with the workload.
And the restore stands in no log.

**Format break.** The field on `NodeSlice` is the tenth and goes with the others into
**one** window (ADR-0072, determination 3).

## Related ADRs

- **ADR-0027** — this ADR redeems its open point; the three volume classes and the
  exclusivity model stay untouched.
- **ADR-0020** carries the retention question, here as with the audit archive.
- **ADR-0071** gives the form of the trigger (a generation, monotonic, level-triggered).
- **ADR-0044** carries the justification for why the recovery path does not hang on the
  cluster.
- **ADR-0057** is not extended: `SnapshotVolume` is permitted to no policy.
- **ADR-0091** determines the ownership in the snapshot: it is a copy of the image, so it
  carries the ids the image carries.
