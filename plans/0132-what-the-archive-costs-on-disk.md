# ADR-0132: What the Archive Costs on Disk

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0020 (the log as a WORM substrate), ADR-0045 (the outcome in
  the chain), ADR-0064 (the lease that sets the cadence), ADR-0104 (retention is
  not a deadline), ADR-0088 (lifetime of a time series)

## Context and Problem Statement

Phase 11 names the same open point three times, and it has been the same since
11a:

> What stays open from the phase is in all three cases **the same**: the path
> of the artifacts outwards — storage, rotation and retention periods in the
> WORM archive (ADR-0020) … That is operations work on an archive system that
> does not exist here, and no missing build work.

The path outwards is operations work. What is left lying **here** as long as
nobody walks it is not.

### The measurement

An archive with real records (`RenewLease`, as they arise in operation):

```text
100000 records: 41377790 bytes, 413.8 B/record
one single writer: 9495 records/day = 3.7 MiB/day = 1367.5 MiB/year
one segment (100000 records) = 39.5 MiB, full after 10.5 days
restart over 100000 records: 1.175072897s
```

The cadence is measured, not computed — over the real planner, 200 ticks over
600 s of simulated time:

```text
LEASE=15000 ms, TICK=3000 ms: 200 ticks, 66 log entries -> every 9.1 s
```

**A single single-writer workload writes 1.34 GiB of audit material per year,
and that solely for the fact that it is still there.** Ten of them are 13 GiB.
That is not a malfunction: the active-role lease must be consensus-backed
(ADR-0064), so its renewal stands in the log, and the log is the audit substrate
(ADR-0020).

### What about it was not decided

- **Nothing deletes.** Sealed segments stay lying around until an operator
  pushes them away — and whether they do this cluster does not know.
- **Nothing reports it.** There is `tg_audit_records_total` (a counter of the
  written records), but no number about what lies on the disk. An operator sees
  the occupancy only by looking on the node.
- **The first signal is the outage.** If the archive cannot write, `apply` ends
  with an error — and that is expressly how it is built:

  > An archive that cannot write is a storage error and no reason to carry on:
  > otherwise the cluster would run on and nobody would see that the audit trail
  > has had holes for hours.

  The decision is right and stays. Its flip side is that a full disk stops the
  node — and that what fills it is our own archive.

### And a second price that until now stood nowhere

`Archive::open` checks the current file before it appends (phase 11a: "a damaged
archive cannot be continued"). Measured, that costs **1.18 s** with a full
segment — at every start. Without rotation this time would grow with the
archive; the rotation bounds it. That is a second reason for `--audit-rotate`,
and it was not stated alongside until now.

## Decision Drivers

- **A store that only grows needs a number** — the same situation as with the
  content store (ADR-0126) and with node fullness (ADR-0127). There the first
  signal was a failed placement; here it is a node that no longer applies.
- **What lies here is evidence nobody has yet exported.** Deleting it because it
  is old is the wrong direction (ADR-0104: a deadline deletes precisely when the
  execution fails to happen).
- **The cluster does not know the retention obligation.** It stands in a
  regulation and in a contract, not in a setting.
- **A metric decides nothing, it shows** (ADR-0047).

## Options Considered

- **A — an upper bound on disk that deletes the oldest.** The ring-buffer
  answer. It deletes precisely the segment with the longest retention
  obligation, and it does so quietly.
- **B — a deadline.** The same movement, the same direction, and ADR-0104 has
  already measured it as wrong once for tombstones.
- **C — make visible, delete nothing**, and write down the price so that an
  operator can size disk and export cadence accordingly.
- **D — make the cadence cheaper**, so that less accrues: fewer lease renewals
  in the log. That touches ADR-0064 and ADR-0076, whose ordering conditions are
  measured and built.

Chosen is **C**.

### Determination 1 — the store gets two numbers

`tg_audit_bytes` and `tg_audit_segments`: what the archive directory occupies
and how many **sealed** segments are still lying there. Without a label — it is
one number per process, and the global label names the node anyway.

Both registered via `Health::on_scrape` (ADR-0088): they change only on rotation
or on writing, and a node that is currently not applying anything would never
set them — they would expire after a quarter of an hour. Read in the scrape, no
intermediate state arises that could become stale.

The current file counts in the bytes and **not** in the segments: an operator
pushes away only what is sealed, and a number that counts something one must not
take misleads them.

### Determination 2 — nothing is deleted here

No upper bound, no deadline, no ring buffer. Neither A nor B.

What lies here is the part of the audit trail nobody has yet pushed into the
WORM archive. A rule that deletes by age or occupancy hits it **precisely** when
the export is not running — and the export is not running precisely when
something is amiss in operations. That is the same inversion ADR-0104 measured
for the tombstones.

The cluster does not know the retention obligation either: it stands in a
regulation, not in a setting. A program that throws away evidence according to a
self-chosen number is, in a REMIT/DORA environment, the opposite of what
ADR-0020 promises.

### Determination 3 — the price stands in the manual, with the numbers

414 bytes per record; a lease renewal every 9.1 s per single-writer workload,
so around 9 500 records a day and **1.34 GiB a year**; a segment of the default
size full after 10.5 days.

With that an operator can size two things they have to guess today: how large
the disk must be and how often the export must run. Both are operations work —
but operations work without numbers is guessing.

### Determination 4 — the rotation bounds the start too

`--audit-rotate` has a second purpose, and it belongs written at the place at
which the first already stands: the check on opening costs a measured 1.18 s
with a full segment. Without rotation it would grow with the archive, and a
node's start would become slower the longer it is in service.

### Determination 5 — the failure stays hard

An archive that cannot write stops the node. That stays as it is; the
alternative would be a cluster that runs on while its audit trail gets holes.
What changes is that there is a number before that.

## Consequences

**Positive**

- **The store is visible before it stops the node.** Until now the first signal
  was an `apply` that no longer got through.
- **Two operations questions are computable** instead of guessed: disk size and
  export cadence.
- **The second price of rotation is named**, instead of slumbering in a
  measurement nobody has taken.

**Negative / costs**

- **Two gauges more**, and one of them reads the directory at every scrape (one
  `read_dir` plus one `metadata` per segment). At one segment per ten days that
  is nothing; with a very small `--audit-rotate` it would be more frequent — and
  then the number of files is the problem one wants to see anyway.
- **The disk stays the limit.** This decision does not move it, it makes it
  visible.

**Risks & open points**

- **The path outwards stays operations work** — the WORM archive still does not
  exist here. What changes is that from here an operator sees how urgent it is.
- **The threshold belongs to operations.** `docs/alerts.yml` gets the building
  blocks and no rule: the number at which it gets tight is the node's disk size,
  and this cluster does not know it.
- **The cadence itself stays as it is** (option D). The lease renewal in the log
  is the promise from ADR-0064; its cadence hangs on the ordering conditions from
  ADR-0076, and those are measured. That the audit trail thereby consists to
  nine tenths of signs of life is the price of provability and stands here so
  that nobody takes it for an oversight.

## Related ADRs

- **Closes the local half** of the open point from **phase 11a/11b/11c** and
  **ADR-0020**: the path outwards stays operations work, what lies here is now
  visible.
- **Applies:** **ADR-0104** (a deadline is the wrong answer), **ADR-0088**
  (gauge with refresh in the scrape), **ADR-0047** (a metric decides nothing).
- **Follows the same shape as:** **ADR-0126** (a store that only grows) and
  **ADR-0127** (fullness that stands out only at the failure).
- **Touches:** **ADR-0064/0076** (the cadence that determines the volume) and
  **ADR-0045** (rejected commands are archived too).
