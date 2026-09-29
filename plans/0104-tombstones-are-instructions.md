# ADR-0104: Tombstones Are Instructions, Not Records

- **Status:** accepted
- **Date:** 2026-09-06
- **Concerns:** ADR-0042 (events between node and log), ADR-0020 (audit trail
  and retention), ADR-0027 (storage), ADR-0040 (the path to the node),
  ADR-0057 (what a policy may read), ADR-0049 (construction: report → policy →
  leader writes)

## Context and Problem Statement

ADR-0042 put the deletion of a volume into the replicated state as a
**tombstone**: "this volume no longer exists" is desired state, exactly like
"this workload shall run". And it left an open point:

> **The retention period of tombstones** couples to ADR-0020 and is open.

**Measured, this coupling is wrong, and the obvious answer — a deadline —
would be actively harmful.**

### What a tombstone is

Measured, there is exactly **one** way in which a tombstone disappears again:
the same volume is declared anew (`upsert_workload` then clears it on **all**
nodes). The normal case — a volume is deleted and never declared again —
leaves it **forever**:

| Where it lies | What that costs |
|---|---|
| `ClusterState::deleted_volumes` | grows unbounded, with nothing clearing it |
| every **snapshot** | carries along every tombstone ever set |
| every **slice** to the affected nodes | carries its own forever |
| every pass of the agent | asks the volume store about them |

### Why ADR-0020 is the wrong coupling

ADR-0020 governs the **audit substrate**, and that is the log. There the
`DeleteVolume` command stands together with actor (ADR-0050) and outcome
(ADR-0045), and it stays there — independently of everything this ADR decides.
**The record is not at risk.**

What lies in the `ClusterState` is something else: the **not yet executed
instruction**. That has nothing to do with retention.

### Why a deadline would be harmful

A tombstone is executed when the node sees it. A node that was away for a week
sees it only on its return — and that is exactly why it was built as **state**
rather than as a shout (ADR-0042: "whoever was away reads them on return").

If it expired after a deadline, the volume would stay **lying** on that node's
disk while the cluster considers it deleted. An operator ordered the deletion
expressly and with confirmation (ADR-0027 requires both), and the result would
be: the data is still there, and nobody knows it. That is the inversion of the
promise.

**The same shape as with the snapshots**, and that is why it is measured along
here: `--keep-snapshots` limits the **number**, and the plan carried "the
deadline stays open" as a gap. Measured, there is **no automatic producer** —
a snapshot arises only when a human decrees it (ADR-0099 expressly rejects a
policy). An age limit would delete there the oldest recovery point an operator
deliberately kept. There too the deadline is not the open question but a wrong
one.

## Decision Drivers

- **ADR-0027:** a deletion is explicit and protected. What an operator ordered
  must happen — not "be attempted within a deadline".
- **ADR-0040 determination 7:** the return direction carries **observed
  state**, no log entries. A node may report what it has done.
- **ADR-0049's construction:** the node reports, the **leader** turns it into
  a log command. The same form as capacity, active-role lease and key
  rotation.
- **ADR-0057:** a policy may only read inputs that a **failure does not
  create**. A report that is there satisfies that; an **absence** does not.
- **ADR-0058's actual side:** what is really there is said by the system and
  not by a memory.

## Options Considered

### R1 — A deadline (the obvious one)

A tombstone expires after *n* days.

- **For:** a number, no mechanism; the state stays bounded.
- **Against:** see above — it leaves data lying that should have been deleted,
  and does so **silently**. And the number would not be choosable: it would
  have to be longer than the longest absence of a node, and nobody knows that
  in advance.

### R2 — The node confirms, the leader clears

The node reports which tombstones of its slice are executed; the leader writes
`RetireTombstone`.

- **For:** the lifetime is "until executed" and thereby the right one. No
  data-loss risk, no guessed number, and the construction already exists three
  times.
- **Against:** one command more in the log, and a node that never comes back
  holds its tombstone forever — visible, but present.

### R3 — The agent deletes and the slice forgets

The leader removes the tombstone as soon as the node has acknowledged the
slice (`applied`).

- **For:** no new command; the mark already exists.
- **Against:** `applied` says "I applied the slice", not "I deleted **this**
  volume". A slice that fails for some other reason would hold the mark back;
  one that succeeds while the deletion was silently skipped would report an
  execution that never happened. The mark is too coarse for a destructive
  action.

## Decision

Chosen: **R2.**

### 1. A tombstone lives until it is executed — not until a deadline expires

There is **no** retention period for tombstones, and that is a decision and
not a deferral. The note in ADR-0042 ("couples to ADR-0020") is thereby
answered: it does **not** couple to ADR-0020, for the record is the log entry
and that stays anyway.

### 2. The node reports the execution as observed state

`NodeReport` carries `retired: Vec<String>` — the volumes from the **current**
slice that this node no longer has.

**Observed and not remembered** (ADR-0058): what is reported is what the
volume store says, not what an earlier pass believes it did. With that the
report survives a restart, a lost intermediate state and a slice that fails
for some other reason.

A tombstone for a volume this node **never had** counts as executed. That is
the same reading the agent has had since ADR-0042, and it is right: the
instruction reads "this volume shall no longer be here".

### 3. The leader writes `RetireTombstone { node, volume }`

The same construction as ADR-0049 and ADR-0064: the node reports, the leader
turns it into an ordinary log command. The log thus contains **both** — that
deletion was to happen (`DeleteVolume`) and that it did (`RetireTombstone`).
For an auditor that is more than before, not less.

The command is **idempotent**: a tombstone that no longer exists is done. Two
leaders writing shortly after one another cost one entry and nothing else.

### 4. It is a permitted policy — and it is the third

ADR-0057 permits exactly the decided cases, and its list is an exhaustive
`match` so that a new command **forces an answer**. `RetireTombstone` is the
third permitted case, and it satisfies the criterion:

- The input is a **present report**. A node that fails reports nothing — and
  then nothing is cleared. The failure does not create the decree, it prevents
  it.
- The effect is **not destructive**: what is cleared is an instruction that
  has already been carried out. The dangerous error would be to clear it too
  early — and against that stands the fact that only the node itself reports
  the execution.

### 5. Whoever does not come back keeps their tombstone — visibly

A node that never reports again holds its tombstone forever. That is the
**right** direction: the instruction stands as long as it is not carried out.
It is visible in `tg_cluster_volume_tombstones` and by name in
`tgctl cluster volumes`; whoever gives up on the node for good takes it out
with `RemoveNode`, and its tombstones go with it.

### 6. Snapshots keep their number and get no deadline

For the same reason (see context). `--keep-snapshots` remains the only limit,
and the plan note "the deadline stays open" is thereby answered: it stays
**off**.

## Consequences

**Positive**

- The replicated state no longer grows unbounded: tombstones disappear in the
  normal case within one reporting period.
- Snapshots and slices shrink accordingly.
- The log contains **the execution**, not just the order — an auditor sees
  that the deletion happened and when.
- No data-loss risk from a guessed deadline.
- **Zero new crates.**

**Negative / costs**

- **One command more in the command set** (38 instead of 37) and one field
  more in the report — the **twelfth** format break, bundled into the window
  from ADR-0072 determination 3.
- **One log entry per executed deletion.** The log is retained (ADR-0020); at
  the rate of volume deletions in a cluster that is negligible against the
  active-role leases that run anyway.
- **A restored volume gets no new tombstone.** Whoever uses
  `tgctl restore-volume` after the execution brings the volume back, and the
  instruction is gone. That is right — a restore is an explicit action by a
  human on that node (ADR-0099, determination 6) — but it is a way in which a
  deleted volume comes back.
- **The execution hangs on the report.** A node whose session stands but whose
  report does not arrive keeps its tombstone. Visible, and conservative.

## Related ADRs

- **Answers:** ADR-0042's open point on the retention period — with a
  rejection of the question instead of a number, and with a correction of the
  coupling to ADR-0020.
- **Extends:** ADR-0057's list of permitted policies by the third case.
- **Applies:** ADR-0040 (determination 7 untouched), ADR-0049 (report → leader
  writes), ADR-0058 (the actual side is supplied by the system).
- **Does not touch:** ADR-0020. The log entry stays as it is; what disappears
  here is the instruction in the state and not the record.
