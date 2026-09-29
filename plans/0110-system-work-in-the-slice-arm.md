# ADR-0110: System Work in the Slice Arm

- **Status:** accepted
- **Date:** 2026-09-09
- **Decider:** Dana Schlifka
- **Technical context:** `tg-agent` (`session`, `reconcile`), `tg-runtime`
  (`NodePaths`, `volume`)

## Context and Problem Statement

The session to the control plane (ADR-0040) is a `tokio::select!` loop with
exactly two arms: one receives slices, the other sends a report every five
seconds (ADR-0068). The slice arm calls `apply`, and since ADR-0042 and
ADR-0099 `apply` carries out two executions that touch the **kernel**: it
deletes volumes (tombstones) and creates snapshots.

Both executions call external programs — `losetup`, `mkfs.ext4`, `fsfreeze`,
`e2fsck`, `resize2fs` — and `std::fs::copy` over an entire image. They are
**synchronous**, so they run in the arm, and each one carries a deadline of one
minute (`volume::TOOL_TIMEOUT`).

## Decision Drivers

- ADR-0068 already set up the rule for this loop: backpressure in one direction
  must not stall the other. It applied to the **send side**; blocking work
  *within* an arm was never considered.
- ADR-0064 makes the report the condition of the lease renewal.
- ADR-0062 decided for the reconciler what a failure may cost: its workload,
  not the node.
- Both executions are **level-triggered** (ADR-0104: a tombstone lives until it
  is executed; ADR-0099: the snapshot compares a mark) — so they can be
  deferred without anything being lost.

## Two measured findings

**The first is the blockage.** A `select!` polls exactly one arm at a time;
blocking work inside it stalls the other for its entire duration. Measured with
a probe with a 50 ms ticker and a 1000 ms blockage in the neighbouring arm:

```text
tick times (ms):  [50, 101, 151, 1151, 1203, 1253, 1303]
largest gap:      1000 ms
```

The gap is exactly the blockage. From that follows the chain from ADR-0068,
number by number:

| Step | Number |
|---|---|
| `apply` blocks, per volume | up to **60 s** (`TOOL_TIMEOUT`), in a loop |
| the ticker arm does not fire | for the same duration |
| the node drops out of `reporting_since` | after **15 s** (`REPORT_WINDOW_SECONDS`) |
| the leader skips the renewal | ADR-0064 |
| every single writer of the node fences itself | after **15 s** (`LEASE_SECONDS`) |

A **healthy** node thereby loses its active roles because it copied a volume.

**The second is the abort, and it is the sharper one.** `apply` propagates the
failure with `?`; `once` returns `Err(Ended)`, and `keep_open` reports "session
ended", **moves the endpoint on** (ADR-0077) and waits five seconds. A
`losetup` that did not work thus ends the session to the control plane and
sends the agent to another node — for an error that has nothing to do with the
control plane. With a permanently broken volume that is a loop over all
endpoints.

That is verbatim the finding from ADR-0062, one layer further: there a broken
entry cost the **node**, here a broken volume costs the **session**.

## Options Considered

- **A — The report gets its own task.** Frees the report and not the slice
  path; `introduction` and `applied` are modified in the other arm and would
  need `Arc<Mutex<…>>`.
- **B — `apply` runs concurrently.** Five follow-up steps in the arm hang on it
  (`absorb`, the progress mark, the wake-up, `underlay::reconcile`,
  `rotate::underlay`), plus the monotonicity check from ADR-0040 determination
  4. The largest rebuild.
- **C — The two executions move into the reconciler.** `apply` writes the lists
  as a file, the reconciler reads and executes.
- **D — Lower `TOOL_TIMEOUT` below the lease.** Rejected: the minute is
  measured and justified (it separates slow storage from "does not answer"),
  and lowering it would turn a slow storage device into a failure.

## Decision

Chosen: **Option C.**

1. **The slice arm does not touch the kernel.** `apply` writes what is to be
   done, and does not do it. Both lists go as a file into the network directory
   — the same construction by which edges, egress permissions, active roles,
   endpoints and the peer list reach their consumer. The tombstone file already
   exists for that (`retired` has read it since ADR-0104); the snapshot orders
   are added.

2. **Execution happens in the reconciler.** It is the strand that **may**
   block: it has a watchdog (`tg_task_alive`, ADR-0082), its readiness is
   visible, and ADR-0062 decided for it that a failure costs its workload and
   not the node. It holds the `VolumeStore` anyway.

3. **A failure ends nothing.** It is reported and retried at the next pass — so
   **more often** than before (every ten seconds instead of per slice), and
   without touching the session.

4. **`--keep-snapshots` stays a setting of the node** and travels via the
   reconciler's `Context`, not via the file. Writing it into the slice would
   turn a node setting into a cluster fact.

5. **The rule applies generally and gets a guard:** no system work stands in an
   arm of this loop. Whoever adds one has the conversation.

## Consequences

**Positive**

- The chain from ADR-0068 is broken at this point: a copied volume no longer
  costs an active role.
- A broken volume no longer costs the session — and thereby no endpoint change
  to a node that is not the leader at all.
- Execution is attempted more often (per pass instead of per slice) and no
  longer depends on the log moving. A tombstone for a volume whose deletion
  once failed was previously retried only at the next slice — in a quiet
  cluster therefore possibly never.
- ADR-0104 stays untouched: the execution is still reported, and the leader
  clears the instruction.

**Negative / costs**

- **The progress mark is written before the volumes are executed.**
  `tg_node_slice_lag` therefore says "applied" while a deletion is still
  outstanding. The information is not gone — it stands in `retired` (ADR-0104)
  and in `tg_cluster_volume_tombstones` — but it stands somewhere other than
  before.
- Between the slice and the execution lies up to one reconcile interval. For a
  deletion an operator expressly decreed that is up to ten seconds more.
- One file more in the network directory.

**Risks & open points**

- The reconciler now blocks at the same place. That is the decision — it has
  the watchdog — but a hanging `losetup` costs a pass there, and the self-fence
  lies in it (ADR-0076). The deadlines from `TOOL_TIMEOUT` bound it; an
  ordering condition between them and the fence margin is **not** established.
- The guard reads source code and knows the names of the system calls, not
  their effect. Whoever blocks via an intermediate value gets past.

## Related ADRs

- Depends on: ADR-0040 (the session), ADR-0068 (the rule for its arms),
  ADR-0062 (what a failure may cost)
- Applies: ADR-0104 (tombstones are level-triggered), ADR-0099 (the snapshot
  compares a mark), ADR-0082 (the reconciler's watchdog)
- Affects: ADR-0064 (the lease renewal hangs on the report), ADR-0077 (the
  endpoint change)
