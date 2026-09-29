# ADR-0010: Reconciliation Model & Autonomy Boundary

- **Status:** accepted — fenced-autonomous (refinement: lease-epoch fencing)
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

Two connected questions that block phase 4 of the build plan: (1) by what model
is actual reconciled against desired, and (2) what may a `tg-agent` do
**without quorum** — in particular on node failure while the control plane is
unreachable. The keystone ADR-0019 demands that the data plane survive loss of
the control plane; at the same time, in a REMIT/DORA context split brain (e.g.
executing an order twice) is catastrophic.

## Decision Drivers

- Level-triggered robustness (missed events must not lead to drift).
- Static stability (ADR-0019): no control-plane call on the hot path.
- **Split-brain safety** for workloads with side effects.
- Fast failover for 4-9/5-9, without waiting for control-plane recovery.

## Decision

### 1. Reconciliation: level-triggered, two-stage

- **Cluster reconciler** (on the leader, quorum-backed): places workloads,
  writes assignments and — for single-writer workloads — the **active-role
  lease** into the Raft log (ADR-0005); materializes into SurrealDB (ADR-0004).
- **Node reconciler** (in the agent, local): drives actual → desired against the
  **persisted local desired-state cache** (ADR-0019), idempotent, able to run
  without control-plane reachability.

### 2. Two workload classes (declared in the definition, ADR-0008)

- **Replicable (default):** stateless/idempotent, no single-writer constraint.
  Full static stability — keeps running on both sides of a partition, **no
  fencing, no activation switchover** needed. The SVID is minted locally.
- **Single writer (opt-in):** at most one active instance cluster-wide, for
  workloads with side effects. Governed by a **quorum-backed active-role lease
  with a monotonically increasing fencing epoch**.

### 3. The autonomy boundary

**Permitted without quorum:**
- letting running workloads keep running (never kill them for loss of quorum);
- restarting our own assigned, crashed instances per the local cache;
- **self-fence:** a single-writer instance that cannot renew its active-role
  lease stops the active role **autonomously** when the lease expires.

**Not permitted without quorum:**
- new placements without a standing assignment;
- **activating** a single-writer standby (needs a lease grant from the quorum
  with a higher epoch);
- cluster-wide mutations (desired state, membership, policy).

### 4. Fencing mechanics (a refinement over "SVID hard expiry alone")

Plain "the standby activates after the primary's SVID hard-expires" is **not**
split-brain safe: a partitioned primary keeps minting its SVID through its local
agent intermediate (static stability!) → the SVID does not expire. Therefore:

- **The active role = a quorum-backed lease with a fencing epoch.** The minority
  side cannot renew → self-fence. On the majority side: a warm, pre-placed
  standby takes a lease with a higher epoch from the quorum → activates
  **quickly**.
- **Downstream enforcement:** the sidecars (ADR-0007/0025) refuse a stale epoch →
  fencing bites even if the old primary stops slowly. The currently valid epoch
  is propagated to the peers (option: as part of the active-role
  credential/SVID — see the open points for the propagation path).
- **SVID hard expiry** remains the identity backstop (an instance without a
  valid SVID is out of the mesh anyway), but it is no longer the sole fence.
- **Replicable workloads** need neither lease nor epoch.

## Consequences

**Positive**
- Split brain for single writers is ruled out **structurally** (the epoch), not
  merely hoped for in time.
- Failover on the majority side is fast (a warm standby plus one lease grant),
  not "wait for control-plane recovery".
- Replicable workloads are fully partition-tolerant.
- Level-triggered → robust against missed events.

**Negative / Costs**
- Single-writer availability is tied to the control plane on **total** loss of
  quorum (inherent, CAP — without a coordination point there is no safe new
  writer). Accepted: rare, and safety dominates.
- A warm standby costs double the resources for single-writer workloads.
- Two workload classes = more model complexity in the definition and in the reconciler.
- Epoch enforcement has to sit in the sidecar/proxy (coupling to ADR-0007/0025).

**Risks & Open Points**
- ~~Quantify lease length and epoch semantics — connected to the figures from
  ADR-0014 (the lease is shorter than, but related to, the SVID TTL).~~ —
  **done:** ADR-0014 (15 s), ADR-0064, ADR-0076, ADR-0078.
- ~~Fix exactly how the valid epoch is **propagated** to downstream peers
  (embedded in the SVID/credential vs. a separate channel).~~ — **done:**
  ADR-0066 — enforced locally, no epoch on the wire.
- ~~Pre-placing the warm standbys is a scheduler task (ADR-0011).~~ — **done:**
  ADR-0034 — instances in the command set, the scheduler places them in advance.

## Related ADRs

- Binds: ADR-0019 (static stability), ADR-0005 (the lease in the Raft log).
- Figures: ADR-0014 (lease vs. SVID TTL). Enforcement: ADR-0007/0025.
- Declaration of the workload class: ADR-0008. Standby placement: ADR-0011.
- The active-role lease is unambiguously actual/cluster state → it belongs in
  the Raft log (anticipating the desired/actual boundary, 0004/0005).
