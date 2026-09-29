# ADR-0031: Cluster size five, quorum three

- **Status:** accepted
- **Date:** 2026-08-21
- **Deciders:** Core team
- **Technical context:** `tgd`, `tg-consensus`
- **Closes an open point from:** ADR-0005

## Terminology

"Quorum" is colloquially used for two different things. In this project the
following holds throughout:

- **Cluster size** = the number of voting control-plane nodes.
- **Quorum** = the majority threshold, i.e. `⌊n/2⌋ + 1` — the number of nodes
  that have to agree to a decision.

| Cluster size | Quorum | Tolerated failures |
|---|---|---|
| 3 | 2 | 1 |
| **5** | **3** | **2** |
| 7 | 4 | 3 |

## Context and Problem Statement

ADR-0005 chose `openraft` and made the control plane the Raft cluster itself,
but explicitly left the size open: "fix the number of control-plane nodes (3 vs.
5) and the quorum policy". Phase 5 builds the cluster and can no longer leave
that open — the number is embedded in membership handling, DST scenarios and the
placement rules from ADR-0011.

This is about **one** quorum: one Raft group, one state machine, one leader.
Multi-Raft or sharding is not up for debate (see the open points).

## Decision Drivers

- **Target availability 4-9 to 5-9** of the workloads, with a deliberately lower
  target for the control plane (ADR-0019).
- **Maintainability in production** — rolling updates must not take fault
  tolerance to zero.
- **Quorum spreading across failure domains** (ADR-0011, ADR-0019).
- **Write latency** of the control plane, damped by the SLO decoupling.

## Options Considered

- **A: 3 nodes**, quorum 2 — tolerates one failure.
- **B: 5 nodes**, quorum 3 — tolerates two failures.
- **C: 7 or more** — higher tolerance, noticeably worse write latency and more
  coordination overhead, with no discernible need.
- Even numbers are out: 4 nodes tolerate exactly as many failures as 3 (namely
  one) but cost one node more.

## Decision

Chosen: **Option B — five nodes, quorum three.**

The deciding factor is not raw fault tolerance but the **behaviour during
maintenance**. With three nodes every rolling update is a state without reserve:
one node is deliberately down, the remaining two just barely form the quorum,
and a *single* additional failure means loss of quorum. In a REMIT/DORA context
where patching is not an option but an obligation, that would mean: the system
is regularly, by plan, vulnerable.

With five nodes a reserve of one remains during a rolling update.

**Loss of quorum is not an outage but a change freeze** (ADR-0019) — the
workloads keep running. That is precisely why option A would have been defensible
too. Choosing five does not buy workload availability, it buys **the ability to
act**: the ability to keep placing, renewing leases (ADR-0010) and changing
policy during a disturbance.

**The placement rule** (a supplement to ADR-0011): the five nodes are distributed
across at least **three** independent failure domains, no domain holding more
than two. The cluster then survives the loss of a complete domain:

- A 2/2/1 distribution across three domains → losing the largest domain leaves
  three nodes, i.e. exactly the quorum.
- With five domains (1/1/1/1/1) it survives losing two.

For comparison: three nodes across three domains also survive losing one domain,
but after that the reserve is zero.

**What that costs:** a write waits for the majority's acknowledgement, i.e. for
the **third fastest** of five instead of the second fastest of three. The
control plane's tail latency gets worse as a result. That is bearable because
ADR-0019 keeps the control plane out of the hot path of workload communication —
the latency that gets worse here lies on no path with a 4-9 claim. Without that
decoupling the decision would have come out differently.

## Consequences

**Positive**
- Rolling updates without losing fault tolerance.
- Survives the loss of a complete failure domain and retains the ability to act.
- The number is usable from now on in phase 5 (DST scenarios) and phase 6
  (placement validation).

**Negative / Costs**
- Two additional control-plane nodes in hardware and operations.
- Higher control-plane write tail latency (the third fastest of five).
- At least three independent failure domains become a **precondition** for a
  conformant cluster, not merely a recommendation.

**Risks & Open Points**
- ~~At which level of the hierarchy site → hall → rack → host the spreading is
  anchored stays open — the same point ADR-0011 carries as "the default
  granularity of anti-affinity (rack vs. hall)", decided in phase 6.~~ — **done:**
  ADR-0034 — default `rack`.
- Smaller installations with fewer than three domains are therefore not
  conformantly operable. Whether there should be an explicitly degraded
  operating model for that is not decided.
- **Multi-Raft** stays outside this decision. A single quorum means every
  linearizable write goes through one leader — the control plane's scaling
  limit. It is not reached at the intended orders of magnitude; if it is, that
  needs an ADR of its own.

## Related ADRs

- Closes an open point from: ADR-0005.
- Supplements: ADR-0011 (quorum spreading, the placement rule), ADR-0010 (a
  lease grant needs quorum).
- Carried by: ADR-0019 (the SLO decoupling makes the latency cost bearable).
