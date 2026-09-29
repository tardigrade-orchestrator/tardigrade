# ADR-0066: Where the active role is enforced

- **Status:** accepted
- **Date:** 2026-08-31
- **Deciders:** Architecture
- **Technical context:** `tg-proxy`, `tg-model::mesh`, `tg-agent`, ADR-0010

## Context and Problem Statement

ADR-0010 explicitly leaves two points open: *"epoch enforcement has to sit in the
sidecar/proxy"* and *"fix exactly how the valid epoch is propagated to downstream
peers"*. ADR-0064 built the lease but bound only the **container lifecycle** to it:
without a valid lease instance 0 does not start, and on expiry the reconciler ends
it.

Measured, two gaps therefore remain:

1. **The standby is unbridled.** `role_of` exempts instance ≠ 0 (ADR-0064,
   determination 8) — correctly, because a warm standby has to **run** in order to
   be warm. But it therefore runs completely: it accepts connections and
   establishes them, although it does not hold the active role. And `replicas="2"`
   is exactly what the lint from ADR-0009 recommends to every single writer.
2. **A slow stop stays unanswered.** ADR-0010 names the case verbatim: *"fencing
   bites even if the old primary stops slowly."* The reconciler ends the container
   with a deadline; if the process hangs, it keeps talking.

Both hit the same promise — **there is at most one writer** — and neither is
enforced today.

## Decision Drivers

- **The sidecar sits on the same machine as the holder.** It has the same clock and
  the same lease statement; it can refuse at once. For the case that matters — a
  **detached, honest** node — that requires **no propagation**.
- **ADR-0040 determination 7** stays untouched: the slice already carries the own
  leases (ADR-0064), nothing is added.
- **Fail-closed, not fail-static.** ADR-0019 protects **existing permitted**
  traffic from a loss of the control plane. Here it is about a role that does not
  arise without quorum at all — the same direction as with the egress port
  (ADR-0041): no information means no active role.
- **No format break.** The fifth is still outstanding; a sixth would be operational
  work nobody ordered.
- **An unmodified third-party image must have to do nothing.** Enforcement belongs
  in the sidecar, not in the workload (ADR-0007).

## Options Considered

- **A — the epoch on the wire.** The client claims its epoch, the server compares
  against a monotonic high-water mark per peer workload (a fencing token). There is
  **no room** for it: the mesh link is mTLS and after that a byte pipe; ALPN is
  free but negotiates exact strings and carries no value. It would need a preamble
  before the splice — a new wire format between sidecars, i.e. a sixth coordinated
  switchover. And it protects against a node that **lies** — not against the one
  that matters.
- **B — the epoch in the SVID.** Re-mint on every renewal: a lease carries 15 s, an
  SVID 15 min (ADR-0014). Twenty times the minting work for a statement that can be
  read locally.
- **C — the sidecar enforces locally.** It learns from a file whether its workload
  holds the active role, and refuses mesh traffic in **both** directions as long as
  it does not hold it.

## Decision

Chosen: **Option C**.

### 1. A single writer's sidecar refuses without the active role

Inbound **and** outbound. Inbound, because otherwise a standby answers requests
that belong to the holder; outbound, because otherwise a slowly dying primary
keeps writing.

What is refused is the **connection**, not the container: the reconciler ends that
(ADR-0064), and whoever coupled the two would have two places deciding the same
thing.

### 2. Who is affected stands on the sidecar — not in the file

The derived unit gets `--single-writer` if its workload carries the class
(ADR-0059: the node derives and knows the definition).

That is the difference between fail-closed and fail-open: if affectedness stood
**in** the file, a missing file would mean "nobody is affected" — and a read error
would lift the active role for everyone. This way it means "no active role", and
that is the safe direction.

### 3. The file carries the holders, with epoch and deadline

One file per node with the workload name in the line — the same construction as
`may-talk` and `egress`, for the same reason: the sidecar runs in a container, has
no node identity and cannot ask the control plane. The agent writes it from the
slice (ADR-0040), the sidecar re-reads it in operation.

The **epoch** stands in it although nobody compares it today: it is the value
ADR-0010 wants propagated, and adding it later would mean changing the format a
second time.

### 4. The deadline is the lease's, without a safety margin

The margin from ADR-0064 determination 7 belongs to the **container stop**: it
exists so that the old holder has stopped before the new one starts. The sidecar is
the **fallback** for the case where exactly that does not work — it cuts at the
real deadline. Cutting earlier would take availability without making anything
safer.

Running connections are **torn down** in the process, not merely new ones refused;
otherwise a long stream would outlive the fencing deadline, and that is precisely
the dangerous case. The machinery for it has existed since ADR-0025 (the version
channel and the watcher).

### 5. What is explicitly **not** decided

The propagation of the epoch to **foreign** peers (option A) stays open. It
protects against a node claiming a false epoch — i.e. a compromised node, which can
switch off enforcement anyway. The case ADR-0010 names ("the old primary stops
slowly") is settled by determination 1.

## Consequences

**Positive**

- The standby no longer talks although it runs — the gap `replicas="2"` opens for a
  single writer.
- A hanging primary loses its traffic at lease expiry, even if its container does
  not die.
- No format break, no new wire format, no second auth path.
- The construction is the third of its kind in the sidecar (`may-talk`, `egress`,
  now the active role) — whoever has read one knows the others.

**Negative / Costs**

- **A behavioural change.** A single writer with `<mesh>` to which nobody grants a
  lease is no longer reachable over the mesh. That is the promise — but it is a
  difference from today.
- **Only with a sidecar.** A single writer without `<mesh>` stays unbridled; the
  same boundary as with ADR-0025 and ADR-0041.
- A fourth path in the container, a fourth mount point.

**Risks & Open Points**

- **It does not help against a lying node** (determination 5).
- ~~**The clock is the node's.** If it runs fast, the sidecar cuts earlier than
  necessary; if it runs slow, later. ADR-0024 requires a traceable time source
  anyway, and the lease is built on the same clocks (ADR-0064).~~ — **done:**
  ADR-0078 — the ordering condition `skew < FENCE_MARGIN`, the skew as a metric.
- **Instance ≠ 0 is bridled too**, although ADR-0064 exempts it from the container
  lifecycle. That is intended and the core of this ADR: run yes, talk no.

## Related ADRs

- Redeems: ADR-0010 ("epoch enforcement has to sit in the sidecar/proxy")
- Depends on: ADR-0064 (the lease), ADR-0059 (the node derives the sidecar),
  ADR-0040 (the slice carries it)
- Adjacent: ADR-0025 (the version channel and the watcher), ADR-0041 (fail-closed
  outbound), ADR-0019 (fail-static does **not** apply here)
