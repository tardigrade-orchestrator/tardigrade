# ADR-0079: The workload API socket in the workload container

- **Status:** accepted
- **Date:** 2026-09-04
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-runtime::apply`, `tg-agent`, `tg-identity`, ADR-0035,
  ADR-0006, ADR-0036, ADR-0053, ADR-0060, ADR-0065

## Context and Problem Statement

ADR-0035 moved the workload API socket to the **standardized** SPIFFE surface, and
the justification was interoperability: the ecosystem's client libraries
(`rust-spiffe`, `go-spiffe`, `java-spiffe`, `py-spiffe`) speak exclusively that. The
ADR explicitly calls the sidecar the **"first consumer"**, and the acceptance of
phase 7c required a **foreign** client.

**Measured, the sidecar is the only one that can reach the socket.** The mount arises
in `tg-agent` as part of `Mesh { mounts }` and is appended in `apply.rs` only when
`principal.is_some()` — i.e. for the derived unit (ADR-0059). A workload container
gets exclusively the mounts of its declared volumes.

For a mesh member that is consistent: the sidecar carries the **delegated** identity
on the wire (ADR-0036), and the workload needs no SVID. For everything else it is
not:

- **A SPIFFE-capable application** — precisely the case for which ADR-0035 built the
  standardized surface — cannot fetch its identity.
- **`<mesh>` does not help with that**, and that is the subtlety: it identifies the
  *sidecar*, not the workload. Whoever wants to speak their own mTLS gets nothing by
  this path.
- The restriction is **decided nowhere**. It is a consequence of which branch the
  mount arose in.

## Options Considered

1. **Every workload container gets the socket.**
2. **Opt-in in the definition** (an `<identity/>` element or an attribute).
3. **Leave it** — sidecars only.
4. **One socket per instance**, mounted into exactly its container.

## Decision

**Option 1.** Every workload container gets the workload API socket at the fixed path
from ADR-0059, writable.

### Determination 1: unconditional, not opt-in

The boundary is the **attestation**, not the mount. Whoever reaches the socket gets
the SVID of the workload **they are** — derived through the `pidfd` and the cgroup
behind it (ADR-0053) and resolved forwards against this node's assignment (ADR-0065).
A mount therefore grants no authority over anybody else; it grants self-declaration.

An opt-in would be a switch buying no security (see "Why not the other options"), and
it costs a schema change with a process of its own.

### Determination 2: writable, and why that yields nothing

Using it means writing into it — the same argument as with the sidecar (ADR-0059,
determination 5). The permissions on the socket have **never** authorized: since
ADR-0060 it stands at `0666`, because a connection requires write permission, and
every single one is attested. That is moreover the model of the SPIFFE specification
that ADR-0035 followed.

### Determination 3: the ways out stay controlled

A workload holding its own SVID thereby circumvents **no** enforcement:

- **Outbound**, the rule set in the namespace redirects its TCP traffic to the
  sidecar (ADR-0060), and UDP is dropped (ADR-0074). Whoever has a sidecar does not
  get past it.
- **Inbound**, the **target's** sidecar decides (ADR-0025: the server governs). An
  SVID therefore opens exactly the edges an operator has written.
- A workload **without** `<mesh>` has no rule set and no sidecar — for it, its own
  mTLS is the only way to speak zero trust at all, and precisely that is what this
  decision enables.

### Determination 4: the agent hands over the path, the runtime mounts

`tg-runtime` must not know `tg-identity` — the edge runs the other way (`tg-identity`
depends on `tg-runtime`), and a second one would be a cycle. The path therefore comes
from the agent as with the sidecar, through the `Context`; the runtime knows only the
target in the container.

## Why not the other options

**Option 2 (opt-in)** is the obvious least-privilege answer and buys nothing here,
and that is measured and not assumed: the SVID a container can get is **its own**. A
compromised workload thereby has nothing it did not already have — its edges are
enforced by the target, and its ways out by the rule set (determination 3). The
switch would instead leave the standardized surface unusable in the default case,
i.e. exactly the state ADR-0035 wanted to end.

**Option 3 (leave it)** is today's state, and it contradicts the purpose of ADR-0035.
That it is decided nowhere makes it worse, not better: it is the side effect of an
`if` branch.

**Option 4 (one socket per instance)** is the **better** answer to a *different*
question — attestation without a PID, noted as an open point in ADR-0053. It
presupposes exactly this mount; this ADR is its precondition and does not pre-empt
it. It stays open.

## Consequences

**Positive:**

- The standardized workload API is usable for what it was built (ADR-0035): a
  SPIFFE-capable application fetches its SVID without our sidecar.
- A workload without `<mesh>` can speak zero trust instead of merely running without
  mTLS.
- The mount arises at **one** place for all containers instead of in a branch for one
  of two cases.

**Negative / Costs:**

- **Every container has a writable socket to a privileged process.** The attack
  surface is the gRPC service itself; every connection is attested, and the answer is
  the caller's identity. The sidecar has had this surface since ADR-0059.
- **`/run/tardigrade/` appears in every container.** An image that mounts a tmpfs
  there itself hides it — then that workload gets no SVID, and that stands out at the
  first fetch.

  An image **without** that directory is by contrast harmless, and that is measured
  and not conjectured: the runtime creates the target of a bind mount including its
  parents. A layer without `/run` starts unchanged.
- A workload holding its own key material loses it on a compromise. It is **its own**,
  and the deadlines from ADR-0014 (15 min) bound the window.

## Risks & Open Points

- **One socket per instance** (ADR-0053) has thereby become buildable and is not
  built. It would make attestation through the PID and `/proc` moot and would lift
  the kernel floor of ≥ 6.5.
- ~~**There is no metric for who uses the socket.** `svid_issued_total` counts
  issuances, not callers; which workload speaks its own mTLS an operator does not
  see.~~ **Built:** `tg_identity_workload_api_calls_total{workload}`, counted per
  **call** and not per issuance — a stream that rotates every thirteen minutes for
  twelve hours is one use and not fifty-five. Both calls of the socket are counted:
  whoever only fetches the anchor uses it just as much.

  The **workload** and not the SPIFFE ID: the cardinality rule from ADR-0015. A
  **refused** call does not appear — it has no workload name, because the attestation
  is precisely what failed (ADR-0081); counting it under an invented label would be a
  number that looks like a statement. That it was refused is said by
  `svid_issued_total{outcome="refused"}`.

  No alerting rule, with the reason in `docs/alerts.yml`: there is no wrong value. A
  workload that never uses the socket is not an error — that is the point below.
- **A workload that does not need the socket gets it anyway.** That is the cost side
  of determination 1, and it is deliberately chosen.

## Related ADRs

- **ADR-0035** — the standardized workload API; its "first consumer" was measured to
  be its **only** one.
- **ADR-0053** and **ADR-0065** — the attestation is the boundary, not the mount.
- **ADR-0059** — the mount path, without which this question would not arise.
- **ADR-0025**, **ADR-0060**, **ADR-0074** — why an opt-in buys nothing.
- **ADR-0081** — builds on it: one socket per instance.
