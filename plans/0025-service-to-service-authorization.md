# ADR-0025: Service-to-Service Authorization (the meshing policy)

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

mTLS (ADR-0007) delivers **authentication** — who the peer cryptographically is,
evidenced by the SPIFFE ID in the URI SAN (ADR-0006). It says nothing about who
**may** talk to whom. "Meshing on demand" is exactly that authorization layer.
To be decided: how reachability is expressed, stored and enforced.

## Decision Drivers

- Zero trust: **deny by default**, least privilege.
- Graph-native: reachability is a relation between identities → naturally stored
  in the SurrealDB graph (ADR-0004).
- Local enforcement without a control-plane call per connection (ADR-0019).
- Orthogonal to the dependency semantics (ADR-0009): "depends on" ≠ "may talk to".
- Auditable (REMIT/DORA): who could talk to whom and when must be evidenceable.

## Options Considered

- **A: a flat mesh (allow-all inside the mesh).** Simple, but it violates zero
  trust — every identity reaches every other. Rejected.
- **B: a statically selective allow list as graph edges.** Deny by default, pairs
  are explicitly enabled on demand. **Chosen.**
- **C: just-in-time grants (a JWT SVID with an audience).** A runtime request,
  time-bounded. Powerful, but more moving parts; not now.
- **D: B and C combined.** Possible later; B does not preclude C.

## Decision

Chosen: **Option B — statically selective authorization.**

**The model**
- **Mesh membership (coarse):** opt-in per workload in the definition (ADR-0008).
  No mesh flag → no identity, no participation.
- **Reachability (fine):** deny by default. A permission is a directed edge in
  the SurrealDB graph, e.g.
  `RELATE $source->may_talk->$target SET port = 8443, proto = "tcp"`.
- **The edge type stands on its own** and is separate from the dependency edges
  from ADR-0009 (tooling may derive suggestions, but not equate them
  automatically).
- **Selectors:** target/source as an exact SPIFFE ID **or** a path prefix selector
  (e.g. "all workloads in `/ns/trading/`"), to keep edges from proliferating.

**Enforcement**
- On both sides (defence in depth): the client sidecar checks "may I initiate to
  the target ID?", the server sidecar checks "may I accept from the source ID?".
  **The server governs** (a malicious client does not clear itself).
- The policy is distributed to the sidecars/agents, **cached locally, enforced
  locally**.
- **Behaviour when the policy store is unreachable (ADR-0019, fail-static):** the
  last known good policy stays valid; existing permitted connections keep
  running; new connections are evaluated against the cache. **Not** fail-open,
  **not** fail-closed on existing traffic.

**Change semantics**
- **Adding** an edge → after propagation, new connections are permitted.
- **Removing** an edge (revocation) → new connections are blocked locally at
  once; existing connections are terminated within a **bounded revocation
  window**. The SVID TTL (ADR-0006) is the final backstop.
- All edge changes are control-plane mutations → they run through the Raft log
  and are therefore logged tamper-evidently (ADR-0005/0020).

**Audit**
- Both edge changes and enforcement decisions (allow/deny, sampled) are audit
  events (ADR-0020) — the basis for the REMIT/DORA evidence "who could talk to
  whom and when".

## Consequences

**Positive**
- Least privilege by default; every communication relation is explicit and justifiable.
- Graph-native — the same storage and traversal as the rest of the config.
- Fully enforceable locally → no availability coupling to the control plane.
- The edge audit trail is a direct compliance artefact.

**Negative / Costs**
- Operational maintenance effort: the edges have to be curated → good CLI/UX is
  needed, otherwise edges proliferate. Prefix selectors damp that.
- Revocation is not instantaneous (a propagation plus revocation window).

**Risks & Open Points**
- ~~**The size of the revocation window** is the central trade-off (security vs.
  static stability) — analogous to the SVID soft-fail window; it must be
  quantified and justified.~~ — **done:** 8b — the version channel, the SVID TTL
  as the backstop.
- Finalize selector granularity (exact/prefix only, or label-based as well?).
- L7 authorization (HTTP path/method) is **not** included — the proxy authorizes
  at L4 (identity plus port/proto). Possibly a later ADR.
- JIT/JWT SVID (option C) stays open for later; this model does not preclude it.

## Related ADRs

- Refines: ADR-0007 (mTLS = authentication; this ADR = authorization).
- Orthogonal to: ADR-0009 (dependency ≠ reachability).
- Storage: ADR-0004. Identity: ADR-0006. Enforcement under: ADR-0019.
- Audit/retention: ADR-0020.
