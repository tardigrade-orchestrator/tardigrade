# ADR-0007: Zero-Trust Data Plane (mTLS) in Userspace, without eBPF

- **Status:** accepted — transport/auth decided; data-plane runtime → ADR-0022
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

Communication between workloads is to be secured zero-trust with mTLS, where
the identities come from ADR-0006 (SPIFFE SVIDs). An explicit requirement:
**entirely in userspace, no eBPF** (no Cilium-style approach). To be settled:
where TLS ends and begins, and how peer identity is enforced.

## Decision Drivers

- No eBPF, no kernel datapath programs.
- mTLS with mutual SPIFFE ID checking (SAN URI verification).
- As little imposition on workload code as possible (transparency), but pure Rust.
- SVID rotation must not break connections permanently.

## Options Considered

- **A: a Rust sidecar proxy per workload.** One small Rust proxy (rustls) per
  container terminates/initiates mTLS transparently. Conceptual model:
  linkerd2-proxy (Rust). Strongest transparency, highest resource/complexity
  overhead.
- **B: a node-local proxy (one per node).** All workloads on a node share one
  Rust proxy that picks the SVID per connection from the source association.
  Fewer processes, but multiplexing complexity plus weaker isolation.
- **C: a library/SDK approach.** Workloads link a Rust crate that encapsulates
  rustls plus SPIFFE verification. No proxy, but practical only for our own
  (Rust) workloads → violates the transparency goal for third-party images.
- **D: no proxy, pure kernel mTLS via kTLS** — the handshake would stay in
  userspace, but identity policy enforcement is missing; only part of a solution.

## Decision

Chosen: **Option A (sidecar) as the standard, option C as a fast path for
native workloads.**

- **Sidecar proxy (Rust, rustls):** terminates inbound mTLS, initiates outbound
  mTLS; verifies the peer through a **custom certificate verifier** that checks
  the SPIFFE ID from the SAN URI against the trust bundle and the policy.
- **SVID acquisition:** the proxy fetches SVID plus bundle over the workload API
  (ADR-0006), hot-reloading on rotation (rustls allows swapping certificates
  without a restart).
- **Data path:** loopback to the workload plus veth/nftables routing (networking
  ADR, proposed). Purely userspace, no BPF programs.
- **Policy:** the authorization "which SPIFFE ID may talk to which" is maintained
  centrally (SurrealDB graph, ADR-0004) and distributed to the proxies.

## Consequences

**Positive**
- Transparent mTLS even for third-party images, with no code change.
- rustls keeps us OpenSSL-free and pure Rust.
- Identity is enforced on the wire, not just in application code.

**Negative / Costs**
- Sidecar overhead (memory/latency) per workload; that is the classic service-mesh price.
- The sidecar lifecycle (starting/stopping alongside, failure domains) is
  additional orchestration load — it couples to the dependency semantics (ADR-0009).

**Risks & Open Points**
- ~~Solve traffic interception cleanly without eBPF (destination redirect via
  nftables in the netns; clarify the relationship to the networking ADR).~~
  — **done:** ADR-0038 and ADR-0060 — `nft` in the netns, destination from
  `SO_ORIGINAL_DST`.
- ~~Policy distribution plus consistency on rotation.~~ — **done:** ADR-0040
  (the slice) and 8b (the version channel).

## Related ADRs

- Depends on: ADR-0006 (SVIDs), the networking ADR (proposed).
- Affects: ADR-0009 (the sidecar as a dependency of the workload).
- **Authorization (who may talk to whom):** ADR-0025 — this ADR covers only
  authentication/transport.
