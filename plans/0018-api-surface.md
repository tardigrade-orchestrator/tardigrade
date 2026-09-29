# ADR-0018: API Surface (CLI & gRPC)

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

The cluster's control interface (CLI, programmatic access) is to be fixed.

## Decision

- **`tgctl`** as the CLI; **`tgd`** exposes a **gRPC API** through `tonic`
  (from ADR-0002).
- **Secured with the same SPIFFE mTLS identities** as the workloads — the API
  dogfoods the identity and authorization system (ADR-0006/0025).
- gRPC is primary; a **REST gateway** is optional for tooling without gRPC.
- All mutating calls run through the leader → the Raft log (ADR-0005) and are
  thereby audited (ADR-0020).

## Consequences

**Positive**
- A uniform mTLS security layer; no separate API auth system.
- Streaming (watches) natively over gRPC.

**Negative / Costs**
- gRPC-only is inconvenient for some clients → an optional REST gateway is effort.

**Risks & Open Points**
- API versioning/compatibility policy.
- ~~The RBAC granularity of the API operations (who may do what) — tied to the
  SPIFFE identity.~~ — **done:** ADR-0103 (transport) and ADR-0105 (five classes).

## Related ADRs

- RPC/TLS: ADR-0002. Identity/authorization: ADR-0006/0025. Audit: ADR-0020.
