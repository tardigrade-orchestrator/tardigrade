# ADR-0013: Service Discovery (a DNS front end, backed by SurrealDB)

- **Status:** accepted — a DNS front end, graph-backed
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

A workload has to find another one's address. Importantly: discovery yields
**only name → endpoint(s)**. Identity is checked by the mTLS handshake through
the SPIFFE ID (ADR-0006/0007), permission comes from the `may_talk` edges
(ADR-0025). Discovery is therefore pure address resolution, separate from
identity and authorization.

## Decision Drivers

- Compatibility with unmodified third-party images (standard DNS).
- The SurrealDB graph remains the source of truth.
- Health-aware resolution.

## Decision

Chosen: **a DNS front end, backed by SurrealDB.**

- A small **pure-Rust DNS server** (aardvark-dns-like) resolves service names
  against the **healthy endpoints** from the eventual actual status (SurrealDB,
  ADR-0004).
- Unmodified images speak ordinary DNS; no application awareness required.
- **Health-aware:** only healthy endpoints are returned. The short staleness of
  the eventual status is absorbed by mTLS plus retry (an endpoint that is
  already dead fails at handshake/connect, and the client tries the next one).
- A clean separation: discovery = address, identity = SPIFFE at the handshake,
  authorization = `may_talk` (0025).

## Consequences

**Positive**
- Third-party images work without modification.
- The graph stays the single truth; discovery is only a projection.
- Health-aware without a separate health protocol in the client.

**Negative / Costs**
- Eventual staleness (brief) — an endpoint that has just died can still be
  resolved; absorbed by retry, but not zero.
- The DNS server is one more component; DNS TTL and negative caching have to be
  set conservatively so that staleness stays small.

**Risks & Open Points**
- ~~Fix the DNS TTL vs. the staleness window.~~ — **done:** 9a — TTL 5 s,
  negative 1 s.
- ~~Placement of the resolver (per node in the agent vs. a central service) —
  leaning per node for failure decoupling (static stability, ADR-0019).~~ —
  **done:** 9c — per node, on the gateway.

## Related ADRs

- Data source: ADR-0004 (actual status). Separation: ADR-0007/0025.
- Datapath: ADR-0012.
