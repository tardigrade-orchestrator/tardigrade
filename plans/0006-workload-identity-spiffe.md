# ADR-0006: Workload Identity per SPIFFE (without SPIRE)

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

Every container is to receive a cryptographic identity per SPIFFE, as the basis
for zero-trust mTLS (ADR-0007). The reference implementation SPIRE is Go and
therefore ruled out by "pure Rust". We have to provide the SPIFFE core
functions ourselves: node attestation, workload attestation, SVID issuance,
rotation, trust-bundle distribution.

## Decision Drivers

- Pure Rust (no SPIRE server/agent).
- SPIFFE ID scheme: `spiffe://<trust-domain>/<path>` per workload.
- Short-lived SVIDs with automatic rotation.
- Interop with standard mTLS (X.509 SVID in the SAN URI).

## Options Considered

- **A: our own SPIFFE server plus node agent, X.509 SVID.** The control plane acts
  as SPIFFE server/registrar; `tg-agent` implements the workload API (a Unix
  domain socket mounted into the container) and issues/rotates SVIDs. Usable on
  the client side through the `spiffe` crate. The CA hierarchy gets its own ADR
  (proposed).
- **B: JWT SVIDs only.** Easier to distribute, but weaker for transport mTLS;
  better suited to app-level auth. A complement, not a basis.
- **C: run SPIRE anyway.** Rejected (Go, violates a core requirement).

## Decision

Chosen: **Option A**, X.509 SVID as the primary format, JWT SVID optional for
app auth.

The model:
- **Trust domain** per cluster, e.g. `spiffe://cluster.local`.
- **SPIFFE ID assignment** derived deterministically from the workload definition:
  `spiffe://cluster.local/ns/<namespace>/workload/<name>`.
- **Node attestation:** the agent authenticates to the SPIFFE server through its
  node identity (bootstrap credential; TPM attestation as later hardening).
- **Workload attestation:** the agent binds the SVID to the concrete container
  (the PID/cgroup association of the OCI runtime start from ADR-0003), not to
  arbitrary processes.
- **Delivery:** SVID plus trust bundle over the SPIFFE workload API socket,
  mounted into the container; short TTL, proactive rotation before expiry.

### Server architecture (refinement)

- **No daemon of its own.** The SPIFFE server is a **subsystem inside `tgd`**
  (next to Raft and the CA) — the deployment stays three binaries, with no
  SPIRE-style additional system.
- **Four jobs:** (1) owner of the trust domain plus publication of the trust
  bundle; (2) node attestation of joining agents; (3) registration authority;
  (4) signing/rotating through the CA (ADR-0014).
- **Registration is derived automatically.** Unlike SPIRE, the entries "which
  SPIFFE ID belongs to which workload" are **not** maintained by hand — they
  follow from desired state (SurrealDB, ADR-0004) plus the scheduling assignment
  (ADR-0011). A structural benefit of identity and orchestration being the same
  system.
- **A delegated intermediate for static stability.** The server issues every
  agent a short-lived signing intermediate; the agent mints and rotates the
  workload SVIDs **locally** from it (no server call on the hot path). If the
  server fails, the agent keeps minting for the lifetime of the intermediate
  (ADR-0019/0014).
- **Authority binding:** an agent may mint SVIDs only for workloads placed on
  its node → a bounded blast radius if a node is compromised.
- **State in the Raft log:** registration entries, agent authorizations and the
  trust bundle are control-plane state (ADR-0005) — replicated, consistent and
  auditable in a tamper-evident way (ADR-0020).
- **Bootstrap chain:** root at cluster init (offline, ADR-0014); the first node
  credential via join token/TPM; after that agent ↔ server over mTLS with node
  SVIDs (the control plane dogfoods its own identity system).

## Consequences

**Positive**
- A standards-conformant identity model; clients can use standard SPIFFE libraries.
- Identity is bound to the real container, not to a secret in the image.

**Negative / Costs**
- Building the SPIFFE server plus attestation ourselves is substantial (this is "SPIRE lite").
- Node attestation is security-critical — a weak bootstrap means identity theft.

**Risks & Open Points**
- ~~CA design (root/intermediate, rotation) → ADR-0014 (accepted: air-gapped root
  plus threshold signing).~~ — **done:** ADR-0014.
- ~~Define the workload attestation selectors exactly (what constitutes workload X?).~~
  — **done:** ADR-0053, ADR-0065, ADR-0081 — the socket is the attestation.

## Related ADRs

- Basis for: ADR-0007 (the mTLS data plane).
- Depends on: ADR-0003 (container PID/cgroup association).
- Opens: the PKI/CA ADR (proposed).
