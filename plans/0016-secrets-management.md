# ADR-0016: Secrets Management (SPIFFE-native)

- **Status:** accepted — a SPIFFE-native secrets service, in-memory delivery
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

Workloads need secrets (DB passwords, registry credentials for the image pull
from ADR-0003, API keys). To be settled: storage and delivery. The SPIFFE
identity system offers a natural solution here.

## Decision

Chosen: **a SPIFFE-native secrets service.**

- Workloads authenticate to the secrets service with their **SVID over mTLS**;
  permission runs through the same deny-by-default policy as `may_talk`
  (ADR-0025).
- **In-memory delivery** (a tmpfs mount or an API) — secrets **never** land on
  the container's persistent disk and **not** in environment variables.
- **Encryption at rest** with a key from the threshold/air-gapped trust or a KMS
  (ADR-0014). The ciphertext may lie in the store; decryptable only through that
  key.
- **The access policy** (which workload gets which secret) is desired state →
  Raft (ADR-0004); every access is auditable (ADR-0020).
- **Registry credentials** (ADR-0003) run over the same path.
- **Static stability:** secrets already delivered stay in the workload's memory
  across control-plane blips; the agent may cache them locally (in memory/tmpfs
  only) for restart resilience. New fetches during a total outage may fail
  (accepted, ADR-0019).

## Consequences

**Positive**
- No secrets on disk or in the environment; dogfoods identity plus authorization.
- Every secret access is identity-bound and audited.

**Negative / Costs**
- A secrets service is extra build effort (more than env/file injection).
- In-memory delivery plus rotation is more complex than a static mount.

**Risks & Open Points**
- ~~Custody of the encryption key (coupling to ADR-0014 threshold/KMS).~~ —
  **done:** ADR-0095 and ADR-0100.
- ~~Fix the delivery mechanism (tmpfs vs. API) and rotation propagation.~~ —
  **done:** ADR-0098 (tmpfs) and ADR-0100 (rotation).

## Related ADRs

- Auth: ADR-0006. Authorization: ADR-0025. The encryption key: ADR-0014.
- Registry credentials: ADR-0003. Audit: ADR-0020. Outage behaviour: ADR-0019.
