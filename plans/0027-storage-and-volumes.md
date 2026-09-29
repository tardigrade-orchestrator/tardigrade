# ADR-0027: Storage & Volumes

- **Status:** accepted — writable exclusive, shared read-only only; shared/mutable state → external S3; application-level replication
- **Date:** 2026-08-19
- **Deciders:** Core team

## Context and Problem Statement

Storage was overlooked in the first round of ADRs. It interacts hard with the
fencing/single-writer model (ADR-0010): a shared **writable** volume reopens, at
the storage level, the split-brain hole that the compute layer closed
structurally — and there it manifests as **data corruption**. On top of that,
shared writable filesystems generally run into the oplocking/coherency cliff
(SMB oplocks, NFS delegations).

## Decision Drivers

- Rule out split brain/corruption structurally (consistent with 0010/0014).
- No oplocking/coherency problem of shared writable filesystems.
- Static stability (0019): no runtime storage dependency in the failure path.
- No large network storage system as a DORA concentration risk.
- Low I/O latency (local) for 4-9/5-9.

## Decision

**Option B, tightened.** The orchestrator does **no** volume orchestration across
nodes.

**Volume types**
- **Ephemeral:** the overlayfs upperdir, local (ADR-0003), dies with the container.
- **Persistent, writable:** **exclusive** — a volume belongs to exactly **one**
  workload/instance, **node-pinned** on a local filesystem. **Never** shared,
  never moved across nodes.
- **Persistent, shared:** **read-only only** — several containers may mount the
  same volume RO (effectively immutable reference data: config, models, static
  assets).

**Rules**
- **No shared writable filesystem** → no oplocking, no storage split brain.
  Producer/consumer runs over the network (mTLS, 0007), not over a shared mutable
  volume.
- **Databases/stateful cores replicate through their own mechanics** (WAL
  shipping, their own Raft/replication). They achieve RPO=0 through **synchronous**
  replication under their own control.
- **HA of a stateful workload = a replica with its own volume** on another node,
  fed by application-level replication — **no** volume migration.
- **Encryption at rest** per volume (LUKS/fs level) with a key from KMS/threshold
  (ADR-0014/0016).
- **Shared RO reference data** is distributed to the nodes content-addressed (like
  the image content store, 0003) or mounted RO — no coherency risk.

**Shared/mutable state across instances → external S3**
- Workloads that appear stateless but have to share state (the classic case: N
  web services writing away uploads) use **external S3 object storage** as a
  client. The state then lies in the S3 store, not on an instance disk → the
  instances are genuinely stateless again and arbitrarily replaceable; no shared
  writable filesystem, no oplocking.
- **The orchestrator provides NO object store of its own.** It points at
  **existing** S3 (e.g. NetApp StorageGRID/ONTAP S3) — durability, replication
  and HA are already solved there, operated and audited separately. That keeps
  the orchestrator's scope lean and imports no large storage subsystem.
- **Access:** S3 is an **external** endpoint (not a SPIFFE workload) → the
  connection runs over **TLS against its CA** (not SPIFFE mTLS); **S3
  credentials** come through the secrets service (ADR-0016), not into the image;
  **egress** to S3 is subject to an egress allowlist (see the open points).
  Encryption/retention is handled by the S3 store (or client-side).

**No storage fencing needed:** because writable volumes are never shared, the
compute fence (the lease epoch, 0010) suffices; a separate storage fence (SCSI
PR or similar) is unnecessary.

## Consequences

**Positive**
- Storage split brain/corruption is **structurally impossible**; the whole
  oplocking class is gone.
- Local I/O latency (NVMe); inherently statically stable (no CP dependency in the
  runtime path).
- No large network storage dependency **in the orchestrator**; it dogfoods the
  local+Raft model of SurrealDB/the Raft log.
- Shared/upload state is offloaded onto **existing** S3 — durability/HA off the
  plate, the orchestrator's scope stays lean.

**Negative / Costs**
- No automatic failover of **arbitrary** black-box stateful workloads — they have
  to replicate, or they are run as a single instance with snapshot/restore DR
  (non-instantaneous recovery).
- A workload with a writable local PV is **node-pinned** (a scheduler constraint,
  0011); HA through a replica instead of volume migration.
- A snapshot/backup mechanism is needed for DR (decoupled from the failover path).
- External S3 is a dependency outside the zero-trust mesh boundary (TLS instead
  of SPIFFE mTLS; separate governance of the S3 system).

**Risks & Open Points**
- ~~The local PV lifecycle (provision/resize/**delete** — delete is destructive,
  protected/explicit).~~ — **done:** 10b and ADR-0063.
- ~~Snapshot/backup/DR mechanics and retention periods (coupling to 0020).~~ —
  **done:** snapshot/restore ADR-0099 — the **retention** stands as a point of
  its own.
- ~~The distribution mechanics of the RO reference data (content-addressed vs. an
  RO mount).~~ — **done:** 10c — content-addressed through the same store.
- ~~Custody of the volume encryption key (0014/0016).~~ — **done:** ADR-0113
  (derivation) on top of ADR-0095 (the data key).
- ~~**An egress policy for external endpoints (S3 and others)** — the allowlist
  model is not yet captured in an ADR of its own (the mesh/`may_talk` covers only
  intra-mesh).~~ — **done:** ADR-0041.

## Related ADRs

- Ephemeral/content store: ADR-0003. No storage fence needed: ADR-0010.
- Node pinning: ADR-0011. Static stability: ADR-0019.
- Encryption: ADR-0014/0016. S3 credentials: ADR-0016. Backup retention/audit: ADR-0020.
- Supplemented by: **ADR-0042** — *how* a deletion reaches the node the volume
  lies on. That it is explicit and protected stays unchanged; only the path
  there is added.
