# Tardigrade

A container orchestrator for Linux, in Rust, without foreign daemons — built for
REMIT/DORA-regulated environments with a target workload availability of 4-9 to
5-9.

Three binaries — `tgd` (control plane), `tg-agent` (per node), `tgctl` (CLI) —
plus `tg-proxy`, the data plane's sidecar.

### Advanced Container Dependency Mechanics (Graph-Based)
* **Orthogonal Dependency Axes:** Explicitly decouples execution ordering (`After`/`Before`) from functional requirements (`Requires`, `Wants`, `BindsTo`, `Conflicts`). This structural separation avoids the classic pitfalls and ambiguities found in standard systemd or compose-style setups.
* **True Graph Modeling:** Dependencies are modeled natively as graph edges rather than loose foreign-key fields. Cycles, self-references, or unreadable configurations are caught early at ingest and isolated before they can compromise the cluster state machine.
* **Damped Runtime Evaluation:** Edges are evaluated dynamically on a per-pass condition basis rather than being driven by brittle, cascade-triggering state change events. A deferred or just-restarted target explicitly avoids dragging down its dependents.
* **Inherent Sidecar Coupling:** The security-critical mTLS data-plane sidecar is bound natively to its application workload using a strict `BindsTo` and `After` edge graph. If the container's cryptographic identity fails or expires, the workload's routing is securely halted.

### Architecture, Performance & Determinism
* **Pure Rust Architecture:** Eliminating Go and standard Kubernetes components removes runtime Garbage Collection (GC) jitter. This choice guarantees deterministic tail-latency profiles across critical data paths.
* **Static Stability Principle:** Workload Availability Service Level Objectives (SLOs) are completely decoupled from the status of the control plane. A control plane failure or quorum loss does not disrupt actively running containers.
* **In-Process State Projection:** The architecture drops heavyweight external database dependencies in favor of a lean, throwaway in-process memory graph projection, streamlining state lookups.

### Zero-Trust Security & Cryptographic Infrastructure
* **Native SPIFFE Server Architecture:** Every container automatically receives a cryptographic identity (X.509 SVID) minted via a localized subsystem built directly into the agent. This removes external SPIRE-style dependencies while keeping the runtime hot path free from central network lookups.
* **Pure Userspace mTLS Data Plane:** Mutual TLS identity checks are handled natively by a customized, transparent sidecar (`rustls`). This provides robust microsegmentation and policy enforcement while explicitly avoiding brittle kernel-level eBPF complexity.
* **Distributed Cryptography (FROST & TPM):** The orchestrator implements Threshold signing (FROST) with distributed key generation (DKG). The Root CA remains securely air-gapped, while live signing shares are physically sealed on-node via TPM.
* **Fully Meshed Wireguard Cluster Underlay** Cluster has a fully encrypted wireguard mesh underneath to protect all traffic inside the cluster, independently from from container zero trust
* **luks2 encrypted container images:** writeable container images are encrypted with linux native luks2, keys bound to TPM

### Fault Tolerance, Compliance & Operations
* **Fail-Soft Isolation Architecture:** A broken or unreadable configuration file only cost-isolates its specific workload. Node agents handle bad definitions gracefully instead of cascading into unrecoverable crash loops that dismantle core network sockets and local resolvers.
* **Tamper-Evident Audit Trails (DORA/REMIT):** Tailored specifically for highly regulated financial/operational compliance environments, the distributed Raft consensus log serves natively as a rigid, tamper-evident WORM substrate before any database compaction takes place.
* **Self Fencing writer instances** singlewriter instances use self fencing to avoid splitbrain situations and maintain data consistency
* **OpenTelemetry Support** full open telemetry support for all components for usage with Grafana, Prometheus e.g.

## Where to find what

| What | Where |
|---|---|
| The architecture decisions | `plans/`, index in `plans/README.md` |
| command reference | `docs/COMMANDs.md` |
| The operations manual | `docs/OPERATIONS.md` |
| The bill of materials of the delivery | `docs/sbom.cdx.json` |


## Building

```bash
cargo xtask ci        # Definition of Done: codegen, fmt, clippy, test, doc,
                      # deny, bill of materials
cargo xtask release   # the delivery build -- reproducible (ADR-0138)
```

Some test runs demand privileges or a running container runtime and therefore do
not belong in the normal suite: `cargo xtask net`, `storage`, `attest`, `image`,
`dst`, `bench`. What they presuppose stands in section 1 of the operations
manual.

## Limitations
Requires Kernel 6.5+

Cluster Size shall not exceed 50 nodes. This is a design choice, as increasing the node count quadratically increases the amount of WireGuard connections (O(n^2)).

No HPA (Horizontal Pod Autoscaler)

No autobalancing, as the goal is static stability.

(It is not and never will be k8s - tardigrade covers a very special niche)

## Licence

Copyright 2026 Dana Schlifka, under the Apache License 2.0 (ADR-0139). The text
lies as `LICENSE` in the root, the notice as `COPYRIGHT`. The foreign components
stand under their own licences; which those are is said by the bill of
materials.
