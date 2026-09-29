# ADR-0028: Device Access via CDI (accelerator inference)

- **Status:** accepted — a CDI seam for inference; training/RDMA/time-slicing out of scope. **Built with ADR-0143** (2026-09-15)
- **Date:** 2026-08-19
- **Deciders:** Core team

## Context and Problem Statement

"AI" breaks into three things: (1) **models as data** — large RO artefacts,
already solved (ADR-0027: RO reference data / external S3); (2) **inference
serving** — from the orchestrator's point of view "a web service that wants an
accelerator", which fits the existing compute model and only lacks device
access; (3) **training** — gang scheduling, RDMA/NVLink, checkpointing, a
different beast. The Linux GPU-in-container landscape is fragmented (MIG,
SR-IOV, vGPU, time slicing) and Go-heavy (nvidia-container-toolkit, device
plugins).

## Decision Drivers

- A vendor-neutral, **Go-free** orchestrator surface.
- Keep the scope lean; do not preclude inference on accelerators, but do not
  build it now.
- Hardware isolation in a regulated multi-tenant context.
- A clean regulatory boundary (model governance/the AI Act stays with the model,
  not with the orchestrator).

## Decision

### Device access through CDI (the Container Device Interface)

- **CDI** (an OCI spec) is the seam: a JSON/YAML file describes device nodes,
  mounts, env and cgroup rules. The `orch-agent` **consumes** the CDI spec and
  injects it into the `config.json` it generates (ADR-0003) — **no** dependence
  on youki's native CDI support, **no** Go runtime.
- **Generating the CDI spec** (NVML introspection or similar) is a node
  provisioning task (vendor tooling at provisioning time is fine, just not in the
  orchestrator's runtime codebase — like installing a driver).
- **The division of labour as CDI prescribes it:** CDI = device exposure (node),
  **the scheduler = resource management**. The scheduler (ADR-0011) gets a
  **generic `device` resource type**: nodes announce available devices (from the
  CDI inventory), workloads declare their device demand (declarative-explicit,
  consistent with 0011), the scheduler places accordingly.
- **Partitioning lies below the CDI line:** whether a "device" is an SR-IOV VF, a
  MIG instance or a whole GPU (full passthrough/VFIO) is a node/vendor detail
  that the CDI spec describes — **not** wired into the orchestrator.
- **Hardware partitioning preferred** (SR-IOV/MIG/passthrough with an IOMMU =
  real isolation). **Time slicing/MPS is avoided** (no hard isolation →
  starvation/side channel) — not admissible in a regulated multi-tenant setting.
- **Inference workloads** are stateless (weights RO from 0027/S3) → failover like
  any stateless replica, the device is re-attached on the new node via CDI.

### Generality (a bonus)

The CDI seam is not GPU-specific — the same pattern exposes FPGAs, SmartNICs or,
prospectively, **HSMs** (relevant to the threshold CA, 0014, as an alternative to
PKCS#11 in-process). The resource type stays generic.

### Explicitly OUT of scope

- **Model training** (gang scheduling contradicts 0011; RDMA/NVLink kernel bypass
  contradicts 0012) → an external training platform.
- **Model governance / AI Act obligations** → these stay with the external
  model/system.
- **Time-slicing/MPS sharing** → no hard isolation.
- ~~This capability is **deferred**: the seam is defined but not implemented in
  the early build phases.~~ **Built: ADR-0143.** It was the last deferred ADR in
  this tree.

## Consequences

**Positive**
- A vendor-neutral, Go-free surface; the vendor fuzziness stays **below** the CDI
  line.
- Accelerator inference later without a redesign; the scheduler extension is a
  **generic** device resource type (reusable for FPGA/NIC/HSM).
- A clean regulatory boundary (models external).

**Negative / Costs**
- Dependent on vendor CDI spec generation at provisioning time (vendor tooling,
  possibly Go, but outside the runtime codebase).
- Proprietary kernel drivers (e.g. NVIDIA) are unavoidable with their GPUs — a
  kernel/vendor dependency, not a codebase dependency.
- The hardware partitioning obligation (no time slicing) limits density in
  multi-tenant setups.

**Risks & Open Points**
- ~~Finally verify youki's CDI handling vs. agent-injected-into-config.json.~~
  **Measured (ADR-0143): youki 0.7.0 does not know CDI.** Agent injection is
  therefore not the better choice but the only one — this ADR's path was right
  as a precaution.
- ~~Device inventory and health reporting (actual status, ADR-0004): how nodes
  announce devices.~~ **Decided and built (ADR-0143, decision 5):** as an
  entirely ordinary resource `device:<kind>` over the path from ADR-0049 — the
  node reports, a policy decides, the leader writes. The scheduler gets **not a
  line** for it, because ADR-0034 and ADR-0109 made it generic; that is this
  ADR's promise, redeemed. A separate *health reporting* per device is thereby
  moot: a device that disappears from the inventory **is** reduced capacity.
  Probing the device itself is vendor tooling and lies below the CDI line.
- **The finding the build produced and this ADR did not know:** CDI's
  `permissions` is, per the specification, a **cgroup** permission, and in
  cgroup v2 the controller for that is eBPF and ruled out by invariant 1
  (ADR-0090). A spec-conformant CDI injection would therefore produce something
  here that this tree cannot enforce. ADR-0143 decision 2 turns it into the
  **file mode**; the barrier is the presence of the node, and it holds because
  `CAP_MKNOD` is absent. The sentence in `bundle.rs` that predicted this since
  ADR-0090 is thereby redeemed.
- ~~The device capacity model couples to the open resource/capacity point in
  ADR-0011.~~ — **done:** ADR-0034 and ADR-0109 — the resource map carries
  `device`.

## Related ADRs

- config.json injection: ADR-0003. Scheduler resource type/capacity: ADR-0011.
- Weights as RO/S3 data: ADR-0027. The training/RDMA exclusion is justified in: ADR-0012.
- Stateless inference failover: ADR-0019. The device seam as an HSM option: ADR-0014.
