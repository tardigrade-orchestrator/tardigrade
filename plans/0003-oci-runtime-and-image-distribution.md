# ADR-0003: OCI Runtime and Image Distribution

- **Status:** accepted — youki first, crun as fallback
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

The orchestrator has to actually start containers (OCI runtime level) and
fetch/unpack images (distribution level). The de-facto stack (containerd +
runc) is Go/C — which collides with "pure Rust". To be decided: what runs the
containers, and how images reach the node.

## Decision Drivers

- Pure Rust in the control logic.
- Conformance to the OCI runtime spec and image spec (compatibility with existing images).
- Rootless operation should be possible (see ops ADR, proposed).
- We do **not** want to pull in a containerd daemon as a dependency.

## Options Considered

**Runtime level**
- **youki** (Rust, OCI runtime spec) — 0.6.0 (Feb 2026), passed containerd's e2e
  tests, first production use. `oci-spec-rs` supplies the types.
- **crun** (C, small, fast) — not Rust, but very stable; drivable through the OCI CLI.
- **runc** (Go) — the reference, but Go.

**Distribution level (image pull/store)**
- **Our own Rust registry client** (`oci-client`/`oci-distribution`, `ocipkg`) plus our
  own content store (layers as tar+gzip/zstd, CAS over sha256).
- **containerd as the store** — a Go daemon, rejected for purity plus the extra daemon.
- **Calling skopeo/umoci** — external CLIs, not Rust.

## Decision

Chosen: (the crun fallback is confirmed — a C binary driven through the OCI CLI,
no Go, permissible under the FFI/C rule.)

- **Runtime:** `youki` as an embedded library/invocation through the OCI CLI interface;
  the agent generates `config.json` from the (XSD-generated) definition.
  - `crun` remains a configurable fallback runtime (the OCI CLI is interchangeable),
    so that gaps in youki do not block us.
- **Spec types:** `oci-spec-rs`.
- **Distribution:** our own Rust puller on top of an OCI distribution client crate,
  a content-addressed store under `/var/lib/tardigrade/content` (sha256), snapshots
  via overlayfs (a kernel feature, no eBPF).

## Consequences

**Positive**
- No Go daemon, no containerd operational overhead.
- youki is close to the syscall layer in Rust and rootless-capable (cgroup v2, seccomp).

**Negative / Costs**
- Our own content store plus GC is real implementation effort (containerd takes a
  lot of this off your hands).
- youki is less mature than runc: we carry runtime bugs ourselves → hence the crun fallback.
- Rootless overlayfs requires a current kernel / suitable mount options.

**Risks & Open Points**
- ~~Image GC, layer dedup, pull auth (registry credentials → see the secrets ADR,
  proposed).~~ — **all three done.** Pull auth: **ADR-0096** (and **ADR-0125**
  for the spelling and for deletion). Layer dedup: never was an open question —
  the store is content-addressed, identical layers lie there once anyway.
  **Image GC: ADR-0126**, the oldest open point in this tree. Measured, the
  store grew linearly and never shrank (five tags of a 5 MB layer: 52.6 MB),
  and **half** of that was a `blobs/` directory that nothing reads on the
  production path and that saves no pull. From there on the blob is **verified,
  not retained**; the rest the reconciler reaps as the second direction of the
  same reconciliation (ADR-0058), with three guards that cost only deferral.
- ~~The `libseccomp` FFI dependency (from ADR-0002).~~ — **done:** ADR-0090 —
  the profile is our own code (`tg_runtime::seccomp`), `libseccomp` is not in
  the tree.

## Related ADRs

- Depends on: ADR-0002.
- Affects: ADR-0008 (definition → config.json mapping).
