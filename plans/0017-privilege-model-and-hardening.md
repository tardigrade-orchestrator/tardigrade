# ADR-0017: Privilege Model & Workload Hardening

- **Status:** accepted — a privileged agent, hardened unprivileged workloads, hardening on by default
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

The kernel datapath (ADR-0012) and cgroups/namespaces (ADR-0003) require a
**privileged** `tg-agent`. "Rootless" can therefore only refer to the
**workloads**. To be settled: the privilege model and the hardening default for
workloads.

## Decision

### The privilege model

- **`tg-agent` runs privileged** (infrastructure: netlink, nftables, cgroups,
  namespaces). Unavoidable with the chosen datapath (0012).
- **Workloads run hardened and unprivileged:** user namespaces (uid/gid
  mapping), dropped capabilities (default: none/minimal), `no_new_privs`,
  cgroup v2 (limits plus delegation), a read-only rootfs where possible.
- **Full rootless rejected** (an unprivileged agent → the pasta datapath → a
  contradiction with 0012).

### The hardening default: on

- **User namespaces, seccomp default-deny and `no_new_privs` active by default.**
- Relaxations only **explicitly per workload** in the definition (ADR-0008) —
  every relaxation is a deliberate, **audited** decision (ADR-0020) → DORA.
- seccomp: a default-deny profile (allowlist), `libseccomp` via FFI (accepted,
  encapsulated in `tg-syscall`, ADR-0002).

## Consequences

**Positive**
- Least privilege as the default; strong workload isolation.
- Every loosening is explicit and visible in the audit trail.

**Negative / Costs**
- Images that need exotic syscalls create friction → an explicit opt-out is
  required.
- User namespaces bring complexity around file/volume ownership (uid mapping).

**Risks & Open Points**
- ~~Maintaining the seccomp default profile (which syscalls go in the allowlist).~~
  — **done:** ADR-0090 — a denylist instead of an allowlist.
- ~~The userns ↔ volume ownership strategy.~~ — **done:** ADR-0091 — a fixed
  mapping per node, `chown`.
- Governance of the per-workload relaxations (a review obligation).

## Related ADRs

- The agent privilege comes from: ADR-0012, ADR-0003. Hardening flags in: ADR-0008.
- The FFI boundary (libseccomp): ADR-0002. Audit of the relaxations: ADR-0020.
