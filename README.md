# Tardigrade

A container orchestrator for Linux, in Rust, without foreign daemons — built for
REMIT/DORA-regulated environments with a target workload availability of 4-9 to
5-9.

Three binaries — `tgd` (control plane), `tg-agent` (per node), `tgctl` (CLI) —
plus `tg-proxy`, the data plane's sidecar.

## What defines it

- **Static stability** (ADR-0019, the keystone): workload availability is
  decoupled from the control plane. A quorum loss stops no running container.
- **Zero trust without eBPF:** SPIFFE identity per container, mTLS in the
  sidecar, container networking via veth, nftables and WireGuard in userspace
  (ADR-0006, ADR-0007, ADR-0012).
- **Tamper-evident audit trail:** the Raft log is the WORM substrate, and the
  archive arises in the apply path, before a compaction can strike (ADR-0020).
- **Pure Rust:** no Go, no Kubernetes. `#![forbid(unsafe_code)]` in every crate
  except `tg-syscall`, the thin syscall edge.

## Where to find what

| What | Where |
|---|---|
| This project's constitution | `CLAUDE.md` |
| The architecture decisions | `plans/`, index in `plans/README.md` |
| The build plan with the phases | `plans/PLAN.md` |
| The build journal | `plans/journal/2026-build.md` |
| The operations manual | `docs/OPERATIONS.md` |
| The bill of materials of the delivery | `docs/sbom.cdx.json` |

The ADRs are the truth: an accepted decision is changed with a new ADR, not by
silent code drift.

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

## Licence

Copyright 2026 Dana Schlifka, under the Apache License 2.0 (ADR-0139). The text
lies as `LICENSE` in the root, the notice as `COPYRIGHT`. The foreign components
stand under their own licences; which those are is said by the bill of
materials.
