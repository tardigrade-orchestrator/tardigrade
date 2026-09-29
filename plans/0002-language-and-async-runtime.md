# ADR-0002: Language, Async Runtime and Process Model

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

The orchestrator is fixed as "pure Rust". What remains to be settled is which
async runtime, which IPC/RPC stack and which process model (control plane vs.
node agent) carry the rest of the architecture.

## Decision Drivers

- Pure Rust, no C core dependencies in the control logic (FFI only where
  unavoidable, e.g. libseccomp — then isolated and documented).
- Must work close to the syscall layer (namespaces, cgroups, netlink) → a good
  `nix`/`rustix` ecosystem.
- gRPC-capable for control plane ↔ agent, compatible with rustls mTLS (see ADR-0007).

## Options Considered

- **tokio + tonic + rustls** — the de-facto standard, largest ecosystem, tonic speaks gRPC natively.
- **async-std / smol** — leaner, but a smaller ecosystem and weaker tonic binding.
- **No async (thread per task)** — mentally simpler, scales poorly with many watches/streams.

## Decision

Chosen:

- **Runtime:** `tokio` (multi-thread).
- **RPC:** `tonic` (gRPC) for control plane ↔ agent and CLI ↔ API.
- **TLS:** `rustls` (no OpenSSL) — this later carries the SPIFFE mTLS verification.
- **Syscalls:** `rustix` preferred, `nix` where needed.
- **Process model:** a clear separation
  - `tgd` (control plane: API, scheduler, reconciler, consensus node)
  - `tg-agent` (per node: talks to the OCI runtime, cgroups, network, local SVID issuance)
  - `tgctl` (CLI)
- **MSRV:** current stable, with a documented N-2 policy. `#![forbid(unsafe_code)]`
  in every crate except the thin syscall wrapper crates.

## Consequences

**Positive**
- Largest ecosystem (youki, openraft, the surrealdb client, rustls and tonic all speak tokio).
- gRPC streams fit watch/reconcile semantics naturally.

**Negative / Costs**
- tokio ties the entire codebase to one runtime model.
- The `libseccomp` FFI is accepted (C FFI within narrow, isolated bounds; no Go).
  Encapsulated in `tg-syscall`. Alternative if needed: build the seccomp BPF
  program directly (more effort; noted as proposed).

## Related ADRs

- Affects: ADR-0003, ADR-0005, ADR-0007.

---
_Addendum (REMIT/DORA context, 4-9/5-9 — see ADR-0019):_ "tokio everywhere"
applies to the **control plane**. For the **data plane** (sidecar proxy,
ADR-0007) with hard tail-latency targets, a thread-per-core model pays off.
→ **decided in ADR-0022: tokio thread-per-core** for `tg-proxy` (no dedicated
io_uring runtime such as monoio/glommio); the control plane stays tokio
multi-thread.
