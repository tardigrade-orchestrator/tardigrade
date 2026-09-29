# ADR-0012: Container Networking (userspace control, kernel datapath, no eBPF)

- **Status:** accepted — veth/bridge/nftables; a **kernel WireGuard full mesh** across all nodes
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

The requirement "entirely in userspace, no eBPF" is clarified as: **control and
configuration in userspace, the datapath over standard kernel networking** — no
eBPF, no kernel modules, but no userspace packet copying either (pasta/slirp was
rejected for latency). Between the nodes a **kernel WireGuard full mesh** is
laid (zero trust towards the local network as well).

## Decision Drivers

- No eBPF, no programmable kernel datapath.
- Low latency/tail (in-kernel forwarding, no userspace datapath) — 4-9/5-9.
- Pure-Rust control through netlink (the datapath stays a kernel feature).
- Zero trust towards the local network too → a uniformly encrypted,
  node-authenticated underlay everywhere, not only across site boundaries.

## Decision

### Datapath (per node, in-kernel)

- A **veth pair** per container in its own netns; a **Linux bridge** per node;
  **nftables** for NAT, filtering and the sidecar redirect (ADR-0007).
- Configured from `tg-agent` through **netlink** (`rtnetlink`) and the nftables
  netlink binding (C FFI accepted within narrow bounds, encapsulated).
- Reference/possible basis: **netavark** (Podman's Rust network stack).
- **No eBPF, no kernel modules.**

### Sidecar interception

Traffic is redirected to the local mTLS sidecar via an **nftables redirect** in
the netns (ADR-0007) — pure netfilter, no BPF.

### The node underlay: a kernel WireGuard full mesh

- **WireGuard between all nodes**, independent of the subnet — one uniform,
  encrypted, node-authenticated underlay. The WireGuard overlay therefore **is**
  the flat L3; the physical underlay does **not** have to route the container
  subnets (which simplifies provisioning).
- **Kernel WireGuard** (native since Linux 5.6), **not boringtun** — this keeps
  the datapath in-kernel and preserves the datapath's latency decision. The
  `tg-agent` only configures peers/keys through netlink (the same pattern as
  bridge/nftables; a kernel feature, no Go). boringtun remains a fallback for
  kernels without native WG support.
- **Layer separation (not redundancy):** WireGuard authenticates **nodes** (peer
  keys) and encrypts the underlay; mTLS (ADR-0007) authenticates **workload
  identities** (SPIFFE) and carries the `may_talk` authorization (ADR-0025). The
  only duplication is **payload encryption** — a deliberate defence-in-depth
  price, plus metadata protection (peer/traffic patterns) on the wire.
- **Peer/key distribution:** WireGuard node keys and peer lists are desired state
  (Raft/SurrealDB, ADR-0004); a joining node gets its mesh configured after node
  attestation (ADR-0006). The existing mesh survives control-plane outages
  (local config, ADR-0019); only new peers need the control plane.

### IPAM

Deterministic IP assignment out of node subnets, derived from topology/desired
state (ADR-0004/0011). The **MTU** is reduced by the WireGuard overhead (~60 B →
e.g. 1420) to avoid fragmentation.

## Consequences

**Positive**
- Low latency (in-kernel forwarding plus kernel WireGuard), no eBPF.
- Pure-Rust control; netavark-like.
- A uniform, encrypted, node-authenticated underlay **everywhere** — zero trust
  towards the local network as well; metadata protection on the wire.
- No reliance on a routed underlay (WireGuard *is* the flat L3) → simpler
  provisioning; a consistent model with no per-site special cases.
- Node authentication (peer keys) as its own layer beneath the SPIFFE workload
  identity.

**Negative / Costs**
- The kernel bridge/veth needs privileges/capabilities → **tension with rootless
  (ADR-0017)**, resolved there (a privileged agent).
- WireGuard per hop: crypto overhead (small, ChaCha20-Poly1305 in-kernel, but not
  zero at a 5-9 tail); **double payload encryption** (WG plus mTLS) as a
  deliberate defence-in-depth price.
- **An MTU reduction** is needed for the WG overhead (~60 B), otherwise fragmentation.
- **A full mesh is O(N²)** in peer administration → large clusters need a peer
  management strategy.
- nftables rules can explode with many workloads/policies → a clean **nftables
  sets/maps design** instead of individual rules.

**Risks & Open Points**
- ~~WireGuard key rotation and peer distribution (through the control
  plane/desired state).~~ — **done:** ADR-0039 (peers) and ADR-0055 (rotation).
- O(N²) peer scaling in large clusters.
- MTU/path-MTU handling end to end.
- nftables scaling (sets/maps, rule generation from the graph).

## Related ADRs

- Sidecar redirect: ADR-0007. The netlink/FFI boundary: ADR-0002 (`tg-syscall`).
- Resolved with: ADR-0017 (rootless). Service discovery: ADR-0013.
- WG peer keys as desired state: ADR-0004; node attestation: ADR-0006.
- The mesh underpins failure domains: ADR-0011/0019.
