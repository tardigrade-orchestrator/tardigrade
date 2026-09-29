# ADR-0022: Data-Plane Runtime & Latency Determinism

- **Status:** accepted — tokio thread-per-core for the proxy; **measured in
  ADR-0114**: no tail difference, `io_uring` rejected, pinning a setting
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

ADR-0002 fixed tokio (multi-thread) for the control plane, but flagged the data
plane (the sidecar proxy, ADR-0007) with its hard tail-latency targets as a
possible special case. To be decided: the runtime for `tg-proxy`.

## Decision Drivers

- Tail latency (4-9/5-9) on the mTLS data path.
- Staying inside the audited **tokio+rustls ecosystem** (reusing the mTLS glue).
- No dependence on a weakly maintained runtime for the security-critical data
  plane.

## Decision

Chosen: **tokio in a thread-per-core model** (one current-thread runtime per
core, pinned) for `tg-proxy`. The control plane stays tokio multi-thread.

Rationale (supported by research):
- Thread-per-core delivers a real ~1.5–2× tail/throughput advantage over work
  stealing; the sidecar is the classic per-connection shardable case.
- Dedicated io_uring runtimes (monoio/glommio) lag on io_uring feature parity,
  are unevenly maintained, use unstable Rust features and a new IO abstraction
  (the rustls glue cannot be reused) — too risky for a security-critical,
  long-lived component.
- tokio thread-per-core captures most of the locality/tail gain without leaving
  the ecosystem.

~~**Upgrade path:** dedicated io_uring (monoio/glommio) only **benchmark-driven**,
should measurements show that the tail really needs it.~~ — **measured and
rejected: ADR-0114 decision 2.** The condition has been checked and is not met;
it is only reopened by a measurement on a real NIC on target hardware.

**Two sentences above hold differently since ADR-0114**, and they stand here
unchanged because an ADR is not rewritten (invariant 6):

- "one current-thread runtime per core, **pinned**" — pinning is, since
  **ADR-0114 decision 3**, an explicit per-node setting defaulting to **off**,
  not part of the decision.
- "thread-per-core delivers a real ~1.5–2× tail/throughput advantage" — **not
  reproducible** in this tree (ADR-0114, finding 1). The choice stands; from
  here on its rationale rests on the remaining arguments.

## Consequences

**Positive**
- A tail gain without breaking the ecosystem; the rustls/tonic glue stays usable.
- No dependence on an immature, security-critical runtime.

**Negative / Costs**
- Two runtime configurations (multi-thread control plane vs. thread-per-core
  proxy) — to be documented deliberately.
- Thread-per-core requires a connection sharding strategy across the cores and
  more manual setup than the default.

**Risks & Open Points**
- ~~Fix the sharding strategy (connections ↔ cores).~~ — **done:** 8b —
  `SO_REUSEPORT` per shard.
- ~~A benchmark that validates the tokio-tpc variant against the tail target (and
  either triggers or discards the io_uring upgrade path).~~ — **done: ADR-0114**,
  built as `cargo xtask bench`. It **discarded** the upgrade path.

## Related ADRs

- Refines: ADR-0002 (runtime). Concerns: ADR-0007 (the sidecar proxy).
- **Changed by: ADR-0114** — the measurement this ADR called for.
