# ADR-0033: Time and determinism in the DST harness, and the latency limit of replication

- **Status:** accepted — adopted on 2026-09-07; the three decisions are built
  and in force. What stays open is a **measurement** per installation, recorded
  under "Risks & Open Points".
- **Date:** 2026-08-21
- **Deciders:** Core team
- **Technical context:** `tests/dst/`, `tg-consensus`, `tgd`
- **Closes the open points from:** ADR-0032

## Context and Problem Statement

ADR-0032 chose our own in-process bus for the deterministic simulation tests and
explicitly left one point open:

> "Simulating clock skew deterministically requires control over the time
> `openraft` sees. Whether `tokio::time::pause` suffices or a time source has to
> be injected is to be clarified in 5b."

Phase 5b built the harness and answered the question — and in doing so exposed
two properties of `openraft` 0.9.25 that were not previously known and that
reach beyond the harness into operations. Per ADR-0020 a DST run is exportable
evidence; it is that only if it can be reconstructed completely from its seed.
That is precisely what the following decisions hang on.

## Decision Drivers

- **Reproducibility** of a run from its seed (ADR-0020, the DORA
  resilience-testing obligation).
- **No rebuilding of production code for the harness.** The bus is a harness
  (ADR-0023: it lies in no shipped binary); a simulation seam cutting through
  `tg-consensus` would be the most expensive way to get it.
- **Honesty about the harness's limits.** A green run must not claim more than
  it checked — otherwise the evidence is worthless.
- **Operability across failure domains** (ADR-0031: five nodes across at least
  three domains).

## Finding 1: `openraft` draws election timeouts from unseeded randomness

`Config::new_rand_election_timeout` draws from `AsyncRuntime::thread_rng()` —
with `TokioRuntime`, that is `rand::thread_rng()`. The value is therefore
neither seeded nor reachable from outside. Without a countermeasure every run
elects differently, and a seed reproduces nothing.

### Options Considered

- **A: our own `AsyncRuntime` with a seeded generator.** `AsyncRuntime` exposes
  `ThreadLocalRng` as an associated type — technically the clean path. Cost: the
  time configuration sits in `RaftTypeConfig`, so the harness would need a second
  `TypeConfig` — and with it `LogStore` and `StateMachine` from phase 5a would
  have to become generic over the type configuration. A rebuild of the consensus
  core for the harness.
- **B: fix the election timeouts instead of drawing them.** `gen_range(min..max)`
  with `max = min + 1` has exactly one possible value. The unseeded generator is
  thereby made ineffective without being replaced. So that not all nodes stand
  for election at once and jam on split votes, each node gets an offset of its
  own.
- **C: accept the nondeterminism** and seed only the fault plan.

### Decision

Chosen: **Option B.** It achieves determinism completely and leaves
`tg-consensus` untouched. The randomness is not seeded but **replaced by an
order** — node 1 stands first, node 5 last.

Option A stays the path should a scenario later need real election randomness
(e.g. "does simultaneous candidacy lead to an endless loop?"). Then the price of
a generic storage layer has to be paid — and the DST suite from 5b backs that
rebuild.

**Important:** this applies to the **harness**. In production (from 5c) the
randomness stays in the election timeouts where it belongs — there it is the
Raft protocol's split-vote avoidance, not a disturbance.

## Finding 2: The virtual clock is global — real monotonic skew cannot be represented

The question from ADR-0032 is answered: **`tokio::time::pause` suffices for
time, but not for skew.** The virtual clock applies process-wide; `openraft`'s
`AsyncRuntime` is a type **without instance state**, and on a `current_thread`
runtime all five nodes share the same thread. There is no place where node 3
could see a different monotonic time than node 4, short of taking option A from
finding 1.

### Decision

Clock skew is simulated **where ADR-0024 locates it**: in the traceable UTC that
travels in the commands (`GrantLease`, `RenewLease`). That is not a makeshift
but the half relevant to this system — ADR-0024 separates the two time sources
explicitly, and ADR-0004 fixes that the UTC stands **in the log**. The
comparison `now >= expires_at` is thereby part of the replicated command and not
of the environment; five requests with five different clock readings produce the
same result on all nodes.

The monotonic side is **approximated**: through per-node offset election
timeouts and through asymmetric latencies in the bus. A node whose messages
systematically arrive later behaves, for the election, like one whose clock runs
slow.

**The limit is borne and documented explicitly** — in the module header of
`tg_dst`, in `tests/dst/README.md` and in the scenario itself. What the harness
does not check, it must not implicitly claim.

## Finding 3: Replication over a link slower than `heartbeat_interval` never happens

The harness found a case that is not simulated but **measured**: in
`replication/mod.rs` `openraft` sets the timeout of the `append_entries` call to
`Config::heartbeat_interval`:

```rust
let the_timeout = Duration::from_millis(self.config.heartbeat_interval);
let res = C::timeout(the_timeout, self.network.append_entries(payload, option)).await;
```

A link whose latency lies above that times out on **every** attempt before the
answer arrives. In the run, the affected node stayed permanently at log index 3
while the others stood at 8. It does not fail in doing so, reports no error and
is listed as dead by no metric — the remaining four hold the quorum, and the
cluster looks healthy.

`Config::validate` only checks `election_timeout_min > heartbeat_interval`.
Nobody checks the relation to the **network latency**.

That hits ADR-0031 directly: the five nodes are distributed across at least
three independent failure domains. With `openraft`'s default of 50 ms, any
domain whose latency lies above that is structurally cut off — and silently so.

### Decision

The ordering holds

```
RTT(p99, between the failure domains)  <  heartbeat_interval  <  election_timeout_min
```

with a clear margin in both steps (Raft spec §5.6:
`broadcastTime ≪ electionTimeout ≪ MTBF`). Concretely:

1. **`heartbeat_interval` ≥ 3 × RTT(p99)** of the slowest link between two
   quorum nodes. The latency is to be **measured**, not estimated; the
   measurement belongs to the cluster's commissioning.
2. **`election_timeout_min` ≥ 3 × `heartbeat_interval`**, `election_timeout_max`
   = 2 × `min` (the random range that is preserved in production).
3. The chosen values are documented **together with the measured latency**. A
   value without the measurement it rests on is not justifiable in the audit
   trail (ADR-0020).

**A starting profile, to be confirmed in phase 5c from a real measurement:** for
a cluster across halls of the same site (latency in the sub-millisecond range),
`heartbeat_interval = 100 ms`, `election_timeout_min = 500 ms`,
`election_timeout_max = 1000 ms` are amply dimensioned. Across sites the profile
is to be recomputed from the measurement.

The cost is low, because the **workloads'** failover behaviour does not hang on
the election but on the lease epoch (ADR-0010, ADR-0014: lease 15 s). An
election that now needs 500–1000 ms instead of 300 ms shifts the control plane's
ability to act by hundreds of milliseconds — not the availability of the
workloads (ADR-0019).

## Consequences

**Positive**
- A seed reproduces a DST run completely; 250 seeds across twelve scenarios
  (3000 cluster runs) execute in about 30 seconds, because time is virtual. That
  makes the sweep something one actually runs.
- `tg-consensus` stays untouched by the harness.
- A silent misconfiguration with operational effect was found **before** there is
  a real network — exactly the order ADR-0005 demands ("test the
  storage/network trait impls early and in isolation").

**Negative / Costs**
- The harness cannot do a per-node shifted monotonic clock. Scenarios that
  depend on it (e.g. a node with a stopped clock standing for election
  constantly) cannot be represented with it.
- The election timeouts in the harness are fixed; a scenario about simultaneous
  candidacy is therefore not available.
- Operations gains a commissioning obligation: the latency between the domains
  is to be measured and documented.

### Why `accepted` (addendum 2026-09-07)

The status stood at `proposed` for over a year, with the note "open: the
concrete time values, to be confirmed in phase 5c". That phase has long been
finished, and the code has followed this decision since the day it was drafted —
verified in three places:

- **The time profile is the default.** `tgd` starts with a 100 ms heartbeat and
  500/1000 ms election timeouts.
- **The ordering condition is enforced at startup**, not merely recommended:
  `Timing::to_config` rejects `heartbeat = 0`, `election_min < 3 × heartbeat` and
  `election_max <= election_min` with a reference to this ADR.
- **And it has become measurable.** The watcher that this document delegates to
  ADR-0015 below exists: `tg_raft_rpc_seconds{quantile="0.99"}` against
  `tg_raft_rpc_deadline_seconds / 3`, with an alerting rule.

A `proposed` on a decision that is enforced and monitored is itself a drift: a
reader consulting the index (invariant 6) takes the whole determination to be
provisional — including the condition on which `tgd` aborts its startup. What is
open is not the decision but **one number per installation**, and that belongs
in the section below.

**Risks & Open Points**
- The starting profile is justified but **not measured**. `RTT(p99)` between the
  failure domains is a property of the installation; whoever knows it checks the
  profile against it and raises it if the link demands it. The metric for that
  exists (see above), the measurement is operational work.
- If `heartbeat_interval` stays coupled to the RPC timeout, the heartbeat
  frequency is no longer freely choosable: it is simultaneously replication's
  patience. Whether that is separated in `openraft` 0.10 belongs to the
  assessment of the migration due there anyway (ADR-0032).
- ~~A watcher that checks the actual latency against `heartbeat_interval` and
  raises an alarm belongs to ADR-0015 (observability) — not decided here.~~ —
  **done:** `docs/alerts.yml`, rule `TardigradeReplicationTooSlow`.

## Related ADRs

- Closes the open points from: ADR-0032.
- Applies: ADR-0024 (separation of the time sources), ADR-0004 (UTC in the log).
- Affects: ADR-0031 (latency between the failure domains as a configuration
  limit), ADR-0015 (a watcher over the latency), phase 5c.
- Serves: ADR-0020 (reproducible runs as evidence).
