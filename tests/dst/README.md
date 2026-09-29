# tests/dst/

Deterministic Simulation Tests (ADR-0005, ADR-0019, ADR-0032).

Five nodes in one process, real `redb` storage from phase 5a, an in-process bus
as `RaftNetwork` with injectable partition, delay, reordering and loss.

## Calls

```bash
cargo test -p tg-dst                  # part of the Definition of Done, few seeds
cargo xtask dst                       # a broad sweep (default: 32 seeds per scenario)
cargo xtask dst --report evidence.txt # the sweep **and** the evidence per ADR-0020
TG_DST_SEEDS=250 cargo test -p tg-dst # a sweep by hand
TG_DST_SEED=98706598451883118 \
  cargo test -p tg-dst                # reproduce a reported run
```

The seeds are **fixed**, not fresh -- unlike the fuzz runs in `tg-defs` and
`tg-consensus`. A DST run is a regression check: it must be green again tomorrow
and, if it turns red, stay red from the same seed (ADR-0020).

## The three sources of the determinism

1. **The fault plan** is a pure function of seed, path and message number -- no
   shared random generator, so that the verdict about a message does not hang on
   the executor's task order.
2. **The time** is virtual (`tokio::time::pause`). 250 seeds over twelve
   scenarios -- 3000 cluster runs -- cost about 30 seconds.
3. **The election timeouts** are fixed per node instead of rolled. `openraft`
   draws them from `rand::thread_rng()`, unseeded; with
   `election_timeout_max = min + 1` the drawn value is determined, and the
   offset between the nodes prevents split votes.

## What the test rig cannot do

`tokio`'s virtual clock is **global**. A monotonic clock offset per node is
therefore not representable: `openraft`'s `AsyncRuntime` is a type without
instance state, and on a `current_thread` runtime all the nodes share the same
thread. Clock skew is therefore simulated where ADR-0024 locates it -- in the
traceable UTC that travels **in the command** -- and approximated on the
monotonic side by offset election timeouts and asymmetric latencies.

## Findings

**Replication over a path slower than `heartbeat_interval` never comes about.**
`openraft` sets the timeout of the `append_entries` call to
`Config::heartbeat_interval` in `replication/mod.rs`. A one-way latency above it
means that every attempt expires before the answer is there: the node does not
fail, it merely never catches up again -- and that quietly, because the other
four hold the quorum.

ADR-0031 distributes the five nodes over at least three failure domains. Before
phase 5c it is therefore to be decided how `heartbeat_interval` stands to the
latency between the domains. Recorded in
`a_link_slower_than_the_heartbeat_never_replicates`.

**The leader does not step down at quorum loss.** `openraft` lets it run
(`raft_state/mod.rs`: "the leader just run as long as it wants to"). That is
correct -- a cut-off leader is harmless as long as it can commit nothing. The
scenarios therefore check the **mutation**, not the opinion: what was attempted
on the minority side afterwards stands in none of the five state machines.

## Scenarios

- `tests/faults.rs` -- the injector itself (phase 5b).
- `tests/bus.rs` -- the bus in operation: does it really lose when it should?
- `tests/scenarios.rs` -- partition, the quorum boundary, reorder, clock skew,
  node loss, reproducibility (phase 5b).
- `tests/membership.rs` -- a membership change under message loss, catching up
  via a snapshot, and: without a quorum no change (phase 5d).
  The snapshot path is forced -- the log is truncated until the next entry of
  the one catching up is deleted. Without this truncation it would catch up over
  the log path, and the test would be green without having touched the path.

## What does not stand here yet

No real network -- that is phase 5c and stands in `crates/tgd/tests/`. The bus
stays the test rig: it checks the correctness, the real network the integration.

## The evidence (ADR-0020, phase 11c)

`--report` writes the report the DORA resilience testing obligation demands:
**seed, scenario, verdict.** Three properties make it an artifact and not a log:

1. **It records the real run instead of rebuilding it.** A list of scenarios in
   the generator would be a second source -- and the second place is the one one
   forgets when adding. A report that does not know a scenario does not report
   it as failed; it reports nothing at all, and that looks like success.
2. **It is sealed** -- with the same hash chain as the audit trail from phase 11a
   (`tg_telemetry::audit`), not with a second one. A verifier learns one
   procedure and applies it to both. The seeds hang **in** the chain: if they
   stood beside it, they could be swapped without the chain breaking.
3. **It contains no run times.** The assurance reads "the same seed produces the
   same report"; a millisecond of difference would turn it into an artifact that
   never looks the same twice.

The report arises **on a failure too** -- then it is all the more what a verifier
wants to see. The error status is passed through nevertheless.
