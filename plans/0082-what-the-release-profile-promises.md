# ADR-0082: What the release profile promises

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `Cargo.toml` (`[profile.release]`), `tg-proxy::runtime`,
  `tg-runtime::reconcile`, `tg-net::nft`, `tg-syscall`, ADR-0019, ADR-0022,
  ADR-0062

## Context and Problem Statement

This tree's tests run in the `dev` profile, what is shipped is `release`. Two
settings distinguish the two in a way that changes behaviour and not merely speed:
`panic = "abort"` and the absent `overflow-checks`. Both came with the scaffolding
from phase 0 and have **never been decided** — the template in
`.claude/rules/ai_cargo_toml_instructions.md` names as its justification "smaller
binary".

Measured, that means:

| | `dev` (the tests) | `release` (shipped) |
|---|---|---|
| a panic in a task | `JoinError::is_panic() == true`, **the process lives on** | **the process dies** |
| `1000u64 - 2000u64` | panic "attempt to subtract with overflow" | `18446744073709550616` |

The second row is the dangerous direction: a "free capacity" of 18 exabytes where a
deficit of 1000 stands.

The first concerns a property this tree **invokes** in six places — and in two of
them in writing. `tg-proxy::runtime` says verbatim when collecting the shards:

> A shard that panics does not take the process with it — the others carry on. That
> is the same stance as in ADR-0019: a partial failure is not a total failure.

And `tg-proxy::main` justifies an earlier correction by saying that "`tokio` catches
them, the `JoinError` was discarded". **Both are false in the shipped binary.** It is
the same family as the mitigation the Raft port invoked (ADR-0043) and as the
enumerated signature from ADR-0042: a comment that passes an intention off as a fact.

So the question stands that invariant 6 demands an ADR for: **what does the release
profile promise, and does it have to promise the same as the tests?**

## Decision Drivers

- **Static stability (ADR-0019).** A partial failure must not be a total failure; a
  node carries on as long as it can.
- **ADR-0062 decided the same case for a smaller cause:** an unreadable entry must not
  end the agent, because with it go the workload API socket (SVIDs carry 15 min), the
  resolver, the session and the restart of crashed instances.
- **A target availability of 4-9 to 5-9**, and the data plane runs four shards on
  `SO_REUSEPORT` (ADR-0022) — precisely so that a part can fail.
- **What an auditor sees (ADR-0020):** a silently wrapped number in the capacity or
  address path is a state nobody can reconstruct.
- **Size and speed** are real costs and the only justification the template names.

## Options Considered

- **Option A — everything stays.** `panic = "abort"`, no overflow check. Smallest
  binaries; a panicking process dies loudly, and a supervisor restarts it.
- **Option B — `panic = "unwind"`.** The panic stays with the task, the six handling
  paths come alive, the two comments become true.
- **Option C — B, plus `overflow-checks = true`.** The tests' arithmetic discipline
  applies when shipped too.
- **Option D — different per binary.** Measured **not available**: cargo answers
  "`panic` may not be specified in a `package` profile". For `overflow-checks` it
  would work (measured), for the panic strategy it does not.

## Decision

Chosen: **Option C.**

### Determination 1 — `panic = "unwind"`

A panic in a task costs the task, not the node. That is word for word the decision
from ADR-0062, only for a different cause — and there the trigger was a **single
file**, here it is a program bug in one of a dozen concurrent strands.

The deciding factor is the data plane: `tg-proxy` runs four shards so that a part can
fail (ADR-0022). With `abort` a panic in one shard takes the other three with it —
and with them every running mTLS connection of the workload. Since the setting cannot
be set per package (option D, measured), the binary with the strictest requirement
determines the value for all four.

**The objection to unwind stands and is answered.** An `abort` dies loudly, and a
supervisor restarts; a dead task leaves a process that **carries on degraded** — a
resolver that no longer answers looks from outside like one that answers. Precisely
against that 11b built the **watchdog** ("a loop that stands still does not report");
it covers three loops today: the reconciliation in the agent, the scheduler and the
Raft loop. That it does not cover all of them is the cost side and stands below; it
weighs less than a node that disappears entirely because of one concurrent strand.

### Determination 2 — `overflow-checks = true`

What the tests treat as an error the shipped binary treats as an error too. ADR-0069
already wrote this argument for **one** function:

> The overflow is refused and not wrapped — a node silently receiving another's
> subnet would be the worst possible outcome.

The profile turns that into the general rule. It is explicitly **no** substitute for
the discipline: the resource arithmetic saturates (`saturating_add`,
`saturating_sub`), the address plan checks before computing, and both stay that way.
The check catches what **nobody** foresaw — and turns it into a panic that, per
determination 1, costs its task and not the node.

Only that order makes it bearable: without unwind every arithmetic bug would be a
dead node.

### Determination 3 — the panic strategy is guarded at compile time

`cfg(panic = "abort")` is stable, so a `compile_error!` catches the regression
**where the setting applies**: a release build with `abort` fails and names this ADR.
In the `dev` profile the guard is silent, because `unwind` is the default there.

It lies in `tg-syscall`, because the profile applies workspace-wide (one compilation
unit suffices), because all four binaries link it (measured) and because the other
invariant guards live there.

**For `overflow-checks` this path does not exist:** `cfg(overflow_checks)` is
`E0658`, i.e. nightly. There only a guard that reads the manifest remains — and it is
necessary, because the default in the release profile is `false`: a deleted line
silently switches the check off. With the panic strategy it is the other way round —
the default is `unwind`, only the explicit value is dangerous, and the compiler
catches that.

## Consequences

**Positive**

- A partial failure stays a partial failure (ADR-0019), in the shipped binary too.
- Six handling paths for a foreign thread's panic are no longer dead; two comments
  that passed an intention off as a fact are true.
- Poisoned locks arise at all — the two places that handle them (`tg-agent::network`
  and `tg-telemetry::probes`) are thereby reachable.
- A wrapped number in the capacity, address or lease path becomes a finding instead of
  a state.
- What the tests check holds when shipped. That was the real gap.

**Negative / Costs**

- **Measured +11.5 % binary size** from unwind (43.8 MB → 48.8 MB across all four),
  plus **+0.4 %** from the overflow check (→ 49.2 MB). For the sidecar alone: 6.6 MB →
  7.4 MB → 7.5 MB. That is the size of the justification with which the template had
  set `abort`.
- **A degraded process is harder to detect than a dead one.** The watchdog covers
  three loops; `tg-agent` alone runs seven tasks (session, socket listener, two
  network tasks, resolver, `keep_fresh`, `keep_open`).
- **The runtime cost of the overflow check is not measured.** What is measured is the
  size; the tail target from ADR-0022 has no benchmark to this day, and without it
  every statement about the data plane is a conjecture. The way out exists and is
  named: `overflow-checks` **is** settable per package (measured), so the check can be
  switched off for `tg-proxy` as soon as a measurement demands it — not before.
- Somewhat slower builds and more memory when linking (LTO over landing pads).

**Risks & Open Points**

- ~~**Nobody restarts a dead task.** The panic path now reports, but the restart is
  missing — for `keep_fresh` that is the most expensive case: fifteen minutes later
  every handshake fails (ADR-0014).~~ — **decided: ADR-0116.** Restarting happens on a
  **panic**, not on a return; measured, four of the five observed tasks cannot return
  at all. The objection in the code ("it will die again on the second attempt") holds
  only for the persistent cause — and the **transient** one is what this ADR has just
  created with `overflow-checks`.
- **A watchdog per task** is the obvious continuation and is not decided: whose
  silence counts is a question of its own per task.
- ~~The benchmark from ADR-0022 stays open, and with it the question of whether the
  overflow check stays in the data plane.~~ — **measured, and it stays.** The
  benchmark has existed since ADR-0114 (`cargo xtask bench`). The measurement used two
  builds into separate target directories
  (`--config profile.release.overflow-checks=false`), run alternately, six sets per
  variant:

  | | p50 | p99 | p99.9 |
  |---|---|---|---|
  | **on** | 130.9 [119.9–142.8] | 388.5 [315.6–489.9] | 748.5 [673.2–888.4] |
  | **off** | 132.1 [122.0–140.6] | 372.5 [360.7–397.6] | 729.6 [701.2–843.5] |

  Median over the sets, the range behind it, in µs. **The differences lie below the
  spread**, and at the median the sign even points the wrong way (with the check 0.9 %
  *faster*) — that is noise and not a measurement of a price. As an upper bound this
  remains: if the check costs anything on this path, then less than the run-to-run
  spread, i.e. under ~5 % at p99.

  That it turns out this way is plausible: this path's time goes into syscalls, into
  `ring`'s TLS record processing (C and assembler, untouched by Rust's overflow check)
  and into scheduling — not into arithmetic in our code.

  **The size costs are precise by contrast**: `tg-proxy` measures 7,676,960 bytes with
  the check and 7,620,408 without, i.e. **+56,552 (+0.74 %)**. That refines the "+12.4 %
  for both together" above: the overflow check is the cheap half, `panic = "unwind"`
  the expensive one.
- **The template still recommends `abort`.**
  `.claude/rules/ai_cargo_toml_instructions.md` names it in two blocks with the
  justification "smaller binary". This ADR departs from that and the file stays
  untouched — it belongs to the user, and changing it would be a separate agreement.
  The guard catches the regression in **this** workspace; a new crate from the same
  template would get `abort` again.

## Related ADRs

- Depends on: ADR-0019 (static stability), ADR-0062 (what a pass error may cost),
  ADR-0022 (data-plane runtime, shards)
- Changed by: **ADR-0116** (the restart this ADR left open)
- Affects: ADR-0015 (the watchdogs become more important), ADR-0023 (supply
  chain/artefact size), ADR-0069 (the overflow promise becomes general)
