# ADR-0089: What a requirement edge may know about readiness

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture
- **Technical context:** `tg-model`, `tg-runtime`, ADR-0009, ADR-0061, ADR-0080

## Context and Problem Statement

ADR-0080 built readiness per workload and left an open point in doing so:

> **The dependency gate** (ADR-0061) still counts "runs" as active. Switching it to
> readiness is the obvious continuation and a decision of its own: it holds a
> dependent back, and a misjudgement by the probe then costs a second workload.

The question is therefore: **should a target that runs and does not answer satisfy a
`requires` or `bindsTo` edge?**

It is not new but has been the same since phase 3. The plan noted it three times as
"healthy means: the container runs" — and twice with the wrong justification, that
ADR-0015 knows no probes per workload. It does know them; since ADR-0080 they exist.
So the question is due.

## What is measured

**The gate reads the outcome of the same pass.** `cascade_stop` receives
`Vec<(&str, Inactivity)>`, filled from the loop over `graph.start_order()` — whoever
comes after their target already sees its outcome (ADR-0061, determination 2).
`Inactivity` has exactly two values, `Failed` and `Stopped`.

**The probe runs after that loop.** `probe_readiness` stands in `once` behind the
`start_order` pass, and that is no negligence: an instance this pass is **starting**
cannot answer beforehand. A gate reading readiness would therefore get the state of
the **previous** pass — i.e. edge-driven on stale state, precisely what ADR-0061
avoids.

**Readiness already takes effect, just elsewhere.** `health_of` turns an unready
instance into `Health::Unhealthy`, and the resolver takes its endpoint out of
resolution (ADR-0013). A dependent resolving its name gets `NODATA` with a negative
deadline of one second (phase 9a) — and through the slice the same holds for
**foreign** nodes (ADR-0073).

## Decision Drivers

- ADR-0009 separates **ordering** and **requirement** into two axes and names that
  separation as its core. Mixing "started" and "healthy" drags a third meaning into
  the requirement axis.
- A misjudgement by the probe costs, with the gate, a **second** workload. A mistyped
  port in `<readiness port="…"/>` would then be one line of XML that halts an entire
  dependency chain.
- ADR-0080 built the probe explicitly low-consequence: "the effect is resolution
  alone". The gate would be the first effect with a blast radius.
- Readiness is a statement about **now**, the gate one about the desired state.
  Level-driven, the gate needs an input the same pass produces.

## Options Considered

- **Option A — the gate reads readiness.** An unready target holds its dependent back
  (`HoldOnRequirement`).
- **Option B — the gate stays with "runs".** Readiness takes effect through
  resolution.
- **Option C — a third edge kind** (`requiresReady`) that demands readiness while
  `requires` does not.

## Decision

Chosen: **Option B.**

1. **A requirement edge is satisfied when the target runs.** Readiness is none of its
   business. That is ADR-0009's separation verbatim: the requirement axis asks whether
   the unit is there, not whether it answers.
2. **Readiness takes effect through resolution, and that is the right granularity.**
   It hits an individual client's individual **connection** at the moment of
   connecting, not the lifecycle of a whole workload. A dependent that has to wait for
   its dependency therefore waits where it has to wait anyway — at its first
   connection.
3. **The order in `once` is part of this decision.** The probe runs **after** the
   `start_order` pass. Whoever moves it before makes the gate's input possible — and
   has to take this decision anew. A guard pins the order down.
4. **`Inactivity` stays at two values.** A third (`Unready`) would be the entry into
   option A through the back door; the enumeration is checked exhaustively, so that a
   fourth forces the conversation.
5. **Option C is rejected.** A fourth edge kind doubles the requirement axis and
   merely shifts the question: an operator would have to answer it per edge without
   knowing more than today. ADR-0009 explicitly decided for **few** orthogonal axes.

## Consequences

**Positive**

- A misjudgement by the probe costs an endpoint in resolution and not a second
  workload. The blast radius of a mistyped port stays with the workload that declared
  it.
- The start order stays as fast as it is: a dependent starts as soon as its target
  **runs** and does not have to wait for its first answer. With `After` chains the
  start-up times would otherwise add up.
- ADR-0061's core property stays: the gate evaluates against the outcome of **the
  same** pass.

**Negative / Costs**

- **A workload can start while its hard dependency does not yet answer.** So it has to
  be able to cope with a failed first connection. That is the expectation this system
  makes anyway — ADR-0009 calls a `Wants` edge legitimate for exactly that reason, and
  the resolver gives `NODATA` instead of `NXDOMAIN` so that a client tries again
  (phase 9a). But it is an expectation, and it now stands written down.
- Whoever needs the other semantics has no tool for it. That is intended; an
  `initContainer` pattern would be a decision of its own.

**Risks & Open Points**

- A workload that **crashes** on connecting instead of retrying runs into a restart
  loop that looks from outside like an orchestrator bug. It is visible in the target's
  `tg_workload_ready`; an alarm on it already exists.
- The decision concerns the **requirement** axis. Whether an `After` should wait for
  readiness — i.e. whether "started" should mean readiness for the ordering axis — is
  the same question in the other axis and is **not** decided here. Today `After` waits
  for the start attempt, not for the answer.

## Related ADRs

- **ADR-0009** — the two orthogonal axes; this decision is their application.
- **ADR-0061** — the runtime evaluation of the requirement edge.
- **ADR-0080** — readiness and its deliberately narrow effect.
- **ADR-0013** — the resolution through which readiness takes effect.
