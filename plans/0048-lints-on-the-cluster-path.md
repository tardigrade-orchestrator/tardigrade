# ADR-0048: The path of a warning — lints beyond `tgctl apply`

- **Status:** accepted
- **Date:** 2026-08-24
- **Deciders:** Core team
- **Technical context:** `tg-model` (`graph`), `tgd` (`admin`), `tgctl`,
  ADR-0009, ADR-0018, ADR-0020, ADR-0044

## Context and Problem Statement

ADR-0009 introduces a linter warning — *"Requires without After"* — and phase 3
built it. While adding a second warning (`SingleWriterWithoutStandby`) we checked
who actually reads it.

## The finding

**`DependencyGraph::lints()` has exactly one caller in production code:**
`tgctl apply` — the node-local path from phase 2 that works against the local
desired-state cache.

The cluster path does not evaluate them. `Command::UpsertWorkload` is applied in
the state machine, and no lint arises there; the admin service passes the result
through without forming one.

So since phase 3 the following holds: **a warning ADR-0009 requires never reaches
an operator on the actual path.**

And a second finding comes with it that puts the urgency in perspective — it is
the same one as in ADR-0044, one level up: **there is no caller.**
`Command::UpsertWorkload` appears in `crates/*/src` exactly once, and that place
lies in a `#[cfg(test)]` module. No program of this system writes a workload into
the cluster today.

The situation is therefore not "a warning gets lost" but: **a path nobody yet
walks has no warning** — and the question is what form it should take before the
first one walks it.

## Decision Drivers

- **The state machine is pure** (ADR-0004/0005). No access to clock, randomness,
  environment — and no output. Five nodes apply the same log and afterwards have
  the same byte.
- **The log is a retention-obliged audit substrate** (ADR-0020). What goes into it
  stays; a warning is not an event that has to be retained.
- **A lint is a property of the set**, not of the document (ADR-0009). It can
  arise and vanish through the change of an **other** workload.
- **A warning nobody reads is none.** That is the finding itself.
- **ADR-0044's rule:** what there is nothing yet to call is fixed and not built.

## Options Considered

- **A — leave it.** Lints stay a courtesy of the local path.
- **B — lints into the `Outcome`.** The state machine forms them while applying
  and returns them with it.
- **C — lints into the admin service's response.** After the write, formed from
  the resulting state, next to the `WriteResult`.
- **D — the sender lints beforehand.** Whoever writes fetches the state, adds
  their document and lints the set themselves.
- **E — a standing query.** `tgctl lint` lints the **current** state,
  independently of a write.

### Why not B

It is the obvious place and the wrong one. A lint in the `Outcome` afterwards
stands in the **log** — the command, its result and its warnings — and the log is
retained (ADR-0020). A warning referring to a state that no longer exists two
commands later would thereby be preserved permanently. In five years an auditor
would read warnings long since resolved, and would have to hold each one against
the state of the time.

On top of that comes effort in the wrong place: the state machine would have to
build the graph of the whole set on **every** upsert — the same work `storage::`
already performs once as a deliberately paid price, but for an output instead of
for an invariant.

### Why not D

It is tempting because it needs no change to server or log, and it moves a check
to the place that can least guarantee it. Whoever lints themselves can also leave
it out; and two clients lint with differing strictness as soon as there are two.
The same consideration as with edge reading in phase 8: a check every caller has
to bring along is one that somebody forgets.

### Why not A

The finding itself is the objection: ADR-0009 did not mean the warning as a
courtesy of the phase-2 path.

## Decision

Chosen: **C and E together** — and both **fixed, not built**, until there is a
client that writes workloads into the cluster.

### 1. The admin service answers with lints, the log carries none

`WriteResult::Applied` gains the lints of the **resulting** set. They are formed
in the admin service, **after** the write, from the projection — not in the state
machine.

Three properties follow from that, and they are the reason for the cut:

- **The state machine stays pure.** It gets no field, no work and no output.
- **The log stays free of the ephemeral.** A lint is a statement about a state,
  not an event; ADR-0020 retains events.
- **The answer reaches whoever caused it** — at the earliest moment at which the
  statement can be true at all: after their document is part of the set.

### 2. And a standing query, because a lint has no sender

A lint belongs to the **set**, not to the document. It can arise because somebody
changed a *different* workload, and then there is no response for it to hang on.
`tgctl lint` (a working name) therefore lints the current state — the same
function, a different trigger.

Without that second trigger the promise would be false: "lints reach the
operator" would hold only for whoever happened to write last.

### 3. Lints reject nothing

They stay what ADR-0009 made of them: **warnings**. A `Requires without After` is
a probable intent and not a violation, and a single writer with one instance is a
legitimate choice (ADR-0010 itself names the doubled resources as a cost). What
is not legitimate is doing either **by accident**.

A rejection is something else and is called `Rejection` — it stands in the log,
because a rejected intent is an event (phase 11a).

### 4. It gets built once there is a client

~~Today no program writes a workload into the cluster. Building a response
without a caller is exactly what ADR-0044 named as the mistake — there it was a
port without clients. What is fixed is therefore the **form**; it gets built
with `tgctl apply --cluster` or whatever ADR-0018 puts in its place.~~

**Built.** The client is `tgctl cluster apply` (`crates/tgctl/src/cluster.rs`),
and it carries both halves: the lints out of `WriteResult::Applied` after every
write, and `tgctl cluster lint` as the standing query from determination 2. The
verb became `cluster apply` and not `apply --cluster` — two verbs leave no
doubt which target was meant, where a switch that flips the target of a writing
action would be the operation that goes wrong at three in the morning.

What holds **immediately**: new lints belong in `DependencyGraph::lints()` and
nowhere else. As long as there is one source, connecting it later is wiring; two
sources would be two behaviours.

## Consequences

**Positive**
- The promise from ADR-0009 becomes redeemable without log or state machine
  noticing anything.
- The place for lints stays one.
- The standing query turns a snapshot into a property one can check at any time —
  the same construction as `tgctl audit`.

**Negative / Costs**
- **It stays unreachable for now.** The finding is named and not fixed; until
  there is a client, only users of `tgctl apply` see lints.
- The admin service gets work it does not have today — the graph of the whole set
  per write. On a consensus write path that is bearable (the same consideration as
  with the volume ingest in phase 10a), on a standing query likewise.
- `WriteResult` grows and is therefore a protocol that changes. Unlike with the
  log that is inconsequential: the admin service talks to a client of the same
  release.

**Risks & Open Points**
- ~~**Who builds the path is ADR-0018 work.** A client that writes workloads into
  the cluster does not exist; `tgctl apply` is node-local.~~ — **done:** ADR-0103
  — the operator port; the client is built.
- ~~**Authorization is still missing** (ADR-0044): whoever reaches the socket may
  do everything — writing included.~~ — **done:** ADR-0105.
- Whether a standing query shows the lints **per workload** or for the whole set
  is a question of implementation.

## Related ADRs

- Depends on: ADR-0009 (the warning), ADR-0004/0005 (the purity of the state
  machine), ADR-0020 (what belongs in the log), ADR-0044 (build nothing without a
  caller)
- Affects: ADR-0018 — the surface gains a response form that has to be served
