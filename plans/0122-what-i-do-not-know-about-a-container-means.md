# ADR-0122: What "I Do Not Know" About a Container Means

- **Status:** accepted
- **Date:** 2026-09-12
- **Concerns:** ADR-0120 (the edge case it names), ADR-0058 (the distinction
  "wanted by nobody" / "not yet heard"), ADR-0061 (the cascade), ADR-0062
  (isolate instead of fail), ADR-0019 (the keystone), ADR-0027 (the ephemeral
  volume)

## Context and Problem Statement

ADR-0120 named an edge case and expressly did not treat it:

> **`ContainerStatus::Unknown` stays an edge case.** If the runtime reports
> `Unknown` while a container is running, the path leads into `start` — and
> with determination 1 into an unmount under a running process. The risk exists
> at this place even before this decision; it is named here and not treated.

Measured, it is not an edge case but a directional decision that was never
made: **"I do not know what it is doing" today means "it does not exist".**

```rust
ContainerStatus::Absent | ContainerStatus::Unknown(_) => {}
// ... falls through to
start(paths, runtime, target, &id, context).await
```

### The measurement

On a real youki container, with a changed declaration — that is, exactly what
`start` would do after an `Unknown`:

```text
mounted before:  true
build: Ok — the rootfs was unmounted under the running container
mounted after:   true        (with the new layer: generation.txt is there)
still running:   Ok(Running)
create: Err — container already exists
upper exists:    true        (new and empty — the old one is gone)
```

Three findings sit in it.

**The damage is silent and comes before the error.** `build` returns `Ok`. At
that moment the ephemeral volume of a **running** container is deleted
(ADR-0027: it dies with the container — here it dies without it), the rootfs
beneath it swapped. The container runs on in its own mount namespace on the old
mount and notices nothing until its next start. The visible part comes
**afterwards** and reads "container already exists" — which reads like a
harmless remainder from an earlier run.

**It never converges, and it drags along.** Every subsequent pass ends again in
`create: Err`, hence in `report.failed`. And per ADR-0061 a `failed` is the
trigger of the cascade: every workload with a `requires` or `bindsTo` edge onto
this one is **stopped**. A status output we cannot read thereby becomes the
outage of a whole chain — while the container runs and serves.

**The precondition ADR-0120 invokes is a claim.** In `bundle.rs` it says
verbatim: *"This is safe here because `build` runs only from `start` and
`start` only after `apply` has ended the container (determination 4)."* The
sentence is true for every branch except the one that lumps `Unknown` together
with `Absent` — and nothing holds it.

### A refuted hypothesis

The obvious suspicion was that `parse_status` is fragile: it searches for the
string `"status"` in a JSON text instead of parsing it. Measured, it holds:

| Input | Result |
|---|---|
| `{"annotations":{"org.example/status":"ok"},"status":"running"}` | `Running` |
| `{"annotations":{"a":"status: running"},"status":"stopped"}` | `Stopped` |
| `{"bundle":"/srv/status/x","status":"running"}` | `Running` |
| `{"id":"tg-status-1","status":"running"}` | `Running` |
| newlines and spaces around `:` | `Running` |

The pair of quotation marks is specific enough; none of the plausible cases
hits. The parser is **not** touched here — a change without a measured occasion
would be work with a risk of its own.

### Where `Unknown` then comes from

From four places, and all four mean the same: **the runtime answered, and we
did not understand it** — no `status` field, a field without a value, a value
that is not a string, or a state word this version does not know. Added to that
is the fifth case, which `step` already names the same way today: the call
itself fails (`Unknown("state not queryable")`).

With a current, spec-faithful runtime that is rare. That is nevertheless not an
argument: ADR-0003 expressly provides for the switch between youki and crun,
and the question "what do we do when we do not know" has already been answered
twice in this system — both times with the safe answer.

## Decision Drivers

- **The rule already exists twice.** ADR-0058: distinguishing "wanted by
  nobody" from "not yet heard" *is* the safety question. ADR-0062: an entry the
  node cannot place is **isolated** — neither started nor stopped. Here it is
  missing for the actual state.
- **The keystone.** A running container is never touched because of an
  uncertainty (ADR-0019). Unmounting beneath it is the sharpest form of that.
- **Not knowing is not failing.** The cascade from ADR-0061 is meant for a
  **failed** target. A container whose state we cannot read may be serving
  perfectly well.
- **And it is not health either.** Whoever does not know whether an instance is
  running must not offer it as an endpoint (ADR-0013).

## Options Considered

- **A — `Unknown` like `Absent`** (today). The unsafe direction, measured.
- **B — `Unknown` like `Running`.** Safe towards the container, but it puts the
  instance into `untouched` — and resolution in the resolver and the report to
  the leader hang on that. We would then be claiming health we do not know.
- **C — `Unknown` like `failed`.** Today's state after the first pass, and it
  drags the dependents with it (ADR-0061).
- **D — an exit of its own.** Not touched, not resolved, not a trigger of the
  cascade, visible with a reason.

Chosen is **D** — the same shape as `held` (ADR-0061), `fenced` (ADR-0064) and
`isolated` (ADR-0062): a bucket for a case that is neither success nor failure.

## Decision

### Determination 1 — "no information" is a case of its own, not `Absent`

`ContainerStatus::Unknown` gets its own `match` arm in `reconcile_one`. The
exhaustive `match` **is** the assertion: whoever adds a state to the enum comes
past this place, and the unsafe direction can no longer be chosen by accident.

With that the precondition from ADR-0120 turns from a claim into a property:
**`start` is reached only when this pass knows that no container of this
identifier is running.**

### Determination 2 — a call that fails is the same as an answer we cannot read

`step` already names it that way today (`Unknown("state not queryable")`), and
`reconcile_one` passes the same case on as an error. From here it is one thing:
both mean **no information**, and both take the same path.

The reason travels along — the `&'static str` in `Unknown` is the diagnosis,
and for a failed call its message goes into the same place.

### Determination 3 — an unknown situation touches nothing

Neither started nor stopped nor cleared away. That is ADR-0062, determination
3, verbatim, one level deeper: "I cannot place you" is not "nobody wants you
any more" — and here also not "you do not exist".

### Determination 4 — it is not a failure

The instance does **not** stand in `failed` and does not trigger the cascade
from ADR-0061. The same justification as with `fenced` (ADR-0064,
determination 6): a `failed` would drag dependents along, and for that the
situation is too unclear — the container may be running and serving.

### Determination 5 — and it is not health

The instance does **not** stand in `untouched` and is thereby not resolved
(ADR-0013). Whoever does not know whether it serves does not offer it.

That is the difference from option B, and it is the whole reason for a bucket
of its own instead of an annotation beside `untouched`: `stale` (ADR-0070) and
`unready` (ADR-0080) are statements about an instance we **know** is running.
Here we do not know it.

### Determination 6 — it is visible, with a reason

The report carries the bucket together with the reason per instance, the log
names it, and a metric counts it per workload (ADR-0015: the workload name is
permitted, the instance is not — which one it was stands in the log).

Without it the decision would be a silence: nothing happens, nothing fails, and
an operator looks for the error where it is not.

## Consequences

**Positive**

- **The ephemeral volume of a running container is safe.** The measured
  sequence — unmount, delete `upper`, swap rootfs, all beneath a running
  process — can no longer arise.
- **An unreadable status output no longer costs the dependents.** The cascade
  from ADR-0061 stays reserved for what it is meant for.
- **The precondition of ADR-0120 is from here a property** and no longer a
  sentence in a comment.
- The rule from ADR-0058 and ADR-0062 now applies on both sides of the
  reconcile: to the desired **and** the actual state.
- **No new crate**, no change to the protocol, no change to the parser.

**Negative / costs**

- **A container in an unknown state is no longer replaced.** Were it actually
  dead and merely unreadable, it would not start up again from here until a
  human intervenes. That is the deliberate choice: the opposite error costs
  data, this one costs the availability of an instance — and it is
  **visible**, which the other was not.
- **A runtime that permanently does not answer starts nothing from here on**,
  instead of trying and failing. That is ADR-0019 in its strict form; the
  information about it is the bucket and the metric.
- **One bucket more in the report.** Every place that adds up instances must
  know it — the same cost that `held`, `fenced` and `unready` had.

**Risks & open points**

- **An unknown state has no deadline.** It stays until the runtime gives an
  answer we can read again, or a human intervenes. An automatic escalation
  would be a policy over an **absence**, and that is forbidden per ADR-0057.
- **The bundle claim stays the only barrier against a foreign writer.** `claim`
  (ADR-0119) checks the identifier, not whether a process is running. A second
  agent on the same data directory would still be an operating error with the
  same consequences; that is not decided here.
- **`parse_status` stays a text parser.** The fragility is measured not to be
  there (see above); if a runtime with a different output form came along, the
  case is from here at least low-consequence rather than destructive.

## Related ADRs

- **Redeems:** **ADR-0120**, open point *"`ContainerStatus::Unknown` stays an
  edge case"* — and the edge case was a directional decision.
- **Applies:** **ADR-0058** ("wanted by nobody" ≠ "not yet heard"), **ADR-0062**
  (isolate instead of fail, and the cost stays with the workload), **ADR-0019**
  (a running container is not touched).
- **Protects:** **ADR-0027** (the ephemeral volume dies with its container —
  not without it), **ADR-0061** (the cascade stays reserved for failure),
  **ADR-0013** (what is resolved is what is healthy).
- **Touches:** **ADR-0003** (the switch between the runtimes is the reason this
  case can occur at all), **ADR-0015** (the metric).
