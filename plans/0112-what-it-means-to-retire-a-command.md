# ADR-0112: What It Means to Retire a Command

- **Status:** accepted
- **Date:** 2026-09-10
- **Decider:** Dana Schlifka
- **Technical context:** `tg-consensus` (`command`, `state`, `store::machine`)

## Context and Problem Statement

A command loses its caller when a better way is found. This has happened three
times, and been handled three different ways:

| Variant | Caller lost | Handling |
|---|---|---|
| `ClearPlacement` | never had one | stays, **executes** |
| `RegisterTrust` | ADR-0055 (`RotateTrust` took its place) | stays, **executes** |
| `RevokeLease` | never had one | **removed** (ADR-0111) |

The commit `8e1664b` ("The alphabet of the log is append-only") already posed
the question once for the first two and answered it with "unremovable".
ADR-0111 decided the opposite for the third — with a justification that
carries, but without naming the contradiction. **There is no rule, there are
three individual cases.** That is the shape of ADR-0057.

And a second answer is missing. With `RegisterTrust` the retirement removed the
**caller**, not the **capability**: `apply` still writes `self.trust`,
unconditionally.

## Decision Drivers

- **ADR-0020** — the log is retained forever. An entry from yesterday must be
  readable years from now.
- **ADR-0030** — the projection arises from the log. What an entry effects is
  decided by the state machine, and an unknown command is **hard rejected**
  rather than skipped.
- **ADR-0037** — the invitation is the one-time, consensus-checked gate through
  which a node obtains trust.
- **ADR-0105** — authorization sits at the **transport**, not in the state
  machine. The comment at the application site says the same: *"Only the
  command goes into the state machine. The actor is provenance and not part of
  the decision (ADR-0050)."*
- **11a / ADR-0045** — rejected commands are archived too: *"a futile attempt
  is exactly the event an auditor looks for."*

## The measured finding

**Exactly one of the three variants ever had a producer.** Measured against the
history, not against today's tree — `git log -S` over all commits, and per
commit the files in which a **construction** was added (`match` arms and tests
subtracted):

```text
ClearPlacement   218f987  only the apply arm           -> never produced
RegisterTrust    07e4304  crates/tgd/src/identity.rs   -> produced
                 351bc87  replaced by RotateTrust      -> producer removed
RevokeLease      218f987  only the apply arm           -> never produced
```

With that the removal from ADR-0111 is retroactively substantiated — and
`RegisterTrust` really is unremovable: a log from the window
`07e4304`..`351bc87` can carry an applied entry.

**The second finding concerns what it can still do.** `RegisterTrust` writes
`self.trust` without an invitation. ADR-0055 named the danger — *"a node whose
trust an operator has just revoked could enter itself again"* — and answered it
with `RotateTrust` (compare-and-set). Only the old way stayed **open**: whoever
reaches the admin service with `Class::Write` enters node trust and bypasses the
gate from ADR-0037. `tgctl` has no subcommand for it; the protocol takes a
`Command`.

**The third concerns the guard from ADR-0111.** It counts
`Command::ClearPlacement` in a **doc comment** (`command.rs:821`) as a
construction and therefore held the variant to be produced. Without comment
lines there are two producer-less variants, not one. The guard concealed
exactly the case for which it was built.

## Options Considered

- **A — Change nothing.** A retired command stays executable; whoever issues it
  gets its effect. Rejected: the retirement is then a note and not a property.
- **B — Reject at the access point** (admin service, alongside the `class()`
  check). `apply` untouched, every log replicates unchanged. Rejected because
  of the price: the attempt never reaches the log, so it leaves **no audit
  entry** — and an attempt to enter node trust without an invitation is exactly
  what an auditor wants to see (11a).
- **C — Reject in `apply` if the entry carries an actor.** Would preserve both:
  rejection *and* audit entry, and historical entries (which the cluster itself
  wrote, without an actor) would replicate unchanged. Rejected: it makes
  **provenance** part of the decision — exactly what ADR-0050 and ADR-0105
  exclude, and authorization in the state machine under another name.
- **D — Reject in `apply`, unconditionally.**

## Decision

Chosen: **Option D**, with an explicit criterion for removal.

### Determination 1 — a variant may be removed exactly when it never had a producer

Then no log can contain it, and ADR-0020 is untouched. The criterion is
**measurable** and answerable from the history, not from today's tree:
`git log -S "Command::<Variant>"`, and per hit the question whether a
**construction** outside tests and `match` arms was added.

It is expressly **not** a test: the history is not available to a test, and a
test that reconstructed it would be a second source. What remains is the
witness from `8e1664b` — `a_command_kind_can_never_be_removed` checks
**literals** of old log lines, and its list is append-only like what it
protects.

### Determination 2 — what stays becomes inert

A retired command stays **readable** (the type still carries it, old entries
decode) and is **rejected** by `apply`. With that the retirement is a property
of the system and not a note on a declaration.

The rejection is unconditional and hangs on nothing but the variant: the state
machine stays a pure function over the **command**, and two nodes still arrive
at the same result (ADR-0004, ADR-0050).

### Determination 3 — and thereby reported

The attempt goes into the log, is applied, rejected and sealed with its outcome
(ADR-0045). An auditor finds it in the archive, together with the actor
(ADR-0050). That is the reason why the rejection sits in `apply` and not at the
access point: **rejecting** both can do, **reporting** only this way.

### Determination 4 — `Command::retired()` is the one source

A `const fn` with an **exhaustive** `match`, like `class()` and
`may_be_policy()` beside it. Whoever adds a variant must decide whether it is
retired — the answer is almost always no, but it is demanded rather than hoped
for.

The guard from ADR-0111 derives its exceptions from it instead of maintaining a
list by hand: **a variant without a producer must be retired, and a retired one
must not have one.** Both directions, as with the earlier exception list — only
without the second list.

### Determination 5 — the guard does not count comment lines

The finding above. A mention in a doc comment is a reference and not a
construction; a guard that counts it is green for the wrong reason.

### Determination 6 — retired today are `ClearPlacement` and `RegisterTrust`

`RevokeLease` is removed (ADR-0111) and stays so: determination 1 covers it.

## Consequences

**Positive**

- The way past ADR-0037's gate is closed. An operator with `write` can no
  longer enter node trust without an invitation.
- A retirement is from here a property and is guarded, instead of standing in a
  doc comment.
- The three individual cases become one sentence, and the next case needs no
  weighing any more — only a measurement.
- The guard from ADR-0111 from here catches what it was supposed to catch.

**Negative / costs**

- **A log from the window `07e4304`..`351bc87` replicates differently than
  before.** A `RegisterTrust` applied in it is rejected on replay, and the
  affected node would lose its trust — fixable with a new invitation, but it is
  a silent change to the meaning of an old entry. Measured, the window lies in
  this tree's development history; a shipped cluster does not exist.
- **This is a change to the state machine**, hence no rolling update: two nodes
  with different versions build different states from the same log. It belongs
  in the same coordinated window as a format change (ADR-0072) and in the
  manual.
- Every attempt costs a log entry that stays forever. That is intended (11a)
  and nevertheless a growth.

**Risks & open points**

- The criterion from determination 1 is a **measurement, not a test**. Whoever
  removes a variant without consulting the history gets past the witness only
  if the variant is not in its literal list — that is exactly how `RevokeLease`
  slipped through. The witness therefore gets every retired variant as a
  literal, not just the two `8e1664b` examined.
- `ClearPlacement` becomes inert although it was harmless. That is deliberate:
  an exception "harmless, may stay" would be a weighing per case, and this ADR
  exists precisely because there were three of those.

## Related ADRs

- Depends on: **ADR-0020** (retention), **ADR-0030** (the projection from the
  log), **ADR-0004** (the state machine decides on the command)
- Applies: **ADR-0045** (the outcome in the sealed payload),
  **ADR-0050**/**ADR-0105** (provenance is not part of the decision)
- Closes: **ADR-0055** — there the producer of `RegisterTrust` was removed and
  the danger named; the capability remained
- Supplements: **ADR-0111** (the guard over producibility) and **ADR-0037**
  (the gate past which `RegisterTrust` led)
