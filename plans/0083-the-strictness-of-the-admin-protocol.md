# ADR-0083: The strictness of the admin protocol

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tgd::admin`, `tgctl`, `tg-wire`, ADR-0044, ADR-0048,
  ADR-0072

## Context and Problem Statement

**ADR-0072** decided that a session message with an unknown field is an error — and
named the scope **by name**: `NodeSlice`, `Instance`, `NodeReport`,
`ControlMessage`, `NodeMessage`. The admin service from **ADR-0044** did not appear
in it.

Measured across the eleven serialized types in `tgd::admin`, exactly **one** carries
`deny_unknown_fields` (`LintsResponse`, from ADR-0048), the other ten do not. That is
not a decision but the state eleven individually written types produce.

And the payload **inside** them is strict: `Command` and `Submission` (ADR-0050)
refuse a foreign field. Strict, then, is the cargo, lenient the envelope.

**Measured, with a positive control:**

```text
CONTROL add_learner:                     true
add_learner with a foreign field accepted:   true
StatusRequest with a foreign field accepted: true
```

The first line is not decoration: the first attempt at this measurement used
`AddLearner` instead of `add_learner` (`rename_all = "snake_case"`) and reported a
refusal that lay with the **variant name** and not with the strictness. Without a
positive control a finding would have come out of it that does not exist.

## Decision Drivers

- **ADR-0072's core sentence is not bound to a transport:** "I received something I
  did not understand and passed over it" is, in a REMIT/DORA environment, not a state
  one can reconstruct afterwards.
- **The admin socket is the recovery path** (ADR-0044). Whoever works on it because
  the cluster has stopped needs it usable.
- **`MembershipChange` carries effective statements** — `blocking` and `retain` — and
  both decide about the quorum.
- **The peer is trustworthy** (a Unix socket, `0700`): whoever reaches it can halt the
  process and read the disk. This is **not** about attack surfaces but about version
  mismatch.
- Unlike nodes and control plane, whose rolling update ADR-0031 explicitly foresees,
  `tgctl` and `tgd` are **two binaries of one build**.

## Options Considered

- **Option A — everything stays.** Ten lenient types, one strict.
- **Option B — strict everywhere.** A foreign field is an error, in both directions.
- **Option C — asymmetric:** requests strict (a **decree**), responses lenient
  (information). An old `tgctl` would see less of a new response instead of nothing.

## Decision

Chosen: **Option B — strict everywhere.**

### Determination 1 — every serialized type of the admin protocol is strict

The empty request types too. `StatusRequest {}` today accepts `{"was":1}`; that costs
nothing and says nothing — but an exception that means "here it does not matter" is
something a reader later has to place.

The case at issue is `MembershipChange`. A new `tgctl` sending along a field an old
`tgd` does not know today gets the change executed **without that field** — with
`blocking` that means: the call returns without the learner having caught up, and the
operator promotes a node that knows nothing yet. Exactly the situation the two-step
procedure from phase 5d is built against.

### Determination 2 — option C is rejected, and the reason is the incident

The distinction "decree against information" holds in itself; it is just not what
counts in an incident. A `tgctl` that displays a response **silently truncated** gives
an operator an incomplete picture in a recovery — and that is the moment in which
they can least check it. "Your tool version does not match this node" is the better
answer, because it is actionable.

That it is readable at all comes from `tg-wire`: an unreadable body becomes
`invalid_argument` with a bounded quotation, not `internal`.

### Determination 3 — the strictness gets a guard

As in ADR-0072, and for the same reason: it is a **promise** and not merely an
attribute. A `#[serde(flatten)]` cancels it silently — ADR-0045 measured that on
`Line`. The guard reads the source of `tgd::admin` and demands it on every serialized
type; a new type is thereby not silently exempt.

## Consequences

**Positive**

- There is no half-understood decree on this transport any more.
- The envelope is as strict as its cargo (`Command`, ADR-0050) — before, the relation
  was inverted and unjustified.
- `LintsResponse` is no longer an exception nobody can explain.

**Negative / Costs**

- **A version mismatch between `tgctl` and `tgd` aborts instead of truncating.** That
  is the intent and still a behavioural change: both binaries belong to **one** build,
  and from here on that stands in the manual.
- Every future extension of an admin type is a format break of the same kind as those
  from ADR-0072 — only it concerns two binaries on the **same** machine, so it is
  handled with the package and not with a maintenance window.

**Risks & Open Points**

- **New enum variants are unaffected by this** and have always been an error: an old
  `tgctl` reading a new `Rejection` fails independently of this decision. Whether a
  response should cushion that is not decided.
- The guard checks the **presence** of the attribute, not its effect. The effect is
  checked by a test per direction.

## Related ADRs

- Depends on: ADR-0044 (the transport), ADR-0072 (the rule and its scope)
- Affects: ADR-0048 (`LintsResponse` was the only strict one), ADR-0050 (the envelope
  was already strict)
