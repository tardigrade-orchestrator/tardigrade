# ADR-0072: The strictness of the session messages

- **Status:** accepted
- **Date:** 2026-09-02
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-store` (`session`), `tgd` (`session`), ADR-0040,
  ADR-0045, ADR-0064, ADR-0031, ADR-0019

## Context and Problem Statement

The session from ADR-0040 carries two directions: the **slice** from the leader to
the node (an instruction) and the **report** back (an observation). Both message
types — `NodeSlice`, `Instance`, `NodeReport` — carry
`serde(deny_unknown_fields)`.

Measured, that means:

```text
old reader (deny_unknown_fields) + new field
  → refused: unknown field `stale`, expected `applied` or `states`
```

**Every** extension of these types is therefore a break for a counterpart that does
not know the field — including those with `serde(default)`, which stood in the
operations manual explicitly as "**no** breaks". That was half right and thereby
wrong: `serde(default)` covers only the direction "new reader, old field missing".

And **both** update orders break in themselves:

| Order | Consequence |
|---|---|
| `tgd` first | old nodes discard the slice; the agent reports "session ended" and keeps trying |
| nodes first | the old `tgd` discards the report and ends the session |

The question of whether this strictness is intended was never decided. It is now.

## Decision Drivers

- **The slice is an instruction, not a data stream.** It carries tombstones
  (ADR-0042), active-role leases (ADR-0064), generations (ADR-0071) and egress
  permissions (ADR-0041). "I received something I did not understand and passed over
  it" is, in a REMIT/DORA environment, not a state one can reconstruct afterwards.
- **ADR-0045** answered the same question for the audit archive: there strictness is
  a security property, and a `flatten` that cancelled it was a finding. The log is
  just as strict — `unknown_commands_are_rejected` justifies it with diverging state
  machines.
- **ADR-0019 (keystone):** a version mismatch must cost no running containers. It
  does not — the agent carries on from its cache.
- **ADR-0064:** what it does cost is the **lease**. Without a session it is not
  renewed, and a single writer fences itself after fifteen seconds.
- **ADR-0031** chooses five nodes so that "rolling updates do not take fault
  tolerance to zero". That holds for the failure of a node — for a **format change**
  it does not, and the difference belongs named.
- **Nothing happens silently.**

## Options Considered

- **Option A — stay strict.** An unknown field means an error. Control plane and
  nodes belong updated together; there is no window with mixed versions.
- **Option B — lax and report.** `deny_unknown_fields` on the session messages goes
  away, unknown fields are caught, reported and ignored. Measured, the semantics
  would be conservative: a field a node does not know makes it do **less** — no lease
  means "does not start", no tombstone means "does not delete", no generation means
  "does not restart".
- **Option C — negotiate a protocol version.** A version field in `Hello`, each side
  speaks the lower one. Two encoding paths, a negotiation step, and every future
  extension has to serve both versions.

## Decision

Chosen: **Option A**.

1. **`deny_unknown_fields` stays** on `NodeSlice`, `Instance`, `NodeReport` and the
   envelope `NodeMessage`. A counterpart that does not fully understand a message
   does **not** process it.

   **And is added to `ControlMessage`.** The first draft counted it among the
   "stays"; measured, it was the **only lenient** one of the five, with no
   justification at the place. It did not matter in weight — the payload is strict
   itself — but its two variants with fields did: a future `Refused { reason, code }`
   would have been read by an old agent, which would have discarded the `code`. Half
   understanding in the reverse direction is the same half understanding. Corrected
   **before** implementation, not after.
2. **The strictness is a promise, not an attribute.** It gets a guard of its own
   that feeds each of these types an unknown field and demands the refusal. The
   reason stands in ADR-0045: there a `#[serde(flatten)]` cancelled the same promise
   **silently**, and it was measured only when somebody looked.
3. **Every extension of these types is a format break** and belongs on the list of
   coordinated switchovers in `plans/PLAN.md` — including those with
   `serde(default)`. They are delivered **bundled** and not individually: five breaks
   in one window cost one window, five windows cost five.
4. **The mismatch is diagnosable on both sides.** The agent reports "session ended"
   with the reason; the server reported **nothing** — it ended silently on
   `Some(Err(_))`. That is fixed: an unreadable input is reported with the node name
   and distinguished from an orderly end of the stream.

   **There are two places, and the more important one was the other.** While
   building it turned out that the stream is read **twice**: the first message before
   the loop, every further one inside it. Before the loop stood a `let … else` with
   three cases in one, and the information given to the agent was not merely missing
   but **wrong** — "the first message must be a Hello", although it was one and the
   server simply could not read it. Since `Hello` is the first thing an agent sends,
   a mismatch on `NodeMessage` shows up there first. Both places now report, and the
   first sends the right reason out with it.
5. **The cost of the window stands in the manual**, not in somebody's head: running
   containers carry on (ADR-0019); the **active-role leases** expire, so single
   writers stand still for the duration of the window and come back by themselves
   afterwards; replicated workloads are unaffected.

Option B is rejected, although its semantics are demonstrably conservative: the
leader's message is a **decree**, and a node that partly executes a decree is
exactly the state an auditor cannot reconstruct. Option C is, for a system whose two
processes come from the same repo and are shipped together, more mechanics than
benefit — it would be the answer if mixed operation were meant to be permanently
normal.

## Consequences

**Positive**

- A node never acts on a half-understood instruction, and a leader takes in no
  half-understood report.
- The mismatch is **loud**: both sides report it, and the session does not come
  about instead of working in an intermediate state.
- The rule is explainable in one place and the same for all three substrates — log,
  archive, session are strict. There is no exception one has to remember.

**Negative / Costs**

- **No rolling upgrade across a format change.** Control plane and nodes belong in
  **one** maintenance window; both orders break in themselves.
- **Single writers stand still for the duration of the window** (ADR-0064: the lease
  is not renewed). They come back by themselves as soon as the leader grants them
  again — but it is an outage, and it belongs planned.
- Every extension, however small, requires this bookkeeping.

**Risks & Open Points**

- **An operator who updates "just one node to try it out" loses that node's
  session.** Loudly, but it is a trap for whoever does not know it — which is why it
  stands in the manual.
- **The length of the window is not measured.** It is the time from stopping to a
  leader with granted leases: restarting the five processes, the election
  (ADR-0033), catching up, one scheduler tick. Whether it stays below the fifteen
  second lease period is unlikely and unmeasured.
- **The bundling is discipline, not a mechanism.** Nothing prevents shipping a
  format break individually; the list in `plans/PLAN.md` is the only bookkeeping.

## Related ADRs

- Depends on: ADR-0040 (the session), ADR-0045 (strictness as a promise), ADR-0064
  (the cost of the window)
- Affects: ADR-0031 (the difference between a node failure and a format change),
  ADR-0042/0046/0050/0055/0071 (the coordinated switchovers)
