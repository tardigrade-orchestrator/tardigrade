# ADR-0045: The verdict in the chain

- **Status:** accepted
- **Date:** 2026-08-23
- **Deciders:** Core team
- **Technical context:** `tg-telemetry` (`audit`), `tg-consensus` (`audit`),
  `tgctl audit`, ADR-0020

## Context and Problem Statement

Phase 11a made the audit trail exportable: the log entries are sealed into a
hash chain that can be verified **outside** the cluster. The claim stands in
ADR-0020 and in the plan: *"Modification, reordering and excision are detected."*

While building `tgctl audit` we checked what the sealing actually covers.
`digest_of` takes five inputs — predecessor digest, index, time, command kind and
payload — and the payload is an `Event` consisting of log index, term and
**command**. The state machine's verdict stands next to it:

```rust
pub struct Line {
    #[serde(flatten)]
    pub record: Record,       // sealed
    pub outcome: Value,       // not sealed
}
```

**Measured:** an archive entry with
`"outcome":{"rejected":{"unknown_workload":{"name":"api"}}}` can be rewritten to
`"outcome":"applied"`, and `verify` still says "it holds". The finding is pinned
as a test.

## Why this is more than a missing field

The gap hits exactly the justification with which 11a introduced archiving
rejections: *"An auditor does not only ask what happened; a futile attempt to
renew a foreign lease is exactly the event they are looking for — and it leaves
nothing in the state."*

What makes this event interesting is its **outcome**. Both directions are damage:

- "Rejected" becomes "applied": the archive states that an unauthorized access
  had effect although the cluster refused it. An auditor opens an incident that
  never happened.
- "Applied" becomes "rejected": an access that had effect looks futile. That is
  the more dangerous direction — it conceals what happened, and the archive
  certifies its own integrity while doing so.

The limit of the gap belongs named as well, so that it does not look bigger than
it is: **the attempt itself is sealed.** An entry cannot be invented, moved or
removed. What is forgeable is only the verdict on a real attempt standing in its
place.

## Decision Drivers

- **ADR-0020 demands tamper-evident, not tamper-evident-with-an-exception.** A
  verification artefact whose integrity claim carries an asterisk is one whose
  footnote nobody will know in two years.
- **One procedure, not two.** 11c deliberately sealed the DST report with *the
  same* chain: *"An auditor learns one procedure and applies it to both."* What
  is decided here must not turn that into two.
- **`digest_of` is the root.** Any change there changes **every** digest in the
  system — including those of the DST evidence from 11c, which has nothing to do
  with commands.
- **Determinism across nodes.** What goes into the digest has to arise byte for
  byte identically on all five nodes (ADR-0004: the same apply, the same result).
- **Effort now against effort later.** There is no shipped archive today. The
  same cut after the first retention period is a migration with an obligation to
  provide evidence.

## Options Considered

- **A — the verdict into the sealed payload.** `Event` gains a field `outcome`;
  `Line` loses its own. `digest_of` and `seal` stay untouched.
- **B — the verdict as a sealed field of its own.** `digest_of` gains a sixth,
  length-prefixed input.
- **C — remove the verdict from the archive.** The file then only claims what it
  can evidence.
- **D — leave it and label it.** The report names the number with the caveat "not
  covered by the chain" (today's state).
- **E — a second chain over the verdicts.**

### Why not B

It is the obvious reading of "the verdict belongs in the sealing", and it is the
most expensive. `digest_of` is the common root of **two** artefacts: the audit
archive and the DST evidence from 11c. A sixth field forces every caller to
supply something — and `tg_dst::evidence` seals test results for which there is
no "verdict of the state machine". It would have to stay empty there, and a
mandatory field that is empty at half the call sites is an invitation to leave it
empty everywhere.

On top of that: the promise from 11c is "the same seed produces the same report".
It stays true, but the report would look different from the switchover on, and an
existing comparison run would be worthless — without the change having anything to
do with the harness.

### Why not C

The renunciation would be honest and would lose something an auditor needs. The
verdict is **in principle** reconstructible — the state machine is deterministic,
so replaying the log yields the same verdicts. In an auditor's position that is
not an answer, though: they hold a **segment**, not the log from the beginning,
and a replay would additionally require the program version of the time. Removing
something that can only be retrieved with the whole system and the right binary
moves verifiability to where ADR-0020 explicitly does not want it.

### Why not D

It is today's state, and as an **interim state** it is right: as long as the gap
exists, the tool must name it rather than conceal it. As a goal it is wrong. A
caveat in an output is a statement about the build state, not a security
property; it does not travel with the file into the archive, and whoever verifies
the file in five years does not have it.

### Why not E

Two chains are two procedures, two anchors and two opportunities to get one of
them wrong. And it does not even solve the problem: a second chain over verdicts
binds a verdict to the **previous verdict**, not to the attempt it belongs to.
Whoever rewrites both chains consistently swaps the verdicts of two entries —
with one chain over the whole entry that is impossible.

## Decision

Chosen: **Option A** — the verdict moves into the sealed payload.

### 1. `Event` carries the verdict, `Line` disappears

```rust
pub struct Event {
    pub log_index: u64,
    pub term: u64,
    pub command: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Value>,   // new, and therefore in the digest
}
```

**`Option`, and that is not convenience.** There are two producers of segments,
and only one knows the verdict: the archive arises in the apply and has it,
`export` reads the **log** — and it does not stand there, because the log carries
commands, not results (ADR-0004). A mandatory field would force the export to
insert something, and an inserted verdict would be a claim about an outcome
nobody observed. 11a decided exactly the same question about the timestamp — *"The
export inserts nothing where nothing stands"* — and the answer is the same here.

The key is then **absent** entirely rather than `null`: "not known" and "the
verdict null" have to produce two digests, as already do the presence and absence
of time in `seal`.

`digest_of` and `seal` stay **unchanged**. The payload is a string, and what
stands in it is decided by its producer — the DST evidence is therefore
unaffected, and the report from 11c stays byte for byte the same.

The archive line is from here on a `Record` and no longer a pair — and that
closes a second, smaller gap that came to light while measuring. `Record` carries
`deny_unknown_fields`; the `#[serde(flatten)]` in `Line` cancels it:

| Read as | Line with a foreign field | Verdict |
|---|---|---|
| `Record` | `…,"outcome":"applied"` | **refused** |
| `Line` | `…,"outcome":"applied","fremd":1` | **accepted** |

An archive line can therefore today carry arbitrary further fields without
anything standing out — unsealed, and for a reader indistinguishable from the
sealed ones. Without the wrapper the strictness takes effect again, for which it
was written down.

With that a segment from the archive says something different from one from the
export, and rightly so: the one attests *"this attempt had this outcome"*, the
other *"this command stood at this place in the log"*. Both statements are true,
and neither passes itself off as the other.

### 2. The payload is "what happened at this index", not "which command arrived"

That is the conceptual shift, and it belongs spoken out loud. `Event` was more
than the command even before this decision: it carries log index and term, i.e.
the placement in consensus. The outcome belongs to the same statement. An audit
record that attests the attempt and leaves the outcome open attests half the
event.

`Record::payload` stays, in its description, "the wire representation" — what
changes is the scope of the event, not the encoding. The command in it is still
byte for byte the one from the log (ADR-0020).

### 3. No compatibility path, and that is a finding

`Record` carries `deny_unknown_fields`, and that takes effect again without the
wrapper (determination 1). An archive line of the old form has a field `outcome`
at the top level and is from here on **no longer read** — measured: read as a
`Record` it is refused. `Archive::open` then refuses to continue, `tgctl audit`
reports an error.

That is bearable because there is no shipped archive: what lies on development
machines is test material. A read path for the old form would be code serving a
data situation that does not exist — and it would permanently have to distinguish
two meanings of "verdict": a sealed one and an unsealed one. Exactly that
distinction is meant to disappear.

The rule for later is the inverse of this: **after the first rollout this change
is no longer a change to the format but a migration with an obligation to provide
evidence.** It therefore belongs done now.

### 4. Determinism: what goes into the digest has to arise identically everywhere

`serde_json` is built without `preserve_order` (checked), so the object mapping is
a `BTreeMap` and the key order is sorted and stable. Together with the
determination from ADR-0004 — the same apply on every node produces the same
`Outcome` — the payload arises byte for byte identically on all five nodes.

That is not an aside: were it to arise differently, five nodes would have five
different chains over the same history, and the comparison of two replicas — the
second half of the proof against truncation at the end — would no longer be
possible.

### 5. The caveat in `tgctl audit` is retracted, not left standing

As soon as the verdict is sealed, the line "(not covered by the chain)" is wrong.
A warning that is no longer true costs the credibility of all the others next time
— the same reason for which the outdated `--keep-logs` note was retracted in 11b.
The test that pins the gap becomes the test that pins its closure: the same
rewriting must from here on produce a finding.

## Consequences

**Positive**
- The claim from ADR-0020 holds without exception: what stands in the archive —
  attempt **and** outcome — is protected against modification, reordering and
  excision.
- `digest_of` stays untouched; the DST evidence from 11c is unaffected, and there
  remains **one** verification procedure.
- One type fewer (`Line`), and `deny_unknown_fields` on `Record` takes effect
  again: an archive line can no longer carry unnoticed extra fields.

**Negative / Costs**
- **The verdict is harder for a human reader to see.** It now lies in the
  payload, i.e. in a JSON string inside the line, instead of as a field of its
  own next to it. The way out is a tool that extracts it — `tgctl audit` has the
  place for that — not a second, unsealed copy on top.
- **Archives of the old form are no longer read.** See determination 3.
- The archive line gets longer, and the verdict is doubly encoded (JSON in JSON).
  That is the price of not touching `digest_of`.

**Risks & Open Points**
- **What is not yet in the chain belongs checked.** This decision closes a gap
  found by looking, not by a systematic survey. What stays open is whether there
  are further fields that lie next to the digest and claim something — in today's
  state `outcome` is the only one, but the question is now asked once and not
  permanently answered.
- **The head comparison stays the other half.** A chain does not catch truncation
  at the end; only comparison with the next segment's anchor or with a running
  replica catches that (11a). This decision changes nothing about it.
- **Retention is still open** (ADR-0020, phase 11a): storage, rotation and
  periods in the WORM archive are operational work and are not built.

## Related ADRs

- Depends on: ADR-0020 (the audit trail as a WORM substrate), ADR-0024 (traceable
  timestamps), ADR-0004 (deterministic apply)
- Affects: ADR-0020 — the promise "tamper-evident" is only fully redeemed with
  this decision; the implementation of 11a is corrected, not replaced
