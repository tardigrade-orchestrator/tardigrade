# ADR-0131: Three Causes, One Label

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0092 (QUIC outwards), ADR-0121 (the metric on dropping),
  ADR-0041 (what a container learns), ADR-0015 (cardinality of a label)

## Context and Problem Statement

ADR-0092 left two open points, and both sounded like construction work:

> **Connection migration breaks the flow mapping.** … The answer would be a
> mapping over the connection ID, and it is not built here.
>
> **Retry and version negotiation.** … To be decided at build time.

Measured, the one is **not buildable**, the other carries itself — and what is
really missing stands in neither note.

### The measurement

Against the real captures from `data/` (ngtcp2 with OpenSSL 3.5) and a
synthetic short-header packet:

```text
1. decided:                    Forward { host: "s3.example.com" }
2. after the migration:        Refuse(Malformed)   open=1
3. QUIC v2 (0x6b3343cf):       Refuse(Malformed)
4. retry before the decision:  Refuse(Malformed)   open=0
5. retry after the decision:   Established
```

### The finding is the label

`QuicError` has **six** variants each with its own message; one of them even
computes the version into the text ("QUIC version `0x6b3343cf` is not read").
`Flows::absorb` maps them all onto `Refusal::Malformed`, and `relay` logs
`?reason` — that is, `Malformed`. **The diagnosis arises and is thrown away
before anyone sees it.**

What the manual says about it:

> `malformed` and `anonymous` mean that no QUIC client is speaking there.

Measured, `malformed` means three further things, and in all three a QUIC
client is very much speaking. What a container learns is silence (ADR-0041);
the metric is expressly the way to distinguish this silence from a network
problem (ADR-0121, determination 6). It distinguishes it — and then points in
the wrong direction in three cases.

### Migration: not construction work but an impossibility

The answer ADR-0092 suggested — mapping over the connection ID — cannot exist
for this relay, and for two reasons, both readable from our own code:

- **A short header does not encode the CID length.** `LongHeader::parse` reads
  it via `r.cid()`, because in the long header a length byte precedes it. In the
  short one there is none: whoever wants to read the DCID must already know its
  length.
- **The CID a migrating client takes we never see.** It is announced in
  `NEW_CONNECTION_ID` frames, and those are 1-RTT protected. This relay derives
  exclusively **Initial** keys (`initial_keys(dcid)`) — it does not terminate
  (ADR-0041, determination 1), so it has no others.

Both together mean: the mapping over the CID is not "not built", it is not
buildable without giving up the property for the sake of which the path exists.

### Retry: carries itself

After the decision the flow is `decided`, a second Initial goes out as
`Established` (measurement 5). Before it, it costs one round trip: the new DCID
does not match the keys from the old one, the flow is cleared away (`open=0`,
measurement 4), and the client's next attempt begins cleanly. That is not a
pretty but a self-healing sequence — and it consumes no slot.

### QUIC v2: buildable, not checkable here

RFC 9369 changes the version number, the Initial salt, the type codepoints and
the HKDF labels. That is manageable — and there is **no capture** against which
to check it: the fixtures come from `curl --http3-only` over ngtcp2
(`data/PROVENANCE.md`), and this tree does not produce a v2 flow.

A cryptographic path in the data path without witnesses is exactly the kind of
code ADR-0041 means about the hand-written TLS parser: written wrong once and
never noticed.

## Decision Drivers

- **A metric that exists so that silence can be interpreted must interpret it
  correctly** (ADR-0121, determination 6).
- **A note "not built" and a note "not buildable" are two different things.**
  The first invites another attempt.
- **One derivation, one place** (ADR-0069): the label belongs to the error that
  produces it, not in a second list beside it.
- **A label may take only values whose number the cluster bounds** (ADR-0015).
  A version number is a number from a container.
- **What cannot be checked is not built** — but one can measure whether anyone
  needs it.

## Options Considered

- **A — leave everything and sharpen the notes.** Free, and the metric keeps
  pointing elsewhere in three cases.
- **B — the label follows the cause**, the version goes into the log, and
  migration is set down as impossible instead of unbuilt.
- **C — B, plus build QUIC v2.** A cryptographic path without witnesses.
- **D — attempt migration via the CID.** Measured to be barred.

Chosen is **B**.

### Determination 1 — the label comes from the error

`Refusal::Malformed` becomes `Refusal::Unreadable(QuicError)`, and the label
value arises from `QuicError` itself — an exhaustive `match` at **one** place.
The values are therefore: `not_initial`, `version`, `malformed`,
`undecryptable`, `too_much`, `not_tls` — plus the existing `not_allowed`,
`anonymous` and `too_many`.

Nine values, all bounded by the code, none from a datagram. With that the rule
from ADR-0015 holds, and the table in `tg_telemetry::names` gets the new number.

### Determination 2 — the version stands in the log, not in the label

`UnsupportedVersion(u32)` carries a number a container chooses — as a label it
would be a memory leak with a Prometheus connection (ADR-0015, the same
justification as with the SPIFFE IDs). Into the log it very much belongs: the
sender address stands there anyway, and without the number "version is not
read" is no information.

From here what is logged is the **message** of the `QuicError` and not the name
of its variant. It already existed; nobody read it.

### Determination 3 — connection migration is refused, permanently

Not deferred. The justification stands above and hangs on two properties that
will not change as long as this relay does not terminate: a short header does
not name its CID length, and the CID after a migration travels 1-RTT protected.

It is visible from here nonetheless: a migrating client produces
`reason="not_initial"`, and that is a different number from "no QUIC client is
speaking there".

**Whoever needs migration takes TCP** — the same answer ADR-0075 gave for plain
UDP, and for the same reason: the path exists, it is just not this one.

### Determination 4 — retry stays as it is

Before the decision it costs one round trip and clears away its flow;
afterwards it goes out as `Established`. Handling it would mean leading the
reassembler over two key derivations — for a sequence that heals itself in one
round trip and consumes no slot.

From here it is distinguishable (`undecryptable`) and thereby no longer a
riddle.

### Determination 5 — QUIC v2 is not built, and the number decides it later

The point stays open — but no longer blind. `reason="version"` says whether in
this installation anyone at all speaks a version we do not read, and the log
says which.

The same movement as with auto-detach (ADR-0057) and the changed declaration
(ADR-0070): instead of guessing, make visible — and then an observation decides
and not a presumption.

## Consequences

**Positive**

- **The metric from ADR-0121 interprets again what it is supposed to.** It
  exists so that an operator can distinguish silence from a network problem; in
  three of five measured cases it turned them away.
- **The version reaches a human.** The text had stood in the code since
  ADR-0092 and had no reader.
- **One open point becomes a decision** (migration) and one becomes an
  observation (v2). Both are less than a note someone eventually re-examines.

**Negative / costs**

- **Nine values on a label instead of four.** That is more cardinality, and it
  is bounded: the cluster cannot produce a tenth.
- **`Refusal` now carries an error.** Whoever matched on `Refusal::Malformed`
  gets caught — those are the witnesses, and that is the purpose.
- **Migration stays broken**, now with a justification. For egress from a
  container the case is rare; it is not rare because we solve it.

**Risks & open points**

- **QUIC v2 is not built** (determination 5). What is missing is a capture;
  whoever can produce one thereby has the witness that carries the build.
- **Version negotiation in the narrower sense** — an endpoint that answers with
  a VN packet — traverses the relay unchanged; the client then chooses a
  version, and whether we read it is decided by determination 1.
- **0-RTT stays covered** as in ADR-0092: the `ClientHello` lies in the Initial
  there too.

## Related ADRs

- **Decides two open points from ADR-0092:** connection migration (permanently
  refused, with a reason) and retry (unchanged, now distinguishable).
- **Redeems what ADR-0121 determination 6 promises:** a number with which
  silence can be interpreted.
- **Applies:** **ADR-0015** (cardinality), **ADR-0069** (one derivation, one
  place), **ADR-0057/0070** (make visible instead of guessing).
- **Delimits itself against ADR-0041:** what the **container** learns stays
  silence. Only the node's log becomes more detailed.
