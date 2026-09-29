# ADR-0046: The signature covers the request, not a list

- **Status:** accepted
- **Date:** 2026-08-24
- **Deciders:** Core team
- **Technical context:** `tg-identity` (`control`), `tgd` (`identity`),
  `tg-agent` (`join`), ADR-0037, ADR-0042

## Context and Problem Statement

ADR-0042 determination 2 reads *"The signature covers what it authorizes"*, and
it **enumerated** the scope: *"What is signed is therefore nonce ‖ key ‖
endpoint."* `renew_message` is built exactly that way.

While checking whether further fields lie next to a digest and claim something
(the question ADR-0045 raises), the enumeration turned out to be incomplete:

| Field in `RenewRequest` | Covered by the signature |
|---|---|
| `nonce` | yes |
| `underlay.key`, `underlay.endpoint` | yes (ADR-0042) |
| `node` | **no** |
| `intermediate_spki` | **no** |

`node` is harmless in this, and that belongs said so that attention goes to the
right place: it selects the key to check against. A wrong entry fails the check
instead of circumventing it.

`intermediate_spki` is the opposite of harmless. It is the key for which `tgd`
issues the **agent intermediate** — i.e. the authority to mint workload SVIDs
(ADR-0006). It is read **after** the signature is checked, and is not covered by
it.

And it was already there when ADR-0042 was written. So it is not that a new field
grew past an old signature — **the enumeration was incomplete from the start.**

## The finding and its mitigation, both measured

It is **not** exploitable today, and an ADR that conceals that drives effort to
the wrong place:

- `Cluster::open_channel` in the agent builds the channel with
  `verifying_client_config` — `tgd` is checked against
  `identity/control-plane.pem` (ADR-0043, determination 3).
- `read_anchors` fails **hard** if the file is missing: *"no anchor, no session"*.

The transport is therefore server-authenticated and fail-closed. Whoever can set
the field is the authenticated node itself — and it may choose its intermediate
key freely; that it is a fresh one every three hours is exactly what ADR-0014
says.

The finding is therefore not a hole but something else that deserves attention
just as much: **a security property that depends on a transport assumption
written down nowhere.** Exactly that kind of assumption ADR-0043 exposed as false
elsewhere — `tg-consensus::net` claimed in its module header that the WireGuard
underlay protected the Raft port, and measured, the route never existed. An
assumption nobody has noted is one nobody can check when it changes.

## Decision Drivers

- **The same mistake twice.** ADR-0042 added the endpoint, now
  `intermediate_spki` is missing. A decision that merely adds the second field
  sets the same trap up again for the third.
- **The discipline belongs in the structure, not in diligence.** The same
  argument as with the `NonceVault` (phase 7b): a rule a caller **must** observe
  is one that somebody eventually does not observe.
- **Length prefixes stay.** Without them two different requests could be brought
  to the same bytes (ADR-0042, phase 11a).
- **The change is a protocol break anyway.** ADR-0042 made one and noted it as
  operational work. A second costs nothing extra as long as it comes in the same
  move — later it costs one of its own.

## Options Considered

- **A — add `intermediate_spki` to the enumeration.** One more field in
  `renew_message`.
- **B — change nothing, write down the transport assumption.** A sentence in the
  module header and a line in the ADR.
- **C — the signature covers the whole request**, formed from the request itself
  instead of from a list in the author's head.
- **D — sign canonical JSON of the request.** Serialize the structure, signature
  over that.

### Why not A

It remedies the finding and leaves the cause standing. The cause is the
**enumeration**: `renew_message(nonce, underlay)` does not see the request but
two parts picked out of it. Whoever adds the third field has to know by
themselves that it has to go here too — and ADR-0042 precisely did not know that
twice.

### Why not B

Writing it down is right and not sufficient. The assumption holds today; it no
longer holds if the join path should ever bootstrap without an anchor, and that
question is open (ADR-0043 names distributing the leaves as operational work). A
signature that covers what it authorizes is independent of that question — and
independence is cheaper than vigilance.

### Why not D

It would be the structurally tightest path and hangs security on the stability of
a serialization. With `serde_json` without `preserve_order` the key order is
sorted, so unambiguous today — but "unambiguous today" is no foundation for a
signature check, and ADR-0042 chose length prefixes for exactly that reason.
Besides, the signature field itself would have to be cut out, and a request
without that field is a second type that has to stay in sync with the first.

## Decision

Chosen: **Option C** — the signature covers the request, and completeness is
checked rather than observed.

### 1. `renew_message` gets the request, not its parts

```rust
pub fn renew_message(request: &RenewRequest) -> Vec<u8>
```

Covered from here on are all fields except `signature` itself: `node`, `nonce`,
`intermediate_spki` and the announcement. Still length-prefixed, still with a
marker byte for the presence of the announcement — a request with and one without
have to produce two different byte sequences (ADR-0042).

`node` is covered too, although it is harmless. Leaving out a field because one
has just reasoned about its harmlessness is the mode of thinking that led to this
ADR.

### 2. Completeness is a test over the fields, not over a list

The actual content of this decision. A test serializes the request, walks over
**its own keys** and modifies one after another; every modification has to break
the check — except for `signature`.

With that the assurance is not "the author thought of all the fields" but "no
field of this request is uncovered", and it holds **also for fields that do not
exist yet**: whoever adds one and does not touch `renew_message` makes this test
red. That is the same construction as the `NonceVault` in 7b — the property lies
in the structure, not in the caller's diligence.

### 3. The transport assumption is written down nonetheless

Option B was not wrong, only insufficient. That the join and renew path requires a
checked anchor and does not come about without it stands in future where it is
needed — at `renew`, not only in ADR-0043 — because it is the property on which
the confidentiality of the request rests. The signature makes it dispensable for
**integrity**, not for confidentiality.

### 4. `JoinRequest` stays unsigned

Unchanged, and for the reason already in ADR-0042: the join is carried by the
token, and whoever can modify the request can just as well swap the `spki` — then
they *are* the node. A signature would there be a ritual without a key to check
it against.

## Consequences

**Positive**
- No statement in the renewal request is uncovered any more, `intermediate_spki`
  included — and with that the integrity of the request no longer hangs on a
  transport assumption.
- The trap is closed, not the hole patched: a future field without coverage makes
  a test red.

**Negative / Costs**
- **A protocol break**, the second after ADR-0042. A node of the old and a `tgd`
  of the new version talk past one another; the switchover has to be coordinated.
  A test of its own pins it down so that nobody later takes it for an oversight.
- The bytes to be signed are longer. That is not measurably expensive: one
  Ed25519 signature every three hours per node.

**Risks & Open Points**
- **The test checks the fields the request has.** A field that is not serialized
  (`skip_serializing`) does not appear to it — in today's state there is none, and
  the possibility is hereby named.
- **`ChallengeRequest` stays without a signature.** It requests a nonce and does
  nothing else; a forced nonce is not damage but the normal case. If it ever
  carries an effective statement, this decision applies to it too.

## Related ADRs

- Depends on: ADR-0037 (node attestation), ADR-0042 (the signature covers what it
  authorizes), ADR-0043 (anchors on the join path)
- Affects: ADR-0042 — its determination 2 goes from an enumeration to a property;
  ADR-0037, as already with 0042, in the scope of the signature
