# ADR-0087: The base64 reader of the credential path

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture
- **Technical context:** `tg-identity` (`control`), `tgd` (`identity`), ADR-0037,
  ADR-0043, ADR-0023

## Context and Problem Statement

`tg_identity::control` writes base64 **by hand**, with the justification in the code:
*"the alphabet is shorter than the dependency"*. Measured, the justification is moot
— `tg_net::wireguard` uses the **crate** `base64` for the same task, and it is
therefore in the tree anyway. So the thing exists twice.

The place matters: `unbase64` decodes `spki`, `signature`, `intermediate_spki` and
`next_node_spki` from a `JoinRequest` or `RenewRequest` (four call sites in
`tgd::identity`), and this port demands **no client certificate** — ADR-0043
determination 3 cannot demand one, because `Join` is the call with which a node
obtains its first. That is this system's least authenticated trust boundary.

Measured, the two versions are **differently strict**:

| Input | hand-written | crate (`STANDARD`) |
|---|---|---|
| `QUJD` | `[65,66,67]` | `[65,66,67]` |
| `QUJD\n` | `[65,66,67]` | error |
| `QU JD` | `[65,66,67]` | error |
| `QUJD=` | `[65,66,67]` | error |
| `QUJ` (padding missing) | `[65,66]` | error |
| `QUJ=` | `[65,66]` | error |
| `QUJD!` | error | error |

From that follows the property at issue: **the hand-written version is not
injective.** Four different texts yield the same bytes. Today that is not
exploitable — the checks in the credential path compare **bytes**, and `RotateTrust`
compares text against text, i.e. in the safe direction. It is a trap for the next
person who builds a check on the text while another works on the bytes.

## Decision Drivers

- A **hand-written reader** at the unauthenticated boundary is exactly what an auditor
  in a REMIT/DORA environment reads as a finding — even when, as here, it is
  measurably correct.
- **One fact, two sources**: base64 exists twice in the tree, and the justification of
  the second version is measurably moot.
- **Injectivity** is the property whose absence hurts later.
- The **tolerance** has **no** user today, and that is measured:
  `NodeTrust::from_base64` reads `guard.trusted()`, i.e. the **log** — there stands
  what `spki_base64` produced, always correctly padded. All four call sites of
  `unbase64` read fields of a node's request. A path on which a **human** types base64
  does not exist.
  *(The first draft of this ADR claimed the opposite; on inspection that was false,
  and the line was corrected before adoption.)*
- ADR-0023: no new dependency without a reason. Here it is **none** — the package is
  in the tree, an edge would be added.

## Options Considered

- **Option A — leave everything.** The fuzz run now covers the reader; the duplication
  stays, the justification in the code stays false.
- **Option B — switch strictly to the crate** (`STANDARD`, padding mandatory).
  Injective, one reader fewer — and an operator who puts down a wrapped line gets an
  error where today it works.
- **Option C — strip whitespace, then decode strictly.** Keeps the tolerance a human
  needs and loses the one nobody needs.

## Decision

Chosen: **Option C.**

1. **Encoding and decoding use the crate `base64`**, alphabet `STANDARD` with padding.
   The hand-written versions go away. The **encoder's output is byte for byte the
   same** as before — re-measured on the edge cases; the switch changes nothing that
   goes on the wire or stands in a file.
2. **Whitespace is removed before decoding**, and nothing else. That costs nothing and
   keeps open the case that does **not** exist today: a value a human types or pastes.
   A line break there is formatting and not an attack, and a refusal for it would be
   the kind one hunts for a long time in production. Being strict where nobody types
   buys nothing by contrast.
3. **Missing or surplus padding is refused**, as is any character outside the alphabet.
   That is the behavioural change, and it is the purpose: apart from formatting, every
   value has exactly one text.
4. **The error message stays its own**, short and without quoting the input — the
   finding from `tg-wire`: otherwise the sender determines the length of our answer.
5. **The fuzz run stays and gets sharper**: the invariant "a character outside the
   alphabet is refused" becomes "**everything that is not whitespace and does not
   belong to the alphabet is refused — and the length of the cleaned input is
   divisible by four**".

## Consequences

**Positive**

- One hand-written reader fewer, and at the place with the least authentication.
- The mapping text → bytes is **injective** apart from whitespace.
- The duplication in the tree is gone; `base64` is the same package in both places.

**Negative / Costs**

- **A behavioural change at a trust boundary.** A text without padding or with one `=`
  too many was accepted until now and is refused. Affected are only hand-written
  values — what this system produces itself is always correctly padded.
- One more edge on `tg-identity` (no new package).

**Risks & Open Points**

- The behavioural change affects **nobody** today — there is no path on which a human
  enters base64, and what this system produces is correctly padded. It counts for the
  day there is one.
- A **node** writing its request with its own lax base64 implementation is refused from
  here on where it previously got through. For a `tg-agent` that does not apply (it
  uses the same function); for a foreign client against the credential port it does.
- `tg_net::wireguard` still uses its own engine instance. Merging them would mean an
  edge from `tg-net` onto `tg-identity`, and the direction is wrong — both use the same
  package, and that suffices.

## Related ADRs

- **ADR-0037** — the credential path whose fields are read here.
- **ADR-0043** — determination 3: this port demands no client certificate.
- **ADR-0023** — supply chain: no new package, one edge.
