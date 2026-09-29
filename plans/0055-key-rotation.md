# ADR-0055: Key rotation — as desired state, not as a shout

- **Status:** accepted
- **Date:** 2026-08-26
- **Deciders:** Core team
- **Technical context:** `tg-consensus` (command set, state), `tg-identity`
  (`control`), `tg-agent` (`join`, `underlay`), ADR-0039, ADR-0037, ADR-0042,
  ADR-0046, ADR-0054, ADR-0043

## Context and Problem Statement

Two keys per node, and **neither of them is ever replaced**:

| Key | What for | Who checks it | Ever replaced |
|---|---|---|---|
| Ed25519 (`node.key.pem`) | the node's identity (ADR-0037), mTLS on the cluster transports (ADR-0043) | `state.trust(node)` | **never** |
| X25519 (`underlay.key`) | the `WireGuard` underlay (ADR-0039) | the peers, from the slice | **never** |

Measured: `node_key` and `underlay_key` read the file when it is there and
generate only when it is missing. There is no path that replaces an existing key.
ADR-0039 names that as an open point; ADR-0043 says it for the other key in the
same words ("rotation is therefore replacement and shares the open spot with
ADR-0039").

For operation under DORA that is the wrong state: a key without a replacement
path is one whose compromise can only be answered by re-admitting the node — and
with the ordinal that is a renumbering (ADR-0039).

The obvious construction is a **shout**: "rotate now". It is wrong, and for the
same reason ADR-0054 built detach as a state: an event gets lost if the node does
not hear it, and then one needs a catch-up protocol for something that needs
none.

## Decision Drivers

- **ADR-0004:** intent into the log, observation into the projection.
- **ADR-0010:** level-triggered, not edge-driven.
- **ADR-0042:** the announcement travels on the credential path — the one way on
  which the node identifies itself anyway.
- **ADR-0046:** the signature covers the **request**, not an enumeration.
- **ADR-0054:** a detached node is out of the data plane.
- **ADR-0019:** a node without a control plane carries on.

## Options Considered

- **A — a generation per node and key kind in the log**, the node compares and
  follows.
- **B — an event** ("rotate") over the credential path.
- **C — by the clock**, without a log: every node rotates by itself every N days.
- **D — nothing;** rotation stays replacement with re-admission.

### Why not B

It gets lost. A node that is currently away never rotates, and nobody sees it —
after being uttered the intent exists nowhere any more. ADR-0054 rejected exactly
this construction for detach.

### Why not C

Because a rotation is then **nobody's decision**. Five nodes rotate at five
different times, an auditor cannot say which key was valid when, and an incident
("this key is compromised") cannot be answered, only waited out. Besides: what
happens by the clock also happens while the cluster is busy surviving something
else.

### Why not D

A key without a replacement path is a finding, not a state.

## Decision

Chosen: **Option A.** The desired key generation stands in the log, the node
compares it with its own and follows.

### 1. One number per node and key kind

`SetKeyGeneration { node, kind, generation }` with
`kind ∈ { Identity, Underlay }`. Two numbers and not one: the two keys rotate for
different reasons, and one should not drag the other along — a compromised
underlay key is no reason to re-register the node's identity.

Monotonic: a generation is only **raised**. Turning it back would mean making an
old key valid again, and that is not a state an operator should be able to
express.

A command of its own and not an extension of `UpsertNode` — the same
justification as with cordon and detach.

### 2. The node knows its own generation, and the comparison is everything

Next to every key lies its generation. If the desired one is higher, the node
generates a new key. No "rotate now" reception, no state "currently rotating", no
catching up: whoever was away compares on return.

### 3. Announce first, then switch — and that is the whole art

For the **underlay** key an order applies that must not be transposed:

1. generate the new key and put it **next to** the old one (not over it),
2. announce it (ADR-0042, on the credential path),
3. wait until it appears in its **own** slice,
4. **only then** switch the interface to it and throw the old one away.

The other way round the node cuts itself off before any peer knows about it. Step
3 is exactly the reconciliation ADR-0042 already built — it wakes the renewer when
log and announcement diverge, and after step 1 they diverge. Rotation therefore
needs no trigger of its own.

The residual window is the spread with which the peers apply the same slice —
seconds, self-healing. **Detach makes it zero** (ADR-0054) but is explicitly
**not** prescribed: detach includes emptying, and emptying a node for a key change
would be a sledgehammer. Whoever does not want the window detaches beforehand;
whoever accepts it rotates in operation.

### 4. The identity key changes on the credential path, and the old one vouches

The request carries one more field: the SPKI of the **new** node key. It is signed
with the **old**, registered key; the server checks as always against
`trust(node)` and replaces the registration afterwards.

That is not a new mechanism but a consequence of ADR-0046: the signature covers
the **request**, so the new field is covered without further ado — and the
completeness test over the request's fields makes it red if somebody adds it and
does not touch `renew_message`.

There is **no** window here: the registration is an entry in the log, not
distributed state. After the apply the new key holds; the cluster transports read
the trust list from the log (ADR-0043) and follow.

**The old key vouches for the new one** — that is the only chain that works
without a ceremony. If the old key is lost, no rotation helps, only re-admission;
that is right and no gap.

### 5. How far the node has got is said by the projection

The node reports its generations in the `NodeReport` (observed state, ADR-0040
determination 7 untouched). From the difference to the desired generation a metric
arises per node and key kind — the same construction as `tg_node_attached`
(ADR-0054): it decides nothing, it shows.

Without it a rotation that does not reach one node would be invisible — and a
rotation one believes finished is worse than none.

### 6. Nobody rotates by themselves

There is **no** clock that raises the generation. Whether a policy should do that
("every 90 days") is the same question as in ADR-0049 and ADR-0054 determination 3
and is **not** decided here. As long as it is missing, a human rotates.

The reason is the same as there: what a clock triggers is nobody's decision, and
in an audit trail there then stands a rotation without a sender (ADR-0049 names
the price).

## Consequences

**Positive**
- Both keys have a replacement path that manages without re-admission and without
  renumbering.
- A rotation is a **decision** with a sender in the log (ADR-0020) and not a time
  of day.
- No new way out: everything travels on the credential path ADR-0042 chose.
- A node that was away during the rotation follows on return.

**Negative / Costs**
- **A protocol break on the request**, the fourth after ADR-0042, ADR-0046 and
  ADR-0050. It belongs in the same coordinated switchover.
- Two more numbers in the state and two more files on disk (the generation next to
  each key).
- The underlay change has a residual window if the node stays attached during it.
  It is small and named, but it is there.
- A half-rotated node is a state: new key generated, announcement not yet
  confirmed. It is harmless (the old one still holds) and nevertheless needs a
  name on disk.

**Risks & Open Points**
- ~~**Who may rotate?** Today: whoever reaches the admin socket (ADR-0044).~~ —
  **done:** ADR-0105.
- ~~**The policy from determination 6** is not decided.~~ — **done:** ADR-0057 —
  rotation by age, auto-detach rejected.
- ~~**The proof needs two nodes with real tunnels**: that the *other* node takes
  over the new key and that the tunnel carries again afterwards is netns work —
  the same lane on which ADR-0054 was evidenced.~~ — **done:** ADR-0055 is
  evidenced at the kernel.
- **The interplay with `RevokeTrust`** is to be clarified: a revocation during a
  running rotation may hit the key with which the node is about to vouch for its
  new one.

## Related ADRs

- Depends on: ADR-0037 (admission, trust), ADR-0039 (the underlay), ADR-0042 (the
  credential path carries events), ADR-0046 (the signature covers the request),
  ADR-0054 (detach makes the window zero), ADR-0040 (the slice)
- Closes the open point "key rotation" from ADR-0039 and the identically worded
  one from ADR-0043
