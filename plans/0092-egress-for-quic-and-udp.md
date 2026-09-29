# ADR-0092: Egress for QUIC and UDP

- **Status:** accepted
- **Date:** 2026-09-06
- **Deciders:** Architecture
- **Technical context:** `tg-proxy`, `tg-net`, `tg-agent`, ADR-0041, ADR-0074,
  ADR-0075

> **Supersedes ADR-0075.** Its decision ("UDP outbound stays forbidden") no longer
> holds; its measurement of the protocol-by-protocol need stays valid and is carried
> forward here.

## Context and Problem Statement

ADR-0075 forbade UDP outbound for mesh members and justified it with a measurement:
the need was protocol by protocol empty or had a TCP path. Two things about that
decision no longer hold.

### The perverse incentive is the real danger

ADR-0075 names it itself and lets it stand: *"Whoever needs UDP outbound leaves out
`<mesh>`."* Measured, that costs not only the UDP block:

| What falls away with `<mesh>` | ADR |
|---|---|
| mTLS on the data plane | 0007 |
| the `may_talk` authorization | 0025 |
| the egress allowlist for **TCP** | 0041 |
| the enforcement of the active role | 0066 |
| the UDP **inbound** filter | 0074 |

To speak NTP, an operator gives up that workload's **entire zero-trust data plane**.
The situation is therefore worse than a coarse permission: ADR-0019's sentence — *"a
perimeter boundary one can circumvent by forgoing enforcement is none"* — hits not the
missing permission but the lever ADR-0075 leaves as the only one.

### And option C was rejected on a false assumption

ADR-0075 writes that a QUIC-aware egress *"requires a QUIC stack in the data path
(`quinn-proto` or similar, ADR-0023)"*. **Measured, it does not.**

`ring` 0.17.14 is in the tree through `rustls` anyway (invariant 3) and brings a module
made for exactly this:

```text
Initial keys from the DCID (RFC 9001 A.1)
  key = 1f369613dd76d5467730efcbe3b1a22d   expected: the same
  iv  = fa044b2f42a3fd3b46fb255c           expected: the same
  hp  = 9f50449e04a0e810283a1e9933adedd2   expected: the same

Header protection (ring::aead::quic, RFC 9001 A.2)
  mask = 437b9aec36                        expected: the same
```

What remains is a **parser and a datagram relay with a flow table** — no QUIC stack, no
connection management, no congestion control. And **zero new crates**; the supply-chain
justification from ADR-0023 falls away.

### And QUIC does not go away

ADR-0075 rests on QUIC being *opportunistic*: every client falls back to TCP, because
Alt-Svc is only an offer. That holds for clients dialling a web server. It does not
hold for a workload whose library or counterpart presupposes QUIC — and the direction
is unambiguous. A decision resting on "it will fall back" is one with an expiry date.

## Decision Drivers

- **A circumventable perimeter is none** (ADR-0019) — and today the detour is *wider*
  than the hole it circumvents.
- **ADR-0041's trust boundary is the name**, not the address. Where a name stands in
  the packet, it has to be used.
- **Where no name stands in the packet**, there is no name-based mechanism — then the
  question is not "name or address" but "address or nothing at all", and "nothing at
  all" today means "entirely without enforcement".
- **Invariant 6:** ADR-0075 is accepted. It is superseded by this ADR, not by drift.

## Options Considered

1. **Stay with ADR-0075.** Rejected: the incentive stays, and the justification for
   option C is measurably false.
2. **Only a narrower lever** (`<mesh udp="…"/>`): cheap, keeps the rest of the
   enforcement, but gives the workload *all* UDP without reference to destination and
   port — and belongs in the XSD, while ADR-0041 determination 3 explicitly carries
   egress as a **command**. Rejected as an end state, see determination 7.
3. **Only the address path** for all UDP, QUIC included. Rejected: it would give QUIC
   the coarser treatment although the name stands in the packet.
4. **Both, separated by transport.** Chosen.

## Decision

### Determination 1 — one allowlist, three transports

`AllowEgress` henceforth carries a **transport**:

```text
AllowEgress { workload, name, port, transport }
                                    ├─ tcp   → the sidecar reads the TLS SNI  (ADR-0041)
                                    ├─ quic  → the sidecar reads the QUIC SNI (new)
                                    └─ udp   → the agent resolves, nftables   (new)
```

For an operator it is **one** concept: a name, a port, a transport. A second command
next to it would be a second place at which the same question is answered — and the
sidecar would have to read both.

### Determination 2 — QUIC gets the same trust boundary as TCP

The sidecar reads the SNI from the initial packet, checks it against the allowlist,
**resolves the name itself** and relays the datagrams — without terminating the
session. That is ADR-0041 determinations 1 and 2 verbatim, only over datagrams:
checking the certificate against the endpoint's CA stays with the workload.

### Determination 3 — the `ClientHello` is not parsed ourselves

The reassembled CRYPTO payload is wrapped in a TLS record header and read by
`rustls::server::Acceptor` — the same seam as with TLS egress.

The reason stands in ADR-0041 and holds more sharply here: the bytes come from a
container, and a hand-written TLS parser is *"the kind of code one writes wrongly once
and never notices"*. What we write ourselves is the QUIC frame around it — and that
gets a fuzz run like every trust boundary.

### Determination 4 — CRYPTO reassembly is mandatory, not optional

A `ClientHello` today often does **not** fit into one initial: post-quantum key shares
burst the 1200 bytes an initial may carry before address validation. Whoever reads only
the first packet sees nothing for precisely the clients it affects first.

That includes: unpacking coalesced packets (one datagram carries initial and
handshake), ordering CRYPTO frames by offset, and an **upper bound** — a container
sending arbitrarily many fragments must not bind memory.

### Determination 5 — plain UDP by address, resolved by the **agent**

A `udp` entry becomes an nftables rule per workload whose addresses the **agent**
resolves through the node-local resolver and refreshes **level-driven per pass**
(ADR-0010).

That is the construction ADR-0041 rejected, and the difference is measured: there it
was about a **static** list and about resolution by the **container**. Here the agent
resolves, through the same resolver the sidecar already uses for TCP (`lookup_host` →
`resolv.conf` → ADR-0013) — so trust in our DNS is not new but the basis on which TCP
egress has stood since ADR-0041. And the list is not static: it follows the name at the
rhythm of the reconciliation.

The price stands here: **an address that changes owner within a refresh window stays
permitted for that long.** Bounded by the reconcile interval and the DNS TTL. For TCP
the same window exists between resolution and connection setup — the difference is its
length, not its kind.

### Determination 6 — the transport is explicit, not guessed

The transport is not inferred from a port. Whoever writes `udp` has **demanded** the
coarser enforcement, and the declaration stands in the audit trail (ADR-0020). A metric
counts the workloads with an address-based permission; it is the number an auditor
wants to see.

### Determination 7 — QUIC first, plain UDP afterwards

And that is explicitly a decision about the **order**, not about the scope. The address
path is the cheaper one; once there, it would be the path of least resistance —
whoever needs QUIC would permit `443/udp` by address, and the SNI path would never
arise. The other way round the address path is an honest fallback for the long tail.

Until the second cut stands, ADR-0075 still holds for plain UDP: forbidden, with the
counter as the diagnostic.

## Consequences

**Positive.** The detour of leaving out `<mesh>` loses its occasion, and the perimeter
becomes effective for the first time for the traffic that is growing. The trust
boundary stays the name.

**Positive.** Zero new crates. `ring::aead::quic` is the part one would otherwise write
oneself, and it is evidenced against the RFC's test vectors.

**Negative.** The data plane gains a second data path with state of its own (the flow
table). ADR-0022's tail target applies to it just the same, and measured it is not
there.

**Negative.** The `udp` transport is coarser than anything else in this system, and it
will be the one somebody uses because it is easier. Determination 6 makes that visible,
it does not prevent it.

**Neutral.** `AllowEgress` gains a field — a format break going into the same bundled
window as the seven before it (ADR-0072, determination 3).

## Risks & Open Points

- ~~**Connection migration breaks the flow association.** … The answer would be an
  association over the connection ID, and it is not built here.~~ — **decided:
  ADR-0131**, and it is not *not built* but **not buildable**: a short header does not
  encode the CID length (the long header has a length byte, the short header none), and
  the CID a migrating client takes is announced in 1-RTT-protected frames — this relay
  derives exclusively **initial** keys, because it does not terminate (ADR-0041).
  Migration is therefore permanently refused; whoever needs it takes TCP. From here on
  it is visible as `reason="not_initial"`.
- ~~**Retry and version negotiation.** … To be decided while building.~~ — **measured:
  ADR-0131.** A `Retry` **after** the decision goes out as `Established`; **before** it
  costs a round trip and reaps its flow (`undecryptable`), the next attempt starts
  cleanly and consumes no second slot. It is therefore not handled. A version we do not
  read is from here on called `reason="version"`, and **which one** stands in the log —
  QUIC v2 (RFC 9369) stays unbuilt, because there is no capture for it and therefore no
  witness.
- **0-RTT is covered**, but only because the `ClientHello` lies in the initial there
  too. A future mode carrying it elsewhere would have to be re-examined.
- **The reassembly's upper bound** is a number with a justification and not a
  measurement, until one exists.
- **Who may grant a permission** stays the same question as in ADR-0041 and ADR-0044:
  whoever reaches the admin socket may do everything.
- **ADR-0075's option D stays empty, not wrong:** if a second node-local UDP service
  arrives, the exception from ADR-0074 is already there.

## Related ADRs

- **Supersedes ADR-0075** — its decision falls away, its protocol-by-protocol
  measurement stays and is carried forward with QUIC.
- **Applies: ADR-0041** — names instead of addresses, resolve ourselves, do not
  terminate; and egress is a command, not a schema field.
- **Depends on: ADR-0074** — the filter chains in the namespace in which the exceptions
  sit; **ADR-0038** (`nft` as a separate process); **ADR-0013** (the resolver through
  which resolution happens).
- **Touches: ADR-0023** — the supply-chain justification against option C is moot, no
  crate is added; **ADR-0022** — the second data path stands under the same tail
  target; **ADR-0072** — the field on `AllowEgress` is a format break for the bundled
  window.
