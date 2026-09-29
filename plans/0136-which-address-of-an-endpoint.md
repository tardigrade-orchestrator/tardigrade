# ADR-0136: Which Address of an Endpoint

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0041 (egress by name), ADR-0092/0094 (QUIC outwards),
  ADR-0012 (the overlay is IPv4), ADR-0013 (the resolver and AAAA)

## Context and Problem Statement

IPv6 has stood as an open point in three ADRs since ADR-0012 ("the overlay is
IPv4, and the question arises with it"). Measured, the question has long been
answered — only at the wrong place, and silently.

### The measurement

```text
localhost: 2 addresses, first = Some([::1]:443)
     all: [[::1]:443, 127.0.0.1:443]
Resolver::System(localhost) = Some([::1]:443)
```

`Resolver::resolve` reads `lookup_host((host, port)).await.ok()?.next()` — the
**first** address. And the connector tries exactly that one:

```rust
let Some(address) = resolver.resolve(&host, port).await else { return Ok(()) };
let mut upstream = match timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(address)).await {
    Ok(stream) => stream?,
    Err(_) => return Ok(()),
};
```

No second attempt. The same in the QUIC path (`quic_egress::relay`).

### What that means

**An endpoint with an AAAA record is a silent egress failure** — even if it has
a flawless A record. The container namespace gets its address from the IPAM
(ADR-0012, phase 9a) and has **no** IPv6 address and no IPv6 route; a connect
there ends in `ENETUNREACH`, and what the container learns of it is silence
(ADR-0041).

Dual stack is not the exceptional case here but the normal one: S3, registries,
every larger API.

**And the second half applies without IPv6:** an endpoint with several A
records — exactly the construction with which an operator catches outages —
gets **one** attempt from us. If the first address happens to be dead, the way
outwards is closed, although three others would answer.

### Why nobody noticed

The egress witnesses (ADR-0041, ADR-0092) pin an endpoint to exactly one
address: `Resolver::Pinned` maps name → `SocketAddr`. That is right for what
they check — the **decision**, not the selection — and therefore a list never
occurred there.

## Decision Drivers

- **What the container learns is silence** (ADR-0041). Every failure on this
  path must therefore be visible elsewhere.
- **An address that has no route in the namespace is not a choice.** Trying it
  costs a deadline and ends the same way.
- **The overlay is IPv4** (ADR-0012), and that is a decision, not a gap — it
  simply stands nowhere for the egress path.
- **Several A records are a promise of the endpoint**, not a coincidence.

## Options Considered

- **A — leave everything** and pass IPv6 on as an open point. The dual-stack
  case stays a network problem that is none.
- **B — try all addresses**, in the resolver's order. Fixes both, but pays a
  deadline per unreachable address.
- **C — B, and sort out addresses without a route beforehand.** As long as the
  overlay is IPv4, an AAAA is not a choice.
- **D — build IPv6.** Overlay, IPAM, rule set, resolver, `AllowedIPs`: a cut of
  its own, and ADR-0012 did not provide for it.

Chosen is **C**. **D** stays open and is from here expressly named.

### Determination 1 — the sidecar chooses among all addresses

`Resolver::resolve` gives the **list**, and the connector goes through it in
order until a connection stands. The order is the resolver's (RFC 6724 sorts it
where the source addresses are known); we do not re-sort, we only skip what does
not work.

**The deadline applies per attempt** (`HANDSHAKE_TIMEOUT`), and the number of
attempts is bounded by the resolver's answer. An endpoint that names twenty
addresses costs twenty deadlines in the worst case — that is the cost side, and
it hits exactly the case in which today nothing works at all.

### Determination 2 — IPv6 addresses fall away before they cost anything

As long as the overlay is IPv4 (ADR-0012), a container has no IPv6 address and
no route there. An AAAA is therefore not a choice but a deadline with a known
outcome.

It is **discarded and counted**, not tried. The filter sits in the resolver,
hence at **one** place for TCP and QUIC.

### Determination 3 — QUIC gets the selection, but no fallback

A `connect` on a UDP socket does not fail visibly — there is no handshake by
which one would notice that nobody is there. The QUIC path therefore takes the
**first usable** address and tries no second.

With that determination 2 takes full effect there (the AAAA falls away) and
determination 1 only by half. That is not negligence but the property of the
protocol: whoever wants to detect the loss must follow the QUIC handshake, and
that would mean terminating (ADR-0041, determination 1).

### Determination 4 — what was discarded and what was tried in vain is visible

Two numbers at the sidecar: how often an address fell away **because of its
family** and how often an attempt **failed** before a later one succeeded.
Without them "the endpoint is v6-only" is indistinguishable from a network
problem — and that was exactly the state.

### Determination 5 — IPv6 stays out, and from here it stands written

Not "not yet" but: **as long as ADR-0012 holds**. What it would take is
enumerated there (overlay, IPAM, rule set, `AllowedIPs`, resolver), and it is a
cut of its own.

What changes is the honesty at the edges: the address plan already rejects a v6
CIDR today with the right sentence ("is not an IPv4 CIDR"), the resolver answers
AAAA with NODATA (phase 9c), and the egress discards an AAAA visibly from here
instead of dialling into the void.

## Consequences

**Positive**

- **A dual-stack endpoint works.** That is the normal case, and it was broken.
- **Several A records do what they exist for.** A dead first one no longer
  costs a connection.
- **The v6-only endpoint is distinguishable** from a network problem.

**Negative / costs**

- **A failure can take longer.** Instead of one deadline, up to one per address.
  Today it ends faster — and wrongly.
- **The resolver gives a list**, and the witnesses that expected a `SocketAddr`
  now see a `Vec`. That is the rebuild this decision costs.
- **A v6-only endpoint stays unreachable.** It was before too; what is new is
  that one sees it.

**Risks & open points**

- **IPv6 as a whole** stays open (determination 5) and hangs on ADR-0012.
- **The order comes from the resolver.** We do not re-sort; whoever wants a
  preference of their own has a policy, and that does not belong in a sidecar.
- **The QUIC path tries only one** (determination 3). Whoever wants a fallback
  there needs a signal the protocol does not provide without terminating.

## Related ADRs

- **Answers** the egress half of the open IPv6 point from **ADR-0012**,
  **ADR-0094** and **ADR-0121** — with a decision, not with a deferral.
- **Supplements ADR-0041** (the sidecar resolves the name itself): *which* of
  the addresses it takes did not stand there.
- **Upholds:** **ADR-0022** (no effort in the hot path — the selection happens
  once per connection, not per byte).
