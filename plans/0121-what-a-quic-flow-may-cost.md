# ADR-0121: What a QUIC Flow May Cost

- **Status:** accepted
- **Date:** 2026-09-12
- **Concerns:** ADR-0094 (the flow limits), ADR-0092 (the retained datagrams),
  ADR-0086/0067 (the sidecar's memory limit), ADR-0012 (the overlay's MTU),
  ADR-0019 (the keystone)

## Context and Problem Statement

ADR-0094 built the QUIC egress and left an open point:

> **The limits from determination 5 are starting values.** How many flows a
> sidecar should carry depends on the data plane and is not measured.

Measured, the question is posed wrongly. **A limit on the number of flows is
not a limit on memory**, because a flow does not cost what it costs but what
the sender lets it cost.

### The measurement

Real sockets, real captures (`data/named_*.bin`, ngtcp2/OpenSSL 3.5), `serve`
unchanged; RSS per flow, linear over 64/128/256/512 flows:

| per flow | today | counter-check with 2 KiB |
|---|---|---|
| endpoint silent | 19.4 KiB | 7.4 KiB |
| endpoint answers | 68.2 KiB | 7.4 KiB |
| **hangs** (8 × 65 000 B, never decides) | **510.1 KiB** | **18.3 KiB** |

At `MAX_FLOWS` = 512 that is **255 MiB** — per listener, held for a minute
(`IDLE`), without a single file descriptor going outwards, and without any
privilege: the container sends eight datagrams per source port and then stays
silent.

Three causes sit in it, and all three are the same one:

1. **`MAX_PENDING` counts datagrams, not bytes.** ADR-0092 determination 4
   rightly requires that the fragments of a `ClientHello` be retained —
   discarding them would take their connection from every client with
   post-quantum key shares. Eight is generous. Eight **times 64 KiB** is half a
   megabyte, and the number eight does not say so.
2. **The return path allocates `vec![0; 65_535]` per flow.** As long as nothing
   comes back it is merely virtual; **one** large datagram makes it resident,
   and it stays so until the flow drops. That is the jump from 19.4 to
   68.2 KiB.
3. **`MAX_FLOWS` applies per listener.** One listener per permitted port
   (ADR-0094, determination 2), so `ports × 512` flows. The number of permitted
   ports is a permission and not a capacity decision.

The common measure is missing: **65 535**. It stands as `MAX_DATAGRAM` in both
directions and is 46 times the overlay MTU from ADR-0012 (1420). No QUIC
datagram of this path is ever that large; the number is the theoretical upper
bound of a UDP datagram, not that of the path.

### Why no witness noticed it

`quic_flows.rs` checks the limit **as a number**: the 513th flow is refused,
and that is true. What a flow holds in doing so is checked nowhere there — and
could not be, for the file works without a socket and without buffers. The
limit was checked, its effect was not.

### What about it touches the keystone

ADR-0086 gave the sidecar a memory limit, with exactly this argument: a sidecar
without a limit takes the node's workloads with it under the OOM killer. The
limit comes from the surcharge (ADR-0067) and is a number an operator sets.
Nothing until now connected it with the question of what its own container can
do inside it — and the answer was 255 MiB per permitted port.

## Decision Drivers

- **What must be limited is bytes, not items.** A bound on the number of
  entries is no bound as long as an entry can be arbitrarily large.
- **The limit belongs to the sidecar**, for the OOM killer knows no listeners.
- **A truncation must not be silent.** A truncated datagram is a broken packet
  for QUIC; passing it on tears the connection apart, and nobody would know
  why.
- **The number must have a computation** so that an operator can hold it
  against the limit from ADR-0086. "512" without a price per flow is none.

## Options Considered

- **A — lower `MAX_FLOWS`.** The obvious reading of the open point. Measured,
  it brings the least: at 510 KiB per flow the number would have to fall below
  100 to stay under 50 MiB — and then a workload that legitimately holds many
  connections loses its egress.
- **B — give the bytes a bound.** The datagram gets the size of the path, the
  retained gets a byte total, the number of flows stays.
- **C — count the memory itself** (a byte budget over all flows). More precise,
  and it only shifts the question: a budget that is used up must take something
  from someone, and from whom would be a policy.

Chosen is **B**, with the part of C that requires no policy: the **number** of
flows stays a bound, and because every flow is bounded from here on, their
product is a number.

## Decision

### Determination 1 — a datagram has the size of the path, not that of UDP

`MAX_DATAGRAM` becomes **2048** instead of 65 535, in both directions. The
overlay MTU is 1420 (ADR-0012), the path to the endpoint lies on the node
network with usually 1500; 2048 covers both with padding and is the smallest
round number that does so.

That is not a saving but the right number: the 65 535 is the upper bound of a
UDP datagram as such and was never a statement about this path.

### Determination 2 — a truncation is detected and ends the flow

Reading is into a buffer of `MAX_DATAGRAM + 1` bytes. If a datagram fills it
entirely, it was larger than the limit: it is **discarded**, the flow drops, and
the reason stands in the log.

That applies in both directions. Passing on a silently truncated datagram would
be the worst of all outcomes — the connection would break, and the sidecar
would report nothing.

What the container learns stays silence (ADR-0041): the reason stands in the
log, not on the wire.

### Determination 3 — the retained is limited in bytes

Beside `MAX_PENDING` (eight items, unchanged) stands a byte total per flow.
With determination 1 it follows from it — 8 × 2048 = 16 KiB — and it stands
there explicitly nonetheless: whoever one day raises `MAX_DATAGRAM` should not
accidentally raise this bound too.

What is retained is still what ADR-0092 determination 4 requires. Just no
longer arbitrarily much.

### Determination 4 — the limit applies to the sidecar, not to the listener

The flows of **all** listeners count against the same number. The demand must
not grow with the number of permitted ports: that is a permission (ADR-0041),
and whoever grants a permission thereby decides nothing about memory.

The budget is **returned when the flow drops** — a token in the flow that its
`Drop` gives back. The same construction as the return path in ADR-0094: the
expiry period clears it along, without anyone keeping books. A second count
beside the flows would be a second truth someone would have to keep in step.

### Determination 5 — 512 stays, and from here has a computation

The value does not change. What changes is that it has a price:

| | per flow | 512 flows |
|---|---|---|
| decided, endpoint silent | 7.4 KiB | 3.8 MiB |
| decided, endpoint answers | 7.4 KiB | 3.8 MiB |
| hanging (the worst case) | 18.3 KiB | 9.2 MiB |

That is the number an operator holds against the memory limit from ADR-0086.
From determination 4 on it applies to the **whole** sidecar.

A switch per node is rejected: it would be a second number that must fit
together with the memory limit, and two numbers that must fit together
eventually do not fit together any more (ADR-0086 left the source at the
surcharge for the same reason).

### Determination 6 — the limit becomes visible

Two metrics, in the form of ADR-0015/0088:

- **A counter** over the refused datagrams, with the reason as a label.
  `Refusal` has four variants — a set the code bounds, hence permitted by the
  cardinality rule from 11b.
- **A gauge** over the open flows, registered via `Health::on_scrape`: it
  changes rarely enough that it would otherwise expire after a quarter of an
  hour (ADR-0088).

Without them, reaching the limit is for an operator indistinguishable from a
network problem — the same argument as with the counter on UDP dropping
(ADR-0075, replaced by ADR-0092 — the justification for the counter outlived
its ADR).

## Consequences

**Positive**

- **The most expensive case falls by a factor of 28** — from 255 MiB to
  9.2 MiB per sidecar, measured against the built state (18.4 KiB per hanging
  flow).
- **And the measured attack costs nothing at all any more.** Eight datagrams of
  65 000 bytes produce **no flow** from here on: they fail at determination 2
  before determination 3 even begins to count. Whoever wants to tie up the
  sidecar must stay within the limit — and there it costs 18.4 KiB.
- A container can no longer tie up its sidecar's memory merely by staying
  silent. The upper bound stands before it does anything.
- The memory limit from ADR-0086 has from here a number against which it can be
  set.
- The demand no longer grows with the number of permitted ports.
- **No new crate**, no new `unsafe`, no change to the protocol.

**Negative / costs**

- **A QUIC datagram over 2048 bytes is discarded from here on.** On a network
  with jumbo frames, on which an endpoint sends larger datagrams, the flow
  breaks — visibly, with a reason in the log, and not silently. The way there
  would be to bind the number to the MTU; that would require a setting per node
  and is not decided here.
- **Detection costs one byte per read.** The price of a buffer of
  `MAX_DATAGRAM + 1` is the detectability of the truncation; without it
  `recvmsg` would have to be queried with `MSG_TRUNC`, that is, a second way
  for the same information.
- **A flow that fails on the budget fails because of a neighbour.** That is the
  price of determination 4 and the right direction: a sidecar that reaches the
  OOM killer costs **all** its flows.

**Risks & open points**

- ~~**`receive` allocates the buffer per datagram**, not per listener — one
  allocation per packet in the hot path. With determination 1 it is 2 KiB
  instead of 64 KiB, so the case becomes cheaper; **it is not measured**. The
  benchmark from ADR-0114 measures TCP round trips, not this path.~~ —
  **measured, and nothing changed.** The allocation alone costs **23.4 ns**; a
  datagram via `receive` costs **3757 ns** (`recvmsg` including cmsg
  evaluation). That is **0.6 %** — and less than the spread between two runs of
  the same code (3757 / 3790 / 3796 ns in three runs, so around ±40 ns, twice
  the allocation).

  With that the per-datagram buffer is not worth optimizing: it would be a
  change without a measured occasion at the place at which the bytes come from
  a container — and `receive` passes the buffer on as `Datagram::bytes`, so a
  reused one would have to be copied anyway. The note stays as a
  **measurement** so that nobody reopens it.
- ~~**`IDLE` stays one minute and is not measured.** It determines how long a
  hanging flow holds its place; with determination 3 that no longer costs much,
  but the number itself still rests on a consideration.~~ — **measured:
  ADR-0130**, and it did not determine it. `Flows::expire` had exactly one
  caller (`Flows::absorb`), so the period ran only with traffic — and the case
  it exists for is the one in which none flows any more: 100 × `IDLE` after the
  onslaught, a listener still held 512 flows unchanged. Because the budget from
  determination 4 belongs to the **sidecar** and the map to the listener,
  another permitted port got `TooMany` for it, and permanently. From ADR-0130
  on, every listener sweeps by the clock (`IDLE / 2`); the **number** stays one
  minute but rests on a written-out condition rather than on a consideration.
- **IPv6 stays open** as in ADR-0094: the overlay is IPv4 (ADR-0012), and the
  question arises with it.

## Related ADRs

- **Redeems:** **ADR-0094**, open point *"The limits from determination 5 are
  starting values"* — and reframes the question in doing so: not how many
  flows, but what one may cost.
- **Refines:** **ADR-0092** determination 4 (retain yes, arbitrarily much no)
  and **ADR-0094** determination 5 (the limit applies to the sidecar).
- **Serves:** **ADR-0086/0067** — the memory limit gets a number that stands
  opposite it; **ADR-0019**, because a sidecar under the OOM killer is the
  wrong way to limit a container.
- **Applies:** **ADR-0012** (the MTU of the path), **ADR-0041** (the reason
  stands in the log, not on the wire), **ADR-0015/0088** (cardinality and
  lifetime of the metrics), **ADR-0075/0092** (a number instead of silence).
