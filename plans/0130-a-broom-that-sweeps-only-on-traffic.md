# ADR-0130: A Broom That Sweeps Only on Traffic

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0121 (the flow limit and the budget), ADR-0094 (one
  listener per permitted port), ADR-0092 (QUIC outwards), ADR-0086/0019 (what a
  sidecar may cost)

## Context and Problem Statement

ADR-0121 left an open point:

> **`IDLE` stays one minute and is not measured.** It determines how long a
> hanging flow holds its place.

Measured, it does not determine that. It only determines it as long as traffic
flows — and the case the period exists for is the one in which none flows any
more.

### The measurement

`Flows::expire` has exactly **one** caller: `Flows::absorb`. The `serve` loop
waits in `tokio::select!` on `shutdown` and `readable()` and has no ticker. The
period therefore runs only when a datagram arrives on **this** listener.

```text
after the onslaught:                    open=512  len=512
100 x IDLE later, without a datagram:   open=512  len=512
listener B after 100 x IDLE:  Refuse(TooMany)  (A holds 4 slots)
held bytes (upper bound): 8 MiB
```

### Two consequences, and the second is the worse one

**The memory.** A sidecar that falls silent holds up to 8 MiB of retained
handshake fragments (512 × `MAX_PENDING_BYTES`) and its flow map until at some
point another datagram comes. That is bounded (ADR-0121, determination 3) and
it heals itself — at the next datagram the same broom sweeps.

**The budget.** Since ADR-0121 determination 4 it applies to the **sidecar**,
but the map lies per listener, and there is one listener per permitted port
(ADR-0094, determination 2). If the traffic on `:443` fills the budget and dries
up there, then listener A holds all the slots with flows that are long dead —
and listener B gets `TooMany`. **No path ever clears that up:** the only broom
sits in the loop that is no longer running. Until the sidecar restarts, and that
comes only with the restart of the workload (ADR-0009: BindsTo+After).

The trigger is no attack. A workload that pushes a batch to `:443` at night and
dials an endpoint on `:8443` in the morning suffices.

### Why no witness saw it

`a_silent_flow_makes_room_again` in `quic_flows.rs` checks exactly the direction
that works: it clears with a **new datagram on the same listener**. The case
without a datagram and the case across the listener boundary did not occur in
it.

### Visible, but mislabelled

The gauge reads `budget.open()`, so an operator sees the 512. What they read
alongside stands in `docs/alerts.yml`: *"`too_many` means the limit"* — and *"a
workload that holds 512 simultaneous QUIC connections outwards"*. Measured, it
could mean "512 corpses on a different port", and the action that follows from
that is a different one.

## Decision Drivers

- **A period that runs only on traffic is none.** It does not take effect in
  the one case it exists for.
- **A slot nobody returns any more is not a budget but a leak** — and the
  consumer that suffers from it is a different port of the same workload.
- **The sidecar is the process whose failure costs all the node's workloads**
  (ADR-0086, ADR-0019). What it holds, it holds on the most expensive machine.
- **Two sets of books about the same fact are two opportunities to count
  differently** (ADR-0069). The budget counts globally, the map expires locally
  — exactly this seam has torn.

## Options Considered

- **A — the broom gets a clock.** Every listener wakes itself and sweeps its
  map, whether traffic came or not. The period then means what ADR-0121 claimed
  of it.
- **B — the budget takes back what has expired.** `take()` would, at full
  occupancy, reclaim slots whose flow has been silent too long. That requires a
  second set of books beside the map: the entry would live on, its slot would be
  gone, and its `Drop` would deduct a second time. Exactly the seam at which
  this finding arose.
- **C — one map for all listeners.** The key would carry the target port, so it
  would be unique, and every datagram of any listener would sweep everything. It
  would need a lock in the data path (ADR-0022) and would still not fix the case
  "the whole sidecar is silent".
- **D — shorten `IDLE`.** Changes nothing: shorter is the same period that does
  not run.

Chosen is **A**.

### Determination 1 — every listener sweeps by the clock, not by the traffic

The `serve` loop gets a third branch: a tick that calls `expire`. With that a
listener returns its dead flows without anyone addressing it — and the
sidecar's budget recovers even if the traffic has moved to a different port.

The broom stays where the map is. A listener that swept another's map would be
a lock in the data path for an operation that is due once every half minute.

### Determination 2 — the tick is derived from `IDLE`

`IDLE / 2`, no second setting. With that a dead flow holds its slot for at most
`IDLE · 1.5`, and whoever changes the period changes the tick with it. A
constant of its own would be a number that must fit another one — and eventually
does not fit any more.

### Determination 3 — the tick runs as long as the listener runs

It arises with it and ends with it. A listener disappears when its permission
disappears (`adjust`, ADR-0094); its map and its slots go with it anyway,
because Rust drops them.

**The order in `select!` stays `biased` and `shutdown` first** (ADR-0068). The
sweep branch stands behind it: after the signal there is no more cleaning up,
only ending.

### Determination 4 — `IDLE` stays one minute, and the open point gets a content

The number does not change. What changes is that from here it bounds anything
at all.

The condition it hangs on is written out instead of presumed: **`IDLE` must lie
above the largest gap between two datagrams of a *living* flow.** This gap is
determined by the counterpart's QUIC idle period, and the sidecar does not know
it — it sees the `ClientHello` and after that ciphertext (ADR-0092). A minute is
therefore still a starting value; it now rests on a named condition rather than
on a consideration.

### Determination 5 — the information in the manual becomes correct

`docs/alerts.yml` reads `too_many` as "the workload holds 512 connections". From
here that is true again. That it was untrue for a while stands there — whoever
has an old sidecar in front of them otherwise looks at the wrong end.

## Consequences

**Positive**

- **A port can no longer take the way outwards from another.** The wedge was
  permanent and reachable without an attacker's involvement.
- **`MAX_FLOWS` is again a statement about simultaneous flows** instead of ever
  opened ones.
- **The memory of a silent sidecar falls by itself**, instead of waiting for a
  datagram that may never come again.
- The metric `tg_proxy_quic_egress_flows` from here measures what its name says.

**Negative / costs**

- **A listener wakes twice a minute even when there is nothing to do.**
  Measured against what it otherwise does (a `recvmsg` costs 3757 ns,
  ADR-0121), that is nothing; as a construction it is nevertheless a polling
  interval, and this tree has rejected several of those. The difference stands
  in determination 1: here there is no event one could wait for — the absence of
  traffic **is** the occasion.
- **A flow can now expire between two datagrams** if the counterpart is silent
  for longer than `IDLE`. It could before too (the next call swept it), only
  later and unpredictably. The condition from determination 4 is what matters
  there.

**Risks & open points**

- **The one map for all listeners** (option C) remains the tidier answer to the
  seam from the decision drivers: budget and map would then really be one set of
  books. What speaks against it is a lock in the data path; what speaks for it
  stays true.
- **The minute itself is still not measured**, only justified (determination 4).
  It would be measurable only against real counterparts.
- **IPv6 stays open** as in ADR-0094 and ADR-0121.

## Related ADRs

- **Redeems:** the open point from **ADR-0121** ("`IDLE` determines how long a
  hanging flow holds its place") — it did not determine it.
- **Establishes what ADR-0121 determination 4 promises:** a budget for the
  sidecar that every listener gets out of again.
- **Applies:** **ADR-0068** (fixed order in the `select!`), **ADR-0069** (one
  derivation, one place), **ADR-0088** (the gauge stays registered).
- **Touches:** **ADR-0094** (one listener per port — the multiplication that
  creates the case in the first place), **ADR-0086/0019** (what the sidecar may
  hold).
