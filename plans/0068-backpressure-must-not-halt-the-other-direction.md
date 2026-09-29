# ADR-0068: Backpressure in one direction must not halt the other

- **Status:** accepted
- **Date:** 2026-08-31
- **Deciders:** Architecture
- **Technical context:** `tgd::session`, `tg-agent::session` (ADR-0040), the
  active-role lease (ADR-0064)

## Context and Problem Statement

The session between control plane and node (ADR-0040) is bidirectional: slices go
out, reports come back. Both sides run a `select!` loop over an `mpsc` channel of
depth eight.

On **both** sides the send stands as `.send(…).await` **outside** a `select!` arm —
on the server side before the loop's selection, on the node side in the **body** of
the tick arm. As long as that `await` hangs, the selection has either not been
reached yet or has already been made; in both cases the incoming side is **not
polled**.

Backpressure in one direction therefore halts the other. That is not a decision
taken but a coupling that follows from the arrangement.

## Decision Drivers

- **The consequence hits the keystone.** On the server the chain is closed and read
  through: a full outgoing side → no `incoming.next()` → no `absorb` → no
  `report_seen` → the node drops out of `reporting_since` → `leases()` skips the
  renewal → the lease expires → the **healthy** single writer fences itself
  (ADR-0064, ADR-0010). Triggered by the leader's backpressure, not by a partition.
- **Both payloads are snapshots.** `report` clones the observed state and reads
  capacity, generations and proxy image; nothing is consumed. `slice_for` computes
  the slice at state `index`. A later snapshot **replaces** an earlier one
  completely.
- **The buffer is deliberately small** (ADR-0030: backpressure instead of memory).
  Enlarging it shifts the problem and does not solve it.
- ADR-0040 names backpressure as an open point — but only for the
  **server→node** direction ("whoever cannot keep up gets the stream cut"). This
  coupling does not stand there.

## Options Considered

- **A — enlarge the buffer.** Shifts the threshold, changes nothing about the
  coupling, and takes backpressure's purpose away.
- **B — cut the stream when the outgoing side is full.** The answer ADR-0040 hints
  at for the other direction. It turns backpressure into a tear-down and therefore a
  delay into an outage.
- **C — the send goes into the `select!` and blocks nothing any more.** On each
  side in the form that fits the payload.

## Decision

Chosen: **Option C**, and **differently** on the two sides, because the two
payloads differ in one property.

### 1. The node discards a report the channel does not take

A report arises on a ticker (every `REPORT_EVERY_SECONDS`), and it is a pure
snapshot. If the channel is full, it is **discarded**; the next tick carries the
same state, and fresher. Queuing one would mean keeping an ageing snapshot.

A **closed** channel stays what it was: the session ends.

### 2. The server waits for room — in the `select!`, not before it

A slice arises **not** on a ticker but only when the log moves. Discarding it would
mean leaving the node stale until the next change — and that may not come. What is
awaited is therefore a **permit reservation** as an arm of the selection of its own
(`Sender::reserve`, documented as cancel-safe in `tokio`). While it hangs, the other
arms keep running, and reports are taken in.

The slice is computed **after** the reservation, not before: it is thereby as fresh
as possible instead of as old as the wait.

### 3. The order is fixed, not drawn at random

`select!` chooses randomly among **ready** arms. If a slice is pending and the
incoming side ends at the same time — which a client may do, gRPC knows half-close —
then without further measures chance would decide whether it still goes out.
Measured: in five of eight runs it was lost.

The send arm is therefore `biased` and stands first. That is exactly the priority
the send had **before** ADR-0068; it is restored without bringing the coupling back.
It cannot starve the others: after the send `sent == index` holds, and the
precondition switches it off.

### 4. The property stands on the code, not in a comment

After this cut there is in **neither** of the two loops an `await` on the outgoing
side outside a selection arm. The remaining `.send(…).await` lie exclusively on
**abort paths** (`Refused`, `ForwardTo`), behind which a `return` stands
immediately — there is nothing left to poll there.

## Consequences

**Positive**

- A slow node costs freshness, not its active role. The chain that fenced a healthy
  single writer is broken.
- Backpressure keeps its purpose (ADR-0030): it slows the producer instead of
  occupying memory.
- The slice is fresher than before, because it is computed after the wait.

**Negative / Costs**

- The node silently discards reports when things jam. It says so — but it is a loss
  of observability precisely when one would need it. Defensible, because the
  **next** report carries the same state.
- On the server side the reservation can hang arbitrarily long. What should happen
  on **sustained** backlog stays the open point from ADR-0040; this ADR only takes
  its side effect away.

**Risks & Open Points**

- ~~**The decoupling itself is guarded by no test** … what is evidenced is the
  arrangement and the chain — every link read through in the code — not a run.~~ —
  **done:** both halves now have a witness, and the objection about buffer size
  turned out to be solvable:

  - **Server side**, end to end against a real `tgd`
    (`a_full_outgoing_queue_does_not_stop_the_incoming_side`): a client that
    **never reads** its slice, plus 200 log movements — and then a report that
    arrives nonetheless (`applied_slice` in the projection). The foreign buffer size
    is no obstacle but a **client parameter**: the harness sets its HTTP/2 receive
    window to 1 KiB, and "eventually it jams" becomes "after a few messages".
  - **Node side** (`a_full_channel_costs_the_report_and_not_the_session`): the seam
    that supposedly did not exist costs a name — `offer` decides full → discarded,
    closed → the session ends, room → sent.

  **The witness's value is measured, not asserted**: with the send *before* the
  selection — the state before this ADR — the end-to-end test runs into its time
  bound (20.6 s, `applied_slice == None`); with the decoupling it is green after
  0.56 s.
- **The order from determination 3 is guarded**, and explicitly deterministically:
  `a_client_that_stops_sending_still_receives_its_slice` opens twelve sessions and
  demands the slice every time. Without `biased` it is red in six of six runs; a
  single pass would have been red only about half the time — and a guard that lets
  through that often looks like a flaky test.
- ~~**The threshold for the tear-down** (ADR-0040) stays open. Until then a
  permanently jammed node is one that holds a session and does nothing.~~ — **done
  for the dead node: ADR-0128.** Measured, **one** place in the whole tree set a
  keepalive — the client in the agent — and **no** server; on a quiet cluster the
  detection time was therefore unbounded. The three network listeners get the same
  number from the same source (`REPORT_EVERY_SECONDS`), the admin socket explicitly
  none.

  **For the slow node it stays open**, and that is determination 3 of ADR-0128:
  whoever reads too slowly answers its pings without complaint — they run in `hyper`
  and not in its application. Whoever works is not reaped (ADR-0019); the
  backpressure from ADR-0040 is a different question.

  Two hypotheses were refuted along the way: an agent walking through its endpoint
  list per ADR-0077 leaves **no** session lying on a follower (that answers
  `ForwardTo` and ends it), and a hanging session costs **no** slice computation per
  log change — the send arm reserves the room first and computes afterwards, i.e.
  exactly what determination 2 of this ADR requires.

## Related ADRs

- ADR-0040 — the path from the control plane to the node; names backpressure as an
  open point for the opposite direction.
- ADR-0064 — the active-role lease; its renewal hangs on `report_seen`.
- ADR-0030 — backpressure instead of memory.
- ADR-0010 — the self-fence as an autonomous action.
