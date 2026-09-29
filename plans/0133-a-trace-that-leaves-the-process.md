# ADR-0133: A Trace That Leaves the Process

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0015 (observability, sampling as an open point), ADR-0022
  and ADR-0114 (what the data plane may pay), ADR-0072 (format breaks in the
  window), ADR-0040 (the slice), ADR-0020 (the audit trail as the other record)

## Context and Problem Statement

ADR-0015 decided on `tracing`→OTLP and named **sampling** as an open point. 11b
left it standing with the justification that at the control plane's event rate
unsampled is defensible and "with the data plane it would not be, and there
nobody exports today".

Measured, the question presupposes something that does not exist.

### The measurement

```text
$ tgd --otlp-endpoint http://127.0.0.1:4317 …
thread 'main' panicked at hyper-util/src/rt/tokio.rs:115:
there is no reactor running, must be called from the context of a Tokio 1.x runtime
```

The same with `tg-agent` and with `tg-proxy`: **all three binaries die at
startup** when the setting is given. `SpanExporter::builder().with_tonic()`
builds a hyper channel, and `tg_telemetry::init::init` runs before
`runtime.block_on`.

And the second half weighs more:

```text
$ grep -rc 'info_span!|debug_span!|#[instrument|span!' crates/*/src
(no hits)
```

**In the whole tree there is not a single span.** A byte-counting collector
beside a running `tgd` saw `CONNECTIONS=0 BYTES=0` over 25 seconds — not even a
TCP connection. The export is not "unsampled", it is empty.

The seam costs **10 crates** in the process (384 with, 374 without).

### What the actual question about it is

A switch that kills the process is a bug and fixed in one sentence. The
decision beneath it is: **what are spans for here?**

This system's logs are structured, and the audit trail carries index, term,
command, outcome and actor (ADR-0020, ADR-0045, ADR-0050). A span per command
in `tgd` largely duplicates that. What **neither** record can do is the chain
across the **process boundary**: an operator issues a command, the leader
applies it, a slice arises, a node executes it — and today that can only be
pieced together by hand from timestamps and names.

Exactly there lies the value, and exactly there this decision goes.

## Decision Drivers

- **The data plane does not pay for observability.** ADR-0022 set the target,
  ADR-0114 measured how narrow the room is. A span per connection would be
  exactly the price it must not pay.
- **What only the caller can uphold, someone eventually fails to uphold.** The
  `block_on` finding from 9d, verbatim: "a seam one **must** uphold is one that
  someone eventually does not uphold."
- **A trace is observation, not state.** It must not influence a decision and
  does not belong in the log (ADR-0004).
- **A format break is not a rolling update** (ADR-0072): what goes onto the wire
  goes bundled into a window.

## Options Considered

- **A — withdraw.** `--otlp-endpoint` is dropped, ten crates go. Cheap, honest,
  and takes from the installation the only information across process
  boundaries.
- **B — repair and leave empty.** A promise without content.
- **C — repair and build the chain** that no other record delivers: command →
  slice → pass.

Chosen is **C**.

### Determination 1 — the exporter arises inside the reactor, and nobody can forget that

`tg_telemetry::init::init` demands a `tokio::runtime::Handle`. Without it there
is no call — the compiler holds the condition, not a comment.

The way via "the caller enters the runtime beforehand" is rejected: that is the
same seam 9d already stood at once, and here it would have to be upheld in
**three** binaries.

### Determination 2 — the sidecar exports no spans, and says so

`tg-proxy` **rejects** `--otlp-endpoint` instead of accepting it and doing
nothing. Two reasons, and both are measured:

- **The data plane gets no spans** (determination 3). An exporter without a span
  is the situation this ADR is just ending.
- **Its bootstrap runtime dies.** It is discarded as soon as the identity has
  been fetched — the finding from 11b that moved the sidecar's metric endpoint
  onto a thread of its own. A batch exporter on it would hang on a dead reactor.

Reject instead of ignore: a switch that does nothing is a promise that stands
out only during an incident.

### Determination 3 — three spans, and no others

| Span | where | cadence |
|---|---|---|
| `apply` | `tgd`, per applied log entry | the log rate |
| `slice` | `tgd`, per sent slice | per log change and node |
| `reconcile` | `tg-agent`, per pass | `--interval`, default 1 s |

**No span in `tg-proxy`, none per connection, none per datagram.** That is the
boundary from ADR-0022 and ADR-0114, and here it is a determination and not an
omission.

### Determination 4 — the context travels twice, and both times beside the state

- **In `tgd`** from `apply` to the session via a **note beside** the state:
  `StateHandle` gets the `traceparent` of the last applied entry, not
  `ClusterState`. A trace is observation; keeping it in the replicated state
  would mean replicating and snapshotting it — and it could influence a decision
  (ADR-0004).
- **Over the wire** in the slice, as a W3C `traceparent`. With that a node's
  pass hangs on the command that triggered it.

That is a **format break** and goes bundled into the window from ADR-0072;
`PROTOCOL_FIELDS` counts it.

### Determination 5 — W3C `traceparent`, no format of our own

One field, one standard, and every tool of the ecosystem reads it. A format of
our own would be a second parser at a trust boundary — an unreadable value means
**no parent**, not "error": a broken trace must not cost a pass (ADR-0019).

### Determination 6 — no sampling, and with that ADR-0015's point is answered

With the data plane out, the rate is **structurally** bounded: one span per log
entry (measured around 9 500 a day per single writer, ADR-0132) and one per
reconcile pass and node. That is not an order of magnitude one rolls dice for.

And there is an argument against it that goes beyond the rate: these traces lie
beside a retention-bound audit trail. A sample would leave out precisely the
operation an auditor looks for — and the absence would be indistinguishable
from an outage.

Sampling is thereby not deferred but **rejected**, as long as determination 3
holds. Whoever ever puts spans into the data plane has the question anew — and
then it is a different one.

## Consequences

**Positive**

- **`--otlp-endpoint` no longer kills the process.** That applied to all three
  binaries and was covered by no test.
- **The chain across process boundaries is visible**, and it is the only thing
  neither log nor audit trail delivers.
- **ADR-0015's open point is answered** instead of passed on.

**Negative / costs**

- **A format break** in the slice (determination 4). It goes into the window
  from ADR-0072, together with the one from ADR-0086.
- **Ten crates stay in the tree.** Until now they had no use; from here they
  have one.
- **A note beside the state** is a second place that wants maintaining. It is
  expressly without consequence: whoever loses it loses a parent, not an
  operation.
- **The sidecar rejects a setting** it previously accepted. A call that sets it
  fails visibly from here — that is the intention.

**Risks & open points**

- **`tgctl` carries no context in.** The chain begins at the leader's `apply`,
  not at the operator. A short-lived CLI with an exporter of its own would be a
  batch export per invocation; whoever wants the chain to begin there first
  needs an answer to that.
- **The slice names the *last* applied entry.** If several entries change the
  same slice, the pass hangs on the most recent. That is the honest mapping:
  there is one slice per state, not per command.
- **Sampling stays rejected, not impossible.** The seam is the same
  `build_subscriber` on which the exporter also hangs.

## Related ADRs

- **Answers:** the open point from **ADR-0015** (sampling) — through a decision
  about the quantity of spans instead of about a sample.
- **Upholds:** **ADR-0022** and **ADR-0114** (the data plane does not pay).
- **Goes into the window from:** **ADR-0072**, together with **ADR-0086**.
- **Delimits itself against:** **ADR-0004/0020** — a trace is observation and
  belongs neither in the log nor in the replicated state.
- **Applies:** the `block_on` finding from **phase 9d** (no seam the caller must
  uphold).
