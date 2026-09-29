# ADR-0128: Who Notices That the Other Is Gone

- **Status:** accepted
- **Date:** 2026-09-13
- **Concerns:** ADR-0068 (the open threshold for the teardown), ADR-0040 (the
  backpressure), ADR-0043 (the three listeners), ADR-0033 (the consensus timing
  rule), ADR-0064 (the lease), ADR-0019 (the keystone)

## Context and Problem Statement

ADR-0068 left an open point:

> **The threshold for the teardown** (ADR-0040) stays open. Until then a
> permanently stuck node is one that holds a session and does nothing.

Measured, the situation is one-sided, and the one side is missing entirely.

### The measurement

In the whole tree **exactly one place** sets a keepalive:

```text
crates/tg-agent/src/cluster.rs:203   .http2_keep_alive_interval(KEEPALIVE)
crates/tg-agent/src/cluster.rs:204   .keep_alive_timeout(KEEPALIVE * 2)
```

There the number is cleanly justified — one ping per reporting period
(`REPORT_EVERY_SECONDS`, that is, lease/3 = 5 s), given up after two — and the
comment names exactly the case: *"A counterpart that disappears **without**
sending a FIN — a partition, a node whose power is pulled — otherwise holds the
stream open forever."*

**No server does the same.** Six `Server::builder()` in `tgd` — Raft port,
session port, credential port, admin socket — are unconfigured; without a
setting `tonic` sets **no** interval.

The consequence is an asymmetry with an unpleasant peak:

- The **client** notices when the leader disappears. Built and justified.
- The **server** does not notice when a node disappears. It sends only when the
  log moves; if it does not move, it sends nothing, so TCP notices nothing
  either. On a **quiescent** cluster the detection time is therefore unbounded.

### Two refuted hypotheses

Both stood at the beginning of this work and reduced its scope:

- **"An agent walking through its endpoint list per ADR-0077 leaves a session
  lying on every follower."** On inspection a follower answers with `ForwardTo`
  and **ends** the session (`session.rs`, line 484). Normal operation does not
  leak.
- **"A hanging session costs a slice computation per log change."** On
  inspection the send branch reserves the slot **first** and computes
  **afterwards** — that is ADR-0068 determination 2. It costs one parked task
  and eight channel slots, nothing else.

What remains is a node that hangs on the leader and does not read: it holds a
session, and nobody takes it away.

## Decision Drivers

- **An end nobody notices is no end.** The promise from ADR-0019 applies to the
  availability of the workloads; a connection that is only memory any more does
  not belong to it.
- **The number already exists.** The client has it, and it is bound to the
  reporting cadence rather than freely chosen. A second one would be a second
  opportunity to diverge.
- **A slow client is not a dead one.** Whoever reads, only too late, is working
  — and throwing them away would be exactly the availability decision ADR-0019
  warns about.

## Options Considered

- **A — do nothing.** Today's state: detection hangs on TCP, and on a
  quiescent cluster it does not happen.
- **B — a deadline of its own in the session service** ("no `Report` since X →
  teardown"). It would lie **above** the transport and would have to be built
  anew in every service; and it confuses "is silent" with "is gone" — exactly
  the distinction ADR-0057 made into a rule.
- **C — HTTP/2 keepalive on the servers**, with the client's numbers.

Chosen is **C**.

## Decision

### Determination 1 — the network listeners get the same keepalive as the client

Raft port, session port and credential port get
`http2_keepalive_interval` = `REPORT_EVERY_SECONDS` and
`http2_keepalive_timeout` = twice that.

**The same source, not the same number copied**: both sides derive from
`tg_store::session::REPORT_EVERY_SECONDS`. Whoever changes the reporting cadence
changes both.

### Determination 2 — the admin socket gets none, and that is a statement

On a Unix socket there is no partition: if the counterpart disappears, EOF
comes. A keepalive there would be a ping against a problem the kernel does not
have.

It stands here so that nobody later "adds it in".

### Determination 3 — it catches the **dead** client, not the slow one

A client that reads too slowly answers its pings without trouble: they run in
`hyper`'s connection task and not in its application. The keepalive therefore
does **not** throw it away — and that is right.

With that the open point from **ADR-0040** (what should happen on persistent
backlog) stays open, and deliberately so: a node that is working is not a node
one tears down. What is closed is the case ADR-0068 was about — one that does
**nothing**.

### Determination 4 — on the Raft port it is a gain and a risk, and both are named

**Gain:** a half-open connection today lets every Raft call run into its
deadline (ADR-0033: `heartbeat_interval` *is* the RPC timeout), and `tonic`
only reconnects when the channel drops — which takes until the TCP
retransmissions, so minutes. The keepalive turns that into ten seconds.

**Risk:** a node whose runtime blocks — a long apply, a snapshot — answers no
pings either, and then the connection drops even though the node is alive. It
is rebuilt immediately; what it costs is a handshake, and Raft already
considers a node unreachable if it says nothing for two reporting periods.

The choice falls on the same keepalive as everywhere: **one** number, and the
justification stands here rather than in a third constant.

### Determination 5 — no metric

`tonic` does not report that it closed a connection because of a ping, and the
way there would be a `tower` layer of its own. What an operator sees is the
effect: a node that no longer reports already stands in `tg_node_last_report`
(ADR-0057), and a node that gets no slice in `tg_node_slice_lag`.

A number about closed connections would be a third view of the same fact.

## Consequences

**Positive**

- **The server now notices too.** Until now only the client protected itself —
  and on a quiescent cluster the server would never have noticed.
- **A dead node's session is freed**, together with task and channel. The open
  point from ADR-0068 is thereby closed for the case it means.
- **A Raft peer hanging half-open costs ten seconds instead of minutes.**
- **One number for both sides**, from one source.
- No new crate, no new setting, four lines.

**Negative / costs**

- **A node whose runtime blocks loses its connections** — including the one to
  the Raft. It rebuilds them immediately; the price is one handshake per
  blockage that lasts longer than two reporting periods.
- **Pings on quiescent connections** are traffic that did not exist before: one
  frame per five seconds per connection. At five nodes that is nothing, and it
  stands here because at five hundred it would be something.
- **The backpressure stays open** (determination 3). Whoever expects this
  decision to clear away a stuck but living node expects the wrong thing.

**Risks & open points**

- **The number is not measured**, it is derived — the same situation as with
  the client it comes from. What binds it is the reporting cadence, and that
  hangs on the lease from ADR-0014, whose numbers are themselves
  unsubstantiated.
- **A blocked apply is not measured.** How long a runtime really stands under a
  large snapshot nobody knows; if it is longer than ten seconds, the gain on
  the Raft port turns into flapping.
- **`tg-proxy` and `tg-agent` have no listening gRPC ports** that would be
  co-decided here: the workload API socket is a Unix socket (determination 2),
  and the sidecar terminates no HTTP/2.

## Related ADRs

- **Redeems:** **ADR-0068**, open point *"The threshold for the teardown"* —
  for the dead client, expressly not for the slow one.
- **Leaves open:** **ADR-0040** (what should happen on persistent backlog), and
  determination 3 says why that is right.
- **Applies:** **ADR-0043** (the three listeners), **ADR-0057** (being silent
  is not being gone — hence the transport and no deadline in the service),
  **ADR-0019** (whoever works is not cleared away).
- **Touches:** **ADR-0033** (the consensus timing rule — the keepalive lies in
  the same order of magnitude), **ADR-0064** (the lease on which the reporting
  cadence hangs).
