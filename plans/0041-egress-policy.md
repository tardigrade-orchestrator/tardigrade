# ADR-0041: Egress policy — traffic out of the mesh

- **Status:** accepted
- **Date:** 2026-08-22
- **Deciders:** Core team
- **Technical context:** `tg-proxy` (the sidecar), `tg-net` (rule set,
  resolver), `tg-consensus` (the command set), ADR-0007, ADR-0012, ADR-0013,
  ADR-0015, ADR-0016, ADR-0019, ADR-0020, ADR-0025, ADR-0027, ADR-0040.

## Context and Problem Statement

ADR-0025 governs who may talk to whom inside the mesh — and **only** that. For
traffic out of the mesh there is to this day no decision, and that has a concrete
consequence: **egress is open.** The rule set from phase 9b lets through
everything that leaves the bridge, and the redirect to the sidecar explicitly
bites only for destinations inside the cluster CIDR. The reason stands in the
code as a comment: *"there is no decision for that yet … a redirect on all TCP
would pre-empt it."*

ADR-0027 needs the decision: shared mutable state goes to **external S3**, and
there "egress to S3 is subject to an egress allowlist" stands as an open point.
Without it the S3 part of phase 10 is not buildable.

The timing has become favourable: since ADR-0040 there is a path over which a
policy reaches the node at all.

## Decision Drivers

- **Zero trust, deny by default** — the same stance as ADR-0025. A mesh that is
  strict inwards and open outwards protects mostly the wrong party.
- **ADR-0027: the external endpoint speaks its own TLS.** "TLS against its CA,
  **not** SPIFFE mTLS." Whatever is decided here must not replace the workload's
  certificate check.
- **ADR-0019, invariant 4:** no control-plane call per connection, and
  enforcement survives the absence of the control plane.
- **ADR-0020, REMIT/DORA:** egress is exactly the question an auditor asks —
  *what left the perimeter, and who permitted it?*
- **ADR-0012: no eBPF.** What enforces is nftables or a userspace process.
- **ADR-0013/phase 9c:** the node-local resolver is **not** a forwarder. What
  lies outside the zone gets `REFUSED`. A container cannot resolve external names
  at all today.

## Options Considered

- **A — nftables by address.** The allowlist names IP and port; the rule set lets
  exactly those through.
- **B — nftables by name, fed through DNS.** A process resolves the permitted
  names and keeps an nftables set current.
- **C — the sidecar reads the name off the wire.** Egress is redirected like
  ingress; the sidecar reads the SNI from the `ClientHello` and decides.
- **D — leave it open and log it.** No prohibition, only visibility.

### Why not A

An S3 endpoint is a name with changing addresses — often dozens, often different
per request. An address list is correct on the day it is created and not
afterwards. It produces outages that look like network problems and invites broad
ranges that no longer restrict anything.

### Why not B

It works, and it is common. The price is a **trust boundary in the wrong place**:
what lands in the set is determined by a DNS server's answer. Whoever influences
that writes into the firewall. On top of that comes the race — between resolution
and connection the answer can change, and the container may take a different
address than the one it asked for anyway.

### Why not D

Visibility without prohibition is, under REMIT/DORA, not a control objective but
a report that there is none.

## Decision

Chosen: **Option C** — the sidecar decides by the name the connection itself
states. Plus eight determinations.

### 1. The sidecar does **not** terminate egress TLS

It reads the `ClientHello`, takes the SNI and then **splices** the bytes. No
termination, no re-establishment, no interception key on the node.

That is the determination ADR-0027 hangs on: the TLS session exists between the
workload and the external endpoint, against its CA, as decided there. A
terminating proxy would take the check away from the workload and replace it with
one resting on a private key on every node — exactly the kind of shortcut that
hollows out a zero-trust model.

The price stands here so that nobody has to look for it later: **content is not
inspectable.** No DLP, no answer to "what exactly went out". That is at the same
time the virtue — there is nothing to steal.

### 2. The sidecar resolves the name **itself** and dials it

That is what makes the SNI trustworthy at all, even though the client writes it.
The sidecar does **not** take the address the container wanted to connect to; it
takes the name, checks it against the allowlist, resolves it and dials the
result.

A lie in the SNI thereby takes the liar exactly where they were allowed to go
anyway. And the address the container had in mind is irrelevant — the redirect
intercepts it in any case.

### 3. The permission is a cluster fact, not a field in the definition

A new command, built like `AllowTraffic` from ADR-0025:

```
AllowEgress { workload, host, port }
```

**Not** an element in the XSD. A definition is written by whoever builds the
workload; who opens the perimeter boundary is a different question and, in a
REMIT/DORA house, a different role. A field in the definition would be
self-service — and an auditor would find the answer to "who permitted this" in a
team's Git instead of in the audit substrate.

As a side effect the schema needs no change.

### 4. No sidecar, no egress

A workload without `<mesh>` has no enforcement point. So the rule set from phase
9b lets nothing out for it — it discards what it does not redirect.

That is a noticeable change from today, and it is the point: deny by default
means that the absence of a decision is a refusal and not a permission. Whoever
wants out joins the mesh.

### 5. Without a name no permission — unless somebody names the number

Traffic that is not TLS or carries no SNI is refused. An operator can explicitly
permit it by **address and port**; that permission is then a separate, visible
line in the log.

The rule in one sentence: *whoever cannot name themselves must be numbered — and
that is visible.*

### 6. The resolver forwards exactly the permitted names

Phase 9c decided that the node-local resolver is not a forwarder. That stays,
with one precise exception: it forwards requests for names that stand on the
allowlist of a workload of this node. Everything else stays `REFUSED`.

With that the allowlist is at the same time the forwarding list, and the resolver
does not become an open resolver. What matters is what does **not** follow from
this: DNS is not a trust boundary for enforcement here — that lies with the SNI
(determination 2). Forwarding only ensures that a connection can come about at
all.

### 7. The policy travels in the slice (ADR-0040)

The same link as the `may_talk` edges, the same local cache, the same fail-static
behaviour from ADR-0025: **stale does not mean invalid.** The sidecar keeps
enforcing what it last knew and concludes nothing from the absence of messages.

The backstop against an eternally old policy is the same as there — the lifetime
of the SVID (ADR-0014), not an expiry date on the cache.

### 8. Permissions into the log, refusals into telemetry

Who permitted egress to whom and when is a decision and belongs in the audit
substrate (ADR-0020). That a container tried it at 3 a.m. anyway is an
observation and belongs in telemetry (ADR-0015) — high-frequency, with no
retention obligation, and in the log it would be noise with a deadline.

## Consequences

**Positive**

- The S3 part of ADR-0027 becomes buildable, and without the orchestrator
  touching the TLS session going there.
- **One** enforcement point for both directions. The same sidecar, the same
  policy cache, the same fail-static behaviour, the same window.
- Names instead of addresses — the rule holds when the provider rotates its
  addresses.
- DNS is no longer a trust boundary, only reachability.
- The resolver stays a non-open resolver, and without a special rule: the
  allowlist is the forwarding list.
- "Who was allowed to leave with what" stands in the log, checkable like any
  other decision.

**Negative / Costs**

- **A new operating mode in the sidecar.** Today it terminates mTLS; here it
  splices without terminating. Two modes in one process, and the difference is
  security-relevant.
- **One more hop** for outbound traffic. Not on the hot path of mesh
  communication, but measurable for S3-heavy workloads.
- **No sidecar means no egress** — a behavioural change that breaks existing
  definitions until they join the mesh.
- **No content inspection.** Deliberate (determination 1), but it is a promise
  one can no longer make.
- The command set grows by one command, and the allowlist grows by a dimension
  that has to be maintained.

**Risks & Open Points**

- **Encrypted Client Hello.** If the SNI is encrypted, the sidecar sees no name
  any more, and this ADR loses its pivot. The way out would be determination 5 —
  addresses — and that is bad. To be watched before ECH is widespread.
- ~~**Wildcards in the allowlist** (`*.s3.example.com`): needed by some providers,
  dangerous as a habit. Whether and how they are permitted is to be decided —
  with the same care as the prefix selectors in ADR-0025.~~ — **done: ADR-0124**,
  and measured the situation was not "undecided" but **accepted and without
  effect**: `AllowEgress` did not check the name at all, the entry went into the
  log and into the slice — and both comparisons in the data plane compared
  exactly. The destination was forbidden **and** the name did not resolve; the
  diagnosis therefore pointed at the resolver instead of at the permission. With
  `udp` a single star even froze every further rule change of the workload
  (fail-static, ADR-0019). From ADR-0124 the state machine checks the **form**,
  and what is permitted is exactly the one from RFC 6125: a `*` as the whole
  leftmost label, covering exactly one label, not the name itself, never for
  `udp`. Comparison in both places uses **the same** function.
- ~~**UDP egress** is not governed here and stays forbidden. NTP runs at node
  level per ADR-0024 and is not workload traffic; if a workload needs UDP
  outbound, that is a decision of its own.~~ — **done:** ADR-0092.
- ~~**Who may grant the permissions** is the RBAC question from ADR-0018, already
  open there. This ADR makes it more urgent, because it entrusts a perimeter
  boundary to it.~~ — **done:** ADR-0105.
- ~~**The latency of splicing** is not measured. ADR-0022 has a measurement
  requirement for the data plane that applies here too.~~ — **done:** measured in
  `crates/tg-proxy/tests/tail_latency.rs`
  (`the_egress_splice_is_measured_against_a_direct_connection`, lane
  `cargo xtask bench`), as the **difference to a direct connection**: the same
  client, the same endpoint, once with and once without the sidecar. 16
  connections, 2000 round trips per connection, 512 B, 5 runs per variant:

  | Round trip, µs | p50 | p99 | p99.9 |
  |---|---|---|---|
  | direct | 82.6 [82.4–83.4] | 132.1 [129.4–140.0] | 160.2 [154.5–189.0] |
  | spliced | 164.9 [161.7–165.0] | 239.0 [236.0–243.6] | 310.1 [280.0–358.1] |

  The splice therefore costs **+82 µs at p50, +107 µs at p99, +150 µs at p99.9**
  — roughly a doubling, and unlike the mesh comparison in ADR-0114 the gap is
  many times larger than the spread between runs. That is the expected shape: one
  more hop and two copies per direction, with no crypto in between
  (determination 1).

  **Connection setup** is reported separately, because it is incurred per
  connection and is the only part in which the sidecar decides anything — read
  the SNI, resolve, dial: 302 µs direct against 791 µs spliced at the median.
  Whoever opens a new connection per request therefore pays a multiple of what a
  round trip costs; that is not a property of splicing but the reason S3 clients
  keep connections.

## Related ADRs

- Supplements: ADR-0025 (intra-mesh there, outbound here) — both deny by default,
  both enforced locally, both fail-static.
- Serves: ADR-0027 (S3 as an external endpoint), ADR-0016 (credentials for it).
- Depends on: ADR-0007 (the sidecar), ADR-0040 (the path to the node), ADR-0013
  (the resolver), ADR-0012 (the rule set), ADR-0019 (fail-static), ADR-0020
  (audit).
- Touches: ADR-0018 (who may permit), ADR-0022 (data-plane latency).
