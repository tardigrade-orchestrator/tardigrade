# ADR-0141: The Port of a Mesh Edge

- **Status:** accepted
- **Date:** 2026-09-15
- **Decider:** Dana Schlifka
- **Technical context:** `tg-proxy` (`sidecar`), `tg-net` (`rules`), `tg-model`
  (`command`), `tg-defs` (schema)

## Context and Problem Statement

ADR-0025 bounds its reach upwards and in doing so describes what should belong
to it downwards:

> L7 authorization (HTTP path/method) is **not** included — the proxy
> authorizes at L4 (**identity + port/proto**).

What is built is the identity. The edge in the command set carries two names:

```rust
AllowTraffic { from: String, to: String }
```

The obvious conclusion reads "the edge is too coarse — it opens every port of
the target". **Measured, that is not true**, and the actual situation is sharper
and in a different direction.

## The measured state

The path of a mesh connection, read from `rules.rs` and `sidecar.rs`:

| Step | What happens | Place |
|---|---|---|
| 1 | Container A dials `B:9999` | — |
| 2 | **all** TCP into the cluster CIDR is redirected, without a port filter | `rules.rs:513` |
| 3 | A's sidecar reads `SO_ORIGINAL_DST` = `B:9999` and connects there | `sidecar.rs:543` |
| 4 | at B: **all** incoming TCP is redirected, without a port filter | `rules.rs:780` |
| 5 | B's sidecar checks the edge and connects to `127.0.0.1:upstream_port` | `sidecar.rs:450` |

The port from step 1 survives to step 4 and is discarded there. `upstream_port`
comes from `<mesh port="…"/>`, and the schema permits exactly one:

```xml
<xs:complexType name="Mesh">
  <xs:attribute name="port" type="Port" use="required"/>
</xs:complexType>
```

**The existing witness already demonstrates it**, without reading it as a
finding: in `tg-proxy/tests/mesh_netns.rs` the client dials `10.42.1.9:9000`
while the echo listens on `127.0.0.1:<random port>` — and the answer arrives.
The test reads that as the normal path ("the client **never** dials a sidecar
port"), and for its subject that is right.

From that follow two facts, and both are the opposite of the presumption:

1. **A mesh member offers exactly one port.** Other ports of the same workload
   are **not** reachable via the mesh at all — not even with an edge.
2. **A dialled port is silently redirected.** Whoever dials `B:9999` gets
   `B:<mesh port>`, without anything appearing anywhere.

## What that means for ADR-0025

**The L4 claim is satisfied, only differently than thought.** "Identity +
port/proto" demands an authorization that includes port and protocol. Here
there is **exactly one** port per target and **exactly one** protocol (TCP; UDP
in the mesh has been rejected since ADR-0074). An edge with a port setting would
therefore have nothing to decide: the set of permitted ports is already one, and
it is declared by the target rather than by the edge.

An `AllowTraffic { from, to, port }` would therefore be no security gain but a
second source for a fact `<mesh port>` already carries — and the dangerous
direction: two places that can name different ports, and operations decides
which applies.

**The redirect is in the process a protective effect and not a hole.** An
attacker in `api`'s container who dials `ledger:22` gets `ledger`'s mesh port
and not its SSH. Abolishing it without putting something in its place would make
the situation worse.

**What it costs is the diagnosis.** Whoever wrote `ledger:9999` into their
configuration while `ledger` declares `8080` gets a working connection to
`8080`. The error never becomes visible — until somebody expects a second
service on `9999` and gets the answer from `8080`. That is verbatim the finding
from ADR-0051, one layer further: *"Whoever dialled `:8443` while `:443` was
permitted silently got a connection they had not asked for."*

## Decision Drivers

- **ADR-0025** — the claim, and the question whether it is open.
- **ADR-0051** — the same finding at the egress, decided there in favour of
  clarity: the port comes from the kernel, an ambiguous case is rejected rather
  than guessed.
- **ADR-0019** — a behaviour change must not cost a running workload.
- **ADR-0004** — a fact has one source. `<mesh port>` is the port's.
- **ADR-0072** — a field in the command set is a format break and goes into the
  bundled window.

## Options Considered

- **A — port on the edge** (`AllowTraffic { from, to, port }`). The literal way
  to ADR-0025's sentence. A second source for the port, without room for a
  decision: the set is one.
- **B — several mesh ports per workload**, then the port on the edge. Makes A
  meaningful, but is a feature: `<mesh>` would get several entries, the incoming
  sidecar a port mapping, and the redirect would have to decide per port. No
  present need is measured.
- **C — reject the redirect.** The target sidecar reads `SO_ORIGINAL_DST` (it
  can — the redirect is NAT, conntrack carries the port) and rejects if the
  dialled port is not the mesh port.
- **D — make the redirect visible.** It stays, but the target sidecar reports
  the case.
- **E — nothing, and close ADR-0025's point as moot.**

## Decision

Chosen: **C, and A/B expressly rejected.**

### Determination 1 — the port on the edge is not built

ADR-0025's "identity + port/proto" is **satisfied** for the mesh edge: per
target there is one port and one protocol, and both are declared by the target.
A port setting on the edge would have no decision to make and would be a second
source (ADR-0004).

The open point in ADR-0025 is thereby closed, **not** built — and with the
justification that the question dissolved on measurement, not with "later".

### Determination 2 — several mesh ports stay out

A workload offers one port. Whoever has two services declares two workloads —
that is the granularity on which identity (ADR-0006), placement (ADR-0011) and
the edge (ADR-0025) hang too. Two ports behind one identity would mean an edge
permits two things that are differently dangerous.

Should the need ever be measured, **B** is the way, and then **A** becomes
necessary in the same step. Until then both would be a mechanism without a
caller (the error from ADR-0044).

### Determination 3 — a different port is rejected, not redirected

The **incoming** sidecar reads `SO_ORIGINAL_DST` and rejects the connection if
the dialled port is not the workload's mesh port. It still forwards to
`upstream_port` — what is checked is whether the caller meant it.

Why the **incoming** one and not the outgoing: it is the one that knows the port
without having to guess (ADR-0007, "server authoritative"). The outgoing one
does not know the target's `<mesh port>` — it has only the edge, and per
determination 1 that carries no port.

The rejection has a **reason in the log** and a metric. A connection abort
without a report would be indistinguishable from a network problem — the same
consideration as with "upstream unreachable in the container" beside it.

### Determination 3a — without conntrack the local address applies

`SO_ORIGINAL_DST` needs **conntrack in the namespace**, and that was measured
during the build:

```text
host namespace (conntrack active):   OK   -> port 50661 (local was 50661)
fresh namespace without rule set:    FAIL -> [Errno 2] No such file or directory
```

Both answers mean the same — **nobody redirected** — and the first says it as a
local address. The fallback on `ENOENT` is therefore the local address and
**not** a rejection.

That affects two cases, and in both it is the right answer:

- **In operation** the sidecar listens on its mesh port, and that is not the
  workload's: rejected. Nobody legitimately dials the sidecar port directly.
- **Before the rule set** — if the sidecar comes up before the NAT chains are in
  place (ADR-0060) — the same applies. It then accepts nothing, and that is the
  safe direction.

A fallback to "then just let it through" would be the alternative and the wrong
one: the check would be switchable off by somebody removing the NAT chains.

**The first draft of this ADR did not have the case**, and the first build
rejected on `ENOENT`. That turned the witness `mesh_netns` red — its peer
namespace deliberately carries no rule set — and in operation would have hit a
sidecar that comes up faster than its rules.

### Determination 4 — it is a behaviour change, and it stands in the manual

A setup in which a container today dials the wrong port and still arrives
breaks. That is the purpose: it is misconfigured and does not know it.

The case belongs in the section "Behavioural changes that concern an upgrade"
with the way out — the number from `<mesh port>` into the caller's
configuration, or, if it is right there, correct `<mesh port>`.

**No switch against it.** A setting that restores the old behaviour would be one
somebody sets and nobody takes back — the construction ADR-0017, ADR-0090 and
ADR-0113 reject.

### Determination 5 — no format break

Nothing in this decision changes a message on a wire: the edge stays
`{ from, to }`, the slice stays as it is, and `<mesh port>` already stands in
the definition. The sidecar reads a value the kernel gives it anyway.

That is the reason why this decision does **not** have to go into the bundled
window from ADR-0072 — unlike option A, which would have been one.

## Consequences

**Positive**

- The last open point from ADR-0025 is closed, and with a measurement rather
  than with a build.
- A misconfigured caller stands out instead of working.
- **Zero new crates, no format break, no field anywhere.** The cut is one check
  in the incoming sidecar and a witness for it.

**Negative / costs**

- An existing setup with a wrong port breaks on upgrade. It was wrong before;
  that does not make it cheaper for operations.
- The check costs one `getsockopt` per incoming connection — the same order of
  magnitude as the three that already stand there.
- **A workload can still offer only one port.** Whoever needs two services
  behind one identity has no way here; that is determination 2 and a decision,
  not a gap.

**Risks & open points**

- **The outgoing sidecar does not check.** It could not — it lacks the target's
  `<mesh port>`. A container therefore learns of the error only at the
  connection abort and not at the `connect`. Carrying the port into the target
  SVID or into the slice would be an extension with a format break, and it buys
  only an earlier report.
- **A workload without `<mesh>` is untouched** — it has no sidecar and no
  redirect (ADR-0093).

## Related ADRs

- Closes the open point from: **ADR-0025**
- The same finding one layer further: **ADR-0051**
- Depends on: ADR-0060 (`SO_ORIGINAL_DST` in the mesh), ADR-0007 (server
  authoritative), ADR-0074 (TCP is the only mesh protocol)
- Touches: ADR-0008 (`<mesh port>` stays single), ADR-0093 (the baseline)
