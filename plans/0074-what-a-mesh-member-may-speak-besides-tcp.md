# ADR-0074: What a mesh member may speak besides TCP

- **Status:** accepted
- **Date:** 2026-09-02
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-net` (`rules`), ADR-0025, ADR-0041, ADR-0060,
  ADR-0007, ADR-0013

## Context and Problem Statement

The rule set in an instance's namespace redirects traffic to the sidecar —
inbound, into the cluster and outbound (ADR-0060, ADR-0041). Measured, **every**
one of these rules carries the condition `meta l4proto == tcp`:

```text
outbound:  l4proto tcp ip daddr <cluster>  redirect to :15001   (mesh)
outbound:  l4proto tcp                     redirect to :15002   (egress)
inbound:   l4proto tcp                     redirect to :15001
```

For UDP from a mesh member that means:

| Destination | What happens | What should hold |
|---|---|---|
| a container in the cluster | goes directly over bridge and tunnel | `may_talk` decides (ADR-0025) |
| anywhere outbound | goes out through the masquerade | deny by default, allowlist (ADR-0041) |

**Both promises are therefore without effect for UDP.** ADR-0025 names deny by
default as the basis of the data plane; ADR-0041 explicitly accepted "no sidecar,
no egress" as a behavioural change — and a container phoning out over UDP bypasses
exactly that. In a REMIT/DORA environment an unauthorized way out is not a residual
risk but the finding.

It was noted as a subordinate clause ("UDP stays out. What is redirected is TCP; a
mesh member speaking UDP talks past it"), and as a completeness gap — not as a
circumvention of authorization.

## Decision Drivers

- **ADR-0025:** deny by default, and enforcement lies in the sidecar. What does not
  pass through the sidecar is not authorized.
- **ADR-0041:** "no sidecar, no egress" — the decision has been taken, and its price
  (existing definitions lose their way out) was borne deliberately.
- **ADR-0007/0022:** the data plane is TLS over TCP (`rustls`). **DTLS does not
  exist in `rustls`**, and QUIC would be a different data plane (ADR-0022) —
  *meshing* UDP is not possible with this architecture but is a new one.
- **ADR-0013:** a container has to reach its **own** resolver, and that speaks UDP.
  That is the one exception, and it is already expressed: the rule set exempts the
  node itself (rule 3).
- **Reach:** only whoever declared `<mesh>` has a netns rule set (ADR-0060: it is
  laid when the sidecar starts). A workload without a mesh is unaffected.

## Options Considered

- **Option A — drop.** UDP from a mesh member is dropped, except to its own node
  (DNS). Fail-closed, and the same direction as ADR-0041.
- **Option B — leave it and document it.** The subordinate clause stays, the
  operations manual names it.
- **Option C — mesh UDP.** DTLS or QUIC in the sidecar. A new data plane.

## Decision

Chosen: **Option A**.

1. **A filter rule set in the instance's namespace** drops UDP — in both
   directions. A **chain of its own** and not the existing ones: those are `nat`
   chains, and only the first packet of a connection arrives there; a `drop` would
   not belong in them.
2. **Its own node stays exempt** (ADR-0013). A container resolves names at its
   node's resolver, and that is UDP. The exception applies in both directions — the
   answer comes back from there.
3. **It applies only to mesh members.** Whoever has not declared `<mesh>` has no
   netns rule set and is unaffected. The blast radius is thereby exactly the set
   that has committed to authorization — and for it, "everything I speak is
   authorized" is the promise, not a restriction.
4. **ICMP stays.** It carries no payload requiring authorization, and `ping` is the
   tool with which an operator checks a network. What is dropped is **UDP**, not
   "everything except TCP": SCTP and others are moot here, and a rule against
   everything unknown would eventually hit something nobody meant.
5. **Dropped and not rejected.** A `reject` would produce an ICMP answer and thereby
   a channel through which a container can probe the rule; and it would tell it
   somebody is filtering. A `drop` looks like a network that does not answer — the
   same choice ADR-0041 made for egress ("whether a workload should learn **why** it
   was refused is open").

Option B is rejected: a promise that does not hold for one protocol is none. Option
C is not a decision about rules but about a data plane — it belongs in an ADR of its
own if somebody needs QUIC in the mesh.

## Consequences

**Positive**

- Deny by default applies to the data plane and not to a protocol within it.
- The way out is exactly one: the sidecar's egress port, with name and port from
  consensus (ADR-0041).
- A mesh member can no longer talk to another container past the certificate.

**Negative / Costs**

- **A behavioural change, and a noticeable one.** A mesh member using NTP, StatsD,
  syslog or QUIC over UDP loses that. Until now it worked — **because a gap stood
  open**, not because it was permitted. That belongs in the operations manual, not
  in a footnote.
- **There is no way out through a permission.** `AllowEgress` rests on the SNI of a
  TLS connection (ADR-0041, determination 1) and has no counterpart for UDP. Whoever
  needs UDP outbound leaves out `<mesh>` — and thereby loses mesh **and** egress
  control for that workload. Whether there should be a UDP permission is open.
- **Two more chains** per instance namespace. The rule set gets longer; the number
  of rules stays fixed (ADR-0038: no growth per peer).

## What this decision does not govern

- ~~**UDP in the mesh** (DTLS/QUIC) — option C, an ADR of its own.~~ — **decided:
  ADR-0142** — QUIC datagrams between the sidecars. The justification here (*"DTLS
  does not exist in `rustls`"*) was confirmed on measurement and decided the choice
  along with it: `quinn` runs on `rustls` and costs 11 crates, `webrtc-dtls` brings
  33 plus a second crypto stack.
- **A permission for UDP egress** by name and port. It would need a different
  mechanism than the SNI.
- **Whether a workload learns the reason** — the same open question as in ADR-0041.

## Related ADRs

- **ADR-0025** — deny by default applies to the data plane, not to a protocol within
  it; for UDP it had no effect.
- **ADR-0041** — the same for the way out.
- **ADR-0060** — the mesh redirect carries `l4proto == tcp`, and from that the
  finding followed.
- **ADR-0013** — the node-local resolver speaks UDP and stays exempt.
- **ADR-0038** — the nftables path over which the rule set arises.
- **ADR-0075** — answers the question this ADR leaves open: UDP outbound.
