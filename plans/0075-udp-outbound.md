# ADR-0075: UDP outbound

- **Status:** superseded by 0092
- **Date:** 2026-09-03
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-net` (`rules`), ADR-0074, ADR-0041, ADR-0024,
  ADR-0015, ADR-0022

## Context and Problem Statement

ADR-0074 drops UDP in a mesh member's namespace, in both directions, with an
exception for its own node (where the resolver listens). The reason was a finding:
**every** redirect rule carried `l4proto == tcp`, and with that a mesh member talked
to any container over UDP past the certificate and phoned out without permission —
ADR-0025 and ADR-0041 were without effect for an entire protocol.

That ADR left a question open and makes it more urgent than it was before:

> **There is no way out through a permission.** `AllowEgress` rests on the SNI of a
> TLS connection (ADR-0041, determination 1) and has no counterpart for UDP. Whoever
> needs UDP outbound leaves out `<mesh>` — and thereby loses mesh **and** egress
> control for that workload.

That is a **perverse incentive**: the only evasive move an operator has today
switches off precisely the enforcement for whose sake the mesh exists. And ADR-0041
had already deferred the question ("if a workload needs UDP outbound, that is a
decision of its own") before enforcement existed. Now it exists, so the question is
due.

## Decision Drivers

- **ADR-0041, determination 2** explicitly rejects an address list: *"an address
  list is correct on the day it is created and not afterwards"*, and a DNS-fed
  firewall *"puts the trust boundary in the wrong place"*. A UDP permission by
  address would be exactly that.
- **UDP carries no SNI.** There is no field on which a permission by **name** could
  bite — the mechanism from ADR-0041 is not transferable.
- **ADR-0019:** a perimeter boundary one can circumvent by forgoing enforcement is
  none.
- **Diagnosability.** Dropping happens without ICMP (ADR-0074: an answer would be a
  channel through which a container probes the rule). An operator therefore sees
  **silence**, and silence is the most expensive diagnosis.

## Options Considered

### A — stay forbidden, and decide it instead of deferring

No mechanism, but a decision with reasons and a diagnostic.

### B — a permission by address (`AllowUdpEgress { host, port }`)

A command in the log, resolved to addresses, programmed as an nftables rule.

Rejected: that **is** the DNS-fed firewall from ADR-0041. An endpoint's addresses
change, the rule stays — and whoever resolves it decides the perimeter on the basis
of an answer they have not checked.

### C — QUIC-aware egress

QUIC's `ClientHello` lies in the initial packet, encrypted with **well-known** keys
derived from the destination connection ID — so the SNI is readable without a
secret. A sidecar could read it and decide as with TLS.

Rejected for this cut: it requires a QUIC stack in the data path (`quinn-proto` or
similar, ADR-0023), the splicing of a connectionless protocol including the
association of response packets, and ADR-0022's tail target applies to it just the
same. That is a cut of its own and not an addition.

### D — the node provides UDP services, not the workload

As with the resolver: what a workload needs in UDP the **node** offers, and the
exception applies to the node address. No perimeter hole, because the node is the
counterpart.

Not rejected, but empty: measured, there is today no second service the node would
have to offer this way.

## Decision

**Option A.** UDP outbound stays forbidden for mesh members. This decision is not
the extension of a deferral but rests on a measurement: **the need is empty or has a
TCP path.**

1. **It stays forbidden, and decidedly so.** A mesh member reaches its own node over
   UDP (the resolver, ADR-0074) and nothing else.

2. **The justification is the measured need**, protocol by protocol:
   - **NTP** is a node matter per ADR-0024 (PTP/chrony) and not workload traffic. A
     workload reads the clock.
   - **DNS** goes to the node-local resolver and is exempt.
   - **Telemetry** (syslog, StatsD) runs over OTLP per ADR-0015, and that is TCP.
   - **QUIC/HTTP-3** is the only real case. Every HTTP-3 client falls back to TCP —
     Alt-Svc is opportunistic, not binding — and the egress path from ADR-0041
     carries TLS over TCP.

3. **The perverse incentive is named, not fixed.** Whoever leaves out `<mesh>` gets
   UDP and loses mesh **and** egress control. That is an operator decision with a
   visible price; it is **not** the same action as "permit UDP", and the difference
   belongs in the manual.

4. **Silence gets a number.** The drop rules carry an anonymous `counter`. An
   operator investigating "my workload does not reach its endpoint" sees in
   `nft list table inet tardigrade` whether packets are dying at this rule — and does
   not have to guess whether it is the network, the edge or this decision.

   Explicitly **no** Prometheus metric: it would lie in an instance's namespace, and
   the agent would have to collect it per pass through `nft list` — a polling
   interval for a diagnostic one poses once, when searching.

5. **No ICMP.** ADR-0074's determination stays: no `reject`, so that no answer goes
   on the wire — to an address the container chose — and so that the rule is
   indistinguishable from a black hole from outside.

   **On measurement "silent" is only half the truth**, and the justification in
   ADR-0074 is correspondingly narrower than it sounds:

   | Direction | Hook | What the sender learns |
   |---|---|---|
   | outbound | output | `sendto` fails with **`EPERM`** |
   | inbound | input | nothing, the packet disappears |

   On the output hook the kernel reports `NF_DROP` back to the socket. So the
   container **does** learn of it — only not over the network, and without learning
   *which* rule it was. For operations that is the better situation: in the
   workload's log there stands a reason and not a timeout. It changes nothing about
   the decision; it does change ADR-0074's sentence "so that a container cannot probe
   the rule", and that is therefore placed here and **not** rewritten there
   (invariant 6).

## Consequences

- **Positive:** the perimeter boundary from ADR-0041 has no hole one opens by
  forgoing enforcement. The need is justified protocol by protocol and not asserted.
- **Positive:** the most expensive diagnosis — silence — gets a number, without a
  polling interval and without a channel to the container.
- **Negative:** a mesh member cannot speak QUIC outbound. Whoever needs it forgoes
  `<mesh>` and thereby enforcement, or waits for option C.
- **Negative:** the decision is one about **today's** need. If QUIC becomes binding
  instead of opportunistic, it has to be taken anew — with a new ADR, not by drift.

## Risks & Open Points

- **Option C stays the way out**, and the path there is described: QUIC's SNI is
  readable without a secret. What is missing is a QUIC stack in the data path and an
  answer to ADR-0022's tail target for a connectionless protocol.
- **Option D is empty, not wrong.** If a second node-local UDP service arrives, the
  exception is already there (ADR-0074).
- **The counter is described and guarded in its order.** That packets die at it is
  checked by a test on real packets (ADR-0074); that the counter runs along **and
  stands before the drop** is in the rule assertions. The order is half the promise:
  `nft` executes a rule's statements in sequence, and after a `drop` none follows —
  a counter after it would never count and would look from outside like "nothing dies
  here".
- Who would be allowed to grant an exception would be the same RBAC question as in
  ADR-0041 — it does not arise here, because there is no exception.

## Related ADRs

- Closes the open point from: ADR-0074 ("whether there should be a UDP permission")
  and ADR-0041 ("UDP egress is not governed here").
- Applies: ADR-0041 (names instead of addresses), ADR-0024 (NTP is a node matter),
  ADR-0015 (telemetry over OTLP), ADR-0019 (a circumventable boundary is none).
- Depends on: ADR-0038 (`nft` as a separate process), ADR-0074 (the chains that
  carry the counter).
