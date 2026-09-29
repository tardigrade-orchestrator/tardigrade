# ADR-0142: UDP in the Mesh

- **Status:** accepted
- **Date:** 2026-09-15
- **Decider:** Dana Schlifka
- **Technical context:** `tg-proxy` (`sidecar`, new: `datagram`), `tg-net`
  (`rules`), `tg-defs` (schema), `tg-model` (`mesh`)

## Context and Problem Statement

ADR-0074 rejects UDP between workloads of this cluster — in both directions,
with an exception for the node itself (DNS). The justification there is not a
trade-off but a property of the tool:

> **DTLS does not exist in `rustls`**, and QUIC would be a different data plane
> (ADR-0022) — meshing UDP is a cut of its own.

And the same ADR carries the successor among its open points:

> **UDP in the mesh** (DTLS/QUIC) — option C, its own ADR.

Since then the situation has moved twice. **ADR-0092** opened UDP and QUIC
**outwards**, because a need was measured there; **ADR-0141** clarified the
mesh edge's notion of a port. What remains is the gap ADR-0074 named itself:
two workloads of this cluster cannot talk to each other over UDP, and the only
way out would be to leave `<mesh>` off — that is, to switch off exactly the
enforcement for whose sake the mesh exists. That is the **perverse incentive**
ADR-0092 removed for the egress and that still stands here.

## Decision Drivers

- **ADR-0025** — deny-by-default and edges between **identities**. A UDP path
  that bypassed that would be a hole and not a feature.
- **Invariant 3 / ADR-0002** — TLS is `rustls`. A second crypto stack in the
  data path is an approval question of its own in a REMIT/DORA house.
- **ADR-0074** — the reason for the bar was the tool, not the need.
- **ADR-0092, determination 7** — there QUIC was built first and plain UDP
  afterwards; the same order carries here.
- **ADR-0012** — the overlay MTU is **1420**, and it is the reason ADR-0012
  fixes it at all: what lies above it fragments.
- **ADR-0022 / ADR-0114** — the data plane is thread-per-core via
  `SO_REUSEPORT`, and that is measured for **TCP**.

## The measured state

The four ways, each reckoned against the **existing** tree:

| Way | New crates | Cryptography | Semantics |
|---|---|---|---|
| **A — QUIC datagrams** (`quinn` 0.11.12, MIT/Apache) | **11** | **`rustls`** | stays unreliable, unordered |
| **B — DTLS** (`webrtc-dtls` 0.12, MIT/Apache) | **33** | its own stack: `aes`, `aes-gcm`, `p256`, `ecdsa`, `sha1`, `hmac`, `crypto-bigint` | stays |
| **C — tunnel through the mTLS TCP channel** | 0 | `rustls` | **becomes reliable and ordered** |
| **D — WireGuard underlay** | 0 | — | authenticates **nodes**, not workloads |

And a QUIC datagram's budget, measured against a real connection:

```text
at setup:               Some(1162)
after 200 datagrams:    Some(1414)
max+1 refused:          datagram too large
```

From that follow three numbers the build needs:

- **The QUIC overhead per datagram is 38 bytes** (1200 − 1162).
- **Before MTU discovery a datagram carries a good 1100 bytes**: QUIC starts at
  a conservative minimum MTU and not at the path's.

  **The exact number is not a constant**, and that stood out during the build of
  cut 2: measured on its own 1162, in the full test run 1288. The **overhead**
  is 38 in both cases (`1200 − 1162`, `1326 − 1288`) — the base MTU is not.
  Binding is only what `max_datagram_size()` says at runtime; a witness that
  pins one of these numbers is a flaky test with a justification.
- **On the overlay (1420) around 1354 bytes remain afterwards** — 1420 − 20 (IP)
  − 8 (UDP) − 38.

The third number is computed and not measured; the measurement needs the
overlay and belongs in the build.

## Options Considered

**B is ruled out on the cryptography.** 33 crates and a **second** complete
crypto stack in the data path — not `rustls`, not `ring`. The SPIFFE verifier
from `tg_proxy::verify` would have to be written a second time, against a
different certificate API, and two verifiers are two opportunities to do the
edge check differently. For invariant 3 it is the wrong direction.

**C is ruled out on the semantics**, and that is the subtler point: it is the
cheapest and looks good the longest. TCP guarantees order and delivery, so a
protocol designed for loss gets **head-of-line blocking** — a lost packet holds
up all the following ones instead of being missing. Whoever chooses UDP usually
chooses exactly that away, and in operation it would look like a network
problem.

**D is ruled out structurally.** The underlay authenticates nodes (ADR-0039);
ADR-0025 wants edges between workloads. And two containers on **one** node it
does not touch at all.

## Decision

Chosen: **A — QUIC datagrams between the sidecars.**

### Determination 1 — the sidecar terminates, the workload speaks plain UDP

The workload sends ordinary UDP datagrams to its peer. The sidecar receives
them in the namespace, carries them as **QUIC datagrams** (RFC 9221) over an
mTLS-secured connection to the target sidecar, and that delivers them by UDP to
its workload.

That is expressly **different from the egress** (ADR-0092/0094): there the
sidecar only reads the name from the Initial and splices through, **without
terminating**, so that the check against the endpoint's CA stays with the
workload (ADR-0041). Here the peer is a workload of **this** cluster, and the
check is exactly what the sidecar is supposed to perform.

A foreign image notices nothing of it — the same promise as with TCP (ADR-0007,
*"transparent for foreign images"*).

### Determination 2 — the same verifier, the same edge

`quinn` runs on `rustls`. With that `tg_proxy::verify` is usable
**unchanged**: the SPIFFE ID comes from the URI SAN, the check is against the
bundle **and** `may_talk` (ADR-0025). The authorization is not rebuilt but
connected.

**The edge stays `{ from, to }`** (ADR-0141, determination 1). Whoever may talk
to `ledger` may do so over what `ledger` offers — and what that is, `ledger`
declares. A transport on the edge would be a second source for a fact that
stands in the definition, and the dangerous direction: two places that can
contradict each other.

Whoever does not want UDP for a workload declares no UDP port.

### Determination 3 — one UDP port per mesh member, in the definition

```xml
<mesh port="8080" udp="9000"/>
```

One attribute, not a second element — it is the same statement ("this is how I
am reachable in the mesh"), only for the other transport. If it is missing there
is no UDP path to this workload, and ADR-0074 applies to it unchanged.

**Exactly one**, for the same reason as with TCP (ADR-0141, determination 2):
two ports behind one identity would mean an edge permits two things that are
differently dangerous. And the check from ADR-0141 applies here likewise —
whoever dials a different UDP port is rejected, not redirected.

### Determination 4 — the budget is a hard limit and is reported

A datagram that does not fit is **refused and counted** — not truncated, not
fragmented, not silently dropped. `quinn` says so of its own accord (`datagram
too large`, measured), and the sidecar reports it with the number.

The limit moves, and that belongs in the manual: **1162 bytes** before MTU
discovery, afterwards ~1354 on the overlay. A workload that sends 1300-byte
datagrams therefore loses the **first** ones — and learns of it instead of
guessing.

That is the same construction as ADR-0121 for the egress: *"a truncation ends
the flow instead of silently passing it on."*

### Determination 5 — the unreliability stays, and it is not hidden

QUIC datagrams are **not** retransmitted and **not** ordered. A lost one stays
lost, exactly as with UDP. The sidecar builds in no ordering and no
retransmission — were it to do so, it would be option C with more steps.

What QUIC adds is **congestion control**: a sender that sends more than the path
carries gets datagrams refused instead of pushing them into the network. That is
a behaviour change compared with raw UDP and belongs named.

### Determination 6 — one endpoint per sidecar, not one shard per core

`SO_REUSEPORT` distributes by 4-tuple; QUIC multiplexes over **connection IDs**.
A shard model as with TCP (ADR-0022) would distribute packets of the **same**
connection across different shards as soon as the source address changes — and
then none of them would have the state.

The QUIC path therefore gets **one** endpoint. The tail target from ADR-0022 is
untouched by that: it applies to the TCP data plane, and the measurement in
ADR-0114 showed **no** tail advantage for thread-per-core anyway.

### Determination 6a — a successful setup proves nothing

**Measured during the build of the first cut:** `dial` against a peer that
rejects the client certificate **succeeds**. With TLS 1.3 the handshake is
finished for the client after the server's `Finished`; its check of **its**
certificate runs afterwards, and the rejection reaches it only as an alert.

That is a difference from the TCP path, where `connector.connect().await` awaits
both directions and a rejection appears as a failed handshake (`sidecar.rs`).
Whoever writes a witness here that only looks at the setup gets a green test
that proves nothing.

What is checked is therefore what matters: **nothing arrives at the receiver.**
That applies to the build likewise — a metric or a log line about "rejected
setups" belongs on the **receiver** side, because only it makes the decision.

### Determination 6b — a datagram is lost when the session closes

Likewise measured during the build (`closed by peer: 0`): whoever closes the
connection while a datagram is in flight loses it. QUIC does not retransmit
datagrams — that is determination 5 in its practical form.

For the sidecar that means: a session is **not** closed as long as the workload
is using it, and a teardown does not wait for delivery, because there is nothing
to wait for. For an operator it means: a datagram at the moment of a connection
teardown is lost, exactly as with UDP.

### Determination 8 — the peer sits in the port, not in the address

**Measured during the build of cut 2, and it is the determination this ADR would
have needed:** with UDP the destination address does not survive a redirect.

| Way | Measured |
|---|---|
| `SO_ORIGINAL_DST` on a UDP socket | `ENOPROTOOPT` (ADR-0094) |
| `redirect to :port` | address **and** port after the DNAT (ADR-0094) |
| `tproxy` in the output hook | `Operation not supported` (ADR-0094) |
| `redirect` without a port | the port stays, **the address becomes local** |

The last row is newly measured for cut 2: a datagram to `127.0.0.9:9000`
reaches the listener, and `IP_RECVORIGDSTADDR` names `127.0.0.1:9000`.

With TCP `SO_ORIGINAL_DST` carries **address and port** — ADR-0060 and ADR-0141
rest on that. With UDP that does not exist, so the sending sidecar would know
*which port* but not *which peer*. Without that there is no QUIC connection.

**So the port carries the information:** the agent lays down, per permitted
peer, a rule of its own

```
udp daddr <peer-ip> redirect to :<local port>
```

and hands the sidecar the mapping `local port → peer` — over the same file seam
with which it already delivers `may_talk` and the egress permissions
(ADR-0040): the sidecar runs in a container, has no node identity and cannot ask
the control plane.

**The model is ADR-0092, determination 5**, and here it carries better. There
the agent resolves a **name**, and the list is right on the day it is created;
here the peer addresses come from the **slice** (ADR-0073), that is, from
consensus. The objection from ADR-0041 against a "DNS-fed firewall" does not
apply: here nobody feeds DNS.

**The agent assigns the ports.** It writes them into the same file; if they
change, the sidecar re-reads them during operation, like the edges too.

> **Correction after the build.** Here it said: "not a computation. A derivation
> from the position in a sorted list would be the finding from 9a in a new form
> — a new peer would shift the mapping of all the following ones, and every
> datagram would afterwards run to the wrong one." Built is exactly this
> derivation, and the second half-sentence does not carry: in 9a subnet and
> route stood on **two** sides, here `session::mesh_udp_lines` writes the file
> and `network::mesh_udp_rules` **reads it back** — one source, one pass. If a
> new peer shifts the ports, rule and mapping shift together; a datagram cannot
> run to the wrong one, because the old port no longer exists. The price is not
> misdelivery but a **session**: the affected QUIC connections break once and
> rebuild, and QUIC does that anyway at every sidecar restart.
>
> A **remembered** ledger would have been more expensive than the computation:
> it would have to survive the agent's restart, hence go to disk, and would
> thereby be the second source 9a actually means. The computation has no state.

**What that costs:**

- **An address list in the rule set**, followed level-triggered. A peer that
  changes its address is unreachable until the next slice — and reachable
  afterwards without anyone doing anything.
- **One listener per permitted peer** instead of one. The number is bounded by
  the edges, that is, by something the cluster knows (ADR-0015).
- **An edge without an endpoint is mute.** As long as a peer has reported no
  address (ADR-0073), there is no rule and no listener — datagrams there die at
  the dropping rule from ADR-0074. That is the safe direction and the same as
  with an unresolved UDP target (ADR-0092).

**The return direction needs none of this.** The receiving sidecar listens on
**one** port — the one from `<mesh udp>` — and whoever reaches it is identified
by the certificate. The asymmetry is the same as in ADR-0141: the receiver
decides, the sender only finds the way.

### Determination 7 — two cuts, QUIC mesh first

As ADR-0092 determination 7: first the path between two sidecars with a witness
on real sockets, then the wiring (rule set in the namespace, derivation of the
command line, manual). A mechanism without a caller is the error from ADR-0044.

## Consequences

**Positive**

- The perverse incentive from ADR-0074 is gone: whoever needs UDP no longer has
  to leave `<mesh>` off and thereby give up mTLS and egress control along with
  it.
- **The same authorization as with TCP**, without rewriting a line of it —
  because `quinn` runs on `rustls`.
- The UDP semantics are preserved; C would have changed them silently.

**Negative / costs**

- **+11 crates in the build** — but **zero in the bill of materials**, and that
  came out during the build: `quinn`, `quinn-proto` and `quinn-udp` had long
  stood there. `reqwest` 0.13.4 (the image puller, ADR-0003) lists them as a
  **non-activated** optional feature (HTTP/3); `cargo tree` does not show them,
  `cargo metadata` does.

  **That is a finding against ADR-0134** and not against this ADR: since its
  first run the bill of materials has named components that are not shipped —
  the other direction from one that omits some, and thus more harmless, but for
  an auditor the same kind of error. It belongs treated there.

  What this ADR really costs is the **activation**: from here the same crates
  are built and linked instead of merely standing in the lockfile.
- **A yanked package came along** and was caught by the gate: `chacha20 0.10.1`
  via `rand 0.10.2`. `cargo update -p chacha20` to 0.10.2 resolves it — but it
  is the reason why `cargo deny check` stands in the Definition of Done.
- **A second data-plane stack.** What ADR-0022 and ADR-0114 measured for TCP
  does not apply to it.
- **The datagram budget** is smaller than a UDP payload on the same path and
  smaller again at the beginning of a connection. A protocol with datagrams over
  ~1350 bytes does not fit here — for that it stays at ADR-0074.
- **Congestion control**, where previously there was none.

**Risks & open points**

- **The ~1354 is computed.** The measurement on the real overlay belongs in the
  first cut; if it deviates, the measured number applies.
- **No need is measured.** ADR-0075 searched protocol by protocol and found
  nothing TCP could not also do. This ADR decides the **way**, and whether it is
  built is decided by the first workload that needs it — unlike with ADR-0092,
  where the need (QUIC to S3) was there.
- ~~**The check from ADR-0141 for UDP** is not yet built: `SO_ORIGINAL_DST`
  exists for UDP sockets in the same form, but the way there is a different one
  (`recvmsg` with `IP_RECVORIGDSTADDR`), and that belongs measured.~~
  **Measured — and the presumption was false:** it does not exist in the same
  form (table in determination 8, the address becomes `127.0.0.1`). A check
  "which port did you want" thereby becomes unnecessary, because here the port
  does not carry the information but **answers the question**: whoever arrives
  at the listener for peer X wanted to go to peer X. ADR-0141 protects a
  collective port against a foreign intent; here there is no collective port.
- **MTU discovery needs traffic.** A connection that rarely sends anything stays
  at 1162. Whether that suffices depends on the protocol.

## Related ADRs

- Redeems the open point from: **ADR-0074** ("UDP in the mesh (DTLS/QUIC) —
  option C, its own ADR")
- Follows the form of: **ADR-0092** (transport explicit, QUIC first),
  **ADR-0121** (a limit is reported, not truncated)
- Depends on: ADR-0025 (the edge), ADR-0141 (one port per transport), ADR-0012
  (the overlay MTU)
- Touches: ADR-0022 (the data-plane runtime), ADR-0134 (the bill of materials)
