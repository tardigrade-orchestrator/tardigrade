# ADR-0043: mTLS on the cluster transports

- **Status:** accepted
- **Date:** 2026-08-23
- **Deciders:** Core team
- **Technical context:** `tg-consensus` (the Raft transport), `tg-store` (the
  node session), `tg-identity` (verifier, join/renew), `tgd`, `tg-agent`

## Context and Problem Statement

Phase 5c built the Raft transport and explicitly left its protection open;
ADR-0040 built the node session and marked the node name in `Hello` as a
**self-declaration**; ADR-0037 names as the target picture "agent ↔ server over
mTLS with node SVIDs" and until then carries the nonce against replay; ADR-0042
establishes that a node could announce another's key as long as that name is a
self-declaration.

Four open points, one cause: **none of the transports between this cluster's
processes authenticates its counterpart.** Measured, there is no `ServerTlsConfig`
and no `ClientTlsConfig` anywhere in the tree; `rustls` lies exclusively in
`tg-proxy`, i.e. in the data plane.

What that is worth today can be quantified from the slice.
`tgd::session::SessionSvc` takes `NodeMessage::Hello { node, .. }` and answers it
with `slice_for(node)`. Whoever reaches the port gets, for an **arbitrary** node
name: its instances with complete definition documents, the `may_talk` edges that
touch them, the egress permissions of those workloads — and the complete underlay
peer list with public keys and endpoints of all nodes. That is not merely a
confidentiality question: it is the loss of least privilege that ADR-0040
determination 5 names as the purpose of the slice.

## Decision Drivers

- **Consensus must not depend on its own PKI.** The CA runs as a subsystem in
  `tgd` (ADR-0006) and hangs on the leader. A check on the Raft port requiring a
  valid signature from the cluster CA is a circle: expired → the port refuses →
  no quorum → no leader → no CA.
- **ADR-0019, static stability.** A node that has been away for a long time must
  be able to come back without an operator intervening — ADR-0037 promises that
  explicitly.
- **ADR-0040 determination 8** wants the node name taken from the connection, not
  from the first message.
- **Invariant 3:** TLS is `rustls`. No OpenSSL, no `native-tls`.
- **The harness stays untouched.** The in-process bus from phase 5b (ADR-0032)
  lies at the `RaftNetwork` level and knows no transport; the correctness of
  consensus is proven there and must not hang on TLS.
- **Revocation must be possible without the consensus it is meant to restore.**

## Findings that carry the decision

Six measurements, each against the code:

1. **Four services, one port, one server.** `tgd/src/lib.rs` hangs `RaftService`,
   `AdminService`, `NodeService` and the `IdentityService` on **one**
   `Server::builder()` and **one** address. One `rustls` `ServerConfig` per
   listener means one client-auth setting for all four — and they need different
   ones.
2. **`Join` cannot present a client certificate.** It is the call with which a
   node obtains its first one.
3. **`Renew` must not demand one.** The node SVID has `Lifetime::default()`, i.e.
   a **15 min** TTL (ADR-0014); the agent renews with `RENEW_EVERY = 3 h`. So it
   is valid for 15 of 180 minutes. If `Renew` demanded a valid node SVID, every
   node would be locked out after more than 15 minutes of absence — the opposite
   of what ADR-0037 promises.
4. **Nobody reads the node SVID today.** `tg-agent` writes it to `node.svid.pem`
   and uses it nowhere. It is present but not load-bearing material.
5. **The mitigation `tg-consensus::net` claims does not exist.** The module header
   says that after phase 9 the Raft traffic runs "over an authenticated,
   encrypted underlay". Measured: a peer's `AllowedIPs` are exactly its
   **container subnet** (`wireguard.rs`: `allowed: subnet.net()`), and
   `ensure_wireguard_link` gives the interface **no address of its own** — it
   sets the MTU and brings it up. There is no route on which management traffic
   between two nodes would take the tunnel. The sentence is to be retracted.
6. **`tonic` 0.14.6 is asymmetric.** `Endpoint::tls_config_with_verifier` takes
   an `Arc<dyn ServerCertVerifier>` of one's own — on the **client** side. On the
   server side there is no hook for a `ClientCertVerifier` of one's own:
   `ServerTlsConfig` knows `identity`, `client_ca_root` and
   `client_auth_optional`, nothing more. And an SVID has no DNS SAN, so the
   built-in name check falls away anyway. What is available are
   `Request::peer_certs()` (feature `tls-connect-info`) and
   `Router::serve_with_incoming`.

## Options Considered

- **Option A** — put the Raft port into the WireGuard underlay (ADR-0012): give
  the interface an address per node, include it in the `AllowedIPs`, bind the
  port there. Authentication by cryptokey routing in the kernel.
- **Option B** — mTLS against the cluster CA on all ports, with the node SVID as
  the credential.
- **Option C** — mTLS on all ports, but the check goes **not** against the CA but
  against the counterpart's **registered public key**; where the registration
  comes from depends on whether the port lies before or behind consensus.
- **Option D** — do nothing: the nonce from ADR-0037 suffices.

### Why not A

It is a circle, and a tighter one than option B's. Since ADR-0040 the underlay's
peer list comes from the **slice**, the slice from the leader, the leader from
Raft. If Raft lay in the tunnel, the tunnel would need a peer list that does not
exist without Raft. A cluster that was once entirely down would never come back
up.

On top of that, option A binds authentication to an address and not to an
identity. For the session it is of no use: it gives the server not a **name** but
a source address from which it would have to guess the name. As an **additional**
layer it stays right and is compatible with this decision — finding 5 only says
that it does not exist today.

### Why not B

Three reasons, each sufficient on its own:

- **The circle.** The CA hangs on the leader, the leader on the Raft port, the
  Raft port on the CA. A cluster whose certificates expired while it stood still
  no longer starts.
- **The lockout.** Finding 3: with a 15 min TTL and 3 h renewal a node would
  regularly be without a valid credential.
- **And the way out would be worse than the problem.** Soft-fail on the consensus
  port (ADR-0014, 2 min grace) would mean: an expired certificate is accepted.
  Whoever once had one has lost nothing on the way there — on the port that *is*
  consensus, that is not a mitigation but an open door with a waiting period.

### Why not D

The nonce covers `Renew`. It does not cover the Raft port, and it does not cover
the slice: `Hello.node` stays a self-declaration, and what hangs on it stands
above. Besides, today the **entire** desired state runs in the clear over the
wire — all definition documents, all edges, all peer keys. In a REMIT/DORA
environment that is a finding in itself.

## Decision

Chosen: **Option C.** The credential is the **key**, not the certificate.

### 1. The key is the credential, not the chain to a CA

On both cluster transports each side presents a **self-issued leaf over its node
key**, with `spiffe://<domain>/node/<name>` in the URI SAN. The verifier reads
the name from the SAN, fetches the public key registered for it and compares it
with the presented one. If they match, `rustls` has already proven with the
handshake signature that the counterpart holds the private part.

**The name in the SAN is not a proof but an index.** It says only which row to
look in. Whoever names a foreign name fails at the key comparison; whoever names
the foreign key fails at the handshake. That belongs written at the seam,
otherwise one day somebody checks the identifier instead of the key.

The validity period of the leaf is therefore **not load-bearing**, and that is
the whole purpose: no deadline that can expire while the instance that would have
to extend it lies there without quorum. Revocation is by removal from the
registration, not by waiting.

### 2. The anchor follows from whether a port lies before or behind consensus

- **Raft** lies **before** consensus. Its anchor is a **local operational
  setting** — the permissible peer keys stand next to `PeerAddrs`. The argument
  already stands verbatim in the code, for the address: *"the way to a node is an
  operational setting of the local process, not a replicated truth. Whoever mixes
  the two can correct a wrong address only through consensus — i.e. precisely not
  when it breaks it."* For the key it holds unchanged.
- **The node session** lies **behind** consensus: it is answered only by the
  leader, and a leader has quorum. Its anchor is therefore the **trust list from
  the log** — `AdmitNode { node, spki }` (ADR-0037) creates it, `RevokeTrust`
  withdraws it. With that, revocation for agents is a consensus action, as it
  should be.

Two anchors are not a break but the consequence: a port that establishes
consensus cannot draw its admission from it.

### 3. The join path stays one-sidedly authenticated

`Join`, `Challenge` and `Renew` demand **no** client certificate (findings 2 and
3). The node continues to identify itself with a token or a nonce signature; the
nonce stays exactly as ADR-0037 describes it.

What is **new** is the other direction: the node checks `tgd`. Today anyone can
pose as the control plane and accept a join — the token then goes to the wrong
party, and the attacker holds a valid invitation. Server TLS closes that.

The anchor for it has to lie locally **before** the first join: it only arrives
with `Credentials::Issued { bundle_pem }`, i.e. too late for the call that brings
it. It therefore lies next to the invitation — the same hand puts both into the
data directory. **No anchor, no join.** That is fail-closed, and it does not
contradict ADR-0019: there it is about existing, permitted work, here about first
entry into a trust boundary.

### 4. Separate listeners, so that no service can forget to ask

`tgd` gets three addresses instead of one (finding 1):

| Listener | Services | Client certificate | Anchor |
|---|---|---|---|
| `--listen` | admin, identity | no | — |
| `--cluster-listen` | Raft | **required** | local peer keys |
| `--node-listen` | node session | **required** | trust list from the log |

The obvious alternative would have been one port with `client_auth_optional` on
which each service checks for itself whether a credential was present. A service
that forgets is then open, without that standing out. The same construction as
the `NonceVault` (phase 7b) and `Confirmation` (phase 10b): **the discipline lies
in the structure, not with the caller.** A port whose default is "nobody gets
through here without a credential" cannot be forgotten.

That admin sits on the unauthenticated side is a transition and not a statement:
ADR-0018 wants the operator surface over SPIFFE mTLS, `tgctl` is node-local
today. That is ADR-0018 work and not this.

All three still bind to loopback by default. The difference is that two of them
can now safely be bound further out.

### 5. The server side terminates itself, the client side takes the hook

From finding 6 it follows necessarily: a self-issued leaf chains to no CA, so
`client_ca_root` cannot accept it, and `ServerTlsConfig` offers no other way. The
two cluster listeners therefore terminate with `tokio-rustls` and hand
`Router::serve_with_incoming` finished streams — exactly the path `tg-proxy` has
taken since 8b.

On the client side `Endpoint::tls_config_with_verifier` suffices. The
`domain_name` remains a formality: what is checked follows determination 1, not a
name in the certificate.

### 6. The verifier lives in `tg-identity`

Measured: `tg-proxy::verify::PeerVerifier` hangs on `PolicyCache` and `may_talk` —
it is a **workload** verifier, and neither `tgd` nor `tg-agent` links `tg-proxy`.
Both link `tg-identity`, and there `SpiffeId`, `Role::Node` and the anchor concept
already live.

It receives the registration **handed to it as a snapshot** and does not fetch it
itself: that way `tg-identity` does not hang on `tg-consensus`, and the check is
testable without `openraft`. The same pattern as `slice_for` in ADR-0040 and
`tg_net::wireguard::peers` in ADR-0039.

### 7. `Hello` loses its name

The server takes the node name from the connection. `NodeMessage::Hello`
afterwards carries only `applied`. That is a **protocol break** like the one from
ADR-0042 and is treated as such: a node that sends a name along is refused,
rather than the server reading it anyway to be safe. A field one lets be both
"for the transition" is the self-declaration with an extra step.

`ChallengeRequest.node` and `RenewRequest.node` stay where they are, by contrast:
on this path there is no client certificate, and the name is no risk there — the
signature has to match the key registered for **this** name.

## Consequences

**Positive**

- Four open points fall with one decision: the Raft port (since 5c), the stream
  (ADR-0040 determination 8), the self-declaration in `Hello` and the
  announcement concern from ADR-0042.
- The slice becomes again what ADR-0040 wanted: **one per node**. Least privilege
  no longer hangs on nobody reaching the port.
- The desired state, the definitions and the underlay keys go encrypted over the
  wire.
- No circle and no new reason for a cluster not to come back up: the check needs
  neither a CA nor a clock.
- The nonce from ADR-0037 stays valid and becomes merely superfluous, not wrong.
- The harness from 5b stays untouched: it sits at the `RaftNetwork` level, beneath
  the transport.

**Negative / Costs**

- **Two more addresses per node**, i.e. three operational settings and three
  firewall rules instead of one.
- **The peer keys are an operational setting.** Whoever swaps a node maintains
  them in five places — the same work `PeerAddrs` already entails.
- **A protocol break** on the stream (determination 7) requires a coordinated
  switchover, as already with ADR-0042.
- **`rustls` arrives in `tgd` and `tg-agent`.** Only `tls-ring`: the finding from
  phase 10d still holds — if `ring` and `aws-lc-rs` meet in the workspace run,
  `rustls` picks neither and panics. The provider is named explicitly, not
  guessed.
- The integration tests that start real processes need material. That is work on
  `tgd/tests` and the agent tests.

**Risks & Open Points**

- **Revocation on the Raft port is an operational action**, not a consensus
  command: change the list, restart the process. That is deliberate — restoring
  consensus must not presuppose consensus — but it is a handling that can go
  wrong, and it belongs in the operations manual.
- ~~**A node key is valid indefinitely on the cluster port.** That follows from
  determination 1 and is the price of circle-freedom. Rotation is therefore the
  same as replacement and shares the open spot with ADR-0039.~~ — **done:**
  ADR-0055.
- ~~**The node SVID stays without a task** (finding 4). Whether it gets one — e.g.
  on the admin port per ADR-0018 — is not decided here.~~ — **done:** ADR-0056.
- **Finding 5 is a correction to ADR-0012, not merely to the comment.** Whether
  management traffic should *additionally* go into the underlay is a question of
  its own; it would be defence in depth and no substitute.
- ~~The admin port stays unauthenticated. As long as `tgctl` is node-local that is
  bearable; with the first cluster client it no longer is.~~ — **done:**
  ADR-0103 — a port of its own with a registration; the socket stays the recovery
  path.

## Related ADRs

- Depends on: ADR-0037 (registered keys, joining), ADR-0006/0014 (the SPIFFE
  path, anchors), ADR-0002 (tonic), ADR-0031 (five nodes)
- Affects: ADR-0040 (determination 8 is redeemed; `Hello` changes), ADR-0042 (the
  announcement no longer rests on a self-declaration), ADR-0019 (circle-freedom
  is the condition for it), ADR-0012 (finding 5)
- Touched but not decided: ADR-0018 (the admin port), ADR-0025 (the data plane,
  unchanged)
