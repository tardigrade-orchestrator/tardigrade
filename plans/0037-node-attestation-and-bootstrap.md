# ADR-0037: Node attestation and bootstrap

- **Status:** accepted
- **Date:** 2026-08-22
- **Deciders:** Core team
- **Technical context:** `tgd` (the SPIFFE server), `tg-agent`, `tgctl`,
  `tg-consensus` (the command set), ADR-0006, ADR-0012, ADR-0014, ADR-0019,
  ADR-0020.

## Context and Problem Statement

The wiring after phase 8 connected everything but one piece: the **SPIFFE server
in `tgd`** does not issue the agent intermediates. To this day an operator puts
the intermediate on disk, just as they put the peer addresses there in phase 5c.

The reason is not convenience but a gap: ADR-0006 says "the first node
credential via join token/TPM; after that agent ↔ server over mTLS with node
SVIDs" — and thereby describes a procedure that is **decided nowhere**. There is
no ADR about join tokens, no determination of what a node presents, and none of
what the server checks.

ADR-0006 at the same time names what is at stake:

> Node attestation is security-critical — **a weak bootstrap means identity
> theft**.

## Two findings that narrow the solution space

**1. WireGuard does not carry the bootstrap.** The obvious move would be to use
the node-authenticated underlay from ADR-0012 — there peer keys already
authenticate nodes. It does not work: ADR-0012 says itself that "a joining node
gets its mesh configured **after** node attestation (ADR-0006)". The order is the
other way round, and reversing it would be a circle. What remains is the correct
layering — ADR-0012 names it explicitly: WireGuard authenticates nodes on the
underlay, SPIFFE authenticates workloads above it. The bootstrap sits **beneath**
both.

**2. The command set already has the place.** Phase 5a created
`RegisterTrust { node, bundle }` and deliberately left the content open: "The
content is opaque here — what it means is decided by phase 7." This ADR fills
exactly that field. A new command is not needed for it; one for the invitation
is.

## Decision Drivers

- **The bootstrap must not create a permanent secret.** What is needed once
  should be worthless afterwards.
- **No bearer secret in the audit substrate.** The Raft log is retained
  (ADR-0020); a secret in it outlives its purpose by years.
- **No hardware obligation.** A procedure that does not start without a TPM makes
  procuring a TPM a precondition for adding a node at all — the same mistake
  ADR-0014 avoided on the HSM question.
- **Restart without an operator.** A node that was away for a week should be able
  to come back; a control plane that fails is a change freeze, not an outage
  (ADR-0019).
- **Revocation must be an action**, not an expiry date.
- **Third-party risk** (DORA, ADR-0023): every trust relation to a manufacturer
  must be named.

## Options Considered

- **A — a join token.** A one-time secret an operator issues and the node
  presents once.
- **B — TPM attestation.** The node proves a key pair in the TPM; the server
  checks the EK certificate against the manufacturer CA.
- **C — a node certificate pre-provisioned by the operator.** Configuration
  management puts key and certificate in place, the node proves possession.
- **D — cloud attestation** (instance identity documents). Moot for this
  operational context: the cluster runs on our own hardware, and a cloud
  metadata service would be a third party in the bootstrap path.

## Decision

Chosen: **A as the procedure, B as a decided hardening with a named seam.**

The load-bearing idea is a separation ADR-0006 does not make: **the join token
is not the node's identity but only the permission to enter its identity once.**
After that it is worthless, and the identity is the key the node generated
itself and that never leaves it.

### The sequence

```
1. Operator:  tgctl node invite <name> --ttl 15m
              → the leader appends IssueJoinToken { node, digest, expires_at }
              → the token is emitted ONCE, only its hash stands in the log
2. Operator:  token + trust bundle (public) + server address to the node
3. Agent:     generates its node key pair LOCALLY; it never leaves the node
4. Agent:     TLS to the server, the server checked against the bundle,
              sends { token, public key }
5. Server:    hash correct? not expired? not redeemed? name matching?
              → RegisterTrust { node, bundle: <SPKI of the node key> }
                and token consumption in THE SAME log round
6. Server:    answers with the node SVID + trust bundle
7. afterwards: agent ↔ server over mTLS. The agent proves possession of its
              registered key and fetches the node SVID and the agent
              intermediate; the token never appears again.
```

### The five determinations in detail

**1. The token is bound to the node name.** It cannot be redeemed as a different
node. Whoever steals it gets the place it was issued for — not the one they
choose.

**2. Only the hash stands in the log.** The token itself is emitted once and
stored nowhere. That is no subtlety: ADR-0020 makes the Raft log the
retention-obliged audit substrate, and a bearer secret in it would be a secret
with a retention period. What has to be auditable is **that** an invitation was
issued and **when** it was redeemed — not its content.

**3. One-time, and the uniqueness is consensus-backed.** Check and consumption
stand in the same log round. Two nodes redeeming the same token simultaneously
are two requests for the same log index; one wins, the other sees a consumed
token. Without Raft that would be a race.

**4. After joining, the **key** is the identity, not the certificate.**
`RegisterTrust.bundle` — the field phase 5a left open — carries the **SPKI of the
node key**. With that:

- the node SVID can be **short** (the same tight profile as elsewhere,
  ADR-0014), because its renewal hangs on the registered key and not on a
  still-valid predecessor;
- a node comes back after an arbitrarily long absence without an operator — it
  proves possession, as it did the first time;
- revocation is **an action**: `RevokeTrust { node }`, one entry, and the node can
  never identify itself again. Not an expiry date one has to wait out.

**5. A joining node is empty, and stays that way.** Joining enters **only**
trust, no capacity. The scheduler places on nodes entered through `UpsertNode`
with topology and capacity (ADR-0034), and today an operator does that.

That is not a new precaution but an **existing property that this ADR explicitly
protects**: the blast radius of a stolen token is a node with an identity on
which nothing runs and onto which nothing is placed. Should the agent ever report
its capacity itself — the open point from ADR-0034 — this separation must be
preserved: **capacity is an operator's statement, not a node's
self-declaration.** Otherwise a stolen token procures its own work.

### TPM: decided, deferred, with a seam

TPM attestation replaces steps 3–5: instead of a locally generated key the node
proves a key pair **in the TPM**, and the server checks its EK certificate. The
gain is substantial — a cloned disk has no matching TPM, and there is no bearer
secret any more.

It nevertheless does not come now, for three reasons:

- It requires `tss-esapi`, i.e. **C FFI in the runtime path of every node**.
  Invariant 1 permits that "within narrow, isolated bounds"; ADR-0014
  deliberately put the FFI boundary on the offline path, and this step would
  bring it back in.
- It creates a **trust relation to the manufacturers' EK CAs**. That is a third
  party in the bootstrap path and per ADR-0023 is to be carried as a
  concentration risk — not inadmissible, but to be named and decided.
- It makes a TPM a **precondition** for adding a node. ADR-0014 avoided exactly
  this trap on the HSM question.

**The seam** is check step 5: what the server accepts as proof is a setting, not
a structure of the sequence. A `NodeAttestor` trait with one method — "is this
request genuine?" — carries the token checker today and the TPM checker
tomorrow, without steps 1–4 or the command set changing.

### Figures

| Figure | Value | Role |
|--------|-------|------|
| Join token TTL | **15 min** (default, settable per invitation) | the window between issuance and redemption |
| Join token uses | **1** | structural, through the log |
| Node SVID TTL | **15 min**, renewal at ~7 min | like the tight profile from ADR-0014 |
| Agent intermediate | **12 h**, renewal every 3 h | unchanged from ADR-0014 |
| Node key | no expiry, revocation by `RevokeTrust` | the actual node identity |

The 15 minutes for the token are a **starting value** and follow the same logic
as the numbers in ADR-0014: short enough that an intercepted token is rarely
still usable; long enough that an operator can transfer it. Like the other
figures it is to be evidenced once there is operational experience.

## Consequences

**Positive**
- The bootstrap creates **no permanent secret**. After joining there is nothing
  left to steal and reuse — the node key never leaves the node.
- The audit trail is complete **without** containing a secret: invitation,
  redemption, revocation are log entries (ADR-0020).
- Revocation is immediate and is an action, not a wait.
- Restart after an arbitrarily long absence without an operator.
- No hardware obligation, no manufacturer in the bootstrap path.
- The field phase 5a left open is filled — without changing the command set;
  only the invitation is added.

**Negative / Costs**
- **The token is a bearer secret** while it lives. Its security lies in the
  transport path and in the TTL, and that is exactly the point the TPM hardening
  later eliminates.
- A new node needs **two** operator actions: the invitation and entering the
  capacity. That is deliberate (see determination 5), but it is effort.
- The node key lies on the node's disk. Without a TPM only the filesystem
  protects it; whoever has the disk has the node.
- One more piece of state in the state machine (pending invitations), which
  travels with the snapshot and goes along with compaction.

**Risks & Open Points**
- **The token's transport path is not decided.** It belongs in the operations
  documentation, not in this ADR — but it is the weakest point of the procedure,
  and whoever chooses it badly has chosen the whole procedure badly.
- ~~**Who may invite?** Today anyone allowed to use `tgctl` against the control
  plane. ADR-0018 knows no roles; authorization by role is therefore open and
  concerns more than this ADR.~~ — **done:** ADR-0103 and ADR-0105.
- ~~**The capacity report** (the open point from ADR-0034) must preserve the
  separation from determination 5. If it becomes the node's self-declaration,
  the blast-radius protection falls.~~ — **done:** ADR-0049 — the report never
  reaches the scheduler.
- **TPM hardening**: decided, not scheduled. It needs a decision about the EK CA
  trust relation (ADR-0023) and one about the FFI boundary (invariant 1).
- The **numbers** are starting values, as in ADR-0014 — to be evidenced once the
  cluster runs.

## Addendum: ADR-0042 changes the scope of the signature

**ADR-0042** (`proposed`, 2026-08-23) lets the underlay announcement from
ADR-0039 travel on **this** path — it is the only one on which a node identifies
itself authenticated, and the control plane writes to the log here anyway.

That changes one determination of this ADR: today the signature covers **only
the nonce**, and that suffices against replay. As soon as the request carries a
statement that has an effect, it no longer suffices — whoever intercepted a
`Renew` call would swap the endpoint, and the signature would stay valid.

Henceforth: what is signed is **nonce ‖ key ‖ endpoint**, length-prefixed. The
entry stands here and not only in ADR-0042, because an accepted decision must
not change silently (CLAUDE.md, invariant 6).

## Related ADRs

- Completes: **ADR-0006** — "the first node credential via join token/TPM" was a
  sketch there; here stands the procedure.
- Fills: `RegisterTrust.bundle` from the phase 5a command set — the content
  ADR-0004 carries as consensus-critical.
- Subordinates itself to: **ADR-0012** (WireGuard comes **after** attestation,
  not before), **ADR-0019** (restart without an operator), **ADR-0020** (no
  secret in the audit substrate).
- Delimits against: **ADR-0014** — there it is about custody of the CA key, here
  about the identity of the node. Both use a TPM, and for different things.
- Touches open points: **ADR-0034** (the capacity report), **ADR-0018** (who may
  invite), **ADR-0023** (the EK CA as a third party).
- To be implemented in: the SPIFFE server in `tgd` and the join path of the
  `tg-agent`.
