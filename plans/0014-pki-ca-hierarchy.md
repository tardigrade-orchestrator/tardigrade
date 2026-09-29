# ADR-0014: PKI / CA Hierarchy (air-gapped root) & Key Lifecycle

- **Status:** accepted
- **Completed on:** 2026-08-21 (sub-decisions 2 and 3, the choice of t) —
  before phase 7, as PLAN.md requires
- **Date:** 2026-08-12
- **Deciders:** Core team
- **Operational context:** REMIT/DORA, 4-9/5-9; SPIFFE identity from ADR-0006.

## Context and Problem Statement

The SPIFFE server (a subsystem in `tgd`) needs a CA to sign workload SVIDs. The
hardest question so far has been **key custody at runtime**: who holds the
signing key, and what happens on leader failover? On top of that, four temporal
figures hang together (SVID TTL, soft-fail window, revocation window,
intermediate lifetime) which until now were scattered over several ADRs. Both
are decided here centrally.

## Decision Drivers

- Minimal attack surface for the trust anchor (the root).
- No coupling of workload identity to runtime reachability (ADR-0019).
- Auditable, rare, controlled root events (DORA).
- Pure Rust; crypto FFI (PKCS#11) only isolated and deliberate.

## Decision

### Root topology (decided)

**An air-gapped offline root.** The root key lives in an HSM or on an air-gapped
system, is **never** in the cluster runtime, and signs intermediates
exclusively. That removes the root's runtime custody problem entirely.

The chain:

```
Air-gapped root            offline, lifetime in years, signs ONLY intermediates
  └─ Signing CA            an intermediate from the root (custody: see the sub-decision)
       └─ Agent intermediate   short-lived, delegated, per node (ADR-0006)
            └─ Workload SVID    X.509, SPIFFE ID in the URI SAN (ADR-0006)
```

Nothing about the agent's minting logic from ADR-0006 changes — the offline root
merely cuts the topmost stage out of the runtime.

**Optional (not the default):** the root can itself be hung as an intermediate
beneath an existing corporate root (SPIFFE "upstream CA"), should interop with
the enterprise PKI or governance require it.

### Sub-decision 1 — Custody of the signing CA (DECIDED: threshold signing)

The options considered were: (A) a cluster-wide signing CA with a replicated
key, (B) an intermediate per node, (C) a cluster-wide signing CA with a
**distributed** key via threshold signing.

**Chosen: option C — threshold signing.** A single signing identity (one group
public key), but **no single node ever holds the complete key**.

**Scheme:** FROST on Ed25519 (`frost`/`frost-ed25519`, Zcash Foundation,
audited, pure Rust). Two-round threshold Schnorr. The group signature is a
**standard Ed25519 signature** — rustls/webpki verify the chain with no special
handling (an Ed25519 CA per RFC 8410).

**Key generation:** distributed key generation (DKG), so that the full signing
key never exists (no trusted-dealer moment). The offline root certifies **one**
intermediate cert for the resulting group public key → still a single signing
CA anchored air-gapped.

**Failover:** trivial in the signing sense — there is no single key that would
have to be transferred; any t-subset of the live signers can sign.

The cut of the group and its relation to the Raft membership are fixed in
sub-decision 3; the original assumption "threshold group = Raft members,
t = Raft majority" did **not** survive it, see there.

**Compatibility with ADR-0019:** threshold signing concerns **only the upper,
rare level** (issuing the agent intermediates, roughly every 24–48 h). The
high-frequency minting of workload SVIDs stays local to the agent (ADR-0006) and
needs **no** quorum. The quorum coupling therefore sits outside the hot path;
the agent-intermediate buffer bridges threshold outages up to its lifetime.
Consequence: choose the agent-intermediate lifetime **more conservatively**
because of the somewhat worse threshold availability profile.

### Sub-decision 2 — Custody of the keys (DECIDED: an HSM for the root, TPMs for the shares)

- **Root: an HSM**, air-gapped. A rare, ceremonial device — for that, PKCS#11 FFI
  is worth it, and it is the form a REMIT/DORA auditor expects.
- **Runtime shares: TPM-sealed**, per node. A share alone is worthless below the
  threshold t; a TPM sits in every server, whereas an HSM per node makes
  procurement and operation more expensive without protecting anything below the
  threshold that would be worth protecting.

**This keeps the FFI boundary on the offline path.** That is the actual reason
for this cut: PKCS#11 is C FFI, and invariant 1 from CLAUDE.md permits it
"within narrow, isolated bounds … encapsulated as a clearly marked boundary". An
HSM per node would have put crypto FFI into the **runtime path of every
control-plane node** — and made procuring an HSM a precondition for adding a
node at all.

Rejected: no HSM (an air-gapped machine with an encrypted keystore). The trust
anchor would then rest on organizational measures, and in a regulated context
that would have to be justified against the alternative rather than simply
taken.

### Sub-decision 3 — Group cut, t and resharing (DECIDED)

This decision is checked against `frost-core` 2.2, not derived from the model.
Two findings from the library determine it:

**Finding 1: t cannot be changed by resharing.** The documentation of
`keys::refresh::compute_refreshing_shares` and `refresh_dkg_part_1` says it
verbatim: `min_signers` *"must be equal to the original value for the group
(i.e. the refresh process can't reduce the threshold)"*. t is **frozen** with
the DKG — changing it requires a new DKG, which produces a new group public key
and therefore a new intermediate from the air-gapped root, i.e. a ceremony.

**Finding 2: resharing removes participants, it does not add any.**
`max_signers` may *"be smaller than the original value"*; a new node has no
share onto which it could add a refresh share. What exists for that is
`keys::repairable` (RTS): a subset of the signers restores a lost share **for an
existing identifier**, without revealing the secret.

It follows that the original formulation does not hold. "Threshold group = Raft
members" would have meant: **every** addition of a control-plane node requires a
root ceremony. Phase 5d has just made membership changes routine (joint
consensus, online, without a ceremony); making them expensive again through the
CA would mean effectively never using them any more — and a cluster that is no
longer rebuilt out of inconvenience is exactly the case ADR-0031 wanted to avoid
with "rolling updates must not take fault tolerance to zero".

**Decided:**

1. **The signing group is decoupled from the Raft membership.** It is a fixed
   set of **N = 5 signer seats** with **t = 3**. A node that joins the Raft
   membership does **not** thereby become a signer.
2. **t = 3 of 5** — the same threshold as the Raft quorum (ADR-0031). Not
   because it moves along (it cannot), but so that there is no state in which
   the cluster can write but not sign, or vice versa: two failures are tolerated
   by both, the third blocks both.
3. **Replacing a signer runs through RTS**, not through a ceremony. If a signer
   fails permanently, another node takes over **its seat** (the same
   identifier): t helpers restore the share, the group public key stays, the
   intermediate stays valid.
4. **Proactive refresh** (`keys::refresh`) runs periodically and on suspicion of
   a compromised share — same identifiers, same group key, new shares. That is
   the case the library has the procedure for.
5. **Changing N or t is a planned ceremony:** a new DKG, a new group public key,
   a new intermediate from the offline root, bundle overlap as with root
   rotation. Rare, documented, audited — and exactly what such an intervention
   ought to be.

**Costs, deliberately borne:** signing availability now follows control-plane
availability only **approximately** rather than exactly. If the cluster grows to
seven nodes, the Raft majority is four while the signing threshold stays three —
signing is then *more* available than consensus. That is the more harmless
direction: only what consensus has already resolved is ever issued, and an agent
intermediate without Raft progress changes nothing about the desired state.

### Figures (fixed: the tight profile)

The chosen profile: **security-tight** — short identity/authz times. The values
are fixed starting values, to be evidenced for compliance.

| Figure | Value (tight) | Role |
|--------|---------------|------|
| SVID TTL | **15 min** (rotation at ~7 min) | lifetime of the workload cert |
| Soft-fail window (0019) | **2 min** | tolerance for late rotation |
| Revocation window (0025) | **~60 s** target, backstop = SVID TTL (15 min) | tearing down an existing connection after `may_talk` is withdrawn |
| Agent intermediate | **12 h** (renewal every 3 h) | buffer for a control-plane outage |
| Active-role lease (0010) | **15 s TTL / 5 s renewal** | failover latency (availability, not a security knob) |
| Signing CA intermediate | ~1 year (ceremony) | the threshold group cert |
| Root | several years (offline) | trust anchor |
| Threshold **N/t** | **5 seats / t = 3**, frozen with the DKG | signature threshold |

**The cost of this tightening (deliberate):**
- Soft-fail 2 min = little rotation tolerance; if an agent hangs past the expiry
  for longer, connections tear. Rotation tolerance traded for a narrower
  compromise window.
- 15-minute SVIDs = roughly 4× more frequent rotation (local minting is cheap,
  but it is more load).
- A 12-hour agent intermediate halves the abuse window, but also the
  static-stability buffer. **Guard rail: not below the maximum plausible
  control-plane outage window** — shorter only with an evidenced CP recovery
  statistic.

**Ordering conditions (hard rules, all observed):**
- Agent intermediate (12 h) **>** the expected control-plane recovery window —
  otherwise static stability breaks (ADR-0019).
- Agent-intermediate renewal (3 h) **≪** the agent-intermediate lifetime.
- Revocation window **≤** SVID TTL (15 min) — otherwise SVID expiry is the
  effective block.
- Soft-fail (2 min) **≪** SVID TTL (15 min) — rotation tolerance, not a second
  validity period.
- Active-role lease (15 s) **≪** SVID TTL — the fast fence lies in the lease, the
  SVID is only the identity backstop.
- Signing CA (1 year) **≫** agent intermediate (12 h) **≫** SVID TTL (15 min).

### Bootstrap (chicken and egg)

- Cluster init: generate the root offline in the HSM; the five initial `tgd`
  nodes run the DKG over **five seats with t = 3** → a group public key; the
  root certifies **one** signing intermediate for this group public key; bring
  it in by a one-off, networkless transfer. The seat assignment (identifier →
  node) is from here on an operational setting like the peer addresses and does
  **not** belong in the Raft membership — otherwise the two would be coupled
  again.
- The agent's first node credential: join token/TPM (ADR-0006); after that agent
  ↔ server runs over mTLS with node SVIDs (the control plane dogfoods its own
  identity system).
- The trust bundle (the root pubkey; the signing intermediate travels in the
  chain) is held in Raft state and distributed via the workload API.

### Revocation strategy

- **Root:** never at runtime → no online revocation. Compromise = a planned root
  rotation ceremony with bundle overlap.
- **Signing CA (the threshold group):** a single compromised share is worthless
  below the threshold t. On suspicion of ≥ t compromised shares: resharing (new
  shares, same/new group key) or a replacement intermediate from the offline
  root; a short signing-CA lifetime as the backstop.
- **Workload SVID:** a short TTL **instead of** a CRL (the SPIFFE philosophy: no
  long-lived certs → no CRL burden).

### The root rotation ceremony

Generate a new root offline → both roots in the trust bundle at the same time
(overlap) → a new signing intermediate (for the existing group public key or one
newly generated by DKG) under the new root → remove the old root after the
switchover. Documented and audited.

## Consequences

**Positive**
- Runtime custody of the root is eliminated entirely; minimal root attack surface.
- Root events are rare, planned, auditable — DORA-conformant.
- Short SVIDs replace CRL infrastructure.
- A single signing identity, but **no node ever holds the full key** (DKG);
  compromising a single node is worthless below the threshold.
- Signing failover is trivial (no key replication, no transfer gap).
- A membership change in the control plane (routine from phase 5d) does not
  touch the CA. Replacing a signer runs online through RTS, without the root.
- FROST-Ed25519 produces standard Ed25519 signatures → rustls/webpki verify the
  chain without a special path; pure Rust, no Go.

**Negative / Costs**
- Threshold signing is implementation- and test-intensive (MPC, two-round
  nonces; nonce reuse is catastrophic → it belongs in the DST/security tests).
- A membership change requires an online resharing protocol (instead of an
  offline signature), coupled to the Raft membership.
- An availability floor: if fewer than t nodes are reachable, **no** new agent
  intermediates can be issued → the agent-intermediate lifetime has to exceed
  the (somewhat more conservative) threshold recovery window.
- PKCS#11 FFI for the root (accepted within narrow bounds, isolated to the
  offline path); TPM sealing of the shares at runtime.
- **N and t are frozen with the DKG.** Changing them is a root ceremony with
  bundle overlap — not impossible, but nothing that happens in passing. Whoever
  permanently grows the cluster plans it in.
- The signing group is a **second** membership list next to the Raft membership.
  Two lists can diverge; the seat → node assignment therefore belongs under
  monitoring (ADR-0015) and in the audit trail (ADR-0020).

**Risks & Open Points**
- ~~**The choice of t:** working value = the Raft majority.~~ **Decided:** N = 5,
  t = 3, frozen with the DKG (sub-decision 3).
- ~~Sub-decision 2 (HSM vs. TPM-sealed shares).~~ **Decided:** the root in an
  HSM, runtime shares TPM-sealed.
- ~~Specify the resharing protocol and its coupling to Raft membership changes.~~
  **Decided:** decoupled — fixed signer seats, replacement via RTS, periodic
  refresh, N/t only by ceremony (sub-decision 3).
- ~~**Open: nonce discipline in the signing protocol.**~~ **Implemented in phase 7b.**
  Uniqueness does not lie with the caller but in the structure: the nonce lives
  exclusively in the `NonceVault`, it leaves only through `take`, and `take`
  removes it in doing so. An abort consumes it just as well — otherwise
  "aborting" would be the way to get it a second time. In addition the vault
  remembers the fingerprints of every commitment ever handed out and refuses one
  that repeats; that catches the case bookkeeping over identifiers does not see
  — an entropy source that repeats (a cloned VM, a restored snapshot). Tested
  under concurrency (forty simultaneous signatures, including over **the same**
  message) and under repetition (a retry returns the same commitment, no second
  signing), plus a fuzz run over random interleavings with a fresh seed.
- ~~**Open: who holds the seat assignment** (identifier → node), and how is a
  permanently failed signer recognized as such? Replacement via RTS is an
  intervention with security weight and should not run automatically on a
  timeout. Phase 7b built the **mechanics** (`repair::restore_seat` as a
  triggered function, deliberately without a watcher) and anchored the
  distinction in the type: a `Seat` is a seat, not a node. Who holds the
  assignment stays open — it belongs under monitoring (ADR-0015) and in the
  audit trail (ADR-0020).~~ — **done:** ADR-0097 (the seat assignment as a
  setting) and ADR-0108 (replacement).
- ~~**Open: custody and transport are seams, not drivers.** Phase 7b delivers
  `ShareCustody` (the TPM seam) and `SignerLink` (the network seam) plus an
  in-process implementation. The TPM sealing of this decision and the gRPC path
  between the signers are outstanding.~~ — **both done:** transport with
  **ADR-0097**, TPM sealing with **ADR-0140**. The seam held, as 7b had
  promised: `TpmCustody` takes the place where `PlainCustody` stood, and not a
  line of the signing path is different. What the build had to add lay
  elsewhere — the seam did not sit at the disk, `Material` wrote past it in the
  clear. `PlainCustody` stays and keeps carrying in its name that it is not the
  model: it is the path for a node without a TPM.
- ~~**Open: proactive refresh** (point 4 of sub-decision 3). It is not in phase
  7b's deliverables and is not built. `frost::keys::refresh` is available; the
  cadence is an operational question.~~ — **done:** ADR-0107.
- **Open (unchanged):** the figures are fixed but must be **evidenced** for
  compliance — in particular soft-fail 2 min and agent intermediate 12 h against
  a CP recovery statistic that will only exist once the cluster runs.
- ~~**Watch:** `frost-core` 3.0 has been released.~~ **Checked before
  implementation (phase 7b); result: sub-decision 3 holds unchanged.** We build
  against 3.0.0 — stable, not an alpha, pinned exactly like the consensus core.
  Both findings hold verbatim in 3.0: `refresh_dkg_part1` requires `min_signers`
  *"equal to the original value for the group"*, and `compute_refreshing_shares`
  removes missing participants instead of admitting new ones. What changed are
  names and types, not semantics: `repair_share_step_N` is called
  `repair_share_partN` and works on its own types `Delta`/`Sigma` instead of raw
  scalars; `compute_refreshing_shares` now reads `min_signers` from the
  `PublicKeyPackage`, which it carries since 3.0. Also checked was the
  compatibility claim on which the choice of FROST rests: a group signature is
  64 bytes, the group key 32, and `ring` — the same verifier that works under
  rustls/webpki — accepts it as an ordinary Ed25519 signature.

## Related ADRs

- Completes: ADR-0006 (issuance), ADR-0019 (static stability).
- Supplies figures for: ADR-0006 (TTL/soft-fail), ADR-0025 (the revocation window).
- Crypto boundary/FFI: ADR-0002.
- Audit of the CA events: ADR-0020.
