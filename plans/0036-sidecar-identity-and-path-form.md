# ADR-0036: The identity of the sidecar — and the form of the SPIFFE path

- **Status:** accepted
- **Date:** 2026-08-22
- **Deciders:** Core team
- **Technical context:** `tg-identity` (ID derivation, attestation), `tg-proxy`
  (phase 8b), `tg-model::mesh`, ADR-0006, ADR-0007, ADR-0025.
- **Supersedes:** the path determination from ADR-0006 (there:
  `spiffe://<domain>/ns/<namespace>/workload/<name>`). Everything else from
  ADR-0006 stays in force.

## Context and Problem Statement

Phase 8a derived the sidecar as **its own unit** in the dependency graph
(ADR-0007/0009). That raises a question nobody had to ask before: **which
identity does the sidecar put on the wire?**

Two accepted ADRs give different answers, and neither of them had the sidecar in
mind:

- **ADR-0006** binds the identity to the **container**: "the agent binds the SVID
  to the concrete container (the PID/cgroup association of the OCI runtime
  start)". The sidecar is a container of its own, so it would get
  `spiffe://…/workload/api-proxy`.
- **ADR-0025** draws the `may_talk` edges between **workloads**: `api → ledger`.
  For the edge to bite, `api` would have to stand on the wire — because it is the
  sidecar that establishes and accepts the connection.

Both at once is impossible. Without a decision phase 8b is not buildable: the
sidecar has to present a certificate, and which one decides everything else.

## A second finding that belongs here

While re-reading ADR-0006 for this decision it became apparent that the **path
form determined there was never built**:

| | Path |
|---|---|
| ADR-0006 determines | `spiffe://cluster.local/ns/<namespace>/workload/<name>` |
| Phase 7a builds | `spiffe://cluster.local/<role>/<name>` |

That is not a triviality and not an accident, but two things:

1. **A namespace concept does not exist in the project.** `schema/workload.xsd`
   does not know it — phase 1 did not build it, and no later phase supplied it.
   The workload name is unique cluster-wide; the dependency graph has enforced
   that since phase 3 (`DuplicateWorkload`).
2. **7a introduced a role segment instead** (`/workload/…` vs. `/node/…`), and
   for a good reason: without it a workload named `node-1` could assume the
   authority of the node `node-1`. The reason stands in the code and in the
   commit — but **not in an ADR**, and invariant 6 from CLAUDE.md requires
   exactly that for changing an `accepted` decision.

The finding belongs in **this** ADR and not in one of its own, because both
questions are the same one: the identity of the sidecar is a statement about the
path. Whoever answers it without fixing the path form answers it on sand.

A side effect that becomes explicable through this: ADR-0025 names `/ns/trading/`
as an example of a prefix selector. That example was **correct** at the time of
ADR-0025 — it rested on the path form from ADR-0006. Only 7a pulled the ground
out from under it. Phase 8a therefore put the selector on the name and
documented the deviation; with this ADR it is no longer a deviation but the
consequence of a written-down decision.

## Decision Drivers

- **The `may_talk` edge must read what the operator wrote.** ADR-0020 requires
  demonstrability of "who could talk to whom and when". An edge that stands
  differently in the log than it acts is worthless as evidence.
- **No naming property may become a security property.** A rule of the form
  "whoever is named so may do that" is one you attack by naming.
- **The authority binding from ADR-0006 stays.** An agent mints only for
  workloads placed on its node — the bounded blast radius hangs on that.
- **No new mechanism where the specification has one.**

## Options Considered

### A — The sidecar presents its workload's identity

The agent mints `…/workload/api` for the sidecar container. The edge
`api → ledger` bites unchanged.

**Against:** the identity is then no longer bound to the container but to an
association. And the sidecar no longer has an identity of its own — it cannot
identify itself to the agent or the control plane as what it is.

### B — The edges are derived along with it

The sidecar keeps `…/workload/api-proxy`, and from `api → ledger` an additional
`api-proxy → ledger-proxy` arises.

**Against:** the effective policy is then not the written one. Between what an
operator sets and what is enforced lies a derivation — and the audit trail shows
edges nobody wrote. That is exactly the kind of indirection that makes ADR-0020
expensive.

### C — Sidecar and workload share the cgroup

Two containers, one cgroup — the pod model. The attestation from ADR-0006 then
yields the same identity by itself.

**Against:** it yields it because it **cannot distinguish** the two. With that,
any future distinction is gone too, and the cgroup — the only attestation basis
we have — becomes blurrier instead of sharper. Besides, it requires a pod
concept that does not exist in the model (ADR-0011 places workloads, not
groups).

### D — Delegation: the sidecar holds **two** SVIDs

The sidecar container gets its own identity `…/workload/api-proxy` **and** a
delegated SVID for `…/workload/api`. It uses the delegated one on the mesh wire
and its own for everything concerning itself.

## Decision

### Part 1 — The path form

What is built is written down:

```
spiffe://<trust-domain>/<role>/<name>
       role ∈ { workload, node }
       name = the facet from ADR-0008: [a-z][a-z0-9-]{0,62}
```

**No namespace segment.** The workload name is unique cluster-wide, and a
hierarchy that does not exist in the definition format does not belong in the
identity. Should a namespace concept ever arrive, that is a change to the
definition format (ADR-0008), to the graph (ADR-0009) and to this path form all
at once — i.e. a new ADR and a new namespace for the schema, not a silent
extension.

**The role segment stays**, with the reason from 7a: without it the identity of
the workload `node-1` and that of the node `node-1` would coincide.

**Prefix selectors act on the name** (`ledger-*`), not on a path. The wording in
ADR-0025 is thereby adapted to the actual path form; the selector's purpose —
limiting edge proliferation — remains fulfilled.

### Part 2 — The identity of the sidecar

Chosen: **Option D — delegation, two SVIDs.**

**Why the specification can already do this.** `X509SVIDResponse` carries
`repeated X509SVID svids`, and the field `hint` exists for exactly this: "An
operator-specified string used to provide guidance on how this identity should
be used by a workload **when more than one SVID is returned**." The workload API
that phase 7c built therefore hands out two identities without any extension.
Our own mechanism would here be a second one next to an existing one.

**The rules:**

1. The sidecar container gets its **own** SVID (`…/workload/api-proxy`),
   attested like any other container through cgroup and `SO_PEERCRED`. ADR-0006
   is thereby untouched — the binding to the container still holds, and for
   **every** issued SVID.
2. In addition it gets a **delegated** SVID for the workload whose sidecar it
   is, with `hint = "delegated"`. Its own carries `hint = "self"`.
3. **Delegation is a property of the desired state, not a naming property.** The
   agent delegates exactly when the requesting container is, in its local
   desired state, the **derived** sidecar of a workload — i.e. passes the check
   from `tg_model::mesh`: proxy image **and** `bindsTo` **and** `after` on
   exactly that workload. The name suffix is merely the address, not the
   credential. A hand-written workload named `fremd-proxy` does not pass this
   check.
4. **The authority binding applies to both.** An agent delegates only for
   workloads placed on its node (ADR-0006). The blast radius stays that of one
   node.
5. On the mesh wire the sidecar uses the **delegated** SVID. That way the
   `may_talk` edges read exactly what the operator wrote, and ADR-0025 stays
   unchanged.
6. Towards agent and control plane it uses its **own**. There it is a sidecar
   and should be one.

**What delegation does not widen.** The sidecar terminates its workload's TLS —
it sees its plaintext and speaks in its name anyway. A compromised sidecar can
therefore represent the workload either way. Delegation makes that **visible**
instead of hiding it; it creates no possibility that did not exist before.

## Consequences

**Positive**
- The written edge is the effective edge. The audit trail per ADR-0020 reads
  like the intent.
- ADR-0006 stays valid in substance: every identity still hangs on the container.
- ADR-0025 needs no change.
- No new mechanism — multi-SVID issuance is in the specification and in the
  `.proto` that phase 7c vendored.
- The path form finally stands in writing where invariant 6 requires it.

**Negative / Costs**
- The agent mints **two** SVIDs for sidecars instead of one. At a 15-minute TTL
  (ADR-0014) that is double the minting load for mesh members; local minting is
  cheap, but the number belongs in observability (ADR-0015).
- The delegation check is one more security-relevant place. It belongs backed by
  its own tests, particularly against the case "a hand-written workload looks
  like a sidecar".
- The workload API socket has to distinguish **which** container is asking and
  deliver one or two identities accordingly. That is a case distinction in a
  path that previously had none.
- The path change relative to ADR-0006 is retroactive: what stands there was
  never built. Whoever read ADR-0006 and acted on it was wrong — that is the
  price of the deviation going unnoticed for a phase and a half.

**Risks & Open Points**
- **The delegation check is only as good as the local desired state.** An agent
  with a stale cache delegates per the old state. That is the same property
  ADR-0019 explicitly wants elsewhere (fail-static), but it belongs named here:
  a withdrawn mesh membership takes effect only with the cache update, and the
  backstop is the SVID TTL.
- **Open: what a workload sees that gets both SVIDs but is not a sidecar.**
  Today, nobody. Should another case of delegation ever arrive (ADR-0016 secrets
  service?), the rule belongs generalized rather than copied.
- **Open (unchanged from 8a):** ADR-0025 wants L4 authorization, "identity
  **and** port/proto". The command set from 5a carries only `from` and `to` on an
  edge. That is an extension of the Raft log and therefore of the audit substrate
  (ADR-0020) — a step of its own, not something done in passing.
- **Open:** whether the role segment ever grows further roles (e.g. `/agent/…`).
  Today two suffice.

## Related ADRs

- **Supersedes:** the path determination in ADR-0006. The rest of ADR-0006 —
  server architecture, the delegated intermediate, the authority binding, the
  bootstrap chain — stays in force unchanged.
- Answers the open point from ADR-0006: "define the workload attestation
  selectors exactly (what constitutes workload X?)" — for the sidecar case.
- Preserves: ADR-0025 (edges between workloads, unchanged), ADR-0007 (the
  sidecar model), ADR-0009 (the coupling).
- Builds on: ADR-0035 (the workload API that can hand out two SVIDs).
- To be implemented in: phase 8b (the sidecar) and in the workload API socket
  from 7c.
