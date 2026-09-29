# ADR-0039: The WireGuard underlay — control path, keys and peer distribution

- **Status:** accepted
- **Date:** 2026-08-22
- **Deciders:** Core team
- **Technical context:** `tg-net` (the underlay), `tg-consensus` (the command
  set), `tg-agent`, `tgd`, ADR-0004, ADR-0012, ADR-0019, ADR-0023, ADR-0031,
  ADR-0037, ADR-0038.

## Context and Problem Statement

ADR-0012 decides **that** a kernel WireGuard full mesh lies between all nodes,
and justifies it: one uniform, encrypted, node-authenticated underlay that at
the same time **is** the flat L3 — the physical network then does not have to
route the container subnets.

It does not decide **how**. Four things are open, and each of them blocks the
build:

1. By what path is the kernel configured?
2. Where do the keys come from, and where do they lie?
3. How do the nodes learn of one another — peer list, endpoint, `AllowedIPs`?
4. Where does the ordinal come from, from which phase 9a derives the node subnet?

Point 4 is an open account: 9a built the ordinal as an **input** and noted in the
module header that it comes "from consensus (ADR-0037, at admission)". The
command `AdmitNode` does not carry it, and `NodeEntry` does not hold it. Without
it there is neither a node subnet nor `AllowedIPs`.

## Decision Drivers

- **ADR-0023, the licence allowlist.** No GPL/AGPL, not even through a C library
  (the finding from ADR-0038).
- **ADR-0012, the datapath in the kernel.** Kernel WireGuard, not boringtun —
  otherwise the latency reason for the whole decision is gone.
- **ADR-0019, static stability.** An existing mesh has to survive the absence of
  the control plane. Only **new** peers need quorum.
- **ADR-0004/0020.** What goes into the Raft log is desired state and at the same
  time audit material. Secrets do not belong in it.
- **ADR-0031.** Five nodes. A full mesh here is 20 directed entries, not a
  scaling question.
- **Determinism.** What can be **computed** from existing state does not
  additionally belong in the log — two sources for the same fact are two
  opportunities to let them diverge.

## Sub-decision 1: the control path

Measured on 2026-08-22:

| Path | Licence | Finding |
|---|---|---|
| `wireguard-control` 2.0.0 | **LGPL-2.1-or-later** | falls under the same rule as `rustables` (ADR-0038) |
| `wireguard-uapi` 3.0.1 | MIT | brings a **second** netlink stack with `neli` next to `rtnetlink`'s, plus `darling`, `derive_builder`, `syn 1.0` |
| `defguard_wireguard_rs` 0.11.2 | Apache-2.0 | lies on the same stack but one level higher than needed |
| `netlink-packet-wireguard` 0.5.0 | **MIT** | exactly the generic netlink family, on the same stack as `rtnetlink` |
| the `wg` program | GPL-2, separate process | admissible per ADR-0038 — but **not installed** on the build host |

Chosen: **`netlink-packet-wireguard`** on the stack that `rtnetlink` has brought
along since phase 9b anyway.

**Why this does not contradict ADR-0038.** There the choice fell on a called
program because there was **no** licence-clean netlink path to nf_tables. Here
there is one. The rule from ADR-0038 was never "always a process" but "the
cheapest licence-clean boundary" — and a library boundary is cheaper than a
process boundary when both are clean.

The difference is measurable too: `nft` is already present on the build host
(Fedora installs it with `firewalld`), `wg` is not. An operational precondition
that has to be installed first is one precondition more.

**boringtun stays out.** ADR-0012 names it as a fallback for kernels without
native WireGuard support. It is a **userspace datapath**, and that is exactly
what ADR-0012 rejected for tail latency. A fallback that gives up the property
for whose sake the decision was made is not one. The kernel module is a hard
precondition and is checked at startup — like `nft` (ADR-0038, determination 6).

## Sub-decision 2: keys

- **X25519, generated locally, the private part never leaves the node.** The same
  form as the node key from ADR-0037, and for the same reason: the key *is* the
  identity, so it must not lie anywhere else. The public part goes into the log.
- **A key of its own, not the one from ADR-0037.** An Ed25519 key could be
  converted computationally to X25519; we do not do it. Using the same key in two
  protocols is a known trap — what is a harmless signature in one protocol can be
  an oracle in the other. The price is two key pairs per node; it is small.
- **Crate:** `x25519-dalek` (BSD-3-Clause, in the allowlist). `curve25519-dalek`
  has been in the tree since ADR-0014 anyway — so it costs **one** crate.
- The private part lies with the other node secrets under `<data-dir>/identity/`,
  with `0600` like the node key.

## Sub-decision 3: what goes into the log — and what does not

One new command:

```
AnnounceUnderlay { node, wg_public_key, endpoint, at }
```

Three statements, all public. The log is an audit substrate (ADR-0020); a private
key in it would not be retractable.

**`AllowedIPs` explicitly do *not* stand in the log.** They follow from the
node's ordinal through the pure function from phase 9a (`ClusterNet::subnet`).
Replicating them as well would mean carrying the same fact twice — and the day
the two diverge produces a network in which packets are tunnelled to the wrong
place, with no error appearing anywhere.

**The endpoint comes from the node**, not from a computation: only it (and its
operator) knows which address is reachable from outside. The setting
`--underlay-endpoint`; the port is fixed at **51820**, the WireGuard standard —
so that firewall rules and operator knowledge carry over.

## Sub-decision 4: the ordinal

It is **assigned in the same apply** in which `AdmitNode` is checked — the same
construction as the uniqueness of the invitation in ADR-0037: no race, because
check and assignment are one apply.

- The **smallest unoccupied** number is assigned. Deterministic from the log, so
  the same on every replica. The command does not carry it — what can be computed
  does not belong in it.
- **It is freed only by explicitly removing the node**, never by failure. A node
  that was away for a week still has its subnet.
- A node that rejoins after a removal is a **different** node and gets a
  different number. Its old addresses are then no longer addresses of its subnet
  — and that stands out, because `Leases::restore` from phase 9a rejects exactly
  that (`LeaseOutsideSubnet`). In that case the agent discards its address ledger
  instead of continuing with addresses that are routed nowhere.
- The supply is the capacity of the cluster CIDR: with `10.42.0.0/16` and a `/24`
  per node that is 256 admissions over the cluster's lifetime. Should that ever
  get tight, the answer is a further cluster CIDR and not reuse.

## Sub-decision 5: fail-static

The agent writes its peer list **next to** the desired-state cache, just as it
writes its address ledger there (phase 9a). At startup it builds the mesh from
that, without asking anyone.

From that follows the split ADR-0019 requires:

- **Existing peers** survive any control-plane outage.
- **New peers** need quorum — a node nobody knows cannot get into the mesh either.

## Consequences

**Positive**

- Pure Rust, one netlink stack, no second program among the operational
  preconditions. One crate for the family, one for the keys.
- `AllowedIPs` and node subnet have **one** source: the ordinal.
- The underlay survives the control plane; the boundary is sharp and explainable
  in one sentence.
- The log carries only public material.
- The ordinal closes the open account from phase 9a.

**Negative / Costs**

- **Two key pairs per node** (Ed25519 for identity, X25519 for the underlay) and
  therefore two things an operator has to back up.
- The WireGuard **kernel module** becomes a hard precondition; without it the
  agent does not start.
- **Double encryption** (WireGuard and mTLS) stays, as ADR-0012 booked it as a
  deliberate price.
- The ordinal supply is finite, because nothing is reused.

**Risks & Open Points**

- ~~**Key rotation** is not decided. It needs a window in which a node has two
  valid public keys — otherwise the switchover tears the mesh. That belongs in a
  decision of its own, together with the question of whether rotation hangs on
  the SVID cadence from ADR-0014 or gets deadlines of its own.~~ — **done:**
  ADR-0055.
- **O(N²)** stays formally; with five nodes it is 20 entries. Above roughly a
  hundred nodes a different topology would be needed — not our case, and ADR-0031
  fixes the size anyway.
- **An endpoint change** (a node moves to a different address) is a
  re-announcement; whether the old one expires at once or overlaps is to be
  decided together with rotation.
- Whether the **MTU** has to differ per peer when a node sits behind a smaller
  path. Today one number applies to all (1420, phase 9a) — and the kernel sets
  the same one for a fresh WireGuard interface by itself.

## Related ADRs

- Executes: ADR-0012 (the "how" to its "that").
- Depends on: ADR-0023 (licence), ADR-0037 (admission), ADR-0031 (size),
  ADR-0004/0020 (what belongs in the log), ADR-0019 (fail-static).
- Supplements: ADR-0038 — the same question, a different answer, and the
  justification for it stands in sub-decision 1.
- Supplemented by: **ADR-0042** — *how* the announcement reaches the control
  plane was left open by this ADR; it travels on the credential path from
  ADR-0037, and with that the key rotation named there as an open point becomes
  routine instead of a ceremony.
- Closes the open account from phase 9a (the ordinal).
