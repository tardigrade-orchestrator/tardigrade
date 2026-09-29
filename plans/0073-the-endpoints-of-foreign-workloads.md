# ADR-0073: How a node learns the endpoints of foreign workloads

- **Status:** accepted
- **Date:** 2026-09-02
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-store` (`session`, `projection`), `tgd` (`session`),
  `tg-agent` (`session`, `network`), `tg-net` (`discovery`), ADR-0013, ADR-0040,
  ADR-0025, ADR-0012, ADR-0011, ADR-0019

## Context and Problem Statement

ADR-0013 promises service discovery as **name → healthy endpoints**. Measured, it
ends at the node:

```text
api.tardigrade.internal:    Addresses([10.42.1.5])
ledger.tardigrade.internal: NxDomain
```

`network::Network::refresh` builds the resolver's registry from `held().entries()` —
the **node-local** address ledger. For a workload the cluster runs, the node answers
"that name does not exist".

That is not a gap in the wiring but a structural data flow:

| Who | knows about container addresses |
|---|---|
| the node itself | its own (phase 9a: assigned node-locally, **deliberately**) |
| `NodeReport` | none — it carries states, capacity, generations, proxy image |
| `NodeSlice` | none — no address field, and foreign instances do not appear at all |
| the leader | none |

**Nobody can name a foreign container address.** At the same time ADR-0011
distributes the instances across nodes with `spread="rack"` as the default, the mesh
(ADR-0007/0025) secures exactly that traffic, and the underlay (ADR-0012/0039)
carries it. The name is not forwarded either: the resolver's forwarding list **is**
the egress allowlist (ADR-0041), and a cluster name does not stand there.

It went unnoticed because every proof of the data plane runs both sides in **one**
namespace pair or on **one** node. The setup that shows it is now built
(`tg-net/tests/two_nodes.rs`) and found a second thing next to this finding — a
missing rule in the node's rule set that lets traffic from the tunnel into the
bridge. That is fixed; **the address stays.**

## Decision Drivers

- **ADR-0013:** discovery is "only a projection" of the graph, and it is
  health-aware. Both hold cluster-wide or nowhere.
- **Phase 9a:** a container's address is node-local and **must not depend on the
  control plane**. Whoever assigns it is the agent.
- **ADR-0040, determination 7:** the session's return direction carries **observed
  state**, no log entries. An address an agent assigned is exactly that.
- **ADR-0025 (least privilege):** a node should learn only what its workloads need.
  `slice_for` already filters that way — edges and egress permissions.
- **ADR-0019 (keystone):** resolution must not hang on the control plane. If the
  session breaks, the last known state holds.
- **ADR-0004:** addresses are `actual`, not `desired`. They do not belong in the log.

## Options Considered

- **Option A — through report and slice.** The node reports its endpoints, the
  leader holds them in the projection, the slice gives each node the endpoints its
  workloads may dial.
- **Option B — computed from the ordinal.** Address = f(ordinal, workload,
  instance). No transport needed.
- **Option C — resolver asks resolver.** Unknown cluster names are forwarded to the
  peers' resolvers; the node knows their addresses from the underlay peer list.

## Decision

Chosen: **Option A**.

1. **The report carries the endpoints** (`NodeReport.endpoints`): workload,
   instance, address. Observed state like `states` and `capacity` — ADR-0040
   determination 7 stays untouched, **no** log entry arises.
2. **The projection holds them next to `Inner`**, replacing per node, like
   `report_capacity` and `report_stale`. `materialize` replaces the content of
   `Inner` (ADR-0030); a report does not come from the log and would vanish there on
   every materialization.
3. **The slice carries the endpoints this node may dial** — for every own workload
   `a` and every edge `a → b` the endpoints of `b`. **Only this direction:** whoever
   dials needs the address; the server checks at the certificate (ADR-0025) and does
   not need it. And **only foreign ones**: its own the node knows better, it assigned
   them.
4. **Health travels with it.** ADR-0013 returns only healthy endpoints, and an
   instance's state stands in the report of the **same** node. The leader puts the
   two together; in the slice the endpoint carries a `healthy` field. An unhealthy
   endpoint is **sent along** and not omitted: if it were missing, the answer would
   be `NXDOMAIN` instead of `NODATA`, and phase 9a made two answers of that for good
   reason.
5. **Assignment stays node-local.** Consensus **transports** addresses, it does not
   assign them — phase 9a stays untouched.
6. **Fail-static.** The agent persists the foreign endpoints next to its peer list
   (`network/endpoints.json`) and loads them at startup. If the session stays away,
   it keeps resolving what it last knew (ADR-0019) — the same construction as
   `peers.json` and the edge file.

Option B is rejected, and with the argument phase 9a already wrote down: a computed
container address makes the association a **position** — and then every change to
the instance set moves the addresses of running containers. For a node's *subnet*
the ordinal is right; for a container's address it explicitly was not.

Option C is rejected because it introduces a **new trust boundary**: a resolver
would have to believe a foreign resolver, and least privilege would have to be
rebuilt there instead of using the filter that already decides over edges. On top of
that comes a network round trip per resolution and the question of what happens when
a peer fails — the answer to the latter would be a cache, i.e. the same state as in
option A, only without the filter.

## Consequences

**Positive**

- Discovery keeps what ADR-0013 promises, and cluster-wide.
- No new mechanism: the session already carries observed state upwards and filtered
  facts downwards.
- Least privilege is the same filter as with the edges — a node learns no address
  its workloads may not dial.
- The path is fail-static: resolution survives the loss of the control plane.

**Negative / Costs**

- **A format break**, the sixth. It goes **bundled** into the window from ADR-0072,
  determination 3, and not individually.
- The leader's projection now holds container addresses. They are `actual`, not
  retention-obliged, and stand in no log (ADR-0020) — but they are there, and `tgctl
  cluster show` could show them. Whether it should is open.
- **Eventual.** An address just assigned reaches a foreign node only through report
  and slice. ADR-0013 names eventual staleness as a known cost, and the short TTL
  (5 s, phase 9a) is chosen for exactly that.
- **Backpressure grows.** The report gets longer by a list whose length grows with
  the number of instances per node. At a channel depth of eight messages (ADR-0068)
  that is bearable; it is not a bound.

## What this decision does not govern

- **The zone.** `--dns-domain` stays a setting per node. Two nodes with different
  values resolve the same names under different zones; whether the zone belongs in
  consensus is a question of its own.
- **Whether an operator should see the addresses** (`tgctl cluster show`).
- **Whether the report has to be trimmed with very many instances.**

## Related ADRs

- **ADR-0040** — the path to the node; determination 7 stays untouched: the return
  direction carries observed state, no log entries.
- **ADR-0013** — service discovery; until now it ended at the node.
- **ADR-0025** — the slice's edge filter **is** least privilege.
- **ADR-0004** — the address is `actual`, not `desired`.
- **ADR-0011** — the scheduler distributes across nodes, and precisely from that the
  question arises.
