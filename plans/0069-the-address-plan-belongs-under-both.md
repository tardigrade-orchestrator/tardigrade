# ADR-0069: The address plan belongs under consensus and under the node

- **Status:** accepted
- **Date:** 2026-08-31
- **Deciders:** Architecture
- **Technical context:** `tg-model::network`, `tg-net::ipam`, `tg-consensus`
  (ADR-0012, ADR-0037, ADR-0039, ADR-0040)

## Context and Problem Statement

ADR-0039 determines: a node's **ordinal** arises in consensus at its admission, and
from it its subnet follows by pure computation. The computation itself lay in
`tg_net::ipam` — where the node needs it.

Consensus must not link `tg-net` (netlink, nftables, `nft`). It therefore did not
know the address plan **at all**, and two commands were thereby accepted that
cannot have any effect:

- **`SetClusterNetwork` took an arbitrary string.** `self.network =
  Some((cidr.clone(), *node_prefix)); Outcome::Applied` — no parsing, no check of
  the prefix, no comparison with the ordinals already assigned. An operator's typo
  therefore stood as a **valid** instruction in the audit substrate (ADR-0020), and
  the error appeared only on every node when building the underlay — fail-soft there
  (ADR-0019) and once per slice.
- **`AdmitNode` assigned ordinals without an upper bound.** `next_free_ordinal` took
  the smallest free number; its comment explicitly pointed out that "a full cluster
  CIDR stands out in `ClusterNet::subnet` anyway". That is true and too late: it
  stands out on the **node**, in a fail-soft path. The cluster admitted a node for
  which it has no addresses.

## Decision Drivers

- **The log is retained.** ADR-0020 makes it a WORM substrate; an instruction that
  is not executable does not belong in it as `Applied`. The rule already stands in
  the tree — `MalformedUnderlay` carries it verbatim ("checked **before** being
  taken into the log: what stands in it is read by somebody later") — it just was
  not applied to these two commands.
- **Both commands carry everything needed to check them.** That is the difference
  from `UpsertWorkload`: referential integrity arises only over the whole set, and a
  state machine demanding it per command would be unusable. A CIDR is
  self-sufficient.
- **A second copy of the computation would be the error source itself.** If it
  drifted, consensus would be stricter than the node (unnecessary refusals) or laxer
  (the finding from above, back again). This project has measured the duplicate
  source as a cause several times.

## Options Considered

- **A — the check in `tgctl`.** It does not bite: per ADR-0044 anyone reaching the
  socket may call `AdminClient::write` directly, and the log would still get the
  string.
- **B — rebuild the arithmetic in `tg-consensus`.** Ten lines, and exactly the
  duplication at issue.
- **C — consensus links `tg-net`.** netlink and `nft` in the consensus core. No.
- **D — the pure computation moves beneath both.**

## Decision

Chosen: **Option D**.

### 1. `tg_model::network::Plan` is the one source

Cluster CIDR and node prefix, plus `capacity`, `holds(ordinal)` and
`subnet_of(ordinal)`. Pure arithmetic without kernel, network or cluster.

`tg_net::ipam::ClusterNet` keeps its surface and **delegates**; the error form
(`IpamError`) stays there, because it belongs to that crate's callers. `NodeSubnet`
and everything node-local likewise stay where they are: gateway, address ledger and
interface names are not a domain question.

**`tg-net` thereby depends on `tg-model`.** The plan until now carried the opposite
as a property ("`tg-net` depends on neither `tg-store` nor `tg-model`"). Half of it
still holds — `tg-store` stays a dev dependency — and the other half is given up
with reason: the property was a statement about independence, and it covered a bug.

### 2. `SetClusterNetwork` is checked before it goes into the log

Parseable, the prefix narrower than the CIDR and not narrower than `/30` — and **the
ordinals already assigned still have to fit.** An ordinal is assigned at admission
and held (ADR-0039); a subsequently narrowed network would take existing nodes'
subnets away, and every route, every nftables rule and every `AllowedIP` would
afterwards point into the void.

### 3. Where there is no subnet left, no node is admitted any more

`AdmitNode` refuses if the next free ordinal lies outside the address plan.

**The relation to ADR-0037 belongs named**, because it says there that "joining
enters **only trust**, no capacity". That sentence means workload capacity — the
blast radius of a stolen token should be "a node onto which nothing is placed".
Address space is something else: ADR-0039 made the ordinal **part of the
admission**. What is refused is therefore not for lack of capacity but because the
admission itself is not fully executable. The blast radius does not grow.

### 4. Without a set address plan nothing is bounded

It may arrive later (ADR-0040), and a cluster that admits no node before it would
never come up. The same holds for an **old, unchecked** entry from the time before
determination 2: the log is retained, such entries exist, and they must not prevent
an admission — only not bound it.

## Consequences

**Positive**

- The log no longer carries a network instruction that is not executable.
- An operator learns of the error **when issuing it**, with a reason, instead of
  hunting for it later in every node's logs.
- The computation stands in one place and is used by both sides.

**Negative / Costs**

- `tg-net` links `tg-model` (and through it `tg-defs`). In the binary that costs
  nothing — `tg-agent` links both anyway — but it is an edge that did not exist
  before.
- A cluster can now be "full". With the default `/16` + `/24` that is 256 nodes;
  whoever wants more has to widen the address plan **before** the 257th node, and
  widening is permitted (only narrowing below the assigned numbers is not).

**Risks & Open Points**

- **A `RemoveNode` frees an ordinal, an outage does not** (ADR-0039). In a full
  cluster that means: a permanently dead node occupies its place until somebody
  removes it. That is intended and now becomes visible, because the bound bites.
- ~~**The capacity is not a metric.** How close a cluster is to its limit nobody
  reports; an operator notices at the first refusal. That is the same gap as with
  the alerting rule set from phase 11b.~~ — **done: ADR-0127.** On inspection the
  number had long been there: ADR-0109 computes the **pressure** at every placement
  in order to sort candidates, and throws it away. From here on `Plan` carries its
  occupancy out — **one** derivation, the scheduler's — and `tg_node_pressure` says
  *how full*, `tg_node_free{resource}` *what it still suffices for*. The denominator
  is the **plannable** capacity (ADR-0047): the raw one would yield a number smaller
  than the truth, and in exactly the reassuring direction.
- **IPv6** stays out, as in ADR-0012.

## Related ADRs

- ADR-0012 — container networking; requires deterministic assignment.
- ADR-0039 — the underlay; makes the ordinal part of the admission.
- ADR-0037 — node attestation; "only trust, no capacity".
- ADR-0040 — the path to the node; introduces `SetClusterNetwork`.
- ADR-0020 — the log as an audit substrate.
