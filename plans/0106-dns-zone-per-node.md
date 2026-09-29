# ADR-0106: The DNS Zone Stays a Setting per Node

- **Status:** accepted
- **Date:** 2026-09-07
- **Deciders:** Architecture
- **Concerns:** ADR-0013 (service discovery), ADR-0040 (slice), ADR-0059
  (setting per node), ADR-0069 (address plan in consensus)

## Context and Problem Statement

`--dns-domain` is a setting per node with the default `tardigrade.internal`.
It is the same string cluster-wide, and therefore it stands under the same
suspicion as the cluster CIDR did before **ADR-0069**:

> It is the same number cluster-wide and therefore really belongs in
> consensus. As long as it is a setting, two nodes with different values
> compute different subnets — without anyone noticing.

The plan has carried the question as open since the visibility step: *"whether
the zone belongs in consensus … making it a cluster-wide fact would be a
decision with a log command and a seventh format break — and the question is
thereby the same as with the proxy image (ADR-0059 deliberately left it per
node there)."*

It has been within reach five times and never decided. That is the occasion.

## Decision Drivers

- **An offset must not be silent.** That is the lesson from ADR-0069, and it
  applies regardless of where the setting lies.
- **A setting per node permits a rolling change.** That is the positive side
  that ADR-0059 expressly accepted for `--proxy-image`.
- **What moves into consensus costs a format break** (ADR-0072, determination
  3) and a coordinated window.
- **And here it costs more than with the CIDR:** checking a zone is RFC 1035
  canonicalization, and that lies in `tg-net` — a crate `tg-consensus` must
  not link (netlink, `nft`). ADR-0069's way would therefore not be one
  function but pulling `canonical`, `NameError` and two constants into
  `tg-model`.

## The finding that turns the answer around

The obvious assumption is that a zone offset tears resolution apart in the
cluster — then there would be no legitimate intermediate state, and the
setting would belong in consensus.

**Measured, it is false.** The agent builds **one** `Domain` from
`--dns-domain` and gives it to both consumers: the resolver's registry and the
container's `resolv.conf` (`search <zone>`). A node is thereby internally
consistent, and a container that addresses its dependency by the **bare name**
— the normal case for an unmodified foreign image (ADR-0013) — resolves on
every node: on A `api.zone-a` is asked, on B `api.zone-b`, and both resolvers
know their endpoints from the slice (ADR-0073).

What an offset costs is therefore exactly one thing: a **fully qualified**
name in a workload's configuration. That resolves on one node and not on the
other — and, if an egress path exists, is forwarded outwards (ADR-0041,
determination 6).

There is therefore a legitimate intermediate state, and the rolling change is
the same gain ADR-0059 chose.

## Options Considered

### K1 — `SetDnsZone` in consensus, travelling in the slice

Like the cluster CIDR since ADR-0069. The zone is set once, applies
cluster-wide, and the state machine rejects one that leaves no room for a
workload name.

- **For:** one source, one change, one central rejection.
- **Against:** a format break, a log command, moving the RFC 1035 check into
  `tg-model` — and the loss of the rolling change for an error case that, per
  the finding above, concerns only FQDNs.

### K2 — Setting per node, offset visible (chosen)

The zone stays `--dns-domain`. The offset is a metric, and which zone a node
serves stands in the read view.

- **For:** no format break, no rebuild, rolling change possible, and
  visibility is the answer this tree has chosen four times (ADR-0054,
  ADR-0057, ADR-0059, ADR-0091).
- **Against:** a change is an action per node, and an offset stays possible.

### K3 — Setting per node, but the leader rejects deviation

The leader could take a node with a deviating zone out of resolution.
**Rejected**: that would turn an observation into a decree, and ADR-0057
forbids exactly that — the input would be a report whose absence is a failure.

## Decision

### 1. The zone stays a setting per node

`--dns-domain`, default `tardigrade.internal`. No log command, no field in the
slice, no format break.

### 2. A node is internally consistent — and that is the condition

Resolver zone and the container's `search` line come from **one** `Domain`.
Determination 1 rests precisely on that: only so does a bare name resolve on
every node, and only for that reason does an offset have a legitimate
intermediate state.

The property is therefore guarded. Whoever one day splits it — the zone from
the slice, the search list from the setting — must make this decision anew.

### 3. The offset is visible, not forbidden

`tg_cluster_dns_zones` counts the distinct zones of the reporting nodes (`1`
means uniform), and `tgctl cluster nodes` names **which** one a node serves.
The same construction as `tg_cluster_proxy_images` and
`tg_cluster_userns_postures`.

### 4. What a zone leaves over is said at startup

The zone is checked on its own; only `<name>.<zone>` blows the 253 bytes from
RFC 1035, and then the resolver answers NXDOMAIN for **everything** — which
looks like "the service does not exist". The agent says so at startup, in
three grades: fits, shorter names only, or **nothing**.

The rule stands as a pure function (`zone_advice`) and not as a `match` in the
construction of the node network — the same movement as `sockets::advice`
(ADR-0081) and for the same reason: a decision about an operator's setting
that can only be checked against a running node network is one whose edges
nobody has ever seen.

### 5. Fail-soft, like the rest of the node network

A zone that leaves no room is valid and is not rejected: the node still
carries bridge, addresses and rule set, and a container reaches its neighbours
via the address (ADR-0019). What is missing is resolution — and that stands
there as an `error!`.

## Consequences

**Positive**

- No format break, no log command, no rebuild of `tg-model`.
- A rolling change of the zone stays possible, and for bare names it is
  seamless.
- What too long a zone costs is said by the node at startup rather than at the
  first NXDOMAIN.
- The question is decided instead of within reach five times.

**Negative / costs**

- **A change is an action per node.** The same price as with `--proxy-image`
  (ADR-0059) and `--userns-base` (ADR-0091).
- **An offset stays possible**, and a workload with a fully qualified name in
  its configuration then breaks on part of the cluster. Visible, not
  prevented.
- **The zone stands in no audit trail.** No log entry says who changed it —
  unlike the cluster CIDR since ADR-0069.

## Related ADRs

- **ADR-0013** — the zone and the node-local resolver.
- **ADR-0069** — the counter-case: the cluster CIDR **does** belong in
  consensus, because two nodes compute different *subnets* from it and every
  route then points into the void. With the zone nobody computes anything
  another node would have to use.
- **ADR-0059**, **ADR-0091** — the same choice for `--proxy-image` and
  `--userns-base`, together with the same metric.
- **ADR-0057** — the reason against K3.
- **ADR-0072** — the format break that thereby does not arise.
