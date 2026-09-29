# ADR-0093: The policy hangs on the instance, not on the sidecar

- **Status:** accepted
- **Date:** 2026-09-06
- **Deciders:** Architecture
- **Technical context:** `tg-net`, `tg-runtime`, ADR-0007, ADR-0025, ADR-0041,
  ADR-0060, ADR-0074

## Context and Problem Statement

Zero trust must not be switchable off by a line of XML. Measured, it is — and on
**two** paths with the same cause.

### Hole 1 — the declaration lever

```text
<mesh> missing
  └─ mesh::expand derives no sidecar                (ADR-0059)
      └─ principal is never Some
          └─ wiring.enforce() is never called       (apply.rs)
              └─ NetnsRules are never laid          (ADR-0060)
```

A workload without `<mesh>` is **unpoliced**: no redirect, no UDP filter, no mTLS
(ADR-0007), no `may_talk` check (ADR-0025), no egress allowlist (ADR-0041), no
active-role enforcement (ADR-0066).

That is not merely a gap but a **perverse incentive**: it is the only way, it is one
line, and it takes effect at once. Whoever wants to reach a UDP destination switches
off the whole data plane — the rule drives towards exactly what it is meant to prevent.

### Hole 2 — the start-up window

The derived sidecar declares `after` on its workload (ADR-0059, ADR-0009) — **the
workload starts first**. But the rule set is laid only when the *sidecar* starts.

Between the two the instance has a connected but **unfiltered** namespace: its traffic
goes straight out over the bridge. With a cold image pull for the sidecar that is
seconds to minutes. The situation is therefore not only unprotected but **fail-open** —
and nobody sees it.

### The cause is the same

**The policy hangs on the sidecar's lifecycle instead of on the instance's.** As long
as that holds, every tightening is just another reason to pull the big switch.

## Decision Drivers

- **ADR-0019:** *"a perimeter boundary one can circumvent by forgoing enforcement is
  none."* The sentence here hits not a missing permission but the forgoing itself.
- **ADR-0025 is deny by default** — but only *inside* the mesh. Outside there is no
  policy at all, and that is the inversion of the promise.
- **ADR-0060 determination 3** justified the order correctly: redirection may only
  happen once somebody listens. But it applies only to the **redirect** and was applied
  to the whole rule set.
- **No new mechanism.** The seam already exists.

## Options Considered

1. **A UDP permission so that nobody pulls the lever any more** (ADR-0092's original
   justification). Rejected as a *solution*: it mitigates the incentive and leaves the
   lever standing. An operator for whom the permission is not enough still pulls it.
2. **Make `<mesh>` mandatory in the schema.** Rejected: a document enforcing a field
   says nothing about the node that executes it — and a node without `--proxy-image`
   would still derive no sidecar. Enforcement belongs at the place that enforces.
3. **Hang the rule set on the instance.** Chosen.

## Decision

### Determination 1 — the filter chains belong to the network, not to the sidecar

`NetnsRules` produces two families, and they are already separate:

| Family | Hooks | needs a listener |
|---|---|---|
| **filter** (`filter_out`, `filter_in`) | output, input | **no** |
| **nat** (`outbound`, `inbound`) — the redirect | output, prerouting | yes |

The **filter chains are laid when attaching to the network**, for **every** instance —
with or without `<mesh>`. The **nat chains** are added when the sidecar starts.

With that the policy is as old as the namespace, and both holes are closed.

### Determination 2 — the baseline drops what does not go through the sidecar

```text
1. accept  ct state established,related   (answers to what was permitted)
2. accept  oif/iif lo                     (the redirect's destination)
3. accept  skuid == <sidecar>             (the sidecar dials out)
4. accept  daddr/saddr == <gateway>       (the resolver, ADR-0013)
5. drop    everything else                + counter
```

**Rule 3 is the whole point.** Without a sidecar process nobody carries that id — the
exception has no effect. With a sidecar it is the only door out. In one sentence:

> **The sidecar is the only door. Whoever has none does not go out.**

Rule 4 stays, because without the resolver no container resolves a name (ADR-0013), and
because the node is the counterpart and not a foreign endpoint.

### Determination 3 — ADR-0060's ordering concern resolves itself

ADR-0060 lays the redirect when the sidecar starts, because a redirect without a
listener *"would take every connection from the workload and would look like a network
problem"*. That stays right and still applies to the **nat** chains.

For the filters it does not: if the baseline drops anyway, there is nothing to lose. The
state before the sidecar is thereby **closed instead of open** — and that is the
inversion at issue.

### Determination 4 — the extension of ADR-0041 is explicit

ADR-0041 decided *"no sidecar, no egress"* for **mesh members**. This determination
extends that to **all** instances. A workload without `<mesh>` afterwards reaches only
the node-local resolver.

That is a hard behavioural change and the real price of this ADR. It stands here and in
the operations manual, not in a commit.

### Determination 5 — `--proxy-image` becomes a de facto precondition

Without the setting a node derives no sidecar (ADR-0059); after this, **no** workload
there reaches anything except DNS. That is fail-closed and intended — but it is an
operational cliff and belongs named, not discovered.

### Determination 6 — the baseline applies to the sidecar container too

It shares its workload's namespace (ADR-0059), so there is only one rule set. Its own id
is the exception in it, and under a user namespace it is the **mapped** id (ADR-0091,
determination 5).

## Consequences

**Positive.** Zero trust can no longer be switched off by a line of XML. The incentive
inverts: the way out leads **through** enforcement, not past it.

**Positive.** The start-up window is closed, and without a new ordering — the baseline
is simply there earlier.

**Positive.** ADR-0092 loses its weaker justification. The UDP and QUIC permission is
afterwards a **need**, not an emergency exit, and its determinations stand unchanged.

**Negative.** A workload whose sidecar does not come up is network-less instead of
partly reachable. Outages shift from "half broken" to "entirely closed" — the intended
direction (ADR-0025), but an adjustment in operations.

**Negative.** `--proxy-image` is from here on not optional.

## Risks & Open Points

- **Two containers on one node talk over L2** and do not traverse the `forward` chain
  (phase 9b, without `br_netfilter`). But the baseline sits in the target instance's
  **input** hook, so it bites there too — that is the difference from the situation 9b
  describes, and it is to be evidenced.
- **The state `established`** carries the answers to permitted connections. Without it
  the sidecar would not get its own answers. That is the place at which a bug looks like
  a network problem.
- **Existing namespaces** get the baseline at the next reconciliation, because
  `ensure_instance` is level-driven (ADR-0010) — not at once.
- **A node without a node network** lays no namespaces at all and is unaffected; nothing
  with an address runs there anyway.
- **Who may grant an exception** stays ADR-0044's open question.

## Related ADRs

- **Changes ADR-0060, determination 3** — it now applies only to the nat chains.
- **Extends ADR-0041** — "no sidecar, no egress" applies to all instances, not only to
  mesh members.
- **Dissolves the incentive ADR-0092 uses as a justification** — its determinations
  stay, its rationale becomes the need.
- **Applies: ADR-0025** (deny by default), **ADR-0019** (a circumventable boundary is
  none), **ADR-0074** (the chains in which the baseline sits), **ADR-0013** (the
  resolver as the only exception), **ADR-0091** (the sidecar's mapped id).
