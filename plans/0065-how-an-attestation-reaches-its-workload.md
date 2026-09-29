# ADR-0065: How an attestation reaches its workload

- **Status:** accepted
- **Date:** 2026-08-31
- **Deciders:** Architecture
- **Technical context:** `tg-identity` (`attest`, `agent`), `tg-runtime`
  (`reconcile`, `bundle`), `tg-agent`

## Context and Problem Statement

The attestation reads the requesting process's cgroup and derives the workload
from it (ADR-0006). It does so **backwards**: it strips the prefix `tg-` from the
container identifier and takes the rest as the name.

But since ADR-0034 the identifier carries the **instance number**
(`container_id("api", 1)` = `tg-api-1`). Read backwards that yields the workload
`api-1`, and that does not exist: what is assigned is `api`. Measured against a
real `Minter`:

```text
instance 1 gets no SVID: 'api-1' is not assigned to this node
```

**No second instance of a workload can obtain an SVID.** The container runs, its
network stands, its name resolves — only mTLS never comes about (ADR-0007). That
hits exactly the construction this system foresees for high availability:
`replicas="2"` is the warm standby from ADR-0010, and the lint from ADR-0009
recommends it for every single writer.

The same backward computation hits a second instance's sidecar a second time:
`delegation_of(attestation.workload())` looks for `api-proxy-1` (ADR-0036).

The finding is therefore **no edge case** but a gap at the identity boundary — and
it is silent.

## Decision Drivers

- **ADR-0006/0036:** the identity belongs to the **workload**, not to the instance.
  The path is `spiffe://<domain>/<role>/<name>` and carries no number; `may_talk`
  edges stand between workload names (ADR-0025). An instance with an identity of
  its own would be wrong even if it were minted.
- **Backwards is ambiguous.** From `tg-api-3` one cannot say whether instance 3 of
  `api` or instance 0 of a workload called `api-3` is meant — both yield the same
  identifier. ADR-0058 already decided the same question for the teardown:
  **compare forwards**, with the same function that assigned the identifier.
- **At the identity boundary ambiguity is a security question.** Whoever gives
  `tg-api-3` the identity `api`, although it could be instance 0 of `api-3`,
  confuses two workloads.
- **The identifier must not change.** A different separator (`tg-api.1`) would be
  unambiguous — and an agent would no longer find the running containers after the
  upgrade, would start second ones next to them, and both would write into the same
  volume (ADR-0027; the same reason for which instance 0 kept its name in phase
  10c).
- **Layers:** `tg-identity` does not depend on `tg-runtime` and must not.

## Options Considered

- **A — strip the number.** `from_cgroup` removes a numeric suffix. Cheap and
  **ambiguous**: `api-3` as a workload name would no longer be distinguishable from
  instance 3 of `api`.
- **B — make the identifier unambiguous.** A separator a name may not contain.
  Solves the problem at the root and **breaks running clusters**.
- **C — resolve forwards.** The node hands the mapping `container identifier →
  workload` to the issuing service; the attestation compares its identifier against
  that instead of computing a name.

## Decision

Chosen: **Option C**.

### 1. The mapping is handed over, not computed

`Minter` keeps a mapping `container identifier → workload` instead of a list of
names. Who forms it is the node: there name **and** instance are known, and there
lies `container_id` — the one function that assigns identifiers.

That is not a new construction but the one already present in the same type. For
the delegations from ADR-0036 `Minter` says it verbatim: *"The mapping is not
computed here but handed over."* The reason is the same — this crate knows neither
the dependency graph nor the instances.

### 2. `Attestation` names an identifier, not a name

From the cgroup one can read that a process runs in **a container of this
orchestrator**, and in **which**. Whom it belongs to is a question for the node's
inventory, not for the string.

`Attestation::workload()` therefore goes away outright. A field that is correct
only for instance 0 is a trap: it reads correctly and mostly is. Resolution happens
through `resolve(&assigned)`, and a refusal names the **identifier** — that really
exists, the guessed name does not.

### 3. The reconciler forms the mapping

`Report::own` carries it instead of a list of names. The reconciler knows the
assigned instances anyway (ADR-0040) and until now threw the number away — the same
place at which it once fell on the floor before.

The seeding at startup (ADR-0019: the socket comes up before the runtime search)
forms the same mapping from the **declared** `replicas`. It stays what it was:
broader than the truth, and the first pass narrows it.

## Consequences

**Positive**

- A warm standby gets its SVID — and **the same** identity as instance 0, as
  ADR-0036 prescribes. `may_talk` edges therefore bite for all instances.
- A second instance's sidecar finds its delegation.
- Nowhere is anything computed backwards any more — the same rule as with the
  teardown (ADR-0058), now at the identity boundary too.
- The refusal becomes more usable: it names a container an operator can find,
  instead of a name that does not exist.

**Negative / Costs**

- `Attestation::workload()` goes away — a change to a public surface. It is
  intended: the method was wrong at every call site except for instance 0.
- The issuing service keeps a mapping instead of a list. It is as large as the
  number of the node's containers.

**Risks & Open Points**

- **The seeding can be broader than the inventory.** It counts the declared
  `replicas`, not the assigned instances — on a node carrying only instance 1,
  instance 0 would stand in the mapping at startup too. That is the same deliberate
  breadth as before, and the first pass narrows it.
- **The identifier stays ambiguous**, it is merely no longer read backwards. Two
  workloads `api` (with instance 3) and `api-3` on the **same** node would yield
  the same container identifier — a collision that already today would mean two
  containers with the same name (`tg-agent::network` pins the case as a test).
  Preventing it is a question of its own.

## Related ADRs

- Depends on: ADR-0006 (identity at the cgroup), ADR-0034 (instances), ADR-0036
  (the path form without an instance)
- Follows: ADR-0058 (compare forwards, do not compute backwards)
- Affects: ADR-0010 (the warm standby gets an identity), ADR-0025 (the edges bite
  for all instances), ADR-0053 (untouched: the attestation still hangs on the
  handle)
