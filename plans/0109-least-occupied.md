# ADR-0109: What "Least Occupied" Means with Several Resources

- **Status:** accepted
- **Date:** 2026-09-09
- **Concerns:** ADR-0011 (scheduler), ADR-0034 (resource map)

## Context and Problem Statement

ADR-0034 lays down the planner's selection rule verbatim:

> **The selection rule is written down, it is not a score:** among the nodes
> that satisfy all constraints, the **least occupied** one wins, and on a tie
> the alphabetically first name.

With **one** resource that is unambiguous. With a map it is no statement at all
— and `Resources` **is** a map (`BTreeMap<String, u64>`, ADR-0034 decision 2,
so that a `device` type per ADR-0028 fits without a rebuild).

Measured, the code fills the gap with a **derived `Ord`**:

```rust
candidates.sort_by(|left, right| {
    left_used.cmp(right_used).then_with(|| left.name.cmp(&right.name))
});
```

`Ord` on a `BTreeMap` compares the **sequence of pairs** lexicographically:
first the alphabetically first key, then its value, then the next. In practice
that means **one** resource decides — `cpu-millicores` comes before
`memory-bytes` — and memory is only considered when CPU is **exactly** equal.

**Measured against real `Resources`** (capacity 4000 mc / 16 GB):

| Case | lexicographic | "least occupied" |
|---|---|---|
| A `{cpu:100, mem:9 GB}` against B `{cpu:200}` | **A** (9 GB occupied) | B |
| A `{mem:5}` against B `{cpu:999 999}` | **B** (1 M millicores occupied) | A |

The second row is the finding in its sharpest form: a node with a **million
occupied millicores** counts as less occupied than one with **five bytes of
memory** — because it *carries* an alphabetically earlier resource, and the key
comparison comes before the value.

**The case is reachable**, not constructed: `schema/workload.xsd` gives `<cpu>`
and `<memory>` each `minOccurs="0"`, so a workload with only one of the two is
an ordinary declaration.

And the rule stands **nowhere**: neither at the type nor at the selection
function is there a word about the ordering. It follows from a derivation, not
from a decision — and `#[derive(Ord)]` is the kind of line nobody reads as a
selection rule.

## Decision Drivers

- ADR-0011 requires **deterministic** and **explainable in one sentence**, and
  excludes **scoring** ("no weighted point system whose parameters nobody can
  explain any more").
- ADR-0034 says "least **occupied**" — a statement about occupancy, and not
  about a resource name.
- The planner is a **pure function** and runs in the leader *and* in the test
  harness (phase 6); two leaders must arrive at the same result.

## Options Considered

**A — lexicographic (today's state).** Deterministic and explainable, but it
answers the wrong question: the decision is made by the alphabetically first
resource, not by occupancy. The price stands in the table above.

**B — an explicit priority ordering of the resources.** The same as A, only
named — and it requires a list someone must maintain (the fifth
hand-maintained list of this tree, and four of them are measured as a source of
error). A `device` from ADR-0028 would have to be added there, and whoever
forgets gets a selection that ignores that resource.

**C — the number of instances.** One sentence, deterministic, independent of
resource names. Rejected because it ignores the **sizes** entirely: a node with
one 32 GB workload would count as emptier than one with three small ones.

**D — the sum over all resources.** Rejected: adding millicores and bytes is
not a number, and a weighting would be exactly the scoring ADR-0011 excludes.

**E — the utilization of the scarcest resource.** Per resource
`occupied / capacity`, and the **maximum** of those applies. One sentence ("the
node whose scarcest resource is least utilized"), no parameters, independent of
names — and it answers the question ADR-0034 poses.

## Decision

**Option E.** The planner chooses the node with the lowest **pressure**, and
pressure is the highest relative utilization across the resources of its
capacity. On a tie the alphabetically first name still applies (ADR-0034
unchanged).

### Determination 1: Computation is in integers

`occupied * 1_000_000 / capacity` in `u128`, not in floating point. The planner
is the input of a log command (ADR-0011), and a rounding that differs between
two runs would be a determinism break of the same class against which
`tg-model` has its tripwire. `u128` excludes overflow: the measured upper bound
lies at `u64::MAX * 10^6`, and that fits.

### Determination 2: Only resources the node carries

The count is over the **capacity**, not over the occupancy: a resource with
capacity zero produces no pressure, and an occupied resource without capacity
is not reachable — `Resources::fits` does not admit a workload with a demand
there (measured: `fits(empty, empty)` is `false` for a demand). A node without
declared capacity thus has pressure zero and takes only workloads without a
resource demand.

### Determination 3: `Resources` loses its `Ord`

The derivation does not stay as a **second** answer to the same question.
`PartialOrd`/`Ord` on a resource map has no meaning anyone intended — and
whoever keeps it has yesterday's rule again at the next `sort`. Where an
ordering is needed (sorting the placements, ADR-0011: deterministic output), it
stands at the **place** that needs it.

## Consequences

**Positive**

- "Least occupied" means what it says. The two measured cases decide
  correctly.
- The rule has no parameters and no list — a `device` from ADR-0028 counts as
  soon as a node carries it as capacity, without anyone adding anything.
- The selection is independent of resource **names**. Whoever calls a resource
  `aaa-something` thereby moves nothing.

**Negative**

- **A behaviour change in placement.** A cluster that chooses nodes today
  chooses different ones after the rebuild. That is the purpose, and it is a
  difference an operator notices.
- **The resolution is finite.** At a capacity of 16 GB, differences below
  16 kB are not visible — measured, pressure calls an occupancy of 1 byte and
  one of 2 bytes **equal**, and then the name decides. The lexicographic
  ordering was finer there; but a planner that prefers a node because of one
  byte does nothing useful.
- **The pressure hangs on the declared capacity.** A node whose capacity an
  operator states too high looks emptier than it is — that applied before as
  well (`fits` checks against the same number), but it now also affects the
  **ordering**.

## Related ADRs

- **ADR-0011** (scheduler): the requirements "deterministic", "one sentence",
  "no scoring" come from there and are satisfied.
- **ADR-0034** (resource map): this ADR **refines** its selection rule; the
  map, the instances and the anti-affinity stay untouched.
- **ADR-0028** (CDI devices): the rule carries a `device` type without an
  addition — that was the reason for the map and remains so.
- **ADR-0047** (reserve): `schedulable_capacity()` is the input, so the
  pressure is computed against the **usable** capacity.
