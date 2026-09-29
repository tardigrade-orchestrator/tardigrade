# ADR-0086: What the sidecar may consume

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-model::mesh`, `tg-runtime::bundle`, ADR-0022,
  ADR-0034, ADR-0059, ADR-0067, ADR-0072

## Context and Problem Statement

**ADR-0067** gave the sidecar a place in the capacity calculation: a cluster-wide
surcharge per mesh instance that the scheduler adds to the demand. With that it is
**booked**.

Measured, it is **not enforced**. `mesh::build` produces no `<resources>` element, so
the sidecar's `config.json` carries no `linux.resources` — while
`bundle::linux_resources` does set a CFS quota and a memory limit for a declared
workload (measured against `LinuxCpuBuilder`/`LinuxMemoryBuilder`).

The situation is therefore asymmetric: **the workload is bounded, its sidecar is
not.** A sidecar consuming more than the surcharge takes it from its neighbours — and
the scheduler's calculation was chosen conservative for exactly that reason.

ADR-0067 says **nothing** about enforcement; the plan does not either. It is not a
decision but an omission.

## Decision Drivers

- **ADR-0022 sets a tail target for the data plane.** A CFS quota produces throttling
  pauses, and that is exactly the kind of standstill thread-per-core is built against.
- **ADR-0022's benchmark is missing to this day.** Without it every number for the
  data plane is a conjecture — the same situation from which pinning stayed unbuilt.
- **ADR-0019 is the keystone.** A sidecar that uses up a node's memory takes **all**
  workloads of that node with it; that is a total failure from a partial one.
- **The surcharge stands in consensus** (`ClusterState::sidecar_overhead`) and **not
  in the slice** (measured). The node does not know it.
- **Every extension of the slice is a format break** (ADR-0072, determination 3) and
  belongs in the bundled window.

## Options Considered

- **Option A — everything stays.** Booked, not enforced, and nobody has written it
  down.
- **Option B — the sidecar gets the surcharge's limits**, CPU and memory. The slice
  has to carry it for that.
- **Option C — memory yes, CPU no.** The limit whose breach costs a node is set; the
  one whose observance costs the tail target is not.
- **Option D — a setting per node** (`--proxy-resources`), like `--proxy-image`.

## Decision

Chosen: **Option C**, with the source from option B — and the build of the memory
limit waits for the window from ADR-0072.

### Determination 1 — no CFS quota for the sidecar

Not now and not until ADR-0022's benchmark exists. A quota on a proxy is a setting
whose price is exactly the figure this system promised for the data plane and never
measured. Setting it because it looks symmetric would be the kind of decision this
project already rejected with pinning.

The price stands with it: a sidecar can consume more CPU than booked. What bounds it
is not the kernel but the work — it does only what its workload's traffic demands.

### Determination 2 — a memory limit is wanted

Because its absence hits the keystone: a sidecar without a memory limit can bring the
node under the OOM killer, and then **all** workloads of that node go with it
(ADR-0019). Unlike with the CPU the damage is not slowness but loss.

### Determination 3 — the source is the surcharge, not a second setting

The limit is the number the scheduler books (ADR-0067). Two sources for the same fact
would be two opportunities to choose them differently — and then the cluster books a
number the kernel does not enforce, i.e. exactly the state this ADR abolishes.

Option D is thereby rejected: a setting per node would be the second source, and
ADR-0059 already paid the same price once for `--proxy-image` ("an accidental
divergence is invisible").

### Determination 4 — it gets built with the format window

The node does not know the surcharge: it stands in consensus and not in the slice
(measured). Carrying it there is a format break, and ADR-0072 decided that those go
bundled. **Until then the sidecar is unbounded, and that stands in the manual** — not
as a note in an ADR but where an operator reads it.

That is not a deferral out of convenience: the individual break would cost a
maintenance window for a limit an operator can today also roughly achieve through the
per-node reserve (ADR-0047).

## Consequences

**Positive**

- The omission is a decision, and both directions are justified.
- The memory limit has a **source** instead of a number once it is built — booking and
  enforcement are then the same thing.
- An operator learns today that the sidecar runs unbounded, instead of learning it
  from an incident.

**Negative / Costs**

- **Until the format window it stays as it is.** A runaway sidecar can hit a node; the
  mitigation is the reserve from ADR-0047, and that is coarse.
- A sidecar may permanently consume more CPU than booked (determination 1).

**Risks & Open Points**

- ~~**The benchmark from ADR-0022 stays the pivot** — for pinning, for the overflow
  check (ADR-0082) and now for the CFS quota. Three decisions wait for one
  measurement.~~ — **all three measured**: pinning in ADR-0114, the overflow check
  noted there, and the quota here.

  Measured with the benchmark in a cgroup with `cpu.max`, `thread-per-core`, in µs:

  | Quota | throttled | p50 | p99 | p99.9 |
  |---|---|---|---|---|
  | none | 0 | 125–141 | 316–418 | 750–838 |
  | 400 % | 0 | 130 | 476 | 736 |
  | 200 % | 0 | 133 | 421 | 670 |
  | 150 % | 0 | 115 | 391 | 684 |
  | 100 % | 0 | 111 | 307 | 661 |
  | **50 %** | **62** | 111 | 349 | **47,121** |
  | **30 %** | **119** | 116 | 465 | **68,672** |
  | **20 %** | **188** | 117 | 469 | **80,941** |

  **It is a cliff, not a slope.** As long as the quota does not bite, it costs
  **nothing** — up to 100 % nothing is distinguishable from the unthrottled
  measurement. Once it bites, p99.9 jumps by a **factor of 70 to 120** (0.66 ms to
  47–81 ms), while p50 and p99 stay almost untouched. The height is the CFS period:
  whoever is throttled waits for the next one.

  **With that determination 1 stands, and with a sharper reason.** It read "not until
  ADR-0022's benchmark exists" — it exists, and the measurement says: still not. Not
  because a quota would be expensive but because it is **free until it is not**, and
  then costs a hundredfold. A setting of that shape is not set on an estimate.

  **The new condition is therefore the second line below it**: a quota becomes
  conceivable only once a sidecar's consumption is **measured and reported** — then
  headroom above it could be chosen instead of guessed. Before that the order is the
  wrong way round.

  What the measurement does **not** say: at which booking the cliff begins. In the
  harness the **whole** process lay in the cgroup, so load and echo service too; the
  percentages are therefore no statement about the surcharge from ADR-0067 but about
  the shape of the price.
- ~~**What a sidecar really consumes nobody reports.** A metric for it would have to
  read the cgroup; whether the agent should do that is not decided.~~ — **decided:
  ADR-0118.** It should: a metric per container (`tg_container_memory_bytes`,
  `tg_container_cpu_seconds_total`), read from `/tardigrade/<container-id>` — the path
  **we** supply (ADR-0006), not the runtime. No field in the report: it has been an
  expensive place since ADR-0072, and the scheduler must never see the number anyway
  (ADR-0049).

  With that the condition under which determination 1 would be posed anew is met: from
  here on the surcharge can be **chosen** instead of guessed, and a quota would for the
  first time be settable with known headroom.

## Related ADRs

- Depends on: ADR-0067 (the booking), ADR-0034 (the resource map), ADR-0022 (the tail
  target), ADR-0072 (the format window)
- Redeems: the omission in ADR-0067 (not a word about enforcement)
- Supplemented by: **ADR-0118** (the consumption nobody reported)
