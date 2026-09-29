# ADR-0143: The Path of a Device Into the Container

- **Status:** accepted
- **Date:** 2026-09-15
- **Decider:** Dana Schlifka
- **Technical context:** `tg-runtime` (new: `cdi`, plus `bundle`), `tg-agent`
  (`capacity`, new: the assignment), `tg-model` (`placement`), `tg-defs`
  (schema)

## Context and Problem Statement

On 2026-08-19 ADR-0028 laid down the **way** for accelerators — CDI as the
seam, the agent injects into the `config.json`, the scheduler gets a generic
`device` resource type — and expressly did not build it: *"This capability is
**deferred**: the seam is defined, but not implemented in the early build
phases."*

It is thereby the last ADR of this tree with a deferred implementation. And it
is not a build instruction: it names two open points itself ("how nodes announce
devices", "finally verify youki's CDI handling"), and on measuring, four more
came out that a build must answer before the first line arises.

## The measured state

**Five measurements, and two of them change the task.**

| Question | Measured |
|---|---|
| Does youki support CDI itself? | **No.** youki 0.7.0 knows no `cdi` in `--help` |
| Is there a real spec here? | `/etc/cdi` and `/var/run/cdi` do not exist |
| Is there a YAML parser in the tree? | **None** |
| Does a container have `CAP_MKNOD`? | **No** — three capabilities, the OCI default |
| What does spec generation do with cgroup device rules? | It **aborts** (`reject_unenforceable`) |

The first row decides ADR-0028's first open point: agent injection is not the
better choice compared with youki's CDI support but the **only** one. The ADR
decided rightly as a precaution.

The last two belong together and are the actual finding. CDI describes per
device node a field `permissions`, and the specification says verbatim what it
is: *"Cgroup permissions (r/w/m); defaults to `rwm`"*. A spec-conformant CDI
injection produces `linux.resources.devices` from it — and exactly that this
tree has rejected since ADR-0090, because the cgroup v2 device controller is
eBPF and excluded per invariant 1. `bundle.rs` has predicted it ever since:

> Device isolation must instead rest on the presence of the device nodes and on
> user namespaces; the cgroup controller would only have been defence in depth.
> Relevant for ADR-0017 and the CDI seam from ADR-0028.

With that the question is not *whether* one injects CDI, but **what of a CDI
spec can take effect in this tree at all** — and what an operator learns when a
part does not.

## Decision Drivers

- **Nothing may be silently without effect.** A spec that describes isolation we
  do not enforce is more dangerous than no spec at all — the finding from
  ADR-0124 (a star that permits nothing) and ADR-0090 in one.
- **Invariants 1 and 3** — no eBPF, no Go in the codebase.
- **Crate poverty.** ADR-0134/0139 have just brought the shipping closure to
  359; a parser for a foreign file type at a trust boundary is the most
  expensive sort of dependency.
- **The division of labour from ADR-0028** — CDI exposes (node), the scheduler
  manages (cluster) — should get by without a rebuild of the planner
  (ADR-0034/0109 made it generic for that).
- **No time slicing** (ADR-0028): at any point in time a device belongs to
  exactly one instance.

## Options Considered

- **Option A — implement the full CDI spec, silently omit cgroup rules.** Cheap,
  and exactly the silent false assumption that `reject_unenforceable` prevents.
- **Option B — reject every spec that sets `permissions` narrower than `rwm`.**
  Honest, but unusable: `rwm` is the *default*, so one would reject the narrower
  ones and let the widest through — the rule would stand on its head.
- **Option C — implement the subset that takes effect here, and report every
  setting that does not take effect when reading the spec.** This tree's way
  since ADR-0058.

Chosen: **option C**.

## Decision

### Determination 1 — what of a CDI spec takes effect, and what is reported

Implemented are `deviceNodes`, `mounts` and `env` — the three parts that map to
OCI fields this tree enforces.

| CDI field | Here |
|---|---|
| `deviceNodes[].path`, `type`, `major`, `minor` | → `linux.devices` |
| `deviceNodes[].fileMode`, `uid`, `gid` | → `linux.devices`, **enforced** |
| `deviceNodes[].permissions` | **no cgroup rule** — see determination 2 |
| `deviceNodes[].hostPath` | read and **checked** to exist |
| `mounts` | → `mounts`, always with `bind` |
| `env` | → `process.env` |
| `hooks` | **spec is rejected** — determination 3 |
| `netDevices`, `intelRdt`, `additionalGids` | **spec is rejected** |
| `annotations` | accepted and **not** read — see below |

The penultimate row is not convenience. `intelRdt` is resctrl, hence isolation;
`additionalGids` changes the process's identity; `netDevices` moves an interface
into the namespace and would thereby reach into ADR-0012 and ADR-0093. Passing
over all three silently would mean accepting a spec and building something other
than what it says.

`annotations` is the one case that lies differently, and the boundary is sharp:
in CDI they take **no effect on the container at all** — they are metadata for
the consumer. Passing over them does not make what runs unlike the spec, so
ADR-0124's argument does not apply here. Rejecting a setting that *can* effect
nothing would be strictness without a statement.

Unknown fields, by contrast, are rejected: **a spec with a field we do not know
does not get through** — the same strictness as ADR-0072 and ADR-0083, and for
the same reason. Whoever half-understands a decree carries it half out. It is at
the same time the version check here: a CDI that adds a field aborts instead of
concealing it.

### Determination 2 — `permissions` becomes `fileMode`, not a cgroup rule

A device is accessible here when its node **exists** in the container, and
otherwise not. That is a real barrier — `CAP_MKNOD` is measured not to be in the
capability set, a container cannot build itself a node — and it is the only one
that remains without eBPF.

What `permissions` says is therefore mapped onto the **file mode** if the spec
names none: `r` → `0444`, `rw` → `0666`, `w` → `0222`. The `m` (mknod) falls
away without consequence, because the capability is missing.

If the spec names **both** and they contradict each other — `permissions: "r"`
with `fileMode: 0666` — the spec is **rejected**. Silently taking the narrower
value would be an isolation the operator did not write down; silently taking the
wider one would be one they did write down and do not get. Both are worse than
an abort with both numbers in the message.

**The loss is named and not played down:** a device whose node a container has
is accessible to it by file mode and owner — not more finely. Whoever needs a
sharper separation needs hardware partitioning, and that is exactly what
ADR-0028 demands anyway (SR-IOV, MIG, passthrough).

### Determination 3 — hooks are rejected, loudly

A CDI hook is a **program with arguments from a file** that the runtime executes
as root — `createRuntime` and `createContainer` run before the start command, in
the container's namespace. The spec file describes devices; that it at the same
time determines which program root executes is a trust boundary this tree draws
nowhere else so widely.

What is rejected is the **whole spec**, not the hook in it. A filtered hook is
the case from ADR-0090: the spec then describes something other than what runs.

**The price is concrete and belongs in the manual:** the spec produced by
`nvidia-ctk cdi generate` carries hooks (`update-ldcache`) and **does not run
here unchanged**. An operator must trim the hooks from it and ensure that the
mounted libraries are found — via `LD_LIBRARY_PATH` in `env`, which CDI itself
offers. That is work at provisioning time, that is, where ADR-0028 locates the
spec generation anyway.

### Determination 4 — JSON, not YAML

What is read is **JSON**. A YAML parser is not in the tree, and none of the
available ones is a dependency one takes on at this place: the file describes
which device nodes a container gets, and it is read as root. `serde_json` has
been in the tree since phase 1.

The vendor tools write YAML by default and JSON on request
(`nvidia-ctk cdi generate --format=json`). That is a switch, not a rebuild.

**A file we cannot read is a report and not a passing-over.** Whoever puts a
`.yaml` into the directory gets a line with the path and the reason — otherwise
it would look as if the device did not exist, and troubleshooting would start at
the driver.

### Determination 5 — the inventory travels like any other capacity

The node reads the specs of its CDI directories and counts per `kind` how many
devices stand in them. That goes as an **entirely ordinary resource** into the
report from ADR-0049:

```
device:nvidia.com/gpu = 2
```

The prefix `device:` separates it from `cpu-millicores` and `memory-bytes`; the
rest is the CDI `kind`, unchanged.

With that ADR-0028's second open point is answered, **without a line in the
planner**: ADR-0034 made capacity a generic map `name → amount`, ADR-0109 made
the comparison the pressure over the scarcest resource. A node without a device
does not name the key, and a workload that demands it is not placed there — that
is already the behaviour today, only nobody had ever written anything into it.

The report is **observed state** and never reaches the planner directly
(ADR-0049): a policy turns it into the usable capacity, the leader writes it. A
device that disappears from the inventory is thereby a reduced capacity and
needs no health report of its own — ADR-0028 names "device health reporting" as
an open point, and the honest answer is that an accelerator health check is a
vendor tool and lies below the CDI line.

### Determination 6 — the demand stands in the declaration, the assignment at the node

**One** element is added to the schema:

```xml
<devices>
  <device kind="nvidia.com/gpu" count="1"/>
</devices>
```

`kind` is the CDI `kind`, `count` the number. **No** concrete device name: which
of the two GPUs an instance gets is a node detail, and ADR-0028 says expressly
that the partitioning stays below the CDI line.

From that follows the division of labour, and it has a model in this tree:

- **Cluster-wide** it is a number — `device:nvidia.com/gpu = 1` in the demand,
  against the same resource in the capacity. The planner sees nothing new.
- **Node-local** it is an assignment: which concrete CDI device name goes to
  which instance. It is **persisted and checked on re-reading** — the same
  construction as the address assignment from phase 9a, and for the same reason.
  A derivation from the position in a list would be the finding from 9a: a
  device that fails would shift the mapping of all the following instances, and
  each would get a different one after a restart.

**The same device twice is a finding, not a state** — two instances that hold
the same device name abort the re-reading, like a doubly assigned address in 9a.
That is the enforcement of ADR-0028's prohibition of time slicing, and it lies
with the node, because the device lies there.

### Determination 7 — the directories are a setting, their absence is normal

`--cdi-dir` is repeatable, the default being the two directories of the
specification (`/etc/cdi`, `/var/run/cdi`). If none exists, that is **not an
error**: a node without accelerators is this cluster's normal case, and a
failure there would turn a missing GPU into a broken node (ADR-0019).

An **unreadable or rejected** spec is by contrast a report, and the devices in it
are missing from the inventory. The difference is the one between "there is
nothing here" and "something stands here that I do not carry out".

### Determination 8 — one cut, and the order

As ADR-0092 and ADR-0142: first the **reading and the mapping** with witnesses
against real spec files and a real `config.json`, then the wiring (inventory
into the report, assignment, schema). A parser without a caller would be the
error from ADR-0044; a caller without a checked parser would be worse, because
it sits at a trust boundary.

A **fuzz run** belongs to it (rule from `ai_rules_unittests.md`: mandatory at a
trust boundary that parses untrusted input) — with the invariants that count
here: no crash, no spec that belongs rejected being accepted, and no device node
outside `/dev`.

## Consequences

**Positive**

- **The last deferred ADR is built**, and ADR-0028's promise is redeemed: the
  planner gets **no** new line, because ADR-0034 and ADR-0109 made it generic.
- **Zero new crates.** `serde_json` and `oci-spec` are in the tree.
- The seam is not GPU-specific (ADR-0028): FPGAs, SmartNICs and an HSM for
  ADR-0014 go the same way.
- What does not take effect **is said**. A spec with hooks or with `intelRdt`
  aborts instead of fulfilling three quarters of its statement.

**Negative / costs**

- **The stock spec from `nvidia-ctk` does not run here.** It carries hooks; an
  operator trims it and sets `LD_LIBRARY_PATH` themselves. That is this ADR's
  most visible cost item.
- **YAML must be converted** — a switch on the vendor tool.
- **Device isolation ends at the file mode.** Without a cgroup controller there
  is no finer barrier; the answer is hardware partitioning, which ADR-0028
  demands anyway.
- **A new schema element** is a schema change with the process from
  `schema/README.md`.

**Risks & open points**

- **None of this is measured against real hardware.** On this machine there is
  no device and no vendor spec; the witnesses run against **invented but real**
  specs and real device nodes of the system. The first run on a GPU is an open
  check, and it belongs in the manual before anyone needs it.
- **The assignment outlives the node, not the cluster.** If a node with an
  occupied GPU fails, the planner places the instance elsewhere — a stateless
  inference workload tolerates that (ADR-0028), another does not. Whoever has a
  device and a writable volume at once is node-pinned anyway (ADR-0027).
- **`hostPath` is checked but not monitored.** If the node disappears on the host
  while a container runs, only the container notices.
- **The `kind` is a string from a file** and becomes the resource name in the
  log. It is checked against the specification's form before it goes there —
  otherwise a file on one node would determine what a key in consensus is
  called.

## Related ADRs

- **Builds ADR-0028** and answers both of its open points (youki's CDI handling:
  measured, there is none; inventory report: determination 5).
- **ADR-0049** — the path of the capacity report, used unchanged.
- **ADR-0034/0109** — the generic resource map and the pressure, which leave the
  planner untouched.
- **ADR-0090** — the cgroup v2 device controller is eBPF; determination 2 is the
  consequence.
- **ADR-0017** — `CAP_MKNOD` is missing, on which the barrier from determination
  2 rests.
- **ADR-0003** — the `config.json` and the runtime into which injection happens.
- **ADR-0027** — models as RO data; the reason why inference is stateless.
- **ADR-0014** — an HSM over the same seam, as an alternative to PKCS#11.
