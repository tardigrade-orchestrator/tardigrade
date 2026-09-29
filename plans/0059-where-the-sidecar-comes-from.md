# ADR-0059: Where the sidecar comes from

- **Status:** accepted
- **Date:** 2026-08-27
- **Deciders:** Core team
- **Technical context:** `tg-model::mesh`, `tg-runtime::reconcile`, `tg-agent`,
  ADR-0007, ADR-0036, ADR-0011, ADR-0019, ADR-0057, ADR-0058

## Context and Problem Statement

`tg-proxy` is built, tested and a binary. The sidecar is derived
(`tg_model::mesh::expand`), gets an identity (ADR-0036) and a delegation. **It
just runs nowhere:** `expand` has exactly one caller in production code, and it
uses the result for the identity — not for starting a container.

What has to be decided is **where the derived unit arises**: in the cluster, i.e.
in the Raft log, or on the node. Three further questions hang on that — who fixes
the proxy image, how the sidecar gets to its workload, and what an auditor sees in
the log.

## The finding: the intent in the code does not hold

`mesh::build` fixes the cluster variant in two comments:

> "At the same time both statements land in the Raft log and therefore in the
> audit trail (ADR-0020)."
>
> "The placement is inherited: the sidecar has to be on the same node as its
> workload, otherwise it proxies over the network to a loopback port that does
> not exist there."

Both were measured, and neither holds:

1. **Nothing lands in the log.** The only caller is the agent's identity path. An
   `UpsertWorkload` for a sidecar exists nowhere.
2. **The inherited placement provides no co-location.** The scheduler works per
   **workload**: `occupied` and `taken` are keyed by workload name
   (`tg_model::placement`). `api` and `api-proxy` are two workloads and are placed
   **independently**. Inheriting the same constraints does not mean landing on the
   same node — with `spread="rack"` it in fact means fairly certainly the
   opposite, because both spread independently across the racks.

The second point is the decisive one: the cluster variant fails to deliver exactly
the one property for whose sake the sidecar exists.

## Decision Drivers

- **ADR-0007/0036:** the sidecar runs **next to** its workload and puts its
  delegated SVID on the wire.
- **ADR-0011:** the scheduler is declarative-explicit and works per workload; a
  co-location rule would be a new kind of constraint.
- **ADR-0057:** a policy may write **exactly** `UpsertNode` and
  `SetKeyGeneration`. `UpsertWorkload` is explicitly not on the list — "permitted
  here means decided".
- **ADR-0019:** the node is locally authoritative; a restart without a control
  plane has to yield the same thing.
- **ADR-0039:** what can be computed does not belong in the log.

## Options Considered

- **A — the node derives.** The agent expands its slice, as it already does for
  the identity.
- **B — the leader derives** and writes a second `UpsertWorkload`.
- **C — the client derives:** `tgctl cluster apply` sends both documents.
- **D — a co-location constraint** in the scheduler, plus B.

### Why not B

Two blocks, and each suffices alone. First co-location: it is missing, and
retrofitting it is option D. Second ADR-0057: a leader that computes a log command
from a state is a **policy**, and `UpsertWorkload` is not on its list. That list is
an exhaustive `match` and deliberately narrow; touching it is a conversation of
its own.

### Why not C

Because the derived unit would then depend on the version of the tool that
submitted it. Two operators with two `tgctl` versions would write different
sidecars into the same cluster, and the log would not say why.

### Why not D

A co-location constraint is a genuine extension of the placement model (ADR-0011):
"this instance must go where that one lies" binds two workloads together and has
repercussions for every displacement, every drain and every re-placement. That is a
lot of model for a property that is **free** on the node: there the question "which
instances do I have" is already answered.

## Decision

Chosen: **Option A**, with five determinations.

### 1. The sidecar arises on the node, from the slice

The reconciler expands the set the local desired state names, with **the same**
function the identity uses (`mesh::expand`). With that it cannot happen that the
agent gives a container an SVID derived for another one — it is one derivation,
not two.

**Computed, not stored.** The derived unit is formed anew on every pass and stored
nowhere. A cache entry would be a second place for the same fact, and it would
drift as soon as the proxy image changes (ADR-0039: what can be computed does not
belong in the log — the same applies here to the local cache).

### 2. Co-location is not a rule but a consequence

An instance's sidecar arises where the instance is, because the node forms it from
**its own** slice. There is no constraint a scheduler could violate, and no second
placement that could fail.

### 3. It shares its workload's network namespace

That is the determination from phase 9b, redeemed here: **one namespace per
workload instance, and the sidecar moves in with it.** It therefore also gets **no
address of its own** — one instance, one address, two processes. Only that way is
the upstream reachable over loopback, and only that way does the exception in the
rule set (ADR-0012), which hangs on the sidecar's user id, hold.

**Who belongs to whom is said by the desired state, not by the name.**
`mesh::delegations` is used — the same check ADR-0036 fixed for the identity: mesh
member, derived name, proxy image **and** both edges. A workload that merely
happens to be called `api-proxy` therefore gets neither a foreign SVID nor a
foreign namespace. Taking the name alone would here be a **trust boundary**, not a
convenience.

### 4. The proxy image stays an operator setting per node

`--proxy-image`, as today. No command, no log entry.

The price stands here rather than being left out: two nodes with different
settings run different sidecar versions. That reads in both directions — it makes
a rolling sidecar update an action per node, and it makes an accidental divergence
invisible. Decided in favour of the simpler version, because the setting exists
anyway and the identity already uses it: a second source next to it would be the
opportunity for divergence that does not exist today.

### 5. The paths in the container are fixed, those on the node come from the agent

The derived unit carries its command line in full — with **container-side** paths:

| In the container | What |
|---|---|
| `/usr/local/bin/tg-proxy` | the program itself |
| `/run/tardigrade/workload-api.sock` | the workload API (ADR-0035) |
| `/etc/tardigrade/may-talk` | the edges (ADR-0025/0040) |
| `/etc/tardigrade/egress` | the egress permissions (ADR-0041) |

The **program path** stands in this list because it belongs there and not because
it would be convenient: `<command>` **overrides the image's entrypoint and cmd** —
so says the schema and ADR-0003. A command line carrying only arguments therefore
yields an `execvp` on `--workload`. That came to light while building this ADR, and
at the runtime: since phase 8a the derived unit carried only arguments and
**could never have started**. Nobody saw it, because nobody started it.

The alternative would have been to give `<command>` OCI semantics (cmd appended to
the entrypoint). That is a **schema change** with a process of its own
(`schema/README.md`) and would affect every written definition; taking it along
here in passing would be exactly the silent drift invariant 6 forbids.

They are constants because they lie **in** the filesystem we build — and therefore
the command line may stand in the document that is the same on every node. Where
they lie on the node only the agent knows; it mounts them.

The socket is mounted **writable**: using it means writing into it. The two files
are mounted **read-only** — a sidecar that could change its own permission list
would be no enforcement.

## Consequences

**Positive**

- Co-location is structural, not hoped for.
- The scheduler stays as it is (ADR-0011), and ADR-0057's list stays closed.
- Identity and runtime see **the same** sidecars, because it is one derivation.
- A node without a control plane starts the same sidecars after a restart as
  before (ADR-0019): the derivation needs only the local cache.

**Negative / Costs**

- **The sidecar does not appear in the log.** An auditor sees `<mesh port="…"/>`
  in the definition and the operator's setting, not the generated document. It is
  fully reconstructible from that — but it is a computation, not an entry. The two
  comments in `mesh::build` that claim otherwise are retracted.
- **It consumes capacity nobody booked.** The scheduler computes with the
  workload's resource map (ADR-0034); the sidecar runs alongside. For the reserve
  from ADR-0047 that means: it is too optimistic by the sidecars' share. A
  surcharge per mesh member would be the answer and is **not** decided here.
- **Two nodes can run different sidecar versions** (determination 4).

**Risks & Open Points**

- ~~**The mesh redirect stays absent.** `NetnsRules` redirects outbound mesh
  traffic to **one** port (`15001`); which peer was meant no longer stands there —
  the same gap ADR-0051 closed for egress with `SO_ORIGINAL_DST`. Until that is
  decided the sidecar listens on explicitly named ports, and the inbound path
  (`15006`) is the one that works without redirection.~~ — **done:** ADR-0060.
- **The sidecar image has to bring the four paths** — the program at
  `/usr/local/bin/tg-proxy` and the three mount points (or the runtime creates the
  latter; it does, but that is not a promise of the specification). That is a
  requirement on an operational artefact and belongs in the operations manual.
- **Whether `<command>` should get OCI semantics** (cmd appended to the
  entrypoint, instead of replacing both) is an open question about the schema. It
  is deliberately not answered here.
- **`tgctl apply`** (the node-local path from phase 2) does not derive: there an
  operator writes the cache themselves, and what they do not write does not exist.

## Related ADRs

- **Redeems ADR-0007** (the sidecar runs) and **ADR-0036** (it gets its delegated
  SVID over the socket it now sees).
- **Corrects the intent in `mesh::build`**, not ADR-0036 itself — nothing is said
  there about the place of derivation.
- **Does not touch ADR-0011** and **does not open ADR-0057's list**; both are the
  reason for the choice.
- **Presupposes ADR-0058:** a sidecar whose workload disappears disappears with it
  — it then no longer stands in the derived desired state.
