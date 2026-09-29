# ADR-0060: The mesh redirect

- **Status:** accepted
- **Date:** 2026-08-27
- **Deciders:** Core team
- **Technical context:** `tg-net::rules`, `tg-proxy::sidecar`,
  `tg-runtime::apply`, ADR-0012, ADR-0025, ADR-0051, ADR-0059, ADR-0006

## Context and Problem Statement

Since phase 9b the rule set for an instance's namespace has lain there built and
checked at the kernel — and it is **not applied**. The reason stood most recently
in ADR-0059: the redirect sends outbound mesh traffic to **one** port, and which
peer was meant no longer stands there. The sidecar therefore listens to this day
on explicitly named ports (`--route peer=address`), i.e. on a list an operator
maintains.

Egress had the same gap, and ADR-0051 closed it with `SO_ORIGINAL_DST`. Here it is
still open, and with it the last piece of the data plane: as long as nobody
redirects, "there is no way past the sidecar" (`tg_model::mesh`) is an assertion.

## Two findings that carry the decision

### The expectation about the peer does not exist at all

`Route.peer` looks as if it fixed whose identity has to hold at the other end.
**Measured, it is used only for the SNI placeholder** — and even there with a
fallback. The verifier receives the **own** ID, the bundle and the policy; it knows
no expected counterpart.

So the outbound path already checks today: *whoever answers — is their identity in
the bundle, and does the edge exist?* That is exactly ADR-0025, and it means: a
redirect to a collecting port changes **nothing about authorization**. It merely
replaces "where the operator laid this route" with "where the container really
wanted to go" — and that is the more faithful statement.

### The exception in the rule set cannot work that way

`NetnsRules` exempts the sidecar from the redirect via `meta skuid`. But both
containers run under the same id — the OCI spec sets none, and the default is 0. An
exception on `skuid 0` therefore exempts **the workload too**, and the redirect
would have no effect.

Phase 9b proposed a way out: "`socket cgroupv2` would be the more apt expression —
it fits the binding ADR-0006 already uses". Since the runtime step that binding
really exists: every instance has its own cgroup under `/tardigrade/<container-id>`.

**Measured, this path is barred, and at a surprising place.** `nft` (v1.1.6)
**prints** the rule as JSON —

```json
{"match":{"op":"==","left":{"socket":{"key":"cgroupv2"}},"right":"tardigrade/tg-api-proxy"}}
```

— and **does not take the same line back**: `Error: Invalid socket key value`. Of
the socket keys the JSON parser knows only `transparent`, `wildcard` and `mark`;
`cgroupv2` exists only on the output side. With and without `level`, both checked.

That hits us because ADR-0038 fixed the path over `nft -j -f -` — and that is not
negotiable: the textual form would be a second interface to the same program, and
one assembled by hand.

Two further expressions were considered and rejected: `meta cgroup` is the **v1**
classid and requires a controller ADR-0003 does not run; `meta mark` would require
the sidecar to set `SO_MARK` — and that needs `CAP_NET_ADMIN` in the container,
which ADR-0017 precisely does not want.

## Decision Drivers

- **ADR-0025:** authorization is by **identity**, not by address.
- **ADR-0051:** the kernel answers "where did it want to go", not "where may it go".
- **ADR-0006:** an instance's identity hangs on its cgroup.
- **ADR-0012:** redirect in the netns, userspace, no eBPF.
- **ADR-0019:** nothing is stopped because something is unreachable.

## Options Considered

- **A — `SO_ORIGINAL_DST`, address and port**, the exception via the cgroup.
- **B — a collecting port plus a map address → workload** that the slice brings
  along.
- **C — stay with the old way:** one listening port per peer, maintained by the
  operator.

### Why not B

Because it would be a second source for a fact the kernel already has — and one
that goes stale: addresses are assigned node-locally (phase 9a), a map in the slice
would lag behind every re-placement. The peer is recognized by its **certificate**
anyway; a map in front of that would answer a question nobody asks.

### Why not C

Because a list an operator maintains is correct on the day it is created and not
afterwards — the same argument with which ADR-0041 rejected the DNS-fed firewall.
And because without a redirect every workload can **bypass** its sidecar by dialling
the address directly.

## Decision

Chosen: **Option A**, with four determinations.

### 1. The sidecar takes address **and** port from the kernel

`SO_ORIGINAL_DST` through the same safe `rustix` wrapper as in ADR-0051. No
answer, no connection — no fallback to a list.

**And here the address is used, unlike with egress.** That looks like a
contradiction to ADR-0051 and is none: there the address was an **authorization**
input, and it came from a resolution the container might have done itself. Here it
is a pure **routing statement** — authorization happens at the counterpart's
certificate (ADR-0025), and that holds regardless of which address led there.
Whoever dials a foreign address thereby reaches no service they would not be
allowed to reach anyway.

### 2. The exception stays with the user id — and the sidecar gets one of its own

`meta skuid` stays, because the better expression does not fit through the
interface (see the finding above). For it to **hold**, the sidecar container gets
an id of its own: the OCI spec sets `process.user.uid = 65532` for it, while the
workload runs as its image wants.

`65532` is the id widespread "distroless" base images carry as `nonroot` — a
sidecar image therefore usually brings it along already, and it lies within every
usual mapping of a user namespace.

**That costs an opening, and it stands here rather than being left out:** a
connection to a Unix socket requires write permission on it, and the agent creates
it as `root`. The workload API socket therefore gets `0666`.

That is defensible because the socket has **never** authorized through file
permissions: it attests every connection individually through its `pidfd` and the
cgroup behind it (ADR-0053), and that is exactly what this attestation was hardened
for. It is moreover the model of the SPIFFE specification that ADR-0035 followed —
the socket is reachable, the attestation is the gate. Handing it over to the
sidecar instead (`chown`) would be narrower and **wrong**: the workload API belongs
to every workload, not only to our sidecars.

**As long as no user namespace is involved**, `skuid` is the id in the container.
With one (ADR-0017) it would be the mapped one on the host side; that is not
configured today and belongs followed up on the day it is.

### 3. The rule set is laid when the sidecar starts, not on every pass

It is laid exactly when the sidecar is **created**. A pass that starts nothing
touches nothing; a restart brings the rules along.

The reason is not the id — that is stable — but the order: redirection may only
happen once somebody is there to listen. A redirect without a listener would take
every connection from the workload and would look like a network problem doing it;
that is the same consideration with which `with_egress` is an explicit setting.

**A side finding that came up while measuring the rejected path** and belongs
written down in case somebody takes it later: `nft` resolves a cgroup path at load
time and puts the **id** into the rule. A newly created cgroup — i.e. every restart
of the sidecar — gets a new id, and the old rule points into the void; `nft list`
then prints a bare number instead of a path.

### 4. No sidecar, no mesh — and that is the intended direction

If the redirect is in place and the sidecar is not running, the workload no longer
gets into the cluster. That is fail-closed and exactly what `tg_model::mesh` has
claimed since phase 8a ("there is no way past it"). It is at the same time a
**behavioural change** from today, where a mesh member without a sidecar cheerfully
talks directly.

ADR-0019 is untouched: the workload is not **stopped**, it is merely unreachable.
`mesh.rs` already names exactly that separation.

## Consequences

**Positive**

- The sidecar can no longer be bypassed; ADR-0007/0025 are for the first time
  really enforced instead of merely configurable.
- `--route` loses its purpose as an operational setting: where it goes is said by
  the container, and whether it may is said by the certificate.
- The exception holds at all — until now it would have exempted the workload too.

**Negative / Costs**

- **A mesh member without a running sidecar is cut off.** A behavioural change,
  see determination 4.
- The rules do not survive an `nft flush` from outside until the sidecar's next
  restart — the same as already holds for the node's rule set.
- **The workload API socket stands at `0666`.** The attestation carries that
  (ADR-0053), but it is an opening, and it belongs in the operations manual.
- **The sidecar runs as `65532`.** An image that cannot take that — e.g. because
  only `root` may read its files — does not start.

**Risks & Open Points**

- **The return path of the redirect is untested for the case that two instances of
  the same workload lie on one node.** Anti-affinity excludes that today
  (ADR-0011), but the assumption stands nowhere.
- **Whether `--route` should go away entirely** is not decided: it is today the
  only path for a setup without a redirect, and the tests from 8b use it.
- **`socket cgroupv2` remains the more apt expression** (9b), and the way there is
  a question for `libnftables-json`, not for us. If the parser ever accepts it, the
  change is one line — and then the side finding from determination 3 belongs
  heeded.
- ~~**UDP stays out.** What is redirected is TCP; a mesh member speaking UDP talks
  past it. That was already so in 9b and is not decided here.~~ — **done:**
  ADR-0074 (in the mesh), ADR-0092 and ADR-0094 (outbound).

## Related ADRs

- **Continues ADR-0051** and delimits itself from it: the same source, a different
  use (route instead of permission).
- **Redeems ADR-0012's redirect** and replaces its id exception with the cgroup
  binding from ADR-0006.
- **Builds on ADR-0059:** without a sidecar in its workload's namespace there would
  be nothing to redirect to.
