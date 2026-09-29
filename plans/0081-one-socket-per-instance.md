# ADR-0081: One socket per instance

- **Status:** accepted
- **Date:** 2026-09-04
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-identity::workload_api`, `tg-runtime::apply`,
  `tg-agent`, `tg-syscall::peer`, ADR-0006, ADR-0035, ADR-0053, ADR-0060,
  ADR-0065, ADR-0079

## Context and Problem Statement

ADR-0053 closed PID reuse: the attestation hangs on a **handle**
(`SO_PEERPIDFD`) instead of a remembered number, and the cgroup is read afresh on
every call. In the same breath that ADR names the better answer and says why it was
not possible at the time:

> The better answer would be a **socket per instance**, mounted into exactly its
> container: then the socket somebody reached does the attesting, and the question is
> moot — no PID, no `/proc`, no kernel floor. It has not become that here, because
> the **mount path does not yet exist**.

It has existed since **ADR-0079**: every workload container gets the socket mounted.
ADR-0079 therefore names the point itself as "become buildable and not built".

**What today's path costs is measured and stands in the operations manual:**

| | |
|---|---|
| Operational precondition | **kernel ≥ 6.5** for `SO_PEERPIDFD` |
| Below that | **no workload gets an SVID** |
| Affected | the identity path; the admin socket not (ADR-0044) |

The default kernels of widespread long-term distributions lie below that. That is no
theoretical restriction: it excludes environments in which REMIT/DORA-regulated
operation typically takes place.

On top comes the chain traversed for **every** SVID request today: `SO_PEERPIDFD` →
pidfd → `/proc/<pid>/cgroup` → a path segment with a `tg-` prefix → the mapping
container identifier → workload (ADR-0065). Four steps, three of them kernel
interfaces, and each has already yielded a finding: `SO_PEERCRED` was unsafe
(ADR-0053), the cgroup path was a foreign program's default (the finding in the
runtime path), and computing backwards from the identifier to the name was wrong
(ADR-0065).

## Decision

### Determination 1: One socket per instance, named after its container

`<data-dir>/sockets/<container-id>.sock`, and the name comes from the same function
that assigns the container identifier (`bundle::container_id`). No second namespace:
two derivations from the same pair of name and number would be two opportunities to
diverge (the same justification as with the name of the network namespace).

In the container it lies unchanged under `SOCKET_IN_CONTAINER` — the fixed path from
ADR-0059 stays, because client libraries expect it through `SPIFFE_ENDPOINT_SOCKET`
(ADR-0035).

### Determination 2: The socket **is** the attestation

Whoever reached it is in the container it was mounted into. The connection carries
the identifier as an extension — the same construction as `PeerCredentials`, only the
source is our listener instead of the kernel.

**That is measured and not assumed.** A socket in a `0700` directory, given into a
container by bind mount:

```text
through the mount, as nobody:  SVID
through the host path, as nobody:   Permission denied
```

Three properties carry that together:

1. **The directory** `<data-dir>/sockets/` belongs to `root` and is `0700`. An
   unprivileged process on the node reaches no socket.
2. **The bind mount** mounts the socket inode directly, so the host's directory
   permissions do not apply in the container — the workload reaches its own, and only
   its own.
3. **Another container** does not have the host path in its mount namespace. It
   cannot name a foreign workload's socket, let alone reach it.

The socket itself stays `0666`, for the reason from ADR-0060: the sidecar runs under
an id of its own, and a connection to a Unix socket requires write permission. What
changes is that the permissions are now **also no longer needed** in order to
separate — the mount does that.

### Determination 3: `SO_PEERPIDFD` and the cgroup read go away

Not kept as a second layer, and that is the decision that weighs most.

**For:** ADR-0053 says itself that it would thereby become "superfluous, not wrong".
The kernel floor falls, the four-stage chain becomes single-stage, and three kernel
interfaces leave the identity path — each of which has already yielded a finding.

**Against:** the security moves from a **kernel property** (a process's cgroup does
not lie) to a property of **our code** (the mount points at the right socket).
Whoever lays it wrongly gives one container the identity of another.

**Why that holds:** the mount and the container identifier arise at **one** place
from **one** derivation. A mismatch is not constructible without confusing the
identifier itself — and then the wrong container would already run under the wrong
name, with the wrong network and the wrong volume. The promise nevertheless gets a
witness of its own: the mount names the same container as the spec.

What **stays** is the credentials check as a statement about the *transport*: a
request without peer credentials did not come over a Unix socket, and then there is
no kernel vouching for the caller. The admin socket (ADR-0044) still authorizes by
**uid** and is unaffected by this decision.

### Determination 4: The socket arises before the container and dies with it

It is **mounted**, so it has to exist before `bundle::build` — the same order as the
network (ADR-0012: the spec carries the namespace path). The seam is therefore the
same form as `Wiring`: the runtime path demands a socket for an instance and gets a
path; who produces it is not visible from there.

**If it fails, the container does not start.** A workload without a way to its
identity starts as if nothing were wrong and stands out only at the first connection
(ADR-0007) — the same reason for which a failed network attachment prevents the start.

**It is reaped with the instance** (ADR-0058): the reconciler knows the desired
state, and a socket nobody withdraws is a way to an identity that no longer exists.
The directory is thereby bounded by the number of assigned instances and does not
grow without bound.

### Determination 5: One listener per instance, one service per listener

Every socket carries the same `SpiffeWorkloadAPI` service; what differs is only the
identifier on the connection. The minter stays **one** — it holds the CA, the signer
and the mapping "what may this node mint" (ADR-0019), and two would be two sources
for the same fact.

The cost: one task and one descriptor per instance instead of per node. At a node's
instance count that is defensible; the number of descriptors is visible anyway
(`tg_process_open_fds`).

### Determination 6: The previous socket goes away

No node-wide socket next to it. It would be exactly the path this decision closes:
reachable from every container, with the cgroup as the only separation.

## Consequences

**Positive:**

- **The kernel floor falls.** `SO_PEERPIDFD` (Linux 6.5) is no longer an operational
  precondition; the identity path runs on every kernel that can do cgroup v2 and Unix
  sockets.
- **The PID class disappears entirely** — there is no PID in the identity path any
  more, so also no window in which it could be reassigned. The PID-namespace caveat
  from ADR-0053 goes with it.
- **The chain becomes single-stage.** No pidfd, no `/proc`, no cgroup regex, no
  forward resolution over a handed-over mapping (ADR-0065).
- **The blast radius of an error shrinks.** A wrongly laid socket affects **one**
  container; a wrong cgroup derivation affected all.

**Negative / Costs:**

- **The security hangs on our mount**, no longer on the kernel. That is the price of
  determination 3, and it is evidenced with a witness rather than asserted.
- **N sockets, N tasks, N descriptors.** A node with forty instances holds forty
  listeners.
- **The socket has to be there before the container.** A failure at that costs the
  start — intended (determination 4), but it is a new way for a container not to come
  up.
- **An operational path disappears.** Whoever addressed the node-wide socket by hand
  until now no longer finds it. It was worthless for a process outside a container
  anyway — the attestation refused it.
- **`root` on the node can obtain an SVID** by dialling a socket directly. Before,
  the cgroup refused it; now only the `0700` directory separates, and that does not
  apply to `root`.

  **That is no loss, and the reason stands here rather than being left out:** `root`
  reads the agent intermediate from the disk (`<data-dir>/identity/`) and mints itself
  — the same argument with which ADR-0044 authorizes the admin socket by `uid`
  ("whoever reaches `0700` can halt the process and read the disk"). What changes is
  convenience, not the boundary.

  An **unprivileged** process by contrast reaches nothing — and that is the promise
  that counts and that has a witness.
- **ADR-0053 becomes superfluous**, and `tg_syscall::peer` loses its caller in the
  identity path. The module stays, because `SO_PEERCRED` is still needed for the
  admin socket's uid check.

## Risks & Open Points

- **The sidecar shares the namespace, not the rootfs** (ADR-0059). It is a container
  of its own with a mount of its own, so it gets its **own** socket — and over it its
  own SVID **and** the delegated one of its workload (ADR-0036). That is the same
  mapping as today, only anchored at the socket instead of at the cgroup.
- **A container that does not get its socket mounted** has no way to its identity.
  Today that would be a failure at start (determination 4); whether a running
  instance can lose its socket hangs on the reap path and is not specifically tested.
- **The lifecycle is level-driven, not event-driven.** A socket whose instance
  disappears is removed at the next pass — not at the same moment. In the gap it is a
  way to an identity the node may no longer mint; the minter refuses it
  (`set_assigned`).
- ~~**No witness across two containers** that cannot reach one another. The property
  follows from the mount namespace and is measured on a bind mount, not on two
  running containers.~~ **Built:** `tg-identity/tests/socket_isolation.rs`, two real
  containers with the real `tg-proxy`. Both access the **same path**
  (`SOCKET_IN_CONTAINER`) and get something different — that is the statement, and
  with one container it cannot be made.

  Two promises, and the second carries the first: each gets **its own** identity
  (same image, same program, same path — the only difference is the mount), and
  **neither** reaches the host directory in which both sockets lie. Without the second
  the first would prove only that the mount works, not that it **separates**.

  The second is **counter-checked**: point the same witness at a directory that does
  exist in the container and it turns red and names `reachable`.

  Both services thereby run with **the same key**; two CAs would make the witness
  green for the wrong reason.

## Related ADRs

- **ADR-0053** — it names this answer itself as the better one and says why it was not
  possible then; its kernel floor thereby goes away.
- **ADR-0079** — it brought the socket into every workload container.
- **ADR-0059** — the mount path.
- **ADR-0065** — the identifier is resolved forwards, not computed backwards.
- **ADR-0044** — the same argument for `root` on the node.
