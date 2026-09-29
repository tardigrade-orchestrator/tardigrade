# ADR-0053: Attestation at the handle — closing PID reuse

- **Status:** accepted
- **Date:** 2026-08-26
- **Deciders:** Core team
- **Technical context:** `tg-identity` (workload API, `attest`), `tg-syscall`,
  ADR-0006, ADR-0035, ADR-0002, invariant 2

## Context and Problem Statement

Phase 7c left as an open point:

> The attestation still reads `/proc/<pid>/cgroup` through the PID from
> `SO_PEERCRED`. […] the known PID-reuse gap stays what it was: between
> `SO_PEERCRED` and reading `/proc` the process may have died and the PID been
> reassigned. A `pidfd` would close that; that belongs decided, not built in
> passing.

The note reads like a race over microseconds. **Measured, it is none.**

## The finding: the window is the connection, not an instant

Three measurements, each reproducible on its own:

1. **The credentials arise at the `accept` and are held on the connection**
   (`incoming` in `workload_api::service`). `/proc/<pid>/cgroup`, by contrast, is
   read **per call**, in `Inner::attest`. Between the two lies the lifetime of the
   connection.
2. **The connection outlives the process that established it.** A connector that
   forks and dies leaves an open connection in its child's hands. Measured:
   `SO_PEERCRED` afterwards names a PID whose `/proc` entry no longer exists,
   while the socket is being served. The obvious mitigation — "if the workload
   dies, the connection dies" — **is false.**
3. **`SO_PEERPIDFD` sees `Pid: -1` on the same connection.** The kernel therefore
   knows what `SO_PEERCRED` cannot say.

The gap is therefore not a race but a **waiting time an attacker chooses
themselves**: connect, fork, let the connector die, wait until the kernel
reassigns the PID to a container process, then ask. The agent reads the cgroup of
a foreign, containerized process and mints an SVID on it — to a requester running
in no container.

That is this system's identity boundary (ADR-0006), and it hangs on a **number**
that can lose its meaning.

## Decision Drivers

- ADR-0006 binds the identity to the container, not to a caller.
- Invariant 2: `unsafe` only in `tg-syscall`.
- ADR-0019: a workload that is already running must be able to rotate its SVID —
  a tightening must not lock it out.
- ADR-0035: the surface is the standardized SPIFFE workload API; the attestation
  hangs on the connection, not on the protocol above it.

## Options Considered

- **A — `SO_PEERPIDFD`.** The kernel gives a **handle** instead of a number.
- **B — `pidfd_open(pid)` right after the `accept`.**
- **C — read `/proc` once at the `accept`** instead of per call.
- **D — one socket per workload instance**, mounted into its container.
- **E — nothing.**

### Why not B

It closes the long window and leaves a short one open — and the short one is
**not** beyond influence: how long a connection waits before being accepted is
determined by the queue length, and an attacker fills that. A defence whose
residual window the attacker can stretch is none.

More weighty still, B **looks like** A. A second, silently weaker path is the
kind of construction this project has already rejected elsewhere: "a port that
demands the credential admits no forgetting" (ADR-0043).

### Why not C

The same problem one level earlier, and it even makes the situation more
unpleasant: the attestation would then be fixed while the container may
meanwhile be a different one. ADR-0006 binds to the container and not to an
instant.

### Why not D (and why it would be the better answer)

**One socket per instance, mounted into exactly its container**, makes the
question moot: what is attested is **which socket** somebody reached, not who
they claim to be. No `/proc`, no PID, no race, no kernel requirement. It is at
the same time the ordinary delivery form of the SPIFFE workload API — the path
stands per container in `SPIFFE_ENDPOINT_SOCKET` anyway.

It is nevertheless not the choice here, and the reason is not taste: **the mount
path does not exist yet.** The agent today attaches its containers neither to the
network nor to mounts of their own (open from 9d, the runtime path does not run
in this environment). D would be a decision whose implementation hangs on another
open building site — and until then the gap would stay open.

**D stays the direction.** Once the mount path stands, it belongs in an ADR of
its own; A then becomes superfluous, not wrong.

## Decision

Chosen: **Option A.** What is attested is a **handle**, not a number.

### 1. `SO_PEERPIDFD` at the `accept`, and the PID comes from it

From here on the connection carries a `pidfd` instead of a PID. The number with
which `/proc` is read is **derived from the handle** (`Pid:` in
`/proc/self/fdinfo/<fd>`) and not remembered from `SO_PEERCRED`.

The difference is the whole decision: as long as the `pidfd` is open, **the
kernel cannot reassign that PID** — it holds a reference to the process entry. So
what is read is either the cgroup of the same process or none at all.

### 2. If the process is dead, there is no identity

If the handle reports `Pid: -1`, the requester has gone. Then the request is
**refused**, not fallen back onto a remembered number. Measured, that is exactly
the case from finding 2 — the connection lives, the connector does not.

That is the same direction as already in `incoming` today: "A connection whose
credentials cannot be read is **dropped** and not served without them."

### 3. The wrapper lives in `tg-syscall`

`rustix` does not know `SO_PEERPIDFD`, and a hand-written `getsockopt` is
`unsafe`. That is exactly what `tg-syscall` exists for (invariant 2, ADR-0002): a
thin, named wrapper with a written-down safety condition. The caller in
`tg-identity` stays safe.

It is the **third** `unsafe` block in the tree after `bpf(2)` and `unshare`, and
it is of the same kind: a kernel interface that does not exist in safe form.

### 4. Fail-closed, and therefore a kernel floor

`SO_PEERPIDFD` has existed since **Linux 6.5**. If it is missing, nobody gets an
SVID — there is no fallback to the old construction.

**The price stands here and is not left out:** kernels below 6.5 no longer carry
this orchestrator, and that includes the default kernels of widespread long-term
distributions. It is paid nonetheless, because the alternative would be a second
path that looks like the first and is not — and because an operator can read a
requirement in the manual but cannot read a silent weakness.

Whoever has to run on an older kernel needs **D**, not B. That is a new decision
and belongs in a new ADR (invariant 6).

**The floor applies to identity, not to the whole node.** The admin socket from
ADR-0044 authorizes by **uid** and does not need the PID; imposing the same
requirement on it would take away an operator's recovery path without making
anything safer. The handle is therefore *attempted* on every connection and
**required** only where an SVID hangs on it.

### 5. The seam for the tests stays where it is

`PeerLookup` stays: the lookup is still testable without starting a container.
What changes is the **origin of the number** that goes into it — and the new
refusal ("the handle names no living process") belongs tested just as much as the
normal case.

## Consequences

**Positive**
- The identity boundary no longer hangs on a number that can lose its meaning.
- The measured attack — connect, fork, die, wait — comes to nothing, and visibly
  rather than silently.
- No new crate: `rustix` and `tg-syscall` are in the tree.

**Negative / Costs**
- **Kernel ≥ 6.5** as an operational precondition.
- A third `unsafe` block, albeit in the place provided for it.
- A `pidfd` per open connection is one more file descriptor; at the number of
  workloads on a node that is inconsequential, but it is a resource that **has
  to** be released with the connection.

**Risks & Open Points**
- ~~**Namespaces:** `Pid:` in `fdinfo` applies in the reader's namespace, `NSpid:`
  in the process's. The agent reads in the host namespace, and there stands the
  value with which `/proc` is to be read — as long as the agent does not itself
  run in a PID namespace. That is the case today and belongs noted.~~ — **done:**
  moot since ADR-0081 — no `/proc` is read any more.
- ~~**Option D stays the better answer** and waits for the mount path from 9d.~~
  — **done:** ADR-0081 — one socket per instance.

## Related ADRs

- Depends on: ADR-0006 (binding to the container), ADR-0002 (`tg-syscall` as the
  only `unsafe` place), ADR-0035 (the surface stays the workload API)
- Does not replace but corrects the implementation of: ADR-0006 — from here on
  the attestation basis is a handle instead of a number
