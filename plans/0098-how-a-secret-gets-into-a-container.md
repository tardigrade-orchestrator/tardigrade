# ADR-0098: How a secret gets into a container

- **Status:** accepted
- **Date:** 2026-09-06
- **Deciders:** Core team

## Context and Problem Statement

ADR-0016 has been `accepted` since 2026-08-12 and explicitly leaves **one** point open:
*"fix the delivery mechanism (tmpfs vs. API) and rotation propagation."*

Measured, the path up to the node is built, and the last step is missing:

| What | State |
|---|---|
| The data key | ADR-0095 — one cluster-wide, delivered on the credential path |
| `PutSecret` / `AllowSecret` | built, sealed at the client |
| The slice carries `(workload, name, Sealed)` | built, filtered to its own |
| What a container sees of it | **nothing** — nobody opens the ciphertext |

Registry credentials are the one consumer that is **not** a container (ADR-0096: they
are used by the agent, and ADR-0016's question was thereby moot for them). What remains
is the case ADR-0016 was about first: a workload needs a DB password.

## Decision Drivers

- **Third-party images must know nothing** (ADR-0007). That is the reason the sidecar
  exists at all: *"transparent for third-party images."*
- **Never on the persistent disk, never in the environment** (ADR-0016).
- **Least privilege** (ADR-0025): a workload sees what it may read, and nothing else.
- **Rotation without a restart**, where it can be done — a restart is a human's action
  (ADR-0070, ADR-0071).
- **Level-triggered** (ADR-0010): no remembered state that can drift.

## Options Considered

**A — an API: the workload fetches its secret over mTLS.** That is the formulation in
ADR-0016 (*"workloads authenticate to the secrets service with their SVID over mTLS"*),
and it is **rejected**.

The reason is measured and structural: a workload that speaks mTLS needs a TLS library,
a client and a protocol. An unmodified image has none of that — and precisely for that
reason a sidecar stands between it and the network (ADR-0007). A secrets API inverts
that decision: it demands from the workload what ADR-0007 takes off its hands.

Giving the fetch to the **sidecar** does not solve it but moves it: it is optional
(`<mesh>`), secrets are not — and it would then have to put them down for the workload
as a file, i.e. over path B.

**B — a tmpfs, filled by the agent and mounted into the container.** Chosen.

**C — environment variables.** ADR-0016 excludes them explicitly, and the reason is
known: `/proc/<pid>/environ`, core dumps, process listings, and every child inherits
them.

## Decision

1. **The agent delivers, not a service.** For every instance with permitted secrets it
   creates a **tmpfs** under `<data-dir>/secrets/<container-id>`, decrypts the values
   with the data key (ADR-0095) and writes one file per secret. The mount goes into the
   spec as an ordinary bind mount, like the workload API socket (ADR-0081).

   **tmpfs explicitly**, not a directory in the data directory: the plaintext should lie
   nowhere at rest (ADR-0016) — not in the container and not on the node's disk. The
   mount carries a small size limit; a tmpfs without one can fill the node's memory.

2. **`/run/tardigrade/secrets/<name>` in the container**, a directory and not one mount
   per secret: adding a secret is then not a change to the spec and therefore not a
   restart. Read-only — what the container writes nobody reads, and the kernel enforces
   it instead of a check by us.

3. **The authorization is the mount.** A container gets exactly the secrets for which
   `AllowSecret` names **its** name. The way there is filtered twice and both times
   structurally: the slice carries only the secrets of this node's workloads (ADR-0095),
   and the agent mounts per container only its own.

   That is **stronger** than mTLS at a service, not weaker: there is no call anybody
   could forge and no credential anybody could borrow. What ADR-0016 means by
   "identity-bound" is here provided by the mount namespace.

4. **The sidecar gets none.** It enters its workload's namespace (ADR-0059), but its
   rootfs is its own — the mount applies to the workload container. Registry credentials
   are read by the agent (ADR-0096); no other need is known, and least privilege
   decides.

5. **Rotation without a restart.** The agent writes the files on **every** pass from the
   slice — level-triggered, like the edges and the egress permissions (ADR-0040). A
   `PutSecret` therefore reaches a running container in one round trip, and a
   `RevokeSecret` takes its file away.

   Whether a workload **uses** the new value is its own affair: whoever reads the file
   once at startup does not see the rotation. That is the answer to ADR-0016's "rotation
   propagation" — we deliver, and whoever wants to re-read can. A restart stays a
   human's action (ADR-0071).

6. **Writing is atomic and replacing.** A file arises through temp and `rename`; what the
   slice no longer names is removed. A half-written secret would be a password that is
   half right — and one left lying around would be one the cluster has revoked.

7. **An unreadable secret costs its container, not the node.** No data key, a ciphertext
   that cannot be opened, a tmpfs that cannot be created: the instance does not start,
   and the reason is named (`RuntimeError` class, ADR-0015). A workload that starts
   without its password looks as if it were running and stands out only at the first
   access — the same choice as with the socket (ADR-0081, determination 4).

   The pass does **not** end in doing so: the other workloads are still reconciled
   (ADR-0062).

8. **The files belong to the mapped range.** With a user namespace (ADR-0091), `uid 0`
   in the container is `base` on the node; a `chown` ensures the container can read.
   Without it they stay with `root`.

## Consequences

**Positive**

- An unmodified third-party image reads a file. No client, no library, no protocol.
- The authorization is structural and not a call somebody could forge.
- Rotation costs no restart.
- The plaintext lies in RAM and nowhere else.

**Negative / Costs**

- **The agent sees every plaintext.** It holds the data key anyway (ADR-0095) and is
  privileged (ADR-0017) — but it is a place through which all of a node's secrets pass.
  An API with end-to-end encryption to the workload would not have that, and it would
  have the price from option A.
- **One tmpfs per instance** with secrets costs a mount and some RAM.
- **Whoever reads the file once sees no rotation.** That cannot be solved from our side;
  a signal to the workload would be a protocol assumption about a third-party image.
- **`root` on the node reads everything.** That is unchanged — it also reads the data
  key.

## Risks & Open Points

- **The plaintext survives a container crash** until the next reaping: the tmpfs hangs on
  the instance, not on the process. The reaper (ADR-0058) takes it along; between the
  crash and the pass it lies there.
- **No audit per access.** ADR-0016 demands *"every access is auditable"*; what is
  audited here is the **delivery** (the log carries `AllowSecret`, and the agent reports
  what it mounts), not the reading of a file by the workload. A read audit would require
  a service, i.e. option A.
- **The size limit and the count** are starting values in the code; whether they need a
  setting is open.

## Related ADRs

- **Refines ADR-0016** on the point it left open (tmpfs instead of API), and names what
  falls away in doing so: the mTLS fetch at the secrets service. That ADR's other
  determinations stay — encrypted at rest (ADR-0095), the policy in consensus, never in
  the environment.
- **Applies:** ADR-0095 (the data key), ADR-0081 (the mount as a trust boundary),
  ADR-0040 (the slice), ADR-0010 (level-triggered), ADR-0091 (the mapped range),
  ADR-0062 (an error costs its workload).
- **Presupposes:** ADR-0017 (the agent is privileged), ADR-0007 (why third-party images
  need to know nothing).
- **Concerns:** ADR-0096 (registry credentials still go the other way — their consumer is
  the agent), ADR-0058 (the reaping takes the tmpfs along).
