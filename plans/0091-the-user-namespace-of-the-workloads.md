# ADR-0091: The user namespace of the workloads

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture
- **Technical context:** `tg-runtime`, `tg-agent`, ADR-0017, ADR-0003, ADR-0012,
  ADR-0027, ADR-0090

## Context and Problem Statement

ADR-0017 names three defaults as **on by default**: `noNewPrivileges`, seccomp and the
**user namespace**. ADR-0090 built the second; the third is missing, and it is the
most consequential: **uid 0 in the container is today uid 0 on the node.** Whoever
escapes a container — through a kernel bug, a forgotten mount, a setuid binary —
stands as `root` on a machine carrying foreign workloads (ADR-0019).

The plan has carried the point since the seccomp step with a justification of why it
does not go in passing: it *"shifts the ownership of every volume, of the mounted
socket (ADR-0081), of the `.owner` marker and of the layer store"*. That is the
question decided here — and it was **measured** beforehand, on real containers with
both runtimes from ADR-0003.

### Measurement 1 — what a user namespace costs first

Mapping `0 → 100000` (65536), nothing else changed:

```text
uid=0 gid=0                       in the container
65534 65534  /                    the rootfs belongs to `nobody`
65534 65534  /vol /vol/file       the volume too
TMP-OK                            (only because /tmp carries 1777)
ROOT-DENIED                       no writing into its own rootfs
VOL-DENIED                        no writing into its own volume
```

Everything the agent created as `root` is foreign to the container. The rootfs `upper`
**is** the ephemeral volume from phase 2 — a container that cannot write into `/` is
unusable for most images.

### Measurement 2 — idmapped mounts solve it for volumes, without touching the disk

The same setup, the volume as a bind with `mounts[].uidMappings`:

```text
0 0 /vol   0 0 /vol/file          in the container: root
VOL-OK
on the host afterwards: 0 0 /tmp/uns2/vol   ← unchanged
```

### Measurement 3 — an overlayfs **cannot** be idmapped

```text
mount_setattr `/vol`: Invalid argument
```

The rootfs mount is an overlayfs, and that is not idmappable. What does work are
**idmapped lower layers** (measured separately: the store stays `0:0` on the disk, in
the overlay it appears as `100000`) — that would need one `mount_setattr` per layer
and per container in the agent.

### Measurement 4 — the design that holds

The layer store and `upper`/`work` chowned to `BASE`, the volume as a bind:

```text
0 0 /   0 0 /data/config   0 0 /vol/store
ROOT-OK        LAYER-COPYUP-OK        VOL-OK
```

A container can write into its rootfs, change a file **from the image** (copy-up) and
write its volume — and `id` says `uid=0`.

### Measurement 5 — and the runtime question that constrains everything

| | crun 1.28 | youki 0.7.0 |
|---|---|---|
| user namespace, fresh netns | yes | **yes** |
| user namespace + **netns through a path** | yes | **no** — `setns` gives `EPERM` |
| idmapped mounts | yes | **no** — "not supported" |

The second point is the hard one: **every** container of this system joins a network
namespace through a path (ADR-0012, "The containers onto the network"). youki enters
it **from within the new user namespace** and does not have the permission there; crun
joins while still privileged and creates the user namespace afterwards.

That is the same shape as ADR-0038: an accepted ADR (here ADR-0003, youki-first) meets
a measurement that makes its default impossible for **one** capability.

## Decision Drivers

- **ADR-0017 requires it**, and the benefit is the largest of the three defaults.
- **It must break no running cluster.** A node running today has layers, bundles and
  volumes belonging to `root`.
- **A failure must not be silent.** A node that cannot apply the hardening has to say
  so — not carry on unprotected.
- **No new `unsafe` place.** `mount_setattr` does not exist in `rustix` as a safe
  wrapper; an implementation over idmapped layers would require a new block in
  `tg-syscall`.

## Options Considered

1. **A fixed mapping per node**, everything `chown`ed to the range.
2. **A mapping per container** with idmapped mounts for everything.
3. **Nothing** — stay with today's situation.

## Decision

### Determination 1 — a fixed mapping per node, `0..65535 → BASE..BASE+65535`

A mapping **per container** would be the stronger isolation: container A and container
B would have different host ids. It is rejected here, and not out of convenience:

- The **layer store is shared** (ADR-0003, one store, one digest). With a mapping per
  container it would have to be chowned per range — the end of sharing — or mounted
  idmapped per layer and per container. The latter requires `mount_setattr` and
  thereby a new `unsafe` place (invariant 2 permits it in `tg-syscall`, but it wants
  justifying).
- What a mapping per container additionally protects is **container against
  container** on the host filesystem. The ways there are closed anyway: every instance
  has its own rootfs and its own volume (ADR-0027), and the shared store is read-only
  anyway.

What the node **gains** is the actual point from ADR-0017: uid 0 in the container is
no longer uid 0 on the node. That is the same choice Docker makes with `userns-remap`.

### Determination 2 — `chown` instead of idmapped mounts

Three places get the range: the **layer store** when unpacking, `upper` and `work`
when building the bundle, and the **root of a volume** when mounting.

Idmapped mounts would be more elegant for volumes (measurement 2: the disk stays
untouched) — but the rootfs overlayfs cannot be idmapped anyway (measurement 3), so a
`chown` of the store is unavoidable. That leaves **one** mechanism instead of two, no
new syscall and no dependence on a capability only one of the two runtimes has.

The price stands here: **the files of a volume afterwards belong to `BASE`** on the
disk, not to `root`. An operator who backs them up and restores them has to preserve
the ids (`tar --numeric-owner`, `rsync -a`).

The `chown` of the volume root is **not recursive**: it makes a fresh volume writable
and leaves existing content alone. Whoever converts a running node migrates their
volumes themselves — a recursive `chown` over an unknown amount of data does not belong
in a reconcile pass.

### Determination 3 — an explicit setting, default **off**, and a failure is loud

The range is a setting on the agent (`--userns-base`). Without it everything stays as
it was.

That is a departure from ADR-0017's "on by default", and the reason is measurement 5:
with youki — the default runtime from ADR-0003 — a container of this system **cannot**
get a user namespace as long as it joins a netns through a path. A default of "on"
would mean making the default runtime unusable; a default of "on unless it does not
work" would mean that two nodes with the same configuration would have different
security postures without anybody seeing it.

If the setting is present and the runtime found cannot do it, **the agent does not
start**. That is the only place in this system where a missing hardening prevents the
start — and it is so because the operator explicitly demanded it: carrying on silently
unprotected would be the worse answer.

### Determination 4 — the socket stays as it is

The workload API socket carries `0666` (ADR-0060), because a connection requires write
permission and the sidecar runs under its own id. So a process under the mapped id
reaches it too. **It needs no `chown`** — the permissions there do not authorize
anyway (ADR-0081: the socket *is* the attestation).

### Determination 5 — the sidecar's id stays a container id

`SIDECAR_UID` (65532, ADR-0060) is an id **in the container**; under the mapping it
becomes `BASE + 65532`. It lies within the range, and the exception in the nftables
rule set hangs on the id the **kernel** sees — i.e. on the mapped one. The agent
converts it when laying the rule set.

## Consequences

**Positive.** An escape no longer ends as `root` on the node. The third default from
ADR-0017 is thereby buildable and built when an operator demands it.

**Negative.** It is not the default, and the reason lies in a foreign runtime. A node
with `--userns-base` requires crun — which ADR-0003 foresees as a fallback but which
here becomes a precondition. And the files in volumes and in the layer store belong to
`BASE` afterwards.

**Neutral.** The range is a setting per node. Two nodes with different ranges are not
an error — their stores and volumes are node-local — but a node that **changes** its
range has to re-chown its store.

## Risks & Open Points

- **A store from before.** A node converted to `--userns-base` has layers belonging to
  `root`. The store is chowned per layer at the next unpack — a layer already there is
  **not** touched. Whoever converts immediately chowns the store once by hand.
- **Volumes with content** stay as they are (determination 2).
- ~~**`--userns-base` is a setting per node**, and a mismatch is not visible. The same
  situation as with `--proxy-image` (ADR-0059) and `--dns-domain` (ADR-0013) — and the
  same answer would be a metric.~~ **Done** (`b66a692`, "The mismatch in the security
  posture is visible"): `tg_cluster_userns_postures`, set in the scheduler — the same
  construction as `PROXY_IMAGES` and `DNS_ZONES`, as this note predicted. The setting
  stays a setting per node; what is visible now is **that** two diverge.
- **Idmapped mounts stay the better answer** for volumes and for the store, as soon as
  youki can do them and a `mount_setattr` in `tg-syscall` is defensible. Then the
  `chown`s would fall away, and a range change would be free.
- **youki stays excluded** as long as it cannot enter a netns through a path from
  within the user namespace. That is a question for youki, not a defect of this design.

## Related ADRs

- **ADR-0017** — it names the user namespace as an "on by default" setting; this ADR
  builds it and says why the default is nevertheless "off".
- **ADR-0090** — the second of the three defaults, built in the same move.
- **ADR-0003** — youki-first; measurement 5 makes that crun-only for this case.
- **ADR-0012** — the netns through a path is the reason for it.
- **ADR-0027** — the volumes whose ownership shifts.
- **ADR-0060** — the socket carries `0666` and is therefore userns-proof without
  further ado; and the sidecar's id is mapped.
- **ADR-0081** — the socket is the attestation, not its permissions.
