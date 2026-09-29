# ADR-0115: The Permissions of the Data Directory

- **Status:** accepted
- **Date:** 2026-09-11
- **Concerns:** ADR-0019 (static stability), ADR-0017 (privileges), ADR-0044
  (operator access)

## Context and Problem Statement

ADR-0019 makes the local cache the node's truth:

> `tg-agent` is locally authoritative from a persisted desired-state cache.

and has named an open point ever since, unchanged since phase 4:

> Protection of the local desired-state cache against manipulation.

Measured against a real `tg-agent` and a real `tgctl apply` in a fresh data
directory:

| Place | Mode | `nobody` reads | `nobody` writes |
|---|---|---|---|
| `<data-dir>` | `drwxr-xr-x` | yes | no |
| `desired/`, `desired/*.xml` | `drwxr-xr-x`, `-rw-r--r--` | **yes** | no |
| `volumes/` | `drwxr-xr-x` | yes | no |
| `content/` | `drwx------` | no | no |
| `runtime/` | `drwx------` | no | no |
| `identity/secrets.key` | `-rw-------` | no | no |

```text
$ runuser -u nobody -- cat <data-dir>/desired/api.xml
<?xml version="1.0" encoding="UTF-8"?>
<tg:workloads xmlns:tg="urn:tardigrade:workload:v1"><tg:workload name="api" …
$ runuser -u nobody -- cat <data-dir>/content/blobs
cat: Permission denied
```

**The finding is sharper than the open point, and different in both
directions.**

### Finding 1 — against manipulation it is the umask that carries

A non-root user can write nothing today. But what prevents them is nothing that
was decided: `DesiredState::open` calls `create_dir_all` and nothing else, and
`create_dir_all` creates with `0777 & !umask`. The security of the desired
state therefore hangs on the umask of whoever started the agent — on a number
that appears in no document of this tree and that a unit file with `UMask=000`
silently sets to zero.

What then happens is the actual damage: a local user replaces
`desired/api.xml`, the agent starts that image — and it gets the **SVID of the
real workload**, because identity hangs on the name (ADR-0006, ADR-0065). The
cache is the node's truth; whoever writes it writes the truth.

For exactly this question the content store has had an explicit `content::seal`
to `0700` since ADR-0017 **and** a witness that checks with
`runuser -u nobody`. The desired state has neither. The same machine, the same
data directory, two answers.

### Finding 2 — against reading nothing carries at all, and that was never the question

The open point says "manipulation". Measured, confidentiality is the bigger gap,
and it stood nowhere: **every local user reads the node's desired state.** Via
`network/`, which arises in the same way (`create_dir_all` in `session::apply`,
`std::fs::write` for the content), they additionally read the `may_talk` edges,
the egress allowlist, the active roles, the WireGuard peers together with
endpoints, and the cluster's address plan.

For a REMIT/DORA system that is the kind of finding an auditor writes down: a
node's complete authorization policy, readable for every account on the
machine.

### Finding 3 — the only protected directory is none of ours

`runtime/` stands at `0700`, and in this tree nobody sets that:
`OciRuntime::discover` creates nothing, and `create_dir` occurs in `oci.rs`
only in the test module. The permissions come from youki or crun. The directory
that is best protected is the one we did not take care of.

## Options Considered

- **A — leave it, write it down.** Name the umask in the operations manual and
  be done.
- **B — seal the directories explicitly**, as the content store has done since
  ADR-0017, with witnesses.
- **C — a MAC over every cache entry** (data key from ADR-0095), set on write,
  checked on read.
- **D — abort at startup** if the permissions are not right.

## Decision

Chosen: **B**.

### Determination 1 — set, not left to the umask

Every directory this tree creates under the data directory gets its mode
**explicitly**, on opening, in the same function that creates it. A security
property that follows from a process environment is none — it is an observation
about one run.

That expressly applies to an **existing** directory too: `create_dir_all` does
not touch one that is already there, and a node that ran before this decision
would otherwise stay in exactly the state at issue. That is the same
justification that already stands above `content::seal`.

### Determination 2 — directories are sealed, not files

The file modes stay as they are. The reason is not convenience: three files
from `network/` are mounted read-only into the sidecar container (`may-talk`,
`egress`, `active-role`), and it runs under the identity 65532 (ADR-0060). Set
to `0600` one would take its edges away — and thereby the enforcement for the
sake of which it exists.

The directory carries the protection: whoever cannot get in does not open the
file via its path. A **bind mount** does not depend on the host's parent path,
so the container stays untouched. The workload API socket has had exactly this
construction since ADR-0081: directory `0700`, socket `0666`.

### Determination 3 — which directories

Newly sealed are `<data-dir>` itself, `desired/`, `network/` and `volumes/`.
Already sealed are `content/` and `bundles/` (ADR-0017) as well as `sockets/`
(ADR-0081). `runtime/` belongs to the OCI runtime and is not touched — a
foreign program keeps its books there, and setting the permissions of its own
state directory would be an intervention across the boundary from ADR-0003.

The root is in the list too, and it is the effective part: what lies under a
directory nobody may enter is protected even if someone later adds a
subdirectory and forgets to seal it.

### Determination 4 — no MAC over the entries

Option C is **rejected**, and that belongs written down rather than left open.
Whoever can write `desired/*.xml` is root. Root reads
`identity/secrets.key` on the same disk — the key with which the MAC would be
formed — and root replaces the binary that checks it anyway. A lock whose key
hangs beside it is none.

That is the same answer ADR-0044 gave for the admin socket ("root is root"),
and here it is not weaker but more precise: the open point from ADR-0019 asks
for protection against manipulation, and the only manipulation the file
permissions do not already exclude is that by root. Against that, nothing
protects at this level.

What would help lies outside this ADR and outside this tree: mandatory access
control (SELinux, AppArmor), measured boot, a read-only root file system. That
is operations work on the machine, not on the orchestrator, and it stands below
as an open point.

### Determination 5 — fail-soft, not fail-closed

Option D is rejected. A node that does not start because of a permission bit
takes its workloads' connections away — the inversion of ADR-0019, and the same
trap ADR-0062 ran into (an unreadable entry ended the agent). The permissions
are **set**; if that fails, it is reported and work continues.

They are set before the first write, not after: the other way round there would
be a window in which the desired state lies in an open directory — and it would
be most open at startup. The same argument as with the admin socket (ADR-0044)
and the socket directory (ADR-0081).

### Determination 6 — the witness checks with foreign eyes

What is checked is not the mode but the **access**: `0700` is a number, and
that the kernel makes a lock out of it is only shown by a
`runuser -u nobody`. That is the witness `private_store` already has for the
content store (ADR-0017), and it belongs in the same path.

Plus the counter-check, which here is the more dangerous half: **the sidecar
still reads its mounted files.** Without it a version would be green that
switches off a whole node's mesh.

## Consequences

**Positive**

- The oldest open point from ADR-0019 is decided — and in the direction the
  measurement showed, not the one it had named.
- The confidentiality of the desired state, the edges, the egress permissions,
  the peers and the address plan no longer hangs on a umask.
- The inconsistency disappears: the same protection for the store and for the
  state that drives it.

**Negative / costs**

- **A tool that looked into the data directory as non-root sees nothing any
  more.** A monitoring script that counted `desired/` breaks. That is the
  point and nevertheless a behaviour change; it belongs in the manual.
- An operator who creates `identity/` themselves determines its permissions
  until the agent's first start. We set them on opening; the moment before
  belongs to them.
- The mode is set at **every** start, even if an operator changed it
  deliberately. That is intended — a security property one can switch off once
  is one that is eventually switched off.

**Risks & open points**

- **Against root this protects nothing**, and it is not supposed to. The next
  layer would be mandatory access control (SELinux/AppArmor) together with a
  profile for the three binaries; that is not decided and belongs to the
  machine, not to the orchestrator.
- **The file's path onto the disk stays unencrypted.** `desired/*.xml` lies in
  plaintext; whoever removes the disk reads it. Volumes have been encrypted
  since ADR-0113, the desired state is not — whether it should be is a separate
  question (the key would come from ADR-0095, and the first start would then
  hang on the credential path).
- **What arose before the sealing stays what it was**, as far as it is not one
  of the named directories: a file an earlier run put into the root with `0644`
  does not become narrower retroactively. Here the protection comes from the
  directory above it.

## Related ADRs

- **Redeems:** **ADR-0019**, open point *"protection of the local
  desired-state cache against manipulation"* — with the finding that the
  question was off target.
- **Applies:** **ADR-0017** (`content::seal`, the same function and the same
  witness), **ADR-0081** (directory narrow, file wide), **ADR-0044** ("root is
  root"), **ADR-0019/0062** (fail-soft: no permission bit costs a node).
- **Touches:** **ADR-0060** (the sidecar reads as 65532 from `network/`),
  **ADR-0003** (`runtime/` belongs to the OCI runtime), **ADR-0113** (volumes
  encrypted, the desired state not).
