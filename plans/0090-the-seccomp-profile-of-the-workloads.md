# ADR-0090: The seccomp profile of the workloads

- **Status:** accepted
- **Date:** 2026-09-05
- **Deciders:** Architecture
- **Technical context:** `tg-runtime`, `tg-agent`, ADR-0017, ADR-0003, ADR-0023,
  ADR-0024

## Context and Problem Statement

ADR-0017 names three defaults as **on by default**: `noNewPrivileges`, a user
namespace and **seccomp**. Measured, one of them is on, and it is the one that comes
from the OCI default:

| Default from ADR-0017 | measured |
|---|---|
| `noNewPrivileges` | **on** — from `ProcessBuilder::default()` |
| capabilities narrow | on (three) |
| masked / read-only paths | on (10 / 5) |
| **seccomp** | **missing** |
| **user namespace** | missing |

The plan has carried the seccomp profile since phase 0 as a "starting value in the
relevant phase" and most recently placed it thus: *"a seccomp profile is either a
vendored list (a supply-chain decision, ADR-0023) or a hand-written one nobody
reads."* That is the question decided here.

### First measured: is a profile applied at all?

That question stands at the beginning, because this project has already found the
opposite case: the **device cgroup** from ADR-0028 is **silently ignored** by the
runtime, because its v2 controller is eBPF-based and invariant 1 excludes that.
Building a profile nobody enforces would be a promise without effect.

Measured against a real container with both runtimes from ADR-0003 — a profile that
answers `utimensat` with `EPERM`:

```text
crun  1.28   without profile: TOUCH-OK    with profile: touch: Operation not permitted
youki 0.7.0  without profile: TOUCH-OK    with profile: touch: Operation not permitted
```

**Both enforce it.** `crun --version` names `+SECCOMP`; youki likewise. So it is not a
promise without effect, and the question deserves a decision.

## Decision Drivers

- **It must break no workload.** Target availability 4-9 to 5-9: a profile that makes
  a legitimate application fail on an unknown syscall costs more than it brings — and
  at a time nobody predicts.
- **It has to be readable.** An auditor per ADR-0020 asks *why* a syscall is blocked.
  A list of 350 names does not answer that.
- **No new supply chain** (ADR-0023). A vendored foreign profile is an artefact
  somebody has to maintain and that ages with every kernel version.
- **Invariant 1** — no eBPF — is today evidenced only at the **node**: the `bpf(2)`
  counter from phase 9b counts loaded programs. A container calling `bpf(2)` is not
  prevented by it, only counted.

## Options Considered

1. **An allowlist** like the Docker default profile: `SCMP_ACT_ERRNO` as the default,
   around 350 permitted names.
2. **A denylist**: `SCMP_ACT_ALLOW` as the default, a small, justified set of blocked
   syscalls.
3. **Nothing** — stay with today's situation and rely on capabilities.

## Decision

**Option 2: a denylist.**

### Determination 1 — `SCMP_ACT_ALLOW` as the default, `SCMP_ACT_ERRNO` (EPERM) for a named set

The allowlist is the common construction and here the wrong one. It is a **vendored
artefact** (ADR-0023) of 350 lines that nobody can justify individually, and it breaks
what it does not know: a new glibc path, an `io_uring` call, a syscall a future kernel
introduces. That is the expensive direction — the outage hits a legitimate workload,
and it hits it at a time nobody plans.

A denylist **structurally cannot** do that: what is not on it runs. Every entry
carries its reason, and an auditor reads one page instead of a table.

The price stands here rather than being left out: a denylist is **no** protection
against an unknown kernel bug in a syscall it does not name. It is the reduction of an
attack surface, not an encapsulation. Whoever wants the latter needs a different
isolation level (Kata, gVisor) — and that would be a decision of its own with a supply
chain of its own.

### Determination 2 — `EPERM` and not `SCMP_ACT_KILL_PROCESS`

A killed process looks like a crash: the reconciler restarts it (ADR-0010), and out of
that comes a restart loop whose cause nobody sees. `EPERM` is an error the workload can
report — and that appears in the node's log as what it is.

### Determination 3 — the denylist, with reasons

| Syscalls | Reason |
|---|---|
| `bpf` | **Invariant 1**: no eBPF — and not from a container either. Until now that was counted at the node, not prevented. |
| `init_module`, `finit_module`, `delete_module`, `create_module`, `query_module`, `get_kernel_syms` | Loading kernel modules means changing the kernel under which all this node's workloads run. |
| `kexec_load`, `kexec_file_load`, `reboot` | Starting another kernel or rebooting the machine — the node carries foreign workloads (ADR-0019). |
| `mount`, `umount2`, `pivot_root`, `move_mount`, `open_tree`, `fsopen`, `fsconfig`, `fsmount`, `fspick` | The rootfs and volume isolation (ADR-0017, ADR-0027) rests on the mounts the agent has set. |
| `setns`, `open_by_handle_at` | Entering a foreign namespace, or reaching the host filesystem past a mount. |
| `add_key`, `keyctl`, `request_key` | The kernel keyring is **not** namespaced: it is shared state between all the node's containers. |
| `perf_event_open`, `syslog`, `fanotify_init` | Observation beyond one's own boundary — the kernel ring buffer and other processes' events. |
| `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`, `stime` | **The host's clock** (ADR-0024). On it hang the audit trail's timestamps (ADR-0020) and the deadline of every active-role lease (ADR-0078). |
| `swapon`, `swapoff`, `acct`, `quotactl`, `ioperm`, `iopl`, `vm86`, `vm86old`, `uselib`, `nfsservctl`, `_sysctl`, `ustat`, `sysfs` | Host-wide or obsolete interfaces no workload of this system needs. |

**Explicitly not blocked:**

- **`ptrace`** and `process_vm_readv`/`process_vm_writev`. They are the way `gdb`,
  `strace` and every profiler work, and they act within the PID namespace. Docker
  re-permitted them for the same reason.
- **`unshare`** and `clone`. Without the matching capabilities they are without effect
  anyway, and tools that try them and handle `EPERM` should keep running.
- **`io_uring_setup` and relatives.** They are a known attack surface — and ADR-0022
  names io_uring as a path for the data plane. Blocking them here would mean
  pre-empting a decision about our own data plane.

Each of these three exclusions is a trade-off, not an omission.

### Determination 4 — all architectures of the platform, not only the native one

A filter applies per **ABI**. If the profile names only `SCMP_ARCH_X86_64`, then a
32-bit process is **unfiltered** through the `i386` compatibility layer — the block
would be there and would be circumventable by calling the same syscall through a
different number.

The profile therefore names `SCMP_ARCH_X86` and `SCMP_ARCH_X32` on x86_64 too, and
`SCMP_ARCH_ARM` additionally on aarch64. Which architectures apply is decided by the
version of the **agent** that writes the specification.

### Determination 5 — for every container, with an explicit way out

The profile applies to **every** container this system starts — including the derived
sidecar (ADR-0059); it calls none of them.

The way out is a setting on the agent (`--no-seccomp`), and it is **reported** at
startup. ADR-0017 demands exactly that for a relaxation: explicit and audited. No
field in the schema — a definition that switches off its own hardening would be a
workload author's decision about the node; the node belongs to the operator.

## Consequences

**Positive.** Invariant 1 is for the first time **enforced** and not merely counted: a
container can no longer call `bpf(2)`. The host's clock is protected against a
container, and with it the time axis on which ADR-0020 and ADR-0078 rest. The list is
one page long and carries its reasons.

**Negative.** A denylist does not protect against the syscall it does not know. And a
workload that **legitimately** needs a blocked call — a monitoring agent with
`perf_event_open`, a tool with `mount` — no longer runs from here on; for it there is
only the setting at the node, i.e. all or nothing. A finer gradation would be a
decision of its own.

**Neutral.** The list stands in one place and will age with kernel versions. That is
intended: extending it is a commit with a justification, not an update of a foreign
artefact.

## Risks & Open Points

- **The user namespace stays open.** It is the second of the three defaults from
  ADR-0017 and shifts the ownership of every volume, of the mounted socket (ADR-0081),
  of the `.owner` marker and of the layer store — a decision of its own.
- **No metric** — and on measurement the path there is longer than this note said. The
  chain, checked on a real container:

  1. **Today a refusal produces nothing at all.** After a run of
     `no_container_may_call_bpf`, `dmesg` is empty and the audit log contains **zero**
     `SECCOMP` records. The container gets `EPERM`, and that is that.
  2. **`SCMP_ACT_LOG` is not needed.** The OCI specification knows
     `SECCOMP_FILTER_FLAG_LOG` as a **flag** on the filter; `oci-spec` serializes it
     (`"flags":["SECCOMP_FILTER_FLAG_LOG"]`), youki 0.7.0 knows the name, and
     `/proc/sys/kernel/seccomp/actions_logged` contains `errno`. So the actions would
     not have to be touched.
  3. **And the log still stays empty.** With the flag no record arose either — because
     this machine's audit rule reads `-a never,task`, the default of widespread
     distributions. It discards task records, `SECCOMP` included, before `auditd` sees
     them.

  So visibility hangs on a configuration **outside** this system. A metric on it would
  be mute on a default installation — i.e. exactly the time series indistinguishable
  from a switched-off reporter, which this tree otherwise rejects (ADR-0088).

  What an operator can do instead stands in the manual: change the audit rule or stop
  `auditd`, then the records stand in `dmesg`. Nothing is built here.
- **The list is not checked against a kernel that does not know a name.** `libseccomp`
  skips unknown names; a typo would therefore **not** stand out. The witness
  accordingly checks the effect on a real container and not the presence in the
  document.

## Related ADRs

- **ADR-0017** — it names seccomp as an "on by default" setting; this ADR redeems one
  of the two missing ones.
- **ADR-0003** — both runtimes enforce a profile, measured.
- **ADR-0023** — an allowlist would be a vendored artefact.
- **ADR-0024**, **ADR-0020**, **ADR-0078** — the host's clock and what hangs on it.
- **ADR-0022** — `io_uring` stays permitted, so that the data plane keeps its own
  decision.
- **ADR-0028** — the opposite case: a setting the runtime silently ignores.
