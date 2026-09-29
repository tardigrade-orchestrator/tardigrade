//! The workloads' seccomp profile.
//!
//! # Why a denylist
//!
//! Seccomp is meant to be on by default for every workload, and measured it was
//! missing. The widespread construction is an **allowlist** with about 350 names;
//! it is the wrong one here, for two reasons: it is a vendored artifact nobody can
//! justify individually, and it breaks what it does not know -- a new glibc path, a
//! syscall from a future kernel. At a target availability of 4-9 to 5-9 that is the
//! expensive direction.
//!
//! A denylist **structurally cannot** do that: what does not stand on it runs. The
//! trade-off is a reduction of an attack surface, not an encapsulation.
//!
//! # What it achieves, and what was measured first
//!
//! This project has already found the opposite case: a device cgroup restriction was
//! **silently ignored** by the runtime. Measured at real containers, **both**
//! container runtimes in use enforce a profile -- `crun` 1.28 and `youki` 0.7.0, each
//! with and without a profile.
//!
//! With that the rule "no eBPF inside a workload" is enforced for the first time and
//! not merely counted: a `bpf(2)` syscall counter on the node says how many programs
//! are loaded; this profile sees to it that a container **cannot** load any.

use oci_spec::runtime::{
    Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder,
};

const EPERM: u32 = 1;

pub const DENIED: &[(&str, &[&str])] = &[
    (
        // No eBPF program may be loaded, and that from a container too.
        "no eBPF",
        &["bpf"],
    ),
    (
        // A kernel module changes the kernel under which **all** the workloads of
        // this node run.
        "kernel modules",
        &[
            "init_module",
            "finit_module",
            "delete_module",
            "create_module",
            "query_module",
            "get_kernel_syms",
        ],
    ),
    (
        // The node carries foreign workloads (ADR-0019).
        "booting another kernel or rebooting",
        &["kexec_load", "kexec_file_load", "reboot"],
    ),
    (
        // The rootfs and volume isolation (ADR-0017, ADR-0027) rests on the mounts
        // the agent set.
        "mounts",
        &[
            "mount",
            "umount2",
            "pivot_root",
            "move_mount",
            "open_tree",
            "fsopen",
            "fsconfig",
            "fsmount",
            "fspick",
        ],
    ),
    (
        // Entering a foreign namespace or reaching past a mount onto the host file
        // system.
        "out of one's own namespace",
        &["setns", "open_by_handle_at"],
    ),
    (
        // The kernel keyring is **not** namespaced: state shared between all the
        // node's containers.
        "the kernel keyring",
        &["add_key", "keyctl", "request_key"],
    ),
    (
        // Observation beyond one's own boundary.
        "observation of the host",
        &["perf_event_open", "syslog", "fanotify_init"],
    ),
    (
        // **The host's clock** (ADR-0024). On it hang the audit trail's timestamps
        // (ADR-0020) and the deadline of every active-role lease (ADR-0078).
        "the host's clock",
        &[
            "settimeofday",
            "clock_settime",
            "clock_adjtime",
            "adjtimex",
            "stime",
        ],
    ),
    (
        // Host-wide or obsolete interfaces no workload of this system needs.
        "host-wide or obsolete",
        &[
            "swapon",
            "swapoff",
            "acct",
            "quotactl",
            "ioperm",
            "iopl",
            "vm86",
            "vm86old",
            "uselib",
            "nfsservctl",
            "_sysctl",
            "ustat",
            "sysfs",
        ],
    ),
];

#[must_use]
pub fn architectures() -> Vec<Arch> {
    #[cfg(target_arch = "x86_64")]
    {
        vec![Arch::ScmpArchX86_64, Arch::ScmpArchX86, Arch::ScmpArchX32]
    }
    #[cfg(target_arch = "aarch64")]
    {
        vec![Arch::ScmpArchAarch64, Arch::ScmpArchArm]
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Vec::new()
    }
}

pub fn profile() -> Result<LinuxSeccomp, String> {
    let mut syscalls = Vec::with_capacity(DENIED.len());
    for (_, names) in DENIED {
        let entry = LinuxSyscallBuilder::default()
            .names(
                names
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>(),
            )
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(EPERM)
            .build()
            .map_err(|err| format!("the syscall entry: {err}"))?;
        syscalls.push(entry);
    }

    LinuxSeccompBuilder::default()
        // **`ALLOW` as the default** (ADR-0090, determination 1): what does not stand
        // on the list runs.
        .default_action(LinuxSeccompAction::ScmpActAllow)
        .architectures(architectures())
        .syscalls(syscalls)
        .build()
        .map_err(|err| format!("the seccomp profile: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_not_on_the_list_runs() {
        assert_eq!(
            profile().expect("the profile").default_action(),
            LinuxSeccompAction::ScmpActAllow,
            "a denylist has ALLOW as its default"
        );
    }

    #[test]
    fn a_denied_call_returns_eperm() {
        let profile = profile().expect("the profile");
        let syscalls = profile.syscalls().as_ref().expect("the entries");
        assert!(!syscalls.is_empty(), "an empty denylist denies nothing");
        for entry in syscalls {
            assert_eq!(
                entry.action(),
                LinuxSeccompAction::ScmpActErrno,
                "a killed process looks like a crash"
            );
            assert_eq!(entry.errno_ret(), Some(EPERM), "the error is EPERM");
        }
    }

    #[test]
    fn no_container_may_load_a_bpf_program() {
        assert!(
            DENIED
                .iter()
                .flat_map(|(_, names)| names.iter())
                .any(|name| *name == "bpf"),
            "invariant 1 belongs in the profile"
        );
    }

    #[test]
    fn the_clock_of_the_host_is_out_of_reach() {
        let denied: Vec<&str> = DENIED
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        for name in ["settimeofday", "clock_settime", "clock_adjtime", "adjtimex"] {
            assert!(
                denied.contains(&name),
                "{name} is missing from the denylist"
            );
        }
    }

    #[test]
    fn the_deliberate_exclusions_stay_out() {
        let denied: Vec<&str> = DENIED
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        for name in [
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "unshare",
            "clone",
            "io_uring_setup",
            "io_uring_enter",
        ] {
            assert!(
                !denied.contains(&name),
                "{name} is expressly permitted (ADR-0090) and stands in the denylist"
            );
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn the_compat_abi_is_filtered_too() {
        let arches = architectures();
        for arch in [Arch::ScmpArchX86_64, Arch::ScmpArchX86, Arch::ScmpArchX32] {
            assert!(
                arches.contains(&arch),
                "{arch:?} is missing from the profile"
            );
        }
    }

    #[test]
    fn every_name_has_exactly_one_reason() {
        let mut seen = std::collections::BTreeSet::new();
        for (reason, names) in DENIED {
            for name in *names {
                assert!(
                    seen.insert(*name),
                    "'{name}' stands twice -- last under '{reason}'"
                );
            }
        }
    }
}
