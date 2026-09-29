//! The hostname comes from the **kernel**, not from the environment.
//!
//! Measured, `$HOSTNAME` was the wrong source: the variable is set by the
//! **shell**, and a service under systemd does not get it —
//!
//! ```text
//! env -i printenv HOSTNAME                       -> exit 1
//! systemd-run --pipe /usr/bin/printenv HOSTNAME  -> exit 1
//! ```
//!
//! — whereby `tgd` and `tg-agent` fell back to the name `node`. The name stands
//! in the URI SAN of the cluster leaf and is bound to an invitation (ADR-0043,
//! ADR-0037); two machines with the same name are not a blemish.

/// **The same answer as the kernel, over a different way.**
///
/// Compared against `/proc/sys/kernel/hostname` — a **different** source from
/// `uname(2)`. A comparison against itself would be a tautology.
#[test]
fn the_hostname_is_the_one_the_kernel_reports() {
    let from_proc = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("procfs has to be readable")
        .trim()
        .to_owned();

    assert_eq!(
        tg_syscall::hostname().as_deref(),
        Some(from_proc.as_str()),
        "uname(2) and procfs disagree"
    );
    assert!(
        !from_proc.is_empty(),
        "an empty hostname — then the default carries nothing"
    );
}

/// **And the environment has no influence on it.**
///
/// The actual assurance of this cut: the same answer whether `$HOSTNAME` is set
/// or not. Checked on a **child process** with an empty environment —
/// `std::env::remove_var` is `unsafe` in this edition and would apply to all
/// threads of the test process.
#[test]
fn an_empty_environment_changes_nothing() {
    let mine = tg_syscall::hostname().expect("a hostname");

    // `printenv HOSTNAME` in an empty environment: nothing. The kernel name, by
    // contrast, stands.
    let empty = std::process::Command::new("env")
        .args(["-i", "/usr/bin/printenv", "HOSTNAME"])
        .output()
        .expect("env has to be startable");
    assert!(
        !empty.status.success(),
        "HOSTNAME is set in an empty environment — then this test checks the \
         wrong thing"
    );

    let kernel = std::process::Command::new("env")
        .args(["-i", "/usr/bin/uname", "-n"])
        .output()
        .expect("uname has to be startable");
    assert_eq!(
        String::from_utf8_lossy(&kernel.stdout).trim(),
        mine,
        "the kernel name hangs on the environment"
    );
}
