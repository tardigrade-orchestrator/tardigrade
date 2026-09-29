//! Network namespaces against the real kernel (phase 9b).
//!
//! These tests create real namespaces. That demands `CAP_SYS_ADMIN` and
//! `CAP_NET_ADMIN`, so they are `#[ignore]` — the same treatment as the
//! container test in `tg-identity/tests/attestation.rs`, and for the same
//! reason: the Definition of Done shall be green on an ordinary working copy
//! without anybody typing `sudo`. They are run with `cargo xtask net`.
//!
//! Unlike the youki test they do **not** hang when the privileges are missing —
//! they fail immediately and readably. The `#[ignore]` is a question of the
//! environment here, not of self-protection.
//!
//! The name check above them runs everywhere: it is a trust boundary and needs
//! no privilege.

use tg_syscall::netns;

/// One name per run so that parallel runs do not get in each other's way.
fn unique(prefix: &str) -> String {
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    format!("{prefix}-{:x}", hasher.finish() & 0xffff_ffff)
}

/// Clears the namespace away even if the test fails.
struct Cleanup(String);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = netns::delete(&self.0);
    }
}

/// The identifier of **this thread's** network namespace.
///
/// `/proc/thread-self`, not `/proc/self`: the latter means the thread group
/// leader, and that one stays with the caller. Whoever writes `self` here
/// measures the wrong thread and never sees a difference.
///
/// And expressly **not** `/sys/class/net`: sysfs shows the namespace that
/// applied at mount time and does not follow a `setns`. `ip netns exec`
/// therefore remounts sysfs.
fn netns_id() -> String {
    std::fs::read_link("/proc/thread-self/ns/net")
        .expect("namespace link")
        .to_string_lossy()
        .into_owned()
}

// ------------------------------------------------ checkable without privileges

/// The name becomes a file name under `/run/netns` — a trust boundary.
#[test]
fn a_name_that_would_escape_the_directory_is_refused() {
    let long = "x".repeat(65);
    for hostile in [
        "..",
        ".",
        "",
        "../../etc/passwd",
        "a/b",
        "a\0b",
        "a b",
        long.as_str(),
    ] {
        let err = netns::path(hostile).expect_err("should have been refused");
        assert!(
            matches!(err, netns::NetNsError::IllegalName { .. }),
            "'{}' yielded {err:?}",
            hostile.escape_debug()
        );
    }
}

#[test]
fn a_legal_name_lands_under_the_run_directory() {
    let path = netns::path("tg-api-0").expect("valid name");
    assert_eq!(path.to_str(), Some("/run/netns/tg-api-0"));
}

// ---------------------------------------------------------- demands privileges

#[test]
#[ignore = "demands CAP_SYS_ADMIN and CAP_NET_ADMIN; run via `cargo xtask net`"]
fn a_namespace_is_created_listed_and_deleted() {
    let name = unique("tg-create");
    let _cleanup = Cleanup(name.clone());

    let path = netns::create(&name).expect("create");
    assert!(path.exists(), "the mount is missing");
    assert!(netns::list().expect("list").contains(&name));

    netns::delete(&name).expect("delete");
    assert!(!path.exists());
    assert!(!netns::list().expect("list").contains(&name));
}

/// Creating twice is an error, not a silent success: two instances sharing a
/// namespace would be an error one would notice only from the traffic.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and CAP_NET_ADMIN; run via `cargo xtask net`"]
fn creating_the_same_namespace_twice_is_refused() {
    let name = unique("tg-twice");
    let _cleanup = Cleanup(name.clone());

    netns::create(&name).expect("first creation");
    let err = netns::create(&name).expect_err("second creation");

    assert!(
        matches!(err, netns::NetNsError::Exists { .. }),
        "expected Exists, was {err:?}"
    );
}

#[test]
#[ignore = "demands CAP_SYS_ADMIN and CAP_NET_ADMIN; run via `cargo xtask net`"]
fn deleting_something_that_is_not_there_is_refused() {
    let err = netns::delete(&unique("tg-nothing")).expect_err("does not exist");
    assert!(matches!(err, netns::NetNsError::Missing { .. }));
}

/// The core: what runs in `run_in` sees a different network — and the calling
/// thread stays where it was. That is the property justifying the thread trick
/// in the module header.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and CAP_NET_ADMIN; run via `cargo xtask net`"]
fn work_inside_a_namespace_sees_a_different_network() {
    let name = unique("tg-inside");
    let _cleanup = Cleanup(name.clone());
    netns::create(&name).expect("create");

    let outside_before = netns_id();
    let inside = netns::run_in(&name, netns_id).expect("run in the namespace");

    assert_ne!(
        inside, outside_before,
        "the thread in run_in sits in the same namespace as the caller"
    );
    assert_eq!(
        netns_id(),
        outside_before,
        "the calling thread must not have moved along"
    );
}

/// A child process inherits the namespace of the **thread** that starts it. The
/// call of `nft` in a container's namespace rests on that (ADR-0038); without
/// this property it would need a detour over `pre_exec` and thereby `unsafe` in
/// a second place.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and CAP_NET_ADMIN; run via `cargo xtask net`"]
fn a_child_process_inherits_the_namespace_of_the_thread_that_forked_it() {
    let name = unique("tg-child");
    let _cleanup = Cleanup(name.clone());
    netns::create(&name).expect("create");

    let child_sees = netns::run_in(&name, || {
        std::process::Command::new("readlink")
            .arg("/proc/self/ns/net")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    })
    .expect("run in the namespace")
    .expect("readlink has to run");

    assert_ne!(
        child_sees,
        netns_id(),
        "the child ran in the caller's namespace"
    );
    assert!(
        child_sees.starts_with("net:["),
        "unexpected output: '{child_sees}'"
    );
}
