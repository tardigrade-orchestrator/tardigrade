//! Thin syscall wrappers: netlink, cgroups, namespaces, mounts.
//!
//! ADR-0002. This is the **only** crate in which `unsafe` is permitted
//! (invariant 2 in CLAUDE.md). Every unsafe block carries a `// SAFETY:`
//! comment — a lint rather than a promise, since
//! `clippy::undocumented_unsafe_blocks` stands workspace-wide on `deny`;
//! `unsafe_op_in_unsafe_fn` below enforces the half a compiler can see, and
//! measured there is **no** `unsafe fn` in the whole tree.
//!
//! The purpose of the crate is the **boundary**, not the `unsafe` itself: all
//! kernel calls converge here so that they can be checked in one place.
//! `rustix` already wraps most of the needed syscalls safely, so `unsafe` is
//! needed only where `rustix` does not know the call.
//!
//! State after ADR-0081: **three** `unsafe` blocks on the production path of the
//! whole tree, all here — `bpf(2)` for the proof from 9b and `unshare` for the
//! namespaces. The two from ADR-0053 (`getsockopt` for `SO_PEERPIDFD` and taking
//! ownership of the descriptor) are gone: since ADR-0081 the socket is the
//! attestation. A fourth lies in a test module ([`unix_path`]) and measures a
//! property of the **type**; it does not count, because it ships nothing.

#![deny(unsafe_op_in_unsafe_fn)]
// No panic-capable call on the production path (ADR-0082). `not(test)` because
// the unit tests in `src` need them; the guard lies in
// `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

// The guard from ADR-0082, determination 3. It lies here because the profile
// applies workspace-wide (one translation unit suffices) and all four binaries
// link this crate. It fires exactly where the setting applies: `dev` defaults to
// `unwind` and stays silent, a release build with `abort` fails. For
// `overflow-checks` there is no such way (`cfg(overflow_checks)` is nightly);
// there a test guards the manifest.
#[cfg(panic = "abort")]
compile_error!(
    "ADR-0082: the release profile must carry `panic = \"unwind\"`. With \
     `abort` a panic in one of the four sidecar shards takes the other three \
     with it, including every running mTLS connection (ADR-0019, ADR-0022) — \
     and the six places that handle a foreign thread's panic are dead code."
);

pub mod accept;
pub mod bpf;
pub mod fds;
pub mod lock;
pub mod mount;
pub mod netns;
pub mod unix_path;

#[must_use]
pub fn hostname() -> Option<String> {
    let raw = rustix::system::uname();
    let name = raw.nodename().to_str().ok()?;
    if name.is_empty() {
        return None;
    }

    Some(name.to_owned())
}
