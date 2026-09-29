//! What a failure to accept a connection may cost.
//!
//! The rule is pure logic and therefore stands here, without a socket: a
//! listener whose rejection paths one can only see with exhausted descriptors is
//! one whose rejection paths nobody has ever seen.
//!
//! The **effect** lies beside it — `tg-net/tests/resolver_exhaustion.rs` runs it
//! on a real listener with a real `EMFILE`.

use tg_syscall::accept::{Fault, classify};

/// A `libc` name instead of a number, and expressly **not** the same way
/// [`classify`] goes (`rustix::io::Errno`): an assertion that draws its expected
/// value from the logic under test checks nothing.
fn errno(number: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(number)
}

/// **`EMFILE` demands a pause, not an immediate carry-on.**
///
/// Measured on a real listener: the waiting connection is **not** consumed, and
/// `accept` returns the same error on the next attempt — immediately. A
/// `continue` without a pause is thereby a hot loop that burns a core (ADR-0022)
/// and achieves nothing.
#[test]
fn exhausted_descriptors_demand_a_pause() {
    assert_eq!(classify(&errno(libc::EMFILE)), Fault::Exhausted);
    assert_eq!(classify(&errno(libc::ENFILE)), Fault::Exhausted);
}

/// The kernel's buffers and memory belong to it too.
///
/// `ENOBUFS` has no name on `stable` in [`std::io::ErrorKind`] — it comes back
/// as `Uncategorized`, and precisely for that reason [`classify`] goes over
/// `raw_os_error`.
#[test]
fn exhausted_buffers_and_memory_demand_a_pause() {
    assert_eq!(classify(&errno(libc::ENOBUFS)), Fault::Exhausted);
    assert_eq!(classify(&errno(libc::ENOMEM)), Fault::Exhausted);
}

/// **A connection that no longer exists costs no half second.**
///
/// That is the normal case on a port every container reaches: a client that
/// disappears between handshake and `accept`, a port scanner, an `EPERM` from
/// the host's packet filter. Answering it with [`Fault::Exhausted`] would mean
/// that a single aborted connection attempt halts the listener for everyone
/// else — and whoever wants to exploit that does it repeatedly.
#[test]
fn a_connection_that_vanished_costs_no_pause() {
    for number in [
        libc::ECONNABORTED,
        libc::ECONNRESET,
        libc::ECONNREFUSED,
        libc::EINTR,
        libc::EPERM,
        libc::ETIMEDOUT,
        libc::EHOSTUNREACH,
    ] {
        assert_eq!(
            classify(&errno(number)),
            Fault::Connection,
            "errno {number} is a failure of this one connection"
        );
    }
}

/// **An unknown failure is decided on the safe side.**
///
/// [`std::io::ErrorKind`] is `non_exhaustive`, and so in practice is the list of
/// `errno` a kernel may return. The default is therefore the pause: it costs
/// half a second of recovery time, while a guessed "carry on immediately" burns
/// a core.
#[test]
fn an_unknown_failure_is_answered_with_a_pause() {
    for number in [libc::ENOENT, libc::EINVAL, libc::ENOSYS] {
        assert_eq!(classify(&errno(number)), Fault::Exhausted);
    }
    assert_eq!(
        classify(&std::io::Error::other("something entirely different")),
        Fault::Exhausted
    );
}

/// `EAGAIN` must never lead to a hot loop.
///
/// `tokio` answers it itself and does not let it out — but if it did come out,
/// "carry on immediately" would be exactly the outcome that must not exist here.
#[test]
fn would_block_never_spins() {
    assert_eq!(classify(&errno(libc::EAGAIN)), Fault::Exhausted);
}

/// The pause is not zero, and it bounds **two** things.
///
/// The consumption of a core, and the number of log lines: every failure is
/// reported, so the deadline is at the same time the upper bound of the report
/// rate. A pause of zero would have neither.
#[test]
fn the_pause_is_neither_zero_nor_endless() {
    assert!(tg_syscall::accept::BACKOFF > std::time::Duration::ZERO);
    // Longer than a second would be a recovery time above the shortest deadline
    // of this system (the negative DNS deadline from ADR-0013).
    assert!(tg_syscall::accept::BACKOFF <= std::time::Duration::from_secs(1));
}

/// The pause hangs on the verdict, not on the caller.
///
/// Nine loops in five crates ask the same question; answering it there would be
/// nine opportunities to do it differently.
#[test]
fn only_the_exhausted_case_waits() {
    assert_eq!(Fault::Connection.pause(), None);
    assert_eq!(
        Fault::Exhausted.pause(),
        Some(tg_syscall::accept::BACKOFF),
        "whoever does not wait here spins on a core without achieving anything"
    );
}
