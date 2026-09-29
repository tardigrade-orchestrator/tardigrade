//! What a failure to accept a connection means.
//!
//! Every service of this system that holds a port has the same loop: accept,
//! hand off, accept again. What was missing is the answer to what a **failure**
//! of the accept may cost — measured, it was answered in nine places in three
//! different ways:
//!
//! | Loop | before | consequence |
//! |---|---|---|
//! | `tg_net::resolver::serve_udp`/`serve_tcp` | `?` | the node's DNS **ends**, and the caller discarded the error |
//! | `tg_proxy::egress::serve` | `?` | no way out any more |
//! | `tg_telemetry::serve::serve_on` | `?` | metrics **and** the liveness probe gone |
//! | the three loops in `tg_proxy::sidecar` | `continue` | hot loop on a shard core |
//! | `tgd::cluster::accept` | error passed to `tonic` | hot loop, reported at `trace` |
//! | `tg_identity::workload_api::incoming` | `accepted.ok()?` | hot loop, not reported at all |
//!
//! Both ends are wrong, measurably. A single `EMFILE` ended the resolver for the
//! agent's lifetime — every container of the node loses name resolution
//! (ADR-0013), and nobody wrote a word about it. And `continue` without a pause
//! is not a mitigation but the other half of the error: measured, `accept` does
//! **not** consume the waiting connection, returns the same error immediately on
//! the next attempt, and the loop spins at full speed — on a thread-per-core
//! sidecar that is one core and the tail target from ADR-0022.
//!
//! **No ADR of its own.** No decision is changed here, an existing one is
//! redeemed: ADR-0013 makes the resolver per node "because of failure
//! decoupling", ADR-0019 says a node carries on, and ADR-0062 has already
//! decided the form. The rule stood in the tree one loop further on
//! (`tgd::cluster::accept`: "a failed handshake does **not** end the port"); it
//! was merely never applied to the failure of the accept itself.
//!
//! It lies here because the distinction demands `errno` and this is the crate
//! that knows the kernel (ADR-0002). Measured, `EMFILE`, `ENFILE` and `ENOBUFS`
//! have **no name** on `stable` in [`std::io::ErrorKind`], and five copies would
//! be the source of error this project has already paid for with the three JSON
//! codecs (`tg-wire`). This file contains no `unsafe`, as [`crate::lock`] does
//! not either.

use std::time::Duration;

use rustix::io::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    Connection,
    Exhausted,
}

impl Fault {
    #[must_use]
    pub const fn pause(self) -> Option<Duration> {
        match self {
            Self::Connection => None,
            Self::Exhausted => Some(BACKOFF),
        }
    }
}

pub const BACKOFF: Duration = Duration::from_millis(500);

#[must_use]
pub fn classify(error: &std::io::Error) -> Fault {
    use std::io::ErrorKind as Kind;

    // `errno` first, because the three cases at issue have no name on `stable`
    // (see the module header).
    if let Some(number) = error.raw_os_error()
        && [Errno::MFILE, Errno::NFILE, Errno::NOBUFS]
            .iter()
            .any(|errno| errno.raw_os_error() == number)
    {
        return Fault::Exhausted;
    }

    match error.kind() {
        // Everything that tells of **one** connection: the client is gone
        // (`ECONNABORTED`, `ECONNRESET`, `ECONNREFUSED`, `ENOTCONN`), the host's
        // packet filter discarded it (`EPERM`), a signal intervened (`EINTR`),
        // or the way there no longer carries.
        Kind::ConnectionAborted
        | Kind::ConnectionReset
        | Kind::ConnectionRefused
        | Kind::NotConnected
        | Kind::BrokenPipe
        | Kind::TimedOut
        | Kind::Interrupted
        | Kind::PermissionDenied
        | Kind::HostUnreachable
        | Kind::NetworkUnreachable => Fault::Connection,
        // Here fall `ENOMEM` (`OutOfMemory`), `ENETDOWN` (`NetworkDown`),
        // `EAGAIN` (`WouldBlock`, which `tokio` does not let out) and everything
        // unknown. For none of them is "carry on immediately" right.
        _ => Fault::Exhausted,
    }
}
