//! How many descriptors this process holds, and how many it may hold.
//!
//! If a process of this system runs out of descriptors, **no listener accepts
//! any more** — each then waits and reports it ([`crate::accept`]), but none
//! works. And nothing about it was observable: the report comes once it has
//! happened, and a number saying how close it is did not exist. The same
//! situation as with a failure domain's reserve before ADR-0047 — a bit has no
//! "almost".
//!
//! The agent holds one descriptor per connected workload (the SVID stream from
//! ADR-0035 stays open), one per open DNS forward, plus netlink, `nft` and the
//! session. Many distributions default to 1024; whether that suffices is a
//! question for operations — and for that it needs the two numbers, not a
//! verdict.
//!
//! Two raw numbers, no ratio — the same choice as with
//! `tg_scheduler_domain_at_risk`/`…_elsewhere` (ADR-0047): the division is the
//! alerting system's job, and a ratio would hide whether the limit is high or
//! the consumption wrong.

use std::path::Path;

const FD_DIR: &str = "/proc/self/fd";

#[must_use]
pub fn open() -> Option<u64> {
    let entries = std::fs::read_dir(Path::new(FD_DIR)).ok()?;
    u64::try_from(entries.count()).ok()
}

#[must_use]
pub fn limit() -> Option<u64> {
    rustix::process::getrlimit(rustix::process::Resource::Nofile).current
}
