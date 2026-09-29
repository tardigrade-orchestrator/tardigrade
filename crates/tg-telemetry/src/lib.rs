//! tracing/metrics and the audit journal.
//!
//! ADR-0015/0020.
//!
//! Phase 11a fills [`audit`]: the export of the Raft log as a **demonstrably**
//! append-only archive. Tracing and metrics follow in 11b.
//!
//! **Field names are identifiers, not prose.** A field name is what an operator
//! filters on, and it is written like everything tools read — measured, five
//! names once diverged from that, and one of them was the same term as its
//! neighbour in another spelling; whoever filtered on `instance=` found half.
//!
//! There is **no** guard for that, deliberately: a maintained word list would be
//! the construction this tree has measured several times as a source of error.
//! What would be checkable is a declared vocabulary as in [`names`] — with around
//! fifty field names, most of which occur once, that would be ceremony without a
//! return.

#![forbid(unsafe_code)]
// No panic-capable call on the production path (ADR-0082). `not(test)` because
// the unit tests in `src` need them; the guard lies in
// `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod args;
pub mod audit;
pub mod init;
pub mod names;
pub mod probes;
pub mod serve;
pub mod trace;
