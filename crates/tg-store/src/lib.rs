//! The projection of the desired state as a read model.
//!
//! The division of roles is the crux:
//!
//! - **Raft is the truth** for desired state and consensus-critical cluster
//!   state.
//! - **This crate is the projection** — materialized deterministically per node
//!   from the replicated state, queryable, and expressly **not** the consensus
//!   backend.
//! - **Actual state** (running/crashed, last seen) is written here directly by
//!   the agents: high-frequency, observational, without a need for
//!   linearizability.
//!
//! From that follows this crate's most important property: **it must contain
//! nothing whose loss hurts.** The projection is rebuildable from the truth at
//! any time. If it is lost, that is a rebuild and not data loss — and therefore
//! an agent may carry on without it.
//!
//! Dependencies lie as edges per kind, not as foreign-key fields — the
//! separation between ordering and requirement axes is thereby preserved in
//! the view too.
//!
//! The projection first ran on an embedded `SurrealDB`. That supplied 292 of
//! the workspace's 566 crates, stood under BSL 1.1 — and was read by nothing.
//! Since `tg-model` answers the hard graph questions anyway and the view is
//! throwaway by design, it now lies in a `BTreeMap`. Should persistence ever
//! be needed: `redb` (3 crates), no home-grown storage layer.

#![forbid(unsafe_code)]
// No panic-capable call is permitted on the production path: the projection
// must stay usable even under an unexpected input. `not(test)` because the
// unit tests in `src` need them; the guard lies in
// `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod projection;
pub mod session;

pub use crate::projection::{ActualStatus, Projection, WorkloadRecord};
