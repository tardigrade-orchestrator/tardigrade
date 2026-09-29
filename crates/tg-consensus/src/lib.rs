//! Consensus: log command set, state machine, durable storage.
//!
//! ADR-0005 makes the control plane itself the Raft cluster and calls the Raft
//! operational details "the project's largest single risk item". ADR-0031 sets
//! the size at five nodes with quorum three, ADR-0032 the implementation:
//! `openraft` 0.9.25, the log on `redb`, our own bus for the simulation.
//!
//! # What stands here (phase 5a)
//!
//! - [`Command`] — the log command set along the boundary from ADR-0004. What
//!   an entry is, and what expressly is **not** an entry.
//! - [`ClusterState`] — the state machine. Pure logic, no access to a clock,
//!   randomness or the environment; five nodes with the same log have the same
//!   state.
//! - [`Storage`] — [`LogStore`] and [`StateMachine`] on one `redb` file.
//! - [`wire`] — the wire format, public, because per ADR-0020 the log is
//!   exportable evidence.
//! - [`net`] — the transport over gRPC (phase 5c). It sits on the same trait
//!   level as the test-rig bus from 5b, only with a wire in between.
//!
//! The order is the instruction from ADR-0005 — test the storage and network
//! traits **in isolation early**, before the scheduler and the reconciler build
//! on them — and it is deliberately built against intuition: the test rig
//! before the real network.
//!
//! # What does not stand here yet
//!
//! No membership change, no log compaction, no projection from the log — that
//! is phase 5d. And the transport is **not secured**: see the head of [`net`].
//!
//! # The boundary from ADR-0004, in one sentence
//!
//! What must be linearizable goes through the log; what is high-frequency and
//! observational goes into the projection. The log carries desired state and
//! consensus-critical cluster state, never health and never metrics.

#![forbid(unsafe_code)]
// **No panicking call in the production path** (ADR-0082): since then a panic
// costs its task and not the node -- and that is a state an operator sees only
// at a metric. `not(test)`, because the unit tests in `src` need them; the
// guard lies in `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod audit;
pub use tg_model::command;
pub mod config;
pub mod net;
pub mod schedule;
pub mod state;
pub mod store;
pub mod wire;

pub use tg_identity::join::{generate_token, token_digest};

pub use crate::command::{
    Actor, Attachment, CapacityPolicy, CapacityRule, Class, Command, Epoch, Generations, KeyKind,
    Layer, Origin, Outcome, Rejection, Resources, RotationPolicy, Schedulability, Submission,
    Topology, UtcMillis,
};
pub use crate::config::{NodeId, TypeConfig};
pub use crate::net::{GrpcNetwork, PeerAddrs, PeerDialer, RaftService};
pub use crate::schedule::{Step, step};
pub use crate::state::{ClusterState, Invitation, Lease, NodeEntry, UnderlayEntry, WorkloadEntry};
pub use crate::store::{
    LogReader, LogStore, SnapshotBuilder, StateHandle, StateMachine, Storage, StoreError,
};
