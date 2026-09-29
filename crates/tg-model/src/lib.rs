//! Domain model: workloads, dependency graph, desired/actual, autonomy rules.
//!
//! The dependency graph ([`graph`]) takes a parsed definition from `tg-defs`
//! and validates it beyond what an XSD can do — referential integrity and
//! freedom from cycles are properties of the **set** of all workloads, not of
//! a single one — and answers from it the reconciler's questions: in what
//! order is it started, and what has to be stopped along with it.
//!
//! The autonomy boundary ([`autonomy`]) enumerates which actions an agent may
//! carry out without quorum.
//!
//! Placement ([`placement`]) is declarative-explicit: constraints filter, a
//! written-down rule decides, and what is running is never moved unbidden.
//!
//! The sidecar derivation ([`mesh`]) gives a mesh member a **unit of its
//! own** in the same graph, with `bindsTo` and `after` on its workload.

#![forbid(unsafe_code)]
// No panic-capable call in the production path: a panic costs its task and
// not the node -- and that is a state an operator sees only at a metric.
// `not(test)`, because the unit tests in `src` need them; the guard lies in
// `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod autonomy;
pub mod capacity;
pub mod command;
pub mod egress;
pub mod graph;
pub mod keys;
pub mod lease;
pub mod mesh;
pub mod names;
pub mod network;
pub mod placement;
pub mod rollout;
pub mod secrets;
pub mod storage;

pub use crate::autonomy::{Action, Quorum, Verdict};
pub use crate::graph::{DependencyGraph, GraphError, Inactivity, Lint};
pub use crate::keys::{Generations, KeyKind, RotationPolicy};
pub use crate::mesh::{MeshError, SidecarSpec};
pub use crate::placement::{
    Assignment, Attachment, Demand, Node, PlacementError, Plan, Resources, Schedulability, Topology,
};
