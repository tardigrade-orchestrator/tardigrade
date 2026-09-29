//! The Raft cluster's type configuration.
//!
//! `openraft` is parameterized over
//! [`RaftTypeConfig`](openraft::RaftTypeConfig); here it is determined which
//! types this cluster works with. The file is short and nevertheless a
//! determination that is hard to change — it sits in every log entry and every
//! snapshot.

use std::io::Cursor;

use crate::command::{Outcome, Submission};

pub use tg_model::command::NodeId;

openraft::declare_raft_types!(
    pub TypeConfig:
        D = Submission,
        R = Outcome,
        NodeId = NodeId,
        Node = openraft::BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);
