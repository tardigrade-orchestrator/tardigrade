//! The wire format of log entries, commands and snapshots.
//!
//! Why this is a module of its own and public, and not hidden in the storage
//! layer: per ADR-0020 the Raft log is the tamper-evident audit substrate with
//! a retention obligation, and the retention outlives every version of this
//! program. A format that exists only as a private detail of a `redb` adapter
//! one cannot export and cannot check.
//!
//! Chosen is **JSON**: slower than a binary format and larger, but readable
//! without our binary. For an auditor that is the difference between a proof
//! and a claim. The log grows with the control plane's consensus rounds, not
//! with workload traffic (ADR-0019) — the data rate justifies no tighter
//! format.

use serde::{Deserialize, Serialize};

use crate::command::Command;
use crate::config::TypeConfig;
use crate::state::ClusterState;

pub type Entry = openraft::Entry<TypeConfig>;

#[derive(Debug)]
pub struct WireError {
    what: &'static str,
    detail: String,
}

impl WireError {
    fn new(what: &'static str, source: &serde_json::Error) -> Self {
        Self {
            what,
            detail: source.to_string(),
        }
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is not in the expected format: {}",
            self.what, self.detail
        )
    }
}

impl std::error::Error for WireError {}

pub fn encode_command(command: &Command) -> Result<String, WireError> {
    serde_json::to_string(command).map_err(|err| WireError::new("command", &err))
}

pub fn decode_command(json: &str) -> Result<Command, WireError> {
    serde_json::from_str(json).map_err(|err| WireError::new("command", &err))
}

pub fn encode_entry(entry: &Entry) -> Result<Vec<u8>, WireError> {
    serde_json::to_vec(entry).map_err(|err| WireError::new("log entry", &err))
}

pub fn decode_entry(bytes: &[u8]) -> Result<Entry, WireError> {
    serde_json::from_slice(bytes).map_err(|err| WireError::new("log entry", &err))
}

pub fn encode_state(state: &ClusterState) -> Result<Vec<u8>, WireError> {
    serde_json::to_vec(state).map_err(|err| WireError::new("state", &err))
}

pub fn decode_state(bytes: &[u8]) -> Result<ClusterState, WireError> {
    serde_json::from_slice(bytes).map_err(|err| WireError::new("state", &err))
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SnapshotBody {
    pub(crate) meta: openraft::SnapshotMeta<crate::config::NodeId, openraft::BasicNode>,
    pub(crate) state: ClusterState,
}

pub(crate) fn encode_snapshot(body: &SnapshotBody) -> Result<Vec<u8>, WireError> {
    serde_json::to_vec(body).map_err(|err| WireError::new("snapshot", &err))
}

pub(crate) fn decode_snapshot(bytes: &[u8]) -> Result<SnapshotBody, WireError> {
    serde_json::from_slice(bytes).map_err(|err| WireError::new("snapshot", &err))
}
