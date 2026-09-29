//! The log and the state machine on `redb`.
//!
//! ADR-0032 gives the reason for the choice: the Raft log is the truth
//! (ADR-0005) and at the same time the audit substrate (ADR-0020), it must be
//! durable — and a crash-safe on-disk format is exactly the kind of problem one
//! does not solve on the side. The caveat from ADR-0030 applies verbatim: "if
//! persistence should be needed later after all, `redb` is to be taken. **Do
//! not write it yourself.**"
//!
//! # One file, four tables
//!
//! The log and the state machine are two objects for `openraft`, but one file
//! here. That is no thrift: they must survive a common crash without one half
//! being further along than the other.
//!
//! - `raft_log` — index → entry.
//! - `raft_meta` — vote, `committed`, `last_purged`.
//! - `machine` — state, `last_applied`, membership, snapshot counter.
//! - `snapshot` — the last snapshot.
//!
//! # What durable means here
//!
//! Every write is a committed `redb` transaction before the function returns.
//! `openraft` demands that expressly for the vote ("must be persisted on disk
//! before returning") — a lost vote is a possible double election in the same
//! term, that is, split-brain.
//!
//! The machine's state is written whole at **every** `apply`. That is O(state)
//! per application and thereby the most expensive decision in this file. It was
//! taken deliberately: the alternative — persisting only snapshots and
//! replaying the log at startup — moves correctness into a start path that runs
//! rarely and is therefore rarely right. The write rate here is that of
//! control-plane mutations, not that of workload traffic (ADR-0019).

// `openraft`'s `StorageError` is large (224 bytes) and stands in every
// signature of the two traits. Boxing is no option, the signatures are foreign
// — and an error class of our own in front of it would be a translation layer
// that loses information in the error case. The lint therefore applies here to
// the whole storage layer and is switched off once instead of at fourteen
// places.
#![allow(clippy::result_large_err)]

mod log;
mod machine;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use redb::{Database, TableDefinition};

pub use crate::store::log::{LogReader, LogStore};
pub use crate::store::machine::{SnapshotBuilder, StateHandle, StateMachine};

/// Index → encoded log entry.
const LOG: TableDefinition<'static, u64, &[u8]> = TableDefinition::new("raft_log");
/// The log's scalars: vote, `committed`, `last_purged`.
const META: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("raft_meta");
/// The state machine's scalars.
const MACHINE: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("machine");
/// The last snapshot.
const SNAPSHOT: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("snapshot");

/// Both halves of the persistence, on one file.
///
/// `openraft` takes them separately in `Raft::new`; here they arise together,
/// so that there is only one file and one version of it.
pub struct Storage {
    /// The log — entries, vote, pointers.
    pub log: LogStore,
    /// The state machine — applied state and snapshots.
    pub machine: StateMachine,
}

impl Storage {
    /// Opens or creates the database under `path`.
    ///
    /// All tables are created in the process, the empty ones too. Otherwise
    /// every read path would have to distinguish "table does not exist" from
    /// "is empty" — two cases for one fact.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the file cannot be opened or created or its structure
    /// cannot be established.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let fail = |detail: String| StoreError {
            path: path.to_path_buf(),
            detail,
        };

        let database = Database::create(path).map_err(|err| fail(err.to_string()))?;

        let txn = database
            .begin_write()
            .map_err(|err| fail(err.to_string()))?;
        {
            txn.open_table(LOG).map_err(|err| fail(err.to_string()))?;
            txn.open_table(META).map_err(|err| fail(err.to_string()))?;
            txn.open_table(MACHINE)
                .map_err(|err| fail(err.to_string()))?;
            txn.open_table(SNAPSHOT)
                .map_err(|err| fail(err.to_string()))?;
        }
        txn.commit().map_err(|err| fail(err.to_string()))?;

        let database = Arc::new(database);
        let machine = StateMachine::load(Arc::clone(&database))
            .map_err(|err| fail(format!("the state is not loadable: {err}")))?;

        Ok(Self {
            log: LogStore::new(database),
            machine,
        })
    }
}

/// The database could not be opened or established.
///
/// Only for the opening: everything afterwards goes over `openraft`'s
/// `StorageError`, because it has to go there anyway.
#[derive(Debug)]
pub struct StoreError {
    /// The file concerned.
    pub path: PathBuf,
    /// The storage layer's message.
    pub detail: String,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the Raft store {} is not usable: {}",
            self.path.display(),
            self.detail
        )
    }
}

impl std::error::Error for StoreError {}

impl From<StoreError> for openraft::StorageError<crate::config::NodeId> {
    fn from(err: StoreError) -> Self {
        openraft::StorageIOError::write(openraft::AnyError::error(err)).into()
    }
}
