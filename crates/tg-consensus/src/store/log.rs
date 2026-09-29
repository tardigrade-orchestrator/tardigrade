//! `RaftLogStorage` and `RaftLogReader` on `redb`.
//!
//! The three correctness obligations from `openraft`'s trait documentation
//! stand at the centre here, because they are what a hand-built log gets wrong:
//!
//! 1. **No holes.** `truncate` and `purge` cut only at the ends.
//! 2. **Serialized write IO.** Follows here from `&mut self`: `openraft` never
//!    calls two writes at the same time, and `redb` commits in one
//!    transaction.
//! 3. **The vote lies on disk before the return.** Otherwise a node can vote
//!    twice in the same term after a restart.

use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{LogFlushed, LogState, RaftLogReader, RaftLogStorage};
use openraft::{AnyError, LogId, StorageError, StorageIOError, Vote};
use redb::{Database, ReadableDatabase as _, ReadableTable as _};

use crate::config::{NodeId, TypeConfig};
use crate::store::{LOG, META};
use crate::wire;

/// Key of the last stored vote.
const KEY_VOTE: &str = "vote";
/// Key of the last known `committed` pointer.
const KEY_COMMITTED: &str = "committed";
/// Key of the last deleted log entry.
const KEY_PURGED: &str = "purged";

/// The Raft log on `redb`.
pub struct LogStore {
    database: Arc<Database>,
}

impl LogStore {
    pub(crate) fn new(database: Arc<Database>) -> Self {
        Self { database }
    }
}

/// A concurrent reader on the same log.
///
/// `openraft` hands out one of these per replication task; they read in
/// parallel with the writer. `redb` permits that (MVCC), so no lock is needed
/// here — only a second handle.
pub struct LogReader {
    database: Arc<Database>,
}

fn read_error(err: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::read_logs(AnyError::new(&err)).into()
}

fn write_error(err: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::write_logs(AnyError::new(&err)).into()
}

/// Converts arbitrary range bounds into a half-open `[start, end)`.
///
/// `openraft` asks with every form, `redb` wants concrete bounds. The
/// conversion at one place instead of three.
fn bounds(range: &impl RangeBounds<u64>) -> (u64, u64) {
    use std::ops::Bound;

    let start = match range.start_bound() {
        Bound::Included(index) => *index,
        Bound::Excluded(index) => index.saturating_add(1),
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(index) => index.saturating_add(1),
        Bound::Excluded(index) => *index,
        Bound::Unbounded => u64::MAX,
    };

    (start, end.max(start))
}

fn entries_in(
    database: &Database,
    range: &impl RangeBounds<u64>,
) -> Result<Vec<openraft::Entry<TypeConfig>>, StorageError<NodeId>> {
    let (start, end) = bounds(range);

    let txn = database.begin_read().map_err(read_error)?;
    let table = txn.open_table(LOG).map_err(read_error)?;

    let mut entries = Vec::new();
    for row in table.range(start..end).map_err(read_error)? {
        let (_, value) = row.map_err(read_error)?;
        entries.push(wire::decode_entry(value.value()).map_err(read_error)?);
    }

    Ok(entries)
}

fn scalar<T: serde::de::DeserializeOwned>(
    database: &Database,
    key: &str,
) -> Result<Option<T>, StorageError<NodeId>> {
    let txn = database.begin_read().map_err(read_error)?;
    let table = txn.open_table(META).map_err(read_error)?;

    match table.get(key).map_err(read_error)? {
        Some(value) => serde_json::from_slice(value.value())
            .map(Some)
            .map_err(read_error),
        None => Ok(None),
    }
}

fn put_scalar<T: serde::Serialize>(
    database: &Database,
    key: &str,
    value: &T,
) -> Result<(), StorageError<NodeId>> {
    let encoded = serde_json::to_vec(value).map_err(write_error)?;

    let txn = database.begin_write().map_err(write_error)?;
    {
        let mut table = txn.open_table(META).map_err(write_error)?;
        table.insert(key, encoded.as_slice()).map_err(write_error)?;
    }
    txn.commit().map_err(write_error)?;

    Ok(())
}

impl RaftLogReader<TypeConfig> for LogReader {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<openraft::Entry<TypeConfig>>, StorageError<NodeId>> {
        entries_in(&self.database, &range)
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<openraft::Entry<TypeConfig>>, StorageError<NodeId>> {
        entries_in(&self.database, &range)
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = LogReader;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let last_purged_log_id: Option<LogId<NodeId>> = scalar(&self.database, KEY_PURGED)?;

        let txn = self.database.begin_read().map_err(read_error)?;
        let table = txn.open_table(LOG).map_err(read_error)?;
        let last = table.last().map_err(read_error)?;

        // If the log is empty, the last *deleted* entry is the last one this
        // node knows about at all. Returning `None` here would make the node
        // take itself for fresh and have the log sent to it from the start.
        let last_log_id = match last {
            Some((_, value)) => Some(
                wire::decode_entry(value.value())
                    .map_err(read_error)?
                    .log_id,
            ),
            None => last_purged_log_id,
        };

        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        LogReader {
            database: Arc::clone(&self.database),
        }
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        put_scalar(&self.database, KEY_VOTE, vote)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        scalar(&self.database, KEY_VOTE)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        put_scalar(&self.database, KEY_COMMITTED, &committed)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(scalar::<Option<LogId<NodeId>>>(&self.database, KEY_COMMITTED)?.flatten())
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = openraft::Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let txn = self.database.begin_write().map_err(write_error)?;
        {
            let mut table = txn.open_table(LOG).map_err(write_error)?;
            for entry in entries {
                let encoded = wire::encode_entry(&entry).map_err(write_error)?;
                table
                    .insert(entry.log_id.index, encoded.as_slice())
                    .map_err(write_error)?;
            }
        }
        txn.commit().map_err(write_error)?;

        // Only after the commit. The callback is `openraft`'s promise to
        // itself that the entries lie on disk — called earlier it would be a
        // lie, and exactly the one that makes a committed entry disappear at a
        // power loss.
        callback.log_io_completed(Ok(()));

        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let txn = self.database.begin_write().map_err(write_error)?;
        {
            let mut table = txn.open_table(LOG).map_err(write_error)?;
            table
                .retain_in(log_id.index.., |_, _| false)
                .map_err(write_error)?;
        }
        txn.commit().map_err(write_error)?;

        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let encoded = serde_json::to_vec(&Some(log_id)).map_err(write_error)?;

        // Pointer and deletion in one transaction: a crash in between would
        // leave either entries before the pointer or — worse — a pointer that
        // gives entries out as present that are gone.
        let txn = self.database.begin_write().map_err(write_error)?;
        {
            let mut table = txn.open_table(LOG).map_err(write_error)?;
            table
                .retain_in(..=log_id.index, |_, _| false)
                .map_err(write_error)?;
        }
        {
            let mut meta = txn.open_table(META).map_err(write_error)?;
            meta.insert(KEY_PURGED, encoded.as_slice())
                .map_err(write_error)?;
        }
        txn.commit().map_err(write_error)?;

        Ok(())
    }
}
