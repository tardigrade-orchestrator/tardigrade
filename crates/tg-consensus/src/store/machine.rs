//! `RaftStateMachine` and snapshots on `redb`.
//!
//! The applied state lies both in memory (for reads without deserialization)
//! and on disk (for the restart). The disk is the truth of these two; memory is
//! an image that arises from it when opening.
//!
//! `openraft` leaves the choice between "the state is durable" and "the
//! snapshot is durable". Chosen is the first, with the rationale in the module
//! head of [`crate::store`]: it makes the start path trivial instead of
//! clever.

use std::io::Cursor;
use std::sync::{Arc, PoisonError, RwLock};

use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{
    AnyError, BasicNode, EntryPayload, LogId, Snapshot, SnapshotMeta, StorageError, StorageIOError,
    StoredMembership,
};
use redb::{Database, ReadableDatabase as _};

use crate::audit::Archive;
use crate::command::Outcome;
use crate::config::{NodeId, TypeConfig};
use crate::state::ClusterState;
use crate::store::{MACHINE, SNAPSHOT};
use crate::wire::{self, SnapshotBody};

/// Key of the applied state.
const KEY_STATE: &str = "state";
/// Key of the `last_applied` pointer.
const KEY_APPLIED: &str = "applied";
/// Key of the last applied membership.
const KEY_MEMBERSHIP: &str = "membership";
/// Key of the snapshot counter.
const KEY_SNAPSHOT_INDEX: &str = "snapshot_index";
/// Key of the stored snapshot.
const KEY_SNAPSHOT: &str = "current";

fn read_error(err: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::read_state_machine(AnyError::new(&err)).into()
}

fn write_error(err: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::write_state_machine(AnyError::new(&err)).into()
}

/// A read handle on the applied state.
///
/// `openraft` 0.9 owns the state machine as soon as `Raft::new` has taken it,
/// and offers no way back (`with_state_machine` exists only in 0.10). Whoever
/// wants to read the state — the API from ADR-0018, the projection from
/// ADR-0030 — therefore needs a handle that is branched off **before** the
/// handover.
///
/// What is to be read here is **durable** by construction: publishing happens
/// only after the transaction is committed. A reader thereby never sees a state
/// a crash would take back.
#[derive(Debug, Clone)]
pub struct StateHandle {
    published: Arc<RwLock<ClusterState>>,
    /// The `traceparent` of the last applied entry (ADR-0133, D4).
    ///
    /// **Beside the state, not in it.** A trace is observation; carried in the
    /// replicated state it would be replicated, snapshotted and could influence
    /// a decision (ADR-0004). It is expressly without consequence: whoever
    /// loses it loses a parent, not an operation.
    trace: Arc<RwLock<Option<String>>>,
}

impl StateHandle {
    /// The last durably applied state.
    ///
    /// A copy: the caller shall be able to take it away without blocking the
    /// machine. A poisoned lock is taken over instead of panicking — pure data
    /// without invariants lies here, and a read path that crashes itself
    /// because of somebody else's crash makes two errors out of one.
    #[must_use]
    pub fn read(&self) -> ClusterState {
        self.published
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The `traceparent` of the last applied entry (ADR-0133, D4).
    ///
    /// `None` means: no trace — the normal case without an OTLP endpoint. The
    /// caller hangs their own span on it, and a missing value costs them only
    /// the parent.
    #[must_use]
    pub fn trace(&self) -> Option<String> {
        self.trace
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The replicated state machine, durable on `redb`.
pub struct StateMachine {
    database: Arc<Database>,
    state: ClusterState,
    /// The published copy for [`StateHandle`]. It never runs ahead of the
    /// state.
    published: Arc<RwLock<ClusterState>>,
    /// The `traceparent` of the last applied entry (ADR-0133).
    trace: Arc<RwLock<Option<String>>>,
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    snapshot_index: u64,
    /// The audit archive (ADR-0020), if one is kept.
    ///
    /// `None` is the test rig: the DST drives five nodes in one process and
    /// wants no five files. In operation `tgd` sets it.
    archive: Option<Archive>,
}

impl StateMachine {
    /// Puts the audit archive under the state machine (ADR-0020).
    ///
    /// Separate from the loading, because the archive is an **operational**
    /// decision: the test rig runs without, `tgd` with. The state machine itself
    /// stays untouched by it — the archive only reads along.
    pub fn with_archive(&mut self, archive: Archive) {
        self.archive = Some(archive);
    }

    /// Loads the last applied state from disk.
    pub(crate) fn load(database: Arc<Database>) -> Result<Self, StorageError<NodeId>> {
        let txn = database.begin_read().map_err(read_error)?;
        let table = txn.open_table(MACHINE).map_err(read_error)?;

        let get = |key: &str| -> Result<Option<Vec<u8>>, StorageError<NodeId>> {
            Ok(table
                .get(key)
                .map_err(read_error)?
                .map(|value| value.value().to_vec()))
        };

        let state = match get(KEY_STATE)? {
            Some(bytes) => wire::decode_state(&bytes).map_err(read_error)?,
            None => ClusterState::default(),
        };
        let last_applied = match get(KEY_APPLIED)? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(read_error)?,
            None => None,
        };
        let last_membership = match get(KEY_MEMBERSHIP)? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(read_error)?,
            None => StoredMembership::default(),
        };
        let snapshot_index = match get(KEY_SNAPSHOT_INDEX)? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(read_error)?,
            None => 0,
        };

        drop(table);
        drop(txn);

        Ok(Self {
            database,
            published: Arc::new(RwLock::new(state.clone())),
            trace: Arc::new(RwLock::new(None)),
            state,
            last_applied,
            last_membership,
            snapshot_index,
            archive: None,
        })
    }

    /// A read handle on the applied state.
    ///
    /// To be branched off before `Raft::new`, otherwise the machine is gone.
    #[must_use]
    pub fn handle(&self) -> StateHandle {
        StateHandle {
            published: Arc::clone(&self.published),
            trace: Arc::clone(&self.trace),
        }
    }

    /// The current replicated state.
    ///
    /// A copy, not a reference: the caller shall be able to take it away
    /// without blocking the machine. At this order of magnitude that is cheaper
    /// than any locking discipline one would otherwise have to document. From
    /// 5d on the projection (`tg-store`) hangs on this.
    #[must_use]
    pub fn state(&self) -> ClusterState {
        self.state.clone()
    }

    /// Writes state, `last_applied` and membership in **one** transaction.
    ///
    /// Written separately a crash could leave a state that is further along
    /// than its pointer — at the next start entries would be applied twice. At
    /// `RemoveWorkload` that does not stand out, at a lease grant it costs an
    /// epoch.
    fn persist(&self) -> Result<(), StorageError<NodeId>> {
        let state = wire::encode_state(&self.state).map_err(write_error)?;
        let applied = serde_json::to_vec(&self.last_applied).map_err(write_error)?;
        let membership = serde_json::to_vec(&self.last_membership).map_err(write_error)?;
        let snapshot_index = serde_json::to_vec(&self.snapshot_index).map_err(write_error)?;

        let txn = self.database.begin_write().map_err(write_error)?;
        {
            let mut table = txn.open_table(MACHINE).map_err(write_error)?;
            table
                .insert(KEY_STATE, state.as_slice())
                .map_err(write_error)?;
            table
                .insert(KEY_APPLIED, applied.as_slice())
                .map_err(write_error)?;
            table
                .insert(KEY_MEMBERSHIP, membership.as_slice())
                .map_err(write_error)?;
            table
                .insert(KEY_SNAPSHOT_INDEX, snapshot_index.as_slice())
                .map_err(write_error)?;
        }
        txn.commit().map_err(write_error)?;

        // Publish only after the commit. The other way round a reader could
        // see a state a crash takes back again right away — and pass it on
        // because they saw it.
        *self
            .published
            .write()
            .unwrap_or_else(PoisonError::into_inner) = self.state.clone();

        Ok(())
    }
}

impl RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotBuilder = SnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        Ok((self.last_applied, self.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Outcome>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = openraft::Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut outcomes = Vec::new();

        for entry in entries {
            self.last_applied = Some(entry.log_id);

            // Exactly one answer per entry, for those that do not come from
            // us too: `Raft::client_write` maps answers by position, a missing
            // one shifts all the following.
            let outcome = match entry.payload {
                EntryPayload::Blank => Outcome::Applied,
                EntryPayload::Normal(submission) => {
                    // **One span per applied entry** (ADR-0133, D3). It is
                    // the start of the only chain neither the log nor the audit
                    // trail delivers: command -> slice -> pass on another
                    // machine. The fields are the same enumerable ones as at
                    // the counter below; a rejection's reason carries names
                    // from the payload and stays out (ADR-0015).
                    let span = tracing::info_span!(
                        "apply",
                        index = entry.log_id.index,
                        term = entry.log_id.leader_id.term,
                        kind = submission.command.kind(),
                        outcome = tracing::field::Empty,
                    );
                    let _entered = span.enter();

                    // **Only the command goes into the state machine.** The
                    // actor is provenance and not part of the decision
                    // (ADR-0050); two nodes still arrive at the same result
                    // (ADR-0004).
                    let outcome = self.state.apply(&submission.command);
                    span.record(
                        "outcome",
                        if matches!(outcome, Outcome::Rejected(_)) {
                            "rejected"
                        } else {
                            "applied"
                        },
                    );

                    // **The note beside the state** (ADR-0133, D4): the slice
                    // that arises next hangs on it. It deliberately does not lie
                    // in `ClusterState` -- a trace is not replicated.
                    *self.trace.write().unwrap_or_else(PoisonError::into_inner) =
                        tg_telemetry::trace::current();

                    // **Before** the return from `apply`, not after: only
                    // thereby can the compaction no longer catch up with the
                    // entry (ADR-0020, open point from phase 5d).
                    //
                    // And **before** `persist()`, which opens a window: if the
                    // process dies in between, the pointer lies back,
                    // `openraft` applies the same entry again at the next start,
                    // and the archive gets it **twice**.
                    //
                    // That is the wanted direction. The other way round — first
                    // persist, then archive — the same crash loses the record
                    // **entirely**, for afterwards the entry is not applied any
                    // more. A duplication is a finding an auditor can resolve; a
                    // gap in the audit trail is one nobody sees any more.
                    //
                    // It is therefore not deduplicated either: it **was**
                    // applied twice, and the archive says what happened.
                    // `a_reapplied_entry_does_not_break_the_chain` records that
                    // the chain carries it — it counts itself and not in log
                    // indices.
                    //
                    // An archive that cannot write is a storage error and no
                    // reason to carry on: otherwise the cluster would run on and
                    // nobody would see that the audit trail has had holes for
                    // hours.
                    if let Some(archive) = self.archive.as_mut() {
                        archive
                            .record(
                                entry.log_id.index,
                                entry.log_id.leader_id.term,
                                &submission,
                                &outcome,
                            )
                            .map_err(write_error)?;
                        metrics::counter!(tg_telemetry::names::AUDIT_RECORDS).increment(1);
                    }

                    // Both labels are enumerable — twenty command kinds
                    // (ADR-0004) and one verdict. A rejection's **reason**
                    // carries names from the payload and therefore belongs in
                    // the log and in the archive, not in a label.
                    metrics::counter!(
                        tg_telemetry::names::APPLIED,
                        "kind" => submission.command.kind(),
                        "outcome" => if matches!(outcome, Outcome::Rejected(_)) {
                            "rejected"
                        } else {
                            "applied"
                        },
                    )
                    .increment(1);

                    outcome
                }
                EntryPayload::Membership(membership) => {
                    self.last_membership = StoredMembership::new(Some(entry.log_id), membership);
                    Outcome::Applied
                }
            };

            outcomes.push(outcome);
        }

        self.persist()?;

        Ok(outcomes)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.snapshot_index += 1;

        SnapshotBuilder {
            database: Arc::clone(&self.database),
            state: self.state.clone(),
            last_applied: self.last_applied,
            last_membership: self.last_membership.clone(),
            snapshot_index: self.snapshot_index,
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let bytes = snapshot.into_inner();
        let body = wire::decode_snapshot(&bytes).map_err(|err| {
            StorageIOError::read_snapshot(Some(meta.signature()), AnyError::new(&err))
        })?;

        // The caller's metadata applies, not the one in the document:
        // `openraft` confirmed it in the protocol, the document is only the
        // payload.
        self.state = body.state;
        self.last_applied = meta.last_log_id;
        self.last_membership = meta.last_membership.clone();

        store_snapshot(&self.database, meta, &bytes)?;
        self.persist()?;

        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let txn = self.database.begin_read().map_err(read_error)?;
        let table = txn.open_table(SNAPSHOT).map_err(read_error)?;

        let Some(value) = table.get(KEY_SNAPSHOT).map_err(read_error)? else {
            return Ok(None);
        };
        let bytes = value.value().to_vec();
        let body = wire::decode_snapshot(&bytes).map_err(read_error)?;

        Ok(Some(Snapshot {
            meta: body.meta,
            snapshot: Box::new(Cursor::new(bytes)),
        }))
    }
}

/// Stores a snapshot.
///
/// Always exactly one: `openraft` expects that after `install_snapshot` all
/// older ones have disappeared. One key instead of a chain of generations makes
/// that a property of the data structure instead of a cleanup task.
fn store_snapshot(
    database: &Database,
    meta: &SnapshotMeta<NodeId, BasicNode>,
    bytes: &[u8],
) -> Result<(), StorageError<NodeId>> {
    let fail = |err: redb::Error| -> StorageError<NodeId> {
        StorageIOError::write_snapshot(Some(meta.signature()), AnyError::new(&err)).into()
    };

    let txn = database
        .begin_write()
        .map_err(|err| fail(redb::Error::from(err)))?;
    {
        let mut table = txn
            .open_table(SNAPSHOT)
            .map_err(|err| fail(redb::Error::from(err)))?;
        table
            .insert(KEY_SNAPSHOT, bytes)
            .map_err(|err| fail(redb::Error::from(err)))?;
    }
    txn.commit().map_err(|err| fail(redb::Error::from(err)))?;

    Ok(())
}

/// Builds a snapshot from a held view of the state.
///
/// The view is a copy that arises when the builder is created. With that later
/// applications do not influence the build in progress — exactly the property
/// `openraft` expects of `get_snapshot_builder`.
pub struct SnapshotBuilder {
    database: Arc<Database>,
    state: ClusterState,
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    snapshot_index: u64,
}

impl RaftSnapshotBuilder<TypeConfig> for SnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let snapshot_id = match &self.last_applied {
            Some(log_id) => format!(
                "{}-{}-{}",
                log_id.leader_id, log_id.index, self.snapshot_index
            ),
            None => format!("--{}", self.snapshot_index),
        };

        let meta = SnapshotMeta {
            last_log_id: self.last_applied,
            last_membership: self.last_membership.clone(),
            snapshot_id,
        };

        let body = SnapshotBody {
            meta: meta.clone(),
            state: self.state.clone(),
        };
        let bytes = wire::encode_snapshot(&body).map_err(|err| {
            StorageIOError::write_snapshot(Some(meta.signature()), AnyError::new(&err))
        })?;

        store_snapshot(&self.database, &meta, &bytes)?;

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(bytes)),
        })
    }
}
