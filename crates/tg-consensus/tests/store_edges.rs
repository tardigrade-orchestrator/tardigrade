//! The edges of the storage layer: error paths and empty cases.
//!
//! `tests/store.rs` checks the way that goes well and lets `openraft`'s
//! conformance suite run over it. Here stands what happens when it does not go
//! well — a file that cannot be opened, a snapshot that is none, a range
//! request that points into the void.
//!
//! The reason for checking that separately: the storage layer is the place at
//! which an error can stay **silent**. A read error that passes through as an
//! empty result looks like an empty log — and a node that takes itself for
//! empty has the whole log sent to it anew.

use std::io::Cursor;

use openraft::storage::{RaftLogStorage, RaftLogStorageExt as _, RaftStateMachine};
use openraft::testing::log_id;
use openraft::{
    BasicNode, Entry, EntryPayload, RaftLogReader as _, RaftSnapshotBuilder as _, SnapshotMeta,
    StoredMembership, Vote,
};
use tg_consensus::{Command, NodeId, Storage, StoreError, TypeConfig};

/// Opens and expects an error.
///
/// By hand instead of with `expect_err`: `Storage` carries no `Debug` — it
/// holds database handles whose output helps nobody in the error case.
fn open_error(path: &std::path::Path) -> StoreError {
    match Storage::open(path) {
        Ok(_) => panic!("{} should not have been openable", path.display()),
        Err(err) => err,
    }
}

fn document(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\">\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

fn normal(index: u64, command: Command) -> Entry<TypeConfig> {
    Entry {
        log_id: log_id(1, 1, index),
        payload: EntryPayload::Normal(command.into()),
    }
}

fn upsert_entries(count: u64) -> Vec<Entry<TypeConfig>> {
    (1..=count)
        .map(|index| {
            normal(
                index,
                Command::UpsertWorkload {
                    document: document(&format!("w{index}")),
                },
            )
        })
        .collect()
}

// --- Opening ----------------------------------------------------------------

/// A path that is a directory yields a named error — no panic and no empty
/// store.
///
/// The error names the path: `tgd` starts with a configured data directory, and
/// "does not work" without saying which file is worthless in operation.
#[test]
fn opening_an_unusable_path_names_the_path() {
    let dir = tempfile::tempdir().expect("tempdir");

    let err = open_error(dir.path());

    assert_eq!(err.path, dir.path());
    assert!(!err.detail.is_empty());

    let text = err.to_string();
    assert!(text.contains(&dir.path().display().to_string()), "{text}");
    assert!(text.starts_with("the Raft store "), "{text}");

    let as_dyn: &dyn std::error::Error = &err;
    assert!(as_dyn.source().is_none());
}

/// The opening error converts into `openraft`'s `StorageError` without the
/// message being lost. Otherwise an error without a text would stand in the
/// Raft log.
#[test]
fn an_open_error_converts_into_a_storage_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = open_error(dir.path());
    let detail = err.detail.clone();

    let converted: openraft::StorageError<NodeId> = err.into();
    let text = converted.to_string();

    assert!(text.contains("the Raft store"), "{text}");
    assert!(text.contains(&detail), "{text}");
}

/// A file that does not yet exist is created — and is usable immediately
/// afterwards, without a second step.
#[tokio::test]
async fn a_fresh_store_opens_empty_and_usable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("create");

    let state = storage.log.get_log_state().await.expect("log_state");
    assert_eq!(state.last_log_id, None);
    assert_eq!(state.last_purged_log_id, None);
    assert_eq!(storage.log.read_vote().await.expect("vote"), None);
    assert_eq!(storage.log.read_committed().await.expect("committed"), None);

    let (applied, membership) = storage.machine.applied_state().await.expect("applied");
    assert_eq!(applied, None);
    assert_eq!(membership, StoredMembership::default());
    assert!(storage.machine.state().workloads().is_empty());
    assert!(
        storage
            .machine
            .get_current_snapshot()
            .await
            .expect("snapshot")
            .is_none()
    );
}

// --- Range requests ---------------------------------------------------------

/// Every form of range bound `openraft` asks with hits the same entries — and
/// an empty or reversed range yields nothing instead of panicking.
///
/// The conversion to half-open bounds lies at **one** place in the log; an error
/// in it shifts replication by exactly one entry, and that is the kind of error
/// that stands out only under load.
#[tokio::test]
async fn every_range_form_selects_the_same_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .log
        .blocking_append(upsert_entries(5))
        .await
        .expect("append");

    let indices = |entries: Vec<Entry<TypeConfig>>| -> Vec<u64> {
        entries
            .into_iter()
            .map(|entry| entry.log_id.index)
            .collect()
    };

    assert_eq!(
        indices(storage.log.try_get_log_entries(2..4).await.expect("read")),
        [2, 3]
    );
    assert_eq!(
        indices(storage.log.try_get_log_entries(2..=4).await.expect("read")),
        [2, 3, 4]
    );
    assert_eq!(
        indices(storage.log.try_get_log_entries(..).await.expect("read")),
        [1, 2, 3, 4, 5]
    );
    assert_eq!(
        indices(storage.log.try_get_log_entries(3..).await.expect("read")),
        [3, 4, 5]
    );
    assert_eq!(
        indices(storage.log.try_get_log_entries(..3).await.expect("read")),
        [1, 2]
    );

    // Empty, past the end, and reversed — three times nothing, three times
    // without a panic.
    assert!(
        storage
            .log
            .try_get_log_entries(3..3)
            .await
            .expect("read")
            .is_empty()
    );
    assert!(
        storage
            .log
            .try_get_log_entries(99..200)
            .await
            .expect("read")
            .is_empty()
    );
    // The reversed range is the point of the exercise: `openraft` shall never
    // ask with it, but the conversion must withstand it anyway instead of
    // passing a panic from `redb` through.
    #[allow(clippy::reversed_empty_ranges)]
    let reversed = storage.log.try_get_log_entries(5..2).await.expect("read");
    assert!(reversed.is_empty());
}

/// The concurrent reader sees the same log as the writer.
///
/// `openraft` hands out one per replication task; if it saw a different state,
/// a task would replicate entries that do not exist.
#[tokio::test]
async fn a_concurrent_reader_sees_the_same_log() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .log
        .blocking_append(upsert_entries(3))
        .await
        .expect("append");

    let mut reader = storage.log.get_log_reader().await;

    let direct = storage.log.try_get_log_entries(1..4).await.expect("read");
    let via_reader = reader.try_get_log_entries(1..4).await.expect("read");

    assert_eq!(direct.len(), 3);
    assert_eq!(
        direct.iter().map(|entry| entry.log_id).collect::<Vec<_>>(),
        via_reader
            .iter()
            .map(|entry| entry.log_id)
            .collect::<Vec<_>>()
    );

    // And it also sees what came along after it was handed out.
    storage
        .log
        .blocking_append(vec![normal(
            4,
            Command::RemoveWorkload {
                name: "w1".to_owned(),
            },
        )])
        .await
        .expect("append");
    assert_eq!(
        reader.try_get_log_entries(1..5).await.expect("read").len(),
        4
    );
}

/// A completely purged log reports the last **deleted** entry as the last known
/// one.
///
/// If it returned `None`, the node would take itself for fresh — and would have
/// the whole log sent to it again although it applied it long ago.
#[tokio::test]
async fn a_fully_purged_log_still_knows_where_it_stands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft.redb");

    {
        let mut storage = Storage::open(&path).expect("open");
        storage
            .log
            .blocking_append(upsert_entries(3))
            .await
            .expect("append");
        storage.log.purge(log_id(1, 1, 3)).await.expect("purge");
    }

    let mut storage = Storage::open(&path).expect("reopen");
    let state = storage.log.get_log_state().await.expect("log_state");

    assert_eq!(state.last_purged_log_id, Some(log_id(1, 1, 3)));
    assert_eq!(
        state.last_log_id,
        Some(log_id(1, 1, 3)),
        "the deleted entry is the last known one"
    );
    assert!(
        storage
            .log
            .try_get_log_entries(1..4)
            .await
            .expect("read")
            .is_empty()
    );
}

/// The vote is overwritten, not accumulated — and the last one applies.
#[tokio::test]
async fn the_latest_vote_wins_and_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft.redb");

    {
        let mut storage = Storage::open(&path).expect("open");
        storage
            .log
            .save_vote(&Vote::new(1, 1))
            .await
            .expect("vote 1");
        storage
            .log
            .save_vote(&Vote::new(7, 4))
            .await
            .expect("vote 2");
    }

    let mut storage = Storage::open(&path).expect("reopen");
    assert_eq!(
        storage.log.read_vote().await.expect("read the vote"),
        Some(Vote::new(7, 4))
    );
}

/// `save_committed(None)` is a valid state and comes back as `None` — not as
/// "never written" with different behaviour.
#[tokio::test]
async fn committed_can_be_reset_to_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");

    storage
        .log
        .save_committed(Some(log_id(2, 1, 9)))
        .await
        .expect("write");
    assert_eq!(
        storage.log.read_committed().await.expect("read"),
        Some(log_id(2, 1, 9))
    );

    storage.log.save_committed(None).await.expect("reset");
    assert_eq!(storage.log.read_committed().await.expect("read"), None);
}

// --- Snapshots --------------------------------------------------------------

/// Two snapshots built one after the other carry different identifiers, even
/// when the state has not changed.
///
/// `openraft` distinguishes snapshots by this identifier. Two identical ones
/// would be the same one for the receiver — a transfer it may take for already
/// done.
#[tokio::test]
async fn two_snapshots_of_the_same_state_have_different_ids() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .machine
        .apply(upsert_entries(1))
        .await
        .expect("apply");

    let first = storage
        .machine
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("first snapshot");
    let second = storage
        .machine
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("second snapshot");

    assert_ne!(first.meta.snapshot_id, second.meta.snapshot_id);
    assert_eq!(first.meta.last_log_id, second.meta.last_log_id);

    // The last one built is the current one; older ones do not stay lying.
    let current = storage
        .machine
        .get_current_snapshot()
        .await
        .expect("read")
        .expect("there is one");
    assert_eq!(current.meta.snapshot_id, second.meta.snapshot_id);
}

/// A snapshot over the empty state is valid and has no `last_log_id`. Exactly
/// that one is built by a node that has applied nothing yet.
#[tokio::test]
async fn an_empty_state_yields_a_valid_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");

    let snapshot = storage
        .machine
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("snapshot");

    assert_eq!(snapshot.meta.last_log_id, None);
    assert!(!snapshot.meta.snapshot_id.is_empty());
    assert!(!snapshot.snapshot.into_inner().is_empty());
}

/// An unreadable snapshot is refused — and leaves the machine as it was.
///
/// That is the case in which a node would otherwise diverge silently: had
/// `install_snapshot` touched the state before decoding, half a foreign state
/// would stand there after an aborted catch-up — and the node would take it for
/// its own.
#[tokio::test]
async fn a_corrupt_snapshot_is_rejected_and_changes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .machine
        .apply(upsert_entries(2))
        .await
        .expect("apply");

    let before = storage.machine.state();
    let applied_before = storage.machine.applied_state().await.expect("applied");

    let meta: SnapshotMeta<NodeId, BasicNode> = SnapshotMeta {
        last_log_id: Some(log_id(9, 1, 99)),
        last_membership: StoredMembership::default(),
        snapshot_id: "broken".to_owned(),
    };

    for payload in [
        Vec::new(),
        b"not even JSON".to_vec(),
        b"{\"meta\":null}".to_vec(),
        b"[]".to_vec(),
    ] {
        let err = storage
            .machine
            .install_snapshot(&meta, Box::new(Cursor::new(payload)))
            .await
            .expect_err("unreadable");
        assert!(format!("{err}").contains("snapshot"), "{err}");
    }

    assert_eq!(storage.machine.state(), before);
    assert_eq!(
        storage.machine.applied_state().await.expect("applied"),
        applied_before
    );
}

/// The buffer for an incoming snapshot begins empty. A remainder from a
/// previous transfer would put itself in front of the new document.
#[tokio::test]
async fn the_receiving_buffer_starts_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");

    let first = storage
        .machine
        .begin_receiving_snapshot()
        .await
        .expect("buffer");
    assert!(first.into_inner().is_empty());

    let snapshot = storage
        .machine
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("snapshot");
    storage
        .machine
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .expect("install");

    let second = storage
        .machine
        .begin_receiving_snapshot()
        .await
        .expect("buffer");
    assert!(second.into_inner().is_empty());
}

/// The receiver takes the **caller's** metadata, not the one in the document.
/// `openraft` confirmed it in the protocol; the document is only the payload
/// and comes from the other side.
#[tokio::test]
async fn the_callers_metadata_wins_over_the_documents() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut source = Storage::open(dir.path().join("source.redb")).expect("open");
    source
        .machine
        .apply(upsert_entries(2))
        .await
        .expect("apply");
    let snapshot = source
        .machine
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("snapshot");
    assert_eq!(snapshot.meta.last_log_id, Some(log_id(1, 1, 2)));

    let mut target = Storage::open(dir.path().join("target.redb")).expect("open");
    let claimed: SnapshotMeta<NodeId, BasicNode> = SnapshotMeta {
        last_log_id: Some(log_id(4, 1, 77)),
        last_membership: StoredMembership::new(
            Some(log_id(4, 1, 77)),
            openraft::Membership::new(vec![[1, 2, 3].into_iter().collect()], ()),
        ),
        snapshot_id: snapshot.meta.snapshot_id.clone(),
    };
    target
        .machine
        .install_snapshot(&claimed, snapshot.snapshot)
        .await
        .expect("install");

    let (applied, membership) = target.machine.applied_state().await.expect("applied");
    assert_eq!(applied, Some(log_id(4, 1, 77)));
    assert_eq!(membership, claimed.last_membership);
    assert_eq!(target.machine.state().workloads().len(), 2);
}

/// An empty batch of entries is no error — and writes no answer.
#[tokio::test]
async fn applying_nothing_yields_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");

    let outcomes = storage
        .machine
        .apply(Vec::<Entry<TypeConfig>>::new())
        .await
        .expect("apply");

    assert!(outcomes.is_empty());
    assert_eq!(
        storage.machine.applied_state().await.expect("applied").0,
        None
    );
}
