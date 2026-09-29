//! The log and the state machine on disk — one node, no network.
//!
//! Before messages fly between nodes, the storage layer underneath consensus
//! must be right on its own — the Raft operational details are the largest
//! single risk in getting consensus correct, which is why the trait
//! implementations are tested here in isolation, before anything else is
//! built on top of them.
//!
//! The first test below is `openraft`'s own conformance suite. It checks around
//! 35 properties of the two traits that one overlooks in droves when writing
//! them oneself: membership reconstruction from the log **and** the state
//! machine, behaviour at a `purge` beyond the end of the log, log holes,
//! snapshot transfer. It replaces no test of our own, but it is the cheapest
//! assurance to be had.

use std::io::Cursor;

use openraft::storage::{RaftLogStorage, RaftLogStorageExt as _, RaftStateMachine};
use openraft::testing::{StoreBuilder, Suite, log_id};
use openraft::{Entry, EntryPayload, RaftLogReader as _, RaftSnapshotBuilder as _, Vote};
use tg_consensus::{Command, LogStore, NodeId, StateMachine, Storage, Topology, TypeConfig};

type Failure = openraft::StorageError<NodeId>;

/// Builds a fresh database per test case in a throwaway directory.
struct TempStore;

impl StoreBuilder<TypeConfig, LogStore, StateMachine, tempfile::TempDir> for TempStore {
    /// Opens a fresh, empty log and state machine in a throwaway directory.
    ///
    /// # Returns
    /// The backing directory (kept alive so it is not deleted early), the log
    /// storage, and the state machine.
    ///
    /// # Errors
    /// Returns an error if the temporary directory cannot be created or the
    /// database cannot be opened.
    async fn build(&self) -> Result<(tempfile::TempDir, LogStore, StateMachine), Failure> {
        let dir = tempfile::tempdir()
            .map_err(|err| openraft::StorageIOError::write(openraft::AnyError::new(&err)))?;
        let storage = Storage::open(dir.path().join("raft.redb"))?;

        Ok((dir, storage.log, storage.machine))
    }
}

/// `openraft`'s conformance suite against our `redb` implementation.
///
/// No `#[tokio::test]`: `Suite` builds itself a runtime of its own for every
/// case, an outer one would be nested and would panic.
#[test]
fn the_openraft_conformance_suite_passes() {
    Suite::test_all(TempStore).expect("conformance suite");
}

/// Builds a normal log entry carrying a command payload.
///
/// # Parameters
/// - `term`: the Raft term of the entry.
/// - `index`: the log index of the entry.
/// - `command`: the command to wrap as the entry's payload.
///
/// # Returns
/// The entry, ready to append to the log.
fn normal(term: u64, index: u64, command: Command) -> Entry<TypeConfig> {
    Entry {
        log_id: log_id(term, 1, index),
        payload: EntryPayload::Normal(command.into()),
    }
}

/// Builds an XML workload document, optionally with a workload `class`
/// attribute.
///
/// # Parameters
/// - `name`: the workload name.
/// - `class`: the workload's class attribute, if any.
///
/// # Returns
/// The XML document as a string.
fn document(name: &str, class: Option<&str>) -> String {
    let class = class.map_or(String::new(), |c| format!(" class=\"{c}\""));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\"{class}>\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

/// A small sequence of commands that touches every layer of desired state:
/// workload definitions, node topology, placement, and traffic authorization.
///
/// # Returns
/// The commands, in application order.
fn script() -> Vec<Command> {
    vec![
        Command::UpsertWorkload {
            document: document("api", None),
        },
        Command::UpsertWorkload {
            document: document("ledger", Some("single-writer")),
        },
        Command::UpsertNode {
            name: "node-1".to_owned(),
            topology: Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r7".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
        Command::AssignPlacement {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        },
        Command::AllowTraffic {
            from: "api".to_owned(),
            to: "ledger".to_owned(),
        },
    ]
}

/// Builds the log entries for [`script`], indexed consecutively from 1.
///
/// # Returns
/// The entries, in application order.
fn entries() -> Vec<Entry<TypeConfig>> {
    script()
        .into_iter()
        .enumerate()
        .map(|(index, command)| {
            let index = u64::try_from(index).expect("fits");
            normal(1, index + 1, command)
        })
        .collect()
}

/// **Apply and restart.** The applied state lies on disk, not in memory —
/// after the restart it is there again without a replay, and the `last_applied`
/// pointer is right. If the pointer stands wrongly, Raft applies entries twice
/// at startup.
#[tokio::test]
async fn applied_state_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft.redb");

    let expected = {
        let mut storage = Storage::open(&path).expect("open");
        storage.machine.apply(entries()).await.expect("apply");

        let (applied, _) = storage
            .machine
            .applied_state()
            .await
            .expect("applied_state");
        assert_eq!(applied, Some(log_id(1, 1, 5)));

        storage.machine.state()
    };

    let mut storage = Storage::open(&path).expect("reopen");
    let (applied, _) = storage
        .machine
        .applied_state()
        .await
        .expect("applied_state");

    assert_eq!(applied, Some(log_id(1, 1, 5)));
    assert_eq!(storage.machine.state(), expected);
    assert_eq!(storage.machine.state().placement("ledger"), Some("node-1"));
}

/// **Restart from the log.** The case this is actually about: the process dies
/// after three of five entries are applied. After the start it reads the rest
/// from the log and applies it — the result must equal the run without a crash.
/// Exactly that Raft does when coming up.
#[tokio::test]
async fn a_restart_replays_the_rest_of_the_log() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Reference: everything in one go.
    let reference = {
        let mut storage = Storage::open(dir.path().join("reference.redb")).expect("open");
        storage
            .log
            .blocking_append(entries())
            .await
            .expect("append");
        storage.machine.apply(entries()).await.expect("apply");
        storage.machine.state()
    };

    let path = dir.path().join("crashed.redb");
    {
        let mut storage = Storage::open(&path).expect("open");
        storage
            .log
            .blocking_append(entries())
            .await
            .expect("append");
        storage
            .machine
            .apply(entries().into_iter().take(3))
            .await
            .expect("apply partially");
    }

    let mut storage = Storage::open(&path).expect("reopen");
    let (applied, _) = storage
        .machine
        .applied_state()
        .await
        .expect("applied_state");
    let resume = applied.map_or(0, |id| id.index + 1);
    assert_eq!(resume, 4, "three entries were applied");

    let rest = storage
        .log
        .try_get_log_entries(resume..)
        .await
        .expect("the rest from the log");
    assert_eq!(rest.len(), 2);
    storage.machine.apply(rest).await.expect("apply the rest");

    assert_eq!(storage.machine.state(), reference);
}

/// The log itself survives the restart: entries, vote and the two pointers. The
/// vote is the part whose loss makes a split-brain possible — it must lie on
/// disk before the return from `save_vote`.
#[tokio::test]
async fn the_log_and_the_vote_survive_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft.redb");
    let vote = Vote::new(3, 2);

    {
        let mut storage = Storage::open(&path).expect("open");
        storage
            .log
            .blocking_append(entries())
            .await
            .expect("append");
        storage.log.save_vote(&vote).await.expect("write the vote");
        storage
            .log
            .save_committed(Some(log_id(1, 1, 4)))
            .await
            .expect("write committed");
    }

    let mut storage = Storage::open(&path).expect("reopen");

    let state = storage.log.get_log_state().await.expect("log_state");
    assert_eq!(state.last_log_id, Some(log_id(1, 1, 5)));
    assert_eq!(state.last_purged_log_id, None);
    assert_eq!(
        storage.log.read_vote().await.expect("read the vote"),
        Some(vote)
    );
    assert_eq!(
        storage.log.read_committed().await.expect("read committed"),
        Some(log_id(1, 1, 4))
    );

    let read = storage
        .log
        .try_get_log_entries(1..6)
        .await
        .expect("read the entries");
    assert_eq!(read.len(), 5);
    assert_eq!(read[0].log_id, log_id(1, 1, 1));
}

/// `purge` and `truncate` are durable. If they were not, deleted entries would
/// reappear after a restart — a hole in the log that Raft expressly does not
/// tolerate.
#[tokio::test]
async fn purge_and_truncate_survive_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft.redb");

    {
        let mut storage = Storage::open(&path).expect("open");
        storage
            .log
            .blocking_append(entries())
            .await
            .expect("append");
        storage
            .log
            .truncate(log_id(1, 1, 5))
            .await
            .expect("truncate");
        storage.log.purge(log_id(1, 1, 2)).await.expect("purge");
    }

    let mut storage = Storage::open(&path).expect("reopen");
    let state = storage.log.get_log_state().await.expect("log_state");

    assert_eq!(state.last_purged_log_id, Some(log_id(1, 1, 2)));
    assert_eq!(state.last_log_id, Some(log_id(1, 1, 4)));

    let read = storage
        .log
        .try_get_log_entries(1..6)
        .await
        .expect("read the entries");
    assert_eq!(read.len(), 2, "only the indices 3 and 4 are left");
}

/// **Snapshot and restore.** One node builds a snapshot, a completely empty
/// second one installs it and afterwards has the same state — including
/// `last_applied` and membership. That is the way a newly added node catches
/// up.
#[tokio::test]
async fn a_snapshot_carries_the_whole_state_to_an_empty_node() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut source = Storage::open(dir.path().join("source.redb")).expect("open");
    source
        .machine
        .apply([Entry {
            log_id: log_id(1, 1, 1),
            payload: EntryPayload::Membership(openraft::Membership::new(
                vec![[1, 2, 3].into_iter().collect()],
                (),
            )),
        }])
        .await
        .expect("apply the membership");
    source
        .machine
        .apply(
            script()
                .into_iter()
                .enumerate()
                .map(|(index, command)| {
                    let index = u64::try_from(index).expect("fits");
                    normal(1, index + 2, command)
                })
                .collect::<Vec<_>>(),
        )
        .await
        .expect("apply");

    let snapshot = source
        .machine
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("build the snapshot");

    // A snapshot read back is the same one.
    let current = source
        .machine
        .get_current_snapshot()
        .await
        .expect("current snapshot")
        .expect("present");
    assert_eq!(current.meta, snapshot.meta);

    let mut target = Storage::open(dir.path().join("target.redb")).expect("open");
    assert_eq!(
        target.machine.state(),
        tg_consensus::ClusterState::default()
    );

    let mut received = target
        .machine
        .begin_receiving_snapshot()
        .await
        .expect("begin receiving");
    *received = Cursor::new(current.snapshot.into_inner());
    target
        .machine
        .install_snapshot(&current.meta, received)
        .await
        .expect("install");

    assert_eq!(target.machine.state(), source.machine.state());

    let (applied, membership) = target.machine.applied_state().await.expect("applied_state");
    assert_eq!(applied, Some(log_id(1, 1, 6)));
    assert_eq!(
        membership.membership(),
        &openraft::Membership::new(vec![[1, 2, 3].into_iter().collect()], None)
    );
}

/// The installed snapshot stays the current one after a restart too —
/// otherwise a node that has caught up would have to catch up again at the next
/// start.
#[tokio::test]
async fn an_installed_snapshot_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft.redb");

    let (meta, state) = {
        let mut storage = Storage::open(&path).expect("open");
        storage.machine.apply(entries()).await.expect("apply");
        let snapshot = storage
            .machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("build");
        (snapshot.meta, storage.machine.state())
    };

    let mut storage = Storage::open(&path).expect("reopen");
    let current = storage
        .machine
        .get_current_snapshot()
        .await
        .expect("read")
        .expect("present");

    assert_eq!(current.meta, meta);
    assert_eq!(storage.machine.state(), state);
}

/// Every entry gets exactly one answer — the blank ones and the membership
/// entries `openraft` produces itself too. `Raft::client_write` maps answers by
/// position; a missing answer shifts all the following ones.
#[tokio::test]
async fn every_entry_yields_exactly_one_response() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");

    let mixed = vec![
        Entry {
            log_id: log_id(1, 1, 1),
            payload: EntryPayload::Blank,
        },
        Entry {
            log_id: log_id(1, 1, 2),
            payload: EntryPayload::Membership(openraft::Membership::new(
                vec![[1, 2].into_iter().collect()],
                (),
            )),
        },
        normal(
            1,
            3,
            Command::UpsertWorkload {
                document: document("api", None),
            },
        ),
    ];

    let responses = storage.machine.apply(mixed).await.expect("apply");
    assert_eq!(responses.len(), 3);
}
