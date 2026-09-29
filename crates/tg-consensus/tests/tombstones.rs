//! How a tombstone disappears again (ADR-0104).
//!
//! ADR-0042 built it and left its lifetime open; the note read "couples to
//! ADR-0020". **Measured, that is the wrong coupling:** the record is the
//! `DeleteVolume` entry in the log, and that stays anyway. What lies in the state
//! is the not yet executed **instruction** — and that lives until it is executed.
//!
//! What a tombstone *is* and when it *arises* is checked by `storage_ingest.rs`.
//! Here stands only the end.

use tg_consensus::{ClusterState, Command, Outcome};

fn delete(volume: &str, node: &str) -> Command {
    Command::DeleteVolume {
        volume: volume.to_owned(),
        node: node.to_owned(),
        at: 1_700_000_000,
    }
}

fn retire(volume: &str, node: &str) -> Command {
    Command::RetireTombstone {
        volume: volume.to_owned(),
        node: node.to_owned(),
    }
}

/// **The execution clears the instruction away.**
///
/// That is ADR-0104's statement: a tombstone lives until the node has reported
/// that it executed it — and not until a deadline runs out. A deadline would
/// leave the data lying on a node that was away for a week while the cluster
/// considers it deleted.
#[test]
fn a_retired_tombstone_leaves_the_state() {
    let mut state = ClusterState::default();
    assert_eq!(state.apply(&delete("data", "node-1")), Outcome::Applied);
    assert_eq!(
        state.deleted_volumes(),
        vec![("node-1", vec!["data"])],
        "the tombstone must stand there to begin with"
    );

    assert_eq!(state.apply(&retire("data", "node-1")), Outcome::Applied);
    assert!(
        state.deleted_volumes().is_empty(),
        "after the execution the instruction is settled: {:?}",
        state.deleted_volumes()
    );
}

/// **And only its own.** A node reports about itself, not about another.
#[test]
fn retiring_on_one_node_leaves_the_other_alone() {
    let mut state = ClusterState::default();
    state.apply(&delete("data", "node-1"));
    state.apply(&delete("data", "node-2"));

    assert_eq!(state.apply(&retire("data", "node-1")), Outcome::Applied);

    assert_eq!(
        state.deleted_volumes(),
        vec![("node-2", vec!["data"])],
        "node-2's tombstone belongs to node-2"
    );
}

/// **And only the reported volume.**
#[test]
fn retiring_one_volume_leaves_the_siblings() {
    let mut state = ClusterState::default();
    state.apply(&delete("data", "node-1"));
    state.apply(&delete("archive", "node-1"));

    state.apply(&retire("data", "node-1"));

    assert_eq!(state.deleted_volumes(), vec![("node-1", vec!["archive"])]);
}

/// **Idempotent** (rule 1): what does not exist is settled.
///
/// Two leaders writing shortly after one another cost one entry and nothing else
/// — and a node that reports the same execution twice likewise.
#[test]
fn retiring_a_tombstone_that_is_gone_is_done() {
    let mut state = ClusterState::default();
    assert_eq!(
        state.apply(&retire("never-existed", "node-1")),
        Outcome::Applied
    );
    assert_eq!(
        state.apply(&retire("never-existed", "node-9")),
        Outcome::Applied
    );
    assert!(state.deleted_volumes().is_empty());
}

/// **An execution leaves no empty node entry behind.**
///
/// The counter-check to the map below: without `retain`, `deleted_volumes` would
/// keep growing — only with empty sets instead of names, and that would be the
/// same unbounded collection with a different content.
#[test]
fn retiring_the_last_tombstone_takes_the_node_entry() {
    let mut state = ClusterState::default();
    state.apply(&delete("data", "node-1"));
    state.apply(&retire("data", "node-1"));

    let wire = serde_json::to_string(&state).expect("serializable");
    assert!(
        !wire.contains("node-1"),
        "an empty entry is the same growing collection: {wire}"
    );
}

/// **`RemoveNode` takes its tombstones with it** (ADR-0104, determination 5).
///
/// Without that there would be a tombstone **nobody can execute any more**: the
/// node is gone, so it never reports, and the instruction would stand forever in
/// the state and in every snapshot. The same rationale as with the key and
/// snapshot generations beside it.
#[test]
fn removing_a_node_takes_its_tombstones() {
    let mut state = ClusterState::default();
    state.apply(&delete("data", "node-1"));
    state.apply(&delete("data", "node-2"));

    assert_eq!(
        state.apply(&Command::RemoveNode {
            name: "node-1".to_owned()
        }),
        Outcome::Applied
    );

    assert_eq!(
        state.deleted_volumes(),
        vec![("node-2", vec!["data"])],
        "the tombstones of a removed node stay lying"
    );
}

/// **A policy may write the execution** (ADR-0104, determination 4) — and
/// expressly not the deletion itself (ADR-0027).
///
/// Without the second half a list that permits everything would be just as
/// green.
#[test]
fn retiring_is_an_allowed_policy_and_deleting_is_not() {
    assert!(retire("data", "node-1").may_be_policy());
    assert!(
        !delete("data", "node-1").may_be_policy(),
        "deleting is decreed by a human (ADR-0027)"
    );
}
