//! The ingest check for volumes (ADR-0027 — phase 10a).
//!
//! `tg-model` checks a **set** of definitions. The log, however, carries exactly
//! one workload per entry — the set arises only in the state machine. This file
//! checks that it really does arise there.
//!
//! The case that matters is the **time-shifted** one: two workloads that want to
//! write the same volume come as two log entries. Between them lies arbitrarily
//! much time. A check that looks only at the submitted document would let both
//! through — and the conflict would arise only at mount time, in a privileged
//! process, on a node.

use tg_consensus::{ClusterState, Command, Outcome, Rejection};

fn definition(workload: &str, volume: &str, path: &str, mode: &str) -> String {
    let extra = if mode == "readOnly" {
        format!(" source=\"registry.example.com/{volume}:1\"")
    } else {
        " size=\"8388608\"".to_owned()
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"{workload}\" kind=\"service\">\n\
         \x20   <image reference=\"example.com/{workload}:1\"/>\n\
         \x20   <volumes>\n\
         \x20     <volume name=\"{volume}\" path=\"{path}\" mode=\"{mode}\"{extra}/>\n\
         \x20   </volumes>\n\
         \x20 </workload>\n\
         </workloads>\n"
    )
}

fn upsert(state: &mut ClusterState, document: String) -> Outcome {
    state.apply(&Command::UpsertWorkload { document })
}

/// **The time-shifted case.** Two entries, one volume, both writing.
#[test]
fn a_second_writer_of_the_same_volume_is_rejected_even_much_later() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(
            &mut state,
            definition("ledger", "data", "/var/lib/ledger", "readWrite")
        ),
        Outcome::Applied
    );

    // In between all sorts of things happen.
    for other in ["api", "cache", "report"] {
        upsert(
            &mut state,
            definition(other, &format!("{other}-data"), "/var/lib/x", "readWrite"),
        );
    }

    let outcome = upsert(
        &mut state,
        definition("second", "data", "/srv/data", "readWrite"),
    );

    assert!(
        matches!(
            outcome,
            Outcome::Rejected(Rejection::UnplaceableDefinition { ref workload, .. })
                if workload == "second"
        ),
        "expected a rejection, was {outcome:?}"
    );
}

/// A shared volume somebody wants to write — the same path, a different
/// rule.
#[test]
fn turning_a_shared_volume_into_a_written_one_is_rejected() {
    let mut state = ClusterState::default();

    upsert(
        &mut state,
        definition("report", "master", "/opt/master", "readOnly"),
    );
    let outcome = upsert(
        &mut state,
        definition("ledger", "master", "/opt/master", "readWrite"),
    );

    assert!(
        matches!(
            outcome,
            Outcome::Rejected(Rejection::UnplaceableDefinition { .. })
        ),
        "expected a rejection, was {outcome:?}"
    );
}

/// Many readers of the same volume are the point of the thing and go through.
#[test]
fn many_readers_of_one_volume_all_apply() {
    let mut state = ClusterState::default();

    for workload in ["api", "report", "ledger"] {
        assert_eq!(
            upsert(
                &mut state,
                definition(workload, "master", "/opt/master", "readOnly")
            ),
            Outcome::Applied,
            "'{workload}' should have gone through"
        );
    }
}

/// **An upsert replaces.** Submitting the same workload again must not fail on
/// its quarrelling with itself over its own volume.
#[test]
fn re_submitting_the_same_workload_does_not_conflict_with_itself() {
    let mut state = ClusterState::default();

    let document = definition("ledger", "data", "/var/lib/ledger", "readWrite");
    assert_eq!(upsert(&mut state, document.clone()), Outcome::Applied);
    assert_eq!(upsert(&mut state, document), Outcome::Applied);
}

/// If the first writer is removed, the volume is free again.
#[test]
fn removing_the_writer_frees_the_volume() {
    let mut state = ClusterState::default();

    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );
    state.apply(&Command::RemoveWorkload {
        name: "ledger".to_owned(),
    });

    assert_eq!(
        upsert(
            &mut state,
            definition("successor", "data", "/var/lib/succ", "readWrite")
        ),
        Outcome::Applied
    );
}

/// The rejection says what it was down to — otherwise the audit trail carries
/// only that something did not work (ADR-0020).
#[test]
fn the_rejection_says_which_volume_and_who_holds_it() {
    let mut state = ClusterState::default();
    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );

    let outcome = upsert(
        &mut state,
        definition("second", "data", "/srv/data", "readWrite"),
    );

    let Outcome::Rejected(Rejection::UnplaceableDefinition { detail, .. }) = outcome else {
        panic!("expected a rejection, was {outcome:?}");
    };
    assert!(detail.contains("data"), "{detail}");
    assert!(detail.contains("ledger"), "{detail}");
}

// ================================================ Deleting (ADR-0027, 10b)

/// **A volume somebody still declares is not deleted.**
///
/// Deleting it while a workload names it would tear that workload open at the
/// next start — and the data would be gone anyway. First change the workload,
/// then the volume.
#[test]
fn a_volume_a_workload_still_declares_is_not_deleted() {
    let mut state = ClusterState::default();
    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );

    let outcome = state.apply(&Command::DeleteVolume {
        volume: "data".to_owned(),
        node: "node-1".to_owned(),
        at: 0,
    });

    assert!(
        matches!(
            outcome,
            Outcome::Rejected(Rejection::VolumeInUse { ref volume, ref workload })
                if volume == "data" && workload == "ledger"
        ),
        "expected VolumeInUse, was {outcome:?}"
    );
}

/// If the workload is withdrawn, the volume is deletable — and the decision
/// stands in the log (ADR-0020).
#[test]
fn once_nobody_declares_it_the_deletion_is_recorded() {
    let mut state = ClusterState::default();
    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );
    state.apply(&Command::RemoveWorkload {
        name: "ledger".to_owned(),
    });

    assert_eq!(
        state.apply(&Command::DeleteVolume {
            volume: "data".to_owned(),
            node: "node-1".to_owned(),
            at: 0,
        }),
        Outcome::Applied
    );
}

/// A merely read volume is protected too: whoever deletes it takes it from
/// everyone who reads it.
#[test]
fn a_read_only_volume_is_protected_too() {
    let mut state = ClusterState::default();
    upsert(
        &mut state,
        definition("report", "master", "/opt/master", "readOnly"),
    );

    let outcome = state.apply(&Command::DeleteVolume {
        volume: "master".to_owned(),
        node: "node-1".to_owned(),
        at: 0,
    });

    assert!(matches!(
        outcome,
        Outcome::Rejected(Rejection::VolumeInUse { .. })
    ));
}

// ----------------------------------------------- Tombstones (ADR-0042)

/// **An applied deletion leaves a tombstone.**
///
/// Without it there would be nothing the slice from ADR-0040 could carry: it is
/// a snapshot of the desired state and no event. And the node on which the volume
/// lies would never learn of it.
#[test]
fn an_applied_deletion_leaves_a_tombstone() {
    let mut state = ClusterState::default();
    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );
    state.apply(&Command::RemoveWorkload {
        name: "ledger".to_owned(),
    });
    state.apply(&Command::DeleteVolume {
        volume: "data".to_owned(),
        node: "node-1".to_owned(),
        at: 0,
    });

    assert_eq!(
        state.deleted_volumes(),
        vec![("node-1", vec!["data"])],
        "the tombstone is missing"
    );
}

/// **A refused deletion leaves no trace.**
///
/// Otherwise a node would delete a volume whose deletion the cluster has just
/// refused — and the auditor would find a rejection in the log and nothing on the
/// disk any more.
#[test]
fn a_rejected_deletion_leaves_no_tombstone() {
    let mut state = ClusterState::default();
    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );

    state.apply(&Command::DeleteVolume {
        volume: "data".to_owned(),
        node: "node-1".to_owned(),
        at: 0,
    });

    assert!(state.deleted_volumes().is_empty());
}

/// **If the same volume is declared again, the tombstone is obsolete.**
///
/// Were it to stay lying, the agent would delete at the next slice exactly what
/// was just wanted — and nobody would look for the error in the state machine.
#[test]
fn declaring_the_volume_again_retires_the_tombstone() {
    let mut state = ClusterState::default();
    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );
    state.apply(&Command::RemoveWorkload {
        name: "ledger".to_owned(),
    });
    state.apply(&Command::DeleteVolume {
        volume: "data".to_owned(),
        node: "node-1".to_owned(),
        at: 0,
    });
    assert!(!state.deleted_volumes().is_empty());

    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );

    assert!(
        state.deleted_volumes().is_empty(),
        "the tombstone outlived the fresh start"
    );
}

/// **The tombstone goes away on all nodes, not only on one.**
///
/// Where the volume will lie in future is decided by the planner. A tombstone
/// left lying on another node would be a deletion that strikes there at some
/// point.
#[test]
fn retiring_a_tombstone_clears_it_everywhere() {
    let mut state = ClusterState::default();
    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );
    state.apply(&Command::RemoveWorkload {
        name: "ledger".to_owned(),
    });

    // Two tombstones for the same name on two nodes. **Without** an `upsert` in
    // between: that would already clear the first away, and precisely that is
    // what the test below checks.
    for node in ["node-1", "node-2"] {
        state.apply(&Command::DeleteVolume {
            volume: "data".to_owned(),
            node: node.to_owned(),
            at: 0,
        });
    }
    assert_eq!(state.deleted_volumes().len(), 2);

    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );

    assert!(state.deleted_volumes().is_empty());
}

/// **A different volume does not clear the tombstone away.**
///
/// The counter-check to the test above: a tombstone is settled only by **its**
/// volume.
#[test]
fn declaring_a_different_volume_leaves_the_tombstone() {
    let mut state = ClusterState::default();
    upsert(
        &mut state,
        definition("ledger", "data", "/var/lib/ledger", "readWrite"),
    );
    state.apply(&Command::RemoveWorkload {
        name: "ledger".to_owned(),
    });
    state.apply(&Command::DeleteVolume {
        volume: "data".to_owned(),
        node: "node-1".to_owned(),
        at: 0,
    });

    upsert(
        &mut state,
        definition("report", "other", "/opt/other", "readWrite"),
    );

    assert_eq!(state.deleted_volumes(), vec![("node-1", vec!["data"])]);
}
