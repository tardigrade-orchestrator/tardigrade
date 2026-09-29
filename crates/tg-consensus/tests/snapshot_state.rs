//! The snapshot decree in consensus.
//!
//! Written **before** the implementation, so the rules are settled ahead of
//! the code that must satisfy them. What is checked is the state machine:
//! what lies in the log, what is refused — pure logic, without a cluster.
//!
//! # Why only the snapshot stands here
//!
//! The counterpart is missing on purpose. A **restore** stands in no log: it
//! is destructive, and a level-triggered decree would overwrite anew at
//! every loss of the progress mark what the application has written since
//! the snapshot. A snapshot, by contrast, is **additive** — making it twice
//! costs space and nothing else.

use tg_consensus::{ClusterState, Command, Outcome, Rejection};

/// Builds a state with one admitted node.
///
/// The condition is the **admission** and not an `UpsertNode`: `AdmitNode`
/// creates no node entry, since admission grants only network trust and not
/// topology or capacity, and an operator shall not have to invent those in
/// order to decree a snapshot. The same choice applies to the key
/// generations elsewhere in this state machine.
///
/// # Parameters
///
/// - `name`: the node name to admit.
///
/// # Returns
///
/// A `ClusterState` with `name` invited and admitted.
fn with_node(name: &str) -> ClusterState {
    let mut state = ClusterState::default();

    let outcome = state.apply(&Command::InviteNode {
        node: name.to_owned(),
        digest: "a".repeat(64),
        expires_at: 1_800_000_000,
    });
    assert!(matches!(outcome, Outcome::Applied), "{outcome:?}");

    let outcome = state.apply(&Command::AdmitNode {
        node: name.to_owned(),
        spki: "AAAA".to_owned(),
        at: 1_700_000_000,
    });
    assert!(matches!(outcome, Outcome::Applied), "{outcome:?}");

    state
}

/// Looks up the stored snapshot generation for a volume on a node.
///
/// # Parameters
///
/// - `state`: the cluster state to query.
/// - `node`: the node the volume is decreed on.
/// - `volume`: the volume name.
///
/// # Returns
///
/// The stored generation, or `None` if no snapshot has been decreed for
/// this node/volume pair.
fn wanted(state: &ClusterState, node: &str, volume: &str) -> Option<u64> {
    state
        .snapshot_generations()
        .into_iter()
        .find(|(had, _)| *had == node)
        .and_then(|(_, volumes)| {
            volumes
                .into_iter()
                .find(|(name, _)| *name == volume)
                .map(|(_, generation)| generation)
        })
}

/// The core: the generation lands in the state.
#[test]
fn a_snapshot_generation_is_stored() {
    let mut state = with_node("node-1");

    let outcome = state.apply(&Command::SnapshotVolume {
        volume: "data-0".to_owned(),
        node: "node-1".to_owned(),
        generation: 4,
    });

    assert!(matches!(outcome, Outcome::Applied), "{outcome:?}");
    assert_eq!(wanted(&state, "node-1", "data-0"), Some(4));
}

/// **Backwards no, the same yes** — the same monotonicity rule applied to
/// the key generations and the workload generations elsewhere in this
/// state machine.
#[test]
fn a_generation_never_goes_backwards() {
    let mut state = with_node("node-1");
    let verdict = |generation| Command::SnapshotVolume {
        volume: "data-0".to_owned(),
        node: "node-1".to_owned(),
        generation,
    };

    assert!(matches!(state.apply(&verdict(4)), Outcome::Applied));

    // The same is settled (rule 1), not refused.
    assert!(
        matches!(state.apply(&verdict(4)), Outcome::Applied),
        "the same generation is settled"
    );

    match state.apply(&verdict(3)) {
        Outcome::Rejected(Rejection::SnapshotGenerationNotAdvancing {
            volume,
            node,
            have,
            wanted: asked,
        }) => {
            assert_eq!(volume, "data-0");
            assert_eq!(node, "node-1");
            assert_eq!(have, 4);
            assert_eq!(asked, 3);
        }
        other => panic!("expected a rejection, got: {other:?}"),
    }

    assert_eq!(
        wanted(&state, "node-1", "data-0"),
        Some(4),
        "a refused decree must not touch the state"
    );
}

/// A node the cluster has not admitted is **refused** and not settled
/// idempotently.
///
/// The exception to rule 1, as with the cordon: "snapshot decreed" on a node that
/// does not exist would look to an operator like "decreed" — and they would move
/// on reassured.
#[test]
fn an_unadmitted_node_gets_no_verdict() {
    let mut state = ClusterState::default();

    match state.apply(&Command::SnapshotVolume {
        volume: "data-0".to_owned(),
        node: "does-not-exist".to_owned(),
        generation: 1,
    }) {
        Outcome::Rejected(Rejection::NotAdmitted { node }) => {
            assert_eq!(node, "does-not-exist");
        }
        other => panic!("expected NotAdmitted, got: {other:?}"),
    }
}

/// **The volume is not checked**, and that is intentional.
///
/// The state knows only the *declarations*, not the disk — and both cases are
/// legitimate: a snapshot of a declared volume is the normal case, one of a
/// volume without a workload is exactly the DR case in which the workload is
/// already withdrawn and the data still lies there.
#[test]
fn a_volume_no_workload_declares_can_still_be_snapshotted() {
    let mut state = with_node("node-1");

    let outcome = state.apply(&Command::SnapshotVolume {
        volume: "orphaned-0".to_owned(),
        node: "node-1".to_owned(),
        generation: 1,
    });

    assert!(
        matches!(outcome, Outcome::Applied),
        "precisely the DR case must not be refused: {outcome:?}"
    );
}

/// Two volumes on one node have generations of their own.
#[test]
fn two_volumes_keep_their_own_generations() {
    let mut state = with_node("node-1");

    for (volume, generation) in [("data-0", 4), ("wal-0", 9)] {
        let outcome = state.apply(&Command::SnapshotVolume {
            volume: volume.to_owned(),
            node: "node-1".to_owned(),
            generation,
        });
        assert!(matches!(outcome, Outcome::Applied), "{outcome:?}");
    }

    assert_eq!(wanted(&state, "node-1", "data-0"), Some(4));
    assert_eq!(wanted(&state, "node-1", "wal-0"), Some(9));
}

/// If a node is deregistered, its decrees go with it.
///
/// Without that a node joining anew under the same name would inherit its
/// predecessor's snapshot history — and would get snapshots decreed of volumes
/// that do not exist there. The same clean-up work applies to the key
/// generations elsewhere in this state machine.
#[test]
fn removing_a_node_takes_its_verdicts() {
    let mut state = with_node("node-1");
    state.apply(&Command::SnapshotVolume {
        volume: "data-0".to_owned(),
        node: "node-1".to_owned(),
        generation: 4,
    });
    assert_eq!(wanted(&state, "node-1", "data-0"), Some(4));

    let outcome = state.apply(&Command::RemoveNode {
        name: "node-1".to_owned(),
    });
    assert!(matches!(outcome, Outcome::Applied), "{outcome:?}");

    assert_eq!(
        wanted(&state, "node-1", "data-0"),
        None,
        "the decrees of a deregistered node must go with it"
    );
}
