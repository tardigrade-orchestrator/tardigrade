//! The ingest check that rejects a workload declaring a `<dependencies><conflicts>`
//! edge against another workload that is already present, or that arrives later.
//!
//! The log carries exactly one workload per entry, the full set of workloads only
//! exists inside the state machine, and arbitrarily much time can pass between
//! two conflicting entries. A check that looked only at the newly submitted
//! document would let both through, since neither document alone shows the
//! contradiction.

use tg_consensus::{ClusterState, Command, Outcome, Rejection};

/// Builds an XML workload definition that optionally declares a conflict.
///
/// # Parameters
/// - `name`: the workload name.
/// - `conflicts_with`: the name of a workload to declare a `<conflicts>` edge
///   against, if any.
///
/// # Returns
/// The XML document as a string.
fn definition(name: &str, conflicts_with: Option<&str>) -> String {
    let dependencies = conflicts_with.map_or_else(String::new, |target| {
        format!("    <dependencies><conflicts ref=\"{target}\"/></dependencies>\n")
    });

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"{name}\" kind=\"service\">\n\
         \x20   <image reference=\"example.com/{name}:1\"/>\n\
         {dependencies}\
         \x20 </workload>\n\
         </workloads>\n"
    )
}

/// Applies an upsert of the given workload document to the cluster state.
///
/// # Parameters
/// - `state`: the cluster state to mutate.
/// - `document`: the XML workload definition to upsert.
///
/// # Returns
/// The outcome of applying the command.
fn upsert(state: &mut ClusterState, document: String) -> Outcome {
    state.apply(&Command::UpsertWorkload { document })
}

/// **The time-shifted case.** The conflict stands in the first entry, the
/// contradiction arises with the second.
#[test]
fn a_conflicting_workload_is_rejected_even_much_later() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(&mut state, definition("old", Some("new"))),
        Outcome::Applied,
        "on its own the declaration is without consequence -- 'new' does not exist yet"
    );

    for other in ["api", "cache", "report"] {
        upsert(&mut state, definition(other, None));
    }

    let outcome = upsert(&mut state, definition("new", None));

    assert!(
        matches!(
            outcome,
            Outcome::Rejected(Rejection::UnplaceableDefinition { ref workload, .. })
                if workload == "new"
        ),
        "expected a rejection, was {outcome:?}"
    );
}

/// **The other way round too**: the new one declares the conflict, the existing
/// one already stands there. Without this counter-check it would stay open
/// whether the check sees only one direction — and then the effect would hang on
/// who came first.
#[test]
fn the_direction_of_the_declaration_does_not_matter() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(&mut state, definition("old", None)),
        Outcome::Applied
    );

    let outcome = upsert(&mut state, definition("new", Some("old")));

    assert!(
        matches!(
            outcome,
            Outcome::Rejected(Rejection::UnplaceableDefinition { .. })
        ),
        "expected a rejection, was {outcome:?}"
    );
}

/// **A conflict onto a workload that does not exist goes through.**
///
/// Referential integrity over the set is satisfiable only at the end: one
/// workload comes per log entry. An upsert that failed because its counterpart is
/// not yet applied would be unusable — and precisely for that reason the state
/// machine builds no graph.
#[test]
fn a_conflict_with_an_absent_workload_is_applied() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(&mut state, definition("old", Some("doesnotexist"))),
        Outcome::Applied
    );
}

/// An upsert of **the same** workload must not fail on its own conflict: the new
/// version replaces the old one, it does not step beside it.
#[test]
fn re_applying_the_same_workload_does_not_conflict_with_itself() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(&mut state, definition("old", Some("new"))),
        Outcome::Applied
    );
    assert_eq!(
        upsert(&mut state, definition("old", Some("new"))),
        Outcome::Applied,
        "the same definition once more is no contradiction"
    );
}

/// And the counter-check to the whole: without a conflict the same path goes through.
#[test]
fn workloads_without_a_conflict_are_applied() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(&mut state, definition("old", None)),
        Outcome::Applied
    );
    assert_eq!(
        upsert(&mut state, definition("new", None)),
        Outcome::Applied
    );
}
