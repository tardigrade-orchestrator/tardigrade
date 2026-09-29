//! The ingest check that blocks a workload name from colliding with a derived
//! sidecar name.
//!
//! A workload named `api` that declares a `<mesh>` element causes a sidecar named
//! `api-proxy` to be derived; a workload directly named `api-proxy` would collide
//! with that derived name. The log carries exactly one workload per entry, the
//! full set of workloads only exists inside the state machine, and arbitrarily
//! much time can pass between the two conflicting entries, so the check has to
//! hold regardless of submission order or delay.
//!
//! The consequence of missing this check was measured directly: a node running
//! `api` (with mesh), the colliding `api-proxy`, and an uninvolved `harmless`
//! workload reconciled none of the three, and repeated the failure every second.

use tg_consensus::{ClusterState, Command, Outcome, Rejection};

/// Builds an XML workload definition, optionally with a `<mesh>` element.
///
/// # Parameters
/// - `name`: the workload name.
/// - `mesh`: whether to include a `<mesh>` element enabling the sidecar.
///
/// # Returns
/// The XML document as a string.
fn definition(name: &str, mesh: bool) -> String {
    let element = if mesh {
        "    <mesh port=\"8443\"/>\n"
    } else {
        ""
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"{name}\" kind=\"service\">\n\
         \x20   <image reference=\"example.com/{name}:1\"/>\n\
         {element}\
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

/// **The time-shifted case.** The mesh member already stands there, the name
/// comes later.
#[test]
fn a_name_that_blocks_a_derivation_is_rejected_even_much_later() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(&mut state, definition("api", true)),
        Outcome::Applied,
        "on its own the mesh member is inconspicuous"
    );
    for other in ["cache", "report"] {
        upsert(&mut state, definition(other, false));
    }

    let outcome = upsert(&mut state, definition("api-proxy", false));
    assert!(
        matches!(
            outcome,
            Outcome::Rejected(Rejection::UnplaceableDefinition { ref workload, ref detail })
                if workload == "api-proxy" && detail.contains("api-proxy")
        ),
        "expected a rejection, was {outcome:?}"
    );
}

/// **The other way round too**: the name already stands there, the mesh member
/// comes.
///
/// Without this counter-check it would stay open whether the check sees only one
/// direction — and then the effect would hang on who came first.
#[test]
fn the_order_of_the_two_does_not_matter() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(&mut state, definition("api-proxy", false)),
        Outcome::Applied,
        "on its own the name is an ordinary choice"
    );

    let outcome = upsert(&mut state, definition("api", true));
    assert!(
        matches!(
            outcome,
            Outcome::Rejected(Rejection::UnplaceableDefinition { ref workload, .. })
                if workload == "api"
        ),
        "expected a rejection, was {outcome:?}"
    );
}

/// **Without `<mesh>` there is nothing to block.**
///
/// Half the assurance: a check that forbids the suffix as such would be just as
/// red at the collision — and would refuse every workload whose name happens to
/// end that way.
#[test]
fn the_suffix_alone_is_accepted() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(&mut state, definition("api", false)),
        Outcome::Applied
    );
    assert_eq!(
        upsert(&mut state, definition("api-proxy", false)),
        Outcome::Applied,
        "without `<mesh>` nothing is derived, so the name blocks nothing"
    );
}

/// **A workload does not fail on itself.**
///
/// A renewed submission **replaces** the old version; it does not step beside it.
/// Without this branch every second `cluster apply` of the same mesh member would
/// be a rejection.
#[test]
fn resubmitting_the_same_workload_is_not_a_collision() {
    let mut state = ClusterState::default();

    assert_eq!(
        upsert(&mut state, definition("api", true)),
        Outcome::Applied
    );
    assert_eq!(
        upsert(&mut state, definition("api", true)),
        Outcome::Applied,
        "the same definition a second time must carry"
    );
}
