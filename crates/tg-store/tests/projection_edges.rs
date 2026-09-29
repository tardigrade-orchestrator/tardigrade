//! The edges of the projection: empty cases, unknown names, concurrency.
//!
//! `tests/projection.rs` checks the path ADR-0004 describes: desired state in,
//! view out. Here stands what the agent really throws at it in operation —
//! names that no longer exist, reports from several tasks, and the case that
//! nothing is wanted.
//!
//! All operations are infallible (ADR-0030): there is no error type one could
//! check. All the more important that the absence of an error does not mean that
//! something happened.

use std::sync::Arc;
use std::thread;

use tg_defs::DependencyKind;
use tg_store::{ActualStatus, Projection};

/// Reports instances as **one** report of a node.
///
/// `report_instances` is replacing per node (ADR-0004): two calls in a row are
/// not two reports but the second one. What applies together therefore belongs
/// in one call.
fn report(projection: &Projection, states: &[(&str, u32, ActualStatus)]) {
    projection.report_instances(
        "n1",
        states
            .iter()
            .map(|(workload, instance, status)| ((*workload).to_owned(), *instance, *status))
            .collect(),
    );
}

const SET: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="example.com/api:1"/>
    <dependencies>
      <after ref="cache"/>
      <requires ref="cache"/>
    </dependencies>
  </workload>
  <workload name="cache" kind="service">
    <image reference="example.com/cache:1"/>
  </workload>
</workloads>"#;

fn projection() -> Projection {
    let set = tg_defs::from_str(SET).expect("fixture has to parse");
    let projection = Projection::new();
    projection.materialize(set.workloads());
    projection
}

/// A fresh projection is empty, and queries on it return nothing instead of
/// panicking. That is how it looks at the start of every agent, before the cache
/// is read.
#[test]
fn a_fresh_projection_answers_everything_with_nothing() {
    let projection = Projection::new();

    assert!(projection.workloads().is_empty());
    assert!(projection.actual_states().is_empty());
    assert!(
        projection
            .targets_of("api", DependencyKind::After)
            .is_empty()
    );
    // A report creates no record — and since the move of the map beside `Inner`
    // that is **structurally** so: it hangs on no `WorkloadRecord`. Previously a
    // `false` said it.
    report(&projection, &[("api", 0, ActualStatus::Running)]);
    assert!(projection.workloads().is_empty());
}

/// An empty desired state yields an empty view — and deletes what was there
/// before.
///
/// The case arises when the last workload of a node is removed. The view has to
/// follow it; a remainder would be a dead entry the agent later reports as
/// running.
#[test]
fn an_empty_desired_state_empties_the_view() {
    let projection = projection();
    assert_eq!(projection.workloads().len(), 2);

    projection.materialize(&[]);

    assert!(projection.workloads().is_empty());
    assert!(projection.actual_states().is_empty());
    assert!(
        projection
            .targets_of("api", DependencyKind::After)
            .is_empty()
    );
}

/// Rematerializing **leaves** the reported actual state alone.
///
/// This witness says the opposite of its predecessor. That one was called
/// `materializing_resets_the_observed_state` and justified the reset thus: after
/// a change of the desired state the old observation is no longer about the same
/// thing. The argument covered a rare case and hit a frequent one — measured,
/// `tgd::projection` calls `materialize` over the **whole** state, i.e. at
/// **every** log movement: a lease renewal every three seconds (ADR-0064) wiped
/// the actual state of the whole cluster.
///
/// It also applied to the five reported neighbours (`stale`, `unready`,
/// `failures`, `capacity`, `endpoints`) — and those survived. An operator then
/// read "observed: nothing" beside "failed: 1 (pull)".
///
/// And for the case the predecessor meant there has been a better tool since
/// ADR-0070: an instance from an older declaration is reported as **stale** — it
/// says so instead of staying silent.
#[test]
fn materializing_leaves_the_reported_state_alone() {
    let projection = projection();
    report(&projection, &[("api", 0, ActualStatus::Running)]);

    let set = tg_defs::from_str(SET).expect("parses");
    projection.materialize(set.workloads());

    assert_eq!(
        projection.actual_states().get(&("api".to_owned(), 0)),
        Some(&ActualStatus::Running),
        "the report does not come from the log and must not fall with it"
    );
    assert_eq!(projection.worst_of("api"), ActualStatus::Running);
}

/// A report about an unknown name is refused and creates no record.
///
/// Were it to create one instead, a workload nobody wanted would arise in the
/// view, and the desired state would no longer be the only source of its
/// entries.
///
/// The **effect** is checked and no longer a return value: since the instance
/// map lies beside `Inner`, a report hangs on no `WorkloadRecord` — the promise
/// thereby holds structurally instead of by check.
#[test]
fn reporting_an_unknown_workload_creates_nothing() {
    let projection = projection();
    let before = projection.workloads();

    for name in ["gibtsnicht", "", "api ", "API", "../api"] {
        report(&projection, &[(name, 0, ActualStatus::Running)]);
        assert_eq!(projection.workloads(), before, "'{name}' created something");
    }
}

/// Edge queries for unknown names and kinds yield an empty list.
///
/// The axis separation from ADR-0009 holds here too: `api` has a `requires`
/// edge but no `wants` edge — and the query for `wants` must not deliver the
/// other one along.
#[test]
fn edge_queries_for_unknown_names_and_kinds_are_empty() {
    let projection = projection();

    assert_eq!(
        projection.targets_of("api", DependencyKind::Requires),
        ["cache"]
    );
    assert!(
        projection
            .targets_of("api", DependencyKind::Wants)
            .is_empty()
    );
    assert!(
        projection
            .targets_of("api", DependencyKind::BindsTo)
            .is_empty()
    );
    assert!(
        projection
            .targets_of("gibtsnicht", DependencyKind::After)
            .is_empty()
    );
    assert!(projection.targets_of("", DependencyKind::After).is_empty());

    // A workload without dependencies has no edges, in no direction.
    assert!(
        projection
            .targets_of("cache", DependencyKind::After)
            .is_empty()
    );
}

/// An edge points in exactly one direction. `api` depends on `cache`, not the
/// other way round — and the view must not make a symmetry out of it.
#[test]
fn edges_are_directed() {
    let projection = projection();

    assert_eq!(
        projection.targets_of("api", DependencyKind::After),
        ["cache"]
    );
    assert!(
        projection
            .targets_of("cache", DependencyKind::After)
            .is_empty()
    );
}

/// The view comes back sorted and complete.
///
/// Sorted is no cosmetics: from phase 5d the projection arises on every node
/// from the same log and has to look the same there. An order that depends on
/// the document order would be different on two nodes.
#[test]
fn the_view_comes_back_sorted() {
    let set = tg_defs::from_str(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="zeta" kind="service"><image reference="example.com/z:1"/></workload>
  <workload name="alpha" kind="service"><image reference="example.com/a:1"/></workload>
  <workload name="mitte" kind="service"><image reference="example.com/m:1"/></workload>
</workloads>"#,
    )
    .expect("parses");

    let projection = Projection::new();
    projection.materialize(set.workloads());

    let names: Vec<String> = projection
        .workloads()
        .into_iter()
        .map(|record| record.name)
        .collect();
    assert_eq!(names, ["alpha", "mitte", "zeta"]);

    // The actual state is empty as long as nobody has reported — the sorting of
    // the **view** stands above, and that of the actual state shows only with
    // reports.
    assert!(projection.actual_states().is_empty());
    report(
        &projection,
        &[
            ("zeta", 0, ActualStatus::Running),
            ("alpha", 0, ActualStatus::Running),
            ("mitte", 0, ActualStatus::Running),
        ],
    );
    let states: Vec<String> = projection
        .actual_states()
        .into_keys()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(states, ["alpha", "mitte", "zeta"]);
}

/// The last reported state applies — including the way back from `Running` to
/// `Failed`. The actual path knows no one-way street.
#[test]
fn the_latest_report_wins_in_both_directions() {
    let projection = projection();

    for status in [
        ActualStatus::Running,
        ActualStatus::Failed,
        ActualStatus::Stopped,
        ActualStatus::Running,
        ActualStatus::Unknown,
    ] {
        report(&projection, &[("api", 0, status)]);
        assert_eq!(
            projection.actual_states().get(&("api".to_owned(), 0)),
            Some(&status)
        );
    }
}

/// The view is a copy, not a reference: whoever holds it does not block the
/// projection and does not see later changes either.
///
/// Without that property a slow reader could have held up the reconcile loop —
/// exactly what ADR-0019 wants to keep away from the actual path.
#[test]
fn a_snapshot_of_the_view_does_not_change_underneath_the_caller() {
    let projection = projection();
    let held = projection.workloads();

    report(&projection, &[("api", 0, ActualStatus::Running)]);
    projection.materialize(&[]);

    assert_eq!(held.len(), 2, "the held view has changed");
    assert!(projection.workloads().is_empty());
}

/// Several tasks report at the same time; the view stays free of contradiction.
///
/// The agent reports from a loop, the projection is filled from the log from
/// phase 5d and read over gRPC streams (ADR-0030) — reading and writing
/// therefore meet. Here stands the proof that this works without lock discipline
/// at the caller: no record is lost, none arises additionally.
#[test]
fn concurrent_reports_leave_the_view_consistent() {
    let projection = Arc::new(projection());

    let handles: Vec<_> = (0..8)
        .map(|index| {
            let projection = Arc::clone(&projection);
            thread::spawn(move || {
                for _ in 0..200 {
                    // **One report per thread, under a node name of its own.**
                    // The report is replacing per node, so eight threads under
                    // one name would delete each other.
                    //
                    // A `ghost-{index}` with an assertion on the refusal also
                    // stood here. The refusal path no longer exists: the
                    // instance map hangs on no `WorkloadRecord`, so a report
                    // cannot create one — structurally instead of by check.
                    projection.report_instances(
                        &format!("n{index}"),
                        vec![
                            ("api".to_owned(), 0, ActualStatus::Running),
                            ("cache".to_owned(), 0, ActualStatus::Stopped),
                        ],
                    );
                    let _ = projection.workloads();
                    let _ = projection.targets_of("api", DependencyKind::After);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("no thread may panic");
    }

    // **Two**, although eight nodes reported: the query is the union over
    // `(workload, instance)`, and all eight name the same two keys. In operation
    // that would not occur — an instance runs on exactly one node — but for a
    // load probe it is the sharper picture: eight writers on the same entries.
    let states = projection.actual_states();
    assert_eq!(states.len(), 2);
    assert_eq!(
        states.get(&("api".to_owned(), 0)),
        Some(&ActualStatus::Running)
    );
    assert_eq!(
        states.get(&("cache".to_owned(), 0)),
        Some(&ActualStatus::Stopped)
    );
}

/// A change of the desired state during running reports leads to no mixed state:
/// at the end exactly one of the two sets stands, never a merge.
#[test]
fn materializing_under_concurrent_reports_never_mixes_the_sets() {
    let projection = Arc::new(Projection::new());
    let first = tg_defs::from_str(SET).expect("parses");
    let second = tg_defs::from_str(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="db" kind="service"><image reference="example.com/db:1"/></workload>
</workloads>"#,
    )
    .expect("parses");

    projection.materialize(first.workloads());

    let reporter = {
        let projection = Arc::clone(&projection);
        thread::spawn(move || {
            for _ in 0..500 {
                // Load, not setup -- see above.
                report(
                    &projection,
                    &[
                        ("api", 0, ActualStatus::Running),
                        ("db", 0, ActualStatus::Running),
                    ],
                );

                let names: Vec<String> = projection
                    .workloads()
                    .into_iter()
                    .map(|record| record.name)
                    .collect();
                assert!(
                    names == ["api", "cache"] || names == ["db"],
                    "mixed state observed: {names:?}"
                );
            }
        })
    };

    for _ in 0..100 {
        projection.materialize(second.workloads());
        projection.materialize(first.workloads());
    }

    reporter.join().expect("no thread may panic");
}
