//! The endpoints of foreign workloads, from the report into the slice
//! (ADR-0073).
//!
//! # Which seam is checked here
//!
//! The **filter** is pure and checked in `tg-store`; the **registry** hangs in
//! `tg-agent` on a file and is substantiated there against `dig`. What lies
//! between the two is the place at which the leader brings observation and
//! replicated state together:
//!
//! ```text
//! NodeReport.endpoints -> projection.report_endpoints
//!                      -> projection.reported_endpoints()   (+ health)
//!                      -> view_of(state, index, …)
//!                      -> slice_for(node, view)
//! ```
//!
//! Checking it without a process is here the **stricter** choice: with a process
//! the test would need a second node together with an mTLS session, and what it
//! then substantiated would be the transport -- that is substantiated in
//! `attestation.rs`. What is checked is the bringing together, and that is a
//! function over two inputs.

use tg_consensus::{ClusterState, Command};
use tg_store::projection::{ActualStatus, Projection};

/// A state with two workloads, one edge and two placements.
fn state() -> ClusterState {
    let mut state = ClusterState::default();
    let mut apply = |command: Command| {
        // **The outcome is asserted, not the variant** -- the finding from the
        // path of the control plane to the node: `Applied` also encloses a
        // rejection, and a state that stays silently empty makes every test on
        // it green-blind.
        let outcome = state.apply(&command);
        assert!(
            matches!(outcome, tg_consensus::Outcome::Applied),
            "{command:?} was not applied: {outcome:?}"
        );
    };

    // The nodes first: `AssignPlacement` refuses an unknown node (measured --
    // the first version of this test ignored the outcome and built a state
    // without placements).
    for node in ["node-a", "node-b"] {
        apply(Command::UpsertNode {
            name: node.to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: node.to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        });
    }

    for (name, node) in [("api", "node-a"), ("ledger", "node-b")] {
        apply(Command::UpsertWorkload {
            document: format!(
                r#"<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="{name}" kind="service">
    <image reference="example.com/{name}:1"/>
  </workload>
</workloads>"#
            ),
        });
        apply(Command::AssignPlacement {
            workload: name.to_owned(),
            instance: 0,
            node: node.to_owned(),
        });
    }
    apply(Command::AllowTraffic {
        from: "api".to_owned(),
        to: "ledger".to_owned(),
    });

    state
}

/// **One node's report reaches the other's slice.**
///
/// The gap that was measured: `node-a` carries `api`, may dial `ledger` -- and
/// never learned its address, because that is assigned node-locally (phase 9a)
/// and stood in no message.
#[test]
fn a_reported_endpoint_reaches_the_slice_of_the_node_that_may_dial_it() {
    let state = state();
    let projection = Projection::new();
    projection.materialize(
        // The projection must know the workloads, otherwise it takes up no
        // actual state (ADR-0004: which instances there should be is said by the
        // log).
        tg_defs::from_str(
            r#"<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service"><image reference="example.com/api:1"/></workload>
  <workload name="ledger" kind="service"><image reference="example.com/ledger:1"/></workload>
</workloads>"#,
        )
        .expect("fixture")
        .workloads(),
    );

    // `node-b` reports what it carries -- and that it is running.
    projection.report_endpoints(
        "node-b",
        vec![(
            "ledger".to_owned(),
            0,
            "10.42.2.5".parse().expect("address"),
        )],
    );
    projection.report_instances(
        "node-b",
        vec![("ledger".to_owned(), 0, ActualStatus::Running)],
    );

    let view = tgd::session::view_of(&state, 7, projection.reported_endpoints());
    let slice = tg_store::session::slice_for("node-a", &view);

    let endpoint = slice
        .endpoints
        .iter()
        .find(|endpoint| endpoint.workload == "ledger")
        .expect("node-a's slice does not carry ledger's endpoint");

    assert_eq!(endpoint.address.to_string(), "10.42.2.5");
    assert!(
        endpoint.healthy,
        "the health does not come from the same node's report"
    );
}

/// **And the health is the report's, not an assumption.**
///
/// The counter-check to the test above: without it a version that sets `healthy`
/// fixed to `true` would be just as green -- and the resolver would offer a dead
/// address (ADR-0013).
#[test]
fn an_instance_that_is_not_running_travels_as_unhealthy() {
    let state = state();
    let projection = Projection::new();
    projection.materialize(
        tg_defs::from_str(
            r#"<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="ledger" kind="service"><image reference="example.com/ledger:1"/></workload>
</workloads>"#,
        )
        .expect("fixture")
        .workloads(),
    );
    projection.report_endpoints(
        "node-b",
        vec![(
            "ledger".to_owned(),
            0,
            "10.42.2.5".parse().expect("address"),
        )],
    );
    projection.report_instances(
        "node-b",
        vec![("ledger".to_owned(), 0, ActualStatus::Failed)],
    );

    let view = tgd::session::view_of(&state, 7, projection.reported_endpoints());
    let slice = tg_store::session::slice_for("node-a", &view);

    let endpoint = slice.endpoints.first().expect("no endpoint");
    assert!(!endpoint.healthy, "a failed instance counts as healthy");
}

/// **Without a report no endpoint** -- and that is not the same as "unhealthy".
///
/// A node nobody has heard anything from yet leaves no address behind. Inventing
/// it would mean giving the resolver a resolution that points into the void.
#[test]
fn without_a_report_no_endpoint_travels() {
    // **`slice_of` and not by hand**: it encapsulates exactly this case -- the
    // slice without observation --, and two reconstructions would be two
    // opportunities to go apart as soon as `view_of` gets a parameter.
    let slice = tgd::session::slice_of(&state(), 7, "node-a");

    assert!(slice.endpoints.is_empty(), "{:?}", slice.endpoints);
    // The edge is there nevertheless -- otherwise the test would only show that
    // this node gets nothing at all.
    assert_eq!(slice.edges, vec![("api".to_owned(), "ledger".to_owned())]);
}
