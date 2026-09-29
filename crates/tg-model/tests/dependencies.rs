//! Acceptance tests of the dependency semantics (ADR-0009, phase 3).
//!
//! This file is written along the phase's acceptance criteria and arose
//! **before** the implementation (CLAUDE.md: tests first for pure-logic
//! crates).

use tg_model::{DependencyGraph, GraphError, Inactivity, Lint};

fn graph(xml: &str) -> DependencyGraph {
    let set = tg_defs::from_str(xml).expect("the fixture has to parse");
    DependencyGraph::build(&set).expect("the graph has to be buildable")
}

fn build_error(xml: &str) -> GraphError {
    let set = tg_defs::from_str(xml).expect("the fixture has to parse");
    DependencyGraph::build(&set).expect_err("the graph must not be buildable")
}

/// db → cache → api: api starts last.
const CHAIN: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
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
    <dependencies>
      <after ref="db"/>
      <requires ref="db"/>
    </dependencies>
  </workload>
  <workload name="db" kind="service">
    <image reference="example.com/db:1"/>
  </workload>
</workloads>"#;

// ------------------------------------------------------- Start order ---

/// First acceptance criterion: the definition starts in the correct order. The
/// document order is deliberately *the reverse* of the start order, so that the
/// test does not accidentally mirror the input.
#[test]
fn start_order_follows_the_ordering_edges_not_the_document() {
    let graph = graph(CHAIN);

    assert_eq!(graph.start_order(), vec!["db", "cache", "api"]);
}

/// `<before>` is the reverse of `<after>` and has to yield the same order
/// (ADR-0009: "stored inversely as one edge with a direction").
#[test]
fn before_is_the_inverse_of_after() {
    let with_before = graph(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="db" kind="service">
    <image reference="example.com/db:1"/>
    <dependencies><before ref="api"/></dependencies>
  </workload>
  <workload name="api" kind="service">
    <image reference="example.com/api:1"/>
  </workload>
</workloads>"#,
    );

    assert_eq!(with_before.start_order(), vec!["db", "api"]);
}

/// Without ordering edges there is no enforced order — the output nevertheless
/// has to be **deterministic**, otherwise the same node starts differently on
/// every run and errors become irreproducible.
#[test]
fn independent_workloads_are_ordered_deterministically() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="zeta" kind="service"><image reference="example.com/z:1"/></workload>
  <workload name="alpha" kind="service"><image reference="example.com/a:1"/></workload>
  <workload name="mike" kind="service"><image reference="example.com/m:1"/></workload>
</workloads>"#;

    let one = graph(xml);
    let two = graph(xml);
    let (first, second) = (one.start_order(), two.start_order());

    assert_eq!(first, second, "two runs have to deliver the same order");
    assert_eq!(first, vec!["alpha", "mike", "zeta"]);
}

/// A requirement without ordering must **not** influence the order — that is
/// the core of the orthogonal axes from ADR-0009.
#[test]
fn requirement_edges_do_not_impose_ordering() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="alpha" kind="service">
    <image reference="example.com/a:1"/>
    <dependencies><requires ref="zeta"/></dependencies>
  </workload>
  <workload name="zeta" kind="service"><image reference="example.com/z:1"/></workload>
</workloads>"#;

    // Only `requires`, no `after`: alphabetical, not dependency-driven.
    assert_eq!(graph(xml).start_order(), vec!["alpha", "zeta"]);
}

// ------------------------------------------------------------ Cycles ---

/// Second acceptance criterion: a cycle is refused at apply.
#[test]
fn ordering_cycle_is_rejected() {
    let err = build_error(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="a" kind="service">
    <image reference="example.com/a:1"/>
    <dependencies><after ref="b"/></dependencies>
  </workload>
  <workload name="b" kind="service">
    <image reference="example.com/b:1"/>
    <dependencies><after ref="a"/></dependencies>
  </workload>
</workloads>"#,
    );

    match err {
        GraphError::OrderingCycle { cycle } => {
            assert!(cycle.contains(&"a".to_owned()) && cycle.contains(&"b".to_owned()));
        }
        other => panic!("wrong error: {other}"),
    }
}

/// The error message has to **name** the cycle. A mere "there is a cycle" is
/// worthless with thirty workloads.
#[test]
fn cycle_error_names_the_path() {
    let err = build_error(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="a" kind="service">
    <image reference="example.com/a:1"/>
    <dependencies><after ref="c"/></dependencies>
  </workload>
  <workload name="b" kind="service">
    <image reference="example.com/b:1"/>
    <dependencies><after ref="a"/></dependencies>
  </workload>
  <workload name="c" kind="service">
    <image reference="example.com/c:1"/>
    <dependencies><after ref="b"/></dependencies>
  </workload>
</workloads>"#,
    );

    let message = err.to_string();
    for name in ["a", "b", "c"] {
        assert!(
            message.contains(name),
            "the cycle does not name '{name}': {message}"
        );
    }
}

/// A requirement cycle is **no** error: only the ordering subgraph has to be
/// acyclic (ADR-0009). Two services may need each other.
#[test]
fn requirement_cycle_is_allowed() {
    let set = tg_defs::from_str(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="a" kind="service">
    <image reference="example.com/a:1"/>
    <dependencies><requires ref="b"/></dependencies>
  </workload>
  <workload name="b" kind="service">
    <image reference="example.com/b:1"/>
    <dependencies><requires ref="a"/></dependencies>
  </workload>
</workloads>"#,
    )
    .expect("parses");

    assert!(DependencyGraph::build(&set).is_ok());
}

#[test]
fn self_reference_is_rejected() {
    let err = build_error(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="a" kind="service">
    <image reference="example.com/a:1"/>
    <dependencies><after ref="a"/></dependencies>
  </workload>
</workloads>"#,
    );

    assert!(matches!(err, GraphError::SelfReference { .. }));
}

/// Referential integrity: the XSD cannot check it (documented in
/// schema/README.md), here is its place.
#[test]
fn dependency_on_unknown_workload_is_rejected() {
    let err = build_error(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="a" kind="service">
    <image reference="example.com/a:1"/>
    <dependencies><requires ref="does-not-exist"/></dependencies>
  </workload>
</workloads>"#,
    );

    match err {
        GraphError::UnknownTarget { target, .. } => assert_eq!(target, "does-not-exist"),
        other => panic!("wrong error: {other}"),
    }
}

#[test]
fn duplicate_workload_name_is_rejected() {
    let err = build_error(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="a" kind="service"><image reference="example.com/a:1"/></workload>
  <workload name="a" kind="job"><image reference="example.com/a:2"/></workload>
</workloads>"#,
    );

    assert!(matches!(err, GraphError::DuplicateWorkload { .. }));
}

// ------------------------------------------------------- Cascades ---

/// Third acceptance criterion, first half: a `BindsTo` target failure stops the
/// dependant.
#[test]
fn binds_to_target_failure_stops_the_dependent() {
    let graph = graph(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="sidecar" kind="service"><image reference="example.com/s:1"/></workload>
  <workload name="app" kind="service">
    <image reference="example.com/app:1"/>
    <dependencies>
      <bindsTo ref="sidecar"/>
      <after ref="sidecar"/>
    </dependencies>
  </workload>
</workloads>"#,
    );

    let stopped = graph.cascade_stop(&[("sidecar", Inactivity::Failed)]);

    assert!(
        stopped.contains("app"),
        "BindsTo has to drag the dependant along"
    );
}

/// Third acceptance criterion, second half: Wants does **not**.
#[test]
fn wants_target_failure_does_not_stop_the_dependent() {
    let graph = graph(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="metrics" kind="service"><image reference="example.com/m:1"/></workload>
  <workload name="app" kind="service">
    <image reference="example.com/app:1"/>
    <dependencies><wants ref="metrics"/></dependencies>
  </workload>
</workloads>"#,
    );

    let stopped = graph.cascade_stop(&[("metrics", Inactivity::Failed)]);

    assert!(stopped.is_empty(), "Wants is a soft coupling: {stopped:?}");
}

#[test]
fn requires_target_failure_stops_the_dependent() {
    let graph = graph(CHAIN);

    let stopped = graph.cascade_stop(&[("db", Inactivity::Failed)]);

    assert!(
        stopped.contains("cache"),
        "Requires has to react to a failure"
    );
}

/// The difference between `requires` and `bindsTo`: a **cleanly stopped**
/// target drags only `bindsTo` along, not `requires` (ADR-0009: `bindsTo` is
/// bound to the exact active state, `requires` to the failure).
#[test]
fn clean_stop_propagates_through_binds_to_but_not_requires() {
    let graph = graph(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="target" kind="service"><image reference="example.com/t:1"/></workload>
  <workload name="hard" kind="service">
    <image reference="example.com/h:1"/>
    <dependencies><bindsTo ref="target"/></dependencies>
  </workload>
  <workload name="soft" kind="service">
    <image reference="example.com/s:1"/>
    <dependencies><requires ref="target"/></dependencies>
  </workload>
</workloads>"#,
    );

    let stopped = graph.cascade_stop(&[("target", Inactivity::Stopped)]);

    assert!(
        stopped.contains("hard"),
        "BindsTo binds to the active state"
    );
    assert!(
        !stopped.contains("soft"),
        "Requires reacts only to a failure"
    );
}

/// Cascades run on transitively, but a workload dragged along counts as
/// **stopped**, not as failed — otherwise a single failure would run on
/// unboundedly over requires chains.
#[test]
fn cascade_is_transitive_through_binds_to() {
    let graph = graph(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="base" kind="service"><image reference="example.com/b:1"/></workload>
  <workload name="middle" kind="service">
    <image reference="example.com/m:1"/>
    <dependencies><bindsTo ref="base"/></dependencies>
  </workload>
  <workload name="top" kind="service">
    <image reference="example.com/t:1"/>
    <dependencies><bindsTo ref="middle"/></dependencies>
  </workload>
</workloads>"#,
    );

    let stopped = graph.cascade_stop(&[("base", Inactivity::Failed)]);

    assert!(stopped.contains("middle"));
    assert!(
        stopped.contains("top"),
        "the cascade has to run transitively"
    );
}

/// A requirement cycle must not send the cascade into an endless loop.
#[test]
fn cascade_terminates_on_a_requirement_cycle() {
    let graph = graph(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="a" kind="service">
    <image reference="example.com/a:1"/>
    <dependencies><bindsTo ref="b"/></dependencies>
  </workload>
  <workload name="b" kind="service">
    <image reference="example.com/b:1"/>
    <dependencies><bindsTo ref="a"/></dependencies>
  </workload>
</workloads>"#,
    );

    let stopped = graph.cascade_stop(&[("a", Inactivity::Failed)]);

    assert!(stopped.contains("b"));
}

// -------------------------------------------------------------- Lint ---

/// ADR-0009 names exactly this warning: `requires` without `after` is the
/// classic systemd pitfall — the target has to run, but nobody said that it has
/// to run **beforehand**.
#[test]
fn requires_without_after_is_linted() {
    let graph = graph(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="db" kind="service"><image reference="example.com/db:1"/></workload>
  <workload name="api" kind="service">
    <image reference="example.com/api:1"/>
    <dependencies><requires ref="db"/></dependencies>
  </workload>
</workloads>"#,
    );

    let lints = graph.lints();

    assert_eq!(lints.len(), 1, "exactly one warning expected: {lints:?}");
    match &lints[0] {
        Lint::RequirementWithoutOrdering {
            workload, target, ..
        } => {
            assert_eq!(workload, "api");
            assert_eq!(target, "db");
        }
        lint @ Lint::SingleWriterWithoutStandby { .. } => {
            panic!("unexpected hint: {lint:?}")
        }
    }
}

#[test]
fn requires_with_after_is_not_linted() {
    assert!(
        graph(CHAIN).lints().is_empty(),
        "CHAIN sets after everywhere"
    );
}

/// `wants` is soft — there is no ordering expectation for it and therefore no
/// warning either.
#[test]
fn wants_without_after_is_not_linted() {
    let graph = graph(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="metrics" kind="service"><image reference="example.com/m:1"/></workload>
  <workload name="app" kind="service">
    <image reference="example.com/app:1"/>
    <dependencies><wants ref="metrics"/></dependencies>
  </workload>
</workloads>"#,
    );

    assert!(graph.lints().is_empty());
}

// --------------------------------------------------------- Conflicts ---

#[test]
fn conflicting_workloads_may_not_be_active_together() {
    let graph = graph(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="example.com/api:1"/>
    <dependencies><conflicts ref="api-legacy"/></dependencies>
  </workload>
  <workload name="api-legacy" kind="service"><image reference="example.com/l:1"/></workload>
</workloads>"#,
    );

    // Conflicts takes effect in both directions, even if only one side
    // declares it.
    assert!(!graph.may_be_active_together("api", "api-legacy"));
    assert!(!graph.may_be_active_together("api-legacy", "api"));
    assert!(graph.may_be_active_together("api", "api"));
}

// --- The warm-standby lint (ADR-0010, ADR-0011) -----------------------------

/// **A single writer with one instance has no standby — and that is said.**
///
/// Without a setting `replicas` stands at 1. The fast failover from ADR-0010,
/// however, rests entirely on the **warm** standby: "the standby fetches a
/// lease with a higher epoch from the quorum → activates quickly." Without a
/// second instance there is nobody who would do that, and until this lint
/// nobody said so.
#[test]
fn a_single_writer_without_a_second_instance_is_linted() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="ledger" kind="service" class="single-writer">
    <image reference="example.com/ledger:1"/>
  </workload>
</workloads>"#;

    let lints = graph(xml).lints();

    assert!(
        lints.iter().any(|lint| matches!(
            lint,
            Lint::SingleWriterWithoutStandby { workload } if workload == "ledger"
        )),
        "no hint: {lints:?}"
    );
    assert!(
        lints[0].to_string().contains("replicas"),
        "the hint does not say how it is done: {}",
        lints[0]
    );
}

/// With a second instance it is silent. Without this counter-check the test
/// above would prove only that something is reported.
#[test]
fn a_single_writer_with_a_standby_is_silent() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="ledger" kind="service" class="single-writer">
    <image reference="example.com/ledger:1"/>
    <placement replicas="2"/>
  </workload>
</workloads>"#;

    assert!(graph(xml).lints().is_empty());
}

/// **A replicated workload with one instance is not reported.** It has no lease
/// and no notion of a standby; warning about it would mean nagging about every
/// single-instance definition in the cluster.
#[test]
fn a_replicated_workload_with_one_instance_is_not_linted() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="example.com/api:1"/>
  </workload>
</workloads>"#;

    assert!(graph(xml).lints().is_empty());
}

// ------------------------------------- The node view (ADR-0061) ---

/// A workload whose target lies on another node.
///
/// The slice from ADR-0040 gives a node only its **own** definitions; of the
/// counterpart it knows the name and nothing else.
const FOREIGN_TARGET: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="example.com/api:1"/>
    <dependencies>
      <after ref="db"/>
      <requires ref="db"/>
    </dependencies>
  </workload>
</workloads>"#;

fn local(xml: &str) -> DependencyGraph {
    let set = tg_defs::from_str(xml).expect("the fixture has to parse");
    let (graph, isolated) = DependencyGraph::from_local(set.workloads());
    assert!(
        isolated.is_empty(),
        "nothing shall be isolated here: {isolated:?}"
    );
    graph
}

/// **An edge across the node boundary does not end the agent** (ADR-0061,
/// determination 1).
///
/// Measured, that was the most expensive finding: `from_workloads` gave
/// `UnknownTarget`, `reconcile::once` passed the error on, and the loop aborted
/// — again at every restart. An edge across the node boundary is the normal
/// case in the cluster (ADR-0011 places independently).
#[test]
fn an_edge_to_a_workload_on_another_node_does_not_break_the_view() {
    let graph = local(FOREIGN_TARGET);

    assert_eq!(graph.start_order(), vec!["api"]);
}

/// **It neither orders nor drags along.**
///
/// The node does not know the foreign workload's state — and cannot even tell
/// whether it does not exist or runs elsewhere. Deriving an effect from not
/// knowing would be wrong in every direction.
#[test]
fn a_foreign_edge_neither_orders_nor_drags() {
    let graph = local(FOREIGN_TARGET);

    assert!(
        graph.cascade_stop(&[("db", Inactivity::Failed)]).is_empty(),
        "a workload on another node must drag nothing along here"
    );
}

/// **The strict way stays strict.**
///
/// The leniency applies to the node view, not to the ingest: `tgctl apply` and
/// the linter see the **whole** set, and there an edge into the void is an
/// error. Without this counter-check it would stay open whether the leniency
/// applies everywhere.
#[test]
fn the_strict_view_still_rejects_a_foreign_target() {
    let set = tg_defs::from_str(FOREIGN_TARGET).expect("the fixture has to parse");

    assert!(matches!(
        DependencyGraph::from_workloads(set.workloads()),
        Err(GraphError::UnknownTarget { .. })
    ));
}

// Here stood `the_node_view_still_rejects_an_ordering_cycle` and
// `the_node_view_still_rejects_a_self_reference`. They demanded an `Err` from
// the node view — and precisely that is what **ADR-0062** abolished, after it
// had been measured what an `Err` costs at this place: `once` passed it on, the
// agent ended, a supervisor made a crash loop out of it.
//
// Their statement has not been lost but has become more precise: both cases
// stay findings and still cost their workload. They now stand as
// `an_ordering_cycle_isolates_its_members_and_leaves_the_rest` and
// `a_self_reference_isolates_only_its_own_workload` further below — with the
// assurance that was missing before: that the uninvolved one keeps running.

// ------------------------------- The node view isolates (ADR-0062) ---

/// The node view **cannot** fail (ADR-0062, determination 1).
fn node_view(xml: &str) -> (DependencyGraph, Vec<tg_model::graph::Isolated>) {
    let set = tg_defs::from_str(xml).expect("the fixture has to parse");
    DependencyGraph::from_local(set.workloads())
}

/// **A cycle costs its members, not the node** (ADR-0062, determination 2).
///
/// Measured, it previously cost the **agent**: `from_local` gave `Err`, `once`
/// passed it on, the process ended — and a supervisor made a crash loop out of
/// it.
#[test]
fn an_ordering_cycle_isolates_its_members_and_leaves_the_rest() {
    let (graph, isolated) = node_view(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="a" kind="service">
    <image reference="example.com/a:1"/>
    <dependencies><after ref="b"/></dependencies>
  </workload>
  <workload name="b" kind="service">
    <image reference="example.com/b:1"/>
    <dependencies><after ref="a"/></dependencies>
  </workload>
  <workload name="sound" kind="service">
    <image reference="example.com/sound:1"/>
  </workload>
</workloads>"#,
    );

    let mut names: Vec<&str> = isolated
        .iter()
        .map(tg_model::graph::Isolated::workload)
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["a", "b"], "both members of the cycle");

    // **The actual statement:** the uninvolved one is still reconciled.
    assert_eq!(graph.start_order(), vec!["sound"]);
}

/// **A doubly declared name isolates both bearers.**
///
/// Which one is meant nobody knows; taking one of them would mean guessing —
/// and the wrong one would then run with the right one's definition.
#[test]
fn a_duplicate_name_isolates_every_bearer() {
    let (graph, isolated) = node_view(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="duplicate" kind="service">
    <image reference="example.com/one:1"/>
  </workload>
  <workload name="duplicate" kind="service">
    <image reference="example.com/two:2"/>
  </workload>
  <workload name="sound" kind="service">
    <image reference="example.com/sound:1"/>
  </workload>
</workloads>"#,
    );

    assert_eq!(
        isolated
            .iter()
            .map(tg_model::graph::Isolated::workload)
            .collect::<Vec<_>>(),
        vec!["duplicate"],
        "the name is named once, not per bearer"
    );
    assert_eq!(graph.start_order(), vec!["sound"]);
}

/// A self-reference costs exactly the workload that declares it.
#[test]
fn a_self_reference_isolates_only_its_own_workload() {
    let (graph, isolated) = node_view(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="crooked" kind="service">
    <image reference="example.com/crooked:1"/>
    <dependencies><requires ref="crooked"/></dependencies>
  </workload>
  <workload name="sound" kind="service">
    <image reference="example.com/sound:1"/>
  </workload>
</workloads>"#,
    );

    assert_eq!(
        isolated
            .iter()
            .map(tg_model::graph::Isolated::workload)
            .collect::<Vec<_>>(),
        vec!["crooked"]
    );
    assert_eq!(graph.start_order(), vec!["sound"]);
}

/// **The counter-check:** a sound set isolates nothing.
///
/// Without it it would stay open whether the isolation ever lets anything
/// through — and a node that isolates everything would look exactly like one
/// that works carefully in the report.
#[test]
fn a_sound_set_isolates_nothing() {
    let (graph, isolated) = node_view(CHAIN);

    assert!(isolated.is_empty(), "what was isolated: {isolated:?}");
    assert_eq!(graph.start_order(), vec!["db", "cache", "api"]);
}

/// An edge onto an isolated target becomes a **foreign** edge: it neither
/// orders nor drags anything along (ADR-0061, determination 1).
///
/// That is the right reading and no side effect: the node knows nothing
/// reliable about the isolated workload, so it must conclude nothing from it.
/// In particular it must not drag a healthy dependant along.
#[test]
fn an_edge_to_an_isolated_workload_falls_silent() {
    let (graph, isolated) = node_view(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="crooked" kind="service">
    <image reference="example.com/crooked:1"/>
    <dependencies><requires ref="crooked"/></dependencies>
  </workload>
  <workload name="depends-on-it" kind="service">
    <image reference="example.com/x:1"/>
    <dependencies><after ref="crooked"/><requires ref="crooked"/></dependencies>
  </workload>
</workloads>"#,
    );

    assert_eq!(isolated.len(), 1);
    assert_eq!(graph.start_order(), vec!["depends-on-it"]);
    assert!(
        graph
            .cascade_stop(&[("crooked", Inactivity::Failed)])
            .is_empty(),
        "an isolated workload must not drag a healthy one along"
    );
}

/// A target is inactive for **two** reasons, not three.
///
/// The tripwire to **ADR-0089**: a requirement edge is satisfied when the
/// target **runs** — readiness is none of its business (ADR-0080 takes effect
/// over the resolution, ADR-0013). A third value would be the entry into the
/// counter-decision through the back door: it would hold a dependant back, and
/// a mistyped port in `<readiness port="…"/>` would thereby be one line of XML
/// that halts a whole chain.
///
/// The `match` is exhaustive and without a `_` arm: whoever adds a value gets a
/// compile error instead of a silent behaviour change — and has the
/// conversation.
#[test]
fn a_target_is_inactive_for_exactly_two_reasons() {
    fn word(state: Inactivity) -> &'static str {
        match state {
            Inactivity::Failed => "failed",
            Inactivity::Stopped => "stopped",
        }
    }

    assert_eq!(word(Inactivity::Failed), "failed");
    assert_eq!(word(Inactivity::Stopped), "stopped");
}
