//! Tests of the projection (ADR-0004, phase 4; ADR-0030 for the implementation).

use tg_defs::DependencyKind;
use tg_store::session::{REPORT_EVERY_SECONDS, REPORT_WINDOW_SECONDS};
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
      <wants ref="metrics"/>
    </dependencies>
  </workload>
  <workload name="cache" kind="service">
    <image reference="example.com/cache:1"/>
    <dependencies><after ref="db"/><requires ref="db"/></dependencies>
  </workload>
  <workload name="db" kind="service">
    <image reference="example.com/db:1"/>
  </workload>
  <workload name="metrics" kind="service">
    <image reference="example.com/metrics:1"/>
  </workload>
</workloads>"#;

fn projection() -> Projection {
    let set = tg_defs::from_str(SET).expect("fixture has to parse");
    let projection = Projection::new();
    projection.materialize(set.workloads());
    projection
}

#[test]
fn materialize_creates_one_record_per_workload() {
    let projection = projection();

    let names: Vec<String> = projection
        .workloads()
        .into_iter()
        .map(|record| record.name)
        .collect();

    assert_eq!(names, vec!["api", "cache", "db", "metrics"]);
}

#[test]
fn records_carry_the_image_from_the_definition() {
    let projection = projection();

    let api = projection
        .workloads()
        .into_iter()
        .find(|record| record.name == "api")
        .expect("api");

    assert_eq!(api.image, "example.com/api:1");
}

/// Dependencies lie as edges per kind, not as foreign-key fields.
#[test]
fn dependencies_are_traversable_edges_per_kind() {
    let projection = projection();

    assert_eq!(
        projection.targets_of("api", DependencyKind::Requires),
        vec!["cache"]
    );
    assert_eq!(
        projection.targets_of("api", DependencyKind::Wants),
        vec!["metrics"]
    );
}

/// The edge kinds must not mix — otherwise the axis separation from ADR-0009
/// would be lost again in the projection.
#[test]
fn edge_kinds_stay_separate() {
    let projection = projection();

    let requires = projection.targets_of("api", DependencyKind::Requires);
    let wants = projection.targets_of("api", DependencyKind::Wants);

    assert!(!requires.contains(&"metrics".to_owned()));
    assert!(!wants.contains(&"cache".to_owned()));
}

#[test]
fn workload_without_dependencies_has_no_edges() {
    let projection = projection();

    assert!(
        projection
            .targets_of("db", DependencyKind::Requires)
            .is_empty()
    );
}

/// Actual is the eventual path from ADR-0004: straight into the projection,
/// without a detour over consensus.
///
/// **Without an observation there is no entry** — not one with `Unknown`.
/// Handing out ignorance as an entry would mean handing it out as a measurement;
/// the coarse view on it is `worst_of`, and that says `Unknown`.
#[test]
fn actual_status_starts_unobserved_and_can_be_reported() {
    let projection = projection();

    assert!(
        projection.actual_states().is_empty(),
        "without a report there is no observation"
    );
    assert_eq!(projection.worst_of("api"), ActualStatus::Unknown);

    report(&projection, &[("api", 0, ActualStatus::Running)]);

    let after = projection.actual_states();
    assert_eq!(
        after.get(&("api".to_owned(), 0)),
        Some(&ActualStatus::Running)
    );
    assert_eq!(projection.worst_of("api"), ActualStatus::Running);
}

/// Materializing is completely replacing. A workload that disappears from the
/// desired state must not stay behind as a dead entry.
#[test]
fn materialize_replaces_instead_of_accumulating() {
    let projection = projection();

    let smaller = tg_defs::from_str(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="db" kind="service"><image reference="example.com/db:1"/></workload>
</workloads>"#,
    )
    .expect("parses");

    projection.materialize(smaller.workloads());

    let names: Vec<String> = projection
        .workloads()
        .into_iter()
        .map(|record| record.name)
        .collect();

    assert_eq!(names, vec!["db"], "old records have to disappear");
}

/// The projection holds nothing whose loss hurts (ADR-0004) — it is rebuildable
/// from the desired state at any time.
#[test]
fn projection_is_rebuildable_from_scratch() {
    let set = tg_defs::from_str(SET).expect("parses");

    let first = Projection::new();
    first.materialize(set.workloads());
    let expected = first.workloads();

    // A completely new instance, no shared state.
    let second = Projection::new();
    second.materialize(set.workloads());

    assert_eq!(second.workloads(), expected);
}

/// **Instances of the same workload are told apart.**
///
/// That is the property at issue: until here the projection carried **one**
/// actual state per workload, and several instances on one node had to be
/// summarized. Whoever derived DNS health from it took a dead instance for all —
/// or a running one for all.
#[test]
fn instances_of_the_same_workload_are_told_apart() {
    let projection = projection();

    report(
        &projection,
        &[
            ("api", 0, ActualStatus::Running),
            ("api", 1, ActualStatus::Failed),
            ("api", 2, ActualStatus::Running),
        ],
    );

    let states = projection.actual_states();
    assert_eq!(
        states.get(&("api".to_owned(), 0)),
        Some(&ActualStatus::Running)
    );
    assert_eq!(
        states.get(&("api".to_owned(), 1)),
        Some(&ActualStatus::Failed)
    );
    assert_eq!(
        states.get(&("api".to_owned(), 2)),
        Some(&ActualStatus::Running)
    );
}

/// The coarse view takes the **worst** state.
///
/// The worst and not the best: whoever derives health from it shall in doubt
/// offer nothing rather than something dead. The rule lies with the data it
/// judges — two callers could otherwise interpret it differently.
#[test]
fn the_coarse_view_takes_the_worst_instance() {
    let projection = projection();

    // The report is replacing per node, so it grows along here — unlike before,
    // where three individual reports built on each other.
    report(&projection, &[("api", 0, ActualStatus::Running)]);
    assert_eq!(projection.worst_of("api"), ActualStatus::Running);

    report(
        &projection,
        &[
            ("api", 0, ActualStatus::Running),
            ("api", 1, ActualStatus::Stopped),
        ],
    );
    assert_eq!(projection.worst_of("api"), ActualStatus::Stopped);

    report(
        &projection,
        &[
            ("api", 0, ActualStatus::Running),
            ("api", 1, ActualStatus::Stopped),
            ("api", 2, ActualStatus::Failed),
        ],
    );
    assert_eq!(projection.worst_of("api"), ActualStatus::Failed);

    // And the running instance stays running — the coarse view hides it, it does
    // not delete it.
    assert_eq!(
        projection.actual_states().get(&("api".to_owned(), 0)),
        Some(&ActualStatus::Running)
    );
}

/// An **empty** report clears its node's map.
///
/// That is the edge case of the reaper, and it is reachable: a node whose last
/// instance disappears reports an empty list — `publish` calls unconditionally.
/// Without this branch the last map would stay standing forever, i.e. exactly
/// the state the replacing semantics abolishes.
///
/// The opposite direction carries it: **another** node's map stays. Without it
/// an empty report that clears everything would be green too.
#[test]
fn an_empty_report_clears_the_map_of_its_node() {
    let projection = projection();
    projection.report_instances("n1", vec![("api".to_owned(), 0, ActualStatus::Running)]);
    projection.report_instances("n2", vec![("cache".to_owned(), 0, ActualStatus::Running)]);

    projection.report_instances("n1", Vec::new());

    let states = projection.actual_states();
    assert_eq!(
        states.get(&("api".to_owned(), 0)),
        None,
        "the empty report clears its node"
    );
    assert_eq!(
        states.get(&("cache".to_owned(), 0)),
        Some(&ActualStatus::Running),
        "and only its own"
    );
}

/// A report **replaces** its node's map — and only that one.
///
/// That is the semantics of the five neighbours (`stale`, `unready`, `failures`,
/// `capacity`, `endpoints`), and it is at the same time the **reaper**: an
/// instance a node no longer names is gone. Before, the report was additive, and
/// the only reaper was `materialize` — in the agent, which materializes exactly
/// once, i.e. none at all.
///
/// The opposite direction stands beside it: a report from **another** node
/// leaves the first map alone.
#[test]
fn a_report_replaces_the_map_of_its_node_and_only_that_one() {
    let projection = projection();

    projection.report_instances(
        "n1",
        vec![
            ("api".to_owned(), 0, ActualStatus::Running),
            ("api".to_owned(), 1, ActualStatus::Running),
        ],
    );
    projection.report_instances("n2", vec![("cache".to_owned(), 0, ActualStatus::Running)]);

    // The second report from `n1` no longer names instance 1 — it is gone.
    projection.report_instances("n1", vec![("api".to_owned(), 0, ActualStatus::Failed)]);

    let states = projection.actual_states();
    assert_eq!(
        states.get(&("api".to_owned(), 1)),
        None,
        "what a node no longer reports is gone"
    );
    assert_eq!(
        states.get(&("cache".to_owned(), 0)),
        Some(&ActualStatus::Running),
        "another node's map stays untouched"
    );
    assert_eq!(
        states.get(&("api".to_owned(), 0)),
        Some(&ActualStatus::Failed),
        "what it still reports applies in the new version"
    );
    assert_eq!(states.len(), 2, "and nothing else");
}

/// An unknown workload creates no record — with an instance number either.
///
/// The witness was called `an_unknown_workload_is_refused_for_any_instance` and
/// demanded that the report be **discarded**. Since the instance map lies beside
/// `Inner` it is **held** — and that is the form of the five neighbours:
/// `report_failures`, `report_stale`, `report_unready` and `report_endpoints`
/// likewise do not filter against the workload list. A comparison there would be
/// a second truth beside the log (ADR-0004): which instances there are is said
/// by the reporter.
///
/// It is without consequence because no reader searches the raw view by name,
/// and self-healing because the same node's next report replaces it.
///
/// What **stays** is the promise at issue: no workload arises that nobody
/// wanted.
#[test]
fn an_unknown_workload_creates_no_record() {
    let projection = projection();
    let before = projection.workloads();

    for instance in [0, 1, 99] {
        report(&projection, &[("fremd", instance, ActualStatus::Running)]);
        assert_eq!(projection.workloads(), before, "instance {instance}");
    }
}

/// A node that missed **one** report still counts as present (ADR-0064).
///
/// That is the property for whose sake the report cadence is a third of the
/// lease. The leader renews the active-role lease only for a node from which it
/// currently has a report; if the window held only a single one, a single writer
/// would lose its active role at every missed heartbeat — not at a partition.
///
/// That is how it was: cadence and window both stood at 15 s, in two different
/// crates, and the comment on the window claimed the opposite.
#[test]
fn a_node_that_missed_one_report_still_counts_as_present() {
    let projection = Projection::default();

    // The last report that arrived. The next stays away; the leader looks at the
    // point in time at which the one after that would be due.
    projection.report_seen("node-1", 1_000);
    let missed_one = 1_000 + 2 * REPORT_EVERY_SECONDS;

    assert!(
        projection
            .reporting_since(missed_one - REPORT_WINDOW_SECONDS)
            .contains("node-1"),
        "a single missed report takes the node out of the set — the single \
         writer then fences itself because of a dropout"
    );
}

/// The counter-check, and it carries half the promise: a node that is silent
/// **longer than the window** no longer counts.
///
/// Without it the test above would be green with an infinitely wide window too —
/// and then the leader would renew a dead holder's lease forever. That is the
/// fence from ADR-0010.
#[test]
fn a_node_silent_beyond_the_window_stops_counting() {
    let projection = Projection::default();

    projection.report_seen("node-1", 1_000);
    let long_silent = 1_000 + REPORT_WINDOW_SECONDS + 1;

    assert!(
        !projection
            .reporting_since(long_silent - REPORT_WINDOW_SECONDS)
            .contains("node-1"),
        "a silent node still counts as present — the leader would renew a dead \
         holder's lease"
    );
}

/// **Which instances run stale comes from the reports** (ADR-0070).
///
/// A node's report is the **complete** statement about its instances — so
/// replacing. Additive it would be an entry a restart does not take away: the
/// deviation would be repaired and the finding would still stand there.
#[test]
fn a_report_replaces_what_a_node_said_about_stale_instances() {
    let projection = Projection::new();

    projection.report_stale("node-a", vec![("api".to_owned(), 0), ("api".to_owned(), 2)]);
    projection.report_stale("node-b", vec![("ledger".to_owned(), 1)]);

    assert_eq!(projection.stale_instances("api"), vec![0, 2]);
    assert_eq!(projection.stale_instances("ledger"), vec![1]);
    assert!(
        projection.stale_instances("ruhig").is_empty(),
        "a workload nobody reported is not stale"
    );

    // The same node now reports less — the restart has taken effect.
    projection.report_stale("node-a", vec![("api".to_owned(), 2)]);
    assert_eq!(
        projection.stale_instances("api"),
        vec![2],
        "the same node's old statement should have been replaced"
    );

    // And nothing at all any more: then nothing stands there either.
    projection.report_stale("node-a", Vec::new());
    assert!(
        projection.stale_instances("api").is_empty(),
        "after the restart no finding may be left over"
    );
    assert_eq!(
        projection.stale_instances("ledger"),
        vec![1],
        "and one node's report says nothing about another"
    );
}

// =========================== The endpoints of foreign workloads (ADR-0073)

/// **The health comes from the same node's report.**
///
/// ADR-0013 resolves only healthy endpoints. The address is reported by the
/// node, the state it reports too — merging them here keeps `slice_for` a pure
/// function over **one** input.
#[test]
fn a_reported_endpoint_carries_the_health_of_its_instance() {
    let projection = projection();
    projection.report_endpoints(
        "node-a",
        vec![
            ("api".to_owned(), 0, "10.42.1.5".parse().expect("address")),
            ("api".to_owned(), 1, "10.42.1.6".parse().expect("address")),
        ],
    );
    // The same node as the endpoints, in **one** report: the health comes from
    // the same node's report, and `report_instances` replaces per node.
    projection.report_instances(
        "node-a",
        vec![
            ("api".to_owned(), 0, ActualStatus::Running),
            ("api".to_owned(), 1, ActualStatus::Failed),
        ],
    );

    let reported = projection.reported_endpoints();
    let endpoints = reported.get("node-a").expect("node-a");

    assert_eq!(endpoints.len(), 2);
    assert!(
        endpoints[0].healthy,
        "the running instance counts as unhealthy"
    );
    assert!(
        !endpoints[1].healthy,
        "the failed instance counts as healthy"
    );
}

/// **Nothing heard yet is not an empty entry.**
///
/// The same distinction as with the stale instances: a node nobody knows
/// anything about does not appear at all — otherwise it would not be separable
/// from a node without instances.
#[test]
fn a_node_that_reported_nothing_does_not_appear() {
    let projection = projection();

    assert!(projection.reported_endpoints().is_empty());

    projection.report_endpoints(
        "node-a",
        vec![("api".to_owned(), 0, "10.42.1.5".parse().expect("address"))],
    );
    assert_eq!(projection.reported_endpoints().len(), 1);

    // And a report without endpoints withdraws the entry: the container is gone
    // (ADR-0058), and an endpoint nobody withdraws would be resolved forever.
    projection.report_endpoints("node-a", Vec::new());
    assert!(projection.reported_endpoints().is_empty());
}

/// **Replacing per node, not additive.**
#[test]
fn a_report_replaces_what_that_node_said_before() {
    let projection = projection();
    projection.report_endpoints(
        "node-a",
        vec![("api".to_owned(), 0, "10.42.1.5".parse().expect("address"))],
    );
    projection.report_endpoints(
        "node-a",
        vec![("api".to_owned(), 0, "10.42.1.9".parse().expect("address"))],
    );

    let reported = projection.reported_endpoints();
    let endpoints = reported.get("node-a").expect("node-a");

    assert_eq!(endpoints.len(), 1, "the old entry stayed standing");
    assert_eq!(endpoints[0].address.to_string(), "10.42.1.9");
}

// ================================ The DNS zone per node (ADR-0013, 0073)

/// **Two nodes with different zones are visible.**
///
/// The zone is a setting per node (`--dns-domain`), and a container always
/// resolves at its **own** resolver — so a bare name works out even with a skew.
/// What does not work out is a workload with a **fully qualified** name in its
/// configuration: the same workload finds its target on one node and not on the
/// other.
///
/// The same situation as with the proxy image (ADR-0059) and the same answer: no
/// decision but **visibility**.
#[test]
fn diverging_dns_zones_are_visible() {
    let projection = projection();

    assert_eq!(projection.distinct_dns_zones(), 0, "nothing reported yet");

    projection.report_dns_zone("node-a", Some("tardigrade.internal"));
    projection.report_dns_zone("node-b", Some("tardigrade.internal"));
    assert_eq!(projection.distinct_dns_zones(), 1, "both the same");

    projection.report_dns_zone("node-b", Some("anders.internal"));
    assert_eq!(
        projection.distinct_dns_zones(),
        2,
        "the skew stays invisible"
    );
}

/// **A node without a node network does not count.**
///
/// It serves no names, so its zone is of no consequence to a client — counting
/// it would produce a deviation that concerns nobody. The same choice as with a
/// node without a mesh and the proxy image.
#[test]
fn a_node_without_a_network_does_not_count_as_a_zone() {
    let projection = projection();
    projection.report_dns_zone("node-a", Some("tardigrade.internal"));
    projection.report_dns_zone("node-b", None);

    assert_eq!(projection.distinct_dns_zones(), 1);
    assert_eq!(projection.reported_dns_zones().len(), 1);

    // And the opposite direction: if its network comes up, it counts again.
    projection.report_dns_zone("node-b", Some("anders.internal"));
    assert_eq!(projection.distinct_dns_zones(), 2);
}

/// **A skew in the security posture is visible** (ADR-0091).
///
/// The range is a setting per node, and **different ranges are expressly no
/// error**: stores and volumes are node-local. What counts is the posture
/// on/off — a node without a mapping beside hardened ones is the finding, and
/// there `uid 0` in the container **is** `uid 0` on the node.
///
/// The third assertion carries the statement: two **different** ranges stay `1`.
/// Without it a count over the values — as with the proxy image — would be green
/// too, and every cluster with two ranges would permanently report a skew that
/// does not exist.
#[test]
fn a_node_without_a_mapping_beside_hardened_ones_is_visible() {
    let projection = projection();

    assert_eq!(
        projection.distinct_userns_postures(),
        0,
        "nothing reported yet"
    );

    projection.report_userns("node-a", Some(100_000));
    projection.report_userns("node-b", Some(100_000));
    assert_eq!(projection.distinct_userns_postures(), 1, "both hardened");

    // **Different ranges are no skew** (ADR-0091).
    projection.report_userns("node-b", Some(200_000));
    assert_eq!(
        projection.distinct_userns_postures(),
        1,
        "two ranges are no finding -- stores and volumes are node-local"
    );

    // And the finding: one without a mapping.
    projection.report_userns("node-c", None);
    assert_eq!(
        projection.distinct_userns_postures(),
        2,
        "an unhardened node beside hardened ones otherwise stays invisible"
    );
}

/// **"Nothing heard yet" is not "does not map".**
///
/// A node from which a report never came is missing entirely; a node that
/// reports and has no mapping stands in it with `None`. Without that separation
/// every freshly started cluster would report a skew as long as not all nodes
/// have reported.
#[test]
fn a_silent_node_is_not_an_unhardened_one() {
    let projection = projection();
    projection.report_userns("node-a", Some(100_000));

    assert_eq!(
        projection.reported_userns().len(),
        1,
        "only the one that spoke"
    );
    assert_eq!(projection.distinct_userns_postures(), 1);

    projection.report_userns("node-b", None);
    assert_eq!(
        projection.reported_userns().get("node-b"),
        Some(&None),
        "whoever reports and does not map stands in it -- with None"
    );
    assert_eq!(projection.distinct_userns_postures(), 2);
}

// ======================= The position this view really knows

/// **Without a note there is no position** — and that is something other than
/// zero.
///
/// An invented number would claim a view that does not exist: an operator would
/// read "position 0" and take an empty projection for the cluster's state.
#[test]
fn a_fresh_projection_knows_no_index() {
    assert_eq!(Projection::new().applied(), None);
}

/// **The note is read as it was set.**
#[test]
fn the_noted_index_is_what_a_reader_gets() {
    let projection = Projection::new();

    projection.note_applied(Some(7));
    assert_eq!(projection.applied(), Some(7));

    // Backwards too: a state freshly materialized from a snapshot may lie behind
    // the old one (ADR-0030 — the projection follows the log, it does not carry
    // it forward).
    projection.note_applied(Some(3));
    assert_eq!(projection.applied(), Some(3));
}

/// **Materializing alone sets no position** — and takes none away either.
///
/// Half the promise, and the more important one: the note belongs to the caller
/// who knows *from what* they materialized. If `materialize` set it itself, each
/// of the thirty callers would have to invent an index — and whoever **deleted**
/// it would turn a valid view into one that claims to know nothing.
#[test]
fn materialising_leaves_the_noted_index_alone() {
    let projection = Projection::new();
    projection.note_applied(Some(7));

    let set = tg_defs::from_str(SET).expect("fixture parses");
    projection.materialize(set.workloads());

    assert_eq!(
        projection.applied(),
        Some(7),
        "materializing touched the position"
    );
}

// ================== Isolated entries, replacing per node (ADR-0062)

/// **A node without a report has no isolated entries.**
#[test]
fn a_node_that_has_not_reported_has_nothing_isolated() {
    assert!(Projection::new().isolated_entries().is_empty());
}

/// **A node's report is the complete statement about it.**
///
/// Replacing and not additive: a repaired document has to **take the finding
/// away**. Additive it would stay standing, and an operator would look for an
/// error they corrected long ago.
///
/// And one node says nothing about another — half the promise, without which the
/// test would be green with a shared list too.
#[test]
fn a_report_replaces_what_that_node_had_isolated() {
    let projection = Projection::new();

    projection.report_isolated("node-a", vec!["kaputt".to_owned()]);
    projection.report_isolated("node-b", vec!["zyklus-x".to_owned()]);
    assert_eq!(
        projection.isolated_entries().get("node-a").cloned(),
        Some(vec!["kaputt".to_owned()])
    );

    // Repaired: the finding disappears — and **only** at this node.
    projection.report_isolated("node-a", Vec::new());
    let all = projection.isolated_entries();
    assert!(
        !all.contains_key("node-a"),
        "a repaired entry has to take the finding away: {all:?}"
    );
    assert_eq!(
        all.get("node-b").cloned(),
        Some(vec!["zyklus-x".to_owned()]),
        "one node's report must not touch another"
    );
}

/// **Why a reconcile failed comes from the reports** (ADR-0015).
///
/// The **class**, not the text: it is enumerable (`RuntimeError::class`) and
/// says *where* to look — `pull`, `mount`, `volume`, `runtime`, … The text names
/// names from a payload and stays in the node's log.
///
/// **Replacing per node**, as with the stale instances: a node's report is the
/// complete statement about its instances. Additive, a finding would stay
/// standing that a successful reconcile has long taken away.
#[test]
fn a_report_replaces_what_a_node_said_about_failures() {
    let projection = Projection::new();

    projection.report_failures(
        "node-a",
        vec![
            ("api".to_owned(), 0, "pull".to_owned()),
            ("api".to_owned(), 2, "mount".to_owned()),
        ],
    );
    projection.report_failures(
        "node-b",
        vec![("ledger".to_owned(), 1, "volume".to_owned())],
    );

    assert_eq!(
        projection.failure_classes("api"),
        [(0, "pull".to_owned()), (2, "mount".to_owned())]
            .into_iter()
            .collect()
    );
    assert_eq!(
        projection.failure_classes("ledger"),
        [(1, "volume".to_owned())].into_iter().collect()
    );
    assert!(
        projection.failure_classes("ruhig").is_empty(),
        "a workload nobody reported has not failed"
    );

    // The same node now reports less — an attempt has taken effect.
    projection.report_failures("node-a", vec![("api".to_owned(), 2, "mount".to_owned())]);
    assert_eq!(
        projection.failure_classes("api"),
        [(2, "mount".to_owned())].into_iter().collect(),
        "the same node's old statement should have been replaced"
    );

    // And nothing at all any more: then nothing stands there either.
    projection.report_failures("node-a", Vec::new());
    assert!(
        projection.failure_classes("api").is_empty(),
        "after a successful reconcile no finding may be left over"
    );
    assert_eq!(
        projection.failure_classes("ledger"),
        [(1, "volume".to_owned())].into_iter().collect(),
        "one node's report says nothing about another"
    );
}

// ==================================== Readiness (ADR-0080)

/// **An unready endpoint counts as unhealthy** — for foreign nodes too.
///
/// `RemoteEndpoint::healthy` was computed by the leader from the reported states
/// alone. An unready instance reports itself as `Running` (ADR-0080,
/// determination 1) — so a **foreign** node offered its address while its **own**
/// withheld it: visibly different answers for the same name, depending on who
/// asks.
///
/// The second assertion carries the test: instance 1 runs and is ready. Without
/// it a computation that reports **everything** as unhealthy would be green too —
/// and then no name would resolve any more.
#[test]
fn an_unready_endpoint_is_not_healthy() {
    let projection = projection();
    projection.report_endpoints(
        "node-a",
        vec![
            ("api".to_owned(), 0, "10.42.1.5".parse().expect("address")),
            ("api".to_owned(), 1, "10.42.1.6".parse().expect("address")),
        ],
    );
    projection.report_instances(
        "node-a",
        vec![
            ("api".to_owned(), 0, ActualStatus::Running),
            ("api".to_owned(), 1, ActualStatus::Running),
        ],
    );
    projection.report_unready("node-a", vec![("api".to_owned(), 0)]);

    let reported = projection.reported_endpoints();
    let endpoints = reported.get("node-a").expect("node-a");

    assert!(
        !endpoints[0].healthy,
        "an unready instance must not be offered (ADR-0013)"
    );
    assert!(
        endpoints[1].healthy,
        "a running, ready instance has to be offered — otherwise no name \
         resolves any more"
    );
}

/// **Replacing per node**, like the stale instances beside it.
///
/// If an instance becomes ready again, it is no longer in the next report and
/// has to be resolved again immediately. Additive it would be a finding no pass
/// withdraws.
///
/// And the second half is the statement about the sender: one node's report says
/// nothing about another.
#[test]
fn readiness_is_replaced_per_node() {
    let projection = projection();
    projection.report_unready("node-a", vec![("api".to_owned(), 0)]);
    projection.report_unready("node-b", vec![("api".to_owned(), 1)]);
    assert_eq!(projection.unready().len(), 2, "both nodes have reported");

    // `node-a` reports nothing any more — `node-b` is untouched.
    projection.report_unready("node-a", Vec::new());

    assert_eq!(
        projection.unready(),
        [("api".to_owned(), 1)].into_iter().collect(),
        "one node's withdrawal must not take another's report with it"
    );
}

/// Materializing does **not** clear the readiness away.
///
/// It does not come from the log (ADR-0030) — it would disappear at every
/// materialization and come back at the next pass, and in the gap the resolution
/// would offer a mute endpoint.
#[test]
fn materialising_keeps_the_readiness() {
    let projection = projection();
    projection.report_unready("node-a", vec![("api".to_owned(), 0)]);

    let set = tg_defs::from_str(SET).expect("fixture has to parse");
    projection.materialize(set.workloads());

    assert_eq!(
        projection.unready(),
        [("api".to_owned(), 0)].into_iter().collect(),
        "an observation does not come from the log and must not follow it"
    );
}
