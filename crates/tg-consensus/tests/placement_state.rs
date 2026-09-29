//! Placement in the replicated state and the scheduler step (phase 6).
//!
//! `tg-model/tests/placement.rs` checks the rules. Here stands what becomes of
//! them in the log: how instances, capacity and the ingest check behave in the
//! state — and that a second scheduler step proposes nothing more.

use tg_consensus::{ClusterState, Command, Outcome, Rejection, Resources, Topology, step};

fn document(name: &str, placement: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\">\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         {placement}\
         </workload>\n\
         </workloads>\n"
    )
}

fn upsert(name: &str, placement: &str) -> Command {
    Command::UpsertWorkload {
        document: document(name, placement),
    }
}

fn node(name: &str, rack: &str, cpu: u64) -> Command {
    Command::UpsertNode {
        name: name.to_owned(),
        topology: Topology {
            site: "fra".to_owned(),
            hall: "h1".to_owned(),
            rack: rack.to_owned(),
        },
        capacity: Resources::default().with(Resources::CPU_MILLICORES, cpu),
        reserved: tg_consensus::Resources::default(),
        source: tg_consensus::Origin::Operator,
    }
}

fn cluster(racks: &[(&str, &str)]) -> ClusterState {
    let mut state = ClusterState::default();
    for (name, rack) in racks {
        assert_eq!(state.apply(&node(name, rack, 4000)), Outcome::Applied);
    }
    state
}

/// A node's capacity lands in the state and comes back.
#[test]
fn a_node_carries_its_capacity() {
    let state = cluster(&[("a", "r1")]);
    let entry = state.node("a").expect("node");

    assert_eq!(entry.topology().rack, "r1");
    assert_eq!(entry.capacity().get(Resources::CPU_MILLICORES), 4000);
    assert_eq!(
        entry.capacity().get("device/nvidia.com-gpu"),
        0,
        "an unlisted resource is not present, not unbounded"
    );
}

/// Instances are assigned individually and read individually.
#[test]
fn instances_are_assigned_and_read_separately() {
    let mut state = cluster(&[("a", "r1"), ("b", "r2")]);
    assert_eq!(state.apply(&upsert("api", "")), Outcome::Applied);

    for (instance, node) in [(0, "a"), (1, "b")] {
        assert_eq!(
            state.apply(&Command::AssignPlacement {
                workload: "api".to_owned(),
                instance,
                node: node.to_owned(),
            }),
            Outcome::Applied
        );
    }

    assert_eq!(state.instance("api", 0), Some("a"));
    assert_eq!(state.instance("api", 1), Some("b"));
    assert_eq!(state.instance("api", 2), None);
    assert_eq!(state.instances("api"), [(0, "a"), (1, "b")]);
    assert_eq!(state.placement("api"), Some("a"), "the zeroth instance");
}

/// A deregistered node takes exactly its own instances with it, not those of
/// the others.
#[test]
fn removing_a_node_takes_only_its_own_instances() {
    let mut state = cluster(&[("a", "r1"), ("b", "r2")]);
    assert_eq!(state.apply(&upsert("api", "")), Outcome::Applied);
    for (instance, node) in [(0, "a"), (1, "b")] {
        state.apply(&Command::AssignPlacement {
            workload: "api".to_owned(),
            instance,
            node: node.to_owned(),
        });
    }

    assert_eq!(
        state.apply(&Command::RemoveNode {
            name: "a".to_owned()
        }),
        Outcome::Applied
    );

    assert_eq!(state.instances("api"), [(1, "b")]);
}

/// Fewer instances in the definition clear the surplus assignments away.
#[test]
fn shrinking_the_replica_count_drops_the_surplus() {
    let mut state = cluster(&[("a", "r1"), ("b", "r2")]);
    assert_eq!(
        state.apply(&upsert("api", "<placement replicas=\"2\"/>")),
        Outcome::Applied
    );
    for (instance, node) in [(0, "a"), (1, "b")] {
        state.apply(&Command::AssignPlacement {
            workload: "api".to_owned(),
            instance,
            node: node.to_owned(),
        });
    }
    assert_eq!(state.instances("api").len(), 2);

    assert_eq!(
        state.apply(&upsert("api", "<placement replicas=\"1\"/>")),
        Outcome::Applied
    );

    assert_eq!(
        state.instances("api"),
        [(0, "a")],
        "the second instance should have gone with it"
    );
}

/// **A setting contradictory in itself is refused at ingest** (ADR-0011).
#[test]
fn a_contradictory_placement_is_rejected_at_ingest() {
    let mut state = cluster(&[("a", "r1")]);

    let outcome = state.apply(&upsert(
        "ledger",
        "<placement replicas=\"2\"><pin node=\"a\"/></placement>",
    ));

    let Outcome::Rejected(Rejection::UnplaceableDefinition { workload, detail }) = outcome else {
        panic!("expected UnplaceableDefinition, got {outcome:?}");
    };
    assert_eq!(workload, "ledger");
    assert!(detail.contains("nailed down"), "{detail}");

    assert!(
        state.workload("ledger").is_none(),
        "the refused definition landed in the state anyway"
    );
}

/// A valid setting goes through — the counter-proof.
#[test]
fn a_sound_placement_passes_ingest() {
    let mut state = cluster(&[("a", "r1")]);

    assert_eq!(
        state.apply(&upsert(
            "ledger",
            "<placement><pin node=\"a\"/></placement>"
        )),
        Outcome::Applied
    );
    assert_eq!(
        state.apply(&upsert(
            "api",
            "<placement replicas=\"3\" spread=\"hall\"/>"
        )),
        Outcome::Applied
    );
}

// --- The scheduler step -----------------------------------------------------

/// The step proposes exactly the missing assignments.
#[test]
fn the_step_proposes_what_is_missing() {
    let mut state = cluster(&[("a", "r1"), ("b", "r2")]);
    state.apply(&upsert("api", "<placement replicas=\"2\"/>"));

    let step = step(&state);

    assert_eq!(step.commands.len(), 2, "{:?}", step.commands);
    assert!(step.rejected.is_empty());
    for command in &step.commands {
        assert!(matches!(command, Command::AssignPlacement { .. }));
    }
}

/// **Level-triggered:** after applying, the step proposes nothing more.
///
/// The property without which a scheduler runs in circles — it would write the
/// same commands into the log again at every pass, and the log would be full of
/// repetitions that look like changes in the audit trail.
#[test]
fn a_second_step_proposes_nothing() {
    let mut state = cluster(&[("a", "r1"), ("b", "r2")]);
    state.apply(&upsert("api", "<placement replicas=\"2\"/>"));

    for command in step(&state).commands {
        assert_eq!(state.apply(&command), Outcome::Applied);
    }

    let second = step(&state);
    assert!(second.is_empty(), "{:?}", second.commands);
}

/// **The loss of a node leads to one replacement assignment — and only to
/// that.**
///
/// The surviving instance is not touched (ADR-0011: no auto-rebalancing); the
/// lost one gets a node in a third rack.
#[test]
fn losing_a_node_yields_exactly_one_replacement() {
    let mut state = cluster(&[("a", "r1"), ("b", "r2"), ("c", "r3")]);
    state.apply(&upsert("api", "<placement replicas=\"2\"/>"));
    for command in step(&state).commands {
        state.apply(&command);
    }

    let before = state.instances("api");
    assert_eq!(before.len(), 2);
    let lost = before[0].1.to_owned();
    let survivor = before[1].1.to_owned();

    assert_eq!(
        state.apply(&Command::RemoveNode { name: lost.clone() }),
        Outcome::Applied
    );

    let step = step(&state);
    assert_eq!(step.commands.len(), 1, "{:?}", step.commands);
    let Command::AssignPlacement { instance, node, .. } = &step.commands[0] else {
        panic!("expected AssignPlacement");
    };
    assert_eq!(*instance, 0, "the lost instance");
    assert_ne!(
        *node, survivor,
        "the replacement instance does not belong beside the surviving one"
    );
    assert_ne!(*node, lost);
}

/// What is not placeable is reported — not kept quiet.
#[test]
fn the_step_reports_what_it_could_not_place() {
    let mut state = cluster(&[("a", "r1")]);
    state.apply(&upsert("api", "<placement replicas=\"3\"/>"));

    let step = step(&state);

    assert_eq!(step.commands.len(), 1);
    assert_eq!(step.rejected.len(), 2, "{:?}", step.rejected);
    assert!(step.rejected[0].to_string().contains("api"));
}

/// Without nodes the step proposes nothing and does not panic.
#[test]
fn a_cluster_without_nodes_proposes_nothing() {
    let mut state = ClusterState::default();
    state.apply(&upsert("api", ""));

    let step = step(&state);

    assert!(step.commands.is_empty());
    assert_eq!(step.rejected.len(), 1);
}

/// The step is deterministic: the same state yields the same commands.
#[test]
fn the_step_is_deterministic() {
    let mut state = cluster(&[("a", "r1"), ("b", "r2"), ("c", "r3")]);
    state.apply(&upsert("api", "<placement replicas=\"2\"/>"));
    state.apply(&upsert("db", "<placement replicas=\"3\"/>"));

    assert_eq!(step(&state).commands, step(&state).commands);
}

// --- The surcharge for the sidecar (ADR-0067) -------------------------------

/// A workload with `<mesh>` and an explicit resource request.
fn mesh_member(name: &str, millicores: u32) -> Command {
    Command::UpsertWorkload {
        document: format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
             <workload name=\"{name}\" kind=\"service\">\n\
             <image reference=\"example.com/{name}:1\"/>\n\
             <resources><cpu millicores=\"{millicores}\"/></resources>\n\
             <mesh port=\"8443\"/>\n\
             </workload>\n\
             </workloads>\n"
        ),
    }
}

/// **A mesh member costs more than its `<resources>`** (ADR-0067).
///
/// Until here the planner did **not see** the sidecar at all: it arises on the
/// node (ADR-0059) and stands in no log. The consequence went in the dangerous
/// direction — overpacked nodes, a too optimistic reserve (ADR-0047) and a metric
/// that reports more room than there is at the outage.
///
/// The node offers 1000 millicores, the workload wants 600. Without a surcharge
/// it fits; with 500 no longer. That is exactly the difference that matters — and
/// the counter-check stands beside it.
#[test]
fn a_mesh_member_costs_more_than_its_declared_resources() {
    let mut state = ClusterState::default();
    state.apply(&node("node-1", "r1", 1_000));
    // **Check the outcome, not the variant.** A document the state machine
    // refuses would yield an empty demand -- and the test would be green without
    // having checked anything.
    assert_eq!(
        state.apply(&mesh_member("api", 600)),
        Outcome::Applied,
        "the document must be accepted"
    );

    // Without the surcharge: it fits.
    assert_eq!(step(&state).rejected.len(), 0, "600 of 1000 fit");

    state.apply(&Command::SetSidecarOverhead {
        resources: Resources::default().with(Resources::CPU_MILLICORES, 500),
    });

    let out = step(&state);
    assert!(
        out.commands.is_empty() && !out.rejected.is_empty(),
        "with the sidecar it no longer fits: {out:?}"
    );
}

/// **And a workload without `<mesh>` does not pay it.**
///
/// The criterion is exactly the one on which ADR-0059 hangs the derivation —
/// whoever gets no sidecar pays for none either. Without this counter-check the
/// test above would be green even if the surcharge applied to **everyone**.
#[test]
fn a_workload_without_a_mesh_pays_no_surcharge() {
    let mut state = ClusterState::default();
    state.apply(&node("node-1", "r1", 1_000));
    state.apply(&upsert("batch", ""));
    state.apply(&Command::SetSidecarOverhead {
        resources: Resources::default().with(Resources::CPU_MILLICORES, 5_000),
    });

    assert_eq!(
        step(&state).rejected.len(),
        0,
        "a workload without a mesh gets no sidecar and pays for none"
    );
}

/// **Without a declaration the cluster computes as before.**
///
/// The default is zero. An invented number would retroactively take room from
/// the planner and would leave workloads lying after an upgrade that ran before —
/// the same consideration as with `reserved` (ADR-0047).
#[test]
fn without_a_declaration_nothing_changes() {
    let mut state = ClusterState::default();
    state.apply(&node("node-1", "r1", 1_000));
    state.apply(&mesh_member("api", 900));

    assert_eq!(step(&state).rejected.len(), 0);
}

/// **The metric computes with the same surcharge as the planner** (ADR-0067,
/// ADR-0047).
///
/// `step` and `headroom` share `inputs()`, and the doc block there says why too:
/// *"Two derivations would be two opportunities to count differently — and then
/// the metric would say something about a cluster the planner does not know."*
/// That was not guarded.
///
/// Without this assurance somebody could give the metric a derivation of its own,
/// and the surcharge would disappear from it — the number would stay precise and
/// would be skewed again, that is, exactly the state ADR-0067 abolishes.
#[test]
fn the_headroom_counts_the_surcharge_too() {
    let mut state = ClusterState::default();
    state.apply(&node("node-1", "r1", 4_000));
    state.apply(&node("node-2", "r2", 4_000));
    assert_eq!(state.apply(&mesh_member("api", 600)), Outcome::Applied);
    state.apply(&Command::SetSidecarOverhead {
        resources: Resources::default().with(Resources::CPU_MILLICORES, 50),
    });

    // Place it so that the instance **lies** in its domain.
    for command in step(&state).commands {
        assert_eq!(state.apply(&command), Outcome::Applied);
    }

    let risk = tg_consensus::schedule::headroom(&state, tg_defs::DomainLevel::Rack)
        .into_iter()
        .find(|domain| domain.at_risk.get(Resources::CPU_MILLICORES) > 0)
        .expect("a domain carries the instance");

    assert_eq!(
        risk.at_risk.get(Resources::CPU_MILLICORES),
        650,
        "600 declared plus 50 sidecar -- otherwise the metric reports more room \
         than there is at the outage"
    );
}
