//! Acceptance tests of the placement (ADR-0011, phase 6).
//!
//! Written **before** the implementation, as CLAUDE.md demands for pure-logic
//! crates, and along the phase's three criteria: workloads spread in conformity
//! with the rules, the loss of a failure domain preserves availability, and a
//! constraint violation is refused.
//!
//! The yardstick is ADR-0011, and it is uncomfortable: **no opaque scoring**.
//! Every choice has to be explainable in one sentence, and two runs with the
//! same input have to give the same answer — otherwise a placement is not
//! auditable, and precisely that is the purpose of the exercise.

use tg_defs::{DomainConstraint, DomainLevel};
use tg_model::placement::{
    Attachment, Demand, Node, PlacementError, Resources, Schedulability, Topology, plan,
};

fn topology(site: &str, hall: &str, rack: &str) -> Topology {
    Topology {
        site: site.to_owned(),
        hall: hall.to_owned(),
        rack: rack.to_owned(),
    }
}

fn node(name: &str, rack: &str, cpu: u64) -> Node {
    Node {
        name: name.to_owned(),
        topology: topology("fra", "h1", rack),
        capacity: Resources::default()
            .with(Resources::CPU_MILLICORES, cpu)
            .with(Resources::MEMORY_BYTES, 64 * 1024 * 1024 * 1024),
        reserved: Resources::default(),
        schedulable: Schedulability::default(),
        attachment: Attachment::default(),
    }
}

fn demand(workload: &str, replicas: u32) -> Demand {
    Demand {
        workload: workload.to_owned(),
        replicas,
        spread: DomainLevel::Rack,
        domains: Vec::new(),
        pin: None,
        stateful: false,
        resources: Resources::default().with(Resources::CPU_MILLICORES, 500),
    }
}

/// A workload with a writable volume (ADR-0027) — not movable.
fn stateful(workload: &str, replicas: u32) -> Demand {
    Demand {
        stateful: true,
        ..demand(workload, replicas)
    }
}

/// A run's nodes, sorted by instance.
fn placed(plan: &tg_model::placement::Plan, workload: &str) -> Vec<String> {
    let mut found: Vec<(u32, String)> = plan
        .assignments
        .iter()
        .filter(|assignment| assignment.workload == workload)
        .map(|assignment| (assignment.instance, assignment.node.clone()))
        .collect();
    found.sort();
    found.into_iter().map(|(_, node)| node).collect()
}

// --- Spreading -------------------------------------------------------------

/// A single instance lands on a node that fits.
#[test]
fn a_single_instance_lands_somewhere_that_fits() {
    let nodes = vec![node("a", "r1", 4000), node("b", "r2", 4000)];
    let result = plan(&[demand("api", 1)], &nodes, &[]);

    assert!(result.rejected.is_empty(), "{:?}", result.rejected);
    assert_eq!(placed(&result, "api").len(), 1);
}

/// **Instances of the same workload lie in different racks.**
///
/// The hard constraint from ADR-0011. Without it a standby would stand beside
/// its primary, and the loss of one rack would take both along.
#[test]
fn instances_of_a_workload_never_share_a_rack() {
    let nodes = vec![
        node("a1", "r1", 4000),
        node("a2", "r1", 4000),
        node("b1", "r2", 4000),
        node("c1", "r3", 4000),
    ];

    let result = plan(&[demand("api", 3)], &nodes, &[]);
    assert!(result.rejected.is_empty(), "{:?}", result.rejected);

    let racks: Vec<&str> = placed(&result, "api")
        .iter()
        .map(|name| match name.as_str() {
            "a1" | "a2" => "r1",
            "b1" => "r2",
            "c1" => "r3",
            other => panic!("unknown node {other}"),
        })
        .collect();

    let mut unique = racks.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), racks.len(), "two instances in the same rack");
}

/// The level is raisable per workload: at `hall` the instances have to lie in
/// different halls, even if the racks would be different.
#[test]
fn the_spread_level_can_be_raised_per_workload() {
    let nodes = vec![
        Node {
            name: "a".to_owned(),
            topology: topology("fra", "h1", "r1"),
            capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
            reserved: Resources::default(),
            schedulable: Schedulability::default(),
            attachment: Attachment::default(),
        },
        Node {
            name: "b".to_owned(),
            topology: topology("fra", "h1", "r2"),
            capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
            reserved: Resources::default(),
            schedulable: Schedulability::default(),
            attachment: Attachment::default(),
        },
    ];

    let mut wanted = demand("api", 2);
    wanted.spread = DomainLevel::Hall;

    let result = plan(&[wanted], &nodes, &[]);

    assert_eq!(placed(&result, "api").len(), 1, "one instance fits");
    assert!(
        matches!(
            result.rejected.first(),
            Some(PlacementError::NoDomainLeft {
                level: DomainLevel::Hall,
                ..
            })
        ),
        "{:?}",
        result.rejected
    );
}

/// More instances than domains: the surplus ones are **refused**, not silently
/// merged.
///
/// That is the difference between a hard and a soft constraint. ADR-0011 says
/// hard — so the scheduler must not say "if need be, then anyway".
#[test]
fn more_instances_than_domains_are_rejected_not_collapsed() {
    let nodes = vec![node("a", "r1", 4000), node("b", "r2", 4000)];

    let result = plan(&[demand("api", 3)], &nodes, &[]);

    assert_eq!(placed(&result, "api").len(), 2);
    assert_eq!(result.rejected.len(), 1);
    assert!(matches!(
        result.rejected[0],
        PlacementError::NoDomainLeft { .. }
    ));
}

// --- Capacity --------------------------------------------------------------

/// What does not fit is not placed.
#[test]
fn a_workload_that_does_not_fit_is_not_placed() {
    let nodes = vec![node("small", "r1", 100)];
    let result = plan(&[demand("api", 1)], &nodes, &[]);

    assert!(placed(&result, "api").is_empty());
    assert!(matches!(result.rejected[0], PlacementError::NoRoom { .. }));
}

/// Occupied capacity counts along — including that from the same planning
/// run.
#[test]
fn capacity_is_counted_across_the_whole_plan() {
    // One node per rack, each with room for exactly two instances.
    let nodes = vec![node("a", "r1", 1000), node("b", "r2", 1000)];

    let result = plan(&[demand("api", 2), demand("db", 2)], &nodes, &[]);

    assert!(result.rejected.is_empty(), "{:?}", result.rejected);
    assert_eq!(placed(&result, "api").len(), 2);
    assert_eq!(placed(&result, "db").len(), 2);

    // A fifth instance no longer fits — 2 x 1000 millicores carry exactly four
    // instances of 500 each.
    //
    // **Which** instance is left over the test deliberately does not say: the
    // planner works the workloads off in name order (not in input order,
    // otherwise the result would hang on who wrote first), and from that it
    // follows here that `db` no longer gets the second instance. That is a
    // consequence of the determinism rule, no statement about precedence — what
    // is nailed down is the balance.
    let result = plan(
        &[demand("api", 2), demand("db", 2), demand("cache", 1)],
        &nodes,
        &[],
    );

    assert_eq!(result.assignments.len(), 4, "{:?}", result.assignments);
    assert_eq!(result.rejected.len(), 1);
    assert!(matches!(result.rejected[0], PlacementError::NoRoom { .. }));

    // And the balance is right: no node is overbooked.
    for node in &nodes {
        let on_node = result
            .assignments
            .iter()
            .filter(|assignment| assignment.node == node.name)
            .count();
        assert!(on_node <= 2, "{} carries {on_node} instances", node.name);
    }
}

/// A resource the node does not carry at all counts as not present.
///
/// The case ADR-0028 needs later: a workload demands a device, the node has
/// none. Without this rule a missing resource would be the same as an unbounded
/// one.
#[test]
fn an_unknown_resource_counts_as_absent() {
    let nodes = vec![node("a", "r1", 4000)];
    let mut wanted = demand("inference", 1);
    wanted.resources = wanted.resources.with("device/nvidia.com-gpu", 1);

    let result = plan(&[wanted], &nodes, &[]);

    assert!(placed(&result, "inference").is_empty());
    assert!(matches!(result.rejected[0], PlacementError::NoRoom { .. }));
}

// --- Domains and pins ------------------------------------------------------

/// A domain constraint excludes everything else.
#[test]
fn a_domain_constraint_excludes_everything_else() {
    let nodes = vec![
        Node {
            name: "fra".to_owned(),
            topology: topology("fra", "h1", "r1"),
            capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
            reserved: Resources::default(),
            schedulable: Schedulability::default(),
            attachment: Attachment::default(),
        },
        Node {
            name: "ber".to_owned(),
            topology: topology("ber", "h1", "r1"),
            capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
            reserved: Resources::default(),
            schedulable: Schedulability::default(),
            attachment: Attachment::default(),
        },
    ];

    let mut wanted = demand("api", 1);
    wanted.domains = vec![DomainConstraint {
        level: DomainLevel::Site,
        value: "ber".to_owned(),
    }];

    let result = plan(&[wanted], &nodes, &[]);
    assert_eq!(placed(&result, "api"), ["ber"]);
}

/// Several settings of the same level are a choice list (OR).
#[test]
fn constraints_of_the_same_level_are_a_choice() {
    let nodes = vec![
        node("a", "r1", 4000),
        node("b", "r2", 4000),
        node("c", "r3", 4000),
    ];

    let mut wanted = demand("api", 2);
    wanted.domains = vec![
        DomainConstraint {
            level: DomainLevel::Rack,
            value: "r1".to_owned(),
        },
        DomainConstraint {
            level: DomainLevel::Rack,
            value: "r3".to_owned(),
        },
    ];

    let result = plan(&[wanted], &nodes, &[]);
    assert!(result.rejected.is_empty(), "{:?}", result.rejected);
    assert_eq!(placed(&result, "api"), ["a", "c"]);
}

/// Settings of different levels apply together (AND).
#[test]
fn constraints_of_different_levels_are_combined() {
    let nodes = vec![
        Node {
            name: "right".to_owned(),
            topology: topology("fra", "h2", "r1"),
            capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
            reserved: Resources::default(),
            schedulable: Schedulability::default(),
            attachment: Attachment::default(),
        },
        Node {
            name: "wrong-hall".to_owned(),
            topology: topology("fra", "h1", "r1"),
            capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
            reserved: Resources::default(),
            schedulable: Schedulability::default(),
            attachment: Attachment::default(),
        },
        Node {
            name: "wrong-site".to_owned(),
            topology: topology("ber", "h2", "r1"),
            capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
            reserved: Resources::default(),
            schedulable: Schedulability::default(),
            attachment: Attachment::default(),
        },
    ];

    let mut wanted = demand("api", 1);
    wanted.domains = vec![
        DomainConstraint {
            level: DomainLevel::Site,
            value: "fra".to_owned(),
        },
        DomainConstraint {
            level: DomainLevel::Hall,
            value: "h2".to_owned(),
        },
    ];

    let result = plan(&[wanted], &nodes, &[]);
    assert_eq!(placed(&result, "api"), ["right"]);
}

/// A pin nails down to exactly one node (ADR-0027).
#[test]
fn a_pin_places_exactly_there() {
    let nodes = vec![node("a", "r1", 4000), node("b", "r2", 4000)];
    let mut wanted = demand("ledger", 1);
    wanted.pin = Some("b".to_owned());

    let result = plan(&[wanted], &nodes, &[]);
    assert_eq!(placed(&result, "ledger"), ["b"]);
}

/// A pin to an unknown node is refused — and **not** placed elsewhere
/// instead.
///
/// The pin is no wish but a statement about a volume that lies only there
/// (ADR-0027). Passing over it would mean separating the workload from its
/// data.
#[test]
fn a_pin_to_an_unknown_node_is_rejected_not_substituted() {
    let nodes = vec![node("a", "r1", 4000)];
    let mut wanted = demand("ledger", 1);
    wanted.pin = Some("gone".to_owned());

    let result = plan(&[wanted], &nodes, &[]);

    assert!(placed(&result, "ledger").is_empty());
    assert!(matches!(
        result.rejected[0],
        PlacementError::PinnedNodeUnknown { .. }
    ));
}

/// A pin with more than one instance is contradictory in itself and is refused
/// at ingest.
#[test]
fn a_pin_with_several_instances_is_contradictory() {
    let mut wanted = demand("ledger", 2);
    wanted.pin = Some("a".to_owned());

    let err = wanted.validate().expect_err("has to fail");
    assert!(matches!(err, PlacementError::PinnedButReplicated { .. }));
}

/// A valid setting gets through the ingest check.
#[test]
fn a_sound_demand_passes_validation() {
    assert!(demand("api", 3).validate().is_ok());

    let mut pinned = demand("ledger", 1);
    pinned.pin = Some("a".to_owned());
    assert!(pinned.validate().is_ok());
}

// --- No auto-rebalancing (ADR-0011) ----------------------------------------

/// **Running instances are never moved unbidden.**
///
/// Not even when an emptier node comes along. ADR-0011 names that expressly:
/// "what is running is never moved unbidden." The reason is not convenience —
/// every move of a single writer is a fencing operation (ADR-0010), and that
/// does not belong in an optimization.
#[test]
fn a_running_instance_is_never_moved_by_itself() {
    let nodes = vec![node("full", "r1", 4000), node("empty", "r2", 4000)];
    let existing = vec![tg_model::placement::Assignment {
        workload: "api".to_owned(),
        instance: 0,
        node: "full".to_owned(),
    }];

    let result = plan(&[demand("api", 1)], &nodes, &existing);

    assert!(result.assignments.is_empty(), "nothing new to do");
    assert_eq!(result.kept, existing);
}

/// **The loss of a failure domain preserves availability.**
///
/// Two instances in two racks; one rack fails. The surviving instance stays
/// where it is, and the lost one is placed anew in a **third** rack — not
/// beside the surviving one.
#[test]
fn losing_a_domain_keeps_the_survivor_and_replaces_the_lost_one() {
    let all = vec![
        node("a", "r1", 4000),
        node("b", "r2", 4000),
        node("c", "r3", 4000),
    ];
    let existing = vec![
        tg_model::placement::Assignment {
            workload: "api".to_owned(),
            instance: 0,
            node: "a".to_owned(),
        },
        tg_model::placement::Assignment {
            workload: "api".to_owned(),
            instance: 1,
            node: "b".to_owned(),
        },
    ];

    // Rack r2 fails: node b is gone.
    let survivors: Vec<Node> = all.into_iter().filter(|n| n.name != "b").collect();
    let result = plan(&[demand("api", 2)], &survivors, &existing);

    assert!(result.rejected.is_empty(), "{:?}", result.rejected);
    assert_eq!(
        result.kept,
        vec![existing[0].clone()],
        "the surviving instance was touched"
    );
    assert_eq!(result.assignments.len(), 1);
    assert_eq!(result.assignments[0].instance, 1);
    assert_eq!(
        result.assignments[0].node, "c",
        "the replacement instance does not belong in the surviving one's rack"
    );
}

/// An assignment to a vanished node is dropped, not kept.
#[test]
fn an_assignment_to_a_vanished_node_is_dropped() {
    let nodes = vec![node("a", "r1", 4000)];
    let existing = vec![tg_model::placement::Assignment {
        workload: "api".to_owned(),
        instance: 0,
        node: "gone".to_owned(),
    }];

    let result = plan(&[demand("api", 1)], &nodes, &existing);

    assert!(result.kept.is_empty());
    assert_eq!(placed(&result, "api"), ["a"]);
}

/// An assignment for a workload that no longer exists is dropped.
#[test]
fn an_assignment_for_a_removed_workload_is_dropped() {
    let nodes = vec![node("a", "r1", 4000)];
    let existing = vec![tg_model::placement::Assignment {
        workload: "gone".to_owned(),
        instance: 0,
        node: "a".to_owned(),
    }];

    let result = plan(&[], &nodes, &existing);

    assert!(result.kept.is_empty());
    assert!(result.assignments.is_empty());
}

/// Too many instances — after a shrunken definition, say — are cleared away,
/// and from the back.
#[test]
fn surplus_instances_are_dropped_from_the_back() {
    let nodes = vec![node("a", "r1", 4000), node("b", "r2", 4000)];
    let existing = vec![
        tg_model::placement::Assignment {
            workload: "api".to_owned(),
            instance: 0,
            node: "a".to_owned(),
        },
        tg_model::placement::Assignment {
            workload: "api".to_owned(),
            instance: 1,
            node: "b".to_owned(),
        },
    ];

    let result = plan(&[demand("api", 1)], &nodes, &existing);

    assert_eq!(result.kept, vec![existing[0].clone()]);
    assert!(result.assignments.is_empty());
}

// --- Determinism -----------------------------------------------------------

/// **The same input yields the same placement.**
///
/// Without that no placement is auditable, and a leader change would re-sort
/// the cluster. The independence from the order of the input is checked too: a
/// node named later is the same node.
#[test]
fn the_same_input_yields_the_same_placement() {
    let nodes = vec![
        node("a", "r1", 4000),
        node("b", "r2", 4000),
        node("c", "r3", 4000),
    ];
    let demands = vec![demand("api", 2), demand("db", 2)];

    let first = plan(&demands, &nodes, &[]);
    let second = plan(&demands, &nodes, &[]);
    assert_eq!(first.assignments, second.assignments);

    let reversed: Vec<Node> = nodes.iter().rev().cloned().collect();
    let third = plan(&demands, &reversed, &[]);
    assert_eq!(
        first.assignments, third.assignments,
        "the order of the nodes changed the placement"
    );

    let reordered = vec![demands[1].clone(), demands[0].clone()];
    let fourth = plan(&reordered, &nodes, &[]);
    let mut left = first.assignments.clone();
    let mut right = fourth.assignments;
    left.sort();
    right.sort();
    assert_eq!(left, right, "the order of the workloads took effect");
}

/// Without nodes nothing is placed — and nothing panics.
#[test]
fn an_empty_cluster_places_nothing() {
    let result = plan(&[demand("api", 1)], &[], &[]);

    assert!(result.assignments.is_empty());
    assert_eq!(result.rejected.len(), 1);
}

/// The rejection names workload and instance — otherwise it cannot be seen in
/// the audit trail what was not placed.
#[test]
fn a_rejection_names_the_instance() {
    let result = plan(&[demand("api", 2)], &[node("a", "r1", 4000)], &[]);

    let rejected = result.rejected.first().expect("one rejection");
    let text = rejected.to_string();
    assert!(text.contains("api"), "{text}");
    assert!(text.contains('1'), "{text}");
}

/// **Every rejection reason is its own word** (ADR-0015).
///
/// The class becomes a metric label, and two variants with the same word would
/// be two causes an operator cannot tell apart. Here that is especially
/// expensive, because the seven send to **different places**: `no_room` to the
/// capacity, `no_domain_left` to the topology, `node_detached` to
/// `tgctl node attach`, `pinned_to_draining_node` to `node uncordon`,
/// `stateful_node_gone` into a DR case (ADR-0027) — and the two `pinned_*` to
/// the definition itself, for those are contradictory in themselves and no
/// operational action makes them go away.
///
/// # What the compiler holds, and what it does not
///
/// `class` is a `match` without a `_` arm: **that** every variant has a class
/// it enforces. That they are **different** it does not — and the most common
/// way there is a copied `match` arm. The same construction and the same
/// rationale as `every_class_is_its_own_word` for `RuntimeError`, where a
/// predecessor checked five of fifteen and let a copied class through.
#[test]
fn every_rejection_class_is_its_own_word() {
    let errors = [
        PlacementError::PinnedButReplicated {
            workload: "api".to_owned(),
            replicas: 2,
        },
        PlacementError::PinnedNodeUnknown {
            workload: "api".to_owned(),
            node: "n9".to_owned(),
        },
        PlacementError::NoDomainLeft {
            workload: "api".to_owned(),
            instance: 1,
            level: tg_defs::DomainLevel::Rack,
        },
        PlacementError::StatefulNodeGone {
            workload: "api".to_owned(),
            instance: 0,
            node: "n1".to_owned(),
        },
        PlacementError::PinnedToDrainingNode {
            workload: "api".to_owned(),
            instance: 0,
            node: "n1".to_owned(),
        },
        PlacementError::NodeDetached {
            workload: "api".to_owned(),
            instance: 0,
            node: "n1".to_owned(),
        },
        PlacementError::NoRoom {
            workload: "api".to_owned(),
            instance: 1,
            wanted: Resources::default(),
        },
    ];

    // **The length assurance is the tripwire.** If an eighth variant comes,
    // the `match` in `class` makes the file uncompilable, the list here grows
    // to eight -- and this line goes red until somebody has classified it. The
    // demanded attention instead of the hoped-for one.
    assert_eq!(errors.len(), 7, "seven variants");

    let mut seen: Vec<&str> = errors.iter().map(PlacementError::class).collect();
    let total = seen.len();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen.len(),
        total,
        "two variants carry the same class: {seen:?}"
    );

    for class in &seen {
        assert!(!class.is_empty(), "a class is empty");
        assert!(
            class.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "'{class}' is not fit as a label"
        );
    }

    // **`CLASSES` is the list from which the scheduler builds its time
    // series** -- it has to be the same set as that of the variants, otherwise
    // it reports a class that does not exist, or one is missing and its time
    // series appears only when the finding happens to occur.
    assert_eq!(
        seen,
        PlacementError::CLASSES.to_vec(),
        "`CLASSES` and the variants' classes have run apart"
    );
}

// ======================================================= Storage (ADR-0027)

/// **The scheduler refuses to move a stateful workload.**
///
/// The third acceptance criterion of phase 10. The node on which the writable
/// volume lies is gone — and the planner does **not** start the workload
/// elsewhere. Were it to do so, it would have silently given up the data, and
/// the workload would start up as if nothing had happened.
///
/// ADR-0027 calls that the structural absence of volume migration.
#[test]
fn a_stateful_instance_is_not_replaced_when_its_node_is_gone() {
    let existing = vec![tg_model::placement::Assignment {
        workload: "ledger".to_owned(),
        instance: 0,
        node: "a".to_owned(),
    }];

    // Node 'a' has vanished, 'b' would have room.
    let result = plan(
        &[stateful("ledger", 1)],
        &[node("b", "r2", 4000)],
        &existing,
    );

    assert!(
        result.assignments.is_empty(),
        "the workload was moved: {:?}",
        result.assignments
    );
    assert!(result.kept.is_empty());

    let rejected = result.rejected.first().expect("one rejection");
    assert!(
        matches!(
            rejected,
            PlacementError::StatefulNodeGone { workload, instance: 0, node }
                if workload == "ledger" && node == "a"
        ),
        "expected StatefulNodeGone, was {rejected:?}"
    );
}

/// The counter-check with **one** thing different: without a writable volume
/// the same workload very much is placed anew. Otherwise the test above would
/// prove only that something was not placed.
#[test]
fn a_stateless_instance_is_replaced_when_its_node_is_gone() {
    let existing = vec![tg_model::placement::Assignment {
        workload: "api".to_owned(),
        instance: 0,
        node: "a".to_owned(),
    }];

    let result = plan(&[demand("api", 1)], &[node("b", "r2", 4000)], &existing);

    assert_eq!(placed(&result, "api"), vec!["b".to_owned()]);
    assert!(result.rejected.is_empty());
}

/// As long as its node is there, a stateful workload stays where it is — even
/// if there were more room elsewhere. That is the same assurance as for all the
/// others (ADR-0011: no auto-rebalancing), but here no convenience but a
/// condition.
#[test]
fn a_stateful_instance_stays_where_its_volume_is() {
    let existing = vec![tg_model::placement::Assignment {
        workload: "ledger".to_owned(),
        instance: 0,
        node: "a".to_owned(),
    }];

    let result = plan(
        &[stateful("ledger", 1)],
        &[node("a", "r1", 1000), node("b", "r2", 64_000)],
        &existing,
    );

    assert_eq!(result.kept, existing);
    assert!(result.assignments.is_empty());
    assert!(result.rejected.is_empty());
}

/// A stateful workload that was **never** placed is placed. The prohibition
/// applies to the move, not to the first start.
#[test]
fn a_stateful_instance_that_was_never_placed_is_placed() {
    let result = plan(&[stateful("ledger", 1)], &[node("a", "r1", 4000)], &[]);

    assert_eq!(placed(&result, "ledger"), vec!["a".to_owned()]);
    assert!(result.rejected.is_empty());
}

/// Replicated and stateful is **no** contradiction: every instance carries its
/// own volume (ADR-0027 — "replica with its own volume"). None is moved
/// nevertheless.
#[test]
fn replicas_of_a_stateful_workload_each_keep_their_own_node() {
    let existing = vec![
        tg_model::placement::Assignment {
            workload: "ledger".to_owned(),
            instance: 0,
            node: "a".to_owned(),
        },
        tg_model::placement::Assignment {
            workload: "ledger".to_owned(),
            instance: 1,
            node: "b".to_owned(),
        },
    ];

    // 'b' fails. Instance 0 stays, instance 1 is refused instead of moved.
    let result = plan(
        &[stateful("ledger", 2)],
        &[node("a", "r1", 4000), node("c", "r3", 4000)],
        &existing,
    );

    assert_eq!(result.kept.len(), 1);
    assert_eq!(result.kept[0].instance, 0);
    assert!(
        result.assignments.is_empty(),
        "instance 1 was moved to 'c': {:?}",
        result.assignments
    );
    assert!(matches!(
        result.rejected.first(),
        Some(PlacementError::StatefulNodeGone { instance: 1, .. })
    ));
}

// --- Cordon and drain (phase 6) ---------------------------------------------

fn assignment(workload: &str, instance: u32, node: &str) -> tg_model::placement::Assignment {
    tg_model::placement::Assignment {
        workload: workload.to_owned(),
        instance,
        node: node.to_owned(),
    }
}

fn cordoned(name: &str, rack: &str, cpu: u64, mode: Schedulability) -> Node {
    Node {
        schedulable: mode,
        ..node(name, rack, cpu)
    }
}

/// **A cordoned node gets nothing new — and keeps what runs.**
///
/// That is the difference between cordon and drain, and it is the reason why
/// there are two states: before a restart the node shall become emptier without
/// anyone tearing anything down.
#[test]
fn a_cordoned_node_takes_nothing_new_and_keeps_what_runs() {
    let nodes = vec![
        cordoned("a", "r1", 4000, Schedulability::Cordoned),
        node("b", "r2", 4000),
    ];
    let demands = vec![demand("api", 2)];
    let existing = vec![assignment("api", 0, "a")];

    let plan = plan(&demands, &nodes, &existing);

    assert!(
        plan.kept.contains(&assignment("api", 0, "a")),
        "the running instance was cleared away: {plan:?}"
    );
    assert!(
        plan.assignments.iter().all(|a| a.node == "b"),
        "placement happened onto the cordoned node: {plan:?}"
    );
}

/// **A drained node gives up.** The instance no longer appears under `kept` and
/// is placed elsewhere.
#[test]
fn a_draining_node_gives_up_what_it_holds() {
    let nodes = vec![
        cordoned("a", "r1", 4000, Schedulability::Draining),
        node("b", "r2", 4000),
    ];
    let demands = vec![demand("api", 1)];
    let existing = vec![assignment("api", 0, "a")];

    let plan = plan(&demands, &nodes, &existing);

    assert!(plan.kept.is_empty(), "the node did not give up: {plan:?}");
    assert_eq!(plan.assignments, vec![assignment("api", 0, "b")]);
}

/// **Where nothing can go, nothing moves away either** — the instance stays
/// unplaced and is reported instead of landing on a node somebody is just
/// draining.
#[test]
fn draining_the_only_node_leaves_the_instance_unplaced() {
    let nodes = vec![cordoned("a", "r1", 4000, Schedulability::Draining)];
    let demands = vec![demand("api", 1)];
    let existing = vec![assignment("api", 0, "a")];

    let plan = plan(&demands, &nodes, &existing);

    assert!(plan.kept.is_empty());
    assert!(plan.assignments.is_empty());
    assert!(!plan.rejected.is_empty(), "no finding: {plan:?}");
}

/// **A nailed-down workload does not leave the node** — and that is reported.
///
/// A writable volume nails it down (ADR-0027); moving it would mean silently
/// giving up the data. An operator who empties a node has to learn what does
/// not come along: a silent exception would be worse than a loud one.
#[test]
fn a_pinned_workload_stays_and_says_so() {
    let nodes = vec![
        cordoned("a", "r1", 4000, Schedulability::Draining),
        node("b", "r2", 4000),
    ];
    let demands = vec![Demand {
        stateful: true,
        ..demand("payments", 1)
    }];
    let existing = vec![assignment("payments", 0, "a")];

    let plan = plan(&demands, &nodes, &existing);

    assert!(
        plan.kept.contains(&assignment("payments", 0, "a")),
        "the data were given up: {plan:?}"
    );
    assert!(
        plan.rejected.iter().any(|err| matches!(
            err,
            PlacementError::PinnedToDrainingNode { workload, node, .. }
                if workload == "payments" && node == "a"
        )),
        "the exception stayed silent: {plan:?}"
    );
}

/// The counter-check beside it: **without** a volume the same workload moves
/// away. Without it the test above would prove only that something stays
/// lying.
#[test]
fn without_a_volume_the_same_workload_moves() {
    let nodes = vec![
        cordoned("a", "r1", 4000, Schedulability::Draining),
        node("b", "r2", 4000),
    ];
    let demands = vec![demand("payments", 1)];
    let existing = vec![assignment("payments", 0, "a")];

    let plan = plan(&demands, &nodes, &existing);

    assert_eq!(plan.assignments, vec![assignment("payments", 0, "b")]);
    assert!(plan.rejected.is_empty(), "{plan:?}");
}

/// **An explicit pin does not place onto a cordoned node either.** The workload
/// stays unplaced and reported — the uncomfortable but right answer.
#[test]
fn an_explicit_pin_does_not_beat_a_cordon() {
    let nodes = vec![
        cordoned("a", "r1", 4000, Schedulability::Cordoned),
        node("b", "r2", 4000),
    ];
    let demands = vec![Demand {
        pin: Some("a".to_owned()),
        ..demand("api", 1)
    }];

    let plan = plan(&demands, &nodes, &[]);

    assert!(plan.assignments.is_empty(), "{plan:?}");
    assert!(
        plan.rejected.iter().any(|err| matches!(
            err,
            PlacementError::PinnedToDrainingNode { node, .. } if node == "a"
        )),
        "{plan:?}"
    );
}

/// A cordoned node is reported as **cordoned** and not as "no room". An
/// operator who reads the wrong cause looks in the wrong place.
#[test]
fn a_cordon_is_not_reported_as_a_lack_of_room() {
    let nodes = vec![cordoned("a", "r1", 4000, Schedulability::Cordoned)];
    let demands = vec![demand("api", 1)];

    let plan = plan(&demands, &nodes, &[]);

    assert!(
        !plan
            .rejected
            .iter()
            .any(|err| matches!(err, PlacementError::NoRoom { .. })),
        "reported as a lack of room: {plan:?}"
    );
}

/// The default is **schedulable**: a node nobody has touched accepts work.
/// Anything else would be a cluster that stands still after an upgrade.
#[test]
fn the_default_is_schedulable() {
    assert_eq!(Schedulability::default(), Schedulability::Schedulable);
    assert!(Schedulability::default().accepts_new());
    assert!(!Schedulability::default().evicts());
}

/// The names on the command line and in the wire format go there and back.
#[test]
fn the_names_round_trip() {
    for mode in [
        Schedulability::Schedulable,
        Schedulability::Cordoned,
        Schedulability::Draining,
    ] {
        assert_eq!(mode.as_str().parse::<Schedulability>(), Ok(mode));
    }

    let err = "barred".parse::<Schedulability>().expect_err("unknown");
    assert!(err.contains("barred"), "{err}");
    assert!(err.contains("cordoned"), "{err}");
}

// --- Reserved capacity (ADR-0047) -------------------------------------------

fn with_reserve(name: &str, rack: &str, cpu: u64, reserve: u64) -> Node {
    Node {
        reserved: Resources::default().with(Resources::CPU_MILLICORES, reserve),
        ..node(name, rack, cpu)
    }
}

/// **The reserve is not there for the planner.** A node with 4000 millicores
/// and a reserve of 3800 takes no instance that demands 500.
#[test]
fn a_reserve_is_not_available_to_the_planner() {
    let nodes = vec![with_reserve("a", "r1", 4000, 3800)];

    let plan = plan(&[demand("api", 1)], &nodes, &[]);

    assert!(plan.assignments.is_empty(), "{plan:?}");
    assert!(
        plan.rejected
            .iter()
            .any(|err| matches!(err, PlacementError::NoRoom { .. })),
        "{plan:?}"
    );
}

/// Without a reserve the same instance fits. The counter-check, without which
/// the test above would show only that something does not fit.
#[test]
fn without_a_reserve_the_same_instance_fits() {
    let nodes = vec![with_reserve("a", "r1", 4000, 0)];

    let plan = plan(&[demand("api", 1)], &nodes, &[]);

    assert_eq!(plan.assignments.len(), 1, "{plan:?}");
}

/// **A reserve raised afterwards displaces nothing** (ADR-0047,
/// determination 4). It takes effect on the next thing that is placed. Anything
/// else would mean that a number in a configuration halts a running
/// container.
#[test]
fn raising_the_reserve_does_not_evict() {
    let nodes = vec![with_reserve("a", "r1", 4000, 3900)];
    let existing = vec![assignment("api", 0, "a")];

    let plan = plan(&[demand("api", 1)], &nodes, &existing);

    assert_eq!(
        plan.kept, existing,
        "the reserve displaced a running instance: {plan:?}"
    );
}

/// **A reserve larger than the capacity yields zero, no overflow.** A typo in a
/// number must not produce an infinitely large node.
#[test]
fn a_reserve_larger_than_the_capacity_saturates_at_zero() {
    let node = with_reserve("a", "r1", 4000, u64::MAX);

    assert_eq!(
        node.schedulable_capacity().get(Resources::CPU_MILLICORES),
        0
    );

    let plan = plan(&[demand("api", 1)], &[node], &[]);
    assert!(plan.assignments.is_empty(), "{plan:?}");
}

/// What the node does not offer at all cannot be reserved from it either.
#[test]
fn reserving_an_unknown_resource_changes_nothing() {
    let node = Node {
        reserved: Resources::default().with("gpu", 4),
        ..node("a", "r1", 4000)
    };

    let free = node.schedulable_capacity();
    assert_eq!(free.get(Resources::CPU_MILLICORES), 4000);
    assert_eq!(free.get("gpu"), 0);
}

// --- The metric per failure domain (ADR-0047, determination 3) --------------

/// **It shows, it decides nothing.** Two racks, one occupied, the other free:
/// the failure of the occupied one could be absorbed.
#[test]
fn a_domain_that_can_be_absorbed_is_reported_as_such() {
    let nodes = vec![node("a", "r1", 4000), node("b", "r2", 4000)];
    let existing = vec![assignment("api", 0, "a")];

    let report = tg_model::placement::headroom(
        &nodes,
        &[demand("api", 1)],
        &existing,
        tg_defs::DomainLevel::Rack,
    );

    let r1 = report.iter().find(|h| h.domain == "fra/h1/r1").expect("r1");
    assert!(r1.absorbs, "{r1:?}");
    assert_eq!(r1.at_risk.get(Resources::CPU_MILLICORES), 500);
}

/// And the case for whose sake the metric exists: it does **not** suffice, and
/// that stands **before** the failure occurs.
#[test]
fn a_domain_that_cannot_be_absorbed_says_so_before_it_fails() {
    // r2 is almost full: 4000 capacity, 3800 occupied.
    let nodes = vec![node("a", "r1", 4000), node("b", "r2", 4000)];
    let demands = vec![
        Demand {
            resources: Resources::default().with(Resources::CPU_MILLICORES, 3000),
            ..demand("large", 1)
        },
        Demand {
            resources: Resources::default().with(Resources::CPU_MILLICORES, 3800),
            ..demand("full", 1)
        },
    ];
    let existing = vec![assignment("large", 0, "a"), assignment("full", 0, "b")];

    let report =
        tg_model::placement::headroom(&nodes, &demands, &existing, tg_defs::DomainLevel::Rack);

    let r1 = report.iter().find(|h| h.domain == "fra/h1/r1").expect("r1");
    assert!(!r1.absorbs, "3000 shall not fit into 200: {r1:?}");
}

/// **A drained node is no room.** It accepts nothing (phase 6), so it must not
/// be counted as a reserve for a failure — otherwise the metric would say "it
/// suffices" where nothing can go.
#[test]
fn a_drained_node_is_not_counted_as_headroom() {
    let nodes = vec![
        node("a", "r1", 4000),
        Node {
            schedulable: Schedulability::Draining,
            ..node("b", "r2", 4000)
        },
    ];
    let existing = vec![assignment("api", 0, "a")];

    let report = tg_model::placement::headroom(
        &nodes,
        &[demand("api", 1)],
        &existing,
        tg_defs::DomainLevel::Rack,
    );

    let r1 = report.iter().find(|h| h.domain == "fra/h1/r1").expect("r1");
    assert_eq!(r1.elsewhere.get(Resources::CPU_MILLICORES), 0);
    assert!(!r1.absorbs, "{r1:?}");
}

/// The reserve does **not** count as room — it is after all precisely what lies
/// ready for the failure... and precisely for that reason already deducted.
/// Counting it twice would mean having it twice.
#[test]
fn the_reserve_is_not_counted_as_free_capacity() {
    let nodes = vec![node("a", "r1", 4000), with_reserve("b", "r2", 4000, 4000)];

    let report = tg_model::placement::headroom(
        &nodes,
        &[demand("api", 1)],
        &[assignment("api", 0, "a")],
        tg_defs::DomainLevel::Rack,
    );

    let r1 = report.iter().find(|h| h.domain == "fra/h1/r1").expect("r1");
    assert_eq!(r1.elsewhere.get(Resources::CPU_MILLICORES), 0);
}

/// Every domain is computed **individually**; the function picks no failure for
/// itself. One that took the worst would have made an assumption nobody ordered
/// (ADR-0047).
#[test]
fn every_domain_is_reported_separately() {
    let nodes = vec![
        node("a", "r1", 4000),
        node("b", "r2", 4000),
        node("c", "r3", 4000),
    ];

    let report = tg_model::placement::headroom(&nodes, &[], &[], tg_defs::DomainLevel::Rack);

    let domains: Vec<&str> = report.iter().map(|h| h.domain.as_str()).collect();
    assert_eq!(domains, ["fra/h1/r1", "fra/h1/r2", "fra/h1/r3"]);
}

// ============================================================ Detach (0054)

fn detached(name: &str, rack: &str, cpu: u64) -> Node {
    Node {
        attachment: Attachment::Detached,
        ..node(name, rack, cpu)
    }
}

/// **A detached node gets nothing and gives up** (ADR-0054,
/// determination 5).
///
/// Both together, and that is the difference from the cordon: a node without a
/// mesh on which workloads still run is worse than both — the containers run
/// and reach nothing.
#[test]
fn a_detached_node_takes_nothing_and_gives_up_what_it_holds() {
    let nodes = vec![detached("a", "r1", 4000), node("b", "r2", 4000)];
    let demands = vec![demand("api", 1)];
    let existing = vec![assignment("api", 0, "a")];

    let plan = plan(&demands, &nodes, &existing);

    assert!(
        plan.kept.is_empty(),
        "the detached node did not give up: {plan:?}"
    );
    assert_eq!(plan.assignments, vec![assignment("api", 0, "b")]);
}

/// **Detached beats schedulable** (ADR-0054, determination 5).
///
/// The interaction lies with the data and not with the caller: two callers
/// would otherwise read it differently. A node that is expressly `schedulable`
/// and detached takes **nothing**.
#[test]
fn detached_beats_schedulable() {
    let nodes = vec![
        Node {
            attachment: Attachment::Detached,
            schedulable: Schedulability::Schedulable,
            ..node("a", "r1", 4000)
        },
        node("b", "r2", 4000),
    ];
    let demands = vec![demand("api", 1)];

    let plan = plan(&demands, &nodes, &[]);

    assert!(
        plan.assignments.iter().all(|a| a.node == "b"),
        "placement happened onto the detached node: {plan:?}"
    );
}

/// **A pin does not land on a detached node either — and the reason is
/// named.**
///
/// "Detached" and "cordoned" send an operator to different places; a rejection
/// that names both the same costs the search.
#[test]
fn a_pin_to_a_detached_node_names_the_reason() {
    let nodes = vec![detached("a", "r1", 4000)];
    let demands = vec![Demand {
        pin: Some("a".to_owned()),
        ..demand("api", 1)
    }];

    let plan = plan(&demands, &nodes, &[]);

    assert!(plan.assignments.is_empty(), "placement happened: {plan:?}");
    assert!(
        plan.rejected
            .iter()
            .any(|error| matches!(error, PlacementError::NodeDetached { .. })),
        "the reason was not named as a detachment: {plan:?}"
    );
}

/// **What cannot move stays lying — and is reported** (ADR-0027).
///
/// The case in which a detachment **never finishes**. It is to be made visible,
/// not left out: whoever detaches a node has to learn what does not come
/// along.
#[test]
fn a_pinned_workload_survives_a_detach_and_says_so() {
    let nodes = vec![detached("a", "r1", 4000), node("b", "r2", 4000)];
    let demands = vec![Demand {
        stateful: true,
        ..demand("payment", 1)
    }];
    let existing = vec![assignment("payment", 0, "a")];

    let pinned = plan(&demands, &nodes, &existing);

    assert!(
        pinned.kept.contains(&assignment("payment", 0, "a")),
        "the nailed-down workload was moved: {pinned:?}"
    );
    assert!(
        !pinned.rejected.is_empty(),
        "the exception was not reported: {pinned:?}"
    );

    // Counter-check: the same workload **without** a volume moves away. Without
    // it the test would prove only that something stays lying.
    let plain = plan(&[demand("payment", 1)], &nodes, &existing);
    assert!(
        plain.kept.is_empty(),
        "without a volume it has to move: {plain:?}"
    );
}

// --- The numbers behind the metric (ADR-0047, determination 3) --------------

/// **Both numbers carry the same set of names** — and that is the security
/// statement, not symmetry for its own sake.
///
/// The alarm ADR-0047 wants reads "it is getting tight" and computes
/// `elsewhere / at_risk`. Were the line whose resource is **not at all** free
/// outside to be missing, there would be no pair for it — and no time series
/// means **no alarm**. Of all cases the worst one would be silent.
#[test]
fn a_resource_with_nothing_free_outside_still_reports_a_pair() {
    let nodes = vec![node("a", "r1", 4000), node("b", "r2", 4000)];
    // No node declares `gpu` — none of it is free outside.
    let demands = vec![Demand {
        resources: Resources::default()
            .with(Resources::CPU_MILLICORES, 500)
            .with("gpu", 2),
        ..demand("ai", 1)
    }];
    let existing = vec![assignment("ai", 0, "a")];

    let report =
        tg_model::placement::headroom(&nodes, &demands, &existing, tg_defs::DomainLevel::Rack);
    let r1 = report.iter().find(|h| h.domain == "fra/h1/r1").expect("r1");

    assert!(
        !r1.absorbs,
        "without a gpu outside the failure cannot be borne"
    );
    assert!(
        r1.series().contains(&("gpu", 2, 0)),
        "the resource without room outside has to yield a pair: {:?}",
        r1.series()
    );
}

/// The counter-check: what is carried **on both sides** appears with both
/// numbers. Without it a version that sets every line to zero would be green
/// too.
#[test]
fn a_resource_present_on_both_sides_reports_both_numbers() {
    let nodes = vec![node("a", "r1", 4000), node("b", "r2", 4000)];
    let existing = vec![assignment("api", 0, "a")];

    let report = tg_model::placement::headroom(
        &nodes,
        &[demand("api", 1)],
        &existing,
        tg_defs::DomainLevel::Rack,
    );
    let r1 = report.iter().find(|h| h.domain == "fra/h1/r1").expect("r1");

    assert!(
        r1.series()
            .contains(&(Resources::CPU_MILLICORES, 500, 4000)),
        "{:?}",
        r1.series()
    );
}

/// And the other direction of the union: free capacity outside that nobody
/// needs is reported as `0` against it instead of being left out.
///
/// Which side is missing an alarm writer shall not have to consider.
#[test]
fn spare_capacity_nobody_needs_is_reported_against_zero() {
    let nodes = vec![node("a", "r1", 4000), node("b", "r2", 4000)];
    let existing = vec![assignment("api", 0, "a")];

    let report = tg_model::placement::headroom(
        &nodes,
        &[demand("api", 1)],
        &existing,
        tg_defs::DomainLevel::Rack,
    );
    let r1 = report.iter().find(|h| h.domain == "fra/h1/r1").expect("r1");

    // This workload demands no memory — some is free outside nevertheless, and
    // that is information and no risk.
    let memory = r1
        .series()
        .into_iter()
        .find(|(name, _, _)| *name == Resources::MEMORY_BYTES)
        .expect("memory has to appear");
    assert_eq!(memory.1, 0, "nothing is demanded");
    assert!(memory.2 > 0, "something is free nevertheless");
}

/// **The planner chooses the node with the lowest pressure** (ADR-0109).
///
/// That is the seam at which the finding lay: `Resources` derived an `Ord`, and
/// the planner sorted with it — lexicographically over the map, that is, by the
/// alphabetically first resource **name**. Measured, a node with 9 GB of
/// occupied memory counted as emptier than one with 200 millicores, because CPU
/// stands before memory and there 100 < 200.
///
/// The setup is exactly that case: `a-much-memory` holds 9 GB and little CPU,
/// `b-much-cpu` holds more CPU and no memory. And the names are deliberately
/// chosen so that the **alphabetically first** one is the wrong one —
/// otherwise the witness would be satisfied by the old rule too (the same
/// finding as with `a-fully-reserved`/`b-free` in ADR-0047).
#[test]
fn the_node_with_the_least_pressure_wins() {
    let cpu = Resources::CPU_MILLICORES;
    let mem = Resources::MEMORY_BYTES;

    // Two nodes in **one** rack: otherwise the anti-affinity decides and not
    // the occupancy.
    let nodes = vec![
        node("a-much-memory", "r1", 4000),
        node("b-much-cpu", "r1", 4000),
    ];

    // What is already running: the state from the ADR.
    let existing = vec![
        tg_model::placement::Assignment {
            workload: "old-memory".to_owned(),
            instance: 0,
            node: "a-much-memory".to_owned(),
        },
        tg_model::placement::Assignment {
            workload: "old-cpu".to_owned(),
            instance: 0,
            node: "b-much-cpu".to_owned(),
        },
    ];
    let mut occupancy = vec![
        Demand {
            workload: "old-memory".to_owned(),
            replicas: 1,
            spread: DomainLevel::Rack,
            domains: Vec::new(),
            pin: None,
            stateful: false,
            resources: Resources::default().with(cpu, 100).with(mem, 9_000_000_000),
        },
        Demand {
            workload: "old-cpu".to_owned(),
            replicas: 1,
            spread: DomainLevel::Rack,
            domains: Vec::new(),
            pin: None,
            stateful: false,
            resources: Resources::default().with(cpu, 200),
        },
    ];

    // The new workload demands little so that it fits onto both.
    occupancy.push(Demand {
        workload: "new".to_owned(),
        replicas: 1,
        spread: DomainLevel::Rack,
        domains: Vec::new(),
        pin: None,
        stateful: false,
        resources: Resources::default().with(cpu, 10),
    });

    let plan = plan(&occupancy, &nodes, &existing);
    let fresh = plan
        .assignments
        .iter()
        .find(|assignment| assignment.workload == "new")
        .expect("the new workload has to be placed");

    assert_eq!(
        fresh.node, "b-much-cpu",
        "the node with 9 GB of occupied memory was chosen -- that is the \
         lexicographic ordering of the map and not the occupancy"
    );
}

/// A **partly** placed declaration is to be told apart from a complete one —
/// with the denominator beside it.
///
/// The planner behaves rightly (ADR-0011: what is unsatisfiable is refused, not
/// softened): six instances on five racks yield five placements and one
/// rejection that names workload, instance and level. What was missing is the
/// **number** — `placed` is a list, and whoever does not know `replicas` beside
/// it has to count.
#[test]
fn a_partly_placed_workload_reports_both_numbers() {
    let nodes: Vec<Node> = (1..=5)
        .map(|n| node(&format!("n{n}"), &format!("r{n}"), 100_000))
        .collect();

    let demands = vec![demand("api", 6), demand("ledger", 3)];
    let plan = plan(&demands, &nodes, &[]);

    let coverage = tg_model::placement::coverage(&plan, &demands);

    assert_eq!(
        coverage,
        vec![
            tg_model::placement::Coverage {
                workload: "api".to_owned(),
                placed: 5,
                wanted: 6,
            },
            tg_model::placement::Coverage {
                workload: "ledger".to_owned(),
                placed: 3,
                wanted: 3,
            },
        ],
        "the gap at 'api' and the completeness at 'ledger'"
    );
}

/// And the counter-direction carries it: **existing** assignments count along.
///
/// That is this computation's trap. In the second pass everything stands in
/// `kept` and `assignments` is empty — whoever counted only the new ones would
/// report a gap of a hundred percent for **every healthy cluster**, and the
/// alert rule beside it would fire permanently.
#[test]
fn kept_assignments_count_towards_the_coverage() {
    let nodes: Vec<Node> = (1..=5)
        .map(|n| node(&format!("n{n}"), &format!("r{n}"), 100_000))
        .collect();

    let demands = vec![demand("api", 3)];
    let first = plan(&demands, &nodes, &[]);
    assert_eq!(first.assignments.len(), 3, "the setup has to take effect");

    // The same state a second time: nothing new to do.
    let second = plan(&demands, &nodes, &first.assignments);
    assert!(
        second.assignments.is_empty(),
        "the second pass places nothing new"
    );

    assert_eq!(
        tg_model::placement::coverage(&second, &demands),
        vec![tg_model::placement::Coverage {
            workload: "api".to_owned(),
            placed: 3,
            wanted: 3,
        }],
        "the existing assignments count along"
    );
}

/// **The plan carries its occupancy out** (ADR-0127, determination 1).
///
/// # The finding
///
/// The pressure from ADR-0109 was computed at **every** placement in order to
/// sort candidates — and thrown away. Nobody reported a cluster's fullness; the
/// first signal was a failed placement, that is, the moment at which it is too
/// late.
///
/// # What is checked
///
/// That the map is **the planner's**: it counts what it has just distributed,
/// and it names **every** node — the empty one too. A missing time series would
/// be indistinguishable from a switched-off reporter.
#[test]
fn the_plan_carries_the_usage_it_sorted_by() {
    let nodes = vec![node("a", "r1", 1000), node("b", "r2", 1000)];

    // Two instances of 500 millicores each, anti-affinity at `rack`: one
    // instance per node.
    let result = plan(&[demand("api", 2)], &nodes, &[]);
    assert!(result.rejected.is_empty(), "both have to fit: {result:?}");

    assert_eq!(
        result.usage.len(),
        2,
        "every node stands there — the empty one too: {:?}",
        result.usage
    );
    for name in ["a", "b"] {
        let used = result.usage.get(name).expect("node in the map");
        assert_eq!(
            used.get(Resources::CPU_MILLICORES),
            500,
            "'{name}' carries one instance of 500 millicores: {used:?}"
        );
        // **And that is the number sorted by** (ADR-0109): the utilization of
        // the scarcest resource, here the half.
        assert_eq!(
            used.pressure(&nodes[0].capacity),
            500_000,
            "the pressure is half of a millionth-whole"
        );
    }
}

/// **A node without an assignment stands there with zero** (ADR-0127).
///
/// The counter-check: "nothing occupied" and "no node" are two statements.
/// Without it a map that names only occupied nodes would be just as green — and
/// an empty node's metric would be missing precisely when an operator is
/// looking for free room.
#[test]
fn an_empty_node_is_reported_as_empty() {
    let nodes = vec![node("a", "r1", 1000), node("empty", "r2", 1000)];

    // A single instance: the second node stays empty.
    let result = plan(&[demand("api", 1)], &nodes, &[]);

    let empty = result.usage.get("empty").expect("the empty node too");
    assert_eq!(empty.get(Resources::CPU_MILLICORES), 0);
    assert_eq!(
        empty.pressure(&nodes[1].capacity),
        0,
        "an empty node has no pressure"
    );
}
