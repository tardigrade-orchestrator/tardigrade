//! From the state to the commands: the scheduler step (ADR-0011).
//!
//! A **pure function** `ClusterState → Vec<Command>`. It decides nothing
//! itself — the rules stand in `tg_model::placement`, here it is translated:
//! the replicated state into the planner's input, and its result back into log
//! commands.
//!
//! That it is a pure function has two reasons, and both are requirements and
//! not preferences:
//!
//! - **Auditability** (ADR-0011). The placement follows from state and rules.
//!   Whoever wants to know why a workload runs on a node needs the state of
//!   back then — not the moment, the order of the calls or a leader's mood.
//! - **Checkability.** The same step runs in `tgd` against a real cluster and
//!   in the test rig (`tests/dst/`) against injected faults. If it lay in
//!   `tgd`'s loop, it would not exist for the DST.
//!
//! The step is **level-triggered** (ADR-0010): it sees the full state and
//! proposes what is missing. Called twice in a row it proposes nothing the
//! second time.

use tg_defs::DomainLevel;
use tg_model::placement::{self, Assignment, Demand, Node, PlacementError};

use crate::command::Command;
use crate::state::ClusterState;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Step {
    pub commands: Vec<Command>,
    pub rejected: Vec<PlacementError>,
    pub coverage: Vec<placement::Coverage>,
    pub usage: std::collections::BTreeMap<String, tg_model::Resources>,
}

impl Step {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }
}

#[must_use]
pub fn headroom(state: &ClusterState, level: DomainLevel) -> Vec<placement::Headroom> {
    let (demands, nodes, existing) = inputs(state);

    placement::headroom(&nodes, &demands, &existing, level)
}

fn inputs(state: &ClusterState) -> (Vec<Demand>, Vec<Node>, Vec<Assignment>) {
    let mut demands = Vec::new();
    for entry in state.workloads() {
        let Ok(set) = tg_defs::from_str(entry.document()) else {
            continue;
        };
        for workload in set.workloads() {
            let mut demand = Demand::from_workload(workload);

            // **The sidecar costs along** (ADR-0067). It stands in no log —
            // it arises on the node (ADR-0059) —, so the planner cannot see it.
            // Without this surcharge it overpacks, the reserve from ADR-0047 is
            // too optimistic, and the metric beside it reports more room than
            // there is at the outage.
            //
            // The criterion is `<mesh>` — exactly the one on which ADR-0059
            // hangs the derivation. And `resources` is **one** instance's
            // demand, so the surcharge lands per instance by itself.
            if tg_defs::WorkloadExt::mesh(workload).is_some() {
                demand.resources = demand.resources.plus(state.sidecar_overhead());
            }

            demands.push(demand);
        }
    }

    let nodes: Vec<Node> = state
        .nodes()
        .into_iter()
        .map(|(name, entry)| Node {
            name: name.to_owned(),
            topology: entry.topology().clone(),
            capacity: entry.capacity().clone(),
            reserved: entry.reserved().clone(),
            schedulable: entry.schedulable(),
            attachment: entry.attachment(),
        })
        .collect();

    let existing: Vec<Assignment> = state
        .placements()
        .into_iter()
        .map(|(workload, instance, node)| Assignment {
            workload: workload.to_owned(),
            instance,
            node: node.to_owned(),
        })
        .collect();

    (demands, nodes, existing)
}

#[must_use]
pub fn step(state: &ClusterState) -> Step {
    let (demands, nodes, existing) = inputs(state);

    let plan = placement::plan(&demands, &nodes, &existing);
    let coverage = placement::coverage(&plan, &demands);

    Step {
        commands: plan
            .assignments
            .into_iter()
            .map(|assignment| Command::AssignPlacement {
                workload: assignment.workload,
                instance: assignment.instance,
                node: assignment.node,
            })
            .collect(),
        rejected: plan.rejected,
        coverage,
        usage: plan.usage,
    }
}
