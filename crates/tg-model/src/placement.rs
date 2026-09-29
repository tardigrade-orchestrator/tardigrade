//! Placement: which workload runs on which node (ADR-0011).
//!
//! The model is **declarative-explicit**, and that is a decision against the
//! widespread alternative: no scoring, no weights, no heuristic one can no
//! longer explain afterwards. ADR-0011 names the reason — "an auditor has to
//! see *why* workload X runs on node Y".
//!
//! Three properties follow from that which determine everything else:
//!
//! 1. **Constraints filter, they do not weigh.** A node comes into question or
//!    not. What remains is decided by a fixed, written-down order — never by a
//!    score.
//! 2. **What is running is never moved unbidden.** The planner gets the
//!    existing assignments and keeps them as long as they are valid. Every move
//!    of a single writer is a fencing operation (ADR-0010) and does not belong
//!    in an optimization.
//! 3. **What is unsatisfiable is refused, not softened.** Per ADR-0011
//!    anti-affinity is a hard constraint. A planner that says "if need be, then
//!    anyway" takes from the operator the assurance for which they set the
//!    constraint.
//!
//! # The resource model
//!
//! Capacity and demand are a **mapping name → amount**, not fixed fields. The
//! reason stands in PLAN.md: the generic `device` type from ADR-0028 shall fit
//! later without a rebuild. A resource a node does not carry counts as not
//! present — otherwise "has no GPU" would be the same as "has arbitrarily
//! many".

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use tg_defs::{DomainConstraint, DomainLevel, PlacementExt, ResourcesExt as _, WorkloadExt as _};

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    pub site: String,
    pub hall: String,
    pub rack: String,
}

impl Topology {
    #[must_use]
    pub fn label(&self, level: DomainLevel) -> &str {
        match level {
            DomainLevel::Site => &self.site,
            DomainLevel::Hall => &self.hall,
            DomainLevel::Rack => &self.rack,
        }
    }

    #[must_use]
    pub fn domain(&self, level: DomainLevel) -> String {
        match level {
            DomainLevel::Site => self.site.clone(),
            DomainLevel::Hall => format!("{}/{}", self.site, self.hall),
            DomainLevel::Rack => format!("{}/{}/{}", self.site, self.hall, self.rack),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Resources(BTreeMap<String, u64>);

impl Resources {
    pub const CPU_MILLICORES: &'static str = "cpu-millicores";
    pub const MEMORY_BYTES: &'static str = "memory-bytes";
    pub const DEVICE_PREFIX: &'static str = "device:";

    #[must_use]
    pub fn with(mut self, name: &str, amount: u64) -> Self {
        if amount > 0 {
            self.0.insert(name.to_owned(), amount);
        }
        self
    }

    #[must_use]
    pub fn get(&self, name: &str) -> u64 {
        self.0.get(name).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn entries(&self) -> Vec<(&str, u64)> {
        self.0
            .iter()
            .map(|(name, amount)| (name.as_str(), *amount))
            .collect()
    }

    #[must_use]
    pub fn fits(&self, used: &Self, capacity: &Self) -> bool {
        self.0.iter().all(|(name, amount)| {
            let available = capacity.get(name).saturating_sub(used.get(name));
            *amount <= available
        })
    }

    #[must_use]
    pub fn pressure(&self, capacity: &Self) -> u128 {
        const SCALE: u128 = 1_000_000;

        capacity
            .entries()
            .into_iter()
            .filter(|(_, have)| *have > 0)
            .map(|(name, have)| u128::from(self.get(name)) * SCALE / u128::from(have))
            .max()
            .unwrap_or(0)
    }

    #[must_use]
    pub fn minus(mut self, other: &Self) -> Self {
        for (name, amount) in &mut self.0 {
            *amount = amount.saturating_sub(other.get(name));
        }
        self
    }

    #[must_use]
    pub fn plus(mut self, other: &Self) -> Self {
        for (name, amount) in &other.0 {
            let sum = self.get(name).saturating_add(*amount);
            self.0.insert(name.clone(), sum);
        }
        self
    }

    #[must_use]
    pub fn from_workload(workload: &tg_defs::generated::WorkloadType) -> Self {
        let Some(resources) = workload.resources() else {
            return Self::default();
        };

        let mut wanted = Self::default();
        if let Some(millicores) = resources.millicores() {
            wanted = wanted.with(Self::CPU_MILLICORES, u64::from(millicores));
        }
        if let Some(bytes) = resources.memory_bytes() {
            wanted = wanted.with(Self::MEMORY_BYTES, bytes);
        }
        wanted.plus(&Self::devices_of(workload))
    }

    #[must_use]
    fn devices_of(workload: &tg_defs::generated::WorkloadType) -> Self {
        let mut wanted = Self::default();
        for device in workload.devices() {
            let name = format!("{}{}", Self::DEVICE_PREFIX, device.kind.0);
            let already = wanted.get(&name);
            wanted = wanted.with(&name, already.saturating_add(u64::from(device.count.0)));
        }
        wanted
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub topology: Topology,
    pub capacity: Resources,
    pub reserved: Resources,
    pub schedulable: Schedulability,
    pub attachment: Attachment,
}

impl Node {
    #[must_use]
    pub const fn accepts_new(&self) -> bool {
        self.attachment.in_mesh() && self.schedulable.accepts_new()
    }

    #[must_use]
    pub const fn evicts(&self) -> bool {
        !self.attachment.in_mesh() || self.schedulable.evicts()
    }

    #[must_use]
    pub fn schedulable_capacity(&self) -> Resources {
        self.capacity.clone().minus(&self.reserved)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Schedulability {
    #[default]
    Schedulable,
    Cordoned,
    Draining,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attachment {
    #[default]
    Attached,
    Detached,
}

impl Attachment {
    #[must_use]
    pub const fn in_mesh(self) -> bool {
        matches!(self, Self::Attached)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Detached => "detached",
        }
    }
}

impl std::str::FromStr for Attachment {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "attached" => Ok(Self::Attached),
            "detached" => Ok(Self::Detached),
            other => Err(format!("unknown state '{other}' — attached or detached")),
        }
    }
}

impl Schedulability {
    #[must_use]
    pub const fn accepts_new(self) -> bool {
        matches!(self, Self::Schedulable)
    }

    #[must_use]
    pub const fn evicts(self) -> bool {
        matches!(self, Self::Draining)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Schedulable => "schedulable",
            Self::Cordoned => "cordoned",
            Self::Draining => "draining",
        }
    }
}

impl std::str::FromStr for Schedulability {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "schedulable" => Ok(Self::Schedulable),
            "cordoned" => Ok(Self::Cordoned),
            "draining" => Ok(Self::Draining),
            other => Err(format!(
                "unknown state '{other}' — schedulable, cordoned or draining"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demand {
    pub workload: String,
    pub replicas: u32,
    pub spread: DomainLevel,
    pub domains: Vec<DomainConstraint>,
    pub pin: Option<String>,
    pub stateful: bool,
    pub resources: Resources,
}

impl Demand {
    #[must_use]
    pub fn from_workload(workload: &tg_defs::generated::WorkloadType) -> Self {
        let placement = workload.placement();

        Self {
            workload: workload.name().to_owned(),
            replicas: placement.map_or(1, PlacementExt::replicas),
            stateful: crate::storage::pinned_by_storage(workload),
            spread: placement.map_or(DomainLevel::Rack, PlacementExt::spread),
            domains: placement.map(PlacementExt::domains).unwrap_or_default(),
            pin: placement.and_then(PlacementExt::pin).map(ToOwned::to_owned),
            resources: Resources::from_workload(workload),
        }
    }

    pub fn validate(&self) -> Result<(), PlacementError> {
        if self.pin.is_some() && self.replicas > 1 {
            return Err(PlacementError::PinnedButReplicated {
                workload: self.workload.clone(),
                replicas: self.replicas,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Assignment {
    pub workload: String,
    pub instance: u32,
    pub node: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlacementError {
    PinnedButReplicated {
        workload: String,
        replicas: u32,
    },
    PinnedNodeUnknown {
        workload: String,
        node: String,
    },
    NoDomainLeft {
        workload: String,
        instance: u32,
        level: DomainLevel,
    },
    StatefulNodeGone {
        workload: String,
        instance: u32,
        node: String,
    },
    PinnedToDrainingNode {
        workload: String,
        instance: u32,
        node: String,
    },
    NodeDetached {
        workload: String,
        instance: u32,
        node: String,
    },
    NoRoom {
        workload: String,
        instance: u32,
        wanted: Resources,
    },
}

impl PlacementError {
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::PinnedButReplicated { .. } => "pinned_but_replicated",
            Self::PinnedNodeUnknown { .. } => "pinned_node_unknown",
            Self::NoDomainLeft { .. } => "no_domain_left",
            Self::StatefulNodeGone { .. } => "stateful_node_gone",
            Self::PinnedToDrainingNode { .. } => "pinned_to_draining_node",
            Self::NodeDetached { .. } => "node_detached",
            Self::NoRoom { .. } => "no_room",
        }
    }

    pub const CLASSES: &'static [&'static str] = &[
        "no_domain_left",
        "no_room",
        "node_detached",
        "pinned_but_replicated",
        "pinned_node_unknown",
        "pinned_to_draining_node",
        "stateful_node_gone",
    ];
}

impl fmt::Display for PlacementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PinnedButReplicated { workload, replicas } => write!(
                f,
                "'{workload}' is nailed down to one node but demands {replicas} \
                 instances — a pin carries exactly one (ADR-0027)"
            ),
            Self::PinnedNodeUnknown { workload, node } => write!(
                f,
                "'{workload}' is nailed down to node '{node}', which does not exist"
            ),
            Self::NoDomainLeft {
                workload,
                instance,
                level,
            } => write!(
                f,
                "'{workload}' instance {instance}: no free failure domain at \
                 level '{level}' any more"
            ),
            Self::StatefulNodeGone {
                workload,
                instance,
                node,
            } => write!(
                f,
                "'{workload}' instance {instance} lies on node '{node}', which \
                 no longer exists — a writable volume is not moved (ADR-0027)"
            ),
            Self::PinnedToDrainingNode {
                workload,
                instance,
                node,
            } => write!(
                f,
                "'{workload}' instance {instance} cannot leave '{node}': nailed \
                 down (ADR-0027)"
            ),
            Self::NodeDetached {
                workload,
                instance,
                node,
            } => write!(
                f,
                "'{workload}' instance {instance} cannot go onto '{node}': the \
                 node is detached (ADR-0054)"
            ),
            Self::NoRoom {
                workload,
                instance,
                wanted,
            } => write!(
                f,
                "'{workload}' instance {instance}: no node has {} left",
                wanted
                    .entries()
                    .iter()
                    .map(|(name, amount)| format!("{name}={amount}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl std::error::Error for PlacementError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub kept: Vec<Assignment>,
    pub assignments: Vec<Assignment>,
    pub rejected: Vec<PlacementError>,
    pub usage: BTreeMap<String, Resources>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    pub workload: String,
    pub placed: u32,
    pub wanted: u32,
}

#[must_use]
pub fn coverage(plan: &Plan, demands: &[Demand]) -> Vec<Coverage> {
    let mut placed: BTreeMap<&str, u32> = demands
        .iter()
        .map(|demand| (demand.workload.as_str(), 0))
        .collect();

    for assignment in plan.kept.iter().chain(plan.assignments.iter()) {
        if let Some(count) = placed.get_mut(assignment.workload.as_str()) {
            *count += 1;
        }
    }

    demands
        .iter()
        .map(|demand| Coverage {
            workload: demand.workload.clone(),
            placed: placed
                .get(demand.workload.as_str())
                .copied()
                .unwrap_or_default(),
            wanted: demand.replicas,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headroom {
    pub domain: String,
    pub at_risk: Resources,
    pub elsewhere: Resources,
    pub absorbs: bool,
}

impl Headroom {
    #[must_use]
    pub fn series(&self) -> Vec<(&str, u64, u64)> {
        let mut names: Vec<&str> = self
            .at_risk
            .entries()
            .into_iter()
            .chain(self.elsewhere.entries())
            .map(|(name, _)| name)
            .collect();
        names.sort_unstable();
        names.dedup();

        names
            .into_iter()
            .map(|name| (name, self.at_risk.get(name), self.elsewhere.get(name)))
            .collect()
    }
}

#[must_use]
pub fn headroom(
    nodes: &[Node],
    demands: &[Demand],
    assignments: &[Assignment],
    level: DomainLevel,
) -> Vec<Headroom> {
    let wanted: BTreeMap<&str, &Demand> = demands
        .iter()
        .map(|demand| (demand.workload.as_str(), demand))
        .collect();

    let mut used: BTreeMap<&str, Resources> = BTreeMap::new();
    for assignment in assignments {
        let Some(demand) = wanted.get(assignment.workload.as_str()) else {
            continue;
        };
        let entry = used.entry(assignment.node.as_str()).or_default();
        *entry = entry.clone().plus(&demand.resources);
    }

    let domains: BTreeSet<String> = nodes
        .iter()
        .map(|node| node.topology.domain(level))
        .collect();

    domains
        .into_iter()
        .map(|domain| {
            let mut at_risk = Resources::default();
            let mut elsewhere = Resources::default();
            let empty = Resources::default();

            for node in nodes {
                let on_node = used.get(node.name.as_str()).unwrap_or(&empty);
                if node.topology.domain(level) == domain {
                    at_risk = at_risk.plus(on_node);
                } else if node.accepts_new() {
                    elsewhere = elsewhere.plus(&node.schedulable_capacity().minus(on_node));
                }
            }

            Headroom {
                absorbs: at_risk.fits(&Resources::default(), &elsewhere),
                domain,
                at_risk,
                elsewhere,
            }
        })
        .collect()
}

fn keep(
    existing: &[Assignment],
    wanted: &BTreeMap<&str, &Demand>,
    by_name: &BTreeMap<&str, &Node>,
) -> (Vec<Assignment>, Vec<PlacementError>) {
    let mut immovable = Vec::new();
    let mut kept: Vec<Assignment> = existing
        .iter()
        .filter(|assignment| {
            let Some(demand) = wanted.get(assignment.workload.as_str()) else {
                return false;
            };
            if assignment.instance >= demand.replicas {
                return false;
            }
            let Some(node) = by_name.get(assignment.node.as_str()) else {
                return false;
            };

            if node.evicts() {
                if demand.stateful || demand.pin.is_some() {
                    immovable.push(PlacementError::PinnedToDrainingNode {
                        workload: demand.workload.clone(),
                        instance: assignment.instance,
                        node: assignment.node.clone(),
                    });
                    return true;
                }
                return false;
            }

            true
        })
        .cloned()
        .collect();
    kept.sort();
    kept.dedup();

    (kept, immovable)
}

#[must_use]
pub fn plan(demands: &[Demand], nodes: &[Node], existing: &[Assignment]) -> Plan {
    let by_name: BTreeMap<&str, &Node> = nodes
        .iter()
        .map(|node| (node.name.as_str(), node))
        .collect();
    let wanted: BTreeMap<&str, &Demand> = demands
        .iter()
        .map(|demand| (demand.workload.as_str(), demand))
        .collect();

    // --- 1. What stays ----------------------------------------------------
    let (kept, immovable) = keep(existing, &wanted, &by_name);

    // --- 2. Occupancy -----------------------------------------------------
    let mut used: BTreeMap<&str, Resources> = BTreeMap::new();
    let mut taken: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();

    for assignment in &kept {
        let Some(demand) = wanted.get(assignment.workload.as_str()) else {
            continue;
        };
        let Some(node) = by_name.get(assignment.node.as_str()) else {
            continue;
        };

        let entry = used.entry(node.name.as_str()).or_default();
        *entry = entry.clone().plus(&demand.resources);

        taken
            .entry(demand.workload.as_str())
            .or_default()
            .insert(node.topology.domain(demand.spread));
    }

    // --- 3. and 4. Place what is missing ----------------------------------
    let stranded = stranded(demands, nodes, existing);
    let stranded_instances: BTreeSet<(String, u32)> =
        stranded.iter().filter_map(stranded_instance).collect();

    let mut rejected = stranded;
    rejected.extend(immovable);

    let mut plan = Plan {
        kept,
        rejected,
        ..Plan::default()
    };

    for demand in wanted.values() {
        if let Err(err) = demand.validate() {
            plan.rejected.push(err);
            continue;
        }

        let placed: BTreeSet<u32> = plan
            .kept
            .iter()
            .filter(|assignment| assignment.workload == demand.workload)
            .map(|assignment| assignment.instance)
            .collect();

        for instance in 0..demand.replicas {
            if placed.contains(&instance)
                || stranded_instances.contains(&(demand.workload.clone(), instance))
            {
                continue;
            }

            match choose(demand, instance, nodes, &used, &taken) {
                Ok(node) => {
                    let entry = used.entry(node).or_default();
                    *entry = entry.clone().plus(&demand.resources);

                    let topology = &by_name[node].topology;
                    taken
                        .entry(demand.workload.as_str())
                        .or_default()
                        .insert(topology.domain(demand.spread));

                    plan.assignments.push(Assignment {
                        workload: demand.workload.clone(),
                        instance,
                        node: node.to_owned(),
                    });
                }
                Err(err) => plan.rejected.push(err),
            }
        }
    }

    plan.assignments.sort();
    // **The nodes without an assignment too** (ADR-0127): a missing time
    // series is indistinguishable from a switched-off reporter, and an empty
    // node is the information an operator is looking for.
    plan.usage = nodes
        .iter()
        .map(|node| {
            (
                node.name.clone(),
                used.get(node.name.as_str()).cloned().unwrap_or_default(),
            )
        })
        .collect();
    plan
}

fn stranded(demands: &[Demand], nodes: &[Node], existing: &[Assignment]) -> Vec<PlacementError> {
    let known: BTreeSet<&str> = nodes.iter().map(|node| node.name.as_str()).collect();
    let wanted: BTreeMap<&str, &Demand> = demands
        .iter()
        .map(|demand| (demand.workload.as_str(), demand))
        .collect();

    let mut out: Vec<PlacementError> = existing
        .iter()
        .filter(|assignment| {
            wanted
                .get(assignment.workload.as_str())
                .is_some_and(|demand| demand.stateful && assignment.instance < demand.replicas)
                && !known.contains(assignment.node.as_str())
        })
        .map(|assignment| PlacementError::StatefulNodeGone {
            workload: assignment.workload.clone(),
            instance: assignment.instance,
            node: assignment.node.clone(),
        })
        .collect();

    out.sort_by_key(|error| stranded_instance(error).unwrap_or_default());
    out.dedup_by_key(|error| stranded_instance(error).unwrap_or_default());

    out
}

fn stranded_instance(error: &PlacementError) -> Option<(String, u32)> {
    match error {
        PlacementError::StatefulNodeGone {
            workload, instance, ..
        } => Some((workload.clone(), *instance)),
        _ => None,
    }
}

fn choose<'a>(
    demand: &Demand,
    instance: u32,
    nodes: &'a [Node],
    used: &BTreeMap<&str, Resources>,
    taken: &BTreeMap<&str, BTreeSet<String>>,
) -> Result<&'a str, PlacementError> {
    let empty = BTreeSet::new();
    let occupied = taken.get(demand.workload.as_str()).unwrap_or(&empty);

    // Pin: exactly one node comes into question, and if it does not exist that
    // is a rejection and no reason to place elsewhere (ADR-0027).
    if let Some(pinned) = &demand.pin {
        let Some(node) = nodes.iter().find(|node| node.name == *pinned) else {
            return Err(PlacementError::PinnedNodeUnknown {
                workload: demand.workload.clone(),
                node: pinned.clone(),
            });
        };

        // A pin does not place onto a cordoned node either. That is the
        // uncomfortable but right answer: the workload stays unplaced and
        // reported instead of landing on a node an operator is just emptying.
        // **Detached first**, because the reason is different: "detached" and
        // "cordoned" send an operator to different places (ADR-0054).
        if !node.attachment.in_mesh() {
            return Err(PlacementError::NodeDetached {
                workload: demand.workload.clone(),
                instance,
                node: node.name.clone(),
            });
        }
        if !node.schedulable.accepts_new() {
            return Err(PlacementError::PinnedToDrainingNode {
                workload: demand.workload.clone(),
                instance,
                node: node.name.clone(),
            });
        }

        let free = Resources::default();
        let on_node = used.get(node.name.as_str()).unwrap_or(&free);
        if !demand.resources.fits(on_node, &node.schedulable_capacity()) {
            return Err(PlacementError::NoRoom {
                workload: demand.workload.clone(),
                instance,
                wanted: demand.resources.clone(),
            });
        }

        return Ok(node.name.as_str());
    }

    // **Cordoned nodes are no candidates** — before any other restriction, so
    // that the rejection afterwards names the right one: a cordoned node shall
    // not appear as "no room".
    let in_domains: Vec<&Node> = nodes
        .iter()
        .filter(|node| node.accepts_new())
        .filter(|node| satisfies(&node.topology, &demand.domains))
        .collect();

    let free_domain: Vec<&Node> = in_domains
        .iter()
        .copied()
        .filter(|node| !occupied.contains(&node.topology.domain(demand.spread)))
        .collect();

    if free_domain.is_empty() {
        return Err(PlacementError::NoDomainLeft {
            workload: demand.workload.clone(),
            instance,
            level: demand.spread,
        });
    }

    let empty_usage = Resources::default();
    let mut candidates: Vec<&Node> = free_domain
        .into_iter()
        .filter(|node| {
            demand.resources.fits(
                used.get(node.name.as_str()).unwrap_or(&empty_usage),
                &node.schedulable_capacity(),
            )
        })
        .collect();

    if candidates.is_empty() {
        return Err(PlacementError::NoRoom {
            workload: demand.workload.clone(),
            instance,
            wanted: demand.resources.clone(),
        });
    }

    // **Least occupied means: the lowest pressure** (ADR-0109) -- the
    // utilization of the scarcest resource, not the lexicographic ordering of
    // the map. On a tie the name (ADR-0034, unchanged).
    candidates.sort_by_key(|node| {
        let node_used = used.get(node.name.as_str()).unwrap_or(&empty_usage);
        (
            node_used.pressure(&node.schedulable_capacity()),
            node.name.clone(),
        )
    });

    Ok(candidates[0].name.as_str())
}

fn satisfies(topology: &Topology, constraints: &[DomainConstraint]) -> bool {
    let mut by_level: BTreeMap<DomainLevel, Vec<&str>> = BTreeMap::new();
    for constraint in constraints {
        by_level
            .entry(constraint.level)
            .or_default()
            .push(constraint.value.as_str());
    }

    by_level
        .into_iter()
        .all(|(level, allowed)| allowed.contains(&topology.label(level)))
}
