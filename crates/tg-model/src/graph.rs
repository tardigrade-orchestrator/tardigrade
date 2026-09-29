//! Dependency graph per ADR-0009.
//!
//! Two **orthogonal** axes that are deliberately not mixed:
//!
//! - **Ordering** (`after`, `before`) — only the order. It has to be acyclic,
//!   otherwise there is no start order.
//! - **Requirement** (`requires`, `wants`, `bindsTo`, `conflicts`) — failure
//!   and lifecycle coupling. It may contain cycles: two services may need each
//!   other.
//!
//! A requirement implies **no** ordering. That is the systemd pitfall ADR-0009
//! wants to avoid, and the reason for [`DependencyGraph::lints`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use tg_defs::PlacementExt;
use tg_defs::generated::WorkloadType;
use tg_defs::{Dependency, DependencyKind, WorkloadClass, WorkloadExt as _, WorkloadSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    DuplicateWorkload {
        name: String,
    },
    UnknownTarget {
        workload: String,
        kind: DependencyKind,
        target: String,
    },
    SelfReference {
        workload: String,
        kind: DependencyKind,
    },
    OrderingCycle {
        cycle: Vec<String>,
    },
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateWorkload { name } => {
                write!(f, "workload '{name}' is defined more than once")
            }
            Self::UnknownTarget {
                workload,
                kind,
                target,
            } => write!(
                f,
                "workload '{workload}' declares {} on '{target}', which does not exist",
                kind.as_element()
            ),
            Self::SelfReference { workload, kind } => write!(
                f,
                "workload '{workload}' declares {} on itself",
                kind.as_element()
            ),
            Self::OrderingCycle { cycle } => write!(
                f,
                "cycle in the start order: {} -> {}",
                cycle.join(" -> "),
                cycle.first().map_or("?", String::as_str)
            ),
        }
    }
}

impl std::error::Error for GraphError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Inactivity {
    Failed,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lint {
    SingleWriterWithoutStandby {
        workload: String,
    },
    RequirementWithoutOrdering {
        workload: String,
        kind: DependencyKind,
        target: String,
    },
}

impl fmt::Display for Lint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleWriterWithoutStandby { workload } => write!(
                f,
                "'{workload}' is single-writer with one instance — no warm \
                 standby, so no fast failover (ADR-0010). \
                 <placement replicas=\"2\"/> sets one"
            ),
            Self::RequirementWithoutOrdering {
                workload,
                kind,
                target,
            } => write!(
                f,
                "'{workload}' declares {} on '{target}', but no <after ref=\"{target}\"/>: \
                 the target has to run but may start later",
                kind.as_element()
            ),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct Edges {
    after: BTreeSet<String>,
    requires: BTreeSet<String>,
    wants: BTreeSet<String>,
    binds_to: BTreeSet<String>,
    conflicts: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Isolated {
    DuplicateName {
        workload: String,
    },
    SelfReference {
        workload: String,
        kind: DependencyKind,
    },
    OrderingCycle {
        workload: String,
        cycle: Vec<String>,
    },
    Unusable {
        workload: String,
    },
}

impl Isolated {
    #[must_use]
    pub fn workload(&self) -> &str {
        match self {
            Self::DuplicateName { workload }
            | Self::SelfReference { workload, .. }
            | Self::OrderingCycle { workload, .. }
            | Self::Unusable { workload } => workload,
        }
    }
}

impl fmt::Display for Isolated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateName { workload } => {
                write!(f, "'{workload}' is declared by more than one document")
            }
            Self::SelfReference { workload, kind } => {
                write!(f, "'{workload}' declares {} on itself", kind.as_element())
            }
            Self::OrderingCycle { workload, cycle } => {
                write!(
                    f,
                    "'{workload}' lies on a cycle in the start order: {}",
                    cycle.join(" -> ")
                )
            }
            Self::Unusable { workload } => write!(f, "'{workload}' cannot be classified"),
        }
    }
}

fn self_referencing(workload: &WorkloadType) -> Option<DependencyKind> {
    workload
        .dependencies()
        .into_iter()
        .find(|dependency| dependency.target() == workload.name())
        .map(Dependency::kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Foreign {
    Reject,
    Drop,
}

#[derive(Debug, Clone)]
pub struct DependencyGraph {
    edges: BTreeMap<String, Edges>,
    foreign: BTreeSet<String>,
    traits: BTreeMap<String, Traits>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Traits {
    single_writer: bool,
    replicas: u32,
}

impl DependencyGraph {
    pub fn build(set: &WorkloadSet) -> Result<Self, GraphError> {
        Self::from_workloads(set.workloads())
    }

    pub fn from_workloads(workloads: &[WorkloadType]) -> Result<Self, GraphError> {
        let graph = Self::assemble(workloads, Foreign::Reject)?;
        if let Some(cycle) = graph.find_ordering_cycle() {
            return Err(GraphError::OrderingCycle { cycle });
        }

        Ok(graph)
    }

    #[must_use]
    pub fn from_local(workloads: &[WorkloadType]) -> (Self, Vec<Isolated>) {
        let mut isolated = Vec::new();
        let mut kept: Vec<WorkloadType> = Vec::new();

        // **Duplicate names first, and both go.** Which one is meant nobody
        // knows; taking one of them would mean guessing — and the wrong one
        // would then run with the right one's definition.
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for workload in workloads {
            *seen.entry(workload.name()).or_default() += 1;
        }
        for workload in workloads {
            if seen.get(workload.name()).copied().unwrap_or_default() > 1 {
                continue;
            }
            // A self-reference is a property of **this** workload and costs
            // only it.
            if let Some(kind) = self_referencing(workload) {
                isolated.push(Isolated::SelfReference {
                    workload: workload.name().to_owned(),
                    kind,
                });
                continue;
            }
            kept.push(workload.clone());
        }
        for (name, count) in seen {
            if count > 1 {
                isolated.push(Isolated::DuplicateName {
                    workload: name.to_owned(),
                });
            }
        }

        // **Cycles: remove and search again.** Every round removes at least
        // one workload, so it terminates. Which one is "to blame" nobody says —
        // the cycle is named as a whole.
        loop {
            // `assemble` can no longer fail here: foreign targets are
            // dropped, self-reference and duplicate names are out above. Were
            // something to remain nevertheless, leaving it out would be more
            // right than dying — that is the whole statement of ADR-0062. The
            // branch therefore stands here and not as an `expect`.
            let Ok(graph) = Self::assemble(&kept, Foreign::Drop) else {
                isolated.extend(kept.iter().map(|workload| Isolated::Unusable {
                    workload: workload.name().to_owned(),
                }));
                kept.clear();
                continue;
            };
            let cycle = graph.find_ordering_cycle();

            let Some(cycle) = cycle else {
                isolated.sort_by(|a, b| a.workload().cmp(b.workload()));
                return (graph, isolated);
            };

            let members: BTreeSet<&str> = cycle.iter().map(String::as_str).collect();
            for name in &members {
                isolated.push(Isolated::OrderingCycle {
                    workload: (*name).to_owned(),
                    cycle: cycle.clone(),
                });
            }
            kept.retain(|workload| !members.contains(workload.name()));
        }
    }

    #[must_use]
    pub fn foreign(&self) -> &BTreeSet<String> {
        &self.foreign
    }

    fn assemble(workloads: &[WorkloadType], foreign: Foreign) -> Result<Self, GraphError> {
        let mut edges: BTreeMap<String, Edges> = BTreeMap::new();

        for workload in workloads {
            let name = workload.name().to_owned();
            if edges.contains_key(&name) {
                return Err(GraphError::DuplicateWorkload { name });
            }
            edges.insert(name, Edges::default());
        }

        // Second pass: now all names are known, targets are checkable.
        let mut dropped = BTreeSet::new();
        for workload in workloads {
            let name = workload.name();
            for dependency in workload.dependencies() {
                Self::insert_edge(&mut edges, name, dependency, foreign, &mut dropped)?;
            }
        }

        let traits = workloads
            .iter()
            .map(|workload| {
                (
                    workload.name().to_owned(),
                    Traits {
                        single_writer: workload.class() == WorkloadClass::SingleWriter,
                        // The same default as in `Demand::from_workload`, and
                        // it is the reason for the lint: without `<placement>`
                        // it is **one** instance.
                        replicas: workload.placement().map_or(1, PlacementExt::replicas),
                    },
                )
            })
            .collect();

        // **The cycle is not checked here**, and that is no omission: the two
        // views answer it differently. The strict way refuses, the node view
        // isolates the members and builds on (ADR-0062). Were the check to
        // stand here, in the node view it would drag the uninvolved along too —
        // precisely that is what the test
        // `an_ordering_cycle_isolates_its_members_and_leaves_the_rest` showed
        // while it was being built.
        Ok(Self {
            edges,
            traits,
            foreign: dropped,
        })
    }

    fn insert_edge(
        edges: &mut BTreeMap<String, Edges>,
        workload: &str,
        dependency: Dependency<'_>,
        foreign: Foreign,
        dropped: &mut BTreeSet<String>,
    ) -> Result<(), GraphError> {
        let kind = dependency.kind();
        let target = dependency.target();

        // The self-reference comes **before** the foreignness question: it
        // does not point outwards but at itself, and stays wrong in both
        // views.
        if target == workload {
            return Err(GraphError::SelfReference {
                workload: workload.to_owned(),
                kind,
            });
        }
        if !edges.contains_key(target) {
            return match foreign {
                Foreign::Reject => Err(GraphError::UnknownTarget {
                    workload: workload.to_owned(),
                    kind,
                    target: target.to_owned(),
                }),
                Foreign::Drop => {
                    dropped.insert(target.to_owned());
                    Ok(())
                }
            };
        }

        match kind {
            // `before` is the reverse of `after` and is stored as one edge
            // with a direction (ADR-0009): "A before B" means that B starts
            // after A.
            DependencyKind::Before => {
                Self::entry(edges, target).after.insert(workload.to_owned());
            }
            DependencyKind::After => {
                Self::entry(edges, workload).after.insert(target.to_owned());
            }
            DependencyKind::Requires => {
                Self::entry(edges, workload)
                    .requires
                    .insert(target.to_owned());
            }
            DependencyKind::Wants => {
                Self::entry(edges, workload).wants.insert(target.to_owned());
            }
            DependencyKind::BindsTo => {
                Self::entry(edges, workload)
                    .binds_to
                    .insert(target.to_owned());
            }
            DependencyKind::Conflicts => {
                Self::entry(edges, workload)
                    .conflicts
                    .insert(target.to_owned());
            }
        }

        Ok(())
    }

    fn entry<'a>(edges: &'a mut BTreeMap<String, Edges>, name: &str) -> &'a mut Edges {
        edges.entry(name.to_owned()).or_default()
    }

    #[must_use]
    pub fn workloads(&self) -> Vec<&str> {
        self.edges.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn start_order(&self) -> Vec<&str> {
        let mut remaining: BTreeMap<&str, usize> = self
            .edges
            .iter()
            .map(|(name, edges)| (name.as_str(), edges.after.len()))
            .collect();

        // A BTreeSet instead of a Vec: the set of workloads ready to start
        // stays sorted, so the tiebreak is the name.
        let mut ready: BTreeSet<&str> = remaining
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(name, _)| *name)
            .collect();

        let mut order = Vec::with_capacity(self.edges.len());

        while let Some(name) = ready.iter().next().copied() {
            ready.remove(name);
            order.push(name);

            for (candidate, edges) in &self.edges {
                if !edges.after.iter().any(|dep| dep == name) {
                    continue;
                }
                if let Some(count) = remaining.get_mut(candidate.as_str()) {
                    *count -= 1;
                    if *count == 0 {
                        ready.insert(candidate.as_str());
                    }
                }
            }
        }

        order
    }

    fn find_ordering_cycle(&self) -> Option<Vec<String>> {
        let mut marks: BTreeMap<&str, Mark> = BTreeMap::new();
        let mut path: Vec<&str> = Vec::new();

        for start in self.edges.keys() {
            if marks.contains_key(start.as_str()) {
                continue;
            }
            if let Some(cycle) = self.walk(start.as_str(), &mut marks, &mut path) {
                return Some(cycle);
            }
        }

        None
    }

    fn walk<'a>(
        &'a self,
        name: &'a str,
        marks: &mut BTreeMap<&'a str, Mark>,
        path: &mut Vec<&'a str>,
    ) -> Option<Vec<String>> {
        marks.insert(name, Mark::Open);
        path.push(name);

        if let Some(edges) = self.edges.get(name) {
            for next in &edges.after {
                match marks.get(next.as_str()) {
                    Some(Mark::Done) => {}
                    Some(Mark::Open) => {
                        // The cycle is the piece of path from the reunion on.
                        let start = path.iter().position(|n| *n == next.as_str())?;
                        return Some(path[start..].iter().map(|n| (*n).to_owned()).collect());
                    }
                    None => {
                        if let Some(cycle) = self.walk(next.as_str(), marks, path) {
                            return Some(cycle);
                        }
                    }
                }
            }
        }

        path.pop();
        marks.insert(name, Mark::Done);
        None
    }

    #[must_use]
    pub fn cascade_stop(&self, trigger: &[(&str, Inactivity)]) -> BTreeSet<String> {
        let mut stopped: BTreeSet<String> = BTreeSet::new();
        let mut queue: VecDeque<(String, Inactivity)> = trigger
            .iter()
            .map(|(name, state)| ((*name).to_owned(), *state))
            .collect();
        let mut seen: BTreeSet<(String, Inactivity)> = queue.iter().cloned().collect();

        while let Some((target, state)) = queue.pop_front() {
            for (candidate, edges) in &self.edges {
                let hit = edges.binds_to.contains(&target)
                    || (matches!(state, Inactivity::Failed) && edges.requires.contains(&target));
                if !hit {
                    continue;
                }

                // Those dragged along count as stopped, not as failed.
                let next = (candidate.clone(), Inactivity::Stopped);
                if seen.insert(next.clone()) {
                    stopped.insert(candidate.clone());
                    queue.push_back(next);
                }
            }
        }

        // A trigger that reappears over a cycle is not one dragged along.
        for (name, _) in trigger {
            stopped.remove(*name);
        }

        stopped
    }

    #[must_use]
    pub fn lints(&self) -> Vec<Lint> {
        let mut lints = Vec::new();

        for (name, traits) in &self.traits {
            if traits.single_writer && traits.replicas < 2 {
                lints.push(Lint::SingleWriterWithoutStandby {
                    workload: name.clone(),
                });
            }
        }

        for (name, edges) in &self.edges {
            let hard = edges
                .requires
                .iter()
                .map(|t| (DependencyKind::Requires, t))
                .chain(edges.binds_to.iter().map(|t| (DependencyKind::BindsTo, t)));

            for (kind, target) in hard {
                if !edges.after.contains(target) {
                    lints.push(Lint::RequirementWithoutOrdering {
                        workload: name.clone(),
                        kind,
                        target: target.clone(),
                    });
                }
            }
        }

        lints
    }

    #[must_use]
    pub fn may_be_active_together(&self, a: &str, b: &str) -> bool {
        !excluded(a, b, |from, to| {
            self.edges
                .get(from)
                .is_some_and(|edges| edges.conflicts.contains(to))
        })
    }
}

fn excluded(a: &str, b: &str, declares: impl Fn(&str, &str) -> bool) -> bool {
    a != b && (declares(a, b) || declares(b, a))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictError {
    BothWanted {
        first: String,
        second: String,
    },
}

impl std::fmt::Display for ConflictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self::BothWanted { first, second } = self;
        write!(
            f,
            "'{first}' and '{second}' must not be active at the same time \
             (<conflicts>), but both are wanted"
        )
    }
}

impl std::error::Error for ConflictError {}

pub fn validate_conflicts(workloads: &[WorkloadType]) -> Result<(), ConflictError> {
    let excluding: BTreeMap<&str, BTreeSet<&str>> = workloads
        .iter()
        .map(|workload| {
            let targets = workload
                .dependencies()
                .into_iter()
                .filter(|dependency| dependency.kind() == DependencyKind::Conflicts)
                .map(Dependency::target)
                .collect();
            (workload.name(), targets)
        })
        .collect();

    let declares = |from: &str, to: &str| excluding.get(from).is_some_and(|set| set.contains(to));

    // Over the **names** and not over the document order: the finding shall
    // not depend on who was submitted first.
    let names: Vec<&str> = excluding.keys().copied().collect();
    for (index, first) in names.iter().enumerate() {
        for second in &names[index + 1..] {
            if excluded(first, second, declares) {
                return Err(ConflictError::BothWanted {
                    first: (*first).to_owned(),
                    second: (*second).to_owned(),
                });
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Mark {
    Open,
    Done,
}
