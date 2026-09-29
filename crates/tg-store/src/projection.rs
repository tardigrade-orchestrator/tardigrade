//! The materialized view, in-process.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use tg_defs::{DependencyKind, ImageExt as _, WorkloadExt as _, generated::WorkloadType};
use tg_model::placement::Resources;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActualStatus {
    Running,
    Stopped,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRecord {
    pub name: String,
    pub image: String,
}

fn worst(states: impl Iterator<Item = ActualStatus>) -> ActualStatus {
    states
        .max_by_key(|status| rank(*status))
        .unwrap_or(ActualStatus::Unknown)
}

fn rank(status: ActualStatus) -> u8 {
    match status {
        ActualStatus::Running => 0,
        ActualStatus::Unknown => 1,
        ActualStatus::Stopped => 2,
        ActualStatus::Failed => 3,
    }
}

#[derive(Debug, Default)]
struct Inner {
    workloads: BTreeMap<String, WorkloadRecord>,
    edges: BTreeMap<(String, DependencyKind), BTreeSet<String>>,
}

type FailureClasses = BTreeMap<(String, u32), String>;

type InstanceStates = BTreeMap<(String, u32), ActualStatus>;

#[derive(Debug, Default)]
pub struct Projection {
    inner: RwLock<Inner>,
    isolated: RwLock<BTreeMap<String, Vec<String>>>,
    retired: RwLock<BTreeMap<String, Vec<String>>>,
    slices: RwLock<BTreeMap<String, u64>>,
    applied: RwLock<Option<u64>>,
    actual: RwLock<BTreeMap<String, InstanceStates>>,
    reported: RwLock<BTreeMap<String, Resources>>,
    seen: RwLock<BTreeMap<String, i64>>,
    key_generations: RwLock<BTreeMap<String, tg_model::Generations>>,
    proxy_images: RwLock<BTreeMap<String, String>>,
    dns_zones: RwLock<BTreeMap<String, String>>,
    userns: RwLock<BTreeMap<String, Option<u32>>>,
    stale: RwLock<BTreeMap<String, std::collections::BTreeSet<(String, u32)>>>,
    unready: RwLock<BTreeMap<String, std::collections::BTreeSet<(String, u32)>>>,
    failures: RwLock<BTreeMap<String, FailureClasses>>,
    endpoints: RwLock<BTreeMap<String, Vec<crate::session::ReportedEndpoint>>>,
}

impl Projection {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn report_slice(&self, node: &str, index: u64) {
        if let Ok(mut slices) = self.slices.write() {
            slices.insert(node.to_owned(), index);
        }
    }

    #[must_use]
    pub fn reported_slices(&self) -> BTreeMap<String, u64> {
        self.slices
            .read()
            .map(|slices| slices.clone())
            .unwrap_or_default()
    }

    pub fn note_applied(&self, index: Option<u64>) {
        if let Ok(mut applied) = self.applied.write() {
            *applied = index;
        }
    }

    #[must_use]
    pub fn applied(&self) -> Option<u64> {
        self.applied.read().ok().and_then(|applied| *applied)
    }

    pub fn materialize(&self, workloads: &[WorkloadType]) {
        let mut inner = self.write();
        inner.workloads.clear();
        inner.edges.clear();

        for workload in workloads {
            inner.workloads.insert(
                workload.name().to_owned(),
                WorkloadRecord {
                    name: workload.name().to_owned(),
                    image: workload.image().reference().to_owned(),
                },
            );
        }

        for workload in workloads {
            for dependency in workload.dependencies() {
                inner
                    .edges
                    .entry((workload.name().to_owned(), dependency.kind()))
                    .or_default()
                    .insert(dependency.target().to_owned());
            }
        }
    }

    pub fn report_instances(&self, node: &str, states: Vec<(String, u32, ActualStatus)>) {
        let mut guard = self.actual.write().unwrap_or_else(PoisonError::into_inner);
        if states.is_empty() {
            guard.remove(node);
        } else {
            guard.insert(
                node.to_owned(),
                states
                    .into_iter()
                    .map(|(workload, instance, status)| ((workload, instance), status))
                    .collect(),
            );
        }
    }

    pub fn report_capacity(&self, node: &str, capacity: Resources) {
        self.reported
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(node.to_owned(), capacity);
    }

    pub fn report_seen(&self, node: &str, at: i64) {
        self.seen
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(node.to_owned(), at);
    }

    #[must_use]
    pub fn reporting_since(&self, since: i64) -> std::collections::BTreeSet<String> {
        self.seen
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, at)| **at >= since)
            .map(|(node, _)| node.clone())
            .collect()
    }

    pub fn report_proxy_image(&self, node: &str, image: Option<&str>) {
        let mut slot = self
            .proxy_images
            .write()
            .unwrap_or_else(PoisonError::into_inner);

        match image {
            // A node without a mesh builds no sidecars — it does not count
            // towards the deviation instead of appearing as a "version" of its
            // own.
            None => slot.remove(node),
            Some(image) => slot.insert(node.to_owned(), image.to_owned()),
        };
    }

    #[must_use]
    pub fn reported_proxy_images(&self) -> BTreeMap<String, String> {
        self.proxy_images
            .read()
            .map(|slot| slot.clone())
            .unwrap_or_default()
    }

    pub fn report_dns_zone(&self, node: &str, zone: Option<&str>) {
        let mut slot = self
            .dns_zones
            .write()
            .unwrap_or_else(PoisonError::into_inner);

        match zone {
            // A node without a node network serves no names — its zone is of no
            // consequence to a client, and counting it would produce a deviation
            // that concerns nobody. The same choice as with a node without a
            // mesh and the proxy image.
            None => slot.remove(node),
            Some(zone) => slot.insert(node.to_owned(), zone.to_owned()),
        };
    }

    pub fn report_userns(&self, node: &str, base: Option<u32>) {
        self.userns
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(node.to_owned(), base);
    }

    #[must_use]
    pub fn reported_userns(&self) -> BTreeMap<String, Option<u32>> {
        self.userns
            .read()
            .map(|slot| slot.clone())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn distinct_userns_postures(&self) -> usize {
        self.userns
            .read()
            .map(|slot| {
                slot.values()
                    .map(Option::is_some)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn reported_dns_zones(&self) -> BTreeMap<String, String> {
        self.dns_zones
            .read()
            .map(|slot| slot.clone())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn distinct_dns_zones(&self) -> usize {
        self.dns_zones
            .read()
            .map(|slot| {
                slot.values()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn last_reports(&self) -> BTreeMap<String, i64> {
        self.seen
            .read()
            .map(|slot| slot.clone())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn distinct_proxy_images(&self) -> usize {
        self.proxy_images
            .read()
            .map(|slot| {
                slot.values()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            })
            .unwrap_or_default()
    }

    pub fn report_key_generations(&self, node: &str, generations: tg_model::Generations) {
        self.key_generations
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(node.to_owned(), generations);
    }

    pub fn report_isolated(&self, node: &str, isolated: Vec<String>) {
        if let Ok(mut all) = self.isolated.write() {
            if isolated.is_empty() {
                all.remove(node);
            } else {
                all.insert(node.to_owned(), isolated);
            }
        }
    }

    pub fn report_retired(&self, node: &str, retired: Vec<String>) {
        if let Ok(mut all) = self.retired.write() {
            if retired.is_empty() {
                all.remove(node);
            } else {
                all.insert(node.to_owned(), retired);
            }
        }
    }

    #[must_use]
    pub fn reported_retired(&self) -> BTreeMap<String, Vec<String>> {
        self.retired
            .read()
            .map(|all| all.clone())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn isolated_entries(&self) -> BTreeMap<String, Vec<String>> {
        self.isolated
            .read()
            .map(|all| all.clone())
            .unwrap_or_default()
    }

    pub fn report_failures(&self, node: &str, failures: Vec<(String, u32, String)>) {
        let mut guard = self
            .failures
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if failures.is_empty() {
            // No entry instead of an empty one, so that a node without a failure
            // does not stand there as "reported, but empty".
            guard.remove(node);
        } else {
            guard.insert(
                node.to_owned(),
                failures
                    .into_iter()
                    .map(|(workload, instance, class)| ((workload, instance), class))
                    .collect(),
            );
        }
    }

    #[must_use]
    pub fn failure_classes(&self, workload: &str) -> BTreeMap<u32, String> {
        let guard = self.failures.read().unwrap_or_else(PoisonError::into_inner);
        guard
            .values()
            .flat_map(|per_node| per_node.iter())
            .filter(|((name, _), _)| name == workload)
            .map(|((_, instance), class)| (*instance, class.clone()))
            .collect()
    }

    pub fn report_stale(&self, node: &str, stale: Vec<(String, u32)>) {
        let mut guard = self.stale.write().unwrap_or_else(PoisonError::into_inner);
        if stale.is_empty() {
            // Nothing stale means **no entry**, not an empty one: that way the
            // map says which nodes ever reported anything — and an empty entry
            // would be indistinguishable from "nothing heard".
            guard.remove(node);
        } else {
            guard.insert(node.to_owned(), stale.into_iter().collect());
        }
    }

    pub fn report_unready(&self, node: &str, unready: Vec<(String, u32)>) {
        let mut guard = self.unready.write().unwrap_or_else(PoisonError::into_inner);
        if unready.is_empty() {
            // Nothing unready means **no entry**, not an empty one — as at
            // [`Self::report_stale`].
            //
            // Without an observable effect, and that stands here instead of as
            // an assertion: `insert` replaces a node's entry anyway, and
            // [`Self::unready`] unions — an empty set is indistinguishable from
            // a missing entry. It stays for consistency with the neighbour.
            guard.remove(node);
        } else {
            guard.insert(node.to_owned(), unready.into_iter().collect());
        }
    }

    #[must_use]
    pub fn unready(&self) -> std::collections::BTreeSet<(String, u32)> {
        // **The union over all nodes**, as at [`Self::stale_instances`]: an
        // instance runs on exactly one node, so there is nothing to merge. In an
        // agent's projection it is its own set, because it is the only reporter.
        self.unready
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .flatten()
            .cloned()
            .collect()
    }

    pub fn report_endpoints(&self, node: &str, endpoints: Vec<crate::session::ReportedEndpoint>) {
        let mut guard = self
            .endpoints
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if endpoints.is_empty() {
            // As at `report_stale`: no entry instead of an empty one, so that
            // "reported nothing" stays distinguishable from "nothing heard yet".
            guard.remove(node);
        } else {
            guard.insert(node.to_owned(), endpoints);
        }
    }

    #[must_use]
    pub fn reported_endpoints(&self) -> BTreeMap<String, Vec<crate::session::RemoteEndpoint>> {
        let actual = self.actual_states();
        let unready = self.unready();
        self.endpoints
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(node, reported)| {
                let endpoints = reported
                    .iter()
                    .map(
                        |(workload, instance, address)| crate::session::RemoteEndpoint {
                            workload: workload.clone(),
                            instance: *instance,
                            address: *address,
                            // **Two axes** (ADR-0080): running **and** serving.
                            // Without the second a foreign node offered the
                            // address of an unready instance while its own node
                            // withheld it — visibly different answers for the
                            // same name.
                            healthy: matches!(
                                actual.get(&(workload.clone(), *instance)),
                                Some(ActualStatus::Running)
                            ) && !unready.contains(&(workload.clone(), *instance)),
                        },
                    )
                    .collect();
                (node.clone(), endpoints)
            })
            .collect()
    }

    #[must_use]
    pub fn stale_instances(&self, workload: &str) -> Vec<u32> {
        let guard = self.stale.read().unwrap_or_else(PoisonError::into_inner);
        let mut instances: Vec<u32> = guard
            .values()
            .flat_map(|entries| {
                entries
                    .iter()
                    .filter(|(name, _)| name == workload)
                    .map(|(_, instance)| *instance)
            })
            .collect();
        instances.sort_unstable();
        instances.dedup();
        instances
    }

    #[must_use]
    pub fn unready_instances(&self, workload: &str) -> Vec<u32> {
        let mut instances: Vec<u32> = self
            .unready()
            .into_iter()
            .filter(|(name, _)| name == workload)
            .map(|(_, instance)| instance)
            .collect();
        instances.sort_unstable();
        instances.dedup();
        instances
    }

    #[must_use]
    pub fn reported_key_generations(&self) -> BTreeMap<String, tg_model::Generations> {
        self.key_generations
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn reported_capacity(&self) -> BTreeMap<String, Resources> {
        self.reported
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn workloads(&self) -> Vec<WorkloadRecord> {
        self.read().workloads.values().cloned().collect()
    }

    #[must_use]
    pub fn targets_of(&self, name: &str, kind: DependencyKind) -> Vec<String> {
        self.read()
            .edges
            .get(&(name.to_owned(), kind))
            .map(|targets| targets.iter().cloned().collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn actual_states(&self) -> BTreeMap<(String, u32), ActualStatus> {
        self.actual
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .flat_map(|states| states.iter().map(|(key, status)| (key.clone(), *status)))
            .collect()
    }

    #[must_use]
    pub fn instances_of(&self, workload: &str) -> BTreeMap<u32, ActualStatus> {
        self.actual
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .flat_map(|states| {
                states
                    .iter()
                    .filter(|((name, _), _)| name == workload)
                    .map(|((_, instance), status)| (*instance, *status))
            })
            .collect()
    }

    #[must_use]
    pub fn worst_of(&self, name: &str) -> ActualStatus {
        worst(self.instances_of(name).into_values())
    }

    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }
}
