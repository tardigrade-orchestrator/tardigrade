//! The node agent's level-triggered reconcile loop.
//!
//! ADR-0010 (the reconciliation model) and ADR-0019 (static stability).
//!
//! **Level-triggered**, not edge-triggered: every pass compares the complete
//! actual state with the desired state and reconciles the difference. There is
//! no event queue one could miss and no catching up after a crash -- a freshly
//! started agent is after one pass exactly as far as one that has been running
//! all along.
//!
//! Two properties make the loop fail-static (ADR-0019):
//!
//! 1. It reads desired **exclusively** from the local cache, never from the
//!    control plane.
//! 2. Every action runs through the autonomy boundary from ADR-0010. Without
//!    quorum, what is assigned is kept and restarted; nothing is placed and
//!    nothing mutated.
//!
//! The projection is **optional** in the process. If it is not reachable, the
//! reconcile runs nevertheless -- it is a read model (ADR-0004), not truth,
//! and its outage must not halt operation.

use std::time::Duration;

use tg_defs::{Probe, WorkloadExt as _, generated::WorkloadType};
use tg_model::{Action, DependencyGraph, Quorum, autonomy};

use crate::error::RuntimeError;
use crate::network::Wiring;
use crate::oci::{ContainerStatus, OciRuntime};
use crate::state::DesiredState;
use crate::{NodePaths, apply, orders};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instance {
    pub workload: String,
    pub instance: u32,
}

impl Instance {
    #[must_use]
    pub fn new(workload: impl Into<String>, instance: u32) -> Self {
        Self {
            workload: workload.into(),
            instance,
        }
    }
}

impl std::fmt::Display for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Instance 0 without a suffix, like the container name (see
        // `bundle::container_id`): the same spelling in the log and in the
        // runtime saves a translation in the head.
        if self.instance == 0 {
            write!(f, "{}", self.workload)
        } else {
            write!(f, "{}#{}", self.workload, self.instance)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub instance: Instance,
    pub class: &'static str,
    pub reason: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{} ({}): {}", self.instance, self.class, self.reason)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub untouched: Vec<Instance>,
    pub reconciled: Vec<Instance>,
    pub stale: Vec<Instance>,
    pub unready: Vec<Instance>,
    pub next_fence: Option<u64>,
    pub deferred: Vec<Instance>,
    pub failed: Vec<Failure>,
    pub own: std::collections::BTreeMap<String, String>,
    pub delegations: std::collections::BTreeMap<String, String>,
    pub waiting: Vec<Instance>,
    pub fenced: Vec<Instance>,
    pub held: Vec<Instance>,
    pub isolated: Vec<String>,
    pub reaped: Vec<String>,
    pub unclear: Vec<Unclear>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unclear {
    pub instance: Instance,
    pub reason: &'static str,
}

impl std::fmt::Display for Unclear {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (state unknown): {}", self.instance, self.reason)
    }
}

impl Report {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        // Isolated counts along: something is wrong with a definition, and a
        // node that does not understand half of its desired state and looks
        // calm while doing so would be worse than one that dies (ADR-0062,
        // determination 6).
        // **`unclear` does not count along** (ADR-0122, determination 4). A
        // pass that could not read an instance's state did nothing wrong -- it
        // did nothing, and exactly that was the decision. Whoever counted it
        // along would make an error out of the safe direction again and
        // thereby an alarm an operator switches off.
        self.failed.is_empty() && self.isolated.is_empty()
    }

    #[must_use]
    pub fn is_certain(&self) -> bool {
        self.unclear.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyMeans {
    NothingWanted,
    NothingHeard,
}

#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub quorum: Quorum,
    pub volume_keys: Option<&'a crate::volume::Derive>,
    pub network: Option<&'a dyn Wiring>,
    pub mesh: Option<&'a crate::network::Mesh>,
    pub workload_api: Option<&'a dyn crate::network::Sockets>,
    pub devices: Option<&'a dyn crate::network::Devices>,
    pub credentials: Option<&'a dyn crate::network::Credentials>,
    pub secrets: Option<&'a dyn crate::network::Secrets>,
    pub empty: &'a dyn Fn() -> EmptyMeans,
    pub no_seccomp: bool,
    pub userns: Option<crate::userns::Mapping>,
    pub now: &'a dyn Fn() -> u64,
    pub fence_margin: u64,
    pub wake: Option<&'a tokio::sync::Notify>,
    pub keep_snapshots: usize,
}

fn own_containers(
    assigned: &[(WorkloadType, Vec<u32>)],
) -> std::collections::BTreeMap<String, String> {
    assigned
        .iter()
        .flat_map(|(workload, instances)| {
            instances.iter().map(|instance| {
                (
                    crate::bundle::container_id(workload.name(), *instance),
                    workload.name().to_owned(),
                )
            })
        })
        .collect()
}

async fn reap_unless_incomplete(
    paths: &NodePaths,
    runtime: &OciRuntime,
    assigned: &[(WorkloadType, Vec<u32>)],
    context: &Context<'_>,
    report: &mut Report,
) {
    if report.isolated.is_empty() {
        reap(paths, runtime, assigned, context, report).await;
    } else {
        tracing::warn!(
            isolated = report.isolated.len(),
            "not cleared away -- the desired state is incomplete"
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct ActiveRole {
    instance: u32,
    held: Option<tg_model::lease::Held>,
}

impl ActiveRole {
    fn of(desired: &DesiredState, workload: &str) -> Self {
        Self {
            instance: desired.active_instance(workload),
            held: desired.lease(workload),
        }
    }
}

pub async fn once(
    paths: &NodePaths,
    runtime: &OciRuntime,
    context: &Context<'_>,
) -> Result<Report, RuntimeError> {
    let desired = DesiredState::open(paths.data_dir())?;
    // **An unreadable entry costs its workload, not the node** (ADR-0062).
    // Measured, the agent ended here before -- and a supervisor made a crash
    // loop out of that.
    let cached = desired.load_assigned()?;
    let unreadable = cached.unreadable.clone();
    let Derived {
        assigned,
        principals,
        isolated: blocked,
    } = expand(cached.workloads, context)?;

    let mut report = Report {
        waiting: Vec::new(),
        fenced: Vec::new(),
        // **What this node holds to be its own** -- derived once, from here
        // on for the identity too (ADR-0059, ADR-0019).
        own: own_containers(&assigned),
        delegations: principals.clone(),
        // Unreadable entries (ADR-0062) and blocked derivations (ADR-0084)
        // are the same sort of finding: neither started nor stopped, and
        // named.
        isolated: unreadable.into_iter().chain(blocked).collect(),
        ..Report::default()
    };

    // **The node view cannot fail** (ADR-0062, determination 1). What it
    // cannot classify -- duplicate names, a self-reference, ordering cycles --
    // it isolates; with the rest it builds on. Before, it gave `Err` here, the
    // error went out of `once`, `run_with` aborted, and the agent ended:
    // together with the workload API socket, the resolver and the session
    // (ADR-0019).
    let workloads: Vec<WorkloadType> = assigned
        .iter()
        .map(|(workload, _)| workload.clone())
        .collect();
    let (graph, isolated) = DependencyGraph::from_local(&workloads);
    for entry in &isolated {
        tracing::error!(
            workload = entry.workload(),
            finding = %entry,
            "the entry is isolated -- it is neither started nor stopped"
        );
    }
    report
        .isolated
        .extend(isolated.iter().map(|entry| entry.workload().to_owned()));
    report.isolated.sort();
    report.isolated.dedup();

    // **What is isolated is not touched** (determination 3): neither started
    // nor stopped. It falls out of `assigned` here so that no step starts it
    // -- and `reap` does not run at all so that none ends it.
    let assigned: Vec<(WorkloadType, Vec<u32>)> = assigned
        .into_iter()
        .filter(|(workload, _)| !report.isolated.iter().any(|name| name == workload.name()))
        .collect();

    // **The fence first** (ADR-0129, determination 1). It takes an
    // instance's write right, and its deadline was set by the leader -- not by
    // this pass. Everything that stood before it would be a waiting time it
    // does not have.
    fence_expired(&desired, &assigned, runtime, context, &mut report).await;

    reap_unless_incomplete(paths, runtime, &assigned, context, &mut report).await;

    // **No early end on an empty assignment**, and that is measured instead
    // of presumed: the three blocks below then do nothing --
    // `graph.start_order()` finds no entry in `assigned`, and
    // `probe_readiness` collects an empty list and thereby sets no metric
    // either. What a `return` would have saved here was nothing; what it cost
    // is the order at the end of this function -- the orders must go **behind**
    // the self-fence, and an emptied node (`assigned` empty) is exactly the
    // normal case of a deletion.

    if !graph.foreign().is_empty() {
        // `debug!` and not louder: it is the normal case of a cluster, and a
        // warning at every pass would train operators to read past
        // warnings.
        tracing::debug!(
            targets = ?graph.foreign(),
            "edges across the node boundary -- they do not order and tear nothing along"
        );
    }

    // The start order applies per **workload** (ADR-0009) -- instances of
    // the same workload have no order among themselves, they are repetitions
    // and not dependencies. Within a workload it therefore goes by number,
    // which serves only predictability.
    //
    // **And it is at the same time the condition's evaluation order**
    // (ADR-0061, determination 2): whoever comes after their target already
    // sees its outcome. Without `After` the target can come later; then the
    // condition bites one pass later, which converges level-triggered -- and
    // it is exactly the case the linter warns about.
    let mut inactive: Vec<(String, tg_model::Inactivity)> = Vec::new();

    for name in graph.start_order() {
        let Some((workload, instances)) = assigned.iter().find(|(w, _)| w.name() == name) else {
            continue;
        };

        let triggers: Vec<(&str, tg_model::Inactivity)> = inactive
            .iter()
            .map(|(target, state)| (target.as_str(), *state))
            .collect();

        if graph.cascade_stop(&triggers).contains(name) {
            hold(runtime, workload, instances, context, &mut report).await;
            // The one torn along counts as **stopped**, not as failed
            // (ADR-0061, determination 5). Otherwise a single crash would run
            // arbitrarily far over `Requires` chains; this way only a
            // `bindsTo` chain carries further.
            inactive.push((name.to_owned(), tg_model::Inactivity::Stopped));
            continue;
        }

        let failed_before = report.failed.len();
        let active_before = report.untouched.len() + report.reconciled.len();

        // **The active role** (ADR-0064, ADR-0111). The rule lies in
        // `tg_model::lease` and is only applied here; the measurement is
        // against the **local** clock and the deadline from the last slice.
        let role = ActiveRole::of(&desired, name);

        let principal = principals.get(name).map(String::as_str);

        // **The same derivation, no second place** (ADR-0059): whoever gets
        // a sidecar stands as a principal in the same map the sidecars arise
        // from.
        let has_sidecar = principals.values().any(|spoken_for| spoken_for == name);

        for instance in instances {
            if !active(runtime, workload, *instance, role, context, &mut report).await {
                continue;
            }

            step(
                paths,
                runtime,
                &apply::Target {
                    workload,
                    instance: *instance,
                    principal,
                    // **The principal's generation** (ADR-0085). A derived
                    // sidecar stands in no log (ADR-0059), so the slice
                    // carries no generation for it, and `generation` would
                    // give `0` here forever -- a decree
                    // `tgctl cluster restart api` would reach `api` and leave
                    // `api-proxy` standing. For a change of class that would
                    // mean: the workload runs from now on as a single writer,
                    // but its sidecar does not rein it in (ADR-0066), because
                    // it lacks `--single-writer`.
                    generation: desired.generation(principal.unwrap_or(name), *instance),
                    has_sidecar,
                },
                context,
                &mut report,
            )
            .await;
        }

        if let Some(state) = trigger_for(
            report.untouched.len() + report.reconciled.len() - active_before,
            report.failed.len() - failed_before,
        ) {
            inactive.push((name.to_owned(), state));
        }
    }

    probe_readiness(&assigned, context, &mut report);
    report_consumption(&assigned);

    // **What the slice left behind** (ADR-0110): deletions and snapshots.
    // Until then they stood in the session arm that takes slices -- and
    // blocking work in it halted the report the active-role lease hangs on
    // (ADR-0068, ADR-0064).
    //
    // **Last, and that is the answer to that ADR's open point.** It asks for
    // an ordering condition between [`crate::volume::TOOL_TIMEOUT`] and the
    // fence distance from ADR-0076 -- measured, none can be set up:
    //
    // - the number of orders is unbounded (as many volumes as an operator
    //   declares), so the bound would be `N x TOOL_TIMEOUT`;
    // - and the copy of an image is `std::fs::copy`, that is, a syscall
    //   without any deadline -- on a network file system that has fallen away
    //   it hangs **unboundedly**.
    //
    // What carries instead of a number is the **order**: before it, every
    // waiting time would shift *this* pass's fence, and the holder would fence
    // too late while the leader has long passed the lease on -- two writers,
    // exactly what ADR-0064 determination 7 is to prevent. Behind it, it hits
    // only the **next** pass, and that one has nothing left to fence.
    //
    // It is the same ordering condition `probe_readiness` above already
    // carries, only one step further: what blocks before the fence is no
    // latency but a second writer.
    //
    // **After the clearing away** it stays likewise: a mounted volume cannot
    // be deleted, and the tombstone comes after the workload has been
    // withdrawn.
    orders::execute(paths, context.keep_snapshots, &orders::read(paths));

    // **And last the content store** (ADR-0126, determination 2). After the
    // clearing away (ADR-0058) and after the release of the bundles
    // (ADR-0119): what this pass released the same pass may collect.
    collect_content(paths, context, &assigned, &report);

    Ok(report)
}

fn collect_content(
    paths: &NodePaths,
    context: &Context<'_>,
    assigned: &[(WorkloadType, Vec<u32>)],
    report: &Report,
) {
    use tg_defs::{ImageExt as _, VolumeExt as _};

    if assigned.is_empty() && (context.empty)() == EmptyMeans::NothingHeard {
        return;
    }
    if !report.isolated.is_empty() {
        return;
    }

    let mut reachable: Vec<String> = assigned
        .iter()
        .flat_map(|(workload, _)| {
            std::iter::once(workload.image().reference().to_owned()).chain(
                // **The shared volumes' sources count along** (ADR-0027,
                // 10c): they lie in the same store, and their layers are roots
                // like an image's.
                workload
                    .volumes()
                    .iter()
                    .filter_map(|volume| volume.source().map(ToOwned::to_owned)),
            )
        })
        .collect();
    reachable.sort();
    reachable.dedup();

    // The third guard: a bundle the desired state does not name.
    let wanted: std::collections::BTreeSet<&str> = assigned
        .iter()
        .map(|(workload, _)| workload.name())
        .collect();
    if let Ok(entries) = std::fs::read_dir(paths.bundles_dir()) {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            if entry.path().is_dir() && !wanted.contains(name.as_str()) {
                tracing::debug!(
                    bundle = %name,
                    "the content GC is deferred -- a bundle is not yet released"
                );
                return;
            }
        }
    }

    let store = match crate::content::ContentStore::open(paths.content_dir()) {
        Ok(store) => store,
        Err(error) => {
            tracing::warn!(%error, "the content GC was skipped -- the store cannot be opened");
            return;
        }
    };
    let freed = crate::content::collect(&store, &reachable);
    if freed == crate::content::Reclaimed::default() {
        return;
    }

    tracing::info!(
        layers = freed.layers,
        records = freed.records,
        bytes = freed.bytes,
        "the content store was released (ADR-0126)"
    );
    metrics::counter!(tg_telemetry::names::CONTENT_RECLAIMED_BYTES).increment(freed.bytes);
    metrics::counter!(tg_telemetry::names::CONTENT_RECLAIMED_LAYERS).increment(freed.layers);
}

fn report_consumption(assigned: &[(WorkloadType, Vec<u32>)]) {
    for (workload, instances) in assigned {
        for instance in instances {
            let id = crate::bundle::container_id(workload.name(), *instance);
            let dir = std::path::Path::new("/sys/fs/cgroup")
                .join(crate::bundle::cgroups_path(&id).trim_start_matches('/'));
            if !dir.is_dir() {
                continue;
            }

            let labels = (workload.name().to_owned(), instance.to_string());
            if let Some(bytes) = read_number(&dir.join("memory.current")) {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "a gauge is an f64; with memory sizes the error \
                              lies beyond petabytes and thereby beyond what a \
                              cgroup reports"
                )]
                metrics::gauge!(
                    tg_telemetry::names::CONTAINER_MEMORY,
                    "workload" => labels.0.clone(),
                    "replica" => labels.1.clone(),
                )
                .set(bytes as f64);
            }
            // **And the peak** (ADR-0123). The number above is a momentary
            // value; measured, a cgroup that went to 200 MiB stands at 0.5
            // half a second later -- and from the number an operator sets the
            // limit from ADR-0086.
            //
            // If the file is missing (Linux < 5.19), nothing is set: the same
            // path as with a controller that is not enabled, and that is why
            // it costs **no** operational prerequisite.
            if let Some(bytes) = read_number(&dir.join("memory.peak")) {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "a gauge is an f64; with memory sizes the error \
                              lies beyond petabytes and thereby beyond what a \
                              cgroup reports"
                )]
                metrics::gauge!(
                    tg_telemetry::names::CONTAINER_MEMORY_PEAK,
                    "workload" => labels.0.clone(),
                    "replica" => labels.1.clone(),
                )
                .set(bytes as f64);
            }
            // **The limit beside it** (ADR-0144). It comes from the cgroup
            // and not from the declaration: this one is what the **kernel
            // enforces**, and between the two lie ADR-0063 and ADR-0070.
            // Without it the two numbers above are without a yardstick.
            // **`max` is no number and does not become one** (determination
            // 3): `read_number` gives `None` for it, and then nothing is set.
            // A zero would be the wrong statement, and a `+Inf` would silently
            // become "infinitely much room" in a division.
            if let Some(bytes) = read_number(&dir.join("memory.max")) {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "the same situation as with the two numbers above"
                )]
                metrics::gauge!(
                    tg_telemetry::names::CONTAINER_MEMORY_LIMIT,
                    "workload" => labels.0.clone(),
                    "replica" => labels.1.clone(),
                )
                .set(bytes as f64);
            }
            if let Some(cores) = cpu_limit(&dir.join("cpu.max")) {
                metrics::gauge!(
                    tg_telemetry::names::CONTAINER_CPU_LIMIT,
                    "workload" => labels.0.clone(),
                    "replica" => labels.1.clone(),
                )
                .set(cores);
            }
            if let Some(usec) = cpu_usec(&dir.join("cpu.stat")) {
                // **Set absolutely, not incremented**: the cgroup keeps the
                // sum, we do not. An `increment` would demand a remembered
                // previous value -- and that would be a second source for a
                // number that stands in the kernel.
                metrics::counter!(
                    tg_telemetry::names::CONTAINER_CPU,
                    "workload" => labels.0,
                    "replica" => labels.1,
                )
                .absolute(usec / 1_000_000);
            }
        }
    }
}

fn cpu_limit(path: &std::path::Path) -> Option<f64> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut parts = text.split_whitespace();
    let quota: u64 = parts.next()?.parse().ok()?;
    let period: u64 = parts.next()?.parse().ok()?;
    if period == 0 {
        return None;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "the quota and the period are microseconds of a CFS period; \
                  the error lies beyond what the kernel carries"
    )]
    Some(quota as f64 / period as f64)
}

fn read_number(path: &std::path::Path) -> Option<u64> {
    let text = std::fs::read_to_string(path)
        .inspect_err(|error| {
            // There and unreadable is the unexpected case -- the caller has
            // already caught the absence.
            tracing::debug!(path = %path.display(), %error, "the cgroup is not readable");
        })
        .ok()?;

    text.trim().parse().ok()
}

fn cpu_usec(path: &std::path::Path) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;

    text.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|value| value.trim().parse().ok())
}

fn probe_readiness(
    assigned: &[(WorkloadType, Vec<u32>)],
    context: &Context<'_>,
    report: &mut Report,
) {
    let Some(wiring) = context.network else {
        // Without a node network there is no namespace in which a probe
        // could run. Then every instance counts as ready -- otherwise a
        // missing node network would take from every instance the resolution
        // it does not have anyway.
        return;
    };

    // **First collect, then ask them all at once** -- across workloads and
    // not per workload. The outer loop was once sequential too, and the worst
    // case was thereby `workloads x TIMEOUT`: with five workloads with a mute
    // probe a floor of 1 s torn, with the same consequence as before (see the
    // ordering condition at [`tg_net::probe::TIMEOUT`]).
    let asking: Vec<(Instance, String, Probe<'_>)> = assigned
        .iter()
        .filter_map(|(workload, instances)| {
            // No declared probe means ready (determination 5). And it means
            // **no metric**: an invented `1` for every workload would be
            // noise, and an operator would learn to read past it.
            let probe = workload.readiness()?;
            Some((workload, instances, probe))
        })
        .flat_map(|(workload, instances, probe)| {
            instances.iter().map(move |instance| {
                (
                    Instance::new(workload.name(), *instance),
                    crate::bundle::container_id(workload.name(), *instance),
                    probe,
                )
            })
        })
        // Only what **runs** is probed. For everything else there is nothing
        // to ask, and a failure would only say what the state already says.
        .filter(|(which, _, _)| {
            report.untouched.contains(which) || report.reconciled.contains(which)
        })
        .collect();

    // **Concurrent, and that is an ordering condition and no optimization.**
    //
    // Sequentially a pass's worst case is `instances x TIMEOUT` -- measured
    // **2.0 s for eight** hanging probes. A handful of mute workloads would
    // thereby shift the next pass, and the fence's detection latency would no
    // longer be the floor from ADR-0076 but a number that grows with the
    // instance count: the holder fences too late while the leader passes the
    // lease on -- **two writers**, exactly what ADR-0064 is to prevent.
    //
    // Concurrently the worst case is `TIMEOUT`, independent of the number of
    // instances. The price is one thread per probe for at most 250 ms;
    // `tg_net::probe` lays one out per probe anyway (`setns` applies to a
    // **thread**), all that is new is that they run at the same time.
    let answers: Vec<(Instance, u16, Result<(), String>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = asking
            .iter()
            .map(|(which, container, probe)| {
                scope.spawn(move || (which.clone(), probe.port, wiring.probe(container, *probe)))
            })
            .collect();

        handles
            .into_iter()
            .filter_map(|handle| {
                // A panic in a probe does **not** take the pass with it: it
                // is an observation, and an agent that ends on it loses the
                // socket, the resolver and the session (ADR-0062).
                if let Ok(answer) = handle.join() {
                    return Some(answer);
                }
                tracing::error!("a readiness probe panicked");
                None
            })
            .collect()
    });

    // **Set in both cases**, not only in the bad one: a time series that
    // appears only on a finding is not distinguishable from a missing one. And
    // **per workload**, not per instance: the cardinality rule permits the
    // workload name, and which instance it was stands in the log.
    let mut ready: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut probed: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    // Sorted, because the answers arise concurrently: `unready` travels in
    // the report (ADR-0080, determination 8), and an order that depends on the
    // runtime would make two equal reports unequal.
    let mut unready: Vec<Instance> = Vec::new();

    for (which, port, answer) in answers {
        *probed.entry(which.workload.clone()).or_default() += 1;
        match answer {
            Ok(()) => *ready.entry(which.workload.clone()).or_default() += 1,
            Err(reason) => {
                // The **reason** belongs in the log and not on the wire:
                // "refused" means "does not bind", "timeout" means "hangs",
                // and an operator looks for those in different places. The
                // metric does not carry it -- it has a cardinality rule
                // (11b).
                tracing::warn!(
                    instance = %which,
                    port,
                    reason = %reason,
                    "the readiness probe gave no answer -- the instance is not resolved"
                );
                unready.push(which);
            }
        }
    }

    unready.sort();
    report.unready.extend(unready);

    for (workload, asked) in probed {
        // **Two raw numbers, the alarm system does the division** -- the
        // same choice as with the domain metrics (ADR-0047) and with the
        // descriptors. Without the denominator a rule catches only the total
        // outage; what one wants to see beforehand is the **one** of two
        // replicas that no longer serves.
        metrics::gauge!(
            tg_telemetry::names::WORKLOAD_PROBED,
            "workload" => workload.clone()
        )
        // A Prometheus metric **is** an `f64`; it would become imprecise
        // beyond 2^53 instances of a workload. The same reason as with the
        // counter beside it -- and it stands here instead of the neighbouring
        // place carrying it for both.
        .set({
            #[allow(clippy::cast_precision_loss)]
            let value = asked as f64;
            value
        });
        metrics::gauge!(
            tg_telemetry::names::WORKLOAD_READY,
            "workload" => workload.clone()
        )
        // A Prometheus metric **is** an `f64`; it would become imprecise
        // beyond 2^53 instances of a workload. The reason stands at the
        // `allow` and not merely the `allow`.
        .set({
            #[allow(clippy::cast_precision_loss)]
            let value = ready.get(&workload).copied().unwrap_or(0) as f64;
            value
        });
    }
}

fn trigger_for(active: usize, failed: usize) -> Option<tg_model::Inactivity> {
    (failed > 0 && active == 0).then_some(tg_model::Inactivity::Failed)
}

async fn hold(
    runtime: &OciRuntime,
    workload: &WorkloadType,
    instances: &[u32],
    context: &Context<'_>,
    report: &mut Report,
) {
    // The autonomy boundary, at the same place as with starting and with
    // clearing away. It cannot defer today (ADR-0061, determination 7), and
    // that is exactly why it stands here: a later reclassification then takes
    // effect instead of being forgotten.
    if let autonomy::Verdict::Deferred { reason } =
        autonomy::check(Action::HoldOnRequirement, context.quorum)
    {
        tracing::info!(workload = %workload.name(), reason, "the hold was deferred");
        return;
    }

    for instance in instances {
        let which = Instance::new(workload.name(), *instance);
        let id = crate::bundle::container_id(&which.workload, *instance);

        if matches!(runtime.status(&id).await, Ok(status) if status.is_running()) {
            match stop(runtime, &id).await {
                Ok(()) => tracing::info!(
                    instance = %which,
                    "held back -- the requirement target has failed"
                ),
                Err(err) => {
                    // It is not kept quiet, but it stays a hold: the next
                    // pass sees the same again (ADR-0010).
                    tracing::error!(instance = %which, error = %err, "not held back");
                }
            }
        }

        report.held.push(which);
    }
}

async fn active(
    runtime: &OciRuntime,
    workload: &WorkloadType,
    instance: u32,
    active_role: ActiveRole,
    context: &Context<'_>,
    report: &mut Report,
) -> bool {
    let held = active_role.held;
    let role = tg_model::lease::role_of(
        workload.class(),
        held,
        instance,
        active_role.instance,
        (context.now)(),
        context.fence_margin,
    );

    // **Make visible what otherwise merely reads "stopped"** (ADR-0064,
    // ADR-0057). A single writer without an active role stands still, and in
    // the projection that is not distinguishable from any other standstill. It
    // is set only for those at issue: a replicated workload has no active
    // role, and a line with a permanent `1` would water the alarm rule
    // down.
    if workload.class() == tg_defs::WorkloadClass::SingleWriter && instance == active_role.instance
    {
        metrics::gauge!(
            tg_telemetry::names::ACTIVE_ROLE,
            "workload" => workload.name().to_owned()
        )
        .set(f64::from(u8::from(matches!(
            role,
            tg_model::lease::Role::Run
        ))));

        // **And how far the clocks lie apart** (ADR-0078, determination 4).
        // The lease applies against the wall clock, and the security statement
        // rests on the skew being smaller than the margin -- a condition that
        // stood nowhere until ADR-0078 and that nobody could see.
        //
        // **Always set once there is a lease**, at zero too: a metric that
        // appears only in the error case is not distinguishable from a missing
        // one. Without a lease there is nothing to compare.
        if let Some(lease) = held {
            let skew = tg_model::lease::skew_at((context.now)(), lease.expires_at);
            #[expect(
                clippy::cast_precision_loss,
                reason = "milliseconds into seconds; a Prometheus metric *is* \
                          an f64, and it would become imprecise only beyond \
                          2^53 ms -- around 285000 years of skew"
            )]
            metrics::gauge!(
                tg_telemetry::names::LEASE_CLOCK_SKEW,
                "workload" => workload.name().to_owned()
            )
            .set(skew as f64 / 1000.0);
        }
    }

    match role {
        tg_model::lease::Role::Run => {
            // **When this instance would fence** if nobody renews. The
            // reconcile afterwards sleeps only until then (ADR-0076,
            // determination 1); it is computed here because both numbers are
            // at hand here.
            if let Some(lease) = held {
                let threshold = lease.expires_at.saturating_sub(context.fence_margin);
                report.next_fence = Some(match report.next_fence {
                    Some(earlier) => earlier.min(threshold),
                    None => threshold,
                });
            }
            true
        }
        tg_model::lease::Role::Wait => {
            // **Do not start up**: the activation needs the quorum
            // (ADR-0010). Reported, not kept quiet -- otherwise an operator
            // sees a workload that simply does not come.
            tracing::info!(
                workload = %workload.name(),
                instance,
                "waiting for the active-role lease (ADR-0010)"
            );
            report
                .waiting
                .push(Instance::new(workload.name(), instance));
            false
        }
        tg_model::lease::Role::Fence => {
            fence(runtime, workload, instance, report).await;
            false
        }
    }
}

#[must_use]
pub fn nap_for(interval: Duration, next_fence: Option<u64>, now: u64) -> Duration {
    let Some(threshold) = next_fence else {
        return interval;
    };

    let floor = Duration::from_millis(tg_model::lease::FENCE_WAKE_FLOOR_MILLIS).min(interval);
    let remaining = Duration::from_millis(threshold.saturating_sub(now));
    remaining.clamp(floor, interval)
}

async fn fence(runtime: &OciRuntime, workload: &WorkloadType, instance: u32, report: &mut Report) {
    let which = Instance::new(workload.name(), instance);
    let id = crate::bundle::container_id(&which.workload, instance);

    if matches!(runtime.status(&id).await, Ok(status) if status.is_running()) {
        match stop_within(runtime, &id, FENCE_GRACE).await {
            Ok(()) => tracing::warn!(
                instance = %which,
                "self-fenced -- the active-role lease has expired (ADR-0010)"
            ),
            Err(err) => {
                tracing::error!(instance = %which, error = %err, "not fenced");
            }
        }
    }

    // **Once in the report** (ADR-0129): since this decision fencing happens
    // before the clearing away, and `active` checks the role again afterwards
    // -- an instance that falls due in between is to be stopped nevertheless.
    // It would not be reported twice in the process.
    if !report.fenced.contains(&which) {
        report.fenced.push(which);
    }
}

async fn fence_expired(
    desired: &DesiredState,
    assigned: &[(WorkloadType, Vec<u32>)],
    runtime: &OciRuntime,
    context: &Context<'_>,
    report: &mut Report,
) {
    for (workload, instances) in assigned {
        let role = ActiveRole::of(desired, workload.name());
        for instance in instances {
            if tg_model::lease::role_of(
                workload.class(),
                role.held,
                *instance,
                role.instance,
                (context.now)(),
                context.fence_margin,
            ) == tg_model::lease::Role::Fence
            {
                fence(runtime, workload, *instance, report).await;
            }
        }
    }
}

pub(crate) struct Derived {
    assigned: Vec<(WorkloadType, Vec<u32>)>,
    principals: std::collections::BTreeMap<String, String>,
    isolated: Vec<String>,
}

fn expand(
    assigned: Vec<(WorkloadType, Vec<u32>)>,
    context: &Context<'_>,
) -> Result<Derived, RuntimeError> {
    let Some(mesh) = context.mesh else {
        return Ok(Derived {
            assigned,
            principals: std::collections::BTreeMap::new(),
            isolated: Vec::new(),
        });
    };

    let declared: Vec<WorkloadType> = assigned
        .iter()
        .map(|(workload, _)| workload.clone())
        .collect();

    // **A name that blocks a derivation costs its workload -- not the pass**
    // (ADR-0084). Before, a `?` stood here, and measured, **none** of this
    // node's workloads was thereby reconciled: nothing started, nothing
    // restarted, nothing cleared away, no single writer fenced (ADR-0064) --
    // and that anew every second.
    //
    // What is isolated is the **mesh member** and not the declared workload:
    // that one's definition is complete in itself, while this one demands a
    // derivation that cannot take place.
    //
    // The loop is the same construction as in `DependencyGraph::from_local`:
    // every round removes at least one entry, so it terminates -- and a second
    // blocked member does not wait for the next pass.
    let mut isolated: Vec<String> = Vec::new();
    let mut declared = declared;
    while let Err(err) = tg_model::mesh::validate_names(&declared) {
        let Some(blocked) = err.workload().map(ToOwned::to_owned) else {
            return Err(RuntimeError::Unmappable {
                workload: "<sidecar>".to_owned(),
                reason: err.to_string(),
            });
        };
        tracing::error!(%err, workload = %blocked, "the sidecar derivation isolates its mesh member");
        declared.retain(|workload| workload.name() != blocked);
        isolated.push(blocked);
    }

    // **The same function as in the identity path.** Two derivations would
    // be two opportunities to disagree -- and then a container would get an
    // SVID meant for another (ADR-0036).
    let expanded =
        tg_model::mesh::expand(&declared, &mesh.spec).map_err(|err| RuntimeError::Unmappable {
            workload: "<sidecar>".to_owned(),
            reason: err.to_string(),
        })?;
    let principals = tg_model::mesh::delegations(&expanded, &mesh.spec);

    let mut assigned = assigned;
    for workload in expanded {
        let name = workload.name().to_owned();
        if assigned.iter().any(|(known, _)| known.name() == name) {
            continue;
        }
        let Some(principal) = principals.get(&name) else {
            // A document `expand` produced but `delegations` does not
            // recognize as a sidecar does not exist -- both check the same
            // four conditions. Starting it would be wrong nevertheless:
            // without a principal there would be no namespace it belonged
            // in.
            continue;
        };
        let instances = assigned
            .iter()
            .find(|(known, _)| known.name() == principal)
            .map(|(_, instances)| instances.clone())
            .unwrap_or_default();
        assigned.push((workload, instances));
    }

    Ok(Derived {
        assigned,
        principals,
        isolated,
    })
}

pub const GRACE: Duration = Duration::from_secs(10);

pub const FENCE_GRACE: Duration = Duration::from_millis(tg_model::lease::FENCE_GRACE_MILLIS);

// **The derivation is assured, not merely written.** Without this line a
// number of its own gets through here and nothing turns red: the holder's
// safety margin still reckons with the one from `tg-model`, and the holder
// would fence too late while the leader has passed the lease on (ADR-0064,
// determination 7). Measured -- a `from_secs(5)` at this place left all 124
// witnesses of the crate green.
const _: () = assert!(
    FENCE_GRACE.as_millis() == tg_model::lease::FENCE_GRACE_MILLIS as u128,
    "the fence's grace period belongs to `tg_model::lease` -- the holder's \
     safety margin reckons with it (ADR-0064, determination 7)"
);

const GRACE_POLL: Duration = Duration::from_millis(200);

async fn reap(
    paths: &NodePaths,
    runtime: &OciRuntime,
    assigned: &[(WorkloadType, Vec<u32>)],
    context: &Context<'_>,
    report: &mut Report,
) {
    // **Determination 3:** an empty desired state clears away only if the
    // caller declares it occupied. Otherwise a lost data directory would mean
    // "nothing wanted" -- and would cost every running container
    // (ADR-0019).
    if assigned.is_empty() && (context.empty)() == EmptyMeans::NothingHeard {
        return;
    }

    // The autonomy boundary, at the same place as with starting. It cannot
    // defer today -- `StopUnwanted` is autonomous (ADR-0058, determination 4)
    // -- and that is exactly why it stands here: a later reclassification then
    // takes effect instead of being forgotten.
    if let autonomy::Verdict::Deferred { reason } =
        autonomy::check(Action::StopUnwanted, context.quorum)
    {
        tracing::info!(reason, "the clearing away was deferred");
        return;
    }

    let wanted: std::collections::BTreeSet<String> = assigned
        .iter()
        .flat_map(|(workload, instances)| {
            instances
                .iter()
                .map(|instance| crate::bundle::container_id(workload.name(), *instance))
        })
        .collect();

    let existing = match runtime.list() {
        Ok(ids) => ids,
        Err(err) => {
            // Fail-soft: without the actual side nothing is guessed. The
            // next pass sees the same again -- level-triggered (ADR-0010).
            tracing::warn!(error = %err, "the runtime's actual state is not readable, nothing cleared away");
            return;
        }
    };

    // **And the network's actual side**, which is a different one from the
    // container's (see `Wiring::leased`). A network that never became a
    // container stands in no state directory -- and would otherwise stay lying
    // forever together with its persisted address.
    if let Some(wiring) = context.network {
        for id in wiring.leased() {
            if wanted.contains(&id) || existing.contains(&id) {
                continue;
            }
            wiring.release(&id);
            tracing::info!(container = %id, "the network was cleared away -- it never became a container");
            report.reaped.push(id);
        }
    }

    // **And the sockets' actual side** (ADR-0081, determination 4). The same
    // situation as with the network: the socket arises *before* the bundle
    // because it is mounted -- if the start fails afterwards, the runtime
    // knows no container. A socket nobody takes back is a way to an identity
    // that no longer exists.
    if let Some(sockets) = context.workload_api {
        for id in sockets.held() {
            if wanted.contains(&id) || existing.contains(&id) {
                continue;
            }
            sockets.release(&id);
            tracing::info!(container = %id, "the socket was cleared away -- it never became a container");
            report.reaped.push(id);
        }
    }

    // **And the secrets' actual side** (ADR-0098). The same situation, and
    // here it weighs more: what stays lying is **plaintext** in a tmpfs.
    if let Some(secrets) = context.secrets {
        for id in secrets.held() {
            if wanted.contains(&id) || existing.contains(&id) {
                continue;
            }
            secrets.release(&id);
            tracing::info!(container = %id, "the secrets were cleared away -- it never became a container");
            report.reaped.push(id);
        }
    }

    // **And the devices' actual side** (ADR-0143). The same situation: the
    // assignment arises **before** the bundle, and if the start fails
    // afterwards, it holds a device nobody ever gets again (ADR-0119).
    if let Some(devices) = context.devices {
        for id in devices.held() {
            if wanted.contains(&id) || existing.contains(&id) {
                continue;
            }
            devices.release(&id);
            tracing::info!(container = %id, "the devices were released -- it never became a container");
            report.reaped.push(id);
        }
    }

    // **Concurrent** (ADR-0129, determination 2). Sequentially every hanging
    // container cost a full grace period -- measured 10.16 s for **one**, and
    // N for N. They are independent of one another; the order of the clearing
    // away never carried a statement. `N x GRACE` thereby becomes `GRACE`.
    let (unwanted, mut remaining): (Vec<String>, Vec<String>) = existing
        .into_iter()
        // The prefix is the belt to the braces: the state directory is ours,
        // and nevertheless only what is also named like ours is ended
        // (ADR-0058, determination 2).
        .partition(|id| !wanted.contains(id) && id.starts_with(crate::bundle::PREFIX));

    let stopped = futures_util::future::join_all(
        unwanted
            .iter()
            .map(|id| async move { (id.clone(), stop(runtime, id).await) }),
    )
    .await;

    for (id, outcome) in stopped {
        match outcome {
            Ok(()) => {
                if let Some(wiring) = context.network {
                    wiring.release(&id);
                }
                // And its socket (ADR-0081): a way to an identity this node
                // may no longer mint.
                if let Some(sockets) = context.workload_api {
                    sockets.release(&id);
                }
                // And its secrets (ADR-0098): a tmpfs with plaintext nobody
                // reads any more.
                if let Some(secrets) = context.secrets {
                    secrets.release(&id);
                }
                // And its devices (ADR-0143): one that stays assigned to a
                // finished instance nobody ever gets again.
                if let Some(devices) = context.devices {
                    devices.release(&id);
                }
                tracing::info!(container = %id, "cleared away -- no longer wanted");
                report.reaped.push(id);
            }
            Err(err) => {
                // The container stays standing in the actual state and is
                // tried again at the next pass. It is not kept quiet: a
                // workload that does not end is a finding.
                tracing::error!(container = %id, error = %err, "not cleared away");
                remaining.push(id);
            }
        }
    }

    release_bundles(paths, assigned, &remaining);
}

fn release_bundles(paths: &NodePaths, assigned: &[(WorkloadType, Vec<u32>)], remaining: &[String]) {
    let wanted: std::collections::BTreeSet<&str> = assigned
        .iter()
        .map(|(workload, _)| workload.name())
        .collect();

    let root = paths.bundles_dir();
    let Ok(entries) = std::fs::read_dir(&root) else {
        // No bundle directory means: there has been no container here
        // yet.
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if wanted.contains(name.as_str()) || !entry.path().is_dir() {
            continue;
        }
        if remaining.iter().any(|id| belongs_to(id, &name)) {
            continue;
        }

        match crate::bundle::release(&root, &name) {
            // **Not in `report.reaped`**: container identifiers stand there,
            // and a bundle is named after the workload. Throwing both into one
            // list would mean keeping two things under one name -- and the
            // reader would have to guess which one they have before them. The
            // bundle belongs to the container reported one line above.
            Ok(()) => tracing::info!(workload = %name, "the bundle was released -- not wanted"),
            // Fail-soft (ADR-0062): that costs its bundle and not the pass.
            // The next one sees the same situation again (ADR-0010).
            Err(err) => {
                tracing::error!(workload = %name, error = %err, "the bundle was not released");
            }
        }
    }
}

fn belongs_to(id: &str, workload: &str) -> bool {
    let Some(rest) = id
        .strip_prefix(crate::bundle::PREFIX)
        .and_then(|rest| rest.strip_prefix(workload))
    else {
        return false;
    };

    rest.is_empty()
        || rest
            .strip_prefix('-')
            .is_some_and(|number| number.parse::<u32>().is_ok())
}

pub(crate) async fn stop(runtime: &OciRuntime, id: &str) -> Result<(), RuntimeError> {
    stop_within(runtime, id, GRACE).await
}

async fn stop_within(runtime: &OciRuntime, id: &str, grace: Duration) -> Result<(), RuntimeError> {
    if matches!(runtime.status(id).await, Ok(status) if status.is_running()) {
        // A `kill` on a container that is itself just ending is no error of
        // this pass.
        let _ = runtime.kill(id, "SIGTERM").await;

        let deadline = std::time::Instant::now() + grace;
        while std::time::Instant::now() < deadline {
            if !matches!(runtime.status(id).await, Ok(status) if status.is_running()) {
                break;
            }
            tokio::time::sleep(GRACE_POLL).await;
        }
    }

    runtime.delete(id, true).await
}

async fn step(
    paths: &NodePaths,
    runtime: &OciRuntime,
    target: &apply::Target<'_>,
    context: &Context<'_>,
    report: &mut Report,
) {
    let workload = target.workload;
    let instance = target.instance;
    let which = Instance::new(workload.name(), instance);
    let id = crate::bundle::container_id(&which.workload, instance);

    let status = match runtime.status(&id).await {
        Ok(status) => status,
        Err(_) => ContainerStatus::Unknown("the state is not queryable"),
    };

    // **Is a restart decreed?** (ADR-0071). The comparison is the generation
    // the bundle was built with; without a decree both are zero, and then it
    // stays at keeping.
    let ordered =
        target.generation > crate::bundle::built_generation(&paths.bundles_dir(), workload);

    // Running: keep. This action is always autonomous (ADR-0019) -- a
    // running container is never touched because of quorum loss.
    if status.is_running() && !ordered {
        // **The declaration may have changed, and then it is said**
        // (ADR-0070). Nothing is touched nevertheless: a number in the XML
        // must not be a restart trigger (ADR-0063), and the list of autonomous
        // actions in ADR-0010 stays as it is.
        //
        // The metric is set in **both** cases, not only in the bad one: a
        // time series that appears only on a finding is not distinguishable
        // from a missing one.
        let stale = crate::bundle::freshness(&paths.bundles_dir(), workload)
            == crate::bundle::Freshness::Stale;
        metrics::gauge!(
            tg_telemetry::names::WORKLOAD_STALE,
            "workload" => workload.name().to_owned()
        )
        .set(f64::from(u8::from(stale)));

        if stale {
            report.stale.push(which.clone());
        }

        // **The rule set follows the allowlist** (ADR-0094, determination
        // 3), and that can change while the sidecar runs: a QUIC permission
        // that comes along needs its redirection without anybody restarting.
        // Before, it was laid **only at the start** -- the permission stood
        // there, the listener was open, and the datagrams died at the
        // discarding rule (ADR-0074): fail-closed and visible, but exactly the
        // riddle determination 4 wanted to avoid one level deeper.
        //
        // **Here and not in `reconcile_one`.** Its `Running` arm is never
        // reached for this case -- measured: this function returns before it,
        // and `reconcile_one` sees only what is to be done.
        //
        // It does not weigh, because `enforce` **asks** and sets only on a
        // deviation; only a sidecar has a principal, and only for it may a
        // redirection lie (ADR-0060, determination 3).
        // **Only one of the two reconciles the namespace.** The baseline and
        // the full rule set are mutually a deviation (measured), so a workload
        // and its sidecar overwrote each other at every pass, and the
        // redirection flickered.
        //
        // The **sidecar wins**: a redirection may lie only when somebody
        // listens (ADR-0060, determination 3) -- and its presence *is* that
        // condition. As long as it does not run, the workload lays its
        // baseline itself; that is the window ADR-0093 closed, now against
        // drift too.
        if let Some(wiring) = context.network {
            match target.principal {
                Some(principal) => {
                    wiring.enforce(&crate::bundle::container_id(principal, instance), principal);
                }
                None if !target.has_sidecar => {
                    wiring.ensure_baseline(&crate::bundle::container_id(workload.name(), instance));
                }
                None => {}
            }
        }

        report.untouched.push(which);
        return;
    }

    // Everything else means: something must be done. Which action that is
    // decides whether it may run without quorum.
    //
    // **A prediction stood here, and it did not come true:** "Only the
    // scheduler assignment from phase 6 makes the difference from `PlaceNew`
    // visible -- and then the autonomy boundary bites sharply here." Phase 6
    // has long been finished, and it came out the other way round: the agent
    // **never** places. The scheduler does it in the leader (ADR-0011), the
    // leader grants leases (ADR-0064), cluster-wide mutations go through the
    // log -- every quorum-bound decision from ADR-0010 lies where quorum
    // exists. An agent executes.
    //
    // Measured, **every** action this tree gives to `autonomy::check` is
    // thereby autonomous, and `Verdict::Deferred` unreachable in operation.
    // The pass stays here nevertheless: it is the place at which a later
    // quorum-bound action would bite, and
    // `tg-model/tests/autonomy_callers.rs` then demands the attention it needs
    // for that.
    // **A decreed restart is an action of its own** (ADR-0071,
    // determination 6): autonomous like `StopUnwanted`, because the decision
    // had quorum when it went into the log -- here it is executed.
    let action = if ordered {
        Action::RestartOnOrder
    } else {
        Action::RestartAssigned
    };

    if let autonomy::Verdict::Deferred { reason } = autonomy::check(action, context.quorum) {
        // `info!`, not `warn!`: a deferred action is the **expected**
        // behaviour under a partition (ADR-0010), no grievance.
        tracing::info!(instance = %which, %action, reason, "deferred");
        report.deferred.push(which);
        return;
    }

    match apply::reconcile_one(paths, runtime, target, context).await {
        Ok(outcome) => {
            tracing::info!(instance = %which, %outcome, "reconciled");

            // **The restart loop gets a number** (ADR-0015).
            //
            // A workload that crashes at startup produces a restart at every
            // pass. Up to here only
            // `tg_agent_reconcile_total{outcome="reconciled"}` counted it --
            // aggregated over the whole node and in one pot with every first
            // start and every decree. **Which** workload does not come up was
            // said by the log alone, and that is the most frequent operational
            // disturbance of all.
            //
            // The workload name is permitted as a label: its number is bounded
            // by the number of definitions (the cardinality rule in
            // `tg_telemetry::names`). The **instance** is not -- which one it
            // was stands in the log.
            if outcome == apply::Outcome::Restarted {
                metrics::counter!(
                    tg_telemetry::names::WORKLOAD_RESTARTS,
                    "workload" => which.workload.clone()
                )
                .increment(1);
            }

            // **No information is neither success nor failure** (ADR-0122).
            // It does not belong in `reconciled` -- nothing was reconciled --
            // not in `untouched` -- we do not know whether it serves
            // (ADR-0013) -- and not in `failed`, because that would tear the
            // dependants along (ADR-0061).
            if let apply::Outcome::Unclear(reason) = outcome {
                metrics::counter!(
                    tg_telemetry::names::WORKLOAD_UNCLEAR,
                    "workload" => which.workload.clone()
                )
                .increment(1);
                report.unclear.push(Unclear {
                    instance: which,
                    reason,
                });
                return;
            }

            report.reconciled.push(which);
        }
        Err(err) => {
            tracing::error!(instance = %which, error = %err, "the reconcile failed");

            // **The class as a metric** (ADR-0015): it answers the question
            // an operator asks first -- where must I look -- and is
            // enumerable. The **text** stays local: it names names from a
            // payload, and a label out of it would be the memory leak the
            // cardinality rule forbids.
            metrics::counter!(
                tg_telemetry::names::WORKLOAD_FAILURES,
                "workload" => which.workload.clone(),
                "class" => err.class()
            )
            .increment(1);

            report.failed.push(Failure {
                instance: which,
                class: err.class(),
                reason: err.to_string(),
            });
        }
    }
}

pub async fn run(
    paths: &NodePaths,
    runtime: &OciRuntime,
    context: &Context<'_>,
    interval: Duration,
) -> Result<(), RuntimeError> {
    run_with(paths, runtime, context, interval, |_| {}).await
}

pub async fn run_with<F>(
    paths: &NodePaths,
    runtime: &OciRuntime,
    context: &Context<'_>,
    interval: Duration,
    observe: F,
) -> Result<(), RuntimeError>
where
    F: FnMut(Result<&Report, &RuntimeError>),
{
    run_traced(paths, runtime, context, interval, observe, || None).await
}

pub async fn run_traced<F, P>(
    paths: &NodePaths,
    runtime: &OciRuntime,
    context: &Context<'_>,
    interval: Duration,
    mut observe: F,
    parent: P,
) -> Result<(), RuntimeError>
where
    F: FnMut(Result<&Report, &RuntimeError>),
    P: Fn() -> Option<String>,
{
    loop {
        let started = std::time::Instant::now();
        // **One span per pass** (ADR-0133, determination 3) -- the end of
        // the chain command -> slice -> pass, and the only piece of it that
        // runs on another machine.
        let span = tracing::info_span!("reconcile");
        tg_telemetry::trace::adopt(&span, parent().as_deref());
        // `instrument` and not `enter`: a guard held across an `.await`
        // hangs on the **thread** and not on the task -- in a multi-threaded
        // runtime that is the wrong span.
        let outcome = {
            use tracing::Instrument as _;
            once(paths, runtime, context).instrument(span).await
        };

        let report = match outcome {
            Ok(report) => report,
            Err(err) => {
                // **No error of a pass ends the agent** (ADR-0062,
                // determination 1). Before, it went out here, the process
                // ended with an error status, and a supervisor made a crash
                // loop out of that -- with it went the workload API socket,
                // the resolver and the session (ADR-0019).
                //
                // The callback is called nevertheless: it carries the
                // watchdog, and a node that cannot reconcile is **not ready**,
                // not dead (determination 5, phase 11b).
                tracing::error!(error = %err, ?interval, "the pass failed, it will be repeated");
                observe(Err(&err));
                tokio::time::sleep(interval).await;
                continue;
            }
        };

        // The duration measures **one pass**, not the waiting time between
        // them. A histogram that measures the distance along shows the setting
        // `--interval` and not the work.
        metrics::histogram!(tg_telemetry::names::RECONCILE_SECONDS)
            .record(started.elapsed().as_secs_f64());
        for (outcome, count) in [
            ("untouched", report.untouched.len()),
            ("reconciled", report.reconciled.len()),
            ("deferred", report.deferred.len()),
            ("failed", report.failed.len()),
            ("held", report.held.len()),
            ("isolated", report.isolated.len()),
            ("reaped", report.reaped.len()),
        ] {
            metrics::counter!(tg_telemetry::names::RECONCILE, "outcome" => outcome)
                .increment(count as u64);
        }

        observe(Ok(&report));

        if !report.is_clean() {
            tracing::warn!(
                failed = report.failed.len(),
                isolated = report.isolated.len(),
                ?interval,
                "not reconciled, it will be repeated"
            );
        }
        // **Sleep lease-aware** (ADR-0076): if a single writer's fence
        // threshold is closer than the interval, it sleeps only until then.
        // The detection latency is thereby a small floor instead of
        // `--interval`, and the safety margin hangs on no setting.
        let nap = nap_for(interval, report.next_fence, (context.now)());
        match context.wake {
            // An arrived slice brings the pass forward (ADR-0076,
            // determination 7).
            Some(wake) => {
                tokio::select! {
                    () = tokio::time::sleep(nap) => {}
                    () = wake.notified() => {}
                }
            }
            None => tokio::time::sleep(nap).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use tg_defs::WorkloadExt as _;

    use tg_model::Inactivity;

    use super::{
        Context, EmptyMeans, Failure, Instance, Quorum, Report, cpu_usec, expand, read_number,
        trigger_for,
    };

    #[test]
    fn an_ambiguous_id_keeps_its_bundle() {
        use super::belongs_to;

        // Unambiguous: instance 0 and instance 3 of `api`.
        assert!(belongs_to("tg-api", "api"));
        assert!(belongs_to("tg-api-3", "api"));

        // **And the same identifier belongs to `api-3` too** -- the
        // ambiguity that lets both sides keep theirs.
        assert!(belongs_to("tg-api-3", "api-3"));

        // Another workload, a foreign prefix, a name prefix without a
        // hyphen: none of them a belonging. The last case is the interesting
        // one -- `api-proxy` begins with `api`, and a `starts_with` without
        // the number behind it tore the sidecar along (the same finding as
        // with the egress allowlist: "a prefix is not a name").
        assert!(!belongs_to("tg-ledger", "api"));
        assert!(!belongs_to("api", "api"));
        assert!(!belongs_to("tg-api-proxy", "api"));
    }

    #[derive(Default)]
    struct Seen {
        memory: Option<(f64, Vec<(String, String)>)>,
        peak: Option<(f64, Vec<(String, String)>)>,
        cpu: Option<(u64, Vec<(String, String)>)>,
        memory_limit: Option<(f64, Vec<(String, String)>)>,
        cpu_limit: Option<(f64, Vec<(String, String)>)>,
    }

    fn collect(snapshotter: &metrics_util::debugging::Snapshotter) -> Seen {
        use metrics_util::debugging::DebugValue;

        let mut seen = Seen::default();
        for (key, _, _, value) in snapshotter.snapshot().into_vec() {
            let name = key.key().name().to_owned();
            let mut labels: Vec<(String, String)> = key
                .key()
                .labels()
                .map(|label| (label.key().to_owned(), label.value().to_owned()))
                .collect();
            // Sorted, so that the assertion checks the **set** and not the
            // order in which a macro appends them.
            labels.sort();
            match value {
                DebugValue::Gauge(v) if name == tg_telemetry::names::CONTAINER_MEMORY => {
                    seen.memory = Some((v.into_inner(), labels));
                }
                DebugValue::Gauge(v) if name == tg_telemetry::names::CONTAINER_MEMORY_PEAK => {
                    seen.peak = Some((v.into_inner(), labels));
                }
                DebugValue::Gauge(v) if name == tg_telemetry::names::CONTAINER_MEMORY_LIMIT => {
                    seen.memory_limit = Some((v.into_inner(), labels));
                }
                DebugValue::Gauge(v) if name == tg_telemetry::names::CONTAINER_CPU_LIMIT => {
                    seen.cpu_limit = Some((v.into_inner(), labels));
                }
                DebugValue::Counter(v) if name == tg_telemetry::names::CONTAINER_CPU => {
                    seen.cpu = Some((v, labels));
                }
                _ => {}
            }
        }
        seen
    }

    #[test]
    #[ignore = "lays out a real cgroup; runs with `cargo xtask storage`"]
    fn a_real_cgroup_is_read_at_the_path_we_write() {
        use metrics_util::debugging::DebuggingRecorder;

        const XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
             <workload name=\"consumption\" kind=\"service\">\n\
             <image reference=\"example.com/consumption:1\"/>\n\
             </workload>\n</workloads>\n";

        let workload = tg_defs::from_str(XML).expect("parses").workloads()[0].clone();
        let id = crate::bundle::container_id("consumption", 0);
        let dir = std::path::Path::new("/sys/fs/cgroup")
            .join(crate::bundle::cgroups_path(&id).trim_start_matches('/'));

        // **The parent must enable the controllers**, otherwise the child
        // has only the core files -- no `memory.current`, no `cpu.stat`. In
        // operation the OCI runtime does that at creation; here the test does
        // it, and that it **must** is itself a finding: if the controller is
        // missing, the metric silently does not arise.
        let parent = dir.parent().expect("the parent").to_owned();
        std::fs::create_dir_all(&parent).expect("laying out the cgroup roof -- demands root");
        let _ = std::fs::write(parent.join("cgroup.subtree_control"), "+memory +cpu");
        std::fs::create_dir_all(&dir).expect("laying out the cgroup -- demands root");

        // **A peak that is gone again** (ADR-0123). A child process in this
        // cgroup briefly occupies memory and releases it; afterwards almost
        // nothing stands in `memory.current` and the peak in `memory.peak`.
        // Without it both numbers would be equal, and the witness below could
        // not say that it reads two **different** files.
        // Over `tmpfs`, because its pages are charged to the writing cgroup
        // and disappear again with the `rm` -- a peak that is one, without the
        // test bringing a language along.
        let burst = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "echo $$ > '{}/cgroup.procs' && \
                 dd if=/dev/zero of=/dev/shm/tg-peak-probe bs=1M count=64 \
                 status=none && rm -f /dev/shm/tg-peak-probe",
                dir.display()
            ))
            .status();
        assert!(
            burst.is_ok_and(|status| status.success()),
            "the peak could not be produced -- then the witness says nothing"
        );

        // **And a real limit** (ADR-0144). Set **after** the peak so that it
        // does not influence it -- here it is about the number the kernel
        // reports, not about its behaviour under pressure.
        //
        // `cpu.max` names `<quota> <period>` in microseconds; 50 000 of
        // 100 000 are half a core.
        let limits_set = std::fs::write(dir.join("memory.max"), "104857600").is_ok()
            && std::fs::write(dir.join("cpu.max"), "50000 100000").is_ok();

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            super::report_consumption(&[(workload, vec![0])]);
        });

        // Clear away before the assertions: a failed test is to leave no
        // cgroup behind. The roof stays only if it is not empty -- then it
        // belongs to a running container.
        let _ = std::fs::remove_dir(&dir);
        let _ = std::fs::remove_dir(&parent);

        let Seen {
            memory,
            peak,
            cpu,
            memory_limit,
            cpu_limit,
        } = collect(&snapshotter);

        let (_, labels) = memory
            .clone()
            .expect("a real cgroup's `memory.current` was not read");
        assert_eq!(
            labels,
            vec![
                ("replica".to_owned(), "0".to_owned()),
                ("workload".to_owned(), "consumption".to_owned()),
            ],
            "the instance number is called `replica` -- `instance` belongs to Prometheus"
        );
        assert!(
            cpu.is_some(),
            "`cpu.stat` was not read -- without the `cpu` controller in the \
             parent the line is missing, and then this test says nothing"
        );

        // **And the peak** (ADR-0123). It carries the same labels and -- and
        // that is the point -- **a different number**: the peak has long been
        // released, `memory.current` stands low again. That both are read
        // alone would prove nothing; that they lie apart proves that two
        // different files stand here.
        let (peak_value, labels) = peak.expect("a real cgroup's `memory.peak` was not read");
        assert_eq!(
            labels,
            vec![
                ("replica".to_owned(), "0".to_owned()),
                ("workload".to_owned(), "consumption".to_owned()),
            ],
            "the peak carries the same labels as the momentary value"
        );
        let (current, _) = memory.expect("the momentary value already stood there");
        assert!(
            peak_value > current && peak_value >= 32.0 * 1024.0 * 1024.0,
            "the peak ({peak_value}) must carry the 64 MiB from above and lie \
             above the momentary value ({current}) -- otherwise the same file \
             is read twice, and exactly that was the state before ADR-0123"
        );

        // **And the limit beside it** (ADR-0144). Without it the two numbers
        // above are without a yardstick: 800 MiB are a lot for a container
        // with one gigabyte and nothing for one with eight.
        assert!(
            limits_set,
            "the limits could not be set -- then this part says nothing"
        );
        let (limit, labels) = memory_limit.expect("`memory.max` was not read");
        assert_eq!(
            labels,
            vec![
                ("replica".to_owned(), "0".to_owned()),
                ("workload".to_owned(), "consumption".to_owned()),
            ],
            "the limit carries the same labels as the consumption -- otherwise \
             no ratio can be formed"
        );
        assert!(
            (limit - 104_857_600.0).abs() < f64::EPSILON,
            "the 100 MiB that were set came back as {limit}"
        );

        let (cores, _) = cpu_limit.expect("`cpu.max` was not read");
        assert!(
            (cores - 0.5).abs() < f64::EPSILON,
            "50 000 of 100 000 are half a core, reported was {cores}"
        );
    }

    #[test]
    fn a_cgroup_without_a_limit_reports_none() {
        let dir = tempfile::tempdir().expect("tempdir");

        let memory = dir.path().join("memory.max");
        std::fs::write(&memory, "max\n").expect("schreiben");
        assert_eq!(super::read_number(&memory), None);

        // The counter-check: a real number gets through.
        std::fs::write(&memory, "104857600\n").expect("schreiben");
        assert_eq!(super::read_number(&memory), Some(104_857_600));

        let cpu = dir.path().join("cpu.max");
        for (text, expected) in [
            ("max 100000\n", None),
            ("50000 100000\n", Some(0.5)),
            ("100000 100000\n", Some(1.0)),
            ("400000 100000\n", Some(4.0)),
            // **A period of zero is discarded instead of divided by**: a
            // `NaN` in a time series is worse than a missing one.
            ("50000 0\n", None),
            ("", None),
            ("50000\n", None),
            ("rubbish rubbish\n", None),
        ] {
            std::fs::write(&cpu, text).expect("schreiben");
            let seen = super::cpu_limit(&cpu);
            match (seen, expected) {
                (None, None) => {}
                (Some(seen), Some(want)) => assert!(
                    (seen - want).abs() < f64::EPSILON,
                    "`{}` yielded {seen} instead of {want}",
                    text.trim()
                ),
                (seen, want) => panic!("`{}` yielded {seen:?} instead of {want:?}", text.trim()),
            }
        }
    }

    #[test]
    fn a_container_without_a_cgroup_sets_nothing() {
        use metrics_util::debugging::DebuggingRecorder;

        const XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
             <workload name=\"does-not-exist\" kind=\"service\">\n\
             <image reference=\"example.com/nothing:1\"/>\n\
             </workload>\n</workloads>\n";

        let workload = tg_defs::from_str(XML).expect("parses").workloads()[0].clone();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            super::report_consumption(&[(workload, vec![0, 1])]);
        });

        assert!(
            snapshotter.snapshot().into_vec().is_empty(),
            "for a container without a cgroup no line must arise"
        );
    }

    #[test]
    fn the_cgroup_readers_take_the_number_and_nothing_else() {
        let dir = tempfile::tempdir().expect("tempdir");

        let memory = dir.path().join("memory.current");
        std::fs::write(&memory, "123456\n").expect("the file");
        assert_eq!(read_number(&memory), Some(123_456));

        // `max` stands in `memory.max`, not in `memory.current` -- but a
        // reader that took it for a number would report nonsense.
        std::fs::write(&memory, "max\n").expect("the file");
        assert_eq!(read_number(&memory), None);
        assert_eq!(read_number(&dir.path().join("does-not-exist")), None);

        // **A cgroup v2's real order**: `usage_usec` first, then
        // `user_usec`. The test reverses it so that it also catches a version
        // that takes the first line.
        let stat = dir.path().join("cpu.stat");
        std::fs::write(
            &stat,
            "user_usec 260272\nsystem_usec 13986954\nusage_usec 14247226\nnr_throttled 0\n",
        )
        .expect("the file");
        assert_eq!(cpu_usec(&stat), Some(14_247_226));

        // A cgroup without a `cpu` controller does not have the line. That
        // is a property of the machine and worth no message.
        std::fs::write(&stat, "nr_periods 0\n").expect("the file");
        assert_eq!(cpu_usec(&stat), None);
        assert_eq!(cpu_usec(&dir.path().join("does-not-exist")), None);
    }

    #[test]
    fn a_run_without_failures_is_clean() {
        assert!(Report::default().is_clean());

        let report = Report {
            unclear: Vec::new(),
            stale: Vec::new(),
            unready: Vec::new(),
            next_fence: None,
            waiting: Vec::new(),
            fenced: Vec::new(),
            untouched: vec![Instance::new("api", 0)],
            reconciled: vec![Instance::new("db", 0)],
            deferred: vec![Instance::new("batch", 0)],
            failed: Vec::new(),
            held: Vec::new(),
            isolated: Vec::new(),
            reaped: Vec::new(),
            own: std::collections::BTreeMap::new(),
            delegations: std::collections::BTreeMap::new(),
        };
        assert!(report.is_clean());
    }

    #[test]
    fn deferred_is_not_failed() {
        let report = Report {
            waiting: Vec::new(),
            fenced: Vec::new(),
            deferred: vec![Instance::new("ledger", 0)],
            ..Report::default()
        };

        assert!(report.is_clean());
        assert!(report.failed.is_empty());
    }

    #[test]
    fn a_single_failure_makes_the_run_unclean() {
        let report = Report {
            unclear: Vec::new(),
            stale: Vec::new(),
            unready: Vec::new(),
            next_fence: None,
            waiting: Vec::new(),
            fenced: Vec::new(),
            untouched: vec![Instance::new("a", 0), Instance::new("b", 0)],
            reconciled: vec![Instance::new("c", 0)],
            deferred: vec![Instance::new("d", 0)],
            failed: vec![Failure {
                instance: Instance::new("e", 0),
                class: "runtime",
                reason: "for the test".to_owned(),
            }],
            held: Vec::new(),
            isolated: Vec::new(),
            reaped: Vec::new(),
            own: std::collections::BTreeMap::new(),
            delegations: std::collections::BTreeMap::new(),
        };

        assert!(!report.is_clean());
    }

    #[test]
    fn the_report_carries_the_derived_sidecar() {
        let (assigned, principals) = derive(Some(&mesh()));

        assert_eq!(
            assigned,
            vec!["api".to_owned(), "api-proxy".to_owned()],
            "the sidecar stands written nowhere -- it arises"
        );
        assert_eq!(
            principals,
            std::collections::BTreeMap::from([("api-proxy".to_owned(), "api".to_owned())]),
            "who may speak for whom is said by the derivation (ADR-0036)"
        );
    }

    #[test]
    fn without_a_mesh_spec_nothing_is_derived() {
        let (assigned, principals) = derive(None);

        assert_eq!(assigned, vec!["api".to_owned()]);
        assert!(principals.is_empty());
    }

    const MESH_MEMBER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.test/api:1"/>
    <mesh port="8443"/>
  </workload>
</workloads>"#;

    fn mesh() -> crate::network::Mesh {
        crate::network::Mesh {
            overhead: std::path::PathBuf::from("/nowhere/sidecar-overhead"),
            spec: tg_model::SidecarSpec::new(
                "registry.example.test/proxy:1".to_owned(),
                "cluster.local",
            )
            .expect("a valid reference"),
            mounts: Vec::new(),
        }
    }

    fn derive(
        mesh: Option<&crate::network::Mesh>,
    ) -> (Vec<String>, std::collections::BTreeMap<String, String>) {
        let workload = tg_defs::from_str(MESH_MEMBER).expect("parses").workloads()[0].clone();
        let context = Context {
            devices: None,
            volume_keys: None,
            no_seccomp: false,
            userns: None,
            wake: None,
            now: &|| 0,
            fence_margin: 0,
            keep_snapshots: 3,
            quorum: Quorum::Available,
            network: None,
            mesh,
            workload_api: None,
            secrets: None,
            credentials: None,
            empty: &|| EmptyMeans::NothingHeard,
        };

        let derived = expand(vec![(workload, vec![0])], &context).expect("the derivation");

        (
            derived
                .assigned
                .iter()
                .map(|(workload, _)| workload.name().to_owned())
                .collect(),
            derived.principals,
        )
    }

    #[test]
    fn one_failed_replica_of_three_is_not_a_trigger() {
        assert_eq!(trigger_for(2, 1), None);
    }

    #[test]
    fn the_only_instance_failing_is_a_trigger() {
        assert_eq!(trigger_for(0, 1), Some(Inactivity::Failed));
    }

    #[test]
    fn a_deferred_target_is_not_a_trigger() {
        assert_eq!(trigger_for(0, 0), None);
    }

    #[test]
    fn an_active_target_is_not_a_trigger() {
        assert_eq!(trigger_for(3, 0), None);
    }

    #[test]
    fn the_instance_buckets_are_disjoint() {
        let report = Report {
            unclear: Vec::new(),
            stale: Vec::new(),
            unready: Vec::new(),
            next_fence: None,
            waiting: Vec::new(),
            fenced: Vec::new(),
            untouched: vec![Instance::new("a", 0)],
            reconciled: vec![Instance::new("b", 0)],
            deferred: vec![Instance::new("c", 0)],
            failed: vec![Failure {
                instance: Instance::new("d", 0),
                class: "runtime",
                reason: "for the test".to_owned(),
            }],
            held: vec![Instance::new("e", 0)],
            isolated: Vec::new(),
            reaped: Vec::new(),
            own: std::collections::BTreeMap::new(),
            delegations: std::collections::BTreeMap::new(),
        };

        let mut all: Vec<&Instance> = report
            .untouched
            .iter()
            .chain(&report.reconciled)
            .chain(&report.deferred)
            // `failed` carries its reason along (`Failure`), so the instance
            // out of it.
            .chain(report.failed.iter().map(|failure| &failure.instance))
            .chain(&report.held)
            .collect();
        let total = all.len();
        all.sort();
        all.dedup();

        assert_eq!(all.len(), total, "a workload stands in two pots");
        assert_eq!(
            total, 5,
            "there are five pots, since ADR-0061 brought a fifth"
        );
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;

    const WITH_PROBE: &str = r#"<?xml version="1.0"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1.0"/>
    <readiness port="8080"/>
  </workload>
</workloads>"#;

    const WITHOUT_PROBE: &str = r#"<?xml version="1.0"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1.0"/>
  </workload>
</workloads>"#;

    struct Recorder {
        answer: Result<(), String>,
        asked: std::sync::Mutex<Vec<(String, u16)>>,
    }

    impl Recorder {
        fn new(answer: Result<(), String>) -> Self {
            Self {
                answer,
                asked: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<(String, u16)> {
            self.asked.lock().expect("the record").clone()
        }
    }

    impl crate::network::Wiring for Recorder {
        fn attach(
            &self,
            _workload: &str,
            _instance: u32,
        ) -> Result<crate::network::Attachment, String> {
            unreachable!("this test attaches nothing")
        }

        fn leased(&self) -> Vec<String> {
            Vec::new()
        }

        fn release(&self, _container: &str) {}

        fn ensure_baseline(&self, _netns: &str) {}

        fn enforce(&self, _netns: &str, _workload: &str) {}

        fn probe(&self, container: &str, probe: Probe<'_>) -> Result<(), String> {
            self.asked
                .lock()
                .expect("the record")
                .push((container.to_owned(), probe.port));
            self.answer.clone()
        }
    }

    fn run(xml: &str, wiring: &dyn crate::network::Wiring, running: &[u32]) -> Report {
        let workload = tg_defs::from_str(xml).expect("parses").workloads()[0].clone();
        let context = Context {
            devices: None,
            volume_keys: None,
            no_seccomp: false,
            userns: None,
            wake: None,
            now: &|| 0,
            fence_margin: 0,
            keep_snapshots: 3,
            quorum: Quorum::Available,
            network: Some(wiring),
            mesh: None,
            workload_api: None,
            secrets: None,
            credentials: None,
            empty: &|| EmptyMeans::NothingHeard,
        };

        let mut report = Report::default();
        for instance in running {
            report.untouched.push(Instance::new("api", *instance));
        }

        probe_readiness(&[(workload, vec![0, 1])], &context, &mut report);
        report
    }

    #[test]
    fn hanging_probes_do_not_push_the_pass() {
        struct Slow;

        impl crate::network::Wiring for Slow {
            fn attach(&self, _w: &str, _i: u32) -> Result<crate::network::Attachment, String> {
                unreachable!("this test attaches nothing")
            }

            fn leased(&self) -> Vec<String> {
                Vec::new()
            }

            fn release(&self, _container: &str) {}

            fn ensure_baseline(&self, _netns: &str) {}

            fn enforce(&self, _netns: &str, _workload: &str) {}

            fn probe(&self, _container: &str, _probe: Probe<'_>) -> Result<(), String> {
                std::thread::sleep(tg_net::probe::TIMEOUT);
                Err("hangs".to_owned())
            }
        }

        // **Both axes**: four workloads with two instances each. The outer
        // loop was still sequential in this cut's first version, and the worst
        // case was thereby `workloads x TIMEOUT` -- with five workloads the
        // same finding once more.
        let mut assigned = Vec::new();
        let mut report = Report::default();
        for name in ["api", "ledger", "journal", "audit"] {
            let document = WITH_PROBE.replace("name=\"api\"", &format!("name=\"{name}\""));
            let workload = tg_defs::from_str(&document).expect("parses").workloads()[0].clone();
            assert_eq!(workload.name(), name, "the substitution did not bite");
            for instance in 0..2 {
                report.untouched.push(Instance::new(name, instance));
            }
            assigned.push((workload, vec![0, 1]));
        }

        let context = Context {
            devices: None,
            volume_keys: None,
            no_seccomp: false,
            userns: None,
            wake: None,
            now: &|| 0,
            fence_margin: 0,
            keep_snapshots: 3,
            quorum: Quorum::Available,
            network: Some(&Slow),
            mesh: None,
            workload_api: None,
            secrets: None,
            credentials: None,
            empty: &|| EmptyMeans::NothingHeard,
        };

        let start = std::time::Instant::now();
        probe_readiness(&assigned, &context, &mut report);
        let elapsed = start.elapsed();

        let floor = Duration::from_millis(tg_model::lease::FENCE_WAKE_FLOOR_MILLIS);
        assert!(
            elapsed < floor,
            "the pass took {elapsed:?} and thereby tore the detection latency \
             of {floor:?} -- sequentially it is `instances x TIMEOUT` \
             (ADR-0076)"
        );
        // Half the assurance: **all eight** were asked. A pass that does not
        // probe at all would be just as fast.
        assert_eq!(
            report.unready.len(),
            8,
            "all eight must have been asked: {:?}",
            report.unready
        );
    }

    #[test]
    fn a_workload_without_a_probe_is_never_asked() {
        let probe = Recorder::new(Err("never".to_owned()));
        let report = run(WITHOUT_PROBE, &probe, &[0, 1]);

        assert!(
            report.unready.is_empty(),
            "without a probe nothing is unready"
        );
        assert!(
            probe.asked().is_empty(),
            "without a declared probe nothing must be asked: {:?}",
            probe.asked()
        );
    }

    #[test]
    fn a_probe_that_answers_leaves_the_instance_alone() {
        let probe = Recorder::new(Ok(()));
        let report = run(WITH_PROBE, &probe, &[0, 1]);

        assert!(report.unready.is_empty(), "both probes answered");
        // **The identifier is computed forwards**, not read backwards: from
        // `tg-api-1` it could not be said whether instance 1 of `api` or
        // instance 0 of a workload `api-1` is meant.
        // **Sorted, because the probing is concurrent**: the order is no
        // assurance but the consequence of an ordering condition (see
        // [`tg_net::probe::TIMEOUT`]). Without the sorting this test would
        // fall occasionally -- measured, one of several runs -- and a flaky
        // test would be the dearer error.
        let mut asked = probe.asked();
        asked.sort();
        assert_eq!(
            asked,
            vec![("tg-api".to_owned(), 8080), ("tg-api-1".to_owned(), 8080)],
            "one ask per running instance, with its identifier and its port"
        );
    }

    #[test]
    fn a_probe_without_an_answer_marks_the_instance_unready() {
        let probe = Recorder::new(Err("refused".to_owned()));
        let report = run(WITH_PROBE, &probe, &[0, 1]);

        assert_eq!(
            report.unready,
            vec![Instance::new("api", 0), Instance::new("api", 1)],
            "both probes stayed without an answer"
        );
        assert_eq!(
            report.untouched,
            vec![Instance::new("api", 0), Instance::new("api", 1)],
            "an unready instance carries on -- it merely does not serve"
        );
        assert!(report.failed.is_empty(), "unready is not failed");
    }

    #[test]
    fn an_instance_that_does_not_run_is_not_probed() {
        let probe = Recorder::new(Ok(()));
        let report = run(WITH_PROBE, &probe, &[0]);

        assert_eq!(
            probe.asked(),
            vec![("tg-api".to_owned(), 8080)],
            "only the running instance is asked"
        );
        assert!(report.unready.is_empty());
    }

    #[test]
    fn the_ready_metric_stands_per_workload_in_both_cases() {
        struct Selective;

        impl crate::network::Wiring for Selective {
            fn attach(&self, _w: &str, _i: u32) -> Result<crate::network::Attachment, String> {
                unreachable!("this test attaches nothing")
            }

            fn leased(&self) -> Vec<String> {
                Vec::new()
            }

            fn release(&self, _container: &str) {}

            fn ensure_baseline(&self, _netns: &str) {}

            fn enforce(&self, _netns: &str, _workload: &str) {}

            fn probe(&self, container: &str, _probe: Probe<'_>) -> Result<(), String> {
                if container.starts_with("tg-api") {
                    Ok(())
                } else {
                    Err("mute".to_owned())
                }
            }
        }

        let mut assigned = Vec::new();
        let mut report = Report::default();
        for name in ["api", "ledger"] {
            let document = WITH_PROBE.replace("name=\"api\"", &format!("name=\"{name}\""));
            let workload = tg_defs::from_str(&document).expect("parses").workloads()[0].clone();
            report.untouched.push(Instance::new(name, 0));
            assigned.push((workload, vec![0]));
        }

        let context = Context {
            devices: None,
            volume_keys: None,
            no_seccomp: false,
            userns: None,
            wake: None,
            now: &|| 0,
            fence_margin: 0,
            keep_snapshots: 3,
            quorum: Quorum::Available,
            network: Some(&Selective),
            mesh: None,
            workload_api: None,
            secrets: None,
            credentials: None,
            empty: &|| EmptyMeans::NothingHeard,
        };

        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            probe_readiness(&assigned, &context, &mut report);
        });

        let mut seen: Vec<(String, f64)> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, _, _, _)| key.key().name() == tg_telemetry::names::WORKLOAD_READY)
            .filter_map(|(key, _, _, value)| {
                let workload = key
                    .key()
                    .labels()
                    .find(|label| label.key() == "workload")?
                    .value()
                    .to_owned();
                match value {
                    metrics_util::debugging::DebugValue::Gauge(ready) => {
                        Some((workload, ready.into_inner()))
                    }
                    _ => None,
                }
            })
            .collect();
        seen.sort_by(|left, right| left.0.cmp(&right.0));

        assert_eq!(
            seen,
            vec![("api".to_owned(), 1.0), ("ledger".to_owned(), 0.0)],
            "the metric must stand per workload, and the zero belongs to it"
        );
    }

    #[test]
    fn the_denominator_stands_beside_the_ready_metric() {
        struct FirstOnly;

        impl crate::network::Wiring for FirstOnly {
            fn attach(&self, _w: &str, _i: u32) -> Result<crate::network::Attachment, String> {
                unreachable!("this test attaches nothing")
            }

            fn leased(&self) -> Vec<String> {
                Vec::new()
            }

            fn release(&self, _container: &str) {}

            fn ensure_baseline(&self, _netns: &str) {}

            fn enforce(&self, _netns: &str, _workload: &str) {}

            fn probe(&self, container: &str, _probe: Probe<'_>) -> Result<(), String> {
                if container == "tg-api" {
                    Ok(())
                } else {
                    Err("mute".to_owned())
                }
            }
        }

        let workload = tg_defs::from_str(WITH_PROBE).expect("parses").workloads()[0].clone();
        let mut report = Report::default();
        report.untouched.push(Instance::new("api", 0));
        report.untouched.push(Instance::new("api", 1));
        let assigned = vec![(workload, vec![0, 1])];

        let context = Context {
            devices: None,
            volume_keys: None,
            no_seccomp: false,
            userns: None,
            wake: None,
            now: &|| 0,
            fence_margin: 0,
            keep_snapshots: 3,
            quorum: Quorum::Available,
            network: Some(&FirstOnly),
            mesh: None,
            workload_api: None,
            secrets: None,
            credentials: None,
            empty: &|| EmptyMeans::NothingHeard,
        };

        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            probe_readiness(&assigned, &context, &mut report);
        });

        let mut seen: Vec<(String, f64)> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter_map(|(key, _, _, value)| {
                let name = key.key().name().to_owned();
                if name != tg_telemetry::names::WORKLOAD_READY
                    && name != tg_telemetry::names::WORKLOAD_PROBED
                {
                    return None;
                }
                match value {
                    metrics_util::debugging::DebugValue::Gauge(seen) => {
                        Some((name, seen.into_inner()))
                    }
                    _ => None,
                }
            })
            .collect();
        seen.sort_by(|left, right| left.0.cmp(&right.0));

        assert_eq!(
            seen,
            vec![
                (tg_telemetry::names::WORKLOAD_PROBED.to_owned(), 2.0),
                (tg_telemetry::names::WORKLOAD_READY.to_owned(), 1.0),
            ],
            "one of two ready -- and the denominator must stand with it, otherwise              `1 of 2` is not distinguishable from `1 of 1`"
        );
    }

    #[test]
    fn without_a_node_network_nothing_is_probed() {
        let workload = tg_defs::from_str(WITH_PROBE).expect("parses").workloads()[0].clone();
        let context = Context {
            devices: None,
            volume_keys: None,
            no_seccomp: false,
            userns: None,
            wake: None,
            now: &|| 0,
            fence_margin: 0,
            keep_snapshots: 3,
            quorum: Quorum::Available,
            network: None,
            mesh: None,
            workload_api: None,
            secrets: None,
            credentials: None,
            empty: &|| EmptyMeans::NothingHeard,
        };

        let mut report = Report::default();
        report.untouched.push(Instance::new("api", 0));
        probe_readiness(&[(workload, vec![0])], &context, &mut report);

        assert!(
            report.unready.is_empty(),
            "without a network, ready applies"
        );
    }
}

#[cfg(test)]
mod adr_0126 {
    use super::{Context, EmptyMeans, Quorum, Report, collect_content};
    use crate::content::{ContentStore, Digest256};
    use crate::resolved::ResolvedImage;
    use tg_defs::generated::WorkloadType;

    const DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"registry.invalid/api:2\"/>\n\
         </workload>\n\
         </workloads>\n";

    fn context(empty: &'static dyn Fn() -> EmptyMeans) -> Context<'static> {
        Context {
            devices: None,
            volume_keys: None,
            no_seccomp: false,
            userns: None,
            wake: None,
            now: &|| 0,
            fence_margin: 0,
            keep_snapshots: 3,
            quorum: Quorum::Available,
            network: None,
            mesh: None,
            workload_api: None,
            secrets: None,
            credentials: None,
            empty,
        }
    }

    fn workload() -> WorkloadType {
        tg_defs::from_str(DOCUMENT)
            .expect("the definition")
            .workloads()[0]
            .clone()
    }

    fn store(paths: &crate::NodePaths) -> (Digest256, Digest256) {
        let store = ContentStore::open(paths.content_dir()).expect("store");
        let layer = |content: &[u8]| {
            let digest = Digest256::of(content);
            let dir = store.layer_path(&digest);
            std::fs::create_dir_all(&dir).expect("dir");
            std::fs::write(dir.join(".complete"), crate::content::LAYER_FORMAT).expect("marker");
            digest
        };
        let stays = layer(b"wanted");
        let goes = layer(b"forgotten");

        for (reference, digest) in [
            ("registry.invalid/api:2", &stays),
            ("registry.invalid/api:1", &goes),
        ] {
            ResolvedImage {
                reference: reference.to_owned(),
                layers: vec![digest.clone()],
                entrypoint: vec!["/bin/sleep".to_owned()],
                env: Vec::new(),
            }
            .save(&store)
            .expect("the record");
        }
        (stays, goes)
    }

    fn gone(paths: &crate::NodePaths, digest: &Digest256) -> bool {
        !ContentStore::open(paths.content_dir())
            .expect("store")
            .has_layer(digest)
    }

    #[test]
    fn a_complete_desired_state_collects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = crate::NodePaths::new(dir.path());
        let (stays, goes) = store(&paths);

        collect_content(
            &paths,
            &context(&|| EmptyMeans::NothingWanted),
            &[(workload(), vec![0])],
            &Report::default(),
        );

        assert!(!gone(&paths, &stays), "the reachable layer must stay");
        assert!(gone(&paths, &goes), "the unreachable one should have gone");
    }

    #[test]
    fn an_empty_desired_state_that_nobody_confirmed_collects_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = crate::NodePaths::new(dir.path());
        let (stays, goes) = store(&paths);

        collect_content(
            &paths,
            &context(&|| EmptyMeans::NothingHeard),
            &[],
            &Report::default(),
        );

        assert!(!gone(&paths, &stays), "nothing heard means touch nothing");
        assert!(!gone(&paths, &goes), "not the forgotten one either");
    }

    #[test]
    fn an_isolated_entry_collects_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = crate::NodePaths::new(dir.path());
        let (_, goes) = store(&paths);

        collect_content(
            &paths,
            &context(&|| EmptyMeans::NothingWanted),
            &[(workload(), vec![0])],
            &Report {
                isolated: vec!["broken".to_owned()],
                ..Report::default()
            },
        );

        assert!(
            !gone(&paths, &goes),
            "an incomplete desired state must remove nothing"
        );
    }

    #[test]
    fn a_leftover_bundle_postpones_the_sweep() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = crate::NodePaths::new(dir.path());
        let (_, goes) = store(&paths);
        std::fs::create_dir_all(paths.bundles_dir().join("forgotten")).expect("the bundle");

        collect_content(
            &paths,
            &context(&|| EmptyMeans::NothingWanted),
            &[(workload(), vec![0])],
            &Report::default(),
        );

        assert!(
            !gone(&paths, &goes),
            "as long as a bundle lies there, nothing is released"
        );
    }
}
