//! The session to the control plane (ADR-0040).
//!
//! The node establishes the stream, gets its slice over it and reports its state
//! over it. That is the way that replaces three stopgaps: the `may_talk` edges,
//! the desired state and the underlay peers.
//!
//! # The stream is a refresh, not a dependency
//!
//! ADR-0040, determination 6 — and the place at which ADR-0019 is upheld or
//! violated. What arrives lands on the disk; the reconcile loop **never** reads
//! from here. If the stream tears, the node works on with what it has and tries
//! again later.
//!
//! From that follows too what a node may conclude from **absence**: nothing. This
//! file never deletes a workload because a message fails to arrive — only because
//! a slice no longer names it.
//!
//! # What is written where
//!
//! ```text
//! <data-dir>/desired/<name>.xml     the definitions -- the same cache as since phase 2
//! <data-dir>/identity/ordinal       the ordinal (ADR-0039)
//! <data-dir>/network/cluster.json   the network parameters (ADR-0040)
//! <data-dir>/network/may-talk       the edges, in the sidecar's format
//! <data-dir>/network/egress         the egress permissions (ADR-0041)
//! <data-dir>/network/peers.json     the underlay peers
//! <data-dir>/network/endpoints.json the endpoints of foreign workloads (ADR-0073)
//! <data-dir>/network/sidecar-overhead the surcharge per mesh instance (ADR-0086)
//! <data-dir>/network/applied        the last applied log index
//! ```
//!
//! The edge file stays a file, and that is no remnant: the sidecar runs in a
//! container, has no node identity and cannot ask the control plane. What is new
//! is **where** its content comes from — until here an operator wrote it, now
//! consensus does. The sidecar re-reads it in operation anyway (`tg-proxy`,
//! phase 8b).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt as _;
use tg_store::session::{
    ControlMessage, InstanceState, NodeMessage, NodeReport, NodeSlice, SessionClient,
};

const RETRY_AFTER: Duration = Duration::from_secs(5);

const REPORT_EVERY: Duration =
    Duration::from_secs(tg_store::session::REPORT_EVERY_SECONDS.unsigned_abs());

pub(crate) struct Paths {
    data_dir: PathBuf,
}

impl Paths {
    pub(crate) fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_owned(),
        }
    }

    pub(crate) fn endpoints(&self) -> PathBuf {
        self.network().join("endpoints.json")
    }

    pub(crate) fn tombstones(&self) -> PathBuf {
        tg_runtime::NodePaths::new(&self.data_dir).tombstones()
    }

    pub(crate) fn snapshot_orders(&self) -> PathBuf {
        tg_runtime::NodePaths::new(&self.data_dir).snapshot_orders()
    }

    pub(crate) fn cluster_network(&self) -> PathBuf {
        self.network().join("cluster.json")
    }

    pub(crate) fn edges(&self) -> PathBuf {
        self.network().join("may-talk")
    }

    pub(crate) fn egress(&self) -> PathBuf {
        self.network().join("egress")
    }

    pub(crate) fn mesh_udp(&self) -> PathBuf {
        self.network().join("mesh-udp")
    }

    pub(crate) fn roles(&self) -> PathBuf {
        self.network().join("active-role")
    }

    pub(crate) fn sidecar_overhead(&self) -> PathBuf {
        self.network().join("sidecar-overhead")
    }

    pub(crate) fn peers(&self) -> PathBuf {
        self.network().join("peers.json")
    }

    pub(crate) fn network(&self) -> PathBuf {
        tg_runtime::NodePaths::new(&self.data_dir).network_dir()
    }

    fn applied(&self) -> PathBuf {
        tg_runtime::NodePaths::new(&self.data_dir).slice_applied()
    }
}

pub(crate) fn slice_applied(data_dir: &Path) -> bool {
    Paths::new(data_dir).applied().exists()
}

fn last_applied(paths: &Paths) -> u64 {
    std::fs::read_to_string(paths.applied())
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
        .unwrap_or(0)
}

fn declares_mesh_udp(document: &str) -> bool {
    use tg_defs::{MeshExt as _, WorkloadExt as _};

    tg_defs::from_str(document).is_ok_and(|set| {
        set.workloads()
            .iter()
            .any(|workload| workload.mesh().is_some_and(|mesh| mesh.udp().is_some()))
    })
}

fn mesh_udp_lines(slice: &NodeSlice) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    for instance in &slice.instances {
        // **Only workloads with `<mesh udp>`.** The document stands in the
        // slice; parsing it costs nothing here that the reconciler would not do
        // anyway, and the alternative would be one more field in the slice for a
        // fact that already stands in it.
        if !declares_mesh_udp(&instance.document) {
            continue;
        }

        let mut peers: Vec<&str> = slice
            .edges
            .iter()
            .filter(|(from, _)| *from == instance.workload)
            .map(|(_, to)| to.as_str())
            .collect();
        peers.sort_unstable();
        peers.dedup();

        for (at, peer) in peers.iter().enumerate() {
            // The peer's **first healthy** instance, otherwise the first at all
            // -- the same choice as with the resolution (ADR-0013).
            let mut mine: Vec<&tg_store::session::RemoteEndpoint> = slice
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.workload == **peer)
                .collect();
            mine.sort_by_key(|endpoint| (!endpoint.healthy, endpoint.instance));

            let Some(endpoint) = mine.first() else {
                // **Without an address no line** -- and thereby no listener and
                // no rule. Datagrams there die at the discarding rule
                // (ADR-0074), and that is the safe direction.
                continue;
            };
            let Some(local) = u16::try_from(at)
                .ok()
                .and_then(|offset| tg_model::mesh::SIDECAR_MESH_UDP_BASE.checked_add(offset))
            else {
                continue;
            };

            let _ = writeln!(
                out,
                "{} {peer} {}:{} {local}",
                instance.workload,
                endpoint.address,
                tg_model::mesh::SIDECAR_MESH_UDP
            );
        }
    }

    out
}

fn write_files(paths: &Paths, slice: &NodeSlice) -> Result<(), String> {
    // 3. The edges, in the format the sidecar reads.
    let mut edges = String::new();
    for (from, to) in &slice.edges {
        use std::fmt::Write as _;
        let _ = writeln!(edges, "{from} -> {to}");
    }
    write(&paths.edges(), &edges)?;

    // 3a. The UDP peers in the mesh (ADR-0142, determination 8). **A
    //     computation over the slice**, unlike the three files beside it: edges
    //     (ADR-0025) times endpoints (ADR-0073), and one local port per peer.
    //
    //     The port carries the statement which peer was meant -- with UDP the
    //     destination address survives no redirect (measured), unlike with TCP
    //     (`SO_ORIGINAL_DST`, ADR-0060).
    //
    //     **Here and not in the reconciler**, because the same computation feeds
    //     the rule set too: two derivations would be two opportunities to
    //     disagree -- a redirect without a listener would take the workload's
    //     way, a listener without a redirect would never get a datagram.
    write(&paths.mesh_udp(), &mesh_udp_lines(slice))?;

    // 3b. The egress permissions (ADR-0041). The same construction and the same
    //     reason as with the edges: the sidecar runs in a container, has no node
    //     identity and cannot ask the control plane.
    //
    //     **One file for all workloads of the node**, with the name in the line
    //     -- not one per workload. The sidecar filters its own out; one file per
    //     workload would be one more file that must arise and disappear, and one
    //     more path a name influences.
    //
    //     The fourth word is the **transport** (ADR-0092). It is at the same time
    //     the contract to `tg_proxy::egress`: the sidecar does not hang on
    //     `tg-model` -- the edge would pull an XSD parser into the data plane --,
    //     so the line is the shared place. A skew falls out fail-closed: what the
    //     sidecar does not understand is no permission.
    let mut egress = String::new();
    for (workload, host, port, transport) in &slice.egress {
        use std::fmt::Write as _;
        let _ = writeln!(egress, "{workload} {host} {port} {transport}");
    }
    write(&paths.egress(), &egress)?;

    // 3c. Who holds the **active role** (ADR-0066). The same construction and
    //     the same reason as with the two before it.
    //
    //     Only the **holders** stand in it. Who is affected is said by the
    //     `--single-writer` at the sidecar (ADR-0066, determination 2): if the
    //     affectedness stood here, a missing file would mean "nobody is
    //     affected", and a read error would lift the active role for everyone.
    //
    //     The slice carries only its own leases anyway (ADR-0040), and it is
    //     granted to the node of instance 0 (ADR-0064) -- what stands here belongs
    //     to this node.
    let mut roles = String::new();
    for (workload, epoch, expires_at) in &slice.leases {
        use std::fmt::Write as _;
        let _ = writeln!(roles, "{workload} {epoch} {expires_at}");
    }
    write(&paths.roles(), &roles)?;

    // 4b. The endpoints of foreign workloads (ADR-0073).
    //
    //     A **file** and no handle into the resolver, for two reasons: the
    //     reconciliation of the registry runs at the reconcile cadence and
    //     re-reads it there anyway, and it survives a restart. If the session
    //     stays away, the node goes on resolving what it last knew (ADR-0019) --
    //     the same construction and the same reason as with `peers.json` and the
    //     edge file.
    write(
        &paths.endpoints(),
        &serde_json::to_string(&slice.endpoints).map_err(|err| err.to_string())?,
    )?;

    // 4. The underlay peers (ADR-0039).
    write(
        &paths.peers(),
        &serde_json::to_string(&slice.peers).map_err(|err| err.to_string())?,
    )?;

    // 5. The surcharge per mesh instance (ADR-0067), from which the reconciler
    //    forms the derived sidecar's limit (ADR-0086). One line per resource,
    //    `name=number` -- the same format as the edge file beside it, and for the
    //    same reason: an operator reads it.
    let mut overhead = String::new();
    for (name, amount) in &slice.sidecar_overhead {
        use std::fmt::Write as _;
        let _ = writeln!(overhead, "{name}={amount}");
    }
    write(&paths.sidecar_overhead(), &overhead)?;

    Ok(())
}

pub(crate) fn apply(paths: &Paths, slice: &NodeSlice) -> Result<(), String> {
    let desired =
        tg_runtime::state::DesiredState::open(&paths.data_dir).map_err(|err| err.to_string())?;

    // 1. The definitions. They go through **the same** loader as a written
    //    definition -- a document from the log that violates the schema would
    //    otherwise stand out only at the start of a container.
    let mut wanted = std::collections::BTreeSet::new();
    // Which **instances** this node shall carry. The slice names them
    // individually (ADR-0034/0040); until the instance distinction the number fell
    // on the floor here, and the reconciler worked per name -- a workload with
    // `replicas="3"` ran with **one** container, and its writable volume was
    // always instance 0's.
    let mut assigned: std::collections::BTreeMap<String, Vec<u32>> =
        std::collections::BTreeMap::new();

    for instance in &slice.instances {
        let set = tg_defs::from_str(&instance.document)
            .map_err(|err| format!("'{}': {err}", instance.workload))?;
        for workload in set.workloads() {
            desired.put(workload).map_err(|err| err.to_string())?;
            wanted.insert(tg_defs::WorkloadExt::name(workload).to_owned());
        }
        // The number belongs to the name the slice names, not to every workload
        // in the document: a document can declare several, and exactly one was
        // placed.
        assigned
            .entry(instance.workload.clone())
            .or_default()
            .push(instance.instance);
    }

    // The workloads **without** an instance get an assignment too, and an empty
    // one at that. A document can declare several workloads; those the slice did
    // not place do not run here. Without the empty entry the default "instance 0"
    // (phase 2) would take hold and the node would start a container nobody put
    // here.
    for name in &wanted {
        let instances = assigned.get(name).cloned().unwrap_or_default();
        desired
            .assign(name, &instances)
            .map_err(|err| err.to_string())?;
    }

    // **The active-role leases** (ADR-0064). They are persisted because the
    // first slice after a restart is still outstanding -- without the deadline the
    // agent would not know that it still holds the active role. A stale setting is
    // harmless: it carries its expiry within it.
    //
    // And **expressly for every wanted name**, with `None` too: what the slice no
    // longer names is no lease any more, and a file left lying would let an
    // expired role live on.
    let leases: std::collections::BTreeMap<&str, (u64, u64)> = slice
        .leases
        .iter()
        .map(|(workload, epoch, expires_at)| (workload.as_str(), (*epoch, *expires_at)))
        .collect();
    for name in &wanted {
        desired
            .set_lease(name, leases.get(name.as_str()).copied())
            .map_err(|err| err.to_string())?;
    }

    // **Who carries the active role** (ADR-0111). The same construction and the
    // same reason as with the leases: **for every wanted name**, with the default
    // zero too. A file left lying would let a withdrawn promotion live on -- and
    // then instance 0 would wait for a lease that goes to another instance.
    let active: std::collections::BTreeMap<&str, u32> = slice
        .active_instances
        .iter()
        .map(|(workload, instance)| (workload.as_str(), *instance))
        .collect();
    for name in &wanted {
        desired
            .set_active_instance(name, active.get(name.as_str()).copied().unwrap_or(0))
            .map_err(|err| err.to_string())?;
    }

    // **The decreed generations** (ADR-0071). They stand at the slice's instances
    // and are filed per workload; **for every wanted name**, empty too --
    // otherwise a file would stay lying whose number triggers a restart nobody
    // decreed any more.
    let mut generations: std::collections::BTreeMap<&str, Vec<(u32, u64)>> =
        std::collections::BTreeMap::new();
    for instance in &slice.instances {
        generations
            .entry(instance.workload.as_str())
            .or_default()
            .push((instance.instance, instance.generation));
    }
    for name in &wanted {
        desired
            .set_generations(
                name,
                generations.get(name.as_str()).map_or(&[], Vec::as_slice),
            )
            .map_err(|err| err.to_string())?;
    }

    // 2. What the slice **no longer** names goes away. That is no conclusion
    //    from the absence of messages but from the content of one that arrived
    //    (ADR-0040, determination 6).
    //
    //    What is asked for are the **file names** and not the content (ADR-0062):
    //    an unreadable document names no workload, and whoever wanted to read it
    //    would fail here -- the session would never get through, and the node
    //    would stand still. The file name carries the name anyway
    //    (`DesiredState::put`), and with that the node heals itself: what the
    //    cluster no longer names goes away, readable or not. What it still names
    //    is rewritten just above.
    for name in desired.names().map_err(|err| err.to_string())? {
        if !wanted.contains(name.as_str()) {
            desired.remove(&name).map_err(|err| err.to_string())?;
        }
    }

    std::fs::create_dir_all(paths.network()).map_err(|err| err.to_string())?;
    // **Before the first write** (ADR-0115, determination 5): the other way round
    // there would be a window in which the edges, the egress permissions, the
    // peers and the address plan lie in an open directory -- and it would be
    // widest open at startup.
    //
    // What is sealed is the **directory**, not the files in it (determination 2):
    // three of them are mounted read-only into the sidecar container, and that
    // runs as 65532 (ADR-0060).
    tg_runtime::content::seal_soft(&paths.network(), "seal the network directory");

    // 3. The files the sidecar and the node network read.
    write_files(paths, slice)?;

    // 5. Ordinal and network parameters. The ordinal comes along at the renewal
    //    too (ADR-0039) -- the same number from the same source, here only earlier
    //    and more often.
    if let Some(ordinal) = slice.ordinal {
        write(
            &crate::identity::dir(&paths.data_dir).join(tg_identity::layout::ORDINAL),
            &format!("{ordinal}\n"),
        )?;
    }
    if let Some(network) = &slice.network {
        let file = paths.cluster_network();
        let fresh = serde_json::to_string(network).map_err(|err| err.to_string())?;

        // **A change is said.** The node network is built at startup (bridge,
        // address ledger, resolver); an address plan that comes afterwards reaches
        // the tunnel at once and the bridge only at the next start. As long as the
        // two lie apart, the tunnel allows a range the own containers do not use
        // -- exactly the state the one source abolishes. Producing it silently
        // would be the worse outcome.
        let before = std::fs::read_to_string(&file).unwrap_or_default();
        if !before.is_empty() && before != fresh {
            tracing::warn!(
                %before,
                after = %fresh,
                "the address plan has changed -- the bridge follows only at this \
                 agent's next start"
            );
        }

        write(&file, &fresh)?;
    }

    // 6. The volume orders (ADR-0110): written, not executed.
    //
    //    **This arm does not touch the kernel.** Until here the deletion
    //    (ADR-0042) and the snapshot (ADR-0099) stood here and called `losetup`,
    //    `fsfreeze` and `std::fs::copy` -- up to a minute per volume
    //    (`volume::TOOL_TIMEOUT`), in a loop. A `select!` polls exactly one arm at
    //    a time, so that halted the report; after `REPORT_WINDOW_SECONDS` the node
    //    dropped out of `reporting`, the leader skipped the renewal, and after
    //    `LEASE_SECONDS` every single writer fenced itself (ADR-0068, ADR-0064). A
    //    **healthy** node lost its active roles because it copied a volume.
    //
    //    And the execution of the deletion passed its `Err` on with `?`: a failed
    //    `losetup` thereby ended the **session** and sent the agent to a different
    //    endpoint (ADR-0077) -- for an error that has nothing to do with the
    //    control plane.
    //
    //    What executes now is the reconciler: it has a watchdog (ADR-0082), and a
    //    failure costs its workload there and not the node (ADR-0062). Both orders
    //    are level-triggered and can therefore be deferred without loss
    //    (ADR-0104, ADR-0099).
    write(
        &paths.tombstones(),
        &serde_json::to_string(&slice.deleted_volumes).map_err(|err| err.to_string())?,
    )?;
    write(
        &paths.snapshot_orders(),
        &serde_json::to_string(&slice.snapshot_generations).map_err(|err| err.to_string())?,
    )?;

    // 7. Last the mark. Only when everything else lies there -- otherwise after
    //    an abort the node would take a slice for applied that is not.
    write(&paths.applied(), &format!("{}\n", slice.index))
}

fn retired(paths: &Paths) -> Vec<String> {
    let path = paths.tombstones();
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        // No file means "no instruction" and is the normal case -- a cluster
        // without a deletion has nothing lying here.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "tombstones unreadable, nothing reported");
            return Vec::new();
        }
    };
    let Ok(tombstones): Result<Vec<String>, _> = serde_json::from_str(&text) else {
        tracing::warn!(path = %path.display(), "tombstones unreadable, nothing reported");
        return Vec::new();
    };
    if tombstones.is_empty() {
        return Vec::new();
    }

    let store = match tg_runtime::volume::VolumeStore::open(&paths.data_dir) {
        Ok(store) => store,
        // **The same failure the execution reports** (since ADR-0110 in the
        // reconciler). It means "the disk is jammed", and without the line the
        // tombstone stays in the state forever (ADR-0104) while the cause lies on
        // this node and nobody names it.
        Err(err) => {
            tracing::warn!(%err, "the volume store cannot be opened, no execution reported");
            return Vec::new();
        }
    };

    tombstones
        .into_iter()
        .filter(|volume| !store.exists(volume))
        .collect()
}

fn write(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    std::fs::write(path, contents).map_err(|err| format!("{}: {err}", path.display()))
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Observation {
    pub(crate) states: Vec<(String, u32, InstanceState)>,
    pub(crate) stale: Vec<(String, u32)>,
    pub(crate) unready: Vec<(String, u32)>,
    pub(crate) failures: Vec<(String, u32, String)>,
    pub(crate) isolated: Vec<String>,
    pub(crate) endpoints: Vec<tg_store::session::ReportedEndpoint>,
    pub(crate) dns_zone: Option<String>,
}

pub(crate) type Observed = Arc<std::sync::RwLock<Observation>>;

pub(crate) fn observed() -> Observed {
    Arc::new(std::sync::RwLock::new(Observation::default()))
}

pub(crate) fn observe(
    observed: &Observed,
    report: &tg_runtime::reconcile::Report,
    net: Option<&crate::network::Network>,
) {
    let mut states = Vec::new();
    let buckets = [
        (&report.untouched, InstanceState::Running),
        (&report.reconciled, InstanceState::Running),
        (&report.deferred, InstanceState::Stopped),
        // As in `publish`: held back is stopped (ADR-0061). If it were missing
        // here, the node would not report an instance to the leader at all -- and
        // "never seen" means something different there than "stands still".
        (&report.held, InstanceState::Stopped),
        // The active-role lease (ADR-0064, determination 6): stopped, not
        // failed. The leader shall see that the holder has stopped -- otherwise a
        // writer that no longer exists stands in its projection.
        (&report.fenced, InstanceState::Stopped),
        (&report.waiting, InstanceState::Stopped),
    ];

    for (instances, state) in buckets {
        for instance in instances {
            states.push((instance.workload.clone(), instance.instance, state));
        }
    }
    // **Failed ones individually**, because they carry their reason along
    // (`Failure`). The **text** expressly does not go along: it names names from a
    // payload, and in the report it would be a format break (ADR-0072) for a
    // statement the node's log carries better. What the cluster sees is the
    // **class** as a metric (ADR-0015).
    for failure in &report.failed {
        states.push((
            failure.instance.workload.clone(),
            failure.instance.instance,
            InstanceState::Failed,
        ));
    }
    // **`report.unclear` is missing here on purpose** (ADR-0122,
    // determination 5) -- the same consideration as in `publish`: the report
    // replaces this node's set, so the absence is the statement "no information".
    // `InstanceState` knows no ignorance, and a variant for it would be a format
    // break (ADR-0072) for something the omission already says.
    //
    // By name and number, so that two reports of the same state look the same.
    // `InstanceState` is not ordering and need not be: an instance occurs exactly
    // once.
    states.sort_by(|left, right| (&left.0, left.1).cmp(&(&right.0, right.1)));

    // **And which of them run stale** (ADR-0070). They also stand in `untouched`
    // and thereby above as `Running`: stale is a statement, no state beside it
    // (ADR-0070, determination 5). If it were missing here, an operator would have
    // to query every node individually in order to find where a change is
    // outstanding.
    let mut stale: Vec<(String, u32)> = report
        .stale
        .iter()
        .map(|instance| (instance.workload.clone(), instance.instance))
        .collect();
    stale.sort();

    // **And which do not answer their readiness probe** (ADR-0080). The same
    // construction and the same reason as `stale` beside it: they also stand above
    // as `Running` (determination 1), and without this line a **foreign** node
    // offered the address of an unready instance while its own kept it quiet
    // (ADR-0073).
    let mut unready: Vec<(String, u32)> = report
        .unready
        .iter()
        .map(|instance| (instance.workload.clone(), instance.instance))
        .collect();
    unready.sort();

    // **The class of the failures** (ADR-0015). The instance stands beside it in
    // `states` with `Failed`; here stands **where** to look -- `pull`, `mount`,
    // `volume`, `runtime`, … The **text** stays in this node's log: it names names
    // from a payload, and here it would be an unbounded value in a message every
    // report carries.
    let mut failures: Vec<(String, u32, String)> = report
        .failed
        .iter()
        .map(|failure| {
            (
                failure.instance.workload.clone(),
                failure.instance.instance,
                failure.class.to_owned(),
            )
        })
        .collect();
    failures.sort();

    // **The isolated entries** (ADR-0062, determination 6). They do not stand in
    // `states`: isolated means neither started nor stopped, and a state beside it
    // would claim something nobody observed. They travel as a list of their own --
    // otherwise the cluster learns nothing of a broken declaration, and the leader
    // reads "never seen".
    let mut isolated = report.isolated.clone();
    isolated.sort();

    // **What the node network knows.** The addresses come from the address ledger
    // and not from the report (ADR-0073): the address belongs to the instance as
    // long as its lease stands. Without a node network there are none -- and that
    // is right, for then nothing runs there that anybody could dial.
    let endpoints = net
        .map(crate::network::Network::endpoints)
        .unwrap_or_default();
    let dns_zone = net.map(|net| net.zone().to_owned());

    if let Ok(mut guard) = observed.write() {
        *guard = Observation {
            states,
            stale,
            unready,
            failures,
            isolated,
            endpoints,
            dns_zone,
        };
    }
}

fn report(
    paths: &Paths,
    observed: &Observed,
    applied: u64,
    proxy_image: Option<String>,
    userns: Option<u32>,
    devices: &std::collections::BTreeMap<String, u64>,
) -> NodeReport {
    let Observation {
        states,
        stale,
        unready,
        failures,
        isolated,
        endpoints,
        dns_zone,
    } = observed
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();

    NodeReport {
        applied,
        states,
        // Observed like the states beside it, and from the same pass (ADR-0070,
        // ADR-0040 determination 7).
        stale,
        // And which do not serve (ADR-0080). Without them the leader computes
        // `RemoteEndpoint::healthy` from the states alone -- and a foreign node
        // offers a mute endpoint.
        unready,
        // Why a reconciliation failed, as a **class** (ADR-0015). Without it
        // `tgctl cluster show` says only `Failed`.
        failures,
        // And what it **could not classify** (ADR-0062). Without this line the
        // cluster learns nothing of a broken declaration.
        isolated,
        // What the machine has (ADR-0049) -- an observation. What of it is usable
        // is decided by a policy in the log, not by this node.
        capacity: crate::capacity::observe(devices),
        // And which key generations it **carries** (ADR-0055, determination 5)
        // -- likewise an observation. What shall apply is said by the log.
        generations: crate::rotate::current(&paths.data_dir),
        // And what it builds its sidecars with (ADR-0059). It stays a setting per
        // node; what becomes visible is only when two drift apart.
        proxy_image,
        // And the addresses of its instances (ADR-0073) -- the only way on which
        // a container address reaches the cluster. They are handed out node-locally
        // (phase 9a), they are reported here.
        endpoints,
        // And which zone it serves (ADR-0013). Like the proxy image it stays a
        // setting per node; what becomes visible is only when two drift apart.
        dns_zone,
        // And whether it maps (ADR-0091). The same situation as the two before it
        // -- a setting per node --, only a skew weighs more here: it is one in the
        // **security posture**.
        userns,
        // And which deletions it has **executed** (ADR-0104). Not from the
        // observation state: that arises per reconcile pass and would overwrite
        // itself. What is asked is the volume store, anew every time.
        retired: retired(paths),
    }
}

#[derive(Clone)]
pub(crate) struct Announcement {
    pub(crate) node: String,
    pub(crate) data_dir: PathBuf,
    pub(crate) endpoint: String,
}

// **Clonable because of ADR-0116**: the watcher holds the factory and sets the
// session up again after a panic -- for that every attempt needs its own
// introduction. All fields are values or shared handles; the copy costs nothing a
// restart would not cost anyway.
#[derive(Clone)]
pub(crate) struct Introduction {
    pub node: String,
    pub endpoints: crate::endpoints::Endpoints,
    pub announcement: Option<Announcement>,
    pub proxy_image: Option<String>,
    pub devices: std::collections::BTreeMap<String, u64>,
    pub userns: Option<u32>,
    pub registries: crate::registries::Registries,
    pub secrets: crate::secrets::SecretStore,
}

impl Introduction {
    fn absorb(&self, slice: &NodeSlice) {
        self.registries.absorb(slice);
        self.secrets.absorb(slice);
    }
}

pub(crate) async fn keep_open(
    data_dir: PathBuf,
    mut introduction: Introduction,
    cluster: crate::cluster::Cluster,
    observed: Observed,
    wake: Arc<tokio::sync::Notify>,
    reconcile_now: Arc<tokio::sync::Notify>,
    // **The `traceparent` of the last applied slice** (ADR-0133): beside the
    // state, not in it -- the same construction as in `tgd`. What `apply` writes
    // onto the disk is the desired state; the trace is observation and lives only
    // in memory.
    trace: Arc<std::sync::RwLock<Option<String>>>,
) {
    let paths = Paths::new(&data_dir);

    loop {
        let outcome = once(
            &paths,
            &introduction,
            &cluster,
            &observed,
            &wake,
            &reconcile_now,
            &trace,
        )
        .await;

        // **Moving on always happens, waiting does not** (ADR-0077,
        // determinations 2 and 3). A referral with a known leader is information:
        // this endpoint is demonstrably the wrong one, and a waiting time there
        // would be lost time. Everything else can be a crashed node -- then the
        // waiting time applies.
        let next = match outcome {
            Ok(()) => crate::endpoints::Next::AfterWaiting,
            Err(Ended { message, next }) => {
                tracing::warn!(
                    %message,
                    endpoint = introduction.endpoints.current(),
                    "session ended"
                );
                next
            }
        };

        introduction.endpoints.advance();
        if next == crate::endpoints::Next::AfterWaiting {
            tokio::time::sleep(RETRY_AFTER).await;
        }
    }
}

pub(crate) struct Ended {
    message: String,
    next: crate::endpoints::Next,
}

impl From<String> for Ended {
    fn from(message: String) -> Self {
        Self {
            message,
            next: crate::endpoints::Next::AfterWaiting,
        }
    }
}

fn report_message(
    paths: &Paths,
    introduction: &Introduction,
    observed: &Observed,
    applied: u64,
) -> NodeMessage {
    NodeMessage::Report(Box::new(report(
        paths,
        observed,
        applied,
        introduction.proxy_image.clone(),
        introduction.userns,
        &introduction.devices,
    )))
}

async fn once(
    paths: &Paths,
    introduction: &Introduction,
    cluster: &crate::cluster::Cluster,
    observed: &Observed,
    // **The wake-up belongs to the renewer, not to the announcement.** It travels
    // independently, because an identity rotation needs it without the node
    // announcing an underlay at all (ADR-0055).
    wake: &Arc<tokio::sync::Notify>,
    // **And one in the other direction** (ADR-0076, determination 7): a slice
    // that has arrived brings a reconcile pass forward. Without it a single writer
    // took up its granted role only at the next pass.
    reconcile_now: &Arc<tokio::sync::Notify>,
    // **The slice's trace** (ADR-0133, D4): it is set here and read by the
    // reconcile pass.
    trace: &Arc<std::sync::RwLock<Option<String>>>,
) -> Result<(), Ended> {
    // The credential lies on the channel, not in the first message (ADR-0043,
    // determination 7).
    let client = SessionClient::with_channel(cluster.channel(introduction.endpoints.current())?);
    let mut applied = last_applied(paths);

    let (sender, receiver) = tokio::sync::mpsc::channel::<NodeMessage>(8);
    sender
        .send(NodeMessage::Hello { applied })
        .await
        .map_err(|_| "the stream is closed".to_owned())?;

    let mut incoming = client
        .open(tokio_stream::wrappers::ReceiverStream::new(receiver))
        .await
        .map_err(|err| err.to_string())?;

    let mut ticker = tokio::time::interval(REPORT_EVERY);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            message = incoming.next() => match message {
                Some(Ok(ControlMessage::Slice(slice))) => {
                    // Monotonicity (ADR-0040, determination 4): what goes
                    // backwards is discarded. Without that a change of the
                    // conversation partner would lay an old state over a new
                    // one.
                    if !slice.newer_than(applied) {
                        continue;
                    }
                    apply(paths, &slice)?;
                    // **The same application, a different sink** (ADR-0096): what
                    // `apply` writes into files goes into memory here.
                    introduction.absorb(&slice);
                    applied = slice.index;
                    // **The trace of the command that triggered this state**
                    // (ADR-0133, D4): the next pass hangs on it. A poisoned lock
                    // is taken over -- pure data lies here, and an observation
                    // must cost no reconciliation (ADR-0019).
                    slice.trace.clone_into(
                        &mut trace
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    );
                    tracing::info!(index = applied, "slice applied");

                    // **Reconcile now, not at the next stroke of the clock**
                    // (ADR-0076, determination 7). What has just arrived -- an
                    // active-role lease, a generation, a tombstone -- shall take
                    // effect without waiting for `--interval`.
                    reconcile_now.notify_one();

                    // **The tunnel follows the slice** (ADR-0039), and only it:
                    // the peer list changes nowhere else. A reconciliation per
                    // reconcile pass would be one netlink call per second for a
                    // list that stays the same for hours.
                    //
                    // **Fail-soft, and that is ADR-0019.** A node without a tunnel
                    // is no broken node; tearing the session down for it would
                    // take from it the way on which the remedy comes too. The next
                    // slice tries again.
                    match crate::underlay::reconcile(&paths.data_dir, &introduction.node) {
                        Ok(applied) => tracing::info!(
                            peers = applied.peers,
                            members = applied.members,
                            "underlay connected"
                        ),
                        Err(message) => tracing::warn!(%message, "no underlay"),
                    }

                    // **Level-triggered, like everything else here** (ADR-0010):
                    // if what the cluster knows about this node deviates, the
                    // announcement is not caught up at the next stroke of the
                    // clock but now. It travels on the renewal path (ADR-0042), so
                    // that is woken -- no second way and no listening port.
                    // **The rotation first** (ADR-0055): it can take over a
                    // pending key, and afterwards the announcement is a different
                    // one.
                    let announced = slice
                        .peers
                        .iter()
                        .find(|peer| Some(peer.node.as_str()) == introduction.announcement.as_ref().map(|a| a.node.as_str()))
                        .map(|peer| peer.key.clone());

                    match crate::rotate::underlay(
                        &paths.data_dir,
                        slice.generations.underlay,
                        announced.as_deref(),
                    ) {
                        Ok(crate::rotate::Done::Nothing) => {}
                        Ok(done) => tracing::info!(?done, "underlay key rotated"),
                        Err(message) => tracing::warn!(%message, "rotation not possible"),
                    }

                    // The identity key is only **filed** here; the confirmation is
                    // the server's yes to the renewal request that carries it
                    // (ADR-0055).
                    match crate::rotate::identity(&paths.data_dir, slice.generations.identity) {
                        Ok(crate::rotate::Done::Nothing) => {}
                        Ok(done) => {
                            tracing::info!(?done, "node key prepared");
                            // **The wake-up must stand here.** The comparison
                            // below sees only the underlay announcement; a new
                            // identity key changes nothing about it, and the
                            // rotation would wait until the next renewal -- so up
                            // to three hours.
                            wake.notify_one();
                        }
                        Err(message) => tracing::warn!(%message, "rotation not possible"),
                    }

                    if let Some(announcement) = introduction.announcement.as_ref()
                        && let Some(key) = crate::join::announced_key(&announcement.data_dir)
                        && !crate::join::announcement_is_current(
                            &slice.peers,
                            &announcement.node,
                            &key,
                            &announcement.endpoint,
                        )
                    {
                        tracing::info!(
                            node = %announcement.node,
                            "the underlay announcement is missing from the slice -- renewing"
                        );
                        wake.notify_one();
                    }
                }
                Some(Ok(ControlMessage::ForwardTo { leader })) => {
                    // **The referral is information** (ADR-0077): with a known
                    // leader it moves on at once; without one it waits, for then
                    // nobody is leading right now.
                    return Err(Ended {
                        message: match leader {
                            Some(id) => format!("this node does not lead; the leader is {id}"),
                            None => "this node does not lead and knows no leader".to_owned(),
                        },
                        next: crate::endpoints::next_after_referral(leader),
                    });
                }
                Some(Ok(ControlMessage::Refused { reason })) => return Err(reason.into()),
                Some(Err(err)) => return Err(err.to_string().into()),
                None => return Ok(()),
            },
            _ = ticker.tick() => {
                // **Discarded instead of waited for** (ADR-0068). An `.await` on
                // the channel stands here in the *body* of a branch: as long as it
                // hangs, `select!` has long chosen its branch, and `incoming` is no
                // longer polled -- the node would accept no slices any more
                // although they are already there, and thereby no lease renewal
                // either (ADR-0064).
                //
                // A report is a pure snapshot: `report` clones the observed state
                // and reads capacity, generations and proxy image; nothing is
                // consumed. The next ticker carries the same state, and fresher at
                // that -- queuing one would mean keeping an ageing snapshot.
                let message = report_message(paths, introduction, observed, applied);
                if offer(&sender, message) == Offer::Closed {
                    return Ok(());
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offer {
    Sent,
    Dropped,
    Closed,
}

fn offer(sender: &tokio::sync::mpsc::Sender<NodeMessage>, message: NodeMessage) -> Offer {
    match sender.try_send(message) {
        Ok(()) => Offer::Sent,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!(
                "report discarded: the session's outbound is backing up. The \
                 next one carries the same state."
            );
            Offer::Dropped
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Offer::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InstanceState, NodeMessage, Offer, Paths, observe, observed, offer, report, retired,
    };
    use tg_runtime::reconcile::{Instance, Report};

    #[test]
    fn a_full_channel_costs_the_report_and_not_the_session() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

        assert_eq!(
            offer(&sender, NodeMessage::Hello { applied: 1 }),
            Offer::Sent,
            "into an empty channel it goes"
        );
        assert_eq!(
            offer(&sender, NodeMessage::Hello { applied: 2 }),
            Offer::Dropped,
            "the channel is full -- the next ticker carries the same state"
        );

        // **And the first one lies in it intact.** Without this line a version
        // that replaces the waiting report when it fills up would be green too
        // -- and then what arrives would hang on the order of two tickers.
        assert!(matches!(
            receiver.try_recv(),
            Ok(NodeMessage::Hello { applied: 1 })
        ));

        drop(receiver);
        assert_eq!(
            offer(&sender, NodeMessage::Hello { applied: 3 }),
            Offer::Closed,
            "a closed channel is a tear, not a backlog"
        );
    }

    #[test]
    fn no_arm_of_the_session_loop_does_system_work() {
        let source = include_str!("session.rs");
        // The production part: in this file lies exactly **one**
        // `#[cfg(test)]`, and that at the end -- measured, because a cut at the
        // first one would otherwise lose everything after it.
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        // Comment lines away: the rationale above names the forbidden names
        // itself, and a guard that objects to its own explanation gets switched
        // off instead of read.
        let code: String = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            code.contains("tokio::select!"),
            "the guard does not read the session loop -- without it it says nothing"
        );

        let found: Vec<&str> = [
            ".delete(",
            ".snapshot(",
            ".provision(",
            ".mount(",
            ".unmount(",
            ".resize(",
            ".restore(",
            "orders::execute",
            "std::fs::copy",
        ]
        .into_iter()
        .filter(|name| code.contains(name))
        .collect();

        assert!(
            found.is_empty(),
            "system work in the arm of the session loop: {found:?} -- it halts \
             the report arm, and then every single writer of this node fences \
             itself (ADR-0110, determination 5). The execution belongs in \
             tg_runtime::orders and is called by the reconciler."
        );
    }

    fn slice(index: u64, document: &str) -> tg_store::session::NodeSlice {
        tg_store::session::NodeSlice {
            index,
            instances: vec![tg_store::session::Instance {
                workload: "api".to_owned(),
                instance: 0,
                document: document.to_owned(),
                generation: 0,
            }],
            ..tg_store::session::NodeSlice::default()
        }
    }

    fn valid() -> String {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20 </workload>\n\
         </workloads>\n"
            .to_owned()
    }

    #[test]
    fn a_slice_that_cannot_be_applied_leaves_no_marker() {
        let dir = tempfile::tempdir().expect("directory");
        let paths = super::Paths::new(dir.path());

        let refused = super::apply(&paths, &slice(7, "no XML"));
        assert!(refused.is_err(), "an unreadable document got through");
        assert!(
            !paths.applied().exists(),
            "the mark stands there although the slice was not applied"
        );

        super::apply(&paths, &slice(8, &valid())).expect("valid slice");
        assert_eq!(
            std::fs::read_to_string(paths.applied())
                .expect("mark")
                .trim(),
            "8"
        );
    }

    #[test]
    fn the_network_directory_is_sealed_but_its_files_are_not() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("directory");
        let paths = super::Paths::new(dir.path());

        super::apply(&paths, &slice(9, &valid())).expect("slice");

        let mode = |path: &std::path::Path| {
            std::fs::metadata(path).expect("there").permissions().mode() & 0o777
        };

        assert_eq!(mode(&paths.network()), 0o700);
        assert_ne!(
            mode(&paths.edges()) & 0o044,
            0,
            "the sidecar runs as 65532 and must be able to read the edges"
        );
    }

    fn empty_devices() -> std::collections::BTreeMap<String, u64> {
        std::collections::BTreeMap::new()
    }

    #[test]
    fn the_report_says_whether_this_node_maps() {
        let observed = observed();
        let paths = super::Paths::new(std::path::Path::new("/nowhere"));

        assert_eq!(
            report(&paths, &observed, 1, None, Some(100_000), &empty_devices()).userns,
            Some(100_000)
        );
        assert_eq!(
            report(&paths, &observed, 1, None, None, &empty_devices()).userns,
            None
        );
    }

    #[test]
    fn the_report_carries_the_real_instance_number() {
        let observed = observed();

        observe(
            &observed,
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                waiting: Vec::new(),
                fenced: Vec::new(),
                untouched: vec![Instance::new("api", 0), Instance::new("api", 2)],
                failed: vec![tg_runtime::reconcile::Failure {
                    instance: Instance::new("ledger", 1),
                    class: "runtime",
                    reason: "for the test".to_owned(),
                }],
                ..Report::default()
            },
            None,
        );

        let report = report(
            &super::Paths::new(std::path::Path::new("/nowhere")),
            &observed,
            42,
            None,
            None,
            &empty_devices(),
        );

        assert_eq!(report.applied, 42);
        assert_eq!(
            report.states,
            vec![
                ("api".to_owned(), 0, InstanceState::Running),
                ("api".to_owned(), 2, InstanceState::Running),
                ("ledger".to_owned(), 1, InstanceState::Failed),
            ]
        );
    }

    #[test]
    fn the_failure_class_travels_and_the_text_does_not() {
        let observed = observed();

        observe(
            &observed,
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                failed: vec![tg_runtime::reconcile::Failure {
                    instance: Instance::new("api", 1),
                    class: "pull",
                    reason: "registry.invalid/api:1 not reachable".to_owned(),
                }],
                ..Report::default()
            },
            None,
        );

        let report = report(
            &super::Paths::new(std::path::Path::new("/nowhere")),
            &observed,
            7,
            None,
            None,
            &empty_devices(),
        );

        assert_eq!(
            report.failures,
            vec![("api".to_owned(), 1, "pull".to_owned())],
            "the class does not travel along"
        );
        assert_eq!(
            report.states,
            vec![("api".to_owned(), 1, InstanceState::Failed)],
            "and the state stays standing beside it"
        );
        let wire = serde_json::to_string(&report).expect("encodable");
        assert!(
            !wire.contains("registry.invalid"),
            "the text must not leave the node: {wire}"
        );
    }

    #[test]
    fn an_isolated_entry_is_reported_without_a_state() {
        let observed = observed();

        observe(
            &observed,
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                untouched: vec![Instance::new("intact", 0)],
                isolated: vec!["broken".to_owned()],
                ..Report::default()
            },
            None,
        );

        let report = report(
            &super::Paths::new(std::path::Path::new("/nowhere")),
            &observed,
            7,
            None,
            None,
            &empty_devices(),
        );

        assert_eq!(report.isolated, vec!["broken".to_owned()]);
        assert_eq!(
            report.states,
            vec![("intact".to_owned(), 0, InstanceState::Running)],
            "an isolated entry must get no state"
        );
    }

    #[test]
    fn a_stale_instance_is_reported_and_still_counts_as_running() {
        let observed = observed();

        observe(
            &observed,
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                untouched: vec![Instance::new("api", 0), Instance::new("api", 1)],
                // As in the reconciler: `stale` is an annotation beside
                // `untouched`, no bucket of its own.
                stale: vec![Instance::new("api", 1)],
                ..Report::default()
            },
            None,
        );

        let report = report(
            &super::Paths::new(std::path::Path::new("/nowhere")),
            &observed,
            7,
            None,
            None,
            &empty_devices(),
        );

        assert_eq!(report.stale, vec![("api".to_owned(), 1)]);
        assert_eq!(
            report.states,
            vec![
                ("api".to_owned(), 0, InstanceState::Running),
                ("api".to_owned(), 1, InstanceState::Running),
            ],
            "stale means running (ADR-0070, determination 5)"
        );
    }

    #[test]
    fn an_unready_instance_is_reported_and_still_counts_as_running() {
        let observed = observed();

        observe(
            &observed,
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                untouched: vec![Instance::new("api", 0), Instance::new("api", 1)],
                // As in the reconciler: `unready` is an annotation beside
                // `untouched`, no bucket of its own (determination 2).
                unready: vec![Instance::new("api", 0)],
                ..Report::default()
            },
            None,
        );

        let report = report(
            &super::Paths::new(std::path::Path::new("/nowhere")),
            &observed,
            7,
            None,
            None,
            &empty_devices(),
        );

        assert_eq!(report.unready, vec![("api".to_owned(), 0)]);
        assert_eq!(
            report.states,
            vec![
                ("api".to_owned(), 0, InstanceState::Running),
                ("api".to_owned(), 1, InstanceState::Running),
            ],
            "unready means running (ADR-0080, determination 2)"
        );
    }

    #[test]
    fn each_bucket_maps_to_the_state_it_means() {
        let observed = observed();

        observe(
            &observed,
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                stale: Vec::new(),
                unready: Vec::new(),
                waiting: Vec::new(),
                fenced: Vec::new(),
                untouched: vec![Instance::new("a", 0)],
                reconciled: vec![Instance::new("b", 0)],
                deferred: vec![Instance::new("c", 0)],
                failed: vec![tg_runtime::reconcile::Failure {
                    instance: Instance::new("d", 0),
                    class: "runtime",
                    reason: "for the test".to_owned(),
                }],
                held: Vec::new(),
                isolated: Vec::new(),
                reaped: Vec::new(),
                own: std::collections::BTreeMap::new(),
                delegations: std::collections::BTreeMap::new(),
            },
            None,
        );

        let states = report(
            &super::Paths::new(std::path::Path::new("/nowhere")),
            &observed,
            1,
            None,
            None,
            &empty_devices(),
        )
        .states;
        assert_eq!(
            states,
            vec![
                ("a".to_owned(), 0, InstanceState::Running),
                ("b".to_owned(), 0, InstanceState::Running),
                ("c".to_owned(), 0, InstanceState::Stopped),
                ("d".to_owned(), 0, InstanceState::Failed),
            ]
        );
    }

    #[test]
    fn without_an_observation_the_report_is_empty() {
        let observed = observed();

        assert!(
            report(
                &super::Paths::new(std::path::Path::new("/nowhere")),
                &observed,
                7,
                None,
                None,
                &empty_devices()
            )
            .states
            .is_empty()
        );
    }

    #[test]
    fn a_new_run_replaces_the_previous_observation() {
        let observed = observed();

        observe(
            &observed,
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                waiting: Vec::new(),
                fenced: Vec::new(),
                untouched: vec![Instance::new("gone", 0)],
                ..Report::default()
            },
            None,
        );
        observe(
            &observed,
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                waiting: Vec::new(),
                fenced: Vec::new(),
                untouched: vec![Instance::new("there", 0)],
                ..Report::default()
            },
            None,
        );

        let states = report(
            &super::Paths::new(std::path::Path::new("/nowhere")),
            &observed,
            1,
            None,
            None,
            &empty_devices(),
        )
        .states;
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].0, "there");
    }

    #[test]
    fn only_a_volume_that_is_really_gone_counts_as_retired() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path());

        let store = tg_runtime::volume::VolumeStore::open(dir.path()).expect("store");
        store
            .declare("still-lies", tg_runtime::volume::MIN_BYTES)
            .expect("create");

        std::fs::create_dir_all(paths.tombstones().parent().expect("parent directory"))
            .expect("directory");
        std::fs::write(
            paths.tombstones(),
            serde_json::to_string(&["still-lies", "was-never-there"]).expect("encodable"),
        )
        .expect("write");

        assert_eq!(
            retired(&paths),
            vec!["was-never-there".to_owned()],
            "a volume that is still there must not count as executed"
        );
    }

    #[test]
    fn without_the_file_nothing_is_retired() {
        let dir = tempfile::tempdir().expect("tempdir");
        let said = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let lines = std::sync::Arc::clone(&said);

        let got = tracing::subscriber::with_default(collector(lines), || {
            retired(&Paths::new(dir.path()))
        });

        assert!(got.is_empty());
        // **And the normal case keeps quiet.** A message here would appear at
        // every report of a cluster without a deletion -- so every five seconds
        // (ADR-0068), and an operator would learn to read over it.
        assert!(
            said.lock().expect("not poisoned").is_empty(),
            "no tombstone is no finding"
        );
    }

    #[test]
    fn an_unreadable_tombstone_list_is_a_finding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path());
        std::fs::create_dir_all(paths.tombstones().parent().expect("parent")).expect("network/");
        // A **directory** in the file's place: reading that fails as `root` too,
        // and it is not `NotFound`.
        std::fs::create_dir(paths.tombstones()).expect("directory there");

        let said = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let lines = std::sync::Arc::clone(&said);
        let got = tracing::subscriber::with_default(collector(lines), || retired(&paths));

        assert!(got.is_empty(), "nothing reported stays the answer");
        let said = said.lock().expect("not poisoned").join("\n");
        assert!(
            said.contains("tombstones unreadable"),
            "a read error belongs named: {said}"
        );
    }

    #[test]
    fn the_active_instance_reaches_the_cache_and_comes_back() {
        let dir = tempfile::tempdir().expect("directory");
        let paths = Paths::new(dir.path());
        let desired = tg_runtime::state::DesiredState::open(dir.path()).expect("desired state");

        let mut promoted = slice(7, &valid());
        promoted.active_instances = vec![("api".to_owned(), 1)];
        super::apply(&paths, &promoted).expect("slice");
        assert_eq!(desired.active_instance("api"), 1);

        // Exactly one thing different: the decree is gone.
        super::apply(&paths, &slice(8, &valid())).expect("slice");
        assert_eq!(
            desired.active_instance("api"),
            0,
            "a withdrawn promotion must clear the file away"
        );
    }

    #[test]
    fn a_standby_node_gets_no_active_role() {
        let dir = tempfile::tempdir().expect("directory");
        let paths = Paths::new(dir.path());
        let now = tg_proxy::role::now_millis();

        // A standby node's slice: its instance runs, and the lease does not
        // stand in it.
        super::apply(&paths, &slice(7, &valid())).expect("slice");
        let text = std::fs::read_to_string(paths.roles()).expect("file");
        assert!(
            !tg_proxy::role::Roles::from_text(&text)
                .role_of("api", now)
                .is_active(),
            "the standby holds the role: '{text}'"
        );

        // **The counter-direction**, and it carries the first: on the holder
        // node the same line stands that the same sidecar reads -- without it a
        // parser that never finds a role would be green too, and no single
        // writer would ever get to talk.
        let mut holder = slice(8, &valid());
        holder.leases = vec![("api".to_owned(), 3, now + 15_000)];
        super::apply(&paths, &holder).expect("slice");
        let text = std::fs::read_to_string(paths.roles()).expect("file");
        assert!(
            tg_proxy::role::Roles::from_text(&text)
                .role_of("api", now)
                .is_active(),
            "the holder does not hold it: '{text}'"
        );
    }

    fn collector(
        sink: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> impl tracing::Subscriber + Send + Sync {
        use tracing_subscriber::layer::SubscriberExt as _;

        struct Collect(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Collect {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                struct Grab<'a>(&'a mut String);

                impl tracing::field::Visit for Grab<'_> {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        use std::fmt::Write as _;
                        let _ = write!(self.0, " {}={value:?}", field.name());
                    }
                }

                let mut line = String::new();
                event.record(&mut Grab(&mut line));
                if let Ok(mut all) = self.0.lock() {
                    all.push(line);
                }
            }
        }

        tracing_subscriber::registry().with(Collect(sink))
    }
}

#[cfg(test)]
mod mesh_udp_lines_tests {
    use super::{declares_mesh_udp, mesh_udp_lines};
    use tg_store::session::{Instance, NodeSlice, RemoteEndpoint};

    const WITH_UDP: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1.0"/>
    <mesh port="8080" udp="9000"/>
  </workload>
</workloads>"#;

    const WITHOUT_UDP: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1.0"/>
    <mesh port="8080"/>
  </workload>
</workloads>"#;

    fn slice(
        document: &str,
        edges: &[(&str, &str)],
        endpoints: &[(&str, u32, &str, bool)],
    ) -> NodeSlice {
        NodeSlice {
            instances: vec![Instance {
                workload: "api".to_owned(),
                instance: 0,
                document: document.to_owned(),
                generation: 0,
            }],
            edges: edges
                .iter()
                .map(|(from, to)| ((*from).to_owned(), (*to).to_owned()))
                .collect(),
            endpoints: endpoints
                .iter()
                .map(|(workload, instance, address, healthy)| RemoteEndpoint {
                    workload: (*workload).to_owned(),
                    instance: *instance,
                    address: address.parse().expect("address"),
                    healthy: *healthy,
                })
                .collect(),
            ..NodeSlice::default()
        }
    }

    #[test]
    fn a_workload_without_the_udp_port_gets_no_line() {
        assert!(!declares_mesh_udp(WITHOUT_UDP));
        assert_eq!(
            mesh_udp_lines(&slice(
                WITHOUT_UDP,
                &[("api", "ledger")],
                &[("ledger", 0, "10.42.1.5", true)]
            )),
            ""
        );
    }

    #[test]
    fn each_peer_gets_a_line_with_the_constant_port() {
        let lines = mesh_udp_lines(&slice(
            WITH_UDP,
            &[("api", "ledger"), ("api", "audit")],
            &[
                ("ledger", 0, "10.42.1.5", true),
                ("audit", 0, "10.42.2.7", true),
            ],
        ));

        assert_eq!(
            lines,
            format!(
                "api audit 10.42.2.7:{port} 15100\napi ledger 10.42.1.5:{port} 15101\n",
                port = tg_model::mesh::SIDECAR_MESH_UDP
            ),
            "one line per peer, sorted, with the fixed listening port"
        );
    }

    #[test]
    fn a_peer_without_an_endpoint_gets_no_line() {
        assert_eq!(
            mesh_udp_lines(&slice(WITH_UDP, &[("api", "ledger")], &[])),
            ""
        );
    }

    #[test]
    fn the_healthy_instance_comes_first() {
        let lines = mesh_udp_lines(&slice(
            WITH_UDP,
            &[("api", "ledger")],
            &[
                ("ledger", 0, "10.42.1.5", false),
                ("ledger", 1, "10.42.1.6", true),
            ],
        ));

        assert!(
            lines.contains("10.42.1.6"),
            "the healthy instance must win: {lines}"
        );
    }

    #[test]
    fn an_unreadable_document_means_no_udp() {
        assert!(!declares_mesh_udp("<no xml"));
    }
}
