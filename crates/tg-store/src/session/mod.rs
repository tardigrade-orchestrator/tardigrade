//! The path from the control plane to the node (ADR-0040).
//!
//! Three building sites had the same cause: the `may_talk` edges reached the
//! sidecar over a text file, the wanted state came from a locally written
//! directory, and the `WireGuard` peer list did not come at all. Here lies the
//! one path that serves all three.
//!
//! **The slice, and what it leaves out.** A node gets **its** slice: the
//! instances it shall carry, their definitions, the edges that touch them, the
//! underlay peers and its network parameters. Not: foreign leases, open
//! invitations, foreign capacities, definitions of workloads that run elsewhere.
//! A compromised node shall not be the cluster's blueprint (ADR-0040,
//! determination 5). The peer list is the express exception: a full mesh per
//! ADR-0012 means that every node knows every other.
//!
//! **The computation stands here and not in `tgd`.** [`slice_for`] takes a
//! [`ClusterView`] and no consensus state. The selection is thereby checkable
//! **without** `openraft` — and the `tg-agent`, which needs the types too, does
//! not link the consensus core. The same pattern as at `tg_identity::control`
//! (ADR-0037) and `tg_net::wireguard` (ADR-0039).
//!
//! **The stream is a refresh, not a dependency.** What arrives here lands in the
//! node's local, persisted state. The reconcile loop **never** reads from the
//! network. If the stream breaks, the node carries on with what it has
//! (ADR-0019) — and concludes **nothing** from the absence of messages:
//! withdrawals come as an explicit change, never as an absence.

pub mod transport;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tg_model::egress::Transport;
use tg_model::placement::Resources;

/// The lease deadline from ADR-0014, in seconds — **re-exported** from
/// `tg_model::lease`.
///
/// It lies there because the **rule** needs it (`role_of`) and `tg-model` cannot
/// read upwards. Until this re-export the number existed in effect four times; a
/// re-export is not a second source.
pub use tg_model::lease::LEASE_SECONDS;

/// How many format breaks this protocol carries since ADR-0072.
///
/// A format change is **no rolling update** (ADR-0072, determination 3): the
/// five nodes from ADR-0031 carry the failure of *one* node, a skew in the
/// format they do not. The manual names the order — all `tgd`, then all
/// `tg-agent` —, and the question an operator asks in the middle is **"am I
/// done?"**.
///
/// It was not answerable. A forgotten process is quiet, and within the window
/// everyone is quiet. Any information that ran over the **session** would be
/// exactly the one the skew is breaking: the only one that survives it is one
/// that does not travel over the broken format — i.e. a metric at every
/// process's Prometheus endpoint.
///
/// **The number of fields and not a version of its own.** An explicit protocol
/// version would be a second source and a discipline: whoever forgets to raise
/// it reports "all the same" while two versions run — a **false all-clear**, and
/// that is the more expensive direction. The field count needs no maintenance:
/// it stands in the types, and
/// `the_protocol_version_is_the_counted_number_of_breaks` in `tests/wire_form.rs`
/// records it.
///
/// **It is a lower bound:** a change of form without a new field does not count
/// (the egress entry went from a triple to a quadruple, ADR-0092).
///
/// `u32`, so that the metric arises from it without a cast (`f64::from`).
pub const PROTOCOL_FIELDS: u32 = 23;

/// How often a node reports when nothing changes (ADR-0040, determination 7).
///
/// The report is at the same time the sign of life: the leader renews the
/// active-role lease only for a node from which it currently has one (ADR-0064).
/// The cadence is thereby not a comfort value but the **sampling period of a
/// failure detector**, and it has to be markedly smaller than the window in
/// which a report counts.
///
/// **A third of the lease**, the same choice and the same rationale as with the
/// DNS TTL in phase 9a: every failover sees at least two samples.
pub const REPORT_EVERY_SECONDS: i64 = LEASE_SECONDS / 3;

/// How long a report marks the node as present (ADR-0064).
///
/// The ordering condition:
///
/// > `REPORT_EVERY_SECONDS` · 2 ≤ `REPORT_WINDOW_SECONDS` ≤ `LEASE_SECONDS`
///
/// **Upwards** the lease bounds it: a wider window would keep a dead holder's
/// lease alive beyond the deadline and delay the failover from ADR-0010 by
/// exactly the difference.
///
/// **Downwards** the report cadence bounds it: a window that holds only one
/// report is a detector without redundancy. The last report then always stands
/// exactly at the edge when idle, and a **single** dropout takes the node out of
/// the set for a full window width.
pub const REPORT_WINDOW_SECONDS: i64 = LEASE_SECONDS;

// The ordering condition, as a build assurance and not as a test: it is
// decidable at compile time, and whoever sets one of the three numbers wrong
// shall get no binary -- not a red run one can repeat.
const _: () = assert!(
    REPORT_EVERY_SECONDS * 2 <= REPORT_WINDOW_SECONDS,
    "the report window does not hold two reports: a single dropout would take \
     the node out of the set, and the single writer would lose its active role \
     because of a missed heartbeat instead of because of a partition"
);
const _: () = assert!(
    REPORT_WINDOW_SECONDS <= LEASE_SECONDS,
    "a window wider than the lease would keep a dead holder's lease alive \
     beyond the deadline and delay the failover"
);

/// The cluster's network parameters (ADR-0012, ADR-0039).
///
/// The same cluster-wide. Until ADR-0040 they stood as a setting at every node —
/// two nodes with different values computed different subnets without it
/// standing out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterNetwork {
    /// The address space of all containers.
    pub cidr: String,
    /// How much of it a node gets.
    pub node_prefix: u8,
}

/// A node in the underlay (ADR-0039).
///
/// The `AllowedIPs` expressly do **not** stand here: they follow from the
/// ordinal. Two sources for the same fact would be two opportunities to let them
/// diverge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnderlayPeer {
    /// Its name.
    pub node: String,
    /// Its ordinal.
    pub ordinal: u32,
    /// Its public X25519 key, base64.
    pub key: String,
    /// Its UDP endpoint.
    pub endpoint: String,
}

/// What a node reports about its instances' addresses (ADR-0073): workload,
/// instance, address.
///
/// Without health — that stands in the report beside it (`states`), and the
/// leader puts the two together. Carrying it a second time here would be two
/// opportunities to determine it differently.
pub type ReportedEndpoint = (String, u32, std::net::Ipv4Addr);

/// The endpoint of an instance that does **not** run on this node (ADR-0073).
///
/// ADR-0013 promises discovery as "name → healthy endpoints". Measured, it ended
/// at the node: the resolver's registry came from the **node-local** address
/// stock, and for a workload the cluster runs the node answered `NXDOMAIN`.
/// Container addresses are assigned node-locally (phase 9a, deliberately) and
/// stood in no message.
///
/// The address is **observed** state: the node that assigned it reports it
/// ([`NodeReport::endpoints`]), and the return direction of the session may
/// carry observed state (ADR-0040, determination 7). **Assignment** stays
/// node-local; consensus only transports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEndpoint {
    /// Which workload it belongs to.
    pub workload: String,
    /// Which instance.
    pub instance: u32,
    /// The address at which it is reachable.
    pub address: std::net::Ipv4Addr,
    /// Whether it is currently **running** (ADR-0013: resolve only healthy
    /// endpoints).
    ///
    /// An unhealthy endpoint travels **along** and is not left out: if it were
    /// missing, the answer would be `NXDOMAIN` instead of `NODATA`, and phase 9a
    /// made two answers out of that for good reason — a client that caches a
    /// negative result would otherwise stay blind until the instance runs again.
    pub healthy: bool,
}

/// An instance this node shall carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    /// The workload.
    pub workload: String,
    /// The serial number.
    pub instance: u32,
    /// The canonical definition document.
    pub document: String,
    /// Which **generation** of this declaration shall run (ADR-0071).
    ///
    /// It stands at the instance and not in a side list: the generation belongs
    /// to exactly this instance, and two lists would be two opportunities to
    /// assign it differently.
    ///
    /// `#[serde(default)]` as at `generations` and `leases` on the slice, and
    /// for the same reason: a node with a new state shall not abort at every
    /// slice against a server with an old one. The default zero means "nobody
    /// has decreed a restart".
    #[serde(default)]
    pub generation: u64,
}

/// The permissions that belong to a node's workloads.
///
/// **The only place at which least privilege happens in this path** (ADR-0040).
/// It stands on its own because `slice_for` would otherwise be over the line
/// limit — and because three selections with **three different rules** belong
/// together: one that bites in both directions, and two that do not.
fn permissions(view: &ClusterView, mine: &BTreeSet<&str>) -> Permissions {
    // An edge comes along if it touches a workload of this node — in **both**
    // directions. The target's sidecar needs it for enforcement (ADR-0025: the
    // server is authoritative), the sender's for connecting.
    let mut edges: Vec<(String, String)> = view
        .edges
        .iter()
        .filter(|(from, to)| mine.contains(from.as_str()) || mine.contains(to.as_str()))
        .cloned()
        .collect();
    edges.sort();
    edges.dedup();

    // **Not** in both directions: where a foreign workload may go is none of
    // this node's business.
    let mut egress: Vec<(String, String, u16, Transport)> = view
        .egress
        .iter()
        .filter(|(workload, _, _, _)| mine.contains(workload.as_str()))
        .cloned()
        .collect();
    egress.sort();
    egress.dedup();

    // And the secrets (ADR-0016) likewise — here the omission is even stricter
    // than with the edges: there the **name** of the counterpart has to come
    // along so that the sidecar can enforce. A foreign secret is under no
    // aspect this node's business.
    let mut secrets: Vec<(String, String, tg_identity::secrets::Sealed)> = view
        .secrets
        .iter()
        .filter(|(workload, _, _)| mine.contains(workload.as_str()))
        .cloned()
        .collect();
    // **Sorted by workload and name, not by value.** A ciphertext has no
    // meaningful ordering, and deriving `Ord` on it invites relying on it. The
    // pair is unique (`secret_grants` is a set), so the ordering is thereby
    // complete — and deterministic, as the slice has to be (ADR-0030).
    secrets.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    secrets.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);

    // **Only mappings whose secret arrives here anyway** (ADR-0096,
    // determination 2). The complete list would be a directory of the cluster's
    // private registries — information a node does not need, and that a
    // compromised one shall not have.
    let known: std::collections::BTreeSet<&str> =
        secrets.iter().map(|(_, name, _)| name.as_str()).collect();
    let mut registries: Vec<(String, String)> = view
        .registry_credentials
        .iter()
        .filter(|(_, secret)| known.contains(secret.as_str()))
        .cloned()
        .collect();
    registries.sort();
    registries.dedup();

    Permissions {
        edges,
        egress,
        secrets,
        registries,
    }
}

/// Which instance per own workload carries the active role (ADR-0111).
///
/// Extracted like [`permissions`] and for the same reason.
///
/// **The filter is a different one from the leases**, and that is this
/// function's whole statement. A lease is given only to its holder (ADR-0064,
/// determination 3). The **number** is also needed by the node whose instance is
/// *not* the active one: only from it does it recognize that it is a warm
/// standby and may run without a lease (ADR-0010). Without the entry it would
/// consider itself the designated active one and wait for a lease that never
/// comes — the workload would run **nowhere**.
///
/// Foreign ones stay out as everywhere (ADR-0040, determination 5): from the
/// number one could read off how many instances a foreign workload has.
fn active_instances(view: &ClusterView, mine: &BTreeSet<&str>) -> Vec<(String, u32)> {
    view.active_instances
        .iter()
        .filter(|(workload, _)| mine.contains(workload.as_str()))
        .map(|(workload, instance)| (workload.clone(), *instance))
        .collect()
}

/// The four selections from [`permissions`].
///
/// A named type and not a tuple: four lists that all consist of strings are not
/// to be told apart at a call site.
struct Permissions {
    edges: Vec<(String, String)>,
    egress: Vec<(String, String, u16, Transport)>,
    secrets: Vec<(String, String, tg_identity::secrets::Sealed)>,
    registries: Vec<(String, String)>,
}

/// What a node gets from the control plane.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSlice {
    /// The log index from which this slice stems.
    ///
    /// The projection is deterministic from the log (ADR-0030), so the index is
    /// the only sensible progress mark.
    pub index: u64,
    /// This node's ordinal; `None` as long as it is not admitted (ADR-0039).
    pub ordinal: Option<u32>,
    /// Which key generations this node shall have (ADR-0055).
    ///
    /// **Only its own.** Which generation a neighbour shall carry is none of
    /// this node's business — the same omission as with the egress permissions
    /// (ADR-0040).
    ///
    /// `#[serde(default)]`, and that is no formalism: without it a node with a
    /// new state aborts against a server with an old one — measured, at every
    /// slice. The default zero means "no rotation wanted".
    #[serde(default)]
    pub generations: tg_model::Generations,
    /// The `traceparent` of the command from which this state arose (ADR-0133).
    ///
    /// **Observation, not state:** it influences no decision, and an unreadable
    /// value costs a parent and not a pass (ADR-0019). `None` is the normal case
    /// — without an OTLP endpoint there is no trace.
    ///
    /// W3C format (`00-<32 hex>-<16 hex>-<2 hex>`), not one of our own: every
    /// tool of the ecosystem reads it.
    ///
    /// `#[serde(default)]` covers the direction "new agent, old server". The
    /// other is a **format break** and goes into the window from ADR-0072.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
    /// The network parameters, as soon as the cluster carries them.
    pub network: Option<ClusterNetwork>,
    /// This node's instances, sorted by name and number.
    pub instances: Vec<Instance>,
    /// The `may_talk` edges that touch one of these workloads (ADR-0025).
    pub edges: Vec<(String, String)>,
    /// The egress destinations of this node's workloads (ADR-0041).
    ///
    /// Workload, name, port. **Only its own** — where a foreign workload may go
    /// is none of this node's business.
    #[serde(default)]
    pub egress: Vec<(String, String, u16, Transport)>,
    /// The secrets this node's workloads may read (ADR-0016).
    ///
    /// Workload, name of the secret, **sealed** value. The plaintext lies
    /// nowhere in the cluster (ADR-0095); it is opened on the node that holds
    /// the data key.
    ///
    /// **Only its own**, and here without the exception `may_talk` has: with an
    /// edge the counterpart's name has to come along so that the sidecar can
    /// enforce (ADR-0025). A foreign workload's secret is under **no** aspect
    /// this node's business.
    #[serde(default)]
    pub secrets: Vec<(String, String, tg_identity::secrets::Sealed)>,
    /// Which secret applies to which registry (ADR-0096, determination 1).
    ///
    /// **Only mappings whose secret comes along above.** The complete list would
    /// be a directory of the cluster's private registries, and a node does not
    /// need that to pull its own image.
    #[serde(default)]
    pub registry_credentials: Vec<(String, String)>,
    /// All underlay peers.
    pub peers: Vec<UnderlayPeer>,
    /// The volumes this node shall delete (ADR-0027, ADR-0042).
    ///
    /// **Only its own**, as everything here. And expressly as a list and not as
    /// a conclusion from the absence of a name: from an absence a node may never
    /// conclude deletion (ADR-0040, determination 6). A workload can leave a
    /// node without its data being meant to go.
    #[serde(default)]
    pub deleted_volumes: Vec<String>,
    /// Which snapshot generation this node's volumes shall have (ADR-0099).
    ///
    /// **Only its own**, as everything here. The node compares every number with
    /// its mark beside the volume and makes a snapshot if it is lower —
    /// level-triggered, so a node that was away catches up on its return
    /// (ADR-0010).
    ///
    /// A **restore** does not stand here (ADR-0099, determination 6): it is
    /// destructive, and a decree that bites anew at every loss of the mark would
    /// be a data loss nobody sees coming.
    #[serde(default)]
    pub snapshot_generations: Vec<(String, u64)>,
    /// This node's active-role leases (ADR-0064): workload, epoch, deadline in
    /// milliseconds.
    ///
    /// **Only its own.** Who holds the active role elsewhere is none of this
    /// node's business — the same omission as with the egress permissions
    /// (ADR-0040).
    ///
    /// `#[serde(default)]` as at `generations`, and for the same reason. The
    /// empty list means "no active role".
    #[serde(default)]
    pub leases: Vec<(String, u64, u64)>,
    /// Which instance per workload carries the **active role** (ADR-0111).
    ///
    /// **Only its own workloads**, as everything here, and within them only the
    /// deviations: a missing entry means instance 0 (ADR-0064, determination 8).
    ///
    /// **On the slice and not on [`Instance`]**: with the generation the choice
    /// fell the other way, for a good reason — it belongs to exactly one
    /// instance. This number belongs to the **workload**, and the default
    /// decides. A `bool` on the instance would have to fall to `false` under
    /// `#[serde(default)]`, and that would mean "none is active": a server
    /// without this field would then let instance 0 start up without a lease
    /// (ADR-0064, determination 4).
    ///
    /// The node needs it to separate its two cases: the **designated active
    /// one** does not start up without a lease, the **warm standby** always runs
    /// (ADR-0010).
    #[serde(default)]
    pub active_instances: Vec<(String, u32)>,
    /// The endpoints this node's workloads **may dial** (ADR-0073).
    ///
    /// Filtered like the edges and the egress permissions: for every own
    /// workload `a` and every edge `a → b` the endpoints of `b`. **Only this
    /// direction** — whoever dials needs the address; the server checks at the
    /// certificate (ADR-0025) and does not need it. And **only foreign ones**:
    /// its own the node knows better, it assigned them.
    ///
    /// `#[serde(default)]` like the fields before it.
    #[serde(default)]
    pub endpoints: Vec<RemoteEndpoint>,
    /// The surcharge per mesh instance (ADR-0067), from which the node forms the
    /// limit of the derived sidecar (ADR-0086).
    ///
    /// **Not filtered**, unlike everything else here: the surcharge is the same
    /// number cluster-wide, there is no foreign half of it.
    ///
    /// `#[serde(default)]` like the fields before it — the empty map means "no
    /// surcharge", which is at the same time the default from ADR-0067.
    #[serde(default)]
    pub sidecar_overhead: Vec<(String, u64)>,
}

impl NodeSlice {
    /// Whether this slice is newer than the last applied one.
    ///
    /// ADR-0040, determination 4. Without this check a change of conversation
    /// partner could lay an old state over a new one — and the error would be
    /// silent.
    #[must_use]
    pub fn newer_than(&self, applied: u64) -> bool {
        self.index > applied
    }
}

/// An active-role lease as the view carries it (ADR-0010, ADR-0064).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Who holds the active role.
    pub holder: String,
    /// The fencing epoch.
    pub epoch: u64,
    /// First point in time at which it no longer applies, in milliseconds.
    pub expires_at: u64,
}

/// What the control plane needs in order to cut the slice.
///
/// Borrowed, simple data instead of consensus types: see the module header.
#[derive(Debug, Clone, Default)]
pub struct ClusterView {
    /// The log index of this view.
    pub index: u64,
    /// Workload, instance, node.
    pub placements: Vec<(String, u32, String)>,
    /// Workload → canonical document.
    pub documents: BTreeMap<String, String>,
    /// All `may_talk` edges.
    pub edges: Vec<(String, String)>,
    /// All egress permissions: workload, name, port (ADR-0041).
    pub egress: Vec<(String, String, u16, Transport)>,
    /// All read permissions including the sealed value (ADR-0016).
    pub secrets: Vec<(String, String, tg_identity::secrets::Sealed)>,
    /// All mappings `registry → secret` (ADR-0096).
    pub registry_credentials: Vec<(String, String)>,
    /// All underlay peers.
    pub peers: Vec<UnderlayPeer>,
    /// Node → deleted volumes (ADR-0042).
    pub deleted_volumes: BTreeMap<String, Vec<String>>,
    /// Node → volume → wanted snapshot generation (ADR-0099).
    pub snapshot_generations: BTreeMap<String, BTreeMap<String, u64>>,
    /// Which key generations shall apply per node (ADR-0055).
    pub generations: BTreeMap<String, tg_model::Generations>,
    /// Which generation of a declaration shall run per workload (ADR-0071).
    pub workload_generations: BTreeMap<String, tg_model::rollout::Generations>,
    /// Who does **not** belong to the data plane (ADR-0054).
    ///
    /// A set and not a map: the only question asked is "is this node detached".
    /// It stands beside the peers and not in them, because a node without an
    /// announcement can be detached too.
    pub detached: BTreeSet<String>,
    /// The active-role leases, by workload (ADR-0064).
    pub leases: BTreeMap<String, Lease>,
    /// Which instance per workload carries the active role (ADR-0111).
    ///
    /// **Only the deviations** — a missing entry means instance 0, the default
    /// from ADR-0064 determination 8.
    pub active_instances: BTreeMap<String, u32>,
    /// Node → ordinal.
    pub ordinals: BTreeMap<String, u32>,
    /// The network parameters, as soon as the cluster carries them.
    pub network: Option<ClusterNetwork>,
    /// The surcharge per mesh instance (ADR-0067), cluster-wide.
    ///
    /// It stands here because the **kernel** shall enforce it (ADR-0086): the
    /// planner has booked it since ADR-0067, and a sidecar without a limit takes
    /// all its node's workloads with it under the OOM killer (ADR-0019).
    ///
    /// The whole resource map and not only the memory: the booking is generic
    /// (ADR-0034), and **which** entry is enforced is a decision of the runtime
    /// layer — ADR-0086 enforces exactly one today and expressly **no** CFS
    /// quota.
    pub sidecar_overhead: Vec<(String, u64)>,
    /// Node → the endpoints it has reported (ADR-0073).
    ///
    /// The health is already resolved here: it stands in the same node's report
    /// (`states`), and `slice_for` thereby stays a pure function over **one**
    /// input instead of over two that have to match.
    pub endpoints: BTreeMap<String, Vec<RemoteEndpoint>>,
}

/// This node's instances, sorted by name and number.
///
/// Extracted from [`slice_for`] so that the **selection** stands there and not
/// also its construction.
fn instances_of(node: &str, view: &ClusterView) -> Vec<Instance> {
    let mut instances: Vec<Instance> = view
        .placements
        .iter()
        .filter(|(_, _, on)| on == node)
        .map(|(workload, instance, _)| Instance {
            workload: workload.clone(),
            instance: *instance,
            document: view.documents.get(workload).cloned().unwrap_or_default(),
            // The **effective** generation of this instance: the maximum of the
            // decree for all and the one for it alone (ADR-0071).
            generation: view
                .workload_generations
                .get(workload)
                .map_or(0, |generations| generations.wanted(*instance)),
        })
        .collect();
    instances.sort_by(|left, right| {
        left.workload
            .cmp(&right.workload)
            .then(left.instance.cmp(&right.instance))
    });
    instances
}

/// Cuts a node's slice (ADR-0040, determination 5).
///
/// A pure function: the same view yields the same slice, and the order of the
/// inputs does not change it. Without that the control plane would send a new
/// slice to every node at every change anywhere in the cluster.
#[must_use]
pub fn slice_for(node: &str, view: &ClusterView) -> NodeSlice {
    let instances = instances_of(node, view);

    // Which names run here — on that hangs which edges come along.
    let mine: BTreeSet<&str> = instances
        .iter()
        .map(|instance| instance.workload.as_str())
        .collect();

    let Permissions {
        edges,
        egress,
        secrets,
        registries,
    } = permissions(view, &mine);

    // **The half convergence from ADR-0054, determination 2**, and it needs no
    // participation from the detached node: the others stop calling it.
    //
    // A detached node, by contrast, sees **only itself** — enough for the
    // comparison of its announcement (ADR-0042), otherwise it would wake its
    // renewer endlessly because it would not find its own entry. And too little
    // for a tunnel: `wireguard::peers` leaves itself out, so the list in the
    // kernel stays empty.
    let mut peers: Vec<UnderlayPeer> = if view.detached.contains(node) {
        view.peers
            .iter()
            .filter(|peer| peer.node == node)
            .cloned()
            .collect()
    } else {
        view.peers
            .iter()
            .filter(|peer| !view.detached.contains(&peer.node))
            .cloned()
            .collect()
    };
    peers.sort_by(|left, right| left.node.cmp(&right.node));

    // This node's tombstones (ADR-0042). A volume lies on **one** node
    // (ADR-0027: writable means node-pinned), so the deletion goes exactly there
    // — and nowhere else.
    let mut deleted_volumes = view.deleted_volumes.get(node).cloned().unwrap_or_default();
    deleted_volumes.sort();
    deleted_volumes.dedup();

    // **Only its own** (ADR-0099). Which snapshots another node shall make is
    // none of this one's business -- and it could not make them anyway: a
    // writable volume lies on exactly one node (ADR-0027). Sorted, because the
    // slice has to look the same for the same content.
    let snapshot_generations: Vec<(String, u64)> = view
        .snapshot_generations
        .get(node)
        .map(|wanted| {
            wanted
                .iter()
                .map(|(volume, generation)| (volume.clone(), *generation))
                .collect()
        })
        .unwrap_or_default();

    // **Only its own lease** (ADR-0064, determination 3). Who holds the active
    // role elsewhere is none of this node's business.
    //
    // **The filter carries a second promise, and it weighs more:** it is what
    // reins in the sidecar of a warm standby (ADR-0066). That one cannot know
    // its instance -- `mesh::build` produces **one** definition with `replicas`,
    // all instances get the same command line (`--workload api`), and
    // `--single-writer` hangs on the class. The sidecar of instance 1 therefore
    // asks for the same name as that of instance 0.
    //
    // What separates them is this line alone: the grant goes to the node of
    // instance 0 (ADR-0064, determination 8), the standby node does not get the
    // lease, writes no line -- and `role_of` gives it no role. Whoever loosens
    // here because "where the writer sits is harmless, surely" takes that along:
    // then two sidecars serve for one single writer, and the standby writes into
    // **its own** volume (ADR-0027).
    //
    // The other half is guarded in `tg_agent::session`
    // (`a_standby_node_gets_no_active_role`): a slice without a lease really
    // yields no role.
    let leases: Vec<(String, u64, u64)> = view
        .leases
        .iter()
        .filter(|(_, lease)| lease.holder == node)
        .map(|(workload, lease)| (workload.clone(), lease.epoch, lease.expires_at))
        .collect();

    let active_instances = active_instances(view, &mine);

    // **The endpoints this node may dial** (ADR-0073).
    //
    // The same filter as with the edges, but **one-sided**: whoever dials needs
    // the address; the target checks at the certificate (ADR-0025) and does not
    // need it. And without its own — those this node assigned and knows better
    // (phase 9a); sending them along would be a second source for the same fact.
    let dialable: BTreeSet<&str> = view
        .edges
        .iter()
        .filter(|(from, _)| mine.contains(from.as_str()))
        .map(|(_, to)| to.as_str())
        .collect();
    let mut endpoints: Vec<RemoteEndpoint> = view
        .endpoints
        .iter()
        .filter(|(on, _)| on.as_str() != node)
        .flat_map(|(_, reported)| reported.iter())
        .filter(|endpoint| dialable.contains(endpoint.workload.as_str()))
        .cloned()
        .collect();
    endpoints.sort_by(|left, right| {
        left.workload
            .cmp(&right.workload)
            .then(left.instance.cmp(&right.instance))
    });

    NodeSlice {
        trace: None,
        index: view.index,
        ordinal: view.ordinals.get(node).copied(),
        generations: view.generations.get(node).copied().unwrap_or_default(),
        network: view.network.clone(),
        instances,
        edges,
        egress,
        secrets,
        registry_credentials: registries,
        peers,
        deleted_volumes,
        snapshot_generations,
        leases,
        active_instances,
        endpoints,
        // **Unfiltered**: the same number cluster-wide (ADR-0067).
        sidecar_overhead: view.sidecar_overhead.clone(),
    }
}

/// How an instance on the node is doing (ADR-0004: actual, eventual).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceState {
    /// Running.
    Running,
    /// Stopped.
    Stopped,
    /// Failed.
    Failed,
}

/// What a node reports about itself.
///
/// Goes into the leader's projection and **expressly not** into the log:
/// ADR-0004 calls actual "high-frequency, observational, without a need for
/// linearizability", and ADR-0020 retains the log. Status noise with a retention
/// period would be the opposite of a usable audit trail.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReport {
    /// The slice index this node last applied.
    pub applied: u64,
    /// The observed state per instance.
    pub states: Vec<(String, u32, InstanceState)>,
    /// Which running instances stem from an **older** declaration (ADR-0070,
    /// ADR-0071): workload and number.
    ///
    /// Observed state like [`Self::states`] — the node compares the digest in
    /// its bundle with the declaration it has, and only it can do that.
    /// ADR-0040 determination 7 permits exactly that in this direction: an
    /// observation, not a log entry.
    ///
    /// **Why it travels at all.** ADR-0070 makes the deviation visible, but the
    /// metric stands at the **node's** endpoint: an operator would have to query
    /// every node to find where a change is outstanding. Here it lands in the
    /// leader's projection and thereby in `tgctl cluster show`.
    ///
    /// The instance still counts as **running** — it stands in [`Self::states`]
    /// with `Running`. Stale is a piece of information, not a state beside it
    /// (ADR-0070, determination 5).
    #[serde(default)]
    pub stale: Vec<(String, u32)>,
    /// Which instances do not answer their readiness probe (ADR-0080).
    ///
    /// `RemoteEndpoint::healthy` is computed by the leader from the reported
    /// states (ADR-0073). Without this field a **foreign** node offered the
    /// address of an unready instance while its **own** withheld it — visibly
    /// different answers for the same name, depending on who asks. That was the
    /// cost side of ADR-0080 determination 8.
    ///
    /// The **reason** does not travel along: "refused" means "does not bind",
    /// "timeout" means "hangs", and both belong in the node's log.
    ///
    /// An unready instance stands **also** in [`Self::states`] with `Running`:
    /// it runs, it merely does not serve (determination 1).
    #[serde(default)]
    pub unready: Vec<(String, u32)>,
    /// The **class** of this node's failed reconciles (`RuntimeError::class`,
    /// ADR-0015).
    ///
    /// Workload, instance, class. It answers the first question in operation —
    /// *where* do I have to look: `pull`, `mount`, `volume`, `runtime`, … —, and
    /// it is **enumerable**: fifteen words that stand in the code.
    ///
    /// The **text** expressly does not travel along. It names names from a
    /// payload (an image reference, a URL), and a log is the place for that;
    /// here it would be an unbounded field in a message every report carries.
    ///
    /// The instance stands **also** in [`Self::states`] with `Failed`: the class
    /// is a piece of information, not a state beside it.
    #[serde(default)]
    pub failures: Vec<(String, u32, String)>,
    /// The entries this node has **isolated** (ADR-0062).
    ///
    /// An unreadable document, a doubly declared name, a self-reference or an
    /// ordering cycle: the node cannot classify them and leaves them alone —
    /// neither started nor stopped.
    ///
    /// ADR-0062 determination 6 says that **none of it happens silently**, and
    /// the node reports them per pass into its log. Only the **cluster** learned
    /// nothing of it: `observe` does not know the category, an isolated workload
    /// is thereby missing from `states`, and the leader reads "never seen" — the
    /// same as with a node that never reported.
    ///
    /// Observed state, no log entry (ADR-0040 determination 7 stays untouched).
    #[serde(default)]
    pub isolated: Vec<String>,
    /// What the node **has** in resources (ADR-0049).
    ///
    /// Observed state like [`Self::states`] — a fact about the machine only it
    /// knows. What of it is **usable** it does not decide: that is `desired`,
    /// stands in the log and arises from a policy (ADR-0004, ADR-0049).
    ///
    /// **It reaches the planner never.** It lands in the leader's projection;
    /// `placement::plan` gets exclusively numbers from the replicated state.
    /// Otherwise a new leader would come to a different result from the old one
    /// (ADR-0011), and a compromised node would attract every workload with an
    /// invented report (ADR-0037).
    #[serde(default)]
    pub capacity: Resources,
    /// Which key generations the node **carries** (ADR-0055, determination 5).
    ///
    /// Observed like [`Self::capacity`]: what shall apply is said by the log;
    /// what really lies on disk only the node knows. The difference is the
    /// metric — without it a rotation that does not arrive would stay invisible.
    ///
    /// It reaches **no** decision: it shows (ADR-0011).
    #[serde(default)]
    pub generations: tg_model::Generations,
    /// Which proxy image this node takes for its sidecars (ADR-0059).
    ///
    /// `None` means: it derives none — without `--proxy-image` there is no mesh
    /// on this node.
    ///
    /// ADR-0059 expressly makes the image a **setting per node** so that a
    /// rolling update stays an action per node — coming from the log, all would
    /// switch at once. The price stands there: *"an accidental deviation \[is\]
    /// invisible."* Exactly that is what this report fixes, and in the way
    /// ADR-0054 and ADR-0057 fixed the same situation: not through a decision
    /// but through **visibility**.
    ///
    /// `#[serde(default)]` like the two before it.
    #[serde(default)]
    pub proxy_image: Option<String>,
    /// The endpoints of the instances this node carries (ADR-0073).
    ///
    /// Observed state like [`Self::states`], and the **only** way on which a
    /// container address reaches the cluster: it is assigned node-locally
    /// (phase 9a), and only the node that assigned it knows it. The leader puts
    /// it into its projection, and the slice gives it to the nodes whose
    /// workloads may dial it.
    ///
    /// It reaches **no** decision: the planner sees exclusively the replicated
    /// state (ADR-0011).
    #[serde(default)]
    pub endpoints: Vec<ReportedEndpoint>,
    /// Which DNS zone this node serves (ADR-0013).
    ///
    /// `None` means: it serves no names — without a node network there is no
    /// resolver.
    ///
    /// Reported for the same reason as the proxy image (ADR-0059):
    /// `--dns-domain` is a setting per node, and a container always resolves at
    /// its **own** resolver. A bare name therefore works out even with a skew; a
    /// workload with a **fully qualified** name in its configuration then finds
    /// its target on one node and not on the other.
    ///
    /// Observed state — it reaches no decision.
    #[serde(default)]
    pub dns_zone: Option<String>,
    /// The range into which this node maps containers (ADR-0091).
    ///
    /// `None` means **no mapping**: `uid 0` in the container is `uid 0` on the
    /// node there. Reported because `--userns-base` is a setting per node — the
    /// same situation as with the proxy image (ADR-0059) and the DNS zone
    /// (ADR-0013), and the same answer: **visibility**, no decision.
    ///
    /// **Different ranges are no error** (ADR-0091: stores and volumes are
    /// node-local). What counts is the posture on/off: a node without a mapping
    /// beside nodes with one is a skew in the security posture, and nobody else
    /// sees it.
    ///
    /// Observed state — it reaches no decision.
    #[serde(default)]
    pub userns: Option<u32>,
    /// Which tombstones this node has **executed** (ADR-0104).
    ///
    /// Observed state like [`Self::states`]: the node asks its volume store
    /// whether an instructed deletion is done — it does not remember it
    /// (ADR-0058). The **leader** makes a `RetireTombstone` out of it, the same
    /// construction as with the capacity (ADR-0049) and the lease renewal
    /// (ADR-0064). ADR-0040 determination 7 stays untouched: here an observation
    /// travels, not a log entry.
    ///
    /// Without this report a tombstone disappears only when the same volume is
    /// declared again — the normal case would leave it forever, in every
    /// snapshot and in every slice to this node. A **deadline** would be the
    /// wrong answer: it would leave the data lying on a node that was away for a
    /// week while the cluster considers it deleted.
    ///
    /// `#[serde(default)]` like the fields before it.
    #[serde(default)]
    pub retired: Vec<String>,
}

/// What a node says on the stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeMessage {
    /// The first message: how far this node is.
    ///
    /// **Without a name**, and that is the core of ADR-0043: the server takes it
    /// from the connection's credential (ADR-0040, determination 8). Until then
    /// it stood here and was a self-declaration — whoever reached the port got
    /// an arbitrary node's slice.
    ///
    /// The field is gone **without replacement** and did not become optional: a
    /// name the server reads "just to be safe" is the same self-declaration with
    /// an intermediate step. A node that sends one is refused
    /// (`deny_unknown_fields`).
    Hello {
        /// Which slice index it last applied.
        applied: u64,
    },
    /// A status report.
    ///
    /// **Boxed**, like [`ControlMessage::Slice`] and for the same reason: the
    /// report is many times larger than `Hello`, and a variant that inflates the
    /// whole enum travels at that size through the channel at every `Hello`
    /// (ADR-0068: eight messages deep).
    Report(Box<NodeReport>),
}

/// What the control plane says on the stream.
///
/// **Strict like the opposite direction** (ADR-0072). Here `deny_unknown_fields`
/// was missing as the only one of the session types, and the asymmetry had no
/// rationale. It does not weigh much as long as the payload itself is strict
/// ([`NodeSlice`]), but the two variants with fields — `ForwardTo` and `Refused`
/// — were lenient: a future `Refused { reason, code }` an old agent would have
/// read while discarding the `code`. Exactly that kind of silent half
/// understanding ADR-0072 rejects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlMessage {
    /// A new slice.
    Slice(Box<NodeSlice>),
    /// This node does not lead — the session belongs to the leader.
    ForwardTo {
        /// The known leader, as far as this node knows one.
        leader: Option<u64>,
    },
    /// Refused, with a reason.
    Refused {
        /// Why.
        reason: String,
    },
}

/// A node's client.
///
/// It establishes the stream — the control plane never calls (ADR-0040,
/// determination 2). With that no agent needs a listening port.
#[derive(Debug, Clone)]
pub struct SessionClient {
    channel: tonic::transport::Channel,
}

impl SessionClient {
    /// Takes a ready-built channel.
    ///
    /// The seam for mTLS (ADR-0043): `tg-store` knows neither `rustls` nor
    /// SPIFFE, and it shall not know them — the selection in [`slice_for`] is
    /// pure logic and is checked without an identity layer. Whoever presents the
    /// credential is the `tg-agent`; there it lies.
    #[must_use]
    pub fn with_channel(channel: tonic::transport::Channel) -> Self {
        Self { channel }
    }

    /// Opens the session.
    ///
    /// # Errors
    ///
    /// [`tonic::Status`] if the call fails. A **referral to the leader** is not
    /// an error but a [`ControlMessage`] in the stream.
    pub async fn open<S>(
        &self,
        outgoing: S,
    ) -> Result<tonic::Streaming<ControlMessage>, tonic::Status>
    where
        S: futures_util::Stream<Item = NodeMessage> + Send + 'static,
    {
        let mut client = tg_wire::client(self.channel.clone());
        client
            .ready()
            .await
            .map_err(|err| tonic::Status::unavailable(err.to_string()))?;

        client
            .streaming(
                tonic::Request::new(outgoing),
                http::uri::PathAndQuery::from_static(transport::SESSION),
                transport::JsonCodec::<NodeMessage, ControlMessage>::default(),
            )
            .await
            .map(tonic::Response::into_inner)
    }
}
