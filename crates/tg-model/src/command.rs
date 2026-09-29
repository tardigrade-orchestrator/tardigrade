//! The log's command set: what an entry in the Raft log is.
//!
//! ADR-0004 draws the boundary, this module traces it. Two layers belong in the
//! log, one expressly does not:
//!
//! - **Desired state** — workload definitions including the dependency graph,
//!   `may_talk` edges (ADR-0025), topology (ADR-0011).
//! - **Consensus-critical cluster state** — placement assignments, active-role
//!   leases with a fencing epoch (ADR-0010), trust registration
//!   (ADR-0006/0014).
//! - **Not in the log: actual status.** "running/crashed, health, metrics, last
//!   seen" are high-frequency and need no linearizability. They go directly
//!   into the projection (`tg-store`). Were that to come in here, every
//!   heartbeat would be a consensus round.
//!
//! **Membership is deliberately missing.** ADR-0004 names it as log content,
//! and it *is* in the log — only not as our command: `openraft` carries it over
//! `EntryPayload::Membership`. A command of our own beside it would be a
//! second, competing source for the same truth.
//!
//! **On the wire format.** Per ADR-0020 the log is the audit substrate with a
//! retention obligation: what is written today has to be readable in years.
//! That is why the encoding is JSON — readable without our binary, which makes
//! the difference for an auditor — and that is why it is nailed down character
//! for character in `tests/command_set.rs`.

use crate::egress::Transport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UtcMillis(u64);

impl UtcMillis {
    #[must_use]
    pub const fn new(millis: u64) -> Self {
        Self(millis)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub log_index: u64,
    pub term: u64,
    pub command: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<serde_json::Value>,
}

pub type NodeId = u64;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Epoch(u64);

impl Epoch {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

pub use crate::Topology;

pub use crate::Resources;

pub use crate::{Attachment, Generations, KeyKind, RotationPolicy, Schedulability};

pub use crate::capacity::{CapacityPolicy, Rule as CapacityRule};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    DesiredState,
    ClusterState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Read,
    Secrets,
    Write,
    Membership,
    Operators,
}

impl Class {
    pub const ALL: [Self; 5] = [
        Self::Read,
        Self::Secrets,
        Self::Write,
        Self::Membership,
        Self::Operators,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Secrets => "secrets",
            Self::Write => "write",
            Self::Membership => "membership",
            Self::Operators => "operators",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.name() == name)
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

fn all_classes() -> Vec<Class> {
    Class::ALL.to_vec()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    UpsertWorkload {
        document: String,
    },
    RemoveWorkload {
        name: String,
    },
    AllowTraffic {
        from: String,
        to: String,
    },
    RevokeTraffic {
        from: String,
        to: String,
    },

    AllowEgress {
        workload: String,
        host: String,
        port: u16,
        #[serde(default)]
        transport: Transport,
    },

    PutSecret {
        name: String,
        value: crate::secrets::Sealed,
    },

    RemoveSecret {
        name: String,
    },

    AllowSecret {
        workload: String,
        secret: String,
    },

    RevokeSecret {
        workload: String,
        secret: String,
    },

    SetRegistryCredential {
        registry: String,
        secret: String,
    },

    ClearRegistryCredential {
        registry: String,
    },

    RevokeEgress {
        workload: String,
        host: String,
        port: u16,
        #[serde(default)]
        transport: Transport,
    },
    UpsertNode {
        name: String,
        topology: Topology,
        #[serde(default)]
        capacity: Resources,
        #[serde(default)]
        reserved: Resources,
        #[serde(default)]
        source: Origin,
    },
    SetCapacityPolicy {
        policy: CapacityPolicy,
    },
    SetSchedulability {
        node: String,
        mode: Schedulability,
    },
    SetAttachment {
        node: String,
        mode: Attachment,
    },
    SetKeyGeneration {
        node: String,
        kind: KeyKind,
        generation: u64,
    },
    SetWorkloadGeneration {
        workload: String,
        instance: Option<u32>,
        generation: u64,
    },
    SetRotationPolicy {
        policy: RotationPolicy,
    },
    RemoveNode {
        name: String,
    },
    AssignPlacement {
        workload: String,
        #[serde(default)]
        instance: u32,
        node: String,
    },
    ClearPlacement {
        workload: String,
    },
    GrantLease {
        workload: String,
        node: String,
        now: UtcMillis,
        expires_at: UtcMillis,
    },
    RenewLease {
        workload: String,
        node: String,
        now: UtcMillis,
        expires_at: UtcMillis,
    },
    SetActiveInstance {
        workload: String,
        instance: u32,
    },
    InviteNode {
        node: String,
        digest: String,
        expires_at: i64,
    },
    AdmitNode {
        node: String,
        spki: String,
        at: i64,
    },

    AnnounceUnderlay {
        node: String,
        key: String,
        endpoint: String,
        at: i64,
    },

    SetClusterNetwork {
        cidr: String,
        node_prefix: u8,
    },

    SetSidecarOverhead {
        resources: Resources,
    },

    DeleteVolume {
        volume: String,
        node: String,
        at: i64,
    },
    RetireTombstone {
        volume: String,
        node: String,
    },
    SnapshotVolume {
        volume: String,
        node: String,
        generation: u64,
    },
    EnrolOperator {
        operator: String,
        spki: String,
        #[serde(default = "all_classes")]
        classes: Vec<Class>,
    },
    RevokeOperator {
        operator: String,
    },
    RegisterTrust {
        node: String,
        bundle: String,
    },
    RotateTrust {
        node: String,
        from: String,
        to: String,
    },
    RevokeTrust {
        node: String,
    },
}

impl Command {
    pub const KINDS: [(&'static str, Layer); 38] = [
        ("upsert_workload", Layer::DesiredState),
        ("remove_workload", Layer::DesiredState),
        ("allow_traffic", Layer::DesiredState),
        ("revoke_traffic", Layer::DesiredState),
        ("allow_egress", Layer::DesiredState),
        ("revoke_egress", Layer::DesiredState),
        // A secret and who may read it: desired state (ADR-0004, ADR-0016). A
        // plaintext **never** stands in the log (ADR-0020, ADR-0095).
        ("put_secret", Layer::DesiredState),
        ("remove_secret", Layer::DesiredState),
        ("allow_secret", Layer::DesiredState),
        ("revoke_secret", Layer::DesiredState),
        ("set_registry_credential", Layer::DesiredState),
        ("clear_registry_credential", Layer::DesiredState),
        ("upsert_node", Layer::DesiredState),
        ("remove_node", Layer::DesiredState),
        ("assign_placement", Layer::ClusterState),
        ("clear_placement", Layer::ClusterState),
        ("grant_lease", Layer::ClusterState),
        ("renew_lease", Layer::ClusterState),
        ("invite_node", Layer::ClusterState),
        ("admit_node", Layer::ClusterState),
        ("register_trust", Layer::ClusterState),
        ("rotate_trust", Layer::ClusterState),
        ("revoke_trust", Layer::ClusterState),
        ("announce_underlay", Layer::ClusterState),
        ("set_schedulability", Layer::DesiredState),
        ("set_attachment", Layer::DesiredState),
        ("set_key_generation", Layer::DesiredState),
        ("set_workload_generation", Layer::DesiredState),
        // **Who carries the active role is desired state** (ADR-0111): a
        // decree of an operator like `set_schedulability`, not the result of an
        // election. The lease above it stays `ClusterState`.
        ("set_active_instance", Layer::DesiredState),
        ("set_capacity_policy", Layer::DesiredState),
        ("set_rotation_policy", Layer::DesiredState),
        ("set_cluster_network", Layer::DesiredState),
        ("set_sidecar_overhead", Layer::DesiredState),
        ("delete_volume", Layer::DesiredState),
        ("snapshot_volume", Layer::DesiredState),
        // The **execution** of a tombstone: desired state like the deletion
        // itself (ADR-0104). What *has* happened stands beside it in the log as
        // `delete_volume` -- the entry here clears the instruction away.
        ("retire_tombstone", Layer::DesiredState),
        // A registration is a **decree of an operator** about who may
        // administer -- desired state, like `upsert_node` and
        // `set_capacity_policy` (ADR-0004 counts topology as desired state).
        ("enrol_operator", Layer::DesiredState),
        ("revoke_operator", Layer::DesiredState),
    ];

    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::UpsertWorkload { .. } => "upsert_workload",
            Self::RemoveWorkload { .. } => "remove_workload",
            Self::AllowTraffic { .. } => "allow_traffic",
            Self::RevokeTraffic { .. } => "revoke_traffic",
            Self::AllowEgress { .. } => "allow_egress",
            Self::RevokeEgress { .. } => "revoke_egress",
            Self::PutSecret { .. } => "put_secret",
            Self::RemoveSecret { .. } => "remove_secret",
            Self::AllowSecret { .. } => "allow_secret",
            Self::RevokeSecret { .. } => "revoke_secret",
            Self::SetRegistryCredential { .. } => "set_registry_credential",
            Self::ClearRegistryCredential { .. } => "clear_registry_credential",
            Self::UpsertNode { .. } => "upsert_node",
            Self::SetCapacityPolicy { .. } => "set_capacity_policy",
            Self::SetRotationPolicy { .. } => "set_rotation_policy",
            Self::SetSchedulability { .. } => "set_schedulability",
            Self::SetAttachment { .. } => "set_attachment",
            Self::SetKeyGeneration { .. } => "set_key_generation",
            Self::SetWorkloadGeneration { .. } => "set_workload_generation",
            Self::RemoveNode { .. } => "remove_node",
            Self::AssignPlacement { .. } => "assign_placement",
            Self::ClearPlacement { .. } => "clear_placement",
            Self::GrantLease { .. } => "grant_lease",
            Self::RenewLease { .. } => "renew_lease",
            Self::SetActiveInstance { .. } => "set_active_instance",
            Self::InviteNode { .. } => "invite_node",
            Self::AdmitNode { .. } => "admit_node",
            Self::RegisterTrust { .. } => "register_trust",
            Self::RotateTrust { .. } => "rotate_trust",
            Self::RevokeTrust { .. } => "revoke_trust",
            Self::AnnounceUnderlay { .. } => "announce_underlay",
            Self::SetClusterNetwork { .. } => "set_cluster_network",
            Self::SetSidecarOverhead { .. } => "set_sidecar_overhead",
            Self::DeleteVolume { .. } => "delete_volume",
            Self::RetireTombstone { .. } => "retire_tombstone",
            Self::SnapshotVolume { .. } => "snapshot_volume",
            Self::EnrolOperator { .. } => "enrol_operator",
            Self::RevokeOperator { .. } => "revoke_operator",
        }
    }

    #[must_use]
    pub const fn class(&self) -> Class {
        match self {
            // **The operator administration is a class of its own.** Were
            // these two to lie in `write`, its holder could enter a second
            // registration with every class or withdraw every other one — then
            // `write` is not one class but `admin` (ADR-0105).
            Self::EnrolOperator { .. } | Self::RevokeOperator { .. } => Class::Operators,

            // **There is no membership command.** `Class::Membership`
            // therefore hangs on the path alone (`MembershipChange` is a type
            // of the admin service and does not go through the log — `openraft`
            // writes the change itself). Measured, not assumed: of the 38
            // variants none carries it.

            // **Everything else is `write`.** Written out and not as a `_` arm:
            // the compiler shall ask at the next command.
            Self::UpsertWorkload { .. }
            | Self::RemoveWorkload { .. }
            | Self::AllowTraffic { .. }
            | Self::RevokeTraffic { .. }
            | Self::AllowEgress { .. }
            | Self::PutSecret { .. }
            | Self::RemoveSecret { .. }
            | Self::AllowSecret { .. }
            | Self::RevokeSecret { .. }
            | Self::SetRegistryCredential { .. }
            | Self::ClearRegistryCredential { .. }
            | Self::RevokeEgress { .. }
            | Self::UpsertNode { .. }
            | Self::SetCapacityPolicy { .. }
            | Self::SetSchedulability { .. }
            | Self::SetAttachment { .. }
            | Self::SetKeyGeneration { .. }
            | Self::SetWorkloadGeneration { .. }
            | Self::SetRotationPolicy { .. }
            | Self::RemoveNode { .. }
            | Self::AssignPlacement { .. }
            | Self::ClearPlacement { .. }
            | Self::GrantLease { .. }
            | Self::RenewLease { .. }
            | Self::SetActiveInstance { .. }
            | Self::InviteNode { .. }
            | Self::AdmitNode { .. }
            | Self::AnnounceUnderlay { .. }
            | Self::SetClusterNetwork { .. }
            | Self::SetSidecarOverhead { .. }
            | Self::DeleteVolume { .. }
            | Self::RetireTombstone { .. }
            | Self::SnapshotVolume { .. }
            | Self::RegisterTrust { .. }
            | Self::RotateTrust { .. }
            | Self::RevokeTrust { .. } => Class::Write,
        }
    }

    #[must_use]
    pub const fn retired(&self) -> Option<&'static str> {
        match self {
            // Placements are cleared away by `RemoveWorkload`. It **never** had
            // a producer (measured against the history); it would therefore be
            // removable, but `8e1664b` nailed it down as a literal in
            // `a_command_kind_can_never_be_removed`, and this list is
            // append-only like what it protects.
            Self::ClearPlacement { .. } => {
                Some("placements are cleared away by `RemoveWorkload` (ADR-0112)")
            }
            // **The case with weight.** ADR-0055 removed the producer and put
            // `RotateTrust` in its place -- a compare-and-set instead of an
            // unconditional write. The capability stayed open: whoever reaches
            // the admin service with `Class::Write` enters node trust and goes
            // past the one-time, consensus-checked gate from ADR-0037.
            Self::RegisterTrust { .. } => Some(
                "trust is entered with the invitation (ADR-0037) and changed \
                 with `RotateTrust` (ADR-0055)",
            ),

            // **Everything else is in use.** Written out and not as a `_` arm:
            // the compiler shall ask at the next command.
            Self::UpsertWorkload { .. }
            | Self::RemoveWorkload { .. }
            | Self::AllowTraffic { .. }
            | Self::RevokeTraffic { .. }
            | Self::AllowEgress { .. }
            | Self::RevokeEgress { .. }
            | Self::PutSecret { .. }
            | Self::RemoveSecret { .. }
            | Self::AllowSecret { .. }
            | Self::RevokeSecret { .. }
            | Self::SetRegistryCredential { .. }
            | Self::ClearRegistryCredential { .. }
            | Self::UpsertNode { .. }
            | Self::SetCapacityPolicy { .. }
            | Self::SetRotationPolicy { .. }
            | Self::SetSchedulability { .. }
            | Self::SetAttachment { .. }
            | Self::SetKeyGeneration { .. }
            | Self::SetWorkloadGeneration { .. }
            | Self::SetActiveInstance { .. }
            | Self::RemoveNode { .. }
            | Self::AssignPlacement { .. }
            | Self::GrantLease { .. }
            | Self::RenewLease { .. }
            | Self::InviteNode { .. }
            | Self::AdmitNode { .. }
            | Self::RotateTrust { .. }
            | Self::RevokeTrust { .. }
            | Self::AnnounceUnderlay { .. }
            | Self::SetClusterNetwork { .. }
            | Self::SetSidecarOverhead { .. }
            | Self::DeleteVolume { .. }
            | Self::RetireTombstone { .. }
            | Self::SnapshotVolume { .. }
            | Self::EnrolOperator { .. }
            | Self::RevokeOperator { .. } => None,
        }
    }

    #[must_use]
    pub const fn may_be_policy(&self) -> bool {
        match self {
            // **Permitted are exactly the three decided cases** — ADR-0049
            // (capacity), ADR-0055/0057 (key generation) and ADR-0104 (the
            // execution of a tombstone). Not "everything that looks harmless":
            // permitted here means **decided**.
            //
            // `UpsertNode` carries the topology too. The policy as built writes
            // it back unchanged from the existing entry (ADR-0049) — it does
            // **not** change it, and that is how it belongs.
            //
            // `RetireTombstone` satisfies ADR-0057's criterion: the input is a
            // **present report**. A node that fails reports nothing — and then
            // nothing is cleared away; the outage does not produce the decree,
            // it prevents it. And the effect is not destructive: what is
            // cleared away is an instruction that has already been carried
            // out.
            Self::UpsertNode { .. }
            | Self::SetKeyGeneration { .. }
            | Self::RetireTombstone { .. } => true,

            // **Everything else: no.** The rationales, in groups:
            //
            // Placing, displacing and leases are the planner and the fencing
            // (ADR-0011, ADR-0010).
            Self::AssignPlacement { .. }
            | Self::ClearPlacement { .. }
            | Self::GrantLease { .. }
            | Self::RenewLease { .. }
            // **A policy does not promote** (ADR-0111, determination 2). The
            // only input from which a program would want to derive a promotion
            // is the holder's **silence** -- and silence is exactly what an
            // outage produces (ADR-0057, determination 3). The same rationale
            // from which auto-detach is permanently refused (ADR-0054), and the
            // same as against auto-rebalancing (ADR-0011).
            | Self::SetActiveInstance { .. }
            // **A policy restarts nothing** (ADR-0071). A restart is
            // disruptive, and the order lies with the human, because there is
            // no health gate per workload — a program that chose it could not
            // check the outcome.
            | Self::SetWorkloadGeneration { .. }
            // Trust is a security action; admission and striking off are human
            // decrees (ADR-0037, ADR-0039). What the identity service writes on
            // a node's say-so is no policy — it carries no `Origin::Policy`
            // (ADR-0042/0050).
            | Self::InviteNode { .. }
            | Self::AdmitNode { .. }
            | Self::RegisterTrust { .. }
            | Self::RotateTrust { .. }
            | Self::RevokeTrust { .. }
            | Self::RemoveNode { .. }
            | Self::AnnounceUnderlay { .. }
            // Definitions and authorization are declared by a human. A policy
            // that could hand out edges or egress targets would be a hole in
            // deny-by-default (ADR-0025, ADR-0041).
            | Self::UpsertWorkload { .. }
            | Self::RemoveWorkload { .. }
            | Self::AllowTraffic { .. }
            | Self::RevokeTraffic { .. }
            | Self::AllowEgress { .. }
            | Self::RevokeEgress { .. }
            // **And no program decrees a snapshot** (ADR-0099,
            // determination 5). A cadence would be admissible per ADR-0057 --
            // the clock is an input an outage does not produce --, but a
            // snapshot consumes room on a disk the leader does not know, and
            // ADR-0027 names no cadence.
            | Self::SnapshotVolume { .. }
            // **No program decrees a secret.** Whoever files or permits one is
            // a human — and the declaration stands in the audit trail
            // (ADR-0016, ADR-0050).
            | Self::PutSecret { .. }
            | Self::RemoveSecret { .. }
            | Self::AllowSecret { .. }
            | Self::RevokeSecret { .. }
            // Which secret applies for a registry is likewise a decree
            // (ADR-0096).
            | Self::SetRegistryCredential { .. }
            | Self::ClearRegistryCredential { .. }
            | Self::SetClusterNetwork { .. }
            | Self::SetSidecarOverhead { .. }
            // Deleting data demands an express action (ADR-0027).
            | Self::DeleteVolume { .. }
            // **Cordoning and detaching: structurally no.** ADR-0057
            // determination 3 refuses auto-detach over the *input* (absence);
            // here it is refused over the *command*, and that is the stronger
            // assurance: it cannot be built without touching this list — and
            // whoever touches it has the conversation.
            | Self::SetSchedulability { .. }
            | Self::SetAttachment { .. }
            // **A policy changes no policy.** Otherwise it could extend its own
            // authority.
            | Self::SetCapacityPolicy { .. }
            // **No program decides who may administer.** A policy that could
            // register an operator would extend its own authority -- the same
            // reason why `SetCapacityPolicy` stands here (ADR-0057).
            | Self::EnrolOperator { .. }
            | Self::RevokeOperator { .. }
            | Self::SetRotationPolicy { .. } => false,
        }
    }

    #[must_use]
    pub fn layer(&self) -> Layer {
        match self {
            Self::UpsertWorkload { .. }
            | Self::RemoveWorkload { .. }
            | Self::AllowTraffic { .. }
            | Self::RevokeTraffic { .. }
            | Self::AllowEgress { .. }
            | Self::RevokeEgress { .. }
            // A secret and who may read it are **desired state** (ADR-0004,
            // ADR-0016): an operator declares them.
            | Self::PutSecret { .. }
            | Self::RemoveSecret { .. }
            | Self::AllowSecret { .. }
            | Self::RevokeSecret { .. }
            // And which secret applies for a registry (ADR-0096).
            | Self::SetRegistryCredential { .. }
            | Self::ClearRegistryCredential { .. }
            | Self::UpsertNode { .. }
            | Self::RemoveNode { .. }
            // A setting of the operator, not an observation (ADR-0040).
            | Self::SetClusterNetwork { .. }
            // Likewise: what a sidecar costs is declared by an operator;
            // measured, it would be eventual and would make the planner
            // non-deterministic (ADR-0067, ADR-0049).
            | Self::SetSidecarOverhead { .. }
            // Both are **decrees of an operator about nodes** and thereby
            // belong where `upsert_node` stands: ADR-0004 counts "topology" as
            // desired state. They stood at ClusterState at first — that was
            // wrong and is corrected here.
            | Self::SetSchedulability { .. }
            // And for the same reason: detach is a decree about a node, no
            // observation (ADR-0054).
            | Self::SetAttachment { .. }
            // And likewise: which key generation shall apply is decreed by an
            // operator (ADR-0055).
            | Self::SetKeyGeneration { .. }
            // And likewise: **when** a declaration takes effect is decreed by
            // an operator (ADR-0071). The declaration itself is
            // `upsert_workload` and stands above; the generation is the second
            // half of the same pair.
            | Self::SetWorkloadGeneration { .. }
            | Self::SetCapacityPolicy { .. }
            // And likewise: how often rotation happens is decreed by an
            // operator (ADR-0057).
            | Self::SetRotationPolicy { .. }
            | Self::DeleteVolume { .. }
            // And its execution (ADR-0104): that a volume is gone is desired
            // state like the deletion itself.
            | Self::RetireTombstone { .. }
            // And likewise: **when** a snapshot arises is decreed by an
            // operator (ADR-0099).
            | Self::SnapshotVolume { .. }
            // A registration is a decree of an operator about who may
            // administer -- desired state like `upsert_node` (ADR-0004 counts
            // topology as such), not an observed one.
            | Self::EnrolOperator { .. }
            | Self::RevokeOperator { .. }
            // Who carries the active role is decreed by an operator
            // (ADR-0111).
            | Self::SetActiveInstance { .. } => Layer::DesiredState,
            Self::AssignPlacement { .. }
            | Self::ClearPlacement { .. }
            | Self::GrantLease { .. }
            | Self::RenewLease { .. }
            | Self::InviteNode { .. }
            | Self::AdmitNode { .. }
            | Self::RegisterTrust { .. }
            | Self::RotateTrust { .. }
            | Self::RevokeTrust { .. }
            | Self::AnnounceUnderlay { .. } => Layer::ClusterState,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    #[default]
    Operator,
    Policy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    Operator(String),
    LocalUid(u32),
}

impl std::fmt::Display for Actor {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operator(name) => write!(out, "operator:{name}"),
            Self::LocalUid(uid) => write!(out, "uid:{uid}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    pub command: Command,
}

impl Submission {
    #[must_use]
    pub const fn internal(command: Command) -> Self {
        Self {
            actor: None,
            command,
        }
    }

    #[must_use]
    pub const fn by(actor: Actor, command: Command) -> Self {
        Self {
            actor: Some(actor),
            command,
        }
    }
}

impl From<Command> for Submission {
    fn from(command: Command) -> Self {
        Self::internal(command)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Applied,
    LeaseGranted {
        epoch: Epoch,
    },
    LeaseRenewed {
        epoch: Epoch,
    },
    Rejected(Rejection),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    MalformedDocument {
        detail: String,
    },
    UnknownWorkload {
        name: String,
    },
    UnknownSecret {
        name: String,
    },
    SecretInUse {
        name: String,
        workload: String,
    },
    SecretUsedByRegistry {
        name: String,
        registry: String,
    },
    UnknownNode {
        name: String,
    },
    RetiredCommand {
        kind: String,
        detail: String,
    },
    NotSingleWriter {
        workload: String,
    },
    UnknownInstance {
        workload: String,
        instance: u32,
        replicas: u32,
    },
    LeaseHeld {
        workload: String,
        holder: String,
        epoch: Epoch,
    },
    NoLease {
        workload: String,
    },
    NotHolder {
        workload: String,
        holder: String,
    },
    ImplausibleLease {
        workload: String,
        granted_millis: u64,
        limit_millis: u64,
    },
    LeaseExpired {
        workload: String,
    },
    NoInvitation {
        node: String,
    },
    VolumeInUse {
        volume: String,
        workload: String,
    },
    SnapshotGenerationNotAdvancing {
        volume: String,
        node: String,
        have: u64,
        wanted: u64,
    },
    NotAdmitted {
        node: String,
    },
    MalformedUnderlay {
        node: String,
        detail: String,
    },
    MalformedSecret {
        name: String,
    },
    MalformedOperator {
        operator: String,
    },
    MalformedNetwork {
        cidr: String,
        detail: String,
    },
    ClusterFull {
        node: String,
        capacity: u32,
    },
    InvitationExpired {
        node: String,
        expired_at: i64,
    },
    GenerationNotAdvancing {
        node: String,
        kind: KeyKind,
        have: u64,
        wanted: u64,
    },
    WorkloadGenerationNotAdvancing {
        workload: String,
        instance: Option<u32>,
        have: u64,
        wanted: u64,
    },
    UnexpectedTrust {
        node: String,
    },
    UnplaceableDefinition {
        workload: String,
        detail: String,
    },
    UnusableEgressTarget {
        host: String,
        detail: String,
    },
}

impl std::fmt::Display for Rejection {
    // **An `allow` and no split**, and the reason is the exhaustiveness: this
    // `match` covers every rejection reason individually, and precisely that
    // forces an answer at the next one instead of hoping for it (the finding
    // from ADR-0049). Splitting it would demand a non-exhaustive first part
    // that delegates to a second -- then the compiler no longer warns at a new
    // variant, and one day an operator gets a rejection nobody explains. The
    // same weighing as with `ClusterState::apply`.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedDocument { detail } => {
                write!(f, "not a valid definition: {detail}")
            }
            Self::UnknownWorkload { name } => write!(f, "the workload '{name}' does not exist"),
            Self::UnknownSecret { name } => write!(f, "the secret '{name}' does not exist"),
            Self::SecretInUse { name, workload } => write!(
                f,
                "'{workload}' may still read the secret '{name}' — withdraw the \
                 permission first"
            ),
            Self::UnusableEgressTarget { host, detail } => write!(
                f,
                "the egress target '{host}' can never permit anything: {detail}"
            ),
            Self::SecretUsedByRegistry { name, registry } => write!(
                f,
                "the registry mapping for '{registry}' points at the secret \
                 '{name}' — `tgctl cluster registry rm {registry}` first"
            ),
            Self::UnknownNode { name } => write!(f, "the node '{name}' does not exist"),
            Self::RetiredCommand { kind, detail } => write!(
                f,
                "'{kind}' is retired and no longer takes effect: {detail}"
            ),
            Self::NotSingleWriter { workload } => {
                write!(f, "'{workload}' is no single writer and has no active role")
            }
            Self::UnknownInstance {
                workload,
                instance,
                replicas,
            } => write!(
                f,
                "'{workload}' declares {replicas} instances, instance {instance} \
                 was demanded"
            ),
            Self::LeaseHeld {
                workload,
                holder,
                epoch,
            } => write!(
                f,
                "'{holder}' holds the active role of '{workload}' (epoch {epoch:?})"
            ),
            Self::NoLease { workload } => {
                write!(f, "no active role is granted for '{workload}'")
            }
            Self::NotHolder { workload, holder } => write!(
                f,
                "'{holder}' holds the active role of '{workload}', not the sender"
            ),
            Self::LeaseExpired { workload } => {
                write!(f, "the active role of '{workload}' has expired")
            }
            Self::ImplausibleLease {
                workload,
                granted_millis,
                limit_millis,
            } => write!(
                f,
                "the active role of '{workload}' shall apply for \
                 {granted_millis} ms, at most {limit_millis} ms are admissible"
            ),
            Self::NoInvitation { node } => write!(f, "there is no invitation for '{node}'"),
            Self::VolumeInUse { volume, workload } => {
                write!(f, "the volume '{volume}' is still declared by '{workload}'")
            }
            Self::SnapshotGenerationNotAdvancing {
                volume,
                node,
                have,
                wanted,
            } => write!(
                f,
                "'{volume}@{node}' already has snapshot generation {have}, \
                 {wanted} was demanded"
            ),
            Self::NotAdmitted { node } => write!(f, "'{node}' is not admitted"),
            Self::MalformedUnderlay { node, detail } => write!(
                f,
                "the underlay settings of '{node}' are unusable: {detail}"
            ),
            Self::MalformedSecret { name } => write!(
                f,
                "'{name}' is no secret name: on the node it becomes a file name, \
                 and only a single ordinary path component is fit for that \
                 (ADR-0098)"
            ),
            Self::MalformedOperator { operator } => write!(
                f,
                "'{operator}' is not registrable as an operator: the name has to \
                 fit into a SPIFFE identifier, the SPKI has to be readable, and \
                 at least one class has to stand there — otherwise the entry \
                 carries no handshake or the registration may do nothing \
                 (ADR-0103, ADR-0105)"
            ),
            Self::MalformedNetwork { cidr, detail } => {
                write!(f, "'{cidr}' is no usable address plan: {detail}")
            }
            Self::ClusterFull { node, capacity } => write!(
                f,
                "no subnet is free any more for '{node}' — the address space \
                 carries {capacity} nodes"
            ),
            Self::InvitationExpired { node, expired_at } => write!(
                f,
                "the invitation for '{node}' has been expired since {expired_at}"
            ),
            Self::GenerationNotAdvancing {
                node,
                kind,
                have,
                wanted,
            } => write!(
                f,
                "the key generation of '{node}' ({kind:?}) stands at {have}; \
                 {wanted} would not be higher"
            ),
            Self::WorkloadGenerationNotAdvancing {
                workload,
                instance,
                have,
                wanted,
            } => {
                let scope = match instance {
                    Some(instance) => format!("'{workload}' (instance {instance})"),
                    None => format!("'{workload}' (all instances)"),
                };
                write!(
                    f,
                    "the generation of {scope} stands at {have}; {wanted} would not be higher"
                )
            }
            Self::UnexpectedTrust { node } => {
                write!(f, "the registered key of '{node}' is not the expected one")
            }
            Self::UnplaceableDefinition { workload, detail } => {
                write!(f, "'{workload}' cannot be placed like this: {detail}")
            }
        }
    }
}
