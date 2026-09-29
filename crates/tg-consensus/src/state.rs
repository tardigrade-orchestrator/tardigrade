//! The replicated state and the applying of commands.
//!
//! This is the state machine in the Raft sense: a function
//! `(state, command) → (state, result)`, and a **pure** one at that. No access
//! to a clock, randomness, the environment or the disk. Every node that
//! applies the same log has the same byte in memory afterwards — otherwise
//! the projection built from it is not deterministic and freedom from
//! split-brain not provable.
//!
//! Where a time is needed — lease expiry — it travels along in the command
//! (ADR-0024). The comparison `now >= expires_at` is thereby part of the log
//! and not part of the environment.
//!
//! Two rules that apply throughout and are therefore not repeated at every
//! variant:
//!
//! 1. **Removing is idempotent.** A `Remove`/`Revoke` on something that is not
//!    there is [`Outcome::Applied`] and not a rejection. Level-triggered
//!    reconciliation (ADR-0010) repeats commands; every repetition would
//!    otherwise have to travel through the caller as an error.
//! 2. **A rejection writes nothing.** Half-applied commands would be hard to
//!    keep identical on two nodes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tg_defs::{WorkloadClass, WorkloadExt as _};
use tg_identity::secrets::SealedExt as _;
use tg_model::egress::Transport;

use tg_model::placement::Demand;

use crate::command::{
    Attachment, CapacityPolicy, Class, Command, Epoch, Generations, Outcome, Rejection, Resources,
    RotationPolicy, Schedulability, Topology, UtcMillis,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operator {
    spki: String,
    classes: Vec<Class>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadEntry {
    name: String,
    document: String,
    single_writer: bool,
}

impl WorkloadEntry {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn document(&self) -> &str {
        &self.document
    }

    #[must_use]
    pub fn class(&self) -> WorkloadClass {
        if self.single_writer {
            WorkloadClass::SingleWriter
        } else {
            WorkloadClass::Replicated
        }
    }

    #[must_use]
    pub fn is_single_writer(&self) -> bool {
        self.single_writer
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub digest: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEntry {
    topology: Topology,
    #[serde(default)]
    capacity: Resources,
    #[serde(default)]
    reserved: Resources,
    #[serde(default)]
    schedulable: Schedulability,
    #[serde(default)]
    attachment: Attachment,
}

impl NodeEntry {
    #[must_use]
    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    #[must_use]
    pub fn capacity(&self) -> &Resources {
        &self.capacity
    }

    #[must_use]
    pub fn reserved(&self) -> &Resources {
        &self.reserved
    }

    #[must_use]
    pub const fn schedulable(&self) -> Schedulability {
        self.schedulable
    }

    #[must_use]
    pub const fn attachment(&self) -> Attachment {
        self.attachment
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnderlayEntry {
    ordinal: u32,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
}

impl UnderlayEntry {
    #[must_use]
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }

    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    #[must_use]
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    holder: String,
    epoch: Epoch,
    expires_at: UtcMillis,
}

impl Lease {
    #[must_use]
    pub fn holder(&self) -> &str {
        &self.holder
    }

    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    #[must_use]
    pub fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    #[must_use]
    pub fn is_valid_at(&self, now: UtcMillis) -> bool {
        now < self.expires_at
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterState {
    workloads: BTreeMap<String, WorkloadEntry>,
    traffic: BTreeSet<(String, String)>,
    nodes: BTreeMap<String, NodeEntry>,
    placements: BTreeMap<String, BTreeMap<u32, String>>,
    leases: BTreeMap<String, Lease>,
    #[serde(default)]
    active_instances: BTreeMap<String, u32>,
    trust: BTreeMap<String, String>,
    #[serde(default)]
    capacity_policy: CapacityPolicy,
    #[serde(default)]
    rotation_policy: RotationPolicy,
    #[serde(default)]
    invitations: BTreeMap<String, Invitation>,
    #[serde(default)]
    key_generations: BTreeMap<String, Generations>,
    #[serde(default)]
    workload_generations: BTreeMap<String, tg_model::rollout::Generations>,
    #[serde(default)]
    underlay: BTreeMap<String, UnderlayEntry>,
    #[serde(default)]
    egress: BTreeSet<(String, String, u16, Transport)>,
    #[serde(default)]
    secrets: BTreeMap<String, tg_identity::secrets::Sealed>,
    #[serde(default)]
    secret_grants: BTreeSet<(String, String)>,

    #[serde(default)]
    registry_credentials: BTreeMap<String, String>,
    #[serde(default)]
    deleted_volumes: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    snapshot_generations: BTreeMap<String, BTreeMap<String, u64>>,
    #[serde(default)]
    operators: BTreeMap<String, Operator>,
    #[serde(default)]
    network: Option<(String, u8)>,
    #[serde(default)]
    sidecar_overhead: Resources,
    next_epoch: Epoch,
}

fn plausible_secret(name: &str) -> bool {
    tg_model::names::is_plausible_secret(name)
}

fn is_plausible_operator(name: &str) -> bool {
    tg_model::names::is_plausible(name)
}

impl ClusterState {
    // The length is the number of command kinds, and the `match` over it is
    // **exhaustive**: it is the tool that forces a new variant to an answer
    // instead of hoping for one -- this tree has measured four
    // hand-maintained lists as a source of error and this one as their
    // replacement. Splitting it would take exactly that from the compiler.
    #[allow(clippy::too_many_lines)]
    pub fn apply(&mut self, command: &Command) -> Outcome {
        // **Every rejection is bounded here**, at *one* place and not at the
        // forty construction sites.
        //
        // The reason has always stood at [`MAX_DETAIL`] and applied only to
        // the document: a rejection goes into the log, the log is retained,
        // and it additionally lies in the archive's sealed payload. A value
        // that determines the size of the rejection thereby permanently
        // determines the size of the archive.
        //
        // Measured, the bound did **not** apply to the other rejections: a
        // 100 kB name got through unshortened while the same document ended at
        // 141 bytes.
        //
        // Here and not there, because `bounded` is an exhaustive `match`: a new
        // variant forces an answer instead of hoping for one.
        // **A retired command no longer takes effect.**
        //
        // Here and not at the access, and that is the actual decision: refusing
        // could do both, **reporting** only this way. The attempt goes into the
        // log, is applied, refused and sealed with its verdict -- an attempt to
        // enter node trust without an invitation is exactly the event an
        // auditor looks for. Refused at the access it would never reach the
        // log.
        //
        // **Unconditionally**, and not hung on the actor: the state machine
        // stays a pure function over the command, and two nodes still arrive
        // at the same result. A rejection that depended on the provenance
        // would be authorization in the state machine -- that sits at the
        // transport instead.
        if let Some(detail) = command.retired() {
            return Outcome::Rejected(bounded(Rejection::RetiredCommand {
                kind: command.kind().to_owned(),
                detail: detail.to_owned(),
            }));
        }

        match self.decide(command) {
            Outcome::Rejected(rejection) => Outcome::Rejected(bounded(rejection)),
            applied => applied,
        }
    }

    // The same trade-off as at [`Self::apply`] -- the exhaustive `match` stands
    // here.
    #[allow(clippy::too_many_lines)]
    fn decide(&mut self, command: &Command) -> Outcome {
        match command {
            Command::UpsertWorkload { document } => self.upsert_workload(document),

            Command::RemoveWorkload { name } => {
                self.workloads.remove(name);
                self.placements.remove(name);
                self.leases.remove(name);
                self.traffic.retain(|(from, to)| from != name && to != name);
                // The egress permissions go with it: a permission for a
                // workload that no longer exists is an open door with no room
                // behind it — and the next workload of the same name would
                // inherit it silently.
                self.egress.retain(|(workload, _, _, _)| workload != name);
                // And the generations: a counter left behind would be a
                // restart that hits a later workload of the same name at some
                // point.
                self.workload_generations.remove(name);
                // And the active instance: an entry left behind would
                // otherwise address a later workload of the same name — and
                // that one possibly carries its role elsewhere.
                self.active_instances.remove(name);
                // And the read permissions, for the same reason as the
                // egress: an open door with no room behind it would be
                // inherited by the next workload of the same name.
                self.secret_grants.retain(|(workload, _)| workload != name);
                Outcome::Applied
            }

            Command::AllowTraffic { from, to } => {
                if let Some(missing) = self.first_unknown_workload([from, to]) {
                    return missing;
                }
                self.traffic.insert((from.clone(), to.clone()));
                Outcome::Applied
            }

            Command::PutSecret { name, value } => {
                // **The name becomes a file name on the node**, and it comes
                // from an operator. It is checked here so that a `../` stands
                // out when issuing and not on a node -- the agent checks it
                // once more anyway, for the log is retained forever.
                if !plausible_secret(name) {
                    return Outcome::Rejected(Rejection::MalformedSecret { name: name.clone() });
                }
                self.secrets.insert(name.clone(), value.clone());
                Outcome::Applied
            }
            Command::RemoveSecret { name } => {
                // **Refused as long as somebody may still read it** — the
                // same direction as at a volume a workload still declares:
                // whoever deletes it takes it from everyone, and a permission
                // that points into the void an auditor takes for one.
                if let Some((workload, _)) =
                    self.secret_grants.iter().find(|(_, secret)| secret == name)
                {
                    return Outcome::Rejected(Rejection::SecretInUse {
                        name: name.clone(),
                        workload: workload.clone(),
                    });
                }
                // **And the second consumer:** a registry mapping.
                // `SetRegistryCredential` refuses a mapping onto a
                // secret that does not exist — "a mapping into the void would
                // look to an operator like one that carries, and the pull would
                // run anonymously afterwards". Measured, this line let exactly
                // that state **arise**: the secret went, the mapping stayed.
                //
                // What hangs on it nobody sees at once: the pull runs
                // anonymously and fails at the registry — at
                // `pullPolicy="always"` at the next start, at a cached image
                // arbitrarily late and far away from the cause.
                if let Some((registry, _)) = self
                    .registry_credentials
                    .iter()
                    .find(|(_, secret)| *secret == name)
                {
                    return Outcome::Rejected(Rejection::SecretUsedByRegistry {
                        name: name.clone(),
                        registry: registry.clone(),
                    });
                }

                // Deleting an unknown secret is **done**, not refused
                // (rule 1).
                self.secrets.remove(name);
                Outcome::Applied
            }
            Command::AllowSecret { workload, secret } => {
                if let Some(missing) = self.first_unknown_workload([workload]) {
                    return missing;
                }
                if !self.secrets.contains_key(secret) {
                    return Outcome::Rejected(Rejection::UnknownSecret {
                        name: secret.clone(),
                    });
                }
                self.secret_grants
                    .insert((workload.clone(), secret.clone()));
                Outcome::Applied
            }
            Command::RevokeSecret { workload, secret } => {
                self.secret_grants
                    .remove(&(workload.clone(), secret.clone()));
                Outcome::Applied
            }
            Command::SetRegistryCredential { registry, secret } => {
                // **A secret that does not exist is refused** — like a
                // permission on it: a mapping into the void would look to an
                // operator like one that carries, and the pull would run
                // anonymously afterwards.
                if !self.secrets.contains_key(secret) {
                    return Outcome::Rejected(Rejection::UnknownSecret {
                        name: secret.clone(),
                    });
                }
                // **Lower-cased.** A registry host is a DNS name; measured,
                // `oci_client` returned the reference's spelling unchanged and
                // it was looked up exactly here — a capital letter meant
                // anonymous, and silently. `AllowEgress` does the same for its
                // name, and for the same reason.
                self.registry_credentials
                    .insert(registry.to_ascii_lowercase(), secret.clone());
                Outcome::Applied
            }
            Command::ClearRegistryCredential { registry } => {
                // **Not refused but answered.** Unlike at `RemoveSecret` no
                // dangling reference arises here but a **valid** state:
                // "pulls from this registry are anonymous" is the normal case
                // of every public one. Who pulls from it is named by the
                // admin service's answer — not by the log, for that is
                // retained permanently.
                self.registry_credentials
                    .remove(&registry.to_ascii_lowercase());
                Outcome::Applied
            }
            Command::AllowEgress {
                workload,
                host,
                port,
                transport,
            } => {
                if let Some(missing) = self.first_unknown_workload([workload]) {
                    return missing;
                }
                // **What can never permit anything is not applied.**
                // Measured, `*.s3.example.com` got through here, into the log
                // and into the slice — and both comparisons in the data plane
                // compare exactly: the destination was forbidden, *and* the
                // name did not resolve.
                //
                // What is checked is the **form**, not the existence. Whether
                // the name exists is still said only by DNS.
                if let Some(refusal) = unusable_target(host, *transport) {
                    return Outcome::Rejected(refusal);
                }
                self.egress.insert((
                    workload.clone(),
                    host.to_ascii_lowercase(),
                    *port,
                    *transport,
                ));
                Outcome::Applied
            }

            Command::RevokeEgress {
                workload,
                host,
                port,
                transport,
            } => {
                self.egress.remove(&(
                    workload.clone(),
                    host.to_ascii_lowercase(),
                    *port,
                    *transport,
                ));
                Outcome::Applied
            }

            Command::RevokeTraffic { from, to } => {
                self.traffic.remove(&(from.clone(), to.clone()));
                Outcome::Applied
            }

            Command::UpsertNode {
                name,
                topology,
                capacity,
                reserved,
                // The provenance stands in the **log** and not in the state:
                // it says something about the event, not about the node. An
                // auditor reads it in the archive; the planner has nothing to
                // do with it.
                source: _,
            } => {
                // **An upsert does not withdraw a block.** It enters
                // inventory — topology and capacity —, and an operator who
                // corrects the capacity while another drains the node would
                // otherwise have lifted the drain without noticing. It is
                // withdrawn with the command that set it.
                let schedulable = self
                    .nodes
                    .get(name)
                    .map_or_else(Schedulability::default, NodeEntry::schedulable);
                // And a detachment just as little, for the same reason.
                let attachment = self
                    .nodes
                    .get(name)
                    .map_or_else(Attachment::default, NodeEntry::attachment);

                self.nodes.insert(
                    name.clone(),
                    NodeEntry {
                        topology: topology.clone(),
                        capacity: capacity.clone(),
                        reserved: reserved.clone(),
                        schedulable,
                        attachment,
                    },
                );
                Outcome::Applied
            }

            Command::SetRotationPolicy { policy } => {
                // As at the capacity policy: no comparison, no rejection.
                // Setting a policy that already applies is idempotent; an empty
                // one withdraws it.
                self.rotation_policy = policy.clone();
                Outcome::Applied
            }

            Command::SetCapacityPolicy { policy } => {
                // No comparison with what exists and no rejection: setting a
                // policy that already applies is idempotent (rule 1 in the
                // module head), and an empty one withdraws it.
                self.capacity_policy = policy.clone();
                Outcome::Applied
            }

            Command::SetSchedulability { node, mode } => {
                // An unknown node is a **rejection** and not
                // idempotently-done: "blocked" on something that does not exist
                // would look to an operator like "blocked", and they would move
                // on to the restart reassured.
                let Some(entry) = self.nodes.get_mut(node) else {
                    return Outcome::Rejected(Rejection::UnknownNode { name: node.clone() });
                };
                entry.schedulable = *mode;
                Outcome::Applied
            }

            Command::SetAttachment { node, mode } => {
                // The same exception to rule 1 as at the block: "detached" on
                // a node that does not exist would look to an operator like
                // "detached".
                let Some(entry) = self.nodes.get_mut(node) else {
                    return Outcome::Rejected(Rejection::UnknownNode { name: node.clone() });
                };
                // **Ordinal and trust stay.** Detach is a statement about the
                // data plane, no security action and no topology change.
                entry.attachment = *mode;
                Outcome::Applied
            }

            Command::SetKeyGeneration {
                node,
                kind,
                generation,
            } => {
                // **The condition is the admission, not the inventory.** A
                // node has keys as soon as `AdmitNode` knows it; admission
                // expressly enters **no** capacity in the process. Hanging the
                // generation on `UpsertNode` would force an operator to invent
                // topology and capacity just in order to rotate a key.
                if !self.trust.contains_key(node) {
                    return Outcome::Rejected(Rejection::NotAdmitted { node: node.clone() });
                }

                let entry = self.key_generations.entry(node.clone()).or_default();
                let have = entry.of(*kind);
                if *generation < have {
                    // **Backwards no, equal yes.** Equal is done (rule 1);
                    // backwards would mean making an old key valid again.
                    return Outcome::Rejected(Rejection::GenerationNotAdvancing {
                        node: node.clone(),
                        kind: *kind,
                        have,
                        wanted: *generation,
                    });
                }
                entry.set(*kind, *generation);
                Outcome::Applied
            }

            Command::SetWorkloadGeneration {
                workload,
                instance,
                generation,
            } => {
                // **The condition is the desired state**: one can restart
                // only what is declared. An unknown name is **refused**, not
                // idempotently done — "restarted" on something that does not
                // exist would look to an operator like "restarted" (the same
                // exception to rule 1 as at the cordon).
                if let Some(missing) = self.first_unknown_workload([workload]) {
                    return missing;
                }

                let entry = self
                    .workload_generations
                    .entry(workload.clone())
                    .or_default();
                let have = entry.at(*instance);
                if *generation < have {
                    // **Backwards no, equal yes.** Equal is done (rule 1);
                    // backwards would mean withdrawing a restart that already
                    // happened.
                    return Outcome::Rejected(Rejection::WorkloadGenerationNotAdvancing {
                        workload: workload.clone(),
                        instance: *instance,
                        have,
                        wanted: *generation,
                    });
                }
                entry.set(*instance, *generation);
                Outcome::Applied
            }

            Command::RemoveNode { name } => {
                self.nodes.remove(name);
                self.trust.remove(name);
                // Only here is the ordinal freed. A failure does not do it:
                // the node was away for a week and still has its subnet.
                self.underlay.remove(name);
                // An open invitation goes with it: otherwise a token would
                // stay valid for a node that no longer exists.
                self.invitations.remove(name);
                // And the key generations: a node that joins anew starts at
                // zero — otherwise it would inherit its predecessor's rotation
                // history and would rotate at once (ADR-0055).
                self.key_generations.remove(name);
                // And the snapshot generations: a node that joins anew does
                // not have its predecessor's volumes and would otherwise be
                // decreed snapshots of something that does not exist there
                // (ADR-0099).
                self.snapshot_generations.remove(name);
                // And the tombstones: they are **instructions to this node**
                // (ADR-0104). If it is gone it never reports the execution, and
                // the instruction would stand forever in the state and in every
                // snapshot — nobody could clear it away any more.
                self.deleted_volumes.remove(name);
                for instances in self.placements.values_mut() {
                    instances.retain(|_, node| node != name);
                }
                self.placements.retain(|_, instances| !instances.is_empty());
                Outcome::Applied
            }

            Command::AssignPlacement {
                workload,
                instance,
                node,
            } => {
                if !self.workloads.contains_key(workload) {
                    return unknown_workload(workload);
                }
                if !self.nodes.contains_key(node) {
                    return Outcome::Rejected(Rejection::UnknownNode { name: node.clone() });
                }
                self.placements
                    .entry(workload.clone())
                    .or_default()
                    .insert(*instance, node.clone());
                Outcome::Applied
            }

            Command::ClearPlacement { workload } => {
                self.placements.remove(workload);
                Outcome::Applied
            }

            Command::GrantLease {
                workload,
                node,
                now,
                expires_at,
            } => self.grant_lease(workload, node, *now, *expires_at),

            Command::RenewLease {
                workload,
                node,
                now,
                expires_at,
            } => self.renew_lease(workload, node, *now, *expires_at),

            Command::SetActiveInstance { workload, instance } => {
                self.set_active_instance(workload, *instance)
            }

            Command::InviteNode {
                node,
                digest,
                expires_at,
            } => {
                // A new invitation replaces an open one. An operator who
                // invites once more thereby devalues the previous token — that
                // is the everyday case, not the exception.
                self.invitations.insert(
                    node.clone(),
                    Invitation {
                        digest: digest.clone(),
                        expires_at: *expires_at,
                    },
                );
                Outcome::Applied
            }

            Command::AdmitNode { node, spki, at } => self.admit(node, spki, *at),

            Command::RegisterTrust { node, bundle } => {
                if !self.nodes.contains_key(node) {
                    return Outcome::Rejected(Rejection::UnknownNode { name: node.clone() });
                }
                self.trust.insert(node.clone(), bundle.clone());
                Outcome::Applied
            }

            Command::RotateTrust { node, from, to } => {
                // **Compare and set** (ADR-0055). If the expected key no
                // longer stands there, the request is overtaken: either an
                // operator revoked, or another change was first. Both mean that
                // there is nothing to replace here.
                //
                // Expressly **without** the condition from `RegisterTrust` that
                // the node must be entered: what is admitted is only trust, no
                // capacity (ADR-0037).
                if self.trust.get(node).map(String::as_str) != Some(from.as_str()) {
                    return Outcome::Rejected(Rejection::UnexpectedTrust { node: node.clone() });
                }
                self.trust.insert(node.clone(), to.clone());
                Outcome::Applied
            }

            Command::RevokeTrust { node } => {
                // Expressly **without** the ordinal: revoking a key is a
                // security action, renumbering a subnet a topology change. The
                // one must not trigger the other.
                self.trust.remove(node);
                Outcome::Applied
            }
            Command::SetClusterNetwork { cidr, node_prefix } => {
                self.set_cluster_network(cidr, *node_prefix)
            }
            Command::SetSidecarOverhead { resources } => {
                self.sidecar_overhead = resources.clone();
                Outcome::Applied
            }
            Command::DeleteVolume { volume, node, .. } => self.delete_volume(volume, node),

            Command::RetireTombstone { volume, node } => self.retire_tombstone(volume, node),

            Command::SnapshotVolume {
                volume,
                node,
                generation,
            } => {
                // **The condition is the admission**, not a `NodeEntry`:
                // `AdmitNode` creates none (ADR-0037 admits only trust), and an
                // operator shall not have to invent topology and capacity in
                // order to decree a snapshot. The same choice as at the key
                // generations (ADR-0055).
                //
                // An unknown node is **refused** and not idempotently done --
                // "snapshot decreed" on a node that does not exist would look to
                // an operator like "decreed" (the same exception to rule 1 as at
                // the cordon).
                if !self.trust.contains_key(node) {
                    return Outcome::Rejected(Rejection::NotAdmitted { node: node.clone() });
                }

                // **The volume is not checked**, and that is deliberate: the
                // state knows only the *declarations*, not the disk. And both
                // cases are legitimate -- a snapshot of a declared volume is the
                // normal case, one of a volume without a workload is exactly the
                // DR case in which the workload has already been withdrawn and
                // the data still lies there. If the node does not find it, it
                // reports so.
                let entry = self
                    .snapshot_generations
                    .entry(node.clone())
                    .or_default()
                    .entry(volume.clone())
                    .or_default();

                if *generation < *entry {
                    // **Backwards no, equal yes.** Equal is done (rule 1);
                    // backwards would mean withdrawing a snapshot that already
                    // happened -- and because the node compares against its
                    // mark, the decree would moreover be without effect.
                    return Outcome::Rejected(Rejection::SnapshotGenerationNotAdvancing {
                        volume: volume.clone(),
                        node: node.clone(),
                        have: *entry,
                        wanted: *generation,
                    });
                }

                *entry = *generation;
                Outcome::Applied
            }

            Command::EnrolOperator {
                operator,
                spki,
                classes,
            } => {
                // **No `NodeTrust` detour and no name check against the
                // nodes**: an operator and a node may have the same name, for
                // the **role** in the certificate separates them (ADR-0103,
                // determination 2). Two lists, two namespaces.
                //
                // What is checked is the **form**: the name goes into a SPIFFE
                // ID (`spiffe://<domain>/operator/<name>`), and what does not
                // fit in there would yield a credential no port accepts -- the
                // finding from the wiring ("mints without complaint, and none is
                // accepted").
                if !is_plausible_operator(operator) {
                    return Outcome::Rejected(Rejection::MalformedOperator {
                        operator: operator.clone(),
                    });
                }

                // And the SPKI must be readable. An entry the verifier cannot
                // decode would be a registration that **never** carries a
                // handshake -- and the error would show up only at the first
                // connection, not at the entering.
                if tg_identity::cluster::NodeTrust::from_base64([(
                    operator.as_str(),
                    spki.as_str(),
                )])
                .is_err()
                {
                    return Outcome::Rejected(Rejection::MalformedOperator {
                        operator: operator.clone(),
                    });
                }

                // **Unconditional**, unlike `RotateTrust` (ADR-0055): an
                // operator does not register themselves -- the command comes
                // from one who is already allowed to. The race against which
                // that ADR built the compare-and-set does not exist here.
                // **Without a class no registration** (ADR-0105): it would be a
                // registration that passes the handshake and may do nothing --
                // and an operator would look for the error at their key. The
                // same exception to rule 1 as at the cordon on an unknown
                // node.
                if classes.is_empty() {
                    return Outcome::Rejected(Rejection::MalformedOperator {
                        operator: operator.clone(),
                    });
                }

                // Sorted and deduplicated: `["read","read"]` and `["read"]`
                // are the same statement, and two spellings for one statement
                // are two opportunities to read it differently. The log is
                // retained (ADR-0020).
                let mut classes = classes.clone();
                classes.sort_unstable();
                classes.dedup();

                self.operators.insert(
                    operator.clone(),
                    Operator {
                        spki: spki.clone(),
                        classes,
                    },
                );
                Outcome::Applied
            }
            Command::RevokeOperator { operator } => {
                // **Idempotent** (rule 1): "no longer registered" is the true
                // statement for a name that never existed. A revocation that
                // failed at a typo would let an operator believe they achieved
                // nothing -- while there was nothing to achieve.
                self.operators.remove(operator);
                Outcome::Applied
            }
            Command::AnnounceUnderlay {
                node,
                key,
                endpoint,
                at: _,
            } => self.announce_underlay(node, key, endpoint),
        }
    }

    #[must_use]
    pub fn workload(&self, name: &str) -> Option<&WorkloadEntry> {
        self.workloads.get(name)
    }

    #[must_use]
    pub fn workloads(&self) -> Vec<&WorkloadEntry> {
        self.workloads.values().collect()
    }

    #[must_use]
    pub const fn rotation_policy(&self) -> &RotationPolicy {
        &self.rotation_policy
    }

    #[must_use]
    pub fn workload_generations(&self, workload: &str) -> tg_model::rollout::Generations {
        self.workload_generations
            .get(workload)
            .cloned()
            .unwrap_or_default()
    }

    #[must_use]
    pub fn key_generations(&self, node: &str) -> Generations {
        self.key_generations.get(node).copied().unwrap_or_default()
    }

    #[must_use]
    pub fn may_talk(&self, from: &str, to: &str) -> bool {
        self.traffic.contains(&(from.to_owned(), to.to_owned()))
    }

    #[must_use]
    pub fn traffic(&self) -> Vec<(&str, &str)> {
        self.traffic
            .iter()
            .map(|(from, to)| (from.as_str(), to.as_str()))
            .collect()
    }

    #[must_use]
    pub fn node(&self, name: &str) -> Option<&NodeEntry> {
        self.nodes.get(name)
    }

    #[must_use]
    pub const fn sidecar_overhead(&self) -> &Resources {
        &self.sidecar_overhead
    }

    #[must_use]
    pub fn nodes(&self) -> Vec<(&str, &NodeEntry)> {
        self.nodes
            .iter()
            .map(|(name, entry)| (name.as_str(), entry))
            .collect()
    }

    #[must_use]
    pub fn capacity_policy(&self) -> &CapacityPolicy {
        &self.capacity_policy
    }

    #[must_use]
    pub fn placement(&self, workload: &str) -> Option<&str> {
        self.instance(workload, 0)
    }

    #[must_use]
    pub fn instance(&self, workload: &str, instance: u32) -> Option<&str> {
        self.placements
            .get(workload)
            .and_then(|instances| instances.get(&instance))
            .map(String::as_str)
    }

    #[must_use]
    pub fn instances(&self, workload: &str) -> Vec<(u32, &str)> {
        self.placements
            .get(workload)
            .map(|instances| {
                instances
                    .iter()
                    .map(|(number, node)| (*number, node.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn placements(&self) -> Vec<(&str, u32, &str)> {
        self.placements
            .iter()
            .flat_map(|(workload, instances)| {
                instances
                    .iter()
                    .map(move |(number, node)| (workload.as_str(), *number, node.as_str()))
            })
            .collect()
    }

    #[must_use]
    pub fn lease(&self, workload: &str) -> Option<&Lease> {
        self.leases.get(workload)
    }

    #[must_use]
    pub fn active_instances(&self) -> Vec<(&str, u32)> {
        self.active_instances
            .iter()
            .map(|(workload, instance)| (workload.as_str(), *instance))
            .collect()
    }

    #[must_use]
    pub fn active_instance(&self, workload: &str) -> u32 {
        self.active_instances.get(workload).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn trust(&self, node: &str) -> Option<&str> {
        self.trust.get(node).map(String::as_str)
    }

    pub fn trusted(&self) -> impl Iterator<Item = (&str, &str)> {
        self.trust
            .iter()
            .map(|(node, spki)| (node.as_str(), spki.as_str()))
    }

    #[must_use]
    pub fn invited(&self, node: &str) -> bool {
        self.invitations.contains_key(node)
    }

    #[must_use]
    pub fn invitations(&self) -> Vec<(&str, i64)> {
        self.invitations
            .iter()
            .map(|(node, invitation)| (node.as_str(), invitation.expires_at))
            .collect()
    }

    #[must_use]
    pub fn invitation_digest(&self, node: &str) -> Option<&str> {
        self.invitations
            .get(node)
            .map(|invitation| invitation.digest.as_str())
    }

    fn admit(&mut self, node: &str, spki: &str, at: i64) -> Outcome {
        let Some(invitation) = self.invitations.get(node) else {
            return Outcome::Rejected(Rejection::NoInvitation {
                node: node.to_owned(),
            });
        };

        if at > invitation.expires_at {
            let expired_at = invitation.expires_at;
            // Expired also means cleared away: a dead invitation shall not
            // stay lying as a leftover.
            self.invitations.remove(node);
            return Outcome::Rejected(Rejection::InvitationExpired {
                node: node.to_owned(),
                expired_at,
            });
        }

        self.invitations.remove(node);
        self.trust.insert(node.to_owned(), spki.to_owned());

        // The ordinal arises **here** — in the same application that checks
        // the invitation. That is why it is no race but a consequence of the
        // log, and every replica computes the same one (ADR-0039).
        //
        // A node that still has one keeps it: it is freed only by an explicit
        // removal, never by a failure.
        if !self.underlay.contains_key(node) {
            // **Where there is no subnet left, no node is admitted any
            // more.**
            //
            // The number arises here and applies forever; if the cluster handed
            // out one for which no subnet exists, it would admit a node for
            // which it has no addresses -- and the error would show up only on
            // the node, in a path that is fail-soft.
            //
            // Without a set address plan it is not bounded: it may come later
            // (ADR-0040), and a cluster that admits no node before it would
            // never come up. The trust part of the admission (ADR-0037) has
            // already happened at this point and stays -- what is refused is the
            // **assignment**, and then the whole command.
            let capacity = self.plan().map_or(u32::MAX, |plan| plan.capacity());
            let Some(ordinal) = self.next_free_ordinal(capacity) else {
                return Outcome::Rejected(Rejection::ClusterFull {
                    node: node.to_owned(),
                    capacity,
                });
            };

            self.underlay.insert(
                node.to_owned(),
                UnderlayEntry {
                    ordinal,
                    key: None,
                    endpoint: None,
                },
            );
        }

        Outcome::Applied
    }

    fn set_cluster_network(&mut self, cidr: &str, node_prefix: u8) -> Outcome {
        let malformed = |detail: String| {
            Outcome::Rejected(Rejection::MalformedNetwork {
                cidr: cidr.to_owned(),
                detail,
            })
        };

        // **One function for both steps** (ADR-0069): `Plan::parse` parses and
        // checks, and the client asks the same question before the access. Two
        // places would be two opportunities to answer it differently.
        let plan = match tg_model::network::Plan::parse(cidr, node_prefix) {
            Ok(plan) => plan,
            Err(err) => return malformed(err.to_string()),
        };

        // **What is already handed out must keep fitting.** An ordinal is
        // handed out at the admission and held (ADR-0039); from it follows every
        // route, every nftables rule and every `AllowedIP`. A network narrowed
        // afterwards would take existing nodes' subnets away -- and silently at
        // that, for the error would show up only on the node.
        if let Some(highest) = self.underlay.values().map(UnderlayEntry::ordinal).max()
            && !plan.holds(highest)
        {
            return malformed(format!(
                "carries {} node subnets, but the highest ordinal handed out \
                 is {highest}",
                plan.capacity()
            ));
        }

        self.network = Some((cidr.to_owned(), node_prefix));
        Outcome::Applied
    }

    fn plan(&self) -> Option<tg_model::network::Plan> {
        let (cidr, node_prefix) = self.network.as_ref()?;
        let net = cidr.parse::<ipnet::Ipv4Net>().ok()?;
        tg_model::network::Plan::new(net, *node_prefix).ok()
    }

    #[must_use]
    pub fn address_capacity(&self) -> Option<u32> {
        self.plan().map(|plan| plan.capacity())
    }

    #[must_use]
    pub fn ordinals_used(&self) -> u32 {
        u32::try_from(self.underlay.len()).unwrap_or(u32::MAX)
    }

    fn next_free_ordinal(&self, capacity: u32) -> Option<u32> {
        let taken: BTreeSet<u32> = self.underlay.values().map(|entry| entry.ordinal).collect();

        (0..capacity).find(|candidate| !taken.contains(candidate))
    }

    fn announce_underlay(&mut self, node: &str, key: &str, endpoint: &str) -> Outcome {
        let Some(entry) = self.underlay.get(node) else {
            return Outcome::Rejected(Rejection::NotAdmitted {
                node: node.to_owned(),
            });
        };

        if let Err(detail) = check_underlay(key, endpoint) {
            return Outcome::Rejected(Rejection::MalformedUnderlay {
                node: node.to_owned(),
                detail,
            });
        }

        let ordinal = entry.ordinal;
        self.underlay.insert(
            node.to_owned(),
            UnderlayEntry {
                ordinal,
                key: Some(key.to_owned()),
                endpoint: Some(endpoint.to_owned()),
            },
        );

        Outcome::Applied
    }

    #[must_use]
    pub fn secret(&self, name: &str) -> Option<&tg_identity::secrets::Sealed> {
        self.secrets.get(name)
    }

    #[must_use]
    pub fn secret_sizes(&self) -> Vec<(&str, usize)> {
        self.secrets
            .iter()
            .map(|(name, value)| (name.as_str(), value.plaintext_len()))
            .collect()
    }

    #[must_use]
    pub fn secret_material(&self) -> Vec<(&str, &tg_identity::secrets::Sealed)> {
        self.secrets
            .iter()
            .map(|(name, value)| (name.as_str(), value))
            .collect()
    }

    #[must_use]
    pub fn secrets_for(&self, workload: &str) -> Vec<(&str, &tg_identity::secrets::Sealed)> {
        self.secret_grants
            .iter()
            .filter(|(who, _)| who == workload)
            .filter_map(|(_, secret)| {
                self.secrets
                    .get_key_value(secret)
                    .map(|(name, value)| (name.as_str(), value))
            })
            .collect()
    }

    #[must_use]
    pub fn secret_grants(&self) -> Vec<(&str, &str)> {
        self.secret_grants
            .iter()
            .map(|(workload, secret)| (workload.as_str(), secret.as_str()))
            .collect()
    }

    #[must_use]
    pub fn registry_credentials(&self) -> Vec<(&str, &str)> {
        self.registry_credentials
            .iter()
            .map(|(registry, secret)| (registry.as_str(), secret.as_str()))
            .collect()
    }

    #[must_use]
    pub fn pullers_of(&self, registry: &str) -> Vec<String> {
        let wanted = registry.to_ascii_lowercase();
        let mut out: Vec<String> = self
            .workloads
            .values()
            .filter_map(|entry| tg_defs::from_str(&entry.document).ok())
            .flat_map(|set| set.workloads().to_vec())
            .filter(|workload| tg_model::egress::registry_of(&workload.image().reference) == wanted)
            .map(|workload| workload.name().to_owned())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    #[must_use]
    pub fn egress_of(&self, workload: &str) -> Vec<(&str, u16, Transport)> {
        self.egress
            .iter()
            .filter(|(who, _, _, _)| who == workload)
            .map(|(_, host, port, transport)| (host.as_str(), *port, *transport))
            .collect()
    }

    #[must_use]
    pub fn egress(&self) -> Vec<(&str, &str, u16, Transport)> {
        self.egress
            .iter()
            .map(|(workload, host, port, transport)| {
                (workload.as_str(), host.as_str(), *port, *transport)
            })
            .collect()
    }

    #[must_use]
    pub fn network(&self) -> Option<(&str, u8)> {
        self.network
            .as_ref()
            .map(|(cidr, prefix)| (cidr.as_str(), *prefix))
    }

    #[must_use]
    pub fn ordinal(&self, node: &str) -> Option<u32> {
        self.underlay.get(node).map(UnderlayEntry::ordinal)
    }

    #[must_use]
    pub fn underlay_of(&self, node: &str) -> Option<&UnderlayEntry> {
        self.underlay.get(node)
    }

    #[must_use]
    pub fn underlay(&self) -> Vec<(&str, &UnderlayEntry)> {
        self.underlay
            .iter()
            .map(|(name, entry)| (name.as_str(), entry))
            .collect()
    }

    #[must_use]
    pub fn next_epoch(&self) -> Epoch {
        self.next_epoch
    }

    fn check_storage(
        &self,
        incoming: &tg_defs::generated::WorkloadType,
    ) -> Result<(), tg_model::storage::StorageError> {
        let mut set = vec![incoming.clone()];

        for entry in self.workloads.values() {
            if entry.name == incoming.name() {
                continue;
            }
            // A stored document that no longer parses cannot exist — it was
            // canonicalized when it was put in. Should it occur anyway,
            // skipping is more right than refusing: the new workload cannot
            // help it.
            if let Ok(parsed) = tg_defs::from_str(&entry.document) {
                set.extend(parsed.workloads().iter().cloned());
            }
        }

        tg_model::storage::validate(&set)
    }

    fn check_conflicts(
        &self,
        incoming: &tg_defs::generated::WorkloadType,
    ) -> Result<(), tg_model::graph::ConflictError> {
        let mut set = vec![incoming.clone()];

        for entry in self.workloads.values() {
            // The new version **replaces** the old one, it does not stand
            // beside it: a workload that is submitted again must not fail at
            // its own conflict.
            if entry.name == incoming.name() {
                continue;
            }
            if let Ok(parsed) = tg_defs::from_str(&entry.document) {
                set.extend(parsed.workloads().iter().cloned());
            }
        }

        tg_model::graph::validate_conflicts(&set)
    }

    fn check_mesh_names(
        &self,
        incoming: &tg_defs::generated::WorkloadType,
    ) -> Result<(), tg_model::mesh::MeshError> {
        let mut set = vec![incoming.clone()];

        for entry in self.workloads.values() {
            // The new version **replaces** the old one: a workload that is
            // submitted again must not fail at itself.
            if entry.name == incoming.name() {
                continue;
            }
            if let Ok(parsed) = tg_defs::from_str(&entry.document) {
                set.extend(parsed.workloads().iter().cloned());
            }
        }

        tg_model::mesh::validate_names(&set)
    }

    fn delete_volume(&mut self, volume: &str, node: &str) -> Outcome {
        for entry in self.workloads.values() {
            let Ok(parsed) = tg_defs::from_str(&entry.document) else {
                continue;
            };
            for workload in parsed.workloads() {
                let declares = tg_defs::WorkloadExt::volumes(workload)
                    .iter()
                    .any(|declared| tg_defs::VolumeExt::name(declared) == volume);
                if declares {
                    return Outcome::Rejected(Rejection::VolumeInUse {
                        volume: volume.to_owned(),
                        workload: entry.name.clone(),
                    });
                }
            }
        }

        // The tombstone (ADR-0042). It arises **after** the check: a refused
        // deletion must leave no trace, otherwise a node would delete a volume
        // whose deletion the cluster refused.
        self.deleted_volumes
            .entry(node.to_owned())
            .or_default()
            .insert(volume.to_owned());

        Outcome::Applied
    }

    fn retire_tombstone(&mut self, volume: &str, node: &str) -> Outcome {
        if let Some(stones) = self.deleted_volumes.get_mut(node) {
            stones.remove(volume);
        }
        // An empty entry would be the same growing collection with different
        // content.
        self.deleted_volumes.retain(|_, stones| !stones.is_empty());
        Outcome::Applied
    }

    #[must_use]
    pub fn deleted_volumes(&self) -> Vec<(&str, Vec<&str>)> {
        self.deleted_volumes
            .iter()
            .map(|(node, volumes)| {
                (
                    node.as_str(),
                    volumes.iter().map(String::as_str).collect::<Vec<_>>(),
                )
            })
            .collect()
    }

    pub fn operators(&self) -> impl Iterator<Item = (&str, &str, &[Class])> {
        self.operators
            .iter()
            .map(|(name, entry)| (name.as_str(), entry.spki.as_str(), entry.classes.as_slice()))
    }

    #[must_use]
    pub fn snapshot_generations(&self) -> Vec<(&str, Vec<(&str, u64)>)> {
        self.snapshot_generations
            .iter()
            .map(|(node, wanted)| {
                (
                    node.as_str(),
                    wanted
                        .iter()
                        .map(|(volume, generation)| (volume.as_str(), *generation))
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }

    fn upsert_workload(&mut self, document: &str) -> Outcome {
        let set = match tg_defs::from_str(document) {
            Ok(set) => set,
            Err(err) => return malformed(&err.to_string()),
        };

        let [workload] = set.workloads() else {
            return malformed(&format!(
                "a log entry carries exactly one workload, this one {}",
                set.workloads().len()
            ));
        };

        // Ingest check per ADR-0011: "rejects unsatisfiable constraints
        // already at ingest". Only what is decidable without knowledge of the
        // cluster — a pin with several instances contradicts itself, too few
        // free racks are by contrast a question of the day and belong to the
        // planner.
        if let Err(err) = Demand::from_workload(workload).validate() {
            return Outcome::Rejected(Rejection::UnplaceableDefinition {
                workload: workload.name().to_owned(),
                detail: err.to_string(),
            });
        }

        // Ingest check per ADR-0027: **writable means exclusive, shared means
        // read-only.** It is a statement about the set of all workloads, so the
        // set is formed — the new workload plus all the others.
        //
        // That parses the stored documents. It costs, and it is the right
        // choice: the alternative would be a derived volume list beside the
        // document, that is, a second source for the same fact. An upsert is a
        // consensus write and no hot path; the saving would be bought at the
        // wrong place.
        if let Err(err) = self.check_storage(workload) {
            return Outcome::Rejected(Rejection::UnplaceableDefinition {
                workload: workload.name().to_owned(),
                detail: err.to_string(),
            });
        }

        // Ingest check per ADR-0009 / ADR-0061 determination 6: two
        // simultaneously wanted workloads of which one excludes the other are a
        // contradiction in the **intent** — and that belongs where the intent
        // arises.
        if let Err(err) = self.check_conflicts(workload) {
            return Outcome::Rejected(Rejection::UnplaceableDefinition {
                workload: workload.name().to_owned(),
                detail: err.to_string(),
            });
        }

        // Ingest check per ADR-0084: a mesh member's sidecar is called
        // `<workload>-proxy` (ADR-0059), and a declared workload of this name
        // blocks the derivation. Measured, the pair previously cost **every**
        // pass of every node with `--proxy-image` set; here it does not reach
        // the log in the first place.
        if let Err(err) = self.check_mesh_names(workload) {
            return Outcome::Rejected(Rejection::UnplaceableDefinition {
                workload: workload.name().to_owned(),
                detail: err.to_string(),
            });
        }

        // Ingest check per ADR-0117: **the class of a placed workload does
        // not change.**
        //
        // Measured, it was `Applied` in both directions, and immediately
        // afterwards the cluster granted an active-role lease. The running
        // sidecar had however never got its `--single-writer`: its command line
        // stems from the document at the start time (ADR-0059), a changed
        // declaration reaches it only at the next start (ADR-0070), and that is
        // triggered only by a decree (ADR-0085). With that the cluster carried
        // an active role nobody enforced — the reversal of ADR-0066, and every
        // display stood on green in the process.
        //
        // **"Placed" and not "runs"**: the state machine must read no observed
        // state (ADR-0004, ADR-0049). The placement is desired state, an
        // overestimation of "runs" — and thereby the safe direction: it refuses
        // more than it would have to, and never less.
        let wanted_class = workload.class().is_single_writer();
        if let Some(known) = self.workloads.get(workload.name())
            && known.single_writer != wanted_class
            && self
                .placements
                .get(workload.name())
                .is_some_and(|instances| !instances.is_empty())
        {
            return Outcome::Rejected(Rejection::UnplaceableDefinition {
                workload: workload.name().to_owned(),
                detail: format!(
                    "the class of a placed workload does not change \
                     ({} -> {}): a single writer hangs on a lease (ADR-0064), \
                     and its sidecar reins it in only from the next start on \
                     (ADR-0066) — first issue `tgctl cluster remove {}`, then \
                     declare it anew (ADR-0117)",
                    class_name(known.single_writer),
                    class_name(wanted_class),
                    workload.name()
                ),
            });
        }

        // Ingest check per ADR-0111, determination 6: **a shrinking that
        // would strand the active instance is refused.**
        //
        // The surplus *placements* this command still clears away silently
        // (further below) — that is the right treatment for a derivation of the
        // planner. The active instance is no derivation but a human's decree;
        // resetting it to zero in passing would be a role change nobody ordered,
        // and leaving it lying a workload that falls silent. Both are worse than
        // a rejection that names the way.
        let active = self.active_instance(workload.name());
        let wanted = Demand::from_workload(workload).replicas;
        if active >= wanted {
            return Outcome::Rejected(Rejection::UnplaceableDefinition {
                workload: workload.name().to_owned(),
                detail: format!(
                    "the active role is carried by instance {active}, the \
                     definition declares only {wanted} — first `tgctl cluster promote \
                     {} <instance>` (ADR-0111)",
                    workload.name()
                ),
            });
        }

        // Canonicalize instead of passing through: what lands here is by
        // construction readable again (see `tg_defs::workload_to_xml`).
        let canonical = match tg_defs::workload_to_xml(workload) {
            Ok(xml) => xml,
            Err(err) => return malformed(&err.to_string()),
        };

        // A tombstone whose volume is declared again is overtaken
        // (ADR-0042). It goes away on **all** nodes and not only where the
        // volume lay: where it will lie in future is decided by the planner, and
        // a tombstone left behind would let the agent delete there what was only
        // just wanted.
        for declared in tg_defs::WorkloadExt::volumes(workload) {
            let name = tg_defs::VolumeExt::name(declared);
            for stones in self.deleted_volumes.values_mut() {
                stones.remove(name);
            }
        }
        self.deleted_volumes.retain(|_, stones| !stones.is_empty());

        self.workloads.insert(
            workload.name().to_owned(),
            WorkloadEntry {
                name: workload.name().to_owned(),
                document: canonical,
                single_writer: workload.class().is_single_writer(),
            },
        );

        // Fewer instances than before: the surplus assignments go with it.
        // Clearing them away here instead of over a command of its own keeps the
        // state consistent in itself — there would otherwise be a moment in
        // which an assignment points at an instance the definition no longer
        // knows, and the planner would drop it at the next step anyway.
        let replicas = Demand::from_workload(workload).replicas;
        if let Some(instances) = self.placements.get_mut(workload.name()) {
            instances.retain(|instance, _| *instance < replicas);
            if instances.is_empty() {
                self.placements.remove(workload.name());
            }
        }

        Outcome::Applied
    }

    fn set_active_instance(&mut self, workload: &str, instance: u32) -> Outcome {
        let Some(entry) = self.workloads.get(workload) else {
            return Outcome::Rejected(Rejection::UnknownWorkload {
                name: workload.to_owned(),
            });
        };

        // **Only single writers** (ADR-0064, determination 8). A replicated
        // workload has no active role; naming an instance for it would be a
        // decree without effect, and a decree without effect looks to an
        // operator like an effective one.
        if !entry.single_writer {
            return Outcome::Rejected(Rejection::NotSingleWriter {
                workload: workload.to_owned(),
            });
        }

        // **An instance that does not exist is refused** (ADR-0111,
        // determination 6). The silent outcome would be the worst: the planner
        // would find no placement for it, the leader would grant nobody a lease,
        // and the workload would fall silent.
        let replicas = match declared_replicas(&entry.document) {
            Ok(replicas) => replicas,
            Err(detail) => return malformed(&detail),
        };
        if instance >= replicas {
            return Outcome::Rejected(Rejection::UnknownInstance {
                workload: workload.to_owned(),
                instance,
                replicas,
            });
        }

        // **The zero is not stored.** It is the default, and an entry that
        // records it would be indistinguishable from "never decreed" -- two
        // snapshots with the same meaning and different bytes. The determinism
        // from ADR-0005 demands the opposite.
        if instance == 0 {
            self.active_instances.remove(workload);
        } else {
            self.active_instances.insert(workload.to_owned(), instance);
        }
        Outcome::Applied
    }

    fn grant_lease(
        &mut self,
        workload: &str,
        node: &str,
        now: UtcMillis,
        expires_at: UtcMillis,
    ) -> Outcome {
        let Some(entry) = self.workloads.get(workload) else {
            return unknown_workload(workload);
        };
        if !entry.is_single_writer() {
            return Outcome::Rejected(Rejection::NotSingleWriter {
                workload: workload.to_owned(),
            });
        }
        if !self.nodes.contains_key(node) {
            return Outcome::Rejected(Rejection::UnknownNode {
                name: node.to_owned(),
            });
        }
        // **Before the fence** (ADR-0078): an implausible deadline must not
        // become a standing lease in the first place -- afterwards it holds the
        // place.
        if let Some(rejected) = implausible(workload, now, expires_at) {
            return rejected;
        }

        // The fence: as long as the standing lease applies, nobody else gets
        // it. That the holder is granted it again themselves is by contrast
        // harmless — it is the same active one, only with a new epoch.
        if let Some(lease) = self.leases.get(workload)
            && lease.is_valid_at(now)
            && lease.holder != node
        {
            return Outcome::Rejected(Rejection::LeaseHeld {
                workload: workload.to_owned(),
                holder: lease.holder.clone(),
                epoch: lease.epoch,
            });
        }

        let epoch = self.next_epoch;
        self.next_epoch = self.next_epoch.next();
        self.leases.insert(
            workload.to_owned(),
            Lease {
                holder: node.to_owned(),
                epoch,
                expires_at,
            },
        );

        Outcome::LeaseGranted { epoch }
    }

    fn renew_lease(
        &mut self,
        workload: &str,
        node: &str,
        now: UtcMillis,
        expires_at: UtcMillis,
    ) -> Outcome {
        let Some(lease) = self.leases.get_mut(workload) else {
            return Outcome::Rejected(Rejection::NoLease {
                workload: workload.to_owned(),
            });
        };

        if lease.holder != node {
            return Outcome::Rejected(Rejection::NotHolder {
                workload: workload.to_owned(),
                holder: lease.holder.clone(),
            });
        }

        // Whoever missed the gap must assume that another became active in
        // it — and therefore needs a new epoch, that is, a grant and not a
        // renewal.
        if !lease.is_valid_at(now) {
            return Outcome::Rejected(Rejection::LeaseExpired {
                workload: workload.to_owned(),
            });
        }
        // **Here too** (ADR-0078). The renewal sets `expires_at` unexamined --
        // and it is the **frequent** path: every five seconds per single
        // writer, against a grant at every role change.
        if let Some(rejected) = implausible(workload, now, expires_at) {
            return rejected;
        }

        lease.expires_at = expires_at;
        Outcome::LeaseRenewed { epoch: lease.epoch }
    }

    fn first_unknown_workload<'a>(
        &self,
        names: impl IntoIterator<Item = &'a String>,
    ) -> Option<Outcome> {
        names
            .into_iter()
            .find(|name| !self.workloads.contains_key(*name))
            .map(|name| unknown_workload(name))
    }
}

fn implausible(workload: &str, now: UtcMillis, expires_at: UtcMillis) -> Option<Outcome> {
    let granted = expires_at.get().saturating_sub(now.get());
    (granted > tg_model::lease::LEASE_MILLIS).then(|| {
        Outcome::Rejected(Rejection::ImplausibleLease {
            workload: workload.to_owned(),
            granted_millis: granted,
            limit_millis: tg_model::lease::LEASE_MILLIS,
        })
    })
}

const MAX_DETAIL: usize = 512;

fn declared_replicas(document: &str) -> Result<u32, String> {
    let set = tg_defs::from_str(document).map_err(|err| err.to_string())?;
    let [workload] = set.workloads() else {
        return Err(format!(
            "a stored entry carries exactly one workload, this one {}",
            set.workloads().len()
        ));
    };
    Ok(Demand::from_workload(workload).replicas)
}

const fn class_name(single_writer: bool) -> &'static str {
    if single_writer {
        "single-writer"
    } else {
        "replicated"
    }
}

fn malformed(detail: &str) -> Outcome {
    let detail = match detail.char_indices().nth(MAX_DETAIL) {
        Some((cut, _)) => format!("{} […]", &detail[..cut]),
        None => detail.to_owned(),
    };

    Outcome::Rejected(Rejection::MalformedDocument { detail })
}

fn cut(value: String) -> String {
    match value.char_indices().nth(MAX_DETAIL) {
        Some((at, _)) => format!("{} […]", &value[..at]),
        None => value,
    }
}

fn unusable_target(host: &str, transport: Transport) -> Option<Rejection> {
    let refuse = |detail: &str| {
        Some(Rejection::UnusableEgressTarget {
            host: host.to_owned(),
            detail: detail.to_owned(),
        })
    };

    match tg_model::egress::target_form(host) {
        None => refuse(
            "no DNS name; a wildcard is exactly '*.<name>.<tld>' \
             — a star as a whole leftmost label (ADR-0124)",
        ),
        Some(tg_model::egress::TargetForm::Wildcard) if transport == Transport::Udp => refuse(
            "for 'udp' there is no wildcard: the node must resolve the name \
             itself (ADR-0092), and an unresolvable target freezes its whole \
             rule set",
        ),
        Some(_) => None,
    }
}

// **An `allow` and no split**, for the same reason as at `Display for
// Rejection` and `ClusterState::apply`: the exhaustiveness *is* the purpose. A
// split `match` would need a non-exhaustive first part that delegates to a
// second -- then the compiler no longer warns at a new variant, and a quoted
// value would stay unbounded. Exactly that this project has measured four
// times.
#[allow(clippy::too_many_lines)]
fn bounded(rejection: Rejection) -> Rejection {
    match rejection {
        Rejection::MalformedDocument { detail } => Rejection::MalformedDocument {
            detail: cut(detail),
        },
        Rejection::UnknownWorkload { name } => Rejection::UnknownWorkload { name: cut(name) },
        Rejection::UnknownSecret { name } => Rejection::UnknownSecret { name: cut(name) },
        Rejection::SecretInUse { name, workload } => Rejection::SecretInUse {
            name: cut(name),
            workload: cut(workload),
        },
        Rejection::SecretUsedByRegistry { name, registry } => Rejection::SecretUsedByRegistry {
            name: cut(name),
            registry: cut(registry),
        },
        Rejection::UnknownNode { name } => Rejection::UnknownNode { name: cut(name) },
        Rejection::UnusableEgressTarget { host, detail } => Rejection::UnusableEgressTarget {
            host: cut(host),
            detail: cut(detail),
        },
        Rejection::NotSingleWriter { workload } => Rejection::NotSingleWriter {
            workload: cut(workload),
        },
        Rejection::RetiredCommand { kind, detail } => Rejection::RetiredCommand {
            kind: cut(kind),
            detail: cut(detail),
        },
        Rejection::UnknownInstance {
            workload,
            instance,
            replicas,
        } => Rejection::UnknownInstance {
            workload: cut(workload),
            instance,
            replicas,
        },
        Rejection::LeaseHeld {
            workload,
            holder,
            epoch,
        } => Rejection::LeaseHeld {
            workload: cut(workload),
            holder: cut(holder),
            epoch,
        },
        Rejection::NoLease { workload } => Rejection::NoLease {
            workload: cut(workload),
        },
        Rejection::NotHolder { workload, holder } => Rejection::NotHolder {
            workload: cut(workload),
            holder: cut(holder),
        },
        Rejection::LeaseExpired { workload } => Rejection::LeaseExpired {
            workload: cut(workload),
        },
        // **The two numbers stay as they are.** What is truncated is what a
        // sender can determine the length of; a `u64` they cannot make longer
        // than a `u64`.
        Rejection::ImplausibleLease {
            workload,
            granted_millis,
            limit_millis,
        } => Rejection::ImplausibleLease {
            workload: cut(workload),
            granted_millis,
            limit_millis,
        },
        Rejection::NoInvitation { node } => Rejection::NoInvitation { node: cut(node) },
        Rejection::VolumeInUse { volume, workload } => Rejection::VolumeInUse {
            volume: cut(volume),
            workload: cut(workload),
        },
        Rejection::SnapshotGenerationNotAdvancing {
            volume,
            node,
            have,
            wanted,
        } => Rejection::SnapshotGenerationNotAdvancing {
            volume: cut(volume),
            node: cut(node),
            have,
            wanted,
        },
        Rejection::NotAdmitted { node } => Rejection::NotAdmitted { node: cut(node) },
        Rejection::MalformedUnderlay { node, detail } => Rejection::MalformedUnderlay {
            node: cut(node),
            detail: cut(detail),
        },
        Rejection::MalformedSecret { name } => Rejection::MalformedSecret { name: cut(name) },
        Rejection::MalformedOperator { operator } => Rejection::MalformedOperator {
            operator: cut(operator),
        },
        Rejection::MalformedNetwork { cidr, detail } => Rejection::MalformedNetwork {
            cidr: cut(cidr),
            detail: cut(detail),
        },
        Rejection::ClusterFull { node, capacity } => Rejection::ClusterFull {
            node: cut(node),
            capacity,
        },
        Rejection::InvitationExpired { node, expired_at } => Rejection::InvitationExpired {
            node: cut(node),
            expired_at,
        },
        Rejection::GenerationNotAdvancing {
            node,
            kind,
            have,
            wanted,
        } => Rejection::GenerationNotAdvancing {
            node: cut(node),
            kind,
            have,
            wanted,
        },
        Rejection::WorkloadGenerationNotAdvancing {
            workload,
            instance,
            have,
            wanted,
        } => Rejection::WorkloadGenerationNotAdvancing {
            workload: cut(workload),
            instance,
            have,
            wanted,
        },
        Rejection::UnexpectedTrust { node } => Rejection::UnexpectedTrust { node: cut(node) },
        Rejection::UnplaceableDefinition { workload, detail } => Rejection::UnplaceableDefinition {
            workload: cut(workload),
            detail: cut(detail),
        },
    }
}

fn unknown_workload(name: &str) -> Outcome {
    Outcome::Rejected(Rejection::UnknownWorkload {
        name: name.to_owned(),
    })
}

const X25519_KEY_LEN: usize = 32;

fn check_underlay(key: &str, endpoint: &str) -> Result<(), String> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|err| format!("the key is no base64: {err}"))?;
    // **The length stands here and not in `tg-net`**, and that is no
    // duplication out of carelessness: `tg-consensus` must not link
    // `tg_net::wireguard` (netlink, `nft`), so `KEY_LEN` is not reachable from
    // here. The number moreover belongs to X25519 and not to us -- it cannot
    // change without it being a different curve.
    if bytes.len() != X25519_KEY_LEN {
        return Err(format!(
            "an X25519 key has {X25519_KEY_LEN} bytes, this one has {}",
            bytes.len()
        ));
    }

    // Expressly `SocketAddr` and no name: a resolution in consensus would not
    // be deterministic — two replicas would possibly get different addresses and
    // thereby different states.
    let address: std::net::SocketAddr = endpoint.parse().map_err(|_| {
        format!(
            "'{}' is no endpoint made of an address and a port",
            endpoint.escape_debug()
        )
    })?;
    if address.port() == 0 {
        return Err("port 0 is no endpoint".to_owned());
    }

    Ok(())
}
