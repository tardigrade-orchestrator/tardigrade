//! The log command set: the boundary between desired state and
//! consensus-critical cluster state, as a type and as a wire format.
//!
//! Two things are nailed down here, and both are contracts, not implementation
//! details:
//!
//! 1. **The layer assignment.** The Raft log carries desired state and
//!    consensus-critical cluster state — and expressly does *not* carry the
//!    actual status. This assignment is the reason why this command set
//!    exists at all.
//! 2. **The wire format.** The log is the tamper-evident audit substrate
//!    with a retention obligation. An entry written two years ago must
//!    still be readable today. The golden tests below fail as soon as a field
//!    name or a variant name changes — precisely then it is a deliberate format
//!    decision and no refactoring.

use tg_consensus::wire::decode_command;
use tg_consensus::{
    Actor, Class, Command, Layer, Resources, Submission, Topology, UtcMillis, wire,
};
use tg_model::egress::Transport;

/// One example per variant, together with the expected wire format.
///
/// The list is at the same time the inventory of the command set: it must be
/// complete, otherwise the reconciliation with [`Command::KINDS`] below does not
/// take hold.
///
/// # Returns
///
/// A pair for every `Command` variant: an example value and its pinned JSON
/// wire form.
// The inventory is a list, not a procedure: it is long because the command set
// is. Splitting it up would make it less readable, not more.
#[allow(clippy::too_many_lines)]
fn samples() -> Vec<(Command, &'static str)> {
    vec![
        // --- Desired state ---
        (
            Command::UpsertWorkload {
                document: "<xml/>".to_owned(),
            },
            r#"{"upsert_workload":{"document":"<xml/>"}}"#,
        ),
        (
            Command::RemoveWorkload {
                name: "api".to_owned(),
            },
            r#"{"remove_workload":{"name":"api"}}"#,
        ),
        (
            Command::AllowTraffic {
                from: "api".to_owned(),
                to: "db".to_owned(),
            },
            r#"{"allow_traffic":{"from":"api","to":"db"}}"#,
        ),
        (
            Command::RevokeTraffic {
                from: "api".to_owned(),
                to: "db".to_owned(),
            },
            r#"{"revoke_traffic":{"from":"api","to":"db"}}"#,
        ),
        (
            Command::AllowEgress {
                workload: "api".to_owned(),
                host: "s3.example.com".to_owned(),
                port: 443,
                transport: Transport::Tcp,
            },
            r#"{"allow_egress":{"workload":"api","host":"s3.example.com","port":443,"transport":"tcp"}}"#,
        ),
        (
            Command::RevokeEgress {
                workload: "api".to_owned(),
                host: "s3.example.com".to_owned(),
                port: 443,
                transport: Transport::Tcp,
            },
            r#"{"revoke_egress":{"workload":"api","host":"s3.example.com","port":443,"transport":"tcp"}}"#,
        ),
        (
            // **A pinned envelope**, not a freshly sealed one: the nonce arises
            // per value, and a generated one would yield a different string
            // here every time. The wire form is the subject, not the crypto.
            Command::PutSecret {
                name: "s3-key".to_owned(),
                value: tg_identity::secrets::Sealed {
                    ciphertext: vec![1, 2, 3],
                    nonce: vec![4, 5, 6],
                },
            },
            r#"{"put_secret":{"name":"s3-key","value":{"ciphertext":[1,2,3],"nonce":[4,5,6]}}}"#,
        ),
        (
            Command::RemoveSecret {
                name: "s3-key".to_owned(),
            },
            r#"{"remove_secret":{"name":"s3-key"}}"#,
        ),
        (
            Command::AllowSecret {
                workload: "api".to_owned(),
                secret: "s3-key".to_owned(),
            },
            r#"{"allow_secret":{"workload":"api","secret":"s3-key"}}"#,
        ),
        (
            Command::RevokeSecret {
                workload: "api".to_owned(),
                secret: "s3-key".to_owned(),
            },
            r#"{"revoke_secret":{"workload":"api","secret":"s3-key"}}"#,
        ),
        (
            Command::SetRegistryCredential {
                registry: "registry.test".to_owned(),
                secret: "s3-key".to_owned(),
            },
            r#"{"set_registry_credential":{"registry":"registry.test","secret":"s3-key"}}"#,
        ),
        (
            Command::ClearRegistryCredential {
                registry: "registry.test".to_owned(),
            },
            r#"{"clear_registry_credential":{"registry":"registry.test"}}"#,
        ),
        (
            Command::UpsertNode {
                name: "node-1".to_owned(),
                topology: Topology {
                    site: "fra".to_owned(),
                    hall: "h1".to_owned(),
                    rack: "r7".to_owned(),
                },
                capacity: tg_consensus::Resources::default(),
                reserved: tg_consensus::Resources::default(),
                source: tg_consensus::Origin::Operator,
            },
            r#"{"upsert_node":{"name":"node-1","topology":{"site":"fra","hall":"h1","rack":"r7"},"capacity":{},"reserved":{},"source":"operator"}}"#,
        ),
        (
            Command::SetSchedulability {
                node: "node-1".to_owned(),
                mode: tg_consensus::Schedulability::Draining,
            },
            r#"{"set_schedulability":{"node":"node-1","mode":"draining"}}"#,
        ),
        (
            Command::SetAttachment {
                node: "node-1".to_owned(),
                mode: tg_consensus::Attachment::Detached,
            },
            r#"{"set_attachment":{"node":"node-1","mode":"detached"}}"#,
        ),
        (
            Command::SetKeyGeneration {
                node: "node-1".to_owned(),
                kind: tg_consensus::KeyKind::Underlay,
                generation: 3,
            },
            r#"{"set_key_generation":{"node":"node-1","kind":"underlay","generation":3}}"#,
        ),
        (
            Command::SetWorkloadGeneration {
                workload: "api".to_owned(),
                instance: Some(1),
                generation: 4,
            },
            r#"{"set_workload_generation":{"workload":"api","instance":1,"generation":4}}"#,
        ),
        (
            Command::SetCapacityPolicy {
                policy: tg_consensus::CapacityPolicy::default().with(
                    "cpu-millicores",
                    tg_consensus::CapacityRule {
                        subtract: 2000,
                        percent: 80,
                        cap: None,
                        reserve: 500,
                    },
                ),
            },
            r#"{"set_capacity_policy":{"policy":{"cpu-millicores":{"subtract":2000,"percent":80,"cap":null,"reserve":500}}}}"#,
        ),
        (
            Command::SetRotationPolicy {
                policy: tg_consensus::RotationPolicy::default()
                    .with(tg_consensus::KeyKind::Underlay, 90),
            },
            r#"{"set_rotation_policy":{"policy":{"underlay":90}}}"#,
        ),
        (
            Command::RemoveNode {
                name: "node-1".to_owned(),
            },
            r#"{"remove_node":{"name":"node-1"}}"#,
        ),
        // --- Consensus-critical cluster state ---
        (
            Command::AssignPlacement {
                workload: "api".to_owned(),
                node: "node-1".to_owned(),
                instance: 0,
            },
            r#"{"assign_placement":{"workload":"api","instance":0,"node":"node-1"}}"#,
        ),
        (
            Command::ClearPlacement {
                workload: "api".to_owned(),
            },
            r#"{"clear_placement":{"workload":"api"}}"#,
        ),
        (
            Command::GrantLease {
                workload: "ledger".to_owned(),
                node: "node-1".to_owned(),
                now: UtcMillis::new(1_000),
                expires_at: UtcMillis::new(16_000),
            },
            r#"{"grant_lease":{"workload":"ledger","node":"node-1","now":1000,"expires_at":16000}}"#,
        ),
        (
            Command::RenewLease {
                workload: "ledger".to_owned(),
                node: "node-1".to_owned(),
                now: UtcMillis::new(10_000),
                expires_at: UtcMillis::new(25_000),
            },
            r#"{"renew_lease":{"workload":"ledger","node":"node-1","now":10000,"expires_at":25000}}"#,
        ),
        (
            Command::SetActiveInstance {
                workload: "ledger".to_owned(),
                instance: 1,
            },
            r#"{"set_active_instance":{"workload":"ledger","instance":1}}"#,
        ),
        (
            // The log carries the **hash** of the token, never the token.
            Command::InviteNode {
                node: "node-1".to_owned(),
                digest: "abc123".to_owned(),
                expires_at: 1_800_000_900,
            },
            r#"{"invite_node":{"node":"node-1","digest":"abc123","expires_at":1800000900}}"#,
        ),
        (
            Command::AdmitNode {
                node: "node-1".to_owned(),
                spki: "MCowBQYDK2VwAyEA".to_owned(),
                at: 1_800_000_000,
            },
            r#"{"admit_node":{"node":"node-1","spki":"MCowBQYDK2VwAyEA","at":1800000000}}"#,
        ),
        (
            Command::RegisterTrust {
                node: "node-1".to_owned(),
                bundle: "-----BEGIN CERTIFICATE-----".to_owned(),
            },
            r#"{"register_trust":{"node":"node-1","bundle":"-----BEGIN CERTIFICATE-----"}}"#,
        ),
        (
            Command::RotateTrust {
                node: "node-1".to_owned(),
                from: "YWx0".to_owned(),
                to: "bmV1".to_owned(),
            },
            r#"{"rotate_trust":{"node":"node-1","from":"YWx0","to":"bmV1"}}"#,
        ),
        (
            Command::RevokeTrust {
                node: "node-1".to_owned(),
            },
            r#"{"revoke_trust":{"node":"node-1"}}"#,
        ),
        (
            Command::AnnounceUnderlay {
                node: "node-1".to_owned(),
                key: "iOnLpv2AL2r0YKGCXpXKaVUsBpVYAyLpJvGVc0nlDXo=".to_owned(),
                endpoint: "203.0.113.7:51820".to_owned(),
                at: 1_756_000_000,
            },
            r#"{"announce_underlay":{"node":"node-1","key":"iOnLpv2AL2r0YKGCXpXKaVUsBpVYAyLpJvGVc0nlDXo=","endpoint":"203.0.113.7:51820","at":1756000000}}"#,
        ),
        (
            Command::SetClusterNetwork {
                cidr: "10.42.0.0/16".to_owned(),
                node_prefix: 24,
            },
            r#"{"set_cluster_network":{"cidr":"10.42.0.0/16","node_prefix":24}}"#,
        ),
        (
            Command::SetSidecarOverhead {
                resources: Resources::default().with(Resources::CPU_MILLICORES, 50),
            },
            r#"{"set_sidecar_overhead":{"resources":{"cpu-millicores":50}}}"#,
        ),
        (
            Command::DeleteVolume {
                volume: "ledger-data-0".to_owned(),
                node: "node-1".to_owned(),
                at: 1_756_000_000,
            },
            r#"{"delete_volume":{"volume":"ledger-data-0","node":"node-1","at":1756000000}}"#,
        ),
        (
            Command::SnapshotVolume {
                volume: "ledger-data-0".to_owned(),
                node: "node-1".to_owned(),
                generation: 4,
            },
            r#"{"snapshot_volume":{"volume":"ledger-data-0","node":"node-1","generation":4}}"#,
        ),
        (
            Command::RetireTombstone {
                volume: "ledger-data-0".to_owned(),
                node: "node-1".to_owned(),
            },
            r#"{"retire_tombstone":{"volume":"ledger-data-0","node":"node-1"}}"#,
        ),
        (
            // **The field `classes` is a format addition to the command set.**
            // It is a break -- `Command` carries `deny_unknown_fields`, and an
            // old reader refuses the entry. With commands that is **wanted**
            // (`unknown_commands_are_rejected`: whoever understands a command
            // half drifts), and it belongs in a coordinated rollout window
            // together with any other format changes made at the same time.
            //
            // The expected string is therefore deliberately brought along and
            // the break not kept quiet.
            Command::EnrolOperator {
                operator: "dana".to_owned(),
                spki: "AAAA".to_owned(),
                classes: vec![Class::Read, Class::Write],
            },
            r#"{"enrol_operator":{"operator":"dana","spki":"AAAA","classes":["read","write"]}}"#,
        ),
        (
            Command::RevokeOperator {
                operator: "dana".to_owned(),
            },
            r#"{"revoke_operator":{"operator":"dana"}}"#,
        ),
    ]
}

/// Checks the wire format of every variant, character for character.
///
/// If this test fails, an old log entry is no longer readable. Because the
/// log is a retention-bound audit substrate, that is no refactoring damage
/// but a retention problem.
#[test]
fn every_command_has_a_pinned_wire_form() {
    for (command, expected) in samples() {
        let encoded = wire::encode_command(&command).expect("encodable");
        assert_eq!(
            encoded,
            expected,
            "the wire format of {} deviates",
            command.kind()
        );
    }
}

/// Checks the pinned wire format of the submission envelope around a command.
///
/// The command inside it is byte for byte the same as without the envelope;
/// that is the assurance the audit export hangs on.
///
/// **Without an actor the key is missing entirely** instead of being `null`:
/// "no human was here" and "the actor is null" would otherwise yield two
/// different digests for what should be the same fact.
#[test]
fn the_submission_has_a_pinned_wire_form() {
    let command = Command::RemoveWorkload {
        name: "api".to_owned(),
    };
    let bare = wire::encode_command(&command).expect("encodable");

    let cluster = serde_json::to_string(&Submission::internal(command.clone())).expect("encodable");
    assert_eq!(
        cluster,
        format!(r#"{{"command":{bare}}}"#),
        "without an actor the key is missing -- see the doc block"
    );

    let human = serde_json::to_string(&Submission {
        actor: Some(Actor::LocalUid(1000)),
        command,
    })
    .expect("encodable");
    assert_eq!(
        human,
        format!(r#"{{"actor":{{"local_uid":1000}},"command":{bare}}}"#),
        "the wire format of the envelope has changed"
    );
}

/// And back. Without that the log would be writable but not readable.
#[test]
fn every_command_survives_a_round_trip() {
    for (command, wire_form) in samples() {
        let decoded = wire::decode_command(wire_form).expect("decodable");
        assert_eq!(decoded, command);
    }
}

/// The tripwire: a new command breaks **this file**.
///
/// An exhaustive `match` and nothing else. It has no value apart from the one:
/// whoever adds a variant does not get past this place and sees the list they
/// would otherwise forget — `KINDS` and [`samples`].
///
/// **There are three lists**, and that is the actual finding: `Command::KINDS`,
/// [`samples`] here, and one more in `tests/invariants.rs`. None of them caught
/// that `set_schedulability` was missing for a whole version — each compares
/// only against another, and whoever forgets all three gets through.
///
/// **What the tripwire does not deliver**, and that belongs to it: it enforces a
/// `match` arm, not an entry in the lists. Rust cannot enumerate variants, and
/// pulling in a dependency to do that would not be worth it for a test; the
/// completeness of the lists stays a matter of attention. The difference is
/// that the attention is now **demanded**.
///
/// # Parameters
///
/// - `command`: the command whose variant name to report.
///
/// # Returns
///
/// The wire-format kind name for `command`'s variant.
fn tripwire(command: &Command) -> &'static str {
    match command {
        Command::UpsertWorkload { .. } => "upsert_workload",
        Command::RemoveWorkload { .. } => "remove_workload",
        Command::AllowTraffic { .. } => "allow_traffic",
        Command::RevokeTraffic { .. } => "revoke_traffic",
        Command::AllowEgress { .. } => "allow_egress",
        Command::RevokeEgress { .. } => "revoke_egress",
        Command::PutSecret { .. } => "put_secret",
        Command::RemoveSecret { .. } => "remove_secret",
        Command::AllowSecret { .. } => "allow_secret",
        Command::RevokeSecret { .. } => "revoke_secret",
        Command::SetRegistryCredential { .. } => "set_registry_credential",
        Command::ClearRegistryCredential { .. } => "clear_registry_credential",
        Command::UpsertNode { .. } => "upsert_node",
        Command::RemoveNode { .. } => "remove_node",
        Command::SetSchedulability { .. } => "set_schedulability",
        Command::SetAttachment { .. } => "set_attachment",
        Command::SetKeyGeneration { .. } => "set_key_generation",
        Command::SetWorkloadGeneration { .. } => "set_workload_generation",
        Command::SetCapacityPolicy { .. } => "set_capacity_policy",
        Command::SetRotationPolicy { .. } => "set_rotation_policy",
        Command::AssignPlacement { .. } => "assign_placement",
        Command::ClearPlacement { .. } => "clear_placement",
        Command::GrantLease { .. } => "grant_lease",
        Command::RenewLease { .. } => "renew_lease",
        Command::SetActiveInstance { .. } => "set_active_instance",
        Command::InviteNode { .. } => "invite_node",
        Command::AdmitNode { .. } => "admit_node",
        Command::RegisterTrust { .. } => "register_trust",
        Command::RotateTrust { .. } => "rotate_trust",
        Command::RevokeTrust { .. } => "revoke_trust",
        Command::AnnounceUnderlay { .. } => "announce_underlay",
        Command::SetClusterNetwork { .. } => "set_cluster_network",
        Command::SetSidecarOverhead { .. } => "set_sidecar_overhead",
        Command::DeleteVolume { .. } => "delete_volume",
        Command::SnapshotVolume { .. } => "snapshot_volume",
        Command::RetireTombstone { .. } => "retire_tombstone",
        Command::EnrolOperator { .. } => "enrol_operator",
        Command::RevokeOperator { .. } => "revoke_operator",
    }
}

/// The inventory: every variant is carried exactly once in
/// [`Command::KINDS`].
///
/// **The comment here once read differently** and claimed the test covered "the
/// other direction" — that the inventory does not fall behind the type. It did
/// not: it compares [`samples`] with [`Command::KINDS`], and those are **two
/// hand-maintained lists**. Whoever forgets both gets through — and exactly that
/// way `set_schedulability` was missing from `KINDS` for a whole version without
/// anything turning red.
///
/// What helps now is [`tripwire`]: an exhaustive `match` that no longer lets
/// this file compile as soon as a command is added.
#[test]
fn the_inventory_matches_the_command_set() {
    let samples = samples();

    assert_eq!(
        samples.len(),
        Command::KINDS.len(),
        "inventory and sample set are of different size"
    );

    for (command, _) in &samples {
        assert_eq!(
            tripwire(command),
            command.kind(),
            "the tripwire and `kind()` disagree"
        );

        let entry = Command::KINDS
            .iter()
            .find(|(kind, _)| *kind == command.kind());

        let (_, layer) =
            entry.unwrap_or_else(|| panic!("{} is missing from KINDS", command.kind()));
        assert_eq!(
            *layer,
            command.layer(),
            "{} is classified differently in KINDS than in the type",
            command.kind()
        );
    }
}

/// The desired-state half of the layer boundary, by name.
///
/// Desired state covers workload specs, the dependency graph, `may_talk`
/// authorization edges, and topology. The dependency graph does not stand
/// here as a command of its own — it is part of the workload definition and
/// comes into the log with it.
#[test]
fn desired_state_commands_are_exactly_those_from_adr_0004() {
    let desired: Vec<&str> = Command::KINDS
        .iter()
        .filter(|(_, layer)| *layer == Layer::DesiredState)
        .map(|(kind, _)| *kind)
        .collect();

    assert_eq!(
        desired,
        vec![
            "upsert_workload",
            "remove_workload",
            "allow_traffic",
            "revoke_traffic",
            "allow_egress",
            "revoke_egress",
            // A secret and who may read it are desired state: an operator
            // declares them, and the log **never** carries a plaintext.
            "put_secret",
            "remove_secret",
            "allow_secret",
            "revoke_secret",
            // And which secret applies for a registry -- a statement about
            // the registry, cluster-wide once.
            "set_registry_credential",
            "clear_registry_credential",
            "upsert_node",
            "remove_node",
            // Both belong to "topology": a cordon and a capacity policy are
            // an operator's decrees about nodes, just like `upsert_node`.
            "set_schedulability",
            "set_attachment",
            "set_key_generation",
            // **When** a declaration takes effect is decreed by an operator
            // -- the second half of the pair whose first is `upsert_workload`.
            "set_workload_generation",
            // **Which** instance carries the active role is decreed by an
            // operator. The lease over it is `ClusterState` and stays so --
            // the one is the intent, the other its enforcement.
            "set_active_instance",
            "set_capacity_policy",
            "set_rotation_policy",
            "set_cluster_network",
            // What a sidecar costs is declared by an operator -- were it
            // measured instead, it would be eventual and would make the
            // planner non-deterministic.
            "set_sidecar_overhead",
            "delete_volume",
            // And **when** a snapshot arises is decreed by an operator. The
            // generation is desired state like any other.
            "snapshot_volume",
            "retire_tombstone",
            // Who may administer is an operator's **decree** -- like
            // `upsert_node`, and expressly nothing a policy may write.
            "enrol_operator",
            "revoke_operator",
        ]
    );
}

/// And the consensus-critical half.
///
/// This layer covers placement assignments, active-role leases with fencing
/// epochs, membership, and trust registration and its bundle.
/// **Membership is deliberately missing here:** `openraft` manages that itself
/// over `EntryPayload::Membership`; a command of its own would be a second,
/// competing source.
#[test]
fn cluster_state_commands_are_exactly_those_from_adr_0004() {
    let cluster: Vec<&str> = Command::KINDS
        .iter()
        .filter(|(_, layer)| *layer == Layer::ClusterState)
        .map(|(kind, _)| *kind)
        .collect();

    assert_eq!(
        cluster,
        vec![
            "assign_placement",
            "clear_placement",
            "grant_lease",
            "renew_lease",
            "invite_node",
            "admit_node",
            "register_trust",
            "rotate_trust",
            "revoke_trust",
            "announce_underlay",
        ]
    );
}

/// There is no command for the actual status — that is the core of the
/// boundary.
///
/// "running/crashed, health, metrics, last-seen" are eventual and go
/// straight into the projection instead of the log. Were that to come into
/// the log, every heartbeat would be a consensus round and the audit trail
/// full of noise.
#[test]
fn no_command_carries_actual_state() {
    for (kind, _) in Command::KINDS {
        for forbidden in ["health", "actual", "heartbeat", "metric", "last_seen"] {
            assert!(
                !kind.contains(forbidden),
                "'{kind}' smells of actual state -- that does not belong in the log"
            );
        }
    }
}

/// An unknown variant name is refused, not silently discarded. A log entry from
/// a newer version must not run through as "nothing to do".
#[test]
fn unknown_commands_are_rejected() {
    assert!(wire::decode_command(r#"{"reticulate_splines":{}}"#).is_err());
}

/// An unknown field likewise: otherwise an old binary swallows an extended
/// command and applies it half — diverging state machines.
#[test]
fn unknown_fields_are_rejected() {
    assert!(wire::decode_command(r#"{"remove_workload":{"name":"api","force":true}}"#).is_err());
}

/// **The log's alphabet is append-only** — a command kind can never be removed
/// again.
///
/// `clear_placement` and `register_trust` might look like candidates for
/// removal: both have no producer today — placements are cleared by
/// `RemoveWorkload`, trust arises at `AdmitNode` and changes over
/// `RotateTrust`. **That impression is wrong**, and consequentially so:
///
/// - The log is kept **forever**, and a restart materializes the
///   projection from it.
/// - An unknown command is **refused hard**, not skipped
///   (`unknown_commands_are_rejected` beside it).
///
/// Whoever removes a variant thereby makes every log that ever contained it
/// unreadable — and this node no longer comes up.
///
/// **The lines here stand deliberately as literals** and are not derived from
/// the type: a derivation would disappear with the variant, and the test would
/// stay green. This list is append-only, like what it protects.
#[test]
fn a_command_kind_can_never_be_removed() {
    for line in [
        r#"{"clear_placement":{"workload":"api"}}"#,
        r#"{"register_trust":{"node":"node-1","bundle":"-----BEGIN CERTIFICATE-----"}}"#,
    ] {
        assert!(
            decode_command(line).is_ok(),
            "'{line}' must stay readable -- otherwise a node with an old log no \
             longer comes up (ADR-0020)"
        );
    }
}

/// **Entries written before later fields existed are still readable.**
///
/// Two fields were added after the fact: `capacity` at the node and
/// `instance` at the assignment. Both carry `#[serde(default)]`, and this
/// test is the reason for it. The Raft log is an audit substrate with a
/// retention obligation — an entry from yesterday must still be readable in
/// years. A new mandatory field would have made every old entry unreadable and
/// thereby devalued the log as evidence.
///
/// The strings here are the **literal** pins from before those fields
/// existed. They must never change; they describe what lies on the disk.
#[test]
fn entries_written_before_phase_six_are_still_readable() {
    let old_node =
        r#"{"upsert_node":{"name":"node-1","topology":{"site":"fra","hall":"h1","rack":"r7"}}}"#;
    let decoded = decode_command(old_node).expect("an old entry must stay readable");

    match decoded {
        Command::UpsertNode {
            name,
            topology,
            capacity,
            reserved,
            source,
        } => {
            assert_eq!(name, "node-1");
            assert_eq!(topology.rack, "r7");
            assert!(
                capacity.is_empty(),
                "an old node has no known capacity -- and must invent none"
            );
            // The same for the reserve field: an entry from before its
            // introduction has none, and **zero is the right default** -- an
            // invented reserve would retroactively take room from the planner.
            assert!(
                reserved.is_empty(),
                "an old node has no reserve -- and must invent none"
            );
            // And the origin field: an entry from a version that did not
            // know this distinction was one a **human** issued -- back then
            // there was nobody else. `Operator` is therefore the right default
            // and not merely the first variant.
            assert_eq!(source, tg_consensus::Origin::Operator);
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // And the egress permission from before the transport field existed: it
    // carried no transport and meant **tcp** -- the only one there was. A
    // different default would retroactively change what an operator permitted.
    let old_egress = r#"{"allow_egress":{"workload":"api","host":"s3.example.com","port":443}}"#;
    let decoded = decode_command(old_egress).expect("an old entry must stay readable");

    match decoded {
        Command::AllowEgress {
            workload,
            host,
            port,
            transport,
        } => {
            assert_eq!(workload, "api");
            assert_eq!(host, "s3.example.com");
            assert_eq!(port, 443);
            assert_eq!(
                transport,
                Transport::Tcp,
                "a permission from before ADR-0092 meant tcp -- any other \
                 default would retroactively change what was permitted"
            );
        }
        other => panic!("wrong variant: {other:?}"),
    }

    let old_placement = r#"{"assign_placement":{"workload":"api","node":"node-1"}}"#;
    let decoded = decode_command(old_placement).expect("an old entry must stay readable");

    match decoded {
        Command::AssignPlacement {
            workload,
            instance,
            node,
        } => {
            assert_eq!(workload, "api");
            assert_eq!(node, "node-1");
            assert_eq!(
                instance, 0,
                "before phase 6 there was exactly one instance per workload, and that is the zeroth"
            );
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

/// And the counter-direction: an old entry yields the same state as the new one
/// when nothing additional stands in it.
///
/// Without that "readable" would be too little — it could be readable and
/// nevertheless mean something else.
#[test]
fn an_old_entry_means_the_same_as_its_new_form() {
    let old = decode_command(r#"{"assign_placement":{"workload":"api","node":"node-1"}}"#)
        .expect("readable");
    let new =
        decode_command(r#"{"assign_placement":{"workload":"api","instance":0,"node":"node-1"}}"#)
            .expect("readable");

    assert_eq!(old, new);
}

// --- What a policy may write --------------------------------------------

/// **The prohibition list on what an autonomous policy may write.**
///
/// A policy may write no command that places or displaces, revokes trust,
/// deregisters a node or deletes data. That is the barrier which makes every
/// **future** policy checkable without knowing it — and that is why it stands at
/// the command set and not with a caller.
#[test]
fn a_policy_may_not_place_revoke_remove_or_delete() {
    let forbidden = [
        Command::AssignPlacement {
            workload: "api".to_owned(),
            instance: 0,
            node: "node-1".to_owned(),
        },
        Command::RevokeTrust {
            node: "node-1".to_owned(),
        },
        Command::RemoveNode {
            name: "node-1".to_owned(),
        },
        Command::DeleteVolume {
            volume: "data-0".to_owned(),
            node: "node-1".to_owned(),
            at: 0,
        },
    ];

    for command in forbidden {
        let kind = command.kind();
        assert!(
            !command.may_be_policy(),
            "'{kind}' must not be written by a policy (ADR-0057, determination 2)"
        );
    }
}

/// And the two that a policy writes may do so.
///
/// The counter-check: without it a rule that forbids **everything** would be
/// green — and the built capacity policy (ADR-0049) would stop working.
#[test]
fn a_policy_may_write_what_the_two_decided_cases_need() {
    let allowed = [
        Command::UpsertNode {
            name: "node-1".to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r7".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Policy,
        },
        Command::SetKeyGeneration {
            node: "node-1".to_owned(),
            kind: tg_consensus::KeyKind::Underlay,
            generation: 4,
        },
    ];

    for command in allowed {
        let kind = command.kind();
        assert!(command.may_be_policy(), "'{kind}' must be permitted");
    }
}

/// **A state from yesterday must stay readable** (ADR-0020).
///
/// # Why that weighs more than the log
///
/// The test above protects the **entries**. The state beside it is the second
/// persisted surface, and it weighs more: `ClusterState` lies as JSON in `redb`
/// and is read at **every start** (`store::machine`, `KEY_STATE`), and the same
/// type sits in the snapshot a catching-up node gets (`wire::SnapshotBody`). A
/// field without `#[serde(default)]` therefore does not mean "an entry is
/// unreadable" but **"the node no longer comes up"** — and an admitted node
/// never catches up.
///
/// # What is nailed down here
///
/// The **core form**: only the fields that carry no `serde(default)`. Ten more
/// have been added over the phases — policies, invitations, generations,
/// underlay, egress, tombstones, network, sidecar surcharge —, and each got its
/// default with the same rationale as `capacity` above. **Nobody** checked
/// that.
///
/// Whoever adds a mandatory field makes this test red, and the message names it
/// (`missing field ...`). That is the demanded attention instead of the hoped-for
/// one — and the difference between an upgrade and a cluster that does not start
/// after the upgrade.
#[test]
fn a_state_written_before_the_later_phases_is_still_readable() {
    // The literal core form. It must never change; it describes what lies on
    // the disk.
    const CORE: &str = r#"{"workloads":{},"traffic":[],"nodes":{},"placements":{},"leases":{},"trust":{},"next_epoch":0}"#;

    let state = tg_consensus::wire::decode_state(CORE.as_bytes()).unwrap_or_else(|err| {
        panic!(
            "the core form must stay readable -- otherwise a node no longer \
             comes up after an upgrade (ADR-0020): {err}"
        )
    });

    // **And the defaults must invent nothing.** The same rule as with
    // `capacity` above: a state from before a field's introduction does **not**
    // have its content, and an invented default would be worse than a missing
    // one -- a cluster network nobody set, say, would let every node compute a
    // subnet (ADR-0069).
    assert!(state.network().is_none(), "a network nobody set");
    assert!(
        state.sidecar_overhead().is_empty(),
        "a surcharge nobody declared (ADR-0067)"
    );
    assert!(
        state.underlay_of("node-1").is_none(),
        "an announcement nobody made (ADR-0039)"
    );
    assert!(
        state.deleted_volumes().is_empty(),
        "a tombstone nobody set (ADR-0042)"
    );
    assert_eq!(
        state.key_generations("node-1"),
        tg_consensus::Generations::default(),
        "a rotation nobody decreed (ADR-0055)"
    );

    // And the counter-check to the core form itself: if a mandatory field is
    // **missing**, it is unreadable. Without this half the test would be green
    // even if `serde` accepted everything handed to it.
    let truncated = CORE.replace(r#","next_epoch":0"#, "");
    assert!(
        tg_consensus::wire::decode_state(truncated.as_bytes()).is_err(),
        "a mandatory field is missing and it does not stand out"
    );
}

/// **Every variant has a producer in production code** (ADR-0111,
/// determination 7).
///
/// # Why this has to be a guard
///
/// A command only tests construct is an assurance to nobody — and more dangerous
/// than it looks: the effect is never exercised, so it also does not stand out
/// when it is wrong. Measured, that was the case for **two** of 38 variants, and
/// both were loaded. `RevokeLease` lifted the fence of the active-role lease
/// (ADR-0111); `RegisterTrust` writes trust without a redeemed invitation, past
/// the gate from ADR-0037.
///
/// That is the pattern from ADR-0044 — there a fully privileged port without a
/// client —, and the lesson was the same: do not ask whether it disturbs but what
/// it would do if somebody connected a producer.
///
/// # What it cannot do
///
/// It reads source text and distinguishes the **spelling** of a construction
/// from that of a pattern. Whoever builds a variant over an intermediate value
/// or a helper function gets past — the same concession as with the guard from
/// ADR-0110. What it catches is a variant that occurs **nowhere** outside tests,
/// and those were both cases.
#[test]
fn every_command_has_a_producer_in_production_code() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let mut produced = std::collections::BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                // **The haystack is the production code.** `tests/` and
                // `benches/` are precisely the side that is checked against.
                if !matches!(name.as_str(), "target" | ".git" | "tests" | "benches") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for line in strip_cfg_test(&text) {
                    // **Comment lines do not count** (ADR-0112,
                    // determination 5). This line was missing here, and the
                    // guard took `ClearPlacement` for produced -- because of a
                    // mention in a doc comment
                    // (`[\`Command::ClearPlacement\`]`). It was green for the
                    // wrong reason and covered exactly the case it was built
                    // for.
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    collect_constructions(&line, &mut produced);
                }
            }
        }
    }

    // **The exceptions come from `retired()`, not from a list here**
    // (ADR-0112, determination 4). A second list would be the construction this
    // tree has measured several times as a source of error -- and it would have
    // to be maintained by hand, while `retired()` is an exhaustive `match`
    // nobody gets past.
    let retired: std::collections::BTreeSet<String> = retired_kinds();

    let missing: Vec<&str> = variants()
        .into_iter()
        .filter(|variant| !produced.contains(*variant) && !retired.contains(*variant))
        .collect();

    assert!(
        missing.is_empty(),
        "no producer in production code: {missing:?} -- either the caller is \
         missing, or the variant is retired and must say so in \
         `Command::retired()` too (ADR-0111, ADR-0112)"
    );

    // **The counter-direction**: a retired variant must have no producer.
    // Otherwise `retired()` would carry a statement the code beside it refutes
    // -- and a note that no longer holds costs the credibility of all the others
    // next time.
    for variant in &retired {
        assert!(
            !produced.contains(variant),
            "'{variant}' is carried as retired and has a producer -- one of the \
             two is wrong (ADR-0112)"
        );
    }
}

/// The names of the retired variants, read from the source of
/// [`Command::retired`].
///
/// Read and not enumerated, for the same reason as with [`variants`]: Rust
/// cannot enumerate variants, and a hand-maintained list would be exactly the
/// second source this guard is meant to abolish. The `match` there is
/// exhaustive — whoever adds a variant does not get past it.
fn retired_kinds() -> std::collections::BTreeSet<String> {
    let source = include_str!("../../tg-model/src/command.rs");
    let start = source
        .find("pub const fn retired(&self)")
        .expect("the source of the retirements");
    let body = &source[start..start + source[start..].find("\n    }\n").expect("its end")];

    // **Arm by arm, not by line shape** -- the search text must not hang on the
    // formatting. At first `"{ .. } => Some("` stood here, and `cargo fmt` turned
    // an arm into a block (`=> {`); then "everything before `=> None`", and that
    // took the whole `|` chain of the `None` branch with it.
    //
    // What carries: from every `Self::X` to the next there stands either a
    // `Some(` -- then the variant is retired -- or only `{ .. }` and a `|`,
    // because it is a link of the chain. Both survive any line break.
    let mut out = std::collections::BTreeSet::new();
    let mut rest = body;
    while let Some(at) = rest.find("Self::") {
        let after = &rest[at + "Self::".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let tail = &after[name.len()..];
        let arm = tail.find("Self::").map_or(tail, |next| &tail[..next]);
        if !name.is_empty() && arm.contains("Some(") {
            out.insert(name.clone());
        }
        rest = tail;
    }
    out
}

/// The variant names, read from the source of the command set.
///
/// Rust cannot enumerate variants, and per ADR-0023 a crate for it would be none
/// for a test. Read instead of enumerated: a hand-maintained list would be the
/// fourth, and the finding from [`tripwire`] applies here just as much.
fn variants() -> Vec<&'static str> {
    let source = include_str!("../../tg-model/src/command.rs");
    let start = source.find("pub enum Command {").expect("the command set");
    let body = &source[start..start + source[start..].find("\n}\n").expect("its end")];

    body.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("    ")?;
            let name = rest.split(|c: char| !c.is_alphanumeric()).next()?;
            (!name.is_empty()
                && name.starts_with(|c: char| c.is_ascii_uppercase())
                && rest[name.len()..].starts_with(" {"))
            .then_some(name)
        })
        .collect()
}

/// The lines of a file without its `#[cfg(test)]` blocks.
///
/// Over brace counting, because a test in a `src/` file would otherwise count as
/// a producer — and exactly that would be the fallacy this guard is meant to
/// avoid.
fn strip_cfg_test(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::with_capacity(lines.len());
    let mut skip_until: Option<i32> = None;
    let mut depth = 0_i32;

    for line in lines {
        if let Some(_target) = skip_until {
            depth += i32::try_from(line.matches('{').count()).unwrap_or(0)
                - i32::try_from(line.matches('}').count()).unwrap_or(0);
            if depth <= 0 {
                skip_until = None;
            }
            continue;
        }
        if line.trim_start().starts_with("#[cfg(test)]") {
            skip_until = Some(0);
            depth = 0;
            continue;
        }
        out.push(line.to_owned());
    }
    out
}

/// Enters every **construction** of a variant from a line.
///
/// A pattern is recognized by the `=>` behind it or by `{ ..` — nobody writes
/// either in order to build a command.
fn collect_constructions(line: &str, out: &mut std::collections::BTreeSet<String>) {
    let mut rest = line;
    while let Some(at) = rest.find("Command::") {
        let after = &rest[at + "Command::".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        rest = &after[name.len()..];
        if name.is_empty() {
            continue;
        }
        let tail = rest.trim_start();
        let is_pattern = rest.contains("=>") || tail.starts_with("{ ..") || tail.starts_with("{..");
        if !is_pattern {
            out.insert(name);
        }
    }
}
