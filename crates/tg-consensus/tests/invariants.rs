//! The two rules from the head of `state.rs`, and the access paths.
//!
//! `tests/state_machine.rs` checks what a command **does**. Here stands what
//! must hold throughout, whichever command it is:
//!
//! 1. **Removing is idempotent.** Level-triggered reconciliation (ADR-0010)
//!    repeats commands; every repetition would otherwise have to travel through
//!    the caller as an error.
//! 2. **A rejection writes nothing.** Half-applied commands would be hard to
//!    keep identical on two nodes.
//!
//! In addition the read paths: from 5d on they fill the projection (ADR-0030),
//! so they are not convenience but the interface at which the state leaves the
//! node.

use tg_consensus::{
    Class, ClusterState, Command, Epoch, Layer, Outcome, Rejection, Topology, UtcMillis,
};
use tg_defs::WorkloadClass;
use tg_model::egress::Transport;

fn document(name: &str, class: Option<&str>) -> String {
    let class = class.map_or(String::new(), |c| format!(" class=\"{c}\""));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\"{class}>\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

fn upsert(name: &str, class: Option<&str>) -> Command {
    Command::UpsertWorkload {
        document: document(name, class),
    }
}

fn node(name: &str) -> Command {
    Command::UpsertNode {
        name: name.to_owned(),
        topology: Topology {
            site: "fra".to_owned(),
            hall: "h1".to_owned(),
            rack: "r7".to_owned(),
        },
        capacity: tg_consensus::Resources::default(),
        reserved: tg_consensus::Resources::default(),
        source: tg_consensus::Origin::Operator,
    }
}

fn populated() -> ClusterState {
    let mut state = ClusterState::default();
    for command in [
        upsert("api", None),
        upsert("ledger", Some("single-writer")),
        node("node-1"),
        node("node-2"),
    ] {
        assert_eq!(state.apply(&command), Outcome::Applied);
    }
    state
}

fn bytes(state: &ClusterState) -> Vec<u8> {
    tg_consensus::wire::encode_state(state).expect("encodable")
}

// --- Rule 1: removing is idempotent ----------------------------------------

/// Every removing command on something that was never there: applied, not
/// refused — and without any trace in the state.
///
/// That is the precondition for a reconciler being allowed to repeat its intent.
/// Were a repetition a rejection, every caller would have to distinguish "already
/// gone" from "went wrong", and at a place at which it does not know the
/// difference.
#[test]
fn removing_something_absent_is_applied_and_changes_nothing() {
    let mut state = populated();
    let before = bytes(&state);

    for command in [
        Command::RemoveWorkload {
            name: "ghost".to_owned(),
        },
        Command::RevokeTraffic {
            from: "ghost".to_owned(),
            to: "phantom".to_owned(),
        },
        Command::RevokeEgress {
            workload: "api".to_owned(),
            host: "s3.example.com".to_owned(),
            port: 443,
            transport: Transport::Tcp,
        },
        Command::RemoveNode {
            name: "node-99".to_owned(),
        },
        Command::RevokeTrust {
            node: "node-99".to_owned(),
        },
        Command::RemoveSecret {
            name: "ghost".to_owned(),
        },
        Command::RevokeSecret {
            workload: "ghost".to_owned(),
            secret: "phantom".to_owned(),
        },
        Command::ClearRegistryCredential {
            registry: "registry.ghost".to_owned(),
        },
        Command::RevokeOperator {
            operator: "ghost".to_owned(),
        },
        Command::RetireTombstone {
            volume: "ghost".to_owned(),
            node: "node-99".to_owned(),
        },
    ] {
        let kind = command.kind();
        assert_eq!(state.apply(&command), Outcome::Applied, "{kind}");
        assert_eq!(bytes(&state), before, "{kind} wrote");
    }
}

/// **The list above is complete** — and the compiler cannot uphold that.
///
/// The doc block says "every removing command", and measured it checked **seven
/// of thirteen**: `RemoveSecret`, `RevokeSecret`, `ClearRegistryCredential`,
/// `RevokeOperator`, `RetireTombstone` and `DeleteVolume` were missing — that is,
/// the commands about secrets, about the operator authorization, and the most
/// destructive one in the system. Rust cannot enumerate its variants, so no
/// `match` upholds the completeness; this guard reads the source.
///
/// **`DeleteVolume` expressly does not stand in the list** but has a witness of
/// its own: it is no removal from the state but the **addition of an
/// instruction** (ADR-0042). The list's second assurance ("wrote") therefore
/// does not apply to it.
#[test]
fn every_removing_command_is_in_the_list() {
    let command_source = include_str!("../../tg-model/src/command.rs");
    let enum_body = command_source
        .split_once("pub enum Command")
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map_or("", |(body, _)| body);

    let removers: Vec<&str> = enum_body
        .lines()
        .filter_map(|line| {
            let name = line.strip_prefix("    ")?;
            let name = name.strip_suffix(" {").or_else(|| name.strip_suffix(','))?;
            ["Remove", "Revoke", "Retire", "Clear", "Delete"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
                .then_some(name)
        })
        // **Retired ones do not count** (ADR-0112). They are refused, so they
        // are neither "applied" nor idempotent -- and this list's rule does not
        // apply to them. Read from `retired()` and not as a second list here:
        // the `match` there is exhaustive, a list here would again be the
        // construction this tree has measured as a source of error.
        .filter(|name| !retired_source().contains(*name))
        .collect();

    assert!(
        removers.len() > 10,
        "the command set was not read: {removers:?}"
    );

    let source = include_str!("invariants.rs");
    let list = source
        .split_once("fn removing_something_absent_is_applied_and_changes_nothing")
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map_or("", |(body, _)| body);

    let own_witness = ["DeleteVolume"];
    let missing: Vec<&&str> = removers
        .iter()
        .filter(|name| !own_witness.contains(*name))
        .filter(|name| !list.contains(&format!("Command::{name}")))
        .collect();

    assert!(
        missing.is_empty(),
        "these removing commands are missing from the list: {missing:?} -- \
         rule 1 applies to every one, or the command needs a witness of its own \
         like `DeleteVolume`"
    );
}

/// **`DeleteVolume` is no removal but an instruction** (ADR-0042).
///
/// It upholds rule 1 to the letter — a volume the state does not know is
/// `Applied` and not refused. What it does **not** uphold is "without a trace":
/// it leaves a **tombstone**, and that is as it should be. The cluster knows only
/// the declarations, not the disk (ADR-0104); a volume that was never declared
/// can nevertheless lie on a node — exactly the DR case.
///
/// That is why it does not stand in the list above, and that is why this stands
/// here: whoever one day optimizes the tombstone away because "an unknown volume
/// has nothing to delete" takes the instruction with it.
#[test]
fn deleting_an_unknown_volume_leaves_an_instruction() {
    let mut state = populated();
    let before = bytes(&state);

    assert_eq!(
        state.apply(&Command::DeleteVolume {
            volume: "ghost".to_owned(),
            node: "node-2".to_owned(),
            at: 1_700_000_000,
        }),
        Outcome::Applied,
        "deleting an unknown volume is settled, not refused"
    );

    assert_ne!(
        bytes(&state),
        before,
        "and it leaves an instruction -- the cluster does not know the disk"
    );
    assert_eq!(
        state.deleted_volumes(),
        vec![("node-2", vec!["ghost"])],
        "the tombstone belongs to the named node"
    );
}

/// And removing the same thing twice is like once.
#[test]
fn removing_twice_equals_removing_once() {
    let mut once = populated();
    let mut twice = populated();

    let commands = [
        Command::RemoveWorkload {
            name: "api".to_owned(),
        },
        Command::RemoveNode {
            name: "node-2".to_owned(),
        },
    ];

    for command in &commands {
        assert_eq!(once.apply(command), Outcome::Applied);
    }
    for command in commands.iter().chain(commands.iter()) {
        assert_eq!(twice.apply(command), Outcome::Applied);
    }

    assert_eq!(once, twice);
}

/// The setting commands are repeatable too: the same command twice yields the
/// same state as once. Without that a repeated reconcile would be a state
/// change.
#[test]
fn setting_the_same_value_twice_is_the_same_as_once() {
    let mut once = populated();
    let mut twice = populated();

    let commands = [
        Command::AllowTraffic {
            from: "api".to_owned(),
            to: "ledger".to_owned(),
        },
        Command::AssignPlacement {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        },
        // **`RegisterTrust` stood here** and has been retired since ADR-0112:
        // it is refused, so it is neither "applied" nor idempotent. This list's
        // rule no longer applies to it.
        node("node-1"),
        upsert("api", None),
    ];

    for command in &commands {
        assert_eq!(once.apply(command), Outcome::Applied);
    }
    for command in commands.iter().chain(commands.iter()) {
        assert_eq!(twice.apply(command), Outcome::Applied);
    }

    assert_eq!(once, twice);
}

// --- Rule 2: a rejection writes nothing ------------------------------------

/// Every refusable command, each in its rejection case — the state is
/// afterwards the same byte for byte.
///
/// Unlike the test of the same name in `state_machine.rs` this one counts the
/// rejections: a command that goes through against expectation would otherwise
/// make the test green without having checked anything.
#[test]
fn every_rejection_leaves_the_state_byte_identical() {
    let mut state = populated();
    let _ = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });
    let before = bytes(&state);

    let cases = [
        Command::UpsertWorkload {
            document: "<no xml".to_owned(),
        },
        Command::AllowTraffic {
            from: "ghost".to_owned(),
            to: "api".to_owned(),
        },
        Command::AllowTraffic {
            from: "api".to_owned(),
            to: "ghost".to_owned(),
        },
        Command::AssignPlacement {
            workload: "ghost".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        },
        Command::AssignPlacement {
            workload: "api".to_owned(),
            node: "node-99".to_owned(),
            instance: 0,
        },
        Command::GrantLease {
            workload: "ghost".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(1),
            expires_at: UtcMillis::new(2),
        },
        Command::GrantLease {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(1),
            expires_at: UtcMillis::new(2),
        },
        Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-99".to_owned(),
            now: UtcMillis::new(1),
            expires_at: UtcMillis::new(2),
        },
        Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(1),
            expires_at: UtcMillis::new(2),
        },
        Command::RenewLease {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(1),
            expires_at: UtcMillis::new(2),
        },
        Command::RenewLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(1),
            expires_at: UtcMillis::new(2),
        },
        Command::RenewLease {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(15_000),
            expires_at: UtcMillis::new(30_000),
        },
        Command::RegisterTrust {
            node: "node-99".to_owned(),
            bundle: "anchor".to_owned(),
        },
    ];

    let mut rejections = 0;
    for command in &cases {
        let kind = command.kind();
        if matches!(state.apply(command), Outcome::Rejected(_)) {
            rejections += 1;
        } else {
            panic!("{kind} should have been refused");
        }
        assert_eq!(bytes(&state), before, "{kind} wrote despite the rejection");
    }

    assert_eq!(rejections, cases.len(), "every case must be a rejection");
}

/// A rejection consumes no epoch. Otherwise the counter could be driven up from
/// outside without a lease ever having been granted.
#[test]
fn a_rejected_grant_burns_no_epoch() {
    let mut state = populated();
    let before = state.next_epoch();

    for command in [
        Command::GrantLease {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(1),
        },
        Command::GrantLease {
            workload: "ghost".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(1),
        },
        Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-99".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(1),
        },
    ] {
        assert!(matches!(state.apply(&command), Outcome::Rejected(_)));
    }

    assert_eq!(state.next_epoch(), before);
}

// --- Order of the checks ---------------------------------------------------

/// With several violated preconditions a fixed order applies.
///
/// The order itself is convention; **that** it is fixed is not: two nodes must
/// deliver the same rationale, otherwise the audit trail of the one carries a
/// different reason from the other's (ADR-0020).
#[test]
fn the_first_violated_precondition_wins() {
    let mut state = populated();

    // Workload before node.
    assert!(matches!(
        state.apply(&Command::AssignPlacement {
            workload: "ghost".to_owned(),
            node: "node-99".to_owned(),
            instance: 0,
        }),
        Outcome::Rejected(Rejection::UnknownWorkload { .. })
    ));

    // Class before node: a replicated workload is refused as such even when the
    // target node does not exist either.
    assert!(matches!(
        state.apply(&Command::GrantLease {
            workload: "api".to_owned(),
            node: "node-99".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(1),
        }),
        Outcome::Rejected(Rejection::NotSingleWriter { .. })
    ));

    // With `AllowTraffic` the source before the target.
    assert!(matches!(
        state.apply(&Command::AllowTraffic {
            from: "ghost".to_owned(),
            to: "phantom".to_owned(),
        }),
        Outcome::Rejected(Rejection::UnknownWorkload { name }) if name == "ghost"
    ));
}

/// The rejection names the name it was about — otherwise it cannot be assigned
/// in the audit trail.
#[test]
fn a_rejection_names_the_offending_value() {
    let mut state = populated();

    let Outcome::Rejected(Rejection::UnknownNode { name }) =
        state.apply(&Command::AssignPlacement {
            workload: "api".to_owned(),
            node: "node-99".to_owned(),
            instance: 0,
        })
    else {
        panic!("UnknownNode expected");
    };
    assert_eq!(name, "node-99");

    let _ = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });

    let Outcome::Rejected(Rejection::LeaseHeld {
        workload,
        holder,
        epoch,
    }) = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-2".to_owned(),
        now: UtcMillis::new(1),
        expires_at: UtcMillis::new(15_001),
    })
    else {
        panic!("LeaseHeld expected");
    };
    assert_eq!(workload, "ledger");
    assert_eq!(holder, "node-1");
    assert_eq!(epoch, Epoch::default());
}

// --- Lease subtleties -------------------------------------------------------

/// The holder may have their own lease granted anew although the old one still
/// applies — documented as "harmless": it is the same active party, only with a
/// new epoch. A fence against oneself is none.
#[test]
fn the_holder_may_be_granted_again_while_the_lease_still_holds() {
    let mut state = populated();

    let Outcome::LeaseGranted { epoch: first } = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    }) else {
        panic!("first grant");
    };

    let Outcome::LeaseGranted { epoch: second } = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(1_000),
        expires_at: UtcMillis::new(16_000),
    }) else {
        panic!("second grant to the same holder");
    };

    assert!(second > first, "the holder too gets a new epoch");
    assert_eq!(state.lease("ledger").expect("lease").epoch(), second);
}

/// The epoch is cluster-wide monotonic — across different workloads too. Two
/// workloads must not share an epoch, otherwise a fencing token can no longer be
/// assigned unambiguously to one activation.
#[test]
fn epochs_are_globally_monotone_across_workloads() {
    let mut state = ClusterState::default();
    for command in [
        upsert("ledger", Some("single-writer")),
        upsert("clearing", Some("single-writer")),
        node("node-1"),
    ] {
        assert_eq!(state.apply(&command), Outcome::Applied);
    }

    let mut seen = Vec::new();
    for round in 0..4_u64 {
        for workload in ["ledger", "clearing"] {
            let Outcome::LeaseGranted { epoch } = state.apply(&Command::GrantLease {
                workload: workload.to_owned(),
                node: "node-1".to_owned(),
                now: UtcMillis::new(round * 1_000),
                expires_at: UtcMillis::new(round * 1_000 + 15_000),
            }) else {
                panic!("grant for {workload}");
            };
            seen.push(epoch);
        }
    }

    let mut sorted = seen.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(seen, sorted, "epochs rise strictly and never repeat");
    assert_eq!(seen.first().copied(), Some(Epoch::default()));
}

/// A workload that changes its class does **not** lose its lease automatically
/// — but it gets no new one.
///
/// The case pins a seam: `UpsertWorkload` replaces the definition but does not
/// touch the cluster-state layer. Mixing both into one command would mean that a
/// change of definition could silently unfence an active party.
#[test]
fn changing_the_class_does_not_touch_the_standing_lease() {
    let mut state = populated();
    let Outcome::LeaseGranted { epoch } = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    }) else {
        panic!("grant");
    };

    assert_eq!(state.apply(&upsert("ledger", None)), Outcome::Applied);

    let lease = state.lease("ledger").expect("the lease still stands");
    assert_eq!(lease.epoch(), epoch);
    assert_eq!(
        state.workload("ledger").expect("workload").class(),
        WorkloadClass::Replicated
    );

    assert!(matches!(
        state.apply(&Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(1_000),
            expires_at: UtcMillis::new(16_000),
        }),
        Outcome::Rejected(Rejection::NotSingleWriter { .. })
    ));
}

/// A deregistered node does **not** take its lease with it.
///
/// That is the cautious direction and intentional: `RemoveNode` is a
/// desired-state command, the lease is consensus-critical cluster state
/// (ADR-0004). Were the deregistration to drop the lease silently, a standby
/// would be activatable at once while the old holder still runs — fencing over a
/// name that no longer exists is none. Whoever really wants to replace the holder
/// revokes the lease expressly or waits for the expiry.
#[test]
fn removing_a_node_does_not_silently_release_its_lease() {
    let mut state = populated();
    let _ = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });

    assert_eq!(
        state.apply(&Command::RemoveNode {
            name: "node-1".to_owned()
        }),
        Outcome::Applied
    );

    let lease = state.lease("ledger").expect("the lease stays standing");
    assert_eq!(lease.holder(), "node-1");

    // And a second node does not get past it as long as it applies.
    assert!(matches!(
        state.apply(&Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(1_000),
            expires_at: UtcMillis::new(16_000),
        }),
        Outcome::Rejected(Rejection::LeaseHeld { .. })
    ));
}

/// `Lease::is_valid_at` at the boundary: valid up to `expires_at` exclusive.
#[test]
fn lease_validity_is_half_open() {
    let mut state = populated();
    let _ = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });
    let lease = state.lease("ledger").expect("lease");

    assert!(lease.is_valid_at(UtcMillis::new(0)));
    assert!(lease.is_valid_at(UtcMillis::new(14_999)));
    assert!(!lease.is_valid_at(UtcMillis::new(15_000)));
    assert!(!lease.is_valid_at(UtcMillis::new(15_001)));
    assert_eq!(lease.expires_at(), UtcMillis::new(15_000));
}

/// A lease with `expires_at <= now` is granted and no longer applies at once.
///
/// No special case in the code, and deliberately none here either: the state
/// machine does not judge the applicant's clock, it only computes with it.
/// Whoever applies for an already expired lease gets an epoch and no protection —
/// and the next applicant comes through unhindered.
#[test]
fn a_lease_that_expires_immediately_blocks_nobody() {
    let mut state = populated();

    let Outcome::LeaseGranted { .. } = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(5_000),
        expires_at: UtcMillis::new(5_000),
    }) else {
        panic!("grant");
    };

    assert!(
        !state
            .lease("ledger")
            .expect("lease")
            .is_valid_at(UtcMillis::new(5_000))
    );

    assert!(matches!(
        state.apply(&Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(5_000),
            expires_at: UtcMillis::new(20_000),
        }),
        Outcome::LeaseGranted { .. }
    ));
}

// --- Read paths -------------------------------------------------------------

/// The collections come back sorted and complete — the order is part of the
/// assurance, because from 5d on the projection arises from them and must look
/// the same on all nodes.
#[test]
fn collections_come_back_sorted_and_complete() {
    let mut state = ClusterState::default();
    for command in [
        upsert("zeta", None),
        upsert("alpha", None),
        upsert("middle", None),
        node("node-9"),
        node("node-1"),
    ] {
        assert_eq!(state.apply(&command), Outcome::Applied);
    }
    for (from, to) in [("zeta", "alpha"), ("alpha", "middle"), ("alpha", "zeta")] {
        assert_eq!(
            state.apply(&Command::AllowTraffic {
                from: from.to_owned(),
                to: to.to_owned()
            }),
            Outcome::Applied
        );
    }

    let names: Vec<&str> = state.workloads().iter().map(|w| w.name()).collect();
    assert_eq!(names, ["alpha", "middle", "zeta"]);

    let nodes: Vec<&str> = state.nodes().iter().map(|(name, _)| *name).collect();
    assert_eq!(nodes, ["node-1", "node-9"]);

    assert_eq!(
        state.traffic(),
        [("alpha", "middle"), ("alpha", "zeta"), ("zeta", "alpha")]
    );
}

/// Deny-by-default (ADR-0025) and direction: an edge permits exactly one.
#[test]
fn traffic_is_directed_and_denied_by_default() {
    let mut state = populated();

    assert!(!state.may_talk("api", "ledger"));
    assert!(!state.may_talk("ledger", "api"));

    assert_eq!(
        state.apply(&Command::AllowTraffic {
            from: "api".to_owned(),
            to: "ledger".to_owned()
        }),
        Outcome::Applied
    );

    assert!(state.may_talk("api", "ledger"));
    assert!(
        !state.may_talk("ledger", "api"),
        "the counter-direction stays closed"
    );
    assert!(!state.may_talk("api", "ghost"));
    assert!(!state.may_talk("api", "api"));
}

/// Absence is `None`, not a placeholder value. A sentinel would be a second way
/// of saying "does not exist".
#[test]
fn absent_things_read_as_none() {
    let state = populated();

    assert!(state.workload("ghost").is_none());
    assert!(state.node("node-99").is_none());
    assert!(state.placement("api").is_none());
    assert!(state.lease("ledger").is_none());
    assert!(state.trust("node-1").is_none());
    assert_eq!(state.next_epoch(), Epoch::default());
}

/// The empty state is empty, and `Default` is every node's starting point.
#[test]
fn the_default_state_is_empty() {
    let state = ClusterState::default();

    assert!(state.workloads().is_empty());
    assert!(state.nodes().is_empty());
    assert!(state.traffic().is_empty());
    assert_eq!(state.next_epoch().get(), 0);
}

/// The stored document is the canonical form, not the submitted byte. The
/// submitted one stands in the log (ADR-0020); here stands the form from which
/// the projection is filled.
#[test]
fn the_stored_document_is_canonical_not_the_submitted_bytes() {
    let mut state = ClusterState::default();
    let submitted = document("api", None);
    assert_eq!(
        state.apply(&Command::UpsertWorkload {
            document: submitted.clone()
        }),
        Outcome::Applied
    );

    let stored = state.workload("api").expect("workload").document();

    // Submitting twice -- once raw, once in canonical form -- must yield the
    // same entry. Otherwise the state would hang on the submitter's
    // formatting.
    let mut again = ClusterState::default();
    assert_eq!(
        again.apply(&Command::UpsertWorkload {
            document: stored.to_owned()
        }),
        Outcome::Applied
    );
    assert_eq!(state, again);
    assert!(
        tg_defs::from_str(stored).is_ok(),
        "canonical means readable"
    );
}

// --- The command set itself -------------------------------------------------

/// `kind()` and `layer()` agree with the inventory — for every variant, not only
/// for the names enumerated in `KINDS`.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "a list of examples per command -- it grows with the command set"
)]
fn kind_and_layer_agree_with_the_inventory() {
    let samples = [
        upsert("api", None),
        Command::RemoveWorkload {
            name: "api".to_owned(),
        },
        Command::AllowTraffic {
            from: "a".to_owned(),
            to: "b".to_owned(),
        },
        Command::RevokeTraffic {
            from: "a".to_owned(),
            to: "b".to_owned(),
        },
        Command::AllowEgress {
            workload: "api".to_owned(),
            host: "s3.example.com".to_owned(),
            port: 443,
            transport: Transport::Tcp,
        },
        Command::RevokeEgress {
            workload: "api".to_owned(),
            host: "s3.example.com".to_owned(),
            port: 443,
            transport: Transport::Tcp,
        },
        Command::PutSecret {
            name: "s3-key".to_owned(),
            value: tg_identity::secrets::Sealed {
                ciphertext: vec![1, 2, 3],
                nonce: vec![4, 5, 6],
            },
        },
        Command::RemoveSecret {
            name: "s3-key".to_owned(),
        },
        Command::AllowSecret {
            workload: "api".to_owned(),
            secret: "s3-key".to_owned(),
        },
        Command::RevokeSecret {
            workload: "api".to_owned(),
            secret: "s3-key".to_owned(),
        },
        Command::SetRegistryCredential {
            registry: "registry.test".to_owned(),
            secret: "s3-key".to_owned(),
        },
        Command::ClearRegistryCredential {
            registry: "registry.test".to_owned(),
        },
        node("node-1"),
        Command::RemoveNode {
            name: "node-1".to_owned(),
        },
        Command::AssignPlacement {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        },
        Command::ClearPlacement {
            workload: "api".to_owned(),
        },
        Command::GrantLease {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(1),
        },
        Command::RenewLease {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(1),
        },
        Command::InviteNode {
            node: "node-1".to_owned(),
            digest: "d".to_owned(),
            expires_at: 1,
        },
        Command::AdmitNode {
            node: "node-1".to_owned(),
            spki: "s".to_owned(),
            at: 0,
        },
        Command::RegisterTrust {
            node: "node-1".to_owned(),
            bundle: "b".to_owned(),
        },
        Command::RotateTrust {
            node: "node-1".to_owned(),
            from: "old".to_owned(),
            to: "new".to_owned(),
        },
        Command::RevokeTrust {
            node: "node-1".to_owned(),
        },
        Command::AnnounceUnderlay {
            node: "node-1".to_owned(),
            key: "k".to_owned(),
            endpoint: "203.0.113.7:51820".to_owned(),
            at: 0,
        },
        Command::SetSchedulability {
            node: "node-1".to_owned(),
            mode: tg_consensus::Schedulability::Cordoned,
        },
        Command::SetAttachment {
            node: "node-1".to_owned(),
            mode: tg_consensus::Attachment::Detached,
        },
        Command::SetKeyGeneration {
            node: "node-1".to_owned(),
            kind: tg_consensus::KeyKind::Underlay,
            generation: 1,
        },
        Command::SetWorkloadGeneration {
            workload: "api".to_owned(),
            instance: None,
            generation: 1,
        },
        Command::SetActiveInstance {
            workload: "api".to_owned(),
            instance: 0,
        },
        Command::SetCapacityPolicy {
            policy: tg_consensus::CapacityPolicy::default(),
        },
        Command::SetRotationPolicy {
            policy: tg_consensus::RotationPolicy::default(),
        },
        Command::SetClusterNetwork {
            cidr: "10.42.0.0/16".to_owned(),
            node_prefix: 24,
        },
        Command::SetSidecarOverhead {
            resources: tg_consensus::Resources::default()
                .with(tg_consensus::Resources::CPU_MILLICORES, 50),
        },
        Command::DeleteVolume {
            volume: "data-0".to_owned(),
            node: "node-1".to_owned(),
            at: 0,
        },
        Command::SnapshotVolume {
            volume: "data-0".to_owned(),
            node: "node-1".to_owned(),
            generation: 1,
        },
        Command::RetireTombstone {
            volume: "data-0".to_owned(),
            node: "node-1".to_owned(),
        },
        Command::EnrolOperator {
            operator: "dana".to_owned(),
            spki: "AAAA".to_owned(),
            classes: Class::ALL.to_vec(),
        },
        Command::RevokeOperator {
            operator: "dana".to_owned(),
        },
    ];

    assert_eq!(samples.len(), Command::KINDS.len());
    for (command, (kind, layer)) in samples.iter().zip(Command::KINDS) {
        assert_eq!(command.kind(), kind);
        assert_eq!(command.layer(), layer);
    }
}

/// No desired-state command hands out an epoch, and no cluster-state command
/// changes a definition. The boundary from ADR-0004 is no label.
#[test]
fn the_two_layers_do_not_reach_into_each_other() {
    let mut state = populated();

    let before_epoch = state.next_epoch();
    for command in [
        upsert("api", None),
        Command::AllowTraffic {
            from: "api".to_owned(),
            to: "ledger".to_owned(),
        },
        node("node-3"),
    ] {
        assert_eq!(command.layer(), Layer::DesiredState);
        assert_eq!(state.apply(&command), Outcome::Applied);
    }
    assert_eq!(state.next_epoch(), before_epoch);

    let definitions_before: Vec<String> = state
        .workloads()
        .iter()
        .map(|w| w.document().to_owned())
        .collect();
    for command in [
        Command::AssignPlacement {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        },
        Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(15_000),
        },
        // `RegisterTrust` stood here, retired since ADR-0112. The statement is
        // about the **layer** and needs a command that acts.
        Command::RevokeTrust {
            node: "node-1".to_owned(),
        },
    ] {
        assert_eq!(command.layer(), Layer::ClusterState);
        assert!(!matches!(state.apply(&command), Outcome::Rejected(_)));
    }
    let definitions_after: Vec<String> = state
        .workloads()
        .iter()
        .map(|w| w.document().to_owned())
        .collect();
    assert_eq!(definitions_before, definitions_after);
}

/// The value types carry what is put into them — the edges included.
#[test]
fn value_types_round_trip_their_extremes() {
    assert_eq!(UtcMillis::new(0).get(), 0);
    assert_eq!(UtcMillis::new(u64::MAX).get(), u64::MAX);
    assert!(UtcMillis::new(1) > UtcMillis::new(0));
    assert_eq!(Epoch::default().get(), 0);
}

/// The retired variants, read from `Command::retired()`.
///
/// The same reading as in `command_set.rs` and for the same reason: a
/// hand-maintained list would be the second source (ADR-0112,
/// determination 4).
fn retired_source() -> std::collections::BTreeSet<String> {
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

/// **A class change at a placed workload is refused** (ADR-0117,
/// determination 1).
///
/// The measured finding this check closes: the change was `Applied` in both
/// directions, and immediately afterwards the cluster granted an active-role
/// lease. The **running** sidecar had never got its `--single-writer`, however —
/// its command line stems from the document at the moment of the start
/// (ADR-0059), and a changed declaration reaches it only at the next start
/// (ADR-0070), which only a decree triggers (ADR-0085).
///
/// The cluster thereby carried an active role nobody enforced — the reversal of
/// ADR-0066, and invisible: every display stood on green.
///
/// **Both directions** are checked. They come out differently if one lets them
/// run — the one is a security error, the other an availability error —, and a
/// version that refuses only one of them would be green with only one half.
#[test]
fn the_class_of_a_placed_workload_cannot_change() {
    for (from, to) in [
        ("replicated", "single-writer"),
        ("single-writer", "replicated"),
    ] {
        let mut state = ClusterState::default();
        assert!(matches!(state.apply(&node("node-1")), Outcome::Applied));
        assert!(matches!(
            state.apply(&upsert("api", Some(from))),
            Outcome::Applied
        ));
        assert!(matches!(
            state.apply(&Command::AssignPlacement {
                workload: "api".to_owned(),
                node: "node-1".to_owned(),
                instance: 0,
            }),
            Outcome::Applied
        ));

        let outcome = state.apply(&upsert("api", Some(to)));
        let Outcome::Rejected(rejection) = outcome else {
            panic!("{from} -> {to} came through: {outcome:?}");
        };
        let text = format!("{rejection:?}");
        assert!(
            text.contains("UnplaceableDefinition"),
            "the same class of ingest finding as the neighbours (ADR-0084): {text}"
        );
        assert!(
            text.contains("remove"),
            "the rejection must name the way: {text}"
        );

        // **And the state stays as it was.** A rejection that rewrites the
        // class anyway would be the worst of all.
        let class = state
            .workloads()
            .into_iter()
            .find(|entry| entry.name() == "api")
            .map(tg_consensus::WorkloadEntry::is_single_writer);
        assert_eq!(class, Some(from == "single-writer"), "{from} -> {to}");
    }
}

/// **Without a placement it goes through** (ADR-0117, determination 2).
///
/// The counter-check, and it carries half the decision: the barrier is "placed",
/// not "declared". Nothing is started, so there is no gap — and an operator who
/// corrects a class seconds after the first upsert shall come through.
///
/// Without this test a version that refuses **every** class change would be green
/// too; the rejection would then stand at a workload on which nothing hangs, and
/// the way out ("withdraw it") would be an empty gesture.
#[test]
fn the_class_of_an_unplaced_workload_may_still_change() {
    let mut state = ClusterState::default();
    assert!(matches!(
        state.apply(&upsert("api", Some("replicated"))),
        Outcome::Applied
    ));

    assert!(
        matches!(
            state.apply(&upsert("api", Some("single-writer"))),
            Outcome::Applied
        ),
        "without a placement nothing runs, so there is nothing to protect"
    );

    let class = state
        .workloads()
        .into_iter()
        .find(|entry| entry.name() == "api")
        .map(tg_consensus::WorkloadEntry::is_single_writer);
    assert_eq!(class, Some(true));
}

/// **Declaring the same class again is no change** (ADR-0117).
///
/// The everyday case: a new image tag at a placed workload. Without this test a
/// version that refuses **every** upsert of a placed workload would be green —
/// and would thereby wall up the delivery path from ADR-0071.
#[test]
fn an_unchanged_class_is_not_a_change() {
    let mut state = ClusterState::default();
    assert!(matches!(state.apply(&node("node-1")), Outcome::Applied));
    assert!(matches!(
        state.apply(&upsert("api", Some("single-writer"))),
        Outcome::Applied
    ));
    assert!(matches!(
        state.apply(&Command::AssignPlacement {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        }),
        Outcome::Applied
    ));

    assert!(matches!(
        state.apply(&upsert("api", Some("single-writer"))),
        Outcome::Applied
    ));
}
