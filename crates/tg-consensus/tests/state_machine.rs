//! The replicated state machine — pure logic, without a network and without a
//! disk.
//!
//! Everything here is deterministic: the same command sequence, the same state,
//! on each of the five nodes (ADR-0031). That is why no command carries a clock
//! and no randomness — where a time is needed (leases) it travels **in the
//! command** and is thereby part of the log (ADR-0024: traceable UTC in the log,
//! monotonic stays local).

use tg_consensus::{
    Attachment, ClusterState, Command, KeyKind, Outcome, Rejection, Schedulability, Topology,
    UtcMillis,
};

/// A document with exactly one workload.
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

/// A state with one replicated and one single-writer workload plus two
/// nodes.
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

// --- Desired state ---------------------------------------------------------

#[test]
fn a_workload_lands_in_the_state_with_its_class() {
    let state = populated();

    let api = state.workload("api").expect("api stands in the state");
    assert!(!api.is_single_writer());

    let ledger = state
        .workload("ledger")
        .expect("ledger stands in the state");
    assert!(ledger.is_single_writer());
}

/// The stored document is readable again. It is the form from which the
/// projection in 5d and the agent's local cache (ADR-0019) are filled — were it
/// not parsable, the state would be worthless.
#[test]
fn the_stored_document_is_still_a_valid_definition() {
    let state = populated();
    let stored = state.workload("ledger").expect("present").document();

    let parsed = tg_defs::from_str(stored).expect("the stored document is readable");
    assert_eq!(parsed.workloads().len(), 1);
}

/// A second upsert replaces, it does not duplicate.
#[test]
fn upserting_twice_replaces() {
    let mut state = populated();
    assert_eq!(
        state.apply(&upsert("api", Some("single-writer"))),
        Outcome::Applied
    );

    assert_eq!(state.workloads().len(), 2);
    assert!(state.workload("api").expect("present").is_single_writer());
}

/// A broken document may reach the log — nobody can prevent that, the log is
/// only a byte sequence. It must not reach the **state**, however, and the
/// rejection must come out identically on every node.
#[test]
fn a_malformed_document_is_rejected_deterministically() {
    let mut state = ClusterState::default();
    let command = Command::UpsertWorkload {
        document: "<nonsense/>".to_owned(),
    };

    let first = state.apply(&command);
    assert!(matches!(
        first,
        Outcome::Rejected(Rejection::MalformedDocument { .. })
    ));
    assert_eq!(state.workloads().len(), 0);

    let mut twin = ClusterState::default();
    assert_eq!(twin.apply(&command), first);
}

/// A document with several workloads is inadmissible as a log entry: one entry,
/// one change. Otherwise it would not be decidable what a later
/// `RemoveWorkload` actually undoes.
#[test]
fn a_document_must_carry_exactly_one_workload() {
    let mut state = ClusterState::default();
    let two = document("api", None).replace(
        "</workloads>",
        "<workload name=\"db\" kind=\"service\"><image reference=\"example.com/db:1\"/></workload></workloads>",
    );

    let outcome = state.apply(&Command::UpsertWorkload { document: two });
    assert!(matches!(
        outcome,
        Outcome::Rejected(Rejection::MalformedDocument { .. })
    ));
}

/// `may_talk` edges (ADR-0025) need two existing endpoints — referential
/// integrity is a property of the set, not of the command.
#[test]
fn traffic_edges_need_both_endpoints() {
    let mut state = populated();

    assert_eq!(
        state.apply(&Command::AllowTraffic {
            from: "api".to_owned(),
            to: "ledger".to_owned(),
        }),
        Outcome::Applied
    );
    assert!(state.may_talk("api", "ledger"));

    // Deny-by-default: the edge is directed.
    assert!(!state.may_talk("ledger", "api"));

    let outcome = state.apply(&Command::AllowTraffic {
        from: "api".to_owned(),
        to: "ghost".to_owned(),
    });
    assert!(matches!(
        outcome,
        Outcome::Rejected(Rejection::UnknownWorkload { .. })
    ));
}

/// A removed workload leaves no dead entries behind: placement, lease and both
/// directions of its `may_talk` edges go with it. An orphaned edge would be an
/// authorization onto a name that a **different** workload can later carry.
#[test]
fn removing_a_workload_cascades() {
    let mut state = populated();
    state.apply(&Command::AllowTraffic {
        from: "api".to_owned(),
        to: "ledger".to_owned(),
    });
    state.apply(&Command::AllowTraffic {
        from: "ledger".to_owned(),
        to: "api".to_owned(),
    });
    state.apply(&Command::AssignPlacement {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        instance: 0,
    });
    state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });

    assert_eq!(
        state.apply(&Command::RemoveWorkload {
            name: "ledger".to_owned()
        }),
        Outcome::Applied
    );

    assert!(state.workload("ledger").is_none());
    assert!(state.placement("ledger").is_none());
    assert!(state.lease("ledger").is_none());
    assert!(!state.may_talk("api", "ledger"));
    assert!(!state.may_talk("ledger", "api"));
}

/// A removed node takes its trust registration and the placements pointing at
/// it with it.
#[test]
fn removing_a_node_cascades() {
    let mut state = populated();
    state.apply(&Command::RegisterTrust {
        node: "node-1".to_owned(),
        bundle: "bundle".to_owned(),
    });
    state.apply(&Command::AssignPlacement {
        workload: "api".to_owned(),
        node: "node-1".to_owned(),
        instance: 0,
    });

    assert_eq!(
        state.apply(&Command::RemoveNode {
            name: "node-1".to_owned()
        }),
        Outcome::Applied
    );

    assert!(state.node("node-1").is_none());
    assert!(state.trust("node-1").is_none());
    assert!(state.placement("api").is_none());
}

// --- Placement -------------------------------------------------------------

#[test]
fn a_placement_needs_a_known_workload_and_a_known_node() {
    let mut state = populated();

    assert_eq!(
        state.apply(&Command::AssignPlacement {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        }),
        Outcome::Applied
    );
    assert_eq!(state.placement("api"), Some("node-1"));

    assert!(matches!(
        state.apply(&Command::AssignPlacement {
            workload: "ghost".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        }),
        Outcome::Rejected(Rejection::UnknownWorkload { .. })
    ));
    assert!(matches!(
        state.apply(&Command::AssignPlacement {
            workload: "api".to_owned(),
            node: "node-9".to_owned(),
            instance: 0,
        }),
        Outcome::Rejected(Rejection::UnknownNode { .. })
    ));
}

// --- Active-role lease and fencing epoch (ADR-0010) ------------------------

/// Only single-writer workloads need a lease. For replicated ones it would not
/// only be useless but harmful: it would bind to the quorum a workload that per
/// ADR-0010 may precisely carry on without it.
#[test]
fn only_single_writer_workloads_get_a_lease() {
    let mut state = populated();

    let outcome = state.apply(&Command::GrantLease {
        workload: "api".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });
    assert!(matches!(
        outcome,
        Outcome::Rejected(Rejection::NotSingleWriter { .. })
    ));
}

#[test]
fn a_grant_hands_out_an_epoch() {
    let mut state = populated();

    let Outcome::LeaseGranted { epoch } = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    }) else {
        panic!("a grant must deliver an epoch");
    };

    let lease = state
        .lease("ledger")
        .expect("the lease stands in the state");
    assert_eq!(lease.epoch(), epoch);
    assert_eq!(lease.holder(), "node-1");
    assert_eq!(lease.expires_at(), UtcMillis::new(15_000));
}

/// The core of the fencing: as long as the lease is valid, no second node gets
/// it. Exactly here split-brain would otherwise arise.
#[test]
fn a_valid_lease_blocks_a_second_holder() {
    let mut state = populated();
    state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });

    // **`now + LEASE`, not some later number.** Here stood 30_000, that is, a
    // span of 15_001 ms -- one millisecond over LEASE. Since ADR-0078 the state
    // machine refuses that, and this witness would then have seen
    // `ImplausibleLease` instead of `LeaseHeld` and would no longer have checked
    // the fence at all.
    let outcome = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-2".to_owned(),
        now: UtcMillis::new(14_999),
        expires_at: UtcMillis::new(29_999),
    });
    assert!(matches!(
        outcome,
        Outcome::Rejected(Rejection::LeaseHeld { .. })
    ));
    assert_eq!(state.lease("ledger").expect("unchanged").holder(), "node-1");
}

/// After expiry the standby may take over — with a **higher** epoch. The old
/// holder has self-fenced autonomously by then (ADR-0010); the epoch sees to it
/// that it takes hold even if they stop slowly.
#[test]
fn after_expiry_the_standby_takes_over_with_a_higher_epoch() {
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
        node: "node-2".to_owned(),
        now: UtcMillis::new(15_000),
        expires_at: UtcMillis::new(30_000),
    }) else {
        panic!("second grant");
    };

    assert!(
        second > first,
        "the epoch must rise: {second:?} after {first:?}"
    );
    assert_eq!(state.lease("ledger").expect("new").holder(), "node-2");
}

/// Expiry is meant inclusively: `expires_at` is the first point in time at
/// which the lease **no longer** applies. Without this determination two
/// implementations quarrel over a millisecond — and exactly in that millisecond
/// lies the double writer.
#[test]
fn expiry_is_inclusive() {
    let mut state = populated();
    state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });

    // One millisecond earlier: still held. (`now + LEASE` and not 30_000 --
    // see the witness above, ADR-0078.)
    assert!(matches!(
        state.apply(&Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(14_999),
            expires_at: UtcMillis::new(29_999),
        }),
        Outcome::Rejected(Rejection::LeaseHeld { .. })
    ));

    // Exactly at the moment of expiry: free.
    assert!(matches!(
        state.apply(&Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(15_000),
            expires_at: UtcMillis::new(30_000),
        }),
        Outcome::LeaseGranted { .. }
    ));
}

/// Renewing extends without touching the epoch. An epoch jump at every renewal
/// would roll the downstream enforcement (ADR-0007/0025) up anew every 15 s
/// without the holder having changed.
#[test]
fn renewing_keeps_the_epoch() {
    let mut state = populated();
    let Outcome::LeaseGranted { epoch } = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    }) else {
        panic!("grant");
    };

    assert_eq!(
        state.apply(&Command::RenewLease {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(10_000),
            expires_at: UtcMillis::new(25_000),
        }),
        Outcome::LeaseRenewed { epoch }
    );

    let lease = state.lease("ledger").expect("present");
    assert_eq!(lease.epoch(), epoch);
    assert_eq!(lease.expires_at(), UtcMillis::new(25_000));
}

/// Only the holder renews. Otherwise a node could extend another's lease and
/// lever out its self-fence.
#[test]
fn only_the_holder_may_renew() {
    let mut state = populated();
    state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });

    assert!(matches!(
        state.apply(&Command::RenewLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(1_000),
            expires_at: UtcMillis::new(16_000),
        }),
        Outcome::Rejected(Rejection::NotHolder { .. })
    ));
}

/// An expired lease cannot be renewed, only granted anew. The difference is the
/// epoch: whoever missed the gap must assume that another became active in
/// it.
#[test]
fn an_expired_lease_cannot_be_renewed() {
    let mut state = populated();
    state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    });

    assert!(matches!(
        state.apply(&Command::RenewLease {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(15_000),
            expires_at: UtcMillis::new(30_000),
        }),
        Outcome::Rejected(Rejection::LeaseExpired { .. })
    ));
}

#[test]
fn renewing_without_a_lease_is_rejected() {
    let mut state = populated();

    assert!(matches!(
        state.apply(&Command::RenewLease {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(15_000),
        }),
        Outcome::Rejected(Rejection::NoLease { .. })
    ));
}

/// The epoch is never reused — not even after a revocation. A reused epoch
/// would be indistinguishable from the old one for the sidecars.
#[test]
fn an_epoch_is_never_reused() {
    let mut state = populated();
    let Outcome::LeaseGranted { epoch: first } = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-1".to_owned(),
        now: UtcMillis::new(0),
        expires_at: UtcMillis::new(15_000),
    }) else {
        panic!("grant");
    };

    // **After expiry, to a different node** -- the only way on which a lease
    // changes its holder (ADR-0111). Until then a `RevokeLease` stood here and
    // after it a grant to **the same** node; that checks the epoch jump in the
    // harmless case and left open the case that matters.
    let Outcome::LeaseGranted { epoch: second } = state.apply(&Command::GrantLease {
        workload: "ledger".to_owned(),
        node: "node-2".to_owned(),
        now: UtcMillis::new(15_000),
        expires_at: UtcMillis::new(30_000),
    }) else {
        panic!("second grant");
    };

    assert!(second > first);
}

/// **There is no way to shed a valid lease early** (ADR-0111, determination 4).
///
/// That is the assurance the striking of `RevokeLease` brought, and it is a
/// statement about the **whole** command set: no command may remove a standing,
/// valid lease without withdrawing the workload itself. It is therefore checked
/// exhaustively -- against every variant there is, instead of against a
/// selection somebody has to maintain.
///
/// `RemoveWorkload` is the one exception, and it is no circumvention: whoever
/// withdraws the workload does not want it still writing.
#[test]
fn no_command_sheds_a_valid_lease() {
    for kind in tg_consensus::Command::KINDS.map(|(kind, _)| kind) {
        if kind == "remove_workload" {
            continue;
        }

        let mut state = populated();
        assert!(matches!(
            state.apply(&Command::GrantLease {
                workload: "ledger".to_owned(),
                node: "node-1".to_owned(),
                now: UtcMillis::new(0),
                expires_at: UtcMillis::new(15_000),
            }),
            Outcome::LeaseGranted { .. }
        ));

        for command in shed_attempts(kind) {
            state.apply(&command);
            let lease = state.lease("ledger");
            assert!(
                lease.is_some_and(|lease| lease.holder() == "node-1"),
                "{kind} shed the active role of 'ledger': {lease:?}"
            );
        }
    }
}

/// The attempts with which a variant could shed the lease.
///
/// Only the commands that can concern "ledger" at all get an attempt; for all
/// the rest the empty list is the right answer -- an `AllowTraffic` cannot shed
/// a lease, and enumerating it here would prove nothing.
fn shed_attempts(kind: &str) -> Vec<Command> {
    match kind {
        "set_active_instance" => vec![Command::SetActiveInstance {
            workload: "ledger".to_owned(),
            instance: 0,
        }],
        "clear_placement" => vec![Command::ClearPlacement {
            workload: "ledger".to_owned(),
        }],
        "grant_lease" => vec![Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(1_000),
            expires_at: UtcMillis::new(16_000),
        }],
        "renew_lease" => vec![Command::RenewLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(1_000),
            expires_at: UtcMillis::new(16_000),
        }],
        "remove_node" => vec![Command::RemoveNode {
            name: "node-1".to_owned(),
        }],
        "set_schedulability" => vec![Command::SetSchedulability {
            node: "node-1".to_owned(),
            mode: tg_consensus::Schedulability::Cordoned,
        }],
        "set_attachment" => vec![Command::SetAttachment {
            node: "node-1".to_owned(),
            mode: tg_consensus::Attachment::Detached,
        }],
        "revoke_trust" => vec![Command::RevokeTrust {
            node: "node-1".to_owned(),
        }],
        _ => Vec::new(),
    }
}

// --- Determinism -----------------------------------------------------------

/// Two nodes, the same command sequence, the same state — down to the byte.
/// That is the property on which the projection in 5d rests.
#[test]
fn the_same_log_yields_the_same_state_and_the_same_bytes() {
    let script = vec![
        upsert("api", None),
        upsert("ledger", Some("single-writer")),
        node("node-1"),
        node("node-2"),
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
        Command::AllowTraffic {
            from: "api".to_owned(),
            to: "ledger".to_owned(),
        },
        Command::RegisterTrust {
            node: "node-1".to_owned(),
            bundle: "bundle".to_owned(),
        },
    ];

    let mut left = ClusterState::default();
    let mut right = ClusterState::default();
    let mut left_outcomes = Vec::new();
    let mut right_outcomes = Vec::new();

    for command in &script {
        left_outcomes.push(left.apply(command));
    }
    for command in &script {
        right_outcomes.push(right.apply(command));
    }

    assert_eq!(left_outcomes, right_outcomes);
    assert_eq!(left, right);
    assert_eq!(
        tg_consensus::wire::encode_state(&left).expect("encodable"),
        tg_consensus::wire::encode_state(&right).expect("encodable")
    );
}

/// A refused command does not change the state — otherwise a rejection would be
/// half a mutation.
#[test]
fn a_rejected_command_leaves_no_trace() {
    let mut state = populated();
    let before = tg_consensus::wire::encode_state(&state).expect("encodable");

    for command in [
        Command::AssignPlacement {
            workload: "ghost".to_owned(),
            node: "node-1".to_owned(),
            instance: 0,
        },
        Command::AllowTraffic {
            from: "ghost".to_owned(),
            to: "api".to_owned(),
        },
        Command::GrantLease {
            workload: "api".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(1),
        },
        Command::SetActiveInstance {
            workload: "ledger".to_owned(),
            instance: 0,
        },
    ] {
        let outcome = state.apply(&command);
        if matches!(outcome, Outcome::Rejected(_)) {
            assert_eq!(
                tg_consensus::wire::encode_state(&state).expect("encodable"),
                before,
                "{} wrote despite the rejection",
                command.kind()
            );
        }
    }
}

/// The state goes through the snapshot format and comes back the same.
#[test]
fn the_state_survives_encoding() {
    let state = populated();
    let bytes = tg_consensus::wire::encode_state(&state).expect("encodable");
    let restored = tg_consensus::wire::decode_state(&bytes).expect("decodable");

    assert_eq!(state, restored);
}

// --- Cordon and drain in the state (phase 6) --------------------------------

/// **An unknown node is refused, not settled idempotently.**
///
/// "Cordoned" on something that does not exist would look to an operator like
/// "cordoned" — and they would move on to the restart reassured. That is the
/// exception to rule 1 in the module head, and it stands here because it is
/// one.
#[test]
fn cordoning_an_unknown_node_is_refused() {
    let mut state = ClusterState::default();

    let outcome = state.apply(&Command::SetSchedulability {
        node: "does-not-exist".to_owned(),
        mode: Schedulability::Cordoned,
    });

    assert!(matches!(
        outcome,
        Outcome::Rejected(Rejection::UnknownNode { .. })
    ));
}

/// The state is set and can be taken back.
#[test]
fn schedulability_is_set_and_taken_back() {
    let mut state = ClusterState::default();
    state.apply(&node("a"));

    assert_eq!(
        state.nodes()[0].1.schedulable(),
        Schedulability::Schedulable,
        "the default is schedulable"
    );

    for mode in [
        Schedulability::Draining,
        Schedulability::Cordoned,
        Schedulability::Schedulable,
    ] {
        assert_eq!(
            state.apply(&Command::SetSchedulability {
                node: "a".to_owned(),
                mode,
            }),
            Outcome::Applied
        );
        assert_eq!(state.nodes()[0].1.schedulable(), mode);
    }
}

/// **An upsert does not take a cordon back.**
///
/// It enters inventory — topology and capacity. An operator who corrects the
/// capacity while another drains the node would otherwise have lifted the drain
/// without noticing.
#[test]
fn an_upsert_does_not_lift_a_cordon() {
    let mut state = ClusterState::default();
    state.apply(&node("a"));
    state.apply(&Command::SetSchedulability {
        node: "a".to_owned(),
        mode: Schedulability::Draining,
    });

    state.apply(&node("a"));

    assert_eq!(
        state.nodes()[0].1.schedulable(),
        Schedulability::Draining,
        "the drain was silently lifted"
    );
}

/// A new node is schedulable — otherwise a cluster would stand still after
/// every addition.
#[test]
fn a_new_node_is_schedulable() {
    let mut state = ClusterState::default();
    state.apply(&node("fresh"));

    assert!(state.nodes()[0].1.schedulable().accepts_new());
}

// --- Detach and attach in the state (ADR-0054) ------------------------------

/// **An unknown node is refused** — the same exception to rule 1 as with the
/// cordon, and for the same reason: "detached" on something that does not exist
/// would look to an operator like "detached".
#[test]
fn detaching_an_unknown_node_is_refused() {
    let mut state = ClusterState::default();

    let outcome = state.apply(&Command::SetAttachment {
        node: "does-not-exist".to_owned(),
        mode: Attachment::Detached,
    });

    assert!(matches!(
        outcome,
        Outcome::Rejected(Rejection::UnknownNode { .. })
    ));
}

/// The default is **attached**, and the state can be taken back.
///
/// Anything else would mean that an upgrade takes every node out of the mesh.
#[test]
fn attachment_is_set_and_taken_back() {
    let mut state = ClusterState::default();
    state.apply(&node("a"));

    assert_eq!(
        state.nodes()[0].1.attachment(),
        Attachment::Attached,
        "the default is attached"
    );

    for mode in [Attachment::Detached, Attachment::Attached] {
        assert_eq!(
            state.apply(&Command::SetAttachment {
                node: "a".to_owned(),
                mode,
            }),
            Outcome::Applied
        );
        assert_eq!(state.nodes()[0].1.attachment(), mode);
    }
}

/// **An upsert does not reattach a detached node** — the same consideration as
/// with the cordon: whoever corrects the capacity while another detaches the
/// node would otherwise have lifted the detachment without noticing.
#[test]
fn an_upsert_does_not_reattach() {
    let mut state = ClusterState::default();
    state.apply(&node("a"));
    state.apply(&Command::SetAttachment {
        node: "a".to_owned(),
        mode: Attachment::Detached,
    });

    state.apply(&node("a"));

    assert_eq!(
        state.nodes()[0].1.attachment(),
        Attachment::Detached,
        "the upsert lifted the detachment"
    );
}

/// **Detach takes neither the ordinal nor the trust** (ADR-0054,
/// determination 4).
///
/// Not the number, because subnets would otherwise renumber (ADR-0039). Not the
/// trust, because the node could otherwise not come back by itself — then
/// "attach" would be a readmission procedure instead of a state change.
#[test]
fn detaching_keeps_the_ordinal_and_the_trust() {
    let mut state = ClusterState::default();
    state.apply(&node("a"));
    state.apply(&Command::InviteNode {
        node: "a".to_owned(),
        digest: tg_consensus::token_digest("whatever"),
        expires_at: 900,
    });
    state.apply(&Command::AdmitNode {
        node: "a".to_owned(),
        spki: "AAAA".to_owned(),
        at: 1,
    });

    let ordinal = state.ordinal("a").expect("the admission hands one out");
    assert!(
        state.trust("a").is_some(),
        "the admission registers the key"
    );

    state.apply(&Command::SetAttachment {
        node: "a".to_owned(),
        mode: Attachment::Detached,
    });

    assert_eq!(
        state.ordinal("a"),
        Some(ordinal),
        "the ordinal is gone -- subnets renumber (ADR-0039)"
    );
    assert!(
        state.trust("a").is_some(),
        "the trust is gone -- the node cannot come back by itself"
    );
}

// --- Key generations in the state (ADR-0055) --------------------------------

/// Admits a node — **without** entering inventory.
///
/// That is ADR-0037: what is admitted is only trust, no capacity. The rotation
/// hangs on exactly that and **not** on `UpsertNode`; otherwise an operator
/// would have to invent topology and capacity just to rotate a key.
fn admit(state: &mut ClusterState, name: &str) {
    state.apply(&Command::InviteNode {
        node: name.to_owned(),
        digest: tg_consensus::token_digest("whatever"),
        expires_at: 900,
    });
    state.apply(&Command::AdmitNode {
        node: name.to_owned(),
        spki: "AAAA".to_owned(),
        at: 1,
    });
}

/// The default is **zero** for both — "the first key the node gave itself".
///
/// An invented start number would make every existing node look like one that
/// has already rotated.
#[test]
fn the_default_generation_is_zero() {
    let mut state = ClusterState::default();
    admit(&mut state, "a");

    let generations = state.key_generations("a");

    assert_eq!(generations.identity, 0);
    assert_eq!(generations.underlay, 0);
}

/// **The rotation hangs on the admission, not on the inventory** (ADR-0037).
///
/// A node `UpsertNode` knows and `AdmitNode` does not has no keys — and
/// conversely an admitted one very much does, even without entered capacity.
/// The test nails both directions down.
#[test]
fn rotation_needs_admission_and_not_inventory() {
    let mut state = ClusterState::default();

    // Only inventory, no admission: refused.
    state.apply(&node("only-inventory"));
    let refused = state.apply(&Command::SetKeyGeneration {
        node: "only-inventory".to_owned(),
        kind: KeyKind::Underlay,
        generation: 1,
    });
    assert!(
        matches!(refused, Outcome::Rejected(Rejection::NotAdmitted { .. })),
        "without an admission nothing may rotate: {refused:?}"
    );

    // Only admission, no inventory: applied.
    admit(&mut state, "only-admission");
    assert_eq!(
        state.apply(&Command::SetKeyGeneration {
            node: "only-admission".to_owned(),
            kind: KeyKind::Underlay,
            generation: 1,
        }),
        Outcome::Applied,
        "an admission suffices -- capacity does not belong to it (ADR-0037)"
    );
}

/// The generation is set, and **both kinds are independent**.
///
/// A compromised underlay key is no reason to register the node's identity
/// anew.
#[test]
fn the_two_kinds_move_independently() {
    let mut state = ClusterState::default();
    admit(&mut state, "a");

    assert_eq!(
        state.apply(&Command::SetKeyGeneration {
            node: "a".to_owned(),
            kind: KeyKind::Underlay,
            generation: 4,
        }),
        Outcome::Applied
    );

    let generations = state.key_generations("a");
    assert_eq!(generations.underlay, 4);
    assert_eq!(
        generations.identity, 0,
        "the other kind was dragged along -- they rotate for different reasons"
    );
}

/// **Backwards is refused, the same is settled.**
///
/// Turning a generation back would mean making an old key valid again; setting
/// it to the same is idempotent (rule 1 in the module head).
#[test]
fn a_generation_never_goes_backwards() {
    let mut state = ClusterState::default();
    admit(&mut state, "a");
    state.apply(&Command::SetKeyGeneration {
        node: "a".to_owned(),
        kind: KeyKind::Identity,
        generation: 3,
    });

    assert_eq!(
        state.apply(&Command::SetKeyGeneration {
            node: "a".to_owned(),
            kind: KeyKind::Identity,
            generation: 3,
        }),
        Outcome::Applied,
        "the same is settled"
    );

    let refused = state.apply(&Command::SetKeyGeneration {
        node: "a".to_owned(),
        kind: KeyKind::Identity,
        generation: 2,
    });
    assert!(
        matches!(
            refused,
            Outcome::Rejected(Rejection::GenerationNotAdvancing { .. })
        ),
        "backwards must be refused: {refused:?}"
    );
    assert_eq!(
        state.key_generations("a").identity,
        3,
        "the refused generation changed the state"
    );
}

/// **A readmission begins at zero.**
///
/// `RemoveNode` takes the generations with it — otherwise a newly joining node
/// would inherit its predecessor's rotation history and rotate immediately.
#[test]
fn removing_a_node_forgets_its_generations() {
    let mut state = ClusterState::default();
    admit(&mut state, "a");
    state.apply(&Command::SetKeyGeneration {
        node: "a".to_owned(),
        kind: KeyKind::Underlay,
        generation: 7,
    });

    state.apply(&Command::RemoveNode {
        name: "a".to_owned(),
    });
    admit(&mut state, "a");

    assert_eq!(
        state.key_generations("a").underlay,
        0,
        "the new node inherited its predecessor's generations"
    );
}

// --- The key change as a compare-and-set (ADR-0055) -------------------------

/// The normal case: the expected key stands, so it is changed.
#[test]
fn rotating_trust_replaces_the_expected_key() {
    let mut state = ClusterState::default();
    admit(&mut state, "a");

    assert_eq!(
        state.apply(&Command::RotateTrust {
            node: "a".to_owned(),
            from: "AAAA".to_owned(),
            to: "BBBB".to_owned(),
        }),
        Outcome::Applied
    );
    assert_eq!(state.trust("a"), Some("BBBB"));
}

/// **A revocation cannot be undone by a request that was still in flight.**
///
/// That is the gap for whose sake `RotateTrust` exists: `RegisterTrust` writes
/// unconditionally, and a compromised node would thereby have lifted its own
/// blocking.
#[test]
fn a_revocation_cannot_be_undone_by_a_rotation_in_flight() {
    let mut state = ClusterState::default();
    admit(&mut state, "a");

    state.apply(&Command::RevokeTrust {
        node: "a".to_owned(),
    });

    let refused = state.apply(&Command::RotateTrust {
        node: "a".to_owned(),
        from: "AAAA".to_owned(),
        to: "BBBB".to_owned(),
    });

    assert!(
        matches!(
            refused,
            Outcome::Rejected(Rejection::UnexpectedTrust { .. })
        ),
        "a revoked node entered itself again: {refused:?}"
    );
    assert_eq!(
        state.trust("a"),
        None,
        "the revocation was lifted -- exactly the gap from ADR-0055"
    );
}

/// And a second change from the same old key does not take hold.
///
/// Two requests that believe they replace the same thing: the second is
/// overtaken.
#[test]
fn a_second_rotation_from_the_same_key_is_refused() {
    let mut state = ClusterState::default();
    admit(&mut state, "a");
    state.apply(&Command::RotateTrust {
        node: "a".to_owned(),
        from: "AAAA".to_owned(),
        to: "BBBB".to_owned(),
    });

    let refused = state.apply(&Command::RotateTrust {
        node: "a".to_owned(),
        from: "AAAA".to_owned(),
        to: "CCCC".to_owned(),
    });

    assert!(matches!(
        refused,
        Outcome::Rejected(Rejection::UnexpectedTrust { .. })
    ));
    assert_eq!(state.trust("a"), Some("BBBB"), "the overtaken one won");
}

/// **A node without inventory may rotate** (ADR-0037).
///
/// `RegisterTrust` demands an entered node — that was the second half of the
/// finding: what is admitted is only trust, no capacity, and a node without
/// `UpsertNode` would thereby not have been able to change its key.
#[test]
fn rotating_trust_needs_no_inventory() {
    let mut state = ClusterState::default();
    admit(&mut state, "a");

    assert!(
        state.nodes().is_empty(),
        "the admission enters no inventory (ADR-0037)"
    );
    assert_eq!(
        state.apply(&Command::RotateTrust {
            node: "a".to_owned(),
            from: "AAAA".to_owned(),
            to: "BBBB".to_owned(),
        }),
        Outcome::Applied
    );
}

/// **Without a declaration no generation** (ADR-0071, determination 1).
///
/// Refused and not settled idempotently — the exception to rule 1, as with the
/// cordon: "restarted" on something that does not exist would look to an
/// operator like "restarted".
#[test]
fn a_generation_for_an_unknown_workload_is_refused() {
    let mut state = ClusterState::default();

    let refused = state.apply(&Command::SetWorkloadGeneration {
        workload: "does-not-exist".to_owned(),
        instance: None,
        generation: 1,
    });

    assert!(
        matches!(
            refused,
            Outcome::Rejected(Rejection::UnknownWorkload { .. })
        ),
        "{refused:?}"
    );
}

/// **Backwards is refused, the same is settled** (ADR-0071).
///
/// And the bar for a single instance is its **effective** generation: a number
/// below it would be accepted and without effect.
#[test]
fn a_workload_generation_never_goes_backwards() {
    let mut state = ClusterState::default();
    state.apply(&upsert("api", None));

    assert_eq!(
        state.apply(&Command::SetWorkloadGeneration {
            workload: "api".to_owned(),
            instance: None,
            generation: 5,
        }),
        Outcome::Applied
    );
    assert_eq!(state.workload_generations("api").wanted(0), 5);
    assert_eq!(
        state.workload_generations("api").wanted(3),
        5,
        "a decree for all applies to an instance that does not yet exist too"
    );

    assert_eq!(
        state.apply(&Command::SetWorkloadGeneration {
            workload: "api".to_owned(),
            instance: None,
            generation: 5,
        }),
        Outcome::Applied,
        "the same is settled"
    );

    let refused = state.apply(&Command::SetWorkloadGeneration {
        workload: "api".to_owned(),
        instance: Some(0),
        generation: 3,
    });
    assert!(
        matches!(
            refused,
            Outcome::Rejected(Rejection::WorkloadGenerationNotAdvancing { .. })
        ),
        "below the effective generation would be accepted and without effect: {refused:?}"
    );
    assert_eq!(state.workload_generations("api").wanted(0), 5);
}

/// **A single instance leaves its siblings alone** — that is the surge control
/// (ADR-0071, determination 3).
#[test]
fn an_order_for_one_instance_leaves_the_others_alone() {
    let mut state = ClusterState::default();
    state.apply(&upsert("api", None));

    assert_eq!(
        state.apply(&Command::SetWorkloadGeneration {
            workload: "api".to_owned(),
            instance: Some(1),
            generation: 2,
        }),
        Outcome::Applied
    );

    assert_eq!(state.workload_generations("api").wanted(1), 2);
    assert_eq!(
        state.workload_generations("api").wanted(0),
        0,
        "otherwise the instance setting would be no surge control"
    );
}

/// **The withdrawal takes the generations with it** (ADR-0071,
/// determination 7).
///
/// A counter left lying would be a restart that at some point strikes a later
/// workload of the same name.
#[test]
fn removing_a_workload_forgets_its_generations() {
    let mut state = ClusterState::default();
    state.apply(&upsert("api", None));
    state.apply(&Command::SetWorkloadGeneration {
        workload: "api".to_owned(),
        instance: None,
        generation: 9,
    });

    state.apply(&Command::RemoveWorkload {
        name: "api".to_owned(),
    });
    state.apply(&upsert("api", None));

    assert_eq!(
        state.workload_generations("api").wanted(0),
        0,
        "the new workload inherited its predecessor's restart history"
    );
}

// --- The active instance (ADR-0111) -----------------------------------------

/// A declaration with several instances — the precondition of every promotion.
fn replicated(name: &str, class: &str, replicas: u32) -> Command {
    Command::UpsertWorkload {
        document: format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
             <workload name=\"{name}\" kind=\"service\" class=\"{class}\">\n\
             <image reference=\"example.com/{name}:1\"/>\n\
             <placement replicas=\"{replicas}\"/>\n\
             </workload>\n\
             </workloads>\n"
        ),
    }
}

/// **Without a decree instance 0 carries the active role** (ADR-0064,
/// determination 8).
///
/// The default is the whole reason why ADR-0111 is no break: an existing cluster
/// behaves unchanged until somebody promotes.
#[test]
fn without_a_decree_instance_zero_carries_the_active_role() {
    let state = populated();

    assert_eq!(state.active_instance("ledger"), 0);
    // For a workload that does not exist at all too: the reader is a default
    // and no statement about existence.
    assert_eq!(state.active_instance("does-not-exist"), 0);
}

/// The operator promotes, and the decree stands in the state.
#[test]
fn an_operator_promotes_a_replica() {
    let mut state = populated();
    assert_eq!(
        state.apply(&replicated("ledger", "single-writer", 3)),
        Outcome::Applied
    );

    assert_eq!(
        state.apply(&Command::SetActiveInstance {
            workload: "ledger".to_owned(),
            instance: 2,
        }),
        Outcome::Applied
    );

    assert_eq!(state.active_instance("ledger"), 2);
}

/// **The promotion grants no lease** (ADR-0111, determination 3).
///
/// That is the assurance on which everything hangs: it changes only from which
/// placement the leader derives the holder. If it lifts the fence, it is
/// `RevokeLease` under a different name.
#[test]
fn promoting_does_not_grant_or_shed_a_lease() {
    let mut state = populated();
    assert_eq!(
        state.apply(&replicated("ledger", "single-writer", 2)),
        Outcome::Applied
    );
    assert!(matches!(
        state.apply(&Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-1".to_owned(),
            now: UtcMillis::new(0),
            expires_at: UtcMillis::new(15_000),
        }),
        Outcome::LeaseGranted { .. }
    ));

    assert_eq!(
        state.apply(&Command::SetActiveInstance {
            workload: "ledger".to_owned(),
            instance: 1,
        }),
        Outcome::Applied
    );

    // The old lease stands unchanged.
    let lease = state.lease("ledger").expect("the lease still stands");
    assert_eq!(lease.holder(), "node-1");

    // And the fence holds: a grant to the new node is refused as long as it
    // applies. **That** is the difference from `RevokeLease`.
    assert!(matches!(
        state.apply(&Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(1_000),
            expires_at: UtcMillis::new(16_000),
        }),
        Outcome::Rejected(Rejection::LeaseHeld { .. })
    ));

    // After expiry it goes through -- the waiting time is the fence, not an error.
    assert!(matches!(
        state.apply(&Command::GrantLease {
            workload: "ledger".to_owned(),
            node: "node-2".to_owned(),
            now: UtcMillis::new(15_000),
            expires_at: UtcMillis::new(30_000),
        }),
        Outcome::LeaseGranted { .. }
    ));
}

/// **A replicated workload has no active role** (ADR-0064, determination 8).
///
/// Refused and not silently stored: a decree without effect looks to an operator
/// like an effective one.
#[test]
fn promoting_a_replicated_workload_is_refused() {
    let mut state = populated();

    assert!(matches!(
        state.apply(&Command::SetActiveInstance {
            workload: "api".to_owned(),
            instance: 0,
        }),
        Outcome::Rejected(Rejection::NotSingleWriter { .. })
    ));
}

/// A workload that does not exist, likewise.
#[test]
fn promoting_an_unknown_workload_is_refused() {
    let mut state = populated();

    assert!(matches!(
        state.apply(&Command::SetActiveInstance {
            workload: "does-not-exist".to_owned(),
            instance: 0,
        }),
        Outcome::Rejected(Rejection::UnknownWorkload { .. })
    ));
}

/// **An instance the declaration does not know is refused** (ADR-0111,
/// determination 6).
///
/// The silent outcome would be the worst: the planner would find no placement
/// for it, the leader would grant nobody a lease, and the workload would fall
/// mute — without an error appearing anywhere.
#[test]
fn promoting_to_an_instance_that_does_not_exist_is_refused() {
    let mut state = populated();
    assert_eq!(
        state.apply(&replicated("ledger", "single-writer", 2)),
        Outcome::Applied
    );

    assert!(matches!(
        state.apply(&Command::SetActiveInstance {
            workload: "ledger".to_owned(),
            instance: 2,
        }),
        Outcome::Rejected(Rejection::UnknownInstance {
            instance: 2,
            replicas: 2,
            ..
        })
    ));
    assert_eq!(state.active_instance("ledger"), 0);
}

/// **A shrinking that would strand the active instance is refused** (ADR-0111,
/// determination 6).
///
/// The surplus *placements* the same command continues to clear away silently —
/// that is the right treatment for a derivation of the planner. The active
/// instance is no derivation but a human's decree.
#[test]
fn shrinking_below_the_active_instance_is_refused() {
    let mut state = populated();
    assert_eq!(
        state.apply(&replicated("ledger", "single-writer", 3)),
        Outcome::Applied
    );
    assert_eq!(
        state.apply(&Command::SetActiveInstance {
            workload: "ledger".to_owned(),
            instance: 2,
        }),
        Outcome::Applied
    );

    assert!(matches!(
        state.apply(&replicated("ledger", "single-writer", 2)),
        Outcome::Rejected(Rejection::UnplaceableDefinition { .. })
    ));

    // And the declaration stayed unchanged: a rejection writes nothing (the
    // rule from `invariants.rs`).
    assert_eq!(state.active_instance("ledger"), 2);
}

/// Back to zero clears the entry away instead of holding it fast.
///
/// Two snapshots with the same meaning and different bytes would be a break of
/// determinism (ADR-0005): "never decreed" and "decreed to zero" are the same
/// situation.
#[test]
fn promoting_back_to_zero_leaves_no_trace() {
    let mut state = populated();
    assert_eq!(
        state.apply(&replicated("ledger", "single-writer", 2)),
        Outcome::Applied
    );
    let untouched = tg_consensus::wire::encode_state(&state).expect("encodable");

    for instance in [1, 0] {
        assert_eq!(
            state.apply(&Command::SetActiveInstance {
                workload: "ledger".to_owned(),
                instance,
            }),
            Outcome::Applied
        );
    }

    assert_eq!(state.active_instance("ledger"), 0);
    assert_eq!(
        tg_consensus::wire::encode_state(&state).expect("encodable"),
        untouched,
        "the return to the default must be the default byte for byte"
    );
}

/// If the workload is withdrawn, the decree goes with it.
///
/// Otherwise it would address a later workload of the same name — and that one
/// possibly carries its role elsewhere.
#[test]
fn removing_the_workload_takes_the_decree_with_it() {
    let mut state = populated();
    assert_eq!(
        state.apply(&replicated("ledger", "single-writer", 2)),
        Outcome::Applied
    );
    assert_eq!(
        state.apply(&Command::SetActiveInstance {
            workload: "ledger".to_owned(),
            instance: 1,
        }),
        Outcome::Applied
    );

    assert_eq!(
        state.apply(&Command::RemoveWorkload {
            name: "ledger".to_owned()
        }),
        Outcome::Applied
    );
    assert_eq!(
        state.apply(&replicated("ledger", "single-writer", 2)),
        Outcome::Applied
    );

    assert_eq!(state.active_instance("ledger"), 0);
}

// --- Retired commands (ADR-0112) --------------------------------------------

/// **A retired command no longer acts** (ADR-0112, determination 2).
///
/// `RegisterTrust` wrote `self.trust` unconditionally — past the one-time,
/// consensus-checked gate from ADR-0037. ADR-0055 named the danger and removed
/// the **caller**; the capability stayed open, and whoever reached the admin
/// service with `Class::Write` could use it.
#[test]
fn a_retired_command_no_longer_acts() {
    let mut state = populated();
    state.apply(&node("node-9"));

    let outcome = state.apply(&Command::RegisterTrust {
        node: "node-9".to_owned(),
        bundle: "-----BEGIN CERTIFICATE-----".to_owned(),
    });

    assert!(
        matches!(outcome, Outcome::Rejected(Rejection::RetiredCommand { .. })),
        "{outcome:?}"
    );
    assert_eq!(
        state.trust("node-9"),
        None,
        "the retired way must no longer enter trust (ADR-0037)"
    );
}

/// **And it stays readable** (ADR-0112, determination 2; ADR-0020).
///
/// The rejection is a statement of the state machine, not of the decoder. Were
/// the variant removed, a node with an old log would no longer come up — the
/// reason why `a_command_kind_can_never_be_removed` beside it checks
/// literals.
#[test]
fn a_retired_command_still_decodes() {
    let line = r#"{"register_trust":{"node":"node-1","bundle":"-----BEGIN CERTIFICATE-----"}}"#;

    assert!(tg_consensus::wire::decode_command(line).is_ok());
}

/// **The rejection names the command and what applies instead of it.**
///
/// An operator who uses a retired way needs the next step and not only a no —
/// otherwise they look for the error at their own end.
#[test]
fn the_refusal_names_the_replacement() {
    let mut state = populated();

    let Outcome::Rejected(rejection) = state.apply(&Command::ClearPlacement {
        workload: "ledger".to_owned(),
    }) else {
        panic!("must be refused");
    };

    let text = rejection.to_string();
    assert!(text.contains("clear_placement"), "{text}");
    assert!(text.contains("RemoveWorkload"), "{text}");
}

/// **A rejection writes nothing** — this one neither.
///
/// The rule from `invariants.rs`, here for the new branch: it stands **before**
/// `decide`, so it must on no way write past the state.
#[test]
fn a_retired_command_leaves_the_state_untouched() {
    let mut state = populated();
    state.apply(&Command::AssignPlacement {
        workload: "ledger".to_owned(),
        instance: 0,
        node: "node-1".to_owned(),
    });
    let before = tg_consensus::wire::encode_state(&state).expect("encodable");

    for command in [
        Command::ClearPlacement {
            workload: "ledger".to_owned(),
        },
        Command::RegisterTrust {
            node: "node-1".to_owned(),
            bundle: "x".to_owned(),
        },
    ] {
        assert!(matches!(
            state.apply(&command),
            Outcome::Rejected(Rejection::RetiredCommand { .. })
        ));
    }

    assert_eq!(
        tg_consensus::wire::encode_state(&state).expect("encodable"),
        before,
        "a retired command wrote despite the rejection"
    );
}
