//! Ordinal and underlay announcement (ADR-0039 — phase 9d).
//!
//! Written before the implementation. Two things are fixed here, and both are
//! statements about what must **not** happen.
//!
//! # The ordinal is no position
//!
//! From it follows, over the pure function from phase 9a, a node's subnet, and
//! from that every route, every nftables rule and every `AllowedIP` in the mesh.
//! Were it to shift, all of that would point into the void — without an error
//! appearing anywhere. Hence: handed out at the admission, held over every
//! outage, freed **only** by express removal.
//!
//! # The log carries only what is public
//!
//! `AnnounceUnderlay` carries a public key and an endpoint. Both are harmless;
//! the private key stays on the node (ADR-0039, like the node key from
//! ADR-0037). What arrives here is **checked** — the log is kept (ADR-0020), and
//! what once stands in it somebody reads later.

use tg_consensus::{ClusterState, Command, Outcome, Rejection};

/// A valid X25519 key in the spelling `WireGuard` uses: 32 bytes, base64, 44
/// characters with a `=` at the end.
const KEY: &str = "iOnLpv2AL2r0YKGCXpXKaVUsBpVYAyLpJvGVc0nlDXo=";
const OTHER_KEY: &str = "2GAX7Nc1YvRHNzMWFqSNXHVDp0oXBSPfKrHWaBaZ2n8=";

fn invite_and_admit(state: &mut ClusterState, node: &str) -> Outcome {
    let digest = tg_consensus::token_digest(&format!("token-for-{node}"));
    state.apply(&Command::InviteNode {
        node: node.to_owned(),
        digest,
        expires_at: 10_000,
    });
    state.apply(&Command::AdmitNode {
        node: node.to_owned(),
        spki: format!("spki-{node}"),
        at: 100,
    })
}

fn announce(state: &mut ClusterState, node: &str, key: &str, endpoint: &str) -> Outcome {
    state.apply(&Command::AnnounceUnderlay {
        node: node.to_owned(),
        key: key.to_owned(),
        endpoint: endpoint.to_owned(),
        at: 200,
    })
}

// ------------------------------------------------------------------- Ordinal

#[test]
fn admission_hands_out_ordinals_in_order() {
    let mut state = ClusterState::default();

    for (index, node) in ["alpha", "beta", "gamma"].iter().enumerate() {
        assert_eq!(invite_and_admit(&mut state, node), Outcome::Applied);
        assert_eq!(
            state.ordinal(node),
            Some(u32::try_from(index).expect("fits")),
            "'{node}' got the wrong ordinal"
        );
    }
}

#[test]
fn no_two_admitted_nodes_share_an_ordinal() {
    let mut state = ClusterState::default();
    let names: Vec<String> = (0..20).map(|index| format!("node-{index}")).collect();

    for node in &names {
        invite_and_admit(&mut state, node);
    }

    let mut seen = std::collections::BTreeSet::new();
    for node in &names {
        let ordinal = state.ordinal(node).expect("admitted");
        assert!(seen.insert(ordinal), "{ordinal} handed out twice");
    }
}

/// A node that is still there keeps its number — even if it is invited and
/// admitted again. A different result would mean that a repeated admission
/// shifts a running node's subnet.
#[test]
fn re_admitting_a_node_that_was_never_removed_keeps_its_ordinal() {
    let mut state = ClusterState::default();
    invite_and_admit(&mut state, "alpha");
    invite_and_admit(&mut state, "beta");
    let before = state.ordinal("beta").expect("admitted");

    invite_and_admit(&mut state, "beta");

    assert_eq!(state.ordinal("beta"), Some(before));
}

/// Only the express removal frees the number.
#[test]
fn removing_a_node_frees_its_ordinal_for_the_next_one() {
    let mut state = ClusterState::default();
    invite_and_admit(&mut state, "alpha");
    invite_and_admit(&mut state, "beta");
    assert_eq!(state.ordinal("beta"), Some(1));

    state.apply(&Command::RemoveNode {
        name: "beta".to_owned(),
    });
    assert_eq!(state.ordinal("beta"), None);

    invite_and_admit(&mut state, "gamma");
    assert_eq!(
        state.ordinal("gamma"),
        Some(1),
        "the freed number is reused"
    );
}

/// Revoking a key is a security action. Renumbering a subnet is a topology
/// change. The one must not trigger the other.
#[test]
fn revoking_a_key_does_not_renumber_the_node() {
    let mut state = ClusterState::default();
    invite_and_admit(&mut state, "alpha");
    let before = state.ordinal("alpha").expect("admitted");

    state.apply(&Command::RevokeTrust {
        node: "alpha".to_owned(),
    });

    assert_eq!(state.ordinal("alpha"), Some(before));
}

/// A failure is no removal. The node was away for a week and still has its
/// subnet — that is exactly the assurance from ADR-0039.
#[test]
fn nothing_short_of_removal_takes_the_ordinal_away() {
    let mut state = ClusterState::default();
    invite_and_admit(&mut state, "alpha");
    invite_and_admit(&mut state, "beta");

    // Everything else that hangs on the node is touched.
    state.apply(&Command::RevokeTrust {
        node: "beta".to_owned(),
    });
    announce(&mut state, "beta", KEY, "10.0.0.2:51820");

    assert_eq!(state.ordinal("beta"), Some(1));
}

// -------------------------------------------------------------- Announcement

#[test]
fn an_announcement_stores_key_and_endpoint() {
    let mut state = ClusterState::default();
    invite_and_admit(&mut state, "alpha");

    assert_eq!(
        announce(&mut state, "alpha", KEY, "203.0.113.7:51820"),
        Outcome::Applied
    );

    let peer = state.underlay_of("alpha").expect("announced");
    assert_eq!(peer.key(), Some(KEY));
    assert_eq!(peer.endpoint(), Some("203.0.113.7:51820"));
    assert_eq!(peer.ordinal(), 0);
}

/// A node moves. The new announcement replaces the old one — and the ordinal
/// stays, for the subnet moves with it.
#[test]
fn a_second_announcement_replaces_the_first_but_keeps_the_ordinal() {
    let mut state = ClusterState::default();
    invite_and_admit(&mut state, "alpha");
    announce(&mut state, "alpha", KEY, "203.0.113.7:51820");

    announce(&mut state, "alpha", OTHER_KEY, "198.51.100.9:51820");

    let peer = state.underlay_of("alpha").expect("announced");
    assert_eq!(peer.key(), Some(OTHER_KEY));
    assert_eq!(peer.endpoint(), Some("198.51.100.9:51820"));
    assert_eq!(peer.ordinal(), 0);
}

/// Whoever is not admitted announces nothing. Otherwise the log would carry a
/// peer for a node nobody invited.
#[test]
fn an_announcement_before_admission_is_rejected() {
    let mut state = ClusterState::default();

    let outcome = announce(&mut state, "stranger", KEY, "203.0.113.7:51820");

    assert!(
        matches!(outcome, Outcome::Rejected(Rejection::NotAdmitted { .. })),
        "expected NotAdmitted, was {outcome:?}"
    );
    assert!(state.underlay_of("stranger").is_none());
}

/// The log is kept (ADR-0020). What once stands in it somebody reads later — so
/// it is checked before it comes in.
#[test]
fn a_malformed_key_is_rejected() {
    let mut state = ClusterState::default();
    invite_and_admit(&mut state, "alpha");

    for bad in [
        "",
        "too-short",
        "!!!!not-base64!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        "iOnLpv2AL2r0YKGCXpXKaVUsBpVYAyLpJvGVc0nlDXo",
        "iOnLpv2AL2r0YKGCXpXKaVUsBpVYAyLpJvGVc0nlDXoAAAA=",
    ] {
        let outcome = announce(&mut state, "alpha", bad, "203.0.113.7:51820");
        assert!(
            matches!(
                outcome,
                Outcome::Rejected(Rejection::MalformedUnderlay { .. })
            ),
            "'{}' was accepted: {outcome:?}",
            bad.escape_debug()
        );
    }

    assert!(
        state
            .underlay_of("alpha")
            .expect("admitted")
            .key()
            .is_none()
    );
}

#[test]
fn a_malformed_endpoint_is_rejected() {
    let mut state = ClusterState::default();
    invite_and_admit(&mut state, "alpha");

    for bad in [
        "",
        "203.0.113.7",
        "no-endpoint",
        "203.0.113.7:0",
        "203.0.113.7:99999",
        "example.com:51820",
    ] {
        let outcome = announce(&mut state, "alpha", KEY, bad);
        assert!(
            matches!(
                outcome,
                Outcome::Rejected(Rejection::MalformedUnderlay { .. })
            ),
            "'{}' was accepted: {outcome:?}",
            bad.escape_debug()
        );
    }
}

// -------------------------------------------------------------- Determinism

/// The same command sequence yields the same state — otherwise a snapshot would
/// be worthless as a basis of comparison (ADR-0005), and two nodes would compute
/// different subnets.
#[test]
fn the_same_log_yields_the_same_ordinals_everywhere() {
    let build = || {
        let mut state = ClusterState::default();
        for node in ["gamma", "alpha", "beta"] {
            invite_and_admit(&mut state, node);
        }
        state.apply(&Command::RemoveNode {
            name: "alpha".to_owned(),
        });
        invite_and_admit(&mut state, "delta");
        announce(&mut state, "delta", KEY, "203.0.113.7:51820");
        state
    };

    let left = build();
    let right = build();

    assert_eq!(left, right);
    assert_eq!(left.ordinal("gamma"), Some(0));
    assert_eq!(left.ordinal("beta"), Some(2));
    assert_eq!(
        left.ordinal("delta"),
        Some(1),
        "delta inherits the number of the removed alpha"
    );
}

// ================================================ The cluster network (0040)

/// Sets the cluster network.
fn set_network(state: &mut ClusterState, cidr: &str, node_prefix: u8) -> Outcome {
    state.apply(&Command::SetClusterNetwork {
        cidr: cidr.to_owned(),
        node_prefix,
    })
}

/// **An address space nobody can read is refused.**
///
/// Until here `SetClusterNetwork` carried an arbitrary string into the log and
/// reported `Applied`. An operator's typo thereby landed as a valid instruction
/// in the audit substrate (ADR-0020) — and on every node as a failure when
/// building the underlay, fail-soft and once per slice.
///
/// The difference from `UpsertWorkload` is the whole reason why it **can** be
/// checked here: this command carries everything needed for its check with it.
/// Referential integrity over a set a state machine cannot check; a CIDR it
/// can.
#[test]
fn an_unreadable_cluster_cidr_is_rejected() {
    let mut state = ClusterState::default();

    for bad in ["", "10.42.0.0", "10.42.0.0/33", "typo", "10.42.0.0/16 "] {
        assert!(
            matches!(
                set_network(&mut state, bad, 24),
                Outcome::Rejected(Rejection::MalformedNetwork { .. })
            ),
            "'{bad}' was accepted"
        );
    }
}

/// **A node prefix from which no subnet follows is refused.**
///
/// Wider than the cluster CIDR there is nothing, and narrower than `/30` nothing
/// is left over for network, broadcast and gateway. Both are pure arithmetic and
/// fully contained in the command.
#[test]
fn a_node_prefix_that_yields_no_subnet_is_rejected() {
    let mut state = ClusterState::default();

    for prefix in [8, 16, 31, 32] {
        assert!(
            matches!(
                set_network(&mut state, "10.42.0.0/16", prefix),
                Outcome::Rejected(Rejection::MalformedNetwork { .. })
            ),
            "/{prefix} was accepted"
        );
    }
}

/// The counter-check: a usable network is applied.
///
/// Without it a check that refuses **everything** would be just as green — and
/// the cluster would afterwards never have a network.
#[test]
fn a_usable_cluster_network_is_applied() {
    let mut state = ClusterState::default();

    assert!(matches!(
        set_network(&mut state, "10.42.0.0/16", 24),
        Outcome::Applied
    ));
}

/// **A network that no longer fits the ordinals already handed out is
/// refused.**
///
/// An ordinal is handed out at the admission and **held** (ADR-0039); from it
/// follows every route and every `AllowedIP`. A network narrowed after the fact
/// would take existing nodes' subnets away — silently, for the error would appear
/// only on the node and there fail-soft.
#[test]
fn narrowing_the_network_below_the_ordinals_in_use_is_rejected() {
    let mut state = ClusterState::default();
    set_network(&mut state, "10.42.0.0/16", 24);

    // Three nodes, so the ordinals 0, 1 and 2.
    invite_and_admit(&mut state, "node-a");
    invite_and_admit(&mut state, "node-b");
    invite_and_admit(&mut state, "node-c");

    // /23 with /24 per node carries **two** subnets -- the ordinal 2 would lie
    // outside. The prefix itself is flawless; it is refused solely because of the
    // numbers already handed out, and that is what matters here.
    assert!(
        matches!(
            set_network(&mut state, "10.42.0.0/23", 24),
            Outcome::Rejected(Rejection::MalformedNetwork { .. })
        ),
        "a network for two nodes was accepted although three are admitted"
    );

    // And the counter-check beside it: the same network with room for three is
    // accepted. Without it the case above would only show that something or
    // other is refused.
    assert!(matches!(
        set_network(&mut state, "10.42.0.0/22", 24),
        Outcome::Applied
    ));
}

/// **Where there is no subnet left, no node is admitted any more.**
///
/// Until here `next_free_ordinal` handed out the next free number and let the
/// node join with it; the subnet failed only on the node, in a path that is
/// fail-soft. The cluster therefore admitted a node for which it has no
/// addresses, and the log reported `Applied`.
#[test]
fn a_node_beyond_the_address_space_is_not_admitted() {
    let mut state = ClusterState::default();
    // /24 with /25 per node: exactly two subnets.
    set_network(&mut state, "10.42.0.0/24", 25);

    assert!(matches!(
        invite_and_admit(&mut state, "node-a"),
        Outcome::Applied
    ));
    assert!(matches!(
        invite_and_admit(&mut state, "node-b"),
        Outcome::Applied
    ));

    assert!(
        matches!(
            invite_and_admit(&mut state, "node-c"),
            Outcome::Rejected(Rejection::ClusterFull { .. })
        ),
        "a third node was admitted although the network carries two"
    );
}

/// The counter-check: **without** a set network admission carries on.
///
/// The address space is a setting that may come later (ADR-0040); a cluster that
/// admitted no node before it would never come up.
#[test]
fn without_a_network_admission_is_unbounded() {
    let mut state = ClusterState::default();

    for node in ["node-a", "node-b", "node-c"] {
        assert!(matches!(
            invite_and_admit(&mut state, node),
            Outcome::Applied
        ));
    }
}

/// **How full the address space is can be asked** (ADR-0069).
///
/// The ADR names it as an open point: an operator noticed it at the **first
/// rejection**, and that comes at the admission of a node — that is, when they
/// need it. Two numbers, so that an alarm rule can form the distance; a ratio
/// would hide how near it really is.
#[test]
fn the_address_space_says_how_full_it_is() {
    let mut state = ClusterState::default();

    // Without an address plan there is no capacity to report. An invented number
    // would be worse than none -- the same rule as with `tg_node_last_report`.
    assert_eq!(state.address_capacity(), None);

    set_network(&mut state, "10.42.0.0/24", 25);
    assert_eq!(state.address_capacity(), Some(2));
    assert_eq!(state.ordinals_used(), 0);

    invite_and_admit(&mut state, "node-a");
    assert_eq!(state.ordinals_used(), 1);
    invite_and_admit(&mut state, "node-b");
    assert_eq!(state.ordinals_used(), 2);

    // The counter-check: a refused third does not count along. Without it a
    // number that simply counts every attempt would be just as green.
    assert!(matches!(
        invite_and_admit(&mut state, "node-c"),
        Outcome::Rejected(Rejection::ClusterFull { .. })
    ));
    assert_eq!(state.ordinals_used(), 2);
}
