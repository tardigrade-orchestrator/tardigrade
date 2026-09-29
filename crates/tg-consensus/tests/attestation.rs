//! Invitation and admission of a node.
//!
//! The bootstrap is the most security-critical place of the identity model: a
//! weak bootstrap is equivalent to identity theft. What is checked here are
//! therefore predominantly the cases in which something must **not** happen.
//!
//! The one-timeness of the token is consensus-backed: check and consumption lie
//! in the same application of the command. Two nodes that redeem the same token
//! are two log entries; the second finds nothing left. Exactly that stands below
//! as a test.

use tg_consensus::{ClusterState, Command, Outcome, Rejection};

const NOW: i64 = 1_800_000_000;
const TTL: i64 = 900;

/// The hash of a token, as the control plane forms it.
fn digest(token: &str) -> String {
    tg_consensus::token_digest(token)
}

/// Builds an `InviteNode` command for the given node and token.
///
/// # Parameters
/// - `node`: the node name to invite.
/// - `token`: the plaintext invitation token; only its digest is stored.
/// - `expires_at`: the timestamp after which the invitation is no longer valid.
///
/// # Returns
/// The command, ready to apply.
fn invite(node: &str, token: &str, expires_at: i64) -> Command {
    Command::InviteNode {
        node: node.to_owned(),
        digest: digest(token),
        expires_at,
    }
}

/// Builds an `AdmitNode` command for the given node and public key.
///
/// # Parameters
/// - `node`: the node name being admitted.
/// - `spki`: the node's public key, in the form stored as its trust anchor.
/// - `at`: the timestamp at which admission is attempted.
///
/// # Returns
/// The command, ready to apply.
fn admit(node: &str, spki: &str, at: i64) -> Command {
    Command::AdmitNode {
        node: node.to_owned(),
        spki: spki.to_owned(),
        at,
    }
}

/// **The normal case:** invited, admitted, key registered.
#[test]
fn an_invited_node_is_admitted_and_its_key_registered() {
    let mut state = ClusterState::default();

    assert_eq!(
        state.apply(&invite("node-1", "topsecret", NOW + TTL)),
        Outcome::Applied
    );
    assert_eq!(
        state.apply(&admit("node-1", "SPKI-1", NOW)),
        Outcome::Applied
    );

    assert_eq!(
        state.trust("node-1"),
        Some("SPKI-1"),
        "after the join the key is the identity (ADR-0037)"
    );
}

/// **A token is redeemed exactly once.**
///
/// The second attempt finds no invitation left — and that independently of which
/// key it brings along. Were it otherwise, an intercepted token could take the
/// node over after the fact.
#[test]
fn a_token_is_redeemed_exactly_once() {
    let mut state = ClusterState::default();
    state.apply(&invite("node-1", "topsecret", NOW + TTL));

    assert_eq!(
        state.apply(&admit("node-1", "SPKI-1", NOW)),
        Outcome::Applied
    );

    let second = state.apply(&admit("node-1", "SPKI-OF-THE-ATTACKER", NOW));
    assert_eq!(
        second,
        Outcome::Rejected(Rejection::NoInvitation {
            node: "node-1".to_owned()
        })
    );
    assert_eq!(
        state.trust("node-1"),
        Some("SPKI-1"),
        "the first key stays standing"
    );
}

/// Without an invitation no admission.
#[test]
fn a_node_without_an_invitation_is_refused() {
    let mut state = ClusterState::default();

    assert_eq!(
        state.apply(&admit("foreign", "SPKI", NOW)),
        Outcome::Rejected(Rejection::NoInvitation {
            node: "foreign".to_owned()
        })
    );
    assert_eq!(state.trust("foreign"), None);
}

/// **An expired invitation does not carry** — and it is cleared away in the
/// process so that it does not stay lying as a legacy.
#[test]
fn an_expired_invitation_does_not_admit() {
    let mut state = ClusterState::default();
    state.apply(&invite("node-1", "topsecret", NOW + TTL));

    let late = state.apply(&admit("node-1", "SPKI", NOW + TTL + 1));

    assert_eq!(
        late,
        Outcome::Rejected(Rejection::InvitationExpired {
            node: "node-1".to_owned(),
            expired_at: NOW + TTL,
        })
    );
    assert_eq!(state.trust("node-1"), None);
    assert!(
        !state.invited("node-1"),
        "an expired invitation does not stay lying"
    );
}

/// A new invitation replaces the old one.
///
/// That is the everyday case: an operator invites once more because the first
/// invitation did not arrive. The old token must then be **worthless**.
#[test]
fn a_fresh_invitation_replaces_the_previous_one() {
    let mut state = ClusterState::default();
    state.apply(&invite("node-1", "first", NOW + TTL));
    state.apply(&invite("node-1", "second", NOW + TTL));

    assert_eq!(
        state.invitation_digest("node-1"),
        Some(digest("second").as_str()),
        "the first token is worthless"
    );
}

/// **The revocation is an action, no expiry date.**
#[test]
fn revoking_trust_ends_the_nodes_identity_at_once() {
    let mut state = ClusterState::default();
    state.apply(&invite("node-1", "topsecret", NOW + TTL));
    state.apply(&admit("node-1", "SPKI-1", NOW));

    state.apply(&Command::RevokeTrust {
        node: "node-1".to_owned(),
    });

    assert_eq!(state.trust("node-1"), None);
}

/// A deregistered node takes its open invitation with it.
///
/// Otherwise a token would stay valid for a node that no longer exists.
#[test]
fn removing_a_node_also_drops_its_pending_invitation() {
    let mut state = ClusterState::default();
    state.apply(&invite("node-1", "topsecret", NOW + TTL));

    state.apply(&Command::RemoveNode {
        name: "node-1".to_owned(),
    });

    assert!(!state.invited("node-1"));
    assert_eq!(
        state.apply(&admit("node-1", "SPKI", NOW)),
        Outcome::Rejected(Rejection::NoInvitation {
            node: "node-1".to_owned()
        })
    );
}

/// **The hash is no token.** Two different tokens yield two different hashes,
/// and from the hash the token does not follow.
///
/// The test nails down above all that the state really holds the **hash** and not
/// the token — the log is kept, so a plaintext token in it would be a lasting
/// secret leak.
#[test]
fn the_state_holds_the_digest_and_not_the_token() {
    let mut state = ClusterState::default();
    state.apply(&invite("node-1", "topsecret", NOW + TTL));

    let stored = state.invitation_digest("node-1").expect("invited");

    assert_ne!(stored, "topsecret");
    assert_eq!(stored.len(), 64, "SHA-256 in hex");
    assert_ne!(digest("topsecret"), digest("topsecret2"));
}

/// **The join enters no capacity.**
///
/// That is the blast-radius protection: a stolen token yields a node with an
/// identity onto which nothing is placed. The test stands here so that nobody
/// later merges that "for convenience".
#[test]
fn admission_grants_identity_but_no_capacity() {
    let mut state = ClusterState::default();
    state.apply(&invite("node-1", "topsecret", NOW + TTL));
    state.apply(&admit("node-1", "SPKI-1", NOW));

    assert_eq!(state.trust("node-1"), Some("SPKI-1"));
    assert!(
        state.node("node-1").is_none(),
        "capacity is an operator's setting, no self-declaration of the node \
         (ADR-0037)"
    );
}

// ------------------------------------------------------------------ Token

/// **A token is random and has 256 bits.**
///
/// That is the only property that carries it: the hash in the state is without a
/// salt, and that is defensible only as long as the token is generated randomly
/// and is no password somebody memorizes.
#[test]
fn a_generated_token_is_random_and_long_enough() {
    use std::collections::BTreeSet;

    let tokens: BTreeSet<String> = (0..64).map(|_| tg_consensus::generate_token()).collect();

    assert_eq!(tokens.len(), 64, "two tokens were the same");
    for token in &tokens {
        assert_eq!(token.len(), 64, "256 bits in hex");
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

/// And its hash is the form that goes into the log.
#[test]
fn a_generated_token_hashes_into_the_form_the_log_holds() {
    let token = tg_consensus::generate_token();
    let mut state = ClusterState::default();

    state.apply(&Command::InviteNode {
        node: "node-1".to_owned(),
        digest: tg_consensus::token_digest(&token),
        expires_at: NOW + TTL,
    });

    assert_eq!(
        state.invitation_digest("node-1"),
        Some(tg_consensus::token_digest(&token).as_str())
    );
    assert_ne!(state.invitation_digest("node-1"), Some(token.as_str()));
}
