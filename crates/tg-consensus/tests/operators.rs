//! The registration of an operator in consensus.
//!
//! Pure logic, without a cluster: what lies in the log, what is refused.
//!
//! # Why a list of its own
//!
//! Not `trust` beside it, and that is the decision: whoever takes over a **node**
//! does not thereby get an operator's authority — admitting a node only grants
//! network trust, never administrative capacity, and that boundary stays the one
//! that was promised. Two lists, two namespaces, and the **role** in the
//! certificate is the second half of it (`tg_identity::cluster`).

use base64::Engine as _;
use tg_consensus::{Class, ClusterState, Command, Outcome, Rejection};

/// Generates a readable SPKI: that of a real Ed25519 key.
///
/// # Returns
///
/// The base64-encoded DER bytes of a freshly generated Ed25519 public key.
fn spki() -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    base64::engine::general_purpose::STANDARD.encode(rcgen::PublicKeyData::der_bytes(&key))
}

/// Builds an `EnrolOperator` command for the given name and key.
///
/// # Parameters
///
/// - `operator`: the name to register.
/// - `spki`: the base64-encoded public key to associate with the name.
///
/// # Returns
///
/// The constructed command, carrying **the full set** of authorization
/// classes — this file checks the registration itself, not the classes,
/// which have a test file of their own. A rejection for a missing class
/// would otherwise look here like one for the key.
fn enrol(operator: &str, spki: &str) -> Command {
    Command::EnrolOperator {
        operator: operator.to_owned(),
        spki: spki.to_owned(),
        classes: Class::ALL.to_vec(),
    }
}

/// **Registered, and the read path names them.**
#[test]
fn an_enrolled_operator_reaches_the_state() {
    let mut state = ClusterState::default();
    let key = spki();

    assert_eq!(state.apply(&enrol("dana", &key)), Outcome::Applied);

    let seen: Vec<_> = state
        .operators()
        .map(|(name, spki, _)| (name, spki))
        .collect();
    assert_eq!(seen, vec![("dana", key.as_str())]);
}

/// **A revocation takes them away — and an unknown name is settled.**
///
/// Idempotent (rule 1), unlike a cordon on an unknown node: "no longer
/// registered" is the true statement for a name that never existed. A revocation
/// that fails on a typo would let an operator believe they achieved nothing —
/// while there was nothing to achieve.
///
/// **Both halves in one test**, because the second says nothing without the
/// first: an `Applied` on an unknown name would come from a state machine that
/// does nothing at all too.
#[test]
fn a_revocation_removes_him_and_an_unknown_name_is_done() {
    let mut state = ClusterState::default();
    state.apply(&enrol("dana", &spki()));

    assert_eq!(
        state.apply(&Command::RevokeOperator {
            operator: "dana".to_owned(),
        }),
        Outcome::Applied
    );
    assert_eq!(state.operators().count(), 0);

    assert_eq!(
        state.apply(&Command::RevokeOperator {
            operator: "does-not-exist".to_owned(),
        }),
        Outcome::Applied,
        "a revocation on an unknown name is settled, not refused"
    );
}

/// **A renewed registration replaces** — a key change needs no command of its
/// own.
///
/// Unconditionally, unlike node key rotation: there it is a compare-and-set,
/// because a **node** enters itself anew and a revoked one could undo that.
/// Here the command comes from somebody who may already administer — the
/// race does not exist.
#[test]
fn enrolling_again_replaces_the_key() {
    let mut state = ClusterState::default();
    let old = spki();
    let new = spki();
    assert_ne!(old, new);

    state.apply(&enrol("dana", &old));
    state.apply(&enrol("dana", &new));

    let seen: Vec<_> = state
        .operators()
        .map(|(name, spki, _)| (name, spki))
        .collect();
    assert_eq!(
        seen,
        vec![("dana", new.as_str())],
        "the new key must replace the old one and not stand beside it"
    );
}

/// **A name that fits into no SPIFFE ID is refused.**
///
/// The name goes into `spiffe://<domain>/operator/<name>`. What does not fit
/// in there would yield a credential **no port accepts** — and the error
/// would show only at the first connection, not at the registration: a
/// signer can mint an SVID for an unusable name without complaint, and
/// nothing would accept the result.
///
/// No dot is permitted, and that is the edge at which a fully qualified
/// domain name fails, since a dot introduces a path separator this identity
/// scheme does not expect there.
#[test]
fn a_name_that_is_no_spiffe_identity_is_refused() {
    let key = spki();
    for name in [
        "",
        "Dana",
        "dana.example.com",
        "dana/two",
        "-dana",
        "1dana",
        "dana ",
        &"d".repeat(64),
    ] {
        let mut state = ClusterState::default();
        let outcome = state.apply(&enrol(name, &key));
        assert!(
            matches!(
                outcome,
                Outcome::Rejected(Rejection::MalformedOperator { .. })
            ),
            "{name:?} must not be registrable, was {outcome:?}"
        );
        assert_eq!(state.operators().count(), 0, "{name:?} leaves nothing");
    }

    // The counter-check: without it a check that refuses **every** name would
    // be just as green -- and then no operator could be registered.
    let mut state = ClusterState::default();
    assert_eq!(state.apply(&enrol("dana-2", &key)), Outcome::Applied);
}

/// **An SPKI no verifier can read is refused.**
///
/// Otherwise an entry would stand in the log that **never** carries a handshake.
/// It is checked with the same reader the port uses (`NodeTrust::from_base64`) —
/// a check of its own would be a second opportunity to make it strict
/// differently.
///
/// # Where the limit lies, and why not narrower
///
/// Measured, the reader checks **readable and not empty** and nothing else: a
/// decodable value of three bytes gets through. Narrower would be possible (an
/// Ed25519 SPKI is 44 bytes of DER) and is rejected — then an operator key of a
/// different type would fall, and measured, the node path (`admit`) does **not
/// check** the SPKI at all. Being stricter than it would demand a rationale of
/// its own; there is none here.
///
/// What a value of this kind costs is thereby a handshake that fails — and not a
/// registration that goes through as a credential.
#[test]
fn an_unreadable_key_is_refused() {
    for key in ["", "no-base64!"] {
        let mut state = ClusterState::default();
        let outcome = state.apply(&enrol("dana", key));
        assert!(
            matches!(
                outcome,
                Outcome::Rejected(Rejection::MalformedOperator { .. })
            ),
            "{key:?} must not be registrable, was {outcome:?}"
        );
    }

    // The counter-check **and** the measured limit in one: a readable, non-empty
    // value gets through even when it is no real SPKI. Without it a check that
    // refuses every key would be just as green.
    let mut state = ClusterState::default();
    assert_eq!(state.apply(&enrol("dana", "QUJD")), Outcome::Applied);
}

/// **An operator and a node may share a name.**
///
/// The role in the certificate separates them, not the name. A name check
/// against the node list would be a coupling that protects nothing — and it
/// would turn a node name into a block on a human.
#[test]
fn an_operator_may_share_a_nodes_name() {
    let mut state = ClusterState::default();
    let key = spki();

    // An admitted node of this name.
    state.apply(&Command::InviteNode {
        node: "node-1".to_owned(),
        digest: "x".repeat(64),
        expires_at: 10,
    });

    assert_eq!(state.apply(&enrol("node-1", &key)), Outcome::Applied);
    assert_eq!(state.operators().count(), 1);
}

/// **No policy may register an operator.**
///
/// Otherwise a program would extend its **own** authority — the same reason for
/// which capacity-setting commands are barred from running as a policy.
#[test]
fn no_policy_may_enrol_an_operator() {
    assert!(!enrol("dana", "AAAA").may_be_policy());
    assert!(
        !Command::RevokeOperator {
            operator: "dana".to_owned(),
        }
        .may_be_policy()
    );
}
