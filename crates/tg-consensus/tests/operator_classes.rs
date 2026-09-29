//! The classes of an operator (ADR-0105).
//!
//! **Tests first** (CLAUDE.md): `tg-consensus` is a pure-logic crate.
//!
//! What is checked here is the **rule**, not its enforcement: which class a
//! command demands, what an old log entry means, and what the state knows about
//! an operator. The gate sits at the transport (determination 1) and has its
//! witnesses in `tgd`.

use tg_consensus::command::{Class, Command};
use tg_consensus::state::ClusterState;

/// The finding for whose sake the class `operators` exists (ADR-0105).
///
/// `Write` takes the **whole** command set. Were the operator administration to
/// lie in `write`, its holder could enter a second registration with every class
/// — and then `write` is not a class but `admin`.
#[test]
fn enrolling_and_revoking_are_not_write() {
    for command in [
        Command::EnrolOperator {
            operator: "dana".into(),
            spki: "AAAA".into(),
            classes: Class::ALL.to_vec(),
        },
        Command::RevokeOperator {
            operator: "dana".into(),
        },
    ] {
        assert_eq!(
            command.class(),
            Class::Operators,
            "{} must demand the class `operators` -- otherwise `write` contains \
             the authority to extend itself",
            command.kind()
        );
    }
}

/// The counter-check: an ordinary command is `write`.
///
/// Without it a classification that calls **everything** `operators` would be
/// just as green — and then no operator would reach the command set any more.
#[test]
fn an_ordinary_command_is_write() {
    let command = Command::RemoveWorkload { name: "api".into() };
    assert_eq!(command.class(), Class::Write);
}

/// **No command asks for `Class::Membership`** — measured, not assumed.
///
/// The membership change does not go through the log: `MembershipChange` is a
/// type of the admin service, and `openraft` writes the change itself. The class
/// therefore hangs on the **path** alone, and this witness nails down that it
/// stays that way: if a membership command is added one day, somebody must decide
/// whether it is classified here or there.
#[test]
fn no_command_asks_for_membership() {
    let orphan: Vec<_> = Command::KINDS
        .iter()
        .map(|(kind, _)| *kind)
        .filter(|kind| *kind == "set_voters" || kind.contains("membership"))
        .collect();
    assert!(
        orphan.is_empty(),
        "there is now a membership command ({orphan:?}) -- its class belongs decided (ADR-0105, determination 2)"
    );
}

/// **The log keeps its meaning** (ADR-0105, determination 6).
///
/// An `EnrolOperator` from before this ADR carried no field `classes` and
/// **meant** "may do anything". A state machine that reads it differently today
/// rewrites the past — and the log is kept (ADR-0020).
#[test]
fn an_entry_from_before_this_adr_still_means_everything() {
    let old = r#"{"enrol_operator":{"operator":"dana","spki":"AAAA"}}"#;
    let command: Command = serde_json::from_str(old).expect("an old entry must stay readable");

    let Command::EnrolOperator { classes, .. } = &command else {
        panic!("wrong variant: {command:?}");
    };
    let mut got = classes.clone();
    got.sort_unstable();
    let mut all = Class::ALL.to_vec();
    all.sort_unstable();
    assert_eq!(
        got, all,
        "the default must be the full set -- otherwise every operator \
         registered today loses their access at the upgrade"
    );
}

/// And the counter-direction: what stands there is read.
///
/// Without this half a default that **always** sets the full set would be just as
/// green — and the classes would have no effect.
#[test]
fn declared_classes_are_taken_as_written() {
    let doc = r#"{"enrol_operator":{"operator":"ci","spki":"AAAA","classes":["read"]}}"#;
    let command: Command = serde_json::from_str(doc).expect("readable");

    let Command::EnrolOperator { classes, .. } = &command else {
        panic!("wrong variant");
    };
    assert_eq!(classes.as_slice(), &[Class::Read]);
}

/// The state carries the classes with the key.
#[test]
fn the_state_remembers_the_classes() {
    let mut state = ClusterState::default();
    assert!(matches!(
        state.apply(&Command::EnrolOperator {
            operator: "ci".into(),
            spki: "AAAA".into(),
            classes: vec![Class::Read],
        }),
        tg_consensus::Outcome::Applied
    ));

    let found: Vec<_> = state.operators().collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "ci");
    assert_eq!(found[0].1, "AAAA");
    assert_eq!(found[0].2, &[Class::Read]);
}

/// A revocation takes the classes with it.
///
/// Otherwise a permission entry would stay standing for an operator that no
/// longer exists — and an auditor would read it as an authorization.
#[test]
fn revoking_takes_the_classes_with_it() {
    let mut state = ClusterState::default();
    state.apply(&Command::EnrolOperator {
        operator: "ci".into(),
        spki: "AAAA".into(),
        classes: vec![Class::Read],
    });
    state.apply(&Command::RevokeOperator {
        operator: "ci".into(),
    });
    assert_eq!(state.operators().count(), 0);
}

/// A registration without any class is **refused**.
///
/// It would be a registration that passes the handshake and may do nothing — and
/// an operator would look for the error at their key. The same exception to rule
/// 1 as with the cordon on an unknown node.
#[test]
fn an_enrolment_without_a_class_is_refused() {
    let mut state = ClusterState::default();
    let outcome = state.apply(&Command::EnrolOperator {
        operator: "empty".into(),
        spki: "AAAA".into(),
        classes: vec![],
    });
    let tg_consensus::Outcome::Rejected(rejection) = &outcome else {
        panic!("expected: a rejection, got: {outcome:?}");
    };
    assert_eq!(state.operators().count(), 0);

    // **And the message must not point in the wrong direction.** The variant is
    // called `MalformedOperator` and covers three reasons; if it named only name
    // and SPKI, an operator would look at the key while `--class` is missing. The
    // same rule as with the Debug output of `tgctl audit`: a rejection that names
    // the wrong cause costs the hour somebody spends looking in the wrong
    // place.
    let said = rejection.to_string();
    assert!(
        said.contains("class"),
        "the rejection must name the missing class: {said}"
    );
}

/// Duplicate settings are no error, but they do not stand twice in the log.
///
/// The log is kept (ADR-0020): `["read","read"]` and `["read"]` are the same
/// statement, and two spellings for one statement are two opportunities to read
/// it differently.
#[test]
fn duplicate_classes_are_normalised() {
    let mut state = ClusterState::default();
    state.apply(&Command::EnrolOperator {
        operator: "ci".into(),
        spki: "AAAA".into(),
        classes: vec![Class::Read, Class::Read, Class::Write],
    });
    let found: Vec<_> = state.operators().collect();
    assert_eq!(found[0].2, &[Class::Read, Class::Write]);
}
