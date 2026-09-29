//! The gate of the classes (ADR-0105, determinations 1 to 4).
//!
//! What is checked are the **pure** halves -- `class_of` and `may` -- and a guard
//! over the paths. The rule lies outside so that its rejection path is visible: an
//! access rule one can only check with a running Raft is one whose no nobody sees
//! (the same argument with which `may_administer` and `admitted` are pulled out).

use tg_consensus::Class;
use tgd::admin;

/// The socket holds **every** class (determination 4).
///
/// It is the way on which an operator gets a cluster going whose identities are
/// broken. Classifying it would mean making the recovery path dependent on what
/// it recovers (ADR-0043, ADR-0044).
#[test]
fn the_socket_holds_every_class() {
    for class in Class::ALL {
        assert!(
            admin::may(None, class),
            "the socket must hold '{class}' -- otherwise the recovery \
             presupposes what it recovers"
        );
    }
}

/// And the counter-check: a registration holds only what stands there.
///
/// Without it a rule that **always** gives `true` would be just as green -- and
/// the classes would have no effect.
#[test]
fn an_enrolment_holds_only_what_it_carries() {
    let read_only = [Class::Read];
    assert!(admin::may(Some(&read_only), Class::Read));
    for class in [
        Class::Write,
        Class::Membership,
        Class::Operators,
        Class::Secrets,
    ] {
        assert!(
            !admin::may(Some(&read_only), class),
            "a read-only registration must not hold '{class}'"
        );
    }
}

/// A registration without a class holds nothing.
///
/// That is the situation after a `RevokeOperator` that lies between handshake and
/// request -- fail-closed, and with that the revocation takes effect on the next
/// **request** instead of on the next connection.
#[test]
fn an_empty_enrolment_holds_nothing() {
    for class in Class::ALL {
        assert!(!admin::may(Some(&[]), class));
    }
}

/// `RekeyMaterial` is **not** a read (ADR-0105, determination 3).
///
/// It hands out every ciphertext of every secret (ADR-0100); a registration for a
/// dashboard would thereby hold the whole stock.
#[test]
fn the_ciphertexts_are_not_a_read() {
    assert_eq!(admin::class_of(admin::REKEY_MATERIAL), Some(Class::Secrets));
    assert_eq!(admin::class_of(admin::SECRETS), Some(Class::Read));
}

/// A signer refresh is **no** read class (ADR-0105, ADR-0107).
///
/// It exchanges the CA's shares -- the same order of magnitude as
/// `RekeyMaterial`, and therefore the same class: a registration for a dashboard
/// shall not be able to touch the signing group.
///
/// And **not** `Write`: no log entry arises, because the group is decoupled from
/// the Raft membership (ADR-0014, determination 1).
#[test]
fn a_signer_refresh_is_a_secrets_class() {
    assert_eq!(admin::class_of(admin::REFRESH_GROUP), Some(Class::Secrets));
    assert!(!admin::may(Some(&[Class::Read]), Class::Secrets));
    assert!(admin::may(Some(&[Class::Secrets]), Class::Secrets));
}

/// The membership change is a class of its own.
#[test]
fn the_quorum_has_its_own_class() {
    assert_eq!(admin::class_of(admin::MEMBERSHIP), Some(Class::Membership));
}

/// **An unknown path means no**, not "not checked".
///
/// A path without a class is either a typo of the client's or a new route nobody
/// has classified. Were it permeable, the second possibility would be an
/// unprotected route nobody notices.
#[test]
fn an_unknown_path_has_no_class() {
    assert_eq!(
        admin::class_of("/tardigrade.admin.v1.Admin/DoesNotExist"),
        None
    );
    assert_eq!(admin::class_of(""), None);
}

/// **Every route has a class** -- the guard the compiler cannot be (ADR-0105,
/// determination 2).
///
/// `&str` constants are not enumerable, so this witness reads the **source**:
/// every `pub const` with a `/tardigrade.admin.v1.Admin/` value must be
/// classified by `class_of`. A list in the test would be the shape this tree has
/// measured five times as a source of error.
///
/// What it **cannot** do stands with it: say whether the class is the *right*
/// one. That is said by the witnesses above.
#[test]
fn every_route_is_classified() {
    let source = include_str!("../../tg-admin/src/lib.rs");
    let mut seen = 0;
    let mut orphans = Vec::new();

    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": &str = ") else {
            continue;
        };
        let path = value.trim().trim_end_matches(';').trim_matches('"');
        if !path.starts_with("/tardigrade.admin.v1.Admin/") {
            continue;
        }
        seen += 1;
        if admin::class_of(path).is_none() {
            orphans.push(name.to_owned());
        }
    }

    assert!(
        seen > 8,
        "only {seen} routes were found -- the guard no longer reads the source \
         correctly"
    );
    assert!(
        orphans.is_empty(),
        "these routes have no class: {orphans:?} (ADR-0105, determination 2)"
    );
}

/// **A revocation holds nothing** -- and not everything (ADR-0105,
/// determination 1).
///
/// That is this gate's most dangerous confusion: [`admin::may`] reads `None` as
/// "no credential, so the socket" and releases **everything** (determination 4).
/// Whoever passes the registration through instead of deciding it thereby turns a
/// revocation over the network into full access.
///
/// Measured, the line was unguarded: turning it to `Class::ALL` left **all** 198
/// targets green. That is why the rule stands there as a function of its own, and
/// that is why its counter-direction stands here with it in one test -- without it
/// a rule that always holds nothing would be just as green, and no operator would
/// get through any more.
#[test]
fn a_revoked_enrolment_holds_nothing_not_everything() {
    assert!(admin::held(None).is_empty());
    for class in Class::ALL {
        assert!(
            !admin::may(Some(&admin::held(None)), class),
            "a revocation must no longer hold '{class}'"
        );
    }

    // The counter-direction: what is registered comes through unchanged.
    let read_only = vec![Class::Read];
    assert_eq!(admin::held(Some(read_only.clone())), read_only);
    assert!(admin::may(Some(&admin::held(Some(read_only))), Class::Read));
}

/// **An actor arises only where a connection substantiates it** (ADR-0050).
///
/// # What hangs on it
///
/// The attribution in the audit trail is ADR-0050's whole deliverable: who caused
/// an entry stands in the sealed payload (ADR-0045) and is thereby
/// forgery-resistant -- **if** the statement is true. It is, because it arises in
/// the **service**: from the socket's `uid` or from the name in the certificate
/// (ADR-0103), never from the message.
///
/// What the cluster itself writes therefore carries **no** actor -- the planner,
/// the capacity, the rotation and the tombstone policy all go over
/// `command.into()`, and that is `Submission::internal`. A `Submission::by` at one
/// of these places would be an invented sender in the archive, and one nobody can
/// distinguish from a real one any more.
///
/// # Why a tripwire
///
/// `Submission::by` is `pub` and must be -- the service lies in a different module
/// from the type. The compiler therefore cannot bound the place; a test can.
#[test]
fn only_the_admin_service_ever_names_an_actor() {
    let allowed = "crates/tgd/src/admin.rs";
    let mut seen = 0_usize;
    let mut offenders: Vec<String> = Vec::new();

    for crate_dir in ["crates/tgd/src", "crates/tgctl/src", "crates/tg-agent/src"] {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(crate_dir);
        for entry in std::fs::read_dir(&dir).expect("directory").flatten() {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read");
            // Only the production part: a test may provide an actor.
            let prod = source
                .split_once("#[cfg(test)]")
                .map_or(source.as_str(), |(before, _)| before);
            seen += 1;
            if !prod.contains("Submission::by") {
                continue;
            }
            let name = format!(
                "{crate_dir}/{}",
                path.file_name().unwrap().to_string_lossy()
            );
            if name.ends_with("admin.rs") && crate_dir == "crates/tgd/src" {
                continue;
            }
            offenders.push(name);
        }
    }

    assert!(seen >= 15, "only {seen} source files were read");
    assert!(
        offenders.is_empty(),
        "an actor arises outside {allowed}: {offenders:?} -- with that a \
         sender nobody has substantiated would stand in the archive (ADR-0050)"
    );
}
