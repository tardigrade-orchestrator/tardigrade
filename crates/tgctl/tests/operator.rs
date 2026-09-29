//! `tgctl operator …` (ADR-0103, ADR-0105).
//!
//! # Why these witnesses were necessary
//!
//! Measured, the whole operator surface had **no** test on the client side.
//! What was checked was the state machine (`tg-consensus`), the gate at the
//! transport (`tgd`) and the usage help — not the line with which a human
//! creates a registration.
//!
//! And that is where the work lies: `--class` is **mandatory with no default**
//! (ADR-0105 — a default would be a decision nobody made), comes
//! comma-separated, and an unknown name is refused instead of skipped. A class
//! that silently drops away is a registration that may do less than intended —
//! and the error showed up only at the first call.

use std::process::Command as OsCommand;

use tg_admin::WriteResult;
use tg_model::command::Class;

mod support;
use support::{Served, serve};

fn run(served: &Served, args: &[&str]) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(served.dir.path())
        .arg("operator")
        .args(args)
        .output()
        .expect("tgctl is startable")
}

fn applied() -> WriteResult {
    WriteResult::Applied {
        outcome: tg_model::command::Outcome::Applied,
        lints: Vec::new(),
    }
}

/// **The classes arrive, in the set that stood there.**
///
/// Two of five, and the three others must **not** be among them: an `enrol`
/// that sends the full set would pass a count — and the registration would
/// afterwards be allowed everything, including entering further operators
/// (ADR-0105: `write` is without the class `operators` of its own not
/// `admin`).
#[tokio::test(flavor = "multi_thread")]
async fn the_named_classes_arrive_and_no_others() {
    let served = serve(1, applied());

    let out = run(
        &served,
        &["enrol", "dana", "MCowBQYDK2Vw", "--class", "read,write"],
    );
    assert!(out.status.success(), "{out:?}");

    let seen = served.seen.lock().expect("mutex").clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let tg_model::command::Command::EnrolOperator {
        operator,
        spki,
        classes,
    } = &seen[0]
    else {
        panic!("no EnrolOperator: {seen:?}");
    };
    assert_eq!(operator, "dana");
    assert_eq!(spki, "MCowBQYDK2Vw");
    assert_eq!(classes, &vec![Class::Read, Class::Write]);
}

/// **A repeated class is deduplicated.**
///
/// The log is retained (ADR-0020), and `["read","read"]` is the same statement
/// as `["read"]` — two forms for one fact would be two forms in the
/// archive.
#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_class_is_deduplicated() {
    let served = serve(1, applied());

    let out = run(
        &served,
        &["enrol", "dana", "MCowBQYDK2Vw", "--class", "read,read"],
    );
    assert!(out.status.success(), "{out:?}");

    let seen = served.seen.lock().expect("mutex").clone();
    let tg_model::command::Command::EnrolOperator { classes, .. } = &seen[0] else {
        panic!("{seen:?}");
    };
    assert_eq!(classes, &vec![Class::Read]);
}

/// **Without `--class` nothing is sent — and the message names the choice.**
///
/// The second assurance is the actual one: the command must not reach the
/// socket. A registration without a class would be one that passes the
/// handshake and may do nothing, and an operator would look for the error at
/// their key.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_class_nothing_is_sent() {
    let served = serve(1, applied());

    let out = run(&served, &["enrol", "dana", "MCowBQYDK2Vw"]);

    assert!(!out.status.success(), "{out:?}");
    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(said.contains("--class is missing"), "{said}");
    // The choice belongs with it -- otherwise an operator must guess it.
    for class in Class::ALL {
        assert!(
            said.contains(class.name()),
            "'{}' is missing from the choice: {said}",
            class.name()
        );
    }
    assert!(
        served.seen.lock().expect("mutex").is_empty(),
        "without a class nothing may be sent"
    );
}

/// **An unknown class name is refused, not skipped.**
///
/// Skipped it would be a registration that may do less than intended — and that
/// showed up only at the first call, as an authorization error at a place that
/// has nothing to do with the typo.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_class_is_refused_not_skipped() {
    let served = serve(1, applied());

    let out = run(
        &served,
        &["enrol", "dana", "MCowBQYDK2Vw", "--class", "read,reed"],
    );

    assert!(!out.status.success(), "{out:?}");
    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(said.contains("unknown class 'reed'"), "{said}");
    assert!(
        served.seen.lock().expect("mutex").is_empty(),
        "a line with a typo may send nothing"
    );
}

/// **The revocation carries the name and nothing else.**
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_carries_the_name() {
    let served = serve(1, applied());

    let out = run(&served, &["revoke", "dana"]);
    assert!(out.status.success(), "{out:?}");

    let seen = served.seen.lock().expect("mutex").clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let tg_model::command::Command::RevokeOperator { operator } = &seen[0] else {
        panic!("no RevokeOperator: {seen:?}");
    };
    assert_eq!(operator, "dana");
}

/// **`keygen` hands out the private part and the SPKI separately.**
///
/// The private part stays on the operator's machine (ADR-0103), the SPKI line
/// is what `enrol` gets — and it is no secret. The separation is the promise:
/// on **stdout** stand both, but the SPKI with its prefix, so that `enrol` does
/// not confuse it with the key.
///
/// **No socket needed** — the key arises at the operator, and this call talks
/// to nobody. That is half the promise of ADR-0103.
#[test]
fn keygen_keeps_the_private_part_and_hands_out_the_spki() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(dir.path())
        .args(["operator", "keygen"])
        .output()
        .expect("tgctl is startable");

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("BEGIN PRIVATE KEY"), "{stdout}");
    let spki = stdout
        .lines()
        .find_map(|line| line.strip_prefix("spki: "))
        .expect("no SPKI line");
    // **And it is usable**: `enrol` does not check the form, but the state
    // machine reads base64 (ADR-0087).
    assert!(
        tg_identity::control::unbase64(spki).is_ok(),
        "the SPKI line is no base64: {spki}"
    );
    // The call puts nothing down -- the key belongs to the operator.
    assert!(
        std::fs::read_dir(dir.path())
            .expect("read")
            .next()
            .is_none(),
        "keygen put something down in the data directory"
    );
}
