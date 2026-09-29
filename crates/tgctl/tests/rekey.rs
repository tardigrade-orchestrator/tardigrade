//! `tgctl cluster secret rekey` (ADR-0100).
//!
//! # Why this witness was necessary
//!
//! It is this system's most consequential command: it **rewrites every secret
//! of the cluster**. Measured, it had on the client side **not a single** test
//! — what was checked was the key ring (`tg-identity`) and the access to the
//! material (`tgd`), not the run that brings the two together.
//!
//! # What is checked here
//!
//! The three promises ADR-0100 gives the client: re-keying happens **here**
//! (determination 1), what already carries the primary key is **skipped** (a
//! log entry without a change would be one ADR-0020 retains forever), and an
//! abort is **resumable**.
//!
//! The service is provided, as at the neighbours: `CARGO_BIN_EXE_tgd` does not
//! exist in `tgctl`'s tests.

use std::process::Command as OsCommand;

use tg_admin::WriteResult;
use tg_identity::secrets::{DataKey, KeyRing, Sealed};

mod support;
use support::{Served, serve_rekey};

/// Two fresh keys as base64 — the primary one and the one to be replaced.
///
/// **As text and not as a value**: `DataKey` does not derive `Clone` (on
/// purpose), and a ring can be built from it again at any time.
fn two_keys() -> (String, String) {
    let primary = DataKey::generate().expect("key").to_base64();
    let previous = DataKey::generate().expect("key").to_base64();
    assert_ne!(primary, previous);
    (primary, previous)
}

fn ring(primary: &str, previous: Option<&str>) -> KeyRing {
    KeyRing::new(
        DataKey::from_base64(primary).expect("primary"),
        previous.map(|text| DataKey::from_base64(text).expect("to be replaced")),
    )
}

/// Puts both keys into the provided service's data directory.
fn place(served: &Served, primary: &str, previous: &str) {
    let identity = tg_identity::layout::dir(served.dir.path());
    std::fs::create_dir_all(&identity).expect("directory");
    std::fs::write(identity.join(tg_identity::layout::SECRETS_KEY), primary).expect("primary");
    std::fs::write(
        identity.join(tg_identity::layout::SECRETS_KEY_PREVIOUS),
        previous,
    )
    .expect("to be replaced");
}

fn rekey(served: &Served) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(served.dir.path())
        .args(["cluster", "secret", "rekey"])
        .output()
        .expect("tgctl is startable")
}

fn material(secrets: Vec<(String, Sealed)>) -> tg_admin::RekeyMaterialResponse {
    tg_admin::RekeyMaterialResponse {
        id: 1,
        last_applied: Some(7),
        secrets,
    }
}

fn applied() -> WriteResult {
    WriteResult::Applied {
        outcome: tg_model::command::Outcome::Applied,
        lints: Vec::new(),
    }
}

/// **Only what carries the old key is rewritten — and the new value opens with
/// the primary one.**
///
/// The second half is the actual promise: that a `PutSecret` arrives says
/// nothing about **what** stands in it. A run that sent random bytes would pass
/// the first half too — and afterwards the secret would be lost.
///
/// And the first carries the cost side: a run that re-keys **everything**
/// produces log entries without a change, and the log is retained forever
/// (ADR-0020).
#[tokio::test(flavor = "multi_thread")]
async fn only_what_carries_the_old_key_is_rewritten() {
    let (primary, previous) = two_keys();
    // One under the old key, one under the new.
    let old = ring(&previous, None).seal(b"old-secret").expect("seal");
    let fresh = ring(&primary, None).seal(b"new-secret").expect("seal");

    let served = serve_rekey(
        1,
        applied(),
        material(vec![("old".to_owned(), old), ("new".to_owned(), fresh)]),
    );
    place(&served, &primary, &previous);

    let out = rekey(&served);
    assert!(out.status.success(), "{out:?}");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("1 secret(s) re-keyed"), "{stdout}");
    assert!(stdout.contains("old: re-keyed"), "{stdout}");
    assert!(
        !stdout.contains("new: re-keyed"),
        "what already carries the primary one belongs skipped: {stdout}"
    );

    // **The value that arrived carries the old plaintext** -- sealed with the
    // primary key.
    let seen = served.seen.lock().expect("mutex").clone();
    assert_eq!(seen.len(), 1, "not exactly one command arrived: {seen:?}");
    let tg_model::command::Command::PutSecret { name, value } = &seen[0] else {
        panic!("no PutSecret: {seen:?}");
    };
    assert_eq!(name, "old");
    let keys = ring(&primary, Some(&previous));
    assert_eq!(
        keys.open(value).expect("open"),
        b"old-secret",
        "the new value does not carry the old plaintext"
    );
    assert!(
        !keys.needs_rekey(value),
        "the new value does not carry the primary key"
    );
}

/// **An abort says how far it got — and that a second run fetches the rest.**
///
/// That is the difference from `cluster apply`: there the half state is a
/// state, here `needs_rekey` decides per value, so the run is resumable.
/// Without the information an operator looks for a half state that does not
/// exist.
#[tokio::test(flavor = "multi_thread")]
async fn an_aborted_run_says_that_a_second_one_continues() {
    let (primary, previous) = two_keys();
    let old = ring(&previous, None).seal(b"secret").expect("seal");

    let served = serve_rekey(
        1,
        WriteResult::Failed {
            detail: "the store is not usable".to_owned(),
        },
        material(vec![("old".to_owned(), old)]),
    );
    place(&served, &primary, &previous);

    let out = rekey(&served);
    assert!(!out.status.success(), "an abort must end red");
    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        said.contains("a second run fetches the rest"),
        "the abort does not say that it is resumable: {said}"
    );
    assert!(said.contains("0 re-keyed before"), "{said}");
}

/// **Without a key to be replaced nothing runs** (ADR-0100, determination 3).
///
/// The re-keying presupposes that the old key still lies there — otherwise
/// there is nothing to open. The message names the path and the order, for
/// whoever fails here did not take the step before.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_previous_key_nothing_runs() {
    let (primary, _) = two_keys();
    let served = serve_rekey(1, applied(), material(Vec::new()));
    let identity = tg_identity::layout::dir(served.dir.path());
    std::fs::create_dir_all(&identity).expect("directory");
    std::fs::write(
        identity.join(tg_identity::layout::SECRETS_KEY),
        primary.as_bytes(),
    )
    .expect("primary");

    let out = rekey(&served);
    assert!(!out.status.success(), "{out:?}");
    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        said.contains("secrets.key.previous") && said.contains("ADR-0100"),
        "the message does not name the path and the order: {said}"
    );
    assert!(
        served.seen.lock().expect("mutex").is_empty(),
        "without a key nothing may be sent"
    );
}
