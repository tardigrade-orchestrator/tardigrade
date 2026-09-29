//! `tgctl restore-volume` (ADR-0099, determination 6).
//!
//! # Why this witness was necessary
//!
//! It is the **most destructive** command an operator can type: it overwrites a
//! volume with an older state, node-local and **in no log**. Measured, it had
//! no test — what was checked was the mechanism (`tg-runtime`, against real
//! loop devices), not the line that triggers it.
//!
//! # What is checked here
//!
//! The confirmation, its **order**, and the form. The mechanism needs
//! privileges; these three do not — and exactly they stand between a typo and
//! lost data.

use std::process::Command as OsCommand;

fn run(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(dir)
        .arg("restore-volume")
        .args(args)
        .output()
        .expect("tgctl is startable")
}

/// **Without `--yes` nothing happens — and really nothing.**
///
/// The confirmation is the **action** (phase 10b, ADR-0027) and stands in no
/// field one could copy. The second assurance is the actual one: the volume
/// store is **not even opened**. With that the order is substantiated — a
/// refusal after the opening would look the same from outside and would already
/// have created something on disk.
#[test]
fn without_a_confirmation_nothing_is_touched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["data", "3"]);

    assert!(!out.status.success(), "{out:?}");
    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        said.contains("--yes") && said.contains("overwrites the data"),
        "the refusal does not name what is missing and why: {said}"
    );
    assert!(
        !dir.path().join("volumes").exists(),
        "the volume store was opened although the confirmation was missing"
    );
}

/// **A generation that is not a number names the form — even when the
/// confirmation is missing as well.**
///
/// The second half is the statement about the **order**, and it needs a call in
/// which **both** are wrong: with `--yes` in the line both orders give the same
/// message, so nothing decides there. If both are missing, the message says
/// which check came first.
///
/// The **form** comes first, and that is right: "the generation must be a
/// number" describes what an operator just typed. Whoever held `--yes` up to
/// them instead would let them append the confirmation and fail the call a
/// second time.
#[test]
fn a_generation_that_is_not_a_number_names_the_form() {
    let dir = tempfile::tempdir().expect("tempdir");

    for args in [
        ["data", "three", "--yes"].as_slice(),
        // **Both wrong** -- here the order decides.
        ["data", "three"].as_slice(),
    ] {
        let out = run(dir.path(), args);
        assert!(!out.status.success(), "{out:?}");
        let said = String::from_utf8(out.stderr).expect("utf8");
        assert!(
            said.contains("must be a number") && said.contains("restore-volume <volume>"),
            "the form is not named ({args:?}): {said}"
        );
        assert!(
            !said.contains("overwrites the data"),
            "the confirmation is the wrong diagnosis here ({args:?}): {said}"
        );
    }
}

/// **A volume that does not exist is named — not silently created.**
///
/// The counter-direction to the two above: with a confirmation and a valid
/// generation the call really goes into the store. Without this witness a
/// `restore-volume` that **always** fails at the form would be just as
/// green.
#[test]
fn a_volume_that_does_not_exist_is_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), &["data", "3", "--yes"]);

    assert!(!out.status.success(), "{out:?}");
    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        said.contains("'data'") && said.contains("does not exist"),
        "{said}"
    );
    // The store **was** opened -- that is the difference from the first
    // witness.
    assert!(
        dir.path().join("volumes").exists(),
        "with a confirmation the call belongs in the store: {said}"
    );
}
