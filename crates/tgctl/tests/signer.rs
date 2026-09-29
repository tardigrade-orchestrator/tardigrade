//! `tgctl signer repair` — the repair of a seat (ADR-0108, determination 7).
//!
//! **A verb group of its own**, and the reason is the same for which `cluster`
//! is separate from `apply`: two targets, two verbs. Here it is a third target
//! — the signing group is **decoupled** from consensus (ADR-0014,
//! determination 1), seat and Raft identifier are independent (ADR-0097), and
//! this command talks to **no** admin socket: it dials the helpers' signer
//! ports and puts material down. Under `cluster` it would be a verb that works
//! without a cluster.
//!
//! What is checked is the **operation**: which settings it demands, what it
//! refuses, and in which order. That the path carries is said by the witnesses
//! against real processes (`tgd/tests/signing.rs`); that the preparation is
//! right by the one in `tgd/tests/repair_client.rs`.

use std::process::Command;

fn tgctl(args: &[&str]) -> (String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_tgctl"))
        .args(args)
        .output()
        .expect("tgctl");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    (text, out.status.success())
}

/// **Without a verb the message names the verbs.**
#[test]
fn the_group_names_its_verbs() {
    let (text, ok) = tgctl(&["signer"]);

    assert!(!ok, "without a verb there is nothing to do");
    assert!(text.contains("repair"), "{text}");
}

/// **Without a seat no repair** — and the message names the form.
#[test]
fn repair_needs_a_seat() {
    let (text, ok) = tgctl(&["signer", "repair"]);

    assert!(!ok);
    assert!(
        text.contains("--helper"),
        "the form belongs with it: {text}"
    );
}

/// **Zero is no seat** — and it is refused before the disk.
///
/// The boundary lies at zero and **not at five**, and that is a decision: how
/// many places there are stands in the **group key**
/// (`min_signers`/`verifying_shares`, ADR-0014) — an upper bound in the type
/// would be a second source, and the same number in two places is two
/// opportunities to disagree. A `6` in a group of five therefore stands out
/// later, but in the right place: there is no `signers/6.pem`, and `restore`
/// finds no `verifying_share`.
#[test]
fn zero_is_no_seat_and_is_refused_before_the_disk() {
    let (text, ok) = tgctl(&[
        "--data-dir",
        "/does-not-exist",
        "signer",
        "repair",
        "0",
        "--helper",
        "1=http://x",
    ]);

    assert!(!ok);
    assert!(
        !text.contains("/does-not-exist"),
        "the seat comes before the disk: {text}"
    );
}

/// **`--helper` without `=` is named, not skipped.**
///
/// A skipped helper would be a run with `t-1` contributions — and that fails
/// only in step 3, at a place that says nothing about the cause (the finding
/// from 7b: `repair_share_part3` does not count the sigmas).
#[test]
fn a_helper_without_an_url_is_named() {
    let (text, ok) = tgctl(&[
        "--data-dir",
        "/does-not-exist",
        "signer",
        "repair",
        "5",
        "--helper",
        "broken",
    ]);

    assert!(!ok);
    assert!(text.contains("broken"), "{text}");
    assert!(
        !text.contains("/does-not-exist"),
        "the setting comes before the disk: {text}"
    );
}

/// **Without a single helper it is refused** — before the disk.
///
/// `Repair::prepare` checks the threshold against the group key
/// (`min_signers`, so no second source). That one must stand there **at all**
/// is a question of operation and belongs here.
#[test]
fn repair_needs_at_least_one_helper() {
    let (text, ok) = tgctl(&["--data-dir", "/does-not-exist", "signer", "repair", "5"]);

    assert!(!ok);
    assert!(text.contains("--helper"), "{text}");
    assert!(
        !text.contains("/does-not-exist"),
        "the setting comes before the disk: {text}"
    );
}
