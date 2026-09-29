//! The writing `tgctl node` subcommands (ADR-0047, ADR-0049, ADR-0055).
//!
//! # Why these witnesses were necessary
//!
//! Measured, **none** of them had a test: `upsert`, `rotate`, `drain` and
//! `uncordon` write into consensus, and what was checked was the state machine
//! behind them — not the line a human types.
//!
//! `upsert` is the most consequential: it is the only way on which an operator
//! sets a node's **capacity and reserve** — the two numbers the planner reckons
//! with (ADR-0034, ADR-0047).
//!
//! And that is where the work lies: `--resource name=number` is an
//! **enumeration** and not a setting (to be given several times), `--reserve`
//! is the same form for a different pot, and `--site/--hall/--rack` are
//! mandatory **with no default** — a node that silently lands in `site=""` lies
//! in the same failure domain as every other one without a setting, and the
//! anti-affinity from ADR-0011 would be without effect for both.

use std::process::Command as OsCommand;

use tg_admin::WriteResult;

mod support;
use support::{Served, serve};

fn upsert(served: &Served, args: &[&str]) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(served.dir.path())
        .args(["node", "upsert"])
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

/// **Both pots arrive, and they are not mixed up.**
///
/// Capacity and reserve are the same form (`name=number`) and two different
/// statements: what a node **has**, and what of it the cluster may **not** take
/// (ADR-0047). A setup with only one of the two could not show a mix-up — that
/// is why both stand here, with different numbers.
///
/// And `--resource` stands **twice**: it is an enumeration, not a setting at
/// which the last occurrence wins.
#[tokio::test(flavor = "multi_thread")]
async fn capacity_and_reserve_arrive_without_being_mixed_up() {
    let served = serve(1, applied());

    let out = upsert(
        &served,
        &[
            "node-7",
            "--site",
            "fra",
            "--hall",
            "h1",
            "--rack",
            "r3",
            "--resource",
            "cpu-millicores=4000",
            "--resource",
            "memory-bytes=64",
            "--reserve",
            "cpu-millicores=1000",
        ],
    );
    assert!(out.status.success(), "{out:?}");

    let seen = served.seen.lock().expect("mutex").clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let tg_model::command::Command::UpsertNode {
        name,
        topology,
        capacity,
        reserved,
        source,
    } = &seen[0]
    else {
        panic!("no UpsertNode: {seen:?}");
    };

    assert_eq!(name, "node-7");
    assert_eq!(topology.site, "fra");
    assert_eq!(topology.hall, "h1");
    assert_eq!(topology.rack, "r3");
    assert_eq!(capacity.get("cpu-millicores"), 4000);
    assert_eq!(capacity.get("memory-bytes"), 64);
    assert_eq!(reserved.get("cpu-millicores"), 1000);
    // **The reserve carries only what stood there.** Without this assurance a
    // call that fills both pots alike would be just as green -- and the planner
    // would retroactively have lost room (ADR-0047).
    assert_eq!(reserved.get("memory-bytes"), 0);
    // **Issued by hand**, and that is the whole difference from what the leader
    // writes out of a policy (ADR-0049).
    assert_eq!(*source, tg_model::command::Origin::Operator);
}

/// **A missing failure domain is said — before the socket search.**
///
/// Measured, the same call reported "no admin socket — is tgd running on this
/// node?", and an operator looked at the service instead of at their line. The
/// same order as at `node invite` and `cluster allow`: the setting a human
/// typed comes first.
///
/// The test therefore runs **without** a provided service — only that way does
/// it check the order and not merely the refusal.
#[test]
fn a_missing_failure_domain_is_named_before_the_socket_is_looked_for() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(dir.path())
        .args(["node", "upsert", "node-7", "--hall", "h1", "--rack", "r3"])
        .output()
        .expect("tgctl is startable");

    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        said.contains("--site"),
        "the missing setting is not named: {said}"
    );
    assert!(
        !said.contains("admin socket"),
        "the socket must not be the diagnosis here: {said}"
    );
}

/// **And a malformed resource setting likewise.**
///
/// `--resource broken` without `=number` measurably reported the same "no admin
/// socket". The form belongs to the line, not to the service.
#[test]
fn a_malformed_resource_is_named_before_the_socket_is_looked_for() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(dir.path())
        .args([
            "node",
            "upsert",
            "node-7",
            "--site",
            "fra",
            "--hall",
            "h1",
            "--rack",
            "r3",
            "--resource",
            "broken",
        ])
        .output()
        .expect("tgctl is startable");

    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        said.contains("name=number"),
        "the form is not named: {said}"
    );
    assert!(
        !said.contains("admin socket"),
        "the socket must not be the diagnosis here: {said}"
    );
}

/// **The three blocking verbs land on three different states.**
///
/// `cordon`, `drain` and `uncordon` are a state in the log and not an action
/// (phase 6) — and the difference between `Cordoned` and `Draining` is exactly
/// the one that matters: the one keeps existing workloads, the other lets them
/// move away. A mix-up would be a node an operator wanted to block and that
/// empties itself out.
///
/// Measured, none of the three was checked.
#[tokio::test(flavor = "multi_thread")]
async fn the_three_verbs_reach_three_different_states() {
    for (verb, want) in [
        ("cordon", tg_model::command::Schedulability::Cordoned),
        ("drain", tg_model::command::Schedulability::Draining),
        ("uncordon", tg_model::command::Schedulability::Schedulable),
    ] {
        let served = serve(1, applied());
        let out = upsert_like(&served, verb, &["node-7"]);
        assert!(out.status.success(), "{verb}: {out:?}");

        let seen = served.seen.lock().expect("mutex").clone();
        assert_eq!(seen.len(), 1, "{verb}: {seen:?}");
        let tg_model::command::Command::SetSchedulability { node, mode } = &seen[0] else {
            panic!("{verb}: no SetSchedulability: {seen:?}");
        };
        assert_eq!(node, "node-7");
        assert_eq!(*mode, want, "'{verb}' sets the wrong state");
    }
}

/// **The kind and the generation of a rotation arrive unswapped** (ADR-0055).
///
/// Two key kinds, two numbers: a mix-up would rotate the identity key where an
/// operator meant the underlay — and the identity key is the one with which the
/// node identifies itself.
#[tokio::test(flavor = "multi_thread")]
async fn the_kind_and_the_generation_of_a_rotation_arrive_unswapped() {
    for (kind, want) in [
        ("identity", tg_model::command::KeyKind::Identity),
        ("underlay", tg_model::command::KeyKind::Underlay),
    ] {
        let served = serve(1, applied());
        let out = upsert_like(&served, "rotate", &["node-7", kind, "5"]);
        assert!(out.status.success(), "{kind}: {out:?}");

        let seen = served.seen.lock().expect("mutex").clone();
        assert_eq!(seen.len(), 1, "{kind}: {seen:?}");
        let tg_model::command::Command::SetKeyGeneration {
            node,
            kind: got,
            generation,
        } = &seen[0]
        else {
            panic!("{kind}: no SetKeyGeneration: {seen:?}");
        };
        assert_eq!(node, "node-7");
        assert_eq!(*got, want, "'{kind}' rotates the wrong key kind");
        assert_eq!(*generation, 5);
    }
}

/// **A rotation without a kind names the form — before the socket search.**
#[test]
fn a_rotation_without_a_kind_names_the_form() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(dir.path())
        .args(["node", "rotate", "node-7"])
        .output()
        .expect("tgctl is startable");

    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        said.contains("identity|underlay"),
        "the form is not named: {said}"
    );
    assert!(
        !said.contains("admin socket"),
        "the socket must not be the diagnosis here: {said}"
    );
}

/// Calls `tgctl node <verb> …` against the provided service.
fn upsert_like(served: &Served, verb: &str, args: &[&str]) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(served.dir.path())
        .args(["node", verb])
        .args(args)
        .output()
        .expect("tgctl is startable")
}

// -------------------------------------------- Rotation against the calendar ---

/// **A decree that outruns the calendar switches the policy off** — and that is
/// said (ADR-0055, ADR-0057).
///
/// `rotations` writes only what is **higher** than the decreed generation. That
/// is the promise ("a manual rotation wins") and at the same time the cost
/// side: measured, at a period of 90 days the generation is **230** today, a
/// decreed `1000` would be overtaken only in **189 years** — and in the state
/// that looks like an ordinary decree.
///
/// The right number hangs on the period (at 365 days it is 56), so an operator
/// cannot guess it. Warned and **not** refused: the command goes through.
#[tokio::test(flavor = "multi_thread")]
async fn a_generation_that_outruns_the_calendar_is_named() {
    let served = support::serve_settings(1, settings_with_rotation(90));

    let out = upsert_like(&served, "rotate", &["node-7", "identity", "1000000"]);

    assert!(out.status.success(), "the warning must not hold it up");
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("period 90 days") && said.contains("1000000"),
        "the warning shall name both numbers: {said}"
    );
    assert_eq!(
        served.seen.lock().expect("mutex").len(),
        1,
        "the command goes through anyway"
    );
}

/// The counter-direction: a generation **below** the calendar is no warning.
///
/// Without it a piece of information that appears at every rotation would be
/// just as green — and an operator would learn to read past it.
#[tokio::test(flavor = "multi_thread")]
async fn a_generation_within_the_calendar_stays_quiet() {
    let served = support::serve_settings(1, settings_with_rotation(90));

    let out = upsert_like(&served, "rotate", &["node-7", "identity", "5"]);

    assert!(out.status.success(), "{out:?}");
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        !said.contains("the policy wants"),
        "a generation below the calendar is no warning: {said}"
    );
}

/// And without a policy there is nothing to compare.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_policy_there_is_nothing_to_compare() {
    let served = serve(1, applied());

    let out = upsert_like(&served, "rotate", &["node-7", "identity", "1000000"]);

    assert!(out.status.success(), "{out:?}");
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("the policy wants"),
        "without a policy nothing may be claimed"
    );
}

fn settings_with_rotation(period: u32) -> tg_admin::SettingsResponse {
    tg_admin::SettingsResponse {
        id: 1,
        last_applied: Some(1),
        network: None,
        sidecar_overhead: Vec::new(),
        capacity: Vec::new(),
        rotation: vec![(tg_model::command::KeyKind::Identity, period)],
    }
}
