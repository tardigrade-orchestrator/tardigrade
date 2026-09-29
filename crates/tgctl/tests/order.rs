//! **The setting a human typed comes before the environment.**
//!
//! The rule stands at five places in this tree's code — and it has been
//! **violated three times**: at `node upsert` (a missing `--site` yielded "no
//! admin socket"), at the operator flags (`--operator` without `--peer` fell
//! back to the socket) and at `cluster voters` (the empty set was checked only
//! behind the socket). Every time an operator read a message about the **disk**
//! while their line was the problem.
//!
//! What is checked here is therefore, for **every** subcommand that needs an
//! access: an incomplete call **without** a data directory must name the form
//! and not the missing disk.
//!
//! The table is hand-maintained, and it must be: "this call is incomplete"
//! cannot be derived. What **is** derived is the coverage — every subcommand
//! from `CLUSTER_SUBCOMMANDS` occurs in it, read from the source.

use std::process::Command;

/// A call without a data directory: what it says, and whether it succeeds.
fn refused(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_tgctl"))
        .args(["--data-dir", "/does-not-exist"])
        .args(args)
        .output()
        .expect("tgctl is startable");

    assert!(
        !out.status.success(),
        "'{args:?}' is incomplete and must be refused"
    );

    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Incomplete calls, one per subcommand with an access.
///
/// **What is missing differs per line** — a mandatory setting, a switch, an
/// identifier —, and that is the point: what is checked is not one form but the
/// **order**.
///
/// Incomplete calls, one per subcommand with an access — and **what the message
/// must name**.
///
/// The second column is a promise per line and expressly **not** a wording
/// comparison across all: my first attempt demanded "expected", "needs" or "--"
/// and went red at a **good** message (`'broken' is not 'kind=days'`). An
/// assurance on a catch-all word checks nothing — here therefore stands what
/// this one message must name: the setting objected to, or the form that is
/// missing.
const INCOMPLETE: &[(&[&str], &str)] = &[
    // --- tgctl node ---
    (&["node", "invite"], "invite"),
    (&["node", "upsert", "tgd-9"], "--site"),
    (&["node", "cordon"], "cordon"),
    (&["node", "drain"], "drain"),
    (&["node", "uncordon"], "uncordon"),
    (&["node", "detach"], "detach"),
    (&["node", "attach"], "attach"),
    (&["node", "remove"], "remove"),
    (&["node", "revoke-trust"], "revoke-trust"),
    (&["node", "rotate", "tgd-1"], "rotate"),
    // Without a setting the empty policy is in each case the **withdrawal**
    // (ADR-0049, ADR-0057) — what is checked is therefore a broken setting.
    (&["node", "policy", "--rule", "broken"], "broken"),
    (&["node", "rotation", "--rotate-every", "broken"], "broken"),
    // --- tgctl cluster ---
    (&["cluster", "apply"], "apply"),
    (&["cluster", "get"], "get"),
    (&["cluster", "remove"], "remove"),
    (&["cluster", "restart", "api"], "restart"),
    (&["cluster", "promote", "api"], "promote"),
    (&["cluster", "allow", "a"], "allow"),
    (&["cluster", "revoke", "a"], "revoke"),
    (&["cluster", "allow-egress", "api"], "allow-egress"),
    (&["cluster", "revoke-egress", "api"], "revoke-egress"),
    (&["cluster", "network", "10.0.0.0/16"], "network"),
    // The CIDR with the **same** function as the state machine (`Plan::parse`,
    // ADR-0069) — and the prefix beside it, which has always been checked.
    (&["cluster", "network", "broken", "24"], "IPv4 CIDR"),
    (&["cluster", "network", "10.0.0.0/16", "8"], "node prefix"),
    (
        &["cluster", "sidecar-overhead", "--resource", "broken"],
        "broken",
    ),
    (&["cluster", "delete-volume", "v1", "n1"], "--yes"),
    (&["cluster", "snapshot-volume", "v1"], "snapshot-volume"),
    (&["cluster", "secret"], "secret"),
    (&["cluster", "registry"], "registry"),
    (&["cluster", "learner"], "learner"),
    (&["cluster", "voters"], "voters"),
    // --- the rest ---
    (&["operator", "enrol", "dana"], "enrol"),
    // The form of the SPKI, with the **same** function as in the state machine
    // (ADR-0103): an entry the verifier cannot decode **never** carries a
    // handshake.
    (
        &["operator", "enrol", "dana", "broken", "--class", "read"],
        "base64",
    ),
    (&["restore-volume", "v1"], "restore-volume"),
];

/// **No incomplete call talks about the disk.**
#[test]
fn every_subcommand_checks_its_arguments_before_the_access() {
    for (args, expected) in INCOMPLETE {
        let said = refused(args);
        // **The path is the marker, not the word.** "unreadable" stood here
        // too and was a catch-all word: the same phrase fits linguistically for
        // an unreadable **SPKI**, and the assurance went red at a good message.
        // The same lesson as at the `--peer` witness, where
        // `contains("socket")` was green for both outcomes.
        assert!(
            !said.contains("/does-not-exist"),
            "'{args:?}' seeks the access before the check: {said}"
        );
        assert!(
            said.contains(expected),
            "'{args:?}' does not name '{expected}': {said}"
        );
    }
}

/// **And a complete call does seek it** — the other half of the promise.
///
/// Without it a `tgctl` that refuses **every** call with a form message would
/// be just as green, and no command would ever get through.
#[test]
fn a_complete_call_does_look_for_the_access() {
    let said = refused(&["cluster", "allow", "a", "b"]);

    assert!(
        said.contains("/does-not-exist"),
        "a complete call belongs failing at the access: {said}"
    );
}

/// **The coverage is derived, not claimed.**
///
/// Every subcommand from `CLUSTER_SUBCOMMANDS` occurs in [`INCOMPLETE`] — read
/// from the source, because a second list would be the shape this tree has
/// measured several times as a source of error.
///
/// **The read paths are excepted**, and that is no gap: `show`, `nodes`,
/// `lint`, `settings` and their siblings take **no** mandatory setting — for
/// them the access is the first thing that can be missing.
#[test]
fn the_table_covers_every_cluster_subcommand() {
    const READ_ONLY: &[&str] = &[
        "show",
        "nodes",
        "lint",
        "settings",
        "trust",
        "volumes",
        "secrets",
        "members",
        "signer",
        "signer-refresh",
    ];

    let source = include_str!("../src/main.rs");
    let start = source
        .find("const CLUSTER_SUBCOMMANDS")
        .expect("the list of subcommands");
    let list = &source[start..start + source[start..].find("];").expect("its end")];

    let mut seen = 0;
    for line in list.lines().skip(1) {
        let Some(name) = line
            .trim()
            .strip_prefix('"')
            .and_then(|r| r.split('"').next())
        else {
            continue;
        };
        seen += 1;
        if READ_ONLY.contains(&name) {
            continue;
        }
        assert!(
            INCOMPLETE.iter().any(|(call, _)| {
                call.first() == Some(&"cluster") && call.get(1) == Some(&name)
            }),
            "'cluster {name}' is missing from the table — if it needs no \
             setting, it belongs in READ_ONLY"
        );
    }

    assert!(seen >= 20, "the list was not read: {seen} names");
}
