//! `tgctl audit` against a real archive (ADR-0020).
//!
//! What is checked here is what the pure tests cannot: the **exit status of the
//! process**. A checking tool that reports a finding and ends with 0 is
//! invisible in a script — and a script is the only place where such a tool
//! runs regularly.

use std::path::Path;
use std::process::Command as OsCommand;

use tg_consensus::Command;
use tg_consensus::audit::Archive;

fn document(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\">\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

/// Creates an archive with three entries under `audit-1.jsonl`.
fn archive(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("audit-1.jsonl");
    let mut archive = Archive::open(&path).expect("archive");
    for (index, name) in ["api", "ledger", "web"].iter().enumerate() {
        archive
            .record(
                u64::try_from(index).expect("index") + 1,
                1,
                &tg_consensus::Submission::internal(Command::UpsertWorkload {
                    document: document(name),
                }),
                &"applied",
            )
            .expect("append");
    }
    path
}

fn audit(data_dir: &Path, args: &[&str]) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(data_dir)
        .arg("audit")
        .args(args)
        .output()
        .expect("tgctl is startable")
}

/// A sound archive is found, recomputed and ended with 0 — and the report names
/// the head, for that is the other half of the proof (phase 11a).
#[test]
fn a_sound_archive_is_found_and_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = archive(dir.path());
    let head = Archive::open(&path).expect("archive").head().to_owned();

    let out = audit(dir.path(), &[]);

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains(&head), "the head is missing: {stdout}");
    assert!(stdout.contains("records:     3"), "{stdout}");
    assert!(stdout.contains("carries"), "{stdout}");
}

/// **A finding ends with a failure status.** That is the difference between a
/// checking tool and a report nobody reads.
#[test]
fn a_tampered_archive_ends_with_a_failure_status() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = archive(dir.path());
    let text = std::fs::read_to_string(&path).expect("read");
    let forged = text.replace("ledger", "leduer");
    assert_ne!(text, forged, "the forgery did not take hold");
    std::fs::write(&path, &forged).expect("write");

    let out = audit(dir.path(), &[]);

    assert!(
        !out.status.success(),
        "a finding counted as a success: {out:?}"
    );
}

/// An explicitly named file is taken — even one that is not named after the
/// pattern. A rotated segment in the archive is no longer called
/// `audit-1.jsonl`.
#[test]
fn an_explicitly_named_file_is_taken() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = archive(dir.path());
    let moved = dir.path().join("segment-2026-08.jsonl");
    std::fs::rename(&path, &moved).expect("rename");

    let out = audit(dir.path(), &[moved.to_str().expect("path")]);

    assert!(out.status.success(), "{out:?}");
}

/// A wrong anchor is a finding and not a success with a hint.
#[test]
fn a_wrong_anchor_ends_with_a_failure_status() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _ = archive(dir.path());

    let out = audit(dir.path(), &["--anchor", &"cd".repeat(32)]);

    assert!(!out.status.success(), "{out:?}");
}

/// No archive is a named error — not "no findings".
#[test]
fn a_missing_archive_is_a_failure_and_not_an_empty_report() {
    let dir = tempfile::tempdir().expect("tempdir");

    let out = audit(dir.path(), &[]);

    assert!(!out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        stderr.contains(&dir.path().display().to_string()),
        "{stderr}"
    );
}

/// **A rewritten verdict is a finding** (ADR-0045). Until then the verdict lay
/// beside the digest: a rejection could be rewritten to `"applied"`, and the
/// report went on saying "carries". This test nailed the gap down as long as it
/// existed, and now nails down its closure.
#[test]
fn a_rewritten_verdict_ends_with_a_failure_status() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = archive(dir.path());

    let before = audit(dir.path(), &[]);
    assert!(before.status.success(), "{before:?}");
    let stdout = String::from_utf8(before.stdout).expect("utf8");
    assert!(
        !stdout.contains("not covered by the chain"),
        "the overtaken caveat still stands there: {stdout}"
    );

    let text = std::fs::read_to_string(&path).expect("read");
    let forged = text.replace("applied", "never-happened");
    assert_ne!(text, forged, "the forgery did not take hold");
    std::fs::write(&path, &forged).expect("write");

    let after = audit(dir.path(), &[]);
    assert!(
        !after.status.success(),
        "the rewritten verdict stayed undetected: {after:?}"
    );
}

/// **A DST evidence segment verifies with the same command** (phase 11c: "an
/// auditor learns one procedure and applies it to both").
///
/// The payload there is **not** a log event but a line of text. The report must
/// not fail on it and must read nothing into it either — it then counts no
/// rejections, and that is right: there are none there.
#[test]
fn a_dst_evidence_segment_verifies_with_the_same_command() {
    use tg_telemetry::audit::{GENESIS, seal};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("evidence.jsonl");

    let mut previous = GENESIS.to_owned();
    let mut lines = String::new();
    for (index, (kind, payload)) in [
        ("dst_seeds", "6839843444216233984,6839843444216233985"),
        (
            "dst_scenario",
            "passed scenarios::five_nodes_elect_a_leader",
        ),
        ("dst_verdict", "passed 1 1 2"),
    ]
    .iter()
    .enumerate()
    {
        let record = seal(
            &previous,
            u64::try_from(index).expect("index") + 1,
            None,
            kind,
            payload,
        );
        previous.clone_from(&record.digest);
        lines.push_str(&serde_json::to_string(&record).expect("line"));
        lines.push('\n');
    }
    std::fs::write(&path, &lines).expect("write");

    let out = audit(dir.path(), &[path.to_str().expect("path")]);

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("records:     3"), "{stdout}");
    assert!(stdout.contains("of those refused: 0"), "{stdout}");
    assert!(stdout.contains("carries"), "{stdout}");
}

/// And a changed verdict in it is a finding — the way an auditor actually
/// goes.
#[test]
fn a_tampered_dst_verdict_ends_with_a_failure_status() {
    use tg_telemetry::audit::{GENESIS, seal};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("evidence.jsonl");
    let record = seal(GENESIS, 1, None, "dst_verdict", "passed 1 1 2");
    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&record).expect("line")),
    )
    .expect("write");
    assert!(
        audit(dir.path(), &[path.to_str().expect("path")])
            .status
            .success()
    );

    let text = std::fs::read_to_string(&path).expect("read");
    let forged = text.replace("passed", "failed");
    assert_ne!(text, forged, "the forgery did not take hold");
    std::fs::write(&path, &forged).expect("write");

    let out = audit(dir.path(), &[path.to_str().expect("path")]);
    assert!(!out.status.success(), "{out:?}");
}

/// **The chain across several segments is checked, not only the last one.**
///
/// The reason for the rotation is movability: a closed segment an operator can
/// put into the WORM archive, a permanently open file not (ADR-0020). The price
/// would be a chain that tears at every seam — this test records that it does
/// not.
#[test]
fn the_chain_across_segments_is_verified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit-1.jsonl");
    let mut archive = Archive::open_with(&path, Some(2)).expect("archive");
    for index in 1..=5_u64 {
        archive
            .record(
                index,
                1,
                &tg_consensus::Submission::internal(Command::UpsertWorkload {
                    document: document(&format!("w{index}")),
                }),
                &"applied",
            )
            .expect("append");
    }
    drop(archive);

    let out = audit(dir.path(), &[]);

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("segments:    3"), "{stdout}");
    assert!(stdout.contains("records:     5"), "{stdout}");
    assert!(stdout.contains("carries"), "{stdout}");
}

/// **A removed segment in the middle is a finding** — the property a chain
/// across segments has and a single segment cannot have.
#[test]
fn a_removed_middle_segment_ends_with_a_failure_status() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit-1.jsonl");
    let mut archive = Archive::open_with(&path, Some(2)).expect("archive");
    for index in 1..=6_u64 {
        archive
            .record(
                index,
                1,
                &tg_consensus::Submission::internal(Command::UpsertWorkload {
                    document: document(&format!("w{index}")),
                }),
                &"applied",
            )
            .expect("append");
    }
    drop(archive);

    let sealed = tg_consensus::audit::sealed(&path);
    assert!(sealed.len() >= 2, "{sealed:?}");
    std::fs::remove_file(&sealed[0]).expect("remove");

    let out = audit(dir.path(), &[]);
    assert!(!out.status.success(), "{out:?}");
}

/// A segment from the middle named **individually** verifies only with its
/// anchor — and that is a setting. `--anchor` exists for exactly that, and until
/// the rotation this switch had no producer.
#[test]
fn a_single_sealed_segment_needs_its_anchor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit-1.jsonl");
    let mut archive = Archive::open_with(&path, Some(2)).expect("archive");
    for index in 1..=6_u64 {
        archive
            .record(
                index,
                1,
                &tg_consensus::Submission::internal(Command::UpsertWorkload {
                    document: document(&format!("w{index}")),
                }),
                &"applied",
            )
            .expect("append");
    }
    drop(archive);

    let sealed = tg_consensus::audit::sealed(&path);
    assert!(sealed.len() >= 2, "{sealed:?}");
    let first = tg_consensus::audit::read(&sealed[0]).expect("read");
    let anchor = first.last().expect("record").digest.clone();
    let second = sealed[1].to_str().expect("path").to_owned();

    // Without an anchor: the start of the chain is expected and not found.
    assert!(!audit(dir.path(), &[&second]).status.success());

    // With the real anchor it carries.
    assert!(
        audit(dir.path(), &[&second, "--anchor", &anchor])
            .status
            .success()
    );
}
