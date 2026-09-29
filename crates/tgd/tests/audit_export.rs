//! `tgd --audit-export` against a real Raft log (ADR-0020, ADR-0137).
//!
//! # Why the witness lies here
//!
//! The command was `tgctl audit export` -- and for it the CLI linked `openraft`
//! and `redb`, that is, 61 crates for a command that runs on the same machine
//! with the service **stopped** (`redb` lets exactly one process at the log).
//! Whoever owns the storage reads it (ADR-0137).
//!
//! What is checked is the **process's exit** and the separation of the streams: a
//! tool whose accompanying text ran into the redirected file would yield no
//! segment.

use std::path::Path;
use std::process::Command as OsCommand;

use tg_consensus::Command;

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

/// Calls `tgd --audit-export` on the data directory.
fn export(data_dir: &Path, args: &[&str]) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
        .arg("--id")
        .arg("1")
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--peer")
        .arg("1=http://127.0.0.1:1")
        .arg("--audit-export")
        .args(args)
        .output()
        .expect("tgd startable")
}

/// **The export carries: the segment from the log verifies with the verifier.**
///
/// The strongest assurance this command can have -- the same procedure an auditor
/// applies to the archive, applied to what comes out of the log (11c: "An auditor
/// learns one procedure and applies it to both").
///
/// **Why the command exists:** ADR-0020 demands the export before the compaction,
/// and an archive `Archive::open` cannot continue does **not** let `tgd` start
/// (11a). Since phase 11a the archive writes in the apply path, so the normal case
/// is covered; this is the rest -- and the recovery way when the archive is
/// missing.
#[test]
fn an_exported_segment_verifies_with_the_verifier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("raft-1.redb");
    build_log(&log);

    let out = export(dir.path(), &[]);
    assert!(out.status.success(), "{out:?}");

    let segment = String::from_utf8(out.stdout).expect("utf8");
    let notes = String::from_utf8(out.stderr).expect("utf8");

    // The records stand **alone** on stdout -- otherwise the file an operator
    // redirects into would be no segment.
    assert!(
        segment.lines().all(|line| line.starts_with('{')),
        "accompanying text stands on stdout: {segment}"
    );
    assert_eq!(segment.lines().count(), 2, "two domain commands: {segment}");

    // And the note that distinguishes it from a repair.
    assert!(
        notes.contains("without** verdicts") || notes.contains("without verdicts"),
        "the note about the missing verdicts is missing: {notes}"
    );
    assert!(notes.contains("head:"), "the head is missing: {notes}");

    // **The actual proof**: the same verifier, the same chain. It is literally
    // the function `tgctl audit` calls -- with that the witness does not check
    // its own reconstruction (11c).
    let path = dir.path().join("segment.jsonl");
    std::fs::write(&path, &segment).expect("writable");
    let records = tg_telemetry::audit::read(&path).expect("readable");
    let report = tg_telemetry::audit::verify(&path, &records, tg_telemetry::audit::GENESIS)
        .expect("the exported segment does not carry");
    assert_eq!(report.records, 2, "{report:?}");
}

/// An empty range ends with an error status and writes **nothing**.
///
/// Otherwise an operator who redirects `> segment.jsonl` would take an empty file
/// for a result.
#[test]
fn an_empty_range_writes_nothing_and_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    build_log(&dir.path().join("raft-1.redb"));

    let out = export(dir.path(), &["--audit-from", "3", "--audit-to", "3"]);

    assert!(!out.status.success(), "an empty range must fail");
    assert!(out.stdout.is_empty(), "something was written: {out:?}");
    assert!(
        // From `tg_consensus::audit`; the message around it (`tgd: the storage
        // is not usable`) comes from this crate.
        String::from_utf8_lossy(&out.stderr).contains("empty range"),
        "{out:?}"
    );
}

/// Creates a log with two domain commands.
fn build_log(path: &Path) {
    use openraft::storage::RaftLogStorageExt as _;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut storage = tg_consensus::Storage::open(path).expect("open");
        let entries: Vec<openraft::Entry<tg_consensus::TypeConfig>> = ["api", "ledger"]
            .iter()
            .enumerate()
            .map(|(at, name)| openraft::Entry {
                log_id: openraft::testing::log_id(1, 1, u64::try_from(at).expect("index") + 1),
                payload: openraft::EntryPayload::Normal(tg_consensus::Submission::internal(
                    Command::UpsertWorkload {
                        document: document(name),
                    },
                )),
            })
            .collect();
        storage.log.blocking_append(entries).await.expect("append");
    });
}
