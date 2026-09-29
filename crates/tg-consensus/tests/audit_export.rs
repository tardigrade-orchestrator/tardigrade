//! The way from the Raft log into the archive (ADR-0020).
//!
//! The chain itself is checked in `tg-telemetry`. Here stands the seam: that a
//! segment arises from **real** log entries which verifies without the cluster
//! — and that a forgery at this seam stands out.
//!
//! The difference from a test against self-built records is the whole point: an
//! export checked only against its own products proves self-consistency. What
//! runs through here is the log.

use openraft::storage::{RaftLogStorage as _, RaftLogStorageExt as _};
use openraft::testing::log_id;
use openraft::{Entry, EntryPayload, Membership};
use tg_consensus::audit::{Event, export};
use tg_consensus::{Command, Storage, TypeConfig, UtcMillis};
use tg_telemetry::audit::{AuditError, GENESIS};

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

fn normal(index: u64, command: Command) -> Entry<TypeConfig> {
    Entry {
        log_id: log_id(1, 1, index),
        payload: EntryPayload::Normal(command.into()),
    }
}

/// A log with five entries in the directory `dir`.
async fn filled_log(dir: &std::path::Path) -> Storage {
    filled_log_inner(&dir.join("raft.redb")).await
}

/// The same under an **explicit** path.
///
/// `export_range` takes the path and opens it itself — a test for that
/// therefore needs the name and not only the directory.
async fn filled_log_at(path: &std::path::Path) -> Storage {
    filled_log_inner(path).await
}

/// A log with what `openraft` really puts in: domain commands, a blank entry
/// at the leader's accession and a membership change.
async fn filled_log_inner(path: &std::path::Path) -> Storage {
    let mut storage = Storage::open(path).expect("open");

    let entries: Vec<Entry<TypeConfig>> = vec![
        Entry {
            log_id: log_id(1, 1, 1),
            payload: EntryPayload::Blank,
        },
        normal(
            2,
            Command::UpsertWorkload {
                document: document("ledger"),
            },
        ),
        normal(
            3,
            Command::AllowTraffic {
                from: "api".to_owned(),
                to: "ledger".to_owned(),
            },
        ),
        Entry {
            log_id: log_id(1, 1, 4),
            payload: EntryPayload::Membership(Membership::new(
                vec![[1, 2, 3].into_iter().collect()],
                None,
            )),
        },
        normal(
            5,
            Command::GrantLease {
                workload: "ledger".to_owned(),
                node: "node-1".to_owned(),
                now: UtcMillis::new(1_756_000_500),
                expires_at: UtcMillis::new(1_756_000_515),
            },
        ),
    ];

    storage.log.blocking_append(entries).await.expect("append");
    storage
}

/// The normal case: the log becomes a segment, and the segment carries.
#[tokio::test]
async fn a_log_becomes_a_segment_that_verifies_on_its_own() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = filled_log(dir.path()).await;
    let mut reader = storage.log.get_log_reader().await;

    let segment = export(&mut reader, 1, 6, GENESIS).await.expect("export");
    let report = segment.verify(GENESIS).expect("the segment carries");

    // Three domain commands out of five entries -- blank and membership are
    // consensus mechanics and do not belong in an audit report.
    assert_eq!(report.records, 3);
    assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
    assert_eq!(
        segment
            .records
            .iter()
            .map(|record| record.kind.as_str())
            .collect::<Vec<_>>(),
        ["upsert_workload", "allow_traffic", "grant_lease"]
    );
}

/// The log index survives the export — it is the consensus-backed ordering,
/// and without it a record could not be traced back.
///
/// The record index numbers the segment beside it gaplessly. Both are needed,
/// and that is why both lie there separately.
#[tokio::test]
async fn the_log_index_survives_the_export_beside_a_gapless_numbering() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = filled_log(dir.path()).await;
    let mut reader = storage.log.get_log_reader().await;

    let segment = export(&mut reader, 1, 6, GENESIS).await.expect("export");

    let events: Vec<Event> = segment
        .records
        .iter()
        .map(|record| serde_json::from_str(&record.payload).expect("payload"))
        .collect();

    assert_eq!(
        events.iter().map(|e| e.log_index).collect::<Vec<_>>(),
        [2, 3, 5],
        "the gaps of the consensus mechanics stay visible"
    );
    assert_eq!(
        segment.records.iter().map(|r| r.index).collect::<Vec<_>>(),
        [1, 2, 3],
        "the segment itself is gapless, otherwise verify would find a gap"
    );
    assert!(events.iter().all(|e| e.term == 1));
}

/// **What is undated stays undated**, and `expires_at` is no event time.
///
/// `grant_lease` carries both: `now` (when it happened) and `expires_at` (when
/// the lease ends). What is taken is `now`. Whoever took `expires_at` instead
/// would date the operation forward by the lease duration — here fifteen
/// seconds — and nobody would see it in the report.
#[tokio::test]
async fn only_commands_that_carry_a_time_get_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = filled_log(dir.path()).await;
    let mut reader = storage.log.get_log_reader().await;

    let segment = export(&mut reader, 1, 6, GENESIS).await.expect("export");

    assert_eq!(
        segment.records.iter().map(|r| r.at).collect::<Vec<_>>(),
        [None, None, Some(1_756_000_500)],
        "1_756_000_515 would be expires_at"
    );
}

/// The actual purpose: whoever touches the exported file is seen.
///
/// What is altered is the XML **inside** the command — the kind of forgery that
/// would matter: it is plausible in the domain and would strike nobody on
/// reading.
#[tokio::test]
async fn altering_the_exported_command_is_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = filled_log(dir.path()).await;
    let mut reader = storage.log.get_log_reader().await;

    let mut segment = export(&mut reader, 1, 6, GENESIS).await.expect("export");
    let original = segment.records[0].payload.clone();
    let forged = original.replace("example.com/ledger:1", "evil.example/ledger:1");
    // First check that the forgery takes hold: a replacement that hits nothing
    // turns this test into one that checks nothing.
    assert_ne!(original, forged, "the forgery did not take hold");
    segment.records[0].payload = forged;

    assert!(matches!(
        segment.verify(GENESIS),
        Err(AuditError::Altered { index: 1 })
    ));
}

/// Two consecutive exports hang together — and the head of the first is the
/// anchor of the second.
///
/// That is the half of the proof the chain alone does not deliver: a segment
/// truncated at the end stands out only here.
#[tokio::test]
async fn the_second_segment_hangs_on_the_head_of_the_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = filled_log(dir.path()).await;
    let mut reader = storage.log.get_log_reader().await;

    let first = export(&mut reader, 1, 4, GENESIS).await.expect("export 1");
    let head = first.verify(GENESIS).expect("segment 1").head;
    let second = export(&mut reader, 4, 6, &head).await.expect("export 2");

    assert!(second.verify(&head).is_ok());

    // And at the wrong anchor it does not carry.
    assert!(matches!(
        second.verify(GENESIS),
        Err(AuditError::WrongAnchor { .. })
    ));

    // If somebody truncates the first segment, the second's anchor no longer fits.
    let mut shortened = first;
    shortened.records.truncate(1);
    let short_head = shortened.verify(GENESIS).expect("intact").head;
    assert!(matches!(
        second.verify(&short_head),
        Err(AuditError::WrongAnchor { .. })
    ));
}

/// An empty range yields an empty segment whose head is the anchor — no error
/// and no panic.
#[tokio::test]
async fn an_empty_range_yields_an_empty_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = filled_log(dir.path()).await;
    let mut reader = storage.log.get_log_reader().await;

    let segment = export(&mut reader, 9, 9, GENESIS).await.expect("export");

    assert!(segment.records.is_empty());
    assert_eq!(segment.head(GENESIS), GENESIS);
}

/// **A command that carries only a future time stays undated.**
///
/// `invite_node` has `expires_at` and nothing else temporal. The export must
/// not make an event time out of it — the invitation was not issued at the
/// moment it expires.
#[tokio::test]
async fn a_command_with_only_a_future_time_stays_undated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .log
        .blocking_append(vec![normal(
            1,
            Command::InviteNode {
                node: "node-7".to_owned(),
                digest: "0".repeat(64),
                expires_at: 1_756_003_600,
            },
        )])
        .await
        .expect("append");
    let mut reader = storage.log.get_log_reader().await;

    let segment = export(&mut reader, 1, 2, GENESIS).await.expect("export");

    assert_eq!(segment.records[0].kind, "invite_node");
    assert_eq!(segment.records[0].at, None);
}

/// **The range resolves out of the log when nobody names it.**
///
/// The rule behind `tgd --audit-export`: without bounds the range is
/// "everything the log carries". It lies here and not in the client, because it
/// must be checkable without a client — and because a `tgctl` that linked
/// `openraft` would hang on the consensus core in order to read a file.
#[tokio::test]
async fn without_bounds_the_whole_log_is_exported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft-1.redb");
    drop(filled_log_at(&path).await);

    let export = tg_consensus::audit::export_range(&path, None, None, GENESIS)
        .await
        .expect("export");

    assert_eq!(export.from, 1, "without a setting the range begins at one");
    assert_eq!(export.last, 5, "the log ends at five");
    assert_eq!(
        export.to, 6,
        "and the upper bound is exclusive -- otherwise the last entry would be \
         missing"
    );

    let report = export.segment.verify(GENESIS).expect("the segment carries");
    assert_eq!(
        report.records, 3,
        "three domain commands out of five entries"
    );
}

/// **A range behind the compaction is refused, not truncated.**
///
/// Measured, `try_get_log_entries` gives an **empty list** for deleted indices
/// and no error (substantiated in the tree, `audit_archive.rs`). Without this
/// bolt an export would quietly have delivered less than demanded — and the
/// segment **verifies**, because its chain is gapless in itself. An auditor
/// would take an incomplete proof for a complete one, and at an assurance per
/// ADR-0020 that is the most expensive outcome.
#[tokio::test]
async fn a_range_behind_the_compaction_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft-1.redb");
    {
        let mut storage = filled_log_at(&path).await;
        storage.log.purge(log_id(1, 1, 3)).await.expect("purge");
    }

    let err = tg_consensus::audit::export_range(&path, Some(1), None, GENESIS)
        .await
        .expect_err("a deleted range must be refused");
    let text = err.to_string();
    assert!(
        text.contains("up to 3 is deleted") && text.contains("without `--from`"),
        "the message does not name the bound and the way out: {text}"
    );
}

/// **And without a setting the export begins at what is still there.**
///
/// The counter-direction, and it carries the bolt above: an `export_range` that
/// refused every range as soon as something is deleted would take from an
/// auditor the access to everything the log **still** has.
#[tokio::test]
async fn without_bounds_the_export_starts_after_the_compaction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft-1.redb");
    {
        let mut storage = filled_log_at(&path).await;
        storage.log.purge(log_id(1, 1, 3)).await.expect("purge");
    }

    let export = tg_consensus::audit::export_range(&path, None, None, GENESIS)
        .await
        .expect("export");

    assert_eq!(
        export.from, 4,
        "without a setting the range begins behind the last deleted index"
    );
    export.segment.verify(GENESIS).expect("the segment carries");
}

/// **An empty range is an error, not an empty output.**
///
/// Otherwise it would be indistinguishable from a successful export — and an
/// operator who redirects `> segment.jsonl` would take an empty file for a
/// result.
#[tokio::test]
async fn an_empty_range_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft-1.redb");
    drop(filled_log_at(&path).await);

    let err = tg_consensus::audit::export_range(&path, Some(3), Some(3), GENESIS)
        .await
        .expect_err("an empty range must be refused");
    let text = err.to_string();
    assert!(
        text.contains("empty range") && text.contains("ends at 5"),
        "the message names the range and the end of the log: {text}"
    );
}

/// **A locked log is refused with the reason.**
///
/// `redb` lets exactly one process at the database — in the recovery case that
/// is exactly the question an operator asks themselves. A message without the
/// hint would let them doubt the file instead of the running `tgd`.
#[tokio::test]
async fn a_locked_log_names_the_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raft-1.redb");
    // **Held**, not dropped: the lock hangs on the open database.
    let _holder = filled_log_at(&path).await;

    let err = tg_consensus::audit::export_range(&path, None, None, GENESIS)
        .await
        .expect_err("a locked log must be refused");
    let text = err.to_string();
    assert!(
        text.contains("Is tgd still running?"),
        "the message does not name the reason: {text}"
    );
}
