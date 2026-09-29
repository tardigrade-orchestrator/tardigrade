//! The archive at the apply path (ADR-0020).
//!
//! The open point from phase 5d read: **compaction deletes audit material.**
//! Here stands the proof that it can no longer do so — not because somebody
//! exports fast enough, but because the record lies on the disk before `apply`
//! returns.

use openraft::RaftLogReader as _;
use openraft::storage::{RaftLogStorage as _, RaftLogStorageExt as _, RaftStateMachine as _};
use openraft::testing::log_id;
use openraft::{Entry, EntryPayload};
use tg_consensus::audit::Archive;
use tg_consensus::{Command, Storage, TypeConfig};
use tg_telemetry::audit::{AuditError, GENESIS, Segment};

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

/// The archive's records — over the same reader an auditor uses.
///
/// A copy of its own stood here until `tgctl audit` needed a reader. Two
/// readers for one format would be two opportunities to read it with differing
/// strictness — and the stricter one would be the one nobody calls.
fn lines(path: &std::path::Path) -> Vec<tg_telemetry::audit::Record> {
    tg_consensus::audit::read(path).expect("read the archive")
}

/// A record's verdict — since ADR-0045 in the sealed payload.
fn verdict(record: &tg_telemetry::audit::Record) -> String {
    let event: tg_consensus::audit::Event = serde_json::from_str(&record.payload).expect("payload");
    event.outcome.map(|out| out.to_string()).unwrap_or_default()
}

/// **The record lies on the disk before the compaction.**
///
/// What is checked is the order that matters: first apply — archiving happens
/// in the process —, then trim the log to behind what was applied. What is
/// still there afterwards is the archive, and it carries.
#[tokio::test]
async fn the_archive_survives_a_compaction_that_erases_the_log() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .machine
        .with_archive(Archive::open(&path).expect("archive"));

    let entries = vec![
        normal(
            1,
            Command::UpsertWorkload {
                document: document("ledger"),
            },
        ),
        normal(
            2,
            Command::AllowTraffic {
                from: "api".to_owned(),
                to: "ledger".to_owned(),
            },
        ),
    ];
    storage
        .log
        .blocking_append(entries.clone())
        .await
        .expect("append");
    storage.machine.apply(entries).await.expect("apply");

    // And now the compaction, which clears the log away.
    storage.log.purge(log_id(1, 1, 2)).await.expect("purge");
    assert!(
        storage
            .log
            .get_log_reader()
            .await
            .try_get_log_entries(1..3)
            .await
            .expect("read")
            .is_empty(),
        "the log is empty -- exactly the case from phase 5d"
    );

    let records = lines(&path);
    assert_eq!(records.len(), 2);
    let report = Segment { records }
        .verify(GENESIS)
        .expect("the archive carries");
    assert_eq!(report.records, 2);
}

/// The archive also records what was **refused**.
///
/// An auditor does not only ask what happened. A futile attempt to renew a
/// foreign lease is exactly the event they look for — and it leaves nothing in
/// the state.
#[tokio::test]
async fn a_rejected_command_is_archived_with_its_rejection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .machine
        .with_archive(Archive::open(&path).expect("archive"));

    // `RemoveWorkload` on an unknown name is **applied**, not refused --
    // measured. A document that is no definition, by contrast, is refused for
    // certain, and only with it does this test check its statement.
    let entries = vec![normal(
        1,
        Command::UpsertWorkload {
            document: "this is no definition".to_owned(),
        },
    )];
    storage.machine.apply(entries).await.expect("apply");

    let archived = lines(&path);
    assert_eq!(archived.len(), 1);
    assert_eq!(archived[0].kind, "upsert_workload");
    let outcome = verdict(&archived[0]);
    assert!(
        outcome.contains("malformed_document"),
        "the rejection stands in the archive too: {outcome}"
    );
}

/// A restart continues the chain instead of beginning a second one.
///
/// Without that every restart would have a new anchor, and the archive would
/// fall apart into fragments that carry individually and together say
/// nothing.
#[tokio::test]
async fn reopening_continues_the_chain_instead_of_starting_a_new_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");

    {
        let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
        storage
            .machine
            .with_archive(Archive::open(&path).expect("archive"));
        storage
            .machine
            .apply(vec![normal(
                1,
                Command::UpsertWorkload {
                    document: document("a"),
                },
            )])
            .await
            .expect("apply");
    }

    let reopened = Archive::open(&path).expect("reopen");
    assert_eq!(reopened.records(), 1);
    let head_after_first = reopened.head().to_owned();
    drop(reopened);

    {
        let mut storage = Storage::open(dir.path().join("raft2.redb")).expect("open");
        storage
            .machine
            .with_archive(Archive::open(&path).expect("archive"));
        storage
            .machine
            .apply(vec![normal(
                2,
                Command::UpsertWorkload {
                    document: document("b"),
                },
            )])
            .await
            .expect("apply");
    }

    let records = lines(&path);
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1].previous, head_after_first,
        "the second run does not hang on the head of the first"
    );
    assert!(Segment { records }.verify(GENESIS).is_ok());
}

/// **A damaged archive cannot be continued.**
///
/// Whoever appended to it without checking would countersign the forgery:
/// everything after the altered place would hang on a head that never existed,
/// and from there on the chain would look intact again.
#[tokio::test]
async fn a_tampered_archive_refuses_to_be_continued() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .machine
        .with_archive(Archive::open(&path).expect("archive"));
    storage
        .machine
        .apply(vec![normal(
            1,
            Command::UpsertWorkload {
                document: document("ledger"),
            },
        )])
        .await
        .expect("apply");
    drop(storage);

    let text = std::fs::read_to_string(&path).expect("read");
    let forged = text.replace("example.com/ledger:1", "evil.example/ledger:1");
    assert_ne!(text, forged, "the forgery did not take hold");
    std::fs::write(&path, &forged).expect("write");

    let err = Archive::open(&path).expect_err("must not have opened");
    // **In words, with the number.** Here stood `contains("Altered")`, that is,
    // the name of a Rust variant -- the assurance thereby hung on the language
    // of the compiler and not on that of an auditor. Since `verify` hands on the
    // `Display` output, the record's number stands in it, and that is exactly
    // "the place" this test wanted to name.
    assert!(
        err.detail.contains("record 1") && err.detail.contains("altered"),
        "the error names the place: {}",
        err.detail
    );
    assert!(matches!(
        Segment {
            records: lines(&path),
        }
        .verify(GENESIS),
        Err(AuditError::Altered { index: 1 })
    ));
}

// --- An auditor's read path ------------------------------------------------

/// **`read` creates nothing.** `Archive::open` does — it is the write path and
/// must be able to begin an empty archive. For an auditor exactly that would be
/// wrong: a typo in the path would come back as an empty, intact archive, and
/// "no findings" would then mean "no file".
#[test]
fn reading_a_missing_archive_fails_and_creates_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("doesnotexist.jsonl");

    let err = tg_consensus::audit::read(&path).expect_err("missing");

    assert_eq!(err.path, path);
    assert!(!path.exists(), "the read path created the archive");

    // The counter-check: the write path creates it. Both behaviours are right
    // -- that is why they are two functions.
    Archive::open(&path).expect("archive");
    assert!(path.exists());
}

/// **The anchor is a setting, not a constant.** A rotated segment begins in the
/// middle of the chain and does **not** verify against GENESIS; whoever
/// silently inserted the anchor would certify to every segment that it was the
/// first.
#[test]
fn verifying_against_a_foreign_anchor_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let mut archive = Archive::open(&path).expect("archive");
    archive
        .record(
            1,
            1,
            &tg_consensus::Submission::internal(Command::UpsertWorkload {
                document: document("api"),
            }),
            &"applied",
        )
        .expect("append");
    let head = archive.head().to_owned();
    drop(archive);

    let read = tg_consensus::audit::read(&path).expect("read");

    tg_consensus::audit::verify(&path, &read, GENESIS).expect("against GENESIS");
    tg_consensus::audit::verify(&path, &read, &head).expect_err("against a foreign head");
}

// --- The verdict in the chain (ADR-0045) ------------------------------------

/// **A rewritten verdict is a finding.**
///
/// That is the decision from ADR-0045, and it closes the gap with which 11a was
/// built: the verdict lay beside the digest. Both directions are damage — out of
/// "refused" comes "applied" (an incident that never was), and out of "applied"
/// comes "refused" (one that stays hidden).
#[tokio::test]
async fn a_rewritten_verdict_is_a_finding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .machine
        .with_archive(Archive::open(&path).expect("archive"));

    // A command the state machine **refuses** -- exactly the event an auditor
    // looks for.
    storage
        .machine
        .apply(vec![normal(
            1,
            Command::UpsertWorkload {
                document: "this is no definition".to_owned(),
            },
        )])
        .await
        .expect("apply");
    drop(storage);

    let text = std::fs::read_to_string(&path).expect("read");
    assert!(
        text.contains("malformed_document"),
        "the rejection stands in the archive: {text}"
    );

    // Out of "refused" comes "applied" -- the direction that invents an
    // incident that never was.
    let cut = text.find("\\\"outcome\\\"").expect("verdict");
    let end = text.find("\",\"previous\"").expect("end of the payload");
    let forged = format!(
        "{}\\\"outcome\\\":\\\"applied\\\"{}",
        &text[..cut],
        &text[end..]
    );
    assert_ne!(text, forged, "the forgery did not take hold");
    std::fs::write(&path, &forged).expect("write");

    let records = tg_consensus::audit::read(&path).expect("read");
    assert!(
        tg_consensus::audit::verify(&path, &records, GENESIS).is_err(),
        "the rewritten verdict stayed undetected"
    );
}

/// **An archive line cannot carry unnoticed extra fields.** `Record` carries
/// `deny_unknown_fields`, and without the `flatten` wrapper from 11a that takes
/// effect again (ADR-0045, determination 1). Previously a foreign field was
/// accepted — unsealed and for a reader indistinguishable from the sealed
/// ones.
#[test]
fn an_unknown_field_in_a_line_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    std::fs::write(
        &path,
        "{\"index\":1,\"at\":null,\"kind\":\"k\",\"payload\":\"p\",\
         \"previous\":\"a\",\"digest\":\"b\",\"foreign\":1}\n",
    )
    .expect("write");

    tg_consensus::audit::read(&path).expect_err("foreign field");
}

/// An archive of the **old shape** is no longer read (ADR-0045, determination
/// 3). The line carried the verdict at the top level; read as a `Record` it is
/// refused. That is the express cost side of the decision and stands here so
/// that it does not appear as an error.
#[test]
fn an_archive_of_the_old_shape_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    std::fs::write(
        &path,
        "{\"index\":1,\"at\":null,\"kind\":\"k\",\"payload\":\"p\",\
         \"previous\":\"a\",\"digest\":\"b\",\"outcome\":\"applied\"}\n",
    )
    .expect("write");

    tg_consensus::audit::read(&path).expect_err("old shape");
}

// --- Rotation: segments one can move away -----------------------------------

/// Creates an archive and writes `count` records, rotating at `at`.
fn filled(dir: &std::path::Path, count: u64, at: Option<u64>) -> std::path::PathBuf {
    let path = dir.join("audit-1.jsonl");
    let mut archive = Archive::open_with(&path, at).expect("archive");
    for index in 1..=count {
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
    path
}

/// **The archive changes the file, and the chain carries on.**
///
/// The purpose is not the file size but the movability: a file that is
/// permanently appended to cannot be moved into the WORM archive by anyone
/// without racing the writer (ADR-0020). A sealed segment can be.
#[test]
fn the_archive_rotates_and_the_chain_continues() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 5, Some(2));

    let all = tg_consensus::audit::segments(&path);
    assert_eq!(all.len(), 3, "two sealed and the running one: {all:?}");

    let chain = tg_consensus::audit::verify_chain(&all, GENESIS).expect("the chain carries");
    assert_eq!(chain.records, 5);
    assert_eq!(chain.segments, 3);
}

/// **The index carries on across the seam**, it does not begin anew. Otherwise
/// a gap between two segments would be indistinguishable from a fresh start.
#[test]
fn the_index_continues_across_the_seam() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 4, Some(2));

    let all = tg_consensus::audit::segments(&path);
    let indices: Vec<u64> = all
        .iter()
        .flat_map(|segment| tg_consensus::audit::read(segment).expect("read"))
        .map(|record| record.index)
        .collect();

    assert_eq!(indices, [1, 2, 3, 4]);
}

/// **The first `previous` of a new file is the head of the old one.** Exactly
/// this case is the reason why `tgctl audit` knows an `--anchor` — until the
/// rotation this switch had no producer.
#[test]
fn a_new_segment_anchors_on_the_previous_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 4, Some(2));

    let all = tg_consensus::audit::segments(&path);
    let first = tg_consensus::audit::read(&all[0]).expect("read");
    let second = tg_consensus::audit::read(&all[1]).expect("read");

    assert_eq!(
        second[0].previous,
        first.last().expect("record").digest,
        "the new file does not hang on the head of the old one"
    );

    // And checked individually the second segment carries **only** with this anchor.
    tg_consensus::audit::verify(&all[1], &second, GENESIS).expect_err("against GENESIS");
    tg_consensus::audit::verify(&all[1], &second, &first.last().expect("record").digest)
        .expect("against the real anchor");
}

/// **A segment removed entirely stands out.**
///
/// That is the property a chain has across segments and a single segment cannot
/// have: whoever deletes a file leaves behind a jump in the index and a foreign
/// anchor.
#[test]
fn a_deleted_segment_is_a_finding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 6, Some(2));

    let all = tg_consensus::audit::segments(&path);
    assert!(all.len() >= 3, "{all:?}");
    std::fs::remove_file(&all[1]).expect("remove");

    let remaining = tg_consensus::audit::segments(&path);
    let err = tg_consensus::audit::verify_chain(&remaining, GENESIS).expect_err("segment missing");
    assert!(
        // **Measured, the index jump**, and the second branch was **dead**.
        // Both ways catch a removed segment (an index jump **and** a foreign
        // anchor), but which takes hold first is a statement about `verify` --
        // and whoever reorders it there shall learn it here instead of being
        // covered by an `||`. **Measured:** without the seam check the same
        // setup reports `WrongAnchor { expected: 8949e4da…, found: d19dd62b… }`,
        // so the second way carries -- it is not unreachable, only not this
        // one.
        err.detail.contains("index jump"),
        "{err}"
    );
}

/// A restart continues in the **running** segment and does not jump back in the
/// index. That was the latent place: `open` read the *number* of records as the
/// last index, and with a second segment those are two different numbers.
#[test]
fn reopening_a_rotated_archive_continues_the_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 5, Some(2));

    let mut reopened = Archive::open_with(&path, Some(2)).expect("archive");
    reopened
        .record(
            6,
            1,
            &tg_consensus::Submission::internal(Command::UpsertWorkload {
                document: document("afterwards"),
            }),
            &"applied",
        )
        .expect("append");
    drop(reopened);

    let all = tg_consensus::audit::segments(&path);
    let indices: Vec<u64> = all
        .iter()
        .flat_map(|segment| tg_consensus::audit::read(segment).expect("read"))
        .map(|record| record.index)
        .collect();

    assert_eq!(indices, [1, 2, 3, 4, 5, 6]);
    tg_consensus::audit::verify_chain(&all, GENESIS).expect("the chain carries");
}

/// **A damaged last segment cannot be continued** — the same assurance as
/// without rotation, now across the seam.
#[test]
fn a_tampered_sealed_segment_refuses_the_continuation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 4, Some(2));

    let sealed = tg_consensus::audit::sealed(&path);
    let last = sealed.last().expect("sealed segment");
    let text = std::fs::read_to_string(last).expect("read");

    // **First check that the forgery takes hold at all.** On the first attempt
    // `w4` stood here -- that lies in the *running* segment, not in the sealed
    // one, and the replacement did nothing. The test was green and checked
    // nothing. Whoever checks a detection checks the forgery first.
    let forged = text.replace("w1", "evil");
    assert_ne!(text, forged, "the forgery did not take hold: {text}");
    std::fs::write(last, &forged).expect("write");

    Archive::open_with(&path, Some(2)).expect_err("damaged segment");
}

/// Without a setting **nothing** rotates. A test that expects one file shall
/// not get a second one it does not expect.
#[test]
fn without_a_limit_nothing_rotates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 10, None);

    assert!(tg_consensus::audit::sealed(&path).is_empty());
    assert_eq!(tg_consensus::audit::segments(&path).len(), 1);
}

/// The numbers are padded so that `ls` shows them in chain order — and sorted
/// **numerically**, because the padding only holds up to 9999.
#[test]
fn sealed_segments_are_named_in_chain_order() {
    let base = std::path::Path::new("/srv/tg/audit-1.jsonl");

    assert_eq!(
        tg_consensus::audit::sealed_path(base, 7),
        std::path::Path::new("/srv/tg/audit-1.0007.jsonl")
    );
    assert_eq!(
        tg_consensus::audit::sealed_path(base, 12_345),
        std::path::Path::new("/srv/tg/audit-1.12345.jsonl")
    );
}

/// Names that *almost* fit are no segments. A `.bak` beside it would otherwise
/// extend the chain by a file nobody wrote.
#[test]
fn near_misses_are_not_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 3, Some(1));

    for name in [
        "audit-1.0002.jsonl.bak",
        "audit-1.jsonl.bak",
        "audit-1.x.jsonl",
        "audit-2.0001.jsonl",
        "audit-1..jsonl",
    ] {
        std::fs::write(dir.path().join(name), "").expect("file");
    }

    let all = tg_consensus::audit::segments(&path);
    for segment in &all {
        let name = segment.file_name().expect("name").to_string_lossy();
        assert!(
            name == "audit-1.jsonl" || name.starts_with("audit-1.0"),
            "{name} does not belong to the chain"
        );
    }
    tg_consensus::audit::verify_chain(&all, GENESIS).expect("the chain carries");
}

// --- The actor in the archive (ADR-0050) ------------------------------------

/// A record's actor — from the sealed payload.
fn actor(record: &tg_telemetry::audit::Record) -> Option<tg_consensus::Actor> {
    let event: tg_consensus::audit::Event = serde_json::from_str(&record.payload).expect("payload");

    event.actor
}

/// **Who caused something stands in the archive — and sealed at that.**
///
/// That was the reason for the envelope instead of a field per command
/// (ADR-0050, determination 4): the archive seals the whole payload (ADR-0045),
/// so it gets the actor for free.
#[test]
fn the_actor_is_sealed_into_the_archive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let mut archive = Archive::open_with(&path, None).expect("archive");

    archive
        .record(
            1,
            1,
            &tg_consensus::Submission::by(
                tg_consensus::Actor::LocalUid(1000),
                Command::UpsertWorkload {
                    document: document("api"),
                },
            ),
            &"applied",
        )
        .expect("append");
    drop(archive);

    let records = tg_consensus::audit::read(&path).expect("read");
    assert_eq!(
        actor(&records[0]),
        Some(tg_consensus::Actor::LocalUid(1000))
    );

    // And a rewritten actor is a **finding**: it lies in the digest.
    let text = std::fs::read_to_string(&path).expect("read");
    let forged = text.replace("1000", "4711");
    assert_ne!(text, forged, "the forgery did not take hold");
    std::fs::write(&path, &forged).expect("write");

    let records = tg_consensus::audit::read(&path).expect("read");
    tg_consensus::audit::verify(&path, &records, GENESIS).expect_err("rewritten actor");
}

/// **No actor means no key**, not `null`.
///
/// "No human was here" and "the actor is null" shall yield two digests — the
/// same consideration as with the missing time in `seal` and with the `outcome`
/// from ADR-0045.
#[test]
fn no_actor_means_no_key_in_the_payload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let mut archive = Archive::open_with(&path, None).expect("archive");

    archive
        .record(
            1,
            1,
            &tg_consensus::Submission::internal(Command::UpsertWorkload {
                document: document("api"),
            }),
            &"applied",
        )
        .expect("append");
    drop(archive);

    let records = tg_consensus::audit::read(&path).expect("read");
    assert_eq!(actor(&records[0]), None);
    assert!(
        !records[0].payload.contains("actor"),
        "the key stands there: {}",
        records[0].payload
    );
}

/// **The actor with and without yields two different digests.** Otherwise one
/// could be removed without breaking the chain.
#[test]
fn presence_and_absence_of_an_actor_differ() {
    let dir = tempfile::tempdir().expect("tempdir");
    let command = Command::UpsertWorkload {
        document: document("api"),
    };

    let mut digests = Vec::new();
    for (name, submission) in [
        (
            "without",
            tg_consensus::Submission::internal(command.clone()),
        ),
        (
            "with",
            tg_consensus::Submission::by(tg_consensus::Actor::LocalUid(0), command.clone()),
        ),
    ] {
        let path = dir.path().join(format!("{name}.jsonl"));
        let mut archive = Archive::open_with(&path, None).expect("archive");
        archive
            .record(1, 1, &submission, &"applied")
            .expect("append");
        digests.push(archive.head().to_owned());
    }

    assert_ne!(digests[0], digests[1]);
}

/// **An entry applied again after a crash does not break the chain**
/// (ADR-0020).
///
/// # The window it is about
///
/// `apply` writes the archive **per entry** and `persist()` only after the
/// batch — state and `last_applied` go in *one* transaction, so that no state
/// arises that is further than its pointer. If the process dies between the
/// archive record and the commit, the pointer therefore lies **back**, and
/// `openraft` applies the same entry again at the next start. The archive
/// thereby gets it twice.
///
/// **That is the wanted direction**, and it stood nowhere: the alternative
/// would be to persist first and archive afterwards — then the same crash loses
/// the record **entirely**, for after the restart the entry is no longer
/// applied. A **duplication** is an audit finding an auditor can resolve
/// themselves; a **gap** is a decision that stands nowhere (ADR-0020).
///
/// # Why it does not break the chain
///
/// The chain's index is its **own** counter (`self.records`); the log index
/// lies as a field in the sealed payload. Whoever one day merges the two — the
/// log index *as* the chain index, which suggests itself — turns this crash into
/// an archive that no longer verifies. And because `Archive::open` checks before
/// appending, the node would afterwards **not come up any more**. Exactly that
/// is what this test nails down.
#[tokio::test]
async fn a_reapplied_entry_does_not_break_the_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let entry = || {
        normal(
            7,
            Command::UpsertWorkload {
                document: document("a"),
            },
        )
    };

    // The run before the crash.
    {
        let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
        storage
            .machine
            .with_archive(Archive::open(&path).expect("archive"));
        storage.machine.apply(vec![entry()]).await.expect("apply");
    }

    // The restart: **the same** log index once more, because the pointer lay
    // back. A fresh store produces exactly that.
    {
        let mut storage = Storage::open(dir.path().join("raft2.redb")).expect("open");
        storage
            .machine
            .with_archive(Archive::open(&path).expect("archive"));
        storage.machine.apply(vec![entry()]).await.expect("apply");
    }

    let records = lines(&path);
    assert_eq!(records.len(), 2, "the entry does not stand there twice");
    assert_eq!(
        records
            .iter()
            .map(|record| record.index)
            .collect::<Vec<_>>(),
        vec![1, 2],
        "the chain index is not its own counter"
    );
    for record in &records {
        assert!(
            record.payload.contains("\"log_index\":7"),
            "the log index does not stand in the payload: {}",
            record.payload
        );
    }
    // And the verdict is the same both times: the repetition runs against the
    // same state, because pointer and state are persisted together (ADR-0004:
    // the same input, the same result).
    assert_eq!(verdict(&records[0]), verdict(&records[1]));

    assert!(
        Segment { records }.verify(GENESIS).is_ok(),
        "the chain does not carry a repetition"
    );
}

/// **An archive that cannot write stops the apply.**
///
/// The assurance has stood in the apply path since 11a and was unguarded: *"An
/// archive that cannot write is a storage error and no reason to carry on —
/// otherwise the cluster would run on and nobody would see that the audit trail
/// has had holes for hours."* That is the fail-closed direction ADR-0020 demands
/// for a retention-bound substrate, and it decides between a node that halts and
/// a cluster with a gappy trail.
///
/// **The error is produced at the rotation.** The open file handle survives
/// every permission change — for `root` too, who passes the bits by anyway. What
/// even `root` cannot do is create a file in a directory that no longer exists:
/// with `--audit-rotate 1` the **second** record needs a new segment, and that
/// fails with `ENOENT`.
///
/// The counter-check stands in the same test: the same course **with** a
/// directory succeeds. Without it the first part would only show that something
/// or other fails at the rotation.
#[tokio::test]
async fn an_archive_that_cannot_be_written_stops_the_apply() {
    // First the counter-check: with a directory the same course carries.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit = dir.path().join("archive");
        std::fs::create_dir(&audit).expect("directory");
        let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
        storage
            .machine
            .with_archive(Archive::open_with(audit.join("audit.jsonl"), Some(1)).expect("archive"));

        for index in 1..=2 {
            storage
                .machine
                .apply(vec![normal(
                    index,
                    Command::UpsertWorkload {
                        document: document("api"),
                    },
                )])
                .await
                .expect("with a directory the apply must go through");
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("archive");
    std::fs::create_dir(&audit).expect("directory");
    let mut storage = Storage::open(dir.path().join("raft.redb")).expect("open");
    storage
        .machine
        .with_archive(Archive::open_with(audit.join("audit.jsonl"), Some(1)).expect("archive"));

    // The first record goes into the open file.
    storage
        .machine
        .apply(vec![normal(
            1,
            Command::UpsertWorkload {
                document: document("api"),
            },
        )])
        .await
        .expect("the first record carries");

    // And then the directory is gone: the open handle carries on, a **new**
    // segment can no longer be created.
    std::fs::remove_dir_all(&audit).expect("directory removable");

    let result = storage
        .machine
        .apply(vec![normal(
            2,
            Command::UpsertWorkload {
                document: document("ledger"),
            },
        )])
        .await;

    assert!(
        result.is_err(),
        "an archive that cannot write must not let the apply through -- \
         otherwise the trail has holes nobody sees (ADR-0020): {result:?}"
    );
}

/// **What stays lying has a number** (ADR-0132, determination 1).
///
/// Nothing is deleted here (determination 2) — what lies there is evidence
/// nobody has yet moved into the WORM archive. Until this number existed, an
/// operator saw the occupancy only when `apply` could no longer write, and that
/// stops the node (ADR-0020).
///
/// **The separation is the point:** the bytes count the running file too (it
/// occupies the disk), the segments do not (one must not take them away). A
/// number that treats both alike leads an operator astray.
#[test]
fn the_footprint_counts_the_open_file_in_bytes_and_not_in_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 5, Some(2));

    let footprint = tg_consensus::audit::footprint(&path);

    assert_eq!(
        footprint.sealed, 2,
        "two sealed segments -- the running one does not belong to them"
    );
    assert_eq!(
        tg_consensus::audit::segments(&path).len(),
        3,
        "three files in total: the counter-check to the number above"
    );

    let by_hand: u64 = tg_consensus::audit::segments(&path)
        .iter()
        .map(|segment| std::fs::metadata(segment).expect("metadata").len())
        .sum();
    assert_eq!(
        footprint.bytes, by_hand,
        "the bytes must cover **all** files, the running one included"
    );
    assert!(
        footprint.bytes > 0,
        "an archive with five records occupies nothing? Then the witness does \
         not measure what it measures"
    );
}

/// **An archive without rotation has nothing to move away.**
///
/// The counter-check: there `sealed` counts zero although bytes lie there.
/// Without it the witness above would be green even if `sealed` simply counted
/// the files.
#[test]
fn an_archive_without_rotation_has_nothing_to_move_away() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 5, None);

    let footprint = tg_consensus::audit::footprint(&path);
    assert_eq!(footprint.sealed, 0);
    assert!(footprint.bytes > 0);
}

/// **A wrong anchor is reported in words, not as a variant name.**
///
/// `--anchor` does not check its form, and that is right: whether it carries is
/// decided by the chain, and a second check would be a second place with the
/// same responsibility. It stands and falls, however, with the **answer** being
/// any good — measured, `WrongAnchor { expected: "nonsense", found: "7ab1…" }`
/// stood there, that is, the name of a Rust variant.
///
/// `AuditError` has had a sentence for this case since phase 11a. It just had
/// no reader.
#[test]
fn a_wrong_anchor_is_reported_in_words() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = filled(dir.path(), 3, None);
    let records = tg_consensus::audit::read(&path).expect("read");

    let err = tg_consensus::audit::verify(&path, &records, "nonsense")
        .expect_err("a wrong anchor must stand out");

    assert!(
        err.detail.contains("expected was 'nonsense'"),
        "the message must name the handed-in anchor: {}",
        err.detail
    );
    assert!(
        !err.detail.contains("WrongAnchor"),
        "the name of the variant is the language of the compiler, not that of \
         an auditor: {}",
        err.detail
    );
    assert!(
        err.detail.contains("a segment before it is missing"),
        "and it must say what that can mean: {}",
        err.detail
    );
}
