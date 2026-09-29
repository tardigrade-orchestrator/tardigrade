//! The audit trail, demonstrably append-only (ADR-0020 — phase 11a).
//!
//! Written before the implementation. The word this phase hangs on is
//! **demonstrably** — the same as with the BPF proof in 9b: not assert, but
//! show.
//!
//! # Why the Raft log alone does not suffice
//!
//! ADR-0020 calls it "append-only, ordered, replicated" and derives tamper
//! evidence from it. That holds **as long as it is replicated**: a change would
//! stand out because four other nodes contradict it. Exported and compacted
//! (phase 5d), nothing of that property is left — the archive is a file, and
//! files can be changed.
//!
//! That is why the export carries its integrity **itself**: a hash chain over
//! the records. That is exactly the open point from ADR-0020, "integrity proof
//! (signature/hash chain over segments)".
//!
//! # What the chain achieves and what it does not
//!
//! It makes **change detectable**, not impossible. Whoever owns the archive can
//! rewrite it — but not so that the head still matches the one a running
//! replica keeps. That is precisely the auditor's task: hold the archive's head
//! against the cluster's.

use tg_telemetry::audit::{Anomaly, AuditError, Segment, seal};

/// The anchor of an archive that begins at zero.
const GENESIS: &str = tg_telemetry::audit::GENESIS;

/// Builds a segment from consecutive records.
fn segment(from: u64, count: u64, anchor: &str) -> Segment {
    let mut records = Vec::new();
    let mut previous = anchor.to_owned();

    for step in 0..count {
        let index = from + step;
        #[allow(clippy::cast_possible_wrap)]
        let record = seal(
            &previous,
            index,
            Some(1_756_000_000 + index as i64),
            "upsert_workload",
            &format!("{{\"index\":{index}}}"),
        );
        previous.clone_from(&record.digest);
        records.push(record);
    }

    Segment { records }
}

// ------------------------------------------------------------ The normal case

#[test]
fn an_untouched_segment_verifies_and_yields_its_head() {
    let segment = segment(1, 10, GENESIS);
    let head = segment.records.last().expect("not empty").digest.clone();

    let report = segment.verify(GENESIS).expect("unaltered");

    assert_eq!(report.head, head);
    assert_eq!(report.records, 10);
    assert!(report.anomalies.is_empty());
}

/// Two segments in a row: the first's head is the second's anchor. Without this
/// chaining a whole segment could be left out.
#[test]
fn segments_chain_through_their_heads() {
    let first = segment(1, 5, GENESIS);
    let head = first.verify(GENESIS).expect("first").head;

    let second = segment(6, 5, &head);
    second.verify(&head).expect("second");
}

#[test]
fn an_empty_segment_verifies_to_its_anchor() {
    let report = Segment {
        records: Vec::new(),
    }
    .verify(GENESIS)
    .expect("empty is valid");

    assert_eq!(report.head, GENESIS);
    assert_eq!(report.records, 0);
}

// ------------------------------------------------- What **must** stand out

/// **Altering.** A record with different content has a different digest.
#[test]
fn altering_a_record_is_detected() {
    let mut segment = segment(1, 5, GENESIS);
    segment.records[2].payload = "{\"index\":999}".to_owned();

    let err = segment.verify(GENESIS).expect_err("altered");

    assert!(
        matches!(err, AuditError::Altered { index: 3 }),
        "expected Altered at 3, was {err:?}"
    );
}

/// The timestamp belongs in the digest too — otherwise an event could be moved
/// afterwards, and that is exactly what would matter to an auditor.
#[test]
fn altering_a_timestamp_is_detected() {
    let mut segment = segment(1, 5, GENESIS);
    segment.records[1].at = segment.records[1].at.map(|at| at + 3600);

    assert!(matches!(
        segment.verify(GENESIS),
        Err(AuditError::Altered { index: 2 })
    ));
}

/// **Removing.** The successor then names a predecessor that no longer stands
/// there — the chain breaks.
#[test]
fn removing_a_record_breaks_the_chain() {
    let mut segment = segment(1, 5, GENESIS);
    segment.records.remove(2);

    let err = segment.verify(GENESIS).expect_err("removed");

    assert!(
        matches!(err, AuditError::Broken { index: 4 }),
        "expected Broken at 4, was {err:?}"
    );
}

/// **Removing and re-chaining.** Here the second check earns its existence: the
/// chain is intact in itself, but the numbering has a hole.
///
/// Whoever only recomputed the chain would see nothing — and the archive would
/// be one event poorer without it standing out. That is why `verify` checks the
/// numbering **separately**.
#[test]
fn a_removal_that_was_rechained_still_shows_as_a_gap() {
    let mut segment = segment(1, 5, GENESIS);
    segment.records.remove(2);

    let mut previous = GENESIS.to_owned();
    for record in &mut segment.records {
        *record = seal(
            &previous,
            record.index,
            record.at,
            &record.kind,
            &record.payload,
        );
        previous.clone_from(&record.digest);
    }

    let err = segment.verify(GENESIS).expect_err("gap");

    assert!(
        matches!(
            err,
            AuditError::Gap {
                after: 2,
                before: 4
            }
        ),
        "expected Gap between 2 and 4, was {err:?}"
    );
}

/// **Reordering.**
#[test]
fn reordering_records_is_detected() {
    let mut segment = segment(1, 5, GENESIS);
    segment.records.swap(1, 3);

    assert!(segment.verify(GENESIS).is_err());
}

/// **Appending with the wrong anchor.** A segment that does not join on to its
/// predecessor does not belong in this archive.
#[test]
fn a_segment_that_does_not_follow_its_anchor_is_refused() {
    let segment = segment(1, 5, GENESIS);

    // An anchor that is not the one under which the segment was sealed.
    // (Sixty-four zeros would be GENESIS and thereby the right one.)
    let err = segment
        .verify("1111111111111111111111111111111111111111111111111111111111111111")
        .expect_err("wrong anchor");

    assert!(
        matches!(err, AuditError::WrongAnchor { .. }),
        "expected WrongAnchor, was {err:?}"
    );
}

/// **Rewriting.** Whoever regenerates the whole segment with a valid chain gets
/// a different head — and that no longer matches the one a running replica
/// keeps. That is the limit of what a hash chain can achieve, and it stands
/// here as a test so that nobody expects more.
#[test]
fn rewriting_the_whole_segment_changes_its_head() {
    let honest = segment(1, 5, GENESIS);
    let head = honest.verify(GENESIS).expect("honest").head;

    let mut forged = segment(1, 5, GENESIS);
    forged.records[2].payload = "{\"index\":999}".to_owned();
    // The forger recomputes the chain.
    let mut previous = GENESIS.to_owned();
    for record in &mut forged.records {
        *record = seal(
            &previous,
            record.index,
            record.at,
            &record.kind,
            &record.payload,
        );
        previous.clone_from(&record.digest);
    }

    let forged_head = forged.verify(GENESIS).expect("consistent in itself").head;

    assert_ne!(
        forged_head, head,
        "a forgery with a valid chain would be indistinguishable from the \
         original"
    );
}

// ------------------------------------------------------------- What stands out

/// A timestamp that jumps back is **no** chain break — but a finding for an
/// auditor. The two are reported separately: the one is manipulation, the other
/// a clock that was corrected (ADR-0024).
#[test]
fn time_going_backwards_is_reported_but_does_not_break_the_chain() {
    let mut records = Vec::new();
    let mut previous = GENESIS.to_owned();
    for (index, at) in [(1_u64, 1_756_000_100_i64), (2, 1_756_000_050)] {
        let record = seal(&previous, index, Some(at), "grant_lease", "{}");
        previous.clone_from(&record.digest);
        records.push(record);
    }

    let report = Segment { records }
        .verify(GENESIS)
        .expect("the chain is intact");

    assert_eq!(
        report.anomalies,
        vec![Anomaly::TimeWentBackwards {
            index: 2,
            from: 1_756_000_100,
            to: 1_756_000_050
        }]
    );
}

// --------------------------------------------------------------- Determinism

/// The same record yields the same digest — otherwise the chain would differ on
/// two nodes and the comparison with the cluster would be worthless.
#[test]
fn sealing_the_same_record_twice_gives_the_same_digest() {
    let left = seal(
        GENESIS,
        7,
        Some(1_756_000_007),
        "admit_node",
        "{\"node\":\"a\"}",
    );
    let right = seal(
        GENESIS,
        7,
        Some(1_756_000_007),
        "admit_node",
        "{\"node\":\"a\"}",
    );

    assert_eq!(left.digest, right.digest);
}

/// A different predecessor yields a different digest — that is the chain.
#[test]
fn the_digest_depends_on_the_predecessor() {
    let left = seal(GENESIS, 7, Some(1_756_000_007), "admit_node", "{}");
    let right = seal(&left.digest, 7, Some(1_756_000_007), "admit_node", "{}");

    assert_ne!(left.digest, right.digest);
}

/// The digest is hexadecimal and has SHA-256's length — an archive is read by
/// tools that expect that.
#[test]
fn a_digest_is_sixty_four_hex_characters() {
    let record = seal(GENESIS, 1, Some(0), "x", "{}");

    assert_eq!(record.digest.len(), 64);
    assert!(record.digest.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(GENESIS.len(), 64);
}

// ---------------------------------------------------- The limit of the chain

/// **Truncation does not stand out to the chain alone** — and that is no
/// weakness but the limit that makes the head comparison necessary.
///
/// Whoever leaves out the last records leaves behind an intact, merely shorter
/// chain. What gives them away is the **head**: it no longer matches the one
/// the next segment names as its anchor, nor the one a running replica keeps.
///
/// The fuzz run pushed me onto this spot; it stands here so that nobody expects
/// more of the chain than it can achieve.
#[test]
fn truncating_a_segment_leaves_a_valid_chain_but_a_different_head() {
    let full = segment(1, 5, GENESIS);
    let head = full.verify(GENESIS).expect("complete").head;

    let mut shortened = full.clone();
    shortened.records.truncate(3);

    let report = shortened.verify(GENESIS).expect("the chain is intact");

    assert_eq!(report.records, 3);
    assert_ne!(
        report.head, head,
        "a truncated segment would have the same head — then nobody would find it"
    );
}

/// And the join gives it away: the next segment names the real head as its
/// anchor, and that no longer fits.
#[test]
fn the_next_segment_no_longer_fits_after_a_truncation() {
    let full = segment(1, 5, GENESIS);
    let head = full.verify(GENESIS).expect("complete").head;
    let next = segment(6, 3, &head);

    let mut shortened = full;
    shortened.records.truncate(3);
    let short_head = shortened.verify(GENESIS).expect("intact").head;

    assert!(
        matches!(
            next.verify(&short_head),
            Err(AuditError::WrongAnchor { .. })
        ),
        "the truncation went unnoticed"
    );
}

// ------------------------------------------------------------- The missing time

/// **No time is something other than the time zero.** Both must lead to
/// different digests, otherwise an undated record could be dated afterwards to
/// 1 January 1970 without the chain breaking.
#[test]
fn an_absent_timestamp_and_the_epoch_are_not_the_same_record() {
    let without = seal(GENESIS, 1, None, "remove_workload", "{}");
    let epoch = seal(GENESIS, 1, Some(0), "remove_workload", "{}");

    assert_ne!(without.digest, epoch.digest);
}

/// A clock jumping back stands out even when undated events lie between the two
/// dated ones.
///
/// Compared is against the last **known** time. Whoever had compared against
/// the last record instead would need only one undated command in between to
/// make the jump back invisible.
#[test]
fn undated_records_in_between_do_not_hide_a_clock_going_backwards() {
    let mut records = Vec::new();
    let mut previous = GENESIS.to_owned();

    for (index, at) in [
        (1_u64, Some(1_756_000_100_i64)),
        (2, None),
        (3, None),
        (4, Some(1_756_000_050)),
    ] {
        let record = seal(&previous, index, at, "grant_lease", "{}");
        previous.clone_from(&record.digest);
        records.push(record);
    }

    let report = Segment { records }
        .verify(GENESIS)
        .expect("the chain holds");

    assert_eq!(
        report.anomalies,
        vec![Anomaly::TimeWentBackwards {
            index: 4,
            from: 1_756_000_100,
            to: 1_756_000_050,
        }]
    );
}

/// **A renumbered segment is detected** (ADR-0020).
///
/// # Why that is not caught by the consecutiveness
///
/// `verify` checks that every index follows the previous one — that catches a
/// **single** shifted number. But if a forger shifts **all** of them, the
/// sequence stays without gaps, and the `previous` chain is untouched: they
/// have re-hung nothing. What then still carries is solely that the index
/// **goes into the digest**.
///
/// And on that rests an assurance from the rotation step: "a **wholly removed**
/// segment leaves a jump in the index and a foreign anchor, and both stand
/// out." Without sealing the index, the jump could be computed away — only the
/// anchor would remain, that is, half of the proof.
///
/// Found by a mutation run: `hasher.update(index)` removed, and no target went
/// red.
#[test]
fn renumbering_the_whole_segment_is_detected() {
    let mut forged = segment(1, 5, GENESIS);

    // The forger shifts everything by the same amount — the sequence stays
    // without gaps, the chain stays closed.
    for record in &mut forged.records {
        record.index += 1000;
    }

    let outcome = forged.verify(GENESIS);

    assert!(
        matches!(outcome, Err(AuditError::Altered { .. })),
        "a renumbering has to stand out: {outcome:?}"
    );
}

/// And the counter-check: the unaltered segment carries.
///
/// Without it the test above would show green even if `verify` rejected
/// everything on principle.
#[test]
fn the_same_segment_without_renumbering_verifies() {
    let honest = segment(1, 5, GENESIS);

    assert!(honest.verify(GENESIS).is_ok());
}

/// **A finding is a sentence and not Rust syntax** (ADR-0020).
///
/// `tgctl audit` wrote the finding with `{anomaly:?}` — that is,
/// `TimeWentBackwards { index: 42, from: …, to: … }`. That is the **one**
/// output an auditor reads, and `AuditError` beside it had long had a
/// `Display`: the asymmetry was the finding, not the line.
///
/// The same rule was already written down once for `tg_consensus::Rejection` —
/// *"An operator reads there the answer to 'why did that not work'; it shall be
/// a sentence."*
#[test]
fn an_anomaly_renders_as_a_sentence() {
    let anomaly = tg_telemetry::audit::Anomaly::TimeWentBackwards {
        index: 42,
        from: 1_700_000_000,
        to: 1_699_999_999,
    };

    let sentence = anomaly.to_string();

    // The three numbers an auditor needs — and the unit, because a bare epoch
    // number tells nobody what it is.
    for part in ["42", "1700000000", "1699999999", "seconds UTC"] {
        assert!(
            sentence.contains(part),
            "'{part}' missing from the finding: {sentence}"
        );
    }

    // And **no** Rust syntax. Without this half a `Display` that merely passed
    // on the Debug body would be green too.
    assert!(
        !sentence.contains("TimeWentBackwards") && !sentence.contains("index:"),
        "the finding carries the Debug form: {sentence}"
    );
}
