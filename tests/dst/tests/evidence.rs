//! The report as an artifact (ADR-0020, phase 11c).
//!
//! The phase's promise is one sentence: **the same seed produces the same
//! report.** What is to be checked about it falls into three parts — that the
//! report reads the result correctly, that it cannot be changed unnoticed, and
//! that it looks the same twice.
//!
//! Pure logic, therefore **tests first** (CLAUDE.md).

use tg_dst::evidence::{Judgement, Report};
use tg_telemetry::audit::{AuditError, GENESIS};

/// The output of an ordinary, green run.
const GREEN: &str = "\
   Compiling tg-dst v0.1.0
    Finished test profile
     Running tests/scenarios.rs (target/debug/deps/scenarios-7fc420d4c94b15da)

running 3 tests
test five_nodes_elect_a_leader_and_commit ... ok
test losing_two_nodes_keeps_the_quorum ... ok
test the_third_loss_breaks_the_quorum ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
";

fn seeds() -> Vec<u64> {
    vec![0x5EED_0000_0000_0000, 0x5EED_0000_0000_0001]
}

// ------------------------------------------------------------------ Reading

/// The normal case: three scenarios, three verdicts, the seeds beside them.
#[test]
fn a_green_run_yields_three_passed_scenarios() {
    let report = Report::parse(GREEN, &seeds());

    assert_eq!(report.scenarios.len(), 3);
    assert!(report.is_clean());
    assert_eq!(report.seeds, seeds());
    assert!(
        report
            .scenarios
            .iter()
            .all(|scenario| scenario.judgement == Judgement::Passed)
    );
}

/// **A failure prevails.**
///
/// `cargo test` names a failed scenario twice: once in the run, once in the
/// summary. If a green line of the same name came from another test file in
/// between, it would overwrite the verdict — and the report would announce a
/// passed run that was none.
#[test]
fn a_failure_wins_over_a_later_pass_of_the_same_name() {
    let output = "\
     Running tests/scenarios.rs (target/debug/deps/scenarios-7fc4)
test a_partition_without_a_majority_freezes_everything ... FAILED
test a_partition_without_a_majority_freezes_everything ... ok
";

    let report = Report::parse(output, &seeds());

    assert_eq!(report.scenarios.len(), 1);
    assert_eq!(report.scenarios[0].judgement, Judgement::Failed);
    assert!(!report.is_clean());
}

/// And the other way round just the same — the order must change nothing.
#[test]
fn the_order_of_the_two_lines_does_not_matter() {
    let first = Report::parse("test x ... ok\ntest x ... FAILED\n", &seeds());
    let second = Report::parse("test x ... FAILED\ntest x ... ok\n", &seeds());

    assert_eq!(first, second);
    assert_eq!(first.scenarios[0].judgement, Judgement::Failed);
}

/// `ok (12 ms)` is passed — only the head of the verdict counts.
#[test]
fn a_duration_after_the_verdict_is_ignored() {
    let report = Report::parse("test schnell ... ok (12 ms)\n", &seeds());

    assert_eq!(report.scenarios[0].judgement, Judgement::Passed);
}

/// Skipped scenarios stand in the report as such.
///
/// Withholding them would be the more dangerous choice: an auditor who expects
/// twelve scenarios and reads eleven asks. One who reads eleven and does not
/// know that there are twelve does not ask.
#[test]
fn an_ignored_scenario_is_named_as_ignored() {
    let report = Report::parse("test teuer ... ignored\n", &seeds());

    assert_eq!(report.scenarios[0].judgement, Judgement::Ignored);
    assert!(report.is_clean(), "skipped is not failed");
}

/// **A line that only looks like a result is passed over — not guessed.**
///
/// A guessed verdict is worse than a missing one: the missing one stands out
/// when counting.
#[test]
fn a_line_that_only_looks_like_a_result_is_skipped() {
    let output = "\
test irgendwas ... unbekannter-zustand
testohnepause ... ok
test  ... ok
";

    let report = Report::parse(output, &seeds());

    assert!(report.scenarios.is_empty(), "{:?}", report.scenarios);
}

/// The scenarios stand sorted, not in execution order.
///
/// `cargo test` runs concurrently; the order changes from run to run. A report
/// whose lines dance cannot be checked with `diff` — and with that the phase's
/// promise cannot be substantiated.
#[test]
fn scenarios_are_sorted_by_name() {
    let report = Report::parse("test zebra ... ok\ntest alpha ... ok\n", &seeds());

    assert_eq!(
        report
            .scenarios
            .iter()
            .map(|scenario| scenario.name.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "zebra"]
    );
}

// ----------------------------------------------------- Reproducibility

/// **The phase's promise.**
///
/// The same run twice, the same artifact twice — character for character.
#[test]
fn the_same_run_renders_the_same_report() {
    let first = Report::parse(GREEN, &seeds()).render();
    let second = Report::parse(GREEN, &seeds()).render();

    assert_eq!(first, second);
}

/// Different seeds, a different report — otherwise the setting would be without
/// effect.
#[test]
fn other_seeds_render_a_different_report() {
    let mine = Report::parse(GREEN, &seeds()).render();
    let other = Report::parse(GREEN, &[1, 2]).render();

    assert_ne!(mine, other);
}

/// The report names all three items ADR-0020 demands.
#[test]
fn the_report_names_seed_scenario_and_verdict() {
    let text = Report::parse(GREEN, &seeds()).render();

    assert!(text.contains(&seeds()[0].to_string()), "seed missing");
    assert!(
        text.contains("five_nodes_elect_a_leader_and_commit"),
        "scenario missing"
    );
    assert!(text.contains("passed"), "verdict missing");
    assert!(text.contains("Head:"), "the chain head is missing");
}

/// A failed run says so in its verdict.
#[test]
fn a_failed_run_says_so_in_its_verdict() {
    let text = Report::parse("test x ... FAILED\n", &seeds()).render();

    assert!(text.contains("failed"), "{text}");
}

// ------------------------------------------------------------- Sealing

/// The report is a chain, and it carries.
#[test]
fn the_report_seals_into_a_chain_that_verifies() {
    let segment = Report::parse(GREEN, &seeds()).to_segment();

    let checked = segment.verify(GENESIS).expect("the chain carries");

    // One record per scenario, plus the head with the seeds and the verdict at
    // the end (ADR-0045 as the question, here the answer).
    assert_eq!(checked.records, 5);
}

/// **Whoever changes a verdict is seen.**
///
/// That is the purpose of the sealing: a report one can change unnoticed is an
/// essay.
#[test]
fn turning_a_failure_into_a_pass_breaks_the_chain() {
    let mut segment = Report::parse("test x ... FAILED\n", &seeds()).to_segment();

    segment.records[1].payload = "passed x".to_owned();

    assert!(matches!(
        segment.verify(GENESIS),
        Err(AuditError::Altered { index: 2 })
    ));
}

/// **The seeds hang in the same chain.**
///
/// Standing beside it, they could be swapped without the chain breaking — and a
/// passed run could afterwards be given different inputs without the report
/// looking different.
#[test]
fn exchanging_the_seeds_breaks_the_chain() {
    let mut segment = Report::parse(GREEN, &seeds()).to_segment();

    segment.records[0].payload = "1,2".to_owned();

    assert!(matches!(
        segment.verify(GENESIS),
        Err(AuditError::Altered { index: 1 })
    ));
}

/// Two different runs have two different heads.
#[test]
fn two_different_runs_have_two_different_heads() {
    let green = Report::parse(GREEN, &seeds()).to_segment();
    let red = Report::parse(
        GREEN
            .replace(
                "test losing_two_nodes_keeps_the_quorum ... ok",
                "test losing_two_nodes_keeps_the_quorum ... FAILED",
            )
            .as_str(),
        &seeds(),
    )
    .to_segment();

    assert_ne!(green.head(GENESIS), red.head(GENESIS));
}

// ------------------------------------------------------------- Provenance

/// **The checks carry where they come from.**
///
/// The first report carried this parser's tests in the same list as the
/// harness's resilience scenarios — and counted them. An auditor would have read
/// sixty resilience checks where twelve had taken place. In a DORA artifact that
/// is no blemish.
#[test]
fn every_check_carries_the_target_it_came_from() {
    let output = "\
     Running tests/scenarios.rs (target/debug/deps/scenarios-7fc4)
test five_nodes_elect_a_leader_and_commit ... ok
     Running tests/evidence.rs (target/debug/deps/evidence-aa11)
test a_green_run_yields_three_passed_scenarios ... ok
";

    let report = Report::parse(output, &seeds());

    assert_eq!(report.scenarios.len(), 2);
    assert_eq!(report.resilience_scenarios(), 1, "{:?}", report.scenarios);
    assert_eq!(report.scenarios[0].suite, "evidence");
    assert_eq!(report.scenarios[1].suite, "scenarios");
}

/// **The hash in the path does not belong in the report.**
///
/// It changes at every rebuild. If it stood in it, the same seed would yield two
/// different reports — and the phase's promise could not be kept.
#[test]
fn the_build_hash_never_reaches_the_report() {
    let first = Report::parse(
        "     Running tests/scenarios.rs (target/debug/deps/scenarios-aaaa)\n\
         test x ... ok\n",
        &seeds(),
    );
    let second = Report::parse(
        "     Running tests/scenarios.rs (target/debug/deps/scenarios-bbbb)\n\
         test x ... ok\n",
        &seeds(),
    );

    assert_eq!(first, second);
    assert!(!first.render().contains("aaaa"), "{}", first.render());
}

/// Two test targets may carry the same test name — and they do.
///
/// With the name alone as the key one would overwrite the other, and the report
/// would lose a check without anybody noticing.
#[test]
fn the_same_name_in_two_targets_stays_two_checks() {
    let output = "\
     Running tests/scenarios.rs (target/debug/deps/scenarios-1)
test a_partition_without_a_majority_freezes_everything ... ok
     Running tests/faults.rs (target/debug/deps/faults-2)
test a_partition_without_a_majority_freezes_everything ... ok
";

    let report = Report::parse(output, &seeds());

    assert_eq!(report.scenarios.len(), 2);
}

/// The report groups by provenance and names both numbers.
#[test]
fn the_verdict_names_both_counts() {
    let output = "\
     Running tests/scenarios.rs (target/debug/deps/scenarios-1)
test resilienz ... ok
     Running tests/bus.rs (target/debug/deps/bus-2)
test der_bus_selbst ... ok
";

    let text = Report::parse(output, &seeds()).render();

    assert!(text.contains("## scenarios"), "{text}");
    assert!(text.contains("## bus"), "{text}");
    assert!(text.contains("1 resilience scenarios"), "{text}");
    assert!(text.contains("2 checks in total"), "{text}");
}

/// And the provenance hangs **in** the chain.
///
/// Otherwise a check of the harness could afterwards be passed off as a
/// resilience scenario without the chain breaking.
#[test]
fn moving_a_check_between_targets_breaks_the_chain() {
    let output = "\
     Running tests/bus.rs (target/debug/deps/bus-1)
test x ... ok
";
    let mut segment = Report::parse(output, &seeds()).to_segment();

    segment.records[1].payload = "passed scenarios::x".to_owned();

    assert!(matches!(
        segment.verify(GENESIS),
        Err(AuditError::Altered { index: 2 })
    ));
}

// --------------------------------------------------------- The verdict in the chain

/// **The verdict hangs in the chain.**
///
/// It is derivable — it could be recomputed from the scenario lines —, and
/// precisely for that reason it was long not sealed. Only nobody recomputes it,
/// and it is the line an auditor reads first: `failed` changed to `passed` would
/// otherwise yield a file with a matching head and a lying headline.
#[test]
fn the_verdict_hangs_in_the_chain() {
    let mut segment = Report::parse(GREEN, &seeds()).to_segment();
    let last = segment.records.len() - 1;
    assert_eq!(segment.records[last].kind, "dst_verdict");
    assert!(
        segment.records[last].payload.starts_with("passed"),
        "{}",
        segment.records[last].payload
    );

    segment.records[last].payload = "failed 3 3 2".to_owned();

    assert!(matches!(
        segment.verify(GENESIS),
        Err(AuditError::Altered { index: 5 })
    ));
}

/// A failed run seals a different verdict **in** the chain, not only in its
/// headline.
#[test]
fn a_failed_run_seals_a_different_verdict() {
    let green = Report::parse(GREEN, &seeds()).to_segment();
    let red = Report::parse(
        &GREEN.replace(
            "test losing_two_nodes_keeps_the_quorum ... ok",
            "test losing_two_nodes_keeps_the_quorum ... FAILED",
        ),
        &seeds(),
    )
    .to_segment();

    let verdict = |segment: &tg_telemetry::audit::Segment| {
        segment.records.last().expect("verdict").payload.clone()
    };

    assert!(verdict(&green).starts_with("passed"));
    assert!(verdict(&red).starts_with("failed"));
}

/// The numbers in the verdict are sealed along. A report that claims "12
/// resilience scenarios" and contains three would be the find from 11c again —
/// there the measuring instrument had counted itself.
#[test]
fn the_counts_in_the_verdict_are_sealed() {
    let segment = Report::parse(GREEN, &seeds()).to_segment();
    let payload = segment.records.last().expect("verdict").payload.clone();

    // passed, 3 resilience scenarios, 3 checks, 2 seeds
    assert_eq!(payload, "passed 3 3 2");
}

// ------------------------------------------------------- The checkable file

/// **The segment is the same format as the audit archive**, so that
/// `tgctl audit` recomputes it without learning a second procedure (11c).
#[test]
fn the_segment_file_is_archive_shaped_and_verifies() {
    let report = Report::parse(GREEN, &seeds());

    let records: Vec<tg_telemetry::audit::Record> = report
        .to_jsonl()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("line"))
        .collect();

    assert_eq!(records, report.to_segment().records);
    assert!(
        tg_telemetry::audit::Segment { records }
            .verify(GENESIS)
            .is_ok()
    );
}

/// The same promise as for the rendered report: the same run yields the same
/// file. Otherwise the artifact would be one that never looks the same twice.
#[test]
fn the_same_run_writes_the_same_segment_file() {
    let first = Report::parse(GREEN, &seeds()).to_jsonl();
    let second = Report::parse(GREEN, &seeds()).to_jsonl();

    assert_eq!(first, second);
}

/// A changed line in the segment file is seen on recomputation — the way an
/// auditor really goes.
#[test]
fn a_tampered_segment_file_does_not_verify() {
    let honest = Report::parse(GREEN, &seeds()).to_jsonl();
    let jsonl = honest.replace("passed", "failed");
    assert_ne!(honest, jsonl, "the forgery did not bite");

    let records: Vec<tg_telemetry::audit::Record> = jsonl
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("line"))
        .collect();

    assert!(
        tg_telemetry::audit::Segment { records }
            .verify(GENESIS)
            .is_err()
    );
}
