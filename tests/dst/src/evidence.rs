//! The report of a DST run — the evidence per ADR-0020.
//!
//! ADR-0020 makes DST runs **exportable evidence** for the DORA resilience test
//! obligation. What an auditor needs for that stands in phase 11c in three
//! words: **seed, scenario, verdict.**
//!
//! **The report records the real run instead of rebuilding it.** The most
//! obvious construction would be a list of scenarios the report generator itself
//! walks. It would be wrong: then the scenarios would exist twice — once as a
//! `#[tokio::test]`, once as an entry in a list — and the second place is the one
//! one forgets when adding. A report that does not know a scenario does not
//! report it as failed either; it reports nothing, and that looks like success.
//!
//! **It is an audit segment.** A report one can change unnoticed is an essay.
//! The report is therefore sealed with the **same** hash chain as the audit trail
//! from phase 11a ([`tg_telemetry::audit`]) — not with a second one of its own.
//!
//! **What does not stand in the report:** runtimes. They differ at every run, and
//! the promise reads "the same seed produces the same report".

use std::collections::BTreeMap;
use std::fmt::Write as _;

use tg_telemetry::audit::{GENESIS, Record, Segment, seal};

/// How a scenario turned out.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Judgement {
    /// Passed.
    Passed,
    /// Failed.
    Failed,
    /// Skipped (`#[ignore]`).
    Ignored,
}

impl Judgement {
    /// The name as it stands in the report.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Ignored => "ignored",
        }
    }
}

/// A scenario with its verdict.
///
/// The provenance stands **first**, because that is what is sorted by: a report
/// that carries the harness's scenarios together with the report parser's tests
/// in one list claims more resilience checks than took place. In a DORA artifact
/// that is no blemish.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Scenario {
    /// Which test target it comes from — `scenarios`, `bus`, `faults`, …
    pub suite: String,
    /// The name as `cargo test` prints it.
    pub name: String,
    /// The verdict.
    pub judgement: Judgement,
}

/// The report of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The seeds that were run over — the first of the three items.
    pub seeds: Vec<u64>,
    /// The scenarios, **sorted by name**.
    ///
    /// Sorted and not in execution order: `cargo test` runs concurrently, and
    /// the order changes from run to run. A report whose lines dance is none.
    pub scenarios: Vec<Scenario>,
}

impl Report {
    /// Reads the report from `cargo test`'s output.
    ///
    /// What is read is `libtest`'s standard format — `test <name> ... ok`.
    /// Expressly **not** `--format json`: that is to this day
    /// `-Z unstable-options` and thereby nightly. A checking artifact that
    /// presupposes a nightly toolchain is one nobody can produce any more at
    /// some point.
    #[must_use]
    pub fn parse(output: &str, seeds: &[u64]) -> Self {
        // A map and not a list: the same line can come twice (`cargo test`
        // prints it again in the summary on a failure), and a scenario must not
        // stand twice in the report. The key carries the provenance: two test
        // targets may use the same test name, and they do.
        let mut found: BTreeMap<(String, String), Judgement> = BTreeMap::new();
        let mut suite = String::from("?");

        for line in output.lines() {
            // `cargo` announces every test target before its lines come. The
            // mapping hangs on that — without it the report parser's tests would
            // stand beside the harness's scenarios as if they were the same.
            if let Some(target) = line.trim().strip_prefix("Running ") {
                suite = suite_name(target);
                continue;
            }
            if line.trim().starts_with("Doc-tests") {
                "doc".clone_into(&mut suite);
                continue;
            }

            let Some(rest) = line.strip_prefix("test ") else {
                continue;
            };
            let Some((name, verdict)) = rest.split_once(" ... ") else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }

            // `ok` covers `ok (n ms)` too; only the head counts.
            let judgement = match verdict.split_whitespace().next() {
                Some("ok") => Judgement::Passed,
                Some("FAILED") => Judgement::Failed,
                Some("ignored") => Judgement::Ignored,
                // Everything else is a line that looks like a result and is
                // none. Guessing it would be worse than passing over it.
                _ => continue,
            };

            // A failure prevails: a scenario that was red in one pass is red.
            // The later green entry of the summary must not overwrite it.
            found
                .entry((suite.clone(), name.to_owned()))
                .and_modify(|existing| {
                    if judgement == Judgement::Failed {
                        *existing = Judgement::Failed;
                    }
                })
                .or_insert(judgement);
        }

        Self {
            seeds: seeds.to_vec(),
            scenarios: found
                .into_iter()
                .map(|((suite, name), judgement)| Scenario {
                    suite,
                    name,
                    judgement,
                })
                .collect(),
        }
    }

    /// How many of the checks are **resilience scenarios** per ADR-0019.
    ///
    /// The number an auditor looks for. Everything else checks the harness — per
    /// ADR-0032 rightly so, but it is not the same, and a report that adds both
    /// together claims more than took place.
    #[must_use]
    pub fn resilience_scenarios(&self) -> usize {
        self.scenarios
            .iter()
            .filter(|scenario| scenario.suite == "scenarios")
            .count()
    }

    /// Whether the run stayed without a failure.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self
            .scenarios
            .iter()
            .any(|scenario| scenario.judgement == Judgement::Failed)
    }

    /// The report as a sealed chain — one record per scenario.
    ///
    /// The **first** record names the seeds. It stands in the same chain and not
    /// beside it: whoever swapped the seeds without breaking the chain could
    /// afterwards give a passed run different inputs — and the report would look
    /// unchanged.
    ///
    /// Undated (`None`), and that is the same honesty as with the log export in
    /// 11a: a DST run has no wall clock, it has a **virtual** time (ADR-0033).
    #[must_use]
    pub fn to_segment(&self) -> Segment {
        let mut records = Vec::new();
        let mut previous = GENESIS.to_owned();
        let mut index = 0_u64;

        let seeds: Vec<String> = self.seeds.iter().map(u64::to_string).collect();
        index += 1;
        let record = seal(&previous, index, None, "dst_seeds", &seeds.join(","));
        previous.clone_from(&record.digest);
        records.push(record);

        for scenario in &self.scenarios {
            index += 1;
            let record = seal(
                &previous,
                index,
                None,
                "dst_scenario",
                &format!(
                    "{} {}::{}",
                    scenario.judgement.as_str(),
                    scenario.suite,
                    scenario.name
                ),
            );
            previous.clone_from(&record.digest);
            records.push(record);
        }

        // **The verdict hangs in the chain** (ADR-0045 as the question, here the
        // answer). It is derivable — it could be recomputed from the scenario
        // lines —, but nobody recomputes it, and it is the line an auditor reads
        // first. Standing only beside it, a `failed` changed to `passed` would
        // yield a file with a matching head and a lying headline.
        index += 1;
        let record = seal(
            &previous,
            index,
            None,
            "dst_verdict",
            &format!(
                "{} {} {} {}",
                if self.is_clean() { "passed" } else { "failed" },
                self.resilience_scenarios(),
                self.scenarios.len(),
                self.seeds.len()
            ),
        );
        records.push(record);

        Segment { records }
    }

    /// The segment as JSONL — the same format as the audit archive.
    ///
    /// With that `tgctl audit <file>` checks this report **without** learning a
    /// second procedure (11c: "an auditor learns one procedure and applies it to
    /// both"). A parser of its own for the rendered form would have been the
    /// alternative — and thereby a second reader for a format that already has a
    /// writer.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        self.to_segment()
            .records
            .iter()
            .filter_map(|record: &Record| serde_json::to_string(record).ok())
            .fold(String::new(), |mut out, line| {
                let _ = writeln!(out, "{line}");
                out
            })
    }

    /// The report as text — what an auditor reads.
    ///
    /// Deliberately line by line and not as JSON: the promise "the same seed
    /// produces the same report" is checked most easily with `diff`, and a format
    /// that needs a tool nobody checks by hand.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from("# Tardigrade — DST evidence (ADR-0019, ADR-0020)\n\n");

        out.push_str("## Seeds\n\n");
        for seed in &self.seeds {
            let _ = writeln!(out, "{seed}");
        }

        // Grouped by provenance. `scenarios` are the resilience cases per
        // ADR-0019; `bus` and `faults` check the harness itself — a bus that
        // does not lose when it should feigns correctness (ADR-0032), and that is
        // why they belong in the report. But not in the same line.
        let mut current = "";
        for scenario in &self.scenarios {
            if scenario.suite != current {
                current = &scenario.suite;
                let _ = write!(out, "\n## {current}\n\n");
            }
            let _ = writeln!(out, "{:<8} {}", scenario.judgement.as_str(), scenario.name);
        }

        let segment = self.to_segment();
        let _ = write!(
            out,
            "\n## Verdict\n\n{}\n{} resilience scenarios (ADR-0019), \
             {} checks in total, {} seeds\nHead: {}\n\nThe verdict hangs in the \
             chain; it is recomputed on the segment file beside it \
             (`tgctl audit`).\n",
            if self.is_clean() { "passed" } else { "failed" },
            self.resilience_scenarios(),
            self.scenarios.len(),
            self.seeds.len(),
            segment.head(GENESIS),
        );

        out
    }
}

/// The short name of a test target from `cargo`'s `Running` line.
///
/// `tests/scenarios.rs (target/debug/deps/scenarios-7fc4…)` becomes
/// `scenarios`. The hash does not belong in the report: it changes at every
/// rebuild, and the promise reads "the same seed produces the same report".
fn suite_name(target: &str) -> String {
    let path = target.split_whitespace().next().unwrap_or(target);

    // `unittests src/lib.rs` is the library itself.
    if path.ends_with("src/lib.rs") {
        return "lib".to_owned();
    }

    path.rsplit('/')
        .next()
        .unwrap_or(path)
        .strip_suffix(".rs")
        .unwrap_or(path)
        .to_owned()
}
