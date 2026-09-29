//! **The XML the operations manual shows is XML this tree accepts.**
//!
//! # Why this exists
//!
//! The manual's `tgctl` calls, switches, metrics, alert names and ADR numbers
//! all have a guard (`crates/tgctl/tests/handbook.rs`). Its definitions did
//! not — and a definition is the one artefact in the manual an operator does
//! not read but **copies**. What it costs when it is wrong is asymmetric:
//! `tgctl` answers an unknown command with a list, while a definition with a
//! misplaced element is refused with a position, and the reader looks for the
//! error in their own file.
//!
//! The occasion is measured. Both stale forms this guard's neighbours missed
//! were argument shapes — `allow-egress` without its transport (ADR-0092),
//! `cluster restart` without its generation. A definition is the same class of
//! rot, one layer deeper: the schema grows (ADR-0142 added `@udp`, ADR-0143
//! the devices), and a block written before the change stays standing.
//!
//! # Why it lives here and not beside the other manual guards
//!
//! Two reasons, and the second decided it:
//!
//! - This crate owns the rules being asserted. Whether a definition holds is
//!   not a question of the schema alone — that a writable volume is exclusive
//!   (ADR-0027), that a single writer without a standby is a lint (ADR-0010),
//!   that a pin excludes replicas (ADR-0011) are statements of the domain.
//! - `tg-model` builds **without** `tg-syscall`. The guard therefore runs on a
//!   developer machine that is not Linux, and a guard one cannot run is one
//!   whose red case nobody has seen.
//!
//! # What is checked, and how strictly
//!
//! A block beginning with `<?xml` is a **complete** definition and is held to
//! everything an apply would hold it to. A block beginning with `<workload` is
//! a **fragment**: it is wrapped into the root element and must parse, and
//! nothing more — its edges may point out of the excerpt, and a graph built
//! over it would report that as an error the manual does not make.
//!
//! A lone element (`<mesh …/>`, `<devices>…`) is skipped. It is an excerpt of
//! a workload, not a document, and there is nothing to parse it into.

use tg_defs::WorkloadExt as _;
use tg_model::DependencyGraph;

/// The manual, read at compile time — a test that looks for a file at run time
/// hangs on the working directory (the same reason as in `handbook.rs`).
const MANUAL: &str = include_str!("../../../docs/OPERATIONS.md");

const ROOT: &str = "<workloads xmlns=\"urn:tardigrade:workload:v1\">";

#[test]
fn every_definition_in_the_manual_is_one_the_cluster_accepts() {
    let mut documents = 0_usize;
    let mut fragments = 0_usize;

    for (at, block) in blocks(MANUAL) {
        let body = dedent(&block);
        let trimmed = body.trim_start();

        if trimmed.starts_with("<?xml") {
            documents += 1;
            check_document(&body, at);
        } else if trimmed.starts_with("<workload") {
            fragments += 1;
            let wrapped = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{ROOT}\n{body}\n</workloads>\n"
            );
            tg_defs::from_str(&wrapped)
                .unwrap_or_else(|err| panic!("the xml excerpt at line {at} does not parse: {err}"));
        }
    }

    // Without these two the test would be green if the reading found nothing —
    // and then it checks nothing. Both kinds exist today; if one disappears,
    // that is a decision and belongs made here, not noticed in a year.
    assert!(documents >= 1, "no complete definition found in the manual");
    assert!(fragments >= 1, "no xml excerpt found in the manual");
}

/// Everything an `apply` would hold the document to, in its order.
///
/// The canonical round trip at the end is not decoration: what reaches the log
/// is the form `workload_to_xml` produces (ADR-0008), not the text somebody
/// wrote. A document that parses and does not survive canonicalization would
/// be one the manual shows and the cluster stores differently.
fn check_document(xml: &str, at: usize) {
    let set = tg_defs::from_str(xml)
        .unwrap_or_else(|err| panic!("the definition at line {at} does not parse: {err}"));

    let graph = DependencyGraph::build(&set)
        .unwrap_or_else(|err| panic!("the definition at line {at} has no usable graph: {err}"));

    let lints = graph.lints();
    assert!(
        lints.is_empty(),
        "the definition at line {at} lints: {lints:?}"
    );

    tg_model::mesh::validate_names(set.workloads())
        .unwrap_or_else(|err| panic!("the definition at line {at}: {err}"));
    tg_model::storage::validate(set.workloads())
        .unwrap_or_else(|err| panic!("the definition at line {at}: {err}"));

    for workload in set.workloads() {
        let name = workload.name();
        tg_model::placement::Demand::from_workload(workload)
            .validate()
            .unwrap_or_else(|err| panic!("the definition at line {at}, '{name}': {err}"));

        let canonical = tg_defs::workload_to_xml(workload)
            .unwrap_or_else(|err| panic!("'{name}' at line {at} canonicalizes not: {err}"));
        tg_defs::from_str(&canonical).unwrap_or_else(|err| {
            panic!("the canonical form of '{name}' at line {at} does not parse: {err}")
        });
    }
}

/// The fenced `xml` blocks, with the line at which each begins.
///
/// The line number is what makes a failure findable: the manual has three
/// thousand of them, and "a definition does not parse" without a place is a
/// message that costs the reader the search this guard was meant to save.
fn blocks(manual: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut lines = manual.lines().enumerate();

    while let Some((at, line)) = lines.next() {
        if line.trim_start() != "```xml" {
            continue;
        }
        let mut body = String::new();
        for (_, inner) in lines.by_ref() {
            if inner.trim_start() == "```" {
                break;
            }
            body.push_str(inner);
            body.push('\n');
        }
        // `at` counts from zero, the reader's editor from one.
        found.push((at + 2, body));
    }

    found
}

/// Take the common indentation off — a block inside a list item carries it,
/// and an XML declaration is only one when nothing stands before it.
fn dedent(block: &str) -> String {
    let indent = block
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);

    block
        .lines()
        .map(|line| line.get(indent..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}
