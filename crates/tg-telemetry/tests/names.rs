//! The metric names and their alert rules.
//!
//! A rule on a metric nobody sets fires **never**. This file holds the one
//! assurance that finds that — checked against `docs/alerts.yml` and against
//! the whole tree's test code.

/// **Every metric with an alert rule has a witness.**
///
/// A rule on a metric nobody sets fires **never** — and that is the silent kind
/// of failure this tree has already measured three times at `docs/alerts.yml`:
/// truncated names, `histogram_quantile` on a summary, and a vector pairing
/// without `on()`. All three looked perfectly proper.
///
/// Searched for is the **constant**, not the literal: the witnesses name
/// `names::LEASE_CLOCK_SKEW`, not `"tg_lease_clock_skew_seconds"`. An
/// instrument that knows only one of the two spellings reported **29 of 57** on
/// the first measurement — it was five.
///
/// What it **cannot** do stands here: it checks the mention, not that the
/// witness asserts something sensible. And the reverse direction is no
/// assurance — not every metric needs a rule (four stand with their reason at
/// the end of `alerts.yml`).
#[test]
fn every_alerted_metric_has_a_witness() {
    let names = include_str!("../src/names.rs");
    let alerts = std::fs::read_to_string("../../docs/alerts.yml").expect("alerts.yml");

    // Literal -> constant, from `names.rs` itself.
    let mut by_literal = std::collections::BTreeMap::new();
    for line in names.lines() {
        let Some(rest) = line.trim().strip_prefix("pub const ") else {
            continue;
        };
        let Some((constant, tail)) = rest.split_once(": &str = \"") else {
            continue;
        };
        let Some((literal, _)) = tail.split_once('"') else {
            continue;
        };
        by_literal.insert(literal.to_owned(), constant.to_owned());
    }
    assert!(
        by_literal.len() > 40,
        "only {} metric names read -- then the guard checks nothing",
        by_literal.len()
    );

    // Haystack: all test files and all test modules under `src`.
    let mut hay = String::new();
    for crate_dir in std::fs::read_dir("../").expect("crates readable") {
        let root = crate_dir.expect("entry").path();
        collect(&root.join("tests"), &mut hay);
        if let Ok(entries) = std::fs::read_dir(root.join("src")) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "rs")
                    && let Ok(text) = std::fs::read_to_string(&path)
                    && let Some(index) = text.find("#[cfg(test)]")
                {
                    hay.push_str(&text[index..]);
                }
            }
        }
    }
    assert!(
        hay.len() > 100_000,
        "only {} characters of test code read -- then the guard checks nothing",
        hay.len()
    );

    // The rules name only `expr` lines; the list of reasons at the end of the
    // file stands in comments and does not count.
    let mut missing = Vec::new();
    for line in alerts.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.starts_with("expr:") {
            continue;
        }
        for word in line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            if !word.starts_with("tg_") {
                continue;
            }
            let Some(constant) = by_literal.get(word) else {
                continue;
            };
            if !hay.contains(constant.as_str()) && !hay.contains(word) {
                missing.push(format!("{word} ({constant})"));
            }
        }
    }
    missing.sort_unstable();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "metrics with an alert rule and without a witness: {missing:?}"
    );
}

/// Collects all `.rs` files under `dir` recursively.
fn collect(dir: &std::path::Path, into: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            into.push_str(&text);
        }
    }
}
