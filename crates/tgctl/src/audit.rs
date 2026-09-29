//! `tgctl audit` — recomputing the audit archive (ADR-0020).
//!
//! **This subcommand does not need the cluster**, and that is no convenience
//! but the assurance from phase 11a: the chain is built so that it can be
//! checked *from outside* — otherwise the system would certify itself. A
//! checking tool that needed quorum would check nothing an operator cannot
//! switch off.
//!
//! What is read is the file `tgd` writes on the apply path
//! (`<data-dir>/audit-<id>.jsonl`). Nothing is written: the check path
//! expressly does **not** go over `Archive::open`, for that creates the file
//! when it is missing — a typo in the path would otherwise come back as an
//! empty, intact archive.

use std::path::{Path, PathBuf};

use tg_telemetry::audit::GENESIS;

pub(crate) fn verify_chain(base: &Path, anchor: &str) -> Result<(), String> {
    let paths = tg_telemetry::audit::segments(base);
    if paths.is_empty() {
        return Err(format!("no segment beside {}", base.display()));
    }

    let chain = tg_telemetry::audit::verify_chain(&paths, anchor).map_err(|err| err.to_string())?;

    println!("{}", base.display());
    println!("segments:    {}", chain.segments);
    for path in &paths {
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        let count = tg_telemetry::audit::read(path).map_or(0, |records| records.len());
        println!("             {name} ({count})");
    }
    println!("records:     {}", chain.records);
    println!("head:        {}", chain.head);
    println!("anchor:      {anchor}");

    // A second pass for the counting. A checking tool is no hot path, and the
    // alternative would be to repeat the seam logic from `verify_chain` here —
    // that is, a second place at which a security property stands.
    let rejected: usize = paths
        .iter()
        .map(|path| tg_telemetry::audit::read(path).map_or(0, |records| count_rejected(&records)))
        .sum();
    println!("of those refused: {rejected}");

    if chain.anomalies.is_empty() {
        println!("chain: carries");
    } else {
        for anomaly in &chain.anomalies {
            println!("FINDING: {anomaly}");
        }
        return Err(format!("{} finding(s)", chain.anomalies.len()));
    }

    // **Across segments the chain catches more**, and the hint therefore says
    // less than the one for a single segment: only the last one stays
    // truncatable. A segment removed in the middle leaves an index jump and a
    // foreign anchor.
    eprintln!(
        "hint: only the last segment stays truncatable — hold its head against \
         a running replica"
    );

    Ok(())
}

fn count_rejected(records: &[tg_telemetry::audit::Record]) -> usize {
    records
        .iter()
        .filter_map(|record| {
            serde_json::from_str::<tg_model::command::AuditEvent>(&record.payload)
                .ok()
                .and_then(|event| event.outcome)
        })
        .filter(|outcome| outcome.get("rejected").is_some())
        .count()
}

pub(crate) fn verify(path: &Path, anchor: &str) -> Result<(), String> {
    let records = tg_telemetry::audit::read(path).map_err(|err| err.to_string())?;
    let report =
        tg_telemetry::audit::verify(path, &records, anchor).map_err(|err| err.to_string())?;

    println!("{}", path.display());
    println!("records:     {}", report.records);
    println!("head:        {}", report.head);
    println!("anchor:      {anchor}");

    // What is refused stands in the archive too (phase 11a): a futile attempt
    // is exactly the event a checking tool looks for, and it leaves nothing in
    // the state. So the number belongs in the report — and since ADR-0045
    // **without a caveat**: the verdict lies in the sealed payload, a rewrite
    // is a finding.
    println!("of those refused: {}", count_rejected(&records));

    if report.anomalies.is_empty() {
        println!("chain: carries");
    } else {
        for anomaly in &report.anomalies {
            println!("FINDING: {anomaly}");
        }
        return Err(format!(
            "{} finding(s) in {}",
            report.anomalies.len(),
            path.display()
        ));
    }

    // Truncation at the end is not caught by the chain — only the head
    // comparison catches it (phase 11a). The hint stands here because a report
    // that says "carries" and keeps the limit quiet claims more than it shows.
    eprintln!(
        "hint: truncation at the end is not caught by the chain — hold the head \
         against the next segment's anchor or against a running replica"
    );

    Ok(())
}

pub(crate) fn find_archive(data_dir: &Path, id: Option<u64>) -> Result<PathBuf, String> {
    if let Some(id) = id {
        let path = data_dir.join(format!("audit-{id}.jsonl"));
        if !path.exists() {
            return Err(format!("no audit archive under {}", path.display()));
        }
        return Ok(path);
    }

    let mut found = Vec::new();
    let entries = std::fs::read_dir(data_dir)
        .map_err(|err| format!("{} not readable: {err}", data_dir.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(id) = name
            .strip_prefix("audit-")
            .and_then(|rest| rest.strip_suffix(".jsonl"))
            .and_then(|id| id.parse::<u64>().ok())
        {
            found.push(id);
        }
    }
    found.sort_unstable();

    match found.as_slice() {
        [] => Err(format!(
            "no audit archive in {} — has tgd ever run here?",
            data_dir.display()
        )),
        [id] => Ok(data_dir.join(format!("audit-{id}.jsonl"))),
        several => Err(format!(
            "several archives in {}: {} — which one? (--node-id)",
            data_dir.display(),
            several
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

#[must_use]
pub(crate) const fn default_anchor() -> &'static str {
    GENESIS
}

#[cfg(test)]
mod tests {
    use super::{find_archive, verify};
    use tg_telemetry::audit::{GENESIS, seal};

    fn archive(dir: &std::path::Path, count: u64) -> std::path::PathBuf {
        let path = dir.join("audit-1.jsonl");
        let mut previous = GENESIS.to_owned();
        let mut lines = Vec::new();
        for index in 1..=count {
            let payload = format!(r#"{{"node":"tgd-{index}"}}"#);
            let record = seal(&previous, index, None, "invite_node", &payload);
            previous.clone_from(&record.digest);
            lines.push(serde_json::to_string(&record).expect("encodable"));
        }
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write");
        path
    }

    fn lines_of(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .expect("read")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn write_lines(path: &std::path::Path, lines: &[String]) {
        std::fs::write(path, format!("{}\n", lines.join("\n"))).expect("write");
    }

    #[test]
    fn a_sound_archive_verifies_without_a_cluster() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = archive(dir.path(), 3);

        verify(&path, GENESIS).expect("carries");
    }

    #[test]
    fn a_modified_entry_is_a_finding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = archive(dir.path(), 3);

        let mut lines = lines_of(&path);
        lines[1] = lines[1].replace("tgd-2", "tgd-9");
        write_lines(&path, &lines);

        verify(&path, GENESIS).expect_err("altered");
    }

    #[test]
    fn reordering_is_a_finding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = archive(dir.path(), 3);

        let mut lines = lines_of(&path);
        lines.swap(0, 2);
        write_lines(&path, &lines);

        verify(&path, GENESIS).expect_err("reordered");
    }

    #[test]
    fn a_removed_entry_is_a_finding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = archive(dir.path(), 3);

        let mut lines = lines_of(&path);
        lines.remove(1);
        write_lines(&path, &lines);

        verify(&path, GENESIS).expect_err("excised");
    }

    #[test]
    fn a_wrong_anchor_does_not_verify() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = archive(dir.path(), 2);

        verify(&path, &"ab".repeat(32)).expect_err("wrong anchor");
    }

    #[test]
    fn a_missing_archive_is_reported_and_not_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("doesnotexist.jsonl");

        let err = verify(&path, GENESIS).expect_err("missing");

        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(!path.exists(), "the check created the archive");
    }

    #[test]
    fn a_garbage_line_is_an_error_and_not_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = archive(dir.path(), 2);

        let mut lines = lines_of(&path);
        lines.insert(1, "{ this is not JSON".to_owned());
        write_lines(&path, &lines);

        verify(&path, GENESIS).expect_err("broken line");
    }

    #[test]
    fn an_emptied_archive_verifies_to_its_anchor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = archive(dir.path(), 3);
        std::fs::write(&path, "").expect("empty it");

        verify(&path, GENESIS).expect("empty carries to the anchor");
    }

    #[test]
    fn an_explicit_id_is_taken_and_a_missing_archive_is_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _ = archive(dir.path(), 1);

        let found = find_archive(dir.path(), Some(1)).expect("archive 1");
        assert!(found.ends_with("audit-1.jsonl"), "{found:?}");

        let err = find_archive(dir.path(), Some(4)).expect_err("archive 4 is missing");
        assert!(err.contains("audit-4.jsonl"), "{err}");
    }

    #[test]
    fn discovery_takes_one_names_many_and_reports_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = find_archive(dir.path(), None).expect_err("none");
        assert!(err.contains(&dir.path().display().to_string()), "{err}");

        let _ = archive(dir.path(), 1);
        assert!(
            find_archive(dir.path(), None)
                .expect("one")
                .ends_with("audit-1.jsonl")
        );

        std::fs::write(dir.path().join("audit-2.jsonl"), "").expect("a second one");
        let err = find_archive(dir.path(), None).expect_err("several");
        assert!(err.contains("1, 2"), "{err}");
        assert!(err.contains("--node-id"), "{err}");
    }

    #[test]
    fn near_misses_are_not_archives() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in [
            "audit-.jsonl",
            "audit-x.jsonl",
            "audit-1.jsonl.bak",
            "admin-1.sock",
            "audit-1",
        ] {
            std::fs::write(dir.path().join(name), "").expect("file");
        }
        std::fs::write(dir.path().join("audit-8.jsonl"), "").expect("file");

        let found = find_archive(dir.path(), None).expect("only one");
        assert!(found.ends_with("audit-8.jsonl"), "{found:?}");
    }
}
