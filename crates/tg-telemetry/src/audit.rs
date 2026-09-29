//! The audit trail, demonstrably append-only (ADR-0020).
//!
//! ADR-0020 calls the Raft log "append-only, ordered, replicated" and derives
//! tamper evidence from it. That holds **as long as it is replicated**: a
//! change would stand out because four other nodes contradict it.
//!
//! Exported and compacted (phase 5d), nothing of that property is left — the
//! archive is a file, and files can be changed. That is why the export carries
//! its integrity **itself**: a hash chain over the records. That is the open
//! point from ADR-0020, "integrity proof (signature/hash chain over segments)".
//!
//! # What the chain achieves — and what it does not
//!
//! It makes change **detectable**, not impossible. Whoever owns the archive can
//! rewrite it with a valid chain; they then get a different head. The proof
//! therefore consists of two parts, and only both together carry:
//!
//! 1. **The chain checks itself** — altering, removing and reordering stand out
//!    without outside help.
//! 2. **The head is compared** — with the one a running replica keeps, or with
//!    that of the previous segment in the archive.
//!
//! A signature over the head would be the next step and needs the threshold CA
//! from ADR-0014; it is deliberately not anticipated here.
//!
//! # Time
//!
//! The timestamp stands **in** the digest. Moving an event afterwards is
//! thereby the same as altering it — and for an auditor under REMIT that is
//! exactly the interesting question. A timestamp that jumps back is by contrast
//! **no** chain break: clocks are corrected (ADR-0024). It is reported as an
//! [`Anomaly`], not as an error — the one is manipulation, the other a finding.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub index: u64,
    pub at: Option<i64>,
    pub kind: String,
    pub payload: String,
    pub previous: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anomaly {
    TimeWentBackwards {
        index: u64,
        from: i64,
        to: i64,
    },
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimeWentBackwards { index, from, to } => write!(
                f,
                "the clock jumped back at record {index}: from {from} to {to} \
                 (seconds UTC). No chain break — clocks are corrected \
                 (ADR-0024)"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    Altered {
        index: u64,
    },
    Broken {
        index: u64,
    },
    Gap {
        after: u64,
        before: u64,
    },
    WrongAnchor {
        expected: String,
        found: String,
    },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Altered { index } => write!(
                f,
                "record {index} does not match its digest — it was altered"
            ),
            Self::Broken { index } => write!(
                f,
                "record {index} names a predecessor other than the actual one — \
                 the chain is interrupted"
            ),
            Self::Gap { after, before } => {
                write!(f, "records are missing between {after} and {before}")
            }
            Self::WrongAnchor { expected, found } => write!(
                f,
                "the segment begins at '{found}', expected was '{expected}' — \
                 it does not belong here or a segment before it is missing"
            ),
        }
    }
}

impl std::error::Error for AuditError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub head: String,
    pub records: usize,
    pub anomalies: Vec<Anomaly>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Segment {
    pub records: Vec<Record>,
}

impl Segment {
    pub fn verify(&self, anchor: &str) -> Result<Report, AuditError> {
        let mut previous = anchor.to_owned();
        let mut last: Option<&Record> = None;
        let mut last_time: Option<i64> = None;
        let mut anomalies = Vec::new();

        for record in &self.records {
            if record.previous != previous {
                return Err(if last.is_none() {
                    AuditError::WrongAnchor {
                        expected: previous,
                        found: record.previous.clone(),
                    }
                } else {
                    AuditError::Broken {
                        index: record.index,
                    }
                });
            }

            let expected = digest_of(
                &record.previous,
                record.index,
                record.at,
                &record.kind,
                &record.payload,
            );
            if expected != record.digest {
                return Err(AuditError::Altered {
                    index: record.index,
                });
            }

            if let Some(last) = last
                && record.index != last.index + 1
            {
                return Err(AuditError::Gap {
                    after: last.index,
                    before: record.index,
                });
            }

            // Compared against the last **known** time, not against the last
            // record: otherwise a run of undated commands would obscure the
            // view of a jump back that spans them.
            if let (Some(now), Some(before)) = (record.at, last_time)
                && now < before
            {
                anomalies.push(Anomaly::TimeWentBackwards {
                    index: record.index,
                    from: before,
                    to: now,
                });
            }
            if record.at.is_some() {
                last_time = record.at;
            }

            previous.clone_from(&record.digest);
            last = Some(record);
        }

        Ok(Report {
            head: previous,
            records: self.records.len(),
            anomalies,
        })
    }

    #[must_use]
    pub fn head(&self, anchor: &str) -> String {
        self.records
            .last()
            .map_or_else(|| anchor.to_owned(), |record| record.digest.clone())
    }
}

fn digest_of(previous: &str, index: u64, at: Option<i64>, kind: &str, payload: &str) -> String {
    let mut hasher = Sha256::new();

    for field in [previous.as_bytes(), kind.as_bytes(), payload.as_bytes()] {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field);
    }
    hasher.update(index.to_be_bytes());
    match at {
        Some(at) => {
            hasher.update([1u8]);
            hasher.update(at.to_be_bytes());
        }
        None => hasher.update([0u8]),
    }

    hex(&hasher.finalize())
}

#[must_use]
pub fn seal(previous: &str, index: u64, at: Option<i64>, kind: &str, payload: &str) -> Record {
    Record {
        index,
        at,
        kind: kind.to_owned(),
        payload: payload.to_owned(),
        previous: previous.to_owned(),
        digest: digest_of(previous, index, at, kind, payload),
    }
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;

    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

// ---------------------------------------------------------------------------
// The **read path** of an archive on disk (ADR-0134).
//
// It lay in `tg-consensus`, because the writer lies there — and `tgctl audit`
// thereby linked the consensus core in order to recompute a file. The chain
// itself has stood here since phase 11a; the files that carry it belong beside
// it.
//
// What stays in `tg-consensus` is the **writer** (`Archive`) and the **export**
// from the Raft log: the one hangs on the apply path, the other needs
// `openraft` to open the log at all.
// ---------------------------------------------------------------------------

pub fn read(path: &std::path::Path) -> Result<Vec<Record>, ArchiveError> {
    let fail = |detail: String| ArchiveError {
        path: path.to_path_buf(),
        detail,
    };

    let text = std::fs::read_to_string(path).map_err(|err| fail(err.to_string()))?;

    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|err| fail(err.to_string())))
        .collect()
}

pub fn verify(
    path: &std::path::Path,
    records: &[Record],
    anchor: &str,
) -> Result<Report, ArchiveError> {
    let segment = Segment {
        records: records.to_vec(),
    };

    // **`Display` and not `Debug`.** `AuditError` has a sentence for every case
    // — "the segment begins at '…', expected was '…'" —, and this place was the
    // only one at which it would have had a reader: measured, `tgctl audit
    // --anchor quatsch` printed `WrongAnchor { expected: "quatsch", found:
    // "7ab1…" }` instead. The name of a variant is the compiler's language, not
    // an auditor's.
    segment.verify(anchor).map_err(|err| ArchiveError {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })
}

#[must_use]
pub fn sealed_path(base: &std::path::Path, sequence: u64) -> std::path::PathBuf {
    let stem = base
        .file_stem()
        .map_or_else(|| "audit".to_owned(), |s| s.to_string_lossy().into_owned());
    let extension = base
        .extension()
        .map_or_else(|| "jsonl".to_owned(), |e| e.to_string_lossy().into_owned());

    base.with_file_name(format!("{stem}.{sequence:04}.{extension}"))
}

#[must_use]
pub fn sequence_of(base: &std::path::Path, candidate: &std::path::Path) -> Option<u64> {
    let stem = base.file_stem()?.to_string_lossy().into_owned();
    let extension = base.extension()?.to_string_lossy().into_owned();
    let name = candidate.file_name()?.to_string_lossy().into_owned();

    name.strip_prefix(&format!("{stem}."))?
        .strip_suffix(&format!(".{extension}"))?
        .parse()
        .ok()
}

#[must_use]
pub fn sealed(base: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Some(dir) = base.parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut found: Vec<(u64, std::path::PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            sequence_of(base, &path).map(|sequence| (sequence, path))
        })
        .collect();
    found.sort_unstable_by_key(|(sequence, _)| *sequence);

    found.into_iter().map(|(_, path)| path).collect()
}

#[must_use]
pub fn segments(base: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut all = sealed(base);
    if base.exists() {
        all.push(base.to_path_buf());
    }
    all
}

#[must_use]
pub fn footprint(base: &std::path::Path) -> Footprint {
    let sealed = sealed(base);
    let bytes = segments(base)
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok())
        .map(|meta| meta.len())
        .sum();

    Footprint {
        bytes,
        sealed: sealed.len(),
    }
}

pub fn report_footprint(health: &crate::probes::Health, path: std::path::PathBuf) {
    let bytes_at = path.clone();
    health.on_scrape(crate::names::AUDIT_BYTES, move || {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a file size; the imprecision begins at 9 petabytes"
        )]
        let bytes = footprint(&bytes_at).bytes as f64;
        metrics::gauge!(crate::names::AUDIT_BYTES).set(bytes);
    });
    health.on_scrape(crate::names::AUDIT_SEGMENTS, move || {
        #[expect(
            clippy::cast_precision_loss,
            reason = "the number of segments is bounded by the disk"
        )]
        let sealed = footprint(&path).sealed as f64;
        metrics::gauge!(crate::names::AUDIT_SEGMENTS).set(sealed);
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Footprint {
    pub bytes: u64,
    pub sealed: usize,
}

pub fn verify_chain(paths: &[std::path::PathBuf], anchor: &str) -> Result<Chain, ArchiveError> {
    let mut head = anchor.to_owned();
    let mut records = 0_usize;
    let mut last_index: Option<u64> = None;
    let mut anomalies = Vec::new();

    for path in paths {
        let entries = read(path)?;

        if let (Some(previous), Some(first)) = (last_index, entries.first())
            && first.index != previous + 1
        {
            return Err(ArchiveError {
                path: path.clone(),
                detail: format!(
                    "index jump across the seam: {} follows {previous}",
                    first.index
                ),
            });
        }

        let report = verify(path, &entries, &head)?;
        head = report.head;
        records += report.records;
        anomalies.extend(report.anomalies);
        if let Some(last) = entries.last() {
            last_index = Some(last.index);
        }
    }

    Ok(Chain {
        segments: paths.len(),
        records,
        head,
        anomalies,
    })
}

#[derive(Debug, Clone)]
pub struct Chain {
    pub segments: usize,
    pub records: usize,
    pub head: String,
    pub anomalies: Vec<Anomaly>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveError {
    pub path: std::path::PathBuf,
    pub detail: String,
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "audit archive {}: {}",
            self.path.display(),
            self.detail
        )
    }
}

impl std::error::Error for ArchiveError {}
