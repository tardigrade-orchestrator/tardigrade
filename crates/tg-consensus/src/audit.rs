//! The export of the Raft log as an audit segment (ADR-0020).
//!
//! ADR-0020 makes the Raft log the **WORM substrate**: it is only appended to,
//! never changed, and every node holds the same sequence. With that the audit
//! trail is already structurally there — as long as it lies in the cluster.
//!
//! What it loses when leaving the cluster is exactly this property. A file in
//! the archive is a file; it does not become immutable by having come from an
//! immutable log. This module closes the gap: it seals the entries into a hash
//! chain ([`tg_telemetry::audit`]) that can be checked **outside** the cluster
//! and without the cluster.
//!
//! Four determinations that are not obvious:
//!
//! - **The index is the ordering, not the clock.** The log index is
//!   consensus-backed and without gaps; it is the strongest ordering argument
//!   this system has. A wall clock it is not.
//! - **What is undated stays undated.** Of the twenty commands five carry an
//!   `at`. The export takes it where it stands and inserts nothing otherwise —
//!   the export time would be a statement about the export, not about the
//!   event.
//! - **Only `normal` entries.** `openraft` also puts membership changes and
//!   empty entries (a leader taking office) into the same log. They are
//!   consensus mechanics, not a domain event, and would fill an audit report
//!   with noise. Their index nevertheless stays visible: the segment then has a
//!   gap at that place, and `verify` says so — that is why the export numbers
//!   **consecutively** anew and records the log index in the payload.
//! - **The verdict lies in the payload** (ADR-0045). Until then it stood
//!   *beside* the record and thereby not in the digest: a rejection could be
//!   rewritten in the archive to `"applied"`, and the chain went on saying
//!   "carries". Forgeable was thus exactly the part for whose sake 11a archives
//!   what is rejected at all. The payload is therefore "what happened at this
//!   index", not "which command came" — the command in it is still byte for
//!   byte the one from the log (ADR-0020).

use openraft::{EntryPayload, RaftLogReader as _};
use serde::Serialize;
use tg_telemetry::audit::{GENESIS, Record, Segment, seal};

pub use tg_telemetry::audit::{
    ArchiveError, Chain, Footprint, footprint, read, report_footprint, sealed, sealed_path,
    segments, sequence_of, verify, verify_chain,
};

use crate::command::Submission;
use crate::store::LogReader;
use crate::wire;

pub use tg_model::command::AuditEvent as Event;

#[derive(Debug)]
pub enum ExportError {
    Unreadable(String),
    Unencodable(String),
    Unopenable(String),
    Purged {
        from: u64,
        purged: u64,
    },
    EmptyRange {
        from: u64,
        to: u64,
        last: u64,
    },
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(detail) => write!(out, "the log is unreadable: {detail}"),
            Self::Unencodable(detail) => write!(out, "the entry is not encodable: {detail}"),
            Self::Unopenable(detail) => write!(
                out,
                "the log cannot be opened: {detail}\n\nhint: `redb` lets exactly \
                 one process at the log. Is tgd still running?"
            ),
            Self::Purged { from, purged } => write!(
                out,
                "the range begins at {from}, but everything up to {purged} is \
                 deleted — it can no longer be exported from the log \
                 (ADR-0020).\n\nhint: without `--from` the export begins at \
                 {}, that is, at what is still there. What lies before that \
                 stands in the archive written in the apply.",
                purged.saturating_add(1)
            ),
            Self::EmptyRange { from, to, last } => {
                write!(out, "empty range [{from}, {to}) — the log ends at {last}")
            }
        }
    }
}

impl std::error::Error for ExportError {}

#[derive(Debug)]
pub struct Export {
    pub segment: tg_telemetry::audit::Segment,
    pub from: u64,
    pub to: u64,
    pub last: u64,
}

pub async fn export_range(
    path: impl AsRef<std::path::Path>,
    from: Option<u64>,
    to: Option<u64>,
    anchor: &str,
) -> Result<Export, ExportError> {
    use openraft::storage::RaftLogStorage as _;

    let mut storage = crate::Storage::open(path.as_ref())
        .map_err(|err| ExportError::Unopenable(err.to_string()))?;
    // `get_log_state` belongs to the storage, `try_get_log_entries` to the
    // reader — hence first the state, then the reader.
    let state = storage
        .log
        .get_log_state()
        .await
        .map_err(|err| ExportError::Unreadable(err.to_string()))?;
    let last = state.last_log_id.map_or(0, |id| id.index);
    let mut reader = storage.log.get_log_reader().await;

    // **The default is "everything that is still there"** and not 1: what the
    // compaction cleared away lies in the archive (11a) and no longer in the
    // log. An explicit setting below it is by contrast **refused** -- the reason
    // stands at `ExportError::Purged`.
    let purged = state.last_purged_log_id.map_or(0, |id| id.index);
    let from = match from {
        Some(from) if from <= purged => return Err(ExportError::Purged { from, purged }),
        Some(from) => from,
        None => purged.saturating_add(1),
    };
    let to = to.unwrap_or_else(|| last.saturating_add(1));
    if to <= from {
        return Err(ExportError::EmptyRange { from, to, last });
    }

    let segment = export(&mut reader, from, to, anchor).await?;

    Ok(Export {
        segment,
        from,
        to,
        last,
    })
}

pub async fn export(
    reader: &mut LogReader,
    from: u64,
    to: u64,
    anchor: &str,
) -> Result<Segment, ExportError> {
    let entries = reader
        .try_get_log_entries(from..to)
        .await
        .map_err(|err| ExportError::Unreadable(err.to_string()))?;

    let mut records: Vec<Record> = Vec::new();
    let mut previous = anchor.to_owned();
    let mut index = 0_u64;

    for entry in entries {
        let EntryPayload::Normal(submission) = entry.payload else {
            continue;
        };

        let json = wire::encode_command(&submission.command)
            .map_err(|err| ExportError::Unencodable(err.to_string()))?;
        let value: serde_json::Value =
            serde_json::from_str(&json).map_err(|err| ExportError::Unencodable(err.to_string()))?;

        let at = timestamp_of(&value);
        let event = Event {
            log_index: entry.log_id.index,
            term: entry.log_id.leader_id.term,
            command: value,
            // The log knows no verdict (ADR-0004), and the export inserts
            // none — the same honesty as at the missing time.
            outcome: None,
            // The actor, by contrast, the log does know (ADR-0050).
            actor: submission.actor.clone(),
        };
        let payload = serde_json::to_string(&event)
            .map_err(|err| ExportError::Unencodable(err.to_string()))?;

        index += 1;
        let record = seal(&previous, index, at, submission.command.kind(), &payload);
        previous.clone_from(&record.digest);
        records.push(record);
    }

    Ok(Segment { records })
}

fn timestamp_of(command: &serde_json::Value) -> Option<i64> {
    let fields = command.as_object()?.values().next()?.as_object()?;

    fields
        .get("at")
        .or_else(|| fields.get("now"))
        .and_then(serde_json::Value::as_i64)
}

pub struct Archive {
    file: std::io::BufWriter<std::fs::File>,
    path: std::path::PathBuf,
    head: String,
    records: u64,
    in_file: u64,
    rotate_at: Option<u64>,
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("Archive")
            .field("head", &self.head)
            .field("records", &self.records)
            .field("in_file", &self.in_file)
            .finish_non_exhaustive()
    }
}

pub const DEFAULT_ROTATE_AT: u64 = 100_000;

impl Archive {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, ArchiveError> {
        Self::open_with(path, Some(DEFAULT_ROTATE_AT))
    }

    pub fn open_with(
        path: impl AsRef<std::path::Path>,
        rotate_at: Option<u64>,
    ) -> Result<Self, ArchiveError> {
        use std::io::Write as _;

        let path = path.as_ref();
        let fail = |detail: String| ArchiveError {
            path: path.to_path_buf(),
            detail,
        };

        // The running file's anchor is the head of the last closed segment —
        // or GENESIS if there is none.
        let (mut head, mut records) = (GENESIS.to_owned(), 0_u64);
        if let Some(last) = sealed(path).last() {
            let entries = read(last)?;
            // Against its own anchor: that stands in the first record. With
            // that every change **inside** the segment stands out. That the
            // anchor itself is right is said only by the whole chain.
            let anchor = entries
                .first()
                .map_or_else(|| GENESIS.to_owned(), |first| first.previous.clone());
            let report = verify(last, &entries, &anchor)?;
            head = report.head;
            records = entries.last().map_or(0, |record| record.index);
        }

        if path.exists() {
            let entries = read(path)?;
            let report = verify(path, &entries, &head)?;
            head = report.head;
            // The **last index**, not the count: with a second segment those
            // are two different numbers, and the count would let the index jump
            // back.
            if let Some(last) = entries.last() {
                records = last.index;
            }
        }

        let in_file = if path.exists() {
            u64::try_from(read(path)?.len()).unwrap_or(u64::MAX)
        } else {
            0
        };

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|err| fail(err.to_string()))?;
        file.flush().map_err(|err| fail(err.to_string()))?;

        Ok(Self {
            file: std::io::BufWriter::new(file),
            path: path.to_path_buf(),
            head,
            records,
            in_file,
            rotate_at,
        })
    }

    fn rotate(&mut self) -> Result<(), ArchiveError> {
        use std::io::Write as _;

        let fail = |detail: String| ArchiveError {
            path: self.path.clone(),
            detail,
        };

        self.file.flush().map_err(|err| fail(err.to_string()))?;

        let next = sealed(&self.path)
            .last()
            .and_then(|last| sequence_of(&self.path, last))
            .unwrap_or(0)
            + 1;
        let target = sealed_path(&self.path, next);
        std::fs::rename(&self.path, &target).map_err(|err| fail(err.to_string()))?;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|err| fail(err.to_string()))?;
        self.file = std::io::BufWriter::new(file);
        self.in_file = 0;

        Ok(())
    }

    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }

    #[must_use]
    pub const fn records(&self) -> u64 {
        self.records
    }

    pub fn record<O: Serialize>(
        &mut self,
        log_index: u64,
        term: u64,
        submission: &Submission,
        outcome: &O,
    ) -> Result<(), ArchiveError> {
        use std::io::Write as _;

        let fail = |detail: String| ArchiveError {
            path: std::path::PathBuf::new(),
            detail,
        };

        // **Rotation happens before the write**, not after: otherwise the
        // record that breaks the bound would still lie in the old segment, and
        // an operator waiting for "exactly N" would find N+1.
        if let Some(limit) = self.rotate_at
            && self.in_file >= limit
        {
            self.rotate()?;
        }

        let json =
            wire::encode_command(&submission.command).map_err(|err| fail(err.to_string()))?;
        let value: serde_json::Value =
            serde_json::from_str(&json).map_err(|err| fail(err.to_string()))?;
        let at = timestamp_of(&value);
        let event = Event {
            log_index,
            term,
            command: value,
            outcome: Some(serde_json::to_value(outcome).map_err(|err| fail(err.to_string()))?),
            actor: submission.actor.clone(),
        };
        let payload = serde_json::to_string(&event).map_err(|err| fail(err.to_string()))?;

        self.records += 1;
        let record = seal(
            &self.head,
            self.records,
            at,
            submission.command.kind(),
            &payload,
        );
        self.head.clone_from(&record.digest);

        let text = serde_json::to_string(&record).map_err(|err| fail(err.to_string()))?;

        self.in_file += 1;
        writeln!(self.file, "{text}").map_err(|err| fail(err.to_string()))?;
        // Only after the flush is the record a record. Without it it would
        // stand in the buffer while `apply` has already returned — and a power
        // failure would decide whether it existed.
        self.file.flush().map_err(|err| fail(err.to_string()))?;

        Ok(())
    }
}
