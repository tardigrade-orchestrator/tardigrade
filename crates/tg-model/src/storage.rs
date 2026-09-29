//! The volume model (ADR-0027).
//!
//! ADR-0027 does not decide *how* volumes are managed but what there is
//! **not**: no shared writable file system. Everything else follows from that —
//! no oplocking, no coherency, no storage fence, no volume migration.
//!
//! The price is that the rejection has to come **at ingest**. Later there would
//! be nothing left to reject: two processes are writing by then.
//!
//! # The three rules
//!
//! 1. **Writable means exclusive.** A volume one workload writes must not be
//!    named by a second.
//! 2. **Shared means read-only.** If several name it, it is `readOnly`
//!    everywhere.
//! 3. **Writable means node-pinned.** Where the volume lies, the workload runs
//!    — and if the node is gone, it is **not** started elsewhere (see
//!    [`pinned_by_storage`]).
//!
//! # Per instance, not per workload
//!
//! ADR-0027 says: "HA of a stateful workload = replica with its **own** volume
//! … no volume migration." A writable volume therefore belongs to an
//! **instance**; the declared name is the template, the instance number turns
//! it into an identifier ([`volume_of`]). A shared volume, by contrast, is one
//! — multiplying it per instance would mean turning reference data into copies,
//! and the purpose was to share them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use tg_defs::generated::WorkloadType;
use tg_defs::{VolumeExt as _, VolumeMode, WorkloadExt as _};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    SharedWritable {
        volume: String,
        first: String,
        second: String,
    },
    ModeConflict {
        volume: String,
        writable: String,
        readonly: String,
    },
    DuplicatePath {
        workload: String,
        path: String,
    },
    SourceOnWritable {
        workload: String,
        volume: String,
    },
    SharedWithoutSource {
        workload: String,
        volume: String,
    },
    SourceConflict {
        volume: String,
        first: String,
        second: String,
    },
    WritableWithoutSize {
        workload: String,
        volume: String,
    },
    SizeOnShared {
        workload: String,
        volume: String,
    },
    DuplicateName {
        workload: String,
        volume: String,
    },
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedWritable {
                volume,
                first,
                second,
            } => write!(
                f,
                "'{first}' and '{second}' both want to write '{volume}' — a \
                 writable volume belongs to exactly one (ADR-0027)"
            ),
            Self::ModeConflict {
                volume,
                writable,
                readonly,
            } => write!(
                f,
                "'{writable}' writes '{volume}', '{readonly}' reads it — a \
                 shared volume is read-only (ADR-0027)"
            ),
            Self::DuplicatePath { workload, path } => write!(
                f,
                "'{workload}' attaches two volumes to '{path}' — which one wins \
                 would be undetermined"
            ),
            Self::DuplicateName { workload, volume } => {
                write!(f, "'{workload}' names '{volume}' twice")
            }
            Self::SourceOnWritable { workload, volume } => write!(
                f,
                "'{workload}' gives '{volume}' a source although it is written — \
                 what is written is not distributed (ADR-0027)"
            ),
            Self::SharedWithoutSource { workload, volume } => write!(
                f,
                "'{workload}' declares '{volume}' as read-only but names no \
                 source — a shared volume without a provenance would be an \
                 empty one nobody can fill (ADR-0027)"
            ),
            Self::WritableWithoutSize { workload, volume } => write!(
                f,
                "'{workload}' declares '{volume}' as writable but names no size \
                 — a volume without a size cannot be created (ADR-0027)"
            ),
            Self::SizeOnShared { workload, volume } => write!(
                f,
                "'{workload}' gives '{volume}' a size although it is only read \
                 — a shared volume has the size of its content"
            ),
            Self::SourceConflict {
                volume,
                first,
                second,
            } => write!(
                f,
                "'{volume}' comes once from '{first}' and once from '{second}' — \
                 one name, two contents"
            ),
        }
    }
}

impl std::error::Error for StorageError {}

struct Usage<'a> {
    writer: Option<&'a str>,
    reader: Option<&'a str>,
    source: Option<&'a str>,
}

pub fn validate(workloads: &[WorkloadType]) -> Result<(), StorageError> {
    let mut usage: BTreeMap<&str, Usage<'_>> = BTreeMap::new();

    for workload in workloads {
        let name = workload.name();

        let mut paths: BTreeSet<&str> = BTreeSet::new();
        let mut names: BTreeSet<&str> = BTreeSet::new();

        for volume in workload.volumes() {
            if !names.insert(volume.name()) {
                return Err(StorageError::DuplicateName {
                    workload: name.to_owned(),
                    volume: volume.name().to_owned(),
                });
            }
            if !paths.insert(volume.path()) {
                return Err(StorageError::DuplicatePath {
                    workload: name.to_owned(),
                    path: volume.path().to_owned(),
                });
            }

            // Source and mode belong together: what is written is not
            // distributed, and what is distributed has a provenance. XSD 1.0
            // cannot express that (no conditional attributes), so it stands
            // here.
            match (volume.mode(), volume.size()) {
                (VolumeMode::ReadWrite, None) => {
                    return Err(StorageError::WritableWithoutSize {
                        workload: name.to_owned(),
                        volume: volume.name().to_owned(),
                    });
                }
                (VolumeMode::ReadOnly, Some(_)) => {
                    return Err(StorageError::SizeOnShared {
                        workload: name.to_owned(),
                        volume: volume.name().to_owned(),
                    });
                }
                _ => {}
            }

            match (volume.mode(), volume.source()) {
                (VolumeMode::ReadWrite, Some(_)) => {
                    return Err(StorageError::SourceOnWritable {
                        workload: name.to_owned(),
                        volume: volume.name().to_owned(),
                    });
                }
                (VolumeMode::ReadOnly, None) => {
                    return Err(StorageError::SharedWithoutSource {
                        workload: name.to_owned(),
                        volume: volume.name().to_owned(),
                    });
                }
                _ => {}
            }

            let entry = usage.entry(volume.name()).or_insert(Usage {
                writer: None,
                reader: None,
                source: None,
            });

            if let Some(source) = volume.source() {
                match entry.source {
                    Some(first) if first != source => {
                        return Err(StorageError::SourceConflict {
                            volume: volume.name().to_owned(),
                            first: first.to_owned(),
                            second: source.to_owned(),
                        });
                    }
                    _ => entry.source = Some(source),
                }
            }

            match volume.mode() {
                VolumeMode::ReadWrite => {
                    if let Some(first) = entry.writer {
                        return Err(StorageError::SharedWritable {
                            volume: volume.name().to_owned(),
                            first: first.to_owned(),
                            second: name.to_owned(),
                        });
                    }
                    if let Some(readonly) = entry.reader {
                        return Err(StorageError::ModeConflict {
                            volume: volume.name().to_owned(),
                            writable: name.to_owned(),
                            readonly: readonly.to_owned(),
                        });
                    }
                    entry.writer = Some(name);
                }
                VolumeMode::ReadOnly => {
                    if let Some(writable) = entry.writer {
                        return Err(StorageError::ModeConflict {
                            volume: volume.name().to_owned(),
                            writable: writable.to_owned(),
                            readonly: name.to_owned(),
                        });
                    }
                    entry.reader.get_or_insert(name);
                }
            }
        }
    }

    Ok(())
}

#[must_use]
pub fn pinned_by_storage(workload: &WorkloadType) -> bool {
    workload
        .volumes()
        .iter()
        .any(|volume| volume.mode() == VolumeMode::ReadWrite)
}

#[must_use]
pub fn volume_of(declared: &str, mode: VolumeMode, instance: u32) -> String {
    match mode {
        VolumeMode::ReadWrite => format!("{declared}-{instance}"),
        VolumeMode::ReadOnly => declared.to_owned(),
    }
}
