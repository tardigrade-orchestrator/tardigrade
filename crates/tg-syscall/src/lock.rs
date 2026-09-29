//! The lock on a data directory (ADR-0043).
//!
//! ADR-0043 names one data directory **per node** as a prerequisite. `tgd` gets
//! it for free: `redb` takes an exclusive lock on the Raft store. The agent has
//! no database.
//!
//! **`flock` and not a PID file.** A PID file outlives the process that wrote
//! it: after a `kill -9` it would stay behind and the restart would no longer
//! come up — the opposite of what it is meant to provide. The kernel releases a
//! `flock` as soon as the last descriptor drops, no matter **how** the process
//! ends. The file stays behind, empty; the lock hangs on the **descriptor**, not
//! on the path.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};

#[derive(Debug)]
pub enum LockError {
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    Held {
        directory: PathBuf,
    },
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(f, "lock file {} not usable: {source}", path.display())
            }
            Self::Held { directory } => write!(
                f,
                "the data directory {} is held by another process — \
                 exactly one per node (ADR-0043)",
                directory.display()
            ),
        }
    }
}

impl std::error::Error for LockError {}

#[derive(Debug)]
pub struct DirectoryLock {
    #[expect(
        dead_code,
        reason = "the descriptor holds the lock; there is no reason to read it"
    )]
    file: File,
}

pub fn hold(directory: &Path, name: &str) -> Result<DirectoryLock, LockError> {
    let path = directory.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| LockError::Open {
            path: path.clone(),
            source,
        })?;
    }

    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|source| LockError::Open {
            path: path.clone(),
            source,
        })?;

    flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| LockError::Held {
        directory: directory.to_path_buf(),
    })?;

    Ok(DirectoryLock { file })
}
