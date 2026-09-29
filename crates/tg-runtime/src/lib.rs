//! The OCI runtime connection, the content store and the image puller.
//!
//! ADR-0003. The way from a definition to a running container:
//!
//! ```text
//!   workload.xml
//!     │  tg_defs::from_path            (ADR-0008)
//!     ▼
//!   WorkloadType ──► state::DesiredState::put   a durable local cache (ADR-0019)
//!     │
//!     ▼
//!   acquire ──► content::ContentStore           locally when possible (policy),
//!     │                                         otherwise image::pull
//!     │
//!     ▼
//!   bundle::build ──► overlayfs + config.json   (tg_syscall::mount)
//!     │                                         the network namespace from the
//!     │                                         seam `network::Wiring` (ADR-0012)
//!     ▼
//!   oci::OciRuntime create/start                youki-first, crun as a fallback
//! ```
//!
//! The agent is thereby **locally authoritative**: everything except the image pull
//! gets by without a network and without a control plane (ADR-0019). A restart
//! reconstructs the desired state solely from [`state::DesiredState`].

#![forbid(unsafe_code)]
// **No panic-capable call in the production path** (ADR-0082): since then a panic
// costs its task and not the node there -- and that is a state an operator sees only
// at a metric. `not(test)`, because the unit tests in `src` need them; the guard lies
// in `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod acquire;
pub mod apply;
pub mod bundle;
pub mod cdi;
pub mod content;
pub mod error;
pub mod image;
pub mod network;
pub mod oci;
pub mod orders;
pub mod reconcile;
pub mod resolved;
pub mod seccomp;
pub mod state;
pub mod userns;
pub mod volume;

use std::path::{Path, PathBuf};

pub use crate::error::RuntimeError;

pub const DEFAULT_DATA_DIR: &str = "/var/lib/tardigrade";

#[derive(Debug, Clone)]
pub struct NodePaths {
    data_dir: PathBuf,
}

impl NodePaths {
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn seal(&self) {
        if !self.data_dir.exists() {
            // Whoever lays it out seals it: `DesiredState::open` and the other
            // openers come right after. Laying one out here merely to close it would
            // mean producing a directory the caller perhaps does not want at all.
            return;
        }

        crate::content::seal_soft(&self.data_dir, "closing the data directory");
    }

    #[must_use]
    pub fn content_dir(&self) -> PathBuf {
        self.data_dir.join("content")
    }

    #[must_use]
    pub fn bundles_dir(&self) -> PathBuf {
        self.data_dir.join("bundles")
    }

    #[must_use]
    pub fn runtime_root(&self) -> PathBuf {
        self.data_dir.join("runtime")
    }

    #[must_use]
    pub fn network_dir(&self) -> PathBuf {
        self.data_dir.join("network")
    }

    #[must_use]
    pub fn slice_applied(&self) -> PathBuf {
        self.network_dir().join("applied")
    }

    #[must_use]
    pub fn tombstones(&self) -> PathBuf {
        self.network_dir().join("tombstones.json")
    }

    #[must_use]
    pub fn snapshot_orders(&self) -> PathBuf {
        self.network_dir().join("snapshots.json")
    }
}

impl Default for NodePaths {
    fn default() -> Self {
        Self::new(DEFAULT_DATA_DIR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_layout_follows_adr_0003() {
        let paths = NodePaths::default();

        assert_eq!(paths.data_dir(), Path::new("/var/lib/tardigrade"));
        assert_eq!(
            paths.content_dir(),
            Path::new("/var/lib/tardigrade/content")
        );
    }

    #[test]
    fn all_paths_stay_under_the_data_dir() {
        let paths = NodePaths::new("/srv/tg");

        for path in [
            paths.content_dir(),
            paths.bundles_dir(),
            paths.runtime_root(),
        ] {
            assert!(
                path.starts_with("/srv/tg"),
                "{} lies outside",
                path.display()
            );
        }
    }
}
