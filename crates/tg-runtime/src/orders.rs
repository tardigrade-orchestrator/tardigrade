//! The orders the slice leaves behind.
//!
//! Two executions of this system touch the **kernel**: a deletion calls `losetup`, a
//! snapshot freezes a file system and copies a whole image. Both used to run directly
//! in the session's arm that receives slices -- and a `tokio::select!` polls exactly
//! one arm at a time.
//!
//! Measured, that halted the neighbouring arm for the whole duration (a 50 ms ticker,
//! a 1000 ms blockage: a gap of 1000 ms). A stalled report means the node drops out of
//! `reporting` after `REPORT_WINDOW_SECONDS`, the leader then skips the lease renewal,
//! and after `LEASE_SECONDS` every single writer fences itself. A **healthy** node lost
//! its active roles because it copied a volume.
//!
//! That is why the session only writes what is to be done, and the reconciler does
//! it. It is the strand that **may** block: it has a watchdog, its readiness is
//! visible, and a failure there is designed to cost its workload and not the node.
//!
//! Both orders are **level-triggered** and can therefore be deferred without loss: a
//! tombstone lives until it is executed, and a snapshot compares a marker against what
//! is already laid out.

use crate::NodePaths;
use crate::volume::{Confirmation, VolumeError, VolumeStore};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Orders {
    pub tombstones: Vec<String>,
    pub snapshots: Vec<(String, u64)>,
}

impl Orders {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tombstones.is_empty() && self.snapshots.is_empty()
    }
}

#[must_use]
pub fn read(paths: &NodePaths) -> Orders {
    Orders {
        tombstones: list(&paths.tombstones(), "the tombstones"),
        snapshots: list(&paths.snapshot_orders(), "the snapshot decrees"),
    }
}

fn list<T: serde::de::DeserializeOwned>(path: &std::path::Path, what: &str) -> Vec<T> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        // No file means no instruction -- that is the normal case.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                %err,
                "{what} are not readable -- what is decreed here is not executed"
            );
            return Vec::new();
        }
    };

    match serde_json::from_str(&text) {
        Ok(list) => list,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                %err,
                "{what} cannot be interpreted -- what is decreed here is not executed"
            );
            Vec::new()
        }
    }
}

pub fn execute(paths: &NodePaths, keep: usize, orders: &Orders) {
    if orders.is_empty() {
        return;
    }

    let store = match VolumeStore::open(paths.data_dir()) {
        Ok(store) => store,
        Err(err) => {
            tracing::warn!(
                %err,
                "the volume store cannot be opened -- neither deleted nor snapshotted"
            );
            return;
        }
    };

    for volume in &orders.tombstones {
        let confirmation = Confirmation::of(volume);
        match store.delete(volume, &confirmation) {
            Ok(()) => tracing::info!(%volume, "the volume was deleted (ADR-0027)"),
            // A tombstone for a volume that never existed here is done -- not failed.
            // The instruction reads "this volume shall no longer be here".
            Err(VolumeError::Unknown { .. }) => {}
            Err(err) => tracing::warn!(%volume, %err, "the volume was not deleted"),
        }
    }

    for (volume, generation) in &orders.snapshots {
        // The marker says what is there already. Without it every pass would lay
        // the same snapshot out anew.
        if *generation <= store.snapshot_mark(volume) {
            continue;
        }

        match store.snapshot(volume, *generation, keep) {
            Ok(snap) => tracing::info!(
                %volume,
                generation = snap.generation,
                bytes = snap.bytes,
                "the snapshot was laid out (ADR-0099)"
            ),
            Err(err) => tracing::warn!(
                %volume,
                generation = *generation,
                %err,
                "the snapshot was not laid out"
            ),
        }
    }
}
