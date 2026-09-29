//! The agent's workload API socket (ADR-0006, ADR-0035).
//!
//! A Unix domain socket that is mounted into the container. Whoever asks at it gets
//! its SVID, its key and the trust bundle -- **if** it can prove who it is.
//!
//! # The proof is the connection itself
//!
//! The caller does not give its identity; it could lie. Instead the agent reads the
//! **connection's** credentials (set by the kernel), asks their `pidfd` for the PID
//! (`SO_PEERPIDFD`, ADR-0053) and looks up in `/proc/<pid>/cgroup` which container
//! the process runs in. Only from that follows the SPIFFE ID.
//!
//! Then comes the second question, and it is the more important one: may **this
//! node** mint for this workload? Only if the workload is assigned to it (ADR-0006,
//! authority binding).
//!
//! That has held since 7a and survived the rebuild onto gRPC -- it **must** survive
//! it, for it is the only place in the rebuild with security weight. The credentials
//! hang on the **connection**, not on the protocol above it; they travel as
//! [`PeerCredentials`] through `tonic`'s connection information into every single
//! call.
//!
//! # The protocol is the standard
//!
//! What goes over the socket is the SPIFFE specification's gRPC service
//! `SpiffeWorkloadAPI` -- the same surface `go-spiffe`, `java-spiffe`, `py-spiffe`
//! and `rust-spiffe` speak. **ADR-0035** justifies the choice and clears away the
//! objection that stood against it until then: the feared second tool chain does not
//! arise, because `protox` compiles without `protoc` and the product is checked in.
//!
//! Until 7b the socket spoke a line-based JSON protocol of its own. It has been
//! **dropped without replacement**, not put beside: two surfaces onto the same state
//! would be two ways on which an SVID goes out, and thereby two places at which the
//! attestation must be right.
//!
//! # What is implemented is the X.509 profile
//!
//! `FetchX509SVID` and `FetchX509Bundles`. The three JWT methods answer
//! `UNIMPLEMENTED` with a reference to ADR-0025, where JWT-SVID is expressly
//! deferred as option C. A method that does not exist shall say so.

pub mod pb;
mod service;

use std::path::{Path, PathBuf};

pub use crate::workload_api::service::{
    Clock, HINT_DELEGATED, HINT_SELF, PeerCredentials, PeerStream, SystemClock, WorkloadApi,
    incoming, incoming_for, serve, serve_on,
};

/// The socket's path below the data directory.
///
/// It lies in the agent's data directory and is mounted from there into the
/// container -- a socket at a fixed place in the host's file system would be
/// reachable for every process that finds it.
#[must_use]
pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join("workload-api.sock")
}
