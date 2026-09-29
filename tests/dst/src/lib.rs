//! Harness for the consensus: five nodes, one process, injected faults.
//!
//! ADR-0032 decided against `turmoil` and `madsim` and for a bus of our own: "a
//! simulation framework simulates the network layer beneath — which does not
//! exist in the DST at all, because there all nodes run in one process." What
//! stands here acts exactly at the level at which `openraft` hands over its
//! messages: [`RaftNetwork`](openraft::RaftNetwork).
//!
//! **The three sources of determinism:**
//!
//! 1. **The fault plan** ([`Faults`]) is a pure function of seed, path and
//!    message number. No shared generator, no dependence on the task order.
//! 2. **Time** is virtual (`tokio::time::pause`). An election with a 300 ms
//!    timeout costs no 300 ms of wall clock, and two runs see the same points in
//!    time.
//! 3. **The election timeouts** are fixed per node instead of rolled.
//!    `openraft` draws them from `AsyncRuntime::thread_rng()`, i.e. from
//!    `rand::thread_rng()` — unseeded. With `election_timeout_max = min + 1` the
//!    drawn value is fixed; the offset between the nodes comes from [`Cluster`].
//!
//! **What the harness cannot do:** `tokio`'s virtual clock is **global**. A
//! monotonic clock offset per node is therefore not representable. Clock skew is
//! simulated where ADR-0024 locates it — in the traceable UTC that travels **in
//! the command** — and approximated on the monotonic side by offset election
//! timeouts and asymmetric latencies. The limit stands here expressly, so that a
//! green run does not claim more than it checked.

#![forbid(unsafe_code)]

mod bus;
mod cluster;
mod faults;
mod trace;

pub mod evidence;

pub use crate::bus::{Bus, BusFactory, Link};
pub use crate::cluster::{Cluster, ClusterError, ELECTION_BASE_MS, HEARTBEAT_MS, Setup};
pub use crate::faults::{Faults, Verdict};
pub use crate::trace::{Event, Kind, Outcome, Trace};

/// The seeds a scenario runs over.
///
/// **Fixed, not fresh** — unlike the fuzz runs in `tg-defs` and `tg-consensus`.
/// A DST run is a regression probe: it has to be green again tomorrow and, if it
/// turns red, stay red from the same seed (ADR-0020: exportable evidence). A
/// fresh seed per run would make a failure disappear at the next attempt.
///
/// `TG_DST_SEED` pins a single seed — the way to reproduce a reported failure.
/// `TG_DST_SEEDS` widens the sweep; that is what `cargo xtask dst` does.
#[must_use]
pub fn seeds() -> Vec<u64> {
    if let Some(single) = std::env::var("TG_DST_SEED")
        .ok()
        .and_then(|raw| raw.parse().ok())
    {
        return vec![single];
    }

    let count: u64 = std::env::var("TG_DST_SEEDS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(2);

    (0..count.max(1))
        .map(|index| 0x5EED_0000_0000_0000 ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15))
        .collect()
}
