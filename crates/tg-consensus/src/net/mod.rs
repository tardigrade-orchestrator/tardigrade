//! The Raft transport over gRPC (ADR-0002, phase 5c).
//!
//! The same trait level as the DST's bus from phase 5b — only with a wire in
//! between. That is the order from ADR-0005: the test rig first, the real
//! network afterwards. What is proven here is **integration**; the correctness
//! comes from 5b.
//!
//! # Security: the port demands a client certificate (ADR-0043)
//!
//! Whoever reaches it can cast votes and append entries — they **are**
//! consensus. That is why it demands a credential and checks the **key** in it
//! against the local peer list (`<data-dir>/peers/<id>.pem`), not the chain
//! against a CA: the CA hangs on the leader and the leader on this port, a
//! check against it would be a circle.
//!
//! `--listen` still binds to **loopback** by default. The difference is that it
//! now **can** safely be bound more widely; a cluster across several machines
//! nevertheless demands an explicit setting — and thereby a deliberate decision
//! by whoever takes it.
//!
//! # Two sentences that stood here and were wrong
//!
//! They are classified here and not merely deleted, because the second was
//! logged as withdrawn **twice** and stayed standing twice — in the commit for
//! ADR-0043 and in `plans/PLAN.md`. Only a search for claims about absence
//! found it.
//!
//! - *"This port is not authenticated."* Right until ADR-0043, not afterwards.
//!   A reader would have concluded that they had to hide the port — and would
//!   have taken a failed check for an error.
//! - *"After phase 9 the Raft traffic runs over an authenticated, encrypted
//!   underlay."* **Measured wrong**: a peer's `AllowedIPs` are exactly its
//!   container subnet, and `ensure_wireguard_link` gives the interface **no
//!   address of its own** — there was no route on which management traffic took
//!   the tunnel. Whether it should go in *additionally* is the open question
//!   from ADR-0043 (see `tg_agent::underlay`).

mod client;
mod codec;
mod server;

pub use crate::net::client::{GrpcNetwork, Link, PeerAddrs, PeerDialer};
pub use crate::net::codec::{JsonCodec, from_bytes, to_bytes};
pub use crate::net::server::RaftService;

/// The service name in the gRPC path.
pub const RAFT_SERVICE: &str = "tardigrade.raft.v1.Raft";

/// The replication path.
pub const APPEND_ENTRIES: &str = "/tardigrade.raft.v1.Raft/AppendEntries";
/// The vote request path.
pub const VOTE: &str = "/tardigrade.raft.v1.Raft/Vote";
/// The snapshot transfer path.
pub const INSTALL_SNAPSHOT: &str = "/tardigrade.raft.v1.Raft/InstallSnapshot";
