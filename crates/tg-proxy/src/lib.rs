//! mTLS sidecar with rustls and a SPIFFE verifier.
//!
//! The sidecar terminates incoming mTLS and initiates outgoing. What it
//! decides in the process falls into two questions one must not mix:
//!
//! - **Who is the peer?** That is answered by the certificate chain and the
//!   SPIFFE ID in the URI SAN -- authentication.
//! - **May they?** That is answered by the `may_talk` edge -- authorization.
//!   It is deny-by-default, lies locally and is enforced locally.
//!
//! Both answers are built as pure logic in [`policy`] and [`verify`], kept
//! separate from the running process in the other modules -- a verifier that
//! is only checked by the end-to-end setup is one whose rejection paths
//! nobody has ever seen.

#![forbid(unsafe_code)]
// **No panic-capable call in the production path**: there a panic costs its
// task and not the node -- and that is a state an operator sees only at a
// metric. `not(test)`, because the unit tests in `src` need them; the guard
// lies in `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub mod datagram;
pub mod egress;
pub mod identity;
pub mod options;
pub mod policy;
pub mod quic;
pub mod quic_egress;
pub mod role;
pub mod runtime;
pub mod selector;
pub mod sidecar;
pub mod tls;
pub mod verify;

pub use crate::identity::{Identity, IdentityError};
pub use crate::options::{Options, OptionsError, edges_from_text};
pub use crate::policy::{
    Decision, DenyReason, Direction, Established, PolicyCache, PolicyError, Review,
    RevocationWindow, Snapshot,
};
pub use crate::runtime::{Shards, allowed_cores, available_shards, reuseport_listener};
pub use crate::selector::{Selector, SelectorError};
pub use crate::sidecar::{Config, Route, SidecarError, serve_inbound, serve_outbound};
pub use crate::verify::{Bundle, Enforcement, PeerVerifier, SharedPolicy, VerifyError};
