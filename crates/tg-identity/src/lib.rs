//! SPIFFE identity: IDs, time windows, attestation.
//!
//! What stands here is the **pure** half of the SVID path: no clock, no network, no
//! disk -- only derivations and comparisons. The time comes in as a parameter, so
//! that a test can set it and two nodes give the same answer.
//!
//! # Three things, and why they stand together here
//!
//! - [`SpiffeId`] -- **derived, not assigned.** Nobody maintains the mapping "which
//!   ID belongs to which workload" by hand, it follows from the desired state. With
//!   that it is the same on every node, and a registration record that could drift
//!   does not exist at all.
//! - [`Lifetime`] and [`Validity`] -- the lifetime metrics together with their
//!   ordering conditions. The soft-fail grace is here a property of the
//!   **holder**, not of the certificate; see [`Validity`].
//! - [`Attestation`] -- who asks, and may they. Two questions, not one: the cgroup
//!   path says **which** container asks; the node's assignment says whether this
//!   node may mint for it.
//!
//! # What does not stand here
//!
//! The minting itself (X.509 over `rcgen`) -- see [`crate::mint`]. The custody of
//! the signing key stands in [`crate::threshold`]: the signing CA is there a FROST
//! group over five seats, of which three suffice, and it steps behind the same
//! seam the SVID path uses -- `rcgen::SigningKey`.

#![forbid(unsafe_code)]
// **No panicking call in the production path**: a panic costs its task and not
// the node -- and that is a state an operator sees only at a metric. `not(test)`,
// because the unit tests in `src` need them; the guard lies in
// `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod agent;
pub mod attest;
pub mod cluster;
pub const SNI: &str = "cluster.invalid";

pub mod control;
pub mod id;
pub mod join;
pub mod layout;
pub mod lifetime;
pub mod mint;
pub mod seats;
pub mod secrets;
pub mod threshold;
pub mod workload_api;

pub use crate::agent::{IntermediateProfile, Minter, Refusal};
pub use crate::attest::Attestation;
pub use crate::cluster::{
    ClusterVerifyError, NodeIdentity, NodeTrust, NodeVerifier, SharedTrust, TrustError,
    anchors_from_pem, check, node_leaf, shared,
};
pub use crate::control::{
    ChallengeRequest, ChallengeResponse, Credentials, IdentityClient, JoinRequest, RenewRequest,
};
pub use crate::id::{DEFAULT_TRUST_DOMAIN, IdError, Role, SpiffeId, TrustDomain};
pub use crate::lifetime::{Lifetime, LifetimeError, State, Validity};
pub use crate::mint::{
    Authority, Ca, Certified, LocalSigner, MintError, Purpose, Signer, Svid, expires_at,
    self_signed_ca,
};
pub use crate::workload_api::{
    Clock, HINT_DELEGATED, HINT_SELF, PeerCredentials, SystemClock, WorkloadApi, incoming_for,
    serve_on,
};
