//! The threshold CA: FROST over five signer seats.
//!
//! The SVID issuance path is built against a seam: `rcgen::SigningKey`, a trait
//! with exactly one method that demands **no key**. Behind that seam sits a
//! signing identity, but no node that ever holds the complete key.
//!
//! # What the procedure delivers, and what it costs
//!
//! FROST on Ed25519 is two-round threshold Schnorr. The result is an **ordinary
//! Ed25519 signature**: 32 bytes of group key, 64 bytes of signature, verified by
//! `ring`/`webpki` without a special path (RFC 8410). That is deliberate: rustls
//! must know nothing of the threshold construction underneath.
//!
//! The price is the nonce. Every seat draws one in round 1, hands out the
//! commitment to it and signs with it in round 2. **If a nonce is used twice, the
//! share falls out** -- two equations, one unknown, which makes nonce reuse the
//! most dangerous failure mode in the whole construction. That is why the
//! uniqueness lies here not with the caller but in the [`NonceVault`]: the nonce
//! lives only there, it leaves it solely through `take`, and `take` removes it in
//! the process.
//!
//! # Design choices fixed for this group
//!
//! - **Five seats, t = 3** ([`GroupShape::adr_0014`]), frozen with the DKG. The
//!   same threshold as the Raft quorum -- not because it moves with it (it
//!   cannot), but so that there is no state in which the cluster can write but
//!   not sign.
//! - **Decoupled from the Raft membership.** A node that joins the membership does
//!   not thereby become a signer. The mapping seat -> node is an operational
//!   setting like the peer addresses.
//! - **Replacement via RTS**, not via a ceremony ([`repair`]). The group public key
//!   stays, so the intermediate the air-gapped root issued on it stays valid too.
//!
//! # Two seams, no driver
//!
//! - [`ShareCustody`] is the **TPM seam**, with [`TpmCustody`] standing behind it:
//!   an envelope, because the share is measured to be six bytes too large for a
//!   TPM object. [`PlainCustody`] is expressly *not* the intended custody model,
//!   just as `LocalSigner` was not the eventual signing model -- it stays the path
//!   for a node without a TPM and for the tests.
//! - [`SignerLink`] is the **network seam**. [`LocalLink`] runs a seat in the same
//!   process; a gRPC link steps beside it later without anything changing in the
//!   signature path.
//!
//! # What does not stand here
//!
//! The proactive refresh (`frost::keys::refresh`) and the ceremony for a new N/t
//! are both out of scope here. And the root: it is air-gapped, its PKCS#11
//! boundary lies on the offline path and does not occur in this codebase.

mod custody;
pub mod dkg;
mod entropy;
mod error;
mod group;
mod material;
mod nonce;
mod participant;
pub mod refresh;
pub mod repair;
mod signer;
mod wire;

pub use crate::threshold::custody::{
    PlainCustody, SealedShare, ShareCustody, TpmCustody, custody_for, envelope_seat, is_envelope,
};
pub use crate::threshold::entropy::{Entropy, OsEntropy};
pub use crate::threshold::error::ThresholdError;
pub use crate::threshold::group::{GroupShape, SEATS, Seat, THRESHOLD};
pub use crate::threshold::material::{
    Epoch, Material, epochs, group_path, group_path_at, groups, load_group, share_path,
    share_path_at,
};
pub use crate::threshold::nonce::{CommitmentId, NonceError, NonceVault};
pub use crate::threshold::participant::{Participant, SessionId};
pub use crate::threshold::signer::{LocalLink, Reached, Round, SignerLink, ThresholdSigner};
pub use crate::threshold::wire::{
    ABANDON, AbandonRequest, AbandonResponse, COMMIT, CommitRequest, CommitResponse, GrpcLink,
    REFRESH_ABANDON, REFRESH_DEAL, REFRESH_FINISH, REFRESH_RETIRE, REFRESH_START, REFRESH_TAKE,
    REPAIR_ABANDON, REPAIR_DEAL, REPAIR_SIGMA, REPAIR_TAKE, RefreshAbandonRequest,
    RefreshAbandonResponse, RefreshDealRequest, RefreshDealResponse, RefreshFinishRequest,
    RefreshFinishResponse, RefreshRetireRequest, RefreshRetireResponse, RefreshStartRequest,
    RefreshStartResponse, RefreshTakeRequest, RefreshTakeResponse, RepairAbandonRequest,
    RepairAbandonResponse, RepairDealRequest, RepairDealResponse, RepairSigmaRequest,
    RepairSigmaResponse, RepairTakeRequest, RepairTakeResponse, SIGN, SignRequest, SignResponse,
};

pub type KeyPackage = frost_ed25519::keys::KeyPackage;

pub type PublicKeyPackage = frost_ed25519::keys::PublicKeyPackage;

pub type SigningCommitments = frost_ed25519::round1::SigningCommitments;

pub type SignatureShare = frost_ed25519::round2::SignatureShare;

pub type SigningPackage = frost_ed25519::SigningPackage;
