//! The nonce vault -- the most dangerous spot in the construction.
//!
//! FROST is two-round. In round 1 a seat draws a nonce and hands out the commitment
//! to it; in round 2 it signs with it. If it uses the same nonce for two signatures,
//! those are two equations with the same unknown -- **the share falls out**. Whoever
//! collects t such shares has the signing CA.
//!
//! The library says it itself: "[`SigningNonces`] must be used *only once* for a
//! signing operation; re-using nonces will result in leakage of a signer's
//! long-lived signing key." But it does not enforce it -- it cannot, because it does
//! not know the object's life story.
//!
//! # Why this is not left to the caller here
//!
//! A nonce error does not arise as a wrong call but as an ordering: a retry, a
//! duplicated packet, two sessions on the same seat. That is why the uniqueness is
//! **structural** here:
//!
//! 1. The nonce lives exclusively in the vault. It is copied nowhere.
//! 2. It leaves the vault only through [`NonceVault::take`], and `take` **removes**
//!    it in the process. A second access finds nothing there any more.
//! 3. [`NonceVault::discard`] consumes it too. Otherwise "abort" would be the way
//!    to get it a second time.
//! 4. The vault remembers every commitment it has ever handed out and refuses one
//!    that repeats. That catches the case bookkeeping over identifiers does not
//!    see: an entropy source that repeats -- a cloned VM, a restored snapshot, a
//!    source before its initialization.

use std::collections::{BTreeMap, BTreeSet};

use frost_ed25519::round1::{SigningNonces, commit};

use crate::threshold::entropy::{Entropy, Source};
use crate::threshold::group::Seat;
use crate::threshold::{KeyPackage, SigningCommitments};

/// The identifier of a commitment from round 1.
///
/// It is bound to its seat: an identifier of another seat is unknown in one's own
/// vault, not spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitmentId {
    seat: Seat,
    serial: u64,
}

impl CommitmentId {
    /// The seat that issued it.
    #[must_use]
    pub fn seat(self) -> Seat {
        self.seat
    }

    /// The serial number within the seat.
    #[must_use]
    pub fn serial(self) -> u64 {
        self.serial
    }
}

impl std::fmt::Display for CommitmentId {
    /// Writes this identifier as `"<seat>/commitment <serial>"` to `f`.
    ///
    /// # Errors
    ///
    /// Propagates any formatting error from the underlying `write!` call.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/commitment {}", self.seat, self.serial)
    }
}

/// What the nonce vault refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceError {
    /// This vault never issued this identifier.
    Unknown {
        /// The demanded identifier.
        id: CommitmentId,
    },
    /// The nonce for this commitment is spent -- redeemed or discarded.
    ///
    /// **That is the case at issue.** A second access to the same nonce is either a
    /// programming error or an attack; both end here and not in a signature.
    AlreadySpent {
        /// The demanded identifier.
        id: CommitmentId,
    },
    /// The entropy source delivered a commitment that already existed.
    ///
    /// The nonce was **not** handed out. In operation that means: this node's
    /// source is broken or its state was duplicated -- an incident, no repeat
    /// case.
    EntropyRepeated {
        /// The affected seat.
        seat: Seat,
    },
    /// A commitment could not be serialized.
    Malformed {
        /// The library's message.
        detail: String,
    },
}

impl std::fmt::Display for NonceError {
    /// Writes a human-readable description of this error to `f`.
    ///
    /// # Errors
    ///
    /// Propagates any formatting error from the underlying `write!` call.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown { id } => write!(f, "{id} was never issued by this vault"),
            Self::AlreadySpent { id } => write!(
                f,
                "the nonce for {id} is spent and is not handed out a second time -- \
                 a reused nonce gives the share away (ADR-0014)"
            ),
            Self::EntropyRepeated { seat } => write!(
                f,
                "{seat}'s entropy source repeated a commitment; the nonce was not \
                 handed out. That is an incident: the source is broken or the node \
                 state was duplicated"
            ),
            Self::Malformed { detail } => write!(f, "the commitment is not serializable: {detail}"),
        }
    }
}

impl std::error::Error for NonceError {}

/// A seat's nonce vault.
///
/// It is the only place at which a [`SigningNonces`] lies, and the only place that
/// hands it out.
///
/// # Memory
///
/// The vault remembers the fingerprints of all the commitments ever handed out
/// (64 bytes each) and the numbers of the spent ones. At a cadence of one agent
/// intermediate every three hours, that is nothing over years. A vault is
/// discarded anyway when the share changes (RTS or refresh); then the
/// bookkeeping may and shall start afresh too, for it belongs to the share, not to
/// the seat.
#[derive(Debug)]
pub struct NonceVault {
    seat: Seat,
    next: u64,
    live: BTreeMap<u64, SigningNonces>,
    spent: BTreeSet<u64>,
    fingerprints: BTreeSet<Vec<u8>>,
}

impl NonceVault {
    /// An empty vault for this seat.
    #[must_use]
    pub fn new(seat: Seat) -> Self {
        Self {
            seat,
            next: 0,
            live: BTreeMap::new(),
            spent: BTreeSet::new(),
            fingerprints: BTreeSet::new(),
        }
    }

    /// The seat it belongs to.
    #[must_use]
    pub fn seat(&self) -> Seat {
        self.seat
    }

    /// Round 1: draw a nonce and hand out the commitment to it.
    ///
    /// The nonce stays in the vault. What the caller gets is the commitment and an
    /// identifier with which they can redeem it **once**.
    ///
    /// # Errors
    ///
    /// [`NonceError::EntropyRepeated`] when the source delivered a commitment that
    /// already existed -- then nothing is handed out.
    /// [`NonceError::Malformed`] when `frost` does not serialize the commitment.
    pub fn commit(
        &mut self,
        share: &KeyPackage,
        entropy: &mut dyn Entropy,
    ) -> Result<(CommitmentId, SigningCommitments), NonceError> {
        let (nonces, commitments) = commit(share.signing_share(), &mut Source::new(entropy));

        let fingerprint = commitments
            .serialize()
            .map_err(|err| NonceError::Malformed {
                detail: err.to_string(),
            })?;
        if !self.fingerprints.insert(fingerprint) {
            // The nonce falls to the floor here without ever having been handed
            // out. That is the right order: rather no signature than one that
            // gives the share away.
            return Err(NonceError::EntropyRepeated { seat: self.seat });
        }

        let serial = self.next;
        self.next += 1;
        self.live.insert(serial, nonces);

        Ok((
            CommitmentId {
                seat: self.seat,
                serial,
            },
            commitments,
        ))
    }

    /// Round 2: the nonce for this commitment -- **once**.
    ///
    /// # Errors
    ///
    /// [`NonceError::AlreadySpent`] when it was redeemed or discarded;
    /// [`NonceError::Unknown`] when this vault never issued it.
    pub fn take(&mut self, id: CommitmentId) -> Result<SigningNonces, NonceError> {
        self.retire(id)
    }

    /// Discard a commitment without redeeming it.
    ///
    /// The nonce is **spent likewise** afterwards. An aborted session must not give
    /// it back.
    ///
    /// # Errors
    ///
    /// As [`NonceVault::take`].
    pub fn discard(&mut self, id: CommitmentId) -> Result<(), NonceError> {
        self.retire(id).map(drop)
    }

    /// How many commitments are open.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.live.len()
    }

    /// How many nonces are spent.
    #[must_use]
    pub fn spent(&self) -> u64 {
        u64::try_from(self.spent.len()).unwrap_or(u64::MAX)
    }

    /// Removes and returns the nonce for `id`, marking it spent. Shared by
    /// [`NonceVault::take`] and [`NonceVault::discard`], since both must retire
    /// the nonce exactly once and never hand it out again.
    ///
    /// # Errors
    ///
    /// [`NonceError::Unknown`] when `id` belongs to a different seat or was never
    /// issued by this vault; [`NonceError::AlreadySpent`] when it was already
    /// redeemed or discarded.
    fn retire(&mut self, id: CommitmentId) -> Result<SigningNonces, NonceError> {
        if id.seat != self.seat {
            return Err(NonceError::Unknown { id });
        }

        if let Some(nonces) = self.live.remove(&id.serial) {
            self.spent.insert(id.serial);
            return Ok(nonces);
        }

        if self.spent.contains(&id.serial) {
            Err(NonceError::AlreadySpent { id })
        } else {
            Err(NonceError::Unknown { id })
        }
    }
}
