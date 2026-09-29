//! A seat in signing operation.
//!
//! The participant holds together three things that are of no use individually: the
//! sealed share, the nonce vault and the mapping session -> commitment. The third is
//! the reason a retry is not dangerous here: a session that already has a
//! commitment gets **the same one** again, no second nonce.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::threshold::custody::{SealedShare, ShareCustody};
use crate::threshold::entropy::Entropy;
use crate::threshold::error::ThresholdError;
use crate::threshold::group::Seat;
use crate::threshold::material::{Epoch, Material};
use crate::threshold::nonce::{CommitmentId, NonceVault};
use crate::threshold::{
    KeyPackage, PublicKeyPackage, SignatureShare, SigningCommitments, SigningPackage,
};

/// The identifier of a signing session.
///
/// It correlates round 1 and round 2 across the seats. It is **no** security
/// boundary -- that lies in the nonce vault. What it delivers is that a seat knows
/// which of its open commitments belongs to which signing package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl From<u64> for SessionId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl SessionId {
    /// The number behind it -- for the wire form (ADR-0097).
    ///
    /// It is **process-local**: the coordinator counts it up, and a seat uses it
    /// only to distinguish its open commitments. Two coordinators that name the
    /// same number are the case `commit`'s idempotence carries: the second gets the
    /// first one's commitment, and a second signing with the same nonce finds it
    /// spent (7b).
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session {}", self.0)
    }
}

/// A seat of the signing group.
///
/// # Two generations at the same time
///
/// A seat holds its share **per epoch** (ADR-0107, determination 3), not one. The
/// reason is measured: shares from two epochs do not combine, and the aggregation
/// blames the one left behind in the process. Without the overlap every refresh
/// would be a window in which the group does not sign -- the same shape as the two
/// data keys in ADR-0100.
///
/// **A session belongs to exactly one epoch**, and it is fixed in round 1. Whoever
/// named it only in round 2 would have two places at which it is decided -- and a
/// commitment from epoch N that is redeemed in N+1 is the sort of error that per
/// ADR-0014 costs the share.
pub struct Participant {
    seat: Seat,
    /// Share **and** group key per generation.
    ///
    /// The group key stands here because round 3 of a refresh needs it: `frost`
    /// adds the delta onto the old share and computes the new `verifying_shares`
    /// from the old package. A seat that did not have it could not renew its own
    /// share.
    sealed: BTreeMap<Epoch, (SealedShare, PublicKeyPackage)>,
    custody: Arc<dyn ShareCustody>,
    vault: NonceVault,
    open: BTreeMap<SessionId, Session>,
}

/// An open session: commitment, commitment identifier and its epoch.
struct Session {
    id: CommitmentId,
    commitments: SigningCommitments,
    epoch: Epoch,
}

impl std::fmt::Debug for Participant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Participant")
            .field("seat", &self.seat)
            .field("epochs", &self.sealed.len())
            .field("open", &self.open.len())
            .field("spent", &self.vault.spent())
            .finish_non_exhaustive()
    }
}

impl Participant {
    /// A seat over this share.
    ///
    /// The share is sealed immediately and afterwards opened only for the duration
    /// of a round.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when the sealing fails.
    pub fn new(
        seat: Seat,
        share: &KeyPackage,
        group: &PublicKeyPackage,
        epoch: Epoch,
        custody: Arc<dyn ShareCustody>,
    ) -> Result<Self, ThresholdError> {
        let mut sealed = BTreeMap::new();
        sealed.insert(epoch, (custody.seal(seat, share)?, group.clone()));

        Ok(Self {
            seat,
            sealed,
            custody,
            vault: NonceVault::new(seat),
            open: BTreeMap::new(),
        })
    }

    /// Which generations this seat can hold, ascending.
    #[must_use]
    pub fn epochs(&self) -> Vec<Epoch> {
        self.sealed.keys().copied().collect()
    }

    /// Puts the share of a **further** generation beside it.
    ///
    /// The refresh's way: the new share comes along, the old one stays, and it is
    /// discarded only once all five seats hold the new generation (ADR-0107,
    /// determination 6). Open sessions stay untouched -- they belong to their epoch
    /// and are not affected by the new one.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when the sealing fails.
    pub fn stage_share(
        &mut self,
        epoch: Epoch,
        share: &KeyPackage,
        group: &PublicKeyPackage,
    ) -> Result<(), ThresholdError> {
        let sealed = self.custody.seal(self.seat, share)?;
        self.sealed.insert(epoch, (sealed, group.clone()));

        Ok(())
    }

    /// The material of the highest generation held.
    ///
    /// The way into round 3 of a refresh: there the delta is added onto **this**
    /// share.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when the share cannot be opened;
    /// [`ThresholdError::UnknownEpoch`] when this seat holds no generation at all --
    /// not reachable as long as it arises over [`Participant::new`].
    pub fn newest_material(&self) -> Result<Material, ThresholdError> {
        let (&epoch, (sealed, group)) =
            self.sealed
                .iter()
                .next_back()
                .ok_or_else(|| ThresholdError::UnknownEpoch {
                    seat: self.seat,
                    wanted: 0,
                    held: Vec::new(),
                })?;

        let share = self.custody.unseal(sealed)?;

        Ok(Material::held(self.seat, share, group.clone(), epoch))
    }

    /// Discards all generations **below** this one.
    ///
    /// Their open commitments are **spent**, not forgotten -- the same doctrine as
    /// at [`Self::abandon`]: a nonce that became free again would be the way to get
    /// it a second time.
    pub fn retire_below(&mut self, epoch: Epoch) {
        self.sealed.retain(|held, _| *held >= epoch);

        let stale: Vec<SessionId> = self
            .open
            .iter()
            .filter(|(_, session)| session.epoch < epoch)
            .map(|(id, _)| *id)
            .collect();
        for session in stale {
            self.abandon(session);
        }
    }

    /// The custody under which this seat holds its share.
    ///
    /// For the way onto the disk: a new generation is written with **the same**
    /// custody under which it lies in memory. Two sources for that would be two
    /// opportunities to file a generation unsealed.
    #[must_use]
    pub fn custody(&self) -> Arc<dyn ShareCustody> {
        Arc::clone(&self.custody)
    }

    /// The seat.
    #[must_use]
    pub fn seat(&self) -> Seat {
        self.seat
    }

    /// How many sessions are open.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.open.len()
    }

    /// Round 1: the commitment for this session.
    ///
    /// **Idempotent.** A session that already has a commitment gets the same one
    /// again. A repeated call -- a network retry, a duplicated packet -- must not
    /// draw a second nonce and certainly not burn the first.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] or [`ThresholdError::Nonce`].
    pub fn commit(
        &mut self,
        session: SessionId,
        epoch: Epoch,
        entropy: &mut dyn Entropy,
    ) -> Result<SigningCommitments, ThresholdError> {
        if let Some(open) = self.open.get(&session) {
            if open.epoch != epoch {
                // The same session in two epochs is no repetition but two
                // questions. The commitment belongs to exactly one share; handing
                // it out for another one would be "one commitment, two shares".
                return Err(ThresholdError::SessionEpoch {
                    session: session.to_string(),
                    running: open.epoch.number(),
                    wanted: epoch.number(),
                });
            }

            return Ok(open.commitments);
        }

        let sealed = self.share_at(epoch)?;
        let share = self.custody.unseal(sealed)?;
        let (id, commitments) = self.vault.commit(&share, entropy)?;
        self.open.insert(
            session,
            Session {
                id,
                commitments,
                epoch,
            },
        );

        Ok(commitments)
    }

    fn share_at(&self, epoch: Epoch) -> Result<&SealedShare, ThresholdError> {
        self.sealed
            .get(&epoch)
            .map(|(sealed, _)| sealed)
            .ok_or_else(|| ThresholdError::UnknownEpoch {
                seat: self.seat,
                wanted: epoch.number(),
                held: self.sealed.keys().map(|epoch| epoch.number()).collect(),
            })
    }

    /// Round 2: the signature share for this package.
    ///
    /// The nonce is taken out of the vault **before** the signing. If the signing
    /// fails afterwards -- say because the package does not contain one's own
    /// commitment at all --, it is spent nevertheless. That is the right order: a
    /// lost nonce costs a round, a reused one the share.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Nonce`] when no open commitment exists for this session any
    /// more; [`ThresholdError::Custody`]; [`ThresholdError::Frost`] when `frost`
    /// refuses the package.
    pub fn sign(
        &mut self,
        session: SessionId,
        package: &SigningPackage,
    ) -> Result<SignatureShare, ThresholdError> {
        let open = self
            .open
            .remove(&session)
            .ok_or_else(|| ThresholdError::NoSuchSession {
                session: session.to_string(),
            })?;

        let nonces = self.vault.take(open.id)?;
        // **The epoch comes from the session**, not from the call: it was fixed in
        // round 1, and a second place would be a second place at which it can be
        // wrong (ADR-0107, determination 4).
        let share = self.custody.unseal(self.share_at(open.epoch)?)?;

        frost_ed25519::round2::sign(package, &nonces, &share)
            .map_err(|err| ThresholdError::frost("FROST round 2", &err))
    }

    /// Abort a session.
    ///
    /// The nonce is spent afterwards, not free. Otherwise "abort" would be the way
    /// to get it a second time.
    ///
    /// **The discarded failure of `discard` is without consequence, and that is
    /// measured** -- at the most dangerous spot in this system (ADR-0014) the
    /// justification belongs, not the hope. `NonceVault::retire` gives `Err` in
    /// exactly three situations, and in each the doctrine is satisfied afterwards:
    ///
    /// | Situation | Why the nonce is not free |
    /// |---|---|
    /// | a foreign seat | impossible here: `open.id` came from **this** vault |
    /// | `AlreadySpent` | it is spent -- exactly the promise |
    /// | `Unknown` | there is nothing that could become free |
    pub fn abandon(&mut self, session: SessionId) {
        if let Some(open) = self.open.remove(&session) {
            let _ = self.vault.discard(open.id);
        }
    }

    /// Take over a new share -- after RTS or a refresh.
    ///
    /// Open sessions of the old share are **spent**, not forgotten: their
    /// commitments belong to a share that no longer exists, and a nonce that became
    /// free again would be precisely the way to get it a second time (the same
    /// doctrine as at [`Self::abandon`]). If the entry stayed at all, the idempotent
    /// [`Self::commit`] would give the same commitment back under a different share
    /// -- one commitment, two shares.
    ///
    /// **The vault expressly gets no fresh start in the process.** It once stood
    /// here that its bookkeeping belongs to the share; measured, that is false for
    /// the one half that matters. The vault recognizes an **entropy source that
    /// repeats** -- a cloned VM, a restored snapshot --, and that is a property of
    /// the machine, not of the share. RTS is on top of that exactly the operation at
    /// which a machine was set up anew, and `restore_seat` gives **the same** share
    /// back: a forgetful vault would afterwards hand out the same nonce under the
    /// same share a second time (ADR-0014).
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when the sealing fails.
    pub fn adopt_share(
        &mut self,
        epoch: Epoch,
        share: &KeyPackage,
        group: &PublicKeyPackage,
    ) -> Result<(), ThresholdError> {
        let sealed = self.custody.seal(self.seat, share)?;
        self.sealed.clear();
        self.sealed.insert(epoch, (sealed, group.clone()));
        for open in std::mem::take(&mut self.open).into_values() {
            let _ = self.vault.discard(open.id);
        }

        Ok(())
    }
}
