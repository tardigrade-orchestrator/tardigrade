//! The coordinator: two rounds behind `rcgen::SigningKey`.
//!
//! Here closes what phase 7a left open. `rcgen::SigningKey` demands one method --
//! `sign(&self, msg) -> Vec<u8>` -- and **no key**. [`ThresholdSigner`] fulfils it
//! by running two rounds over the group. Not a line of the SVID path changes for
//! that: the same `Authority`, the same `issue`, the same verifier.
//!
//! # The coordinator is not trustworthy, and that is planned for
//!
//! `frost` says it plainly: the coordinator learns nothing secret but can practise
//! denial of service. Here it is the same process that wants the certificate anyway
//! -- it thereby harms only itself. What it **cannot** do is redeem a nonce twice:
//! that is decided by the seat, not by it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::threshold::entropy::Entropy;
use crate::threshold::error::ThresholdError;
use crate::threshold::group::{GroupShape, Seat};
use crate::threshold::material::{Epoch, Material};
use crate::threshold::participant::{Participant, SessionId};
use crate::threshold::{PublicKeyPackage, SignatureShare, SigningCommitments, SigningPackage};
use crate::threshold::{refresh, repair};

/// The link to a seat.
///
/// The seam to the network. [`LocalLink`] runs a seat in the same process; a gRPC
/// link (ADR-0018) steps beside it later without anything here becoming different.
pub trait SignerLink: std::fmt::Debug + Send + Sync {
    /// Which seat.
    fn seat(&self) -> Seat;

    /// Round 1, in this generation of the shares.
    ///
    /// **The epoch stands here and not in round 2** (ADR-0107, determination 4): it
    /// belongs to the session, and a second place would be a second at which it can
    /// be wrong.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Unreachable`] when the seat does not answer;
    /// [`ThresholdError::UnknownEpoch`] when it does not hold this generation.
    fn commit(
        &self,
        session: SessionId,
        epoch: Epoch,
    ) -> Result<SigningCommitments, ThresholdError>;

    /// Round 2.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Unreachable`] when the seat does not answer, or
    /// [`ThresholdError::Nonce`] when its commitment is already redeemed.
    fn sign(
        &self,
        session: SessionId,
        package: &SigningPackage,
    ) -> Result<SignatureShare, ThresholdError>;

    /// Abort a session. Best effort -- a seat one does not reach clears its
    /// commitment away itself as soon as it is back.
    fn abandon(&self, session: SessionId);

    /// Refresh, round 1: one's own zero polynomial (ADR-0107).
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Unreachable`] when the seat does not answer.
    fn refresh_start(&self, epoch: Epoch) -> Result<refresh::Broadcast, ThresholdError>;

    /// Refresh, round 2: **the seat delivers itself.**
    ///
    /// The call returns when this seat has handed its directed packages to all the
    /// others -- not before. The coordinator afterwards knows that everyone has
    /// everything **without having seen the packages**: it would otherwise see every
    /// delta and be the dealer ADR-0107 rejected.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Unreachable`] when the seat or one of its receivers does not
    /// answer.
    fn refresh_deal(
        &self,
        epoch: Epoch,
        broadcasts: &BTreeMap<Seat, refresh::Broadcast>,
    ) -> Result<(), ThresholdError>;

    /// Refresh, round 2 from seat to seat: accept a directed package.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Unreachable`] when the seat does not answer.
    fn refresh_take(
        &self,
        epoch: Epoch,
        from: Seat,
        directed: &refresh::Directed,
    ) -> Result<(), ThresholdError>;

    /// Refresh, round 3: form the new share and lay it **beside**.
    ///
    /// Returns the generation reached **and** the new group key. That is public, and
    /// the coordinator needs it: without the new `verifying_shares` it cannot name a
    /// culprit. It is not believed -- [`ThresholdSigner::refresh`] demands that all
    /// five name the same one and that its verifying key is the old one.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Unreachable`] or [`ThresholdError::Frost`].
    fn refresh_finish(&self, epoch: Epoch) -> Result<Reached, ThresholdError>;

    /// Refresh, afterwards: **retire every generation below this one** (ADR-0107,
    /// determination 6).
    ///
    /// Only here does the refresh have its effect: as long as the old generation
    /// lies, t seats can go on signing in it -- and a betrayed share thereby still
    /// applies. What is retired is on the **disk** and in memory.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Unreachable`] when the seat does not answer.
    fn refresh_retire(&self, epoch: Epoch) -> Result<(), ThresholdError>;

    /// Abort a begun refresh. Best effort.
    ///
    /// **Why the failure is without consequence**, and that is the question with an
    /// operation that exchanges shares: a seat one does not reach has no inbox to be
    /// cleared either -- and a left-behind state does not block a begun run, because
    /// **a second start discards the first** (ADR-0107, determination 4). What the
    /// abort achieves is the release **immediately** instead of at the next attempt.
    fn refresh_abandon(&self, epoch: Epoch);

    // --- RTS (ADR-0108) ---------------------------------------------------
    //
    // **Without a default implementation**, and that is a choice: a default that
    // refuses would be the right answer for each of the four dummies in the test rig
    // and for [`GrpcLink`] until cut 2 -- and it would take the question away from
    // the compiler. Whoever builds a new seam shall be asked whether it carries the
    // repair; four lines in test code are the price for that.

    /// RTS, steps 1 and 2: produce one's own deltas and **deliver them oneself**
    /// (ADR-0108).
    ///
    /// The call returns when this helper has handed to all the others -- not before.
    /// Literally the same shape as [`Self::refresh_deal`] and for the same,
    /// **measured** reason: a coordinator that passed the deltas through would see
    /// exactly the input of `repair::restore_seat` and reconstruct the share.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Repair`] when one's own seat stands among the helpers;
    /// [`ThresholdError::Unreachable`] when a seat does not answer;
    /// [`ThresholdError::Frost`] when the library refuses.
    fn repair_deal(&self, lost: Seat, helpers: &[Seat]) -> Result<(), ThresholdError>;

    /// RTS, from seat to seat: accept a delta.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Unreachable`] when the seat does not answer.
    fn repair_take(
        &self,
        lost: Seat,
        from: Seat,
        delta: &repair::Delta,
    ) -> Result<(), ThresholdError>;

    /// RTS, step 2: one's own sigma for the lost seat.
    ///
    /// **Only it may see it** (ADR-0108, determination 3) -- measured, `t`
    /// passed-through sigmas yield the share, they *are* the input of step 3. The
    /// check that the caller is the lost seat sits at the **service**: it knows it
    /// from the connection's credential (ADR-0097), this seam does not.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Repair`] when no repair was begun for this seat;
    /// [`ThresholdError::Unreachable`] when the seat does not answer.
    fn repair_sigma(&self, lost: Seat) -> Result<repair::Sigma, ThresholdError>;

    /// Abort a begun repair. Best effort.
    ///
    /// The same rationale as at [`Self::refresh_abandon`]: a second run discards the
    /// first (ADR-0108, determination 4), so a left-behind inbox blocks nothing. And
    /// a delta **alone** says nothing -- what makes it a share is `t` of them.
    fn repair_abandon(&self, lost: Seat);
}

/// What round 3 of a refresh reached.
///
/// **`persisted` decides determination 6**: the coordinator retires the old
/// generation only when all five have the new one *on the disk* -- having it in
/// memory does not suffice, for a restart would take it away again, and then this
/// seat would stand without a generation in which t come together.
#[derive(Debug, Clone)]
pub struct Reached {
    /// The generation reached.
    pub epoch: Epoch,
    /// Its group key -- public.
    pub group: PublicKeyPackage,
    /// Whether it lies on the disk.
    pub persisted: bool,
}

/// A seat in the same process.
///
/// The mutex is no optimization question: it is the place at which the nonce
/// bookkeeping holds under concurrency. Two threads that want to redeem the same
/// commitment at the same time serialize here -- and the second finds it spent.
pub struct LocalLink {
    seat: Seat,
    /// Where a new generation is written when a refresh forms it.
    ///
    /// **Without a directory it stays in memory**, and a restart loses it. That is
    /// harmless and not harmless at once: the seat falls back on its previous
    /// generation, and that goes on signing -- the refresh only has to be repeated.
    /// It is missing in the test rig, where there is no data directory; in operation
    /// `tgd` gives it along.
    store: Option<std::path::PathBuf>,
    inner: Mutex<Inner>,
    /// The other seats -- **only** for round 2 of a refresh.
    ///
    /// They are attached after the build because in operation they are `GrpcLink`s
    /// and one's own seat arises before them. A seat without them cannot deal, and
    /// that is no code path but a misconfiguration: `--signer` names the other four
    /// (ADR-0097).
    peers: std::sync::OnceLock<Vec<Arc<dyn SignerLink>>>,
}

struct Inner {
    participant: Participant,
    entropy: Box<dyn Entropy>,
    /// The running RTS repair, when one runs (ADR-0108).
    ///
    /// **At most one**, for the same reason as at the refresh: the lost seat is the
    /// only driver, and a left-behind state from an aborted run must not block a new
    /// one.
    repair: Option<Repairing>,
    /// The running refresh, when one runs.
    ///
    /// **At most one.** A second start discards the first -- the coordinator is the
    /// only driver, and a left-behind state from an aborted run must not block a new
    /// one (the same doctrine as at the `NonceVault`: an abort consumes).
    refresh: Option<Pending>,
}

/// An RTS repair between its rounds (ADR-0108).
///
/// The state is **only the inbox** -- unlike at the refresh there is no secret that
/// must be held across the rounds: step 1 hands out the deltas, and what a helper
/// needs for step 2 is what has arrived at **it**.
///
/// Keyed by seat and not as a list: the same helper must not contribute twice, and a
/// network retry replaces instead of doubling.
struct Repairing {
    lost: Seat,
    /// What has arrived at this helper, by sender.
    ///
    /// **`repair::Delta` is `Copy`** -- measured, and the reason why there would be
    /// nothing to delete here: a copy leaves no trace a `Drop` could collect. The
    /// answer to that is `ShareCustody` (ADR-0014, TPM), not a bolt on this map.
    inbox: BTreeMap<Seat, repair::Delta>,
}

/// A refresh between two rounds.
///
/// **The inbox stands beside the round and not within it**, and that is a finding of
/// the witness over five seats: in a network there is no order. Seat 1 delivers its
/// directed packages while seat 2 still stands in round 1 -- an inbox that existed
/// only after round 2 would refuse them with "does not stand in round 2", and no
/// refresh would ever come about.
struct Pending {
    epoch: Epoch,
    stage: Stage,
    inbox: BTreeMap<Seat, refresh::Directed>,
}

/// How far this seat is.
enum Stage {
    /// After round 1.
    Started(refresh::Started),
    /// After round 2.
    Exchanged(refresh::Exchanged),
}

impl std::fmt::Debug for LocalLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalLink")
            .field("seat", &self.seat)
            .finish_non_exhaustive()
    }
}

impl LocalLink {
    /// A local seat with its own entropy source.
    ///
    /// **Its own** source, not a shared one: in operation every seat is a process of
    /// its own with its own `OsRng`, and the separation belongs here even when it is
    /// not necessary just now.
    #[must_use]
    pub fn new(participant: Participant, entropy: Box<dyn Entropy>) -> Self {
        Self {
            seat: participant.seat(),
            store: None,
            inner: Mutex::new(Inner {
                participant,
                entropy,
                repair: None,
                refresh: None,
            }),
            peers: std::sync::OnceLock::new(),
        }
    }

    /// The same seat, writing a new generation **to the disk**.
    ///
    /// The directory is the data directory it was loaded from; the write happens in
    /// round 3, **after** the new share is formed. A failure at that does not cost
    /// the generation -- it lies in memory and carries until the restart --, but it
    /// is reported: a refresh a restart quietly loses is one an operator takes for
    /// done.
    #[must_use]
    pub fn persisting_to(mut self, data_dir: impl AsRef<std::path::Path>) -> Self {
        self.store = Some(data_dir.as_ref().to_path_buf());

        self
    }
}

impl LocalLink {
    /// Which generations **this seat** holds, ascending (ADR-0107).
    ///
    /// Not the same as what lies on the disk: here stands what it **can** sign with.
    /// A seat whose write failed in round 3 holds the new one and has not filed it.
    #[must_use]
    pub fn epochs(&self) -> Vec<Epoch> {
        self.inner
            .lock()
            .map_or_else(|_| Vec::new(), |guard| guard.participant.epochs())
    }

    /// Attach the other seats -- **once**.
    ///
    /// A second call is passed over: a seat's peers do not change in operation (the
    /// group is frozen with the DKG, ADR-0014), and a swap in the middle of a refresh
    /// would be the opportunity to deliver a package to somebody else.
    pub fn attach_peers(&self, peers: Vec<Arc<dyn SignerLink>>) {
        let _ = self.peers.set(peers);
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Inner>, ThresholdError> {
        self.inner
            .lock()
            .map_err(|_| ThresholdError::Unreachable { seat: self.seat })
    }

    /// Delivers the directed packages to the other seats.
    ///
    /// **Over one's own channels**, not over the coordinator: what travels here
    /// demands a confidential channel, and whoever passes it through knows every
    /// delta and is the trusted dealer ADR-0107 rejected.
    fn deal(
        &self,
        epoch: Epoch,
        outgoing: &BTreeMap<Seat, refresh::Directed>,
    ) -> Result<(), ThresholdError> {
        let Some(peers) = self.peers.get() else {
            return Err(ThresholdError::Shape {
                detail: format!(
                    "{} does not know the other seats -- without them there is no \
                     round 2 (ADR-0097: --signer names them)",
                    self.seat
                ),
            });
        };

        for (&to, directed) in outgoing {
            let Some(peer) = peers.iter().find(|peer| peer.seat() == to) else {
                return Err(ThresholdError::Unreachable { seat: to });
            };
            peer.refresh_take(epoch, self.seat, directed)?;
        }

        Ok(())
    }

    /// Delivers the RTS deltas to the other helpers (ADR-0108).
    ///
    /// The same as [`Self::deal`] and for the same reason: a delta is the part of a
    /// share, and whoever passes them through is the trusted dealer.
    fn deal_repair(
        &self,
        lost: Seat,
        outgoing: &BTreeMap<Seat, repair::Delta>,
    ) -> Result<(), ThresholdError> {
        let Some(peers) = self.peers.get() else {
            return Err(ThresholdError::Shape {
                detail: format!(
                    "{} does not know the other seats -- without them there is no \
                     repair (ADR-0097: --signer names them)",
                    self.seat
                ),
            });
        };

        for (&to, delta) in outgoing {
            if to == self.seat {
                continue;
            }
            let Some(peer) = peers.iter().find(|peer| peer.seat() == to) else {
                return Err(ThresholdError::Unreachable { seat: to });
            };
            peer.repair_take(lost, self.seat, delta)?;
        }

        Ok(())
    }

    /// Round 1 in wire form (ADR-0097).
    ///
    /// # One seat, one vault
    ///
    /// These three methods hang **on the same `LocalLink`** that also stands in one's
    /// own [`ThresholdSigner`] -- not on a second type over the same share. Two
    /// carriers would be two nonce vaults, and then two coordinators with the same
    /// session number would each find a fresh commitment: the replay protection from
    /// 7b would no longer bite, and the nonce is the place at which an error gives
    /// the share away (ADR-0014).
    ///
    /// # Errors
    ///
    /// [`ThresholdError`] when the entropy source fails or repeats itself, or the
    /// commitment cannot be serialized.
    pub fn answer_commit(
        &self,
        request: &crate::threshold::CommitRequest,
    ) -> Result<crate::threshold::CommitResponse, ThresholdError> {
        let commitments =
            self.round_one(SessionId::from(request.session), Epoch::new(request.epoch))?;
        let bytes = commitments
            .serialize()
            .map_err(|err| ThresholdError::frost("writing the commitment", &err))?;

        Ok(crate::threshold::CommitResponse {
            seat: self.seat.number(),
            commitments: bytes,
        })
    }

    /// Round 2 in wire form.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Frost`] when the package is no signature package; otherwise
    /// the round's errors.
    pub fn answer_sign(
        &self,
        request: &crate::threshold::SignRequest,
    ) -> Result<crate::threshold::SignResponse, ThresholdError> {
        let package = SigningPackage::deserialize(&request.package)
            .map_err(|err| ThresholdError::frost("reading the signature package", &err))?;
        let share = self.round_two(SessionId::from(request.session), &package)?;

        Ok(crate::threshold::SignResponse {
            share: share.serialize(),
        })
    }

    /// Abort in wire form.
    ///
    /// **Always** gives an answer: an abort the coordinator did not get confirmed
    /// would make it repeat -- and the nonce is spent afterwards anyway (7b: an abort
    /// spends it likewise).
    pub fn answer_abandon(
        &self,
        request: &crate::threshold::AbandonRequest,
    ) -> crate::threshold::AbandonResponse {
        SignerLink::abandon(self, SessionId::from(request.session));
        crate::threshold::AbandonResponse {}
    }

    /// Refresh round 1 in wire form (ADR-0107).
    ///
    /// # Errors
    ///
    /// [`ThresholdError`] when the entropy source fails or the binding cannot be
    /// serialized.
    pub fn answer_refresh_start(
        &self,
        request: &crate::threshold::RefreshStartRequest,
    ) -> Result<crate::threshold::RefreshStartResponse, ThresholdError> {
        let broadcast = SignerLink::refresh_start(self, Epoch::new(request.epoch))?;
        let bytes = broadcast
            .serialize()
            .map_err(|err| ThresholdError::frost("writing the binding", &err))?;

        Ok(crate::threshold::RefreshStartResponse {
            seat: self.seat.number(),
            broadcast: bytes,
        })
    }

    /// Refresh round 2 in wire form.
    ///
    /// Returns only when the directed packages are delivered to all the other seats
    /// (ADR-0107).
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Frost`] when a binding is unreadable;
    /// [`ThresholdError::Shape`] when this seat does not stand in round 1;
    /// [`ThresholdError::Unreachable`] when a receiver does not answer.
    pub fn answer_refresh_deal(
        &self,
        request: &crate::threshold::RefreshDealRequest,
    ) -> Result<crate::threshold::RefreshDealResponse, ThresholdError> {
        let mut broadcasts = BTreeMap::new();
        for (number, bytes) in &request.broadcasts {
            let seat = Seat::new(*number)?;
            let broadcast = refresh::Broadcast::deserialize(bytes)
                .map_err(|err| ThresholdError::frost("reading the binding", &err))?;
            broadcasts.insert(seat, broadcast);
        }

        SignerLink::refresh_deal(self, Epoch::new(request.epoch), &broadcasts)?;

        Ok(crate::threshold::RefreshDealResponse {})
    }

    /// Accept a directed package of another seat, in wire form.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Frost`] when the package is unreadable;
    /// [`ThresholdError::Shape`] when this seat does not stand in round 2.
    pub fn answer_refresh_take(
        &self,
        request: &crate::threshold::RefreshTakeRequest,
    ) -> Result<crate::threshold::RefreshTakeResponse, ThresholdError> {
        let from = Seat::new(request.from)?;
        let directed = refresh::Directed::deserialize(&request.directed)
            .map_err(|err| ThresholdError::frost("reading the package", &err))?;

        SignerLink::refresh_take(self, Epoch::new(request.epoch), from, &directed)?;

        Ok(crate::threshold::RefreshTakeResponse {})
    }

    /// RTS step 1 in wire form (ADR-0108).
    ///
    /// # Errors
    ///
    /// As [`SignerLink::repair_deal`], plus [`ThresholdError::Shape`] on an unusable
    /// seat number.
    pub fn answer_repair_deal(
        &self,
        request: &crate::threshold::RepairDealRequest,
    ) -> Result<crate::threshold::RepairDealResponse, ThresholdError> {
        let lost = Seat::new(request.lost)?;
        let helpers: Result<Vec<Seat>, _> =
            request.helpers.iter().copied().map(Seat::new).collect();

        SignerLink::repair_deal(self, lost, &helpers?)?;

        Ok(crate::threshold::RepairDealResponse {})
    }

    /// Accept a delta, in wire form (ADR-0108).
    ///
    /// **The sender comes from the caller**, not from the message: the signer service
    /// reads it from the connection's credential (ADR-0097). Unlike at the refresh
    /// the crypto **does not** catch a self-declaration here -- the sender is the
    /// inbox's key, and whoever lies overwrites another's delta. The run then breaks
    /// in step 3 at the check against the group key, but it breaks.
    ///
    /// # Errors
    ///
    /// As [`SignerLink::repair_take`], plus [`ThresholdError::Frost`] when the delta
    /// is unreadable.
    pub fn answer_repair_take(
        &self,
        from: Seat,
        request: &crate::threshold::RepairTakeRequest,
    ) -> Result<crate::threshold::RepairTakeResponse, ThresholdError> {
        let lost = Seat::new(request.lost)?;
        let delta = repair::Delta::deserialize(&request.delta)
            .map_err(|err| ThresholdError::frost("reading the delta", &err))?;

        SignerLink::repair_take(self, lost, from, &delta)?;

        Ok(crate::threshold::RepairTakeResponse {})
    }

    /// One's own sigma, in wire form (ADR-0108).
    ///
    /// **The authorization does not lie here.** Who may ask is decided by the service
    /// over the connection's credential (determination 3) -- this method knows no
    /// connection, and a check that cannot see the caller would be one that checks
    /// nothing.
    ///
    /// # Errors
    ///
    /// As [`SignerLink::repair_sigma`].
    pub fn answer_repair_sigma(
        &self,
        request: &crate::threshold::RepairSigmaRequest,
    ) -> Result<crate::threshold::RepairSigmaResponse, ThresholdError> {
        let lost = Seat::new(request.lost)?;
        let sigma = SignerLink::repair_sigma(self, lost)?;

        Ok(crate::threshold::RepairSigmaResponse {
            sigma: sigma.serialize(),
        })
    }

    /// Abort a repair, in wire form.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] on an unusable seat number.
    pub fn answer_repair_abandon(
        &self,
        request: &crate::threshold::RepairAbandonRequest,
    ) -> Result<crate::threshold::RepairAbandonResponse, ThresholdError> {
        SignerLink::repair_abandon(self, Seat::new(request.lost)?);

        Ok(crate::threshold::RepairAbandonResponse {})
    }

    /// Refresh round 3 in wire form.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] when this seat does not stand in round 2;
    /// [`ThresholdError::Frost`] when `frost` refuses -- in there sits the case that a
    /// package does not fit its sender's binding.
    pub fn answer_refresh_finish(
        &self,
        request: &crate::threshold::RefreshFinishRequest,
    ) -> Result<crate::threshold::RefreshFinishResponse, ThresholdError> {
        let reached = SignerLink::refresh_finish(self, Epoch::new(request.epoch))?;

        Ok(crate::threshold::RefreshFinishResponse {
            seat: self.seat.number(),
            epoch: reached.epoch.number(),
            persisted: reached.persisted,
            group: serialized(&reached.group)?,
        })
    }

    /// Refresh, retiring the old generations in wire form (ADR-0107).
    ///
    /// # Errors
    ///
    /// [`ThresholdError`] when an old generation cannot be removed.
    pub fn answer_refresh_retire(
        &self,
        request: &crate::threshold::RefreshRetireRequest,
    ) -> Result<crate::threshold::RefreshRetireResponse, ThresholdError> {
        SignerLink::refresh_retire(self, Epoch::new(request.epoch))?;

        Ok(crate::threshold::RefreshRetireResponse {
            seat: self.seat.number(),
        })
    }

    /// Abort a refresh, in wire form.
    pub fn answer_refresh_abandon(
        &self,
        request: &crate::threshold::RefreshAbandonRequest,
    ) -> crate::threshold::RefreshAbandonResponse {
        SignerLink::refresh_abandon(self, Epoch::new(request.epoch));

        crate::threshold::RefreshAbandonResponse {}
    }

    /// How many commitments are open -- for the observation (ADR-0015).
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.inner
            .lock()
            .map_or(0, |guard| guard.participant.outstanding())
    }

    /// Round 1, without a wire.
    fn round_one(
        &self,
        session: SessionId,
        epoch: Epoch,
    ) -> Result<SigningCommitments, ThresholdError> {
        SignerLink::commit(self, session, epoch)
    }

    /// Round 2, without a wire.
    fn round_two(
        &self,
        session: SessionId,
        package: &SigningPackage,
    ) -> Result<SignatureShare, ThresholdError> {
        SignerLink::sign(self, session, package)
    }
}

impl SignerLink for LocalLink {
    fn seat(&self) -> Seat {
        self.seat
    }

    fn commit(
        &self,
        session: SessionId,
        epoch: Epoch,
    ) -> Result<SigningCommitments, ThresholdError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ThresholdError::Unreachable { seat: self.seat })?;
        let Inner {
            participant,
            entropy,
            refresh: _,
            repair: _,
        } = &mut *inner;

        participant.commit(session, epoch, entropy.as_mut())
    }

    fn sign(
        &self,
        session: SessionId,
        package: &SigningPackage,
    ) -> Result<SignatureShare, ThresholdError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ThresholdError::Unreachable { seat: self.seat })?;

        inner.participant.sign(session, package)
    }

    fn abandon(&self, session: SessionId) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.participant.abandon(session);
        }
    }

    fn refresh_start(&self, epoch: Epoch) -> Result<refresh::Broadcast, ThresholdError> {
        let mut inner = self.locked()?;
        let (state, broadcast) =
            refresh::start(self.seat, GroupShape::adr_0014(), inner.entropy.as_mut())?;
        // **A second start discards the first.** A left-behind state from an
        // aborted run must not block a new one; the coordinator is the only driver.
        inner.refresh = Some(Pending {
            epoch,
            stage: Stage::Started(state),
            inbox: BTreeMap::new(),
        });

        Ok(broadcast)
    }

    fn refresh_deal(
        &self,
        epoch: Epoch,
        broadcasts: &BTreeMap<Seat, refresh::Broadcast>,
    ) -> Result<(), ThresholdError> {
        let mut inner = self.locked()?;
        let outgoing = {
            let pending = inner.refresh.take().ok_or_else(|| ThresholdError::Shape {
                detail: format!("{} has begun no refresh", self.seat),
            })?;
            if pending.epoch != epoch {
                let running = pending.epoch.number();
                inner.refresh = Some(pending);
                return Err(ThresholdError::SessionEpoch {
                    session: format!("refresh at {}", self.seat),
                    running,
                    wanted: epoch.number(),
                });
            }
            let Pending {
                stage: Stage::Started(state),
                inbox,
                ..
            } = pending
            else {
                return Err(ThresholdError::Shape {
                    detail: format!("{} does not stand in round 1", self.seat),
                });
            };

            let (state, outgoing) = state.round2(broadcasts)?;
            // **The inbox travels along.** What arrived before one's own round 2
            // belongs to the same refresh.
            inner.refresh = Some(Pending {
                epoch,
                stage: Stage::Exchanged(state),
                inbox,
            });
            outgoing
        };
        drop(inner);

        // **The seat delivers itself**, over its own channels: what travels here
        // demands a confidential channel, and a coordinator that passed it through
        // would know every delta (ADR-0107). Whoever carries the packages on is this
        // method's caller -- in operation the signer service, which holds the peers.
        self.deal(epoch, &outgoing)
    }

    fn refresh_take(
        &self,
        epoch: Epoch,
        from: Seat,
        directed: &refresh::Directed,
    ) -> Result<(), ThresholdError> {
        let mut inner = self.locked()?;
        let Some(pending) = inner.refresh.as_mut() else {
            return Err(ThresholdError::Shape {
                detail: format!("{} has begun no refresh", self.seat),
            });
        };
        if pending.epoch != epoch {
            return Err(ThresholdError::SessionEpoch {
                session: format!("refresh at {}", self.seat),
                running: pending.epoch.number(),
                wanted: epoch.number(),
            });
        }

        // **Without regard for one's own round.** In a network there is no order: a
        // package arrives while this seat still stands in round 1.
        pending.inbox.insert(from, directed.clone());

        Ok(())
    }

    fn refresh_finish(&self, epoch: Epoch) -> Result<Reached, ThresholdError> {
        let mut inner = self.locked()?;
        let pending = inner.refresh.take().ok_or_else(|| ThresholdError::Shape {
            detail: format!("{} has begun no refresh", self.seat),
        })?;
        if pending.epoch != epoch {
            let running = pending.epoch.number();
            inner.refresh = Some(pending);
            return Err(ThresholdError::SessionEpoch {
                session: format!("refresh at {}", self.seat),
                running,
                wanted: epoch.number(),
            });
        }
        let Pending {
            stage: Stage::Exchanged(state),
            inbox,
            ..
        } = pending
        else {
            return Err(ThresholdError::Shape {
                detail: format!("{} does not stand in round 2", self.seat),
            });
        };

        let held = inner.participant.newest_material()?;
        let next = state.finish(&held, &inbox)?;
        inner
            .participant
            .stage_share(next.epoch(), next.share(), next.group())?;

        // **First lay it beside, then write.** The other way round the generation
        // would stand on the disk while this seat does not hold it -- and the next
        // start would find a generation nobody formed.
        //
        // **And whether it succeeded travels back** (determination 6): the
        // coordinator retires the old generation only when all five have the new one
        // on the disk.
        let persisted = match self.store.as_ref() {
            None => false,
            Some(dir) => match Material::save(
                dir,
                next.share(),
                next.group(),
                next.epoch(),
                // **The same custody under which it lies in memory** (ADR-0140): a
                // second source would be an opportunity to file a generation
                // unsealed.
                inner.participant.custody().as_ref(),
            ) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!(
                        seat = self.seat.number(),
                        epoch = next.epoch().number(),
                        error = %err,
                        "the new generation is not written -- it carries until the restart"
                    );

                    false
                }
            },
        };

        Ok(Reached {
            epoch: next.epoch(),
            group: next.group().clone(),
            persisted,
        })
    }

    fn refresh_retire(&self, epoch: Epoch) -> Result<(), ThresholdError> {
        let mut inner = self.locked()?;
        let below: Vec<Epoch> = inner
            .participant
            .epochs()
            .into_iter()
            .filter(|held| *held < epoch)
            .collect();
        if below.is_empty() {
            return Ok(());
        }

        // **First the disk, then memory.** The other way round the old generation
        // would come back at the next start, and an operator would take the retiring
        // for done.
        if let Some(dir) = self.store.as_ref() {
            for stale in &below {
                if let Err(err) = Material::remove(dir, *stale) {
                    // **Fail-soft and named**: a left-behind old generation is a
                    // finding and no outage -- the group goes on signing in the new
                    // one. But as long as it lies, the refresh has no effect.
                    tracing::warn!(
                        seat = self.seat.number(),
                        epoch = stale.number(),
                        error = %err,
                        "the old generation still lies on the disk -- until then its \
                         share applies"
                    );

                    return Err(err);
                }
            }
        }

        inner.participant.retire_below(epoch);
        tracing::info!(
            seat = self.seat.number(),
            below = epoch.number(),
            retired = below.len(),
            "old generations retired (ADR-0107)"
        );

        Ok(())
    }

    fn repair_deal(&self, lost: Seat, helpers: &[Seat]) -> Result<(), ThresholdError> {
        if helpers.contains(&lost) {
            return Err(ThresholdError::Repair {
                detail: format!(
                    "{lost} stands among its own helpers -- whoever has the share \
                     does not need it"
                ),
            });
        }
        if lost == self.seat {
            return Err(ThresholdError::Repair {
                detail: format!(
                    "{} shall repair itself -- whoever has its share does not need \
                     it (ADR-0108)",
                    self.seat
                ),
            });
        }

        let outgoing = {
            let mut inner = self.locked()?;
            let material = inner.participant.newest_material()?;
            let Inner {
                ref mut entropy, ..
            } = *inner;
            let outgoing =
                repair::helper_deltas(helpers, material.share(), lost, entropy.as_mut())?;

            // **The inbox travels along** -- literally the same rule as in round 2
            // of the refresh, and here forced by a witness: the repair is start
            // **and** delivery in one call, so the first helper has already
            // delivered to the second before it begins. Whoever empties the inbox in
            // the process loses `t-1` deltas, and step 3 yields a share that looks
            // valid and is wrong (the finding `restore` catches).
            //
            // **For another lost seat it is discarded**: that is the doctrine of
            // ADR-0108 determination 4, and an inbox from a run for another seat does
            // not belong to this one.
            let mut inbox: BTreeMap<Seat, repair::Delta> = match inner.repair.take() {
                Some(open) if open.lost == lost => open.inbox,
                _ => BTreeMap::new(),
            };

            // One's own delta stands **here** in the inbox: `helper_deltas` produces
            // one per helper, and this seat is one of them. Sending it to itself
            // would be a way over a channel that begins and ends at it.
            if let Some(own) = outgoing.get(&self.seat) {
                inbox.insert(self.seat, *own);
            }
            inner.repair = Some(Repairing { lost, inbox });

            outgoing
        };

        self.deal_repair(lost, &outgoing)
    }

    fn repair_take(
        &self,
        lost: Seat,
        from: Seat,
        delta: &repair::Delta,
    ) -> Result<(), ThresholdError> {
        let mut inner = self.locked()?;

        // **A delta may arrive before one's own step 1**, and that is, measured, the
        // normal case: `repair_deal` is start **and** delivery in one call, so the
        // first helper delivers to the second before it has begun. Unlike at the
        // refresh there is no state here that one's own round would first have to
        // produce -- the inbox is everything a helper needs for step 2 (ADR-0108).
        //
        // **And a delta for another seat displaces the run.** That is ADR-0108
        // determination 4 literally: *a left-behind state from an aborted run must
        // not block a new one.*
        //
        // The cautious version -- refuse, so that no peer can abort a running repair
        // -- was built first and is **wrong**: a delta for another seat *is* the
        // message that a new run has begun elsewhere, and whoever refuses it locks
        // exactly that one out. The price is named and the same as in determination
        // 4: a helper can break a run -- an operator sets it up anew, and no material
        // is given away in the process (a delta alone says nothing).
        let open = match inner.repair.as_mut() {
            Some(open) if open.lost == lost => open,
            _ => inner.repair.insert(Repairing {
                lost,
                inbox: BTreeMap::new(),
            }),
        };

        open.inbox.insert(from, *delta);

        Ok(())
    }

    fn repair_sigma(&self, lost: Seat) -> Result<repair::Sigma, ThresholdError> {
        let inner = self.locked()?;
        let Some(repairing) = inner.repair.as_ref() else {
            return Err(ThresholdError::Repair {
                detail: format!("{} has begun no repair", self.seat),
            });
        };
        if repairing.lost != lost {
            return Err(ThresholdError::Repair {
                detail: format!(
                    "{} has begun no repair for {lost} -- but for {}",
                    self.seat, repairing.lost
                ),
            });
        }

        let deltas: Vec<repair::Delta> = repairing.inbox.values().copied().collect();

        Ok(repair::combine_deltas(&deltas))
    }

    fn repair_abandon(&self, lost: Seat) {
        if let Ok(mut inner) = self.locked()
            && inner.repair.as_ref().is_some_and(|open| open.lost == lost)
        {
            inner.repair = None;
        }
    }

    fn refresh_abandon(&self, epoch: Epoch) {
        if let Ok(mut inner) = self.inner.lock()
            && inner.refresh.as_ref().is_some_and(|p| p.epoch == epoch)
        {
            inner.refresh = None;
        }
    }
}

/// An opened signature round.
///
/// It holds what stands fixed between the rounds: the session, the participating
/// seats and the package that goes to them.
///
/// **And it clears itself away when it falls.** A round reserves `t` nonce sessions,
/// and those carry nonce secrets in the vault (ADR-0014). Measured, five discarded
/// rounds left `[5, 5, 5, 0, 0]` open sessions per seat -- they grew linearly, and
/// nobody cleared them away. The discipline therefore lies **in the structure** and
/// not with the caller: the same construction as `Thaw` at the freezing of a volume
/// (ADR-0099) and as the nonce vault itself.
///
/// It is **not** `Clone`: a clone that falls would clear the original's session
/// away.
///
/// The `Drop` carries on the panic path too only since ADR-0082 -- with
/// `panic = "abort"` there would be no unwinding.
#[derive(Debug)]
pub struct Round<'a> {
    signer: &'a ThresholdSigner,
    session: SessionId,
    epoch: Epoch,
    seats: Vec<Seat>,
    package: SigningPackage,
    /// Whether it has already been settled -- set by
    /// [`ThresholdSigner::close_round`], in **both** outcomes: there it is spent on
    /// success and cleared away on failure.
    settled: std::cell::Cell<bool>,
}

impl Drop for Round<'_> {
    fn drop(&mut self) {
        if !self.settled.get() {
            self.signer.abandon(self.session, &self.seats);
        }
    }
}

impl Round<'_> {
    /// The session.
    #[must_use]
    pub fn session(&self) -> SessionId {
        self.session
    }

    /// In which generation of the shares the round runs.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The participating seats.
    #[must_use]
    pub fn seats(&self) -> &[Seat] {
        &self.seats
    }

    /// The message at issue.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        self.package.message()
    }
}

/// The signing CA as a threshold group.
///
/// From outside it looks like an Ed25519 key: 32 bytes public, 64 bytes signature.
/// Inside it is five seats of which three suffice -- and none ever holds the full
/// key.
pub struct ThresholdSigner {
    /// The group keys per generation.
    ///
    /// **Mutable**, because a refresh adds a generation and the methods take `&self`
    /// (the signer stands behind an `Arc` in `rcgen::SigningKey`, 7a). The
    /// **verifying key** never changes in the process -- it lies beside and is
    /// checked at the addition.
    groups: std::sync::RwLock<BTreeMap<Epoch, PublicKeyPackage>>,
    verifying_key: Vec<u8>,
    shape: GroupShape,
    links: Vec<Arc<dyn SignerLink>>,
    sessions: AtomicU64,
    last_failure: Mutex<Option<String>>,
}

impl std::fmt::Debug for ThresholdSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdSigner")
            .field("shape", &self.shape)
            .field("epochs", &self.epochs().len())
            .field("links", &self.links.len())
            .finish_non_exhaustive()
    }
}

impl ThresholdSigner {
    /// A group over these seats, in this generation.
    ///
    /// # Errors
    ///
    /// As [`ThresholdSigner::over`].
    pub fn new(
        group: PublicKeyPackage,
        shape: GroupShape,
        links: Vec<Arc<dyn SignerLink>>,
    ) -> Result<Self, ThresholdError> {
        Self::over(
            std::iter::once((Epoch::GENESIS, group)).collect(),
            shape,
            links,
        )
    }

    /// A group over these seats, with **several** generations.
    ///
    /// To the aggregation belongs the group key of **the same** epoch as the shares:
    /// what changes at the refresh are the `verifying_shares` (ADR-0107). A single
    /// one for all epochs would be exactly the mixed case determination 3 avoids.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] when no generation is named, the generations carry
    /// different verifying keys -- then it is not **one** group --, the group key is
    /// unreadable or the threshold does not fit the shape;
    /// [`ThresholdError::Threshold`] when the named seats cannot reach the threshold
    /// from the outset.
    pub fn over(
        groups: BTreeMap<Epoch, PublicKeyPackage>,
        shape: GroupShape,
        links: Vec<Arc<dyn SignerLink>>,
    ) -> Result<Self, ThresholdError> {
        let Some(newest) = groups.values().next_back() else {
            return Err(ThresholdError::Shape {
                detail: "a group without a generation cannot sign".to_owned(),
            });
        };

        for group in groups.values() {
            if let Some(min) = group.min_signers()
                && min != shape.threshold()
            {
                return Err(ThresholdError::Shape {
                    detail: format!(
                        "the group key was produced with threshold {min}, demanded is \
                         {} -- the threshold is frozen with the DKG (ADR-0014)",
                        shape.threshold()
                    ),
                });
            }
        }

        let mut seen = std::collections::BTreeSet::new();
        for link in &links {
            let seat = link.seat();
            if !shape.holds(seat) {
                return Err(ThresholdError::UnknownSeat {
                    number: seat.number(),
                });
            }
            if !seen.insert(seat) {
                // Two links to the same seat would look like two seats but would be
                // one: the signature package holds one commitment per identifier, the
                // second would overwrite the first. The threshold would thereby only
                // seemingly be reached.
                return Err(ThresholdError::Shape {
                    detail: format!("{seat} is represented twice"),
                });
            }
        }

        let count = u16::try_from(seen.len()).unwrap_or(u16::MAX);
        if count < shape.threshold() {
            return Err(ThresholdError::Threshold {
                needed: shape.threshold(),
                got: count,
            });
        }

        let verifying_key = newest
            .verifying_key()
            .serialize()
            .map_err(|err| ThresholdError::frost("reading the group key", &err))?;

        // The **verifying key** survives a refresh byte for byte (measured,
        // ADR-0107). If it does not, there are two groups in one signer -- and the
        // intermediate from the root applies to at most one.
        for (epoch, group) in &groups {
            let key = group
                .verifying_key()
                .serialize()
                .map_err(|err| ThresholdError::frost("reading the group key", &err))?;
            if key != verifying_key {
                return Err(ThresholdError::Shape {
                    detail: format!(
                        "{epoch} carries a different verifying key -- that is two \
                         groups and not one"
                    ),
                });
            }
        }

        Ok(Self {
            groups: std::sync::RwLock::new(groups),
            verifying_key,
            shape,
            links,
            sessions: AtomicU64::new(0),
            last_failure: Mutex::new(None),
        })
    }

    /// The group key -- 32 bytes, an ordinary Ed25519 key.
    #[must_use]
    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying_key
    }

    /// The group's shape.
    #[must_use]
    pub fn shape(&self) -> GroupShape {
        self.shape
    }

    /// Which generations this coordinator knows, ascending.
    #[must_use]
    pub fn epochs(&self) -> Vec<Epoch> {
        self.groups
            .read()
            .map(|groups| groups.keys().copied().collect())
            .unwrap_or_default()
    }

    /// To which seats a link is **entered**, ascending.
    ///
    /// The input of the pre-check from [`Self::refresh`], made readable: it demands
    /// all the seats of the group, and without this information an operator learns
    /// that only when a refresh aborts.
    ///
    /// **Entered does not mean reachable.** Whether a seat answers is said only by a
    /// call; here stands with whom this process would try at all.
    ///
    /// **One's own seat counts along.** Measured, a coordinator holds five links --
    /// its own [`LocalLink`] and four [`GrpcLink`](crate::threshold::GrpcLink) --,
    /// and that must be so: one's own share is one of the `t` commitments. The
    /// setting `--signer`, by contrast, names only the **other four**; whoever
    /// compares the two numbers finds a difference of one that is none.
    #[must_use]
    pub fn linked(&self) -> Vec<Seat> {
        let mut seats: Vec<Seat> = self.links.iter().map(|link| link.seat()).collect();
        seats.sort_unstable();

        seats
    }

    fn group_at(&self, epoch: Epoch) -> Option<PublicKeyPackage> {
        self.groups
            .read()
            .ok()
            .and_then(|groups| groups.get(&epoch).cloned())
    }

    /// The last cause that got lost behind `rcgen::SigningKey::sign`.
    ///
    /// `rcgen::Error::RemoteKeyError` carries no reason. So that a failure at the
    /// issuance of an intermediate stays explainable nevertheless, the actual cause
    /// is filed here.
    #[must_use]
    pub fn last_failure(&self) -> Option<String> {
        self.last_failure.lock().ok().and_then(|slot| slot.clone())
    }

    /// Round 1: collect commitments until the threshold stands.
    ///
    /// Tries the **highest** generation this process holds and falls back on the
    /// previous one when no `t` seats come together for it (ADR-0107, determination
    /// 4). The fallback is one attempt per held generation and no loop over
    /// arbitrarily many: per determination 6 two are held.
    ///
    /// Seats are asked in turn and skipped when they do not answer. Asking goes on
    /// only until the threshold is reached -- every further commitment would be a
    /// nonce that would be spent without being needed.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Threshold`] when in **no** generation enough seats answer.
    /// The commitments already collected are cleared away in the process.
    pub fn open_round(&self, message: &[u8]) -> Result<Round<'_>, ThresholdError> {
        let mut last = ThresholdError::Threshold {
            needed: self.shape.threshold(),
            got: 0,
        };

        for epoch in self.epochs().into_iter().rev() {
            match self.open_round_at(message, epoch) {
                Ok(round) => return Ok(round),
                Err(err) => last = err,
            }
        }

        Err(last)
    }

    /// Round 1 in exactly this generation.
    ///
    /// # Why not public
    ///
    /// A round reserves `t` **nonce sessions** -- at the place ADR-0014 calls the
    /// most dangerous of this system. The only caller is [`Self::open_round`] above
    /// it, which tries the generations from the highest downwards (ADR-0107,
    /// determination 4); there is no reason to choose a generation from outside.
    ///
    /// The `Drop` at [`Round`] takes a discarded round's sessions back from it -- but
    /// that is the **second** layer: the first is that nobody outside can open one.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Threshold`] when too few seats hold this generation and
    /// answer.
    fn open_round_at(&self, message: &[u8], epoch: Epoch) -> Result<Round<'_>, ThresholdError> {
        let session = SessionId::from(self.sessions.fetch_add(1, Ordering::SeqCst));
        let needed = usize::from(self.shape.threshold());

        let mut seats = Vec::with_capacity(needed);
        let mut commitments = BTreeMap::new();
        for link in &self.links {
            if seats.len() == needed {
                break;
            }
            match link.commit(session, epoch) {
                Ok(commitment) => {
                    seats.push(link.seat());
                    commitments.insert(link.seat().identifier(), commitment);
                }
                Err(err) => self.remember(&err),
            }
        }

        if seats.len() < needed {
            self.abandon(session, &seats);
            return Err(ThresholdError::Threshold {
                needed: self.shape.threshold(),
                got: u16::try_from(seats.len()).unwrap_or(u16::MAX),
            });
        }

        Ok(Round {
            signer: self,
            session,
            epoch,
            seats,
            package: SigningPackage::new(commitments, message),
            settled: std::cell::Cell::new(false),
        })
    }

    /// Round 2: collect the shares and aggregate them into the group signature.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Threshold`] when not **all** the seats of the round deliver
    /// -- unlike in round 1 none can be replaced here any more, because its
    /// commitment stands in the package. [`ThresholdError::Frost`] when the shares do
    /// not fit together; in there sits `frost`'s cheat detection too, which names the
    /// guilty seat.
    pub fn close_round(&self, round: &Round<'_>) -> Result<Vec<u8>, ThresholdError> {
        // **Settled is settled**, in both outcomes: on success the nonces are spent,
        // on failure the branch below clears away.
        //
        // This line has **no** witness, and that is measured instead of presumed:
        // without it `Round`'s `Drop` clears a second time, and `Participant::abandon`
        // is a no-op on an unknown session (`self.open.remove(&session)` gives `None`)
        // -- the counter-check hit nothing. It stays because it expresses the intent
        // and survives the day on which `abandon` is no longer idempotent; it is
        // expressly not to be read as a security layer.
        round.settled.set(true);

        let mut shares = BTreeMap::new();
        for seat in &round.seats {
            let Some(link) = self.link_for(*seat) else {
                continue;
            };
            if let Ok(share) = link.sign(round.session, &round.package) {
                shares.insert(seat.identifier(), share);
            }
        }

        if shares.len() < round.seats.len() {
            self.abandon(round.session, &round.seats);
            return Err(ThresholdError::Threshold {
                needed: u16::try_from(round.seats.len()).unwrap_or(u16::MAX),
                got: u16::try_from(shares.len()).unwrap_or(u16::MAX),
            });
        }

        // **This lookup carries the diagnosis, not the correctness.** Measured,
        // shares from epoch 0 against the group key of epoch 1 yield a **valid**
        // signature: `frost::aggregate` checks the sum against the `verifying_key`,
        // and that survives a refresh byte for byte (ADR-0107). The
        // `verifying_shares` -- which very much do change -- it draws on only to name
        // a **culprit**.
        //
        // What carries the correctness is the gate at the epoch in round 1 (ADR-0107,
        // determination 4): it does not let mixed shares into a package at all.
        // Whoever weakens it because "the aggregation catches it anyway" is mistaken
        // -- it does not catch it.
        let group = self
            .group_at(round.epoch)
            .ok_or_else(|| ThresholdError::Shape {
                detail: format!("there is no group key for {}", round.epoch),
            })?;

        let signature = frost_ed25519::aggregate(&round.package, &shares, &group)
            .map_err(|err| ThresholdError::frost("aggregating the shares", &err))?;

        signature
            .serialize()
            .map_err(|err| ThresholdError::frost("reading the signature", &err))
    }

    /// Runs a refresh over **all** the seats of the group (ADR-0107).
    ///
    /// Three rounds, and round 2 goes **from seat to seat**: `refresh_deal` returns
    /// only when this seat has delivered its directed packages. The coordinator never
    /// sees them -- if it saw them, it would know every delta and be the trusted
    /// dealer ADR-0107 rejected.
    ///
    /// Afterwards every seat holds **both** generations (determination 3). The old
    /// one is expressly not retired here.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Threshold`] when not **all** the seats of the group are
    /// reachable -- a refresh with fewer would be a silent shrinking (measured,
    /// ADR-0107), and the abort comes **before** round 1 so that the report names the
    /// missing seat and not a failed round. Otherwise as the three rounds; a failure
    /// clears the begun run away at all the seats.
    pub fn refresh(&self) -> Result<Epoch, ThresholdError> {
        let places = self.shape.places();
        let missing: Vec<String> = places
            .iter()
            .filter(|seat| self.link_for(**seat).is_none())
            .map(|seat| seat.number().to_string())
            .collect();
        // **An information and a saving, no layer.** Measured, a refresh without all
        // the seats aborts without this check too -- but then only in round 1 and
        // with "seat 5 did not answer", which an operator reads as a network problem.
        // Clearing away happens anyway (`refresh_abandon` in the error path).
        // **What it does not see: the reachability.** What is checked is whether a
        // link is *entered* -- a seat that is entered and does not answer falls only
        // in round 1. The group nevertheless stays unchanged, and that through the
        // abort path below and not through this check.
        if !missing.is_empty() {
            return Err(ThresholdError::Shape {
                detail: format!(
                    "a refresh needs all {} seats; no link to [{}] -- with fewer \
                     the group would be shrunk (ADR-0107)",
                    places.len(),
                    missing.join(", ")
                ),
            });
        }

        let Some(current) = self.epochs().into_iter().next_back() else {
            return Err(ThresholdError::Shape {
                detail: "a group without a generation cannot be refreshed".to_owned(),
            });
        };
        let next = current.next();
        if next == current {
            return Err(ThresholdError::Shape {
                detail: format!("{current} is the last -- the epoch does not run on"),
            });
        }

        match self.run_refresh(&places, next) {
            Ok(()) => Ok(next),
            Err(err) => {
                for seat in &places {
                    if let Some(link) = self.link_for(*seat) {
                        link.refresh_abandon(next);
                    }
                }

                Err(err)
            }
        }
    }

    fn run_refresh(&self, places: &[Seat], next: Epoch) -> Result<(), ThresholdError> {
        let mut agreed: Option<PublicKeyPackage> = None;
        let mut on_disk = true;
        let mut broadcasts = BTreeMap::new();
        for seat in places {
            let link = self
                .link_for(*seat)
                .ok_or(ThresholdError::Unreachable { seat: *seat })?;
            broadcasts.insert(*seat, link.refresh_start(next)?);
        }

        for seat in places {
            let link = self
                .link_for(*seat)
                .ok_or(ThresholdError::Unreachable { seat: *seat })?;
            let others: BTreeMap<Seat, refresh::Broadcast> = broadcasts
                .iter()
                .filter(|&(other, _)| other != seat)
                .map(|(other, broadcast)| (*other, broadcast.clone()))
                .collect();
            link.refresh_deal(next, &others)?;
        }

        for seat in places {
            let link = self
                .link_for(*seat)
                .ok_or(ThresholdError::Unreachable { seat: *seat })?;
            let reached = link.refresh_finish(next)?;
            if reached.epoch != next {
                return Err(ThresholdError::SessionEpoch {
                    session: format!("refresh at {seat}"),
                    running: reached.epoch.number(),
                    wanted: next.number(),
                });
            }
            if !reached.persisted {
                // **No reason to abort**, but determination 6 thereby falls away:
                // the old generation stays lying, because this seat would not have
                // the new one after a restart.
                on_disk = false;
                tracing::warn!(
                    seat = seat.number(),
                    epoch = next.number(),
                    "the new generation does not lie on the disk at this seat -- \
                     the old one is not retired"
                );
            }
            let group = reached.group;

            // **All five must name the same one.** The group key is public, but it
            // comes from five seats -- and a seat that names a different one would
            // bring the coordinator to aggregate against foreign
            // `verifying_shares`.
            let bytes = serialized(&group)?;
            match &agreed {
                None => agreed = Some(group),
                Some(first) if serialized(first)? == bytes => {}
                Some(_) => {
                    return Err(ThresholdError::Shape {
                        detail: format!(
                            "{seat} names a different group key than the seats \
                             before it"
                        ),
                    });
                }
            }
        }

        let Some(group) = agreed else {
            return Err(ThresholdError::Shape {
                detail: "no seat named a group key".to_owned(),
            });
        };

        // And the **verifying key** must be the old one: it survives a refresh byte
        // for byte (ADR-0107), and if it did not, the intermediate from the root
        // would be done for.
        let key = group
            .verifying_key()
            .serialize()
            .map_err(|err| ThresholdError::frost("reading the group key", &err))?;
        if key != self.verifying_key {
            return Err(ThresholdError::Shape {
                detail: "the refresh changed the verifying key -- the intermediate \
                         from the root does not apply to it"
                    .to_owned(),
            });
        }

        self.groups
            .write()
            .map_err(|_| ThresholdError::Shape {
                detail: "the generations are not writable".to_owned(),
            })?
            .insert(next, group);

        // **Only now retire the old one** (determination 6), and only when all five
        // have the new one on the disk: as long as one seat holds it only in memory,
        // the old one is the only one in which t come together after a restart.
        //
        // And only here does the refresh have its **effect**: as long as the old one
        // lies, t seats can go on signing in it, and a betrayed share still
        // applies.
        if on_disk {
            self.retire(places, next);
        } else {
            tracing::warn!(
                epoch = next.number(),
                "the old generations stay lying -- until then their share applies"
            );
        }

        Ok(())
    }

    /// Retire every generation below `keep` at all the seats -- **best effort**.
    ///
    /// A seat that fails at it keeps its old generation; the group goes on signing in
    /// the new one. It is reported, because until then the refresh is without
    /// effect.
    fn retire(&self, places: &[Seat], keep: Epoch) {
        // One's own stock first: what this coordinator no longer offers, nobody can
        // have opened in the old generation any more.
        if let Ok(mut groups) = self.groups.write() {
            groups.retain(|held, _| *held >= keep);
        }

        for seat in places {
            if let Some(link) = self.link_for(*seat)
                && let Err(err) = link.refresh_retire(keep)
            {
                tracing::warn!(
                    seat = seat.number(),
                    error = %err,
                    "old generations not retired"
                );
            }
        }
    }

    /// Both rounds: a group signature over the message.
    ///
    /// # Errors
    ///
    /// As [`ThresholdSigner::open_round`] and [`ThresholdSigner::close_round`].
    pub fn sign_with_group(&self, message: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        let round = self.open_round(message)?;

        self.close_round(&round)
    }

    fn link_for(&self, seat: Seat) -> Option<&Arc<dyn SignerLink>> {
        self.links.iter().find(|link| link.seat() == seat)
    }

    fn abandon(&self, session: SessionId, seats: &[Seat]) {
        for seat in seats {
            if let Some(link) = self.link_for(*seat) {
                link.abandon(session);
            }
        }
    }

    fn remember(&self, err: &ThresholdError) {
        if let Ok(mut slot) = self.last_failure.lock() {
            *slot = Some(err.to_string());
        }
    }
}

impl rcgen::PublicKeyData for ThresholdSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.verifying_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        // RFC 8410: a FROST(Ed25519) group signature is an Ed25519 signature.
        // Exactly on that rests ADR-0014's rationale that rustls/webpki verify the
        // chain without a special path.
        &rcgen::PKCS_ED25519
    }
}

impl rcgen::SigningKey for ThresholdSigner {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.sign_with_group(msg).map_err(|err| {
            self.remember(&err);
            rcgen::Error::RemoteKeyError
        })
    }
}

fn serialized(group: &PublicKeyPackage) -> Result<Vec<u8>, ThresholdError> {
    group
        .serialize()
        .map_err(|err| ThresholdError::frost("writing the group key", &err))
}
