//! Tooling for the threshold-signing tests.
//!
//! Two things stand here that belong in no production path: a seeded entropy source
//! and a custody that counts along. Both are expressly test rig -- the seeded source
//! above all, for in operation a predictable nonce is exactly the error this phase
//! tests against.

// The module is included by four test binaries, and each uses a different slice.
// `dead_code` and `unreachable_pub` therefore report something different per binary
// -- neither says anything here.
#![allow(dead_code, unreachable_pub)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tg_identity::threshold::{
    Entropy, Epoch, GroupShape, KeyPackage, LocalLink, Participant, PlainCustody, PublicKeyPackage,
    Reached, SealedShare, Seat, SessionId, ShareCustody, SignatureShare, SignerLink,
    SigningCommitments, SigningPackage, ThresholdError, ThresholdSigner, dkg, repair,
};

/// A seeded entropy source -- **only for the test rig**.
///
/// xorshift64*, the same generator as in the fuzz runs of `tg-defs` and
/// `tg-consensus`. It is not cryptographic, and that is exactly the point here: a run
/// reproducible from its seed can be replayed deterministically and its inputs
/// inspected after the fact. In operation `OsEntropy` stands at this place.
pub struct SeededEntropy {
    state: u64,
}

impl SeededEntropy {
    /// Creates a generator seeded with `seed`.
    ///
    /// The low bit of `seed` is forced to `1`, since a xorshift generator whose
    /// state reaches zero locks up and produces only zeroes forever after.
    pub fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    /// A stream of its own for a further seat.
    ///
    /// Every seat needs its **own** stream: FROST derives the nonce from share and
    /// randomness, and two seats with the same stream are admittedly different (the
    /// shares differ), but the separation expressly belongs here -- in operation every
    /// seat is a process of its own with its own `OsRng`.
    ///
    /// Returns a new generator, seeded from a value drawn from `self`.
    pub fn fork(&mut self) -> Self {
        Self::new(self.next())
    }

    /// Advances the xorshift64* state and returns the next pseudo-random word.
    ///
    /// Mutates the internal state, so the next call yields a different value.
    fn next(&mut self) -> u64 {
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        self.state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Draws a pseudo-random index strictly below `bound`.
    ///
    /// Returns a value in `0..bound`, computed by reducing the next generated word
    /// modulo `bound`.
    ///
    /// # Panics
    ///
    /// Panics if `bound` is `0`, or if the reduced value does not fit in a `usize`
    /// (unreachable on any platform where `usize` is at least 32 bits wide).
    pub fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("fits")
    }
}

impl Entropy for SeededEntropy {
    /// Fills `dest` with pseudo-random bytes drawn from the generator.
    ///
    /// Generates one 64-bit word per 8-byte chunk of `dest`, so the output is fully
    /// determined by the generator's seed and call history.
    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

/// A custody that counts along -- otherwise it would not be checkable whether the
/// seam is traversed at all.
#[derive(Debug, Default)]
pub struct CountingCustody {
    inner: PlainCustody,
    seals: AtomicUsize,
    unseals: AtomicUsize,
}

impl CountingCustody {
    /// Returns how many times `seal` has been called so far.
    pub fn seals(&self) -> usize {
        self.seals.load(Ordering::SeqCst)
    }

    /// Returns how many times `unseal` has been called so far.
    pub fn unseals(&self) -> usize {
        self.unseals.load(Ordering::SeqCst)
    }
}

impl ShareCustody for CountingCustody {
    /// Seals `share` for `seat` via the wrapped `PlainCustody`, counting the call.
    ///
    /// # Errors
    ///
    /// Propagates any error the wrapped custody's `seal` returns.
    fn seal(&self, seat: Seat, share: &KeyPackage) -> Result<SealedShare, ThresholdError> {
        self.seals.fetch_add(1, Ordering::SeqCst);
        self.inner.seal(seat, share)
    }

    /// Unseals `sealed` via the wrapped `PlainCustody`, counting the call.
    ///
    /// # Errors
    ///
    /// Propagates any error the wrapped custody's `unseal` returns.
    fn unseal(&self, sealed: &SealedShare) -> Result<KeyPackage, ThresholdError> {
        self.unseals.fetch_add(1, Ordering::SeqCst);
        self.inner.unseal(sealed)
    }
}

/// A seat that does not answer.
#[derive(Debug)]
pub struct DeadLink {
    seat: Seat,
}

impl DeadLink {
    /// Creates a link for `seat` that answers every call with an unreachable error.
    pub fn new(seat: Seat) -> Self {
        Self { seat }
    }
}

impl SignerLink for DeadLink {
    /// Returns the seat this dead link stands in for.
    fn seat(&self) -> Seat {
        self.seat
    }

    /// Refuses to produce signing commitments, simulating an unreachable seat
    /// during round 1 of signing.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn commit(
        &self,
        _session: SessionId,
        _epoch: Epoch,
    ) -> Result<SigningCommitments, ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Refuses to produce a signature share, simulating an unreachable seat
    /// during round 2 of signing.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn sign(
        &self,
        _session: SessionId,
        _package: &SigningPackage,
    ) -> Result<SignatureShare, ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Does nothing: a seat that never answered has no session state to release.
    fn abandon(&self, _session: SessionId) {}

    /// Refuses to start a proactive refresh round, simulating an unreachable seat.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn refresh_start(
        &self,
        _epoch: Epoch,
    ) -> Result<tg_identity::threshold::refresh::Broadcast, ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Refuses to accept the other seats' refresh broadcasts.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn refresh_deal(
        &self,
        _epoch: Epoch,
        _broadcasts: &std::collections::BTreeMap<Seat, tg_identity::threshold::refresh::Broadcast>,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Refuses to accept a directed refresh delta from another seat.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn refresh_take(
        &self,
        _epoch: Epoch,
        _from: Seat,
        _directed: &tg_identity::threshold::refresh::Directed,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Refuses to retire the previous epoch's share material after a refresh.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn refresh_retire(&self, _epoch: Epoch) -> Result<(), ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Refuses to conclude the refresh round.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn refresh_finish(&self, _epoch: Epoch) -> Result<Reached, ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Does nothing: a seat that never answered has no refresh state to release.
    fn refresh_abandon(&self, _epoch: Epoch) {}
    /// Refuses to deal repair shares to the helpers reconstructing a lost seat.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn repair_deal(&self, _lost: Seat, _helpers: &[Seat]) -> Result<(), ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Refuses to accept a repair delta from another helper.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn repair_take(
        &self,
        _lost: Seat,
        _from: Seat,
        _delta: &repair::Delta,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Refuses to produce its repair contribution (sigma) for a lost seat.
    ///
    /// # Errors
    ///
    /// Always returns `ThresholdError::Unreachable`.
    fn repair_sigma(&self, _lost: Seat) -> Result<repair::Sigma, ThresholdError> {
        Err(ThresholdError::Unreachable { seat: self.seat })
    }

    /// Does nothing: a seat that never answered has no repair state to release.
    fn repair_abandon(&self, _lost: Seat) {}
}

/// A seat that can be switched off -- **on two axes**.
///
/// `take_down` takes it off the network entirely; `mute_signing` lets it **commit**
/// and refuse afterwards. The second axis is the more interesting one: there the
/// nonce sessions of the whole round are already reserved, and whether they are
/// cleared away is decided only by round 2.
///
/// A second wrapper beside it would be two versions of the same dummy.
#[derive(Debug)]
pub struct ToggleLink {
    inner: LocalLink,
    up: AtomicBool,
    signing: AtomicBool,
}

impl ToggleLink {
    /// Wraps a real `LocalLink`, starting out reachable and willing to sign.
    pub fn new(inner: LocalLink) -> Self {
        Self {
            inner,
            up: AtomicBool::new(true),
            signing: AtomicBool::new(true),
        }
    }

    /// Switches the seat off entirely: every subsequent call reports it as
    /// unreachable, on both axes.
    pub fn take_down(&self) {
        self.up.store(false, Ordering::SeqCst);
    }

    /// Commit yes, sign no.
    pub fn mute_signing(&self) {
        self.signing.store(false, Ordering::SeqCst);
    }

    /// How many nonce sessions this seat holds open.
    pub fn outstanding(&self) -> usize {
        self.inner.outstanding()
    }

    /// Checks whether the seat is still switched on.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` once `take_down` has been called.
    fn check(&self) -> Result<(), ThresholdError> {
        if self.up.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ThresholdError::Unreachable {
                seat: self.inner.seat(),
            })
        }
    }
}

impl SignerLink for ToggleLink {
    /// Returns the seat of the wrapped link.
    fn seat(&self) -> Seat {
        self.inner.seat()
    }

    /// Produces signing commitments via the wrapped link, unless the seat has been
    /// switched off.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` if `take_down` has been called;
    /// otherwise propagates any error from the wrapped link.
    fn commit(
        &self,
        session: SessionId,
        epoch: Epoch,
    ) -> Result<SigningCommitments, ThresholdError> {
        self.check()?;
        self.inner.commit(session, epoch)
    }

    /// Produces a signature share via the wrapped link, unless the seat has been
    /// switched off or `mute_signing` has been called since the last commit.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` in either case; otherwise propagates
    /// any error from the wrapped link.
    fn sign(
        &self,
        session: SessionId,
        package: &SigningPackage,
    ) -> Result<SignatureShare, ThresholdError> {
        self.check()?;
        if !self.signing.load(Ordering::SeqCst) {
            return Err(ThresholdError::Unreachable {
                seat: self.inner.seat(),
            });
        }
        self.inner.sign(session, package)
    }

    /// Releases the nonce session for `session` on the wrapped link.
    fn abandon(&self, session: SessionId) {
        self.inner.abandon(session);
    }

    /// Starts a proactive refresh round via the wrapped link, unless the seat has
    /// been switched off.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` if `take_down` has been called;
    /// otherwise propagates any error from the wrapped link.
    fn refresh_start(
        &self,
        epoch: Epoch,
    ) -> Result<tg_identity::threshold::refresh::Broadcast, ThresholdError> {
        self.check()?;
        self.inner.refresh_start(epoch)
    }

    /// Accepts the other seats' refresh broadcasts via the wrapped link, unless
    /// the seat has been switched off.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` if `take_down` has been called;
    /// otherwise propagates any error from the wrapped link.
    fn refresh_deal(
        &self,
        epoch: Epoch,
        broadcasts: &std::collections::BTreeMap<Seat, tg_identity::threshold::refresh::Broadcast>,
    ) -> Result<(), ThresholdError> {
        self.check()?;
        self.inner.refresh_deal(epoch, broadcasts)
    }

    /// Accepts a directed refresh delta from `from` via the wrapped link, unless
    /// the seat has been switched off.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` if `take_down` has been called;
    /// otherwise propagates any error from the wrapped link.
    fn refresh_take(
        &self,
        epoch: Epoch,
        from: Seat,
        directed: &tg_identity::threshold::refresh::Directed,
    ) -> Result<(), ThresholdError> {
        self.check()?;
        self.inner.refresh_take(epoch, from, directed)
    }

    /// Retires the previous epoch's share material via the wrapped link.
    ///
    /// Runs regardless of whether the seat has been switched off: retirement is
    /// local bookkeeping, not a network round the seat could fail to answer.
    ///
    /// # Errors
    ///
    /// Propagates any error from the wrapped link.
    fn refresh_retire(&self, epoch: Epoch) -> Result<(), ThresholdError> {
        self.inner.refresh_retire(epoch)
    }

    /// Concludes the refresh round via the wrapped link, unless the seat has been
    /// switched off.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` if `take_down` has been called;
    /// otherwise propagates any error from the wrapped link.
    fn refresh_finish(&self, epoch: Epoch) -> Result<Reached, ThresholdError> {
        self.check()?;
        self.inner.refresh_finish(epoch)
    }

    /// Releases the refresh state for `epoch` on the wrapped link.
    fn refresh_abandon(&self, epoch: Epoch) {
        self.inner.refresh_abandon(epoch);
    }
    /// Deals repair shares to the helpers reconstructing `lost` via the wrapped
    /// link, unless the seat has been switched off.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` if `take_down` has been called;
    /// otherwise propagates any error from the wrapped link.
    fn repair_deal(&self, lost: Seat, helpers: &[Seat]) -> Result<(), ThresholdError> {
        self.check()?;

        self.inner.repair_deal(lost, helpers)
    }

    /// Accepts a repair delta for `lost` from `from` via the wrapped link, unless
    /// the seat has been switched off.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` if `take_down` has been called;
    /// otherwise propagates any error from the wrapped link.
    fn repair_take(
        &self,
        lost: Seat,
        from: Seat,
        delta: &repair::Delta,
    ) -> Result<(), ThresholdError> {
        self.check()?;

        self.inner.repair_take(lost, from, delta)
    }

    /// Produces the repair contribution (sigma) for `lost` via the wrapped link,
    /// unless the seat has been switched off.
    ///
    /// # Errors
    ///
    /// Returns `ThresholdError::Unreachable` if `take_down` has been called;
    /// otherwise propagates any error from the wrapped link.
    fn repair_sigma(&self, lost: Seat) -> Result<repair::Sigma, ThresholdError> {
        self.check()?;

        self.inner.repair_sigma(lost)
    }

    /// Releases the repair state for `lost` on the wrapped link.
    fn repair_abandon(&self, lost: Seat) {
        self.inner.repair_abandon(lost);
    }
}

/// A finished group from the DKG, together with its five seats.
pub struct Fixture {
    shape: GroupShape,
    public: PublicKeyPackage,
    shares: BTreeMap<Seat, KeyPackage>,
    links: BTreeMap<Seat, Arc<ToggleLink>>,
}

impl Fixture {
    /// Returns the group's shape: its seats and its signing threshold.
    pub fn shape(&self) -> GroupShape {
        self.shape
    }

    /// Returns the group's public key package.
    pub fn public(&self) -> &PublicKeyPackage {
        &self.public
    }

    /// Returns the key package held by `seat`.
    ///
    /// # Panics
    ///
    /// Panics if `seat` does not belong to this group.
    pub fn share(&self, seat: Seat) -> &KeyPackage {
        self.shares
            .get(&seat)
            .expect("the seat belongs to the group")
    }

    /// Returns every seat's key package, keyed by seat.
    pub fn shares(&self) -> &BTreeMap<Seat, KeyPackage> {
        &self.shares
    }

    /// Resolves seat number `number` to its `Seat` handle.
    ///
    /// # Panics
    ///
    /// Panics if `number` does not name one of the group's five seats.
    pub fn seat(&self, number: u16) -> Seat {
        self.shape.seat(number).expect("seat")
    }

    /// A signer over all five seats.
    ///
    /// # Panics
    ///
    /// Panics if the five-seat group cannot be assembled into a signer.
    pub fn signer(&self) -> ThresholdSigner {
        self.signer_over(&[1, 2, 3, 4, 5])
    }

    /// A signer over the named seats.
    ///
    /// # Panics
    ///
    /// Panics if `seats` does not name a valid signing group (wrong size, unknown
    /// seat number, and so on).
    pub fn signer_over(&self, seats: &[u16]) -> ThresholdSigner {
        self.try_signer_over(seats).expect("group")
    }

    /// As [`Fixture::signer_over`], but without an expectation of the result.
    ///
    /// # Errors
    ///
    /// Returns an error if `seats` does not name a valid signing group (wrong
    /// size, unknown seat number, and so on).
    pub fn try_signer_over(&self, seats: &[u16]) -> Result<ThresholdSigner, ThresholdError> {
        let links: Vec<Arc<dyn SignerLink>> = seats
            .iter()
            .map(|number| {
                let link: Arc<dyn SignerLink> =
                    self.links.get(&self.seat(*number)).expect("seat").clone();
                link
            })
            .collect();

        ThresholdSigner::new(self.public.clone(), self.shape, links)
    }

    /// A signer over the named seats **plus** a seat that holds a freshly taken-over
    /// share -- the case after a signer replacement.
    ///
    /// # Panics
    ///
    /// Panics if constructing the extra participant or assembling the signer
    /// fails.
    pub fn signer_with(
        &self,
        seats: &[u16],
        replaced: Seat,
        share: &KeyPackage,
        entropy: &mut SeededEntropy,
    ) -> ThresholdSigner {
        let mut links: Vec<Arc<dyn SignerLink>> = seats
            .iter()
            .map(|number| {
                let link: Arc<dyn SignerLink> =
                    self.links.get(&self.seat(*number)).expect("seat").clone();
                link
            })
            .collect();

        let participant = Participant::new(
            replaced,
            share,
            &self.public,
            Epoch::GENESIS,
            Arc::new(PlainCustody),
        )
        .expect("participant");
        links.push(Arc::new(LocalLink::new(
            participant,
            Box::new(entropy.fork()),
        )));

        ThresholdSigner::new(self.public.clone(), self.shape, links).expect("group")
    }

    /// The named seats as `LocalLink`s of their own, **known to each other**.
    ///
    /// Repair works the same way as refresh: the deltas go from seat to seat, so
    /// every helper needs to reach the others directly (`attach_peers` wires each
    /// link to its peers).
    ///
    /// Expressly **not** the fixture's `ToggleLink`s: those do not carry their peers,
    /// and a wrapper that passes `repair_take` through would be a second version of
    /// the same dummy.
    ///
    /// # Panics
    ///
    /// Panics if `seats` contains a seat number that is not part of the group.
    pub fn wired(&self, seats: &[u16]) -> Vec<Arc<LocalLink>> {
        let mut links: Vec<Arc<LocalLink>> = Vec::new();
        for (index, participant) in self.participants(seats).into_iter().enumerate() {
            let seed = 0x5EA7_0000 + u64::try_from(index).unwrap_or(0);
            links.push(Arc::new(LocalLink::new(
                participant,
                Box::new(SeededEntropy::new(seed)),
            )));
        }

        for link in &links {
            let peers: Vec<Arc<dyn SignerLink>> = links
                .iter()
                .filter(|other| other.seat() != link.seat())
                .map(|other| Arc::clone(other) as Arc<dyn SignerLink>)
                .collect();
            link.attach_peers(peers);
        }

        links
    }

    /// Switches off every seat named in `seats`, so subsequent calls against them
    /// report unreachable.
    ///
    /// # Panics
    ///
    /// Panics if `seats` contains a seat number that is not part of the group.
    pub fn take_down(&self, seats: &[u16]) {
        for number in seats {
            self.links
                .get(&self.seat(*number))
                .expect("seat")
                .take_down();
        }
    }

    /// Lets the named seats **commit** and refuse afterwards.
    ///
    /// # Panics
    ///
    /// Panics if `seats` contains a seat number that is not part of the group.
    pub fn mute_signing(&self, seats: &[u16]) {
        for number in seats {
            self.links
                .get(&self.seat(*number))
                .expect("seat")
                .mute_signing();
        }
    }

    /// How many nonce sessions are open per seat, by seat number.
    pub fn outstanding(&self) -> Vec<usize> {
        self.links.values().map(|link| link.outstanding()).collect()
    }

    /// Builds a `Participant` for each named seat, ready to be wrapped in a link.
    ///
    /// # Panics
    ///
    /// Panics if `seats` contains a seat number that is not part of the group, or
    /// if constructing a participant from its share fails.
    pub fn participants(&self, seats: &[u16]) -> Vec<Participant> {
        seats
            .iter()
            .map(|number| {
                let seat = self.seat(*number);
                Participant::new(
                    seat,
                    self.share(seat),
                    &self.public,
                    Epoch::GENESIS,
                    Arc::new(PlainCustody),
                )
                .expect("participant")
            })
            .collect()
    }
}

/// Five seats, t = 3, from a real DKG -- no trusted dealer.
///
/// `entropy` drives both the DKG itself and the nonce generation of each seat's
/// link; forking it per seat keeps their randomness independent. Returns a
/// `Fixture` holding the group's public key, every seat's share, and a
/// `ToggleLink` per seat.
///
/// # Panics
///
/// Panics if the DKG or the construction of a seat's participant fails.
pub fn group_of_five(entropy: &mut SeededEntropy) -> Fixture {
    let shape = GroupShape::adr_0014();
    let (public, shares) = run_dkg(shape, entropy);

    let links = shares
        .iter()
        .map(|(seat, share)| {
            let participant = Participant::new(
                *seat,
                share,
                &public,
                Epoch::GENESIS,
                Arc::new(PlainCustody),
            )
            .expect("participant");
            (
                *seat,
                Arc::new(ToggleLink::new(LocalLink::new(
                    participant,
                    Box::new(entropy.fork()),
                ))),
            )
        })
        .collect();

    Fixture {
        shape,
        public,
        shares,
        links,
    }
}

/// The DKG over all the seats, run in one process.
///
/// Every seat computes from its **own** secret package; the full key arises at no
/// place. That the five state machines lie here in the same process is a property of
/// the test rig, not of the procedure.
///
/// `shape` fixes the seats and threshold to run the protocol over; `entropy`
/// supplies the randomness for every seat's round-1 contribution. Returns the
/// group's public key package together with each seat's own key package.
///
/// # Panics
///
/// Panics if any round of the protocol fails for any seat.
pub fn run_dkg(
    shape: GroupShape,
    entropy: &mut SeededEntropy,
) -> (PublicKeyPackage, BTreeMap<Seat, KeyPackage>) {
    let mut started = BTreeMap::new();
    let mut broadcasts = BTreeMap::new();
    for seat in shape.places() {
        let (state, broadcast) = dkg::start(seat, shape, entropy).expect("round 1");
        started.insert(seat, state);
        broadcasts.insert(seat, broadcast);
    }

    let mut exchanged = BTreeMap::new();
    let mut inbox: BTreeMap<Seat, BTreeMap<Seat, dkg::Directed>> = shape
        .places()
        .into_iter()
        .map(|seat| (seat, BTreeMap::new()))
        .collect();
    for (seat, state) in started {
        let (state, outgoing) = state.round2(&others(&broadcasts, seat)).expect("round 2");
        exchanged.insert(seat, state);
        for (to, message) in outgoing {
            inbox.get_mut(&to).expect("seat").insert(seat, message);
        }
    }

    let mut shares = BTreeMap::new();
    let mut public = None;
    for (seat, state) in exchanged {
        let directed = inbox.remove(&seat).expect("inbox");
        let (own, joint) = state
            .finish(&others(&broadcasts, seat), &directed)
            .expect("round 3");
        shares.insert(seat, own);
        public = Some(joint);
    }

    (public.expect("group key"), shares)
}

/// Returns every seat's broadcast except `seat`'s own -- what `seat` receives as
/// its round-1 input from its peers.
///
/// `all` holds every seat's round-1 broadcast, keyed by seat; `seat` is the seat
/// whose own entry is excluded from the result.
fn others(all: &BTreeMap<Seat, dkg::Broadcast>, seat: Seat) -> BTreeMap<Seat, dkg::Broadcast> {
    all.iter()
        .filter(|(other, _)| **other != seat)
        .map(|(other, package)| (*other, package.clone()))
        .collect()
}
