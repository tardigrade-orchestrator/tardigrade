//! The distributed key generation over the signer seats.
//!
//! Why DKG and not a trusted dealer: a dealer would hold the full signing key --
//! even if only for a moment, and that moment is precisely what this design
//! avoids. In the DKG every seat computes from its own secret polynomial; the
//! group key arises as a sum that lies **nowhere** as a whole.
//!
//! # Three rounds, three types
//!
//! The sequence is built as a state machine per seat, not as one function that
//! drives everything. That is no fussiness but the precondition for the five seats
//! really being able to be five processes: every step **consumes** its predecessor,
//! and what travels between the steps is a value, not a pointer.
//!
//! ```text
//! start   -> Broadcast   to all          (the binding to one's own polynomial)
//! round2  -> Directed    to each one     (the share for exactly them)
//! finish  -> KeyPackage + PublicKeyPackage
//! ```
//!
//! # What the channel must deliver
//!
//! `frost` says it expressly for round 2: the directed packages must go over a
//! **confidential and authenticated** channel. In this cluster that is the mTLS
//! path between the control-plane nodes. For round 1 authenticity suffices -- but
//! that does not suffice optionally: whoever can slip in a foreign broadcast
//! package shifts the group key.

use std::collections::BTreeMap;

use frost_ed25519::Identifier;
use frost_ed25519::keys::dkg;

use crate::threshold::entropy::{Entropy, Source};
use crate::threshold::error::ThresholdError;
use crate::threshold::group::{GroupShape, Seat};
use crate::threshold::{KeyPackage, PublicKeyPackage};

/// What a seat sends to **all** after round 1.
pub type Broadcast = dkg::round1::Package;

/// What a seat sends to **one particular** one after round 2.
///
/// To be transmitted confidentially and authenticated -- here sits the share this
/// one receiver gets.
pub type Directed = dkg::round2::Package;

/// A seat after round 1.
#[derive(Debug)]
pub struct Started {
    seat: Seat,
    shape: GroupShape,
    secret: dkg::round1::SecretPackage,
}

/// A seat after round 2.
#[derive(Debug)]
pub struct Exchanged {
    seat: Seat,
    shape: GroupShape,
    secret: dkg::round2::SecretPackage,
}

/// Drives the whole ceremony in **one** process.
///
/// # Only for the test rig and `xtask`
///
/// **This call sees all the shares.** For the duration of its execution it thereby
/// holds the full group key -- exactly what the group is designed to abolish. In
/// operation the DKG is a **ceremony**: every seat produces its secret on its own
/// machine, and the three rounds go over a channel a human has set up.
///
/// It stands here and not in the test rig because it would otherwise stand there
/// **three times** -- in `tg-identity`'s tests, in `xtask` and in the witness over
/// five processes -- and three copies of a ceremony are three opportunities to run
/// it differently. It has no production caller and shall have none; it carries that
/// like [`crate::threshold::PlainCustody`] in the doc instead of in the name,
/// because `ceremony` is exactly what it drives.
///
/// # Errors
///
/// [`ThresholdError`] when a round fails -- in the test rig that means the entropy
/// source failed.
pub fn ceremony(
    shape: GroupShape,
    entropy: &mut dyn crate::threshold::Entropy,
) -> Result<Vec<(Seat, KeyPackage, PublicKeyPackage)>, ThresholdError> {
    let mut started = BTreeMap::new();
    let mut broadcasts = BTreeMap::new();
    for seat in shape.places() {
        let (state, broadcast) = start(seat, shape, entropy)?;
        started.insert(seat, state);
        broadcasts.insert(seat, broadcast);
    }

    let mut exchanged = BTreeMap::new();
    let mut inbox: BTreeMap<Seat, BTreeMap<Seat, Directed>> = shape
        .places()
        .into_iter()
        .map(|seat| (seat, BTreeMap::new()))
        .collect();
    for (seat, state) in started {
        let others = without(&broadcasts, seat);
        let (state, outgoing) = state.round2(&others)?;
        exchanged.insert(seat, state);
        for (to, message) in outgoing {
            if let Some(box_) = inbox.get_mut(&to) {
                box_.insert(seat, message);
            }
        }
    }

    let mut done = Vec::new();
    for (seat, state) in exchanged {
        let others = without(&broadcasts, seat);
        let directed = inbox.remove(&seat).unwrap_or_default();
        let (secret, group) = state.finish(&others, &directed)?;
        done.push((seat, secret, group));
    }

    Ok(done)
}

/// All commitments except one's own -- every seat needs the others'.
fn without<T: Clone>(all: &BTreeMap<Seat, T>, seat: Seat) -> BTreeMap<Seat, T> {
    all.iter()
        .filter(|&(&other, _)| other != seat)
        .map(|(&other, value)| (other, value.clone()))
        .collect()
}

/// Round 1: draw one's own secret polynomial and commit to it.
///
/// # Errors
///
/// [`ThresholdError::UnknownSeat`] when the seat does not belong to the group;
/// [`ThresholdError::Frost`] when the library refuses.
pub fn start(
    seat: Seat,
    shape: GroupShape,
    entropy: &mut dyn Entropy,
) -> Result<(Started, Broadcast), ThresholdError> {
    if !shape.holds(seat) {
        return Err(ThresholdError::UnknownSeat {
            number: seat.number(),
        });
    }

    let (secret, broadcast) = dkg::part1(
        seat.identifier(),
        shape.seats(),
        shape.threshold(),
        Source::new(entropy),
    )
    .map_err(|err| ThresholdError::frost("DKG round 1", &err))?;

    Ok((
        Started {
            seat,
            shape,
            secret,
        },
        broadcast,
    ))
}

impl Started {
    /// The seat at issue.
    #[must_use]
    pub fn seat(&self) -> Seat {
        self.seat
    }

    /// Round 2: form the directed packages from the others' broadcasts.
    ///
    /// `from_others` contains the broadcasts of **all the other** seats, not one's
    /// own.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] when not all the other seats are represented -- an
    /// incomplete DKG would yield a group that is not the agreed one.
    /// [`ThresholdError::Frost`] when the library refuses.
    pub fn round2(
        self,
        from_others: &BTreeMap<Seat, Broadcast>,
    ) -> Result<(Exchanged, BTreeMap<Seat, Directed>), ThresholdError> {
        self.expect_all_others(from_others.keys().copied())?;

        let (secret, outgoing) = dkg::part2(self.secret, &by_identifier(from_others))
            .map_err(|err| ThresholdError::frost("DKG round 2", &err))?;

        Ok((
            Exchanged {
                seat: self.seat,
                shape: self.shape,
                secret,
            },
            by_seat(outgoing)?,
        ))
    }

    /// Checks that `present` names exactly the group's other seats, delegating
    /// to the free function [`expect_all_others`] with this seat's own identity
    /// and shape.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] when a seat is missing or a foreign one is
    /// present.
    fn expect_all_others(&self, present: impl Iterator<Item = Seat>) -> Result<(), ThresholdError> {
        expect_all_others(self.seat, self.shape, present)
    }
}

impl Exchanged {
    /// The seat at issue.
    #[must_use]
    pub fn seat(&self) -> Seat {
        self.seat
    }

    /// Round 3: form one's own share and the group key.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] when not all the other seats are represented;
    /// [`ThresholdError::Frost`] when the library refuses -- in there sits the case
    /// too that a seat sent a share that does not fit its broadcast.
    pub fn finish(
        self,
        broadcasts: &BTreeMap<Seat, Broadcast>,
        directed: &BTreeMap<Seat, Directed>,
    ) -> Result<(KeyPackage, PublicKeyPackage), ThresholdError> {
        expect_all_others(self.seat, self.shape, broadcasts.keys().copied())?;
        expect_all_others(self.seat, self.shape, directed.keys().copied())?;

        dkg::part3(
            &self.secret,
            &by_identifier(broadcasts),
            &by_identifier(directed),
        )
        .map_err(|err| ThresholdError::frost("DKG round 3", &err))
    }
}

/// Checks that `present` names exactly the group's other seats -- everyone in
/// `shape` except `own`, no more and no fewer.
///
/// # Errors
///
/// [`ThresholdError::Shape`] when the seats present do not match the expected
/// set exactly.
fn expect_all_others(
    own: Seat,
    shape: GroupShape,
    present: impl Iterator<Item = Seat>,
) -> Result<(), ThresholdError> {
    let present: std::collections::BTreeSet<Seat> = present.collect();
    let expected: std::collections::BTreeSet<Seat> = shape
        .places()
        .into_iter()
        .filter(|seat| *seat != own)
        .collect();

    if present == expected {
        return Ok(());
    }

    Err(ThresholdError::Shape {
        detail: format!(
            "the DKG needs packages from all {} other seats, {} are present",
            expected.len(),
            present.len()
        ),
    })
}

/// Re-keys a map from [`Seat`] to the FROST `Identifier` each seat corresponds
/// to, cloning the values.
fn by_identifier<T: Clone>(from: &BTreeMap<Seat, T>) -> BTreeMap<Identifier, T> {
    from.iter()
        .map(|(seat, value)| (seat.identifier(), value.clone()))
        .collect()
}

/// Re-keys a map from FROST `Identifier` back to [`Seat`], consuming the input.
///
/// # Errors
///
/// Propagates the error from [`Seat::from_identifier`] when any identifier does
/// not correspond to a valid seat number.
fn by_seat<T>(from: BTreeMap<Identifier, T>) -> Result<BTreeMap<Seat, T>, ThresholdError> {
    from.into_iter()
        .map(|(id, value)| Seat::from_identifier(id).map(|seat| (seat, value)))
        .collect()
}
