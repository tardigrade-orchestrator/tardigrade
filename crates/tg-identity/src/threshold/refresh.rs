//! The proactive refresh of the signer shares (ADR-0107).
//!
//! New shares, **the same** group key: the intermediate from the air-gapped root
//! stays valid, no verifier notices anything, and a share that was betrayed before
//! the refresh is worthless afterwards. That is this system's only answer to a
//! compromise that is no ceremony -- RTS ([`crate::threshold::repair`]) restores a
//! **lost** share and does not invalidate it.
//!
//! # Why the DKG and not the trusted dealer
//!
//! `frost` has both ways, and the dealer would be **one** round instead of three --
//! measured, it needs only the public group key and sees no share. It is discarded
//! nevertheless, for two reasons (ADR-0107):
//!
//! 1. It knows **all the deltas** and thereby holds the bridge between two epochs.
//!    Whoever takes it over converts a new share into an old one -- and precisely
//!    that the refresh is supposed to make impossible.
//! 2. It can **shrink the group.** Measured, `compute_refreshing_shares` is
//!    *accepted* with three of five identifiers; afterwards the group key has three
//!    `verifying_shares`, the two omitted seats are `UnknownIdentifier` -- and
//!    because the verifying key stays the same, **nothing breaks visibly.** Out of
//!    "two failures tolerated" (ADR-0014, determination 2) would come "none
//!    tolerated", and it would stand out at the next failure.
//!
//! The DKG way cannot make the second error: `frost` answers with
//! `IncorrectNumberOfPackages`. The price -- all five seats -- is thereby not one the
//! dealer would have saved but a requirement of the operation itself.
//!
//! # Three rounds, the same shape as the DKG
//!
//! ```text
//! start   -> Broadcast   to all          (the binding to one's own zero polynomial)
//! round2  -> Directed    to each one
//! finish  -> KeyPackage + PublicKeyPackage of the next epoch
//! ```
//!
//! The difference from the DKG is the constant term: every seat draws a polynomial
//! with **zero** at position zero. The sum of the shares therefore stays the same
//! secret, and the individual shares are new.
//!
//! # What the channel must deliver
//!
//! The same as at the DKG: round 2 demands a confidential **and** authenticated
//! channel -- in this cluster the signer port from ADR-0097. For round 1
//! authenticity suffices, but it does not suffice optionally: whoever can slip in a
//! foreign broadcast package shifts the new shares against the group key, and
//! afterwards the group does not sign any more.

use std::collections::{BTreeMap, BTreeSet};

use frost_ed25519::Identifier;
use frost_ed25519::keys::refresh as frost_refresh;

use crate::threshold::entropy::{Entropy, Source};
use crate::threshold::error::ThresholdError;
use crate::threshold::group::{GroupShape, Seat};
use crate::threshold::material::{Epoch, Material};

/// What a seat sends to **all** after round 1.
pub type Broadcast = frost_ed25519::keys::dkg::round1::Package;

/// What a seat sends to **one particular** one after round 2.
pub type Directed = frost_ed25519::keys::dkg::round2::Package;

/// A seat after round 1 of the refresh.
#[derive(Debug)]
pub struct Started {
    seat: Seat,
    shape: GroupShape,
    secret: frost_ed25519::keys::dkg::round1::SecretPackage,
}

/// A seat after round 2 of the refresh.
#[derive(Debug)]
pub struct Exchanged {
    seat: Seat,
    shape: GroupShape,
    secret: frost_ed25519::keys::dkg::round2::SecretPackage,
    round1: BTreeMap<Identifier, Broadcast>,
}

/// Round 1: draw one's own zero polynomial and commit to it.
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

    let (secret, broadcast) = frost_refresh::refresh_dkg_part1(
        seat.identifier(),
        shape.seats(),
        shape.threshold(),
        Source::new(entropy),
    )
    .map_err(|err| ThresholdError::frost("refresh round 1", &err))?;

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
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] when not **all** the other seats are represented;
    /// [`ThresholdError::Frost`] when the library refuses.
    pub fn round2(
        self,
        from_others: &BTreeMap<Seat, Broadcast>,
    ) -> Result<(Exchanged, BTreeMap<Seat, Directed>), ThresholdError> {
        expect_all_others(self.seat, self.shape, from_others.keys().copied())?;

        let round1 = by_identifier(from_others);
        let (secret, outgoing) = frost_refresh::refresh_dkg_part2(self.secret, &round1)
            .map_err(|err| ThresholdError::frost("refresh round 2", &err))?;

        Ok((
            Exchanged {
                seat: self.seat,
                shape: self.shape,
                secret,
                round1,
            },
            by_seat(outgoing)?,
        ))
    }
}

impl Exchanged {
    /// The seat at issue.
    #[must_use]
    pub fn seat(&self) -> Seat {
        self.seat
    }

    /// Round 3: form the new share and the new group key.
    ///
    /// `held` is this seat's **previous** material -- the refresh adds onto it;
    /// without it there would be no share a delta fits (ADR-0014, finding 2).
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] when not all the other seats are represented or the
    /// material belongs to a different seat; [`ThresholdError::Frost`] when the
    /// library refuses -- in there sits the case too that a seat sent a share that
    /// does not fit its broadcast, and the case that somebody wanted to change the
    /// **threshold** (`InvalidMinSigners`, measured only in this round).
    pub fn finish(
        self,
        held: &Material,
        directed: &BTreeMap<Seat, Directed>,
    ) -> Result<Material, ThresholdError> {
        expect_all_others(self.seat, self.shape, directed.keys().copied())?;

        if held.seat() != self.seat {
            return Err(ThresholdError::Shape {
                detail: format!(
                    "the material belongs to {} and not to {}",
                    held.seat(),
                    self.seat
                ),
            });
        }

        let (share, group) = frost_refresh::refresh_dkg_shares(
            &self.secret,
            &self.round1,
            &by_identifier(directed),
            held.group().clone(),
            held.share().clone(),
        )
        .map_err(|err| ThresholdError::frost("refresh round 3", &err))?;

        Ok(Material::held(self.seat, share, group, held.epoch().next()))
    }
}

/// Drives the refresh over **all** the seats in one process.
///
/// # What this is good for, and what expressly not
///
/// **This process sees all five shares.** With that it is for the duration of its
/// run the full CA key -- exactly what the group abolishes. In operation the three
/// rounds are an operation between five processes over the signer port (ADR-0097);
/// this function stands here for the same reason as
/// [`crate::threshold::dkg::ceremony`]: otherwise it would stand in the test rig
/// **and** in the tool, and two copies of a ceremony are two opportunities to run it
/// differently.
///
/// # Errors
///
/// [`ThresholdError::Shape`] when `held` does not carry **exactly** the shape's
/// seats -- a refresh with fewer than all is on the dealer way a silent shrinking of
/// the group (measured, ADR-0107), so it does not exist here. Otherwise as the three
/// rounds.
pub fn ceremony(
    shape: GroupShape,
    held: &BTreeMap<Seat, Material>,
    entropy: &mut dyn Entropy,
) -> Result<BTreeMap<Seat, Material>, ThresholdError> {
    expect_every_seat(shape, held)?;

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

    let mut done = BTreeMap::new();
    for (seat, state) in exchanged {
        let directed = inbox.remove(&seat).unwrap_or_default();
        let material = state.finish(&held[&seat], &directed)?;
        done.insert(seat, material);
    }

    Ok(done)
}

/// Exactly the shape's seats, and their material belongs to **one** group.
fn expect_every_seat(
    shape: GroupShape,
    held: &BTreeMap<Seat, Material>,
) -> Result<(), ThresholdError> {
    let present: BTreeSet<Seat> = held.keys().copied().collect();
    let expected: BTreeSet<Seat> = shape.places().into_iter().collect();

    if present != expected {
        let missing: Vec<String> = expected
            .difference(&present)
            .map(|seat| seat.number().to_string())
            .collect();
        let extra: Vec<String> = present
            .difference(&expected)
            .map(|seat| seat.number().to_string())
            .collect();

        return Err(ThresholdError::Shape {
            detail: format!(
                "a refresh needs all {} seats; missing: [{}], unknown: [{}] -- \
                 with fewer the group would be shrunk (ADR-0107)",
                expected.len(),
                missing.join(", "),
                extra.join(", ")
            ),
        });
    }

    // A seat with **foreign** material is a seat the counting does not catch: its
    // identifier fits, its share lies on a different polynomial. It would stand out
    // only in round 3, and there as a `Frost` error.
    let mut keys = BTreeSet::new();
    for material in held.values() {
        keys.insert(
            material
                .group()
                .verifying_key()
                .serialize()
                .map_err(|err| ThresholdError::frost("reading the group key", &err))?,
        );
    }
    if keys.len() > 1 {
        return Err(ThresholdError::Shape {
            detail: format!(
                "the seats hold {} different group keys -- that is not one group",
                keys.len()
            ),
        });
    }

    let epochs: BTreeSet<Epoch> = held.values().map(Material::epoch).collect();
    if epochs.len() > 1 {
        return Err(ThresholdError::Shape {
            detail: format!(
                "the seats stand in {} different epochs -- a refresh presupposes a \
                 common one (ADR-0107)",
                epochs.len()
            ),
        });
    }

    Ok(())
}

fn expect_all_others(
    own: Seat,
    shape: GroupShape,
    present: impl Iterator<Item = Seat>,
) -> Result<(), ThresholdError> {
    let present: BTreeSet<Seat> = present.collect();
    let expected: BTreeSet<Seat> = shape
        .places()
        .into_iter()
        .filter(|seat| *seat != own)
        .collect();

    if present == expected {
        return Ok(());
    }

    Err(ThresholdError::Shape {
        detail: format!(
            "the refresh needs packages from all {} other seats, {} are present",
            expected.len(),
            present.len()
        ),
    })
}

fn without<T: Clone>(all: &BTreeMap<Seat, T>, seat: Seat) -> BTreeMap<Seat, T> {
    all.iter()
        .filter(|&(&other, _)| other != seat)
        .map(|(&other, value)| (other, value.clone()))
        .collect()
}

fn by_identifier<T: Clone>(from: &BTreeMap<Seat, T>) -> BTreeMap<Identifier, T> {
    from.iter()
        .map(|(seat, value)| (seat.identifier(), value.clone()))
        .collect()
}

fn by_seat<T>(from: BTreeMap<Identifier, T>) -> Result<BTreeMap<Seat, T>, ThresholdError> {
    from.into_iter()
        .map(|(id, value)| Seat::from_identifier(id).map(|seat| (seat, value)))
        .collect()
}
