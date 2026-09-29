//! The signing group's shape.

use frost_ed25519::Identifier;

use crate::threshold::error::ThresholdError;

/// The number of signer seats in the default group shape.
pub const SEATS: u16 = 5;

/// The signature threshold in the default group shape.
///
/// The same number as the Raft quorum, and that is deliberate: both tolerate two
/// failures, the third blocks both. There is thereby no state in which the
/// cluster can write but not sign -- or the other way round.
pub const THRESHOLD: u16 = 3;

/// A signer seat.
///
/// **A seat, not a node.** The signing group is decoupled from the Raft
/// membership: which node currently sits on which seat is an operational setting
/// and may change (via RTS, see [`crate::threshold::repair`]) without the group
/// becoming a different one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seat(u16);

impl Seat {
    /// The seat with this number.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::UnknownSeat`] when the number is zero -- FROST knows no
    /// identifier zero, the scalar would be degenerate.
    pub fn new(number: u16) -> Result<Self, ThresholdError> {
        if number == 0 {
            return Err(ThresholdError::UnknownSeat { number });
        }

        Ok(Self(number))
    }

    /// The seat's number.
    #[must_use]
    pub fn number(self) -> u16 {
        self.0
    }

    /// Converts this seat into the FROST `Identifier` it corresponds to.
    ///
    /// # Panics
    ///
    /// Never panics in practice: `Seat::new` refuses seat number zero, and
    /// `Identifier::try_from` fails only on zero.
    pub(crate) fn identifier(self) -> Identifier {
        // This is the only call in this module that can panic, and it cannot fire
        // in practice: `Seat::new` refuses zero, and `Identifier::try_from` fails
        // only on it. A `Result` here would push the question onto a caller who
        // cannot answer it -- the same choice made for the regex literals of the
        // generated parser.
        #[allow(clippy::expect_used, reason = "Seat::new refuses zero")]
        Identifier::try_from(self.0).expect("a seat number is never zero")
    }

    /// The number back out of a FROST identifier.
    ///
    /// `Identifier::try_from(u16)` maps `n` onto the scalar `n`; the serialization
    /// of the Ed25519 scalar field is little-endian. So we read the two lowest
    /// bytes and insist that the rest is zero -- an identifier that does not come
    /// from a seat number does not belong in this group.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] when the identifier's high bytes are non-zero,
    /// i.e. it did not originate from a seat number; also propagates the error
    /// from [`Seat::new`] when the recovered number is zero.
    pub(crate) fn from_identifier(id: Identifier) -> Result<Self, ThresholdError> {
        let bytes = id.serialize();

        let (low, high) = bytes.split_at(2);
        if high.iter().any(|byte| *byte != 0) {
            return Err(ThresholdError::Shape {
                detail: "a FROST identifier outside the seat-number range".to_owned(),
            });
        }

        Self::new(u16::from_le_bytes([low[0], low[1]]))
    }
}

impl std::fmt::Display for Seat {
    /// Writes this seat as `"seat <number>"` to `f`.
    ///
    /// # Errors
    ///
    /// Propagates any formatting error from the underlying `write!` call.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "seat {}", self.0)
    }
}

/// How many seats, and how many of them are necessary to sign.
///
/// **Frozen with the DKG.** `frost` cannot change the threshold through
/// resharing. A different N or t means a new DKG, a new group public key, a new
/// intermediate from the air-gapped root -- a ceremony, not something that
/// happens along the way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupShape {
    seats: u16,
    threshold: u16,
}

impl GroupShape {
    /// The default shape used by this system: five seats, t = 3.
    #[must_use]
    pub fn adr_0014() -> Self {
        Self {
            seats: SEATS,
            threshold: THRESHOLD,
        }
    }

    /// A shape of one's own.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Shape`] when the shape is not load-bearing: fewer than two
    /// seats, a threshold beyond the seat count, or a threshold below the majority.
    /// The last case is the interesting one -- at `t <= N/2` two **disjoint**
    /// subsets can sign at the same time, which is the same split-brain condition
    /// that is guarded against on the consensus side.
    pub fn new(seats: u16, threshold: u16) -> Result<Self, ThresholdError> {
        if seats < 2 {
            return Err(ThresholdError::Shape {
                detail: format!("{seats} seats are no group"),
            });
        }
        if threshold < 2 || threshold > seats {
            return Err(ThresholdError::Shape {
                detail: format!("a threshold of {threshold} does not fit {seats} seats"),
            });
        }
        if 2 * u32::from(threshold) <= u32::from(seats) {
            return Err(ThresholdError::Shape {
                detail: format!(
                    "a threshold of {threshold} does not lie above the majority of \
                     {seats} seats -- two disjoint subsets could sign at the same \
                     time"
                ),
            });
        }

        Ok(Self { seats, threshold })
    }

    /// The number of seats.
    #[must_use]
    pub fn seats(self) -> u16 {
        self.seats
    }

    /// The threshold.
    #[must_use]
    pub fn threshold(self) -> u16 {
        self.threshold
    }

    /// All the group's seats, ascending.
    #[must_use]
    pub fn places(self) -> Vec<Seat> {
        (1..=self.seats).map(Seat).collect()
    }

    /// The seat with this number, as far as the group has it.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::UnknownSeat`] when the number lies outside the group. That
    /// is **no** case for RTS: resharing adds no participants. A sixth seat is a
    /// ceremony, no repair case.
    pub fn seat(self, number: u16) -> Result<Seat, ThresholdError> {
        if number == 0 || number > self.seats {
            return Err(ThresholdError::UnknownSeat { number });
        }

        Ok(Seat(number))
    }

    /// Whether this seat belongs to the group.
    #[must_use]
    pub fn holds(self, seat: Seat) -> bool {
        seat.0 >= 1 && seat.0 <= self.seats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seat round-trips through a FROST identifier and back unchanged.
    #[test]
    fn a_seat_survives_the_trip_through_a_frost_identifier() {
        for number in [1_u16, 2, 5, 255, 256, 65_535] {
            let seat = Seat::new(number).expect("seat");
            let back = Seat::from_identifier(seat.identifier()).expect("back");

            assert_eq!(back, seat);
        }
    }

    /// Seat number zero is rejected because FROST has no identifier zero.
    #[test]
    fn seat_zero_does_not_exist() {
        Seat::new(0).expect_err("FROST knows no identifier zero");
    }

    /// The default group shape has five seats and a threshold of three.
    #[test]
    fn the_adr_shape_is_five_of_three() {
        let shape = GroupShape::adr_0014();

        assert_eq!(shape.seats(), 5);
        assert_eq!(shape.threshold(), 3);
        assert_eq!(shape.places().len(), 5);
        assert!(shape.holds(shape.seat(5).expect("seat")));
    }
}
