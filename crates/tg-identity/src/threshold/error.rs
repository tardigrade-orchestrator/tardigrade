//! What can fail on the threshold path.

use crate::threshold::group::Seat;
use crate::threshold::nonce::NonceError;

/// An error on the threshold path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
    /// The group's shape does not carry.
    Shape {
        /// What it is down to.
        detail: String,
    },
    /// This seat does not exist in the group.
    UnknownSeat {
        /// The demanded number.
        number: u16,
    },
    /// The seat did not answer.
    ///
    /// For the coordinator not distinguishable from a failed node -- and it does
    /// not have to be: it skips it and asks the next one, as long as the threshold
    /// is still reachable.
    Unreachable {
        /// The seat.
        seat: Seat,
    },
    /// Too few seats could take part.
    Threshold {
        /// How many would have been necessary.
        needed: u16,
        /// How many there were.
        got: u16,
    },
    /// No commitment is open at this seat for this session.
    ///
    /// Either there never was one, or it is redeemed -- in both cases there is
    /// nothing left to sign.
    NoSuchSession {
        /// The demanded session.
        session: String,
    },
    /// This seat does not hold the demanded generation of the shares.
    ///
    /// The normal case during a refresh: the coordinator names an epoch, a seat is
    /// not there yet. **Our** rejection and not `InvalidSignatureShare` in the
    /// aggregation -- that comes too late, does not name the seat (measured) and
    /// would look like a broken seat.
    UnknownEpoch {
        /// The seat.
        seat: Seat,
        /// The demanded generation.
        wanted: u64,
        /// Which ones it holds.
        held: Vec<u64>,
    },
    /// This session runs in a different generation from the demanded one.
    ///
    /// The case [`crate::threshold::SessionId`] describes: two coordinators name
    /// the same number. Until now the second got the first one's commitment -- with
    /// epochs that would be **one commitment for two shares**, and that is the place
    /// at which an error costs the share.
    SessionEpoch {
        /// The session.
        session: String,
        /// In which generation it runs.
        running: u64,
        /// Which one was demanded.
        wanted: u64,
    },
    /// The nonce discipline has struck.
    Nonce(NonceError),
    /// The share could not be sealed or opened.
    Custody {
        /// What it is down to.
        detail: String,
    },
    /// The restoration of a share (RTS) is not feasible.
    Repair {
        /// What it is down to.
        detail: String,
    },
    /// `frost` refused.
    Frost {
        /// What was being attempted.
        during: String,
        /// The library's message.
        detail: String,
    },
}

impl ThresholdError {
    /// Builds a [`ThresholdError::Frost`] from an error the `frost_ed25519`
    /// library returned, recording what operation (`during`) produced it and the
    /// library's own message (`err`).
    pub(crate) fn frost(during: &str, err: &frost_ed25519::Error) -> Self {
        Self::Frost {
            during: during.to_owned(),
            detail: err.to_string(),
        }
    }
}

impl std::fmt::Display for ThresholdError {
    /// Writes a human-readable description of this error to `f`.
    ///
    /// # Errors
    ///
    /// Propagates any formatting error from the underlying `write!` call.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shape { detail } => write!(f, "the group shape is unusable: {detail}"),
            Self::UnknownSeat { number } => write!(
                f,
                "seat {number} does not belong to the signing group -- changing N is \
                 a ceremony (ADR-0014), no runtime operation"
            ),
            Self::Unreachable { seat } => write!(f, "{seat} did not answer"),
            Self::Threshold { needed, got } => write!(
                f,
                "the threshold of {needed} seats was not reached, there were {got}"
            ),
            Self::NoSuchSession { session } => write!(
                f,
                "no commitment is open for {session} -- it is redeemed or there never \
                 was one"
            ),
            Self::UnknownEpoch { seat, wanted, held } => write!(
                f,
                "{seat} does not hold epoch {wanted} but [{}]",
                held.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::SessionEpoch {
                session,
                running,
                wanted,
            } => write!(f, "{session} runs in epoch {running}, {wanted} is demanded"),
            Self::Nonce(err) => write!(f, "nonce discipline: {err}"),
            Self::Custody { detail } => write!(f, "share custody: {detail}"),
            Self::Repair { detail } => write!(f, "the share is not restorable: {detail}"),
            Self::Frost { during, detail } => write!(f, "{during}: {detail}"),
        }
    }
}

impl std::error::Error for ThresholdError {}

impl From<NonceError> for ThresholdError {
    /// Wraps a [`NonceError`] as a [`ThresholdError::Nonce`].
    fn from(err: NonceError) -> Self {
        Self::Nonce(err)
    }
}
