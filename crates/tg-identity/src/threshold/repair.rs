//! Replacement of a signer via RTS.
//!
//! That is the point at which the decoupling from the Raft membership becomes
//! practical. If a signer fails permanently, another node takes over **its seat**
//! -- the same identifier, a restored share. The group public key stays, so the
//! intermediate the air-gapped root once issued on it stays valid too. **No
//! ceremony.**
//!
//! # What RTS is not
//!
//! It adds no seat -- a new participant has no share to add anything to -- and it
//! does not lower the threshold. A sixth seat or a different t are a new DKG and
//! thereby a root ceremony.
//!
//! # Why this is no automatism
//!
//! Who declares a signer permanently failed is deliberately left to a human: the
//! replacement is an intervention with security weight and should not run
//! automatically on a timeout. That is why a function and no guard stands here:
//! it is prompted, it does not prompt itself.
//!
//! # The sequence
//!
//! ```text
//! every helper i:  delta[i][j]  for every helper j        (part1)
//! every helper j:  sigma[j] = sum delta[i][j]             (part2)
//! the lost one:    share from all the sigmas              (part3)
//! ```
//!
//! The deltas go from helper to helper, the sigmas to the lost one -- both over
//! confidential, authenticated channels. The group secret arises at no place in the
//! process.

use std::collections::BTreeMap;

use frost_ed25519::Ed25519Sha512;
use frost_ed25519::keys::repairable;

use crate::threshold::entropy::{Entropy, Source};
use crate::threshold::error::ThresholdError;
use crate::threshold::group::Seat;
use crate::threshold::{KeyPackage, PublicKeyPackage};

/// What a helper produces in step 1 for every other helper.
pub type Delta = repairable::Delta;

/// What a helper sends to the lost one in step 2.
pub type Sigma = repairable::Sigma;

/// Step 1: a helper produces its deltas for all helpers.
///
/// # Errors
///
/// [`ThresholdError::Frost`] when the library refuses -- in particular when the
/// number of helpers does not reach the threshold.
pub fn helper_deltas(
    helpers: &[Seat],
    helper_share: &KeyPackage,
    lost: Seat,
    entropy: &mut dyn Entropy,
) -> Result<BTreeMap<Seat, Delta>, ThresholdError> {
    let ids: Vec<_> = helpers.iter().map(|seat| seat.identifier()).collect();
    let deltas = repairable::repair_share_part1::<Ed25519Sha512, _>(
        &ids,
        helper_share,
        &mut Source::new(entropy),
        lost.identifier(),
    )
    .map_err(|err| ThresholdError::frost("RTS step 1", &err))?;

    deltas
        .into_iter()
        .map(|(id, delta)| Seat::from_identifier(id).map(|seat| (seat, delta)))
        .collect()
}

/// Step 2: a helper combines the deltas addressed to it.
#[must_use]
pub fn combine_deltas(deltas: &[Delta]) -> Sigma {
    repairable::repair_share_part2(deltas)
}

/// Step 3: the lost one forms its share from the sigmas.
///
/// **And checks it against the group key.** That is no ornament but the correction
/// of a measured finding: `repair_share_part3` does **not** count the sigmas, and
/// with too few it delivers a share that looks valid and is wrong --
///
/// ```text
/// full == real:  true
/// half == real:  false      (one sigma instead of three)
/// half is a valid KeyPackage: true
/// ```
///
/// A seat that takes over such a share looks healthy, writes it to disk and is
/// named as the culprit at every signature -- the nonce and share discipline is
/// the most dangerous spot in this system.
///
/// The group key names **every** seat's `verifying_share`, and the restored share
/// fits it exactly when it is right -- measured. That catches more than a count: a
/// damaged sigma, one from the wrong seat, and a share for the wrong seat. And it
/// needs only **public** material.
///
/// # Errors
///
/// [`ThresholdError::Frost`] when the library refuses;
/// [`ThresholdError::Repair`] when the share does not fit the group key or the
/// latter does not know the seat.
pub fn restore(
    sigmas: &[Sigma],
    seat: Seat,
    group: &PublicKeyPackage,
) -> Result<KeyPackage, ThresholdError> {
    let share = repairable::repair_share_part3(sigmas, seat.identifier(), group)
        .map_err(|err| ThresholdError::frost("RTS step 3", &err))?;

    let expected = group
        .verifying_shares()
        .get(share.identifier())
        .ok_or_else(|| ThresholdError::Repair {
            detail: format!("the group key does not know {seat}"),
        })?;
    if expected != share.verifying_share() {
        return Err(ThresholdError::Repair {
            detail: format!(
                "{seat}'s restored share does not fit the group key -- too few or \
                 damaged sigmas ({} contributed)",
                sigmas.len()
            ),
        });
    }

    Ok(share)
}

/// All three steps, run in one process.
///
/// That the helpers lie in the same process here is a property of this call, not of
/// the procedure: the three steps above are callable individually, and between them
/// values travel, not pointers.
///
/// # Errors
///
/// [`ThresholdError::Repair`] when the helpers do not reach the threshold or the
/// lost seat stands among them; [`ThresholdError::Frost`] when the library
/// refuses.
pub fn restore_seat(
    helpers: &BTreeMap<Seat, KeyPackage>,
    lost: Seat,
    group: &PublicKeyPackage,
    entropy: &mut dyn Entropy,
) -> Result<KeyPackage, ThresholdError> {
    if helpers.contains_key(&lost) {
        return Err(ThresholdError::Repair {
            detail: format!(
                "{lost} stands among its own helpers -- whoever has its share does \
                 not need it restored"
            ),
        });
    }

    let threshold = group.min_signers().ok_or_else(|| ThresholdError::Repair {
        detail: "the group key does not name its threshold (a package before \
                 frost-core 3.0)"
            .to_owned(),
    })?;
    let available = u16::try_from(helpers.len()).unwrap_or(u16::MAX);
    if available < threshold {
        return Err(ThresholdError::Repair {
            detail: format!("{available} helpers do not reach the threshold of {threshold}"),
        });
    }

    let seats: Vec<Seat> = helpers.keys().copied().collect();

    // Step 1: every helper for every helper.
    let mut inbox: BTreeMap<Seat, Vec<Delta>> =
        seats.iter().map(|seat| (*seat, Vec::new())).collect();
    for (from, share) in helpers {
        let deltas = helper_deltas(&seats, share, lost, entropy)?;
        for (to, delta) in deltas {
            inbox
                .get_mut(&to)
                .ok_or_else(|| ThresholdError::Repair {
                    detail: format!("{from} produced a delta for {to}, which does not help"),
                })?
                .push(delta);
        }
    }

    // Steps 2 and 3.
    let sigmas: Vec<Sigma> = inbox
        .values()
        .map(|deltas| combine_deltas(deltas))
        .collect();

    restore(&sigmas, lost, group)
}
