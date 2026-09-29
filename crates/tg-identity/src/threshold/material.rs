//! The group material on the disk (ADR-0097, determination 3).
//!
//! Two files under `<data-dir>/signing/`: one's own share and the group public key.
//! What does **not** lie here is the decisive property -- there is no `ca.key.pem`
//! any more, and a stolen node gives one share below the threshold (ADR-0014).
//!
//! Both packages are read and written **byte-wise** (`frost-core` serialization),
//! not over `serde`: the byte form is a property of the library version, and it is
//! the only one `frost-core` promises without a feature gate.

use std::path::{Path, PathBuf};

use crate::layout;
use crate::threshold::custody::{SealedShare, ShareCustody, envelope_seat, is_envelope};
use crate::threshold::error::ThresholdError;
use crate::threshold::group::Seat;
use crate::threshold::{KeyPackage, PublicKeyPackage};

/// Which generation of the shares a group holds (ADR-0107, determination 5).
///
/// It does **not** stand in the log, and that is no thrift: the signing group is
/// decoupled from the Raft membership (ADR-0014, determination 1) -- a seat need
/// not see the consensus at all. A marker in the log would be a setting a seat
/// cannot read.
///
/// Material without an epoch -- from the time before ADR-0107 -- is
/// [`Epoch::GENESIS`]. An invented number would take an existing group's shares
/// away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u64);

impl Epoch {
    /// The epoch in which a group stands after the DKG.
    pub const GENESIS: Self = Self(0);

    /// From a number.
    #[must_use]
    pub const fn new(number: u64) -> Self {
        Self(number)
    }

    /// The number.
    #[must_use]
    pub const fn number(self) -> u64 {
        self.0
    }

    /// The next one.
    ///
    /// Saturates instead of overflowing: at `u64::MAX` it stays the same epoch, and
    /// a refresh that brings nothing forward is refused by
    /// [`crate::threshold::refresh`]. An overflow to zero would mean the DKG's epoch
    /// -- that is, a step backwards at the place at which the monotonicity carries
    /// the whole security.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch {}", self.0)
    }
}

/// A seat's material.
#[derive(Debug, Clone)]
pub struct Material {
    seat: Seat,
    share: KeyPackage,
    group: PublicKeyPackage,
    epoch: Epoch,
}

impl Material {
    /// Reads share and group key from `<data-dir>/signing/`.
    ///
    /// The **seat comes from the share** and not from a setting (ADR-0097,
    /// determination 1): the mapping seat <-> FROST `Identifier` is invertible, a
    /// setting beside it would be a second source -- and the dangerous direction,
    /// for a process that announces itself as seat 3 and holds seat 2's share would
    /// let the group take the threshold for reached without it being so.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when a file is missing or its content is no
    /// package; [`ThresholdError::UnknownSeat`] when the share points at a seat that
    /// does not exist in the shape.
    pub fn load(data_dir: &Path, custody: &dyn ShareCustody) -> Result<Self, ThresholdError> {
        let epoch = epochs(data_dir)?.last().copied().unwrap_or(Epoch::GENESIS);

        Self::load_epoch(data_dir, epoch, custody)
    }

    /// Reads a particular generation.
    ///
    /// # Errors
    ///
    /// As [`Material::load`].
    pub fn load_epoch(
        data_dir: &Path,
        epoch: Epoch,
        custody: &dyn ShareCustody,
    ) -> Result<Self, ThresholdError> {
        let share_at = share_path_at(data_dir, epoch);
        let group_at = group_path_at(data_dir, epoch);

        let share = read_share(&share_at, custody)?;
        let group = PublicKeyPackage::deserialize(&read(&group_at)?).map_err(|err| {
            ThresholdError::Custody {
                detail: format!("{}: {err}", group_at.display()),
            }
        })?;

        let seat = Seat::from_identifier(*share.identifier())?;

        Ok(Self {
            seat,
            share,
            group,
            epoch,
        })
    }

    /// Removes a generation from the disk (ADR-0107, determination 6).
    ///
    /// **The disk first, then the memory** -- the other way round it would come back
    /// at the next start, and an operator would take the discarding for failed. If
    /// it is already missing, there is nothing to do: the discarding is idempotent,
    /// because it is attempted again at the next refresh.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when one of the two files lies there and cannot
    /// be removed.
    pub fn remove(data_dir: &Path, epoch: Epoch) -> Result<(), ThresholdError> {
        for path in [
            share_path_at(data_dir, epoch),
            group_path_at(data_dir, epoch),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(ThresholdError::Custody {
                        detail: format!("{}: {err}", path.display()),
                    });
                }
            }
        }

        Ok(())
    }

    /// Files share and group key -- the way the ceremony goes.
    ///
    /// The share gets `0600`, the group key `0644`: the one is a secret, the other
    /// is public and is distributed.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when the write fails.
    pub fn save(
        data_dir: &Path,
        share: &KeyPackage,
        group: &PublicKeyPackage,
        epoch: Epoch,
        custody: &dyn ShareCustody,
    ) -> Result<(), ThresholdError> {
        let dir = layout::signing(data_dir);
        std::fs::create_dir_all(&dir).map_err(|err| ThresholdError::Custody {
            detail: format!("{}: {err}", dir.display()),
        })?;

        let seat = Seat::from_identifier(*share.identifier())?;
        let share_bytes = custody.seal(seat, share)?.blob().to_vec();
        let group_bytes = group.serialize().map_err(|err| ThresholdError::Custody {
            detail: err.to_string(),
        })?;

        write(&share_path_at(data_dir, epoch), &share_bytes, 0o600)?;
        write(&group_path_at(data_dir, epoch), &group_bytes, 0o644)
    }

    /// Seals what still lies in the clear on the disk (ADR-0140, determination 9).
    ///
    /// **Without an operator's handling**, and that is deliberate: a step a human
    /// has to carry out is one they forget on one of five nodes -- and there the
    /// share would then go on lying open without anybody noticing.
    ///
    /// # The counter-check is the whole point
    ///
    /// Sealed, **opened again immediately, compared with the original** -- and only
    /// then is the file replaced. A TPM that seals and does not open would otherwise
    /// take a node's share away, and with a rolling update over the group it would
    /// be all five. What goes wrong in the process costs nothing: the old file is
    /// still there.
    ///
    /// Returns which generations were converted -- empty means nothing lay open (or
    /// the custody does not seal at all, see [`crate::threshold::PlainCustody`]).
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when a generation cannot be read, sealed or
    /// written back. **The error aborts**: a half-converted group is a state nobody
    /// wants to look at.
    pub fn adopt(
        data_dir: &Path,
        custody: &dyn ShareCustody,
    ) -> Result<Vec<Epoch>, ThresholdError> {
        let mut adopted = Vec::new();

        for epoch in epochs(data_dir)? {
            let path = share_path_at(data_dir, epoch);
            let bytes = read(&path)?;
            if is_envelope(&bytes) {
                continue;
            }

            let share = KeyPackage::deserialize(&bytes).map_err(|err| ThresholdError::Custody {
                detail: format!("{}: {err}", path.display()),
            })?;
            let seat = Seat::from_identifier(*share.identifier())?;
            let sealed = custody.seal(seat, &share)?;

            // **Does this custody seal at all?** `PlainCustody` gives the share
            // back unchanged; writing it back would be a conversion that began
            // afresh at every start.
            if !is_envelope(sealed.blob()) {
                continue;
            }

            // The counter-check, **before** the write.
            let opened = custody.unseal(&sealed)?;
            if opened.serialize().map_err(|err| ThresholdError::Custody {
                detail: err.to_string(),
            })? != bytes
            {
                return Err(ThresholdError::Custody {
                    detail: format!(
                        "{}: the sealed share came back different -- nothing is replaced",
                        path.display()
                    ),
                });
            }

            write(&path, sealed.blob(), 0o600)?;
            adopted.push(epoch);
        }

        Ok(adopted)
    }

    /// The seat this process holds.
    #[must_use]
    pub fn seat(&self) -> Seat {
        self.seat
    }

    /// The group public key.
    #[must_use]
    pub fn group(&self) -> &PublicKeyPackage {
        &self.group
    }

    /// One's own share.
    ///
    /// The caller builds the [`crate::threshold::Participant`] itself, because it
    /// must **share** the `LocalLink` that arises from it: the same one stands in
    /// its own signer and in the signer service (ADR-0097, determination 2). Two
    /// carriers would be two nonce vaults.
    #[must_use]
    pub fn share(&self) -> &KeyPackage {
        &self.share
    }

    /// Which generation of the shares this seat holds.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Material a caller already has in hand.
    ///
    /// The way for the ceremony and for the refresh: both produce share and group
    /// key before anything lies on a disk.
    #[must_use]
    pub fn held(seat: Seat, share: KeyPackage, group: PublicKeyPackage, epoch: Epoch) -> Self {
        Self {
            seat,
            share,
            group,
            epoch,
        }
    }

    /// Hands out the group key -- the way into `ThresholdSigner::new`.
    #[must_use]
    pub fn into_group(self) -> PublicKeyPackage {
        self.group
    }
}

/// Reads a share -- **both forms** (ADR-0140).
///
/// If the file carries the marker, it is an envelope and goes through the custody.
/// If it does not carry it, it is a naked share from the time before, and it is read
/// instead of refused: a cluster that converts to the TPM must not stop in the
/// process. It is cleared up by [`Material::adopt`], not here -- **reading reads**.
fn read_share(path: &Path, custody: &dyn ShareCustody) -> Result<KeyPackage, ThresholdError> {
    let bytes = read(path)?;

    if is_envelope(&bytes) {
        // The seat stands **in** the envelope: without it the share could not be
        // opened without knowing it already.
        let seat = envelope_seat(&bytes)?;
        return custody.unseal(&SealedShare::new(seat, bytes));
    }

    KeyPackage::deserialize(&bytes).map_err(|err| ThresholdError::Custody {
        detail: format!("{}: {err}", path.display()),
    })
}

/// `<data-dir>/signing/share` -- the generation after the DKG.
#[must_use]
pub fn share_path(data_dir: &Path) -> PathBuf {
    share_path_at(data_dir, Epoch::GENESIS)
}

/// `<data-dir>/signing/group` -- the generation after the DKG.
#[must_use]
pub fn group_path(data_dir: &Path) -> PathBuf {
    group_path_at(data_dir, Epoch::GENESIS)
}

/// A generation's share.
///
/// [`Epoch::GENESIS`] carries **no** suffix, and that is no style: a group from the
/// time before ADR-0107 lies under this name, and it is to carry on without a
/// handling.
#[must_use]
pub fn share_path_at(data_dir: &Path, epoch: Epoch) -> PathBuf {
    layout::signing(data_dir).join(suffixed(layout::SHARE, epoch))
}

/// A generation's group key.
///
/// It moves along although the **verifying key** stays the same (measured,
/// ADR-0107): what changes are the `verifying_shares`, and without the matching
/// ones no signature aggregates.
#[must_use]
pub fn group_path_at(data_dir: &Path, epoch: Epoch) -> PathBuf {
    layout::signing(data_dir).join(suffixed(layout::GROUP, epoch))
}

/// Which generations lie under `<data-dir>/signing/`, ascending.
///
/// What is counted is what has **both** -- share and group key. A half generation is
/// none: it would arise if a refresh aborted between the two writes, and a seat that
/// took it for an epoch would be in one in which it cannot sign.
///
/// # Errors
///
/// [`ThresholdError::Custody`] when the directory is not readable. That it is
/// **missing** is no error: a node without group material is the normal case
/// (ADR-0097).
pub fn epochs(data_dir: &Path) -> Result<Vec<Epoch>, ThresholdError> {
    let dir = layout::signing(data_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(ThresholdError::Custody {
                detail: format!("{}: {err}", dir.display()),
            });
        }
    };

    let mut found = std::collections::BTreeSet::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(epoch) = epoch_of(name, layout::SHARE)
            && group_path_at(data_dir, epoch).exists()
        {
            found.insert(epoch);
        }
    }

    Ok(found.into_iter().collect())
}

/// Which **group keys** lie under `<data-dir>/signing/`.
///
/// The difference from [`epochs`] is the whole purpose: there only what has
/// **both** counts, because a half generation is none (ADR-0107) -- here the group
/// alone counts, for that **is** the repair case: the share is gone, the group key
/// lies there (ADR-0108). Without this read path the coordinator could not read the
/// key it must check the result against (determination 6).
///
/// Sorted ascending; the **last** one is the generation in which the group is
/// currently signing (a helper lays out its deltas from `newest_material()`).
///
/// # Errors
///
/// [`ThresholdError::Custody`] when the directory is not readable. That it is
/// **missing** is none: then no material lies there.
pub fn groups(data_dir: &Path) -> Result<Vec<Epoch>, ThresholdError> {
    let dir = layout::signing(data_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(ThresholdError::Custody {
                detail: format!("{}: {err}", dir.display()),
            });
        }
    };

    let mut found = std::collections::BTreeSet::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(epoch) = epoch_of(name, layout::GROUP) {
            found.insert(epoch);
        }
    }

    Ok(found.into_iter().collect())
}

/// Reads a group key -- **without** the share beside it.
///
/// # Errors
///
/// [`ThresholdError::Custody`] when the file is missing or its content is no
/// package.
pub fn load_group(data_dir: &Path, epoch: Epoch) -> Result<PublicKeyPackage, ThresholdError> {
    let at = group_path_at(data_dir, epoch);

    PublicKeyPackage::deserialize(&read(&at)?).map_err(|err| ThresholdError::Custody {
        detail: format!("{}: {err}", at.display()),
    })
}

fn suffixed(stem: &str, epoch: Epoch) -> String {
    if epoch == Epoch::GENESIS {
        stem.to_owned()
    } else {
        format!("{stem}.{}", epoch.number())
    }
}

fn epoch_of(name: &str, stem: &str) -> Option<Epoch> {
    if name == stem {
        return Some(Epoch::GENESIS);
    }

    let rest = name.strip_prefix(stem)?.strip_prefix('.')?;

    rest.parse().ok().map(Epoch::new)
}

fn read(path: &Path) -> Result<Vec<u8>, ThresholdError> {
    std::fs::read(path).map_err(|err| ThresholdError::Custody {
        detail: format!("{}: {err}", path.display()),
    })
}

fn write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ThresholdError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, bytes).map_err(|err| ThresholdError::Custody {
        detail: format!("{}: {err}", path.display()),
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|err| {
        ThresholdError::Custody {
            detail: format!("{}: {err}", path.display()),
        }
    })
}
