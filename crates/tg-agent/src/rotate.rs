//! Key rotation on the node (ADR-0055).
//!
//! The cluster says which **generation** shall apply; the node compares it with
//! its own and follows. No reception of a "rotate now", no state "rotating right
//! now" in the log, no catching up: whoever was away compares on return
//! (ADR-0010).
//!
//! # The order is the whole art
//!
//! For the underlay key: generate -> put it **beside** -> announce -> wait until
//! its own slice confirms it -> **only then** switch over. The other way round
//! the node cuts itself off before any peer knows of it.
//!
//! Step three needs no trigger of its own: after generating, log and
//! announcement diverge, and the comparison from ADR-0042 wakes the renewer.
//!
//! # Why beside and not over
//!
//! As long as the confirmation is missing, the **old** key is the valid one.
//! Overwriting it would mean relying on an assurance nobody has yet given — and a
//! node whose peers no longer understand it can no longer call for help either
//! (ADR-0019).

use std::path::{Path, PathBuf};

use tg_model::KeyKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Wait,
    Generate,
    Promote,
}

#[must_use]
pub(crate) const fn step(wanted: u64, mine: u64, pending: bool, confirmed: bool) -> Step {
    if pending {
        // **The confirmation beats everything.** Even if an even higher
        // generation is wanted by then: first the change that was begun is
        // finished, otherwise an announced key would stay lying unused and the
        // node would announce a third that again nobody knows.
        if confirmed { Step::Promote } else { Step::Wait }
    } else if wanted > mine {
        Step::Generate
    } else {
        Step::Wait
    }
}

pub(crate) struct Files {
    pub(crate) current: PathBuf,
    pub(crate) pending: PathBuf,
    pub(crate) generation: PathBuf,
    pub(crate) pending_generation: PathBuf,
}

impl Files {
    pub(crate) fn new(data_dir: &Path, kind: KeyKind) -> Self {
        Self::in_identity_dir(&crate::identity::dir(data_dir), kind)
    }

    pub(crate) fn in_identity_dir(dir: &Path, kind: KeyKind) -> Self {
        let stem = match kind {
            KeyKind::Identity => tg_identity::layout::NODE_KEY,
            KeyKind::Underlay => tg_identity::layout::UNDERLAY_KEY,
        };

        Self {
            current: dir.join(stem),
            pending: dir.join(format!("{stem}.pending")),
            generation: dir.join(format!("{stem}.generation")),
            pending_generation: dir.join(format!("{stem}.pending.generation")),
        }
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.pending.is_file()
    }

    pub(crate) fn generation(&self) -> u64 {
        read_number(&self.generation)
    }

    pub(crate) fn pending_generation(&self) -> u64 {
        read_number(&self.pending_generation)
    }

    pub(crate) fn stage(&self, material: &str, generation: u64) -> Result<(), String> {
        crate::join::write_secret(&self.pending, material).map_err(|err| err.to_string())?;
        std::fs::write(&self.pending_generation, format!("{generation}\n"))
            .map_err(|err| format!("{}: {err}", self.pending_generation.display()))
    }

    pub(crate) fn promote(&self) -> Result<(), String> {
        let generation = self.pending_generation();

        std::fs::write(&self.generation, format!("{generation}\n"))
            .map_err(|err| format!("{}: {err}", self.generation.display()))?;
        std::fs::rename(&self.pending, &self.current)
            .map_err(|err| format!("{}: {err}", self.current.display()))?;
        let _ = std::fs::remove_file(&self.pending_generation);

        Ok(())
    }
}

fn read_number(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{Step, step};

    #[test]
    fn nothing_to_do_when_the_generation_matches() {
        assert_eq!(step(0, 0, false, false), Step::Wait);
        assert_eq!(step(3, 3, false, false), Step::Wait);
    }

    #[test]
    fn a_higher_wanted_generation_generates() {
        assert_eq!(step(1, 0, false, false), Step::Generate);
    }

    #[test]
    fn without_confirmation_nothing_is_switched() {
        assert_eq!(step(1, 0, true, false), Step::Wait);
    }

    #[test]
    fn with_confirmation_the_pending_key_is_promoted() {
        assert_eq!(step(1, 0, true, true), Step::Promote);
    }

    #[test]
    fn a_started_rotation_finishes_before_the_next_begins() {
        assert_eq!(step(5, 0, true, true), Step::Promote);
        assert_eq!(step(5, 0, true, false), Step::Wait);
    }

    #[test]
    fn a_lower_wanted_generation_changes_nothing() {
        assert_eq!(step(1, 3, false, false), Step::Wait);
    }
}

// =============================================================== The underlay way

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Done {
    Nothing,
    Staged,
    Promoted,
}

pub(crate) fn underlay(
    data_dir: &Path,
    wanted: u64,
    announced: Option<&str>,
) -> Result<Done, String> {
    let files = Files::new(data_dir, KeyKind::Underlay);

    let pending_public = std::fs::read_to_string(&files.pending)
        .ok()
        .and_then(|text| tg_net::wireguard::Keypair::from_private_base64(text.trim()).ok())
        .map(|key| key.public_base64());

    // Confirmed means: the cluster names **the one lying beside it**.
    let confirmed = match (&pending_public, announced) {
        (Some(pending), Some(announced)) => pending == announced,
        _ => false,
    };

    match step(wanted, files.generation(), files.has_pending(), confirmed) {
        Step::Wait => Ok(Done::Nothing),
        Step::Generate => {
            let key = tg_net::wireguard::Keypair::generate();
            files.stage(&format!("{}\n", key.private_base64()), wanted)?;
            Ok(Done::Staged)
        }
        Step::Promote => {
            files.promote()?;
            Ok(Done::Promoted)
        }
    }
}

#[must_use]
pub(crate) fn current(data_dir: &Path) -> tg_model::Generations {
    let mut out = tg_model::Generations::default();
    for kind in KeyKind::ALL {
        out.set(kind, Files::new(data_dir, kind).generation());
    }

    out
}

#[must_use]
pub(crate) fn pending(data_dir: &Path) -> bool {
    KeyKind::ALL
        .iter()
        .any(|kind| Files::new(data_dir, *kind).has_pending())
}

#[must_use]
pub(crate) fn key_to_announce(data_dir: &Path) -> Option<String> {
    let files = Files::new(data_dir, KeyKind::Underlay);

    for path in [&files.pending, &files.current] {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(key) = tg_net::wireguard::Keypair::from_private_base64(text.trim())
        {
            return Some(key.public_base64());
        }
    }

    None
}

pub(crate) fn identity(data_dir: &Path, wanted: u64) -> Result<Done, String> {
    let files = Files::new(data_dir, KeyKind::Identity);

    // `pending` here means "already announced": the next request carries it. A
    // second generated key would overwrite the first before the server has seen
    // it.
    if files.has_pending() || wanted <= files.generation() {
        return Ok(Done::Nothing);
    }

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|err| format!("the node key cannot be generated: {err}"))?;
    files.stage(&key.serialize_pem(), wanted)?;

    Ok(Done::Staged)
}
