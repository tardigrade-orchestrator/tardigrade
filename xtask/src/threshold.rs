//! The signing group for a local run (ADR-0097, determination 5).
//!
//! Runs the DKG over the five seats from ADR-0014 and puts the material down for
//! each of them, plus the CA certificate over the group key.
//!
//! **This process sees all five shares.** For the duration of its run it is
//! thereby the full CA key — precisely what the group abolishes. In operation
//! the DKG is a **ceremony**: every seat produces its share on its own machine,
//! and the rounds go over a channel a human has established. A tool that runs it
//! in one process is therefore no substitute and lies in the `xtask` rather than
//! in a delivery binary (ADR-0023) — the same separation as at
//! `cargo xtask identity`.

use std::fs;
use std::path::Path;

use crate::TaskError;

/// Produces the group and puts it down for every seat under `<root>/<seat>`.
pub(crate) fn run(root: &Path, domain: &str) -> Result<(), TaskError> {
    use tg_identity::threshold::{Epoch, GroupShape, Material, OsEntropy, PlainCustody, dkg};

    let shape = GroupShape::adr_0014();
    let fail = |what: &str, err: &dyn std::fmt::Display| TaskError::Identity {
        detail: format!("{what}: {err}"),
    };

    // **One** ceremony function, not a copy here: it stands in `tg-identity`,
    // and the witness over five processes uses the same one.
    let mut entropy = OsEntropy;
    let done = dkg::ceremony(shape, &mut entropy).map_err(|err| fail("DKG", &err))?;

    let mut group_key = None;
    for (seat, share, group) in done {
        let dir = root.join(seat.number().to_string());
        fs::create_dir_all(&dir)?;
        // **`PlainCustody`, and that is the right choice here** (ADR-0140). The
        // ceremony runs on **one** machine and produces shares for **five**
        // nodes. Sealing them into this machine's TPM would mean that no other
        // node could ever open its share -- a sealed share is bound to exactly
        // this device, that is its whole purpose.
        //
        // The share therefore leaves the ceremony in the clear, is transported,
        // and **every node seals it itself at the first start**
        // (`Material::adopt`).
        Material::save(&dir, &share, &group, Epoch::GENESIS, &PlainCustody)
            .map_err(|err| fail("store material", &err))?;
        group_key = Some(group);
    }

    // The CA certificate over the group key. It is **public** and stands at
    // every seat — signed by the group itself, so it needed all five shares, and
    // only this process has them.
    let group = group_key.ok_or_else(|| TaskError::Identity {
        detail: "the DKG yielded no group key".to_owned(),
    })?;
    certify(root, &group, shape, domain)?;

    eprintln!(
        "threshold: {} seats in {} (each <seat>/signing/), threshold {}.",
        shape.seats(),
        root.display(),
        shape.threshold()
    );
    eprintln!(
        "threshold: dev material. **This process has seen all shares** — in \
         operation the DKG is a ceremony (ADR-0014)."
    );

    Ok(())
}

/// Issues the CA certificate over the group key and puts it down at every seat.
///
/// Signed with the **group**: this process holds all shares, so it can — and
/// afterwards nobody can alone. That is the moment at which the key stops lying
/// in one place.
fn certify(
    root: &Path,
    group: &tg_identity::threshold::PublicKeyPackage,
    shape: tg_identity::threshold::GroupShape,
    domain: &str,
) -> Result<(), TaskError> {
    use std::sync::Arc;
    use tg_identity::threshold::{
        LocalLink, Material, OsEntropy, Participant, PlainCustody, SignerLink, ThresholdSigner,
    };

    let fail = |what: &str, err: &dyn std::fmt::Display| TaskError::Identity {
        detail: format!("{what}: {err}"),
    };

    // All five seats in this process — the reason why this is an `xtask`.
    let mut links: Vec<Arc<dyn SignerLink>> = Vec::new();
    for seat in shape.places() {
        let dir = root.join(seat.number().to_string());
        // The same reason as in the ceremony: five seats in **one** process, so
        // no device binding.
        let material =
            Material::load(&dir, &PlainCustody).map_err(|err| fail("read material", &err))?;
        let participant = Participant::new(
            seat,
            material.share(),
            material.group(),
            material.epoch(),
            Arc::new(PlainCustody),
        )
        .map_err(|err| fail("seal share", &err))?;
        links.push(Arc::new(LocalLink::new(participant, Box::new(OsEntropy))));
    }

    let signer = ThresholdSigner::new(group.clone(), shape, links)
        .map_err(|err| fail("build group", &err))?;

    let domain = tg_identity::TrustDomain::new(domain.to_owned())
        .map_err(|err| fail("trust domain", &err))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| fail("clock", &err))?
        .as_secs();
    #[expect(
        clippy::cast_possible_wrap,
        reason = "a Unix second fits into i64 until 2038 x 10^11"
    )]
    let ca = tg_identity::self_signed_ca(
        &domain,
        &signer,
        now as i64 - 3600,
        now as i64 + 3650 * 86_400,
    )
    .map_err(|err| fail("CA certificate", &err))?;

    // The anchor: the same certificate. The group is a root, not an intermediate
    // under another one — there is nobody who signs it.
    for seat in shape.places() {
        let dir = tg_identity::layout::signing(&root.join(seat.number().to_string()));
        fs::write(dir.join(tg_identity::layout::CA), ca.certificate_pem())?;
        fs::write(dir.join(tg_identity::layout::BUNDLE), ca.certificate_pem())?;
    }

    Ok(())
}
