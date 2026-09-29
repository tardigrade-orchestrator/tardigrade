//! Identity material for a local run (ADR-0006, ADR-0014).
//!
//! Produces a small chain — root and agent intermediate — and puts it where
//! `tg-agent` looks for it.
//!
//! In operation the root comes from an HSM and is air-gapped, and the agent
//! intermediate is issued by the control plane over an authenticated path
//! (ADR-0006/0014). What arises here is **dev material**: good enough to see the
//! path from the socket to the sidecar run once, and expressly nothing that
//! shall ever carry a cluster. Hence it lies in the `xtask` and not in a
//! delivery binary — a tool that creates CAs does not belong in the same program
//! that trusts them.
//!
//! **Ed25519, and that is no choice.** ADR-0014 fixed the signing CA as a FROST
//! group, and a FROST group signature **is** an Ed25519 signature. An
//! intermediate with a different key type — RSA from a corporate PKI, say —
//! mints SVIDs without complaint, and **none** of them is accepted: the leaf
//! would carry `sha256WithRSA`, and the verifier knows only `1.3.101.112`. This
//! trap is measured and noted in `tg_proxy::verify`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::TaskError;

/// The intermediate's lifetime from ADR-0014.
const HOURS: u64 = 12;

/// Produces root and agent intermediate below `data_dir`.
pub(crate) fn run(data_dir: &Path, hours: u64) -> Result<(), TaskError> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    let dir = tg_identity::layout::dir(data_dir);
    fs::create_dir_all(&dir)?;

    let now = time::OffsetDateTime::now_utc();
    let fail = |what: &str, err: &dyn std::fmt::Display| TaskError::Identity {
        detail: format!("{what}: {err}"),
    };

    // The root. In operation it lies in the HSM and never sees this machine.
    let root_key =
        KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|err| fail("root key", &err))?;
    let mut root = CertificateParams::default();
    root.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    root.not_before = now - time::Duration::hours(1);
    root.not_after = now + time::Duration::days(3650);
    root.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    root.distinguished_name = DistinguishedName::new();
    root.distinguished_name
        .push(DnType::CommonName, "tardigrade dev root");
    let root_cert = root
        .clone()
        .self_signed(&root_key)
        .map_err(|err| fail("root certificate", &err))?;

    // The agent intermediate. Its lifetime is the one from ADR-0014, and it is
    // meant to be short: if it expires, the agent mints no more. Precisely that
    // is worth having seen once.
    let agent_key =
        KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|err| fail("agent key", &err))?;
    let mut agent = CertificateParams::default();
    agent.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    agent.not_before = now - time::Duration::hours(1);
    agent.not_after =
        now + time::Duration::hours(i64::try_from(hours).unwrap_or(i64::from(u32::MAX)));
    agent.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    agent.distinguished_name = DistinguishedName::new();
    agent
        .distinguished_name
        .push(DnType::CommonName, "tardigrade dev agent intermediate");

    let issuer = Issuer::from_params(&root, &root_key);
    let agent_cert = agent
        .signed_by(&agent_key, &issuer)
        .map_err(|err| fail("agent intermediate", &err))?;

    write(
        &dir.join(tg_identity::layout::INTERMEDIATE),
        &agent_cert.pem(),
        false,
    )?;
    write(
        &dir.join(tg_identity::layout::INTERMEDIATE_KEY),
        &agent_key.serialize_pem(),
        true,
    )?;
    write(
        &dir.join(tg_identity::layout::BUNDLE),
        &root_cert.pem(),
        false,
    )?;

    eprintln!(
        "identity: root and agent intermediate in {} — the intermediate expires \
         in {hours} h (ADR-0014).",
        dir.display()
    );
    eprintln!("identity: dev material. It carries no cluster.");

    Ok(())
}

/// Writes a file; keys readable only by the owner.
fn write(path: &PathBuf, contents: &str, secret: bool) -> Result<(), TaskError> {
    fs::write(path, contents)?;

    if secret {
        use std::os::unix::fs::PermissionsExt as _;

        // 0600. A private key the group can read is one that knows the group.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// The default for the lifetime.
pub(crate) const fn default_hours() -> u64 {
    HOURS
}
