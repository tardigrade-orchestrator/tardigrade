//! The agent's identity side (ADR-0006, ADR-0019, ADR-0036).
//!
//! The agent holds a short-lived **agent intermediate** and mints the workload
//! SVIDs from it **locally** — no server call in the hot path (ADR-0006/0019).
//! Exactly that is what this file makes tangible: it reads the material from the
//! disk, builds the issuing service and hangs the workload API socket beside it.
//!
//! # Why the material comes from the disk
//!
//! ADR-0006 provides for the control plane issuing the intermediate and the
//! agent fetching it over an authenticated path — "first node credential by join
//! token/TPM; after that agent <-> server over mTLS with node SVIDs".
//!
//! **That path is built** (ADR-0037): with `--control-plane` the agent creates
//! its node key locally, joins against the invitation in
//! `<data-dir>/identity/join-token` and afterwards renews every three hours over
//! this key — see [`crate::join`]. Here it stood that the bootstrap was "decided
//! nowhere"; that was right until ADR-0037 and has been wrong since.
//!
//! What **remains** is the other way: if the material already lies there, it is
//! taken. An operator can put it in place, and the minting path notices no
//! difference — it was laid out for exactly that since 7a. Both ways create
//! **the same** files.
//!
//! ```text
//! <data-dir>/identity/intermediate.pem       the agent intermediate
//! <data-dir>/identity/intermediate.key.pem   its key
//! <data-dir>/identity/bundle.pem             the trust anchors
//! ```

// A module of a binary crate: nothing of it is reachable from outside, and
// `pub(crate)` says so too.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tg_defs::WorkloadExt as _;
use tg_defs::generated::WorkloadType;
use tg_identity::{
    Authority, Ca, Lifetime, LocalSigner, Minter, SystemClock, TrustDomain, WorkloadApi,
};
use tg_model::mesh::{SidecarSpec, delegations};

const DIR: &str = tg_identity::layout::DIR;

#[derive(Debug)]
pub(crate) enum IdentityError {
    Missing {
        path: PathBuf,
        detail: String,
    },
    Material {
        detail: String,
    },
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { path, detail } => write!(
                f,
                "{} not readable: {detail}. Without an agent intermediate this \
                 node mints no SVIDs (ADR-0006)",
                path.display()
            ),
            Self::Material { detail } => write!(f, "identity material unusable: {detail}"),
        }
    }
}

impl std::error::Error for IdentityError {}

#[must_use]
pub(crate) fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join(DIR)
}

#[must_use]
pub(crate) fn is_configured(data_dir: &Path) -> bool {
    dir(data_dir)
        .join(tg_identity::layout::INTERMEDIATE)
        .is_file()
}

pub(crate) fn minter(
    material: &Material,
    domain: &TrustDomain,
) -> Result<Minter<LocalSigner>, IdentityError> {
    let (authority, until) = material.authority()?;

    Ok(Minter::new(
        authority,
        domain.clone(),
        until,
        BTreeMap::new(),
    ))
}

fn build(
    certificate: &str,
    key: &str,
    where_: &Path,
) -> Result<(Authority<LocalSigner>, i64), IdentityError> {
    if certificate.is_empty() || key.is_empty() {
        return Err(IdentityError::Missing {
            path: where_.to_owned(),
            detail: "not readable or empty".to_owned(),
        });
    }

    let ca = Ca::from_pem(certificate).map_err(|err| IdentityError::Material {
        detail: err.to_string(),
    })?;
    let until = ca.not_after();
    let signer = LocalSigner::from_pem(key).map_err(|err| IdentityError::Material {
        detail: err.to_string(),
    })?;
    let authority =
        Authority::new(ca, signer, Lifetime::default()).map_err(|err| IdentityError::Material {
            detail: err.to_string(),
        })?;

    Ok((authority, until))
}

fn anchors_of(contents: &str, path: &Path) -> Result<Vec<Vec<u8>>, IdentityError> {
    let anchors = pem::parse_many(contents).map_err(|err| IdentityError::Material {
        detail: format!("{}: {err}", path.display()),
    })?;
    if anchors.is_empty() {
        return Err(IdentityError::Material {
            detail: format!("{} contains no anchor", path.display()),
        });
    }

    Ok(anchors.into_iter().map(pem::Pem::into_contents).collect())
}

pub(crate) struct Assignment {
    pub assigned: BTreeMap<String, String>,
    pub delegations: BTreeMap<String, String>,
}

#[must_use]
pub(crate) fn assignment(workloads: &[WorkloadType], spec: &SidecarSpec) -> Assignment {
    Assignment {
        assigned: container_ids(workloads),
        delegations: delegations(workloads, spec),
    }
}

pub(crate) fn container_ids(workloads: &[WorkloadType]) -> BTreeMap<String, String> {
    workloads
        .iter()
        .flat_map(|workload| {
            let name = workload.name().to_owned();
            let replicas = workload
                .placement()
                .map_or(1, tg_defs::PlacementExt::replicas);
            (0..replicas).map(move |instance| {
                (
                    tg_runtime::bundle::container_id(&name, instance),
                    name.clone(),
                )
            })
        })
        .collect()
}

pub(crate) type Api = WorkloadApi<LocalSigner>;

#[must_use]
pub(crate) fn workload_api(minter: Minter<LocalSigner>, anchors: Vec<Vec<u8>>) -> Api {
    WorkloadApi::new(minter, anchors, Arc::new(SystemClock))
}

pub(crate) fn ordinal(data_dir: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(dir(data_dir).join(tg_identity::layout::ORDINAL))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[derive(Clone)]
pub(crate) struct Material {
    base: PathBuf,
    intermediate: String,
    key: String,
    bundle: String,
}

impl Material {
    #[must_use]
    pub(crate) fn read(data_dir: &Path) -> Self {
        let base = dir(data_dir);
        Self {
            intermediate: slurp(&base.join(tg_identity::layout::INTERMEDIATE)),
            key: slurp(&base.join(tg_identity::layout::INTERMEDIATE_KEY)),
            bundle: slurp(&base.join(tg_identity::layout::BUNDLE)),
            base,
        }
    }

    pub(crate) fn authority(&self) -> Result<(Authority<LocalSigner>, i64), IdentityError> {
        build(
            &self.intermediate,
            &self.key,
            &self.base.join(tg_identity::layout::INTERMEDIATE),
        )
    }

    pub(crate) fn anchors(&self) -> Result<Vec<Vec<u8>>, IdentityError> {
        anchors_of(&self.bundle, &self.base.join(tg_identity::layout::BUNDLE))
    }

    pub(crate) fn refresh(&mut self, api: &Api) {
        let intermediate = slurp(&self.base.join(tg_identity::layout::INTERMEDIATE));
        let key = slurp(&self.base.join(tg_identity::layout::INTERMEDIATE_KEY));
        if !intermediate.is_empty() && (intermediate != self.intermediate || key != self.key) {
            match build(
                &intermediate,
                &key,
                &self.base.join(tg_identity::layout::INTERMEDIATE),
            ) {
                Ok((authority, until)) => {
                    api.adopt(authority, until);
                    self.intermediate = intermediate;
                    self.key = key;
                    tracing::info!(until, "agent intermediate taken over");
                }
                Err(err) => tracing::warn!(
                    error = %err,
                    "new agent intermediate unusable -- the old one still applies"
                ),
            }
        }

        let bundle = slurp(&self.base.join(tg_identity::layout::BUNDLE));
        if !bundle.is_empty() && bundle != self.bundle {
            match anchors_of(&bundle, &self.base.join(tg_identity::layout::BUNDLE)) {
                Ok(anchors) => {
                    let count = anchors.len();
                    api.set_trust_bundle(anchors);
                    self.bundle = bundle;
                    tracing::info!(anchors = count, "trust anchors taken over");
                }
                Err(err) => tracing::warn!(
                    error = %err,
                    "new trust anchors unusable -- the old ones still apply"
                ),
            }
        }
    }
}

fn slurp(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
