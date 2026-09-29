//! Local minting in the agent (ADR-0006, ADR-0019).
//!
//! The agent holds a short-lived **agent intermediate** (ADR-0014: 12 h, renewal
//! every 3 h) and mints the workload SVIDs from it **itself**. No server call in the
//! hot path -- that is the static stability from ADR-0019 at the place at which it is
//! worth the most: if the control plane fails, running containers keep getting their
//! certificates.
//!
//! # The buffer has an end, and that is deliberate
//!
//! The minting runs only as long as the intermediate holds. Afterwards it is over --
//! not out of harshness but because the alternative would be worse: an agent that
//! keeps minting after the expiry issues identities nobody can revoke any more.
//! ADR-0014 names the ordering condition for that: the intermediate's lifetime must
//! lie above the control plane's expected outage window. That is a statement about
//! the **number**, not about the behaviour when it is exceeded.

use std::collections::BTreeMap;

use crate::attest::Attestation;
use crate::id::{SpiffeId, TrustDomain};
use crate::lifetime::{UnixSeconds, Validity};
use crate::mint::{Authority, MintError, Svid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotAttested,
    NotAssigned {
        workload: String,
    },
    UnknownContainer {
        container_id: String,
    },
    IntermediateExpired {
        expired_at: UnixSeconds,
    },
    MintFailed {
        detail: String,
    },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAttested => {
                f.write_str("the asking process runs in no container of this orchestrator")
            }
            Self::UnknownContainer { container_id } => write!(
                f,
                "the container '{container_id}' belongs to no workload of this node \
                 -- this agent must not mint for it (ADR-0006)"
            ),
            Self::NotAssigned { workload } => write!(
                f,
                "'{workload}' is not assigned to this node -- this agent must not \
                 mint for it (ADR-0006)"
            ),
            Self::IntermediateExpired { expired_at } => write!(
                f,
                "the agent intermediate has been expired since {expired_at}; without \
                 a renewal by the control plane nothing is minted any more"
            ),
            Self::MintFailed { detail } => write!(f, "the SVID cannot be issued: {detail}"),
        }
    }
}

impl std::error::Error for Refusal {}

pub struct Minter<S: rcgen::SigningKey> {
    authority: Authority<S>,
    domain: TrustDomain,
    intermediate_until: UnixSeconds,
    assigned: BTreeMap<String, String>,
    delegations: BTreeMap<String, String>,
    issued: BTreeMap<String, Svid>,
}

impl<S: rcgen::SigningKey> std::fmt::Debug for Minter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minter")
            .field("domain", &self.domain)
            .field("intermediate_until", &self.intermediate_until)
            .field("assigned", &self.assigned)
            .finish_non_exhaustive()
    }
}

impl<S: rcgen::SigningKey> Minter<S> {
    #[must_use]
    pub fn new(
        authority: Authority<S>,
        domain: TrustDomain,
        intermediate_until: UnixSeconds,
        assigned: BTreeMap<String, String>,
    ) -> Self {
        report_expiry(intermediate_until);

        Self {
            authority,
            domain,
            intermediate_until,
            assigned,
            delegations: BTreeMap::new(),
            issued: BTreeMap::new(),
        }
    }

    pub fn set_delegations(&mut self, delegations: BTreeMap<String, String>) {
        self.delegations = delegations;
    }

    #[must_use]
    pub fn delegation_of(&self, workload: &str) -> Option<&str> {
        self.delegations.get(workload).map(String::as_str)
    }

    pub fn set_assigned(&mut self, assigned: BTreeMap<String, String>) {
        self.assigned = assigned;
    }

    #[must_use]
    pub fn workload_of(&self, attestation: &Attestation) -> Option<&str> {
        attestation.resolve(&self.assigned)
    }

    pub fn adopt(&mut self, authority: Authority<S>, intermediate_until: UnixSeconds) {
        self.authority = authority;
        self.intermediate_until = intermediate_until;
        self.issued.clear();
        report_expiry(intermediate_until);
    }

    #[must_use]
    pub fn can_mint_at(&self, now: UnixSeconds) -> bool {
        now < self.intermediate_until
    }

    pub fn svid_for(
        &mut self,
        attestation: &Attestation,
        now: UnixSeconds,
    ) -> Result<&Svid, Refusal> {
        let workload = attestation
            .resolve(&self.assigned)
            .ok_or_else(|| Refusal::UnknownContainer {
                container_id: attestation.container_id().to_owned(),
            })?
            .to_owned();

        self.svid_named(&workload, now)
    }

    pub fn svid_named(&mut self, workload: &str, now: UnixSeconds) -> Result<&Svid, Refusal> {
        if !self.assigned.values().any(|name| name == workload) {
            return Err(Refusal::NotAssigned {
                workload: workload.to_owned(),
            });
        }

        let workload = workload.to_owned();
        let fresh_enough = self
            .issued
            .get(&workload)
            .is_some_and(|svid| !svid.validity().should_rotate_at(now));

        if !fresh_enough {
            match self.mint(&workload, now) {
                Ok(svid) => {
                    self.issued.insert(workload.clone(), svid);
                }
                Err(refusal) => {
                    // Minting does not work -- but an SVID from the cache that is
                    // still usable is better than none. Exactly that is the soft
                    // fail from ADR-0019: the CA's outage breaks no existing
                    // connection as long as the grace runs.
                    let usable = self
                        .issued
                        .get(&workload)
                        .is_some_and(|svid| svid.validity().is_usable_at(now));
                    if !usable {
                        return Err(refusal);
                    }
                }
            }
        }

        self.issued.get(&workload).ok_or(Refusal::NotAttested)
    }

    #[must_use]
    pub fn chain_pem(&self) -> &str {
        self.authority.certificate_pem()
    }

    #[must_use]
    pub fn chain_der(&self) -> &[u8] {
        self.authority.certificate_der()
    }

    #[must_use]
    pub fn domain(&self) -> &TrustDomain {
        &self.domain
    }

    #[must_use]
    pub fn lifetime(&self) -> crate::lifetime::Lifetime {
        self.authority.lifetime()
    }

    #[must_use]
    pub fn validity_of(&self, workload: &str) -> Option<Validity> {
        self.issued.get(workload).map(Svid::validity)
    }

    fn mint(&self, workload: &str, now: UnixSeconds) -> Result<Svid, Refusal> {
        let svid = self.mint_inner(workload, now);
        // **Not** the SPIFFE ID as a label (ADR-0015, cardinality rule in
        // `tg_telemetry::names`): it is different per workload and instance, and an
        // attacker who chooses names freely could inflate the metric. The outcome
        // suffices -- which identity it was stands in the audit trail (ADR-0020).
        metrics::counter!(
            tg_telemetry::names::SVID_ISSUED,
            "outcome" => if svid.is_ok() { "issued" } else { "refused" },
        )
        .increment(1);
        svid
    }

    fn mint_inner(&self, workload: &str, now: UnixSeconds) -> Result<Svid, Refusal> {
        if !self.can_mint_at(now) {
            return Err(Refusal::IntermediateExpired {
                expired_at: self.intermediate_until,
            });
        }

        let id =
            SpiffeId::for_workload(&self.domain, workload).map_err(|err| Refusal::MintFailed {
                detail: err.to_string(),
            })?;

        self.authority
            .issue(&id, now)
            .map_err(|err: MintError| Refusal::MintFailed {
                detail: err.to_string(),
            })
    }
}

fn report_expiry(until: UnixSeconds) {
    REPORTED_EXPIRY.store(until, std::sync::atomic::Ordering::Relaxed);
    publish_expiry(until);
}

static REPORTED_EXPIRY: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

// A Prometheus metric *is* an `f64`. A Unix timestamp would become imprecise beyond
// 2^53 seconds, that is, in 285 million years.
#[allow(clippy::cast_precision_loss)]
fn publish_expiry(until: UnixSeconds) {
    metrics::gauge!(tg_telemetry::names::INTERMEDIATE_EXPIRES_AT).set(until as f64);
}

pub fn refresh_expiry() {
    let until = REPORTED_EXPIRY.load(std::sync::atomic::Ordering::Relaxed);
    if until != 0 {
        publish_expiry(until);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntermediateProfile {
    pub ttl: std::time::Duration,
    pub renew_after: std::time::Duration,
}

impl IntermediateProfile {
    pub const TTL: std::time::Duration = std::time::Duration::from_hours(12);

    pub const RENEW_AFTER: std::time::Duration = std::time::Duration::from_hours(3);
}

impl Default for IntermediateProfile {
    fn default() -> Self {
        Self {
            ttl: Self::TTL,
            renew_after: Self::RENEW_AFTER,
        }
    }
}

impl IntermediateProfile {
    pub fn validate(self) -> Result<(), String> {
        if self.ttl.is_zero() {
            return Err("the intermediate's lifetime is zero".to_owned());
        }
        if self.renew_after * 4 > self.ttl {
            return Err(format!(
                "renewal after {:?} is not far enough before the expiry ({:?}) -- \
                 ADR-0014 demands renewal much smaller than lifetime",
                self.renew_after, self.ttl
            ));
        }

        Ok(())
    }
}

pub fn report_data_key(path: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(key) = crate::secrets::DataKey::from_base64(text.trim()) else {
        return;
    };
    metrics::gauge!(
        tg_telemetry::names::DATA_KEY,
        "fingerprint" => key.fingerprint()
    )
    .set(1.0);
}
