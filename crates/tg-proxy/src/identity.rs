//! The key material with which the sidecar appears (ADR-0006, ADR-0036).
//!
//! # Which of the two identities
//!
//! A sidecar gets **two** SVIDs over the workload API (ADR-0036): its own with
//! `hint = "self"` and its workload's delegated one with
//! `hint = "delegated"`. On the mesh wire the **delegated** one applies --
//! only that way do the `may_talk` edges read what the operator wrote
//! (ADR-0025).
//!
//! [`Identity::for_mesh`] selects it expressly by `hint`. That is neither
//! chance nor convenience: the agent puts the **narrower** identity to the
//! front, so that a caller who overlooks `hint` gets the narrower authority
//! and fails visibly at the policy -- instead of talking quietly with foreign
//! authority.

use std::fmt;
use std::sync::Arc;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tg_identity::SpiffeId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    EmptyChain,
    Id {
        detail: String,
    },
    MissingHint {
        wanted: String,
    },
    Malformed {
        detail: String,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => f.write_str("the certificate chain is empty"),
            Self::Id { detail } => write!(f, "the SPIFFE ID is not readable: {detail}"),
            Self::MissingHint { wanted } => write!(
                f,
                "the workload API delivered no SVID with hint='{wanted}' -- \
                 without a delegated identity this sidecar cannot speak for its \
                 workload (ADR-0036)"
            ),
            Self::Malformed { detail } => write!(f, "the SVID is not readable: {detail}"),
        }
    }
}

impl std::error::Error for IdentityError {}

#[derive(Clone)]
pub struct Identity {
    id: SpiffeId,
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("id", &self.id)
            .field("chain", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn new(id: &str, chain: Vec<Vec<u8>>, key: Vec<u8>) -> Result<Self, IdentityError> {
        if chain.is_empty() {
            return Err(IdentityError::EmptyChain);
        }

        let id: SpiffeId = id
            .parse()
            .map_err(|err: tg_identity::IdError| IdentityError::Id {
                detail: err.to_string(),
            })?;

        Ok(Self {
            id,
            chain: chain.into_iter().map(CertificateDer::from).collect(),
            key,
        })
    }

    pub fn for_mesh(svids: &[(String, Vec<u8>, Vec<u8>)]) -> Result<Self, IdentityError> {
        Self::with_hint(svids, tg_identity::workload_api::HINT_DELEGATED)
    }

    pub fn with_hint(
        svids: &[(String, Vec<u8>, Vec<u8>)],
        hint: &str,
    ) -> Result<Self, IdentityError> {
        let (_, chain_der, key) = svids
            .iter()
            .find(|(candidate, _, _)| candidate == hint)
            .ok_or_else(|| IdentityError::MissingHint {
                wanted: hint.to_owned(),
            })?;

        // The chain comes as **one** DER sequence; taking it apart means
        // reading ASN.1. The ecosystem's library does that -- the same one 7c
        // substantiated the interop against.
        let svid = spiffe::X509Svid::parse_from_der(chain_der, key).map_err(|err| {
            IdentityError::Malformed {
                detail: err.to_string(),
            }
        })?;

        Self::new(
            &svid.spiffe_id().to_string(),
            svid.cert_chain()
                .iter()
                .map(|cert| cert.as_bytes().to_vec())
                .collect(),
            key.clone(),
        )
    }

    #[must_use]
    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    #[must_use]
    pub fn chain(&self) -> Vec<CertificateDer<'static>> {
        self.chain.clone()
    }

    #[must_use]
    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()))
    }
}

#[derive(Debug, Clone)]
pub struct SharedIdentity {
    inner: Arc<std::sync::RwLock<Arc<Identity>>>,
}

impl SharedIdentity {
    #[must_use]
    pub fn new(identity: Identity) -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(Arc::new(identity))),
        }
    }

    #[must_use]
    pub fn current(&self) -> Arc<Identity> {
        Arc::clone(
            &self
                .inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    #[must_use]
    pub fn id(&self) -> SpiffeId {
        self.current().id().clone()
    }

    pub fn replace(&self, identity: Identity) {
        // When this SVID expires is the number an alarm rule belongs on: if
        // the stream stays out, the sidecar holds its old one and carries on
        // enforcing (ADR-0019) -- until the first handshake fails. An
        // unreadable leaf is not reported: an invented deadline would be worse
        // than none (the same rule as with `tg_node_last_report`).
        if let Some(Ok(until)) = identity
            .chain
            .first()
            .map(|leaf| tg_identity::expires_at(leaf))
        {
            // A Prometheus metric *is* an `f64`. A Unix timestamp would
            // become imprecise beyond 2^53 seconds, that is, in 285 million
            // years.
            #[allow(clippy::cast_precision_loss)]
            metrics::gauge!(tg_telemetry::names::PROXY_SVID_EXPIRES_AT).set(until as f64);
        }

        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *inner = Arc::new(identity);
    }
}
