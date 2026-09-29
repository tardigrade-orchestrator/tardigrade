//! The peer verifier (ADR-0007, ADR-0025).
//!
//! # What is different here from ordinary TLS
//!
//! Ordinary TLS asks: "does the name in the certificate match the name I
//! dialled?" SPIFFE mTLS does **not** ask that. The name one dials is an
//! address; the identity stands in the URI SAN, and only it counts
//! (ADR-0006). A verifier that additionally checked the DNS name here would
//! either always fail -- the SVIDs carry no DNS SAN -- or it would check
//! something the attacker chooses.
//!
//! # Three questions, in this order
//!
//! 1. **Does the chain carry up to the anchor?** `webpki`, the same verifier
//!    ADR-0007 names. Here an expired certificate falls, here a foreign CA
//!    falls.
//! 2. **Which identity does the leaf claim?** The SPIFFE ID from the URI SAN.
//!    It is read **twice**: once by the ecosystem's library (`spiffe`, which
//!    also enforces the rule "exactly one URI SAN") and once by the strict
//!    parser from phase 7a. If the two do not agree, it is refused. Two
//!    independent parsers that must agree are cheap to have here -- and the
//!    alternative would be to rely on one whose edge cases one does not know.
//! 3. **May this identity?** The `may_talk` edge, deny-by-default (ADR-0025).
//!
//! # On both sides, and the server is authoritative
//!
//! Both sides check (ADR-0025, defence in depth): the client asks "may I
//! initiate **to** this target?", the server asks "may I accept **from** this
//! source?". Authoritative is the server -- a malicious client does not
//! release itself. The difference lies solely in [`Enforcement`]; the check
//! path is the same.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use rustls_pki_types::{CertificateDer, UnixTime};
use tg_identity::{Role, SpiffeId, TrustDomain};

use crate::policy::{Decision, DenyReason, PolicyCache};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    NoCertificate,
    Chain {
        detail: String,
    },
    NoSpiffeId {
        detail: String,
    },
    Disagreement {
        ecosystem: String,
        strict: String,
    },
    NotAWorkload {
        id: String,
    },
    ForeignTrustDomain {
        expected: String,
        got: String,
    },
    Denied {
        reason: DenyReason,
        from: String,
        to: String,
    },
    PolicyUnavailable,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCertificate => f.write_str("the counterpart presented no certificate"),
            Self::Chain { detail } => write!(f, "the certificate chain does not carry: {detail}"),
            Self::NoSpiffeId { detail } => {
                write!(f, "no SPIFFE ID in the URI SAN: {detail}")
            }
            Self::Disagreement { ecosystem, strict } => write!(
                f,
                "two parsers read different identities from the same SAN: \
                 '{ecosystem}' and '{strict}'. A certificate whose identity \
                 depends on who reads it is not accepted"
            ),
            Self::NotAWorkload { id } => write!(
                f,
                "'{id}' is no workload identity -- nodes do not talk over \
                 may_talk edges (ADR-0006)"
            ),
            Self::ForeignTrustDomain { expected, got } => write!(
                f,
                "the trust domain '{got}' instead of '{expected}' -- ADR-0025 does \
                 not provide for federation"
            ),
            Self::Denied { reason, from, to } => {
                write!(f, "'{from}' must not talk with '{to}': {reason}")
            }
            Self::PolicyUnavailable => f.write_str(
                "the policy cache is not readable; a policy one cannot read is no \
                 permission",
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

#[derive(Debug, Clone, Default)]
pub struct Bundle {
    anchors: Vec<CertificateDer<'static>>,
}

impl Bundle {
    #[must_use]
    pub fn from_der(anchors: Vec<Vec<u8>>) -> Self {
        Self {
            anchors: anchors.into_iter().map(CertificateDer::from).collect(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct SharedPolicy {
    cache: Arc<RwLock<PolicyCache>>,
    version: tokio::sync::watch::Sender<u64>,
}

impl SharedPolicy {
    #[must_use]
    pub fn new(cache: PolicyCache) -> Self {
        let version = cache.version();

        Self {
            cache: Arc::new(RwLock::new(cache)),
            version: tokio::sync::watch::Sender::new(version),
        }
    }

    pub fn apply(
        &self,
        snapshot: &crate::policy::Snapshot,
        at: crate::policy::UnixSeconds,
    ) -> Result<(), crate::policy::PolicyError> {
        let mut cache = self
            .cache
            .write()
            .map_err(|_| crate::policy::PolicyError::Stale {
                have: u64::MAX,
                offered: snapshot.version(),
            })?;
        cache.apply(snapshot, at)?;
        let version = cache.version();
        drop(cache);

        // After releasing the lock: the woken want to read immediately.
        let _ = self.version.send(version);

        Ok(())
    }

    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.version.subscribe()
    }

    #[must_use]
    pub fn handle(&self) -> &Arc<RwLock<PolicyCache>> {
        &self.cache
    }
}

#[derive(Debug, Clone)]
pub struct SharedBundle {
    inner: Arc<RwLock<Arc<Bundle>>>,
}

impl SharedBundle {
    #[must_use]
    pub fn new(bundle: Bundle) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(bundle))),
        }
    }

    #[must_use]
    pub fn current(&self) -> Arc<Bundle> {
        Arc::clone(&self.inner.read().unwrap_or_else(PoisonError::into_inner))
    }

    #[must_use]
    pub fn replace(&self, bundle: Bundle) -> bool {
        if bundle.is_empty() {
            return false;
        }

        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        *inner = Arc::new(bundle);

        true
    }
}

#[derive(Debug, Clone)]
pub struct PeerVerifier {
    local: SpiffeId,
    domain: TrustDomain,
    bundle: SharedBundle,
    policy: SharedPolicy,
    enforcement: Enforcement,
}

impl PeerVerifier {
    #[must_use]
    pub fn new(
        local: SpiffeId,
        bundle: SharedBundle,
        policy: SharedPolicy,
        enforcement: Enforcement,
    ) -> Self {
        let domain = local.trust_domain().clone();

        Self {
            local,
            domain,
            bundle,
            policy,
            enforcement,
        }
    }

    #[must_use]
    pub fn local(&self) -> &SpiffeId {
        &self.local
    }

    pub fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<SpiffeId, VerifyError> {
        self.verify_chain(end_entity, intermediates, now)?;
        let peer = Self::read_identity(end_entity)?;
        self.authorize(&peer)?;

        Ok(peer)
    }

    fn verify_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), VerifyError> {
        let bundle = self.bundle.current();
        let anchors: Vec<rustls_pki_types::TrustAnchor<'_>> = bundle
            .anchors
            .iter()
            .map(|anchor| {
                webpki::anchor_from_trusted_cert(anchor).map_err(|err| VerifyError::Chain {
                    detail: format!("the anchor is unreadable: {err}"),
                })
            })
            .collect::<Result<_, _>>()?;

        let leaf =
            webpki::EndEntityCert::try_from(end_entity).map_err(|err| VerifyError::Chain {
                detail: err.to_string(),
            })?;

        // Both usages are permissible: the same SVID serves the workload as
        // a server **and** as a client (ADR-0006, one identity per
        // container). Which role applies just now is decided by the
        // direction.
        let usage = match self.enforcement {
            Enforcement::Inbound => webpki::KeyUsage::client_auth(),
            Enforcement::Outbound => webpki::KeyUsage::server_auth(),
        };

        // Ed25519 only: all of this system's SVIDs are Ed25519 (ADR-0014,
        // and the threshold CA's group signature is too). A longer list would
        // be an invitation to use a weaker procedure that is never to occur
        // here.
        //
        // The consequence is sharp and belongs here because it surprises: an
        // intermediate with a **different** key type -- RSA from a corporate
        // PKI, say -- mints SVIDs without complaint, and **none** of them is
        // accepted here. Measured: the leaf then carries the signature
        // sha256WithRSA (OID 1.2.840.113549.1.1.11), and the verifier knows
        // only 1.3.101.112. Whoever wants to hang a foreign CA in changes
        // ADR-0014 -- not this list.
        leaf.verify_for_usage(
            &[webpki::ring::ED25519],
            &anchors,
            intermediates,
            now,
            usage,
            None,
            None,
        )
        .map(|_| ())
        .map_err(|err| VerifyError::Chain {
            detail: err.to_string(),
        })
    }

    fn read_identity(end_entity: &CertificateDer<'_>) -> Result<SpiffeId, VerifyError> {
        let certificate = spiffe::Certificate::try_from(end_entity.as_ref()).map_err(|err| {
            VerifyError::NoSpiffeId {
                detail: err.to_string(),
            }
        })?;
        let ecosystem = certificate
            .spiffe_id()
            .map_err(|err| VerifyError::NoSpiffeId {
                detail: err.to_string(),
            })?
            .to_string();

        let strict: SpiffeId =
            ecosystem
                .parse()
                .map_err(|err: tg_identity::IdError| VerifyError::Disagreement {
                    ecosystem: ecosystem.clone(),
                    strict: err.to_string(),
                })?;

        // The round trip must leave the string unchanged. If it did not,
        // there would be two spellings of the same identity -- and an edge
        // that fits only one of them.
        if strict.to_string() != ecosystem {
            return Err(VerifyError::Disagreement {
                ecosystem,
                strict: strict.to_string(),
            });
        }

        Ok(strict)
    }

    fn authorize(&self, peer: &SpiffeId) -> Result<(), VerifyError> {
        if peer.role() != Role::Workload {
            return Err(VerifyError::NotAWorkload {
                id: peer.to_string(),
            });
        }
        if peer.trust_domain() != &self.domain {
            return Err(VerifyError::ForeignTrustDomain {
                expected: self.domain.to_string(),
                got: peer.trust_domain().to_string(),
            });
        }

        let (from, to) = match self.enforcement {
            Enforcement::Inbound => (peer, &self.local),
            Enforcement::Outbound => (&self.local, peer),
        };

        let cache = self
            .policy
            .handle()
            .read()
            .map_err(|_| VerifyError::PolicyUnavailable)?;

        match cache.allows(from, to) {
            Decision::Allow => {
                metrics::counter!(
                    tg_telemetry::names::PROXY_DECISIONS,
                    "direction" => "ingress",
                    "outcome" => "allow",
                )
                .increment(1);
                Ok(())
            }
            Decision::Deny(reason) => Err({
                metrics::counter!(
                    tg_telemetry::names::PROXY_DECISIONS,
                    "direction" => "ingress",
                    "outcome" => "deny",
                )
                .increment(1);
                VerifyError::Denied {
                    reason,
                    from: from.to_string(),
                    to: to.to_string(),
                }
            }),
        }
    }
}
