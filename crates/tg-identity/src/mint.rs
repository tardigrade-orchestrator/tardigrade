//! The minting of an X.509 SVID (ADR-0006).
//!
//! An SVID is an ordinary X.509 certificate with one peculiarity: the identity
//! stands **not** in the subject but as a URI in the SAN. Thereby every standard TLS
//! library verifies the chain without a special path, and the SPIFFE ID is
//! nevertheless unambiguously readable (ADR-0007 builds on that).
//!
//! # The signature seam
//!
//! Signing goes over `rcgen::SigningKey` -- a trait with exactly one method,
//! `sign(&self, msg) -> Vec<u8>`. It does **not** demand that the signer hold a key.
//! Exactly on that hangs ADR-0014: in phase 7b a FROST round over the cluster steps
//! behind this method without a line becoming different here.
//!
//! What phase 7a brings along is [`LocalSigner`] -- an Ed25519 key in memory. It is
//! **not** the custody model from ADR-0014 and carries that in its name and in the
//! documentation, so that nobody takes it for one.

use rcgen::{
    CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, KeyUsagePurpose, SanType,
};

use x509_parser::prelude::FromDer as _;

use crate::id::SpiffeId;
use crate::lifetime::{Lifetime, UnixSeconds, Validity};

#[derive(Debug)]
pub struct MintError {
    detail: String,
}

impl MintError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the SVID cannot be issued: {}", self.detail)
    }
}

impl std::error::Error for MintError {}

#[derive(Clone)]
pub struct Svid {
    id: SpiffeId,
    certificate_pem: String,
    certificate_der: Vec<u8>,
    private_key_pem: String,
    private_key_der: Vec<u8>,
    validity: Validity,
}

impl std::fmt::Debug for Svid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Svid")
            .field("id", &self.id)
            .field("validity", &self.validity)
            .finish_non_exhaustive()
    }
}

impl Svid {
    #[must_use]
    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    #[must_use]
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    #[must_use]
    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }

    #[must_use]
    pub fn validity(&self) -> Validity {
        self.validity
    }
}

#[derive(Debug)]
pub struct LocalSigner {
    key: KeyPair,
}

impl LocalSigner {
    pub fn generate() -> Result<Self, MintError> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|err| MintError::new(err.to_string()))?;

        Ok(Self { key })
    }

    pub fn from_pem(pem: &str) -> Result<Self, MintError> {
        let key = KeyPair::from_pem(pem).map_err(|err| MintError::new(err.to_string()))?;

        Ok(Self { key })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        self.key.serialize_pem()
    }

    #[must_use]
    pub fn signing_key(&self) -> &KeyPair {
        &self.key
    }
}

// So that a `LocalSigner` can stand where the threshold group stands: for
// `Authority` both are only an `rcgen::SigningKey`, and the difference between them
// is exactly the one ADR-0014 describes -- who holds the key.
impl rcgen::PublicKeyData for LocalSigner {
    fn der_bytes(&self) -> &[u8] {
        self.key.der_bytes()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.key.algorithm()
    }
}

impl rcgen::SigningKey for LocalSigner {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.key.sign(msg)
    }
}

#[derive(Debug)]
pub enum Signer {
    Local(Box<LocalSigner>),
    Group(std::sync::Arc<crate::threshold::ThresholdSigner>),
}

impl Signer {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Local(_) => "local",
            Self::Group(_) => "group",
        }
    }
}

impl rcgen::PublicKeyData for Signer {
    fn der_bytes(&self) -> &[u8] {
        match self {
            Self::Local(signer) => signer.der_bytes(),
            Self::Group(signer) => signer.der_bytes(),
        }
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            Self::Local(signer) => signer.algorithm(),
            Self::Group(signer) => signer.algorithm(),
        }
    }
}

impl rcgen::SigningKey for Signer {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        match self {
            Self::Local(signer) => signer.sign(msg),
            Self::Group(signer) => signer.sign(msg),
        }
    }
}

pub struct Authority<S: rcgen::SigningKey> {
    issuer: Issuer<'static, S>,
    ca: Ca,
    lifetime: Lifetime,
}

impl<S: rcgen::SigningKey> std::fmt::Debug for Authority<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authority").finish_non_exhaustive()
    }
}

impl<S: rcgen::SigningKey> Authority<S> {
    pub fn new(ca: Ca, signer: S, lifetime: Lifetime) -> Result<Self, MintError> {
        lifetime
            .validate()
            .map_err(|err| MintError::new(err.to_string()))?;

        // The issuer's parameters are read back from its certificate -- the same
        // way for a self-produced one and for one that came from outside. Two ways
        // would be two opportunities to differ.
        let issuer = Issuer::from_ca_cert_pem(&ca.pem, signer)
            .map_err(|err| MintError::new(format!("the CA certificate is not readable: {err}")))?;

        Ok(Self {
            issuer,
            ca,
            lifetime,
        })
    }

    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.ca.pem
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.ca.certificate_der()
    }

    #[must_use]
    pub fn signer(&self) -> &S {
        self.issuer.key()
    }

    #[must_use]
    pub fn lifetime(&self) -> Lifetime {
        self.lifetime
    }

    pub fn certify(
        &self,
        id: &SpiffeId,
        spki_der: &[u8],
        purpose: Purpose,
        lifetime: Lifetime,
        now: UnixSeconds,
    ) -> Result<Certified, MintError> {
        let public_key = rcgen::SubjectPublicKeyInfo::from_der(spki_der)
            .map_err(|err| MintError::new(format!("the public key is unreadable: {err}")))?;
        let validity = Validity::issued_at(now, lifetime);

        let mut params = CertificateParams::default();
        params.not_before = offset(validity.not_before())?;
        params.not_after = offset(validity.not_after())?;
        params.subject_alt_names =
            vec![SanType::URI(id.to_string().try_into().map_err(|_| {
                MintError::new("the SPIFFE ID does not fit into a URI SAN")
            })?)];
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "tardigrade");

        match purpose {
            Purpose::Leaf => {
                params.is_ca = rcgen::IsCa::ExplicitNoCa;
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyEncipherment,
                ];
                params.extended_key_usages = vec![
                    rcgen::ExtendedKeyUsagePurpose::ServerAuth,
                    rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                ];
            }
            Purpose::Intermediate => {
                // pathlen 0: it may issue leaves and no further CA. An agent that
                // could issue intermediates would be an agent that invents nodes
                // for itself.
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
                params.key_usages = vec![
                    KeyUsagePurpose::KeyCertSign,
                    KeyUsagePurpose::CrlSign,
                    KeyUsagePurpose::DigitalSignature,
                ];
            }
        }

        let certificate = params
            .signed_by(&public_key, &self.issuer)
            .map_err(|err| MintError::new(err.to_string()))?;

        Ok(Certified {
            id: id.clone(),
            certificate_pem: certificate.pem(),
            certificate_der: certificate.der().to_vec(),
            validity,
        })
    }

    pub fn issue(&self, id: &SpiffeId, now: UnixSeconds) -> Result<Svid, MintError> {
        let validity = Validity::issued_at(now, self.lifetime);

        let mut params = CertificateParams::default();
        params.not_before = offset(validity.not_before())?;
        params.not_after = offset(validity.not_after())?;

        // The identity stands in the SAN, not in the subject -- that is the SPIFFE
        // determination. A common name would be a second, competing statement here
        // about who that is.
        params.subject_alt_names =
            vec![SanType::URI(id.to_string().try_into().map_err(|_| {
                MintError::new("the SPIFFE ID does not fit into a URI SAN")
            })?)];
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "tardigrade");

        // An SVID is an end certificate: it may sign nothing further.
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|err| MintError::new(err.to_string()))?;

        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|err| MintError::new(err.to_string()))?;

        Ok(Svid {
            id: id.clone(),
            certificate_pem: certificate.pem(),
            certificate_der: certificate.der().to_vec(),
            private_key_pem: key.serialize_pem(),
            private_key_der: key.serialize_der(),
            validity,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Leaf,
    Intermediate,
}

#[derive(Debug, Clone)]
pub struct Certified {
    id: SpiffeId,
    certificate_pem: String,
    certificate_der: Vec<u8>,
    validity: Validity,
}

impl Certified {
    #[must_use]
    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    #[must_use]
    pub fn validity(&self) -> Validity {
        self.validity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ca {
    pem: String,
    der: Vec<u8>,
    not_after: crate::lifetime::UnixSeconds,
}

impl Ca {
    pub fn from_pem(pem: &str) -> Result<Self, MintError> {
        let der = pem::parse(pem)
            .map_err(|err| MintError::new(format!("the CA PEM is not readable: {err}")))?
            .into_contents();
        let not_after = expires_at(&der)?;

        Ok(Self {
            pem: pem.to_owned(),
            der,
            not_after,
        })
    }

    #[must_use]
    pub fn not_after(&self) -> crate::lifetime::UnixSeconds {
        self.not_after
    }

    #[must_use]
    pub fn certificate_pem(&self) -> String {
        self.pem.clone()
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.der
    }
}

pub fn self_signed_ca(
    domain: &crate::id::TrustDomain,
    signer: &impl rcgen::SigningKey,
    not_before: UnixSeconds,
    not_after: UnixSeconds,
) -> Result<Ca, MintError> {
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(1));
    params.not_before = offset(not_before)?;
    params.not_after = offset(not_after)?;
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("tardigrade CA {domain}"));

    let certificate = params
        .self_signed(signer)
        .map_err(|err| MintError::new(err.to_string()))?;

    let der = certificate.der().to_vec();
    // Read back instead of passed through -- the same way as in `Ca::from_pem`. Two
    // ways would be two opportunities to differ, and the loaded one is the one that
    // counts in operation.
    let not_after = expires_at(&der)?;

    Ok(Ca {
        pem: certificate.pem(),
        der,
        not_after,
    })
}

pub fn expires_at(der: &[u8]) -> Result<UnixSeconds, MintError> {
    let (_, certificate) = x509_parser::prelude::X509Certificate::from_der(der)
        .map_err(|err| MintError::new(format!("the certificate is not readable: {err}")))?;

    Ok(certificate.validity().not_after.timestamp())
}

fn offset(seconds: UnixSeconds) -> Result<time::OffsetDateTime, MintError> {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|err| MintError::new(format!("the point in time {seconds} is unusable: {err}")))
}
