//! The credential on the cluster transports (ADR-0043).
//!
//! # What is different here from ADR-0007
//!
//! The data plane checks a **chain up to an anchor** and after that the `may_talk`
//! edge (`tg_proxy::verify`). Here no chain is checked and no deadline: the
//! credential is the **key**, not the certificate.
//!
//! The reason is a circle ADR-0043 computes. The CA runs as a subsystem in `tgd` and
//! hangs on the leader; the leader hangs on the Raft port. If the Raft port demanded
//! a valid signature of this CA, then "certificates expired" would also mean "no
//! quorum" -- and thereby "no CA that issues new ones". A cluster that once stood
//! still long enough would never come up again.
//!
//! Therefore: the leaf carries the public key and the SPIFFE ID, and what is checked
//! is the key against a [`NodeTrust`] registration. Where that comes from is decided
//! by the port -- the local peer list before consensus, the trust list from the log
//! behind it (ADR-0043, determination 2). This module gets it **handed** and does not
//! fetch it: with that `tg-identity` does not hang on `tg-consensus`, and the check is
//! testable without `openraft` -- the same pattern as `tg_store::session::slice_for`
//! (ADR-0040).
//!
//! # The name in the SAN is an index, no proof
//!
//! It only says in which line of the registration to look. Whoever names a foreign
//! name fails at the key comparison; whoever names a foreign key fails at the
//! handshake, because the private half is missing.
//!
//! **That belongs read as it stands:** whoever one day checks the identifier here and
//! takes the key comparison for a formality abolishes the authentication without a
//! test turning red -- that is why the attack stands as a case of its own in
//! `tests/cluster_trust.rs`.
//!
//! # The deadline is expressly not checked
//!
//! An expired leaf gets through. That is no gap but the circle-freedom from above:
//! revocation happens by removal from the registration, not by waiting. For the data
//! plane the opposite still applies (ADR-0014) -- there the deadline is the
//! backstop.

use std::collections::BTreeMap;
use std::fmt;

use rustls_pki_types::CertificateDer;

use crate::id::{Role, SpiffeId, TrustDomain};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeTrust {
    keys: BTreeMap<String, Vec<u8>>,
}

impl NodeTrust {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, node: &str, spki_der: Vec<u8>) {
        self.keys.insert(node.to_owned(), spki_der);
    }

    #[must_use]
    pub fn with(mut self, node: &str, spki_der: Vec<u8>) -> Self {
        self.insert(node, spki_der);
        self
    }

    pub fn remove(&mut self, node: &str) -> bool {
        self.keys.remove(node).is_some()
    }

    pub fn from_base64<'a, I>(entries: I) -> Result<Self, TrustError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut trust = Self::new();
        for (node, encoded) in entries {
            if node.is_empty() {
                return Err(TrustError::EmptyName);
            }
            let spki = decode_base64(encoded).ok_or_else(|| TrustError::BadKey {
                node: node.to_owned(),
            })?;
            if spki.is_empty() {
                return Err(TrustError::BadKey {
                    node: node.to_owned(),
                });
            }
            trust.insert(node, spki);
        }

        Ok(trust)
    }

    #[must_use]
    pub fn get(&self, node: &str) -> Option<&[u8]> {
        self.keys.get(node).map(Vec::as_slice)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    EmptyName,
    BadKey {
        node: String,
    },
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => write!(f, "an entry without a node name"),
            Self::BadKey { node } => {
                write!(f, "the key of '{node}' is no usable base64")
            }
        }
    }
}

impl std::error::Error for TrustError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterVerifyError {
    NoCertificate,
    Unreadable {
        detail: String,
    },
    NoSpiffeId {
        detail: String,
    },
    Disagreement {
        ecosystem: String,
        strict: String,
    },
    WrongRole {
        expected: &'static str,
        id: String,
    },
    ForeignTrustDomain {
        expected: String,
        got: String,
    },
    Unexpected {
        expected: String,
        got: String,
    },
    Unregistered {
        node: String,
    },
    KeyMismatch {
        node: String,
    },
}

impl fmt::Display for ClusterVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCertificate => write!(f, "no certificate was presented"),
            Self::Unreadable { detail } => write!(f, "the certificate is unreadable: {detail}"),
            Self::NoSpiffeId { detail } => write!(f, "no SPIFFE ID in the URI SAN: {detail}"),
            Self::Disagreement { ecosystem, strict } => write!(
                f,
                "two parsers read different identities from the same SAN: \
                 '{ecosystem}' vs. '{strict}'"
            ),
            Self::WrongRole { expected, id } => {
                write!(f, "'{id}' does not carry the role '{expected}'")
            }
            Self::ForeignTrustDomain { expected, got } => {
                write!(
                    f,
                    "a foreign trust domain: expected '{expected}', was '{got}'"
                )
            }
            Self::Unexpected { expected, got } => {
                write!(f, "dialled was '{expected}', answered has '{got}'")
            }
            Self::Unregistered { node } => write!(f, "the node '{node}' is not admitted"),
            Self::KeyMismatch { node } => {
                write!(f, "the node '{node}' is admitted, but with a different key")
            }
        }
    }
}

impl std::error::Error for ClusterVerifyError {}

pub fn check(
    end_entity: &CertificateDer<'_>,
    role: Role,
    domain: &TrustDomain,
    trust: &NodeTrust,
    expected: Option<&str>,
) -> Result<SpiffeId, ClusterVerifyError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|err| {
        ClusterVerifyError::Unreadable {
            detail: err.to_string(),
        }
    })?;

    let id = read_identity(end_entity)?;

    let Some(name) = id.named(role) else {
        return Err(ClusterVerifyError::WrongRole {
            expected: role.as_str(),
            id: id.to_string(),
        });
    };
    if id.trust_domain() != domain {
        return Err(ClusterVerifyError::ForeignTrustDomain {
            expected: domain.as_str().to_owned(),
            got: id.trust_domain().as_str().to_owned(),
        });
    }
    if let Some(want) = expected
        && want != name
    {
        return Err(ClusterVerifyError::Unexpected {
            expected: want.to_owned(),
            got: name.to_owned(),
        });
    }

    let Some(registered) = trust.get(name) else {
        return Err(ClusterVerifyError::Unregistered {
            node: name.to_owned(),
        });
    };
    if parsed.public_key().raw != registered {
        return Err(ClusterVerifyError::KeyMismatch {
            node: name.to_owned(),
        });
    }

    Ok(id)
}

pub fn spiffe_id_of(end_entity: &CertificateDer<'_>) -> Result<SpiffeId, ClusterVerifyError> {
    read_identity(end_entity)
}

fn read_identity(end_entity: &CertificateDer<'_>) -> Result<SpiffeId, ClusterVerifyError> {
    let certificate = spiffe::Certificate::try_from(end_entity.as_ref()).map_err(|err| {
        ClusterVerifyError::Unreadable {
            detail: err.to_string(),
        }
    })?;
    let ecosystem = certificate
        .spiffe_id()
        .map_err(|err| ClusterVerifyError::NoSpiffeId {
            detail: err.to_string(),
        })?
        .to_string();

    let strict: SpiffeId =
        ecosystem
            .parse()
            .map_err(|err: crate::id::IdError| ClusterVerifyError::Disagreement {
                ecosystem: ecosystem.clone(),
                strict: err.to_string(),
            })?;

    // The round trip must leave the string unchanged -- otherwise there would be two
    // spellings of the same identity, and a registration that fits only one of
    // them.
    if strict.to_string() != ecosystem {
        return Err(ClusterVerifyError::Disagreement {
            ecosystem,
            strict: strict.to_string(),
        });
    }

    Ok(strict)
}

#[must_use]
pub fn node_name_from_hostname(raw: &str) -> Option<String> {
    let label = raw.split('.').next()?.trim().to_ascii_lowercase();
    let mut chars = label.chars();

    if !chars.next().is_some_and(|first| first.is_ascii_lowercase()) {
        return None;
    }
    if label.len() > 63 {
        return None;
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return None;
    }

    Some(label)
}

pub const LEAF_YEARS: i64 = 10;

pub fn node_leaf(key: &rcgen::KeyPair, id: &SpiffeId) -> Result<Vec<u8>, String> {
    Ok(leaf_params(id)?
        .self_signed(key)
        .map_err(|err| format!("the leaf cannot be issued: {err}"))?
        .der()
        .to_vec())
}

pub fn node_leaf_pem(key: &rcgen::KeyPair, id: &SpiffeId) -> Result<String, String> {
    Ok(leaf_params(id)?
        .self_signed(key)
        .map_err(|err| format!("the leaf cannot be issued: {err}"))?
        .pem())
}

pub fn operator_keys() -> Result<(String, String), String> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|err| format!("no key pair: {err}"))?;

    // **`spki_base64` and not `der_bytes`**, and the difference is the finding from
    // ADR-0097: `der_bytes` gives the **raw** key (32 bytes at Ed25519),
    // `subject_public_key_info` the whole SPKI DER (44). And the comparison is against
    // `x509_parser`'s `public_key().raw` -- that is, against the DER. With the wrong
    // half the entry registers without complaint and **no handshake is accepted**:
    // `UnknownCA`, and the error shows itself only at the first connection.
    //
    // The same function a node uses for its own SPKI (`control::spki_base64`, called
    // in `tg_agent::join`) -- a second one would be a second opportunity to disagree
    // about the half.
    let spki = crate::control::spki_base64(&key);

    Ok((key.serialize_pem(), spki))
}

fn leaf_params(id: &SpiffeId) -> Result<rcgen::CertificateParams, String> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyUsagePurpose, SanType,
    };

    let mut params = CertificateParams::default();
    // One day of lead against clock skew, after that LEAF_YEARS. The system clock
    // goes in here, and that is harmless: `check` does not look at the window, and the
    // leaf arises anew at every start from the same key -- a copied anchor stays valid
    // because it carries the same key.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now.saturating_sub(time::Duration::days(1));
    params.not_after = now.saturating_add(time::Duration::days(365 * LEAF_YEARS + 3));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    // Both: the same credential serves on the Raft port as a server **and** as a
    // client. Two leaves would be two opportunities to forget one.
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "tardigrade");
    params.subject_alt_names =
        vec![SanType::URI(id.to_string().try_into().map_err(|_| {
            "the SPIFFE ID does not fit into a URI SAN".to_owned()
        })?)];

    Ok(params)
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let raw = text.trim().as_bytes();
    if raw.is_empty() || !raw.len().is_multiple_of(4) {
        return None;
    }

    let mut out = Vec::with_capacity(raw.len() / 4 * 3);
    for block in raw.chunks(4) {
        let pad = block.iter().rev().take_while(|b| **b == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut bits = 0u32;
        for (i, byte) in block.iter().enumerate() {
            let six = if *byte == b'=' {
                if i < 4 - pad {
                    return None;
                }
                0
            } else {
                value(*byte)?
            };
            bits = (bits << 6) | u32::from(six);
        }
        let bytes = bits.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
        if pad > 0 {
            break;
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::decode_base64;
    use crate::control::base64;

    #[test]
    fn base64_round_trips() {
        for len in 0..64_usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 251).unwrap_or(0))
                .collect();
            let encoded = base64(&bytes);
            if bytes.is_empty() {
                assert!(decode_base64(&encoded).is_none(), "empty is no entry");
                continue;
            }
            assert_eq!(
                decode_base64(&encoded).as_deref(),
                Some(bytes.as_slice()),
                "the round trip at length {len}"
            );
        }
    }

    #[test]
    fn rubbish_is_refused() {
        for bad in ["", "A", "AA", "AAA", "!!!!", "ä", "AAAA=", "=AAA", "A=AA"] {
            assert!(
                decode_base64(bad).is_none(),
                "'{bad}' should have been refused"
            );
        }
    }
}

// --- The rustls seam --------------------------------------------------------

#[derive(Clone)]
pub struct NodeIdentity {
    id: SpiffeId,
    leaf: Vec<u8>,
    key_pem: String,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("id", &self.id)
            .field("leaf", &format_args!("{} bytes", self.leaf.len()))
            .finish_non_exhaustive()
    }
}

impl NodeIdentity {
    pub fn new(key: &rcgen::KeyPair, id: SpiffeId) -> Result<Self, String> {
        let leaf = node_leaf(key, &id)?;

        Ok(Self {
            id,
            leaf,
            key_pem: key.serialize_pem(),
        })
    }

    #[must_use]
    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    #[must_use]
    pub fn leaf(&self) -> &[u8] {
        &self.leaf
    }

    #[must_use]
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }
}

pub type SharedTrust = std::sync::Arc<std::sync::RwLock<NodeTrust>>;

#[must_use]
pub fn shared(trust: NodeTrust) -> SharedTrust {
    std::sync::Arc::new(std::sync::RwLock::new(trust))
}

#[derive(Debug, Clone)]
pub struct NodeVerifier {
    role: Role,
    domain: TrustDomain,
    trust: SharedTrust,
    expected: Option<String>,
}

impl NodeVerifier {
    #[must_use]
    pub fn new(domain: TrustDomain, trust: SharedTrust) -> Self {
        Self {
            role: Role::Node,
            domain,
            trust,
            expected: None,
        }
    }

    #[must_use]
    pub fn operators(domain: TrustDomain, trust: SharedTrust) -> Self {
        Self {
            role: Role::Operator,
            domain,
            trust,
            expected: None,
        }
    }

    #[must_use]
    pub fn expecting(mut self, node: &str) -> Self {
        self.expected = Some(node.to_owned());
        self
    }

    #[must_use]
    pub fn trust(&self) -> &SharedTrust {
        &self.trust
    }

    fn judge(&self, end_entity: &CertificateDer<'_>) -> Result<SpiffeId, ClusterVerifyError> {
        // A poisoned lock is no reason to let everybody through -- and none to take
        // the process down with it either. It is a refusal.
        let trust = self
            .trust
            .read()
            .map_err(|_| ClusterVerifyError::Unregistered {
                node: "<the registration is unreadable>".to_owned(),
            })?;

        check(
            end_entity,
            self.role,
            &self.domain,
            &trust,
            self.expected.as_deref(),
        )
    }
}

fn alert(err: &ClusterVerifyError) -> rustls::Error {
    use rustls::CertificateError;

    let kind = match err {
        ClusterVerifyError::NoCertificate => CertificateError::NotValidForName,
        ClusterVerifyError::Unreadable { .. }
        | ClusterVerifyError::NoSpiffeId { .. }
        | ClusterVerifyError::Disagreement { .. } => CertificateError::BadEncoding,
        ClusterVerifyError::Unregistered { .. } | ClusterVerifyError::KeyMismatch { .. } => {
            CertificateError::UnknownIssuer
        }
        ClusterVerifyError::WrongRole { .. }
        | ClusterVerifyError::ForeignTrustDomain { .. }
        | ClusterVerifyError::Unexpected { .. } => CertificateError::ApplicationVerificationFailure,
    };

    rustls::Error::InvalidCertificate(kind)
}

fn provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug)]
struct Side {
    inner: NodeVerifier,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for Side {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Neither `server_name` nor `now` goes in, and both are deliberate: the name
        // one dials is an address (ADR-0006), and per ADR-0043 the deadline does not
        // carry. A leaf without intermediates is the normal case here -- it is
        // self-issued.
        self.inner
            .judge(end_entity)
            .map(|_| rustls::client::danger::ServerCertVerified::assertion())
            .map_err(|err| alert(&err))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl rustls::server::danger::ClientCertVerifier for Side {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // No hint. There is no CA here whose name we could name -- and every node has
        // exactly one leaf for this purpose.
        &[]
    }

    fn client_auth_mandatory(&self) -> bool {
        // The port carries an address of its own for exactly that reason (ADR-0043,
        // determination 4): without a credential nobody gets through here, and no
        // service behind it can forget to ask.
        true
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.inner
            .judge(end_entity)
            .map(|_| rustls::server::danger::ClientCertVerified::assertion())
            .map_err(|err| alert(&err))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsError {
    detail: String,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the TLS configuration: {}", self.detail)
    }
}

impl std::error::Error for TlsError {}

fn key_of(identity: &NodeIdentity) -> Result<rustls_pki_types::PrivateKeyDer<'static>, TlsError> {
    let parsed = pem::parse(identity.key_pem()).map_err(|err| TlsError {
        detail: format!("the key is unreadable: {err}"),
    })?;

    Ok(rustls_pki_types::PrivateKeyDer::Pkcs8(
        rustls_pki_types::PrivatePkcs8KeyDer::from(parsed.into_contents()),
    ))
}

fn chain(identity: &NodeIdentity) -> Vec<CertificateDer<'static>> {
    vec![CertificateDer::from(identity.leaf().to_vec())]
}

pub fn server_config(
    identity: &NodeIdentity,
    verifier: NodeVerifier,
) -> Result<rustls::ServerConfig, TlsError> {
    let provider = provider();
    let side = std::sync::Arc::new(Side {
        inner: verifier,
        provider: std::sync::Arc::clone(&provider),
    });

    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })?
        .with_client_cert_verifier(side)
        .with_single_cert(chain(identity), key_of(identity)?)
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })
}

pub fn client_config(
    identity: &NodeIdentity,
    verifier: NodeVerifier,
) -> Result<rustls::ClientConfig, TlsError> {
    let provider = provider();
    let side = std::sync::Arc::new(Side {
        inner: verifier,
        provider: std::sync::Arc::clone(&provider),
    });

    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })?
        .dangerous()
        .with_custom_certificate_verifier(side)
        .with_client_auth_cert(chain(identity), key_of(identity)?)
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })
}

pub fn open_server_config(identity: &NodeIdentity) -> Result<rustls::ServerConfig, TlsError> {
    let provider = provider();

    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })?
        .with_no_client_auth()
        .with_single_cert(chain(identity), key_of(identity)?)
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })
}

pub fn verifying_client_config(verifier: NodeVerifier) -> Result<rustls::ClientConfig, TlsError> {
    let provider = provider();
    let side = std::sync::Arc::new(Side {
        inner: verifier,
        provider: std::sync::Arc::clone(&provider),
    });

    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })?
        .dangerous()
        .with_custom_certificate_verifier(side)
        .with_no_client_auth())
}

pub fn anchors_from_pem(text: &str, domain: &TrustDomain) -> Result<NodeTrust, String> {
    let blocks = pem::parse_many(text).map_err(|err| format!("no PEM: {err}"))?;
    if blocks.is_empty() {
        return Err("no PEM block".to_owned());
    }

    let mut trust = NodeTrust::new();
    for block in blocks {
        let der = block.into_contents();
        let (_, cert) = x509_parser::parse_x509_certificate(&der)
            .map_err(|err| format!("no certificate: {err}"))?;
        let id = spiffe_id_of(&CertificateDer::from(der.clone())).map_err(|err| err.to_string())?;

        if id.trust_domain() != domain {
            return Err(format!(
                "a foreign trust domain '{}'",
                id.trust_domain().as_str()
            ));
        }
        let name = id
            .node()
            .ok_or_else(|| format!("'{id}' is no node identity"))?;

        trust.insert(name, cert.public_key().raw.to_vec());
    }

    Ok(trust)
}

pub fn read_leaf(
    path: &std::path::Path,
    domain: &TrustDomain,
) -> Result<(String, Vec<u8>), String> {
    let text = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
    let parsed = pem::parse(&text).map_err(|err| format!("no PEM: {err}"))?;
    let der = parsed.into_contents();

    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|err| format!("no certificate: {err}"))?;
    let spki = cert.public_key().raw.to_vec();

    let id = spiffe_id_of(&rustls_pki_types::CertificateDer::from(der.clone()))
        .map_err(|err| err.to_string())?;

    // Check role and trust domain here already, not only at the handshake: a peer
    // leaf the verifier would refuse later is a finding at the read-in and not, in the
    // night, an inexplicable connection problem.
    if id.trust_domain() != domain {
        return Err(format!(
            "a foreign trust domain '{}'",
            id.trust_domain().as_str()
        ));
    }
    let name = id
        .node()
        .ok_or_else(|| format!("'{id}' is no node identity"))?;

    Ok((name.to_owned(), spki))
}
