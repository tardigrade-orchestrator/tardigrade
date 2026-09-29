//! The `rustls` side: our decision laid into the library's traits.
//!
//! The content of the decision stands in [`crate::verify`]. What stands here
//! is the adaptation -- and two things about it deserve a rationale.
//!
//! # The server name is ignored, and that is the point
//!
//! `ServerCertVerifier::verify_server_cert` gets the name the client dialled.
//! We do **not** check it. With SPIFFE the dialled name is an address; the
//! identity stands in the URI SAN, and the SVIDs carry no DNS SAN at all
//! (ADR-0006). A verifier that additionally checked the name here would either
//! always fail or would check something the attacker chooses.
//!
//! # Client certificates are mandatory
//!
//! [`ClientCertVerifier::client_auth_mandatory`] returns `true`. Without it a
//! connection without a client certificate would be a connection without an
//! identity -- and deny-by-default (ADR-0025) would have nothing to decide
//! about.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use rustls::sign::CertifiedKey;

use crate::identity::{Identity, SharedIdentity};
use crate::verify::{PeerVerifier, VerifyError};

#[derive(Debug)]
pub struct TlsError {
    detail: String,
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the TLS configuration is not buildable: {}", self.detail)
    }
}

impl std::error::Error for TlsError {}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn alert(err: &VerifyError) -> rustls::Error {
    // **The wire gets the category, the log gets the reason.**
    //
    // Here the information otherwise dies: `VerifyError` carries the reason
    // and both parties, `rustls::Error` carries none of it. Until here the
    // verifier only counted its refusals (`PROXY_DECISIONS`) -- and **which**
    // identity it was must not be a label per the cardinality rule
    // (`tg_telemetry::names`), which refers to the audit trail. A sidecar has
    // no way to that. So into the log, and here: `alert` is the only
    // translation and is called from both directions.
    //
    // Saying more to the counterpart would be something else and is not
    // decided -- returning a diagnosis would mean blurting out the policy to
    // it (ADR-0041 names the same question for the egress).
    tracing::warn!(reason = %err, "the peer is refused");

    match err {
        VerifyError::Denied { .. } => rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ),
        _ => rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),
    }
}

#[derive(Debug)]
struct ServerSide {
    inner: PeerVerifier,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for ServerSide {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .check(end_entity, intermediates, now)
            .map(|_| ServerCertVerified::assertion())
            .map_err(|err| alert(&err))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
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
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct ClientSide {
    inner: PeerVerifier,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for ClientSide {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No hint. The client knows which SVID it has -- it has exactly one
        // for this purpose (ADR-0036), and a selection aid would here be a
        // piece of information about our CA to everyone who connects.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.inner
            .check(end_entity, intermediates, now)
            .map(|_| ClientCertVerified::assertion())
            .map_err(|err| alert(&err))
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
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
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn server_config(
    identity: &SharedIdentity,
    verifier: PeerVerifier,
) -> Result<ServerConfig, TlsError> {
    let provider = provider();
    let client_verifier = Arc::new(ClientSide {
        inner: verifier,
        provider: Arc::clone(&provider),
    });
    let resolver = Rotating::new(identity, &provider)?;

    Ok(ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })?
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(Arc::new(resolver)))
}

pub fn client_config(
    identity: &SharedIdentity,
    verifier: PeerVerifier,
) -> Result<ClientConfig, TlsError> {
    let provider = provider();
    let server_verifier = Arc::new(ServerSide {
        inner: verifier,
        provider: Arc::clone(&provider),
    });
    let resolver = Rotating::new(identity, &provider)?;

    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })?
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_cert_resolver(Arc::new(resolver)))
}

#[derive(Debug)]
struct Rotating {
    identity: SharedIdentity,
    provider: Arc<rustls::crypto::CryptoProvider>,
    current: std::sync::Mutex<(Vec<CertificateDer<'static>>, Arc<CertifiedKey>)>,
}

impl Rotating {
    fn new(
        identity: &SharedIdentity,
        provider: &Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, TlsError> {
        let now = identity.current();
        let key = certified(&now, provider)?;

        Ok(Self {
            identity: identity.clone(),
            provider: Arc::clone(provider),
            current: std::sync::Mutex::new((now.chain().clone(), key)),
        })
    }

    fn resolve(&self) -> Arc<CertifiedKey> {
        let identity = self.identity.current();
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if current.0 != identity.chain() {
            match certified(&identity, &self.provider) {
                Ok(key) => *current = (identity.chain().clone(), key),
                Err(err) => {
                    tracing::error!(
                        detail = %err.detail,
                        "the new SVID is not usable -- the previous one applies on"
                    );
                }
            }
        }

        Arc::clone(&current.1)
    }
}

fn certified(
    identity: &Identity,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let key = provider
        .key_provider
        .load_private_key(identity.key())
        .map_err(|err| TlsError {
            detail: err.to_string(),
        })?;

    Ok(Arc::new(CertifiedKey::new(identity.chain().clone(), key)))
}

impl rustls::server::ResolvesServerCert for Rotating {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Rotating::resolve(self))
    }
}

impl rustls::client::ResolvesClientCert for Rotating {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Rotating::resolve(self))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::alert;
    use crate::policy::DenyReason;
    use crate::verify::VerifyError;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            let guard = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn logged(err: &VerifyError) -> String {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let _ = alert(err);
        });

        captured.text()
    }

    #[test]
    fn a_refusal_is_logged_with_its_reason() {
        let text = logged(&VerifyError::Denied {
            reason: DenyReason::NoEdge,
            from: "spiffe://cluster.local/workload/api".to_owned(),
            to: "spiffe://cluster.local/workload/ledger".to_owned(),
        });

        assert!(text.contains("workload/api"), "{text}");
        assert!(text.contains("workload/ledger"), "{text}");
        assert!(!text.is_empty(), "the refusal must stand in the log");
    }

    #[test]
    fn a_broken_chain_is_logged_too() {
        let text = logged(&VerifyError::Chain {
            detail: "expired".to_owned(),
        });

        assert!(text.contains("expired"), "{text}");
    }
}
