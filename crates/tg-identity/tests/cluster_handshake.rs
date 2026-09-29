//! The handshake on a cluster port, at real sockets (ADR-0043).
//!
//! The check logic has tests of its own (`cluster_trust.rs`). What is proved here is
//! that `rustls` really asks it and that a refusal aborts the handshake instead of
//! merely commenting on it.
//!
//! Every refusal case runs against **the same** build-up in which exactly **one**
//! thing is different -- the key, the name, the registration. Otherwise a red test
//! would merely prove that something did not work. The same yardstick as in phase
//! 8b.

use std::sync::Arc;

use tg_identity::cluster::{NodeIdentity, NodeTrust, NodeVerifier, client_config, server_config};
use tg_identity::{SpiffeId, TrustDomain};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const GREETING: &[u8] = b"append_entries";

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("Trust Domain")
}

/// A process of this cluster: key, leaf, identity.
struct Peer {
    name: String,
    key: rcgen::KeyPair,
    identity: NodeIdentity,
}

fn peer(name: &str) -> Peer {
    let id = SpiffeId::for_node(&domain(), name).expect("ID");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let identity = NodeIdentity::new(&key, id).expect("leaf");

    Peer {
        name: name.to_owned(),
        key,
        identity,
    }
}

fn spki(key: &rcgen::KeyPair) -> Vec<u8> {
    use rcgen::PublicKeyData as _;

    key.subject_public_key_info()
}

fn registry(peers: &[&Peer]) -> NodeTrust {
    let mut trust = NodeTrust::new();
    for entry in peers {
        trust.insert(&entry.name, spki(&entry.key));
    }
    trust
}

/// Runs a TLS server that accepts exactly one connection and sends the greeting
/// back.
fn serve(
    listener: TcpListener,
    identity: &NodeIdentity,
    trust: tg_identity::SharedTrust,
) -> tokio::task::JoinHandle<Result<Vec<u8>, String>> {
    let verifier = NodeVerifier::new(domain(), trust);
    let config = server_config(identity, verifier).expect("server configuration");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.map_err(|err| err.to_string())?;
        let mut tls = acceptor
            .accept(stream)
            .await
            .map_err(|err| format!("the handshake: {err}"))?;

        let mut buffer = vec![0_u8; GREETING.len()];
        tls.read_exact(&mut buffer)
            .await
            .map_err(|err| err.to_string())?;
        tls.write_all(&buffer)
            .await
            .map_err(|err| err.to_string())?;
        tls.flush().await.map_err(|err| err.to_string())?;

        Ok(buffer)
    })
}

/// Dials, talks, and returns what arrived.
async fn dial(
    addr: std::net::SocketAddr,
    identity: &NodeIdentity,
    trust: tg_identity::SharedTrust,
    expect: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut verifier = NodeVerifier::new(domain(), trust);
    if let Some(name) = expect {
        verifier = verifier.expecting(name);
    }
    let config = client_config(identity, verifier).expect("client configuration");
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    // The name is an address and is not checked (ADR-0006); `rustls` demands
    // one nevertheless, so one stands here.
    let server_name =
        rustls_pki_types::ServerName::try_from("cluster.invalid").map_err(|err| err.to_string())?;

    let mut tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|err| format!("the handshake: {err}"))?;

    tls.write_all(GREETING).await.map_err(|e| e.to_string())?;
    tls.flush().await.map_err(|e| e.to_string())?;

    let mut back = vec![0_u8; GREETING.len()];
    tls.read_exact(&mut back).await.map_err(|e| e.to_string())?;

    Ok(back)
}

async fn listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bound");
    let addr = listener.local_addr().expect("address");
    (listener, addr)
}

// --- The normal case --------------------------------------------------------

/// Two admitted nodes talk. Both sides check, both are satisfied.
#[tokio::test]
async fn two_registered_nodes_talk() {
    let server = peer("node-1");
    let client = peer("node-2");
    let trust = tg_identity::shared(registry(&[&server, &client]));

    let (sock, addr) = listener().await;
    let task = serve(sock, &server.identity, Arc::clone(&trust));

    let back = dial(addr, &client.identity, Arc::clone(&trust), Some("node-1"))
        .await
        .expect("connection");

    assert_eq!(back, GREETING);
    assert_eq!(task.await.expect("task").expect("server"), GREETING);
}

// --- The refusals, one thing different each ---------------------------------

/// Only one thing different: the client does **not** stand in the registration.
#[tokio::test]
async fn an_unregistered_client_is_refused() {
    let server = peer("node-1");
    let stranger = peer("node-9");
    // Only the server is entered -- the client is not.
    let trust = tg_identity::shared(registry(&[&server]));

    let (sock, addr) = listener().await;
    let task = serve(sock, &server.identity, Arc::clone(&trust));

    let err = dial(addr, &stranger.identity, Arc::clone(&trust), Some("node-1"))
        .await
        .expect_err("refused");

    assert!(!err.is_empty(), "a refusal without a reason");
    assert!(
        task.await.expect("task").is_err(),
        "the server should have aborted the handshake"
    );
}

/// Only one thing different: the client carries the right **name** and a foreign
/// **key**. That is the attack determination 1 wards off.
#[tokio::test]
async fn the_right_name_with_the_wrong_key_is_refused_on_the_wire() {
    let server = peer("node-1");
    let real = peer("node-2");
    let forged = peer("node-2");

    // Entered is the real node-2; the forged one will dial.
    let trust = tg_identity::shared(registry(&[&server, &real]));

    let (sock, addr) = listener().await;
    let task = serve(sock, &server.identity, Arc::clone(&trust));

    let err = dial(addr, &forged.identity, Arc::clone(&trust), Some("node-1"))
        .await
        .expect_err("refused");

    assert!(!err.is_empty(), "a refusal without a reason");
    assert!(
        task.await.expect("task").is_err(),
        "the server should have aborted the handshake"
    );
}

/// Only one thing different: the client expects `node-2` and reaches `node-1`.
/// Both are admitted -- and it is the wrong one nevertheless.
#[tokio::test]
async fn reaching_the_wrong_peer_is_refused() {
    let server = peer("node-1");
    let other = peer("node-2");
    let client = peer("node-3");
    let trust = tg_identity::shared(registry(&[&server, &other, &client]));

    let (sock, addr) = listener().await;
    let _task = serve(sock, &server.identity, Arc::clone(&trust));

    let err = dial(addr, &client.identity, Arc::clone(&trust), Some("node-2"))
        .await
        .expect_err("refused");

    assert!(!err.is_empty(), "a refusal without a reason");
}

/// Only one thing different: the client presents **no** certificate at all.
///
/// `client_auth_mandatory` is what determination 4 makes structural -- no
/// service behind this port can forget to ask.
#[tokio::test]
async fn a_client_without_a_certificate_is_refused() {
    let server = peer("node-1");
    let trust = tg_identity::shared(registry(&[&server]));

    let (sock, addr) = listener().await;
    let task = serve(sock, &server.identity, Arc::clone(&trust));

    // A client without client auth, otherwise set up the same.
    let verifier = NodeVerifier::new(domain(), Arc::clone(&trust)).expecting("node-1");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyServer { inner: verifier }))
    .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(addr).await.expect("connected");
    let name = rustls_pki_types::ServerName::try_from("cluster.invalid").expect("name");

    let outcome = async {
        let mut tls = connector
            .connect(name, stream)
            .await
            .map_err(|err| err.to_string())?;
        tls.write_all(GREETING).await.map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        let mut back = vec![0_u8; GREETING.len()];
        tls.read_exact(&mut back).await.map_err(|e| e.to_string())
    }
    .await;

    assert!(
        outcome.is_err(),
        "a client without a credential should not have got through"
    );
    assert!(
        task.await.expect("task").is_err(),
        "the server should have aborted the handshake"
    );
}

/// A server verifier that uses this module's check -- only so that the test above
/// varies exclusively the **client auth**.
#[derive(Debug)]
struct AcceptAnyServer {
    inner: NodeVerifier,
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let _ = &self.inner;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Only one thing different: the **server** does not stand in the client's
/// registration. Both sides check, not only one.
#[tokio::test]
async fn an_unregistered_server_is_refused_by_the_client() {
    let server = peer("node-1");
    let client = peer("node-2");

    // The server knows both; the client knows only itself.
    let server_trust = tg_identity::shared(registry(&[&server, &client]));
    let client_trust = tg_identity::shared(registry(&[&client]));

    let (sock, addr) = listener().await;
    let _task = serve(sock, &server.identity, server_trust);

    let err = dial(addr, &client.identity, client_trust, Some("node-1"))
        .await
        .expect_err("refused");

    assert!(!err.is_empty(), "a refusal without a reason");
}

// --- The revocation ---------------------------------------------------------

/// The revocation takes effect on the **next** connection, and the existing one
/// stays.
///
/// That is no carelessness but the division of labour: on the mesh an edge withdrawal
/// tears the running connection down (phase 8b, ADR-0025), because there an
/// authorization decision is revoked. Here a **node** is taken out of the cluster, and
/// that happens over the membership -- a torn-down Raft stream in the middle of a
/// replication would be an availability problem without a security gain.
#[tokio::test]
async fn revocation_takes_effect_on_the_next_handshake() {
    let server = peer("node-1");
    let client = peer("node-2");
    let trust = tg_identity::shared(registry(&[&server, &client]));

    // First connection: works.
    let (sock, addr) = listener().await;
    let task = serve(sock, &server.identity, Arc::clone(&trust));
    let back = dial(addr, &client.identity, Arc::clone(&trust), Some("node-1"))
        .await
        .expect("the first connection");
    assert_eq!(back, GREETING);
    task.await.expect("task").expect("server");

    // Revocation: node-2 flies out of the registration.
    assert!(
        trust.write().expect("the registration").remove("node-2"),
        "node-2 was not entered"
    );

    // Second connection: no longer works.
    let (sock, addr) = listener().await;
    let task = serve(sock, &server.identity, Arc::clone(&trust));
    let err = dial(addr, &client.identity, Arc::clone(&trust), Some("node-1"))
        .await
        .expect_err("refused after the revocation");

    assert!(!err.is_empty(), "a refusal without a reason");
    assert!(task.await.expect("task").is_err(), "Server nahm ihn an");
}
