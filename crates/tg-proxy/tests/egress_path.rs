//! Egress end to end, against foreign TLS (ADR-0041 -- phase 10d).
//!
//! The client is **`curl` with OpenSSL** -- code that read the TLS
//! specification independently. A test that asks with `rustls` and answers
//! with `rustls` would show self-consistency; the same yardstick as with `dig`
//! in 9c and `rust-spiffe` in 7c.
//!
//! That `curl` is built against OpenSSL does not violate invariant 3: it says
//! what is **linked**, not what a test invokes.
//!
//! # The decisive assertion
//!
//! `curl` checks the endpoint's certificate against **our CA**. Had the
//! sidecar terminated the connection, `curl` would see a different certificate
//! and would abort. That the call succeeds is therefore the substantiation
//! that it did **not** terminate (ADR-0041, determination 1) -- and thereby
//! that no interception key lies on the node.
//!
//! `#[ignore]`, because `curl` is needed; run with `cargo xtask storage`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tg_proxy::egress::{EgressPolicy, Resolver};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The name under which the endpoint is to be reachable.
const ENDPOINT: &str = "s3.test";

struct Server {
    address: SocketAddr,
    ca_pem: String,
}

/// Names the crypto provider expressly.
///
/// In the workspace run `cargo` unifies the features, and `rustls` gets
/// **both** providers -- `ring` over this crate, `aws-lc-rs` over `reqwest` in
/// the image puller. Then it chooses none and panics. The production path is
/// untouched by this: `tg_proxy::tls` names the provider anyway
/// (`builder_with_provider`), and `peek` never gets as far as needing a cipher
/// suite.
fn provider() {
    // Called several times, the second call is an error, no problem.
    let _ = rustls::crypto::ring::default_provider().install_default();
}
/// A real TLS server with a certificate of its own.
async fn tls_endpoint() -> Server {
    provider();
    // A CA of our own and a leaf for `s3.test` -- the same way as in
    // `tg-identity`, only without SPIFFE: the endpoint is expressly **no**
    // workload of this mesh (ADR-0027).
    let ca_key = rcgen::KeyPair::generate().expect("the CA key");
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "tardigrade-test-ca");
    let ca = ca_params.self_signed(&ca_key).expect("the CA");

    let leaf_key = rcgen::KeyPair::generate().expect("the leaf key");
    let leaf = rcgen::CertificateParams::new(vec![ENDPOINT.to_owned()])
        .expect("the parameter")
        .signed_by(
            &leaf_key,
            &rcgen::Issuer::from_ca_cert_der(ca.der(), ca_key).expect("the issuer"),
        )
        .expect("the leaf");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        )
        .expect("the server configuration");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("the address");

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut discard = [0_u8; 1024];
                    let _ = tls.read(&mut discard).await;
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfrom-store")
                        .await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });

    Server {
        address,
        ca_pem: ca.pem(),
    }
}

/// Starts the egress sidecar in front of an endpoint.
async fn sidecar(endpoint: SocketAddr, allowed: &[&str]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("the address");

    // **Two ports, and both belong in the allowlist** -- the reason sits in
    // ADR-0051.
    //
    // Since then the sidecar checks `name + port`, and the port comes from
    // `SO_ORIGINAL_DST`: what the container dialled. This test has no nftables
    // redirect; `curl` dials the egress port **directly**, so the original
    // destination address is precisely that port. Permitting it is no bypass
    // here but the truth of this topology.
    //
    // **In a real netns it would be a gap** (ADR-0051, determination 3): there
    // the traffic comes over the redirect, and a permitted egress port would
    // let everyone out who bypasses the redirect. The more faithful
    // reproduction therefore stands beside it: `tests/egress_netns.rs`, behind
    // `cargo xtask net`, with a real redirect and **without** the egress port
    // in the list.
    //
    // The endpoint port stays in the list beside it: **it** is what the
    // sidecar dials (ADR-0041, determination 2).
    let policy = tg_proxy::egress::SharedEgress::new(EgressPolicy::from_entries(
        allowed.iter().flat_map(|host| {
            [
                (
                    (*host).to_owned(),
                    endpoint.port(),
                    tg_proxy::egress::Transport::Tcp,
                ),
                (
                    (*host).to_owned(),
                    address.port(),
                    tg_proxy::egress::Transport::Tcp,
                ),
            ]
        }),
    ));
    let resolver = Resolver::Pinned(Arc::new(BTreeMap::from([(ENDPOINT.to_owned(), endpoint)])));

    tokio::spawn(async move {
        tg_proxy::egress::serve(
            listener,
            policy,
            resolver,
            tg_proxy::policy::RevocationWindow::adr_0014(),
            None,
            std::future::pending(),
        )
        .await;
    });

    address
}

fn curl(through: SocketAddr, ca_pem: &str) -> std::process::Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, ca_pem).expect("write the CA");

    std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            "--cacert",
            ca.to_str().expect("the path"),
            // curl connects to the sidecar but names the endpoint --
            // exactly like a container behind the redirect from 9b.
            "--resolve",
            &format!("{ENDPOINT}:{}:127.0.0.1", through.port()),
            &format!("https://{ENDPOINT}:{}/", through.port()),
        ])
        .output()
        .expect("curl must be startable")
}

/// **The path carries, and it does not terminate.**
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands curl; via `cargo xtask storage`"]
async fn an_allowed_endpoint_is_reached_without_terminating_the_tls() {
    let server = tls_endpoint().await;
    let through = sidecar(server.address, &[ENDPOINT]).await;

    let output = curl(through, &server.ca_pem);
    let body = String::from_utf8_lossy(&output.stdout);
    let complaint = String::from_utf8_lossy(&output.stderr);

    assert!(
        body.contains("from-store"),
        "the answer did not get through. curl said: '{}' / '{}'",
        body.trim(),
        complaint.trim()
    );
}

/// **The counter-check with one thing different:** the same setup, but the
/// name does not stand on the list. Deny-by-default means that nothing gets
/// through.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands curl; via `cargo xtask storage`"]
async fn an_unlisted_endpoint_gets_nothing() {
    let server = tls_endpoint().await;
    let through = sidecar(server.address, &["something.else"]).await;

    let output = curl(through, &server.ca_pem);

    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("from-store"),
        "a non-permitted endpoint was reached"
    );
}

/// What is no TLS has no name -- and without a name no permission (ADR-0041,
/// determination 5).
#[tokio::test(flavor = "multi_thread")]
async fn plain_http_never_leaves() {
    let server = tls_endpoint().await;
    let through = sidecar(server.address, &[ENDPOINT]).await;

    let mut stream = TcpStream::connect(through).await.expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: s3.test\r\n\r\n")
        .await
        .expect("send");

    let mut answer = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_to_end(&mut answer),
    )
    .await;

    assert!(
        answer.is_empty(),
        "plaintext HTTP got through: {:?}",
        String::from_utf8_lossy(&answer)
    );
}
