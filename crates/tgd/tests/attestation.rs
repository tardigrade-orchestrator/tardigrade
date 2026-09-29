//! The SPIFFE server against a real process (ADR-0006, ADR-0037).
//!
//! A `tgd` runs, an operator invites, a "node" joins and renews. All over real
//! gRPC, with real certificates and a real signature -- and the issued chain is
//! verified at the end by `webpki`, not claimed.
//!
//! The emphasis lies on the cases in which something must **not** happen.
//! ADR-0006 names the reason: "weak bootstrap = identity theft".

use std::path::Path;
use std::process::{Child, Command as OsCommand, Stdio};
use std::time::{Duration, Instant};

use rcgen::SigningKey as _;
use rustls_pki_types::{CertificateDer, UnixTime};
use tg_consensus::Command;
use tg_identity::control::{
    Credentials, IdentityClient, JoinRequest, RenewRequest, Underlay, spki_base64,
};
use tg_identity::{Authority, Ca, Lifetime, LocalSigner, SpiffeId, TrustDomain};
use tgd::admin::{AdminClient, WriteResult};

mod support;

const PATIENCE: Duration = Duration::from_secs(30);
const TOKEN: &str = "a-random-token-from-tgctl";

/// Two valid X25519 keys, base64 -- 32 bytes, as ADR-0039 demands.
///
/// By hand and not generated: the test rig is to be deterministic, and the state
/// machine checks the **length**, not the provenance. A generated pair would bring
/// `tg-net` into `tgd` as a test dependency without the test showing more for
/// it.
const X25519_A: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
const X25519_B: &str = "ZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4Q=";

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs(),
    )
    .expect("fits")
}

/// A single `tgd` with signing material.
struct Server {
    child: Child,
    admin: AdminClient,
    identity: IdentityClient,
    /// The address, for calls that need a client of their own.
    ///
    /// Since ADR-0043 the tests address the session port, not this one -- the
    /// field stays because the next extension needs it again.
    #[expect(dead_code, reason = "the clients above already hold the address")]
    endpoint: String,
    /// The address of the node session -- since ADR-0043 a port of its own.
    session: String,
    /// Where the metrics lie.
    telemetry: u16,
    /// The node's cluster leaf: the anchor an agent checks it against.
    leaf: Vec<u8>,
    anchor: Vec<u8>,
    /// Where `tgd` writes its log.
    ///
    /// It is **caught** and not discarded, because a report here is an assurance:
    /// ADR-0072 determination 4 demands that a version skew becomes visible on the
    /// server side. Without the file the only place at which that is measurable
    /// would not be measurable.
    log: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Files a signing CA as it would come in operation from the air-gapped root.
fn signing_material(dir: &Path) -> Vec<u8> {
    let signing = dir.join("signing");
    std::fs::create_dir_all(&signing).expect("directory");

    let domain = TrustDomain::new("cluster.local").expect("domain");
    let key = LocalSigner::generate().expect("key");
    let ca = tg_identity::self_signed_ca(&domain, &key, 0, 10 * 365 * 24 * 3_600).expect("CA");

    std::fs::write(signing.join("ca.pem"), ca.certificate_pem()).expect("CA");
    std::fs::write(signing.join("ca.key.pem"), key.to_pem()).expect("key");
    std::fs::write(signing.join("bundle.pem"), ca.certificate_pem()).expect("bundle");

    ca.certificate_der().to_vec()
}

impl Server {
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = signing_material(dir.path());
        let port = support::free_port();
        // Three ports, all freely chosen (ADR-0043, determination 4). The
        // defaults would be the same for every test binary, and `cargo test` runs
        // them concurrently -- the same finding as in phases 10a and 11b.
        let cluster_port = support::free_port();
        let session_port = support::free_port();
        // **With** telemetry, on a free port: a metric of this path can only be
        // seen at the endpoint. It was switched off because the default port
        // would be the same for every test binary -- a free one solves the same
        // problem and leaves the number measurable.
        let telemetry_port = support::free_port();

        let mut child = OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
            .args([
                "--telemetry-addr",
                &format!("127.0.0.1:{telemetry_port}"),
                "--id",
                "1",
                "--node",
                "tgd-1",
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--cluster-listen",
                &format!("127.0.0.1:{cluster_port}"),
                "--node-listen",
                &format!("127.0.0.1:{session_port}"),
                "--data-dir",
                dir.path().to_str().expect("path"),
                "--peer",
                &format!("1=http://127.0.0.1:{port}"),
                "--init",
            ])
            .stdout(support::log("tgd"))
            .stderr(Stdio::from(
                std::fs::File::create(dir.path().join("stderr.log")).expect("log file"),
            ))
            .spawn()
            .expect("tgd startable");

        let addr = format!("http://127.0.0.1:{port}");

        // `tgd` writes the cluster leaf at startup. It is the anchor for the
        // counter-direction (ADR-0043, determination 3) -- here the test stands in
        // for the operator who files it.
        let leaf_pem = support::await_leaf(dir.path());
        let leaf = pem::parse(&leaf_pem).expect("PEM").into_contents();

        // **What is waited for is the socket, not only the leaf.** Measured,
        // both arise far apart (`lib.rs:248` against `:970`), and `connect_unix`
        // is lazy: this setup thereby got a client on a socket that did not exist
        // yet, and fell at the first call with `Unavailable: No such file or
        // directory` -- of the nine `tgd` test rigs it was the only one without a
        // waiting place.
        let admin =
            support::await_admin(&tgd::admin::socket_path(dir.path(), 1), &mut [&mut child]);

        Self {
            child,
            telemetry: telemetry_port,
            // Admin has lain on a Unix socket since ADR-0044, identity on
            // `--listen` with server TLS (ADR-0043).
            admin,
            identity: IdentityClient::with_channel(support::open_channel(&addr, &leaf_pem)),
            endpoint: addr,
            session: format!("http://127.0.0.1:{session_port}"),
            leaf,
            anchor,
            log: dir.path().join("stderr.log"),
            _dir: dir,
        }
    }

    /// What `tgd` has reported so far.
    ///
    /// If the file is missing, that is no panic: the process may not have written
    /// anything yet, and the caller waits anyway.
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Waits until a line stands in the log -- or gives up.
    ///
    /// With a deadline, because the error case here is an **absence**; without it
    /// the test hangs instead of failing (the finding from 11b).
    async fn await_log(&self, needle: &str) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if self.log().contains(needle) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }

    async fn await_leadership(&self) {
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
            if let Ok(status) = self.admin.status().await
                && status.leader == Some(1)
            {
                return;
            }
            // A dead process is no condition: without this line the loop waits
            // out its whole 30 s and afterwards reports the wrong cause -- the node
            // had died on a port conflict.
            support::assert_alive(1, self.child.id());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the node did not take over the leadership");
    }

    /// The operator invites (ADR-0037, step 1).
    async fn invite(&self, node: &str, token: &str, ttl: i64) {
        let result = self
            .admin
            .write(Command::InviteNode {
                node: node.to_owned(),
                digest: tg_consensus::token_digest(token),
                expires_at: now() + ttl,
            })
            .await
            .expect("call");

        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "the invitation must get through: {result:?}"
        );
    }
}

/// A node that generates its key itself (ADR-0037, step 3).
struct Applicant {
    key: rcgen::KeyPair,
}

impl Applicant {
    fn new() -> Self {
        Self {
            key: rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key"),
        }
    }

    fn spki(&self) -> String {
        spki_base64(&self.key)
    }
}

/// A fully signed renewal request (ADR-0046).
///
/// **Request first, then signature** -- the order is the content of ADR-0046: what
/// does not yet stand in the request at the moment of signing cannot be signed
/// along, and exactly that way `intermediate_spki` stayed uncovered until then.
/// Whoever wants to check a forgery takes this request and changes **one** thing
/// about it; the signature then stays the real one over the real material.
fn signed_renew(
    node: &str,
    nonce: String,
    key: &rcgen::KeyPair,
    intermediate_spki: String,
    underlay: Option<Underlay>,
) -> RenewRequest {
    let mut request = RenewRequest {
        node: node.to_owned(),
        nonce,
        signature: String::new(),
        intermediate_spki,
        next_node_spki: None,
        underlay,
    };
    let signature = key
        .sign(&tg_identity::control::renew_message(&request))
        .expect("signature");
    request.signature = tg_identity::control::base64(&signature);

    request
}

/// Verifies an issued chain against the anchor.
fn verify(leaf_pem: &str, chain_pem: Option<&str>, anchor: &[u8]) {
    let leaf = pem::parse(leaf_pem).expect("PEM").into_contents();
    let anchor_der = CertificateDer::from(anchor.to_vec());
    let trust = webpki::anchor_from_trusted_cert(&anchor_der).expect("anchor");
    let leaf_der = CertificateDer::from(leaf);
    let cert = webpki::EndEntityCert::try_from(&leaf_der).expect("readable");

    let intermediates: Vec<CertificateDer<'_>> = chain_pem
        .map(|pem| {
            vec![CertificateDer::from(
                pem::parse(pem).expect("PEM").into_contents(),
            )]
        })
        .unwrap_or_default();

    cert.verify_for_usage(
        &[webpki::ring::ED25519],
        &[trust],
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(now() + 30).expect("after 1970"),
        )),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .expect("the issued chain must carry");
}

/// **The normal case:** invited, joined, the chain carries.
#[tokio::test]
async fn an_invited_node_joins_and_receives_a_usable_svid() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;

    let applicant = Applicant::new();
    let credentials = server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: applicant.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let Credentials::Issued {
        node_svid_pem,
        bundle_pem,
        intermediate_pem,
        ordinal,
        ..
    } = credentials
    else {
        panic!("the join was refused: {credentials:?}");
    };

    assert!(intermediate_pem.is_none(), "the join gives no intermediate");
    assert!(!bundle_pem.is_empty(), "the anchor travels along");
    // The ordinal travels along too (ADR-0039). It arises at admission, so the
    // first admitted node has 0 -- and without it it could not compute its
    // subnet.
    assert_eq!(
        ordinal,
        Some(0),
        "the first admitted node gets the ordinal 0"
    );
    verify(&node_svid_pem, None, &server.anchor);
}

/// **A wrong token does not carry** -- and the refusal does not give away whether
/// there ever was an invitation.
#[tokio::test]
async fn a_wrong_token_is_refused_without_saying_why() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;

    let applicant = Applicant::new();
    let credentials = server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: "guessed".to_owned(),
            spki: applicant.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let Credentials::Refused { reason } = credentials else {
        panic!("a wrong token was accepted: {credentials:?}");
    };
    assert_eq!(
        reason, "no open invitation",
        "the same wording as with no invitation at all -- whoever is not invited \
         does not learn whether they once were"
    );

    // And the node is not admitted: a second attempt with the right token still
    // works.
    let second = server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: applicant.spki(),
            underlay: None,
        })
        .await
        .expect("call");
    assert!(matches!(second, Credentials::Issued { .. }));
}

/// **The token is redeemed exactly once** -- over the real service too.
///
/// The second join, with a **different** key, is refused. Without that an
/// intercepted token could take over the node afterwards.
#[tokio::test]
async fn a_token_cannot_be_redeemed_twice() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;

    let first = Applicant::new();
    assert!(matches!(
        server
            .identity
            .join(JoinRequest {
                node: "node-7".to_owned(),
                token: TOKEN.to_owned(),
                spki: first.spki(),
                underlay: None,
            })
            .await
            .expect("call"),
        Credentials::Issued { .. }
    ));

    let attacker = Applicant::new();
    let second = server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: attacker.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    assert!(
        matches!(second, Credentials::Refused { .. }),
        "the token was redeemed a second time: {second:?}"
    );
}

/// **A node that was not invited does not get in.**
#[tokio::test]
async fn an_uninvited_node_is_refused() {
    let server = Server::start();
    server.await_leadership().await;

    let applicant = Applicant::new();
    let credentials = server
        .identity
        .join(JoinRequest {
            node: "stranger".to_owned(),
            token: TOKEN.to_owned(),
            spki: applicant.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    assert!(matches!(credentials, Credentials::Refused { .. }));
}

/// **The renewal runs over the key, not over a certificate** (ADR-0037,
/// determination 4) -- and delivers the agent intermediate.
#[tokio::test]
async fn renewal_proves_possession_of_the_registered_key() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;

    let node = Applicant::new();
    assert!(matches!(
        server
            .identity
            .join(JoinRequest {
                node: "node-7".to_owned(),
                token: TOKEN.to_owned(),
                spki: node.spki(),
                underlay: None,
            })
            .await
            .expect("call"),
        Credentials::Issued { .. }
    ));

    // The agent generates a **fresh** key for the intermediate: it is renewed
    // every three hours (ADR-0014), and that is cheap.
    let intermediate_key = Applicant::new();

    let nonce = server
        .identity
        .challenge("node-7")
        .await
        .expect("nonce")
        .nonce;
    let credentials = server
        .identity
        .renew(signed_renew(
            "node-7",
            nonce,
            &node.key,
            intermediate_key.spki(),
            None,
        ))
        .await
        .expect("call");

    let Credentials::Issued {
        node_svid_pem,
        intermediate_pem,
        ..
    } = credentials
    else {
        panic!("the renewal was refused: {credentials:?}");
    };

    verify(&node_svid_pem, None, &server.anchor);
    let intermediate = intermediate_pem.expect("the agent intermediate is missing");

    // And the agent mints a workload SVID from it whose chain carries up to the
    // control plane's anchor -- the whole path from ADR-0006.
    let domain = TrustDomain::new("cluster.local").expect("domain");
    let agent = Authority::new(
        Ca::from_pem(&intermediate).expect("CA"),
        LocalSigner::from_pem(&intermediate_key.key.serialize_pem()).expect("key"),
        Lifetime::default(),
    )
    .expect("issuer");
    let svid = agent
        .issue(&SpiffeId::for_workload(&domain, "api").expect("ID"), now())
        .expect("SVID");

    verify(svid.certificate_pem(), Some(&intermediate), &server.anchor);
}

/// **A wrong signature does not carry.**
#[tokio::test]
async fn a_signature_from_another_key_is_refused() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;

    let node = Applicant::new();
    server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let impostor = Applicant::new();
    let nonce = server
        .identity
        .challenge("node-7")
        .await
        .expect("nonce")
        .nonce;
    let credentials = server
        .identity
        .renew(signed_renew(
            "node-7",
            nonce,
            &impostor.key,
            impostor.spki(),
            None,
        ))
        .await
        .expect("call");

    assert!(
        matches!(credentials, Credentials::Refused { .. }),
        "a foreign signature was accepted: {credentials:?}"
    );
}

/// **A nonce cannot be reused.**
///
/// That is the reason the nonce exists at all: an intercepted `Renew` call must
/// not be replayable as long as the transport is not mTLS.
#[tokio::test]
async fn a_nonce_cannot_be_replayed() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;

    let node = Applicant::new();
    server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let nonce = server
        .identity
        .challenge("node-7")
        .await
        .expect("nonce")
        .nonce;
    let request = signed_renew("node-7", nonce, &node.key, Applicant::new().spki(), None);

    assert!(matches!(
        server.identity.renew(request.clone()).await.expect("call"),
        Credentials::Issued { .. }
    ));

    let replayed = server.identity.renew(request).await.expect("call");
    assert!(
        matches!(replayed, Credentials::Refused { .. }),
        "the same call got through a second time: {replayed:?}"
    );
}

/// Builds the mTLS channel to the node session (ADR-0043).
///
/// The credential is a self-issued leaf over the **same** key the join registered
/// -- no new material, no second identity. The anchor for the counter-direction is
/// `tgd`'s cluster leaf.
fn session_channel(server: &Server, node: &str, key: &rcgen::KeyPair) -> tonic::transport::Channel {
    session_channel_with(server, node, key, None)
}

/// As [`session_channel`], but with a **small** receive window.
///
/// For the backpressure witness (ADR-0068). The buffer sizes between `mpsc` and
/// wire do not belong to us; the window belongs to the **client**, and a small one
/// turns "at some point it backs up" into "after a few messages".
fn session_channel_small_window(
    server: &Server,
    node: &str,
    key: &rcgen::KeyPair,
) -> tonic::transport::Channel {
    session_channel_with(server, node, key, Some(1024))
}

fn session_channel_with(
    server: &Server,
    node: &str,
    key: &rcgen::KeyPair,
    window: Option<u32>,
) -> tonic::transport::Channel {
    use rustls_pki_types::CertificateDer;

    let domain = TrustDomain::new("cluster.local").expect("domain");
    let id = tg_identity::SpiffeId::for_node(&domain, node).expect("ID");
    let identity = tg_identity::NodeIdentity::new(key, id).expect("leaf");

    let leaf = CertificateDer::from(server.leaf.clone());
    let server_id = tg_identity::cluster::spiffe_id_of(&leaf).expect("tgd leaf readable");
    let (_, parsed) = x509_parser::parse_x509_certificate(&server.leaf).expect("readable");
    let mut trust = tg_identity::NodeTrust::new();
    trust.insert(
        server_id.node().expect("node role"),
        parsed.public_key().raw.to_vec(),
    );

    let verifier = tg_identity::NodeVerifier::new(domain, tg_identity::cluster::shared(trust));
    let config = tg_identity::cluster::client_config(&identity, verifier).expect("configuration");
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));

    let endpoint =
        tonic::transport::Endpoint::from_shared(server.session.clone()).expect("address");
    let endpoint = match window {
        Some(bytes) => endpoint
            .initial_stream_window_size(bytes)
            .initial_connection_window_size(bytes),
        None => endpoint,
    };
    endpoint.connect_with_connector_lazy(tower::service_fn(move |uri: http::Uri| {
        let connector = connector.clone();
        async move {
            let host = uri.host().unwrap_or("127.0.0.1").to_owned();
            let port = uri.port_u16().unwrap_or(80);
            let stream = tokio::net::TcpStream::connect((host, port)).await?;
            let name = rustls_pki_types::ServerName::try_from("cluster.invalid")
                .map_err(std::io::Error::other)?;
            let tls = connector.connect(name, stream).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
        }
    }))
}

/// The underlay peers the cluster tells this node about.
///
/// Over the **session** from ADR-0040 and not over a state handle: this test rig
/// runs a real `tgd` process, and the way on which an announcement really comes
/// back out is exactly this one. A test that instead looked into memory would
/// prove that something was stored -- not that it arrives.
async fn peers_seen_by(
    server: &Server,
    node: &str,
    key: &rcgen::KeyPair,
) -> Vec<tg_store::session::UnderlayPeer> {
    use futures_util::StreamExt as _;

    let client = tg_store::session::SessionClient::with_channel(session_channel(server, node, key));
    // **Without a name** (ADR-0043, determination 7): the server takes it from
    // the connection's credential.
    let hello = tokio_stream::iter(vec![tg_store::session::NodeMessage::Hello { applied: 0 }]);
    let mut stream = client.open(hello).await.expect("stream");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        match stream.next().await {
            Some(Ok(tg_store::session::ControlMessage::Slice(slice))) => {
                if !slice.peers.is_empty() {
                    return slice.peers;
                }
            }
            Some(Ok(_)) => {}
            _ => break,
        }
    }

    Vec::new()
}

// ================================================ The underlay announcement (0042)

/// **The announcement reaches the log -- over the path on which the node
/// identifies itself.**
///
/// That is the core of ADR-0042. `AnnounceUnderlay` is a log command, and the only
/// way on which a node may cause it is the one on which it produces a signature
/// with its registered key.
#[tokio::test]
async fn a_renewal_carries_the_underlay_announcement_into_the_log() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;
    let node = Applicant::new();

    server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let announcement = Underlay {
        key: X25519_A.to_owned(),
        endpoint: "10.0.0.7:51820".to_owned(),
    };
    let nonce = server
        .identity
        .challenge("node-7")
        .await
        .expect("nonce")
        .nonce;
    let credentials = server
        .identity
        .renew(signed_renew(
            "node-7",
            nonce,
            &node.key,
            Applicant::new().spki(),
            Some(announcement.clone()),
        ))
        .await
        .expect("call");

    assert!(
        matches!(credentials, Credentials::Issued { .. }),
        "{credentials:?}"
    );

    let peers = peers_seen_by(&server, "node-7", &node.key).await;
    let peer = peers
        .iter()
        .find(|peer| peer.node == "node-7")
        .expect("the announcement does not arrive in the slice");

    assert_eq!(peer.key, announcement.key);
    assert_eq!(peer.endpoint, announcement.endpoint);
}

/// **A client that closes its send direction gets its slice -- every time**
/// (ADR-0068).
///
/// The guard over the order in the session loop. `select!` rolls among ready arms;
/// if the slice is due **and** the inbound is at an end, without `biased` chance
/// decides whether the slice still goes out. Measured: in five runs in eight it was
/// lost.
///
/// **That is why the repetition is part of the assurance and no trimming.** A guard
/// that lets a regression through in four cases in ten looks like a flaky test --
/// and this project has paid for that misdiagnosis several times. Twelve sessions
/// on the same server: without the fixed order a probability of 2^-12 remains that
/// all twelve go well.
///
/// The neighbour `a_renewal_carries_…` checks the **announcement** (ADR-0042) and
/// did find the error, but only by chance -- it opens the session once.
#[tokio::test]
async fn a_client_that_stops_sending_still_receives_its_slice() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-9", TOKEN, 900).await;
    let node = Applicant::new();

    server
        .identity
        .join(JoinRequest {
            node: "node-9".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("join");

    // Without a first slice the repetition would say nothing: it would then only
    // confirm that nothing came twelve times.
    assert!(
        slice_seen_by(&server, "node-9", &node.key).await,
        "even the first slice does not arrive -- then the repetition below \
         checks nothing"
    );

    for round in 1..=12 {
        assert!(
            slice_seen_by(&server, "node-9", &node.key).await,
            "round {round}: the due slice was lost because the inbound was at \
             an end at the same time"
        );
    }
}

/// **A full outgoing queue does not stop the incoming side** (ADR-0068,
/// determination 2).
///
/// That ADR's open point read: *"The decoupling itself is guarded by no test …
/// Substantiated are the arrangement and the chain -- every link read back in the
/// code --, not a run."* Here is the run.
///
/// **The chain at issue**: full outgoing -> no `incoming.next()` -> no `absorb` ->
/// no `report_seen` -> the node drops out of `reporting_since` -> `leases()` skips
/// the renewal -> the lease expires -> a **healthy** single writer fences itself
/// (ADR-0064, ADR-0010). Triggered by the leader's backpressure, not by a
/// partition.
///
/// **The setup**: a client that **never reads** its slice. Then the way outwards
/// fills up -- `mpsc`, tonic's buffer, the HTTP/2 window --, and
/// `sender.reserve()` hangs. Exactly then a report is sent, and the assurance is
/// that it arrives nevertheless.
///
/// **How one sees it**: `report.applied` lands over `absorb` in the projection
/// (`applied_slice`). A number this test chooses, so not one that would stand there
/// by chance too.
///
/// **Why the many writes**: the server sends **one** slice per log movement
/// (afterwards `sent == index` holds, and the precondition switches the arm off).
/// The number of buffers in between does not belong to us -- therefore enough of
/// them instead of a computed amount. That it suffices is measured: with a
/// `send().await` outside the selection -- the state before ADR-0068 -- this test
/// runs into the time bound.
#[tokio::test]
async fn a_full_outgoing_queue_does_not_stop_the_incoming_side() {
    /// The number the report carries. Conspicuous, so that it cannot come by
    /// chance from another way too.
    const MARK: u64 = 987_654;

    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-8", TOKEN, 900).await;
    let node = Applicant::new();
    server
        .identity
        .join(JoinRequest {
            node: "node-8".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("join");

    // **The node must stand in the log**, otherwise the projection has no entry
    // in which `absorb` could file anything -- `AdmitNode` takes it into the trust
    // list, `UpsertNode` makes it a node of the cluster (ADR-0037, ADR-0034).
    server
        .admin
        .write(Command::UpsertNode {
            name: "node-8".to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r7".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        })
        .await
        .expect("call");

    let client = tg_store::session::SessionClient::with_channel(session_channel_small_window(
        &server, "node-8", &node.key,
    ));
    let (to_server, from_client) = tokio::sync::mpsc::channel(8);
    to_server
        .send(tg_store::session::NodeMessage::Hello { applied: 0 })
        .await
        .expect("Hello");

    // **The slice stream is held and never read.** That is the whole setup: a
    // client that does not take delivery.
    let stream = client
        .open(tokio_stream::wrappers::ReceiverStream::new(from_client))
        .await
        .expect("session");

    // Move the log until the way outwards is full.
    for round in 0..200_u32 {
        server
            .admin
            .write(Command::AllowTraffic {
                from: format!("a{round}"),
                to: format!("b{round}"),
            })
            .await
            .expect("call");
    }

    // And now a report -- while the outgoing side backs up.
    to_server
        .send(tg_store::session::NodeMessage::Report(Box::new(
            tg_store::session::NodeReport {
                applied: MARK,
                ..Default::default()
            },
        )))
        .await
        .expect("report");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut seen = None;
    while std::time::Instant::now() < deadline {
        let projection = server.admin.projection().await.expect("projection");
        seen = projection
            .nodes
            .iter()
            .find(|entry| entry.name == "node-8")
            .and_then(|entry| entry.applied_slice);
        if seen == Some(MARK) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert_eq!(
        seen,
        Some(MARK),
        "the report was not taken up while the outgoing side backed up -- then \
         the inbound hangs on the outbound (ADR-0068), and a healthy single \
         writer fences itself"
    );

    // The stream is dropped here, and expressly **after** the assertion: if it
    // falls earlier, the outgoing side is no longer full, and the test measures
    // something else.
    drop(stream);
}

/// Whether a slice arrives at all when the client stops sending after `Hello`.
///
/// `tokio_stream::iter` ends after the one message -- so the client half-closes, as
/// gRPC allows. Exactly that situation leaves both arms of the selection ready at
/// the same time.
async fn slice_seen_by(server: &Server, node: &str, key: &rcgen::KeyPair) -> bool {
    use futures_util::StreamExt as _;

    let client = tg_store::session::SessionClient::with_channel(session_channel(server, node, key));
    let hello = tokio_stream::iter(vec![tg_store::session::NodeMessage::Hello { applied: 0 }]);
    let Ok(mut stream) = client.open(hello).await else {
        return false;
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        match stream.next().await {
            Some(Ok(tg_store::session::ControlMessage::Slice(_))) => return true,
            Some(Ok(_)) => {}
            _ => return false,
        }
    }

    false
}

/// **Whoever swaps the endpoint is refused.**
///
/// The test ADR-0042 is about. Until then the signature covered only the nonce; an
/// interceptor would have replaced the endpoint, the signature would have stayed
/// valid, and the whole cluster traffic for this node would afterwards run over a
/// foreign address -- encrypted, but to the wrong party.
#[tokio::test]
async fn an_endpoint_swapped_after_signing_is_refused() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;
    let node = Applicant::new();
    server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let honest = Underlay {
        key: X25519_A.to_owned(),
        endpoint: "10.0.0.7:51820".to_owned(),
    };
    let nonce = server
        .identity
        .challenge("node-7")
        .await
        .expect("nonce")
        .nonce;
    // Exactly **one** thing is different: the endpoint. Everything else -- nonce,
    // key, signature -- is the real material.
    let mut request = signed_renew(
        "node-7",
        nonce,
        &node.key,
        Applicant::new().spki(),
        Some(honest.clone()),
    );
    request.underlay = Some(Underlay {
        endpoint: "192.0.2.66:51820".to_owned(),
        ..honest
    });

    let credentials = server.identity.renew(request).await.expect("call");

    assert!(
        matches!(credentials, Credentials::Refused { .. }),
        "the swapped endpoint got through: {credentials:?}"
    );
    assert!(
        peers_seen_by(&server, "node-7", &node.key).await.is_empty(),
        "a refused announcement must not reach the slice"
    );
}

/// **An announcement cannot be appended.**
///
/// The counter-check: the node signs *without* an announcement, an interceptor
/// appends one. If the absence did not count along into the signed bytes, that
/// would get through.
#[tokio::test]
async fn an_announcement_appended_after_signing_is_refused() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;
    let node = Applicant::new();
    server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let nonce = server
        .identity
        .challenge("node-7")
        .await
        .expect("nonce")
        .nonce;
    let mut request = signed_renew("node-7", nonce, &node.key, Applicant::new().spki(), None);
    request.underlay = Some(Underlay {
        key: X25519_A.to_owned(),
        endpoint: "192.0.2.66:51820".to_owned(),
    });

    let credentials = server.identity.renew(request).await.expect("call");

    assert!(
        matches!(credentials, Credentials::Refused { .. }),
        "the appended announcement got through: {credentials:?}"
    );
}

/// **The join carries it too** -- then it is there from the first moment instead
/// of waiting until the first renewal.
///
/// Without a signature of its own, and that is no oversight: the join is carried by
/// the token, and whoever can alter this request can just as well swap the `spki`
/// -- then they are the node.
#[tokio::test]
async fn a_join_can_carry_the_announcement_too() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;
    let node = Applicant::new();

    let announcement = Underlay {
        key: X25519_B.to_owned(),
        endpoint: "10.0.0.9:51820".to_owned(),
    };

    let credentials = server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: Some(announcement.clone()),
        })
        .await
        .expect("call");

    assert!(
        matches!(credentials, Credentials::Issued { .. }),
        "{credentials:?}"
    );
    let peers = peers_seen_by(&server, "node-7", &node.key).await;
    assert_eq!(
        peers
            .iter()
            .find(|peer| peer.node == "node-7")
            .expect("the announcement is missing")
            .endpoint,
        announcement.endpoint
    );
}

/// **A swapped intermediate key is refused** (ADR-0046).
///
/// The ADR's occasion, at a real node. Until then the signature covered only nonce
/// and announcement -- whoever intercepted this call and swapped
/// `intermediate_spki` would get a valid agent intermediate for **their** key and
/// with it the authority to mint workload SVIDs for this node (ADR-0006).
///
/// Exactly **one** thing is different: the intermediate key. Nonce, name, signature
/// and node key are the real material.
#[tokio::test]
async fn a_swapped_intermediate_key_is_refused() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;

    let node = Applicant::new();
    server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let nonce = server
        .identity
        .challenge("node-7")
        .await
        .expect("nonce")
        .nonce;
    let honest = Applicant::new();
    let mut request = signed_renew("node-7", nonce, &node.key, honest.spki(), None);
    request.intermediate_spki = Applicant::new().spki();

    let credentials = server.identity.renew(request).await.expect("call");

    assert!(
        matches!(credentials, Credentials::Refused { .. }),
        "the swapped intermediate key was accepted: {credentials:?}"
    );
}

/// **A node that still signs only the nonce is refused.**
///
/// The protocol break from ADR-0046, recorded -- so that nobody later takes it for
/// an oversight. It is the second after ADR-0042, and it demands the same
/// coordinated transition: a node of the old and a `tgd` of the new version talk
/// past each other.
#[tokio::test]
async fn signing_only_the_nonce_no_longer_works() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-7", TOKEN, 900).await;

    let node = Applicant::new();
    server
        .identity
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let nonce = server
        .identity
        .challenge("node-7")
        .await
        .expect("nonce")
        .nonce;

    // The old form: length-prefixed nonce and a zero byte for the missing
    // announcement -- exactly what ADR-0042 had determined.
    let mut old_form = Vec::new();
    old_form.extend_from_slice(&u64::try_from(nonce.len()).expect("length").to_be_bytes());
    old_form.extend_from_slice(nonce.as_bytes());
    old_form.extend_from_slice(&1_u64.to_be_bytes());
    old_form.push(0);

    let credentials = server
        .identity
        .renew(RenewRequest {
            node: "node-7".to_owned(),
            nonce,
            signature: tg_identity::control::base64(&node.key.sign(&old_form).expect("signature")),
            next_node_spki: None,
            intermediate_spki: Applicant::new().spki(),
            underlay: None,
        })
        .await
        .expect("call");

    assert!(
        matches!(credentials, Credentials::Refused { .. }),
        "the old signature form was accepted: {credentials:?}"
    );
}

// ======================================== The skew is diagnosable (0072)

/// An inbound message this `tgd` does not understand.
///
/// It has the shape of a future `NodeMessage::Hello` with one field more --
/// exactly what a newer agent sends against an older server.
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum FutureMessage {
    /// Like today's `Hello` -- the good case, so that the session starts.
    Hello { applied: u64 },
    /// Like today's `Hello` with one field more.
    HelloTooNew { applied: u64, something_new: u32 },
    /// Like today's `Report` with one field more.
    Report {
        applied: u64,
        states: Vec<()>,
        something_new: u32,
    },
}

impl FutureMessage {
    /// Builds the call by hand, because `SessionClient` sends only real
    /// [`tg_store::session::NodeMessage`] -- and exactly that is not wanted
    /// here.
    async fn send(
        server: &Server,
        node: &str,
        key: &rcgen::KeyPair,
        messages: Vec<Self>,
    ) -> Result<tonic::Response<tonic::Streaming<tg_store::session::ControlMessage>>, tonic::Status>
    {
        let mut client = tonic::client::Grpc::new(session_channel(server, node, key));
        client
            .ready()
            .await
            .map_err(|err| tonic::Status::unavailable(err.to_string()))?;
        client
            .streaming(
                tonic::Request::new(tokio_stream::iter(messages)),
                http::uri::PathAndQuery::from_static(tg_store::session::transport::SESSION),
                tg_store::session::transport::JsonCodec::<
                    Self,
                    tg_store::session::ControlMessage,
                >::default(),
            )
            .await
    }
}

/// **An unreadable inbound message is reported, with the node's name** (ADR-0072,
/// determination 4).
///
/// The strictness of the session messages is a decision: whoever does not
/// understand a decree fully does not execute it partially. The price is a format
/// break per extension -- and that is only bearable as long as an operator
/// **sees** it. Until here the server ended on `Some(Err(_)) | None => return` and
/// said nothing; a newer agent got a session that closed silently, and the other
/// side reported "session ended" without an addressee.
///
/// It is checked at the **process**, because that is where the property lies: the
/// report arises in the session loop of a real `tgd`, and a test against a helper
/// function would only show that a `tracing::warn!` prints something.
#[tokio::test]
async fn an_unreadable_session_input_is_reported_with_the_node() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-9", TOKEN, 900).await;
    let node = Applicant::new();

    server
        .identity
        .join(JoinRequest {
            node: "node-9".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    // The same path as every agent -- mTLS, the same key, the same route.
    // **One** thing is different: the message carries one field too many.
    let response = FutureMessage::send(
        &server,
        "node-9",
        &node.key,
        vec![FutureMessage::HelloTooNew {
            applied: 0,
            something_new: 1,
        }],
    )
    .await;

    // And the agent learns the **right** reason. Previously "the first message
    // must be a Hello" stood here -- it was one, the server merely could not read
    // it. An operator who sees only the agent's log would have looked at the wrong
    // end.
    let refusal = next_refusal(response).await;
    assert!(
        refusal.contains("unreadable"),
        "the reason does not name the skew: {refusal:?}"
    );

    assert!(
        server
            .await_log("the session's inbound is unreadable")
            .await,
        "the server did not report the skew:\n{}",
        server.log()
    );
    assert!(
        server.log().contains("node-9"),
        "the message does not name the node -- an operator then does not know \
         which agent does not fit:\n{}",
        server.log()
    );

    // The counter-check: a **readable** inbound message does not produce this
    // report. Without it the test would be green too if every session triggered
    // it.
    let clean = Server::start();
    clean.await_leadership().await;
    clean.invite("node-9", TOKEN, 900).await;
    let other = Applicant::new();
    clean
        .identity
        .join(JoinRequest {
            node: "node-9".to_owned(),
            token: TOKEN.to_owned(),
            spki: other.spki(),
            underlay: None,
        })
        .await
        .expect("call");
    let _ = peers_seen_by(&clean, "node-9", &other.key).await;
    assert!(
        !clean.log().contains("the session's inbound is unreadable"),
        "a proper session was reported as unreadable:\n{}",
        clean.log()
    );
}

/// Reads the reason for refusal from the answer, as far as one comes.
async fn next_refusal(
    response: Result<
        tonic::Response<tonic::Streaming<tg_store::session::ControlMessage>>,
        tonic::Status,
    >,
) -> String {
    use futures_util::StreamExt as _;

    let Ok(response) = response else {
        return String::new();
    };
    let mut stream = response.into_inner();
    match stream.next().await {
        Some(Ok(tg_store::session::ControlMessage::Refused { reason })) => reason,
        other => format!("{other:?}"),
    }
}

/// **An unreadable inbound message is reported in the middle of the stream too**
/// (ADR-0072, determination 4).
///
/// Two places read from this stream, and they are different: the first message is
/// read before the loop, every further one in it. The neighbour checks the first --
/// and left this one here unseen, for a session that does not start at all never
/// reaches the loop.
#[tokio::test]
async fn an_unreadable_report_inside_the_loop_is_reported() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-11", TOKEN, 900).await;
    let node = Applicant::new();

    server
        .identity
        .join(JoinRequest {
            node: "node-11".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    // A valid Hello -- the session starts --, afterwards a report with one field
    // too many.
    let _ = FutureMessage::send(
        &server,
        "node-11",
        &node.key,
        vec![
            FutureMessage::Hello { applied: 0 },
            FutureMessage::Report {
                applied: 0,
                states: Vec::new(),
                something_new: 1,
            },
        ],
    )
    .await;

    assert!(
        server
            .await_log("the session's inbound is unreadable")
            .await,
        "the server did not report the skew in the loop:\n{}",
        server.log()
    );
    assert!(
        server.log().contains("node-11"),
        "the message does not name the node:\n{}",
        server.log()
    );
}

// ============ The nonce map, bounded by the admission (ADR-0037)

/// **An unknown name gets no stored nonce.**
///
/// # The finding
///
/// The nonce map is keyed by **node name**, and the name comes from the request.
/// It was cleared only by time (30 s); within this window it grew with the number
/// of requests. And this port demands **no** client certificate (ADR-0043,
/// determination 3) -- whoever reached it could fill the control plane's memory
/// and, because the clearing runs over everything at every insert, consume
/// quadratic compute time.
///
/// The bolt is the same one `renew` has anyway: only a node with registered trust.
/// With that the **admission** bounds the map (five nodes, ADR-0031) instead of a
/// request rate.
///
/// # What is measured
///
/// The map cannot be seen from outside, and an access only for a test would be the
/// wrong way. What is therefore watched is the counter that is needed anyway: it
/// separates `stored` from `unknown`, and `unknown` is the number an alarm rule
/// belongs on -- a real node asks every three hours.
///
/// **Both directions**, because the second carries the first: without it a server
/// that keeps no nonce at all would be green too, and then no node could renew any
/// more.
#[tokio::test(flavor = "multi_thread")]
async fn a_name_the_cluster_does_not_know_gets_no_stored_nonce() {
    let server = Server::start();
    server.invite("node-7", TOKEN, 900).await;

    let node = Applicant::new();
    assert!(matches!(
        server
            .identity
            .join(JoinRequest {
                node: "node-7".to_owned(),
                token: TOKEN.to_owned(),
                spki: node.spki(),
                underlay: None,
            })
            .await
            .expect("call"),
        Credentials::Issued { .. }
    ));

    // Twenty **different** names, none of them admitted. Before the bolt those
    // would be twenty entries in the map.
    for i in 0..20 {
        let _ = server
            .identity
            .challenge(&format!("stranger-{i}"))
            .await
            .expect("nonce");
    }
    // And one the cluster knows.
    let nonce = server
        .identity
        .challenge("node-7")
        .await
        .expect("nonce")
        .nonce;

    let metrics = await_metric(&server, tg_telemetry::names::IDENTITY_CHALLENGES);
    let count = |outcome: &str| {
        metrics
            .lines()
            .find(|line| {
                line.starts_with(tg_telemetry::names::IDENTITY_CHALLENGES)
                    && line.contains(&format!("outcome=\"{outcome}\""))
            })
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or(-1.0)
    };

    assert!(
        (count("unknown") - 20.0).abs() < f64::EPSILON,
        "twenty foreign names must be counted as 'unknown': {metrics}"
    );
    assert!(
        count("stored") >= 1.0,
        "the admitted node must keep a nonce: {metrics}"
    );

    // **The second direction**: the admitted node's nonce really carries -- the
    // bolt must not take the renewal along.
    let intermediate_key = Applicant::new();
    assert!(matches!(
        server
            .identity
            .renew(signed_renew(
                "node-7",
                nonce,
                &node.key,
                intermediate_key.spki(),
                None,
            ))
            .await
            .expect("call"),
        Credentials::Issued { .. }
    ));
}

/// Waits until a metric stands at the endpoint and returns the document.
fn await_metric(server: &Server, needle: &str) -> String {
    let url = format!("http://127.0.0.1:{}/metrics", server.telemetry);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut body = String::new();
    while std::time::Instant::now() < deadline {
        let out = std::process::Command::new("curl")
            .args(["--silent", "--max-time", "2", &url])
            .output();
        if let Ok(out) = out {
            body = String::from_utf8_lossy(&out.stdout).into_owned();
            if body.contains(needle) {
                return body;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    body
}

/// **A rejection from the state machine comes as a sentence, not as Rust
/// syntax.**
///
/// The reason travels to the node and lands in its log ("refused: …"), that is,
/// where an operator looks up why a join does not work. `Rejection` has a `Display`
/// for that; `{rejection:?}` showed it `MalformedUnderlay { node: "…" }` -- the same
/// family as the Debug output `tgctl` filed.
///
/// **And it is the only place at which a `Rejection` reaches a remote caller:**
/// this port demands no client certificate (ADR-0043, determination 3). The
/// **length** is covered by `ClusterState::apply` (`MAX_DETAIL`), not by this
/// path.
#[tokio::test]
async fn a_rejection_from_the_state_machine_reads_as_a_sentence() {
    let server = Server::start();
    server.await_leadership().await;
    server.invite("node-9", TOKEN, 900).await;
    let node = Applicant::new();
    server
        .identity
        .join(JoinRequest {
            node: "node-9".to_owned(),
            token: TOKEN.to_owned(),
            spki: node.spki(),
            underlay: None,
        })
        .await
        .expect("call");

    let nonce = server
        .identity
        .challenge("node-9")
        .await
        .expect("nonce")
        .nonce;

    // Exactly **one** thing is different: the underlay key is none. Signature and
    // nonce are real, so the request gets through every check of this service --
    // and fails only in the **state machine** (`check_underlay`: an X25519 key has
    // 32 bytes base64).
    let request = signed_renew(
        "node-9",
        nonce,
        &node.key,
        Applicant::new().spki(),
        Some(Underlay {
            key: "no-key".to_owned(),
            endpoint: "10.0.0.9:51820".to_owned(),
        }),
    );

    let credentials = server.identity.renew(request).await.expect("call");
    let Credentials::Refused { reason } = credentials else {
        panic!("an unusable underlay key must be refused: {credentials:?}");
    };

    // **The sentence, not the struct.** A `{:?}` carries the variant name and
    // braces; a `Display` a sentence with the reason.
    assert!(
        !reason.contains('{') && !reason.contains("MalformedUnderlay"),
        "the reason is Rust syntax instead of a sentence: {reason}"
    );
    assert!(
        reason.contains("node-9"),
        "the reason must name the node: {reason}"
    );
}
