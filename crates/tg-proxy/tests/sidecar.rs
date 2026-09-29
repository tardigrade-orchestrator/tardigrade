//! The sidecar end to end (ADR-0007, ADR-0019, ADR-0025 -- phase 8b).
//!
//! Here stand the phase's acceptance criteria, over real sockets, real mTLS and
//! real certificates. The setup is the same every time:
//!
//! ```text
//!   Test ──plaintext──▶ api sidecar ──mTLS──▶ ledger sidecar ──plaintext──▶ Echo
//!                        (outbound)             (inbound)
//! ```
//!
//! The test writes in on the left and expects the same back on the right. If it
//! comes back, the whole route held -- handshake, verification, authorization,
//! passing through. If it does not, something of that fell, and the tests
//! distinguish which.

use std::net::SocketAddr;
use std::time::Duration;

use tg_identity::{Authority, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};
use tg_proxy::identity::Identity;
use tg_proxy::policy::{PolicyCache, RevocationWindow, Snapshot};
use tg_proxy::sidecar::{Config, Route};
use tg_proxy::verify::{Bundle, Enforcement, PeerVerifier, SharedBundle, SharedPolicy};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const YEAR: i64 = 365 * 24 * 60 * 60;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs(),
    )
    .expect("fits")
}

/// A short window, so that a test does not wait a minute.
///
/// The number from ADR-0014 (~60 s) is the operational setting; what is checked
/// is the **behaviour**, and that hangs on the ratio, not on the absolute
/// value.
fn window() -> RevocationWindow {
    RevocationWindow {
        target: Duration::from_secs(1),
        staleness: Duration::from_mins(15),
    }
}

/// A CA and the SVIDs it issues.
struct Pki {
    anchor: Vec<u8>,
    authority: Authority<LocalSigner>,
}

impl Pki {
    fn new() -> Self {
        let signer = LocalSigner::generate().expect("the key");
        let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("the CA");
        let anchor = ca.certificate_der().to_vec();
        let authority = Authority::new(ca, signer, Lifetime::default()).expect("the issuer");

        Self { anchor, authority }
    }

    fn identity(&self, workload: &str) -> tg_proxy::identity::SharedIdentity {
        let id = SpiffeId::for_workload(&domain(), workload).expect("the ID");
        let svid = self.authority.issue(&id, now()).expect("the SVID");

        tg_proxy::identity::SharedIdentity::new(
            Identity::new(
                &id.to_string(),
                vec![svid.certificate_der().to_vec()],
                svid.private_key_der().to_vec(),
            )
            .expect("the identity"),
        )
    }
}

fn policy(edges: &[(&str, &str)]) -> SharedPolicy {
    let mut cache = PolicyCache::new(window());
    cache
        .apply(
            &Snapshot::from_edges(
                1,
                edges
                    .iter()
                    .map(|(a, b)| ((*a).to_owned(), (*b).to_owned())),
            ),
            now(),
        )
        .expect("the snapshot");

    SharedPolicy::new(cache)
}

/// An echo service -- the "workload" behind the inbound sidecar.
async fn echo_server() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
    let addr = listener.local_addr().expect("the address");
    // **Counted**, so that the refusal can be told apart from the guard:
    // without the refusal the sidecar first builds the route and then tears it
    // down -- the upstream sees a connection. With it, it sees none. Without
    // this counter both cases would be "nothing arrived".
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&seen);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    (addr, seen)
}

/// The whole route, set up and running.
struct Mesh {
    outbound: SocketAddr,
    /// The inbound sidecar's mTLS port.
    ///
    /// Almost all the tests go over `outbound` -- the whole route. Whoever
    /// wants to check what the **server** demands must dial it directly.
    inbound: SocketAddr,
    server_policy: SharedPolicy,
    client_policy: SharedPolicy,
    /// The server's active-role state -- for withdrawing it in operation.
    server_roles: Option<tg_proxy::role::SharedRoles>,
    /// How many connections the upstream in the container has seen.
    upstream_connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    _shutdown: Vec<tokio::sync::oneshot::Sender<()>>,
}

/// Builds `api → ledger` with the given edges on both sides.
async fn mesh(server_edges: &[(&str, &str)], client_edges: &[(&str, &str)]) -> Mesh {
    mesh_with(&Pki::new(), server_edges, client_edges, None, Roles::none()).await
}

/// Like [`mesh`], but the client may come from a foreign PKI.
/// The active roles of both sidecars (ADR-0066).
///
/// `none()` means: neither of the two is a single writer, so nothing reins
/// anything in -- the state of all the tests that know nothing of the active
/// role.
struct Roles {
    server: Option<tg_proxy::role::Gate>,
    client: Option<tg_proxy::role::Gate>,
}

impl Roles {
    fn none() -> Self {
        Self {
            server: None,
            client: None,
        }
    }

    /// A single writer on the server side, with this file as its state.
    fn server(text: &str) -> Self {
        Self {
            server: Some(tg_proxy::role::Gate::new(
                "ledger".to_owned(),
                tg_proxy::role::SharedRoles::new(tg_proxy::role::Roles::from_text(text)),
            )),
            client: None,
        }
    }

    /// A single writer on the client side.
    fn client(text: &str) -> Self {
        Self {
            server: None,
            client: Some(tg_proxy::role::Gate::new(
                "api".to_owned(),
                tg_proxy::role::SharedRoles::new(tg_proxy::role::Roles::from_text(text)),
            )),
        }
    }
}

async fn mesh_with(
    pki: &Pki,
    server_edges: &[(&str, &str)],
    client_edges: &[(&str, &str)],
    client_pki: Option<&Pki>,
    roles: Roles,
) -> Mesh {
    let (upstream, upstream_connections) = echo_server().await;
    let mut shutdown = Vec::new();

    // `ledger`'s inbound sidecar -- on the **same port number** as its
    // workload, only on a different address.
    //
    // **That is what operation looks like** (ADR-0059/0141): the workload
    // listens on loopback in the container, the sidecar on the instance's
    // address, and `<mesh port>` is **one** number for both -- a caller dials
    // it, the sidecar passes on to it. Previously this witness bound two
    // different ports on loopback; that does not exist in operation, and since
    // ADR-0141 the sidecar refuses it.
    let server_policy = policy(server_edges);
    let inbound_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 2], upstream.port())))
        .await
        .expect("the socket");
    let inbound_addr = inbound_listener.local_addr().expect("the address");
    let server_roles = roles.server.as_ref().map(|gate| gate.roles().clone());
    let server_config = Config {
        identity: pki.identity("ledger"),
        bundle: SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()])),
        policy: server_policy.clone(),
        window: window(),
        role: roles.server,
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    shutdown.push(tx);
    tokio::spawn(async move {
        let _ = tg_proxy::serve_inbound(server_config, inbound_listener, upstream.port(), async {
            let _ = rx.await;
        })
        .await;
    });

    // `api`'s outbound sidecar.
    let client_pki = client_pki.unwrap_or(pki);
    let client_policy = policy(client_edges);
    let outbound_listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
    let outbound_addr = outbound_listener.local_addr().expect("the address");
    let client_config = Config {
        identity: client_pki.identity("api"),
        // The client trusts **our** anchor, even when its own SVID comes from
        // elsewhere -- otherwise the test would fail for the wrong reason.
        bundle: SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()])),
        policy: client_policy.clone(),
        window: window(),
        role: roles.client,
    };
    let route = Route {
        listen: outbound_addr,
        connect: inbound_addr,
        peer: SpiffeId::for_workload(&domain(), "ledger").expect("the ID"),
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    shutdown.push(tx);
    tokio::spawn(async move {
        let _ = tg_proxy::serve_outbound(client_config, route, outbound_listener, async {
            let _ = rx.await;
        })
        .await;
    });

    // Both sidecars need a moment before they listen.
    tokio::time::sleep(Duration::from_millis(50)).await;

    Mesh {
        outbound: outbound_addr,
        inbound: inbound_addr,
        server_policy,
        client_policy,
        server_roles,
        upstream_connections,
        _shutdown: shutdown,
    }
}

/// Writes something in and waits for the echo.
async fn round_trip(addr: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|err| format!("connection: {err}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| format!("write: {err}"))?;

    let mut buffer = vec![0_u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buffer))
        .await
        .map_err(|_| "no echo within 5 s".to_owned())?
        .map_err(|err| format!("read: {err}"))?;

    Ok(buffer)
}

/// **Two workloads talk when a `may_talk` edge exists.**
#[tokio::test]
async fn two_workloads_talk_when_the_edge_exists() {
    let mesh = mesh(&[("api", "ledger")], &[("api", "ledger")]).await;

    let echo = round_trip(mesh.outbound, b"hello ledger")
        .await
        .expect("the route must hold");

    assert_eq!(echo, b"hello ledger");
}

/// **Deny-by-default: no edge, no traffic.**
///
/// Both sides have an empty policy. The handshake fails, and with that no byte
/// gets through.
#[tokio::test]
async fn without_an_edge_nothing_gets_through() {
    let mesh = mesh(&[], &[]).await;

    let result = round_trip(mesh.outbound, b"hello ledger").await;

    assert!(
        result.is_err(),
        "without an edge nothing may get through, it came: {result:?}"
    );
}

/// **The server is authoritative** (ADR-0025).
///
/// The client believes the edge exists -- the server does not. Nothing gets
/// through. That is exactly the case "a malicious client does not clear
/// itself": here the client is even honest and merely misinformed, and the
/// decision falls at the server nevertheless.
#[tokio::test]
async fn the_server_decides_even_when_the_client_thinks_otherwise() {
    let mesh = mesh(&[], &[("api", "ledger")]).await;

    assert!(
        round_trip(mesh.outbound, b"hello").await.is_err(),
        "the server has no edge -- then nothing goes"
    );
}

/// And the other way round: a client that knows it may not does not even try.
/// Defence in depth (ADR-0025).
#[tokio::test]
async fn the_client_also_refuses_on_its_own_side() {
    let mesh = mesh(&[("api", "ledger")], &[]).await;

    assert!(
        round_trip(mesh.outbound, b"hello").await.is_err(),
        "the client is to apply its own policy as well"
    );
}

/// **An SVID from a foreign CA is refused** -- end to end, not only in the
/// verifier.
#[tokio::test]
async fn a_peer_from_a_foreign_ca_is_refused_end_to_end() {
    let ours = Pki::new();
    let theirs = Pki::new();
    let mesh = mesh_with(
        &ours,
        &[("api", "ledger")],
        &[("api", "ledger")],
        Some(&theirs),
        Roles::none(),
    )
    .await;

    assert!(
        round_trip(mesh.outbound, b"hello").await.is_err(),
        "a certificate from a foreign CA must not open the route"
    );
}

/// **Removing the edge ends the existing connection** -- the phase's third
/// acceptance criterion.
///
/// The connection stands and carries traffic. Then the edge is withdrawn, on
/// the authoritative side. The connection's guard wakes up through the version
/// change, checks anew and closes.
#[tokio::test]
async fn revoking_the_edge_tears_down_a_live_connection() {
    let mesh = mesh(&[("api", "ledger")], &[("api", "ledger")]).await;

    let mut stream = TcpStream::connect(mesh.outbound)
        .await
        .expect("the connection");
    stream.write_all(b"hello first").await.expect("write");
    let mut buffer = [0_u8; 11];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buffer))
        .await
        .expect("the echo")
        .expect("the echo");
    assert_eq!(&buffer, b"hello first");

    // Now the withdrawal, on the side that decides.
    mesh.server_policy
        .apply(&Snapshot::from_edges(2, []), now())
        .expect("the withdrawal");

    // The connection must end. A read on it then yields 0 bytes (EOF) or an
    // error -- both mean: it is gone.
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        let mut sink = [0_u8; 64];
        loop {
            // Keep writing, so that a mere read timeout does not pass as a
            // teardown: as long as the route stands, the echo comes back.
            if stream.write_all(b"still there?").await.is_err() {
                return true;
            }
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => return true,
                Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await;

    assert_eq!(
        ended,
        Ok(true),
        "the connection carried on after the edge withdrawal"
    );
}

/// **"Control plane gone": existing permitted traffic does not break.**
///
/// The fourth acceptance criterion. **No** new state arrives -- neither a
/// permitting nor a forbidding one. The connection must stay standing
/// nevertheless, and over several windows: fail-static means that a stale
/// policy carries on applying, not that it strikes at some point
/// (ADR-0019/0025).
#[tokio::test]
async fn established_traffic_survives_a_silent_control_plane() {
    let mesh = mesh(&[("api", "ledger")], &[("api", "ledger")]).await;

    let mut stream = TcpStream::connect(mesh.outbound)
        .await
        .expect("the connection");

    // For five windows (5 x 1 s) not a word from the control plane.
    for round in 0..5 {
        stream.write_all(b"still there?").await.expect("write");
        let mut buffer = [0_u8; 12];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("round {round}: the connection fell"))
            .unwrap_or_else(|err| panic!("round {round}: {err}"));
        assert_eq!(&buffer, b"still there?");

        tokio::time::sleep(Duration::from_millis(1_100)).await;
    }

    // And the policy is as stale as before.
    assert_eq!(
        mesh.client_policy
            .handle()
            .read()
            .expect("the cache")
            .version(),
        1
    );
}

/// **New** connections also keep arising, as long as the cache permits them.
///
/// A control plane that is silent is a change freeze and not an outage
/// (ADR-0019).
#[tokio::test]
async fn new_connections_still_open_from_a_stale_cache() {
    let mesh = mesh(&[("api", "ledger")], &[("api", "ledger")]).await;

    for round in 0..3 {
        let echo = round_trip(mesh.outbound, b"still")
            .await
            .unwrap_or_else(|err| panic!("round {round}: {err}"));
        assert_eq!(echo, b"still");
        tokio::time::sleep(Duration::from_millis(1_100)).await;
    }
}

// ----------------------------------------------------------- thread-per-core

/// **The sharding from ADR-0022 carries the route.**
///
/// Four inbound sidecars on the **same** address, each with its own
/// `SO_REUSEPORT` socket. The kernel distributes; every connection lands on one
/// shard and is served there completely. Twenty rounds, so that not only the
/// shard the kernel happens to take first is checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn several_shards_on_one_address_serve_the_same_route() {
    let pki = Pki::new();
    let (upstream, _) = echo_server().await;
    let server_policy = policy(&[("api", "ledger")]);

    // The first listener fixes the address, the rest share it.
    //
    // **On the workload's port number**, a different address -- as in `mesh()`
    // and for the same reason (ADR-0141): a caller dials `<mesh port>`, and the
    // sidecar refuses whoever wanted something else.
    let first = tg_proxy::reuseport_listener(SocketAddr::from(([127, 0, 0, 2], upstream.port())))
        .expect("the socket");
    let inbound_addr = first.local_addr().expect("the address");

    let mut shutdown: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();
    for shard in 0..4 {
        let listener = if shard == 0 {
            first.try_clone().expect("the socket")
        } else {
            tg_proxy::reuseport_listener(inbound_addr).expect("the socket")
        };
        let listener = TcpListener::from_std(listener).expect("the tokio socket");

        let config = Config {
            identity: pki.identity("ledger"),
            bundle: SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()])),
            policy: server_policy.clone(),
            window: window(),
            role: None,
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        shutdown.push(tx);
        tokio::spawn(async move {
            let _ = tg_proxy::serve_inbound(config, listener, upstream.port(), async {
                let _ = rx.await;
            })
            .await;
        });
    }
    drop(first);

    // An outbound sidecar in front of it.
    let client_policy = policy(&[("api", "ledger")]);
    let outbound_listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
    let outbound_addr = outbound_listener.local_addr().expect("the address");
    let config = Config {
        identity: pki.identity("api"),
        bundle: SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()])),
        policy: client_policy,
        window: window(),
        role: None,
    };
    let route = Route {
        listen: outbound_addr,
        connect: inbound_addr,
        peer: SpiffeId::for_workload(&domain(), "ledger").expect("the ID"),
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    shutdown.push(tx);
    tokio::spawn(async move {
        let _ = tg_proxy::serve_outbound(config, route, outbound_listener, async {
            let _ = rx.await;
        })
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    for round in 0..20 {
        let echo = round_trip(outbound_addr, b"over any shard")
            .await
            .unwrap_or_else(|err| panic!("round {round}: {err}"));
        assert_eq!(echo, b"over any shard");
    }
}

/// A shard set runs and ends -- and in doing so calls the seam behind which
/// per ADR-0022 the pinning once steps.
#[test]
fn the_shard_set_starts_every_shard_and_offers_the_pinning_seam() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let started = Arc::new(AtomicUsize::new(0));
    let ran = Arc::new(AtomicUsize::new(0));

    let seen = Arc::clone(&started);
    let counter = Arc::clone(&ran);
    tg_proxy::Shards::exactly(3)
        .on_start(move |_shard| {
            seen.fetch_add(1, Ordering::SeqCst);
        })
        .run(move |_shard| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        })
        .expect("the shards");

    assert_eq!(started.load(Ordering::SeqCst), 3);
    assert_eq!(ran.load(Ordering::SeqCst), 3);
    assert!(tg_proxy::available_shards() >= 1);
}

/// **Pinning happens over the cores the cgroup grants** (ADR-0114,
/// determination 3).
///
/// The test looks in the **kernel**, not in its own state: after the run every
/// shard thread has exactly one permitted core, and that lies in the set the
/// process may use at all. A test that instead checked that the hook was called
/// would prove that a function ran -- not that it took effect.
///
/// The counter-check stands beside it and is the more important half: **without
/// the setting nothing is pinned.** That is the default (ADR-0114), and a
/// version that always pinned would be green without it.
#[test]
fn pinned_shards_end_up_on_exactly_one_allowed_core() {
    use std::sync::Arc;
    use std::sync::Mutex;

    /// The cores this thread may use -- as a list.
    fn mine() -> Vec<usize> {
        let set = rustix::thread::sched_getaffinity(None).expect("the affinity");
        (0..rustix::thread::CpuSet::MAX_CPU)
            .filter(|cpu| set.is_set(*cpu))
            .collect()
    }

    let allowed = tg_proxy::allowed_cores();
    // On a machine with exactly one permitted core the test says nothing:
    // pinned and unpinned would be the same set. That is no reason to colour it
    // green -- it is a reason to say so.
    if allowed.len() < 2 {
        eprintln!(
            "only {} permitted core -- the comparison does not carry here",
            allowed.len()
        );
        return;
    }

    let pinned: Arc<Mutex<Vec<Vec<usize>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&pinned);
    tg_proxy::Shards::exactly(2)
        .pinned(true)
        .run(move |_shard| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock().expect("the lock").push(mine());
            }
        })
        .expect("the shards");

    let masks = pinned.lock().expect("the lock").clone();
    assert_eq!(masks.len(), 2);
    for mask in &masks {
        assert_eq!(
            mask.len(),
            1,
            "a pinned shard has exactly one core: {mask:?}"
        );
        assert!(
            allowed.contains(&mask[0]),
            "core {} does not stand in the permitted set {allowed:?}",
            mask[0]
        );
    }

    // And the counter-check: without the setting the process's mask stays.
    let loose: Arc<Mutex<Vec<Vec<usize>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&loose);
    tg_proxy::Shards::exactly(2)
        .pinned(false)
        .run(move |_shard| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock().expect("the lock").push(mine());
            }
        })
        .expect("the shards");

    for mask in loose.lock().expect("the lock").iter() {
        assert_eq!(
            *mask, allowed,
            "without the setting nothing is pinned (ADR-0114 D3)"
        );
    }
}

/// **The handshake itself demands a client certificate** (ADR-0007,
/// ADR-0025).
///
/// Checked is **only** `tls::server_config` -- without the sidecar above it,
/// and that is the whole point. There are two layers:
///
/// 1. `ClientCertVerifier::client_auth_mandatory` lets `rustls` abort the
///    handshake;
/// 2. `serve_inbound` afterwards discards every connection without a peer
///    identity.
///
/// **Measured, the second catches the first** -- with `client_auth_mandatory`
/// at `false` the anonymous client still does not get through. Defence in
/// depth, and it holds. Only it thereby also guards the first layer **away**:
/// an end-to-end test would stay green if layer 1 disappeared, and the
/// handshake would from then on succeed with an anonymous client. That is why
/// the guard stands here, where only layer 1 takes effect.
///
/// The cluster transport has had its own since ADR-0043
/// (`a_client_without_a_certificate_is_refused`); the data plane had none --
/// and it is the more exposed of the two.
#[tokio::test]
async fn the_handshake_itself_demands_a_client_certificate() {
    let pki = Pki::new();
    let identity = pki.identity("ledger");
    let verifier = PeerVerifier::new(
        identity.id(),
        SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()])),
        policy(&[("api", "ledger")]),
        Enforcement::Inbound,
    );
    let server = tg_proxy::tls::server_config(&identity, verifier).expect("the server side");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
    let addr = listener.local_addr().expect("the address");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepted");
        acceptor
            .accept(stream)
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    });

    // A client without client auth that does not check the server: what is
    // checked here is what the **server** demands.
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the versions")
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyServer))
    .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let stream = TcpStream::connect(addr).await.expect("connected");
    let name = rustls_pki_types::ServerName::try_from("ledger.invalid").expect("the name");

    let _ = connector.connect(name, stream).await;

    // **What is asserted is the server side**, and only it. Measured, the
    // client's `write_all` still succeeds under TLS 1.3: it sends before the
    // rejection reaches it. Whoever built an assertion out of that would check
    // a timing behaviour instead of a decision.
    assert!(
        task.await.expect("the task").is_err(),
        "the server should have aborted the handshake"
    );
}

/// **And the same situation over the whole route.**
///
/// The compound statement: an anonymous client gets nothing. It is true because
/// **both** layers carry it -- the test above says which.
#[tokio::test]
async fn an_anonymous_client_gets_nothing_end_to_end() {
    let mesh = mesh(&[("api", "ledger")], &[("api", "ledger")]).await;

    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the versions")
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyServer))
    .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let stream = TcpStream::connect(mesh.inbound).await.expect("connected");
    let name = rustls_pki_types::ServerName::try_from("ledger.invalid").expect("the name");

    let outcome = async {
        let mut tls = connector
            .connect(name, stream)
            .await
            .map_err(|err| err.to_string())?;
        tls.write_all(b"anonymous")
            .await
            .map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        let mut back = [0_u8; 9];
        tls.read_exact(&mut back).await.map_err(|e| e.to_string())
    }
    .await;

    assert!(
        outcome.is_err(),
        "a client without a credential should not have got through"
    );
}

/// Accepts every server certificate -- the test checks the other direction.
#[derive(Debug)]
struct AcceptAnyServer;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
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

// --- The active role (ADR-0066) ---------------------------------------------

/// A state that holds `<workload>` far into the future.
fn holding(workload: &str) -> String {
    format!("{workload} 7 99999999999999\n")
}

/// **A single writer without the active role accepts nothing.**
///
/// That is the gap ADR-0064 left open: `role_of` expressly exempts instance
/// ≠ 0 (determination 8), because a warm standby must **run** in order to be
/// warm. With that it ran completely, however -- and answered requests that
/// belong to the holder.
///
/// The counter-check stands beside it and is half the assurance: with the role
/// the same route carries. Without it a sidecar that lets nothing through at
/// all would be green too.
#[tokio::test]
async fn a_single_writer_without_the_active_role_serves_nobody() {
    let passive = mesh_with(
        &Pki::new(),
        &[("api", "ledger")],
        &[("api", "ledger")],
        None,
        Roles::server(""),
    )
    .await;

    assert!(
        round_trip(passive.outbound, b"hello").await.is_err(),
        "a standby must not serve (ADR-0066)"
    );
    // **And the upstream saw nothing.** That is the part that tells the
    // refusal apart from the guard: without it the sidecar would first build
    // the route and then tear it down -- from outside both would look the same,
    // and the line would be unguarded.
    assert_eq!(
        passive
            .upstream_connections
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "without an active role the upstream must not even be dialled"
    );

    let active = mesh_with(
        &Pki::new(),
        &[("api", "ledger")],
        &[("api", "ledger")],
        None,
        Roles::server(&holding("ledger")),
    )
    .await;

    assert_eq!(
        round_trip(active.outbound, b"hello")
            .await
            .expect("the answer"),
        b"hello".to_vec(),
        "with the active role the same route carries"
    );
}

/// **And it does not build one either.**
///
/// The other direction, and it is the one for which ADR-0010 names the
/// fencing: a primary whose lease has expired and whose container **stops
/// slowly** would otherwise carry on writing.
#[tokio::test]
async fn a_single_writer_without_the_active_role_initiates_nothing() {
    let passive = mesh_with(
        &Pki::new(),
        &[("api", "ledger")],
        &[("api", "ledger")],
        None,
        Roles::client(""),
    )
    .await;

    assert!(
        round_trip(passive.outbound, b"hello").await.is_err(),
        "without an active role nothing is dialled (ADR-0066)"
    );

    let active = mesh_with(
        &Pki::new(),
        &[("api", "ledger")],
        &[("api", "ledger")],
        None,
        Roles::client(&holding("api")),
    )
    .await;

    assert_eq!(
        round_trip(active.outbound, b"hello")
            .await
            .expect("the answer"),
        b"hello".to_vec()
    );
}

/// **An expired lease is no active role**, even when the line still stands
/// there.
///
/// The difference from the test above is **one** thing: the deadline.
/// Otherwise a red run would merely prove that something did not work.
#[tokio::test]
async fn an_expired_lease_serves_nobody_either() {
    let expired = mesh_with(
        &Pki::new(),
        &[("api", "ledger")],
        &[("api", "ledger")],
        None,
        // The same line as above, only with a deadline in the past.
        Roles::server("ledger 7 1000\n"),
    )
    .await;

    assert!(
        round_trip(expired.outbound, b"hello").await.is_err(),
        "an expired lease must not carry on serving (ADR-0010)"
    );
}

/// **Withdrawing the active role tears down a running connection.**
///
/// Refusing new connections does not suffice: a long stream would otherwise
/// survive the fencing deadline, and that is exactly the case ADR-0010 names
/// ("fencing takes hold even when the old primary stops slowly").
///
/// The same construction as with the edge withdrawal (ADR-0025): the guard
/// wakes up through the version change and closes.
#[tokio::test]
async fn losing_the_active_role_tears_down_a_live_connection() {
    let mesh = mesh_with(
        &Pki::new(),
        &[("api", "ledger")],
        &[("api", "ledger")],
        None,
        Roles::server(&holding("ledger")),
    )
    .await;

    let mut stream = tokio::net::TcpStream::connect(mesh.outbound)
        .await
        .expect("the connection");
    stream.write_all(b"one").await.expect("writable");
    let mut buffer = [0_u8; 3];
    stream.read_exact(&mut buffer).await.expect("the answer");
    assert_eq!(&buffer, b"one", "the route must carry first");

    // The role goes away -- as the agent writes it at the next slice.
    mesh.server_roles
        .as_ref()
        .expect("the server is a single writer")
        .replace(tg_proxy::role::Roles::default());

    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        let mut sink = [0_u8; 1];
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;

    assert!(
        closed.is_ok(),
        "the running connection must end when the role is withdrawn (ADR-0066)"
    );
}

/// **Whoever wanted another port is refused** (ADR-0141).
///
/// # The finding behind it
///
/// The rule set redirects **all** inbound TCP onto the sidecar, without a port
/// filter, and the sidecar connected to exactly one port -- the one from
/// `<mesh port>`. Whoever dialled `ledger:9999` while `ledger` declares `8080`
/// thereby got a connection to `8080`, **silently**.
///
/// # Why the setup looks like this
///
/// The sidecar here listens on a **different** port number from its workload,
/// and that is exactly the failure case: without a NAT entry
/// `SO_ORIGINAL_DST` names the local address, that is, the sidecar's port --
/// and that is not the workload's. Until ADR-0141 that was the setup of
/// **all** the witnesses here, and it ran green.
///
/// The counter-check stands in `two_workloads_talk_when_the_edge_exists`:
/// there sidecar and workload carry the same port number, and the route holds.
/// Both runs differ in **one** thing -- the sidecar's port number --, otherwise
/// a red test would merely prove that something did not work.
#[tokio::test]
async fn a_caller_that_wanted_another_port_is_refused() {
    let pki = Pki::new();
    let (upstream, upstream_connections) = echo_server().await;
    let server_policy = policy(&[("api", "ledger")]);

    // **A different port from the workload's** -- the failure case.
    let inbound_listener = TcpListener::bind("127.0.0.2:0").await.expect("the socket");
    let inbound_addr = inbound_listener.local_addr().expect("the address");
    assert_ne!(
        inbound_addr.port(),
        upstream.port(),
        "the setup hits the case only when the ports are different"
    );

    let server_config = Config {
        identity: pki.identity("ledger"),
        bundle: SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()])),
        policy: server_policy,
        window: window(),
        role: None,
    };
    tokio::spawn(async move {
        let _ = tg_proxy::serve_inbound(
            server_config,
            inbound_listener,
            upstream.port(),
            std::future::pending(),
        )
        .await;
    });

    // The outbound sidecar in front of it -- with an edge, so that the refusal
    // can lie **only** with the port.
    let client_policy = policy(&[("api", "ledger")]);
    let outbound_listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
    let outbound_addr = outbound_listener.local_addr().expect("the address");
    let client_config = Config {
        identity: pki.identity("api"),
        bundle: SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()])),
        policy: client_policy,
        window: window(),
        role: None,
    };
    let route = Route {
        listen: outbound_addr,
        connect: inbound_addr,
        peer: SpiffeId::for_workload(&domain(), "ledger").expect("the ID"),
    };
    tokio::spawn(async move {
        let _ = tg_proxy::serve_outbound(
            client_config,
            route,
            outbound_listener,
            std::future::pending(),
        )
        .await;
    });

    let result = round_trip(outbound_addr, b"hello ledger").await;

    assert!(
        result.is_err(),
        "a caller that wanted another port must not get through -- it came: {result:?}"
    );
    // **And the workload saw nothing.** Without this assertion the test would
    // be green too if the route had been built and torn down afterwards -- the
    // upstream would then have counted a connection.
    assert_eq!(
        upstream_connections.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the workload must have seen nothing of this connection"
    );
}
