//! UDP between two sidecars, carried over QUIC datagrams.
//!
//! The first cut: the path between two sidecars at **real** sockets, with
//! real certificates and real verification. The wiring -- the rule set in
//! the namespace, the derived call line -- is a separate concern covered
//! elsewhere.
//!
//! # What is substantiated here
//!
//! The design rests on **one** property: `quinn` runs on `rustls`, so
//! `tg_proxy::verify` is usable unchanged. These witnesses check precisely
//! that -- the same SPIFFE check and the same `may_talk` edge as on the TCP
//! side, without one line of authorization anew.
//!
//! Every rejection case differs from the normal case in **one** thing (the
//! edge, the CA) -- otherwise a red test would prove merely that something did
//! not work.

use std::net::SocketAddr;
use std::time::Duration;

use tg_identity::{Authority, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};
use tg_proxy::datagram::Endpoint;
use tg_proxy::identity::Identity;
use tg_proxy::policy::{PolicyCache, RevocationWindow, Snapshot};
use tg_proxy::verify::{Bundle, Enforcement, PeerVerifier, SharedBundle, SharedPolicy};

const YEAR: i64 = 365 * 24 * 3600;

/// Returns the current Unix time, in seconds.
fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs(),
    )
    .expect("fits")
}

/// Returns the trust domain used by these tests.
fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local".to_owned()).expect("the domain")
}

/// Returns the revocation window used to build a policy cache in these tests.
fn window() -> RevocationWindow {
    RevocationWindow {
        target: Duration::from_secs(1),
        staleness: Duration::from_mins(15),
    }
}

struct Pki {
    anchor: Vec<u8>,
    authority: Authority<LocalSigner>,
}

impl Pki {
    /// Creates a self-signed CA and an issuing authority backed by it, for
    /// use as a test fixture.
    ///
    /// # Returns
    /// A `Pki` holding the CA's DER-encoded anchor certificate and the
    /// authority that issues SVIDs from it.
    fn new() -> Self {
        let signer = LocalSigner::generate().expect("the key");
        let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("the CA");
        let anchor = ca.certificate_der().to_vec();
        let authority = Authority::new(ca, signer, Lifetime::default()).expect("the issuer");

        Self { anchor, authority }
    }

    /// Issues an SVID for the named workload and wraps it as a shared
    /// identity.
    ///
    /// # Parameters
    /// - `workload`: the workload name to derive the SPIFFE ID from.
    ///
    /// # Returns
    /// The workload's shared identity, holding its certificate chain and
    /// private key.
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

/// Builds a shared policy cache from a fixed set of `may_talk` edges.
///
/// # Parameters
/// - `edges`: the `(from, to)` name pairs permitted to talk to each other.
///
/// # Returns
/// The resulting shared policy cache.
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

/// Builds a QUIC endpoint bound to loopback, configured with an identity, a
/// trust anchor and a set of permitted edges.
///
/// # Parameters
/// - `pki`: the PKI that issues this endpoint's own identity.
/// - `anchor`: the PKI whose certificate is trusted as the peer's anchor.
/// - `workload`: the workload name this endpoint identifies as.
/// - `edges`: the `(from, to)` name pairs permitted to talk to each other.
/// - `side`: whether this endpoint enforces policy as the inbound or
///   outbound side of the connection.
///
/// # Returns
/// The bound, configured endpoint.
fn endpoint(
    pki: &Pki,
    anchor: &Pki,
    workload: &str,
    edges: &[(&str, &str)],
    side: Enforcement,
) -> Endpoint {
    let identity = pki.identity(workload);
    let verifier = PeerVerifier::new(
        identity.id().clone(),
        SharedBundle::new(Bundle::from_der(vec![anchor.anchor.clone()])),
        policy(edges),
        side,
    );

    Endpoint::bind(
        "127.0.0.1:0".parse::<SocketAddr>().expect("the address"),
        &identity,
        &verifier,
    )
    .expect("the endpoint")
}

/// **Two workloads exchange datagrams when the edge is there.**
///
/// The normal case, and it carries the three refusals below: without it a
/// setup in which nothing gets through on principle would be green too.
#[tokio::test(flavor = "multi_thread")]
async fn two_workloads_exchange_datagrams_when_the_edge_exists() {
    let pki = Pki::new();
    let ledger = endpoint(
        &pki,
        &pki,
        "ledger",
        &[("api", "ledger")],
        Enforcement::Inbound,
    );
    let api = endpoint(
        &pki,
        &pki,
        "api",
        &[("api", "ledger")],
        Enforcement::Outbound,
    );
    let peer = ledger.local_addr().expect("the address");

    let (done, wait) = tokio::sync::oneshot::channel();
    let served = tokio::spawn(async move {
        let session = ledger.accept().await.expect("the connection");
        let seen = session.recv().await.expect("the datagram");
        // **Back over the same session** -- QUIC is bidirectional, and a
        // second setup in the reverse direction would need a second edge.
        session.send(b"pong".to_vec()).expect("the answer");
        let who = session.peer();

        // **The session stays until the client has read**, and that is no
        // test detail: a datagram is **unreliable**. Whoever closes the
        // connection while one is on its way loses it -- measured as
        // `closed by peer: 0`. Precisely for that QUIC has no repeat here,
        // and precisely that is the semantics UDP brings along.
        let _ = wait.await;
        drop(session);

        (seen, who)
    });

    let session = api.dial(peer, "cluster.local").await.expect("the setup");
    session.send(b"ping".to_vec()).expect("send");
    let back = session.recv().await.expect("the answer");
    let _ = done.send(());

    let (seen, who) = served.await.expect("the task");
    assert_eq!(seen, b"ping");
    assert_eq!(back, b"pong");
    assert_eq!(
        who.map(|id| id.to_string()),
        Some("spiffe://cluster.local/workload/api".to_owned()),
        "the receiver must know with whom it speaks -- from the certificate"
    );
}

/// **Deny-by-default: without an edge no datagram gets through.**
///
/// Only **one** thing is different from above: the edges are empty. The
/// verification runs in the handshake, so the setup already fails -- there is
/// no session over which anything could come.
#[tokio::test(flavor = "multi_thread")]
async fn without_an_edge_no_datagram_gets_through() {
    let pki = Pki::new();
    let ledger = endpoint(&pki, &pki, "ledger", &[], Enforcement::Inbound);
    let api = endpoint(&pki, &pki, "api", &[], Enforcement::Outbound);
    let peer = ledger.local_addr().expect("the address");

    tokio::spawn(async move {
        let _ = ledger.accept().await;
    });

    let result =
        tokio::time::timeout(Duration::from_secs(5), api.dial(peer, "cluster.local")).await;

    assert!(
        matches!(result, Ok(Err(_)) | Err(_)),
        "without an edge no session may arise"
    );
}

/// **A peer from a foreign CA does not get through.**
///
/// The edge is there, the identities are named right -- only the anchor is a
/// different one. That separates "the edge is missing" from "the credential is
/// no good".
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_from_a_foreign_ca_is_refused() {
    let ours = Pki::new();
    let theirs = Pki::new();

    let ledger = endpoint(
        &ours,
        &ours,
        "ledger",
        &[("api", "ledger")],
        Enforcement::Inbound,
    );
    // A foreign CA, but our anchor in the trust list -- the handshake fails
    // on the chain and not on the edge.
    let api = endpoint(
        &theirs,
        &ours,
        "api",
        &[("api", "ledger")],
        Enforcement::Outbound,
    );
    let peer = ledger.local_addr().expect("the address");

    let served = tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_secs(2), ledger.accept()).await {
            Ok(Some(session)) => session.recv().await.ok(),
            _ => None,
        }
    });

    // **The setup can succeed, and that is the finding**: with TLS 1.3 the
    // handshake is finished for the client after the server's `Finished`; the
    // latter's check of **its** certificate runs afterwards, and the refusal
    // reaches it only as an alert. A test that looked only at `dial` would be
    // green and would prove nothing -- the difference from the TCP path, where
    // `connector.connect().await` waits out both directions.
    //
    // What is checked is therefore what matters: nothing arrives at the
    // receiver.
    if let Ok(Ok(session)) =
        tokio::time::timeout(Duration::from_secs(5), api.dial(peer, "cluster.local")).await
    {
        let _ = session.send(b"ping".to_vec());
        let _ = tokio::time::timeout(Duration::from_secs(2), session.recv()).await;
    }

    assert_eq!(
        served.await.expect("the task"),
        None,
        "nothing from a foreign CA may arrive at the receiver"
    );
}

/// **The budget is a hard bound, and it is reported.**
///
/// A fresh connection carries around 1162 bytes, more after MTU discovery.
/// What is nailed down here is **not** the number -- it hangs on the path --
/// but the behaviour at the bound: a datagram above it is **refused** and
/// not truncated. A truncation would tear the same datagram apart without
/// any trace.
#[tokio::test(flavor = "multi_thread")]
async fn a_datagram_over_the_budget_is_refused_and_not_truncated() {
    let pki = Pki::new();
    let ledger = endpoint(
        &pki,
        &pki,
        "ledger",
        &[("api", "ledger")],
        Enforcement::Inbound,
    );
    let api = endpoint(
        &pki,
        &pki,
        "api",
        &[("api", "ledger")],
        Enforcement::Outbound,
    );
    let peer = ledger.local_addr().expect("the address");

    let served = tokio::spawn(async move {
        let session = ledger.accept().await.expect("the connection");
        // What arrives is counted -- with a truncation something would arrive.
        tokio::time::timeout(Duration::from_secs(2), session.recv())
            .await
            .ok()
            .and_then(Result::ok)
    });

    let session = api.dial(peer, "cluster.local").await.expect("the setup");
    let budget = session
        .max_datagram()
        .expect("the counterpart carries datagrams");

    let err = session
        .send(vec![0_u8; budget + 1])
        .expect_err("a datagram over the budget must not be accepted");
    assert!(
        err.to_string().contains("too large"),
        "the message must name the reason: {err}"
    );

    // **And at the budget itself it gets through** -- the counter-check.
    // Without it a setup in which nothing gets through at all would be green
    // too.
    session.send(vec![7_u8; budget]).expect("the budget itself");

    let seen = served.await.expect("the task");
    assert_eq!(
        seen.map(|bytes| bytes.len()),
        Some(budget),
        "exactly the budget must arrive untruncated"
    );
}

/// **The budget starts conservatively -- far below what the path carries.**
///
/// QUIC begins at a minimum MTU and raises it by discovery. For operation that
/// means: a connection's **first** datagrams carry less than the later ones --
/// a workload with 1300-byte datagrams loses them, and it learns of it (the
/// test above).
///
/// # Why no number stands here
///
/// The first attempt nailed `1200 - OVERHEAD` down and was **green
/// individually, red in the full run**: measured 1162 alone, 1288 beside
/// others. The difference is not the overhead -- that is 38 in both cases
/// (`1200 - 1162` and `1326 - 1288`) -- but the **base** quinn assumes, and
/// that hangs on things a test does not control.
///
/// A witness that nails such a number down is a flaky test with a rationale.
/// What is nailed down is therefore the **ordering**: conservative against the
/// path, and the computation from the constant works out.
#[tokio::test(flavor = "multi_thread")]
async fn the_budget_starts_conservatively() {
    let pki = Pki::new();
    let ledger = endpoint(
        &pki,
        &pki,
        "ledger",
        &[("api", "ledger")],
        Enforcement::Inbound,
    );
    let api = endpoint(
        &pki,
        &pki,
        "api",
        &[("api", "ledger")],
        Enforcement::Outbound,
    );
    let peer = ledger.local_addr().expect("the address");

    tokio::spawn(async move {
        let session = ledger.accept().await.expect("the connection");
        while session.recv().await.is_ok() {}
    });

    let session = api.dial(peer, "cluster.local").await.expect("the setup");
    let start = session.max_datagram().expect("the datagrams");

    // **Far below what loopback could do** (65 536). Without this bound a
    // stack that exhausts the path MTU immediately would be green too -- and
    // then the warning in the manual that the first datagrams are smaller
    // would not hold.
    assert!(
        start < 2048,
        "{start} is no conservative minimum MTU -- on loopback 65 536 would be \
         possible"
    );

    // **And the computation works out.** The overhead is the number the
    // manual reckons with; the base beside it must be a plausible MTU.
    let mtu = start + tg_proxy::datagram::QUIC_DATAGRAM_OVERHEAD;
    assert!(
        (1200..=1500).contains(&mtu),
        "from {start} + {} follows an MTU of {mtu} -- that is none",
        tg_proxy::datagram::QUIC_DATAGRAM_OVERHEAD
    );
}

// ====================== the peer mapping

use tg_proxy::datagram::{Peer, peers_from_text};

/// **The sidecar reads only its own lines.**
///
/// One file for all the node's workloads, as with the egress permissions --
/// and a prefix is no name: `api-test` does not get what `api` is due.
#[test]
fn a_sidecar_reads_only_its_own_peers() {
    let text = "\
# a comment
api      ledger  10.42.1.5:9000  15100
api-test ledger  10.42.9.9:9000  15100
batch    ledger  10.42.2.7:9000  15101
";

    assert_eq!(
        peers_from_text(text, "api").expect("readable"),
        vec![Peer {
            name: "ledger".to_owned(),
            endpoint: "10.42.1.5:9000".parse().expect("the address"),
            local: 15100,
        }]
    );
}

/// **Two peers on one local port are an error.**
///
/// The last line does not win: which peer that would be would be decided by
/// the order in the file -- and a datagram would go to the other. Precisely
/// that damage this map is meant to prevent.
#[test]
fn two_peers_on_one_local_port_are_refused() {
    let text = "\
api ledger 10.42.1.5:9000 15100
api audit  10.42.2.7:9000 15100
";

    let err = peers_from_text(text, "api").expect_err("two on one port");
    assert!(
        err.to_string().contains("share a local port"),
        "the message must name the reason: {err}"
    );
}

/// **A broken line discards the whole file.**
///
/// Fail-closed, and the reason stands in `peers_from_text`'s documentation: a
/// half-read mapping would send datagrams to the wrong party. That is a
/// different trade-off than isolating a single broken entry and continuing
/// with the rest -- here traffic would go to the wrong receiver, so the
/// whole file is discarded instead.
#[test]
fn a_broken_line_refuses_the_whole_file() {
    for text in [
        "api ledger 10.42.1.5:9000",
        "api ledger 10.42.1.5:9000 15100 too-much",
        "api ledger no-address 15100",
        "api ledger 10.42.1.5:9000 no-port",
    ] {
        assert!(
            peers_from_text(text, "api").is_err(),
            "'{text}' should have been refused"
        );
    }
}

/// **An empty file is no error** -- it means "no UDP peers".
///
/// The counter-check to the three refusals above: without it a parser that
/// discards everything would be green too.
#[test]
fn an_empty_file_means_no_peers() {
    assert_eq!(
        peers_from_text("# only a comment\n\n", "api").expect("readable"),
        vec![]
    );
}

// ================================== the path end to end

/// **A workload sends UDP and gets its answer back** -- through two sidecars,
/// over QUIC, with mTLS.
///
/// The witness the whole second cut aims at. The "workload" here is an
/// ordinary UDP socket: it knows no QUIC, no TLS and no sidecar -- the same
/// transparency guarantee given to foreign images on the TCP path.
///
/// What the setup does **not** have is the redirect: the test socket sends
/// directly to the local listener instead of being redirected. That is this
/// witness's bound; the redirection itself is substantiated separately, at
/// real packets against real namespaces.
#[tokio::test(flavor = "multi_thread")]
async fn a_workload_sends_udp_and_gets_its_answer_back() {
    let pki = Pki::new();

    // The peer: a QUIC endpoint that mirrors datagrams.
    let ledger = endpoint(
        &pki,
        &pki,
        "ledger",
        &[("api", "ledger")],
        Enforcement::Inbound,
    );
    let peer_addr = ledger.local_addr().expect("the address");
    tokio::spawn(async move {
        let session = ledger.accept().await.expect("the connection");
        while let Ok(bytes) = session.recv().await {
            let mut back = b"echo:".to_vec();
            back.extend_from_slice(&bytes);
            if session.send(back).is_err() {
                break;
            }
        }
    });

    // Its own sidecar: a listener for exactly this peer.
    let api = std::sync::Arc::new(endpoint(
        &pki,
        &pki,
        "api",
        &[("api", "ledger")],
        Enforcement::Outbound,
    ));
    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("the listener");
    let local = listener.local_addr().expect("the address");

    let (stop, halt) = tokio::sync::oneshot::channel();
    tokio::spawn(tg_proxy::datagram::relay(
        api,
        Peer {
            name: "ledger".to_owned(),
            endpoint: peer_addr,
            local: local.port(),
        },
        listener,
        async move {
            let _ = halt.await;
        },
    ));

    // The "workload" -- an ordinary UDP socket.
    let workload = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("the workload");
    workload.send_to(b"ping", local).await.expect("send");

    let mut buffer = [0_u8; 64];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), workload.recv_from(&mut buffer))
        .await
        .expect("within 5 s")
        .expect("the answer");

    assert_eq!(&buffer[..len], b"echo:ping");
    let _ = stop.send(());
}

/// **Without an edge nothing gets through over the listener either.**
///
/// Only **one** thing is different from above: the edges are empty. The loop
/// runs, the workload sends, and the QUIC session does not come about -- the
/// verifier decides, not the loop.
#[tokio::test(flavor = "multi_thread")]
async fn without_an_edge_the_relay_carries_nothing() {
    let pki = Pki::new();

    let ledger = endpoint(&pki, &pki, "ledger", &[], Enforcement::Inbound);
    let peer_addr = ledger.local_addr().expect("the address");
    tokio::spawn(async move {
        if let Some(session) = ledger.accept().await {
            while let Ok(bytes) = session.recv().await {
                let _ = session.send(bytes);
            }
        }
    });

    let api = std::sync::Arc::new(endpoint(&pki, &pki, "api", &[], Enforcement::Outbound));
    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("the listener");
    let local = listener.local_addr().expect("the address");

    let (stop, halt) = tokio::sync::oneshot::channel();
    tokio::spawn(tg_proxy::datagram::relay(
        api,
        Peer {
            name: "ledger".to_owned(),
            endpoint: peer_addr,
            local: local.port(),
        },
        listener,
        async move {
            let _ = halt.await;
        },
    ));

    let workload = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("the workload");
    workload.send_to(b"ping", local).await.expect("send");

    let mut buffer = [0_u8; 64];
    let answer =
        tokio::time::timeout(Duration::from_secs(2), workload.recv_from(&mut buffer)).await;

    assert!(
        answer.is_err(),
        "without an edge nothing may come back, there came: {answer:?}"
    );
    let _ = stop.send(());
}
