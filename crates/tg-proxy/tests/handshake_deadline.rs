//! **Whoever does not identify themselves may not stay** (ADR-0007,
//! ADR-0019).
//!
//! # The finding that triggered this file
//!
//! Measured at an inbound sidecar: a hundred TCP connections that send **no**
//! `ClientHello` -- after three seconds **none** was closed, and the process
//! held two hundred descriptors.
//!
//! Each of them costs a task and a descriptor, and the limit belongs to the
//! **process**. Once it is exhausted the sidecar accepts nothing more -- its
//! workload is then no longer reachable, that is, precisely what ADR-0019 sets
//! as the goal. And after the mesh redirect the place is reachable from
//! **every** container of the node (ADR-0060), **without a credential**: the
//! handshake *is* the authentication.
//!
//! # Why the deadline is short in the test
//!
//! It is not: the test uses the **real** constant and does not wait for it. It
//! checks that the server **holds** the connection as long as it runs, and
//! closes afterwards -- waiting out the second half against a deadline of ten
//! seconds would be a test that takes ten seconds. So: `tokio::time::pause`,
//! and the time is fast-forwarded.

use std::time::Duration;

use tg_identity::{Authority, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};
use tg_proxy::identity::Identity;
use tg_proxy::policy::{PolicyCache, RevocationWindow, Snapshot};
use tg_proxy::sidecar::Config;
use tg_proxy::verify::{Bundle, SharedBundle, SharedPolicy};

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("the domain")
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

fn window() -> RevocationWindow {
    RevocationWindow {
        target: Duration::from_mins(1),
        staleness: Duration::from_mins(15),
    }
}

/// A sidecar with a real identity and a real verifier.
fn config() -> Config {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let signer = LocalSigner::generate().expect("the key");
    let ca = self_signed_ca(&domain(), &signer, 0, 10 * 365 * 24 * 3_600).expect("the CA");
    let anchor = ca.certificate_der().to_vec();
    let authority = Authority::new(ca, signer, Lifetime::default()).expect("the issuer");
    let id = SpiffeId::for_workload(&domain(), "ledger").expect("the ID");
    let svid = authority.issue(&id, now()).expect("the SVID");

    let mut cache = PolicyCache::new(window());
    cache
        .apply(
            &Snapshot::from_edges(1, [("api".to_owned(), "ledger".to_owned())]),
            now(),
        )
        .expect("the snapshot");

    Config {
        identity: tg_proxy::identity::SharedIdentity::new(
            Identity::new(
                &id.to_string(),
                vec![svid.certificate_der().to_vec()],
                svid.private_key_der().to_vec(),
            )
            .expect("the identity"),
        ),
        bundle: SharedBundle::new(Bundle::from_der(vec![anchor])),
        policy: SharedPolicy::new(cache),
        window: window(),
        role: None,
    }
}

/// **A connection without a `ClientHello` is closed after the deadline.**
///
/// # Why the test really waits its ten seconds
///
/// The obvious shortcut was the paused clock, and it does **not** work:
/// `tokio` fast-forwards of its own accord as soon as all the tasks rest.
/// Measured, eight of twenty connections thereby fell before the first
/// `advance`, and "shortly before the deadline" was not producible. A test
/// that only apparently checks the deadline is worse than one that takes
/// eleven seconds.
///
/// # Two halves, and the first carries the second
///
/// Before the deadline the server holds -- otherwise one that closes every
/// connection immediately would be green too, and that one would be broken.
/// Afterwards it is closed.
///
/// That a **too short** deadline does not get through is additionally carried
/// by the tests beside it: measured, a deadline of one nanosecond makes **six**
/// tests in `sidecar.rs` red -- precisely the ones that run a real handshake.
/// The rest of this crate's targets are pure logic and do not notice it; that
/// belongs to the picture and is the reason the first half stands **here** and
/// not merely there.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_that_never_identifies_itself_is_dropped() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the port");
    let addr = listener.local_addr().expect("the address");
    // **The offered port is the one that is listened on** (ADR-0141).
    // Otherwise the sidecar refuses before the handshake begins -- and this
    // witness would check a deadline that is never reached.
    let upstream = addr.port();
    tokio::spawn(async move {
        let _ = tg_proxy::serve_inbound(config(), listener, upstream, std::future::pending()).await;
    });

    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the call");

    // **The first half**: one second after the call the connection still
    // stands.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        still_open(&mut client).await,
        "the connection was closed long before the deadline"
    );

    // **The second half**: after the deadline no longer.
    tokio::time::sleep(tg_proxy::HANDSHAKE_TIMEOUT).await;
    assert!(
        !still_open(&mut client).await,
        "a connection without a ClientHello stays open forever -- each costs a \
         task and a descriptor, and the limit belongs to the process"
    );
}

/// Whether the server still holds the connection.
///
/// A closed socket delivers `Ok(0)` or an error on reading; on an open one at
/// which nothing is pending the reading blocks -- and precisely that is here
/// the answer "still holds".
async fn still_open(client: &mut tokio::net::TcpStream) -> bool {
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(
        Duration::from_millis(200),
        tokio::io::AsyncReadExt::read(client, &mut byte),
    )
    .await
    {
        // Nothing to read and no end: it holds.
        Err(_) | Ok(Ok(1..)) => true,
        // `0` means "the server hung up", an error the same.
        Ok(Ok(0) | Err(_)) => false,
    }
}
