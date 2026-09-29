//! A withdrawn egress permission tears the running connection down
//! (ADR-0041, ADR-0025).
//!
//! Written **before** the implementation.
//!
//! # The finding
//!
//! ADR-0041 expressly names as a positive consequence: "**one** enforcement
//! place for both directions. The same sidecar, the same policy cache, the
//! same fail-static behaviour, **the same window**."
//!
//! Measured, the window did **not** apply for the egress. The mesh path has
//! had its guard since 8b (`revoking_the_edge_tears_down_a_live_connection`);
//! the egress decided **once**, at the connection setup, and spliced
//! afterwards until one side closed. A withdrawal took effect only for new
//! connections -- with a long-lived stream "withdrawn" thereby meant nothing.
//!
//! And the comment at `SharedEgress` called that "a decision of its own,
//! deliberately not taken here". It **was** taken, in ADR-0041. The record is
//! withdrawn.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tg_proxy::egress::{EgressPolicy, Resolver, SharedEgress};
use tg_proxy::policy::RevocationWindow;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// A real `ClientHello` -- the same production as in `egress.rs`.
fn client_hello(server_name: &str) -> Vec<u8> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let name = server_name.to_owned().try_into().expect("a valid name");
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), name).expect("the connection");

    let mut bytes = Vec::new();
    connection.write_tls(&mut bytes).expect("the ClientHello");

    bytes
}

/// An endpoint that sends back what it gets.
///
/// It need speak **no** TLS: the sidecar does not terminate (ADR-0041,
/// determination 1), it splices raw bytes on.
async fn echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
    let addr = listener.local_addr().expect("the address");

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    addr
}

/// The egress sidecar with an exchangeable permission list.
async fn sidecar() -> (std::net::SocketAddr, SharedEgress) {
    sidecar_with(None).await
}

/// The same setup, but with an active-role gate (ADR-0066).
async fn sidecar_with(role: Option<tg_proxy::role::Gate>) -> (std::net::SocketAddr, SharedEgress) {
    let upstream = echo().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
    let addr = listener.local_addr().expect("the address");

    // **The permission names the listening port, and that looks like a
    // bypass.** This setup has no redirect: the client dials the egress port
    // directly, so the original destination address *is* that port
    // (ADR-0051). In a real netns the same line would be a gap -- there the
    // traffic comes over the redirect, and a permitted egress port would let
    // everyone out who bypasses it. The same reason stands at the end-to-end
    // test in `egress_path.rs`.
    let policy = SharedEgress::new(EgressPolicy::from_entries([(
        "s3.test".to_owned(),
        addr.port(),
        tg_proxy::egress::Transport::Tcp,
    )]));

    let mut pinned = BTreeMap::new();
    pinned.insert("s3.test".to_owned(), upstream);
    let resolver = Resolver::Pinned(Arc::new(pinned));

    let serving = policy.clone();
    tokio::spawn(async move {
        tg_proxy::egress::serve(
            listener,
            serving,
            resolver,
            window(),
            role,
            std::future::pending(),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, policy)
}

/// A window that is **long**, and that is the whole trick.
///
/// The guard has two ways to notice a withdrawal: the version channel and the
/// window's timer. With a short window the timer **covers** the channel -- the
/// counter-check stayed green although the wake-up had been removed. The same
/// case as with `client_auth_mandatory`, where the second layer hid the first.
///
/// With a 60 s window and 10 s of patience only the **channel** can make it.
/// What thereby stays unchecked is the backstop itself -- as in the mesh, and
/// for the same reason: checking it would mean letting a test wait a
/// minute.
fn window() -> RevocationWindow {
    RevocationWindow::adr_0014()
}

/// Sets up a running route and gives it back.
async fn live(addr: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("the connection");
    stream
        .write_all(&client_hello("s3.test"))
        .await
        .expect("the ClientHello");

    // The `ClientHello` arrives at the echo and comes back -- with that it
    // is settled that splicing happens.
    let mut back = vec![0_u8; 5];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("the route must stand")
        .expect("the echo");

    stream
}

/// Whether the connection ends within the patience.
///
/// Writing carries on in the process so that a pure read timeout does not pass
/// as a teardown: as long as the route stands, the echo comes back.
async fn ended(mut stream: TcpStream, patience: Duration) -> bool {
    tokio::time::timeout(patience, async {
        let mut sink = [0_u8; 64];
        loop {
            if stream.write_all(b"still there?").await.is_err() {
                return true;
            }
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => return true,
                Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// **The withdrawal tears the running connection down** (ADR-0041: the same
/// window as ADR-0025).
#[tokio::test(flavor = "multi_thread")]
async fn revoking_an_egress_permission_tears_down_a_live_connection() {
    let (addr, policy) = sidecar().await;
    let stream = live(addr).await;

    policy.replace(EgressPolicy::from_entries([]), 1_000);

    assert!(
        ended(stream, Duration::from_secs(10)).await,
        "a withdrawn permission must end the running connection"
    );
}

/// **And without a withdrawal it holds** -- across several windows.
///
/// The counter-check, and it weighs the same: a guard that clears every
/// connection away after one window would pass the test above too. Fail-static
/// does not mean that the deadline strikes at some point (ADR-0019) -- the
/// same counter-check 8b has for the mesh.
#[tokio::test(flavor = "multi_thread")]
async fn an_unchanged_permission_keeps_the_connection() {
    let (addr, _policy) = sidecar().await;
    let stream = live(addr).await;

    assert!(
        !ended(stream, Duration::from_secs(5)).await,
        "without a withdrawal the connection must hold across several windows"
    );
}

/// **And over the way operation goes: the file.**
///
/// The test above calls `replace` directly. In operation `egress::refresh`
/// does that after the agent has rewritten the file from the slice (ADR-0040)
/// -- and **there** the wake-up can be lost: whoever one day lets `refresh`
/// change the list in place instead of calling `replace` takes the version
/// channel along, and the withdrawal again takes effect only for new
/// connections. From outside that would look as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_rewritten_allowlist_tears_down_a_live_connection() {
    let dir = tempfile::tempdir().expect("the directory");
    let file = dir.path().join("egress");
    let (addr, policy) = sidecar().await;
    let stream = live(addr).await;

    // The agent writes the file anew -- without the permission. Written
    // unconditionally even when nothing is left: precisely that **is** the
    // withdrawal.
    std::fs::write(&file, "").expect("the file");

    let outcome = tg_proxy::egress::refresh(&policy, &file, "api", addr.port(), 1_000);
    assert!(
        matches!(outcome, tg_proxy::policy::Refresh::Applied),
        "an empty list is no error but the withdrawal: {outcome:?}"
    );

    assert!(
        ended(stream, Duration::from_secs(10)).await,
        "the withdrawal over the file must end the running connection"
    );
}

// --- the active role to the outside (ADR-0066) ---------------------------

/// A gate for `api`, with this file as the state.
fn gate(text: &str) -> tg_proxy::role::Gate {
    tg_proxy::role::Gate::new(
        "api".to_owned(),
        tg_proxy::role::SharedRoles::new(tg_proxy::role::Roles::from_text(text)),
    )
}

/// **Without an active role nothing goes out either.**
///
/// The mesh alone does not suffice: per ADR-0027 a workload's shared mutable
/// state lies in **external S3**, and the way there is precisely this port. A
/// fenced writer that were cut only in the mesh would carry on writing where
/// it hurts.
///
/// The counter-check stands beside it and is half the assurance: with the role
/// the same route carries.
#[tokio::test]
async fn without_the_active_role_nothing_goes_out() {
    let (passive, _) = sidecar_with(Some(gate(""))).await;
    let mut stream = TcpStream::connect(passive).await.expect("the connection");
    stream
        .write_all(&client_hello("s3.test"))
        .await
        .expect("the ClientHello");

    // Nothing comes back, and the connection ends: the sidecar discarded it
    // before it even resolved.
    let mut back = vec![0_u8; 5];
    let echoed = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await;
    assert!(
        matches!(echoed, Ok(Err(_))),
        "a fenced writer must not go out (ADR-0066): {echoed:?}"
    );

    // The counter-check, and it is half the assurance: **with** the role the
    // same route carries. Without it a sidecar that lets nothing through on
    // principle would be green too.
    let (active, _) = sidecar_with(Some(gate("api 7 99999999999999\n"))).await;
    let _ = live(active).await;
}

/// **The loss of the active role tears a running egress connection down.**
///
/// That is the case the refusal at the connection setup does **not** cover --
/// and the dangerous one: a primary whose lease expires while it is just
/// writing to S3.
///
/// The two layers otherwise mask each other: with a connection that arrives
/// passive already, either of them bites, and no counter-check separates them.
/// Only this expiry can be passed by the guard alone.
#[tokio::test]
async fn losing_the_active_role_tears_down_a_live_egress_connection() {
    let held = gate("api 7 99999999999999\n");
    let roles = held.roles().clone();
    let (addr, _policy) = sidecar_with(Some(held)).await;

    let stream = live(addr).await;

    // The role goes away -- as the agent writes it at the next slice.
    roles.replace(tg_proxy::role::Roles::default());

    assert!(
        ended(stream, Duration::from_secs(10)).await,
        "the running connection must end at the role withdrawal (ADR-0066)"
    );
}
