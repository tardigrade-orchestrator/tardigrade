//! The running sidecar (ADR-0007, ADR-0022, ADR-0025).
//!
//! Two directions, the same decision:
//!
//! - **inbound** -- accept mTLS, check the peer, pass the plaintext through to
//!   its own workload on loopback. That is the **authoritative** side
//!   (ADR-0025).
//! - **outbound** -- accept plaintext from its own workload, build mTLS to the
//!   target, check the peer. Defence in depth: a malicious client would
//!   release itself, so the server decides; but an *honest* client that tries
//!   something forbidden is to notice it here already.
//!
//! # The connection is not checked only at the setup
//!
//! A `guard` runs alongside every running connection. It waits for two things:
//! for a **version change** of the policy -- then it checks immediately -- or
//! for the expiry of the **revocation window** from ADR-0014, in case no new
//! state comes at all. If the check turns out negative, the connection is
//! closed. That is the assurance from ADR-0025: "existing connections are
//! ended within a bounded revocation window."
//!
//! What does **not** happen: a connection is not closed because the control
//! plane is gone. The cache applies on (ADR-0019, fail-static), the guard
//! checks against it, and permitted traffic runs on.
//!
//! # The redirect is still missing, and that is deliberate
//!
//! From phase 9 on nftables directs the traffic through the sidecar
//! (ADR-0012). Until then it listens on expressly named ports, and every
//! outgoing route is a setting of its own. That is less convenient, but it
//! shifts no decision: which identity is to be expected at the other end the
//! sidecar must know either way.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::identity::SharedIdentity;
use crate::policy::{DenyReason, Direction, Established, Review, RevocationWindow, UnixSeconds};
use crate::verify::{Enforcement, PeerVerifier, SharedBundle, SharedPolicy};
use tg_identity::SpiffeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Listener {
    MeshInbound,
    MeshRedirect,
    MeshOutbound,
    Egress,
    #[cfg(test)]
    Witness,
    #[cfg(test)]
    Counted,
}

impl Listener {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::MeshInbound => "mesh_inbound",
            Self::MeshRedirect => "mesh_redirect",
            Self::MeshOutbound => "mesh_outbound",
            Self::Egress => "egress",
            #[cfg(test)]
            Self::Witness => "witness",
            #[cfg(test)]
            Self::Counted => "counted",
        }
    }

    pub(crate) const fn what(self) -> &'static str {
        match self {
            Self::MeshInbound => "incoming mTLS",
            Self::MeshRedirect => "the mesh redirect",
            Self::MeshOutbound => "an outgoing route",
            Self::Egress => "the egress port",
            #[cfg(test)]
            Self::Witness => "a witness",
            #[cfg(test)]
            Self::Counted => "the gauge's witness",
        }
    }

    pub(crate) const ALL: [Self; 4] = [
        Self::MeshInbound,
        Self::MeshRedirect,
        Self::MeshOutbound,
        Self::Egress,
    ];

    const fn slot(self) -> usize {
        match self {
            Self::MeshInbound => 0,
            Self::MeshRedirect => 1,
            Self::MeshOutbound => 2,
            Self::Egress => 3,
            #[cfg(test)]
            Self::Witness => 4,
            #[cfg(test)]
            Self::Counted => 5,
        }
    }
}

static LIVE: [std::sync::atomic::AtomicUsize; 6] = [
    std::sync::atomic::AtomicUsize::new(0),
    std::sync::atomic::AtomicUsize::new(0),
    std::sync::atomic::AtomicUsize::new(0),
    std::sync::atomic::AtomicUsize::new(0),
    // The last two belong to the witnesses (`Listener::Witness` and
    // `Listener::Counted`). They cost sixteen bytes and spare a `cfg` at a
    // place at which a `cfg` would mean that a witness measures something
    // other than operation does.
    std::sync::atomic::AtomicUsize::new(0),
    std::sync::atomic::AtomicUsize::new(0),
];

pub(crate) fn publish_live(listener: Listener) {
    let live = LIVE[listener.slot()].load(std::sync::atomic::Ordering::Relaxed);
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!(
        tg_telemetry::names::PROXY_CONNECTIONS,
        "listener" => listener.label(),
    )
    .set(live as f64);
}

pub fn refresh_connections() {
    for listener in Listener::ALL {
        publish_live(listener);
    }
}

fn note_live(listener: Listener, arrived: bool) {
    let slot = &LIVE[listener.slot()];
    if arrived {
        slot.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        // **`saturating_sub` and no `fetch_sub`:** an underflow on a `usize`
        // would yield 18 quintillion open connections, and the gauge would
        // look like an attack.
        let _ = slot.fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |live| Some(live.saturating_sub(1)),
        );
    }
    publish_live(listener);
}

pub(crate) async fn accept_until<H, F>(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
    what: Listener,
    mut handle: H,
) where
    H: FnMut(tokio::net::TcpStream) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    let mut shutdown = std::pin::pin!(shutdown);
    let mut live = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            // **Fixed order, no dice** (ADR-0068). `select!` chooses at
            // random among ready branches -- and at shutdown both are ready as
            // soon as something lies in the backlog. Measured, the waiting
            // connection then still got through in **99 of 200** rounds, under
            // load on average 1.2 and in the worst case 6: it goes into
            // `live`, holds the drain up and dies with the container after the
            // grace period -- the opposite of the assurance above.
            //
            // `accept` cannot starve that: `shutdown` finishes exactly once,
            // and then this loop no longer exists. Guarded by
            // `a_connection_already_waiting_is_not_accepted_after_the_signal`.
            biased;

            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    // **At the accept, not at the handshake** (ADR-0114):
                    // the question is how much a sidecar **carries**, and a
                    // connection that dies at the handshake has occupied
                    // it.
                    metrics::counter!(
                        tg_telemetry::names::PROXY_CONNECTIONS_TOTAL,
                        "listener" => what.label(),
                    )
                    .increment(1);
                    note_live(what, true);

                    let task = handle(stream);
                    live.spawn(async move {
                        task.await;
                        note_live(what, false);
                    });
                }
                Err(error) => absorb(&error, what.what()).await,
            },
        }
    }

    // **Close the listener, not merely stop accepting.** If it stays bound,
    // the **kernel** carries on taking into the backlog: a `connect` succeeds,
    // and the client waits for a service that never accepts it -- that is
    // worse than a refusal it sees immediately. Measured at a witness that
    // failed on precisely that first.
    drop(listener);

    let waiting = live.len();
    if waiting > 0 {
        tracing::info!(
            what = what.what(),
            waiting,
            "no new connections, the running ones are being ended"
        );
    }
    while live.join_next().await.is_some() {}
}

#[derive(Debug)]
pub enum SidecarError {
    Tls {
        detail: String,
    },
}

impl std::fmt::Display for SidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls { detail } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for SidecarError {}

#[derive(Debug, Clone)]
pub struct Route {
    pub listen: SocketAddr,
    pub connect: SocketAddr,
    pub peer: SpiffeId,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub identity: SharedIdentity,
    pub bundle: SharedBundle,
    pub policy: SharedPolicy,
    pub window: RevocationWindow,
    pub role: Option<crate::role::Gate>,
}

pub(crate) async fn absorb(error: &io::Error, port: &str) {
    if let Some(pause) = tg_syscall::accept::classify(error).pause() {
        tracing::warn!(%error, port, "not accepting -- it is waiting");
        tokio::time::sleep(pause).await;
    }
}

fn may_speak(config: &Config, direction: Direction) -> bool {
    let Some(gate) = &config.role else {
        return true;
    };
    if gate.is_active(crate::role::now_millis()) {
        return true;
    }

    tracing::warn!(
        ?direction,
        "there is no talking without an active role (ADR-0010, ADR-0066)"
    );
    false
}

async fn until_fenced<F: std::future::Future<Output = ()>>(config: &Config, work: F) {
    crate::role::guarded(config.role.as_ref(), work).await;
}

fn now() -> UnixSeconds {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

fn teardown(live: &Established, reason: DenyReason) -> DenyReason {
    tracing::warn!(
        local = %live.local,
        peer = %live.peer,
        direction = ?live.direction,
        reason = %reason,
        "the connection is torn down"
    );

    reason
}

async fn guard(policy: SharedPolicy, mut live: Established, window: Duration) -> DenyReason {
    let mut versions = policy.subscribe();

    loop {
        let verdict = {
            let Ok(cache) = policy.handle().read() else {
                // A poisoned lock is no free pass -- but no authorization
                // decision either. It is therefore reported **as a defect**
                // and not merely as `NoEdge`: an operator who reads "no
                // may_talk edge" looks for an edge that exists.
                //
                // Since ADR-0082 (`panic = "unwind"`) the class is reachable
                // at all: previously a panic would have taken the process with
                // it.
                tracing::error!(
                    local = %live.local,
                    peer = %live.peer,
                    "the policy lock is poisoned -- the connection is being ended"
                );
                return teardown(&live, DenyReason::NoEdge);
            };
            cache.review(&live, now())
        };

        let next_check = match verdict {
            Review::Close { reason } => return teardown(&live, reason),
            Review::Keep { next_check } => next_check,
        };
        live.checked_at = now();
        live.version_seen = policy
            .handle()
            .read()
            .map_or(live.version_seen, |cache| cache.version());

        let wait = Duration::from_secs(
            u64::try_from(next_check.saturating_sub(now()))
                .unwrap_or(0)
                .max(1),
        )
        .min(window);

        // Either the window runs out, or a new state arrives. Both lead to
        // the next check; the second case is normal operation and practically
        // immediate.
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            changed = versions.changed() => {
                if changed.is_err() {
                    // Nobody refreshes any more. The last known policy
                    // applies on (ADR-0019, fail-static) -- we carry on
                    // checking against it, at the window's rhythm.
                    tokio::time::sleep(window).await;
                }
            }
        }
    }
}

async fn pump<A, B>(
    mut left: A,
    mut right: B,
    policy: SharedPolicy,
    live: Established,
    window: Duration,
) -> Result<Option<DenyReason>, io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        result = copy_bidirectional(&mut left, &mut right) => result.map(|_| None),
        reason = guard(policy, live, window) => Ok(Some(reason)),
    }
}

fn verifier(config: &Config, enforcement: Enforcement) -> PeerVerifier {
    PeerVerifier::new(
        config.identity.id().clone(),
        config.bundle.clone(),
        config.policy.clone(),
        enforcement,
    )
}

pub async fn serve_inbound(
    config: Config,
    listener: TcpListener,
    upstream_port: u16,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), SidecarError> {
    let tls = crate::tls::server_config(&config.identity, verifier(&config, Enforcement::Inbound))
        .map_err(|err| SidecarError::Tls {
            detail: err.to_string(),
        })?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    accept_until(listener, shutdown, Listener::MeshInbound, move |stream| {
        let acceptor = acceptor.clone();
        let config = config.clone();

        async move {
            // **Did the caller want this workload?** (ADR-0141)
            //
            // Before the handshake and before the active role: the question
            // costs one `getsockopt` and spares a whole TLS round in the
            // refusal case. It stands here and not at the outgoing sidecar,
            // because **this one** knows the port without guessing -- the
            // other has only the edge, and that carries none (ADR-0007: the
            // server is authoritative).
            if !wanted_us(&stream, upstream_port) {
                return;
            }
            // **No talking without an active role** (ADR-0066). Before the
            // handshake, because a standby is not to appear in the first
            // place.
            if !may_speak(&config, Direction::Inbound) {
                return;
            }
            // **With a deadline** (`HANDSHAKE_TIMEOUT`): whoever sends
            // nothing held a task and a descriptor forever until here --
            // measured a hundred out of a hundred. And after the mesh redirect
            // this place is reachable from **every** container of the node
            // (ADR-0060), without a credential: the handshake *is* it.
            let handshake = tokio::time::timeout(crate::HANDSHAKE_TIMEOUT, acceptor.accept(stream));
            let Ok(Ok(tls)) = handshake.await else {
                // The handshake failed or stayed out -- the wrong
                // certificate, a missing edge, an expired SVID, or nobody ever
                // sent anything. The verifier has already decided; there is
                // nothing left to do here.
                return;
            };

            let Some(peer) = peer_identity(tls.get_ref().1.peer_certificates()) else {
                // **The second layer, and it is no longer silent.** That is
                // reachable only when `client_auth_mandatory` no longer
                // applies (`tls.rs`) -- then the connection abort here catches
                // it, and without this line it would catch it *soundlessly*.
                // Defence in depth is to report when it bites; otherwise it is
                // not distinguishable from a quiet network problem.
                tracing::warn!(
                    "a connection without a peer certificate is discarded -- the \
                         handshake should not have permitted it at all (ADR-0025)"
                );
                return;
            };
            let upstream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, upstream_port));
            let Ok(mut upstream) = upstream.await else {
                // **The most frequent case in operation, and it was mute.**
                // The peer was permitted, the mTLS stood -- only the workload
                // does not listen. Without this line an operator sees
                // permitted traffic that arrives nowhere.
                tracing::warn!(
                    port = upstream_port,
                    "the upstream in the container is not reachable"
                );
                return;
            };

            let live = Established {
                local: config.identity.id(),
                peer,
                direction: Direction::Inbound,
                version_seen: config
                    .policy
                    .handle()
                    .read()
                    .map_or(0, |cache| cache.version()),
                checked_at: now(),
            };
            let mut tls = tls;
            until_fenced(&config, async {
                let _ = pump(
                    &mut tls,
                    &mut upstream,
                    config.policy.clone(),
                    live,
                    config.window.target,
                )
                .await;
            })
            .await;
        }
    })
    .await;

    Ok(())
}

pub async fn serve_mesh(
    config: Config,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), SidecarError> {
    let tls = crate::tls::client_config(&config.identity, verifier(&config, Enforcement::Outbound))
        .map_err(|err| SidecarError::Tls {
            detail: err.to_string(),
        })?;
    let connector = TlsConnector::from(Arc::new(tls));

    // As in `serve_outbound`: the SNI is a placeholder, the identity stands
    // in the URI SAN (ADR-0006).
    let sni = rustls_pki_types::ServerName::try_from(
        config.identity.id().trust_domain().as_str().to_owned(),
    )
    .unwrap_or(rustls_pki_types::ServerName::IpAddress(
        std::net::Ipv4Addr::LOCALHOST.into(),
    ));

    accept_until(
        listener,
        shutdown,
        Listener::MeshRedirect,
        move |mut plain| {
            let connector = connector.clone();
            let config = config.clone();
            let sni = sni.clone();

            async move {
                // **Before the first byte**: where the container wanted to
                // go stands in the conntrack and not in the data stream.
                // Without the setting there is no destination -- and no
                // fallback to a list (ADR-0060, determination 1).
                let Some(wanted) = original_destination(&plain) else {
                    return;
                };

                // **No talking without an active role** (ADR-0066). Before
                // the handshake, because a standby is not to appear in the
                // first place.
                if !may_speak(&config, Direction::Outbound) {
                    return;
                }
                // With a deadline as inbound: a counterpart that does not
                // complete the setup would otherwise hold a task and a
                // descriptor.
                let Ok(Ok(tcp)) =
                    tokio::time::timeout(crate::HANDSHAKE_TIMEOUT, TcpStream::connect(wanted))
                        .await
                else {
                    tracing::warn!(%wanted, "the external endpoint is not reachable");
                    return;
                };
                let Ok(Ok(mut tls)) =
                    tokio::time::timeout(crate::HANDSHAKE_TIMEOUT, connector.connect(sni, tcp))
                        .await
                else {
                    tracing::warn!(%wanted, "the mTLS to the peer failed");
                    return;
                };
                let Some(peer) = peer_identity(tls.get_ref().1.peer_certificates()) else {
                    // As inbound: reachable only if the verifier let the
                    // counterpart through without a credential.
                    tracing::warn!(
                        "a connection without a peer certificate is discarded -- the \
                         handshake should not have permitted it at all (ADR-0025)"
                    );
                    return;
                };

                let live = Established {
                    local: config.identity.id(),
                    peer,
                    direction: Direction::Outbound,
                    version_seen: config
                        .policy
                        .handle()
                        .read()
                        .map_or(0, |cache| cache.version()),
                    checked_at: now(),
                };
                until_fenced(&config, async {
                    let _ = pump(
                        &mut plain,
                        &mut tls,
                        config.policy.clone(),
                        live,
                        config.window.target,
                    )
                    .await;
                })
                .await;
            }
        },
    )
    .await;

    Ok(())
}

fn wanted_us(client: &TcpStream, upstream_port: u16) -> bool {
    // `ENOENT` means "no conntrack entry" and thereby "not redirected" -- the
    // same statement the kernel gives with conntrack as the local address.
    let wanted = match rustix::net::sockopt::ip_original_dst(client) {
        Ok(wanted) => wanted.port(),
        Err(_) => match client.local_addr() {
            Ok(local) => local.port(),
            Err(err) => {
                // A socket without a local address is already dead; there is
                // nothing to decide here.
                tracing::warn!(%err, "no local destination to read -- refused (ADR-0141)");
                return false;
            }
        },
    };

    if wanted == upstream_port {
        return true;
    }

    // **Reported, not mute.** A connection abort without a reason is not
    // distinguishable from a network problem -- the same consideration as with
    // "the upstream in the container is not reachable" beside it.
    tracing::warn!(
        wanted,
        offered = upstream_port,
        "refused: this workload offers exactly one port (ADR-0141)"
    );
    metrics::counter!(tg_telemetry::names::PROXY_WRONG_PORT).increment(1);

    false
}

fn original_destination(client: &TcpStream) -> Option<SocketAddr> {
    let wanted = rustix::net::sockopt::ip_original_dst(client).ok()?;
    let local = client.local_addr().ok()?;

    (wanted.port() != local.port()).then_some(SocketAddr::V4(wanted))
}

pub async fn serve_outbound(
    config: Config,
    route: Route,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), SidecarError> {
    let tls = crate::tls::client_config(&config.identity, verifier(&config, Enforcement::Outbound))
        .map_err(|err| SidecarError::Tls {
            detail: err.to_string(),
        })?;
    let connector = TlsConnector::from(Arc::new(tls));

    // The SNI is **not** used for the verification (ADR-0006: the identity
    // stands in the URI SAN). `rustls` nevertheless demands a syntactically
    // valid name; the trust domain is the most honest placeholder -- it gives
    // away nothing the peer does not know anyway.
    let sni = rustls_pki_types::ServerName::try_from(route.peer.trust_domain().as_str().to_owned())
        .unwrap_or(rustls_pki_types::ServerName::IpAddress(
            std::net::Ipv4Addr::LOCALHOST.into(),
        ));

    accept_until(
        listener,
        shutdown,
        Listener::MeshOutbound,
        move |mut plain| {
            let connector = connector.clone();
            let config = config.clone();
            let route = route.clone();
            let sni = sni.clone();

            async move {
                // **No talking without an active role** (ADR-0066). Before
                // the handshake, because a standby is not to appear in the
                // first place.
                if !may_speak(&config, Direction::Outbound) {
                    return;
                }
                // With a deadline as inbound: a counterpart that does not
                // complete the setup would otherwise hold a task and a
                // descriptor.
                let Ok(Ok(tcp)) = tokio::time::timeout(
                    crate::HANDSHAKE_TIMEOUT,
                    TcpStream::connect(route.connect),
                )
                .await
                else {
                    tracing::warn!(peer = %route.connect, "the peer sidecar is not reachable");
                    return;
                };
                let Ok(Ok(mut tls)) =
                    tokio::time::timeout(crate::HANDSHAKE_TIMEOUT, connector.connect(sni, tcp))
                        .await
                else {
                    // The other side refused, and **it** knows why (`alert`
                    // there). Here stands whom it concerned.
                    tracing::warn!(peer = %route.connect, "the mTLS to the peer failed");
                    return;
                };

                let Some(peer) = peer_identity(tls.get_ref().1.peer_certificates()) else {
                    // As in the two other directions: reachable only if the
                    // verifier let the counterpart through without a
                    // credential.
                    tracing::warn!(
                        "a connection without a peer certificate is discarded -- the \
                         handshake should not have permitted it at all (ADR-0025)"
                    );
                    return;
                };

                let live = Established {
                    local: config.identity.id(),
                    peer,
                    direction: Direction::Outbound,
                    version_seen: config
                        .policy
                        .handle()
                        .read()
                        .map_or(0, |cache| cache.version()),
                    checked_at: now(),
                };
                until_fenced(&config, async {
                    let _ = pump(
                        &mut plain,
                        &mut tls,
                        config.policy.clone(),
                        live,
                        config.window.target,
                    )
                    .await;
                })
                .await;
            }
        },
    )
    .await;

    Ok(())
}

pub(crate) fn peer_identity(
    certificates: Option<&[rustls_pki_types::CertificateDer<'_>]>,
) -> Option<SpiffeId> {
    let leaf = certificates?.first()?;
    let certificate = spiffe::Certificate::try_from(leaf.as_ref()).ok()?;

    certificate.spiffe_id().ok()?.to_string().parse().ok()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::absorb;
    use crate::policy::{DenyReason, Direction, Established};

    #[tokio::test]
    async fn only_an_exhausted_listener_is_answered_with_a_pause() {
        // `EMFILE`. The number stands here instead of `rustix::io::Errno`:
        // the assertion is not to go the same way as the checked logic.
        let started = Instant::now();
        absorb(&std::io::Error::from_raw_os_error(24), "a test").await;
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "without a pause the loop spins: {:?}",
            started.elapsed()
        );

        let started = Instant::now();
        absorb(
            &std::io::Error::from(std::io::ErrorKind::ConnectionAborted),
            "a test",
        )
        .await;
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "a vanished connection must hold nobody up: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_shutdown_stops_accepting_and_waits_for_the_live_ones() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("the address");

        let (stop, wait) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(super::accept_until(
            listener,
            async move {
                let _ = wait.await;
            },
            super::Listener::Witness,
            |stream| async move {
                // Holds the connection until the client closes it.
                let mut stream = stream;
                let mut buf = [0_u8; 1];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            },
        ));

        // One running connection, and a moment so that it is accepted.
        let live = tokio::net::TcpStream::connect(addr).await.expect("connect");
        tokio::time::sleep(Duration::from_millis(200)).await;

        stop.send(()).expect("the signal");
        tokio::time::sleep(Duration::from_millis(200)).await;

        // **The first half**: no new connection any more. The listener is
        // gone, so the connecting already fails.
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "after the signal no new connection may be accepted any more"
        );

        // **The second half**: the running one is still there, so the
        // service is not back yet.
        assert!(
            !serving.is_finished(),
            "the service returned while a connection was still running -- it \
             would have been torn down"
        );

        // And as soon as it is closed, it returns.
        drop(live);
        let finished = tokio::time::timeout(Duration::from_secs(5), serving).await;
        assert!(
            finished.is_ok(),
            "the service did not come back although no connection was running any more"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_connection_already_waiting_is_not_accepted_after_the_signal() {
        async fn accepted(shutdown: impl std::future::Future<Output = ()> + Send) -> usize {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("the address");

            let waiting = tokio::net::TcpStream::connect(addr).await.expect("connect");
            // The kernel does the handshake; `accept` only fetches from the
            // finished queue. The moment gives it time for that.
            tokio::time::sleep(Duration::from_millis(20)).await;

            let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = std::sync::Arc::clone(&seen);
            super::accept_until(
                listener,
                shutdown,
                super::Listener::Witness,
                move |_stream| {
                    let counter = std::sync::Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                },
            )
            .await;

            drop(waiting);
            seen.load(std::sync::atomic::Ordering::SeqCst)
        }

        // **The assurance**: the signal is given, so nothing is accepted any
        // more -- in none of the twenty rounds.
        let mut after = 0;
        for _ in 0..20 {
            after += accepted(std::future::ready(())).await;
        }
        assert_eq!(
            after, 0,
            "after the signal something was still accepted -- the connection \
             then holds the drain up and dies with the container"
        );

        // **The counter direction**: without a signal very much so.
        let before = accepted(tokio::time::sleep(Duration::from_millis(300))).await;
        assert_eq!(
            before, 1,
            "without a signal the waiting connection must be accepted"
        );
    }
    #[tokio::test]
    async fn a_sidecar_reports_what_it_is_holding() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
        use tokio::io::AsyncReadExt as _;

        fn live(snapshotter: &Snapshotter) -> Option<f64> {
            snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .find_map(|(key, _, _, value)| {
                    let mine = key.key().name() == tg_telemetry::names::PROXY_CONNECTIONS
                        && key
                            .key()
                            .labels()
                            .any(|label| label.key() == "listener" && label.value() == "counted");
                    match value {
                        DebugValue::Gauge(seen) if mine => Some(seen.into_inner()),
                        _ => None,
                    }
                })
        }

        async fn wait_for(snapshotter: &Snapshotter, want: f64) -> Option<f64> {
            for _ in 0..200 {
                if let Some(seen) = live(snapshotter)
                    && (seen - want).abs() < f64::EPSILON
                {
                    return Some(seen);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            live(snapshotter)
        }

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let guard = metrics::set_default_local_recorder(&recorder);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("the address");
        let (stop, wait) = tokio::sync::oneshot::channel::<()>();

        let serving = tokio::spawn(super::accept_until(
            listener,
            async move {
                let _ = wait.await;
            },
            super::Listener::Counted,
            |mut stream| async move {
                // Holds the connection until the client closes it.
                let mut byte = [0_u8; 1];
                let _ = stream.read(&mut byte).await;
            },
        ));

        let first = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let second = tokio::net::TcpStream::connect(addr).await.expect("connect");

        assert_eq!(
            wait_for(&snapshotter, 2.0).await,
            Some(2.0),
            "two open connections must be reported as two"
        );

        drop(first);
        drop(second);
        assert_eq!(
            wait_for(&snapshotter, 0.0).await,
            Some(0.0),
            "after the end of both connections the gauge must come back"
        );

        let _ = stop.send(());
        let _ = serving.await;
        drop(guard);
    }

    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

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

    fn live() -> Established {
        Established {
            local: "spiffe://cluster.local/workload/api"
                .parse()
                .expect("its own identifier"),
            peer: "spiffe://cluster.local/workload/ledger"
                .parse()
                .expect("the counterpart's identifier"),
            direction: Direction::Outbound,
            version_seen: 7,
            checked_at: 1_700_000_000,
        }
    }

    fn torn_down(reason: DenyReason) -> (String, DenyReason) {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();

        let passed =
            tracing::subscriber::with_default(subscriber, || super::teardown(&live(), reason));

        (captured.text(), passed)
    }

    #[test]
    fn a_teardown_names_its_reason_and_both_parties() {
        let (text, _) = torn_down(DenyReason::NoEdge);

        assert!(text.contains("workload/api"), "{text}");
        assert!(text.contains("workload/ledger"), "{text}");
        assert!(text.contains("may_talk"), "the reason is missing: {text}");
        assert!(
            text.contains("Outbound"),
            "the direction is missing: {text}"
        );
    }

    #[test]
    fn the_reason_passes_through_unchanged() {
        for reason in [
            DenyReason::NoEdge,
            DenyReason::NotAWorkload,
            DenyReason::ForeignTrustDomain,
        ] {
            let (_, passed) = torn_down(reason);
            assert_eq!(passed, reason, "the reason was changed on the way");
        }
    }

    #[test]
    fn every_way_out_of_the_guard_goes_through_the_report() {
        let src = include_str!("sidecar.rs");

        // Cut the body of `guard` -- do not search the whole file: this
        // witness names `teardown` itself, and a text search over it would
        // find itself (the same false hit as with the determinism
        // tripwires).
        let at = src
            .find("async fn guard(")
            .expect("guard stands in this file");
        let open = src[at..].find('{').expect("a body") + at;
        let mut depth = 0;
        let mut end = open;
        for (offset, ch) in src[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &src[open..end];

        let ways: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("return ") && !line.starts_with("//"))
            .collect();

        assert!(
            ways.len() >= 2,
            "the body of `guard` was not read: {} return places",
            ways.len()
        );
        for way in &ways {
            assert!(
                way.contains("teardown("),
                "this return does not report the teardown: {way}"
            );
        }
    }
}

#[cfg(test)]
mod port_tests {
    use std::net::{TcpListener, TcpStream as StdStream};

    use super::wanted_us;

    fn accepted() -> (tokio::net::TcpStream, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the socket");
        let port = listener.local_addr().expect("the address").port();
        let client = StdStream::connect(("127.0.0.1", port)).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        server.set_nonblocking(true).expect("nonblocking");

        // The client stays alive as long as the test runs -- otherwise its
        // `drop` closes the connection, and `getsockopt` would have nothing to
        // read.
        std::mem::forget(client);

        (
            tokio::net::TcpStream::from_std(server).expect("the tokio socket"),
            port,
        )
    }

    #[tokio::test]
    async fn the_port_the_caller_wanted_is_the_one_we_serve() {
        let (stream, port) = accepted();

        assert!(
            wanted_us(&stream, port),
            "whoever dials the offered port must get through"
        );
    }

    #[tokio::test]
    async fn another_port_is_refused_and_counted() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let (stream, port) = accepted();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let (verdict, counted) = metrics::with_local_recorder(&recorder, || {
            let verdict = wanted_us(&stream, port.wrapping_add(1));
            let counted: Vec<u64> = snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .filter_map(|(key, _, _, value)| {
                    (key.key().name() == tg_telemetry::names::PROXY_WRONG_PORT).then_some(value)
                })
                .map(|value| match value {
                    DebugValue::Counter(seen) => seen,
                    other => panic!("no counter: {other:?}"),
                })
                .collect();

            (verdict, counted)
        });

        assert!(!verdict, "another port must not get through");
        assert_eq!(
            counted,
            vec![1],
            "the refusal must be counted -- otherwise it is not \
             distinguishable from a network problem"
        );
    }
}
