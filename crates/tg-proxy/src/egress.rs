//! Egress: traffic out of the mesh (ADR-0041).
//!
//! ADR-0025 governs who talks with whom in the mesh. Here stands the other
//! direction, and it has the same attitude: **deny-by-default**.
//!
//! # The hinge: the name comes from the connection
//!
//! The sidecar reads the SNI from the `ClientHello`, checks it against the
//! allowlist, **resolves it itself and dials it**. That is what makes the name
//! trustworthy although the client writes it: a lie brings the liar precisely
//! where they were allowed to go anyway.
//!
//! The alternatives are rejected in ADR-0041 and the reason stands there: an
//! address list is right on the day it is created and not afterwards, and a
//! DNS-fed firewall puts the trust boundary in the wrong place -- whoever
//! influences the DNS answer would write into the firewall.
//!
//! # There is **no** termination
//!
//! After the reading the bytes are spliced. No interception key on the node,
//! and the certificate check against the endpoint's CA stays with the workload
//! as ADR-0027 demands. The price stands in the ADR: contents are not
//! checkable. That is at the same time the virtue -- there is nothing to
//! steal.
//!
//! # Why no TLS parser of our own stands here
//!
//! The `ClientHello` comes from a container: a trust boundary. `rustls` can
//! read it without continuing the handshake, and `rustls` is there anyway
//! (invariant 3). A hand-written parser would be the kind of code one writes
//! wrong once and never notices.

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peek {
    Named(String),
    Anonymous,
    NotTls,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    NoName,
    NotAllowed {
        host: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Forward {
        host: String,
        port: u16,
    },
    Deny {
        reason: DenyReason,
    },
    NeedMore,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    allowed: BTreeSet<(String, u16, Transport)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Transport {
    #[default]
    Tcp,
    Quic,
    Udp,
}

impl Transport {
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "tcp" => Some(Self::Tcp),
            "quic" => Some(Self::Quic),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
            Self::Udp => "udp",
        })
    }
}

pub type Permission = (String, u16, Transport);

pub fn without_listen_port(
    entries: impl IntoIterator<Item = Permission>,
    listen: u16,
) -> (Vec<Permission>, Vec<Permission>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();

    for entry in entries {
        if entry.1 == listen {
            dropped.push(entry);
        } else {
            kept.push(entry);
        }
    }

    (kept, dropped)
}

impl EgressPolicy {
    #[must_use]
    pub fn from_entries(entries: impl IntoIterator<Item = Permission>) -> Self {
        Self {
            allowed: entries
                .into_iter()
                .map(|(host, port, transport)| (host.to_ascii_lowercase(), port, transport))
                .collect(),
        }
    }

    #[must_use]
    pub fn permits(&self, host: &str, port: u16, transport: Transport) -> bool {
        self.allowed
            .iter()
            .any(|(pattern, allowed_port, allowed_transport)| {
                *allowed_port == port
                    && *allowed_transport == transport
                    && tg_model::egress::target_allows(pattern, host)
            })
    }

    #[must_use]
    pub fn quic_ports(&self) -> Vec<u16> {
        let mut out: Vec<u16> = self
            .allowed
            .iter()
            .filter(|(_, _, transport)| *transport == Transport::Quic)
            .map(|(_, port, _)| *port)
            .collect();
        // **Sort before deduplicating.** The set is ordered by the *name*,
        // so two permissions onto the same port do not stand beside each other
        // -- and `dedup` removes only what follows on.
        out.sort_unstable();
        out.dedup();

        out
    }

    #[must_use]
    pub fn hosts(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self
            .allowed
            .iter()
            .map(|(host, _, _)| host.as_str())
            .collect();
        out.dedup();
        out
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

#[must_use]
pub fn peek(bytes: &[u8]) -> Peek {
    if bytes.is_empty() {
        return Peek::Incomplete;
    }

    // The first byte of a TLS record is the handshake type 0x16. That is no
    // check but a shortcut: it distinguishes "no TLS" from "not yet enough",
    // which `rustls` alone does not do.
    if bytes[0] != 0x16 {
        return Peek::NotTls;
    }

    let mut acceptor = rustls::server::Acceptor::default();
    let mut cursor = std::io::Cursor::new(bytes);

    // `read_tls` takes what is there. An incomplete record is no error --
    // then `Ok(None)` comes out of `accept`.
    while cursor.position() < bytes.len() as u64 {
        if acceptor.read_tls(&mut cursor).is_err() {
            return Peek::NotTls;
        }
    }

    match acceptor.accept() {
        Ok(Some(accepted)) => match accepted.client_hello().server_name() {
            Some(name) => Peek::Named(name.to_owned()),
            None => Peek::Anonymous,
        },
        Ok(None) => Peek::Incomplete,
        Err(_) => Peek::NotTls,
    }
}

#[must_use]
pub fn decide(policy: &EgressPolicy, bytes: &[u8], port: u16) -> Decision {
    match peek(bytes) {
        Peek::Named(host) => {
            // Over TCP the name comes from the TLS `ClientHello`; the QUIC
            // path has its own reader (`crate::quic`) and its own decision.
            if policy.permits(&host, port, Transport::Tcp) {
                Decision::Forward { host, port }
            } else {
                Decision::Deny {
                    reason: DenyReason::NotAllowed { host },
                }
            }
        }
        // Without a name no permission (ADR-0041, determination 5). Whoever
        // cannot name themselves must let themselves be numbered -- and that
        // is a visible line of its own in the allowlist, no quiet exception
        // here.
        Peek::Anonymous | Peek::NotTls => Decision::Deny {
            reason: DenyReason::NoName,
        },
        Peek::Incomplete => Decision::NeedMore,
    }
}

// =============================================================== the path

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::policy::RevocationWindow;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

pub const HELLO_LIMIT: usize = 16 * 1024;

#[derive(Clone)]
pub enum Resolver {
    System,
    Pinned(Arc<BTreeMap<String, SocketAddr>>),
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => f.write_str("Resolver::System"),
            Self::Pinned(map) => write!(f, "Resolver::Pinned({} entries)", map.len()),
        }
    }
}

impl Resolver {
    pub async fn resolve(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        let found: Vec<SocketAddr> = match self {
            Self::System => tokio::net::lookup_host((host, port))
                .await
                .map(Iterator::collect)
                .unwrap_or_default(),
            Self::Pinned(map) => map
                .get(&host.to_ascii_lowercase())
                .copied()
                .into_iter()
                .collect(),
        };

        // **What has no route falls away before it costs anything**
        // (ADR-0136, determination 2): as long as the overlay is IPv4
        // (ADR-0012), an AAAA is no choice but a deadline with a known
        // outcome.
        //
        // The filter sits **here** and not at the dialler: TCP and QUIC both
        // go through it, and two filters would be two opportunities to filter
        // differently (ADR-0069).
        let usable: Vec<SocketAddr> = found.iter().copied().filter(SocketAddr::is_ipv4).collect();

        let dropped = found.len() - usable.len();
        if dropped > 0 {
            metrics::counter!(tg_telemetry::names::EGRESS_UNROUTABLE).increment(dropped as u64);
            tracing::info!(
                %host,
                dropped,
                "addresses without a route in the namespace are discarded (IPv6, ADR-0012)"
            );
        }

        usable
    }
}

pub async fn dial_any(addresses: &[SocketAddr]) -> Option<TcpStream> {
    for address in addresses {
        match tokio::time::timeout(crate::HANDSHAKE_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Some(stream),
            Ok(Err(err)) => {
                tracing::debug!(%address, error = %err, "the endpoint is not reachable");
            }
            Err(_) => {
                tracing::debug!(%address, "the endpoint does not answer within the deadline");
            }
        }
        metrics::counter!(tg_telemetry::names::EGRESS_ATTEMPTS_FAILED).increment(1);
    }
    None
}

pub async fn serve(
    listener: TcpListener,
    policy: SharedEgress,
    resolver: Resolver,
    window: crate::policy::RevocationWindow,
    role: Option<crate::role::Gate>,
    shutdown: impl Future<Output = ()> + Send,
) {
    crate::sidecar::accept_until(
        listener,
        shutdown,
        crate::sidecar::Listener::Egress,
        move |stream| {
            let policy = policy.clone();
            let role = role.clone();
            let resolver = resolver.clone();

            async move {
                // **Without an active role nothing goes out either**
                // (ADR-0066).
                //
                // The mesh alone does not suffice: per ADR-0027 a workload's
                // shared mutable state lies in **external S3**, and the way
                // there is precisely this port. A fenced writer that were cut
                // only in the mesh would carry on writing where it hurts.
                //
                // **This line saves work, it is not the assurance.** Measured:
                // removing it makes no test red, because `guarded` below
                // encloses the whole relay and aborts immediately when the
                // role is missing. What it spares is a task, a resolution and
                // a connection attempt -- and it says in the log why. The
                // assurance is carried by the guard, and that one has a
                // witness of its own
                // (`losing_the_active_role_tears_down_a_live_egress_connection`).
                if role
                    .as_ref()
                    .is_some_and(|gate| !gate.is_active(crate::role::now_millis()))
                {
                    tracing::warn!("no egress without an active role (ADR-0010, ADR-0066)");
                    return;
                }
                // **The snapshot falls at the connection setup**, and for
                // two reasons: the decision falls there too (ADR-0041), and a
                // `std` lock must never be held across an `await`. The list is
                // a handful of entries; the clone costs nothing against a TLS
                // handshake (ADR-0022).
                let shared = policy.clone();
                let policy = policy.snapshot();
                let resolver = resolver.clone();

                // A failure concerns one connection, not the service. And it
                // is **not** reported back to the container: what it is to
                // learn is that the connection is closed.
                crate::role::guarded(role.as_ref(), async {
                    let _ = relay(stream, &policy, &resolver, &shared, window).await;
                })
                .await;
            }
        },
    )
    .await;
}

fn original_port(client: &TcpStream) -> Option<u16> {
    rustix::net::sockopt::ip_original_dst(client)
        .ok()
        .map(|address| address.port())
}

async fn relay(
    mut client: TcpStream,
    policy: &EgressPolicy,
    resolver: &Resolver,
    shared: &SharedEgress,
    window: crate::policy::RevocationWindow,
) -> std::io::Result<()> {
    // **Before the first byte**: what the container wanted stands in the
    // conntrack and not in the data stream. Without this setting there is no
    // decision (ADR-0051, determination 3).
    let Some(wanted) = original_port(&client) else {
        return Ok(());
    };

    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 2048];

    // **The `ClientHello` has a deadline** (`HANDSHAKE_TIMEOUT`). The byte
    // bound [`HELLO_LIMIT`] alone does not suffice: whoever sends one byte per
    // minute stays below it and holds a task and a descriptor arbitrarily
    // long. Measured at the incoming side it was a hundred out of a hundred.
    //
    // The block gives `None` where it previously gave `Ok(())`: "no name" and
    // "refused" are the same result here -- the connection is closed, and the
    // container learns nothing about it (ADR-0041).
    let named = tokio::time::timeout(crate::HANDSHAKE_TIMEOUT, async {
        loop {
            let verdict = decide(policy, &buffer, wanted);
            // Counting happens at the **place of effect**, not in `decide`:
            // the decision function is pure and is called from tests and the
            // fuzz run too. A metric there would count test runs along.
            metrics::counter!(
                tg_telemetry::names::PROXY_DECISIONS,
                "direction" => "egress",
                "outcome" => if matches!(verdict, Decision::Forward { .. }) { "allow" } else { "deny" },
            )
            .increment(1);

            match verdict {
                Decision::Forward { host, port } => break Some((host, port)),
                Decision::Deny { .. } => return None,
                Decision::NeedMore => {}
            }

            if buffer.len() >= HELLO_LIMIT {
                return None;
            }

            let Ok(read) = client.read(&mut chunk).await else {
                return None;
            };
            if read == 0 {
                // The container stopped before it named itself.
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
    })
    .await;

    // Without a name within the deadline there is nothing to decide. The
    // container learns what it is to learn anyway: the connection is
    // closed.
    let Ok(Some((host, port))) = named else {
        return Ok(());
    };

    let addresses = resolver.resolve(&host, port).await;
    if addresses.is_empty() {
        tracing::warn!(%host, "the endpoint does not resolve");
        return Ok(());
    }

    // **In turn, until one stands** (ADR-0136, determination 1). One attempt
    // onto the **first** address stood here -- and an endpoint with several A
    // records, that is, the construction with which an operator catches
    // outages, was closed as soon as the first one was dead.
    //
    // The deadline applies per attempt: an endpoint that does not complete the
    // setup would otherwise hold a task and a descriptor.
    let Some(mut upstream) = dial_any(&addresses).await else {
        tracing::warn!(
            %host,
            attempts = addresses.len(),
            "no address of the endpoint answers"
        );
        return Ok(());
    };

    // The bytes that were read go out **unchanged**. They were never more
    // than looked at; the handshake runs between the workload and the
    // endpoint, against the latter's CA (ADR-0027).
    upstream.write_all(&buffer).await?;
    upstream.flush().await?;

    // **The splice races against the guard** (ADR-0041: the same window as
    // ADR-0025). Without it the egress decided **once**, at the connection
    // setup -- a withdrawal took effect only for new connections, and with a
    // long-lived stream "withdrawn" meant nothing at all.
    tokio::select! {
        outcome = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {
            outcome.map(|_| ())
        }
        () = revoked(shared, &host, port, Transport::Tcp, window) => Ok(()),
    }
}

async fn revoked(
    shared: &SharedEgress,
    host: &str,
    port: u16,
    transport: Transport,
    window: RevocationWindow,
) {
    let mut versions = shared.subscribe();

    loop {
        if !shared.permits(host, port, transport) {
            return;
        }

        tokio::select! {
            () = tokio::time::sleep(window.target) => {}
            changed = versions.changed() => {
                if changed.is_err() {
                    // Nobody refreshes any more. The last known state
                    // applies on (ADR-0019, fail-static) -- checking carries
                    // on against it, at the window's rhythm.
                    tokio::time::sleep(window.target).await;
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct SharedEgress {
    inner: Arc<std::sync::RwLock<EgressPolicy>>,
    version: tokio::sync::watch::Sender<u64>,
    refreshed_at: Arc<std::sync::atomic::AtomicI64>,
}

impl SharedEgress {
    #[must_use]
    pub fn new(policy: EgressPolicy) -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(policy)),
            version: tokio::sync::watch::Sender::new(0),
            refreshed_at: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        }
    }

    #[must_use]
    pub fn refreshed_at(&self) -> crate::policy::UnixSeconds {
        self.refreshed_at.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.version.subscribe()
    }

    #[must_use]
    pub fn permits(&self, host: &str, port: u16, transport: Transport) -> bool {
        // A poisoned lock means **not permitted**: deny-by-default is the
        // safe direction (ADR-0041), and a permission out of a broken state
        // would be the unsafe one.
        self.inner
            .read()
            .is_ok_and(|policy| policy.permits(host, port, transport))
    }

    #[must_use]
    pub fn snapshot(&self) -> EgressPolicy {
        self.inner
            .read()
            .map_or_else(|_| EgressPolicy::from_entries([]), |inner| inner.clone())
    }

    pub fn replace(&self, policy: EgressPolicy, at: crate::policy::UnixSeconds) {
        if let Ok(mut inner) = self.inner.write() {
            *inner = policy;
        }
        self.refreshed_at
            .store(at, std::sync::atomic::Ordering::Relaxed);
        // **After** the write: a guard the strike wakes is to find the new
        // state and not the old one.
        self.version.send_modify(|version| *version += 1);
    }
}

#[must_use]
pub fn refresh(
    egress: &SharedEgress,
    path: &std::path::Path,
    workload: &str,
    listen: u16,
    at: crate::policy::UnixSeconds,
) -> crate::policy::Refresh {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            return crate::policy::Refresh::Unreadable {
                detail: err.to_string(),
            };
        }
    };

    let entries = match crate::options::egress_from_text(&text, workload) {
        Ok(entries) => entries,
        Err(err) => {
            return crate::policy::Refresh::Malformed {
                detail: err.to_string(),
            };
        }
    };

    let (entries, dropped) = without_listen_port(entries, listen);
    for (host, port, transport) in dropped {
        tracing::warn!(
            %host,
            port,
            %transport,
            "the egress permission onto the own port is discarded -- it would \
             be the bypass of the redirect (ADR-0051)"
        );
    }

    egress.replace(EgressPolicy::from_entries(entries), at);

    crate::policy::Refresh::Applied
}

pub fn report(egress: &SharedEgress, at: crate::policy::UnixSeconds) {
    let _ = at;

    #[expect(
        clippy::cast_precision_loss,
        reason = "a Prometheus metric is an f64; it would become imprecise \
                  beyond 2^53 seconds"
    )]
    let refreshed_at = egress.refreshed_at() as f64;
    metrics::gauge!(tg_telemetry::names::PROXY_EGRESS_REFRESHED_AT).set(refreshed_at);
}
