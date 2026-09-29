//! The way of a QUIC datagram to the sidecar (ADR-0094).
//!
//! Over TCP the sidecar fetches its original destination with
//! `SO_ORIGINAL_DST` from the kernel (ADR-0051). For **UDP** that is measured
//! not to exist, and neither do the obvious substitutes:
//!
//! | Way | Measured |
//! |---|---|
//! | `SO_ORIGINAL_DST` on a UDP socket | `ENOPROTOOPT` |
//! | `IP_RECVORIGDSTADDR` under `redirect to :port` | the address **after** the DNAT |
//! | `tproxy` in the output hook | `Operation not supported` |
//! | **`redirect` without a port setting** | **the port stays**, the address becomes local |
//!
//! So the last line: the redirection happens without a port setting, and the
//! sidecar listens on **the** port the container chose. What it takes from
//! that is only the port -- after the redirect the address is `127.0.0.1` and
//! would even without it be the one the container dialled, that is, precisely
//! the setting ADR-0041 does not want.
//!
//! # Why `nix`
//!
//! The destination stands in the **ancillary data** of a `recvmsg`, not in a
//! `getsockopt`. `rustix` does not know `IP_ORIGDSTADDR`; a cmsg parser of our
//! own would be this project's fourth `unsafe` block for something that exists
//! ready-made. `nix` lies in the tree over `rtnetlink` anyway.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn, recvmsg, setsockopt, sockopt};

use crate::quic::{Handshake, Peek};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub from: SocketAddr,
    pub port: u16,
    pub bytes: Vec<u8>,
}

pub const MAX_DATAGRAM: usize = 2_048;

const READ_BUFFER: usize = MAX_DATAGRAM + 1;

const ANCILLARY: usize = 128;

pub fn listener(port: u16) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
    setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &true)
        .map_err(|err| io::Error::from_raw_os_error(err as i32))?;
    // **Non-blocking**, because the loop runs in `tokio`: `AsyncFd` reports
    // readability, `recvmsg` fetches the datagram together with the ancillary
    // data. A blocking socket would hang the shard in the process
    // (ADR-0022).
    socket.set_nonblocking(true)?;

    Ok(socket)
}

pub fn receive(socket: &UdpSocket) -> io::Result<Datagram> {
    let mut buffer = vec![0_u8; READ_BUFFER];
    let mut ancillary = [0_u8; ANCILLARY];

    let (read, from, port) = {
        let mut slices = [io::IoSliceMut::new(&mut buffer)];
        let message = recvmsg::<SockaddrIn>(
            socket.as_raw_fd(),
            &mut slices,
            Some(&mut ancillary),
            MsgFlags::empty(),
        )
        .map_err(|err| io::Error::from_raw_os_error(err as i32))?;

        let from = message
            .address
            .map(|addr: SockaddrIn| SocketAddr::from(SocketAddrV4::new(addr.ip(), addr.port())))
            .ok_or_else(|| io::Error::other("the datagram names no sender"))?;

        let port = message
            .cmsgs()
            .map_err(|err| io::Error::from_raw_os_error(err as i32))?
            .find_map(|control| match control {
                ControlMessageOwned::Ipv4OrigDstAddr(addr) => Some(u16::from_be(addr.sin_port)),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::other(
                    "the kernel names no original destination -- without it there \
                     is no connection (ADR-0051)",
                )
            })?;

        (message.bytes, from, port)
    };

    // **Truncated means discarded** (ADR-0121, determination 2). The buffer
    // is one byte larger than the bound; whoever fills it was larger than
    // it.
    if read >= READ_BUFFER {
        return Err(io::Error::other(format!(
            "the datagram is larger than {MAX_DATAGRAM} bytes -- passing a \
             truncated one on would tear the connection apart (ADR-0121)"
        )));
    }

    buffer.truncate(read);

    Ok(Datagram {
        from,
        port,
        bytes: buffer,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Wait,
    Forward {
        host: String,
    },
    Established,
    Refuse(Refusal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotAllowed {
        host: String,
    },
    Anonymous,
    Unreadable(crate::quic::QuicError),
    TooMany,
}

impl Refusal {
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::NotAllowed { .. } => "not_allowed",
            Self::Anonymous => "anonymous",
            // **From the error, not from a second list** (ADR-0069):
            // whoever adds a cause comes past there and not here.
            Self::Unreadable(err) => err.label(),
            Self::TooMany => "too_many",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed { host } => write!(f, "{host} does not stand in the allowlist"),
            Self::Anonymous => f.write_str("a ClientHello without an SNI"),
            Self::Unreadable(err) => write!(f, "{err}"),
            Self::TooMany => f.write_str("too many open flows"),
        }
    }
}

pub const MAX_FLOWS: usize = 512;

pub const IDLE: std::time::Duration = std::time::Duration::from_mins(1);

pub const MAX_PENDING: usize = 8;

pub const MAX_PENDING_BYTES: usize = MAX_PENDING * MAX_DATAGRAM;

pub type Flow = (SocketAddr, u16);

#[derive(Debug)]
struct Session<T> {
    handshake: Handshake,
    decided: bool,
    seen: std::time::Instant,
    pending: Vec<Vec<u8>>,
    pending_bytes: usize,
    carried: Option<T>,
    _permit: Permit,
}

#[derive(Debug)]
pub struct Budget {
    open: std::sync::atomic::AtomicUsize,
    limit: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self::with_limit(MAX_FLOWS)
    }
}

impl Budget {
    #[must_use]
    pub const fn with_limit(limit: usize) -> Self {
        Self {
            open: std::sync::atomic::AtomicUsize::new(0),
            limit,
        }
    }

    #[must_use]
    pub fn open(&self) -> usize {
        self.open.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    fn take(self: &std::sync::Arc<Self>) -> Option<Permit> {
        let mut seen = self.open();
        loop {
            if seen >= self.limit {
                return None;
            }
            match self.open.compare_exchange_weak(
                seen,
                seen + 1,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(Permit {
                        budget: std::sync::Arc::clone(self),
                    });
                }
                Err(now) => seen = now,
            }
        }
    }
}

#[derive(Debug)]
struct Permit {
    budget: std::sync::Arc<Budget>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.budget
            .open
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub struct Flows<T> {
    open: std::collections::HashMap<Flow, Session<T>>,
    budget: std::sync::Arc<Budget>,
}

impl<T> Default for Flows<T> {
    fn default() -> Self {
        Self::sharing(std::sync::Arc::new(Budget::default()))
    }
}

impl<T> Flows<T> {
    #[must_use]
    pub fn sharing(budget: std::sync::Arc<Budget>) -> Self {
        Self {
            open: std::collections::HashMap::new(),
            budget,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    pub fn absorb(
        &mut self,
        flow: Flow,
        bytes: &[u8],
        now: std::time::Instant,
        permits: &dyn Fn(&str, u16) -> bool,
    ) -> Step {
        self.expire(now);

        // **One handle instead of two lookups** (ADR-0131). Previously a
        // second `get_mut` with an `else` branch stood behind the `if let`
        // that the code cannot reach -- and that nevertheless reported a
        // refusal. Since the refusal's label names its cause, that would be a
        // reason that does not exist.
        let session = match self.open.entry(flow) {
            std::collections::hash_map::Entry::Occupied(open) => {
                let session = open.into_mut();
                session.seen = now;
                if session.decided {
                    // A decided flow is not checked anew. The withdrawal
                    // runs over the guard, not over every datagram -- the same
                    // construction as with the TCP egress (ADR-0041).
                    return Step::Established;
                }
                session
            }
            std::collections::hash_map::Entry::Vacant(free) => {
                // **Clear first, then refuse.** A full stock of nothing but
                // dead flows must not cost a new one; `expire` above has
                // already emptied it.
                //
                // Counting happens in the **budget** and not in this map: the
                // bound applies to the sidecar, not to the listener
                // (ADR-0121, D4).
                let Some(permit) = self.budget.take() else {
                    return Step::Refuse(Refusal::TooMany);
                };
                free.insert(Session {
                    handshake: Handshake::new(),
                    decided: false,
                    seen: now,
                    pending: Vec::new(),
                    pending_bytes: 0,
                    carried: None,
                    _permit: permit,
                })
            }
        };

        match session.handshake.absorb(bytes) {
            Ok(Peek::Incomplete) => {
                // **Keep, do not discard** (ADR-0092, determination 4). The
                // bound is the same as in the reader: more fragments than a
                // `ClientHello` ever needs are no handshake any more -- and
                // since ADR-0121 **no more bytes** either than they may carry
                // together.
                if session.pending.len() < MAX_PENDING
                    && session.pending_bytes + bytes.len() <= MAX_PENDING_BYTES
                {
                    session.pending_bytes += bytes.len();
                    session.pending.push(bytes.to_vec());
                }
                Step::Wait
            }
            Ok(Peek::Named(host)) => {
                session.decided = true;
                session.pending_bytes += bytes.len();
                session.pending.push(bytes.to_vec());
                if permits(&host, flow.1) {
                    Step::Forward { host }
                } else {
                    self.open.remove(&flow);
                    Step::Refuse(Refusal::NotAllowed { host })
                }
            }
            Ok(Peek::Anonymous) => {
                self.open.remove(&flow);
                Step::Refuse(Refusal::Anonymous)
            }
            // **The reason travels along** (ADR-0131, determination 1).
            // Until here six distinguishable causes fell onto one `Malformed`
            // -- among them a connection migration and a version we do not
            // read. Both speak QUIC; the manual read the label as "no QUIC
            // client is speaking there".
            Err(err) => {
                self.open.remove(&flow);
                Step::Refuse(Refusal::Unreadable(err))
            }
        }
    }

    pub fn forget(&mut self, flow: &Flow) {
        self.open.remove(flow);
    }

    pub fn take_pending(&mut self, flow: &Flow) -> Vec<Vec<u8>> {
        self.open
            .get_mut(flow)
            .map(|session| {
                session.pending_bytes = 0;
                std::mem::take(&mut session.pending)
            })
            .unwrap_or_default()
    }

    pub fn carry(&mut self, flow: &Flow, value: T) {
        if let Some(session) = self.open.get_mut(flow) {
            session.carried = Some(value);
        }
    }

    #[must_use]
    pub fn carried(&self, flow: &Flow) -> Option<&T> {
        self.open.get(flow).and_then(|s| s.carried.as_ref())
    }

    pub fn expire(&mut self, now: std::time::Instant) {
        self.open
            .retain(|_, session| now.duration_since(session.seen) < IDLE);
    }
}

#[derive(Debug)]
struct Upstream {
    socket: std::sync::Arc<tokio::net::UdpSocket>,
    back: tokio::task::JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.back.abort();
    }
}

pub async fn serve(
    socket: UdpSocket,
    egress: crate::egress::SharedEgress,
    resolver: crate::egress::Resolver,
    budget: std::sync::Arc<Budget>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    let Ok(client) = tokio::io::unix::AsyncFd::with_interest(socket, tokio::io::Interest::READABLE)
    else {
        tracing::error!("the QUIC listener could not be hung into the runtime");
        return;
    };
    let client = std::sync::Arc::new(client);
    // **Shared with the other listeners** (ADR-0121, determination 4).
    let mut flows: Flows<Upstream> = Flows::sharing(budget);
    let mut shutdown = std::pin::pin!(shutdown);
    // **The broom gets a clock** (ADR-0130, determination 1). Without it only
    // `absorb` swept, that is, only on traffic -- and a listener that falls
    // silent held its places fast until the sidecar's restart, while another
    // port of the same workload got `TooMany`.
    //
    // The cadence comes from `IDLE` and is no second setting (determination
    // 2): a dead flow thereby holds its place for at most `IDLE * 1.5`.
    // `Delay`, because a missed tick has nothing to catch up on -- sweeping
    // happens against the clock, not against a number of passes.
    let mut sweep = tokio::time::interval(IDLE / 2);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let ready = tokio::select! {
            // **Fixed order** (ADR-0068), for the same reason as in
            // `sidecar::accept_until`: after the signal no datagram is to go
            // out any more. A relay has no drain that would catch it -- what
            // gets through here is a forwarding after the stop.
            //
            // Without a witness of its own: the property is substantiated at
            // `sidecar::accept_until`, where a backlog makes it producible
            // without privileges. Here it would need a socket with a datagram
            // in the buffer and an endpoint that receives it -- only the
            // privileged run has that setup.
            biased;

            () = &mut shutdown => return,
            // **Behind the signal** (ADR-0130, determination 3): after the
            // stop there is no more clearing away, only ending.
            _ = sweep.tick() => {
                flows.expire(std::time::Instant::now());
                continue;
            }
            ready = client.readable() => ready,
        };
        let Ok(mut guard) = ready else {
            tracing::error!("the QUIC listener is no longer readable");
            return;
        };

        let Ok(seen) = guard.try_io(|inner| receive(inner.get_ref())) else {
            continue;
        };
        let datagram = match seen {
            Ok(datagram) => datagram,
            Err(err) => {
                tracing::warn!(error = %err, "the QUIC datagram is not readable");
                continue;
            }
        };

        relay(&mut flows, &client, &egress, &resolver, datagram).await;
    }
}

async fn relay(
    flows: &mut Flows<Upstream>,
    client: &std::sync::Arc<tokio::io::unix::AsyncFd<UdpSocket>>,
    egress: &crate::egress::SharedEgress,
    resolver: &crate::egress::Resolver,
    datagram: Datagram,
) {
    let flow = (datagram.from, datagram.port);
    let step = flows.absorb(
        flow,
        &datagram.bytes,
        std::time::Instant::now(),
        &|host, port| egress.permits(host, port, crate::egress::Transport::Quic),
    );

    match step {
        // Kept, not discarded -- it goes out as soon as the destination is
        // settled (ADR-0092, determination 4).
        Step::Wait => {}
        Step::Forward { host } => {
            // **The first usable one** (ADR-0136, determination 3): a
            // `connect` on a UDP socket does not fail visibly, so there is
            // nothing by which a fallback would notice that nobody is there.
            // What the filter in the resolver achieves takes effect
            // nevertheless -- an AAAA falls away before it points into the
            // void.
            let Some(address) = resolver
                .resolve(&host, datagram.port)
                .await
                .first()
                .copied()
            else {
                tracing::warn!(%host, "the endpoint does not resolve");
                flows.forget(&flow);
                return;
            };
            match dial(client, flow, address).await {
                Ok(upstream) => {
                    let socket = std::sync::Arc::clone(&upstream.socket);
                    flows.carry(&flow, upstream);
                    for pending in flows.take_pending(&flow) {
                        let _ = socket.send(&pending).await;
                    }
                    tracing::info!(%host, %address, "QUIC out");
                }
                Err(err) => {
                    tracing::warn!(%host, %address, error = %err, "no way to the endpoint");
                    flows.forget(&flow);
                }
            }
        }
        Step::Established => {
            if let Some(upstream) = flows.carried(&flow) {
                let _ = upstream.socket.send(&datagram.bytes).await;
            }
        }
        Step::Refuse(reason) => {
            // **The reason stands in the log, not on the wire.** What the
            // container learns is silence -- saying more to it would mean
            // blurting out the allowlist to it (ADR-0041).
            //
            // And in a metric (ADR-0121, determination 6): for an operator
            // this silence is otherwise not distinguishable from a network
            // problem.
            metrics::counter!(
                tg_telemetry::names::QUIC_EGRESS_REFUSED,
                "reason" => reason.reason()
            )
            .increment(1);
            tracing::warn!(
                from = %datagram.from,
                port = datagram.port,
                // **In words** (ADR-0131, determination 2): `?reason` named
                // the variant's name, and the version we do not read thereby
                // stood nowhere.
                reason = %reason,
                "the QUIC datagram was not let out"
            );
        }
    }
}

async fn dial(
    client: &std::sync::Arc<tokio::io::unix::AsyncFd<UdpSocket>>,
    flow: Flow,
    address: SocketAddr,
) -> io::Result<Upstream> {
    let socket = tokio::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect(address).await?;
    let socket = std::sync::Arc::new(socket);

    let back = tokio::spawn({
        let upstream = std::sync::Arc::clone(&socket);
        let client = std::sync::Arc::clone(client);
        async move {
            let mut buffer = vec![0_u8; READ_BUFFER];
            while let Ok(read) = upstream.recv(&mut buffer).await {
                // **Truncated means stop** (ADR-0121, determination 2), in
                // this direction just the same: giving a cut-off datagram back
                // would tear the same connection apart, only from the other
                // side.
                if read >= READ_BUFFER {
                    tracing::warn!(
                        from = %flow.0,
                        port = flow.1,
                        "the endpoint sends more than {MAX_DATAGRAM} bytes -- the flow ends"
                    );
                    return;
                }

                // Back to the container -- from **the** socket it dialled.
                // A different sender would be a foreign packet for it, and
                // QUIC would discard it.
                let Ok(mut guard) = client.writable().await else {
                    return;
                };
                let sent = guard.try_io(|inner| inner.get_ref().send_to(&buffer[..read], flow.0));
                if matches!(sent, Ok(Err(_))) {
                    return;
                }
            }
        }
    });

    Ok(Upstream { socket, back })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjust {
    pub open: Vec<u16>,
    pub close: Vec<u16>,
}

#[must_use]
pub fn adjust(desired: &[u16], open: &[u16]) -> Adjust {
    let desired: std::collections::BTreeSet<u16> = desired.iter().copied().collect();
    let open: std::collections::BTreeSet<u16> = open.iter().copied().collect();

    Adjust {
        open: desired.difference(&open).copied().collect(),
        close: open.difference(&desired).copied().collect(),
    }
}

pub async fn supervise(
    egress: crate::egress::SharedEgress,
    resolver: crate::egress::Resolver,
    health: tg_telemetry::probes::Health,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    let mut versions = egress.subscribe();
    let mut open: std::collections::BTreeMap<u16, tokio::task::JoinHandle<()>> =
        std::collections::BTreeMap::new();
    let mut shutdown = std::pin::pin!(shutdown);

    // **One budget for all the listeners** (ADR-0121, determination 4). It
    // arises here and not per listener: the number of permitted ports is a
    // permission (ADR-0041) and decides nothing about memory.
    let budget = std::sync::Arc::new(Budget::default());

    // Registered instead of set (ADR-0088): the number changes only when a
    // flow arises or falls -- a sidecar without egress would never set it, and
    // it would expire after a quarter of an hour.
    health.on_scrape(tg_telemetry::names::QUIC_EGRESS_FLOWS, {
        let budget = std::sync::Arc::clone(&budget);
        move || {
            #[expect(
                clippy::cast_precision_loss,
                reason = "the number is bounded by MAX_FLOWS"
            )]
            metrics::gauge!(tg_telemetry::names::QUIC_EGRESS_FLOWS).set(budget.open() as f64);
        }
    });

    loop {
        let step = adjust(
            &egress.snapshot().quic_ports(),
            &open.keys().copied().collect::<Vec<_>>(),
        );

        for port in step.close {
            // **Aborted, not run out.** A port that is taken back is a
            // withdrawal; a datagram that is on its way at this moment is one
            // that is no longer to go out (ADR-0041).
            if let Some(task) = open.remove(&port) {
                task.abort();
                tracing::info!(port, "the QUIC listener is closed");
            }
        }

        for port in step.open {
            match listener(port) {
                Ok(socket) => {
                    let egress = egress.clone();
                    let resolver = resolver.clone();
                    let budget = std::sync::Arc::clone(&budget);
                    open.insert(
                        port,
                        tokio::spawn(async move {
                            serve(socket, egress, resolver, budget, std::future::pending()).await;
                        }),
                    );
                    tracing::info!(port, "the QUIC listener is open");
                }
                // **No listener, no egress** (determination 4) -- and the
                // case is named: a target that stands in the permission and is
                // nevertheless not reachable would otherwise be a riddle in
                // operation. It is repeated at the next state; a loop of its
                // own here would be a second cadence.
                Err(err) => {
                    tracing::error!(port, error = %err, "the QUIC listener cannot be opened");
                }
            }
        }

        tokio::select! {
            // **Fixed order** (ADR-0068). At shutdown both branches are
            // ready as soon as a state is still pending -- and then the
            // supervisor would open listeners it aborts immediately
            // afterwards.
            //
            // Without a witness of its own: the property is substantiated at
            // `sidecar::accept_until`, where a backlog makes it producible
            // without privileges. Here it would need a socket with a datagram
            // in the buffer and an endpoint that receives it -- only the
            // privileged run has that setup.
            biased;

            () = &mut shutdown => {
                for (_, task) in open {
                    task.abort();
                }
                return;
            }
            changed = versions.changed() => {
                if changed.is_err() {
                    // The sender is gone -- the sidecar is shutting down.
                    for (_, task) in open {
                        task.abort();
                    }
                    return;
                }
            }
        }
    }
}
