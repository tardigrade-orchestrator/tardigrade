//! The resolver on the wire.
//!
//! A small pure-Rust DNS server, chosen for what counts here: **unmodified
//! foreign images speak normal DNS.** No sidecar knowledge, no library in the
//! workload, no environment variable — `getaddrinfo` and done.
//!
//! The resolution itself already stands in [`crate::discovery`] and is
//! checked there. This module brings it onto the wire and in doing so answers
//! the questions that exist only on the wire.
//!
//! # Per node, not central
//!
//! A central resolver would be a control-plane call in the hot path of every
//! connection — precisely the kind of dependency that would make workload
//! availability hang on reaching the control plane. The resolver therefore
//! runs on the node, on the bridge address, and answers what the node knows —
//! because of failure decoupling.
//!
//! # The SOA is no ornament
//!
//! Without an SOA record in the authority section the negative TTL has **no
//! effect**: per RFC 2308 a resolver takes the negative cache duration from
//! exactly this record. If it is missing, everyone sets their own number —
//! typically longer by orders of magnitude. A workload that legitimately asks
//! too early — a dependency may come up after its dependant asks for it —
//! would then stay blind for minutes.
//!
//! # What this server is not
//!
//! No general forwarder. For everything outside the zone comes `REFUSED` — a
//! resolver in the mesh that resolves arbitrary names is an open resolver. And
//! no cache: the answer comes from the registry, which lies in memory anyway.
//!
//! # The one exception
//!
//! Names that stand on the egress allowlist of a workload of this node are
//! forwarded. With that the allowlist is at the same time the forwarding list —
//! and what does not stand on it stays `REFUSED`. That is the difference between
//! an exception and an open resolver.
//!
//! What does **not** follow from it: DNS is no trust boundary for the
//! enforcement. That lies at the SNI — the kernel-level redirect catches every
//! address, no matter where the container got it from. The forwarding only
//! sees to it that a connection can come about at all.
//!
//! # Why the verdict and the forwarding are separate
//!
//! [`Resolver::respond`] stays a **pure function**: bytes in, verdict out. It
//! knows no network and no clock, and that is why the whole decision "who may go
//! out" is checkable without a socket. The forwarding itself is done by the loop
//! — see [`Verdict`].

use std::net::Ipv4Addr;
use std::sync::{Arc, PoisonError, RwLock};

use simple_dns::rdata::{A, RData, SOA};
use simple_dns::{
    CLASS, Name, OPCODE, Packet, PacketFlag, QCLASS, QTYPE, RCODE, ResourceRecord, TYPE,
};

use crate::discovery::{Answer, NEGATIVE_TTL_SECONDS, Registry, TTL_SECONDS};

pub const PORT: u16 = 53;

#[derive(Debug)]
pub enum Verdict {
    Reply(Vec<u8>),
    Forward,
    Silence,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forwarding {
    names: std::collections::BTreeSet<String>,
}

impl Forwarding {
    #[must_use]
    pub fn new<I: IntoIterator<Item = String>>(names: I) -> Self {
        Self {
            names: names
                .into_iter()
                .map(|name| normalise(&name))
                .filter(|name| !name.is_empty())
                .collect(),
        }
    }

    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn allows(&self, name: &str) -> bool {
        let name = normalise(name);
        self.names
            .iter()
            .any(|pattern| tg_model::egress::target_allows(pattern, &name))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }
}

fn normalise(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub const UDP_LIMIT: usize = 512;

pub const TCP_LIMIT: usize = u16::MAX as usize;

const SERIAL: u32 = 1;

#[derive(Debug)]
pub struct Resolver {
    registry: RwLock<Registry>,
    forwarding: RwLock<Forwarding>,
}

impl Resolver {
    #[must_use]
    pub fn new(registry: Registry) -> Self {
        Self {
            registry: RwLock::new(registry),
            forwarding: RwLock::new(Forwarding::none()),
        }
    }

    pub fn forward_to(&self, forwarding: Forwarding) {
        *self
            .forwarding
            .write()
            .unwrap_or_else(PoisonError::into_inner) = forwarding;
    }

    #[must_use]
    pub fn forwarded_names(&self) -> usize {
        self.forwarding
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    pub fn update(&self, registry: Registry) {
        *self
            .registry
            .write()
            .unwrap_or_else(PoisonError::into_inner) = registry;
    }

    #[must_use]
    pub fn respond(&self, query: &[u8], limit: usize) -> Verdict {
        let Ok(request) = Packet::parse(query) else {
            return silence();
        };

        // Answers are not answered.
        if request.has_flags(PacketFlag::RESPONSE) {
            return silence();
        }

        let id = request.id();
        let opcode = request.opcode();

        if opcode != OPCODE::StandardQuery {
            return counted("notimplemented", bare(id, opcode, RCODE::NotImplemented));
        }
        // Exactly one question. Everything else is either broken or a variant
        // this server does not know.
        if request.questions.len() != 1 {
            return counted("malformed", bare(id, opcode, RCODE::FormatError));
        }

        let question = &request.questions[0];
        if question.qclass != QCLASS::CLASS(CLASS::IN) {
            return counted("refused", bare(id, opcode, RCODE::Refused));
        }

        let name = question.qname.to_string();
        let registry = self.registry.read().unwrap_or_else(PoisonError::into_inner);
        let zone = registry.domain().as_str().to_owned();
        let resolved = registry.resolve(&name);
        drop(registry);

        // A is answered; everything else about a name that exists is NODATA. An
        // NXDOMAIN on AAAA would make a client not even issue the A query.
        let wants_a = matches!(question.qtype, QTYPE::TYPE(TYPE::A));

        let mut reply = Packet::new_reply(id);
        reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
        reply.questions.push(question.clone());

        // How it was answered — for the metric below. It stands here and not at
        // the caller: `Verdict::Reply` carries finished bytes, and reading the
        // response code back out of them would be a second reader for a format
        // with one writer.
        let outcome;
        match resolved {
            Answer::Addresses(addresses) if wants_a => {
                outcome = "noerror";
                for address in addresses {
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        CLASS::IN,
                        TTL_SECONDS,
                        RData::A(A {
                            address: u32::from(address),
                        }),
                    ));
                }
            }
            // The name exists, only not in this shape.
            Answer::Addresses(_) | Answer::NoData => {
                outcome = "nodata";
                push_soa(&mut reply, &zone);
            }
            Answer::NxDomain => {
                outcome = "nxdomain";
                *reply.rcode_mut() = RCODE::NameError;
                push_soa(&mut reply, &zone);
            }
            // Outside the zone. Exactly here the forwarding exception bites:
            // if the name stands on the allowlist, the query goes out —
            // otherwise it stays refused.
            Answer::Refused => {
                let allowed = self
                    .forwarding
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .allows(&name);
                if allowed {
                    answered("forwarded");
                    return Verdict::Forward;
                }
                outcome = "refused";
                *reply.rcode_mut() = RCODE::Refused;
            }
        }

        counted(outcome, fit(&reply, limit, id, opcode))
    }
}

fn counted(outcome: &'static str, reply: Vec<u8>) -> Verdict {
    answered(outcome);
    Verdict::Reply(reply)
}

fn silence() -> Verdict {
    answered("dropped");
    Verdict::Silence
}

fn answered(outcome: &'static str) {
    metrics::counter!(tg_telemetry::names::DNS_ANSWERS, "outcome" => outcome).increment(1);
}

fn push_soa(reply: &mut Packet<'_>, zone: &str) {
    let (Ok(origin), Ok(mname), Ok(rname)) = (
        Name::new(zone).map(Name::into_owned),
        Name::new(&format!("ns.{zone}")).map(Name::into_owned),
        Name::new(&format!("hostmaster.{zone}")).map(Name::into_owned),
    ) else {
        // A zone that is no DNS name cannot exist — `Domain` checks that at
        // construction. Answering without an SOA is still better than not
        // answering at all.
        return;
    };

    reply.name_servers.push(ResourceRecord::new(
        origin,
        CLASS::IN,
        NEGATIVE_TTL_SECONDS,
        RData::SOA(SOA {
            mname,
            rname,
            serial: SERIAL,
            // Refresh, retry and expire have a meaning only with zone
            // transfers. They stand here at values no tool objects to, and
            // otherwise mean nothing.
            refresh: 3600,
            retry: 600,
            expire: 86_400,
            // That is the number at issue: the negative TTL a resolver
            // caches NXDOMAIN/NODATA answers for.
            minimum: NEGATIVE_TTL_SECONDS,
        }),
    ));
}

fn bare(id: u16, opcode: OPCODE, rcode: RCODE) -> Vec<u8> {
    let mut reply = Packet::new_reply(id);
    *reply.opcode_mut() = opcode;
    *reply.rcode_mut() = rcode;

    reply.build_bytes_vec().unwrap_or_else(|_| {
        // Twelve bytes of header without sections can always be built; the
        // branch is unreachable. A panic would nevertheless be wrong here: it is
        // an assertion about foreign code.
        Vec::new()
    })
}

fn fit(reply: &Packet<'_>, limit: usize, id: u16, opcode: OPCODE) -> Vec<u8> {
    if let Ok(bytes) = reply.build_bytes_vec_compressed()
        && bytes.len() <= limit
    {
        return bytes;
    }

    let mut short = Packet::new_reply(id);
    short.set_flags(PacketFlag::AUTHORITATIVE_ANSWER | PacketFlag::TRUNCATION);
    *short.rcode_mut() = reply.rcode();
    for question in &reply.questions {
        short.questions.push(question.clone());
    }

    short
        .build_bytes_vec()
        .unwrap_or_else(|_| bare(id, opcode, RCODE::ServerFailure))
}

pub async fn serve_udp(
    resolver: Arc<Resolver>,
    socket: Arc<tokio::net::UdpSocket>,
    upstream: Option<std::net::SocketAddr>,
) -> std::convert::Infallible {
    let mut buffer = vec![0_u8; UDP_LIMIT];

    loop {
        let (len, from) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) => {
                if let Some(pause) = tg_syscall::accept::classify(&error).pause() {
                    tracing::warn!(%error, "resolver (UDP) does not receive — waiting");
                    tokio::time::sleep(pause).await;
                }
                continue;
            }
        };
        let answer = match resolver.respond(&buffer[..len], UDP_LIMIT) {
            Verdict::Reply(bytes) => Some(bytes),
            Verdict::Forward => forward(&buffer[..len], upstream, UDP_LIMIT).await,
            Verdict::Silence => None,
        };

        if let Some(answer) = answer {
            // A failed send does not end the service: the asker may already be
            // gone, and the next one is waiting.
            let _ = socket.send_to(&answer, from).await;
        }
    }
}

const FORWARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

async fn forward(
    query: &[u8],
    upstream: Option<std::net::SocketAddr>,
    limit: usize,
) -> Option<Vec<u8>> {
    let upstream = upstream?;
    let bind: std::net::SocketAddr = if upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };

    let socket = match tokio::net::UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(err) => {
            tracing::warn!(%upstream, error = %err, "forwarding: no socket");
            return None;
        }
    };
    if let Err(err) = socket.send_to(query, upstream).await {
        tracing::warn!(%upstream, error = %err, "forwarding: not sendable");
        return None;
    }

    let mut buffer = vec![0_u8; TCP_LIMIT.min(65_535)];
    // **The classic three-in-the-morning case, and it was mute.** If the
    // upstream does not answer, the asker gets silence — its workload hangs on
    // DNS, and nothing says on what. The cause lies with the operator
    // (`--dns-forward`), not with the container.
    let received = match tokio::time::timeout(FORWARD_TIMEOUT, socket.recv_from(&mut buffer)).await
    {
        Err(_) => {
            tracing::warn!(%upstream, "forwarding: the upstream does not answer");
            return None;
        }
        Ok(Err(err)) => {
            tracing::warn!(%upstream, error = %err, "forwarding: receive failed");
            return None;
        }
        Ok(Ok(received)) => received,
    };
    let (len, from) = received;

    // Only the one called may answer. Without this check it would suffice to
    // guess the source port — and that is the only unknown.
    //
    // **Reported**, for an answer from a foreign address is no operational
    // coincidence: either somebody is aiming at the cache, or the network
    // configuration is wrong. Discarded silently, both look like a timeout.
    if from != upstream {
        tracing::warn!(
            %upstream,
            %from,
            "forwarding: answer from a foreign address discarded"
        );
        return None;
    }

    buffer.truncate(len);

    // Too large for the way on which the client asks: then the TC bit and
    // nothing further. It asks again over TCP, where the limit is a different
    // one. Simply truncating the answer would be a broken packet.
    if buffer.len() > limit {
        let parsed = Packet::parse(&buffer).ok()?;
        return Some(fit(&parsed, limit, parsed.id(), parsed.opcode()));
    }

    Some(buffer)
}

pub async fn serve_tcp(
    resolver: Arc<Resolver>,
    listener: Arc<tokio::net::TcpListener>,
    upstream: Option<std::net::SocketAddr>,
) -> std::convert::Infallible {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                if let Some(pause) = tg_syscall::accept::classify(&error).pause() {
                    tracing::warn!(%error, "resolver (TCP) does not accept — waiting");
                    tokio::time::sleep(pause).await;
                }
                continue;
            }
        };
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            let _ = serve_one_tcp(&resolver, stream, upstream).await;
        });
    }
}

async fn serve_one_tcp(
    resolver: &Resolver,
    mut stream: tokio::net::TcpStream,
    upstream: Option<std::net::SocketAddr>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    loop {
        // Two bytes of length, then the message (RFC 1035, 4.2.2).
        let mut prefix = [0_u8; 2];
        if stream.read_exact(&mut prefix).await.is_err() {
            return Ok(());
        }
        let len = usize::from(u16::from_be_bytes(prefix));

        let mut message = vec![0_u8; len];
        stream.read_exact(&mut message).await?;

        let answer = match resolver.respond(&message, TCP_LIMIT) {
            Verdict::Reply(bytes) => bytes,
            // Asked over TCP, forwarded over UDP: the upstream speaks both, and
            // the answer fits here anyway.
            Verdict::Forward => match forward(&message, upstream, TCP_LIMIT).await {
                Some(bytes) => bytes,
                None => return Ok(()),
            },
            Verdict::Silence => return Ok(()),
        };
        let Ok(length) = u16::try_from(answer.len()) else {
            return Ok(());
        };

        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&answer).await?;
    }
}

#[must_use]
pub fn address(subnet: &crate::ipam::NodeSubnet) -> (Ipv4Addr, u16) {
    (subnet.gateway(), PORT)
}
