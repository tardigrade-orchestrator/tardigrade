//! UDP between two workloads -- over QUIC datagrams (ADR-0142).
//!
//! # Why this way exists
//!
//! ADR-0074 discards UDP between this cluster's workloads, and the rationale
//! there is no weighing-up but a property of the tool: *"DTLS does not exist
//! in `rustls`."* The only way out would have been to leave `<mesh>` out --
//! that is, to switch off precisely the enforcement for whose sake the mesh
//! exists.
//!
//! QUIC **is** authenticated UDP, and `send_datagram` (RFC 9221) carries
//! unreliably and unordered. That preserves the semantics a workload chose
//! when it took UDP -- unlike with a tunnel through the existing TCP channel,
//! which would have made head-of-line blocking out of loss.
//!
//! # Why `quinn` and not DTLS
//!
//! Measured (ADR-0142): `quinn` brings **11** new crates and runs on
//! **`rustls`**, `webrtc-dtls` brings **33** including a second crypto stack.
//! The first number does not decide -- the second property does: because
//! `quinn` runs on `rustls`, [`crate::verify::PeerVerifier`] is usable here
//! **unchanged**. The same SPIFFE check, the same `may_talk` edge, not one
//! line of authorization anew.
//!
//! # What the workload notices
//!
//! Nothing. It sends ordinary UDP datagrams to its peer; the sidecar receives
//! them in the namespace and carries them over. The same assurance as with TCP
//! (ADR-0007: *"transparent for foreign images"*).

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

use crate::identity::SharedIdentity;
use crate::verify::PeerVerifier;

pub const QUIC_DATAGRAM_OVERHEAD: usize = 38;

#[derive(Debug)]
pub enum DatagramError {
    Tls {
        detail: String,
    },
    Endpoint {
        detail: String,
    },
}

impl std::fmt::Display for DatagramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls { detail } => write!(f, "the QUIC TLS is not buildable: {detail}"),
            Self::Endpoint { detail } => write!(f, "the QUIC endpoint is not buildable: {detail}"),
        }
    }
}

impl std::error::Error for DatagramError {}

pub struct Endpoint {
    inner: quinn::Endpoint,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("local", &self.inner.local_addr().ok())
            .finish()
    }
}

impl Endpoint {
    pub fn bind(
        addr: SocketAddr,
        identity: &SharedIdentity,
        verifier: &PeerVerifier,
    ) -> Result<Self, DatagramError> {
        let server = crate::tls::server_config(identity, verifier.clone()).map_err(|err| {
            DatagramError::Tls {
                detail: err.to_string(),
            }
        })?;
        let client = crate::tls::client_config(identity, verifier.clone()).map_err(|err| {
            DatagramError::Tls {
                detail: err.to_string(),
            }
        })?;

        // **The conversion is the place at which QUIC demands TLS 1.3.** If
        // it fails, it is down to the protocol versions and not to our
        // verifier -- the message names both.
        let server = QuicServerConfig::try_from(server).map_err(|err| DatagramError::Tls {
            detail: format!("server: {err}"),
        })?;
        let client = QuicClientConfig::try_from(client).map_err(|err| DatagramError::Tls {
            detail: format!("client: {err}"),
        })?;

        let mut endpoint =
            quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(server)), addr)
                .map_err(|err| DatagramError::Endpoint {
                    detail: err.to_string(),
                })?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client)));

        Ok(Self { inner: endpoint })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, DatagramError> {
        self.inner
            .local_addr()
            .map_err(|err| DatagramError::Endpoint {
                detail: err.to_string(),
            })
    }

    pub async fn dial(&self, peer: SocketAddr, sni: &str) -> Result<Session, DatagramError> {
        let connecting = self
            .inner
            .connect(peer, sni)
            .map_err(|err| DatagramError::Endpoint {
                detail: err.to_string(),
            })?;

        Ok(Session {
            inner: connecting.await.map_err(|err| DatagramError::Endpoint {
                detail: err.to_string(),
            })?,
        })
    }

    pub async fn accept(&self) -> Option<Session> {
        loop {
            let incoming = self.inner.accept().await?;
            match incoming.await {
                Ok(inner) => return Some(Session { inner }),
                Err(err) => {
                    // **Reported and on.** A failed handshake is the normal
                    // case of deny-by-default (ADR-0025): the verifier has
                    // decided, and an endpoint that ended because of it would
                    // take the next peer's route away.
                    tracing::debug!(%err, "the QUIC handshake failed");
                }
            }
        }
    }

    pub async fn close(&self) {
        self.inner.close(0_u32.into(), b"shutdown");
        self.inner.wait_idle().await;
    }
}

pub struct Session {
    inner: quinn::Connection,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("peer", &self.inner.remote_address())
            .field("max_datagram", &self.inner.max_datagram_size())
            .finish()
    }
}

impl Session {
    #[must_use]
    pub fn peer(&self) -> Option<tg_identity::SpiffeId> {
        let identity = self.inner.peer_identity()?;
        let chain = identity
            .downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
            .ok()?;

        // **The same derivation as on the TCP side** -- two would be two
        // opportunities to read the same chain differently.
        crate::sidecar::peer_identity(Some(&chain))
    }

    #[must_use]
    pub fn max_datagram(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    pub fn send(&self, payload: Vec<u8>) -> Result<(), DatagramError> {
        self.inner
            .send_datagram(payload.into())
            .map_err(|err| DatagramError::Endpoint {
                detail: err.to_string(),
            })
    }

    pub async fn recv(&self) -> Result<Vec<u8>, DatagramError> {
        self.inner
            .read_datagram()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|err| DatagramError::Endpoint {
                detail: err.to_string(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub name: String,
    pub endpoint: SocketAddr,
    pub local: u16,
}

pub fn peers_from_text(text: &str, workload: &str) -> Result<Vec<Peer>, DatagramError> {
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let mut fields = line.split_whitespace();
        let (Some(owner), Some(name), Some(endpoint), Some(local), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(DatagramError::Endpoint {
                detail: format!(
                    "'{line}' is no peer line -- expected: \
                     <workload> <peer> <address>:<port> <local port>"
                ),
            });
        };

        // **A prefix is no name** (the finding from "The egress path,
        // wired"): `api-test` does not get what `api` is permitted.
        if owner != workload {
            continue;
        }

        let endpoint = endpoint
            .parse::<SocketAddr>()
            .map_err(|err| DatagramError::Endpoint {
                detail: format!("'{endpoint}' is no address: {err}"),
            })?;
        let local = local
            .parse::<u16>()
            .map_err(|err| DatagramError::Endpoint {
                detail: format!("'{local}' is no port: {err}"),
            })?;

        out.push(Peer {
            name: name.to_owned(),
            endpoint,
            local,
        });
    }

    // **Two lines onto the same local port are an error**, no overwrite:
    // which peer would win would be decided by the order in the file -- and a
    // datagram would go to the other one.
    let mut ports: Vec<u16> = out.iter().map(|peer| peer.local).collect();
    ports.sort_unstable();
    let before = ports.len();
    ports.dedup();
    if ports.len() != before {
        return Err(DatagramError::Endpoint {
            detail: "two peers share a local port -- then the order in the file \
                     would decide where a datagram goes"
                .to_owned(),
        });
    }

    Ok(out)
}

pub async fn relay(
    endpoint: std::sync::Arc<Endpoint>,
    peer: Peer,
    socket: tokio::net::UdpSocket,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    let mut shutdown = std::pin::pin!(shutdown);
    let mut session: Option<Session> = None;
    let mut buffer = vec![0_u8; 2048];

    loop {
        let read = tokio::select! {
            () = &mut shutdown => break,
            read = socket.recv_from(&mut buffer) => read,
        };

        let Ok((len, from)) = read else {
            // A socket that no longer reads is dead -- the caller restarts
            // the listener (ADR-0116).
            tracing::warn!(peer = %peer.name, "the UDP listener no longer reads");
            break;
        };

        // **The session only now**, and not at startup: a peer nobody talks
        // with thereby costs no handshake and no signature.
        if session.is_none() {
            // **The SNI is a placeholder** (as in [`crate::sidecar`]): the
            // identity stands in the URI SAN (ADR-0006), and
            // `verify_server_cert` expressly does not check the dialled name.
            // The trust domain is the most honest placeholder -- it gives away
            // nothing the peer does not know anyway.
            session = match endpoint
                .dial(peer.endpoint, tg_identity::DEFAULT_TRUST_DOMAIN)
                .await
            {
                Ok(open) => Some(open),
                Err(err) => {
                    // **Reported, not kept quiet.** What a container learns
                    // of a failed datagram is silence -- this line is the only
                    // information.
                    tracing::warn!(
                        peer = %peer.name,
                        endpoint = %peer.endpoint,
                        %err,
                        "the QUIC session to the peer did not come about"
                    );
                    continue;
                }
            };
        }

        let Some(open) = session.as_ref() else {
            continue;
        };

        if let Err(err) = open.send(buffer[..len].to_vec()) {
            tracing::warn!(peer = %peer.name, %err, "the datagram was not delivered");
            // **The session falls, the next datagram builds anew.** A
            // `datagram too large` is no reason for it -- but distinguishing
            // it from a dead peer would demand taking the error apart; a
            // rebuild costs one round trip and is the safer direction.
            session = None;
            continue;
        }

        // **The answer back to the sender.** A workload that sends a
        // datagram expects the answer on the same socket -- this loop holds
        // `from` for that.
        if let Some(open) = session.as_ref() {
            // **No answer is the normal case.** UDP is not
            // request-response; whoever waited here would make a ping-pong out
            // of a datagram stream -- hence the short deadline and no `else`
            // branch.
            if let Ok(Ok(answer)) =
                tokio::time::timeout(std::time::Duration::from_millis(100), open.recv()).await
                && let Err(err) = socket.send_to(&answer, from).await
            {
                tracing::warn!(peer = %peer.name, %err, "the answer is not deliverable");
            }
        }
    }
}
