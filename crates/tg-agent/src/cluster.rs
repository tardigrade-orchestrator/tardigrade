//! The agent's credential on the node session (ADR-0043).
//!
//! ```text
//! <data-dir>/identity/node.key.pem        the node key (ADR-0037)
//! <data-dir>/identity/node.leaf.pem       its cluster leaf, created here
//! <data-dir>/identity/control-plane.pem   the leaves of the tgd nodes
//! ```
//!
//! # The key is the same one the join registered
//!
//! That is ADR-0043's whole trick: `AdmitNode { node, spki }` puts exactly this
//! public key into the log (ADR-0037), and the session checks it there. **No**
//! second identity arises, no second issuance, no deadline that can run out.
//!
//! # And the anchor for the counter-direction lies beside it
//!
//! The agent checks `tgd` likewise, and for that it needs its leaf. It cannot
//! come from the session — the session is what it is supposed to secure. So the
//! same hand that puts down the invitation puts it down (ADR-0043,
//! determination 3).
//!
//! **Without an anchor no session.** That is fail-closed and does not contradict
//! ADR-0019: there it is about existing, permitted work — the reconciler carries
//! on, the containers carry on. Here it is about the first entry into a trust
//! boundary, and a session that comes about without a check is worse than
//! none.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tg_identity::cluster::{NodeIdentity, NodeTrust, NodeVerifier};
use tg_identity::{SpiffeId, TrustDomain};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const KEEPALIVE: Duration =
    Duration::from_secs(tg_store::session::REPORT_EVERY_SECONDS.unsigned_abs());

use tg_identity::SNI;

const ANCHORS: &str = tg_identity::layout::CONTROL_PLANE;

#[derive(Debug, Clone)]
pub(crate) struct Cluster {
    identity: NodeIdentity,
    domain: TrustDomain,
    trust: NodeTrust,
}

impl Cluster {
    pub(crate) fn load(data_dir: &Path, domain: &str, node: &str) -> Result<Self, String> {
        let dir = crate::identity::dir(data_dir);
        let domain =
            TrustDomain::new(domain.to_owned()).map_err(|err| format!("trust domain: {err}"))?;

        let key_path = dir.join(tg_identity::layout::NODE_KEY);
        let text = std::fs::read_to_string(&key_path)
            .map_err(|err| format!("{}: {err}", key_path.display()))?;
        let key = rcgen::KeyPair::from_pem(text.trim())
            .map_err(|err| format!("{}: {err}", key_path.display()))?;

        let id = SpiffeId::for_node(&domain, node)
            .map_err(|err| format!("node name '{node}': {err}"))?;
        let identity = NodeIdentity::new(&key, id)?;

        // The own leaf lies beside the key so that an operator finds it: it
        // need not go to the tgd nodes -- the key already stands in the log there
        // --, but whoever wants to look at what the agent presents shall be able
        // to see it.
        let leaf_path = dir.join(tg_identity::layout::NODE_LEAF);
        let pem = tg_identity::cluster::node_leaf_pem(&key, identity.id())?;
        std::fs::write(&leaf_path, &pem)
            .map_err(|err| format!("{}: {err}", leaf_path.display()))?;

        let anchors = dir.join(ANCHORS);
        let trust = read_anchors(&anchors, &domain)?;

        Ok(Self {
            identity,
            domain,
            trust,
        })
    }

    pub(crate) fn anchors(&self) -> usize {
        self.trust.len()
    }

    pub(crate) fn channel(&self, endpoint: &str) -> Result<tonic::transport::Channel, String> {
        let config = tg_identity::cluster::client_config(&self.identity, self.verifier())
            .map_err(|err| err.to_string())?;

        // **Without a request deadline**, for a *stream* runs here (ADR-0040):
        // `Endpoint::timeout` would cut it off after expiry, and a slice comes
        // only when the log moves -- that may take hours. Against a **dead**
        // counterpart the keepalive helps instead.
        connect(endpoint, config, None)
    }

    pub(crate) fn open_channel(&self, endpoint: &str) -> Result<tonic::transport::Channel, String> {
        let config = tg_identity::cluster::verifying_client_config(self.verifier())
            .map_err(|err| err.to_string())?;

        // **With** a request deadline: these are unary calls (`Join`,
        // `Challenge`, `Renew`), and one that never answers would halt
        // `keep_fresh` forever -- after twelve hours the agent intermediate has
        // then expired, and **no** SVID of this node is accepted any more
        // (ADR-0014).
        connect(endpoint, config, Some(REQUEST_TIMEOUT))
    }

    fn verifier(&self) -> NodeVerifier {
        NodeVerifier::new(
            self.domain.clone(),
            tg_identity::cluster::shared(self.trust.clone()),
        )
    }
}

fn connect(
    endpoint: &str,
    config: rustls::ClientConfig,
    request: Option<Duration>,
) -> Result<tonic::transport::Channel, String> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut endpoint = tonic::transport::Endpoint::from_shared(endpoint.to_owned())
        .map_err(|err| format!("address: {err}"))?
        // **Keepalive on HTTP/2**, and that is the more important of the two
        // settings. A counterpart that disappears **without** sending a FIN -- a
        // partition, a node whose power is pulled -- otherwise holds the stream
        // open forever: TCP would give up only after its retransmissions, and
        // those are minutes. For that long this node gets no slice, and nobody
        // renews its active-role lease (ADR-0064).
        //
        // The numbers hang on the report cadence instead of being freely chosen:
        // one ping per report period, and it gives up after two. The detection
        // thereby lies in the same order of magnitude as the leader's report
        // window (ADR-0068).
        .http2_keep_alive_interval(KEEPALIVE)
        .keep_alive_timeout(KEEPALIVE * 2)
        // And a deadline for the establishment itself: TCP plus TLS. The same
        // number and the same reason as `tg_proxy::HANDSHAKE_TIMEOUT` -- a
        // counterpart that never completes the establishment would otherwise wait
        // forever.
        .connect_timeout(CONNECT_TIMEOUT);

    if let Some(request) = request {
        endpoint = endpoint.timeout(request);
    }

    Ok(
        endpoint.connect_with_connector_lazy(tower::service_fn(move |uri: http::Uri| {
            let connector = connector.clone();
            async move {
                let host = uri.host().unwrap_or("127.0.0.1").to_owned();
                let port = uri.port_u16().unwrap_or(80);
                let stream = tokio::net::TcpStream::connect((host, port)).await?;
                let name =
                    rustls_pki_types::ServerName::try_from(SNI).map_err(std::io::Error::other)?;
                let tls = connector.connect(name, stream).await?;

                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }
        })),
    )
}

fn read_anchors(path: &Path, domain: &TrustDomain) -> Result<NodeTrust, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("{}: {err} -- without an anchor no session", path.display()))?;

    tg_identity::cluster::anchors_from_pem(&text, domain)
        .map_err(|err| format!("{}: {err}", path.display()))
}

pub(crate) fn anchors_cover(endpoints: usize, anchors: usize) -> Option<usize> {
    endpoints
        .checked_sub(anchors)
        .filter(|missing| *missing > 0)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::anchors_cover;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_silent_peer_does_not_hold_the_agent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");
        // Accepted and **held**: a `drop` would send a FIN, and then it would be
        // an ordinary connection break instead of the silence that matters
        // here.
        let peer = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let config = || {
            let verifier = tg_identity::cluster::NodeVerifier::new(
                tg_identity::TrustDomain::new("cluster.local".to_owned()).expect("domain"),
                tg_identity::cluster::shared(tg_identity::cluster::NodeTrust::new()),
            );
            tg_identity::cluster::verifying_client_config(verifier).expect("material")
        };
        let endpoint = format!("http://{addr}");

        let credential = super::connect(&endpoint, config(), Some(super::REQUEST_TIMEOUT))
            .expect("credential channel");
        let session = super::connect(&endpoint, config(), None).expect("session channel");

        // The patience lies between the two barriers (10 s and 30 s): a run
        // that exhausts it thereby says "`CONNECT_TIMEOUT` did not take hold" and
        // not merely "it took a long time".
        let patience = Duration::from_secs(20);
        let started = Instant::now();
        let credential = tg_identity::control::IdentityClient::with_channel(credential);
        let session = tg_identity::control::IdentityClient::with_channel(session);
        let (credential, session) = tokio::join!(
            tokio::time::timeout(patience, credential.challenge("node-1")),
            tokio::time::timeout(patience, session.challenge("node-1")),
        );
        let elapsed = started.elapsed();
        peer.abort();

        for (role, outcome) in [("credential path", credential), ("session", session)] {
            let answered = outcome.unwrap_or_else(|_| {
                panic!(
                    "{role}: no answer after {elapsed:?} -- the deadline for \
                     establishing the connection did not take hold"
                )
            });
            assert!(answered.is_err(), "{role}: a silent counterpart answered");
        }
    }
    #[test]
    fn a_short_anchor_file_is_named() {
        assert_eq!(anchors_cover(3, 1), Some(2));
        assert_eq!(anchors_cover(5, 4), Some(1));
        // Covered, and more than covered.
        assert_eq!(anchors_cover(3, 3), None);
        assert_eq!(anchors_cover(3, 5), None);
        // Without endpoints there is nothing to cover.
        assert_eq!(anchors_cover(0, 0), None);
    }
}
