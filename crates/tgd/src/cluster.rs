//! The cluster transports and their credential (ADR-0043).
//!
//! Three addresses instead of one, and the division is the decision:
//!
//! | Listener | Services | Client certificate | Anchor |
//! |---|---|---|---|
//! | `--listen` | admin, identity | no | -- |
//! | `--cluster-listen` | Raft | required | local peer list |
//! | `--node-listen` | node session | required | trust list from the log |
//!
//! A port with "client auth optional", on which every service looks for itself,
//! would have been cheaper -- and a service that forgets it would be open without
//! that standing out. The separation makes the forgetting impossible.
//!
//! # Why two anchors
//!
//! **Raft lies before consensus.** Its admission cannot come from it: a wrong
//! entry could otherwise be corrected only over the consensus it breaks. That is
//! verbatim the argument `tg_consensus::net::client` already makes for the
//! *address*.
//!
//! **The node session lies behind it.** It is answered only by the leader, and a
//! leader has a quorum -- so the trust list from the log is available, and the
//! revocation is a consensus action (`RevokeTrust`).

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tg_consensus::net::PeerDialer;
use tg_consensus::{NodeId, StateHandle};
use tg_identity::cluster::{NodeIdentity, NodeTrust, NodeVerifier, SharedTrust};
use tg_identity::{SpiffeId, TrustDomain};
use tokio::net::TcpListener;

const LEAF_FILE: &str = tg_identity::layout::NODE_LEAF;
const KEY_FILE: &str = tg_identity::layout::NODE_KEY;

#[derive(Debug)]
pub enum ClusterError {
    Io {
        path: PathBuf,
        detail: String,
    },
    Material {
        detail: String,
    },
}

impl std::fmt::Display for ClusterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, detail } => write!(f, "{}: {detail}", path.display()),
            Self::Material { detail } => write!(f, "cluster material: {detail}"),
        }
    }
}

impl std::error::Error for ClusterError {}

fn io(path: &Path) -> impl Fn(std::io::Error) -> ClusterError + '_ {
    move |err| ClusterError::Io {
        path: path.to_path_buf(),
        detail: err.to_string(),
    }
}

fn material(detail: impl Into<String>) -> ClusterError {
    ClusterError::Material {
        detail: detail.into(),
    }
}

pub fn node_key(data_dir: &Path) -> Result<rcgen::KeyPair, ClusterError> {
    let dir = tg_identity::layout::dir(data_dir);
    let path = dir.join(KEY_FILE);

    if let Ok(text) = std::fs::read_to_string(&path) {
        return rcgen::KeyPair::from_pem(text.trim())
            .map_err(|err| material(format!("the node key is unreadable: {err}")));
    }

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|err| material(format!("the node key cannot be created: {err}")))?;
    std::fs::create_dir_all(&dir).map_err(io(&dir))?;
    write_private(&path, &key.serialize_pem())?;

    Ok(key)
}

fn write_private(path: &Path, text: &str) -> Result<(), ClusterError> {
    std::fs::write(path, text).map_err(io(path))?;
    // A private key with world-read permissions is no private key.
    let mut perms = std::fs::metadata(path).map_err(io(path))?.permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
    std::fs::set_permissions(path, perms).map_err(io(path))
}

pub fn identity(
    data_dir: &Path,
    domain: &TrustDomain,
    node: &str,
) -> Result<NodeIdentity, ClusterError> {
    let key = node_key(data_dir)?;
    let id = SpiffeId::for_node(domain, node)
        .map_err(|err| material(format!("the node name '{node}' is unusable: {err}")))?;
    let identity = NodeIdentity::new(&key, id).map_err(material)?;

    // One data directory per node is a prerequisite: if two processes share one,
    // they overwrite this file for each other. It is only information -- the
    // credential itself arises in memory --, but whoever then copies it as the
    // anchor copies the wrong one.
    let path = tg_identity::layout::at(data_dir, LEAF_FILE);
    let pem = tg_identity::cluster::node_leaf_pem(&key, identity.id()).map_err(material)?;
    std::fs::write(&path, &pem).map_err(io(&path))?;

    Ok(identity)
}

#[derive(Debug, Clone, Default)]
pub struct Peers {
    names: BTreeMap<NodeId, String>,
    trust: NodeTrust,
}

impl Peers {
    #[must_use]
    pub fn load(data_dir: &Path, domain: &TrustDomain) -> (Self, Vec<String>) {
        let dir = tg_identity::layout::peers(data_dir);
        let mut peers = Self::default();
        let mut notes = Vec::new();

        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                notes.push(format!("{}: {err}", dir.display()));
                return (peers, notes);
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("pem") {
                continue;
            }
            let Some(id) = path
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .and_then(|stem| stem.parse::<NodeId>().ok())
            else {
                notes.push(format!(
                    "{}: the file name is no identifier",
                    path.display()
                ));
                continue;
            };
            match read_leaf(&path, domain) {
                Ok((name, spki)) => {
                    peers.names.insert(id, name.clone());
                    peers.trust.insert(&name, spki);
                }
                Err(detail) => notes.push(format!("{}: {detail}", path.display())),
            }
        }

        (peers, notes)
    }

    #[must_use]
    pub fn name(&self, id: NodeId) -> Option<&str> {
        self.names.get(&id).map(String::as_str)
    }

    #[must_use]
    pub fn trust(&self) -> &NodeTrust {
        &self.trust
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    #[must_use]
    pub fn without_leaf<I: IntoIterator<Item = NodeId>>(&self, ids: I, own: NodeId) -> Vec<NodeId> {
        ids.into_iter()
            .filter(|id| *id != own && !self.names.contains_key(id))
            .collect()
    }

    pub fn admit_self(&mut self, id: NodeId, identity: &NodeIdentity) {
        let Some(name) = identity.id().node() else {
            return;
        };
        if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(identity.leaf()) {
            self.names.insert(id, name.to_owned());
            self.trust.insert(name, parsed.public_key().raw.to_vec());
        }
    }
}

pub(crate) use tg_identity::cluster::read_leaf;

#[derive(Debug)]
pub struct TlsDialer {
    identity: NodeIdentity,
    domain: TrustDomain,
    peers: Peers,
    trust: SharedTrust,
}

impl TlsDialer {
    #[must_use]
    pub fn new(identity: NodeIdentity, domain: TrustDomain, peers: Peers) -> Self {
        let trust = tg_identity::cluster::shared(peers.trust().clone());
        Self {
            identity,
            domain,
            peers,
            trust,
        }
    }

    #[must_use]
    pub fn trust(&self) -> &SharedTrust {
        &self.trust
    }

    #[must_use]
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }
}

impl PeerDialer for TlsDialer {
    fn channel(&self, target: NodeId, addr: &str) -> Option<tonic::transport::Channel> {
        // Without a name no channel: the verifier needs it in order to check
        // that the one answering is the one dialled. A channel without this
        // binding would be one that accepts every admitted party -- that is,
        // precisely the misconfiguration that is meant to stand out.
        let name = self.peers.name(target)?;
        let verifier =
            NodeVerifier::new(self.domain.clone(), Arc::clone(&self.trust)).expecting(name);
        let config = tg_identity::cluster::client_config(&self.identity, verifier).ok()?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let endpoint = tonic::transport::Endpoint::from_shared(addr.to_owned()).ok()?;
        Some(
            endpoint.connect_with_connector_lazy(tower::service_fn(move |uri: http::Uri| {
                let connector = connector.clone();
                async move {
                    let host = uri.host().unwrap_or("127.0.0.1").to_owned();
                    let port = uri.port_u16().unwrap_or(80);
                    let stream = tokio::net::TcpStream::connect((host, port)).await?;

                    // The name is an address (ADR-0006) and is not checked --
                    // `rustls` demands one all the same, so a fixed one stands
                    // here. If it were meaningful here, the attacker could choose
                    // it.
                    let name = rustls_pki_types::ServerName::try_from(SNI)
                        .map_err(std::io::Error::other)?;
                    let tls = connector.connect(name, stream).await?;

                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
                }
            })),
        )
    }
}

pub(crate) use tg_identity::SNI;

pub fn accept(
    listener: TcpListener,
    config: rustls::ServerConfig,
) -> impl futures_util::Stream<
    Item = Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, Infallible>,
> {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    futures_util::stream::unfold((listener, acceptor), |(listener, acceptor)| async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => {
                    if let Some(pause) = tg_syscall::accept::classify(&error).pause() {
                        tracing::warn!(%error, "the cluster port does not accept -- it waits");
                        tokio::time::sleep(pause).await;
                    }
                    continue;
                }
            };
            match acceptor.clone().accept(stream).await {
                Ok(tls) => return Some((Ok(tls), (listener, acceptor))),
                Err(err) => {
                    // A failed handshake does **not** end the port. It is the
                    // normal case on an authenticated port: a port scanner, a node
                    // with old material, an operator with `curl`. Ending the
                    // listener on it would mean being able to halt the cluster
                    // with a `curl`.
                    tracing::debug!(%peer, %err, "handshake on the cluster port refused");
                }
            }
        }
    })
}

#[must_use]
pub fn session_trust(state: &StateHandle) -> (NodeTrust, Vec<String>) {
    registry(state, Registry::Nodes)
}

pub fn refresh_session_trust(
    raft: &openraft::Raft<tg_consensus::TypeConfig>,
    state: StateHandle,
    trust: SharedTrust,
) -> tokio::task::JoinHandle<()> {
    refresh_trust(raft, state, trust, Registry::Nodes)
}

#[derive(Debug, Clone, Copy)]
pub enum Registry {
    Nodes,
    Operators,
}

#[must_use]
pub fn registry(state: &StateHandle, which: Registry) -> (NodeTrust, Vec<String>) {
    let guard = state.read();
    let mut trust = NodeTrust::new();
    let mut notes = Vec::new();

    let entries: Vec<(&str, &str)> = match which {
        Registry::Nodes => guard.trusted().collect(),
        // The **classes** stay out here: the verifier checks the key, the gate
        // checks the class (ADR-0105, determination 1). Whoever took them along
        // here would need them at a place that makes no authorization decision.
        Registry::Operators => guard
            .operators()
            .map(|(name, spki, _)| (name, spki))
            .collect(),
    };

    for (name, spki) in entries {
        match NodeTrust::from_base64([(name, spki)]) {
            Ok(one) => {
                if let Some(bytes) = one.get(name) {
                    trust.insert(name, bytes.to_vec());
                }
            }
            Err(err) => notes.push(format!("'{name}': {err}")),
        }
    }

    (trust, notes)
}

pub fn refresh_trust(
    raft: &openraft::Raft<tg_consensus::TypeConfig>,
    state: StateHandle,
    trust: SharedTrust,
    which: Registry,
) -> tokio::task::JoinHandle<()> {
    let mut metrics = raft.metrics();

    tokio::spawn(async move {
        loop {
            // `borrow_and_update`, not `borrow`: the rationale stands in
            // `session.rs`. Measured it is **no** hot loop -- `changed()` marks
            // itself -- but the shape that carries with `has_changed()` too
            // (`tgd/tests/watch_marking.rs`).
            let seen = metrics.borrow_and_update().last_applied;
            let (fresh, notes) = registry(&state, which);
            for note in notes {
                tracing::warn!(%note, "trust list");
            }
            if let Ok(mut guard) = trust.write() {
                *guard = fresh;
            }
            let _ = seen;

            if metrics.changed().await.is_err() {
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::Peers;

    #[test]
    fn a_named_peer_without_a_leaf_is_named() {
        let mut peers = Peers::default();
        peers.names.insert(2, "tgd-2".to_owned());
        peers.names.insert(1, "tgd-1".to_owned());

        // Covered: our own identifier does not count.
        assert!(peers.without_leaf([1, 2], 1).is_empty());
        // And the shortfall is called by its name.
        assert_eq!(peers.without_leaf([1, 2, 5], 1), vec![5]);
        assert_eq!(peers.without_leaf([3, 4], 1), vec![3, 4]);
        // Our own identifier without a leaf is no gap: `admit_self` enters it,
        // and whoever dials themselves does it without a network.
        assert!(Peers::default().without_leaf([7], 7).is_empty());
    }
}
