//! The client side: `RaftNetwork` and `RaftNetworkFactory` over gRPC.

use std::collections::BTreeMap;
use std::fmt;

use openraft::BasicNode;
use openraft::error::{RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use tonic::transport::Channel;

use crate::config::{NodeId, TypeConfig};
use crate::net::codec::JsonCodec;
use crate::net::{APPEND_ENTRIES, INSTALL_SNAPSHOT, VOTE};

/// The addresses of the peer nodes.
///
/// Kept separate from `openraft`'s membership and **not** derived from it:
/// `BasicNode` does carry an address field, but the way to a node is an
/// operational setting of the local process, not a replicated truth. Whoever
/// mixes the two can correct a wrong address only over consensus — that is,
/// exactly not when it breaks it.
#[derive(Debug, Clone, Default)]
pub struct PeerAddrs(BTreeMap<NodeId, String>);

impl PeerAddrs {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enters an address (`http://host:port`).
    #[must_use]
    pub fn with(mut self, id: NodeId, addr: impl Into<String>) -> Self {
        self.0.insert(id, addr.into());
        self
    }

    /// A node's address.
    #[must_use]
    pub fn get(&self, id: NodeId) -> Option<&str> {
        self.0.get(&id).map(String::as_str)
    }

    /// Which of the named identifiers have **no** address, excluding its own.
    ///
    /// # Why its own does not count
    ///
    /// A node does not dial itself. Demanding its address in its own `--peer`
    /// would mean forcing a setting that has no effect.
    ///
    /// # Why this stands here and not at the callers
    ///
    /// **Two** ask: the precondition of a membership change
    /// (`tgd::admin::unreachable`) and the running check whether the own list
    /// covers the voters (`tgd::health`). Two versions would be two
    /// opportunities to interpret it differently — and the one says "refused",
    /// the other "reported".
    #[must_use]
    pub fn missing<I: IntoIterator<Item = NodeId>>(&self, ids: I, own: NodeId) -> Vec<NodeId> {
        ids.into_iter()
            .filter(|id| *id != own && !self.0.contains_key(id))
            .collect()
    }

    /// All entries, sorted by identifier.
    #[must_use]
    pub fn entries(&self) -> Vec<(NodeId, &str)> {
        self.0
            .iter()
            .map(|(id, addr)| (*id, addr.as_str()))
            .collect()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An error on the way to the peer node.
///
/// It is reported to `openraft` as [`Unreachable`] — not as a network error
/// with an immediate retry. The difference is a backoff: a node that is just
/// restarting shall not be called in a loop.
#[derive(Debug)]
struct Unreached {
    target: NodeId,
    detail: String,
}

impl fmt::Display for Unreached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node {} is unreachable: {}", self.target, self.detail)
    }
}

impl std::error::Error for Unreached {}

/// Who builds the endpoint to a peer node.
///
/// The seam for mTLS (ADR-0043). `tg-consensus` knows neither `rustls` nor
/// SPIFFE — it knows `tonic`, and a finished `Endpoint` is all it needs. Who
/// presents the credential and whom it expects is decided by `tgd`: identity
/// and registration lie there, and that is where the decision belongs.
/// Otherwise the consensus core would hang on the identity layer in order to
/// open a connection — the same layering question `tg_identity::control`
/// answers for the join path.
pub trait PeerDialer: Send + Sync + fmt::Debug + 'static {
    /// The channel to this node, or `None` if there is none.
    ///
    /// The channel is built **lazily**: per `openraft`'s trait documentation
    /// `new_client` must not connect and must not report an error. In practice
    /// it is what makes a cluster without a start order possible — every node
    /// may be there first.
    ///
    /// `None` is no error: the node is then unreachable, and the cluster
    /// carries on with the rest (ADR-0031).
    fn channel(&self, target: NodeId, addr: &str) -> Option<Channel>;
}

/// A node's network factory.
#[derive(Debug, Clone)]
pub struct GrpcNetwork {
    peers: PeerAddrs,
    dialer: std::sync::Arc<dyn PeerDialer>,
}

impl GrpcNetwork {
    /// A factory that gets its endpoints from this dialer.
    ///
    /// **There is no plaintext default**, and that is ADR-0043's promise: the
    /// Raft port demands a client certificate, so there is no way to build a
    /// factory without a credential. Measured, the plaintext dialer was a
    /// **chain of dead links** — `Node::start` → `start_with(None)` →
    /// `GrpcNetwork::new` → `PlainDialer`, and the first had zero callers. Its
    /// head claimed the test rig needed it; that one drives an in-process bus
    /// (ADR-0032) and no `tonic`.
    #[must_use]
    pub fn with_dialer(peers: PeerAddrs, dialer: std::sync::Arc<dyn PeerDialer>) -> Self {
        Self { peers, dialer }
    }
}

impl RaftNetworkFactory<TypeConfig> for GrpcNetwork {
    type Network = Link;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        let channel = self
            .peers
            .get(target)
            .and_then(|addr| self.dialer.channel(target, addr));

        Link { target, channel }
    }
}

/// A connection to exactly one peer node.
#[derive(Debug, Clone)]
pub struct Link {
    target: NodeId,
    /// `None` if no usable address is entered for this node. That is no reason
    /// to crash: the node is then simply unreachable, and the cluster carries on
    /// with the rest (ADR-0031).
    channel: Option<Channel>,
}

/// The call as a label — **three** values, so permitted per the cardinality
/// rule (`tg_telemetry::names`).
fn rpc_label(path: &'static str) -> &'static str {
    match path {
        APPEND_ENTRIES => "append_entries",
        VOTE => "vote",
        INSTALL_SNAPSHOT => "install_snapshot",
        // A fourth path would be a programming error, not an operational case.
        _ => "unknown",
    }
}

impl Link {
    /// The peer node's identifier as a label.
    ///
    /// **The identifier and not the address**: it is bounded by the cluster
    /// size (ADR-0031), an address would not be — and the cardinality rule
    /// forbids exactly that.
    fn peer_label(&self) -> String {
        self.target.to_string()
    }

    fn unreachable<E: std::error::Error + 'static>(
        &self,
        detail: impl Into<String>,
    ) -> RPCError<NodeId, BasicNode, E> {
        RPCError::Unreachable(Unreachable::new(&Unreached {
            target: self.target,
            detail: detail.into(),
        }))
    }

    /// A unary call over the JSON codec.
    async fn call<Req, Resp, E>(
        &self,
        path: &'static str,
        request: Req,
    ) -> Result<Resp, RPCError<NodeId, BasicNode, E>>
    where
        Req: serde::Serialize + Send + Sync + 'static,
        Resp: serde::de::DeserializeOwned + Send + Sync + 'static,
        E: std::error::Error + 'static,
    {
        let Some(channel) = self.channel.clone() else {
            return Err(self.unreachable("no address entered"));
        };

        // **The round-trip time is measured** (ADR-0033, delegated to
        // ADR-0015). `openraft` uses `heartbeat_interval` at the same time as
        // this call's deadline — a slower path never replicates, and quietly at
        // that. Here is the only place all three calls pass by.
        let started = std::time::Instant::now();
        let outcome = self.attempt(path, request, channel).await;

        let peer = self.peer_label();
        let rpc = rpc_label(path);
        match &outcome {
            // Only the **successful** call carries a round-trip time. A failed
            // one carries the deadline, and that would be no measurement of the
            // path but one of patience.
            Ok(_) => metrics::histogram!(
                tg_telemetry::names::RAFT_RPC_SECONDS,
                "peer" => peer,
                "rpc" => rpc
            )
            .record(started.elapsed().as_secs_f64()),
            Err(_) => metrics::counter!(
                tg_telemetry::names::RAFT_RPC_FAILURES,
                "peer" => peer,
                "rpc" => rpc
            )
            .increment(1),
        }

        outcome
    }

    /// The call itself, without measurement.
    async fn attempt<Req, Resp, E>(
        &self,
        path: &'static str,
        request: Req,
        channel: Channel,
    ) -> Result<Resp, RPCError<NodeId, BasicNode, E>>
    where
        Req: serde::Serialize + Send + Sync + 'static,
        Resp: serde::de::DeserializeOwned + Send + Sync + 'static,
        E: std::error::Error + 'static,
    {
        let mut client = tg_wire::client(channel);
        client
            .ready()
            .await
            .map_err(|err| self.unreachable(err.to_string()))?;

        let path = http::uri::PathAndQuery::from_static(path);
        let codec: JsonCodec<Req, Resp> = JsonCodec::default();

        client
            .unary(tonic::Request::new(request), path, codec)
            .await
            .map(tonic::Response::into_inner)
            // Every status is reported as "unreachable", a substantive one
            // too. That is deliberately coarse: `openraft`'s error channel
            // distinguishes here only between "try again" and "the peer node
            // answered substantively" — and an answer we could not read is no
            // substantive one.
            .map_err(|status| self.unreachable(status.to_string()))
    }
}

impl RaftNetwork<TypeConfig> for Link {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.call(APPEND_ENTRIES, rpc).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.call(VOTE, rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, openraft::error::InstallSnapshotError>>,
    > {
        self.call(INSTALL_SNAPSHOT, rpc).await
    }
}
