//! The admin service: the server that serves the protocol from `tg-admin`.
//!
//! **Not** the API from ADR-0018. That one is secured with SPIFFE mTLS, dogfoods
//! the identity and has a surface that is still to be discussed. What is served
//! here are two calls: one that writes, and one that says where the cluster
//! stands.
//!
//! They stand here because the phase's acceptance criterion -- "leader kill ->
//! refailover **without data loss in the desired state**" -- would otherwise not be
//! checkable: one must be able to write something in and look afterwards.
//!
//! # What no longer stands here
//!
//! **Protocol and client lie in `tg-admin`** (ADR-0134). They lay here, and
//! `tgctl` therefore linked the whole consensus core -- measured 369 crates against
//! 311 at `tgd`, `openraft` and `redb` included. The re-export below holds the
//! paths this crate knows them under; it is no second source.
//!
//! What stays here is what makes the **server**: the access rules that interrogate
//! an incoming request, the statements that arise from Raft and projection, and the
//! branches themselves.

use std::convert::Infallible;
use std::task::{Context, Poll};

use openraft::Raft;
use tg_consensus::net::JsonCodec;
use tg_consensus::{Actor, Class, Command, NodeId, StateHandle, Submission, TypeConfig};
use tg_defs::DependencyKind;
use tg_store::Projection;
use tonic::body::Body;
use tonic::codegen::{BoxFuture, Service};
use tonic::server::NamedService;
use tonic::{Request, Response, Status};

pub use tg_admin::*;

#[must_use]
pub fn actor_of(extensions: &http::Extensions) -> Option<Actor> {
    if let Some(name) = peer_operator(extensions) {
        return Some(Actor::Operator(name));
    }
    extensions
        .get::<PeerCredentials>()
        .map(|peer| Actor::LocalUid(peer.uid))
}

#[must_use]
pub fn peer_operator(extensions: &http::Extensions) -> Option<String> {
    let info = extensions
        .get::<tonic::transport::server::TlsConnectInfo<tonic::transport::server::TcpConnectInfo>>(
        )?;

    operator_of(info.peer_certs()?.first()?)
}

#[must_use]
pub fn operator_of(leaf: &rustls_pki_types::CertificateDer<'_>) -> Option<String> {
    tg_identity::cluster::spiffe_id_of(leaf)
        .ok()?
        .named(tg_identity::Role::Operator)
        .map(str::to_owned)
}

#[must_use]
pub fn admitted(extensions: &http::Extensions) -> bool {
    if peer_operator(extensions).is_some() {
        return true;
    }
    extensions
        .get::<PeerCredentials>()
        .is_some_and(may_administer)
}

#[must_use]
pub fn class_of(path: &str) -> Option<Class> {
    match path {
        STATUS | PROJECTION | LINTS | DOCUMENT | SETTINGS | SECRETS | TRUST | VOLUMES
        | OPERATORS | SIGNER => Some(Class::Read),
        REKEY_MATERIAL | REFRESH_GROUP => Some(Class::Secrets),
        WRITE => Some(Class::Write),
        MEMBERSHIP => Some(Class::Membership),
        _ => None,
    }
}

#[must_use]
pub fn may(held: Option<&[Class]>, needed: Class) -> bool {
    match held {
        None => true,
        Some(classes) => classes.contains(&needed),
    }
}

#[must_use]
pub fn held(enrolled: Option<Vec<Class>>) -> Vec<Class> {
    enrolled.unwrap_or_default()
}

#[must_use]
pub fn may_administer(credentials: &PeerCredentials) -> bool {
    credentials.uid == 0 || credentials.uid == nix_uid()
}

fn nix_uid() -> u32 {
    // `getuid` is infallible and needs no `unsafe`: `rustix` encapsulates it.
    rustix::process::getuid().as_raw()
}
#[must_use]
pub fn unreachable(
    change: &MembershipChange,
    peers: &tg_consensus::net::PeerAddrs,
    own: NodeId,
) -> Option<String> {
    let named = match change {
        MembershipChange::AddLearner { id, .. } => vec![*id],
        MembershipChange::SetVoters { ids, .. } => ids.clone(),
    };
    // **The rule lies at the addresses**, not here: the running check in
    // `crate::health` asks the same question (ADR-0005).
    let missing = peers.missing(named, own);

    if missing.is_empty() {
        return None;
    }

    let listed: Vec<String> = missing.iter().map(u64::to_string).collect();
    Some(format!(
        "no address for node {} -- it belongs in this process's `--peer` \
         (ADR-0005: the address is an operational setting, no replicated \
         truth). Without it the leader cannot replicate.",
        listed.join(", ")
    ))
}

#[must_use]
pub fn reaching(
    metrics: &openraft::RaftMetrics<NodeId, openraft::BasicNode>,
    own: NodeId,
) -> Vec<NodeId> {
    let mut ids: Vec<NodeId> = std::iter::once(own)
        .chain(
            metrics
                .replication
                .as_ref()
                .into_iter()
                .flat_map(|map| map.iter().filter_map(|(peer, at)| at.map(|_| *peer))),
        )
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}
fn lints_of(state: &StateHandle) -> Vec<String> {
    let applied = state.read();
    let mut workloads = Vec::new();
    for entry in applied.workloads() {
        let Ok(set) = tg_defs::from_str(entry.document()) else {
            continue;
        };
        workloads.extend(set.workloads().iter().cloned());
    }

    tg_model::DependencyGraph::from_workloads(&workloads)
        .map(|graph| graph.lints().iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

fn notes_for(state: &StateHandle, registry: &str) -> Vec<String> {
    let pullers = state.read().pullers_of(registry);
    if pullers.is_empty() {
        return Vec::new();
    }

    vec![format!(
        "{} pulls anonymously from '{}' from now on: {}",
        if pullers.len() == 1 {
            "one workload"
        } else {
            "several workloads"
        },
        registry.to_ascii_lowercase(),
        pullers.join(", ")
    )]
}

fn amounts(resources: &tg_model::Resources) -> Vec<(String, u64)> {
    resources
        .entries()
        .into_iter()
        .map(|(name, amount)| (name.to_owned(), amount))
        .collect()
}

#[derive(Clone)]
pub struct AdminService {
    id: NodeId,
    raft: Raft<TypeConfig>,
    state: StateHandle,
    projection: std::sync::Arc<Projection>,
    peers: tg_consensus::net::PeerAddrs,
    group: Option<GroupState>,
}

#[derive(Clone)]
pub struct GroupState {
    pub signer: std::sync::Arc<tg_identity::threshold::ThresholdSigner>,
    pub seat: u16,
    pub admitted: usize,
}

impl AdminService {
    fn classes_of(&self, operator: &str) -> Vec<Class> {
        held(
            self.state
                .read()
                .operators()
                .find(|(name, _, _)| *name == operator)
                .map(|(_, _, classes)| classes.to_vec()),
        )
    }

    #[must_use]
    pub fn new(
        id: NodeId,
        raft: Raft<TypeConfig>,
        state: StateHandle,
        projection: std::sync::Arc<Projection>,
        peers: tg_consensus::net::PeerAddrs,
        group: Option<GroupState>,
    ) -> Self {
        Self {
            id,
            raft,
            state,
            projection,
            peers,
            group,
        }
    }
}

impl From<&crate::Group> for GroupState {
    fn from(group: &crate::Group) -> Self {
        Self {
            signer: std::sync::Arc::clone(&group.signer),
            seat: {
                use tg_identity::threshold::SignerLink as _;

                group.seat.seat().number()
            },
            admitted: group.seats.len(),
        }
    }
}

impl std::fmt::Debug for AdminService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminService")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl AdminService {
    fn gate<B>(&self, request: &http::Request<B>) -> Option<http::Response<Body>> {
        // **One** gate for all four calls. The check here and not in the four
        // services behind it: one that forgets it would be open without that
        // standing out (ADR-0044, determination 3 -- reading does not become easier
        // than writing).
        //
        // If the credentials are missing entirely, it is refused. On the admin
        // socket that can happen only when it is run without `incoming` -- and then
        // the refusal is right.
        if !admitted(request.extensions()) {
            let (parts, ()) =
                Status::permission_denied("the admin socket is reserved for this node's operator")
                    .into_http::<()>()
                    .into_parts();

            return Some(http::Response::from_parts(parts, Body::empty()));
        }

        // **And the class** (ADR-0105, determination 1). At the same gate and for
        // the same reason: one check per service would be one somebody forgets.
        //
        // `None` is the socket and holds everything (determination 4). For an
        // operator the registration is read -- **every time**, so that a revocation
        // and a changed class take effect on the next request and not only on the
        // next connection.
        let held = peer_operator(request.extensions()).map(|name| self.classes_of(&name));
        if let Some(classes) = &held {
            let path = request.uri().path().to_owned();
            let ok = class_of(&path).is_some_and(|needed| may(Some(classes), needed));
            if !ok {
                let (parts, ()) = Status::permission_denied(format!(
                    "this credential does not have the class for it (ADR-0105); \
                     it holds: {}",
                    held.unwrap_or_default()
                        .iter()
                        .map(|class| class.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
                .into_http::<()>()
                .into_parts();

                return Some(http::Response::from_parts(parts, Body::empty()));
            }
        }

        None
    }
}

impl NamedService for AdminService {
    const NAME: &'static str = ADMIN_SERVICE;
}

impl<B> Service<http::Request<B>> for AdminService
where
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        if let Some(refused) = self.gate(&request) {
            return Box::pin(async move { Ok(refused) });
        }

        let this = self.clone();

        match request.uri().path() {
            WRITE => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<WriteResult, Command>::default());
                Ok(grpc.unary(WriteSvc { inner: this }, request).await)
            }),
            STATUS => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<StatusResponse, StatusRequest>::default());
                Ok(grpc.unary(StatusSvc { inner: this }, request).await)
            }),
            MEMBERSHIP => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<MembershipResult, MembershipChange>::default());
                Ok(grpc.unary(MembershipSvc { inner: this }, request).await)
            }),
            LINTS => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<LintsResponse, LintsRequest>::default());
                Ok(grpc.unary(LintsSvc { inner: this }, request).await)
            }),
            DOCUMENT => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<DocumentResponse, DocumentRequest>::default());
                Ok(grpc.unary(DocumentSvc { inner: this }, request).await)
            }),
            VOLUMES => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<VolumesResponse, VolumesRequest>::default());
                Ok(grpc.unary(VolumesSvc { inner: this }, request).await)
            }),
            OPERATORS => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<OperatorsResponse, OperatorsRequest>::default());
                Ok(grpc.unary(OperatorsSvc { inner: this }, request).await)
            }),
            TRUST => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<TrustResponse, TrustRequest>::default());
                Ok(grpc.unary(TrustSvc { inner: this }, request).await)
            }),
            SIGNER => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<SignerResponse, SignerRequest>::default());
                Ok(grpc.unary(SignerSvc { inner: this }, request).await)
            }),
            SETTINGS => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<SettingsResponse, SettingsRequest>::default());
                Ok(grpc.unary(SettingsSvc { inner: this }, request).await)
            }),
            REFRESH_GROUP => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    RefreshGroupResponse,
                    RefreshGroupRequest,
                >::default());
                Ok(grpc.unary(RefreshGroupSvc { inner: this }, request).await)
            }),
            REKEY_MATERIAL => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    RekeyMaterialResponse,
                    RekeyMaterialRequest,
                >::default());
                Ok(grpc.unary(RekeyMaterialSvc { inner: this }, request).await)
            }),
            SECRETS => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<SecretsResponse, SecretsRequest>::default());
                Ok(grpc.unary(SecretsSvc { inner: this }, request).await)
            }),
            PROJECTION => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<ProjectionResponse, ProjectionRequest>::default());
                Ok(grpc.unary(ProjectionSvc { inner: this }, request).await)
            }),
            _ => Box::pin(async move {
                let (parts, ()) = Status::unimplemented("unknown method")
                    .into_http::<()>()
                    .into_parts();
                Ok(http::Response::from_parts(parts, Body::empty()))
            }),
        }
    }
}

struct WriteSvc {
    inner: AdminService,
}

impl Service<Request<Command>> for WriteSvc {
    type Response = Response<WriteResult>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Command>) -> Self::Future {
        let raft = self.inner.raft.clone();
        let state = self.inner.state.clone();
        let actor = actor_of(request.extensions());

        // **The second level of the class check** (ADR-0105, determination 2). The
        // gate has checked the path and knows `Class::Write`; which class this
        // **command** demands stands fixed only here -- and `EnrolOperator` demands
        // `operators`, otherwise `write` contains the authority to extend itself.
        let held = peer_operator(request.extensions()).map(|name| self.inner.classes_of(&name));
        let needed = request.get_ref().class();
        if !may(held.as_deref(), needed) {
            return Box::pin(async move {
                Err(Status::permission_denied(format!(
                    "this command needs the class '{needed}' (ADR-0105)"
                )))
            });
        }

        Box::pin(async move {
            // A refused write attempt is no gRPC error: the call worked, the
            // answer reads "not here" or "no". Packed as a `Status` both would be
            // indistinguishable from a transport problem.
            // **The actor arises here and does not come from the message**
            // (ADR-0050): it is formed from the connection's credentials. A field a
            // client fills would be a self-declaration -- the same one ADR-0043
            // removed from `NodeMessage::Hello` without replacement.
            //
            // On the socket that is the peer identifier. It is no identity
            // (ADR-0050, H2 rejected), but as a **statement** true: a file mode
            // gives no more.
            let command = request.into_inner();
            // **The name is held fast, the note arises afterwards** (ADR-0125):
            // the command travels into the `Submission` in a moment, and after the
            // write the mapping has disappeared from the state -- it is computed
            // from the **resulting** state all the same, like the lints beside it
            // (ADR-0048).
            let cleared = match &command {
                Command::ClearRegistryCredential { registry } => Some(registry.clone()),
                _ => None,
            };
            let submission = match actor {
                Some(actor) => Submission::by(actor, command),
                None => Submission::internal(command),
            };

            let result = match raft.client_write(submission).await {
                // **After** the write and from the resulting state (ADR-0048):
                // beforehand the note would be a statement about a set the
                // submitted document does not yet belong to.
                Ok(response) => WriteResult::Applied {
                    outcome: response.data,
                    lints: lints_of(&state)
                        .into_iter()
                        .chain(
                            cleared
                                .as_deref()
                                .map_or_else(Vec::new, |registry| notes_for(&state, registry)),
                        )
                        .collect(),
                },
                Err(err) => {
                    let leader = raft.metrics().borrow().current_leader;
                    let detail = err.to_string();
                    if detail.contains("forward request to") {
                        WriteResult::ForwardTo { leader }
                    } else {
                        WriteResult::Failed { detail }
                    }
                }
            };

            Ok(Response::new(result))
        })
    }
}

struct StatusSvc {
    inner: AdminService,
}

impl Service<Request<StatusRequest>> for StatusSvc {
    type Response = Response<StatusResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<StatusRequest>) -> Self::Future {
        let AdminService {
            id, raft, state, ..
        } = self.inner.clone();

        Box::pin(async move {
            let metrics = raft.metrics().borrow().clone();
            let applied = state.read();

            let mut voters: Vec<NodeId> =
                metrics.membership_config.membership().voter_ids().collect();
            voters.sort_unstable();

            Ok(Response::new(StatusResponse {
                id,
                leader: metrics.current_leader,
                is_leader: metrics.current_leader == Some(id)
                    && metrics.state == openraft::ServerState::Leader,
                last_applied: metrics.last_applied.map(|log_id| log_id.index),
                voters,
                reachable: reaching(&metrics, id),
                snapshot: metrics.snapshot.map(|log_id| log_id.index),
                purged: metrics.purged.map(|log_id| log_id.index),
                workloads: applied
                    .workloads()
                    .iter()
                    .map(|entry| entry.name().to_owned())
                    .collect(),
                nodes: applied
                    .nodes()
                    .iter()
                    .map(|(name, _)| (*name).to_owned())
                    .collect(),
                placements: applied
                    .placements()
                    .into_iter()
                    .map(|(workload, instance, node)| {
                        (workload.to_owned(), instance, node.to_owned())
                    })
                    .collect(),
            }))
        })
    }
}

struct MembershipSvc {
    inner: AdminService,
}

impl Service<Request<MembershipChange>> for MembershipSvc {
    type Response = Response<MembershipResult>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<MembershipChange>) -> Self::Future {
        let raft = self.inner.raft.clone();
        let peers = self.inner.peers.clone();
        let own = self.inner.id;

        Box::pin(async move {
            let change = request.into_inner();

            // **The precondition first** -- without an address the leader cannot
            // replicate, and the call would otherwise end in a time limit without a
            // reason or would succeed without taking effect.
            if let Some(detail) = unreachable(&change, &peers, own) {
                return Ok(Response::new(MembershipResult::Failed { detail }));
            }

            let outcome = match change {
                MembershipChange::AddLearner { id, blocking } => raft
                    .add_learner(id, openraft::BasicNode::default(), blocking)
                    .await
                    .map(|_| ()),
                MembershipChange::SetVoters { ids, retain } => {
                    let voters: std::collections::BTreeSet<NodeId> = ids.into_iter().collect();
                    raft.change_membership(voters, retain).await.map(|_| ())
                }
            };

            let result = match outcome {
                Ok(()) => {
                    let mut voters: Vec<NodeId> = raft
                        .metrics()
                        .borrow()
                        .membership_config
                        .membership()
                        .voter_ids()
                        .collect();
                    voters.sort_unstable();
                    MembershipResult::Changed { voters }
                }
                Err(err) => {
                    let detail = err.to_string();
                    if detail.contains("forward request to") {
                        MembershipResult::ForwardTo {
                            leader: raft.metrics().borrow().current_leader,
                        }
                    } else {
                        MembershipResult::Failed { detail }
                    }
                }
            };

            Ok(Response::new(result))
        })
    }
}

struct LintsSvc {
    inner: AdminService,
}

impl Service<Request<LintsRequest>> for LintsSvc {
    type Response = Response<LintsResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<LintsRequest>) -> Self::Future {
        let AdminService {
            id, raft, state, ..
        } = self.inner.clone();

        Box::pin(async move {
            // First the state, then the statement -- the same order as with the
            // projection: the reported index belongs at most to an older statement,
            // never to a newer one.
            let last_applied = raft.metrics().borrow().last_applied.map(|log| log.index);

            Ok(Response::new(LintsResponse {
                id,
                last_applied,
                lints: lints_of(&state),
            }))
        })
    }
}

struct VolumesSvc {
    inner: AdminService,
}

impl Service<Request<VolumesRequest>> for VolumesSvc {
    type Response = Response<VolumesResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<VolumesRequest>) -> Self::Future {
        let AdminService {
            id, raft, state, ..
        } = self.inner.clone();

        Box::pin(async move {
            // First the state, then the statement -- as with all read paths.
            let last_applied = raft.metrics().borrow().last_applied.map(|log| log.index);
            let applied = state.read();

            Ok(Response::new(VolumesResponse {
                id,
                last_applied,
                tombstones: applied
                    .deleted_volumes()
                    .into_iter()
                    .map(|(node, volumes)| {
                        (
                            node.to_owned(),
                            volumes.into_iter().map(str::to_owned).collect(),
                        )
                    })
                    .collect(),
            }))
        })
    }
}

struct OperatorsSvc {
    inner: AdminService,
}

impl Service<Request<OperatorsRequest>> for OperatorsSvc {
    type Response = Response<OperatorsResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<OperatorsRequest>) -> Self::Future {
        let AdminService {
            id, raft, state, ..
        } = self.inner.clone();

        Box::pin(async move {
            // First the state, then the statement -- as with all read paths.
            let last_applied = raft.metrics().borrow().last_applied.map(|log| log.index);
            let applied = state.read();

            Ok(Response::new(OperatorsResponse {
                id,
                last_applied,
                operators: applied
                    .operators()
                    .map(|(name, spki, classes)| EnrolledOperator {
                        name: name.to_owned(),
                        spki: spki.to_owned(),
                        classes: classes
                            .iter()
                            .map(|class| class.name().to_owned())
                            .collect(),
                    })
                    .collect(),
            }))
        })
    }
}

struct TrustSvc {
    inner: AdminService,
}

impl Service<Request<TrustRequest>> for TrustSvc {
    type Response = Response<TrustResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<TrustRequest>) -> Self::Future {
        let AdminService {
            id, raft, state, ..
        } = self.inner.clone();

        Box::pin(async move {
            // First the state, then the statement -- as with all read paths.
            let last_applied = raft.metrics().borrow().last_applied.map(|log| log.index);
            let applied = state.read();

            let nodes = applied
                .trusted()
                .map(|(name, spki)| TrustedNode {
                    name: name.to_owned(),
                    spki: spki.to_owned(),
                    ordinal: applied.ordinal(name),
                    underlay: applied.underlay_of(name).and_then(|entry| {
                        // **Both or nothing**: a peer needs a key *and* an
                        // endpoint, and half an announcement is for a tunnel the
                        // same as none.
                        entry
                            .key()
                            .zip(entry.endpoint())
                            .map(|(key, endpoint)| (key.to_owned(), endpoint.to_owned()))
                    }),
                })
                .collect();

            Ok(Response::new(TrustResponse {
                id,
                last_applied,
                nodes,
                invitations: applied
                    .invitations()
                    .into_iter()
                    .map(|(node, expires_at)| (node.to_owned(), expires_at))
                    .collect(),
            }))
        })
    }
}

struct SignerSvc {
    inner: AdminService,
}

impl Service<Request<SignerRequest>> for SignerSvc {
    type Response = Response<SignerResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<SignerRequest>) -> Self::Future {
        let AdminService { id, group, .. } = self.inner.clone();

        Box::pin(async move {
            // **No state beside it**, unlike with the other read paths: the group
            // is decoupled from the Raft membership (ADR-0014), its state lies on
            // the disk and in the process -- not in the log. A `last_applied` beside
            // it would claim a connection that does not exist.
            let Some(group) = group else {
                return Ok(Response::new(SignerResponse {
                    id,
                    kind: "local".to_owned(),
                    seat: None,
                    shape: None,
                    epochs: Vec::new(),
                    fingerprint: None,
                    linked: Vec::new(),
                    admitted: 0,
                    last_failure: None,
                }));
            };

            let shape = group.signer.shape();

            Ok(Response::new(SignerResponse {
                id,
                kind: "group".to_owned(),
                seat: Some(group.seat),
                shape: Some((shape.seats(), shape.threshold())),
                epochs: group
                    .signer
                    .epochs()
                    .into_iter()
                    .map(tg_identity::threshold::Epoch::number)
                    .collect(),
                fingerprint: Some(tg_identity::secrets::fingerprint(
                    group.signer.verifying_key(),
                )),
                linked: group
                    .signer
                    .linked()
                    .into_iter()
                    .map(tg_identity::threshold::Seat::number)
                    .collect(),
                admitted: group.admitted,
                last_failure: group.signer.last_failure(),
            }))
        })
    }
}

struct SettingsSvc {
    inner: AdminService,
}

impl Service<Request<SettingsRequest>> for SettingsSvc {
    type Response = Response<SettingsResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<SettingsRequest>) -> Self::Future {
        let AdminService {
            id, raft, state, ..
        } = self.inner.clone();

        Box::pin(async move {
            // First the state, then the statement -- as with all read paths.
            let last_applied = raft.metrics().borrow().last_applied.map(|log| log.index);
            let applied = state.read();

            Ok(Response::new(SettingsResponse {
                id,
                last_applied,
                network: applied
                    .network()
                    .map(|(cidr, prefix)| (cidr.to_owned(), prefix)),
                sidecar_overhead: amounts(applied.sidecar_overhead()),
                capacity: applied
                    .capacity_policy()
                    .entries()
                    .into_iter()
                    .map(|(resource, rule)| (resource.to_owned(), rule.clone()))
                    .collect(),
                rotation: applied.rotation_policy().entries(),
            }))
        })
    }
}

struct RefreshGroupSvc {
    inner: AdminService,
}

impl Service<Request<RefreshGroupRequest>> for RefreshGroupSvc {
    type Response = Response<RefreshGroupResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<RefreshGroupRequest>) -> Self::Future {
        let AdminService { id, group, .. } = self.inner.clone();

        Box::pin(async move {
            let Some(signer) = group.map(|group| group.signer) else {
                return Err(Status::failed_precondition(
                    "this node holds no seat of the signing group -- a refresh \
                     belongs on one that holds one (ADR-0097)",
                ));
            };

            // **On a thread of its own.** The three rounds dial four other seats
            // over mTLS and block; on the reactor that would be the disturbance
            // that halts the admin socket -- the same consideration as with
            // `RefreshDealSvc` in the signer service.
            let epoch = tokio::task::spawn_blocking(move || signer.refresh())
                .await
                .map_err(|err| Status::internal(format!("the refresh was aborted: {err}")))?
                .map_err(|err| Status::failed_precondition(err.to_string()))?;

            tracing::warn!(epoch = epoch.number(), "signer shares refreshed (ADR-0107)");

            Ok(Response::new(RefreshGroupResponse {
                id,
                epoch: epoch.number(),
            }))
        })
    }
}

struct RekeyMaterialSvc {
    inner: AdminService,
}

impl Service<Request<RekeyMaterialRequest>> for RekeyMaterialSvc {
    type Response = Response<RekeyMaterialResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<RekeyMaterialRequest>) -> Self::Future {
        let AdminService {
            id, raft, state, ..
        } = self.inner.clone();

        Box::pin(async move {
            let last_applied = raft.metrics().borrow().last_applied.map(|log| log.index);
            let applied = state.read();

            Ok(Response::new(RekeyMaterialResponse {
                id,
                last_applied,
                secrets: applied
                    .secret_material()
                    .into_iter()
                    .map(|(name, sealed)| (name.to_owned(), sealed.clone()))
                    .collect(),
            }))
        })
    }
}

struct SecretsSvc {
    inner: AdminService,
}

impl Service<Request<SecretsRequest>> for SecretsSvc {
    type Response = Response<SecretsResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<SecretsRequest>) -> Self::Future {
        let AdminService {
            id, raft, state, ..
        } = self.inner.clone();

        Box::pin(async move {
            let last_applied = raft.metrics().borrow().last_applied.map(|log| log.index);
            let applied = state.read();

            Ok(Response::new(SecretsResponse {
                id,
                last_applied,
                names: applied
                    .secret_sizes()
                    .into_iter()
                    .map(|(name, size)| (name.to_owned(), size))
                    .collect(),
                grants: applied
                    .secret_grants()
                    .into_iter()
                    .map(|(workload, secret)| (workload.to_owned(), secret.to_owned()))
                    .collect(),
                registries: applied
                    .registry_credentials()
                    .into_iter()
                    .map(|(registry, secret)| (registry.to_owned(), secret.to_owned()))
                    .collect(),
            }))
        })
    }
}

struct DocumentSvc {
    inner: AdminService,
}

impl Service<Request<DocumentRequest>> for DocumentSvc {
    type Response = Response<DocumentResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<DocumentRequest>) -> Self::Future {
        let AdminService {
            id, raft, state, ..
        } = self.inner.clone();
        let wanted = request.into_inner().workload;

        Box::pin(async move {
            // First the state, then the statement -- the same order as with the
            // projection and the lints.
            let last_applied = raft.metrics().borrow().last_applied.map(|log| log.index);
            let document = state
                .read()
                .workload(&wanted)
                .map(|entry| entry.document().to_owned());

            Ok(Response::new(DocumentResponse {
                id,
                last_applied,
                document,
            }))
        })
    }
}

struct ProjectionSvc {
    inner: AdminService,
}

impl Service<Request<ProjectionRequest>> for ProjectionSvc {
    type Response = Response<ProjectionResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<ProjectionRequest>) -> Self::Future {
        let AdminService {
            id,
            // `raft` is **not** read here: this answer's state is the projection's,
            // not the log's (see below).
            raft: _,
            state,
            projection,
            // The peer addresses belong to the membership path, not to the read
            // path.
            peers: _,
            group: _,
        } = self.inner.clone();

        Box::pin(async move {
            // **The view's state, not the log's.** `raft.metrics()` stood here,
            // with the rationale "that way the reported index belongs at most to an
            // older view, never to a newer one". For the state that is true; for the
            // **projection** it is not -- it is tracked by a task of its own and lies
            // behind the metric. Whoever wrote and then read could thereby read
            // "state N" and get a view without N, and a dead feed let the number go
            // on growing while the content froze.
            //
            // The answer mixes both -- what was decreed from the state, what was
            // reported from the projection. What is named is the **lagging** source:
            // with that the number is valid for everything in it.
            let last_applied = projection.applied();

            // **Desired from the log, observed from the projection** (ADR-0004).
            // The decreed generations are desired, so from the state -- and that is
            // why it is read here already and not only below at the nodes.
            let applied = state.read();

            // **Where the instances are reachable** (ADR-0073). Read once and
            // sorted by workload instead of anew per workload -- the report lies per
            // **node**, and a lookup per workload would run the whole map over and
            // over.
            let mut addresses: std::collections::BTreeMap<String, Vec<(u32, String)>> =
                std::collections::BTreeMap::new();
            for endpoints in projection.reported_endpoints().into_values() {
                for endpoint in endpoints {
                    addresses
                        .entry(endpoint.workload)
                        .or_default()
                        .push((endpoint.instance, endpoint.address.to_string()));
                }
            }
            for entries in addresses.values_mut() {
                entries.sort_unstable();
            }

            let workloads = projection
                .workloads()
                .into_iter()
                .map(|record| {
                    let mut edges = Vec::new();
                    for kind in [
                        DependencyKind::After,
                        DependencyKind::Before,
                        DependencyKind::Requires,
                        DependencyKind::Wants,
                        DependencyKind::BindsTo,
                        DependencyKind::Conflicts,
                    ] {
                        for target in projection.targets_of(&record.name, kind) {
                            edges.push((kind_name(kind).to_owned(), target));
                        }
                    }

                    observed(&record, edges, &projection, &applied, &addresses)
                })
                .collect();

            // Pulled together, desired and observed would yield a statement nobody
            // can substantiate.
            let reported = projection.reported_key_generations();
            let images = projection.reported_proxy_images();
            let zones = projection.reported_dns_zones();
            let mappings = projection.reported_userns();
            let reports = projection.last_reports();
            let slices = projection.reported_slices();
            let isolated = projection.isolated_entries();
            let capacities = projection.reported_capacity();
            let nodes = applied
                .nodes()
                .into_iter()
                .map(|(name, entry)| {
                    let wanted = applied.key_generations(name);
                    ProjectedNode {
                        name: name.to_owned(),
                        domain: format!(
                            "{}/{}/{}",
                            entry.topology().site,
                            entry.topology().hall,
                            entry.topology().rack
                        ),
                        schedulable: format!("{:?}", entry.schedulable()).to_lowercase(),
                        attached: entry.attachment().in_mesh(),
                        ordinal: applied.ordinal(name),
                        capacity: amounts(entry.capacity()),
                        reserved: amounts(entry.reserved()),
                        reported_capacity: capacities.get(name).map(amounts),
                        wanted_generations: (wanted.identity, wanted.underlay),
                        reported_generations: reported
                            .get(name)
                            .map(|seen| (seen.identity, seen.underlay)),
                        proxy_image: images.get(name).cloned(),
                        last_report: reports.get(name).copied(),
                        applied_slice: slices.get(name).copied(),
                        isolated: isolated.get(name).cloned().unwrap_or_default(),
                        dns_zone: zones.get(name).cloned(),
                        userns: mappings.get(name).copied().flatten(),
                    }
                })
                .collect();

            Ok(Response::new(ProjectionResponse {
                id,
                last_applied,
                workloads,
                nodes,
            }))
        })
    }
}

fn observed(
    record: &tg_store::WorkloadRecord,
    edges: Vec<(String, String)>,
    projection: &tg_store::Projection,
    applied: &tg_consensus::ClusterState,
    addresses: &std::collections::BTreeMap<String, Vec<(u32, String)>>,
) -> ProjectedWorkload {
    ProjectedWorkload {
        name: record.name.clone(),
        image: record.image.clone(),
        // Written out and not `{:?}`: a renamed variant would otherwise change
        // the wire format without anybody noticing it at the rename -- the same
        // consideration as with `edge_kind` and `actual_name`.
        class: applied
            .workload(&record.name)
            .map_or_else(String::new, |entry| class_name(entry.class()).to_owned()),
        edges,
        egress: applied
            .egress_of(&record.name)
            .into_iter()
            .map(|(host, port, transport)| (host.to_owned(), port, transport.to_string()))
            .collect(),
        placed: applied
            .instances(&record.name)
            .into_iter()
            .map(|(number, node)| (number, node.to_owned()))
            .collect(),
        // **From the document, not from a field at the entry.** `class` above
        // stands derived in the `WorkloadEntry`, because a lease grant would
        // otherwise have to parse XML at every call -- that is a question of
        // frequency, and it falls differently here: this view arises when a human
        // types `tgctl cluster show`.
        //
        // And it is **the same** derivation the planner uses
        // (`Demand::from_workload`): without `<placement>` it is one instance.
        replicas: applied
            .workload(&record.name)
            .and_then(|entry| tg_defs::from_str(entry.document()).ok())
            .and_then(|set| {
                set.workloads()
                    .iter()
                    .find(|workload| tg_defs::WorkloadExt::name(*workload) == record.name)
                    .map(|workload| tg_model::placement::Demand::from_workload(workload).replicas)
            })
            .unwrap_or_default(),
        lease: applied.lease(&record.name).map(|lease| {
            (
                lease.holder().to_owned(),
                lease.epoch().get(),
                // The expiry is in **milliseconds** UTC (ADR-0064); the other
                // points in time of this view are seconds. The conversion happens
                // **here** and not at the reader: two units in one answer are an
                // invitation to take the wrong one.
                i64::try_from(lease.expires_at().get() / 1000).unwrap_or(i64::MAX),
            )
        }),
        // **From the projection, not from the record.** It lies there beside
        // `Inner`, like `stale`, `unready` and `failures` below it -- until then
        // `materialize` took it along at every movement of the log, and this line
        // said "nothing observed" while the three lines below it named a failed
        // instance.
        instances: projection
            .instances_of(&record.name)
            .into_iter()
            .map(|(number, status)| (number, actual_name(status).to_owned()))
            .collect(),
        addresses: addresses.get(&record.name).cloned().unwrap_or_default(),
        ordered: applied.workload_generations(&record.name),
        stale: projection.stale_instances(&record.name),
        unready: projection.unready_instances(&record.name),
        failures: projection
            .failure_classes(&record.name)
            .into_iter()
            .collect(),
    }
}

const fn class_name(class: tg_defs::WorkloadClass) -> &'static str {
    match class {
        tg_defs::WorkloadClass::SingleWriter => "single-writer",
        tg_defs::WorkloadClass::Replicated => "replicated",
    }
}

const fn actual_name(status: tg_store::ActualStatus) -> &'static str {
    match status {
        tg_store::ActualStatus::Running => "running",
        tg_store::ActualStatus::Stopped => "stopped",
        tg_store::ActualStatus::Failed => "failed",
        tg_store::ActualStatus::Unknown => "unknown",
    }
}

fn kind_name(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::After => "after",
        DependencyKind::Before => "before",
        DependencyKind::Requires => "requires",
        DependencyKind::Wants => "wants",
        DependencyKind::BindsTo => "bindsTo",
        DependencyKind::Conflicts => "conflicts",
    }
}
