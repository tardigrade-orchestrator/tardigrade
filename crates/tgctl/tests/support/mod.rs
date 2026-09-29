//! A **provided** admin service for `tgctl`'s tests.
//!
//! Why provided and not a real `tgd`: `CARGO_BIN_EXE_tgd` does not exist in
//! this crate's tests — the environment variable knows only the package the
//! binary belongs to. Guessing a path beside it would be a dependency on
//! somebody having run `cargo build --workspace` beforehand.
//!
//! The server side is checked in `tgd` anyway; what is checked here is the
//! **client**. The two cannot diverge: path (`admin::WRITE`), request and
//! response type are the same elements `tgd` uses.
//!
//! And it can do something a real one-node cluster cannot: **answer
//! `ForwardTo`.** A single node is always the leader.

// Every test binary includes this module in full and uses a subset of it —
// what one does not need is dead code there.
#![allow(dead_code)]

use std::sync::Arc;

use tg_admin as admin;
use tg_admin::WriteResult;
use tg_consensus::Command;
use tg_wire::JsonCodec;
use tonic::body::Body;
use tonic::codegen::{BoxFuture, Service};

/// What the provided server answers, and what it has seen.
#[derive(Clone)]
struct Answering {
    answer: Arc<WriteResult>,
    seen: Arc<std::sync::Mutex<Vec<Command>>>,
    /// What the standing query answers (ADR-0048, determination 2).
    standing: Vec<String>,
    /// What the projection shows — the read path of `tgctl cluster show`.
    projected: Vec<admin::ProjectedWorkload>,
    /// The nodes the provided service shows (ADR-0054, ADR-0059).
    nodes: Vec<admin::ProjectedNode>,
    /// The voters `Status` names (ADR-0005).
    voters: Vec<u64>,
    /// Whom the leader reaches — the information without which a `SetVoters`
    /// can lead into a dead end (`change_membership` needs quorum).
    reachable: Vec<u64>,
    /// Whether the provided node leads (ADR-0044: `ForwardTo` otherwise).
    is_leader: bool,
    /// How a new node catches up — `(purged, snapshot)`.
    compaction: (Option<u64>, Option<u64>),
    /// What `Membership` answers.
    ///
    /// Provided and not started, for the same reason as at the write path: only
    /// that way is **`ForwardTo`** checkable — a one-node cluster is always the
    /// leader and cannot give this answer at all.
    membership: Arc<admin::MembershipResult>,
    /// Which changes were seen.
    changes: Arc<std::sync::Mutex<Vec<admin::MembershipChange>>>,
    document: Option<String>,
    settings: Arc<admin::SettingsResponse>,
    trust: Arc<admin::TrustResponse>,
    volumes: Arc<admin::VolumesResponse>,
    /// What `Secrets` answers (ADR-0016, ADR-0096).
    secrets: Arc<admin::SecretsResponse>,
    rekey: Arc<admin::RekeyMaterialResponse>,
    /// What `RefreshGroup` answers (ADR-0107) — or an error.
    ///
    /// **Both outcomes**, because both count: reached is an epoch, and refused
    /// is the node without a seat.
    refresh: Result<admin::RefreshGroupResponse, String>,
    /// What `Signer` answers (ADR-0097, ADR-0107).
    signer: Arc<admin::SignerResponse>,
}

impl Service<http::Request<Body>> for Answering {
    type Response = http::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        // **One route per function.** Four calls inline would let `call` grow
        // past the line limit — that is a sign, not an annoyance.
        let path = request.uri().path().to_owned();
        let me = self.clone();

        Box::pin(async move {
            if path == admin::LINTS {
                return Ok(me.lints(request).await);
            }
            if path == admin::DOCUMENT {
                return Ok(me.document(request).await);
            }
            if path == admin::SETTINGS {
                return Ok(me.settings(request).await);
            }
            if path == admin::REFRESH_GROUP {
                return Ok(me.refresh(request).await);
            }
            if path == admin::SIGNER {
                return Ok(me.signer(request).await);
            }
            if path == admin::REKEY_MATERIAL {
                return Ok(me.rekey(request).await);
            }
            if path == admin::SECRETS {
                return Ok(me.secrets(request).await);
            }
            if path == admin::TRUST {
                return Ok(me.trust(request).await);
            }
            if path == admin::VOLUMES {
                return Ok(me.volumes(request).await);
            }
            if path == admin::PROJECTION {
                return Ok(me.projection(request).await);
            }
            if path == admin::STATUS {
                return Ok(me.status(request).await);
            }
            if path == admin::MEMBERSHIP {
                return Ok(me.membership(request).await);
            }
            if path == admin::WRITE {
                return Ok(me.write(request).await);
            }
            Ok(tonic::Status::unimplemented(path).into_http::<Body>())
        })
    }
}

impl Answering {
    async fn lints(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::LintsResponse,
            admin::LintsRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::LintsRequest>| {
                let lints = self.standing.clone();
                async move {
                    Ok::<_, tonic::Status>(tonic::Response::new(admin::LintsResponse {
                        id: 1,
                        last_applied: Some(7),
                        lints,
                    }))
                }
            }),
            request,
        )
        .await
    }

    async fn document(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::DocumentResponse,
            admin::DocumentRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |request: tonic::Request<admin::DocumentRequest>| {
                // Answered by the **name**: only that way can the test
                // produce the case "it does not know it" at all.
                let wanted = request.into_inner().workload;
                let document = self.document.clone().filter(|_| wanted == "api");
                async move {
                    Ok::<_, tonic::Status>(tonic::Response::new(admin::DocumentResponse {
                        id: 1,
                        last_applied: Some(7),
                        document,
                    }))
                }
            }),
            request,
        )
        .await
    }

    async fn volumes(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::VolumesResponse,
            admin::VolumesRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::VolumesRequest>| {
                let volumes = admin::VolumesResponse::clone(&self.volumes);
                async move { Ok::<_, tonic::Status>(tonic::Response::new(volumes)) }
            }),
            request,
        )
        .await
    }

    async fn trust(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::TrustResponse,
            admin::TrustRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::TrustRequest>| {
                let trust = admin::TrustResponse::clone(&self.trust);
                async move { Ok::<_, tonic::Status>(tonic::Response::new(trust)) }
            }),
            request,
        )
        .await
    }

    /// The re-keying path (ADR-0100, determination 2).
    ///
    /// **A call of its own**, as in the service: `SecretsResponse` is
    /// enumerated and expressly does not carry the values.
    async fn rekey(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::RekeyMaterialResponse,
            admin::RekeyMaterialRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::RekeyMaterialRequest>| {
                let rekey = admin::RekeyMaterialResponse::clone(&self.rekey);
                async move { Ok::<_, tonic::Status>(tonic::Response::new(rekey)) }
            }),
            request,
        )
        .await
    }

    /// The refresh of the signer shares (ADR-0107).
    async fn refresh(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::RefreshGroupResponse,
            admin::RefreshGroupRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::RefreshGroupRequest>| {
                let refresh = self.refresh.clone();
                async move {
                    match refresh {
                        Ok(answer) => Ok(tonic::Response::new(answer)),
                        Err(detail) => Err(tonic::Status::failed_precondition(detail)),
                    }
                }
            }),
            request,
        )
        .await
    }

    async fn secrets(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::SecretsResponse,
            admin::SecretsRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::SecretsRequest>| {
                let secrets = admin::SecretsResponse::clone(&self.secrets);
                async move { Ok::<_, tonic::Status>(tonic::Response::new(secrets)) }
            }),
            request,
        )
        .await
    }

    async fn signer(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::SignerResponse,
            admin::SignerRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::SignerRequest>| {
                let signer = admin::SignerResponse::clone(&self.signer);
                async move { Ok::<_, tonic::Status>(tonic::Response::new(signer)) }
            }),
            request,
        )
        .await
    }

    async fn settings(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::SettingsResponse,
            admin::SettingsRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::SettingsRequest>| {
                let settings = admin::SettingsResponse::clone(&self.settings);
                async move { Ok::<_, tonic::Status>(tonic::Response::new(settings)) }
            }),
            request,
        )
        .await
    }

    async fn projection(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::ProjectionResponse,
            admin::ProjectionRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::ProjectionRequest>| {
                let workloads = self.projected.clone();
                let nodes = self.nodes.clone();
                async move {
                    Ok::<_, tonic::Status>(tonic::Response::new(admin::ProjectionResponse {
                        id: 1,
                        last_applied: Some(7),
                        workloads,
                        nodes,
                    }))
                }
            }),
            request,
        )
        .await
    }

    async fn status(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::StatusResponse,
            admin::StatusRequest,
        >::default());
        grpc.unary(
            tower::service_fn(move |_: tonic::Request<admin::StatusRequest>| {
                let voters = self.voters.clone();
                let reachable = self.reachable.clone();
                let compaction = self.compaction;
                let is_leader = self.is_leader;
                async move {
                    Ok::<_, tonic::Status>(tonic::Response::new(admin::StatusResponse {
                        id: 1,
                        leader: Some(1),
                        is_leader,
                        last_applied: Some(7),
                        workloads: Vec::new(),
                        nodes: Vec::new(),
                        voters,
                        reachable,
                        snapshot: compaction.1,
                        purged: compaction.0,
                        placements: Vec::new(),
                    }))
                }
            }),
            request,
        )
        .await
    }

    async fn membership(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<
            admin::MembershipResult,
            admin::MembershipChange,
        >::default());
        grpc.unary(
            tower::service_fn(move |req: tonic::Request<admin::MembershipChange>| {
                let answer = Arc::clone(&self.membership);
                let changes = Arc::clone(&self.changes);
                async move {
                    changes.lock().expect("mutex").push(req.into_inner());
                    Ok::<_, tonic::Status>(tonic::Response::new((*answer).clone()))
                }
            }),
            request,
        )
        .await
    }

    async fn write(self, request: http::Request<Body>) -> http::Response<Body> {
        let mut grpc = tonic::server::Grpc::new(JsonCodec::<WriteResult, Command>::default());
        grpc.unary(
            tower::service_fn(move |req: tonic::Request<Command>| {
                let answer = Arc::clone(&self.answer);
                let seen = Arc::clone(&self.seen);
                async move {
                    seen.lock().expect("mutex").push(req.into_inner());
                    Ok::<_, tonic::Status>(tonic::Response::new((*answer).clone()))
                }
            }),
            request,
        )
        .await
    }
}

impl tonic::server::NamedService for Answering {
    const NAME: &'static str = "tardigrade.admin.v1.Admin";
}

pub(crate) struct Served {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) seen: Arc<std::sync::Mutex<Vec<Command>>>,
    /// Which membership changes the provided service has seen (ADR-0005).
    pub(crate) changes: Arc<std::sync::Mutex<Vec<admin::MembershipChange>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Brings up a socket in the data directory that answers `answer`.
///
/// Not `async`, although it needs a runtime: `tokio::spawn` demands a context,
/// not an `await`. An `async fn` without an `await` would be a claim about the
/// function that is not right.
pub(crate) fn serve(id: u64, answer: WriteResult) -> Served {
    served(
        id,
        Answers {
            answer,
            ..Answers::default()
        },
    )
}

/// Like [`serve`], with a projection behind the read path.
pub(crate) fn serve_showing(
    id: u64,
    answer: WriteResult,
    projected: Vec<admin::ProjectedWorkload>,
) -> Served {
    served(
        id,
        Answers {
            answer,
            projected,
            ..Answers::default()
        },
    )
}

/// Like [`serve`], with a canonical document behind the read path (ADR-0008).
/// Only the name `api` is answered — only that way can a test produce the case
/// "it does not know it".
/// A test rig that answers `Volumes`.
pub(crate) fn serve_volumes(id: u64, volumes: admin::VolumesResponse) -> Served {
    served(
        id,
        Answers {
            volumes,
            ..Answers::default()
        },
    )
}

/// A test rig that answers `Secrets`.
pub(crate) fn serve_secrets(id: u64, secrets: admin::SecretsResponse) -> Served {
    served(
        id,
        Answers {
            secrets,
            ..Answers::default()
        },
    )
}

/// Like [`serve`], with re-keying material behind `RekeyMaterial`.
pub(crate) fn serve_rekey(
    id: u64,
    answer: WriteResult,
    rekey: admin::RekeyMaterialResponse,
) -> Served {
    served(
        id,
        Answers {
            answer,
            rekey,
            ..Answers::default()
        },
    )
}

/// A test rig that **writes and knows secrets**.
///
/// For `node remove`: the hint about the data key (ADR-0095, ADR-0100) hangs on
/// whether there is a secret to protect at all — both directions therefore need
/// the same setup with **one** thing different.
pub(crate) fn serve_writing_with_secrets(
    id: u64,
    answer: WriteResult,
    secrets: admin::SecretsResponse,
) -> Served {
    served(
        id,
        Answers {
            answer,
            secrets,
            ..Answers::default()
        },
    )
}

/// Like [`serve`], with an admission list behind `Trust`.
///
/// For the commands that look before writing at whether a node is **admitted**
/// (`trust`, ADR-0037) — not at whether it has a `NodeEntry`.
pub(crate) fn serve_admitted(id: u64, answer: WriteResult, admitted: &[&str]) -> Served {
    served(
        id,
        Answers {
            answer,
            trust: admin::TrustResponse {
                id,
                last_applied: Some(7),
                nodes: admitted
                    .iter()
                    .map(|name| admin::TrustedNode {
                        name: (*name).to_owned(),
                        spki: "AAAA".to_owned(),
                        ordinal: None,
                        underlay: None,
                    })
                    .collect(),
                invitations: Vec::new(),
            },
            ..Answers::default()
        },
    )
}

/// A test rig that answers `Trust`.
pub(crate) fn serve_trust(id: u64, trust: admin::TrustResponse) -> Served {
    served(
        id,
        Answers {
            trust,
            ..Answers::default()
        },
    )
}

/// A test rig that answers `Settings`.
pub(crate) fn serve_settings(id: u64, settings: admin::SettingsResponse) -> Served {
    served(
        id,
        Answers {
            settings,
            ..Answers::default()
        },
    )
}

/// A service that answers `RefreshGroup` as given (ADR-0107).
pub(crate) fn serve_refresh(
    id: u64,
    refresh: Result<admin::RefreshGroupResponse, String>,
) -> Served {
    served(
        id,
        Answers {
            refresh,
            ..Answers::default()
        },
    )
}

/// A test rig that answers `Signer` (ADR-0097, ADR-0107).
pub(crate) fn serve_signer(id: u64, signer: admin::SignerResponse) -> Served {
    served(
        id,
        Answers {
            signer,
            ..Answers::default()
        },
    )
}

pub(crate) fn serve_document(id: u64, document: String) -> Served {
    served(
        id,
        Answers {
            document: Some(document),
            ..Answers::default()
        },
    )
}

/// Like [`serve`], with nodes behind the read path (ADR-0054, ADR-0059).
pub(crate) fn serve_nodes(id: u64, nodes: Vec<admin::ProjectedNode>) -> Served {
    served(
        id,
        Answers {
            nodes,
            ..Answers::default()
        },
    )
}

/// Like [`serve`], with an answer to the standing query.
pub(crate) fn serve_with(id: u64, answer: WriteResult, standing: Vec<String>) -> Served {
    served(
        id,
        Answers {
            answer,
            standing,
            ..Answers::default()
        },
    )
}

/// What the provided service shall answer.
///
/// **One bundle instead of seven parameters**: at seven nobody sees any more
/// what belongs where — the same correction as at the reconciler's `Context`
/// and at `Sinks` in the agent.
#[derive(Clone)]
pub(crate) struct Answers {
    pub(crate) answer: WriteResult,
    pub(crate) standing: Vec<String>,
    pub(crate) projected: Vec<admin::ProjectedWorkload>,
    pub(crate) nodes: Vec<admin::ProjectedNode>,
    pub(crate) voters: Vec<u64>,
    pub(crate) reachable: Vec<u64>,
    /// Whether the provided node leads.
    ///
    /// Default `true`: almost every witness checks a command, and on a follower
    /// that ends with `ForwardTo` anyway. Whoever sets `false` checks the
    /// branches that run **only** there.
    pub(crate) is_leader: bool,
    /// How a new node catches up — `(purged, snapshot)`.
    pub(crate) compaction: (Option<u64>, Option<u64>),
    pub(crate) membership: admin::MembershipResult,
    pub(crate) document: Option<String>,
    pub(crate) settings: admin::SettingsResponse,
    pub(crate) trust: admin::TrustResponse,
    pub(crate) volumes: admin::VolumesResponse,
    pub(crate) secrets: admin::SecretsResponse,
    pub(crate) rekey: admin::RekeyMaterialResponse,
    pub(crate) refresh: Result<admin::RefreshGroupResponse, String>,
    pub(crate) signer: admin::SignerResponse,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            answer: WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                lints: Vec::new(),
            },
            standing: Vec::new(),
            projected: Vec::new(),
            nodes: Vec::new(),
            voters: Vec::new(),
            reachable: Vec::new(),
            is_leader: true,
            compaction: (None, None),
            document: None,
            settings: admin::SettingsResponse {
                id: 1,
                last_applied: Some(7),
                network: None,
                sidecar_overhead: Vec::new(),
                capacity: Vec::new(),
                rotation: Vec::new(),
            },
            trust: admin::TrustResponse {
                id: 1,
                last_applied: Some(7),
                nodes: Vec::new(),
                invitations: Vec::new(),
            },
            volumes: admin::VolumesResponse {
                id: 1,
                last_applied: Some(7),
                tombstones: Vec::new(),
            },
            membership: changed(&[]),
            secrets: admin::SecretsResponse {
                id: 1,
                last_applied: Some(7),
                names: Vec::new(),
                grants: Vec::new(),
                registries: Vec::new(),
            },
            rekey: admin::RekeyMaterialResponse {
                id: 1,
                last_applied: Some(7),
                secrets: Vec::new(),
            },
            refresh: Ok(admin::RefreshGroupResponse { id: 1, epoch: 1 }),
            signer: admin::SignerResponse {
                id: 1,
                kind: "local".to_owned(),
                seat: None,
                shape: None,
                epochs: Vec::new(),
                fingerprint: None,
                linked: Vec::new(),
                admitted: 0,
                last_failure: None,
            },
        }
    }
}

fn served(id: u64, answers: Answers) -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = admin::socket_path(dir.path(), id);
    let listener = tokio::net::UnixListener::bind(&path).expect("socket");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let changes = Arc::new(std::sync::Mutex::new(Vec::new()));

    let service = Answering {
        answer: Arc::new(answers.answer),
        document: answers.document,
        settings: Arc::new(answers.settings),
        trust: Arc::new(answers.trust),
        volumes: Arc::new(answers.volumes),
        secrets: Arc::new(answers.secrets),
        rekey: Arc::new(answers.rekey),
        refresh: answers.refresh,
        signer: Arc::new(answers.signer),
        seen: Arc::clone(&seen),
        standing: answers.standing,
        projected: answers.projected,
        nodes: answers.nodes,
        voters: answers.voters,
        reachable: answers.reachable,
        is_leader: answers.is_leader,
        compaction: answers.compaction,
        membership: Arc::new(answers.membership),
        changes: Arc::clone(&changes),
    };
    let handle = tokio::spawn(async move {
        // `UnixListenerStream` instead of a stream of our own: `tokio-stream`
        // lies in the tree anyway, a generator crate would be two crates for
        // one loop (ADR-0023).
        let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Served {
        dir,
        seen,
        changes,
        handle,
    }
}

/// A membership service with the named voters.
pub(crate) fn serve_members(id: u64, voters: Vec<u64>, answer: admin::MembershipResult) -> Served {
    served(
        id,
        Answers {
            voters,
            membership: answer,
            ..Answers::default()
        },
    )
}

/// Like [`serve_members`], only with the reachability as well.
///
/// An **empty** list is here a statement of its own and not an omission: it
/// means "this control plane does not name it" (`serde(default)`), for a node
/// of this version always puts its own identifier in as well.
pub(crate) fn serve_reachable(
    id: u64,
    voters: Vec<u64>,
    reachable: Vec<u64>,
    answer: admin::MembershipResult,
) -> Served {
    served(
        id,
        Answers {
            voters,
            reachable,
            membership: answer,
            ..Answers::default()
        },
    )
}

/// A service that **does not lead** — with a dead majority behind it.
///
/// The setup of `serve_reachable`, with **one** thing different: on a follower
/// `metrics.replication` is empty, and "silent" would there be a statement
/// about something it cannot know.
pub(crate) fn serve_follower(
    id: u64,
    voters: Vec<u64>,
    reachable: Vec<u64>,
    answer: admin::MembershipResult,
) -> Served {
    served(
        id,
        Answers {
            voters,
            reachable,
            is_leader: false,
            membership: answer,
            ..Answers::default()
        },
    )
}

/// A service whose log is **truncated** (ADR-0020).
///
/// The two numbers with which an operator plans a replacement: does the new
/// node catch up from the log or by snapshot?
pub(crate) fn serve_compacted(
    id: u64,
    voters: Vec<u64>,
    compaction: (Option<u64>, Option<u64>),
) -> Served {
    served(
        id,
        Answers {
            voters,
            compaction,
            ..Answers::default()
        },
    )
}

/// The ordinary answer: changed, with this set.
pub(crate) fn changed(voters: &[u64]) -> admin::MembershipResult {
    admin::MembershipResult::Changed {
        voters: voters.to_vec(),
    }
}
