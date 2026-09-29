#![forbid(unsafe_code)]
// No panic-capable call on the production path (ADR-0082); in a client a panic
// is what an operator sees as a crash. `not(test)` because the unit tests need
// them; the guard lies in `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

use serde::{Deserialize, Serialize};
use tg_model::command::{Command, NodeId, Outcome};
use tg_wire::JsonCodec;
use tonic::{Request, Response, Status};

pub use tg_identity::PeerCredentials;

#[must_use]
pub fn socket_path(data_dir: &std::path::Path, id: NodeId) -> std::path::PathBuf {
    data_dir.join(format!("admin-{id}.sock"))
}

pub const ADMIN_SERVICE: &str = "tardigrade.admin.v1.Admin";
pub const WRITE: &str = "/tardigrade.admin.v1.Admin/Write";
pub const STATUS: &str = "/tardigrade.admin.v1.Admin/Status";
pub const MEMBERSHIP: &str = "/tardigrade.admin.v1.Admin/Membership";
pub const PROJECTION: &str = "/tardigrade.admin.v1.Admin/Projection";

pub const LINTS: &str = "/tardigrade.admin.v1.Admin/Lints";

pub const DOCUMENT: &str = "/tardigrade.admin.v1.Admin/Document";
pub const SETTINGS: &str = "/tardigrade.admin.v1.Admin/Settings";

pub const SECRETS: &str = "/tardigrade.admin.v1.Admin/Secrets";
pub const REKEY_MATERIAL: &str = "/tardigrade.admin.v1.Admin/RekeyMaterial";

pub const REFRESH_GROUP: &str = "/tardigrade.admin.v1.Admin/RefreshGroup";

pub const TRUST: &str = "/tardigrade.admin.v1.Admin/Trust";

pub const VOLUMES: &str = "/tardigrade.admin.v1.Admin/Volumes";

pub const OPERATORS: &str = "/tardigrade.admin.v1.Admin/Operators";

pub const SIGNER: &str = "/tardigrade.admin.v1.Admin/Signer";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum WriteResult {
    Applied {
        outcome: Outcome,
        #[serde(default)]
        lints: Vec<String>,
    },
    ForwardTo {
        leader: Option<NodeId>,
    },
    Failed {
        detail: String,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    pub id: NodeId,
    pub leader: Option<NodeId>,
    pub is_leader: bool,
    pub last_applied: Option<u64>,
    pub workloads: Vec<String>,
    pub nodes: Vec<String>,
    pub voters: Vec<NodeId>,
    #[serde(default)]
    pub reachable: Vec<NodeId>,
    pub snapshot: Option<u64>,
    pub placements: Vec<(String, u32, String)>,
    pub purged: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum MembershipChange {
    AddLearner {
        id: NodeId,
        blocking: bool,
    },
    SetVoters {
        ids: Vec<NodeId>,
        retain: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum MembershipResult {
    Changed {
        voters: Vec<NodeId>,
    },
    ForwardTo {
        leader: Option<NodeId>,
    },
    Failed {
        detail: String,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRequest {}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LintsRequest {}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsRequest {}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshGroupRequest {}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshGroupResponse {
    pub id: NodeId,
    pub epoch: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RekeyMaterialRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RekeyMaterialResponse {
    pub id: NodeId,
    pub last_applied: Option<u64>,
    pub secrets: Vec<(String, tg_identity::secrets::Sealed)>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsResponse {
    pub id: NodeId,
    pub last_applied: Option<u64>,
    pub names: Vec<(String, usize)>,
    pub grants: Vec<(String, String)>,
    pub registries: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumesResponse {
    pub id: u64,
    pub last_applied: Option<u64>,
    pub tombstones: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumesRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledOperator {
    pub name: String,
    pub spki: String,
    pub classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorsResponse {
    pub id: u64,
    pub last_applied: Option<u64>,
    pub operators: Vec<EnrolledOperator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorsRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedNode {
    pub name: String,
    pub spki: String,
    pub ordinal: Option<u32>,
    pub underlay: Option<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustResponse {
    pub id: u64,
    pub last_applied: Option<u64>,
    pub nodes: Vec<TrustedNode>,
    pub invitations: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerResponse {
    pub id: u64,
    pub kind: String,
    pub seat: Option<u16>,
    pub shape: Option<(u16, u16)>,
    pub epochs: Vec<u64>,
    pub fingerprint: Option<String>,
    pub linked: Vec<u16>,
    pub admitted: usize,
    pub last_failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsResponse {
    pub id: NodeId,
    pub last_applied: Option<u64>,
    #[serde(default)]
    pub network: Option<(String, u8)>,
    #[serde(default)]
    pub sidecar_overhead: Vec<(String, u64)>,
    #[serde(default)]
    pub capacity: Vec<(String, tg_model::capacity::Rule)>,
    #[serde(default)]
    pub rotation: Vec<(tg_model::KeyKind, u32)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRequest {
    pub workload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentResponse {
    pub id: NodeId,
    pub last_applied: Option<u64>,
    #[serde(default)]
    pub document: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LintsResponse {
    pub id: NodeId,
    pub last_applied: Option<u64>,
    pub lints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectedWorkload {
    pub name: String,
    pub image: String,
    #[serde(default)]
    pub class: String,
    pub edges: Vec<(String, String)>,
    #[serde(default)]
    pub egress: Vec<(String, u16, String)>,
    #[serde(default)]
    pub placed: Vec<(u32, String)>,
    #[serde(default)]
    pub replicas: u32,
    #[serde(default)]
    pub lease: Option<(String, u64, i64)>,
    #[serde(default)]
    pub instances: Vec<(u32, String)>,
    #[serde(default)]
    pub addresses: Vec<(u32, String)>,
    #[serde(default)]
    pub ordered: tg_model::rollout::Generations,
    #[serde(default)]
    pub stale: Vec<u32>,
    #[serde(default)]
    pub unready: Vec<u32>,
    #[serde(default)]
    pub failures: Vec<(u32, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionResponse {
    pub id: NodeId,
    pub last_applied: Option<u64>,
    pub workloads: Vec<ProjectedWorkload>,
    #[serde(default)]
    pub nodes: Vec<ProjectedNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedNode {

    pub name: String,

    pub domain: String,

    pub schedulable: String,

    pub attached: bool,

    #[serde(default)]
    pub ordinal: Option<u32>,

    #[serde(default)]
    pub capacity: Vec<(String, u64)>,

    #[serde(default)]
    pub reserved: Vec<(String, u64)>,

    #[serde(default)]
    pub reported_capacity: Option<Vec<(String, u64)>>,

    pub wanted_generations: (u64, u64),

    #[serde(default)]
    pub reported_generations: Option<(u64, u64)>,
    #[serde(default)]
    pub proxy_image: Option<String>,
    #[serde(default)]
    pub last_report: Option<i64>,
    #[serde(default)]
    pub isolated: Vec<String>,
    #[serde(default)]
    pub applied_slice: Option<u64>,
    #[serde(default)]
    pub dns_zone: Option<String>,
    #[serde(default)]
    pub userns: Option<u32>,
}

const OPERATOR_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const OPERATOR_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct AdminClient {
    channel: tonic::transport::Channel,
}

impl AdminClient {
    pub fn connect_unix(path: &std::path::Path) -> Result<Self, String> {
        let path = path.to_path_buf();

        // The URI is a formality: `tonic` demands one and the connector does not
        // look at it. The socket path stands in the connector.
        let channel = tonic::transport::Endpoint::try_from("http://admin.invalid")
            .map_err(|err| err.to_string())?
            .connect_with_connector_lazy(tower::service_fn(move |_: http::Uri| {
                let path = path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }));

        Ok(Self { channel })
    }

    pub fn connect_operator(
        endpoint: &str,
        operator: &str,
        key: &std::path::Path,
        anchors: &std::path::Path,
        domain: &str,
    ) -> Result<Self, String> {
        let domain =
            tg_identity::TrustDomain::new(domain).map_err(|err| format!("--domain: {err}"))?;

        let pem =
            std::fs::read_to_string(key).map_err(|err| format!("{}: {err}", key.display()))?;
        let pair = rcgen::KeyPair::from_pem(&pem)
            .map_err(|err| format!("{}: not a key ({err})", key.display()))?;
        let id = tg_identity::SpiffeId::for_operator(&domain, operator)
            .map_err(|err| format!("--operator: {err}"))?;
        let identity = tg_identity::NodeIdentity::new(&pair, id)
            .map_err(|err| format!("no credential: {err}"))?;

        let text = std::fs::read_to_string(anchors).map_err(|err| {
            format!(
                "{}: {err} — without an anchor there is no connection",
                anchors.display()
            )
        })?;
        let trust = tg_identity::cluster::anchors_from_pem(&text, &domain)
            .map_err(|err| format!("{}: {err}", anchors.display()))?;

        let config = tg_identity::cluster::client_config(
            &identity,
            tg_identity::NodeVerifier::new(domain, tg_identity::cluster::shared(trust)),
        )
        .map_err(|err| err.to_string())?;

        // The same construction as `tg_agent::cluster::connect`: `rustls` with
        // our verifier, and `tonic` only sees a finished stream. That it exists
        // twice is measured and not wanted — merging them is a cut of its own.
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{endpoint}"))
            .map_err(|err| format!("--peer '{endpoint}': {err}"))?
            .connect_timeout(OPERATOR_CONNECT_TIMEOUT)
            .timeout(OPERATOR_CALL_TIMEOUT)
            .connect_with_connector_lazy(tower::service_fn(move |uri: http::Uri| {
                let connector = connector.clone();
                async move {
                    let host = uri.host().unwrap_or("127.0.0.1").to_owned();
                    let port = uri.port_u16().unwrap_or(80);
                    let stream = tokio::net::TcpStream::connect((host, port)).await?;
                    // The SNI is a formality: **no server reads it** (ADR-0043,
                    // determination 1) — checked is the SPIFFE ID against the
                    // anchors.
                    let name = rustls_pki_types::ServerName::try_from(tg_identity::SNI)
                        .map_err(std::io::Error::other)?;
                    let tls = connector.connect(name, stream).await?;

                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
                }
            }));

        Ok(Self { channel })
    }

    #[must_use]
    pub fn with_channel(channel: tonic::transport::Channel) -> Self {
        Self { channel }
    }

    pub async fn write(&self, command: Command) -> Result<WriteResult, Status> {
        self.unary(WRITE, command).await
    }

    pub async fn status(&self) -> Result<StatusResponse, Status> {
        self.unary(STATUS, StatusRequest {}).await
    }

    pub async fn membership(&self, change: MembershipChange) -> Result<MembershipResult, Status> {
        self.unary(MEMBERSHIP, change).await
    }

    pub async fn lints(&self) -> Result<LintsResponse, Status> {
        self.unary(LINTS, LintsRequest {}).await
    }

    pub async fn volumes(&self) -> Result<VolumesResponse, Status> {
        self.unary(VOLUMES, VolumesRequest {}).await
    }

    pub async fn operators(&self) -> Result<OperatorsResponse, Status> {
        self.unary(OPERATORS, OperatorsRequest {}).await
    }

    pub async fn trust(&self) -> Result<TrustResponse, Status> {
        self.unary(TRUST, TrustRequest {}).await
    }

    pub async fn signer(&self) -> Result<SignerResponse, Status> {
        self.unary(SIGNER, SignerRequest {}).await
    }

    pub async fn settings(&self) -> Result<SettingsResponse, Status> {
        self.unary(SETTINGS, SettingsRequest {}).await
    }

    pub async fn secrets(&self) -> Result<SecretsResponse, Status> {
        self.unary(SECRETS, SecretsRequest {}).await
    }

    pub async fn rekey_material(&self) -> Result<RekeyMaterialResponse, Status> {
        self.unary(REKEY_MATERIAL, RekeyMaterialRequest {}).await
    }

    pub async fn refresh_group(&self) -> Result<RefreshGroupResponse, Status> {
        self.unary(REFRESH_GROUP, RefreshGroupRequest {}).await
    }

    pub async fn document(&self, workload: &str) -> Result<DocumentResponse, Status> {
        self.unary(
            DOCUMENT,
            DocumentRequest {
                workload: workload.to_owned(),
            },
        )
        .await
    }

    pub async fn projection(&self) -> Result<ProjectionResponse, Status> {
        self.unary(PROJECTION, ProjectionRequest {}).await
    }

    async fn unary<Req, Resp>(&self, path: &'static str, request: Req) -> Result<Resp, Status>
    where
        Req: serde::Serialize + Send + Sync + 'static,
        Resp: serde::de::DeserializeOwned + Send + Sync + 'static,
    {
        let mut client = tg_wire::client(self.channel.clone());
        client
            .ready()
            .await
            .map_err(|err| Status::unavailable(err.to_string()))?;

        client
            .unary(
                Request::new(request),
                http::uri::PathAndQuery::from_static(path),
                JsonCodec::<Req, Resp>::default(),
            )
            .await
            .map(Response::into_inner)
    }
}
