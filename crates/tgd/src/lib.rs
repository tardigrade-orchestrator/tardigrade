//! Control-plane node: Raft over a real network (ADR-0002, ADR-0005).
//!
//! Phase 5c turns the five nodes in one process (phase 5b) into five real
//! processes. What changes is only the stretch between them -- the command set,
//! the state machine and the storage are unchanged the ones from 5a, and the test
//! rig from 5b goes on running against the same traits.
//!
//! # Time values
//!
//! From ADR-0033: `RTT(p99) < heartbeat_interval < election_timeout_min`, with a
//! factor of three in both steps. The defaults here are the starting profile named
//! there for a cluster across halls of the same site. Whoever stands further apart
//! measures and recomputes -- [`Timing`] makes that a setting and not a change to
//! the code.
//!
//! # What does not stand here yet
//!
//! No TLS and no authentication on the Raft port (see [`tg_consensus::net`]), no
//! membership change and no log compaction (phase 5d), no API per ADR-0018 -- the
//! admin service here is its forerunner, just large enough to show this phase's
//! acceptance.

#![forbid(unsafe_code)]
// **No panic-capable call in the production path** (ADR-0082): since then a panic
// costs its task and not the node -- and that is a state an operator sees only at
// a metric. `not(test)`, because the unit tests in `src` need them; the guard lies
// in `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod admin;
pub mod cluster;
pub mod health;
pub mod identity;
pub mod options;
pub mod projection;
pub mod scheduler;
pub mod session;
pub mod signer;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use openraft::{BasicNode, Raft};
use tg_consensus::audit::Archive;
use tg_consensus::net::{GrpcNetwork, RaftService};
use tg_consensus::{NodeId, StateHandle, Storage, TypeConfig};

pub use crate::options::{Options, Timing};

#[derive(Debug)]
pub enum NodeError {
    Storage(String),
    Raft {
        operation: &'static str,
        detail: String,
    },
    Serve(String),
    Options(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(detail) => write!(f, "the storage is not usable: {detail}"),
            Self::Raft { operation, detail } => write!(f, "{operation}: {detail}"),
            Self::Serve(detail) => write!(f, "server: {detail}"),
            Self::Options(detail) => write!(f, "call: {detail}"),
        }
    }
}

impl std::error::Error for NodeError {}

pub struct Node {
    id: NodeId,
    raft: Raft<TypeConfig>,
    state: StateHandle,
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Node {
    pub async fn start_with(
        options: &Options,
        dialer: Arc<dyn tg_consensus::net::PeerDialer>,
    ) -> Result<Self, NodeError> {
        std::fs::create_dir_all(&options.data_dir)
            .map_err(|err| NodeError::Storage(err.to_string()))?;

        let path = options.data_dir.join(format!("raft-{}.redb", options.id));
        let mut storage =
            Storage::open(&path).map_err(|err| NodeError::Storage(err.to_string()))?;

        // The audit archive (ADR-0020) hooks itself in **before** the Raft start.
        // Afterwards it would be too late: `openraft` applies as soon as it runs,
        // and every entry that got through before the hooking in would be missing
        // from the chain -- not visible as a gap but not there at all.
        let archive = options.data_dir.join(format!("audit-{}.jsonl", options.id));
        let archive = Archive::open_with(&archive, options.audit_rotate)
            .map_err(|err| NodeError::Storage(err.to_string()))?;
        tracing::info!(
            records = archive.records(),
            head = %archive.head(),
            "the audit archive is continued"
        );
        storage.machine.with_archive(archive);

        let state = storage.machine.handle();

        let config = options
            .timing
            .to_config(options.snapshots)
            .map_err(|detail| NodeError::Raft {
                operation: "configuration",
                detail,
            })?;

        let raft = Raft::new(
            options.id,
            Arc::new(config),
            GrpcNetwork::with_dialer(options.peers.clone(), dialer),
            storage.log,
            storage.machine,
        )
        .await
        .map_err(|err| NodeError::Raft {
            operation: "Raft::new",
            detail: err.to_string(),
        })?;

        Ok(Self {
            id: options.id,
            raft,
            state,
        })
    }

    pub async fn initialize(&self, members: &[NodeId]) -> Result<bool, NodeError> {
        let members: BTreeMap<NodeId, BasicNode> = members
            .iter()
            .map(|id| (*id, BasicNode::default()))
            .collect();

        match self.raft.initialize(members).await {
            Ok(()) => Ok(true),
            // **`NotAllowed` is the only refusal we swallow:** it means "this node
            // already has a log and a vote", and at a node's restart that is the
            // truth.
            //
            // What is checked is the **variant** and not the message.
            // `err.to_string().contains("already initialized")` stood here -- and
            // that string occurs **nowhere** in `openraft` 0.9.25, only in three
            // comments. The branch was thereby dead, and the promise above it
            // false: measured, a second start with `--init` on the same data
            // directory ended with "not allowed to initialize due to current raft
            // state".
            //
            // `NotInMembers` expressly stays an error: it means that this node does
            // not occur in the named membership -- a setting of the operator that
            // is not true.
            Err(openraft::error::RaftError::APIError(
                openraft::error::InitializeError::NotAllowed(_),
            )) => Ok(false),
            Err(err) => Err(NodeError::Raft {
                operation: "initialize",
                detail: err.to_string(),
            }),
        }
    }

    #[must_use]
    pub fn raft(&self) -> &Raft<TypeConfig> {
        &self.raft
    }

    #[must_use]
    pub fn state(&self) -> &StateHandle {
        &self.state
    }

    #[must_use]
    pub fn id(&self) -> NodeId {
        self.id
    }
}

pub async fn audit_export(options: &Options) -> Result<(), NodeError> {
    let path = options.data_dir.join(format!("raft-{}.redb", options.id));
    let anchor = options
        .audit_anchor
        .clone()
        .unwrap_or_else(|| tg_telemetry::audit::GENESIS.to_owned());

    let export =
        tg_consensus::audit::export_range(&path, options.audit_from, options.audit_to, &anchor)
            .await
            .map_err(|err| NodeError::Storage(err.to_string()))?;

    for record in &export.segment.records {
        let line = serde_json::to_string(record)
            .map_err(|err| NodeError::Storage(format!("a record cannot be encoded: {err}")))?;
        println!("{line}");
    }

    // Everything accompanying goes to stderr -- otherwise it would stand in the
    // file an operator redirects the segment into.
    eprintln!(
        "range [{}, {}), {} records, anchor {anchor}",
        export.from,
        export.to,
        export.segment.records.len()
    );
    if let Some(head) = export.segment.records.last() {
        eprintln!("head: {} (anchor of the next segment)", head.digest);
    }
    eprintln!(
        "careful: exported from the log, so **without** verdicts (ADR-0045). \
         That is evidence about the log's content and not the continuation of an \
         existing chain."
    );

    Ok(())
}

pub async fn run(options: Options, scrape: tg_telemetry::serve::Scrape) -> Result<(), NodeError> {
    // The cluster identity stands **before** the Raft start: the Raft port's
    // dialler hangs on it, and `Raft::new` gets the dialler along.
    let domain = tg_identity::TrustDomain::new(options.trust_domain.clone())
        .map_err(|err| NodeError::Options(format!("trust domain: {err}")))?;
    let identity = cluster::identity(&options.data_dir, &domain, &options.node)
        .map_err(|err| NodeError::Options(err.to_string()))?;

    let peers = load_peers(&options, &domain, &identity);

    let dialer = Arc::new(cluster::TlsDialer::new(
        identity.clone(),
        domain.clone(),
        peers,
    ));
    let raft_trust = Arc::clone(dialer.trust());

    let node = Node::start_with(&options, dialer.clone()).await?;

    if options.init {
        let members: Vec<NodeId> = options
            .init_voters
            .clone()
            .unwrap_or_else(|| options.peers.entries().iter().map(|(id, _)| *id).collect());
        let fresh = node.initialize(&members).await?;
        tracing::info!(
            fresh,
            members = members.len(),
            "the cluster membership was created"
        );
    }

    tracing::info!(
        id = options.id,
        listen = %options.listen,
        peers = options.peers.entries().len().saturating_sub(1),
        "the node is listening"
    );

    // **The time limit the runtime is to be read against** (ADR-0033).
    //
    // `openraft` uses `heartbeat_interval` at the same time as the time limit of
    // the replication call; the ordering condition there reads
    // `RTT(p99) < heartbeat_interval`, with a factor of three. Without this number
    // at the endpoint somebody would have to copy it from the command line into the
    // alarm rule -- the second source this tree avoids everywhere else.
    let deadline =
        f64::from(u32::try_from(options.timing.heartbeat_ms).unwrap_or(u32::MAX)) / 1000.0;
    metrics::gauge!(tg_telemetry::names::RAFT_RPC_DEADLINE).set(deadline);

    // The observation of the node (ADR-0015). It starts **before** the loops it
    // observes: a watchdog that is set up after the loop does not know its first
    // round.
    let health = health::spawn(node.raft(), options.peers.clone(), options.id);

    // The time limit is a constant of this process and is set exactly once -- with
    // the gauge expiry (ADR-0088) it would vanish after 15 minutes, and with it the
    // right-hand side of the alarm rule from ADR-0033.
    health.on_scrape(tg_telemetry::names::RAFT_RPC_DEADLINE, move || {
        metrics::gauge!(tg_telemetry::names::RAFT_RPC_DEADLINE).set(deadline);
    });

    // Which version of the session protocol this process speaks (ADR-0072). In the
    // maintenance window of a format change it is the only statement that survives
    // the skew: everything that would run over the session is exactly what the skew
    // breaks.
    tg_telemetry::probes::report_protocol(&health, tg_store::session::PROTOCOL_FIELDS);

    // **What the audit archive occupies on the disk** (ADR-0132, determination 1).
    // The registration lies at the number's source and not here: `tg-telemetry`
    // must not know the consensus core, `tg-consensus` very much may know its own
    // footprint.
    tg_consensus::audit::report_footprint(
        &health,
        options.data_dir.join(format!("audit-{}.jsonl", options.id)),
    );

    if let Some(addr) = options.telemetry.addr {
        let health = health.clone();
        let scrape = scrape.clone();
        tokio::spawn(async move {
            if let Err(err) = tg_telemetry::serve::serve(addr, health, scrape).await {
                // No abort: a node without a metrics endpoint is a poorly
                // observable node, not a broken one. Halting it for that would mean
                // hanging the workloads' availability on the telemetry -- exactly
                // the other way round from ADR-0019.
                tracing::warn!(%addr, error = %err, "the telemetry endpoint");
            }
        });
        tracing::info!(%addr, "the telemetry endpoint stands");
    }

    // From here the projection follows the log (ADR-0004, ADR-0030) -- not a local
    // cache.
    let feed = projection::Feed::spawn(node.raft(), node.state(), &health);

    // The scheduler runs on every node but plans only as long as that node leads
    // (ADR-0011: scheduling is leader- and quorum-bound). That way there is nothing
    // to start after a leader change -- the new one was already planning along
    // anyway.
    let _scheduler = scheduler::Scheduler::spawn(
        node.raft(),
        node.state().clone(),
        feed.projection(),
        health.clone(),
    );

    // The SPIFFE server (ADR-0006/0037). If the signing material is missing, the
    // node runs without it -- a cluster without a CA is a cluster without
    // identities, but no broken cluster.
    let (seats, signing) = load_signing(&options, &identity, &domain);
    // **The data key is read, not created** (ADR-0095, determination 2). A `tgd`
    // that created it on demand would create a **different** one on every node --
    // and what the one sealed nobody would open afterwards, without anything
    // appearing anywhere. It comes from an operator (`tgctl secret keygen`), like
    // the join token.
    let (data_key, previous_data_key) = data_keys(&options, &health, node.state().clone());
    report_signing(&health, signing.as_ref(), seats.len(), &options.data_dir);
    // **Both or neither** (ADR-0097): the seat and the list its port checks
    // against belong together.
    let group = signing
        .as_ref()
        .and_then(|signing| signing.seat.clone())
        .zip(signing.as_ref().and_then(|signing| signing.group.clone()))
        .map(|(seat, signer)| Group {
            seat,
            seats: seats.clone(),
            signer,
        });
    let spiffe = signing.map(|signing| {
        tracing::info!(domain = %signing.ca.domain(), "SPIFFE server");
        identity::IdentityService::new(
            node.raft().clone(),
            node.state().clone(),
            std::sync::Arc::new(signing.ca),
        )
        .with_data_key(data_key, previous_data_key)
    });

    // `add_optional_service` instead of two branches: otherwise the router carries
    // a different type depending on the case, and the difference would then stand
    // in the signature instead of in the matter.
    serve_all(
        &options,
        &node,
        &Credentials {
            identity: &identity,
            domain: &domain,
            raft_trust,
        },
        &feed,
        spiffe,
        group,
    )
    .await
}

fn load_peers(
    options: &Options,
    domain: &tg_identity::TrustDomain,
    identity: &tg_identity::cluster::NodeIdentity,
) -> cluster::Peers {
    let (mut peers, notes) = cluster::Peers::load(&options.data_dir, domain);
    for note in notes {
        tracing::warn!(%note, "peer list");
    }
    peers.admit_self(options.id, identity);
    tracing::info!(
        id = %identity.id(),
        peers = peers.len().saturating_sub(1),
        "the cluster credential"
    );

    // **Half-configured is the frequent state** (ADR-0043: an operator distributes
    // the leaves). Whoever extends `--peer` and forgets `peers/<id>.pem` gets
    // `UnknownIssuer` to this node -- and it stands out only when it leads and wants
    // to replicate to us. The two numbers stood in two lines and were both called
    // `peers`.
    let without = peers.without_leaf(
        options.peers.entries().iter().map(|(id, _)| *id),
        options.id,
    );
    if !without.is_empty() {
        tracing::warn!(
            ids = ?without,
            dir = %tg_identity::layout::peers(&options.data_dir).display(),
            "named peers without a leaf: the handshake to them fails (ADR-0043). \
             Every node's leaf belongs as <id>.pem in this directory"
        );
    }

    peers
}

fn bind_admin_socket(path: &std::path::Path) -> Result<tokio::net::UnixListener, NodeError> {
    use std::os::unix::fs::PermissionsExt as _;

    if !tg_syscall::unix_path::fits(path) {
        let name = path
            .file_name()
            .map_or(0, |name| name.len() + 1)
            .min(tg_syscall::unix_path::MAX_PATH);
        return Err(NodeError::Serve(format!(
            "the admin socket '{}' is {} bytes long, the limit is {} \
             (sun_path); choose a shorter --data-dir: {} bytes remain for it",
            path.display(),
            path.as_os_str().len(),
            tg_syscall::unix_path::MAX_PATH,
            tg_syscall::unix_path::MAX_PATH - name,
        )));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| NodeError::Serve(err.to_string()))?;
    }
    let _ = std::fs::remove_file(path);

    let listener =
        tokio::net::UnixListener::bind(path).map_err(|err| NodeError::Serve(err.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| NodeError::Serve(err.to_string()))?;

    Ok(listener)
}

fn report_data_key(health: &tg_telemetry::probes::Health, data_key: Option<&str>) {
    let Some(fingerprint) = data_key
        .and_then(|text| tg_identity::secrets::DataKey::from_base64(text).ok())
        .map(|key| key.fingerprint())
    else {
        return;
    };

    health.on_scrape(tg_telemetry::names::DATA_KEY, move || {
        // The value is always `1`; the statement sits in the label.
        metrics::gauge!(tg_telemetry::names::DATA_KEY, "fingerprint" => fingerprint.clone())
            .set(1.0);
    });
}

fn data_keys(
    options: &Options,
    health: &tg_telemetry::probes::Health,
    state: tg_consensus::store::StateHandle,
) -> (Option<String>, Option<String>) {
    // **The data key is read, not created** (ADR-0095, determination 2). A `tgd`
    // that created it on demand would create a **different** one on every node --
    // and what the one sealed nobody would open afterwards, without anything
    // appearing anywhere. It comes from an operator (`tgctl secret keygen`), like
    // the join token.
    let primary = load_data_key(options, tg_identity::layout::SECRETS_KEY);
    // **The one being replaced, if a rotation is running** (ADR-0100). If the file
    // is missing, there is nothing to replace -- the normal case, and
    // `load_data_key` then does not report it as a shortcoming.
    let previous = load_data_key(options, tg_identity::layout::SECRETS_KEY_PREVIOUS);

    report_data_key(health, primary.as_deref());
    // **The number at which a rotation becomes completable** (ADR-0100,
    // determination 3). It stands only while one is running.
    report_secrets_previous(health, state, primary.as_deref(), previous.as_deref());

    (primary, previous)
}

fn report_secrets_previous(
    health: &tg_telemetry::probes::Health,
    state: tg_consensus::store::StateHandle,
    primary: Option<&str>,
    previous: Option<&str>,
) {
    let read = |text: Option<&str>| {
        text.and_then(|raw| tg_identity::secrets::DataKey::from_base64(raw).ok())
    };
    let (Some(primary), Some(previous)) = (read(primary), read(previous)) else {
        return;
    };

    let ring = tg_identity::secrets::KeyRing::new(primary, Some(previous));
    health.on_scrape(tg_telemetry::names::SECRETS_PREVIOUS, move || {
        let applied = state.read();
        let outstanding = applied
            .secret_material()
            .into_iter()
            .filter(|(_, sealed)| ring.needs_rekey(sealed))
            .count();
        metrics::gauge!(tg_telemetry::names::SECRETS_PREVIOUS)
            .set(f64::from(u32::try_from(outstanding).unwrap_or(u32::MAX)));
    });
}

fn load_signing(
    options: &Options,
    identity: &tg_identity::NodeIdentity,
    domain: &tg_identity::TrustDomain,
) -> (signer::Seats, Option<Signing>) {
    let (seats, notes) = signer::Seats::load(&options.data_dir, domain);
    for note in notes {
        tracing::warn!(%note, "signer list");
    }

    let signing = load_signing_ca(
        options,
        identity,
        &seats,
        &tokio::runtime::Handle::current(),
    );

    (seats, signing)
}

fn report_signing(
    health: &tg_telemetry::probes::Health,
    signing: Option<&Signing>,
    admitted: usize,
    data_dir: &std::path::Path,
) {
    if let Some(signing) = signing {
        let kind = signing.ca.signer_kind();
        health.on_scrape(tg_telemetry::names::SIGNER, move || {
            metrics::gauge!(tg_telemetry::names::SIGNER, "kind" => kind).set(1.0);
        });
    }

    // **Read in the scrape, not remembered** (ADR-0088): a generation changes at
    // most every few months, and a gauge that is set only at the refresh expires
    // after 15 minutes. What is read is the **seat**, because the truth value lies
    // there: a generation can lie on the disk that it does not hold (the reverse
    // too, if the write failed).
    if let Some(seat) = signing.and_then(|signing| signing.seat.as_ref()).cloned() {
        health.on_scrape(tg_telemetry::names::SIGNER_EPOCH, move || {
            let held = seat.epochs();
            let Some(newest) = held.last() else {
                // A seat without a generation is not constructible (`Participant`
                // holds at least one). An invented zero would be the more dangerous
                // lie -- it would look like a seat that lags behind.
                return;
            };
            #[expect(
                clippy::cast_precision_loss,
                reason = "a Prometheus metric is an f64; generation numbers stand here"
            )]
            metrics::gauge!(tg_telemetry::names::SIGNER_EPOCH).set(newest.number() as f64);
            #[expect(
                clippy::cast_precision_loss,
                reason = "a Prometheus metric is an f64; one or two stand here"
            )]
            metrics::gauge!(tg_telemetry::names::SIGNER_EPOCHS).set(held.len() as f64);
        });
    }

    // **Does the share lie sealed?** (ADR-0140, determination 8)
    //
    // **Read from the disk** in the scrape and not remembered at the start -- the
    // same rationale as with the generation beside it: a gauge that is set once
    // expires after 15 minutes (ADR-0088), and the disk is the truth. A remembered
    // value would moreover stay green if a refresh had added a generation
    // unsealed.
    //
    // Only the beginning of the file is read: the mark stands in the first eight
    // bytes, and reading in the whole share would be one more secret in memory
    // every fifteen seconds.
    if signing.is_some() {
        let share_at = tg_identity::threshold::share_path(data_dir);
        health.on_scrape(tg_telemetry::names::SIGNER_SEALED, move || {
            use std::io::Read as _;

            let mut head = [0_u8; 8];
            let sealed = std::fs::File::open(&share_at)
                .and_then(|mut file| file.read_exact(&mut head).map(|()| head))
                .is_ok_and(|head| tg_identity::threshold::is_envelope(&head));

            metrics::gauge!(tg_telemetry::names::SIGNER_SEALED).set(f64::from(u8::from(sealed)));
        });
    }

    health.on_scrape(tg_telemetry::names::SIGNER_SEATS, move || {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a Prometheus metric is an f64; five seats stand here"
        )]
        metrics::gauge!(tg_telemetry::names::SIGNER_SEATS).set(admitted as f64);
    });

    // **The fingerprint of the group key** (ADR-0107). It never changes over a
    // process's lifetime -- a refresh expressly leaves it the same -- and must stand
    // in the scrape all the same (ADR-0088): a gauge that is set once at the start
    // expires after 15 minutes, and with it the rule that reports a seat with a
    // foreign group.
    //
    // What is read is the **coordinator** and not the disk: there stands the key
    // this process really aggregates with.
    if let Some(group) = signing.and_then(|signing| signing.group.as_ref()).cloned() {
        health.on_scrape(tg_telemetry::names::SIGNER_GROUP, move || {
            let print = tg_identity::secrets::fingerprint(group.verifying_key());
            metrics::gauge!(tg_telemetry::names::SIGNER_GROUP, "fingerprint" => print).set(1.0);
        });
    }
}

pub struct Credentials<'a> {
    pub identity: &'a tg_identity::NodeIdentity,
    pub domain: &'a tg_identity::TrustDomain,
    pub raft_trust: tg_identity::SharedTrust,
}

pub struct Group {
    pub seat: Arc<tg_identity::threshold::LocalLink>,
    pub seats: signer::Seats,
    pub signer: Arc<tg_identity::threshold::ThresholdSigner>,
}

async fn operator_port(
    options: &Options,
    creds: &Credentials<'_>,
    node: &Node,
    projection: Arc<tg_store::Projection>,
    group: Option<admin::GroupState>,
) -> Result<
    Option<(
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
        tokio::task::JoinHandle<()>,
    )>,
    NodeError,
> {
    let Some(addr) = options.operator_listen else {
        return Ok(None);
    };

    let (snapshot, notes) = cluster::registry(node.state(), cluster::Registry::Operators);
    for note in notes {
        tracing::warn!(%note, "operator registration");
    }
    let admitted = snapshot.len();
    let trust = tg_identity::cluster::shared(snapshot);
    let refresher = cluster::refresh_trust(
        node.raft(),
        node.state().clone(),
        Arc::clone(&trust),
        cluster::Registry::Operators,
    );

    let tls = tg_identity::cluster::server_config(
        creds.identity,
        tg_identity::NodeVerifier::operators(creds.domain.clone(), trust),
    )
    .map_err(|err| NodeError::Options(err.to_string()))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| NodeError::Serve(err.to_string()))?;
    let service = admin::AdminService::new(
        node.id(),
        node.raft().clone(),
        node.state().clone(),
        projection,
        options.peers.clone(),
        group,
    );

    // **Without a registered operator it accepts nobody**, and that is said: a
    // port that stands open and refuses everybody looks from outside like one that
    // is broken. The first operator is registered over the socket (ADR-0103,
    // determination 3).
    if admitted == 0 {
        tracing::warn!(
            listen = %addr,
            "the operator port without a registered operator -- until the first \
             `tgctl operator enrol` it refuses everybody"
        );
    }
    tracing::info!(listen = %addr, admitted, "the operator port (mTLS)");

    Ok(Some((
        tokio::spawn(async move {
            watched()
                .add_service(service)
                .serve_with_incoming(cluster::accept(listener, tls))
                .await
        }),
        refresher,
    )))
}

async fn signer_port(
    options: &Options,
    creds: &Credentials<'_>,
    group: Option<Group>,
) -> Result<Option<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>>, NodeError> {
    match (group, options.signer_listen) {
        (Some(group), Some(addr)) => {
            let tls = tg_identity::cluster::server_config(
                creds.identity,
                tg_identity::NodeVerifier::new(
                    creds.domain.clone(),
                    tg_identity::cluster::shared(group.seats.trust()),
                ),
            )
            .map_err(|err| NodeError::Options(err.to_string()))?;
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|err| NodeError::Serve(err.to_string()))?;
            let admitted = group.seats.len();
            let service = signer::SignerService::new(group.seat, Arc::new(group.seats));
            tracing::info!(listen = %addr, admitted, "the signer port (mTLS)");
            Ok(Some(tokio::spawn(async move {
                watched()
                    .add_service(service)
                    .serve_with_incoming(cluster::accept(listener, tls))
                    .await
            })))
        }
        (Some(_), None) => Err(NodeError::Options(
            "group material lies there, but --signer-listen is missing: this node \
             holds a seat nobody can reach"
                .to_owned(),
        )),
        (None, Some(addr)) => {
            tracing::warn!(
                listen = %addr,
                "--signer-listen without group material -- there is no share to offer"
            );
            Ok(None)
        }
        (None, None) => Ok(None),
    }
}

async fn node_session(
    options: &Options,
    node: &Node,
    creds: &Credentials<'_>,
    feed: &projection::Feed,
) -> Result<
    (
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
        tokio::task::JoinHandle<()>,
    ),
    NodeError,
> {
    let (snapshot, notes) = cluster::session_trust(node.state());
    for note in notes {
        tracing::warn!(%note, "trust list");
    }
    let trust = tg_identity::cluster::shared(snapshot);
    let refresher =
        cluster::refresh_session_trust(node.raft(), node.state().clone(), Arc::clone(&trust));

    let tls = tg_identity::cluster::server_config(
        creds.identity,
        tg_identity::NodeVerifier::new(creds.domain.clone(), trust),
    )
    .map_err(|err| NodeError::Options(err.to_string()))?;
    let listener = tokio::net::TcpListener::bind(options.node_listen)
        .await
        .map_err(|err| NodeError::Serve(err.to_string()))?;
    // A service **of its own** beside the operator surface -- different callers,
    // different rights.
    let service = session::NodeService::new(
        node.id(),
        node.raft().clone(),
        node.state().clone(),
        feed.projection(),
    );
    tracing::info!(listen = %options.node_listen, "the node session (mTLS)");

    Ok((
        tokio::spawn(async move {
            watched()
                .add_service(service)
                .serve_with_incoming(cluster::accept(listener, tls))
                .await
        }),
        refresher,
    ))
}

fn watched() -> tonic::transport::Server {
    let interval =
        std::time::Duration::from_secs(tg_store::session::REPORT_EVERY_SECONDS.unsigned_abs());

    tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(interval))
        .http2_keepalive_timeout(Some(interval * 2))
}

async fn serve_all(
    options: &Options,
    node: &Node,
    creds: &Credentials<'_>,
    feed: &projection::Feed,
    spiffe: Option<identity::IdentityService>,
    group: Option<Group>,
) -> Result<(), NodeError> {
    // --- The three listeners (ADR-0043, determination 4) -------------------
    //
    // Separate, so that no service can forget to ask for the credential: the
    // admission is decided by the port, not by the handler behind it.

    // The Raft port: mTLS against the local peer list.
    let raft_tls = tg_identity::cluster::server_config(
        creds.identity,
        tg_identity::NodeVerifier::new(
            creds.domain.clone(),
            tg_identity::SharedTrust::clone(&creds.raft_trust),
        ),
    )
    .map_err(|err| NodeError::Options(err.to_string()))?;
    let raft_listener = tokio::net::TcpListener::bind(options.cluster_listen)
        .await
        .map_err(|err| NodeError::Serve(err.to_string()))?;
    let raft_service = RaftService::new(node.raft().clone());
    let raft_server = tokio::spawn(async move {
        watched()
            .add_service(raft_service)
            .serve_with_incoming(cluster::accept(raft_listener, raft_tls))
            .await
    });
    tracing::info!(listen = %options.cluster_listen, "the Raft port (mTLS)");

    let (session_server, _session_refresher) = node_session(options, node, creds, feed).await?;

    // The admin service: a **Unix socket**, no TCP port (ADR-0044). On it lies not
    // a part of the control but all of it -- up to `ChangeMembership`. The access is
    // thereby a question of file permissions, and those are answered by the
    // operating system; the counter-check over `SO_PEERCRED` stands in
    // `admin::may_administer`.
    let admin_socket = admin::socket_path(&options.data_dir, options.id);
    let admin_listener = bind_admin_socket(&admin_socket)?;
    let admin_service = admin::AdminService::new(
        node.id(),
        node.raft().clone(),
        node.state().clone(),
        feed.projection(),
        options.peers.clone(),
        group.as_ref().map(admin::GroupState::from),
    );
    let admin_server = tokio::spawn(async move {
        // **Without a keepalive** (ADR-0128, determination 2): this here is a
        // Unix socket. There is no partition there -- if the counterpart
        // disappears, EOF comes. A ping would be one against a problem the kernel
        // does not have.
        tonic::transport::Server::builder()
            .add_service(admin_service)
            .serve_with_incoming(tg_identity::workload_api::incoming(admin_listener))
            .await
    });
    tracing::info!(socket = %admin_socket.display(), "the admin socket");

    // The refresher is **held**, not collected: it runs as long as the process
    // runs, and a `select!` branch on it would end the node as soon as the metrics
    // channel closes. The same construction as with the node list's refresher
    // beside it.
    let (operator_serving, _operator_refresher) = match operator_port(
        options,
        creds,
        node,
        feed.projection(),
        group.as_ref().map(admin::GroupState::from),
    )
    .await?
    {
        Some((serving, refresher)) => (Some(serving), Some(refresher)),
        None => (None, None),
    };

    let signer_server = signer_port(options, creds, group).await?;

    // Identity: **no** client certificate, but TLS. `Join` can present none and
    // `Renew` must demand none (ADR-0043, determination 3) -- the other direction
    // is checked all the same: without it anybody could pass themselves off as the
    // control plane and accept a join, and the token would go to the wrong one.
    let open_tls = tg_identity::cluster::open_server_config(creds.identity)
        .map_err(|err| NodeError::Options(err.to_string()))?;
    let open_listener = tokio::net::TcpListener::bind(options.listen)
        .await
        .map_err(|err| NodeError::Serve(err.to_string()))?;
    let open_server = watched()
        .add_optional_service(spiffe)
        .serve_with_incoming(cluster::accept(open_listener, open_tls));

    // If one of the three ports falls, the node falls. A node that carries only
    // two of three stretches is harder to recognize than one that is gone -- and
    // the membership then replaces it cleanly (ADR-0031).
    tokio::select! {
        result = open_server => result.map_err(|err| NodeError::Serve(err.to_string())),
        result = raft_server => match result {
            Ok(inner) => inner.map_err(|err| NodeError::Serve(format!("the Raft port: {err}"))),
            Err(err) => Err(NodeError::Serve(format!("the Raft port: {err}"))),
        },
        result = session_server => match result {
            Ok(inner) => inner.map_err(|err| NodeError::Serve(format!("the session port: {err}"))),
            Err(err) => Err(NodeError::Serve(format!("the session port: {err}"))),
        },
        result = admin_server => match result {
            Ok(inner) => inner.map_err(|err| NodeError::Serve(format!("the admin socket: {err}"))),
            Err(err) => Err(NodeError::Serve(format!("the admin socket: {err}"))),
        },
        // In the `None` case `OptionFuture` returns `Some(None)` **at once** --
        // the `Some(result) =` pattern catches it, and `select!` discards the
        // branch afterwards. Without the pattern a node without a seat would end
        // itself at the first poll.
        Some(result) = futures_util::future::OptionFuture::from(signer_server) => match result {
            Ok(inner) => inner.map_err(|err| NodeError::Serve(format!("the signer port: {err}"))),
            Err(err) => Err(NodeError::Serve(format!("the signer port: {err}"))),
        },
        Some(result) = futures_util::future::OptionFuture::from(operator_serving) => match result {
            Ok(inner) => inner.map_err(|err| NodeError::Serve(format!("the operator port: {err}"))),
            Err(err) => Err(NodeError::Serve(format!("the operator port: {err}"))),
        },
    }
}

fn load_data_key(options: &Options, name: &str) -> Option<String> {
    let path = tg_identity::layout::dir(&options.data_dir).join(name);

    let Ok(text) = std::fs::read_to_string(&path) else {
        // **Only the primary one is missing notably.** A missing key being
        // replaced is the normal state (ADR-0100): no rotation is running right
        // now. Reporting it would be noise that covers the real message.
        if name == tg_identity::layout::SECRETS_KEY {
            tracing::warn!(
                path = %path.display(),
                "no data key -- there are no secrets on this cluster (ADR-0095)"
            );
        }
        return None;
    };

    // **Checked, not passed through.** A text that is no key otherwise stands out
    // only at the agent -- and there it looks like an error of the agent's.
    if let Err(err) = tg_identity::secrets::DataKey::from_base64(&text) {
        tracing::error!(
            path = %path.display(),
            error = %err,
            "the data key is unreadable -- it is not passed on"
        );
        return None;
    }

    Some(text.trim().to_owned())
}

pub struct Signing {
    pub ca: identity::SigningCa,
    pub seat: Option<Arc<tg_identity::threshold::LocalLink>>,
    pub group: Option<Arc<tg_identity::threshold::ThresholdSigner>>,
}

fn prepare_custody(
    data_dir: &std::path::Path,
) -> Option<Arc<dyn tg_identity::threshold::ShareCustody>> {
    use tg_identity::threshold::Material;

    // If a TPM is there it is used; if none is there `custody_for` says so and the
    // share lies open as before.
    let signing_dir = tg_identity::layout::signing(data_dir);
    let custody = match tg_identity::threshold::custody_for(&signing_dir) {
        Ok(custody) => custody,
        Err(err) => {
            tracing::error!(error = %err, "the custody is not ready -- the seat keeps still");
            return None;
        }
    };

    // **What lies open is sealed** -- at the start and without a handgrip
    // (ADR-0140, determination 9). A step a human has to carry out is one they
    // forget on one of five nodes.
    match Material::adopt(data_dir, custody.as_ref()) {
        Ok(adopted) if !adopted.is_empty() => {
            tracing::info!(
                generations = adopted.len(),
                "shares taken over into the TPM (ADR-0140)"
            );
        }
        Ok(_) => {}
        Err(err) => {
            // **No running on.** `adopt` replaces only after the counter-check, so
            // everything still lies there -- but a node that cannot seal its share
            // shall report that and not carry on unsealed.
            tracing::error!(error = %err, "the share cannot be taken over -- the seat keeps still");
            return None;
        }
    }

    Some(custody)
}

fn load_group(
    options: &Options,
    identity: &tg_identity::NodeIdentity,
    domain: &tg_identity::TrustDomain,
    seats: &signer::Seats,
    runtime: &tokio::runtime::Handle,
) -> Option<(
    Arc<tg_identity::threshold::ThresholdSigner>,
    Arc<tg_identity::threshold::LocalLink>,
)> {
    use tg_identity::threshold::{
        GroupShape, GrpcLink, LocalLink, Material, OsEntropy, Seat, SignerLink,
    };

    if !tg_identity::threshold::share_path(&options.data_dir).exists() {
        return None;
    }

    // **All** generations, not only the highest (ADR-0107, determination 3):
    // during a refresh a seat holds two, and the old one is the one in which `t`
    // seats are guaranteed to come together.
    let held = match tg_identity::threshold::epochs(&options.data_dir) {
        Ok(held) if !held.is_empty() => held,
        Ok(_) => {
            tracing::error!("no group material under signing/");
            return None;
        }
        Err(err) => {
            tracing::error!(error = %err, "the group material is unusable");
            return None;
        }
    };

    let custody = prepare_custody(&options.data_dir)?;

    let mut versions = Vec::new();
    for epoch in held {
        // **Here the share is opened, in the start** (ADR-0140, determination 6):
        // a TPM problem stands out now and not only when a workload needs an
        // SVID.
        match Material::load_epoch(&options.data_dir, epoch, custody.as_ref()) {
            Ok(material) => versions.push(material),
            Err(err) => {
                tracing::error!(epoch = epoch.number(), error = %err, "the generation is unusable");
                return None;
            }
        }
    }

    let Some(material) = versions.last() else {
        // Not reachable -- `held` is checked above as not empty, and the loop
        // aborts at every error. An `expect` would be a panic in a node's startup
        // path all the same.
        tracing::error!("no group material under signing/");
        return None;
    };
    let mine = material.seat();

    // Our own seat belongs **not** in `--signer`: it is run locally, and an
    // address for it would be a call to ourselves over mTLS -- with our own leaf in
    // our own trust list.
    if options.signers.contains_key(&mine.number()) {
        tracing::warn!(
            seat = mine.number(),
            "--signer names our own seat; it is run locally and the setting is \
             passed over"
        );
    }

    let mut remote: Vec<Arc<dyn SignerLink>> = Vec::new();
    for (&number, url) in &options.signers {
        if number == mine.number() {
            continue;
        }
        let seat = match Seat::new(number) {
            Ok(seat) => seat,
            Err(err) => {
                tracing::error!(seat = number, error = %err, "the seat is unusable");
                return None;
            }
        };
        let Some(channel) = seats.dial(number, url, identity, domain) else {
            tracing::error!(
                seat = number,
                url = %url,
                "no channel to this seat -- is its leaf missing under signers/?"
            );
            return None;
        };
        remote.push(Arc::new(GrpcLink::new(seat, channel, runtime.clone())));
    }

    let entropy: Box<dyn tg_identity::threshold::Entropy> = Box::new(OsEntropy);
    let mut participant = match tg_identity::threshold::Participant::new(
        mine,
        material.share(),
        material.group(),
        material.epoch(),
        custody,
    ) {
        Ok(participant) => participant,
        Err(err) => {
            tracing::error!(error = %err, "the share is not sealable");
            return None;
        }
    };
    for older in &versions[..versions.len() - 1] {
        if let Err(err) = participant.stage_share(older.epoch(), older.share(), older.group()) {
            tracing::error!(epoch = older.epoch().number(), error = %err, "the share is not sealable");
            return None;
        }
    }
    // **And it writes a new generation onto the disk** (ADR-0107,
    // determination 5): the same directory it was loaded from. Without that a
    // restart would lose every refresh -- harmless, because the old generation goes
    // on signing, but an operator would take it for settled.
    let seat = Arc::new(LocalLink::new(participant, entropy).persisting_to(&options.data_dir));

    // **Our own seat needs the others** -- for round 2 of a refresh (ADR-0107):
    // the directed packets go from seat to seat, not over the coordinator. They are
    // attached after the build, because the peers arise before our own seat and a
    // cycle in the build would otherwise be unavoidable.
    seat.attach_peers(remote.clone());

    let mut links: Vec<Arc<dyn SignerLink>> = vec![Arc::clone(&seat) as Arc<dyn SignerLink>];
    links.extend(remote);

    let groups = versions
        .into_iter()
        .map(|material| (material.epoch(), material.into_group()))
        .collect();

    match tg_identity::threshold::ThresholdSigner::over(groups, GroupShape::adr_0014(), links) {
        Ok(signer) => Some((Arc::new(signer), seat)),
        Err(err) => {
            tracing::error!(error = %err, "the signing group is unusable");
            None
        }
    }
}

fn load_signing_ca(
    options: &Options,
    node_identity: &tg_identity::NodeIdentity,
    seats: &signer::Seats,
    runtime: &tokio::runtime::Handle,
) -> Option<Signing> {
    let dir = tg_identity::layout::signing(&options.data_dir);
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).ok();

    // `bundle.pem` is named here as under `identity/` -- **deliberately**: the same
    // form, so that an operator does not have to keep two conventions in mind. It
    // is not the same file.
    //
    // **`ca.key.pem` is expressly no longer mandatory** (ADR-0097,
    // determination 3): on a node that runs the group it does not exist, and that
    // is the property for whose sake this path exists -- it is readable off the
    // **absence of a file**.
    let (certificate, bundle) = (
        read(tg_identity::layout::CA)?,
        read(tg_identity::layout::BUNDLE)?,
    );
    let domain = match tg_identity::TrustDomain::new(options.trust_domain.clone()) {
        Ok(domain) => domain,
        Err(err) => {
            tracing::error!(error = %err, "the trust domain is unusable");
            return None;
        }
    };

    // The group first, the key in memory as the fallback (ADR-0097,
    // determination 6). Which it became is said by the metric.
    if let Some((signer, seat)) = load_group(options, node_identity, &domain, seats, runtime) {
        let group = Arc::clone(&signer);

        return match identity::SigningCa::with_signer(
            &certificate,
            tg_identity::Signer::Group(signer),
            bundle,
            domain,
        ) {
            Ok(ca) => {
                tracing::info!(
                    seat = tg_identity::threshold::SignerLink::seat(seat.as_ref()).number(),
                    "the signing CA: the group (ADR-0014)"
                );
                Some(Signing {
                    ca,
                    seat: Some(seat),
                    group: Some(group),
                })
            }
            Err(err) => {
                tracing::error!(error = %err, "the group CA is unusable");
                None
            }
        };
    }

    let Some(key) = read(tg_identity::layout::CA_KEY) else {
        tracing::error!(
            path = %dir.join(tg_identity::layout::CA_KEY).display(),
            "no group material and no CA key -- this node issues nothing"
        );
        return None;
    };

    match identity::SigningCa::new(&certificate, &key, bundle, domain) {
        Ok(ca) => {
            tracing::warn!("the signing CA: a key in memory -- not the model from ADR-0014");
            Some(Signing {
                ca,
                seat: None,
                group: None,
            })
        }
        Err(err) => {
            tracing::error!(error = %err, "the signing material is unusable");
            None
        }
    }
}
