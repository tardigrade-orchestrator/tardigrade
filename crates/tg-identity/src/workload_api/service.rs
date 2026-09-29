//! The service behind the socket (ADR-0035).
//!
//! # The streams are the rotation mechanism
//!
//! `FetchX509SVID` and `FetchX509Bundles` are **server-streaming** in the
//! specification, and that is no formality. The client holds the stream open; as
//! soon as the rotation becomes due, the server sends the new SVID **of its own
//! accord**. A client that had to poll would have to guess how often -- and with a
//! 15 min TTL and rotation after 7 min ADR-0014 chose a profile at which guessing
//! wrongly is expensive.
//!
//! # Why the attestation happens per call and not per connection
//!
//! It happens per **call** although the credentials hang on the connection. The
//! reason is the stream: it runs for a long time, and what authorizes it can change
//! in the meantime -- the workload's assignment to this node, say (ADR-0006,
//! authority binding). That is why the question is asked anew at **every** issuance,
//! not only at the setup. If the assignment falls away, the stream ends.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status};

use crate::agent::{Minter, Refusal};
use crate::attest::Attestation;
use crate::lifetime::UnixSeconds;
use crate::workload_api::pb::spiffe_workload_api_server::{
    SpiffeWorkloadApi, SpiffeWorkloadApiServer,
};
use crate::workload_api::pb::{
    JwtBundlesRequest, JwtBundlesResponse, JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest,
    ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse, X509svid, X509svidRequest,
    X509svidResponse,
};

/// The header the specification demands.
///
/// It is no secret and no authentication -- it is a barrier against the
/// **unsuspecting** caller. A browser or a general gRPC console does not set it; a
/// client that wants to speak the workload API always sets it. The specification
/// demands that the server refuse without it, and we do that -- accepting and
/// ignoring would be the sort of carelessness one finds again later as a gap.
const SPIFFE_HEADER: &str = "workload.spiffe.io";

/// The `hint` of one's own identity (ADR-0036).
pub const HINT_SELF: &str = "self";

/// The `hint` of the delegated identity (ADR-0036).
///
/// It belongs to the workload this container proxies for -- it uses it on the mesh
/// wire so that the `may_talk` edges read what the operator wrote (ADR-0025).
pub const HINT_DELEGATED: &str = "delegated";

/// One entry of the answer.
fn entry(svid: &crate::mint::Svid, chain: &[u8], bundle: &[u8], hint: &str) -> X509svid {
    // The chain: leaf first, then the agent intermediate. The specification is
    // literal at this place -- "the leaf certificate (or SVID itself) MUST come
    // first".
    let mut chain_der = svid.certificate_der().to_vec();
    chain_der.extend_from_slice(chain);

    X509svid {
        spiffe_id: svid.id().to_string(),
        x509_svid: chain_der,
        x509_svid_key: svid.private_key_der().to_vec(),
        bundle: bundle.to_vec(),
        hint: hint.to_owned(),
    }
}

/// The service's clock.
///
/// As a trait, because the whole SVID path has taken the time in instead of reading
/// it since 7a (ADR-0024): a test shall be able to provide it.
pub trait Clock: Send + Sync + 'static {
    /// Now, in Unix seconds UTC.
    fn now(&self) -> UnixSeconds;
}

/// The system's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixSeconds {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
            })
    }
}

/// The counterpart's credentials, set by the kernel.
///
/// That is the attestation basis from ADR-0006. It comes from `SO_PEERCRED` and is
/// **not forgeable**: the caller does not write it, the kernel sets it at the
/// `connect`.
///
/// # Why no PID stands here (ADR-0053, ADR-0081)
///
/// A remembered PID can lose its meaning: if the process dies, the kernel reassigns
/// it -- and the connection outlives it, measured (a connector that forks and dies
/// leaves it to its child). Whoever holds it fast at the `accept` and later reads
/// `/proc` with it possibly reads a **different** process. That was ADR-0053's
/// finding.
///
/// Its answer was a **handle** (`SO_PEERPIDFD`), from which the number arises anew
/// at every call -- and that cost kernel >= 6.5 as an operational prerequisite of
/// the identity path. **ADR-0081 replaced it:** every container gets its own socket,
/// mounted into exactly it, and with that the question is moot. Neither PID nor
/// handle stands here; `SO_PEERPIDFD` and the cgroup read have fallen away.
///
/// The note stands nevertheless because it names the trap: whoever one day holds a
/// PID fast again has ADR-0053's finding back.
#[derive(Debug, Clone)]
pub struct PeerCredentials {
    /// The identifier of the socket it reached (ADR-0081).
    ///
    /// **The socket is the attestation**: every container gets its own, mounted into
    /// exactly it (ADR-0079). Whoever reached it is in this container -- and that is
    /// the only question `attest` has to ask.
    ///
    /// `None` on a socket that belongs to no instance: the admin socket (ADR-0044)
    /// authorizes over the `uid` and needs none. For an SVID it is refused there.
    pub container: Option<Arc<str>>,
    /// Its UID.
    pub uid: u32,
    /// Its GID.
    pub gid: u32,
}

/// A socket connection together with its credentials.
///
/// The detour over a type of its own is necessary because `tonic` collects the
/// connection information over [`Connected`] and `UnixStream` does not deliver that
/// of its own accord.
#[derive(Debug)]
pub struct PeerStream {
    inner: UnixStream,
    credentials: PeerCredentials,
}

impl Connected for PeerStream {
    type ConnectInfo = PeerCredentials;

    fn connect_info(&self) -> Self::ConnectInfo {
        // Cloned instead of copied, since the handle travels along (ADR-0053). The
        // clone is an `Arc` count: the descriptor stays **one**, and it falls with
        // the last connection that holds it.
        self.credentials.clone()
    }
}

impl tokio::io::AsyncRead for PeerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PeerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The stream of the incoming connections, each with its credentials.
///
/// A connection whose credentials cannot be read is
/// **dropped** and not served without them: without them there is no attestation,
/// and without an attestation there is no SVID.
///
/// # The failure of accepting is answered here
///
/// That was once a `filter_map` with `accepted.ok()?` -- a failure of `accept`
/// thereby fell silently to the floor, the stream was polled again, and because
/// `accept` does not consume the waiting connection on `EMFILE`, the loop spun at
/// full speed. On this socket hang the SVIDs of every workload of this node
/// (ADR-0035) and in `tgd` the admin access (ADR-0044).
///
/// The error type is therefore [`std::convert::Infallible`]: the stream delivers a
/// connection or waits, but it never fails.
pub fn incoming(
    listener: UnixListener,
) -> impl Stream<Item = Result<PeerStream, std::convert::Infallible>> + Send {
    incoming_for(listener, None)
}

/// As [`incoming`], with the socket's identifier (ADR-0081).
///
/// Every connection over this listener carries it -- and thereby the statement of
/// which container its caller runs in. Separate from [`incoming`], because the admin
/// socket (ADR-0044) has none and needs none.
pub fn incoming_for(
    listener: UnixListener,
    container: Option<Arc<str>>,
) -> impl Stream<Item = Result<PeerStream, std::convert::Infallible>> + Send {
    futures_util::stream::unfold((listener, container), |(listener, container)| async move {
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(error) => {
                    if let Some(pause) = tg_syscall::accept::classify(&error).pause() {
                        tracing::warn!(%error, "the Unix socket does not accept -- waiting");
                        tokio::time::sleep(pause).await;
                    }
                    continue;
                }
            };

            let Some(credentials) = stream.peer_cred().ok().map(|cred| PeerCredentials {
                container: container.clone(),
                uid: cred.uid(),
                gid: cred.gid(),
            }) else {
                // It is dropped -- and **said**: without credentials there is no
                // attestation and thereby no SVID (ADR-0006). A silent drop would
                // not be distinguishable from a network problem.
                tracing::warn!("a connection without readable credentials was refused");
                continue;
            };

            return Some((
                Ok(PeerStream {
                    inner: stream,
                    credentials,
                }),
                (listener, container),
            ));
        }
    })
}

struct Inner<S: rcgen::SigningKey> {
    minter: Mutex<Minter<S>>,
    clock: Arc<dyn Clock>,
    /// The trust domain's trust anchors, DER-encoded.
    ///
    /// They come from the Raft state (ADR-0014, bootstrap) and are only distributed
    /// here -- the agent does not produce them.
    trust_bundle: Mutex<Vec<Vec<u8>>>,
}

/// A node's workload API service.
pub struct WorkloadApi<S: rcgen::SigningKey> {
    inner: Arc<Inner<S>>,
}

impl<S: rcgen::SigningKey> Clone for WorkloadApi<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S: rcgen::SigningKey> std::fmt::Debug for WorkloadApi<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadApi").finish_non_exhaustive()
    }
}

impl<S: rcgen::SigningKey + Send + Sync + 'static> WorkloadApi<S> {
    /// A service over this issuing service.
    #[must_use]
    pub fn new(minter: Minter<S>, trust_bundle: Vec<Vec<u8>>, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Arc::new(Inner {
                minter: Mutex::new(minter),
                clock,
                trust_bundle: Mutex::new(trust_bundle),
            }),
        }
    }

    /// Swaps the trust bundle -- the control plane distributed a new one.
    pub fn set_trust_bundle(&self, bundle: Vec<Vec<u8>>) {
        if let Ok(mut slot) = self.inner.trust_bundle.lock() {
            *slot = bundle;
        }
    }

    /// Takes over a freshly fetched agent intermediate (ADR-0006/0037).
    ///
    /// The same reason as at [`Self::set_assigned`], only with more weight: the
    /// material on the disk is replaced every three hours, and whoever does not take
    /// it over mints from an expired intermediate after twelve hours (ADR-0014).
    /// What happens to the issued SVIDs in the process stands at
    /// [`Minter::adopt`].
    pub fn adopt(
        &self,
        authority: crate::Authority<S>,
        intermediate_until: crate::lifetime::UnixSeconds,
    ) {
        if let Ok(mut minter) = self.inner.minter.lock() {
            minter.adopt(authority, intermediate_until);
        }
    }

    /// Sets the node's assignments anew (ADR-0019: from the local cache).
    pub fn set_assigned(&self, assigned: std::collections::BTreeMap<String, String>) {
        if let Ok(mut minter) = self.inner.minter.lock() {
            minter.set_assigned(assigned);
        }
    }

    /// Sets the delegations anew (ADR-0036).
    ///
    /// As [`Self::set_assigned`] and for the same reason: a node's desired state
    /// changes while the service runs. A sidecar that joins after the start would
    /// otherwise never get its workload's SVID.
    pub fn set_delegations(&self, delegations: BTreeMap<String, String>) {
        if let Ok(mut minter) = self.inner.minter.lock() {
            minter.set_delegations(delegations);
        }
    }

    /// The service as a `tonic` server.
    #[must_use]
    pub fn into_server(self) -> SpiffeWorkloadApiServer<Self> {
        SpiffeWorkloadApiServer::new(self)
    }
}

/// Enforces the header from the specification.
fn require_header<T>(request: &Request<T>) -> Result<(), Status> {
    let present = request
        .metadata()
        .get(SPIFFE_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "true");

    if present {
        return Ok(());
    }

    Err(Status::invalid_argument(format!(
        "the header '{SPIFFE_HEADER}: true' is missing -- the SPIFFE Workload API \
         demands it from every caller"
    )))
}

/// Translates a refusal into a gRPC status.
///
/// Kept coarse, for the same reason as in 7a: the answer goes to a process that
/// could not just now identify itself.
fn refusal(reason: &Refusal) -> Status {
    // **The wire gets the coarse information, the log the reason.**
    //
    // Until here it died entirely: the caller read "not admitted on this node", and
    // the node wrote nothing -- whoever can do something about it learned neither the
    // workload nor the deadline. The same shape as `tg_proxy::tls::alert`: one
    // translation, two addressees.
    //
    // `warn!` and not `error!`: a refusal is the normal case of a node that does not
    // mint for everybody (ADR-0006) -- it is notable and no defect. The volume is the
    // responsibility of whoever starts the process (`tg_telemetry::init`: to stderr,
    // not into a file).
    tracing::warn!(%reason, "the SVID was refused");

    match reason {
        Refusal::NotAttested => Status::permission_denied("not attested"),
        Refusal::NotAssigned { .. } | Refusal::UnknownContainer { .. } => {
            Status::permission_denied("not admitted on this node")
        }
        Refusal::IntermediateExpired { .. } => {
            Status::unavailable("the node cannot issue at the moment")
        }
        Refusal::MintFailed { .. } => Status::internal("the issuance failed"),
    }
}

/// The status for the specification's JWT half.
fn jwt_deferred() -> Status {
    Status::unimplemented(
        "JWT-SVID is not implemented: ADR-0025 expressly defers it (option C). \
         This server offers the X.509 profile.",
    )
}

type SvidStream = Pin<Box<dyn Stream<Item = Result<X509svidResponse, Status>> + Send>>;
type BundleStream = Pin<Box<dyn Stream<Item = Result<X509BundlesResponse, Status>> + Send>>;
type JwtBundleStream = Pin<Box<dyn Stream<Item = Result<JwtBundlesResponse, Status>> + Send>>;

impl<S: rcgen::SigningKey + Send + Sync + 'static> Inner<S> {
    /// Attests a request's caller.
    ///
    /// **The socket is the attestation** (ADR-0081): every container gets its own,
    /// mounted into exactly it (ADR-0079) -- whoever reached it is in this container.
    ///
    /// With that the chain is single-stage. Previously it was four steps, three of
    /// them kernel interfaces, and every one of them has already delivered a finding
    /// once: `SO_PEERCRED` was unsafe (ADR-0053), the cgroup path was a foreign
    /// program's default, and the backwards computation from the identifier to the
    /// name was wrong (ADR-0065).
    fn attest<T>(request: &Request<T>) -> Result<Attestation, Status> {
        require_header(request)?;

        let credentials = request
            .extensions()
            .get::<PeerCredentials>()
            .cloned()
            .ok_or_else(|| {
                // Without credentials no SVID. That is the case in which the
                // service was not reached over the Unix socket -- then there is no
                // kernel that vouches for the caller.
                tracing::warn!("a request without credentials -- it did not come over the socket");
                Status::permission_denied("no credentials on this connection")
            })?;

        let container = credentials.container.as_deref().ok_or_else(|| {
            // The case is a socket that belongs to no instance -- the admin socket
            // (ADR-0044), say, which authorizes over the uid.
            tracing::warn!("a request over a socket without an instance -- no SVID");
            Status::permission_denied("this socket belongs to no instance")
        })?;

        Attestation::from_socket(container).ok_or_else(|| {
            // The identifier stands in the log: it comes from **our** listener, so
            // an implausible one is a finding about us and not about the caller.
            tracing::warn!(container, "an implausible identifier at the socket");
            // Deliberately without a name: the refusal goes to a process that could
            // not just now identify itself, and shall not give away which workloads
            // exist on this node.
            Status::permission_denied("not attested")
        })
    }

    /// Counts a call on the name of its caller (ADR-0079).
    ///
    /// **Without a name nothing is counted.** A caller whose identifier this node
    /// does not know has no workload name -- counting it under an invented label
    /// would be a number that looks like a statement. That it was refused is said by
    /// `SVID_ISSUED` with `outcome = "refused"`.
    fn note_call(&self, attestation: &Attestation) {
        let Ok(minter) = self.minter.lock() else {
            return;
        };
        let Some(workload) = minter.workload_of(attestation) else {
            return;
        };
        metrics::counter!(
            tg_telemetry::names::WORKLOAD_API_CALLS,
            "workload" => workload.to_owned(),
        )
        .increment(1);
    }

    fn issue(&self, attestation: &Attestation) -> Result<(X509svidResponse, Duration), Status> {
        let now = self.clock.now();
        let mut minter = self
            .minter
            .lock()
            .map_err(|_| Status::internal("the issuing service is not available"))?;

        let chain = minter.chain_der().to_vec();
        let lifetime = minter.lifetime();
        let bundle = self
            .trust_bundle
            .lock()
            .map_err(|_| Status::internal("the trust bundle is not readable"))?
            .concat();

        let own = minter
            .svid_for(attestation, now)
            .map_err(|reason| refusal(&reason))?
            .clone();
        let wait = until_rotation(own.validity(), lifetime, now);

        // One's own identity stands **first**. A client that does not read `hint`
        // takes the first entry -- and shall then get the narrower identity, not the
        // wider one. Our sidecar chooses expressly by `hint`; if it forgot, it would
        // fail visibly at the policy instead of quietly talking with foreign
        // authority.
        let mut svids = vec![entry(&own, &chain, &bundle, HINT_SELF)];

        // The workload is resolved **forwards** (ADR-0065) -- from the identifier
        // `tg-api-proxy-1` no name could be computed.
        if let Some(target) = minter
            .workload_of(attestation)
            .and_then(|workload| minter.delegation_of(workload))
            .map(str::to_owned)
        {
            let delegated = minter
                .svid_named(&target, now)
                .map_err(|reason| refusal(&reason))?
                .clone();
            svids.push(entry(&delegated, &chain, &bundle, HINT_DELEGATED));
        }

        Ok((
            X509svidResponse {
                svids,
                crl: Vec::new(),
                federated_bundles: std::collections::HashMap::new(),
            },
            wait,
        ))
    }

    fn bundles(&self) -> Result<X509BundlesResponse, Status> {
        let domain = {
            let minter = self
                .minter
                .lock()
                .map_err(|_| Status::internal("the issuing service is not available"))?;
            minter.domain().clone()
        };
        let bundle = self
            .trust_bundle
            .lock()
            .map_err(|_| Status::internal("the trust bundle is not readable"))?
            .concat();

        let mut bundles = std::collections::HashMap::new();
        bundles.insert(format!("spiffe://{domain}"), bundle);

        Ok(X509BundlesResponse {
            crl: Vec::new(),
            bundles,
        })
    }
}

#[tonic::async_trait]
impl<S: rcgen::SigningKey + Send + Sync + 'static> SpiffeWorkloadApi for WorkloadApi<S> {
    type FetchX509SVIDStream = SvidStream;
    type FetchX509BundlesStream = BundleStream;
    type FetchJWTBundlesStream = JwtBundleStream;

    async fn fetch_x509svid(
        &self,
        request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        let attestation = Inner::<S>::attest(&request)?;

        // The first issuance happens **here**, not in the task. With that an
        // unauthorized request fails immediately and typed instead of opening a
        // stream that then stays empty.
        let (first, mut wait) = self.inner.issue(&attestation)?;
        // **Here and not in `issue`** (ADR-0079): what is counted is the **call**,
        // not the issuance. A stream that rotates every thirteen minutes for twelve
        // hours is one use of the socket and not fifty-five -- and precisely that
        // question ("who uses it") ADR-0079 left open.
        self.inner.note_call(&attestation);

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            if tx.send(Ok(first)).await.is_err() {
                return;
            }

            loop {
                tokio::time::sleep(wait).await;

                // Attest anew: the stream runs for a long time, and the workload's
                // assignment to this node can be gone in the meantime.
                match inner.issue(&attestation) {
                    Ok((response, next)) => {
                        wait = next;
                        if tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                    }
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        return;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    /// Serves the `FetchX509Bundles` server-streaming call.
    ///
    /// # Parameters
    ///
    /// - `request`: the incoming request to attest and serve.
    ///
    /// # Returns
    ///
    /// A single-item stream carrying the current trust bundle.
    ///
    /// # Errors
    ///
    /// [`Status`] when the caller cannot be attested or the bundle cannot
    /// be read.
    async fn fetch_x509_bundles(
        &self,
        request: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        // Here too attestation happens. The specification names this call for
        // clients that only want to verify -- but this socket lies in a container,
        // and whoever does not run in a container of this orchestrator has no
        // business at it. The assignment to the node is **not** demanded: a trust
        // anchor is public.
        let attestation = Inner::<S>::attest(&request)?;
        let bundles = self.inner.bundles()?;
        // **This call counts too**: whoever only fetches the anchor uses
        // the socket likewise -- and a workload that does *only* that is precisely
        // the information an operator looks for.
        self.inner.note_call(&attestation);

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx.try_send(Ok(bundles));

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    /// Answers `FetchJWTSVID` with `UNIMPLEMENTED`.
    ///
    /// # Parameters
    ///
    /// - `_request`: unused -- the JWT profile is deferred entirely.
    ///
    /// # Returns
    ///
    /// Never returns `Ok`.
    ///
    /// # Errors
    ///
    /// Always [`Status::unimplemented`].
    async fn fetch_jwtsvid(
        &self,
        _request: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        Err(jwt_deferred())
    }

    /// Answers `FetchJWTBundles` with `UNIMPLEMENTED`.
    ///
    /// # Parameters
    ///
    /// - `_request`: unused -- the JWT profile is deferred entirely.
    ///
    /// # Returns
    ///
    /// Never returns `Ok`.
    ///
    /// # Errors
    ///
    /// Always [`Status::unimplemented`].
    async fn fetch_jwt_bundles(
        &self,
        _request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        Err(jwt_deferred())
    }

    /// Answers `ValidateJWTSVID` with `UNIMPLEMENTED`.
    ///
    /// # Parameters
    ///
    /// - `_request`: unused -- the JWT profile is deferred entirely.
    ///
    /// # Returns
    ///
    /// Never returns `Ok`.
    ///
    /// # Errors
    ///
    /// Always [`Status::unimplemented`].
    async fn validate_jwtsvid(
        &self,
        _request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        Err(jwt_deferred())
    }
}

/// Runs the service on a Unix socket until the shutdown signal comes.
///
/// # Errors
///
/// `tonic`'s transport error.
pub async fn serve<S: rcgen::SigningKey + Send + Sync + 'static>(
    api: WorkloadApi<S>,
    listener: UnixListener,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<(), tonic::transport::Error> {
    serve_on(api, incoming(listener), shutdown).await
}

/// As [`serve`], on a ready-made stream.
///
/// Since ADR-0081 the stream carries the socket's identifier -- the caller builds it
/// with [`incoming_for`], and the service then knows at every connection which
/// container its caller runs in.
///
/// # Errors
///
/// `tonic`'s transport error.
pub async fn serve_on<S: rcgen::SigningKey + Send + Sync + 'static>(
    api: WorkloadApi<S>,
    incoming: impl Stream<Item = Result<PeerStream, std::convert::Infallible>> + Send,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<(), tonic::transport::Error> {
    tonic::transport::Server::builder()
        .add_service(api.into_server())
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
}

/// How long is waited until the next rotation.
///
/// At least one second: a stream that pushes without a pause would be a loop that
/// keeps the node busy without anything changing.
fn until_rotation(
    validity: crate::lifetime::Validity,
    lifetime: crate::lifetime::Lifetime,
    now: UnixSeconds,
) -> Duration {
    let due_at =
        validity.not_before() + i64::try_from(lifetime.rotate_after.as_secs()).unwrap_or(0);
    let remaining = due_at.saturating_sub(now).max(1);

    Duration::from_secs(u64::try_from(remaining).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::refusal;
    use crate::agent::Refusal;

    /// Collects what `tracing` writes.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            let guard = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn logged(reason: &Refusal) -> String {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let _ = refusal(reason);
        });

        captured.text()
    }

    /// **The operator learns which workload got no SVID.**
    ///
    /// The answer to the container is deliberately coarse -- it goes to a process
    /// that could not just now identify itself, and shall not give away which
    /// workloads exist here. Exactly for that reason the reason died **entirely**
    /// until here: the caller got "not admitted on this node", and the node wrote
    /// nothing.
    #[test]
    fn a_refused_workload_is_named_in_the_log() {
        let text = logged(&Refusal::NotAssigned {
            workload: "payments".to_owned(),
        });

        assert!(
            text.contains("payments"),
            "the name belongs in the log, not on the wire: {text}"
        );
    }

    /// And the expired intermediate names its deadline.
    ///
    /// That is the case in which **all** the workloads of this node fail at the same
    /// time (ADR-0014). The caller gets "the node cannot issue at the moment";
    /// whoever can do something about it needs the number.
    #[test]
    fn an_expired_intermediate_names_its_deadline() {
        let text = logged(&Refusal::IntermediateExpired {
            expired_at: 1_800_000_000,
        });

        assert!(text.contains("1800000000"), "{text}");
    }

    /// The refusal without a name stays without a name -- in the log too there is
    /// none, for none is known.
    #[test]
    fn an_unattested_caller_is_logged_without_inventing_a_name() {
        let text = logged(&Refusal::NotAttested);

        assert!(!text.is_empty(), "that belongs reported too");
        assert!(text.contains("container"), "{text}");
    }
}
