//! The standardized SPIFFE workload API (ADR-0035, phase 7c).
//!
//! # Why a foreign client stands here
//!
//! This cut's acceptance expressly demands that a **foreign** client speak the socket.
//! The reason is that a test against our own generated client would have shown only
//! self-consistency: it uses the same `.proto`, the same codegen and the same
//! assumptions. If our reading of the specification were wrong, it would be equally
//! wrong on both sides, and the test would be green.
//!
//! `rust-spiffe` is code somebody else wrote, who read the specification
//! independently and which is used against SPIRE. What it accepts the standard
//! accepts.
//!
//! # How the attestation works in the test
//!
//! The test process runs in no container. It would therefore rightly get no SVID --
//! the attestation hangs on `/proc/<pid>/cgroup`. The tests reproduce this directory
//! (`ProcLookup::rooted_at`) and give the test process a cgroup line as a runtime
//! would write it. What is **not** reproduced is `SO_PEERCRED`: the PID comes from the
//! kernel, over the real socket connection. Exactly that is what matters.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use spiffe::BundleSource as _;
use tg_identity::{
    Authority, Lifetime, LocalSigner, Minter, SystemClock, TrustDomain, WorkloadApi, self_signed_ca,
};

const YEAR: i64 = 365 * 24 * 60 * 60;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

/// A running service together with its environment.
struct Fixture {
    _dir: tempfile::TempDir,
    endpoint: String,
    path: std::path::PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
    bundle_der: Vec<u8>,
    /// The handle on the **running** service.
    ///
    /// It lies here because a node's desired state changes while the service runs
    /// (ADR-0019) -- and because a test that could set that only before the start
    /// would not see precisely the case in which a workload joins **after** the
    /// start.
    api: WorkloadApi<LocalSigner>,
}

impl Fixture {
    /// A service that may mint for `assigned`, with these time windows.
    ///
    /// The test process thereby looks like the container of the **first** assigned
    /// workload.
    fn start(assigned: &[&str], lifetime: Lifetime) -> Self {
        Self::start_seen_as(
            assigned,
            lifetime,
            assigned.first().copied().unwrap_or("api"),
        )
    }

    /// As [`Self::start`], but the test process looks like `seen_as`'s container.
    ///
    /// The entry of its own is necessary as soon as assignment and caller fall apart
    /// -- at a caller, say, for which this node may not (yet) mint at all.
    fn start_seen_as(assigned: &[&str], lifetime: Lifetime, seen_as: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // **The socket says which container it is** (ADR-0081). Until here this test
        // reproduced a `/proc` so that the test process looks like a container -- with
        // the identifier at the listener it does not need that.
        let container = format!("tg-{seen_as}");

        let signer = LocalSigner::generate().expect("key");
        let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("CA");
        let bundle_der = ca.certificate_der().to_vec();
        let authority = Authority::new(ca, signer, lifetime).expect("issuer");
        let minter = Minter::new(authority, domain(), i64::MAX, assignment(assigned));

        let api = WorkloadApi::new(minter, vec![bundle_der.clone()], Arc::new(SystemClock));

        let path = dir.path().join(format!("{container}.sock"));
        let listener = tokio::net::UnixListener::bind(&path).expect("socket");
        let (tx, rx) = tokio::sync::oneshot::channel();

        // The handle stays here, the service moves into the task with the clone.
        // Both share their state -- otherwise the test would write into something
        // nobody reads.
        let api_handle = api.clone();
        let handle = tokio::spawn(async move {
            let stream = tg_identity::incoming_for(listener, Some(Arc::from(&*container)));
            let _ = tg_identity::serve_on(api, stream, async {
                let _ = rx.await;
            })
            .await;
        });

        Self {
            endpoint: format!("unix://{}", path.display()),
            path,
            _dir: dir,
            shutdown: Some(tx),
            handle,
            bundle_der,
            api: api_handle,
        }
    }

    /// A client from `rust-spiffe` -- foreign code that read the specification
    /// independently.
    async fn foreign_client(&self) -> spiffe::WorkloadApiClient {
        // The service needs a moment until it listens on the socket.
        for _ in 0..50 {
            if let Ok(client) = spiffe::WorkloadApiClient::connect_to(&self.endpoint).await {
                return client;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        panic!("the service did not become reachable");
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
    }
}

/// **The first acceptance criterion: a foreign client speaks the socket.**
///
/// `rust-spiffe` fetches an X.509 SVID and reads the SPIFFE ID out of it. That it is
/// the same ID we derived is the actual statement: the identity survives the round
/// through a foreign understanding of the specification.
#[tokio::test]
async fn a_foreign_spiffe_client_fetches_an_svid() {
    let fixture = Fixture::start(&["api"], Lifetime::default());
    let client = fixture.foreign_client().await;

    let svid = client.fetch_x509_svid().await.expect("SVID");

    assert_eq!(
        svid.spiffe_id().to_string(),
        "spiffe://cluster.local/workload/api"
    );
    assert!(!svid.cert_chain().is_empty(), "the chain must not be empty");

    fixture.stop().await;
}

/// The trust anchor comes along, and it is the same one the CA issued. Without this
/// check it would stay open whether anything usable stands in the `bundle` field at
/// all -- an empty bundle would stand out to the client only when it is to verify
/// somebody for the first time.
#[tokio::test]
async fn the_trust_bundle_travels_with_the_svid() {
    let fixture = Fixture::start(&["api"], Lifetime::default());
    let client = fixture.foreign_client().await;

    let bundles = client.fetch_x509_bundles().await.expect("bundles");
    let anchor = bundles
        .bundle_for_trust_domain(&spiffe::TrustDomain::new("cluster.local").expect("domain"))
        .expect("readable")
        .expect("a bundle for the trust domain");

    let authorities: Vec<Vec<u8>> = anchor
        .authorities()
        .iter()
        .map(|cert| cert.as_bytes().to_vec())
        .collect();

    assert_eq!(
        authorities,
        vec![fixture.bundle_der.clone()],
        "the delivered anchor is not the CA's"
    );

    fixture.stop().await;
}

/// **The attestation survived the rebuild.**
///
/// A workload this node is **not** responsible for gets no SVID -- the authority
/// binding from ADR-0006. The refusal now comes as a gRPC status instead of a JSON
/// line, but it comes.
#[tokio::test]
async fn a_workload_not_assigned_to_this_node_is_refused() {
    // The test process looks like `ledger` in its cgroup, but only `api` is assigned
    // to the node.
    let dir = tempfile::tempdir().expect("tempdir");
    // **The socket says which container it is** (ADR-0081) -- the listener belongs to
    // `tg-ledger`, only `api` is assigned to the node.
    let container = "tg-ledger";

    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("CA");
    let bundle = ca.certificate_der().to_vec();
    let authority = Authority::new(ca, signer, Lifetime::default()).expect("issuer");
    let minter = Minter::new(authority, domain(), i64::MAX, assignment(&["api"]));
    let api = WorkloadApi::new(minter, vec![bundle], Arc::new(SystemClock));

    let path = dir.path().join(format!("{container}.sock"));
    let listener = tokio::net::UnixListener::bind(&path).expect("socket");
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let stream = tg_identity::incoming_for(listener, Some(Arc::from(&*container)));
        let _ = tg_identity::serve_on(api, stream, async {
            let _ = rx.await;
        })
        .await;
    });

    let endpoint = format!("unix://{}", path.display());
    let client = loop {
        if let Ok(client) = spiffe::WorkloadApiClient::connect_to(&endpoint).await {
            break client;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let err = client
        .fetch_x509_svid()
        .await
        .expect_err("a foreign workload must get nothing here");
    assert!(
        format!("{err}").contains("not admitted"),
        "the refusal shall name the reason without giving names away: {err}"
    );

    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

/// **The header from the specification is enforced, not merely tolerated.**
///
/// Here, exceptionally, no foreign client is used: `rust-spiffe` always sets the
/// header and could not be brought to leave it out. Exactly for that reason the
/// refusal has to be checked differently -- with a call that does not send it.
#[tokio::test]
async fn a_call_without_the_specified_header_is_refused() {
    use tg_identity::workload_api::pb::X509svidRequest;
    use tg_identity::workload_api::pb::spiffe_workload_api_client::SpiffeWorkloadApiClient;

    let fixture = Fixture::start(&["api"], Lifetime::default());
    // Wait until the service stands -- over the foreign client, which is needed
    // anyway to recognize the socket as ready.
    let _ = fixture.foreign_client().await;

    let path = fixture.endpoint.trim_start_matches("unix://").to_owned();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .expect("endpoint")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("connection");

    let mut bare = SpiffeWorkloadApiClient::new(channel);
    let err = bare
        .fetch_x509svid(X509svidRequest {})
        .await
        .expect_err("without the header nothing must come out");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message().contains("workload.spiffe.io"),
        "the message shall name the missing header: {}",
        err.message()
    );

    fixture.stop().await;
}

/// **The rotation comes as a push, not as an answer to a poll.**
///
/// That is the reason ADR-0035 takes the specification's streams seriously. The client
/// asks **once** and holds the stream open; the second SVID comes without its asking
/// again.
///
/// The time windows are compressed for the test (4 s TTL, rotation after 1 s) -- the
/// ordering conditions from ADR-0014 still apply in the process, they are ratios and
/// no absolute numbers.
#[tokio::test]
async fn rotation_arrives_as_a_push_on_the_open_stream() {
    let lifetime = Lifetime {
        ttl: Duration::from_secs(4),
        rotate_after: Duration::from_secs(1),
        grace: Duration::from_secs(1),
    };
    let fixture = Fixture::start(&["api"], lifetime);
    let client = fixture.foreign_client().await;

    let mut stream = client.stream_x509_svids().await.expect("stream");

    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("the first SVID must come immediately")
        .expect("element")
        .expect("SVID");

    // And now no asking happens. Something comes all the same.
    let second = tokio::time::timeout(Duration::from_secs(10), stream.next())
        .await
        .expect("the second SVID must come of its own accord")
        .expect("element")
        .expect("SVID");

    assert_eq!(
        first.spiffe_id(),
        second.spiffe_id(),
        "the identity stays, only the certificate is new"
    );
    assert_ne!(
        first.cert_chain()[0].as_bytes(),
        second.cert_chain()[0].as_bytes(),
        "the same certificate was sent once more -- then nothing rotates"
    );

    fixture.stop().await;
}

/// The JWT half says that it does not exist -- with the ADR that defers it.
///
/// `UNIMPLEMENTED` is the honest answer here. A method that does something half would
/// be worse than none.
#[tokio::test]
async fn the_jwt_half_answers_unimplemented_and_names_the_adr() {
    use tg_identity::workload_api::pb::JwtsvidRequest;
    use tg_identity::workload_api::pb::spiffe_workload_api_client::SpiffeWorkloadApiClient;

    let fixture = Fixture::start(&["api"], Lifetime::default());
    let _ = fixture.foreign_client().await;

    let path = fixture.endpoint.trim_start_matches("unix://").to_owned();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .expect("endpoint")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("connection");

    let mut client = SpiffeWorkloadApiClient::new(channel);
    let mut request = tonic::Request::new(JwtsvidRequest {
        audience: vec!["anybody".to_owned()],
        spiffe_id: String::new(),
    });
    request
        .metadata_mut()
        .insert("workload.spiffe.io", "true".parse().expect("value"));

    let err = client
        .fetch_jwtsvid(request)
        .await
        .expect_err("there is no JWT-SVID");

    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert!(
        err.message().contains("ADR-0025"),
        "the message shall say where the deferral stands: {}",
        err.message()
    );

    fixture.stop().await;
}

/// Fetches the SVID list over the **generated** client.
///
/// `rust-spiffe` hands out only the first entry; where the whole list is the statement
/// (delegation, ADR-0036), the generated client is needed. The seam stands here once,
/// because two copies would be two opportunities to set the mandatory header from
/// ADR-0035 differently.
async fn svids_over_generated_client(
    path: &std::path::Path,
) -> tg_identity::workload_api::pb::X509svidResponse {
    use tg_identity::workload_api::pb::X509svidRequest;
    use tg_identity::workload_api::pb::spiffe_workload_api_client::SpiffeWorkloadApiClient;

    let endpoint = path.display().to_string();
    let channel = loop {
        let target = endpoint.clone();
        let attempt = tonic::transport::Endpoint::try_from("http://[::]:50051")
            .expect("endpoint")
            .connect_with_connector(tower::service_fn(move |_| {
                let target = target.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(target).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await;
        if let Ok(channel) = attempt {
            break channel;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let mut client = SpiffeWorkloadApiClient::new(channel);
    let mut request = tonic::Request::new(X509svidRequest {});
    request
        .metadata_mut()
        .insert("workload.spiffe.io", "true".parse().expect("value"));

    let mut stream = client
        .fetch_x509svid(request)
        .await
        .expect("stream")
        .into_inner();

    stream.message().await.expect("element").expect("answer")
}

// --------------------------------------------------------------- Delegation

/// **A sidecar gets two SVIDs** (ADR-0036) -- its own and the delegated one of its
/// workload, distinguished over `hint`.
///
/// Checked with the generated client instead of with `rust-spiffe`: its
/// `fetch_x509_svid` delivers only the first entry, and precisely the list is the
/// statement here.
#[tokio::test]
async fn a_sidecar_receives_its_own_and_a_delegated_svid() {
    use std::collections::BTreeMap;

    use tg_identity::{HINT_DELEGATED, HINT_SELF};

    let dir = tempfile::tempdir().expect("tempdir");
    // The socket belongs to the sidecar container (ADR-0081).
    let container = "tg-api-proxy";

    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("CA");
    let bundle = ca.certificate_der().to_vec();
    let authority = Authority::new(ca, signer, Lifetime::default()).expect("issuer");
    let mut minter = Minter::new(
        authority,
        domain(),
        i64::MAX,
        assignment(&["api", "api-proxy"]),
    );
    // The mapping comes from the desired state (tg_model::mesh::delegations) and is
    // handed in here, not computed.
    minter.set_delegations(BTreeMap::from([("api-proxy".to_owned(), "api".to_owned())]));

    let api = WorkloadApi::new(minter, vec![bundle], Arc::new(SystemClock));

    let path = dir.path().join(format!("{container}.sock"));
    let listener = tokio::net::UnixListener::bind(&path).expect("socket");
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let stream = tg_identity::incoming_for(listener, Some(Arc::from(&*container)));
        let _ = tg_identity::serve_on(api, stream, async {
            let _ = rx.await;
        })
        .await;
    });

    let response = svids_over_generated_client(&path).await;

    assert_eq!(response.svids.len(), 2, "one's own and the delegated SVID");

    assert_eq!(response.svids[0].hint, HINT_SELF);
    assert_eq!(
        response.svids[0].spiffe_id, "spiffe://cluster.local/workload/api-proxy",
        "the narrower identity stands first -- whoever does not read `hint` does \
         not get the wider one"
    );

    assert_eq!(response.svids[1].hint, HINT_DELEGATED);
    assert_eq!(
        response.svids[1].spiffe_id, "spiffe://cluster.local/workload/api",
        "on the mesh wire the sidecar speaks as its workload (ADR-0036)"
    );

    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

/// An ordinary workload gets **one**. The delegation is the exception, not the
/// rule.
#[tokio::test]
async fn a_plain_workload_receives_exactly_one_svid() {
    use tg_identity::workload_api::pb::X509svidRequest;
    use tg_identity::workload_api::pb::spiffe_workload_api_client::SpiffeWorkloadApiClient;

    let fixture = Fixture::start(&["api"], Lifetime::default());
    let _ = fixture.foreign_client().await;

    let path = fixture.endpoint.trim_start_matches("unix://").to_owned();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .expect("endpoint")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("connection");

    let mut client = SpiffeWorkloadApiClient::new(channel);
    let mut request = tonic::Request::new(X509svidRequest {});
    request
        .metadata_mut()
        .insert("workload.spiffe.io", "true".parse().expect("value"));

    let response = client
        .fetch_x509svid(request)
        .await
        .expect("stream")
        .into_inner()
        .message()
        .await
        .expect("element")
        .expect("answer");

    assert_eq!(response.svids.len(), 1);

    fixture.stop().await;
}

// ----------------------------------------------------- The state changes

/// **A workload that joins after the start gets an SVID.**
///
/// A node's desired state does not stand fixed at the start: with a control plane the
/// local cache is often **empty** at that moment, and the first slice fills it
/// afterwards (ADR-0040). Whoever sets the assignment once at the build-up gives every
/// container that arrived that way a no until the agent restarts.
///
/// The refusal before it is half the assurance and no accessory: without it the test
/// would be green even if this node minted for everything from the start.
#[tokio::test]
async fn a_workload_that_arrives_after_the_start_still_gets_an_svid() {
    let fixture = Fixture::start_seen_as(&[], Lifetime::default(), "api");
    let client = fixture.foreign_client().await;

    let err = client
        .fetch_x509_svid()
        .await
        .expect_err("as long as nothing is assigned, there is nothing");
    assert!(
        format!("{err}").contains("not admitted"),
        "the refusal shall name the reason: {err}"
    );

    // What the reconciler writes anew at every pass (ADR-0019).
    fixture.api.set_assigned(assignment(&["api"]));

    let svid = client
        .fetch_x509_svid()
        .await
        .expect("after the assignment the same SVID must come out");
    assert_eq!(
        svid.spiffe_id().to_string(),
        "spiffe://cluster.local/workload/api"
    );

    fixture.stop().await;
}

/// **A delegation that joins after the start takes effect.**
///
/// The same case as above, one layer higher: the sidecar is a **derived** unit
/// (ADR-0059), and it is derived from a state that changes. If it does not get its
/// delegated SVID, it lays its own identity down on the mesh wire -- and the
/// `may_talk` edges an operator wrote do not bite (ADR-0036, ADR-0025).
///
/// Checked with the generated client, because here the **list** is the statement.
#[tokio::test]
async fn a_delegation_that_arrives_after_the_start_still_takes_effect() {
    use std::collections::BTreeMap;

    use tg_identity::{HINT_DELEGATED, HINT_SELF};

    let fixture = Fixture::start_seen_as(&["api", "api-proxy"], Lifetime::default(), "api-proxy");
    let _ = fixture.foreign_client().await;

    let before = svids_over_generated_client(&fixture.path).await;
    assert_eq!(
        before.svids.len(),
        1,
        "without a delegation the sidecar speaks only for itself"
    );
    assert_eq!(before.svids[0].hint, HINT_SELF);

    fixture
        .api
        .set_delegations(BTreeMap::from([("api-proxy".to_owned(), "api".to_owned())]));

    let after = svids_over_generated_client(&fixture.path).await;
    assert_eq!(
        after.svids.len(),
        2,
        "with a delegation the workload's SVID comes along"
    );
    assert_eq!(after.svids[1].hint, HINT_DELEGATED);
    assert_eq!(
        after.svids[1].spiffe_id, "spiffe://cluster.local/workload/api",
        "what is delegated is the workload's identity, not the sidecar's"
    );

    fixture.stop().await;
}

/// What the node hands the issuing service (ADR-0065): container identifier ->
/// workload, formed with **the same** function that assigns the identifiers in
/// operation.
fn assignment(names: &[&str]) -> std::collections::BTreeMap<String, String> {
    names
        .iter()
        .map(|name| {
            (
                tg_runtime::bundle::container_id(name, 0),
                (*name).to_owned(),
            )
        })
        .collect()
}

/// **A material swap reaches every socket** (ADR-0081, determination 5).
///
/// # What hung on it
///
/// Since ADR-0081 there is one socket **per instance**, and the obvious reading is to
/// give each its own issuing service. Precisely that must not be: the minter holds CA,
/// signer and the mapping "what may this node mint" (ADR-0019), and an agent that
/// renews its intermediate (`adopt`) would thereby reach only **one** socket. The
/// others would go on minting from the old one -- and after twelve hours **no** SVID
/// of this node is accepted any more, because every verifier checks the chain. The
/// error shows itself not at the issuance but at the first connection, and then at
/// all of them.
///
/// # Why the witness is necessary nevertheless
///
/// Today the property holds **structurally**: `WorkloadApi` clones over an `Arc`, so
/// there is no second minter at all. A mutation run cannot break that without
/// rebuilding the type -- and exactly against that stands this test: what is checked
/// is the **effect**, not the mechanism.
#[tokio::test]
async fn a_material_swap_reaches_every_socket() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Material A, and an issuing service on it.
    let signer_a = LocalSigner::generate().expect("key");
    let ca_a = self_signed_ca(&domain(), &signer_a, 0, 10 * YEAR).expect("CA A");
    let anchor_a = ca_a.certificate_der().to_vec();
    let api = WorkloadApi::new(
        Minter::new(
            Authority::new(ca_a, signer_a, Lifetime::default()).expect("issuer A"),
            domain(),
            i64::MAX,
            assignment(&["api", "ledger"]),
        ),
        vec![anchor_a.clone()],
        Arc::new(SystemClock),
    );

    // **Two sockets over one service**, as `tg_agent::sockets::Listeners` does it:
    // the clone is a handle, no second state.
    let mut endpoints = Vec::new();
    let mut tasks = Vec::new();
    for name in ["api", "ledger"] {
        let container = tg_runtime::bundle::container_id(name, 0);
        let path = dir.path().join(format!("{container}.sock"));
        let listener = tokio::net::UnixListener::bind(&path).expect("socket");
        let served = api.clone();
        tasks.push(tokio::spawn(async move {
            let stream = tg_identity::incoming_for(listener, Some(Arc::from(&*container)));
            let _ = tg_identity::serve_on(served, stream, std::future::pending::<()>()).await;
        }));
        endpoints.push(format!("unix://{}", path.display()));
    }

    // The chain both deliver before the swap.
    let mut before = Vec::new();
    for endpoint in &endpoints {
        before.push(await_chain(endpoint).await);
    }

    // **The swap, on this test's handle** -- not on one of the services: exactly so
    // does the agent do it (`Minter::adopt` over the one `Api`).
    let signer_b = LocalSigner::generate().expect("key");
    let ca_b = self_signed_ca(&domain(), &signer_b, 0, 10 * YEAR).expect("CA B");
    let anchor_b = ca_b.certificate_der().to_vec();
    assert_ne!(anchor_a, anchor_b, "two CAs must differ");
    api.adopt(
        Authority::new(ca_b, signer_b, Lifetime::default()).expect("issuer B"),
        i64::MAX,
    );

    // And **every** socket mints from B afterwards. That is the statement: not "one
    // has changed" but "all".
    //
    // What is checked is the **chain**, not the trust bundle: measured, `adopt`
    // changes the issuer, and the bundle is a state of its own (`set_trust_bundle`) --
    // the agent calls both in the same round. A test over the bundle would therefore
    // check the other half.
    for (endpoint, old) in endpoints.iter().zip(&before) {
        let now = await_chain(endpoint).await;
        assert_ne!(
            &now, old,
            "after the swap {endpoint} still mints from the old intermediate -- \
             and after twelve hours none of its SVIDs is accepted any more \
             (ADR-0014)"
        );
    }

    for task in tasks {
        task.abort();
    }
}

/// Waits until a socket answers and returns its SVID's **chain** -- without the leaf.
///
/// The leaf changes at every issuance (serial number, key, validity); what gives the
/// **issuer** away is the rest of the chain. A comparison over the whole certificate
/// would therefore say "different" for every second request and nothing about the
/// material.
async fn await_chain(endpoint: &str) -> Vec<Vec<u8>> {
    for _ in 0..50 {
        if let Ok(client) = spiffe::WorkloadApiClient::connect_to(endpoint).await
            && let Ok(svid) = client.fetch_x509_svid().await
        {
            return svid
                .cert_chain()
                .iter()
                .skip(1)
                .map(|cert| cert.as_bytes().to_vec())
                .collect();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    panic!("the socket {endpoint} did not become reachable");
}

/// **Who uses the socket stands in a metric** (ADR-0079).
///
/// The note there read: *"`svid_issued_total` counts issuances, not callers; which
/// workload speaks its own mTLS an operator does not see."*
///
/// Both are checked -- that the **caller's name** stands there, and that what is
/// counted is what ADR-0079 means: the **call**. A stream that rotates for twelve
/// hours is one use and not fifty-five; for that stands the one after the first
/// fetch.
///
/// **A single-thread runtime**, as at the witness of the sidecar connections: the
/// local recorder applies per thread, and the metric arises in the service.
#[tokio::test]
async fn the_socket_says_who_used_it() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let guard = metrics::set_default_local_recorder(&recorder);

    let fixture = Fixture::start(&["api"], Lifetime::default());
    let client = fixture.foreign_client().await;
    let _ = client.fetch_x509_svid().await.expect("SVID");

    let calls: Vec<(String, u64)> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            if key.key().name() != tg_telemetry::names::WORKLOAD_API_CALLS {
                return None;
            }
            let workload = key
                .key()
                .labels()
                .find(|label| label.key() == "workload")?
                .value()
                .to_owned();
            match value {
                DebugValue::Counter(seen) => Some((workload, seen)),
                _ => None,
            }
        })
        .collect();

    assert_eq!(
        calls,
        vec![("api".to_owned(), 1)],
        "the caller must stand there with its name and exactly one call"
    );

    fixture.stop().await;
    drop(guard);
}
