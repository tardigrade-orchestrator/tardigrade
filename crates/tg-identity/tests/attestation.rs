//! The attestation at the socket (ADR-0081).
//!
//! # What this file checks, and what has changed
//!
//! Until ADR-0081 the attestation was a **chain**: `SO_PEERPIDFD` -> pidfd ->
//! `/proc/<pid>/cgroup` -> a path segment with a `tg-` prefix -> the mapping container
//! identifier -> workload (ADR-0065). Four steps, three of them kernel interfaces, and
//! every one of them has already delivered a finding once.
//!
//! Now it is **single-stage**: every container gets its own socket, mounted into
//! exactly it (ADR-0079). Whoever reached it is in this container -- that is the whole
//! statement.
//!
//! # Why no container runs here
//!
//! This file's test **became simpler because the matter did.** A real container was
//! necessary as long as the attestation had to read a cgroup; with the socket as the
//! source a client at the socket checks exactly the same. What a container contributes
//! is the **mount** -- a different assurance, and it lies in `mesh_container.rs` and
//! `sidecar_image.rs`, where real containers run.
//!
//! What a container could not check is checked by the privileged test at the end: that
//! the **host path** does not give a socket up while the bind mount does (ADR-0081,
//! determination 2).

use tokio::net::{UnixListener, UnixStream};

const NOW: i64 = 1_800_000_000;

/// A minter that may mint `api` in three instances.
fn minter() -> tg_identity::Minter<tg_identity::LocalSigner> {
    let domain = tg_identity::TrustDomain::new("cluster.local").expect("valid");
    let signer = tg_identity::LocalSigner::generate().expect("key");
    let ca =
        tg_identity::self_signed_ca(&domain, &signer, 0, 365 * 24 * 60 * 60).expect("intermediate");
    let authority =
        tg_identity::Authority::new(ca, signer, tg_identity::Lifetime::default()).expect("issuer");

    // The mapping is formed by the node -- here with **the same** function that
    // assigns the identifiers in operation (ADR-0065).
    let assigned = (0..3_u32)
        .map(|instance| {
            (
                tg_runtime::bundle::container_id("api", instance),
                "api".to_owned(),
            )
        })
        .collect();

    tg_identity::Minter::new(authority, domain, NOW + 12 * 60 * 60, assigned)
}

// ==================================== The identifier comes from the socket

/// **The socket names the container** -- checked over a real socket.
///
/// The connection carries the identifier the listener was built with
/// (`incoming_for`), and `attest` reads only it. No pidfd, no `/proc`, no cgroup.
///
/// Checked at **both** instances, and the second is the point (ADR-0065): its
/// identifier carries the number, and the identity belongs to the **workload** all the
/// same (ADR-0036).
#[tokio::test(flavor = "multi_thread")]
async fn the_socket_names_the_container() {
    let dir = tempfile::tempdir().expect("tempdir");

    for instance in [0_u32, 1] {
        let container = tg_runtime::bundle::container_id("api", instance);
        let path = dir.path().join(format!("{container}.sock"));
        let listener = UnixListener::bind(&path).expect("socket");

        // The service is the same for all the sockets (ADR-0081, determination 5);
        // different is solely the identifier at the connection.
        // A minter of its own per pass: `Minter` does not clone (it holds the cache
        // of the issued SVIDs), and the build-up is cheap.
        let api = tg_identity::WorkloadApi::new(
            minter(),
            Vec::new(),
            std::sync::Arc::new(tg_identity::SystemClock),
        );
        let id: std::sync::Arc<str> = std::sync::Arc::from(container.as_str());
        let serving = tokio::spawn(async move {
            let stream = tg_identity::incoming_for(listener, Some(id));
            let _ = tg_identity::serve_on(api, stream, std::future::pending()).await;
        });

        let svid = fetch_svid(&path).await;
        serving.abort();

        assert_eq!(
            svid, "spiffe://cluster.local/workload/api",
            "instance {instance}: the identity belongs to the workload, not to the instance"
        );
    }
}

/// **A socket without an instance gives no SVID** (ADR-0081, determination 2).
///
/// The case is a listener that belongs to no instance -- the admin socket (ADR-0044),
/// say, which authorizes over the `uid`. It is the counter-check to the test above:
/// without it an attestation that accepts **every** connection would be green
/// likewise, and every process on the node would get an SVID.
#[tokio::test(flavor = "multi_thread")]
async fn a_socket_without_an_instance_gives_no_svid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nameless.sock");
    let listener = UnixListener::bind(&path).expect("socket");

    let api = tg_identity::WorkloadApi::new(
        minter(),
        Vec::new(),
        std::sync::Arc::new(tg_identity::SystemClock),
    );
    let serving = tokio::spawn(async move {
        // **Without** an identifier -- `incoming` instead of `incoming_for`.
        let stream = tg_identity::workload_api::incoming(listener);
        let _ = tg_identity::serve_on(api, stream, std::future::pending()).await;
    });

    let outcome = try_fetch(&path).await;
    serving.abort();

    let err = outcome.expect_err("a socket without an instance must give no SVID");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "the refusal comes with `permission_denied`, not with a transport error: {err}"
    );
}

/// **An implausible identifier is refused.**
///
/// It comes from **our** listener, so an implausible one is a finding about us -- it
/// is checked all the same, because it becomes the name of a SPIFFE identifier
/// (ADR-0006) and a check there costs nothing.
///
/// Both directions: without a prefix it is no identifier, and with a prefix but an
/// implausible name it is none either.
#[test]
fn an_implausible_identifier_is_refused() {
    assert!(
        tg_identity::Attestation::from_socket("api").is_none(),
        "without the runtime's prefix it is no identifier"
    );
    assert!(
        tg_identity::Attestation::from_socket("tg-../etc").is_none(),
        "`tg-../etc` is not an identifier with an invalid name -- it is none at all"
    );

    let good = tg_runtime::bundle::container_id("api", 1);
    assert_eq!(
        tg_identity::Attestation::from_socket(&good)
            .expect("an identifier of the product")
            .container_id(),
        good,
        "and what `container_id` produces must get through"
    );
}

/// **A second instance gets its workload's identity** (ADR-0065).
///
/// `container_id` appends the instance number (`tg-api-1`, ADR-0034). Whoever cuts it
/// off backwards reads the workload `api-1` from it -- which does not exist, and a
/// warm standby would get no SVID (ADR-0007), silently, for the container runs.
///
/// The input is built from the **producer** (`container_id`), not from a copied string:
/// with that it stands out at the same time when the runtime changes its prefix and
/// the attestation does not move along.
#[test]
fn a_second_instance_is_minted_for_its_workload() {
    let mut minter = minter();

    for instance in [0_u32, 1, 2] {
        let id = tg_runtime::bundle::container_id("api", instance);
        let attestation =
            tg_identity::Attestation::from_socket(&id).expect("an identifier of the product");

        let svid = minter
            .svid_for(&attestation, NOW)
            .unwrap_or_else(|err| panic!("instance {instance} gets no SVID: {err}"));

        assert_eq!(
            svid.id().to_string(),
            "spiffe://cluster.local/workload/api",
            "the identity belongs to the workload, not to the instance (ADR-0036)"
        );
    }
}

// ==================================== What separates the socket from the node

/// **The host path does not reach the socket, the mount does** (ADR-0081,
/// determination 2).
///
/// # What it assures
///
/// On this property rests the whole decision: the socket carries `0666` (ADR-0060 --
/// a connection demands write permission, and the sidecar runs under an identifier of
/// its own), and what **separates** is the `0700` directory above it plus the bind
/// mount that gets around it.
///
/// Both directions, and the first carries: without it a build-up in which **nothing**
/// is reachable would be green likewise -- and then no workload would get at its SVID.
///
/// `#[ignore]`, because `mount` demands privileges; run with `cargo xtask attest`.
#[test]
#[ignore = "demands CAP_SYS_ADMIN for mount; cargo xtask attest"]
fn the_host_path_does_not_reach_the_socket() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let host = dir.path().join("sockets");
    let target = dir.path().join("in-the-container");
    std::fs::create_dir_all(&host).expect("directory");
    std::fs::create_dir_all(&target).expect("directory");
    std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o700)).expect("0700");

    let socket = host.join("tg-api.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).expect("0666");

    let accepting = std::thread::spawn(move || while listener.accept().is_ok() {});

    let inside = target.join("workload-api.sock");
    std::fs::write(&inside, b"").expect("mount point");
    let mounted = std::process::Command::new("mount")
        .args(["--bind", &socket.display().to_string()])
        .arg(&inside)
        .status()
        .expect("mount");
    assert!(mounted.success(), "the bind mount must stand");

    let over_mount = connect_as_nobody(&inside);
    let over_host = connect_as_nobody(&socket);

    let _ = std::process::Command::new("umount").arg(&inside).status();
    drop(accepting);

    assert!(
        over_mount,
        "over the mount the workload must reach its socket -- otherwise it gets \
         no SVID"
    );
    assert!(
        !over_host,
        "over the host path an unprivileged process must **not** reach it: then \
         every local user would be the identity of every workload"
    );
}

/// Whether an unprivileged process reaches the socket.
///
/// Over `runuser`, because a test cannot change its own uid without taking the whole
/// process along.
#[cfg(test)]
fn connect_as_nobody(path: &std::path::Path) -> bool {
    let script = format!(
        "import socket,sys\n\
         s=socket.socket(socket.AF_UNIX)\n\
         s.settimeout(2)\n\
         try:\n    s.connect({:?})\n    print('ok')\nexcept Exception as e:\n    print(type(e).__name__)\n",
        path.display().to_string()
    );

    let out = std::process::Command::new("runuser")
        .args(["-u", "nobody", "--", "python3", "-c", &script])
        .output()
        .expect("runuser");

    String::from_utf8_lossy(&out.stdout).trim() == "ok"
}

// =============================================================== Helpers

/// Fetches an SVID over the socket and gives its SPIFFE identifier.
async fn fetch_svid(path: &std::path::Path) -> String {
    try_fetch(path).await.expect("an SVID")
}

/// As [`fetch_svid`], with the error instead of a panic.
async fn try_fetch(path: &std::path::Path) -> Result<String, tonic::Status> {
    let owned = path.to_path_buf();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:0")
        .expect("placeholder")
        .connect_with_connector(tower::service_fn(move |_| {
            let owned = owned.clone();
            async move {
                UnixStream::connect(owned)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .expect("connection");

    let mut client =
        tg_identity::workload_api::pb::spiffe_workload_api_client::SpiffeWorkloadApiClient::new(
            channel,
        );
    let mut request = tonic::Request::new(tg_identity::workload_api::pb::X509svidRequest {});
    request
        .metadata_mut()
        .insert("workload.spiffe.io", "true".parse().expect("header"));

    let mut stream = client.fetch_x509svid(request).await?.into_inner();
    let response = stream
        .message()
        .await?
        .ok_or_else(|| tonic::Status::internal("no entry"))?;

    Ok(response.svids[0].spiffe_id.clone())
}
