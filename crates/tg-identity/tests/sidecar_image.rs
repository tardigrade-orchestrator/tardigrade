//! The **real** `tg-proxy` in a container (ADR-0059, ADR-0019).
//!
//! # What is checked here for the first time
//!
//! The sidecar process is substantiated at three places -- the workload API against
//! `rust-spiffe` (7c), mTLS end to end (8b), egress against `curl` (10d) -- and **every
//! time as a test process**, never in a container. `sidecar_path.rs` starts a container
//! but with a placeholder, and that is the right choice there: what is checked is the
//! wiring, and a `tg-proxy` that does not start would not say which of the four
//! assurances is broken.
//!
//! What nobody has thereby ever measured: **does the image carry what the program
//! needs?** A missing loader, a missing `libgcc_s`, a path ADR-0059 fixes as a constant
//! and the image does not have -- all of that stands out only in the container, and
//! there as `executable not found` or `error while loading shared libraries`.
//!
//! # The build-up
//!
//! `cargo xtask image` builds the layer with the real binary into a content store;
//! this test **lays a second one above it** that brings a shell and a wrapper script.
//! Two reasons:
//!
//! - A container without a shell cannot steer its output into a file, and the output
//!   **is** the statement here.
//! - The real image stays minimal: it contains no shell, and it shall not (ADR-0017:
//!   hardened unprivileged workloads).
//!
//! Incidentally that runs the **multi-layer** overlay path (ADR-0052), which is
//! otherwise checked only at staged layers.
//!
//! The second test goes further: it puts a **real** workload API socket beside it, and
//! the sidecar fetches its **delegated SVID** over it (ADR-0035, ADR-0036). The
//! attestation happens over the connection's `pidfd` and the cgroup behind it
//! (ADR-0053, ADR-0065) -- at a container the reconciler started.
//!
//! `#[ignore]`: demands an OCI runtime and `CAP_SYS_ADMIN` -- run with
//! `cargo xtask storage`, which executes `cargo xtask image` beforehand.

mod containers;

use containers::{Cleanup, PROOF, await_line, base_layer, definition, probe_layer, seed};
use tg_runtime::content::ContentStore;

/// Under which reference the first test files its image.
const PROBE_REFERENCE: &str = "tardigrade.local/tg-proxy-probe:dev";

/// A `Context` without any seam -- what these tests need.
///
/// Literally the same literal twice, and at the next field on `Context` there would be
/// two places to pull along; at exactly that this test grew over the line limit at
/// ADR-0098.
fn plain_context() -> tg_runtime::reconcile::Context<'static> {
    tg_runtime::reconcile::Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        now: &|| 0,
        fence_margin: 0,
        wake: None,
        keep_snapshots: 3,
        quorum: tg_model::Quorum::Available,
        network: None,
        mesh: None,
        workload_api: None,
        secrets: None,
        credentials: None,
        empty: &|| tg_runtime::reconcile::EmptyMeans::NothingWanted,
    }
}

/// **The real `tg-proxy` runs in the container and gets as far as its socket.**
///
/// The statement is exactly that threshold, and it is the interesting one: that the
/// program does **not** reach the socket is expected here -- there is none. That it
/// complains about it means that everything before it carried: the dynamic linker,
/// the libraries, the fixed path to the binary inside the container, its own
/// identifier.
///
/// What the test does **not** show: an issued identity or an mTLS connection. Both
/// hang on an attested socket and are substantiated elsewhere in this crate; here
/// it is about the image.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands an OCI runtime and CAP_SYS_ADMIN; over `cargo xtask storage`"]
async fn the_real_sidecar_binary_runs_in_a_container() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime = tg_runtime::oci::OciRuntime::discover(
        tg_runtime::oci::DEFAULT_RUNTIMES,
        paths.runtime_root(),
    )
    .expect("no OCI runtime in the PATH");
    let store = ContentStore::open(paths.content_dir()).expect("store");

    // The real layer, above it shell and wrapper script.
    let base = base_layer(&store);
    let over = probe_layer(&store, &wrapper("tg-image-probe"));
    seed(&store, PROBE_REFERENCE, &[base, over]);

    // **The production path**, not a rebuilt bundle: the reconciler starts the
    // container as it does in operation (ADR-0010).
    let cache = tg_runtime::state::DesiredState::open(paths.data_dir()).expect("cache");
    let set = tg_defs::from_str(&definition("tg-image-probe", PROBE_REFERENCE))
        .expect("the definition parses");
    cache
        .put(&set.workloads()[0])
        .expect("filing the definition");
    cache.assign("tg-image-probe", &[0]).expect("assignment");

    let id = tg_runtime::bundle::container_id("tg-image-probe", 0);
    let _cleanup = Cleanup::new(
        id,
        paths.runtime_root(),
        runtime.name().to_owned(),
        dir.path().to_path_buf(),
    );

    let context = plain_context();
    let report = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("pass");
    assert!(
        report.failed.is_empty(),
        "the container did not start up: {report:?}"
    );

    let proof = paths
        .bundles_dir()
        .join("tg-image-probe")
        .join("rootfs")
        .join(PROOF.trim_start_matches('/'));
    // The marker is the assurance: the program **looked for** the socket, so the
    // linker carried. The needle is `tg-proxy`'s log line.
    let text = await_line(&proof, "the workload API").unwrap_or_else(|last| {
        panic!("the wrapper script did not write the marker: {report:?}\nso far:\n{last}")
    });

    // **The dynamic linker carried.** That is the assurance: a missing library would
    // yield "error while loading shared libraries", a missing program "not found".
    assert!(
        !text.contains("loading shared libraries"),
        "the image does not bring a library along:\n{text}"
    );
    assert!(
        !text.contains("not found"),
        "the program does not lie under {} :\n{text}",
        tg_model::mesh::PROGRAM_IN_CONTAINER
    );

    // And it got as far as the socket -- the expected threshold.
    assert!(
        text.contains("the workload API"),
        "the program did not look for its socket; then it stopped \
         beforehand:\n{text}"
    );
}

// ================ And the whole path: an SVID over a real socket

/// **The sidecar in the container fetches its delegated SVID and becomes ready.**
///
/// The path that was substantiated at **every** place individually until here and
/// never together: the workload API over a Unix socket (7c), the attestation at the
/// `pidfd` together with the cgroup (ADR-0053), the resolution container identifier ->
/// workload (ADR-0065), the delegation to the sidecar (ADR-0036) -- and a **real**
/// container with the **real** binary.
///
/// The assurance is the line `the sidecar is ready` together with the SPIFFE ID of **its
/// workload**, not of itself: it lays the delegated SVID on the wire (ADR-0036), and
/// that `workload/<name>` stands there and not `workload/<name>-proxy` is the whole
/// point.
///
/// # Why two passes
///
/// The socket must lie **in** the container, and without a mesh derivation there is no
/// mount path for that (the derivation is substantiated in `sidecar_path.rs`, here the
/// identity is the subject). So: the first pass builds the bundle and lets the
/// container fail at its missing socket; then the test binds it into the rootfs; the
/// second pass starts anew.
///
/// That is no makeshift but **level-triggered** (ADR-0010): the reconciler finds an
/// ended container and starts it again. The first pass is thereby at the same time the
/// evidence for that.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands an OCI runtime and CAP_SYS_ADMIN; over `cargo xtask storage`"]
async fn the_sidecar_in_a_container_gets_its_delegated_svid() {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Arc;

    let dir = tempfile::tempdir().expect("tempdir");
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime = tg_runtime::oci::OciRuntime::discover(
        tg_runtime::oci::DEFAULT_RUNTIMES,
        paths.runtime_root(),
    )
    .expect("no OCI runtime in the PATH");
    let store = ContentStore::open(paths.content_dir()).expect("store");

    let workload = "tg-svid-api";
    let sidecar = format!("{workload}-proxy");

    // **Both identifiers from the same function** that assigns them in operation
    // (ADR-0065: resolve forwards, never compute backwards).
    // Without a subscriber `tracing` discards silently (the finding from 11b) -- and
    // the server's refusal is a `warn!`.
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let assigned = BTreeMap::from([
        (
            tg_runtime::bundle::container_id(&sidecar, 0),
            sidecar.clone(),
        ),
        // **The workload itself too**, and that is no accessory: the delegation
        // checks whether the **target** is assigned to this node (`svid_named`, the
        // second layer from the mutation run). In operation it runs beside it -- a
        // sidecar without its workload does not exist (ADR-0059: co-location is a
        // consequence).
        //
        // Measured, its absence yielded exactly the message the server writes about
        // it: "'...' is not assigned to this node".
        (
            tg_runtime::bundle::container_id(workload, 0),
            workload.to_owned(),
        ),
    ]);
    // **Who may speak for whom** (ADR-0036). Without this line the sidecar would get
    // only its own SVID -- and `tg-proxy` looks for the one with
    // `hint = "delegated"`.
    let delegations = BTreeMap::from([(sidecar.clone(), workload.to_owned())]);

    let domain = tg_identity::TrustDomain::new("cluster.local").expect("domain");
    let signer = tg_identity::LocalSigner::generate().expect("key");
    let ca = tg_identity::self_signed_ca(&domain, &signer, 0, 10 * 365 * 24 * 3_600).expect("CA");
    let anchor = ca.certificate_der().to_vec();
    let authority =
        tg_identity::Authority::new(ca, signer, tg_identity::Lifetime::default()).expect("issuer");
    let mut minter = tg_identity::Minter::new(authority, domain, i64::MAX, assigned);
    minter.set_delegations(delegations);

    let api =
        tg_identity::WorkloadApi::new(minter, vec![anchor], Arc::new(tg_identity::SystemClock));

    // The image: the real layer, above it shell and wrapper script -- this time it
    // calls **with** a socket.
    let base = base_layer(&store);
    let over = probe_layer(&store, &wrapper(&sidecar));
    let reference = format!("tardigrade.local/{sidecar}:dev");
    seed(&store, &reference, &[base, over]);

    let cache = tg_runtime::state::DesiredState::open(paths.data_dir()).expect("cache");
    let set = tg_defs::from_str(&definition(&sidecar, &reference)).expect("the definition parses");
    cache
        .put(&set.workloads()[0])
        .expect("filing the definition");
    cache.assign(&sidecar, &[0]).expect("assignment");

    let id = tg_runtime::bundle::container_id(&sidecar, 0);
    // **The identifier the socket carries** (ADR-0081) -- secured before the move
    // into the seeding so that the assurance names the same one.
    let attested: std::sync::Arc<str> = std::sync::Arc::from(id.as_str());
    let _cleanup = Cleanup::new(
        id,
        paths.runtime_root(),
        runtime.name().to_owned(),
        dir.path().to_path_buf(),
    );

    let context = plain_context();

    // Pass 1: the bundle arises, the container fails at its missing socket. Exactly
    // that is what the neighbouring test checks, and here it is the way to the
    // rootfs.
    let first = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("pass");
    assert!(first.failed.is_empty(), "{first:?}");

    let rootfs = paths.bundles_dir().join(&sidecar).join("rootfs");
    let socket = rootfs.join(tg_model::mesh::SOCKET_IN_CONTAINER.trim_start_matches('/'));
    std::fs::create_dir_all(socket.parent().expect("directory")).expect("directory");
    let listener = tokio::net::UnixListener::bind(&socket).expect("socket");
    // `0666` (ADR-0060): the sidecar runs under an identifier of its own, and a
    // connection there demands write permission. The permissions do not authorize --
    // every connection is attested individually (ADR-0053).
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).expect("permissions");

    let (stop, wait) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        // **The socket carries the identifier** (ADR-0081): this one is mounted into
        // the sidecar container, so its caller is this container -- without a cgroup,
        // without a pidfd.
        let stream = tg_identity::incoming_for(listener, Some(attested));
        let _ = tg_identity::serve_on(api, stream, async {
            let _ = wait.await;
        })
        .await;
    });

    // The first pass's trace away, so that the statement is unambiguous.
    let proof = rootfs.join(PROOF.trim_start_matches('/'));
    let _ = std::fs::remove_file(&proof);

    // Pass 2: the same desired state, an ended container -- the reconciler starts
    // anew (ADR-0010).
    let second = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("pass");
    assert!(second.failed.is_empty(), "{second:?}");

    // The needle is `tg-proxy`'s log line.
    let text = await_line(&proof, "the sidecar is ready").unwrap_or_else(|last| {
        panic!(
            "the sidecar did not become ready -- the identity path does not \
             carry: {second:?}\nso far:\n{last}"
        )
    });

    // **Aborted, not cleanly ended** -- and that is a property of the system, no
    // convenience: the sidecar holds the SVID stream **open**, because the rotation
    // comes as a push over it (ADR-0035). `serve` waits at the shutdown for running
    // calls, so it waited forever here -- measured as a hanging test, and a hanging
    // test is worse than a failing one (11b).
    //
    // The container goes away right after anyway (`Cleanup`), and what it had to say
    // already stands in `text`.
    let _ = stop;
    served.abort();

    assert!(
        text.contains("the sidecar is ready"),
        "the sidecar did not become ready -- the identity path does not \
         carry:\n{text}"
    );
    // **The delegated SVID, not its own** (ADR-0036): on the wire lies the workload's
    // identity, without an instance number and without `-proxy`.
    assert!(
        text.contains(&format!("spiffe://cluster.local/workload/{workload}")),
        "the sidecar does not carry its workload's identity:\n{text}"
    );
}

/// The wrapper script: it calls the real program with a command line that corresponds
/// to the derived unit (ADR-0059), and steers both streams into a file.
fn wrapper(workload: &str) -> String {
    format!(
        "#!/bin/sh\nexec >{PROOF} 2>&1\n{program} --workload {workload} \
         --upstream-port 8080 --socket {socket} --telemetry-addr off\n",
        program = tg_model::mesh::PROGRAM_IN_CONTAINER,
        socket = tg_model::mesh::SOCKET_IN_CONTAINER,
    )
}
