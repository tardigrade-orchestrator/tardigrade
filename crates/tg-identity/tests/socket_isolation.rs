//! **Two real containers, and each gets only its own identity** (ADR-0081).
//!
//! # What is checked here for the first time
//!
//! ADR-0081 says: *"the socket **is** the attestation"* -- one per instance, mounted
//! into exactly its container. The price stands there likewise: the security moves
//! from a **kernel** property (`SO_PEERPIDFD`) to a property of **our code**, and the
//! ADR carried as an open point:
//!
//! > **No witness over two containers** that cannot reach each other. The property
//! > follows from the mount namespace and is measured at a bind mount, not at two
//! > running containers.
//!
//! Here there are two running containers. Both reach for **the same path**
//! (`SOCKET_IN_CONTAINER`, a constant from ADR-0059), and both get something different
//! -- that is the statement, and it cannot be made with one container.
//!
//! # Two assurances, and the second carries the first
//!
//! 1. **Each gets its own.** `api` gets `.../workload/api`, `ledger` gets
//!    `.../workload/ledger` -- at the same path, in the same image, with the same
//!    program. The only difference is the **mount**.
//! 2. **Neither can get at the other's.** The directory in which both sockets lie on
//!    the host is in neither of the two mount namespaces. Without that second
//!    assurance the first would prove only that the mount works -- not that it
//!    **separates**.
//!
//! The second is **counter-checked**: point the same witness at a directory that
//! exists in the container (`/bin`) and it turns red and names `reachable`. An
//! assurance that was green only because it never applies is none (the finding from
//! 9c).
//!
//! `#[ignore]`: demands an OCI runtime and `CAP_SYS_ADMIN` -- run with
//! `cargo xtask storage`, which executes `cargo xtask image` beforehand.

mod containers;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use containers::{Cleanup, PROOF, await_line, base_layer, definition, probe_layer, seed};
use tg_runtime::content::ContentStore;

/// The two workloads. Two, because the statement is one about **separation**.
const WORKLOADS: [&str; 2] = ["tg-iso-api", "tg-iso-ledger"];

/// The name of a workload's sidecar (ADR-0059).
fn sidecar(workload: &str) -> String {
    format!("{workload}-proxy")
}

/// Who produces the sockets -- and runs the service behind them.
///
/// **The real construction** (ADR-0081): one socket per instance under
/// `<data-dir>/sockets/<container-id>.sock`, the directory `0700`, and the connection
/// carries the identifier because the socket is mounted into exactly this container.
/// No `pidfd`, no cgroup.
struct Sockets {
    dir: PathBuf,
    minter: Arc<std::sync::Mutex<Option<tg_identity::Minter<tg_identity::LocalSigner>>>>,
    anchor: Vec<u8>,
    served: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    handle: tokio::runtime::Handle,
}

impl tg_runtime::network::Sockets for Sockets {
    fn ensure(&self, container: &str) -> Result<PathBuf, String> {
        use std::os::unix::fs::PermissionsExt as _;

        // **Follow no symlink.** While building I pointed the counter-check
        // at `/bin` -- a symlink to `/usr/bin` --, and `set_permissions`
        // followed it: the system directory stood at `0700` afterwards, and on
        // the machine no unprivileged process could execute anything any more.
        // A test helper that chmods a **handed-in** path is a trap; this line
        // closes exactly the one that snapped shut.
        //
        // **Not** "must be new": both containers share this directory, as in
        // operation too (ADR-0081).
        if std::fs::symlink_metadata(&self.dir).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(format!(
                "{} is a symlink -- no chmod happens here",
                self.dir.display()
            ));
        }
        std::fs::create_dir_all(&self.dir).map_err(|err| err.to_string())?;
        // **`0700` on the directory, not on the file** (ADR-0115): the socket
        // itself must be writable, because a connection to it demands write
        // permission (ADR-0060).
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| err.to_string())?;

        let path = self.dir.join(format!("{container}.sock"));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .map_err(|err| err.to_string())?;

        let minter = self
            .minter
            .lock()
            .map_err(|_| "the minter is poisoned".to_owned())?
            .take()
            .ok_or_else(|| "the minter is already given out".to_owned())?;
        let api = tg_identity::WorkloadApi::new(
            minter,
            vec![self.anchor.clone()],
            Arc::new(tg_identity::SystemClock),
        );

        // **The identifier comes from the mount**, not from the kernel: this
        // socket is about to be bound into exactly this container, so its
        // caller is this container (ADR-0081, determination 2).
        let attested: Arc<str> = Arc::from(container);
        let handle = self.handle.clone();
        let served = handle.spawn(async move {
            let listener =
                tokio::net::UnixListener::from_std(listener).expect("taking the socket over");
            let stream = tg_identity::incoming_for(listener, Some(attested));
            let _ = tg_identity::serve_on(api, stream, std::future::pending::<()>()).await;
        });
        self.served
            .lock()
            .map_err(|_| "the task list is poisoned".to_owned())?
            .push(served);

        Ok(path)
    }

    fn held(&self) -> Vec<String> {
        Vec::new()
    }

    fn release(&self, _container: &str) {}
}

/// The wrapper script.
///
/// It does **two** things, and the second is the actual assurance: it fetches its
/// identity over the mounted socket, and it looks whether it gets at the host
/// directory in which both sockets lie.
///
/// **`cd` and not `ls`**: the image carries a shell and the real `tg-proxy`, nothing
/// else -- measured as `ls: command not found`. `cd` is a builtin and answers the same
/// question.
fn wrapper(workload: &str, host_dir: &str) -> String {
    format!(
        "#!/bin/sh\nexec >{PROOF} 2>&1\n\
         echo \"host-dir:\"\n\
         if cd {host_dir} 2>/dev/null; then echo reachable; else echo \"no access\"; fi\n\
         cd /\n\
         echo \"--\"\n\
         {program} --workload {workload} --upstream-port 8080 \
         --socket {socket} --telemetry-addr off\n",
        program = tg_model::mesh::PROGRAM_IN_CONTAINER,
        socket = tg_model::mesh::SOCKET_IN_CONTAINER,
    )
}

/// Lays out image, declaration and socket producer for both workloads.
///
/// **A function of its own**, because the witness would otherwise go over the length
/// limit -- and because the same thing happens twice here for two names: exactly the
/// symmetry its statement rests on.
struct Material<'a> {
    domain: &'a tg_identity::TrustDomain,
    key: &'a str,
    anchor: &'a [u8],
    assigned: &'a BTreeMap<String, String>,
    delegations: &'a BTreeMap<String, String>,
}

fn prepare(
    store: &ContentStore,
    paths: &tg_runtime::NodePaths,
    host_dir: &std::path::Path,
    material: &Material<'_>,
) -> Vec<Sockets> {
    let Material {
        domain,
        key,
        anchor,
        assigned,
        delegations,
    } = material;
    let cache = tg_runtime::state::DesiredState::open(paths.data_dir()).expect("cache");
    let mut sockets = Vec::new();
    for name in WORKLOADS {
        let proxy = sidecar(name);
        let base = base_layer(store);
        let over = probe_layer(store, &wrapper(&proxy, &host_dir.display().to_string()));
        let reference = format!("tardigrade.local/{proxy}:dev");
        seed(store, &reference, &[base, over]);

        let set =
            tg_defs::from_str(&definition(&proxy, &reference)).expect("the definition parses");
        cache
            .put(&set.workloads()[0])
            .expect("filing the definition");
        cache.assign(&proxy, &[0]).expect("assignment");

        let mine = tg_identity::LocalSigner::from_pem(key).expect("key");
        let authority = tg_identity::Authority::new(
            tg_identity::self_signed_ca(domain, &mine, 0, 10 * 365 * 24 * 3_600).expect("CA"),
            tg_identity::LocalSigner::from_pem(key).expect("key"),
            tg_identity::Lifetime::default(),
        )
        .expect("issuer");
        sockets.push(Sockets {
            dir: host_dir.to_path_buf(),
            minter: Arc::new(std::sync::Mutex::new(Some({
                let mut minter = tg_identity::Minter::new(
                    authority,
                    (*domain).clone(),
                    i64::MAX,
                    (*assigned).clone(),
                );
                // **Who may speak for whom** (ADR-0036). Without this line the
                // sidecar would get only its own SVID, and `tg-proxy` looks for
                // the one with `hint = "delegated"`.
                minter.set_delegations((*delegations).clone());
                minter
            }))),
            anchor: anchor.to_vec(),
            served: std::sync::Mutex::new(Vec::new()),
            handle: tokio::runtime::Handle::current(),
        });
    }
    sockets
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands an OCI runtime and CAP_SYS_ADMIN; via `cargo xtask storage`"]
async fn two_containers_each_get_only_their_own_identity() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let dir = tempfile::tempdir().expect("tempdir");
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime = tg_runtime::oci::OciRuntime::discover(
        tg_runtime::oci::DEFAULT_RUNTIMES,
        paths.runtime_root(),
    )
    .expect("no OCI runtime in the PATH");
    let store = ContentStore::open(paths.content_dir()).expect("store");

    // **The host directory of the sockets** -- the path no container may
    // see.
    let host_dir = dir.path().join("sockets");

    // **Both sides of every pair.** The container that runs is the
    // **sidecar** -- `tg-proxy` demands a delegated SVID and ends itself
    // without one (ADR-0036, measured). Its workload belongs to it, because the
    // delegation checks whether the **target** is assigned to this node.
    let mut assigned: BTreeMap<String, String> = BTreeMap::new();
    let mut delegations: BTreeMap<String, String> = BTreeMap::new();
    for name in WORKLOADS {
        let proxy = sidecar(name);
        assigned.insert(tg_runtime::bundle::container_id(&proxy, 0), proxy.clone());
        assigned.insert(tg_runtime::bundle::container_id(name, 0), name.to_owned());
        delegations.insert(proxy, name.to_owned());
    }

    let domain = tg_identity::TrustDomain::new("cluster.local").expect("domain");
    let signer = tg_identity::LocalSigner::generate().expect("key");
    let ca = tg_identity::self_signed_ca(&domain, &signer, 0, 10 * 365 * 24 * 3_600).expect("CA");
    let anchor = ca.certificate_der().to_vec();
    // **The same key for both services.** Every socket needs its own `Minter`
    // (the `WorkloadApi` consumes it), but **two CAs would make the witness
    // green for the wrong reason**: then the identities would be different
    // simply because they come from different hands. Here the only difference
    // is the **mount**.
    let key = signer.to_pem();
    let cleanup: Vec<Cleanup> = WORKLOADS
        .iter()
        .map(|name| {
            Cleanup::new(
                tg_runtime::bundle::container_id(&sidecar(name), 0),
                paths.runtime_root(),
                runtime.name().to_owned(),
                dir.path().to_path_buf(),
            )
        })
        .collect();

    let mut sockets = prepare(
        &store,
        &paths,
        &host_dir,
        &Material {
            domain: &domain,
            key: &key,
            anchor: &anchor,
            assigned: &assigned,
            delegations: &delegations,
        },
    );

    // **One producer for both containers**, because the reconciler has one
    // `Context`. It assigns a socket and a service of its own per identifier --
    // exactly as the agent does.
    let all = Both {
        first: sockets.remove(0),
        second: sockets.remove(0),
    };

    let context = tg_runtime::reconcile::Context {
        workload_api: Some(&all),
        ..plain_context()
    };

    let run = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("pass");
    assert!(run.failed.is_empty(), "{run:?}");

    for name in WORKLOADS {
        // **The bundle carries the sidecar's name**, not its principal's -- the
        // container that runs is the sidecar.
        let proof = paths
            .bundles_dir()
            .join(sidecar(name))
            .join("rootfs")
            .join(PROOF.trim_start_matches('/'));
        // The needle is `tg-proxy`'s log line.
        let text = await_line(&proof, "the sidecar is ready").unwrap_or_else(|last| {
            // **Says what was there**, not merely that something is missing: an
            // empty proof and a missing one are two findings, and without this line
            // the difference costs a search for the error.
            panic!(
                "`{name}` did not become ready.\nProof: {} (exists: {})\n\
                 so far:\n{last}",
                proof.display(),
                proof.exists()
            )
        });

        // **1. Each gets its own.** The same path, the same image, the same program
        // -- the only difference is the mount.
        assert!(
            text.contains(&format!("spiffe://cluster.local/workload/{name}")),
            "`{name}` does not carry its own identity:\n{text}"
        );
        for other in WORKLOADS.iter().filter(|other| **other != name) {
            assert!(
                !text.contains(&format!("spiffe://cluster.local/workload/{other}")),
                "`{name}` got `{other}`'s identity -- then the mount does not \
                 separate (ADR-0081):\n{text}"
            );
        }

        // **2. Neither gets at the directory in which both sockets lie.** Without
        // this assurance the first would prove only that the mount works, not that it
        // separates.
        let host = text.split("--").next().unwrap_or_default();
        assert!(
            host.contains("no access"),
            "`{name}` sees the host's socket directory -- with that another \
             container's socket is reachable (ADR-0081):\n{host}"
        );
    }

    drop(cleanup);
}

/// Two producers behind one seam.
///
/// The `Context` takes **one** [`tg_runtime::network::Sockets`]; in operation that is
/// the agent, which produces a socket per identifier. Here two prepared services stand
/// behind it, and `ensure` gives each its own.
struct Both {
    first: Sockets,
    second: Sockets,
}

impl tg_runtime::network::Sockets for Both {
    fn ensure(&self, container: &str) -> Result<PathBuf, String> {
        if container == tg_runtime::bundle::container_id(&sidecar(WORKLOADS[0]), 0) {
            self.first.ensure(container)
        } else {
            self.second.ensure(container)
        }
    }

    fn held(&self) -> Vec<String> {
        Vec::new()
    }

    fn release(&self, _container: &str) {}
}

/// A `Context` without the other seams -- literally the one from
/// `sidecar_image.rs`.
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
