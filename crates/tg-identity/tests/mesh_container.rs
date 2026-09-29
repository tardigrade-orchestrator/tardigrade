//! **Two real sidecar containers, and mTLS between them.**
//!
//! The path this system builds was substantiated at every place individually and
//! never together:
//!
//! | What | Where | What was missing there |
//! |---|---|---|
//! | mTLS end to end | `tg-proxy/tests/sidecar.rs` | a test process, no container |
//! | the redirect at real packets | `tg-proxy/tests/mesh_netns.rs` | a test process, a staged PKI |
//! | the sidecar in a container | `sidecar_image.rs` | no counterpart |
//! | container to container | `tg-net/tests/two_nodes.rs` | without a sidecar |
//!
//! Here both are: **two containers with the real `tg-proxy`**, each with a **real
//! delegated SVID** fetched over an attested socket, a kernel-level redirect in the
//! namespace, and authorization enforced at the `may_talk` edge.
//!
//! # The build-up
//!
//! ```text
//!   netns tg-api                        netns tg-ledger
//!     client (nobody) ──► 10.42.1.3:9000
//!            │ nft redirect (output, skuid != 65532)
//!            ▼
//!     api-proxy :15001  ──mTLS──►  ┄veth┄ tg0 ┄veth┄ ──► 10.42.1.3:9000
//!     (container, SVID api)                            │ nft redirect
//!                                                      ▼   (prerouting)
//!                                        ledger-proxy :15006 (container,
//!                                        SVID ledger) ──► 127.0.0.1:<mesh>
//!                                                             echo
//! ```
//!
//! **Two namespaces and not one**, and that is measured, not taste: the derived unit
//! listens on `15006` and the redirect there sits in a **prerouting** chain. That
//! fires for a packet that arrives over an interface -- on loopback in the same
//! namespace not reliably. `mesh_netns` gets around that by having its inbound sidecar
//! bind the peer address directly; a **real** sidecar cannot do that, because its
//! command line comes from `tg_model::mesh`.
//!
//! # Why the reconciler derives the sidecars
//!
//! They are **not** built by hand. The reconciler gets `Context.mesh` as in operation,
//! derives the sidecar from `<mesh port="…"/>`, assigns it a user identifier of its
//! own so the redirect rule set can exempt it, and mounts the four files a sidecar
//! expects to find in its container. With that the test checks the command line the
//! product produces and not one it wrote itself -- and the one socket reaches **both**
//! containers without the test having to mount anything.
//!
//! # Why the workloads sleep
//!
//! An image without `nc` cannot listen, and the statement does not hang on it: a
//! workload's upstream is an ordinary TCP listener, and the client is a process in the
//! namespace. The test provides both -- what is checked is the way **between** them.
//! The containers of `api` and `ledger` run all the same: without them there would be
//! no derivation and no delegation -- the sidecar is derived from its own workload's
//! placement, so co-location follows automatically rather than being scheduled for.
//!
//! `#[ignore]`: demands an OCI runtime, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `nft`, `ip`
//! and `runuser` -- run with `cargo xtask net`.

mod containers;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use containers::{Cleanup, base_layer, probe_layer, seed};
use tg_net::ipam::{ClusterNet, NodeSubnet};
use tg_runtime::content::ContentStore;
use tg_runtime::network::Probe;

/// The workload that dials.
const CLIENT: &str = "api";
/// The workload that answers.
const SERVER: &str = "ledger";
/// Where the server's upstream listens -- the setting from `<mesh port="…"/>`.
const UPSTREAM: u16 = 8080;
/// The port the client means. It stands in **no** route list.
const PEER_PORT: u16 = 9000;
/// What the echo gives back.
const MARK: &str = "ledger-echo";

/// Computes the overlay MTU the same way the node computes it in operation, by
/// subtracting the tunnel encapsulation overhead from the link MTU.
///
/// # Panics
///
/// Panics if the computed value does not fit the expected range.
fn mtu() -> u16 {
    tg_net::ipam::Mtu::for_overlay(1500)
        .expect("1500 carries")
        .get()
}

/// **Two containers speak mTLS, and the edge decides.**
///
/// The client never names a sidecar port: it dials `10.42.1.3:9000`, and that the
/// echo's marker comes back is the whole evidence -- for the redirect, for two real
/// SVIDs out of an attested socket, for the handshake between them and for the edge
/// that permits it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands a runtime, CAP_NET_ADMIN and CAP_SYS_ADMIN; over `cargo xtask net`"]
async fn two_containerised_sidecars_speak_mtls() {
    let answer = run(&[(CLIENT, SERVER)]).await;
    assert!(
        answer.contains(MARK),
        "the path does not carry -- what was answered: {answer:?}"
    );
}

/// **Without an edge nothing gets through** -- not between containers either.
///
/// The counter-check, and it carries the test above: "nothing arrives" is what this
/// build-up would get too if the rule set were not loaded, a container had not started
/// up or the veth pair were missing. Only because the same build-up **with** an edge
/// delivers the marker does the empty answer say something about the authorization
/// policy rather than about a broken build-up.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands a runtime, CAP_NET_ADMIN and CAP_SYS_ADMIN; over `cargo xtask net`"]
async fn without_an_edge_the_containerised_sidecars_carry_nothing() {
    let answer = run(&[]).await;
    assert!(
        !answer.contains(MARK),
        "without an edge traffic got through: {answer:?}"
    );
}

// ============================================================ The build-up

/// Runs the whole build-up -- node network, identity service, two containerised
/// sidecars and their workloads -- and returns what the client read back from its
/// dial attempt.
///
/// `edges` lists the `(from, to)` pairs written into the `may-talk` file, i.e. which
/// mesh members are authorized to talk to which; an empty slice means no edges at all.
///
/// Returns the combined stdout and stderr of the client's dial attempt: it contains
/// the echo's marker on success, and does not otherwise.
///
/// # Panics
///
/// Panics if any setup step -- runtime discovery, the content store, the network
/// fixture, or the reconcile pass -- fails, since those are preconditions of the test
/// rather than outcomes under test.
async fn run(edges: &[(&str, &str)]) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime = tg_runtime::oci::OciRuntime::discover(
        tg_runtime::oci::DEFAULT_RUNTIMES,
        paths.runtime_root(),
    )
    .expect("no OCI runtime in the PATH");
    let store = ContentStore::open(paths.content_dir()).expect("store");

    // Without a subscriber, `tracing` discards events silently, and the identity
    // service logs its refusals at `warn!` level.
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    // --- The node network: one bridge, two instance namespaces.
    let cluster = ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24).expect("valid");
    let subnet = cluster.subnet(1).expect("valid");
    let net = Fixture::new(&cluster, &subnet);

    // --- The four files a sidecar expects to find mounted in its container.
    let network = paths.data_dir().join("network");
    std::fs::create_dir_all(&network).expect("directory");
    let mut text = String::new();
    for (from, to) in edges {
        use std::fmt::Write as _;
        let _ = writeln!(text, "{from} -> {to}");
    }
    std::fs::write(network.join("may-talk"), text).expect("edges");
    std::fs::write(network.join("egress"), "").expect("egress");
    std::fs::write(network.join("active-role"), "").expect("roles");

    // --- The identity service: **one** CA for both sidecars.
    let _identity = serve_identity(&paths);

    // --- The images: the real `tg-proxy` for the sidecars, a sleeper for the
    //     workloads.
    let base = base_layer(&store);
    seed(&store, PROXY_IMAGE, std::slice::from_ref(&base));
    let sleeper = probe_layer(&store, "#!/bin/sh\nexec sleep 600\n");
    seed(&store, SLEEPER_IMAGE, &[base, sleeper]);

    // --- The desired state: two mesh members.
    let cache = tg_runtime::state::DesiredState::open(paths.data_dir()).expect("cache");
    for (name, port) in [(CLIENT, PEER_PORT), (SERVER, UPSTREAM)] {
        let set = tg_defs::from_str(&definition(name, port)).expect("the definition parses");
        cache
            .put(&set.workloads()[0])
            .expect("filing the definition");
        cache.assign(name, &[0]).expect("assignment");
    }

    let _cleanups: Vec<Cleanup> = [CLIENT, SERVER]
        .iter()
        .flat_map(|name| [(*name).to_owned(), tg_model::mesh::sidecar_name(name)])
        .map(|name| {
            Cleanup::new(
                tg_runtime::bundle::container_id(&name, 0),
                paths.runtime_root(),
                runtime.name().to_owned(),
                dir.path().to_path_buf(),
            )
        })
        .collect();

    // --- And the pass, with **mesh** as in operation.
    let sockets = TestSockets::new(paths.data_dir());
    let mesh = tg_runtime::network::Mesh {
        // No surcharge: this test checks the identity, not resource limits.
        overhead: dir.path().join("no-surcharge"),
        // This build-up's trust domain -- it must fit the SVIDs the minter mints,
        // otherwise the sidecar cannot validate the certificate chain back to its
        // trust anchor.
        spec: tg_model::SidecarSpec::new(PROXY_IMAGE, "cluster.local").expect("spec"),
        mounts: mounts(&network),
    };
    let context = tg_runtime::reconcile::Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        now: &|| 0,
        fence_margin: 0,
        wake: None,
        keep_snapshots: 3,
        quorum: tg_model::Quorum::Available,
        network: Some(&net),
        mesh: Some(&mesh),
        workload_api: Some(&sockets),
        secrets: None,
        credentials: None,
        empty: &|| tg_runtime::reconcile::EmptyMeans::NothingWanted,
    };
    let report = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("pass");
    assert!(
        report.failed.is_empty(),
        "a container did not start up: {report:?}"
    );

    // --- The echo in the server's namespace, and the call from the client's.
    let echo = echo_in(&tg_runtime::bundle::container_id(SERVER, 0));
    let answer = dial_as_nobody(
        &tg_runtime::bundle::container_id(CLIENT, 0),
        &Fixture::peer_address(),
    );
    drop(echo);

    answer
}

/// Under which reference the real `tg-proxy` lies.
const PROXY_IMAGE: &str = "tardigrade.local/mesh-proxy:dev";
/// And under which the sleeper the workloads run.
const SLEEPER_IMAGE: &str = "tardigrade.local/mesh-sleeper:dev";

/// Renders a mesh-member workload definition as an operator would write it.
///
/// `<mesh port="…"/>` is at the same time the opt-in and the only setting the sidecar
/// needs -- everything further the node derives.
///
/// `name` is the workload's name and `upstream` is the port its own process listens
/// on; returns the XML document text.
fn definition(name: &str, upstream: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="{name}" kind="service">
    <image reference="{SLEEPER_IMAGE}"/>
    <command>
      <arg>/wrapper</arg>
    </command>
    <mesh port="{upstream}"/>
  </workload>
</workloads>"#
    )
}

/// Builds the four mounts a sidecar expects in its container -- **the same list the
/// node's agent mounts in operation**.
///
/// The socket writable (using it means writing into it), the three files read-only: a
/// sidecar that could change its own permission list would be no enforcement.
///
/// `network` is the directory holding the `may-talk`, `egress` and `active-role`
/// files; returns the mount list to attach to the sidecar's container.
fn mounts(network: &std::path::Path) -> Vec<tg_runtime::bundle::VolumeMount> {
    use tg_runtime::bundle::VolumeMount;

    vec![
        VolumeMount {
            source: network.join("may-talk"),
            destination: tg_model::mesh::EDGES_IN_CONTAINER.to_owned(),
            readonly: true,
        },
        VolumeMount {
            source: network.join("egress"),
            destination: tg_model::mesh::EGRESS_IN_CONTAINER.to_owned(),
            readonly: true,
        },
        VolumeMount {
            source: network.join("active-role"),
            destination: tg_model::mesh::ROLE_IN_CONTAINER.to_owned(),
            readonly: true,
        },
    ]
}

/// This test's stand-in for the node's per-container workload API sockets.
///
/// It does what `tg_agent::sockets::Listeners` does: **bind** when the socket is
/// missing. The first attempt returned only the path -- and `youki` aborted ("failed
/// to canonicalize ... No such file or directory"), because a bind mount needs an
/// existing source file: the socket must exist before the container starts, or the
/// mount itself fails.
///
/// For the **sidecars** it lies there already (`serve_identity` bound it and put a
/// service on it), for the **workloads** it arises here. Both paths come from the same
/// function -- two derivations would be two opportunities for mount and listener to
/// point at two sockets.
struct TestSockets {
    dir: std::path::PathBuf,
    /// The listeners this fixture bound itself.
    ///
    /// Held, because a discarded `UnixListener` leaves its socket inode unusable --
    /// and the mount then finds it, but nobody accepts on it.
    held: std::sync::Mutex<Vec<std::os::unix::net::UnixListener>>,
}

impl TestSockets {
    /// Creates a fresh, empty socket registry rooted at `dir`.
    fn new(dir: &std::path::Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            held: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl tg_runtime::network::Sockets for TestSockets {
    /// Returns the workload API socket path for `container`, binding a listener at
    /// that path first if one is not already bound.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket directory cannot be created or the socket
    /// cannot be bound.
    fn ensure(&self, container: &str) -> Result<std::path::PathBuf, String> {
        let dir = self.dir.join("sockets");
        std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
        let path = dir.join(format!("{container}.sock"));

        if !path.exists() {
            let listener =
                std::os::unix::net::UnixListener::bind(&path).map_err(|err| err.to_string())?;
            self.held.lock().expect("listener").push(listener);
        }

        Ok(path)
    }

    /// Reports the containers this fixture considers to be holding a socket lease.
    ///
    /// Always empty: this fixture does not model socket release, only binding.
    fn held(&self) -> Vec<String> {
        Vec::new()
    }

    /// Releases a container's socket lease.
    ///
    /// A no-op: this fixture has no leases to release, sockets stay bound for the
    /// lifetime of the fixture.
    fn release(&self, _container: &str) {}
}

/// Computes a container's workload API socket path -- the same convention as
/// `tg_agent::sockets::Listeners` -- without binding anything.
///
/// `paths` gives the node's data directory and `container` names the container the
/// socket belongs to; returns the path the socket would be bound at.
fn socket_of(paths: &tg_runtime::NodePaths, container: &str) -> std::path::PathBuf {
    // **Only compute, do not bind** -- `ensure` binds, and whoever does both gets
    // `AddrInUse`.
    paths
        .data_dir()
        .join("sockets")
        .join(format!("{container}.sock"))
}

/// Starts the identity service and serves the workload API for both sidecars, one
/// listener **per container**.
///
/// Until here it was one for all, and the cgroup separated. Now the mount separates:
/// every sidecar gets its own socket, and that names it.
///
/// **One** CA for both sidecars, and that it is one is half the assurance: the
/// verifier checks the counterpart's certificate chain against its trust bundle, and
/// two CAs would yield two anchors that do not know each other.
///
/// `paths` gives the node's data directory the sockets are bound under; returns the
/// spawned server task handles, kept so the caller can decide when to drop them.
fn serve_identity(paths: &tg_runtime::NodePaths) -> Vec<tokio::task::JoinHandle<()>> {
    use std::os::unix::fs::PermissionsExt as _;

    // **Both identifiers come from the same function** that assigns them in
    // operation -- the mapping is always resolved forward from an assigned name to a
    // container identifier, never computed backward from one -- and the workload
    // itself belongs to it: `svid_named` checks whether the delegation's **target**
    // is assigned to this node.
    let mut assigned = BTreeMap::new();
    let mut delegations = BTreeMap::new();
    for name in [CLIENT, SERVER] {
        let sidecar = tg_model::mesh::sidecar_name(name);
        assigned.insert(tg_runtime::bundle::container_id(name, 0), name.to_owned());
        assigned.insert(
            tg_runtime::bundle::container_id(&sidecar, 0),
            sidecar.clone(),
        );
        delegations.insert(sidecar, name.to_owned());
    }

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

    let mut serving = Vec::new();
    for name in [CLIENT, SERVER] {
        let container = tg_runtime::bundle::container_id(&tg_model::mesh::sidecar_name(name), 0);
        let path = socket_of(paths, &container);
        std::fs::create_dir_all(path.parent().expect("directory")).expect("directory");
        let listener = tokio::net::UnixListener::bind(&path).expect("socket");
        // `0666`: the sidecar runs under a user identifier of its own, and a
        // connection there demands write permission. The permissions do **not**
        // authorize -- what separates callers is which socket path is mounted into
        // their container.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("permissions");

        let api = api.clone();
        serving.push(tokio::spawn(async move {
            // **The socket carries the identifier**: a caller is known by which
            // socket path was mounted into its container, not by anything it
            // presents on the connection.
            let stream =
                tg_identity::incoming_for(listener, Some(std::sync::Arc::from(container.as_str())));
            let _ = tg_identity::serve_on(api, stream, std::future::pending::<()>()).await;
        }));
    }

    serving
}

// ========================================================= The node network

/// The bridge, the instance namespaces and the rule set -- a thin stand-in for
/// `tg-agent::network`.
///
/// **Thin and not rebuilt**: every line calls the same function the agent calls. What
/// does not stand here is the address ledger -- the addresses are two constants,
/// because address assignment itself is tested elsewhere and is not the subject here.
struct Fixture {
    subnet: NodeSubnet,
    cluster: ClusterNet,
    addresses: std::sync::Mutex<BTreeMap<String, Ipv4Addr>>,
    namespaces: std::sync::Mutex<Vec<String>>,
}

impl Fixture {
    /// Creates the fixture and ensures the shared bridge for `subnet` exists on the
    /// host, within `cluster`'s address space.
    fn new(cluster: &ClusterNet, subnet: &NodeSubnet) -> Self {
        tg_net::link::ensure_bridge(subnet, mtu()).expect("bridge");

        Self {
            subnet: subnet.clone(),
            cluster: cluster.clone(),
            addresses: std::sync::Mutex::new(BTreeMap::from([
                (
                    tg_runtime::bundle::container_id(CLIENT, 0),
                    "10.42.1.2".parse().expect("valid"),
                ),
                (
                    tg_runtime::bundle::container_id(SERVER, 0),
                    "10.42.1.3".parse().expect("valid"),
                ),
            ])),
            namespaces: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// The address the client dials -- with a port.
    ///
    /// A constant and no query at the ledger: that it does **not** come from the
    /// assignment is right here -- the client shall name an address that stands in no
    /// route list.
    fn peer_address() -> String {
        format!("10.42.1.3:{PEER_PORT}")
    }
}

impl tg_runtime::network::Wiring for Fixture {
    /// Attaches instance `instance` of `workload` to its pre-assigned address and
    /// creates its network namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if no address was reserved for this container, or if
    /// creating the namespace fails.
    fn attach(
        &self,
        workload: &str,
        instance: u32,
    ) -> Result<tg_runtime::network::Attachment, String> {
        let netns = tg_runtime::bundle::container_id(workload, instance);
        let address = *self
            .addresses
            .lock()
            .expect("lock")
            .get(&netns)
            .ok_or_else(|| format!("no address for {netns}"))?;

        let path = tg_net::link::ensure_instance(&netns, address, &self.subnet, mtu())
            .map_err(|err| err.to_string())?;
        self.namespaces.lock().expect("lock").push(netns);

        Ok(tg_runtime::network::Attachment {
            netns: path,
            // No node-local resolver in this build-up: the client names an address
            // directly, and DNS resolution itself is tested elsewhere.
            resolv_conf: None,
        })
    }

    /// Lists the container identifiers whose namespaces this fixture created.
    fn leased(&self) -> Vec<String> {
        self.namespaces.lock().expect("lock").clone()
    }

    /// Deletes `container`'s network namespace, ignoring any error.
    fn release(&self, container: &str) {
        let _ = tg_syscall::netns::delete(container);
    }

    /// Does nothing here: a sidecar always runs in this namespace, so `enforce`
    /// lays the complete rule set itself.
    fn ensure_baseline(&self, _netns: &str) {
        // A sidecar runs here, so `enforce` lays the full rule set -- both at once
        // would overwrite each other's rules.
    }

    /// Renders and applies the full nftables rule set for `netns`, including the
    /// sidecar's redirect and exemption rules.
    ///
    /// # Panics
    ///
    /// Panics if the rule set cannot be serialized or applied.
    fn enforce(&self, netns: &str, _workload: &str) {
        let rules = tg_net::rules::NetnsRules::new(
            &self.cluster,
            &self.subnet,
            tg_model::mesh::SIDECAR_UID,
        );
        let json = tg_net::rules::to_json(&rules.render()).expect("serializable");
        tg_net::nft::apply_in(netns, &json).expect("the namespace rule set");
    }

    /// Reports readiness for any container as trivially ready.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    fn probe(&self, _container: &str, _probe: Probe<'_>) -> Result<(), String> {
        // No definition of this test declares a readiness probe, so no asking ever
        // happens here. `Ok` and no `unreachable!`: a panic in a fixture would take
        // the test's statement from it and replace it with a crash.
        Ok(())
    }
}

impl Drop for Fixture {
    /// Deletes every namespace this fixture created, plus the two workload
    /// namespaces, ignoring errors.
    fn drop(&mut self) {
        for netns in self.namespaces.lock().expect("lock").iter() {
            let _ = tg_syscall::netns::delete(netns);
        }
        for name in [CLIENT, SERVER] {
            let _ = tg_syscall::netns::delete(&tg_runtime::bundle::container_id(name, 0));
        }
    }
}

// ========================================= The client and echo in the namespace

/// Starts the server's upstream: an ordinary TCP listener **in** its namespace, on
/// loopback, that echoes back a marker on the first successful read.
///
/// On **one** thread with **one** single-threaded runtime: `run_in` enters the calling
/// thread's namespace, and a multi-threaded runtime would lay its workers beside it in
/// the host namespace (the finding from `mesh_netns`).
///
/// `netns` names the namespace to listen in; returns a handle that keeps the
/// listener thread alive until dropped.
///
/// # Panics
///
/// Panics if the listener does not come up within ten seconds.
fn echo_in(netns: &str) -> Echo {
    let (ready, wait) = std::sync::mpsc::channel();
    let netns = netns.to_owned();

    let handle = std::thread::spawn(move || {
        let _ = tg_syscall::netns::run_in(&netns, move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");

            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind(("127.0.0.1", UPSTREAM))
                    .await
                    .expect("echo");
                let _ = ready.send(());

                while let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buffer = [0_u8; 64];
                        if let Ok(read) =
                            tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                            && read > 0
                        {
                            let _ =
                                tokio::io::AsyncWriteExt::write_all(&mut stream, MARK.as_bytes())
                                    .await;
                        }
                    });
                }
            });
        });
    });

    wait.recv_timeout(std::time::Duration::from_secs(10))
        .expect("the echo in the namespace did not come up");

    Echo(Some(handle))
}

/// The echo, as long as it is needed.
struct Echo(Option<std::thread::JoinHandle<()>>);

impl Drop for Echo {
    /// Drops the listener thread's handle without joining it.
    fn drop(&mut self) {
        // **Not collected**, and that is deliberate: the thread listens in an
        // endless loop, and a `join` would hang there. It ends with the test process.
        // The same rationale applies to any test thread that runs an intentionally
        // endless loop: joining it would hang, so it is simply dropped and left to
        // end together with the process.
        let _ = self.0.take();
    }
}

/// Dials `peer` from inside `netns` -- as `nobody`, so that the redirect bites.
///
/// **Not as `root`**: the exception in the rule set hangs on the sidecar's own user
/// identifier (`meta skuid`). If the client ran under the same one, it would be
/// exempt along with it, and the test would prove nothing.
///
/// Retries once a second for up to twenty seconds, since the sidecar needs to fetch
/// its first SVID before it can complete a handshake. Returns the combined stdout
/// and stderr of the dial attempt.
///
/// # Panics
///
/// Panics if `ip netns exec` itself cannot be started.
fn dial_as_nobody(netns: &str, peer: &str) -> String {
    // One attempt per second, for the sidecar in the container needs its first SVID
    // fetch before it can carry out a handshake.
    let script = format!(
        "for i in $(seq 1 20); do \
           out=$(printf 'ping' | timeout 3 bash -c 'exec 3<>/dev/tcp/{host}/{port}; \
                 cat >&3; timeout 2 cat <&3') && \
           case \"$out\" in *{MARK}*) printf '%s' \"$out\"; exit 0;; esac; \
           sleep 1; \
         done; printf 'nothing'",
        host = peer.split(':').next().expect("address"),
        port = peer.split(':').nth(1).expect("port"),
    );

    let out = std::process::Command::new("ip")
        .args([
            "netns", "exec", netns, "runuser", "-u", "nobody", "--", "bash", "-c", &script,
        ])
        .output()
        .expect("ip netns exec must be startable");

    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
