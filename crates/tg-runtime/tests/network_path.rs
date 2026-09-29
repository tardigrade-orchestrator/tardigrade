//! A **real container** in a **real network namespace** (ADR-0012).
//!
//! The seam from `tg_runtime::network` has two sides, and both are checked
//! individually: `tg-net` lays out the namespace, the veth and the address
//! (`cargo xtask net`), and `bundle::spec_for` writes the path into the spec
//! (unit tests). What lies between them is checked only by this test -- that a
//! container the runtime starts **really** lands in the network the agent
//! prepared for it.
//!
//! # The container is the witness, not the test
//!
//! It writes what it sees from inside: its `/etc/resolv.conf` and its routing
//! table. Looking from outside would be weaker -- then the test would check
//! the state it produced itself, and not the one the container sits in.
//!
//! In addition there is a statement no file can deliver: from a **second**
//! namespace the container's address is dialled. Nothing listens there, so the
//! connection is **refused** -- and exactly that is the proof. An address no
//! stack carries would yield a timeout; an `ECONNREFUSED` can only have been
//! sent by the network stack in the container's namespace.
//!
//! `#[ignore]`: demands `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` and an OCI runtime.
//! Run with `cargo xtask net`.

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tg_net::ipam::{ClusterNet, Leases, Mtu, NodeSubnet, host_link};
use tg_runtime::network::{Attachment, Extras, Probe, Wiring};
use tg_runtime::oci::{ContainerStatus, DEFAULT_RUNTIMES, OciRuntime};
use tg_runtime::reconcile::{Context, EmptyMeans};
use tg_runtime::resolved::ResolvedImage;

mod support;
use support::await_line;

const ZONE: &str = "10.42.0.0/16";

/// A port on which **nothing** listens in the container.
const NOWHERE: u16 = 9;

const DEFINITION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1"/>
  </workload>
</workloads>"#;

fn cluster() -> ClusterNet {
    ClusterNet::new(ZONE.parse().expect("valid"), 24).expect("valid")
}

/// A different subnet from `kernel_path.rs` -- the tests do not share the
/// bridge but they do share the address range, and one run is not to disturb
/// the other.
fn subnet() -> NodeSubnet {
    cluster().subnet(1).expect("valid")
}

/// Clears away namespaces and veth pairs even when a test fails.
struct Fixture {
    names: Vec<String>,
    links: Vec<tg_net::ipam::LinkName>,
    rootfs: Option<PathBuf>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = tg_syscall::netns::delete(name);
        }
        for host in &self.links {
            let _ = tg_net::link::detach(host);
        }
        // The rootfs is mounted as overlayfs. If it stays mounted, the next
        // run finds an occupied directory, and `tempfile` cannot get rid of
        // it.
        if let Some(rootfs) = &self.rootfs {
            let _ = tg_syscall::mount::unmount_at(rootfs);
        }
    }
}

/// **A container lands in the network prepared for it.**
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and an OCI runtime; cargo xtask net"]
async fn a_real_container_runs_in_the_prepared_network() {
    let runtime = OciRuntime::discover(DEFAULT_RUNTIMES, "/tmp")
        .expect("no OCI runtime in the PATH -- this test demands youki or crun");

    let dir = tempfile::tempdir().expect("tempdir");
    let mtu = Mtu::for_overlay(1500).expect("1500 carries");
    let subnet = subnet();

    let mut leases = Leases::new(subnet.clone());
    let address = leases.lease("api", 0).expect("room enough");
    let neighbour = leases.lease("ledger", 0).expect("room enough");

    let set = tg_defs::from_str(DEFINITION).expect("the definition parses");
    let workload = &set.workloads()[0];
    let id = tg_runtime::bundle::container_id("api", 0);
    let ns_neighbour = "tg-netpath-nb".to_owned();

    let mut fixture = Fixture {
        names: vec![id.clone(), ns_neighbour.clone()],
        links: vec![host_link(address), host_link(neighbour)],
        rootfs: None,
    };
    for name in &fixture.names {
        let _ = tg_syscall::netns::delete(name);
    }
    for host in &fixture.links {
        let _ = tg_net::link::detach(host);
    }
    let _ = runtime.delete(&id, true).await;

    tg_net::link::ensure_bridge(&subnet, mtu.get()).expect("the bridge");

    // **Exactly what the agent does** (`tg_agent::network::Wiring::attach`):
    // the namespace is named like the container, the address comes from the
    // inventory, and the path goes into the spec.
    let netns = tg_net::link::ensure_instance(&id, address, &subnet, mtu.get())
        .expect("attaching the instance");
    tg_net::link::ensure_instance(&ns_neighbour, neighbour, &subnet, mtu.get())
        .expect("attaching the neighbour");

    let attachment = Attachment {
        netns,
        resolv_conf: Some(format!(
            "nameserver {}\nsearch tardigrade.internal\n",
            subnet.gateway()
        )),
    };

    let layer = dir.path().join("layer");
    build_layer(&layer);

    let built = tg_runtime::bundle::build(
        &dir.path().join("bundles"),
        workload,
        &id,
        &[layer],
        &image(PROOF),
        &[],
        // **Only the network is not the default here.** `Extras` derives
        // `Default`, and the default situation is the hardened one -- written
        // out, every new field would be a line in a witness it does not
        // concern (most recently `devices` from ADR-0143).
        Extras {
            network: Some(&attachment),
            ..Extras::default()
        },
    )
    .expect("the bundle");
    fixture.rootfs = Some(built.rootfs().to_path_buf());

    runtime.create(&id, built.dir()).await.expect("lay out");
    runtime.start(&id).await.expect("start");

    // The container writes its finding and then sleeps. What is waited for
    // is the file and not a fixed time -- a fixed time is either too short
    // (then the test is flaky) or too long (then it costs every run).
    let proof = built.rootfs().join("proof");
    let text = await_line(&proof, "nameserver ").unwrap_or_else(|last| {
        let log = std::fs::read_to_string(built.dir().join("container.log")).unwrap_or_default();
        panic!("the container did not write the marker; so far:\n{last}\nlog:\n{log}");
    });

    assert!(
        text.contains(&format!("nameserver {}", subnet.gateway())),
        "the container does not see our resolver (ADR-0013):\n{text}"
    );
    assert!(
        text.contains("eth0"),
        "there is no eth0 in the container's namespace:\n{text}"
    );

    // **The container sits in *its* namespace, not in just any one.** That
    // is the assertion for whose sake this test exists, and it needs both
    // halves: `/proc/net/fib_trie` names the local addresses of the namespace
    // in which the process really runs. Without the counter-check on the
    // neighbour the test would be green even if the container had landed in
    // the neighbour's network -- the same route and the same `resolv.conf`
    // stand there.
    assert!(
        text.contains(&address.to_string()),
        "the container does not carry its address {address}:\n{text}"
    );
    assert!(
        !text.contains(&neighbour.to_string()),
        "the container sits in the neighbour's namespace ({neighbour}):\n{text}"
    );
    // The default route, in `/proc/net/route`'s spelling: destination
    // 00000000, the gateway as little-endian hex. Without it the container
    // reaches nothing outside its subnet -- not the resolver either, if that
    // one day stands elsewhere.
    assert!(
        text.contains(&format!("eth0\t00000000\t{}", hex_route(subnet.gateway()))),
        "no default route over {} in the container:\n{text}",
        subnet.gateway()
    );

    // **And the address lives.** Dialled from the neighbouring namespace,
    // the container's stack answers with a refusal; an address nobody carries
    // would yield a timeout.
    let refused = tg_syscall::netns::run_in(&ns_neighbour, move || {
        TcpStream::connect_timeout(
            &SocketAddr::from((address, NOWHERE)),
            Duration::from_secs(2),
        )
    })
    .expect("entering the namespace")
    .expect_err("nothing must listen on this port");

    assert_eq!(
        refused.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "the container's address does not answer ({refused}) -- a timeout \
         means that no stack carries it"
    );

    let _ = runtime.delete(&id, true).await;
    drop(fixture);
}

/// A layer that brings a shell and `cat` along.
fn build_layer(layer: &Path) {
    std::fs::create_dir_all(layer.join("bin")).expect("bin");
    for dir in ["proc", "dev", "sys", "etc"] {
        std::fs::create_dir_all(layer.join(dir)).expect("the directory");
    }
    copy_with_libraries("/bin/sh", layer);
    // `cat` is no builtin, and `sleep` is not either.
    copy_with_libraries("/bin/cat", layer);
    copy_with_libraries("/bin/sleep", layer);
    // A listener so that the readiness probe (ADR-0080) has something to
    // find. `ncat` and not `sh`: a shell cannot bind a socket, and without a
    // real listener only the **negative** direction would be checkable.
    copy_with_libraries("/usr/bin/ncat", layer);
}

/// The finding the container writes, and then waiting.
///
/// A container that ends immediately would leave the file behind but no
/// address to dial.
const PROOF: &str = "cat /etc/resolv.conf /proc/net/route /proc/net/fib_trie > /proof; \
                     exec /bin/sleep 30";

/// A workload that listens to `SIGTERM`.
///
/// **`trap` is no subtlety here but the whole difference.** A process that is
/// PID 1 in its own PID namespace gets a signal delivered only if it has
/// installed a **handler** for it -- the kernel does not apply the default
/// handling to PID 1. Without `trap` the same container carries on through the
/// whole deadline and dies only at the `SIGKILL` (see the test beside it,
/// measured).
const COOPERATIVE: &str = "trap 'exit 0' TERM; /bin/sleep 30 & wait";

/// A workload that ignores `SIGTERM` -- the normal case for a slim image.
const STUBBORN: &str = "exec /bin/sleep 30";

fn image(command: &str) -> ResolvedImage {
    ResolvedImage {
        reference: "registry.example.com/api:1".to_owned(),
        layers: Vec::new(),
        entrypoint: vec!["/bin/sh".to_owned(), "-c".to_owned(), command.to_owned()],
        env: vec!["PATH=/bin".to_owned()],
    }
}

/// An address in `/proc/net/route`'s spelling.
///
/// The kernel writes it there as a 32-bit word in host order, so backwards on
/// little-endian. The conversion here instead of a fixed value in the test: a
/// fixed value would be wrong on a big-endian machine without anybody seeing
/// the reason.
fn hex_route(address: Ipv4Addr) -> String {
    format!("{:08X}", u32::from_le_bytes(address.octets()))
}

fn copy_with_libraries(binary: &str, rootfs: &Path) {
    let name = Path::new(binary).file_name().expect("a file name");
    std::fs::copy(binary, rootfs.join("bin").join(name)).expect("the program is copyable");

    let ldd = std::process::Command::new("ldd")
        .arg(binary)
        .output()
        .expect("ldd");
    for line in String::from_utf8_lossy(&ldd.stdout).lines() {
        for token in line.split_whitespace() {
            if token.starts_with('/') && token.contains(".so") {
                let source = Path::new(token);
                let Some(parent) = source.parent() else {
                    continue;
                };
                let target_dir = rootfs.join(parent.strip_prefix("/").unwrap_or(parent));
                let _ = std::fs::create_dir_all(&target_dir);
                let Some(name) = source.file_name() else {
                    continue;
                };
                let _ = std::fs::copy(source, target_dir.join(name));
            }
        }
    }
}

/// An attachment as the agent has it -- only without its bookkeeping.
///
/// The agent is a binary; its `network` module is not reachable from outside.
/// What stands here are the **same two calls** it makes; its assignment
/// identifier -> address is checked separately (`tg_agent::network::tests`).
struct TestWiring {
    subnet: NodeSubnet,
    mtu: u16,
    address: Ipv4Addr,
    /// Which identifiers currently hold a network -- the actual side the
    /// agent takes from its address inventory.
    leased: std::sync::Mutex<Vec<String>>,
    /// What the readiness probe is to answer, and **what was asked**
    /// (ADR-0080).
    ///
    /// The recorded questions are half the assurance: without them a
    /// reconciler that does **not** probe at all would not be distinguishable
    /// from one with nothing but healthy probes.
    probe: std::sync::Mutex<(bool, Vec<(String, u16)>)>,
    /// In which namespaces the **baseline** was reconciled (ADR-0093).
    ///
    /// A workload without a sidecar gets it from its own pass -- before, it
    /// was laid at the `attach` and never asked about again, and whoever
    /// deleted it talked unfiltered until the next start.
    baselined: std::sync::Mutex<Vec<String>>,
}

/// A test run's sockets (ADR-0081).
///
/// It **binds** like `tg_agent::sockets::Listeners`, without a service on it:
/// what is checked here is the **lifecycle** (arises before the bundle, dies
/// with the instance), not the attestation -- that lies in `tg-identity`.
struct TestSockets {
    dir: std::path::PathBuf,
    held: std::sync::Mutex<Vec<(String, std::os::unix::net::UnixListener)>>,
}

impl TestSockets {
    fn new(dir: &Path) -> Self {
        std::fs::create_dir_all(dir.join("sockets")).expect("the directory");
        Self {
            dir: dir.to_path_buf(),
            held: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn path_of(&self, container: &str) -> std::path::PathBuf {
        self.dir.join("sockets").join(format!("{container}.sock"))
    }
}

impl tg_runtime::network::Sockets for TestSockets {
    fn ensure(&self, container: &str) -> Result<std::path::PathBuf, String> {
        let path = self.path_of(container);
        let mut held = self.held.lock().expect("the sockets");
        if !held.iter().any(|(name, _)| name == container) {
            let listener =
                std::os::unix::net::UnixListener::bind(&path).map_err(|err| err.to_string())?;
            held.push((container.to_owned(), listener));
        }
        Ok(path)
    }

    fn held(&self) -> Vec<String> {
        self.held
            .lock()
            .expect("the sockets")
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn release(&self, container: &str) {
        self.held
            .lock()
            .expect("the sockets")
            .retain(|(name, _)| name != container);
        let _ = std::fs::remove_file(self.path_of(container));
    }
}

impl Wiring for TestWiring {
    fn attach(&self, workload: &str, instance: u32) -> Result<Attachment, String> {
        let netns = tg_runtime::bundle::container_id(workload, instance);
        let path = tg_net::link::ensure_instance(&netns, self.address, &self.subnet, self.mtu)
            .map_err(|err| err.to_string())?;
        let mut leased = self.leased.lock().expect("the inventory");
        if !leased.contains(&netns) {
            leased.push(netns.clone());
        }
        Ok(Attachment {
            netns: path,
            resolv_conf: None,
        })
    }

    fn leased(&self) -> Vec<String> {
        self.leased.lock().expect("the inventory").clone()
    }

    fn release(&self, container: &str) {
        let _ = tg_net::link::release_instance(container, Some(self.address));
        self.leased
            .lock()
            .expect("the inventory")
            .retain(|held| held != container);
    }

    fn ensure_baseline(&self, netns: &str) {
        // What is written down is **that** it was called: a seam that
        // silently does nothing is not distinguishable from a missing one.
        // `kernel_path.rs` checks the rule set itself.
        self.baselined
            .lock()
            .expect("the record")
            .push(netns.to_owned());
    }

    fn enforce(&self, _netns: &str, _workload: &str) {
        // This test knows no sidecar; `enforce` is called only for one
        // (ADR-0060) and therefore never arrives here.
    }

    fn probe(&self, container: &str, probe: Probe<'_>) -> Result<(), String> {
        let mut guard = self.probe.lock().expect("the probe");
        guard.1.push((container.to_owned(), probe.port));
        if guard.0 {
            // **The real probe**, the same function the agent calls
            // (ADR-0080). A provided answer here would only prove that the
            // reconciler can process an answer.
            match probe.path {
                Some(path) => tg_net::probe::get_in(container, probe.port, path),
                None => tg_net::probe::connect_in(container, probe.port),
            }
        } else {
            Err("refused: provided".to_owned())
        }
    }
}

/// **What nobody wants any more ends -- together with its network**
/// (ADR-0058).
///
/// The container runs, the desired state is empty, and the node has applied a
/// slice: `EmptyMeans::NothingWanted`. Afterwards the container is gone, its
/// namespace is gone and its veth pair is gone.
///
/// The counter-check stands **in the same test**, and it is the actual
/// security statement: with `NothingHeard` -- a node that has never seen a
/// slice -- the same container stays untouched (ADR-0019). Without it the test
/// would only show that something ends.
///
/// The workload listens to `SIGTERM` here, and the time measurement at the end
/// is therefore no ornament: it distinguishes "the signal was accepted" from
/// "the deadline ran out and `SIGKILL` set it right". Without it both ways
/// would look the same.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and an OCI runtime; cargo xtask net"]
async fn a_container_that_nobody_wants_anymore_is_reaped_with_its_network() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime, wiring, id, address) =
        running_container(dir.path(), "tg-reap-a", COOPERATIVE).await;
    // **And its socket** (ADR-0081, determination 4). It arises by hand
    // here, because `running_container` builds the bundle immediately; in
    // operation the start path lays it out.
    let sockets = TestSockets::new(dir.path());
    tg_runtime::network::Sockets::ensure(&sockets, &id).expect("the socket");

    // **The counter-check first.** A node that has never applied a slice
    // clears away **nothing** on an empty desired state: "nothing wanted" and
    // "nothing heard yet" look the same, and the safe reading is fail-static
    // (ADR-0019).
    let unheard = Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        // ADR-0064: the local clock for the active-role lease.
        now: &|| 0,
        fence_margin: 0,
        wake: None,
        keep_snapshots: 3,
        quorum: tg_model::Quorum::Available,
        network: Some(&wiring),
        mesh: None,
        workload_api: Some(&sockets),
        secrets: None,
        credentials: None,
        empty: &|| EmptyMeans::NothingHeard,
    };
    let report = tg_runtime::reconcile::once(&paths, &runtime, &unheard)
        .await
        .expect("the pass");
    assert!(
        report.reaped.is_empty(),
        "a lost data directory must cost no containers: {:?}",
        report.reaped
    );
    assert!(
        runtime.status(&id).await.expect("the state").is_running(),
        "the container was ended although the desired state was not occupied"
    );

    // And now the same pass with an occupied desired state.
    let wanted = Context {
        devices: None,
        volume_keys: None,
        // ADR-0064: the local clock for the active-role lease.
        now: &|| 0,
        fence_margin: 0,
        wake: None,
        empty: &|| EmptyMeans::NothingWanted,
        ..unheard
    };
    let started = std::time::Instant::now();
    let report = tg_runtime::reconcile::once(&paths, &runtime, &wanted)
        .await
        .expect("the pass");
    let took = started.elapsed();

    assert_eq!(report.reaped, vec![id.clone()]);
    assert_eq!(
        runtime.status(&id).await.expect("the state"),
        ContainerStatus::Absent,
        "the container is not gone"
    );

    // The deadline is ten seconds. Whoever stays well below it went on the
    // signal and did not die at the backstop.
    assert!(
        took < Duration::from_secs(8),
        "the container took {took:?} -- that is the deadline, not the signal"
    );

    // **And its bundle goes along** (ADR-0119). The fourth thing that hangs
    // on a container, and the only one that stayed lying until then: the mount
    // held the layers fast (ADR-0003), and the `upper` **is** the ephemeral
    // volume (ADR-0027) that per the plan dies with the container. Measured,
    // it did not die -- a name that came back later inherited its
    // predecessor's writable layer.
    //
    // What is checked is the **directory**, not the mount: a `umount` that
    // does not succeed leaves it standing, and then the directory still stands
    // there too (determination 2 -- first unmount, then remove).
    assert!(
        !paths.bundles_dir().join("tg-reap-a").exists(),
        "the bundle still lies there: {}",
        paths.bundles_dir().join("tg-reap-a").display()
    );

    // **And the socket goes along** (ADR-0081, determination 4). A socket
    // nobody takes back is a way to an identity that no longer exists -- the
    // minter refuses it, but the file would stand there forever.
    assert!(
        tg_runtime::network::Sockets::held(&sockets).is_empty(),
        "the socket was not released: {:?}",
        tg_runtime::network::Sockets::held(&sockets)
    );
    assert!(
        !sockets.path_of(&id).exists(),
        "the socket file still stands"
    );

    // The network goes along (ADR-0058, determination 5).
    assert!(
        !std::path::Path::new("/run/netns").join(&id).exists(),
        "the network namespace still stands"
    );
    assert!(
        !std::path::Path::new("/sys/class/net")
            .join(host_link(address).as_str())
            .exists(),
        "the veth pair still stands"
    );

    drop(fixture);
}

/// **A container that ignores `SIGTERM` goes nevertheless** -- and that is
/// the normal case, not the special case.
///
/// Measured at exactly this setup: `kill SIGTERM` reports `Ok`, and after the
/// full deadline the container **carries on**. The reason is no broken runtime
/// but the rule for PID 1 in its own PID namespace -- without an installed
/// handler the kernel does not apply the default handling. A slim image with
/// `exec sleep` as its entry point is thereby **always** this case.
///
/// Without the backstop such a container would stand forever, and the clearing
/// away from ADR-0058 would be without effect for the majority of images.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and an OCI runtime; cargo xtask net"]
async fn a_container_that_ignores_sigterm_is_removed_anyway() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, paths, runtime, wiring, id, _address) =
        running_container(dir.path(), "tg-reap-b", STUBBORN).await;

    let context = Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        // ADR-0064: the local clock for the active-role lease.
        now: &|| 0,
        fence_margin: 0,
        wake: None,
        keep_snapshots: 3,
        quorum: tg_model::Quorum::Available,
        network: Some(&wiring),
        mesh: None,
        workload_api: None,
        secrets: None,
        credentials: None,
        empty: &|| EmptyMeans::NothingWanted,
    };
    let report = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("the pass");

    assert_eq!(report.reaped, vec![id.clone()]);
    assert_eq!(
        runtime.status(&id).await.expect("the state"),
        ContainerStatus::Absent,
        "a container that ignores SIGTERM still stands"
    );

    drop(fixture);
}

/// Sets up a running container together with its network.
///
/// The setup is the same as in the test above -- namespace, veth, address,
/// bundle -- only the entry point changes. Two copies would be two
/// opportunities to let them diverge.
async fn running_container(
    dir: &Path,
    workload_name: &'static str,
    command: &str,
) -> (
    Fixture,
    tg_runtime::NodePaths,
    OciRuntime,
    TestWiring,
    String,
    Ipv4Addr,
) {
    running_container_from(dir, workload_name, command, DEFINITION).await
}

/// Like [`running_container`], with a definition of its own.
///
/// Separate so that the two clearing-away tests stay unchanged: they say
/// nothing about readiness, and an additional parameter at their call site
/// would be noise.
async fn running_container_from(
    dir: &Path,
    workload_name: &'static str,
    command: &str,
    definition: &str,
) -> (
    Fixture,
    tg_runtime::NodePaths,
    OciRuntime,
    TestWiring,
    String,
    Ipv4Addr,
) {
    let paths = tg_runtime::NodePaths::new(dir);
    let runtime = OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root())
        .expect("no OCI runtime in the PATH");

    let mtu = Mtu::for_overlay(1500).expect("1500 carries");
    let subnet = subnet();
    let mut leases = Leases::new(subnet.clone());
    let address = leases.lease(workload_name, 0).expect("room enough");

    // The definition carries the name, for the container's identifier arises
    // from it -- and that is at the same time the namespace's name.
    let xml = definition.replace("\"api\"", &format!("\"{workload_name}\""));
    let set = tg_defs::from_str(&xml).expect("the definition parses");
    let workload = &set.workloads()[0];
    let id = tg_runtime::bundle::container_id(workload_name, 0);

    let mut fixture = Fixture {
        names: vec![id.clone()],
        links: vec![host_link(address)],
        rootfs: None,
    };
    let _ = tg_syscall::netns::delete(&id);
    let _ = tg_net::link::detach(&host_link(address));

    tg_net::link::ensure_bridge(&subnet, mtu.get()).expect("the bridge");

    let wiring = TestWiring {
        subnet: subnet.clone(),
        mtu: mtu.get(),
        address,
        leased: std::sync::Mutex::new(Vec::new()),
        probe: std::sync::Mutex::new((true, Vec::new())),
        baselined: std::sync::Mutex::new(Vec::new()),
    };
    let attachment = wiring.attach(workload_name, 0).expect("attach");

    let layer = dir.join("layer");
    build_layer(&layer);
    let built = tg_runtime::bundle::build(
        &paths.bundles_dir(),
        workload,
        &id,
        &[layer],
        &image(command),
        &[],
        // **Only the network is not the default here.** `Extras` derives
        // `Default`, and the default situation is the hardened one -- written
        // out, every new field would be a line in a witness it does not
        // concern (most recently `devices` from ADR-0143).
        Extras {
            network: Some(&attachment),
            ..Extras::default()
        },
    )
    .expect("the bundle");
    fixture.rootfs = Some(built.rootfs().to_path_buf());

    runtime.create(&id, built.dir()).await.expect("lay out");
    runtime.start(&id).await.expect("start");
    assert!(
        runtime.status(&id).await.expect("the state").is_running(),
        "the container is not running -- the test would otherwise prove nothing"
    );

    (fixture, paths, runtime, wiring, id, address)
}

/// **A network without a container is cleared away too** (ADR-0058).
///
/// Measured, the clearer read exclusively the **runtime** as the actual side.
/// The network, however, arises before the bundle -- the spec carries the
/// namespace's path (ADR-0012) -- and `bundle::build`, `create` and `start`
/// can fail afterwards. If the workload is withdrawn in this state, the
/// runtime knows no container, and the namespace, the veth pair and the
/// **persisted** address would stay lying forever.
///
/// The address weighs heaviest: it lies beside the desired-state cache
/// (phase 9a) and survives every restart. Enough failed starts, and a node's
/// /24 is full -- without an error appearing anywhere.
///
/// Exactly this state is produced here: a network that never became a
/// container.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; cargo xtask net"]
async fn a_network_that_never_became_a_container_is_reaped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime = OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root())
        .expect("no OCI runtime in the PATH");

    let mtu = Mtu::for_overlay(1500).expect("1500 carries");
    let subnet = subnet();
    let mut leases = Leases::new(subnet.clone());
    let address = leases.lease("orphan", 0).expect("room enough");
    let id = tg_runtime::bundle::container_id("orphan", 0);

    let fixture = Fixture {
        names: vec![id.clone()],
        links: vec![host_link(address)],
        rootfs: None,
    };
    let _ = tg_syscall::netns::delete(&id);
    let _ = tg_net::link::detach(&fixture.links[0]);

    tg_net::link::ensure_bridge(&subnet, mtu.get()).expect("the bridge");

    let wiring = TestWiring {
        subnet: subnet.clone(),
        mtu: mtu.get(),
        address,
        leased: std::sync::Mutex::new(Vec::new()),
        probe: std::sync::Mutex::new((true, Vec::new())),
        baselined: std::sync::Mutex::new(Vec::new()),
    };

    // The attachment succeeds -- and afterwards nothing happens any more.
    // Exactly the situation in which a bundle error would abort the pass.
    let attachment = wiring.attach("orphan", 0).expect("the attachment");
    assert!(
        std::path::Path::new(&attachment.netns).exists(),
        "the namespace was not laid out"
    );

    // No container: the runtime knows nothing. Without this assertion the test
    // would check the ordinary clearing-away path and not the new one.
    assert!(
        runtime.list().expect("the inventory").is_empty(),
        "this test presupposes that no container ever arose"
    );

    // **The counter-check first**, as with the neighbouring test: a node that
    // has never applied a slice clears away **nothing** -- not an orphaned
    // network either (ADR-0058, determination 3; ADR-0019). Without it the
    // test below would only show that something disappears.
    let unheard = Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        now: &|| 0,
        fence_margin: 0,
        wake: None,
        keep_snapshots: 3,
        quorum: tg_model::Quorum::Available,
        network: Some(&wiring),
        mesh: None,
        workload_api: None,
        secrets: None,
        credentials: None,
        empty: &|| EmptyMeans::NothingHeard,
    };
    tg_runtime::reconcile::once(&paths, &runtime, &unheard)
        .await
        .expect("the pass");
    assert!(
        std::path::Path::new(&attachment.netns).exists(),
        "a lost data directory must cost no network"
    );

    let wanted = Context {
        devices: None,
        volume_keys: None,
        empty: &|| EmptyMeans::NothingWanted,
        ..unheard
    };
    tg_runtime::reconcile::once(&paths, &runtime, &wanted)
        .await
        .expect("the pass");

    assert!(
        !std::path::Path::new(&attachment.netns).exists(),
        "'{id}'s namespace stayed lying although nobody wants it any more"
    );
    assert!(
        wiring.leased().is_empty(),
        "the address stayed handed out -- it lies beside the desired-state \
         cache and survives every restart"
    );
    drop(fixture);
}

// ============================================= readiness (ADR-0080)

/// The definition with a readiness probe.
const WITH_READINESS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1"/>
    <readiness port="8080"/>
  </workload>
</workloads>"#;

/// A workload that **listens**.
const LISTENING: &str = "exec /bin/ncat -l -k 8080";

/// **The readiness probe reaches a real container** (ADR-0080).
///
/// # What it asserts, and what is new about it
///
/// The rule -- who is asked and what follows -- is checked purely. What is
/// checkable **only** here is the path: `<readiness port>` in the definition
/// -> `probe_readiness` -> `tg_net::probe::connect_in` -> **a real namespace**
/// -> a real container. And with the **same** function the agent calls:
/// `TestWiring::probe` delegates to it instead of providing an answer.
///
/// # Both directions, and the second carries
///
/// A container that **listens** is ready; one that does **not** listen is not.
/// Without the first half a probe that always fails would be green too -- and
/// then every workload with a probe would fall out of the resolution forever.
///
/// The unready instance stays in `untouched` in the process
/// (determination 1): it runs, it merely does not serve.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN and an OCI runtime; runs with `cargo xtask net`"]
async fn a_readiness_probe_reaches_a_real_container() {
    // **Two directories**, and that is no tidiness: shared, the first
    // workload would stay in the second pass's cache and would be pulled anew
    // -- measured as a `pull` failure against `registry.example.com`. The test
    // would be green nevertheless and would carry a failure along that has
    // nothing to do with it.
    let dir = tempfile::tempdir().expect("tempdir");
    let other = tempfile::tempdir().expect("tempdir");

    // ---- listens ----
    let (fixture, paths, runtime, wiring, id, _address) =
        running_container_from(dir.path(), "tg-ready-yes", LISTENING, WITH_READINESS).await;
    want(dir.path(), "tg-ready-yes", WITH_READINESS);

    // The listener needs a moment until it binds -- that is exactly the
    // start-up case for whose sake the probe exists. What is waited for is the
    // **assertion**, not a number.
    let mut ready = false;
    for _ in 0..50 {
        let report = reconcile_once(&paths, &runtime, &wiring).await;
        // **Empty and asked** -- both. An empty `unready` alone also means
        // "not probed", and on exactly that the first version of this test was
        // green before the desired state stood.
        if report.unready.is_empty() && !wiring.probe.lock().expect("the probe").1.is_empty() {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(
        ready,
        "a container that listens on 8080 must count as ready -- what was \
         asked is: {:?}",
        wiring.probe.lock().expect("the probe").1
    );
    let _ = runtime.delete(&id, true).await;
    drop(fixture);

    // ---- does not listen ----
    let (fixture, paths, runtime, wiring, id, _address) =
        running_container_from(other.path(), "tg-ready-no", STUBBORN, WITH_READINESS).await;
    want(other.path(), "tg-ready-no", WITH_READINESS);

    let report = reconcile_once(&paths, &runtime, &wiring).await;

    assert_eq!(
        report.unready,
        vec![tg_runtime::reconcile::Instance::new("tg-ready-no", 0)],
        "a container without a listener must be unready -- otherwise the \
         resolver resolves a mute endpoint (ADR-0013)"
    );
    assert_eq!(
        report.untouched,
        vec![tg_runtime::reconcile::Instance::new("tg-ready-no", 0)],
        "unready is no state: the instance carries on (determination 1)"
    );

    // **And the baseline is reconciled** (ADR-0093, ADR-0094).
    //
    // It belongs to the **network** and not to the sidecar -- this workload
    // has none. Measured, it was laid at the `attach` and **never asked about
    // again** afterwards: whoever deleted it in a namespace talked unfiltered
    // until the next start, and that is the assurance for whose sake it
    // exists.
    assert!(
        wiring
            .baselined
            .lock()
            .expect("the record")
            .contains(&tg_runtime::bundle::container_id("tg-ready-no", 0)),
        "the baseline of a workload without a sidecar is not reconciled per \
         pass -- it was called for {:?}",
        wiring.baselined.lock().expect("the record")
    );

    let _ = runtime.delete(&id, true).await;
    drop(fixture);
}

/// One pass against the setup from [`running_container_from`].
async fn reconcile_once(
    paths: &tg_runtime::NodePaths,
    runtime: &OciRuntime,
    wiring: &TestWiring,
) -> tg_runtime::reconcile::Report {
    let context = tg_runtime::reconcile::Context {
        devices: None,
        volume_keys: None,
        no_seccomp: false,
        userns: None,
        wake: None,
        now: &|| 0,
        fence_margin: 0,
        keep_snapshots: 3,
        quorum: tg_model::Quorum::Available,
        network: Some(wiring),
        mesh: None,
        workload_api: None,
        secrets: None,
        credentials: None,
        empty: &|| tg_runtime::reconcile::EmptyMeans::NothingHeard,
    };

    tg_runtime::reconcile::once(paths, runtime, &context)
        .await
        .expect("the pass")
}

/// Files a workload as **wanted** in the local desired state.
///
/// `running_container_from` builds a container without wanting it -- the two
/// clearing-away tests need exactly that (ADR-0058). A witness for readiness
/// needs the opposite, otherwise the report is empty and **every** assertion
/// on `unready` would be green without saying anything.
fn want(dir: &Path, workload_name: &str, definition: &str) {
    let xml = definition.replace("\"api\"", &format!("\"{workload_name}\""));
    let set = tg_defs::from_str(&xml).expect("the definition parses");
    let desired = tg_runtime::state::DesiredState::open(dir).expect("the desired state");
    desired.put(&set.workloads()[0]).expect("file it");
    desired.assign(workload_name, &[0]).expect("assign");
}
