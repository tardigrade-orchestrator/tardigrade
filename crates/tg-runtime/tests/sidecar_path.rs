//! The sidecar runs -- **in its workload's namespace** (ADR-0059).
//!
//! Up to here `tg-proxy` was a binary without a starter: `mesh::expand` had
//! exactly one caller, and that one used the result for the identity, not for
//! a container. This test checks the four assurances ADR-0059 makes:
//!
//! 1. The sidecar **arises** from the node's slice without anybody having
//!    written it down.
//! 2. It gets **its workload's instance numbers** (co-location as a
//!    consequence, not as a rule).
//! 3. It shares that one's **network namespace** -- and thereby its address.
//! 4. It sees the **socket, the edges and the egress permissions** under the
//!    fixed paths from determination 5.
//!
//! # Why a placeholder instead of `tg-proxy`
//!
//! The sidecar process is checked elsewhere: the workload API against
//! `rust-spiffe` (7c), the mTLS path end to end (8b), the egress against
//! `curl` (10d). What is new here is the **wiring**, and a program that writes
//! down what it got checks that more precisely than one that works with it: a
//! `tg-proxy` that does not start does not say which of the four assurances is
//! broken.
//!
//! `#[ignore]`: demands `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` and an OCI runtime.
//! Run with `cargo xtask net`.

use std::path::Path;

use tg_net::ipam::{ClusterNet, Leases, Mtu, NodeSubnet, host_link};
use tg_runtime::content::{ContentStore, Digest256};
use tg_runtime::network::{Attachment, Mesh, Probe, Wiring};
use tg_runtime::reconcile::{Context, EmptyMeans};
use tg_runtime::resolved::ResolvedImage;

mod support;
use support::await_line;

const ZONE: &str = "10.42.0.0/16";
const WORKLOAD_IMAGE: &str = "registry.example.test/api:1";
const PROXY_IMAGE: &str = "registry.example.test/proxy:1";

/// A mesh member. Its sidecar stands **nowhere** -- it arises.
const DEFINITION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.test/api:1"/>
    <mesh port="8443"/>
  </workload>
</workloads>"#;

fn subnet() -> NodeSubnet {
    ClusterNet::new(ZONE.parse().expect("valid"), 24)
        .expect("valid")
        .subnet(1)
        .expect("valid")
}

/// Clears away namespaces, veth pairs and mounts.
struct Fixture {
    names: Vec<String>,
    links: Vec<tg_net::ipam::LinkName>,
    rootfs: Vec<std::path::PathBuf>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = tg_syscall::netns::delete(name);
        }
        for host in &self.links {
            let _ = tg_net::link::detach(host);
        }
        for rootfs in &self.rootfs {
            let _ = tg_syscall::mount::unmount_at(rootfs);
        }
    }
}

/// The attachment as the agent has it -- one address per **instance**, not
/// per container.
///
/// Exactly that is determination 3: `attach` is called for the sidecar with
/// its **workload's** name, so it gets the same namespace and the same
/// address. An inventory that gave the sidecar one of its own would stand out
/// here.
struct TestWiring {
    subnet: NodeSubnet,
    mtu: u16,
    leases: std::sync::Mutex<Leases>,
    /// In which namespaces the rule set would have been laid (ADR-0060).
    enforced: std::sync::Mutex<Vec<String>>,
}

impl Wiring for TestWiring {
    fn attach(&self, workload: &str, instance: u32) -> Result<Attachment, String> {
        let netns = tg_runtime::bundle::container_id(workload, instance);
        let address = self
            .leases
            .lock()
            .map_err(|err| err.to_string())?
            .lease(workload, instance)
            .map_err(|err| err.to_string())?;

        let path = tg_net::link::ensure_instance(&netns, address, &self.subnet, self.mtu)
            .map_err(|err| err.to_string())?;

        Ok(Attachment {
            netns: path,
            resolv_conf: None,
        })
    }

    fn leased(&self) -> Vec<String> {
        // From the real inventory, as in the agent -- resolved forwards
        // (ADR-0065).
        self.leases
            .lock()
            .expect("the inventory")
            .entries()
            .into_iter()
            .map(|lease| tg_runtime::bundle::container_id(&lease.workload, lease.instance))
            .collect()
    }

    fn release(&self, container: &str) {
        let _ = tg_net::link::release_instance(container, None);
    }

    fn ensure_baseline(&self, netns: &str) {
        // **A record of its own**, no passing on to `enforce`: the two are
        // mutually a deviation (measured), and a witness that pulled them
        // together could not say which of the two reconciled the namespace.
        self.enforced
            .lock()
            .expect("the record")
            .push(format!("{netns}/baseline"));
    }

    fn enforce(&self, netns: &str, workload: &str) {
        // The redirect does not belong to this test -- it checks the
        // derivation, not the redirection (that stands in
        // `tg-proxy/tests/mesh_netns.rs`). A reference to a file of this name
        // with `_redirect` instead of `_netns` once stood here -- that one
        // does not exist, and `every_referenced_rust_file_exists` catches that
        // now. What is written down nevertheless is **that** it was called: a
        // seam that silently does nothing is not distinguishable from a
        // missing one.
        // Both: the namespace **and** the principal. Since ADR-0094 the
        // redirection hangs on the workload's desired state, not only on the
        // namespace -- and whoever recorded only the namespace here would not
        // see a confusion of the two.
        self.enforced
            .lock()
            .expect("the record")
            .push(format!("{netns}/{workload}"));
    }

    fn probe(&self, _container: &str, _probe: Probe<'_>) -> Result<(), String> {
        // No definition of this test declares a readiness probe (ADR-0080),
        // so nothing is ever asked here. `Ok` and no `unreachable!`: a panic
        // in a fixture would take the test's statement away and replace it
        // with a crash.
        Ok(())
    }
}

/// **The sidecar arises, runs and sits in its workload's network.**
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and an OCI runtime; cargo xtask net"]
#[expect(
    clippy::too_many_lines,
    reason = "one setup, four assurances -- separating them would mean \
              repeating the setup four times or hiding it behind a helper that \
              conceals more than it saves"
)]
async fn a_sidecar_is_derived_and_runs_beside_its_workload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime = tg_runtime::oci::OciRuntime::discover(
        tg_runtime::oci::DEFAULT_RUNTIMES,
        paths.runtime_root(),
    )
    .expect("no OCI runtime in the PATH");

    let mtu = Mtu::for_overlay(1500).expect("1500 carries");
    let subnet = subnet();

    // The local desired state: **one** workload, with `<mesh>`.
    let cache = tg_runtime::state::DesiredState::open(paths.data_dir()).expect("the cache");
    let set = tg_defs::from_str(DEFINITION).expect("the definition parses");
    cache
        .put(&set.workloads()[0])
        .expect("filing the definition");
    cache.assign("api", &[0]).expect("the assignment");

    // Two images in the content store -- without a registry (ADR-0019: if it
    // lies locally, it is taken locally).
    let store = ContentStore::open(paths.content_dir()).expect("the store");
    seed(
        &store,
        WORKLOAD_IMAGE,
        &["/bin/sh", "-c", "exec /bin/sleep 30"],
        None,
    );
    // **The placeholder lies where ADR-0059 expects the program.** The
    // derived command line carries this path as argv[0] and thereby overrides
    // the image's entrypoint (the schema, ADR-0003) -- so what the image
    // brings along is immaterial, and `exit 17` says that plainly: a container
    // that used it would be dead immediately.
    seed(
        &store,
        PROXY_IMAGE,
        &["/bin/sh", "-c", "exit 17"],
        Some(PLACEHOLDER),
    );

    // What the agent contributes: the proxy image and the four mounts.
    let node_files = dir.path().join("network");
    std::fs::create_dir_all(&node_files).expect("the directory");
    std::fs::write(node_files.join("may-talk"), "api -> ledger\n").expect("the edges");
    std::fs::write(node_files.join("egress"), "api s3.test 443\n").expect("egress");
    // The active role (ADR-0066). A sidecar that does not see it refuses
    // fail-closed -- then a single writer would never run, and nobody would
    // see why.
    std::fs::write(node_files.join("active-role"), "api 3 99999999999999\n").expect("the role");
    // A placeholder for the socket: the agent lays a real one there, here a
    // file suffices -- what is checked is that it **arrives**.
    std::fs::write(dir.path().join("workload-api.sock"), "").expect("the socket placeholder");
    // The surcharge per mesh instance (ADR-0067). The CPU stands expressly
    // in it: per ADR-0086 **only** the memory is enforced.
    std::fs::write(
        node_files.join("sidecar-overhead"),
        "cpu-millicores=50\nmemory-bytes=67108864\n",
    )
    .expect("the surcharge");

    let mesh = Mesh {
        spec: tg_model::SidecarSpec::new(PROXY_IMAGE, "cluster.local").expect("the image"),
        mounts: vec![
            mount(
                dir.path().join("workload-api.sock"),
                tg_model::mesh::SOCKET_IN_CONTAINER,
                false,
            ),
            mount(
                node_files.join("may-talk"),
                tg_model::mesh::EDGES_IN_CONTAINER,
                true,
            ),
            mount(
                node_files.join("egress"),
                tg_model::mesh::EGRESS_IN_CONTAINER,
                true,
            ),
            mount(
                node_files.join("active-role"),
                tg_model::mesh::ROLE_IN_CONTAINER,
                true,
            ),
        ],
        // **A path, no mount** (ADR-0086): the kernel sets the limit over
        // the cgroup, the sidecar never sees it. The agent writes the file
        // from the slice, the reconciler reads it per pass.
        overhead: node_files.join("sidecar-overhead"),
    };

    let workload_id = tg_runtime::bundle::container_id("api", 0);
    let sidecar_id = tg_runtime::bundle::container_id("api-proxy", 0);

    let mut fixture = Fixture {
        // **Both names**, the sidecar's too -- it may get no namespace of
        // its own here, but exactly that is what the test checks, and a failed
        // run would otherwise leave it behind. That cost a search for an
        // error: a remnant from a counter-check made the next run red, and the
        // assertion was right.
        names: vec![workload_id.clone(), sidecar_id.clone()],
        links: Vec::new(),
        rootfs: vec![
            paths.bundles_dir().join("api").join("rootfs"),
            paths.bundles_dir().join("api-proxy").join("rootfs"),
        ],
    };
    for name in &fixture.names {
        let _ = tg_syscall::netns::delete(name);
    }
    // The veth pairs are named after the address (phase 9a), and this test
    // can hand out only the subnet's first two. A remnant with the same name
    // would let `attach` return early -- the container would then lie in a
    // foreign namespace, and the test would not see it.
    for host in stale_links(&subnet) {
        let _ = tg_net::link::detach(&host);
    }

    tg_net::link::ensure_bridge(&subnet, mtu.get()).expect("the bridge");
    let wiring = TestWiring {
        subnet: subnet.clone(),
        mtu: mtu.get(),
        leases: std::sync::Mutex::new(Leases::new(subnet.clone())),
        enforced: std::sync::Mutex::new(Vec::new()),
    };

    let handed = Handed {
        root: dir.path().join("provided-secrets"),
        asked: std::sync::Mutex::new(Vec::new()),
    };
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
        mesh: Some(&mesh),
        workload_api: None,
        // ADR-0098: the seam delivers one for **every** call -- the question
        // is whether the reconciler calls it for the sidecar at all.
        secrets: Some(&handed),
        credentials: None,
        empty: &|| EmptyMeans::NothingHeard,
    };

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("the pass");

    assert!(
        report.failed.is_empty(),
        "the pass failed: {:?}",
        report.failed
    );

    // **Assurances 1 and 2:** the sidecar stands in the report, with its
    // workload's number -- although nobody wrote it down.
    let started: Vec<String> = report.reconciled.iter().map(ToString::to_string).collect();
    assert!(
        started.contains(&"api".to_owned()) && started.contains(&"api-proxy".to_owned()),
        "the workload and the sidecar were expected, what was started is {started:?}"
    );
    assert!(
        runtime
            .status(&sidecar_id)
            .await
            .expect("the state")
            .is_running(),
        "the sidecar is not running"
    );

    // **And the report carries the same derivation** -- from it the agent
    // follows up on what this node may mint (ADR-0019, ADR-0036). Were there
    // two derivations, a running container could stand there without an SVID;
    // that it is the same one is said by exactly this assertion.
    // Since ADR-0065 it is a **map** identifier -> workload, and the assertion
    // becomes sharper for it: it nails the assignment down and not merely the
    // membership.
    for name in ["api", "api-proxy"] {
        assert_eq!(
            report
                .own
                .get(&tg_runtime::bundle::container_id(name, 0))
                .map(String::as_str),
            Some(name),
            "the report does not assign '{name}': {:?}",
            report.own
        );
    }
    assert_eq!(
        report.delegations.get("api-proxy").map(String::as_str),
        Some("api"),
        "the delegation is missing from the report: {:?}",
        report.delegations
    );

    // **Assurance 4:** the three mounts have arrived -- the sidecar read
    // them itself.
    let proof = await_line(
        &paths
            .bundles_dir()
            .join("api-proxy")
            .join("rootfs")
            .join("tmp")
            .join("proof"),
        // **The marker is measured, not guessed.** The placeholder writes
        // `ARGV $*` as the **first** line (see `PROBE`), and having waited for
        // exactly that is the point: the witness file arises line by line, and
        // the assertions below read the later ones.
        "ARGV ",
    )
    .unwrap_or_else(|last| {
        let log =
            std::fs::read_to_string(paths.bundles_dir().join("api-proxy").join("container.log"))
                .unwrap_or_default();
        panic!("the sidecar did not write the marker; so far:\n{last}\nlog:\n{log}");
    });

    assert!(
        proof.contains("api -> ledger"),
        "the edges are missing in the sidecar:\n{proof}"
    );
    assert!(
        proof.contains("api s3.test 443"),
        "the egress permissions are missing in the sidecar:\n{proof}"
    );
    assert!(
        proof.contains("api 3 99999999999999"),
        "the active role is missing in the sidecar (ADR-0066):\n{proof}"
    );
    assert!(
        proof.contains("SOCKET-THERE"),
        "the workload API socket is missing in the sidecar:\n{proof}"
    );

    // And the derived command line is the one `tg-proxy` expects.
    assert!(
        proof.contains("--workload api --upstream-port 8443"),
        "the sidecar's command line is not right:\n{proof}"
    );
    assert!(
        proof.contains(tg_model::mesh::SOCKET_IN_CONTAINER),
        "the socket path does not stand in the command line:\n{proof}"
    );

    // **Assurance 3, the most important:** the same namespace, so the same
    // address. The inventory handed out exactly **one** -- had the sidecar got
    // one of its own, two would stand here.
    let entries = wiring.leases.lock().expect("the inventory").entries();
    assert_eq!(
        entries.len(),
        1,
        "one instance, one address -- what was handed out is {entries:?}"
    );
    let address = entries[0].address;
    assert_eq!(entries[0].workload, "api");
    assert!(
        proof.contains(&address.to_string()),
        "the sidecar does not see {address} -- it sits in a different namespace:\n{proof}"
    );
    assert!(
        !std::path::Path::new("/run/netns")
            .join(&sidecar_id)
            .exists(),
        "the sidecar got a namespace of **its own**"
    );

    // **And the rule set was laid** -- in the *workload's* namespace, not in
    // one of its own (ADR-0060, determination 3). A seam that silently does
    // nothing is not distinguishable from a missing one.
    //
    // The **principal** stands beside it (ADR-0094): the redirection for QUIC
    // applies to the ports of *its* allowlist, and whoever passed `api-proxy`
    // here would get an empty list and thereby no way out.
    assert_eq!(
        *wiring.enforced.lock().expect("the record"),
        vec![format!("{workload_id}/api")],
        "the redirect was not laid (or was laid for the wrong namespace or \
         principal)"
    );

    // **And it is reconciled, not laid once** (ADR-0094, D3).
    //
    // Measured, `enforce` ran only where a container was **started** -- a QUIC
    // permission that comes along for a **running** workload thereby got its
    // redirection only at the next start. The outage was fail-closed and
    // visible (the datagrams die at the discarding rule from ADR-0074, with
    // its counter) -- and exactly the riddle determination 4 wanted to avoid
    // one level deeper: the permission stands there, the listener is open, and
    // nothing goes out.
    //
    // That it costs nothing is down to `enforce` itself: it **asks** first and
    // sets only on a deviation (`is_applied`). Here the call counts.
    std::fs::write(node_files.join("egress"), "api s3.test 443 quic\n").expect("egress");

    let again = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("the second pass");
    assert!(
        again.failed.is_empty(),
        "the second pass failed: {:?}",
        again.failed
    );

    assert_eq!(
        *wiring.enforced.lock().expect("the record"),
        vec![format!("{workload_id}/api"), format!("{workload_id}/api"),],
        "the rule set is laid only at the start instead of reconciled per \
         pass -- a new permission never reaches a running workload"
    );

    // **And the sidecar wins** (ADR-0093, ADR-0094): no `/baseline` in the
    // record. The baseline and the full rule set are mutually a deviation --
    // measured -- so a workload and its sidecar overwrote each other at every
    // pass, and the redirection flickered. The assertion above alone would not
    // see that: it checks the order, not the absence.
    assert!(
        !wiring
            .enforced
            .lock()
            .expect("the record")
            .iter()
            .any(|entry| entry.ends_with("/baseline")),
        "a workload with a sidecar must not reconcile its baseline itself: {:?}",
        wiring.enforced.lock().expect("the record")
    );
    // **Assurance 4: a decree reaches the sidecar too** (ADR-0085).
    //
    // Measured, `DesiredState::generation("api-proxy", 0)` returned **zero**,
    // and forever at that: the generations stem from `slice.instances`
    // (ADR-0040), and a derived sidecar stands in no log (ADR-0059).
    // `tgctl cluster restart api` thereby restarted `api` and left `api-proxy`
    // standing -- with a change of class that would mean: the workload runs as
    // a single writer, and its sidecar does not rein it in, because it lacks
    // `--single-writer` (ADR-0066).
    //
    // The second pass is at the same time the **counter-check to the first**:
    // without a decree both would be `untouched`, and that they are not after
    // the decree is the whole statement.
    cache
        .set_generations("api", &[(0, 1)])
        .expect("decreeing the generation");

    let second = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("the second pass");

    let restarted: Vec<String> = second.reconciled.iter().map(ToString::to_string).collect();
    assert!(
        restarted.contains(&"api".to_owned()) && restarted.contains(&"api-proxy".to_owned()),
        "the decree must reach the workload **and** the sidecar, what was restarted          is {restarted:?}"
    );

    // **Assurance 5: the sidecar has a memory limit and no quota**
    // (ADR-0086). What is read is the **spec** the reconciler wrote -- the
    // seam from the slice to the `config.json` is thereby substantiated in one
    // piece, and not merely `sidecar_limit` for itself.
    let spec: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(paths.bundles_dir().join("api-proxy").join("config.json"))
            .expect("the sidecar's spec"),
    )
    .expect("parses");
    let limits = &spec["linux"]["resources"];
    assert_eq!(
        limits["memory"]["limit"].as_u64(),
        Some(67_108_864),
        "without a memory limit an OOM kill takes all the node's workloads with it: {limits}"
    );
    assert!(
        limits["cpu"].is_null(),
        "a CFS quota on a proxy is the throttling from ADR-0022: {limits}"
    );

    // **Assurance 6: the sidecar gets no secrets** (ADR-0098,
    // determination 4). It enters its workload's namespace, but its rootfs is
    // its own -- and least privilege gives the decision.
    //
    // The provided seam delivers a directory for **every** call, so this list
    // says who the reconciler asked about at all. And the first half carries
    // the second: were it empty, the sidecar's absence would prove nothing.
    let asked = handed.asked.lock().expect("the lock").clone();
    assert!(
        asked.contains(&workload_id),
        "the workload must have been asked about -- otherwise the sidecar's \
         absence would prove nothing: {asked:?}"
    );
    assert!(
        !asked.contains(&sidecar_id),
        "the sidecar must not be asked about: {asked:?}"
    );
    // **Per pass**, not once: this test drives `once` several times (a
    // decree, a restart), and the seam was asked every time. Exactly that is
    // the rotation from determination 5 -- an `ensure` that ran only the first
    // time would never reach a running container.
    assert!(
        asked.len() > 1,
        "the content must follow the slice per pass: {asked:?}"
    );
    let sidecar_spec: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(paths.bundles_dir().join("api-proxy").join("config.json"))
            .expect("the sidecar's spec"),
    )
    .expect("parses");
    assert!(
        !sidecar_spec["mounts"]
            .as_array()
            .expect("the mounts")
            .iter()
            .any(|mount| mount["destination"] == tg_model::mesh::SECRETS_IN_CONTAINER),
        "the sidecar must get no secrets directory mounted: {}",
        sidecar_spec["mounts"]
    );

    for id in [&workload_id, &sidecar_id] {
        let _ = runtime.delete(id, true).await;
    }
    // What was really handed out is known only now.
    fixture.links = entries
        .iter()
        .map(|lease| host_link(lease.address))
        .collect();
    drop(fixture);
}

/// A provided secrets seam (ADR-0098).
///
/// It delivers a directory for **every** call -- the question is precisely
/// whether it is called for the sidecar at all (determination 4).
#[derive(Debug)]
struct Handed {
    root: std::path::PathBuf,
    asked: std::sync::Mutex<Vec<String>>,
}

impl tg_runtime::network::Secrets for Handed {
    fn ensure(
        &self,
        container: &str,
        _workload: &str,
    ) -> Result<Option<std::path::PathBuf>, String> {
        if let Ok(mut guard) = self.asked.lock() {
            guard.push(container.to_owned());
        }

        let dir = self.root.join(container);
        std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
        std::fs::write(dir.join("db-password"), b"hunter2").map_err(|err| err.to_string())?;

        Ok(Some(dir))
    }

    fn held(&self) -> Vec<String> {
        Vec::new()
    }

    fn release(&self, _container: &str) {}
}

/// The placeholder at the place of the sidecar program.
///
/// It writes down what it got: its command line, the two files, whether the
/// socket is there, and its namespace's local addresses. Afterwards it stays
/// standing -- a container that ends immediately could no longer be asked
/// about its state.
const PLACEHOLDER: &str = "#!/bin/sh\n\
     { echo \"ARGV $*\"; \
       cat /etc/tardigrade/may-talk /etc/tardigrade/egress /etc/tardigrade/active-role; \
       [ -e /run/tardigrade/workload-api.sock ] && echo SOCKET-THERE; \
       cat /proc/net/fib_trie; } > /tmp/proof\n\
     exec /bin/sleep 30\n";

fn mount(
    source: std::path::PathBuf,
    destination: &str,
    readonly: bool,
) -> tg_runtime::bundle::VolumeMount {
    tg_runtime::bundle::VolumeMount {
        source,
        destination: destination.to_owned(),
        readonly,
    }
}

/// Lays an image into the content store, without a registry.
fn seed(store: &ContentStore, reference: &str, command: &[&str], program: Option<&str>) {
    let mut tar = tar::Builder::new(Vec::new());

    // One layer per image, and both contain the same: a shell. The
    // difference between the workload and the sidecar is the **command line**
    // here, not the content -- what is checked is the wiring.
    for dir in [
        "bin",
        "proc",
        "dev",
        "sys",
        "etc",
        "run",
        "usr",
        "usr/local",
        "usr/local/bin",
        "tmp",
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        // `/tmp` stands at 1777 as in every real image -- since ADR-0060 the
        // sidecar runs under an identifier of its own and may otherwise write
        // nowhere. Exactly on that this test failed when switching over, and
        // that is the assurance the ADR makes: an image that does not tolerate
        // the identifier stands out.
        header.set_mode(if dir == "tmp" { 0o1777 } else { 0o755 });
        header.set_size(0);
        tar.append_data(&mut header, format!("{dir}/"), std::io::empty())
            .expect("the directory");
    }
    for binary in ["/bin/sh", "/bin/sleep", "/bin/cat", "/bin/echo"] {
        append(&mut tar, binary, &format!("bin/{}", basename(binary)));
        for library in libraries(binary) {
            let inside = library.trim_start_matches('/').to_owned();
            append(&mut tar, &library, &inside);
        }
    }

    if let Some(script) = program {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_size(script.len() as u64);
        header.set_cksum();
        tar.append_data(
            &mut header,
            tg_model::mesh::PROGRAM_IN_CONTAINER.trim_start_matches('/'),
            script.as_bytes(),
        )
        .expect("the program");
    }

    let blob = tar.into_inner().expect("the archive");
    let digest = Digest256::of(&blob);
    store.verify_blob(&digest, &blob).expect("the blob");
    store
        .unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", &blob)
        .expect("unpack");

    ResolvedImage {
        reference: reference.to_owned(),
        layers: vec![digest],
        entrypoint: command.iter().map(|arg| (*arg).to_owned()).collect(),
        env: vec!["PATH=/bin".to_owned()],
    }
    .save(store)
    .expect("the record");
}

fn basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
}

fn libraries(binary: &str) -> Vec<String> {
    let ldd = std::process::Command::new("ldd")
        .arg(binary)
        .output()
        .expect("ldd");

    String::from_utf8_lossy(&ldd.stdout)
        .lines()
        .flat_map(|line| {
            line.split_whitespace()
                .filter(|token| token.starts_with('/') && token.contains(".so"))
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn append(tar: &mut tar::Builder<Vec<u8>>, source: &str, inside: &str) {
    let Ok(mut file) = std::fs::File::open(source) else {
        return;
    };
    let mut header = tar::Header::new_gnu();
    let metadata = file.metadata().expect("the metadata");
    header.set_metadata(&metadata);
    header.set_mode(0o755);
    let _ = tar.append_data(&mut header, inside, &mut file);
}

/// The veth names this test can hand out.
///
/// Two, because it can hand out two addresses: one in the normal case, two if
/// the co-location breaks. More is not needed, and guessing more would mean
/// clearing away foreign interfaces.
fn stale_links(subnet: &NodeSubnet) -> Vec<tg_net::ipam::LinkName> {
    let mut leases = Leases::new(subnet.clone());
    (0..2)
        .filter_map(|instance| leases.lease("clear-away", instance).ok())
        .map(host_link)
        .collect()
}
