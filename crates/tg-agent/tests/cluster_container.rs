//! **The way the operations manual describes** -- in one piece.
//!
//! This tree has one setup for each of the two halves, and they exclude each
//! other:
//!
//! | Setup | What it has | What it lacks |
//! |---|---|---|
//! | `session`, `node_network` | a real `tgd`, a real `tg-agent` | the runtime is a **stub** (`#!/bin/sh\nexit 0`) |
//! | `network_path`, `sidecar_path` | real containers | no `tgd`, no slice -- the cache is sown by hand |
//!
//! Measured, **every** test with a real `tgd` uses a stub, and **every** test
//! with a real container calls `reconcile::once` directly. The seam in between
//! -- the slice writes the cache, and the reconciler starts a container from it
//! -- thereby had no witness.
//!
//! That is exactly the way an operator goes on the first day: `tgd --init`,
//! invite, admit, `UpsertWorkload`, place -- and then something shall run.
//!
//! `#[ignore]`, because it needs two processes, a real OCI runtime,
//! `CAP_NET_ADMIN` (the bridge) and `CAP_SYS_ADMIN` (overlayfs); run via
//! `cargo xtask net`.

use std::path::Path;
use std::time::{Duration, Instant};

use tg_consensus::Command;
use tg_runtime::content::{ContentStore, Digest256, LAYER_FORMAT};
use tg_runtime::resolved::ResolvedImage;
use tgd::admin::{AdminClient, WriteResult};

mod support;

use support::{Running, agent_cluster_material, binary, now, signing_material};

/// An address space of its own: the privileged tests share `tg0`, and
/// `xtask net` runs them individually. `node_network` takes 10.44, `session`
/// 10.99.
const CIDR: &str = "10.46.0.0/16";

/// Two minutes. The way is long: leadership, admission, credential, session,
/// slice, bundle, container -- and every step has its own waiting time.
const PATIENCE: Duration = Duration::from_mins(2);

/// What the container writes. Afterwards it lives on: a container that ends at
/// once leaves the file behind and is already cleared away when one looks.
/// How long it waits for the evidence after a `reconciled`.
///
/// The container writes it first; measured, it is there before the agent has
/// written its message. Five seconds are room for a loaded machine and short
/// enough that a failure says so instead of running the patience out.
const GRACE: Duration = Duration::from_secs(5);

/// The invitation as `tgctl node invite` prints it.
///
/// Only its hash stands in the log (ADR-0037): the log is retention-bound, and a
/// bearer secret in it would be a secret with a retention period.
const TOKEN: &str = "this-token-gets-redeemed";

const PROOF: &str = "echo ran > /proof; exec /bin/sleep 60";

/// A layer with `sh` and `sleep`, together with their libraries.
fn build_layer(layer: &Path) {
    for dir in ["bin", "proc", "dev", "sys", "etc"] {
        std::fs::create_dir_all(layer.join(dir)).expect("directory");
    }
    for binary in ["/bin/sh", "/bin/sleep"] {
        let name = Path::new(binary).file_name().expect("a file name");
        std::fs::copy(binary, layer.join("bin").join(name)).expect("program copyable");
        let ldd = std::process::Command::new("ldd")
            .arg(binary)
            .output()
            .expect("ldd");
        for line in String::from_utf8_lossy(&ldd.stdout).lines() {
            for token in line.split_whitespace() {
                if token.starts_with('/') && token.contains(".so") {
                    let source = Path::new(token);
                    if let (Some(parent), Some(file)) = (source.parent(), source.file_name()) {
                        let target = layer.join(parent.strip_prefix("/").unwrap_or(parent));
                        let _ = std::fs::create_dir_all(&target);
                        let _ = std::fs::copy(source, target.join(file));
                    }
                }
            }
        }
    }
}

/// Sows an image **locally** into the agent's store.
///
/// No network and no registry: if the image lies locally in full, it is taken
/// locally (ADR-0019, `acquire`). That is no convenience here -- there is no
/// registry in this test rig, and the matter is the seam slice -> container, not
/// the puller.
fn seed_image(data_dir: &Path, reference: &str) {
    // **`content_dir()` and not the data directory.** The agent opens its store
    // under `<data-dir>/content` (`NodePaths::content_dir`); sown one level
    // higher it finds nothing and asks the registry -- measured, at this test's
    // first run.
    let store =
        ContentStore::open(tg_runtime::NodePaths::new(data_dir).content_dir()).expect("store");
    let digest = Digest256::of(reference.as_bytes());
    let layer = store.layer_path(&digest);
    std::fs::create_dir_all(&layer).expect("layer directory");
    build_layer(&layer);
    // **The mark last**, as with unpacking: a half-filled layer must not count
    // as finished.
    std::fs::write(layer.join(".complete"), LAYER_FORMAT).expect("mark");

    ResolvedImage {
        reference: reference.to_owned(),
        layers: vec![digest],
        entrypoint: vec!["/bin/sh".to_owned(), "-c".to_owned(), PROOF.to_owned()],
        env: vec!["PATH=/bin".to_owned()],
    }
    .save(&store)
    .expect("record");
}

/// Clears container and mount away when the test ends.
///
/// **Necessary because the container outlives the agent** -- and on purpose at
/// that: it is not its child process, and ADR-0019 lets it run on for exactly
/// that reason. `Running::drop` takes the agent and its children along; the
/// container belongs to the runtime.
///
/// Measured, this test's first run left behind a running `sleep 60`, an overlayfs
/// mount and thereby a temp directory nobody can get at any more -- the same
/// shape that has already filled the disk once in this session.
///
/// And the `Drop` carries only since ADR-0082: with `panic = "abort"` there
/// would be no unwinding.
struct Reaped {
    data_dir: std::path::PathBuf,
}

impl Drop for Reaped {
    fn drop(&mut self) {
        let root = tg_runtime::NodePaths::new(&self.data_dir).runtime_root();
        // **The same runtime that created it.** Writing `crun` hard was a
        // finding once already: `DEFAULT_RUNTIMES` names youki first, and a
        // foreign runtime does not know the state.
        if let Ok(runtime) =
            tg_runtime::oci::OciRuntime::discover(tg_runtime::oci::DEFAULT_RUNTIMES, &root)
        {
            let _ = std::process::Command::new(runtime.name())
                .args([
                    "--root",
                    &root.to_string_lossy(),
                    "delete",
                    "--force",
                    "tg-api",
                ])
                .output();
        }
        let rootfs = tg_runtime::NodePaths::new(&self.data_dir)
            .bundles_dir()
            .join("api")
            .join("rootfs");
        let _ = std::process::Command::new("umount").arg(&rootfs).output();
    }
}

/// The definition as an operator submits it.
fn definition(reference: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"{reference}\"/>\n\
         \x20 </workload>\n\
         </workloads>\n"
    )
}

/// Waits for the evidence -- and **aborts as soon as the reconciliation fails**.
///
/// Without the second condition every failure would run the whole patience out
/// and say "no container" at the end. The reason stands in the agent's log the
/// whole time; measured, a green run has **not one** line of it, a run with a
/// runtime stub, by contrast, has one at once.
///
/// Out of 120 seconds of waiting there thereby becomes a rejection in seconds
/// that names the reason (since ADR-0088 together with the error class).
///
/// The two quoted lines are still German: they come from
/// `tg_runtime::reconcile` and move along when that crate is translated.
fn await_proof(proof: &Path, agent_log: &Path) -> Result<String, String> {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(proof)
            && !text.is_empty()
        {
            return Ok(text);
        }
        if let Ok(log) = std::fs::read_to_string(agent_log) {
            if let Some(line) = log
                .lines()
                .find(|line| line.contains("the reconcile failed"))
            {
                return Err(line.to_owned());
            }
            // **And the other outcome**: the agent reports `reconciled`, and
            // still no evidence comes. That is exactly what a runtime stub that
            // ends with 0 does -- it does not *fail*, it just starts nothing.
            // That is why this case needs a signal of its own; without it it
            // would run the whole patience out.
            if log.contains("\"message\":\"reconciled\"") {
                let grace = Instant::now() + GRACE;
                while Instant::now() < grace {
                    if let Ok(text) = std::fs::read_to_string(proof)
                        && !text.is_empty()
                    {
                        return Ok(text);
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                return Err(format!(
                    "the agent reports `reconciled`, but after {} seconds \
                     there is no evidence -- no container ran. The log stands \
                     under {}",
                    GRACE.as_secs(),
                    agent_log.display()
                ));
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "the patience ran out, and the agent reported neither `reconciled` \
         nor a failure -- the log stands under {}",
        agent_log.display()
    ))
}

/// **From the `UpsertWorkload` to the running container**, over consensus.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands two processes, an OCI runtime, CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
#[allow(clippy::too_many_lines)]
async fn a_workload_from_the_consensus_becomes_a_real_container() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let admin_port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let _control_plane = Running(
        std::process::Command::new(binary("tgd"))
            .args([
                "--telemetry-addr",
                "off",
                "--id",
                "1",
                "--node",
                "tgd-1",
                "--listen",
                &format!("127.0.0.1:{admin_port}"),
                "--cluster-listen",
                &format!("127.0.0.1:{cluster_port}"),
                "--node-listen",
                &format!("127.0.0.1:{session_port}"),
                "--data-dir",
                cp_dir.path().to_str().expect("path"),
                "--peer",
                &format!("1=http://127.0.0.1:{cluster_port}"),
                "--init",
            ])
            .stdout(support::log("tgd"))
            .stderr(support::log("tgd"))
            .spawn()
            .expect("tgd startable"),
    );

    let admin = AdminClient::connect_unix(&tgd::admin::socket_path(cp_dir.path(), 1))
        .expect("admin socket");
    let deadline = Instant::now() + PATIENCE;
    loop {
        assert!(Instant::now() < deadline, "no leadership");
        if let Ok(status) = admin.status().await
            && status.leader == Some(1)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let agent_dir = tempfile::tempdir().expect("tempdir");
    // **Before the first container**, so that a red run clears away too.
    let _reaped = Reaped {
        data_dir: agent_dir.path().to_owned(),
    };
    std::fs::create_dir_all(agent_dir.path().join("desired")).expect("directory");
    let reference = "registry.example.invalid/api:1";
    seed_image(agent_dir.path(), reference);

    // **The invitation is really redeemed** (manual 2.2). No `AdmitNode` by
    // hand: the server writes that itself when the agent joins -- check and
    // consumption lie in the same apply (ADR-0037), and the ordinal comes with
    // it. Admitted by hand the join would be skipped, and the test would run
    // past half of the documented way.
    let identity = agent_dir.path().join("identity");
    let _anchors = agent_cluster_material(agent_dir.path(), cp_dir.path());
    std::fs::write(identity.join("join-token"), TOKEN).expect("invitation");

    for command in [
        Command::InviteNode {
            node: "node-46".to_owned(),
            digest: tg_consensus::token_digest(TOKEN),
            expires_at: now() + 900,
        },
        Command::UpsertNode {
            name: "node-46".to_owned(),
            topology: tg_consensus::Topology {
                site: "s".to_owned(),
                hall: "h".to_owned(),
                rack: "r".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
        Command::SetClusterNetwork {
            cidr: CIDR.to_owned(),
            node_prefix: 24,
        },
        Command::UpsertWorkload {
            document: definition(reference),
        },
        // **No `AssignPlacement`.** Measured, the planner places a wanted
        // workload of its own accord (ADR-0011) -- the counter-check that left
        // it out was green. Setting it here would therefore have covered the
        // stretch this test actually substantiates: the placement comes from the
        // **leader** and not from my hand.
    ] {
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "the setup must get through: {result:?}"
        );
    }

    // **No stub PATH.** The agent looks for its runtime in the test process's
    // `PATH`, and `youki` and `crun` really lie there.
    let _agent = Running(
        std::process::Command::new(binary("tg-agent"))
            .args([
                "--telemetry-addr",
                "off",
                "--data-dir",
                agent_dir.path().to_str().expect("path"),
                "--node",
                "node-46",
                "--control-plane",
                &format!("http://127.0.0.1:{admin_port}"),
                "--node-session",
                &format!("http://127.0.0.1:{session_port}"),
                "--interval",
                "1",
            ])
            .stdout(support::log("tg-agent"))
            .stderr(support::log("tg-agent"))
            .spawn()
            .expect("tg-agent startable"),
    );

    // **The evidence is a file the container wrote itself.** A `reconciled` in
    // the log would prove that the agent tried; that a process in the bundle
    // really ran is said only by itself.
    let proof = tg_runtime::NodePaths::new(agent_dir.path())
        .bundles_dir()
        .join("api")
        .join("rootfs")
        .join("proof");
    let seen = await_proof(&proof, &support::log_path("tg-agent"))
        .unwrap_or_else(|why| panic!("no container ran: {why}"));
    assert!(seen.contains("ran"), "{seen}");
}
