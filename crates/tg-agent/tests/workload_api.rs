//! The agent hands out identities (ADR-0006, ADR-0035, ADR-0036).
//!
//! Until the wiring `tg-identity` was connected to no binary: checked but
//! started by nothing. Here the **process** is checked -- started as in
//! operation, with a data directory as an operator puts it in place.
//!
//! # What is not checked here, and why
//!
//! An **issued** SVID presupposes a socket an instance has got -- since ADR-0081
//! **the socket is the attestation**, and it lies per instance in exactly its
//! container. That part is covered by the runs with a real container
//! (`cargo xtask attest`, `cargo xtask storage`).
//!
//! The head here long said that attestation went over `/proc/<pid>/cgroup` and
//! that the test process "rightly gets nothing". Both are **outdated** since
//! ADR-0081: the cgroup read has gone, and `root` very much reaches an
//! instance's socket (the assurance below says so). What remains is the boundary
//! for all the **others** -- the `0700` directory -- and that is the statement
//! this process witness gives.
//!
//! What is checked is therefore: the socket is there, it speaks gRPC, an
//! unprivileged process does not reach it, a second agent on the same data
//! directory does not start up, and after a hard abort it comes back.

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use support::Running;
use tg_identity::{LocalSigner, TrustDomain, self_signed_ca};

mod support;

const YEAR: i64 = 365 * 24 * 60 * 60;

/// Creates a data directory as an operator sets it up.
fn dev_node(dir: &Path) {
    std::fs::create_dir_all(dir.join("desired")).expect("directory");
    std::fs::write(
        dir.join("desired").join("api.xml"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n\
         </workloads>\n",
    )
    .expect("definition");

    // The agent intermediate. In operation it comes from the control plane
    // (ADR-0006); here it stands as an operational setting, just like the peer
    // addresses in phase 5c.
    let identity = dir.join("identity");
    std::fs::create_dir_all(&identity).expect("directory");
    let domain = TrustDomain::new("cluster.local").expect("domain");
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain, &signer, 0, 10 * YEAR).expect("CA");
    std::fs::write(identity.join("intermediate.pem"), ca.certificate_pem()).expect("certificate");
    std::fs::write(identity.join("intermediate.key.pem"), signer.to_pem()).expect("key");
    std::fs::write(identity.join("bundle.pem"), ca.certificate_pem()).expect("bundle");

    // A runtime stub: the agent looks for it at startup. It does nothing -- this
    // test checks the identity side, not the starting of containers.
    let stub = dir.join("stub");
    std::fs::create_dir_all(&stub).expect("directory");
    let crun = stub.join("crun");
    std::fs::write(&crun, "#!/bin/sh\nexit 0\n").expect("stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&crun, std::fs::Permissions::from_mode(0o755)).expect("mode");
    }
}

/// Starts the agent and waits until its socket is there.
///
/// The process is collected by [`Running`]; whoever calls this function puts it
/// there.
#[allow(clippy::zombie_processes)]
fn start(dir: &Path) -> (Child, std::path::PathBuf) {
    let path = env!("PATH");
    let child = Command::new(env!("CARGO_BIN_EXE_tg-agent"))
        .args([
            // Without telemetry: `cargo test` runs the test binaries
            // concurrently, and the default port would be the same for all.
            "--telemetry-addr",
            "off",
            "--data-dir",
            dir.to_str().expect("path"),
            "--interval",
            "3600",
            "--proxy-image",
            "registry.example.com/tg-proxy:1.0",
        ])
        .env("PATH", format!("{}:{path}", dir.join("stub").display()))
        .stdout(support::log("tg-agent"))
        .stderr(support::log("tg-agent"))
        .spawn()
        .expect("tg-agent startable");

    // **The directory, not a socket** (ADR-0081): one arises per **instance**,
    // and this agent has none assigned. What it produces at startup is the
    // directory -- and its permissions are the security statement
    // (determination 2).
    let sockets = dir.join("sockets");
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if sockets.is_dir() {
            return (child, sockets);
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    panic!("the agent did not create the socket directory");
}

/// **The agent opens the workload API socket.**
///
/// That is the statement of the wiring: `tg-identity` is no longer only tested
/// but started.
#[test]
fn the_agent_opens_the_workload_api_socket() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("tempdir");
    dev_node(dir.path());

    let (child, sockets) = start(dir.path());
    let _running = Running(child);

    assert!(sockets.is_dir(), "the socket directory is missing");

    // **`0700`, and the whole decision rests on it** (ADR-0081,
    // determination 2): the sockets in it carry `0666` so that the sidecar
    // reaches them under its own identifier -- what **separates** is this
    // directory plus the bind mount that bypasses it. Without the permissions
    // every local user would be every workload's identity.
    let mode = std::fs::metadata(&sockets)
        .expect("readable")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o700,
        "the directory must be tight -- otherwise every local user reaches \
         every socket"
    );
}

/// **An unprivileged process reaches no socket** (ADR-0081, determination 2).
///
/// # What replaced this test, and why
///
/// Here stood "an unattested caller gets no SVID": the test process spoke to the
/// node-wide socket, and the **cgroup** refused it. With one socket per instance
/// that no longer applies -- whoever has reached the socket **is** the instance,
/// and `root` reaches it.
///
/// That is no loss: `root` reads the agent intermediate from the disk and mints
/// itself (ADR-0081, consequences; the same argument as with the admin socket,
/// ADR-0044). What counts is the boundary for all the **others** -- and that is
/// the `0700` directory.
#[test]
fn an_unprivileged_process_reaches_no_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    dev_node(dir.path());

    let (child, sockets) = start(dir.path());
    let _running = Running(child);

    // A socket as an instance would get it -- laid by hand, for this agent has
    // none assigned. Its permissions are those of a real one (`0666`) so that
    // the test checks the directory and not the file.
    let socket = sockets.join("tg-probe.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("socket");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
            .expect("permissions");
    }
    drop(listener);

    let script = format!(
        "import socket,sys\n\
         s=socket.socket(socket.AF_UNIX)\n\
         s.settimeout(2)\n\
         try:\n    s.connect({:?})\n    print('ok')\nexcept Exception as e:\n    print(type(e).__name__)\n",
        socket.display().to_string()
    );
    let out = std::process::Command::new("runuser")
        .args(["-u", "nobody", "--", "python3", "-c", &script])
        .output()
        .expect("runuser");
    let verdict = String::from_utf8_lossy(&out.stdout).trim().to_owned();

    // **"Not measured" is not "reachable".** The helper can fail for reasons
    // that have nothing to do with the socket -- measured, when `/usr/bin` on a
    // development machine accidentally stood at `0700` and `runuser` as `nobody`
    // could therefore execute **nothing** (`failed to execute python3:
    // Permission denied`). Without this distinction the witness then said "an
    // unprivileged process reaches the socket", and that is the most dangerous
    // way to be wrong: a security statement that falls over for a foreign reason
    // sends the search for the error to the wrong place -- here it sent me to
    // SELinux for two rounds, and there was nothing there.
    //
    // **Red nevertheless and not skipped:** a witness that cannot measure must
    // not be green (the same reason as with the empty fuzz run in 9c). It now
    // says only what is really going on.
    assert!(
        !verdict.is_empty(),
        "the helper said nothing -- this environment does not allow the \
         measurement, and thereby **nothing** is stated about the socket.\n\
         runuser: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );

    assert_eq!(
        verdict, "PermissionError",
        "an unprivileged process must not reach the socket: {verdict}"
    );
}

/// **A second agent on the same data directory does not start up** (ADR-0043,
/// ADR-0062).
///
/// ADR-0043 names one data directory **per node** as a prerequisite. It was not
/// enforced -- and the damage is the same one ADR-0062 describes: the agent
/// removes a socket left lying before it binds (without that a crashed
/// predecessor would never come up again), and a **running** first one would
/// thereby silently lose its workload API socket. It afterwards holds the
/// descriptor on an unlinked inode; nobody reaches it any more, and every SVID on
/// this node expires within fifteen minutes (ADR-0014). Plus two reconcile loops
/// on the same desired state and two writers on the same address ledger.
///
/// `tgd` is protected against the same thing -- there `redb` takes an exclusive
/// lock. The agent has no database, so it needs the lock itself.
///
/// **What is checked is the effect**, not the exit code: after the failed second
/// start the first one's socket is **used**.
#[test]
fn a_second_agent_on_the_same_data_dir_does_not_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    dev_node(dir.path());
    let (child, sockets) = start(dir.path());
    let _running = Running(child);

    let second = Command::new(env!("CARGO_BIN_EXE_tg-agent"))
        .args([
            "--telemetry-addr",
            "off",
            "--data-dir",
            dir.path().to_str().expect("path"),
            "--interval",
            "3600",
            "--proxy-image",
            "registry.example.com/tg-proxy:1.0",
        ])
        .stdout(support::log("tg-agent"))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("tg-agent startable");

    // With a deadline, not with `output()`: if the second one runs on, **that**
    // is the finding -- and a test that hangs is worse than one that fails (11b).
    let second = await_exit(second, Duration::from_secs(20));
    assert!(
        !second.status.success(),
        "a second agent on the same data directory must not start up"
    );
    let said = String::from_utf8_lossy(&second.stderr);
    assert!(
        said.contains("data directory"),
        "the reason does not name the data directory: {said}"
    );

    // **The actual assurance**: the first one is untouched.
    //
    // Since ADR-0081 there is no node-wide socket left that a second agent could
    // remove -- the damage from ADR-0043 has thereby become structurally
    // smaller. The lock stays right all the same: two reconcile loops on the same
    // desired state and two writers on the same address ledger.
    //
    // What is checked is the **usability**, not the presence: a socket in its
    // directory still accepts. An `is_dir()` alone would say nothing about
    // whether the second one bent the permissions.
    assert!(
        sockets.is_dir(),
        "the first agent's socket directory has disappeared"
    );
    let probe = sockets.join("tg-afterwards.sock");
    let listener = std::os::unix::net::UnixListener::bind(&probe);
    assert!(
        listener.is_ok(),
        "the first agent's directory is no longer usable: {listener:?}"
    );
    let client = std::os::unix::net::UnixStream::connect(&probe);
    assert!(
        client.is_ok(),
        "a socket in it accepts no connection: {client:?}"
    );
}

/// Waits for a child to end -- and ends it when the deadline tears.
fn await_exit(mut child: Child, patience: Duration) -> std::process::Output {
    let deadline = Instant::now() + patience;

    while Instant::now() < deadline {
        if child.try_wait().expect("child status").is_some() {
            return child.wait_with_output().expect("output");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    let _ = child.wait();
    panic!("the second agent ran on instead of ending at the lock");
}

/// **After a `kill -9` the agent starts up again** (ADR-0043, ADR-0019).
///
/// The counter-check to the lock, and it carries the other half of the
/// assurance: a lock that prevents a restart would be worse than none. That is
/// exactly why it is **no** PID file -- that outlives the process that wrote it,
/// and after a hard abort the node would never come up again. The kernel releases
/// a `flock` as soon as the last descriptor falls, no matter **how** the process
/// ends.
///
/// `SIGKILL`, not `SIGTERM`: an orderly end would release the lock anyway, and
/// then this test would check nothing.
#[test]
fn the_agent_starts_again_after_a_hard_kill() {
    let dir = tempfile::tempdir().expect("tempdir");
    dev_node(dir.path());

    let (mut child, socket) = start(dir.path());
    child.kill().expect("SIGKILL");
    child.wait().expect("ended");
    assert!(
        socket.exists(),
        "the lock file and the socket stay lying -- that is the point"
    );

    let (child, sockets) = start(dir.path());
    let _running = Running(child);
    assert!(sockets.is_dir(), "the second run did not come up");
}
