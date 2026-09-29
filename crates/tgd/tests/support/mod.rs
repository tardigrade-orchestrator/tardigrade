//! Shared helpers of the `tgd` integration tests.
//!
//! They previously stood once in every test file. With ADR-0043 a third one
//! came along -- the TLS channel --, and three copies of a security seam are
//! three opportunities to make them differently strict.

// Every test binary includes this module in full and uses a subset of it --
// what a binary does not need is dead code there. That is the peculiarity of
// shared test helpers and no finding.
#![allow(dead_code)]

use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tg_identity::{SpiffeId, TrustDomain};

/// The name the handshake gives -- a placeholder (RFC 2606).
const SNI: &str = "cluster.invalid";

/// Is this child process still alive?
///
/// # Why not `try_wait`
///
/// Measured, in Rust a child that has died is a **zombie** until somebody calls
/// `wait` -- and the test rig calls it only in `Drop`. `/proc/<pid>/stat` then
/// shows `Z`, and after a `try_wait` the entry is gone entirely; both mean dead.
///
/// The way over `/proc` needs only the **PID** and thereby `&self`, while
/// `try_wait` demands a `&mut Child`. That is the reason why ten waiting helpers
/// of this crate did not have the check: their signature is `&self`, and the check
/// was thereby not writable -- not forgotten.
pub(crate) fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| stat.split_whitespace().nth(2).map(str::to_owned))
        .is_some_and(|state| state != "Z")
}

/// Aborts when this node has ended itself.
///
/// **A dead process is no condition one waits for.** Without this check a loop
/// waits out its whole deadline and afterwards reports the wrong cause -- "the node
/// did not take over the leadership", where it has long died on a port conflict.
/// The reason then stands in the log the test rig catches, and nobody looks there.
pub(crate) fn assert_alive(id: impl std::fmt::Display, pid: u32) {
    assert!(
        alive(pid),
        "node {id} ended itself -- the reason stands in its log, which the test \
         rig catches (`<temp>/tg-test-logs/<pid>/`). A frequent case is \
         `Address already in use`: then another process took the port \
         `free_port` had just released."
    );
}

/// The tests' trust domain.
pub(crate) fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("trust domain")
}

/// Puts in place the cluster material ADR-0043 demands.
///
/// The test stands in for the operator: **one** node key in the shared data
/// directory and one leaf per node under `peers/<id>.pem`. That all use the same
/// key pair is a peculiarity of this test rig -- the names are different, and what
/// is checked is name -> key, so the real path runs.
pub(crate) fn cluster_material(data_dir: &Path, ids: &[u64]) {
    let identity = data_dir.join("identity");
    std::fs::create_dir_all(&identity).expect("directory");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    std::fs::write(identity.join("node.key.pem"), key.serialize_pem()).expect("key");

    let peers = data_dir.join("peers");
    std::fs::create_dir_all(&peers).expect("directory");
    for id in ids {
        let sid = SpiffeId::for_node(&domain(), &format!("tgd-{id}")).expect("ID");
        let pem = tg_identity::cluster::node_leaf_pem(&key, &sid).expect("leaf");
        std::fs::write(peers.join(format!("{id}.pem")), pem).expect("leaf");
    }
}

/// Waits until `tgd` has written its cluster leaf and returns it.
///
/// The anchor for the counter-direction (ADR-0043, determination 3). In operation
/// an operator puts it in place; here it is fetched where `tgd` files it.
pub(crate) fn await_leaf(data_dir: &Path) -> String {
    let path = data_dir.join("identity").join("node.leaf.pem");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);

    loop {
        if let Ok(text) = std::fs::read_to_string(&path)
            && text.contains("BEGIN CERTIFICATE")
        {
            return text;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "tgd wrote no cluster leaf -- the reason stands in its log under \
             `{}`. A frequent case is a node that dies at startup (say \
             `Address already in use`); the waiting loop here does not see \
             that.",
            log_path("tgd").display()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// A channel to a port that demands **no** credential but shows one.
///
/// That is the client side of `--listen` since ADR-0043: what is checked is that
/// the control plane really answers there.
pub(crate) fn open_channel(endpoint: &str, anchor_pem: &str) -> tonic::transport::Channel {
    let trust = tg_identity::cluster::anchors_from_pem(anchor_pem, &domain()).expect("anchor");
    let verifier = tg_identity::NodeVerifier::new(domain(), tg_identity::cluster::shared(trust));
    let config = tg_identity::cluster::verifying_client_config(verifier).expect("configuration");
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    tonic::transport::Endpoint::from_shared(endpoint.to_owned())
        .expect("address")
        .connect_with_connector_lazy(tower::service_fn(move |uri: http::Uri| {
            let connector = connector.clone();
            async move {
                let host = uri.host().unwrap_or("127.0.0.1").to_owned();
                let port = uri.port_u16().unwrap_or(80);
                let stream = tokio::net::TcpStream::connect((host, port)).await?;
                let name =
                    rustls_pki_types::ServerName::try_from(SNI).map_err(std::io::Error::other)?;
                let tls = connector.connect(name, stream).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }
        }))
}
/// The path to a **foreign** binary of the workspace.
///
/// `CARGO_BIN_EXE_<name>` knows only the own package, so the path is looked for
/// beside our own binary -- with the same safeguard as in `tg-agent`: if it is
/// missing or older than its source, the test **aborts** instead of checking
/// against a version that no longer exists in that form.
///
/// **The second copy of this seam**, and that is a decision: they are two crates,
/// a test helper across crate boundaries would need a crate of its own (ADR-0023),
/// and the same choice has already been made in the tree for `Running` -- one per
/// crate instead of four scattered over the tree.
pub(crate) fn foreign_binary(name: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_tgd"));
    path.pop();
    let path = path.join(name);

    assert!(
        path.is_file(),
        "{} is missing -- this test needs both binaries. \
         `cargo test --workspace` builds them; individually: \
         `cargo build -p {name}`",
        path.display()
    );

    let built = std::fs::metadata(&path)
        .and_then(|meta| meta.modified())
        .expect("timestamp");
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join(name)
        .join("src");
    assert!(
        newest_source(&src) <= built,
        "{} is older than its source -- `cargo build --workspace`, then again",
        path.display()
    );

    path
}

/// The youngest timestamp under `dir`.
fn newest_source(dir: &Path) -> std::time::SystemTime {
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return newest;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            newest = newest.max(newest_source(&path));
        } else if let Ok(when) = entry.metadata().and_then(|meta| meta.modified()) {
            newest = newest.max(when);
        }
    }
    newest
}

/// A free port that stays free beside other runs too.
///
/// # Two failed attempts stand in here
///
/// First it was `bind("127.0.0.1:0")` and release it again. Between the release
/// and the child's bind lies a gap, and under the load of a workspace run another
/// test binary reaches into it -- the finding from phase 11b, and with three ports
/// per node (ADR-0043) three times as likely.
///
/// Then a **fixed range per test file**. That fixed the collision within one run
/// and created a new one: two simultaneous `cargo test` runs went through the same
/// ports in the same order, so in lockstep. The bind check has the same gap as
/// before -- it makes it only rarer, not smaller.
///
/// The right axis was there the whole time: **every test binary is a process of
/// its own.** The process id thereby separates both at once -- the binaries of one
/// run and the runs among each other --, and it needs no agreement between files
/// nobody maintains.
///
/// # And the block was too small -- measured
///
/// With `BLOCK = 100` `signing.rs` exhausted its block and ran into the
/// neighbour's:
///
/// ```text
/// PROBE step=124 port=22724 base=22600      (signing.rs)
/// PROBE step=82  port=26082 base=26000      (telemetry.rs)
/// ```
///
/// Five ports per node, five nodes, five tests. With that the separation the
/// paragraph above promises did **not** apply for this file -- and the neighbouring
/// block belongs to a binary that binds there at the same time. The bind check does
/// take hold then, but it has the same gap as ever: between it and the child's bind
/// lies a window.
///
/// The block is therefore **250** -- twice the measured peak --, and the range now
/// lies **below** the ephemeral one (`ip_local_port_range` is `32768 60999` here).
/// Previously it lay in the middle of it, so every bound test port competed with
/// the machine's outgoing connections.
///
/// The price is named: 90 blocks instead of 400, so two simultaneous binaries hit
/// the same one more often. That is the better trade -- a collision within the block
/// is handled by the bind check and the carrying on, a collision with an ephemeral
/// connection is not.
pub(crate) fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};

    /// The lowest port from which the search starts -- below the ephemeral range.
    const FIRST: u16 = 10_000;
    /// How many ports a process has for itself (measured peak: 125).
    const BLOCK: u16 = 250;
    /// How many blocks there are -- `FIRST + BLOCKS * BLOCK` stays below 32768.
    const BLOCKS: u16 = 90;

    static NEXT: AtomicU16 = AtomicU16::new(0);

    let block = u16::try_from(std::process::id() % u32::from(BLOCKS)).unwrap_or(0);
    let base = FIRST + block * BLOCK;

    for _ in 0..(BLOCKS * BLOCK) {
        let step = NEXT.fetch_add(1, Ordering::Relaxed);
        // Carry on past the own block if it is occupied: two processes with the
        // same remainder otherwise share a block.
        let port = base.wrapping_add(step % (BLOCKS * BLOCK));
        if port >= FIRST && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port found");
}

/// A destination for a child process's output -- a file that outlives the
/// failure.
///
/// # Why not `Stdio::null()`
///
/// `null()` stood here in 42 places, and the price is measured: when the
/// ADR-0076 witness fell in the full run, there was **no log** -- the test could
/// not say why the active role never appeared, and the cause had to be derived
/// from the constants. That is the same shortcoming this tree fixed at the
/// sidecar (`alert`), at the identity service (`refusal`) and at the DNS
/// forwarder, only in the test rig.
///
/// **Not `Stdio::piped()`**, and for the reason the same tree measured at the
/// `nft` writer: whoever does not read a pipe blocks the child as soon as the
/// buffer is full (64 KiB). A `tgd` under load reaches that.
///
/// # Where the file lies
///
/// `<temp>/tg-test-logs/<pid>/<name>-<thread>.log`. The **thread name** is the
/// test's name (that is how `libtest` names its threads), so every test has its
/// own file -- even when seventeen of them run concurrently in one binary.
///
/// The panic hook below shows the tail of exactly this file when the test falls.
/// With that the diagnosis stands **in** the error message and not in a
/// directory nobody knows about.
pub(crate) fn log(name: &str) -> Stdio {
    let path = log_path(name);
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(file) => {
            install_dump();
            Stdio::from(file)
        }
        // A log that cannot be created is no reason to lose a test: then quiet,
        // as before.
        Err(_) => Stdio::null(),
    }
}

/// Waits until `needle` stands in this test's log -- and returns it.
///
/// **What is read is the log file, not a pipe.** The reason stands at [`log`]:
/// whoever does not drain a pipe blocks the child. The file is there anyway, the
/// panic hook shows its tail on a failure, and with that this helper needs no
/// second reader for the same stream.
///
/// On expiry what was last to be seen comes back -- the caller's assertion then
/// names the finding, not this helper.
pub(crate) fn await_stderr(child: &mut Child, needle: &str) -> String {
    let path = log_path("tgd");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut seen = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&path) {
            seen = text;
            if seen.contains(needle) {
                return seen;
            }
        }
        // A child that has ended writes nothing more.
        if matches!(child.try_wait(), Ok(Some(_))) {
            return std::fs::read_to_string(&path).unwrap_or(seen);
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    seen
}

/// The path of this test's log file for `name`.
pub(crate) fn log_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir()
        .join("tg-test-logs")
        .join(std::process::id().to_string());
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{name}-{}.log", thread_slug()))
}

/// The name of the running test, usable as a file name.
fn thread_slug() -> String {
    std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Attaches a panic hook **once per process** that shows the logs of the fallen
/// test.
///
/// The previous hook is still called -- otherwise the panic message itself would
/// disappear, and that would be worse than no log.
fn install_dump() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        sweep_old_logs();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            previous(info);
            dump_logs_of_this_thread();
        }));
    });
}

/// Shows the tail of the running thread's logs.
fn dump_logs_of_this_thread() {
    let slug = thread_slug();
    let dir = std::env::temp_dir()
        .join("tg-test-logs")
        .join(std::process::id().to_string());
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(&format!("-{slug}.log")))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // The **tail**: what stands at the end explains a failure; what stands
        // at the beginning is the start.
        let tail: Vec<&str> = text.lines().rev().take(40).collect();
        eprintln!("--- {} (last {} lines) ---", path.display(), tail.len());
        for line in tail.into_iter().rev() {
            eprintln!("{line}");
        }
    }
}

/// Clears away logs of **earlier** runs -- once per process.
///
/// Without that `<temp>/tg-test-logs` grows with every run, and unbounded growth
/// in `/tmp` is exactly what has filled the disk twice in this tree (`target/`
/// with 167 GB, 22 overlayfs mounts left lying).
///
/// One hour, and by **mtime**: another process of the **same** run has fresh
/// files and stays untouched.
pub(crate) fn sweep_old_logs() {
    let root = std::env::temp_dir().join("tg-test-logs");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    let cutoff = std::time::Duration::from_hours(1);
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .and_then(|at| at.elapsed().map_err(std::io::Error::other))
            .is_ok_and(|age| age > cutoff);
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// A child process that dies with its value.
///
/// # Why here and not per test file
///
/// These four lines stood **eight times** in the tree, byte for byte identical.
/// What they do is clear away: a child that outlives the test holds ports, data
/// directories and -- as measured in this session -- overlayfs mounts fast until
/// somebody finds the disk full.
///
/// Eight copies of a cleanup discipline are eight opportunities to make them
/// differently strict; today they agree, and that stays so because there is only
/// one of them.
///
/// The field is visible so that the call sites can write `Running(child)`
/// unchanged -- the rebuild was **not** to touch the 30 places.
pub(crate) struct Running(pub(crate) Child);

/// Waits until a file is there -- and **a dead process is a finding**.
///
/// The finding from `cluster.rs` (`assert_all_alive`), at a second place: a
/// superseded waiting place did not check whether the child was still alive,
/// therefore waited out its whole patience and reported "the socket did not come
/// up" -- that is, the **wrong** cause, where `tgd` had died on a port conflict.
/// An operator of this test rig looks for that in the product.
///
/// # Panics
///
/// When the process ends or the deadline expires. The message names in both
/// cases where the reason stands -- the panic hook shows it anyway, but it says
/// in addition **which** of the two cases it was.
pub(crate) fn await_file(child: &mut Child, path: &Path, patience: Duration) {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!(
                "the process ended itself ({status}) before {} was there -- \
                 the reason stands in its log, which the test rig catches \
                 (`<temp>/tg-test-logs/<pid>/`). A frequent case is `Address \
                 already in use`: then another process took the port \
                 `free_port` had just released.",
                path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    panic!(
        "{} did not come up, and the process is still running -- its log lies \
         under `<temp>/tg-test-logs/<pid>/`",
        path.display()
    );
}

impl Drop for Running {
    fn drop(&mut self) {
        // **The children too** -- and that is measured, not precautionary.
        //
        // A `tg-agent` or `tgd` starts `crun`/`youki` as a child. Whoever kills
        // only the pid leaves it running, and it afterwards creates its
        // `--root`: measured, `crun --root <dir>/runtime delete` creates the
        // directory, **even when it finds nothing to delete** -- and that after
        // `TempDir::drop`. What is left behind is a temp directory containing
        // only `runtime/`.
        //
        // Exactly this shape stood in `plans/PLAN.md` **twice as unexplained**,
        // and both explanations were false (first "a killed run", then "not
        // reproducible"). What caught them was a watcher that noted the running
        // test binaries at every occurrence.
        //
        // **First collect, then kill the parent, then the children:** once the
        // parent is gone, its children are reparented to `init` and
        // `/proc/<pid>/task/*/children` is gone. And expressly **not** the
        // process group: without `process_group(0)` at the start the child lies
        // in the **test runner's** group, and `kill(-pid)` would take it along.
        let children = descendants(self.0.id());
        let _ = self.0.kill();
        let _ = self.0.wait();
        for pid in children {
            // A failure is expected: the child can already be gone.
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// A pid's child processes, read from `/proc`.
///
/// Linux-specific and for that **exact**: `children` names exactly those this
/// process started -- unlike a process group, which would contain the test runner
/// too.
fn descendants(pid: u32) -> Vec<u32> {
    let tasks = std::path::Path::new("/proc")
        .join(pid.to_string())
        .join("task");
    let Ok(entries) = std::fs::read_dir(&tasks) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for task in entries.filter_map(Result::ok) {
        let Ok(text) = std::fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        out.extend(
            text.split_whitespace()
                .filter_map(|raw| raw.parse::<u32>().ok()),
        );
    }
    out
}

/// Waits until the admin socket **accepts calls** -- and names a dead process
/// instead of waiting out its patience.
///
/// # Why waiting for the leaf does not suffice
///
/// Measured, the two things a test rig can wait for arise **far apart**: `tgd`
/// writes its cluster leaf in `lib.rs:248` and binds the admin socket in
/// `lib.rs:970` -- between them lie the Raft storage, the membership, the network
/// and three TLS configurations.
///
/// Whoever calls only [`await_leaf`] thereby gets a client on a socket that does
/// not exist yet. `AdminClient::connect_unix` is **lazy** and therefore fails not
/// there but at the first call -- with `Unavailable: No such file or directory`,
/// that is, at a place that looks like a server error. Exactly that way
/// `attestation::a_name_the_cluster_does_not_know_gets_no_stored_nonce` fell in a
/// workspace run, while it went through three times in isolation.
///
/// # A dead process is a finding, not a condition
///
/// The finding from `cluster.rs` (`assert_all_alive`). Of the two versions this
/// waiting place had, only one checked it: `signing::wait_for_admin` did,
/// `audit_rotation::await_socket` saw only `path.exists()` and reported after its
/// whole patience "the socket did not come up" -- even when the process had long
/// died on a port conflict. Two versions of a waiting discipline are two
/// opportunities to make them differently strict, and one of them was.
///
/// # Panics
///
/// When a child ends before the socket accepts, or when it does not do so within
/// twenty seconds -- the same patience as [`await_leaf`], because it is the same
/// waiting for the same start.
pub(crate) fn await_admin(path: &Path, children: &mut [&mut Child]) -> tgd::admin::AdminClient {
    await_admin_within(path, children, Duration::from_secs(20))
}

/// The same with a deadline of its own.
///
/// It is a **setting** and not the constant, for the same reason as at
/// `volume::run_within`: a witness that checks that what is no socket does *not*
/// get through here would otherwise wait twenty seconds -- and a test that waits
/// that long for an expected no is one somebody switches off.
///
/// # Panics
///
/// As [`await_admin`].
pub(crate) fn await_admin_within(
    path: &Path,
    children: &mut [&mut Child],
    within: Duration,
) -> tgd::admin::AdminClient {
    let deadline = Instant::now() + within;
    loop {
        // What is asked is the **client**, not the file: a socket inode can be
        // left over from a predecessor (`tgd` removes it at startup so that a
        // crashed one comes up again) -- `path.exists()` would then be true and
        // the call after it red.
        if let Ok(client) = tgd::admin::AdminClient::connect_unix(path)
            && std::os::unix::net::UnixStream::connect(path).is_ok()
        {
            return client;
        }
        for (at, child) in children.iter_mut().enumerate() {
            if let Ok(Some(status)) = child.try_wait() {
                panic!(
                    "node {} ended itself ({status}) -- the reason stands in \
                     its log (`<temp>/tg-test-logs/<pid>/`), and a frequent \
                     case is `Address already in use`",
                    at + 1
                );
            }
        }
        assert!(
            Instant::now() < deadline,
            "the admin socket '{}' accepts no calls",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Fetches a process's metrics document.
///
/// `curl` and no HTTP client in the tree -- foreign code, the same yardstick as
/// `dig` in 9c and `rust-spiffe` in 7c; a crate for it would be one for a single
/// line (ADR-0023).
///
/// **Soft, on purpose:** if the call fails, an empty text comes back. Every
/// caller sits in a waiting loop, and there "the endpoint does not stand yet" is
/// the same situation as "the line is not there yet"; an `expect` would turn that
/// into a failure on the first attempt.
///
/// The function existed **twice** and differently strict -- the one returned
/// empty on a failure, the other aborted.
pub(crate) fn scrape(port: u16) -> String {
    let out = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            &format!("http://127.0.0.1:{port}/metrics"),
        ])
        .output();
    out.map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default()
}
