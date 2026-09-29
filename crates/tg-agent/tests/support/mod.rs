//! Shared helpers of the `tg-agent` integration tests.
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

use tg_identity::{LocalSigner, TrustDomain};

/// The name the handshake gives -- a placeholder (RFC 2606).
const SNI: &str = "cluster.invalid";

/// The tests' trust domain.
pub(crate) fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("trust domain")
}

/// Waits until `tgd` has written its cluster leaf and returns it.
///
/// The anchor for the counter-direction (ADR-0043, determination 3). In
/// operation an operator puts it in place; here it is fetched where `tgd` files
/// it.
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

/// A free port that stays free beside other runs too.
///
/// # Two failed attempts stand in here
///
/// First it was `bind("127.0.0.1:0")` and release it again. Between the release
/// and the child's bind lies a gap, and under the load of a workspace run
/// another test binary reaches into it -- the finding from phase 11b, and with
/// three ports per node (ADR-0043) three times as likely.
///
/// Then a **fixed range per test file**. That fixed the collision within one run
/// and created a new one: two simultaneous `cargo test` runs went through the
/// same ports in the same order, so in lockstep. The bind check has the same gap
/// as before -- it makes it only rarer, not smaller.
///
/// The right axis was there the whole time: **every test binary is a process of
/// its own.** The process id thereby separates both at once -- the binaries of
/// one run and the runs among each other --, and it needs no agreement between
/// files nobody maintains.
pub(crate) fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};

    /// The lowest port from which the search starts.
    const FIRST: u16 = 20_000;
    /// How many ports a process has for itself.
    const BLOCK: u16 = 100;
    /// How many blocks there are.
    const BLOCKS: u16 = 400;

    static NEXT: AtomicU16 = AtomicU16::new(0);

    let block = u16::try_from(std::process::id() % u32::from(BLOCKS)).unwrap_or(0);
    let base = FIRST + block * BLOCK;

    for _ in 0..(BLOCKS * BLOCK) {
        let step = NEXT.fetch_add(1, Ordering::Relaxed);
        // Carry on past the own block if it is occupied: two processes with
        // the same remainder otherwise share a block.
        let port = base.wrapping_add(step % (BLOCKS * BLOCK));
        if port >= FIRST && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port found");
}

/// The path to a binary of the workspace -- and the assurance that it is **up
/// to date**.
///
/// `CARGO_BIN_EXE_*` exists only for the binaries of the **own** package, and
/// these tests need two: `tg-agent` and `tgd`. The second lies as a sibling
/// beside the first -- the same `target/` level, the same run.
///
/// # Why a time check stands here
///
/// `cargo test -p tg-agent` does **not** rebuild `tgd` -- it does rebuild the
/// library beside it, because these tests use it. Whoever changes something in
/// `tgd` and tests only this package checks against the old control plane, and
/// it looks perfectly normal.
///
/// That is expensive with a **counter-check**, and it has happened **three
/// times** in this project: the proof applied every time to a binary that no
/// longer existed in that form. A note beside it did not prevent it.
///
/// **The note had moreover compared the wrong pair.** It read that a time check
/// would not catch it reliably, because "in a shared run the order of the two
/// targets is not fixed" -- what is compared here, however, is not two targets
/// but **binary against source**.
///
/// # Only against the binary's own crate
///
/// The first throw compared against **all** `crates/*/src`, and beside it stood
/// that `cargo test --workspace` builds everything before the first test anyway.
/// **Measured that is false**: cargo does not relink when nothing has changed
/// for a target -- the file's time then rightly stays put. A change to
/// `tg-agent` alone thereby made the whole workspace run red, with a message
/// about `tgd`, which has nothing to do with it.
///
/// The second throw left the **leaf binaries** out and was for the same reason
/// still false: `tgd` has a `lib.rs`, so it stayed in, and a touched file there
/// made the run red -- with a message about `tg-agent`, which cargo had quite
/// rightly not relinked. And a `cargo build --workspace` did not help, because
/// it changes nothing about this situation.
///
/// **The lesson: mtime is no measure for "stale" across crate boundaries.** What
/// it answers reliably is the one question at issue here: *is this binary older
/// than its **own** source?* Exactly this case happened to me three times --
/// worked on `tgd`, ran `cargo test -p tg-agent`, green against the old control
/// plane. It is also the only one a `cargo build` fixes.
///
/// What the check thereby does **not** catch: a change to a library `tgd` links
/// (`tg-store`, say). Then the binary is old and its own crate untouched. A
/// narrower check that carries is better than a broad one that makes the
/// workspace run red and says nothing about the matter in the process.
///
/// The price stands beside it: after a `cargo fmt` alone the sources are younger
/// without anything having changed -- then this check demands a build that is
/// substantively unnecessary. Twenty seconds against a proof that was worth
/// nothing: that is the trade, and it is worth it.
pub(crate) fn binary(name: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_tg-agent"));
    path.pop();
    let path = path.join(name);

    assert!(
        path.is_file(),
        "{} is missing -- this test needs both binaries. \
         `cargo test --workspace` builds them; individually: \
         `cargo build -p tgd`",
        path.display()
    );

    if let Some(source) = stale_against_sources(&path) {
        panic!(
            "{} is older than {} -- this binary does not contain the code you \
             are checking right now. `cargo build --workspace`, then again.",
            path.display(),
            source.display()
        );
    }

    path
}

/// The workspace's youngest source file, if it is younger than `binary`.
///
/// `None` means: the binary is up to date. What is compared against are **all**
/// crates, not only `tgd`: a change in `tg-store` likewise demands a new build
/// of the binary, and cargo does not build it along with
/// `cargo test -p tg-agent`.
fn stale_against_sources(binary: &Path) -> Option<std::path::PathBuf> {
    let built = std::fs::metadata(binary).ok()?.modified().ok()?;
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?;
    // The binary's own crate -- in this workspace it is named like the binary.
    // If the directory does not exist, there is nothing to compare.
    let src = crates.join(binary.file_name()?).join("src");
    if !src.is_dir() {
        return None;
    }

    let mut newest: Option<(std::path::PathBuf, std::time::SystemTime)> = None;
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Only `src/`: cargo rebuilds a changed test file anyway, and
                // `target/` does not belong to it.
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && path.components().any(|part| part.as_os_str() == "src")
                && let Ok(modified) = entry.metadata().and_then(|meta| meta.modified())
                && modified > built
                && newest.as_ref().is_none_or(|(_, seen)| modified > *seen)
            {
                newest = Some((path, modified));
            }
        }
    }

    newest.map(|(path, _)| path)
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
fn sweep_old_logs() {
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

/// Is this child process still alive?
///
/// # Why not `try_wait`
///
/// In Rust a child that has died is a **zombie** until somebody calls `wait` --
/// and [`Running`] calls it only in `Drop`. `/proc/<pid>/stat` then shows `Z`,
/// and after a `try_wait` the entry is gone entirely; both mean dead.
///
/// The way over `/proc` needs only the **PID**, while `try_wait` demands a
/// `&mut Child` -- exactly the reason why waiting helpers with `&` access did not
/// have the check.
///
/// The same version stands in `crates/tgd/tests/support`, and for the same
/// reason as [`Running`] itself: a test helper across crate boundaries would need
/// a crate of its own (ADR-0023).
pub(crate) fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| stat.split_whitespace().nth(2).map(str::to_owned))
        .is_some_and(|state| state != "Z")
}

/// Aborts when this process has ended itself.
///
/// **A dead process is no condition one waits for.** Without this check a loop
/// waits out its whole deadline and afterwards reports the wrong cause -- "no
/// leadership", where the control plane has long died on a port conflict. The
/// reason then stands in the log the test rig catches, and nobody looks
/// there.
pub(crate) fn assert_alive(was: &str, pid: u32) {
    assert!(
        alive(pid),
        "{was} ended itself -- the reason stands in its log, which the test \
         rig catches (`<temp>/tg-test-logs/<pid>/`). A frequent case is \
         `Address already in use`: then another process took the port \
         `free_port` had just released."
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

/// Puts the cluster material in place for the agent and returns its SPKI.
///
/// The test stands in for the operator here (ADR-0043, determination 3): the
/// node key arises locally, and `tgd`'s cluster leaf comes as the anchor beside
/// it. The SPKI then travels via `InviteNode`/`AdmitNode` into the trust list --
/// **without admission no session**, and that is the point.
/// How long it waits for the cluster leaf `tgd` writes at startup.
///
/// **A constant of its own and not the caller's**: the test files' patience
/// diverges (30 s to 2 min), and this helper waits for an operation that belongs
/// to the start. A borrowed number would be one here that somebody changes for a
/// different reason.
const LEAF_PATIENCE: Duration = Duration::from_secs(30);

pub(crate) fn agent_cluster_material(
    agent_dir: &std::path::Path,
    tgd_dir: &std::path::Path,
) -> String {
    let identity = agent_dir.join("identity");
    std::fs::create_dir_all(&identity).expect("directory");

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    std::fs::write(identity.join("node.key.pem"), key.serialize_pem()).expect("key");

    // `tgd` writes the leaf at startup; here it waits until it is there.
    let leaf = tgd_dir.join("identity").join("node.leaf.pem");
    let deadline = Instant::now() + LEAF_PATIENCE;
    let pem = loop {
        if let Ok(text) = std::fs::read_to_string(&leaf)
            && text.contains("BEGIN CERTIFICATE")
        {
            break text;
        }
        assert!(Instant::now() < deadline, "tgd wrote no cluster leaf");
        std::thread::sleep(Duration::from_millis(50));
    };
    std::fs::write(identity.join("control-plane.pem"), pem).expect("anchor");

    tg_identity::control::spki_base64(&key)
}

pub(crate) fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs(),
    )
    .expect("fits")
}

/// A control plane with a signing CA.
pub(crate) fn signing_material(dir: &Path) -> Vec<u8> {
    let signing = dir.join("signing");
    std::fs::create_dir_all(&signing).expect("directory");

    let domain = TrustDomain::new("cluster.local").expect("domain");
    let key = LocalSigner::generate().expect("key");
    let ca = tg_identity::self_signed_ca(&domain, &key, 0, 10 * 365 * 24 * 3_600).expect("CA");

    std::fs::write(signing.join("ca.pem"), ca.certificate_pem()).expect("CA");
    std::fs::write(signing.join("ca.key.pem"), key.to_pem()).expect("key");
    std::fs::write(signing.join("bundle.pem"), ca.certificate_pem()).expect("bundle");

    ca.certificate_der().to_vec()
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
