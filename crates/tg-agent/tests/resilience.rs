//! A broken entry costs its workload, not the node (ADR-0062).
//!
//! What is checked is the **process**, for exactly there lay the finding: `once`
//! gave `Err`, `run_with` passed it through, `main` ended with an error status --
//! and a supervisor turned that into a crash loop. With the agent went the
//! workload API socket (SVIDs carry 15 min, ADR-0014), the resolver (ADR-0013)
//! and the session to the control plane (ADR-0040). A test against `once` alone
//! would not have shown that: there an `Err` is only an `Err`.
//!
//! The second half of every assurance is therefore always the same: the
//! **uninvolved** workload is still reconciled. An agent that lives and does
//! nothing any more would hardly be better than one that dies.
//!
//! Several needles here are still German: they come from `tg_runtime::reconcile`
//! and move along when that crate is translated.

use std::io::Read as _;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use support::Running;

mod support;

/// A healthy workload. Its image does not exist (`.invalid`, RFC 2606) -- the
/// reconciliation therefore fails fast and without a network. That it is
/// **attempted** is the statement.
fn healthy(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"{name}\" kind=\"service\">\n\
         \x20   <image reference=\"registry.invalid/{name}:1\"/>\n\
         \x20 </workload>\n\
         </workloads>\n"
    )
}

/// Two workloads waiting for each other.
fn cyclic(name: &str, other: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"{name}\" kind=\"service\">\n\
         \x20   <image reference=\"registry.invalid/{name}:1\"/>\n\
         \x20   <dependencies><after ref=\"{other}\"/></dependencies>\n\
         \x20 </workload>\n\
         </workloads>\n"
    )
}

fn put(dir: &Path, name: &str, document: &str) {
    std::fs::create_dir_all(dir.join("desired")).expect("directory");
    std::fs::write(dir.join("desired").join(format!("{name}.xml")), document).expect("definition");
    std::fs::write(dir.join("desired").join(format!("{name}.instances")), "0\n")
        .expect("assignment");
}

/// A runtime stub: the agent looks for one at startup. It does nothing -- what is
/// checked here is the resilience against the cache, not the starting of
/// containers.
fn stub_runtime(dir: &Path) {
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

#[allow(clippy::zombie_processes)]
fn start(dir: &Path) -> Child {
    let path = env!("PATH");
    Command::new(env!("CARGO_BIN_EXE_tg-agent"))
        .args([
            // Without telemetry: `cargo test` runs the test binaries
            // concurrently, and the default port would be the same for all.
            "--telemetry-addr",
            "off",
            "--data-dir",
            dir.to_str().expect("path"),
            "--interval",
            "1",
            // Without identity material; this test checks the cache path.
            "--identity=false",
        ])
        .env("PATH", format!("{}:{path}", dir.join("stub").display()))
        .stdout(support::log("tg-agent"))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("tg-agent startable")
}

/// Collects the log until both lines are there or the patience ends.
///
/// The patience is generous because it is exhausted only in the **failure
/// case**: in the normal case both stand there after the first pass.
fn await_log(child: &mut Child, needles: &[&str]) -> String {
    let mut stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let mut buffer = [0_u8; 4096];
        while let Ok(read) = stderr.read(&mut buffer) {
            if read == 0 {
                break;
            }
            text.push_str(&String::from_utf8_lossy(&buffer[..read]));
            if tx.send(text.clone()).is_err() {
                return;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seen = String::new();
    while Instant::now() < deadline {
        let Ok(text) = rx.recv_timeout(Duration::from_secs(5)) else {
            break;
        };
        seen = text;
        if needles.iter().all(|needle| seen.contains(needle)) {
            return seen;
        }
    }

    seen
}

/// **An unreadable document does not cost the agent** (ADR-0062,
/// determinations 1 and 2).
///
/// Measured, it was deadly before, and already **at startup** -- the agent never
/// got to its first pass, and at the next attempt it read the same file.
#[test]
fn an_unreadable_entry_costs_its_workload_and_not_the_node() {
    let dir = tempfile::tempdir().expect("tempdir");
    stub_runtime(dir.path());
    put(dir.path(), "intact", &healthy("intact"));
    std::fs::write(dir.path().join("desired").join("broken.xml"), "no XML\n")
        .expect("broken entry");
    std::fs::write(dir.path().join("desired").join("broken.instances"), "0\n").expect("assignment");

    let mut child = start(dir.path());
    let log = await_log(&mut child, &["unreadable", "intact"]);
    let alive = child.try_wait().expect("state").is_none();
    let _running = Running(child);

    assert!(alive, "the agent died; log:\n{log}");
    assert!(
        log.contains("unreadable"),
        "the finding must be named (determination 6); log:\n{log}"
    );
    // **The second half**: the uninvolved one is still reconciled. Without it
    // the test would show only that a process lives.
    assert!(
        log.contains("intact"),
        "the healthy workload was not reconciled; log:\n{log}"
    );
}

/// **An ordering cycle costs its members, not the node** (ADR-0062,
/// determination 2).
///
/// It needs no damage: `tgctl` refuses it on both client paths, a direct
/// `AdminClient::write` does not -- and per ADR-0044 whoever reaches the socket
/// may do that.
#[test]
fn an_ordering_cycle_costs_its_members_and_not_the_node() {
    let dir = tempfile::tempdir().expect("tempdir");
    stub_runtime(dir.path());
    put(dir.path(), "a", &cyclic("a", "b"));
    put(dir.path(), "b", &cyclic("b", "a"));
    put(dir.path(), "intact", &healthy("intact"));

    let mut child = start(dir.path());
    let log = await_log(&mut child, &["cycle", "intact"]);
    let alive = child.try_wait().expect("state").is_none();
    let _running = Running(child);

    assert!(alive, "the agent died; log:\n{log}");
    assert!(
        log.contains("cycle"),
        "the cycle must be named; log:\n{log}"
    );
    assert!(
        log.contains("intact"),
        "the uninvolved one was not reconciled; log:\n{log}"
    );
}

/// **`--once` says what it found** (ADR-0062, determination 6).
///
/// A one-shot call is a tool, and its caller wants the verdict -- that is why it
/// still returns an error status. Only the message must be right too: measured,
/// it said "0 workload(s) not reconciled" **and** failed, because `is_clean` has
/// counted the isolated entries since ADR-0062 while the message named only the
/// failed ones. An operator reads a zero in it and afterwards looks in the wrong
/// place.
#[test]
fn a_single_run_names_what_it_isolated() {
    let dir = tempfile::tempdir().expect("tempdir");
    stub_runtime(dir.path());
    put(dir.path(), "a", &cyclic("a", "b"));
    put(dir.path(), "b", &cyclic("b", "a"));

    let output = Command::new(env!("CARGO_BIN_EXE_tg-agent"))
        .args([
            "--telemetry-addr",
            "off",
            "--data-dir",
            dir.path().to_str().expect("path"),
            "--once",
            "--identity=false",
        ])
        .env(
            "PATH",
            format!("{}:{}", dir.path().join("stub").display(), env!("PATH")),
        )
        .output()
        .expect("tg-agent startable");

    let log = String::from_utf8_lossy(&output.stderr).into_owned();

    // The outcome stays an error status -- nothing changes about that.
    assert!(
        !output.status.success(),
        "a verdict is expected; log:\n{log}"
    );
    assert!(
        log.contains('a') && log.contains('b') && log.contains("isolated"),
        "the message must name the isolated entries; log:\n{log}"
    );
    assert!(
        !log.contains("0 workload(s) not reconciled\""),
        "a zero as the only number sends the operator to the wrong place; \
         log:\n{log}"
    );
}

// ============= The ordering condition, measured at the default

/// **`--interval` does not influence the fence** (ADR-0076, determination 6).
///
/// # What stood here before, and why it is gone
///
/// The agent formed the safety margin from `--interval` plus the fence deadline
/// and checked the ordering condition from ADR-0064 at startup. A test nailed
/// down that the **default** yields no warning in the process and that a really
/// unbearable interval (20 s) does.
///
/// Measured, that was green and the matter broken: the condition "detection +
/// stop < lease deadline" is **necessary and not sufficient**, and with the
/// default configuration a healthy single writer counted as fenced two thirds of
/// the time. There is therefore no check at startup any more -- the condition is
/// a build assurance in `tg_model::lease`, and the margin hangs on no setting.
///
/// # What this test assures now
///
/// That **no** interval produces such a message. That is the decoupling as a
/// statement about the process: whoever raises the interval slows the
/// reconciliation and not the fence. Both directions of the old test have thereby
/// become the same -- and that is exactly the change.
#[test]
fn the_interval_does_not_reach_the_fence() {
    // No interval may produce a statement about single writers.
    const NEEDLE: &str = "interval does not reach";

    // An endpoint nobody listens at: the agent needs a control-plane setting in
    // order to start up at all -- without it it ends at the empty cache
    // (ADR-0019). Reachable it need not be, and port 1 is privileged: nobody
    // listens there for certain.
    let dead = "http://127.0.0.1:1";

    for interval in ["10", "20", "120"] {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("identity")).expect("directory");

        let mut child = Command::new(env!("CARGO_BIN_EXE_tg-agent"))
            .args([
                "--telemetry-addr",
                "off",
                "--data-dir",
                dir.path().to_str().expect("path"),
                "--interval",
                interval,
                "--control-plane",
                dead,
                "--node-session",
                dead,
            ])
            .stdout(support::log("tg-agent"))
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("tg-agent startable");

        // What is waited for is a line that comes anyway -- otherwise every case
        // would wait out its whole patience.
        let log = await_log(&mut child, &["reconcile loop"]);
        let _running = Running(child);
        assert!(
            !log.contains(NEEDLE),
            "interval {interval}s produces a statement about single writers \
             although it no longer influences the fence (ADR-0076)\n{log}"
        );
        // And the counter-check to the search itself: the agent really talked.
        // Without it the test would be green if nothing came.
        assert!(
            log.contains("reconcile loop"),
            "the agent reported nothing: {log}"
        );
    }
}

/// **A name that blocks a derivation costs its workload -- not the pass**
/// (ADR-0084, determination 1).
///
/// # What was measured
///
/// The same setup previously yielded:
///
/// ```text
/// ERROR "the pass failed, it will be repeated"
///       error: "… the sidecar of 'api' would be called 'api-proxy', and this
///               workload already exists…"
/// ```
///
/// **None** of the three workloads was reconciled, `harmless` included, and that
/// anew every second: nothing started, nothing restarted after a crash, nothing
/// cleared away, no single writer fenced (ADR-0064).
///
/// Three lines above the place stands the comment that names the rule for the
/// neighbouring case -- "an unreadable entry costs its workload, not the node"
/// (ADR-0062) --, and the documentation of `once` says the same for an error at
/// **one** workload. For this case it was not true.
///
/// # Why the test runs against the process
///
/// Because the finding lay there: `once` gives an `Err`, the loop reports and
/// retries. A test against the pure function would have shown that an `Err` is
/// an `Err`.
#[test]
fn a_blocked_derivation_costs_its_workload_and_not_the_pass() {
    let dir = tempfile::tempdir().expect("directory");
    stub_runtime(dir.path());

    // `api` takes part in the mesh; its sidecar would be called `api-proxy`.
    put(
        dir.path(),
        "api",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.invalid/api:1\"/>\n\
         \x20   <mesh port=\"9000\"/>\n\
         \x20 </workload>\n\
         </workloads>\n",
    );
    // And an operator has handed out this name.
    put(dir.path(), "api-proxy", &healthy("api-proxy"));
    // The uninvolved one -- it carries the statement.
    put(dir.path(), "harmless", &healthy("harmless"));

    let path = env!("PATH");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tg-agent"))
        .args([
            "--telemetry-addr",
            "off",
            "--data-dir",
            dir.path().to_str().expect("path"),
            "--interval",
            "1",
            "--identity=false",
            // Without this setting the node derives nothing at all (ADR-0059).
            "--proxy-image",
            "registry.invalid/proxy:1",
        ])
        .env(
            "PATH",
            format!("{}:{path}", dir.path().join("stub").display()),
        )
        .stdout(support::log("tg-agent"))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("tg-agent startable");

    let seen = await_log(&mut child, &["isolated", "harmless"]);
    let _ = child.kill();

    assert!(
        !seen.contains("the pass failed"),
        "the pass must not fail on a name:\n{seen}"
    );
    assert!(
        seen.contains("api-proxy"),
        "the reason must name the occupied name:\n{seen}"
    );
    // The evidence: the uninvolved one is reconciled. Without it the test would
    // show only that something is reported.
    assert!(
        seen.contains("harmless"),
        "the uninvolved workload must be reconciled:\n{seen}"
    );
}

/// **An anchor file that does not cover all named nodes is reported.**
///
/// # Why that is the frequent state
///
/// Since ADR-0077 `--control-plane` and `--node-session` take **several**
/// addresses -- and `identity/control-plane.pem` must carry the leaves of **all**
/// these nodes concatenated (ADR-0043). Whoever extends the list and forgets the
/// file gets `UnknownIssuer` for the new node and nothing else: the agent runs,
/// fetches its slices from the covered node -- and stands as soon as the
/// uncovered one leads.
///
/// Both numbers had long stood beside each other in the log (`endpoints = 2,
/// anchors = 1`); an operator had to see the difference themselves.
///
/// # The setup
///
/// **Three** endpoints and **one** anchor: with that endpoints, anchors and
/// shortfall are three different numbers, and an assurance on the shortfall
/// cannot accidentally hit one of the inputs.
///
/// A **self-signed** cluster leaf suffices: the agent counts what
/// `anchors_from_pem` finds in its trust domain -- that a running `tgd` stands
/// behind it is of no consequence for the coverage. That is why this witness
/// needs no process on the other side.
#[test]
fn a_short_anchor_file_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = dir.path().join("identity");
    std::fs::create_dir_all(&identity).expect("directory");

    // The agent's own key.
    let own = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    std::fs::write(identity.join("node.key.pem"), own.serialize_pem()).expect("key");

    // **One** anchor for two named endpoints.
    let domain = tg_identity::TrustDomain::new("cluster.local").expect("domain");
    let cp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let id = tg_identity::SpiffeId::for_node(&domain, "tgd-1").expect("identifier");
    let leaf = tg_identity::cluster::node_leaf_pem(&cp, &id).expect("leaf");
    std::fs::write(identity.join("control-plane.pem"), leaf).expect("anchor");

    let dead = "http://127.0.0.1:1";
    let mut child = Command::new(env!("CARGO_BIN_EXE_tg-agent"))
        .args([
            "--telemetry-addr",
            "off",
            "--data-dir",
            dir.path().to_str().expect("path"),
            "--node",
            "node-1",
            "--control-plane",
            dead,
            "--node-session",
            dead,
            "--node-session",
            "http://127.0.0.1:2",
            "--node-session",
            "http://127.0.0.1:3",
        ])
        .stdout(support::log("tg-agent"))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("tg-agent startable");

    // What is waited for is **exactly** the line that is assured afterwards --
    // otherwise the test runs into its patience and reports an excerpt in which
    // it does not stand yet.
    let log = await_log(&mut child, &["have no anchor"]);
    let _running = Running(child);

    // **With the number, not with a catch-all word.** The first version of this
    // assurance was `contains("2 named") || contains("have no")` -- and the `||`
    // covered an arithmetic error of mine: the shortfall is `endpoints - anchors`,
    // so **two**, not three. That is exactly what three different numbers are in
    // play for here.
    assert!(
        log.contains("2 named control-plane nodes have no anchor"),
        "the shortfall was not called by its name: {log}"
    );
    // **The numbers belong to it**, otherwise an operator does not know how much
    // is missing -- and the file it belongs in.
    assert!(
        log.contains("\"anchors\":1") && log.contains("\"endpoints\":3"),
        "the message does not name the two numbers: {log}"
    );
    assert!(
        log.contains("control-plane.pem"),
        "the message does not name the file: {log}"
    );
}
