//! The agent takes over a freshly fetched intermediate (ADR-0006/0014/0037).
//!
//! The renewal path writes fresh material every three hours into **the same**
//! files the issuing service was built from at startup. If nobody read them a
//! second time, the agent went on minting twelve hours after its start from an
//! expired intermediate -- and **none** of the issued SVIDs would still have been
//! acceptable, because every verifier checks the chain.
//!
//! # Why at the process and not at the socket
//!
//! The workload API socket attests **both** calls, `FetchX509Bundles` too -- a
//! test process runs in no container and rightly gets nothing. What `adopt` does
//! is checked in `tg-identity` at the matter itself (chain, deadline, cache).
//! What remains here is the question only the running process can answer: **does
//! it see the change at all?**
//!
//! The test is **deterministic because the material is read once**:
//! `Material::read` runs before the line "workload API" this test waits for. With
//! two reads it was not -- and the wobble was no test error but a window in the
//! production path into which a renewal write fell.
//!
//! And the counter-direction weighs just as much. A reconciliation that takes
//! over *anyway* with unchanged material empties the cache in every pass and
//! mints every SVID anew every second -- on a node with a handful of workloads a
//! signing load nobody ordered.

use std::io::Read as _;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use support::Running;
use tg_identity::{LocalSigner, TrustDomain, self_signed_ca};

mod support;

const HOUR: i64 = 60 * 60;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("domain")
}

/// Writes an agent intermediate with a given deadline -- as the renewal path
/// from ADR-0037 does it: a fresh certificate, a **fresh key**, the same file
/// names.
fn write_intermediate(dir: &Path, not_after: i64) {
    let identity = dir.join("identity");
    std::fs::create_dir_all(&identity).expect("directory");
    let signer = LocalSigner::generate().expect("key");
    let ca = self_signed_ca(&domain(), &signer, 0, not_after).expect("CA");
    std::fs::write(identity.join("intermediate.pem"), ca.certificate_pem()).expect("certificate");
    std::fs::write(identity.join("intermediate.key.pem"), signer.to_pem()).expect("key");
    std::fs::write(identity.join("bundle.pem"), ca.certificate_pem()).expect("bundle");
}

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

fn node(dir: &Path, not_after: i64) {
    // A workload must be there: without one the issuing service does not come up
    // at all, and then the test would check past its subject.
    let desired = dir.join("desired");
    std::fs::create_dir_all(&desired).expect("directory");
    std::fs::write(
        desired.join("api.xml"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.invalid/api:1\"/>\n\
         \x20 </workload>\n\
         </workloads>\n",
    )
    .expect("definition");
    std::fs::write(desired.join("api.instances"), "0\n").expect("assignment");
    write_intermediate(dir, not_after);
    stub_runtime(dir);
}

#[allow(clippy::zombie_processes)]
fn start(dir: &Path, telemetry: u16) -> Child {
    let path = env!("PATH");
    let addr = if telemetry == 0 {
        "off".to_owned()
    } else {
        format!("127.0.0.1:{telemetry}")
    };
    Command::new(env!("CARGO_BIN_EXE_tg-agent"))
        .args([
            "--telemetry-addr",
            &addr,
            "--data-dir",
            dir.to_str().expect("path"),
            "--interval",
            "1",
        ])
        .env("PATH", format!("{}:{path}", dir.join("stub").display()))
        .stdout(support::log("tg-agent"))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("tg-agent startable")
}

/// Reads along until all needles are there or the patience ends.
fn watch(child: &mut Child) -> std::sync::mpsc::Receiver<String> {
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
    rx
}

/// The name of the metric that carries the deadline.
const METRIC: &str = tg_telemetry::names::INTERMEDIATE_EXPIRES_AT;

/// Asks the telemetry endpoint until the line is there.
///
/// Line by line and for the **value**: the recorder attaches a global `node`
/// label, and a bare `contains` on the name would prove only that the metric
/// exists.
fn scraped(port: u16, metric: &str, value: i64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let body = support::scrape(port);
        if body
            .lines()
            .any(|line| line.starts_with(metric) && line.ends_with(&format!(" {value}")))
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    false
}

fn until(rx: &std::sync::mpsc::Receiver<String>, needle: &str, patience: Duration) -> String {
    let deadline = Instant::now() + patience;
    let mut seen = String::new();
    while Instant::now() < deadline {
        let Ok(text) = rx.recv_timeout(Duration::from_secs(2)) else {
            continue;
        };
        seen = text;
        if seen.contains(needle) {
            return seen;
        }
    }
    seen
}

/// **A fresh intermediate is taken over, together with its deadline.**
///
/// What is assured is not "something happened" but the **number**: the deadline
/// in the log is the expiry of the newly laid certificate. A reconciliation that
/// kept the old material would name the old one.
#[test]
fn a_fresh_intermediate_is_adopted_while_the_agent_runs() {
    let dir = tempfile::tempdir().expect("directory");
    let old = 12 * HOUR;
    let new = 5000 * HOUR;
    node(dir.path(), old);
    let telemetry = support::free_port();

    let mut child = start(dir.path(), telemetry);
    let rx = watch(&mut child);
    let mut running = Running(child);
    // The socket stands before anything is replaced -- otherwise the test would
    // not know whether it is observing a change or the start.
    let seen = until(&rx, "workload API", Duration::from_secs(20));
    assert!(
        seen.contains("workload API"),
        "the agent did not come up: {seen}"
    );
    assert!(
        !seen.contains("taken over"),
        "before the change nothing may have been taken over: {seen}"
    );

    write_intermediate(dir.path(), new);

    // What is waited for is the **second** of the two lines: `refresh` takes the
    // intermediate first and then the anchors, and whoever waits for the first
    // may not have read the second yet.
    let seen = until(&rx, "trust anchors taken over", Duration::from_secs(30));
    assert!(
        seen.contains("agent intermediate taken over"),
        "the fresh intermediate was not taken over: {seen}"
    );
    assert!(
        seen.contains(&format!("\"until\":{new}")),
        "the deadline must be that of the new certificate ({new}): {seen}"
    );
    assert!(
        seen.contains("trust anchors taken over"),
        "the anchors lie in the same round and must move along: {seen}"
    );

    // **And the operator sees it.** Without this metric a node whose renewal has
    // been failing for hours is indistinguishable from a healthy one from the
    // outside -- until it stops minting and all this node's workloads fail at
    // once.
    assert!(
        scraped(telemetry, METRIC, new),
        "the deadline must come out as a metric"
    );

    let _ = running.0.kill();
}

/// **And unchanged material is not taken over again.**
///
/// The counter-check to the first assurance, and it does not stand there for
/// symmetry's sake: one takeover per pass would empty the cache every second and
/// mint every SVID anew. That would be silent from the outside -- and expensive.
#[test]
fn unchanged_material_is_not_adopted_again() {
    let dir = tempfile::tempdir().expect("directory");
    node(dir.path(), 12 * HOUR);

    let mut child = start(dir.path(), 0);
    let rx = watch(&mut child);
    let mut running = Running(child);
    let seen = until(&rx, "workload API", Duration::from_secs(20));
    assert!(
        seen.contains("workload API"),
        "the agent did not come up: {seen}"
    );

    // Enough passes that one takeover per round would not be missable.
    let seen = until(&rx, "\u{0}never", Duration::from_secs(6));

    assert!(
        !seen.contains("taken over"),
        "without a change nothing may be taken over: {seen}"
    );

    let _ = running.0.kill();
}

/// **The agent reports its data key's fingerprint** (ADR-0100).
///
/// The metric is named like `tgd`'s, and only both together answer the question
/// that matters before a `rekey`: **does every node carry the new primary key?**
/// As long as an agent does not have it, it does not open the newly sealed
/// values -- running containers stay untouched, but every **start** of a
/// container with secrets fails (ADR-0098, determination 7).
///
/// What is checked is the **label** and not the presence of the line: a
/// fingerprint belonging to a different key would be a false all-clear. And the
/// counter-direction stands before it -- **without** a key no time series, for an
/// invented one would look like agreement.
#[test]
fn the_agent_reports_its_data_key_fingerprint() {
    let dir = tempfile::tempdir().expect("directory");
    node(dir.path(), 12 * HOUR);
    let telemetry = support::free_port();

    // Without a key: the time series must not arise.
    let mut child = start(dir.path(), telemetry);
    let mut running = Running(child);
    assert!(
        !scraped_any(telemetry, tg_telemetry::names::DATA_KEY),
        "without a data key no fingerprint may be reported"
    );
    drop(running);

    // And with one: the fingerprint is that of the key lying there.
    let key = tg_identity::secrets::DataKey::generate().expect("key");
    let identity = dir.path().join(tg_identity::layout::DIR);
    std::fs::create_dir_all(&identity).expect("directory");
    std::fs::write(
        identity.join(tg_identity::layout::SECRETS_KEY),
        key.to_base64(),
    )
    .expect("file it");

    let telemetry = support::free_port();
    child = start(dir.path(), telemetry);
    running = Running(child);
    assert!(
        scraped_label(telemetry, tg_telemetry::names::DATA_KEY, &key.fingerprint()),
        "the reported fingerprint must be that of the filed key"
    );
    drop(running);
}

/// **The agent reports its protocol version** (ADR-0072).
///
/// It is named like `tgd`'s, and only both together answer the question that
/// matters in the maintenance window: **does everyone already speak the same
/// version?** Until here it was unanswerable -- in the window every agent is
/// quiet, so a forgotten one looks like a waiting one, and every statement over
/// the session would be exactly the one the skew breaks.
///
/// What is checked is the **value** and not the presence of the line: the number
/// is the whole statement, and it must be the one the manual guard counts.
#[test]
fn the_agent_reports_its_protocol_version() {
    let dir = tempfile::tempdir().expect("directory");
    node(dir.path(), 12 * HOUR);
    let telemetry = support::free_port();

    let running = Running(start(dir.path(), telemetry));
    let fields = i64::from(tg_store::session::PROTOCOL_FIELDS);
    assert!(
        scraped(telemetry, tg_telemetry::names::PROTOCOL_FIELDS, fields),
        "the agent does not report its protocol version -- then in the \
         maintenance window a forgotten node is indistinguishable from a \
         waiting one (ADR-0072)"
    );
    drop(running);
}

/// Whether the metric appears at all.
fn scraped_any(port: u16, metric: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        let body = support::scrape(port);
        if body.lines().any(|line| line.starts_with(metric)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Whether the metric appears with this label.
fn scraped_label(port: u16, metric: &str, label: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let body = support::scrape(port);
        if body
            .lines()
            .any(|line| line.starts_with(metric) && line.contains(label))
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}
