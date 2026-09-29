//! The rotation of the data key over all six steps (ADR-0100).
//!
//! # Why this witness was necessary
//!
//! ADR-0100 names it itself as an open point: *"No end-to-end witness over the
//! whole rotation. Substantiated are the ring, the container in both situations
//! and the wiring per piece; a run over all steps would need two restarts of
//! `tgd` in the middle of the test."*
//!
//! It is worth it because the rotation is the **only** answer to a compromised
//! data key (ADR-0095) and because two of its steps are waiting points an
//! operator skips. What it substantiates is the assurance that carries the whole
//! procedure: **after the old key is gone, the value can still be opened.**
//! Without the re-keying it would be lost, and the container that needs it would
//! no longer start (ADR-0098, determination 7).
//!
//! # Why it lies here and not with `tgctl`
//!
//! It needs **both** real binaries: `tgd` for the state across two restarts,
//! `tgctl` for the re-keying, which per ADR-0100 determination 1 happens in the
//! client. The test rig for a real `tgd` lies here; copying it over to `tgctl`
//! would be two copies of a discipline, and this tree has just merged four of
//! them into one per crate.

use std::path::Path;
use std::process::Command as OsCommand;
use std::time::Duration;

use tg_identity::secrets::{DataKey, KeyRing};

mod support;
use support::Running;

/// How long the test waits for a node.
const PATIENCE: Duration = Duration::from_secs(30);

/// A node on a **given** data directory.
///
/// Unlike `node()` in the neighbouring files: this directory outlives the
/// restart, and that is exactly the point here.
async fn start(dir: &Path, ports: (u16, u16, u16, u16)) -> Running {
    let (listen, cluster, session, telemetry) = ports;
    let child = OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
        .args([
            // **With** telemetry: `tg_cluster_secrets_previous` is the number
            // that makes a rotation completable (ADR-0100), and two alarm rules
            // hang on it. A fixed default port would be the same for all test
            // binaries -- `free_port` resolves that.
            "--telemetry-addr",
            &format!("127.0.0.1:{telemetry}"),
            "--id",
            "1",
            "--node",
            "tgd-1",
            "--listen",
            &format!("127.0.0.1:{listen}"),
            "--cluster-listen",
            &format!("127.0.0.1:{cluster}"),
            "--node-listen",
            &format!("127.0.0.1:{session}"),
            "--data-dir",
            dir.to_str().expect("path"),
            "--peer",
            &format!("1=http://127.0.0.1:{cluster}"),
            // **`--init` stays at every start**, and that is no oversight:
            // exactly so it stands in a unit file an operator writes once. That
            // the second and third start nevertheless come up is the assurance
            // from ADR-0005 (`InitializeError::NotAllowed` means "already
            // happened") -- this test substantiates it along the way, without
            // having to.
            "--init",
        ])
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    let node = Running(child);

    // **Wait for a connection, not for the file.** `await_file` does not do
    // here: the socket is still there from the previous run, and the test would
    // carry on immediately -- against a node that is not listening yet or has
    // not come up at all. Measured, that was this test's first failure
    // (`Connection refused` on a file that exists).
    let socket = tgd::admin::socket_path(dir, 1);
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        // **`async`, and the reason is measured**: `Handle::block_on` panics in
        // a running runtime (the finding from 9d).
        let reached = match tgd::admin::AdminClient::connect_unix(&socket) {
            Ok(client) => client.status().await.is_ok(),
            Err(_) => false,
        };
        if reached {
            return node;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the node does not answer on its admin socket. Its log stands \
             under `{}`; a child that dies at startup (say `Address already in \
             use`) this loop does not see.",
            support::log_path("tgd").display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `tgctl cluster <args>` against this data directory.
fn tgctl(dir: &Path, args: &[&str]) -> std::process::Output {
    OsCommand::new(support::foreign_binary("tgctl"))
        .arg("--data-dir")
        .arg(dir)
        .arg("cluster")
        .args(args)
        .output()
        .expect("tgctl startable")
}

/// Puts the key ring in place: primary, and optionally the one to be retired.
fn put_keys(dir: &Path, primary: &DataKey, previous: Option<&DataKey>) {
    let identity = dir.join("identity");
    std::fs::create_dir_all(&identity).expect("identity/");
    std::fs::write(
        identity.join(tg_identity::layout::SECRETS_KEY),
        primary.to_base64(),
    )
    .expect("primary");

    let path = identity.join(tg_identity::layout::SECRETS_KEY_PREVIOUS);
    match previous {
        Some(key) => std::fs::write(&path, key.to_base64()).expect("to be retired"),
        None => {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Reads a metric **line by line** from the endpoint.
///
/// With `curl` -- foreign code, the same yardstick as at the other endpoint
/// witnesses; `--max-time` as a fallback, so that a test would rather fail than
/// hang (11b).
///
/// Line by line, not two substrings in the whole document: otherwise it would
/// suffice that the name stands somewhere and the value somewhere else.
async fn await_metric(port: u16, metric: &str, wanted: &str) -> bool {
    let deadline = std::time::Instant::now() + PATIENCE;
    while std::time::Instant::now() < deadline {
        let out = OsCommand::new("curl")
            .args([
                "--silent",
                "--max-time",
                "5",
                &format!("http://127.0.0.1:{port}/metrics"),
            ])
            .output()
            .expect("curl must be startable");
        let body = String::from_utf8_lossy(&out.stdout);
        if body
            .lines()
            .any(|line| line.starts_with(metric) && line.ends_with(wanted))
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    false
}

/// **The whole rotation, and at the end the value is still there.**
///
/// Six steps, as in the operations manual -- and the last one is the statement:
/// after `rm secrets.key.previous` the value must be openable with the **new**
/// key. The counter-check to that is the skipped re-keying; then it is lost.
#[tokio::test(flavor = "multi_thread")]
async fn the_whole_rotation_keeps_the_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ports = (
        support::free_port(),
        support::free_port(),
        support::free_port(),
        support::free_port(),
    );
    support::cluster_material(dir.path(), &[1]);

    let old = DataKey::generate().expect("key");
    let new = DataKey::generate().expect("key");

    // --- Step 0: a node with the old key, one secret in it ---
    put_keys(dir.path(), &old, None);
    let node = start(dir.path(), ports).await;

    let value = dir.path().join("value");
    std::fs::write(&value, b"strictly-secret").expect("value");
    let out = tgctl(
        dir.path(),
        &["secret", "put", "s3-key", value.to_str().expect("path")],
    );
    assert!(out.status.success(), "file: {out:?}");

    // --- Step 1+2: the old one beside it, the new one in its place, restart ---
    drop(node);
    put_keys(dir.path(), &new, Some(&old));
    let node = start(dir.path(), ports).await;

    // The cluster now holds both -- and **exactly for that reason** the value is
    // still readable although it carries the old one (ADR-0100, determination 1).
    let out = tgctl(dir.path(), &["secrets"]);
    assert!(out.status.success(), "enumerate: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("s3-key"),
        "the secret has disappeared: {out:?}"
    );

    // --- Step 4: re-key ---
    let out = tgctl(dir.path(), &["secret", "rekey"]);
    assert!(out.status.success(), "re-key: {out:?}");

    // **And the number that makes the last step completable** (ADR-0100).
    // `tg_cluster_secrets_previous` now says `0`: everything is re-keyed, the key
    // to be retired is still there -- exactly the situation
    // `TardigradeRetiredKeyStillPresent` waits for. And because it is a
    // **number** and not a bit, it distinguishes this situation from the one in
    // which the rotation is still running (`> 0`,
    // `TardigradeRotationStalled`).
    //
    // Refreshed in the scrape (ADR-0088), so it exists only when both keys are
    // there -- the absence of the time series is the third statement: the
    // rotation is through and cleared up.
    assert!(
        await_metric(ports.3, tg_telemetry::names::SECRETS_PREVIOUS, " 0").await,
        "the number of outstanding values is missing -- then two alarm rules \
         stand on a time series that does not exist"
    );

    // --- Step 6: remove the old one, restart ---
    drop(node);
    put_keys(dir.path(), &new, None);
    let _node = start(dir.path(), ports).await;

    // **The carrying assertion**: the value now carries the new key. Checked at
    // the ciphertext itself -- an enumeration would only say that a name stands
    // there, and that would stand there for a value nobody can open any more too.
    let socket = tgd::admin::socket_path(dir.path(), 1);
    let client = tgd::admin::AdminClient::connect_unix(&socket).expect("socket");
    let material = client.rekey_material().await.expect("material");
    let ring = KeyRing::new(new, None);
    assert_eq!(material.secrets.len(), 1, "{material:?}");
    for (name, sealed) in &material.secrets {
        let plain = ring
            .open(sealed)
            .unwrap_or_else(|err| panic!("'{name}' is lost after the rotation: {err}"));
        assert_eq!(plain, b"strictly-secret", "'{name}' has a different value");
    }
}
