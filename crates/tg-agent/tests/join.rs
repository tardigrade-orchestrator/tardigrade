//! The agent fetches its intermediate (ADR-0006, ADR-0037).
//!
//! Two real processes: a `tgd` with a signing CA and a `tg-agent` that gets
//! nothing but an invitation. **No operator puts a certificate in place.** At the
//! end an agent intermediate stands on the agent's disk whose chain carries to
//! the control plane's anchor -- and the way there ran entirely over the network.
//!
//! That is the keystone of ADR-0006: "The server issues every agent a short-lived
//! signing intermediate; the agent mints and rotates the workload SVIDs
//! **locally** from it."

use std::path::Path;
use std::process::Command as OsCommand;
use std::time::{Duration, Instant};

use rustls_pki_types::{CertificateDer, UnixTime};
use tg_consensus::Command;
use tg_identity::{Authority, Ca, Lifetime, LocalSigner, SpiffeId, TrustDomain};
use tgd::admin::{AdminClient, WriteResult};

mod support;

const PATIENCE: Duration = Duration::from_secs(30);

use support::Running;
/// The path to a binary of the workspace.
///
/// `CARGO_BIN_EXE_*` exists only for the binaries of the **own** package, and
/// this test needs two: `tg-agent` and `tgd`. The second lies as a sibling beside
/// the first -- the same `target/` level, the same run.
///
/// If it is missing, that is **said** instead of skipped: a test that signs off
/// silently is one people believe is running.
use support::binary;

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs(),
    )
    .expect("fits")
}

/// A control plane with a signing CA.
/// Puts a data key in place for the control plane (ADR-0095).
///
/// **`tgd` does not create it** -- it comes from an operator
/// (`tgctl secret keygen`), because a `tgd` that created it would create a
/// different one on every node.
fn data_key(dir: &Path) -> String {
    let key = tg_identity::secrets::DataKey::generate()
        .expect("key")
        .to_base64();
    let identity = dir.join("identity");
    std::fs::create_dir_all(&identity).expect("identity/");
    std::fs::write(identity.join("secrets.key"), &key).expect("file the key");

    key
}

fn signing_material(dir: &Path) -> Vec<u8> {
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

/// Creates a node's data directory -- **without** identity material.
fn agent_node(dir: &Path, token: Option<&str>, anchor: Option<&str>) {
    std::fs::create_dir_all(dir.join("desired")).expect("directory");
    std::fs::write(
        dir.join("desired").join("api.xml"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20 </workload>\n\
         </workloads>\n",
    )
    .expect("definition");

    if let Some(token) = token {
        let identity = dir.join("identity");
        std::fs::create_dir_all(&identity).expect("directory");
        std::fs::write(identity.join("join-token"), token).expect("invitation");
    }
    // ADR-0043, determination 3: **the same hand** puts the anchor in place that
    // puts the invitation in place. Without it no join -- the node does not show
    // its token to somebody who merely calls themselves the control plane.
    if let Some(anchor) = anchor {
        let identity = dir.join("identity");
        std::fs::create_dir_all(&identity).expect("directory");
        std::fs::write(identity.join("control-plane.pem"), anchor).expect("anchor");
    }

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

/// Waits until a file is there.
fn await_file(path: &Path) -> bool {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if path.is_file() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    false
}

/// **The keystone:** the agent fetches its intermediate, and the chain carries.
///
/// The test is long because the way is long: two processes, an invitation, a
/// join, a renewal and a verification. Splitting it would mean cutting the
/// stretch into pieces that substantiate nothing individually.
#[allow(clippy::too_many_lines)]
///
/// The agent starts with a data directory in which **only** an invitation lies --
/// no key, no certificate, no anchor. Everything else it fetches.
#[tokio::test]
async fn the_agent_fetches_its_intermediate_and_the_chain_holds() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let anchor = signing_material(cp_dir.path());
    let key = data_key(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let control_plane = Running(
        OsCommand::new(binary("tgd"))
            .args([
                // Without telemetry: `cargo test` runs the test binaries
                // concurrently, and the default port would be the same for all.
                "--telemetry-addr",
                "off",
                "--id",
                "1",
                "--node",
                "tgd-1",
                "--listen",
                &format!("127.0.0.1:{port}"),
                // Three ports (ADR-0043, determination 4), all freely chosen: the
                // defaults would be the same for every test binary.
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

    let endpoint = format!("http://127.0.0.1:{port}");
    let cp_leaf = support::await_leaf(cp_dir.path());
    // Since ADR-0044 admin lies on a Unix socket, not on `--listen`.
    let admin = AdminClient::connect_unix(&tgd::admin::socket_path(cp_dir.path(), 1))
        .expect("admin socket");

    // Wait until the node leads.
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

    // The operator invites -- the only action they take.
    let token = tg_consensus::generate_token();
    let result = admin
        .write(Command::InviteNode {
            node: "node-7".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");
    assert!(
        matches!(
            result,
            WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                ..
            }
        ),
        "{result:?}"
    );

    // The agent gets only the invitation.
    let agent_dir = tempfile::tempdir().expect("tempdir");
    agent_node(agent_dir.path(), Some(&token), Some(&cp_leaf));
    let identity = agent_dir.path().join("identity");
    assert!(
        !identity.join("intermediate.pem").exists(),
        "the agent starts without a certificate"
    );

    let path = env!("PATH");
    let _agent = Running(
        OsCommand::new(binary("tg-agent"))
            .args([
                // Without telemetry: `cargo test` runs the test binaries
                // concurrently, and the default port would be the same for all.
                "--telemetry-addr",
                "off",
                "--data-dir",
                agent_dir.path().to_str().expect("path"),
                "--interval",
                "3600",
                // An address space of its own per test file: `cargo test` runs
                // the test binaries concurrently, and two agents with the same
                // default fought over the bridge address and the resolver port.
                // Fail-soft catches that, but a test that lives off fail-soft no
                // longer checks what it is supposed to check.
                "--cluster-cidr",
                "10.45.0.0/16",
                "--node",
                "node-7",
                "--control-plane",
                &endpoint,
            ])
            .env(
                "PATH",
                format!("{}:{path}", agent_dir.path().join("stub").display()),
            )
            .stdout(support::log("tg-agent"))
            .stderr(support::log("tg-agent"))
            .spawn()
            .expect("tg-agent startable"),
    );

    assert!(
        await_file(&identity.join("intermediate.pem")),
        "the agent did not fetch its intermediate"
    );
    assert!(await_file(&identity.join("bundle.pem")));

    // **And the node SVID expressly does *not* lie there** (ADR-0056).
    //
    // Nobody reads it -- on the cluster transports the node identifies itself
    // with its key (ADR-0043) --, and it carries 15 minutes at a renewal every
    // three hours: on the disk it would be expired 92 % of the time. A
    // certificate an auditor reads as a finding although it is none.
    //
    // The assurance stands here and not merely in the ADR, so that nobody adds
    // the line back as an oversight at the next reading.
    assert!(
        !identity.join("node.svid.pem").exists(),
        "the node SVID lies on the disk -- there it would mostly be expired and \
         is read by nothing (ADR-0056)"
    );

    // **And the data key has travelled along** (ADR-0095, determination 2).
    //
    // It stands in **no** log (determination 1) and goes the same way as
    // `intermediate_pem` -- a private key. That it is **the same** one is the
    // actual assurance: a mere presence this test would get from an agent that
    // creates one itself too, and then it would open nothing `tgctl` has sealed.
    assert!(
        await_file(&identity.join("secrets.key")),
        "the data key did not travel along"
    );
    assert_eq!(
        std::fs::read_to_string(identity.join("secrets.key"))
            .expect("readable")
            .trim(),
        key.trim(),
        "the agent has a **different** key -- then it opens nothing another node \
         has sealed"
    );

    // **And it lies like a secret**, not like a credential.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::metadata(identity.join("secrets.key"))
            .expect("permissions")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the data key is not 0600");
    }

    // **The token is consumed** -- on the agent's disk too.
    assert!(
        !identity.join("join-token").exists(),
        "the invitation still lies there; a secret without a purpose"
    );

    // And now the actual statement: the agent mints from it, and the chain
    // carries to the control plane's anchor.
    let intermediate =
        std::fs::read_to_string(identity.join("intermediate.pem")).expect("intermediate");
    let key = std::fs::read_to_string(identity.join("intermediate.key.pem")).expect("key");

    let domain = TrustDomain::new("cluster.local").expect("domain");
    let agent = Authority::new(
        Ca::from_pem(&intermediate).expect("CA"),
        LocalSigner::from_pem(&key).expect("key"),
        Lifetime::default(),
    )
    .expect("issuer");
    let svid = agent
        .issue(&SpiffeId::for_workload(&domain, "api").expect("ID"), now())
        .expect("SVID");

    let anchor_der = CertificateDer::from(anchor);
    let trust = webpki::anchor_from_trusted_cert(&anchor_der).expect("anchor");
    let leaf_der = CertificateDer::from(svid.certificate_der().to_vec());
    let leaf = webpki::EndEntityCert::try_from(&leaf_der).expect("readable");
    let chain = [CertificateDer::from(
        pem::parse(&intermediate).expect("PEM").into_contents(),
    )];

    leaf.verify_for_usage(
        &[webpki::ring::ED25519],
        &[trust],
        &chain,
        UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(now() + 30).expect("after 1970"),
        )),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .expect("workload SVID -> agent intermediate -> anchor must carry");

    drop(control_plane);
}

/// **Without a control plane what is there stays.**
///
/// An agent that does not reach its control plane throws nothing away and does
/// not abort -- it runs on with what it has (ADR-0019). Here it has nothing, so
/// it does not mint; but it runs.
#[tokio::test]
async fn an_unreachable_control_plane_does_not_stop_the_agent() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Without an anchor: this test checks that the agent runs **without** a
    // control plane, and for that the absence of the anchor is the more honest
    // setup.
    agent_node(dir.path(), Some("a-token-that-arrives-nowhere"), None);

    let path = env!("PATH");
    let agent = Running(
        OsCommand::new(binary("tg-agent"))
            .args([
                // Without telemetry: `cargo test` runs the test binaries
                // concurrently, and the default port would be the same for all.
                "--telemetry-addr",
                "off",
                "--data-dir",
                dir.path().to_str().expect("path"),
                "--interval",
                "3600",
                // An address space of its own per test file: `cargo test` runs
                // the test binaries concurrently, and two agents with the same
                // default fought over the bridge address and the resolver port.
                // Fail-soft catches that, but a test that lives off fail-soft no
                // longer checks what it is supposed to check.
                "--cluster-cidr",
                "10.45.0.0/16",
                "--node",
                "node-7",
                // A port nobody listens at.
                "--control-plane",
                &format!("http://127.0.0.1:{}", support::free_port()),
            ])
            .env(
                "PATH",
                format!("{}:{path}", dir.path().join("stub").display()),
            )
            .stdout(support::log("tg-agent"))
            .stderr(support::log("tg-agent"))
            .spawn()
            .expect("tg-agent startable"),
    );

    // It still runs after a few seconds -- and it has kept the token, for it was
    // never redeemed.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut agent = agent;
    assert!(
        agent.0.try_wait().expect("status").is_none(),
        "the agent gave up instead of trying again later"
    );
    assert!(
        dir.path().join("identity").join("join-token").exists(),
        "a token that was not redeemed must not be consumed"
    );

    // The node key arose all the same: it hangs on nothing foreign, and creating
    // it later would need a second way.
    assert!(dir.path().join("identity").join("node.key.pem").exists());
}

/// **A control plane the node cannot verify does not get its token** (ADR-0043,
/// determination 3).
///
/// The setup is the same as with the successful join, and exactly **one** thing
/// is different: the anchor belongs to a different key. Otherwise a green test
/// would prove only that something did not work.
///
/// What is at stake here is not confidentiality: without this check anybody can
/// pass themselves off as the control plane, accept the join -- and afterwards
/// holds a valid invitation.
#[tokio::test]
async fn a_control_plane_with_a_foreign_anchor_gets_no_token() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let _control_plane = Running(
        OsCommand::new(binary("tgd"))
            .args([
                "--telemetry-addr",
                "off",
                "--id",
                "1",
                "--node",
                "tgd-1",
                "--listen",
                &format!("127.0.0.1:{port}"),
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

    // Wait until the node really listens -- otherwise the test checks only that a
    // connection did not come about.
    let endpoint = format!("http://127.0.0.1:{port}");
    // Since ADR-0044 admin lies on a Unix socket, not on `--listen`.
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

    let token = tg_consensus::generate_token();
    admin
        .write(Command::InviteNode {
            node: "node-7".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");

    // **The one thing that is different:** a leaf with the same name but a
    // foreign key.
    let foreign_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let foreign_id = SpiffeId::for_node(&support::domain(), "tgd-1").expect("ID");
    let foreign_leaf =
        tg_identity::cluster::node_leaf_pem(&foreign_key, &foreign_id).expect("leaf");

    let agent_dir = tempfile::tempdir().expect("tempdir");
    agent_node(agent_dir.path(), Some(&token), Some(&foreign_leaf));

    let path = env!("PATH");
    let _agent = Running(
        OsCommand::new(binary("tg-agent"))
            .args([
                "--telemetry-addr",
                "off",
                "--data-dir",
                agent_dir.path().to_str().expect("path"),
                "--interval",
                "1",
                "--node",
                "node-7",
                "--control-plane",
                &endpoint,
            ])
            .env(
                "PATH",
                format!("{}:{path}", agent_dir.path().join("stub").display()),
            )
            .stdout(support::log("tg-agent"))
            .stderr(support::log("tg-agent"))
            .spawn()
            .expect("tg-agent startable"),
    );

    tokio::time::sleep(Duration::from_secs(4)).await;

    let identity = agent_dir.path().join("identity");
    assert!(
        !identity.join("intermediate.pem").exists(),
        "the agent fetched its intermediate although it could not verify the \
         other side"
    );
    assert!(
        identity.join("join-token").exists(),
        "the token was consumed although the join was not allowed to take place"
    );
}

/// Starts a control plane for this test.
///
/// **Extracted because clippy counts the lines** -- and rightly: the start is
/// mechanics, the statement stands below it.
fn control_plane(dir: &Path, port: u16, cluster_port: u16, session_port: u16) -> Running {
    Running(
        OsCommand::new(binary("tgd"))
            .args([
                "--telemetry-addr",
                "off",
                "--id",
                "1",
                "--node",
                "tgd-1",
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--cluster-listen",
                &format!("127.0.0.1:{cluster_port}"),
                "--node-listen",
                &format!("127.0.0.1:{session_port}"),
                "--data-dir",
                dir.to_str().expect("path"),
                "--peer",
                &format!("1=http://127.0.0.1:{cluster_port}"),
                "--init",
            ])
            .stdout(support::log("tgd"))
            .stderr(support::log("tgd"))
            .spawn()
            .expect("tgd startable"),
    )
}

/// **A lost answer must not lock the node out.**
///
/// The invitation is **consumed** at the `AdmitNode` (ADR-0037: check and
/// consumption in the same apply). If the answer is lost afterwards -- a reset, a
/// restart at the wrong moment --, a token lies at the agent that the cluster has
/// long invalidated. Until here it went on trying the join with it **forever**
/// while the cluster took it for admitted: a node that without `RemoveNode` and a
/// new invitation never gets to a certificate again.
///
/// The way out needs nothing new: our public key **stands** registered in the
/// log, and `renew` proves its possession. Whoever was never admitted does not
/// get through with it either -- the fallback grants nothing the token would not
/// have granted.
///
/// The state is reproduced exactly as it arises: first a successful pass, then
/// the certificate gone and **the same** token back.
#[tokio::test]
async fn a_consumed_invitation_still_yields_a_certificate() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let _control_plane = control_plane(cp_dir.path(), port, cluster_port, session_port);

    let endpoint = format!("http://127.0.0.1:{port}");
    let cp_leaf = support::await_leaf(cp_dir.path());
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

    let token = tg_consensus::generate_token();
    let result = admin
        .write(Command::InviteNode {
            node: "node-8".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");
    assert!(
        matches!(
            result,
            WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                ..
            }
        ),
        "{result:?}"
    );

    let agent_dir = tempfile::tempdir().expect("tempdir");
    agent_node(agent_dir.path(), Some(&token), Some(&cp_leaf));
    let identity = agent_dir.path().join("identity");
    let token_path = identity.join("join-token");

    // A single pass fetches the identity: `start_identity_refresh` calls `fetch`
    // **before** the first sleep, so under `--once` too.
    let once = |dir: &Path| {
        OsCommand::new(binary("tg-agent"))
            .args([
                "--telemetry-addr",
                "off",
                "--once",
                "--data-dir",
                dir.to_str().expect("path"),
                "--cluster-cidr",
                "10.46.0.0/16",
                "--node",
                "node-8",
                "--control-plane",
                &endpoint,
            ])
            .env(
                "PATH",
                format!("{}:{}", dir.join("stub").display(), env!("PATH")),
            )
            .output()
            .expect("tg-agent startable")
    };

    let first = once(agent_dir.path());
    assert!(
        identity.join("intermediate.pem").exists(),
        "the first pass fetched no intermediate: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        !token_path.exists(),
        "the consumed token still lies there -- a secret without a purpose"
    );

    // **The state after a lost answer**: no certificate, and the token the
    // cluster has already invalidated lies there again.
    let before = std::fs::read_to_string(identity.join("intermediate.pem")).expect("readable");
    std::fs::remove_file(identity.join("intermediate.pem")).expect("removable");
    std::fs::write(&token_path, &token).expect("invitation");

    let second = once(agent_dir.path());
    let notes = String::from_utf8_lossy(&second.stderr).into_owned();

    assert!(
        identity.join("intermediate.pem").exists(),
        "the agent no longer got to a certificate -- the consumed token locks it \
         out:\n{notes}"
    );
    let after = std::fs::read_to_string(identity.join("intermediate.pem")).expect("readable");
    assert_ne!(
        before, after,
        "the same certificate -- then it did not come from a new renewal"
    );
    // **The join must have been refused.** Measured, the server says "no open
    // invitation" -- without this assurance the test would be green if it had
    // accepted the invitation a second time, and that would be a finding of its
    // own (ADR-0037: one-time, check and consumption in the same apply).
    assert!(
        notes.contains("join refused") && notes.contains("no open invitation"),
        "the join should have been refused:\n{notes}"
    );
    assert!(
        !token_path.exists(),
        "the worthless token still lies there -- every pass tries the join anew"
    );
}
