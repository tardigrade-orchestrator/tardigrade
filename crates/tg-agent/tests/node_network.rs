//! The node builds its network and answers names (ADR-0012, ADR-0013,
//! ADR-0039 -- phase 9d).
//!
//! The keystone of the wiring: **the ordinal comes from consensus, and at the
//! other end a DNS server answers.** In between lie a join, a subnet, a bridge,
//! an address assignment and a resolver -- and not a single setting of an
//! operator apart from the cluster CIDR.
//!
//! `#[ignore]`, because it demands two processes, `CAP_NET_ADMIN`,
//! `CAP_SYS_ADMIN` and `dig`; run with `cargo xtask net`.
//!
//! The helper functions are the same as in `join.rs`. They stand here once more
//! instead of in a shared module: the two files check different stretches, and a
//! shared setup would be a coupling that later breaks both at once.

use std::path::Path;
use std::process::{Command as OsCommand, Stdio};
use std::time::{Duration, Instant};

use tg_consensus::Command;
use tg_identity::{LocalSigner, TrustDomain};
use tgd::admin::{AdminClient, WriteResult};

mod support;

const PATIENCE: Duration = Duration::from_secs(30);

use support::Running;
/// The path to a binary of the workspace.
///
/// `CARGO_BIN_EXE_*` exists only for the binaries of the **own** package, and
/// this test needs two: `tg-agent` and `tgd`. The second lies as a sibling
/// beside the first -- the same `target/` level, the same run.
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
    // puts the invitation in place. Without it the node does not join -- and
    // without a join it gets no ordinal.
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

/// This test's cluster CIDR -- expressly a different one than in `tg-net`, so
/// that the two suites do not take the addresses from each other.
const CIDR: &str = "10.44.0.0/16";

/// Clears the bridge address away again so that a second run begins cleanly.
struct Cleanup(Vec<String>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for lease in &self.0 {
            if let Ok(address) = lease.parse() {
                let _ = tg_net::link::detach(&tg_net::ipam::host_link(address));
            }
        }
    }
}

/// Asks the node's resolver -- with `dig`, so with foreign code.
fn dig(server: std::net::Ipv4Addr, name: &str) -> String {
    let output = OsCommand::new("dig")
        .args([&format!("@{server}"), "+time=2", "+tries=1", name, "A"])
        .output()
        .expect("dig must be startable");

    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Waits until the resolver answers at all.
fn await_resolver(server: std::net::Ipv4Addr) -> String {
    let deadline = Instant::now() + PATIENCE;
    let mut answer = String::new();
    while Instant::now() < deadline {
        answer = dig(server, "api.tardigrade.internal");
        if answer.contains("status:") {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    answer
}

/// **From consensus to the name.**
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands two processes, CAP_NET_ADMIN/CAP_SYS_ADMIN and dig; via `cargo xtask net`"]
#[allow(clippy::too_many_lines)]
async fn the_node_builds_its_network_from_the_ordinal_and_answers_names() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let _control_plane = Running(
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
                // Three ports (ADR-0043, determination 4), all freely chosen:
                // the defaults would be the same for every test binary.
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
            node: "node-9".to_owned(),
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
                "1",
                "--node",
                "node-9",
                "--control-plane",
                &endpoint,
                "--cluster-cidr",
                CIDR,
            ])
            .env(
                "PATH",
                format!("{}:{path}", agent_dir.path().join("stub").display()),
            )
            .stdout(support::log("tg-agent"))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("tg-agent startable"),
    );

    // 1. The ordinal comes from consensus -- the agent did not bring it along.
    let ordinal_file = agent_dir.path().join("identity").join("ordinal");
    assert!(await_file(&ordinal_file), "the agent got no ordinal");
    let ordinal: u32 = std::fs::read_to_string(&ordinal_file)
        .expect("readable")
        .trim()
        .parse()
        .expect("a number");
    assert_eq!(ordinal, 0, "the first admitted node gets the 0");

    // 2. From it follows the subnet -- computed, not read (ADR-0039).
    let cluster = tg_net::ipam::ClusterNet::new(CIDR.parse().expect("valid"), 24).expect("valid");
    let subnet = cluster.subnet(ordinal).expect("valid");
    let gateway = subnet.gateway();
    assert_eq!(gateway.to_string(), "10.44.0.1");

    // 3. And the address ledger the agent carries locally (ADR-0019).
    let leases_file = agent_dir.path().join("network").join("leases.json");
    assert!(await_file(&leases_file), "no address ledger");
    let table: tg_net::ipam::LeaseTable =
        serde_json::from_str(&std::fs::read_to_string(&leases_file).expect("readable"))
            .expect("readable");
    let api = table
        .leases()
        .iter()
        .find(|lease| lease.workload == "api")
        .expect("'api' has no address");
    let _cleanup = Cleanup(vec![api.address.to_string()]);
    assert!(
        subnet.holds(api.address),
        "{} does not lie in this node's subnet",
        api.address
    );

    // 4. At the other end a DNS server answers -- to `dig`, so to foreign code,
    //    and from this node's registry.
    //
    //    What is checked is the difference between the two negative answers, and
    //    that is the actual statement here: `api` yields **NODATA** -- the name
    //    exists, it has an address, but no healthy instance. A name the node does
    //    not know yields **NXDOMAIN**. Distinguishing the two presupposes that
    //    the address ledger really stands in the resolution.
    //
    //    That `api` does not become healthy is down to the environment and not
    //    to the code: the stub for the runtime cannot pull an image, so nothing
    //    runs. That a **healthy** instance resolves is substantiated in
    //    `tg-net/tests/dns_interop.rs` against `dig`, `host` and glibc.
    let answer = await_resolver(gateway);
    assert!(
        answer.contains("status: NOERROR"),
        "'api' should have yielded NODATA. dig said:\n{answer}"
    );
    assert!(
        answer.contains("ANSWER: 0"),
        "no instance runs, so no address may come out:\n{answer}"
    );
    assert!(
        answer.contains("AUTHORITY: 1"),
        "NODATA without an SOA -- then the negative deadline from ADR-0013 does not apply:\n{answer}"
    );

    // 4b. **A workload on another node resolves** (ADR-0073).
    //
    //     That is the gap that was measured: until then the registry came from
    //     the node-local address ledger alone, and a workload the cluster runs
    //     yielded NXDOMAIN -- while ADR-0011 with `spread="rack"` as the default
    //     distributes exactly there.
    //
    //     The way goes over the file `session::apply` writes from the slice.
    //     Here the test puts it in place, and that is at the same time the
    //     evidence for the fail-static assurance from ADR-0073 determination 6:
    //     the resolution does not hang on a standing session.
    let endpoints = agent_dir.path().join("network").join("endpoints.json");
    std::fs::write(
        &endpoints,
        r#"[{"workload":"foreign","instance":0,"address":"10.44.7.9","healthy":true}]"#,
    )
    .expect("endpoints");

    let mut foreign = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        foreign = dig(gateway, "foreign.tardigrade.internal");
        if foreign.contains("10.44.7.9") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(
        foreign.contains("10.44.7.9"),
        "the foreign endpoint does not resolve. dig said:\n{foreign}"
    );

    // And the counter-check to the health field: an unhealthy foreign endpoint
    // yields **NODATA** and not NXDOMAIN -- the name exists, it just has no
    // healthy instance right now (ADR-0073, determination 4).
    std::fs::write(
        &endpoints,
        r#"[{"workload":"foreign","instance":0,"address":"10.44.7.9","healthy":false}]"#,
    )
    .expect("endpoints");
    let mut sick = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        sick = dig(gateway, "foreign.tardigrade.internal");
        if sick.contains("ANSWER: 0") && sick.contains("status: NOERROR") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(
        sick.contains("status: NOERROR") && sick.contains("ANSWER: 0"),
        "an unhealthy foreign endpoint should have yielded NODATA:\n{sick}"
    );

    // 5. And what the node does not know is NXDOMAIN -- not the same thing.
    let unknown = dig(gateway, "doesnotexist.tardigrade.internal");
    assert!(
        unknown.contains("status: NXDOMAIN"),
        "an unknown name should have yielded NXDOMAIN:\n{unknown}"
    );

    // 6. And nothing outside the zone is answered.
    let outside = dig(gateway, "example.com");
    assert!(
        outside.contains("status: REFUSED"),
        "the node resolver is no open resolver:\n{outside}"
    );
}

/// **The node's rule set is reconciled, not set once** (ADR-0010, ADR-0012).
///
/// Until here it lay exactly once -- at startup. Whoever emptied the table
/// afterwards (an `nft flush ruleset` from any script beside it suffices) got it
/// back only at the agent's next start, and until then the masquerading -- without
/// which no container reaches anything outside the cluster -- and the bridge's
/// shielding were missing.
///
/// This test needs **no cluster**: the ordinal is a file, and the node network
/// demands no more. What it checks is the reconciliation, and that has nothing to
/// do with the join.
///
/// Three assurances, and the first and second carry the third: the rule set
/// **stands** after the start, the deletion **takes hold**, and the node fetches
/// it back. Without the first two the test would show only that a table is there
/// at some point.
#[test]
#[ignore = "demands CAP_NET_ADMIN and nft; cargo xtask net"]
fn the_host_ruleset_comes_back_after_someone_removes_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    agent_node(dir.path(), None, None);
    // In operation the ordinal comes from consensus (ADR-0039). Here the same
    // hand puts it in place that otherwise puts the invitation in place -- what
    // is checked is the reconciliation, not the join.
    let identity = dir.path().join("identity");
    std::fs::create_dir_all(&identity).expect("directory");
    std::fs::write(identity.join("ordinal"), "7\n").expect("ordinal");

    let path = env!("PATH");
    let _agent = Running(
        OsCommand::new(binary("tg-agent"))
            .args([
                "--telemetry-addr",
                "off",
                "--data-dir",
                dir.path().to_str().expect("path"),
                "--interval",
                "1",
                "--identity=false",
                "--cluster-cidr",
                CIDR,
            ])
            .env(
                "PATH",
                format!("{}:{path}", dir.path().join("stub").display()),
            )
            .stdout(support::log("tg-agent"))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("tg-agent startable"),
    );

    assert!(
        await_table(true),
        "the rule set did not stand after the start"
    );

    // **Two rounds, and the second is the statement.** The first can still fall
    // into the run-up: the first pass follows the start immediately, and a test
    // that sees only it does not substantiate the loop. After the first
    // restoration the node is unmistakably in continuous operation -- there it
    // was previously never set again.
    for round in 1..=2 {
        std::process::Command::new("nft")
            .args(["delete", "table", "inet", tg_net::rules::TABLE])
            .status()
            .expect("nft");
        assert!(
            !table_present(),
            "round {round}: the deletion did not take hold -- \
             the test would otherwise prove nothing"
        );

        assert!(
            await_table(true),
            "round {round}: the node did not fetch its rule set back"
        );
    }
}

/// Whether the table stands in the kernel.
fn table_present() -> bool {
    tg_net::nft::list_table(tg_net::rules::FAMILY, tg_net::rules::TABLE).is_ok()
}

/// Waits until the table has the expected state.
fn await_table(present: bool) -> bool {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if table_present() == present {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    false
}
