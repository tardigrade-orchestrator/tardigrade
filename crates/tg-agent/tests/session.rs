//! The way from the control plane to the node (ADR-0040).
//!
//! The agent starts with a data directory in which **no** workload stands -- only
//! an invitation. At the end a definition lies there it never got, and a
//! `may_talk` edge nobody ever wrote there.
//!
//! That is the test three stopgaps have held open since phase 8b. It checks the
//! stretch and not its parts: the slice is cut in `tg-store` and checked there,
//! the stream here.
//!
//! It starts two processes and runs in the normal suite all the same -- like
//! `join.rs`, and for the same reason: it needs no privileges, only the two
//! binaries.

use std::path::Path;
use std::process::{Command as OsCommand, Stdio};
use std::time::{Duration, Instant};
use tg_model::egress::Transport;

use tg_consensus::Command;
use tgd::admin::{AdminClient, WriteResult};

mod support;

/// How long a test waits for an effect **before** it declares it absent.
///
/// Computed from the mechanism and not guessed: several tests here wait for a
/// **wake-up**, and that has the lower bound of five seconds from ADR-0042; the
/// rotation test waits for two of them, plus renewal rounds and slices. At idle
/// that is around ten seconds.
///
/// Thirty seconds would thereby let the **load** decide: in the full workspace
/// run these tests occasionally failed with a timeout -- that was the unexplained
/// wobble from the build for ADR-0055. Not repeated until green, but the deadline
/// chosen so that a loaded machine does not determine it.
///
/// The price is named: a really broken test now needs two minutes to say so. That
/// is better than one that is sometimes right.
const PATIENCE: Duration = Duration::from_mins(2);

use support::Running;
/// The path to a binary of the workspace.
///
/// `CARGO_BIN_EXE_*` exists only for the binaries of the **own** package, and
/// this test needs two: `tg-agent` and `tgd`. The second lies as a sibling beside
/// the first -- the same `target/` level, the same run.
///
/// If it is missing, that is **said** instead of skipped: a test that signs off
/// silently is one people believe is running.
///
/// # That it is **stale** nobody notices here
///
/// `cargo test -p tg-agent` does **not** rebuild `tgd` -- it does rebuild the
/// library beside it, because this test uses it. So whoever changes something in
/// `tgd` and tests only this package checks against the old control plane, and it
/// looks perfectly normal.
///
/// That is expensive with a **counter-check**: it was green once although the
/// checked path was switched off -- the proof applied to a binary that no longer
/// existed in that form. Before a counter-check a `cargo build --workspace`
/// therefore belongs.
///
/// A comparison of the timestamps would not catch it reliably: in a shared run
/// the order of the two targets is not fixed, and a tolerance on it would be
/// exactly the sort of seam wobbling tests arise from.
use support::binary;
use support::{agent_cluster_material, now, signing_material};

/// A data directory **without** a workload -- only the invitation.
fn bare_node(dir: &Path, token: &str) {
    std::fs::create_dir_all(dir.join("desired")).expect("directory");
    let identity = dir.join("identity");
    std::fs::create_dir_all(&identity).expect("directory");
    std::fs::write(identity.join("join-token"), token).expect("invitation");

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

/// Two workloads: `api` runs on the node, `ledger` is only the target of the
/// edge -- it runs elsewhere and must not appear in the slice.
fn definition(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"{name}\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/{name}:1.0\"/>\n\
         \x20 </workload>\n\
         </workloads>\n"
    )
}

/// Waits until a file has content that fits.
fn await_content(path: &Path, wanted: &str) -> String {
    let deadline = Instant::now() + PATIENCE;
    let mut seen = String::new();
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(path) {
            seen = text;
            if seen.contains(wanted) {
                return seen;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    seen
}

/// **The slice comes from consensus onto the node's disk.**
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_node_learns_its_workloads_and_edges_from_the_control_plane() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();
    // **With** telemetry, unlike the neighbours: this witness reads
    // `tg_node_isolated_entries` at the endpoint (ADR-0062, determination 6). A
    // fixed default port would be the same for all test binaries -- `free_port`
    // solves that, as with the generation witness further below.
    let telemetry_port = support::free_port();

    let _control_plane = Running(
        OsCommand::new(binary("tgd"))
            .args([
                "--telemetry-addr",
                &format!("127.0.0.1:{telemetry_port}"),
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
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
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

    // The agent directory arises here, because the cluster material belongs into
    // it before the admission.
    let agent_dir = tempfile::tempdir().expect("tempdir");

    // ADR-0043: without admission no session. The node comes into the trust list
    // with its key, otherwise the port refuses it.
    let spki = agent_cluster_material(agent_dir.path(), cp_dir.path());
    for command in [
        Command::InviteNode {
            node: "node-11".to_owned(),
            digest: tg_consensus::token_digest("whatever-the-test-does-not-redeem"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-11".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
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
            "the admission must get through: {result:?}"
        );
    }

    // The operator enters: node, network parameters, workload, edge, placement.
    for command in [
        Command::UpsertNode {
            name: "node-11".to_owned(),
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
            cidr: "10.99.0.0/16".to_owned(),
            node_prefix: 24,
        },
        Command::UpsertWorkload {
            document: definition("api"),
        },
        Command::UpsertWorkload {
            document: definition("ledger"),
        },
        Command::UpsertWorkload {
            document: single_writer("journal"),
        },
        Command::AllowTraffic {
            from: "api".to_owned(),
            to: "ledger".to_owned(),
        },
        Command::AllowEgress {
            workload: "api".to_owned(),
            host: "s3.example.com".to_owned(),
            port: 443,
            transport: Transport::Tcp,
        },
        // The same name and port over **quic** (ADR-0092). Without it the test
        // would show only that the default gets through -- and a writer that does
        // not know the fourth word at all would be green too.
        Command::AllowEgress {
            workload: "api".to_owned(),
            host: "s3.example.com".to_owned(),
            port: 443,
            transport: Transport::Quic,
        },
        // And **plain UDP** (ADR-0092, determination 5) -- the third transport,
        // for which the sidecar does nothing and the agent lays one nftables rule
        // per resolved address. It must be able to read the line all the same: an
        // `Err` would turn a UDP permission into the loss of this workload's whole
        // egress.
        Command::AllowEgress {
            workload: "api".to_owned(),
            host: "ntp.example.com".to_owned(),
            port: 123,
            transport: Transport::Udp,
        },
        Command::AssignPlacement {
            workload: "api".to_owned(),
            instance: 0,
            node: "node-11".to_owned(),
        },
        // The single writer whose active role the leader grants of its own accord
        // as soon as this node reports (ADR-0064).
        Command::AssignPlacement {
            workload: "journal".to_owned(),
            instance: 0,
            node: "node-11".to_owned(),
        },
        // A **second** instance of the same workload onto the same node. Until the
        // instance distinction its number fell on the floor in the agent: the
        // reconciler worked per name, so one container ran.
        Command::AssignPlacement {
            workload: "api".to_owned(),
            instance: 1,
            node: "node-11".to_owned(),
        },
    ] {
        // **Not** only `Applied`: the variant encloses a rejection too. This
        // test's first attempt was therefore green although the placement was
        // refused with `UnknownNode` -- and the slice arrived empty.
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }

    let token = tg_consensus::generate_token();
    let result = admin
        .write(Command::InviteNode {
            node: "node-11".to_owned(),
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

    // The agent knows only the invitation. No workload, no edge.
    bare_node(agent_dir.path(), &token);
    assert!(
        std::fs::read_dir(agent_dir.path().join("desired"))
            .expect("readable")
            .next()
            .is_none(),
        "the agent starts without a wanted workload"
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
                "1",
                // An address space of its own per test file: `cargo test` runs the
                // test binaries concurrently, and two agents with the same default
                // fought over the bridge address and the resolver port. Fail-soft
                // catches that, but a test that lives off fail-soft no longer
                // checks what it is supposed to check.
                "--cluster-cidr",
                "10.46.0.0/16",
                "--node",
                "node-11",
                "--control-plane",
                &endpoint,
                "--node-session",
                &session_endpoint,
                // **With mapping** (ADR-0091), so that step 8 has something to
                // see. It demands a capable runtime, otherwise the agent does not
                // start -- that is why `/usr/local/bin` drops out of the `PATH`
                // just below.
                "--userns-base",
                "100000",
            ])
            .env(
                "PATH",
                // **Without `/usr/local/bin`**, and that is no trick but the
                // prerequisite from ADR-0091: youki lies there, and with youki the
                // agent refuses to start. The rest it needs (`nft`, `ip`, ...)
                // lies in `/usr/bin`.
                format!(
                    "{}:{}",
                    agent_dir.path().join("stub").display(),
                    path.split(':')
                        .filter(|dir| *dir != "/usr/local/bin")
                        .collect::<Vec<_>>()
                        .join(":")
                ),
            )
            .stdout(support::log("tg-agent"))
            .stderr(support::log("tg-agent"))
            .spawn()
            .expect("tg-agent startable"),
    );

    // 1. The definition it never got.
    let definition = await_content(&agent_dir.path().join("desired").join("api.xml"), "api");
    assert!(
        definition.contains("registry.example.com/api:1.0"),
        "the definition did not arrive: '{definition}'"
    );

    // 1b. And **which instances** shall run here. The document belongs to the
    //     workload, the assignment to this node (ADR-0034) -- until the instance
    //     distinction the number fell on the floor, and a workload with two
    //     instances ran with one container.
    let assignment = await_content(&agent_dir.path().join("desired").join("api.instances"), "0");
    let mut numbers: Vec<&str> = assignment.split_whitespace().collect();
    numbers.sort_unstable();
    assert_eq!(
        numbers,
        vec!["0", "1"],
        "the assignment does not name both instances: '{assignment}'"
    );

    // 2. The edge nobody ever wrote there -- in the sidecar's format (ADR-0025,
    //    phase 8b).
    let edges = await_content(
        &agent_dir.path().join("network").join("may-talk"),
        "api -> ledger",
    );
    assert!(edges.contains("api -> ledger"), "edges: '{edges}'");
    //    And the counter-check to the contract, the same as with the egress
    //    below: what the agent wrote is read by the **sidecar**. A `contains`
    //    says that the text occurs -- not that an edge becomes of it. And more
    //    hangs on it here: `edges_from_text` gives `Err` for the **whole file**
    //    when one line does not fit. A format change would thereby mean
    //    deny-by-default for every workload of this node (ADR-0025) -- and a
    //    witness that checks only the text would stay green.
    assert_eq!(
        tg_proxy::options::edges_from_text(&edges).expect("the sidecar reads them"),
        vec![("api".to_owned(), "ledger".to_owned())],
        "agent and sidecar do not agree about the edge"
    );

    // 3. The egress permission (ADR-0041) -- in the format the sidecar reads. It
    //    stands **with the workload name** in the line: several run on one node,
    //    and every sidecar filters its own out.
    let egress = await_content(
        &agent_dir.path().join("network").join("egress"),
        "s3.example.com",
    );
    assert!(
        egress.contains("api s3.example.com 443 tcp"),
        "egress: '{egress}'"
    );
    //    **The transport travels along** (ADR-0092), and the line is the contract
    //    between agent and sidecar: the sidecar does not hang on `tg-model`, so
    //    the enum exists twice, and only a run like this one nails down that both
    //    sides mean the same word.
    assert!(
        egress.contains("api s3.example.com 443 quic"),
        "the transport did not survive the slice: '{egress}'"
    );
    assert!(
        egress.contains("api ntp.example.com 123 udp"),
        "the address-based permission did not survive the slice: '{egress}'"
    );

    //    And the counter-check to the contract: what the agent wrote is read by
    //    the **sidecar** -- with its own parser, from its own enum.
    let read = tg_proxy::options::egress_from_text(&egress, "api").expect("the sidecar reads them");
    assert_eq!(
        read,
        // **Sorted by name**, as the slice carries them -- not in the order in
        // which they were permitted.
        vec![
            (
                "ntp.example.com".to_owned(),
                123,
                tg_proxy::egress::Transport::Udp
            ),
            (
                "s3.example.com".to_owned(),
                443,
                tg_proxy::egress::Transport::Tcp
            ),
            (
                "s3.example.com".to_owned(),
                443,
                tg_proxy::egress::Transport::Quic
            ),
        ],
        "agent and sidecar do not agree about the line"
    );

    // 3b. The **active role** (ADR-0066), and it is the evidence over the whole
    //     chain: nobody issued a lease. The leader granted it of its own accord,
    //     because `journal` is a single writer and this node reports (ADR-0064)
    //     -- then the slice carries it, and the agent writes it into the format
    //     the sidecar reads.
    let roles = await_content(
        &agent_dir.path().join("network").join("active-role"),
        "journal ",
    );
    //     It is read with the **sidecar's** reader and not with a rebuilt one:
    //     one stood here once, and a comment beside it claimed "the sidecar reads
    //     exactly this format" -- that was not checked. The contract is the
    //     **line** (the sidecar does not hang on `tg-model`), and a contract holds
    //     only when a run sees both sides.
    let read = tg_proxy::role::Roles::from_text(&roles);
    //     `role_of` with the clock says both in one: the line parses, **and** the
    //     deadline lies in the future -- otherwise the sidecar would have a role
    //     that has already expired, and the test would prove nothing.
    let tg_proxy::role::ActiveRole::Active { epoch: _epoch } =
        read.role_of("journal", tg_proxy::role::now_millis())
    else {
        panic!("the sidecar reads no valid active role: '{roles}'");
    };
    //     The epoch is **read and not judged**: it is a cluster-wide counter that
    //     begins at zero (`ClusterState::next_epoch`) -- an assurance `>= 1` would
    //     be an assumption about it and not about this stretch.
    //
    //     And the counter-direction, **over the absence of the entry**: a
    //     `role_of` would give `Passive` for `api` even if it stood there with an
    //     expired deadline.
    assert_eq!(
        read.expires_at("api"),
        None,
        "only single writers get an active role (ADR-0064, D8): '{roles}'"
    );

    // 4. The network parameters -- cluster-wide one source instead of one setting
    //    per node (open point from 9d).
    let network = await_content(
        &agent_dir.path().join("network").join("cluster.json"),
        "10.99.0.0/16",
    );
    assert!(
        network.contains("\"node_prefix\":24"),
        "network: '{network}'"
    );

    // 5. And the progress mark, without which there is no monotonicity.
    let applied = await_content(&agent_dir.path().join("network").join("applied"), "");
    let index: u64 = applied.trim().parse().expect("a number");
    assert!(index > 0, "the slice index is missing");

    // 6. **And the leader knows it** (ADR-0040). The number has stood in every
    //    report since that ADR and was read by **nobody** -- it is the one at
    //    which a node stands out that gets slices and does not apply them: its
    //    report keeps coming, so `tg_node_last_report` says something fresh while
    //    this number stands still.
    //
    //    The test stands **here** and not in `tgctl`: that test rig provides the
    //    admin service and cannot see the seam `absorb` at all.
    //    **The abort condition is the assurance.** A node's first report comes
    //    before it has applied anything -- `0` stands there, and the leader takes
    //    it in. Whoever waits for `Some(_)` and afterwards assures `> 0` aborts at
    //    exactly this zero: measured as a wobble in the workspace run, green in
    //    the individual run.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let reported = loop {
        if let Ok(view) = admin.projection().await
            && let Some(node) = view.nodes.iter().find(|node| node.name == "node-11")
            && let Some(slice) = node.applied_slice
            && slice > 0
        {
            break slice;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the leader never learned the applied slice"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert!(
        reported > 0,
        "the reported slice is zero although the node applied {index}"
    );

    // 7. **And a broken declaration reaches the cluster** (ADR-0062,
    //    determination 6). The node reports it per pass into its log; without the
    //    way here it would only be found there, and the leader reads "never seen"
    //    for the workload -- the same as with a node that has never reported.
    //
    //    **The cluster must carry the isolation, not the disk.** A file damaged
    //    by hand stood here with the rationale "the log rests" -- measured it does
    //    **not** rest: the lease renewals for `journal` move it every few seconds
    //    (ADR-0064), the next slice wrote `api.xml` back, and the isolation was
    //    gone. The test was thereby a race against the self-healing from ADR-0062
    //    -- and lost it in the workspace run.
    //
    //    Deterministic is a document the **cluster** accepts and the node cannot
    //    classify: a self-reference. The state machine builds no graph (it cannot:
    //    an upsert carries one workload, the set is complete only at the end), so
    //    it gets through -- and the node isolates it anew at every pass.
    for command in [
        Command::UpsertWorkload {
            document: self_referencing("circle"),
        },
        Command::AssignPlacement {
            workload: "circle".to_owned(),
            instance: 0,
            node: "node-11".to_owned(),
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    let isolated = loop {
        if let Ok(view) = admin.projection().await
            && let Some(node) = view.nodes.iter().find(|node| node.name == "node-11")
            && !node.isolated.is_empty()
        {
            break node.isolated.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the leader never learned of the broken declaration"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        isolated,
        vec!["circle".to_owned()],
        "exactly the damaged entry must be reported"
    );

    // **And the metric says it too** (ADR-0062, determination 6). The list above
    // is the way into `tgctl cluster nodes`; `tg_node_isolated_entries` is the way
    // to the alarm rule (`TardigradeBrokenDeclaration`) -- and a rule on a metric
    // nobody sets fires **never**. The same silent kind of failure this tree has
    // measured three times at `docs/alerts.yml`.
    //
    // The label is the **observed** node and not the reporting process: the rule
    // for that stands in `tg_telemetry::names`, and the local label wins against
    // the global one.
    assert!(
        await_metric(
            telemetry_port,
            tg_telemetry::names::NODE_ISOLATED,
            "node=\"node-11\"} 1",
        )
        .await,
        "the metric does not report the isolated entry -- then the alarm rule \
         stands on a time series that does not exist"
    );

    // 8. **And whether this node maps container identifiers** (ADR-0091).
    //
    //    `--userns-base` is a setting per node, and nobody would otherwise see a
    //    skew -- the same situation as with the proxy image (ADR-0059) and with
    //    the DNS zone (ADR-0013). What hangs on it weighs more, though: on a node
    //    without a mapping `uid 0` in the container **is** `uid 0` on the node.
    //
    //    The witness stands **here** and not in `tgctl`: there the test rig
    //    provides the admin service and cannot see the seam `absorb` at all.
    //    Measured, exactly this line was unguarded -- an `absorb` that inserts
    //    `None` turned every hardened node into an unhardened one, and the metric
    //    reported a false all-clear.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(view) = admin.projection().await
            && let Some(node) = view.nodes.iter().find(|node| node.name == "node-11")
            && node.userns.is_some()
        {
            assert_eq!(
                node.userns,
                Some(100_000),
                "the leader learned a different range than the node runs"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the leader never learned of the mapping"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// **A workload the slice no longer names disappears.**
///
/// Expressly from the **content** of a message that arrived, never from the
/// absence of messages (ADR-0040, determination 6).
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_workload_removed_from_the_slice_leaves_the_cache() {
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
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
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

    // The agent directory arises here, because the cluster material belongs into
    // it before the admission.
    let agent_dir = tempfile::tempdir().expect("tempdir");

    // ADR-0043: without admission no session. The node comes into the trust list
    // with its key, otherwise the port refuses it.
    let spki = agent_cluster_material(agent_dir.path(), cp_dir.path());
    for command in [
        Command::InviteNode {
            node: "node-11".to_owned(),
            digest: tg_consensus::token_digest("whatever-the-test-does-not-redeem"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-11".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
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
            "the admission must get through: {result:?}"
        );
    }

    for command in [
        Command::UpsertNode {
            name: "node-12".to_owned(),
            topology: tg_consensus::Topology {
                site: "s".to_owned(),
                hall: "h".to_owned(),
                rack: "r".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
        Command::UpsertWorkload {
            document: definition("api"),
        },
        Command::AssignPlacement {
            workload: "api".to_owned(),
            instance: 0,
            node: "node-12".to_owned(),
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }

    let token = tg_consensus::generate_token();
    admin
        .write(Command::InviteNode {
            node: "node-12".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");

    bare_node(agent_dir.path(), &token);

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
                // An address space of its own per test file: `cargo test` runs the
                // test binaries concurrently, and two agents with the same default
                // fought over the bridge address and the resolver port. Fail-soft
                // catches that, but a test that lives off fail-soft no longer
                // checks what it is supposed to check.
                "--cluster-cidr",
                "10.46.0.0/16",
                "--node",
                "node-12",
                "--control-plane",
                &endpoint,
                "--node-session",
                &session_endpoint,
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

    let definition = agent_dir.path().join("desired").join("api.xml");
    assert!(
        !await_content(&definition, "api").is_empty(),
        "the workload never arrived"
    );

    // The operator withdraws the workload.
    //
    // **Not** the placement: the scheduler in `tgd` places a wanted workload
    // again at once, and that is right (ADR-0011). This test's first attempt
    // tested against that property and thereby proved only that it works.
    let result = admin
        .write(Command::RemoveWorkload {
            name: "api".to_owned(),
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
        "the withdrawal was not applied: {result:?}"
    );

    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if !definition.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("the workload still lies in the cache although the slice no longer names it");
}

/// **A deletion reaches the node's disk** (ADR-0027, ADR-0042).
///
/// The way there is the whole point: the command stands in the log, the state
/// leaves a **tombstone**, the slice carries it -- and the agent executes it.
/// Without the tombstone there would be nothing to carry: the slice is a snapshot
/// of the desired state and no event.
///
/// Expressly **not** checked is whether a volume disappears because its workload
/// leaves the node. That must not happen (ADR-0027), and the test beside it nails
/// it down.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_deletion_reaches_the_disk_of_the_node() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
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

    // The agent directory arises here, because the cluster material belongs into
    // it before the admission.
    let agent_dir = tempfile::tempdir().expect("tempdir");

    // ADR-0043: without admission no session. The node comes into the trust list
    // with its key, otherwise the port refuses it.
    let spki = agent_cluster_material(agent_dir.path(), cp_dir.path());
    for command in [
        Command::InviteNode {
            node: "node-11".to_owned(),
            digest: tg_consensus::token_digest("whatever-the-test-does-not-redeem"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-11".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
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
            "the admission must get through: {result:?}"
        );
    }

    for command in [
        Command::UpsertNode {
            name: "node-13".to_owned(),
            topology: tg_consensus::Topology {
                site: "s".to_owned(),
                hall: "h".to_owned(),
                rack: "r".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
        Command::UpsertWorkload {
            document: definition("api"),
        },
        Command::AssignPlacement {
            workload: "api".to_owned(),
            instance: 0,
            node: "node-13".to_owned(),
        },
        // Nobody declares 'old-stock' -- it is a volume left over from a withdrawn
        // workload. Exactly the case for which ADR-0027 provides the express
        // command.
        Command::DeleteVolume {
            volume: "old-stock".to_owned(),
            node: "node-13".to_owned(),
            at: now(),
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }

    let token = tg_consensus::generate_token();
    admin
        .write(Command::InviteNode {
            node: "node-13".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");

    bare_node(agent_dir.path(), &token);

    // The volume lies there before the agent starts -- otherwise the test checks
    // only that nothing happens.
    //
    // `declare` and not `provision`: what is checked is the **way** -- log,
    // tombstone, slice, agent --, not ext4. An `mkfs.ext4` in a session test would
    // need tools that have nothing to do with the matter, and would let the test
    // fail at their absence instead of at its subject.
    let store = tg_runtime::volume::VolumeStore::open(agent_dir.path()).expect("store");
    store
        .declare("old-stock", tg_runtime::volume::MIN_BYTES)
        .expect("create");
    assert!(store.exists("old-stock"), "the volume was not created");

    let _agent = agent(agent_dir.path(), "node-13", port, session_port);

    // The slice arrives -- everything further hangs on it, and that is why it is
    // **assured**: `await_content` does not panic on a timeout. Without the line
    // the waiting loop below would catch the same case, but with the wrong cause
    // ("the deletion did not reach the node") -- and after twice the waiting time.
    let desired = await_content(&agent_dir.path().join("desired").join("api.xml"), "api");
    assert!(
        desired.contains("api"),
        "the slice did not arrive: '{desired}'"
    );

    let deadline = Instant::now() + PATIENCE;
    loop {
        assert!(
            Instant::now() < deadline,
            "the volume still lies there -- the deletion did not reach the node"
        );
        if !store.exists("old-stock") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // **And the instruction is cleared away** (ADR-0104).
    //
    // The second half of the same stretch, and without it the tombstone would stay
    // standing **forever**: the only other way on which it disappears is a renewed
    // declaration of the same volume -- and there is none here. It would thereby
    // stand in every snapshot and in every slice to this node.
    //
    // The way: the node asks its volume store, reports the execution as observed
    // state (ADR-0040 determination 7), and the **leader** makes a
    // `RetireTombstone` of it -- the same construction as with the capacity
    // (ADR-0049) and the lease renewal (ADR-0064).
    let deadline = Instant::now() + PATIENCE;
    loop {
        let volumes = admin.volumes().await.expect("call");
        if volumes.tombstones.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the tombstone still stands: {:?} -- the execution did not reach the leader",
            volumes.tombstones
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// **The snapshot decree reaches the node's disk** (ADR-0099).
///
/// The stretch no other witness covers: `SnapshotVolume` -> log -> `view_of` ->
/// `slice_for` -> slice -> the order file -> the reconciler -> file. The state
/// machine, the slice filter and the copy itself are each checked individually;
/// **that they hang together** is said only by a run.
///
/// Since ADR-0110 the execution lies in the **reconciler** and no longer in the
/// session's arm; the witness is untouched by that because it checks the
/// **effect** -- the file and its content -- and not the call.
///
/// What is assured is the snapshot's **content** and not its presence: an empty
/// file in the right place would pass every assurance about paths.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_snapshot_verdict_reaches_the_disk_of_the_node() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
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
    let spki = agent_cluster_material(agent_dir.path(), cp_dir.path());
    for command in [
        Command::InviteNode {
            node: "node-11".to_owned(),
            digest: tg_consensus::token_digest("whatever-the-test-does-not-redeem"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-11".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
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
            "the admission must get through: {result:?}"
        );
    }

    let token = tg_consensus::generate_token();
    for command in [
        Command::UpsertWorkload {
            document: definition("api"),
        },
        Command::InviteNode {
            node: "node-13".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }

    bare_node(agent_dir.path(), &token);

    // The volume lies there before the agent starts -- with a recognizable
    // content. `declare` and an image by hand instead of `provision`: what is
    // checked is the **way**, not ext4 (the same choice as with the deletion
    // witness beside it, and the snapshot is a file copy anyway).
    let store = tg_runtime::volume::VolumeStore::open(agent_dir.path()).expect("store");
    store
        .declare("old-stock", tg_runtime::volume::MIN_BYTES)
        .expect("create");
    let image = store.image_of("old-stock").expect("path");
    std::fs::write(&image, b"the state of back then").expect("image");

    // **The admission must lie before the decree**: `SnapshotVolume` refuses a
    // node the cluster does not know (ADR-0099).
    let result = admin
        .write(Command::AdmitNode {
            node: "node-13".to_owned(),
            spki,
            at: now(),
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
        "admission of node-13: {result:?}"
    );

    let result = admin
        .write(Command::SnapshotVolume {
            volume: "old-stock".to_owned(),
            node: "node-13".to_owned(),
            generation: 4,
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
        "the decree was not applied: {result:?}"
    );

    let _agent = agent(agent_dir.path(), "node-13", port, session_port);

    let deadline = Instant::now() + PATIENCE;
    loop {
        assert!(
            Instant::now() < deadline,
            "no snapshot -- the decree did not reach the node"
        );

        let held = store.snapshots("old-stock").unwrap_or_default();
        if let Some(snap) = held.iter().find(|snap| snap.generation == 4) {
            // **The content, not the presence.**
            let raw = std::fs::read(&snap.path).expect("snapshot readable");
            assert_eq!(
                raw, b"the state of back then",
                "the snapshot does not carry the image's state"
            );
            // **And the mark** -- without it the next slice would make it again,
            // and the reconciler would run in circles.
            assert_eq!(
                store.snapshot_mark("old-stock"),
                4,
                "the mark must carry the executed generation"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// **And the counter-check: a volume does not disappear on its own.**
///
/// The slice does not name `leftover` -- neither as a tombstone nor otherwise.
/// From absence "delete" must never follow (ADR-0027, ADR-0040 determination 6):
/// a workload can leave a node without its data being meant to go.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_volume_nobody_mentions_survives() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
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
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
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

    // The agent directory arises here, because the cluster material belongs into
    // it before the admission.
    let agent_dir = tempfile::tempdir().expect("tempdir");

    // ADR-0043: without admission no session. The node comes into the trust list
    // with its key, otherwise the port refuses it.
    let spki = agent_cluster_material(agent_dir.path(), cp_dir.path());
    for command in [
        Command::InviteNode {
            node: "node-11".to_owned(),
            digest: tg_consensus::token_digest("whatever-the-test-does-not-redeem"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-11".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
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
            "the admission must get through: {result:?}"
        );
    }

    for command in [
        Command::UpsertNode {
            name: "node-14".to_owned(),
            topology: tg_consensus::Topology {
                site: "s".to_owned(),
                hall: "h".to_owned(),
                rack: "r".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
        Command::UpsertWorkload {
            document: definition("api"),
        },
        Command::AssignPlacement {
            workload: "api".to_owned(),
            instance: 0,
            node: "node-14".to_owned(),
        },
    ] {
        admin.write(command).await.expect("call");
    }

    let token = tg_consensus::generate_token();
    admin
        .write(Command::InviteNode {
            node: "node-14".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");

    bare_node(agent_dir.path(), &token);

    let store = tg_runtime::volume::VolumeStore::open(agent_dir.path()).expect("store");
    store
        .declare("leftover", tg_runtime::volume::MIN_BYTES)
        .expect("create");

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
                "--interval",
                &std::env::var("MEASURE_INTERVAL").unwrap_or_else(|_| "10".to_owned()),
                "--cluster-cidr",
                "10.48.0.0/16",
                "--node",
                "node-14",
                "--control-plane",
                &endpoint,
                "--node-session",
                &session_endpoint,
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

    // First wait until the slice was really applied -- otherwise the test would
    // prove only that the agent has not done anything yet.
    //
    // **And the waiting is assured.** `await_content` does not panic on a
    // timeout, it returns what it last saw -- both stood here as `let _ =`. This
    // witness checks an **absence**, and there a discarded waiting point is
    // deadly: if the slice never arrives, the volume is of course still there, the
    // test is green and has checked nothing. The comment above says it verbatim.
    let desired = await_content(&agent_dir.path().join("desired").join("api.xml"), "api");
    assert!(
        desired.contains("api"),
        "the slice did not arrive: '{desired}'"
    );
    // The mark carries the log index (ADR-0040). `contains("")` is always true, so
    // the waiting ends as soon as the **file is there** -- what it contains is
    // said only by the assurance.
    let applied = await_content(&agent_dir.path().join("network").join("applied"), "");
    assert!(
        applied.trim().parse::<u64>().is_ok_and(|index| index > 0),
        "no slice was applied: '{applied}'"
    );
    std::thread::sleep(Duration::from_secs(2));

    assert!(
        store.exists("leftover"),
        "a volume nobody mentions was deleted"
    );
}

/// A workload with a resource wish and without a fixed placement.
fn hungry(name: &str, millicores: u32) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"{name}\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/{name}:1.0\"/>\n\
         \x20   <resources><cpu millicores=\"{millicores}\"/></resources>\n\
         \x20 </workload>\n\
         </workloads>\n"
    )
}

/// **The node reports, a policy decides, the leader writes** (ADR-0049).
///
/// The whole stretch at real processes: the agent reports over the session what
/// its machine has; an operator deposits a rule; the leader makes an `UpsertNode`
/// of it. Nobody types numbers per node, and a consensus-backed number stands in
/// the log all the same.
///
/// **The evidence is a placement, not a query.** Before the policy the node has
/// no capacity and the workload stays lying; afterwards it has some, and it is
/// placed. That checks the effect instead of a field -- and it checks at the same
/// time that the number really landed in the **replicated** state, for only that
/// is seen by the planner (determination 2).
///
/// The upper bound makes the test independent of the test machine: `cap = 1000`
/// means 1000, no matter how many cores the computer has.
#[tokio::test]
async fn a_reported_capacity_becomes_usable_through_a_policy() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let (_control_plane, admin) = leader(cp_dir.path(), port, cluster_port, session_port).await;
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
    let agent_dir = admitted(&admin, cp_dir.path()).await;
    // **The session is run here by the test itself, not by a `tg-agent`.**
    //
    // **A correction of a rationale that stood here wrongly.** It read that there
    // was no OCI runtime in this environment and that the agent ends itself at
    // startup. Measured, that is not so: `youki` and `crun` run the full cycle
    // here, and the agents of the neighbouring tests live for minutes.
    //
    // The setup stays all the same, and for the reason that was always the
    // better one: what is checked is ADR-0049 -- report, policy, log -- and not
    // the runtime path, which has nothing to do with it. A real agent would need
    // an image from a registry here in order to show the same thing.
    let channel = node_channel(agent_dir.path(), &session_endpoint);
    let (to_server, from_test) = tokio::sync::mpsc::channel(8);
    let client = tg_store::session::SessionClient::with_channel(channel);
    let mut incoming = client
        .open(tokio_stream::wrappers::ReceiverStream::new(from_test))
        .await
        .expect("session");

    to_server
        .send(tg_store::session::NodeMessage::Hello { applied: 0 })
        .await
        .expect("Hello");

    // The node reports what it has. The number is freely chosen -- the policy's
    // upper bound makes the result independent of it.
    to_server
        .send(tg_store::session::NodeMessage::Report(Box::new(
            tg_store::session::NodeReport {
                stale: Vec::new(),
                unready: Vec::new(),
                failures: Vec::new(),
                isolated: Vec::new(),
                generations: tg_consensus::Generations::default(),
                applied: 0,
                states: Vec::new(),
                capacity: tg_consensus::Resources::default()
                    .with(tg_consensus::Resources::CPU_MILLICORES, 64_000),
                proxy_image: None,
                endpoints: Vec::new(),
                dns_zone: None,
                userns: None,
                retired: Vec::new(),
            },
        )))
        .await
        .expect("report");

    // Without a policy the workload stays lying. The counter-check is important:
    // without it the test below would prove only that something is placed at some
    // point.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !placed(&mut incoming).await,
        "it placed without a policy -- then this test checks nothing"
    );

    // The policy: a hundred per cent, but at most 1000 millicores.
    let result = admin
        .write(Command::SetCapacityPolicy {
            policy: tg_consensus::CapacityPolicy::default().with(
                tg_consensus::Resources::CPU_MILLICORES,
                tg_consensus::CapacityRule {
                    subtract: 0,
                    percent: 100,
                    cap: Some(1000),
                    reserve: 250,
                },
            ),
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

    // 1000 - 250 reserve = 750 usable, and the workload wants 500. If it arrives
    // in the slice, the leader has written the number into the **replicated**
    // state -- only that is seen by the planner (ADR-0049, determination 2).
    let deadline = Instant::now() + PATIENCE;
    let mut arrived = false;
    while !arrived && Instant::now() < deadline {
        arrived = placed(&mut incoming).await;
    }
    assert!(arrived, "the workload never arrived in the slice");
}

/// Whether a placement stands in the next slice.
async fn placed(incoming: &mut tonic::Streaming<tg_store::session::ControlMessage>) -> bool {
    use futures_util::StreamExt as _;

    let next = tokio::time::timeout(Duration::from_secs(3), incoming.next()).await;

    matches!(
        next,
        Ok(Some(Ok(tg_store::session::ControlMessage::Slice(slice))))
            if !slice.instances.is_empty()
    )
}

/// An mTLS channel to the node session, as `tg-agent::cluster` builds it.
///
/// Extracted because the test would otherwise lie above the line limit -- and
/// because it is the place at which this test rebuilds something instead of using
/// it: `tg-agent`'s own module is private, and a test must not be the reason to
/// open it.
fn node_channel(agent_dir: &Path, endpoint: &str) -> tonic::transport::Channel {
    let key_pem =
        std::fs::read_to_string(agent_dir.join("identity").join("node.key.pem")).expect("key");
    let key = rcgen::KeyPair::from_pem(key_pem.trim()).expect("key");
    let domain = tg_identity::TrustDomain::new("cluster.local").expect("domain");
    let id = tg_identity::SpiffeId::for_node(&domain, "node-11").expect("ID");
    let identity = tg_identity::cluster::NodeIdentity::new(&key, id).expect("credential");
    let anchors = tg_identity::cluster::anchors_from_pem(
        &std::fs::read_to_string(agent_dir.join("identity").join("control-plane.pem"))
            .expect("anchor"),
        &domain,
    )
    .expect("anchor");
    let verifier =
        tg_identity::NodeVerifier::new(domain.clone(), tg_identity::cluster::shared(anchors));
    let config = tg_identity::cluster::client_config(&identity, verifier).expect("configuration");
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    tonic::transport::Endpoint::from_shared(endpoint.to_owned())
        .expect("address")
        .connect_with_connector_lazy(tower::service_fn(move |uri: http::Uri| {
            let connector = connector.clone();
            async move {
                let host = uri.host().unwrap_or("127.0.0.1").to_owned();
                let port = uri.port_u16().unwrap_or(80);
                let stream = tokio::net::TcpStream::connect((host, port)).await?;
                let name = rustls_pki_types::ServerName::try_from("cluster.invalid")
                    .map_err(std::io::Error::other)?;
                let tls = connector.connect(name, stream).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }
        }))
}

/// Starts a leading `tgd` and returns its admin client.
///
/// The same lines stood in every test of this file; here they stand once, because
/// the new one would otherwise lie above the line limit. The others have **not**
/// been converted -- that would be a change to tests that have nothing to do with
/// this work.
async fn leader(
    dir: &Path,
    port: u16,
    cluster_port: u16,
    session_port: u16,
) -> (Running, AdminClient) {
    leader_with_telemetry(dir, port, cluster_port, session_port, "off").await
}

/// Like [`leader`], with a telemetry endpoint.
///
/// Separate, because the other tests must **switch it off**: `cargo test` runs
/// the test binaries concurrently, and a default port would be the same for all
/// (the finding from 11b).
async fn leader_with_telemetry(
    dir: &Path,
    port: u16,
    cluster_port: u16,
    session_port: u16,
    telemetry: &str,
) -> (Running, AdminClient) {
    let control_plane = Running(
        OsCommand::new(binary("tgd"))
            .args([
                "--telemetry-addr",
                telemetry,
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
    );

    let admin = AdminClient::connect_unix(&tgd::admin::socket_path(dir, 1)).expect("admin socket");

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

    (control_plane, admin)
}

/// Admits a node and enters what this test needs.
///
/// Extracted because the test would otherwise lie above the line limit -- and
/// because it is the preparation and not what is checked.
async fn admitted(admin: &AdminClient, cp_dir: &Path) -> tempfile::TempDir {
    let agent_dir = tempfile::tempdir().expect("tempdir");
    let spki = agent_cluster_material(agent_dir.path(), cp_dir);
    for command in [
        Command::InviteNode {
            node: "node-11".to_owned(),
            digest: tg_consensus::token_digest("whatever"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-11".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
        // The node comes into the log **without** capacity -- exactly the
        // situation ADR-0049 describes: entered, but no number.
        Command::UpsertNode {
            name: "node-11".to_owned(),
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
            cidr: "10.98.0.0/16".to_owned(),
            node_prefix: 24,
        },
        Command::UpsertWorkload {
            document: hungry("computer", 500),
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "{kind}: {result:?}"
        );
    }

    agent_dir
}

/// **The cluster forgets the announcement -- and the node fetches it back
/// without waiting three hours** (ADR-0042).
///
/// The announcement travels on the renewal path, and that goes by the clock. An
/// endpoint change is thereby harmless: `--underlay-endpoint` stands on the
/// command line, a change demands a restart, and that announces at once. What
/// does **not** hang on a restart is the case here: the log suddenly knows
/// something else -- a `RemoveNode` with a renewed admission, a write that lapsed
/// at a leader change, or as here a foreign entry. Until here the node then stood
/// in the log without an underlay for up to three hours, and nobody would have
/// noticed.
///
/// The test writes the contradiction itself and waits in three steps: the
/// announcement at the start, the contradiction in the slice, the correction. The
/// middle step carries the test -- without it the right endpoint would stand in
/// the file from the beginning, and the last step would prove nothing.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_lost_announcement_comes_back_without_waiting_for_the_clock() {
    /// A valid but foreign X25519 key: 32 bytes base64.
    const STRANGER: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
    /// What the agent announces.
    const MINE: &str = "203.0.113.9:51820";
    /// What the log believes to know instead.
    const THEIRS: &str = "198.51.100.7:51820";

    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
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

    let endpoint = format!("http://127.0.0.1:{port}");
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
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
    let spki = agent_cluster_material(agent_dir.path(), cp_dir.path());

    // **Two invitations, and that is no duplication.** `AdmitNode` checks and
    // **consumes** the first (ADR-0037: check and consumption in the same apply,
    // so that the one-timeness is consensus-backed). The agent therefore redeems a
    // second one.
    for command in [
        Command::InviteNode {
            node: "node-21".to_owned(),
            digest: tg_consensus::token_digest("only-for-the-admission"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-21".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }

    let token = tg_consensus::generate_token();
    admin
        .write(Command::InviteNode {
            node: "node-21".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");

    bare_node(agent_dir.path(), &token);

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
                "--interval",
                &std::env::var("MEASURE_INTERVAL").unwrap_or_else(|_| "10".to_owned()),
                "--cluster-cidr",
                "10.48.0.0/16",
                "--node",
                "node-21",
                "--control-plane",
                &endpoint,
                "--node-session",
                &session_endpoint,
                "--underlay-endpoint",
                MINE,
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

    let peers = agent_dir.path().join("network").join("peers.json");

    // 1. The restart announces at once -- that is the case that **never** needed
    //    three hours, and the prerequisite for everything further.
    //
    //    **Assured and not merely waited out:** `await_content` returns on a
    //    timeout what it last saw instead of failing. A `let _ =` out of it turned
    //    a missing prerequisite into a silent pause -- exactly what this test
    //    checked past at its first attempt.
    let seen = await_content(&peers, MINE);
    assert!(seen.contains(MINE), "the start did not announce: {seen}");

    // 2. The log now knows something else.
    //
    //    **The timestamp is taken before the write, and that is this section's
    //    whole point.** An assurance on the intermediate state stood here before
    //    -- that `peers.json` *contains* the foreign entry. That is a race against
    //    the node, and one it is meant to win: it deletes this state as fast as it
    //    can. Under load (full workspace run) the transient was shorter than the
    //    sampling interval, and the test failed at a system that had worked
    //    exactly right.
    //
    //    What is assured is therefore the **statement** instead of the transient:
    //    after this point in time a slice comes, and in it its own announcement
    //    stands again. The slice comes from consensus, the file is rewritten at
    //    every slice -- a newer timestamp with `MINE` therefore means: the log
    //    carries it again.
    let before_write = std::time::SystemTime::now();
    let result = admin
        .write(Command::AnnounceUnderlay {
            node: "node-21".to_owned(),
            key: STRANGER.to_owned(),
            endpoint: THEIRS.to_owned(),
            at: now(),
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
        "the contradiction must land in the log: {result:?}"
    );
    // 3. And the node fetches its announcement back. Without the wake-up the
    //    foreign entry would stand here until the next stroke of the clock -- this
    //    test's patience is orders of magnitude shorter than three hours.
    //
    //    The timestamp carries the distinction: a `MINE` from step 1 would already
    //    stand there without anything having happened. What is demanded is a
    //    `MINE` that was written **after** the contradiction.
    let deadline = Instant::now() + PATIENCE;
    let mut text = String::new();
    let mut fresh = false;
    while Instant::now() < deadline {
        let written = std::fs::metadata(&peers).and_then(|meta| meta.modified());
        if let (Ok(written), Ok(current)) = (written, std::fs::read_to_string(&peers))
            && written > before_write
        {
            text = current;
            if text.contains(MINE) && !text.contains(THEIRS) {
                fresh = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    assert!(
        fresh,
        "the node did not fetch its announcement back: {text}"
    );
}

/// **The tunnel follows the slice** (ADR-0039 -- the connection that had been
/// missing since 9d).
///
/// `tg-net::wireguard` was built and checked at real packets, but **no process
/// called it**: `configure` had no caller, the agent wrote `peers.json` and nobody
/// read it. That is the same pattern as with `tg-identity` and `tg-proxy` before
/// the wiring -- and this test is the answer to it.
///
/// # What the assurance is worth
///
/// What is read is the agent's message, and it says more than "the code ran":
/// `reconcile` reports only when `configure` has **returned**, and that is a
/// netlink call. `peers=1` therefore means that the kernel has taken in a peer.
///
/// The peer is a second, admitted node with an announced underlay -- without it
/// the list would be **empty**, for `wireguard::peers` leaves the node itself out
/// (ADR-0039).
///
/// `#[ignore]`: demands `CAP_NET_ADMIN` and the `WireGuard` module, and it creates
/// `tgwg0` on the host -- run with `cargo xtask net`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_NET_ADMIN and the WireGuard module; via `cargo xtask net`"]
#[allow(clippy::too_many_lines)]
async fn the_tunnel_follows_the_slice() {
    /// The neighbour's key: 32 bytes base64.
    const NEIGHBOUR_KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
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

    let endpoint = format!("http://127.0.0.1:{port}");
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
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
    let spki = agent_cluster_material(agent_dir.path(), cp_dir.path());

    for command in [
        // The address space comes from consensus (ADR-0040). Without it the node
        // has no network parameters, and `reconcile` says exactly that.
        Command::SetClusterNetwork {
            cidr: "10.49.0.0/16".to_owned(),
            node_prefix: 24,
        },
        Command::InviteNode {
            node: "node-31".to_owned(),
            digest: tg_consensus::token_digest("only-for-the-admission"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-31".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
        // The neighbour. It does not run -- for the peer list it suffices that
        // consensus knows it.
        Command::InviteNode {
            node: "node-32".to_owned(),
            digest: tg_consensus::token_digest("also-only-for-the-admission"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-32".to_owned(),
            spki: "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            at: now(),
        },
        Command::AnnounceUnderlay {
            node: "node-32".to_owned(),
            key: NEIGHBOUR_KEY.to_owned(),
            endpoint: "198.51.100.32:51820".to_owned(),
            at: now(),
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }

    let token = tg_consensus::generate_token();
    admin
        .write(Command::InviteNode {
            node: "node-31".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");

    bare_node(agent_dir.path(), &token);

    // The agent's messages go into a file so that `await_content` can read them
    // -- asking the kernel itself would need a second way there, and `reconcile`
    // reports only when netlink has agreed.
    let log = agent_dir.path().join("agent.log");
    let sink = std::fs::File::create(&log).expect("log file");

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
                "--cluster-cidr",
                "10.49.0.0/16",
                "--node",
                "node-31",
                "--control-plane",
                &endpoint,
                "--node-session",
                &session_endpoint,
                "--underlay-endpoint",
                "203.0.113.31:51820",
            ])
            .env(
                "PATH",
                format!("{}:{path}", agent_dir.path().join("stub").display()),
            )
            .stdout(support::log("tg-agent"))
            .stderr(Stdio::from(sink))
            .spawn()
            .expect("tg-agent startable"),
    );

    let seen = await_content(&log, "underlay connected");
    assert!(
        seen.contains("underlay connected"),
        "the tunnel was not connected: {seen}"
    );
    assert!(
        seen.contains("\"peers\":1"),
        "the neighbour does not stand in the kernel -- peers=1 expected: {seen}"
    );
}

/// **The node rotates its keys when the cluster decrees it** (ADR-0055).
///
/// Both kinds in one test, because they go **different ways**: the identity key
/// changes on the credential path (the old one vouches for the new one), the
/// underlay key over announcement and confirmation. A test that checks only one
/// leaves the other unseen -- and exactly that way it stayed hidden at the first
/// attempt that the identity path demanded an entered node that `AdmitNode` never
/// creates.
///
/// What is checked is the whole order at a real cluster: generate -> put beside ->
/// announce -> confirm -> switch over. What one sees from the outside is the
/// **key in the slice**, and that it is a different one after the decree than
/// before -- more is not needed, because the slice comes from consensus and not
/// from the node.
///
/// # Why the before value is read and not guessed
///
/// "The key is now X" would be an assurance about something the test does not
/// know. "It is a **different** one than before" is the statement at issue -- and
/// the before value carries the test at the same time: without it an arbitrary key
/// would prove nothing.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_node_rotates_its_underlay_key_when_the_cluster_asks() {
    const MINE: &str = "203.0.113.41:51820";

    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
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

    let endpoint = format!("http://127.0.0.1:{port}");
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
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
    let spki = agent_cluster_material(agent_dir.path(), cp_dir.path());

    for command in [
        Command::InviteNode {
            node: "node-41".to_owned(),
            digest: tg_consensus::token_digest("only-for-the-admission"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-41".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }

    let token = tg_consensus::generate_token();
    admin
        .write(Command::InviteNode {
            node: "node-41".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");

    bare_node(agent_dir.path(), &token);

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
                "--cluster-cidr",
                "10.50.0.0/16",
                "--node",
                "node-41",
                "--control-plane",
                &endpoint,
                "--node-session",
                &session_endpoint,
                "--underlay-endpoint",
                MINE,
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

    let peers = agent_dir.path().join("network").join("peers.json");
    let seen = await_content(&peers, MINE);
    assert!(seen.contains(MINE), "the start did not announce: {seen}");

    let before: tg_store::session::UnderlayPeer =
        serde_json::from_str::<Vec<tg_store::session::UnderlayPeer>>(&seen)
            .expect("peer list")
            .into_iter()
            .find(|peer| peer.node == "node-41")
            .expect("its own entry");

    // **The identity key first**, and that is no trimming: it goes a different
    // way (the old one vouches for the new one, ADR-0055), and this way was broken
    // at the first attempt -- `RegisterTrust` demands an entered node, and
    // `AdmitNode` enters none (ADR-0037). A test that rotates only the underlay
    // does not see that.
    let result = admin
        .write(Command::SetKeyGeneration {
            node: "node-41".to_owned(),
            kind: tg_consensus::KeyKind::Identity,
            generation: 1,
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
        "the decree was not applied: {result:?}"
    );

    // **And the second decree immediately afterwards** -- that is the shape that
    // found an error, and that is why it stays.
    //
    // Two rotations shortly after one another let the **wake-ups coincide**:
    // `Notify` holds exactly one place, and the second announcement then waited
    // until the next stroke of the clock -- up to three hours. The test ran into
    // its patience, deterministically. Fixed by letting the pending key shorten
    // the cadence of its own accord: it is state, not a signal (ADR-0055).
    //
    // Decreed one after the other it would be the easier case, and nobody would
    // have seen that one red.
    admin
        .write(Command::SetKeyGeneration {
            node: "node-41".to_owned(),
            kind: tg_consensus::KeyKind::Underlay,
            generation: 1,
        })
        .await
        .expect("call");

    // It becomes visible in that the generation is taken over -- and that happens
    // only when the **server** has accepted the change.
    let identity = agent_dir.path().join("identity");
    let deadline = Instant::now() + PATIENCE;
    let mut seen_identity = false;
    while Instant::now() < deadline {
        let generation =
            std::fs::read_to_string(identity.join("node.key.pem.generation")).unwrap_or_default();
        if generation.trim() == "1" && !identity.join("node.key.pem.pending").exists() {
            seen_identity = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        seen_identity,
        "the node key was not rotated -- the server did not accept the change"
    );

    // And the node follows at the underlay too. The wake-up from ADR-0042 carries
    // it; the lower bound there is five seconds.
    let deadline = Instant::now() + PATIENCE;
    let mut current = before.key.clone();
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&peers)
            && let Ok(list) = serde_json::from_str::<Vec<tg_store::session::UnderlayPeer>>(&text)
            && let Some(mine) = list.into_iter().find(|peer| peer.node == "node-41")
        {
            current = mine.key;
            if current != before.key {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    assert_ne!(
        current, before.key,
        "the node did not rotate its underlay key"
    );

    // And it has **switched over**, not only announced: the generation stands, and
    // nothing lies beside it any more.
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        let generation =
            std::fs::read_to_string(identity.join("underlay.key.generation")).unwrap_or_default();
        if generation.trim() == "1" && !identity.join("underlay.key.pending").exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    panic!("the generation was not taken over -- the node only announced");
}

/// **A policy rotates without anyone decreeing it** (ADR-0057, determination 5).
///
/// The neighbouring test above issues `SetKeyGeneration` by hand; here an operator
/// sets **only the rule**, and the leader makes the decree of it. That is the
/// stretch this test alone covers -- policy in the log -> computation in the
/// leader -> `SetKeyGeneration` in the log -> slice -> node.
///
/// # Why only the underlay key
///
/// The **two ways** of a key change are substantiated above, both. What is new
/// here is not the way but its **trigger**; checking it twice would check the
/// same thing twice. The underlay is the stricter choice in this, because it
/// becomes visible in the slice -- and that comes from consensus, not from the
/// node.
///
/// # Why the generation is checked against the calendar and not against `> 0`
///
/// `> 0` would be green too if anybody had decreed anything. The policy computes
/// `(day + offset) / period`, and with a period of one day the offset is zero --
/// the generation **is** then the day number. That a five-digit number stands
/// there and no `1` is the evidence that it comes from the clock.
///
/// And it substantiates at the same time the promise from ADR-0055 that is checked
/// nowhere else: the node catches up **one** generation, not twenty thousand. It
/// jumps straight to the day number instead of working its way up step by step.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_policy_rotates_a_key_without_anyone_decreeing_it() {
    const MINE: &str = "203.0.113.44:51820";

    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
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

    let endpoint = format!("http://127.0.0.1:{port}");
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
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
    let spki = agent_cluster_material(agent_dir.path(), cp_dir.path());

    for command in [
        Command::InviteNode {
            node: "node-44".to_owned(),
            digest: tg_consensus::token_digest("only-for-the-admission"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: "node-44".to_owned(),
            spki: spki.clone(),
            at: now(),
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }

    let token = tg_consensus::generate_token();
    admin
        .write(Command::InviteNode {
            node: "node-44".to_owned(),
            digest: tg_consensus::token_digest(&token),
            expires_at: now() + 900,
        })
        .await
        .expect("call");

    bare_node(agent_dir.path(), &token);

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
                "--cluster-cidr",
                "10.53.0.0/16",
                "--node",
                "node-44",
                "--control-plane",
                &endpoint,
                "--node-session",
                &session_endpoint,
                "--underlay-endpoint",
                MINE,
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

    let peers = agent_dir.path().join("network").join("peers.json");
    let seen = await_content(&peers, MINE);
    let before: tg_store::session::UnderlayPeer =
        serde_json::from_str::<Vec<tg_store::session::UnderlayPeer>>(&seen)
            .expect("peer list")
            .into_iter()
            .find(|peer| peer.node == "node-44")
            .expect("its own entry");

    // The day is read **before** the rule: read afterwards it could already be the
    // one taken over, and the assurance would check itself.
    let day = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
        / 86_400;

    // **Only the rule.** No `SetKeyGeneration` by hand -- if something rotates
    // here, then because the leader computed.
    let result = admin
        .write(Command::SetRotationPolicy {
            policy: tg_consensus::RotationPolicy::default()
                .with(tg_consensus::KeyKind::Underlay, 1),
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
        "the rule was not applied: {result:?}"
    );

    // Visible in the **slice**, so from consensus: the node carries a different
    // key than before.
    let deadline = Instant::now() + PATIENCE;
    let mut current = before.key.clone();
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&peers)
            && let Ok(list) = serde_json::from_str::<Vec<tg_store::session::UnderlayPeer>>(&text)
            && let Some(mine) = list.into_iter().find(|peer| peer.node == "node-44")
        {
            current = mine.key;
            if current != before.key {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_ne!(current, before.key, "the policy triggered no rotation");

    // And the generation comes from the **calendar**. A change of day in the
    // middle of the run is permitted -- this test cannot last more than a day.
    let identity = agent_dir.path().join("identity");
    let deadline = Instant::now() + PATIENCE;
    let mut generation = String::new();
    while Instant::now() < deadline {
        generation =
            std::fs::read_to_string(identity.join("underlay.key.generation")).unwrap_or_default();
        if !generation.trim().is_empty() && !identity.join("underlay.key.pending").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let taken_over: u64 = generation
        .trim()
        .parse()
        .unwrap_or_else(|err| panic!("the generation was not taken over ({err}): '{generation}'"));
    assert!(
        taken_over == day || taken_over == day + 1,
        "the generation does not stem from the clock: {taken_over}, expected {day}"
    );
}

/// **The reported generation becomes a metric** (ADR-0055, determination 5).
///
/// The node reports which key generations it **carries**; the log says which shall
/// apply. The difference shows whether a rotation has arrived -- and a rotation
/// one takes for settled is worse than none.
///
/// The session is run here by the test itself, for the same reason as with
/// ADR-0049: what is checked is the **reporting stretch**, not the runtime path.
/// (The earlier rationale -- "there is no OCI runtime in this environment" -- is
/// measured to be false and withdrawn.)
///
/// **Both directions in one test:** first the backlog, then its disappearance.
/// Without the second part it would stay open whether the metric ever says
/// anything other than a warning.
#[tokio::test(flavor = "multi_thread")]
async fn a_reported_generation_becomes_a_metric() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();
    let telemetry_port = support::free_port();

    let (_control_plane, admin) = leader_with_telemetry(
        cp_dir.path(),
        port,
        cluster_port,
        session_port,
        &format!("127.0.0.1:{telemetry_port}"),
    )
    .await;
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
    let agent_dir = admitted(&admin, cp_dir.path()).await;

    // Decreed: generation 2 for the underlay. **The node is the one whose
    // credential the session carries** (`admitted` admits `node-11`) -- the name in
    // the report plays no role, for the leader takes it from the certificate
    // (ADR-0043).
    admin
        .write(Command::SetKeyGeneration {
            node: "node-11".to_owned(),
            kind: tg_consensus::KeyKind::Underlay,
            generation: 2,
        })
        .await
        .expect("call");

    let channel = node_channel(agent_dir.path(), &session_endpoint);
    let (to_server, from_test) = tokio::sync::mpsc::channel(8);
    let client = tg_store::session::SessionClient::with_channel(channel);
    let incoming = client
        .open(tokio_stream::wrappers::ReceiverStream::new(from_test))
        .await
        .expect("session");

    to_server
        .send(tg_store::session::NodeMessage::Hello { applied: 0 })
        .await
        .expect("Hello");

    // The node reports that it is still at **zero**: a backlog of two.
    to_server
        .send(tg_store::session::NodeMessage::Report(Box::new(
            tg_store::session::NodeReport {
                stale: Vec::new(),
                unready: Vec::new(),
                failures: Vec::new(),
                isolated: Vec::new(),
                applied: 0,
                states: Vec::new(),
                capacity: tg_consensus::Resources::default(),
                generations: tg_consensus::Generations::default(),
                proxy_image: None,
                endpoints: Vec::new(),
                dns_zone: None,
                userns: None,
                retired: Vec::new(),
            },
        )))
        .await
        .expect("report");

    assert!(
        await_metric(
            telemetry_port,
            tg_telemetry::names::KEY_GENERATION_LAG,
            "kind=\"underlay\"} 2",
        )
        .await,
        "the backlog of two does not appear"
    );

    // And now it reports that it has caught up.
    to_server
        .send(tg_store::session::NodeMessage::Report(Box::new(
            tg_store::session::NodeReport {
                stale: Vec::new(),
                unready: Vec::new(),
                failures: Vec::new(),
                isolated: Vec::new(),
                applied: 0,
                states: Vec::new(),
                capacity: tg_consensus::Resources::default(),
                generations: tg_consensus::Generations {
                    identity: 0,
                    underlay: 2,
                },
                proxy_image: None,
                endpoints: Vec::new(),
                dns_zone: None,
                userns: None,
                retired: Vec::new(),
            },
        )))
        .await
        .expect("report");

    assert!(
        await_metric(
            telemetry_port,
            tg_telemetry::names::KEY_GENERATION_LAG,
            "kind=\"underlay\"} 0",
        )
        .await,
        "the backlog does not disappear when the node has caught up"
    );

    // The stream is held until the end: if it fell, the session would end, and the
    // leader would forget nothing -- but the test would then check a view nobody
    // refreshes any more.
    drop(incoming);
}

/// Waits until the telemetry endpoint contains a line.
///
/// `curl` instead of an HTTP client in the tree, as in `tgd/tests/telemetry.rs`:
/// foreign code that read the specification independently -- and a crate for it
/// would be one for a single line (ADR-0023). `--max-time` stands beside it as a
/// fallback: a test that hangs is worse than one that fails (11b).
async fn await_metric(port: u16, metric: &str, wanted: &str) -> bool {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
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
        // **Line by line**, not two substrings in the whole document: otherwise it
        // would suffice that the name stands somewhere and the value somewhere
        // else -- and a wrong label would not stand out. The same rule as with the
        // other endpoint witnesses of this tree.
        if body
            .lines()
            .any(|line| line.starts_with(metric) && line.contains(wanted))
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    false
}

/// **A leader that lies behind the node sends no slice** (ADR-0040, ADR-0058).
///
/// # Why this one line carries so much
///
/// The slice is a **snapshot**: what it does not name is cleared out of the cache
/// by `session::apply` (ADR-0040, determination 6), and what no longer stands in
/// the cache is ended by the clearer (ADR-0058). An **empty** slice thereby means
/// "nothing runs on this node any more" -- right for a drained node, catastrophic
/// for one whose leader has merely not caught up yet.
///
/// Against that stands `if index > sent` in `tgd::session`, where `sent` begins
/// with the state the node names in its `Hello`. One line between "the leader lies
/// behind" and "every container of this node is ended" -- and until here nobody
/// guarded it.
///
/// The counter-check sits in the test itself: the same setup, only the cluster
/// catches up afterwards, and the slice comes. Without it the test would be green
/// too if a slice never came.
#[tokio::test(flavor = "multi_thread")]
async fn a_lagging_leader_sends_no_slice() {
    use futures_util::StreamExt as _;

    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let (_control_plane, admin) = leader(cp_dir.path(), port, cluster_port, session_port).await;
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
    let agent_dir = admitted(&admin, cp_dir.path()).await;

    let channel = node_channel(agent_dir.path(), &session_endpoint);
    let (to_server, from_test) = tokio::sync::mpsc::channel(8);
    let client = tg_store::session::SessionClient::with_channel(channel);
    let mut incoming = client
        .open(tokio_stream::wrappers::ReceiverStream::new(from_test))
        .await
        .expect("session");

    // The node claims to be further along than the cluster. Exactly the situation
    // of a freshly elected leader whose projection is still catching up. Large
    // enough that the cluster really lies behind, small enough that the
    // counter-check below does not become a load test.
    let ahead = 200;
    to_server
        .send(tg_store::session::NodeMessage::Hello { applied: ahead })
        .await
        .expect("Hello");

    // Write something so that `last_applied` **moves** -- otherwise the test would
    // show only that a quiet cluster keeps quiet.
    let _ = admin
        .write(tg_consensus::Command::SetClusterNetwork {
            cidr: "10.42.0.0/16".to_owned(),
            node_prefix: 24,
        })
        .await;

    let quiet = tokio::time::timeout(Duration::from_secs(3), incoming.next()).await;
    assert!(
        quiet.is_err(),
        "a leader lying behind should have sent nothing: {quiet:?}"
    );

    // **And the counter-check in the same setup**: the cluster catches up. Without
    // it the test would be green too if this channel never carried a slice -- a
    // test on silence has many reasons to be green.
    for _ in 0..=ahead {
        let _ = admin
            .write(tg_consensus::Command::SetClusterNetwork {
                cidr: "10.42.0.0/16".to_owned(),
                node_prefix: 24,
            })
            .await;
    }

    let arrived = tokio::time::timeout(Duration::from_secs(10), incoming.next()).await;
    assert!(
        matches!(
            arrived,
            Ok(Some(Ok(tg_store::session::ControlMessage::Slice(_))))
        ),
        "as soon as the cluster is past it, the slice must come: {arrived:?}"
    );
}

/// A single writer (ADR-0010).
/// Issues a setup command and **checks the outcome**.
///
/// `Applied` means "applied in the log", not "accepted" -- the verdict stands in
/// it (ADR-0045). `let _ = admin.write(command).await` stood here once: a refused
/// setup command let the test afterwards check against a cluster that does not
/// have it.
async fn applied(admin: &tgd::admin::AdminClient, command: Command) {
    let written = admin.write(command).await.expect("write");
    assert!(
        matches!(
            written,
            WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                ..
            }
        ),
        "setup command refused: {written:?}"
    );
}

fn single_writer(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"{name}\" kind=\"service\" class=\"single-writer\">\n\
         \x20   <image reference=\"registry.example.com/{name}:1.0\"/>\n\
         \x20 </workload>\n\
         </workloads>\n"
    )
}

/// **The leader grants the active-role lease, and it arrives** (ADR-0064).
///
/// # What only this test covers
///
/// The leader side is checked as a pure function, the node side at real
/// containers. What lies in between is checked by neither: that the **planner**
/// really calls it, that the state machine accepts it, and that it comes back in
/// the slice.
///
/// And the way is the statement: the node **asks for nothing**. It only reports --
/// more is not needed, because the leader renews on a present observation
/// (ADR-0057) and ADR-0040 determination 7 thereby stays untouched.
#[tokio::test(flavor = "multi_thread")]
async fn the_leader_grants_the_active_role_lease() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let (_control_plane, admin) = leader(cp_dir.path(), port, cluster_port, session_port).await;
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
    let agent_dir = admitted(&admin, cp_dir.path()).await;

    // The node must be **entered**: `grant_lease` refuses an unknown one, and per
    // ADR-0037 `AdmitNode` enters only trust.
    for command in [
        Command::UpsertNode {
            name: "node-11".to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r1".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
        Command::UpsertWorkload {
            document: single_writer("till"),
        },
        Command::AssignPlacement {
            workload: "till".to_owned(),
            instance: 0,
            node: "node-11".to_owned(),
        },
    ] {
        applied(&admin, command).await;
    }

    let channel = node_channel(agent_dir.path(), &session_endpoint);
    let (to_server, from_test) = tokio::sync::mpsc::channel(8);
    let client = tg_store::session::SessionClient::with_channel(channel);
    let mut incoming = client
        .open(tokio_stream::wrappers::ReceiverStream::new(from_test))
        .await
        .expect("session");

    to_server
        .send(tg_store::session::NodeMessage::Hello { applied: 0 })
        .await
        .expect("Hello");
    // **Reporting suffices.** The node asks for no lease -- the leader renews for
    // the one that reports.
    to_server
        .send(tg_store::session::NodeMessage::Report(Box::new(
            tg_store::session::NodeReport {
                stale: Vec::new(),
                unready: Vec::new(),
                failures: Vec::new(),
                isolated: Vec::new(),
                generations: tg_consensus::Generations::default(),
                applied: 0,
                states: Vec::new(),
                capacity: tg_consensus::Resources::default(),
                proxy_image: None,
                endpoints: Vec::new(),
                dns_zone: None,
                userns: None,
                retired: Vec::new(),
            },
        )))
        .await
        .expect("report");

    let deadline = Instant::now() + PATIENCE;
    let mut first = None;
    while first.is_none() && Instant::now() < deadline {
        first = lease_deadline(&mut incoming).await;
    }

    let first = first.expect("the active-role lease never arrived in the slice");

    // **And it is renewed, beyond the deadline.**
    //
    // That is a liveness promise and was unchecked until here. The renewal hung on
    // **something** moving the metrics; in a quiet cluster that was the log, which
    // it moves itself -- a chain without a floor. Since ADR-0064 the leader has a
    // cadence of its own for it, and this test is its witness: a deadline that lies
    // later than the first can only come from a second renewal.
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut later = None;
    while later.is_none() && Instant::now() < deadline {
        // Report, like the real agent -- otherwise the lease rightly lapses.
        let _ = to_server
            .send(tg_store::session::NodeMessage::Report(Box::new(
                tg_store::session::NodeReport {
                    stale: Vec::new(),
                    unready: Vec::new(),
                    failures: Vec::new(),
                    isolated: Vec::new(),
                    generations: tg_consensus::Generations::default(),
                    applied: 0,
                    states: Vec::new(),
                    capacity: tg_consensus::Resources::default(),
                    proxy_image: None,
                    endpoints: Vec::new(),
                    dns_zone: None,
                    userns: None,
                    retired: Vec::new(),
                },
            )))
            .await;
        later = lease_deadline(&mut incoming)
            .await
            .filter(|seen| *seen > first);
    }

    assert!(
        later.is_some(),
        "the lease was not renewed -- a single writer would have fenced itself \
         after fifteen seconds"
    );
}

/// **A node that keeps quiet gets no lease** (ADR-0064, determination 2).
///
/// That **is** the fence from ADR-0010: the minority side does not reach the
/// leader, so nobody renews, so the lease lapses. Without this test the condition
/// `reporting.contains(holder)` would be unguarded -- the neighbouring test stays
/// green if one removes it, because its node reports.
///
/// What is assured is the **absence**, and that is why it stands beside it that
/// slices arrive at all: otherwise the test would be green too if the session
/// carried nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_node_gets_no_lease() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let (_control_plane, admin) = leader(cp_dir.path(), port, cluster_port, session_port).await;
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
    let agent_dir = admitted(&admin, cp_dir.path()).await;

    for command in [
        Command::UpsertNode {
            name: "node-11".to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r1".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
        Command::UpsertWorkload {
            document: single_writer("till"),
        },
        Command::AssignPlacement {
            workload: "till".to_owned(),
            instance: 0,
            node: "node-11".to_owned(),
        },
    ] {
        applied(&admin, command).await;
    }

    let channel = node_channel(agent_dir.path(), &session_endpoint);
    let (to_server, from_test) = tokio::sync::mpsc::channel(8);
    let client = tg_store::session::SessionClient::with_channel(channel);
    let mut incoming = client
        .open(tokio_stream::wrappers::ReceiverStream::new(from_test))
        .await
        .expect("session");

    // **Hello, but no report.** The slice hangs on the log and comes all the same;
    // the lease hangs on the report and may stay away.
    to_server
        .send(tg_store::session::NodeMessage::Hello { applied: 0 })
        .await
        .expect("Hello");

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut slices = 0_u32;
    let mut leased = false;
    while Instant::now() < deadline {
        use futures_util::StreamExt as _;
        let next = tokio::time::timeout(Duration::from_secs(2), incoming.next()).await;
        if let Ok(Some(Ok(tg_store::session::ControlMessage::Slice(slice)))) = next {
            slices += 1;
            if slice.leases.iter().any(|(w, _, _)| w == "till") {
                leased = true;
                break;
            }
        }
    }

    assert!(
        slices > 0,
        "no slice arrived -- the test would have checked nothing"
    );
    assert!(!leased, "a node that kept quiet got a lease");
}

/// Whether a lease for `till` stands in the next slice.
/// The deadline of `till`'s lease, if the next slice carries it.
async fn lease_deadline(
    incoming: &mut tonic::Streaming<tg_store::session::ControlMessage>,
) -> Option<u64> {
    use futures_util::StreamExt as _;

    let next = tokio::time::timeout(Duration::from_secs(3), incoming.next()).await;

    match next {
        Ok(Some(Ok(tg_store::session::ControlMessage::Slice(slice)))) => slice
            .leases
            .iter()
            .find(|(workload, _, _)| workload == "till")
            .map(|(_, _, expires_at)| *expires_at),
        _ => None,
    }
}

/// **A stale instance reaches the leader's read path** (ADR-0070).
///
/// ADR-0070 makes the deviation visible -- but the metric stands at the **node's**
/// endpoint. An operator would have to query every node in order to find where a
/// change is outstanding; here it lands in the leader's projection and thereby in
/// `tgctl cluster show`.
///
/// The stretch this test alone covers: report -> `absorb` -> projection -> the
/// admin service's answer. The setup runs the session itself, for the same reason
/// as with ADR-0049: what is checked is the observation's **way**, not the runtime
/// path that produces it.
#[tokio::test]
async fn a_stale_instance_reaches_the_leaders_read_path() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let (_control_plane, admin) = leader(cp_dir.path(), port, cluster_port, session_port).await;
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
    let agent_dir = admitted(&admin, cp_dir.path()).await;

    // The workload must be declared, otherwise there is no line the statement
    // could hang on.
    let applied = admin
        .write(Command::UpsertWorkload {
            document: hungry("api", 100),
        })
        .await
        .expect("write");
    assert!(
        matches!(
            applied,
            WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                ..
            }
        ),
        "{applied:?}"
    );

    let channel = node_channel(agent_dir.path(), &session_endpoint);
    let (to_server, from_test) = tokio::sync::mpsc::channel(8);
    let client = tg_store::session::SessionClient::with_channel(channel);
    let _incoming = client
        .open(tokio_stream::wrappers::ReceiverStream::new(from_test))
        .await
        .expect("session");

    to_server
        .send(tg_store::session::NodeMessage::Hello { applied: 0 })
        .await
        .expect("Hello");

    // **Instance 1 runs stale, instance 0 does not.** Both run -- stale is a
    // statement, no state beside it (ADR-0070, determination 5).
    to_server
        .send(tg_store::session::NodeMessage::Report(Box::new(
            tg_store::session::NodeReport {
                applied: 0,
                states: vec![
                    (
                        "api".to_owned(),
                        0,
                        tg_store::session::InstanceState::Running,
                    ),
                    (
                        "api".to_owned(),
                        1,
                        tg_store::session::InstanceState::Running,
                    ),
                ],
                stale: vec![("api".to_owned(), 1)],
                unready: Vec::new(),
                failures: Vec::new(),
                isolated: Vec::new(),
                capacity: tg_consensus::Resources::default(),
                generations: tg_consensus::Generations::default(),
                proxy_image: None,
                endpoints: Vec::new(),
                dns_zone: None,
                userns: None,
                retired: Vec::new(),
            },
        )))
        .await
        .expect("report");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the statement never arrived in the read path"
        );

        if let Ok(view) = admin.projection().await
            && let Some(api) = view.workloads.iter().find(|entry| entry.name == "api")
            && !api.stale.is_empty()
        {
            assert_eq!(api.stale, vec![1], "only instance 1 runs stale");
            // **And it still counts as running.** If it fell out of `instances`,
            // the statement would take the instance's state from it -- and thereby
            // its address from the resolver.
            assert!(
                api.instances.contains(&(1, "running".to_owned())),
                "stale means running: {:?}",
                api.instances
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// **Why an instance failed reaches the leader's read path** (ADR-0015).
///
/// The seam: report -> `absorb` -> projection -> the admin service's answer.
/// Checked at a **real** `tgd`, because exactly in between lie the places a
/// provided service does not have.
///
/// What travels is the **class**, not the text: it is enumerable and says *where*
/// to look. The text names names from a payload and stays in the node's log -- in
/// the report it would be an unbounded value in a message every pass carries.
///
/// And the instance still counts as **failed**: the class is a statement, no state
/// beside it.
#[tokio::test]
async fn a_failure_class_reaches_the_leaders_read_path() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let (_control_plane, admin) = leader(cp_dir.path(), port, cluster_port, session_port).await;
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
    let agent_dir = admitted(&admin, cp_dir.path()).await;

    // The workload must be declared, otherwise there is no line the statement
    // could hang on.
    let applied = admin
        .write(Command::UpsertWorkload {
            document: hungry("api", 100),
        })
        .await
        .expect("write");
    assert!(
        matches!(
            applied,
            WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                ..
            }
        ),
        "{applied:?}"
    );

    let channel = node_channel(agent_dir.path(), &session_endpoint);
    let (to_server, from_test) = tokio::sync::mpsc::channel(8);
    let client = tg_store::session::SessionClient::with_channel(channel);
    let _incoming = client
        .open(tokio_stream::wrappers::ReceiverStream::new(from_test))
        .await
        .expect("session");

    to_server
        .send(tg_store::session::NodeMessage::Hello { applied: 0 })
        .await
        .expect("Hello");

    // **Instance 1 has failed, instance 0 runs.** The class stands beside it, not
    // in place of the state.
    to_server
        .send(tg_store::session::NodeMessage::Report(Box::new(
            tg_store::session::NodeReport {
                applied: 0,
                states: vec![
                    (
                        "api".to_owned(),
                        0,
                        tg_store::session::InstanceState::Running,
                    ),
                    (
                        "api".to_owned(),
                        1,
                        tg_store::session::InstanceState::Failed,
                    ),
                ],
                stale: Vec::new(),
                unready: Vec::new(),
                failures: vec![("api".to_owned(), 1, "pull".to_owned())],
                isolated: Vec::new(),
                capacity: tg_consensus::Resources::default(),
                generations: tg_consensus::Generations::default(),
                proxy_image: None,
                endpoints: Vec::new(),
                dns_zone: None,
                userns: None,
                retired: Vec::new(),
            },
        )))
        .await
        .expect("report");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the statement never arrived in the read path"
        );

        // **What is waited for is both, not one of them.** The witness checks two
        // facts -- the class **and** the state beside it --, and although they
        // arrive in **one** report they do not reach the read path in one go:
        // `absorb` writes them one after the other, and the projection holds
        // `failures` and `actual` under **two** locks (`tg_store::projection`).
        // Whoever reads in between sees the class already and the state not yet.
        // Waiting for the first and assuring the second therefore yields a witness
        // that tips over under load -- measured in the full workspace run, green
        // on its own.
        //
        // The tear is permitted to the read path: `actual` is eventual (ADR-0004).
        // The witness must endure it, not forbid it.
        if let Ok(view) = admin.projection().await
            && let Some(api) = view.workloads.iter().find(|entry| entry.name == "api")
            && !api.failures.is_empty()
            && api.instances.contains(&(1, "failed".to_owned()))
        {
            assert_eq!(
                api.failures,
                vec![(1, "pull".to_owned())],
                "the class must arrive, and only for instance 1"
            );
            // **And the state stays standing beside it.** If it fell away, the
            // statement would take the instance's state from it -- and a tool that
            // reads the column would see an instance without anything.
            assert!(
                api.instances.contains(&(1, "failed".to_owned())),
                "the class is a statement beside the state: {:?}",
                api.instances
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// **The readiness reaches the leader's read path** (ADR-0080, determination 8).
///
/// # Why this witness stands here and not in `tgctl`
///
/// `tgctl`'s test rig **provides** the admin service and lays the answer down --
/// it cannot see `absorb` at all. What is checkable only here is the seam: report
/// -> `absorb` -> projection -> the service's answer, against a **real** `tgd`.
///
/// # What hung on it
///
/// The leader computed `RemoteEndpoint::healthy` from the reported states alone,
/// and an unready instance reports itself as `Running` (determination 1). A
/// **foreign** node thereby offered its address while its **own** kept it quiet --
/// visibly different answers for the same name, depending on who asks.
#[tokio::test]
async fn an_unready_instance_reaches_the_leaders_read_path() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let (_control_plane, admin) = leader(cp_dir.path(), port, cluster_port, session_port).await;
    let session_endpoint = format!("http://127.0.0.1:{session_port}");
    let agent_dir = admitted(&admin, cp_dir.path()).await;

    // The workload must be declared, otherwise there is no line the statement
    // could hang on.
    let applied = admin
        .write(Command::UpsertWorkload {
            document: hungry("api", 100),
        })
        .await
        .expect("write");
    assert!(
        matches!(
            applied,
            WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                ..
            }
        ),
        "{applied:?}"
    );

    let channel = node_channel(agent_dir.path(), &session_endpoint);
    let (to_server, from_test) = tokio::sync::mpsc::channel(8);
    let client = tg_store::session::SessionClient::with_channel(channel);
    let _incoming = client
        .open(tokio_stream::wrappers::ReceiverStream::new(from_test))
        .await
        .expect("session");

    to_server
        .send(tg_store::session::NodeMessage::Hello { applied: 0 })
        .await
        .expect("Hello");

    // **Instance 0 is unready, both run.** The statement stands beside it, not in
    // place of the state (ADR-0080, determination 1).
    to_server
        .send(tg_store::session::NodeMessage::Report(Box::new(
            tg_store::session::NodeReport {
                applied: 0,
                states: vec![
                    (
                        "api".to_owned(),
                        0,
                        tg_store::session::InstanceState::Running,
                    ),
                    (
                        "api".to_owned(),
                        1,
                        tg_store::session::InstanceState::Running,
                    ),
                ],
                stale: Vec::new(),
                unready: vec![("api".to_owned(), 0)],
                failures: Vec::new(),
                isolated: Vec::new(),
                capacity: tg_consensus::Resources::default(),
                generations: tg_consensus::Generations::default(),
                proxy_image: None,
                endpoints: Vec::new(),
                dns_zone: None,
                userns: None,
                retired: Vec::new(),
            },
        )))
        .await
        .expect("report");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the statement never arrived in the read path"
        );

        if let Ok(view) = admin.projection().await
            && let Some(api) = view.workloads.iter().find(|entry| entry.name == "api")
            && !api.unready.is_empty()
        {
            assert_eq!(
                api.unready,
                vec![0],
                "the readiness must arrive, and only for instance 0"
            );
            // **And both still run** (determination 1). That is the half that
            // counts: an unready instance must not lose its state, otherwise the
            // leader reads "never seen" instead of "runs" -- and the clearer
            // (ADR-0058) would have one instance less in the wanted set.
            assert_eq!(
                api.instances,
                vec![(0, "running".to_owned()), (1, "running".to_owned())],
                "unready is a statement beside the state, no state"
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The active role as the sidecar reads it: epoch and deadline.
///
/// **With its reader**, not with a rebuilt one. One of our own stood here once,
/// and measured it was a different one in *both* directions:
///
/// | Line | the sidecar | the rebuild |
/// |---|---|---|
/// | `journal 3 178…` | active | active |
/// | `journal 3 178… extra` | **passive** | active |
/// | `  journal 3 178…` | active | **nothing** |
///
/// The first deviation is the dangerous one, and it is the case ADR-0066
/// determination 3 provides for: adding a fourth field would be a format change,
/// `from_text` would afterwards skip **every** line -- no single writer would talk
/// any more --, and a witness with its own reader would stay green.
///
/// `now = 0` reads the line **without** judging it: what matters here is what
/// stands there (epoch stable, deadline growing), not whether it applies right
/// now.
fn active_role(dir: &Path) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(dir.join("network").join("active-role")).ok()?;
    let roles = tg_proxy::role::Roles::from_text(&text);
    let tg_proxy::role::ActiveRole::Active { epoch } = roles.role_of("journal", 0) else {
        return None;
    };
    Some((epoch, roles.expires_at("journal")?))
}

/// Runs a control plane on the named ports and data directory.
///
/// `init` only at the **first** start: afterwards the membership stands in the
/// log, and a second `--init` would be a statement about a state that exists.
fn control_plane(dir: &Path, admin: u16, cluster: u16, session: u16, init: bool) -> Running {
    let mut command = OsCommand::new(binary("tgd"));
    command.args([
        "--telemetry-addr",
        "off",
        "--id",
        "1",
        "--node",
        "tgd-1",
        "--listen",
        &format!("127.0.0.1:{admin}"),
        "--cluster-listen",
        &format!("127.0.0.1:{cluster}"),
        "--node-listen",
        &format!("127.0.0.1:{session}"),
        "--data-dir",
        dir.to_str().expect("path"),
        "--peer",
        &format!("1=http://127.0.0.1:{cluster}"),
    ]);
    if init {
        command.arg("--init");
    }
    Running(
        command
            .stdout(support::log("tgd"))
            .stderr(support::log("tgd"))
            .spawn()
            .expect("tgd startable"),
    )
}

/// **A single writer comes back on its own after a restart of the control
/// plane** -- and how long that takes is thereby measured.
///
/// # Why this test exists
///
/// `docs/OPERATIONS.md` promises two things for the maintenance window from
/// ADR-0072, and **neither** of them was guarded:
///
/// > Single writers come back **on their own** as soon as the session stands
/// > again; no intervention is necessary.
///
/// And ADR-0072 names the number for it as an open point: *"The length of the
/// window is not measured."* Both hang on the same stretch -- election, catching
/// up, session, one scheduler cadence (ADR-0064) --, and it has many links that
/// are checked individually and together never.
///
/// # What the test assures, and what it only reports
///
/// Assured is the **return without intervention**: nobody issues a lease, nobody
/// restarts the agent, and the deadline in the sidecar's role format (ADR-0066)
/// lies **later** afterwards than before. The measured duration is printed and not
/// assured: a wall-clock bound would be the sort of seam wobbling tests arise
/// from. The patience is the backstop -- it catches the case that the role
/// **never** comes back.
///
/// Likewise only reported is **how** it came back: the same epoch means renewed
/// (the restart was faster than the lease), a higher one means the node fenced
/// itself in the meantime and got a new role. That is exactly the question an
/// operator has when planning the window -- and it hangs on a number the test
/// machine determines.
#[tokio::test(flavor = "multi_thread")]
async fn a_single_writer_comes_back_after_a_control_plane_restart() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let admin_port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();

    let first = control_plane(cp_dir.path(), admin_port, cluster_port, session_port, true);

    let admin = AdminClient::connect_unix(&tgd::admin::socket_path(cp_dir.path(), 1))
        .expect("admin socket");
    await_leadership(&admin, &first).await;

    let agent_dir = tempfile::tempdir().expect("tempdir");
    seed_single_writer(&admin, agent_dir.path(), cp_dir.path(), "node-31").await;

    let _agent = agent(agent_dir.path(), "node-31", admin_port, session_port);

    // The starting state: the role is there, granted by the leader without anybody
    // having asked for it (ADR-0064).
    //
    // A `||` fallback with a discarded `await_content` stood here. It was a
    // **saving** and no second condition: if the role already lies there, the file
    // contains `journal `, and the waiting point returns at once. What it cost is
    // the diagnosis -- `await_content` does not panic on a timeout, and without the
    // return value the message says only that nothing came, and not what stood
    // there.
    let seen = await_content(
        &agent_dir.path().join("network").join("active-role"),
        "journal ",
    );
    assert!(
        active_role(agent_dir.path()).is_some(),
        "the active role never arrived: '{seen}'"
    );
    let (epoch, before) = active_role(agent_dir.path()).expect("assured above");

    // **The restart.** No intervention at the agent -- it runs on and must rebuild
    // its session itself (ADR-0040: the node establishes it).
    let started = Instant::now();
    drop(first);
    let _restarted = control_plane(cp_dir.path(), admin_port, cluster_port, session_port, false);

    // **Two numbers, and they measure different things.** The first is the
    // recovery: the node has rebuilt its session, and the leader has a fresh
    // report (ADR-0057) -- that is what `tgctl cluster nodes` shows an operator as
    // "last" and what OPERATIONS 6.1 names as step 4. The second is the **renewal
    // cadence**: renewal happens only in the second half of the deadline
    // (ADR-0064), so the deadline moves later even when everything has long been
    // running again. Whoever measured only the second would take a cadence for a
    // downtime.
    let admin = AdminClient::connect_unix(&tgd::admin::socket_path(cp_dir.path(), 1))
        .expect("admin socket");

    // The **third** number, and the only one an operator can influence: how long
    // the process needs until it leads again. Everything after that is cadences --
    // the reporting period (ADR-0068) and the renewal in the second half of the
    // deadline (ADR-0064).
    let deadline = Instant::now() + PATIENCE;
    let leading = loop {
        if let Ok(status) = admin.status().await
            && status.leader == Some(1)
        {
            break started.elapsed();
        }
        assert!(Instant::now() < deadline, "no leadership after the restart");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let restarted_at = now();
    let deadline = Instant::now() + PATIENCE;
    let session_back = loop {
        if let Ok(view) = admin.projection().await
            && view
                .nodes
                .iter()
                .any(|node| node.name == "node-31" && node.last_report >= Some(restarted_at))
        {
            break started.elapsed();
        }
        assert!(
            Instant::now() < deadline,
            "the node did not rebuild its session after the restart -- from the \
             outside it would look like a mute one (OPERATIONS 6.1)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let deadline = Instant::now() + PATIENCE;
    let recovered = loop {
        if let Some((now_epoch, after)) = active_role(agent_dir.path())
            && after > before
        {
            break (now_epoch, after, started.elapsed());
        }
        assert!(
            Instant::now() < deadline,
            "the active role did not come back after the restart -- a single \
             writer would stand forever (OPERATIONS 6.1)"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let (after_epoch, after, took) = recovered;
    eprintln!(
        "MEASUREMENT leadership: {}ms · session back: {:.1}s · deadline moved: \
         {:.1}s (epoch {epoch} -> {after_epoch}, {before} -> {after}) -- {}",
        leading.as_millis(),
        session_back.as_secs_f64(),
        took.as_secs_f64(),
        if after_epoch == epoch {
            "renewed, the restart was faster than the lease"
        } else {
            "newly granted, the node had fenced itself"
        }
    );
}

/// Enters a node and a single writer as an operator would.
///
/// Extracted because the setup is not the subject: what is checked is what
/// happens after a restart.
async fn seed_single_writer(admin: &AdminClient, agent_dir: &Path, cp_dir: &Path, node: &str) {
    let spki = agent_cluster_material(agent_dir, cp_dir);
    let token = tg_consensus::generate_token();

    for command in [
        // **Two invitations, and that is no oversight.** `AdmitNode` **consumes**
        // the invitation (ADR-0037: check and consumption in the same apply), so
        // the agent needs a second one -- the first therefore carries a digest
        // nobody redeems.
        Command::InviteNode {
            node: node.to_owned(),
            digest: tg_consensus::token_digest("whatever-the-test-does-not-redeem"),
            expires_at: now() + 900,
        },
        Command::AdmitNode {
            node: node.to_owned(),
            spki,
            at: now(),
        },
        Command::UpsertNode {
            name: node.to_owned(),
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
            cidr: "10.99.0.0/16".to_owned(),
            node_prefix: 24,
        },
        Command::UpsertWorkload {
            document: single_writer("journal"),
        },
        Command::AssignPlacement {
            workload: "journal".to_owned(),
            instance: 0,
            node: node.to_owned(),
        },
    ] {
        let kind = command.kind();
        let result = admin.write(command).await.expect("call");
        assert!(
            matches!(
                result,
                WriteResult::Applied {
                    outcome: tg_consensus::Outcome::Applied,
                    ..
                }
            ),
            "'{kind}' was not applied: {result:?}"
        );
    }
    // And the invitation the agent really redeems.
    let result = admin
        .write(Command::InviteNode {
            node: node.to_owned(),
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

    bare_node(agent_dir, &token);
}

/// Runs an agent, like the neighbouring test beside it.
///
/// An address space of its own per test file: `cargo test` runs the test binaries
/// concurrently, and two agents with the same default fought over the bridge
/// address and the resolver port.
fn agent(dir: &Path, node: &str, admin_port: u16, session_port: u16) -> Running {
    let path = env!("PATH");
    Running(
        OsCommand::new(binary("tg-agent"))
            .args([
                "--telemetry-addr",
                "off",
                "--data-dir",
                dir.to_str().expect("path"),
                "--interval",
                "1",
                "--cluster-cidr",
                "10.47.0.0/16",
                "--node",
                node,
                "--control-plane",
                &format!("http://127.0.0.1:{admin_port}"),
                "--node-session",
                &format!("http://127.0.0.1:{session_port}"),
            ])
            .env("PATH", format!("{}:{path}", dir.join("stub").display()))
            .stdout(support::log("tg-agent"))
            .stderr(support::log("tg-agent"))
            .spawn()
            .expect("tg-agent startable"),
    )
}

/// Waits until this node leads.
async fn await_leadership(admin: &AdminClient, node: &support::Running) {
    let deadline = Instant::now() + PATIENCE;
    loop {
        // A dead process is no condition: without this line the loop waits out its
        // whole deadline and afterwards reports the wrong cause.
        support::assert_alive("the control plane", node.0.id());
        assert!(Instant::now() < deadline, "no leadership");
        if let Ok(status) = admin.status().await
            && status.leader == Some(1)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// **A single writer holds its active role through with the default
/// configuration** (ADR-0076).
///
/// # The finding there was
///
/// The holder's safety margin carried `--interval`: the detection latency was a
/// whole reconcile pass. With the default of ten seconds plus two seconds of fence
/// deadline it became larger than the remaining time a lease falls to in the
/// steady state (`lease/2 - tick`) -- and measured a **healthy** single writer
/// counted as fenced two thirds of the time:
///
/// ```text
/// 10.1s role=1 … 20.2s role=1 · 21.2s role=0 … 39.3s role=0 · 40.4s role=1
/// ```
///
/// Its container was therefore stopped (ADR-0058) and started again at the next
/// pass -- a fluttering single writer, exactly what ADR-0064 was meant to prevent.
///
/// # Why the witness stands here and not in `tg-model`
///
/// The arithmetic is checked there
/// (`a_holder_never_fences_across_a_renewal_cycle`), and a test at **one** point
/// in time let this error through. What only a process witness shows is the
/// interplay of the three cadences: the leader renews by its clock, the slice
/// travels, and the agent evaluates by its own sleep. Hence: a real `tgd`, a real
/// `tg-agent`, the **default interval**, and the metric sampled.
///
/// # Why it costs time
///
/// The error showed itself around eleven seconds after the role had appeared --
/// one lease length. Sampling more briefly would mean not seeing it. A test that
/// substantiates a security property of the default configuration may take twenty
/// seconds.
#[tokio::test(flavor = "multi_thread")]
async fn a_single_writer_keeps_its_role_with_the_default_interval() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let admin_port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();
    let telemetry = support::free_port();

    let control_plane = control_plane(cp_dir.path(), admin_port, cluster_port, session_port, true);
    let admin = AdminClient::connect_unix(&tgd::admin::socket_path(cp_dir.path(), 1))
        .expect("admin socket");
    await_leadership(&admin, &control_plane).await;

    let agent_dir = tempfile::tempdir().expect("tempdir");
    seed_single_writer(&admin, agent_dir.path(), cp_dir.path(), "node-31").await;

    // **Without `--interval`**, and that is the subject: the default applies.
    let path = env!("PATH");
    let _agent = Running(
        OsCommand::new(binary("tg-agent"))
            .args([
                "--telemetry-addr",
                &format!("127.0.0.1:{telemetry}"),
                "--data-dir",
                agent_dir.path().to_str().expect("path"),
                "--cluster-cidr",
                "10.49.0.0/16",
                "--node",
                "node-31",
                "--control-plane",
                &format!("http://127.0.0.1:{admin_port}"),
                "--node-session",
                &format!("http://127.0.0.1:{session_port}"),
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

    let role = || {
        std::process::Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "2",
                &format!("http://127.0.0.1:{telemetry}/metrics"),
            ])
            .output()
            .ok()
            .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
            .and_then(|text| {
                text.lines()
                    .find(|line| {
                        line.starts_with(tg_telemetry::names::ACTIVE_ROLE)
                            && line.contains("journal")
                    })
                    .and_then(|line| line.rsplit(' ').next().map(std::borrow::ToOwned::to_owned))
            })
    };

    // First it must appear at all -- nobody asked for it, the leader grants it of
    // its own accord (ADR-0064).
    let deadline = Instant::now() + PATIENCE;
    loop {
        assert!(Instant::now() < deadline, "the active role never appeared");
        if role().as_deref() == Some("1") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // And then it must **stay**. One lease length plus reserve: the finding showed
    // itself around eleven seconds after it appeared.
    let watching = Instant::now();
    let mut samples = 0_u32;
    while watching.elapsed() < Duration::from_secs(20) {
        let seen = role();
        assert_ne!(
            seen.as_deref(),
            Some("0"),
            "the single writer lost its active role after {:.1}s although \
             nobody failed (ADR-0076)",
            watching.elapsed().as_secs_f64()
        );
        samples += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Without this assurance the test would be green too if the endpoint had
    // delivered nothing -- the finding from the mutation test rig.
    assert!(samples >= 30, "too few samples: {samples}");
}

/// **The holder fences in time, with a large `--interval` too** (ADR-0076,
/// determinations 1 and 6).
///
/// That is the **security direction** of the same change, and it is the more
/// important one: the margin now covers only a small floor instead of a reconcile
/// interval. If the comparison went on sleeping stubbornly for `--interval`, the
/// holder would notice the expiry correspondingly late and would run **beyond the
/// deadline** -- and the leader grants anew on expiry. Two active writers are
/// exactly what ADR-0064 excludes.
///
/// The setup makes a statement of it: `--interval 60`, then the control plane
/// dies. Nobody renews, the lease lapses within fifteen seconds, and the holder
/// must fence **on its own** -- with a sleep of sixty seconds it could not do
/// that.
#[tokio::test(flavor = "multi_thread")]
async fn the_holder_fences_in_time_despite_a_long_interval() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let admin_port = support::free_port();
    let cluster_port = support::free_port();
    let session_port = support::free_port();
    let telemetry = support::free_port();

    let leader = control_plane(cp_dir.path(), admin_port, cluster_port, session_port, true);
    let admin = AdminClient::connect_unix(&tgd::admin::socket_path(cp_dir.path(), 1))
        .expect("admin socket");
    await_leadership(&admin, &leader).await;

    let agent_dir = tempfile::tempdir().expect("tempdir");
    seed_single_writer(&admin, agent_dir.path(), cp_dir.path(), "node-31").await;

    let path = env!("PATH");
    let _agent = Running(
        OsCommand::new(binary("tg-agent"))
            .args([
                "--telemetry-addr",
                &format!("127.0.0.1:{telemetry}"),
                "--data-dir",
                agent_dir.path().to_str().expect("path"),
                // **Sixty seconds**, and that is the subject: the fence must not
                // hang on it.
                "--interval",
                "60",
                "--cluster-cidr",
                "10.50.0.0/16",
                "--node",
                "node-31",
                "--control-plane",
                &format!("http://127.0.0.1:{admin_port}"),
                "--node-session",
                &format!("http://127.0.0.1:{session_port}"),
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

    let role = || {
        std::process::Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "2",
                &format!("http://127.0.0.1:{telemetry}/metrics"),
            ])
            .output()
            .ok()
            .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
            .and_then(|text| {
                text.lines()
                    .find(|line| {
                        line.starts_with(tg_telemetry::names::ACTIVE_ROLE)
                            && line.contains("journal")
                    })
                    .and_then(|line| line.rsplit(' ').next().map(std::borrow::ToOwned::to_owned))
            })
    };

    let deadline = Instant::now() + PATIENCE;
    loop {
        assert!(Instant::now() < deadline, "the active role never appeared");
        if role().as_deref() == Some("1") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // **Nobody renews any more.** The lease still carries for up to fifteen
    // seconds; afterwards the holder must stop without anybody telling it
    // (ADR-0010: the self-fence is autonomous).
    drop(leader);
    let killed = Instant::now();
    let deadline = killed + Duration::from_secs(20);
    loop {
        if role().as_deref() == Some("0") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the holder did not fence itself {:.0}s after the failure -- with a \
             sleep of 60s it notices the expiry much later, and the leader \
             grants anew on expiry (ADR-0064)",
            killed.elapsed().as_secs_f64()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!(
        "MEASUREMENT fence after the failure: {:.1}s (lease 15s, margin {}ms)",
        killed.elapsed().as_secs_f64(),
        tg_model::lease::FENCE_MARGIN_MILLIS
    );
}

/// A node's ports: admin, cluster, session.
struct NodePorts {
    id: u64,
    admin: u16,
    cluster: u16,
    session: u16,
}

/// Two nodes with membership `{1,2}`: both run, one leads.
///
/// Returns the ports (admin, cluster, session per node) and keeps the processes
/// alive as long as the return value lives.
fn two_nodes(dir: &Path) -> (Vec<NodePorts>, Vec<Running>) {
    let ports: Vec<NodePorts> = (1..=2)
        .map(|id| NodePorts {
            id,
            admin: support::free_port(),
            cluster: support::free_port(),
            session: support::free_port(),
        })
        .collect();
    let peers: Vec<String> = ports
        .iter()
        .map(|node| format!("{}=http://127.0.0.1:{}", node.id, node.cluster))
        .collect();

    // **Peer leaves** (ADR-0043): without them no Raft handshake comes about, and
    // two nodes elect nobody.
    let identity = dir.join("identity");
    std::fs::create_dir_all(&identity).expect("directory");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    std::fs::write(identity.join("node.key.pem"), key.serialize_pem()).expect("key");
    let peer_dir = dir.join("peers");
    std::fs::create_dir_all(&peer_dir).expect("directory");
    for node in &ports {
        let sid = tg_identity::SpiffeId::for_node(
            &tg_identity::TrustDomain::new("cluster.local").expect("domain"),
            &format!("tgd-{}", node.id),
        )
        .expect("ID");
        let pem = tg_identity::cluster::node_leaf_pem(&key, &sid).expect("leaf");
        std::fs::write(peer_dir.join(format!("{}.pem", node.id)), pem).expect("leaf");
    }

    let mut running = Vec::new();
    for node in &ports {
        let mut command = OsCommand::new(binary("tgd"));
        command.args([
            "--telemetry-addr",
            "off",
            "--id",
            &node.id.to_string(),
            "--node",
            &format!("tgd-{}", node.id),
            "--listen",
            &format!("127.0.0.1:{}", node.admin),
            "--cluster-listen",
            &format!("127.0.0.1:{}", node.cluster),
            "--node-listen",
            &format!("127.0.0.1:{}", node.session),
            "--data-dir",
            dir.to_str().expect("path"),
        ]);
        for peer in &peers {
            command.args(["--peer", peer]);
        }
        // Exactly one creates the membership -- it is a log entry.
        if node.id == 1 {
            command.arg("--init");
        }
        running.push(Running(
            command
                .stdout(support::log("tgd"))
                .stderr(support::log("tgd"))
                .spawn()
                .expect("tgd startable"),
        ));
    }

    (ports, running)
}

/// Which of the two leads.
async fn which_leads(dir: &Path, ports: &[NodePorts]) -> u64 {
    let deadline = Instant::now() + PATIENCE;
    loop {
        assert!(Instant::now() < deadline, "no leadership");
        for node in ports {
            if let Ok(admin) = AdminClient::connect_unix(&tgd::admin::socket_path(dir, node.id))
                && let Ok(status) = admin.status().await
                && let Some(who) = status.leader
            {
                return who;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// **An agent pointed at a follower finds the leader** (ADR-0077).
///
/// # The finding
///
/// Both ways to the control plane go to the leader, and a follower answers with a
/// **referral** (ADR-0040, ADR-0037). The referral carries an **identifier**, no
/// address -- and the agent knew exactly **one** address per way. It reported
/// "this node does not lead; the leader is 1" and tried the same address again.
///
/// Measured with exactly this setup: twenty-five seconds, **no slice**. ADR-0040
/// names as the price "a gap during every election" -- the gap was permanent, and
/// with it withdrawals (ADR-0025), active-role leases (ADR-0064) and tombstones
/// (ADR-0042) stayed away.
///
/// # Why the setup needs two nodes
///
/// With one there is no follower. The error is therefore invisible in every
/// one-node test -- and that is the reason it stayed unnoticed for a year and a
/// half.
#[tokio::test(flavor = "multi_thread")]
async fn an_agent_pointed_at_a_follower_finds_the_leader() {
    let cp_dir = tempfile::tempdir().expect("tempdir");
    let _anchor = signing_material(cp_dir.path());
    let (ports, _cluster) = two_nodes(cp_dir.path());

    let leader = which_leads(cp_dir.path(), &ports).await;
    let follower = ports
        .iter()
        .find(|node| node.id != leader)
        .expect("a follower");

    let admin = AdminClient::connect_unix(&tgd::admin::socket_path(cp_dir.path(), leader))
        .expect("admin socket");
    let agent_dir = tempfile::tempdir().expect("tempdir");
    seed_single_writer(&admin, agent_dir.path(), cp_dir.path(), "node-31").await;

    // **The anchor covers all endpoints** (ADR-0077, determination 7). With a list
    // of addresses the agent needs the leaves of **all** nodes:
    // `anchors_from_pem` reads several blocks, and with only one the handshake to
    // every other one fails with `UnknownIssuer`. Measured, that was the second
    // half of the finding.
    let mut anchors = String::new();
    for node in &ports {
        anchors.push_str(
            &std::fs::read_to_string(cp_dir.path().join("peers").join(format!("{}.pem", node.id)))
                .expect("peer leaf"),
        );
    }
    std::fs::write(
        agent_dir
            .path()
            .join(tg_identity::layout::DIR)
            .join(tg_identity::layout::CONTROL_PLANE),
        &anchors,
    )
    .expect("anchor");

    // **Only the follower, and it stands first.** The leader stands after it in
    // the list -- exactly the setting an operator makes: all nodes.
    let leading = ports.iter().find(|node| node.id == leader).expect("leader");
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
                "--cluster-cidr",
                "10.51.0.0/16",
                "--node",
                "node-31",
                "--control-plane",
                &format!("http://127.0.0.1:{}", follower.admin),
                "--control-plane",
                &format!("http://127.0.0.1:{}", leading.admin),
                "--node-session",
                &format!("http://127.0.0.1:{}", follower.session),
                "--node-session",
                &format!("http://127.0.0.1:{}", leading.session),
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

    // The slice must arrive although the **first** entry is the wrong one. Without
    // the rotation it never comes.
    let document = await_content(
        &agent_dir.path().join("desired").join("journal.xml"),
        "journal",
    );
    assert!(
        document.contains("journal"),
        "the slice did not arrive although the leader stands in the list: \
         '{document}'"
    );

    // And the active role with it -- it is the evidence that the session really
    // lies at the **leader**: only it grants one (ADR-0064).
    let roles = await_content(
        &agent_dir.path().join("network").join("active-role"),
        "journal ",
    );
    // The same mark as above, and that is no accident: `await_content` does not
    // panic on a timeout, it returns what it last saw -- the line is thereby the
    // **catcher** and not a repetition. It was weaker than the waiting condition
    // (`journal` against `journal `), so a file with `journalX 5 123` would have
    // satisfied it.
    assert!(roles.contains("journal "), "active role: '{roles}'");

    // **And the credential path**, which has a list of its own and does not hang
    // on the session: the join writes the agent intermediate (ADR-0037). Without
    // rotation it would meet only the follower -- and after twelve hours no SVID
    // of this node would be accepted any more (ADR-0014).
    let intermediate = await_content(
        &agent_dir
            .path()
            .join(tg_identity::layout::DIR)
            .join(tg_identity::layout::INTERMEDIATE),
        "BEGIN CERTIFICATE",
    );
    assert!(
        intermediate.contains("BEGIN CERTIFICATE"),
        "the join did not leave the follower: '{intermediate}'"
    );
}

/// A workload that waits on **itself**.
///
/// The state machine accepts it -- it builds no graph, and it cannot build one: an
/// `UpsertWorkload` carries exactly one workload (ADR-0004), and the set is
/// complete only at the end. The **node** isolates it (ADR-0062: self-reference),
/// and because the cluster still names it, every slice writes it back -- the
/// isolation is thereby a state and no race.
fn self_referencing(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"{name}\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/{name}:1.0\"/>\n\
         \x20   <dependencies>\n\
         \x20     <after ref=\"{name}\"/>\n\
         \x20   </dependencies>\n\
         \x20 </workload>\n\
         </workloads>\n"
    )
}
