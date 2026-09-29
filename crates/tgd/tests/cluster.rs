//! Five real processes (phase 5c).
//!
//! That is the difference from phase 5b: there five nodes ran in one process over
//! a bus, here five operating-system processes run over real gRPC. The test proves
//! **integration** -- that serialization, connection setup, addressing and process
//! boundaries fit together. Correctness under faults comes from 5b and is not
//! repeated here.
//!
//! The leader is ended with `SIGKILL`, not shut down cleanly. A proper ending
//! would miss the case: what is checked is that a node disappears without being
//! able to clear anything up -- and that the rest carries on without anything
//! missing from the desired state.

use std::path::PathBuf;
use std::process::{Child, Command as OsCommand};
use std::time::{Duration, Instant};

use tg_consensus::{Command, NodeId, Outcome, Topology};
use tgd::admin::{AdminClient, WriteResult};

mod support;

/// How long an expected state is waited for.
///
/// Generous: with the start profile from ADR-0033 (election 500-1000 ms) an
/// election takes under a second, but the test runs on a machine that does other
/// things too.
const PATIENCE: Duration = Duration::from_secs(30);

fn document(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\">\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

fn upsert(name: &str) -> Command {
    Command::UpsertWorkload {
        document: document(name),
    }
}

fn node_command(name: &str) -> Command {
    Command::UpsertNode {
        name: name.to_owned(),
        topology: Topology {
            site: "fra".to_owned(),
            hall: "h1".to_owned(),
            rack: "r7".to_owned(),
        },
        capacity: tg_consensus::Resources::default(),
        reserved: tg_consensus::Resources::default(),
        source: tg_consensus::Origin::Operator,
    }
}

/// Five processes, one throwaway directory.
struct Cluster {
    children: Vec<(NodeId, Child)>,
    /// Where each node's metrics lie.
    ///
    /// The ports existed here already -- they were only noted nowhere, and without
    /// them a metric of the replication cannot be read (ADR-0033).
    telemetry: Vec<(NodeId, u16)>,
    clients: Vec<(NodeId, AdminClient)>,
    size: usize,
    data_dir: PathBuf,
    _dir: tempfile::TempDir,
}

impl Cluster {
    fn start(size: NodeId) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();

        // Three ports per node (ADR-0043, determination 4). `--peer` now points
        // at the **cluster** port: Raft lies there, no longer on `--listen`.
        let ports: Vec<(NodeId, u16, u16, u16)> = (1..=size)
            .map(|id| {
                (
                    id,
                    support::free_port(),
                    support::free_port(),
                    support::free_port(),
                )
            })
            .collect();
        let peers: Vec<String> = ports
            .iter()
            .map(|(id, _, cluster, _)| format!("{id}=http://127.0.0.1:{cluster}"))
            .collect();

        support::cluster_material(
            &data_dir,
            &ports.iter().map(|(id, ..)| *id).collect::<Vec<_>>(),
        );

        let mut children = Vec::new();
        let mut clients = Vec::new();
        let mut telemetry = Vec::new();

        for (id, port, cluster, session) in &ports {
            let telemetry_port = support::free_port();
            telemetry.push((*id, telemetry_port));
            let mut command = OsCommand::new(env!("CARGO_BIN_EXE_tgd"));
            command
                .arg("--id")
                .arg(id.to_string())
                .arg("--node")
                .arg(format!("tgd-{id}"))
                .arg("--listen")
                .arg(format!("127.0.0.1:{port}"))
                .arg("--cluster-listen")
                .arg(format!("127.0.0.1:{cluster}"))
                .arg("--node-listen")
                .arg(format!("127.0.0.1:{session}"))
                .arg("--data-dir")
                .arg(&data_dir)
                // A port of its own per node. Without that five processes bind
                // the same default, and four fail -- fail-soft does catch it, but
                // a test that lives off fail-soft no longer checks what it is
                // supposed to check (the same finding as in 10a).
                .arg("--telemetry-addr")
                .arg(format!("127.0.0.1:{telemetry_port}"));
            for peer in &peers {
                command.arg("--peer").arg(peer);
            }
            // Exactly one node creates the membership -- it is a log entry, not
            // a configuration value.
            if *id == 1 {
                command.arg("--init");
            }

            let child = command
                .stdout(support::log("tgd"))
                .stderr(support::log("tgd"))
                .spawn()
                .expect("tgd startable");

            children.push((*id, child));
            clients.push((
                *id,
                // Admin has lain on a Unix socket since ADR-0044.
                AdminClient::connect_unix(&tgd::admin::socket_path(&data_dir, *id))
                    .expect("admin socket"),
            ));
        }

        Self {
            children,
            telemetry,
            clients,
            size: ports.len(),
            data_dir,
            _dir: dir,
        }
    }

    /// Where this node's metrics lie.
    fn telemetry_of(&self, id: NodeId) -> u16 {
        let Some((_, port)) = self.telemetry.iter().find(|(node, _)| *node == id) else {
            panic!("node {id} has no telemetry port")
        };
        *port
    }

    fn client(&self, id: NodeId) -> &AdminClient {
        &self
            .clients
            .iter()
            .find(|(other, _)| *other == id)
            .expect("node")
            .1
    }

    fn running(&self) -> Vec<NodeId> {
        self.children.iter().map(|(id, _)| *id).collect()
    }

    /// Aborts when a node has ended **by itself**.
    ///
    /// # What hung on it
    ///
    /// [`Cluster::kill`] removes its child from the list, so `children` contains
    /// only nodes that are **supposed** to run. Nobody checked that: if one dies
    /// at startup, every loop waited out the full [`PATIENCE`] and then reported
    /// "missing on the nodes [3]" -- the **wrong** cause, and thirty seconds for
    /// it.
    ///
    /// Measured it was exactly that, and the cause stood in the log the test rig
    /// has been catching for a short while:
    ///
    /// ```text
    /// tgd-3: cluster credential     21:11:14.612
    /// tgd ended, error: "Server: Address already in use (os error 98)"
    ///                               21:11:14.614
    /// ```
    ///
    /// Two milliseconds after its credential it was gone -- a port conflict in the
    /// test rig, not in the product. The message now points there, and the test
    /// falls in seconds instead of in thirty.
    fn assert_all_alive(&self) {
        for (id, child) in &self.children {
            support::assert_alive(*id, child.id());
        }
    }

    /// Waits until the majority has agreed on a leader.
    ///
    /// Not "somebody takes themselves for the leader": that can be a cut-off old
    /// one too (finding from phase 5b). What is asked for is the one the majority
    /// has agreed on.
    async fn wait_for_leader(&mut self) -> NodeId {
        // A dead node is a finding, not a condition one waits for.
        self.assert_all_alive();
        let deadline = Instant::now() + PATIENCE;
        let quorum = self.size.div_ceil(2);

        loop {
            let mut votes: Vec<Option<NodeId>> = Vec::new();
            for id in self.running() {
                votes.push(
                    self.client(id)
                        .status()
                        .await
                        .ok()
                        .and_then(|status| status.leader),
                );
            }

            for candidate in self.running() {
                let agreeing = votes
                    .iter()
                    .filter(|vote| **vote == Some(candidate))
                    .count();
                if agreeing >= quorum {
                    return candidate;
                }
            }

            assert!(
                Instant::now() < deadline,
                "no leader within {PATIENCE:?}; votes: {votes:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Writes over the leader and follows referrals in the process.
    async fn write(&mut self, command: Command) -> Outcome {
        let deadline = Instant::now() + PATIENCE;

        loop {
            let leader = self.wait_for_leader().await;

            match self.client(leader).write(command.clone()).await {
                Ok(WriteResult::Applied { outcome, .. }) => return outcome,
                Ok(other) => assert!(
                    Instant::now() < deadline,
                    "the write did not get through: {other:?}"
                ),
                Err(status) => assert!(Instant::now() < deadline, "the write failed: {status}"),
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Ends a node hard.
    fn kill(&mut self, id: NodeId) {
        let index = self
            .children
            .iter()
            .position(|(other, _)| *other == id)
            .expect("the node is running");
        let (_, mut child) = self.children.remove(index);
        child.kill().expect("SIGKILL");
        child.wait().expect("ended");
    }

    /// Waits until all running nodes have applied the **node entry**.
    ///
    /// The counterpart to [`Cluster::wait_for_workload`], and it was missing. The
    /// test wrote two commands, waited for the first and checked the second -- a
    /// race that can go well for years. It became visible when mTLS on the Raft
    /// port added a handshake to the first call of a fresh connection and a
    /// follower thereby briefly fell behind. The behaviour is right -- Raft applies
    /// when it gets around to it --, the test was underdetermined.
    async fn wait_for_node(&mut self, name: &str) {
        // A dead node is a finding, not a condition one waits for.
        self.assert_all_alive();
        let deadline = Instant::now() + PATIENCE;

        loop {
            let mut missing = Vec::new();
            for id in self.running() {
                let seen = self
                    .client(id)
                    .status()
                    .await
                    .is_ok_and(|status| status.nodes.iter().any(|n| n == name));
                if !seen {
                    missing.push(id);
                }
            }

            if missing.is_empty() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the node entry '{name}' is missing on the nodes {missing:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Waits until all running nodes have applied the workload.
    async fn wait_for_workload(&mut self, name: &str) {
        // A dead node is a finding, not a condition one waits for.
        self.assert_all_alive();
        let deadline = Instant::now() + PATIENCE;

        loop {
            let mut missing = Vec::new();
            for id in self.running() {
                let seen = self
                    .client(id)
                    .status()
                    .await
                    .is_ok_and(|status| status.workloads.iter().any(|w| w == name));
                if !seen {
                    missing.push(id);
                }
            }

            if missing.is_empty() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "'{name}' is missing on the nodes {missing:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The data directory -- for the check that every node has written its own
    /// file.
    fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for (_, child) in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// **The phase's acceptance criterion.**
///
/// Five processes elect a leader; it is ended hard; the remaining four elect a
/// new one and have the desired state complete -- and afterwards take further
/// writes.
#[tokio::test(flavor = "multi_thread")]
async fn five_processes_elect_and_survive_a_leader_kill() {
    let mut cluster = Cluster::start(5);

    let first = cluster.wait_for_leader().await;
    assert!((1..=5).contains(&first));

    assert_eq!(
        cluster.write(upsert("before-the-kill")).await,
        Outcome::Applied
    );
    assert_eq!(
        cluster.write(node_command("node-1")).await,
        Outcome::Applied
    );
    cluster.wait_for_workload("before-the-kill").await;

    // Every node has its own file -- the state lies five times on the disk, not
    // once.
    for id in 1..=5 {
        assert!(
            cluster.data_dir().join(format!("raft-{id}.redb")).is_file(),
            "node {id} wrote no file"
        );
    }

    cluster.kill(first);
    assert_eq!(cluster.running().len(), 4);

    let second = cluster.wait_for_leader().await;
    assert_ne!(second, first, "the ended node still leads");

    // No data loss in the desired state: what was committed before the kill
    // stands on all surviving nodes.
    cluster.wait_for_workload("before-the-kill").await;
    cluster.wait_for_node("node-1").await;
    for id in cluster.running() {
        let status = cluster.client(id).status().await.expect("status");
        assert!(
            status.nodes.iter().any(|n| n == "node-1"),
            "node {id} is missing the node entry"
        );
        assert!(status.last_applied.is_some_and(|index| index >= 2));
    }

    // And the cluster has stayed able to act, not merely readable.
    assert_eq!(
        cluster.write(upsert("after-the-kill")).await,
        Outcome::Applied
    );
    cluster.wait_for_workload("after-the-kill").await;
}

/// The loss of **two** nodes keeps the quorum (ADR-0031) -- across real process
/// boundaries too.
#[tokio::test(flavor = "multi_thread")]
async fn two_dead_processes_keep_the_cluster_writable() {
    let mut cluster = Cluster::start(5);
    cluster.write(upsert("before")).await;

    // End a node that is not currently leading, twice: what is checked is the
    // quorum boundary, not the failover -- that stands in the test above.
    for _ in 0..2 {
        let leader = cluster.wait_for_leader().await;
        let victim = cluster
            .running()
            .into_iter()
            .find(|id| *id != leader)
            .expect("a node that does not lead");
        cluster.kill(victim);
    }

    assert_eq!(cluster.running().len(), 3);
    assert_eq!(cluster.write(upsert("after")).await, Outcome::Applied);
    cluster.wait_for_workload("after").await;
    cluster.wait_for_workload("before").await;
}

/// **The round-trip time of the replication is visible** (ADR-0033, ADR-0015).
///
/// # The open point this closes
///
/// ADR-0033 records a finding of the test rig: `openraft` uses
/// `heartbeat_interval` **at the same time** as the time bound of the replication
/// call. *"A path that is slower never replicates -- and quietly at that, because
/// the remaining nodes hold the quorum."* The ordering condition there reads
/// `RTT(p99) < heartbeat_interval`, and the left-hand side was nowhere to be
/// seen. The ADR names the remedy and delegates it: *"A guard … belongs to
/// ADR-0015."*
///
/// # Why the test stands here and not in `telemetry.rs`
///
/// Measured: a single node with unreachable peers produces **no** call. Without a
/// peer leaf the dialer builds no channel (ADR-0043), and `Link::call` reports "no
/// address entered" without leaving the process -- ten times in six seconds in the
/// log, but no measurement. A real round-trip time exists only where replication
/// really happens.
#[tokio::test(flavor = "multi_thread")]
async fn the_replication_round_trip_is_visible() {
    let mut cluster = Cluster::start(3);
    let leader = cluster.wait_for_leader().await;

    // Something that **must** be replicated -- heartbeats alone would be a weaker
    // statement.
    assert_eq!(cluster.write(upsert("measured")).await, Outcome::Applied);
    cluster.wait_for_workload("measured").await;

    let port = cluster.telemetry_of(leader);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut metrics = String::new();
    while std::time::Instant::now() < deadline {
        metrics = support::scrape(port);
        if metrics.contains(tg_telemetry::names::RAFT_RPC_SECONDS) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    assert!(
        metrics.contains(tg_telemetry::names::RAFT_RPC_SECONDS),
        "the replication round-trip time is missing at the leader's endpoint: {metrics}"
    );
    assert!(
        metrics.contains("rpc=\"append_entries\""),
        "the call must stand there as a label: {metrics}"
    );

    // **And the value, not just the line.** A series that stands there and
    // contains nonsense tells an operator nothing -- the same rule as with the
    // deadlines in 11b. The exporter renders the histogram as a summary with
    // quantiles; the p99 is the number ADR-0033's ordering condition means.
    let quantile = metrics
        .lines()
        .find(|line| {
            line.starts_with(tg_telemetry::names::RAFT_RPC_SECONDS)
                && line.contains("quantile=\"0.99\"")
                && line.contains("rpc=\"append_entries\"")
        })
        .unwrap_or_else(|| panic!("no p99 at the endpoint: {metrics}"));
    let p99: f64 = quantile
        .rsplit(' ')
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("no number: {quantile}"));
    assert!(
        p99.is_finite() && p99 > 0.0 && p99 < 1.0,
        "the p99 must be a real round-trip time -- on loopback far below one \
         second: {quantile}"
    );
    // **And the time bound beside it.** Without it somebody would have to copy
    // the number from the command line into the alarm rule -- the second source
    // this tree avoids everywhere else. What is checked is the **value**: the
    // default is 100 ms.
    let line = metrics
        .lines()
        .find(|line| line.starts_with(tg_telemetry::names::RAFT_RPC_DEADLINE))
        .unwrap_or_else(|| panic!("the time bound is missing: {metrics}"));
    let value: f64 = line
        .rsplit(' ')
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("no number: {line}"));
    assert!(
        (value - 0.1).abs() < 1e-9,
        "the time bound must be the setting (default 100 ms): {line}"
    );

    // **And the other half**: "slow" and "not at all" are two situations, and the
    // metrics separate them.
    //
    // What is compared is the **increase** and not the presence. Here stood at
    // first "in the healthy cluster the counter is not there", and that is
    // measured **false**: in the workspace run five test binaries start
    // concurrently, and a call to a node that is not listening yet rightly fails.
    // An assertion about the presence thereby checked the startup order, not the
    // metric.
    let victim = (1..=3).find(|id| *id != leader).expect("a follower");
    let before = failures_for(&metrics, victim);

    // One follower gone: now the calls there fail, and permanently at that.
    cluster.kill(victim);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut after = before;
    while std::time::Instant::now() < deadline {
        after = failures_for(&support::scrape(port), victim);
        if after > before {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(
        after > before,
        "a failed call to node {victim} must be counted: {before} -> {after}"
    );
}

/// How many calls to this counter-node have failed -- over all call kinds.
fn failures_for(metrics: &str, peer: NodeId) -> u64 {
    metrics
        .lines()
        .filter(|line| {
            line.starts_with(tg_telemetry::names::RAFT_RPC_FAILURES)
                && line.contains(&format!("peer=\"{peer}\""))
        })
        .filter_map(|line| line.rsplit(' ').next())
        .filter_map(|value| value.parse::<u64>().ok())
        .sum()
}

/// **A named peer without a leaf is named at startup** (ADR-0043).
///
/// # Why that is the frequent state
///
/// The peer leaves are distributed by an **operator** -- ADR-0043 says it
/// expressly, and the manual names the handling. Whoever adds a node has two of
/// them: extend `--peer` and file `peers/<id>.pem`. Whoever forgets the second
/// gets `UnknownIssuer` to this node -- and it stands out only when the uncovered
/// node leads and wants to replicate to us.
///
/// Both numbers stood in the log, in **two** lines, and both were called `peers`.
///
/// # The setup
///
/// Two `--peer` settings and an empty data directory: `tgd` writes its own leaf
/// at startup and enters it itself (`admit_self`), for the second there is none.
/// `--init` stays off -- the node is only supposed to get as far as having read
/// its list.
#[test]
fn a_named_peer_without_a_leaf_is_reported_at_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut child = OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
        .args([
            "--data-dir",
            dir.path().to_str().expect("path"),
            "--id",
            "1",
            "--node",
            "tgd-1",
            "--telemetry-addr",
            "off",
            "--peer",
            "1=http://127.0.0.1:19990",
            "--peer",
            "2=http://127.0.0.1:19991",
        ])
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    let log = support::await_stderr(&mut child, "named peers without a leaf");
    let _running = support::Running(child);

    // **The identifier belongs with it**, not just the number: an operator must
    // know which leaf is missing.
    assert!(
        log.contains("\"ids\":\"[2]\""),
        "the message does not name the identifier: {log}"
    );
    assert!(
        log.contains("peers"),
        "the message does not name the directory: {log}"
    );
}
