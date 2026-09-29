//! The scheduler over real processes (phase 6, ADR-0011).
//!
//! The phase's three acceptance criteria, against a running cluster: workloads
//! spread in conformity with the rules, the loss of a failure domain preserves
//! availability, and a constraint violation is rejected.
//!
//! The nodes are here **placement targets**, not control-plane processes. Those
//! are two different things that could carry the same names and deliberately do
//! not here: `tgd` processes are called `1..3`, the targets carry names like
//! `rack-a`. A cluster in which both roles coincide is possible -- for the test it
//! would only be confusing.

use std::process::{Child, Command as OsCommand};
use std::time::{Duration, Instant};

use tg_consensus::{Command, NodeId, Outcome, Resources, Topology};
use tgd::admin::{AdminClient, StatusResponse, WriteResult};

mod support;

const PATIENCE: Duration = Duration::from_secs(30);

fn document(name: &str, placement: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\">\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         <resources><cpu millicores=\"500\"/></resources>\n\
         {placement}\
         </workload>\n\
         </workloads>\n"
    )
}

fn upsert(name: &str, placement: &str) -> Command {
    Command::UpsertWorkload {
        document: document(name, placement),
    }
}

fn target(name: &str, rack: &str) -> Command {
    Command::UpsertNode {
        name: name.to_owned(),
        topology: Topology {
            site: "fra".to_owned(),
            hall: "h1".to_owned(),
            rack: rack.to_owned(),
        },
        capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
        reserved: tg_consensus::Resources::default(),
        source: tg_consensus::Origin::Operator,
    }
}

struct Cluster {
    children: Vec<(NodeId, Child)>,
    clients: Vec<(NodeId, AdminClient)>,
    /// The telemetry port per node -- remembered because `free_port` assigns it
    /// and only the leader sets the placement metrics.
    telemetry: Vec<(NodeId, u16)>,
    _dir: tempfile::TempDir,
}

impl Cluster {
    fn start(size: NodeId) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // Three ports per node (ADR-0043, determination 4). `--peer` now points
        // at the **cluster** port: Raft lies there, no longer on `--listen`.
        //
        // Plus a fourth for the telemetry: the denominator of the placement
        // (ADR-0011) stands as a metric at the leader's endpoint, and a default
        // port would be the same for every concurrent test binary.
        let ports: Vec<(NodeId, u16, u16, u16, u16)> = (1..=size)
            .map(|id| {
                (
                    id,
                    support::free_port(),
                    support::free_port(),
                    support::free_port(),
                    support::free_port(),
                )
            })
            .collect();
        let peers: Vec<String> = ports
            .iter()
            .map(|(id, _, cluster, ..)| format!("{id}=http://127.0.0.1:{cluster}"))
            .collect();

        support::cluster_material(
            dir.path(),
            &ports.iter().map(|(id, ..)| *id).collect::<Vec<_>>(),
        );

        let mut children = Vec::new();
        let mut clients = Vec::new();

        for (id, port, cluster, session, telemetry) in &ports {
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
                .arg("--telemetry-addr")
                .arg(format!("127.0.0.1:{telemetry}"))
                .arg("--data-dir")
                .arg(dir.path());
            for peer in &peers {
                command.arg("--peer").arg(peer);
            }
            if *id == 1 {
                command.arg("--init");
            }

            children.push((
                *id,
                command
                    .stdout(support::log("tgd"))
                    .stderr(support::log("tgd"))
                    .spawn()
                    .expect("tgd startable"),
            ));
            clients.push((
                *id,
                // Admin has lain on a Unix socket since ADR-0044.
                AdminClient::connect_unix(&tgd::admin::socket_path(dir.path(), *id))
                    .expect("admin socket"),
            ));
        }

        Self {
            children,
            clients,
            telemetry: ports
                .iter()
                .map(|(id, .., telemetry)| (*id, *telemetry))
                .collect(),
            _dir: dir,
        }
    }

    /// A node's telemetry port.
    fn telemetry_port(&self, id: NodeId) -> u16 {
        self.telemetry
            .iter()
            .find(|(other, _)| *other == id)
            .expect("node")
            .1
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

    /// Aborts when a node has ended itself.
    ///
    /// `children` is here the **desired set**: killing happens only in `Drop`, so
    /// every entry belongs to a node that is supposed to run. Without this check
    /// a loop waits out its whole deadline and afterwards reports the wrong
    /// cause.
    fn assert_all_alive(&self) {
        for (id, child) in &self.children {
            support::assert_alive(*id, child.id());
        }
    }

    async fn wait_for_leader(&self) -> NodeId {
        let deadline = Instant::now() + PATIENCE;
        let quorum = self.children.len().div_ceil(2);

        loop {
            let mut votes = Vec::new();
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
                if votes.iter().filter(|v| **v == Some(candidate)).count() >= quorum {
                    return candidate;
                }
            }
            assert!(Instant::now() < deadline, "no leader: {votes:?}");
            self.assert_all_alive();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Writes and returns the result -- a rejection too.
    async fn write(&self, command: Command) -> WriteResult {
        let deadline = Instant::now() + PATIENCE;

        loop {
            let leader = self.wait_for_leader().await;
            match self.client(leader).write(command.clone()).await {
                Ok(WriteResult::ForwardTo { .. }) => {}
                Ok(other) => return other,
                Err(status) => assert!(Instant::now() < deadline, "failed: {status}"),
            }
            assert!(Instant::now() < deadline, "did not get through");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn applied(&self, command: Command) -> Outcome {
        match self.write(command).await {
            WriteResult::Applied { outcome, .. } => outcome,
            other => panic!("not applied: {other:?}"),
        }
    }

    async fn status(&self) -> StatusResponse {
        let leader = self.wait_for_leader().await;
        self.client(leader).status().await.expect("status")
    }

    /// Waits until the scheduler has placed the expected number of instances.
    async fn wait_for_placements(&self, workload: &str, count: usize) -> Vec<(u32, String)> {
        let deadline = Instant::now() + PATIENCE;

        loop {
            let status = self.status().await;
            let mut found: Vec<(u32, String)> = status
                .placements
                .iter()
                .filter(|(name, _, _)| name == workload)
                .map(|(_, instance, node)| (*instance, node.clone()))
                .collect();
            found.sort();

            if found.len() == count {
                return found;
            }
            assert!(
                Instant::now() < deadline,
                "'{workload}': {} of {count} placed ({found:?})",
                found.len()
            );
            self.assert_all_alive();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
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

/// **Workloads spread in conformity with the rules** -- the scheduler in the
/// leader places by itself, without anybody writing an assignment.
#[tokio::test(flavor = "multi_thread")]
async fn the_leader_places_workloads_across_racks() {
    let cluster = Cluster::start(3);
    cluster.wait_for_leader().await;

    for (name, rack) in [("rack-a", "r1"), ("rack-b", "r2"), ("rack-c", "r3")] {
        assert_eq!(cluster.applied(target(name, rack)).await, Outcome::Applied);
    }

    // Nobody writes an assignment -- only the definition.
    assert_eq!(
        cluster
            .applied(upsert("api", "<placement replicas=\"3\"/>"))
            .await,
        Outcome::Applied
    );

    let placed = cluster.wait_for_placements("api", 3).await;
    let mut nodes: Vec<&str> = placed.iter().map(|(_, node)| node.as_str()).collect();
    nodes.sort_unstable();
    assert_eq!(
        nodes,
        ["rack-a", "rack-b", "rack-c"],
        "the three instances do not lie in three racks"
    );
}

/// **The loss of a failure domain preserves availability.**
///
/// Two instances in two racks, a third stands ready. If a rack fails, the
/// surviving instance stays **untouched** (ADR-0011: no auto-rebalancing) and the
/// lost one is replaced in the third rack.
#[tokio::test(flavor = "multi_thread")]
async fn losing_a_rack_keeps_the_survivor_and_replaces_the_lost_instance() {
    let cluster = Cluster::start(3);
    cluster.wait_for_leader().await;

    for (name, rack) in [("rack-a", "r1"), ("rack-b", "r2"), ("rack-c", "r3")] {
        cluster.applied(target(name, rack)).await;
    }
    cluster
        .applied(upsert("api", "<placement replicas=\"2\"/>"))
        .await;

    let before = cluster.wait_for_placements("api", 2).await;
    let lost = before[0].1.clone();
    let survivor = before[1].1.clone();

    // The rack fails: the node is removed.
    cluster
        .applied(Command::RemoveNode { name: lost.clone() })
        .await;

    let after = cluster.wait_for_placements("api", 2).await;
    let nodes: Vec<&str> = after.iter().map(|(_, node)| node.as_str()).collect();

    assert!(
        nodes.contains(&survivor.as_str()),
        "the surviving instance was moved: {after:?}"
    );
    assert!(
        !nodes.contains(&lost.as_str()),
        "the lost instance still stands on the dead node"
    );
    assert_eq!(
        nodes
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2,
        "both instances lie on the same node: {after:?}"
    );
}

/// **A constraint violation is rejected** -- already at ingest, not only at
/// placement.
#[tokio::test(flavor = "multi_thread")]
async fn a_contradictory_constraint_is_rejected_at_ingest() {
    let cluster = Cluster::start(3);
    cluster.wait_for_leader().await;
    cluster.applied(target("rack-a", "r1")).await;

    let outcome = cluster
        .applied(upsert(
            "ledger",
            "<placement replicas=\"2\"><pin node=\"rack-a\"/></placement>",
        ))
        .await;

    assert!(
        matches!(
            outcome,
            Outcome::Rejected(tg_consensus::Rejection::UnplaceableDefinition { .. })
        ),
        "{outcome:?}"
    );

    // And the definition did not land in the state.
    let status = cluster.status().await;
    assert!(!status.workloads.iter().any(|name| name == "ledger"));
}

/// A pin places exactly there -- the basis of the node pinning from ADR-0027.
#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_workload_lands_on_its_node() {
    let cluster = Cluster::start(3);
    cluster.wait_for_leader().await;

    for (name, rack) in [("rack-a", "r1"), ("rack-b", "r2")] {
        cluster.applied(target(name, rack)).await;
    }
    cluster
        .applied(upsert(
            "ledger",
            "<placement><pin node=\"rack-b\"/></placement>",
        ))
        .await;

    let placed = cluster.wait_for_placements("ledger", 1).await;
    assert_eq!(placed[0].1, "rack-b");
}

/// More instances than racks: the surplus ones stay unplaced instead of being
/// collapsed together -- and the placeable ones run nevertheless.
#[tokio::test(flavor = "multi_thread")]
async fn surplus_instances_stay_unplaced_rather_than_collapse() {
    let cluster = Cluster::start(3);
    cluster.wait_for_leader().await;

    for (name, rack) in [("rack-a", "r1"), ("rack-b", "r2")] {
        cluster.applied(target(name, rack)).await;
    }
    cluster
        .applied(upsert("api", "<placement replicas=\"3\"/>"))
        .await;

    let placed = cluster.wait_for_placements("api", 2).await;
    let nodes: std::collections::BTreeSet<&str> =
        placed.iter().map(|(_, node)| node.as_str()).collect();
    assert_eq!(nodes.len(), 2, "two instances in the same rack: {placed:?}");

    // And it stays that way -- the scheduler does not add the third after all.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let still = cluster.status().await;
    assert_eq!(
        still
            .placements
            .iter()
            .filter(|(name, _, _)| name == "api")
            .count(),
        2
    );

    // **And an operator sees it** (ADR-0011). The rejection above goes into the
    // leader's log and nowhere else; without these two numbers a partially placed
    // declaration could not be distinguished from a complete one. Two raw numbers
    // and no ratio -- the division is done by the alarm system.
    //
    // The leader sets them, so it is asked: `status()` names it.
    let leader = still.leader.expect("a leader");
    let port = cluster.telemetry_port(leader);
    assert!(
        await_metric(
            port,
            tg_telemetry::names::WORKLOAD_PLACED,
            ("workload", "api"),
            " 2"
        )
        .await,
        "the numerator is missing or does not say 2"
    );
    assert!(
        await_metric(
            port,
            tg_telemetry::names::WORKLOAD_REPLICAS,
            ("workload", "api"),
            " 3"
        )
        .await,
        "the denominator is missing or does not say 3 -- without it the rule is not writable"
    );

    // **And he sees where he has to go** (ADR-0011). The two numbers above say
    // *that* something is missing; the reason stood until here only in the
    // leader's log. Here it is `no_domain_left` -- so topology, and not capacity.
    assert!(
        await_metric(
            port,
            tg_telemetry::names::SCHEDULER_UNPLACEABLE,
            ("class", "no_domain_left"),
            " 1"
        )
        .await,
        "the class of the rejection is missing or does not say 1"
    );

    // The other half of the assurance: **all seven** are set, the uninvolved
    // ones too. A time series that appears only on a finding cannot be
    // distinguished from a missing one -- and `no_room` sent an operator to the
    // capacity, where there is nothing to get.
    assert!(
        await_metric(
            port,
            tg_telemetry::names::SCHEDULER_UNPLACEABLE,
            ("class", "no_room"),
            " 0"
        )
        .await,
        "an uninvolved class is missing instead of saying zero"
    );
}

/// Waits until a metric with this label says this value.
///
/// Line by line and with the label, not two substrings in the whole document:
/// otherwise it would suffice that the name stands somewhere and the value
/// somewhere else -- and a wrong label would not stand out.
async fn await_metric(port: u16, metric: &str, label: (&str, &str), wanted: &str) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let label = format!("{}=\"{}\"", label.0, label.1);
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
            .any(|line| line.starts_with(metric) && line.contains(&label) && line.ends_with(wanted))
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    false
}

/// **Drain at the running cluster: the planner empties the node.**
///
/// The open point from phase 6, at real processes. Nothing is moved by a tool in
/// the process -- the state stands in the log, and the planner does it in its
/// ordinary step (ADR-0011: nobody rebalances, somebody decreed something).
#[tokio::test]
async fn draining_a_node_moves_its_workload_away() {
    let cluster = Cluster::start(3);
    cluster.wait_for_leader().await;

    for (name, rack) in [("rack-a", "r1"), ("rack-b", "r2")] {
        cluster.applied(target(name, rack)).await;
    }
    cluster
        .applied(upsert("api", "<placement replicas=\"1\"/>"))
        .await;

    let before = cluster.wait_for_placements("api", 1).await;
    let occupied = before[0].1.clone();

    cluster
        .applied(Command::SetSchedulability {
            node: occupied.clone(),
            mode: tg_consensus::Schedulability::Draining,
        })
        .await;

    // What is waited for is the **movement**, not a count: the number is one
    // before and after, and a test that only counts would be green immediately.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut now = occupied.clone();
    while now == occupied && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        now = cluster.wait_for_placements("api", 1).await[0].1.clone();
    }

    assert_ne!(now, occupied, "the workload stayed on the emptied node");
}

/// **Reserved capacity at the running cluster** (ADR-0047).
///
/// The node has room and nevertheless does not give it up: the reserve is air for
/// the **outage**, not for the next instance.
#[tokio::test]
async fn a_reserve_keeps_a_node_from_taking_work() {
    let cluster = Cluster::start(3);
    cluster.wait_for_leader().await;

    // Two racks. On the one everything is reserved, on the other nothing.
    //
    // **The names are chosen deliberately.** On a tie the planner takes the
    // alphabetically first (ADR-0011), and the reserved one is therefore called
    // `a-...`: were the reserve without effect, it would win -- and the test would
    // be green without checking anything. It went past exactly that once.
    cluster
        .applied(Command::UpsertNode {
            name: "a-fully-reserved".to_owned(),
            topology: Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r1".to_owned(),
            },
            capacity: Resources::default().with(Resources::CPU_MILLICORES, 4000),
            reserved: Resources::default().with(Resources::CPU_MILLICORES, 4000),
            source: tg_consensus::Origin::Operator,
        })
        .await;
    cluster.applied(target("b-free", "r2")).await;

    cluster
        .applied(upsert("api", "<placement replicas=\"1\"/>"))
        .await;

    let placed = cluster.wait_for_placements("api", 1).await;

    assert_eq!(
        placed[0].1, "b-free",
        "the reserve was given away: {placed:?}"
    );
}
