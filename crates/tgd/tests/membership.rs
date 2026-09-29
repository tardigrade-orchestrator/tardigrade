//! Membership, snapshots and the projection from the log (phase 5d).
//!
//! ADR-0005 names exactly these three "our own responsibility": snapshots,
//! membership changes, log compaction and restore are the part of Raft `openraft`
//! does not take off our hands, because it hangs on our storage layer.
//!
//! The test forces the case at issue: the log is kept **short**, so that
//! compaction takes hold before the new node joins. With that the early entries no
//! longer exist -- the new one can only catch up via a snapshot. Without this
//! shortening it would quietly catch up over the log path, and the snapshot path
//! would stay unchecked although the test would be green.

use std::path::PathBuf;
use std::process::{Child, Command as OsCommand};
use std::time::{Duration, Instant};

use tg_consensus::{Command, NodeId, Outcome, Topology};

mod support;
use tgd::admin::{
    AdminClient, MembershipChange, MembershipResult, ProjectionResponse, WriteResult,
};

/// How long an expected state is waited for.
///
/// More generous than in `tests/cluster.rs`: here snapshot building and transfer
/// come along, and the membership change needs two log commits instead of one.
const PATIENCE: Duration = Duration::from_mins(1);

/// After this few entries a snapshot arises, and this few stay in the log
/// afterwards. Small enough that a short test triggers compaction.
const SNAPSHOT_EVERY: u64 = 4;
const KEEP_LOGS: u64 = 1;

fn document(name: &str, after: Option<&str>) -> String {
    let dependencies = after.map_or(String::new(), |target| {
        format!("<dependencies><after ref=\"{target}\"/></dependencies>")
    });
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\">\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         {dependencies}\
         </workload>\n\
         </workloads>\n"
    )
}

fn upsert(name: &str, after: Option<&str>) -> Command {
    Command::UpsertWorkload {
        document: document(name, after),
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

/// Processes of which only a part is a member at the beginning.
struct Cluster {
    children: Vec<(NodeId, Child)>,
    clients: Vec<(NodeId, AdminClient)>,
    voters: usize,
    _dir: tempfile::TempDir,
}

impl Cluster {
    /// Starts `total` processes but initializes only the first `voters` as
    /// members.
    ///
    /// All know everyone's addresses from the start -- the address table is an
    /// operational setting and no replicated truth
    /// (`tg_consensus::net::PeerAddrs`). A node becomes a member only through a
    /// log entry.
    fn start(total: NodeId, voters: NodeId) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir: PathBuf = dir.path().to_path_buf();

        // Three ports per node (ADR-0043, determination 4). `--peer` now points
        // at the **cluster** port: Raft lies there, no longer on `--listen`.
        let ports: Vec<(NodeId, u16, u16, u16)> = (1..=total)
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

        for (id, port, cluster, session) in &ports {
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
                // Without telemetry: `cargo test` runs the test binaries
                // concurrently, and the default port would be the same for all.
                .arg("--telemetry-addr")
                .arg("off")
                .arg("--data-dir")
                .arg(&data_dir)
                .arg("--snapshot-every")
                .arg(SNAPSHOT_EVERY.to_string())
                .arg("--keep-logs")
                .arg(KEEP_LOGS.to_string());
            for peer in &peers {
                command.arg("--peer").arg(peer);
            }
            // Node 1 creates the membership -- and only over the first
            // `voters`. The remaining processes run but do not belong to it.
            if *id == 1 {
                command.arg("--init").arg("--init-voters").arg(
                    (1..=voters)
                        .map(|id| id.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                );
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
            clients,
            voters: usize::try_from(voters).expect("fits"),
            _dir: dir,
        }
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
        let quorum = self.voters.div_ceil(2);

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
                if votes.iter().filter(|v| **v == Some(candidate)).count() >= quorum {
                    return candidate;
                }
            }

            assert!(
                Instant::now() < deadline,
                "no leader within {PATIENCE:?}; votes: {votes:?}"
            );
            self.assert_all_alive();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn write(&self, command: Command) -> Outcome {
        let deadline = Instant::now() + PATIENCE;

        loop {
            let leader = self.wait_for_leader().await;
            match self.client(leader).write(command.clone()).await {
                Ok(WriteResult::Applied { outcome, .. }) => return outcome,
                Ok(other) => {
                    assert!(Instant::now() < deadline, "did not get through: {other:?}");
                }
                Err(status) => assert!(Instant::now() < deadline, "failed: {status}"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Carries out a membership change over the leader.
    async fn change(&self, change: MembershipChange) -> Vec<NodeId> {
        let deadline = Instant::now() + PATIENCE;

        loop {
            let leader = self.wait_for_leader().await;
            match self.client(leader).membership(change.clone()).await {
                Ok(MembershipResult::Changed { voters }) => return voters,
                Ok(other) => assert!(
                    Instant::now() < deadline,
                    "the membership change did not get through: {other:?}"
                ),
                Err(status) => assert!(
                    Instant::now() < deadline,
                    "the membership change failed: {status}"
                ),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Waits until compaction has taken place on the leader.
    async fn wait_for_compaction(&self) -> u64 {
        let deadline = Instant::now() + PATIENCE;

        loop {
            let leader = self.wait_for_leader().await;
            if let Ok(status) = self.client(leader).status().await
                && let Some(purged) = status.purged
            {
                return purged;
            }

            assert!(
                Instant::now() < deadline,
                "no compaction within {PATIENCE:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Waits until the named nodes have applied the same state **and** carry the
    /// named workloads, and returns their projections.
    ///
    /// # Why `expect` must not be left out
    ///
    /// Without this condition the assertion waited only for **equality** -- and
    /// that is already satisfied right after the start, namely on the membership
    /// entry. The callers write a workload immediately before and compare
    /// afterwards; if the first query hit the nodes before the entry replicated, a
    /// matching but **old** view came back, and the test failed with "missing at
    /// the follower".
    ///
    /// That is the same error as with the missing `wait_for_node` in `cluster.rs`:
    /// the assertion checked a different property from the one it had waited for.
    /// It went wrong in one run in eight.
    async fn wait_for_converged_projections(
        &self,
        nodes: &[NodeId],
        expect: &[&str],
    ) -> Vec<ProjectionResponse> {
        let deadline = Instant::now() + PATIENCE;

        loop {
            let mut views = Vec::new();
            for id in nodes {
                if let Ok(view) = self.client(*id).projection().await {
                    views.push(view);
                }
            }

            if views.len() == nodes.len() {
                let first = views[0].last_applied;
                let converged =
                    first.is_some() && views.iter().all(|view| view.last_applied == first);
                let complete = views.iter().all(|view| {
                    expect
                        .iter()
                        .all(|name| view.workloads.iter().any(|w| w.name == *name))
                });
                if converged && complete {
                    return views;
                }
            }

            assert!(
                Instant::now() < deadline,
                "projections not at the same state or incomplete \
                 (expected {expect:?}): {:?}",
                views
                    .iter()
                    .map(|v| (v.id, v.last_applied, v.workloads.len()))
                    .collect::<Vec<_>>()
            );
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

/// **The phase's acceptance criteria, in one run.**
///
/// Three nodes, a fourth waits beside them. So much is written that compaction
/// takes hold; then the fourth joins -- first as a learner, then as a voter -- and
/// catches up via a snapshot. Across the whole change the cluster stays writable,
/// and at the end all four have the same projection.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_node_joins_by_snapshot_without_losing_the_quorum() {
    let cluster = Cluster::start(4, 3);
    cluster.wait_for_leader().await;

    // Enough entries for a snapshot to arise and the log to be truncated.
    cluster.write(node_command("node-1")).await;
    for index in 0..8 {
        assert_eq!(
            cluster.write(upsert(&format!("w{index}"), None)).await,
            Outcome::Applied
        );
    }

    let purged = cluster.wait_for_compaction().await;
    assert!(
        purged >= 4,
        "compaction deleted only up to index {purged} -- then the early entries \
         still lie in the log and the snapshot path stays unchecked"
    );

    // The fourth is not in yet.
    let before = cluster.client(1).status().await.expect("status");
    assert_eq!(before.voters, vec![1, 2, 3]);
    let outsider = cluster.client(4).status().await.expect("status");
    assert!(
        outsider.last_applied.is_none(),
        "node 4 applied something although it is not a member"
    );

    // Step one: learner. It catches up without voting -- and because the log is
    // truncated, that works only over a snapshot.
    cluster
        .change(MembershipChange::AddLearner {
            id: 4,
            blocking: true,
        })
        .await;

    caught_up_by_snapshot(&cluster, purged).await;

    // During the change the cluster stays able to act.
    assert_eq!(
        cluster.write(upsert("during-the-change", None)).await,
        Outcome::Applied
    );

    // Step two: voter. Joint consensus holds the quorum across the change.
    let voters = cluster
        .change(MembershipChange::SetVoters {
            ids: vec![1, 2, 3, 4],
            retain: false,
        })
        .await;
    assert_eq!(voters, vec![1, 2, 3, 4]);

    assert_eq!(
        cluster.write(upsert("after-the-change", None)).await,
        Outcome::Applied
    );

    // **The projection is deterministically identical on all nodes.**
    let views = cluster
        .wait_for_converged_projections(&[1, 2, 3, 4], &["after-the-change"])
        .await;
    let reference = &views[0];
    for view in &views[1..] {
        assert_eq!(
            view.workloads, reference.workloads,
            "node {} has a different projection from node {}",
            view.id, reference.id
        );
    }

    let names: Vec<&str> = reference
        .workloads
        .iter()
        .map(|w| w.name.as_str())
        .collect();
    assert!(names.contains(&"after-the-change"));
    assert!(
        names.contains(&"w0"),
        "the state before the snapshot is missing"
    );
    assert_eq!(
        names,
        {
            let mut sorted = names.clone();
            sorted.sort_unstable();
            sorted
        },
        "the projection is not sorted -- then it is not comparable"
    );
}

/// Substantiates that node 4 caught up via a **snapshot** -- and that it applied
/// it fully and took it over as its beginning.
///
/// Not `snapshot.is_some()`: that would be true too if it had built itself one
/// after catching up. What is compelling is the availability of `w0` -- the entry
/// stands below `purged`, which the leader deleted, and node 4 had demonstrably
/// applied nothing before. If it knows `w0` nevertheless, that can only come from
/// a transferred snapshot.
async fn caught_up_by_snapshot(cluster: &Cluster, purged: u64) {
    let deadline = Instant::now() + PATIENCE;
    let caught_up = loop {
        let view = cluster.client(4).projection().await;
        if let Ok(view) = view
            && view.workloads.iter().any(|w| w.name == "w0")
        {
            break view;
        }
        assert!(
            Instant::now() < deadline,
            "node 4 does not know 'w0' -- the entry no longer exists in the log \
             (deleted up to {purged}), so it got no snapshot"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    // **And it applied it fully, not merely saw `w0`.** Previously
    // `last_applied.is_some()` stood here -- that is trivially true after the loop
    // above and says nothing. The number says something: node 4's view reaches
    // **beyond** the range the leader deleted. Measured, for instance `purged =
    // 14` with a view of `19`; the numbers vary per run, the relation does not.
    let state = caught_up
        .last_applied
        .expect("the view knows 'w0', so it has a state");
    assert!(
        state >= purged,
        "node 4's view stands at {state}, the leader deleted up to {purged} -- \
         then a part of the snapshot is missing from it"
    );

    // **The snapshot is installed, not merely received.** The comment here once
    // said "the metric confirms it" -- it confirms nothing, that stands in this
    // function's header. What the numbers say is something else: it truncated its
    // **own** log up to the snapshot's state (measured, both `Some(19)`), so it
    // really took it over as its beginning and did not file it beside.
    let status = cluster.client(4).status().await.expect("status");
    assert_eq!(
        status.snapshot, status.purged,
        "node 4 carries a snapshot at {:?} and truncated its log up to {:?} -- \
         then it is not its beginning. State: {status:?}",
        status.snapshot, status.purged
    );
    // And equality alone does not suffice: two `None` are equal too, and that
    // would mean neither a snapshot nor a truncation.
    assert!(status.snapshot.is_some(), "state: {status:?}");
}

/// A node can be taken out of the quorum without it breaking.
///
/// The counter-direction to the test above. Four voters become three; the quorum
/// falls from three to two, and the cluster stays writable throughout.

#[tokio::test(flavor = "multi_thread")]
async fn a_voter_can_be_removed_while_the_cluster_keeps_working() {
    let cluster = Cluster::start(4, 4);
    cluster.wait_for_leader().await;
    cluster.write(upsert("before", None)).await;

    // Remove a node that does not lead -- otherwise the test checks the failover
    // along the way, and that stands in `tests/cluster.rs`.
    let leader = cluster.wait_for_leader().await;
    let victim = cluster
        .running()
        .into_iter()
        .find(|id| *id != leader)
        .expect("a node that does not lead");
    let remaining: Vec<NodeId> = (1..=4).filter(|id| *id != victim).collect();

    let voters = cluster
        .change(MembershipChange::SetVoters {
            ids: remaining.clone(),
            retain: false,
        })
        .await;
    assert_eq!(voters, remaining);

    assert_eq!(cluster.write(upsert("after", None)).await, Outcome::Applied);

    let views = cluster
        .wait_for_converged_projections(&remaining, &["after"])
        .await;
    for view in &views[1..] {
        assert_eq!(view.workloads, views[0].workloads);
    }
}

/// The projection follows the log, not a local cache.
///
/// The proof: a node that was not the leader at the write and never saw the
/// definition itself carries it nevertheless -- it can only have come from the
/// log. And it disappears again when the entry is removed.
#[tokio::test(flavor = "multi_thread")]
async fn the_projection_follows_the_log() {
    let cluster = Cluster::start(3, 3);
    let leader = cluster.wait_for_leader().await;
    let follower = cluster
        .running()
        .into_iter()
        .find(|id| *id != leader)
        .expect("a follower");

    cluster.write(upsert("db", None)).await;
    cluster.write(upsert("api", Some("db"))).await;

    let views = cluster
        .wait_for_converged_projections(&[leader, follower], &["db", "api"])
        .await;
    let on_follower = views
        .iter()
        .find(|view| view.id == follower)
        .expect("follower");

    let api = on_follower
        .workloads
        .iter()
        .find(|w| w.name == "api")
        .expect("api is missing at the follower");
    assert_eq!(api.image, "example.com/api:1");
    assert_eq!(
        api.edges,
        vec![("after".to_owned(), "db".to_owned())],
        "the edge from the definition is missing in the projection"
    );

    // Removing takes effect over the log likewise.
    cluster
        .write(Command::RemoveWorkload {
            name: "api".to_owned(),
        })
        .await;

    let deadline = Instant::now() + PATIENCE;
    loop {
        let view = cluster.client(follower).projection().await.expect("view");
        if !view.workloads.iter().any(|w| w.name == "api") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "'api' still stands in the follower's projection"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// **A node without an address is refused at once, not waited out** (ADR-0005,
/// phase 5d).
///
/// The witness at the **real process** to what `admin::unreachable` says as a pure
/// rule. What can only be seen here: that the rejection falls **before** the
/// consensus -- with `blocking: true` `openraft` would otherwise have waited until
/// a node catches up that is not reachable, and the call would end in a time bound
/// without a reason.
///
/// What is therefore measured too is the **time**: a rejection that takes a minute
/// cannot be distinguished from the old situation.
#[tokio::test(flavor = "multi_thread")]
async fn a_learner_without_an_address_is_refused_at_once() {
    // One node suffices: it leads, and the precondition falls before the
    // consensus.
    let cluster = Cluster::start(1, 1);
    let leader = cluster.wait_for_leader().await;

    let started = Instant::now();
    let result = cluster
        .client(leader)
        .membership(MembershipChange::AddLearner {
            // This identifier stands in no `--peer` of this process.
            id: 42,
            blocking: true,
        })
        .await
        .expect("the call must answer");

    let MembershipResult::Failed { detail } = &result else {
        panic!("expected a rejection with a reason: {result:?}");
    };
    assert!(detail.contains("42"), "{detail}");
    assert!(
        detail.contains("--peer"),
        "the message must say where the address belongs: {detail}"
    );

    // **At once**, not after a time bound. Two seconds are generous for a call
    // that does nothing but ask a table -- and two orders of magnitude away from
    // the patience in which the old situation ended.
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the rejection took {:.1}s -- one that waits cannot be distinguished \
         from the old situation",
        started.elapsed().as_secs_f64()
    );
}
