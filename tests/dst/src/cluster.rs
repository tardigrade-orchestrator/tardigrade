//! Five nodes in one process (ADR-0031).
//!
//! The cluster uses the **real** storage from phase 5a, not a dummy: one `redb`
//! file per node in a throwaway directory. A dummy would leave out exactly the
//! layer ADR-0005 calls "the largest single risk item in the project" — and a
//! restart that fetches the state back from the file would not be checkable.
//!
//! **The fixed election timeouts.** `openraft` rolls the election timeout from
//! `rand::thread_rng()`, unseeded. With `election_timeout_max = min + 1` the
//! drawn value is fixed: `gen_range(300..301)` always yields 300. So that the
//! nodes do not all candidate at the same time and get stuck in split votes,
//! each gets an offset of its own — node 1 elects first, node 5 last. That
//! replaces the randomness with an order and makes the run reproducible.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use openraft::{BasicNode, Config, Raft, ServerState};
use tg_consensus::{ClusterState, Command, NodeId, Outcome, StateHandle, Storage, TypeConfig};

use crate::bus::Bus;
use crate::faults::Faults;

/// Base value of the election timeout in milliseconds.
pub const ELECTION_BASE_MS: u64 = 300;
/// Offset per node — node `n` elects after `BASE + (n-1) * STAGGER`.
const ELECTION_STAGGER_MS: u64 = 40;
/// Heartbeat interval of the leader in milliseconds.
pub const HEARTBEAT_MS: u64 = 50;
/// Upper bound for waiting on a state — in **virtual** time.
const PATIENCE: Duration = Duration::from_secs(10);

/// Something in the harness failed.
#[derive(Debug)]
pub enum ClusterError {
    /// A node's storage could not be opened.
    Storage {
        /// Affected node.
        node: NodeId,
        /// Message of the storage layer.
        detail: String,
    },
    /// `openraft` refused a call.
    Raft {
        /// What was attempted.
        operation: &'static str,
        /// Message.
        detail: String,
    },
    /// An expected state did not occur within the patience.
    Timeout {
        /// What was waited for.
        expected: String,
    },
    /// A node was addressed that does not exist in the run.
    UnknownNode {
        /// The identifier.
        node: NodeId,
    },
}

impl fmt::Display for ClusterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage { node, detail } => {
                write!(f, "storage of node {node} not usable: {detail}")
            }
            Self::Raft { operation, detail } => write!(f, "{operation} failed: {detail}"),
            Self::Timeout { expected } => write!(f, "time ran out while waiting for: {expected}"),
            Self::UnknownNode { node } => {
                write!(f, "node {node} does not exist in this run")
            }
        }
    }
}

impl std::error::Error for ClusterError {}

/// How a run is set up.
///
/// Separate from [`Cluster::start`], because phase 5d needs two things nobody
/// needed before: a cluster in which not every started node is a member, and a
/// log short enough for compaction to bite in a test run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    /// Seed of the run.
    pub seed: u64,
    /// How many nodes are started.
    pub size: u64,
    /// How many of them are voters at creation.
    ///
    /// The rest run but are not members — being reachable and being a member are
    /// two different things.
    pub voters: u64,
    /// After how many entries a snapshot arises.
    pub snapshot_every: u64,
    /// How many entries stay in the log after a snapshot.
    pub keep_logs: u64,
}

impl Setup {
    /// Five nodes, all voters, snapshots practically never.
    ///
    /// The defaults of a run that is not interested in compaction: every entry
    /// stays in the log, and a test that talks about catching up talks about the
    /// log path.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            size: 5,
            voters: 5,
            snapshot_every: 5_000,
            keep_logs: 1_000,
        }
    }

    /// A run in which compaction bites early.
    #[must_use]
    pub fn with_short_log(mut self, snapshot_every: u64, keep_logs: u64) -> Self {
        self.snapshot_every = snapshot_every;
        self.keep_logs = keep_logs;
        self
    }

    /// A run in which only a part of the nodes is a member.
    #[must_use]
    pub fn with_voters(mut self, voters: u64) -> Self {
        self.voters = voters;
        self
    }
}

/// A running cluster in the process.
pub struct Cluster {
    bus: Bus,
    nodes: BTreeMap<NodeId, Raft<TypeConfig>>,
    /// Read handles on the applied state — the same seam `tgd` uses (phase 5d).
    /// Without them the state could be read only after stopping, and a scenario
    /// about placement needs it during the run.
    states: BTreeMap<NodeId, StateHandle>,
    paths: BTreeMap<NodeId, PathBuf>,
    size: u64,
    setup: Setup,
    dir: tempfile::TempDir,
}

impl fmt::Debug for Cluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cluster")
            .field("seed", &self.bus.seed())
            .field("size", &self.size)
            .field("running", &self.nodes.keys().collect::<Vec<_>>())
            .field("directory", &self.dir.path())
            .finish_non_exhaustive()
    }
}

impl Cluster {
    /// Starts `size` nodes and initializes the membership.
    ///
    /// # Errors
    ///
    /// [`ClusterError`] if a storage cannot be opened, `openraft` refuses the
    /// start or no leader comes about within the patience.
    pub async fn start(seed: u64, size: u64) -> Result<Self, ClusterError> {
        let mut setup = Setup::new(seed);
        setup.size = size;
        setup.voters = size;
        Self::start_with(setup).await
    }

    /// Starts a run per [`Setup`].
    ///
    /// # Errors
    ///
    /// [`ClusterError`] if a storage cannot be opened, `openraft` refuses the
    /// start or no leader comes about within the patience.
    pub async fn start_with(setup: Setup) -> Result<Self, ClusterError> {
        let dir = tempfile::tempdir().map_err(|err| ClusterError::Storage {
            node: 0,
            detail: err.to_string(),
        })?;

        let bus = Bus::new(setup.seed);
        let mut nodes = BTreeMap::new();
        let mut paths = BTreeMap::new();

        let mut states = BTreeMap::new();
        for id in 1..=setup.size {
            let path = dir.path().join(format!("node-{id}.redb"));
            let (raft, state) = spawn(id, &path, &bus, &setup).await?;
            bus.register(id, raft.clone());
            nodes.insert(id, raft);
            states.insert(id, state);
            paths.insert(id, path);
        }

        let members: BTreeMap<NodeId, BasicNode> = (1..=setup.voters)
            .map(|id| (id, BasicNode::default()))
            .collect();
        nodes
            .get(&1)
            .ok_or(ClusterError::UnknownNode { node: 1 })?
            .initialize(members)
            .await
            .map_err(|err| ClusterError::Raft {
                operation: "initialize",
                detail: err.to_string(),
            })?;

        let cluster = Self {
            bus,
            nodes,
            states,
            paths,
            size: setup.size,
            setup,
            dir,
        };
        cluster.wait_for_leader().await?;

        Ok(cluster)
    }

    /// Takes a node in as a learner — it catches up but does not vote.
    ///
    /// # Errors
    ///
    /// [`ClusterError`] if there is no leader or `openraft` refuses.
    pub async fn add_learner(&self, node: NodeId) -> Result<(), ClusterError> {
        let leader = self.wait_for_leader().await?;
        self.nodes
            .get(&leader)
            .ok_or(ClusterError::UnknownNode { node: leader })?
            .add_learner(node, BasicNode::default(), true)
            .await
            .map(|_| ())
            .map_err(|err| ClusterError::Raft {
                operation: "add_learner",
                detail: err.to_string(),
            })
    }

    /// Sets the set of voters (joint consensus).
    ///
    /// # Errors
    ///
    /// [`ClusterError`] if there is no leader or the change fails — for
    /// instance because it lacks the quorum.
    pub async fn set_voters(&self, voters: &[NodeId]) -> Result<Vec<NodeId>, ClusterError> {
        let leader = self.wait_for_leader().await?;
        let ids: std::collections::BTreeSet<NodeId> = voters.iter().copied().collect();

        let raft = self
            .nodes
            .get(&leader)
            .ok_or(ClusterError::UnknownNode { node: leader })?;

        tokio::time::timeout(PATIENCE, raft.change_membership(ids, false))
            .await
            .map_err(|_| ClusterError::Timeout {
                expected: "membership change".to_owned(),
            })?
            .map_err(|err| ClusterError::Raft {
                operation: "change_membership",
                detail: err.to_string(),
            })?;

        let mut result: Vec<NodeId> = raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect();
        result.sort_unstable();

        Ok(result)
    }

    /// A node's applied state.
    ///
    /// `None` if the node is not running.
    #[must_use]
    pub fn state(&self, node: NodeId) -> Option<ClusterState> {
        self.states.get(&node).map(StateHandle::read)
    }

    /// A node's last purged log index — the proof that compaction has happened.
    #[must_use]
    pub fn purged(&self, node: NodeId) -> Option<u64> {
        self.nodes
            .get(&node)
            .and_then(|raft| raft.metrics().borrow().purged)
            .map(|log_id| log_id.index)
    }

    /// The last index that stands in a snapshot on a node.
    #[must_use]
    pub fn snapshot(&self, node: NodeId) -> Option<u64> {
        self.nodes
            .get(&node)
            .and_then(|raft| raft.metrics().borrow().snapshot)
            .map(|log_id| log_id.index)
    }

    /// Waits until compaction on a node has bitten beyond `index`.
    ///
    /// The bound belongs to it: "something has been purged" does not suffice to
    /// show that a particular node can no longer go the log path. What is asked
    /// is whether **its next** entry is gone.
    ///
    /// # Errors
    ///
    /// [`ClusterError::Timeout`] if it is not purged that far.
    pub async fn wait_for_compaction_beyond(
        &self,
        node: NodeId,
        index: u64,
    ) -> Result<u64, ClusterError> {
        self.wait_until(&format!("log purged beyond index {index}"), || {
            self.purged(node).filter(|purged| *purged > index)
        })
        .await
    }

    /// Waits until compaction has bitten on a node at all.
    ///
    /// # Errors
    ///
    /// [`ClusterError::Timeout`] if nothing is purged.
    pub async fn wait_for_compaction(&self, node: NodeId) -> Result<u64, ClusterError> {
        self.wait_for_compaction_beyond(node, 0).await
    }

    /// The bus of this run — here faults are injected.
    #[must_use]
    pub fn bus(&self) -> &Bus {
        &self.bus
    }

    /// The identifiers of the running nodes.
    #[must_use]
    pub fn running(&self) -> Vec<NodeId> {
        self.nodes.keys().copied().collect()
    }

    /// The current leader as the running nodes see it.
    ///
    /// `None` if none of them agrees on one — the normal case on the minority
    /// side of a partition.
    #[must_use]
    pub fn leader(&self) -> Option<NodeId> {
        self.nodes
            .iter()
            .find(|(_, raft)| raft.metrics().borrow().state == ServerState::Leader)
            .map(|(id, _)| *id)
    }

    /// Waits until exactly one node considers itself the leader.
    ///
    /// # Errors
    ///
    /// [`ClusterError::Timeout`] if none leads within the patience.
    pub async fn wait_for_leader(&self) -> Result<NodeId, ClusterError> {
        self.wait_until("a leader", || self.leader()).await
    }

    /// Waits until one of `candidates` leads.
    ///
    /// With a partition one needs exactly that: "any leader" is ambiguous as
    /// long as the cut-off old leader still considers itself one. What is asked
    /// is the leader **of a particular side**.
    ///
    /// # Errors
    ///
    /// [`ClusterError::Timeout`] if none of the named ones leads.
    pub async fn wait_for_leader_among(
        &self,
        candidates: &[NodeId],
    ) -> Result<NodeId, ClusterError> {
        self.wait_until("a leader on this side", || {
            candidates.iter().copied().find(|id| {
                self.nodes
                    .get(id)
                    .is_some_and(|raft| raft.metrics().borrow().state == ServerState::Leader)
            })
        })
        .await
    }

    /// Waits until all running nodes have applied the same position.
    ///
    /// # Errors
    ///
    /// [`ClusterError::Timeout`] if they do not agree.
    pub async fn wait_for_convergence(&self) -> Result<u64, ClusterError> {
        let applied = || -> BTreeMap<NodeId, Option<u64>> {
            self.nodes
                .iter()
                .map(|(id, raft)| {
                    (
                        *id,
                        raft.metrics()
                            .borrow()
                            .last_applied
                            .map(|log_id| log_id.index),
                    )
                })
                .collect()
        };

        let converged = || -> Option<u64> {
            let stands = applied();
            let mut values = stands.values();
            let first = (*values.next()?)?;
            values.all(|other| *other == Some(first)).then_some(first)
        };

        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            if let Some(index) = converged() {
                return Ok(index);
            }
            if tokio::time::Instant::now() >= deadline {
                // The positions belong in the message: "not converged" without
                // the numbers leaves open whether one hangs or all wait.
                return Err(ClusterError::Timeout {
                    expected: format!("the same applied position, last {:?}", applied()),
                });
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits until the named nodes have applied the same position.
    ///
    /// For runs in which a node deliberately lags behind.
    ///
    /// # Errors
    ///
    /// [`ClusterError::Timeout`] if they do not agree.
    pub async fn wait_for_convergence_among(&self, nodes: &[NodeId]) -> Result<u64, ClusterError> {
        self.wait_until("the same position among the named nodes", || {
            let mut applied = nodes.iter().map(|id| {
                self.nodes
                    .get(id)
                    .and_then(|raft| raft.metrics().borrow().last_applied)
                    .map(|log_id| log_id.index)
            });

            let first = applied.next().flatten()?;
            applied.all(|other| other == Some(first)).then_some(first)
        })
        .await
    }

    /// Writes over the given node.
    ///
    /// # Errors
    ///
    /// [`ClusterError::Raft`] if `openraft` refuses (for instance: no leader),
    /// [`ClusterError::Timeout`] if the write is not committed — the case
    /// without quorum.
    pub async fn write(&self, node: NodeId, command: Command) -> Result<Outcome, ClusterError> {
        let raft = self
            .nodes
            .get(&node)
            .ok_or(ClusterError::UnknownNode { node })?;

        let attempt = tokio::time::timeout(PATIENCE, raft.client_write(command.into()))
            .await
            .map_err(|_| ClusterError::Timeout {
                expected: format!("commit over node {node}"),
            })?;

        attempt
            .map(|response| response.data)
            .map_err(|err| ClusterError::Raft {
                operation: "client_write",
                detail: err.to_string(),
            })
    }

    /// Writes over the current leader and follows referrals in the process.
    ///
    /// A node that led a moment ago refers to the new leader after a change
    /// (`ForwardToLeader`). That is no error but the statement to try elsewhere —
    /// and a real client (ADR-0018) will have to do the same.
    ///
    /// # Errors
    ///
    /// As [`Cluster::write`]; additionally if after several referrals still no
    /// reachable leader has been found.
    pub async fn write_to_leader(&self, command: Command) -> Result<Outcome, ClusterError> {
        let mut target = self.wait_for_leader().await?;

        for _ in 0..8 {
            match self.write(target, command.clone()).await {
                Ok(outcome) => return Ok(outcome),
                Err(ClusterError::Raft { operation, detail }) => {
                    let Some(next) = leader_hint(&detail) else {
                        return Err(ClusterError::Raft { operation, detail });
                    };
                    target = next;
                }
                Err(other) => return Err(other),
            }
        }

        Err(ClusterError::Timeout {
            expected: "a leader that accepts the write".to_owned(),
        })
    }

    /// Halts a node: shut `openraft` down, take it off the bus, mark it as
    /// failed.
    ///
    /// The order is deliberate — a node still hanging on the bus while its tasks
    /// end would get messages that go nowhere.
    ///
    /// # Errors
    ///
    /// [`ClusterError`] if `openraft` does not complete the shutdown.
    pub async fn stop(&mut self, node: NodeId) -> Result<(), ClusterError> {
        let raft = self
            .nodes
            .remove(&node)
            .ok_or(ClusterError::UnknownNode { node })?;

        self.bus.unregister(node);
        let mut down: Vec<NodeId> = (1..=self.size)
            .filter(|id| self.bus.faults().is_down(*id))
            .collect();
        down.push(node);
        self.bus.inject(self.bus.faults().with_down(down));

        raft.shutdown().await.map_err(|err| ClusterError::Raft {
            operation: "shutdown",
            detail: err.to_string(),
        })?;

        Ok(())
    }

    /// Restarts a halted node from **its** file.
    ///
    /// The proof that the state lay on disk and not in memory: the file is the
    /// same, the process part is another.
    ///
    /// # Errors
    ///
    /// [`ClusterError`] if the storage cannot be opened or `openraft` refuses
    /// the start.
    pub async fn restart(&mut self, node: NodeId) -> Result<(), ClusterError> {
        let path = self
            .paths
            .get(&node)
            .ok_or(ClusterError::UnknownNode { node })?
            .clone();

        let (raft, state) = spawn(node, &path, &self.bus, &self.setup).await?;
        self.bus.register(node, raft.clone());
        self.nodes.insert(node, raft);
        self.states.insert(node, state);

        let down: Vec<NodeId> = (1..=self.size)
            .filter(|id| *id != node && self.bus.faults().is_down(*id))
            .collect();
        self.bus.inject(self.bus.faults().with_down(down));

        Ok(())
    }

    /// Injects a fault state and keeps the halted nodes as failed — a stopped
    /// node does not come back to life through a healed partition.
    pub fn inject(&self, faults: Faults) {
        let down: Vec<NodeId> = (1..=self.size)
            .filter(|id| !self.nodes.contains_key(id))
            .collect();
        self.bus.inject(faults.with_down(down));
    }

    /// Halts everything and reads the applied state **from disk**.
    ///
    /// The detour over the file is the point: the state machine belongs to
    /// `openraft` as long as the node runs. What comes back here has survived a
    /// restart — and that is exactly the question a split-brain test asks.
    ///
    /// # Errors
    ///
    /// [`ClusterError`] if a node does not halt or its file is not readable
    /// afterwards.
    pub async fn stop_and_read(mut self) -> Result<BTreeMap<NodeId, ClusterState>, ClusterError> {
        for node in self.running() {
            self.stop(node).await?;
        }

        let mut states = BTreeMap::new();
        for (node, path) in &self.paths {
            let storage = open_when_released(*node, path).await?;
            states.insert(*node, storage.machine.state());
        }

        drop(self.dir);
        Ok(states)
    }

    /// Polls until the condition bites — in virtual time, i.e. without wall
    /// clock cost.
    async fn wait_until<T>(
        &self,
        expected: &str,
        mut condition: impl FnMut() -> Option<T>,
    ) -> Result<T, ClusterError> {
        let deadline = tokio::time::Instant::now() + PATIENCE;

        loop {
            if let Some(value) = condition() {
                return Ok(value);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ClusterError::Timeout {
                    expected: expected.to_owned(),
                });
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Builds a `Raft` instance on a file.
async fn spawn(
    id: NodeId,
    path: &PathBuf,
    bus: &Bus,
    setup: &Setup,
) -> Result<(Raft<TypeConfig>, StateHandle), ClusterError> {
    let storage = Storage::open(path).map_err(|err| ClusterError::Storage {
        node: id,
        detail: err.to_string(),
    })?;
    let state = storage.machine.handle();

    let min = ELECTION_BASE_MS + (id - 1) * ELECTION_STAGGER_MS;
    let config = Config {
        cluster_name: "tardigrade-dst".to_owned(),
        // max = min + 1: `gen_range(min..min+1)` has exactly one possible value.
        // `openraft`'s unseeded `thread_rng` thereby becomes without effect,
        // without having to be replaced.
        election_timeout_min: min,
        election_timeout_max: min + 1,
        heartbeat_interval: HEARTBEAT_MS,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(setup.snapshot_every),
        max_in_snapshot_log_to_keep: setup.keep_logs,
        ..Config::default()
    };
    let config = config.validate().map_err(|err| ClusterError::Raft {
        operation: "config",
        detail: err.to_string(),
    })?;

    let raft = Raft::new(
        id,
        std::sync::Arc::new(config),
        bus.factory(id),
        storage.log,
        storage.machine,
    )
    .await
    .map_err(|err| ClusterError::Raft {
        operation: "Raft::new",
        detail: err.to_string(),
    })?;

    Ok((raft, state))
}

/// Opens a halted node's file as soon as it is released.
///
/// `Raft::shutdown` ends the core, but a delivery that was just sleeping in the
/// bus's latency still holds a handle on the target instance — and thereby
/// `redb` the file. That is no malfunction but the consequence of the harness
/// having real messages in the air.
///
/// Waiting happens in virtual time: the sleep gives the executor the opportunity
/// to finish exactly those tasks, and costs no wall clock.
async fn open_when_released(node: NodeId, path: &PathBuf) -> Result<Storage, ClusterError> {
    let mut last = String::new();

    for _ in 0..100 {
        match Storage::open(path) {
            Ok(storage) => return Ok(storage),
            Err(err) => {
                last = err.to_string();
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    Err(ClusterError::Storage {
        node,
        detail: format!("still occupied after the halt: {last}"),
    })
}

/// Extracts the referred leader from a `ForwardToLeader` message.
///
/// Over the text and not over the error type: `client_write` delivers the
/// referral in `ClientWriteError`, and the way there leads through two generic
/// envelopes whose type parameters would turn up here only for this one purpose.
/// In the harness that is defensible — in a real client (ADR-0018) it would not
/// be; there the error is evaluated typed.
fn leader_hint(detail: &str) -> Option<NodeId> {
    let rest = detail.strip_prefix("has to forward request to: Some(")?;
    let (id, _) = rest.split_once(')')?;
    id.parse().ok()
}
