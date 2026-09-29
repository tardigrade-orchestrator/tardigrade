//! The in-process bus: `RaftNetwork` and `RaftNetworkFactory` over channels
//! instead of over a network.
//!
//! A message runs through three stations here, and the middle one is the reason
//! the bus exists:
//!
//! 1. The injector decides about it ([`Faults::decide`]).
//! 2. It waits out its latency — in **virtual** time.
//! 3. It is handed to the target `Raft` instance, which knows nothing of it.
//!
//! Between 2 and 3 the fault state is checked **again**. A message that took off
//! while the path was open and arrives when it is no longer open gets lost —
//! that is no special case but the normal case with a partition, and without
//! this second check the bus would become reliable at exactly the moment at
//! which it must not be.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use openraft::error::{RPCError, RaftError, RemoteError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, Raft};
use tg_consensus::{NodeId, TypeConfig};
use tokio::time::Instant;

use crate::faults::{Faults, Verdict};
use crate::trace::{Event, Kind, Outcome, Trace};

/// The bus discarded the message.
///
/// For `openraft` indistinguishable from a crashed peer — and that is exactly
/// the point: a partition looks from inside like a dead node.
#[derive(Debug)]
struct Dropped {
    from: NodeId,
    to: NodeId,
}

impl fmt::Display for Dropped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "message {} -> {} discarded", self.from, self.to)
    }
}

impl std::error::Error for Dropped {}

/// The shared state of the bus.
struct Inner {
    seed: u64,
    faults: Faults,
    /// Serial number per path. It stands here and not in the [`Link`] instance,
    /// because `openraft` may build itself a new client for the same target at
    /// any time — a counter in the instance would then begin anew and draw the
    /// same verdicts a second time.
    counters: BTreeMap<(NodeId, NodeId), u64>,
    nodes: BTreeMap<NodeId, Raft<TypeConfig>>,
    trace: Trace,
    start: Instant,
}

/// The bus, shared by all nodes of a run.
#[derive(Clone)]
pub struct Bus {
    inner: Arc<Mutex<Inner>>,
}

impl fmt::Debug for Bus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.lock();
        f.debug_struct("Bus")
            .field("seed", &inner.seed)
            .field("nodes", &inner.nodes.keys().collect::<Vec<_>>())
            .field("events", &inner.trace.events().len())
            .finish()
    }
}

impl Bus {
    /// A bus without a disturbance, for a run with this seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                seed,
                faults: Faults::none(),
                counters: BTreeMap::new(),
                nodes: BTreeMap::new(),
                trace: Trace::new(seed),
                start: Instant::now(),
            })),
        }
    }

    /// Hangs a `Raft` instance on the bus.
    ///
    /// After the construction, not during it: `Raft::new` wants the network
    /// factory already, the factory wants the instances — one of the two sides
    /// has to be handed in afterwards.
    pub fn register(&self, id: NodeId, raft: Raft<TypeConfig>) {
        self.lock().nodes.insert(id, raft);
    }

    /// Takes an instance out again (node stopped).
    pub fn unregister(&self, id: NodeId) {
        self.lock().nodes.remove(&id);
    }

    /// Sets the fault state — from now on it applies to every further decision.
    pub fn inject(&self, faults: Faults) {
        self.lock().faults = faults;
    }

    /// The current fault state.
    #[must_use]
    pub fn faults(&self) -> Faults {
        self.lock().faults.clone()
    }

    /// Lifts partition and failures, leaves latency and loss standing.
    pub fn heal(&self) {
        let healed = self.lock().faults.healed();
        self.inject(healed);
    }

    /// The trace recorded so far.
    #[must_use]
    pub fn trace(&self) -> Trace {
        self.lock().trace.clone()
    }

    /// The seed of this run.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.lock().seed
    }

    /// The network factory for a node.
    #[must_use]
    pub fn factory(&self, from: NodeId) -> BusFactory {
        BusFactory {
            bus: self.clone(),
            from,
        }
    }

    /// A poisoned lock is taken over instead of panicking: here lie recordings
    /// without invariants, and a test that fails at a lock instead of at its
    /// claim obscures its own failure.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Obtain the verdict and record it. The lock is released before the wait —
    /// a lock held across an `await` would serialize the whole run and thereby
    /// remove exactly the concurrency that is to be checked.
    fn depart(&self, from: NodeId, to: NodeId, kind: Kind) -> (Verdict, u64) {
        let mut inner = self.lock();

        let counter = inner.counters.entry((from, to)).or_default();
        let seq = *counter;
        *counter += 1;

        let verdict = inner.faults.decide(inner.seed, from, to, seq);
        let at = Instant::now().saturating_duration_since(inner.start);

        if verdict == Verdict::Drop {
            inner.trace.record(Event {
                at,
                from,
                to,
                kind,
                seq,
                outcome: Outcome::Dropped,
            });
        }

        (verdict, seq)
    }

    /// After the latency: is the path still open, and does the target still
    /// exist? Yields the instance or nothing.
    fn arrive(
        &self,
        from: NodeId,
        to: NodeId,
        kind: Kind,
        seq: u64,
        delay: Duration,
    ) -> Option<Raft<TypeConfig>> {
        let mut inner = self.lock();
        let at = Instant::now().saturating_duration_since(inner.start);

        let still_open = inner.faults.decide(inner.seed, from, to, seq) != Verdict::Drop;
        let target = inner.nodes.get(&to).cloned();

        // Delivered only if both hold: the path is still open and the target is
        // still running. Everything else is a loss in flight.
        let arrived = if still_open { target } else { None };

        let outcome = match &arrived {
            Some(_) => Outcome::Delivered { delay },
            None => Outcome::LostInFlight,
        };
        inner.trace.record(Event {
            at,
            from,
            to,
            kind,
            seq,
            outcome,
        });

        arrived
    }
}

/// A node's network factory.
#[derive(Debug, Clone)]
pub struct BusFactory {
    bus: Bus,
    from: NodeId,
}

impl RaftNetworkFactory<TypeConfig> for BusFactory {
    type Network = Link;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        Link {
            bus: self.bus.clone(),
            from: self.from,
            to: target,
        }
    }
}

/// A directed path between two nodes.
#[derive(Debug, Clone)]
pub struct Link {
    bus: Bus,
    from: NodeId,
    to: NodeId,
}

impl Link {
    /// The common way of every message: decide, wait, decide again, deliver.
    ///
    /// Returns `None` if the message was discarded — the caller makes the
    /// `Unreachable` out of it that `openraft` expects.
    async fn carry(&self, kind: Kind) -> Option<Raft<TypeConfig>> {
        let (verdict, seq) = self.bus.depart(self.from, self.to, kind);

        let delay = match verdict {
            Verdict::Drop => return None,
            Verdict::Deliver { delay } => delay,
        };

        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }

        self.bus.arrive(self.from, self.to, kind, seq, delay)
    }

    fn unreachable<E: std::error::Error + 'static>(&self) -> RPCError<NodeId, BasicNode, E> {
        RPCError::Unreachable(Unreachable::new(&Dropped {
            from: self.from,
            to: self.to,
        }))
    }
}

impl RaftNetwork<TypeConfig> for Link {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let Some(target) = self.carry(Kind::AppendEntries).await else {
            return Err(self.unreachable());
        };

        target
            .append_entries(rpc)
            .await
            .map_err(|err| RPCError::RemoteError(RemoteError::new(self.to, err)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let Some(target) = self.carry(Kind::Vote).await else {
            return Err(self.unreachable());
        };

        target
            .vote(rpc)
            .await
            .map_err(|err| RPCError::RemoteError(RemoteError::new(self.to, err)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, openraft::error::InstallSnapshotError>>,
    > {
        let Some(target) = self.carry(Kind::InstallSnapshot).await else {
            return Err(self.unreachable());
        };

        target
            .install_snapshot(rpc)
            .await
            .map_err(|err| RPCError::RemoteError(RemoteError::new(self.to, err)))
    }
}
