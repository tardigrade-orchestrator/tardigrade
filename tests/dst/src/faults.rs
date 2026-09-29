//! The fault injector: what happens to a single message.
//!
//! The core is a **pure function**
//! `(seed, sender, receiver, message number) → verdict`. No shared random
//! generator, no state, no clock.
//!
//! That is the decision on which the reproducibility from ADR-0020 hangs. A
//! shared generator would be consumed in the order in which the executor lets
//! the tasks run — the verdict about the seventh message from node 1 to node 2
//! would then hang on how many messages have meanwhile flowed between entirely
//! different nodes. A seed would then reproduce the run only as long as the task
//! order stays the same, and that is not a promise one wants to give.
//!
//! Drawn per counter, every verdict hangs only on its own number.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use tg_consensus::NodeId;

/// How the bus treats a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Deliver, after this latency.
    Deliver {
        /// Latency until delivery.
        delay: Duration,
    },
    /// Drop. For the sender indistinguishable from a dead receiver — that is
    /// exactly what a packet loss looks like.
    Drop,
}

/// The configured fault state of the network.
///
/// Built over `with_*`: a scenario thereby reads as one line, and the state is
/// immutable — it is **replaced** during the run, not changed, so that it stays
/// clear from when which disturbance applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Faults {
    /// Node → group number. Whoever is not named lies in group 0.
    partition: BTreeMap<NodeId, u8>,
    /// Failed nodes: they neither send nor receive.
    down: BTreeSet<NodeId>,
    /// Base latency of every message.
    base_delay: Duration,
    /// Spread on top, uniformly distributed in `[0, jitter)`.
    jitter: Duration,
    /// Additional latency per node, in both directions.
    node_delay: BTreeMap<NodeId, Duration>,
    /// Loss probability in per mille.
    loss_permille: u32,
}

impl Faults {
    /// A network without a disturbance: everything arrives, immediately.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Divides the nodes into groups; nothing crosses group boundaries.
    ///
    /// Whoever is named in no group stays with all the other unnamed ones —
    /// otherwise every scenario would have to enumerate all five nodes.
    ///
    /// # Panics
    ///
    /// At more than 254 groups. The cluster has five nodes (ADR-0031); a silent
    /// collapse of two group numbers would be the worse answer — it would join
    /// two islands that should be separate, and the test would run green.
    #[must_use]
    pub fn with_partition<'a>(mut self, groups: impl IntoIterator<Item = &'a [NodeId]>) -> Self {
        self.partition.clear();
        for (index, group) in groups.into_iter().enumerate() {
            let index = u8::try_from(index + 1).expect("at most 254 groups");
            for node in group {
                self.partition.insert(*node, index);
            }
        }
        self
    }

    /// Declares nodes failed.
    #[must_use]
    pub fn with_down(mut self, nodes: impl IntoIterator<Item = NodeId>) -> Self {
        self.down = nodes.into_iter().collect();
        self
    }

    /// Sets the base latency of every message.
    #[must_use]
    pub fn with_base_delay(mut self, delay: Duration) -> Self {
        self.base_delay = delay;
        self
    }

    /// Sets the spread of the latency — out of it the reordering arises.
    #[must_use]
    pub fn with_jitter(mut self, jitter: Duration) -> Self {
        self.jitter = jitter;
        self
    }

    /// Gives a node an additional latency of its own, in both directions.
    #[must_use]
    pub fn with_node_delay(mut self, node: NodeId, delay: Duration) -> Self {
        self.node_delay.insert(node, delay);
        self
    }

    /// Sets the loss rate in per mille (1000 = everything).
    #[must_use]
    pub fn with_loss_permille(mut self, permille: u32) -> Self {
        self.loss_permille = permille.min(1000);
        self
    }

    /// The same settings, but without a partition and without a failure.
    ///
    /// Healing leaves latency and loss standing: a partition ends, the network
    /// beneath stays the same.
    #[must_use]
    pub fn healed(&self) -> Self {
        Self {
            partition: BTreeMap::new(),
            down: BTreeSet::new(),
            ..self.clone()
        }
    }

    /// Whether a node counts as failed.
    #[must_use]
    pub fn is_down(&self, node: NodeId) -> bool {
        self.down.contains(&node)
    }

    /// The verdict about a single message.
    ///
    /// `seq` is the serial number of **this path**, not of the whole run. Pure:
    /// the same call always yields the same verdict.
    #[must_use]
    pub fn decide(&self, seed: u64, from: NodeId, to: NodeId, seq: u64) -> Verdict {
        // A node always reaches itself. `openraft` sends itself no RPCs; an
        // injector that partitioned the own identifier would nevertheless be a
        // trap for every later scenario.
        if from == to && !self.down.contains(&from) {
            return Verdict::Deliver {
                delay: Duration::ZERO,
            };
        }

        // Hard causes first: they are state, not a roll.
        if self.down.contains(&from) || self.down.contains(&to) {
            return Verdict::Drop;
        }
        if self.group(from) != self.group(to) {
            return Verdict::Drop;
        }

        let mut draw = Draw::new(seed, from, to, seq);

        if self.loss_permille > 0 && draw.below(1000) < u64::from(self.loss_permille) {
            return Verdict::Drop;
        }

        let mut delay = self.base_delay
            + self.node_delay.get(&from).copied().unwrap_or_default()
            + self.node_delay.get(&to).copied().unwrap_or_default();

        if !self.jitter.is_zero() {
            let span = u64::try_from(self.jitter.as_nanos()).unwrap_or(u64::MAX);
            delay += Duration::from_nanos(draw.below(span));
        }

        Verdict::Deliver { delay }
    }

    fn group(&self, node: NodeId) -> u8 {
        self.partition.get(&node).copied().unwrap_or(0)
    }
}

/// Counter-based drawing: out of (seed, path, number) comes a stream.
///
/// `splitmix64` as the mixing function — it is meant exactly for making
/// independent-looking values out of a running counter, and it comes without a
/// dependency (ADR-0023: the supply chain does not grow for a harness).
struct Draw(u64);

impl Draw {
    fn new(seed: u64, from: NodeId, to: NodeId, seq: u64) -> Self {
        let mut state = seed;
        for part in [from.wrapping_mul(0x9E37_79B9_7F4A_7C15), to, seq] {
            state = mix(state ^ part);
        }
        Self(state)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix(self.0)
    }

    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 { 0 } else { self.next() % bound }
    }
}

fn mix(value: u64) -> u64 {
    let mut z = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
