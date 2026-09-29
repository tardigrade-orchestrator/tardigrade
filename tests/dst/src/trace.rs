//! The trace of a run — what falls out at the end as evidence.
//!
//! ADR-0020 makes DST runs exportable evidence for the DORA resilience test
//! obligation. The trace is thereby not a log for debugging but an artifact: it
//! has to be complete, ordered and reconstructible from the seed.
//!
//! Recorded is every decision of the bus, not every delivery — a discarded
//! message is the more interesting entry.

use std::time::Duration;

use tg_consensus::NodeId;

/// Which kind of message was in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Replication and heartbeat.
    AppendEntries,
    /// Vote request of an election.
    Vote,
    /// Snapshot transfer.
    InstallSnapshot,
}

impl Kind {
    /// The name as it stands in the trace.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AppendEntries => "append_entries",
            Self::Vote => "vote",
            Self::InstallSnapshot => "install_snapshot",
        }
    }
}

/// What the bus did with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Delivered, after this latency.
    Delivered {
        /// Latency until delivery.
        delay: Duration,
    },
    /// Discarded on sending.
    Dropped,
    /// Discarded in flight: at sending the path was open, at delivery it was
    /// not. That is exactly how a packet flying into a partition behaves.
    LostInFlight,
}

/// An entry of the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// Virtual time since the start of the run.
    pub at: Duration,
    /// Sender.
    pub from: NodeId,
    /// Receiver.
    pub to: NodeId,
    /// Kind of message.
    pub kind: Kind,
    /// Serial number on this path.
    pub seq: u64,
    /// What happened.
    pub outcome: Outcome,
}

/// The ordered trace of a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trace {
    events: Vec<Event>,
    seed: u64,
}

impl Trace {
    /// An empty trace for a run with this seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            events: Vec::new(),
            seed,
        }
    }

    pub(crate) fn record(&mut self, event: Event) {
        self.events.push(event);
    }

    /// The seed from which the run arose.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// All events in the order of their decision.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Number of discarded messages — on sending and in flight.
    #[must_use]
    pub fn dropped(&self) -> usize {
        self.events
            .iter()
            .filter(|event| !matches!(event.outcome, Outcome::Delivered { .. }))
            .count()
    }

    /// Number of delivered messages.
    #[must_use]
    pub fn delivered(&self) -> usize {
        self.events.len() - self.dropped()
    }

    /// The trace without timestamps.
    ///
    /// For the comparison of two runs: the bus's decisions hang on the seed, the
    /// points in time additionally on when `openraft` let its tasks run. Whoever
    /// checks reproducibility compares the decisions — the points in time are
    /// incidental and would hide a real comparison behind noise.
    #[must_use]
    pub fn decisions(&self) -> Vec<(NodeId, NodeId, Kind, u64, Outcome)> {
        self.events
            .iter()
            .map(|event| (event.from, event.to, event.kind, event.seq, event.outcome))
            .collect()
    }

    /// The trace as JSON — the output format of the evidence.
    ///
    /// As with the Raft log (ADR-0020): readable without our binary. An auditor
    /// gets the seed and the file and can hold them against each other.
    #[must_use]
    pub fn to_json(&self) -> String {
        let events: Vec<serde_json::Value> = self
            .events
            .iter()
            .map(|event| {
                let (outcome, delay) = match event.outcome {
                    Outcome::Delivered { delay } => ("delivered", Some(delay)),
                    Outcome::Dropped => ("dropped", None),
                    Outcome::LostInFlight => ("lost_in_flight", None),
                };
                serde_json::json!({
                    "at_ms": event.at.as_millis(),
                    "from": event.from,
                    "to": event.to,
                    "kind": event.kind.as_str(),
                    "seq": event.seq,
                    "outcome": outcome,
                    "delay_ms": delay.map(|delay| delay.as_millis()),
                })
            })
            .collect();

        serde_json::json!({
            "seed": self.seed,
            "delivered": self.delivered(),
            "dropped": self.dropped(),
            "events": events,
        })
        .to_string()
    }
}
