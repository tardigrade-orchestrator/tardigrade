//! The projection, materialized from the log (ADR-0004, ADR-0030).
//!
//! Until phase 4 the view came from the agent's local cache, because there was no
//! cluster. From here it comes from the state machine -- and that comes from the
//! log. That is the sentence from ADR-0004, at last verbatim: the projection is
//! **deterministically derived from the truth** and holds nothing whose loss
//! hurts.
//!
//! From that follows the property this phase must check: five nodes with the same
//! log have the same projection. It follows not from good will but from three
//! determinations that already stand:
//!
//! 1. The state is ordered (`BTree*` in `ClusterState`, phase 5a).
//! 2. The documents in it are **canonical** -- reserialized from the parsed model,
//!    not the submitted byte (phase 5a).
//! 3. The projection itself is ordered (`BTreeMap` in `tg-store`, phase 4).
//!
//! # Why the agent keeps its own projection
//!
//! The `tg-agent` goes on materializing from its local cache. Hanging it on this
//! projection would mean making it dependent on the control plane -- exactly what
//! ADR-0019 excludes. The two views have different tasks: this one is cluster-wide
//! and for readers (ADR-0018), the agent's is node-local and survives the loss of
//! the quorum.

use std::sync::Arc;

use tg_consensus::ClusterState;
use tg_store::Projection;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Skipped {
    pub workloads: usize,
}

impl Skipped {
    #[must_use]
    pub fn any(self) -> bool {
        self.workloads > 0
    }
}

pub fn materialize(state: &ClusterState, into: &Projection) -> Skipped {
    let mut workloads = Vec::new();
    let mut skipped = Skipped::default();

    for entry in state.workloads() {
        match tg_defs::from_str(entry.document()) {
            Ok(set) => workloads.extend(set.workloads().iter().cloned()),
            Err(_) => skipped.workloads += 1,
        }
    }

    into.materialize(&workloads);
    skipped
}

pub struct Feed {
    projection: Arc<Projection>,
}

impl std::fmt::Debug for Feed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Feed").finish_non_exhaustive()
    }
}

impl Feed {
    #[must_use]
    pub fn spawn(
        raft: &openraft::Raft<tg_consensus::TypeConfig>,
        state: &tg_consensus::StateHandle,
        health: &tg_telemetry::probes::Health,
    ) -> Self {
        let projection = Arc::new(Projection::new());

        // Once at once: after a restart the state already stands on the disk,
        // and the first metric change would come only with the next entry. Until
        // then a reader would see an empty view and take it for the truth.
        // **Read the index before the content**, so that it never points beyond it
        // (see `Projection::applied`).
        let at = raft.metrics().borrow().last_applied.map(|log| log.index);
        let skipped = materialize(&state.read(), &projection);
        report(skipped);
        projection.note_applied(at);

        // **A factory instead of a handle** (ADR-0116, determination 2): the
        // watcher starts the task itself and can set it up again after a panic.
        // `raft.metrics()` gives a **fresh** receiver in the process -- one passed
        // on would carry the crashed one's state, and the first `changed()` would
        // come only at the next change.
        //
        // This task may return: if the sender falls, the Raft is gone, and that is
        // the end of the process. Then the watcher expressly does **not** restart
        // it (determination 1).
        let feed_raft = raft.clone();
        let feed_state = state.clone();
        let feed_projection = Arc::clone(&projection);
        let feed = move || {
            let mut metrics = feed_raft.metrics();
            let state = feed_state.clone();
            let task_projection = Arc::clone(&feed_projection);

            tokio::spawn(async move {
                let mut applied = None;

                while metrics.changed().await.is_ok() {
                    let current = metrics.borrow().last_applied;
                    if current == applied {
                        continue;
                    }
                    applied = current;

                    let skipped = materialize(&state.read(), &task_projection);
                    report(skipped);
                    // **After** materializing: the noted state thereby belongs at
                    // most to an older view, never to a newer one. And if this task
                    // dies, the number stops growing. Until ADR-0082 that was the
                    // only way on which a reader could see it (it stands in no
                    // `select!`, ADR-0031); since then it has a watcher.
                    task_projection.note_applied(current.map(|log| log.index));
                }
            })
        };

        let _watcher = tg_telemetry::probes::supervise(health, crate::health::PROJECTION, feed);

        Self { projection }
    }

    #[must_use]
    pub fn projection(&self) -> Arc<Projection> {
        Arc::clone(&self.projection)
    }
}

fn report(skipped: Skipped) {
    if skipped.any() {
        tracing::warn!(
            workloads = skipped.workloads,
            "not readable in the state, left out of the projection"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{Skipped, materialize};
    use tg_consensus::{ClusterState, Command, Outcome, Topology};
    use tg_defs::DependencyKind;
    use tg_store::{ActualStatus, Projection};

    fn document(name: &str, after: Option<&str>) -> String {
        let dependencies = after.map_or(String::new(), |target| {
            format!(
                "<dependencies><after ref=\"{target}\"/><requires ref=\"{target}\"/></dependencies>"
            )
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

    fn populated() -> ClusterState {
        let mut state = ClusterState::default();
        for command in [
            upsert("db", None),
            upsert("api", Some("db")),
            Command::UpsertNode {
                name: "node-1".to_owned(),
                topology: Topology {
                    site: "fra".to_owned(),
                    hall: "h1".to_owned(),
                    rack: "r7".to_owned(),
                },
                capacity: tg_consensus::Resources::default(),
                reserved: tg_consensus::Resources::default(),
                source: tg_consensus::Origin::Operator,
            },
        ] {
            assert_eq!(state.apply(&command), Outcome::Applied);
        }
        state
    }

    #[test]
    fn the_state_becomes_the_view() {
        let projection = Projection::new();
        let skipped = materialize(&populated(), &projection);

        assert_eq!(skipped, Skipped::default());

        let names: Vec<String> = projection
            .workloads()
            .into_iter()
            .map(|record| record.name)
            .collect();
        assert_eq!(names, ["api", "db"]);

        assert_eq!(projection.targets_of("api", DependencyKind::After), ["db"]);
        assert_eq!(
            projection.targets_of("api", DependencyKind::Requires),
            ["db"]
        );
        assert!(
            projection
                .targets_of("db", DependencyKind::After)
                .is_empty()
        );
    }

    #[test]
    fn the_same_state_yields_the_same_view() {
        let mut forward = ClusterState::default();
        for command in [upsert("db", None), upsert("api", Some("db"))] {
            assert_eq!(forward.apply(&command), Outcome::Applied);
        }

        let mut backward = ClusterState::default();
        for command in [upsert("api", Some("db")), upsert("db", None)] {
            assert_eq!(backward.apply(&command), Outcome::Applied);
        }

        let left = Projection::new();
        let right = Projection::new();
        materialize(&forward, &left);
        materialize(&backward, &right);

        assert_eq!(left.workloads(), right.workloads());
        assert_eq!(
            left.targets_of("api", DependencyKind::After),
            right.targets_of("api", DependencyKind::After)
        );
        assert_eq!(left.actual_states(), right.actual_states());
    }

    #[test]
    fn materializing_replaces_instead_of_accumulating() {
        let mut state = populated();
        let projection = Projection::new();
        materialize(&state, &projection);
        assert_eq!(projection.workloads().len(), 2);

        assert_eq!(
            state.apply(&Command::RemoveWorkload {
                name: "api".to_owned()
            }),
            Outcome::Applied
        );
        materialize(&state, &projection);

        let names: Vec<String> = projection
            .workloads()
            .into_iter()
            .map(|record| record.name)
            .collect();
        assert_eq!(names, ["db"]);
        assert!(
            projection
                .targets_of("api", DependencyKind::After)
                .is_empty()
        );
    }

    #[test]
    fn an_empty_state_yields_an_empty_view() {
        let projection = Projection::new();
        let skipped = materialize(&ClusterState::default(), &projection);

        assert!(!skipped.any());
        assert!(projection.workloads().is_empty());
    }

    #[test]
    fn a_rebuild_leaves_the_reported_state_alone() {
        let state = populated();
        let projection = Projection::new();
        materialize(&state, &projection);

        projection.report_instances("n1", vec![("api".to_owned(), 0, ActualStatus::Running)]);
        assert_eq!(
            projection.actual_states().get(&("api".to_owned(), 0)),
            Some(&ActualStatus::Running)
        );

        materialize(&state, &projection);
        assert_eq!(
            projection.actual_states().get(&("api".to_owned(), 0)),
            Some(&ActualStatus::Running),
            "the reported actual state survives a movement of the log"
        );
        assert_eq!(projection.worst_of("api"), ActualStatus::Running);
    }
}
