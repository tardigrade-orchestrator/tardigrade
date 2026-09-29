//! The scheduler in the leader (ADR-0011).
//!
//! It decides nothing itself: the rules stand in `tg_model::placement`, the step
//! in `tg_consensus::schedule`. What stands here is the loop around it -- and
//! three determinations that belong to it.
//!
//! **Only the leader plans.** Placement is a cluster-wide mutation and thereby
//! quorum-bound (ADR-0010, ADR-0019). A follower that planned would either be
//! refused (because it may not write) or -- worse -- build a second truth on a
//! minority side.
//!
//! **Level-triggered.** The step sees the whole state and proposes what is
//! missing. There is no event queue one could miss, and after a leader change the
//! new one does not begin at zero -- it sees the same state and comes to the same
//! result (ADR-0011: deterministic).
//!
//! **Without a quorum nothing happens.** Not as a special case but of its own
//! accord: without a majority there is no leader that can write, and a write
//! attempt runs into the refusal. That is the autonomy boundary from ADR-0010 at
//! the place it belongs -- running workloads stay untouched by it (ADR-0019).

use std::time::Duration;

use openraft::{Raft, ServerState};
use std::sync::Arc;

use tg_consensus::{Command, Origin, StateHandle, TypeConfig, schedule};
use tg_defs::DomainLevel;
use tg_model::placement::PlacementError;
use tg_store::Projection;

const COOLDOWN: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct Scheduler;

impl Scheduler {
    async fn apply_capacity_policy(
        raft: &Raft<TypeConfig>,
        state: &tg_consensus::ClusterState,
        projection: &Projection,
    ) {
        let policy = state.capacity_policy();
        if policy.is_empty() {
            return;
        }

        let reported = projection.reported_capacity();
        for (name, entry) in state.nodes() {
            let Some(report) = reported.get(name) else {
                continue;
            };
            let (capacity, reserved) = policy.apply(report);
            if capacity == *entry.capacity() && reserved == *entry.reserved() {
                continue;
            }

            let command = Command::UpsertNode {
                name: name.to_owned(),
                topology: entry.topology().clone(),
                capacity,
                reserved,
                // The origin stands in the log so that an auditor does not look
                // for an operator that did not exist (ADR-0049).
                source: Origin::Policy,
            };
            // Without an actor: the leader computed, no human decreed (ADR-0050).
            // `Origin::Policy` additionally says **which** computation it was.
            if let Err(err) = raft.client_write(command.into()).await {
                tracing::debug!(%err, node = %name, "the capacity was not written");
            }
        }
    }

    #[must_use]
    pub fn spawn(
        raft: &Raft<TypeConfig>,
        state: StateHandle,
        projection: Arc<Projection>,
        health: tg_telemetry::probes::Health,
    ) -> Self {
        let raft = raft.clone();
        let mut metrics = raft.metrics();

        tokio::spawn(async move {
            // **A cadence, and with a reason** (ADR-0057, determination 5). The
            // rotation policy reads the **clock**; a state channel cannot report
            // that a day has passed. Here the timer is no substitute for a signal,
            // it **is** the signal.
            //
            // One hour at a period of days: amply fine, and outside a window the
            // policy writes nothing, so a tick without a change costs nothing.
            let mut clock = tokio::time::interval(std::time::Duration::from_hours(1));
            clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            // **And a cadence that belongs to the lease** (ADR-0064). Until here
            // the renewal hung on **something** moving the metrics -- in a quiet
            // cluster that was the log, which it moves itself. A chain without a
            // floor: a single failed write let the next renewal wait until the
            // hourly cadence, and a single writer fenced itself after fifteen
            // seconds.
            //
            // A **fifth** of the deadline (ADR-0076, determination 4). A third
            // stood here -- the same choice as with the DNS TTL in phase 9a --, and
            // that was too slow: the cadence determines how deep the remaining time
            // falls before the leader **notices** a renewal that is due. With a
            // third the trough was `lease/6` (2.5 s) and thereby smaller than the
            // holder's safety margin -- measured, a healthy single writer counted as
            // fenced two thirds of the time.
            //
            // The cadence is a **sampling rate, no rate limiter**: how often it
            // writes is determined by the "second half" rule below alone. The log
            // does not grow because of it.
            let mut lease_clock = tokio::time::interval(LEASE_TICK);
            lease_clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                // **The watchdog** (ADR-0015). This loop renews the active-role
                // leases; if it dies, every single writer in the cluster fences
                // itself within fifteen seconds (ADR-0064) -- while liveness and
                // readiness stayed green because Raft is working after all, and the
                // metrics beside it froze at their last, healthy-looking values.
                //
                // The beat sits **in the pass** and not in a timer of its own: a
                // beat from a timer of its own would attest to the timer (the
                // finding from 11b).
                health.beat(crate::health::SCHEDULER, crate::health::now());

                // Only the leader plans. `borrow_and_update` as with the three
                // siblings (`session.rs`, `cluster.rs`, `health.rs`): measured it is
                // behaviourally neutral here -- the `changed()` below in the
                // `select!` marks itself -- but four loops with one question shall
                // have one shape, and it is the one that carries with
                // `has_changed()` too (`tgd/tests/watch_marking.rs`).
                let leading = metrics.borrow_and_update().state == ServerState::Leader;

                if leading {
                    let applied = state.read();

                    // **Detach without attach is a trap** (ADR-0054): a node
                    // nobody fetches back runs on unnoticed without a mesh -- it
                    // accepts nothing, gives everything away and reports nothing
                    // that would stand out. Here it becomes visible.
                    for (node, entry) in applied.nodes() {
                        metrics::gauge!(
                            tg_telemetry::names::NODE_ATTACHED,
                            "node" => node.to_owned()
                        )
                        .set(f64::from(u8::from(entry.attachment().in_mesh())));

                        if !entry.attachment().in_mesh() {
                            tracing::warn!(
                                %node,
                                "this node is detached and carries nothing"
                            );
                        }
                    }

                    report_state_sizes(&applied);

                    // **The rotation policy** (ADR-0057, determination 5). It reads
                    // the clock and the name, nothing else -- no failure produces
                    // these inputs (determination 1).
                    for command in rotations(&applied, days_since_epoch()) {
                        // The prohibition list is no claim: it is asked (ADR-0057,
                        // determination 2).
                        debug_assert!(command.may_be_policy());
                        let describe = format!("{command:?}");
                        if let Err(err) = raft.client_write(command.into()).await {
                            tracing::warn!(error = %err, %describe, "the rotation was not decreed");
                        }
                    }

                    // **The active-role leases** (ADR-0064). Renewal happens for a
                    // node that **reports** -- a present observation (ADR-0057). The
                    // expiry is time: whoever does not report gets nothing, and
                    // their lease lapses of its own accord. Exactly that is the
                    // fence from ADR-0010.
                    apply_leases_impl(&raft, &applied, &projection).await;

                    // **Clear away executed tombstones** (ADR-0104). Here too the
                    // input is a **present report**: a node that fails reports
                    // nothing, and then nothing is cleared away -- the failure does
                    // not produce the decree, it prevents it (ADR-0057).
                    apply_retirements(&raft, &applied, &projection).await;

                    report_divergences(&projection);

                    report_headroom(&applied);

                    // **Out of report and policy comes a log entry** (ADR-0049,
                    // determination 3). Before the planning, so that the step
                    // afterwards computes with the new numbers instead of lagging a
                    // round behind.
                    Self::apply_capacity_policy(&raft, &applied, &projection).await;
                    let applied = state.read();

                    let step = schedule::step(&applied);

                    // **How full the nodes are afterwards** (ADR-0127) -- from the
                    // map this step sorted by. After the planning and not before:
                    // the number shall name the state it produced.
                    report_pressure(&applied, &step.usage);

                    for rejection in &step.rejected {
                        tracing::warn!(
                            %rejection,
                            class = rejection.class(),
                            "not placeable"
                        );
                    }

                    // **Where an operator must go** (ADR-0011). That something does
                    // not lie anywhere is said by the two numbers below it -- and
                    // that is where the alarm rule belongs. This one says the
                    // **reason**, and until here that stood only in this process's
                    // log: on exactly one of five nodes, and only as long as it
                    // leads.
                    //
                    // The seven classes send to seven different places (capacity,
                    // topology, `node attach`, `node uncordon`, a DR case, or the
                    // declaration itself), so the class is the actual statement.
                    //
                    // **All seven per pass**, the ones with zero too: a time series
                    // that appears only at a finding is indistinguishable from a
                    // missing one -- and one that stays put when the class changes
                    // would report a reason that no longer exists (the finding of
                    // `tg_cluster_proxy_images`).
                    for class in PlacementError::CLASSES {
                        let count = step
                            .rejected
                            .iter()
                            .filter(|rejection| rejection.class() == *class)
                            .count();
                        metrics::gauge!(
                            tg_telemetry::names::SCHEDULER_UNPLACEABLE,
                            "class" => *class
                        )
                        .set(f64::from(u32::try_from(count).unwrap_or(u32::MAX)));
                    }

                    // **The denominator of the placement** (ADR-0011). The refusal
                    // above goes into this process's log and nowhere else; without
                    // these two numbers an operator does not see that their cluster
                    // cannot place something -- `tgctl cluster show` named the
                    // placements as a list without a wanted number beside it.
                    //
                    // Here and not in the scrape: the pass ticks **unconditionally**
                    // (`lease_clock`, ADR-0076), so far below the expiry window
                    // (ADR-0088) -- the same place and the same rationale as the
                    // `DOMAIN_*` beside it. And only the leader stands here -- this
                    // block lies in `if leading` --, which is right: the placement is
                    // desired and lies in the log, and five nodes with the same
                    // number would be five sources for one fact.
                    for coverage in &step.coverage {
                        metrics::gauge!(
                            tg_telemetry::names::WORKLOAD_PLACED,
                            "workload" => coverage.workload.clone()
                        )
                        .set(f64::from(coverage.placed));
                        metrics::gauge!(
                            tg_telemetry::names::WORKLOAD_REPLICAS,
                            "workload" => coverage.workload.clone()
                        )
                        .set(f64::from(coverage.wanted));
                    }

                    for command in step.commands {
                        let describe = format!("{command:?}");
                        // An error here is the normal case and no reason to halt:
                        // the node can have lost the leadership in the middle of the
                        // step. The next leader sees the same state and comes to the
                        // same result.
                        // Without an actor: the leader computed, no human decreed
                        // (ADR-0050). `Origin::Policy` additionally says **which**
                        // computation it was.
                        if let Err(err) = raft.client_write(command.into()).await {
                            tracing::warn!(command = %describe, error = %err, "the placement was not committed");
                            break;
                        }
                    }

                    if !step.rejected.is_empty() {
                        tokio::time::sleep(COOLDOWN).await;
                    }
                }

                // The log **or** the clock. Both wake the same pass; which of the
                // two it was plays no role, because every step is level-triggered
                // (ADR-0010).
                tokio::select! {
                    changed = metrics.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    _ = clock.tick() => {}
                    _ = lease_clock.tick() => {}
                }
            }
        });

        Self
    }
}

fn days_since_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| tg_model::keys::day_of(since.as_secs()))
        .unwrap_or_default()
}

fn rotations(state: &tg_consensus::ClusterState, day: u64) -> Vec<Command> {
    let policy = state.rotation_policy();
    if policy.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    // **The admitted nodes**, not the entered ones: a node has keys as soon as
    // `AdmitNode` knows it (ADR-0037, and ADR-0055 hangs the generation on exactly
    // that).
    for (node, _) in state.underlay() {
        for kind in tg_consensus::KeyKind::ALL {
            let Some(wanted) = policy.wanted(node, kind, day) else {
                continue;
            };
            if wanted <= state.key_generations(node).of(kind) {
                continue;
            }
            out.push(Command::SetKeyGeneration {
                node: node.to_owned(),
                kind,
                generation: wanted,
            });
        }
    }

    out
}

#[cfg(test)]
#[test]
fn the_lease_reads_the_report_and_not_the_readiness() {
    const SOURCE: &str = include_str!("scheduler.rs");

    // **The anchor begins with a line break**, and that is no cosmetics: without
    // it `find` finds the literal in **this** test and reads the guard instead of
    // the function (measured). The same self-reference as with the `alerts.yml`
    // guard and with the determinism tripwire.
    let start = SOURCE
        .find("\nfn leases(\n")
        .expect("the grant stands in this file");
    let end = SOURCE[start..]
        .find("\n}\n")
        .map_or(SOURCE.len(), |at| start + at);
    let body = &SOURCE[start..end];

    for forbidden in ["unready", "ready", "probe"] {
        assert!(
            !body.contains(forbidden),
            "`leases` names '{forbidden}' -- the active-role lease hangs on the \
             **report** and not on the probe (ADR-0101). Whoever changes that \
             turns a mismeasurement into a role change, and the standby starts \
             up on its own volume (ADR-0027)."
        );
    }

    // **And the guard must have found the body.** Without this assurance a run
    // over an empty excerpt would be green too -- the finding from the mutation
    // test rig.
    assert!(
        body.contains("reporting.contains(holder)"),
        "the body of `leases` was not read: {} characters",
        body.len()
    );
}

#[cfg(test)]
mod tests {
    use super::{retirements, rotations};
    use tg_consensus::{ClusterState, Command, KeyKind, RotationPolicy};

    fn admit(state: &mut ClusterState, name: &str) {
        state.apply(&Command::InviteNode {
            node: name.to_owned(),
            digest: tg_consensus::token_digest("whatever"),
            expires_at: 900,
        });
        state.apply(&Command::AdmitNode {
            node: name.to_owned(),
            spki: "AAAA".to_owned(),
            at: 1,
        });
    }

    #[test]
    fn without_a_policy_nothing_is_written() {
        let mut state = ClusterState::default();
        admit(&mut state, "a");

        assert!(rotations(&state, 10_000).is_empty());
    }

    #[test]
    fn a_policy_writes_only_the_kind_it_names() {
        let mut state = ClusterState::default();
        admit(&mut state, "a");
        state.apply(&Command::SetRotationPolicy {
            policy: RotationPolicy::default().with(KeyKind::Underlay, 90),
        });

        let out = rotations(&state, 10_000);

        assert_eq!(out.len(), 1, "exactly one decree: {out:?}");
        match &out[0] {
            Command::SetKeyGeneration { node, kind, .. } => {
                assert_eq!(node, "a");
                assert_eq!(*kind, KeyKind::Underlay);
            }
            other => panic!("the wrong command: {other:?}"),
        }
    }

    #[test]
    fn a_second_tick_on_the_same_day_writes_nothing() {
        let mut state = ClusterState::default();
        admit(&mut state, "a");
        state.apply(&Command::SetRotationPolicy {
            policy: RotationPolicy::default().with(KeyKind::Underlay, 90),
        });

        for command in rotations(&state, 10_000) {
            state.apply(&command);
        }

        assert!(
            rotations(&state, 10_000).is_empty(),
            "the policy writes twice on the same day"
        );
    }

    #[test]
    fn a_manual_generation_wins() {
        let mut state = ClusterState::default();
        admit(&mut state, "a");
        state.apply(&Command::SetRotationPolicy {
            policy: RotationPolicy::default().with(KeyKind::Underlay, 90),
        });
        state.apply(&Command::SetKeyGeneration {
            node: "a".to_owned(),
            kind: KeyKind::Underlay,
            generation: 100_000,
        });

        assert!(
            rotations(&state, 10_000).is_empty(),
            "the policy overwrote a higher generation set by hand"
        );
    }

    #[test]
    fn everything_it_writes_is_allowed_for_a_policy() {
        let mut state = ClusterState::default();
        admit(&mut state, "a");
        admit(&mut state, "b");
        state.apply(&Command::SetRotationPolicy {
            policy: RotationPolicy::default()
                .with(KeyKind::Underlay, 90)
                .with(KeyKind::Identity, 180),
        });

        let out = rotations(&state, 10_000);
        assert!(!out.is_empty(), "otherwise the test checks nothing");
        for command in out {
            let kind = command.kind();
            assert!(command.may_be_policy(), "no policy may write '{kind}'");
        }
    }

    #[test]
    fn a_reported_retirement_becomes_a_command() {
        let mut state = ClusterState::default();
        state.apply(&Command::DeleteVolume {
            volume: "data".to_owned(),
            node: "node-1".to_owned(),
            at: 0,
        });

        let reported = [("node-1".to_owned(), vec!["data".to_owned()])]
            .into_iter()
            .collect();

        assert_eq!(
            retirements(&state, &reported),
            vec![Command::RetireTombstone {
                volume: "data".to_owned(),
                node: "node-1".to_owned(),
            }]
        );
    }

    #[test]
    fn a_silent_node_keeps_its_tombstone() {
        let mut state = ClusterState::default();
        state.apply(&Command::DeleteVolume {
            volume: "data".to_owned(),
            node: "node-1".to_owned(),
            at: 0,
        });

        assert!(retirements(&state, &std::collections::BTreeMap::new()).is_empty());
    }

    #[test]
    fn a_report_from_one_node_does_not_retire_another() {
        let mut state = ClusterState::default();
        for node in ["node-1", "node-2"] {
            state.apply(&Command::DeleteVolume {
                volume: "data".to_owned(),
                node: node.to_owned(),
                at: 0,
            });
        }

        let reported = [("node-1".to_owned(), vec!["data".to_owned()])]
            .into_iter()
            .collect();

        let out = retirements(&state, &reported);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(
            out[0],
            Command::RetireTombstone {
                volume: "data".to_owned(),
                node: "node-1".to_owned(),
            }
        );
    }

    #[test]
    fn a_report_without_a_tombstone_writes_nothing() {
        let state = ClusterState::default();
        let reported = [("node-1".to_owned(), vec!["data".to_owned()])]
            .into_iter()
            .collect();

        assert!(retirements(&state, &reported).is_empty());
    }

    #[test]
    fn every_retirement_may_be_a_policy() {
        let mut state = ClusterState::default();
        state.apply(&Command::DeleteVolume {
            volume: "data".to_owned(),
            node: "node-1".to_owned(),
            at: 0,
        });
        let reported = [("node-1".to_owned(), vec!["data".to_owned()])]
            .into_iter()
            .collect();

        let out = retirements(&state, &reported);
        assert!(!out.is_empty(), "otherwise the test checks nothing");
        for command in out {
            assert!(command.may_be_policy());
        }
    }
}

async fn apply_leases_impl(
    raft: &Raft<TypeConfig>,
    applied: &tg_consensus::ClusterState,
    projection: &Projection,
) {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return;
    };
    let seconds = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    let millis = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);

    // **Who has reported within the reporting window.** The width is no free
    // choice: it stands between the lease (upwards) and the reporting cadence
    // (downwards), and both bounds are written down and checked at
    // `REPORT_WINDOW_SECONDS` as an ordering condition.
    //
    // `LEASE_SECONDS` once stood here with the note that a shorter window would let
    // the lease "fall at a single missed report" -- and exactly that is what it did,
    // because the reporting cadence beside it stood at the same number.
    let reporting = projection.reporting_since(seconds - REPORT_WINDOW_SECONDS);

    for command in leases(
        applied,
        &reporting,
        tg_consensus::UtcMillis::new(millis),
        LEASE_MILLIS,
    ) {
        let describe = format!("{command:?}");
        if let Err(err) = raft.client_write(command.into()).await {
            tracing::warn!(error = %err, %describe, "the lease was not decreed");
        }
    }
}

fn retirements(
    applied: &tg_consensus::ClusterState,
    reported: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<Command> {
    let mut commands = Vec::new();
    for (node, tombstones) in applied.deleted_volumes() {
        let Some(done) = reported.get(node) else {
            continue;
        };
        for volume in tombstones {
            if done.iter().any(|name| name == volume) {
                commands.push(Command::RetireTombstone {
                    volume: volume.to_owned(),
                    node: node.to_owned(),
                });
            }
        }
    }
    commands
}

async fn apply_retirements(
    raft: &Raft<TypeConfig>,
    applied: &tg_consensus::ClusterState,
    projection: &Projection,
) {
    for command in retirements(applied, &projection.reported_retired()) {
        // The prohibition list is no claim: it is asked (ADR-0057,
        // determination 2).
        debug_assert!(command.may_be_policy());
        let describe = format!("{command:?}");
        if let Err(err) = raft.client_write(command.into()).await {
            tracing::warn!(error = %err, %describe, "the tombstone was not cleared away");
        }
    }
}

use tg_store::session::{LEASE_SECONDS, REPORT_WINDOW_SECONDS};

const LEASE_MILLIS: u64 = LEASE_SECONDS.unsigned_abs() * 1_000;

const LEASE_TICK: Duration = Duration::from_millis(tg_model::lease::LEASE_TICK_MILLIS);

fn leases(
    state: &tg_consensus::ClusterState,
    reporting: &std::collections::BTreeSet<String>,
    now: tg_consensus::UtcMillis,
    lease: u64,
) -> Vec<Command> {
    let mut out = Vec::new();

    for entry in state.workloads() {
        // **Only single writers** (ADR-0064, determination 7). A replicated
        // workload has no active role; binding it to a lease would mean shutting it
        // down without a quorum -- the opposite of ADR-0019.
        if entry.class() != tg_defs::WorkloadClass::SingleWriter {
            continue;
        }

        let name = entry.name();
        // **The operator says which instance carries the active role**
        // (ADR-0111); without a decree it is the zeroth (ADR-0064,
        // determination 8). The others are standbys -- the warm standby is a
        // running instance (ADR-0010).
        //
        // The zero stood here as a constant, and that was the reason why a
        // promotion lived exactly one lease deadline: the leader never renewed the
        // promoted node and after the expiry granted again to instance 0's node.
        let active = state.active_instance(name);
        let Some((_, _, holder)) = state
            .placements()
            .into_iter()
            .find(|(workload, instance, _)| *workload == name && *instance == active)
        else {
            continue;
        };
        if !reporting.contains(holder) {
            continue;
        }

        let expires_at = tg_consensus::UtcMillis::new(now.get().saturating_add(lease));
        match state.lease(name) {
            // **The holder renews -- but only when it is necessary.**
            //
            // An unconditional `RenewLease` once stood here, and the cadence then
            // came from outside: measured, the leader wrote a renewal every five
            // seconds because something else moved the metrics. That is wrong
            // twice. It couples a lease's lifetime to a cadence nobody chose for it
            // -- and every renewal is a log entry ADR-0020 retains **forever**:
            // around 17 000 records per day and workload that say nothing.
            //
            // Renewal therefore happens only in the second half of the deadline.
            // That leaves a whole half lease of time for a failure and makes the
            // rate a property of the lease instead of that of a foreign timer.
            //
            // **And only one that still applies.** Without `is_valid_at` this arm
            // also caught an **expired** lease of the same holder and sent an
            // extension -- which `renew_lease` refuses with `LeaseExpired`, because
            // a holder that missed the gap needs a new epoch. The next tick tried
            // the same: a single writer whose node was briefly away never got its
            // active role back and in the process wrote a refused entry into a
            // retention-bound log every `LEASE_TICK` (ADR-0020, ADR-0045). The third
            // arm below carried the right answer as a comment from the start and was
            // never reached.
            Some(current) if current.holder() == holder && current.is_valid_at(now) => {
                let half = tg_consensus::UtcMillis::new(now.get().saturating_add(lease / 2));
                if current.is_valid_at(half) {
                    continue;
                }
                out.push(Command::RenewLease {
                    workload: name.to_owned(),
                    node: holder.to_owned(),
                    now,
                    expires_at,
                });
            }
            // Another still holds it -- then the fence applies, and the state
            // machine would refuse. Only after the expiry is the way free, and
            // **that** is the activation delay from ADR-0064.
            Some(current) if current.is_valid_at(now) => {}
            // None or an expired one: grant, with a higher epoch.
            _ => out.push(Command::GrantLease {
                workload: name.to_owned(),
                node: holder.to_owned(),
                now,
                expires_at,
            }),
        }
    }

    out
}

#[cfg(test)]
mod lease_tests {
    use std::collections::BTreeSet;

    use super::{LEASE_MILLIS, LEASE_TICK, leases};
    use tg_consensus::{ClusterState, Command, UtcMillis};

    const LEASE: u64 = LEASE_MILLIS;

    fn now(millis: u64) -> UtcMillis {
        UtcMillis::new(millis)
    }

    fn reporting(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    fn cluster(class: &str) -> ClusterState {
        let mut state = ClusterState::default();
        state.apply(&Command::UpsertNode {
            name: "node-1".to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r1".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        });
        state.apply(&Command::UpsertWorkload {
            document: format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
                 \x20 <workload name=\"till\" kind=\"service\" class=\"{class}\">\n\
                 \x20   <image reference=\"registry.invalid/till:1\"/>\n\
                 \x20 </workload>\n\
                 </workloads>\n"
            ),
        });
        state.apply(&Command::AssignPlacement {
            workload: "till".to_owned(),
            instance: 0,
            node: "node-1".to_owned(),
        });
        state
    }

    #[test]
    fn a_fresh_lease_is_not_renewed() {
        let mut state = cluster("single-writer");
        state.apply(&Command::GrantLease {
            workload: "till".to_owned(),
            node: "node-1".to_owned(),
            now: now(1_000),
            expires_at: now(16_000),
        });

        // One second later: fourteen of fifteen seconds are still there.
        let out = leases(&state, &reporting(&["node-1"]), now(2_000), LEASE);
        assert!(out.is_empty(), "nothing to do yet: {out:?}");

        // Beyond the half: now there is.
        let out = leases(&state, &reporting(&["node-1"]), now(9_000), LEASE);
        assert!(
            matches!(out.as_slice(), [Command::RenewLease { .. }]),
            "in the second half it must renew: {out:?}"
        );
    }

    #[test]
    fn the_lease_tick_leaves_room_for_a_missed_round() {
        assert!(
            LEASE_TICK.as_millis() * 2 <= u128::from(LEASE_MILLIS),
            "the cadence ({LEASE_TICK:?}) must fit twice into the deadline"
        );
        assert!(
            tg_model::lease::margin_holds(tg_model::lease::FENCE_MARGIN_MILLIS),
            "the cadence ({LEASE_TICK:?}) lets the remaining time fall below \
             the safety margin (ADR-0076)"
        );
    }

    fn two_nodes() -> ClusterState {
        let mut state = ClusterState::default();
        for name in ["node-1", "node-2"] {
            state.apply(&Command::UpsertNode {
                name: name.to_owned(),
                topology: tg_consensus::Topology {
                    site: "fra".to_owned(),
                    hall: "h1".to_owned(),
                    rack: "r1".to_owned(),
                },
                capacity: tg_consensus::Resources::default(),
                reserved: tg_consensus::Resources::default(),
                source: tg_consensus::Origin::Operator,
            });
        }
        state.apply(&Command::UpsertWorkload {
            document: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
                 \x20 <workload name=\"till\" kind=\"service\" \
                 class=\"single-writer\">\n\
                 \x20   <image reference=\"registry.invalid/till:1\"/>\n\
                 \x20   <placement replicas=\"2\"/>\n\
                 \x20 </workload>\n\
                 </workloads>\n"
                .to_owned(),
        });
        for (instance, node) in [(0, "node-1"), (1, "node-2")] {
            state.apply(&Command::AssignPlacement {
                workload: "till".to_owned(),
                instance,
                node: node.to_owned(),
            });
        }
        state
    }

    #[test]
    fn the_holder_follows_the_promoted_instance() {
        let mut state = two_nodes();
        let everyone = reporting(&["node-1", "node-2"]);

        // Without a decree: instance 0's node.
        let out = leases(&state, &everyone, now(0), LEASE);
        assert!(
            matches!(
                out.as_slice(),
                [Command::GrantLease { node, .. }] if node == "node-1"
            ),
            "{out:?}"
        );

        // Exactly one thing different.
        assert_eq!(
            state.apply(&Command::SetActiveInstance {
                workload: "till".to_owned(),
                instance: 1,
            }),
            tg_consensus::Outcome::Applied
        );

        let out = leases(&state, &everyone, now(0), LEASE);
        assert!(
            matches!(
                out.as_slice(),
                [Command::GrantLease { node, .. }] if node == "node-2"
            ),
            "{out:?}"
        );
    }

    #[test]
    fn a_promotion_survives_the_lease_it_was_made_in() {
        let mut state = two_nodes();
        assert_eq!(
            state.apply(&Command::SetActiveInstance {
                workload: "till".to_owned(),
                instance: 1,
            }),
            tg_consensus::Outcome::Applied
        );
        state.apply(&Command::GrantLease {
            workload: "till".to_owned(),
            node: "node-2".to_owned(),
            now: now(0),
            expires_at: now(LEASE),
        });

        let everyone = reporting(&["node-1", "node-2"]);

        // In the second half: renewed, not granted anew.
        let out = leases(&state, &everyone, now(LEASE * 3 / 4), LEASE);
        assert!(
            matches!(
                out.as_slice(),
                [Command::RenewLease { node, .. }] if node == "node-2"
            ),
            "{out:?}"
        );

        // And after the expiry: node-2 again, not node-1.
        state.apply(&Command::RenewLease {
            workload: "till".to_owned(),
            node: "node-2".to_owned(),
            now: now(LEASE * 3 / 4),
            expires_at: now(LEASE * 3 / 4 + LEASE),
        });
        let out = leases(&state, &everyone, now(LEASE * 3), LEASE);
        assert!(
            matches!(
                out.as_slice(),
                [Command::GrantLease { node, .. }] if node == "node-2"
            ),
            "{out:?}"
        );
    }

    #[test]
    fn an_expired_lease_is_granted_afresh_even_to_the_same_holder() {
        let mut state = cluster("single-writer");
        state.apply(&Command::GrantLease {
            workload: "till".to_owned(),
            node: "node-1".to_owned(),
            now: now(0),
            expires_at: now(LEASE),
        });

        // The holder was away and is back; the deadline has elapsed.
        let out = leases(&state, &reporting(&["node-1"]), now(LEASE * 2), LEASE);

        assert!(
            matches!(
                out.as_slice(),
                [Command::GrantLease { workload, node, .. }]
                    if workload == "till" && node == "node-1"
            ),
            "{out:?}"
        );

        // And it is **accepted** -- that is the half the finding cost: an
        // extension would have been refused here forever.
        for command in &out {
            assert!(
                !matches!(state.apply(command), tg_consensus::Outcome::Rejected(_)),
                "{command:?}"
            );
        }
        assert!(
            state
                .lease("till")
                .is_some_and(|lease| lease.is_valid_at(now(LEASE * 2))),
            "the active role must apply again afterwards"
        );
    }

    #[test]
    fn a_placed_standby_alone_gets_no_lease() {
        let mut state = ClusterState::default();
        state.apply(&Command::UpsertNode {
            name: "node-2".to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r2".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        });
        state.apply(&Command::UpsertWorkload {
            document: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
                 \x20 <workload name=\"till\" kind=\"service\" class=\"single-writer\">\n\
                 \x20   <image reference=\"registry.invalid/till:1\"/>\n\
                 \x20 </workload>\n\
                 </workloads>\n"
                .to_owned(),
        });
        // **Only the standby is placed.** Instance 0 has no node -- say because
        // the planner found none (`NoRoom`, ADR-0011).
        state.apply(&Command::AssignPlacement {
            workload: "till".to_owned(),
            instance: 1,
            node: "node-2".to_owned(),
        });

        let out = leases(&state, &reporting(&["node-2"]), now(1_000), LEASE);

        assert!(
            out.is_empty(),
            "without instance 0 there is no active role to grant: {out:?}"
        );
    }

    #[test]
    fn a_single_writer_without_a_lease_gets_one() {
        let state = cluster("single-writer");

        let out = leases(&state, &reporting(&["node-1"]), now(1_000), LEASE);

        assert!(
            matches!(
                out.as_slice(),
                [Command::GrantLease { workload, node, expires_at, .. }]
                    if workload == "till" && node == "node-1"
                        && expires_at.get() == 16_000
            ),
            "{out:?}"
        );
    }

    #[test]
    fn a_replicated_workload_gets_no_lease() {
        let state = cluster("replicated");

        let out = leases(&state, &reporting(&["node-1"]), now(1_000), LEASE);

        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn a_silent_node_gets_nothing() {
        let state = cluster("single-writer");

        let out = leases(&state, &reporting(&[]), now(1_000), LEASE);

        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn the_holder_renews() {
        let mut state = cluster("single-writer");
        state.apply(&Command::GrantLease {
            workload: "till".to_owned(),
            node: "node-1".to_owned(),
            now: now(1_000),
            expires_at: now(16_000),
        });

        let out = leases(&state, &reporting(&["node-1"]), now(9_000), LEASE);

        assert!(
            matches!(
                out.as_slice(),
                [Command::RenewLease { workload, node, .. }]
                    if workload == "till" && node == "node-1"
            ),
            "{out:?}"
        );
    }

    #[test]
    fn a_valid_foreign_lease_is_not_taken() {
        let mut state = cluster("single-writer");
        state.apply(&Command::UpsertNode {
            name: "node-2".to_owned(),
            topology: tg_consensus::Topology {
                site: "fra".to_owned(),
                hall: "h1".to_owned(),
                rack: "r2".to_owned(),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        });
        state.apply(&Command::GrantLease {
            workload: "till".to_owned(),
            node: "node-2".to_owned(),
            now: now(1_000),
            expires_at: now(16_000),
        });

        let held = leases(&state, &reporting(&["node-1"]), now(2_000), LEASE);
        assert!(held.is_empty(), "{held:?}");

        // After the expiry the way is free.
        let free = leases(&state, &reporting(&["node-1"]), now(17_000), LEASE);
        assert!(
            matches!(free.as_slice(), [Command::GrantLease { node, .. }] if node == "node-1"),
            "{free:?}"
        );
    }
}

fn report_pressure(
    applied: &tg_consensus::ClusterState,
    usage: &std::collections::BTreeMap<String, tg_model::Resources>,
) {
    // The **plannable** capacity, so less the reserve (ADR-0047) -- the same one
    // the planner checks against. Taking the raw one would yield a number smaller
    // than the truth, and precisely in the direction that reassures.
    let nodes: std::collections::BTreeMap<String, tg_model::Resources> = applied
        .nodes()
        .into_iter()
        .map(|(name, entry)| {
            (
                name.to_owned(),
                entry.capacity().clone().minus(entry.reserved()),
            )
        })
        .collect();

    for (name, used) in usage {
        let Some(capacity) = nodes.get(name) else {
            continue;
        };

        // The pressure is computed in millionths (ADR-0109, in integers and
        // thereby deterministic); a Prometheus metric is a ratio. The loss of
        // precision lies beyond what a utilization expresses.
        #[allow(clippy::cast_precision_loss)]
        let pressure = used.pressure(capacity) as f64 / 1_000_000.0;
        metrics::gauge!(
            tg_telemetry::names::NODE_PRESSURE,
            "node" => name.clone()
        )
        .set(pressure);

        // **And what it is still enough for.** The pressure does not call the
        // scarcest resource by its name.
        #[allow(clippy::cast_precision_loss)]
        for (resource, free) in capacity.clone().minus(used).entries() {
            metrics::gauge!(
                tg_telemetry::names::NODE_FREE,
                "node" => name.clone(),
                "resource" => resource.to_owned()
            )
            .set(free as f64);
        }
    }
}

fn report_headroom(applied: &tg_consensus::ClusterState) {
    for domain in schedule::headroom(applied, DomainLevel::Rack) {
        metrics::gauge!(
            tg_telemetry::names::DOMAIN_ABSORBS,
            "domain" => domain.domain.clone()
        )
        .set(f64::from(u8::from(domain.absorbs)));

        // The numbers beside it (ADR-0047, determination 3: "how much free
        // capacity lies outside, compared with what runs in it"). Without them the
        // alarm the ADR demands could not be written at all: `absorbs` jumps only
        // when it is already too late.
        // The loss of precision is no shortcoming but the format: a Prometheus
        // metric **is** an `f64`. It would become imprecise beyond 2^53 -- with
        // memory in bytes that would be nine petabytes in one domain.
        #[allow(clippy::cast_precision_loss)]
        for (resource, at_risk, elsewhere) in domain.series() {
            metrics::gauge!(
                tg_telemetry::names::DOMAIN_AT_RISK,
                "domain" => domain.domain.clone(),
                "resource" => resource.to_owned()
            )
            .set(at_risk as f64);
            metrics::gauge!(
                tg_telemetry::names::DOMAIN_ELSEWHERE,
                "domain" => domain.domain.clone(),
                "resource" => resource.to_owned()
            )
            .set(elsewhere as f64);
        }

        if !domain.absorbs {
            tracing::warn!(
                domain = %domain.domain,
                "the failure of this failure domain would not be absorbable"
            );
        }
    }
}

fn report_state_sizes(applied: &tg_consensus::ClusterState) {
    // **How full the address space is** (ADR-0069). The bound has bitten since
    // then: where no subnet is free any more, no node is admitted any more.
    // Without these two numbers an operator would notice it at the **first
    // refusal** -- so when they need the node.
    //
    // Without a set address plan **neither** of the two appears: an invented
    // capacity would report a full cluster where merely nothing is set.
    if let Some(capacity) = applied.address_capacity() {
        metrics::gauge!(tg_telemetry::names::CLUSTER_ORDINALS_USED)
            .set(f64::from(applied.ordinals_used()));
        metrics::gauge!(tg_telemetry::names::CLUSTER_ORDINALS_CAPACITY).set(f64::from(capacity));
    }

    // **The tombstones** (ADR-0042). They travel along in every slice and in
    // every snapshot until the affected node reports the execution and the leader
    // clears the instruction away (`RetireTombstone`, ADR-0104). There is no
    // **deadline**, and that is decided: if the instruction expired, the volume
    // would stay lying on a node that was away for a week. That is exactly why the
    // number is the way to the statement -- the rule on it is called
    // `TardigradeTombstoneNotExecuted`.
    let tombstones: usize = applied
        .deleted_volumes()
        .iter()
        .map(|(_, volumes)| volumes.len())
        .sum();
    metrics::gauge!(tg_telemetry::names::CLUSTER_VOLUME_TOMBSTONES)
        .set(f64::from(u32::try_from(tombstones).unwrap_or(u32::MAX)));

    // **Who takes the coarser enforcement** (ADR-0092, determination 6). Plain
    // UDP knows no name on the wire; the agent resolves and lays one rule per
    // address. What is counted are **workloads** and not permissions: an auditor's
    // question is how many units hang on it, not how many lines there are.
    let with_udp: std::collections::BTreeSet<&str> = applied
        .egress()
        .into_iter()
        .filter(|(_, _, _, transport)| *transport == tg_model::egress::Transport::Udp)
        .map(|(workload, _, _, _)| workload)
        .collect();
    metrics::gauge!(tg_telemetry::names::CLUSTER_UDP_EGRESS_WORKLOADS)
        .set(f64::from(u32::try_from(with_udp.len()).unwrap_or(u32::MAX)));
}

fn report_divergences(projection: &Projection) {
    let count = |value: usize| f64::from(u32::try_from(value).unwrap_or(u32::MAX));

    metrics::gauge!(tg_telemetry::names::PROXY_IMAGES)
        .set(count(projection.distinct_proxy_images()));
    metrics::gauge!(tg_telemetry::names::DNS_ZONES).set(count(projection.distinct_dns_zones()));
    metrics::gauge!(tg_telemetry::names::USERNS_POSTURES)
        .set(count(projection.distinct_userns_postures()));
}
