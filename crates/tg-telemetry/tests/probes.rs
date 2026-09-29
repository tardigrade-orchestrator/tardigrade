//! Liveness and readiness — and the separation ADR-0019 hangs on.
//!
//! The most important test in this file is the one that proves a node without
//! quorum stays **alive**. If it did not, a partition would turn five healthy
//! machines into five restarts — and with them the workloads ADR-0019
//! expressly lets keep running.

use std::time::Duration;

use tg_telemetry::probes::{Health, Readiness};

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// --------------------------------------------------------------- Readiness

/// A fresh process is **not** ready.
///
/// "Reported nothing" is no assurance. Whoever returned green here would get
/// work they cannot do in the window between process start and first report —
/// and that is exactly the window a rolling update passes through on every node
/// in turn.
#[test]
fn a_fresh_process_is_not_ready() {
    let health = Health::new();

    let probe = health.readiness();

    assert!(!probe.ok);
    assert!(
        probe.body().contains("nothing registered"),
        "{}",
        probe.body()
    );
}

/// A process is ready only when **all** sub-tasks are.
#[test]
fn readiness_needs_every_part_to_be_ready() {
    let health = Health::new();
    health.set("raft", Readiness::up());
    health.set("projection", Readiness::down("still materializing"));

    assert!(!health.readiness().ok);

    health.set("projection", Readiness::up());

    assert!(health.readiness().ok);
}

/// The reason stands in the body — otherwise a red `/readyz` is no use to
/// anyone.
#[test]
fn a_refusal_names_its_reason() {
    let health = Health::new();
    health.set("raft", Readiness::down("no quorum: 2 of 5 reachable"));

    let body = health.readiness().body();

    assert!(body.contains("not ok"), "{body}");
    assert!(body.contains("no quorum: 2 of 5 reachable"), "{body}");
}

// ---------------------------------------------------------------- Liveness

/// **The test at issue (ADR-0019).**
///
/// A node without quorum is not ready — and alive nevertheless. If liveness
/// tipped along with it, the restart would hit all nodes of the minority side
/// at once, and running workloads would go with them. ADR-0019 says so
/// expressly: "Running containers are **never** stopped because of quorum
/// loss."
#[test]
fn losing_quorum_makes_a_node_unready_but_never_dead() {
    let health = Health::new();
    health.watch("reconcile", secs(60), secs(0));
    health.set("raft", Readiness::up());

    // The partition arrives.
    health.set("raft", Readiness::down("no quorum"));
    health.beat("reconcile", secs(5));

    assert!(
        !health.readiness().ok,
        "without quorum it accepts nothing new"
    );
    assert!(
        health.liveness(secs(5)).ok,
        "but it lives — a restart would do damage here"
    );
}

/// A loop that stops beating makes the process dead — that is what the watchdog
/// is for.
#[test]
fn a_loop_that_stops_beating_fails_liveness() {
    let health = Health::new();
    health.watch("reconcile", secs(60), secs(0));

    assert!(health.liveness(secs(59)).ok);
    assert!(!health.liveness(secs(61)).ok);
}

/// A beat resets the clock.
#[test]
fn a_beat_resets_the_watchdog() {
    let health = Health::new();
    health.watch("reconcile", secs(60), secs(0));

    health.beat("reconcile", secs(50));

    assert!(health.liveness(secs(100)).ok, "50 + 60 > 100");
    assert!(!health.liveness(secs(111)).ok);
}

/// **A typo sets up no watchdog.**
///
/// If `beat("reconcil")` produced a second watchdog, liveness would hang on a
/// loop that does not exist — and it would strike as soon as nobody writes the
/// wrong name any more.
#[test]
fn beating_an_unknown_watch_creates_nothing() {
    let health = Health::new();
    health.watch("reconcile", secs(60), secs(0));

    health.beat("reconcil", secs(10));

    let probe = health.liveness(secs(10));
    assert!(probe.ok);
    assert_eq!(probe.lines.len(), 1, "{:?}", probe.lines);
}

/// A process without watchdogs is alive.
///
/// The reverse of the readiness default, and right for the same reason: red
/// means here "restart me". A process that watches nothing gives no cause for
/// that — whoever restarted it would swap an unknown state for an outage.
#[test]
fn a_process_without_watchdogs_is_alive() {
    assert!(Health::new().liveness(secs(1_000)).ok);
}

/// The clock may jump back without the watchdog barking.
///
/// `Duration` cannot become negative; without saturating subtraction a jump
/// back would have yielded a panic — in the HTTP handler, that is, as a failure
/// of the probe itself.
#[test]
fn a_clock_going_backwards_does_not_panic_the_probe() {
    let health = Health::new();
    health.watch("reconcile", secs(60), secs(100));

    assert!(health.liveness(secs(10)).ok);
}

/// **A dead task is reported and no longer counts as ready.**
///
/// Since ADR-0082 a panic costs its task and not the node — and thereby the
/// state arises that did not exist before: a process that keeps running and no
/// longer does something. Measured, that was mute in five places; the handles
/// lay as `let _renewal = …` or in a field `_tasks`.
///
/// **Both** outcomes are checked in one, because they must name different
/// reasons: a task that *returns* is just as much a defect as one that is
/// *aborted*. A guard that only says "not ready" would leave an operator
/// guessing which of the two cases applies.
///
/// **Neither of the two is restarted** (ADR-0116, determination 1): whoever
/// returns has decided to be finished, and aborting happens from within. That
/// this test ends at all is the assurance — with a restart the watcher would
/// run on, and `await` would never come back.
///
/// The recorder is **local** and the runtime `current_thread`: the watcher is a
/// task of its own, and a global recorder would belong to the process — `cargo
/// test` runs a file's tests concurrently.
#[test]
fn a_task_that_ends_on_its_own_is_reported_and_not_restarted() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use tg_telemetry::probes::{Health, supervise};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let (probe, alive) = metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let health = Health::new();

            // **A factory, not a handle** (ADR-0116): the watcher starts it
            // itself. Both return — and a return is expressly **not**
            // restarted, otherwise this watcher would never end.
            let returned = supervise(&health, "returns", || tokio::spawn(async {}));
            let cancelled = supervise(&health, "aborted", || {
                let task = tokio::spawn(async { std::future::pending::<()>().await });
                task.abort();
                task
            });
            returned.await.expect("watcher");
            cancelled.await.expect("watcher");

            let alive: Vec<(String, f64)> = snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .filter(|(key, _, _, _)| key.key().name() == tg_telemetry::names::TASK_ALIVE)
                .map(|(key, _, _, value)| {
                    let task = key
                        .key()
                        .labels()
                        .find(|label| label.key() == "task")
                        .map(|label| label.value().to_owned())
                        .expect("label `task`");
                    match value {
                        DebugValue::Gauge(seen) => (task, seen.into_inner()),
                        other => panic!("not a gauge: {other:?}"),
                    }
                })
                .collect();

            (health.readiness(), alive)
        })
    });

    assert!(
        !probe.ok,
        "a dead task has to withdraw the readiness: {}",
        probe.body()
    );
    let body = probe.body();
    assert!(
        body.contains("returns: not ready: the task returned"),
        "the reason is missing or names the wrong outcome: {body}"
    );
    assert!(
        body.contains("aborted: not ready: the task was aborted"),
        "an abort has to appear as an abort: {body}"
    );

    let mut alive = alive;
    alive.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        alive,
        vec![("aborted".to_owned(), 0.0), ("returns".to_owned(), 0.0),],
        "`{}` has to stand at 0 after the end — and per task",
        tg_telemetry::names::TASK_ALIVE
    );
}

/// **A panicked task comes back** (ADR-0116, determination 1).
///
/// The most expensive case from ADR-0082: `identity-refresh` dies of an
/// overflow panic, and fifteen minutes later no SVID rotates any more. For
/// exactly this sort the objection in the old code is wrong — a panic that
/// hangs on **one input** does not repeat on the next attempt.
///
/// Checked **at the factory**: it counts its calls and panics only on the
/// first. A second call is the restart, and afterwards `alive` stands at `1`
/// again — the counter-check to it is the test above, in which a return is
/// **not** restarted and the watcher therefore ends.
///
/// Time is paused: the backoff is one second, and a test that really waits it
/// out is one somebody eventually comments out.
#[test]
fn a_task_that_panics_comes_back() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tg_telemetry::probes::{Health, supervise};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("runtime");

    let starts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&starts);
    let seen = Arc::clone(&starts);

    let (probe, alive, restarts) = metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async move {
            let health = Health::new();
            let watcher = supervise(&health, "panics", move || {
                let first = counted.fetch_add(1, Ordering::SeqCst) == 0;
                tokio::spawn(async move {
                    assert!(!first, "the task dies");
                    std::future::pending::<()>().await;
                })
            });

            // **The clock is pushed, not waited out**, and expressly so: with
            // `yield_now` in a loop the runtime is never idle, and then a
            // paused clock does not advance at all by itself. First give the
            // panic an opportunity to arrive at the watcher, then push past the
            // backoff, then give it an opportunity to restart.
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            tokio::time::advance(std::time::Duration::from_secs(2)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                seen.load(Ordering::SeqCst),
                2,
                "the restart did not get through"
            );
            watcher.abort();

            let mut alive = 0.0;
            let mut restarts = 0_u64;
            for (key, _, _, value) in snapshotter.snapshot().into_vec() {
                match (key.key().name(), value) {
                    (name, DebugValue::Gauge(seen)) if name == tg_telemetry::names::TASK_ALIVE => {
                        alive = seen.into_inner();
                    }
                    (name, DebugValue::Counter(seen))
                        if name == tg_telemetry::names::TASK_RESTARTS =>
                    {
                        restarts = seen;
                    }
                    _ => {}
                }
            }

            (health.readiness(), alive, restarts)
        })
    });

    assert_eq!(
        starts.load(Ordering::SeqCst),
        2,
        "the factory has to have been called a second time — otherwise there was no restart"
    );
    assert_eq!(
        restarts,
        1,
        "`{}` has to count the attempt: without it a flapping task is invisible, \
         because the gauge stands at 1 again",
        tg_telemetry::names::TASK_RESTARTS
    );
    assert!(
        (alive - 1.0).abs() < f64::EPSILON,
        "after the restart `{}` has to stand at 1 again, seen: {alive}",
        tg_telemetry::names::TASK_ALIVE
    );
    assert!(
        probe.ok,
        "after the restart the task is ready again: {}",
        probe.body()
    );
}

/// **The counter-check: a running task counts as ready.**
///
/// Without it a watcher that declared **every** task dead would be just as
/// green — and the node would never be ready. The number must besides **stand
/// there** and not be missing: a metric that appears only in the error case is
/// indistinguishable from a missing one.
#[test]
fn a_running_task_stays_ready() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use tg_telemetry::probes::{Health, supervise};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let (probe, alive) = metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let health = Health::new();
            let watcher = supervise(&health, "running", || {
                tokio::spawn(async { std::future::pending::<()>().await })
            });

            // Give the watcher an opportunity to have started — without it the
            // test only checks that `supervise` itself set the value, and not
            // that the watcher stays quiet.
            tokio::task::yield_now().await;
            watcher.abort();

            let alive: Vec<f64> = snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .filter(|(key, _, _, _)| key.key().name() == tg_telemetry::names::TASK_ALIVE)
                .map(|(_, _, _, value)| match value {
                    DebugValue::Gauge(seen) => seen.into_inner(),
                    other => panic!("not a gauge: {other:?}"),
                })
                .collect();

            (health.readiness(), alive)
        })
    });

    assert!(probe.ok, "a running task has to be ready: {}", probe.body());
    assert_eq!(
        alive,
        vec![1.0],
        "`{}` has to stand there during the run time and be `1`",
        tg_telemetry::names::TASK_ALIVE
    );
}

/// The refresh runs in the scrape — and a second one **replaces** the first.
///
/// It is the substitute for a loop (ADR-0088, determination 3): a time series
/// nobody sets at least once per decay deadline has to be set in the scrape. A
/// counter in the assertion instead of a flag, so that a second call counts
/// too.
#[test]
fn a_registered_refresh_runs_on_every_scrape() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let health = Health::new();
    let runs = Arc::new(AtomicUsize::new(0));

    let counted = Arc::clone(&runs);
    health.on_scrape("a", move || {
        counted.fetch_add(1, Ordering::Relaxed);
    });

    health.refresh();
    health.refresh();

    assert_eq!(
        runs.load(Ordering::Relaxed),
        2,
        "the refresh has to run in **every** scrape, not once"
    );

    // The second half: a second call under the same name **replaces**.
    // `supervise` rests on that when a task dies — and without this assurance a
    // registration that stacks would be just as green: then both would run, and
    // the gauge would carry whatever chance set last.
    let counted = Arc::clone(&runs);
    health.on_scrape("a", move || {
        counted.fetch_add(100, Ordering::Relaxed);
    });
    health.refresh();

    assert_eq!(
        runs.load(Ordering::Relaxed),
        102,
        "the second registration has to replace the first, not run beside it"
    );
}

/// A dead task stays dead.
///
/// That is the order at issue in `supervise`: first deregister, then set the
/// zero. The other way round, the refresh would set the one back in the next
/// scrape, and a dead task would look **alive forever** — exactly the lie the
/// metric exists against.
#[test]
fn a_dead_task_is_not_revived_by_the_next_scrape() {
    use metrics_util::MetricKind;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let health = Health::new();

    metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let dying =
                    tg_telemetry::probes::supervise(&health, "dying", || tokio::spawn(async {}));
                // Wait for its end, not for a point in time: the watcher sets
                // the zero when the watched task ends.
                let _ = dying.await;
            });

        // The value a decay or a left-behind refresh would leave — then a
        // scrape comes. It has to restore the **zero**: it must not be replaced
        // by the one (the task is dead) and it must not **disappear**
        // (ADR-0088), otherwise `TardigradeTaskDied` would resolve itself after
        // a quarter of an hour while the task is still dead.
        metrics::gauge!(tg_telemetry::names::TASK_ALIVE, "task" => "dying").set(1.0);
        health.refresh();
    });

    let alive: Vec<f64> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| {
            key.kind() == MetricKind::Gauge && key.key().name() == tg_telemetry::names::TASK_ALIVE
        })
        .map(|(_, _, _, value)| match value {
            DebugValue::Gauge(seen) => seen.into_inner(),
            other => panic!("not a gauge: {other:?}"),
        })
        .collect();

    assert_eq!(
        alive,
        vec![0.0],
        "after the end `{}` has to stand at zero and stay there",
        tg_telemetry::names::TASK_ALIVE
    );
    assert!(
        !health.readiness().ok,
        "and the node is no longer ready: {}",
        health.readiness().body()
    );
}

/// A running task reports itself in **every** scrape.
///
/// The distinguishing case: the gauge is set by hand to a wrong value, then a
/// scrape comes. If it brings the one back, `supervise` really registered a
/// refresh (ADR-0088) — without it the wrong value would remain. A test that
/// only checked the value **after** `supervise` would be green without the
/// registration too: with a watcher that sets the metric only once, the first
/// look is the same.
#[test]
fn a_live_task_reports_itself_on_every_scrape() {
    use metrics_util::MetricKind;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let health = Health::new();

    metrics::with_local_recorder(&recorder, || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let guard = runtime.enter();
        let watcher = tg_telemetry::probes::supervise(&health, "live", || {
            // Runs until the test aborts it.
            tokio::spawn(async { std::future::pending::<()>().await })
        });

        // The value a decay would leave.
        metrics::gauge!(tg_telemetry::names::TASK_ALIVE, "task" => "live").set(0.0);
        health.refresh();

        watcher.abort();
        drop(guard);
        drop(runtime);
    });

    let alive: Vec<f64> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| {
            key.kind() == MetricKind::Gauge && key.key().name() == tg_telemetry::names::TASK_ALIVE
        })
        .map(|(_, _, _, value)| match value {
            DebugValue::Gauge(seen) => seen.into_inner(),
            other => panic!("not a gauge: {other:?}"),
        })
        .collect();

    assert_eq!(
        alive,
        vec![1.0],
        "the scrape has to fetch `{}` back to one — otherwise the series disappears after the decay deadline",
        tg_telemetry::names::TASK_ALIVE
    );
}
