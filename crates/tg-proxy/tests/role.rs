//! The active role in the sidecar (ADR-0066).
//!
//! Pure logic: out of a file's content and a clock comes a verdict. Checkable
//! without sockets -- and that is the point at which it counts: the
//! **rejection paths** are the assurance here, and a refusal one sees only in
//! the end-to-end setup nobody has ever seen.

use tg_proxy::role::{ActiveRole, Roles};

const NOW: u64 = 1_800_000_000_000;

/// A node that holds `api` just now.
fn holding() -> Roles {
    Roles::from_text("api 7 1800000015000\nledger 3 1800000015000\n")
}

/// **Without an active role a single writer does not talk.**
///
/// That is the assurance from ADR-0066: running yes (a warm standby must run
/// in order to be warm), talking no.
#[test]
fn a_single_writer_without_the_role_is_refused() {
    let roles = holding();

    assert_eq!(roles.role_of("api", NOW), ActiveRole::Active { epoch: 7 });
    assert_eq!(roles.role_of("standby-only", NOW), ActiveRole::Passive);
}

/// **An expired lease is no active role** -- even when the line still stands
/// there.
///
/// The case for whose sake this exists: the old primary stops slowly
/// (ADR-0010). Its file is still there, its deadline is not.
#[test]
fn an_expired_lease_is_no_longer_the_active_role() {
    let roles = holding();

    assert_eq!(
        roles.role_of("api", 1_800_000_014_999),
        ActiveRole::Active { epoch: 7 }
    );
    assert_eq!(roles.role_of("api", 1_800_000_015_000), ActiveRole::Passive);
    assert_eq!(roles.role_of("api", 1_800_000_099_999), ActiveRole::Passive);
}

/// **An unreadable or missing file means "no active role".**
///
/// Fail-closed and not fail-static: ADR-0019 protects existing **permitted**
/// traffic from a control-plane loss; a role that does not arise at all
/// without quorum must not arise from a read error.
#[test]
fn an_unreadable_file_grants_nothing() {
    assert_eq!(
        Roles::from_text("").role_of("api", NOW),
        ActiveRole::Passive
    );
    assert_eq!(
        Roles::from_text("complete nonsense\n").role_of("api", NOW),
        ActiveRole::Passive
    );
}

/// Broken lines do not take the whole ones with them.
///
/// Otherwise a typo in one line would cost another workload's active role --
/// and that one would stand still without it being down to it.
#[test]
fn a_broken_line_does_not_take_the_others_with_it() {
    let roles = Roles::from_text("broken\napi 7 1800000015000\n\nalso broken 1\n");

    assert_eq!(roles.role_of("api", NOW), ActiveRole::Active { epoch: 7 });
}

/// **A prefix is no name** -- the same trap as with the egress list.
#[test]
fn a_prefix_is_not_a_name() {
    let roles = holding();

    assert_eq!(roles.role_of("api-test", NOW), ActiveRole::Passive);
    assert_eq!(roles.role_of("ap", NOW), ActiveRole::Passive);
}

/// When the role ends must be queryable -- the guard that tears a **running**
/// connection down hangs on it (ADR-0066, determination 4).
#[test]
fn the_deadline_is_readable_for_the_watchdog() {
    assert_eq!(
        holding().expires_at("api"),
        Some(1_800_000_015_000),
        "without the deadline only a new connection could be checked"
    );
    assert_eq!(holding().expires_at("foreign"), None);
}

// --- when there is a re-read (ADR-0066) ---------------------------------

/// **Whoever reads more slowly than the lease is renewed fences themselves.**
///
/// The lease carries fifteen seconds (ADR-0014) and is renewed continuously;
/// the sidecar at first looked at it once a minute. With that the active role
/// applied for fifteen seconds and then fell out for forty-five -- a single
/// writer would have been unreachable three quarters of the time.
///
/// Coupling therefore happens to the **data** and not to a shared number:
/// `tg-proxy` does not know the lease deadline and is not to have to know
/// it.
#[test]
fn the_next_read_falls_well_within_the_role() {
    let remaining = std::time::Duration::from_secs(15);
    let next = tg_proxy::role::next_read(Some(remaining), RELOAD);

    assert!(
        next * 2 <= remaining,
        "before the expiry there must be at least two reads: {next:?}"
    );
}

/// **Without an active role the fastest pace applies**, not the slowest.
///
/// This test once stood here the other way round ("without a role there is no
/// deadline that presses -- then the ordinary cadence applies") and thereby
/// nailed the wrong behaviour down. Changed, not because it went red but
/// because the statement was false: `reload` runs **only** for a single
/// writer, and there "no role" means *this workload waits to take the active
/// role over*. The haste is then greatest.
///
/// And it possibly waits **permanently**: a warm standby gets the lease only
/// once instance 0 loses it (ADR-0064, determination 8), and its sidecar
/// carries `--single-writer` nevertheless -- the call line is one per
/// definition. It is precisely the one that takes over at the failover.
#[test]
fn without_a_role_the_fastest_pace_applies() {
    let next = tg_proxy::role::next_read(None, RELOAD);

    assert!(
        next < RELOAD,
        "the ordinary cadence would leave a freshly granted holder mute for up \
         to {RELOAD:?}: {next:?}"
    );
    assert!(
        next >= std::time::Duration::from_secs(1),
        "and nevertheless no hot loop: {next:?}"
    );
}

/// **And it never becomes a hot loop.** A deadline that is just running out
/// must not yield one file access per microsecond.
#[test]
fn an_expiring_role_does_not_become_a_hot_loop() {
    for remaining in [
        std::time::Duration::ZERO,
        std::time::Duration::from_millis(1),
        std::time::Duration::from_millis(999),
    ] {
        assert!(
            tg_proxy::role::next_read(Some(remaining), RELOAD) >= std::time::Duration::from_secs(1),
            "{remaining:?}"
        );
    }
}

const RELOAD: std::time::Duration = std::time::Duration::from_mins(1);

/// **The refresher comes back before the expiry** (ADR-0066).
///
/// The test that was missing: the pure computation in `next_read` says only
/// what would come out -- whether the loop **uses** it, it does not say.
/// Precisely there the error sat, and it was invisible as long as the loop sat
/// in a binary.
///
/// A role with a three-second deadline, an ordinary cadence of one minute:
/// whoever takes the cadence reads again only in sixty seconds and lets the
/// role lapse. Whoever takes the deadline is back after one and a half.
#[tokio::test]
async fn the_refresher_returns_before_the_role_lapses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("active-role");

    let now = tg_proxy::role::now_millis();
    std::fs::write(&path, format!("api 1 {}\n", now + 3_000)).expect("writable");

    let roles = tg_proxy::role::SharedRoles::new(tg_proxy::role::Roles::from_text(
        &std::fs::read_to_string(&path).expect("readable"),
    ));
    let gate = tg_proxy::role::Gate::new("api".to_owned(), roles.clone());
    let refresher = tokio::spawn(tg_proxy::role::reload(
        gate,
        Some(path.clone()),
        std::time::Duration::from_mins(1),
    ));

    // The agent renews -- as the leader does every few seconds.
    let renewed = now + 60_000;
    std::fs::write(&path, format!("api 2 {renewed}\n")).expect("writable");

    let seen = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if roles.expires_at("api") == Some(renewed) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;

    refresher.abort();
    assert!(
        seen.is_ok(),
        "the renewal must arrive before the role lapses"
    );
}

/// **And it comes back when there is no role at all yet** (ADR-0066).
///
/// That is the counter direction to the test above, and it was the unseen one.
/// `reload` runs **only** when there is a gate -- that is, only for a single
/// writer. There "no role" does not mean "nothing to do" but precisely the
/// opposite: this workload waits to take the active role over, and the cluster
/// waits for it.
///
/// The case is the normal case and no edge: **every start** of a single writer
/// goes through it -- the leader grants the lease only one cadence later, it
/// travels in the slice, and the agent writes the file. And every failover
/// goes through it after the old holder is fenced.
///
/// With the ordinary cadence the new holder would stay mute for up to a minute
/// -- after the lease machinery worked in seconds. The fence would be fast and
/// the return slow.
#[tokio::test]
async fn the_refresher_returns_before_a_role_arrives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("active-role");

    // No lease yet: the standby waits.
    std::fs::write(&path, "").expect("writable");

    let roles = tg_proxy::role::SharedRoles::new(tg_proxy::role::Roles::default());
    let gate = tg_proxy::role::Gate::new("api".to_owned(), roles.clone());
    let refresher = tokio::spawn(tg_proxy::role::reload(
        gate.clone(),
        Some(path.clone()),
        RELOAD,
    ));

    // The cluster grants it -- the agent writes it down.
    let granted = tg_proxy::role::now_millis() + 15_000;
    std::fs::write(&path, format!("api 1 {granted}\n")).expect("writable");

    let seen = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if gate.is_active(tg_proxy::role::now_millis()) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;

    refresher.abort();
    assert!(
        seen.is_ok(),
        "the granted active role must arrive at the sidecar before the \
         ordinary cadence has run out -- otherwise the fence is fast and the \
         return slow"
    );
}

/// **The active role's deadline appears as a metric -- the `0` too.**
///
/// Of the four files a sidecar re-reads in operation, this was the only one
/// without one. The gap was not mere symmetry: the **agent** sets
/// `tg_workload_active_role` from the lease (ADR-0064), not the sidecar from
/// the file. If the refresher dies (since ADR-0082 that costs only it), the
/// agent reports `1` on, while the sidecar refuses as soon as the state it
/// read expires (ADR-0066).
///
/// **Both** cases are checked in one, and the second half carries: a metric
/// that appears only when there is a role is, in the case "the sidecar does
/// not talk", not distinguishable from a missing one.
///
/// The recorder is **local**: `cargo test` runs a file's tests concurrently,
/// and a global one would belong to the process.
#[test]
fn the_role_deadline_is_reported_in_both_cases() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use tg_proxy::role::{Gate, SharedRoles};

    let seen = |workload: &str| {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let gate = Gate::new(workload.to_owned(), SharedRoles::new(holding()));

        metrics::with_local_recorder(&recorder, || {
            tg_proxy::role::report(&gate);
            snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .filter(|(key, _, _, _)| {
                    key.key().name() == tg_telemetry::names::PROXY_ROLE_EXPIRES_AT
                })
                .map(|(_, _, _, value)| match value {
                    DebugValue::Gauge(value) => value.into_inner(),
                    other => panic!("no gauge: {other:?}"),
                })
                .collect::<Vec<f64>>()
        })
    };

    // The file names milliseconds, the metric seconds -- like its
    // siblings.
    assert_eq!(
        seen("api"),
        vec![1_800_000_015.0],
        "the active role's deadline must stand there as a point in time in seconds"
    );
    assert_eq!(
        seen("standby-only"),
        vec![0.0],
        "without a role `0` must stand there and the line must not be missing"
    );
}
