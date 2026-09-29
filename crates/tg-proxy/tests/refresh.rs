//! A sidecar that hears nothing any more says so (ADR-0019, ADR-0025).
//!
//! Written **before** the implementation.
//!
//! # The finding
//!
//! `reload_policy` read the edge file at a one-minute cadence and discarded
//! **both** error cases silently:
//!
//! ```text
//! let Ok(text) = std::fs::read_to_string(&path) else { continue };
//! let Ok(edges) = edges_from_text(&text) else { continue };
//! ```
//!
//! Fail-static is right -- the last known state applies on, that is ADR-0019
//! and ADR-0025 verbatim. Only nobody learned of it. A sidecar whose file
//! disappears enforces the edges from three days ago, and the only metric for
//! it -- `PolicyCache::is_stale` -- had **no caller**.
//!
//! In a system in which `may_talk` **is** the authorization (ADR-0025), that
//! is a blind spot with compliance weight.

use std::time::Duration;

use tg_proxy::policy::{PolicyCache, Refresh, RevocationWindow, Snapshot, refresh};
use tg_proxy::verify::SharedPolicy;

const T0: i64 = 1_000;

fn shared() -> SharedPolicy {
    let mut cache = PolicyCache::new(RevocationWindow::adr_0014());
    cache
        .apply(
            &Snapshot::from_edges(1, vec![("api".to_owned(), "ledger".to_owned())]),
            T0,
        )
        .expect("the first state");

    SharedPolicy::new(cache)
}

/// A new state is taken over and **reported**.
#[test]
fn a_readable_file_is_applied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("may-talk");
    std::fs::write(&path, "api -> ledger\napi -> cache\n").expect("write");
    let policy = shared();

    let outcome = refresh(&policy, &path, 2, T0 + 60);

    assert!(
        matches!(outcome, Refresh::Applied),
        "expected taken over, was {outcome:?}"
    );
}

/// **A missing file is a finding, no silence.**
///
/// And the old state applies on -- fail-static (ADR-0019). Both together are
/// the statement: reported **and** not discarded.
#[test]
fn a_missing_file_is_reported_and_the_old_state_holds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = shared();

    let outcome = refresh(&policy, &dir.path().join("nosuchthing"), 2, T0 + 60);

    assert!(
        matches!(outcome, Refresh::Unreadable { .. }),
        "expected unreadable, was {outcome:?}"
    );
    assert_eq!(
        policy.handle().read().expect("the lock").version(),
        1,
        "the last known state must apply on"
    );
}

/// A file that cannot be interpreted, likewise -- and with its reason.
#[test]
fn a_malformed_file_is_reported_with_its_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("may-talk");
    std::fs::write(&path, "this is no edge\n").expect("write");
    let policy = shared();

    let Refresh::Malformed { detail } = refresh(&policy, &path, 2, T0 + 60) else {
        panic!("expected uninterpretable");
    };

    assert!(
        !detail.is_empty(),
        "the reason must stand there -- otherwise an operator looks for it in the file"
    );
    assert_eq!(policy.handle().read().expect("the lock").version(), 1);
}

/// **The state goes stale visibly.**
///
/// `is_stale` thereby gets its caller. Before the window it is not, afterwards
/// it is -- without the first half a function that always says `true` would be
/// green too.
#[test]
fn the_age_crosses_the_window() {
    let policy = shared();
    let cache = policy.handle().read().expect("the lock");

    assert!(!cache.is_stale(T0 + 60));
    assert!(cache.is_stale(
        T0 + i64::try_from(RevocationWindow::adr_0014().staleness.as_secs()).expect("fits")
    ));
    assert_eq!(cache.age(T0 + 60), Duration::from_mins(1));
}

// --------------------------------- the egress permissions (ADR-0041) ---

use tg_proxy::egress::{SharedEgress, Transport};

/// **A withdrawn egress permission reaches the sidecar.**
///
/// Until here it was read **once at startup**, laid into an `Arc` and never
/// touched again. A granted permission could thereby not be taken back:
/// `RemoveWorkload` takes it along (ADR-0041), the agent writes the file anew
/// -- and the sidecar carried on letting its container out until somebody
/// restarted it. Deny-by-default was thereby a one-way street.
#[test]
fn a_withdrawn_egress_permission_reaches_the_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("egress");
    std::fs::write(&path, "api s3.test 443\napi log.test 443\n").expect("write");

    let egress = SharedEgress::new(tg_proxy::egress::EgressPolicy::from_entries([]));
    assert!(matches!(
        tg_proxy::egress::refresh(&egress, &path, "api", 15002, 1_000),
        Refresh::Applied
    ));
    assert!(egress.permits("s3.test", 443, Transport::Tcp));
    assert!(egress.permits("log.test", 443, Transport::Tcp));

    // The operator takes one back.
    std::fs::write(&path, "api s3.test 443\n").expect("write");
    assert!(matches!(
        tg_proxy::egress::refresh(&egress, &path, "api", 15002, 1_000),
        Refresh::Applied
    ));

    assert!(
        egress.permits("s3.test", 443, Transport::Tcp),
        "the other applies on"
    );
    assert!(
        !egress.permits("log.test", 443, Transport::Tcp),
        "the withdrawn permission still applies"
    );
}

/// **A missing file takes nothing away** -- fail-static, as with the edges
/// (ADR-0019), and it is reported.
///
/// The counter-check to the test above: a refresh that emptied at every
/// failure would make an outage to the outside out of a file error.
#[test]
fn a_missing_egress_file_does_not_revoke_anything() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("egress");
    std::fs::write(&path, "api s3.test 443\n").expect("write");

    let egress = SharedEgress::new(tg_proxy::egress::EgressPolicy::from_entries([]));
    let _ = tg_proxy::egress::refresh(&egress, &path, "api", 15002, 1_000);
    std::fs::remove_file(&path).expect("gone");

    let outcome = tg_proxy::egress::refresh(&egress, &path, "api", 15002, 1_000);

    assert!(
        matches!(outcome, Refresh::Unreadable { .. }),
        "expected unreadable, was {outcome:?}"
    );
    assert!(
        egress.permits("s3.test", 443, Transport::Tcp),
        "the last known state must apply on"
    );
}

/// **The own port flies out on the refresh too** (ADR-0051,
/// determination 3).
///
/// Until now the check sat in the startup path alone. Without it here the gap
/// would be open again at the first refresh -- and nobody would have noticed,
/// because the startup test would stay green.
#[test]
fn the_own_port_is_dropped_on_refresh_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("egress");
    std::fs::write(&path, "api s3.test 443\napi own.test 15002\n").expect("write");

    let egress = SharedEgress::new(tg_proxy::egress::EgressPolicy::from_entries([]));
    let _ = tg_proxy::egress::refresh(&egress, &path, "api", 15002, 1_000);

    assert!(egress.permits("s3.test", 443, Transport::Tcp));
    assert!(
        !egress.permits("own.test", 15002, Transport::Tcp),
        "the permission onto the own port would be the bypass of the redirect"
    );
}
