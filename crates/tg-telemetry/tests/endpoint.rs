//! The telemetry endpoint on a real socket.
//!
//! It is substantiated with `curl` — foreign code that read HTTP
//! independently. The same yardstick as `dig` in phase 9c and `rust-spiffe` in
//! 7c: a test against our own client would show only that both sides share a
//! view, not that it is the right one.
//!
//! What matters here is the **status code**. Prometheus, kubelet-like probers
//! and every operations tool decide by it; a body that says "not ok" while the
//! code reads 200 is read by nobody.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tg_telemetry::probes::{Health, Readiness};

/// One call with `curl`.
///
/// **The tests run on a multi-thread runtime**, and that is no convenience:
/// `std::process::Command::output` blocks the thread it runs on. On the
/// single-thread runtime `#[tokio::test]` provides, that would be the same
/// thread on which the endpoint accepts connections — the test would then hang
/// forever, and in a way that looked like a server error. Exactly that happened
/// on the first attempt.
///
/// `--max-time` stands beside it as a fallback: a test that hangs is worse than
/// one that fails.
fn curl(url: &str) -> (u16, String) {
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "5",
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            url,
        ])
        .output()
        .expect("invoke curl");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = text.rsplit_once('\n').expect("status line");
    (code.trim().parse().expect("status code"), body.to_owned())
}

/// Starts the endpoint on a free port and returns it.
///
/// **The socket is bound and not released again.** The first attempt bound,
/// discarded and let `serve` bind anew — and under load somebody else took the
/// port in the gap. The test then failed with "unreachable" and looked like a
/// server error. That is why `serve_on` exists.
async fn start(health: Health, scrape: &'static str) -> SocketAddr {
    start_with(health, Arc::new(move || scrape.to_owned())).await
}

/// The same with a **real** exporter instead of a fixed string.
async fn start_with(health: Health, scrape: tg_telemetry::serve::Scrape) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("address");

    tokio::spawn(
        async move { match tg_telemetry::serve::serve_on(listener, health, scrape).await {} },
    );

    addr
}

/// The soft limit from `/proc/self/limits` — a **different** way from the one
/// the endpoint goes (`getrlimit`). An assertion that draws its expected value
/// from the logic under test checks nothing.
fn soft_limit_from_proc() -> u64 {
    let text = std::fs::read_to_string("/proc/self/limits").expect("limits readable");
    let line = text
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .expect("line present");
    line.split_whitespace()
        .nth(3)
        .expect("soft limit")
        .parse()
        .expect("number")
}

/// Reads a gauge's value from the Prometheus text.
///
/// **Line by line and on the value**, not `contains(name)`: the name occurs in
/// the `# TYPE` line too, and that it stands somewhere says nothing about the
/// number beside it (the finding from "two deadlines, made visible").
fn gauge(body: &str, name: &str) -> f64 {
    body.lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let (key, value) = line.rsplit_once(' ')?;
            // The name stands alone or with labels behind it.
            let key = key.split('{').next()?;
            (key == name).then(|| value.parse().ok())?
        })
        .unwrap_or_else(|| panic!("{name} missing in:\n{body}"))
}

/// The normal case: three paths, three answers, and `/metrics` emits what the
/// exporter yields.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_three_paths_answer() {
    let health = Health::new();
    health.watch("reconcile", Duration::from_hours(1), now());
    health.set("raft", Readiness::up());

    let addr = start(health, "tg_up 1\n").await;

    let (code, body) = curl(&format!("http://{addr}/metrics"));
    assert_eq!(code, 200);
    assert!(body.contains("tg_up 1"), "{body}");

    let (code, body) = curl(&format!("http://{addr}/livez"));
    assert_eq!(code, 200, "{body}");

    let (code, body) = curl(&format!("http://{addr}/readyz"));
    assert_eq!(code, 200, "{body}");
    assert!(body.contains("raft: ready"), "{body}");
}

/// **Not ready is `503`, not `500`.**
///
/// `500` would mean "the telemetry is broken"; an operator would then look for
/// the error at the endpoint instead of at the node. `503` means "I, right now,
/// not" — and that is exactly the statement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unready_node_answers_503_and_says_why() {
    let health = Health::new();
    health.set("raft", Readiness::down("no quorum: 2 of 5 reachable"));

    let addr = start(health, String::new().leak()).await;

    let (code, body) = curl(&format!("http://{addr}/readyz"));

    assert_eq!(code, 503);
    assert!(body.contains("no quorum: 2 of 5 reachable"), "{body}");
}

/// And `/livez` stays green in the process — the separation from ADR-0019, now
/// over real HTTP.
///
/// Without this test the previous one would prove only that something goes red.
/// Here **one** thing is different, and the difference is the whole point: a
/// prober that confuses the two restarts every node on the minority side of a
/// partition.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn liveness_stays_green_while_readiness_is_red() {
    let health = Health::new();
    health.watch("reconcile", Duration::from_hours(1), now());
    health.set("raft", Readiness::down("no quorum"));

    let addr = start(health, String::new().leak()).await;

    assert_eq!(curl(&format!("http://{addr}/readyz")).0, 503);
    assert_eq!(curl(&format!("http://{addr}/livez")).0, 200);
}

/// A wedged loop turns `/livez` red — and names it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wedged_loop_turns_livez_red() {
    let health = Health::new();
    health.set("raft", Readiness::up());
    // The last beat lies in the distant past.
    health.watch("reconcile", Duration::from_mins(1), Duration::ZERO);

    let addr = start(health, String::new().leak()).await;

    let (code, body) = curl(&format!("http://{addr}/livez"));

    assert_eq!(code, 503);
    assert!(body.contains("reconcile"), "{body}");
    assert!(body.contains("without a sign of life"), "{body}");
}

/// An unknown path names the known ones instead of only saying `404`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_path_lists_the_known_ones() {
    let addr = start(Health::new(), String::new().leak()).await;

    let (code, body) = curl(&format!("http://{addr}/is-there-anything-here"));

    assert_eq!(code, 404);
    assert!(body.contains("/metrics"), "{body}");
    assert!(body.contains("/livez"), "{body}");
    assert!(body.contains("/readyz"), "{body}");
}

fn now() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

/// **How many descriptors the process holds, and how many it may hold.**
///
/// The reason stands at [`tg_telemetry::names::OPEN_FDS`]: if they run out, no
/// listener of this system accepts any more — and nothing about it was
/// observable. The report comes when it has happened.
///
/// Checked is the **number**, not the presence of the line, and the limit
/// against an independent way (`/proc/self/limits` instead of `getrlimit`).
/// That it **moves** is the second half: a gauge that always says the same
/// thing would be indistinguishable from a constant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_endpoint_reports_the_descriptors_of_this_process() {
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("recorder");
    let scrape: tg_telemetry::serve::Scrape = Arc::new(move || handle.render());

    let health = Health::new();
    let addr = start_with(health, scrape).await;

    let (code, body) = curl(&format!("http://{addr}/metrics"));
    assert_eq!(code, 200, "{body}");

    let limit = gauge(&body, "tg_process_max_fds");
    #[allow(clippy::cast_precision_loss)]
    let expected = soft_limit_from_proc() as f64;
    assert!(
        (limit - expected).abs() < f64::EPSILON,
        "reported {limit}, in /proc/self/limits {expected}"
    );

    let before = gauge(&body, "tg_process_open_fds");
    assert!(before > 0.0 && before < limit, "{before} of {limit}");

    // **It has to move.** Held until after the second scrape; a `drop` before
    // that would make the test one that can measure nothing.
    //
    // **Five hundred and not fifty, and the bound is 400.** The counter belongs
    // to the *process*, and `cargo test` runs this file's tests concurrently:
    // the neighbours bind sockets, call `curl` and close both again. Measured,
    // a first attempt with fifty saw a difference of 41 — computed correctly,
    // only not deterministically. Five hundred washes the noise away instead of
    // inventing a tolerance that is tight again with the next test neighbour.
    let held: Vec<std::fs::File> = (0..500)
        .map(|_| std::fs::File::open("/dev/null").expect("openable"))
        .collect();

    let (_, body) = curl(&format!("http://{addr}/metrics"));
    let after = gauge(&body, "tg_process_open_fds");
    drop(held);

    assert!(
        after >= before + 400.0,
        "before {before}, after {after} — the gauge does not follow the process"
    );
}
