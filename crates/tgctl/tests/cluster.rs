//! `tgctl cluster apply` (ADR-0018, ADR-0048).
//!
//! Up to here **nobody** could write a workload into the cluster:
//! `Command::UpsertWorkload` occurred in `crates/*/src` exactly once, in a
//! `#[cfg(test)]` module. `tgctl apply` has written the node-local desired
//! state since phase 2 — a different target, hence a different verb.
//!
//! What is checked is the **client** against a provided admin service; the
//! server side — that a hint arises at all — stands in
//! `crates/tgd/tests/admin_socket.rs`.

use std::process::Command as OsCommand;
use tg_model::egress::Transport;

use tg_admin::WriteResult;
use tg_model::command::Outcome;

mod support;

use support::{
    Served, serve, serve_admitted, serve_document, serve_nodes, serve_settings, serve_showing,
    serve_trust, serve_volumes,
};

const PLAIN: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
     <workload name=\"api\" kind=\"service\">\n\
     <image reference=\"example.com/api:1\"/>\n\
     </workload>\n\
     <workload name=\"web\" kind=\"service\">\n\
     <image reference=\"example.com/web:1\"/>\n\
     </workload>\n\
     </workloads>\n";

fn applied(lints: Vec<String>) -> WriteResult {
    WriteResult::Applied {
        outcome: Outcome::Applied,
        lints,
    }
}

fn write(served: &Served, name: &str, xml: &str) -> std::path::PathBuf {
    let path = served.dir.path().join(name);
    std::fs::write(&path, xml).expect("write");
    path
}

/// A valid definition with one workload, in `dir`.
fn one_workload(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("api.xml");
    std::fs::write(
        &path,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"registry.invalid/api:1\"/>\n\
         </workload>\n\
         </workloads>\n",
    )
    .expect("write");
    path
}

/// Calls `tgctl` with a data directory.
fn run(args: &[&str], dir: &std::path::Path) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(dir)
        .args(args)
        .output()
        .expect("tgctl is startable")
}

fn apply(served: &Served, file: &std::path::Path) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(served.dir.path())
        .args(["cluster", "apply"])
        .arg(file)
        .output()
        .expect("tgctl is startable")
}

/// **Every workload individually.**
///
/// `UpsertWorkload` carries exactly one definition (ADR-0004). A file with two
/// workloads is a convenience of the operator, not a unit in the log — a
/// collective command would make one event out of two, and an auditor would no
/// longer see what came when.
#[tokio::test(flavor = "multi_thread")]
async fn a_definition_reaches_the_cluster_one_workload_at_a_time() {
    let served = serve(1, applied(Vec::new()));
    let file = write(&served, "two.xml", PLAIN);

    let out = apply(&served, &file);

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("api: taken"), "{stdout}");
    assert!(stdout.contains("web: taken"), "{stdout}");
    assert_eq!(
        served.seen.lock().expect("mutex").len(),
        2,
        "not two commands arrived"
    );
}

/// **The canonical document is what travels**, not the submitted text: that
/// way what arrives in the log is what the loader understood (ADR-0008).
#[tokio::test(flavor = "multi_thread")]
async fn the_canonical_document_is_what_travels() {
    let served = serve(1, applied(Vec::new()));
    let file = write(&served, "two.xml", PLAIN);

    let _ = apply(&served, &file);

    let seen = served.seen.lock().expect("mutex").clone();
    for command in &seen {
        let tg_model::command::Command::UpsertWorkload { document } = command else {
            panic!("wrong command: {command:?}");
        };
        // Exactly **one** workload per command, and it is readable again.
        let set = tg_defs::from_str(document).expect("canonical and readable");
        assert_eq!(set.workloads().len(), 1, "{document}");
    }
}

/// **A hint from the cluster reaches the operator** (ADR-0048) — and it stands
/// on stderr, not on stdout: the output says what was taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_lint_from_the_cluster_reaches_the_operator() {
    let served = serve(
        1,
        applied(vec![
            "'ledger' is single-writer with one instance".to_owned(),
        ]),
    );
    let file = write(&served, "api.xml", PLAIN);

    let out = apply(&served, &file);

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("warning"), "no hint: {stderr}");
    assert!(stderr.contains("ledger"), "{stderr}");
    assert!(
        !stdout.contains("ledger"),
        "the hint stands on stdout: {stdout}"
    );
}

/// **A cycle does not reach the cluster in the first place.** It is refused in
/// the client before the first workload is written — otherwise half an invalid
/// set would lie in the log (ADR-0009).
#[tokio::test(flavor = "multi_thread")]
async fn a_cycle_never_reaches_the_cluster() {
    let served = serve(1, applied(Vec::new()));
    let file = write(
        &served,
        "cycle.xml",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"a\" kind=\"service\">\n\
         <image reference=\"example.com/a:1\"/>\n\
         <dependencies><after ref=\"b\"/></dependencies>\n\
         </workload>\n\
         <workload name=\"b\" kind=\"service\">\n\
         <image reference=\"example.com/b:1\"/>\n\
         <dependencies><after ref=\"a\"/></dependencies>\n\
         </workload>\n\
         </workloads>\n",
    );

    let out = apply(&served, &file);

    assert!(!out.status.success(), "{out:?}");
    assert!(
        served.seen.lock().expect("mutex").is_empty(),
        "it was written: {out:?}"
    );
}

/// **A follower does not write and says where to go.**
#[tokio::test(flavor = "multi_thread")]
async fn a_follower_names_the_leader() {
    let served = serve(1, WriteResult::ForwardTo { leader: Some(3) });
    let file = write(&served, "api.xml", PLAIN);

    let out = apply(&served, &file);

    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains('3'),
        "{out:?}"
    );
}

/// Without a socket the directory is named — and nothing is written.
#[test]
fn without_a_socket_nothing_is_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("api.xml");
    std::fs::write(&file, PLAIN).expect("write");

    let out = OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(dir.path())
        .args(["cluster", "apply"])
        .arg(&file)
        .output()
        .expect("tgctl is startable");

    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&dir.path().display().to_string()),
        "{out:?}"
    );
}

// --- The standing query (ADR-0048, determination 2) -------------------------

fn lint(served: &Served) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(served.dir.path())
        .args(["cluster", "lint"])
        .output()
        .expect("tgctl is startable")
}

/// **The standing query needs no write.**
///
/// That is its whole point: a lint belongs to the **set** and can arise because
/// somebody changed an *other* workload — then there is no write to whose
/// answer it could attach itself.
#[tokio::test(flavor = "multi_thread")]
async fn the_standing_query_needs_no_write() {
    let served = support::serve_with(
        1,
        applied(Vec::new()),
        vec!["'ledger' is single-writer with one instance".to_owned()],
    );

    let out = lint(&served);

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("ledger"), "{stdout}");
    assert!(stdout.contains("1 hint"), "{stdout}");
    assert!(
        served.seen.lock().expect("mutex").is_empty(),
        "the query wrote"
    );
}

/// **A hint is not a failure status.** Hints are warnings and not rejections
/// (ADR-0009); a tool that ends with an error on a hint turns a recommendation
/// into a rule — and then somebody switches it off.
///
/// That is the difference from `tgctl audit`, where a finding **does** yield a
/// failure status: there it is damage, here a recommendation.
#[tokio::test(flavor = "multi_thread")]
async fn a_lint_is_not_a_failure_status() {
    let served = support::serve_with(1, applied(Vec::new()), vec!["anything".to_owned()]);

    assert!(lint(&served).status.success());
}

/// No hints is **said**, not expressed by silence. An empty output is
/// indistinguishable from a tool that did not run.
#[tokio::test(flavor = "multi_thread")]
async fn no_lints_is_said_out_loud() {
    let served = support::serve_with(1, applied(Vec::new()), Vec::new());

    let out = lint(&served);

    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no hints"),
        "{out:?}"
    );
}

/// **The state belongs with it.** Without it an operator does not know whether
/// the statement already knows their last write.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_names_the_state_it_came_from() {
    let served = support::serve_with(1, applied(Vec::new()), Vec::new());

    let stdout = String::from_utf8(lint(&served).stdout).expect("utf8");

    assert!(stdout.contains("state 7"), "{stdout}");
}

/// Without a socket the directory is named.
#[test]
fn the_standing_query_without_a_socket_names_the_directory() {
    let dir = tempfile::tempdir().expect("tempdir");

    let out = OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(dir.path())
        .args(["cluster", "lint"])
        .output()
        .expect("tgctl is startable");

    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&dir.path().display().to_string()),
        "{out:?}"
    );
}

// --- The read path and the withdrawal ---------------------------------------
//
// **All tests here run `multi_thread`**, like those above, and that is no
// habit: `Command::output()` blocks its thread. On the single-thread runtime
// `#[tokio::test]` provides, that is the same thread on which the provided
// admin service accepts connections — the test would then wait for a server it
// had itself denied execution, and **hangs** instead of failing. The same
// finding as at the telemetry tests in 11b, and it happened here a second
// time.

fn cluster(served: &Served, args: &[&str]) -> std::process::Output {
    OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(served.dir.path())
        .arg("cluster")
        .args(args)
        .output()
        .expect("tgctl is startable")
}

fn projected(name: &str, instances: Vec<(u32, &str)>) -> tg_admin::ProjectedWorkload {
    tg_admin::ProjectedWorkload {
        stale: Vec::new(),
        unready: Vec::new(),
        failures: Vec::new(),
        name: name.to_owned(),
        image: format!("example.com/{name}:1"),
        class: "replicated".to_owned(),
        edges: vec![("after".to_owned(), "ledger".to_owned())],
        instances: instances
            .into_iter()
            .map(|(number, status)| (number, status.to_owned()))
            .collect(),
        ordered: tg_model::rollout::Generations::default(),
        addresses: Vec::new(),
        egress: Vec::new(),
        placed: Vec::new(),
        // One instance as the default -- the witnesses that check the
        // denominator change it. `0` would be the wrong default: then every
        // witness would report a workload nobody wants.
        replicas: 1,
        lease: None,
    }
}

/// The same with decreed generations (ADR-0071).
fn ordered(name: &str, all: u64, single: &[(u32, u64)]) -> tg_admin::ProjectedWorkload {
    let mut workload = projected(name, vec![(0, "running")]);
    workload.ordered.set(None, all);
    for (instance, generation) in single {
        workload.ordered.set(Some(*instance), *generation);
    }
    workload
}

/// **Wanted and observed stand separately** (ADR-0004).
///
/// The test demands both in the output: the image comes from the log, the
/// instance state from a report. Pulled together they would be more convenient
/// to read and a statement nobody can substantiate.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_path_separates_what_should_run_from_what_was_seen() {
    let served = serve_showing(
        1,
        applied(Vec::new()),
        vec![projected("api", vec![(0, "running"), (1, "failed")])],
    );

    let output = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "show must succeed: {text}");
    assert!(text.contains("state 7"), "the state is missing: {text}");
    assert!(
        text.contains("example.com/api:1"),
        "the image is missing: {text}"
    );
    assert!(text.contains("after=ledger"), "the edge is missing: {text}");
    assert!(
        text.contains("0=running") && text.contains("1=failed"),
        "the observed instances are missing — and **per instance** at that: {text}"
    );
}

/// **"Nothing observed" is not "nothing runs".**
///
/// The distinction is the reason why the line carries words at all instead of
/// an empty list: an empty map means "no report" (ADR-0004), and an operator
/// who reads that as a finding looks in the wrong place.
#[tokio::test(flavor = "multi_thread")]
async fn an_absent_report_is_not_reported_as_a_failure() {
    let served = serve_showing(1, applied(Vec::new()), vec![projected("api", Vec::new())]);

    let output = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&output.stdout);

    assert!(
        text.contains("no report"),
        "the absence of a report must be named: {text}"
    );
    assert!(
        !text.contains("failed") && !text.contains("stopped"),
        "without a report no state may be claimed: {text}"
    );
}

/// An empty projection is **said**.
///
/// The same rule as at `lint`: an empty output is indistinguishable from a tool
/// that did not run.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_cluster_is_said_out_loud() {
    let served = serve_showing(1, applied(Vec::new()), Vec::new());

    let output = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        text.contains("no workloads"),
        "silence does not suffice: {text}"
    );
}

/// The withdrawal sends **exactly** `RemoveWorkload`.
#[tokio::test(flavor = "multi_thread")]
async fn a_removal_reaches_the_cluster_as_one_command() {
    let served = serve_showing(
        1,
        applied(Vec::new()),
        vec![projected("api", vec![(0, "running")])],
    );

    let output = cluster(&served, &["remove", "api"]);
    assert!(output.status.success(), "remove must succeed");

    let seen = served.seen.lock().expect("mutex").clone();
    assert_eq!(seen.len(), 1, "exactly one command: {seen:?}");
    match &seen[0] {
        tg_model::command::Command::RemoveWorkload { name } => assert_eq!(name, "api"),
        other => panic!("wrong command: {other:?}"),
    }

    // What goes with it is **said**: no `apply` brings the permissions back.
    let complaint = String::from_utf8_lossy(&output.stderr);
    assert!(
        complaint.contains("egress permissions"),
        "the loss of the permissions must be named: {complaint}"
    );
}

/// **A typo does not look like a success.**
///
/// `RemoveWorkload` is idempotent — an unknown name is done for the state
/// machine, not refused. Without the hint an operator would read "withdrawn"
/// and walk on reassured.
///
/// The hint is expressly no failure status: the projection is eventual and
/// node-local, a missing name can be mere lag.
#[tokio::test(flavor = "multi_thread")]
async fn removing_a_name_this_node_never_saw_says_so() {
    let served = serve_showing(
        1,
        applied(Vec::new()),
        vec![projected("api", vec![(0, "running")])],
    );

    let output = cluster(&served, &["remove", "typo"]);
    let complaint = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "it is no error, only a hint");
    assert!(
        complaint.contains("did not know 'typo'"),
        "the unknown name must be named: {complaint}"
    );

    // Counter-check: at a known name the hint stays away. Without it the test
    // would be green even if it always appeared.
    let known = cluster(&served, &["remove", "api"]);
    assert!(
        !String::from_utf8_lossy(&known.stderr).contains("did not know"),
        "at a known name the hint does not belong"
    );
}

/// The withdrawal too names the leader instead of silently doing nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_follower_names_the_leader_on_removal() {
    let served = serve(1, WriteResult::ForwardTo { leader: Some(3) });

    let output = cluster(&served, &["remove", "api"]);

    assert!(!output.status.success(), "on a follower it must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("node 3"),
        "the leader must be named"
    );
}

// ----------------------------------------------- Allowing and withdrawing

/// **A `may_talk` edge reaches the cluster** (ADR-0025).
///
/// # Why this command exists
///
/// `Command::AllowTraffic` occurred in production code exactly once: in its own
/// `match` arm in the state machine. **Nobody produced it.** With that
/// deny-by-default had no way to a yes — a freshly built cluster refused every
/// connection, and an operator could do nothing about it.
///
/// The same pattern as at ADR-0044 (a privileged port without a client) and
/// ADR-0048 (lints without a client), only at the most consequential place.
#[tokio::test(flavor = "multi_thread")]
async fn an_edge_reaches_the_cluster() {
    let served = serve(1, applied(Vec::new()));

    let out = cluster(&served, &["allow", "api", "ledger"]);

    assert!(out.status.success(), "{out:?}");
    let seen = served.seen.lock().expect("commands");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        matches!(
            &seen[0],
            tg_model::command::Command::AllowTraffic { from, to } if from == "api" && to == "ledger"
        ),
        "{seen:?}"
    );
}

/// And it can be withdrawn.
#[tokio::test(flavor = "multi_thread")]
async fn an_edge_can_be_revoked() {
    let served = serve(1, applied(Vec::new()));

    let out = cluster(&served, &["revoke", "api", "ledger"]);

    assert!(out.status.success(), "{out:?}");
    let seen = served.seen.lock().expect("commands");
    assert!(
        matches!(
            &seen[0],
            tg_model::command::Command::RevokeTraffic { from, to } if from == "api" && to == "ledger"
        ),
        "{seen:?}"
    );
}

/// **An egress permission carries its port** (ADR-0041, ADR-0051).
///
/// The port is mandatory and is not guessed: the sidecar dials **that** one,
/// and the port on which the connection arrives at it carries no information
/// after the redirect.
#[tokio::test(flavor = "multi_thread")]
async fn an_egress_permission_carries_its_port() {
    let served = serve(1, applied(Vec::new()));

    let out = cluster(&served, &["allow-egress", "api", "s3.example.com:443"]);

    assert!(out.status.success(), "{out:?}");
    let seen = served.seen.lock().expect("commands");
    assert!(
        matches!(
            &seen[0],
            tg_model::command::Command::AllowEgress {
                workload,
                host,
                port,
                transport,
            } if workload == "api"
                && host == "s3.example.com"
                && *port == 443
                && *transport == Transport::Tcp
        ),
        "{seen:?}"
    );
}

/// **And the revocation carries it just the same** (ADR-0092).
///
/// The transport belongs to a permission's **key**: the same name and the same
/// port over `tcp` **and** `quic` is the normal case, for an HTTP/3 client
/// falls back to TCP. Whoever revokes one means only one — a revocation that
/// lost the transport would take both or the wrong one.
///
/// Measured, `revoke-egress` was the only subcommand with **no** test.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_egress_permission_carries_its_transport() {
    let served = serve(1, applied(Vec::new()));

    let out = cluster(
        &served,
        &["revoke-egress", "api", "s3.example.com:443/quic"],
    );

    assert!(out.status.success(), "{out:?}");
    let seen = served.seen.lock().expect("commands");
    assert!(
        matches!(
            &seen[0],
            tg_model::command::Command::RevokeEgress {
                workload,
                host,
                port,
                transport,
            } if workload == "api"
                && host == "s3.example.com"
                && *port == 443
                && *transport == Transport::Quic
        ),
        "{seen:?}"
    );
}

/// **Without a port it is refused, not guessed** — and **before** the socket
/// search at that.
///
/// Assuming `:443` would be a decision the operator did not make — and a
/// permission on the wrong port is an open door at a place nobody meant.
///
/// The order is the second half of the promise: measured, first came
/// "`/var/lib/tardigrade` is unreadable" — an operator's typo thereby hung on
/// whether an admin socket is found. The same rule as at the volume name in
/// 10b: the setting the human typed comes first.
#[tokio::test(flavor = "multi_thread")]
async fn an_egress_permission_without_a_port_is_refused() {
    let served = serve(1, applied(Vec::new()));

    let out = cluster(&served, &["allow-egress", "api", "s3.example.com"]);

    assert!(!out.status.success(), "{out:?}");
    assert!(
        served.seen.lock().expect("commands").is_empty(),
        "nothing may have been sent"
    );

    // Without a data directory — that is, without a socket — the same message
    // must come. Otherwise the check would lie behind the search again.
    let bare = OsCommand::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg("/does/not/exist")
        .args(["cluster", "allow-egress", "api", "s3.example.com"])
        .output()
        .expect("tgctl is startable");

    assert!(!bare.status.success());
    assert!(
        String::from_utf8_lossy(&bare.stderr).contains("names no port"),
        "{}",
        String::from_utf8_lossy(&bare.stderr)
    );
}

// --------------------------------------------- The remaining log commands

/// **Deleting a volume demands a confirmation** (ADR-0027).
///
/// `DeleteVolume` had no producer in production code — a volume could never be
/// deleted although the whole machinery stands behind it: the check in the
/// state machine, the tombstone from ADR-0042, the execution in the agent.
///
/// The confirmation does **not** stand in the command (phase 10b: "a
/// confirmation field in the log would be a string one can copy"). It is the
/// explicit action when issuing — here `--yes`.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_volume_needs_a_confirmation() {
    let served = serve(1, applied(Vec::new()));

    let refused = cluster(&served, &["delete-volume", "master", "node-1"]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        served.seen.lock().expect("commands").is_empty(),
        "without a confirmation nothing may be sent"
    );

    let out = cluster(&served, &["delete-volume", "master", "node-1", "--yes"]);
    assert!(out.status.success(), "{out:?}");
    let seen = served.seen.lock().expect("commands");
    assert!(
        matches!(
            &seen[0],
            tg_model::command::Command::DeleteVolume { volume, node, at }
                if volume == "master" && node == "node-1" && *at > 0
        ),
        "{seen:?}"
    );
}

/// **The cluster network comes from consensus** (ADR-0040).
///
/// It is the same number cluster-wide; two nodes with different values compute
/// different subnets without it standing out. Hence one command and not a
/// setting per node — only up to here nobody could issue it.
#[tokio::test(flavor = "multi_thread")]
async fn the_cluster_network_can_be_set() {
    let served = serve(1, applied(Vec::new()));

    let out = cluster(&served, &["network", "10.42.0.0/16", "24"]);

    assert!(out.status.success(), "{out:?}");
    let seen = served.seen.lock().expect("commands");
    assert!(
        matches!(
            &seen[0],
            tg_model::command::Command::SetClusterNetwork { cidr, node_prefix }
                if cidr == "10.42.0.0/16" && *node_prefix == 24
        ),
        "{seen:?}"
    );
}

// --- The node view (ADR-0054, ADR-0055, ADR-0059) ---------------------------

/// Two nodes for the read path: one complete, one without anything.
///
/// Moved out because the test would otherwise lie past the line limit — and
/// because the **counter-direction** carries half the promise: "nothing heard
/// yet" and "nothing known" are two statements, and both must stand there.
fn two_nodes() -> Served {
    serve_nodes(
        1,
        vec![
            tg_admin::ProjectedNode {
                name: "node-1".to_owned(),
                domain: "fra/h1/r1".to_owned(),
                schedulable: "schedulable".to_owned(),
                attached: true,
                capacity: vec![("cpu-millicores".to_owned(), 4000)],
                reserved: vec![("cpu-millicores".to_owned(), 1000)],
                reported_capacity: Some(vec![("cpu-millicores".to_owned(), 8000)]),
                ordinal: Some(1),
                wanted_generations: (3, 5),
                reported_generations: Some((1, 5)),
                proxy_image: Some("registry.test/proxy:1".to_owned()),
                last_report: Some(1_800_000_000),
                dns_zone: Some("tardigrade.internal".to_owned()),
                userns: Some(100_000),
                applied_slice: Some(42),
                isolated: vec!["broken".to_owned()],
            },
            tg_admin::ProjectedNode {
                name: "node-2".to_owned(),
                domain: "fra/h1/r2".to_owned(),
                schedulable: "cordoned".to_owned(),
                attached: false,
                capacity: Vec::new(),
                reserved: Vec::new(),
                reported_capacity: None,
                ordinal: None,
                wanted_generations: (0, 0),
                reported_generations: None,
                proxy_image: None,
                last_report: None,
                dns_zone: None,
                userns: None,
                applied_slice: None,
                isolated: Vec::new(),
            },
        ],
    )
}

/// **What an operator can see about their nodes, without Prometheus.**
///
/// These settings were up to here to be had only as metrics. The test checks
/// the three places at which the output makes a **statement** instead of
/// printing a number:
///
/// - "nothing heard yet" is said, not expressed by a blank — whoever reads it
///   as a finding looks in the wrong place;
/// - a node without a mesh says that it builds no sidecar instead of simply
///   naming nothing (ADR-0059);
/// - a generation backlog is **named**, because it is the reason the message
///   exists at all (ADR-0055, determination 5).
#[tokio::test(flavor = "multi_thread")]
async fn the_node_view_says_what_it_does_not_know() {
    let served = two_nodes();

    let output = cluster(&served, &["nodes"]);
    let text = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "nodes must succeed: {text}");

    assert!(text.contains("node-1  fra/h1/r1"), "{text}");
    // **Which zone it serves** (ADR-0013). The metric says how many there are;
    // which node deviates must stand here — otherwise an operator has the
    // number and no place.
    assert!(
        text.contains("zone:       tardigrade.internal"),
        "the node's zone is missing: {text}"
    );
    // And said instead of kept quiet: a node without a node network serves no
    // names.
    assert!(
        text.contains("zone:       none (no node network)"),
        "a missing zone is not said: {text}"
    );
    assert!(
        text.contains("(behind: 2)"),
        "the generation backlog must be named: {text}"
    );
    assert!(
        text.contains("registry.test/proxy:1"),
        "the sidecar's generation is missing: {text}"
    );
    // **Whether it maps** (ADR-0091). The same task as the zone, only a skew
    // weighs more here: `tg_cluster_userns_postures` says **whether** there is
    // one, this line **where**. And it names the **consequence** -- an operator
    // would otherwise read a number and not its meaning.
    assert!(
        text.contains("userns:     100000 (uid 0 in the container is 100000 here)"),
        "the node's range is missing: {text}"
    );
    assert!(
        text.contains("userns:     none (uid 0 in the container is uid 0 on the node)"),
        "an unhardened node must say so, not keep quiet: {text}"
    );
    assert!(
        text.contains("nothing (no report)"),
        "\"nothing heard yet\" must be said: {text}"
    );

    // **What the planner reckons with** (ADR-0034) and **what is reserved**
    // (ADR-0047). Without these numbers a `NoRoom` rejection is not
    // reconstructable, and `tg_scheduler_domain_*` gives sums per domain.
    assert!(
        text.contains("capacity:   cpu-millicores=4000")
            && text.contains("(reserved: cpu-millicores=1000)"),
        "the capacity and the reserve are missing: {text}"
    );
    // **And separate from that, what the node itself reports** (ADR-0049,
    // ADR-0004). The distinction is the point: a capacity policy reckons on the
    // **measured** number, and whoever writes it without seeing it writes
    // blind. 8000 measured against 4000 wanted is exactly the case an operator
    // must see.
    assert!(
        text.contains("measured:   cpu-millicores=8000"),
        "die gemeldete Kapazitaet fehlt: {text}"
    );
    // "Nothing heard yet" and "nothing known" are two statements, and both are
    // said — a blank is indistinguishable from a rendering error.
    assert!(
        text.contains("measured:   nothing (no report)"),
        "a node without a report must say so: {text}"
    );
    // **The ordinal** (ADR-0039). The node's subnet follows from it and from
    // that every route, every nftables rule and every `AllowedIP` (phase 9a) —
    // at a network problem the first number an operator needs, and up to here
    // readable nowhere. Both directions, because a blank is indistinguishable
    // from a rendering error.
    assert!(
        text.contains("ordinal:    1"),
        "the ordinal is missing: {text}"
    );
    assert!(
        text.contains("ordinal:    none (no subnet)"),
        "a node without an ordinal must say so: {text}"
    );
    assert!(
        text.contains("capacity:   empty"),
        "\"nothing known\" is a statement and must stand there: {text}"
    );
    assert!(
        text.contains("none (without --proxy-image no mesh)"),
        "a node without a mesh must say so: {text}"
    );
    assert!(text.contains("last:       never"), "{text}");

    // **Which slice it has applied** (ADR-0040). The number has stood in
    // **every** report since that ADR and was read by nobody; it is the one at
    // which a node stands out that gets slices and does not apply them — `last`
    // then says something fresh while this number stands still.
    assert!(
        text.contains("applied:    slice 42"),
        "the applied slice is missing: {text}"
    );
    // And the counter-direction, as at the neighbours: "nothing reported" is
    // something other than "slice zero".
    assert!(
        text.contains("applied:    nothing reported"),
        "a node without a report must say so: {text}"
    );

    // **What it could not classify** (ADR-0062). The node reports it per pass
    // into its log; without this line a broken declaration is to be found only
    // there.
    assert!(
        text.contains("isolated:   broken"),
        "the isolated entry is missing: {text}"
    );
    // And empty is **not** said: unlike at the settings above, "none" here
    // means the same as "nothing reported" — there is nothing to do here.
    assert_eq!(
        text.matches("isolated:").count(),
        1,
        "a node without isolated entries gets no line: {text}"
    );
}

/// **Stale is a line of its own** (ADR-0070).
///
/// The instance runs; it merely runs from an older declaration. Written into
/// the `observed` column it would be a **state**, and a tool that reads it
/// would not understand it.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_path_says_which_instances_are_stale() {
    let mut api = projected("api", vec![(0, "running"), (1, "running")]);
    api.stale = vec![1];

    let served = serve_showing(1, applied(Vec::new()), vec![api]);
    let out = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        text.contains("stale: 1"),
        "the information is missing:\n{text}"
    );
    assert!(
        text.contains("observed: 0=running 1=running"),
        "and the state stays what it is:\n{text}"
    );
}

/// **Unready is a line of its own** (ADR-0080, determination 1).
///
/// The same separation as at `stale`: the instance runs, it merely does not
/// serve. Written into the `observed` column it would be a state.
///
/// Without this line an operator would have **no** read path for the readiness
/// — only the metric `tg_workload_ready` at every single node's endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_path_says_which_instances_are_unready() {
    let mut api = projected("api", vec![(0, "running"), (1, "running")]);
    api.unready = vec![0];

    let served = serve_showing(1, applied(Vec::new()), vec![api]);
    let out = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        text.contains("unready: 0"),
        "the information is missing:\n{text}"
    );
    assert!(
        text.contains("observed: 0=running 1=running"),
        "and the state stays what it is:\n{text}"
    );
}

/// **And empty is not said.**
///
/// A line "unready: none" for every healthy workload would be noise, and an
/// operator would learn to read past it — unlike at `observed`, where "nothing
/// reported" is to be distinguished from "nothing runs".
#[tokio::test(flavor = "multi_thread")]
async fn a_ready_workload_gets_no_line() {
    let api = projected("api", vec![(0, "running")]);

    let served = serve_showing(1, applied(Vec::new()), vec![api]);
    let out = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        !text.contains("unready:"),
        "a ready workload gets no line:\n{text}"
    );
}

/// **The decreed generation stands in the output** (ADR-0071).
///
/// It is the number an operator needs in order to name the next one: `restart`
/// demands it, and backwards is refused. Without a read path they learned it
/// only from a rejection.
///
/// **Both levels**, for the effective generation of an instance is the maximum
/// — a computed number alone would leave open what applies to the others.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_path_shows_the_ordered_generation() {
    let served = serve_showing(
        1,
        applied(Vec::new()),
        vec![ordered("api", 2, &[(1, 5)]), projected("quiet", vec![])],
    );

    let out = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        text.contains("generation: 2"),
        "the generation for all is missing:\n{text}"
    );
    assert!(
        text.contains("individually: 1=5"),
        "the deviating instance is missing:\n{text}"
    );

    // **Without a decree no line.** A "generation: 0" at every workload would be
    // noise, and an operator would learn to read past it.
    let quiet = text
        .lines()
        .skip_while(|line| !line.starts_with("quiet"))
        .take_while(|line| !line.is_empty())
        .any(|line| line.contains("generation"));
    assert!(
        !quiet,
        "without a decree no generation may stand there:\n{text}"
    );
}

/// **Where an instance is reachable stands in the output** (ADR-0073).
///
/// The address is assigned node-locally (phase 9a) and **reported**; it stands
/// in no log. For an operator it is the one number with which they can look up
/// what the resolver offers — and until ADR-0073 every node knew only its
/// own.
///
/// **A line of its own**, no addition to the state: the address is information.
/// Written into `observed` it would be a state, and a tool that reads the
/// column would not understand it.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_path_shows_where_an_instance_is_reachable() {
    let mut workload = projected("api", vec![(0, "running"), (1, "running")]);
    workload.addresses = vec![(0, "10.42.1.5".to_owned()), (1, "10.42.2.5".to_owned())];
    let served = serve_showing(1, applied(Vec::new()), vec![workload]);

    let output = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "show must succeed: {text}");
    assert!(
        text.contains("addresses:  0=10.42.1.5 1=10.42.2.5"),
        "the addresses are missing: {text}"
    );
}

/// **And without a report no line stands there.**
///
/// The counter-check: an empty line would mean "no address", and that is
/// something other than "nothing reported yet" — the same difference `observed`
/// beside it expressly names.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_reported_address_no_line_appears() {
    let served = serve_showing(
        1,
        applied(Vec::new()),
        vec![projected("api", vec![(0, "running")])],
    );

    let output = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{text}");
    assert!(
        !text.contains("addresses:"),
        "without a report no address line may appear: {text}"
    );
}

/// **The membership had no client** (ADR-0005, phase 5d).
///
/// # The finding
///
/// `MembershipChange` did **not** occur in production code — only in its own
/// definition and in a test of `tgd`. A node replacement in the control plane
/// was thereby possible only with Rust, and that is the procedure a five-node
/// design (ADR-0031) provides for: replacing a failed node.
///
/// It is the pattern this tree has found a dozen times — built, checked, unused
/// (`AdminClient` before ADR-0044, `generate_token` before `node invite`,
/// `permits` before ADR-0051).
///
/// # The read path first
///
/// It is not convenience: [`voters`] takes the **complete** future set, and
/// nobody who does not see today's can name it.
#[tokio::test(flavor = "multi_thread")]
async fn the_voters_can_be_read() {
    let served = support::serve_members(1, vec![1, 2, 3, 4, 5], support::changed(&[]));
    let out = run(&["cluster", "members"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("voters: 1 2 3 4 5"),
        "the voters are missing: '{text}'"
    );
    // Five is the promise from ADR-0031 — then there is no hint.
    assert!(
        !text.contains("ADR-0031"),
        "five voters are the promise, not a hint: '{text}'"
    );
}

/// **Fewer than five is said** (ADR-0031) — and not refused.
///
/// A replacement passes through four; a refusal would make the ordinary
/// procedure impossible. The counter-check to the test above: without it a tool
/// that never gives the hint would be green too.
#[tokio::test(flavor = "multi_thread")]
async fn a_thin_cluster_is_named() {
    let served = support::serve_members(1, vec![1, 2, 3], support::changed(&[]));
    let out = run(&["cluster", "members"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("ADR-0031"),
        "three voters belong named: '{text}'"
    );
}

/// **Step one of two: the learner, and it waits** (phase 5d).
///
/// `blocking` is the whole point of this step: the call returns when the node
/// has caught up. Without the waiting an operator would have to guess when they
/// may promote — and the answer stands in no metric.
#[tokio::test(flavor = "multi_thread")]
async fn a_learner_is_added_blocking() {
    let served = support::serve_members(1, vec![1, 2, 3], support::changed(&[1, 2, 3]));
    let out = run(&["cluster", "learner", "4"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let changes = served.changes.lock().expect("mutex").clone();
    assert!(
        matches!(
            changes.as_slice(),
            [tg_admin::MembershipChange::AddLearner {
                id: 4,
                blocking: true
            }]
        ),
        "expected a blocking AddLearner: {changes:?}"
    );
}

/// **Step two: the complete set, not an increment.**
///
/// The command below means a **state**. A delta would be a read-modify-write:
/// two operators who add a node at the same time would lose each other silently
/// — the same consideration with which `SetSchedulability` is separated from
/// `UpsertNode` (phase 6).
#[tokio::test(flavor = "multi_thread")]
async fn the_voters_are_set_as_a_whole() {
    let served = support::serve_members(1, vec![1, 2, 3], support::changed(&[1, 2, 3, 4]));
    let out = run(&["cluster", "voters", "1,2,3,4"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let changes = served.changes.lock().expect("mutex").clone();
    let [tg_admin::MembershipChange::SetVoters { ids, retain }] = changes.as_slice() else {
        panic!("expected a SetVoters: {changes:?}");
    };
    assert_eq!(ids, &[1, 2, 3, 4]);
    assert!(
        !retain,
        "whoever is not named does not stay as a learner — otherwise the cluster \
         supplies a state nobody wanted"
    );

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("voters now: 1 2 3 4"),
        "the new set is missing: '{text}'"
    );
}

/// **On the wrong node it says who leads** (ADR-0044).
///
/// The admin socket is node-local, so `tgctl` cannot forward — and exactly for
/// that reason the test rig provides the service instead of starting it: a
/// one-node cluster is always the leader and could **not give** this answer at
/// all.
#[tokio::test(flavor = "multi_thread")]
async fn a_membership_change_on_a_follower_names_the_leader() {
    let served = support::serve_members(
        1,
        vec![1, 2, 3],
        tg_admin::MembershipResult::ForwardTo { leader: Some(3) },
    );
    let out = run(&["cluster", "voters", "1,2,3"], served.dir.path());

    assert!(!out.status.success(), "a referral is no success");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("leader is 3"), "{text}");
}

/// **An identifier that is none is refused — before the socket.**
///
/// The order counts: a typo shall not depend on whether an admin socket is
/// found. The test therefore runs **without** a data directory.
#[tokio::test(flavor = "multi_thread")]
async fn a_bad_id_is_refused_before_the_socket() {
    let empty = tempfile::tempdir().expect("tempdir");
    let out = run(&["cluster", "learner", "three"], empty.path());

    assert!(!out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("'three' is no node identifier"),
        "expected the setting, not the socket: '{text}'"
    );
}

/// **`tgctl apply` says so when the cluster steers the node** (ADR-0040,
/// ADR-0058).
///
/// # The trap
///
/// `apply` writes the **node-local** desired state — the way from phase 2, for
/// a node without a cluster. On a node *with* a session the same action is one
/// the next slice turns back: it removes what it does not name (ADR-0040,
/// determination 6, **by file names**), and afterwards the clearer ends the
/// container (ADR-0058).
///
/// The operator saw "taken" and seconds later a workload that is gone — without
/// a word about it.
///
/// # Why the mark is the right signal
///
/// `network/applied` arises only once a slice has been applied **completely**.
/// It is thereby exactly the statement "the cluster is authoritative here" —
/// and the same mark with which the reconciler distinguishes "nothing wanted"
/// from "nothing heard yet".
#[tokio::test(flavor = "multi_thread")]
async fn a_local_apply_on_a_cluster_managed_node_is_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = one_workload(dir.path());

    // The mark an agent leaves behind after its first slice.
    let network = tg_runtime::NodePaths::new(dir.path()).network_dir();
    std::fs::create_dir_all(&network).expect("directory");
    std::fs::write(
        tg_runtime::NodePaths::new(dir.path()).slice_applied(),
        "7\n",
    )
    .expect("mark");

    // The outcome is immaterial: the start fails at an image that does not
    // exist. The subject is the **warning**, and it falls before that.
    let out = run(&["apply", file.to_str().expect("path")], dir.path());
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("steered by the cluster") && text.contains("cluster apply"),
        "the warning is missing:\n{text}"
    );
}

/// **And without a mark there is no warning** — the counter-check.
///
/// Without it a `tgctl` that nags at every local `apply` would be green too;
/// then an operator would read the warning as noise and overlook it where it
/// counts.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_apply_without_a_slice_says_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = one_workload(dir.path());

    let out = run(&["apply", file.to_str().expect("path")], dir.path());
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        !text.contains("steered by the cluster"),
        "without a slice there is nothing to warn about:\n{text}"
    );
}

/// **Why an instance failed stands in the output** (ADR-0015).
///
/// Up to here `cluster show` said only `failed`, and the first question in
/// operation — *why does that not run* — demanded shell access to the right
/// node. Now the **class** stands beside it: it says where to look.
///
/// The **text** expressly does not stand there: it names names out of a payload
/// (an image reference, a URL), and the node's log is the place for that.
///
/// And it is a **line of its own**, no addition to the state — the same
/// separation as at `stale` (ADR-0070, determination 5): the instance stands in
/// `observed` with `failed`, and the class is information beside it.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_path_says_why_an_instance_failed() {
    let mut api = projected("api", vec![(0, "running"), (1, "failed")]);
    api.failures = vec![(1, "pull".to_owned())];

    let served = serve_showing(1, applied(Vec::new()), vec![api]);
    let out = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        text.contains("failed: 1=pull"),
        "the class is missing from the output:\n{text}"
    );
    assert!(
        text.contains("observed: 0=running 1=failed"),
        "and the state stays what it is:\n{text}"
    );
}

/// **The client checks before it writes for the first time** (ADR-0084,
/// determination 3).
///
/// The same place and the same reason as at the cycle: *"a set with a cycle
/// must not reach the cluster half way in the first place"*. An upsert carries
/// exactly one workload (ADR-0004), so otherwise half the file would stand in
/// the log before the cluster refuses the second.
///
/// # Why without a data directory
///
/// Because only that way is the **order** checked. If a socket lay ready, a
/// failure would not prove that the check comes before the connecting — it
/// could stem from the connection too. Without a data directory the socket
/// search is the second source of error, and the message says which came
/// first.
#[test]
fn a_blocked_derivation_is_refused_before_the_first_write() {
    let dir = tempfile::tempdir().expect("directory");
    let file = dir.path().join("both.xml");
    std::fs::write(
        &file,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         \x20 <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.invalid/api:1\"/>\n\
         \x20   <mesh port=\"9000\"/>\n\
         \x20 </workload>\n\
         \x20 <workload name=\"api-proxy\" kind=\"service\">\n\
         \x20   <image reference=\"registry.invalid/own:1\"/>\n\
         \x20 </workload>\n\
         </workloads>\n",
    )
    .expect("file");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("--data-dir")
        .arg(dir.path().join("does-not-exist"))
        .args(["cluster", "apply"])
        .arg(&file)
        .output()
        .expect("tgctl is startable");

    assert!(!out.status.success(), "the file must not get through");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("api-proxy"),
        "the message must name the occupied name: {text}"
    );
    // And it must come **before** the socket search: otherwise the reason would
    // lie at the missing data directory, and an operator would look there.
    assert!(
        !text.contains("unreadable") && !text.contains("socket"),
        "the check must come before the socket search: {text}"
    );
}

/// **The other half of the authorization, where the workload lies, and who
/// writes.**
///
/// # The finding
///
/// `ProjectedWorkload` carried `edges` — who may talk to whom in the mesh — and
/// **not** the egress permissions. Both are deny-by-default (ADR-0025,
/// ADR-0041), both are written by `tgctl cluster allow…`, and only the one half
/// was readable. A permission one cannot enumerate one cannot check (ADR-0020)
/// — and "where may this workload phone" is exactly the question an auditor
/// asks.
///
/// To that come two operational gaps: **where** an instance lies (ADR-0011)
/// stood nowhere, and **who** holds the active role (ADR-0064) neither —
/// `tg_workload_active_role` says at a node's endpoint whether *it* holds it.
///
/// What is additionally checked is the statement that is no number: "placed
/// nowhere" is **said**, not expressed by a blank.
#[tokio::test(flavor = "multi_thread")]
async fn the_workload_view_shows_egress_placement_and_lease() {
    let mut api = projected("api", vec![(0, "running")]);
    api.egress = vec![("s3.example.com".to_owned(), 443, "tcp".to_owned())];
    api.placed = vec![(0, "node-1".to_owned()), (1, "node-2".to_owned())];
    api.replicas = 2;
    api.lease = Some(("node-1".to_owned(), 7, 1_800_000_000));

    let mut unplaced = projected("waiting", vec![]);
    unplaced.replicas = 2;

    let served = serve_showing(1, applied(Vec::new()), vec![api, unplaced]);
    let output = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "show must succeed: {text}");

    assert!(
        text.contains("egress: s3.example.com:443"),
        "the egress permission is missing — it is the other half of the authorization: {text}"
    );
    assert!(
        text.contains("placed:     2/2 0@node-1 1@node-2"),
        "the placement is missing, or its denominator: {text}"
    );
    assert!(
        text.contains("active role: node-1 (epoch 7, until 1800000000 seconds UTC)"),
        "the holder of the active role is missing: {text}"
    );
    // **The class makes the line above readable** (ADR-0010): without it a
    // missing lease cannot be classified -- at a replicated workload it is the
    // normal case, at a single writer it means "does not write".
    assert!(
        text.contains("class: replicated"),
        "the class is missing: {text}"
    );
    // Said, not kept quiet: a blank is indistinguishable from a rendering
    // error.
    assert!(
        text.contains("placed:     nowhere of 2"),
        "\"not placed\" must stand there, with the number beside it: {text}"
    );
    // And the counter-check to the holder: a workload without a lease gets no
    // line — otherwise it would stand at every replicated workload and would be
    // noise.
    let lines: Vec<&str> = text.lines().filter(|l| l.contains("active role")).collect();
    assert_eq!(
        lines.len(),
        1,
        "only the workload **with** a lease may have the line: {text}"
    );
}

/// **The canonical document can be fetched** (ADR-0008).
///
/// # The finding
///
/// In the log stands what the **loader** understood — not the file an operator
/// submitted. Whoever lost their file got at it up to here only via
/// `tgd --audit-export`: with `tgd` stopped and as JSONL. A recovery path that
/// presupposes an outage is none.
///
/// # What the test assures
///
/// The document stands **alone** on stdout, so that
/// `tgctl cluster get api > api.xml` yields the file `tgctl cluster apply`
/// takes back. And an unknown name is an **error** and not an empty output —
/// whoever redirects would otherwise take an empty file for a result (the same
/// consideration as at the empty range in `audit export`).
#[tokio::test(flavor = "multi_thread")]
async fn the_canonical_document_can_be_fetched() {
    let document = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"example.com/api:1\"/>\n\
         </workload>\n\
         </workloads>\n";

    let served = serve_document(1, document.to_owned());

    let output = cluster(&served, &["get", "api"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "get must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        text, document,
        "on stdout belongs the document and nothing else"
    );
    // The state goes to stderr — on stdout it would stand **inside** the
    // document.
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("state 7"),
        "the state is missing from stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // And the counter-check: a name the cluster does not know is an error.
    // Without it a `get` that always prints nothing would be just as green.
    let missing = cluster(&served, &["get", "does-not-exist"]);
    assert!(
        !missing.status.success(),
        "an unknown name must fail: {}",
        String::from_utf8_lossy(&missing.stdout)
    );
    assert!(
        missing.stdout.is_empty(),
        "and write nothing on stdout: {}",
        String::from_utf8_lossy(&missing.stdout)
    );
}

/// What applies cluster-wide is readable — and "not set" is said.
///
/// Four settings apply to the whole cluster: the address plan (ADR-0069), the
/// sidecar surcharge (ADR-0067), the capacity policy (ADR-0049) and the
/// rotation policy (ADR-0057). `tgctl` writes all four, and **none** was
/// readable. For the two policies that weighs double: `SetCapacityPolicy` and
/// `SetRotationPolicy` **replace** the whole policy — whoever wants to add a
/// rule must know the existing ones.
///
/// Both directions stand here, and the second carries half the promise: a blank
/// is indistinguishable from a tool that did not run.
#[tokio::test(flavor = "multi_thread")]
async fn what_holds_cluster_wide_is_readable() {
    let served = serve_settings(
        1,
        tg_admin::SettingsResponse {
            id: 1,
            last_applied: Some(7),
            network: Some(("10.42.0.0/16".to_owned(), 24)),
            sidecar_overhead: vec![("millicores".to_owned(), 50)],
            capacity: vec![(
                "millicores".to_owned(),
                tg_model::capacity::Rule {
                    subtract: 2000,
                    percent: 80,
                    cap: Some(64_000),
                    reserve: 1000,
                },
            )],
            rotation: vec![(tg_model::KeyKind::Underlay, 90)],
        },
    );

    let output = cluster(&served, &["settings"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "settings must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for wanted in [
        "10.42.0.0/16",
        "/24",
        "millicores=50",
        "percent=80",
        "subtract=2000",
        "cap=64000",
        "reserve=1000",
        "underlay every 90 days",
        "state 7",
    ] {
        assert!(
            text.contains(wanted),
            "'{wanted}' is missing from the output: {text}"
        );
    }

    // The counter-direction: nothing set means that it is **said**.
    let empty = serve_settings(
        2,
        tg_admin::SettingsResponse {
            id: 2,
            last_applied: None,
            network: None,
            sidecar_overhead: Vec::new(),
            capacity: Vec::new(),
            rotation: Vec::new(),
        },
    );
    let output = cluster(&empty, &["settings"]);
    let text = String::from_utf8_lossy(&output.stdout);
    for wanted in [
        "not set",
        "no surcharge",
        "capacity policy: none",
        "rotation: none",
        "no state yet",
    ] {
        assert!(
            text.contains(wanted),
            "'{wanted}' is missing at empty settings: {text}"
        );
    }
}

/// Who may be a node is readable — and the absence is said.
///
/// **The key is the credential** (ADR-0037, ADR-0043), and the list that
/// decides it an operator could not see: `RevokeTrust` is the documented answer
/// to a compromised key (ADR-0054), and whether it took hold was not
/// ascertainable.
///
/// Three statements stand here, and all three carry: the SPKI **unshortened**
/// (after a rotation one compares it), "nothing announced means no tunnel"
/// instead of a blank, and an **expired** invitation is named as such — it
/// stays lying in the state until somebody tries to redeem it, and whoever
/// holds it for valid waits for a join that cannot come.
#[tokio::test(flavor = "multi_thread")]
async fn who_may_be_a_node_is_readable() {
    let served = serve_trust(
        1,
        tg_admin::TrustResponse {
            id: 1,
            last_applied: Some(7),
            nodes: vec![
                tg_admin::TrustedNode {
                    name: "node-1".to_owned(),
                    spki: "MCowBQYDK2VwAyEAtestkey".to_owned(),
                    ordinal: Some(1),
                    underlay: Some(("wgKEY".to_owned(), "10.0.0.1:51820".to_owned())),
                },
                tg_admin::TrustedNode {
                    name: "node-2".to_owned(),
                    spki: "MCowBQYDK2VwAyEAsecond".to_owned(),
                    ordinal: None,
                    underlay: None,
                },
            ],
            // One valid and one dead — both directions in one run.
            invitations: vec![
                ("node-3".to_owned(), 4_102_444_800),
                ("node-4".to_owned(), 1_000_000_000),
            ],
        },
    );

    let output = cluster(&served, &["trust"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "trust must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for wanted in [
        "MCowBQYDK2VwAyEAtestkey",
        "10.0.0.1:51820",
        "nothing announced",
        "node-3 valid until",
        "node-4 expired since",
        // The unit belongs with it: an operator reckons the number against their
        // clock, and milliseconds against seconds is a factor of a thousand.
        "(seconds UTC)",
        "state 7",
    ] {
        assert!(
            text.contains(wanted),
            "'{wanted}' is missing from the output: {text}"
        );
    }

    // The counter-direction: a cluster without an admitted node says so — an
    // empty output is indistinguishable from a tool that did not run.
    let empty = serve_trust(
        2,
        tg_admin::TrustResponse {
            id: 2,
            last_applied: None,
            nodes: Vec::new(),
            invitations: Vec::new(),
        },
    );
    let output = cluster(&empty, &["trust"]);
    let text = String::from_utf8_lossy(&output.stdout);
    for wanted in ["no node admitted", "invitations: none open"] {
        assert!(text.contains(wanted), "'{wanted}' is missing: {text}");
    }
}

/// What is deleted is readable — together with the sum.
///
/// `DeleteVolume` is the only destructive command (ADR-0027) and the
/// **decision**, not the deed: the node carries it out when it sees the
/// tombstone (ADR-0042). Whether it has done so was not to be looked up.
///
/// The **sum** stands with it because it is the question ADR-0042 leaves open:
/// a tombstone goes away only when the same volume is declared again — it is
/// the only collection in the replicated state that grows without anything
/// clearing it, and it travels along in every snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn what_is_deleted_is_readable() {
    let served = serve_volumes(
        1,
        tg_admin::VolumesResponse {
            id: 1,
            last_applied: Some(7),
            tombstones: vec![
                (
                    "node-1".to_owned(),
                    vec!["old".to_owned(), "data".to_owned()],
                ),
                ("node-2".to_owned(), vec!["archive".to_owned()]),
            ],
        },
    );

    let output = cluster(&served, &["volumes"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "volumes must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for wanted in [
        "node-1: old data",
        "node-2: archive",
        "tombstones: 3",
        "state 7",
    ] {
        assert!(text.contains(wanted), "'{wanted}' is missing: {text}");
    }

    // The counter-direction: no tombstones is **said**. An empty output is
    // indistinguishable from a tool that did not run.
    let empty = serve_volumes(
        2,
        tg_admin::VolumesResponse {
            id: 2,
            last_applied: Some(1),
            tombstones: Vec::new(),
        },
    );
    let output = cluster(&empty, &["volumes"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("no tombstone"), "{text}");
    assert!(
        !text.contains("tombstones:"),
        "without tombstones no sum belongs there: {text}"
    );
}

// ============================ The transport (ADR-0092, determinations 1 and 6)

/// **`/quic` reaches the log as `quic`.**
///
/// The record on the client side: the word from the command line is not merely
/// parsed, it stands in the command. Without this assurance the transport could
/// fall back to the default on the way — and an operator would have demanded
/// QUIC and got TCP.
#[tokio::test(flavor = "multi_thread")]
async fn the_transport_from_the_command_line_reaches_the_log() {
    let served = serve(1, applied(Vec::new()));

    // **All three**, not only one: a dispatch that knows two words and falls
    // back to the default at the third would look exactly the same at a single
    // case (ADR-0092, determination 6).
    for (word, want) in [
        ("quic", Transport::Quic),
        ("udp", Transport::Udp),
        ("tcp", Transport::Tcp),
    ] {
        let out = cluster(
            &served,
            &["allow-egress", "api", &format!("s3.example.com:443/{word}")],
        );
        assert!(out.status.success(), "{word}: {out:?}");

        let seen = served.seen.lock().expect("commands");
        let last = seen.last().expect("one command");
        assert!(
            matches!(
                last,
                tg_model::command::Command::AllowEgress { transport, .. } if *transport == want
            ),
            "'{word}' arrived as {last:?}"
        );
    }
}

/// **An unknown transport is refused — and before the socket search at
/// that.**
///
/// The same order as at the port: the setting a human typed comes first. The
/// test therefore runs against a data directory **without** a socket — only
/// that way does it check the order and not merely the refusal.
///
/// The word here was once `udp`, and that was right in its time: ADR-0092
/// determination 7 built the address path **after** the SNI path, and until
/// then ADR-0075 applied to plain UDP — forbidden. Since the second cut it is a
/// transport like the others; the promise this test carries is unchanged.
#[test]
fn an_unknown_transport_is_refused_before_the_socket_is_sought() {
    let dir = tempfile::tempdir().expect("directory");
    let out = run(
        &["cluster", "allow-egress", "api", "s3.example.com:443/sctp"],
        dir.path(),
    );

    assert!(!out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("sctp") && text.contains("transport"),
        "the message does not name the transport: {text}"
    );
}

/// **The data key stands alone on standard output** (ADR-0095).
///
/// With that `tgctl secret keygen > secrets.key` is the file an operator puts
/// into `<data-dir>/identity/` — the same form as at the join token, and for
/// the same reason: an accompanying line in it would be a key that is not
/// right.
#[test]
fn a_generated_data_key_stands_alone_on_stdout() {
    let dir = tempfile::tempdir().expect("directory");
    let out = run(&["secret", "keygen"], dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);

    // Exactly one line, and it is a key.
    assert_eq!(
        text.lines().count(),
        1,
        "the output is not one line: {text:?}"
    );
    assert!(
        tg_identity::secrets::DataKey::from_base64(text.trim()).is_ok(),
        "the output is no data key: {text:?}"
    );

    // The hint belongs on stderr — there stands what an operator must know
    // without spoiling the file.
    let note = String::from_utf8_lossy(&out.stderr);
    assert!(
        note.contains("secrets.key") && note.contains("backup material"),
        "the hint names neither the place nor the backup obligation: {note}"
    );
}

/// **Two calls yield two keys** — the counter-check. Without it a `keygen` that
/// prints a constant would be just as green.
#[test]
fn two_keygen_calls_differ() {
    let dir = tempfile::tempdir().expect("directory");

    let first = run(&["secret", "keygen"], dir.path());
    let second = run(&["secret", "keygen"], dir.path());

    assert_ne!(first.stdout, second.stdout, "keygen prints a constant");
}

/// **`tgctl` seals, and the plaintext never reaches the cluster** (ADR-0095,
/// determination 4).
///
/// The carrying assurance is the second: that a command arrives says nothing
/// about **what** stands in it. It is therefore checked at the serialized
/// command — and additionally that the value can be opened again with the key:
/// a `PutSecret` with random bytes would otherwise be just as green.
///
/// A secret above the limit does not reach the **log**.
///
/// That is the statement, and not merely "the call fails": a value in the log
/// stays there forever (ADR-0020) and travels along in **every** slice. What is
/// measured is therefore that **no** command arrived.
///
/// The counter-direction carries it: an ordinary secret gets through. Without
/// it a check that refuses every one would be just as green -- and the
/// neighbouring witness substantiates that it does not.
#[tokio::test(flavor = "multi_thread")]
async fn a_secret_over_the_limit_never_reaches_the_log() {
    let served = serve(1, applied(Vec::new()));

    let key = tg_identity::secrets::DataKey::generate().expect("key");
    let identity = served.dir.path().join("identity");
    std::fs::create_dir_all(&identity).expect("identity/");
    std::fs::write(identity.join("secrets.key"), key.to_base64()).expect("store");

    let limit = tg_identity::secrets::MAX_SECRET_BYTES;
    let value = served.dir.path().join("huge");
    std::fs::write(&value, vec![b'x'; limit + 1]).expect("value");

    let out = cluster(
        &served,
        &["secret", "put", "s3-key", value.to_str().expect("path")],
    );
    assert!(!out.status.success(), "{out:?}");

    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains(&(limit + 1).to_string()) && text.contains(&limit.to_string()),
        "the message does not name size and limit: {text}"
    );

    assert!(
        served.seen.lock().expect("commands").is_empty(),
        "the value reached the log -- it would stay there forever (ADR-0020)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secret_is_sealed_before_it_reaches_the_cluster() {
    let served = serve(1, applied(Vec::new()));

    // The data key lies where `tgctl` looks for it.
    let key = tg_identity::secrets::DataKey::generate().expect("key");
    let identity = served.dir.path().join("identity");
    std::fs::create_dir_all(&identity).expect("identity/");
    std::fs::write(identity.join("secrets.key"), key.to_base64()).expect("store");

    let value = served.dir.path().join("value");
    std::fs::write(&value, b"top-secret").expect("value");

    let out = cluster(
        &served,
        &["secret", "put", "s3-key", value.to_str().expect("path")],
    );
    assert!(out.status.success(), "{out:?}");

    let seen = served.seen.lock().expect("commands");
    let last = seen.last().expect("one command");

    let serialized = serde_json::to_string(last).expect("serializable");
    assert!(
        !serialized.contains("top-secret"),
        "the plaintext reached the control plane: {serialized}"
    );

    let tg_model::command::Command::PutSecret { value, .. } = last else {
        panic!("no PutSecret: {last:?}");
    };
    assert_eq!(
        key.open(value).expect("openable"),
        b"top-secret",
        "the sealed value is not the one that went in"
    );
}

/// **Without a data key nothing is stored**, and the message says how it
/// arises — otherwise an operator looks in the wrong place.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_data_key_no_secret_is_written() {
    let served = serve(1, applied(Vec::new()));
    let value = served.dir.path().join("value");
    std::fs::write(&value, b"whatever").expect("value");

    let out = cluster(
        &served,
        &["secret", "put", "s3-key", value.to_str().expect("path")],
    );

    assert!(!out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("secret keygen"),
        "the message does not say how the key arises: {text}"
    );
    assert!(
        served.seen.lock().expect("commands").is_empty(),
        "without a key no command may be issued"
    );
}

/// **The mapping is cluster-wide and carries no workload** (ADR-0096,
/// determination 1).
///
/// The counter-check stands beside it and is the actual statement: `rm` issues
/// a **different** command. Without it a client that always sends the same
/// would be just as green — and a mapping could never be withdrawn.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_is_mapped_and_cleared() {
    let served = serve(1, applied(Vec::new()));

    let out = cluster(&served, &["registry", "registry.test", "s3-key"]);
    assert!(out.status.success(), "{out:?}");
    assert!(matches!(
        served.seen.lock().expect("commands").last(),
        Some(tg_model::command::Command::SetRegistryCredential { registry, secret })
            if registry == "registry.test" && secret == "s3-key"
    ));

    let out = cluster(&served, &["registry", "rm", "registry.test"]);
    assert!(out.status.success(), "{out:?}");
    assert!(matches!(
        served.seen.lock().expect("commands").last(),
        Some(tg_model::command::Command::ClearRegistryCredential { registry })
            if registry == "registry.test"
    ));
}

/// **Who may read a secret stands beside its name** (ADR-0016).
///
/// That is the line which explains a refused deletion: `secret rm` is refused
/// as long as a permission stands, and its message names only **one**
/// workload.
#[tokio::test(flavor = "multi_thread")]
async fn the_readers_stand_next_to_their_secret() {
    let served = support::serve_secrets(
        1,
        tg_admin::SecretsResponse {
            id: 1,
            last_applied: Some(7),
            names: vec![("reg-key".to_owned(), 32), ("lonely".to_owned(), 8)],
            grants: vec![
                ("api".to_owned(), "reg-key".to_owned()),
                ("ledger".to_owned(), "reg-key".to_owned()),
            ],
            registries: vec![("registry.test".to_owned(), "reg-key".to_owned())],
        },
    );

    let out = cluster(&served, &["secrets"]);
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        text.contains("reg-key (32 B) -> api, ledger"),
        "the readers or the size are missing: {text}"
    );
    // **And "nobody" is said**, not expressed by a blank: a secret without a
    // permission is one nobody can use — and that is information, not a missing
    // setting.
    assert!(
        text.contains("lonely (8 B, nobody may read it)"),
        "a secret without readers is kept quiet: {text}"
    );
    assert!(
        text.contains("registry.test -> 'reg-key'"),
        "the registry mapping is missing: {text}"
    );
}

/// A secret above the limit is **named**, an ordinary one is not.
///
/// The client refuses one that is too large when storing — what can lie here is
/// one from a log entry from before this limit (the log is retained, ADR-0020)
/// or from somebody who wrote past the client (ADR-0044). It costs its
/// container at the next start (ADR-0098, determination 7), and without this
/// line nobody sees it beforehand.
///
/// The counter-direction carries the assurance: for the ordinary one beside it
/// **no** warning appears. Without it one that appears for every secret would
/// be just as green — and an operator would learn to read past it.
#[tokio::test(flavor = "multi_thread")]
async fn a_secret_over_the_limit_is_named() {
    let limit = tg_identity::secrets::MAX_SECRET_BYTES;
    let served = support::serve_secrets(
        1,
        tg_admin::SecretsResponse {
            id: 1,
            last_applied: Some(7),
            names: vec![("huge".to_owned(), limit + 1), ("ordinary".to_owned(), 64)],
            grants: Vec::new(),
            registries: Vec::new(),
        },
    );

    let out = cluster(&served, &["secrets"]);
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);

    assert!(
        text.contains("huge") && text.contains(&(limit + 1).to_string()),
        "the over-large secret is kept quiet: {text}"
    );
    assert!(
        !text.contains("ordinary"),
        "the ordinary one is warned about: {text}"
    );
}

/// **"None" is said**, not expressed by silence.
///
/// The counter-check to the test above: an empty output is indistinguishable
/// from a tool that did not run.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_cluster_says_so() {
    let served = support::serve_secrets(
        1,
        tg_admin::SecretsResponse {
            id: 1,
            last_applied: Some(7),
            names: Vec::new(),
            grants: Vec::new(),
            registries: Vec::new(),
        },
    );

    let out = cluster(&served, &["secrets"]);
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("none stored"), "{text}");
    assert!(text.contains("no mapping"), "{text}");
}

/// **Operator settings without `--peer` are a contradiction** (ADR-0050,
/// ADR-0103).
///
/// # The finding
///
/// Measured, such a call fell back to the local admin socket, succeeded — and
/// `local_uid` stood in the log instead of the name:
///
/// ```text
/// "actor":{"local_uid":0}
/// ```
///
/// An operator who types `--operator dana` and forgets `--peer` believes they
/// acted as `dana`, and the audit trail names a uid. That is exactly the
/// question for whose sake ADR-0050 exists — **who stands in the log** —, and a
/// wrong answer to it stands out to nobody.
///
/// # Why without a data directory
///
/// As at the neighbour above: only that way does the test check the **order**.
/// If a socket lay ready, a failure would not prove that the check comes before
/// the connecting.
#[test]
fn operator_flags_without_a_peer_are_refused() {
    for flag in ["--operator", "--operator-key", "--anchors"] {
        let value = if flag == "--operator" {
            "dana"
        } else {
            "/dev/null"
        };

        let out = std::process::Command::new(env!("CARGO_BIN_EXE_tgctl"))
            .args(["--data-dir", "/does-not-exist", flag, value])
            .args(["cluster", "allow", "a", "b"])
            .output()
            .expect("tgctl is startable");

        assert!(!out.status.success(), "{flag} must be refused");
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(
            text.contains(flag) && text.contains("--peer"),
            "the message must name both switches ({flag}): {text}"
        );
        assert!(
            !text.contains("not readable"),
            "the check must come before the socket search ({flag}): {text}"
        );
    }
}

/// **And without them the socket stays the way.**
///
/// The other half of the promise: a check that refuses *every* call without
/// `--peer` would take the local way from the operator — and that is the
/// recovery path (ADR-0044).
#[test]
fn without_operator_flags_the_socket_still_works() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tgctl"))
        .args(["--data-dir", "/does-not-exist"])
        .args(["cluster", "allow", "a", "b"])
        .output()
        .expect("tgctl is startable");

    let text = String::from_utf8_lossy(&out.stderr);
    // **On the socket search and expressly not on the word "socket"**: the
    // message about the contradiction contains it as well ("over the local
    // admin socket"), and an assurance on it would be green for **both**
    // outcomes. Measured: the counter-check "every call without --peer is
    // refused" thereby did not hit this witness.
    assert!(
        text.contains("not readable"),
        "without operator settings the socket belongs sought: {text}"
    );
    assert!(
        !text.contains("--peer"),
        "there is no contradiction to report here: {text}"
    );
}

/// Three workloads in one file — for the case in which the first aborts.
const THREE: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
     <workload name=\"api\" kind=\"service\">\n\
     <image reference=\"example.com/api:1\"/>\n\
     </workload>\n\
     <workload name=\"web\" kind=\"service\">\n\
     <image reference=\"example.com/web:1\"/>\n\
     </workload>\n\
     <workload name=\"ledger\" kind=\"service\">\n\
     <image reference=\"example.com/ledger:1\"/>\n\
     </workload>\n\
     </workloads>\n";

/// **What was no longer sent after a rejection stands in the message.**
///
/// # Why that counts
///
/// `UpsertWorkload` carries exactly one definition (ADR-0004) — a file with
/// three workloads is three log entries. If one aborts, `apply` stops, and the
/// cluster stands at what arrived until then. Without the information an
/// operator does not know whether the rest is in or was never sent — and has to
/// look it up individually.
///
/// # The setup
///
/// The provided service refuses **every** write, so the first already falls.
/// Which one it is changes nothing about the statement: what is checked is that
/// the rest did **not** arrive and that the message names it.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_workload_names_what_was_not_sent() {
    let served = serve(
        1,
        WriteResult::Applied {
            outcome: Outcome::Rejected(tg_model::command::Rejection::MalformedDocument {
                detail: "unreadable".to_owned(),
            }),
            lints: Vec::new(),
        },
    );
    let file = write(&served, "three.xml", THREE);

    let out = apply(&served, &file);

    assert!(!out.status.success(), "a rejection must end red");
    let said = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        said.contains("2 of 3") && said.contains("web, ledger"),
        "the message does not name what stayed behind: {said}"
    );

    // **The hard half**: the rest really did not arrive. Without it the message
    // would be a claim about a state nobody checked.
    assert_eq!(
        served.seen.lock().expect("mutex").len(),
        1,
        "after a rejection nothing more may be sent"
    );
}

/// **`tgctl list` says "none" when there is none** — and otherwise names the
/// names.
///
/// The node-local read path from phase 2, and the last subcommand without a
/// witness. The first half is this tree's rule: an empty output is
/// indistinguishable from a tool that did not run.
///
/// The second carries it: without it a `list` that **always** says "none" would
/// be just as green — and an operator would take a filled cache for empty.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_list_says_none_or_names_them() {
    let dir = tempfile::tempdir().expect("tempdir");

    let out = run(&["list"], dir.path());
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("no wanted workload"),
        "empty is not said: {text}"
    );

    // Two workloads into the local desired state -- over the way an operator
    // goes.
    let file = write_local(dir.path(), "two.xml", PLAIN);
    let _ = run(&["apply", file.to_str().expect("path")], dir.path());

    let out = run(&["list"], dir.path());
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("api") && text.contains("web"),
        "the names are missing: {text}"
    );
    assert!(
        !text.contains("no wanted workload"),
        "with content the empty information must not come: {text}"
    );
}

/// Writes a definition into an ordinary directory.
fn write_local(dir: &std::path::Path, name: &str, xml: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, xml).expect("write");
    path
}

/// **The epoch reached alone on stdout** (ADR-0107).
///
/// With that `tgctl cluster signer-refresh > epoch` is the number a script
/// reads — the same separation as at the join token: on stdout stands what was
/// asked for, on stderr what is to be known beside it.
#[tokio::test(flavor = "multi_thread")]
async fn a_signer_refresh_prints_the_epoch_alone() {
    let served = support::serve_refresh(1, Ok(tg_admin::RefreshGroupResponse { id: 4, epoch: 3 }));

    let out = run(&["cluster", "signer-refresh"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8(out.stdout).expect("utf8").trim(),
        "3",
        "the epoch does not stand alone on stdout"
    );
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    // And the information an operator needs: the **same** group key (the chains
    // keep applying), and when the old epoch falls (ADR-0107, determination 6).
    //
    // The last two assurances were once called `two epochs` — that described the
    // state *immediately* after the refresh and left open that it ends: the old
    // one is discarded as soon as **all five** have reported that the new one
    // lies on their disk. An operator who does not read that takes the
    // operation for finished while a left-out share still applies.
    assert!(stderr.contains("epoch 3"), "{stderr}");
    assert!(stderr.contains("node 4"), "{stderr}");
    assert!(stderr.contains("the same"), "{stderr}");
    assert!(stderr.contains("all five have reported"), "{stderr}");
    assert!(stderr.contains("cluster signer"), "{stderr}");
}

/// **A node without a seat refuses it, and the reason stands there.**
///
/// The group is decoupled from the Raft membership (ADR-0014, determination 1):
/// this command belongs not on the leader but on a node with a seat — and an
/// operator who does not read that looks at the socket.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_without_a_seat_says_so() {
    let served = support::serve_refresh(
        1,
        Err("this node holds no seat of the signing group".to_owned()),
    );

    let out = run(&["cluster", "signer-refresh"], served.dir.path());

    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8(out.stdout).expect("utf8").is_empty(),
        "a refused request must print no epoch"
    );
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    assert!(stderr.contains("no seat"), "{stderr}");
}

/// A seat with the shape from ADR-0014 and two epochs.
fn seated(epochs: Vec<u64>) -> tg_admin::SignerResponse {
    tg_admin::SignerResponse {
        id: 4,
        kind: "group".to_owned(),
        seat: Some(2),
        shape: Some((5, 3)),
        epochs,
        fingerprint: Some("4f2a91be".to_owned()),
        // **Five, its own included** — measured against five real processes:
        // the own share is one of the `t` commitments.
        linked: vec![1, 2, 3, 4, 5],
        admitted: 5,
        last_failure: None,
    }
}

/// A node that runs the CA alone (ADR-0097: `LocalSigner`).
fn unseated(id: u64) -> tg_admin::SignerResponse {
    tg_admin::SignerResponse {
        id,
        kind: "local".to_owned(),
        seat: None,
        shape: None,
        epochs: Vec::new(),
        fingerprint: None,
        linked: Vec::new(),
        admitted: 0,
        last_failure: None,
    }
}

/// **What this node knows about the group stands there** (ADR-0097, ADR-0107).
///
/// Two questions around a refresh, and both are unanswerable without this
/// command: can it run here (does this node hold a seat, are links and
/// admissions complete), and **is it through** — one epoch means discarded, two
/// mean that the old one still applies and a left-out share still contributes
/// to a signature (determination 6).
#[tokio::test(flavor = "multi_thread")]
async fn the_signing_group_of_this_node_is_readable() {
    let served = support::serve_signer(1, seated(vec![1, 2]));

    let out = run(&["cluster", "signer"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).expect("utf8");
    assert!(text.contains("node 4"), "{text}");
    assert!(
        text.contains("group"),
        "the kind of the CA is missing: {text}"
    );
    assert!(text.contains("seat:        2"), "{text}");
    assert!(text.contains("5 seats, threshold 3"), "{text}");
    // **The command's statement**: two epochs and the reason for it.
    assert!(text.contains("1, 2"), "{text}");
    assert!(text.contains("not discarded yet"), "{text}");
    // The fingerprint **with** the hint that it is none — eight hex characters
    // are short enough that nobody takes them for a key, and the line says so
    // anyway.
    assert!(text.contains("4f2a91be"), "{text}");
    assert!(text.contains("not a key"), "{text}");
    assert!(
        text.contains("1, 2, 3, 4, 5"),
        "the links are missing: {text}"
    );
    assert!(text.contains("including its own"), "{text}");
    assert!(text.contains("admissions:  5"), "{text}");
}

/// **One epoch does not mean "not discarded yet".**
///
/// The counter-check to the witness above: a line that always carries the
/// sentence would be just as green there — and an operator who reads it after a
/// finished refresh looks for a remainder that does not exist.
#[tokio::test(flavor = "multi_thread")]
async fn one_epoch_is_not_reported_as_a_leftover() {
    let served = support::serve_signer(1, seated(vec![2]));

    let out = run(&["cluster", "signer"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).expect("utf8");
    assert!(text.contains("epochs:      2"), "{text}");
    assert!(
        !text.contains("not discarded yet"),
        "one epoch is a finished refresh: {text}"
    );
}

/// **A node without a seat says so in words.**
///
/// It is the normal case in a cluster without a group, and the blank alone
/// would be indistinguishable from a rendering error. To that belongs where a
/// refresh goes instead (ADR-0014, determination 1).
#[tokio::test(flavor = "multi_thread")]
async fn a_node_without_a_seat_names_it() {
    let served = support::serve_signer(1, unseated(9));

    let out = run(&["cluster", "signer"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).expect("utf8");
    assert!(text.contains("node 9"), "{text}");
    assert!(text.contains("local"), "{text}");
    assert!(text.contains("none"), "{text}");
    assert!(text.contains("node with a seat"), "{text}");
    // And nothing that claims a shape that does not exist.
    assert!(!text.contains("threshold"), "{text}");
    assert!(!text.contains("generations"), "{text}");
}

/// **A silent voter is named.**
///
/// The information without which a `SetVoters` can lead into a dead end:
/// `change_membership` needs quorum, and `--init` is refused when a log already
/// exists. Whoever changes to a set whose majority is dead has **no way back**.
///
/// Both directions in one witness: the reachable ones stand **without** an
/// addition. Without this half a tool that reports every node as silent would
/// be green too
/// **How a new node catches up stands in `members`** (ADR-0005, ADR-0020).
///
/// Both numbers stood in the answer and were read by **nobody**. `purged`'s doc
/// block names their two consumers itself: a node that lacks everything before
/// it can only catch up by snapshot — and everything up to there can no longer
/// be exported from the log.
///
/// Three situations, three statements, and the third is the one an operator
/// must see: **no snapshot and a truncated log** means that a new node cannot
/// catch up at all.
#[tokio::test(flavor = "multi_thread")]
async fn how_a_new_node_catches_up_is_shown() {
    // Complete: from the log.
    let served = support::serve_compacted(1, vec![1, 2, 3], (None, None));
    let out = cluster(&served, &["members"]);
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("catch-up: from the log"),
        "the complete log is kept quiet: {text}"
    );

    // Truncated, with a snapshot.
    let served = support::serve_compacted(1, vec![1, 2, 3], (Some(40), Some(45)));
    let out = cluster(&served, &["members"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("by snapshot") && text.contains("up to 40") && text.contains("up to 45"),
        "the two numbers are missing: {text}"
    );

    // Truncated, **without** a snapshot — the situation that counts.
    let served = support::serve_compacted(1, vec![1, 2, 3], (Some(40), None));
    let out = cluster(&served, &["members"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("NOT POSSIBLE"),
        "a node cannot catch up, and it is not said: {text}"
    );
}

/// — and that is the alarming direction.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_voter_is_named() {
    let served =
        support::serve_reachable(1, vec![1, 2, 3, 4, 5], vec![1, 2, 3], support::changed(&[]));
    let out = run(&["cluster", "members"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("voters: 1 2 3 4(silent) 5(silent)"),
        "the silent nodes are missing: '{text}'"
    );
}

/// **Without the information nobody is called silent.**
///
/// The node always puts its own identifier in as well, so an empty list is
/// structurally impossible for an answer of this version — it means "this
/// version does not say" (`serde(default)`; ADR-0083 lets `tgctl` and `tgd` be
/// the same build, but the default applies nevertheless). Without the
/// distinction a new `tgctl` against an old `tgd` would report **every** node as
/// silent.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_answer_nobody_is_called_silent() {
    let served =
        support::serve_reachable(1, vec![1, 2, 3, 4, 5], Vec::new(), support::changed(&[]));
    let out = run(&["cluster", "members"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    // Checked on the **line**, not on the whole text: the hint below names
    // `(silent)` itself in order to say that it never appears.
    let line = text
        .lines()
        .find(|line| line.starts_with("voters:"))
        .unwrap_or_default();
    assert!(
        !line.contains("(silent)"),
        "without the information nobody may be called silent: '{line}'"
    );
    assert!(
        text.contains("does not name reachability"),
        "and the reason belongs with it: '{text}'"
    );
}

/// **A change onto a dead majority is named** — and not refused.
///
/// Of three named voters the leader reaches one; the quorum would be two. After
/// that there is no way back: `change_membership` needs quorum, and `--init` is
/// refused when a log already exists.
///
/// Warned instead of refused: a node can be silent this second and there the
/// next, and an operator who is repairing an outage must not hang on a snapshot
/// in time.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_onto_a_dead_majority_is_named() {
    let served = support::serve_reachable(
        1,
        vec![1, 2, 3, 4, 5],
        vec![1, 2, 3],
        support::changed(&[1, 4, 5]),
    );
    let out = run(&["cluster", "voters", "1", "4", "5"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("the leader reaches 1") && text.contains("quorum would be 2"),
        "the numbers are missing: '{text}'"
    );
    assert!(
        text.contains("Silent: 4 5"),
        "and the silent nodes belong with them: '{text}'"
    );
}

/// **On a follower it keeps quiet** — even at a dead majority.
///
/// The promise has stood at the code since the build: `metrics.replication` is
/// filled only on the leader, "silent" would on a follower be a statement about
/// something it cannot know. It had **no witness**, and the rationale for that
/// — "making that changeable would be a rebuild at every call site" — has
/// become moot with the `Answers` bundle: it is three lines.
///
/// The setup is the same as at the witness two above, with **one** thing
/// different. Without it an operator on a follower would report every
/// unreplicated node as silent — and in the alarming direction at that, for an
/// outage that does not exist.
#[tokio::test(flavor = "multi_thread")]
async fn on_a_follower_the_warning_stays_quiet() {
    let served = support::serve_follower(
        1,
        vec![1, 2, 3, 4, 5],
        vec![1],
        support::changed(&[1, 4, 5]),
    );
    let out = run(&["cluster", "voters", "1", "4", "5"], served.dir.path());

    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        !text.contains("no way back") && !text.contains("Silent:"),
        "a follower does not know who answers -- it may call nobody silent: \
         '{text}'"
    );
}

/// **And a living majority stays quiet.**
///
/// The counter-check to the witness above: without it a tool that warns at
/// every change would be green too — and a warning that always appears an
/// operator learns to read past.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_onto_a_living_majority_stays_quiet() {
    let served = support::serve_reachable(
        1,
        vec![1, 2, 3, 4, 5],
        vec![1, 2, 3],
        support::changed(&[1, 2, 3]),
    );
    let out = run(&["cluster", "voters", "1", "2", "3"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        !text.contains("no way back"),
        "a living majority is no finding: '{text}'"
    );
}

/// **Without the information there is nothing to compare.**
///
/// The same distinction as in `members`, at the second place: an empty list
/// means "does not say" and not "nobody". Without it a new `tgctl` against an
/// old `tgd` would warn at **every** change — and a warning that always appears
/// an operator learns to read past.
///
/// # What is not checked here
///
/// That the warning keeps quiet on a **follower** (`metrics.replication` is
/// filled only on the leader, and there the number would be wrong). The test
/// rig always answers with `is_leader: true`; making that changeable would be a
/// rebuild at every call site for a branch that is immediately followed by
/// `ForwardTo` anyway.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_answer_a_change_is_not_warned_about() {
    let served = support::serve_reachable(
        1,
        vec![1, 2, 3, 4, 5],
        Vec::new(),
        support::changed(&[1, 4, 5]),
    );
    let out = run(&["cluster", "voters", "1", "4", "5"], served.dir.path());

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        !text.contains("the leader reaches"),
        "without the information there is nothing to compare: '{text}'"
    );
}

/// **A typo in the node name is named** — and not refused.
///
/// A node that is not admitted gets no slice (ADR-0043), so the instruction
/// never reaches it; and because a tombstone disappears only when the named
/// node reports the execution (ADR-0104), it stays in the state and in every
/// snapshot.
///
/// # Why not in the state machine
///
/// The same check there would be **more expensive than a format change**:
/// `DeleteVolume` has stood in the log since phase 10b, and that is retained
/// (ADR-0020) — two nodes of different versions would derive different states
/// from the same entry, one with a tombstone and one without. At
/// `SnapshotVolume` the same check is free (ADR-0099, `NotAdmitted`), because
/// the command was new and there are no old entries.
///
/// The way out belongs in the warning: `RemoveNode` takes its node's tombstones
/// along, even those of a node that never existed.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_on_an_unadmitted_node_is_named() {
    let served = serve_admitted(1, applied(Vec::new()), &["node-1"]);
    let out = cluster(&served, &["delete-volume", "master", "node-typo", "--yes"]);

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("'node-typo' is not admitted"),
        "the typo belongs named: '{text}'"
    );
    assert!(
        text.contains("node remove node-typo"),
        "and the way out with it: '{text}'"
    );

    // It is sent anyway: the projection is eventual and node-local, a missing
    // name can be mere lag.
    assert_eq!(
        served.seen.lock().expect("commands").len(),
        1,
        "warned and not refused"
    );
}

/// **And an admitted node stays quiet.**
///
/// The counter-check to the witness above: without it a tool that warns at
/// every deletion would be green too — and a warning that always appears an
/// operator learns to read past, of all things at this system's most
/// destructive command (ADR-0027).
#[tokio::test(flavor = "multi_thread")]
async fn deleting_on_an_admitted_node_stays_quiet() {
    let served = serve_admitted(1, applied(Vec::new()), &["node-1"]);
    let out = cluster(&served, &["delete-volume", "master", "node-1", "--yes"]);

    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        !text.contains("is not admitted"),
        "an admitted node is no finding: '{text}'"
    );
}

/// A **partly** placed declaration says so — with the denominator and the
/// numbers that have no node (ADR-0011, ADR-0034).
///
/// That is the case the line could not show before: at `replicas="6"` on five
/// racks five node names stand there, and `nowhere` appears only when **none at
/// all** is placed. An operator had to count — against a number that stands in
/// the definition and that the view did not name.
///
/// The counter-direction carries it: a **completely** placed workload names no
/// missing numbers. Without it an output that always reports a gap would be
/// just as green — and an operator would learn to read past the line.
#[tokio::test(flavor = "multi_thread")]
async fn a_partly_placed_workload_names_the_instances_without_a_node() {
    let mut api = projected("api", vec![(0, "running")]);
    api.replicas = 6;
    api.placed = (0..5).map(|n| (n, format!("node-{}", n + 1))).collect();

    let mut ledger = projected("ledger", vec![(0, "running")]);
    ledger.replicas = 2;
    ledger.placed = vec![(0, "node-1".to_owned()), (1, "node-2".to_owned())];

    let served = serve_showing(1, applied(Vec::new()), vec![api, ledger]);
    let output = cluster(&served, &["show"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "show must succeed: {text}");

    assert!(
        text.contains("placed:     5/6"),
        "the denominator is missing: {text}"
    );
    assert!(
        text.contains("without a node: 5"),
        "the missing instance number is missing — it is the setting with which \
         an operator looks into the log: {text}"
    );

    // The counter-direction: complete means without an addition.
    let complete: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("placed:     2/2"))
        .collect();
    assert_eq!(
        complete.len(),
        1,
        "'ledger' must be reported as complete: {text}"
    );
    assert!(
        !complete[0].contains("without a node"),
        "a completely placed workload names no missing ones: {text}"
    );
}
