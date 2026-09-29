//! The telemetry endpoint at the running `tgd` (ADR-0015).
//!
//! The probes are checked individually in `tg-telemetry`. What was missing here is
//! the seam: that a **real** node fills them with real Raft metrics and hands them
//! out over HTTP. Queried with `curl` -- foreign code, the same yardstick as `dig`
//! in phase 9c.
//!
//! The test that matters is the last one: **a node without a quorum is not ready
//! and nevertheless alive** (ADR-0019). Here it is produced with a single process
//! that knows four counter-nodes that do not exist -- exactly the situation on the
//! minority side of a partition.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

mod support;

/// A node that is ended when it falls.
struct Node {
    child: Child,
    telemetry: u16,
    dir: tempfile::TempDir,
}

impl Node {
    /// This node's data directory.
    ///
    /// The field was called `_dir` -- "only held" -- until this test really needed
    /// it. An underscore one does read after all is a claim that no longer
    /// holds.
    fn data_dir(&self) -> &std::path::Path {
        self.dir.path()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn curl(url: &str) -> (u16, String) {
    let out = Command::new("curl")
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
        .expect("call curl");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (code.trim().parse().unwrap_or(0), body.to_owned())
}

/// Starts `tgd` with `peers` counter-nodes, of which only the first really
/// exists.
fn start(peers: u64, init: bool) -> Node {
    start_exporting(peers, init, None)
}

/// The same, and with `--otlp-endpoint` on `collector`.
fn start_exporting(peers: u64, init: bool, collector: Option<u16>) -> Node {
    let dir = tempfile::tempdir().expect("tempdir");
    let raft = support::free_port();
    let cluster = support::free_port();
    let telemetry = support::free_port();

    let mut command = Command::new(env!("CARGO_BIN_EXE_tgd"));
    command
        .arg("--id")
        .arg("1")
        // Expressly, so that the witness can assert on the global label:
        // without the setting `tgd` takes the first label of the hostname, and
        // the machine does not belong to us.
        .arg("--node")
        .arg("tgd-1")
        .arg("--listen")
        .arg(format!("127.0.0.1:{raft}"))
        .arg("--cluster-listen")
        .arg(format!("127.0.0.1:{cluster}"))
        .arg("--node-listen")
        .arg(format!("127.0.0.1:{}", support::free_port()))
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--telemetry-addr")
        .arg(format!("127.0.0.1:{telemetry}"))
        // `--peer` has pointed at the **cluster** port since ADR-0043: Raft lies
        // there, no longer on `--listen`.
        .arg("--peer")
        .arg(format!("1=http://127.0.0.1:{cluster}"));

    // The remaining counter-nodes get free ports on which nothing listens. That is
    // the minority side of a partition, staged with a single process.
    for id in 2..=peers {
        command
            .arg("--peer")
            .arg(format!("{id}=http://127.0.0.1:{}", support::free_port()));
    }
    if init {
        command.arg("--init");
    }
    if let Some(port) = collector {
        command
            .arg("--otlp-endpoint")
            .arg(format!("http://127.0.0.1:{port}"));
    }

    let child = command
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    Node {
        child,
        telemetry,
        dir,
    }
}

/// Waits until `/livez` answers -- the endpoint needs a moment.
fn await_endpoint(node: &Node) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if curl(&format!("http://127.0.0.1:{}/livez", node.telemetry)).0 != 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the telemetry endpoint did not come up");
}

/// Waits until `/readyz` delivers the expected code.
fn await_readiness(node: &Node, want: u16) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (code, body) = curl(&format!("http://127.0.0.1:{}/readyz", node.telemetry));
        if code == want {
            return body;
        }
        last = format!("{code}: {body}");
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("/readyz did not become {want}, last {last}");
}

/// A one-node cluster becomes ready -- and `/metrics` prints what the apply path
/// counted.
#[test]
fn a_healthy_node_becomes_ready_and_reports_metrics() {
    let node = start(1, true);
    await_endpoint(&node);

    let body = await_readiness(&node, 200);
    assert!(body.contains("raft: ready"), "{body}");

    let (code, metrics) = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry));
    assert_eq!(code, 200);
    // The node **name** stands as a global label on every metric -- and **only**
    // it, per the cardinality rule from `tg_telemetry::names`.
    //
    // Here once stood `node="1"`, that is, the **Raft identifier**, while the
    // comment above spoke of the name: `tgd` passed `options.id.to_string()`.
    // Measured, the same label thereby carried three meanings in three processes
    // -- identifier, node name, workload --, and an alarm text
    // `{{ $labels.node }}` named something different per process.
    //
    // And the second arm was `|| metrics.is_empty()`: measured, the endpoint
    // answers with `200` and a body, so it was dead and covered the assertion.
    assert!(
        metrics.contains("node=\"tgd-1\""),
        "unexpected output: {metrics}"
    );
    assert!(
        !metrics.contains("node=\"1\""),
        "the Raft identifier does not belong in this label: {metrics}"
    );
}

/// **The test that matters (ADR-0019).**
///
/// A node whose four counter-nodes do not answer has no quorum. It reports
/// `/readyz` as `503` -- and `/livez` stays `200`.
///
/// If the liveness tipped along with it, a prober on the minority side of a
/// partition would restart every node, and the running containers would go with
/// them. ADR-0019 says about that: "Running containers are **never** stopped
/// because of quorum loss."
#[test]
fn a_node_without_quorum_is_unready_but_stays_alive() {
    let node = start(5, true);
    await_endpoint(&node);

    let body = await_readiness(&node, 503);

    // **`no leader`, not `no quorum`** -- and that is measured, not chosen:
    // twelve queries over five seconds always yielded `raft: not ready: no
    // leader`. A node without a majority never becomes leader, and `verdict`
    // checks the leadership **first**; the quorum line is only reachable once one
    // is there and the majority falls away afterwards. It has its own witness as a
    // pure function (`health::tests::without_a_quorum_a_leader_is_not_ready`).
    //
    // Previously `contains("no quorum") || contains("no leader")` stood here,
    // and that **covered** the difference: the test carried the name of the one
    // cause and checks the other.
    assert!(body.contains("no leader"), "the reason is missing: {body}");

    let (code, live) = curl(&format!("http://127.0.0.1:{}/livez", node.telemetry));
    assert_eq!(
        code, 200,
        "without a quorum the liveness must not tip (ADR-0019): {live}"
    );
}

/// **Who leads stands in a metric -- and who does not lead reports `0`.**
///
/// # Why it exists
///
/// A dozen metrics are set **only by the leader** (`tg_node_*`, `tg_cluster_*`,
/// `tg_scheduler_domain_*`), and with the gauge decay from ADR-0088 a **stepped
/// down** leader keeps its series for up to fifteen minutes -- frozen. Measured,
/// that hit three alarm rules with a `for:` duration below the decay window, and
/// the first one most sharply:
/// `time() - tg_node_last_report_timestamp_seconds > 60` becomes true on the
/// frozen series after a minute, for a node that reports flawlessly to the **new**
/// leader.
///
/// With `and on(instance) (tg_raft_leader == 1)` the foreign series falls away --
/// and for that the stepped-down one's `0` must stand there **immediately**. It
/// does, because the number arises in the **scrape** (ADR-0088) and not in a loop.
///
/// # Both directions, and the second one carries
///
/// A metric that always says `1` would pass the first half too -- and the linking
/// would be without effect, because exactly the stepped-down leader must not
/// report `1`. The node without a quorum is the load-bearing case for that:
/// **nobody** leads.
#[test]
fn the_leader_says_that_it_leads_and_the_others_say_zero() {
    // A node on its own elects itself -- without a round trip.
    let leader = start(1, true);
    await_endpoint(&leader);
    await_readiness(&leader, 200);

    let (_, body) = curl(&format!("http://127.0.0.1:{}/metrics", leader.telemetry));
    // **On the value and line by line**: that the name occurs somewhere says
    // nothing -- and the three rules hang on the `1`.
    assert!(
        body.lines()
            .any(|line| { line.starts_with("tg_raft_leader{") && line.trim_end().ends_with(" 1") }),
        "the leader does not report that it leads: {body}"
    );

    // **The counter-direction**: four unreachable counter-nodes, so nobody
    // leads.
    let lonely = start(5, true);
    await_endpoint(&lonely);
    await_readiness(&lonely, 503);

    let (_, body) = curl(&format!("http://127.0.0.1:{}/metrics", lonely.telemetry));
    assert!(
        body.lines()
            .any(|line| { line.starts_with("tg_raft_leader{") && line.trim_end().ends_with(" 0") }),
        "a node without leadership must report `0` -- otherwise the linking in \
         `alerts.yml` does not strike its stale series: {body}"
    );
}

/// The endpoint can be switched off, and then nothing listens there.
#[test]
fn the_endpoint_can_be_switched_off() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raft = support::free_port();
    let cluster = support::free_port();
    let telemetry = support::free_port();

    let mut child = Command::new(env!("CARGO_BIN_EXE_tgd"))
        .args([
            "--id",
            "1",
            "--listen",
            &format!("127.0.0.1:{raft}"),
            "--cluster-listen",
            &format!("127.0.0.1:{cluster}"),
            "--node-listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--data-dir",
            dir.path().to_str().expect("path"),
            "--peer",
            &format!("1=http://127.0.0.1:{raft}"),
            "--telemetry-addr",
            "off",
            "--init",
        ])
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    std::thread::sleep(Duration::from_secs(3));
    let reachable = std::net::TcpStream::connect(format!("127.0.0.1:{telemetry}")).is_ok();

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !reachable,
        "something listens on {telemetry} although 'off' applied"
    );
}

/// **The metric from ADR-0047 stands at the endpoint** -- and it says "no" before
/// anything fails.
///
/// A one-node cluster with one rack: if this rack fails, there is nothing outside
/// that would take up the load. Exactly that the metric is to report, **before**
/// the outage -- a `NoRoom` in the middle of it would come too late.
///
/// Only the leader sets it. Five nodes that all reported the same number would be
/// five sources for one fact.
#[test]
fn the_leader_reports_whether_a_domain_could_be_absorbed() {
    let node = start(1, true);
    await_endpoint(&node);
    await_readiness(&node, 200);

    // The client is built **inside** the runtime: `connect_unix` creates a lazy
    // channel, and `hyper` demands a running reactor for it. Built outside, it
    // panics -- and only here, not at its use.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let socket = tgd::admin::socket_path(node.data_dir(), 1);
    runtime.block_on(async {
        let client = tgd::admin::AdminClient::connect_unix(&socket).expect("client");
        let _ = client
            .write(tg_consensus::Command::UpsertNode {
                name: "lonely".to_owned(),
                topology: tg_consensus::Topology {
                    site: "fra".to_owned(),
                    hall: "h1".to_owned(),
                    rack: "r1".to_owned(),
                },
                capacity: tg_consensus::Resources::default()
                    .with(tg_consensus::Resources::CPU_MILLICORES, 4000),
                reserved: tg_consensus::Resources::default(),
                source: tg_consensus::Origin::Operator,
            })
            .await;
    });

    // The scheduler runs at its own cadence; the metric appears as soon as it has
    // been through once.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut metrics = String::new();
    while Instant::now() < deadline {
        metrics = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry)).1;
        if metrics.contains(tg_telemetry::names::DOMAIN_ABSORBS) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    assert!(
        metrics.contains(tg_telemetry::names::DOMAIN_ABSORBS),
        "the metric is missing at the endpoint: {metrics}"
    );
    assert!(
        metrics.contains("domain=\"fra/h1/r1\""),
        "the domain is missing as a label: {metrics}"
    );
}

/// **A detached node is reported** (ADR-0054).
///
/// Detach without attach is a trap: a node nobody brings back runs on unnoticed
/// without a mesh -- it takes nothing on, gives everything up and reports nothing
/// that would stand out. The metric decides nothing (ADR-0011), it shows.
///
/// One label per node and no sum: a `2` does not tell an operator whom to bring
/// back.
#[test]
fn the_leader_reports_a_detached_node() {
    let node = start(1, true);
    await_endpoint(&node);
    await_readiness(&node, 200);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let socket = tgd::admin::socket_path(node.data_dir(), 1);
    runtime.block_on(async {
        let client = tgd::admin::AdminClient::connect_unix(&socket).expect("client");
        let _ = client
            .write(tg_consensus::Command::UpsertNode {
                name: "detached-one".to_owned(),
                topology: tg_consensus::Topology {
                    site: "fra".to_owned(),
                    hall: "h1".to_owned(),
                    rack: "r9".to_owned(),
                },
                capacity: tg_consensus::Resources::default(),
                reserved: tg_consensus::Resources::default(),
                source: tg_consensus::Origin::Operator,
            })
            .await;
        let _ = client
            .write(tg_consensus::Command::SetAttachment {
                node: "detached-one".to_owned(),
                mode: tg_consensus::Attachment::Detached,
            })
            .await;
    });

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut metrics = String::new();
    while Instant::now() < deadline {
        metrics = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry)).1;
        if metrics.contains(tg_telemetry::names::NODE_ATTACHED) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    assert!(
        metrics.contains(tg_telemetry::names::NODE_ATTACHED),
        "the metric is missing at the endpoint: {metrics}"
    );
    // The **value** carries the statement: the metric alone would appear for an
    // attached node too.
    let line = metrics
        .lines()
        .find(|line| {
            line.starts_with(tg_telemetry::names::NODE_ATTACHED)
                && line.contains("node=\"detached-one\"")
        })
        .unwrap_or_else(|| panic!("no line for the node: {metrics}"));

    assert!(
        line.ends_with(" 0"),
        "the detached node is reported as attached: {line}"
    );
}

/// **A node without a report does not appear** (ADR-0055, determination 5).
///
/// "Nothing heard yet" and "carries generation zero" are two statements; only the
/// second justifies a number. A `0` for a mute node would be the more dangerous
/// lie -- it would look caught up without anybody having heard from it.
///
/// The test decrees a rotation for a node that **never** sends a report (no agent
/// is running) and demands that the metric stays silent.
#[test]
fn a_node_that_never_reported_gets_no_lag() {
    let node = start(1, true);
    await_endpoint(&node);
    await_readiness(&node, 200);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let socket = tgd::admin::socket_path(node.data_dir(), 1);
    runtime.block_on(async {
        let client = tgd::admin::AdminClient::connect_unix(&socket).expect("client");
        // Admission instead of inventory: the rotation hangs on it (ADR-0037).
        for command in [
            tg_consensus::Command::InviteNode {
                node: "mute-one".to_owned(),
                digest: tg_consensus::token_digest("whatever"),
                expires_at: 4_000_000_000,
            },
            tg_consensus::Command::AdmitNode {
                node: "mute-one".to_owned(),
                spki: "AAAA".to_owned(),
                at: 1,
            },
            // Inventory **too**, and that makes the test stricter: the node is
            // there in every respect -- only nobody has heard from it. It is at
            // the same time the proof that the scheduler was through
            // (`tg_node_attached` applies only to entered nodes).
            tg_consensus::Command::UpsertNode {
                name: "mute-one".to_owned(),
                topology: tg_consensus::Topology {
                    site: "fra".to_owned(),
                    hall: "h1".to_owned(),
                    rack: "r5".to_owned(),
                },
                capacity: tg_consensus::Resources::default(),
                reserved: tg_consensus::Resources::default(),
                source: tg_consensus::Origin::Operator,
            },
            tg_consensus::Command::SetKeyGeneration {
                node: "mute-one".to_owned(),
                kind: tg_consensus::KeyKind::Underlay,
                generation: 3,
            },
        ] {
            // **The outcome is checked**, not discarded (ADR-0045).
            let written = client.write(command).await.expect("write");
            assert!(
                matches!(
                    written,
                    tgd::admin::WriteResult::Applied {
                        outcome: tg_consensus::Outcome::Applied,
                        ..
                    }
                ),
                "setup command refused: {written:?}"
            );
        }
    });

    // Give the scheduler time to run through once -- the other metrics appear in
    // the process, this one precisely must not.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut metrics = String::new();
    while Instant::now() < deadline {
        metrics = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry)).1;
        if metrics.contains(tg_telemetry::names::NODE_ATTACHED) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    assert!(
        metrics.contains(tg_telemetry::names::NODE_ATTACHED),
        "the scheduler was not through -- then the test below says nothing: {metrics}"
    );
    assert!(
        !metrics.contains(tg_telemetry::names::KEY_GENERATION_LAG),
        "a mute node appears with a backlog although nobody has heard from it: \
         {metrics}"
    );
}

/// **The numbers behind the verdict stand at the endpoint** (ADR-0047,
/// determination 3).
///
/// `absorbs` is a bit, and a bit has no "almost": it jumps at the moment at which
/// the reserve is already used up. The alarm the ADR demands -- **before** it gets
/// tight -- could not be written with that at all. It needs `elsewhere / at_risk`,
/// that is, both sets.
///
/// Two racks so that anything lies outside at all: with a single one both sides
/// would be empty and there would be nothing to report.
///
/// What is checked is **line by line**: that the name occurs somewhere in the
/// document says nothing about the labels, and the union of the name sets is
/// exactly the assurance at issue here.
#[test]
fn the_leader_reports_the_numbers_behind_the_verdict() {
    let node = start(1, true);
    await_endpoint(&node);
    await_readiness(&node, 200);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let socket = tgd::admin::socket_path(node.data_dir(), 1);
    runtime.block_on(async {
        let client = tgd::admin::AdminClient::connect_unix(&socket).expect("client");
        for (name, rack) in [("a", "r1"), ("b", "r2")] {
            let _ = client
                .write(tg_consensus::Command::UpsertNode {
                    name: name.to_owned(),
                    topology: tg_consensus::Topology {
                        site: "fra".to_owned(),
                        hall: "h1".to_owned(),
                        rack: rack.to_owned(),
                    },
                    capacity: tg_consensus::Resources::default()
                        .with(tg_consensus::Resources::CPU_MILLICORES, 4000),
                    reserved: tg_consensus::Resources::default(),
                    source: tg_consensus::Origin::Operator,
                })
                .await;
        }
    });

    // The line that matters: the same domain, the same resource -- on **both**
    // metrics.
    let line = |text: &str, metric: &str| -> Option<String> {
        text.lines()
            .find(|l| {
                l.starts_with(metric)
                    && l.contains("domain=\"fra/h1/r1\"")
                    && l.contains("resource=\"cpu-millicores\"")
            })
            .map(str::to_owned)
    };

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut metrics = String::new();
    while Instant::now() < deadline {
        metrics = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry)).1;
        if line(&metrics, tg_telemetry::names::DOMAIN_ELSEWHERE).is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let elsewhere = line(&metrics, tg_telemetry::names::DOMAIN_ELSEWHERE).unwrap_or_else(|| {
        panic!("the free capacity is missing at the endpoint: {metrics}");
    });
    let at_risk = line(&metrics, tg_telemetry::names::DOMAIN_AT_RISK).unwrap_or_else(|| {
        panic!("the counter-number is missing -- without it there is no ratio: {metrics}");
    });

    // Outside r1 lies exactly the other node, and that one is empty.
    assert!(
        elsewhere.ends_with(" 4000"),
        "expected are b's free millicores: {elsewhere}"
    );
    // And in r1 nothing runs -- which the line must nevertheless say instead of
    // being missing.
    assert!(
        at_risk.ends_with(" 0"),
        "nothing runs in r1, the line nevertheless belongs there: {at_risk}"
    );
}

/// **The scheduler loop stands under the watchdog** (ADR-0015, ADR-0064).
///
/// It writes the placements, **renews the active-role leases** and runs the
/// capacity and rotation policy. Until here the watchdog watched only the Raft
/// loop: if the scheduler task dies, **every single writer in the cluster** fences
/// itself within fifteen seconds -- and liveness as well as readiness stayed green,
/// because Raft is working after all. The metrics beside it froze on their last,
/// healthy-looking values.
///
/// The same argument as in 11b for the agent: *a loop that stands still does not
/// report -- it also does not report that it is unwell.*
///
/// **And ADR-0019 stays untouched:** the loop wakes unconditionally every
/// `LEASE_TICK`, independently of leadership and quorum. The neighbouring test
/// records that a node without a quorum stays alive.
#[test]
fn the_scheduler_loop_is_under_the_watchdog() {
    let node = start(1, true);
    await_endpoint(&node);
    await_readiness(&node, 200);

    // **On the idle time, not on the name.** This test's first attempt checked
    // whether `scheduler:` stands in the output -- and the registration happens in
    // `health::spawn`, not in the loop. It stayed green when the beat was removed.
    // Measured, only the number behind it separates: `0s` with a beat, `4s`
    // without.
    //
    // Wait first, so that a dead loop visibly falls behind; then sample for a round
    // and demand **one** fresh value. A single delayed pass under load does not tip
    // that -- one sign of life in the whole window suffices --, and a dead loop can
    // deliver none, because its number only grows.
    std::thread::sleep(std::time::Duration::from_secs(8));

    let mut seen = Vec::new();
    for _ in 0..6 {
        let (code, live) = curl(&format!("http://127.0.0.1:{}/livez", node.telemetry));
        assert_eq!(code, 200, "{live}");
        assert!(live.contains("raft:"), "{live}");

        let idle = idle_seconds(&live, "scheduler")
            .unwrap_or_else(|| panic!("the scheduler loop is not registered: {live}"));
        if idle <= 5 {
            return;
        }
        seen.push(idle);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    panic!("the scheduler loop does not beat the watchdog: {seen:?}");
}

/// How long an observation in the liveness body has already been silent.
///
/// The line reads `name: Ns` in the green case -- and carries a sentence in the red
/// one. `None` means "not registered", and that is a different finding from
/// "registered and silent".
fn idle_seconds(body: &str, name: &str) -> Option<u64> {
    let line = body
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))?;

    // In the red case a sentence stands there -- then the watchdog is already
    // struck anyway, and any large number will do.
    Some(
        line.strip_suffix('s')
            .and_then(|n| n.parse().ok())
            .unwrap_or(u64::MAX),
    )
}

/// **How full the address space is stands at the endpoint** (ADR-0069).
///
/// The boundary has bitten since ADR-0069: where no subnet is free any more, no
/// node is admitted any more. Without these two numbers an operator noticed it at
/// the **first rejection** -- that is, when they need the node.
///
/// What is checked are the **values**, not the presence of the lines: a cluster
/// that reports any old number tells an operator nothing. And the counter-check
/// stands in the same test: **before** the address plan neither of the two appears
/// -- an invented capacity would report a full cluster where merely nothing is
/// set.
#[test]
fn the_leader_reports_how_full_the_address_space_is() {
    let node = start(1, true);
    await_endpoint(&node);
    await_readiness(&node, 200);

    let (_, before) = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry));
    assert!(
        !before.contains(tg_telemetry::names::CLUSTER_ORDINALS_CAPACITY),
        "without an address plan no capacity may be reported: {before}"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let socket = tgd::admin::socket_path(node.data_dir(), 1);
    runtime.block_on(async {
        let client = tgd::admin::AdminClient::connect_unix(&socket).expect("client");
        // /24 with /25 per node: exactly two subnets, and none assigned.
        let _ = client
            .write(tg_consensus::Command::SetClusterNetwork {
                cidr: "10.42.0.0/24".to_owned(),
                node_prefix: 25,
            })
            .await;
    });

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut metrics = String::new();
    while Instant::now() < deadline {
        metrics = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry)).1;
        if metrics.contains(tg_telemetry::names::CLUSTER_ORDINALS_CAPACITY) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let value_of = |name: &str| {
        metrics
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.rsplit(' ').next().map(str::to_owned))
            .unwrap_or_else(|| panic!("no line for {name}: {metrics}"))
    };

    assert_eq!(
        value_of(tg_telemetry::names::CLUSTER_ORDINALS_CAPACITY),
        "2",
        "{metrics}"
    );
    assert_eq!(
        value_of(tg_telemetry::names::CLUSTER_ORDINALS_USED),
        "0",
        "{metrics}"
    );
}

/// **The per-node settings whose skew would otherwise be invisible** (ADR-0059,
/// ADR-0013, ADR-0091).
///
/// Three metrics with the same shape: `--proxy-image`, `--dns-domain` and
/// `--userns-base` expressly stay settings **per node**, so that a rolling update
/// stays one action per node. The price stands in ADR-0059: *"an accidental
/// deviation [is] invisible."* Exactly that the report fixes -- and `1` means
/// uniform, everything above it is a skew.
///
/// **What is checked is the value and not the presence of the line.** A line with
/// any old number tells an operator nothing; and the proxy-image counter had no
/// witness at all until here -- built, checked only at the projection, never seen
/// at the endpoint.
///
/// A one-node cluster without a session reports **nothing**, so the expected value
/// is `0`: nobody has reported. That it becomes a `2` with two different reports
/// is substantiated at the projection (`tg-store/tests/projection.rs`) -- here it
/// is about the way onto the wire.
#[test]
fn the_per_node_divergences_reach_the_endpoint() {
    let node = start(1, true);
    await_endpoint(&node);
    let _ = await_readiness(&node, 200);

    // The scheduler cadence writes them; without log movement it waits up to
    // `LEASE_TICK`. Therefore with patience instead of with a single grab.
    let mut metrics = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        metrics = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry)).1;
        if metrics.contains("tg_cluster_dns_zones") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    for name in [
        "tg_cluster_proxy_images",
        "tg_cluster_dns_zones",
        // And the security posture (ADR-0091). It counts the **posture** and not
        // the range -- different ranges are no error --, but the way onto the wire
        // is the same.
        "tg_cluster_userns_postures",
    ] {
        let line = metrics
            .lines()
            .find(|line| line.starts_with(name) && !line.starts_with(&format!("# {name}")))
            .unwrap_or_else(|| panic!("{name} does not stand at the endpoint:\n{metrics}"));
        assert!(
            line.ends_with(" 0"),
            "without a node's report the number must be 0: {line}"
        );
    }
}

/// **A voter without an address is reported** (ADR-0005).
///
/// # What was already checked, and what was not
///
/// At **creation** `options` has long checked it: `--init-voters` with an
/// identifier without a `--peer` address is refused ("a member whose address
/// nobody knows is a node the cluster counts along and never reaches"). And since
/// the step before it the **leader** refuses a membership change when *its* list
/// does not know the node.
///
/// What stayed uncovered is the situation in between: the membership stands in the
/// **log**, the address in **every** process's configuration. Whoever admits a
/// node and forgets the configuration on one of the others notices nothing -- until
/// exactly that one takes over the leadership and cannot replicate to the peer.
///
/// # The setup
///
/// A node creates a membership `{1,2}`, with both addresses. Then it restarts --
/// with only **one**. Its log knows two voters, its list one: exactly the
/// forgotten entry.
#[test]
fn a_voter_without_an_address_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cluster = support::free_port();
    let absent = support::free_port();

    // First start: the membership arises, both addresses are there.
    let mut first = Command::new(env!("CARGO_BIN_EXE_tgd"))
        .arg("--id")
        .arg("1")
        .arg("--node")
        .arg("tgd-1")
        .arg("--listen")
        .arg(format!("127.0.0.1:{}", support::free_port()))
        .arg("--cluster-listen")
        .arg(format!("127.0.0.1:{cluster}"))
        .arg("--node-listen")
        .arg(format!("127.0.0.1:{}", support::free_port()))
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--telemetry-addr")
        .arg("off")
        .arg("--peer")
        .arg(format!("1=http://127.0.0.1:{cluster}"))
        .arg("--peer")
        .arg(format!("2=http://127.0.0.1:{absent}"))
        .arg("--init")
        .arg("--init-voters")
        .arg("1,2")
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    // Wait until the membership stands in the log -- otherwise the second process
    // starts with an empty state, and the test checks nothing.
    let deadline = Instant::now() + Duration::from_secs(20);
    let socket = tgd::admin::socket_path(dir.path(), 1);
    while Instant::now() < deadline && !socket.exists() {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(1));
    let _ = first.kill();
    let _ = first.wait();

    // Second start: **only its own address.** That is the forgotten entry.
    let telemetry = support::free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_tgd"))
        .arg("--id")
        .arg("1")
        .arg("--node")
        .arg("tgd-1")
        .arg("--listen")
        .arg(format!("127.0.0.1:{}", support::free_port()))
        .arg("--cluster-listen")
        .arg(format!("127.0.0.1:{cluster}"))
        .arg("--node-listen")
        .arg(format!("127.0.0.1:{}", support::free_port()))
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--telemetry-addr")
        .arg(format!("127.0.0.1:{telemetry}"))
        .arg("--peer")
        .arg(format!("1=http://127.0.0.1:{cluster}"))
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");

    let node = Node {
        child,
        telemetry,
        dir,
    };
    await_endpoint(&node);

    // What is checked is the **value**, not the presence of the line: a metric
    // that carries any old number tells an operator nothing.
    let mut seen = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let (_, body) = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry));
        seen = body;
        if seen.lines().any(|line| {
            line.starts_with(tg_telemetry::names::PEERS_MISSING) && line.ends_with(" 1")
        }) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    panic!("no reported shortfall:\n{seen}");
}

/// **The supervised task appears at the endpoint and in the readiness.**
///
/// Since ADR-0082 a panic costs its task and not the node -- and with that a
/// process arises that carries on and no longer does something. The tracking of the
/// projection is this binary's case: it stands in no `select!` (ADR-0031), has no
/// watchdog (it wakes only on log movement, a time watchdog would strike falsely in
/// a quiet cluster) -- and until here its death could only be seen from
/// `last_applied` ceasing to grow in an answer.
///
/// What is checked are the **value** and the **label**, not the presence of the
/// name: a line with any old number tells an operator nothing, and one without a
/// label does not say which task is alive.
#[test]
fn the_projection_task_is_supervised() {
    let node = start(1, true);
    await_endpoint(&node);

    let body = await_readiness(&node, 200);
    assert!(
        body.contains("projection: ready"),
        "the tracking must register as a subtask: {body}"
    );

    let (code, metrics) = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry));
    assert_eq!(code, 200);
    let alive = tg_telemetry::names::TASK_ALIVE;
    assert!(
        metrics.lines().any(|line| {
            line.starts_with(alive) && line.contains("task=\"projection\"") && line.ends_with(" 1")
        }),
        "`{alive}` is missing for the tracking or does not stand at 1: {metrics}"
    );
}

/// **The tombstones are countable** (ADR-0042).
///
/// # Why this number
///
/// A volume tombstone arises with `DeleteVolume` and disappears **only** when the
/// same volume is declared again. It is thereby the only collection in the
/// replicated state that grows without anything clearing it away -- and it travels
/// in **every snapshot** to every node that catches up.
///
/// The number decides nothing. It makes measurable what ADR-0042 names as open:
/// the **retention period** couples to ADR-0020 and is not decided. Without it the
/// question could not even be asked.
///
/// **Both directions**, and the first carries half the assurance: without a
/// deletion a `0` stands there. A number that appears only on a finding cannot be
/// distinguished from a missing one.
#[test]
fn the_tombstones_are_countable() {
    let node = start(1, true);
    await_endpoint(&node);
    let _ = await_readiness(&node, 200);

    let read = |node: &Node| -> String {
        let mut metrics = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            metrics = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry)).1;
            if metrics.contains("tg_cluster_volume_tombstones") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        metrics
            .lines()
            .find(|line| line.starts_with("tg_cluster_volume_tombstones{"))
            .unwrap_or_else(|| {
                panic!("tg_cluster_volume_tombstones does not stand at the endpoint:\n{metrics}")
            })
            .to_owned()
    };

    let line = read(&node);
    assert!(
        line.ends_with(" 0"),
        "without a deletion a zero belongs there: {line}"
    );

    // Two deletions, and the number follows.
    let socket = tgd::admin::socket_path(node.data_dir(), 1);
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    // **The client arises in the runtime**: `connect_unix` builds a `hyper`
    // channel, and that demands a running reactor. Outside it panics in
    // `hyper-util` -- an error that looks like a server problem and is none.
    let guard = runtime.enter();
    let client = tgd::admin::AdminClient::connect_unix(&socket).expect("client");
    drop(guard);
    for volume in ["old", "archive"] {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            assert!(std::time::Instant::now() < deadline, "nothing accepted");
            let outcome = runtime.block_on(client.write(tg_consensus::Command::DeleteVolume {
                volume: volume.to_owned(),
                node: "node-9".to_owned(),
                at: 1_800_000_000,
            }));
            // The **outcome**, not the variant (ADR-0045).
            if let Ok(tgd::admin::WriteResult::Applied {
                outcome: tg_consensus::Outcome::Applied,
                ..
            }) = outcome
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let line = read(&node);
        if line.ends_with(" 2") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the tombstones were not counted: {line}"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// **The data key's fingerprint is reported** (ADR-0095).
///
/// Two `tgd` with different keys do not otherwise stand out: measured, **all**
/// agents get the leader's (ADR-0077), a follower with a wrong one looks uniform
/// from outside -- and strikes only at the leader change. Counting happens in the
/// alarm rule over the instances.
///
/// What is checked is the **value of the label**, not the presence of the line: a
/// metric with any old fingerprint tells an operator nothing.
///
/// And the counter-direction stands beside it: **without a key no time series**. An
/// invented one would be the more dangerous lie -- it would look like agreement.
#[test]
fn the_data_key_fingerprint_is_reported() {
    // First without a key: the line must not appear.
    let bare = start(1, true);
    await_endpoint(&bare);
    let (code, metrics) = curl(&format!("http://127.0.0.1:{}/metrics", bare.telemetry));
    assert_eq!(code, 200, "{metrics}");
    assert!(
        !metrics.contains(tg_telemetry::names::DATA_KEY),
        "without a data key no time series may arise: {metrics}"
    );
    drop(bare);

    // And with one: the fingerprint stands in the label.
    let node = start(1, true);
    let key = tg_identity::secrets::DataKey::generate().expect("key");
    let identity = node.dir.path().join("identity");
    std::fs::create_dir_all(&identity).expect("identity/");
    std::fs::write(identity.join("secrets.key"), key.to_base64()).expect("file");
    drop(node);

    // The key is read at **startup**, so a second process on the same directory
    // is needed. A restart is cheaper here than a seam that would exist only for
    // the test.
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = dir.path().join("identity");
    std::fs::create_dir_all(&identity).expect("identity/");
    std::fs::write(identity.join("secrets.key"), key.to_base64()).expect("file");

    let telemetry = support::free_port();
    let cluster = support::free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_tgd"))
        .args([
            "--id",
            "1",
            "--listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--cluster-listen",
            &format!("127.0.0.1:{cluster}"),
            "--node-listen",
            &format!("127.0.0.1:{}", support::free_port()),
            "--data-dir",
            dir.path().to_str().expect("path"),
            "--telemetry-addr",
            &format!("127.0.0.1:{telemetry}"),
            "--peer",
            &format!("1=http://127.0.0.1:{cluster}"),
            "--init",
        ])
        .stdout(support::log("tgd"))
        .stderr(support::log("tgd"))
        .spawn()
        .expect("tgd startable");
    let node = Node {
        child,
        telemetry,
        dir,
    };
    await_endpoint(&node);

    let (code, metrics) = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry));
    assert_eq!(code, 200, "{metrics}");
    let want = format!("fingerprint=\"{}\"", key.fingerprint());
    assert!(
        metrics
            .lines()
            .any(|line| line.starts_with(tg_telemetry::names::DATA_KEY) && line.contains(&want)),
        "the fingerprint is missing or is a different one ({want}): {metrics}"
    );
}

/// **The protocol version stands at the endpoint** -- the only piece of
/// information that survives a format skew.
///
/// # Why it exists
///
/// A format change is no rolling update (ADR-0072, determination 3): the manual
/// names a maintenance window with an order -- all `tgd`, then all `tg-agent`. The
/// question in the middle of it reads **"am I done?"**, and it was not answerable:
/// in this window every agent is silent, so a forgotten one looks like a waiting
/// one.
///
/// And every piece of information that ran over the **session** would be exactly
/// the one the skew breaks.
///
/// # What is checked is the value, not the line
///
/// The number **is** the statement; a line with any old number tells an operator
/// nothing. And it must be the same one the manual guard counts -- two sources for
/// one version would be two versions.
#[test]
fn the_protocol_version_stands_at_the_endpoint() {
    let leader = start(1, true);
    await_endpoint(&leader);

    let (_, body) = curl(&format!("http://127.0.0.1:{}/metrics", leader.telemetry));
    let name = tg_telemetry::names::PROTOCOL_FIELDS;
    let expected = format!(" {}", tg_store::session::PROTOCOL_FIELDS);

    assert!(
        body.lines()
            .any(|line| line.starts_with(name) && line.trim_end().ends_with(&expected)),
        "`{name}` is missing or does not carry the counted version ({}) -- \
         without it a forgotten node in the maintenance window cannot be \
         distinguished from a waiting one: {body}",
        tg_store::session::PROTOCOL_FIELDS
    );
}

/// **How full a node is stands at the endpoint** (ADR-0127).
///
/// # The finding
///
/// The pressure from ADR-0109 was computed at every placement -- and thrown away.
/// How close a cluster is to its boundary nobody reported (ADR-0069): the first
/// signal was `tg_scheduler_unplaceable`, that is, a failed placement. A node at
/// 99 % said the same as one at 1 %: nothing.
///
/// # What is checked here
///
/// A node with 4000 millicores, of which **2000 reserved** (ADR-0047), and a
/// workload that demands 500: the pressure must be **0.25** -- 500 of 2000
/// plannable -- and not 0.125. Exactly that is the assurance, and it has two
/// halves:
///
/// - a number **between** empty and full, for both edges the system reported
///   before;
/// - computed over the **plannable** capacity. Taking the raw one would yield
///   0.125, that is, a number smaller than the truth -- exactly in the direction
///   that reassures.
///
/// The reserve is therefore not zero: with zero both denominators would be equal,
/// and this witness could not see the second half. Measured -- the first attempt
/// was written with an empty reserve and stayed green when the counter-check
/// replaced the plannable capacity with the raw one.
///
/// And `tg_node_free` beside it, because the pressure does not name the scarcest
/// resource by name.
#[test]
fn the_leader_reports_how_full_a_node_is() {
    const DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"api\" kind=\"service\">\n\
         <image reference=\"registry.invalid/api:1\"/>\n\
         <resources><cpu millicores=\"500\"/></resources>\n\
         </workload>\n\
         </workloads>\n";

    let node = start(1, true);
    await_endpoint(&node);
    await_readiness(&node, 200);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let socket = tgd::admin::socket_path(node.data_dir(), 1);
    runtime.block_on(async {
        let client = tgd::admin::AdminClient::connect_unix(&socket).expect("client");
        let _ = client
            .write(tg_consensus::Command::UpsertNode {
                name: "a".to_owned(),
                topology: tg_consensus::Topology {
                    site: "fra".to_owned(),
                    hall: "h1".to_owned(),
                    rack: "r1".to_owned(),
                },
                capacity: tg_consensus::Resources::default()
                    .with(tg_consensus::Resources::CPU_MILLICORES, 4000),
                reserved: tg_consensus::Resources::default()
                    .with(tg_consensus::Resources::CPU_MILLICORES, 2000),
                source: tg_consensus::Origin::Operator,
            })
            .await;
        let _ = client
            .write(tg_consensus::Command::UpsertWorkload {
                document: DOCUMENT.to_owned(),
            })
            .await;
    });

    let line = |text: &str, metric: &str| -> Option<String> {
        text.lines()
            .find(|l| l.starts_with(metric) && l.contains("node=\"a\""))
            .map(str::to_owned)
    };

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut metrics = String::new();
    while Instant::now() < deadline {
        metrics = curl(&format!("http://127.0.0.1:{}/metrics", node.telemetry)).1;
        if line(&metrics, tg_telemetry::names::NODE_PRESSURE).is_some_and(|l| !l.ends_with(" 0")) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let pressure = line(&metrics, tg_telemetry::names::NODE_PRESSURE).unwrap_or_else(|| {
        panic!("the pressure is missing at the endpoint: {metrics}");
    });
    assert!(
        pressure.ends_with(" 0.25"),
        "500 of 2000 **plannable** millicores are 0.25 -- over the raw capacity \
         it would be 0.125, that is, less than the truth: {pressure}"
    );

    let free = metrics
        .lines()
        .find(|l| {
            l.starts_with(tg_telemetry::names::NODE_FREE)
                && l.contains("node=\"a\"")
                && l.contains("resource=\"cpu-millicores\"")
        })
        .unwrap_or_else(|| panic!("the free room is missing: {metrics}"));
    assert!(
        free.ends_with(" 1500"),
        "the pressure does not name the scarcest resource by name -- this line \
         is there for that: {free}"
    );
}

/// **What the audit archive occupies stands at the endpoint** (ADR-0132,
/// determination 1).
///
/// # The finding
///
/// Nothing is deleted here, and that is right: what lies there is evidence nobody
/// has yet pushed into the WORM archive (ADR-0020, ADR-0104). But nobody reported
/// it either -- the first signal was an `apply` that could no longer write, and
/// that stops the node.
///
/// Measured, a record costs 414 bytes, and an active-role lease produces one every
/// 9.1 s per single writer: 1.34 GiB a year for **one** workload.
///
/// # What is checked here
///
/// That both numbers are there and that the bytes are **not zero** -- a running
/// node has applied, so something lies there. A line with any old value would be
/// no statement; one with zero would be the wrong one.
#[test]
fn the_archive_footprint_stands_at_the_endpoint() {
    let leader = start(1, true);
    await_endpoint(&leader);

    // **Apply first, then measure.** A freshly started node has applied only the
    // membership entry, and that is no command -- the archive is then an empty
    // file. Without this step the witness would prove that zero is reported, and a
    // number out of nowhere can do that too.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let socket = tgd::admin::socket_path(leader.data_dir(), 1);
    runtime.block_on(async {
        let client = tgd::admin::AdminClient::connect_unix(&socket).expect("client");
        let _ = client
            .write(tg_consensus::Command::SetClusterNetwork {
                cidr: "10.42.0.0/16".to_owned(),
                node_prefix: 24,
            })
            .await
            .expect("write");
    });

    let (_, body) = curl(&format!("http://127.0.0.1:{}/metrics", leader.telemetry));

    let bytes = body
        .lines()
        .find(|line| line.starts_with(tg_telemetry::names::AUDIT_BYTES))
        .unwrap_or_else(|| panic!("`tg_audit_bytes` is missing: {body}"));
    let value: f64 = bytes
        .rsplit(' ')
        .next()
        .and_then(|raw| raw.trim().parse().ok())
        .unwrap_or_else(|| panic!("no value in `{bytes}`"));
    assert!(
        value > 0.0,
        "a node that has applied occupies nothing? Then the number reads at the \
         wrong place: `{bytes}`"
    );

    assert!(
        body.lines()
            .any(|line| line.starts_with(tg_telemetry::names::AUDIT_SEGMENTS)),
        "`tg_audit_segments` is missing -- and with it the number that says how \
         much an operator can push away: {body}"
    );
}

/// **Spans leave the process** (ADR-0133).
///
/// # The finding
///
/// `--otlp-endpoint` killed **all three** binaries at startup:
///
/// ```text
/// thread 'main' panicked at hyper-util/src/rt/tokio.rs:115:
/// there is no reactor running, must be called from the context of a Tokio 1.x runtime
/// ```
///
/// The exporter builds a hyper channel, and `init` ran before `runtime.block_on`.
/// No test covered that -- the setting occurred in none.
///
/// And even repaired it would have sent nothing: in the whole tree there was **not
/// a single span**. A byte-counting collector saw `CONNECTIONS=0 BYTES=0` over 25
/// seconds.
///
/// # What is checked here
///
/// Both, and in this order: the process lives, and it **sends**. The collector is a
/// raw TCP listener -- what arrives is OTLP over gRPC, and what is checked is
/// **that** something arrives, not what stands in it. A test that reconstructed the
/// protocol would check its own reconstruction.
#[test]
fn spans_leave_the_process() {
    use std::io::Read as _;

    let collector = std::net::TcpListener::bind("127.0.0.1:0").expect("collector");
    let port = collector.local_addr().expect("address").port();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let counted = std::sync::Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in collector.incoming() {
            let Ok(mut stream) = stream else { continue };
            let counted = std::sync::Arc::clone(&counted);
            std::thread::spawn(move || {
                let mut buffer = [0_u8; 8192];
                while let Ok(read) = stream.read(&mut buffer) {
                    if read == 0 {
                        return;
                    }
                    counted.fetch_add(read, std::sync::atomic::Ordering::Relaxed);
                }
            });
        }
    });

    let leader = start_exporting(1, true, Some(port));
    await_endpoint(&leader);

    // **A command first, then wait.** A node that has applied only the membership
    // entry produces no `apply` span -- and the witness would then prove that
    // nothing arrives when nothing happens.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let socket = tgd::admin::socket_path(leader.data_dir(), 1);
    runtime.block_on(async {
        let client = tgd::admin::AdminClient::connect_unix(&socket).expect("client");
        let _ = client
            .write(tg_consensus::Command::SetClusterNetwork {
                cidr: "10.42.0.0/16".to_owned(),
                node_prefix: 24,
            })
            .await
            .expect("write");
    });

    // The batch exporter sends after its deadline, not immediately.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while seen.load(std::sync::atomic::Ordering::Relaxed) == 0
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    assert!(
        seen.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "the collector got nothing -- either the process dies on the setting, or \
         there is no span to export (ADR-0133)"
    );
}
