//! The shared telemetry settings.
//!
//! They are evaluated by three binaries. What stands here therefore holds for
//! `tgd`, `tg-agent` and `tg-proxy` alike — that is the reason they lie in one
//! place.

use std::net::SocketAddr;

use tg_telemetry::args::Args;

/// Evaluates an invocation line the way the binaries do.
fn parse(argv: &[&str]) -> Result<Args, String> {
    let mut parsed = Args::with_port(7101);
    let mut rest = argv.iter();

    while let Some(flag) = rest.next() {
        let mut next = || -> Result<String, String> {
            rest.next()
                .map(|value| (*value).to_owned())
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        if !parsed.take(flag, &mut next)? {
            return Err(format!("unknown: {flag}"));
        }
    }

    Ok(parsed)
}

/// **The default is loopback.**
///
/// A metrics endpoint gives information about cluster size, node names and load
/// history. Opening it shall be an act, not an omission — just as with the Raft
/// port.
#[test]
fn the_default_address_is_loopback() {
    let args = Args::with_port(7101);

    assert_eq!(
        args.addr,
        Some("127.0.0.1:7101".parse::<SocketAddr>().expect("address"))
    );
}

/// Without a setting **nothing** is exported.
///
/// ADR-0019 in miniature: a node's observability must not hang on a collector
/// being reachable. The local endpoint stands independently of it.
#[test]
fn without_an_endpoint_nothing_is_exported() {
    assert_eq!(Args::default().otlp, None);
}

/// An address can be set.
#[test]
fn an_address_can_be_given() {
    let args = parse(&["--telemetry-addr", "0.0.0.0:9100"]).expect("readable");

    assert_eq!(args.addr, "0.0.0.0:9100".parse().ok());
}

/// **"off" switches it off**, without anyone having to invent an address.
///
/// Without this way an operator who does not want the telemetry would have to
/// name an address on which nothing listens — and would then stand there with a
/// port they did not want.
#[test]
fn the_endpoint_can_be_switched_off() {
    assert_eq!(
        parse(&["--telemetry-addr", "off"]).expect("readable").addr,
        None
    );
    assert_eq!(
        parse(&["--telemetry-addr", "-"]).expect("readable").addr,
        None
    );
}

/// An unusable address is an error with a name, not a silent default.
#[test]
fn an_unusable_address_names_itself() {
    let err = parse(&["--telemetry-addr", "no-port"]).expect_err("should have failed");

    assert!(err.contains("no-port"), "{err}");
    assert!(err.contains("--telemetry-addr"), "{err}");
}

/// `--log-format` knows exactly two values, and a third names both.
#[test]
fn the_log_format_names_its_two_values() {
    assert!(!parse(&["--log-format", "text"]).expect("readable").json);
    assert!(parse(&["--log-format", "json"]).expect("readable").json);

    let err = parse(&["--log-format", "xml"]).expect_err("should have failed");
    assert!(err.contains("json"), "{err}");
    assert!(err.contains("text"), "{err}");
}

/// A missing value at the end of the line is an error, not a crash.
#[test]
fn a_missing_value_is_an_error() {
    assert!(parse(&["--otlp-endpoint"]).is_err());
}

/// A foreign option is **not** swallowed.
///
/// `take` returns `false` so that the caller can evaluate its own options. If
/// it returned `true` here, `--data-dir` and everything else would disappear
/// silently.
#[test]
fn a_foreign_option_is_handed_back() {
    let mut args = Args::default();

    let taken = args
        .take("--data-dir", || Ok("/var/lib/tardigrade".to_owned()))
        .expect("no error");

    assert!(!taken);
}

/// The help lines name every option `take` knows.
///
/// An option one finds only by reading the code does not exist in operation.
#[test]
fn the_usage_lists_every_flag() {
    for flag in [
        "--telemetry-addr",
        "--otlp-endpoint",
        "--log-filter",
        "--log-format",
    ] {
        assert!(
            tg_telemetry::args::mentions_word(Args::USAGE, flag),
            "{flag} missing from the overview"
        );
    }
}

/// The decay applies **only** to the gauges.
///
/// Checked on the source, because `install_recorder` is global and can run
/// exactly once in a process — a behaviour test on it would exclude every other
/// test of this file. What the exporter does with a decaying series is measured
/// in `gauge_decay.rs` against the **library**; here stands that we ask it for
/// that, and for which kind.
///
/// `MetricKindMask::ALL` is the obvious change nobody would make red: it reads
/// more tidily and lets counters decay — disappearing and returning reads to
/// `rate()` as a reset, so it produces a spike that never happened.
#[test]
fn only_gauges_decay() {
    const SOURCE: &str = include_str!("../src/init.rs");

    assert!(
        SOURCE.contains("idle_timeout("),
        "without `idle_timeout` the exporter keeps every series until the process ends (ADR-0088)"
    );
    assert!(
        SOURCE.contains("MetricKindMask::GAUGE"),
        "the decay has to be restricted to gauges"
    );
    for forbidden in ["MetricKindMask::ALL", "MetricKindMask::COUNTER"] {
        assert!(
            !SOURCE.contains(forbidden),
            "`{forbidden}` would let counters decay — `rate()` reads that as a reset"
        );
    }
}

/// The gauges' decay deadline is the one from ADR-0088.
///
/// It is an **ordering condition** and no matter of taste: bounded below by the
/// slowest legitimate scrape cadence (Prometheus typically asks every 15 to 60
/// seconds — whoever sets more rarely registers a refresh), above by the time
/// an alert keeps firing after a deliberate withdrawal. Nailed down here,
/// because `gauge_decay.rs` checks the **property** with one second and says
/// nothing about the default. The **lower bound** is a build assertion in
/// `init.rs` — it is decidable at compile time, and then it belongs there.
#[test]
fn the_gauge_idle_timeout_is_the_one_from_the_adr() {
    assert_eq!(
        tg_telemetry::init::GAUGE_IDLE_SECONDS,
        15 * 60,
        "the deadline belongs to the decision (ADR-0088) and not to chance"
    );
}

/// A node process reports `node`, a sidecar `workload`.
///
/// **Both directions**, and that is the statement: a function that always said
/// `node` would pass the first half — and the sidecar would keep carrying a
/// label that names the node and contains a workload.
#[test]
fn a_node_reports_node_and_a_sidecar_reports_workload() {
    use tg_telemetry::init::Reporter;

    assert_eq!(
        Reporter::Node("node-11".to_owned()).label(),
        ("node", "node-11")
    );
    assert_eq!(
        Reporter::Workload("journal".to_owned()).label(),
        ("workload", "journal")
    );
}

/// An empty value sets no label — for **both** kinds.
///
/// `Options::default` carries an empty `Reporter::Node`, and `init` then skips
/// the label; without this assurance there would be a `node=""` on every metric
/// of a process that knows no name.
#[test]
fn an_empty_name_carries_no_label() {
    use tg_telemetry::init::Reporter;

    assert_eq!(Reporter::Node(String::new()).label().1, "");
    assert_eq!(Reporter::Workload(String::new()).label().1, "");
    assert_eq!(
        tg_telemetry::init::Options::default().reporter,
        Reporter::Node(String::new())
    );
}

/// **A flag is named when it stands there as a word** — not as part of a longer
/// one.
///
/// Five guards of this tree check "every parsed flag stands in the usage help",
/// and all five did it with `contains`. Measured, there are **seven** prefix
/// pairs across the four binaries — `--node` in `--node-prefix` and
/// `--node-session` (`tg-agent`), `--init` in `--init-voters`, `--node` in
/// `--node-listen` and `--signer` in `--signer-listen` (`tgd`), `--anchor` in
/// `--anchors` and `--operator` in `--operator-key` (`tgctl`).
///
/// Substantiated on a real case: `--node` removed from `tg-agent`'s overview,
/// and `the_usage_text_lists_every_flag` stayed **green** — because
/// `--node-prefix` stands there. An operator then looks for `--node` in
/// `--help` and does not find it, and the guard says nothing. They are exactly
/// the flags whose absence nobody finds: the node name (ADR-0037/0043),
/// `--init`, the signer accesses (ADR-0097), the operator identity (ADR-0103).
#[test]
fn a_flag_counts_as_named_only_at_a_word_boundary() {
    let help = "  --node <name>            name of this node\n  \
                 --node-prefix <n>         prefix length\n  \
                 -h, --help                this overview\n";

    // The counter-direction carries the guard: what stands there counts as
    // named — otherwise a check that denies everything would be just as green,
    // and no usage help would ever get through.
    for flag in ["--node", "--node-prefix", "--help"] {
        assert!(
            tg_telemetry::args::mentions_word(help, flag),
            "{flag} stands there and does not count as named"
        );
    }

    // And the case at issue.
    let without_node = "  --node-prefix <n>         prefix length\n";
    assert!(
        !tg_telemetry::args::mentions_word(without_node, "--node"),
        "`--node-prefix` alone must not let `--node` count as named"
    );

    // Backwards too: a longer flag is not named because its prefix stands
    // there.
    assert!(
        !tg_telemetry::args::mentions_word("  --node <name>\n", "--node-prefix"),
        "`--node` alone must not let `--node-prefix` count as named"
    );

    // A subcommand without `--` goes the same way (`tgctl help`, ADR-0018).
    assert!(tg_telemetry::args::mentions_word(
        "  help  this overview\n",
        "help"
    ));
    assert!(
        !tg_telemetry::args::mentions_word("  --log-filter <f>\n", "log"),
        "`log` must not be inferred from `--log-filter`"
    );
}

/// **The same rule carries the metric names — and not the paths.**
///
/// The second consumer is `every_metric_has_a_rule_or_a_reason` in `tgctl`: it
/// asks whether a metric has a rule or a reason in `docs/alerts.yml`, and did
/// it with `contains`. Measured, `names.rs` has **six** substring pairs, five
/// of them in the signer family (ADR-0097/0107) — `tg_identity_signer` says
/// whether the group runs at all, and is the shortest of five.
///
/// # What it does not carry
///
/// Measured on `layout::SECRETS_KEY` (`secrets.key`) and
/// `SECRETS_KEY_PREVIOUS`: a **dot** is no word character, so `secrets.key`
/// counts as named in `secrets.key.previous`. For paths the word boundary is
/// thereby the wrong rule — there, what `no_crate_spells_a_path_a_second_time`
/// uses carries: the literal **with quotation marks**, and those are the
/// boundary.
#[test]
fn a_metric_name_counts_as_named_only_at_a_word_boundary() {
    // The counter-direction first: a name that stands there counts as named —
    // otherwise no metric would ever get through its guard.
    let both = "expr: tg_identity_signer == 0\n  # tg_identity_signer_epoch\n";
    for name in ["tg_identity_signer", "tg_identity_signer_epoch"] {
        assert!(
            tg_telemetry::args::mentions_word(both, name),
            "{name} stands there and does not count as named"
        );
    }

    // And the case at issue: the underscore is a word character, so the signer
    // family's five names separate.
    let only_epoch = "expr: count_values(\"epoch\", tg_identity_signer_epoch)\n";
    assert!(
        !tg_telemetry::args::mentions_word(only_epoch, "tg_identity_signer"),
        "`tg_identity_signer_epoch` alone must not let `tg_identity_signer` \
         count as covered"
    );
    assert!(
        !tg_telemetry::args::mentions_word(only_epoch, "tg_identity_signer_epochs"),
        "`…_epoch` alone must not let `…_epochs` count as covered"
    );

    // The boundary, measured: a dot is no word character. Whoever applies this
    // rule to path names gains nothing.
    assert!(
        tg_telemetry::args::mentions_word("secrets.key.previous", "secrets.key"),
        "for paths with a dot the word boundary does not carry — stated so at the code"
    );
}
