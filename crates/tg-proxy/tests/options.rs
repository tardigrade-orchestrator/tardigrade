//! The sidecar's call and the policy format.
//!
//! The binary itself cannot be started outside a container -- its identity
//! comes over the workload API socket, and that rightly gives nothing to an
//! unattested process (ADR-0006). What remains and can be checked is
//! everything that is decided **before** the first byte: the settings and the
//! edges.

use std::net::SocketAddr;

use tg_proxy::options::{Options, OptionsError, edges_from_text};

fn args(raw: &[&str]) -> Vec<String> {
    raw.iter().map(|s| (*s).to_owned()).collect()
}

fn minimal() -> Vec<String> {
    args(&[
        "--workload",
        "api",
        "--upstream-port",
        "8443",
        "--socket",
        "/run/tg/workload-api.sock",
    ])
}

/// The three mandatory settings stand in the derived sidecar unit -- the
/// sidecar need guess nothing.
#[test]
fn the_three_required_flags_are_read() {
    let options = Options::parse(&minimal()).expect("valid");

    assert_eq!(options.workload, "api");
    assert_eq!(options.upstream_port, 8443);
    assert_eq!(options.socket.to_str(), Some("/run/tg/workload-api.sock"));
}

/// Every missing mandatory setting is **named**, not merely reported as "the
/// call is wrong".
#[test]
fn every_missing_flag_names_itself() {
    for (drop_at, expected) in [(0, "--workload"), (2, "--upstream-port"), (4, "--socket")] {
        let mut incomplete = minimal();
        incomplete.drain(drop_at..drop_at + 2);

        let err = Options::parse(&incomplete).expect_err("incomplete");
        assert_eq!(err, OptionsError::Missing { flag: expected });
    }
}

/// An unusable port stands out at the call, not at the first byte.
#[test]
fn an_unusable_port_is_refused_at_startup() {
    let mut bad = minimal();
    bad[3] = "forty-eight".to_owned();

    let err = Options::parse(&bad).expect_err("no port");
    assert!(matches!(
        err,
        OptionsError::Value {
            flag: "--upstream-port",
            ..
        }
    ));
}

/// Routes are collected, not overwritten.
#[test]
fn several_routes_are_collected() {
    let mut with_routes = minimal();
    with_routes.extend(args(&[
        "--route",
        "ledger=127.0.0.1:9443",
        "--route",
        "audit=127.0.0.1:9444",
    ]));

    let options = Options::parse(&with_routes).expect("valid");

    assert_eq!(options.routes.len(), 2);
    assert_eq!(
        options.routes.get("ledger"),
        Some(&"127.0.0.1:9443".parse::<SocketAddr>().expect("the address"))
    );
}

/// A route without a target is no route.
#[test]
fn a_route_without_a_target_is_refused() {
    let mut bad = minimal();
    bad.extend(args(&["--route", "ledger"]));

    assert!(matches!(
        Options::parse(&bad).expect_err("unusable"),
        OptionsError::Value {
            flag: "--route",
            ..
        }
    ));
}

/// The peer name becomes a SPIFFE ID in the call's trust domain.
#[test]
fn a_peer_name_becomes_an_identity_in_the_trust_domain() {
    let options = Options::parse(&minimal()).expect("valid");

    assert_eq!(
        options.peer_id("ledger").expect("the ID").to_string(),
        "spiffe://cluster.local/workload/ledger"
    );
    assert!(
        options.peer_id("Gross").is_err(),
        "a name outside the facet is no identity (ADR-0008)"
    );
}

// ------------------------------------------------------- the policy file

/// The format is one line per edge -- readable and judgeable in a review.
#[test]
fn the_policy_format_is_one_edge_per_line() {
    let edges = edges_from_text(
        "# who may talk with whom\n\
         api -> ledger\n\
         \n\
         ledger-* -> audit   # a family\n",
    )
    .expect("readable");

    assert_eq!(
        edges,
        vec![
            ("api".to_owned(), "ledger".to_owned()),
            ("ledger-*".to_owned(), "audit".to_owned()),
        ]
    );
}

/// An empty file yields no edges -- and thereby deny-by-default.
#[test]
fn an_empty_file_yields_no_edges() {
    assert!(edges_from_text("").expect("readable").is_empty());
    assert!(
        edges_from_text("# only a comment\n")
            .expect("readable")
            .is_empty()
    );
}

/// A line that is no edge is **reported**.
///
/// Skipping it silently would be the worse choice: the operator would then
/// believe they had set an edge that does not exist.
#[test]
fn a_line_that_is_not_an_edge_is_reported() {
    for line in ["api ledger", "api ->", "-> ledger"] {
        assert!(
            edges_from_text(line).is_err(),
            "'{line}' was accepted silently"
        );
    }
}

/// **The derived command line parses -- completely.**
///
/// It is the contract between `tg_model::mesh::build` and this reader
/// (ADR-0059, determination 5): an operator does **not** reach it, it is
/// fixed. Measured, the producer side was guarded -- `tg-model/tests/mesh.rs`
/// compares the line word for word -- and the **consumer side** at five
/// switches not at all: `--listen`, `--mesh-listen`, `--policy`, `--shards`
/// and `--trust-domain` had not a single witness. What hangs on it:
///
/// - `--mesh-listen` is the port the rule set redirects onto (ADR-0060);
/// - `--policy` is the edge file, and a wrong path means deny-by-default
///   forever (ADR-0025, fail-static);
/// - `--trust-domain` is the setting at which the sidecar looks for its anchor
///   -- and the hole that was found in this session.
///
/// `tg-proxy` deliberately does **not** hang on `tg-model` (no XSD parser in
/// the data plane), so the contract here is a **literal** -- the same
/// construction as with the wire-format guards: two sides, two literals, and
/// whoever changes one makes one of the two red.
#[test]
fn the_derived_command_line_parses_completely() {
    let options = Options::parse(&args(&[
        "--workload",
        "api",
        "--upstream-port",
        "8443",
        "--socket",
        "/run/tardigrade/workload-api.sock",
        "--policy",
        "/run/tardigrade/may-talk",
        "--egress",
        "/run/tardigrade/egress",
        "--active-role",
        "/run/tardigrade/active-role",
        "--listen",
        "0.0.0.0:15006",
        "--mesh-listen",
        "0.0.0.0:15001",
        "--egress-listen",
        "0.0.0.0:15002",
        "--trust-domain",
        "acme.internal",
    ]))
    .expect("the derived line must parse");

    assert_eq!(options.workload, "api");
    assert_eq!(options.upstream_port, 8443);
    assert_eq!(
        options.socket,
        std::path::Path::new("/run/tardigrade/workload-api.sock")
    );
    assert_eq!(
        options.policy.as_deref(),
        Some(std::path::Path::new("/run/tardigrade/may-talk"))
    );
    assert_eq!(
        options.egress.as_deref(),
        Some(std::path::Path::new("/run/tardigrade/egress"))
    );
    assert_eq!(
        options.active_role.as_deref(),
        Some(std::path::Path::new("/run/tardigrade/active-role"))
    );
    assert_eq!(
        options.inbound,
        Some("0.0.0.0:15006".parse().expect("the address"))
    );
    assert_eq!(
        options.mesh_listen,
        Some("0.0.0.0:15001".parse().expect("the address"))
    );
    assert_eq!(
        options.egress_listen,
        Some("0.0.0.0:15002".parse().expect("the address"))
    );
    assert_eq!(options.trust_domain, "acme.internal");

    // The counter direction: `--single-writer` stands **conditionally** in
    // the line (ADR-0066), and without it the sidecar reins nothing in.
    assert!(
        !options.single_writer,
        "without the setting no single writer may be assumed"
    );
    // The same for the pinning (ADR-0114, determination 3): conditional in
    // the line, the default is off.
    assert!(
        !options.pin_shards,
        "without the setting there is no pinning (ADR-0114 D3)"
    );
}

/// **`--pin-shards` is read** (ADR-0114, determination 3).
///
/// The positive case alone would prove nothing -- the counter-check stands
/// above in `the_derived_command_line_parses_completely`, and it is the more
/// important half: the default is off.
#[test]
fn the_pinning_flag_is_read() {
    let mut raw = vec![
        "--workload",
        "api",
        "--upstream-port",
        "8443",
        "--socket",
        "/run/tardigrade/workload-api.sock",
    ];
    raw.push("--pin-shards");

    let options = Options::parse(&args(&raw)).expect("parses");

    assert!(options.pin_shards);
}

/// **`--shards` is the data plane's only number** (ADR-0022) and had no
/// witness.
///
/// It stands **not** in the derived line -- otherwise the sidecar takes one
/// shard per core. A value that does not parse is therefore an error and no
/// default: whoever sets the number meant it.
#[test]
fn the_shard_count_is_read_or_refused() {
    let options = Options::parse(&args(&[
        "--workload",
        "api",
        "--upstream-port",
        "8443",
        "--socket",
        "/run/tg/s.sock",
        "--shards",
        "4",
    ]))
    .expect("valid");
    assert_eq!(options.shards, Some(4));

    // Without the setting: no number, and the sidecar decides itself.
    assert_eq!(minimal_options().shards, None);

    let err = Options::parse(&args(&[
        "--workload",
        "api",
        "--upstream-port",
        "8443",
        "--socket",
        "/run/tg/s.sock",
        "--shards",
        "four",
    ]))
    .expect_err("no number");
    assert!(
        format!("{err}").contains("--shards"),
        "the message must name the switch: {err}"
    );
}

/// The three mandatory settings, parsed -- for the counter directions above.
fn minimal_options() -> Options {
    Options::parse(&minimal()).expect("valid")
}
