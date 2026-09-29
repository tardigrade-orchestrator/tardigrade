//! The wire form of the session, nailed down (ADR-0040).
//!
//! `Command` has had a byte-for-byte pinned form since phase 5a
//! (`tg-consensus`, `every_command_has_a_pinned_wire_form`). **All of this
//! project's format breaks so far lay elsewhere** — in the slice (`generations`
//! from ADR-0055, `leases` from ADR-0064), in the credential protocol (ADR-0042,
//! ADR-0046) and in the log envelope (ADR-0050). Every time they were found by
//! measuring against an old peer, not by a test.
//!
//! The plan carries them as a "coordinated switch", i.e. as operations work with
//! an outage window. Then the moment at which one **arises** is the most
//! important — and precisely that is what this test makes visible.
//!
//! **What to do when it turns red:** not adjust the expected string and move on.
//! Red means: a format break arises here. It belongs in the plan, with the
//! others, and the question is whether a `#[serde(default)]` avoids it — as with
//! `generations` and `leases`, which therefore became **no** breaks.

use tg_model::egress::Transport;
use tg_store::session::{
    ClusterNetwork, Instance, InstanceState, NodeMessage, NodeReport, NodeSlice, RemoteEndpoint,
    UnderlayPeer,
};

/// A slice in which **every** field is filled.
///
/// An empty field would withhold the question at issue: whether it turns up on
/// the wire at all and what it is called.
fn slice() -> NodeSlice {
    NodeSlice {
        // ADR-0133: the `traceparent` of the command from which this state
        // arose. A **format break** (an old agent does not know the field and
        // refuses it, ADR-0072) — it goes into the window.
        trace: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_owned()),
        // ADR-0016/0095: **no format break** — `serde(default)`, and the sealed
        // value stands there as a pinned envelope, not as a freshly produced
        // one: the nonce arises per value, and a produced one would yield a
        // different string every time. The object is the wire form, not the
        // crypto.
        secrets: vec![(
            "api".to_owned(),
            "s3-key".to_owned(),
            tg_identity::secrets::Sealed {
                ciphertext: vec![1, 2, 3],
                nonce: vec![4, 5, 6],
            },
        )],
        // The **ninth** format break (ADR-0096, ADR-0072): the field is added,
        // and `NodeSlice` is strict — an old reader refuses it. It goes into the
        // same bundled window as the eight before it.
        registry_credentials: vec![("registry.test".to_owned(), "s3-key".to_owned())],
        index: 7,
        ordinal: Some(3),
        generations: tg_model::Generations {
            identity: 2,
            underlay: 5,
        },
        network: Some(ClusterNetwork {
            cidr: "10.42.0.0/16".to_owned(),
            node_prefix: 24,
        }),
        instances: vec![Instance {
            workload: "api".to_owned(),
            instance: 1,
            document: "<workloads/>".to_owned(),
            generation: 4,
        }],
        edges: vec![("api".to_owned(), "ledger".to_owned())],
        egress: vec![("api".to_owned(), "s3.test".to_owned(), 443, Transport::Quic)],
        peers: vec![UnderlayPeer {
            node: "node-2".to_owned(),
            ordinal: 4,
            key: "AAAA".to_owned(),
            endpoint: "10.0.0.2:51820".to_owned(),
        }],
        deleted_volumes: vec!["alt".to_owned()],
        snapshot_generations: vec![("daten".to_owned(), 3)],
        leases: vec![("api".to_owned(), 9, 1_800_000_015_000)],
        // The **twenty-second** format break (ADR-0111, ADR-0072): the field is
        // added, and `NodeSlice` is strict — an old reader refuses it. It goes
        // into the same bundled window as the ones before it.
        active_instances: vec![("api".to_owned(), 1)],
        endpoints: vec![RemoteEndpoint {
            workload: "ledger".to_owned(),
            instance: 0,
            address: "10.42.2.5".parse().expect("address"),
            healthy: true,
        }],
        sidecar_overhead: vec![("memory-bytes".to_owned(), 67_108_864)],
    }
}

/// **The slice has a fixed shape.**
#[test]
fn the_slice_has_a_pinned_wire_form() {
    let encoded = serde_json::to_string(&slice()).expect("encodable");

    assert_eq!(
        encoded,
        r#"{"index":7,"ordinal":3,"generations":{"identity":2,"underlay":5},"trace":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01","network":{"cidr":"10.42.0.0/16","node_prefix":24},"instances":[{"workload":"api","instance":1,"document":"<workloads/>","generation":4}],"edges":[["api","ledger"]],"egress":[["api","s3.test",443,"quic"]],"secrets":[["api","s3-key",{"ciphertext":[1,2,3],"nonce":[4,5,6]}]],"registry_credentials":[["registry.test","s3-key"]],"peers":[{"node":"node-2","ordinal":4,"key":"AAAA","endpoint":"10.0.0.2:51820"}],"deleted_volumes":["alt"],"snapshot_generations":[["daten",3]],"leases":[["api",9,1800000015000]],"active_instances":[["api",1]],"endpoints":[{"workload":"ledger","instance":0,"address":"10.42.2.5","healthy":true}],"sidecar_overhead":[["memory-bytes",67108864]]}"#,
        "the wire form of the slice has changed — see the module header"
    );
}

/// And back. Without that it would be writable but not readable.
#[test]
fn the_slice_survives_a_round_trip() {
    let encoded = serde_json::to_string(&slice()).expect("encodable");
    let decoded: NodeSlice = serde_json::from_str(&encoded).expect("decodable");

    assert_eq!(decoded, slice());
}

/// **The return direction likewise** — it carries observed state (ADR-0040,
/// determination 7).
#[test]
fn the_node_messages_have_a_pinned_wire_form() {
    let hello = serde_json::to_string(&NodeMessage::Hello { applied: 4 }).expect("encodable");
    assert_eq!(
        hello, r#"{"hello":{"applied":4}}"#,
        "`Hello` carries **no name** (ADR-0043) — if one stands here, that is \
         not a format break but a security regression"
    );

    let report = serde_json::to_string(&NodeMessage::Report(Box::new(NodeReport {
        applied: 4,
        states: vec![("api".to_owned(), 1, InstanceState::Running)],
        capacity: tg_model::Resources::default().with(tg_model::Resources::CPU_MILLICORES, 4000),
        generations: tg_model::Generations {
            identity: 2,
            underlay: 5,
        },
        proxy_image: Some("registry.example.com/proxy:1".to_owned()),
        stale: vec![("api".to_owned(), 1)],
        unready: vec![("api".to_owned(), 1)],
        isolated: vec!["kaputt".to_owned()],
        // **Completely filled**, like every field here: an empty one would
        // withhold the question whether it turns up on the wire at all
        // (ADR-0073).
        endpoints: vec![("api".to_owned(), 1, "10.42.1.5".parse().expect("address"))],
        dns_zone: Some("tardigrade.internal".to_owned()),
        userns: Some(100_000),
        failures: vec![("api".to_owned(), 2, "pull".to_owned())],
        retired: vec!["daten".to_owned()],
    })))
    .expect("encodable");
    assert_eq!(
        report,
        r#"{"report":{"applied":4,"states":[["api",1,"running"]],"stale":[["api",1]],"unready":[["api",1]],"failures":[["api",2,"pull"]],"isolated":["kaputt"],"capacity":{"cpu-millicores":4000},"generations":{"identity":2,"underlay":5},"proxy_image":"registry.example.com/proxy:1","endpoints":[["api",1,"10.42.1.5"]],"dns_zone":"tardigrade.internal","userns":100000,"retired":["daten"]}}"#,
        "the wire form of the report has changed — see the module header"
    );
}

/// **And the same sentence for the report** (ADR-0040, determination 7).
///
/// `capacity`, `generations`, `proxy_image` and `stale` are `serde(default)`: a
/// report from an **old** node still reads at a new `tgd`, and the defaults mean
/// exactly what it means — no capacity reported, generation zero, no proxy
/// image, nothing stale.
///
/// **The opposite direction does not carry**, and that stands here so that
/// nobody takes it for granted: `NodeReport` has `deny_unknown_fields`, so an
/// **old** `tgd` refuses a new node's report. Each of these four extensions is
/// thereby a break in that direction.
#[test]
fn a_report_without_the_later_fields_still_reads() {
    let old = r#"{"applied":4,"states":[["api",0,"running"]]}"#;

    let decoded: NodeReport = serde_json::from_str(old).expect("an old report has to carry");

    assert_eq!(decoded.applied, 4);
    assert!(decoded.capacity.is_empty());
    assert_eq!(decoded.generations, tg_model::Generations::default());
    assert!(decoded.proxy_image.is_none());
    assert!(decoded.stale.is_empty(), "nothing stale");
}

/// **A field an old server does not know must not mean an abort.**
///
/// `generations` and `leases` are therefore `#[serde(default)]` — they are the
/// two extensions that became **no** format breaks. This test records why: a
/// slice without them still reads, and the default means exactly what an old
/// server means.
#[test]
fn a_slice_without_the_later_fields_still_reads() {
    let old = r#"{"index":7,"ordinal":null,"network":null,"instances":[],"edges":[],"peers":[]}"#;

    let decoded: NodeSlice = serde_json::from_str(old).expect("an old slice has to carry");

    assert_eq!(decoded.generations, tg_model::Generations::default());
    assert!(decoded.leases.is_empty(), "no active role");
    assert!(decoded.egress.is_empty());
    assert!(decoded.deleted_volumes.is_empty());
    // ADR-0099: without a decree no snapshot generation -- exactly what a server
    // without this field means.
    assert!(decoded.snapshot_generations.is_empty());
}

/// **A node without a mesh does not count towards the deviation** (ADR-0059).
///
/// `None` means "builds no sidecars" and not "runs a version of its own". If it
/// counted, every cluster with a node without `--proxy-image` would permanently
/// report a deviation — and the number would be worthless for an alert rule.
#[test]
fn a_node_without_a_mesh_does_not_count_as_a_version() {
    let projection = tg_store::Projection::default();

    projection.report_proxy_image("a", Some("registry.test/proxy:1"));
    projection.report_proxy_image("b", Some("registry.test/proxy:1"));
    projection.report_proxy_image("c", None);
    assert_eq!(projection.distinct_proxy_images(), 1, "uniform");

    // And the counter-check: a real deviation is counted.
    projection.report_proxy_image("b", Some("registry.test/proxy:2"));
    assert_eq!(projection.distinct_proxy_images(), 2);

    // Whoever gives up their mesh disappears — otherwise their old version would
    // stay standing as a deviation that no longer exists. Exactly this case is
    // the reason why it is **one number** and not a label per node.
    projection.report_proxy_image("b", None);
    assert_eq!(projection.distinct_proxy_images(), 1);
}

/// **The strictness is a promise, not an attribute** (ADR-0072, determination
/// 2).
///
/// `deny_unknown_fields` stands on each of these types — and ADR-0045 measured
/// that a `#[serde(flatten)]` lifts the same promise **silently**. There it was
/// a finding; here it is a guard.
///
/// A peer that does not fully understand a message does **not** process it. The
/// slice is a decree — it carries tombstones (ADR-0042), active-role leases
/// (ADR-0064) and generations (ADR-0071) —, and a partially executed decree is
/// the state an auditor cannot reconstruct.
///
/// The price stands in ADR-0072: **every** extension of these types is a format
/// break, and both update orders break on their own.
#[test]
fn an_unknown_field_is_refused_in_both_directions() {
    // The slice — the decree.
    let slice = r#"{"index":7,"ordinal":null,"network":null,"instances":[],"edges":[],"peers":[],"was_neues":1}"#;
    let refused = serde_json::from_str::<NodeSlice>(slice);
    assert!(
        refused.is_err(),
        "a slice with an unknown field has to be refused (ADR-0072)"
    );
    assert!(
        format!("{}", refused.unwrap_err()).contains("was_neues"),
        "and the message has to name the field"
    );

    // An instance within it — it has carried the generation since ADR-0071.
    let instance = r#"{"workload":"api","instance":0,"document":"<workloads/>","was_neues":1}"#;
    assert!(
        serde_json::from_str::<tg_store::session::Instance>(instance).is_err(),
        "the instance is strict too — otherwise the envelope would be so only \
         apparently"
    );

    // The opposite direction: what the control plane says. Until ADR-0072 it was
    // the only lenient one of the five.
    let control = r#"{"refused":{"reason":"not admitted","code":7}}"#;
    assert!(
        serde_json::from_str::<tg_store::session::ControlMessage>(control).is_err(),
        "the control message is strict too — otherwise an old agent silently \
         discards what a new server wanted to tell it"
    );

    // And the report — the observation.
    let report = r#"{"applied":4,"states":[],"something_new":1}"#;
    assert!(
        serde_json::from_str::<NodeReport>(report).is_err(),
        "a report with an unknown field has to be refused (ADR-0072)"
    );

    // The counter-check: **without** the extra field all three carry. Without it
    // the test would only prove that something does not parse.
    assert!(
        serde_json::from_str::<NodeSlice>(
            r#"{"index":7,"ordinal":null,"network":null,"instances":[],"edges":[],"peers":[]}"#
        )
        .is_ok()
    );
    assert!(
        serde_json::from_str::<tg_store::session::Instance>(
            r#"{"workload":"api","instance":0,"document":"<workloads/>"}"#
        )
        .is_ok()
    );
    assert!(serde_json::from_str::<NodeReport>(r#"{"applied":4,"states":[]}"#).is_ok());
    assert!(
        serde_json::from_str::<tg_store::session::ControlMessage>(
            r#"{"refused":{"reason":"not admitted"}}"#
        )
        .is_ok()
    );
}

/// **A report stays far below the message limit** (ADR-0073, ADR-0068).
///
/// The report grows with the number of instances per node — since ADR-0073 by
/// the endpoints, i.e. by a second list of the same length. Whether that needs a
/// bound is a question of measurement, and here it is answered:
///
/// | instances on **one** node | report |
/// |---|---|
/// | 10 | 751 B |
/// | 100 | 6 KiB |
/// | 1 000 | 63 KiB |
///
/// The limit is `tonic`'s default of **4 MiB** per message (we set none of our
/// own). It would be reached at about 65 000 instances on a single node; the
/// channel is eight messages deep (ADR-0068), so with 1 000 instances at most
/// around 500 KiB are in flight.
///
/// A bound is therefore not needed. What is needed is this guard: a future field
/// that drags a string along per instance — a document, say — would tip the
/// calculation by orders of magnitude, and the session would break with
/// `message too large` instead of with a message that names the reason.
#[test]
fn a_report_with_a_thousand_instances_stays_small() {
    /// What `tonic` accepts without a setting of our own.
    const LIMIT: usize = 4 * 1024 * 1024;

    let count = 1_000_u32;
    let report = NodeReport {
        applied: 42,
        states: (0..count)
            .map(|n| (format!("workload-{n}"), n, InstanceState::Running))
            .collect(),
        stale: Vec::new(),
        unready: Vec::new(),
        failures: Vec::new(),
        isolated: Vec::new(),
        capacity: tg_model::Resources::default(),
        generations: tg_model::Generations::default(),
        proxy_image: Some("registry.example.com/tg-proxy:1.2.3".to_owned()),
        endpoints: (0..count)
            .map(|n| {
                (
                    format!("workload-{n}"),
                    n,
                    std::net::Ipv4Addr::new(10, 42, 0, 1),
                )
            })
            .collect(),
        dns_zone: Some("tardigrade.internal".to_owned()),
        userns: Some(100_000),
        retired: Vec::new(),
    };

    let bytes = serde_json::to_vec(&report).expect("encodable").len();

    assert!(
        bytes < LIMIT / 8,
        "a report with {count} instances is {bytes} bytes — more than an eighth \
         of the message limit of {LIMIT}. A field per instance has grown; see \
         the comment on this test."
    );
}

/// **The protocol version is the counted number of format breaks.**
///
/// A format change is no rolling update (ADR-0072, determination 3), and the
/// manual names a **maintenance window** with an order for it. The question in
/// the middle is "am I done?" — and in that window every node is quiet, so a
/// forgotten one looks like a waiting one. Any information that ran over the
/// **session** would be exactly the one the skew breaks; the only one that
/// survives it is a metric at every process's Prometheus endpoint
/// (`tg_process_protocol_fields`).
///
/// **Counted and not maintained.** An explicit protocol version would be a
/// second source **and** a discipline: whoever forgets to raise it reports "all
/// the same" while two versions run — a **false all-clear**, and that is the
/// more expensive direction.
///
/// **What is counted:** every `#[serde(default)]` field on one of the three
/// **strict** types. The default covers one direction — a new reader tolerates a
/// missing field —, the strictness refuses the other. Each such field is thereby
/// exactly one break.
///
/// **What it does not count:** a change of form without a new field (the egress
/// entry went from a triple to a quadruple, ADR-0092). The number is a **lower
/// bound**.
///
/// The counting lies here and not at the manual guard in `tgctl`: here is the
/// source, and two counts would be two opportunities to count differently.
#[test]
fn the_protocol_version_is_the_counted_number_of_breaks() {
    let source = include_str!("../src/session/mod.rs");

    // The three strict types, by name: `ControlMessage` and `NodeMessage` are
    // strict too and have **no** default fields -- they stand here so that a new
    // field there stands out instead of counting silently.
    let strict = ["NodeSlice", "Instance", "NodeReport"];
    let mut counted = 0_u32;
    for name in strict {
        let start = source
            .find(&format!("pub struct {name} "))
            .unwrap_or_else(|| panic!("{name} not found — type renamed?"));
        let body = &source[start..];
        let end = body.find("\n}\n").expect("type without an end");
        // **Without comment lines.** The documentation quotes the attribute
        // ("as at `generations`, and for the same reason"), and a text
        // comparison over the whole file counted them too: measured 28 instead
        // of 21. A guard that produces false hits gets switched off instead of
        // read.
        counted += u32::try_from(
            body[..end]
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                // **With the prefix and not the whole attribute:** a field may
                // say something else beside the default (`skip_serializing_if`,
                // ADR-0133), and it remains the same format break -- what is
                // tolerated is its **absence**. The narrower comparison would
                // have missed it, and the constant would have been one too
                // small.
                .filter(|line| line.contains("#[serde(default"))
                .count(),
        )
        .expect("number");
    }

    assert!(
        counted > 10,
        "only {counted} default fields found — the search no longer bites"
    );

    assert_eq!(
        counted,
        tg_store::session::PROTOCOL_FIELDS,
        "the counted number of format breaks and `session::PROTOCOL_FIELDS` \
         diverge. Whoever adds a field adjusts the constant — otherwise the \
         endpoint reports a version that does not exist, and a skew in the \
         maintenance window does not stand out (ADR-0072)"
    );
}
