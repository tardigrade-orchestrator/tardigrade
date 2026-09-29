//! How the resolver answered, as a metric.
//!
//! # Why a file of its own
//!
//! The `metrics` recorder is **global** and belongs to the process, and `cargo
//! test` runs the tests of **one** file concurrently: the other resolver tests
//! call `respond` too and book on the same counters. Measured, the numbers
//! thereby fluctuated from run to run (`dropped: 3` instead of 2, `noerror: 2`
//! instead of 1) — the test then measures the whole binary and not itself.
//!
//! The same situation and the same answer as with `RLIMIT_NOFILE` in
//! `resolver_exhaustion.rs`: what belongs to the process gets its own.

use std::net::Ipv4Addr;

use simple_dns::{CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, TYPE};
use tg_net::discovery::{Domain, Endpoint, Health, Registry};
use tg_net::resolver::{Resolver, UDP_LIMIT};

const ZONE: &str = "tardigrade.internal";

/// Builds a fixture endpoint on the `10.42.1.0/24` test subnet.
///
/// # Parameters
/// - `workload`: the workload name the endpoint belongs to.
/// - `instance`: the instance number within the workload.
/// - `last`: the last octet of the fixture address.
/// - `health`: the health state to report for the endpoint.
///
/// # Returns
/// The constructed endpoint.
fn endpoint(workload: &str, instance: u32, last: u8, health: Health) -> Endpoint {
    Endpoint {
        workload: workload.to_owned(),
        instance,
        address: Ipv4Addr::new(10, 42, 1, last),
        health,
    }
}

/// Builds the fixture resolver used by this file's tests: one healthy `api`
/// instance and one unhealthy `cache` instance.
///
/// # Returns
/// The constructed resolver.
fn resolver() -> Resolver {
    Resolver::new(Registry::new(
        Domain::new(ZONE).expect("valid"),
        vec![
            endpoint("api", 0, 10, Health::Healthy),
            endpoint("cache", 0, 30, Health::Unhealthy),
        ],
    ))
}

/// Builds a query as a client sends it.
///
/// # Parameters
/// - `name`: the queried name.
/// - `qtype`: the queried record type.
///
/// # Returns
/// The serialized query bytes.
fn query(name: &str, qtype: QTYPE) -> Vec<u8> {
    let mut packet = Packet::new_query(0x4711);
    packet.questions.push(Question::new(
        Name::new(name).expect("valid name"),
        qtype,
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    packet.build_bytes_vec().expect("query")
}

/// **How the resolver answered is queryable, as a metric per outcome.**
///
/// The most expensive case in operations is "my workload does not reach its
/// target", and the resolver answered every query without telling anybody how.
/// A log line per query would be wrong for that: `REFUSED` is the
/// deny-by-default answer and the normal case for every name outside the
/// zone — a container can issue arbitrarily many.
///
/// **Counted at the decision**, not at the wire: `Verdict::Reply` carries
/// finished bytes, and reading the response code back out of them would be a
/// second reader for a format with one writer.
///
/// # Why one snapshot and exact numbers
///
/// The `DebuggingRecorder` **empties itself on reading** (measured in
/// `tg-runtime`'s `lease_path`): two snapshots, and the second reads zeros. So
/// one at the end — counters sum anyway.
///
/// And checked are **numbers per outcome**, not the presence of the line: a
/// counter that books every answer as `noerror` would otherwise be green too,
/// and precisely that distinction is the metric's purpose.
#[test]
fn every_kind_of_answer_is_counted() {
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    // The recorder is global; if setting it fails, another test in the same
    // binary has already set it — then its snapshotter counts, and this test can
    // state nothing.
    recorder.install().expect("recorder");

    let resolver = resolver();

    // A name with addresses, one without an A, one that does not exist, and one
    // outside the zone.
    for (name, qtype) in [
        (format!("api.{ZONE}"), QTYPE::TYPE(TYPE::A)),
        (format!("api.{ZONE}"), QTYPE::TYPE(TYPE::AAAA)),
        (format!("does-not-exist.{ZONE}"), QTYPE::TYPE(TYPE::A)),
        ("example.com".to_owned(), QTYPE::TYPE(TYPE::A)),
    ] {
        let _ = resolver.respond(&query(&name, qtype), UDP_LIMIT);
    }

    // And the three ways that never see a resolution: an answer instead of a
    // query, unreadable bytes, and an opcode this server does not know.
    let mut reply = Packet::new_reply(0x4711);
    reply.set_flags(PacketFlag::RESPONSE);
    let _ = resolver.respond(&reply.build_bytes_vec().expect("answer"), UDP_LIMIT);
    let _ = resolver.respond(b"not DNS", UDP_LIMIT);

    // The opcode has no setter in `simple-dns` — so at the byte. It lies in
    // bits 3..6 of the second header byte (RFC 1035): `2` is `SERVERSTATUS`,
    // which this server does not know.
    let mut status = query(&format!("api.{ZONE}"), QTYPE::TYPE(TYPE::A));
    status[2] |= 2 << 3;
    let _ = resolver.respond(&status, UDP_LIMIT);

    let seen = counters(&snapshotter);
    for (outcome, expected) in [
        ("noerror", 1),
        ("nodata", 1),
        ("nxdomain", 1),
        ("refused", 1),
        ("dropped", 2),
        ("notimplemented", 1),
    ] {
        assert_eq!(
            seen.get(outcome).copied(),
            Some(expected),
            "the outcome '{outcome}' was not counted — seen: {seen:?}"
        );
    }
}

/// The answer metric's counters, by outcome, from **one** snapshot.
///
/// # Parameters
/// - `snapshotter`: the recorder snapshotter to read from.
///
/// # Returns
/// A map from outcome label to the counted number of answers.
fn counters(
    snapshotter: &metrics_util::debugging::Snapshotter,
) -> std::collections::BTreeMap<String, u64> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| key.key().name() == tg_telemetry::names::DNS_ANSWERS)
        .filter_map(|(key, _, _, value)| {
            let outcome = key
                .key()
                .labels()
                .find(|label| label.key() == "outcome")?
                .value()
                .to_owned();
            match value {
                metrics_util::debugging::DebugValue::Counter(seen) => Some((outcome, seen)),
                _ => None,
            }
        })
        .collect()
}
