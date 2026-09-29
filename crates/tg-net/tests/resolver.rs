//! The resolver on the wire.
//!
//! What is checked here is the **answer as bytes** — that a foreign resolver
//! understands it is checked by `dns_interop.rs` with `dig`, `host` and glibc.
//!
//! The resolution logic itself is checked in `discovery.rs`. What comes on
//! top here are the DNS peculiarities one sees only on the wire — and each
//! one of them produces an error that is hard to find in operation:
//!
//! - **NODATA needs an SOA.** Without it, negative caching has no effect: RFC
//!   2308 takes the negative cache duration from the SOA record in the
//!   authority section. If it is missing, every resolver sets its own number,
//!   and that is typically longer by orders of magnitude.
//! - **AAAA for a known name is NODATA, not NXDOMAIN.** A client that asks for
//!   both would otherwise conclude from an NXDOMAIN that the name does not exist
//!   at all — and would no longer issue the A query.
//! - **One does not answer an answer.** Otherwise two resolvers egg each other
//!   on.
//! - **What does not fit into a UDP packet is truncated and marked.** A server
//!   that sets TC must be reachable over TCP — otherwise the client has no
//!   second way.

use std::net::Ipv4Addr;

use simple_dns::rdata::RData;
use simple_dns::{CLASS, Name, OPCODE, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE};
use tg_net::discovery::{Domain, Endpoint, Health, NEGATIVE_TTL_SECONDS, Registry, TTL_SECONDS};
use tg_net::resolver::{Resolver, UDP_LIMIT, Verdict};

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

/// Builds the fixture resolver used by most tests in this file.
///
/// # Returns
/// The constructed resolver, serving two healthy `api` instances and one
/// unhealthy `cache` instance.
fn resolver() -> Resolver {
    Resolver::new(Registry::new(
        Domain::new(ZONE).expect("valid"),
        vec![
            endpoint("api", 0, 10, Health::Healthy),
            endpoint("api", 1, 11, Health::Healthy),
            endpoint("cache", 0, 30, Health::Unhealthy),
        ],
    ))
}

/// Builds a query as a client sends it.
///
/// # Parameters
/// - `name`: the query name.
/// - `qtype`: the requested record type.
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
    packet.build_bytes_vec().expect("serializable")
}

/// Sends a query to the fixture resolver and unwraps the reply bytes.
///
/// # Parameters
/// - `name`: the query name.
/// - `qtype`: the requested record type.
///
/// # Returns
/// The serialized answer bytes.
///
/// # Panics
/// Panics if the resolver does not reply (the fixture resolver has no
/// forwarding list, so it only ever replies or stays silent — the forwarding
/// exception is checked by `forwarding.rs`).
fn ask(name: &str, qtype: QTYPE) -> Vec<u8> {
    // Without a forwarding list there is only `Reply` and `Silence` — the
    // forwarding exception is checked by `forwarding.rs`.
    match resolver().respond(&query(name, qtype), UDP_LIMIT) {
        Verdict::Reply(bytes) => bytes,
        other => panic!("there must be an answer, was {other:?}"),
    }
}

/// Extracts the A-record addresses from a serialized DNS answer.
///
/// # Parameters
/// - `bytes`: the serialized answer.
///
/// # Returns
/// The addresses carried by the answer's A records, in order.
///
/// # Panics
/// Panics if `bytes` does not parse as a DNS message.
fn addresses(bytes: &[u8]) -> Vec<Ipv4Addr> {
    let packet = Packet::parse(bytes).expect("the answer must parse");
    packet
        .answers
        .iter()
        .filter_map(|record| match &record.rdata {
            RData::A(a) => Some(Ipv4Addr::from(a.address)),
            _ => None,
        })
        .collect()
}

// ------------------------------------------------------------- The normal case

/// An A query returns the addresses of all healthy instances.
#[test]
fn an_a_query_returns_the_healthy_addresses() {
    let bytes = ask("api.tardigrade.internal", QTYPE::TYPE(simple_dns::TYPE::A));

    assert_eq!(
        addresses(&bytes),
        vec![Ipv4Addr::new(10, 42, 1, 10), Ipv4Addr::new(10, 42, 1, 11)]
    );
}

/// We are authoritative for this zone and say so. Without the AA bit a client
/// takes the answer for one out of a cache.
#[test]
fn the_answer_is_marked_authoritative() {
    let bytes = ask("api.tardigrade.internal", QTYPE::TYPE(simple_dns::TYPE::A));
    let packet = Packet::parse(&bytes).expect("parses");

    assert!(packet.has_flags(PacketFlag::RESPONSE), "QR missing");
    assert!(
        packet.has_flags(PacketFlag::AUTHORITATIVE_ANSWER),
        "AA missing"
    );
    assert_eq!(packet.rcode(), RCODE::NoError);
}

/// The answer's records carry the resolver's configured positive TTL.
#[test]
fn the_answer_carries_the_ttl_from_adr_0013() {
    let bytes = ask("api.tardigrade.internal", QTYPE::TYPE(simple_dns::TYPE::A));
    let packet = Packet::parse(&bytes).expect("parses");

    for record in &packet.answers {
        assert_eq!(record.ttl, TTL_SECONDS);
    }
}

/// Id and question come back — otherwise the client does not assign the answer
/// and discards it.
#[test]
fn the_id_and_the_question_are_echoed() {
    let bytes = ask("api.tardigrade.internal", QTYPE::TYPE(simple_dns::TYPE::A));
    let packet = Packet::parse(&bytes).expect("parses");

    assert_eq!(packet.id(), 0x4711);
    assert_eq!(packet.questions.len(), 1);
    assert_eq!(
        packet.questions[0].qname.to_string(),
        "api.tardigrade.internal"
    );
}

/// A find of the fuzz run, nailed down deterministically.
///
/// The answer mirrors the **question's letter case** back, not the canonical
/// one. That is no accident and no negligence: RFC 1035 demands that the name in
/// the answer section correspond to the question's, and DNS-0x20 builds a
/// spoofing protection on it — a client randomizes the upper and lower case and
/// discards answers that do not return it.
#[test]
fn the_answer_echoes_the_case_of_the_question() {
    let bytes = ask("ApI.Tardigrade.INTERNAL", QTYPE::TYPE(simple_dns::TYPE::A));
    let packet = Packet::parse(&bytes).expect("parses");

    assert_eq!(
        packet.questions[0].qname.to_string(),
        "ApI.Tardigrade.INTERNAL"
    );
    assert_eq!(
        packet.answers[0].name.to_string(),
        "ApI.Tardigrade.INTERNAL",
        "the answer has to carry the question's letter case (DNS-0x20)"
    );
    assert_eq!(addresses(&bytes).len(), 2, "it has to resolve nevertheless");
}

/// A per-instance name resolves to exactly that instance's address.
#[test]
fn an_instance_name_resolves_to_that_instance() {
    let bytes = ask(
        "1.api.tardigrade.internal",
        QTYPE::TYPE(simple_dns::TYPE::A),
    );
    assert_eq!(addresses(&bytes), vec![Ipv4Addr::new(10, 42, 1, 11)]);
}

// ------------------------------------------------------- The negative answers

/// The point at which the configured negative-caching TTL first takes effect.
#[test]
fn a_nodata_answer_carries_an_soa_so_negative_caching_uses_our_number() {
    let bytes = ask(
        "cache.tardigrade.internal",
        QTYPE::TYPE(simple_dns::TYPE::A),
    );
    let packet = Packet::parse(&bytes).expect("parses");

    assert_eq!(packet.rcode(), RCODE::NoError, "NODATA is no error");
    assert!(packet.answers.is_empty(), "there is no healthy instance");

    let soa = packet
        .name_servers
        .iter()
        .find(|record| matches!(record.rdata, RData::SOA(_)))
        .expect("without an SOA the resolver caches its own deadline");

    assert_eq!(soa.ttl, NEGATIVE_TTL_SECONDS);
    match &soa.rdata {
        RData::SOA(inner) => assert_eq!(inner.minimum, NEGATIVE_TTL_SECONDS),
        other => panic!("no SOA: {other:?}"),
    }
}

/// An unknown name in the zone answers NXDOMAIN, and the answer carries an
/// SOA record too.
#[test]
fn an_unknown_name_answers_nxdomain_with_an_soa() {
    let bytes = ask(
        "does-not-exist.tardigrade.internal",
        QTYPE::TYPE(simple_dns::TYPE::A),
    );
    let packet = Packet::parse(&bytes).expect("parses");

    assert_eq!(packet.rcode(), RCODE::NameError);
    assert!(
        packet
            .name_servers
            .iter()
            .any(|record| matches!(record.rdata, RData::SOA(_))),
        "NXDOMAIN needs the SOA too"
    );
}

/// A client asks A **and** AAAA. If an NXDOMAIN came for AAAA, it would conclude
/// that the name does not exist — and would not even issue the A query.
#[test]
fn an_aaaa_query_for_a_known_name_is_nodata_not_nxdomain() {
    let bytes = ask(
        "api.tardigrade.internal",
        QTYPE::TYPE(simple_dns::TYPE::AAAA),
    );
    let packet = Packet::parse(&bytes).expect("parses");

    assert_eq!(packet.rcode(), RCODE::NoError);
    assert!(packet.answers.is_empty());
}

/// A name outside the zone is refused.
#[test]
fn a_name_outside_the_zone_is_refused() {
    let bytes = ask("example.com", QTYPE::TYPE(simple_dns::TYPE::A));
    let packet = Packet::parse(&bytes).expect("parses");

    assert_eq!(packet.rcode(), RCODE::Refused);
    assert!(packet.answers.is_empty());
}

// -------------------------------------------------------------- What is refused

/// One does not answer an answer — otherwise two resolvers egg each other on
/// when one enters the other as its server.
#[test]
fn a_response_is_never_answered() {
    let mut packet = Packet::new_reply(1);
    packet.questions.push(Question::new(
        Name::new("api.tardigrade.internal").expect("valid"),
        QTYPE::TYPE(simple_dns::TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let bytes = packet.build_bytes_vec().expect("serializable");

    assert!(matches!(
        resolver().respond(&bytes, UDP_LIMIT),
        Verdict::Silence
    ));
}

/// A message with a non-query opcode answers NOTIMP.
#[test]
fn a_query_that_is_not_a_query_answers_notimp() {
    let mut packet = Packet::new_query(2);
    *packet.opcode_mut() = OPCODE::Update;
    let bytes = packet.build_bytes_vec().expect("serializable");

    let Verdict::Reply(answer) = resolver().respond(&bytes, UDP_LIMIT) else {
        panic!("that gets an answer");
    };
    assert_eq!(
        Packet::parse(&answer).expect("parses").rcode(),
        RCODE::NotImplemented
    );
}

/// A query without a question section answers FORMERR.
#[test]
fn a_query_without_a_question_answers_formerr() {
    let bytes = Packet::new_query(3)
        .build_bytes_vec()
        .expect("serializable");

    let Verdict::Reply(answer) = resolver().respond(&bytes, UDP_LIMIT) else {
        panic!("that gets an answer");
    };
    assert_eq!(
        Packet::parse(&answer).expect("parses").rcode(),
        RCODE::FormatError
    );
}

/// Another class is no query to us. `CHAOS` is the classic (`version.bind`) —
/// and information we do not give.
#[test]
fn a_query_in_another_class_is_refused() {
    let mut packet = Packet::new_query(4);
    packet.questions.push(Question::new(
        Name::new("version.bind").expect("valid"),
        QTYPE::TYPE(simple_dns::TYPE::TXT),
        QCLASS::CLASS(CLASS::CH),
        false,
    ));
    let bytes = packet.build_bytes_vec().expect("serializable");

    let Verdict::Reply(answer) = resolver().respond(&bytes, UDP_LIMIT) else {
        panic!("that gets an answer");
    };
    assert_eq!(
        Packet::parse(&answer).expect("parses").rcode(),
        RCODE::Refused
    );
}

/// Unparseable bytes get no answer at all — the resolver stays silent rather
/// than guess at a reply.
#[test]
fn unparseable_bytes_get_no_answer_at_all() {
    for garbage in [
        vec![],
        vec![0x00],
        vec![0xff; 3],
        vec![0x47, 0x11],
        b"HTTP/1.1 200 OK".to_vec(),
    ] {
        assert!(
            matches!(resolver().respond(&garbage, UDP_LIMIT), Verdict::Silence),
            "{garbage:?} was answered"
        );
    }
}

// ---------------------------------------------------------------- Truncation

/// What does not fit into a UDP packet is truncated and **marked**. The client
/// then asks again over TCP — that is why the TCP way has to exist.
#[test]
fn an_answer_too_large_for_udp_is_truncated_and_marked() {
    let many: Vec<Endpoint> = (0..200)
        .map(|instance| Endpoint {
            workload: "wide".to_owned(),
            instance,
            #[allow(clippy::cast_possible_truncation)]
            address: Ipv4Addr::new(10, 42, 1, instance as u8),
            health: Health::Healthy,
        })
        .collect();

    let resolver = Resolver::new(Registry::new(Domain::new(ZONE).expect("valid"), many));
    let Verdict::Reply(bytes) = resolver.respond(
        &query("wide.tardigrade.internal", QTYPE::TYPE(simple_dns::TYPE::A)),
        UDP_LIMIT,
    ) else {
        panic!("answer");
    };

    assert!(
        bytes.len() <= UDP_LIMIT,
        "the answer bursts the UDP packet: {} bytes",
        bytes.len()
    );

    let packet = Packet::parse(&bytes).expect("parses");
    assert!(packet.has_flags(PacketFlag::TRUNCATION), "TC missing");
}

/// Over TCP the same answer fits whole.
#[test]
fn over_tcp_the_same_answer_fits_whole() {
    let many: Vec<Endpoint> = (0..200)
        .map(|instance| Endpoint {
            workload: "wide".to_owned(),
            instance,
            #[allow(clippy::cast_possible_truncation)]
            address: Ipv4Addr::new(10, 42, 1, instance as u8),
            health: Health::Healthy,
        })
        .collect();

    let resolver = Resolver::new(Registry::new(Domain::new(ZONE).expect("valid"), many));
    let Verdict::Reply(bytes) = resolver.respond(
        &query("wide.tardigrade.internal", QTYPE::TYPE(simple_dns::TYPE::A)),
        tg_net::resolver::TCP_LIMIT,
    ) else {
        panic!("answer");
    };

    let packet = Packet::parse(&bytes).expect("parses");
    assert!(!packet.has_flags(PacketFlag::TRUNCATION), "TC set");
    assert_eq!(packet.answers.len(), 200);
}
