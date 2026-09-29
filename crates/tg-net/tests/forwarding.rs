//! The forwarding of permitted names.
//!
//! This resolver is deliberately **no** general forwarder — a resolver in the
//! mesh that resolves arbitrary names is an open resolver. It takes exactly
//! one exception from that: names that stand on the egress allowlist of a
//! workload of this node.
//!
//! # The boundary is the whole point
//!
//! With that the allowlist is at the same time the forwarding list. What does
//! not stand on it stays `REFUSED` — and that is the difference between an
//! exception and an open resolver. The tests here therefore check above all
//! the **non**-forwarding.
//!
//! And what does not follow from it: DNS is no trust boundary for the
//! enforcement — that lies at the egress sidecar's SNI check. The forwarding
//! only sees to it that a connection can come about at all.

use std::net::Ipv4Addr;

use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, RCODE};
use tg_net::discovery::{Domain, Endpoint, Health, Registry};
use tg_net::resolver::{Forwarding, Resolver, UDP_LIMIT, Verdict};

const ZONE: &str = "tardigrade.internal";

/// Builds the fixture registry for the internal zone under test.
///
/// # Returns
/// The constructed registry for `tardigrade.internal`.
fn registry() -> Registry {
    Registry::new(
        Domain::new(ZONE).expect("valid"),
        vec![Endpoint {
            workload: "api".to_owned(),
            instance: 0,
            address: Ipv4Addr::new(10, 42, 1, 10),
            health: Health::Healthy,
        }],
    )
}

/// Builds a serialized DNS query for the given name and record type.
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

/// Parses a DNS answer and extracts its response code.
///
/// # Parameters
/// - `bytes`: the serialized DNS answer.
///
/// # Returns
/// The answer's response code.
///
/// # Panics
/// Panics if `bytes` does not parse as a DNS message.
fn rcode(bytes: &[u8]) -> RCODE {
    Packet::parse(bytes).expect("answer must parse").rcode()
}

/// A resolver with a forwarding list.
///
/// # Parameters
/// - `names`: the names permitted to be forwarded.
///
/// # Returns
/// The constructed resolver.
fn with_allowed(names: &[&str]) -> Resolver {
    let resolver = Resolver::new(registry());
    resolver.forward_to(Forwarding::new(
        names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>(),
    ));
    resolver
}

// --- Forwarded is what is permitted ----------------------------------------

/// A name on the allowlist is forwarded.
#[test]
fn an_allowed_name_is_forwarded() {
    let resolver = with_allowed(&["s3.example.com"]);

    let verdict = resolver.respond(
        &query("s3.example.com", QTYPE::TYPE(simple_dns::TYPE::A)),
        UDP_LIMIT,
    );

    assert!(
        matches!(verdict, Verdict::Forward),
        "expected Forward, was {verdict:?}"
    );
}

/// The letter case does not decide: DNS names are independent of it.
///
/// The same principle applies to the SNI the egress sidecar reads —
/// `rustls` returns it lowercased, and a list that checks for byte equality
/// could be bypassed with a capital letter. Here it is the other direction:
/// the asker chooses the letter case.
#[test]
fn the_allowlist_ignores_letter_case() {
    let resolver = with_allowed(&["s3.example.com"]);

    for name in ["S3.EXAMPLE.COM", "s3.Example.Com", "S3.example.com"] {
        let verdict = resolver.respond(&query(name, QTYPE::TYPE(simple_dns::TYPE::A)), UDP_LIMIT);
        assert!(
            matches!(verdict, Verdict::Forward),
            "'{name}' should have been forwarded, was {verdict:?}"
        );
    }
}

/// A trailing dot is the same name (RFC 1035: the root).
#[test]
fn a_trailing_dot_is_the_same_name() {
    let resolver = with_allowed(&["s3.example.com"]);

    let verdict = resolver.respond(
        &query("s3.example.com.", QTYPE::TYPE(simple_dns::TYPE::A)),
        UDP_LIMIT,
    );

    assert!(
        matches!(verdict, Verdict::Forward),
        "expected Forward, was {verdict:?}"
    );
}

// --- And nothing else -------------------------------------------------------

/// **Without a list nothing is forwarded.** That is the default state and
/// must stay the state as long as nobody has permitted anything.
#[test]
fn without_an_allowlist_nothing_is_forwarded() {
    let resolver = Resolver::new(registry());

    let verdict = resolver.respond(
        &query("s3.example.com", QTYPE::TYPE(simple_dns::TYPE::A)),
        UDP_LIMIT,
    );

    match verdict {
        Verdict::Reply(bytes) => assert_eq!(rcode(&bytes), RCODE::Refused),
        other => panic!("expected Refused, was {other:?}"),
    }
}

/// **A foreign name stays `REFUSED`, even when the list is not empty.**
///
/// Here it is decided whether this server is an open resolver.
#[test]
fn a_name_outside_the_allowlist_stays_refused() {
    let resolver = with_allowed(&["s3.example.com"]);

    for name in [
        "evil.example.com",
        "example.com",
        "com",
        "s3.example.com.evil.test",
    ] {
        let verdict = resolver.respond(&query(name, QTYPE::TYPE(simple_dns::TYPE::A)), UDP_LIMIT);
        match verdict {
            Verdict::Reply(bytes) => assert_eq!(
                rcode(&bytes),
                RCODE::Refused,
                "'{name}' should have been refused"
            ),
            other => panic!("'{name}': expected Refused, was {other:?}"),
        }
    }
}

/// **A prefix is no name, and a suffix is none either.**
///
/// `s3.example.com` on the list does not permit `xs3.example.com` and not
/// `s3.example.com.attacker.test`. A comparison with `ends_with` would shift
/// the boundary by every domain that ends in a permitted one — the same
/// mistake that would let `internaltardigrade.internal` be treated as if it
/// lay inside the zone `tardigrade.internal`, merely because it ends with
/// that string.
#[test]
fn neither_a_prefix_nor_a_suffix_counts_as_the_name() {
    let resolver = with_allowed(&["s3.example.com"]);

    for name in [
        "xs3.example.com",
        "s3.example.common",
        "not-s3.example.com",
        "s3.example.com.attacker.test",
    ] {
        let verdict = resolver.respond(&query(name, QTYPE::TYPE(simple_dns::TYPE::A)), UDP_LIMIT);
        match verdict {
            Verdict::Reply(bytes) => assert_eq!(
                rcode(&bytes),
                RCODE::Refused,
                "'{name}' is not the permitted name"
            ),
            other => panic!("'{name}': expected Refused, was {other:?}"),
        }
    }
}

/// A name **in** our own zone is never forwarded, even if it happens to stand on
/// the list. The zone is authoritative.
#[test]
fn a_name_in_our_own_zone_is_never_forwarded() {
    let resolver = with_allowed(&[&format!("api.{ZONE}"), &format!("missing.{ZONE}")]);

    // A known name: a normal answer.
    let verdict = resolver.respond(
        &query(&format!("api.{ZONE}"), QTYPE::TYPE(simple_dns::TYPE::A)),
        UDP_LIMIT,
    );
    match verdict {
        Verdict::Reply(bytes) => assert_eq!(rcode(&bytes), RCODE::NoError),
        other => panic!("expected an answer, was {other:?}"),
    }

    // An unknown name in the zone: NXDOMAIN, **not** forwarded. Otherwise this
    // server would ask outside about its own services.
    let verdict = resolver.respond(
        &query(&format!("missing.{ZONE}"), QTYPE::TYPE(simple_dns::TYPE::A)),
        UDP_LIMIT,
    );
    match verdict {
        Verdict::Reply(bytes) => assert_eq!(rcode(&bytes), RCODE::NameError),
        other => panic!("expected NXDOMAIN, was {other:?}"),
    }
}

/// A list that is withdrawn takes effect at once — the control-plane update
/// that carries the allowlist can revoke a permission just as it grants one.
#[test]
fn withdrawing_the_allowlist_takes_effect() {
    let resolver = with_allowed(&["s3.example.com"]);
    assert!(matches!(
        resolver.respond(
            &query("s3.example.com", QTYPE::TYPE(simple_dns::TYPE::A)),
            UDP_LIMIT
        ),
        Verdict::Forward
    ));

    resolver.forward_to(Forwarding::none());

    match resolver.respond(
        &query("s3.example.com", QTYPE::TYPE(simple_dns::TYPE::A)),
        UDP_LIMIT,
    ) {
        Verdict::Reply(bytes) => assert_eq!(rcode(&bytes), RCODE::Refused),
        other => panic!("expected Refused, was {other:?}"),
    }
}

/// Non-A queries for a permitted name are forwarded too.
///
/// A client asks A **and** AAAA. Forwarding only A would mean giving it a
/// `REFUSED` for AAAA — and some resolver libraries read that as an error of the
/// whole resolution, not as "no AAAA".
#[test]
fn other_record_types_for_an_allowed_name_are_forwarded_too() {
    let resolver = with_allowed(&["s3.example.com"]);

    for qtype in [
        QTYPE::TYPE(simple_dns::TYPE::AAAA),
        QTYPE::TYPE(simple_dns::TYPE::CNAME),
        QTYPE::TYPE(simple_dns::TYPE::TXT),
    ] {
        let verdict = resolver.respond(&query("s3.example.com", qtype), UDP_LIMIT);
        assert!(
            matches!(verdict, Verdict::Forward),
            "{qtype:?} should have been forwarded, was {verdict:?}"
        );
    }
}

/// Unreadable bytes are not forwarded but discarded.
///
/// Otherwise this server would be an amplifier: it would send garbage to an
/// upstream an attacker need only name.
#[test]
fn unreadable_bytes_are_never_forwarded() {
    let resolver = with_allowed(&["s3.example.com"]);

    for bad in [&b""[..], b"\x00", b"not DNS", &[0xFF; 40]] {
        let verdict = resolver.respond(bad, UDP_LIMIT);
        assert!(
            !matches!(verdict, Verdict::Forward),
            "{bad:?} must not have been forwarded"
        );
    }
}

/// **A wildcard forwards the bucket, and only it.**
///
/// # Why this stands here and not only at the sidecar
///
/// Both sides compare exactly, and that is why a wildcard entry once cost
/// **two** silent failures at once: the target was not permitted, and the
/// name was not forwarded. The container thereby saw no TLS error but a DNS
/// error — the diagnosis pointed at the resolver instead of at the
/// permission.
///
/// Both places share **one** function (`tg_model::egress::target_allows`).
/// This witness holds fast that it is really used here; two separate
/// implementations would be two opportunities to differ.
#[test]
fn a_wildcard_forwards_the_bucket_and_only_the_bucket() {
    let forwarding = Forwarding::new(["*.s3.example.com".to_owned()]);

    assert!(forwarding.allows("mybucket.s3.example.com"));
    assert!(
        forwarding.allows("MYBUCKET.S3.Example.COM"),
        "DNS is independent of letter case — here the asker chooses it"
    );

    assert!(
        !forwarding.allows("a.b.s3.example.com"),
        "exactly one label"
    );
    assert!(!forwarding.allows("s3.example.com"), "not the name itself");
    assert!(
        !forwarding.allows("mybucket.s3.example.com.evil.net"),
        "no suffix comparison — matching a suffix would let an attacker's domain pass"
    );
}
