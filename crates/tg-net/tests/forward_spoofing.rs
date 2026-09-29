//! The forwarder takes only its upstream's answer.
//!
//! Three properties carry the forwarder's security: a time bound, a socket of
//! its own per query (a shared socket would let cache poisoning take hold), and
//! **the source is checked**.
//!
//! The third property needs a test of its own: `forwarding.rs` checks only the
//! *verdict* (`Verdict::Forward`), not the forwarding itself, and
//! `dns_interop.rs` runs the normal case. Neither would go red if the source
//! check (`from != upstream`) were removed.
//!
//! # How the forgery is staged
//!
//! The forwarder binds a socket **of its own** with an ephemeral port per
//! query — an attacker would have to guess it. In the test the real upstream
//! suffices as an observer: it sees the query and thereby the port, and a
//! **third** socket sends the forged answer there. That is the attacker who has
//! guessed right.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use simple_dns::rdata::{A, RData};
use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, ResourceRecord};
use tg_net::discovery::{Domain, Endpoint, Health, Registry};
use tg_net::resolver::{Forwarding, Resolver, serve_udp};
use tokio::net::UdpSocket;

const ZONE: &str = "tardigrade.internal";
/// The address that stands **only** in the forgery.
const FORGED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 66);

/// Builds the fixture registry served by the forwarder under test.
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

/// Builds a query as a client sends it.
///
/// # Parameters
/// - `name`: the queried name.
///
/// # Returns
/// The serialized query bytes.
fn query(name: &str) -> Vec<u8> {
    let mut packet = Packet::new_query(0x4711);
    packet.questions.push(Question::new(
        Name::new(name).expect("valid name"),
        QTYPE::TYPE(simple_dns::TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    packet.build_bytes_vec().expect("serializable")
}

/// An answer as an upstream sends it — with `address` as its content.
///
/// # Parameters
/// - `question`: the serialized query bytes being answered.
/// - `address`: the address to place in the answer record.
///
/// # Returns
/// The serialized answer bytes.
fn answer(question: &[u8], address: Ipv4Addr) -> Vec<u8> {
    let asked = Packet::parse(question).expect("question parses");
    let mut reply = Packet::new_reply(asked.id());
    let name = asked.questions[0].qname.clone();
    reply.questions.push(asked.questions[0].clone());
    reply.answers.push(ResourceRecord::new(
        name,
        CLASS::IN,
        60,
        RData::A(A {
            address: u32::from(address),
        }),
    ));
    reply.build_bytes_vec().expect("serializable")
}

/// **An answer from the wrong address is not passed on.**
///
/// The real upstream stays silent; only the forger answers, and to the right
/// port at that. What the client may see is everything except the forged
/// address — as a rule, nothing at all.
#[tokio::test]
async fn a_reply_from_a_foreign_source_is_ignored() {
    // The upstream: it receives and does **not** answer.
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");
    let upstream_addr = upstream.local_addr().expect("address");

    let resolver = Resolver::new(registry());
    resolver.forward_to(Forwarding::new(vec!["s3.example.com".to_owned()]));
    let served = Arc::new(resolver);

    let front = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");
    let front_addr = front.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = serve_udp(served, std::sync::Arc::new(front), Some(upstream_addr)).await;
    });

    // The forger: a **third** socket that never saw the query.
    let forger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");
    let question = query("s3.example.com");
    client.send_to(&question, front_addr).await.expect("query");

    // The upstream sees the query — and thereby the port the forwarder uses. In
    // operation an attacker would have to guess it; here they get it for free,
    // so that the test measures the **source check** and not the probability of
    // guessing.
    let mut seen = vec![0_u8; 512];
    let (len, from) = tokio::time::timeout(Duration::from_secs(5), upstream.recv_from(&mut seen))
        .await
        .expect("the forwarder has to ask")
        .expect("query");

    forger
        .send_to(&answer(&seen[..len], FORGED), from)
        .await
        .expect("forgery");

    // What now arrives at the client must not contain the forged address. As a
    // rule it is silence.
    let mut back = vec![0_u8; 512];
    let arrived = tokio::time::timeout(Duration::from_secs(4), client.recv_from(&mut back)).await;

    if let Ok(Ok((len, _))) = arrived {
        let packet = Packet::parse(&back[..len]).expect("answer parses");
        for record in &packet.answers {
            assert!(
                !matches!(&record.rdata, RData::A(a) if a.address == u32::from(FORGED)),
                "the forged address reached the client"
            );
        }
    }
}

/// The counter-check: the **upstream's** answer gets through.
///
/// Without it the test above would show green even if the forwarder passed
/// nothing on at all — and then it would check nothing.
#[tokio::test]
async fn the_reply_of_the_real_upstream_gets_through() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");
    let upstream_addr = upstream.local_addr().expect("address");

    let resolver = Resolver::new(registry());
    resolver.forward_to(Forwarding::new(vec!["s3.example.com".to_owned()]));
    let served = Arc::new(resolver);

    let front = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");
    let front_addr = front.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = serve_udp(served, std::sync::Arc::new(front), Some(upstream_addr)).await;
    });

    tokio::spawn(async move {
        let mut seen = vec![0_u8; 512];
        if let Ok((len, from)) = upstream.recv_from(&mut seen).await {
            let _ = upstream.send_to(&answer(&seen[..len], FORGED), from).await;
        }
    });

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("socket");
    client
        .send_to(&query("s3.example.com"), front_addr)
        .await
        .expect("query");

    let mut back = vec![0_u8; 512];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut back))
        .await
        .expect("the real answer has to get through")
        .expect("answer");

    let packet = Packet::parse(&back[..len]).expect("answer parses");
    assert!(
        packet
            .answers
            .iter()
            .any(|record| matches!(&record.rdata, RData::A(a) if a.address == u32::from(FORGED))),
        "the upstream's answer has to be passed on"
    );
}
