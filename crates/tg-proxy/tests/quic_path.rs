//! The QUIC egress path, end to end (ADR-0094).
//!
//! ```text
//!   netns tg-quicpath
//!     container ──► 10.42.1.9:443/udp
//!            │  nft redirect **without a port setting** (output)
//!            ▼
//!     sidecar :443/udp  ──IP_RECVORIGDSTADDR──► port 443
//!            │  the SNI from the Initial, against the allowlist (ADR-0041/0092)
//!            ▼
//!     endpoint — the bytes **unchanged**, without terminating
//! ```
//!
//! The container **never** dials a sidecar port, and `443` stands nowhere in
//! its line. That the datagrams nevertheless arrive at the endpoint is the
//! whole substantiation.
//!
//! The Initials are recordings from `curl --http3-only` over ngtcp2 with
//! OpenSSL 3.5 (`data/PROVENANCE.md`) -- foreign code, and both are needed: the
//! `ClientHello` does not fit into one.
//!
//! `#[ignore]`: demands `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `nft` and `ip` --
//! run with `cargo xtask net`.

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use tg_proxy::egress::{EgressPolicy, Resolver, SharedEgress, Transport};

/// The address the container dials -- in the cluster network.
const PEER: &str = "10.42.1.9";
/// The port it means.
const PORT: u16 = 443;
/// The name in its `ClientHello`.
const NAME: &str = "s3.example.com";

const NAMED: [&[u8]; 2] = [
    include_bytes!("data/named_0.bin"),
    include_bytes!("data/named_1.bin"),
];

fn sh(args: &[&str]) {
    let status = std::process::Command::new(args[0])
        .args(&args[1..])
        .status()
        .unwrap_or_else(|err| panic!("{} must be startable: {err}", args[0]));
    assert!(status.success(), "{args:?} failed");
}

struct Netns(String);

impl Netns {
    fn create(tag: &str) -> Self {
        let name = format!("tg-quicpath-{tag}");
        let _ = tg_syscall::netns::delete(&name);
        tg_syscall::netns::create(&name).expect("lay the namespace out");

        for args in [
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "set", "lo", "up",
            ],
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "add", "name", "q0", "type", "dummy",
            ],
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "set", "q0", "up",
            ],
        ] {
            sh(&args);
        }
        for address in ["10.42.1.2", PEER] {
            sh(&[
                "ip",
                "netns",
                "exec",
                &name,
                "ip",
                "addr",
                "add",
                &format!("{address}/24"),
                "dev",
                "q0",
            ]);
        }

        Self(name)
    }

    fn name(&self) -> &str {
        &self.0
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        let _ = tg_syscall::netns::delete(&self.0);
    }
}

/// The redirection as the agent lays it -- **without** a port setting.
fn redirect(netns: &str) {
    let cluster =
        tg_net::ipam::ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24).expect("valid");
    let subnet = cluster.subnet(1).expect("valid");
    let json = tg_net::rules::to_json(
        // **Not 0**: the test process runs as root and would otherwise hit
        // the exception for the sidecar -- it would not be redirected at all,
        // and the test would prove nothing. The real identifier (ADR-0060) at
        // the same time holds fast that root **in** the container is not
        // exempt either.
        &tg_net::rules::NetnsRules::new(&cluster, &subnet, 65532)
            .with_quic(&[PORT])
            .render(),
    )
    .expect("serializable");
    tg_net::nft::apply_in(netns, &json).expect("the namespace rule set");
}

/// **The container reaches its endpoint without ever naming a sidecar
/// port.**
///
/// And without `443` standing in a route list: the port comes from the kernel
/// (ADR-0051/0094), the name from the `ClientHello` (ADR-0041).
///
/// **Both datagrams must arrive**, and that is the second assurance: the first
/// already lies there at the time of the decision and must be delivered
/// afterwards (ADR-0092, determination 4). A relay that forwards only from the
/// decision on would rob every client with post-quantum key shares of its
/// handshake.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN, nft and ip; cargo xtask net"]
fn a_container_reaches_its_endpoint_through_the_sidecar() {
    let seen = carry(NAME, "through");

    assert_eq!(
        seen.len(),
        2,
        "both datagrams of the handshake must arrive at the endpoint"
    );
    assert_eq!(seen[0], NAMED[0], "the bytes are not unchanged");
    assert_eq!(seen[1], NAMED[1]);
}

/// **Without a permission nothing arrives** -- the counter-check with an
/// otherwise identical setup.
///
/// Only the name in the allowlist is a different one. Without this test the
/// first would show merely that some way exists, and not that ADR-0041 applies
/// on it.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN, nft and ip; cargo xtask net"]
fn without_a_permission_nothing_arrives() {
    assert!(
        carry("other.example", "deny").is_empty(),
        "without a permission nothing may go out (ADR-0041)"
    );
}

/// Runs the path and gives back what arrived at the endpoint.
fn carry(allowed: &str, tag: &str) -> Vec<Vec<u8>> {
    let netns = Netns::create(tag);
    redirect(netns.name());

    let (ready, wait) = std::sync::mpsc::channel();
    let allowed = allowed.to_owned();
    let name = netns.name().to_owned();

    // **One runtime, one thread.** `run_in` enters the calling thread's
    // namespace; a multi-threaded runtime would lay its workers beside it into
    // the host namespace (the finding from `egress_netns.rs`).
    let worker = std::thread::spawn(move || {
        let _ = tg_syscall::netns::run_in(&name, move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the runtime");

            runtime.block_on(async move {
                // The "endpoint": it does not answer, it only remembers.
                //
                // **A `tokio` socket, no blocking one.** A
                // `std::net::UdpSocket::recv_from` halts the single-thread
                // runtime on which the relay is to run -- the test then waited
                // for a service to which it had itself denied execution (the
                // finding from 11b, here for the third time).
                let endpoint = tokio::net::UdpSocket::bind("127.0.0.1:0")
                    .await
                    .expect("the endpoint");
                let address: SocketAddr = endpoint.local_addr().expect("the address");

                let policy = SharedEgress::new(EgressPolicy::from_entries([(
                    allowed.clone(),
                    PORT,
                    Transport::Quic,
                )]));
                let resolver =
                    Resolver::Pinned(Arc::new(BTreeMap::from([(NAME.to_owned(), address)])));

                let socket = tg_proxy::quic_egress::listener(PORT).expect("the listener");
                tokio::spawn(tg_proxy::quic_egress::serve(
                    socket,
                    policy,
                    resolver,
                    Arc::new(tg_proxy::quic_egress::Budget::default()),
                    std::future::pending(),
                ));

                // The "container": it dials the peer's address.
                let container = UdpSocket::bind("0.0.0.0:0").expect("the container");
                for datagram in NAMED {
                    container
                        .send_to(datagram, format!("{PEER}:{PORT}"))
                        .expect("send");
                    tokio::time::sleep(Duration::from_millis(80)).await;
                }

                let mut seen = Vec::new();
                let mut buffer = vec![0_u8; 65_535];
                while let Ok(Ok((read, _))) =
                    tokio::time::timeout(Duration::from_secs(3), endpoint.recv_from(&mut buffer))
                        .await
                {
                    seen.push(buffer[..read].to_vec());
                    if seen.len() == 2 {
                        break;
                    }
                }

                let _ = ready.send(seen);
            });
        });
    });

    let seen = wait
        .recv_timeout(Duration::from_secs(20))
        .expect("the setup in the namespace did not come up");
    drop(worker);

    seen
}
