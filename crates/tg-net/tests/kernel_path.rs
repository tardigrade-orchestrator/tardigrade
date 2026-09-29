//! The kernel path on real packets.
//!
//! This file substantiates three properties: containers reach each other in
//! conformity with the rules, the redirect to the sidecar works, and no BPF
//! program is loaded. Everything in it runs against the real kernel: real
//! namespaces, real veth pairs, a real bridge, a real `nft` and real TCP
//! connections. That is `#[ignore]`, because it demands `CAP_NET_ADMIN` and
//! `CAP_SYS_ADMIN` — run with `cargo xtask net`.
//!
//! # The setup
//!
//! ```text
//!   netns tg-a (10.42.1.2)          netns tg-b (10.42.1.3)
//!        eth0                             eth0
//!          |                                |
//!      tg<hex>  ------  tg0 (10.42.1.1)  ------  tg<hex>
//! ```
//!
//! # What the redirect test proves, and what it does not
//!
//! Every rejection and redirection case is checked against the **same** setup,
//! in which exactly **one** thing is different — the user identifier in the
//! exception rule. Otherwise a pair of tests would prove merely that something
//! has changed.
//!
//! # A property one has to know
//!
//! Two containers on **one** node in the same subnet talk over L2. Their
//! traffic does not pass through the `forward` chain at all — that would need
//! `br_netfilter`, and that is a module this orchestrator does not demand. So
//! the filter rules take effect for routed traffic: out of the cluster and
//! (from the `WireGuard` underlay on) between nodes. That is no gap but a
//! deliberate division of labour: **who may talk to whom is decided by the
//! certificate in the sidecar, not by the address in the packet filter.**

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use tg_net::ipam::{ClusterNet, Leases, Mtu, NodeSubnet, host_link};
use tg_net::rules::{HostRules, NetnsRules, SIDECAR_EGRESS, SIDECAR_INBOUND, SIDECAR_OUTBOUND};
use tg_net::{link, nft};

const ZONE: &str = "10.42.0.0/16";
/// A port on which **nothing** listens in the target namespace.
const NOWHERE: u16 = 8080;

/// Builds the fixture cluster network used by this file's tests.
///
/// # Returns
/// The cluster network for `10.42.0.0/16`, split into `/24` node subnets.
fn cluster() -> ClusterNet {
    ClusterNet::new(ZONE.parse().expect("valid"), 24).expect("valid")
}

/// Builds the fixture node subnet used by this file's tests.
///
/// # Returns
/// Node subnet 1 of the fixture cluster network.
fn subnet() -> NodeSubnet {
    cluster().subnet(1).expect("valid")
}

/// Clears everything away again, even when a test fails.
struct Fixture {
    names: Vec<String>,
    links: Vec<tg_net::ipam::LinkName>,
}

impl Drop for Fixture {
    /// Removes the namespaces and detaches the host-side links created for the
    /// test, best-effort.
    fn drop(&mut self) {
        for name in &self.names {
            let _ = tg_syscall::netns::delete(name);
        }
        for host in &self.links {
            let _ = link::detach(host);
        }
    }
}

/// Builds two instances on the network and returns their addresses.
///
/// # Parameters
/// - `tag`: a short tag used to derive unique namespace names.
///
/// # Returns
/// A cleanup fixture, the first namespace and its address, and the second
/// namespace and its address.
fn two_containers(tag: &str) -> (Fixture, String, Ipv4Addr, String, Ipv4Addr) {
    let mtu = Mtu::for_overlay(1500).expect("1500 carries").get();
    let subnet = subnet();

    let mut leases = Leases::new(subnet.clone());
    let api = leases.lease("api", 0).expect("room enough");
    let ledger = leases.lease("ledger", 0).expect("room enough");

    let ns_api = format!("tg-{tag}-a");
    let ns_ledger = format!("tg-{tag}-b");

    let mut fixture = Fixture {
        names: vec![ns_api.clone(), ns_ledger.clone()],
        links: vec![host_link(api), host_link(ledger)],
    };
    // A remnant of an aborted run must not disturb the next one.
    for name in &fixture.names {
        let _ = tg_syscall::netns::delete(name);
    }
    for host in &fixture.links {
        let _ = link::detach(host);
    }

    link::ensure_bridge(&subnet, mtu).expect("bridge");

    for (name, address) in [(&ns_api, api), (&ns_ledger, ledger)] {
        tg_syscall::netns::create(name).expect("namespace");
        link::attach(name, &host_link(address), address, &subnet, mtu).expect("attach");
    }

    nft::apply(
        &tg_net::rules::to_json(&HostRules::new(&cluster(), &subnet).render())
            .expect("serializable"),
    )
    .expect("host rule set");

    fixture.links.sort_by_key(|l| l.as_str().to_owned());
    (fixture, ns_api, api, ns_ledger, ledger)
}

/// A listener **in** the namespace. The socket keeps the namespace in which it
/// was bound — accepting can be done from anywhere.
///
/// # Parameters
/// - `netns`: the namespace to bind in.
/// - `port`: the port to listen on.
///
/// # Returns
/// The bound listener.
///
/// # Panics
/// Panics if the namespace cannot be entered or the port cannot be bound.
fn listen_in(netns: &str, port: u16) -> TcpListener {
    tg_syscall::netns::run_in(netns, move || {
        TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
    })
    .expect("enter namespace")
    .expect("bind")
}

/// A connection **out of** a namespace.
///
/// # Parameters
/// - `netns`: the namespace to connect from.
/// - `to`: the address to connect to.
///
/// # Returns
/// The connected stream.
///
/// # Errors
/// Returns an error if the connection attempt fails or times out.
///
/// # Panics
/// Panics if the namespace cannot be entered.
fn connect_from(netns: &str, to: SocketAddr) -> std::io::Result<TcpStream> {
    tg_syscall::netns::run_in(netns, move || {
        TcpStream::connect_timeout(&to, Duration::from_secs(2))
    })
    .expect("enter namespace")
}

/// Accepts a connection and sends a mark back.
///
/// # Parameters
/// - `listener`: the listener to accept one connection from.
/// - `mark`: the bytes to write back to the accepted connection.
///
/// # Returns
/// A handle to the thread serving the single connection.
fn serve_once(listener: TcpListener, mark: &'static str) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(mark.as_bytes());
        }
    })
}

/// Reads whatever a peer sends until it closes the connection.
///
/// # Parameters
/// - `stream`: the connection to read from.
///
/// # Returns
/// The bytes read, decoded as UTF-8; empty if nothing arrived in time.
fn read_mark(mut stream: TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("deadline");
    let mut buffer = String::new();
    let _ = stream.read_to_string(&mut buffer);
    buffer
}

// ============================================================ Criterion 1

/// **Containers reach each other in conformity with the rules.**
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn two_containers_on_a_node_reach_each_other() {
    let (_fixture, ns_api, _api, ns_ledger, ledger) = two_containers("reach");

    let listener = listen_in(&ns_ledger, 9000);
    let server = serve_once(listener, "ledger");

    let stream =
        connect_from(&ns_api, SocketAddr::from((ledger, 9000))).expect("api has to reach ledger");
    assert_eq!(read_mark(stream), "ledger");

    server.join().expect("listener");
}

/// The counter-check: a port on which nothing listens is refused — not
/// swallowed silently. Without this test the one above would prove only that
/// *something* answers.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn a_port_nobody_listens_on_is_refused() {
    let (_fixture, ns_api, _api, _ns_ledger, ledger) = two_containers("refuse");

    let err = connect_from(&ns_api, SocketAddr::from((ledger, NOWHERE)))
        .expect_err("nobody listens there");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "expected 'refused', was {err:?}"
    );
}

/// The container reaches its gateway — as far as it is up to us.
///
/// **A measured finding that concerns operators.**
///
/// On the machine on which this test arose, `firewalld` runs, and its
/// `filter_INPUT` ends with `reject with icmpx admin-prohibited`. The container
/// therefore does **not** reach the gateway — and our rule set can change
/// nothing about it: in netfilter all base chains of a hook run, an `accept` in
/// one does not cancel a later `reject` in another. Only a terminal verdict
/// ends the evaluation, and here that falls at firewalld.
///
/// That reflects a deliberate choice recorded in `rules.rs`: we do not seize
/// the host's firewall policy, so it applies unchanged. In consequence, the
/// node-local resolver on a host with default-deny INPUT **has to be
/// released** — an operational prerequisite like `nft` itself.
///
/// What is checked is therefore what **our** layer promises: that the packet
/// arrives at the node. A `refused` or `admin-prohibited` proves exactly that —
/// somebody answered. A timeout or `ENETUNREACH` would by contrast be our
/// error: then the route would be missing.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn a_containers_packets_reach_the_node_even_if_the_host_says_no() {
    let (_fixture, ns_api, _api, _b, _ledger) = two_containers("gateway");

    let listener = TcpListener::bind(SocketAddr::from((subnet().gateway(), 9053)))
        .expect("bind on the bridge");
    let server = serve_once(listener, "node");

    match connect_from(&ns_api, SocketAddr::from((subnet().gateway(), 9053))) {
        Ok(stream) => {
            assert_eq!(read_mark(stream), "node");
            server.join().expect("listener");
        }
        Err(err) => {
            use std::io::ErrorKind::{ConnectionRefused, HostUnreachable, PermissionDenied};
            assert!(
                matches!(
                    err.kind(),
                    HostUnreachable | ConnectionRefused | PermissionDenied
                ),
                "the packet did not reach the node — that would be our layer, \
                 not the host's firewall: {err:?}"
            );
            drop(server);
        }
    }
}

// ============================================================ Criterion 2

/// **The redirect to the sidecar works.**
///
/// The connection goes to `ledger:8080`, where nobody listens. It lands
/// nevertheless — at the sidecar placeholder in its own namespace.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn outbound_traffic_is_redirected_to_the_local_sidecar() {
    let (_fixture, ns_api, _api, _ns_ledger, ledger) = two_containers("out");

    // The test process runs as uid 0. The exception applies to a **different**
    // identifier, so our traffic is redirected.
    apply_netns_rules(&ns_api, 4711);

    let sidecar = listen_in(&ns_api, SIDECAR_OUTBOUND);
    let server = serve_once(sidecar, "sidecar-out");

    let stream = connect_from(&ns_api, SocketAddr::from((ledger, NOWHERE)))
        .expect("the connection has to land at the sidecar");
    assert_eq!(
        read_mark(stream),
        "sidecar-out",
        "the traffic did not go through the sidecar"
    );

    server.join().expect("listener");
}

/// The same path, **one** thing different: the exception now applies to our own
/// identifier. The traffic goes past the sidecar — and is refused, because
/// nobody listens there.
///
/// That is the rule from `rules.rs` whose violation would be a loop.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn the_sidecars_own_traffic_is_not_redirected_back_into_itself() {
    let (_fixture, ns_api, _api, _ns_ledger, ledger) = two_containers("loop");

    // uid 0 — this test process's identifier. It plays the sidecar.
    apply_netns_rules(&ns_api, 0);

    let sidecar = listen_in(&ns_api, SIDECAR_OUTBOUND);
    let server = serve_once(sidecar, "sidecar-out");

    let err = connect_from(&ns_api, SocketAddr::from((ledger, NOWHERE)))
        .expect_err("the sidecar's traffic must not go back to it");
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);

    drop(server);
}

/// Traffic **into** the cluster is redirected, traffic outwards is not.
///
/// Egress policy is out of scope here — the authorization model in this test
/// covers only traffic between mesh members; folding egress into it would
/// anticipate a decision this test does not make.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn traffic_leaving_the_cluster_is_not_redirected() {
    let (_fixture, ns_api, _api, _b, _ledger) = two_containers("egress");
    apply_netns_rules(&ns_api, 4711);

    let sidecar = listen_in(&ns_api, SIDECAR_OUTBOUND);
    let server = serve_once(sidecar, "sidecar-out");

    // 198.51.100.0/24 is TEST-NET-2 (RFC 5737) and lies outside the cluster
    // CIDR. Nobody routes that — the connection must **not** land at the
    // sidecar.
    let outside = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), NOWHERE));
    let result = connect_from(&ns_api, outside);

    assert!(
        result.is_err(),
        "traffic outwards was redirected into the sidecar"
    );

    drop(server);
}

/// Incoming traffic lands at the sidecar, not at the workload.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn inbound_traffic_is_redirected_to_the_local_sidecar() {
    let (_fixture, ns_api, api, ns_ledger, _ledger) = two_containers("in");
    apply_netns_rules(&ns_api, 4711);

    let sidecar = listen_in(&ns_api, SIDECAR_INBOUND);
    let server = serve_once(sidecar, "sidecar-in");

    let stream = connect_from(&ns_ledger, SocketAddr::from((api, NOWHERE)))
        .expect("the connection has to land at the sidecar");
    assert_eq!(read_mark(stream), "sidecar-in");

    server.join().expect("listener");
}

/// Loads **only** the baseline into the namespace — the state after `attach`,
/// before a sidecar runs.
///
/// # Parameters
/// - `netns`: the namespace to apply the baseline ruleset in.
///
/// # Panics
/// Panics if the ruleset cannot be applied.
fn apply_baseline(netns: &str) {
    // **Not** the test process's identifier: it runs as root, and with `0` it
    // would itself be the exception for the sidecar. The real sidecar
    // identifier makes clear that root **in** the container is not exempt
    // either.
    let json = tg_net::rules::to_json(
        &NetnsRules::new(&cluster(), &subnet(), tg_model::mesh::SIDECAR_UID).render_baseline(),
    )
    .expect("serializable");
    nft::apply_in(netns, &json).expect("namespace baseline");
}

/// **Without a sidecar a workload does not reach its neighbour.**
///
/// That is the assurance for whose sake the filter chains belong to the
/// **network** and not to the sidecar. Before this, there were two ways past
/// it, and both were measured: whoever did not declare `<mesh>` got no rule
/// set at all and talked unfiltered with every container; and between the
/// start of a workload and that of its sidecar stood a **window** in which
/// the same applied.
///
/// **Both halves stand in one test**, and that is the statement: "does not
/// arrive" this test would also get if `nft` had discarded the rules or the
/// namespace looked different from what was intended. That the same baseline
/// carries the **own loopback** excludes that — and it is at the same time
/// the exception without which the sidecar does not reach its workload.
///
/// The node stands **not** in the counter-check, although it is the second
/// exception. Measured, it is unreachable in this environment **without**
/// the baseline too: on a host with default-deny INPUT a container does not
/// reach the node's services, and our rule set can change nothing about it.
/// An assurance on that would check the host's firewall, not us; that the
/// rule stands there is recorded by `rules.rs`.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn without_a_sidecar_a_workload_reaches_only_its_own_loopback() {
    let (_fixture, ns_api, _api, ns_ledger, ledger) = two_containers("baseline");
    apply_baseline(&ns_api);

    // The neighbour really listens — otherwise the rejection would prove
    // nothing.
    let neighbour = serve_once(listen_in(&ns_ledger, 8080), "ledger");
    let blocked = connect_from(&ns_api, SocketAddr::from((ledger, 8080)))
        .map(read_mark)
        .unwrap_or_default();
    drop(neighbour);

    // And the own loopback carries: there the sidecar reaches its workload, and
    // without it the instance would be dead inwards too.
    let inside = tg_syscall::netns::run_in(&ns_api, || {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let port = listener.local_addr()?.port();
        let server = serve_once(listener, "upstream");
        let mark = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_secs(2),
        )
        .map(read_mark)
        .unwrap_or_default();
        drop(server);

        Ok::<_, std::io::Error>(mark)
    })
    .expect("enter namespace")
    .expect("loopback");

    assert_eq!(
        inside, "upstream",
        "the own loopback does not carry — with that no sidecar reaches its \
         workload any more (ADR-0059)"
    );
    assert_eq!(
        blocked, "",
        "a workload without a sidecar reached a neighbour: with that the \
         authorization can be switched off by leaving <mesh> out (ADR-0093)"
    );
}

/// **The server is authoritative — over L2 too.**
///
/// Two containers on **one** node talk over the bridge and do not pass through
/// the `forward` chain (that would need `br_netfilter`). What has to apply
/// nonetheless: the baseline sits in the target instance's **input** hook and
/// therefore takes effect regardless.
///
/// The difference from the witness beside it is the **side**: there the source
/// carries the rule set and its output hook stops the packet. Here **only the
/// target** carries it — the sender is unregulated, and were the assurance
/// wrong, the packet would arrive.
///
/// That is the assurance the authorization model rests on: whoever authorizes
/// is the server. Without it the authorization could be switched off by
/// declaring the **caller** without `<mesh>`.
#[test]
#[ignore = "needs CAP_NET_ADMIN and nft; runs with `cargo xtask net`"]
fn the_target_side_baseline_stops_a_neighbour_on_the_same_node() {
    let (_fixture, ns_api, _api, ns_ledger, ledger) = two_containers("inbound");

    // **The same path twice, one thing different** — that is the whole
    // statement. First without a rule set: if it does not carry, the rejection
    // afterwards says nothing about the baseline but about the setup.
    //
    // As a counter-check **not** the reverse call: `ledger` carries the rule
    // set right away and would then not get out itself (the output hook) —
    // measured, and it would be the wrong side.
    let open = serve_once(listen_in(&ns_ledger, 8080), "ledger");
    let reachable = connect_from(&ns_api, SocketAddr::from((ledger, 8080)))
        .map(read_mark)
        .unwrap_or_default();
    drop(open);

    // **Only the target** gets the rule set; the caller stays unregulated.
    apply_baseline(&ns_ledger);

    let guarded = serve_once(listen_in(&ns_ledger, 8080), "ledger");
    let blocked = connect_from(&ns_api, SocketAddr::from((ledger, 8080)))
        .map(read_mark)
        .unwrap_or_default();
    drop(guarded);

    assert_eq!(
        reachable, "ledger",
        "the path does not carry even without a rule set — then the rejection \
         beside it says nothing about the baseline"
    );
    assert_eq!(
        blocked, "",
        "the **target's** baseline did not stop the neighbour: with that the \
         authorization could be switched off by declaring the caller without \
         <mesh> (ADR-0025, ADR-0093)"
    );
}

/// **A permitted UDP target gets through, another does not.**
///
/// Plain UDP knows no name on the wire — the agent resolves it and lays a rule
/// per **address and port**. Both are checked in one setup, for "does not
/// arrive" this test would also get if `nft` had discarded the rules or the
/// namespace looked different from what was intended.
///
/// The neighbour plays the external endpoint here: the baseline does not tell
/// it apart from a real one — it sees an address and a port.
#[test]
#[ignore = "needs CAP_NET_ADMIN and nft; runs with `cargo xtask net`"]
fn a_permitted_udp_target_is_reached_and_no_other() {
    let (_fixture, ns_api, _api, ns_ledger, ledger) = two_containers("udpout");

    // Permitted is **one** target: the same address, but only port 9123.
    let json = tg_net::rules::to_json(
        &NetnsRules::new(&cluster(), &subnet(), tg_model::mesh::SIDECAR_UID)
            .with_udp(&[(ledger, 9123)])
            .render_baseline(),
    )
    .expect("serializable");
    nft::apply_in(&ns_api, &json).expect("namespace rule set");

    let permitted = udp_echo(&ns_ledger, 9123, &ns_api, ledger, b"permitted");
    let forbidden = udp_echo(&ns_ledger, 9124, &ns_api, ledger, b"forbidden");

    assert_eq!(
        permitted.as_deref(),
        Some(&b"permitted"[..]),
        "the permitted target was not reached — then the rejection beside it \
         says nothing"
    );
    assert_eq!(
        forbidden, None,
        "a **not** permitted port was reached: the permission applies to \
         address **and** port (ADR-0092, determination 5)"
    );
}

/// Sends a datagram from `from` to `(address, port)` and returns what a
/// listener there received.
///
/// # Parameters
/// - `listener_ns`: the namespace the listener binds in.
/// - `port`: the port both the listener and the target datagram use.
/// - `from`: the namespace the datagram is sent from.
/// - `address`: the address to send the datagram to.
/// - `payload`: the bytes to send.
///
/// # Returns
/// The bytes received by the listener, or `None` if the send was rejected or
/// nothing arrived in time.
fn udp_echo(
    listener_ns: &str,
    port: u16,
    from: &str,
    address: Ipv4Addr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let bind_at = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let target = SocketAddr::from((address, port));
    let payload = payload.to_vec();

    let socket = tg_syscall::netns::run_in(listener_ns, move || {
        let socket = std::net::UdpSocket::bind(bind_at)?;
        socket.set_read_timeout(Some(Duration::from_millis(700)))?;
        Ok::<_, std::io::Error>(socket)
    })
    .expect("enter namespace")
    .expect("listener");

    let sent = tg_syscall::netns::run_in(from, move || {
        let client = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
        client.send_to(&payload, target)
    })
    .expect("enter namespace");

    // **An `EPERM` is the output hook's answer**, measured: the kernel
    // reports to the sender that its packet was discarded.
    if sent.is_err() {
        return None;
    }

    let mut buffer = [0_u8; 64];
    socket
        .recv_from(&mut buffer)
        .ok()
        .map(|(read, _)| buffer[..read].to_vec())
}

/// Renders and applies the full namespace ruleset, with the given sidecar
/// user ID as the exception in the redirect rules.
///
/// # Parameters
/// - `netns`: the namespace to apply the ruleset in.
/// - `sidecar_uid`: the user ID exempted from redirection.
///
/// # Panics
/// Panics if the ruleset cannot be applied.
fn apply_netns_rules(netns: &str, sidecar_uid: u32) {
    let json =
        tg_net::rules::to_json(&NetnsRules::new(&cluster(), &subnet(), sidecar_uid).render())
            .expect("serializable");
    nft::apply_in(netns, &json).expect("namespace rule set");
}

// ============================================================ Criterion 3

/// **No BPF program loaded — demonstrably.**
///
/// The whole setup runs between two measurements. If the set of loaded programs
/// grows, it has loaded one, no matter who did it.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn building_the_whole_network_loads_no_bpf_program() {
    assert!(
        tg_syscall::bpf::enumeration_available(),
        "without enumeration this proof would be worthless"
    );

    let before = tg_syscall::bpf::loaded_programs().expect("count beforehand");

    let (_fixture, ns_api, _api, ns_ledger, ledger) = two_containers("bpf");
    apply_netns_rules(&ns_api, 4711);

    let listener = listen_in(&ns_ledger, 9000);
    let server = serve_once(listener, "ledger");
    let _ = connect_from(&ns_api, SocketAddr::from((ledger, 9000)));
    drop(server);

    let after = tg_syscall::bpf::loaded_programs().expect("count afterwards");

    let added: Vec<u32> = after
        .iter()
        .filter(|id| !before.contains(id))
        .copied()
        .collect();

    assert!(
        added.is_empty(),
        "the setup loaded BPF programs: {added:?} \
         (before {before:?}, after {after:?})"
    );
}

/// **The rule set with egress loads into a real `nft`.**
///
/// The test beside it in `tests/rules.rs` checks the order of the statements;
/// this one checks that `nft` accepts them at all. Both are needed: a rule set
/// that is sorted right and that the kernel refuses is none.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn the_egress_ruleset_loads_into_a_real_nft() {
    let ruleset = tg_net::rules::to_json(
        &NetnsRules::new(&cluster(), &subnet(), 4711)
            .with_egress(SIDECAR_EGRESS)
            .render(),
    )
    .expect("serializable");

    tg_net::nft::check(&ruleset).expect("nft accepts the rule set");
}

/// **Attaching an instance is repeatable.**
///
/// `ensure_instance` is the form a level-triggered reconciler needs: it runs
/// over the same instance arbitrarily often, and the second pass may neither
/// fail nor rebuild anything. A newly built veth pair would tear off a running
/// container's connections — and the reconciler would then do that every
/// second.
///
/// What is checked is therefore **both**: that the second call names the same
/// path, and that the interface in the namespace has stayed the same. Comparing
/// only the path would leave a rebuild underneath unnoticed.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn attaching_an_instance_twice_leaves_its_link_alone() {
    let mtu = Mtu::for_overlay(1500).expect("1500 carries").get();
    let subnet = subnet();

    let mut leases = Leases::new(subnet.clone());
    let address = leases.lease("api", 0).expect("room enough");

    let netns = "tg-ensure-a".to_owned();
    let fixture = Fixture {
        names: vec![netns.clone()],
        links: vec![host_link(address)],
    };
    let _ = tg_syscall::netns::delete(&netns);
    let _ = link::detach(&host_link(address));

    link::ensure_bridge(&subnet, mtu).expect("bridge");

    let first = link::ensure_instance(&netns, address, &subnet, mtu).expect("first attachment");
    let index = index_of(&host_link(address));

    // **The same call, a second time.** Without `ensure_instance` that would be
    // a `NetNsError::Exists` — and the reconciler would report every pass as
    // failed although everything stands.
    let second = link::ensure_instance(&netns, address, &subnet, mtu).expect("second attachment");

    assert_eq!(first, second, "the namespace changed its path");
    assert_eq!(
        index,
        index_of(&host_link(address)),
        "the veth pair was rebuilt — a running connection would be gone"
    );

    drop(fixture);
}

/// **The instance reaches its neighbour over the attachment in one go.**
///
/// The test above says that nothing breaks; this one says that anything arises
/// at all. Without it an `ensure_instance` that does nothing would be just as
/// green.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn an_instance_attached_in_one_go_reaches_its_neighbour() {
    let mtu = Mtu::for_overlay(1500).expect("1500 carries").get();
    let subnet = subnet();

    let mut leases = Leases::new(subnet.clone());
    let api = leases.lease("api", 0).expect("room enough");
    let ledger = leases.lease("ledger", 0).expect("room enough");

    let ns_api = "tg-ensure-c".to_owned();
    let ns_ledger = "tg-ensure-d".to_owned();
    let fixture = Fixture {
        names: vec![ns_api.clone(), ns_ledger.clone()],
        links: vec![host_link(api), host_link(ledger)],
    };
    for name in &fixture.names {
        let _ = tg_syscall::netns::delete(name);
    }
    for host in &fixture.links {
        let _ = link::detach(host);
    }

    link::ensure_bridge(&subnet, mtu).expect("bridge");
    for (name, address) in [(&ns_api, api), (&ns_ledger, ledger)] {
        link::ensure_instance(name, address, &subnet, mtu).expect("attach");
    }

    let server = serve_once(listen_in(&ns_ledger, 9000), "ledger");
    let stream = connect_from(&ns_api, SocketAddr::from((ledger, 9000))).expect("connect");

    assert_eq!(read_mark(stream), "ledger");
    let _ = server.join();

    drop(fixture);
}

/// The interface number of a veth pair's **host side**.
///
/// The number and not the name: a newly built pair would be called the same but
/// would carry a different number. The name alone could not see the rebuild.
///
/// It is read on the **host**, and that is no accident: `/sys/class/net` does
/// not follow a `setns` — read in the namespace, the number of a foreign
/// interface would come back, and the test would compare two numbers it did
/// not mean at all. The host side is besides exactly what `attach` recognizes
/// whether something already stands by.
///
/// # Parameters
/// - `host`: the host-side link name to look up.
///
/// # Returns
/// The kernel interface index of the link.
///
/// # Panics
/// Panics if the interface's `ifindex` file cannot be read or parsed.
fn index_of(host: &tg_net::ipam::LinkName) -> u32 {
    let path = format!("/sys/class/net/{}/ifindex", host.as_str());
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("{path}: {err}"))
        .trim()
        .parse()
        .expect("ifindex is a number")
}

/// **The reconcile carries against a real kernel.**
///
/// The comparison in `rules::is_applied` rests on a measured property: `nft`
/// gives the expressions back byte for byte as it got them. The unit tests
/// beside it re-enact the return — here the kernel itself asks. Without this
/// test everything would hang on an assumption about a foreign program, and
/// were it wrong, the agent would set the rule set anew on **every** pass
/// without anyone noticing.
///
/// The second half is the cut's actual statement: after an `nft delete table` —
/// what a `flush ruleset` next door wreaks — it is a deviation.
#[test]
#[ignore = "demands CAP_NET_ADMIN and nft; cargo xtask net"]
fn the_host_ruleset_is_recognised_and_its_removal_is_drift() {
    let rules = tg_net::rules::HostRules::new(&cluster(), &subnet());
    let rendered = rules.render();

    tg_net::nft::apply(&tg_net::rules::to_json(&rendered).expect("serializable"))
        .expect("rule set applicable");

    let listed = tg_net::nft::list_table(tg_net::rules::FAMILY, tg_net::rules::TABLE)
        .expect("the table stands");
    assert!(
        tg_net::rules::is_applied(&rendered, &listed),
        "the kernel reports something other than what we sent:\n{listed}"
    );

    // And now what the reconcile is built against.
    std::process::Command::new("nft")
        .args(["delete", "table", "inet", tg_net::rules::TABLE])
        .status()
        .expect("nft");

    // **Both ways are assured, and today the first carries.** Measured, `nft
    // list table` gives `Rejected` ("No such file or directory") on a missing
    // table, so `is_err()` takes effect; the second half is the fallback for
    // the day on which `nft` prints an empty table instead — and then
    // `is_applied` has to read it as a deviation, otherwise the reconcile would
    // never set anew. It therefore stands here although it does not take effect
    // today; striking it would mean giving up exactly this case.
    let gone = tg_net::nft::list_table(tg_net::rules::FAMILY, tg_net::rules::TABLE);
    assert!(
        gone.is_err() || !tg_net::rules::is_applied(&rendered, &gone.unwrap_or_default()),
        "a deleted table has to count as a deviation"
    );
}

/// **And in an instance's namespace just the same.**
///
/// Since the redirection applies only to the **permitted** ports, the rule set
/// in the namespace hangs on the desired state and no longer only on the
/// topology — so it has to be reconciled like the node's. The comparison rests
/// on the same measured property, and the test beside it substantiates it for
/// the host table; here for a namespace in which `nft` runs as a child process.
///
/// **The second half is the statement:** a QUIC permission that comes along has
/// to count as a deviation. Did it not, a running workload would never get its
/// redirection — the permission would stand there, the listener would be open,
/// and the datagrams would die at the discarding rule.
#[test]
#[ignore = "demands CAP_NET_ADMIN and nft; cargo xtask net"]
fn a_new_quic_permission_is_drift_in_the_namespace() {
    let netns = "tg-drift-quic";
    let _ = tg_syscall::netns::delete(netns);
    tg_syscall::netns::create(netns).expect("namespace");
    let _fixture = Fixture {
        names: vec![netns.to_owned()],
        links: Vec::new(),
    };

    let base = tg_net::rules::NetnsRules::new(&cluster(), &subnet(), tg_model::mesh::SIDECAR_UID);
    let rendered = base.render();
    tg_net::nft::apply_in(
        netns,
        &tg_net::rules::to_json(&rendered).expect("serializable"),
    )
    .expect("rule set applicable");

    let listed = tg_net::nft::list_table_in(netns, tg_net::rules::FAMILY, tg_net::rules::TABLE)
        .expect("the table stands");
    assert!(
        tg_net::rules::is_applied(&rendered, &listed),
        "the kernel reports something other than what we sent:\n{listed}"
    );

    // And now what the reconcile is built against: a permission comes along
    // while the sidecar runs.
    let wanted = base.with_quic(&[443]).render();
    assert!(
        !tg_net::rules::is_applied(&wanted, &listed),
        "a new QUIC permission has to count as a deviation:\n{listed}"
    );
}

// ================================================== Loopback and the redirect

/// **The redirection in the namespace does not take effect on loopback** — and
/// two of this system's assurances rest on that.
///
/// # Why this test is here
///
/// [`NetnsRules`]'s incoming chain redirects **all** TCP onto the sidecar port;
/// only the **outgoing** one has a loopback exception. A reader easily takes
/// that for an oversight, and it is none: `prerouting` does not fire on
/// loopback, so the incoming chain needs none.
///
/// Two things hang on it, and both would without this witness be an unwritten
/// assumption about the kernel — exactly the kind of assumption that has
/// turned out **false** elsewhere in this codebase:
///
/// - **The sidecar's path to its workload**: it addresses it over
///   `127.0.0.1:<port>`. Were the incoming redirection to take effect, it would
///   talk to itself.
/// - **The readiness probe**: it runs in the namespace over loopback, because
///   from outside it would measure the sidecar — and that one refuses without
///   an active role.
///
/// # What it checks
///
/// The **real** rule set, not a staged one: `NetnsRules` with egress, so both
/// redirects. Two listeners on loopback, and the connect onto the workload's
/// has to land at it. The second listener carries the statement — without it a
/// redirection that points into the void would be indistinguishable from no
/// redirection.
#[test]
#[ignore = "needs CAP_NET_ADMIN and nft; runs with `cargo xtask net`"]
fn the_redirect_does_not_touch_loopback() {
    let netns = "tg-loopback-probe";
    let _ = tg_syscall::netns::delete(netns);
    tg_syscall::netns::create(netns).expect("namespace");
    let fixture = Fixture {
        names: vec![netns.to_owned()],
        links: Vec::new(),
    };

    // `lo` has to be up, otherwise the connect fails before any rule.
    tg_syscall::netns::run_in(netns, || {
        std::process::Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
    })
    .expect("enter namespace")
    .expect("lo up");

    let rules = NetnsRules::new(&cluster(), &subnet(), 65532).with_egress(SIDECAR_EGRESS);
    let json = tg_net::rules::to_json(&rules.render()).expect("rule set");
    nft::apply_in(netns, &json).expect("nft");

    // The workload on 8080, the sidecar on its incoming port. Both on loopback,
    // both in the namespace.
    let workload = listen_in(netns, 8080);
    let sidecar = listen_in(netns, SIDECAR_INBOUND);
    let one = serve_once(workload, "WORKLOAD");
    let two = serve_once(sidecar, "SIDECAR");

    let stream = connect_from(netns, SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)))
        .expect("loopback carries");
    let mark = read_mark(stream);

    // **Neither** of the two listeners is collected, and that is more important
    // than it looks: were the redirection to take effect after all, the
    // workload's listener would wait forever, and a `join` would turn a failure
    // into a **hang**. Measured, that is exactly the case — the counter-check
    // (a redirection in the `output` hook, which very much does take effect on
    // loopback) let the test run with `join` into the suite's timeout. A test
    // that hangs is worse than one that fails.
    drop(one);
    drop(two);
    drop(fixture);

    assert_eq!(
        mark, "WORKLOAD",
        "the connect on loopback was redirected — then the sidecar talks to \
         itself (ADR-0059) and the readiness probe measures it instead of the \
         workload (ADR-0080)"
    );
    // The counter-check to the path: that somebody really held 15006. Without
    // it the mark above would say only that somebody answered.
    assert_ne!(mark, "SIDECAR");
}

/// **The probe asks in the namespace, not on the host.**
///
/// # What hung on it
///
/// A mutation run showed that `run_in` can be removed from [`probe::connect_in`]
/// without a target in `tg-net` going red — the probe had **no** witness here.
/// The end-to-end test in `tg-runtime` catches it, but only **because nothing
/// happens to listen on 8080 on the host**: were a service running there, the
/// probe would report "ready" for a foreign process, and the instance would
/// appear in the resolution although its workload is silent.
///
/// # Why it separates independently of the environment
///
/// The listener stands **on the host**, the namespace is empty. A probe without
/// `setns` reaches it and says `Ok`; one with it says `Err`. The verdict
/// thereby does not hang on what is running on this machine right now.
///
/// The counter-direction stands beside it and is half the assurance: a listener
/// **in** the namespace is reached. Without it a probe that always fails would
/// be just as green — and then every instance would drop out of the resolution.
#[test]
#[ignore = "needs CAP_NET_ADMIN; runs with `cargo xtask net`"]
fn the_probe_asks_inside_the_namespace_and_not_on_the_host() {
    let netns = "tg-probe-where";
    let _ = tg_syscall::netns::delete(netns);
    tg_syscall::netns::create(netns).expect("namespace");
    let fixture = Fixture {
        names: vec![netns.to_owned()],
        links: Vec::new(),
    };

    loopback_up(netns);

    // The listener stands on the **host**. The port comes from the kernel so
    // that the test does not choose a number that is already taken elsewhere.
    let host = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener on the host");
    let port = host.local_addr().expect("address").port();

    let outcome = tg_net::probe::connect_in(netns, port);
    assert!(
        outcome.is_err(),
        "the probe reached the **host's** listener — then it reports 'ready' \
         for a foreign process (ADR-0080, determination 3)"
    );
    drop(host);

    // **The counter-direction**: the same call, the listener this time in the
    // namespace. The thread lives as long as the connect, for `run_in` creates
    // its own.
    let inside = std::thread::spawn(move || {
        tg_syscall::netns::run_in("tg-probe-where", || {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("listener in the netns");
            let port = listener.local_addr().expect("address").port();
            // The listener has to survive the connect, so it is held here and
            // discarded only after the acceptance.
            (listener, port)
        })
        .expect("enter namespace")
    });
    let (listener, port) = inside.join().expect("thread");

    let accepting = std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let reached = tg_net::probe::connect_in(netns, port);
    // **Not collected**, for the same reason as above: if the connect fails,
    // the listener waits forever, and a `join` would turn a failure into a
    // hang.
    drop(accepting);
    drop(fixture);

    assert!(
        reached.is_ok(),
        "a listener in the namespace has to be reached, otherwise every \
         instance drops out of the resolution: {reached:?}"
    );
}

/// Brings `lo` up in the namespace.
///
/// Without that a connect there fails at the **interface** instead of at the
/// absence of a listener, and a test checks a different `Err` from the one
/// meant.
///
/// # Parameters
/// - `netns`: the namespace whose loopback interface is brought up.
///
/// # Panics
/// Panics if the namespace cannot be entered or `ip link set lo up` fails.
fn loopback_up(netns: &str) {
    tg_syscall::netns::run_in(netns, || {
        std::process::Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
    })
    .expect("enter namespace")
    .expect("lo up");
}

/// Starts a listener in the namespace and hands its port out.
///
/// The handle is **not** collected, and that is deliberate: if a probe fails,
/// the listener waits up to its own deadline, and a `join` would turn a failure
/// into a hang.
///
/// # Parameters
/// - `netns`: the namespace to bind the listener in.
/// - `serve`: the function run on a background thread to serve the listener.
///
/// # Returns
/// The port the listener bound to.
///
/// # Panics
/// Panics if the namespace cannot be entered or the port is not received in
/// time.
fn listener_in<F>(netns: &'static str, serve: F) -> u16
where
    F: FnOnce(TcpListener) + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tg_syscall::netns::run_in(netns, move || {
            let listener =
                TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener in the namespace");
            let port = listener.local_addr().expect("address").port();
            tx.send(port).expect("port out");
            serve(listener);
        })
        .expect("enter namespace");
    });

    rx.recv_timeout(Duration::from_secs(5)).expect("port")
}

/// **The path reaches the server, and `2xx` decides.**
///
/// A real namespace, a real listener, a real `GET`. The server answers
/// `/healthz` with `200` and everything else with `503` — that the one probe
/// carries and the other does not is the substantiation for **both**: the
/// declared path arrives, and the status is interpreted.
///
/// A test with only one of the two paths would not say that: it would be green
/// too if the probe discarded the path and took every answer as ready.
#[test]
#[ignore = "needs CAP_NET_ADMIN; runs with `cargo xtask net`"]
fn the_declared_path_reaches_the_server_and_the_status_decides() {
    let netns = "tg-probe-http";
    let _ = tg_syscall::netns::delete(netns);
    tg_syscall::netns::create(netns).expect("namespace");
    let fixture = Fixture {
        names: vec![netns.to_owned()],
        links: Vec::new(),
    };
    loopback_up(netns);

    let port = listener_in(netns, |listener| {
        // Two connections, because `Connection: close` makes each one separate.
        for stream in listener.incoming().take(2) {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0_u8; 512];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let answer = if request.starts_with("GET /healthz ") {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
            };
            let _ = stream.write_all(answer.as_bytes());
        }
    });

    let ready = tg_net::probe::get_in(netns, port, "/healthz");
    let unready = tg_net::probe::get_in(netns, port, "/");
    drop(fixture);

    assert!(
        ready.is_ok(),
        "the declared path has to reach the server: {ready:?}"
    );
    assert_eq!(
        unready.unwrap_err(),
        "status 503",
        "a status other than 2xx means unready — otherwise the probe would be \
         a connection attempt with more steps"
    );
}

/// **The case a connect does not see.**
///
/// A process that binds and **does not answer** is exactly the situation for
/// whose sake this probe exists: a workload that loads something at startup and
/// already has its port open. The connection attempt calls it ready, the `GET`
/// does not.
///
/// **Both halves in one test**, because the statement is the difference: "the
/// `GET` fails" alone this setup would also get if the namespace or the
/// listener were broken.
#[test]
#[ignore = "needs CAP_NET_ADMIN; runs with `cargo xtask net`"]
fn a_process_that_binds_and_never_answers_is_not_ready() {
    let netns = "tg-probe-silent";
    let _ = tg_syscall::netns::delete(netns);
    tg_syscall::netns::create(netns).expect("namespace");
    let fixture = Fixture {
        names: vec![netns.to_owned()],
        links: Vec::new(),
    };
    loopback_up(netns);

    let port = listener_in(netns, |listener| {
        // Accept and **stay silent**. The connections are held so that no
        // `close` makes a proper end out of it.
        let held: Vec<_> = listener.incoming().take(2).filter_map(Result::ok).collect();
        std::thread::sleep(Duration::from_secs(2));
        drop(held);
    });

    let connected = tg_net::probe::connect_in(netns, port);
    let asked = tg_net::probe::get_in(netns, port, "/healthz");
    drop(fixture);

    assert!(
        connected.is_ok(),
        "the connection attempt has to succeed, otherwise the half below it \
         says nothing: {connected:?}"
    );
    let message = asked.expect_err("a silent server is not ready");
    assert!(
        // **Measured `read: operation would block`.** The branch
        // `|| contains("expired")` was **dead**: a process that binds and stays
        // silent lets the probe fail at the **read**, not at the deadline --
        // that takes effect only when it also lets the connection hang.
        message.contains("read"),
        "the message has to say what it was: {message}"
    );
}

/// **The second pass lays the same network down once more — and does not
/// fail.**
///
/// That is the idempotence without which the level-triggered reconcile fails
/// every second pass after the first: the bridge address and the routes then
/// answer with `EEXIST`.
///
/// It was checked implicitly — this file's privileged tests call
/// `ensure_bridge` several times in the same process —, but by no assurance.
/// And it hung on a string: `contains("File exists")` is the `strerror` text,
/// and that is locale-dependent; that it stays English here is a property of
/// the Rust runtime (**no `setlocale`**) and not of our code. Measured, the same
/// `strerror(17)` from C with `LC_ALL=de_DE.utf8` gives "Die Datei existiert
/// bereits".
///
/// What is checked is therefore the **effect**: the same call three times, and
/// afterwards the address stands there **once**. Without the last half the test
/// would hold for an `ensure_bridge` that appends the address a second time
/// every time.
#[test]
#[ignore = "demands CAP_NET_ADMIN"]
fn the_same_network_may_be_built_twice() {
    let subnet = subnet();
    let mtu = 1420;

    for round in 1..=3 {
        link::ensure_bridge(&subnet, mtu).unwrap_or_else(|err| panic!("round {round}: {err}"));
    }

    // The gateway's address stands on the bridge exactly once.
    let shown = std::process::Command::new("ip")
        .args(["-o", "addr", "show", "dev", tg_net::ipam::BRIDGE])
        .output()
        .expect("ip addr");
    let text = String::from_utf8_lossy(&shown.stdout);
    let gateway = subnet.gateway().to_string();
    let seen = text.matches(&gateway).count();
    assert_eq!(
        seen, 1,
        "{gateway} stands {seen} times on the bridge:\n{text}"
    );

    // And the routes just the same: the same call twice, on the bridge.
    let route: ipnet::Ipv4Net = "10.42.7.0/24".parse().expect("valid");
    for round in 1..=2 {
        link::ensure_routes(tg_net::ipam::BRIDGE, &[route])
            .unwrap_or_else(|err| panic!("routes {round}: {err}"));
    }
    let shown = std::process::Command::new("ip")
        .args(["-o", "route", "show", "10.42.7.0/24"])
        .output()
        .expect("ip route");
    let text = String::from_utf8_lossy(&shown.stdout);
    assert_eq!(
        text.lines().count(),
        1,
        "the route does not stand exactly once:\n{text}"
    );
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "10.42.7.0/24"])
        .status();
}
