//! A container on node A reaches a container on node B — the path this system
//! actually builds.
//!
//! `#[ignore]`, because it demands `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` and the
//! `WireGuard` module — run with `cargo xtask net`.
//!
//! # Why this setup was missing
//!
//! Every previous substantiation of the data plane runs **both sides on one
//! node**: `mesh_netns`, `egress_netns`, `sidecar_path`. The tunnel is
//! substantiated between two nodes (`underlay_path`), but with addresses the
//! test sets itself and that no container holds. With that the one path was
//! unchecked for whose sake anti-affinity (`spread="rack"`), mesh and underlay
//! exist at all: **container A → container B across node boundaries.**
//!
//! # The setup
//!
//! ```text
//!   node A (ordinal 0)                     node B (ordinal 1)
//!   cont-a 10.42.0.2 -- tg0 10.42.0.1      tg0 10.42.1.1 -- cont-b 10.42.1.2
//!                       tgwg0 <=== WireGuard ===> tgwg0
//!                       veth 192.168.99.1 ---- .2 (the "physical" network)
//! ```
//!
//! Four namespaces: two nodes, two containers. The transport network between
//! the nodes stands for the physical network and lies **outside** the cluster
//! CIDR — unlike in `underlay_path`, where it came from the same range. That
//! matters here, because the masquerade rule from [`HostRules`] rests on
//! exactly this distinction.
//!
//! Built with **the same** functions the agent uses: `ensure_bridge`,
//! `ensure_instance`, `wireguard::{peers, configure}`, `ensure_routes` and the
//! rule set from `HostRules`. The addresses are set by the test by hand — the
//! question of how a node **learns** a foreign container's address is open and
//! the subject of a decision of its own.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use tg_net::ipam::{ClusterNet, Leases, Mtu, NodeSubnet};
use tg_net::rules::HostRules;
use tg_net::wireguard::{self, Keypair, Member};

/// The containers' address space — the `AllowedIPs` come from it.
const CLUSTER: &str = "10.42.0.0/16";
/// The network over which the nodes reach each other. Outside the cluster.
const TRANSPORT: (&str, &str) = ("192.168.99.1", "192.168.99.2");
/// Where the listener in node B's container sits.
const PORT: u16 = 9000;

/// Builds the fixture cluster network shared by both nodes in this test.
///
/// # Returns
/// The constructed `10.42.0.0/16` cluster network with `/24` node subnets.
fn cluster() -> ClusterNet {
    ClusterNet::new(CLUSTER.parse().expect("valid"), 24).expect("valid")
}

/// Computes the overlay MTU for the fixture underlay.
///
/// # Returns
/// The overlay MTU for a 1500-byte underlay.
fn mtu() -> u16 {
    Mtu::for_overlay(1500).expect("1500 carries").get()
}

/// A node with its container.
struct Node {
    netns: String,
    container: String,
    ordinal: u32,
    subnet: NodeSubnet,
    keypair: Keypair,
    /// The address in the transport network — the peer's `endpoint`.
    transport: Ipv4Addr,
    /// The container's address.
    container_address: Ipv4Addr,
}

struct Fixture {
    namespaces: Vec<String>,
}

impl Drop for Fixture {
    /// Removes all namespaces created for the test, best-effort.
    fn drop(&mut self) {
        for name in &self.namespaces {
            let _ = tg_syscall::netns::delete(name);
        }
    }
}

/// Runs a command and returns its output.
///
/// # Parameters
/// - `command`: the shell command line to run.
///
/// # Returns
/// The combined stdout and stderr text.
///
/// # Panics
/// Panics if `sh` cannot be started.
fn sh(command: &str) -> String {
    let out = std::process::Command::new("sh")
        .args(["-c", command])
        .output()
        .expect("sh startable");

    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Builds the four namespaces and the transport network.
///
/// # Parameters
/// - `tag`: a short tag used to derive unique namespace and interface names.
///
/// # Returns
/// A cleanup guard for the created namespaces, plus the two node fixtures.
///
/// # Panics
/// Panics if the transport network cannot be set up.
fn topology(tag: &str) -> (Fixture, Node, Node) {
    let nodes = [format!("tg-{tag}-a"), format!("tg-{tag}-b")];
    let containers = [format!("tg-{tag}-ca"), format!("tg-{tag}-cb")];

    let fixture = Fixture {
        namespaces: nodes
            .iter()
            .chain(containers.iter())
            .cloned()
            .collect::<Vec<_>>(),
    };
    for name in &fixture.namespaces {
        let _ = tg_syscall::netns::delete(name);
    }
    let _ = sh(&format!("ip link del tr-{tag}-a 2>/dev/null"));

    for name in &nodes {
        tg_syscall::netns::create(name).expect("node namespace");
    }

    // The transport network: a veth pair directly between the two nodes. With
    // `ip`, not with `tg_net::link` — it stands for the physical network and is
    // not the subject of the check (the same choice as in `egress_netns`).
    let (a_transport, b_transport) = TRANSPORT;
    let setup = sh(&format!(
        "ip link add tr-{tag}-a type veth peer name tr-{tag}-b && \
         ip link set tr-{tag}-a netns {a} && ip link set tr-{tag}-b netns {b} && \
         ip -n {a} addr add {a_transport}/24 dev tr-{tag}-a && \
         ip -n {b} addr add {b_transport}/24 dev tr-{tag}-b && \
         ip -n {a} link set tr-{tag}-a up && ip -n {b} link set tr-{tag}-b up && \
         ip netns exec {a} sysctl -qw net.ipv4.ip_forward=1 && \
         ip netns exec {b} sysctl -qw net.ipv4.ip_forward=1",
        a = nodes[0],
        b = nodes[1],
    ));
    assert!(setup.trim().is_empty(), "transport network: {setup}");

    let a = Node {
        netns: nodes[0].clone(),
        container: containers[0].clone(),
        ordinal: 0,
        subnet: cluster().subnet(0).expect("subnet"),
        keypair: Keypair::generate(),
        transport: a_transport.parse().expect("address"),
        container_address: Ipv4Addr::UNSPECIFIED,
    };
    let b = Node {
        netns: nodes[1].clone(),
        container: containers[1].clone(),
        ordinal: 1,
        subnet: cluster().subnet(1).expect("subnet"),
        keypair: Keypair::generate(),
        transport: b_transport.parse().expect("address"),
        container_address: Ipv4Addr::UNSPECIFIED,
    };

    (fixture, a, b)
}

/// Builds the node network: bridge, container, rule set, tunnel.
///
/// **With the agent's functions**, so that the test checks what runs.
///
/// # Parameters
/// - `me`: the node to bring up; its container address is written back into
///   `container_address`.
/// - `peer`: the other node, used to derive the `WireGuard` peer entry.
///
/// # Panics
/// Panics if any step of bringing up the network fails.
fn bring_up(me: &mut Node, peer: &Node) {
    let subnet = me.subnet.clone();
    let container = me.container.clone();
    let mut leases = Leases::new(subnet.clone());
    let address = leases.lease("api", 0).expect("address");
    me.container_address = address;

    let keypair = me.keypair.clone();
    let endpoint = format!("{}:{}", peer.transport, wireguard::PORT);
    let peer_key = peer.keypair.public_base64();
    let members = vec![
        Member {
            name: "me",
            ordinal: me.ordinal,
            key: None,
            endpoint: None,
        },
        Member {
            name: "peer",
            ordinal: peer.ordinal,
            key: Some(&peer_key),
            endpoint: Some(&endpoint),
        },
    ];
    let derived = wireguard::peers(&cluster(), &members, "me").expect("derivable");
    let routes: Vec<ipnet::Ipv4Net> = derived.iter().map(|peer| peer.allowed).collect();
    let rules = tg_net::rules::to_json(&HostRules::new(&cluster(), &subnet).render())
        .expect("render rule set");
    let netns = me.netns.clone();

    tg_syscall::netns::run_in(&me.netns, move || {
        // 1. The node's bridge and the container on it.
        tg_net::link::ensure_bridge(&subnet, mtu()).expect("bridge");
        tg_net::link::ensure_instance(&container, address, &subnet, mtu()).expect("container");

        // 2. The node's rule set. The masquerade must **not** hit
        //    container-to-container — it is conditioned on "destination outside
        //    the cluster".
        tg_net::nft::apply(&rules).expect("rule set");

        // 3. The tunnel — **without an address on `tgwg0`**, as in operation:
        //    `AllowedIPs` says what may pass, a route says what takes it.
        wireguard::ensure_link(mtu()).expect("WireGuard interface");
        wireguard::configure(&keypair, wireguard::PORT, &derived).expect("configure");
        tg_net::link::ensure_routes(wireguard::DEVICE, &routes).expect("routes");
    })
    .expect("enter namespace");

    let _ = netns;
}

/// Binds a listening socket inside the given network namespace.
///
/// # Parameters
/// - `netns`: the namespace to bind in.
/// - `address`: the address to listen on, on [`PORT`].
///
/// # Returns
/// The bound listener.
///
/// # Panics
/// Panics if entering the namespace or binding fails.
fn listen_in(netns: &str, address: Ipv4Addr) -> TcpListener {
    tg_syscall::netns::run_in(netns, move || {
        TcpListener::bind(SocketAddr::from((address, PORT))).expect("bind")
    })
    .expect("enter namespace")
}

/// Connects to an address from inside the given network namespace.
///
/// # Parameters
/// - `netns`: the namespace to connect from.
/// - `to`: the address to connect to.
///
/// # Returns
/// The connected stream, or the connection error.
///
/// # Errors
/// Returns an error if the connection cannot be established within the
/// timeout.
///
/// # Panics
/// Panics if entering the namespace fails.
fn connect_from(netns: &str, to: SocketAddr) -> std::io::Result<TcpStream> {
    tg_syscall::netns::run_in(netns, move || {
        TcpStream::connect_timeout(&to, Duration::from_secs(5))
    })
    .expect("enter namespace")
}

// ===================================== The path across node boundaries

/// **A container on node A reaches a container on node B.**
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and the WireGuard module; via `cargo xtask net`"]
fn a_container_reaches_a_container_on_another_node() {
    let (fixture, mut a, mut b) = topology("2n");
    bring_up(&mut a, &b);
    bring_up(&mut b, &a);

    // What the kernel now sees — the measurement at issue.
    for node in [&a, &b] {
        eprintln!(
            "--- {}\n{}{}",
            node.netns,
            sh(&format!("ip -n {} route", node.netns)),
            sh(&format!("ip netns exec {} wg show", node.netns))
        );
    }

    let listener = listen_in(&b.container, b.container_address);
    let target = SocketAddr::from((b.container_address, PORT));

    let served = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("connection");
        let mut buffer = [0_u8; 5];
        stream.read_exact(&mut buffer).expect("read");
        stream.write_all(b"pong!").expect("write");
    });

    let mut stream = connect_from(&a.container, target).unwrap_or_else(|err| {
        panic!(
            "container A does not reach container B ({err}).\n\
             routes A:\n{}\nrules A:\n{}",
            sh(&format!("ip -n {} route", a.netns)),
            sh(&format!("ip netns exec {} nft list ruleset", a.netns))
        )
    });
    stream.write_all(b"ping!").expect("write");
    let mut answer = [0_u8; 5];
    stream.read_exact(&mut answer).expect("read");
    served.join().expect("listener");

    assert_eq!(&answer, b"pong!");
    drop(fixture);
}

/// **And through the tunnel at that** — with the wrong key nothing arrives.
///
/// Without this counter-check the test above would show only that two addresses
/// reach each other. They could do that over a way nobody meant: a route into
/// the transport network, a remnant from an earlier run, a neighbouring
/// interface. Here **one** thing is different — the peer key on A's side —, and
/// afterwards the path no longer carries.
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and the WireGuard module; via `cargo xtask net`"]
fn with_the_wrong_key_the_containers_do_not_reach_each_other() {
    let (fixture, mut a, mut b) = topology("2nx");
    // A stranger: the same setup, a different key.
    let stranger = Node {
        netns: b.netns.clone(),
        container: b.container.clone(),
        ordinal: b.ordinal,
        subnet: b.subnet.clone(),
        keypair: Keypair::generate(),
        transport: b.transport,
        container_address: b.container_address,
    };
    bring_up(&mut a, &stranger);
    bring_up(&mut b, &a);

    let _listener = listen_in(&b.container, b.container_address);
    let refused = connect_from(&a.container, SocketAddr::from((b.container_address, PORT)));

    assert!(
        refused.is_err(),
        "the connection came about despite the wrong key — then it does not \
         run through the tunnel"
    );
    drop(fixture);
}
