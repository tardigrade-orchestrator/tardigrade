//! A real `WireGuard` tunnel between two nodes.
//!
//! `#[ignore]`, because it demands `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` and the
//! `WireGuard` kernel module — run with `cargo xtask net`.
//!
//! # The setup
//!
//! Two namespaces play two nodes. The **underlay** is the bridge over which
//! the nodes reach each other, the **overlay** are the `WireGuard`
//! interfaces:
//!
//! ```text
//!   node A (ordinal 0)                 node B (ordinal 1)
//!   tgwg0 10.43.0.1/24  <== encrypted ==>  tgwg0 10.43.1.1/24
//!   eth0  10.42.1.2         ---- tg0 ----  eth0  10.42.1.3
//! ```
//!
//! That the underlay here stems from the cluster CIDR is a peculiarity of the
//! setup: in operation it is the physical network. What is checked is untouched
//! by that — that packets go through the tunnel and that the allowed networks
//! come from the **ordinal** and not from the log.
//!
//! # What the counter-test shows
//!
//! A peer with the wrong key brings no connection about. Without it the test
//! above would prove only that two addresses reach each other — which they
//! would do over the bridge anyway.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use tg_net::ipam::{ClusterNet, Leases, Mtu, host_link};
use tg_net::wireguard::{self, Keypair, Member};

/// The network in which the containers lie — the `AllowedIPs` come from it.
const OVERLAY: &str = "10.43.0.0/16";
/// The network over which the nodes reach each other.
const UNDERLAY: &str = "10.42.0.0/16";

/// Builds the fixture overlay network from which container addresses and
/// `AllowedIPs` are derived.
///
/// # Returns
/// The constructed overlay cluster network.
fn overlay() -> ClusterNet {
    ClusterNet::new(OVERLAY.parse().expect("valid"), 24).expect("valid")
}

/// Builds the fixture underlay network over which the nodes reach each other.
///
/// # Returns
/// The constructed underlay cluster network.
fn underlay() -> ClusterNet {
    ClusterNet::new(UNDERLAY.parse().expect("valid"), 24).expect("valid")
}

struct Fixture {
    names: Vec<String>,
    links: Vec<tg_net::ipam::LinkName>,
}

impl Drop for Fixture {
    /// Removes the namespaces and detaches the host links created for the
    /// test, best-effort.
    fn drop(&mut self) {
        for name in &self.names {
            let _ = tg_syscall::netns::delete(name);
        }
        for host in &self.links {
            let _ = tg_net::link::detach(host);
        }
    }
}

struct Node {
    netns: String,
    ordinal: u32,
    keypair: Keypair,
    underlay_address: Ipv4Addr,
    overlay_address: Ipv4Addr,
}

/// Builds two nodes with an underlay connection.
///
/// # Parameters
/// - `tag`: a short tag used to derive the namespace names.
///
/// # Returns
/// A cleanup fixture and the two constructed nodes.
fn two_nodes(tag: &str) -> (Fixture, Node, Node) {
    let mtu = Mtu::for_overlay(1500).expect("1500 carries").get();
    let underlay_subnet = underlay().subnet(1).expect("valid");

    let mut leases = Leases::new(underlay_subnet.clone());
    let a_under = leases.lease("node-a", 0).expect("room");
    let b_under = leases.lease("node-b", 0).expect("room");

    let names = vec![format!("tg-{tag}-a"), format!("tg-{tag}-b")];
    let fixture = Fixture {
        names: names.clone(),
        links: vec![host_link(a_under), host_link(b_under)],
    };
    for name in &fixture.names {
        let _ = tg_syscall::netns::delete(name);
    }
    for host in &fixture.links {
        let _ = tg_net::link::detach(host);
    }

    tg_net::link::ensure_bridge(&underlay_subnet, mtu).expect("bridge");

    for (name, address) in [(&names[0], a_under), (&names[1], b_under)] {
        tg_syscall::netns::create(name).expect("namespace");
        tg_net::link::attach(name, &host_link(address), address, &underlay_subnet, mtu)
            .expect("attach");
    }

    let a = Node {
        netns: names[0].clone(),
        ordinal: 0,
        keypair: Keypair::generate(),
        underlay_address: a_under,
        overlay_address: overlay().subnet(0).expect("valid").gateway(),
    };
    let b = Node {
        netns: names[1].clone(),
        ordinal: 1,
        keypair: Keypair::generate(),
        underlay_address: b_under,
        overlay_address: overlay().subnet(1).expect("valid").gateway(),
    };

    (fixture, a, b)
}

/// Sets up a node's underlay interface.
///
/// # Parameters
/// - `me`: the node whose underlay interface is configured.
/// - `peer_key`: the peer's base64-encoded public key.
/// - `peer`: the peer node to connect to.
fn bring_up(me: &Node, peer_key: &str, peer: &Node) {
    let endpoint = format!("{}:{}", peer.underlay_address, wireguard::PORT);
    let members = vec![
        Member {
            name: "a",
            ordinal: me.ordinal,
            key: None,
            endpoint: None,
        },
        Member {
            name: "b",
            ordinal: peer.ordinal,
            key: Some(peer_key),
            endpoint: Some(&endpoint),
        },
    ];

    let derived = wireguard::peers(&overlay(), &members, "a").expect("derivable");
    assert_eq!(derived.len(), 1);

    let keypair = me.keypair.clone();
    let address = me.overlay_address;
    let routes: Vec<ipnet::Ipv4Net> = derived.iter().map(|peer| peer.allowed).collect();
    let mtu = Mtu::for_overlay(1500).expect("1500 carries").get();

    tg_syscall::netns::run_in(&me.netns, move || {
        wireguard::ensure_link(mtu).expect("WireGuard interface");
        wireguard::configure(&keypair, wireguard::PORT, &derived).expect("configure");
        tg_net::link::ensure_overlay(wireguard::DEVICE, address, 24, &routes).expect("overlay");
    })
    .expect("enter namespace");
}

/// Binds a TCP listener inside the given network namespace.
///
/// # Parameters
/// - `netns`: the name of the network namespace to enter.
/// - `address`: the address to bind.
/// - `port`: the port to bind.
///
/// # Returns
/// The bound listener.
///
/// # Panics
/// Panics if the namespace cannot be entered or the bind fails.
fn listen_in(netns: &str, address: Ipv4Addr, port: u16) -> TcpListener {
    tg_syscall::netns::run_in(netns, move || {
        TcpListener::bind(SocketAddr::from((address, port))).expect("bind")
    })
    .expect("enter namespace")
}

/// Connects to `to` from inside the given network namespace.
///
/// # Parameters
/// - `netns`: the name of the network namespace to connect from.
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
        TcpStream::connect_timeout(&to, Duration::from_secs(3))
    })
    .expect("enter namespace")
}

// ================================================================= The tunnel

/// **Two nodes reach each other over the encrypted underlay.**
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and the WireGuard module; via `cargo xtask net`"]
fn two_nodes_reach_each_other_through_the_tunnel() {
    let (_fixture, a, b) = two_nodes("wg");

    bring_up(&a, &b.keypair.public_base64(), &b);
    bring_up(&b, &a.keypair.public_base64(), &a);

    let listener = listen_in(&b.netns, b.overlay_address, 9000);
    let server = std::thread::spawn(move || {
        if let Ok((mut stream, from)) = listener.accept() {
            let _ = stream.write_all(format!("{}", from.ip()).as_bytes());
        }
    });

    let mut stream = connect_from(&a.netns, SocketAddr::from((b.overlay_address, 9000)))
        .expect("the tunnel has to carry");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("deadline");

    let mut seen = String::new();
    let _ = stream.read_to_string(&mut seen);

    assert_eq!(
        seen,
        a.overlay_address.to_string(),
        "the other side did not see the overlay address — the traffic ran past \
         the tunnel"
    );

    server.join().expect("listener");
}

/// The counter-check: **one** thing different — the peer's key is a stranger's.
/// Without it the test above would prove only that two addresses reach each
/// other, which they would do over the bridge anyway.
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and the WireGuard module; via `cargo xtask net`"]
fn a_peer_with_the_wrong_key_gets_no_tunnel() {
    let (_fixture, a, b) = two_nodes("wgbad");

    let stranger = Keypair::generate();
    bring_up(&a, &stranger.public_base64(), &b);
    bring_up(&b, &a.keypair.public_base64(), &a);

    let listener = listen_in(&b.netns, b.overlay_address, 9000);
    let server = std::thread::spawn(move || {
        let _ = listener.accept();
    });

    let result = connect_from(&a.netns, SocketAddr::from((b.overlay_address, 9000)));

    assert!(
        result.is_err(),
        "with a foreign key no connection may come about"
    );

    drop(server);
}

/// The allowed networks come from the ordinal — looked up on the wire.
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and the WireGuard module; via `cargo xtask net`"]
fn the_allowed_networks_in_the_kernel_come_from_the_ordinal() {
    let (_fixture, a, b) = two_nodes("wgallowed");

    bring_up(&a, &b.keypair.public_base64(), &b);

    let netns = a.netns.clone();
    let seen = tg_syscall::netns::run_in(&netns, move || {
        std::process::Command::new("ip")
            .args(["route", "show", "dev", wireguard::DEVICE])
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
    })
    .expect("enter namespace")
    .expect("ip has to run");

    assert!(
        seen.contains("10.43.1.0/24"),
        "node B's network (ordinal 1) is missing: {seen}"
    );
}

// ================================================== Detach

/// A cluster view with both nodes — and optionally a detached one.
///
/// It is built here because this test is to check the **whole chain**: slice →
/// peer derivation → kernel. `slice_for` is the place where detachment
/// filtering takes effect, and checking it without the kernel would leave
/// open whether the filtering actually arrives there.
///
/// # Parameters
/// - `a`: the first node.
/// - `b`: the second node.
/// - `detached`: the names of nodes to mark as detached in the view.
///
/// # Returns
/// The constructed cluster view.
fn view_with(a: &Node, b: &Node, detached: &[&str]) -> tg_store::session::ClusterView {
    let peer = |name: &str, node: &Node| tg_store::session::UnderlayPeer {
        node: name.to_owned(),
        ordinal: node.ordinal,
        key: node.keypair.public_base64(),
        endpoint: format!("{}:{}", node.underlay_address, wireguard::PORT),
    };

    tg_store::session::ClusterView {
        snapshot_generations: std::collections::BTreeMap::new(),
        active_instances: std::collections::BTreeMap::new(),
        secrets: Vec::new(),
        registry_credentials: Vec::new(),
        sidecar_overhead: Vec::new(),
        leases: std::collections::BTreeMap::new(),
        index: 1,
        placements: Vec::new(),
        documents: std::collections::BTreeMap::new(),
        edges: Vec::new(),
        egress: Vec::new(),
        peers: vec![peer("a", a), peer("b", b)],
        deleted_volumes: std::collections::BTreeMap::new(),
        generations: std::collections::BTreeMap::new(),
        workload_generations: std::collections::BTreeMap::new(),
        detached: detached.iter().map(|name| (*name).to_owned()).collect(),
        ordinals: [("a".to_owned(), a.ordinal), ("b".to_owned(), b.ordinal)]
            .into_iter()
            .collect(),
        network: Some(tg_store::session::ClusterNetwork {
            cidr: "10.43.0.0/16".to_owned(),
            node_prefix: 24,
        }),
        endpoints: std::collections::BTreeMap::new(),
    }
}

/// Sets up a node's underlay **from the slice**.
///
/// The same way `tg-agent::underlay` goes: the peers are derived from the
/// slice and not enumerated by hand.
///
/// # Parameters
/// - `me`: the node whose underlay interface is configured.
/// - `name`: the node's name as it appears in the cluster view.
/// - `view`: the cluster view to derive peers from.
fn bring_up_from_slice(me: &Node, name: &str, view: &tg_store::session::ClusterView) {
    let slice = tg_store::session::slice_for(name, view);
    let members: Vec<Member<'_>> = slice
        .peers
        .iter()
        .map(|peer| Member {
            name: &peer.node,
            ordinal: peer.ordinal,
            key: Some(&peer.key),
            endpoint: Some(&peer.endpoint),
        })
        .collect();

    let derived = wireguard::peers(&overlay(), &members, name).expect("derivable");
    let keypair = me.keypair.clone();
    let address = me.overlay_address;
    let routes: Vec<ipnet::Ipv4Net> = derived.iter().map(|peer| peer.allowed).collect();
    let mtu = Mtu::for_overlay(1500).expect("1500 carries").get();

    tg_syscall::netns::run_in(&me.netns, move || {
        wireguard::ensure_link(mtu).expect("WireGuard interface");
        wireguard::configure(&keypair, wireguard::PORT, &derived).expect("configure");
        if !routes.is_empty() {
            tg_net::link::ensure_overlay(wireguard::DEVICE, address, 24, &routes).expect("overlay");
        }
    })
    .expect("enter namespace");
}

/// **A detached node disappears from the other's kernel.**
///
/// The whole chain is checked on real packets: the slice leaves it out
/// (`slice_for`), the derivation does not see it, `configure` replaces the peer
/// list — and afterwards the tunnel no longer carries. The slice alone without
/// the kernel would leave open whether the filtering arrives there.
///
/// **The first part carries the test:** without it a failed connection attempt
/// would prove only that something did not work.
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and the WireGuard module; via `cargo xtask net`"]
fn detaching_a_node_removes_it_from_the_kernel_of_the_others() {
    let (_fixture, a, b) = two_nodes("wgdetach");

    // 1. Attached: the path carries.
    let attached = view_with(&a, &b, &[]);
    bring_up_from_slice(&a, "a", &attached);
    bring_up_from_slice(&b, "b", &attached);

    let listener = listen_in(&b.netns, b.overlay_address, 9000);
    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"here");
        }
    });

    let mut stream = connect_from(&a.netns, SocketAddr::from((b.overlay_address, 9000)))
        .expect("attached, the tunnel has to carry");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("deadline");
    let mut seen = String::new();
    let _ = stream.read_to_string(&mut seen);
    assert_eq!(seen, "here", "the setup does not stand");
    server.join().expect("listener");

    // 2. Detached: **one** thing different, and the same way once more.
    let detached = view_with(&a, &b, &["b"]);
    bring_up_from_slice(&a, "a", &detached);

    let listener = listen_in(&b.netns, b.overlay_address, 9001);
    let server = std::thread::spawn(move || {
        let _ = listener.accept();
    });

    let result = connect_from(&a.netns, SocketAddr::from((b.overlay_address, 9001)));

    assert!(
        result.is_err(),
        "the detached node is still reachable in the other's kernel"
    );

    drop(server);
}

/// **And the detached one itself sees nobody any more.**
///
/// The other half of the convergence: it happens at its own end and does not
/// need the others. In the kernel an **empty** peer list remains: `slice_for`
/// gives it only its own entry, and `wireguard::peers` leaves it out itself.
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and the WireGuard module; via `cargo xtask net`"]
fn a_detached_node_ends_up_with_an_empty_peer_list() {
    let (_fixture, a, b) = two_nodes("wgempty");

    let detached = view_with(&a, &b, &["b"]);
    let slice = tg_store::session::slice_for("b", &detached);

    assert_eq!(
        slice.peers.len(),
        1,
        "the detached one has to see itself still (ADR-0042)"
    );

    let members: Vec<Member<'_>> = slice
        .peers
        .iter()
        .map(|peer| Member {
            name: &peer.node,
            ordinal: peer.ordinal,
            key: Some(&peer.key),
            endpoint: Some(&peer.endpoint),
        })
        .collect();

    assert!(
        wireguard::peers(&overlay(), &members, "b")
            .expect("derivable")
            .is_empty(),
        "the detached one still has peers"
    );

    // And then no route stands in the kernel either: there is nothing to reach.
    bring_up_from_slice(&b, "b", &detached);
    let netns = b.netns.clone();
    let routes = tg_syscall::netns::run_in(&netns, move || {
        std::process::Command::new("ip")
            .args(["route", "show", "dev", wireguard::DEVICE])
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
    })
    .expect("enter namespace")
    .expect("ip has to run");

    assert!(
        routes.trim().is_empty(),
        "the detached one still has routes into the mesh: {routes}"
    );

    // Counter-check: the same node **attached** has one.
    let attached = view_with(&a, &b, &[]);
    bring_up_from_slice(&b, "b", &attached);
    let netns = b.netns.clone();
    let routes = tg_syscall::netns::run_in(&netns, move || {
        std::process::Command::new("ip")
            .args(["route", "show", "dev", wireguard::DEVICE])
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
    })
    .expect("enter namespace")
    .expect("ip has to run");

    assert!(
        !routes.trim().is_empty(),
        "attached, a route has to stand — otherwise the test above checks nothing"
    );
}

// ================================================== Rotation

/// **The tunnel carries again as soon as both sides have the new key.**
///
/// What matters is that the *other* node takes over the new key. Checked on
/// real packets and over the whole chain — the slice carries the new key, the
/// derivation sees it, `configure` puts it into the kernel.
///
/// # The second part is the more interesting one
///
/// If **only one** side is switched over, the tunnel does **not** carry. That
/// is the window that the rotation order (announce first, then switch over)
/// exists to keep small — and it shows at the same time that the test
/// measures the key and not something else.
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN and the WireGuard module; via `cargo xtask net`"]
fn a_rotated_key_carries_once_both_sides_know_it() {
    let (_fixture, a, b) = two_nodes("wgrot");

    // 1. Before the rotation the path carries — the part that carries the test.
    let before = view_with(&a, &b, &[]);
    bring_up_from_slice(&a, "a", &before);
    bring_up_from_slice(&b, "b", &before);
    assert!(
        reaches(&a, &b, 9100),
        "before the rotation the tunnel has to carry"
    );

    // 2. `b` rotates: a new key, and **only it** switches over.
    let rotated = Node {
        keypair: Keypair::generate(),
        netns: b.netns.clone(),
        ..b
    };
    let after = view_with(&a, &rotated, &[]);
    bring_up_from_slice(&rotated, "b", &after);

    assert!(
        !reaches(&a, &rotated, 9101),
        "with half-switched keys the tunnel must not carry — that is the \
         window from ADR-0055"
    );

    // 3. And `a` follows: the slice names the new key.
    bring_up_from_slice(&a, "a", &after);
    assert!(
        reaches(&a, &rotated, 9102),
        "after the rotation the tunnel does not carry again — the other node \
         did not take over the new key"
    );
}

/// Whether `from` reaches `to` over the tunnel.
///
/// # Parameters
/// - `from`: the node to connect from.
/// - `to`: the node to connect to.
/// - `port`: the port to listen on and connect to.
///
/// # Returns
/// `true` if the connection succeeded and the expected payload was received.
fn reaches(from: &Node, to: &Node, port: u16) -> bool {
    let listener = listen_in(&to.netns, to.overlay_address, port);
    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"here");
        }
    });

    let reached = match connect_from(&from.netns, SocketAddr::from((to.overlay_address, port))) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let mut seen = String::new();
            let _ = stream.read_to_string(&mut seen);
            seen == "here"
        }
        Err(_) => false,
    };

    // The listener is **not** collected: on a failed attempt it is still
    // waiting, and a `join` would hang the test.
    drop(server);

    reached
}
