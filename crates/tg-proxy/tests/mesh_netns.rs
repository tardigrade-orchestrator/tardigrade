//! The mesh behind a **real** redirect (ADR-0060).
//!
//! `tests/sidecar.rs` substantiates the mTLS path end to end, but without a
//! redirection: there the workload dials the port an operator wrote in
//! `--route`. With that the sidecar is a **setting** and no enforcement --
//! whoever dials the address directly goes past it.
//!
//! Here the redirection exists, and the sidecar learns its destination from the
//! kernel:
//!
//! ```text
//!   netns tg-mesh-*                      netns tg-mesh-*-p
//!     client (uid nobody) ──► 10.42.1.9:9000
//!            │  nft redirect (output, skuid != the sidecar)
//!            ▼
//!     sidecar :15001  ──SO_ORIGINAL_DST──► 10.42.1.9:9000
//!            │  mTLS, verified against the bundle and the edge (ADR-0025)
//!            └──────────────┄veth┄─────────► the inbound sidecar
//!                                                  └──► echo on 127.0.0.1
//! ```
//!
//! **Two namespaces, and the reason is measured:** `prerouting` does not fire
//! on loopback. If both addresses lay in one, the sidecar's call to
//! `10.42.1.9:9000` would arrive on the input chain as a **new** connection --
//! and the baseline from ADR-0093 discards everything there that does not lie
//! on the inbound sidecar's port. In operation the peer's redirect rewrites the
//! port beforehand; the setup follows that.
//!
//! The second namespace carries **no** rule set -- it plays the container on
//! the other side. What is checked is the caller's namespace; that the
//! counterpart has its rules too is substantiated at real containers
//! (`tg-identity/tests/mesh_container.rs`).
//!
//! The client **never** dials a sidecar port. That it nevertheless arrives at
//! the echo is the whole substantiation: `15001` stands nowhere in its line,
//! and `10.42.1.9:9000` stands in no route list.
//!
//! # Two assurances, two tests
//!
//! - **The way leads through the sidecar** -- and the answer carries the echo's
//!   marker, not a coincidence's.
//! - **The sidecar itself is not redirected.** Without this exception its own
//!   call to `10.42.1.9:9000` would call it again -- a loop that would appear
//!   as a timeout and not as a rule error. The test for it is the first: if the
//!   exception did not exist, no answer would come.
//!
//! The fixture builds its network with `ip` instead of with `tg_net::link` --
//! the same rationale as in `egress_netns.rs`: the veth and the bridge are
//! substantiated at real packets in 9b and are not the object here.
//!
//! `#[ignore]`: demands `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `nft`, `ip` and
//! `runuser` -- run with `cargo xtask net`.

use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::Duration;

use tg_identity::{Authority, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};
use tg_net::ipam::ClusterNet;
use tg_net::rules::NetnsRules;
use tg_proxy::identity::Identity;
use tg_proxy::policy::{PolicyCache, RevocationWindow, Snapshot, UnixSeconds};
use tg_proxy::sidecar::Config;
use tg_proxy::verify::{Bundle, SharedBundle, SharedPolicy};

const YEAR: i64 = 365 * 24 * 60 * 60;

/// The address the client dials. In the cluster network -- that is, what the
/// rule from 9b redirects.
const PEER: &str = "10.42.1.9";
/// The port the client means. It stands in **no** route list.
const PEER_PORT: u16 = 9000;
/// The client's address in the namespace.
const OWN: &str = "10.42.1.2";
/// The node's address -- the resolver listens there (ADR-0013).
const GATEWAY: &str = "10.42.1.1";

fn provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("the domain")
}

fn now() -> UnixSeconds {
    UnixSeconds::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs(),
    )
    .expect("fits")
}

fn sh(args: &[&str]) {
    let status = std::process::Command::new(args[0])
        .args(&args[1..])
        .status()
        .unwrap_or_else(|err| panic!("{} must be startable: {err}", args[0]));
    assert!(status.success(), "{args:?} failed");
}

/// A namespace that clears itself away.
struct Netns(String);

impl Netns {
    /// Two namespaces, connected by a veth pair.
    ///
    /// **Two**, and the reason is measured: `prerouting` does not fire on
    /// loopback. If both addresses lay in one namespace, the sidecar's call to
    /// `PEER:9000` would arrive on the input chain as a **new** connection --
    /// and the baseline from ADR-0093 discards everything there that does not
    /// lie on the inbound sidecar's port. In operation the peer's redirect
    /// rewrites the port beforehand; the setup follows that.
    ///
    /// The second namespace carries **no** rule set. It plays the container on
    /// the other side; what is checked is the caller's namespace. That the
    /// counterpart has its rules too is substantiated at real containers
    /// (`tg-identity/tests/mesh_container.rs`).
    fn pair(tag: &str) -> (Self, Self) {
        let near = Self::empty(&format!("tg-mesh-{tag}"));
        let far = Self::empty(&format!("tg-mesh-{tag}-p"));
        let (here, there) = (format!("v-{tag}"), format!("p-{tag}"));

        sh(&[
            "ip", "link", "add", &here, "type", "veth", "peer", "name", &there,
        ]);
        sh(&["ip", "link", "set", &here, "netns", near.name()]);
        sh(&["ip", "link", "set", &there, "netns", far.name()]);

        // Its own address and the node's here -- in operation the resolver
        // listens there, and the exception for it is half the UDP assurance
        // from ADR-0074. The peer's over there.
        for (netns, link, addresses) in [
            (&near, &here, vec![OWN, GATEWAY]),
            (&far, &there, vec![PEER]),
        ] {
            sh(&[
                "ip",
                "netns",
                "exec",
                netns.name(),
                "ip",
                "link",
                "set",
                link,
                "up",
            ]);
            for address in addresses {
                sh(&[
                    "ip",
                    "netns",
                    "exec",
                    netns.name(),
                    "ip",
                    "addr",
                    "add",
                    &format!("{address}/24"),
                    "dev",
                    link,
                ]);
            }
        }

        (near, far)
    }

    /// A namespace with nothing but a running loopback.
    fn empty(name: &str) -> Self {
        let _ = tg_syscall::netns::delete(name);
        tg_syscall::netns::create(name).expect("lay the namespace out");
        sh(&["ip", "netns", "exec", name, "ip", "link", "set", "lo", "up"]);

        Self(name.to_owned())
    }

    fn create(tag: &str) -> Self {
        let name = format!("tg-mesh-{tag}");
        let _ = tg_syscall::netns::delete(&name);
        tg_syscall::netns::create(&name).expect("lay the namespace out");

        // **Both** addresses on one dummy: its own and the peer's. The peer
        // thereby lies in the same namespace -- what is checked is the
        // redirection, not the delivery over the bridge (that is
        // substantiated in 9b).
        for args in [
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "set", "lo", "up",
            ],
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "add", "mesh", "type", "dummy",
            ],
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "set", "mesh", "up",
            ],
        ] {
            sh(&args);
        }
        // And the node's: in operation the resolver listens there, and the
        // exception for it is half the UDP assurance from ADR-0074.
        for address in [OWN, PEER, GATEWAY] {
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
                "mesh",
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

/// Loads the rule set into the namespace.
///
/// The sidecar's identifier is **0** -- the test process's, which plays it;
/// the client therefore runs as `nobody`. In operation the sidecar has its own
/// identifier (`mesh::SIDECAR_UID`), and `sidecar_path.rs` substantiates that
/// the container really runs under it.
fn apply_rules(netns: &str) {
    let cluster = ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24).expect("valid");
    let subnet = cluster.subnet(1).expect("valid");
    let json = tg_net::rules::to_json(&NetnsRules::new(&cluster, &subnet, 0).render())
        .expect("serializable");
    tg_net::nft::apply_in(netns, &json).expect("the namespace rule set");
}

/// A CA and the SVIDs it issues -- as in `tests/sidecar.rs`.
struct Pki {
    anchor: Vec<u8>,
    authority: Authority<LocalSigner>,
}

impl Pki {
    fn new() -> Self {
        let signer = LocalSigner::generate().expect("the key");
        let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("the CA");
        let anchor = ca.certificate_der().to_vec();
        let authority = Authority::new(ca, signer, Lifetime::default()).expect("the issuer");

        Self { anchor, authority }
    }

    fn identity(&self, workload: &str) -> tg_proxy::identity::SharedIdentity {
        let id = SpiffeId::for_workload(&domain(), workload).expect("the ID");
        let svid = self.authority.issue(&id, now()).expect("the SVID");

        tg_proxy::identity::SharedIdentity::new(
            Identity::new(
                &id.to_string(),
                vec![svid.certificate_der().to_vec()],
                svid.private_key_der().to_vec(),
            )
            .expect("the identity"),
        )
    }
}

fn policy(edges: &[(&str, &str)]) -> SharedPolicy {
    let window = RevocationWindow {
        target: Duration::from_secs(1),
        staleness: Duration::from_mins(15),
    };
    let mut cache = PolicyCache::new(window);
    cache
        .apply(
            &Snapshot::from_edges(
                1,
                edges
                    .iter()
                    .map(|(a, b)| ((*a).to_owned(), (*b).to_owned())),
            ),
            now(),
        )
        .expect("the snapshot");

    SharedPolicy::new(cache)
}

fn window() -> RevocationWindow {
    RevocationWindow {
        target: Duration::from_secs(1),
        staleness: Duration::from_mins(15),
    }
}

/// The "workload" behind the inbound sidecar -- on loopback, as in operation
/// (ADR-0059: one instance, one address, two processes).
async fn echo(port: u16) -> u16 {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("the echo");
    let port = listener.local_addr().expect("the address").port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0_u8; 64];
                if let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    && read > 0
                {
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, b"ledger-echo").await;
                }
            });
        }
    });

    port
}

/// Brings the peer up **over there**: the echo and the inbound sidecar on the
/// address the client dials.
///
/// Everything on **one** runtime on **one** thread: `run_in` enters the
/// calling thread's namespace, and a multi-threaded runtime would lay its
/// workers beside it into the host namespace.
fn peer_in(
    netns: &str,
    identity: tg_proxy::identity::SharedIdentity,
    anchor: Vec<u8>,
    edges: &'static [(&'static str, &'static str)],
) {
    let (ready, wait) = mpsc::channel();
    let netns = netns.to_owned();

    std::thread::spawn(move || {
        let _ = tg_syscall::netns::run_in(&netns, move || {
            provider();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the runtime");

            runtime.block_on(async move {
                // **On the port number the client dials** (ADR-0141). In
                // operation `<mesh port>` is one number for both: the caller
                // dials it, the sidecar passes through to it. The sidecar
                // listens beside it on the same number and a different address
                // -- here `PEER`, in operation the instance's address.
                let upstream = echo(PEER_PORT).await;
                let inbound = tokio::net::TcpListener::bind(
                    format!("{PEER}:{PEER_PORT}")
                        .parse::<SocketAddr>()
                        .expect("the address"),
                )
                .await
                .expect("the inbound sidecar");
                let ledger = Config {
                    identity,
                    bundle: SharedBundle::new(Bundle::from_der(vec![anchor])),
                    policy: policy(edges),
                    window: window(),
                    role: None,
                };

                tokio::spawn(async move {
                    let _ =
                        tg_proxy::serve_inbound(ledger, inbound, upstream, std::future::pending())
                            .await;
                });

                let _ = ready.send(());
                std::future::pending::<()>().await;
            });
        });
    });

    wait.recv_timeout(Duration::from_secs(10))
        .expect("the peer did not come up");
}

/// Brings the mesh port up **here** -- what was redirected lands there.
fn mesh_in(
    netns: &str,
    identity: tg_proxy::identity::SharedIdentity,
    anchor: Vec<u8>,
    edges: &'static [(&'static str, &'static str)],
) {
    let (ready, wait) = mpsc::channel();
    let netns = netns.to_owned();

    std::thread::spawn(move || {
        let _ = tg_syscall::netns::run_in(&netns, move || {
            provider();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the runtime");

            runtime.block_on(async move {
                let mesh = tokio::net::TcpListener::bind("0.0.0.0:15001")
                    .await
                    .expect("the mesh port");
                let api = Config {
                    identity,
                    bundle: SharedBundle::new(Bundle::from_der(vec![anchor])),
                    policy: policy(edges),
                    window: window(),
                    role: None,
                };

                tokio::spawn(async move {
                    let _ = tg_proxy::sidecar::serve_mesh(api, mesh, std::future::pending()).await;
                });

                let _ = ready.send(());
                std::future::pending::<()>().await;
            });
        });
    });

    wait.recv_timeout(Duration::from_secs(10))
        .expect("the mesh port did not come up");
}

/// The whole setup: the peer over there, the mesh port here -- with **one**
/// PKI.
///
/// It arises here and not in the two threads: two CAs would not know each
/// other, and the handshake would fall for a reason that has nothing to do
/// with the test's object.
fn stacks_in(near: &Netns, far: &Netns, edges: &'static [(&'static str, &'static str)]) {
    provider();
    let pki = Pki::new();

    peer_in(
        far.name(),
        pki.identity("ledger"),
        pki.anchor.clone(),
        edges,
    );
    mesh_in(near.name(), pki.identity("api"), pki.anchor.clone(), edges);
}

/// Dials from the namespace -- as `nobody`, so that the redirect bites.
fn dial_as_nobody(netns: &str) -> String {
    let script =
        format!("exec 3<>/dev/tcp/{PEER}/{PEER_PORT} && printf 'hello' >&3 && head -c 11 <&3");
    let out = std::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            netns,
            "runuser",
            "-u",
            "nobody",
            "--",
            "/bin/bash",
            "-c",
            &script,
        ])
        .output()
        .expect("bash must be startable");

    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// **The client lands at the echo without ever naming a sidecar port.**
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN, nft, ip and runuser; cargo xtask net"]
fn a_redirected_connection_reaches_the_peer_through_the_sidecar() {
    let (netns, peer) = Netns::pair("through");
    stacks_in(&netns, &peer, &[("api", "ledger")]);
    apply_rules(netns.name());

    assert_eq!(
        dial_as_nobody(netns.name()),
        "ledger-echo",
        "the redirected traffic did not arrive at the echo"
    );
}

/// **Without an edge nothing gets through** -- over the redirect either.
///
/// The counter-check to the test above, with an otherwise identical setup:
/// only the edge is missing. Without it the first test would show merely that
/// some way exists, and not that ADR-0025 applies on it.
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN, nft, ip and runuser; cargo xtask net"]
fn without_an_edge_the_redirected_connection_carries_nothing() {
    let (netns, peer) = Netns::pair("denied");
    stacks_in(&netns, &peer, &[]);
    apply_rules(netns.name());

    assert_eq!(
        dial_as_nobody(netns.name()),
        "",
        "without a may_talk edge nothing may get through (ADR-0025)"
    );
}

/// **The original destination comes from the kernel** -- checked at a second
/// port.
///
/// The same setup, one thing different: the client dials `:9001`. **Nobody**
/// listens there, so nothing may arrive either. If the echo came back
/// nevertheless, the sidecar would have guessed its destination instead of
/// asking.
#[test]
#[ignore = "demands CAP_NET_ADMIN, CAP_SYS_ADMIN, nft, ip and runuser; cargo xtask net"]
fn the_destination_comes_from_the_kernel_not_from_a_guess() {
    let (netns, peer) = Netns::pair("kernel");
    stacks_in(&netns, &peer, &[("api", "ledger")]);
    apply_rules(netns.name());

    let script = format!("exec 3<>/dev/tcp/{PEER}/9001 && printf 'hello' >&3 && head -c 11 <&3");
    let out = std::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            netns.name(),
            "runuser",
            "-u",
            "nobody",
            "--",
            "/bin/bash",
            "-c",
            &script,
        ])
        .output()
        .expect("bash must be startable");

    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "",
        "nobody listens on 9001 -- the sidecar guessed its destination"
    );
}

// ==================== UDP leaves no mesh member (ADR-0074)

/// **UDP does not get through -- and to the resolver it does.**
///
/// Measured, every redirect rule carried `l4proto == tcp`: a mesh member
/// talked by UDP past the certificate with every container and phoned outside
/// without a permission. ADR-0025 and ADR-0041 were thereby without effect for
/// a whole protocol.
///
/// **Both halves stand in one test**, and that is the statement: "does not
/// arrive" this test would get too if `nft` had rejected the rules or the
/// namespace looked different from what was thought. That the same path to the
/// gateway **carries** excludes that -- and it is at the same time the
/// exception without which no container resolves a name any more
/// (ADR-0013).
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN; via `cargo xtask net`"]
fn udp_is_dropped_except_towards_the_resolver() {
    use std::net::{SocketAddr, UdpSocket};

    let netns = Netns::create("udp");
    apply_rules(netns.name());

    // A datagram to an address in the cluster: discarded.
    let blocked = tg_syscall::netns::run_in(netns.name(), || {
        let server = UdpSocket::bind(SocketAddr::new(PEER.parse().expect("the address"), 9999))
            .expect("bind");
        server
            .set_read_timeout(Some(std::time::Duration::from_millis(600)))
            .expect("the deadline");
        let client = UdpSocket::bind("0.0.0.0:0").expect("bind");
        let _ = client.send_to(b"ping", format!("{PEER}:9999"));

        let mut buffer = [0_u8; 8];
        server.recv_from(&mut buffer).is_ok()
    })
    .expect("enter the namespace");

    // The same to the node: it arrives, otherwise no container would resolve
    // a name any more.
    let allowed = tg_syscall::netns::run_in(netns.name(), || {
        let server = UdpSocket::bind(SocketAddr::new(GATEWAY.parse().expect("the address"), 9999))
            .expect("bind");
        server
            .set_read_timeout(Some(std::time::Duration::from_millis(600)))
            .expect("the deadline");
        let client = UdpSocket::bind("0.0.0.0:0").expect("bind");
        let _ = client.send_to(b"ping", format!("{GATEWAY}:9999"));

        let mut buffer = [0_u8; 8];
        server.recv_from(&mut buffer).is_ok()
    })
    .expect("enter the namespace");

    assert!(
        allowed,
        "its own resolver is not reachable -- with that no container resolves \
         a name any more (ADR-0013)"
    );
    assert!(
        !blocked,
        "UDP to a container in the cluster got through: it thereby goes past \
         the certificate (ADR-0025)"
    );
}
