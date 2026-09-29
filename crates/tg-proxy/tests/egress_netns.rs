//! Egress behind a **real** redirect (ADR-0051 -- the more faithful
//! reproduction).
//!
//! `tests/egress_path.rs` proves the path against foreign TLS, but without a
//! redirect: `curl` dials the egress port directly, so the original
//! destination address *is* that port -- and it must stand in the allowlist
//! there. The test says itself that in a real netns that would be a gap. Here
//! the redirect exists, and the allowlist contains **only** the endpoint's
//! port.
//!
//! # What is substantiated here and could not be in `egress_path.rs`
//!
//! That the port comes from the **kernel** and not from the list. The container
//! dials `198.51.100.7:443`, lands over `nft redirect` at the sidecar on
//! `15002` -- and that one asks `SO_ORIGINAL_DST` for the port the container
//! meant. The counter-check beside it dials `:8443` with an otherwise
//! identical setup: before ADR-0051 it would have been **silently redirected
//! to 443**.
//!
//! # The setup
//!
//! ```text
//!   netns tg-egress-*
//!     curl (uid nobody) ──► 198.51.100.7:443
//!            │  nft redirect (output, uid != the sidecar)
//!            ▼
//!     sidecar (uid 0) :15002 ──SNI──► s3.test ──► 127.0.0.1:<endpoint>
//! ```
//!
//! The endpoint is **no** workload of this mesh (ADR-0027): its own CA, its own
//! certificate, and `curl` checks it. If the call succeeds, the sidecar did not
//! terminate (ADR-0041, determination 1).
//!
//! The fixture builds its network with `ip` instead of with `tg_net::link`, and
//! that is deliberate: the bridge and the veth are substantiated at real
//! packets in 9b, and they are not the object here. The object is the redirect
//! and the sidecar behind it.
//!
//! `#[ignore]`: demands `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `nft`, `ip`,
//! `runuser` and `curl` -- run with `cargo xtask net`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::sync::mpsc;

use tg_net::ipam::ClusterNet;
use tg_net::rules::{NetnsRules, SIDECAR_EGRESS};
use tg_proxy::egress::{EgressPolicy, Resolver};

/// The name under which the endpoint is to be reachable.
const ENDPOINT: &str = "s3.test";

/// The address the container dials. TEST-NET-2 (RFC 5737) and outside the
/// cluster network -- **nothing** listens there, and that is the point: what
/// arrives came over the redirect.
const OUTSIDE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

/// The port the permission names.
const ALLOWED_PORT: u16 = 443;

/// Names the crypto provider expressly (see `egress_path.rs`).
fn provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn sh(args: &[&str]) {
    let status = std::process::Command::new(args[0])
        .args(&args[1..])
        .status()
        .unwrap_or_else(|err| panic!("{} must be startable: {err}", args[0]));
    assert!(status.success(), "{args:?} failed");
}

/// A namespace that clears itself away -- even when a test fails.
struct Netns(String);

impl Netns {
    fn create(tag: &str) -> Self {
        let name = format!("tg-egress-{tag}");
        let _ = tg_syscall::netns::delete(&name);
        tg_syscall::netns::create(&name).expect("lay the namespace out");

        // Without a route to the outside `connect` fails with ENETUNREACH
        // **before** a packet arises -- and the redirect hangs on the output
        // hook. The gateway need not answer: the redirection happens before
        // the first ARP.
        for args in [
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "set", "lo", "up",
            ],
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "add", "outer", "type", "dummy",
            ],
            vec![
                "ip",
                "netns",
                "exec",
                &name,
                "ip",
                "addr",
                "add",
                "10.42.1.2/24",
                "dev",
                "outer",
            ],
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "set", "outer", "up",
            ],
            vec![
                "ip",
                "netns",
                "exec",
                &name,
                "ip",
                "route",
                "add",
                "default",
                "via",
                "10.42.1.1",
            ],
        ] {
            sh(&args);
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

/// Loads the rule set with egress into the namespace.
///
/// The sidecar's identifier is **0** -- the test process's, which plays it.
/// `curl` therefore runs as `nobody`: only then does the redirect bite for the
/// client and not for the sidecar. That is the same separation as in
/// operation, where the sidecar has its own identifier.
fn apply_rules(netns: &str) {
    let cluster = ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24).expect("valid");
    let subnet = cluster.subnet(1).expect("valid");
    let json = tg_net::rules::to_json(
        &NetnsRules::new(&cluster, &subnet, 0)
            .with_egress(SIDECAR_EGRESS)
            .render(),
    )
    .expect("serializable");
    tg_net::nft::apply_in(netns, &json).expect("the namespace rule set");
}

/// Produces the CA and the leaf for the endpoint.
///
/// The same way as in `egress_path.rs` and in `tg-identity`: the test
/// certificates are really minted, not reproduced. Without SPIFFE -- the
/// endpoint is expressly **no** workload of this mesh (ADR-0027).
fn endpoint_identity() -> (rcgen::Certificate, rcgen::KeyPair, String) {
    let ca_key = rcgen::KeyPair::generate().expect("the CA key");
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "tardigrade-test-ca");
    let ca = ca_params.self_signed(&ca_key).expect("the CA");
    let ca_pem = ca.pem();

    let leaf_key = rcgen::KeyPair::generate().expect("the leaf key");
    let leaf = rcgen::CertificateParams::new(vec![ENDPOINT.to_owned()])
        .expect("the parameter")
        .signed_by(
            &leaf_key,
            &rcgen::Issuer::from_ca_cert_der(ca.der(), ca_key).expect("the issuer"),
        )
        .expect("the leaf");

    (leaf, leaf_key, ca_pem)
}

/// Brings the endpoint **and** the sidecar up in the namespace and gives the
/// CA back.
///
/// Both run on **one** runtime on **one** thread, and that is no thrift:
/// `run_in` enters the calling thread's namespace. A multi-threaded runtime
/// would lay its workers beside it into the host namespace, and the sidecar's
/// call would then go into the wrong network.
fn stack_in(netns: &str) -> String {
    let (leaf, leaf_key, ca_pem) = endpoint_identity();
    let (tx, rx) = mpsc::channel();
    let netns = netns.to_owned();

    std::thread::spawn(move || {
        let _ = tg_syscall::netns::run_in(&netns, move || {
            provider();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the runtime");

            runtime.block_on(async move {
                let endpoint = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind the endpoint");
                let endpoint_addr = endpoint.local_addr().expect("the address");

                let egress = tokio::net::TcpListener::bind(SocketAddr::from((
                    Ipv4Addr::UNSPECIFIED,
                    SIDECAR_EGRESS,
                )))
                .await
                .expect("bind the egress port");

                // **Only the endpoint's port.** The egress port expressly
                // does *not* stand in it -- that is the difference from
                // `egress_path.rs` and this test's whole purpose.
                let policy = tg_proxy::egress::SharedEgress::new(EgressPolicy::from_entries([(
                    ENDPOINT.to_owned(),
                    ALLOWED_PORT,
                    tg_proxy::egress::Transport::Tcp,
                )]));
                let resolver = Resolver::Pinned(Arc::new(BTreeMap::from([(
                    ENDPOINT.to_owned(),
                    endpoint_addr,
                )])));

                tokio::spawn(serve_tls(endpoint, leaf, leaf_key));
                tx.send(()).expect("report ready");

                tg_proxy::egress::serve(
                    egress,
                    policy,
                    resolver,
                    tg_proxy::policy::RevocationWindow::adr_0014(),
                    None,
                    std::future::pending(),
                )
                .await;
            });
        });
    });

    rx.recv().expect("the setup must come up");
    ca_pem
}

/// A real TLS server that delivers a marker.
async fn serve_tls(
    listener: tokio::net::TcpListener,
    leaf: rcgen::Certificate,
    key: rcgen::KeyPair,
) {
    use rustls_pki_types::PrivateKeyDer;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .expect("the server configuration");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nfrom-store",
                    )
                    .await;
                let _ = tls.shutdown().await;
            }
        });
    }
}

/// `curl` **as `nobody`, in the namespace** -- the client is a different user
/// from the sidecar, otherwise the exception from `rules.rs` bites for it
/// too.
fn curl_in(netns: &str, ca_pem: &str, port: u16) -> std::process::Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, ca_pem).expect("write the CA");

    // `nobody` must be able to read them; `tempfile` lays out 0700.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).expect("the mode");
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o644)).expect("the mode");

    std::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            netns,
            "runuser",
            "-u",
            "nobody",
            "--",
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            "--cacert",
            ca.to_str().expect("the path"),
            // The container dials an **address outside**. That the answer
            // comes nevertheless is the substantiation for the redirect.
            "--resolve",
            &format!("{ENDPOINT}:{port}:{OUTSIDE}"),
            &format!("https://{ENDPOINT}:{port}/"),
        ])
        .output()
        .expect("curl must be startable")
}

/// **The path carries behind a real redirect.**
#[test]
#[ignore = "demands CAP_NET_ADMIN, nft, ip, runuser and curl; via `cargo xtask net`"]
fn an_allowed_endpoint_is_reached_through_a_real_redirect() {
    let netns = Netns::create("ok");
    apply_rules(netns.name());
    let ca_pem = stack_in(netns.name());

    let output = curl_in(netns.name(), &ca_pem, ALLOWED_PORT);
    let body = String::from_utf8_lossy(&output.stdout);

    assert!(
        body.contains("from-store"),
        "the answer did not get through. curl said: '{}' / '{}'",
        body.trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

/// **The find from ADR-0051, at real packets.**
///
/// The same setup, **one** thing different: the container dials `:8443`
/// instead of `:443`. Before ADR-0051 the sidecar took the only listed port
/// and connected silently to 443 -- to a service that can be something else
/// there, and because it does not terminate, at most the endpoint noticed.
///
/// # Why both halves stand in one namespace
///
/// "No `from-store`" alone would be no statement -- the test would get that
/// too if the setup did not run at all, if `nft` had rejected the rules or if
/// `curl` were missing. The permitted port therefore runs through the same
/// setup **first** and substantiates that the path stands; only then is the
/// refusal one about the port.
///
/// That it is possible at all is at the same time the substantiation that the
/// port comes from the **kernel**: the allowlist is the same in both calls, and
/// it names only 443.
#[test]
#[ignore = "demands CAP_NET_ADMIN, nft, ip, runuser and curl; via `cargo xtask net`"]
fn a_port_nobody_allowed_is_refused_instead_of_redirected() {
    let netns = Netns::create("port");
    apply_rules(netns.name());
    let ca_pem = stack_in(netns.name());

    let allowed = curl_in(netns.name(), &ca_pem, ALLOWED_PORT);
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("from-store"),
        "the setup does not stand -- without it the refusal below says nothing. \
         curl said: '{}'",
        String::from_utf8_lossy(&allowed.stderr).trim()
    );

    let refused = curl_in(netns.name(), &ca_pem, 8443);
    assert!(
        !String::from_utf8_lossy(&refused.stdout).contains("from-store"),
        "a non-permitted port was redirected to {ALLOWED_PORT}"
    );
}
