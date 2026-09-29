//! **An unmodified foreign image resolves service names.**
//!
//! That is the acceptance bar for this resolver, and it can only be
//! substantiated with **foreign code**. A test that asks with `simple-dns` and
//! answers with `simple-dns` shows self-consistency only — proving real
//! interoperability requires clients that read the DNS specification
//! independently of this codebase.
//!
//! Here there are two strangers, and the second weighs more:
//!
//! 1. **`dig` and `host`** from BIND — implementations that read the RFCs
//!    independently. They get the server named expressly.
//! 2. **glibc** via `/etc/resolv.conf` and `getent hosts`. That is the way an
//!    unmodified image actually goes: `getaddrinfo`, nothing else. No container
//!    knowledge, no library, no environment variable.
//!
//! # The setup
//!
//! The resolver listens on `127.0.0.1:53` **in a network namespace of its
//! own**. There port 53 is free without the host's `systemd-resolved` having to
//! give way. For glibc a separated mount namespace comes along, in which
//! `/etc/resolv.conf` points at this resolver.
//!
//! The `nsswitch.conf` is laid over as well (`hosts: files dns`). That is no
//! concession but the approximation of what is to be substantiated: the build
//! host's names `resolve`, that is, `systemd-resolved` over a Unix socket — and
//! Unix sockets are **not** affected by the network namespace. A container
//! image does not have that entry; it has `files dns`.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;

use tg_net::discovery::{Domain, Endpoint, Health, Registry};
use tg_net::resolver::{self, Resolver};

const ZONE: &str = "tardigrade.internal";

/// Builds a name unique to this test process, to avoid collisions between
/// concurrently running test binaries.
///
/// # Parameters
/// - `prefix`: a short tag identifying the caller.
///
/// # Returns
/// A string combining the prefix with a hash derived from the process ID.
fn unique(prefix: &str) -> String {
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    format!("{prefix}-{:x}", hasher.finish() & 0xffff)
}

struct Cleanup(String);

impl Drop for Cleanup {
    /// Removes the network namespace created for the test, best-effort.
    fn drop(&mut self) {
        let _ = tg_syscall::netns::delete(&self.0);
    }
}

/// Builds the fixture registry served by the internal zone under test.
///
/// # Returns
/// The constructed registry for `tardigrade.internal`.
fn registry() -> Registry {
    Registry::new(
        Domain::new(ZONE).expect("valid"),
        vec![
            Endpoint {
                workload: "api".to_owned(),
                instance: 0,
                address: Ipv4Addr::new(10, 42, 1, 10),
                health: Health::Healthy,
            },
            Endpoint {
                workload: "api".to_owned(),
                instance: 1,
                address: Ipv4Addr::new(10, 42, 1, 11),
                health: Health::Healthy,
            },
            Endpoint {
                workload: "cache".to_owned(),
                instance: 0,
                address: Ipv4Addr::new(10, 42, 1, 30),
                health: Health::Unhealthy,
            },
        ],
    )
}

/// The zone "outside" — what the upstream knows and we do not.
///
/// # Returns
/// The constructed registry for the external `example.test` zone.
fn upstream_registry() -> Registry {
    Registry::new(
        Domain::new("example.test").expect("valid zone"),
        vec![Endpoint {
            workload: "s3".to_owned(),
            instance: 0,
            address: Ipv4Addr::new(203, 0, 113, 7),
            health: Health::Healthy,
        }],
    )
}

/// Starts the resolver in a fresh namespace and returns its name. The service
/// runs until the test process ends.
///
/// # Parameters
/// - `tag`: a short tag used to derive the namespace name.
///
/// # Returns
/// A cleanup guard for the namespace and the namespace's name.
fn resolver_in_a_namespace(tag: &str) -> (Cleanup, String) {
    resolver_with_forwarding(tag, &[])
}

/// Like [`resolver_in_a_namespace`], but with a forwarding list and an upstream
/// that answers on port 5300 in the same namespace.
///
/// The upstream is a second [`Resolver`] with a zone of **its own**. What is
/// substantiated here is the client side: that a real DNS client gets an
/// answer through our forwarding. For that `dig` is the judge, and it is
/// foreign code that reads the DNS specification independently of this
/// resolver.
///
/// # Parameters
/// - `tag`: a short tag used to derive the namespace name.
/// - `allow`: the names permitted to be forwarded to the upstream.
///
/// # Returns
/// A cleanup guard for the namespace and the namespace's name.
fn resolver_with_forwarding(tag: &str, allow: &[&str]) -> (Cleanup, String) {
    let name = unique(tag);
    let allowed: Vec<String> = allow.iter().map(|n| (*n).to_owned()).collect();
    let _ = tg_syscall::netns::delete(&name);
    tg_syscall::netns::create(&name).expect("namespace");
    let cleanup = Cleanup(name.clone());

    tg_net::link::ensure_loopback(&name).expect("switch lo on");

    // The upstream lies in the **host** namespace, not in the test namespace.
    // That is no convenience but the topology from operation: the agent runs on
    // the host and listens on the bridge address, the container lies in the
    // namespace. `forward()` binds its socket where the process is — so on the
    // host.
    //
    // The first attempt put the upstream into the namespace, and `dig` ran into
    // a timeout: the query went out and found nothing there.
    let upstream_udp =
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind upstream");
    upstream_udp.set_nonblocking(true).expect("nonblocking");
    let upstream_addr = upstream_udp.local_addr().expect("address");

    let bound = name.clone();
    let (udp, tcp) = tg_syscall::netns::run_in(&bound, || {
        let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, resolver::PORT));
        let udp = UdpSocket::bind(listen).expect("bind UDP");
        let tcp = TcpListener::bind(listen).expect("bind TCP");
        udp.set_nonblocking(true).expect("nonblocking");
        tcp.set_nonblocking(true).expect("nonblocking");
        (udp, tcp)
    })
    .expect("enter namespace");

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let served = Arc::new(Resolver::new(registry()));
            served.forward_to(tg_net::resolver::Forwarding::new(allowed));
            let udp = tokio::net::UdpSocket::from_std(udp).expect("take over UDP");
            let tcp = tokio::net::TcpListener::from_std(tcp).expect("take over TCP");

            // The upstream: a second resolver with a zone of its own.
            let outside = Arc::new(Resolver::new(upstream_registry()));
            let upstream_udp =
                tokio::net::UdpSocket::from_std(upstream_udp).expect("take over upstream");

            let forward = Some(upstream_addr);

            tokio::select! {
                result = resolver::serve_udp(Arc::clone(&served), Arc::new(udp), forward) => {
                    let _ = result;
                }
                result = resolver::serve_tcp(served, Arc::new(tcp), forward) => {
                    let _ = result;
                }
                result = resolver::serve_udp(outside, Arc::new(upstream_udp), None) => {
                    let _ = result;
                }
            }
        });
    });

    // The listener stands as soon as `bind` came back — the thread only has to
    // bring the runtime up.
    std::thread::sleep(std::time::Duration::from_millis(200));

    (cleanup, name)
}

/// Runs a program inside the given network namespace and captures its output.
///
/// # Parameters
/// - `netns`: the name of the network namespace to enter.
/// - `program`: the executable to run.
/// - `args`: the arguments to pass to the program.
///
/// # Returns
/// The process output.
///
/// # Panics
/// Panics if the program cannot be started.
fn run_in(netns: &str, program: &'static str, args: Vec<String>) -> std::process::Output {
    tg_syscall::netns::run_in(netns, move || {
        std::process::Command::new(program)
            .args(args)
            .output()
            .unwrap_or_else(|err| panic!("'{program}' could not be started: {err}"))
    })
    .expect("enter namespace")
}

/// Combines a process's stdout and stderr into one string for assertions.
///
/// # Parameters
/// - `output`: the process output to render.
///
/// # Returns
/// The concatenated stdout and stderr text.
fn text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// =============================================== Foreign client no. 1: BIND

/// `dig` is BIND's own client — code that read the RFCs independently.
#[test]
#[ignore = "demands CAP_SYS_ADMIN/CAP_NET_ADMIN and dig from bind-utils; via `cargo xtask net`"]
fn dig_resolves_a_service_name() {
    let (_cleanup, netns) = resolver_in_a_namespace("tg-dig");

    let output = run_in(
        &netns,
        "dig",
        vec![
            "@127.0.0.1".to_owned(),
            "+short".to_owned(),
            "api.tardigrade.internal".to_owned(),
            "A".to_owned(),
        ],
    );

    let answer = text(&output);
    let mut lines: Vec<&str> = answer.split_whitespace().collect();
    lines.sort_unstable();

    assert_eq!(
        lines,
        vec!["10.42.1.10", "10.42.1.11"],
        "dig said: {answer}"
    );
}

/// A name that does not exist arrives at `dig` as NXDOMAIN — and not as a
/// timeout. Without this test the one above would prove only that something
/// answers.
#[test]
#[ignore = "demands CAP_SYS_ADMIN/CAP_NET_ADMIN and dig from bind-utils; via `cargo xtask net`"]
fn dig_gets_nxdomain_for_a_name_that_does_not_exist() {
    let (_cleanup, netns) = resolver_in_a_namespace("tg-dignx");

    let output = run_in(
        &netns,
        "dig",
        vec![
            "@127.0.0.1".to_owned(),
            "doesnotexist.tardigrade.internal".to_owned(),
            "A".to_owned(),
        ],
    );

    let answer = text(&output);
    assert!(
        answer.contains("status: NXDOMAIN"),
        "expected NXDOMAIN, dig said: {answer}"
    );
}

/// A name **outside** the zone is refused, not forwarded. An open resolver in
/// the mesh would be a weakness of its own.
#[test]
#[ignore = "demands CAP_SYS_ADMIN/CAP_NET_ADMIN and dig from bind-utils; via `cargo xtask net`"]
fn dig_gets_refused_outside_the_zone() {
    let (_cleanup, netns) = resolver_in_a_namespace("tg-digref");

    let output = run_in(
        &netns,
        "dig",
        vec![
            "@127.0.0.1".to_owned(),
            "example.com".to_owned(),
            "A".to_owned(),
        ],
    );

    let answer = text(&output);
    assert!(
        answer.contains("status: REFUSED"),
        "expected REFUSED, dig said: {answer}"
    );
}

/// `host` is a second client from the same collection, with its own output —
/// it checks in passing that the answer is not readable only for `dig`.
#[test]
#[ignore = "demands CAP_SYS_ADMIN/CAP_NET_ADMIN and host from bind-utils; via `cargo xtask net`"]
fn host_resolves_a_service_name() {
    let (_cleanup, netns) = resolver_in_a_namespace("tg-host");

    let output = run_in(
        &netns,
        "host",
        vec!["api.tardigrade.internal".to_owned(), "127.0.0.1".to_owned()],
    );

    let answer = text(&output);
    assert!(answer.contains("10.42.1.10"), "host said: {answer}");
    assert!(answer.contains("10.42.1.11"), "host said: {answer}");
}

// =========================== Foreign client no. 2: glibc, as in the image

/// **The strongest test in this file: an unmodified image, unaware of this
/// resolver, has to be able to resolve a name.**
///
/// `getent hosts` goes through `getaddrinfo` — exactly the way every unmodified
/// image goes. The resolver is found via `/etc/resolv.conf`, nothing else.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and CAP_NET_ADMIN; via `cargo xtask net`"]
fn glibc_resolves_a_service_name_through_resolv_conf() {
    let (_cleanup, netns) = resolver_in_a_namespace("tg-glibc");

    let directory = std::env::temp_dir().join(unique("tg-etc"));
    std::fs::create_dir_all(&directory).expect("directory");
    let resolv = directory.join("resolv.conf");
    let nsswitch = directory.join("nsswitch.conf");
    std::fs::write(
        &resolv,
        "nameserver 127.0.0.1\noptions timeout:2 attempts:2 ndots:1\n",
    )
    .expect("resolv.conf");
    // As in a container image, not as on a systemd host.
    std::fs::write(&nsswitch, "hosts: files dns\n").expect("nsswitch.conf");

    let answer = tg_syscall::netns::run_in(&netns, move || {
        tg_syscall::mount::isolate_mounts().expect("separate the mount namespace");
        tg_syscall::mount::bind_file(&resolv, std::path::Path::new("/etc/resolv.conf"))
            .expect("lay resolv.conf over");
        tg_syscall::mount::bind_file(&nsswitch, std::path::Path::new("/etc/nsswitch.conf"))
            .expect("lay nsswitch.conf over");

        std::process::Command::new("getent")
            .args(["hosts", "api.tardigrade.internal"])
            .output()
            .map(|out| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )
            })
    })
    .expect("enter namespace")
    .expect("getent has to run");

    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        answer.contains("10.42.1.10") || answer.contains("10.42.1.11"),
        "glibc did not resolve the name. getent said: '{}'",
        answer.trim()
    );
    assert!(
        answer.contains("api.tardigrade.internal"),
        "getent said: '{}'",
        answer.trim()
    );
}

/// The counter-check in the same setup: a name that does not exist does not
/// resolve over glibc either. Otherwise the test above would prove only that
/// `getent` prints something.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and CAP_NET_ADMIN; via `cargo xtask net`"]
fn glibc_does_not_resolve_a_name_that_does_not_exist() {
    let (_cleanup, netns) = resolver_in_a_namespace("tg-glibcnx");

    let directory = std::env::temp_dir().join(unique("tg-etc-nx"));
    std::fs::create_dir_all(&directory).expect("directory");
    let resolv = directory.join("resolv.conf");
    let nsswitch = directory.join("nsswitch.conf");
    std::fs::write(
        &resolv,
        "nameserver 127.0.0.1\noptions timeout:2 attempts:2\n",
    )
    .expect("resolv.conf");
    std::fs::write(&nsswitch, "hosts: files dns\n").expect("nsswitch.conf");

    let status = tg_syscall::netns::run_in(&netns, move || {
        tg_syscall::mount::isolate_mounts().expect("separate the mount namespace");
        tg_syscall::mount::bind_file(&resolv, std::path::Path::new("/etc/resolv.conf"))
            .expect("lay resolv.conf over");
        tg_syscall::mount::bind_file(&nsswitch, std::path::Path::new("/etc/nsswitch.conf"))
            .expect("lay nsswitch.conf over");

        std::process::Command::new("getent")
            .args(["hosts", "doesnotexist.tardigrade.internal"])
            .status()
            .map(|status| status.success())
    })
    .expect("enter namespace")
    .expect("getent has to run");

    let _ = std::fs::remove_dir_all(&directory);

    assert!(!status, "a name that does not exist was resolved");
}

// ============================= The forwarding (egress name allowlist)

/// **An allowed name resolves through the forwarding** — checked with `dig`.
///
/// The substantiation lies on the client side: a real DNS client gets an answer
/// through our forwarding, with a matching identifier and a matching question.
/// That the answer comes from our own code as the upstream is immaterial here —
/// the judge is `dig`.
#[test]
#[ignore = "demands CAP_SYS_ADMIN/CAP_NET_ADMIN and dig from bind-utils; via `cargo xtask net`"]
fn dig_resolves_an_allowed_egress_name_through_the_forwarder() {
    let (_cleanup, netns) = resolver_with_forwarding("tg-digfwd", &["s3.example.test"]);

    let output = run_in(
        &netns,
        "dig",
        vec![
            "@127.0.0.1".to_owned(),
            "s3.example.test".to_owned(),
            "A".to_owned(),
        ],
    );

    let answer = text(&output);
    assert!(
        answer.contains("status: NOERROR"),
        "expected NOERROR, dig said: {answer}"
    );
    assert!(
        answer.contains("203.0.113.7"),
        "the upstream's address is missing, dig said: {answer}"
    );
}

/// **And a name that does not stand on the list stays `REFUSED`** — even if the
/// upstream knew it.
///
/// Here it is decided whether the forwarding is an exception or an open
/// resolver. The setup is the same as above, and exactly **one** thing is
/// different: the name asked for does not stand on the allowlist.
#[test]
#[ignore = "demands CAP_SYS_ADMIN/CAP_NET_ADMIN and dig from bind-utils; via `cargo xtask net`"]
fn dig_gets_refused_for_a_name_that_is_not_allowed() {
    // Allowed is a **different** name in the upstream's same zone.
    let (_cleanup, netns) = resolver_with_forwarding("tg-dignofwd", &["allowed.example.test"]);

    let output = run_in(
        &netns,
        "dig",
        vec![
            "@127.0.0.1".to_owned(),
            "s3.example.test".to_owned(),
            "A".to_owned(),
        ],
    );

    let answer = text(&output);
    assert!(
        answer.contains("status: REFUSED"),
        "expected REFUSED, dig said: {answer}"
    );
}
