//! The original destination of a **UDP** datagram (ADR-0094).
//!
//! Over TCP it comes from `SO_ORIGINAL_DST`; for UDP that is measured not to
//! exist, and `IP_RECVORIGDSTADDR` delivers under `redirect to :port` the
//! address **after** the DNAT. What carries is `redirect` **without** a port
//! setting: the port is preserved.
//!
//! Precisely that stands here at real packets through a real `nft` -- the four
//! measurements from ADR-0094 as a witness instead of as a note.
//!
//! `#[ignore]`: demands `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `nft` and `ip` --
//! run with `cargo xtask net`.

use std::net::{SocketAddr, UdpSocket};

/// The address the "container" dials -- in the cluster network.
const PEER: &str = "10.42.1.9";
/// The port it means. It stands in **no** route list.
const WANTED: u16 = 443;
/// The caller's address in the namespace.
const OWN: &str = "10.42.1.2";

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
    fn create(tag: &str) -> Self {
        let name = format!("tg-origdst-{tag}");
        let _ = tg_syscall::netns::delete(&name);
        tg_syscall::netns::create(&name).expect("lay the namespace out");

        for args in [
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "set", "lo", "up",
            ],
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "add", "name", "d0", "type", "dummy",
            ],
            vec![
                "ip", "netns", "exec", &name, "ip", "link", "set", "d0", "up",
            ],
        ] {
            sh(&args);
        }
        for address in [OWN, PEER] {
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
                "d0",
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

/// Loads a redirection **without** a port setting.
fn redirect_without_port(netns: &str) {
    let rules = format!(
        "table inet probe {{\n\
         \x20 chain out {{ type nat hook output priority -100; policy accept;\n\
         \x20   meta l4proto udp ip daddr {PEER} udp dport {WANTED} redirect\n\
         \x20 }}\n\
         }}\n"
    );
    let mut child = std::process::Command::new("ip")
        .args(["netns", "exec", netns, "nft", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("nft must be startable");
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(rules.as_bytes()).expect("the rules");
    }
    assert!(child.wait().expect("nft").success(), "nft refused");
}

/// **The port comes from the kernel, not from a list** (ADR-0051/0094).
///
/// The caller dials `10.42.1.9:443`; the redirection rewrites the address to
/// `127.0.0.1` and **leaves the port**. That the address is discarded in the
/// process is ADR-0041: it stems from a resolution the container may have done
/// itself.
///
/// **What this test cannot show**, and that is measured: under every redirect
/// the listening port is **equal** to the wanted one -- the mechanism
/// preserves it after all. A fallback to `local_addr()` would therefore be
/// invisible here. What excludes it is the test below.
#[test]
#[ignore = "demands CAP_NET_ADMIN and CAP_SYS_ADMIN, nft and ip; cargo xtask net"]
fn the_wanted_port_survives_the_redirect() {
    let netns = Netns::create("port");
    redirect_without_port(netns.name());

    let seen = tg_syscall::netns::run_in(netns.name(), || {
        // The listener stands on **the same** port the caller means -- that
        // is the consequence of determination 2, and without it the datagram
        // would arrive nowhere.
        let listener = tg_proxy::quic_egress::listener(WANTED).expect("the listener");
        let caller = UdpSocket::bind("0.0.0.0:0").expect("the caller");
        caller
            .send_to(b"initial", format!("{PEER}:{WANTED}"))
            .expect("send");

        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("the deadline");
        tg_proxy::quic_egress::receive(&listener)
    })
    .expect("enter the namespace")
    .expect("the datagram did not arrive");

    assert_eq!(
        seen.port, WANTED,
        "the port did not survive the redirect -- then it would come from the \
         allowlist, and that was measured to be redirecting (ADR-0051)"
    );
    assert_eq!(seen.bytes, b"initial", "the bytes are not unchanged");
    assert_eq!(
        seen.from.ip().to_string(),
        OWN,
        "the sender is wrong -- the answer goes back there"
    );
}

/// **Without the kernel's answer there is no destination** (ADR-0051).
///
/// The counter-check the test above cannot provide. The socket here has
/// **not** set `IP_RECVORIGDSTADDR`, so the kernel sends no ancillary message
/// -- and `receive` must fail instead of falling back to the listener's port.
///
/// A fallback would be exactly what ADR-0051 measured: a connection to a port
/// nobody chose. And it would make the strictness depend on whether a kernel
/// call succeeds.
#[test]
#[ignore = "demands CAP_SYS_ADMIN; cargo xtask net"]
fn without_the_kernels_answer_there_is_no_destination() {
    let netns = Netns::create("kernel");

    let outcome = tg_syscall::netns::run_in(netns.name(), || {
        // **Without** `listener()` -- a naked socket, as somebody who
        // forgets the option would build it.
        let plain = UdpSocket::bind("0.0.0.0:9443").expect("the listener");
        let caller = UdpSocket::bind("0.0.0.0:0").expect("the caller");
        caller
            .send_to(
                b"x",
                SocketAddr::new(PEER.parse().expect("the address"), 9443),
            )
            .expect("send");

        plain
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("the deadline");
        tg_proxy::quic_egress::receive(&plain)
    })
    .expect("enter the namespace");

    let err = outcome.expect_err(
        "without an ancillary message no destination may arise -- otherwise \
         the port would come from the listener and not from the kernel \
         (ADR-0051)",
    );
    assert!(
        err.to_string().contains("original destination"),
        "the reason is not named: {err}"
    );
}
