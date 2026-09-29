//! Egress: who may go out, and where to.
//!
//! The hinge: **the sidecar decides by the name the connection itself
//! names.** It does not terminate the connection in the process -- it reads
//! the `ClientHello`, takes the SNI and splices the bytes afterwards.
//!
//! # Why the lie in the SNI does not help
//!
//! The name is a self-declaration of the client. It nevertheless becomes
//! trustworthy because the sidecar **resolves and dials it itself**: a lie
//! brings the liar precisely where they were allowed to go anyway. The
//! address the container wanted to connect to is irrelevant -- the redirect
//! catches it anyway.
//!
//! # What does not happen here
//!
//! The `ClientHello` comes from a container. That is a trust boundary, and it
//! is **not parsed by hand**: `rustls` can read a `ClientHello` without
//! continuing the handshake, and `rustls` is there anyway. A TLS parser of
//! our own at this place would be the kind of code one writes wrong once and
//! never notices.

use tg_proxy::egress::{Decision, DenyReason, EgressPolicy, Peek, Transport};

/// Names the crypto provider expressly.
///
/// In the workspace run `cargo` unifies the features, and `rustls` gets
/// **both** providers -- `ring` over this crate, `aws-lc-rs` over `reqwest` in
/// the image puller. Then it chooses none and panics. The production path is
/// untouched by this: `tg_proxy::tls` names the provider anyway
/// (`builder_with_provider`), and `peek` never gets as far as needing a cipher
/// suite.
fn provider() {
    // Called several times, the second call is an error, no problem.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Produces a real `ClientHello` wire message, via `rustls`.
///
/// # Parameters
/// - `server_name`: the SNI hostname to embed in the `ClientHello`.
///
/// # Returns
/// The raw bytes of the `ClientHello` record.
fn client_hello(server_name: &str) -> Vec<u8> {
    provider();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let name = server_name.to_owned().try_into().expect("a valid name");
    let mut connection =
        rustls::ClientConnection::new(std::sync::Arc::new(config), name).expect("the connection");

    let mut bytes = Vec::new();
    connection.write_tls(&mut bytes).expect("the ClientHello");

    bytes
}

/// Returns a fixed egress policy allowing two hosts on TCP, for use across
/// these tests.
fn policy() -> EgressPolicy {
    EgressPolicy::from_entries([
        ("s3.example.com".to_owned(), 443, Transport::Tcp),
        ("api.partner.example".to_owned(), 8443, Transport::Tcp),
    ])
}

// ------------------------------------------------------------- reading

#[test]
fn the_server_name_is_read_from_a_real_client_hello() {
    match tg_proxy::egress::peek(&client_hello("s3.example.com")) {
        Peek::Named(name) => assert_eq!(name, "s3.example.com"),
        other => panic!("expected Named, was {other:?}"),
    }
}

/// A find of the fuzz run, nailed down deterministically.
///
/// `rustls` returns the SNI **lower-cased** -- DNS names are independent of
/// the spelling. That is as it should be and the reason
/// [`EgressPolicy::permits`] must compare likewise: if it did not, the
/// allowlist could be bypassed with a capital letter.
#[test]
fn the_server_name_comes_back_lowercased() {
    let mut bytes = client_hello("s3.example.com");
    let at = bytes
        .windows(14)
        .position(|window| window == b"s3.example.com")
        .expect("the name stands in the buffer");
    bytes[at] = b'S';

    match tg_proxy::egress::peek(&bytes) {
        Peek::Named(name) => assert_eq!(name, "s3.example.com"),
        other => panic!("expected Named, was {other:?}"),
    }
}

/// Half a `ClientHello` is no error but a "not yet" -- the sidecar reads on.
/// Counting it as "no TLS" would mean refusing every connection whose first
/// packet was small.
#[test]
fn a_truncated_client_hello_asks_for_more() {
    let full = client_hello("s3.example.com");

    for cut in [1, 5, 20, full.len() / 2, full.len() - 1] {
        assert!(
            matches!(tg_proxy::egress::peek(&full[..cut]), Peek::Incomplete),
            "at {cut} of {} bytes there was no reading on",
            full.len()
        );
    }
}

#[test]
fn bytes_that_are_not_tls_are_recognised_as_such() {
    for garbage in [
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        vec![0xff; 64],
        b"SSH-2.0-OpenSSH_9.0\r\n".to_vec(),
    ] {
        assert!(
            matches!(tg_proxy::egress::peek(&garbage), Peek::NotTls),
            "{garbage:?} was taken for TLS"
        );
    }
}

/// Empty bytes are no "no TLS" -- nothing is there yet.
#[test]
fn no_bytes_at_all_ask_for_more() {
    assert!(matches!(tg_proxy::egress::peek(&[]), Peek::Incomplete));
}

// ------------------------------------------------------------ permitting

/// **Deny-by-default** -- the same attitude taken for inbound mesh traffic.
#[test]
fn nothing_is_allowed_without_an_entry() {
    let empty = EgressPolicy::from_entries([]);

    assert!(!empty.permits("s3.example.com", 443, Transport::Tcp));
    assert!(!empty.permits("", 443, Transport::Tcp));
}

#[test]
fn an_allowed_host_and_port_passes() {
    assert!(policy().permits("s3.example.com", 443, Transport::Tcp));
}

/// The port belongs to the permission. Whoever releases 443 does not release 22.
#[test]
fn the_same_host_on_another_port_is_denied() {
    assert!(!policy().permits("s3.example.com", 22, Transport::Tcp));
    assert!(!policy().permits("s3.example.com", 8443, Transport::Tcp));
}

/// An SNI is a DNS name, and DNS is independent of upper and lower case.
/// Whoever compared letter for letter here could be bypassed with a capital
/// letter.
#[test]
fn the_host_is_matched_case_insensitively() {
    assert!(policy().permits("S3.Example.COM", 443, Transport::Tcp));
}

/// A name that **ends** with a permitted one is not the same one.
/// `evil-s3.example.com` and `s3.example.com.evil.test` are foreign targets --
/// the same class of finding as with the DNS resolver's own zone matching,
/// here at a more expensive place.
#[test]
fn a_name_that_merely_resembles_an_allowed_one_is_denied() {
    for outsider in [
        "evil-s3.example.com",
        "s3.example.com.evil.test",
        "xs3.example.com",
        "s3.example.co",
        "s3.example.com.",
    ] {
        assert!(
            !policy().permits(outsider, 443, Transport::Tcp),
            "'{outsider}' was permitted"
        );
    }
}

// ------------------------------------------------------------- deciding

/// **The port comes from the allowlist**, not from the connection.
///
/// After the redirect the **arriving** port is the sidecar's -- it carries
/// no information. The port comes from the kernel (`SO_ORIGINAL_DST`); here
/// it is handed to the decider, because the function stays pure and does not
/// know the socket.
#[test]
fn an_allowed_connection_is_forwarded_to_the_name_it_gave() {
    match tg_proxy::egress::decide(&policy(), &client_hello("s3.example.com"), 443) {
        Decision::Forward { host, port } => {
            assert_eq!(host, "s3.example.com");
            assert_eq!(port, 443);
        }
        other => panic!("expected Forward, was {other:?}"),
    }
}

/// **A non-permitted port is refused, not redirected.**
///
/// That is a deliberate behaviour change from an earlier version. Previously
/// the port came from the allowlist: whoever dialled `:8443` while `:443`
/// was permitted got **silently** a connection to 443 -- one they had not
/// demanded, to a service that can be something else there.
#[test]
fn a_port_nobody_allowed_is_denied_instead_of_redirected() {
    match tg_proxy::egress::decide(&policy(), &client_hello("s3.example.com"), 8443) {
        Decision::Deny {
            reason: DenyReason::NotAllowed { host },
        } => assert_eq!(host, "s3.example.com"),
        other => panic!("expected Deny/NotAllowed, was {other:?}"),
    }
}

/// The counter-check: **the same port at another name** is permitted. Without
/// it the test above would check only that something is refused.
#[test]
fn the_same_port_at_another_name_is_allowed() {
    assert!(matches!(
        tg_proxy::egress::decide(&policy(), &client_hello("api.partner.example"), 8443),
        Decision::Forward { port: 8443, .. }
    ));
}

#[test]
fn a_connection_to_an_unlisted_host_is_denied() {
    match tg_proxy::egress::decide(&policy(), &client_hello("foreign.example.com"), 443) {
        Decision::Deny {
            reason: DenyReason::NotAllowed { host },
        } => assert_eq!(host, "foreign.example.com"),
        other => panic!("expected Deny/NotAllowed, was {other:?}"),
    }
}

/// **Without a name no permission.** Whoever cannot name themselves must let
/// themselves be numbered -- and that is a visible line of its own in the
/// allowlist, no quiet exception here.
#[test]
fn traffic_that_is_not_tls_is_denied() {
    match tg_proxy::egress::decide(&policy(), b"GET / HTTP/1.1\r\n\r\n", 443) {
        Decision::Deny {
            reason: DenyReason::NoName,
        } => {}
        other => panic!("expected Deny/NoName, was {other:?}"),
    }
}

#[test]
fn an_incomplete_hello_is_neither_allowed_nor_denied() {
    let full = client_hello("s3.example.com");
    assert!(matches!(
        tg_proxy::egress::decide(&policy(), &full[..10], 443),
        Decision::NeedMore
    ));
}

// ------------------------------------------- the names for the resolver

/// The allowlist is at the same time the resolver's forwarding list. With
/// that it stays no open resolver, without needing a second list for it.
#[test]
fn the_policy_names_exactly_what_the_resolver_may_forward() {
    let policy = policy();
    let mut hosts = policy.hosts();
    hosts.sort_unstable();

    assert_eq!(hosts, vec!["api.partner.example", "s3.example.com"]);
}

/// **A name with two ports is now expressible.**
///
/// An earlier version of this test held fast that both are refused: without
/// the original destination address it could not be said which was meant.
/// With it, it is no longer a question -- and a third port stays refused.
#[test]
fn a_host_listed_with_two_ports_is_decided_by_the_original_destination() {
    let both = EgressPolicy::from_entries([
        ("s3.example.com".to_owned(), 443, Transport::Tcp),
        ("s3.example.com".to_owned(), 9000, Transport::Tcp),
    ]);

    for allowed in [443, 9000] {
        assert!(
            matches!(
                tg_proxy::egress::decide(&both, &client_hello("s3.example.com"), allowed),
                Decision::Forward { .. }
            ),
            "{allowed} should be permitted"
        );
    }

    assert!(matches!(
        tg_proxy::egress::decide(&both, &client_hello("s3.example.com"), 8443),
        Decision::Deny {
            reason: DenyReason::NotAllowed { .. }
        }
    ));
}

// ------------------------------------------- the allowlist from the file

/// The sidecar reads **only its own** permissions.
///
/// Several workloads run on one node, and the file the node writes carries
/// all of their targets. Where the neighbour phones is none of this
/// sidecar's business -- and letting it act on that would be a quiet
/// widening of its permission.
#[test]
fn the_sidecar_reads_only_its_own_permissions() {
    let text = "\
api      s3.example.com   443
ledger   backup.internal  9000
api      logs.example.com 443
";

    let mine = tg_proxy::options::egress_from_text(text, "api").expect("readable");

    assert_eq!(
        mine,
        vec![
            ("s3.example.com".to_owned(), 443, Transport::Tcp),
            ("logs.example.com".to_owned(), 443, Transport::Tcp),
        ]
    );
}

/// Comments and blank lines as with the edges.
#[test]
fn comments_and_blank_lines_are_skipped() {
    let text = "\
# where api may go
api s3.example.com 443

   # one more
";

    let mine = tg_proxy::options::egress_from_text(text, "api").expect("readable");

    assert_eq!(mine.len(), 1);
}

/// **An unusable line is an error, no quiet omission.**
///
/// The file comes from consensus. A line the reader does not understand and
/// passes over would mean: a permission that stands in the log has no effect
/// -- and nobody would see it. The failure in the safe direction is
/// nevertheless the loud one here.
#[test]
fn a_malformed_line_is_an_error_that_names_itself() {
    for line in [
        "api s3.example.com",
        "api s3.example.com 443 too-much",
        "api s3.example.com forty-three",
        "api s3.example.com 99999",
    ] {
        let err =
            tg_proxy::options::egress_from_text(line, "api").expect_err("it should have failed");
        assert!(format!("{err}").contains("egress"), "{line}: {err}");
    }
}

/// A workload without an entry gets an empty list -- and empty means
/// deny-by-default.
#[test]
fn a_workload_without_entries_gets_nothing() {
    let text = "ledger backup.internal 9000\n";

    let mine = tg_proxy::options::egress_from_text(text, "api").expect("readable");

    assert!(mine.is_empty());
}

/// **A prefix is no name.**
///
/// `api-test` must not get what `api` is permitted. A comparison that used
/// `starts_with` here would shift the boundary by every workload whose name
/// begins with another's.
#[test]
fn a_name_that_merely_starts_with_another_gets_nothing() {
    let text = "api s3.example.com 443\n";

    assert!(
        tg_proxy::options::egress_from_text(text, "api-test")
            .expect("readable")
            .is_empty()
    );
}

// ================================================ the own port

/// **A permission onto the egress port itself is discarded.**
///
/// It would be the bypass of the redirect: whoever dials the sidecar port
/// directly has not run through the rule set, and `SO_ORIGINAL_DST` then
/// names precisely that port. If it stood in the list, everyone who reaches
/// it would get out.
#[test]
fn a_permission_pointing_at_the_egress_port_is_dropped() {
    let (kept, dropped) = tg_proxy::egress::without_listen_port(
        [
            ("s3.example.com".to_owned(), 443, Transport::Tcp),
            ("secretly.example.com".to_owned(), 15002, Transport::Tcp),
        ],
        15002,
    );

    assert_eq!(
        kept,
        vec![("s3.example.com".to_owned(), 443, Transport::Tcp)]
    );
    assert_eq!(
        dropped,
        vec![("secretly.example.com".to_owned(), 15002, Transport::Tcp)],
        "the discarded permission must be named -- silently it would be a \
         riddle in operation"
    );
}

/// The same name with a different port stays.
///
/// The **permission** is discarded, not the name: a target that would happen
/// to be reachable on the egress port too loses only that port.
#[test]
fn only_the_offending_entry_goes() {
    let (kept, dropped) = tg_proxy::egress::without_listen_port(
        [
            ("s3.example.com".to_owned(), 443, Transport::Tcp),
            ("s3.example.com".to_owned(), 15002, Transport::Tcp),
        ],
        15002,
    );

    assert_eq!(
        kept,
        vec![("s3.example.com".to_owned(), 443, Transport::Tcp)]
    );
    assert_eq!(dropped.len(), 1);
}

/// Without a conflict everything stays -- the counter-check.
///
/// Without it the tests above would prove only that something is filtered.
#[test]
fn without_a_conflict_nothing_is_dropped() {
    let (kept, dropped) = tg_proxy::egress::without_listen_port(
        [("s3.example.com".to_owned(), 443, Transport::Tcp)],
        15002,
    );

    assert_eq!(kept.len(), 1);
    assert!(dropped.is_empty());
}

/// **When the permission list was last taken over is a number** -- the same
/// assurance as with the mesh edges.
///
/// It was missing, and the asymmetry lay in the same authorization layer:
/// fail-static means that a sidecar with an unreadable egress file **carries
/// on working** -- and carrying on working means here granting a
/// **withdrawn** permission to the outside on. From outside that looks like a
/// sidecar that works.
///
/// A **point in time**, no age: an age would have to be carried forward by
/// somebody and would look fresh between two carryings-forward. What is
/// asserted is therefore exactly what makes a point in time: it does not
/// move when only the clock runs on.
#[test]
fn the_reported_egress_state_does_not_move_with_the_clock() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let shared = tg_proxy::egress::SharedEgress::new(EgressPolicy::from_entries([(
        "s3.test".to_owned(),
        443,
        Transport::Tcp,
    )]));
    shared.replace(
        EgressPolicy::from_entries([("s3.test".to_owned(), 443, Transport::Tcp)]),
        1_000,
    );

    let seen: Vec<f64> = metrics::with_local_recorder(&recorder, || {
        for at in [1_005, 4_600] {
            tg_proxy::egress::report(&shared, at);
        }

        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter_map(|(key, _, _, value)| {
                (key.key().name() == tg_telemetry::names::PROXY_EGRESS_REFRESHED_AT)
                    .then_some(value)
            })
            .map(|value| match value {
                DebugValue::Gauge(seen) => seen.into_inner(),
                other => panic!("no gauge: {other:?}"),
            })
            .collect()
    });

    assert!(!seen.is_empty(), "the state must be reported");
    for value in seen {
        assert!(
            (value - 1_000.0).abs() < 1.0,
            "{value} instead of the point in time 1000 -- that is an age, and \
             a frozen writer would thereby look fresh"
        );
    }
}

// ==================================== the transport

/// **A line without a fourth word means `tcp`.**
///
/// It stems from before the transport field existed, and the log is kept for
/// retention. A different default would change retroactively what an
/// operator permitted -- the same consideration as at the log entry.
#[test]
fn a_line_without_a_transport_means_tcp() {
    let mine =
        tg_proxy::options::egress_from_text("api s3.example.com 443\n", "api").expect("readable");

    assert_eq!(
        mine,
        vec![("s3.example.com".to_owned(), 443, Transport::Tcp)]
    );
}

/// **The fourth word is read** -- and both transports side by side.
///
/// The same name and the same port over `tcp` **and** `quic` is the normal
/// case, no special case: an HTTP/3 client falls back to TCP when QUIC does
/// not get through.
#[test]
fn both_transports_may_stand_side_by_side() {
    let text = "\
api s3.example.com 443 tcp
api s3.example.com 443 quic
";
    let mine = tg_proxy::options::egress_from_text(text, "api").expect("readable");

    assert_eq!(
        mine,
        vec![
            ("s3.example.com".to_owned(), 443, Transport::Tcp),
            ("s3.example.com".to_owned(), 443, Transport::Quic),
        ]
    );
}

/// **The transport belongs to the key.**
///
/// Whoever permitted `quic` did not permit `tcp`. Without this separation the
/// fourth word would be an ornament: a permission for the one transport would
/// apply silently to the other.
#[test]
fn a_permission_for_one_transport_is_not_one_for_the_other() {
    let policy = EgressPolicy::from_entries([("s3.example.com".to_owned(), 443, Transport::Quic)]);

    assert!(policy.permits("s3.example.com", 443, Transport::Quic));
    assert!(
        !policy.permits("s3.example.com", 443, Transport::Tcp),
        "a QUIC permission opened the TCP way"
    );
}

/// **An unknown word is an error, no default.**
///
/// Pulling it quietly to `tcp` would make a **permission** out of a line the
/// sidecar does not understand -- a skew between agent and sidecar would
/// thereby be fail-open instead of fail-closed.
///
/// `"udp"` once stood here, and that was right in its time: plain UDP was
/// forbidden outright before the second cut of this feature. What the
/// sidecar does with it stands in the test beside this one.
#[test]
fn an_unknown_transport_is_refused_not_defaulted() {
    for word in ["UDP", "TCP", "sctp", "http3"] {
        let text = format!("api s3.example.com 443 {word}\n");
        assert!(
            tg_proxy::options::egress_from_text(&text, "api").is_err(),
            "'{word}' was accepted as a transport"
        );
    }
}

/// **The listening ports are those of the QUIC permissions** (ADR-0094,
/// determination 2).
///
/// Because the redirection works without a port setting, the sidecar must
/// listen on exactly the port the container chose -- and which ones those can
/// be is said by the allowlist alone.
#[test]
fn the_listening_ports_are_those_of_the_quic_permissions() {
    let policy = EgressPolicy::from_entries([
        ("s3.example.com".to_owned(), 443, Transport::Quic),
        ("logs.example.com".to_owned(), 8443, Transport::Quic),
        // The same port over quic at a second name: **one** listener.
        ("backup.example.com".to_owned(), 443, Transport::Quic),
        // And a TCP target: there a fixed egress port stands, not one of its own.
        ("api.partner.example".to_owned(), 9443, Transport::Tcp),
    ]);

    assert_eq!(policy.quic_ports(), vec![443, 8443]);
}

/// **Without a QUIC permission no listener.**
///
/// The counter-check: a sidecar whose workload has only TCP targets binds not
/// a single UDP port -- and a workload without a permission even less so.
/// Without it a list that always returns something would be green too.
#[test]
fn without_a_quic_permission_no_port_is_bound() {
    let only_tcp = EgressPolicy::from_entries([("s3.example.com".to_owned(), 443, Transport::Tcp)]);
    assert!(only_tcp.quic_ports().is_empty());

    let nothing = EgressPolicy::from_entries([]);
    assert!(nothing.quic_ports().is_empty());
}

/// **A `udp` line does not take the workload's egress away** (ADR-0092, D5).
///
/// The sidecar has nothing to do for plain UDP -- the agent lays one nftables
/// rule per address for it. **Refusing** it for that reason would be the
/// obvious strictness and the expensive error: `egress_from_text` then returns
/// `Err` for the **whole** file, and a single UDP permission would cost the
/// same workload its TCP and QUIC way.
///
/// So it is read, and it opens **nothing**: a request always carries `tcp` or
/// `quic`, and the comparison is the whole key.
#[test]
fn a_udp_line_is_read_and_opens_nothing_in_the_sidecar() {
    let entries = tg_proxy::options::egress_from_text(
        "api ntp.example.com 123 udp\napi s3.example.com 443 quic\n",
        "api",
    )
    .expect("a udp line must not make the file unusable");
    let policy = EgressPolicy::from_entries(entries);

    assert!(
        policy.permits("s3.example.com", 443, Transport::Quic),
        "the other permissions must apply on"
    );
    assert!(
        !policy.permits("ntp.example.com", 123, Transport::Tcp)
            && !policy.permits("ntp.example.com", 123, Transport::Quic),
        "a udp permission must open no way in the sidecar"
    );
    assert!(
        policy.quic_ports() == vec![443],
        "a udp port must get no listener: {:?}",
        policy.quic_ports()
    );
}

/// **The bolt applies to every transport** (ADR-0051 D3, ADR-0092).
///
/// Its rationale is a TCP property (`SO_ORIGINAL_DST`), and since ADR-0092 a
/// permission carries a transport -- the three witnesses above all check
/// `Tcp`. What applies for `quic` stands at the code: the listening port
/// **is** the permitted port there (ADR-0094), so a UDP listener would lie
/// exactly on the TCP egress port, and `nft list` would show two redirections
/// onto the same number with different meanings.
///
/// For `udp` it is too strict and stays so: **one** rule instead of three
/// cases, and the price stands at the code.
#[test]
fn the_bar_holds_for_every_transport() {
    let (kept, dropped) = tg_proxy::egress::without_listen_port(
        [
            ("permitted.example.com".to_owned(), 443, Transport::Quic),
            ("secretly.example.com".to_owned(), 15002, Transport::Quic),
            ("also.example.com".to_owned(), 15002, Transport::Udp),
            ("and.example.com".to_owned(), 15002, Transport::Tcp),
        ],
        15002,
    );

    assert_eq!(
        kept,
        vec![("permitted.example.com".to_owned(), 443, Transport::Quic)],
        "only the foreign port stays -- and it stays, otherwise the bolt would \
         take more than its one permission"
    );
    assert_eq!(
        dropped.len(),
        3,
        "every transport on the own port goes: {dropped:?}"
    );
}

/// **A wildcard permits the bucket, and only it** (ADR-0124).
///
/// # The finding
///
/// Until ADR-0124 `*.s3.example.com` was **accepted everywhere** -- by the
/// state machine, by the log, by the slice, by the file -- and took effect
/// **nowhere**: `permits` compared exactly, so the target was forbidden
/// although it stood in the permission. Measured:
///
/// ```text
/// parsed: [("*.s3.example.com", 443, Tcp)]
///   permits(mybucket.s3.example.com) = false
/// ```
///
/// Both are checked: that it carries now, **and** that it covers no more than
/// one label -- otherwise the relaxation would be an invitation.
#[test]
fn a_wildcard_permits_the_bucket_and_only_the_bucket() {
    let policy = EgressPolicy::from_entries([
        ("*.s3.example.com".to_owned(), 443, Transport::Tcp),
        ("logs.example.com".to_owned(), 443, Transport::Tcp),
    ]);

    assert!(
        policy.permits("mybucket.s3.example.com", 443, Transport::Tcp),
        "precisely for that the wildcard exists: the bucket stands in the name"
    );
    assert!(
        policy.permits("other.s3.example.com", 443, Transport::Tcp),
        "and for every further one, without a second log entry"
    );

    // **Exactly one label**, not arbitrarily deep.
    assert!(!policy.permits("a.b.s3.example.com", 443, Transport::Tcp));
    // **Not the name itself** -- whoever means both writes both.
    assert!(!policy.permits("s3.example.com", 443, Transport::Tcp));
    // And the find from 10d applies on.
    assert!(!policy.permits("evil-s3.example.com", 443, Transport::Tcp));
    assert!(!policy.permits("mybucket.s3.example.com.evil.net", 443, Transport::Tcp));

    // The star relaxes **only** the name: the port and the transport stay as
    // they were.
    assert!(!policy.permits("mybucket.s3.example.com", 8443, Transport::Tcp));
    assert!(!policy.permits("mybucket.s3.example.com", 443, Transport::Quic));

    // And an entry without a star stays exact.
    assert!(policy.permits("logs.example.com", 443, Transport::Tcp));
    assert!(!policy.permits("x.logs.example.com", 443, Transport::Tcp));
}

/// **An address without a route falls away before it costs anything**
/// (ADR-0136, determination 2).
///
/// # The finding
///
/// `Resolver::resolve` took `lookup_host(…).next()` -- the **first**.
/// Measured, with a dual-stack name that is the IPv6 address:
///
/// ```text
/// localhost: [[::1]:443, 127.0.0.1:443]  ->  Some([::1]:443)
/// ```
///
/// A container has no IPv6 address and no route there (ADR-0012). An endpoint
/// with an AAAA record was thereby a **silent** egress failure, even with a
/// flawless A record -- and dual stack is the normal case.
///
/// # Why `localhost`
///
/// It is the only name that has both guaranteed without a network. The witness
/// thereby checks the selection and not the resolution.
#[tokio::test]
async fn an_address_without_a_route_is_dropped_before_it_costs_anything() {
    let found = tg_proxy::egress::Resolver::System
        .resolve("localhost", 443)
        .await;

    assert!(
        !found.is_empty(),
        "localhost does not resolve -- then this witness measures nothing"
    );
    assert!(
        found.iter().all(std::net::SocketAddr::is_ipv4),
        "an address without a route in the namespace was left over: {found:?}"
    );

    // The counter-check to the counter-check: the raw resolution very much
    // names both, and **first** the one that does not work. Without it the
    // test would be green too if this machine knew no IPv6.
    let raw: Vec<std::net::SocketAddr> = tokio::net::lookup_host(("localhost", 443))
        .await
        .expect("the resolution")
        .collect();
    assert!(
        raw.iter().any(std::net::SocketAddr::is_ipv6),
        "this machine knows no IPv6 for localhost -- the witness then confirms \
         itself: {raw:?}"
    );
}

/// **The dialler walks the list until one answers** (ADR-0136,
/// determination 1).
///
/// An endpoint with several A records is the construction with which an
/// operator catches outages. Until here it got **one** attempt: if the first
/// address was dead, the way out was closed.
#[tokio::test]
async fn the_dialler_walks_the_list_until_one_answers() {
    let live = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the listener");
    let reachable = live.local_addr().expect("the address");

    // An address on which **nothing** listens: bound, read, released.
    let dead = {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the listener");
        socket.local_addr().expect("the address")
    };

    let stream = tg_proxy::egress::dial_any(&[dead, reachable])
        .await
        .expect("the second address answers");
    assert_eq!(
        stream.peer_addr().expect("the counterpart"),
        reachable,
        "the connection went to the wrong address"
    );

    // And the counter-check: if none is reachable, there is nothing.
    assert!(
        tg_proxy::egress::dial_any(&[dead]).await.is_none(),
        "a dead address must yield no connection"
    );
}
