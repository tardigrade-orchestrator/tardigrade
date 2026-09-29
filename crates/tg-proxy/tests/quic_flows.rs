//! The state of a QUIC egress flow (ADR-0094, determination 5).
//!
//! The datagrams come from a **container**. What is decided here is checkable
//! without a socket and without an allowlist: `permits` is handed in, not
//! asked.
//!
//! The basis are the same recordings as in `quic_initial.rs` -- real Initials
//! from ngtcp2/OpenSSL 3.5, the provenance in `data/PROVENANCE.md`.
//!
//! # What a flow may cost (ADR-0121)
//!
//! The bound was checked as a **number** -- the 513th flow is refused, and
//! that is true. What a flow **holds** in the process nothing checked:
//! measured, one that never decides bound 510.1 KiB, that is, 255 MiB at
//! `MAX_FLOWS`, per listener, out of a container. The witnesses for it stand
//! below.
//!
//! One of them needs a **socket**, against the announcement of the paragraph
//! above: a truncation arises in the kernel, and a `recv` that cuts off
//! quietly cannot be demonstrated without one. It needs no privileges for
//! it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tg_proxy::quic::QuicError;
use tg_proxy::quic_egress;
use tg_proxy::quic_egress::{
    Budget, Flows, IDLE, MAX_DATAGRAM, MAX_FLOWS, MAX_PENDING, MAX_PENDING_BYTES, Refusal, Step,
};

const NAMED: [&[u8]; 2] = [
    include_bytes!("data/named_0.bin"),
    include_bytes!("data/named_1.bin"),
];
const ANONYMOUS: [&[u8]; 2] = [
    include_bytes!("data/anon_0.bin"),
    include_bytes!("data/anon_1.bin"),
];

const NAME: &str = "s3.example.com";
const PORT: u16 = 443;

fn flow(port: u16) -> (SocketAddr, u16) {
    ("10.42.1.5:51000".parse().expect("the address"), port)
}

fn allow_all(_host: &str, _port: u16) -> bool {
    true
}

fn allow_nothing(_host: &str, _port: u16) -> bool {
    false
}

/// **The name arises only from both datagrams -- and then forwarding
/// happens.**
///
/// The first alone yields `Wait`, and that is no formality: the datagram
/// belongs to the handshake and must go out as soon as the destination is
/// settled. Whoever discarded it would rob every client with post-quantum key
/// shares of its connection (ADR-0092, determination 4).
#[test]
fn a_flow_waits_for_its_name_and_then_forwards() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    assert_eq!(
        flows.absorb(flow(PORT), NAMED[0], now, &allow_all),
        Step::Wait
    );
    assert_eq!(
        flows.absorb(flow(PORT), NAMED[1], now, &allow_all),
        Step::Forward {
            host: NAME.to_owned()
        }
    );
}

/// **A decided flow is not checked anew.**
///
/// The withdrawal runs over the guard, not over every datagram -- the same
/// construction as with the TCP egress (ADR-0041).
///
/// **With that `Retry` and version negotiation are covered** -- the point
/// ADR-0092 names as "to be decided at the build". Both come from the
/// **server** and force a *second* Initial from the client, with a new DCID
/// and possibly a different version. For the relay that is a datagram on a
/// decided flow: it goes out unchanged, without the name being read again. The
/// permission hangs on the **flow** (the 4-tuple), not on the packet -- and
/// that is why no line is needed for it.
///
/// What is **not** covered stands in the ADR too: a connection migration that
/// changes the 4-tuple loses the assignment.
///
/// **Measured**, a follow-up datagram without this assertion yields not an
/// error but `Forward` again: the `Handshake` holds the finished
/// `ClientHello`, and a packet that is no Initial only ends its pass. The
/// difference is thereby no crash but the **semantics** -- the permission
/// would be checked anew per datagram instead of over the guard in the window
/// (ADR-0041), and that costs one lookup per packet in the data plane
/// (ADR-0022).
#[test]
fn a_decided_flow_is_not_asked_again() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    let _ = flows.absorb(flow(PORT), NAMED[0], now, &allow_all);
    let _ = flows.absorb(flow(PORT), NAMED[1], now, &allow_all);

    assert_eq!(
        flows.absorb(flow(PORT), b"any payload", now, &allow_all),
        Step::Established,
        "a running flow must not fail on the ClientHello"
    );
}

/// **Without a permission no way out** (ADR-0041, deny-by-default).
///
/// And the flow is **forgotten** in the process: a refused one must bind no
/// place, otherwise a container would fill the stock with nothing but
/// refusals.
#[test]
fn a_name_without_a_permission_is_refused_and_forgotten() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    let _ = flows.absorb(flow(PORT), NAMED[0], now, &allow_nothing);
    assert_eq!(
        flows.absorb(flow(PORT), NAMED[1], now, &allow_nothing),
        Step::Refuse(Refusal::NotAllowed {
            host: NAME.to_owned()
        })
    );
    assert!(flows.is_empty(), "a refused flow binds a place");
}

/// **The port belongs to the key.**
///
/// The same container may phone two endpoints on different ports at the same
/// time, and both are QUIC connections of their own. Without the port in the
/// key the second would run into the first's `Handshake`.
#[test]
fn two_ports_from_the_same_sender_are_two_flows() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    assert_eq!(
        flows.absorb(flow(443), NAMED[0], now, &allow_all),
        Step::Wait
    );
    assert_eq!(
        flows.absorb(flow(8443), NAMED[0], now, &allow_all),
        Step::Wait
    );
    assert_eq!(flows.len(), 2);
}

/// **A `ClientHello` without an SNI is unassignable.**
#[test]
fn a_flow_without_a_name_is_refused() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    let _ = flows.absorb(flow(PORT), ANONYMOUS[0], now, &allow_all);
    assert_eq!(
        flows.absorb(flow(PORT), ANONYMOUS[1], now, &allow_all),
        Step::Refuse(Refusal::Anonymous)
    );
    assert!(flows.is_empty());
}

/// **What is no QUIC binds no place.**
#[test]
fn rubbish_is_refused_and_forgotten() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    // **And the reason is called what it is** (ADR-0131): no Initial begins
    // here. Until then that meant the same as a version we do not read, and
    // the same as a connection migration.
    let step = flows.absorb(flow(PORT), b"no QUIC", now, &allow_all);
    assert_eq!(
        step,
        Step::Refuse(Refusal::Unreadable(QuicError::NotInitial))
    );
    let Step::Refuse(reason) = step else {
        panic!("it should have been refused");
    };
    assert_eq!(reason.reason(), "not_initial");
    assert!(flows.is_empty());
}

/// **The stock is bounded** (ADR-0094, determination 5).
///
/// A container that uses arbitrarily many sender ports must not tie up memory.
/// The counter-check stands beside it: up to the bound acceptance happens -- a
/// bound that refuses everything would be green too and would take every
/// workload's way out.
#[test]
fn the_number_of_flows_is_bounded() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    for port in 0..u16::try_from(MAX_FLOWS).expect("fits") {
        assert_eq!(
            flows.absorb(flow(port), NAMED[0], now, &allow_all),
            Step::Wait,
            "up to the bound acceptance must happen"
        );
    }
    assert_eq!(flows.len(), MAX_FLOWS);

    assert_eq!(
        flows.absorb(flow(60000), NAMED[0], now, &allow_all),
        Step::Refuse(Refusal::TooMany)
    );
}

/// **A dead flow does not cost a new one its place.**
///
/// Clear first, then refuse. Without this order a listener would stay
/// permanently full after a rush -- with nothing but flows from which no
/// datagram ever comes again.
#[test]
fn a_silent_flow_makes_room_again() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    for port in 0..u16::try_from(MAX_FLOWS).expect("fits") {
        let _ = flows.absorb(flow(port), NAMED[0], now, &allow_all);
    }

    let later = now + IDLE + Duration::from_secs(1);
    assert_eq!(
        flows.absorb(flow(60000), NAMED[0], later, &allow_all),
        Step::Wait,
        "after the deadline there must be room again"
    );
    assert_eq!(flows.len(), 1, "the dead flows are not gone");
}

/// **A flow that carries on speaking does not expire.**
///
/// The counter-check to the test above: without it a stock that clears
/// everything away at every datagram would be green too -- and every QUIC
/// connection would fall apart after the first packet.
#[test]
fn a_speaking_flow_does_not_expire() {
    let mut flows: Flows<()> = Flows::default();
    let mut now = Instant::now();

    let _ = flows.absorb(flow(PORT), NAMED[0], now, &allow_all);
    for _ in 0..5 {
        now += IDLE / 2;
        let _ = flows.absorb(flow(PORT), NAMED[0], now, &allow_all);
    }

    assert_eq!(flows.len(), 1, "the flow expired although it spoke");
}

/// **The datagrams before the decision go out** (ADR-0092, determination 4).
///
/// They belong to the handshake. Whoever discarded them would rob every client
/// with post-quantum key shares of its connection -- the `ClientHello` then
/// does not fit into one Initial, and without the first datagram the endpoint
/// cannot assemble it.
///
/// **Taken out, not read:** they go out exactly once.
#[test]
fn the_datagrams_before_the_decision_are_kept_and_taken_once() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    let _ = flows.absorb(flow(PORT), NAMED[0], now, &allow_all);
    let _ = flows.absorb(flow(PORT), NAMED[1], now, &allow_all);

    let pending = flows.take_pending(&flow(PORT));
    assert_eq!(
        pending.len(),
        2,
        "both datagrams of the handshake must go out"
    );
    assert_eq!(pending[0], NAMED[0], "and in the order in which they came");

    assert!(
        flows.take_pending(&flow(PORT)).is_empty(),
        "they go out exactly once"
    );
}

/// **The way out falls with its flow.**
///
/// It lies with the flow and not in a second map of the caller's: two maps
/// with the same key would have to be kept the same, and the expiry deadline
/// would clear only one of them -- the other's sockets would stay lying.
#[test]
fn what_a_flow_carries_expires_with_it() {
    let mut flows: Flows<u32> = Flows::default();
    let now = Instant::now();

    let _ = flows.absorb(flow(PORT), NAMED[0], now, &allow_all);
    flows.carry(&flow(PORT), 4711);
    assert_eq!(flows.carried(&flow(PORT)), Some(&4711));

    // Another flow after the deadline clears the first away along with it.
    let later = now + IDLE + Duration::from_secs(1);
    let _ = flows.absorb(flow(9999), NAMED[0], later, &allow_all);

    assert_eq!(
        flows.carried(&flow(PORT)),
        None,
        "the way out outlived its flow -- then sockets stay lying"
    );
}

/// **The keeping is bounded too** (ADR-0094, determination 5).
///
/// A client that sends arbitrarily many incomplete Initials must not tie up
/// memory. The counter-check sits in the first assertion: up to the bound
/// there really is keeping.
#[test]
fn the_pending_datagrams_are_bounded() {
    use tg_proxy::quic_egress::MAX_PENDING;

    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    for _ in 0..MAX_PENDING * 4 {
        assert_eq!(
            flows.absorb(flow(PORT), NAMED[0], now, &allow_all),
            Step::Wait
        );
    }

    assert_eq!(flows.take_pending(&flow(PORT)).len(), MAX_PENDING);
}

// --- the reconcile of the listeners against the allowlist (ADR-0094, D2) ---
//
// A pure computation: what is to be opened, what to be closed. It lies open so
// that its omissions are visible without sockets -- a rule one can check only
// at a running sidecar is one whose edges nobody has ever seen.

#[test]
fn an_unchanged_allowlist_moves_no_listener() {
    let step = quic_egress::adjust(&[443, 8443], &[443, 8443]);

    assert!(step.open.is_empty(), "nothing to open: {:?}", step.open);
    assert!(step.close.is_empty(), "nothing to close: {:?}", step.close);
}

#[test]
fn a_new_permission_opens_exactly_its_port() {
    let step = quic_egress::adjust(&[443, 8443], &[443]);

    assert_eq!(step.open, vec![8443]);
    assert!(step.close.is_empty(), "nothing to close: {:?}", step.close);
}

#[test]
fn a_revoked_permission_closes_exactly_its_port() {
    let step = quic_egress::adjust(&[443], &[443, 8443]);

    assert!(step.open.is_empty(), "nothing to open: {:?}", step.open);
    assert_eq!(step.close, vec![8443]);
}

#[test]
fn an_empty_allowlist_closes_every_listener() {
    // Deny-by-default (ADR-0041): no permission means no way out, and a
    // listener that serves nobody any more is an open port.
    let step = quic_egress::adjust(&[], &[443, 8443]);

    assert_eq!(step.close, vec![443, 8443]);
}

#[test]
fn a_repeated_port_does_not_churn() {
    // `quic_ports` already sorts and deduplicates -- the reconcile must not
    // rely on that nevertheless: otherwise a duplicated line in the permission
    // file would close a listener that is meant to exist.
    let step = quic_egress::adjust(&[8443, 443, 443], &[443, 8443]);

    assert!(step.open.is_empty(), "nothing to open: {:?}", step.open);
    assert!(step.close.is_empty(), "nothing to close: {:?}", step.close);
}

/// **A flow that bursts the bound starts afresh** (ADR-0094,
/// determination 5).
///
/// That is the availability side of the bound from ADR-0092 determination 4:
/// if the stock held the broken assembler, the same flow would from then on
/// give a finding **forever** -- and would occupy one of `MAX_FLOWS` places in
/// the process. A duplicating network would thereby cost not one handshake but
/// this sender port's way out.
///
/// The effect is checked in three steps: the refusal comes, the place is free,
/// and **the same** flow carries again afterwards -- together, for
/// individually none of them says anything. A stock that throws every flow
/// away after every datagram would pass the first two.
#[test]
fn a_flow_that_hits_the_ceiling_starts_over() {
    let now = std::time::Instant::now();
    let target = flow(PORT);
    let mut flows: Flows<()> = Flows::default();

    // Repeat until the assembler refuses. The upper bound keeps a test from
    // hanging if the bound one day falls out.
    let mut refused = None;
    for round in 1..=10_000_u32 {
        if let Step::Refuse(reason) = flows.absorb(target, NAMED[0], now, &allow_all) {
            refused = Some((round, reason));
            break;
        }
    }

    let Some((round, reason)) = refused else {
        panic!("the assembler never refused -- the bound does not bite");
    };
    assert_eq!(
        reason,
        Refusal::Unreadable(QuicError::TooMuch),
        "round {round}: the bound is to appear as a finding at the datagram"
    );
    // A burst bound is something other than a broken frame (ADR-0131,
    // determination 1) -- an operator looks for those in different places.
    assert_eq!(reason.reason(), "too_much");
    assert_eq!(
        flows.len(),
        0,
        "round {round}: the place must become free, otherwise a duplicating \
         network holds one of {MAX_FLOWS} places permanently"
    );

    // And the same flow carries again afterwards -- with a complete flight.
    assert!(matches!(
        flows.absorb(target, NAMED[0], now, &allow_all),
        Step::Wait
    ));
    assert_eq!(
        flows.absorb(target, NAMED[1], now, &allow_all),
        Step::Forward {
            host: NAME.to_owned()
        },
        "after the bound the same flow must be able to start from the beginning"
    );
}

/// **What a flow holds before the decision is bounded in bytes** (ADR-0121,
/// determination 3).
///
/// `MAX_PENDING` counts pieces, and a bound over pieces is none over memory as
/// long as a piece may be arbitrarily large. Measured, a flow thereby bound
/// half a megabyte -- eight datagrams of 65 000 bytes each, and the number
/// eight did not say so.
///
/// It is checked at `absorb` and not at the socket: `receive` already refuses
/// a too large datagram today (determination 2), so the way over the socket
/// would be a witness for the **other** determination. This one here carries
/// the case that somebody raises `MAX_DATAGRAM` and forgets this bound.
#[test]
fn what_a_flow_keeps_before_deciding_is_bounded_in_bytes() {
    let now = Instant::now();
    let target = flow(PORT);
    let mut flows: Flows<()> = Flows::default();

    // A real fragment, blown up to a multiple of the bound -- precisely what
    // a container sends when it wants to tie up memory.
    let mut fat = NAMED[0].to_vec();
    fat.resize(65_000, 0);

    for round in 0..MAX_PENDING * 2 {
        assert_eq!(
            flows.absorb(target, &fat, now, &allow_all),
            Step::Wait,
            "round {round}: a fragment stays a fragment"
        );
    }

    let kept: usize = flows.take_pending(&target).iter().map(Vec::len).sum();
    assert!(
        kept <= MAX_PENDING_BYTES,
        "a flow holds {kept} bytes -- permitted are {MAX_PENDING_BYTES}; \
         without this bound it was 520 000"
    );
}

/// **A datagram over the bound is discarded, not truncated** (ADR-0121,
/// determination 2).
///
/// `recv` on a UDP socket cuts off quietly. Passing a cut-off datagram on
/// would tear the QUIC connection apart, and nobody would know why -- the
/// sidecar does not terminate (ADR-0041), so it never sees the damage.
///
/// The counter-check stands beside it: **exactly** `MAX_DATAGRAM` bytes arrive
/// in full. Without it the test would prove only that something refuses.
#[test]
fn a_datagram_over_the_limit_is_refused_instead_of_truncated() {
    let listener = quic_egress::listener(0).expect("the listener");
    let addr = listener.local_addr().expect("the address");
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("the sender");
    sender
        .connect(SocketAddr::from(([127, 0, 0, 1], addr.port())))
        .expect("connect");
    listener
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("the deadline");
    listener.set_nonblocking(false).expect("blocking");

    // Exactly on the bound: that must get through.
    sender.send(&vec![7_u8; MAX_DATAGRAM]).expect("send");
    let datagram = quic_egress::receive(&listener).expect("exactly the bound carries");
    assert_eq!(
        datagram.bytes.len(),
        MAX_DATAGRAM,
        "at the bound nothing may be missing"
    );

    // One byte above: refused, not truncated.
    sender.send(&vec![7_u8; MAX_DATAGRAM + 1]).expect("send");
    let err = quic_egress::receive(&listener).expect_err("above it there is a refusal");
    assert!(
        err.to_string().contains("larger than"),
        "the reason belongs in the message, not in a quiet truncation: {err}"
    );
}

/// **The bound applies to the sidecar, not to the listener** (ADR-0121, D4).
///
/// There is one listener per permitted port (ADR-0094, determination 2). If
/// the bound were its own, the demand would grow with the number of
/// permissions -- and a permission (ADR-0041) decides nothing about memory.
/// The OOM killer knows no listeners anyway (ADR-0086).
///
/// The counter-check is half the witness: with budgets of their **own** every
/// listener gets its full number -- precisely the state from before
/// ADR-0121.
#[test]
fn the_ceiling_belongs_to_the_sidecar_not_to_one_listener() {
    let now = Instant::now();
    let limit = 8;

    let shared = Arc::new(Budget::with_limit(limit));
    let mut first: Flows<()> = Flows::sharing(Arc::clone(&shared));
    let mut second: Flows<()> = Flows::sharing(Arc::clone(&shared));

    for port in 0..u16::try_from(limit).expect("fits") {
        assert_eq!(
            first.absorb(flow(port), NAMED[0], now, &allow_all),
            Step::Wait,
            "up to the bound the first listener accepts"
        );
    }
    assert_eq!(shared.open(), limit);

    assert_eq!(
        second.absorb(flow(4242), NAMED[0], now, &allow_all),
        Step::Refuse(Refusal::TooMany),
        "the second listener shares the bound -- otherwise the sidecar \
         carries ports x bound flows"
    );
    assert_eq!(second.len(), 0, "and it keeps nothing of it");

    // The counter-check: own budgets, and the same flow gets through.
    let mut lonely: Flows<()> = Flows::sharing(Arc::new(Budget::with_limit(limit)));
    assert_eq!(
        lonely.absorb(flow(4242), NAMED[0], now, &allow_all),
        Step::Wait,
        "without a shared budget precisely that would be the state from before"
    );
}

/// **A flow that falls gives its place back** (ADR-0121, D4).
///
/// The permit lies **in** the flow so that its `Drop` gives it back -- the
/// same construction as the way back in ADR-0094. A count beside it would have
/// to be kept the same by somebody, and the expiry deadline would clear only
/// one of the two.
///
/// All three ways on which a flow falls are checked: the deadline, the
/// take-back and the refusal.
#[test]
fn a_flow_that_falls_gives_its_place_back() {
    let budget = Arc::new(Budget::with_limit(4));
    let mut flows: Flows<()> = Flows::sharing(Arc::clone(&budget));
    let now = Instant::now();

    // 1. The deadline.
    assert_eq!(flows.absorb(flow(1), NAMED[0], now, &allow_all), Step::Wait);
    assert_eq!(budget.open(), 1);
    assert_eq!(
        flows.absorb(
            flow(2),
            NAMED[0],
            now + IDLE + Duration::from_secs(1),
            &allow_all
        ),
        Step::Wait
    );
    assert_eq!(
        budget.open(),
        1,
        "the expired flow must have given its place back"
    );

    // 2. The take-back.
    flows.forget(&flow(2));
    assert_eq!(budget.open(), 0, "whoever is taken back gives back");

    // 3. The refusal at the allowlist.
    let later = now + IDLE + Duration::from_secs(1);
    assert_eq!(
        flows.absorb(flow(3), NAMED[0], later, &allow_nothing),
        Step::Wait
    );
    assert!(matches!(
        flows.absorb(flow(3), NAMED[1], later, &allow_nothing),
        Step::Refuse(Refusal::NotAllowed { .. })
    ));
    assert_eq!(
        budget.open(),
        0,
        "a refused flow must keep no place -- otherwise a container fills the \
         bound with targets it may not reach at all"
    );
}

/// **A silent listener holds the whole sidecar's places** -- until the
/// deadline fetches them (ADR-0130).
///
/// The budget applies to the sidecar (ADR-0121, determination 4), the map lies
/// per listener, and there is one listener per permitted port (ADR-0094).
/// Until ADR-0130 only `absorb` swept, that is, only on traffic: a listener
/// whose traffic dries up held all the places fast, and **another** port of
/// the same workload got `TooMany` for it -- permanently, for the only broom
/// sat in the loop that was just no longer running.
///
/// The counter-check stands **in** the test and not beside it: without the
/// sweeping B is out, afterwards in. A test that showed only the afterwards
/// would be green too if the budget had never bitten.
#[test]
fn a_silent_listener_returns_its_slots_to_the_sidecar() {
    let budget = Arc::new(Budget::with_limit(4));
    let mut a: Flows<()> = Flows::sharing(Arc::clone(&budget));
    let mut b: Flows<()> = Flows::sharing(Arc::clone(&budget));
    let now = Instant::now();

    for port in 0..4 {
        assert_eq!(a.absorb(flow(port), NAMED[0], now, &allow_all), Step::Wait);
    }
    assert_eq!(budget.open(), 4, "the rush must fill the budget");

    // Long after the deadline -- and A has seen no datagram since.
    let later = now + IDLE * 100;
    assert_eq!(
        b.absorb(flow(9000), NAMED[0], later, &allow_all),
        Step::Refuse(Refusal::TooMany),
        "that was the situation: B is refused although A's flows are a \
         hundred deadlines old"
    );

    a.expire(later);
    assert_eq!(
        budget.open(),
        0,
        "the deadline must give the places back, without a datagram too"
    );
    assert_eq!(
        b.absorb(flow(9001), NAMED[0], later, &allow_all),
        Step::Wait,
        "and afterwards the other listener gets out again"
    );
}

/// **Three causes, three labels** (ADR-0131, determination 1).
///
/// Measured, they all fell onto `malformed`, and the manual read that as "no
/// QUIC client is speaking there" -- while in all three one very much was
/// speaking. What a container learns stays silence (ADR-0041); the metric is
/// the only way to interpret that silence (ADR-0121, determination 6), and it
/// pointed in the wrong direction.
///
/// The counter-check sits in the last assertion: **the three labels must be
/// different.** Without it the test would be green too if they all fell onto
/// one value again.
#[test]
fn every_unreadable_datagram_names_its_own_cause() {
    let now = Instant::now();
    let mut flows: Flows<()> = Flows::default();

    // 1. A connection migration: the same client, a new source port -- and
    //    thereby a short-header packet, as it flies after the handshake. No
    //    Initial begins.
    let mut short = vec![0x40_u8];
    short.extend_from_slice(&[0xab; 8]);
    short.extend_from_slice(&[0x11; 40]);
    let migrated = refusal(&mut flows, flow(1), &short, now);
    assert_eq!(migrated.reason(), "not_initial");

    // 2. A version we do not read (QUIC v2, RFC 9369): the same ClientHello, a
    //    different number in the head.
    let mut v2 = NAMED[0].to_vec();
    v2[1..5].copy_from_slice(&0x6b33_43cf_u32.to_be_bytes());
    let version = refusal(&mut flows, flow(2), &v2, now);
    assert_eq!(version.reason(), "version");
    // **The number stands in the text, not in the label** (determination 2): a
    // label with values from a container would be a memory leak (ADR-0015).
    assert!(
        version.to_string().contains("0x6b3343cf"),
        "the unread version must stand in the log: {version}"
    );

    // 3. A retry **before** the decision: the client draws the new DCID, and
    //    the keys from the old one no longer fit.
    let mut late: Flows<()> = Flows::default();
    assert_eq!(late.absorb(flow(3), NAMED[0], now, &allow_all), Step::Wait);
    let mut other = NAMED[0].to_vec();
    other[6..14].copy_from_slice(&[0x99; 8]);
    let retry = refusal(&mut late, flow(3), &other, now);
    assert_eq!(retry.reason(), "undecryptable");
    assert_eq!(
        late.len(),
        0,
        "the flow must be cleared away -- the next attempt begins cleanly and \
         uses no second place (ADR-0131, determination 4)"
    );

    let labels =
        std::collections::BTreeSet::from([migrated.reason(), version.reason(), retry.reason()]);
    assert_eq!(
        labels.len(),
        3,
        "three causes that fall onto one label are no diagnosis: {labels:?}"
    );
}

/// **A retry after the decision goes out** (ADR-0131, determination 4).
///
/// The counter-check to the case above: the flow is decided, a second Initial
/// with a new DCID is not checked anew. Without it the test above would show
/// only that a retry somehow fails -- including when it **always** fails.
#[test]
fn a_retry_after_the_decision_is_carried_on() {
    let mut flows: Flows<()> = Flows::default();
    let now = Instant::now();

    assert_eq!(
        flows.absorb(flow(PORT), NAMED[0], now, &allow_all),
        Step::Wait
    );
    assert!(matches!(
        flows.absorb(flow(PORT), NAMED[1], now, &allow_all),
        Step::Forward { .. }
    ));

    let mut other = NAMED[0].to_vec();
    other[6..14].copy_from_slice(&[0x99; 8]);
    assert_eq!(
        flows.absorb(flow(PORT), &other, now, &allow_all),
        Step::Established,
        "a decided flow is not checked anew"
    );
}

/// Refuses and gives the reason -- or fails with what came instead.
fn refusal(flows: &mut Flows<()>, flow: (SocketAddr, u16), bytes: &[u8], now: Instant) -> Refusal {
    match flows.absorb(flow, bytes, now, &allow_all) {
        Step::Refuse(reason) => reason,
        other => panic!("it should have been refused, but was {other:?}"),
    }
}
