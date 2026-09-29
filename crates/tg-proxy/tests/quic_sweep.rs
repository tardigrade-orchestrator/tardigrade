//! The deadline clears away even when nobody speaks any more (ADR-0130).
//!
//! # What is measured here, and why it takes time
//!
//! Until ADR-0130 `Flows::expire` had **one** caller: `Flows::absorb`. So the
//! deadline ran only on traffic -- and the case it exists for is the one in
//! which none flows any more. Measured, a listener held 512 flows over
//! 100 x `IDLE`, and **another** listener of the same sidecar got `TooMany`
//! for it; the budget applies to the sidecar (ADR-0121, determination 4).
//!
//! That the repair bites is shown by `quic_flows.rs` without a socket and in
//! milliseconds. What **this** witness shows is the other half: that it is
//! also **called**, by nobody but the clock. That cannot be shortened -- the
//! deadline is a minute, and a number the test sets would not be the number
//! that applies in operation.
//!
//! `#[ignore]`: **not** because of privileges -- it needs none -- but because
//! of the duration. It runs with `cargo xtask net`, where the rest of the QUIC
//! witnesses lie.

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tg_proxy::egress::{EgressPolicy, Resolver, SharedEgress, Transport};
use tg_proxy::quic_egress::{Budget, IDLE};

/// A single Initial: it does not name the name yet, so the flow waits -- and
/// holds its place. Precisely the state from the measurement.
const NAMED0: &[u8] = include_bytes!("data/named_0.bin");

/// The name in the complete `ClientHello`. It is never reached here; the
/// allowlist stands nevertheless, so that the setup equals operation's.
const NAME: &str = "s3.example.com";

/// How many flows the budget carries. Small, because each costs a sender
/// socket of its own -- what is measured is the deadline, not the bound.
const LIMIT: usize = 2;

/// **The broom sweeps by the clock** (ADR-0130, determination 1).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "takes a deadline (around 60 s); cargo xtask net"]
async fn a_listener_that_hears_nothing_still_frees_its_slots() {
    let socket = tg_proxy::quic_egress::listener(0).expect("the listener");
    let port = socket.local_addr().expect("the address").port();

    let policy = SharedEgress::new(EgressPolicy::from_entries([(
        NAME.to_owned(),
        port,
        Transport::Quic,
    )]));
    // A target that is never dialled: a single Initial decides nothing
    // (ADR-0092, determination 4).
    let resolver = Resolver::Pinned(Arc::new(BTreeMap::from([(
        NAME.to_owned(),
        "127.0.0.1:9".parse::<SocketAddr>().expect("the address"),
    )])));

    let budget = Arc::new(Budget::with_limit(LIMIT));
    tokio::spawn(tg_proxy::quic_egress::serve(
        socket,
        policy,
        resolver,
        Arc::clone(&budget),
        std::future::pending(),
    ));

    // **One socket per flow:** the key is the sender **and** the destination
    // port, and the destination port is the same listener for all of them.
    let mut clients = Vec::new();
    for _ in 0..LIMIT {
        let client = UdpSocket::bind("127.0.0.1:0").expect("the sender");
        client
            .send_to(NAMED0, format!("127.0.0.1:{port}"))
            .expect("send");
        clients.push(client);
    }

    // They must have arrived before there is any waiting -- otherwise the
    // test measures a deadline over an empty stock and is always green.
    let deadline = Instant::now() + Duration::from_secs(10);
    while budget.open() < LIMIT && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        budget.open(),
        LIMIT,
        "the flows did not arrive -- then this witness measures nothing"
    );

    // And from here on the container is silent. No further datagram.
    let start = Instant::now();
    let deadline = start + IDLE * 2;
    while budget.open() > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let elapsed = start.elapsed();

    assert_eq!(
        budget.open(),
        0,
        "after {elapsed:?} without a datagram the listener still holds its \
         places -- the deadline runs only on traffic (ADR-0130)"
    );
    assert!(
        elapsed >= IDLE,
        "free already after {elapsed:?}: that would be shorter than the \
         deadline, and then something other than it clears here"
    );
    eprintln!("the places came back after {elapsed:?} (IDLE = {IDLE:?})");

    drop(clients);
}
