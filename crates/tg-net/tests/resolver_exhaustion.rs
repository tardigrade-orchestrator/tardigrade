//! The resolver survives exhausted descriptors — and does not spin in the
//! process.
//!
//! # The finding
//!
//! `serve_tcp` stood on `listener.accept().await?`, and the agent discarded the
//! error (`let _ = ...`). A single `EMFILE` thereby ended the node's name
//! resolution for the **lifetime of the agent**: every container on that node
//! loses it (the resolver runs per node precisely so that one node's failure
//! does not take down another's), and not a word stood in the log — for the
//! workload it looked like a network problem.
//!
//! `EMFILE` is not far-fetched on this process: the agent holds one descriptor
//! per connected workload (the SVID stream stays open for the workload API),
//! one per open DNS forwarding, plus netlink, `nft` and the session.
//!
//! # Why this test lies alone in its file
//!
//! It lowers `RLIMIT_NOFILE`, and the limit applies to the **process**. `cargo
//! test` runs a file's tests concurrently; a second test beside it would get the
//! lowered limit without knowing it.
//!
//! # Two assurances, two counter-checks
//!
//! The test carries both halves of the decision, and each has its own
//! counter-check:
//!
//! * **It does not end** — with the old `?` the question at the end is never
//!   answered.
//! * **It does not spin** — without the pause from `tg_syscall::accept` the loop
//!   burns a core, because `accept` does not consume the waiting connection on
//!   `EMFILE` and repeats the error immediately.

use std::io::{Read as _, Seek as _};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question};
use tg_net::discovery::{Domain, Endpoint, Health, Registry};
use tg_net::resolver::{Resolver, serve_tcp};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const ZONE: &str = "tardigrade.internal";

/// How many descriptors the process may have at most.
///
/// High enough for the runtime that is already running, and low enough that the
/// exhaustion takes fractions of a second.
const LIMIT: u64 = 128;

/// How long is measured under `EMFILE`.
const WINDOW: Duration = Duration::from_secs(1);

/// The process's compute time in ticks (`utime + stime` from `/proc`).
///
/// The descriptor is opened **beforehand** and rewound afterwards: during the
/// exhaustion `/proc/self/stat` could no longer be opened, and the test would
/// fail at its own measurement.
///
/// # Parameters
/// - `stat`: an already-open handle to `/proc/self/stat`.
///
/// # Returns
/// The sum of `utime` and `stime`, in clock ticks.
fn ticks(stat: &mut std::fs::File) -> u64 {
    stat.rewind().expect("rewind");
    let mut text = String::new();
    stat.read_to_string(&mut text).expect("stat readable");
    // The command name stands in parentheses and may contain spaces.
    let tail = text.rsplit_once(')').expect("stat shape").1;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    // After the parenthesis field 3 begins (`state`); `utime` is field 14,
    // `stime` field 15.
    let utime: u64 = fields[11].parse().expect("utime");
    let stime: u64 = fields[12].parse().expect("stime");
    utime + stime
}

/// Builds a query as a client sends it.
///
/// # Parameters
/// - `name`: the queried name.
///
/// # Returns
/// The serialized query bytes.
fn query(name: &str) -> Vec<u8> {
    let mut packet = Packet::new_query(0x4711);
    packet.questions.push(Question::new(
        Name::new(name).expect("valid name"),
        QTYPE::TYPE(simple_dns::TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    packet.build_bytes_vec().expect("serializable")
}

/// **`multi_thread` deliberately.** On a single-thread runtime a spinning accept
/// loop starved the test itself: it hung instead of failing — and a test that
/// hangs is worse than one that fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exhausted_listener_neither_dies_nor_spins() {
    let mut stat = std::fs::File::open("/proc/self/stat").expect("open stat");

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");

    let registry = Registry::new(
        Domain::new(ZONE).expect("valid zone"),
        vec![Endpoint {
            workload: "api".to_owned(),
            instance: 0,
            address: Ipv4Addr::new(10, 42, 1, 10),
            health: Health::Healthy,
        }],
    );
    let resolver = Arc::new(Resolver::new(registry));
    tokio::spawn(async move { match serve_tcp(resolver, Arc::new(listener), None).await {} });

    // **The client socket arises before the exhaustion.** Afterwards there
    // would be no descriptor left for it — and without a waiting connection
    // `accept` would see no error at all but would wait for readiness.
    let client = rustix::net::socket(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        None,
    )
    .expect("socket");

    let previous = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(LIMIT),
            maximum: previous.maximum,
        },
    )
    .expect("limit lowerable");

    let mut hold = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => hold.push(file),
            Err(error) => {
                assert_eq!(
                    error.raw_os_error(),
                    Some(libc_emfile()),
                    "what shall be exhausted are the descriptors, nothing else"
                );
                break;
            }
        }
    }
    assert!(
        !hold.is_empty(),
        "without held descriptors there would be nothing to release"
    );

    // The connection lands in the kernel's accept queue — the server need not
    // accept for that. From here on `accept` gives `EMFILE`.
    rustix::net::connect(&client, &address).expect("connect");

    let before = ticks(&mut stat);
    tokio::time::sleep(WINDOW).await;
    let spent = ticks(&mut stat) - before;

    // A fully loaded core is around 100 ticks per second; idle it is zero or
    // one. Two orders of magnitude of distance — the bound is not chosen
    // narrowly.
    assert!(
        spent < 20,
        "the listener burned {spent} ticks instead of waiting"
    );

    drop(hold);
    rustix::process::setrlimit(rustix::process::Resource::Nofile, previous).expect("limit back");

    // And now the other half: the service is still alive.
    let mut stream = tokio::net::TcpStream::from_std({
        let stream = std::net::TcpStream::from(client);
        stream.set_nonblocking(true).expect("nonblocking");
        stream
    })
    .expect("take over");

    let question = query(&format!("api.{ZONE}"));
    let mut framed = u16::try_from(question.len()).expect("length").to_be_bytes()[..].to_vec();
    framed.extend_from_slice(&question);
    stream.write_all(&framed).await.expect("send question");

    let mut prefix = [0_u8; 2];
    let answer = tokio::time::timeout(Duration::from_secs(5), async {
        stream.read_exact(&mut prefix).await?;
        let mut body = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut body).await?;
        Ok::<_, std::io::Error>(body)
    })
    .await
    .expect("the resolver did not survive the exhaustion")
    .expect("answer readable");

    let parsed = Packet::parse(&answer).expect("answer parses");
    assert_eq!(parsed.answers.len(), 1, "one healthy instance");
}

/// `EMFILE` without `libc` — the value is 24 on Linux.
///
/// Expressly a number and not `rustix::io::Errno`: the assertion shall not go
/// the same way as the logic under test.
///
/// # Returns
/// The raw `EMFILE` errno value on Linux.
const fn libc_emfile() -> i32 {
    24
}
