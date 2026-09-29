//! The benchmark from ADR-0022 -- what the tail really costs.
//!
//! ADR-0022 chose thread-per-core and left **one** open point behind: "a
//! benchmark that validates the tokio-tpc variant against the tail target (and
//! triggers or rejects the `io_uring` upgrade path)." Four further records now
//! hang on it -- the pinning (ADR-0022 itself), the data plane's overflow check
//! (ADR-0082), the sidecar's CFS quota (ADR-0086) and the splice latency
//! (ADR-0041). All four say the same: without a measurement the setting would
//! be one that is made because it stands in a document.
//!
//! # What is **not** measured here: an absolute target
//!
//! "The tail target" does not exist as a number. `plans/README.md` names
//! **availability** (4-9 to 5-9), not microseconds, and ADR-0022 derives no
//! latency bound from it. A test that claimed a bound here would invent it --
//! and it would pass or fall afterwards with the machine on which it runs.
//!
//! What is measured is therefore the **difference**, and with the discipline
//! from 8b: between two runs exactly one thing is different. That is also the
//! question ADR-0022 actually asks -- "does the tail need `io_uring`?" is a
//! question about a distance, not about an absolute value.
//!
//! # The setup
//!
//! The same path as in `sidecar.rs`, only under load:
//!
//! ```text
//!   load ──plaintext──▶ api sidecar ──mTLS──▶ ledger sidecar ──plaintext──▶ echo
//! ```
//!
//! What is measured is the **settled** round trip on a standing connection:
//! connect, warm up, then write per round and wait for the echo. The handshake
//! stays out -- it measures `rustls` and `ring`, not the runtime, and it takes
//! place once per connection, while the assurance from ADR-0007 applies to the
//! traffic **on** the connection.
//!
//! The load is **closed** (a fixed concurrency, sequential per connection). An
//! open load with a fixed rate would form unbounded queues under overload and
//! would compute the tail arbitrarily large; the closed one says what a caller
//! sees who waits for its answer -- the case the sidecar is built for.
//!
//! # No benchmark framework
//!
//! No `criterion` (ADR-0023: every crate is a decision). It measures the mean
//! and the slope of a microbenchmark; here it is about the p99/p99.9 of a
//! network path. A sorted vector of nanoseconds achieves precisely that and
//! nothing else.
//!
//! # Two paths, two measurements
//!
//! The mesh path terminates TLS **twice**; the egress path does **not**
//! terminate (ADR-0041, determination 1) -- it reads the SNI, dials the name
//! itself and splices raw bytes. Those are two different costs, and ADR-0041
//! names the second as an open point of its own.
//!
//! It is measured as the **difference from the direct connection**: the same
//! client, the same endpoint, once with and once without the sidecar in
//! between. What remains is the splice -- one hop more and two copies per
//! direction.
//!
//! The **setup** is reported separately in the process and not averaged into
//! the round trip. It arises per connection, not per round, and it is the part
//! in which the sidecar does anything at all: read the SNI, resolve the name,
//! dial the endpoint. The settled round trip afterwards is pure copying. With
//! sixteen connections per run the p99 and the p99.9 of the setup lie on **the
//! same** value -- the largest; the columns stand there nevertheless so that
//! the table has the same shape as the one above.
//!
//! # What the run may claim
//!
//! What is asserted is that **measuring happened**: every round of every
//! connection came back, and the sample has the expected size. A run that
//! loses half the round trips and nevertheless prints a fine p99 is the case
//! 11c learned expensively (the report that announced "0 scenarios" and looked
//! perfectly proper doing so). The **verdict** over the numbers is passed by a
//! human in the ADR -- a measurement decides nothing, it shows.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tg_identity::{Authority, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};
use tg_proxy::identity::Identity;
use tg_proxy::policy::{PolicyCache, RevocationWindow, Snapshot};
use tg_proxy::sidecar::{Config, Route};
use tg_proxy::verify::{Bundle, SharedBundle, SharedPolicy};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const YEAR: i64 = 365 * 24 * 60 * 60;

/// How many connections run at the same time.
///
/// Four per shard: enough that the kernel hash over the four-tuple hits every
/// shard, and few enough that the load does not saturate the machine -- what
/// is to be measured is the way, not the queue in front of it.
const PER_SHARD: usize = 4;

/// Round trips per connection that go into the statistics.
const ROUNDS: usize = 2000;

/// How often every variant is measured.
///
/// **Once per variant would be no measurement.** A run takes a good second,
/// and in that second the machine also carries the load and the echo service;
/// between two runs of the same variant lie measurably two-digit percentages.
/// Whoever draws a comparison from that compares chance. The runs therefore go
/// **round-robin** (first every variant once, then from the beginning again),
/// so that drift -- the clock, the cache, another process -- hits them all
/// equally and not the one that happens to stand last.
const REPEATS: usize = 5;

/// Round trips per connection that do **not** go in.
///
/// The first round trip carries the handshake, the next ones the ramp-up of
/// the TCP windows on both legs. Counting them along would mean computing the
/// setup into the tail -- and the setup is the question from another ADR.
const WARMUP: usize = 50;

/// A round trip's payload.
///
/// 512 bytes: large enough for a call with a header and a small load, small
/// enough to stay in one TLS record and one segment. Whoever wants to measure
/// the bandwidth measures something else.
const PAYLOAD: usize = 512;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs(),
    )
    .expect("fits")
}

fn window() -> RevocationWindow {
    RevocationWindow {
        target: Duration::from_mins(1),
        staleness: Duration::from_mins(15),
    }
}

/// A CA and the SVIDs it issues.
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
    let mut cache = PolicyCache::new(window());
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

/// The "workload" behind the inbound sidecar.
///
/// It lies deliberately on a runtime of its **own**: were it on the sidecar's,
/// the run would measure the sum of both, and the variant would change two
/// things instead of one.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
    let addr = listener.local_addr().expect("the address");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    addr
}

/// Which runtime model the sidecar runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Model {
    /// A multi-thread runtime with work stealing and **one** listener --
    /// tokio's default and what ADR-0022 decided against.
    WorkStealing,
    /// One `current_thread` runtime per shard, each with its own
    /// `SO_REUSEPORT` listener -- the decision from ADR-0022, with and without
    /// pinning.
    ThreadPerCore { pinned: bool },
}

impl Model {
    fn label(self) -> &'static str {
        match self {
            Self::WorkStealing => "work-stealing",
            Self::ThreadPerCore { pinned: false } => "thread-per-core",
            Self::ThreadPerCore { pinned: true } => "thread-per-core, pinned",
        }
    }
}

/// A run's sample.
struct Report {
    /// Ascending sorted round-trip times in nanoseconds.
    nanos: Vec<u64>,
    errors: usize,
}

impl Report {
    /// The quantile, without interpolation.
    ///
    /// With a tail the **observed** value is what matters: the p99.9 is to be
    /// the round trip a thousand others undercut, not a mean between two that
    /// never took place that way.
    fn quantile(&self, numerator: usize, denominator: usize) -> Duration {
        if self.nanos.is_empty() {
            return Duration::ZERO;
        }
        let rank = self.nanos.len().saturating_mul(numerator) / denominator;
        let index = rank.min(self.nanos.len() - 1);

        Duration::from_nanos(self.nanos[index])
    }
}

/// Both sidecars of the path, as **one** shard runs them.
///
/// They stand together in one type, because the two models are to differ
/// exactly in **how often** this pair arises -- once on a runtime with work
/// stealing, or once per shard on a `current_thread` runtime. Two separate
/// setups would be two opportunities to change something else
/// inadvertently.
#[derive(Clone)]
struct Pair {
    server: Config,
    client: Config,
    route: Route,
    inbound: SocketAddr,
    outbound: SocketAddr,
    upstream_port: u16,
    halt: tokio::sync::watch::Receiver<bool>,
}

impl Pair {
    /// Binds its own sockets and carries until the run ends.
    ///
    /// Every call binds **anew**: with thread-per-core precisely that is the
    /// sharding (`SO_REUSEPORT`, ADR-0022), with work stealing it happens
    /// once.
    async fn serve(mut self) {
        let inbound = TcpListener::from_std(listener_on(self.inbound)).expect("the tokio socket");
        let outbound = TcpListener::from_std(listener_on(self.outbound)).expect("the tokio socket");
        let mut client_halt = self.halt.clone();
        let upstream_port = self.upstream_port;

        let server = tokio::spawn(async move {
            let _ = tg_proxy::serve_inbound(
                self.server,
                inbound,
                upstream_port,
                wait_for(&mut self.halt),
            )
            .await;
        });
        let client = tokio::spawn(async move {
            let _ = tg_proxy::serve_outbound(
                self.client,
                self.route,
                outbound,
                wait_for(&mut client_halt),
            )
            .await;
        });

        let _ = server.await;
        let _ = client.await;
    }
}

/// Runs the pair under the variant's runtime model.
fn spawn_sidecars(model: Model, shards: usize, pair: Pair) -> std::thread::JoinHandle<()> {
    match model {
        Model::WorkStealing => std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(shards)
                .enable_all()
                .build()
                .expect("the runtime");
            runtime.block_on(pair.serve());
        }),
        Model::ThreadPerCore { pinned } => std::thread::spawn(move || {
            // **The same function as in operation** (ADR-0114, determination
            // 3): a rebuilt pinning in the test path would measure something
            // other than what a sidecar does with `--pin-shards`.
            let _ = tg_proxy::Shards::exactly(shards)
                .pinned(pinned)
                .run(move |_shard| pair.clone().serve());
        }),
    }
}

/// Builds the path, runs the load, gives the sample back.
fn measure(model: Model, shards: usize) -> Report {
    let pki = Pki::new();
    let server_identity = pki.identity("ledger");
    let client_identity = pki.identity("api");
    let bundle = SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()]));
    let server_policy = policy(&[("api", "ledger")]);
    let client_policy = policy(&[("api", "ledger")]);

    // The runtime of the load **and** of the echo service. It is the same in
    // every variant; only the two sidecars' runtime changes.
    let harness = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("the runtime");
    let upstream = harness.block_on(echo_server());

    // The addresses arise **before** the sidecars, because both models need
    // them: one binds once, the other per shard onto the same one.
    let inbound_seed = tg_proxy::reuseport_listener("127.0.0.1:0".parse().expect("the address"))
        .expect("the socket");
    let inbound_addr = inbound_seed.local_addr().expect("the address");
    let outbound_seed = tg_proxy::reuseport_listener("127.0.0.1:0".parse().expect("the address"))
        .expect("the socket");
    let outbound_addr = outbound_seed.local_addr().expect("the address");
    drop(inbound_seed);
    drop(outbound_seed);

    let route = Route {
        listen: outbound_addr,
        connect: inbound_addr,
        peer: SpiffeId::for_workload(&domain(), "ledger").expect("the ID"),
    };
    let server_config = Config {
        identity: server_identity,
        bundle: bundle.clone(),
        policy: server_policy,
        window: window(),
        role: None,
    };
    let client_config = Config {
        identity: client_identity,
        bundle,
        policy: client_policy,
        window: window(),
        role: None,
    };

    let (stop, halt) = tokio::sync::watch::channel(false);
    let pair = Pair {
        server: server_config,
        client: client_config,
        route,
        inbound: inbound_addr,
        outbound: outbound_addr,
        upstream_port: upstream.port(),
        halt,
    };
    let sidecars = spawn_sidecars(model, shards, pair);

    // Until all the shards listen. A connection attempt that is too early
    // would fall onto the one shard that is already there and would shift the
    // distribution.
    std::thread::sleep(Duration::from_millis(250));

    let connections = shards * PER_SHARD;
    let errors = Arc::new(AtomicUsize::new(0));
    let nanos = harness.block_on(load(outbound_addr, connections, &errors));

    let _ = stop.send(true);
    // The teardown must not disturb the next run: as long as a shard still
    // listens on the address, the next variant would get its connections.
    let _ = sidecars.join();

    let mut nanos = nanos;
    nanos.sort_unstable();

    Report {
        nanos,
        errors: errors.load(Ordering::SeqCst),
    }
}

/// A listener with `SO_REUSEPORT` on a known address.
fn listener_on(addr: SocketAddr) -> std::net::TcpListener {
    tg_proxy::reuseport_listener(addr).expect("the socket")
}

/// Waits until the run ends.
async fn wait_for(halt: &mut tokio::sync::watch::Receiver<bool>) {
    while !*halt.borrow_and_update() {
        if halt.changed().await.is_err() {
            return;
        }
    }
}

/// The closed load.
async fn load(addr: SocketAddr, connections: usize, errors: &Arc<AtomicUsize>) -> Vec<u64> {
    let mut tasks = Vec::with_capacity(connections);
    for _ in 0..connections {
        let errors = Arc::clone(errors);
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::with_capacity(ROUNDS);
            let Ok(mut stream) = TcpStream::connect(addr).await else {
                errors.fetch_add(1, Ordering::SeqCst);
                return samples;
            };
            let _ = stream.set_nodelay(true);

            let payload = vec![0x5a_u8; PAYLOAD];
            let mut echo = vec![0_u8; PAYLOAD];
            for round in 0..(WARMUP + ROUNDS) {
                let started = Instant::now();
                if stream.write_all(&payload).await.is_err() {
                    errors.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                let echoed =
                    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echo))
                        .await;
                if !matches!(echoed, Ok(Ok(_))) {
                    errors.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                if round >= WARMUP {
                    samples.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
                }
            }

            samples
        }));
    }

    let mut nanos = Vec::with_capacity(connections * ROUNDS);
    for task in tasks {
        match task.await {
            Ok(samples) => nanos.extend(samples),
            Err(_) => {
                errors.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    nanos
}

/// Whether the path runs over the sidecar or past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Egress {
    /// Client -> endpoint. The comparison line.
    Direct,
    /// Client -> egress port -> endpoint (ADR-0041).
    Spliced,
}

impl Egress {
    fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Spliced => "spliced",
        }
    }
}

/// A real `ClientHello` -- the same production as in `egress.rs`.
///
/// Without it the sidecar decides nothing at all: the SNI **is** its input
/// (ADR-0041, determination 2). For the direct path it is sent nevertheless,
/// so that both variants carry the same bytes over the connection.
fn client_hello(server_name: &str) -> Vec<u8> {
    let _ = rustls::crypto::ring::default_provider().install_default();
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

/// The endpoint "outside".
///
/// It speaks **no** TLS, and that is as it should be: the sidecar does not
/// terminate (ADR-0041, determination 1), it splices raw bytes. What is
/// measured here is the splice and not the endpoint's crypto.
async fn endpoint() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
    let addr = listener.local_addr().expect("the address");

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    addr
}

/// Measures one of the two egress paths.
fn measure_egress(route: Egress) -> (Report, Report) {
    let harness = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("the runtime");

    let (target, _guard) = harness.block_on(async move {
        let upstream = endpoint().await;
        if route == Egress::Direct {
            return (upstream, None);
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
        let addr = listener.local_addr().expect("the address");

        // The permission names the listening port: this setup has no
        // redirect, the client dials the egress port directly, so the original
        // destination address **is** that port (ADR-0051).
        let policy =
            tg_proxy::egress::SharedEgress::new(tg_proxy::egress::EgressPolicy::from_entries([(
                "s3.test".to_owned(),
                addr.port(),
                tg_proxy::egress::Transport::Tcp,
            )]));
        let mut pinned = std::collections::BTreeMap::new();
        pinned.insert("s3.test".to_owned(), upstream);
        let resolver = tg_proxy::egress::Resolver::Pinned(std::sync::Arc::new(pinned));

        let (stop, halt) = tokio::sync::watch::channel(false);
        let mut halt = halt;
        tokio::spawn(async move {
            tg_proxy::egress::serve(
                listener,
                policy,
                resolver,
                window(),
                None,
                wait_for(&mut halt),
            )
            .await;
        });

        (addr, Some(stop))
    });

    // Until the egress port listens.
    std::thread::sleep(Duration::from_millis(150));

    let errors = Arc::new(AtomicUsize::new(0));
    let hello = client_hello("s3.test");
    let (mut nanos, mut setups) =
        harness.block_on(spliced_load(target, PER_SHARD * 4, &hello, &errors));
    nanos.sort_unstable();
    setups.sort_unstable();

    let seen = errors.load(Ordering::SeqCst);
    (
        Report {
            nanos,
            errors: seen,
        },
        Report {
            nanos: setups,
            errors: seen,
        },
    )
}

/// The closed load for the egress.
///
/// **The `ClientHello` goes ahead once** and is not measured along: it is the
/// setup, and the endpoint sends it back (it is an echo). What is measured is
/// the same settled round trip as in the mesh part.
async fn spliced_load(
    addr: SocketAddr,
    connections: usize,
    hello: &[u8],
    errors: &Arc<AtomicUsize>,
) -> (Vec<u64>, Vec<u64>) {
    let mut tasks = Vec::with_capacity(connections);
    for _ in 0..connections {
        let errors = Arc::clone(errors);
        let hello = hello.to_vec();
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::with_capacity(ROUNDS);
            // **The setup is measured separately** (ADR-0041): it arises per
            // connection, not per round trip -- and at the egress it is the
            // part in which the sidecar decides anything at all (read the SNI,
            // resolve the name, dial).
            let opened = Instant::now();
            let Ok(mut stream) = TcpStream::connect(addr).await else {
                errors.fetch_add(1, Ordering::SeqCst);
                return (samples, None);
            };
            let _ = stream.set_nodelay(true);

            // The setup: the SNI out, the echo back.
            let mut back = vec![0_u8; hello.len()];
            if stream.write_all(&hello).await.is_err()
                || tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back))
                    .await
                    .is_err()
            {
                errors.fetch_add(1, Ordering::SeqCst);
                return (samples, None);
            }
            let setup = u64::try_from(opened.elapsed().as_nanos()).unwrap_or(u64::MAX);

            let payload = vec![0x5a_u8; PAYLOAD];
            let mut echo = vec![0_u8; PAYLOAD];
            for round in 0..(WARMUP + ROUNDS) {
                let started = Instant::now();
                if stream.write_all(&payload).await.is_err() {
                    errors.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                let echoed =
                    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echo))
                        .await;
                if !matches!(echoed, Ok(Ok(_))) {
                    errors.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                if round >= WARMUP {
                    samples.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
                }
            }

            (samples, Some(setup))
        }));
    }

    let mut nanos = Vec::with_capacity(connections * ROUNDS);
    let mut setups = Vec::with_capacity(connections);
    for task in tasks {
        match task.await {
            Ok((samples, setup)) => {
                nanos.extend(samples);
                setups.extend(setup);
            }
            Err(_) => {
                errors.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    (nanos, setups)
}

/// A variant's spread over its runs.
struct Aggregate {
    label: &'static str,
    /// One quantile per run, ascending sorted.
    p50: Vec<f64>,
    p99: Vec<f64>,
    p999: Vec<f64>,
}

impl Aggregate {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            p50: Vec::new(),
            p99: Vec::new(),
            p999: Vec::new(),
        }
    }

    fn push(&mut self, report: &Report) {
        self.p50.push(report.quantile(50, 100).as_secs_f64() * 1e6);
        self.p99.push(report.quantile(99, 100).as_secs_f64() * 1e6);
        self.p999
            .push(report.quantile(999, 1000).as_secs_f64() * 1e6);
    }

    fn finish(&mut self) {
        for series in [&mut self.p50, &mut self.p99, &mut self.p999] {
            series.sort_by(f64::total_cmp);
        }
    }

    fn median(series: &[f64]) -> f64 {
        series.get(series.len() / 2).copied().unwrap_or_default()
    }

    /// The median and the span -- **both**, because a median without a span
    /// is a claim.
    fn line(&self) -> String {
        format!(
            "{:<26} {:>6.1} [{:>6.1}–{:>6.1}]  {:>6.1} [{:>6.1}–{:>6.1}]  \
             {:>6.1} [{:>6.1}–{:>6.1}]",
            self.label,
            Self::median(&self.p50),
            self.p50.first().copied().unwrap_or_default(),
            self.p50.last().copied().unwrap_or_default(),
            Self::median(&self.p99),
            self.p99.first().copied().unwrap_or_default(),
            self.p99.last().copied().unwrap_or_default(),
            Self::median(&self.p999),
            self.p999.first().copied().unwrap_or_default(),
            self.p999.last().copied().unwrap_or_default(),
        )
    }
}

/// **The measurement from ADR-0022**, in three variants with one difference each.
#[test]
#[ignore = "measures a network path under load; runs in `cargo xtask bench`"]
fn the_data_plane_is_measured_against_its_alternatives() {
    // Four shards, not `all_cores`: the number must be the same between two
    // runs, and `available_parallelism` hangs on the cgroup this run is
    // currently in.
    let shards = tg_proxy::available_shards().min(4);
    let expected = shards * PER_SHARD * ROUNDS;
    let models = [
        Model::WorkStealing,
        Model::ThreadPerCore { pinned: false },
        Model::ThreadPerCore { pinned: true },
    ];

    let mut aggregates: Vec<Aggregate> = models
        .iter()
        .map(|model| Aggregate::new(model.label()))
        .collect();
    for pass in 0..REPEATS {
        for (index, model) in models.iter().copied().enumerate() {
            let report = measure(model, shards);
            assert_eq!(
                report.errors,
                0,
                "{} (run {pass}): {} errors -- the numbers above then measure \
                 something else",
                model.label(),
                report.errors
            );
            assert_eq!(
                report.nanos.len(),
                expected,
                "{} (run {pass}): {} instead of {expected} round trips -- a \
                 sample that loses half prints a fine p99 nevertheless",
                model.label(),
                report.nanos.len()
            );
            aggregates[index].push(&report);
        }
    }
    for aggregate in &mut aggregates {
        aggregate.finish();
    }

    println!("\nADR-0022 -- round trip on a standing mTLS connection, in µs");
    println!(
        "  {shards} shards, {} connections, {ROUNDS} round trips per \
         connection, {PAYLOAD} B payload, {REPEATS} runs per variant",
        shards * PER_SHARD
    );
    println!(
        "  machine: {} visible cores -- the load and the echo service share \
         them with the shards\n",
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    );
    // The median **and** the span over the runs: a number without its spread
    // does not say whether a difference is one.
    println!(
        "  {:<26} {:^21}  {:^21}  {:^21}",
        "median [min-max]", "p50", "p99", "p99.9"
    );
    for aggregate in &aggregates {
        println!("  {}", aggregate.line());
    }
    println!();
}

/// **What the splice costs** (ADR-0041, open point).
///
/// The egress path does **not** terminate (determination 1): the sidecar reads
/// the SNI, dials the name itself and copies raw bytes afterwards. What that
/// costs stood nowhere -- ADR-0041 refers to the measurement requirement from
/// ADR-0022, and that did not exist until ADR-0114.
///
/// What is measured is the **difference from the direct connection**: the same
/// client, the same endpoint, once with and once without the sidecar in
/// between. What remains is the splice -- one hop more and two copies per
/// direction. An absolute number would say even less here than in the mesh
/// part: it would contain the endpoint, the kernel and the test rig's loop.
///
/// The endpoint speaks **no** TLS, and that is no shortcut: the sidecar does
/// not terminate, so everything after the `ClientHello` is opaque to it.
/// Whoever spoke TLS here would measure the client's and the endpoint's crypto
/// -- both the same in both variants, and neither the object.
#[test]
#[ignore = "measures a network path under load; runs in `cargo xtask bench`"]
fn the_egress_splice_is_measured_against_a_direct_connection() {
    let routes = [Egress::Direct, Egress::Spliced];
    let expected = PER_SHARD * 4 * ROUNDS;

    let mut aggregates: Vec<Aggregate> = routes
        .iter()
        .map(|route| Aggregate::new(route.label()))
        .collect();
    let mut setups: Vec<Aggregate> = routes
        .iter()
        .map(|route| Aggregate::new(route.label()))
        .collect();

    for pass in 0..REPEATS {
        for (index, route) in routes.iter().copied().enumerate() {
            let (report, setup) = measure_egress(route);
            setups[index].push(&setup);
            assert_eq!(
                report.errors,
                0,
                "{} (run {pass}): {} errors -- the numbers above then measure something else",
                route.label(),
                report.errors
            );
            assert_eq!(
                report.nanos.len(),
                expected,
                "{} (run {pass}): {} instead of {expected} round trips",
                route.label(),
                report.nanos.len()
            );
            aggregates[index].push(&report);
        }
    }
    for aggregate in aggregates.iter_mut().chain(setups.iter_mut()) {
        aggregate.finish();
    }

    println!("\nADR-0041 -- round trip over the egress, in µs");
    println!(
        "  {} connections, {ROUNDS} round trips per connection, {PAYLOAD} B \
         payload, {REPEATS} runs per variant\n",
        PER_SHARD * 4
    );
    println!(
        "  {:<26} {:^21}  {:^21}  {:^21}",
        "median [min-max]", "p50", "p99", "p99.9"
    );
    for aggregate in &aggregates {
        println!("  {}", aggregate.line());
    }

    // **The setup, separately** -- it arises per connection and at the egress
    // is the part in which the sidecar decides anything at all.
    println!("\n  connection setup (until the SNI is through), in µs");
    for aggregate in &setups {
        println!("  {}", aggregate.line());
    }
    println!();
}
