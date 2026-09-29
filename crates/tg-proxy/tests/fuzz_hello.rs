//! A fuzz run against the egress trust boundary (ADR-0041 -- phase 10d).
//!
//! The bytes come from a **container**, and they are the first thing the
//! sidecar sees of an outgoing connection. Between them and a decision lies a
//! TLS parser.
//!
//! Conventions as in the other fuzz runs: a fresh seed per run, the iteration
//! count from `TG_FUZZ_ITERATIONS`, the default is the release threshold.
//!
//! Three invariants:
//!
//! 1. No crash, whatever arrives.
//! 2. **A name comes out only if it went in too.** A parser that invents a
//!    name or reads one from the neighbouring field would give a permission
//!    for a target nobody named.
//! 3. **`Forward` only for permitted targets.** That is the statement this run
//!    exists for.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use tg_proxy::egress::{Decision, EgressPolicy, Peek, Transport};

const DEFAULT_ITERATIONS: u32 = 20_000;

fn iterations() -> u32 {
    std::env::var("TG_FUZZ_ITERATIONS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS)
}

fn fresh_seed() -> u64 {
    RandomState::new().build_hasher().finish() | 1
}

/// xorshift64* -- reproduces a run from its seed completely.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("fits")
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next() & 0xff).expect("fits")
    }
}

const NAMES: &[&str] = &[
    "s3.example.com",
    "api.partner.example",
    "evil-s3.example.com",
    "foreign.example.com",
];

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

/// A buffer: usually a real `ClientHello`, then damaged.
///
/// Pure randomness never reaches the parser -- the first byte would have to be
/// `0x16` and the length fields would have to fit. The same lesson as with the
/// DNS run in 9c: something valid is produced, and then it is tampered
/// with.
fn message(rng: &mut Rng) -> (Vec<u8>, Option<&'static str>) {
    let choice = rng.below(10);

    if choice < 2 {
        let len = rng.below(400);
        return ((0..len).map(|_| rng.byte()).collect(), None);
    }

    let name = NAMES[rng.below(NAMES.len())];
    let mut bytes = client_hello(name);

    if choice < 5 {
        return (bytes, Some(name));
    }

    for _ in 0..=rng.below(4) {
        match rng.below(3) {
            0 if !bytes.is_empty() => {
                let at = rng.below(bytes.len());
                bytes[at] ^= rng.byte();
            }
            1 if bytes.len() > 1 => bytes.truncate(rng.below(bytes.len())),
            _ => bytes.push(rng.byte()),
        }
    }

    (bytes, None)
}

#[test]
fn no_bytes_from_a_container_produce_a_name_that_was_not_there() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let policy = EgressPolicy::from_entries([
        ("s3.example.com".to_owned(), 443, Transport::Tcp),
        ("api.partner.example".to_owned(), 8443, Transport::Tcp),
    ]);

    let rounds = iterations();
    let mut named = 0_u32;

    for round in 0..rounds {
        let (bytes, expected) = message(&mut rng);
        // **The port is fuzzed along** (ADR-0051): in operation it comes
        // from the kernel and is thereby no self-declaration -- but the
        // decision function must take it just as strictly as the name. It is
        // rolled from permitted and non-permitted ones, otherwise the oracle
        // checks only the one case.
        let port = [443_u16, 8443, 22, 0, 15002][rng.below(5)];
        let context = || {
            format!(
                "seed {seed}, round {round}, {} bytes, port {port}",
                bytes.len()
            )
        };

        if let Peek::Named(name) = tg_proxy::egress::peek(&bytes) {
            named += 1;

            // The name must stand in the bytes -- **compared lower-cased**.
            // `rustls` returns the SNI lower-cased, because DNS names are
            // independent of the spelling; a buffer with `frJmd.example.com`
            // yields `frjmd.example.com`. This oracle's first attempt compared
            // letter for letter and reported that as a find; nailed down in
            // `egress.rs` as `the_server_name_comes_back_lowercased`.
            //
            // A parser that invents a name or reads one from the neighbouring
            // field would give a permission for a target nobody named -- the
            // comparison carries on catching that.
            let lowered: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
            assert!(
                lowered
                    .windows(name.len())
                    .any(|window| window == name.as_bytes()),
                "'{name}' does not stand in the bytes. {}",
                context()
            );

            if let Some(expected) = expected {
                assert_eq!(name, expected, "{}", context());
            }
        }

        match tg_proxy::egress::decide(&policy, &bytes, port) {
            Decision::Forward { host, port } => {
                assert!(
                    policy.permits(&host, port, Transport::Tcp),
                    "Forward for a target that is not permitted: '{host}':{port}. {}",
                    context()
                );
            }
            Decision::Deny { .. } | Decision::NeedMore => {}
        }
    }

    // Without this assurance the run would be empty: if only unreadable
    // buffers arrived, every invariant would confirm itself.
    assert!(
        named * 10 >= rounds,
        "seed {seed}: only {named} of {rounds} buffers carried a name -- the \
         run hardly checks the read path"
    );
}
