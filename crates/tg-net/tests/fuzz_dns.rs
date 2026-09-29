//! Fuzz run against the resolver's wire trust boundary.
//!
//! The bytes come from **containers**, over UDP, unauthenticated. That is the
//! most open boundary this system has: `discovery.rs` at least still reads a
//! name, here somebody reads a raw buffer.
//!
//! Conventions as in the other fuzz runs: fresh seed per run, iteration count
//! from `TG_FUZZ_ITERATIONS`, default is the release threshold, every find is
//! nailed down as a deterministic test.
//!
//! Four invariants, and the third is the one for whose sake this run exists:
//!
//! 1. No crash, whatever arrives.
//! 2. If an answer is given, it carries the query's id and the QR bit —
//!    otherwise the client does not assign it.
//! 3. **No answer ever exceeds 512 bytes.** That is the bound against
//!    amplification: this server stands on an address every container knows, and
//!    a DNS server that gives arbitrarily large answers to small queries is an
//!    amplifier for reflection attacks. The truncation (TC bit) is therefore not
//!    only protocol fidelity but the upper bound. A ratio of 1:1 would by
//!    contrast be **falsely asserted** — every real answer is longer than its
//!    question; this run's first attempt demanded that and was green only
//!    because it never produced an answer.
//! 4. Addresses come out only for names that exist in the zone.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::Ipv4Addr;

use simple_dns::{CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, TYPE};
use tg_net::discovery::{Domain, Endpoint, Health, Registry};
use tg_net::resolver::{Resolver, UDP_LIMIT};

/// Iterations, if `TG_FUZZ_ITERATIONS` says nothing else.
const DEFAULT_ITERATIONS: u32 = 20_000;

/// Determines how many fuzz rounds to run.
///
/// # Returns
/// The value of `TG_FUZZ_ITERATIONS` if set and parseable, otherwise
/// [`DEFAULT_ITERATIONS`].
fn iterations() -> u32 {
    std::env::var("TG_FUZZ_ITERATIONS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS)
}

/// Draws a fresh, non-deterministic seed for one fuzz run.
///
/// # Returns
/// A random, odd `u64` seed.
fn fresh_seed() -> u64 {
    RandomState::new().build_hasher().finish() | 1
}

/// xorshift64* — reproduces a run completely from its seed.
struct Rng(u64);

impl Rng {
    /// Builds a generator seeded with `seed`.
    ///
    /// # Parameters
    /// - `seed`: the seed to initialize the generator with; forced odd.
    ///
    /// # Returns
    /// The seeded generator.
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    /// Advances the generator and returns its next pseudo-random value.
    ///
    /// # Returns
    /// The next 64-bit pseudo-random value.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Draws a pseudo-random value strictly below `bound`.
    ///
    /// # Parameters
    /// - `bound`: the exclusive upper bound.
    ///
    /// # Returns
    /// A value in `0..bound`.
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("fits")
    }

    /// Draws a single pseudo-random byte.
    ///
    /// # Returns
    /// A pseudo-random byte.
    fn byte(&mut self) -> u8 {
        u8::try_from(self.next() & 0xff).expect("fits")
    }
}

/// Builds the fixture resolver serving one healthy `api` instance.
///
/// # Returns
/// The constructed resolver.
fn resolver() -> Resolver {
    Resolver::new(Registry::new(
        Domain::new("tardigrade.internal").expect("valid"),
        vec![Endpoint {
            workload: "api".to_owned(),
            instance: 0,
            address: Ipv4Addr::new(10, 42, 1, 10),
            health: Health::Healthy,
        }],
    ))
}

/// Names that lie close to what the resolver knows.
const NAMES: &[&str] = &[
    "api.tardigrade.internal",
    "0.api.tardigrade.internal",
    "9.api.tardigrade.internal",
    "cache.tardigrade.internal",
    "tardigrade.internal",
    "api.evil.example.com",
    "a.b.c.d.e.f.tardigrade.internal",
];

/// Generates one fuzz input buffer: either pure random bytes, or a valid DNS
/// query that is then optionally damaged (bytes flipped, truncated, or
/// appended to).
///
/// **Pure randomness never reaches the answer path** — a DNS packet demands
/// validly encoded labels, and one does not hit those. This run's first attempt
/// therefore consisted of 200 000 unreadable buffers and proved nothing; the
/// assurance at the end of the test holds that fast. Produced are therefore
/// **valid queries that are then damaged** — that is where the errors sit.
///
/// # Parameters
/// - `rng`: the random source to draw the buffer's content from.
///
/// # Returns
/// The generated buffer.
fn message(rng: &mut Rng) -> Vec<u8> {
    let choice = rng.below(10);

    if choice < 2 {
        // Pure randomness — for completeness.
        let len = rng.below(600);
        return (0..len).map(|_| rng.byte()).collect();
    }

    let mut packet = Packet::new_query(u16::try_from(rng.below(0x1_0000)).expect("fits"));
    let name = NAMES[rng.below(NAMES.len())];
    let qtype = match rng.below(4) {
        0 => QTYPE::TYPE(TYPE::AAAA),
        1 => QTYPE::TYPE(TYPE::TXT),
        _ => QTYPE::TYPE(TYPE::A),
    };
    packet.questions.push(Question::new(
        Name::new(name).expect("fixture name must be valid"),
        qtype,
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let mut bytes = packet.build_bytes_vec().expect("serializable");

    if choice < 5 {
        // Undamaged — that is the share that surely hits the answer path.
        return bytes;
    }

    // Damage: flip bytes, truncate, append.
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

    bytes
}

/// Fuzzes the resolver's UDP wire boundary: no input crashes it, every answer
/// stays within the UDP size limit, and it never forwards outside its
/// configured allowlist.
#[test]
fn no_datagram_from_a_container_breaks_the_resolver_or_makes_it_an_amplifier() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let resolver = resolver();

    let rounds = iterations();
    let mut answered = 0_u32;

    for round in 0..rounds {
        let incoming = message(&mut rng);
        // `Forward` does not occur here: the harness sets no forwarding list,
        // and without it everything outside the zone stays `REFUSED`. That
        // this is so is held fast by `forwarding.rs` — here it would be a
        // second assertion.
        let answer = match resolver.respond(&incoming, UDP_LIMIT) {
            tg_net::resolver::Verdict::Reply(bytes) => bytes,
            // Silence is the normal case with garbage — precisely what this run
            // checks.
            tg_net::resolver::Verdict::Silence => continue,
            // **Forwarding must never occur here:** the harness sets no
            // allowlist, and without it everything outside the zone stays
            // `REFUSED`. A `Forward` would mean that this resolver has become
            // an amplifier — sending garbage to an upstream an attacker need
            // only name.
            tg_net::resolver::Verdict::Forward => panic!(
                "seed {seed}, round {round}: forwarded without an allowlist — \
                 the resolver is an amplifier"
            ),
        };
        answered += 1;

        let context = || format!("seed {seed}, round {round}, {} bytes in", incoming.len());

        assert!(
            answer.len() <= UDP_LIMIT,
            "the answer bursts the UDP packet ({} bytes). {}",
            answer.len(),
            context()
        );
        assert!(
            incoming.len() >= 12,
            "there must be no answer to less than a DNS header. {}",
            context()
        );

        let parsed = Packet::parse(&answer)
            .unwrap_or_else(|err| panic!("own answer unreadable ({err}). {}", context()));
        assert!(
            parsed.has_flags(PacketFlag::RESPONSE),
            "QR missing. {}",
            context()
        );
        assert_eq!(
            parsed.id(),
            u16::from_be_bytes([incoming[0], incoming[1]]),
            "the id is wrong. {}",
            context()
        );

        for record in &parsed.answers {
            // **Compared lowercased.** The resolver mirrors the question's
            // letter case back, and that is as it should be: RFC 1035 demands
            // that the answer's name correspond to the question's, and DNS-0x20
            // builds a spoofing protection on exactly that. This oracle's first
            // attempt compared letter for letter and reported
            // `api.tardigrade.Internal` as a find — the error lay in the
            // oracle.
            let name = record.name.to_string().to_ascii_lowercase();
            assert!(
                name == "api.tardigrade.internal" || name == "0.api.tardigrade.internal",
                "address handed out for '{}'. {}",
                name.escape_debug(),
                context()
            );
        }
    }

    // Without this assurance the run would be empty: if only unreadable buffers
    // arrived, every invariant would confirm itself.
    assert!(
        answered * 20 >= rounds,
        "seed {seed}: only {answered} of {rounds} buffers were answered at \
         all — the run hardly checks the answer path"
    );
}
