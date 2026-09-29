//! A fuzz run against the egress's QUIC frame (ADR-0092).
//!
//! The datagrams come from a **container**, and between them and a decision
//! lies hand-written code: the long header, varints, header protection, AEAD
//! and the assembly of the CRYPTO frames. The `ClientHello` inside goes to
//! `rustls` (ADR-0092, determination 3) -- the frame around it is ours, and
//! precisely it is fired at here.
//!
//! Conventions as in the other fuzz runs: a fresh seed per run, the iteration
//! count from `TG_FUZZ_ITERATIONS`, the default is the release threshold.
//!
//! **Valid datagrams are damaged**, not randomness -- the finding from phase
//! 9c: pure randomness never reaches the acceptance path, and every invariant
//! confirms itself. The basis are the recordings from `data/`.
//!
//! Four invariants:
//!
//! 1. **No crash**, whatever arrives.
//! 2. **A name comes out only if it went in too.** A frame that reads a name
//!    from the neighbouring field would give a permission for a target nobody
//!    named.
//! 3. **Nothing grows unbounded.** A container must not tie up memory with
//!    fragments -- that is the bound from determination 4.
//! 4. **The acceptance path is really entered.** Without this assurance a run
//!    that only refuses would confirm every claim.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use tg_proxy::quic::{Handshake, Peek};

const DEFAULT_ITERATIONS: u32 = 20_000;

/// The name that stands in the recordings. No other may come out.
const NAME: &str = "s3.example.com";

const NAMED: [&[u8]; 2] = [
    include_bytes!("data/named_0.bin"),
    include_bytes!("data/named_1.bin"),
];

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

/// Damages a datagram in one of five ways.
///
/// The fifth case leaves it **unchanged** -- otherwise the run would never
/// enter the acceptance path, and the assurance on it would not be
/// fulfillable.
fn damage(rng: &mut Rng, bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();

    match rng.below(5) {
        0 => {
            // Flip one byte -- somewhere.
            if !out.is_empty() {
                let at = rng.below(out.len());
                out[at] ^= rng.byte();
            }
        }
        1 => {
            // Cut off at the back.
            if !out.is_empty() {
                out.truncate(rng.below(out.len()));
            }
        }
        2 => {
            // Bend the head: lengths and varints sit there.
            let head = out.len().min(24);
            if head > 0 {
                let at = rng.below(head);
                out[at] ^= rng.byte();
            }
        }
        3 => {
            // Append -- a datagram possibly carries several packets.
            for _ in 0..rng.below(64) {
                out.push(rng.byte());
            }
        }
        _ => {}
    }

    out
}

#[test]
fn no_datagram_makes_the_reader_lie_or_grow() {
    let seed = fresh_seed();
    let rounds = iterations();
    let mut rng = Rng::new(seed);
    let mut accepted = 0_u32;

    for round in 0..rounds {
        let mut handshake = Handshake::new();
        let mut named = false;

        // A whole flight: both datagrams, each damaged on its own.
        for base in NAMED {
            let datagram = damage(&mut rng, base);
            if let Ok(Peek::Named(name)) = &handshake.absorb(&datagram) {
                assert_eq!(
                    name, NAME,
                    "round {round} (seed {seed}): a name that went in \
                     nowhere -- with that the egress permits a target nobody \
                     named"
                );
                named = true;
            }
        }

        if named {
            accepted += 1;
        }
    }

    // Without this assurance a run that only refuses would confirm every
    // invariant.
    //
    // The threshold is **measured, not computed** -- the finding from the peer
    // run, where it lay on the expected value and therefore every second run
    // fell. The calculation said 4 % (a fifth leaves it unchanged, both
    // datagrams must hit it); measured over four seeds it is **15.5 %** (3089
    // to 3148 of 20 000), for a damage often hits bytes outside what the
    // header and the AEAD cover. What is demanded is **one** per cent:
    // fifteenfold room.
    let floor = rounds / 100;
    assert!(
        accepted >= floor,
        "only {accepted} of {rounds} flights yielded a name (seed {seed}) -- \
         the acceptance path was hardly entered, and the run confirms itself"
    );
}

/// **Arbitrarily many damaged datagrams neither crash nor hang.**
///
/// That is this witness's whole assurance, and it is less than its name says:
/// what is checked is that `absorb` **returns** -- with a name, with a finding
/// or with "not yet enough". That the bound from ADR-0092 determination 4
/// really bites is checked by `quic_initial.rs`
/// (`repeats_run_into_a_ceiling_that_sits_far_above_a_real_client`), and that
/// the stock above it does not grow, by the neighbour here.
///
/// The doc block once said "what is checked is the effect: never a quiet state
/// that carries on growing" -- it did not, and the assurance stood nowhere.
/// Withdrawn instead of left standing.
#[test]
fn a_flood_of_datagrams_neither_panics_nor_hangs() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let mut handshake = Handshake::new();

    for round in 0..2_000 {
        let base = NAMED[usize::from(round % 2 == 1)];
        let datagram = damage(&mut rng, base);

        // The assurance is that it **returns** -- with a name, with a
        // finding or with "not yet enough". A crash or a hang would be the
        // find.
        let _ = handshake.absorb(&datagram);
    }
}

/// **The stock does not grow, whatever arrives** (ADR-0094,
/// determination 5).
///
/// A container must not tie up memory with arbitrary sender ports and
/// arbitrary bytes. What is checked is the effect: after many datagrams from
/// many flows the stock stays below its bound.
///
/// **And the second half carries the first:** a stock that takes nothing in at
/// all would be below the bound too -- and would take every workload's way
/// out. What is demanded is therefore that flows arise at all.
#[test]
fn a_flood_of_flows_stays_bounded() {
    use tg_proxy::quic_egress::{Flows, MAX_FLOWS};

    let seed = fresh_seed();
    let rounds = iterations();
    let mut rng = Rng::new(seed);
    let mut flows: Flows<()> = Flows::default();
    let now = std::time::Instant::now();
    let mut opened = 0_u32;

    for round in 0..rounds {
        let port = u16::try_from(rng.below(65_535)).expect("fits");
        let datagram = damage(&mut rng, NAMED[usize::from(round % 2 == 1)]);
        let flow = ("10.42.1.5:51000".parse().expect("the address"), port);

        let _ = flows.absorb(flow, &datagram, now, &|_, _| true);

        assert!(
            flows.len() <= MAX_FLOWS,
            "round {round} (seed {seed}): the stock grew past its bound \
             ({} > {MAX_FLOWS})",
            flows.len()
        );
        if !flows.is_empty() {
            opened += 1;
        }
    }

    assert!(
        opened > rounds / 100,
        "only {opened} of {rounds} rounds held a flow at all (seed {seed}) \
         -- a stock that takes nothing in is always below its bound"
    );
}
