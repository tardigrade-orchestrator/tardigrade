//! Fuzz run against the archive's verifier (ADR-0020 — phase 11a).
//!
//! An archive comes from **disk** — from a WORM store, from a tape, from an
//! operator's hand. Whoever checks it has no reason to assume it is intact;
//! that is the purpose of the check.
//!
//! Conventions as in the other fuzz runs: fresh seed per run, iteration count
//! from `TG_FUZZ_ITERATIONS`, default is the release threshold.
//!
//! The invariant at issue:
//!
//! > **If an altered segment gets through, it has a different head.**
//!
//! The first attempt demanded "must never get through" and was too strong: a
//! segment truncated at the **end** verifies itself successfully — the chain is
//! intact, it is merely shorter. The same holds for a segment from which
//! everything has been removed; it verifies to its anchor.
//!
//! That is no weakness of the chain but its limit, and it stands so in
//! `audit.rs`'s module header: the proof consists of **two** parts. The chain
//! catches altering, reordering and excising; the **head comparison** catches
//! truncation. A verifier that does only the one certifies the other.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use tg_telemetry::audit::{GENESIS, Record, Segment, seal};

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

/// xorshift64* — reproduces a run completely from its seed.
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
}

const KINDS: &[&str] = &[
    "upsert_workload",
    "grant_lease",
    "admit_node",
    "allow_egress",
    "delete_volume",
];

/// An honest segment.
fn honest(rng: &mut Rng) -> Segment {
    let count = 1 + rng.below(12);
    let mut records = Vec::with_capacity(count);
    let mut previous = GENESIS.to_owned();

    for step in 0..count {
        let index = 1 + step as u64;
        #[allow(clippy::cast_possible_wrap)]
        let record = seal(
            &previous,
            index,
            Some(1_756_000_000 + index as i64),
            KINDS[rng.below(KINDS.len())],
            &format!("{{\"n\":{}}}", rng.below(1000)),
        );
        previous.clone_from(&record.digest);
        records.push(record);
    }

    Segment { records }
}

/// Alters a segment in one of the ways that must stand out.
fn tamper(rng: &mut Rng, segment: &Segment) -> Segment {
    let mut records: Vec<Record> = segment.records.clone();
    if records.is_empty() {
        return Segment { records };
    }

    match rng.below(6) {
        0 => {
            let at = rng.below(records.len());
            records[at].payload = format!("{{\"forged\":{}}}", rng.below(1000));
        }
        1 => {
            let at = rng.below(records.len());
            let bump = 1 + i64::try_from(rng.below(10_000)).unwrap_or(1);
            records[at].at = Some(records[at].at.map_or(bump, |now| now + bump));
        }
        2 => {
            let at = rng.below(records.len());
            records.remove(at);
        }
        3 if records.len() > 1 => {
            let (left, right) = (rng.below(records.len()), rng.below(records.len()));
            records.swap(left, right);
        }
        4 => {
            let at = rng.below(records.len());
            "something-else".clone_into(&mut records[at].kind);
        }
        _ => {
            // Append what does not belong.
            let index = records.last().map_or(1, |last| last.index + 1);
            records.push(seal(GENESIS, index, Some(0), "slipped-in", "{}"));
        }
    }

    Segment { records }
}

#[test]
fn a_tampered_segment_never_verifies() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);

    let rounds = iterations();
    let mut caught = 0_u32;
    let mut identical = 0_u32;

    for round in 0..rounds {
        let good = honest(&mut rng);
        good.verify(GENESIS)
            .unwrap_or_else(|err| panic!("seed {seed}, round {round}: honest, but {err:?}"));

        let suspect = tamper(&mut rng, &good);

        match suspect.verify(GENESIS) {
            Err(_) => caught += 1,
            Ok(report) => {
                // What is character for character the same may get through (a
                // swap of two equal positions, say) — and what was truncated.
                // The latter, however, **only with a different head**: that is
                // the place at which the head comparison steps in.
                if suspect == good {
                    identical += 1;
                } else {
                    let honest_head = good.verify(GENESIS).expect("honest").head;
                    assert_ne!(
                        report.head, honest_head,
                        "seed {seed}, round {round}: an altered segment got \
                         through with the same head"
                    );
                    caught += 1;
                }
            }
        }
    }

    // Without this assurance the run would be empty: if `tamper` never altered
    // anything, the invariant would confirm itself.
    assert!(
        caught * 2 >= rounds,
        "seed {seed}: only {caught} of {rounds} alterations were caught \
         ({identical} were none) — the run hardly checks the verifier"
    );
}
