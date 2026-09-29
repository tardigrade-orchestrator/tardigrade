//! **The loader's rejection path, randomized** (ADR-0008).
//!
//! # Why this run is here
//!
//! This repo's test rules make a fuzz run mandatory at every trust boundary,
//! and the loader parses a document an operator wrote. `fuzz_canonical` beside
//! it checks exclusively the **acceptance** path — "the values that get
//! through" —, and the rejection path was **fixture**-covered: the invalid
//! fixtures in `loader.rs` with one known violation each, and
//! `tg-consensus/tests/hostile_input.rs` the same boundary one layer up (via
//! `apply`, with 29 cases: facet lengths, oversized values, deep nesting, and
//! the bounded rejection message).
//!
//! What was missing is the **randomizing**: fixed cases check what one thought
//! of.
//!
//! What was missing is the invariant the rule demands: **no crash, only
//! expected error signals** for arbitrarily damaged inputs.
//!
//! # Why from the fixtures and not from the generator
//!
//! The generator in `fuzz_canonical` lies in a different integration test and
//! thereby in a different crate; copying it would be two fixtures that diverge.
//! The **valid fixtures** are the better basis: they are the documents this
//! project declares valid, and damaging them covers the realistic cases — a
//! byte that flips, a document that breaks off, a character that is added.
//!
//! # What it found
//!
//! At the first build, and via a **counter-check** rather than via the run
//! itself: `<broken` appended to a valid document left it green, and
//! re-measured, **everything** after `</workloads>` was silently discarded —
//! including a second complete document. The finding and its fix stand at
//! `nothing_may_follow_the_root_element` in `loader.rs`.
//!
//! **And it would not find it even now** — measured: with the trailing check
//! switched off it runs green through 20 000 iterations. That is structural and
//! no weakness of the number: a silently discarded remainder is
//! indistinguishable from a valid document as long as the run does not **know**
//! that it appended something. Exactly that is what the regression test knows,
//! and that is why the witness lies there.
//!
//! What this run achieves is the other half: **no crash** on arbitrary damage.
//! It found the finding via a counter-check, not via an invariant — and that
//! stands here instead of passing it off as a catcher.
//!
//! # What is expressly **not** checked here
//!
//! The **length** of the error message. Measured, the loader quotes the
//! objected value unabridged — 50 137 bytes for an input 50 145 bytes long —,
//! and that is known and handled: `tg_consensus::state` truncates to 512
//! characters before a rejection goes into the log (ADR-0020). Whoever
//! otherwise sees the message sent the document themselves.
//!
//! # Conventions
//!
//! A fresh seed per run (a fixed one would turn the fuzzing into a static test
//! set), `TG_FUZZ_ITERATIONS` with the release threshold as the default, and
//! seed plus round in every message. A failure is a **finding** and belongs
//! nailed down as a seeded regression test.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

/// Iterations, if `TG_FUZZ_ITERATIONS` says nothing else.
const DEFAULT_ITERATIONS: u32 = 20_000;

fn iterations() -> u32 {
    std::env::var("TG_FUZZ_ITERATIONS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS)
}

/// A seed that differs per run.
fn fresh_seed() -> u64 {
    RandomState::new().build_hasher().finish()
}

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
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next() % bound as u64).expect("fits")
    }

    fn pick<'a, T>(&mut self, from: &'a [T]) -> &'a T {
        &from[self.below(from.len())]
    }
}

/// The valid fixtures, as bytes.
///
/// Enumerated by name: `include_str!` needs a literal path, and a file nobody
/// names would not be checked along — the guard
/// `every_fixture_is_named_by_a_test` in `loader.rs` holds that fast.
const BASES: &[&str] = &[
    include_str!("fixtures/valid/minimal.xml"),
    include_str!("fixtures/valid/full.xml"),
    include_str!("fixtures/valid/command.xml"),
    include_str!("fixtures/valid/mesh.xml"),
    include_str!("fixtures/valid/mesh-udp.xml"),
    include_str!("fixtures/valid/readiness.xml"),
    include_str!("fixtures/valid/volumes.xml"),
    include_str!("fixtures/valid/placement.xml"),
    include_str!("fixtures/valid/workload-class.xml"),
    include_str!("fixtures/valid/devices.xml"),
];

/// **`BASES` does not lag behind the fixtures.**
///
/// The guard in `loader.rs` demands that **one** test names every fixture — not
/// that this one knows it. A new valid fixture would thus be added, be named
/// there and not be damaged here, without anything going red.
///
/// The reverse direction is no assurance: `BASES` must name nothing that does
/// not exist — `include_str!` sees to that at compile time.
#[test]
fn every_valid_fixture_is_a_basis() {
    let dir = std::path::Path::new("tests/fixtures/valid");
    let files: Vec<String> = std::fs::read_dir(dir)
        .expect("fixtures")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            // Via the extension as an `OsStr`, not as a string: clippy rightly
            // objects to an `ends_with(".xml")` as case-dependent, and here the
            // extension is a fact of the path and not a text search.
            if path.extension()? != "xml" {
                return None;
            }
            Some(path.file_name()?.to_string_lossy().into_owned())
        })
        .collect();

    assert!(files.len() > 4, "fixtures must have been found: {files:?}");
    assert_eq!(
        BASES.len(),
        files.len(),
        "`BASES` names {} documents, {} holds {} — a fixture that is missing \
         here is not damaged: {files:?}",
        BASES.len(),
        dir.display(),
        files.len()
    );
}

/// Damages a document in one of six ways.
///
/// The selection is not arbitrary: every kind hits a different layer — the byte
/// hits the parser, the truncation the well-formedness, the inserted bracket
/// the structure, the long value the facets, the swap the `xs:sequence`, and
/// the doubled root the cardinality.
fn damage(rng: &mut Rng, base: &str) -> Vec<u8> {
    let mut bytes = base.as_bytes().to_vec();
    if bytes.is_empty() {
        return bytes;
    }

    match rng.below(6) {
        // A byte flips.
        0 => {
            let at = rng.below(bytes.len());
            bytes[at] ^= 1 << rng.below(8);
        }
        // The document breaks off.
        1 => {
            let keep = rng.below(bytes.len());
            bytes.truncate(keep);
        }
        // A character is added.
        2 => {
            let at = rng.below(bytes.len() + 1);
            bytes.insert(at, *rng.pick(b"<>&\"'/= \0\t\n"));
        }
        // A value gets long — that is the facet case.
        3 => {
            if let Some(at) = base.find("name=\"") {
                let filler = "a".repeat(1 + rng.below(4_000));
                bytes.splice(at + 6..at + 6, filler.into_bytes());
            }
        }
        // Two bytes swap places.
        4 => {
            if bytes.len() > 1 {
                let a = rng.below(bytes.len());
                let b = rng.below(bytes.len());
                bytes.swap(a, b);
            }
        }
        // A piece is doubled — the doubled root belongs to this.
        _ => {
            let from = rng.below(bytes.len());
            let len = 1 + rng.below(bytes.len() - from);
            let piece = bytes[from..from + len].to_vec();
            bytes.splice(from..from, piece);
        }
    }

    bytes
}

/// **No damaged document ever crashes the loader** — it is accepted or refused
/// with a `LoadError`, and nothing in between.
///
/// The third possibility at issue is a **panic**: it would take the `tgd`
/// process's state machine (ADR-0004) and would thereby be a crash a sender
/// triggers.
#[test]
fn no_damaged_document_ever_panics() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);

    let mut rejected = 0_u32;
    let mut accepted = 0_u32;

    for round in 0..iterations() {
        let base = *rng.pick(BASES);
        let bytes = damage(&mut rng, base);

        // Not every damage yields valid UTF-8, and that is an input case of its
        // own: `from_str` demands a `&str`, so the boundary comes before — here
        // it is reproduced as a caller would cross it.
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };

        match tg_defs::from_str(&text) {
            Ok(set) => {
                accepted += 1;
                // **Accepted means usable.** A document that gets through must
                // also be usable — the state machine calls `workload_to_xml`
                // afterwards (ADR-0008), and a panic there would be the same gap
                // one place later.
                for workload in set.workloads() {
                    let xml = tg_defs::workload_to_xml(workload).unwrap_or_else(|err| {
                        panic!("seed {seed}, round {round}: not serializable: {err}\n{text}")
                    });
                    tg_defs::from_str(&xml).unwrap_or_else(|err| {
                        panic!("seed {seed}, round {round}: own output not readable: {err}\n{xml}")
                    });
                }
            }
            Err(err) => {
                rejected += 1;
                // **The message must say something.** An empty rejection is
                // indistinguishable from a swallowed error, and an operator then
                // looks for it in the wrong place.
                assert!(
                    !err.to_string().is_empty(),
                    "seed {seed}, round {round}: rejection without a reason"
                );
            }
        }
    }

    // **The run must really have damaged something.** If the generator damages
    // nothing, everything gets through, and the invariant above confirms
    // itself — the finding from 9c, where 200 000 buffers reached the answer
    // path not once.
    let floor = iterations() / 20;
    assert!(
        rejected > floor,
        "seed {seed}: only {rejected} of {} documents were refused — then the \
         run damages nothing",
        iterations()
    );
    // And the reverse direction: if **nothing** got through, the acceptance path
    // above checks nothing. Both numbers together say that the run has seen both
    // sides.
    assert!(
        accepted > 0,
        "seed {seed}: not a single damaged document got through — then the \
         acceptance path is unchecked"
    );
}
