//! **A fuzz run on the files the sidecar re-reads in operation.**
//!
//! The **agent** writes the edges (ADR-0025) and the egress permissions
//! (ADR-0041) from the slice (ADR-0040) -- so the input comes from inside and
//! is no trust boundary in the sense of the test rules. The plan left the
//! classification open; it stands there now, and this run is its consequence:
//! it checks not what an attacker sends but **what may come out of half a
//! file**.
//!
//! The case is reachable without anybody being malicious: the agent writes
//! over temp and `rename`, but a file can stem from an older state, a slice
//! can carry a field this sidecar does not know, and an operator can lay it
//! down by hand in an emergency.
//!
//! Two invariants carry, and the second is a **security statement**:
//!
//! 1. **Nothing is invented.** Every pair that comes out builds itself back
//!    into a line of the input -- an independent oracle and no second version
//!    of the logic.
//! 2. **No foreign workload comes out.** Several run on one node, and where
//!    the neighbour phones is none of this sidecar's business (ADR-0041). A
//!    prefix is no name in the process.

use std::collections::hash_map::RandomState;
use std::fmt::Write as _;
use std::hash::{BuildHasher as _, Hasher as _};

use tg_proxy::options::{edges_from_text, egress_from_text};

/// Iterations, if `TG_FUZZ_ITERATIONS` says nothing else.
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

/// xorshift64* -- one seed reproduces the run completely.
struct Rng(u64);

impl Rng {
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

/// The workload whose sidecar reads.
const MINE: &str = "api";

/// Names as they stand in the files -- together with the two at which a
/// prefix comparison fails (`api-test`, `apix`).
const NAMES: &[&str] = &["api", "api-test", "apix", "ledger", "foreign", "a"];

/// Characters with which damage is done: the two formats' separators,
/// whitespace, the comment character and ordinary name bytes.
const NOISE: &[char] = &[
    '-', '>', ' ', '\t', '#', ':', 'a', '9', '\n', '\r', '.', 'ä', '\u{0}',
];

/// Produces a file as the agent writes it -- and damages it.
///
/// **Valid lines, then damaged**, the finding from 9c: pure randomness never
/// reaches the acceptance path, and then every invariant confirms itself.
fn file(rng: &mut Rng, egress: bool) -> String {
    let mut text = String::new();

    for _ in 0..=rng.below(5) {
        match rng.below(8) {
            // A comment and an empty line -- the reader must pass over
            // both, and without them the path would never run.
            0 => text.push_str("# a comment\n"),
            1 => text.push('\n'),
            _ => {
                if egress {
                    let owner = NAMES[rng.below(NAMES.len())];
                    let host = NAMES[rng.below(NAMES.len())];
                    let port = [80_u32, 443, 8443, 65535, 65536, 0][rng.below(6)];
                    let transport = ["", " tcp", " quic", " udp", " sctp"][rng.below(5)];
                    writeln!(text, "{owner} {host}.test {port}{transport}").expect("the string");
                } else {
                    let from = NAMES[rng.below(NAMES.len())];
                    let to = NAMES[rng.below(NAMES.len())];
                    writeln!(text, "{from} -> {to}").expect("the string");
                }
            }
        }
    }

    // Exactly one byte is damaged -- at a character boundary, for a cut in
    // the middle of a multi-byte character would yield no `String`.
    if !text.is_empty() && rng.below(4) != 0 {
        let at = (0..text.len())
            .rev()
            .find(|at| text.is_char_boundary(*at))
            .unwrap_or(0);
        let at = (0..=at)
            .rev()
            .filter(|at| text.is_char_boundary(*at))
            .nth(rng.below(text.chars().count().max(1)))
            .unwrap_or(0);
        let mut damaged = String::with_capacity(text.len() + 1);
        damaged.push_str(&text[..at]);
        damaged.push(NOISE[rng.below(NOISE.len())]);
        damaged.push_str(&text[at..]);
        text = damaged;
    }

    text
}

/// **Nothing is invented, and no foreign workload comes out.**
#[test]
fn no_half_written_file_invents_a_permission() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let rounds = iterations();

    let mut edges_read = 0_u32;
    let mut edges_refused = 0_u32;
    let mut permits_read = 0_u32;
    let mut permits_refused = 0_u32;

    for round in 0..rounds {
        // ---------------------------------------------------- the edges
        let text = file(&mut rng, false);
        match edges_from_text(&text) {
            Err(_) => edges_refused += 1,
            Ok(edges) => {
                edges_read += 1;
                let lines: Vec<&str> = text.lines().collect();
                for (from, to) in edges {
                    assert!(
                        lines.iter().any(|line| {
                            let line = line.split('#').next().unwrap_or("").trim();
                            line.starts_with(&from) && line.ends_with(&to) && line.contains("->")
                        }),
                        "seed {seed}, round {round}: the edge {from:?} -> {to:?} \
                         does not stand in {text:?}"
                    );
                }
            }
        }

        // ----------------------------------------------- the permissions
        let text = file(&mut rng, true);
        match egress_from_text(&text, MINE) {
            Err(_) => permits_refused += 1,
            Ok(permits) => {
                permits_read += 1;
                let lines: Vec<&str> = text.lines().collect();
                for (host, port, _transport) in permits {
                    // The security statement: the line belongs to **us**,
                    // and a prefix is no name.
                    assert!(
                        lines.iter().any(|line| {
                            let line = line.split('#').next().unwrap_or("").trim();
                            let mut fields = line.split_whitespace();
                            fields.next() == Some(MINE)
                                && fields.next() == Some(host.as_str())
                                // The **number** is compared and not the
                                // text: `09` parses to `9`, and for a port
                                // that is the same. Unlike with the instance
                                // number from 9a, where the leading zero was
                                // part of an identifier and the same
                                // comparison a finding -- an oracle may be
                                // independent but not stricter than the
                                // contract.
                                && fields.next().and_then(|raw| raw.parse().ok())
                                    == Some(port)
                        }),
                        "seed {seed}, round {round}: the permission onto \
                         {host:?}:{port} does not stand that way in {text:?} -- \
                         or it belongs to another workload"
                    );
                }
            }
        }
    }

    // A run that never enters a branch confirms its invariant itself. The
    // thresholds are measured, not computed.
    let twentieth = rounds / 20;
    for (what, count) in [
        ("edge files read", edges_read),
        ("edge files refused", edges_refused),
        ("egress files read", permits_read),
        ("egress files refused", permits_refused),
    ] {
        assert!(
            count > twentieth,
            "seed {seed}: only {count} {what} of {rounds}"
        );
    }
}
