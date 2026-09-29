//! Fuzz run against the resolution's trust boundary.
//!
//! The names this resolver reads come from **containers**. That is the same kind
//! of boundary as parsing untrusted input in a definition file or over the
//! wire, and it is treated the same way here: fresh seed per run, iteration
//! count from `TG_FUZZ_ITERATIONS`, default is the release threshold, a find is
//! nailed down as a deterministic test of its own.
//!
//! Four invariants are asserted, and the third is the one at issue:
//!
//! 1. No crash, whatever arrives.
//! 2. `Refused` exactly when the name does not lie in the zone.
//! 3. **An address comes out only when the name belongs to exactly one
//!    registered, healthy endpoint.** A parser that holds `api` and
//!    `a\u{0301}pi` or `api.tardigrade.internal.evil.com` to be the same name
//!    hands addresses to askers who meant a different zone.
//! 4. Letter case and the trailing dot do not change the answer — otherwise the
//!    result hangs on how a client phrases it.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::Ipv4Addr;

use tg_net::discovery::{Answer, Domain, Endpoint, Health, Registry};

/// Iterations, if `TG_FUZZ_ITERATIONS` says nothing else.
const DEFAULT_ITERATIONS: u32 = 20_000;

/// Determines the number of fuzz iterations to run.
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
/// An odd 64-bit seed suitable for [`Rng::new`].
fn fresh_seed() -> u64 {
    RandomState::new().build_hasher().finish() | 1
}

/// xorshift64* — reproduces a run completely from its seed.
struct Rng(u64);

impl Rng {
    /// Creates a generator from a seed.
    ///
    /// # Parameters
    /// - `seed`: the seed to reproduce a run from.
    ///
    /// # Returns
    /// A new generator.
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    /// Advances the generator and returns the next pseudo-random value.
    ///
    /// # Returns
    /// The next 64-bit output of the xorshift64* sequence.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Draws a pseudo-random index below a bound.
    ///
    /// # Parameters
    /// - `bound`: the exclusive upper bound.
    ///
    /// # Returns
    /// A value in `0..bound`.
    ///
    /// # Panics
    /// Panics if the result does not fit in a `usize` (unreachable for the
    /// bounds used in this file).
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("fits")
    }

    /// Picks a pseudo-random element from a slice.
    ///
    /// # Parameters
    /// - `from`: the slice to pick from.
    ///
    /// # Returns
    /// A reference to one of the slice's elements.
    fn pick<'a, T>(&mut self, from: &'a [T]) -> &'a T {
        &from[self.below(from.len())]
    }

    /// Draws a boolean with probability `1 / in_n`.
    ///
    /// # Parameters
    /// - `in_n`: the odds denominator.
    ///
    /// # Returns
    /// `true` with probability `1 / in_n`.
    fn chance(&mut self, in_n: u64) -> bool {
        self.next().is_multiple_of(in_n)
    }
}

const DOMAIN: &str = "tardigrade.internal";

/// Builds the fixture registry used by the fuzz runs in this file.
///
/// # Returns
/// The constructed registry, including one unhealthy endpoint.
fn registry() -> Registry {
    Registry::new(
        Domain::new(DOMAIN).expect("valid"),
        vec![
            Endpoint {
                workload: "api".to_owned(),
                instance: 0,
                address: Ipv4Addr::new(10, 42, 1, 10),
                health: Health::Healthy,
            },
            Endpoint {
                workload: "api".to_owned(),
                instance: 1,
                address: Ipv4Addr::new(10, 42, 1, 11),
                health: Health::Healthy,
            },
            Endpoint {
                workload: "ledger".to_owned(),
                instance: 0,
                address: Ipv4Addr::new(10, 42, 1, 20),
                health: Health::Unhealthy,
            },
        ],
    )
}

/// Building blocks that lie close to valid names — that is where the errors sit.
///
/// Pure randomness over bytes finds mostly NXDOMAIN. What is interesting are the
/// cases that are *almost* right: the correct name with a suffix, the wrong
/// separator, an invisible character in between.
const PIECES: &[&str] = &[
    "api",
    "ledger",
    "cache",
    "tardigrade",
    "internal",
    "0",
    "1",
    "9",
    "",
    ".",
    "..",
    "-",
    "_",
    "*",
    "%",
    "\\",
    "/",
    "\0",
    "\n",
    "\t",
    " ",
    "..",
    "API",
    "Api",
    "aPi",
    "\u{0301}",
    "\u{200b}",
    "ａｐｉ",
    "xn--api",
    "evil",
    "com",
    "127.0.0.1",
    "[::1]",
    "'",
    "\"",
    ";",
    "$(id)",
    "%2e",
];

/// Builds a name that lies close to a valid one, sometimes from scratch and
/// sometimes by damaging a real name, since that is where the interesting
/// errors sit.
///
/// # Parameters
/// - `rng`: the generator driving the construction.
///
/// # Returns
/// A generated, possibly malformed or malicious, DNS name.
fn name(rng: &mut Rng) -> String {
    // Sometimes build from nothing, sometimes start from a real name and damage
    // it — the latter finds the cases that are just barely off.
    let mut out = if rng.chance(2) {
        String::new()
    } else {
        let base = rng.pick(&["api", "ledger", "cache", "0.api", "1.api"]);
        format!("{base}.{DOMAIN}")
    };

    let edits = rng.below(6);
    for _ in 0..edits {
        let piece = *rng.pick(PIECES);
        if out.is_empty() || rng.chance(3) {
            out.push_str(piece);
        } else {
            // Insert at a character boundary so that valid UTF-8 remains —
            // invalid UTF-8 is a different boundary and is already rejected
            // when the DNS message itself is decoded.
            let at = out
                .char_indices()
                .nth(rng.below(out.chars().count()))
                .map_or(0, |(index, _)| index);
            out.insert_str(at, piece);
        }
    }

    out
}

/// Fuzzes name resolution to check that no generated name ever yields an
/// address it is not entitled to.
#[test]
fn no_name_from_a_container_yields_an_address_it_should_not() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let registry = registry();

    // What deserves an address at all — every other name must get none.
    // Deliberately written out here and not computed from the same logic that is
    // under test.
    let allowed: std::collections::BTreeMap<&str, Ipv4Addr> = [
        ("api.tardigrade.internal", Ipv4Addr::new(10, 42, 1, 10)),
        ("0.api.tardigrade.internal", Ipv4Addr::new(10, 42, 1, 10)),
        ("1.api.tardigrade.internal", Ipv4Addr::new(10, 42, 1, 11)),
    ]
    .into_iter()
    .collect();

    for round in 0..iterations() {
        let raw = name(&mut rng);
        let answer = registry.resolve(&raw);
        let canonical = raw.trim_end_matches('.').to_ascii_lowercase();

        // The zone ends at a **label boundary**. `ends_with` alone does not
        // suffice: `internaltardigrade.internal` ends in the zone but does not
        // lie within it.
        let in_zone = canonical == DOMAIN || canonical.ends_with(&format!(".{DOMAIN}"));

        let context = || {
            format!(
                "seed {seed}, round {round}, name '{}' → {answer:?}",
                raw.escape_debug()
            )
        };

        match &answer {
            Answer::Addresses(addresses) => {
                assert!(
                    !addresses.is_empty(),
                    "Addresses must never be empty — NoData exists for that. {}",
                    context()
                );
                assert!(
                    allowed.contains_key(canonical.as_str()),
                    "address for a name that must get none. {}",
                    context()
                );
                for address in addresses {
                    assert!(
                        address.octets()[..3] == [10, 42, 1],
                        "foreign address in the answer. {}",
                        context()
                    );
                    assert_ne!(
                        *address,
                        Ipv4Addr::new(10, 42, 1, 20),
                        "the unhealthy endpoint must never come out. {}",
                        context()
                    );
                }
            }
            Answer::Refused => assert!(
                !in_zone,
                "Refused for a name in our own zone. {}",
                context()
            ),
            Answer::NoData | Answer::NxDomain => {}
        }
    }
}

/// Fuzzes name resolution to check that letter case and a trailing dot never
/// change the answer for the same name.
#[test]
fn case_and_the_trailing_dot_never_change_the_answer() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let registry = registry();

    for round in 0..iterations() {
        let raw = name(&mut rng);
        let plain = registry.resolve(&raw);

        // Append a dot only if one does not already stand there: `..` is an
        // empty label and thereby a **different**, invalid name — no spelling
        // variant of the same one.
        let mut variants = vec![raw.to_ascii_uppercase(), raw.to_ascii_lowercase()];
        if !raw.ends_with('.') {
            variants.push(format!("{raw}."));
        }

        for variant in variants {
            assert_eq!(
                registry.resolve(&variant),
                plain,
                "seed {seed}, round {round}: '{}' and '{}' are answered \
                 differently",
                raw.escape_debug(),
                variant.escape_debug()
            );
        }
    }
}
