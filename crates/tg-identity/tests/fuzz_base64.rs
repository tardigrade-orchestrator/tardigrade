//! A fuzz run against the hand-written base64 reader (ADR-0037).
//!
//! **Why this reader of all things.** `unbase64` decodes `spki`, `signature`,
//! `intermediate_spki` and `next_node_spki` out of a `JoinRequest` or `RenewRequest`
//! -- and this port demands **no client certificate** (ADR-0043, determination 3: it
//! is the call with which a node procures its first one). With that it is the least
//! authenticated trust boundary of this system, and the repo's test rules make a fuzz
//! run there **mandatory**. It was missing.
//!
//! Four invariants, and the second is the carrying one:
//!
//! 1. **No crash** -- at an arbitrary input. Since ADR-0082 a panic is no longer a
//!    silent computation error but costs its task.
//! 2. **The round trip is lossless.** What `base64` writes `unbase64` must give back
//!    byte for byte -- on that hangs every signature check of the credential path.
//! 3. **No amplification**: the output is at most three quarters of the input.
//! 4. **A character outside the alphabet is refused.** Without that assurance a
//!    reader that skips everything unknown would be green likewise -- and two
//!    different texts would yield the same bytes.
//!
//! Conventions as in the eleven runs beside it: a fresh seed per run, the iteration
//! count from `TG_FUZZ_ITERATIONS` with the release threshold as the default, the
//! seed in every message. A failure is a **finding** and belongs nailed down as a
//! seeded regression test, not repeated.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use tg_identity::control::{base64, unbase64};

/// Iterations, when `TG_FUZZ_ITERATIONS` says nothing else.
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

/// A seeded stream -- the same construction as in the other fuzz runs.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            usize::try_from(self.next_u64() % bound as u64).unwrap_or(0)
        }
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next_u64() & 0xFF).unwrap_or(0)
    }

    /// A **printable ASCII character**.
    ///
    /// The first attempt diced full bytes -- and `String::from_utf8` afterwards
    /// discarded about half of all the damaged inputs before they reached the reader
    /// at all. Measured, the share of refusals thereby rose from **11.8 %** to
    /// **40.2 %**: the same finding as at the empty fuzz run in 9c, only the other way
    /// round -- it was not the acceptance path that stayed unentered but half the
    /// refusal path.
    fn printable(&mut self) -> u8 {
        0x20 + u8::try_from(self.next_u64() % 0x5F).unwrap_or(0)
    }
}

/// Does the character belong to the alphabet?
fn is_alphabet(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

/// **The round trip and the four invariants.**
///
/// What is produced is **valid** base64 and then damaged -- the lesson from 9c: pure
/// randomness hardly reaches the acceptance path, and a run that never enters it
/// confirms every invariant itself. Two counts at the end record that both paths
/// really ran.
#[test]
fn no_input_ever_panics_and_the_round_trip_is_lossless() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let mut accepted = 0_u32;
    let mut rejected = 0_u32;
    let rounds = iterations();

    for round in 0..rounds {
        // A plaintext whose length hits the three remainder cases too.
        let len = rng.below(48);
        let plain: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let encoded = base64(&plain);

        // **The round trip, undamaged.** It is the assurance on which the signature
        // check hangs.
        match unbase64(&encoded) {
            Ok(back) => assert_eq!(
                back, plain,
                "seed {seed}, round {round}: the round trip lost bytes \
                 (length {len}, text {encoded:?})"
            ),
            Err(err) => panic!(
                "seed {seed}, round {round}: our own base64 is not readable: {err} \
                 (length {len}, text {encoded:?})"
            ),
        }
        accepted += 1;

        // And then damaged: replace a character, append one, remove one, or dice
        // the whole text.
        let mut damaged: Vec<u8> = encoded.into_bytes();
        match rng.below(4) {
            0 if !damaged.is_empty() => {
                let at = rng.below(damaged.len());
                damaged[at] = rng.printable();
            }
            1 => damaged.push(rng.printable()),
            2 if !damaged.is_empty() => {
                let at = rng.below(damaged.len());
                damaged.remove(at);
            }
            _ => {
                damaged = (0..rng.below(64)).map(|_| rng.printable()).collect();
            }
        }

        // The damage is printable ASCII, so always UTF-8 -- the case "no UTF-8" does
        // not exist at this boundary anyway, the message comes as a `String` out of
        // the codec (ADR-0040).
        let text = String::from_utf8(damaged).expect("printable ASCII is UTF-8");

        match unbase64(&text) {
            Ok(bytes) => {
                accepted += 1;
                // **No amplification.**
                assert!(
                    bytes.len() <= text.len().saturating_mul(3) / 4 + 3,
                    "seed {seed}, round {round}: {} bytes out of {} characters",
                    bytes.len(),
                    text.len()
                );
                // **Strict apart from whitespace** (ADR-0087): every character
                // belongs to the alphabet or is padding, and the cleaned length is
                // divisible by four. Without the second half a reader that supplies
                // missing padding would be green likewise -- and then two different
                // texts would yield the same bytes.
                let cleaned: Vec<u8> = text.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
                assert!(
                    cleaned.iter().all(|c| is_alphabet(*c) || *c == b'='),
                    "seed {seed}, round {round}: accepted with a foreign character: {text:?}"
                );
                assert!(
                    cleaned.len().is_multiple_of(4),
                    "seed {seed}, round {round}: accepted without complete padding \
                     ({} characters): {text:?}",
                    cleaned.len()
                );
            }
            Err(_) => rejected += 1,
        }
    }

    // **So that the run does not confirm itself.** Without these assurances a reader
    // that accepts nothing would be as green as one that takes everything.
    assert!(
        accepted >= rounds,
        "seed {seed}: only {accepted} of at least {rounds} acceptances -- the \
         acceptance path was hardly entered"
    );
    // The threshold is **computed, not guessed**: measured, about 40 % of the rounds
    // are refused, demanded are 5 % -- an eight-fold of air. The finding from the peer
    // run, where it lay on the expected value and therefore every second run fell.
    assert!(
        rejected * 20 >= rounds,
        "seed {seed}: only {rejected} of {rounds} rounds were refused -- the \
         refusal path was hardly entered"
    );
}
