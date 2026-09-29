//! Fuzz run against the wire boundary.
//!
//! `from_bytes` sees bytes from the peer of a gRPC call. On the identity port
//! they come from somebody who has to show **no** client certificate — the
//! weakest precondition a trust boundary has in this system.
//!
//! Pure randomness almost never produces parsable JSON, so the run produces
//! **valid** messages and damages them, and an assertion at the end records
//! that a minimum share could be read at all.
//!
//! Conventions as in the other fuzz runs: a fresh seed per run, iteration count
//! from `TG_FUZZ_ITERATIONS`, the default being the release threshold. A failure
//! reports its seed and belongs nailed down as a seeded regression test — it is
//! a finding, not flakiness.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use serde::{Deserialize, Serialize};
use tg_wire::{MAX_DETAIL, from_bytes, to_bytes};
use tonic::Code;

const DEFAULT_ITERATIONS: u32 = 20_000;

/// Determines how many fuzz rounds to run.
///
/// # Returns
///
/// The value of `TG_FUZZ_ITERATIONS` if set and parseable, otherwise
/// [`DEFAULT_ITERATIONS`].
fn iterations() -> u32 {
    std::env::var("TG_FUZZ_ITERATIONS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS)
}

/// Draws a fresh seed for this run from the process's random state.
///
/// # Returns
///
/// A nonzero `u64` seed, different on every run so the fuzz run explores new
/// inputs each time.
fn fresh_seed() -> u64 {
    RandomState::new().build_hasher().finish() | 1
}

struct Rng(u64);

impl Rng {
    /// Advances the generator and returns the next pseudo-random value.
    ///
    /// # Returns
    ///
    /// The next `u64` in the xorshift sequence.
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Draws a pseudo-random index strictly below `bound`.
    ///
    /// # Parameters
    ///
    /// - `bound`: the exclusive upper bound.
    ///
    /// # Returns
    ///
    /// A value in `0..bound`, or `0` if `bound` is `0`.
    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            usize::try_from(self.next_u64() % bound as u64).unwrap_or(0)
        }
    }

    /// Draws a pseudo-random byte.
    ///
    /// # Returns
    ///
    /// A value in `0..=255`.
    fn byte(&mut self) -> u8 {
        u8::try_from(self.next_u64() & 0xFF).unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    name: String,
    number: u64,
    list: Vec<String>,
}

/// Checks three absolute invariants of `from_bytes` against damaged and
/// adversarial JSON buffers.
///
/// 1. No buffer leads to a panic.
/// 2. Every refusal is `invalid_argument` — never `internal`. The bytes are
///    foreign, so the error is not ours.
/// 3. **No message is longer than the bound permits.** Without this, the
///    sender determines how much we write.
#[test]
fn no_buffer_panics_and_no_sender_chooses_our_message_length() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let total = iterations();
    let mut readable = 0_u32;

    for round in 0..total {
        // A valid message whose size the "sender" chooses.
        let value = Message {
            name: "ä".repeat(rng.below(3_000)),
            number: rng.next_u64(),
            list: (0..rng.below(8)).map(|i| format!("e{i}")).collect(),
        };
        let mut bytes = to_bytes(&value).expect("own message encodable");

        match rng.below(6) {
            0 => {
                let flips = 1 + rng.below(4);
                for _ in 0..flips {
                    let at = rng.below(bytes.len());
                    bytes[at] = rng.byte();
                }
            }
            1 => {
                let keep = rng.below(bytes.len());
                bytes.truncate(keep);
            }
            2 => {
                for _ in 0..=rng.below(16) {
                    bytes.push(rng.byte());
                }
            }
            3 if bytes.len() > 4 => {
                let a = rng.below(bytes.len());
                let b = rng.below(bytes.len());
                bytes.swap(a, b);
            }
            // A type error: exactly the case in which `serde_json` quotes the
            // value — and thereby the one the bound aims at.
            4 => {
                bytes = format!(
                    "{{\"name\":{:?},\"number\":\"not a number\",\"list\":[]}}",
                    value.name
                )
                .into_bytes();
            }
            // Undamaged: the run has to hit the normal case.
            _ => {}
        }

        match from_bytes::<Message>(&bytes) {
            Ok(_) => readable += 1,
            Err(err) => {
                assert_eq!(
                    err.code(),
                    Code::InvalidArgument,
                    "round {round}, seed {seed}: code {:?} instead of InvalidArgument",
                    err.code()
                );
                let laenge = err.message().chars().count();
                assert!(
                    laenge <= MAX_DETAIL + 64,
                    "round {round}, seed {seed}: message {laenge} characters long — \
                     the sender determines our output size"
                );
                assert!(
                    !err.message().is_empty(),
                    "round {round}, seed {seed}: refusal without a message"
                );
            }
        }
    }

    // The assurance from the module header: the run hit the normal case.
    // Without it we would only be checking that garbage is refused.
    assert!(
        readable > total / 20,
        "seed {seed}: only {readable} of {total} buffers were readable — the run \
         does not hit the normal case"
    );
}
