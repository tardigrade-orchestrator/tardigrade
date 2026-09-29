//! **A fuzz run on the login-line reader** (ADR-0096, determination 3).
//!
//! The plaintext comes from a secret an operator filed and that the data key
//! unseals in an authenticated manner (ADR-0095) -- so it is no trust boundary
//! in the sharp sense like the bytes from a container. The run stands
//! nevertheless, because the test rules recommend it for every reader with a
//! non-trivial input space and because it nails down a property fixed cases do
//! not see:
//!
//! **What comes out must be rebuildable into the input.** That is an
//! independent oracle and no second version of the same logic -- a reader that
//! one day splits at the *last* colon stands out on it without anybody having
//! thought of that case.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hasher as _};

use tg_runtime::network::RegistryLogin;

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

/// Characters as they occur in user names, passwords and tokens -- including
/// those a reader fails on: a colon, white space, a line ending.
const CHARS: &[char] = &[
    'a', 'Z', '7', '-', '_', '.', '+', '/', '=', '@', ':', ' ', '\t', '\n', '\r', 'ä', '€',
];

fn word(rng: &mut Rng, max: usize) -> String {
    (0..rng.below(max))
        .map(|_| CHARS[rng.below(CHARS.len())])
        .collect()
}

/// Produces a login line as an operator would file it -- and damages it.
///
/// **Valid lines, then damaged**, the finding from 9c: pure randomness never
/// reaches the acceptance path, and then every invariant confirms itself.
fn line(rng: &mut Rng) -> String {
    const PREFIXES: &[&str] = &["basic ", "bearer ", "Basic ", "basic", "", "token "];

    let prefix = PREFIXES[rng.below(PREFIXES.len())];
    let mut line = String::from(prefix);
    line.push_str(&word(rng, 12));
    if rng.below(4) != 0 {
        line.push(':');
        line.push_str(&word(rng, 20));
    }
    line
}

/// **No crash, nothing invented, no unbounded output.**
#[test]
fn no_login_line_is_misread() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let rounds = iterations();

    let mut basic = 0_u32;
    let mut bearer = 0_u32;
    let mut refused = 0_u32;

    for round in 0..rounds {
        let raw = line(&mut rng);
        let trimmed = raw.trim();

        match RegistryLogin::parse(&raw) {
            None => refused += 1,
            Some(RegistryLogin::Basic { user, password }) => {
                basic += 1;
                // The independent oracle: the parts rebuild the line.
                assert_eq!(
                    format!("basic {user}:{password}"),
                    trimmed,
                    "seed {seed}, round {round}: the parts do not rebuild \
                     {raw:?}"
                );
                assert!(
                    !user.is_empty(),
                    "seed {seed}, round {round}: an empty user from {raw:?}"
                );
                assert!(
                    !user.contains(':'),
                    "seed {seed}, round {round}: the user carries a colon -- \
                     the split was at the wrong one"
                );
            }
            Some(RegistryLogin::Bearer { token }) => {
                bearer += 1;
                // With the token **it itself** is trimmed as well, so no
                // equality oracle applies but a containment one.
                //
                // What it thereby does **not** see: whether the token was
                // trimmed. `"bearer  tok"` yields with and without the trim a
                // line that can be rebuilt -- measured, and that is why it
                // stands here instead of passing as an assurance. The fixed
                // witness `bearer    ` in `registry_login.rs` covers that
                // case.
                assert!(
                    trimmed.starts_with("bearer ") && trimmed.ends_with(token.as_str()),
                    "seed {seed}, round {round}: {token:?} does not sit like \
                     that in {raw:?}"
                );
                assert!(
                    !token.is_empty(),
                    "seed {seed}, round {round}: an empty token from {raw:?}"
                );
            }
        }
    }

    // A run that never enters an arm confirms its invariant itself. The
    // thresholds are measured, not computed.
    let fiftieth = rounds / 50;
    assert!(
        basic > fiftieth,
        "seed {seed}: only {basic} of {rounds} lines became `basic`"
    );
    assert!(
        bearer > fiftieth,
        "seed {seed}: only {bearer} of {rounds} lines became `bearer`"
    );
    assert!(
        refused > fiftieth,
        "seed {seed}: only {refused} of {rounds} lines were refused"
    );
}
