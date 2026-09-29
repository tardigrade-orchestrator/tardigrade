//! A fuzz run at the at-rest boundary (ADR-0095).
//!
//! A `Sealed` comes from the **log**, and that is retained (ADR-0020) -- whoever
//! reads a segment from an archive holds the bytes in their hand. Exactly against that
//! stands the AEAD, and the frame around it is **our** code: the nonce length, the
//! `try_into`, the buffers. It is diced here.
//!
//! **A fresh seed per run** (test rule): a fixed one would turn the run into a static
//! test set. The number of rounds is settable via `TG_FUZZ_ITERATIONS`; the default is
//! the release threshold.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use tg_identity::secrets::{DataKey, SealError, Sealed};

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

/// xorshift64* -- reproduces a run completely from its seed.
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

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(limit.max(1)).unwrap_or(1)).unwrap_or(0)
    }
}

/// **No crash, no wrong plaintext, no growth.**
///
/// The carrying invariant is the second: if something comes out, it **must** be the
/// plaintext that went in. Anything else would mean that a bent ciphertext yields a
/// different value -- and exactly that an AEAD must not do.
#[test]
fn no_damaged_envelope_opens_to_something_else() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let rounds = iterations() as usize;

    let key = DataKey::generate().expect("key");
    let mut opened = 0_usize;
    let mut refused = 0_usize;

    for round in 0..rounds {
        // A valid envelope, then damaged -- pure randomness never produces one (the
        // finding from 9c).
        let len = rng.below(64);
        let plaintext: Vec<u8> = (0..len).map(|_| (rng.next() & 0xff) as u8).collect();
        let mut sealed = key.seal(&plaintext).expect("sealable");

        match rng.below(6) {
            // Unchanged -- the acceptance path.
            0 => {}
            1 if !sealed.ciphertext.is_empty() => {
                let at = rng.below(sealed.ciphertext.len());
                sealed.ciphertext[at] ^= 1 << rng.below(8);
            }
            2 => {
                let at = rng.below(sealed.nonce.len());
                sealed.nonce[at] ^= 1 << rng.below(8);
            }
            // A nonce of the wrong length -- that is our frame, not `ring`.
            3 => sealed.nonce.truncate(rng.below(sealed.nonce.len())),
            4 => sealed.nonce.push((rng.next() & 0xff) as u8),
            // A ciphertext shorter than the tag.
            _ => sealed
                .ciphertext
                .truncate(rng.below(sealed.ciphertext.len() + 1)),
        }

        match key.open(&sealed) {
            Ok(got) => {
                assert_eq!(
                    got, plaintext,
                    "seed {seed}, round {round}: an envelope yielded a **different** \
                     plaintext"
                );
                opened += 1;
            }
            Err(err) => {
                assert_eq!(
                    err,
                    SealError::NotAuthentic,
                    "seed {seed}, round {round}: an unexpected error signal"
                );
                refused += 1;
            }
        }
    }

    // **Both paths must have been entered.** Without the first assurance a run that
    // never opens would confirm every invariant itself (the finding from 9c); without
    // the second a procedure that refuses nothing at all would be green.
    //
    // The thresholds are **measured**, not computed -- the finding from the peer run,
    // where one lay on the expected value and therefore every second run fell. Over
    // three seeds: opened 3383-3418 of 20 000 (17 %), refused the rest (83 %). What is
    // demanded is a twentieth each -- a good three- and sixteen-fold of air.
    assert!(
        opened * 20 >= rounds,
        "seed {seed}: only {opened} of {rounds} envelopes opened -- the \
         acceptance path was hardly entered"
    );
    assert!(
        refused * 20 >= rounds,
        "seed {seed}: only {refused} of {rounds} refused -- the refusal path \
         was hardly entered"
    );
}

/// **A diced envelope does not crash** -- one that never came out of a `seal`
/// either.
#[test]
fn arbitrary_bytes_never_panic() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let key = DataKey::generate().expect("key");

    for round in 0..iterations() {
        let sealed = Sealed {
            ciphertext: (0..rng.below(80))
                .map(|_| (rng.next() & 0xff) as u8)
                .collect(),
            nonce: (0..rng.below(20))
                .map(|_| (rng.next() & 0xff) as u8)
                .collect(),
        };

        assert!(
            matches!(key.open(&sealed), Err(SealError::NotAuthentic)),
            "seed {seed}, round {round}: diced bytes were opened"
        );
    }
}

/// **A key ring never opens something none of its keys sealed** (ADR-0100).
///
/// That is the security statement of the two-key phase: it is the price for a
/// rotation having no window, and it must not make the boundary softer. What is diced
/// is therefore **which** key sealed -- the primary, the one to be replaced or a
/// **foreign** one -- and whether the envelope is damaged.
///
/// The carrying invariant is the third: if something comes out, it must be the
/// plaintext that went in. A foreign envelope must **never** open.
#[test]
fn a_ring_never_opens_a_foreign_envelope() {
    use tg_identity::secrets::KeyRing;

    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let rounds = iterations() as usize;

    let primary = DataKey::generate().expect("key");
    let previous = DataKey::generate().expect("key");
    let foreign = DataKey::generate().expect("key");

    // The ring gets copies: the originals stay for sealing.
    let key_ring = KeyRing::new(
        DataKey::from_base64(&primary.to_base64()).expect("key"),
        Some(DataKey::from_base64(&previous.to_base64()).expect("key")),
    );

    let mut from_primary = 0_usize;
    let mut from_previous = 0_usize;
    let mut refused = 0_usize;

    for round in 0..rounds {
        let len = rng.below(48);
        let plaintext: Vec<u8> = (0..len).map(|_| (rng.next() & 0xff) as u8).collect();

        // Who sealed? The foreign one is the case that must **never** open.
        let who = rng.below(3);
        let origin = match who {
            0 => &primary,
            1 => &previous,
            _ => &foreign,
        };
        let mut sealed = origin.seal(&plaintext).expect("sealable");

        // And damaged, in one of three cases.
        if rng.below(3) == 0 && !sealed.ciphertext.is_empty() {
            let at = rng.below(sealed.ciphertext.len());
            sealed.ciphertext[at] ^= 1 << rng.below(8);
        }

        match key_ring.open(&sealed) {
            Ok(got) => {
                assert_ne!(
                    who, 2,
                    "seed {seed}, round {round}: a **foreign** envelope opened"
                );
                assert_eq!(
                    got, plaintext,
                    "seed {seed}, round {round}: the ring yielded a **different** \
                     plaintext"
                );

                // **And the re-keying question must fit it.** If `needs_rekey` said
                // `true` for a value of the primary, the rotation would never run to
                // the end; if it said `false` for one of the key to be replaced, an
                // operator would remove the old key too early -- and the value would
                // be unreadable.
                assert_eq!(
                    key_ring.needs_rekey(&sealed),
                    who == 1,
                    "seed {seed}, round {round}: needs_rekey does not fit the sealer"
                );

                if who == 0 {
                    from_primary += 1;
                } else {
                    from_previous += 1;
                }
            }
            Err(err) => {
                assert_eq!(
                    err,
                    SealError::NotAuthentic,
                    "seed {seed}, round {round}: an unexpected error signal"
                );
                refused += 1;
            }
        }
    }

    // **All three paths must have been entered.** Without the first two a run that
    // never opens would confirm every invariant itself -- and without the third a ring
    // that refuses nothing at all would be green.
    //
    // The thresholds are computed and with air: a third of the rounds per sealer, of
    // those two thirds undamaged -- so about 22 % each. What is demanded is a
    // twentieth, so a good four-fold of air. Refused is the foreign third plus the
    // damaged ones, so about 44 %.
    assert!(
        from_primary * 20 >= rounds,
        "seed {seed}: only {from_primary} of {rounds} opened with the primary"
    );
    assert!(
        from_previous * 20 >= rounds,
        "seed {seed}: only {from_previous} of {rounds} opened with the key to be \
         replaced -- the two-key phase was hardly checked"
    );
    assert!(
        refused * 20 >= rounds,
        "seed {seed}: only {refused} of {rounds} refused"
    );
}
