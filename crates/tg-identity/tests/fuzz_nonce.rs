//! A fuzz run against the nonce discipline (ADR-0014).
//!
//! The other nonce tests check named cases. This one throws random interleavings of
//! commitments, redemptions, repetitions and aborts over five seats and many sessions
//! -- the form in which a nonce error arises in operation: not as a wrong call but as
//! an unfortunate ordering.
//!
//! The claimed invariant is a single one and it is absolute: **no commitment is ever
//! redeemed twice, and no commitment repeats itself.**
//!
//! Conventions as in `tg-defs`/`tg-consensus`: a fresh seed per run, the iteration
//! count from `TG_FUZZ_ITERATIONS`, the default is the release threshold. A failure
//! reports its seed and belongs nailed down as a seeded regression test of its own --
//! it is a finding, no flakiness.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{BuildHasher, Hasher};

use tg_identity::threshold::{CommitmentId, NonceError, NonceVault, Seat};

mod support;
use support::{SeededEntropy, group_of_five};

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

/// **No nonce twice**, over random interleavings.
#[test]
fn no_commitment_is_ever_issued_or_spent_twice() {
    let seed = fresh_seed();
    let mut entropy = SeededEntropy::new(seed);
    let group = group_of_five(&mut entropy);

    let mut vaults: BTreeMap<Seat, NonceVault> = group
        .shares()
        .keys()
        .map(|seat| (*seat, NonceVault::new(*seat)))
        .collect();
    let mut streams: BTreeMap<Seat, SeededEntropy> = group
        .shares()
        .keys()
        .map(|seat| (*seat, entropy.fork()))
        .collect();

    // What the run knows about itself.
    let mut issued: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut open: Vec<(Seat, CommitmentId)> = Vec::new();
    let mut retired: BTreeSet<(Seat, CommitmentId)> = BTreeSet::new();
    let mut spent_count: BTreeMap<Seat, u64> = BTreeMap::new();

    let seats: Vec<Seat> = group.shares().keys().copied().collect();

    for step in 0..iterations() {
        let seat = seats[entropy.below(seats.len())];
        let choice = entropy.below(100);

        match choice {
            // Commit -- the most frequent step.
            0..=44 => {
                let vault = vaults.get_mut(&seat).expect("seat");
                let stream = streams.get_mut(&seat).expect("stream");
                let (id, commitments) = vault
                    .commit(group.share(seat), stream)
                    .unwrap_or_else(|err| panic!("seed {seed}, step {step}: commit: {err}"));

                let bytes = commitments.serialize().expect("bytes");
                assert!(
                    issued.insert(bytes),
                    "seed {seed}, step {step}: the same commitment handed out twice"
                );
                open.push((seat, id));
            }
            // Redeem an open commitment.
            45..=74 if !open.is_empty() => {
                let index = entropy.below(open.len());
                let (seat, id) = open.swap_remove(index);
                let vault = vaults.get_mut(&seat).expect("seat");

                vault
                    .take(id)
                    .unwrap_or_else(|err| panic!("seed {seed}, step {step}: redeem: {err}"));
                assert!(
                    retired.insert((seat, id)),
                    "seed {seed}, step {step}: a commitment redeemed twice"
                );
                *spent_count.entry(seat).or_default() += 1;
            }
            // Discard an open commitment.
            75..=84 if !open.is_empty() => {
                let index = entropy.below(open.len());
                let (seat, id) = open.swap_remove(index);
                let vault = vaults.get_mut(&seat).expect("seat");

                vault
                    .discard(id)
                    .unwrap_or_else(|err| panic!("seed {seed}, step {step}: discard: {err}"));
                assert!(retired.insert((seat, id)));
                *spent_count.entry(seat).or_default() += 1;
            }
            // Repetition: redeem an already settled commitment once more. That is
            // the attack the whole construction stands against.
            85..=99 if !retired.is_empty() => {
                let index = entropy.below(retired.len());
                let (seat, id) = *retired.iter().nth(index).expect("present");
                let vault = vaults.get_mut(&seat).expect("seat");

                let err = vault.take(id).expect_err(&format!(
                    "seed {seed}, step {step}: a settled commitment was redeemed \
                     a second time"
                ));
                assert!(
                    matches!(err, NonceError::AlreadySpent { .. }),
                    "seed {seed}, step {step}: the wrong reason: {err}"
                );
            }
            _ => {}
        }
    }

    // Bookkeeping: open plus spent is everything that ever went out.
    for (seat, vault) in &vaults {
        let still_open = open.iter().filter(|(other, _)| other == seat).count();
        assert_eq!(
            vault.outstanding(),
            still_open,
            "seed {seed}: {seat} counts the open commitments wrongly"
        );
        assert_eq!(
            vault.spent(),
            spent_count.get(seat).copied().unwrap_or_default(),
            "seed {seed}: {seat} counts the spent commitments wrongly"
        );
    }

    assert_eq!(
        issued.len(),
        open.len() + retired.len(),
        "seed {seed}: handed out is not open plus settled"
    );
}
