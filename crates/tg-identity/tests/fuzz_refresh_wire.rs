//! A fuzz run against the refresh's wire surface (ADR-0107, ADR-0097).
//!
//! **Why there are two nonce-adjacent runs.** `fuzz_nonce` checks the **vault**:
//! random interleavings of commitments and redemptions. This one checks the **way
//! there** -- the six `answer_refresh_*` methods a seat offers over the signer port
//! and whose payloads come from another seat. The port demands mTLS against
//! `signers/<seat>.pem` (ADR-0097), so it is authenticated; the bytes thereby stem
//! from a **registered** peer -- and precisely that is the situation for which
//! ADR-0014 provides a threshold of three: a taken-over seat.
//!
//! Four assurances, and the third is the one for whose sake the run exists:
//!
//! 1. no crash, whatever stands on the wire;
//! 2. a damaged round leaves the **generations** unchanged -- ADR-0107 says "all five
//!    or none", and a half-applied refresh would be exactly the state it excludes;
//! 3. a seat stays **usable** afterwards: it can begin a new round. Without that
//!    assurance a single broken package would suffice to take a seat out of the group
//!    permanently -- at t = 3 of 5 three of those cost the CA;
//! 4. the **acceptance path** is really entered (the finding from 9c: a run that never
//!    reaches it confirms every invariant itself).
//!
//! Conventions as everywhere: a fresh seed per run, the iteration count from
//! `TG_FUZZ_ITERATIONS`, the default is the release threshold. A failure reports its
//! seed and belongs nailed down as a seeded regression test.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use tg_identity::threshold::{RefreshDealRequest, RefreshStartRequest};

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

/// Alters a payload -- or leaves it alone.
///
/// Five kinds as in `fuzz_dns`/`fuzz_quic`, and one of them is **none**: only so does
/// an acceptable round arise at all.
///
/// **`true` means "altered", not "must be refused"**, and that is measured:
/// `frost-core`'s `deserialize` **tolerates appended bytes** -- a binding with one byte
/// too many at the end is accepted and carries the same values. Functionally harmless
/// (the round runs with the correct points), and measured, no byte comparison builds
/// on these payloads. It is the same non-injectivity ADR-0087 found for base64: the
/// trap for the next person who builds a check on the **bytes** while another works on
/// the parsed object.
fn damage(bytes: &mut Vec<u8>, entropy: &mut SeededEntropy) -> bool {
    if bytes.is_empty() {
        return false;
    }

    match entropy.below(5) {
        0 => return false,
        1 => {
            let at = entropy.below(bytes.len());
            bytes[at] ^= 1 << entropy.below(8);
        }
        2 => bytes.push(u8::try_from(entropy.below(256)).unwrap_or(0)),
        3 => {
            let keep = entropy.below(bytes.len());
            bytes.truncate(keep);
        }
        _ => bytes.clear(),
    }

    true
}

/// **Arbitrary bytes on the wire do not take a seat's generation from it.**
#[test]
fn no_damaged_round_changes_a_seat() {
    let seed = fresh_seed();
    let mut entropy = SeededEntropy::new(seed);
    let group = group_of_five(&mut entropy);
    let numbers: Vec<u16> = (1..=5).collect();

    let mut accepted = 0_u32;
    let mut refused = 0_u32;
    let mut longest = 0_usize;

    for step in 0..iterations() {
        // **All five in one call**, and that is a finding about my first build-up:
        // `Fixture::wired` builds **new** `LocalLink`s at every call. The seat under
        // test was thereby a different object from the ones in the loop, its
        // `refresh_start` lay elsewhere, and an undamaged round was refused with
        // "seat 1 has begun no refresh" -- an error in the test rig that looked like
        // one in the code.
        //
        // Fresh per round it stays nevertheless: a round's state shall not carry over
        // the iterations, otherwise the run would check a history instead of a
        // payload.
        let links = group.wired(&numbers);
        let index = entropy.below(links.len());
        let link = &links[index];
        let before = link.epochs();

        // Round 1 at all five: valid broadcasts that the run damages afterwards.
        // Pure randomness produces no parsable broadcast.
        let epoch = 1_u64 + u64::try_from(entropy.below(3)).unwrap_or(0);
        let mut broadcasts = Vec::new();
        for (at, (number, seat)) in numbers.iter().zip(&links).enumerate() {
            let answer = seat
                .answer_refresh_start(&RefreshStartRequest { epoch })
                .unwrap_or_else(|err| panic!("seed {seed}, step {step}: round 1: {err}"));

            // **Without one's own.** Every seat knows its broadcast already; the round
            // demands those of the other four. That too came out as a refusal ("5 are
            // present") -- the surface says its expectation, and the test rig had it
            // wrong.
            if at != index {
                broadcasts.push((*number, answer.broadcast));
            }
        }

        // **The decision falls per round, not per broadcast** -- and that is a
        // finding about my first attempt: with five broadcasts each having a 1/5
        // chance of "undamaged" the acceptance path lies at 1:3125, and the run
        // reported "only 0 of 300 rounds were accepted". It would have confirmed every
        // invariant itself (the finding from 9c). And it is at the same time the more
        // realistic situation: a taken-over seat sends **its** package broken, not all
        // five.
        let damaged = if entropy.below(2) == 0 {
            let at = entropy.below(broadcasts.len());
            match entropy.below(10) {
                // The **seat** in the mapping is input too: an unknown or duplicate
                // seat arrives that way.
                0 => {
                    broadcasts[at].0 = 9;
                    true
                }
                1 => {
                    // One's **own** seat as the sender: a seat that gets its own
                    // broadcast as a foreign one.
                    let claimed = numbers[index];
                    let was = broadcasts[at].0;
                    broadcasts[at].0 = claimed;
                    claimed != was
                }
                2 => {
                    broadcasts.truncate(at);
                    at < numbers.len()
                }
                _ => damage(&mut broadcasts[at].1, &mut entropy),
            }
        } else {
            false
        };

        match link.answer_refresh_deal(&RefreshDealRequest { epoch, broadcasts }) {
            Ok(_) => accepted += 1,
            // **An undamaged round must get through.** Without this direction a
            // `refresh_deal` that refuses everything would be green likewise -- and
            // then no refresh would ever come about.
            Err(err) if !damaged => {
                panic!("seed {seed}, step {step}: an undamaged round was refused: {err}")
            }
            Err(err) => {
                refused += 1;
                let said = err.to_string();
                longest = longest.max(said.len());
                assert!(
                    said.len() < 4096,
                    "seed {seed}, step {step}: the message is {} bytes long -- the \
                     sender does not determine it",
                    said.len()
                );
            }
        }

        // **The generations are untouched** (ADR-0107: all five or none). An accepted
        // round 2 does not change them either -- only `refresh_finish` does that.
        assert_eq!(
            link.epochs(),
            before,
            "seed {seed}, step {step}: a round 2 changed the generations"
        );

        // **And the seat is still usable.** A single broken package must not take it
        // out of the group permanently.
        link.answer_refresh_start(&RefreshStartRequest { epoch: epoch + 100 })
            .unwrap_or_else(|err| panic!("seed {seed}, step {step}: the seat is jammed: {err}"));
    }

    // The acceptance path must be entered, and the refusal path too. **Measured over
    // three seeds: 66 % accepted, 33 % refused**, the longest refusal 102 bytes. The
    // thresholds lie at 5 % and thereby have a thirteen- and six-fold of air -- the
    // finding from the peer run: a threshold on the expected value lets every second
    // run fall, and a fuzz run that is red half the time gets switched off instead of
    // read.
    let total = iterations();
    // **The acceptance assurance is the weaker of two**, and that stands here so that
    // nobody takes it for the carrying one: the acceptance path is covered above all
    // by "an undamaged round must get through" above -- the counter-check "refuse
    // everything" falls there, long before this count bites. And it cannot be brought
    // to zero with this run's means: even if every round goes into the alteration
    // branch, the appended bytes get through (see `damage`).
    assert!(
        accepted * 20 > total,
        "seed {seed}: only {accepted} of {total} rounds were accepted"
    );
    assert!(
        refused * 20 > total,
        "seed {seed}: only {refused} of {total} rounds were refused"
    );
    assert!(
        longest > 20,
        "seed {seed}: the longest refusal was {longest} bytes -- the run hardly \
         touched the message path"
    );
}
