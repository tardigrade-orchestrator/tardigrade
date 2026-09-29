//! The nonce discipline (ADR-0014, "the most dangerous place of the whole
//! construction").
//!
//! FROST is two-round: in round 1 a seat draws a nonce and hands out the commitment
//! to it, in round 2 it signs with it. If the same nonce is used for two signatures,
//! the **share** can be computed from them -- two equations, one unknown. Whoever
//! collects t such shares has the signing CA.
//!
//! That is why the uniqueness does not lie with the caller but in the structure: the
//! nonce lives exclusively in the [`NonceVault`], it leaves it only through `take`,
//! and `take` removes it in the process. A second access finds nothing there any
//! more. This file checks that under **repetition** and **concurrency** -- the two
//! conditions under which ADR-0014 expects the error, and not in the happy path.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tg_identity::threshold::{
    Epoch, NonceError, NonceVault, Participant, PlainCustody, SessionId, ThresholdError,
};

mod support;
use support::{SeededEntropy, group_of_five};

/// **A nonce is handed out exactly once.** The second access fails typed instead of
/// delivering a copy.
#[test]
fn a_nonce_can_be_taken_only_once() {
    let mut entropy = SeededEntropy::new(0x7B_1001);
    let group = group_of_five(&mut entropy);
    let seat = group.seat(1);
    let mut vault = NonceVault::new(seat);

    let (id, _commitments) = vault
        .commit(group.share(seat), &mut entropy)
        .expect("commitment");

    vault.take(id).expect("the first withdrawal succeeds");
    let err = vault.take(id).expect_err("the second must not succeed");

    assert!(
        matches!(err, NonceError::AlreadySpent { .. }),
        "the reason must be named, not merely 'not found': {err}"
    );
}

/// An identifier that never existed in this vault is something other than a spent one
/// -- and the message says so. Otherwise a programming error blurs with an attack.
#[test]
fn an_unknown_commitment_is_distinguished_from_a_spent_one() {
    let mut entropy = SeededEntropy::new(0x7B_1002);
    let group = group_of_five(&mut entropy);

    let mut mine = NonceVault::new(group.seat(1));
    let mut theirs = NonceVault::new(group.seat(2));

    let (own, _) = mine
        .commit(group.share(group.seat(1)), &mut entropy)
        .expect("one's own commitment");
    let (foreign, _) = theirs
        .commit(group.share(group.seat(2)), &mut entropy)
        .expect("a foreign commitment");

    mine.take(own).expect("known");
    assert!(matches!(
        mine.take(own).expect_err("spent"),
        NonceError::AlreadySpent { .. }
    ));
    assert!(matches!(
        mine.take(foreign).expect_err("a foreign seat"),
        NonceError::Unknown { .. }
    ));
}

/// A discarded commitment is spent likewise. Otherwise "abort" would be the way to
/// get the same nonce a second time.
#[test]
fn a_discarded_commitment_stays_spent() {
    let mut entropy = SeededEntropy::new(0x7B_1003);
    let group = group_of_five(&mut entropy);
    let seat = group.seat(1);
    let mut vault = NonceVault::new(seat);

    let (id, _) = vault
        .commit(group.share(seat), &mut entropy)
        .expect("commitment");
    vault.discard(id).expect("retire");

    assert!(matches!(
        vault.take(id).expect_err("discarded means spent"),
        NonceError::AlreadySpent { .. }
    ));
    assert_eq!(vault.outstanding(), 0);
    assert_eq!(vault.spent(), 1);
}

/// A thousand draws, a thousand distinct commitments.
#[test]
fn a_thousand_commitments_are_a_thousand_distinct_values() {
    let mut entropy = SeededEntropy::new(0x7B_1004);
    let group = group_of_five(&mut entropy);
    let seat = group.seat(1);
    let share = group.share(seat).clone();
    let mut vault = NonceVault::new(seat);

    let mut seen = BTreeSet::new();
    for _ in 0..1_000 {
        let (id, commitments) = vault.commit(&share, &mut entropy).expect("commitment");
        assert!(seen.insert(commitments.serialize().expect("bytes")));
        vault.take(id).expect("spend");
    }

    assert_eq!(seen.len(), 1_000);
    assert_eq!(vault.spent(), 1_000);
}

/// **An entropy source that repeats itself is recognized** -- before the nonce
/// leaves the vault.
///
/// That is the case one fears in operation: a cloned VM, a restored snapshot, a
/// source before its initialization. The vault does not hand out a commitment it has
/// already given once.
#[test]
fn a_repeating_entropy_source_is_caught_before_the_nonce_leaves() {
    let mut entropy = SeededEntropy::new(0x7B_1005);
    let group = group_of_five(&mut entropy);
    let seat = group.seat(1);
    let share = group.share(seat).clone();
    let mut vault = NonceVault::new(seat);

    let mut source = SeededEntropy::new(0x1234_5678);
    let (id, _) = vault
        .commit(&share, &mut source)
        .expect("the first commitment");
    vault.take(id).expect("spend");

    // The same source once more from the start: it delivers exactly the same
    // bytes.
    let mut source_again = SeededEntropy::new(0x1234_5678);
    let err = vault
        .commit(&share, &mut source_again)
        .expect_err("the same nonce must not leave the vault");

    assert!(
        matches!(err, NonceError::EntropyRepeated { .. }),
        "the reason must name the source: {err}"
    );
    assert_eq!(
        vault.outstanding(),
        0,
        "and the refused commitment must not stay lying open"
    );
}

/// **Repetition, first half:** letting the same session commit twice gives the same
/// commitment, not a second nonce. A network retry or a duplicated packet must burn
/// no nonce.
#[test]
fn a_repeated_commit_for_one_session_returns_the_same_commitment() {
    let mut entropy = SeededEntropy::new(0x7B_1006);
    let group = group_of_five(&mut entropy);
    let seat = group.seat(1);
    let mut participant = Participant::new(
        seat,
        group.share(seat),
        group.public(),
        Epoch::GENESIS,
        Arc::new(PlainCustody),
    )
    .expect("participant");

    let session = SessionId::from(42);
    let first = participant
        .commit(session, Epoch::GENESIS, &mut entropy)
        .expect("the first");
    let second = participant
        .commit(session, Epoch::GENESIS, &mut entropy)
        .expect("the second");

    assert_eq!(
        first.serialize().expect("bytes"),
        second.serialize().expect("bytes"),
        "a retry must not draw a second nonce"
    );
    assert_eq!(
        participant.outstanding(),
        1,
        "and must leave no second one open"
    );
}

/// **Repetition, second half:** letting the same session sign twice fails. After the
/// first time the nonce is gone.
#[test]
fn a_repeated_sign_for_one_session_is_refused() {
    let mut entropy = SeededEntropy::new(0x7B_1007);
    let group = group_of_five(&mut entropy);
    let signer = group.signer_over(&[1, 2, 3]);

    let round = signer.open_round(b"once").expect("round 1");
    signer.close_round(&round).expect("round 2");

    let err = signer
        .close_round(&round)
        .expect_err("redeeming the same round a second time must not work");
    assert!(
        matches!(err, ThresholdError::Threshold { .. }),
        "no seat can serve this round any more: {err}"
    );
}

/// A seat that is in two sessions at once uses **two** nonces. That is the normal
/// case: two agent intermediates fall due at the same time.
#[test]
fn two_concurrent_sessions_on_one_seat_use_two_nonces() {
    let mut entropy = SeededEntropy::new(0x7B_1008);
    let group = group_of_five(&mut entropy);
    let seat = group.seat(1);
    let mut participant = Participant::new(
        seat,
        group.share(seat),
        group.public(),
        Epoch::GENESIS,
        Arc::new(PlainCustody),
    )
    .expect("participant");

    let a = participant
        .commit(SessionId::from(1), Epoch::GENESIS, &mut entropy)
        .expect("session A");
    let b = participant
        .commit(SessionId::from(2), Epoch::GENESIS, &mut entropy)
        .expect("session B");

    assert_ne!(
        a.serialize().expect("bytes"),
        b.serialize().expect("bytes"),
        "two sessions, two nonces"
    );
    assert_eq!(participant.outstanding(), 2);
}

/// **Concurrency:** forty threads sign at the same time over the same group. Every
/// signature must apply, and none may equal another -- two equal signatures over
/// different messages would be the symptom of a reused nonce.
#[test]
fn forty_concurrent_signings_share_no_nonce() {
    let mut entropy = SeededEntropy::new(0x7B_1009);
    let group = group_of_five(&mut entropy);
    let signer = Arc::new(group.signer());
    let failures = Arc::new(AtomicUsize::new(0));

    let signatures = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..40u32)
            .map(|index| {
                let signer = Arc::clone(&signer);
                let failures = Arc::clone(&failures);
                scope.spawn(move || {
                    let message = format!("at the same time {index}");
                    let Ok(signature) = signer.sign_with_group(message.as_bytes()) else {
                        failures.fetch_add(1, Ordering::SeqCst);
                        return None;
                    };

                    let peer = ring::signature::UnparsedPublicKey::new(
                        &ring::signature::ED25519,
                        signer.verifying_key(),
                    );
                    peer.verify(message.as_bytes(), &signature)
                        .expect("every signature must apply");

                    Some(signature)
                })
            })
            .collect();

        handles
            .into_iter()
            .filter_map(|handle| handle.join().expect("thread"))
            .collect::<Vec<_>>()
    });

    assert_eq!(failures.load(Ordering::SeqCst), 0, "none may fail");
    assert_eq!(signatures.len(), 40);

    let distinct: BTreeSet<_> = signatures.into_iter().collect();
    assert_eq!(distinct.len(), 40, "no signature may repeat itself");
}

/// And the same message, forty times at once: here the equality of two signatures is
/// no longer chance but the proof of a repeated nonce. Deterministic Ed25519 would
/// give the same thing forty times here -- FROST must not.
#[test]
fn forty_concurrent_signings_of_one_message_stay_distinct() {
    let mut entropy = SeededEntropy::new(0x7B_100A);
    let group = group_of_five(&mut entropy);
    let signer = Arc::new(group.signer());

    let signatures = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..40u32)
            .map(|_| {
                let signer = Arc::clone(&signer);
                scope.spawn(move || signer.sign_with_group(b"the same message"))
            })
            .collect();

        handles
            .into_iter()
            .map(|handle| handle.join().expect("thread").expect("signature"))
            .collect::<Vec<_>>()
    });

    let distinct: BTreeSet<_> = signatures.into_iter().collect();
    assert_eq!(
        distinct.len(),
        40,
        "two equal signatures over the same message mean: the nonce was reused"
    );
}
