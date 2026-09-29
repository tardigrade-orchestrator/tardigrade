//! The replacement of a signer via RTS (ADR-0014 sub-decision 3, point 3).
//!
//! The point of the whole decoupling: if a signer fails permanently, another node
//! takes over **its seat** -- the same identifier, a restored share. The group public
//! key stays, the intermediate from the air-gapped root stays valid, **no ceremony**.
//! Exactly that is what this file checks, and that at the place where it counts: after
//! the replacement the group must sign again, and the signature must apply under the
//! **unchanged** group key.
//!
//! What RTS cannot do stands just as plainly in ADR-0014 and is checked along here: it
//! adds no participant and does not lower the threshold.

use std::collections::BTreeMap;

use tg_identity::threshold::{Seat, SignerLink, repair};

mod support;
use support::{SeededEntropy, group_of_five};

/// **A lost seat's share is restored** -- by t helpers, without the group secret
/// arising in the process.
#[test]
fn a_lost_share_is_restored_by_three_helpers() {
    let mut entropy = SeededEntropy::new(0x7B_2001);
    let group = group_of_five(&mut entropy);
    let lost = group.seat(4);

    let helpers: BTreeMap<Seat, _> = [1, 2, 3]
        .into_iter()
        .map(|number| {
            let seat = group.seat(number);
            (seat, group.share(seat).clone())
        })
        .collect();

    let restored =
        repair::restore_seat(&helpers, lost, group.public(), &mut entropy).expect("restoration");

    assert_eq!(
        restored.serialize().expect("bytes"),
        group.share(lost).serialize().expect("bytes"),
        "the restored share is the same share, not a new one"
    );
}

/// **The second acceptance criterion: the replacement of a signer without a
/// ceremony.**
///
/// The group key stays byte for byte the same -- so the intermediate the air-gapped
/// root once issued on it stays valid too. And the replaced seat signs along again.
#[test]
fn the_group_key_survives_the_replacement_of_a_signer() {
    let mut entropy = SeededEntropy::new(0x7B_2002);
    let group = group_of_five(&mut entropy);
    let lost = group.seat(5);

    let before = group.public().verifying_key().serialize().expect("bytes");

    let helpers: BTreeMap<Seat, _> = [2, 3, 4]
        .into_iter()
        .map(|number| {
            let seat = group.seat(number);
            (seat, group.share(seat).clone())
        })
        .collect();
    let restored =
        repair::restore_seat(&helpers, lost, group.public(), &mut entropy).expect("restoration");

    // The new node on seat 5 signs with two that did not help -- so the share is
    // good in general, not only towards the helpers.
    let signer = group.signer_with(&[1, 2], lost, &restored, &mut entropy);
    let signature = signer
        .sign_with_group(b"after the replacement")
        .expect("the group signs again");

    assert_eq!(
        signer.verifying_key(),
        before.as_slice(),
        "the group key must not change at the replacement"
    );

    let peer =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, signer.verifying_key());
    peer.verify(b"after the replacement", &signature)
        .expect("and the signature applies under the unchanged key");
}

/// Fewer than t helpers can restore nothing. Were it otherwise, the threshold would be
/// none.
#[test]
fn two_helpers_cannot_restore_a_share() {
    let mut entropy = SeededEntropy::new(0x7B_2003);
    let group = group_of_five(&mut entropy);
    let lost = group.seat(4);

    let helpers: BTreeMap<Seat, _> = [1, 2]
        .into_iter()
        .map(|number| {
            let seat = group.seat(number);
            (seat, group.share(seat).clone())
        })
        .collect();

    let err = repair::restore_seat(&helpers, lost, group.public(), &mut entropy)
        .expect_err("two helpers must not suffice");
    assert!(
        err.to_string().contains("threshold"),
        "the message shall name the threshold: {err}"
    );
}

/// A helper that is at the same time the lost one is none. That would be the short
/// circuit with which a seat restored itself.
#[test]
fn the_lost_seat_cannot_help_itself() {
    let mut entropy = SeededEntropy::new(0x7B_2004);
    let group = group_of_five(&mut entropy);
    let lost = group.seat(3);

    let helpers: BTreeMap<Seat, _> = [1, 2, 3]
        .into_iter()
        .map(|number| {
            let seat = group.seat(number);
            (seat, group.share(seat).clone())
        })
        .collect();

    repair::restore_seat(&helpers, lost, group.public(), &mut entropy)
        .expect_err("the lost seat must not stand among its own helpers");
}

/// **RTS adds no seat.** ADR-0014 finding 2: a new node has no share it could add
/// something to. A seat beyond N is therefore no restoration case but a configuration
/// error -- and is refused as such, not offered as a ceremony.
#[test]
fn a_seat_beyond_the_group_cannot_be_repaired_into_existence() {
    let shape = tg_identity::threshold::GroupShape::adr_0014();

    shape
        .seat(6)
        .expect_err("there is no seat 6 -- changing N is a ceremony, no repair case");
}

// --- The take-over itself (ADR-0014, sub-decision 3) ------------------------
//
// The tests above substantiate the **mathematics**: the share comes back, and the
// group key stays the same. What a running participant does at the swap stood until
// here only as an assurance in `adopt_share`'s doc comment -- and phase 7b expressly
// calls the nonce discipline the most dangerous place of this system.

/// **An open session does not survive the share swap.**
///
/// If it stayed standing, round 2 would take a nonce out of the **new** vault for a
/// commitment that was published under the **old** share. The bookkeeping belongs to
/// the share, not to the seat.
#[test]
fn adopting_a_share_drops_the_open_sessions() {
    let mut entropy = SeededEntropy::new(0x7B_2003);
    let group = group_of_five(&mut entropy);
    let seat = group.seat(4);

    let mut participant = tg_identity::threshold::Participant::new(
        seat,
        group.share(seat),
        group.public(),
        tg_identity::threshold::Epoch::GENESIS,
        std::sync::Arc::new(tg_identity::threshold::PlainCustody),
    )
    .expect("participant");

    let session = tg_identity::threshold::SessionId::from(7);
    let _ = participant
        .commit(
            session,
            tg_identity::threshold::Epoch::GENESIS,
            &mut entropy,
        )
        .expect("round 1 under the old share");
    assert_eq!(participant.outstanding(), 1);

    participant
        .adopt_share(
            tg_identity::threshold::Epoch::GENESIS,
            group.share(seat),
            group.public(),
        )
        .expect("take-over");

    assert_eq!(
        participant.outstanding(),
        0,
        "the old share's commitment must not survive the swap"
    );
}

/// **And the same session gets a fresh commitment afterwards, not the old one.**
///
/// That is the sharper half. `commit` is deliberately idempotent -- a network retry
/// must burn no nonce. If the entry survived the swap, the coordinator would get
/// **the same** commitment back while the participant has long held a different share:
/// one commitment, two shares. Exactly out of that an attacker gains two signature
/// shares under one commitment -- the case that gives the share away.
#[test]
fn a_session_gets_a_fresh_commitment_after_the_swap() {
    let mut entropy = SeededEntropy::new(0x7B_2004);
    let group = group_of_five(&mut entropy);
    let seat = group.seat(2);

    let mut participant = tg_identity::threshold::Participant::new(
        seat,
        group.share(seat),
        group.public(),
        tg_identity::threshold::Epoch::GENESIS,
        std::sync::Arc::new(tg_identity::threshold::PlainCustody),
    )
    .expect("participant");

    let session = tg_identity::threshold::SessionId::from(11);
    let before = participant
        .commit(
            session,
            tg_identity::threshold::Epoch::GENESIS,
            &mut entropy,
        )
        .expect("round 1")
        .serialize()
        .expect("bytes");

    // The restored share is byte for byte the same (see above) -- the swap is one all
    // the same, and the bookkeeping starts afresh.
    participant
        .adopt_share(
            tg_identity::threshold::Epoch::GENESIS,
            group.share(seat),
            group.public(),
        )
        .expect("take-over");

    let after = participant
        .commit(
            session,
            tg_identity::threshold::Epoch::GENESIS,
            &mut entropy,
        )
        .expect("round 1, once more")
        .serialize()
        .expect("bytes");

    assert_ne!(
        before, after,
        "after the swap no commitment of the old share may come back"
    );
}

/// **The entropy source's memory survives the share swap.**
///
/// The vault recognizes a source that repeats itself -- "a cloned VM, a restored
/// snapshot, a source before its initialization" (`nonce.rs`). That is a property of
/// the **machine**, not of the share.
///
/// And RTS is precisely the operation at which a machine was set up anew:
/// `restore_seat` delivers **the same** share back byte for byte. If the bookkeeping
/// were thrown away at the swap, the vault would afterwards hand out the same nonce
/// under the same share a second time -- the case that gives the share away
/// (ADR-0014).
#[test]
fn the_memory_of_a_repeating_entropy_source_survives_the_swap() {
    let mut entropy = SeededEntropy::new(0x7B_2005);
    let group = group_of_five(&mut entropy);
    let seat = group.seat(3);

    let mut participant = tg_identity::threshold::Participant::new(
        seat,
        group.share(seat),
        group.public(),
        tg_identity::threshold::Epoch::GENESIS,
        std::sync::Arc::new(tg_identity::threshold::PlainCustody),
    )
    .expect("participant");

    let mut source = SeededEntropy::new(0x0BAD_5EED);
    participant
        .commit(
            tg_identity::threshold::SessionId::from(1),
            tg_identity::threshold::Epoch::GENESIS,
            &mut source,
        )
        .expect("the first commitment");

    participant
        .adopt_share(
            tg_identity::threshold::Epoch::GENESIS,
            group.share(seat),
            group.public(),
        )
        .expect("the take-over after RTS -- the same share");

    // The same source from the start: the cloned machine delivers exactly the same
    // bytes as before the swap.
    let mut cloned = SeededEntropy::new(0x0BAD_5EED);
    let err = participant
        .commit(
            tg_identity::threshold::SessionId::from(2),
            tg_identity::threshold::Epoch::GENESIS,
            &mut cloned,
        )
        .expect_err("the same nonce must not leave the vault after the swap either");

    assert!(
        format!("{err}").contains("entropy source")
            || format!("{err:?}").contains("EntropyRepeated"),
        "the reason must name the source: {err}"
    );
}

/// **Too few sigmas yield a valid wrong share -- and are refused.**
///
/// The finding for whose sake [`repair::restore`] checks against the group key:
/// `repair_share_part3` does **not** count the sigmas. Measured, the result with one
/// instead of three is a `KeyPackage` that can be serialized, is byte for byte **not**
/// the real share, and whose `verifying_share` does not fit the group key.
///
/// Without the check a seat would take it over, write it to the disk (ADR-0107) and be
/// named as the culprit at every signature -- and because it survives a restart, the
/// cause would no longer be findable.
///
/// **The way there goes over the individual steps**, not over `restore_seat`: that
/// checks the number of **helpers** and would not get here at all. In the transport
/// case the receiver calls `restore` with the sigmas that arrive -- and how many those
/// are it does not know beforehand.
#[test]
fn too_few_sigmas_are_refused_not_assembled() {
    let mut entropy = SeededEntropy::new(0x7B_2007);
    let group = group_of_five(&mut entropy);
    let lost = group.seat(5);
    let seats: Vec<Seat> = [1, 2, 3].into_iter().map(|n| group.seat(n)).collect();

    let mut inbox: BTreeMap<Seat, Vec<repair::Delta>> =
        seats.iter().map(|seat| (*seat, Vec::new())).collect();
    for helper in &seats {
        for (to, delta) in
            repair::helper_deltas(&seats, group.share(*helper), lost, &mut entropy).expect("deltas")
        {
            inbox.get_mut(&to).expect("slot").push(delta);
        }
    }
    let sigmas: Vec<repair::Sigma> = inbox
        .values()
        .map(|deltas| repair::combine_deltas(deltas))
        .collect();

    // All three: byte for byte the real share. **The counter-direction**, without
    // which the refusal below says nothing about the number.
    let whole = repair::restore(&sigmas, lost, group.public()).expect("full");
    assert_eq!(
        whole.serialize().expect("bytes"),
        group.share(lost).serialize().expect("bytes")
    );

    // One: refused, and the message names the number.
    let err = repair::restore(&sigmas[..1], lost, group.public())
        .expect_err("one sigma must yield no share");
    let text = format!("{err}");
    assert!(
        text.contains("does not fit the group key") && text.contains('1'),
        "the refusal does not name the reason: {text}"
    );
}

/// **A share for the wrong seat is refused likewise.**
///
/// The same gate, a different error: the sigmas belong to the restoration of seat 5,
/// what is asked for is seat 4's share. `repair_share_part3` takes the identifier as an
/// argument and computes with it -- it does not check that it belongs to the
/// sigmas.
#[test]
fn sigmas_for_another_seat_do_not_assemble() {
    let mut entropy = SeededEntropy::new(0x7B_2008);
    let group = group_of_five(&mut entropy);
    let lost = group.seat(5);
    let seats: Vec<Seat> = [1, 2, 3].into_iter().map(|n| group.seat(n)).collect();

    let mut inbox: BTreeMap<Seat, Vec<repair::Delta>> =
        seats.iter().map(|seat| (*seat, Vec::new())).collect();
    for helper in &seats {
        for (to, delta) in
            repair::helper_deltas(&seats, group.share(*helper), lost, &mut entropy).expect("deltas")
        {
            inbox.get_mut(&to).expect("slot").push(delta);
        }
    }
    let sigmas: Vec<repair::Sigma> = inbox
        .values()
        .map(|deltas| repair::combine_deltas(deltas))
        .collect();

    let err = repair::restore(&sigmas, group.seat(4), group.public())
        .expect_err("sigmas for another seat must yield no share");
    assert!(
        format!("{err}").contains("does not fit the group key"),
        "the refusal does not name the reason: {err}"
    );
}

// --- The distributed sequence (ADR-0108) ------------------------------------

/// The error of a sigma call, **without** `expect_err`.
///
/// A measured reason and no detour: `repair::Sigma` has **no `Debug`** -- `frost`
/// gives it none, and that is right, for `t` sigmas yield the share (ADR-0108,
/// determination 3). `expect_err` would demand one for the Ok side and would thereby
/// bring share material into a panic message; the same line as the four `Debug` bolts
/// in `tg-identity`.
fn sigma_err(result: Result<repair::Sigma, tg_identity::threshold::ThresholdError>) -> String {
    match result {
        Ok(_) => panic!("there should have been no sigma"),
        Err(err) => err.to_string(),
    }
}

/// **The repair runs over the seams, not in one function** (ADR-0108).
///
/// `repair::restore_seat` runs all three steps in **one** process, and that is
/// expressly a property of this test rig: there all the helper shares lie side by
/// side, which is never the case in operation. This witness goes the same way ADR-0108
/// fixes -- every helper over its own [`SignerLink`], the deltas from seat to seat,
/// the sigmas to the lost seat.
///
/// The carrying assurance is the last: the restored share is **byte for byte** the
/// lost one. RTS restores, it produces nothing new.
#[test]
fn a_lost_share_is_restored_over_the_links() {
    let mut entropy = SeededEntropy::new(0x7B_2010);
    let group = group_of_five(&mut entropy);
    let lost = group.seat(4);
    let real = group.share(lost).clone();

    // Three helpers, each with its own link -- and they know each other (ADR-0097:
    // `--signer` names them).
    let helpers = group.wired(&[1, 2, 3]);
    let seats: Vec<Seat> = [1, 2, 3].into_iter().map(|n| group.seat(n)).collect();

    // Steps 1 and 2: every helper produces its deltas and **delivers them itself**.
    // The coordinator sees none of them in the process -- exactly ADR-0108's point:
    // passed-through deltas yield the share.
    for link in &helpers {
        link.repair_deal(lost, &seats).expect("step 1");
    }

    // Step 3: the lost seat fetches the sigmas. Only it may see them.
    let sigmas: Vec<_> = helpers
        .iter()
        .map(|link| link.repair_sigma(lost).expect("sigma"))
        .collect();

    let restored = repair::restore(&sigmas, lost, group.public()).expect("step 3");
    assert_eq!(
        restored.signing_share(),
        real.signing_share(),
        "RTS restores -- the share must be byte for byte the same"
    );
}

/// **A helper that does not join in breaks the run** (ADR-0108, determination 4).
///
/// The counter-check to the witness above: with two sigmas instead of three the
/// restored share is **valid and wrong** -- `repair_share_part3` does not count them
/// (phase 7b). What catches it is the check against the group key, and that it bites
/// here is half the assurance of the distributed sequence.
#[test]
fn two_sigmas_do_not_restore_a_share() {
    let mut entropy = SeededEntropy::new(0x7B_2011);
    let group = group_of_five(&mut entropy);
    let lost = group.seat(5);

    let helpers = group.wired(&[1, 2, 3]);
    let seats: Vec<Seat> = [1, 2, 3].into_iter().map(|n| group.seat(n)).collect();
    for link in &helpers {
        link.repair_deal(lost, &seats).expect("step 1");
    }

    let sigmas: Vec<_> = helpers[..2]
        .iter()
        .map(|link| link.repair_sigma(lost).expect("sigma"))
        .collect();

    let err =
        repair::restore(&sigmas, lost, group.public()).expect_err("two sigmas must yield no share");
    assert!(
        err.to_string().contains("does not fit the group key"),
        "{err}"
    );
}

/// **A sigma without a begun repair is refused.**
///
/// Without this assurance a helper would hand out a sigma from an empty inbox -- and
/// `combine_deltas` on zero deltas is a number that looks like a contribution and is
/// none.
#[test]
fn a_sigma_without_a_started_repair_is_refused() {
    let mut entropy = SeededEntropy::new(0x7B_2012);
    let group = group_of_five(&mut entropy);
    let lost = group.seat(5);
    let helpers = group.wired(&[1, 2, 3]);

    let err = sigma_err(helpers[0].repair_sigma(lost));
    assert!(err.contains("no repair"), "{err}");
}

/// **A second start discards the first** (ADR-0108, determination 4).
///
/// The same doctrine as at the refresh and at the nonce vault: a left-behind state
/// from an aborted run must not block a new one. What is checked is the **effect** --
/// after the second run the second lost seat's share carries.
#[test]
fn a_second_repair_replaces_the_first() {
    let mut entropy = SeededEntropy::new(0x7B_2013);
    let group = group_of_five(&mut entropy);
    let helpers = group.wired(&[1, 2, 3]);
    let seats: Vec<Seat> = [1, 2, 3].into_iter().map(|n| group.seat(n)).collect();

    let first = group.seat(4);
    for link in &helpers {
        link.repair_deal(first, &seats).expect("the first run");
    }

    let second = group.seat(5);
    for link in &helpers {
        link.repair_deal(second, &seats).expect("the second run");
    }

    let sigmas: Vec<_> = helpers
        .iter()
        .map(|link| link.repair_sigma(second).expect("sigma"))
        .collect();
    let restored = repair::restore(&sigmas, second, group.public()).expect("step 3");
    assert_eq!(
        restored.signing_share(),
        group.share(second).signing_share(),
        "the second run must carry"
    );

    // And the first one is gone -- its sigma no longer exists.
    let err = sigma_err(helpers[0].repair_sigma(first));
    assert!(err.contains("no repair"), "{err}");
}

/// **A seat does not restore its own share** -- not with foreign helpers either.
///
/// Whoever has it does not need it. And the situation is reachable in operation: the
/// lost seat **coordinates** (ADR-0108, determination 1), so a mistyped `--helper`
/// with its own address runs up at it itself.
///
/// The helpers here are expressly `2,3,4` and not `1,2,3`: otherwise the bolt of the
/// witness below bites first, and this one would check nothing of its own.
#[test]
fn a_helper_does_not_repair_its_own_seat() {
    let mut entropy = SeededEntropy::new(0x7B_2014);
    let group = group_of_five(&mut entropy);
    let links = group.wired(&[1, 2, 3, 4]);
    let seats: Vec<Seat> = [2, 3, 4].into_iter().map(|n| group.seat(n)).collect();

    let err = links[0]
        .repair_deal(group.seat(1), &seats)
        .expect_err("one's own seat does not repair itself");
    assert!(err.to_string().contains("shall repair itself"), "{err}");
}

/// **And the lost seat does not belong among *foreign* helpers either.**
///
/// The distinguishing case to the witness above, and it is forced by a counter-check:
/// there **two** bolts bite (`lost` among the helpers *and* `lost` is one's own seat),
/// and the counter-check on the first therefore hit nothing. Here the caller is seat 2
/// and the lost one is seat 1 -- only the first bolt can catch it.
///
/// The matter behind it is not formal: a helper that is at the same time carried as
/// lost gets a delta to itself, and `helper_deltas` then divides the share among
/// receivers of whom one is the lost one.
#[test]
fn the_lost_seat_is_not_one_of_the_helpers() {
    let mut entropy = SeededEntropy::new(0x7B_2015);
    let group = group_of_five(&mut entropy);
    let helpers = group.wired(&[1, 2, 3]);
    let seats: Vec<Seat> = [1, 2, 3].into_iter().map(|n| group.seat(n)).collect();

    let err = helpers[1]
        .repair_deal(group.seat(1), &seats)
        .expect_err("a helper must not be the lost seat");
    assert!(err.to_string().contains("among its own helpers"), "{err}");
}
