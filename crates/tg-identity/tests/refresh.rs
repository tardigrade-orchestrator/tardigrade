//! The proactive refresh of the signer shares (ADR-0107).
//!
//! **Tests first** (CLAUDE.md): `tg-identity` is pure logic, and the properties at
//! issue here are all observable without a network and without a disk.
//!
//! The six measurements ADR-0107 rests on stand here as witnesses -- not because they
//! are our rules but because they are statements about a **foreign library**: that the
//! group key survives and that mixed epochs do not sign is the condition under which
//! the decision was taken. If `frost-core` changes, it belongs checked anew and not
//! silently inherited.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use tempfile::{TempDir, tempdir};

use tg_identity::threshold::{
    Epoch, GroupShape, LocalLink, Material, OsEntropy, Participant, PlainCustody, PublicKeyPackage,
    Reached, Seat, SessionId, SignatureShare, SignerLink, SigningCommitments, SigningPackage,
    ThresholdError, ThresholdSigner, dkg, refresh,
};

/// A fresh group: five seats, t = 3 (ADR-0014).
fn fresh() -> (GroupShape, BTreeMap<Seat, Material>) {
    let shape = GroupShape::adr_0014();
    let mut entropy = OsEntropy;
    let done = dkg::ceremony(shape, &mut entropy).expect("the ceremony must carry");
    let held = done
        .into_iter()
        .map(|(seat, share, group)| (seat, Material::held(seat, share, group, Epoch::GENESIS)))
        .collect();
    (shape, held)
}

/// Signs over the **production path**: `ThresholdSigner` over `LocalLink`s.
///
/// A signing helper of its own would be a second way to a group signature -- and then
/// a green witness would say that *that* way carries, not the one `tgd` goes.
fn signs(held: &[(Seat, Material)]) -> Result<Vec<u8>, ThresholdError> {
    let shape = GroupShape::adr_0014();
    let mut groups = BTreeMap::new();
    let mut links: Vec<Arc<dyn SignerLink>> = Vec::new();
    for (seat, material) in held {
        groups.insert(material.epoch(), material.group().clone());
        let custody = Arc::new(PlainCustody);
        let participant = Participant::new(
            *seat,
            material.share(),
            material.group(),
            material.epoch(),
            custody,
        )?;
        links.push(Arc::new(LocalLink::new(participant, Box::new(OsEntropy))));
    }

    ThresholdSigner::over(groups, shape, links)?.sign_with_group(b"a message")
}

#[test]
fn the_group_key_survives_a_refresh() {
    let (shape, before) = fresh();
    let old = before[&shape.seat(1).unwrap()]
        .group()
        .verifying_key()
        .serialize()
        .expect("group key");

    let mut entropy = OsEntropy;
    let after = refresh::ceremony(shape, &before, &mut entropy).expect("the refresh must carry");

    for (seat, material) in &after {
        let now = material
            .group()
            .verifying_key()
            .serialize()
            .expect("group key");
        assert_eq!(
            now,
            old,
            "seat {} has a different group key -- then the intermediate from the \
             root is done for and it *is* a ceremony (ADR-0107 D1)",
            seat.number()
        );
    }

    // The counter-direction: the **shares** are new. Without it a refresh that does
    // nothing would be green likewise -- and a betrayed share would stay valid.
    for (seat, material) in &after {
        assert_ne!(
            material.share().serialize().expect("share"),
            before[seat].share().serialize().expect("share"),
            "seat {} holds the same share as before",
            seat.number()
        );
    }
}

#[test]
fn the_epoch_advances_by_one() {
    let (shape, before) = fresh();
    assert_eq!(before[&shape.seat(1).unwrap()].epoch(), Epoch::GENESIS);

    let mut entropy = OsEntropy;
    let after = refresh::ceremony(shape, &before, &mut entropy).expect("refresh");

    for (seat, material) in &after {
        assert_eq!(
            material.epoch(),
            Epoch::GENESIS.next(),
            "seat {} stands in the wrong epoch",
            seat.number()
        );
    }
}

#[test]
fn a_refreshed_group_still_signs_with_the_threshold() {
    let (shape, before) = fresh();
    let mut entropy = OsEntropy;
    let after = refresh::ceremony(shape, &before, &mut entropy).expect("refresh");

    let three: Vec<_> = after.iter().take(3).map(|(s, m)| (*s, m.clone())).collect();
    let signature = signs(&three).expect("t of n must sign after the refresh");
    assert_eq!(
        signature.len(),
        64,
        "a group signature is 64 bytes (ADR-0014)"
    );
}

#[test]
fn a_half_refreshed_group_signs_in_neither_epoch() {
    let (shape, before) = fresh();
    let mut entropy = OsEntropy;
    let after = refresh::ceremony(shape, &before, &mut entropy).expect("refresh");

    // Two from the new generation, one from the old -- and each holds only its own.
    // In epoch 1 two come together, in epoch 0 one: in neither the threshold.
    let mut mixed: Vec<_> = after.iter().take(2).map(|(s, m)| (*s, m.clone())).collect();
    let straggler = *after.keys().nth(2).expect("the third seat");
    mixed.push((straggler, before[&straggler].clone()));

    let err = signs(&mixed).expect_err("mixed epochs must not sign");
    let text = format!("{err}");

    // **And the refusal is ours, not the aggregation's** (ADR-0107, determination 4):
    // the gate at the epoch catches the case before shares are aggregated. The
    // aggregation would come too late and would accuse the wrong seat -- see the
    // witness beside it.
    assert!(
        text.contains("threshold"),
        "the refusal does not come from the gate at the epoch: {text}"
    );
    assert!(
        !text.contains("Invalid signature share"),
        "the aggregation saw the case -- then determination 4 does not bite: {text}"
    );
}

/// Verifies the underlying FROST library behaviour that justifies checking epochs
/// before aggregation: when three seats all claim the same epoch but their shares
/// actually come from two different generations, aggregation itself fails, and the
/// error message from the library does not identify which seat lied. This is the
/// case the epoch gate is designed to make impossible -- it can only still occur if
/// a seat lies about its own generation, bypassing that gate entirely.
#[test]
fn mixed_shares_under_one_epoch_are_what_the_gate_prevents() {
    let (shape, before) = fresh();
    let mut entropy = OsEntropy;
    let after = refresh::ceremony(shape, &before, &mut entropy).expect("refresh");

    // Three seats name the same epoch and hold shares from **two** -- the case the
    // gate at the epoch makes impossible. It can only still be produced by a seat
    // *lying* about its generation.
    let seats: Vec<Seat> = shape.places().into_iter().take(3).collect();
    let straggler = seats[2];

    let mut groups = BTreeMap::new();
    groups.insert(Epoch::GENESIS, after[&seats[0]].group().clone());

    let links: Vec<Arc<dyn SignerLink>> = seats
        .iter()
        .map(|seat| {
            let held = if *seat == straggler {
                before[seat].share()
            } else {
                after[seat].share()
            };
            let participant = Participant::new(
                *seat,
                held,
                after[&seats[0]].group(),
                Epoch::GENESIS,
                Arc::new(PlainCustody),
            )
            .expect("participant");
            Arc::new(LocalLink::new(participant, Box::new(OsEntropy))) as Arc<dyn SignerLink>
        })
        .collect();

    let signer = ThresholdSigner::over(groups, GroupShape::adr_0014(), links).expect("signer");
    let err = signer
        .sign_with_group(b"a message")
        .expect_err("shares from two generations must yield no valid signature");
    let text = format!("{err}");
    assert!(
        text.contains("Invalid signature share"),
        "the refusal is not the aggregation's: {text}"
    );

    // And it does **not** name the seat: `frost` carries the culprits in the Debug
    // form, its `Display` says only "Invalid signature share". Measured -- and exactly
    // for that reason the coordinator names the epoch itself instead of relying on
    // this message to identify the offending seat.
    assert!(
        !text.contains(&straggler.number().to_string()),
        "if the message names the straggler, determination 4 belongs justified \
         anew: {text}"
    );
}

/// Verifies that a refresh ceremony with only three of five seats present is
/// refused, and that the error message names the missing seats rather than just
/// reporting failure.
#[test]
fn a_refresh_without_every_seat_is_refused() {
    let (shape, before) = fresh();
    let mut partial = before.clone();
    partial.remove(&shape.seat(4).unwrap());
    partial.remove(&shape.seat(5).unwrap());

    let mut entropy = OsEntropy;
    let err = refresh::ceremony(shape, &partial, &mut entropy)
        .expect_err("a refresh with three of five seats must be refused");

    // The reason belongs in the message: with a dealer-based scheme the same call
    // would be **accepted** and would shrink the group from five to three, silently
    // narrowing who can sign. Whoever reads only "failed" here searches wrongly --
    // the message must say which seats are missing.
    let text = format!("{err}");
    assert!(
        text.contains('4') && text.contains('5'),
        "the refusal does not name the missing seats: {text}"
    );
}

/// Verifies that **resharing adds no seat**: a seat the existing group does not know
/// does not join a refresh, even if it carries otherwise-valid material.
///
/// A same-named witness exists in `threshold.rs` too, but that one is about the
/// group's fixed shape of five seats, a different question from the one here.
#[test]
fn a_seat_outside_the_group_is_refused() {
    let (shape, before) = fresh();
    let mut too_many = before.clone();
    // A seat the group does not know does not join: resharing removes participants,
    // it never adds one.
    let (_, other) = fresh();
    let stranger = *other.keys().next().expect("seat");
    too_many.insert(stranger, other[&stranger].clone());

    // It is a *known* seat with **foreign material** -- the case counting the seats
    // does not catch.
    let mut entropy = OsEntropy;
    let err = refresh::ceremony(shape, &too_many, &mut entropy)
        .expect_err("foreign material must carry no refresh");
    assert!(
        format!("{err}").contains("group"),
        "the refusal does not name the group: {err}"
    );
}

/// Verifies that key material written before epoched storage existed -- under the
/// unsuffixed `share`/`group` file names -- is still read back correctly as the
/// genesis epoch, without requiring any migration step.
#[test]
fn material_from_before_this_adr_is_the_genesis_epoch() {
    let dir = tempfile::tempdir().expect("temp");
    let (shape, held) = fresh();
    let mine = &held[&shape.seat(1).unwrap()];

    Material::save(
        dir.path(),
        mine.share(),
        mine.group(),
        Epoch::GENESIS,
        &PlainCustody,
    )
    .expect("file");

    // Pre-existing groups must keep working without a migration step: material
    // written before epoched storage existed lies under `share`/`group` **without**
    // a suffix and must carry on without a single action.
    //
    // What is compared is the **spelled-out** name and not `share_path(dir)` -- that is
    // defined as `share_path_at(dir, GENESIS)`, so it would move along, and the witness
    // would be a tautology. (Measured: with the derived path the counter-check stayed
    // green.)
    let signing = dir.path().join("signing");
    for name in ["share", "group"] {
        assert!(
            signing.join(name).exists(),
            "'{name}' is missing -- the generation after the DKG carries a suffix, \
             and then every existing group needs a migration"
        );
    }
    assert_eq!(
        Material::load(dir.path(), &PlainCustody)
            .expect("read")
            .epoch(),
        Epoch::GENESIS
    );
}

/// Verifies that when two generations of material are on disk at once, the default
/// load reads the highest (newest) epoch, while the older epoch stays individually
/// readable as a fallback.
#[test]
fn the_highest_epoch_is_the_one_that_is_read() {
    let dir = tempfile::tempdir().expect("temp");
    let (shape, held) = fresh();
    let seat = shape.seat(1).unwrap();
    let mine = &held[&seat];

    let mut entropy = OsEntropy;
    let after = refresh::ceremony(shape, &held, &mut entropy).expect("refresh");
    let next = &after[&seat];

    Material::save(
        dir.path(),
        mine.share(),
        mine.group(),
        mine.epoch(),
        &PlainCustody,
    )
    .expect("the old one");
    Material::save(
        dir.path(),
        next.share(),
        next.group(),
        next.epoch(),
        &PlainCustody,
    )
    .expect("the new one");

    // **Both** lie there: a seat holds the active and the new generation at once,
    // otherwise every refresh would open a window in which the group cannot sign.
    assert_eq!(
        tg_identity::threshold::epochs(dir.path()).expect("generations"),
        vec![Epoch::GENESIS, Epoch::GENESIS.next()]
    );
    assert_eq!(
        Material::load(dir.path(), &PlainCustody)
            .expect("read")
            .epoch(),
        Epoch::GENESIS.next(),
        "what is read is the highest generation"
    );

    // And the old one is still individually readable -- the fallback path a caller
    // uses when it specifically needs the earlier generation.
    assert_eq!(
        Material::load_epoch(dir.path(), Epoch::GENESIS, &PlainCustody)
            .expect("read")
            .epoch(),
        Epoch::GENESIS
    );
}

/// Verifies that a generation left with a share file but no matching group-key file
/// (as if a write had been interrupted between the two) does not count as a present
/// epoch at all.
#[test]
fn half_a_version_is_no_version() {
    let dir = tempfile::tempdir().expect("temp");
    let (shape, held) = fresh();
    let mine = &held[&shape.seat(1).unwrap()];
    let next = Epoch::GENESIS.next();

    Material::save(
        dir.path(),
        mine.share(),
        mine.group(),
        Epoch::GENESIS,
        &PlainCustody,
    )
    .expect("file");
    Material::save(dir.path(), mine.share(), mine.group(), next, &PlainCustody).expect("file");
    // A refresh that aborts between the two writes.
    std::fs::remove_file(tg_identity::threshold::group_path_at(dir.path(), next)).expect("remove");

    assert_eq!(
        tg_identity::threshold::epochs(dir.path()).expect("generations"),
        vec![Epoch::GENESIS],
        "a generation without a group key is one in which this seat cannot sign \
         -- it must not count as present"
    );
}

/// Builds a `ThresholdSigner` over the given seats, staging **all** the generations
/// each one holds (not just the newest) so the coordinator can fall back to
/// whichever epoch actually reaches the threshold.
///
/// # Panics
///
/// Panics if any seat's version list is empty, or if a participant or the signer
/// cannot be constructed from the given material.
fn signer_over(held: &[(Seat, Vec<Material>)]) -> ThresholdSigner {
    let mut groups = BTreeMap::new();
    let mut links: Vec<Arc<dyn SignerLink>> = Vec::new();

    for (seat, versions) in held {
        let newest = versions.last().expect("at least one generation");
        let mut participant = Participant::new(
            *seat,
            newest.share(),
            newest.group(),
            newest.epoch(),
            Arc::new(PlainCustody),
        )
        .expect("participant");
        for older in &versions[..versions.len() - 1] {
            participant
                .stage_share(older.epoch(), older.share(), older.group())
                .expect("lay beside");
        }
        for version in versions {
            groups.insert(version.epoch(), version.group().clone());
        }
        links.push(Arc::new(LocalLink::new(participant, Box::new(OsEntropy))));
    }

    ThresholdSigner::over(groups, GroupShape::adr_0014(), links).expect("signer")
}

/// Verifies that asking a participant to commit for an epoch it does not hold fails
/// with our own error naming the seat and the epoch, rather than surfacing later as
/// an opaque aggregation failure.
#[test]
fn a_seat_that_lacks_the_epoch_says_so() {
    let (shape, before) = fresh();
    let seat = shape.seat(1).unwrap();
    let mut participant = Participant::new(
        seat,
        before[&seat].share(),
        before[&seat].group(),
        Epoch::GENESIS,
        Arc::new(PlainCustody),
    )
    .expect("participant");
    let mut entropy = OsEntropy;

    // One's own generation: there is a commitment.
    participant
        .commit(1.into(), Epoch::GENESIS, &mut entropy)
        .expect("the held generation must carry");

    // One it does not hold: this must be **our** refusal, not an
    // `InvalidSignatureShare` surfacing later during aggregation.
    let err = participant
        .commit(2.into(), Epoch::GENESIS.next(), &mut entropy)
        .expect_err("a generation not held must yield no commitment");
    let text = format!("{err}");
    assert!(
        text.contains('1') && text.contains("epoch"),
        "the refusal names neither the seat nor the generation: {text}"
    );
}

/// Verifies that a session identifier is bound to one epoch: committing under the
/// same session for a different epoch is refused (rather than silently handing out
/// a second nonce for one commitment slot), while repeating the same session and
/// epoch is idempotent and returns the same commitment.
#[test]
fn the_same_session_may_not_change_its_epoch() {
    let (shape, before) = fresh();
    let seat = shape.seat(1).unwrap();
    let mut entropy = OsEntropy;
    let after = refresh::ceremony(shape, &before, &mut entropy).expect("refresh");

    let mut participant = Participant::new(
        seat,
        after[&seat].share(),
        after[&seat].group(),
        after[&seat].epoch(),
        Arc::new(PlainCustody),
    )
    .expect("participant");
    participant
        .stage_share(Epoch::GENESIS, before[&seat].share(), before[&seat].group())
        .expect("lay beside");

    let session = tg_identity::threshold::SessionId::from(7);
    participant
        .commit(session, Epoch::GENESIS, &mut entropy)
        .expect("the first");

    // The case `SessionId` describes: two coordinators name the same number. Without
    // this check, the second call would silently get handed the first's commitment --
    // with different epochs that would mean **one commitment covering two shares**,
    // exactly the situation in which a nonce collision costs the share.
    let err = participant
        .commit(session, Epoch::GENESIS.next(), &mut entropy)
        .expect_err("the same session in two generations must yield no commitment");
    assert!(
        format!("{err}").contains("session 7"),
        "the refusal does not name the session: {err}"
    );

    // And the counter-direction: **the same** generation is a repetition and gets the
    // same commitment back -- without that idempotency a network retry would produce
    // a second nonce instead of returning the one already committed.
    participant
        .commit(session, Epoch::GENESIS, &mut entropy)
        .expect("the same generation is idempotent");
}

/// Verifies that when a refresh has only partially propagated, the coordinator falls
/// back to the epoch in which enough seats agree to reach the signing threshold.
#[test]
fn the_coordinator_falls_back_to_the_epoch_that_reaches_the_threshold() {
    let (shape, before) = fresh();
    let mut entropy = OsEntropy;
    let after = refresh::ceremony(shape, &before, &mut entropy).expect("refresh");

    // A half-run refresh: **two** seats have the new generation, three do not. In
    // epoch 1 no `t = 3` come together, in epoch 0 all five -- and the coordinator
    // must fall back to the epoch that still reaches the threshold.
    let mut held: Vec<(Seat, Vec<Material>)> = Vec::new();
    for (index, seat) in shape.places().into_iter().enumerate() {
        let mut versions = vec![before[&seat].clone()];
        if index < 2 {
            versions.push(after[&seat].clone());
        }
        held.push((seat, versions));
    }

    let signer = signer_over(&held);
    let round = signer
        .open_round(b"a message")
        .expect("in one generation the threshold must stand");
    assert_eq!(
        round.epoch(),
        Epoch::GENESIS,
        "the coordinator did not fall back on the generation in which the \
         threshold stands"
    );

    let signature = signer.close_round(&round).expect("the round must carry");
    assert_eq!(signature.len(), 64);
}

/// Verifies the counter-direction to the fallback test above: once every seat holds
/// the new epoch, the coordinator uses that epoch rather than always preferring the
/// old generation (which would make a refresh have no observable effect).
#[test]
fn once_every_seat_has_the_new_epoch_it_is_the_one_that_is_used() {
    let (shape, before) = fresh();
    let mut entropy = OsEntropy;
    let after = refresh::ceremony(shape, &before, &mut entropy).expect("refresh");

    let held: Vec<(Seat, Vec<Material>)> = shape
        .places()
        .into_iter()
        .map(|seat| (seat, vec![before[&seat].clone(), after[&seat].clone()]))
        .collect();

    // The counter-direction to the fallback: without it a coordinator that **always**
    // takes the old generation would be green likewise -- and then the refresh would be
    // without effect.
    let signer = signer_over(&held);
    let round = signer.open_round(b"a message").expect("round");
    assert_eq!(
        round.epoch(),
        Epoch::GENESIS.next(),
        "the coordinator does not take the highest generation"
    );
    assert_eq!(signer.close_round(&round).expect("signature").len(), 64);
}

/// Verifies that a `ThresholdSigner` refuses to build when the epoch-to-group-key
/// map contains two different verifying keys, since two distinct verifying keys
/// mean two distinct signing groups sharing one signer would be nonsensical.
#[test]
fn two_groups_are_not_one_signer() {
    let (shape, mine) = fresh();
    let (_, other) = fresh();
    let seat = shape.seat(1).unwrap();

    let mut groups = BTreeMap::new();
    groups.insert(Epoch::GENESIS, mine[&seat].group().clone());
    groups.insert(Epoch::GENESIS.next(), other[&seat].group().clone());

    let links: Vec<Arc<dyn SignerLink>> = shape
        .places()
        .into_iter()
        .map(|seat| {
            let participant = Participant::new(
                seat,
                mine[&seat].share(),
                mine[&seat].group(),
                Epoch::GENESIS,
                Arc::new(PlainCustody),
            )
            .expect("participant");
            Arc::new(LocalLink::new(participant, Box::new(OsEntropy))) as Arc<dyn SignerLink>
        })
        .collect();

    let err = ThresholdSigner::over(groups, GroupShape::adr_0014(), links)
        .expect_err("two verifying keys are two groups");
    assert!(
        format!("{err}").contains("two groups"),
        "the refusal does not name the reason: {err}"
    );
}

/// Builds a `ThresholdSigner` over the given seats' material, with every seat's
/// `LocalLink` wired to the other four as peers, since round 2 of the refresh
/// protocol requires messages to travel **from seat to seat**.
///
/// In production the peers are `GrpcLink`s talking over the signer port; here they
/// are the other four `LocalLink`s directly. That forms a reference cycle, which is
/// accepted in this test rig because the process ends with the test.
///
/// # Panics
///
/// Panics if a participant or the signer cannot be constructed from the given
/// material.
fn wired(held: &BTreeMap<Seat, Material>) -> ThresholdSigner {
    let shape = GroupShape::adr_0014();
    let mut seats: BTreeMap<Seat, Arc<LocalLink>> = BTreeMap::new();
    let mut groups = BTreeMap::new();

    for (seat, material) in held {
        groups.insert(material.epoch(), material.group().clone());
        let participant = Participant::new(
            *seat,
            material.share(),
            material.group(),
            material.epoch(),
            Arc::new(PlainCustody),
        )
        .expect("participant");
        seats.insert(
            *seat,
            Arc::new(LocalLink::new(participant, Box::new(OsEntropy))),
        );
    }

    for (seat, link) in &seats {
        let peers: Vec<Arc<dyn SignerLink>> = seats
            .iter()
            .filter(|&(other, _)| other != seat)
            .map(|(_, other)| Arc::clone(other) as Arc<dyn SignerLink>)
            .collect();
        link.attach_peers(peers);
    }

    let links: Vec<Arc<dyn SignerLink>> = seats
        .into_values()
        .map(|link| link as Arc<dyn SignerLink>)
        .collect();

    ThresholdSigner::over(groups, shape, links).expect("signer")
}

/// Verifies an end-to-end refresh driven by the coordinator over all five wired
/// seats: the group signs before the refresh, advances to the next epoch, and
/// keeps signing afterwards with the same group verifying key.
#[test]
fn the_coordinator_drives_a_refresh_over_all_five_seats() {
    let (_, before) = fresh();
    let signer = wired(&before);

    // Beforehand: the group signs in epoch 0.
    let first = signer.open_round(b"beforehand").expect("round");
    assert_eq!(first.epoch(), Epoch::GENESIS);
    let before_key = signer.verifying_key().to_vec();
    signer.close_round(&first).expect("signature");

    let reached = signer.refresh().expect("the refresh must carry");
    assert_eq!(reached, Epoch::GENESIS.next());

    // Afterwards: **the new generation**, and the group key is the same -- if it
    // were not, anything anchored to that verifying key from before this refresh
    // would stop being valid.
    let second = signer.open_round(b"afterwards").expect("round");
    assert_eq!(
        second.epoch(),
        Epoch::GENESIS.next(),
        "after the refresh the group does not run in the new generation"
    );
    let signature = signer.close_round(&second).expect("signature");
    assert_eq!(signature.len(), 64);
    assert_eq!(
        signer.verifying_key(),
        before_key.as_slice(),
        "the group key has changed"
    );
}

/// Verifies that a `LocalLink` with no peers attached cannot complete round 2 of a
/// refresh, and that the error message points the operator at the `--signer` wiring
/// rather than making them search at the refresh call itself.
#[test]
fn a_seat_without_peers_cannot_deal() {
    let (shape, before) = fresh();
    let seat = shape.seat(1).unwrap();
    let material = &before[&seat];
    let participant = Participant::new(
        seat,
        material.share(),
        material.group(),
        material.epoch(),
        Arc::new(PlainCustody),
    )
    .expect("participant");
    let link = LocalLink::new(participant, Box::new(OsEntropy));

    link.refresh_start(Epoch::GENESIS.next()).expect("round 1");

    // Without the others there is no round 2 -- and the message names the reason so
    // that an operator does not search at the refresh call but at how `--signer`
    // wires up the peers.
    //
    // The bindings of the other four are **real**: with an empty inbox `round2` would
    // fail already, and the witness would say nothing about the peers.
    let mut others = BTreeMap::new();
    for other in shape.places().into_iter().filter(|place| *place != seat) {
        let (_, broadcast) =
            refresh::start(other, shape, &mut OsEntropy).expect("the other's binding");
        others.insert(other, broadcast);
    }
    let err = link
        .refresh_deal(Epoch::GENESIS.next(), &others)
        .expect_err("without peers there must be no round 2");
    assert!(
        format!("{err}").contains("--signer"),
        "the refusal does not name the reason: {err}"
    );
}

/// Verifies that a signer missing one seat can still sign (it has four of five, more
/// than the threshold) but cannot refresh (a refresh needs every seat), and that the
/// refusal names the reason rather than reading like a network failure -- and that
/// the group's epoch stays unchanged afterwards.
#[test]
fn a_refresh_that_a_seat_refuses_changes_nothing() {
    let (shape, before) = fresh();
    let mut short = before.clone();
    short.remove(&shape.seat(5).unwrap());

    // A signer without a link to seat 5: it still has **four**, so more than the
    // threshold -- signing works, a refresh does not.
    let signer = wired(&short);
    signer.open_round(b"m").expect("signing works with four");

    let err = signer
        .refresh()
        .expect_err("a refresh without all the seats must abort");
    let text = format!("{err}");
    assert!(
        text.contains('5') && text.contains("shrunk"),
        "the refusal does not name the reason: {text}"
    );

    // What is demanded is the **reason** and not just the number: a build-up without
    // this pre-check would say "seat 5 did not answer" -- an operator reads that as a
    // network problem and searches at the port, while the actual requirement is that
    // the group must be complete for a refresh to run at all.
    //
    // And the group stands unchanged.
    let round = signer.open_round(b"afterwards").expect("round");
    assert_eq!(round.epoch(), Epoch::GENESIS);
    assert_eq!(signer.close_round(&round).expect("signature").len(), 64);
}

/// Verifies that if a directed round-2 package is filed under the wrong sender's
/// slot (as if one seat had submitted in another's name), round 3's cryptographic
/// check against the sender's round-1 binding catches it and refuses.
#[test]
fn a_directed_package_filed_under_the_wrong_seat_fails_in_round_three() {
    let shape = GroupShape::adr_0014();
    let mut entropy = OsEntropy;

    // The assurance from `RefreshTakeRequest::from`: the setting is a
    // self-declaration, and the **crypto** catches it. Round 3 checks every directed
    // package against its sender's binding from round 1.
    let mut started = BTreeMap::new();
    let mut broadcasts = BTreeMap::new();
    for seat in shape.places() {
        let (state, broadcast) = refresh::start(seat, shape, &mut entropy).expect("round 1");
        started.insert(seat, state);
        broadcasts.insert(seat, broadcast);
    }

    let mut exchanged = BTreeMap::new();
    let mut inbox: BTreeMap<Seat, BTreeMap<Seat, refresh::Directed>> = shape
        .places()
        .into_iter()
        .map(|seat| (seat, BTreeMap::new()))
        .collect();
    for (seat, state) in started {
        let others: BTreeMap<Seat, refresh::Broadcast> = broadcasts
            .iter()
            .filter(|&(other, _)| *other != seat)
            .map(|(other, package)| (*other, package.clone()))
            .collect();
        let (state, outgoing) = state.round2(&others).expect("round 2");
        exchanged.insert(seat, state);
        for (to, message) in outgoing {
            if let Some(box_) = inbox.get_mut(&to) {
                box_.insert(seat, message);
            }
        }
    }

    // Seat 1 files the packages of 2 and 3 swapped -- as if 2 had submitted in 3's
    // name.
    let (_, held) = fresh();
    let mine = shape.seat(1).unwrap();
    let two = shape.seat(2).unwrap();
    let three = shape.seat(3).unwrap();
    let mut swapped = inbox.remove(&mine).expect("inbox");
    let from_two = swapped.remove(&two).expect("of 2");
    let from_three = swapped.remove(&three).expect("of 3");
    swapped.insert(two, from_three);
    swapped.insert(three, from_two);

    let state = exchanged.remove(&mine).expect("state");
    let err = state
        .finish(&held[&mine], &swapped)
        .expect_err("a package in the wrong slot must not carry round 3");
    assert!(
        format!("{err}").contains("refresh round 3"),
        "the refusal does not come from round 3: {err}"
    );
}

/// A seat that names a **foreign** group key in round 3.
///
/// The rounds really run through -- the `LocalLink`s are directly connected over
/// `attach_peers`, so round 2 goes past this double. What is lied about is only the
/// answer to the **coordinator**.
#[derive(Debug)]
struct LyingLink {
    inner: Arc<LocalLink>,
    group: PublicKeyPackage,
}

impl SignerLink for LyingLink {
    /// Returns the seat this link stands in for, delegating to the wrapped link.
    fn seat(&self) -> Seat {
        self.inner.seat()
    }

    /// Produces a signing commitment for the given session and epoch, delegating to
    /// the wrapped link unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error under whatever conditions the wrapped link itself refuses to
    /// commit.
    fn commit(
        &self,
        session: SessionId,
        epoch: Epoch,
    ) -> Result<SigningCommitments, ThresholdError> {
        self.inner.commit(session, epoch)
    }

    /// Produces a signature share for the given signing package, delegating to the
    /// wrapped link unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error under whatever conditions the wrapped link itself refuses to
    /// sign.
    fn sign(
        &self,
        session: SessionId,
        package: &SigningPackage,
    ) -> Result<SignatureShare, ThresholdError> {
        self.inner.sign(session, package)
    }

    /// Abandons the given signing session, delegating to the wrapped link
    /// unchanged.
    fn abandon(&self, session: SessionId) {
        self.inner.abandon(session);
    }

    /// Starts round 1 of a refresh for the given epoch, delegating to the wrapped
    /// link unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error under whatever conditions the wrapped link itself refuses
    /// to start.
    fn refresh_start(&self, epoch: Epoch) -> Result<refresh::Broadcast, ThresholdError> {
        self.inner.refresh_start(epoch)
    }

    /// Deals round 2 of a refresh from the given broadcasts, delegating to the
    /// wrapped link unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error under whatever conditions the wrapped link itself refuses
    /// to deal.
    fn refresh_deal(
        &self,
        epoch: Epoch,
        broadcasts: &BTreeMap<Seat, refresh::Broadcast>,
    ) -> Result<(), ThresholdError> {
        self.inner.refresh_deal(epoch, broadcasts)
    }

    /// Takes a round-3 directed package from another seat, delegating to the
    /// wrapped link unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error under whatever conditions the wrapped link itself refuses
    /// to take the package.
    fn refresh_take(
        &self,
        epoch: Epoch,
        from: Seat,
        directed: &refresh::Directed,
    ) -> Result<(), ThresholdError> {
        self.inner.refresh_take(epoch, from, directed)
    }

    /// Finishes the refresh for the given epoch, then substitutes the configured
    /// foreign group key into the result -- this is where the lie about the group
    /// key reaches the coordinator, even though the underlying rounds ran honestly.
    ///
    /// # Errors
    ///
    /// Returns an error if the wrapped link's own `refresh_finish` fails.
    fn refresh_finish(&self, epoch: Epoch) -> Result<Reached, ThresholdError> {
        let reached = self.inner.refresh_finish(epoch)?;

        Ok(Reached {
            group: self.group.clone(),
            ..reached
        })
    }

    /// Retires an old generation after a refresh, delegating to the wrapped link
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error under whatever conditions the wrapped link itself refuses
    /// to retire.
    fn refresh_retire(&self, epoch: Epoch) -> Result<(), ThresholdError> {
        self.inner.refresh_retire(epoch)
    }

    /// Abandons an in-progress refresh for the given epoch, delegating to the
    /// wrapped link unchanged.
    fn refresh_abandon(&self, epoch: Epoch) {
        self.inner.refresh_abandon(epoch);
    }

    /// Refuses to deal a repair share: this test double never plays the repair
    /// protocol, so any attempt reports the target seat as unreachable.
    fn repair_deal(&self, lost: Seat, _helpers: &[Seat]) -> Result<(), ThresholdError> {
        Err(ThresholdError::Unreachable { seat: lost })
    }

    /// Refuses to take a repair delta: this test double never plays the repair
    /// protocol, so any attempt reports the target seat as unreachable.
    fn repair_take(
        &self,
        lost: Seat,
        _from: Seat,
        _delta: &tg_identity::threshold::repair::Delta,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::Unreachable { seat: lost })
    }

    /// Refuses to produce a repair sigma: this test double never plays the repair
    /// protocol, so any attempt reports the target seat as unreachable.
    fn repair_sigma(
        &self,
        lost: Seat,
    ) -> Result<tg_identity::threshold::repair::Sigma, ThresholdError> {
        Err(ThresholdError::Unreachable { seat: lost })
    }

    /// Does nothing: this test double never plays the repair protocol, so there is
    /// no repair attempt to abandon.
    fn repair_abandon(&self, _lost: Seat) {}
}

/// A seat that is entered and **does not answer**.
///
/// The situation the manual assures the operator and that no witness had: `refresh`'s
/// pre-check checks whether a link is **entered** -- a seat that is entered and stays
/// silent falls only in **round 1**. Precisely then the run has already begun, and
/// that the group stays unchanged hangs on the abort path and not on the pre-check.
///
/// Silence happens only in the refresh rounds: `commit`/`sign` get through so that the
/// witness can afterwards show that the group goes on signing.
#[derive(Debug)]
struct SilentLink {
    inner: Arc<LocalLink>,
    /// How often the abort reached this seat.
    abandoned: std::sync::atomic::AtomicUsize,
    /// Whether it is still silent.
    ///
    /// Switchable, so that the second attempt goes over **the same** links: only so
    /// does it say something about no begun run staying behind. A freshly wired signer
    /// would have new `LocalLink`s and could not answer the question at all.
    quiet: std::sync::atomic::AtomicBool,
}

impl SilentLink {
    /// From now on it answers.
    fn speak(&self) {
        self.quiet
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// The error while it stays silent.
    fn silence(&self) -> Option<ThresholdError> {
        self.quiet
            .load(std::sync::atomic::Ordering::Relaxed)
            .then(|| ThresholdError::Unreachable {
                seat: self.inner.seat(),
            })
    }
}

impl SignerLink for SilentLink {
    /// Returns the seat this link stands in for, delegating to the wrapped link.
    fn seat(&self) -> Seat {
        self.inner.seat()
    }

    /// Produces a signing commitment for the given session and epoch, delegating to
    /// the wrapped link unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error under whatever conditions the wrapped link itself refuses to
    /// commit.
    fn commit(
        &self,
        session: SessionId,
        epoch: Epoch,
    ) -> Result<SigningCommitments, ThresholdError> {
        self.inner.commit(session, epoch)
    }

    /// Produces a signature share for the given signing package, delegating to the
    /// wrapped link unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error under whatever conditions the wrapped link itself refuses to
    /// sign.
    fn sign(
        &self,
        session: SessionId,
        package: &SigningPackage,
    ) -> Result<SignatureShare, ThresholdError> {
        self.inner.sign(session, package)
    }

    /// Abandons the given signing session, delegating to the wrapped link
    /// unchanged.
    fn abandon(&self, session: SessionId) {
        self.inner.abandon(session);
    }

    /// Starts round 1 of a refresh, unless still silent, in which case it reports
    /// the wrapped seat as unreachable instead of delegating.
    ///
    /// # Errors
    ///
    /// Returns an "unreachable" error while silent, or whatever error the wrapped
    /// link itself produces otherwise.
    fn refresh_start(&self, epoch: Epoch) -> Result<refresh::Broadcast, ThresholdError> {
        match self.silence() {
            Some(err) => Err(err),
            None => self.inner.refresh_start(epoch),
        }
    }

    /// Deals round 2 of a refresh, unless still silent, in which case it reports the
    /// wrapped seat as unreachable instead of delegating.
    ///
    /// # Errors
    ///
    /// Returns an "unreachable" error while silent, or whatever error the wrapped
    /// link itself produces otherwise.
    fn refresh_deal(
        &self,
        epoch: Epoch,
        broadcasts: &BTreeMap<Seat, refresh::Broadcast>,
    ) -> Result<(), ThresholdError> {
        match self.silence() {
            Some(err) => Err(err),
            None => self.inner.refresh_deal(epoch, broadcasts),
        }
    }

    /// Takes a round-3 directed package, unless still silent, in which case it
    /// reports the wrapped seat as unreachable instead of delegating.
    ///
    /// # Errors
    ///
    /// Returns an "unreachable" error while silent, or whatever error the wrapped
    /// link itself produces otherwise.
    fn refresh_take(
        &self,
        epoch: Epoch,
        from: Seat,
        directed: &refresh::Directed,
    ) -> Result<(), ThresholdError> {
        match self.silence() {
            Some(err) => Err(err),
            None => self.inner.refresh_take(epoch, from, directed),
        }
    }

    /// Finishes the refresh, unless still silent, in which case it reports the
    /// wrapped seat as unreachable instead of delegating.
    ///
    /// # Errors
    ///
    /// Returns an "unreachable" error while silent, or whatever error the wrapped
    /// link itself produces otherwise.
    fn refresh_finish(&self, epoch: Epoch) -> Result<Reached, ThresholdError> {
        match self.silence() {
            Some(err) => Err(err),
            None => self.inner.refresh_finish(epoch),
        }
    }

    /// Retires an old generation, unless still silent, in which case it reports the
    /// wrapped seat as unreachable instead of delegating.
    ///
    /// # Errors
    ///
    /// Returns an "unreachable" error while silent, or whatever error the wrapped
    /// link itself produces otherwise.
    fn refresh_retire(&self, epoch: Epoch) -> Result<(), ThresholdError> {
        match self.silence() {
            Some(err) => Err(err),
            None => self.inner.refresh_retire(epoch),
        }
    }

    /// Records that an abort reached this seat, then delegates the abandon to the
    /// wrapped link -- this runs regardless of silence, so a witness can confirm
    /// the abort reaches even the seat that caused it.
    fn refresh_abandon(&self, epoch: Epoch) {
        self.abandoned
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.refresh_abandon(epoch);
    }

    /// Refuses to deal a repair share: this test double never plays the repair
    /// protocol, so any attempt reports the target seat as unreachable.
    fn repair_deal(&self, lost: Seat, _helpers: &[Seat]) -> Result<(), ThresholdError> {
        Err(ThresholdError::Unreachable { seat: lost })
    }

    /// Refuses to take a repair delta: this test double never plays the repair
    /// protocol, so any attempt reports the target seat as unreachable.
    fn repair_take(
        &self,
        lost: Seat,
        _from: Seat,
        _delta: &tg_identity::threshold::repair::Delta,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::Unreachable { seat: lost })
    }

    /// Refuses to produce a repair sigma: this test double never plays the repair
    /// protocol, so any attempt reports the target seat as unreachable.
    fn repair_sigma(
        &self,
        lost: Seat,
    ) -> Result<tg_identity::threshold::repair::Sigma, ThresholdError> {
        Err(ThresholdError::Unreachable { seat: lost })
    }

    /// Does nothing: this test double never plays the repair protocol, so there is
    /// no repair attempt to abandon.
    fn repair_abandon(&self, _lost: Seat) {}
}

/// As [`wired`], but the named seat stays silent in the refresh rounds.
///
/// Returns the signer and the silent link -- the witness needs both: the one to
/// attempt the refresh, the other to see that the abort reached it.
fn wired_with_a_silent_seat(
    held: &BTreeMap<Seat, Material>,
    silent: u16,
) -> (ThresholdSigner, Arc<SilentLink>) {
    let shape = GroupShape::adr_0014();
    let mut seats: BTreeMap<Seat, Arc<LocalLink>> = BTreeMap::new();
    let mut groups = BTreeMap::new();

    for (seat, material) in held {
        groups.insert(material.epoch(), material.group().clone());
        let participant = Participant::new(
            *seat,
            material.share(),
            material.group(),
            material.epoch(),
            Arc::new(PlainCustody),
        )
        .expect("participant");
        seats.insert(
            *seat,
            Arc::new(LocalLink::new(participant, Box::new(OsEntropy))),
        );
    }

    for (seat, link) in &seats {
        let peers: Vec<Arc<dyn SignerLink>> = seats
            .iter()
            .filter(|&(other, _)| other != seat)
            .map(|(_, other)| Arc::clone(other) as Arc<dyn SignerLink>)
            .collect();
        link.attach_peers(peers);
    }

    let mut quiet = None;
    let links: Vec<Arc<dyn SignerLink>> = seats
        .into_iter()
        .map(|(seat, link)| {
            if seat.number() == silent {
                let wrapped = Arc::new(SilentLink {
                    inner: link,
                    abandoned: std::sync::atomic::AtomicUsize::new(0),
                    quiet: std::sync::atomic::AtomicBool::new(true),
                });
                quiet = Some(Arc::clone(&wrapped));
                wrapped as Arc<dyn SignerLink>
            } else {
                link as Arc<dyn SignerLink>
            }
        })
        .collect();

    let signer = ThresholdSigner::over(groups, shape, links).expect("signer");

    (signer, quiet.expect("the silent seat"))
}

/// **An entered seat that stays silent leaves the group unchanged.**
///
/// The witness to the assurance the manual gives -- and to the pre-check's boundary:
/// it sees the **configuration**, not the reachability. Here the link is entered, so
/// the refresh starts up and falls in round 1.
///
/// Three assurances, and they check three different things: the group goes on signing
/// in the old generation; the abort reaches the silent seat **too** (it must not be
/// left out merely because it is the reason); and a second attempt over **the same**
/// links carries.
///
/// That the third does **not** hang on the abort is measured -- the reason stands at
/// it.
#[test]
fn a_silent_seat_leaves_the_group_untouched() {
    let (_, before) = fresh();
    let (signer, quiet) = wired_with_a_silent_seat(&before, 3);

    let err = signer
        .refresh()
        .expect_err("a refresh with a silent seat must abort");
    let text = format!("{err}");
    assert!(
        text.contains('3'),
        "the message does not name the silent seat: {text}"
    );

    // The group goes on signing, and that in the old generation.
    let round = signer.open_round(b"afterwards").expect("round");
    assert_eq!(round.epoch(), Epoch::GENESIS);
    assert_eq!(signer.close_round(&round).expect("signature").len(), 64);
    assert_eq!(signer.epochs(), vec![Epoch::GENESIS]);

    // The abort reaches the reason for the abort too.
    assert!(
        quiet.abandoned.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "the silent seat was left out at the clearing away"
    );

    // And a second attempt over **the same** links carries: a begun run does not block
    // the next. A freshly wired signer could not show that -- its `LocalLink`s would be
    // new.
    //
    // **What that hangs on is measured and not the abort:** with the abort path
    // switched off the same second attempt still carries, because `refresh_start`
    // **replaces** a left-behind state (so it stands there). This assurance is thereby
    // the witness for that assurance; what the abort achieves is the release
    // **immediately** instead of at the next attempt, and for that stands the
    // assurance above.
    quiet.speak();
    assert_eq!(
        signer.refresh().expect("the second attempt must carry"),
        Epoch::GENESIS.next()
    );
}

/// As [`wired`], but the named seats lie about the group key.
fn wired_with_liars(
    held: &BTreeMap<Seat, Material>,
    liars: &[u16],
    lie: &PublicKeyPackage,
) -> ThresholdSigner {
    let shape = GroupShape::adr_0014();
    let mut seats: BTreeMap<Seat, Arc<LocalLink>> = BTreeMap::new();
    let mut groups = BTreeMap::new();

    for (seat, material) in held {
        groups.insert(material.epoch(), material.group().clone());
        let participant = Participant::new(
            *seat,
            material.share(),
            material.group(),
            material.epoch(),
            Arc::new(PlainCustody),
        )
        .expect("participant");
        seats.insert(
            *seat,
            Arc::new(LocalLink::new(participant, Box::new(OsEntropy))),
        );
    }

    for (seat, link) in &seats {
        let peers: Vec<Arc<dyn SignerLink>> = seats
            .iter()
            .filter(|&(other, _)| other != seat)
            .map(|(_, other)| Arc::clone(other) as Arc<dyn SignerLink>)
            .collect();
        link.attach_peers(peers);
    }

    let links: Vec<Arc<dyn SignerLink>> = seats
        .into_iter()
        .map(|(seat, link)| {
            if liars.contains(&seat.number()) {
                Arc::new(LyingLink {
                    inner: link,
                    group: lie.clone(),
                }) as Arc<dyn SignerLink>
            } else {
                link as Arc<dyn SignerLink>
            }
        })
        .collect();

    ThresholdSigner::over(groups, shape, links).expect("signer")
}

#[test]
fn a_seat_that_names_another_group_key_is_refused() {
    let (_, before) = fresh();
    let (_, foreign) = fresh();
    let lie = foreign[&GroupShape::adr_0014().seat(1).unwrap()]
        .group()
        .clone();

    // **One** liar: seat 1 answers first, so it is the seats after it that
    // contradict -- and the coordinator aborts.
    let signer = wired_with_liars(&before, &[1], &lie);
    let err = signer.refresh().expect_err("a contradiction must abort");
    assert!(
        format!("{err}").contains("a different group key"),
        "the refusal does not name the contradiction: {err}"
    );

    // And the group stands in the old generation.
    assert_eq!(signer.epochs(), vec![Epoch::GENESIS]);
}

#[test]
fn a_group_key_that_all_five_agree_on_must_still_be_the_old_one() {
    let (_, before) = fresh();
    let (_, foreign) = fresh();
    let lie = foreign[&GroupShape::adr_0014().seat(1).unwrap()]
        .group()
        .clone();

    // **All five** agreed, and wrong all the same: that is not caught by the
    // agreement check but only by the comparison with the verifying key -- the
    // intermediate from the root does not apply to a different one (ADR-0014).
    let signer = wired_with_liars(&before, &[1, 2, 3, 4, 5], &lie);
    let err = signer
        .refresh()
        .expect_err("a foreign verifying key must abort");
    assert!(
        format!("{err}").contains("verifying key"),
        "the refusal does not name the verifying key: {err}"
    );
    assert_eq!(signer.epochs(), vec![Epoch::GENESIS]);
}

/// As [`wired`], but every seat writes its new generation into the directory beside
/// it -- the operating case (ADR-0107, determination 5).
fn wired_persisting(
    held: &BTreeMap<Seat, Material>,
    dirs: &BTreeMap<Seat, PathBuf>,
) -> ThresholdSigner {
    let shape = GroupShape::adr_0014();
    let mut seats: BTreeMap<Seat, Arc<LocalLink>> = BTreeMap::new();
    let mut groups = BTreeMap::new();

    for (seat, material) in held {
        groups.insert(material.epoch(), material.group().clone());
        let participant = Participant::new(
            *seat,
            material.share(),
            material.group(),
            material.epoch(),
            Arc::new(PlainCustody),
        )
        .expect("participant");
        seats.insert(
            *seat,
            Arc::new(LocalLink::new(participant, Box::new(OsEntropy)).persisting_to(&dirs[seat])),
        );
    }

    for (seat, link) in &seats {
        let peers: Vec<Arc<dyn SignerLink>> = seats
            .iter()
            .filter(|&(other, _)| other != seat)
            .map(|(_, other)| Arc::clone(other) as Arc<dyn SignerLink>)
            .collect();
        link.attach_peers(peers);
    }

    let links: Vec<Arc<dyn SignerLink>> = seats
        .into_values()
        .map(|link| link as Arc<dyn SignerLink>)
        .collect();

    ThresholdSigner::over(groups, shape, links).expect("signer")
}

#[test]
fn a_refresh_survives_a_restart() {
    let (shape, before) = fresh();
    let homes: Vec<TempDir> = (0..5).map(|_| tempdir().expect("directory")).collect();
    let dirs: BTreeMap<Seat, PathBuf> = shape
        .places()
        .into_iter()
        .zip(&homes)
        .map(|(seat, home)| (seat, home.path().to_path_buf()))
        .collect();

    // Every seat lies on the disk as `tgd` finds it.
    for (seat, material) in &before {
        Material::save(
            &dirs[seat],
            material.share(),
            material.group(),
            material.epoch(),
            &PlainCustody,
        )
        .expect("the initial generation");
        assert_eq!(
            tg_identity::threshold::epochs(&dirs[seat]).expect("generations"),
            vec![Epoch::GENESIS]
        );
    }

    let signer = wired_persisting(&before, &dirs);
    let reached = signer.refresh().expect("the refresh must carry");

    // **The restart is the assurance**, not the file: from what lies on the disk a
    // signer is built that signs in the new generation -- without anything having come
    // along from memory.
    //
    // **And only the new one still lies there.** This assurance read "both
    // generations" until ADR-0107 determination 6 -- it has become sharper with the
    // retiring, not weaker: as long as the old one lies there, t seats can go on
    // signing in it, and a betrayed share still applies. It is retired here because all
    // five wrote the new one.
    let mut reloaded = BTreeMap::new();
    for (seat, dir) in &dirs {
        let held = tg_identity::threshold::epochs(dir).expect("generations");
        assert_eq!(
            held,
            vec![reached],
            "{seat} does not hold exactly the new generation after the refresh"
        );
        reloaded.insert(
            *seat,
            Material::load(dir, &PlainCustody).expect("the newest generation"),
        );
    }

    let after = wired(&reloaded);
    let round = after.open_round(b"after the restart").expect("round");
    assert_eq!(round.epoch(), reached);
    assert_eq!(after.close_round(&round).expect("signature").len(), 64);
    assert_eq!(
        after.verifying_key(),
        signer.verifying_key(),
        "the group key did not survive the restart"
    );
}

/// **A seat without a disk holds the old generation fast** (ADR-0107,
/// determination 6).
///
/// The condition is "all five have the new one **on the disk**", not "in memory": a
/// restart would take it away again, and then this seat would stand without a
/// generation in which `t` come together. Nothing is therefore retired as long as
/// **one** holds it only in memory.
#[test]
fn without_every_seat_on_disk_the_old_version_stays() {
    let (shape, before) = fresh();
    let homes: Vec<TempDir> = (0..5).map(|_| tempdir().expect("directory")).collect();
    let dirs: BTreeMap<Seat, PathBuf> = shape
        .places()
        .into_iter()
        .zip(&homes)
        .map(|(seat, home)| (seat, home.path().to_path_buf()))
        .collect();
    for (seat, material) in &before {
        Material::save(
            &dirs[seat],
            material.share(),
            material.group(),
            material.epoch(),
            &PlainCustody,
        )
        .expect("the initial generation");
    }

    // Seat 5 runs **without** a directory -- it forms the new generation and does not
    // write it.
    let mut short = dirs.clone();
    short.remove(&shape.seat(5).unwrap());
    let signer = wired_persisting_some(&before, &short);
    let reached = signer.refresh().expect("the refresh must carry");

    // The four with a directory hold **both**: nothing was retired.
    for (seat, dir) in &short {
        assert_eq!(
            tg_identity::threshold::epochs(dir).expect("generations"),
            vec![Epoch::GENESIS, reached],
            "{seat} retired the old generation although a seat needs it"
        );
    }

    // And the group signs in the new one all the same -- the retiring is the
    // **effect** of the refresh, not its condition.
    let round = signer.open_round(b"m").expect("round");
    assert_eq!(round.epoch(), reached);
    assert_eq!(signer.close_round(&round).expect("signature").len(), 64);
}

/// As [`wired_persisting`], but only the named seats write.
fn wired_persisting_some(
    held: &BTreeMap<Seat, Material>,
    dirs: &BTreeMap<Seat, PathBuf>,
) -> ThresholdSigner {
    let shape = GroupShape::adr_0014();
    let mut seats: BTreeMap<Seat, Arc<LocalLink>> = BTreeMap::new();
    let mut groups = BTreeMap::new();

    for (seat, material) in held {
        groups.insert(material.epoch(), material.group().clone());
        let participant = Participant::new(
            *seat,
            material.share(),
            material.group(),
            material.epoch(),
            Arc::new(PlainCustody),
        )
        .expect("participant");
        let link = LocalLink::new(participant, Box::new(OsEntropy));
        let link = match dirs.get(seat) {
            Some(dir) => link.persisting_to(dir),
            None => link,
        };
        seats.insert(*seat, Arc::new(link));
    }

    for (seat, link) in &seats {
        let peers: Vec<Arc<dyn SignerLink>> = seats
            .iter()
            .filter(|&(other, _)| other != seat)
            .map(|(_, other)| Arc::clone(other) as Arc<dyn SignerLink>)
            .collect();
        link.attach_peers(peers);
    }

    let links: Vec<Arc<dyn SignerLink>> = seats
        .into_values()
        .map(|link| link as Arc<dyn SignerLink>)
        .collect();

    ThresholdSigner::over(groups, shape, links).expect("signer")
}
