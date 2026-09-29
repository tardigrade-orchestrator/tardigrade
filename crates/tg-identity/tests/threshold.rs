//! The threshold CA (ADR-0014 sub-decisions 1 and 3, phase 7b).
//!
//! Two claims stand on the test rig here, and both are the sort of claim one should
//! not believe but measure:
//!
//! 1. **A group signature is an ordinary Ed25519 signature.** On that rests the whole
//!    construction -- ADR-0014 justifies the choice of FROST with "rustls/webpki
//!    verify the chain without special handling". It is therefore checked with a
//!    verifier that knows nothing of FROST: `ring`, the same library that works under
//!    webpki.
//! 2. **No node ever holds the full key.** The DKG runs here as five separate state
//!    machines; every seat computes from its own secret package. There is no point in
//!    the sequence at which the group key exists as a whole -- not even briefly.

use std::collections::BTreeMap;
use std::sync::Arc;

use tg_identity::threshold::{
    Epoch, GroupShape, LocalLink, Participant, Seat, SessionId, SignerLink, ThresholdSigner, dkg,
};
use tg_identity::{Authority, Lifetime, SpiffeId, TrustDomain, self_signed_ca};

mod support;
use support::{SeededEntropy, group_of_five};

const YEAR: i64 = 365 * 24 * 60 * 60;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

/// **The default from ADR-0014 is five seats with t = 3** -- and it stands in the
/// code, not only in the document.
#[test]
fn the_group_shape_is_five_seats_with_a_threshold_of_three() {
    let shape = GroupShape::adr_0014();

    assert_eq!(shape.seats(), 5);
    assert_eq!(shape.threshold(), 3);
    assert_eq!(shape.places().len(), 5);
}

/// A threshold below the majority lets two disjoint subsets sign at the same time.
/// That is no fine polish but the same split-brain ADR-0031 excludes on the consensus
/// side.
#[test]
fn a_threshold_below_the_majority_is_refused() {
    let err = GroupShape::new(5, 2).expect_err("must not be accepted");

    assert!(
        err.to_string().contains("majority"),
        "the message shall name the reason: {err}"
    );
}

#[test]
fn a_threshold_above_the_seat_count_is_refused() {
    GroupShape::new(5, 6).expect_err("must not be accepted");
}

/// **The shape knows five seats** (ADR-0014), and a sixth is none.
///
/// A witness in `refresh.rs` carries the same name -- there it is about the
/// **resharing**: a seat the *existing* group does not know does not join (ADR-0107).
/// Two different assurances, and `cargo test a_seat_outside_the_group_is_refused` runs
/// both.
#[test]
fn a_seat_outside_the_group_is_refused() {
    let shape = GroupShape::adr_0014();

    assert!(shape.seat(1).is_ok());
    assert!(shape.seat(5).is_ok());
    shape.seat(0).expect_err("there is no seat 0");
    shape.seat(6).expect_err("there is no seat 6");
}

/// **The first acceptance criterion: a group signature verifies as an ordinary
/// Ed25519 signature.**
///
/// `ring` knows nothing of FROST. It gets 32 bytes of public key, 64 bytes of
/// signature and a message -- and must agree.
#[test]
fn a_group_signature_verifies_as_a_plain_ed25519_signature() {
    let mut entropy = SeededEntropy::new(0x7B_0001);
    let group = group_of_five(&mut entropy);
    let signer = group.signer();

    let message = b"what the group signs";
    let signature = signer.sign_with_group(message).expect("group signature");

    assert_eq!(signature.len(), 64, "an Ed25519 signature is 64 bytes");
    assert_eq!(
        signer.verifying_key().len(),
        32,
        "an Ed25519 key is 32 bytes"
    );

    let peer =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, signer.verifying_key());
    peer.verify(message, &signature)
        .expect("an ordinary Ed25519 verifier takes the group signature");
}

/// And it applies to **this** message, not to any at all.
#[test]
fn a_group_signature_does_not_cover_another_message() {
    let mut entropy = SeededEntropy::new(0x7B_0002);
    let group = group_of_five(&mut entropy);
    let signer = group.signer();

    let signature = signer.sign_with_group(b"the original").expect("signature");

    let peer =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, signer.verifying_key());
    peer.verify(b"something else", &signature)
        .expect_err("a foreign message must not get through");
}

/// Two runs over the same message yield **different** signatures -- FROST is
/// randomized Schnorr, not deterministic Ed25519. Both apply.
///
/// That is no blemish but the place at which the nonce sits: if two signatures over
/// the same message were equal, the nonce would have been repeated.
#[test]
fn two_signatures_over_the_same_message_differ() {
    let mut entropy = SeededEntropy::new(0x7B_0003);
    let group = group_of_five(&mut entropy);
    let signer = group.signer();

    let first = signer.sign_with_group(b"twice").expect("the first");
    let second = signer.sign_with_group(b"twice").expect("the second");

    assert_ne!(
        first, second,
        "the same signature twice would mean: the same nonce twice"
    );

    let peer =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, signer.verifying_key());
    peer.verify(b"twice", &first).expect("the first applies");
    peer.verify(b"twice", &second).expect("the second applies");
}

/// **Exactly t suffices**, and t - 1 does not. The threshold is no
/// recommendation.
#[test]
fn three_of_five_suffice_and_two_do_not() {
    let mut entropy = SeededEntropy::new(0x7B_0004);
    let group = group_of_five(&mut entropy);

    let three = group.signer_over(&[1, 2, 3]);
    three
        .sign_with_group(b"three suffice")
        .expect("three seats are the threshold");

    // Two seats do not fail only at the signing but at the build-up already: a group
    // that **cannot** reach the threshold is none. The error belongs at the place at
    // which it arises -- not at the one at which a certificate is needed for the first
    // time.
    let err = group
        .try_signer_over(&[4, 5])
        .expect_err("two seats are no group");
    assert!(
        err.to_string().contains("threshold"),
        "the message shall name the threshold: {err}"
    );
}

/// The failure of two seats holds the signature, the third breaks it -- the same
/// boundary as the Raft quorum from ADR-0031, and exactly for that reason t = 3 was
/// chosen.
#[test]
fn two_failures_are_survived_and_the_third_is_not() {
    let mut entropy = SeededEntropy::new(0x7B_0005);
    let group = group_of_five(&mut entropy);

    let signer = group.signer();
    group.take_down(&[4, 5]);
    signer
        .sign_with_group(b"two failures")
        .expect("two failures are to be borne");

    group.take_down(&[3]);
    signer
        .sign_with_group(b"three failures")
        .expect_err("the third failure breaks the threshold");
}

/// **The seam holds.** `ThresholdSigner` steps into the place where `LocalSigner`
/// stood in phase 7a -- the same `Authority`, the same SVID path, not a line of
/// difference in it.
#[test]
fn the_threshold_group_signs_a_certificate_chain_through_the_same_seam() {
    use std::time::Duration;

    use rustls_pki_types::{CertificateDer, UnixTime};

    let mut entropy = SeededEntropy::new(0x7B_0006);
    let group = group_of_five(&mut entropy);
    let signer = group.signer();

    // Exactly the call from phase 7a -- only the signer is a different one.
    let ca = self_signed_ca(&domain(), &signer, 0, YEAR).expect("signing CA");
    let anchor_der = ca.certificate_der().to_vec();
    let authority = Authority::new(ca, &signer, Lifetime::default()).expect("issuer");
    let id = SpiffeId::for_workload(&domain(), "api").expect("ID");
    let svid = authority.issue(&id, 1_000).expect("SVID");

    // And the chain is verified, not asserted.
    let anchor_der = CertificateDer::from(anchor_der);
    let anchor = webpki::anchor_from_trusted_cert(&anchor_der).expect("anchor");
    let leaf = CertificateDer::from(svid.certificate_der().to_vec());
    let cert = webpki::EndEntityCert::try_from(&leaf).expect("a readable certificate");

    cert.verify_for_usage(
        &[webpki::ring::ED25519],
        &[anchor],
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(1_100)),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .expect("webpki takes the chain signed by the group");
}

/// The group key hangs on the DKG, not on the seat: all five seats arrive at **the
/// same** public key.
#[test]
fn every_seat_agrees_on_the_group_key() {
    let mut entropy = SeededEntropy::new(0x7B_0007);
    let shape = GroupShape::adr_0014();

    let mut started = BTreeMap::new();
    let mut broadcasts = BTreeMap::new();
    for seat in shape.places() {
        let (state, broadcast) = dkg::start(seat, shape, &mut entropy).expect("round 1");
        started.insert(seat, state);
        broadcasts.insert(seat, broadcast);
    }

    let mut exchanged = BTreeMap::new();
    let mut inbox: BTreeMap<Seat, BTreeMap<Seat, dkg::Directed>> = shape
        .places()
        .into_iter()
        .map(|s| (s, BTreeMap::new()))
        .collect();
    for (seat, state) in started {
        let from_others = without(&broadcasts, seat);
        let (state, outgoing) = state.round2(&from_others).expect("round 2");
        exchanged.insert(seat, state);
        for (to, message) in outgoing {
            inbox.get_mut(&to).expect("seat").insert(seat, message);
        }
    }

    let mut keys = Vec::new();
    for (seat, state) in exchanged {
        let from_others = without(&broadcasts, seat);
        let directed = inbox.remove(&seat).expect("inbox");
        let (_share, public) = state.finish(&from_others, &directed).expect("round 3");
        keys.push(public.verifying_key().serialize().expect("key"));
    }

    assert_eq!(keys.len(), 5);
    assert!(
        keys.windows(2).all(|pair| pair[0] == pair[1]),
        "all five seats must see the same group key"
    );
}

/// The share lies sealed, not open: the custody seam from ADR-0014 sub-decision 2 is
/// traversed at **every** use.
#[test]
fn a_seat_reads_its_share_through_the_custody_seam() {
    let mut entropy = SeededEntropy::new(0x7B_0008);
    let group = group_of_five(&mut entropy);
    let custody = Arc::new(support::CountingCustody::default());

    let seat = Seat::new(1).expect("seat");
    let mut participant = Participant::new(
        seat,
        group.share(seat),
        group.public(),
        Epoch::GENESIS,
        custody.clone(),
    )
    .expect("participant");
    assert_eq!(custody.seals(), 1, "at the laying out sealing happens");
    assert_eq!(custody.unseals(), 0, "and not yet opening");

    let session = SessionId::from(7);
    participant
        .commit(session, Epoch::GENESIS, &mut entropy)
        .expect("commitment");

    assert_eq!(
        custody.unseals(),
        1,
        "the commitment needs the share and fetches it out of the sealing"
    );
}

fn without(all: &BTreeMap<Seat, dkg::Broadcast>, seat: Seat) -> BTreeMap<Seat, dkg::Broadcast> {
    all.iter()
        .filter(|(other, _)| **other != seat)
        .map(|(other, package)| (*other, package.clone()))
        .collect()
}

/// A link that does not answer is skipped instead of blocking -- otherwise the
/// threshold would be a threshold only on paper.
#[test]
fn an_unreachable_seat_is_skipped_rather_than_fatal() {
    let mut entropy = SeededEntropy::new(0x7B_0009);
    let group = group_of_five(&mut entropy);

    let links: Vec<Arc<dyn SignerLink>> = group
        .participants(&[1, 2, 3, 4])
        .into_iter()
        .map(|participant| {
            let seat = participant.seat();
            let link: Arc<dyn SignerLink> = if seat.number() == 1 {
                Arc::new(support::DeadLink::new(seat))
            } else {
                Arc::new(LocalLink::new(participant, Box::new(entropy.fork())))
            };
            link
        })
        .collect();

    let signer =
        ThresholdSigner::new(group.public().clone(), GroupShape::adr_0014(), links).expect("group");

    let signature = signer
        .sign_with_group(b"one stays silent")
        .expect("three of the four answer, that suffices");
    let peer =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, signer.verifying_key());
    peer.verify(b"one stays silent", &signature).expect("valid");
}

/// Two links to **the same** seat are not two seats. The package holds one commitment
/// per identifier; the second would overwrite the first, and the threshold would only
/// seemingly be reached.
#[test]
fn one_seat_cannot_stand_in_twice() {
    let mut entropy = SeededEntropy::new(0x7B_000A);
    let group = group_of_five(&mut entropy);

    let err = group
        .try_signer_over(&[1, 2, 2])
        .expect_err("a seat must not be represented twice");

    assert!(
        err.to_string().contains("twice"),
        "the message shall name the reason: {err}"
    );
}

/// **No outcome leaves a nonce session open** (ADR-0014).
///
/// Measured, a reserved, never spent nonce is no trifle: a round reserves `t` of them,
/// they carry nonce secrets in the vault, and nobody clears them away -- five discarded
/// rounds yielded `[5, 5, 5, 0, 0]` open sessions. The way there leads over a `Round`
/// that falls without being closed; `sign_with_group` therefore runs both rounds and
/// clears away in **every** outcome.
///
/// Three outcomes, and the third is the one one forgets: a seat that **commits** and
/// refuses afterwards. There the package already stands, `t` nonces are reserved, and
/// none of them can be replaced any more.
#[test]
fn no_outcome_leaves_a_nonce_reserved() {
    let mut entropy = SeededEntropy::new(0x7B_000E);
    let group = group_of_five(&mut entropy);
    let signer = group.signer();

    assert_eq!(group.outstanding(), vec![0; 5], "beforehand");

    // 1. **Success** -- the nonces are spent, not reserved.
    signer
        .sign_with_group(b"success")
        .expect("the group carries");
    assert_eq!(
        group.outstanding(),
        vec![0; 5],
        "a successful signature leaves a nonce reserved"
    );

    // 2. **A failure in round 1** -- the threshold does not come together, and the
    // commitments that were already there are cleared away.
    group.take_down(&[3, 4, 5]);
    signer
        .sign_with_group(b"round one")
        .expect_err("three failures break the threshold");
    assert_eq!(
        group.outstanding(),
        vec![0; 5],
        "a failure in round 1 leaves a nonce reserved"
    );
}

/// **A failure in round 2 clears away too** (ADR-0014).
///
/// A witness of its own, because the case arises differently: here `t` seats have
/// **committed**, the package stands, and only at the signing does one refuse. It can
/// no longer be replaced -- its commitment sits in the package --, so clearing away is
/// the only answer.
#[test]
fn a_failure_in_the_second_round_releases_the_nonces() {
    let mut entropy = SeededEntropy::new(0x7B_000F);
    let group = group_of_five(&mut entropy);
    let signer = group.signer();

    group.mute_signing(&[1, 2, 3, 4, 5]);
    let err = signer
        .sign_with_group(b"commit and refuse")
        .expect_err("without shares no signature");
    assert!(
        err.to_string().contains("threshold"),
        "the failure belongs in round 2: {err}"
    );
    assert_eq!(
        group.outstanding(),
        vec![0; 5],
        "a failure in round 2 leaves the reserved nonces lying"
    );
}

/// **A discarded round clears itself away** (ADR-0014).
///
/// The witness to the finding that forced this `Drop`: measured, five opened and
/// discarded rounds left `[5, 5, 5, 0, 0]` open nonce sessions per seat -- they carry
/// nonce secrets, they grew linearly, and nobody cleared them away. That was reachable
/// over a `Round` that falls without being closed.
///
/// The answer is **structural** and not "not public": the rounds stay callable (two
/// witnesses in `refresh.rs` need `Round::epoch`), and the case is no longer
/// constructible.
///
/// Five rounds and not one: with one, `[0; 5]` would be fulfilled by a `Drop` that
/// clears only the *first* away too.
#[test]
fn a_dropped_round_releases_its_nonces() {
    let mut entropy = SeededEntropy::new(0x7B_0010);
    let group = group_of_five(&mut entropy);
    let signer = group.signer();

    for round in 0..5 {
        drop(signer.open_round(b"never closed").expect("round"));
        assert_eq!(
            group.outstanding(),
            vec![0; 5],
            "after round {round} reserved nonces lie there"
        );
    }

    // And afterwards the same group goes on signing -- a `Drop` that clears too much
    // away would take its share from it.
    assert_eq!(
        signer
            .sign_with_group(b"afterwards")
            .expect("signature")
            .len(),
        64
    );
}
