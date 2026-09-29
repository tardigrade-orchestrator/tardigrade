//! The admission list of the signer port (ADR-0097).
//!
//! It is keyed by **seat**, the trust list below it by **node name** -- and from
//! this layering follows a collision nobody has checked: two seats whose leaves
//! carry the same name.
//!
//! Measured, that was silent before:
//!
//! ```text
//! MEASUREMENT len=2 notes=[]
//! MEASUREMENT trust entries=1
//! ```
//!
//! Two admitted seats, **one** registration, and not a word. The seat whose leaf
//! was overwritten does not get through the handshake afterwards -- and
//! `tg_identity_signer_seats` counts it along. Exactly that number tells an
//! operator whether the group *can reach* the threshold (ADR-0097, determination
//! 7); with five leaves and one collision it reports five, and the group has
//! four.

use tg_identity::{SpiffeId, TrustDomain};

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("domain")
}

/// Files `signers/<seat>.pem` with a leaf on this node name.
fn place(dir: &std::path::Path, seat: u16, node: &str) {
    let signers = tg_identity::layout::signers(dir);
    std::fs::create_dir_all(&signers).expect("mkdir");

    let key = rcgen::KeyPair::generate().expect("key");
    let id = SpiffeId::for_node(&domain(), node).expect("ID");
    let pem = tg_identity::cluster::node_leaf_pem(&key, &id).expect("leaf");
    std::fs::write(signers.join(format!("{seat}.pem")), pem).expect("write");
}

/// **Five seats with five names are five admissions** -- the counter-direction.
///
/// Without it a `load` that empties every list would be just as green, and the
/// signer port would never come up.
#[test]
fn five_distinct_names_are_five_seats() {
    let dir = tempfile::tempdir().expect("temp");
    for seat in 1..=5u16 {
        place(dir.path(), seat, &format!("tgd-{seat}"));
    }

    let (seats, notes) = tgd::signer::Seats::load(dir.path(), &domain());

    assert_eq!(seats.len(), 5, "{notes:?}");
    assert!(notes.is_empty(), "{notes:?}");
}

/// **Two seats with the same node name are both refused.**
///
/// Not one, and that is the same argument as with the doubly declared workload in
/// ADR-0062: *which one is meant nobody knows, and taking one would mean
/// guessing.* Here guessing would mean that a seat looks admitted and does not
/// get through the handshake -- and **which one** is decided by the order in
/// which the files are read.
///
/// With that the number is right again at the same time: `len()` is the number of
/// seats that can really identify themselves.
#[test]
fn two_seats_with_the_same_node_name_are_both_refused() {
    let dir = tempfile::tempdir().expect("temp");
    place(dir.path(), 1, "tgd-1");
    place(dir.path(), 4, "tgd-2");
    place(dir.path(), 5, "tgd-2");

    let (seats, notes) = tgd::signer::Seats::load(dir.path(), &domain());

    assert_eq!(seats.len(), 1, "both colliding ones must be gone");
    assert!(
        notes
            .iter()
            .any(|note| note.contains("tgd-2") && note.contains('4') && note.contains('5')),
        "the note must name the name and both seats: {notes:?}"
    );
}

/// **And the reverse mapping name -> seat is thereby unambiguous.**
///
/// That is the property on which ADR-0108 determination 3 rests: the service
/// knows the caller's **node name** from the connection's credential and must
/// read the seat from it in order to give a sigma only to the seat it concerns.
/// With a collision in the list it would not be formulable.
#[test]
fn the_name_names_exactly_one_seat() {
    let dir = tempfile::tempdir().expect("temp");
    for seat in 1..=3u16 {
        place(dir.path(), seat, &format!("tgd-{seat}"));
    }

    let seats = tgd::signer::Seats::load(dir.path(), &domain()).0;

    assert_eq!(seats.seat_of("tgd-2"), Some(2));
    assert_eq!(seats.seat_of("tgd-foreign"), None, "no seat for a stranger");
}

// --- From the leaf to the seat (ADR-0108, determination 3) -------------------

/// **An admitted leaf names its seat.**
///
/// The counter-direction to the two below, and it carries them: a function that
/// always gives `None` would pass the rejections just as well -- and then no seat
/// would ever get its sigma.
#[test]
fn an_admitted_leaf_names_its_seat() {
    let dir = tempfile::tempdir().expect("temp");
    for seat in 1..=5u16 {
        place(dir.path(), seat, &format!("tgd-{seat}"));
    }
    let (seats, _) = tgd::signer::Seats::load(dir.path(), &domain());

    let leaf = leaf_of("tgd-3");
    assert_eq!(tgd::signer::seat_from_leaf(&seats, &leaf), Some(3));
}

/// **A name the admission list does not know gives no seat** -- and expressly no
/// **invented** one.
///
/// The occasion is a mutation run: an `.or(Some(5))` behind `seat_of` left **all
/// eleven** witnesses of this surface green. A caller whose name does not stand
/// in the list would thereby have got the sigma for seat 5 -- and `t`
/// passed-through sigmas *are* the input of step 3 (ADR-0108).
///
/// That the situation is not reachable today (the port's verifier checks against
/// the **same** list) makes it defence in depth: exactly the sort of layer a
/// rebuild takes away without anybody noticing.
#[test]
fn a_name_outside_the_list_gives_no_seat() {
    let dir = tempfile::tempdir().expect("temp");
    for seat in 1..=5u16 {
        place(dir.path(), seat, &format!("tgd-{seat}"));
    }
    let (seats, _) = tgd::signer::Seats::load(dir.path(), &domain());

    let leaf = leaf_of("tgd-foreign");
    assert_eq!(
        tgd::signer::seat_from_leaf(&seats, &leaf),
        None,
        "no seat -- and no invented one"
    );
}

/// **A leaf that is no node leaf gives no seat.**
///
/// An operator credential (ADR-0103) carries the same trust domain and a
/// different role. The signer port does not let it through -- but `node()` gives
/// `None` here, and the line rests on that.
#[test]
fn a_leaf_that_is_no_node_gives_no_seat() {
    let dir = tempfile::tempdir().expect("temp");
    place(dir.path(), 1, "tgd-1");
    let (seats, _) = tgd::signer::Seats::load(dir.path(), &domain());

    let key = rcgen::KeyPair::generate().expect("key");
    let id = SpiffeId::for_operator(&domain(), "dana").expect("ID");
    let pem = tg_identity::cluster::node_leaf_pem(&key, &id).expect("leaf");
    let der = pem::parse(&pem).expect("PEM").into_contents();

    assert_eq!(
        tgd::signer::seat_from_leaf(&seats, &rustls_pki_types::CertificateDer::from(der)),
        None
    );
}

/// A node leaf for a name -- the same shape `place` files.
fn leaf_of(node: &str) -> rustls_pki_types::CertificateDer<'static> {
    let key = rcgen::KeyPair::generate().expect("key");
    let id = SpiffeId::for_node(&domain(), node).expect("ID");
    let pem = tg_identity::cluster::node_leaf_pem(&key, &id).expect("leaf");

    rustls_pki_types::CertificateDer::from(pem::parse(&pem).expect("PEM").into_contents())
}
