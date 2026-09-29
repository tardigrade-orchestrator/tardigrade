//! A seat's material on the disk (ADR-0097, ADR-0107, ADR-0108).
//!
//! What is checked here is the **read path**: which generations apply, and what
//! becomes of a half one. That a repair carries is said by the witnesses in
//! `repair.rs`; that a refresh leaves two generations behind by those in
//! `refresh.rs`.

use tg_identity::threshold::{GroupShape, OsEntropy, dkg};

/// A seat's share and group key from a real ceremony.
///
/// Two calls yield **two different** groups -- that is the reason why
/// `the_newest_group_wins` can distinguish at all.
fn seat_material() -> (
    frost_ed25519::keys::KeyPackage,
    frost_ed25519::keys::PublicKeyPackage,
) {
    let mut entropy = OsEntropy;
    let group = dkg::ceremony(GroupShape::adr_0014(), &mut entropy).expect("DKG");
    let (_, share, public) = group.first().expect("share");

    (share.clone(), public.clone())
}

// --- The repair case: the group without its share (ADR-0108) ----------------

/// **A group key without a share is the repair case.**
///
/// [`epochs`](tg_identity::threshold::epochs) expressly does **not** count it -- a
/// half generation is none (ADR-0107) --, and `Material::load` fails at it. But
/// exactly that situation is the occasion of the repair: the share is gone, the group
/// lies there. Without a read path of its own the coordinator (ADR-0108,
/// determination 1) could not read the key against which it has to check the
/// result.
#[test]
fn a_group_without_its_share_is_still_readable() {
    let dir = tempfile::tempdir().expect("temp");
    let (_, group) = seat_material();
    let path = tg_identity::layout::signing(dir.path());
    std::fs::create_dir_all(&path).expect("directory");
    std::fs::write(path.join("group"), group.serialize().expect("group")).expect("write");

    assert_eq!(
        tg_identity::threshold::epochs(dir.path()).expect("generations"),
        Vec::new(),
        "a half generation is none (ADR-0107)"
    );
    assert!(
        tg_identity::threshold::Material::load(dir.path(), &tg_identity::threshold::PlainCustody)
            .is_err(),
        "without a share there is no material"
    );

    let found = tg_identity::threshold::groups(dir.path()).expect("groups");
    assert_eq!(found, vec![tg_identity::threshold::Epoch::GENESIS]);
    let read = tg_identity::threshold::load_group(dir.path(), found[0]).expect("group");
    assert_eq!(
        read.verifying_key(),
        group.verifying_key(),
        "it must be the same group"
    );
}

/// **The highest group wins** -- and it is the one in which the group is currently
/// signing.
///
/// A helper lays out its deltas from `newest_material()`; what is repaired is
/// therefore the newest generation, and `restore` checks against its group key. If
/// the coordinator took the lowest, the check would fail -- loudly, and for a reason
/// the message does not name.
#[test]
fn the_newest_group_wins() {
    let dir = tempfile::tempdir().expect("temp");
    let (_, first) = seat_material();
    let (_, second) = seat_material();
    let path = tg_identity::layout::signing(dir.path());
    std::fs::create_dir_all(&path).expect("directory");
    std::fs::write(path.join("group"), first.serialize().expect("group")).expect("write");
    std::fs::write(path.join("group.1"), second.serialize().expect("group")).expect("write");

    let found = tg_identity::threshold::groups(dir.path()).expect("groups");
    assert_eq!(found.len(), 2, "both generations: {found:?}");
    let newest = *found.last().expect("the highest");
    assert_eq!(newest.number(), 1);

    let read = tg_identity::threshold::load_group(dir.path(), newest).expect("group");
    assert_eq!(read.verifying_key(), second.verifying_key());
}

/// **Without a group key an empty list, no error.**
///
/// The counter-direction, and it carries half the assurance: a search that always
/// fails would not pass the witness above -- and one that always finds something
/// would be distinguishable from a correct one only at this place.
#[test]
fn without_any_group_the_list_is_empty() {
    let dir = tempfile::tempdir().expect("temp");

    assert!(
        tg_identity::threshold::groups(dir.path())
            .expect("no directory is no error")
            .is_empty()
    );
}
