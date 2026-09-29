//! The coordinator of the RTS repair (ADR-0108, determination 1 and 7).
//!
//! It runs on the node of the **affected** seat, drives the three steps over the
//! helpers' signer ports and **puts material in place** -- the same role as
//! `cargo xtask threshold` at the ceremony. `tgd` reads it at startup; a `tgd`
//! that started without a share in a repair state would be a process that opens a
//! signer port and holds no seat.
//!
//! What is checked here is the **preparation** without a network: which settings
//! it needs, what it refuses, and where the result goes. That the path carries is
//! said by the witnesses at real processes (`signing.rs`).

use tg_identity::TrustDomain;
use tgd::signer::Repair;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("domain")
}

/// **Without a node key no repair.**
///
/// It is the credential on the signer port (ADR-0097) -- and the reason why the
/// lost seat *can* coordinate at all: what is checked is the node key, not the
/// share.
#[test]
fn without_a_node_key_nothing() {
    let dir = tempfile::tempdir().expect("temp");

    let err = Repair::prepare(dir.path(), &domain(), 5, &[(1, "http://x".to_owned())])
        .expect_err("without a key there is no credential");

    assert!(err.contains("node.key.pem"), "{err}");
}

/// **Without its own cluster leaf it does not know its name.**
///
/// The name goes into the SPIFFE identifier it presents on the signer port -- and
/// a helper admits only a caller whose name stands in its admission list
/// (ADR-0097). What is read is therefore `identity/node.leaf.pem`, **not**
/// `signers/<lost>.pem`: that is the leaf the others hold of it, and that it lies
/// with the node itself is a habit of the distribution.
#[test]
fn without_its_own_leaf_nothing() {
    let dir = tempfile::tempdir().expect("temp");
    place_node_key(dir.path());

    let err = Repair::prepare(dir.path(), &domain(), 5, &[(1, "http://x".to_owned())])
        .expect_err("without its own leaf there is no name");

    assert!(err.contains("node.leaf.pem"), "{err}");
}

/// **Without a group key no check** -- and then no repair.
///
/// `repair::restore` compares the restored share against the `verifying_share`
/// from the group key (the finding from 7b: `repair_share_part3` does **not**
/// count the sigmas and with too few delivers a share that looks valid and is
/// wrong). Without it there would be nothing to check, and determination 6
/// demands the check **before** the write.
#[test]
fn without_a_group_key_nothing() {
    let dir = tempfile::tempdir().expect("temp");
    place_node_key(dir.path());
    place_own_leaf(dir.path());

    let err = Repair::prepare(dir.path(), &domain(), 5, &[(1, "http://x".to_owned())])
        .expect_err("without a group key there is no check");

    assert!(err.contains("group key"), "{err}");
}

/// **Fewer helpers than the threshold is refused** -- before the first call.
///
/// The threshold stands in the group key (`min_signers`), so that is no second
/// source. Refusing it here saves three network rounds whose result would have to
/// fail at `restore` anyway -- and if it did **not**, that would be the finding
/// from 7b.
#[test]
fn fewer_helpers_than_the_threshold_is_refused() {
    let dir = tempfile::tempdir().expect("temp");
    place_node_key(dir.path());
    place_own_leaf(dir.path());
    place_group(dir.path());

    let err = Repair::prepare(
        dir.path(),
        &domain(),
        5,
        &[(1, "http://x".to_owned()), (2, "http://y".to_owned())],
    )
    .expect_err("two helpers do not reach the threshold of three");

    assert!(err.contains("threshold"), "{err}");
}

/// **Its own seat does not belong among the helpers.**
///
/// The same refusal as at the seam and in `repair::restore_seat`, here **before**
/// the network: the lost seat coordinates (determination 1), so a mistyped
/// `--helper` with its own address runs up against itself.
#[test]
fn the_lost_seat_is_not_a_helper() {
    let dir = tempfile::tempdir().expect("temp");
    place_node_key(dir.path());
    place_own_leaf(dir.path());
    place_group(dir.path());

    let err = Repair::prepare(
        dir.path(),
        &domain(),
        5,
        &[
            (1, "http://x".to_owned()),
            (2, "http://y".to_owned()),
            (5, "http://z".to_owned()),
        ],
    )
    .expect_err("its own seat does not help");

    assert!(err.contains("its own helpers"), "{err}");
}

/// **A helper without a leaf is named, not passed over.**
///
/// The credential needs the binding: `Seats::dial` checks that the one answering
/// is the one dialled, and without `signers/<n>.pem` there is no channel. A
/// silently skipped helper would be a run with `t-1` contributions -- and that
/// fails only in step 3, at a place that says nothing about the cause.
#[test]
fn a_helper_without_a_leaf_is_named() {
    let dir = tempfile::tempdir().expect("temp");
    place_node_key(dir.path());
    place_own_leaf(dir.path());
    place_group(dir.path());

    let err = Repair::prepare(
        dir.path(),
        &domain(),
        5,
        &[
            (1, "http://x".to_owned()),
            (2, "http://y".to_owned()),
            (3, "http://z".to_owned()),
        ],
    )
    .expect_err("without a leaf there is no channel");

    assert!(err.contains("signers/"), "{err}");
    assert!(err.contains('1'), "the message must name the seat: {err}");
}

// --- Setup ------------------------------------------------------------------

fn place_node_key(dir: &std::path::Path) {
    let identity = tg_identity::layout::dir(dir);
    std::fs::create_dir_all(&identity).expect("directory");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    std::fs::write(
        identity.join(tg_identity::layout::NODE_KEY),
        key.serialize_pem(),
    )
    .expect("write");
}

/// Its own cluster leaf, as `tgd` files it at startup (ADR-0043).
fn place_own_leaf(dir: &std::path::Path) {
    let identity = tg_identity::layout::dir(dir);
    let key_pem = std::fs::read_to_string(identity.join(tg_identity::layout::NODE_KEY))
        .expect("file the node key first");
    let key = rcgen::KeyPair::from_pem(&key_pem).expect("key");
    let id = tg_identity::SpiffeId::for_node(&domain(), "tgd-5").expect("identifier");
    let node = tg_identity::NodeIdentity::new(&key, id).expect("identity");

    std::fs::write(
        identity.join(tg_identity::layout::NODE_LEAF),
        pem::encode(&pem::Pem::new("CERTIFICATE", node.leaf().to_vec())),
    )
    .expect("write");
}

/// The group key **alone** -- and that is the repair case.
///
/// `Material::save` also filed the share, and then no witness would have hit the
/// situation at issue: the share is gone (`epochs` therefore does not count the
/// generation, ADR-0107), the group key lies there.
fn place_group(dir: &std::path::Path) {
    use tg_identity::threshold::{GroupShape, OsEntropy, dkg};

    let mut entropy = OsEntropy;
    let group = dkg::ceremony(GroupShape::adr_0014(), &mut entropy).expect("DKG");
    let (_, _, public) = group.first().expect("share");

    let signing = tg_identity::layout::signing(dir);
    std::fs::create_dir_all(&signing).expect("directory");
    std::fs::write(
        signing.join(tg_identity::layout::GROUP),
        public.serialize().expect("group"),
    )
    .expect("write");

    assert!(
        tg_identity::threshold::Material::load(dir, &tg_identity::threshold::PlainCustody).is_err(),
        "the witness must hit the repair case: without a share"
    );
}
