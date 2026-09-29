//! What comes out of an image stays under lock (ADR-0017).
//!
//! Written **before** the implementation.
//!
//! # The measured finding
//!
//! An unpacked layer keeps the permissions from the tar -- **including setuid
//! and setgid** -- and the files belong to `root`, because the agent runs
//! privileged (ADR-0017). The directory chain above it arose with
//! `create_dir_all` and the umask, that is, `0755`:
//!
//! ```text
//! 104755  <data-dir>/content/layers/sha256/<digest>/bin/suid
//!  40755  <data-dir>/content
//!  40755  <data-dir>/bundles/<workload>/rootfs
//! ```
//!
//! **Every setuid-root binary of every image ever pulled** was thereby
//! executable for every local user of the node -- including from images that
//! have long run nowhere, and with old, vulnerable versions. The whole
//! hardening from ADR-0017 applies *in* the container; the same binary lay
//! open beside it.
//!
//! # Why the bar sits at the top and not at the file
//!
//! A path is traversed only if **every** component gives the execute right. A
//! bolt at the root therefore suffices -- and does not touch what the container
//! sees. The permissions *in* the layer are the image's and belong to it:
//! whoever strips them here changes what applies in the container (`ping`,
//! `su`), and that would be a decision and no safeguard.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).expect("there").permissions().mode() & 0o777
}

/// **The content store is private.**
#[test]
fn the_content_store_is_not_world_traversable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("content");

    let _store = tg_runtime::content::ContentStore::open(&root).expect("store");

    assert_eq!(
        mode_of(&root),
        0o700,
        "the store stands open -- every setuid binary of every image would be reachable"
    );
}

/// **A store that already existed too.**
///
/// A node that ran before this change already has its directory -- and
/// `create_dir_all` does not touch an existing one. Without this case exactly
/// the stock at issue would stay open.
#[test]
fn an_existing_store_is_tightened_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("content");
    std::fs::create_dir_all(root.join("blobs")).expect("the old stock");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("open");

    let _store = tg_runtime::content::ContentStore::open(&root).expect("store");

    assert_eq!(mode_of(&root), 0o700);
}

/// **And the bundles**, in which a running container's rootfs lies.
#[test]
fn the_bundle_root_is_not_world_traversable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bundles = dir.path().join("bundles");

    tg_runtime::bundle::ensure_root(&bundles).expect("the root");

    assert_eq!(mode_of(&bundles), 0o700);
}

/// An existing bundle directory is sealed likewise.
#[test]
fn an_existing_bundle_root_is_tightened_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bundles = dir.path().join("bundles");
    std::fs::create_dir_all(&bundles).expect("the old stock");
    std::fs::set_permissions(&bundles, std::fs::Permissions::from_mode(0o755)).expect("open");

    tg_runtime::bundle::ensure_root(&bundles).expect("the root");

    assert_eq!(mode_of(&bundles), 0o700);
}

/// **The desired state is private** (ADR-0115, determination 3).
///
/// It is this node's truth (ADR-0019): whoever reads it knows the cluster's
/// wanted state -- images, ports, volumes, dependencies. Measured, before
/// ADR-0115 it stood at `0755` while the store beside it has stood at `0700`
/// since ADR-0017. The same machine, the same data directory, two answers.
#[test]
fn the_desired_state_is_not_world_traversable() {
    let dir = tempfile::tempdir().expect("tempdir");

    let state = tg_runtime::state::DesiredState::open(dir.path()).expect("the desired state");

    assert_eq!(mode_of(state.dir()), 0o700);
}

/// **One that already existed too** -- the same case as with the store.
#[test]
fn an_existing_desired_state_is_tightened_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = dir.path().join("desired");
    std::fs::create_dir_all(&cache).expect("the old stock");
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).expect("open");

    let _state = tg_runtime::state::DesiredState::open(dir.path()).expect("the desired state");

    assert_eq!(mode_of(&cache), 0o700);
}

/// **And the volumes** -- an application's state lies behind an image.
///
/// Since ADR-0113 it is encrypted; **existing** plaintext volumes stay,
/// however, and the directory counts for exactly those.
#[test]
fn the_volume_store_is_not_world_traversable() {
    let dir = tempfile::tempdir().expect("tempdir");

    let _volumes = tg_runtime::volume::VolumeStore::open(dir.path()).expect("the volumes");

    assert_eq!(mode_of(&dir.path().join("volumes")), 0o700);
}

/// **The root carries the protection for everything below it** (ADR-0115,
/// determination 3).
///
/// It is the effective part: what lies under a directory nobody may enter is
/// protected even when somebody later adds a subdirectory and forgets the
/// sealing.
#[test]
fn the_data_dir_itself_is_sealed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("tardigrade");
    std::fs::create_dir_all(&root).expect("the directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("open");

    tg_runtime::NodePaths::new(&root).seal();

    assert_eq!(mode_of(&root), 0o700);
}

/// **A data directory that does not exist is not created.**
///
/// `seal` is a safeguard and no producer: a path holder that lays out
/// directories in passing would do so on a typo in `--data-dir` too -- and the
/// operator would afterwards look for their state in a directory they never
/// meant.
#[test]
fn sealing_does_not_create_a_missing_data_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("does-not-exist");

    tg_runtime::NodePaths::new(&missing).seal();

    assert!(!missing.exists());
}

/// **What is sealed is the directory, not the file** (ADR-0115,
/// determination 2).
///
/// That is the assurance a whole node's mesh hangs on: three files from
/// `network/` are mounted read-only into the sidecar container, and that one
/// runs as 65532 (ADR-0060). A bind mount does not hang on the host's parent
/// path -- so the directory protects without taking anything from the
/// container. Whoever sealed the files here too would take the sidecar's edges
/// from it.
#[test]
fn sealing_a_directory_leaves_its_files_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let network = dir.path().join("network");
    std::fs::create_dir_all(&network).expect("the directory");
    let edges = network.join("may-talk");
    std::fs::write(&edges, "api -> ledger\n").expect("the file");
    std::fs::set_permissions(&edges, std::fs::Permissions::from_mode(0o644))
        .expect("the permissions");

    tg_runtime::content::seal_soft(&network, "the network directory");

    assert_eq!(mode_of(&network), 0o700);
    assert_eq!(
        mode_of(&edges),
        0o644,
        "the sidecar runs as 65532 and reads this file"
    );
}

/// **The permissions in the layer stay as the image means them.**
///
/// The counter-check to the bar: it sits at the root and does not touch what
/// the container sees. Whoever stripped the setuid bit here would change the
/// image's meaning -- and that would be a decision, no safeguard.
#[test]
fn the_modes_inside_a_layer_are_the_images_own() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = tg_runtime::content::ContentStore::open(dir.path()).expect("store");

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(1);
    header.set_mode(0o4755);
    header.set_cksum();
    builder
        .append_data(&mut header, "bin/suid", &b"x"[..])
        .expect("tar");
    let blob = builder.into_inner().expect("tar");

    let digest = tg_runtime::content::Digest256::of(&blob);
    let layer = store
        .unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", &blob)
        .expect("unpacked");

    assert_eq!(
        std::fs::metadata(layer.join("bin").join("suid"))
            .expect("there")
            .permissions()
            .mode()
            & 0o7777,
        0o4755,
        "the permissions in the layer belong to the image"
    );
}

/// **And a foreign user really does not get in** (ADR-0017).
///
/// Up to here the **mode** was checked and not the **access attempt** -- that
/// stood as an open point at this step. The difference is no formality: `0700`
/// on a directory is a number, and that the kernel makes a bar out of it hangs
/// on things a number does not show -- a `chmod` at another place, an ACL
/// entry, a group membership.
///
/// What is measured is therefore what a local user **does**: `runuser -u
/// nobody` tries to read the file under the layer. The same yardstick as with
/// `dig` in 9c and `curl` in 10d -- foreign code at the place where the
/// assurance applies.
///
/// **Both halves in one test**, and the first carries: `root` reads it.
/// Without it this setup would get its `Permission denied` from a file that
/// does not exist too, or from a `runuser` that does not start at all.
#[test]
#[ignore = "demands root (for runuser) and a user `nobody`; runs with `cargo xtask storage`"]
fn an_unprivileged_user_cannot_read_the_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("content");
    let deep = root.join("layers/sha256/deadbeef");
    std::fs::create_dir_all(&deep).expect("the directory");
    let secret = deep.join("bin/suid");
    std::fs::create_dir_all(secret.parent().expect("the parent")).expect("the directory");
    std::fs::write(&secret, b"from an image").expect("the file");

    // The bolt sits at the **root** -- and only there. Everything below keeps
    // the permissions a layer brings along, and that is the point.
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o755))
        .expect("the permissions");
    tg_runtime::content::seal(&root, "the content store").expect("sealed");

    // And the temp directory above must be traversable, otherwise the test
    // would check `tempfile`'s permissions instead of ours.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("the permissions");

    let path = secret.to_str().expect("the path");

    // **The first half**: as `root` it reads.
    assert_eq!(
        std::fs::read(&secret).expect("root reads"),
        b"from an image",
        "without this half the second says nothing"
    );

    // **The second**: as `nobody` it does not.
    let out = std::process::Command::new("runuser")
        .args(["-u", "nobody", "--", "cat", path])
        .output()
        .expect("runuser");
    let complaint = String::from_utf8_lossy(&out.stderr).into_owned();

    assert!(
        !out.status.success(),
        "a foreign user read the file -- then `0700` at the root is a number \
         and no bar: {complaint}"
    );
    assert!(
        complaint.contains("Permission denied") || complaint.contains("Keine Berechtigung"),
        "the reason must be the permissions and not a missing path: {complaint}"
    );
}

/// **And a foreign user really no longer reads the desired state**
/// (ADR-0115).
///
/// The same setup as with the store above, and for the same reason: `0700` is
/// a number, and that the kernel makes a bar out of it is shown only by a
/// `runuser -u nobody`.
///
/// What would be read here is not just any file: it is the node's wanted state
/// -- images, ports, volumes, dependencies -- and over the same directory
/// permission beside it the `may_talk` edges, the egress permissions, the
/// `WireGuard` peers and the cluster's address plan. Measured, before ADR-0115
/// that worked with every account on the machine.
#[test]
#[ignore = "demands root (for runuser) and a user `nobody`; runs with `cargo xtask storage`"]
fn an_unprivileged_user_cannot_read_the_desired_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The temp directory above must be traversable, otherwise the test would
    // check `tempfile`'s permissions instead of ours.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("the permissions");

    let state = tg_runtime::state::DesiredState::open(dir.path()).expect("the desired state");
    let entry = state.dir().join("api.xml");
    std::fs::write(&entry, "<workloads/>").expect("the file");
    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o644))
        .expect("the permissions");

    let path = entry.to_str().expect("the path");

    // **The first half**: as `root` it reads. Without it this setup would get
    // its `Permission denied` from a file that does not exist too.
    assert_eq!(
        std::fs::read_to_string(&entry).expect("root reads"),
        "<workloads/>",
        "without this half the second says nothing"
    );

    // **The second**: as `nobody` it does not -- although the file itself
    // carries `0644`. The bolt sits at the directory (determination 2).
    let out = std::process::Command::new("runuser")
        .args(["-u", "nobody", "--", "cat", path])
        .output()
        .expect("runuser");
    let complaint = String::from_utf8_lossy(&out.stderr).into_owned();

    assert!(
        !out.status.success(),
        "a foreign user read the desired state: {complaint}"
    );
    assert!(
        complaint.contains("Permission denied") || complaint.contains("Keine Berechtigung"),
        "the reason must be the permissions and not a missing path: {complaint}"
    );
}
