//! Whiteouts on unpacking (ADR-0052).
//!
//! The finding that led to the ADR was larger than the note from phase 10c:
//! `Content::unpack_layer` serves the shared volumes **and** the container
//! images -- exactly that was 10c's point, one store and one mechanism -- and
//! both mount the layers as overlayfs `lowerdir=`. A deletion that does not
//! take effect therefore concerned every multi-layer image since phase 2, and
//! deleting is a usual operation in images with a security intention.
//!
//! # Why all the tests need privileges
//!
//! A character device demands `CAP_MKNOD`, a `trusted.` xattr demands
//! `CAP_SYS_ADMIN` (ADR-0017: the agent has both). There is no refusal half
//! here that would be checkable without rights -- that is why the file is
//! wholly `#[ignore]` and runs with `cargo xtask storage`.
//!
//! # The order of the tests is the order of the burden of proof
//!
//! The first four look at **what lies in the store**. The last two ask what it
//! is about: **whether a deletion takes effect** -- over real overlayfs, not
//! over the form of the translation. A test that checks only the form
//! witnesses the translation; it does not witness that the kernel understands
//! it.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use tg_runtime::content::{ContentStore, Digest256};

/// Builds an uncompressed layer tar.
///
/// Uncompressed, because the compression contributes nothing here:
/// `decompress` has tests of its own, and a gzip frame around the same bytes
/// only obscures what the test actually says.
struct Tar {
    builder: tar::Builder<Vec<u8>>,
}

impl Tar {
    fn new() -> Self {
        Self {
            builder: tar::Builder::new(Vec::new()),
        }
    }

    fn file(mut self, path: &str, content: &[u8]) -> Self {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        self.builder
            .append_data(&mut header, path, content)
            .expect("the entry must be appendable");
        self
    }

    fn dir(mut self, path: &str) -> Self {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        self.builder
            .append_data(&mut header, path, std::io::empty())
            .expect("the directory must be attachable");
        self
    }

    fn bytes(self) -> Vec<u8> {
        self.builder.into_inner().expect("the tar must close")
    }
}

/// Unpacks a layer tar into a fresh store and gives its directory.
fn unpacked(store: &ContentStore, tar: &[u8]) -> PathBuf {
    // The digest over the bytes: that way every layer gets its own directory
    // without the test having to invent names.
    let digest = Digest256::of(tar);
    store
        .unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", tar)
        .expect("the layer must be unpackable")
}

fn store(dir: &Path) -> ContentStore {
    ContentStore::open(dir).expect("the store must be openable")
}

fn opaque(dir: &Path) -> Option<Vec<u8>> {
    let mut buf = vec![0_u8; 64];
    match rustix::fs::getxattr(dir, "trusted.overlay.opaque", &mut buf) {
        Ok(len) => {
            buf.truncate(len);
            Some(buf)
        }
        Err(_) => None,
    }
}

// ============================================== what lies in the store

/// `.wh.<name>` becomes a character device 0:0, and the marker itself does
/// **not** stay lying: it is a setting about the layer, no file of the
/// image.
#[test]
#[ignore = "demands CAP_MKNOD -- cargo xtask storage"]
fn a_whiteout_becomes_a_character_device_and_the_marker_is_gone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let layer = unpacked(
        &store,
        &Tar::new()
            .file("stays", b"there")
            .file(".wh.secret", b"")
            .bytes(),
    );

    let hidden = layer.join("secret");
    let meta = std::fs::symlink_metadata(&hidden).expect("the whiteout must exist");
    assert!(
        meta.file_type().is_char_device(),
        "the whiteout must be a character device, is {:?}",
        meta.file_type()
    );
    assert_eq!(
        meta.rdev(),
        0,
        "overlayfs recognizes only 0:0 as a whiteout"
    );

    assert!(
        !layer.join(".wh.secret").exists(),
        "the marker itself must not stay lying as a file -- otherwise the \
         container sees a file that does not exist in the image"
    );

    // Counter-check: the translation does not spread.
    assert_eq!(
        std::fs::read(layer.join("stays")).expect("the other file must be there"),
        b"there"
    );
}

/// `.wh..wh..opq` becomes `trusted.overlay.opaque` on the **containing**
/// directory.
#[test]
#[ignore = "demands CAP_SYS_ADMIN -- cargo xtask storage"]
fn an_opaque_marker_becomes_an_extended_attribute_and_the_marker_is_gone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let layer = unpacked(
        &store,
        &Tar::new()
            .dir("etc/")
            .file("etc/.wh..wh..opq", b"")
            .file("etc/new", b"content")
            .bytes(),
    );

    assert_eq!(
        opaque(&layer.join("etc")).as_deref(),
        Some(b"y".as_slice()),
        "the directory must be marked as opaque"
    );
    assert!(
        !layer.join("etc/.wh..wh..opq").exists(),
        "the marker itself must not stay lying"
    );

    // Counter-check: only the named directory, not the root.
    assert_eq!(
        opaque(&layer),
        None,
        "the opacity applies to the containing directory, not to the layer"
    );
}

/// The translation goes into the depth -- a whiteout rarely lies in the
/// root.
#[test]
#[ignore = "demands CAP_MKNOD -- cargo xtask storage"]
fn a_whiteout_in_a_nested_directory_is_translated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let layer = unpacked(
        &store,
        &Tar::new()
            .dir("var/")
            .dir("var/cache/")
            .file("var/cache/.wh.credentials", b"")
            .bytes(),
    );

    let hidden = layer.join("var/cache/credentials");
    let meta = std::fs::symlink_metadata(&hidden).expect("the whiteout must exist");
    assert!(meta.file_type().is_char_device());
    assert!(!layer.join("var/cache/.wh.credentials").exists());
}

/// The convention is a **prefix**, no resemblance.
///
/// `.wh.` and nothing else. `.whisky` begins with `.wh` and is an ordinary
/// file; whoever writes `starts_with(".wh")` here deletes it. And `wh.foo`
/// without a dot is certainly no marker.
#[test]
#[ignore = "demands CAP_MKNOD -- cargo xtask storage"]
fn a_name_that_merely_resembles_a_whiteout_is_left_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let layer = unpacked(
        &store,
        &Tar::new()
            .file(".whisky", b"peat")
            .file("wh.foo", b"no dot")
            .file(".wh.real", b"")
            .bytes(),
    );

    for harmless in [".whisky", "wh.foo"] {
        let meta = std::fs::symlink_metadata(layer.join(harmless))
            .unwrap_or_else(|err| panic!("{harmless} must still be there: {err}"));
        assert!(
            meta.file_type().is_file(),
            "{harmless} is no whiteout marker and must stay a file"
        );
    }

    // Counter-check in the same layer: the real marker was translated. Without
    // it the test would be green even if the translation did not run at all.
    assert!(
        std::fs::symlink_metadata(layer.join("real"))
            .expect("the real marker must be translated")
            .file_type()
            .is_char_device()
    );
}

// ======================================= whether the deletion takes effect

/// A guard that unmounts even when an assertion fails.
struct Overlay(PathBuf);

impl Overlay {
    fn mount(layers: &[&Path], at: &Path) -> Self {
        // `lowerdir=` expects the topmost layer first -- the same reversal
        // as in `bundle.rs` and `volume.rs`.
        let mut lower: Vec<PathBuf> = layers.iter().map(|p| p.to_path_buf()).collect();
        lower.reverse();
        tg_syscall::mount::mount_overlay_readonly(&lower, at).expect("the overlay must mount");
        Self(at.to_path_buf())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Overlay {
    fn drop(&mut self) {
        let _ = tg_syscall::mount::unmount_overlay(&self.0);
    }
}

/// **The test it is all about.**
///
/// Not the form of the translation but its effect: what a later layer deletes
/// the container does not see. That is the state ADR-0052 produces -- before,
/// the file still lay in the store, and a key somebody removed in a build
/// layer was there.
#[test]
#[ignore = "demands CAP_SYS_ADMIN (mount) and CAP_MKNOD -- cargo xtask storage"]
fn a_file_deleted_in_a_later_layer_is_not_visible_through_the_overlay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let lower = unpacked(
        &store,
        &Tar::new()
            .file("secret", b"key")
            .file("stays", b"harmless")
            .bytes(),
    );
    let upper = unpacked(&store, &Tar::new().file(".wh.secret", b"").bytes());

    let target = tempfile::tempdir().expect("tempdir");
    let overlay = Overlay::mount(&[&lower, &upper], target.path());

    assert!(
        !overlay.path().join("secret").exists(),
        "the deleted file must not shine through"
    );

    // Counter-check, and it carries the test: without it it would be green
    // even if the mount had gone wrong and the point were simply empty.
    assert_eq!(
        std::fs::read(overlay.path().join("stays")).expect("the rest must be visible"),
        b"harmless"
    );
}

/// An opaque directory **replaces** the one below it instead of supplementing
/// it.
#[test]
#[ignore = "demands CAP_SYS_ADMIN (mount and xattr) -- cargo xtask storage"]
fn an_opaque_directory_replaces_what_the_lower_layer_put_there() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let lower = unpacked(
        &store,
        &Tar::new().dir("etc/").file("etc/old", b"stale").bytes(),
    );
    let upper = unpacked(
        &store,
        &Tar::new()
            .dir("etc/")
            .file("etc/.wh..wh..opq", b"")
            .file("etc/new", b"current")
            .bytes(),
    );

    let target = tempfile::tempdir().expect("tempdir");
    let overlay = Overlay::mount(&[&lower, &upper], target.path());

    assert!(
        !overlay.path().join("etc/old").exists(),
        "an opaque directory does not let the old content through"
    );
    assert_eq!(
        std::fs::read(overlay.path().join("etc/new")).expect("the new content must be there"),
        b"current"
    );
}

// ================================================= the trust boundary

/// **A regression test for the find made while building ADR-0052.**
///
/// Cutting `.wh.` off and appending the result yields the name `..` for
/// `.wh...`. The old way would have called `remove_dir_all` on that -- with a
/// layer in the root, therefore, on **all the node's unpacked layers**,
/// triggered by a file name in an image from a foreign registry. `.wh.` alone
/// yields the empty name, that is, the layer directory itself.
///
/// What is checked is not the refusal -- that stands as a unit test beside
/// `classify` -- but its **effect**: the witness beside it survives. Without it
/// the test would be green even if only the error message were right.
#[test]
#[ignore = "demands CAP_MKNOD -- cargo xtask storage"]
fn a_marker_pointing_out_of_the_layer_leaves_the_neighbourhood_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    // A real layer beside it -- that is what would have been lost.
    let neighbour = unpacked(&store, &Tar::new().file("valuable", b"content").bytes());

    for hostile in [".wh...", ".wh."] {
        let tar = Tar::new().file(hostile, b"").bytes();
        let digest = Digest256::of(&tar);
        let outcome = store.unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", &tar);

        assert!(
            outcome.is_err(),
            "'{hostile}' must refuse the layer, not be bent into shape"
        );
        assert!(
            !store.has_layer(&digest),
            "'{hostile}': a refused layer must not count as complete"
        );
        assert_eq!(
            std::fs::read(neighbour.join("valuable")).unwrap_or_default(),
            b"content",
            "'{hostile}' touched the neighbouring layer"
        );
    }
}

// ==================================================== the upgrade

/// **A layer from the time before ADR-0052 does not count as complete.**
///
/// That was that ADR's open point, and without it it would have migrated into
/// the operations manual: whoever upgrades would have had to clear the layer
/// part of the store away by hand -- otherwise a container still shows files
/// its image has deleted. A manual step an operator *must* take is one
/// somebody eventually does not take.
///
/// What is checked is the effect and not the marker: the whiteout is
/// **translated** afterwards, so the layer was really unpacked anew.
#[test]
#[ignore = "demands CAP_MKNOD -- cargo xtask storage"]
fn a_layer_from_before_the_translation_is_unpacked_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let tar = Tar::new().file(".wh.secret", b"").bytes();
    let digest = Digest256::of(&tar);

    // The old form reproduced by hand: unpacked, but without the translation,
    // and with the empty marker that existed until ADR-0052.
    let layer = store.layer_path(&digest);
    std::fs::create_dir_all(&layer).expect("the layer directory");
    std::fs::write(layer.join(".wh.secret"), b"").expect("the old marker");
    std::fs::write(layer.join(".complete"), b"").expect("the old completion marker");

    assert!(
        !store.has_layer(&digest),
        "a layer of the old version must not count as complete"
    );

    let again = unpacked(&store, &tar);

    assert!(
        std::fs::symlink_metadata(again.join("secret"))
            .expect("the whiteout must be there now")
            .file_type()
            .is_char_device(),
        "the layer was not unpacked anew"
    );
    assert!(
        !again.join(".wh.secret").exists(),
        "the old marker still lies there"
    );
    assert!(store.has_layer(&digest), "afterwards it counts as complete");
}

/// A layer of the **current** version is not unpacked a second time.
///
/// The counter-check to the test above: without it it would only prove that
/// something is unpacked anew -- and a version check that *always* unpacks
/// anew would take the store's purpose from it.
#[test]
#[ignore = "demands CAP_MKNOD -- cargo xtask storage"]
fn a_layer_of_the_current_format_is_left_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let tar = Tar::new().file("content", b"one").bytes();
    let layer = unpacked(&store, &tar);

    // A file that does not stand in the tar: it survives precisely when
    // nothing was unpacked anew.
    std::fs::write(layer.join("witness"), b"there").expect("the witness");
    unpacked(&store, &tar);

    assert!(
        layer.join("witness").is_file(),
        "the layer was unpacked anew unnecessarily"
    );
}

/// **Hardlinks across layer boundaries fail loudly** -- measured, not
/// decided.
///
/// ADR-0052 names them as a related, unmeasured case. Measured, it is no quiet
/// falsehood as with the whiteouts: a hardlink onto a target this layer does
/// not bring along makes the unpacking **fail**, and the layer does not count
/// as complete. The OCI convention demands anyway that a hardlink stay within
/// its layer.
///
/// The test stands here so that the loud failure does not unnoticed become a
/// quiet one.
#[test]
fn a_hardlink_out_of_its_layer_fails_loudly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Link);
    header.set_cksum();
    builder
        .append_link(&mut header, "new", "missing/in/this/layer")
        .expect("the entry");
    let tar = builder.into_inner().expect("the tar");

    let digest = Digest256::of(&tar);
    assert!(
        store
            .unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", &tar)
            .is_err(),
        "a hardlink into nothing must refuse the layer"
    );
    assert!(
        !store.has_layer(&digest),
        "a failed layer must not count as complete"
    );
}
