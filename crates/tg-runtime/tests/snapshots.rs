//! Snapshot and restore of a volume (ADR-0099).
//!
//! Written before the implementation, and divided into two halves -- by what
//! the matter demands, not by convenience:
//!
//! - **Without privileges** runs everything that concerns a volume at rest:
//!   the copying of the image, the selection when clearing away, the marker,
//!   and every refusal. A snapshot is a file copy -- as long as the volume is
//!   not mounted, no loop device and no freeze occur.
//! - **With privileges** runs the part that carries the assurance: the freeze
//!   under write load, and that the snapshot is mountable and carries the
//!   data. `#[ignore]`, run with `cargo xtask storage`.
//!
//! # Why the confirmation stands at the restore and not at the snapshot
//!
//! The asymmetry is ADR-0099's decision. A snapshot is **additive** -- making
//! it twice costs room and nothing else. A restore is **destructive** and
//! therefore carries the same two bolts as `delete`: unmounted and expressly
//! confirmed.

use tg_runtime::volume::{Confirmation, VolumeError, VolumeStore};

fn store(dir: &std::path::Path) -> VolumeStore {
    VolumeStore::open(dir)
        .expect("the store must be openable")
        // Since ADR-0113 every writable volume is encrypted; without a
        // derivation none arises (determination 5). **A snapshot thereby
        // carries ciphertext** -- and that is the right direction: one that
        // carried the plaintext would lift the assurance itself.
        .keyed(Some(std::sync::Arc::new(|volume: &str| {
            Some(tg_runtime::volume::Passphrases {
            current: format!("passphrase-for-{volume}"),
            previous: None,
        })
        })))
}

/// Lays out a volume with an image, without `mkfs`.
///
/// `provision` needs `losetup` and `mkfs.ext4`; what is checked here is the
/// snapshot mechanism and not the creation of a file system. The image
/// therefore carries a recognizable content instead of a real ext4.
fn with_image(store: &VolumeStore, name: &str, content: &[u8]) -> std::path::PathBuf {
    let info = store
        .declare(name, tg_runtime::volume::MIN_BYTES)
        .expect("the volume must be declarable");
    assert_eq!(info.name, name);

    let image = store.image_of(name).expect("the path must be formable");
    std::fs::write(&image, content).expect("the image must be writable");
    image
}

// ============================================ checkable without privileges

/// The core: the snapshot is a complete copy of the image.
#[test]
fn a_snapshot_is_a_full_copy_of_the_image() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());
    with_image(&store, "data", b"the stand of back then");

    let snap = store
        .snapshot("data", 1, 0)
        .expect("the snapshot must succeed");

    assert_eq!(snap.generation, 1, "the generation must be taken over");
    assert_eq!(
        snap.bytes,
        "the stand of back then".len() as u64,
        "the snapshot must be as large as the image"
    );

    // **The content counts, not the presence.** An empty file at the right
    // place would pass every assertion about paths.
    let raw = std::fs::read(&snap.path).expect("the snapshot must be readable");
    assert_eq!(
        raw, b"the stand of back then",
        "the snapshot must carry the image's stand"
    );
}

/// The marker is the answer to "has this generation already been
/// executed".
#[test]
fn the_mark_follows_the_snapshot_and_survives_a_restart() {
    let dir = tempfile::tempdir().expect("temp");

    {
        let store = store(dir.path());
        with_image(&store, "data", b"x");

        assert_eq!(
            store.snapshot_mark("data"),
            0,
            "without a snapshot no generation must be claimed"
        );

        store.snapshot("data", 7, 0).expect("the snapshot");
        assert_eq!(store.snapshot_mark("data"), 7);
    }

    // A second store on the same directory -- like a restart of the agent.
    // Without the marker on the disk it would make the snapshot again.
    let again = store(dir.path());
    assert_eq!(
        again.snapshot_mark("data"),
        7,
        "the marker must survive the restart"
    );
}

/// Clearing away goes by generation, and the youngest stay.
#[test]
fn keeping_three_removes_the_oldest() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());
    with_image(&store, "data", b"x");

    for generation in 1..=5 {
        store
            .snapshot("data", generation, 3)
            .expect("the snapshot must succeed");
    }

    let held: Vec<u64> = store
        .snapshots("data")
        .expect("the list")
        .into_iter()
        .map(|snap| snap.generation)
        .collect();

    assert_eq!(
        held,
        vec![3, 4, 5],
        "the three youngest generations must stay"
    );
}

/// Zero means keep -- the default must not clear away secretly.
#[test]
fn keeping_zero_removes_nothing() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());
    with_image(&store, "data", b"x");

    for generation in 1..=4 {
        store.snapshot("data", generation, 0).expect("the snapshot");
    }

    assert_eq!(
        store.snapshots("data").expect("the list").len(),
        4,
        "with keep=0 nothing must be cleared away"
    );
}

/// The restore overwrites -- and secures beforehand what it overwrites.
#[test]
fn a_restore_overwrites_and_keeps_the_replaced_state() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());
    let image = with_image(&store, "data", b"the old stand");

    store.snapshot("data", 1, 0).expect("the snapshot");
    std::fs::write(&image, b"the new stand").expect("the image must be changeable");

    let replaced = store
        .restore("data", 1, &Confirmation::of("data"))
        .expect("the restore must succeed");

    assert_eq!(
        std::fs::read(&image).expect("the image"),
        b"the old stand",
        "the restore must write the snapshot back"
    );

    // **The trace the restore leaves** (ADR-0099, determination 6): it stands
    // in no log, so the overwritten state must be preserved -- otherwise the
    // operation is irreversible and unsubstantiated.
    assert_eq!(
        std::fs::read(&replaced.path).expect("the before-snapshot"),
        b"the new stand",
        "the overwritten stand must be secured"
    );
    assert!(
        replaced.generation > 1,
        "the before-snapshot needs a higher generation of its own, otherwise \
         it overwrites the one being restored from"
    );
}

/// A generation that does not exist is named and not guessed.
#[test]
fn an_unknown_generation_cannot_be_restored() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());
    with_image(&store, "data", b"x");
    store.snapshot("data", 1, 0).expect("the snapshot");

    let err = store
        .restore("data", 9, &Confirmation::of("data"))
        .expect_err("a generation that does not exist must restore nothing");

    match err {
        VolumeError::NoSnapshot { name, generation } => {
            assert_eq!(name, "data");
            assert_eq!(generation, 9);
        }
        other => panic!("expected NoSnapshot, got: {other:?}"),
    }
}

/// The confirmation carries the name of the volume it means.
#[test]
fn a_confirmation_for_another_volume_does_not_restore_this_one() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());
    let image = with_image(&store, "data", b"the old stand");
    store.snapshot("data", 1, 0).expect("the snapshot");
    std::fs::write(&image, b"the new stand").expect("the image");

    let err = store
        .restore("data", 1, &Confirmation::of("something-else"))
        .expect_err("a foreign confirmation must not restore");

    assert!(matches!(err, VolumeError::NotConfirmed { .. }));
    assert_eq!(
        std::fs::read(&image).expect("the image"),
        b"the new stand",
        "a refused restore must not touch the image"
    );
}

/// A mounted volume is not overwritten.
#[test]
fn a_mounted_volume_is_not_restorable() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());
    with_image(&store, "data", b"x");
    store.snapshot("data", 1, 0).expect("the snapshot");
    store
        .note_mounted("data", "/dev/loop-does-not-exist")
        .expect("the record");

    let err = store
        .restore("data", 1, &Confirmation::of("data"))
        .expect_err("a mounted volume must not be overwritten");

    assert!(matches!(err, VolumeError::Mounted { .. }));
}

/// A volume without an image can have no snapshot.
#[test]
fn a_volume_without_an_image_gives_no_snapshot() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());
    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("the declaration");

    let err = store
        .snapshot("data", 1, 0)
        .expect_err("without an image there is nothing to copy");

    assert!(
        matches!(err, VolumeError::Disk { .. }),
        "expected a disk problem, got: {err:?}"
    );
}

/// A volume that does not exist is named.
#[test]
fn an_unknown_volume_is_named_when_snapshotting() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());

    let err = store
        .snapshot("does-not-exist", 1, 0)
        .expect_err("an unknown volume must get no snapshot");

    match err {
        VolumeError::Unknown { name } => assert_eq!(name, "does-not-exist"),
        other => panic!("expected Unknown, got: {other:?}"),
    }
}

// ========================================= with privileges: the assurance

/// Mounts a snapshot to look into it -- and unmounts it again, even when the
/// test fails.
///
/// A left-behind loop device and a left-behind mount hold the temp directory
/// fast until somebody finds the full disk. The `Drop` is therefore no
/// ornament; the same discipline as in `userns_path.rs`.
struct Opened {
    device: String,
    at: std::path::PathBuf,
}

impl Opened {
    /// Opens a snapshot to look into it.
    ///
    /// **Over `cryptsetup`, not over `losetup`** -- since ADR-0113 a snapshot
    /// is the copy of a LUKS image and thereby carries **ciphertext**. That is
    /// the right direction: one that carried the plaintext would lift the
    /// assurance itself. The witness measured it instead of believing it --
    /// before, it failed with `unknown filesystem type 'crypto_LUKS'`.
    ///
    /// The price stands in ADR-0113: a restore on a cluster with a different
    /// data key fails. That too is the point.
    fn open(image: &std::path::Path, at: std::path::PathBuf) -> Self {
        let mapper = format!("tgsnap-{}", std::process::id());
        let mut child = std::process::Command::new("cryptsetup")
            .args(["open", "--key-file", "-"])
            .arg(image)
            .arg(&mapper)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("cryptsetup");
        {
            use std::io::Write as _;
            let mut stdin = child.stdin.take().expect("stdin");
            stdin
                .write_all(b"passphrase-for-data")
                .expect("the passphrase");
        }
        assert!(child.wait().expect("cryptsetup").success(), "unlock");
        let device = format!("/dev/mapper/{mapper}");

        std::fs::create_dir_all(&at).expect("the mount point");
        let out = std::process::Command::new("mount")
            .arg(&device)
            .arg(&at)
            .output()
            .expect("mount");
        assert!(
            out.status.success(),
            "the snapshot must be mountable: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        Self { device, at }
    }

    /// How many files the snapshot carries.
    fn files(&self) -> usize {
        std::fs::read_dir(&self.at)
            .expect("the mount")
            .flatten()
            .filter(|entry| entry.file_name() != "lost+found")
            .count()
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount").arg(&self.at).status();
        // Close, do not detach: what `open` took is a mapper.
        if let Some(mapper) = self.device.strip_prefix("/dev/mapper/") {
            let _ = std::process::Command::new("cryptsetup")
                .args(["close", mapper])
                .status();
        }
    }
}

/// ADR-0099's assurance: the snapshot of a **mounted** volume carries the
/// application's stand, not the disk's.
///
/// That is the test for whose sake the freeze exists. Measured without it, the
/// snapshot contains a fraction of the files -- not merely inconsistent,
/// almost empty. The number therefore stands here as a lower bound and not as
/// "more than zero".
#[test]
#[ignore = "demands losetup, mkfs.ext4, mount and fsfreeze"]
fn a_snapshot_under_load_carries_what_the_application_wrote() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());

    store
        .provision("data", 256 << 20)
        .expect("the volume must be creatable");
    let mount = store.mount("data").expect("the volume must mount");

    // Write load that runs while the snapshot arises. 200 files of 256 KiB
    // each -- enough that the page cache does not keep up by itself.
    let written = std::thread::scope(|scope| {
        let load = scope.spawn(|| {
            let payload = vec![0x5au8; 256 << 10];
            let mut count = 0usize;
            for i in 0..200 {
                if std::fs::write(mount.join(format!("f{i}")), &payload).is_ok() {
                    count += 1;
                }
            }
            count
        });

        // Right into the middle of the load.
        std::thread::sleep(std::time::Duration::from_millis(150));
        store
            .snapshot("data", 1, 0)
            .expect("a snapshot of a mounted volume must succeed");

        load.join().expect("the load")
    });

    assert!(
        written > 100,
        "the setup must produce real load, written: {written}"
    );

    // **The freeze must have released again.** Otherwise the next writer
    // hangs, and this call is the witness for it.
    std::fs::write(mount.join("after-the-snapshot"), b"x")
        .expect("after the snapshot it must be writable again");

    store.unmount("data").expect("unmount");
    let snap = &store.snapshots("data").expect("the list")[0];
    let opened = Opened::open(&snap.path, dir.path().join("look"));

    // Measured: **without** the freeze it is 12 of 412. The bound thereby
    // separates sharply without depending on the exact number the cache had
    // just written.
    let carried = opened.files();
    assert!(
        carried > 50,
        "the snapshot carries only {carried} files -- without the freeze the \
         image on the disk lies far behind what the application did"
    );

    // And it is a clean file system: `mount` accepted it, and `e2fsck` finds
    // nothing to repair.
    let fsck = std::process::Command::new("e2fsck")
        .args(["-fn", &opened.device])
        .output()
        .expect("e2fsck");
    assert!(
        fsck.status.success(),
        "e2fsck must hold the snapshot to be clean: {}",
        String::from_utf8_lossy(&fsck.stdout)
    );
}

/// The counter-direction: a restore brings a real file system back, and the
/// file that arose after the snapshot is gone afterwards.
#[test]
#[ignore = "demands losetup, mkfs.ext4 and mount"]
fn a_restore_brings_back_the_filesystem_of_its_snapshot() {
    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());

    store.provision("data", 32 << 20).expect("lay out");
    let mount = store.mount("data").expect("mount");
    std::fs::write(mount.join("before"), b"old").expect("write");
    store.unmount("data").expect("unmount");

    store.snapshot("data", 1, 0).expect("the snapshot");

    // Write something else in after the snapshot.
    let mount = store.mount("data").expect("mount again");
    std::fs::write(mount.join("after"), b"new").expect("write");
    store.unmount("data").expect("unmount");

    store
        .restore("data", 1, &Confirmation::of("data"))
        .expect("the restore");

    let mount = store.mount("data").expect("mounting after the restore");
    assert!(
        mount.join("before").is_file(),
        "the snapshot's stand must be back"
    );
    assert!(
        !mount.join("after").is_file(),
        "what arose after the snapshot must be gone -- otherwise the restore \
         restored nothing"
    );
    store.unmount("data").expect("unmount");
}

/// **A volume that stayed behind frozen thaws at the start.**
///
/// The case is measured and not imagined: the release hangs on `Thaw::thaw`
/// or -- on the panic path -- on its `Drop`, and a **signal** reaches neither
/// of the two. What that costs is more than a blockade: a writer on a frozen
/// file system sits in the **D state** and is thereby unkillable -- measured
/// on a real ext4 on a loop device, where `timeout` did not give up and only
/// the thaw let the writer carry on.
///
/// What is checked is the **effect** and not the return value: after
/// `thaw_all` a writer must get through. A test on `Ok(1)` would prove that
/// `fsfreeze` ended with 0, not that the volume is usable.
///
/// The counter-direction stands beside it and carries half the assurance: a
/// volume that is **not** frozen is not counted -- otherwise a `thaw_all` that
/// reports every volume as thawed would be green too, and the warning in the
/// log would appear at every start.
#[test]
#[ignore = "demands losetup, mkfs.ext4, mount and fsfreeze"]
fn a_volume_left_frozen_thaws_on_start() {
    // A guard that thaws, unmounts **and detaches the loop device**, even
    // when the test turns red: a frozen volume would otherwise hold its temp
    // directory fast, and a writer on it is unkillable. `output()` and not
    // `status()`, so that the expected `EINVAL` does not stand in the test
    // output.
    //
    // **The detaching belongs to it**, and it was missing here: measured, this
    // witness left a `/dev/loopN` on a deleted file behind after a green run.
    // It is the same error the same session has already fixed once -- `umount`
    // without `losetup --detach` -- and the third kind of remnant, after
    // overlayfs and tmpfs.
    struct Thawed(std::path::PathBuf, Option<String>);
    impl Drop for Thawed {
        fn drop(&mut self) {
            let _ = std::process::Command::new("fsfreeze")
                .args(["--unfreeze", &self.0.to_string_lossy()])
                .output();
            let _ = std::process::Command::new("umount").arg(&self.0).output();
            // **A mapper or a loop, as the case may be** (ADR-0113). Only
            // `losetup --detach` stood here, and since a volume is a LUKS
            // container that hit nothing: the mapper stayed open and held its
            // loop device fast with `AUTOCLEAR`. The `xtask`'s remnant guard
            // saw it once it knew mappers -- in the concurrent run, not in the
            // single one.
            //
            // It is the same error for the third time in this file, and that
            // is why it stands written out here instead of fixed and
            // forgotten: **a guard must release what it really took**, not
            // what it would have taken at the time of writing.
            if let Some(device) = &self.1 {
                if let Some(mapper) = device.strip_prefix("/dev/mapper/") {
                    let _ = std::process::Command::new("cryptsetup")
                        .args(["close", mapper])
                        .output();
                } else {
                    let _ = std::process::Command::new("losetup")
                        .args(["--detach", device])
                        .output();
                }
            }
        }
    }

    let dir = tempfile::tempdir().expect("temp");
    let store = store(dir.path());

    store
        .provision("data", 64 << 20)
        .expect("the volume must be creatable");
    let mount = store.mount("data").expect("the volume must mount");
    let device = store.info("data").expect("known").device.clone();
    let guard = Thawed(mount.clone(), device);

    // The counter-direction first: not frozen, so nothing to do.
    assert_eq!(
        store.thaw_all().expect("the inventory is readable"),
        0,
        "a volume that is not frozen must not count as thawed -- otherwise \
         the start warns on every run"
    );

    // Now the case: frozen, and the process that did it is gone.
    let frozen = std::process::Command::new("fsfreeze")
        .args(["--freeze", &mount.to_string_lossy()])
        .status()
        .expect("fsfreeze");
    assert!(frozen.success(), "the freeze must succeed");

    assert_eq!(
        store.thaw_all().expect("the inventory is readable"),
        1,
        "the frozen volume must be thawed"
    );

    // **The effect**: a writer gets through. Without the thaw it sits in the D
    // state, and this test hangs instead of failing -- that is why the
    // assertion above stands before it.
    std::fs::write(mount.join("after-the-thaw"), b"x").expect("after the thaw it must be writable");

    drop(guard);
}
