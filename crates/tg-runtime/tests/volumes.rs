//! The local PV lifecycle (ADR-0027 -- phase 10b).
//!
//! Written before the implementation. Two halves under different conditions:
//!
//! - **Without privileges** everything that is a refusal is checkable: the
//!   name as a trust boundary, the confirmation on deletion, the ban on
//!   shrinking, the ban on deleting a mounted volume.
//! - **With privileges** the real path runs: loop device, `mkfs`, mounting,
//!   growing. `#[ignore]`, run with `cargo xtask storage`.
//!
//! # Why the confirmation is a type of its own
//!
//! ADR-0027 demands "delete **explicit and protected**, because destructive".
//! A `bool` would be neither: `delete(name, true)` reads at the call site like
//! any other argument, and a `true` in the wrong place is a typo with data
//! loss. The confirmation therefore carries **the name of the volume** it
//! means -- the same construction as the `NonceVault` from 7b: the discipline
//! lies in the structure, not with the caller.

use tg_runtime::volume::{Confirmation, VolumeError, VolumeStore};

fn store(dir: &std::path::Path) -> VolumeStore {
    VolumeStore::open(dir)
        .expect("the store must be openable")
        .keyed(Some(key()))
}

/// The derivation the agent provides in operation (ADR-0113,
/// determination 4).
///
/// **A fixed key**, so that the assurances hang on numbers and not on chance
/// -- and expressly none from a real environment.
fn key() -> tg_runtime::volume::Derive {
    std::sync::Arc::new(|volume: &str| {
        Some(tg_runtime::volume::Passphrases {
            current: format!("passphrase-for-{volume}"),
            previous: None,
        })
    })
}

/// A store **without** a key -- a node before its first admission.
fn keyless(dir: &std::path::Path) -> VolumeStore {
    VolumeStore::open(dir).expect("the store must be openable")
}

/// **Without a data key no writable volume arises** (ADR-0113,
/// determination 5).
///
/// Fail-closed and express: the quiet way out would be a plaintext disk
/// without a signal. The test needs no privileges -- it never gets as far as
/// the `luksFormat`.
#[test]
fn without_a_data_key_no_writable_volume_is_created() {
    let dir = tempfile::tempdir().expect("tempdir");

    let outcome = keyless(dir.path()).provision("data", 64 << 20);

    assert!(
        matches!(outcome, Err(VolumeError::NoKey { ref name }) if name == "data"),
        "{outcome:?}"
    );
}

/// **And the message names the way**, not only the no.
///
/// An operator who sees a node before its first admission would otherwise look
/// for the error at the volume instead of at the credential path.
#[test]
fn the_refusal_names_the_credential_path() {
    let text = VolumeError::NoKey {
        name: "data".to_owned(),
    }
    .to_string();

    assert!(text.contains("data"), "{text}");
    assert!(text.contains("credential path"), "{text}");
}

// ============================================ checkable without privileges

/// The name becomes a directory name -- the same trust boundary as the
/// namespace name in 9b, and the same answer.
#[test]
fn a_name_that_would_escape_the_directory_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let long = "x".repeat(200);
    for hostile in [
        "",
        ".",
        "..",
        "../../etc",
        "a/b",
        "a\0b",
        "a b",
        long.as_str(),
    ] {
        let err = store
            .declare(hostile, tg_runtime::volume::MIN_BYTES)
            .expect_err("should have been refused");
        assert!(
            matches!(err, VolumeError::IllegalName { .. }),
            "'{}' yielded {err:?}",
            hostile.escape_debug()
        );
    }
}

/// **The confirmation must name the volume it means.**
#[test]
fn a_confirmation_for_another_volume_does_not_delete_this_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());
    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    let err = store
        .delete("data", &Confirmation::of("something-else"))
        .expect_err("the confirmation names another volume");

    assert!(
        matches!(err, VolumeError::NotConfirmed { .. }),
        "expected NotConfirmed, was {err:?}"
    );
    assert!(store.exists("data"), "the volume is gone nevertheless");
}

#[test]
fn the_right_confirmation_deletes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());
    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    store
        .delete("data", &Confirmation::of("data"))
        .expect("with the right confirmation");

    assert!(!store.exists("data"));
}

/// Deleting a mounted volume would mean pulling the ground from under a
/// running container. The kernel would permit it; we do not.
#[test]
fn a_mounted_volume_is_not_deletable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());
    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    store.note_mounted("data", "/dev/loop9").expect("record it");

    let err = store
        .delete("data", &Confirmation::of("data"))
        .expect_err("mounted");

    assert!(
        matches!(err, VolumeError::Mounted { .. }),
        "expected Mounted, was {err:?}"
    );
    assert!(store.exists("data"));
}

/// **Growing yes, shrinking never.**
///
/// Shrinking a file system is the operation that eats data when it goes wrong
/// -- and ADR-0027 demands it nowhere. What one cannot safely undo one does
/// not undo.
#[test]
fn a_volume_never_shrinks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());
    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    let err = store
        .resize("data", 4 << 20)
        .expect_err("shrinking is forbidden");

    assert!(
        matches!(err, VolumeError::WouldShrink { .. }),
        "expected WouldShrink, was {err:?}"
    );
}

#[test]
fn resizing_to_the_same_size_is_not_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());
    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    store
        .resize("data", tg_runtime::volume::MIN_BYTES)
        .expect("the same size");
}

#[test]
fn an_unknown_volume_is_named_in_the_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let err = store
        .delete("nosuchthing", &Confirmation::of("nosuchthing"))
        .expect_err("does not exist");

    assert!(matches!(err, VolumeError::Unknown { .. }), "{err:?}");
    assert!(err.to_string().contains("nosuchthing"), "{err}");
}

/// A volume that is already there is not silently laid out anew -- that would
/// overwrite data.
#[test]
fn declaring_the_same_volume_twice_keeps_the_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("the second call");

    assert_eq!(
        store.info("data").expect("known").bytes,
        tg_runtime::volume::MIN_BYTES,
        "the second call overwrote the size"
    );
}

/// The inventory survives a restart of the agent -- it lies on the disk, not
/// in memory (ADR-0019).
#[test]
fn the_inventory_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    store(dir.path())
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    let names: Vec<String> = store(dir.path())
        .list()
        .expect("list")
        .into_iter()
        .map(|info| info.name)
        .collect();

    assert_eq!(names, vec!["data".to_owned()]);
}

// ==================================================== demands privileges

/// **The real path**: image, file system, loop device, mount.
#[test]
#[ignore = "demands CAP_SYS_ADMIN, losetup and mkfs; via `cargo xtask storage`"]
fn a_volume_is_provisioned_mounted_and_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    store.provision("data", 32 << 20).expect("lay out");
    let mount = store.mount("data").expect("mount");

    let file = mount.join("record.txt");
    std::fs::write(&file, "written").expect("write");
    assert_eq!(std::fs::read_to_string(&file).expect("read"), "written");

    store.unmount("data").expect("unmount");
    assert!(!file.exists(), "after the unmount the path is empty");

    // And back again when it is mounted anew -- that is the whole point.
    let mount = store.mount("data").expect("mount again");
    assert_eq!(
        std::fs::read_to_string(mount.join("record.txt")).expect("read"),
        "written"
    );
    store.unmount("data").expect("clear away");
}

/// **The phase's test "control plane gone"**, in its honest form.
///
/// There is nothing to simulate here: the volume path asks nobody. What is
/// checked is the property that follows from it -- a **restart of the agent**
/// unmounts nothing. The store is thrown away and reopened; the mount
/// survives, and the data is there.
#[test]
#[ignore = "demands CAP_SYS_ADMIN, losetup and mkfs; via `cargo xtask storage`"]
fn a_mounted_volume_survives_the_agent() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mount = {
        let store = store(dir.path());
        store.provision("data", 32 << 20).expect("lay out");
        let mount = store.mount("data").expect("mount");
        std::fs::write(mount.join("record.txt"), "survived").expect("write");
        mount
    };

    // The agent is gone. The mount is not.
    let store = store(dir.path());
    assert!(store.info("data").expect("known").mounted());
    assert_eq!(
        std::fs::read_to_string(mount.join("record.txt")).expect("read"),
        "survived"
    );

    store.unmount("data").expect("clear away");
}

#[test]
#[ignore = "demands CAP_SYS_ADMIN, losetup and mkfs; via `cargo xtask storage`"]
fn a_volume_grows_and_keeps_its_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    store.provision("data", 32 << 20).expect("lay out");
    let mount = store.mount("data").expect("mount");
    std::fs::write(mount.join("record.txt"), "before").expect("write");
    store.unmount("data").expect("unmount");

    store.resize("data", 64 << 20).expect("grow");

    let mount = store.mount("data").expect("mount again");
    assert_eq!(
        std::fs::read_to_string(mount.join("record.txt")).expect("read"),
        "before",
        "the growth lost the content"
    );
    assert!(store.info("data").expect("known").bytes >= 64 << 20);

    store.unmount("data").expect("clear away");
}

/// A mounted volume is not grown. Offline is the way that cannot go wrong;
/// online would demand changing the loop device under a running file
/// system.
#[test]
#[ignore = "demands CAP_SYS_ADMIN, losetup and mkfs; via `cargo xtask storage`"]
fn a_mounted_volume_is_not_resized() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    store.provision("data", 32 << 20).expect("lay out");
    store.mount("data").expect("mount");

    let err = store.resize("data", 64 << 20).expect_err("mounted");
    assert!(matches!(err, VolumeError::Mounted { .. }), "{err:?}");

    store.unmount("data").expect("clear away");
}

// ============================================== mounts in the bundle (10c)

/// **A shared volume is mounted as `ro`** -- by the kernel, not by a check
/// somebody can forget.
#[test]
fn a_shared_volume_is_mounted_read_only() {
    let mount = tg_runtime::bundle::VolumeMount {
        source: std::path::PathBuf::from("/var/lib/tardigrade/content/layers/abc"),
        destination: "/opt/stock".to_owned(),
        readonly: true,
    };

    let options = mount.options();
    assert!(options.contains(&"ro".to_owned()), "{options:?}");
    assert!(!options.contains(&"rw".to_owned()), "{options:?}");
}

#[test]
fn a_writable_volume_is_mounted_read_write() {
    let mount = tg_runtime::bundle::VolumeMount {
        source: std::path::PathBuf::from("/var/lib/tardigrade/volumes/data-0/mnt"),
        destination: "/var/lib/ledger".to_owned(),
        readonly: false,
    };

    assert!(mount.options().contains(&"rw".to_owned()));
}

/// `rbind` instead of `bind`: what is mounted under the source path comes
/// along. Otherwise the container would see a directory in which its volume is
/// just not mounted. And `rprivate`, so that a mount in the container does not
/// propagate back onto the host.
#[test]
fn every_mount_is_recursive_and_private() {
    for readonly in [true, false] {
        let mount = tg_runtime::bundle::VolumeMount {
            source: std::path::PathBuf::from("/a"),
            destination: "/b".to_owned(),
            readonly,
        };
        let options = mount.options();

        assert!(options.contains(&"rbind".to_owned()), "{options:?}");
        assert!(options.contains(&"rprivate".to_owned()), "{options:?}");
    }
}

/// A workload's volumes land as mounts in the `config.json` -- in document
/// order, so that an operator finds them again.
#[test]
fn the_declared_volumes_become_mounts_in_the_spec() {
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
        \x20 <workload name=\"ledger\" kind=\"service\">\n\
        \x20   <image reference=\"e.com/ledger:1\"/>\n\
        \x20 </workload>\n\
        </workloads>\n";
    let set = tg_defs::from_str(xml).expect("the fixture");

    let volumes = vec![
        tg_runtime::bundle::VolumeMount {
            source: std::path::PathBuf::from("/host/data"),
            destination: "/var/lib/ledger".to_owned(),
            readonly: false,
        },
        tg_runtime::bundle::VolumeMount {
            source: std::path::PathBuf::from("/host/stock"),
            destination: "/opt/stock".to_owned(),
            readonly: true,
        },
    ];

    let spec = tg_runtime::bundle::spec_for(
        &set.workloads()[0],
        "tg-api",
        &["/bin/sh".to_owned()],
        &[],
        &volumes,
        tg_runtime::network::Extras::default(),
    )
    .expect("the spec");

    let mounts = spec.mounts().as_ref().expect("the mounts");
    let ours: Vec<&str> = mounts
        .iter()
        .filter(|mount| mount.typ().as_deref() == Some("bind"))
        .map(|mount| {
            Box::leak(
                mount
                    .destination()
                    .to_string_lossy()
                    .into_owned()
                    .into_boxed_str(),
            ) as &str
        })
        .collect();

    assert_eq!(ours, vec!["/var/lib/ledger", "/opt/stock"]);
    let shared = mounts
        .iter()
        .find(|mount| mount.destination().to_string_lossy() == "/opt/stock")
        .expect("the shared volume");
    assert!(
        shared
            .options()
            .as_ref()
            .expect("the options")
            .contains(&"ro".to_owned()),
        "the shared volume is not ro"
    );
}

/// **The standard mounts stay.**
///
/// `SpecBuilder` brings /proc, /dev, /sys and the rest along. Replacing them
/// with the volumes would yield a container without /proc -- and that does not
/// stand out at startup but at the first program that looks for itself. This
/// module's first attempt did exactly that.
#[test]
fn the_default_mounts_survive_the_volumes() {
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
        \x20 <workload name=\"ledger\" kind=\"service\">\n\
        \x20   <image reference=\"e.com/ledger:1\"/>\n\
        \x20 </workload>\n\
        </workloads>\n";
    let set = tg_defs::from_str(xml).expect("the fixture");

    let without = tg_runtime::bundle::spec_for(
        &set.workloads()[0],
        "tg-api",
        &["/bin/sh".to_owned()],
        &[],
        &[],
        tg_runtime::network::Extras::default(),
    )
    .expect("the spec");
    let with = tg_runtime::bundle::spec_for(
        &set.workloads()[0],
        "tg-api",
        &["/bin/sh".to_owned()],
        &[],
        &[tg_runtime::bundle::VolumeMount {
            source: std::path::PathBuf::from("/host/data"),
            destination: "/var/lib/ledger".to_owned(),
            readonly: false,
        }],
        tg_runtime::network::Extras::default(),
    )
    .expect("the spec");

    let defaults = without
        .mounts()
        .as_ref()
        .expect("the standard mounts")
        .len();
    assert!(defaults > 0, "the builder brings no standard mounts along");
    assert_eq!(
        with.mounts().as_ref().expect("the mounts").len(),
        defaults + 1,
        "the volumes displaced the standard mounts"
    );

    for mount in without.mounts().as_ref().expect("the standard mounts") {
        assert!(
            with.mounts()
                .as_ref()
                .expect("the mounts")
                .iter()
                .any(|other| other.destination() == mount.destination()),
            "'{}' has disappeared",
            mount.destination().display()
        );
    }
}

/// A workload without volumes gets exactly the standard mounts -- no
/// additional bind.
#[test]
fn a_workload_without_volumes_gets_no_bind_mounts() {
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
        \x20 <workload name=\"api\" kind=\"service\">\n\
        \x20   <image reference=\"e.com/api:1\"/>\n\
        \x20 </workload>\n\
        </workloads>\n";
    let set = tg_defs::from_str(xml).expect("the fixture");

    let spec = tg_runtime::bundle::spec_for(
        &set.workloads()[0],
        "tg-api",
        &["/bin/sh".to_owned()],
        &[],
        &[],
        tg_runtime::network::Extras::default(),
    )
    .expect("the spec");

    let binds = spec
        .mounts()
        .as_ref()
        .map(|mounts| {
            mounts
                .iter()
                .filter(|mount| mount.typ().as_deref() == Some("bind"))
                .count()
        })
        .unwrap_or_default();

    assert_eq!(binds, 0);
}

/// **A grown volume really has more room** (ADR-0063).
///
/// The decision stands in `volume_sizing.rs` without privileges; here stands
/// the **effect**. It is measured at what a workload sees -- the free room in
/// the mounted file system -- not at the number in `info.json`: that one would
/// be larger even if `resize2fs` had not run at all.
///
/// And the data survives. A resize that laid the file system out anew would
/// not be distinguishable from one that grows it by the size alone.
///
/// The neighbour `a_volume_grows_and_keeps_its_content` is **not** the same
/// and stays: it calls `resize` directly and checks `info.bytes`. This one
/// goes through `provision` -- the way the reconciler goes -- and measures the
/// room a workload actually has.
#[test]
#[ignore = "demands CAP_SYS_ADMIN, losetup and mkfs; via `cargo xtask storage`"]
fn a_grown_volume_really_has_more_room() {
    use tg_runtime::volume::Sizing;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    store
        .provision("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    let mount = store.mount("data").expect("mount");
    std::fs::write(mount.join("record.txt"), "written").expect("write");
    let before = free_bytes(&mount);
    store.unmount("data").expect("unmount");

    // The same call the reconciler makes at the start -- only with a larger
    // declaration.
    let grown_to = 4 * tg_runtime::volume::MIN_BYTES;
    let (info, sizing) = store.provision("data", grown_to).expect("grow");
    assert_eq!(info.bytes, grown_to);
    assert!(matches!(sizing, Sizing::Grown { .. }), "{sizing:?}");

    let mount = store.mount("data").expect("mount again");
    let after = free_bytes(&mount);

    // **Half the increase**, not the whole: ext4 takes a part for its own
    // structures, and since ADR-0113 the LUKS header lies below it as well.
    // What the witness claims is "really grown" -- not a number it recomputes
    // itself.
    assert!(
        after > before + (grown_to - tg_runtime::volume::MIN_BYTES) / 2,
        "the file system must have really grown: {before} -> {after}"
    );
    assert_eq!(
        std::fs::read_to_string(mount.join("record.txt")).expect("read"),
        "written",
        "the data must survive the growth"
    );

    store.unmount("data").expect("clear away");
}

/// Free room in the mounted file system, in bytes.
///
/// Over `df`, because that is what an operator would look at themselves -- and
/// because a crate for one number would not be proportionate (ADR-0023).
fn free_bytes(mount: &std::path::Path) -> u64 {
    let out = std::process::Command::new("df")
        .args(["--output=avail", "--block-size=1"])
        .arg(mount)
        .output()
        .expect("df must be startable");

    String::from_utf8_lossy(&out.stdout)
        .lines()
        .nth(1)
        .and_then(|line| line.trim().parse().ok())
        .expect("df must deliver a number")
}

/// **A record that cannot be written leaves no loop device** (ADR-0027).
///
/// `mount` mounts and writes **afterwards** that it is mounted. If that write
/// fails -- a full disk suffices -- the volume is mounted and the loop device
/// occupied, but `info.device` stays empty. Thereby:
///
/// - `unmount` returns immediately ("not mounted"), and the mount stays
///   forever,
/// - `mounted()` says `false`, so the **next** pass tries again -- and
///   `losetup --find` takes **another** device every time.
///
/// That is the dangerous half: the reconciler is level-triggered and repeats
/// every few seconds. Loop devices are a finite kernel resource, and the
/// mounts stack up on the same target.
///
/// The failure is produced here by making `meta.json` a **directory** -- that
/// fails for `root` too, unlike a permission bit.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and losetup; cargo xtask storage"]
fn a_note_that_cannot_be_written_leaves_no_loop_device() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());
    store
        .provision("memory", tg_runtime::volume::MIN_BYTES)
        .expect("laid out");

    // **Searched for, not rebuilt.** Where the store files its volumes is its
    // own business; repeating the constant here would be a second source that
    // diverges quietly at the first rebuild.
    let volume = find_volume(dir.path(), "memory").expect("the volume must be on the disk");
    // **Readable but unwritable -- for `root` too.** Permission bits do not
    // suffice: `root` passes them over. A read-only bind mount on **exactly
    // this one file** hits the record and leaves the image writable so that
    // `losetup` gets its turn at all.
    let meta = volume.join("meta.json");
    let readonly = ReadOnlyFile::over(&meta);

    let err = store.mount("memory").expect_err("the record must fail");

    // Without this assertion the test would check a failure that would have
    // happened earlier -- and the cleanup afterwards not at all.
    assert!(
        matches!(err, VolumeError::Disk { .. }),
        "the failure did not come from the record: {err:?}"
    );

    drop(readonly);

    // **Waited, and with a reason.** `losetup --detach` returns with success
    // before the kernel has really released the device -- measured: the
    // cleanup line reported no error, and `--associated` still named the
    // device nevertheless. Without this bound the test would be flaky (two of
    // five runs red), and a guard that is sometimes right is the beginning of
    // a misdiagnosis.
    //
    // What is checked here is nevertheless the thing itself: a device that was
    // **not** detached does not disappear after two seconds either.
    let image = volume.join("image");
    let attached = await_detached(&image);

    assert!(
        attached.is_empty(),
        "the loop device stayed hanging: {attached}"
    );
}

/// Waits until no loop device hangs on this image any more -- and gives back
/// what is still there at the end.
fn await_detached(image: &std::path::Path) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);

    loop {
        let out = std::process::Command::new("losetup")
            .args(["--associated", &image.to_string_lossy()])
            .output()
            .expect("losetup");
        let listed = String::from_utf8_lossy(&out.stdout).trim().to_owned();

        if listed.is_empty() || std::time::Instant::now() >= deadline {
            return listed;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Makes a file unwritable until it falls.
///
/// Over a bind mount, because `root` passes permission bits over -- and over
/// **exactly one** file, so that everything beside it stays writable.
struct ReadOnlyFile(std::path::PathBuf);

impl ReadOnlyFile {
    fn over(path: &std::path::Path) -> Self {
        let path = path.to_owned();
        for args in [
            vec!["--bind", &path.to_string_lossy(), &path.to_string_lossy()],
            vec!["-o", "remount,ro,bind", &path.to_string_lossy()],
        ] {
            let out = std::process::Command::new("mount")
                .args(args.iter().map(std::string::ToString::to_string))
                .output()
                .expect("mount");
            assert!(
                out.status.success(),
                "mount: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        Self(path)
    }
}

impl Drop for ReadOnlyFile {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount").arg(&self.0).status();
    }
}

/// Finds a volume's directory under a data directory.
///
/// One level deep -- more is not needed, and claiming more would be an
/// assumption about a filing that does not belong to this test.
fn find_volume(data_dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    for entry in std::fs::read_dir(data_dir).ok()? {
        let candidate = entry.ok()?.path().join(name);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }

    None
}

/// **An interrupted provision heals itself instead of staying broken
/// forever** (ADR-0027, ADR-0010).
///
/// `provision` wrote the record **before** `mkfs.ext4`. If the creation of the
/// file system fails -- a full disk, a killed process in the middle of a
/// rolling restart -- then the volume counts as present:
///
/// - the next `provision` sees `exists() == true` and **skips `mkfs`**,
/// - `mount` mounts an image without a file system and fails,
/// - and that at **every** pass of the level-triggered reconciler.
///
/// The workload thereby never starts up again, and no path in the system ever
/// puts that right. A reconciler that **cannot** converge is the opposite of
/// ADR-0010.
///
/// The bolt now lies at the **image**: it appears only once the file system
/// stands in it (built beside, then renamed) -- the same discipline as with
/// the pending key from ADR-0055. An interrupted attempt thereby leaves the
/// record without an image behind, and **exactly that** state is produced by
/// hand here.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and losetup; cargo xtask storage"]
fn an_interrupted_provision_heals_itself() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());
    store
        .provision("half-done", tg_runtime::volume::MIN_BYTES)
        .expect("laid out");

    // **Exactly the state after an interrupted attempt:** the record from
    // `declare` is there, the image is not. It appears only once the file
    // system stands in it -- it is built beside and then renamed.
    let volume = find_volume(dir.path(), "half-done").expect("on the disk");
    std::fs::remove_file(volume.join("image")).expect("the image");
    assert!(
        volume.join("meta.json").is_file(),
        "the record must stay -- it is what makes the volume look present"
    );

    // Without this assertion the test would check a state that is already
    // usable.
    assert!(
        store.mount("half-done").is_err(),
        "this test presupposes that there is nothing to mount"
    );

    store
        .provision("half-done", tg_runtime::volume::MIN_BYTES)
        .expect("the second attempt must catch up on the file system");

    let target = store
        .mount("half-done")
        .expect("after the second attempt it must be mountable");
    assert!(target.is_dir());
    store.unmount("half-done").expect("unmounted");
}

/// **A damaged record is a finding, no missing volume** (ADR-0027).
///
/// `info` mapped **every** error onto `Unknown` -- a read or parse error too.
/// And `declare` reads that as "does not exist" and writes a **fresh** record
/// over it. What is lost in the process is not the number but the mounted
/// device:
///
/// - the fresh record carries `device: None`,
/// - `mounted()` thereby says `false` although the volume **is** mounted,
/// - and the next `mount` takes a **second** device with `losetup --find` and
///   stacks a second mount onto the same target.
///
/// The way there is short: `write_info` wrote with `std::fs::write` and
/// thereby **not atomically** -- as the only writer in the tree; eight others
/// use temp and `rename`. A break in the middle of writing leaves half a
/// file.
#[test]
fn a_damaged_note_is_a_finding_not_a_missing_volume() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());
    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    let volume = find_volume(dir.path(), "data").expect("on the disk");
    // Exactly what a break in the middle of writing leaves behind.
    std::fs::write(volume.join("meta.json"), "{\"name\":\"da").expect("half a file");

    let err = store
        .info("data")
        .expect_err("half a record must not pass as a volume");
    assert!(
        !matches!(err, VolumeError::Unknown { .. }),
        "a damaged record is reported as a missing volume: {err:?}"
    );

    // **The assertion it is about:** `declare` does not write over it.
    let err = store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect_err("a damaged record must not be overwritten");
    assert!(!matches!(err, VolumeError::Unknown { .. }), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(volume.join("meta.json")).expect("readable"),
        "{\"name\":\"da",
        "the damaged record was overwritten"
    );
}

/// The counter-check: a volume that **really** does not exist stays
/// `Unknown`.
///
/// Without it a check that makes every error a finding would be green too --
/// and `declare` would never lay a volume out again.
#[test]
fn a_volume_that_was_never_declared_stays_unknown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    assert!(matches!(
        store.info("nosuchthing"),
        Err(VolumeError::Unknown { .. })
    ));
    store
        .declare("nosuchthing", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
}

/// **And a record that cannot be *read*, likewise.**
///
/// The neighbour above damages the **content**; this one the **reading**. The
/// difference is not cosmetic: `info` mapped every read error onto `Unknown`,
/// and `declare` reads `Unknown` as permission to write a fresh record. An I/O
/// error besides sent an operator to the wrong place with "the volume does not
/// exist" while in truth the disk is stuck.
///
/// Produced with a **directory** at the file's place: that fails on reading
/// with `IsADirectory`, and for `root` too -- unlike a permission bit.
#[test]
fn a_note_that_cannot_be_read_is_a_finding_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());
    store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    let volume = find_volume(dir.path(), "data").expect("on the disk");
    let meta = volume.join("meta.json");
    std::fs::remove_file(&meta).expect("the record");
    std::fs::create_dir(&meta).expect("the record as a directory");

    let err = store.info("data").expect_err("the read must fail");
    assert!(
        !matches!(err, VolumeError::Unknown { .. }),
        "a read error is reported as a missing volume: {err:?}"
    );

    let err = store
        .declare("data", tg_runtime::volume::MIN_BYTES)
        .expect_err("an unreadable record must not be overwritten");
    assert!(!matches!(err, VolumeError::Unknown { .. }), "{err:?}");
    assert!(meta.is_dir(), "the record was replaced");
}

// ========= the two numbers that show a failed growth

/// **Declared and actual stand there as two numbers** (ADR-0063).
///
/// # What these numbers show, and what they do not
///
/// An **outstanding** growth has long been visible: the size stands in the
/// declaration, so in the digest, so the instance is **stale** (ADR-0070, and
/// `bundle::a_pending_resize_makes_the_instance_stale` nails it down).
///
/// **A volume without a snapshot reports a zero** -- not nothing.
///
/// The case for whose sake the metric exists (ADR-0099): a missing time series
/// is not distinguishable from a switched-off reporter, and
/// `TardigradeVolumeWithoutSnapshot` checks `== 0`. A rule on a metric nobody
/// sets fires **never** -- the same quiet kind of failure this tree has
/// already measured three times at `docs/alerts.yml` (truncated names,
/// `histogram_quantile` on a summary, vector matching).
///
/// Without privileges, and that is no shortcut: `declare` writes the record,
/// `list` reads it, and `snapshots` returns an empty list for a directory that
/// does not exist. What a snapshot **costs** (the copy, the freeze) is checked
/// by `cargo xtask storage`; here it is about the number.
#[test]
fn a_volume_without_a_snapshot_reports_a_zero() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    let dir = tempfile::tempdir().expect("tempdir");
    metrics::with_local_recorder(&recorder, || {
        let store = store(dir.path());
        store.declare("data", 32 << 20).expect("declare");
        tg_runtime::volume::report_snapshots(dir.path());
    });

    let mut count = None;
    let mut youngest = None;
    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        let name = key.key().name().to_owned();
        let DebugValue::Gauge(number) = value else {
            continue;
        };
        // The label belongs to the statement: a number without `volume`
        // would not tell an operator which volume has no restore point.
        let labelled = key
            .key()
            .labels()
            .any(|l| l.key() == "volume" && l.value() == "data");
        assert!(labelled, "the number does not name its volume: {key:?}");
        if name == tg_telemetry::names::VOLUME_SNAPSHOTS {
            count = Some(number.into_inner());
        } else if name == tg_telemetry::names::VOLUME_SNAPSHOT_AT {
            youngest = Some(number.into_inner());
        }
    }

    // **Both numbers**, and both zero. Only the first would be half the
    // statement: `TardigradeSnapshotStale` reckons with the point in time.
    assert_eq!(count, Some(0.0), "the number of snapshots is missing");
    assert_eq!(youngest, Some(0.0), "the point in time is missing");
}

/// What was left is the other case -- a growth that **fails**. Then the
/// declaration agrees with the bundle, the instance is not stale, and the
/// workload runs with less room than somebody declared. Until these numbers
/// that was a `warn!` at startup and nothing else.
///
/// **Two raw numbers and no difference**, the same choice as with the domain
/// metrics (ADR-0047): the alarm system does the subtraction, and a difference
/// would hide whether 8 MiB of 64 are missing or 8 of 8192.
///
/// It is checked at a **refused shrink**, because that can be produced without
/// a broken environment and yields the same situation: the two numbers diverge
/// and the instance is **not** stale in the process.
#[test]
#[ignore = "demands CAP_SYS_ADMIN, losetup and mkfs; via `cargo xtask storage`"]
fn the_declared_and_the_actual_size_are_two_numbers() {
    use metrics_util::debugging::{DebuggingRecorder, Snapshotter};

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    // **Not installed globally**: `cargo test` runs a file's tests
    // concurrently, and a global recorder would be the same for all.
    metrics::with_local_recorder(&recorder, || {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        store.provision("data", 32 << 20).expect("lay out");
        // Declared smaller: it is never shrunk (ADR-0027), the volume keeps
        // its size -- and precisely then the two numbers diverge.
        let (info, _) = store
            .provision("data", tg_runtime::volume::MIN_BYTES)
            .expect("refused");
        assert_eq!(info.bytes, 32 << 20, "it must not be shrunk");
    });

    let mut declared = None;
    let mut actual = None;
    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        let name = key.key().name().to_owned();
        let metrics_util::debugging::DebugValue::Gauge(number) = value else {
            continue;
        };
        if name == tg_telemetry::names::VOLUME_DECLARED {
            declared = Some(number.into_inner());
        } else if name == tg_telemetry::names::VOLUME_SIZE {
            actual = Some(number.into_inner());
        }
    }

    // **Both numbers, and they diverge.** Only one of the two would be half
    // the statement: an alarm rule needs the comparison.
    assert_eq!(
        declared,
        // A Prometheus metric **is** an `f64`; the lower bound lies far
        // below 2^53, so the conversion is exact.
        Some(min_bytes_as_f64()),
        "the declared size is missing or wrong"
    );
    assert_eq!(
        actual,
        Some(32.0 * 1024.0 * 1024.0),
        "the actual size is missing or wrong"
    );
}

/// The lower bound as an `f64` -- the form in which a metric carries it.
#[expect(
    clippy::cast_precision_loss,
    reason = "a Prometheus metric is an f64; the lower bound lies far below \
              2^53, the conversion is exact"
)]
fn min_bytes_as_f64() -> f64 {
    tg_runtime::volume::MIN_BYTES as f64
}

// ================================================ encryption (ADR-0113)

/// **The image is a LUKS container, and the plaintext does not stand in it.**
///
/// The witness without which everything else only shows that *something* runs:
/// a recognizable string is written, and afterwards the **raw image** is
/// searched for it. If one found it, the whole decision would be paper.
///
/// `#[ignore]`: demands `CAP_SYS_ADMIN`, `cryptsetup` and `losetup` -- via
/// `cargo xtask storage`.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and cryptsetup; via `cargo xtask storage`"]
fn the_image_is_a_luks_container_and_holds_no_plaintext() {
    const NEEDLE: &str = "TARDIGRADE-PLAINTEXT-CANARY";

    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    let (info, _) = store
        .provision("secret", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    assert!(info.encrypted, "the record must name the encryption");

    let mount = store.mount("secret").expect("mount");
    std::fs::write(mount.join("record.txt"), NEEDLE).expect("write");
    // **Unmount before searching**, otherwise the plaintext might still stand
    // in the page cache and not on the disk -- and the witness would prove
    // nothing.
    store.unmount("secret").expect("unmount");

    let image = store.image_of("secret").expect("the image");
    let raw = std::fs::read(&image).expect("read");

    assert!(
        raw.windows(6).any(|w| w == b"LUKS\xba\xbe"),
        "the image carries no LUKS signature"
    );
    assert!(
        !raw.windows(NEEDLE.len()).any(|w| w == NEEDLE.as_bytes()),
        "the plaintext stands in the image -- the encryption has no effect"
    );
}

/// **The counter-check to the witness beside it.**
///
/// Without it a search that *never* finds anything would be green too -- and
/// then the test above would prove nothing about the encryption but only that
/// `windows()` was called. The same discipline as with the BPF proof in 9b,
/// whose measuring instrument has tests of its own.
#[test]
fn the_needle_would_be_found_in_a_plain_file() {
    const NEEDLE: &str = "TARDIGRADE-PLAINTEXT-CANARY";

    let dir = tempfile::tempdir().expect("tempdir");
    let plain = dir.path().join("plaintext.bin");
    std::fs::write(&plain, format!("before{NEEDLE}after")).expect("write");

    let raw = std::fs::read(&plain).expect("read");
    assert!(
        raw.windows(NEEDLE.len()).any(|w| w == NEEDLE.as_bytes()),
        "the search finds nothing -- then the witness beside it says nothing"
    );
}

/// **An existing plaintext volume stays usable** (ADR-0113,
/// determination 6).
///
/// No silent conversion: it is mounted, read and written as before. The state
/// is built as it lies on a node from before ADR-0113 -- a naked `mkfs.ext4`
/// in the image and a record without the encryption.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and losetup; via `cargo xtask storage`"]
fn a_plaintext_volume_from_before_still_mounts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path());

    // The record arises as it always did; the image gets **no** LUKS.
    store
        .declare("old-stock", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    let image = store.image_of("old-stock").expect("the image");
    let file = std::fs::File::create(&image).expect("laying out the image");
    file.set_len(tg_runtime::volume::MIN_BYTES)
        .expect("the size");
    drop(file);
    assert!(
        std::process::Command::new("mkfs.ext4")
            .args(["-q", "-F", &image.to_string_lossy()])
            .status()
            .expect("mkfs")
            .success()
    );

    let mount = store.mount("old-stock").expect("mount");
    std::fs::write(mount.join("record.txt"), "old").expect("write");
    assert_eq!(
        std::fs::read_to_string(mount.join("record.txt")).expect("read"),
        "old"
    );
    store.unmount("old-stock").expect("unmount");
}

/// **A plaintext volume reports a zero** (ADR-0113, determination 6).
///
/// The witness for the alarm rule `TardigradeVolumeUnencrypted`: it is the
/// work list of the switch-over, and a list that never gets an entry is none.
///
/// Without privileges: `declare` writes the record, the image stays out, and
/// `is_luks` says `no` for a missing image -- exactly the default meant here.
/// That an **encrypted** volume reports a one is substantiated by
/// `the_image_is_a_luks_container_and_holds_no_plaintext` in the privileged
/// run.
#[test]
fn a_plaintext_volume_reports_a_zero() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    let dir = tempfile::tempdir().expect("tempdir");
    metrics::with_local_recorder(&recorder, || {
        let store = store(dir.path());
        store
            .declare("old-stock", tg_runtime::volume::MIN_BYTES)
            .expect("declare");
        tg_runtime::volume::report_snapshots(dir.path());
    });

    let mut encrypted = None;
    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        let DebugValue::Gauge(number) = value else {
            continue;
        };
        if key.key().name() == tg_telemetry::names::VOLUME_ENCRYPTED {
            // The label belongs to the statement: a zero without `volume`
            // would not tell an operator which volume is to be switched
            // over.
            assert!(
                key.key()
                    .labels()
                    .any(|l| l.key() == "volume" && l.value() == "old-stock"),
                "the number does not name its volume: {key:?}"
            );
            encrypted = Some(number.into_inner());
        }
    }

    assert_eq!(
        encrypted,
        Some(0.0),
        "a volume without a LUKS header must be reported as unencrypted"
    );
}

// ============================== the keyslot reconcile (ADR-0113, D7)

/// A store whose derivation delivers **two** passphrases.
///
/// That is what a node looks like during a rotation (ADR-0100): the new data
/// key applies, the old one is still there.
fn store_rotating(dir: &std::path::Path, current: &str, previous: Option<&str>) -> VolumeStore {
    let current = current.to_owned();
    let previous = previous.map(str::to_owned);
    VolumeStore::open(dir)
        .expect("the store")
        .keyed(Some(std::sync::Arc::new(move |volume: &str| {
            Some(tg_runtime::volume::Passphrases {
                current: format!("{current}-{volume}"),
                previous: previous.as_ref().map(|p| format!("{p}-{volume}")),
            })
        })))
}

/// **A rotated data key does not make a volume unopenable** (ADR-0113,
/// determination 7).
///
/// The witness for whose sake the reconcile exists: the volume arises under
/// the old key, the cluster rotates, and at the next mount it must open
/// **nevertheless** -- without a byte having been re-encrypted.
///
/// And the second half, which weighs more: afterwards the **old** passphrase
/// must no longer open it. Otherwise the rotation would be robbed of its
/// purpose, and the witness would only show that something still works.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and cryptsetup; via `cargo xtask storage`"]
fn a_rotated_data_key_keeps_the_volume_openable() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Before the rotation: laid out and written under the old key.
    let before = store_rotating(dir.path(), "old", None);
    before
        .provision("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    let mount = before.mount("data").expect("mount");
    std::fs::write(mount.join("record.txt"), "before the rotation").expect("write");
    before.unmount("data").expect("unmount");

    // Exactly **one** thing different: the cluster has rotated.
    let after = store_rotating(dir.path(), "new", Some("old"));
    let mount = after.mount("data").expect("mounting after the rotation");
    assert_eq!(
        std::fs::read_to_string(mount.join("record.txt")).expect("read"),
        "before the rotation",
        "the data must survive the rotation"
    );
    after.unmount("data").expect("unmount");

    // **The old passphrase no longer opens.** Asked directly of `cryptsetup`
    // and not over the store: that one takes the one in force anyway.
    let image = after.image_of("data").expect("the image");
    assert!(
        !passphrase_opens(&image, "old-data"),
        "the old keyslot still stands -- the rotation had no effect"
    );
    assert!(
        passphrase_opens(&image, "new-data"),
        "the new keyslot is missing"
    );
}

/// **And without a rotation nothing is touched.**
///
/// The counter-check: a store without a passphrase to be replaced returns from
/// the reconcile without even calling `cryptsetup` -- and the volume has
/// exactly one keyslot afterwards, as at creation.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and cryptsetup; via `cargo xtask storage`"]
fn without_a_rotation_the_keyslot_is_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store_rotating(dir.path(), "old", None);

    store
        .provision("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");
    store.mount("data").expect("mount");
    store.unmount("data").expect("unmount");

    let image = store.image_of("data").expect("the image");
    assert_eq!(keyslots(&image), 1, "it must be exactly one keyslot");
    assert!(passphrase_opens(&image, "old-data"));
}

/// **If neither of the two opens, nothing is touched** (determination 7,
/// case 3).
///
/// The case of a node that was away across two rotations. What matters is not
/// the refusal alone but that the volume **still opens** afterwards -- a
/// reconcile that removes a slot in case of doubt would be worse than none.
#[test]
#[ignore = "demands CAP_SYS_ADMIN and cryptsetup; via `cargo xtask storage`"]
fn two_missed_rotations_are_refused_without_damage() {
    let dir = tempfile::tempdir().expect("tempdir");

    let first = store_rotating(dir.path(), "first", None);
    first
        .provision("data", tg_runtime::volume::MIN_BYTES)
        .expect("lay out");

    // Two rotations further on: neither the passphrase in force nor the one to
    // be replaced belongs to the keyslot that stands there.
    let third = store_rotating(dir.path(), "third", Some("second"));
    let outcome = third.mount("data");

    assert!(outcome.is_err(), "{outcome:?}");
    let text = outcome.expect_err("the error").to_string();
    assert!(text.contains("rotations"), "{text}");

    // **And the old slot still stands.** That is the actual assurance.
    let image = first.image_of("data").expect("the image");
    assert_eq!(keyslots(&image), 1, "nothing must have been removed");
    assert!(
        passphrase_opens(&image, "first-data"),
        "the volume must still open"
    );
}

/// Whether a passphrase opens an image -- without mounting it.
fn passphrase_opens(image: &std::path::Path, passphrase: &str) -> bool {
    use std::io::Write as _;

    let Ok(mut child) = std::process::Command::new("cryptsetup")
        .args(["open", "--test-passphrase", "--key-file", "-"])
        .arg(image)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(passphrase.as_bytes());
    }
    child.wait().is_ok_and(|status| status.success())
}

/// How many keyslots are occupied.
fn keyslots(image: &std::path::Path) -> usize {
    let out = std::process::Command::new("cryptsetup")
        .arg("luksDump")
        .arg(image)
        .output()
        .expect("luksDump");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| {
            line.trim_start().starts_with(|c: char| c.is_ascii_digit()) && line.contains("luks2")
        })
        .count()
}
