//! The local persistent-volume lifecycle.
//!
//! A persistent volume's model: writable means exclusive and node-pinned,
//! shared means read-only. Here stands the path onto the disk.
//!
//! # An image, not a directory
//!
//! A volume is a file with a file system in it, mounted over a loop device. A
//! mere directory would be simpler and could not do three things this model
//! demands: have a **size**, be **grown**, and offer a seam for **at-rest
//! encryption**. A LUKS container lies exactly where the naked file system
//! lies today.
//!
//! # Foreign programs, at arm's length
//!
//! `losetup`, `mkfs.ext4` and `resize2fs` are GPL-2. They are **called**, not
//! linked -- the same boundary this codebase uses for `nft` and for
//! youki/crun: the cheapest licence-clean boundary. Writing a file system
//! ourselves would not be up for debate.
//!
//! # What does **not** happen here
//!
//! No network. The whole path asks nobody -- no consensus, no control plane,
//! no resolver. That is a deliberate assurance, and here it is no effort but
//! an absence: there is simply no call that could violate it.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

const DIR: &str = "volumes";

const SNAPSHOTS: &str = "snapshots";

const SNAPSHOT_MARK: &str = "snapshot.generation";

pub const MIN_BYTES: u64 = LUKS_HEADER_BYTES + MIN_PAYLOAD_BYTES;

const LUKS_HEADER_BYTES: u64 = 16 << 20;

const MIN_PAYLOAD_BYTES: u64 = 8 << 20;

pub const TOOL_TIMEOUT: Duration = Duration::from_mins(1);

#[derive(Debug)]
pub enum VolumeError {
    IllegalName {
        name: String,
    },
    Unknown {
        name: String,
    },
    Mounted {
        name: String,
    },
    NoSnapshot {
        name: String,
        generation: u64,
    },
    StillFrozen {
        name: String,
        detail: String,
    },
    NotConfirmed {
        name: String,
        confirmed: String,
    },
    WouldShrink {
        from: u64,
        to: u64,
    },
    TooSmall {
        bytes: u64,
    },
    NoKey {
        name: String,
    },
    Tool {
        program: &'static str,
        detail: String,
    },
    Disk {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalName { name } => {
                write!(f, "'{}' is no good as a volume name", name.escape_debug())
            }
            Self::Unknown { name } => write!(f, "the volume '{name}' does not exist"),
            Self::Mounted { name } => {
                write!(f, "the volume '{name}' is mounted -- unmount it first")
            }
            Self::NoSnapshot { name, generation } => write!(
                f,
                "the volume '{name}' has no snapshot of generation {generation}"
            ),
            Self::StillFrozen { name, detail } => write!(
                f,
                "the volume '{name}' has stayed frozen and halts every \
                 writer: {detail}"
            ),
            Self::NotConfirmed { name, confirmed } => write!(
                f,
                "the confirmation names '{confirmed}', what was to be deleted \
                 is '{name}' -- deleting is destructive and demands the name"
            ),
            Self::WouldShrink { from, to } => write!(
                f,
                "{to} bytes would be less than the {from} that are there -- a \
                 volume is not shrunk"
            ),
            Self::TooSmall { bytes } => {
                write!(f, "{bytes} bytes are too few; at least {MIN_BYTES}")
            }
            Self::NoKey { name } => write!(
                f,
                "for '{name}' there is no data key -- a writable volume is \
                 always encrypted. The key comes on the node's credential \
                 path; a node before its first admission does not have it \
                 yet"
            ),
            Self::Tool { program, detail } => write!(f, "{program}: {detail}"),
            Self::Disk { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for VolumeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation(String);

impl Confirmation {
    #[must_use]
    pub fn of(volume: &str) -> Self {
        Self(volume.to_owned())
    }

    #[must_use]
    pub fn names(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeInfo {
    pub name: String,
    pub bytes: u64,
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sizing {
    Created,
    Unchanged,
    Grown {
        from: u64,
        to: u64,
    },
    ShrinkRefused {
        actual: u64,
        declared: u64,
    },
    GrowthFailed {
        to: u64,
        detail: String,
    },
}

impl std::fmt::Display for Sizing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "laid out"),
            Self::Unchanged => write!(f, "unchanged"),
            Self::Grown { from, to } => write!(f, "grown from {from} to {to} bytes"),
            Self::ShrinkRefused { actual, declared } => write!(
                f,
                "shrinking refused: declared {declared} bytes, present {actual} bytes \
                 -- it is never shrunk"
            ),
            Self::GrowthFailed { to, detail } => {
                write!(f, "growth to {to} bytes failed: {detail}")
            }
        }
    }
}

impl VolumeInfo {
    #[must_use]
    pub fn mounted(&self) -> bool {
        self.device.is_some()
    }
}

#[derive(Clone)]
pub struct VolumeStore {
    root: PathBuf,
    userns: Option<crate::userns::Mapping>,
    derive: Option<Derive>,
}

pub type Derive = std::sync::Arc<dyn Fn(&str) -> Option<Passphrases> + Send + Sync>;

pub struct Passphrases {
    pub current: String,
    pub previous: Option<String>,
}

impl std::fmt::Debug for Passphrases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passphrases")
            .field("previous", &self.previous.is_some())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for VolumeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeStore")
            .field("root", &self.root)
            .field("userns", &self.userns)
            .field("keyed", &self.derive.is_some())
            .finish()
    }
}

impl VolumeStore {
    pub fn open(data_dir: &Path) -> Result<Self, VolumeError> {
        let root = data_dir.join(DIR);
        std::fs::create_dir_all(&root).map_err(|source| VolumeError::Disk {
            path: root.clone(),
            source,
        })?;
        // A LUKS container lies behind an image since encryption applied to
        // every writable volume; **existing** plaintext volumes stay,
        // however, and their content is an application's state.
        crate::content::seal_soft(&root, "closing the volumes");

        Ok(Self {
            root,
            userns: None,
            derive: None,
        })
    }

    #[must_use]
    pub fn keyed(mut self, derive: Option<Derive>) -> Self {
        self.derive = derive;
        self
    }

    fn keys(&self, name: &str) -> Result<Passphrases, VolumeError> {
        self.derive
            .as_ref()
            .and_then(|derive| derive(name))
            .ok_or_else(|| VolumeError::NoKey {
                name: name.to_owned(),
            })
    }

    fn passphrase(&self, name: &str) -> Result<String, VolumeError> {
        self.keys(name).map(|keys| keys.current)
    }

    fn ensure_keyslot(&self, name: &str, image: &Path) -> Result<(), VolumeError> {
        let keys = self.keys(name)?;
        let Some(previous) = keys.previous else {
            return Ok(());
        };

        let path = image.to_string_lossy().into_owned();
        let opens = |passphrase: &str| {
            run_with_secret(
                "cryptsetup",
                &["open", "--test-passphrase", "--key-file", "-", &path],
                passphrase,
            )
            .is_ok()
        };

        if !opens(&keys.current) {
            if !opens(&previous) {
                return Err(VolumeError::Tool {
                    program: "cryptsetup",
                    detail: format!(
                        "neither the data key in force nor the one to be replaced opens \
                         '{name}'. If the node was away across two rotations, its keyslot \
                         carries a third one"
                    ),
                });
            }

            // **Both secrets over stdin**, one after the other and with a
            // size -- measured that `cryptsetup` takes them that way. The way
            // over a file would be a secret on the disk, the one over an
            // additional descriptor would demand `unsafe` outside
            // `tg-syscall`, where this crate forbids it.
            let len = keys.current.len().to_string();
            let both = format!("{previous}{}", keys.current);
            run_with_secret(
                "cryptsetup",
                &[
                    "luksAddKey",
                    "--batch-mode",
                    "--key-file",
                    "-",
                    "--keyfile-size",
                    &previous.len().to_string(),
                    "--new-keyfile",
                    "-",
                    "--new-keyfile-size",
                    &len,
                    &path,
                ],
                &both,
            )?;

            // **First check, then remove.** Without this line the last slot
            // would hang on the assumption that `luksAddKey` did what it
            // reports.
            if !opens(&keys.current) {
                return Err(VolumeError::Tool {
                    program: "cryptsetup",
                    detail: format!(
                        "the new keyslot for '{name}' does not open -- the old one stays"
                    ),
                });
            }
            tracing::info!(volume = %name, "keyslot brought up to the data key in force");
        }

        if opens(&previous) {
            run_with_secret(
                "cryptsetup",
                &["luksRemoveKey", "--key-file", "-", &path],
                &previous,
            )?;
            tracing::info!(volume = %name, "the keyslot to be replaced was removed");
        }

        Ok(())
    }

    fn mapper(&self, name: &str) -> String {
        // FNV-1a over the root path. **No cryptographic claim** -- what is
        // sought is distinguishability, not unforgeability, and a hash from
        // the tree for that would be a dependency for eight hex characters.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in self.root.as_os_str().as_encoded_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        // **The truncation is wanted**, not a loss: what is sought are eight
        // hex characters that distinguish two data directories. A mapper name
        // is length-bounded besides, and the volume name stands after it.
        format!("tgvol-{:08x}-{name}", hash & 0xffff_ffff)
    }

    #[must_use]
    pub fn mapped(mut self, userns: Option<crate::userns::Mapping>) -> Self {
        self.userns = userns;
        self
    }

    pub fn thaw_all(&self) -> Result<u32, VolumeError> {
        let mut thawed = 0;
        for info in self.list()? {
            if !info.mounted() {
                continue;
            }
            let Ok(dir) = self.dir(&info.name) else {
                continue;
            };
            let mount = dir.join("mnt");
            if run("fsfreeze", &["--unfreeze", &mount.to_string_lossy()]).is_ok() {
                thawed += 1;
                tracing::warn!(
                    volume = info.name,
                    "the volume was frozen and has been thawed -- a previous \
                     process was ended between the snapshot freeze and the \
                     release, and its writers stood still"
                );
            }
        }
        Ok(thawed)
    }

    fn dir(&self, name: &str) -> Result<PathBuf, VolumeError> {
        check_name(name)?;
        Ok(self.root.join(name))
    }

    #[must_use]
    pub fn exists(&self, name: &str) -> bool {
        self.dir(name)
            .is_ok_and(|dir| dir.join("meta.json").is_file())
    }

    pub fn info(&self, name: &str) -> Result<VolumeInfo, VolumeError> {
        let path = self.dir(name)?.join("meta.json");
        // **`Unknown` means "does not exist", not "could not be read".**
        // Reporting an I/O error as "unknown volume" would send an operator to
        // the wrong place -- and `declare` reads `Unknown` as permission to
        // write a fresh record.
        let raw = std::fs::read_to_string(&path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                VolumeError::Unknown {
                    name: name.to_owned(),
                }
            } else {
                VolumeError::Disk {
                    path: path.clone(),
                    source,
                }
            }
        })?;

        serde_json::from_str(&raw).map_err(|err| VolumeError::Disk {
            path,
            source: std::io::Error::other(err),
        })
    }

    fn write_info(&self, info: &VolumeInfo) -> Result<(), VolumeError> {
        let path = self.dir(&info.name)?.join("meta.json");
        let text = serde_json::to_string(info).map_err(|err| VolumeError::Disk {
            path: path.clone(),
            source: std::io::Error::other(err),
        })?;

        // **Atomic, like every other writer in this tree.** `fs::write`
        // truncates first and then writes; a break in between leaves half a
        // file, and from outside that is a damaged record. `state.rs`,
        // `resolved.rs`, `content.rs`, `rotate.rs` and `audit.rs` all do it
        // via temp and `rename` -- this place was the only one that did
        // not.
        let temp = path.with_extension("json.new");
        std::fs::write(&temp, text).map_err(|source| VolumeError::Disk {
            path: temp.clone(),
            source,
        })?;

        std::fs::rename(&temp, &path).map_err(|source| VolumeError::Disk { path, source })
    }

    pub fn list(&self) -> Result<Vec<VolumeInfo>, VolumeError> {
        let entries = std::fs::read_dir(&self.root).map_err(|source| VolumeError::Disk {
            path: self.root.clone(),
            source,
        })?;

        let mut out: Vec<VolumeInfo> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter_map(|name| self.info(&name).ok())
            .collect();
        out.sort_by(|left, right| left.name.cmp(&right.name));

        Ok(out)
    }

    pub fn declare(&self, name: &str, bytes: u64) -> Result<VolumeInfo, VolumeError> {
        // The name **first**: it is the trust boundary. A size check before
        // it would let a malicious name fail on a number error instead of on
        // what is wrong with it -- and the next caller with a plausible size
        // would get through.
        let dir = self.dir(name)?;

        // **Lay out only on a genuine absence.** Here stood
        // `if let Ok(existing) = ...`, and *every* error thereby counted as
        // "does not exist": a damaged record was overwritten. What is lost in
        // the process is not the number but the mounted device -- the fresh
        // record carries `device: None`, `mounted()` says `false`, and the
        // next `mount` takes a **second** loop device and stacks a second
        // mount onto the same target.
        match self.info(name) {
            Ok(existing) => return Ok(existing),
            // Really not there -- the only case in which it is laid out.
            Err(VolumeError::Unknown { .. }) => {}
            Err(err) => return Err(err),
        }
        if bytes < MIN_BYTES {
            return Err(VolumeError::TooSmall { bytes });
        }

        std::fs::create_dir_all(dir.join("mnt")).map_err(|source| VolumeError::Disk {
            path: dir.clone(),
            source,
        })?;

        let info = VolumeInfo {
            name: name.to_owned(),
            bytes,
            device: None,
            // **The record does not say so yet.** It arises in `declare`,
            // that is, before the `luksFormat` in `provision` -- and a record
            // that claims an encryption that does not exist yet would be worse
            // than none. It is set once the container stands.
            encrypted: false,
        };
        self.write_info(&info)?;

        Ok(info)
    }

    pub fn provision(&self, name: &str, bytes: u64) -> Result<(VolumeInfo, Sizing), VolumeError> {
        // **Two raw numbers:** the declared and the actual size. They stand
        // **here**, because both are known here -- and not at the caller,
        // which gets one of them back only afterwards.
        //
        // If a growth is outstanding, the instance is **stale** anyway and is
        // reported: the size stands in the declaration and thereby in the
        // digest. What these numbers show is the other case -- a growth that
        // **fails**. Then the declaration agrees with the bundle, the
        // instance is not stale, and the workload runs with less room than
        // declared. Up to here that was a `warn!` at startup and nothing
        // else.
        let report = |declared: u64, actual: u64| report_sizes(name, declared, actual);

        let existed = self.exists(name);
        let info = self.declare(name, bytes)?;
        let image = self.dir(name)?.join("image");

        // **The image is the bolt, not the record.**
        //
        // The record arises in `declare`, that is, **before** `mkfs`. If it
        // stayed behind alone -- a full disk, a killed process in the middle
        // of a rolling restart -- then the volume counted as present: the next
        // pass skipped `mkfs`, `mount` mounted an image without a file system
        // and failed, and that at **every** pass. The workload never started
        // up again, and no path in the system ever put that right -- a
        // reconciler that **cannot** converge defeats the whole point of
        // reconciling.
        //
        // `image` therefore appears only once the file system stands in it: it
        // is built beside and then renamed. The same discipline as with a
        // pending key rotation and with the desired-state cache.
        if existed && image.is_file() {
            let outcome = self.bring_to_size(info, bytes);
            report(bytes, outcome.0.bytes);
            return Ok(outcome);
        }

        let staged = self.dir(name)?.join("image.new");
        // Sparse: the file occupies room only once it is written. Laying out
        // a volume is not to take as long as filling it.
        let file = std::fs::File::create(&staged).map_err(|source| VolumeError::Disk {
            path: staged.clone(),
            source,
        })?;
        file.set_len(info.bytes)
            .map_err(|source| VolumeError::Disk {
                path: staged.clone(),
                source,
            })?;
        drop(file);

        // **The LUKS container first, the file system in it.** The
        // passphrase goes over stdin, never over argv.
        //
        // If something fails here, `image.new` stays lying and `image` does
        // not arise -- the next pass starts from the beginning. That is the
        // same discipline as with the `mkfs` before it, and the reason stands
        // above.
        let passphrase = self.passphrase(name)?;
        let staged_path = staged.to_string_lossy().into_owned();
        run_with_secret(
            "cryptsetup",
            &[
                "luksFormat",
                "--batch-mode",
                "--type",
                "luks2",
                "--key-file",
                "-",
                &staged_path,
            ],
            &passphrase,
        )?;

        let mapper = self.mapper(name);
        run_with_secret(
            "cryptsetup",
            &["open", "--key-file", "-", &staged_path, &mapper],
            &passphrase,
        )?;

        let outcome = run("mkfs.ext4", &["-q", "-F", &format!("/dev/mapper/{mapper}")]);
        // **Close it in every case.** An open mapper on an image that is
        // called `image.new` right now and then disappears is a device that
        // points at nothing -- and the next pass would no longer get through
        // with the same name.
        if let Err(err) = run("cryptsetup", &["close", &mapper]) {
            tracing::error!(volume = %name, %mapper, error = %err, "the mapper was not closed");
        }
        outcome?;

        std::fs::rename(&staged, &image).map_err(|source| VolumeError::Disk {
            path: image,
            source,
        })?;

        let mut info = info;
        info.encrypted = true;
        self.write_info(&info)?;

        report(bytes, info.bytes);
        Ok((info, Sizing::Created))
    }

    fn bring_to_size(&self, info: VolumeInfo, declared: u64) -> (VolumeInfo, Sizing) {
        if declared < info.bytes {
            let sizing = Sizing::ShrinkRefused {
                actual: info.bytes,
                declared,
            };
            return (info, sizing);
        }
        if declared == info.bytes {
            return (info, Sizing::Unchanged);
        }

        let from = info.bytes;
        match self.resize(&info.name, declared) {
            Ok(()) => match self.info(&info.name) {
                Ok(grown) => (grown, Sizing::Grown { from, to: declared }),
                // Cannot occur -- `resize` has just written the
                // information. An `unwrap` would be wrong nevertheless: a
                // privileged process runs here.
                Err(err) => (
                    info,
                    Sizing::GrowthFailed {
                        to: declared,
                        detail: err.to_string(),
                    },
                ),
            },
            Err(err) => (
                info,
                Sizing::GrowthFailed {
                    to: declared,
                    detail: err.to_string(),
                },
            ),
        }
    }

    pub fn mount(&self, name: &str) -> Result<PathBuf, VolumeError> {
        let mut info = self.info(name)?;
        let dir = self.dir(name)?;
        let target = dir.join("mnt");

        if info.mounted() {
            return Ok(target);
        }

        let image = dir.join("image");
        // **Two ways, and the record does not decide** (ADR-0113,
        // determination 6): the **image** is asked. A record can stem from a
        // restore or from an older version; the LUKS header stands in the data
        // at issue.
        let device = if info.encrypted || is_luks(&image) {
            // **Bring it up before opening** (ADR-0113, determination 7). If
            // no rotation is running, that costs not a single call.
            self.ensure_keyslot(name, &image)?;
            let mapper = self.mapper(name);
            run_with_secret(
                "cryptsetup",
                &["open", "--key-file", "-", &image.to_string_lossy(), &mapper],
                &self.passphrase(name)?,
            )?;
            info.encrypted = true;
            format!("/dev/mapper/{mapper}")
        } else {
            run("losetup", &["--find", "--show", &image.to_string_lossy()])?
                .trim()
                .to_owned()
        };

        // First the record, then mount? No -- the other way round: a record
        // without a mount would let `unmount` unmount something that is not
        // there, and `delete` fail on a state that does not exist.
        if let Err(err) = tg_syscall::mount::bind_device(&device, &target) {
            // **Reported and not quiet**, like twenty lines further down: if
            // the device stays lying, it still points at an image nobody looks
            // for any more -- a finite kernel resource, and the way out stands
            // in the message. The error that goes back is the mount's: it is
            // the cause, the device only the consequence.
            if let Err(detach) = release(&device) {
                tracing::error!(volume = %name, %device, error = %detach, "the device was not released");
            }
            return Err(VolumeError::Tool {
                program: "mount",
                detail: err.to_string(),
            });
        }

        info.device = Some(device.clone());
        if let Err(err) = self.write_info(&info) {
            // **The record is the only trace.** If it does not appear,
            // `mounted()` still says `false`: `unmount` would return
            // immediately and leave the mount standing, and the next pass of
            // the level-triggered reconciler would take **another** device
            // with `losetup --find` and stack a second mount onto the same
            // target. Loop devices are finite.
            //
            // So back to the state from before. What still goes wrong here is
            // reported and not quiet.
            //
            // **Unmount immediately, not lazily.** `unmount_at` sets
            // `MNT_DETACH`: the mount disappears from the namespace, the file
            // system only once the last reference falls -- and until then it
            // holds the loop device. `losetup --detach` would run against
            // that, and exactly the device at issue here would stay hanging.
            // Here it is safe: this mount has only just arisen, and nobody has
            // entered it.
            if let Err(err) = tg_syscall::mount::unmount_now(&target) {
                tracing::error!(volume = %info.name, error = %err, "not unmounted");
            }
            if let Err(err) = release(&device) {
                tracing::error!(volume = %info.name, %device, error = %err, "the device was not released");
            }
            return Err(err);
        }

        // **The root gets the identifier** (ADR-0091, determination 2).
        // After `mkfs` it belongs to `root`, and under a mapping the container
        // could not write its own volume (measurement 1).
        //
        // **Not recursive**, and that is the decision: a fresh volume is
        // thereby writable, and existing content stays as it is. A recursive
        // `chown` over an unknown amount of data does not belong in a
        // reconcile pass -- whoever switches over migrates themselves.
        //
        // Fail-soft: a volume that is mounted stays mounted (ADR-0019). What
        // goes wrong here is reported.
        if let Some(mapping) = self.userns
            && let Err(err) = crate::userns::shift_tree(&target, mapping)
        {
            tracing::error!(volume = %name, error = %err, "the volume was not mapped");
        }

        Ok(target)
    }

    pub fn unmount(&self, name: &str) -> Result<(), VolumeError> {
        let mut info = self.info(name)?;
        let Some(device) = info.device.clone() else {
            return Ok(());
        };

        let target = self.dir(name)?.join("mnt");
        tg_syscall::mount::unmount_at(&target).map_err(|err| VolumeError::Tool {
            program: "umount",
            detail: err.to_string(),
        })?;
        release(&device)?;

        info.device = None;
        self.write_info(&info)
    }

    pub fn resize(&self, name: &str, bytes: u64) -> Result<(), VolumeError> {
        let mut info = self.info(name)?;

        if bytes < info.bytes {
            return Err(VolumeError::WouldShrink {
                from: info.bytes,
                to: bytes,
            });
        }
        if bytes == info.bytes {
            return Ok(());
        }
        if info.mounted() {
            return Err(VolumeError::Mounted {
                name: name.to_owned(),
            });
        }

        let image = self.dir(name)?.join("image");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&image)
            .map_err(|source| VolumeError::Disk {
                path: image.clone(),
                source,
            })?;
        file.set_len(bytes).map_err(|source| VolumeError::Disk {
            path: image.clone(),
            source,
        })?;
        drop(file);

        // **Behind the mapper, if there is one** (ADR-0113, open point).
        //
        // The image has grown; the LUKS container in it has **not**. Without
        // `cryptsetup resize` `resize2fs` still sees the old size: the volume
        // grows visibly and without effect -- exactly the outcome ADR-0063
        // refused as "a size that does not take effect".
        let path = image.to_string_lossy().into_owned();
        let encrypted = info.encrypted || is_luks(&image);
        let target = if encrypted {
            self.ensure_keyslot(name, &image)?;
            let mapper = self.mapper(name);
            run_with_secret(
                "cryptsetup",
                &["open", "--key-file", "-", &path, &mapper],
                &self.passphrase(name)?,
            )?;
            // The container takes the new room. Without a size
            // `cryptsetup resize` takes everything the device offers -- and
            // that is exactly right here: the file is already at `bytes`.
            let grown = run_with_secret(
                "cryptsetup",
                &["resize", "--key-file", "-", &mapper],
                &self.passphrase(name)?,
            );
            if grown.is_err() {
                if let Err(err) = run("cryptsetup", &["close", &mapper]) {
                    tracing::error!(volume = %name, %mapper, error = %err, "the mapper was not closed");
                }
                grown?;
            }
            format!("/dev/mapper/{mapper}")
        } else {
            path.clone()
        };

        // `resize2fs` insists on a check. It costs nothing with a clean file
        // system and is the condition for the growth running at all.
        let outcome =
            run("e2fsck", &["-p", "-f", &target]).and_then(|_| run("resize2fs", &[&target]));

        if encrypted && let Err(err) = run("cryptsetup", &["close", &self.mapper(name)]) {
            tracing::error!(volume = %name, error = %err, "the mapper was not closed");
        }
        outcome?;

        info.bytes = bytes;
        info.encrypted = encrypted;
        self.write_info(&info)
    }

    pub fn delete(&self, name: &str, confirm: &Confirmation) -> Result<(), VolumeError> {
        let info = self.info(name)?;

        if confirm.names() != name {
            return Err(VolumeError::NotConfirmed {
                name: name.to_owned(),
                confirmed: confirm.names().to_owned(),
            });
        }
        if info.mounted() {
            return Err(VolumeError::Mounted {
                name: name.to_owned(),
            });
        }

        let dir = self.dir(name)?;
        std::fs::remove_dir_all(&dir).map_err(|source| VolumeError::Disk { path: dir, source })
    }

    pub fn note_mounted(&self, name: &str, device: &str) -> Result<(), VolumeError> {
        let mut info = self.info(name)?;
        info.device = Some(device.to_owned());
        self.write_info(&info)
    }

    pub fn image_of(&self, name: &str) -> Result<PathBuf, VolumeError> {
        Ok(self.dir(name)?.join("image"))
    }

    pub fn snapshots(&self, name: &str) -> Result<Vec<SnapshotInfo>, VolumeError> {
        let root = self.dir(name)?.join(SNAPSHOTS);
        let Ok(entries) = std::fs::read_dir(&root) else {
            return Ok(Vec::new());
        };

        let mut found: Vec<SnapshotInfo> = entries
            .flatten()
            .filter_map(|entry| {
                let generation: u64 = entry.file_name().to_str()?.parse().ok()?;
                let meta = entry.metadata().ok()?;
                Some(SnapshotInfo {
                    generation,
                    bytes: meta.len(),
                    taken_at: meta
                        .modified()
                        .ok()
                        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                        .map_or(0, |since| since.as_secs()),
                    path: entry.path(),
                })
            })
            .collect();

        found.sort_by_key(|snap| snap.generation);
        Ok(found)
    }

    #[must_use]
    pub fn snapshot_mark(&self, name: &str) -> u64 {
        self.dir(name)
            .ok()
            .and_then(|dir| std::fs::read_to_string(dir.join(SNAPSHOT_MARK)).ok())
            .and_then(|raw| raw.trim().parse().ok())
            .unwrap_or(0)
    }

    pub fn snapshot(
        &self,
        name: &str,
        generation: u64,
        keep: usize,
    ) -> Result<SnapshotInfo, VolumeError> {
        let snap = self.copy_image(name, generation)?;
        self.write_mark(name, generation)?;
        self.prune(name, keep)?;
        Ok(snap)
    }

    pub fn restore(
        &self,
        name: &str,
        generation: u64,
        confirm: &Confirmation,
    ) -> Result<SnapshotInfo, VolumeError> {
        let info = self.info(name)?;

        if confirm.names() != name {
            return Err(VolumeError::NotConfirmed {
                name: name.to_owned(),
                confirmed: confirm.names().to_owned(),
            });
        }
        if info.mounted() {
            return Err(VolumeError::Mounted {
                name: name.to_owned(),
            });
        }

        let held = self.snapshots(name)?;
        let source = held
            .iter()
            .find(|snap| snap.generation == generation)
            .ok_or_else(|| VolumeError::NoSnapshot {
                name: name.to_owned(),
                generation,
            })?
            .path
            .clone();

        // **The before-snapshot's generation lies above all known ones.**
        // Closer to `generation` it would be a collision: it would overwrite
        // the snapshot being restored from.
        let next = held.iter().map(|snap| snap.generation).max().unwrap_or(0) + 1;
        let replaced = self.copy_image(name, next)?;

        // **The marker is not touched.** It answers "which log generation is
        // executed"; the before-snapshot comes from no log, and a raised
        // marker would let the node hold a decree for executed that nobody
        // made.
        let image = self.image_of(name)?;
        std::fs::copy(&source, &image).map_err(|source| VolumeError::Disk {
            path: image,
            source,
        })?;

        Ok(replaced)
    }

    fn copy_image(&self, name: &str, generation: u64) -> Result<SnapshotInfo, VolumeError> {
        let info = self.info(name)?;
        let dir = self.dir(name)?;
        let root = dir.join(SNAPSHOTS);
        std::fs::create_dir_all(&root).map_err(|source| VolumeError::Disk {
            path: root.clone(),
            source,
        })?;

        let image = dir.join("image");
        let target = root.join(generation.to_string());
        let mount = dir.join("mnt");

        // **Frozen only if mounted.** An unmounted volume has no writers,
        // and `fsfreeze` on a directory without a file system in it would be
        // an error without an object.
        let frozen = if info.mounted() {
            Some(Thaw::freeze(name, &mount)?)
        } else {
            None
        };

        // `std::fs::copy` goes over `copy_file_range(2)`; on a host with
        // reflink the kernel makes a copy-on-write copy out of it (measured:
        // 256 MiB, **zero** occupied blocks), otherwise the same call falls
        // back to a real copy. A `cp --reflink=auto` would be a third process
        // dependency for the same result.
        let copied = std::fs::copy(&image, &target);

        // **The release comes before the copy's error handling.** An early
        // abort would leave the file system frozen, and then the workload
        // halts -- worse than a failed copy.
        if let Some(guard) = frozen {
            guard.thaw()?;
        }

        let bytes = copied.map_err(|source| VolumeError::Disk {
            path: target.clone(),
            source,
        })?;

        Ok(SnapshotInfo {
            generation,
            bytes,
            taken_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
            path: target,
        })
    }

    fn write_mark(&self, name: &str, generation: u64) -> Result<(), VolumeError> {
        let path = self.dir(name)?.join(SNAPSHOT_MARK);
        let temp = path.with_extension("new");
        std::fs::write(&temp, generation.to_string()).map_err(|source| VolumeError::Disk {
            path: temp.clone(),
            source,
        })?;
        std::fs::rename(&temp, &path).map_err(|source| VolumeError::Disk { path, source })
    }

    fn prune(&self, name: &str, keep: usize) -> Result<(), VolumeError> {
        if keep == 0 {
            return Ok(());
        }

        let held = self.snapshots(name)?;
        let Some(surplus) = held.len().checked_sub(keep) else {
            return Ok(());
        };

        for snap in held.iter().take(surplus) {
            std::fs::remove_file(&snap.path).map_err(|source| VolumeError::Disk {
                path: snap.path.clone(),
                source,
            })?;
        }

        Ok(())
    }
}

struct Thaw<'a> {
    name: &'a str,
    target: PathBuf,
    armed: bool,
}

impl<'a> Thaw<'a> {
    fn freeze(name: &'a str, target: &Path) -> Result<Self, VolumeError> {
        run("fsfreeze", &["--freeze", &target.to_string_lossy()])?;
        Ok(Self {
            name,
            target: target.to_owned(),
            armed: true,
        })
    }

    fn thaw(mut self) -> Result<(), VolumeError> {
        self.armed = false;
        run("fsfreeze", &["--unfreeze", &self.target.to_string_lossy()]).map_err(|err| {
            VolumeError::StillFrozen {
                name: self.name.to_owned(),
                detail: err.to_string(),
            }
        })?;
        Ok(())
    }
}

impl Drop for Thaw<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Err(err) = run("fsfreeze", &["--unfreeze", &self.target.to_string_lossy()])
        {
            tracing::error!(
                volume = %self.name,
                target = %self.target.display(),
                error = %err,
                "the volume stays frozen -- its writers hang until the agent's next start"
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub generation: u64,
    pub bytes: u64,
    pub taken_at: u64,
    pub path: PathBuf,
}

fn check_name(name: &str) -> Result<(), VolumeError> {
    let legal = !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');

    if legal {
        Ok(())
    } else {
        Err(VolumeError::IllegalName {
            name: name.to_owned(),
        })
    }
}

fn run(program: &'static str, args: &[&str]) -> Result<String, VolumeError> {
    run_within(program, args, TOOL_TIMEOUT)
}

fn is_luks(image: &Path) -> bool {
    run("cryptsetup", &["isLuks", &image.to_string_lossy()]).is_ok()
}

fn release(device: &str) -> Result<String, VolumeError> {
    let Some(mapper) = device.strip_prefix("/dev/mapper/") else {
        return run("losetup", &["--detach", device]);
    };

    // **And if it is still busy, deferred** -- the difference from
    // `losetup`, and it is measured.
    //
    // The way back in `mount` unmounts with `MNT_DETACH`: the mount
    // disappears from the namespace, the file system only once the last
    // reference falls. `losetup --detach` succeeds on that; a
    // `cryptsetup close` fails with "device busy" and **would leave the mapper
    // lying**. That stood out not at the single witness -- alone they all pass
    // -- but only in the concurrent run, and the `xtask`'s remnant guard saw
    // it once it knew mappers.
    //
    // `--deferred` is thereby not the weaker choice but the same assurance as
    // with the loop device: gone as soon as nobody stands in it any more.
    match run("cryptsetup", &["close", mapper]) {
        Ok(out) => Ok(out),
        Err(err) => {
            tracing::debug!(%mapper, error = %err, "the mapper is busy, closing deferred");
            run("cryptsetup", &["close", "--deferred", mapper])
        }
    }
}

fn run_with_secret(
    program: &'static str,
    args: &[&str],
    secret: &str,
) -> Result<String, VolumeError> {
    run_with_secret_within(program, args, secret, TOOL_TIMEOUT)
}

fn run_with_secret_within(
    program: &'static str,
    args: &[&str],
    secret: &str,
    within: Duration,
) -> Result<String, VolumeError> {
    use std::io::Write as _;

    let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let secret = secret.to_owned();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = (|| {
            let mut child = Command::new(program)
                .args(&owned)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;
            // **The handle falls here**, and that is the whole mechanism:
            // without the `drop` the child sees no EOF and waits for more key
            // material while we wait for its end.
            // **No `expect`**: `stdin` is `piped`, so it is always there --
            // but an assertion about it costs nothing if one does not make it.
            // If the handle is missing against expectation, the child sees EOF
            // immediately and refuses itself; the message then comes from
            // `cryptsetup` and not from us.
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(secret.as_bytes())?;
            }
            child.wait_with_output()
        })();
        let _ = tx.send(outcome);
    });

    finish(program, rx.recv_timeout(within), within)
}

fn run_within(
    program: &'static str,
    args: &[&str],
    within: Duration,
) -> Result<String, VolumeError> {
    let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(Command::new(program).args(&owned).output());
    });

    finish(program, rx.recv_timeout(within), within)
}

fn finish(
    program: &'static str,
    received: Result<std::io::Result<std::process::Output>, std::sync::mpsc::RecvTimeoutError>,
    within: Duration,
) -> Result<String, VolumeError> {
    let output = match received {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            return Err(VolumeError::Tool {
                program,
                detail: if err.kind() == std::io::ErrorKind::NotFound {
                    format!("not in the PATH -- {program} is an operational prerequisite")
                } else {
                    err.to_string()
                },
            });
        }
        Err(_) => {
            return Err(VolumeError::Tool {
                program,
                detail: format!(
                    "did not answer in {} s -- the call was aborted, the child may be \
                     running on. Does the data directory lie on a network file system \
                     whose server is gone?",
                    within.as_secs()
                ),
            });
        }
    };

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(VolumeError::Tool {
            program,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

// ================================================ Shared reference data (10c)

pub async fn materialize_shared(
    store: &crate::content::ContentStore,
    reference: &str,
    login: Option<crate::network::RegistryLogin>,
) -> Result<PathBuf, VolumeError> {
    let pulled = crate::image::pull(store, reference, login)
        .await
        .map_err(|err| VolumeError::Tool {
            program: "pull",
            detail: err.to_string(),
        })?;

    let dirs = crate::bundle::layer_dirs(store, &pulled.layers);
    let [only] = dirs.as_slice() else {
        return compose(store, &pulled.layers, &dirs);
    };

    // A single layer needs no overlay. That is the normal case for reference
    // data -- one tar, one directory -- and it then costs no mount either.
    Ok(only.clone())
}

fn compose(
    store: &crate::content::ContentStore,
    layers: &[crate::content::Digest256],
    dirs: &[PathBuf],
) -> Result<PathBuf, VolumeError> {
    // The composed content's identifier is the digest over the digest list.
    // The composition is thereby content-addressed too and not merely its
    // parts.
    let joined = layers
        .iter()
        .map(crate::content::Digest256::hex)
        .collect::<Vec<_>>()
        .join(":");
    let identity = crate::content::Digest256::of(joined.as_bytes());

    let target = store.root().join("shared").join(identity.hex());
    std::fs::create_dir_all(&target).map_err(|source| VolumeError::Disk {
        path: target.clone(),
        source,
    })?;

    if tg_syscall::mount::is_overlay_mounted(&target) {
        return Ok(target);
    }

    // The order reverses: `lowerdir=` expects the topmost layer first, OCI
    // counts from below. The same reversal as with the bundle.
    let mut lower: Vec<PathBuf> = dirs.to_vec();
    lower.reverse();

    tg_syscall::mount::mount_overlay_readonly(&lower, &target).map_err(|err| {
        VolumeError::Tool {
            program: "mount",
            detail: err.to_string(),
        }
    })?;

    Ok(target)
}

pub fn report_sizes(name: &str, declared: u64, actual: u64) {
    // The precision loss is the format and no defect: a Prometheus metric
    // **is** an `f64`. It would become imprecise beyond 2^53 bytes -- eight
    // petabytes in one volume.
    #[expect(
        clippy::cast_precision_loss,
        reason = "Prometheus computes in f64; 2^53 bytes are eight petabytes"
    )]
    let (declared, actual) = (declared as f64, actual as f64);
    metrics::gauge!(tg_telemetry::names::VOLUME_DECLARED, "volume" => name.to_owned())
        .set(declared);
    metrics::gauge!(tg_telemetry::names::VOLUME_SIZE, "volume" => name.to_owned()).set(actual);
}

pub fn report_snapshots(data_dir: &Path) {
    let Ok(store) = VolumeStore::open(data_dir) else {
        return;
    };
    let Ok(volumes) = store.list() else {
        return;
    };

    // The precision loss is no defect but the format: a Prometheus metric
    // **is** an `f64` (the same rationale as with the domain metrics in
    // `tgd::scheduler`). It would become imprecise beyond 2^53 -- with a
    // number of snapshots and a Unix timestamp that is out of reach.
    #[allow(clippy::cast_precision_loss)]
    for info in volumes {
        let held = store.snapshots(&info.name).unwrap_or_default();
        let name = info.name.clone();
        // **The header decides, not the record** (ADR-0113): a record from
        // the time before the ADR says `false`, and precisely then the metric
        // must be right nevertheless -- otherwise the work list would show a
        // volume that has long been encrypted, or keep quiet about one that is
        // not.
        let encrypted = store
            .image_of(&info.name)
            .is_ok_and(|image| info.encrypted || is_luks(&image));
        metrics::gauge!(tg_telemetry::names::VOLUME_ENCRYPTED, "volume" => name.clone())
            .set(f64::from(u8::from(encrypted)));
        metrics::gauge!(tg_telemetry::names::VOLUME_SNAPSHOTS, "volume" => name.clone())
            .set(held.len() as f64);
        // **The youngest, not the last in the list.** It is sorted by
        // *generation*; what a DR concept asks for is the **time**.
        let youngest = held.iter().map(|snap| snap.taken_at).max().unwrap_or(0);
        metrics::gauge!(tg_telemetry::names::VOLUME_SNAPSHOT_AT, "volume" => name)
            .set(youngest as f64);
    }
}

pub fn report_declared(
    data_dir: &Path,
    workload: &tg_defs::generated::WorkloadType,
    instance: u32,
) {
    use tg_defs::{VolumeExt as _, VolumeMode};

    let declared = tg_defs::WorkloadExt::volumes(workload);
    if declared.is_empty() {
        return;
    }
    let Ok(store) = VolumeStore::open(data_dir) else {
        return;
    };

    for volume in declared {
        if volume.mode() != VolumeMode::ReadWrite {
            continue;
        }
        let Some(bytes) = volume.size() else { continue };
        let name = tg_model::storage::volume_of(volume.name(), VolumeMode::ReadWrite, instance);
        if let Ok(info) = store.info(&name) {
            report_sizes(&name, bytes, info.bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TOOL_TIMEOUT, run_within};
    use std::time::{Duration, Instant};

    #[test]
    fn a_tool_that_does_not_answer_costs_the_deadline() {
        let started = Instant::now();
        let err = run_within("/bin/sleep", &["1"], Duration::from_millis(50))
            .expect_err("the deadline must bite");
        let waited = started.elapsed();

        let text = err.to_string();
        assert!(
            text.contains("sleep") && text.contains("did not answer"),
            "the message must name the tool and the reason: {text}"
        );
        assert!(
            waited < Duration::from_millis(900),
            "it waited {waited:?} -- the deadline did not bite"
        );
    }

    #[test]
    fn a_tool_that_answers_gets_through() {
        let out = run_within("/bin/echo", &["hello"], TOOL_TIMEOUT).expect("echo");
        assert_eq!(out.trim(), "hello");
    }

    #[test]
    fn output_beyond_the_pipe_buffer_is_read() {
        let out = run_within("/usr/bin/seq", &["1", "200000"], TOOL_TIMEOUT).expect("seq");
        assert!(
            out.len() > 64 * 1024,
            "the output was only {} bytes -- then this test does not check the buffer",
            out.len()
        );
        assert!(out.ends_with("200000\n"), "the output is truncated");
    }

    #[test]
    fn only_the_wrappers_set_the_deadline() {
        let source = include_str!("volume.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);

        assert_eq!(
            production.matches("TOOL_TIMEOUT)").count(),
            2,
            "the deadline belongs at exactly one place per wrapper -- `run` \
             and `run_with_secret`"
        );
        assert_eq!(
            production.matches("recv_timeout(within)").count(),
            2,
            "both `_within` siblings must take the deadline passed to them, \
             not the constant"
        );
    }
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            let guard = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn a_volume_that_stays_frozen_is_named() {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let armed = super::Thaw {
                name: "payments",
                target: std::path::PathBuf::from("/does-not-exist/no-volume"),
                armed: true,
            };
            drop(armed);
        });

        let text = captured.text();
        assert!(text.contains("payments"), "{text}");
        assert!(text.contains("frozen"), "the reason is missing: {text}");
    }

    #[test]
    fn a_disarmed_thaw_stays_quiet() {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let disarmed = super::Thaw {
                name: "payments",
                target: std::path::PathBuf::from("/does-not-exist/no-volume"),
                armed: false,
            };
            drop(disarmed);
        });

        assert!(
            captured.text().is_empty(),
            "a disarmed Thaw must report nothing: {}",
            captured.text()
        );
    }
}
