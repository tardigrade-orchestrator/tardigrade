//! Mount operations for container rootfs.
//!
//! ADR-0003: snapshots via overlayfs — a kernel feature, no eBPF.

use std::ffi::CString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use rustix::mount::{MountFlags, UnmountFlags, mount, unmount};

#[derive(Debug)]
pub enum MountError {
    Syscall {
        operation: &'static str,
        target: PathBuf,
        source: io::Error,
    },
    UnsupportedPath {
        path: PathBuf,
        reason: &'static str,
    },
    NoLowerDirs,
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syscall {
                operation,
                target,
                source,
            } => write!(f, "{operation} on {} failed: {source}", target.display()),
            Self::UnsupportedPath { path, reason } => {
                write!(f, "path {} is not usable: {reason}", path.display())
            }
            Self::NoLowerDirs => f.write_str("overlayfs needs at least one lowerdir"),
        }
    }
}

impl std::error::Error for MountError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syscall { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayMount {
    target: PathBuf,
}

impl OverlayMount {
    #[must_use]
    pub fn already_mounted(target: &Path) -> Self {
        Self {
            target: target.to_path_buf(),
        }
    }

    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }
}

pub fn mount_overlay(
    lower_dirs: &[PathBuf],
    upper_dir: &Path,
    work_dir: &Path,
    target: &Path,
) -> Result<OverlayMount, MountError> {
    if lower_dirs.is_empty() {
        return Err(MountError::NoLowerDirs);
    }

    for path in lower_dirs
        .iter()
        .map(PathBuf::as_path)
        .chain([upper_dir, work_dir])
    {
        check_option_safe(path)?;
    }

    // The option line goes to the kernel as a C string; it is built over bytes
    // so that paths outside UTF-8 get through too.
    let mut options: Vec<u8> = Vec::from(&b"lowerdir="[..]);
    for (index, dir) in lower_dirs.iter().enumerate() {
        if index > 0 {
            options.push(b':');
        }
        options.extend_from_slice(dir.as_os_str().as_encoded_bytes());
    }
    options.extend_from_slice(b",upperdir=");
    options.extend_from_slice(upper_dir.as_os_str().as_encoded_bytes());
    options.extend_from_slice(b",workdir=");
    options.extend_from_slice(work_dir.as_os_str().as_encoded_bytes());

    let options = CString::new(options).map_err(|_| MountError::UnsupportedPath {
        path: target.to_path_buf(),
        reason: "mount options contain a NUL byte",
    })?;

    mount(
        "overlay",
        target,
        "overlay",
        MountFlags::empty(),
        options.as_c_str(),
    )
    .map_err(|errno| MountError::Syscall {
        operation: "overlayfs mount",
        target: target.to_path_buf(),
        source: io::Error::from(errno),
    })?;

    Ok(OverlayMount {
        target: target.to_path_buf(),
    })
}

#[must_use]
pub fn is_overlay_mounted(target: &Path) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return false;
    };
    let needle = target.to_string_lossy();

    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let (_source, mount_point, fs_type) = (fields.next(), fields.next(), fields.next());
        // /proc/self/mounts escapes spaces as \040 — for the comparison the
        // unescaped form suffices, because our paths contain none.
        mount_point == Some(needle.as_ref()) && fs_type == Some("overlay")
    })
}

pub fn unmount_overlay(target: &Path) -> Result<(), MountError> {
    unmount(target, UnmountFlags::empty()).map_err(|errno| MountError::Syscall {
        operation: "unmount",
        target: target.to_path_buf(),
        source: io::Error::from(errno),
    })
}

fn check_option_safe(path: &Path) -> Result<(), MountError> {
    let bytes = path.as_os_str().as_encoded_bytes();

    if bytes.contains(&b':') {
        return Err(MountError::UnsupportedPath {
            path: path.to_path_buf(),
            reason: "contains ':', the separator of the lowerdir list",
        });
    }
    if bytes.contains(&b',') {
        return Err(MountError::UnsupportedPath {
            path: path.to_path_buf(),
            reason: "contains ',', the separator of the mount options",
        });
    }

    Ok(())
}

pub fn isolate_mounts() -> Result<(), MountError> {
    use rustix::mount::{MountPropagationFlags, mount_change};
    use rustix::thread::{UnshareFlags, unshare_unsafe};

    // SAFETY: the safety condition of `unshare_unsafe` concerns exclusively
    // `UnshareFlags::FILES` — a thread would afterwards no longer see another's
    // descriptors. Only `NEWNS` is passed here; the descriptor table stays
    // untouched. The same rationale as in `netns::create`.
    unsafe { unshare_unsafe(UnshareFlags::NEWNS) }.map_err(|errno| MountError::Syscall {
        operation: "unshare(CLONE_NEWNS)",
        target: PathBuf::from("/"),
        source: io::Error::from(errno),
    })?;

    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(|errno| MountError::Syscall {
        operation: "mount --make-rprivate",
        target: PathBuf::from("/"),
        source: io::Error::from(errno),
    })
}

pub fn bind_file(source: &Path, target: &Path) -> Result<(), MountError> {
    rustix::mount::mount_bind(source, target).map_err(|errno| MountError::Syscall {
        operation: "mount --bind",
        target: target.to_path_buf(),
        source: io::Error::from(errno),
    })
}

pub fn bind_device(device: &str, target: &Path) -> Result<(), MountError> {
    rustix::mount::mount(
        device,
        target,
        "ext4",
        rustix::mount::MountFlags::empty(),
        None,
    )
    .map_err(|errno| MountError::Syscall {
        operation: "mount(ext4)",
        target: target.to_path_buf(),
        source: io::Error::from(errno),
    })
}

pub fn mount_tmpfs(target: &Path, bytes: u64) -> Result<(), MountError> {
    // The options are built from constants and a number — a NUL byte is not
    // constructible, so `CString::new` never fails.
    let options = CString::new(format!("size={bytes},mode=0700")).map_err(|_| {
        MountError::UnsupportedPath {
            path: target.to_path_buf(),
            reason: "mount options contain a NUL byte",
        }
    })?;

    mount(
        "tmpfs",
        target,
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        options.as_c_str(),
    )
    .map_err(|errno| MountError::Syscall {
        operation: "mount(tmpfs)",
        target: target.to_path_buf(),
        source: io::Error::from(errno),
    })
}

#[must_use]
pub fn is_tmpfs_mounted(target: &Path) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return false;
    };
    let Some(target) = target.to_str() else {
        return false;
    };

    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let source = fields.next();
        let at = fields.next();
        let kind = fields.next();

        source == Some("tmpfs") && at == Some(target) && kind == Some("tmpfs")
    })
}

pub fn unmount_now(target: &Path) -> Result<(), MountError> {
    unmount(target, UnmountFlags::empty()).map_err(|errno| MountError::Syscall {
        operation: "umount2",
        target: target.to_path_buf(),
        source: io::Error::from(errno),
    })
}

pub fn unmount_at(target: &Path) -> Result<(), MountError> {
    rustix::mount::unmount(target, rustix::mount::UnmountFlags::DETACH).map_err(|errno| {
        MountError::Syscall {
            operation: "umount2",
            target: target.to_path_buf(),
            source: io::Error::from(errno),
        }
    })
}

pub fn mount_overlay_readonly(lower_dirs: &[PathBuf], target: &Path) -> Result<(), MountError> {
    if lower_dirs.is_empty() {
        return Err(MountError::NoLowerDirs);
    }
    for path in lower_dirs.iter().map(PathBuf::as_path).chain([target]) {
        check_option_safe(path)?;
    }

    let mut options: Vec<u8> = Vec::from(&b"lowerdir="[..]);
    for (index, dir) in lower_dirs.iter().enumerate() {
        if index > 0 {
            options.push(b':');
        }
        options.extend_from_slice(dir.as_os_str().as_encoded_bytes());
    }

    let options = CString::new(options).map_err(|_| MountError::UnsupportedPath {
        path: target.to_path_buf(),
        reason: "mount options contain a NUL byte",
    })?;

    mount(
        "overlay",
        target,
        "overlay",
        MountFlags::RDONLY,
        options.as_c_str(),
    )
    .map_err(|errno| MountError::Syscall {
        operation: "overlayfs mount (ro)",
        target: target.to_path_buf(),
        source: io::Error::from(errno),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_without_lower_dirs_is_rejected() {
        let result = mount_overlay(
            &[],
            Path::new("/tmp/upper"),
            Path::new("/tmp/work"),
            Path::new("/tmp/target"),
        );

        assert!(matches!(result, Err(MountError::NoLowerDirs)));
    }

    #[test]
    fn colon_in_path_is_rejected_before_the_syscall() {
        let result = mount_overlay(
            &[PathBuf::from("/var/lib/tardigrade/a:b")],
            Path::new("/tmp/upper"),
            Path::new("/tmp/work"),
            Path::new("/tmp/target"),
        );

        assert!(matches!(result, Err(MountError::UnsupportedPath { .. })));
    }

    #[test]
    fn comma_in_path_is_rejected_before_the_syscall() {
        let result = mount_overlay(
            &[PathBuf::from("/var/lib/tardigrade/layer")],
            Path::new("/tmp/up,per"),
            Path::new("/tmp/work"),
            Path::new("/tmp/target"),
        );

        assert!(matches!(result, Err(MountError::UnsupportedPath { .. })));
    }

    #[test]
    fn every_path_is_checked_not_just_the_first() {
        let ok = PathBuf::from("/var/lib/tardigrade/layer");
        let bad = PathBuf::from("/var/lib/tardigrade/a:b");

        let cases = [
            (vec![ok.clone(), bad.clone()], ok.clone(), ok.clone()),
            (vec![ok.clone()], bad.clone(), ok.clone()),
            (vec![ok.clone()], ok.clone(), bad.clone()),
        ];

        for (lower, upper, work) in cases {
            let result = mount_overlay(&lower, &upper, &work, Path::new("/tmp/target"));
            match result {
                Err(MountError::UnsupportedPath { path, reason }) => {
                    assert_eq!(path, bad, "the message names the wrong path");
                    assert!(reason.contains(':'), "{reason}");
                }
                other => panic!("expected UnsupportedPath, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_nul_byte_in_a_path_is_rejected() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let with_nul = PathBuf::from(OsString::from_vec(b"/var/lib/tg/la\0yer".to_vec()));
        let result = mount_overlay(
            &[with_nul],
            Path::new("/tmp/upper"),
            Path::new("/tmp/work"),
            Path::new("/tmp/target"),
        );

        assert!(
            matches!(result, Err(MountError::UnsupportedPath { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn every_error_variant_states_what_and_where() {
        let syscall = MountError::Syscall {
            operation: "overlayfs mount",
            target: PathBuf::from("/var/lib/tardigrade/rootfs"),
            source: io::Error::from_raw_os_error(1),
        };
        let text = syscall.to_string();
        assert!(text.contains("overlayfs mount"), "{text}");
        assert!(text.contains("/var/lib/tardigrade/rootfs"), "{text}");
        assert!(std::error::Error::source(&syscall).is_some());

        let unsupported = MountError::UnsupportedPath {
            path: PathBuf::from("/var/lib/a:b"),
            reason: "contains ':', the separator of the lowerdir list",
        };
        let text = unsupported.to_string();
        assert!(text.contains("/var/lib/a:b"), "{text}");
        assert!(text.contains("separator"), "{text}");
        assert!(std::error::Error::source(&unsupported).is_none());

        let none = MountError::NoLowerDirs;
        assert!(none.to_string().contains("lowerdir"), "{none}");
        assert!(std::error::Error::source(&none).is_none());
    }

    #[test]
    fn an_unmounted_or_foreign_path_does_not_count_as_overlay() {
        let dir = std::env::temp_dir().join("tg-syscall-never-mounted");
        assert!(!is_overlay_mounted(&dir));

        // /proc hangs in every Linux but is never an overlay.
        assert!(!is_overlay_mounted(Path::new("/proc")));

        // A prefix of a real mount point does not count as a hit.
        assert!(!is_overlay_mounted(Path::new("/pro")));
        assert!(!is_overlay_mounted(Path::new("")));
    }

    #[test]
    fn unmounting_something_that_is_not_mounted_fails_cleanly() {
        let dir = std::env::temp_dir().join("tg-syscall-never-mounted");

        match unmount_overlay(&dir) {
            Err(MountError::Syscall {
                operation, target, ..
            }) => {
                assert_eq!(operation, "unmount");
                assert_eq!(target, dir);
            }
            other => panic!("expected a syscall error, got {other:?}"),
        }
    }

    #[test]
    fn an_existing_mount_can_be_described_without_touching_it() {
        let target = Path::new("/var/lib/tardigrade/rootfs/api");
        let mount = OverlayMount::already_mounted(target);

        assert_eq!(mount.target(), target);
        assert_eq!(mount.clone(), mount);
        assert_ne!(
            mount,
            OverlayMount::already_mounted(Path::new("/var/lib/tardigrade/rootfs/db"))
        );
    }
}
