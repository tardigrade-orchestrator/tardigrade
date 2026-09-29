//! Network namespaces (ADR-0012).
//!
//! One namespace per **workload instance**, not per container: the sidecar from
//! ADR-0007 moves into the same namespace as its workload (phase 9b). ADR-0012
//! demands the redirect "in the netns", and that is only true if the sidecar is
//! reachable over loopback. In a namespace of its own the way would go over the
//! bridge, and the exception "from the sidecar itself" could no longer be pinned
//! to the user id.
//!
//! The identity does not suffer, and since **ADR-0081** for a different reason
//! than first stood here: the workload API socket lies **per instance** and is
//! mounted into exactly its container — the connection thereby carries the
//! identifier, and `SO_PEERCRED` including the cgroup read is gone. The identity
//! was bound to the network namespace in neither version; the sidecar keeps its
//! own SPIFFE ID and the delegated SVID beside it (ADR-0036).
//!
//! **The one `unsafe` here.** `rustix` wraps `setns`, `mount` and `umount2`
//! safely; `unshare` not — since 1.1 it is deprecated in favour of
//! `unshare_unsafe`, whose safety condition concerns **exclusively**
//! `UnshareFlags::FILES`. Only `NEWNET` is passed here, so the condition does
//! not bite.
//!
//! **The trick with the thread.** Namespaces hang on the thread, not on the
//! process. An `unshare` in the main thread of a `tokio` program would change
//! **that** thread's namespace and leave all the others behind. Every namespace
//! operation therefore runs on a short-lived thread of its own; the namespace
//! survives because the bind mount under [`RUN_DIR`] holds it.

use std::io;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::mount::{UnmountFlags, mount_bind, unmount};
use rustix::thread::{UnshareFlags, move_into_link_name_space, unshare_unsafe};

pub const RUN_DIR: &str = "/run/netns";

const SELF_NET: &str = "/proc/thread-self/ns/net";

#[derive(Debug)]
pub enum NetNsError {
    Exists {
        name: String,
    },
    Missing {
        name: String,
    },
    IllegalName {
        name: String,
    },
    Syscall {
        call: &'static str,
        source: io::Error,
    },
}

impl std::fmt::Display for NetNsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exists { name } => write!(f, "network namespace '{name}' already exists"),
            Self::Missing { name } => write!(f, "network namespace '{name}' does not exist"),
            Self::IllegalName { name } => {
                write!(
                    f,
                    "'{}' is no good as a namespace name",
                    name.escape_debug()
                )
            }
            Self::Syscall { call, source } => write!(f, "{call}: {source}"),
        }
    }
}

impl std::error::Error for NetNsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syscall { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn syscall(call: &'static str) -> impl FnOnce(rustix::io::Errno) -> NetNsError {
    move |errno| NetNsError::Syscall {
        call,
        source: io::Error::from(errno),
    }
}

fn check(name: &str) -> Result<(), NetNsError> {
    let legal = !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');

    if legal {
        Ok(())
    } else {
        Err(NetNsError::IllegalName {
            name: name.to_owned(),
        })
    }
}

pub fn path(name: &str) -> Result<PathBuf, NetNsError> {
    check(name)?;
    Ok(Path::new(RUN_DIR).join(name))
}

pub fn create(name: &str) -> Result<PathBuf, NetNsError> {
    let target = path(name)?;

    std::fs::create_dir_all(RUN_DIR).map_err(|source| NetNsError::Syscall {
        call: "mkdir /run/netns",
        source,
    })?;

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
    {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            return Err(NetNsError::Exists {
                name: name.to_owned(),
            });
        }
        Err(source) => {
            return Err(NetNsError::Syscall {
                call: "create /run/netns/<name>",
                source,
            });
        }
    }

    let mounted = {
        let target = target.clone();
        // A thread of its own: `unshare` acts on the calling thread. Were it
        // this one, the rest of the process would afterwards carry a different
        // namespace than the caller — and nobody would see it.
        std::thread::spawn(move || -> Result<(), NetNsError> {
            // SAFETY: `unshare_unsafe` carries exactly one condition, and it
            // concerns exclusively `UnshareFlags::FILES` — a thread could
            // afterwards no longer see descriptors another created. **Only**
            // `NEWNET` is passed here; the descriptor table stays untouched, and
            // the network namespace is a property of this thread anyway. The
            // thread ends right after.
            unsafe { unshare_unsafe(UnshareFlags::NEWNET) }
                .map_err(syscall("unshare(CLONE_NEWNET)"))?;
            // The mount keeps the namespace alive when this thread dies. The
            // mount namespace is **not** unshared, so it is visible everywhere —
            // including to `ip netns list`.
            mount_bind(SELF_NET, &target).map_err(syscall("mount --bind"))
        })
        .join()
    };

    match mounted {
        Ok(Ok(())) => Ok(target),
        Ok(Err(err)) => {
            let _ = std::fs::remove_file(&target);
            Err(err)
        }
        Err(_) => {
            let _ = std::fs::remove_file(&target);
            Err(NetNsError::Syscall {
                call: "unshare thread",
                source: io::Error::other("the thread died"),
            })
        }
    }
}

pub fn open(name: &str) -> Result<OwnedFd, NetNsError> {
    let target = path(name)?;

    std::fs::File::open(&target)
        .map(OwnedFd::from)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                NetNsError::Missing {
                    name: name.to_owned(),
                }
            } else {
                NetNsError::Syscall {
                    call: "open /run/netns/<name>",
                    source,
                }
            }
        })
}

pub fn delete(name: &str) -> Result<(), NetNsError> {
    let target = path(name)?;
    if !target.exists() {
        return Err(NetNsError::Missing {
            name: name.to_owned(),
        });
    }

    // `DETACH`: the mount goes away as soon as nobody uses it any more. Without
    // it the unmount would fail while a descriptor is still open.
    unmount(&target, UnmountFlags::DETACH).map_err(syscall("umount2"))?;
    std::fs::remove_file(&target).map_err(|source| NetNsError::Syscall {
        call: "unlink /run/netns/<name>",
        source,
    })
}

pub fn list() -> Result<Vec<String>, NetNsError> {
    let entries = match std::fs::read_dir(RUN_DIR) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(NetNsError::Syscall {
                call: "readdir /run/netns",
                source,
            });
        }
    };

    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();

    Ok(names)
}

pub fn run_in<T, F>(name: &str, body: F) -> Result<T, NetNsError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let handle = open(name)?;

    let joined = std::thread::spawn(move || -> Result<T, NetNsError> {
        move_into_link_name_space(
            handle.as_fd(),
            Some(rustix::thread::LinkNameSpaceType::Network),
        )
        .map_err(syscall("setns(CLONE_NEWNET)"))?;
        Ok(body())
    })
    .join();

    match joined {
        Ok(result) => result,
        Err(_) => Err(NetNsError::Syscall {
            call: "setns thread",
            source: io::Error::other("the thread died"),
        }),
    }
}
