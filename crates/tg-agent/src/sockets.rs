//! One workload API socket per instance (ADR-0081).
//!
//! # Why per instance
//!
//! **The socket is the attestation.** Every container gets its own, mounted into
//! exactly it (ADR-0079) — whoever reached it is in this container. With that
//! `SO_PEERPIDFD` (Linux 6.5), the cgroup read and the forward resolution over a
//! handed-in mapping (ADR-0065) fall away: four steps become one, and the kernel
//! lower bound from ADR-0053 falls.
//!
//! # What separates
//!
//! Three properties, and the first is measured: a socket in a `0700` directory is
//! reachable over a **bind mount** and not over the host path (as an
//! unprivileged user: `Permission denied`).
//!
//! 1. The directory belongs to `root` and is `0700` — no unprivileged process on
//!    the node reaches a socket.
//! 2. The bind mount mounts the inode directly, so the directory permissions do
//!    not take hold in the container: the workload reaches its own.
//! 3. **Another** container does not have the host path in its mount namespace —
//!    it cannot name a foreign socket.
//!
//! The socket itself stays `0666` (ADR-0060: the sidecar runs under an identifier
//! of its own, and a connection demands write permission). What changes is that
//! the permissions are no longer needed to **separate**.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tg_runtime::network::Sockets;

const DIR: &str = "sockets";

const DIR_MODE: u32 = 0o700;

const SOCKET_MODE: u32 = 0o666;

pub(crate) struct Listeners {
    dir: PathBuf,
    running: Mutex<BTreeMap<String, tokio::task::JoinHandle<()>>>,
    api: crate::identity::Api,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Advice {
    Fits,
    Shortens {
        longest: usize,
    },
    None,
}

fn advice(dir: &Path) -> Advice {
    match longest_name(dir) {
        None => Advice::None,
        Some(longest) if longest < tg_model::mesh::MAX_NAME => Advice::Shortens { longest },
        Some(_) => Advice::Fits,
    }
}

const SUFFIX: &str = ".sock";

fn longest_name(dir: &Path) -> Option<usize> {
    // `tg-` + name + `-` + two digits + `.sock`, plus the slash. The prefix
    // comes from the source (`tg_runtime::bundle::PREFIX`) -- a string of its own
    // here would have separated the computation from the identifier it
    // measures.
    let fixed = 1 + tg_runtime::bundle::PREFIX.len() + 1 + 2 + SUFFIX.len();
    tg_syscall::unix_path::headroom(dir)?.checked_sub(fixed)
}

impl Listeners {
    pub(crate) fn open(data_dir: &Path, api: crate::identity::Api) -> Result<Self, String> {
        let dir = data_dir.join(DIR);
        std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;

        // **The permissions before the first socket**, not after: the other way
        // round there would be a window in which a socket lies in an open
        // directory -- and it would be widest open precisely at startup (the same
        // argument as with the admin socket, ADR-0044).
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(DIR_MODE))
            .map_err(|err| format!("{} to {DIR_MODE:o}: {err}", dir.display()))?;

        // **What still fits with this data directory** -- said now, not at the
        // first start of a workload with a long name (see [`advice`]).
        match advice(&dir) {
            Advice::Fits => {}
            Advice::Shortens { longest } => tracing::warn!(
                directory = %dir.display(),
                longest_name = longest,
                facet = tg_model::mesh::MAX_NAME,
                limit = tg_syscall::unix_path::MAX_PATH,
                "with this data directory only a workload name of at most \
                 {longest} characters fits into the socket path; longer ones get \
                 no socket, and their containers do not start (ADR-0081). \
                 Remedy: a shorter --data-dir or shorter names"
            ),
            Advice::None => tracing::error!(
                directory = %dir.display(),
                limit = tg_syscall::unix_path::MAX_PATH,
                "this data directory is too long for a Unix socket -- **no** \
                 container gets an identity (ADR-0081)"
            ),
        }

        Ok(Self {
            dir,
            running: Mutex::new(BTreeMap::new()),
            api,
        })
    }

    fn path_of(&self, container: &str) -> PathBuf {
        self.dir.join(format!("{container}{SUFFIX}"))
    }
}

impl Sockets for Listeners {
    fn ensure(&self, container: &str) -> Result<PathBuf, String> {
        let path = self.path_of(container);

        let mut running = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // **Idempotent** (ADR-0010): if it is already running, it stays. Binding
        // it anew would take a running container's way to its identity, and a
        // reconciler that did that per pass would be worse than none.
        if let Some(handle) = running.get(container)
            && !handle.is_finished()
        {
            return Ok(path);
        }

        // A socket left lying from a previous run otherwise holds the bind up.
        // It belongs to us, and its loss does not hurt.
        // **The reason before the attempt.** `bind` refuses a path that is too
        // long itself ("path must be shorter than SUN_LEN", `raw_os_error` is
        // `None` -- it does not reach the kernel at all), and that message names
        // neither the number nor the two levers. Measured, the limit is 107
        // bytes, and a data directory **per node** (ADR-0043) breaks it already
        // with a name the schema permits.
        //
        // **What has no witness here is the message**, and that stands so:
        // `ensure` demands a running service including a CA. What is guarded is
        // the *condition* -- `tg_syscall::unix_path` holds `fits` against a real
        // `bind`, at the limit and one byte over it. And the number together with
        // the two levers is said by the start anyway (see [`advice`]); this
        // message is for whoever read past it.
        if !tg_syscall::unix_path::fits(&path) {
            return Err(format!(
                "{}: {} bytes, the limit for a Unix socket is {} -- a shorter \
                 --data-dir or a shorter workload name (ADR-0081)",
                path.display(),
                path.as_os_str().len(),
                tg_syscall::unix_path::MAX_PATH
            ));
        }

        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path)
            .map_err(|err| format!("{}: {err}", path.display()))?;

        // Fail-**hard**, unlike with the socket per node: there it stayed
        // unreachable for the sidecar without the permissions and the node
        // carried on. Here the start of this one container hangs on it, and a
        // container without a way to its identity starts up as if nothing
        // (ADR-0007).
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|err| format!("{} to {SOCKET_MODE:o}: {err}", path.display()))?;

        let api = self.api.clone();
        let id: std::sync::Arc<str> = std::sync::Arc::from(container);
        let name = container.to_owned();
        running.insert(
            container.to_owned(),
            tokio::spawn(async move {
                let stream = tg_identity::incoming_for(listener, Some(id));
                if let Err(err) = tg_identity::serve_on(api, stream, std::future::pending()).await {
                    tracing::error!(container = %name, error = %err, "workload API ended");
                }
            }),
        );

        Ok(path)
    }

    fn held(&self) -> Vec<String> {
        self.running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    fn release(&self, container: &str) {
        if let Some(handle) = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(container)
        {
            handle.abort();
        }

        let path = self.path_of(container);
        if let Err(err) = std::fs::remove_file(&path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            // Said and not reported: the container is gone, and a socket left
            // lying is no reason to report it as "not cleared away" (ADR-0058).
            // The minter refuses a request over it anyway -- what this node may
            // mint is said by `set_assigned`.
            tracing::warn!(container, error = %err, "the socket stayed lying");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_data_dir_per_node_does_not_fit_a_maximal_name() {
        let short = Path::new("/var/lib/tardigrade").join(DIR);
        let per_node = Path::new("/var/lib/tardigrade/node-1").join(DIR);

        let fits_short = longest_name(&short).expect("fits");
        let fits_node = longest_name(&per_node).expect("fits");

        assert!(
            fits_short >= tg_model::mesh::MAX_NAME,
            "the short directory must carry the whole facet, but carries {fits_short}"
        );
        assert!(
            fits_node < tg_model::mesh::MAX_NAME,
            "a data directory per node should break the limit, but carries {fits_node}"
        );
    }

    #[test]
    fn the_advice_distinguishes_the_three_cases() {
        let short = Path::new("/var/lib/tardigrade").join(DIR);
        let per_node = Path::new("/var/lib/tardigrade/node-1").join(DIR);
        let absurd = PathBuf::from(format!("/{}", "x".repeat(tg_syscall::unix_path::MAX_PATH)));

        // **The number, not the identity.** Here stood
        // `Shortens { longest: longest_name(&per_node) }` -- a tautology: it
        // checks that `advice` uses `longest_name`, and not what comes out of it.
        // Measured it is 61, and exactly this number an operator reads off the
        // manual.
        assert_eq!(advice(&short), Advice::Fits);
        assert_eq!(advice(&per_node), Advice::Shortens { longest: 61 });
        assert_eq!(advice(&absurd), Advice::None);
    }

    #[test]
    fn the_handbook_budget_matches_the_computation() {
        let handbook = include_str!("../../../docs/OPERATIONS.md");

        let mut seen = 0;
        for line in handbook.lines() {
            // `| `<path>` | <bytes> | <name> ...`
            let mut cells = line.split('|').map(str::trim);
            let (Some(""), Some(path), Some(bytes), Some(name)) =
                (cells.next(), cells.next(), cells.next(), cells.next())
            else {
                continue;
            };
            let Some(path) = path.strip_prefix('`').and_then(|p| p.strip_suffix('`')) else {
                continue;
            };
            if !path.starts_with('/') {
                continue;
            }
            let Ok(claimed_len) = bytes.parse::<usize>() else {
                continue;
            };
            seen += 1;

            assert_eq!(
                path.len(),
                claimed_len,
                "'{path}' is {} bytes long, the table says {claimed_len}",
                path.len()
            );

            let dir = Path::new(path).join(DIR);
            let longest = longest_name(&dir).expect("the directory fits");
            let claimed = name
                .trim_start_matches("**")
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or_else(|| panic!("'{name}' names no number"));

            assert_eq!(
                longest, claimed,
                "'{path}': computed {longest}, the table says {claimed}"
            );
            assert_eq!(
                longest >= tg_model::mesh::MAX_NAME,
                name.contains("fits entirely"),
                "'{path}': longest={longest}, facet={} -- the table says \
                 {}\"fits entirely\"",
                tg_model::mesh::MAX_NAME,
                if name.contains("fits entirely") {
                    ""
                } else {
                    "not "
                }
            );
        }

        assert!(seen >= 3, "the table was not read: {seen} lines");
    }

    #[test]
    fn a_directory_that_is_itself_too_long_yields_nothing() {
        let long = PathBuf::from(format!("/{}", "x".repeat(tg_syscall::unix_path::MAX_PATH)));
        assert_eq!(longest_name(&long), None);
    }

    #[test]
    fn the_calculation_is_the_worst_case() {
        let dir = PathBuf::from("/var/lib/tardigrade/node-1").join(DIR);
        let fits = longest_name(&dir).expect("fits");

        for (len, expect) in [(fits, true), (fits + 1, false)] {
            let path = dir.join(format!("tg-{}-63.sock", "a".repeat(len)));
            assert_eq!(
                tg_syscall::unix_path::fits(&path),
                expect,
                "name with {len} characters: {} bytes",
                path.as_os_str().len()
            );
        }
    }
}
