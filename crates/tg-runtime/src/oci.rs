//! Driver for OCI runtimes over their command-line interface.
//!
//! ADR-0003: youki-first, crun as a configurable fallback. The coupling runs
//! deliberately over the **OCI CLI** (`create`/`start`/`state`/`kill`/
//! `delete`) and not over an embedded library -- only that way do the runtimes
//! stay exchangeable, which the ADR expressly demands.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::error::RuntimeError;

pub const DEFAULT_RUNTIMES: &[&str] = &["youki", "crun"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStatus {
    Created,
    Running,
    Paused,
    Stopped,
    Absent,
    Unknown(&'static str),
}

impl ContainerStatus {
    #[must_use]
    pub fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }

    fn from_spec_str(value: &str) -> Self {
        match value {
            "creating" | "created" => Self::Created,
            "running" => Self::Running,
            "paused" => Self::Paused,
            "stopped" => Self::Stopped,
            _ => Self::Unknown("an unknown OCI status"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OciRuntime {
    binary: PathBuf,
    root: PathBuf,
}

pub const CALL_TIMEOUT: Duration = Duration::from_mins(1);

async fn timed<T>(
    command: &str,
    runtime: &str,
    call: impl Future<Output = T>,
) -> Result<T, RuntimeError> {
    timed_within(command, runtime, CALL_TIMEOUT, call).await
}

async fn timed_within<T>(
    command: &str,
    runtime: &str,
    within: Duration,
    call: impl Future<Output = T>,
) -> Result<T, RuntimeError> {
    tokio::time::timeout(within, call)
        .await
        .map_err(|_| RuntimeError::Runtime {
            runtime: runtime.to_owned(),
            command: command.to_owned(),
            status: None,
            stderr: format!(
                "did not answer within {} s -- the call was aborted. A hanging \
                 runtime call halts the whole pass, and with it the self-fence \
                 of a single writer (ADR-0064).",
                within.as_secs()
            ),
        })
}

impl OciRuntime {
    pub fn discover(
        candidates: &[&str],
        state_root: impl Into<PathBuf>,
    ) -> Result<Self, RuntimeError> {
        let root = state_root.into();

        for candidate in candidates {
            if let Some(path) = which(candidate) {
                return Ok(Self { binary: path, root });
            }
        }

        Err(RuntimeError::RuntimeMissing {
            candidates: candidates.iter().map(|c| (*c).to_owned()).collect(),
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.binary
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
    }

    pub async fn create(&self, id: &str, bundle: &Path) -> Result<(), RuntimeError> {
        let log_path = bundle.join("container.log");
        let log = std::fs::File::create(&log_path).map_err(|source| RuntimeError::Runtime {
            runtime: self.name().to_owned(),
            command: "create".to_owned(),
            status: None,
            stderr: format!("the log {} is not creatable: {source}", log_path.display()),
        })?;
        let log_err = log.try_clone().map_err(|source| RuntimeError::Runtime {
            runtime: self.name().to_owned(),
            command: "create".to_owned(),
            status: None,
            stderr: format!("the log descriptor is not duplicable: {source}"),
        })?;

        let status = Command::new(&self.binary)
            .arg("--root")
            .arg(&self.root)
            .args(["create", "--bundle", &bundle.to_string_lossy(), id])
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            // `kill_on_drop`: if the deadline runs out, `timeout` gives the
            // future up -- without it the child stayed behind as an orphan,
            // and this tree has paid for remnants several times.
            .kill_on_drop(true)
            .status();
        let status = timed("create", self.name(), status)
            .await?
            .map_err(|source| RuntimeError::Runtime {
                runtime: self.name().to_owned(),
                command: "create".to_owned(),
                status: None,
                stderr: source.to_string(),
            })?;

        if status.success() {
            return Ok(());
        }

        Err(RuntimeError::Runtime {
            runtime: self.name().to_owned(),
            command: format!("create --bundle {} {id}", bundle.display()),
            status: status.code(),
            stderr: tail_of(&log_path),
        })
    }

    pub async fn start(&self, id: &str) -> Result<(), RuntimeError> {
        self.run(&["start", id]).await.map(drop)
    }

    pub async fn status(&self, id: &str) -> Result<ContainerStatus, RuntimeError> {
        match self.run(&["state", id]).await {
            Ok(stdout) => Ok(parse_status(&stdout)),
            Err(RuntimeError::Runtime { stderr, .. }) if mentions_missing_container(&stderr) => {
                Ok(ContainerStatus::Absent)
            }
            Err(other) => Err(other),
        }
    }

    pub async fn kill(&self, id: &str, signal: &str) -> Result<(), RuntimeError> {
        self.run(&["kill", id, signal]).await.map(drop)
    }

    pub fn list(&self) -> Result<Vec<String>, RuntimeError> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(RuntimeError::io("the state directory", &self.root, source));
            }
        };

        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry
                .map_err(|source| RuntimeError::io("the state directory", &self.root, source))?;
            if !entry.path().is_dir() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                ids.push(name.to_owned());
            }
        }

        ids.sort();
        Ok(ids)
    }

    pub async fn delete(&self, id: &str, force: bool) -> Result<(), RuntimeError> {
        let mut args = vec!["delete"];
        if force {
            args.push("--force");
        }
        args.push(id);
        self.run(&args).await.map(drop)
    }

    async fn run(&self, args: &[&str]) -> Result<String, RuntimeError> {
        let output = Command::new(&self.binary)
            .arg("--root")
            .arg(&self.root)
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output();
        let command = args.first().map_or_else(String::new, |a| (*a).to_owned());
        let output = timed(&command, self.name(), output)
            .await?
            .map_err(|source| RuntimeError::Runtime {
                runtime: self.name().to_owned(),
                command,
                status: None,
                stderr: source.to_string(),
            })?;

        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }

        Err(RuntimeError::Runtime {
            runtime: self.name().to_owned(),
            command: args.join(" "),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn tail_of(path: &Path) -> String {
    const MAX: usize = 4096;

    let Ok(text) = std::fs::read_to_string(path) else {
        return format!("(the log {} is not readable)", path.display());
    };
    let trimmed = text.trim_end();

    if trimmed.len() <= MAX {
        return trimmed.to_owned();
    }

    let start = trimmed.len() - MAX;
    // Go back to a character boundary, otherwise the slicing panics.
    let start = (start..trimmed.len())
        .find(|i| trimmed.is_char_boundary(*i))
        .unwrap_or(trimmed.len());

    format!("… {}", &trimmed[start..])
}

fn parse_status(stdout: &str) -> ContainerStatus {
    let Some(rest) = stdout.split("\"status\"").nth(1) else {
        return ContainerStatus::Unknown("no status field in the state output");
    };
    let Some(rest) = rest.split_once(':') else {
        return ContainerStatus::Unknown("a status field without a value");
    };
    let mut chars = rest.1.trim_start().chars();
    if chars.next() != Some('"') {
        return ContainerStatus::Unknown("the status value is not a string");
    }
    let value: String = chars.take_while(|c| *c != '"').collect();

    ContainerStatus::from_spec_str(&value)
}

fn mentions_missing_container(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    lowered.contains("does not exist")
        || lowered.contains("not exist")
        || lowered.contains("no such container")
        || lowered.contains("failed to find")
        || lowered.contains("container not found")
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_read_from_oci_state_json() {
        let json = r#"{"ociVersion":"1.0.2","id":"tg-api","status":"running","pid":42}"#;
        assert_eq!(parse_status(json), ContainerStatus::Running);
    }

    #[test]
    fn status_tolerates_whitespace_and_field_order() {
        let json = "{\n  \"id\": \"tg-api\",\n  \"status\" :   \"stopped\"\n}";
        assert_eq!(parse_status(json), ContainerStatus::Stopped);
    }

    #[test]
    fn created_and_creating_both_count_as_created() {
        assert_eq!(
            parse_status(r#"{"status":"created"}"#),
            ContainerStatus::Created
        );
        assert_eq!(
            parse_status(r#"{"status":"creating"}"#),
            ContainerStatus::Created
        );
    }

    #[test]
    fn missing_status_field_does_not_panic() {
        assert!(matches!(parse_status("{}"), ContainerStatus::Unknown(_)));
        assert!(matches!(parse_status(""), ContainerStatus::Unknown(_)));
    }

    #[test]
    fn absent_container_is_recognised_for_youki_and_crun() {
        assert!(mentions_missing_container(
            "Error: container tg-api does not exist"
        ));
        assert!(mentions_missing_container(
            "error opening file `state.json`: No such container"
        ));
        assert!(mentions_missing_container(
            "failed to find container tg-api"
        ));
        assert!(!mentions_missing_container("permission denied"));
    }

    #[test]
    fn running_status_is_the_only_one_that_counts_as_running() {
        assert!(ContainerStatus::Running.is_running());
        for other in [
            ContainerStatus::Created,
            ContainerStatus::Paused,
            ContainerStatus::Stopped,
            ContainerStatus::Absent,
        ] {
            assert!(!other.is_running(), "{other:?} must not count as running");
        }
    }

    #[test]
    fn the_state_directory_names_the_containers() {
        let dir = tempfile::tempdir().expect("tempdir");
        for id in ["tg-api", "tg-ledger-2"] {
            std::fs::create_dir(dir.path().join(id)).expect("the directory");
        }
        // A file is no container. Both runtimes lay out a directory; what
        // lies beside it does not belong to it.
        std::fs::write(dir.path().join("something.json"), "{}").expect("the file");

        let runtime = OciRuntime {
            binary: PathBuf::from("/bin/true"),
            root: dir.path().to_path_buf(),
        };

        assert_eq!(
            runtime.list().expect("readable"),
            vec!["tg-api".to_owned(), "tg-ledger-2".to_owned()]
        );
    }

    #[test]
    fn a_missing_state_directory_is_empty_not_broken() {
        let runtime = OciRuntime {
            binary: PathBuf::from("/bin/true"),
            root: PathBuf::from("/tmp/does-not-exist-tg-0058"),
        };

        assert!(runtime.list().expect("no error").is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_hanging_call_ends_with_a_reason() {
        let dir = tempfile::tempdir().expect("the directory");
        let binary = dir.path().join("crun");
        std::fs::write(&binary, "#!/bin/sh\nexec sleep 600\n").expect("the dummy");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
                .expect("the mode");
        }
        let runtime = OciRuntime {
            binary,
            root: dir.path().join("runtime"),
        };

        // `CALL_TIMEOUT` is a constant, and that is deliberate -- so what is
        // measured here is not the number but that the call **hangs** where it
        // bites. The second half (expiry and message) stands in the witness
        // below, with a paused clock.
        let hung =
            tokio::time::timeout(Duration::from_secs(2), runtime.kill("tg-whatever", "TERM")).await;
        assert!(
            hung.is_err(),
            "the call returned within 2 s -- then it does not hang, and the \
             test checks nothing: {hung:?}"
        );
    }

    #[tokio::test]
    async fn the_deadline_names_the_call_and_its_cost() {
        // The witness protects itself: if `timed_within` does **not** take
        // the handed-in deadline, it hangs on a `pending()` -- measured at a
        // counter-check that put in 60 minutes, and a test that hangs is worse
        // than one that fails. The outer deadline turns that into a failure in
        // five seconds; **which** number the production path takes is held by
        // the witness below (without waiting).
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            timed_within::<()>(
                "delete",
                "crun",
                Duration::from_millis(10),
                std::future::pending(),
            ),
        )
        .await
        .expect("`timed_within` does not take the handed-in deadline -- the call hangs")
        .expect_err("the deadline must run out");
        let text = err.to_string();
        assert!(
            text.contains("delete") && text.contains("crun"),
            "the message does not name the call and the runtime: '{text}'"
        );
        assert!(text.contains("self-fence"), "and the reason: '{text}'");
    }

    #[test]
    fn only_the_wrapper_sets_the_deadline() {
        let source = include_str!("oci.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        // Measured **one** call site: the definition reads `timed_within<T>(`,
        // so it does not carry the pattern.
        assert_eq!(
            production.matches("timed_within(").count(),
            1,
            "`timed_within` belongs in the production part exactly once: the \
             call from `timed`. Whoever builds a second place sets a second \
             deadline."
        );
        assert!(
            production.contains("timeout(within, call)"),
            "the deadline must be the handed-in one -- otherwise the witness \
             above says nothing about `CALL_TIMEOUT`"
        );
    }

    #[test]
    fn discovery_reports_all_candidates_when_none_is_found() {
        let err = OciRuntime::discover(&["does-not-exist-xyz"], "/tmp/tg-test").unwrap_err();

        match err {
            RuntimeError::RuntimeMissing { candidates } => {
                assert_eq!(candidates, vec!["does-not-exist-xyz".to_owned()]);
            }
            other => panic!("the wrong error: {other}"),
        }
    }
}
