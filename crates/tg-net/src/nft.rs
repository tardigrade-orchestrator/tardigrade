//! Applying the rule set.
//!
//! The rule set goes as JSON to the program `nft`, which runs as a **process
//! of its own**. No netlink binding, no FFI — `nft`'s GPL-2 stays on its side
//! of the `fork` (the same relationship as to youki and crun for the OCI
//! runtime).
//!
//! This module follows a few rules concerning the invocation:
//!
//! - **Check first, then apply.** `nft --check` is a dry run one gets for
//!   free. A rule set that `nft` refuses shall do so **before** the old table
//!   is deleted.
//! - **One transaction per reconcile.** There is no function here that
//!   appends a single rule — measured, one call costs around 12 ms, and with
//!   a hundred containers that would be 1.2 s of pure `fork`/`exec`.
//! - **`nft` stands out at startup**, not at the first container: [`require`].
//!
//! What does **not** stand here is just as deliberate: no function that sends
//! `flush ruleset`. It does not exist, so that nobody calls it by accident and
//! takes the host's firewall with it.

use std::io::Write as _;
use std::process::{Child, Command, Output, Stdio};

const NFT: &str = "nft";

pub const SCHEMA_VERSION: u64 = 1;

#[derive(Debug)]
pub enum NftError {
    Missing,
    Rejected {
        detail: String,
    },
    Failed {
        source: std::io::Error,
    },
    UnknownSchema {
        found: u64,
    },
    Namespace {
        detail: String,
    },
}

impl std::fmt::Display for NftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(
                f,
                "'{NFT}' is not in the PATH — ADR-0038 makes it an operational \
                 prerequisite"
            ),
            Self::Rejected { detail } => write!(f, "{NFT} refused: {detail}"),
            Self::Failed { source } => write!(f, "{NFT} not executable: {source}"),
            Self::UnknownSchema { found } => write!(
                f,
                "{NFT} reports json_schema_version {found}, this module is \
                 written against {SCHEMA_VERSION}"
            ),
            Self::Namespace { detail } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for NftError {}

fn run(args: &[&str], json: &str) -> Result<String, NftError> {
    let child = Command::new(NFT)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                NftError::Missing
            } else {
                NftError::Failed { source }
            }
        })?;

    let output = feed(child, json.as_bytes()).map_err(|source| NftError::Failed { source })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(NftError::Rejected {
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

pub fn check(json: &str) -> Result<(), NftError> {
    run(&["--check", "-j", "-f", "-"], json).map(|_| ())
}

pub fn apply(json: &str) -> Result<(), NftError> {
    check(json)?;
    run(&["-j", "-f", "-"], json).map(|_| ())
}

pub fn list_table(family: &str, table: &str) -> Result<String, NftError> {
    run(&["-j", "list", "table", family, table], "")
}

pub fn apply_in(netns: &str, json: &str) -> Result<(), NftError> {
    let owned = json.to_owned();

    tg_syscall::netns::run_in(netns, move || apply(&owned)).map_err(|err| NftError::Namespace {
        detail: err.to_string(),
    })?
}

pub fn list_table_in(netns: &str, family: &str, table: &str) -> Result<String, NftError> {
    let family = family.to_owned();
    let table = table.to_owned();

    tg_syscall::netns::run_in(netns, move || list_table(&family, &table)).map_err(|err| {
        NftError::Namespace {
            detail: err.to_string(),
        }
    })?
}

pub fn schema_version() -> Result<u64, NftError> {
    let out = run(&["-j", "list", "tables"], "")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&out).map_err(|_| NftError::UnknownSchema { found: 0 })?;

    parsed
        .get("nftables")
        .and_then(|list| list.get(0))
        .and_then(|first| first.get("metainfo"))
        .and_then(|meta| meta.get("json_schema_version"))
        .and_then(serde_json::Value::as_u64)
        .ok_or(NftError::UnknownSchema { found: 0 })
}

pub fn require() -> Result<(), NftError> {
    match schema_version()? {
        SCHEMA_VERSION => Ok(()),
        found => Err(NftError::UnknownSchema { found }),
    }
}

fn feed(mut child: Child, input: &[u8]) -> std::io::Result<Output> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("no standard input"))?;

    // The thread takes the input with it and closes the pipe when it is done. A
    // failure while writing is **not** discarded but answered by the child: it
    // then sees a truncated input and says what it is missing — a better message
    // than "broken pipe".
    let owned = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&owned));

    let output = child.wait_with_output()?;
    // A panicked thread is an error on our side, not a result of the child.
    writer
        .join()
        .map_err(|_| std::io::Error::other("the writer thread panicked"))?
        .or_else(|err| {
            // `BrokenPipe` means the child ended first — then its output is
            // the answer, not our write error.
            if err.kind() == std::io::ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(err)
            }
        })?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::feed;
    use std::process::{Command, Stdio};

    #[test]
    fn a_child_that_writes_back_does_not_block_the_writer() {
        let (sender, receiver) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let child = Command::new("cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("cat");
            let input = vec![b'x'; 1024 * 1024];
            let output = feed(child, &input).expect("output");
            let _ = sender.send(output.stdout.len());
        });

        let seen = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
                "the write did not come back — the child's standard input is \
                 filled while nobody reads its output",
            );

        assert_eq!(seen, 1024 * 1024, "cat returns what it gets");
    }
}
