//! The runtime crate's error type.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum RuntimeError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Volume {
        volume: String,
        detail: String,
    },
    Network {
        instance: String,
        detail: String,
    },
    DigestMismatch {
        expected: String,
        actual: String,
    },
    MalformedDigest {
        value: String,
        reason: String,
    },
    BundleTaken {
        owner: String,
        wanted: String,
    },
    MalformedWhiteout {
        marker: String,
        reason: &'static str,
    },
    UnknownMediaType {
        media_type: String,
    },
    Decompress {
        codec: &'static str,
        source: io::Error,
    },
    Pull {
        reference: String,
        detail: String,
    },
    Mount(tg_syscall::mount::MountError),
    Runtime {
        runtime: String,
        command: String,
        status: Option<i32>,
        stderr: String,
    },
    RuntimeMissing {
        candidates: Vec<String>,
    },
    Unenforceable {
        workload: String,
        detail: String,
    },
    Unmappable {
        workload: String,
        reason: String,
    },
}

impl RuntimeError {
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io",
            Self::Volume { .. } => "volume",
            Self::Network { .. } => "network",
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::MalformedDigest { .. } => "malformed_digest",
            Self::BundleTaken { .. } => "bundle_taken",
            Self::MalformedWhiteout { .. } => "malformed_whiteout",
            Self::UnknownMediaType { .. } => "unknown_media_type",
            Self::Decompress { .. } => "decompress",
            Self::Pull { .. } => "pull",
            Self::Mount { .. } => "mount",
            Self::Runtime { .. } => "runtime",
            Self::RuntimeMissing { .. } => "runtime_missing",
            Self::Unenforceable { .. } => "unenforceable",
            Self::Unmappable { .. } => "unmappable",
        }
    }
}

impl RuntimeError {
    pub(crate) fn io(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }

    pub(crate) fn decompress(codec: &'static str, source: io::Error) -> Self {
        Self::Decompress { codec, source }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Volume { volume, detail } => {
                write!(f, "the volume '{volume}': {detail}")
            }
            Self::Network { instance, detail } => {
                write!(f, "the network for '{instance}': {detail}")
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(f, "{operation} ({}) failed: {source}", path.display()),
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "the digest does not match: expected {expected}, computed {actual}"
            ),
            Self::MalformedDigest { value, reason } => {
                write!(f, "the digest '{value}' is unreadable: {reason}")
            }
            Self::BundleTaken { owner, wanted } => {
                write!(
                    f,
                    "the bundle belongs to '{owner}', '{wanted}' does not get it -- \
                     two instances would otherwise share their ephemeral volume \
                     (ADR-0027)"
                )
            }
            Self::MalformedWhiteout { marker, reason } => {
                write!(f, "the whiteout marker '{marker}' is unusable: {reason}")
            }
            Self::UnknownMediaType { media_type } => {
                write!(f, "an unknown layer media type '{media_type}'")
            }
            Self::Decompress { codec, source } => {
                write!(f, "the {codec} decompression failed: {source}")
            }
            Self::Pull { reference, detail } => {
                write!(f, "the image '{reference}' could not be fetched: {detail}")
            }
            Self::Mount(source) => write!(f, "the rootfs could not be mounted: {source}"),
            Self::Runtime {
                runtime,
                command,
                status,
                stderr,
            } => {
                write!(f, "'{runtime} {command}' failed")?;
                if let Some(code) = status {
                    write!(f, " (exit {code})")?;
                }
                if !stderr.trim().is_empty() {
                    write!(f, ": {}", stderr.trim())?;
                }
                Ok(())
            }
            Self::RuntimeMissing { candidates } => write!(
                f,
                "no OCI runtime was found, what was looked for: {}",
                candidates.join(", ")
            ),
            Self::Unenforceable { workload, detail } => {
                write!(f, "the workload '{workload}': {detail}")
            }
            Self::Unmappable { workload, reason } => {
                write!(f, "the workload '{workload}' cannot be mapped: {reason}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::Decompress { source, .. } => Some(source),
            Self::Mount(source) => Some(source),
            _ => None,
        }
    }
}

impl From<tg_syscall::mount::MountError> for RuntimeError {
    fn from(source: tg_syscall::mount::MountError) -> Self {
        Self::Mount(source)
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeError;
    use std::error::Error as _;

    fn tripwire(error: &RuntimeError) {
        match error {
            RuntimeError::Io { .. }
            | RuntimeError::Volume { .. }
            | RuntimeError::Network { .. }
            | RuntimeError::DigestMismatch { .. }
            | RuntimeError::MalformedDigest { .. }
            | RuntimeError::BundleTaken { .. }
            | RuntimeError::MalformedWhiteout { .. }
            | RuntimeError::UnknownMediaType { .. }
            | RuntimeError::Decompress { .. }
            | RuntimeError::Pull { .. }
            | RuntimeError::Mount(_)
            | RuntimeError::Runtime { .. }
            | RuntimeError::RuntimeMissing { .. }
            | RuntimeError::Unenforceable { .. }
            | RuntimeError::Unmappable { .. } => {}
        }
    }

    fn cases() -> Vec<(RuntimeError, Vec<&'static str>)> {
        vec![
            (
                RuntimeError::io(
                    "laying out the directory",
                    std::path::Path::new("/var/lib/tardigrade/rootfs"),
                    std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                ),
                vec!["laying out the directory", "/var/lib/tardigrade/rootfs"],
            ),
            (
                RuntimeError::DigestMismatch {
                    expected: "sha256:aaa".to_owned(),
                    actual: "sha256:bbb".to_owned(),
                },
                vec!["sha256:aaa", "sha256:bbb"],
            ),
            (
                RuntimeError::MalformedDigest {
                    value: "sha256".to_owned(),
                    reason: "no colon".to_owned(),
                },
                vec!["sha256", "no colon"],
            ),
            (
                RuntimeError::UnknownMediaType {
                    media_type: "application/x-home-made".to_owned(),
                },
                vec!["application/x-home-made"],
            ),
            (
                RuntimeError::decompress(
                    "gzip",
                    std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
                ),
                vec!["gzip"],
            ),
            (
                RuntimeError::Pull {
                    reference: "example.com/api:1".to_owned(),
                    detail: "401 Unauthorized".to_owned(),
                },
                vec!["example.com/api:1", "401 Unauthorized"],
            ),
            (
                RuntimeError::Mount(tg_syscall::mount::MountError::NoLowerDirs),
                vec!["lowerdir"],
            ),
            (
                RuntimeError::RuntimeMissing {
                    candidates: vec!["youki".to_owned(), "crun".to_owned()],
                },
                vec!["youki", "crun"],
            ),
            (
                RuntimeError::Unenforceable {
                    workload: "api".to_owned(),
                    detail: "device rules are not enforceable on cgroup v2 without eBPF".to_owned(),
                },
                vec!["api", "device rules"],
            ),
            (
                RuntimeError::Unmappable {
                    workload: "api".to_owned(),
                    reason: "a cycle in the dependency graph".to_owned(),
                },
                vec!["api", "a cycle"],
            ),
            (
                RuntimeError::Volume {
                    volume: "payments".to_owned(),
                    detail: "resize2fs: no space left".to_owned(),
                },
                vec!["payments", "no space left"],
            ),
            (
                RuntimeError::Network {
                    instance: "tg-api-1".to_owned(),
                    detail: "the veth pair already exists".to_owned(),
                },
                vec!["tg-api-1", "veth pair"],
            ),
            // **Both identifiers**, and that is the whole assurance of this variant:
            // a refused mount must let an operator know **who** stands in the way.
            (
                RuntimeError::BundleTaken {
                    owner: "tg-ledger".to_owned(),
                    wanted: "tg-api-1".to_owned(),
                },
                // **Two names of which neither is a prefix of the other.** With
                // `tg-api`/`tg-api-1` the test would pass for a message that names
                // only the second too.
                vec!["tg-ledger", "tg-api-1"],
            ),
            (
                RuntimeError::MalformedWhiteout {
                    marker: ".wh...".to_owned(),
                    reason: "no single ordinary path component",
                },
                vec![".wh...", "path component"],
            ),
        ]
    }

    #[test]
    fn every_class_is_its_own_word() {
        // `Runtime` is missing from `cases()` (the message arises piecewise there)
        // but belongs here: checked completeness would otherwise be fourteen of
        // fifteen.
        let mut errors: Vec<RuntimeError> = cases().into_iter().map(|(err, _)| err).collect();
        errors.push(RuntimeError::Runtime {
            runtime: "youki".to_owned(),
            command: "create".to_owned(),
            status: Some(1),
            stderr: String::new(),
        });
        assert_eq!(errors.len(), 15, "fifteen variants");

        let mut seen: Vec<&str> = errors.iter().map(RuntimeError::class).collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            total,
            "two variants carry the same class: {seen:?}"
        );

        for class in seen {
            assert!(!class.is_empty(), "a class is empty");
            assert!(
                class.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "'{class}' is no good as a label"
            );
        }
    }

    #[test]
    fn every_variant_names_its_subject_and_its_cause() {
        let cases = cases();

        // `Runtime` has its own witness (the message arises piecewise there) but
        // stands in the tripwire -- the attention is on the **set**, not on this list.
        assert_eq!(cases.len(), 14, "fourteen of fifteen stand here");

        for (error, expected) in cases {
            tripwire(&error);
            let text = error.to_string();
            for needle in expected {
                assert!(text.contains(needle), "'{needle}' is missing from: {text}");
            }
            assert!(!text.trim().is_empty());
        }
    }

    #[test]
    fn the_runtime_error_reads_well_in_every_combination() {
        let build = |status: Option<i32>, stderr: &str| RuntimeError::Runtime {
            runtime: "youki".to_owned(),
            command: "create api".to_owned(),
            status,
            stderr: stderr.to_owned(),
        };

        let full = build(Some(1), "container exists").to_string();
        assert!(full.contains("'youki create api'"), "{full}");
        assert!(full.contains("exit 1"), "{full}");
        assert!(full.contains("container exists"), "{full}");

        let no_status = build(None, "aborted").to_string();
        assert!(!no_status.contains("exit"), "{no_status}");
        assert!(no_status.contains("aborted"), "{no_status}");

        for stderr in ["", "   ", "\n\t "] {
            let quiet = build(Some(137), stderr).to_string();
            assert!(quiet.contains("exit 137"), "{quiet}");
            assert!(
                !quiet.ends_with(':') && !quiet.trim_end().ends_with(':'),
                "an empty stderr appends a colon: {quiet:?}"
            );
        }

        // stderr is trimmed, not appended raw.
        let padded = build(Some(1), "  an error  \n").to_string();
        assert!(padded.ends_with("an error"), "{padded:?}");
    }

    #[test]
    fn only_the_wrapping_variants_carry_a_source() {
        let with_source: Vec<RuntimeError> = vec![
            RuntimeError::io(
                "reading",
                std::path::Path::new("/tmp/x"),
                std::io::Error::from(std::io::ErrorKind::NotFound),
            ),
            RuntimeError::decompress(
                "zstd",
                std::io::Error::from(std::io::ErrorKind::InvalidData),
            ),
            RuntimeError::Mount(tg_syscall::mount::MountError::NoLowerDirs),
        ];
        for error in with_source {
            assert!(error.source().is_some(), "{error}");
        }

        let without_source: Vec<RuntimeError> = vec![
            RuntimeError::DigestMismatch {
                expected: "a".to_owned(),
                actual: "b".to_owned(),
            },
            RuntimeError::UnknownMediaType {
                media_type: "x".to_owned(),
            },
            RuntimeError::Pull {
                reference: "a".to_owned(),
                detail: "b".to_owned(),
            },
            RuntimeError::Runtime {
                runtime: "youki".to_owned(),
                command: "state".to_owned(),
                status: Some(1),
                stderr: String::new(),
            },
            RuntimeError::RuntimeMissing { candidates: vec![] },
            RuntimeError::Unmappable {
                workload: "api".to_owned(),
                reason: "x".to_owned(),
            },
        ];
        for error in without_source {
            assert!(error.source().is_none(), "{error}");
        }
    }

    #[test]
    fn a_mount_error_is_wrapped_not_stringified() {
        let error: RuntimeError = tg_syscall::mount::MountError::UnsupportedPath {
            path: std::path::PathBuf::from("/var/lib/a:b"),
            reason: "contains ':'",
        }
        .into();

        assert!(matches!(error, RuntimeError::Mount(_)));
        assert!(error.to_string().contains("/var/lib/a:b"), "{error}");
        assert!(error.source().is_some());
    }

    #[test]
    fn a_missing_runtime_without_candidates_stays_readable() {
        let text = RuntimeError::RuntimeMissing { candidates: vec![] }.to_string();

        assert!(text.contains("no OCI runtime was found"), "{text}");
    }
}
