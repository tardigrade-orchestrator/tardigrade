//! The build of what is shipped (ADR-0138).
//!
//! `cargo build --release` produces a runnable binary — and one that **names its
//! build machine**. Measured, the four units together contain 2355 absolute
//! paths of the home directory under which they were built; they are the
//! `file!()` locations of the `panic!` sites **in the dependencies**. Our own
//! crates contribute none of them.
//!
//! Two consequences, and the second is the one ADR-0023 names: a panic from a
//! dependency prints the build machine's home directory into a stream ADR-0020
//! retains; and two build machines with different user accounts yield different
//! binaries. Source path, target directory and clock are measured to be without
//! consequence; **`CARGO_HOME` is not.**
//!
//! **Not `trim-paths`**, which would be cargo's own way and is measured to be
//! barred (`not stabilized in this version of Cargo`), and nightly is excluded
//! by the rule from phase 11c. As soon as `profile.release.trim-paths` is
//! stable, it replaces the `RUSTFLAGS` here and this file loses its reason.
//!
//! **The prefix is computed** because it contains **this** machine's home
//! directory. As a constant in `.cargo/config.toml` it would hit nothing on any
//! other machine and stay without effect — worse than nothing, because it would
//! look like care.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::TaskError;
use crate::sbom::DELIVERED;

/// Where the build machine's home directory is mapped to.
///
/// The same form `rustc` already uses for the standard library
/// (`/rustc/<commit>`) — inventing a second one would mean teaching a reader
/// two.
const REMAPPED: &str = "/cargo";

/// Where the delivery build lies.
///
/// **Not `target/`**: the `RUSTFLAGS` differ from the development build, and two
/// sets of flags on the same directory rebuild each other in turn. That a target
/// directory of its own does not change the product is measured (ADR-0138,
/// run 2).
const TARGET_DIR: &str = "target/release-build";

/// Builds the delivery and checks that it does not name its build machine.
///
/// # Errors
///
/// If `CARGO_HOME` is not determinable, the build fails, a product is not
/// readable — or if a path of this machine stands in it.
pub(crate) fn run(root: &Path) -> Result<(), TaskError> {
    let home = cargo_home()?;
    let target = root.join(TARGET_DIR);

    eprintln!(
        "xtask: delivery build, {} -> {REMAPPED} (ADR-0138)",
        home.display()
    );
    build(root, &home, &target)?;

    let produced = target.join("release");
    for package in DELIVERED {
        let path = produced.join(package);
        let bytes = std::fs::read(&path).map_err(|source| TaskError::Write {
            path: path.clone(),
            source,
        })?;

        check(package, &bytes, &home, root)?;
        println!("{package:<9} {}  {} bytes", digest(&bytes), bytes.len());
    }

    eprintln!(
        "xtask: {} units in {}, without a path of this machine.",
        DELIVERED.len(),
        produced.display()
    );
    Ok(())
}

/// The home directory `cargo` passes to the dependencies.
///
/// Exactly this path stands in the products; another would hit nothing.
fn cargo_home() -> Result<PathBuf, TaskError> {
    remap_source(std::env::var("CARGO_HOME").ok(), std::env::var("HOME").ok())
}

/// The choice as a **pure function**, so that it can have a witness.
///
/// Changing a test's environment is `unsafe` in edition 2024 and thereby
/// excluded per invariant 2 — and a test that reached the choice only over
/// `cargo_home()` would check the machine instead of the rule.
fn remap_source(cargo_home: Option<String>, home: Option<String>) -> Result<PathBuf, TaskError> {
    if let Some(explicit) = cargo_home.filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(explicit));
    }
    home.filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".cargo"))
        .ok_or_else(|| TaskError::Failed {
            step: "neither CARGO_HOME nor HOME set — the remap prefix cannot be \
                   determined (ADR-0138)"
                .to_owned(),
        })
}

/// Runs the build of the four units from ADR-0134.
fn build(root: &Path, home: &Path, target: &Path) -> Result<(), TaskError> {
    let mut command = Command::new("cargo");
    command.args(["build", "--release", "--locked"]);
    for package in DELIVERED {
        command.args(["-p", package]);
    }

    let status = command
        // **Set and not appended**: a `RUSTFLAGS` from the environment would be
        // displaced by `cargo` anyway, and two sources for the same setting
        // would be two opportunities for the flag not to arrive. Whether it
        // arrived is said by the counter-check below.
        .env(
            "RUSTFLAGS",
            format!("--remap-path-prefix={}={REMAPPED}", home.display()),
        )
        .env("CARGO_TARGET_DIR", target)
        .current_dir(root)
        .status()
        .map_err(|source| TaskError::Spawn {
            program: "cargo build --release".to_owned(),
            source,
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(TaskError::Failed {
            step: "cargo build --release".to_owned(),
        })
    }
}

/// The counter-check: does a path of this machine stand in the product?
///
/// Without it the flag would be a **claim**. A switch that silently stops
/// arriving is the kind of error this tree has measured several times.
fn check(package: &str, bytes: &[u8], home: &Path, root: &Path) -> Result<(), TaskError> {
    for (what, path) in [("CARGO_HOME", home), ("workspace", root)] {
        let needle = path.as_os_str().as_encoded_bytes();
        let found = bytes
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count();
        if found > 0 {
            return Err(TaskError::Failed {
                step: format!(
                    "{package} names the {what} path {} {found}x — the remap did \
                     not arrive (ADR-0138)",
                    path.display()
                ),
            });
        }
    }
    Ok(())
}

/// The digest a second run has to reproduce.
fn digest(bytes: &[u8]) -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut hex = String::with_capacity(hash.as_ref().len() * 2);
    for byte in hash.as_ref() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{REMAPPED, check, digest, remap_source};

    /// **A planted path is found.**
    ///
    /// The counter-check to the counter-check: a check that never finds anything
    /// confirms every claim — the same finding as with the BPF counter in 9b and
    /// the empty fuzz run in 9c.
    #[test]
    fn the_check_finds_the_path_of_this_machine() {
        let home = Path::new("/root/.cargo");
        let root = Path::new("/root/tardigrade");
        let bytes = b"xx/root/.cargo/registry/src/openraft-0.9.25/src/config.rs\0".to_vec();

        let err = check("tgd", &bytes, home, root).expect_err("the path stands in it");
        let message = format!("{err}");
        assert!(
            message.contains("/root/.cargo") && message.contains("tgd"),
            "{message}"
        );
    }

    /// **And the workspace root likewise.**
    ///
    /// It contributes nothing today — our own crates are compiled relatively. It
    /// is checked nevertheless: that is a property of `cargo`, not a promise of
    /// ours.
    #[test]
    fn the_check_finds_the_workspace_root() {
        let bytes = b"xx/root/tardigrade/crates/tgd/src/main.rsxx".to_vec();
        let err = check(
            "tgd",
            &bytes,
            Path::new("/root/.cargo"),
            Path::new("/root/tardigrade"),
        )
        .expect_err("the root stands in it");
        assert!(format!("{err}").contains("workspace"), "{err}");
    }

    /// **A remapped product passes.**
    #[test]
    fn a_remapped_binary_passes() {
        let bytes =
            format!("xx{REMAPPED}/registry/src/openraft-0.9.25/src/config.rs\0").into_bytes();
        check(
            "tgd",
            &bytes,
            Path::new("/root/.cargo"),
            Path::new("/root/tardigrade"),
        )
        .expect("no path of this machine");
    }

    /// **`CARGO_HOME` beats `HOME`** — it is the path `cargo` really passes.
    #[test]
    fn the_explicit_cargo_home_wins() {
        let chosen = remap_source(Some("/anderswo/cargo".to_owned()), Some("/root".to_owned()))
            .expect("prefix");
        assert_eq!(chosen, PathBuf::from("/anderswo/cargo"));
    }

    /// **Without `CARGO_HOME` the default under `HOME`.**
    #[test]
    fn without_cargo_home_the_default_under_home() {
        let chosen = remap_source(None, Some("/home/betreiber".to_owned())).expect("prefix");
        assert_eq!(chosen, PathBuf::from("/home/betreiber/.cargo"));
    }

    /// **Without either the run stops, it does not guess.**
    ///
    /// A guessed prefix hits nothing, and the build would look successful. An
    /// empty setting counts as none: `CARGO_HOME=` would otherwise yield the
    /// prefix `/`, and that hits **everything**.
    #[test]
    fn without_either_the_run_stops() {
        remap_source(None, None).expect_err("no prefix determinable");
        remap_source(Some(String::new()), None).expect_err("empty is no setting");
    }

    /// **The digest is SHA-256**, on a pinned vector.
    ///
    /// A number a second machine is meant to recompute has to mean the same
    /// procedure.
    #[test]
    fn the_digest_is_sha256() {
        assert_eq!(
            digest(b"tardigrade"),
            "f52ccfb92d96d002c8f933eee1fd80968a1b06271ab1a7a414ea563b2e8e1042"
        );
    }
}
