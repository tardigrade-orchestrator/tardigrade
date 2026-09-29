//! What this crate's privileged container tests share.
//!
//! **Why shared and not copied per file.** `Fixture`, its `Drop` and
//! `build_layer` existed **four times**, and the struct as well as the
//! producer were byte for byte the same. Only the `Drop` was not: it called
//! `crun` hard-written, while `DEFAULT_RUNTIMES` names **youki first** -- and
//! when that was fixed, the fix travelled into **one** of the four copies.
//!
//! What that costs is measured to be **smaller than it looks**: the reconciler
//! ends the container in these tests itself, so at the `Drop` there is nothing
//! left to delete and the `umount` succeeds with the wrong runtime too. A leak
//! arises only when the container is still **alive** at the `Drop` -- and then
//! the wrong name does not help.
//!
//! The reason is therefore not a proven leak but the number: four
//! opportunities to make a cleanup discipline differently strict are three too
//! many.

// **Recompiled per test target.** In integration tests `mod support` is no
// shared crate but a source every target compiles for itself -- and none needs
// all of it. "Unused here" is thereby the normal case of cargo's test model
// and no negligence; without this line every new inclusion pays with warnings
// in all the other targets.
#![allow(dead_code)]

use std::path::Path;

use tg_runtime::oci::{DEFAULT_RUNTIMES, OciRuntime};

/// Clears the container away even when the test fails.
pub(crate) struct Fixture {
    pub(crate) id: String,
    pub(crate) root: std::path::PathBuf,
    pub(crate) rootfs: Option<std::path::PathBuf>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(runtime) = OciRuntime::discover(DEFAULT_RUNTIMES, &self.root) {
            let _ = std::process::Command::new(runtime.name())
                .args([
                    "--root",
                    &self.root.to_string_lossy(),
                    "delete",
                    "--force",
                    &self.id,
                ])
                .output();
        }
        if let Some(rootfs) = &self.rootfs {
            let _ = std::process::Command::new("umount").arg(rootfs).output();
        }
    }
}

pub(crate) fn build_layer(layer: &Path) {
    std::fs::create_dir_all(layer.join("bin")).expect("bin");
    for dir in ["proc", "dev", "sys", "etc"] {
        std::fs::create_dir_all(layer.join(dir)).expect("the directory");
    }
    for binary in ["/bin/sh", "/bin/sleep"] {
        let name = Path::new(binary).file_name().expect("a file name");
        std::fs::copy(binary, layer.join("bin").join(name)).expect("the program is copyable");
        let ldd = std::process::Command::new("ldd")
            .arg(binary)
            .output()
            .expect("ldd");
        for line in String::from_utf8_lossy(&ldd.stdout).lines() {
            for token in line.split_whitespace() {
                if token.starts_with('/') && token.contains(".so") {
                    let source = Path::new(token);
                    if let (Some(parent), Some(name)) = (source.parent(), source.file_name()) {
                        let target = layer.join(parent.strip_prefix("/").unwrap_or(parent));
                        let _ = std::fs::create_dir_all(&target);
                        let _ = std::fs::copy(source, target.join(name));
                    }
                }
            }
        }
    }
}

/// Waits until a witness file contains a **marker**.
///
/// # Why not on the first content
///
/// This function stood three times in this directory, and all three versions
/// returned as soon as the file contained anything -- but a container writes
/// **line by line**. Measured at its twin in `tg-identity`: a sidecar's first
/// line was the warning "no `--policy` given", and the marker that mattered
/// came later. Under load the test read the first line and failed on an
/// assertion about the second -- a race in the test rig that looks like an
/// error in the code.
///
/// On a timeout what stood there until then comes back: without the
/// intermediate stand nobody knows how far it got.
pub(crate) fn await_line(path: &Path, needle: &str) -> Result<String, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.contains(needle) {
                return Ok(text);
            }
            last = text;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Err(last)
}
