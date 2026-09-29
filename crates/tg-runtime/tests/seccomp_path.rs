//! The seccomp profile takes effect in a real container (ADR-0090).
//!
//! # Why this witness is necessary
//!
//! This project has found the opposite case: the device cgroup from ADR-0028
//! is **quietly ignored** by the runtime, because its v2 controller is
//! eBPF-based. A profile that stands in the spec and nobody enforces would be
//! the same sort of assurance -- and it would never stand out.
//!
//! # What is checked here, and what is not
//!
//! **Not** the list: which names stand on it is pure logic and checked in
//! `tg_runtime::seccomp`; that it comes into the spec, in
//! `bundle::the_profile_is_in_the_spec`.
//!
//! Here it is about the **effect**: that the runtime this node found applies
//! `linux.seccomp` -- and that the bar hits the call and not merely a missing
//! capability.
//!
//! # The probe is `bpf(2)` with an invalid command
//!
//! Every name on the denylist demands a capability a container does not have
//! anyway -- exactly that is why the list is safe. An ordinary program can
//! thereby not distinguish "barred by seccomp" from "no capability": both
//! yield `EPERM`.
//!
//! `bpf(-1, NULL, 0)` distinguishes it: the kernel checks the **command
//! first** and answers `EINVAL`; a seccomp filter answers `EPERM` before the
//! kernel checks anything. The test is thereby **self-discriminating** -- `22`
//! against `1` -- and at the same time substantiates invariant 1 where up to
//! here it was only counted (phase 9b).

use std::path::Path;

use tg_runtime::network::Extras;
use tg_runtime::oci::{DEFAULT_RUNTIMES, OciRuntime};
use tg_runtime::resolved::ResolvedImage;

const DEFINITION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="seccomp-probe" kind="service">
    <image reference="registry.invalid/probe:1"/>
  </workload>
</workloads>"#;

/// The probe: a `bpf(2)` with an invalid command, and the `errno` with it.
const PROBE: &str = r#"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(void) {
    long result = syscall(SYS_bpf, -1, NULL, 0);
    FILE *out = fopen("/proof", "w");
    if (!out) { return 2; }
    fprintf(out, "bpf=%ld errno=%d\n", result, errno);
    fclose(out);
    return 0;
}
"#;

/// Builds a layer with `/bin/probe` and the libraries it needs.
fn layer_with_probe(dir: &Path) -> std::path::PathBuf {
    let layer = dir.join("layer");
    for sub in ["bin", "proc", "dev", "sys", "etc"] {
        std::fs::create_dir_all(layer.join(sub)).expect("the directory");
    }

    let source = dir.join("probe.c");
    std::fs::write(&source, PROBE).expect("the source is writable");
    let binary = layer.join("bin").join("probe");
    let built = std::process::Command::new("cc")
        .arg("-O0")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("cc in the PATH -- an operational prerequisite of this test");
    assert!(
        built.status.success(),
        "the probe could not be compiled: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    // The same mechanism as in `support::build_layer`: what `ldd` names
    // comes along. An image without its libraries does not start, and the
    // error would look like an error of the profile.
    let ldd = std::process::Command::new("ldd")
        .arg(&binary)
        .output()
        .expect("ldd");
    for token in String::from_utf8_lossy(&ldd.stdout).split_whitespace() {
        if token.starts_with('/') && token.contains(".so") {
            let source = Path::new(token);
            if let (Some(parent), Some(name)) = (source.parent(), source.file_name()) {
                let target = layer.join(parent.strip_prefix("/").unwrap_or(parent));
                let _ = std::fs::create_dir_all(&target);
                let _ = std::fs::copy(source, target.join(name));
            }
        }
    }

    layer
}

/// Clears mounts away **even when an assertion fires**.
///
/// A `umount` at the end of the function does not run on a red test -- and a
/// left-behind overlayfs mount holds its temp directory fast until somebody
/// finds the full disk. This project has measured that: 22 mounts from aborted
/// runs, around 400 MiB each.
#[derive(Default)]
struct Cleanup {
    mounts: Vec<std::path::PathBuf>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for mount in &self.mounts {
            let _ = std::process::Command::new("umount").arg(mount).output();
        }
    }
}

/// Starts the probe once and gives back what it wrote down.
async fn run(
    dir: &Path,
    layer: &Path,
    id: &str,
    extras: Extras<'_>,
    cleanup: &mut Cleanup,
) -> String {
    let runtime = OciRuntime::discover(DEFAULT_RUNTIMES, dir.join("runtime"))
        .expect("no OCI runtime in the PATH -- this test demands youki or crun");
    let _ = runtime.delete(id, true).await;

    let set = tg_defs::from_str(DEFINITION).expect("parses");
    let built = tg_runtime::bundle::build(
        &dir.join(id),
        &set.workloads()[0],
        id,
        std::slice::from_ref(&layer.to_path_buf()),
        &ResolvedImage {
            reference: "registry.invalid/probe:1".to_owned(),
            layers: Vec::new(),
            entrypoint: vec!["/bin/probe".to_owned()],
            // youki demands a `PATH` in the environment and otherwise
            // aborts already at the `create` -- an error that would look like
            // an error of the profile.
            env: vec!["PATH=/bin".to_owned()],
        },
        &[],
        extras,
    )
    .expect("the bundle");
    cleanup.mounts.push(built.rootfs().to_path_buf());

    runtime.create(id, built.dir()).await.expect("create");
    runtime.start(id).await.expect("start");

    let proof = built.rootfs().join("proof");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let text = loop {
        if let Ok(text) = std::fs::read_to_string(&proof)
            && !text.is_empty()
        {
            break text;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the probe wrote nothing down"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };

    let _ = runtime.delete(id, true).await;
    text
}

/// **A container can no longer call `bpf(2)`** (ADR-0090, invariant 1).
///
/// Both directions in one run, and the difference **is** the statement: with
/// the profile the filter answers `EPERM` (1), without the profile the kernel
/// answers `EINVAL` (22) to the invalid command. A test that checked only the
/// first half would be green even if `bpf` failed for a quite different
/// reason.
#[tokio::test]
#[ignore = "demands CAP_SYS_ADMIN (overlayfs) and cc; cargo xtask storage"]
async fn no_container_may_call_bpf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layer = layer_with_probe(dir.path());

    let mut cleanup = Cleanup::default();

    let denied = run(
        dir.path(),
        &layer,
        "tg-seccomp-on",
        Extras::default(),
        &mut cleanup,
    )
    .await;
    assert!(
        denied.contains("errno=1"),
        "with the profile the filter must give EPERM: {denied}"
    );

    // **The counter-direction** (ADR-0090, determination 5): without the
    // profile the kernel answers the same invalid command with EINVAL. It
    // substantiates two things -- that the way out takes effect, and that the
    // 1 above really came from the filter.
    let allowed = run(
        dir.path(),
        &layer,
        "tg-seccomp-off",
        Extras {
            no_seccomp: true,
            ..Extras::default()
        },
        &mut cleanup,
    )
    .await;
    assert!(
        allowed.contains("errno=22"),
        "without the profile the kernel must give EINVAL: {allowed}"
    );
}
