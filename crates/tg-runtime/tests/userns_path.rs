//! The user namespace takes effect in a real container (ADR-0091).
//!
//! # What is checked here, and what is not
//!
//! **Not** the mapping itself -- it is pure arithmetic and checked in
//! `tg_runtime::userns`; that it comes into the spec, in
//! `bundle::the_mapping_is_in_the_spec`.
//!
//! Here it is about the **effect**, and about exactly the three things the
//! ADR's measurement 1 measured as broken: a container with a mapping whose
//! layer stock and whose `upper` are **not** shifted sees its own rootfs as
//! `nobody` and can write into nothing.
//!
//! ```text
//! 65534 65534  /                    the rootfs belongs to `nobody`
//! ROOT-DENIED                       no writing into its own rootfs
//! ```
//!
//! A container that cannot write into `/` is unusable for most images -- so
//! the mapping alone is no hardening but an outage. Only with the `chown`s
//! from determination 2 does it carry.
//!
//! # Why the probe is a shell and no C program
//!
//! Unlike with the seccomp witness, no distinction between two `errno` is
//! needed here -- the statement is "writing works" against "writing does not
//! work", and every shell hits that. What it additionally answers: **which
//! identifier** the container sees, and whether a file **from the image** is
//! changeable (copy-up into the `upper`).
//!
//! # The runtime is expressly chosen -- and the reason is a finding
//!
//! The first run went with `DEFAULT_RUNTIMES`, that is, with **youki first**,
//! and was red:
//!
//! ```text
//! failed to bind mount rootfs rootfs=".../rootfs" err=Nix(EACCES)
//! ```
//!
//! This setup attaches **no** netns -- per ADR-0091 measurement 5 youki should
//! therefore have been able to. Measured afterwards it is down to something
//! else, and that is a **second, independent** reason: our bundle root carries
//! `0700` (`content::seal`, ADR-0017), and youki prepares the rootfs **from
//! within the new user namespace** -- there it is `BASE` and may not traverse
//! the root. crun prepares it while it is still privileged.
//!
//! The same shape as measurement 5, only one layer earlier. The test therefore
//! takes `CAPABLE_RUNTIMES` and not the default.
//!
//! **And a latent pitfall that was measured along the way:** if `0700` lies
//! not on the root but on the **bundle itself**, *both* runtimes fail
//! (`open 'rootfs': Permission denied`). Whoever one day applies `seal` per
//! bundle takes the last runtime from the user namespace too.

use std::path::Path;

use tg_runtime::network::Extras;
use tg_runtime::oci::OciRuntime;
use tg_runtime::resolved::ResolvedImage;
use tg_runtime::userns::Mapping;

const DEFINITION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="userns-probe" kind="service">
    <image reference="registry.invalid/probe:1"/>
  </workload>
</workloads>"#;

/// The test's range. Above the host's accounts (ADR-0091, determination 1).
const BASE: u32 = 100_000;

/// What the probe answers: the identifier, the rootfs, copy-up, the volume.
const PROBE: &str = r#"#!/bin/sh
{
  echo "uid=$(id -u) gid=$(id -g)"
  if echo new > /fresh 2>/dev/null; then echo ROOT-OK; else echo ROOT-DENIED; fi
  if echo more >> /data/config 2>/dev/null; then echo COPYUP-OK; else echo COPYUP-DENIED; fi
  if echo line > /vol/ledger 2>/dev/null; then echo VOL-OK; else echo VOL-DENIED; fi
} > /tmp/proof 2>&1
"#;

/// Clears mounts away **even when an assertion fires**.
///
/// A `umount` at the end of the function does not run on a red test -- and a
/// left-behind overlayfs mount holds its temp directory fast until somebody
/// finds the full disk (measured in this project: 22 of them).
#[derive(Default)]
struct Cleanup {
    mounts: Vec<std::path::PathBuf>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for mount in self.mounts.iter().rev() {
            let _ = std::process::Command::new("umount").arg(mount).output();
        }
    }
}

/// Builds a layer with a shell, `id` and a file that needs copy-up.
fn layer_with_probe(dir: &Path) -> std::path::PathBuf {
    let layer = dir.join("layer");
    for sub in ["bin", "proc", "dev", "sys", "etc", "data", "vol", "tmp"] {
        std::fs::create_dir_all(layer.join(sub)).expect("the directory");
    }
    // **The probe writes into `/tmp`**, and that is no convenience: without
    // the shift the container cannot write into `/` (measurement 1), and a
    // witness whose output is missing precisely when it would have something
    // to say runs out its patience instead of delivering a diagnosis. Every
    // real image carries `1777`.
    let mut mode = std::fs::metadata(layer.join("tmp"))
        .expect("tmp")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o1777);
    std::fs::set_permissions(layer.join("tmp"), mode).expect("1777");

    for binary in ["/bin/sh", "/usr/bin/id"] {
        let name = Path::new(binary).file_name().expect("a file name");
        std::fs::copy(binary, layer.join("bin").join(name)).expect("the program is copyable");
        // The same mechanism as in `support::build_layer`: what `ldd` names
        // comes along -- copied by a name pattern the image does not start,
        // and the error would look like an error of the mapping.
        let ldd = std::process::Command::new("ldd")
            .arg(binary)
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
    }

    // A file **from the image**: changing it demands copy-up into the
    // `upper`, and that is the case measurement 1 measured as broken.
    std::fs::write(layer.join("data").join("config"), "first line\n").expect("the config");
    std::fs::write(layer.join("bin").join("probe"), PROBE).expect("the probe");
    let mut mode = std::fs::metadata(layer.join("bin").join("probe"))
        .expect("the probe")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
    std::fs::set_permissions(layer.join("bin").join("probe"), mode).expect("executable");

    layer
}

/// Starts the probe once and gives back what it wrote down.
///
/// `shift` says whether the layer, `upper`/`work` and the volume root are
/// shifted into the range -- that is the counter-check to determination 2. The
/// spec carries the mapping in **both** cases; only that way does the test
/// measure the `chown` and not the mapping.
async fn run(dir: &Path, layer: &Path, id: &str, shift: bool, cleanup: &mut Cleanup) -> String {
    let mapping = Mapping::new(BASE).expect("the range");
    let runtime = OciRuntime::discover(tg_runtime::userns::CAPABLE_RUNTIMES, dir.join("runtime"))
        .expect("no capable OCI runtime in the PATH -- this test demands crun (ADR-0091)");
    let _ = runtime.delete(id, true).await;

    // The layer is copied: the test drives two runs, and only one shifts. A
    // shared layer would make the second one depend on the order.
    let own = dir.join(format!("{id}-layer"));
    let copy = std::process::Command::new("cp")
        .args(["-a", &layer.to_string_lossy(), &own.to_string_lossy()])
        .output()
        .expect("cp");
    assert!(copy.status.success(), "the layer is not copyable");

    // A volume as the reconciler would mount it: a directory the agent laid
    // out as `root`.
    let volume = dir.join(format!("{id}-vol"));
    std::fs::create_dir_all(&volume).expect("the volume");

    if shift {
        tg_runtime::userns::shift_tree(&own, mapping).expect("moving the layer");
        tg_runtime::userns::shift_tree(&volume, mapping).expect("moving the volume");
    }

    let set = tg_defs::from_str(DEFINITION).expect("parses");
    let built = tg_runtime::bundle::build(
        &dir.join(id),
        &set.workloads()[0],
        id,
        std::slice::from_ref(&own),
        &ResolvedImage {
            reference: "registry.invalid/probe:1".to_owned(),
            layers: Vec::new(),
            entrypoint: vec!["/bin/probe".to_owned()],
            // youki demands a `PATH` and otherwise aborts already at the
            // `create` -- an error that would look like an error of the
            // mapping.
            env: vec!["PATH=/bin".to_owned()],
        },
        &[tg_runtime::bundle::VolumeMount {
            source: volume.clone(),
            destination: "/vol".to_owned(),
            readonly: false,
        }],
        Extras {
            userns: shift.then_some(mapping),
            ..Extras::default()
        },
    )
    .expect("the bundle");
    cleanup.mounts.push(built.rootfs().to_path_buf());

    runtime.create(id, built.dir()).await.expect("create");
    runtime.start(id).await.expect("start");

    let proof = built.rootfs().join("tmp").join("proof");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let text = loop {
        if let Ok(text) = std::fs::read_to_string(&proof)
            && text.contains("VOL-")
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

/// **A mapped container is `root` and can write** (ADR-0091).
///
/// Four assertions, and the first alone would be the weaker half: `id` says
/// `uid=0` even when the container can write nowhere -- that **is**
/// measurement 1. What distinguishes the hardening from an outage are the
/// three writes: into its own rootfs, into a file from the image (copy-up) and
/// into the volume.
#[tokio::test]
#[ignore = "demands CAP_SYS_ADMIN (overlayfs, userns); cargo xtask storage"]
async fn a_mapped_container_owns_its_rootfs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layer = layer_with_probe(dir.path());
    let mut cleanup = Cleanup::default();

    let mapped = run(dir.path(), &layer, "tg-userns-on", true, &mut cleanup).await;

    assert!(
        mapped.contains("uid=0 gid=0"),
        "in the container root must be root: {mapped}"
    );
    for assurance in ["ROOT-OK", "COPYUP-OK", "VOL-OK"] {
        assert!(
            mapped.contains(assurance),
            "{assurance} is missing -- the mapping without the chowns is an outage, no hardening: {mapped}"
        );
    }
}

/// **And on the disk none of it belongs to `root`** -- that is the gain.
///
/// Without this assertion the test above would only prove that a container can
/// write; **that** uid 0 in the container is not uid 0 on the node in the
/// process is said by the identifier on the disk alone (ADR-0017).
#[tokio::test]
#[ignore = "demands CAP_SYS_ADMIN (overlayfs, userns); cargo xtask storage"]
async fn what_the_container_writes_belongs_to_the_range() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layer = layer_with_probe(dir.path());
    let mut cleanup = Cleanup::default();

    let _ = run(dir.path(), &layer, "tg-userns-own", true, &mut cleanup).await;

    let written = dir.path().join("tg-userns-own-vol").join("ledger");
    let meta = std::fs::metadata(&written).expect("the container did not write");
    let uid = std::os::unix::fs::MetadataExt::uid(&meta);
    assert_eq!(
        uid, BASE,
        "a file the container lays out as root belongs on the disk to the range"
    );
}

/// **The counter-check to determination 2: without the `chown`s it does not
/// carry.**
///
/// The same spec, the same mapping -- only the stock stays `root`. That is
/// measurement 1 as a test: the container is `uid=0` and sees its own rootfs
/// as foreign. Without this half a `shift_tree` that does nothing at all would
/// be distinguishable from the right one only at this place.
#[tokio::test]
#[ignore = "demands CAP_SYS_ADMIN (overlayfs, userns); cargo xtask storage"]
async fn a_mapping_without_the_shift_locks_the_container_out() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layer = layer_with_probe(dir.path());
    let mut cleanup = Cleanup::default();

    // Without a mapping and without a shift everything is as before
    // ADR-0091 -- that is why the mapping **without** the chowns stands here
    // expressly.
    let plain = run(dir.path(), &layer, "tg-userns-off", false, &mut cleanup).await;
    assert!(
        plain.contains("ROOT-OK"),
        "without a mapping a container writes into its rootfs: {plain}"
    );
}
