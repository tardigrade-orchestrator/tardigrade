//! A bundle belongs to one instance.
//!
//! Written **before** the implementation.
//!
//! # The measured finding
//!
//! `bundle::build` lays out under `<bundles>/<workload-name>` -- the same
//! place for **every** instance. Measured:
//!
//! ```text
//! instance 0: id=tg-api    dir=<bundles>/api
//! instance 1: id=tg-api-1  dir=<bundles>/api
//! same directory: true
//! instance-1 sees instance-0's file: true
//! ```
//!
//! The `upper` in it **is** the ephemeral volume, and the rule for writable
//! storage is that it must stay exclusive to one instance. Two instances
//! shared it, quietly.
//!
//! # Why that was nevertheless no open attack path
//!
//! No built path today produces two instances of a workload on one node: the
//! anti-affinity filters by **domain**, and a node lies in exactly one;
//! `tgctl apply` expressly takes instance 0. The property thereby rested on
//! three assumptions, none of which was assured -- and this project has
//! measured such assumptions to be false before.
//!
//! No rule is therefore invented here but one applied: the attempt is
//! **refused, not serialized**.

use std::path::Path;

use tg_runtime::network::Extras;
use tg_runtime::resolved::ResolvedImage;

const DEFINITION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.invalid/api:1"/>
  </workload>
</workloads>"#;

/// Creates a minimal OCI layer directory tree (the standard Linux
/// directories) under `dir`.
///
/// # Parameters
/// - `dir`: the temporary directory under which the layer is built.
///
/// # Returns
/// The path to the created layer directory.
fn layer(dir: &Path) -> std::path::PathBuf {
    let layer = dir.join("layer");
    for sub in ["bin", "proc", "dev", "sys", "etc"] {
        std::fs::create_dir_all(layer.join(sub)).expect("the directory");
    }
    layer
}

/// Builds a bundle for the `api` workload's given instance number, using a
/// single-layer image rooted at `layer`.
///
/// # Parameters
/// - `bundles`: the bundles directory under which the bundle is laid out.
/// - `layer`: the layer directory to use as the image's sole layer.
/// - `instance`: the instance number to build the bundle for.
///
/// # Returns
/// The built [`tg_runtime::bundle::Bundle`].
///
/// # Errors
/// Returns an error if building the bundle fails, in particular when another
/// instance already owns the same bundle directory.
fn build(
    bundles: &Path,
    layer: &Path,
    instance: u32,
) -> Result<tg_runtime::bundle::Bundle, tg_runtime::RuntimeError> {
    let set = tg_defs::from_str(DEFINITION).expect("parses");
    let id = tg_runtime::bundle::container_id("api", instance);

    tg_runtime::bundle::build(
        bundles,
        &set.workloads()[0],
        &id,
        std::slice::from_ref(&layer.to_path_buf()),
        &ResolvedImage {
            reference: "registry.invalid/api:1".to_owned(),
            layers: Vec::new(),
            entrypoint: vec!["/bin/true".to_owned()],
            env: Vec::new(),
        },
        &[],
        Extras::default(),
    )
}

/// **A second instance does not get the first one's bundle.**
///
/// They would otherwise share the `upper` -- the ephemeral volume, which must
/// stay exclusive to one instance -- and without it standing out anywhere.
#[test]
#[ignore = "demands CAP_SYS_ADMIN (overlayfs); cargo xtask storage"]
fn a_second_instance_is_refused_not_serialised() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bundles = dir.path().join("bundles");
    let layer = layer(dir.path());

    let first = build(&bundles, &layer, 0).expect("the first instance builds its bundle");

    let err = build(&bundles, &layer, 1).expect_err("the second one must not get it");
    let text = err.to_string();

    // **Both identifiers**, for an operator must know who is in the way.
    assert!(
        text.contains("tg-api-1") && text.contains("tg-api"),
        "the message does not name both instances: {text}"
    );

    let _ = std::process::Command::new("umount")
        .arg(first.rootfs())
        .output();
}

/// **The same instance once more is no contradiction** -- that is the restart
/// case, where the same instance rebuilds its own bundle after the agent
/// restarts.
///
/// Without this counter-check a bar that refuses *every* second build would be
/// green too -- and the agent would never come up again after a restart.
#[test]
#[ignore = "demands CAP_SYS_ADMIN (overlayfs); cargo xtask storage"]
fn the_same_instance_may_build_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bundles = dir.path().join("bundles");
    let layer = layer(dir.path());

    let first = build(&bundles, &layer, 0).expect("the first time");
    // What lies in the ephemeral volume survives the rebuild: a restart must
    // not lose it.
    std::fs::write(first.dir().join("upper").join("witness"), "x").expect("write");

    let again = build(&bundles, &layer, 0).expect("the same container may again");

    assert_eq!(again.dir(), first.dir());
    assert!(
        again.dir().join("upper").join("witness").exists(),
        "the ephemeral volume did not survive the rebuild"
    );

    let _ = std::process::Command::new("umount")
        .arg(again.rootfs())
        .output();
}
