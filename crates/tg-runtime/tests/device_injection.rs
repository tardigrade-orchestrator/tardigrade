//! **A device reaches the `config.json`** (ADR-0143, builds ADR-0028).
//!
//! The witness ADR-0028 would have needed since 2026: the seam was defined and
//! never injected anything. Here stands what arrives -- and, more importantly,
//! what does **not**: a cgroup device rule. The controller for it is eBPF and
//! out per invariant 1 (ADR-0090), and `reject_unenforceable` aborts if a spec
//! carries them.

use std::path::PathBuf;

use tg_runtime::bundle::spec_for;
use tg_runtime::cdi::Catalogue;
use tg_runtime::network::Extras;

/// A workload that declares a device.
const WITH_DEVICE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="inference" kind="service">
    <image reference="registry.test/inference:1"/>
    <command><arg>/bin/sh</arg></command>
    <devices>
      <device kind="example.com/probe" count="1"/>
    </devices>
  </workload>
</workloads>"#;

/// A spec with a node, a mount and an environment -- everything that takes
/// effect here.
fn catalogue() -> (tempfile::TempDir, Catalogue) {
    let dir = tempfile::tempdir().expect("the directory");
    std::fs::write(
        dir.path().join("probe.json"),
        r#"{
          "cdiVersion": "0.6.0",
          "kind": "example.com/probe",
          "containerEdits": {
            "env": [ "PROBE_LIB=/opt/probe" ],
            "mounts": [ { "hostPath": "/etc", "containerPath": "/opt/probe",
                          "options": ["ro"] } ]
          },
          "devices": [
            { "name": "0", "containerEdits": {
                "deviceNodes": [ { "path": "/dev/null", "type": "c",
                                   "major": 1, "minor": 3,
                                   "permissions": "rw" } ] } }
          ]
        }"#,
    )
    .expect("write");
    let (catalogue, findings) = Catalogue::read(&[dir.path().to_path_buf()]);
    assert!(findings.is_empty(), "{findings:?}");
    (dir, catalogue)
}

/// **The node, the mount and the environment arrive -- the cgroup rule does
/// not.**
#[test]
fn a_device_reaches_the_spec_without_a_cgroup_rule() {
    let (_dir, catalogue) = catalogue();
    let device = catalogue.get("example.com/probe=0").expect("the device");

    let set = tg_defs::from_str(WITH_DEVICE).expect("the definition");
    let spec = spec_for(
        &set.workloads()[0],
        "tg-inference-0",
        &["/bin/sh".into()],
        &["PATH=/usr/bin".to_owned()],
        &[],
        Extras {
            devices: Some(&device.edits),
            ..Extras::default()
        },
    )
    .expect("the spec");

    let linux = spec.linux().as_ref().expect("the linux section");

    let devices = linux.devices().clone().expect("linux.devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].path(), &PathBuf::from("/dev/null"));
    assert_eq!(
        devices[0].file_mode(),
        Some(0o666),
        "`permissions: rw` must become the file mode (determination 2)"
    );

    // **This witness's security statement.** A conforming CDI injection
    // would produce `linux.resources.devices` here; this tree cannot enforce
    // them and therefore does not produce them. That the spec could be built
    // nevertheless is the evidence: `reject_unenforceable` would otherwise
    // have refused it.
    assert!(
        linux
            .resources()
            .as_ref()
            .and_then(|resources| resources.devices().as_ref())
            .is_none_or(Vec::is_empty),
        "a cgroup device rule would be quietly without effect (ADR-0090, ADR-0143 D2)"
    );

    let env = spec
        .process()
        .as_ref()
        .and_then(|process| process.env().clone())
        .expect("the environment");
    assert!(
        env.contains(&"PROBE_LIB=/opt/probe".to_owned()),
        "the device's environment is missing: {env:?}"
    );
    assert!(
        env.iter().position(|v| v == "PATH=/usr/bin")
            < env.iter().position(|v| v == "PROBE_LIB=/opt/probe"),
        "the device's environment belongs after the image's"
    );

    let mounts = spec.mounts().clone().expect("the mounts");
    let probe = mounts
        .iter()
        .find(|mount| mount.destination() == &PathBuf::from("/opt/probe"))
        .expect("the device's mount");
    let options = probe.options().clone().expect("the options");
    assert!(options.contains(&"bind".to_owned()) && options.contains(&"ro".to_owned()));

    // **The standard mounts survive** -- the finding from 10c, once more
    // here: a container without /proc does not stand out at startup.
    assert!(
        mounts
            .iter()
            .any(|mount| mount.destination() == &PathBuf::from("/proc")),
        "the OCI standard mounts were replaced instead of supplemented"
    );
}

/// **Without a device nothing changes** -- the counter-check.
///
/// Without it the witness above would only prove that something is
/// different.
#[test]
fn a_workload_without_a_device_gets_no_device_section() {
    let set = tg_defs::from_str(WITH_DEVICE).expect("the definition");
    let spec = spec_for(
        &set.workloads()[0],
        "tg-inference-0",
        &["/bin/sh".into()],
        &[],
        &[],
        Extras::default(),
    )
    .expect("the spec");

    assert!(
        spec.linux()
            .as_ref()
            .and_then(|linux| linux.devices().as_ref())
            .is_none(),
        "without an assigned device no node belongs in the spec"
    );
}
