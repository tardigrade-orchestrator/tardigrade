//! The CDI reading at real files.
//!
//! # Why the refusals come first
//!
//! A CDI spec determines which device nodes a container gets, and it is read
//! as root. The normal case is one line; the cases that count are those in
//! which the file demands something this tree **cannot** enforce -- and those
//! must not slip through.
//!
//! # The device nodes are real
//!
//! It is built against `/dev/null` (1:3) and `/dev/zero` (1:5) -- they exist
//! on every Linux, and the check "does the host node exist?" is thereby a real
//! check instead of one that always agrees. This machine does not have a GPU
//! to test against.

use std::path::PathBuf;

use tg_runtime::cdi::{Catalogue, RESOURCE_PREFIX};

/// Writes each named CDI spec file with its body into a fresh temporary
/// directory.
///
/// # Parameters
/// - `files`: pairs of file name and file body to write.
///
/// # Returns
/// The temporary directory containing the written files.
fn dir_with(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("the directory");
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).expect("write");
    }
    dir
}

/// Reads the CDI catalogue from `dir` and collects the reasons of any
/// findings.
///
/// # Parameters
/// - `dir`: the directory containing the CDI spec files to read.
///
/// # Returns
/// A tuple of the resulting [`Catalogue`] and the finding reason strings.
fn read(dir: &tempfile::TempDir) -> (Catalogue, Vec<String>) {
    let (catalogue, findings) = Catalogue::read(&[dir.path().to_path_buf()]);
    (
        catalogue,
        findings.into_iter().map(|f| f.reason).collect::<Vec<_>>(),
    )
}

/// A spec with nothing to object to -- the counter-check to everything
/// below.
const GOOD: &str = r#"{
  "cdiVersion": "0.6.0",
  "kind": "example.com/probe",
  "devices": [
    {
      "name": "0",
      "containerEdits": {
        "deviceNodes": [
          { "path": "/dev/null", "type": "c", "major": 1, "minor": 3 }
        ]
      }
    },
    {
      "name": "1",
      "containerEdits": {
        "deviceNodes": [
          { "path": "/dev/zero", "type": "c", "major": 1, "minor": 5 }
        ]
      }
    }
  ]
}"#;

/// **The normal case**, and it delivers the inventory of device counts by
/// resource kind at the same time.
#[test]
fn two_devices_become_two_of_one_kind() {
    let dir = dir_with(&[("probe.json", GOOD)]);
    let (catalogue, findings) = read(&dir);

    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    assert_eq!(catalogue.len(), 2);
    assert_eq!(
        catalogue.inventory(),
        [(format!("{RESOURCE_PREFIX}example.com/probe"), 2)]
            .into_iter()
            .collect(),
        "the inventory is the resource map from ADR-0049"
    );
    assert_eq!(catalogue.names_of("example.com/probe"), vec!["0", "1"]);

    let device = catalogue
        .get("example.com/probe=0")
        .expect("addressable fully qualified");
    let devices = device.edits.oci_devices().expect("the OCI entry");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].path(), &PathBuf::from("/dev/null"));
    assert_eq!(devices[0].major(), 1);
    assert_eq!(devices[0].minor(), 3);
}

/// **Hooks cost the whole spec, not the hook.**
///
/// A filtered hook would leave the file describing something other than what
/// actually runs, and hooks run arbitrary commands as root that this tree
/// cannot enforce. And because `nvidia-ctk`'s stock spec carries exactly
/// that, the message must name the way -- an operator reads it before
/// cutting the file.
#[test]
fn a_spec_with_a_hook_is_refused_whole() {
    let body = r#"{
      "cdiVersion": "0.6.0",
      "kind": "example.com/probe",
      "devices": [
        {
          "name": "0",
          "containerEdits": {
            "deviceNodes": [ { "path": "/dev/null", "type": "c", "major": 1, "minor": 3 } ],
            "hooks": [
              { "hookName": "createContainer", "path": "/usr/bin/nvidia-ctk",
                "args": ["nvidia-ctk", "hook", "update-ldcache"] }
            ]
          }
        }
      ]
    }"#;
    let dir = dir_with(&[("hook.json", body)]);
    let (catalogue, findings) = read(&dir);

    assert!(
        catalogue.is_empty(),
        "the spec carries a hook and must deliver no device"
    );
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].contains("hook") && findings[0].contains("root"),
        "the message must say what a hook is: {}",
        findings[0]
    );
}

/// **The three other sections likewise get refused whole.**
///
/// One run of its own each, with only **one** thing different -- otherwise a
/// red test would merely prove that something did not work.
#[test]
fn net_devices_intel_rdt_and_additional_gids_are_refused() {
    for (label, extra) in [
        ("netDevices", r#""netDevices": [ { "name": "eth1" } ]"#),
        ("intelRdt", r#""intelRdt": { "closID": "group" }"#),
        ("additionalGids", r#""additionalGids": [ 44 ]"#),
    ] {
        let body = format!(
            r#"{{
              "cdiVersion": "0.6.0",
              "kind": "example.com/probe",
              "devices": [
                {{
                  "name": "0",
                  "containerEdits": {{
                    "deviceNodes": [ {{ "path": "/dev/null", "type": "c", "major": 1, "minor": 3 }} ],
                    {extra}
                  }}
                }}
              ]
            }}"#
        );
        let dir = dir_with(&[("x.json", &body)]);
        let (catalogue, findings) = read(&dir);

        assert!(catalogue.is_empty(), "{label} must cost the spec");
        assert_eq!(findings.len(), 1, "{label}");
        assert!(
            findings[0].contains(label),
            "the message does not name the section: {}",
            findings[0]
        );
    }
}

/// **An unknown field aborts.**
///
/// That is at the same time the generation check: a CDI that adds something
/// does not keep it quiet here.
#[test]
fn an_unknown_field_is_refused() {
    let body = r#"{
      "cdiVersion": "0.6.0",
      "kind": "example.com/probe",
      "devices": [
        { "name": "0", "containerEdits": {
            "deviceNodes": [ { "path": "/dev/null", "type": "c", "major": 1, "minor": 3 } ],
            "somethingNew": true } }
      ]
    }"#;
    let dir = dir_with(&[("new.json", body)]);
    let (catalogue, findings) = read(&dir);

    assert!(catalogue.is_empty());
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].contains("somethingNew"),
        "the message must name the field: {}",
        findings[0]
    );
}

/// **`annotations` get through** -- the one case that lies differently.
///
/// In CDI they do not act on the container at all. Refusing a setting that
/// *cannot* have an effect would be strictness without a statement.
#[test]
fn annotations_are_accepted_and_change_nothing() {
    let body = r#"{
      "cdiVersion": "0.6.0",
      "kind": "example.com/probe",
      "annotations": { "org.example/note": "Rack 4" },
      "devices": [
        { "name": "0",
          "annotations": { "org.example/serial": "X1" },
          "containerEdits": {
            "deviceNodes": [ { "path": "/dev/null", "type": "c", "major": 1, "minor": 3 } ] } }
      ]
    }"#;
    let dir = dir_with(&[("anno.json", body)]);
    let (catalogue, findings) = read(&dir);

    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(catalogue.len(), 1);
}

/// **`permissions` becomes the file mode.**
///
/// And `m` falls away without consequence: it is the cgroup permission to
/// `mknod`, and the capability is missing anyway (guarded in `bundle.rs`).
#[test]
fn permissions_become_the_file_mode() {
    for (permissions, expected) in [("r", 0o444), ("rw", 0o666), ("w", 0o222), ("rwm", 0o666)] {
        let body = format!(
            r#"{{
              "cdiVersion": "0.6.0",
              "kind": "example.com/probe",
              "devices": [
                {{ "name": "0", "containerEdits": {{
                    "deviceNodes": [ {{ "path": "/dev/null", "type": "c",
                                        "major": 1, "minor": 3,
                                        "permissions": "{permissions}" }} ] }} }}
              ]
            }}"#
        );
        let dir = dir_with(&[("p.json", &body)]);
        let (catalogue, findings) = read(&dir);
        assert!(findings.is_empty(), "{permissions}: {findings:?}");

        let device = catalogue.get("example.com/probe=0").expect("the device");
        assert_eq!(
            device.edits.nodes[0].file_mode, expected,
            "`{permissions}` must yield {expected:#o}"
        );
    }
}

/// **If `permissions` and `fileMode` contradict each other, the spec
/// aborts.**
///
/// Silently taking the narrower value would be an isolation nobody wrote down;
/// silently taking the wider one an isolation somebody wrote down and does not
/// get.
#[test]
fn a_contradiction_between_permissions_and_file_mode_is_refused() {
    let body = r#"{
      "cdiVersion": "0.6.0",
      "kind": "example.com/probe",
      "devices": [
        { "name": "0", "containerEdits": {
            "deviceNodes": [ { "path": "/dev/null", "type": "c", "major": 1, "minor": 3,
                               "permissions": "r", "fileMode": 438 } ] } }
      ]
    }"#;
    let dir = dir_with(&[("w.json", body)]);
    let (catalogue, findings) = read(&dir);

    assert!(catalogue.is_empty());
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].contains("0o666") && findings[0].contains("0o444"),
        "the message must name both numbers: {}",
        findings[0]
    );
}

/// **A device node outside `/dev` is refused.**
///
/// Otherwise a spec file would lay a node over a file of the rootfs, and what
/// a program in the container opens would be decided by it.
#[test]
fn a_device_node_outside_dev_is_refused() {
    for path in ["/etc/passwd", "/dev/../etc/passwd", "dev/null"] {
        let body = format!(
            r#"{{
              "cdiVersion": "0.6.0",
              "kind": "example.com/probe",
              "devices": [
                {{ "name": "0", "containerEdits": {{
                    "deviceNodes": [ {{ "path": "{path}", "type": "c",
                                        "major": 1, "minor": 3 }} ] }} }}
              ]
            }}"#
        );
        let dir = dir_with(&[("p.json", &body)]);
        let (catalogue, findings) = read(&dir);
        assert!(catalogue.is_empty(), "{path} got through");
        assert_eq!(findings.len(), 1, "{path}");
    }
}

/// **A host node that does not exist is a finding** and no start error.
///
/// Otherwise the runtime would fail only afterwards -- and for the workload,
/// not for whoever laid the spec down.
#[test]
fn a_missing_host_node_is_a_finding() {
    let body = r#"{
      "cdiVersion": "0.6.0",
      "kind": "example.com/probe",
      "devices": [
        { "name": "0", "containerEdits": {
            "deviceNodes": [ { "path": "/dev/doesnotexist-tardigrade", "type": "c",
                               "major": 1, "minor": 3 } ] } }
      ]
    }"#;
    let dir = dir_with(&[("m.json", body)]);
    let (catalogue, findings) = read(&dir);

    assert!(catalogue.is_empty());
    assert!(
        findings[0].contains("does not exist on this host"),
        "{}",
        findings[0]
    );
}

/// **The `kind` is checked because it travels into consensus** as a
/// resource name, so it must be a valid one.
#[test]
fn a_kind_that_is_no_resource_name_is_refused() {
    for kind in [
        "gpu",              // no `/`
        "nvidia/gpu",       // a vendor without a dot
        "nvidia.com/a/b",   // two slashes
        "nvidia.com/",      // an empty class
        "nvidia.com/gpu u", // a space
    ] {
        let body = format!(
            r#"{{
              "cdiVersion": "0.6.0",
              "kind": "{kind}",
              "devices": [
                {{ "name": "0", "containerEdits": {{
                    "deviceNodes": [ {{ "path": "/dev/null", "type": "c",
                                        "major": 1, "minor": 3 }} ] }} }}
              ]
            }}"#
        );
        let dir = dir_with(&[("k.json", &body)]);
        let (catalogue, findings) = read(&dir);
        assert!(catalogue.is_empty(), "`{kind}` got through");
        assert_eq!(findings.len(), 1, "`{kind}`");
    }
}

/// **The same device from two files is an ambiguity.**
///
/// Which applies would otherwise hang on the reading order -- the same
/// "one name, one content" rule applied one layer further.
#[test]
fn the_same_device_from_two_files_is_a_finding() {
    let dir = dir_with(&[("a.json", GOOD), ("b.json", GOOD)]);
    let (catalogue, findings) = read(&dir);

    assert_eq!(catalogue.len(), 2, "the first file applies");
    assert_eq!(findings.len(), 2, "both devices of the second are findings");
    assert!(findings[0].contains("reading order"), "{}", findings[0]);
}

/// **A broken file costs its file, not the inventory.**
#[test]
fn a_broken_file_costs_only_itself() {
    let dir = dir_with(&[("good.json", GOOD), ("broken.json", "{ this is no JSON")]);
    let (catalogue, findings) = read(&dir);

    assert_eq!(catalogue.len(), 2, "the good file carries on");
    assert_eq!(findings.len(), 1);
}

/// **YAML gets a sentence of its own.**
///
/// Without it, it would look as though the device did not exist, and the
/// search for the error would begin at the driver instead of at the tool.
#[test]
fn a_yaml_file_is_named_and_not_skipped() {
    let dir = dir_with(&[(
        "spec.yaml",
        "cdiVersion: \"0.6.0\"\nkind: example.com/probe\n",
    )]);
    let (catalogue, findings) = read(&dir);

    assert!(catalogue.is_empty());
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].contains("--format=json"),
        "the message must name the way out: {}",
        findings[0]
    );
}

/// **A missing directory is no finding.**
///
/// A node without an accelerator is this cluster's normal case; a failure
/// there would make a broken node out of a missing GPU, when running
/// containers must never be stopped for a reason unrelated to them.
#[test]
fn a_missing_directory_is_normal() {
    let (catalogue, findings) = Catalogue::read(&[PathBuf::from("/does/not/exist/tardigrade-cdi")]);

    assert!(catalogue.is_empty());
    assert!(
        findings.is_empty(),
        "having no device is no finding: {findings:?}"
    );
}

/// **The global `containerEdits` apply to every device.**
#[test]
fn the_global_edits_reach_every_device() {
    let body = r#"{
      "cdiVersion": "0.6.0",
      "kind": "example.com/probe",
      "containerEdits": {
        "env": [ "PROBE_LIB=/opt/probe" ],
        "mounts": [ { "hostPath": "/etc", "containerPath": "/opt/probe", "options": ["ro"] } ]
      },
      "devices": [
        { "name": "0", "containerEdits": {
            "deviceNodes": [ { "path": "/dev/null", "type": "c", "major": 1, "minor": 3 } ] } },
        { "name": "1", "containerEdits": {
            "deviceNodes": [ { "path": "/dev/zero", "type": "c", "major": 1, "minor": 5 } ] } }
      ]
    }"#;
    let dir = dir_with(&[("g.json", body)]);
    let (catalogue, findings) = read(&dir);
    assert!(findings.is_empty(), "{findings:?}");

    for name in ["0", "1"] {
        let device = catalogue
            .get(&format!("example.com/probe={name}"))
            .expect("the device");
        assert_eq!(device.edits.env, vec!["PROBE_LIB=/opt/probe"]);

        let mounts = device.edits.oci_mounts().expect("the mounts");
        assert_eq!(mounts.len(), 1);
        // **`bind` is enforced**, even when the spec names only `ro`.
        let options = mounts[0].options().clone().expect("the options");
        assert!(options.contains(&"ro".to_owned()));
        assert!(
            options.contains(&"bind".to_owned()),
            "without `bind` the kernel mounts an empty file system"
        );
    }
}

/// **A device without a node gives nothing** and is therefore a finding.
#[test]
fn a_device_without_a_node_is_refused() {
    let body = r#"{
      "cdiVersion": "0.6.0",
      "kind": "example.com/probe",
      "devices": [ { "name": "0", "containerEdits": { "env": ["X=1"] } } ]
    }"#;
    let dir = dir_with(&[("empty.json", body)]);
    let (catalogue, findings) = read(&dir);

    assert!(catalogue.is_empty());
    assert!(findings[0].contains("device node"), "{}", findings[0]);
}
