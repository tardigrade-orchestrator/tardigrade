//! The volume model (ADR-0027 — phase 10a).
//!
//! Written before the implementation. **Three of the five** acceptance criteria
//! of the phase fall here, and all three are rejections:
//!
//! 1. A writable volume cannot be mounted by a second workload — **refused, not
//!    serialized.**
//! 2. A shared volume is mountable only RO; an RW mount is refused.
//! 3. A workload with a writable volume is node-pinned, and the scheduler
//!    refuses to move it.
//!
//! That they stand here and not in an integration test is the core of the
//! decision from ADR-0027: **split brain is structurally excluded, not handled
//! at runtime.** A shared writable file system does not exist, so no oplocking,
//! no coherency and no storage fence are needed. The price for that is that the
//! rejection has to come at ingest — later there would be nothing left to
//! refuse.

use tg_defs::VolumeMode;
use tg_model::storage::{self, StorageError};

fn set(xml: &str) -> Vec<tg_defs::generated::WorkloadType> {
    tg_defs::from_str(xml)
        .expect("the fixture has to parse")
        .workloads()
        .to_vec()
}

fn workload(name: &str, volumes: &str) -> String {
    format!(
        "  <workload name=\"{name}\" kind=\"service\">\n\
         \x20   <image reference=\"example.com/{name}:1\"/>\n\
         {volumes}\
         \x20 </workload>\n"
    )
}

fn volume(name: &str, path: &str, mode: &str) -> String {
    // A read-only volume needs a source (ADR-0027): it is distributed
    // content-addressed, and without a provenance it would be an empty one
    // nobody can fill.
    // readOnly carries a source, readWrite a size — both mandatory and both
    // exclusive (ADR-0027).
    let extra = if mode == "readOnly" {
        format!(" source=\"registry.example.com/{name}:1\"")
    } else {
        " size=\"8388608\"".to_owned()
    };

    format!(
        "    <volumes>\n      <volume name=\"{name}\" path=\"{path}\" mode=\"{mode}\"{extra}/>\n    </volumes>\n"
    )
}

fn document(workloads: &[String]) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n{}</workloads>\n",
        workloads.concat()
    )
}

// ============================================================== Criterion 1

/// **A writable volume belongs to exactly one workload.**
///
/// Refused, not serialized: an orchestrator that admitted two writers one after
/// the other would merely have moved the problem — and ADR-0027 excludes it
/// structurally.
#[test]
fn two_workloads_may_not_both_write_the_same_volume() {
    let xml = document(&[
        workload("ledger", &volume("data", "/var/lib/ledger", "readWrite")),
        workload("report", &volume("data", "/var/lib/report", "readWrite")),
    ]);

    let err = storage::validate(&set(&xml)).expect_err("two writers");

    assert!(
        matches!(err, StorageError::SharedWritable { ref volume, .. } if volume == "data"),
        "expected SharedWritable, was {err:?}"
    );
}

#[test]
fn one_writer_alone_is_fine() {
    let xml = document(&[workload(
        "ledger",
        &volume("data", "/var/lib/ledger", "readWrite"),
    )]);

    storage::validate(&set(&xml)).expect("one writer is the normal case");
}

// ============================================================== Criterion 2

/// **And in the reverse order** — the reader stands first.
///
/// The rule is symmetric, the code is not: there are **two** branches,
/// depending on whom the state machine sees first. The test below covered only
/// the one; a mutation run removed the other, and no target went red.
///
/// In the cluster the order of the log entries decides which branch takes
/// effect — and an operator chooses that, not us.
#[test]
fn the_same_conflict_is_caught_when_the_reader_comes_first() {
    let xml = document(&[
        workload("report", &volume("reference", "/opt/reference", "readOnly")),
        workload(
            "ledger",
            &volume("reference", "/opt/reference", "readWrite"),
        ),
    ]);

    let err = storage::validate(&set(&xml)).expect_err("mixed modes");

    assert!(
        matches!(
            err,
            StorageError::ModeConflict { ref volume, ref writable, ref readonly }
                if volume == "reference" && writable == "ledger" && readonly == "report"
        ),
        "expected ModeConflict, was {err:?}"
    );
}

/// **A shared volume is read-only.**
///
/// The mixed case is the more dangerous one: a writer and a reader see two
/// different states of the same file system, and the reader does not notice
/// it.
#[test]
fn a_volume_that_more_than_one_workload_names_must_be_read_only_everywhere() {
    let xml = document(&[
        workload(
            "ledger",
            &volume("reference", "/opt/reference", "readWrite"),
        ),
        workload("report", &volume("reference", "/opt/reference", "readOnly")),
    ]);

    let err = storage::validate(&set(&xml)).expect_err("mixed modes");

    assert!(
        matches!(
            err,
            StorageError::ModeConflict { ref volume, ref writable, .. }
                if volume == "reference" && writable == "ledger"
        ),
        "expected ModeConflict, was {err:?}"
    );
}

#[test]
fn many_readers_of_one_volume_are_fine() {
    let xml = document(&[
        workload("ledger", &volume("reference", "/opt/reference", "readOnly")),
        workload("report", &volume("reference", "/opt/ref", "readOnly")),
        workload("api", &volume("reference", "/srv/reference", "readOnly")),
    ]);

    storage::validate(&set(&xml)).expect("shared reference data are the point");
}

// ------------------------------------------------ Contradictions in itself

#[test]
fn a_workload_may_not_mount_two_volumes_at_the_same_path() {
    let mut volumes = String::from("    <volumes>\n");
    volumes.push_str(
        "      <volume name=\"one\" path=\"/data\" mode=\"readOnly\" source=\"e.com/a:1\"/>\n",
    );
    volumes.push_str(
        "      <volume name=\"two\" path=\"/data\" mode=\"readOnly\" source=\"e.com/b:1\"/>\n",
    );
    volumes.push_str("    </volumes>\n");
    let xml = document(&[workload("ledger", &volumes)]);

    let err = storage::validate(&set(&xml)).expect_err("two volumes, one path");

    assert!(
        matches!(err, StorageError::DuplicatePath { ref path, .. } if path == "/data"),
        "expected DuplicatePath, was {err:?}"
    );
}

#[test]
fn a_workload_may_not_name_the_same_volume_twice() {
    let mut volumes = String::from("    <volumes>\n");
    volumes.push_str(
        "      <volume name=\"data\" path=\"/a\" mode=\"readOnly\" source=\"e.com/a:1\"/>\n",
    );
    volumes.push_str(
        "      <volume name=\"data\" path=\"/b\" mode=\"readOnly\" source=\"e.com/a:1\"/>\n",
    );
    volumes.push_str("    </volumes>\n");
    let xml = document(&[workload("ledger", &volumes)]);

    let err = storage::validate(&set(&xml)).expect_err("the same name twice");

    assert!(
        matches!(err, StorageError::DuplicateName { ref volume, .. } if volume == "data"),
        "expected DuplicateName, was {err:?}"
    );
}

// ------------------------------------------------- Volumes per instance

/// **HA runs over a replica with its own volume, never over volume migration**
/// (ADR-0027). So every instance carries its own writable volume, and the
/// declared name is the template.
#[test]
fn a_writable_volume_belongs_to_an_instance_not_to_a_workload() {
    assert_eq!(
        storage::volume_of("data", VolumeMode::ReadWrite, 0),
        "data-0"
    );
    assert_eq!(
        storage::volume_of("data", VolumeMode::ReadWrite, 2),
        "data-2"
    );
}

/// A shared volume, by contrast, is **one**. Multiplying it per instance would
/// mean turning reference data into copies — and the point was to share
/// them.
#[test]
fn a_read_only_volume_is_the_same_for_every_instance() {
    for instance in 0..5 {
        assert_eq!(
            storage::volume_of("reference", VolumeMode::ReadOnly, instance),
            "reference"
        );
    }
}

// ------------------------------------------------- Node pinning

#[test]
fn a_workload_with_a_writable_volume_is_pinned_to_its_node() {
    let xml = document(&[workload(
        "ledger",
        &volume("data", "/var/lib/ledger", "readWrite"),
    )]);

    assert!(storage::pinned_by_storage(&set(&xml)[0]));
}

/// Read-only volumes do not bind: they are distributed content-addressed
/// (ADR-0027, like the image store from ADR-0003) and lie everywhere.
#[test]
fn a_workload_with_only_read_only_volumes_is_not_pinned() {
    let xml = document(&[workload(
        "report",
        &volume("reference", "/opt/reference", "readOnly"),
    )]);

    assert!(!storage::pinned_by_storage(&set(&xml)[0]));
}

#[test]
fn a_workload_without_volumes_is_not_pinned() {
    let xml = document(&[workload("api", "")]);

    assert!(!storage::pinned_by_storage(&set(&xml)[0]));
}

// ------------------------------------------- Malicious and broken inputs

/// A volume's name becomes a directory name on the node's disk — the same trust
/// boundary as with the namespace name in 9b. The schema enforces the facet;
/// this test records that it takes effect.
#[test]
fn a_volume_name_that_would_escape_its_directory_never_parses() {
    for hostile in ["../etc", "a/b", ".", "..", "a b"] {
        let xml = document(&[workload(
            "ledger",
            &volume(hostile, "/var/lib/ledger", "readWrite"),
        )]);

        assert!(
            tg_defs::from_str(&xml).is_err(),
            "'{}' was accepted as a volume name",
            hostile.escape_debug()
        );
    }
}

// ===================================== Provenance of shared data (10c)

/// **What is written is not distributed.**
///
/// A source on a writable volume would be an assurance nobody can keep: the
/// volume changes, the source does not.
#[test]
fn a_writable_volume_may_not_name_a_source() {
    let xml = document(&[workload(
        "ledger",
        "    <volumes>\n      <volume name=\"data\" path=\"/var/lib/ledger\" \
         mode=\"readWrite\" size=\"8388608\" source=\"e.com/data:1\"/>\n    </volumes>\n",
    )]);

    let err = storage::validate(&set(&xml)).expect_err("a source on the writer");

    assert!(
        matches!(err, StorageError::SourceOnWritable { ref volume, .. } if volume == "data"),
        "expected SourceOnWritable, was {err:?}"
    );
}

/// **What is distributed has a provenance.**
///
/// A shared volume without a source would be an empty one nobody can fill —
/// after all, nobody may write it.
#[test]
fn a_read_only_volume_must_name_a_source() {
    let xml = document(&[workload(
        "report",
        "    <volumes>\n      <volume name=\"reference\" path=\"/opt/reference\" \
         mode=\"readOnly\"/>\n    </volumes>\n",
    )]);

    let err = storage::validate(&set(&xml)).expect_err("no source");

    assert!(
        matches!(err, StorageError::SharedWithoutSource { ref volume, .. } if volume == "reference"),
        "expected SharedWithoutSource, was {err:?}"
    );
}

/// **One name, one content.**
///
/// Two sources under one name would yield two different directories both called
/// "reference" — and which one a container saw would hang on who was there
/// first.
#[test]
fn two_workloads_may_not_give_one_volume_two_sources() {
    let xml = document(&[
        workload(
            "report",
            "    <volumes>\n      <volume name=\"reference\" path=\"/opt/s\" \
             mode=\"readOnly\" source=\"e.com/reference:1\"/>\n    </volumes>\n",
        ),
        workload(
            "api",
            "    <volumes>\n      <volume name=\"reference\" path=\"/srv/s\" \
             mode=\"readOnly\" source=\"e.com/reference:2\"/>\n    </volumes>\n",
        ),
    ]);

    let err = storage::validate(&set(&xml)).expect_err("two sources");

    assert!(
        matches!(err, StorageError::SourceConflict { ref volume, .. } if volume == "reference"),
        "expected SourceConflict, was {err:?}"
    );
}

/// The same source under the same name is the normal case — that is how
/// workloads share reference data.
#[test]
fn the_same_source_under_the_same_name_is_the_point() {
    let xml = document(&[
        workload("report", &volume("reference", "/opt/s", "readOnly")),
        workload("api", &volume("reference", "/srv/s", "readOnly")),
    ]);

    storage::validate(&set(&xml)).expect("shared reference data");
}

/// **What is written needs a size.**
///
/// A volume without a size cannot be created — and the error would otherwise
/// come from `mkfs`, on a node, in a privileged process.
#[test]
fn a_writable_volume_must_name_a_size() {
    let xml = document(&[workload(
        "ledger",
        "    <volumes>\n      <volume name=\"data\" path=\"/var/lib/ledger\" \
         mode=\"readWrite\"/>\n    </volumes>\n",
    )]);

    let err = storage::validate(&set(&xml)).expect_err("no size");

    assert!(
        matches!(err, StorageError::WritableWithoutSize { ref volume, .. } if volume == "data"),
        "expected WritableWithoutSize, was {err:?}"
    );
}

/// **What is shared has the size of its content.**
///
/// A setting beside it would be a second truth — and the one that counts stands
/// in the digest.
#[test]
fn a_read_only_volume_may_not_name_a_size() {
    let xml = document(&[workload(
        "report",
        "    <volumes>\n      <volume name=\"reference\" path=\"/opt/reference\" \
         mode=\"readOnly\" source=\"e.com/reference:1\" size=\"8388608\"/>\n    </volumes>\n",
    )]);

    let err = storage::validate(&set(&xml)).expect_err("a size on the reader");

    assert!(
        matches!(err, StorageError::SizeOnShared { ref volume, .. } if volume == "reference"),
        "expected SizeOnShared, was {err:?}"
    );
}
