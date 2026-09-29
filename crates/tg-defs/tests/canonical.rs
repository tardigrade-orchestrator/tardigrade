//! Canonicalization and the loader's file path.
//!
//! `tests/loader.rs` checks the way in: XML → typed values. Here stands the way
//! back out and the way from disk.
//!
//! Why that deserves tests of its own: `workload_to_xml` is no convenience but
//! the canonicalization step of two other crates. `tg-consensus` puts its
//! output into the replicated state machine, `tg-runtime` into the local
//! desired-state cache. If a field is lost in the process, it is not the
//! loader that loses it but the **desired state** — and silently at that: the
//! result still parses, it merely means something else.

use std::fs;

use tg_defs::{
    DependencyKind, ImageExt as _, Kind, LoadError, PullPolicy, ResourcesExt as _, WorkloadClass,
    WorkloadExt as _, from_path, from_str, workload_to_xml,
};

const FULL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service" class="single-writer">
    <image reference="registry.example.com/api:1.4.2" pullPolicy="always"/>
    <command>
      <arg>/usr/bin/api</arg>
      <arg>--port</arg>
      <arg>8080</arg>
    </command>
    <resources>
      <cpu millicores="500"/>
      <memory bytes="536870912"/>
    </resources>
    <dependencies>
      <after ref="db"/>
      <requires ref="db"/>
      <wants ref="cache"/>
      <bindsTo ref="api-sidecar"/>
      <before ref="batch"/>
      <conflicts ref="api-legacy"/>
    </dependencies>
  </workload>
</workloads>"#;

const MINIMAL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="db" kind="service">
    <image reference="registry.example.com/postgres:16"/>
  </workload>
</workloads>"#;

/// Parses `xml`, asserts it contains exactly one workload, and returns a
/// clone of it.
///
/// # Panics
///
/// Panics if the fixture does not parse or does not contain exactly one
/// workload.
fn only(xml: &str) -> tg_defs::generated::WorkloadType {
    let set = from_str(xml).expect("fixture must parse");
    assert_eq!(set.workloads().len(), 1);
    set.workloads()[0].clone()
}

// --- Canonicalization -------------------------------------------------------

/// A complete workload survives serializing and re-reading with **every**
/// field.
///
/// That is the test that exposes a lost field. A comparison over the name alone
/// would be worthless here — it survives even when everything else is gone.
#[test]
fn every_field_survives_the_canonical_round_trip() {
    let original = only(FULL);
    let xml = workload_to_xml(&original).expect("serializable");
    let restored = only(&xml);

    assert_eq!(restored.name(), "api");
    assert_eq!(restored.kind(), Kind::Service);
    assert_eq!(restored.class(), WorkloadClass::SingleWriter);
    assert_eq!(
        restored.image().reference(),
        "registry.example.com/api:1.4.2"
    );
    assert_eq!(restored.image().pull_policy(), Some(PullPolicy::Always));
    assert_eq!(restored.command(), ["/usr/bin/api", "--port", "8080"]);

    let resources = restored.resources().expect("resources");
    assert_eq!(resources.millicores(), Some(500));
    assert_eq!(resources.memory_bytes(), Some(536_870_912));

    let dependencies: Vec<(DependencyKind, &str)> = restored
        .dependencies()
        .iter()
        .map(|dependency| (dependency.kind(), dependency.target()))
        .collect();
    assert_eq!(
        dependencies,
        [
            (DependencyKind::After, "db"),
            (DependencyKind::Requires, "db"),
            (DependencyKind::Wants, "cache"),
            (DependencyKind::BindsTo, "api-sidecar"),
            (DependencyKind::Before, "batch"),
            (DependencyKind::Conflicts, "api-legacy"),
        ]
    );
}

/// Canonicalizing is idempotent: the second round changes nothing any more.
///
/// Without this property the stored state drifts by a trifle at every upsert —
/// and two nodes that have written a different number of times would have
/// different bytes for the same definition.
#[test]
fn canonicalization_is_idempotent() {
    for source in [FULL, MINIMAL] {
        let first = workload_to_xml(&only(source)).expect("serializable");
        let second = workload_to_xml(&only(&first)).expect("serializable");

        assert_eq!(first, second);
    }
}

/// The order of the dependencies is preserved.
///
/// Ordering and requirement are separate axes; the start order is computed by
/// `tg-model` from the graph and not from the document order. The
/// canonicalization must nevertheless not reorder: what comes out here is the
/// audit object, and a reordered list is a different record.
#[test]
fn the_dependency_order_is_preserved() {
    let xml = workload_to_xml(&only(FULL)).expect("serializable");
    let restored = only(&xml);

    let targets: Vec<&str> = restored
        .dependencies()
        .iter()
        .map(|dependency| dependency.target())
        .collect();
    assert_eq!(
        targets,
        ["db", "db", "cache", "api-sidecar", "batch", "api-legacy"]
    );
}

/// A minimal workload gains no fields on canonicalization.
///
/// A silently inserted default value would be a statement nobody made — and
/// from the first upsert on it would stand in the log as desired.
#[test]
fn canonicalization_invents_nothing() {
    let restored = only(&workload_to_xml(&only(MINIMAL)).expect("serializable"));

    assert_eq!(restored.image().pull_policy(), None);
    assert!(restored.resources().is_none());
    assert!(restored.dependencies().is_empty());
    assert!(restored.command().is_empty());
    assert_eq!(
        restored.class(),
        WorkloadClass::Replicated,
        "without a setting it stays replicated (ADR-0010)"
    );
}

/// The output carries the XML declaration and is thereby a complete file, not a
/// fragment. `tg-runtime` puts it on disk like that.
#[test]
fn the_output_is_a_complete_document() {
    let xml = workload_to_xml(&only(MINIMAL)).expect("serializable");

    assert!(
        xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
        "{xml}"
    );
    assert!(xml.ends_with('\n'), "{xml:?}");
    assert!(xml.contains("urn:tardigrade:workload:v1"), "{xml}");
}

/// A value with XML special characters is escaped on serialization and comes
/// back unchanged.
///
/// The way leads over the generated serializer and not over assembled strings —
/// precisely for that reason. A hand-built output would be an injection point
/// here: an image reference with `"/>` would otherwise append an element nobody
/// wrote.
#[test]
fn special_characters_are_escaped_not_interpolated() {
    let source = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/a&amp;b:1&lt;2"/>
    <command>
      <arg>--flag=&quot;value&quot;</arg>
      <arg>a&gt;b</arg>
    </command>
  </workload>
</workloads>"#;

    let original = only(source);
    assert_eq!(original.image().reference(), "registry.example.com/a&b:1<2");

    let xml = workload_to_xml(&original).expect("serializable");
    assert!(
        !xml.contains("a&b:1<2"),
        "the raw value stands unescaped in the output: {xml}"
    );

    let restored = only(&xml);
    assert_eq!(restored.image().reference(), "registry.example.com/a&b:1<2");
    assert_eq!(restored.command(), [r#"--flag="value""#, "a>b"]);
}

/// A set becomes one document per workload — each readable on its own. That is
/// how one entry gets into the log (one entry, one change) and one file into
/// the cache.
#[test]
fn each_workload_becomes_a_document_of_its_own() {
    let set = from_str(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="db" kind="service">
    <image reference="example.com/db:1"/>
  </workload>
  <workload name="api" kind="service">
    <image reference="example.com/api:1"/>
    <dependencies>
      <after ref="db"/>
    </dependencies>
  </workload>
</workloads>"#,
    )
    .expect("must parse");

    for workload in set.workloads() {
        let xml = workload_to_xml(workload).expect("serializable");
        let single = from_str(&xml).expect("readable again");

        assert_eq!(single.workloads().len(), 1);
        assert_eq!(single.workloads()[0].name(), workload.name());
    }
}

// --- The file path ----------------------------------------------------------

/// A file is read and yields the same as its contents as a string.
#[test]
fn a_file_yields_the_same_as_its_contents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("workload.xml");
    fs::write(&path, MINIMAL).expect("write");

    let from_file = from_path(&path).expect("must parse");
    let from_string = from_str(MINIMAL).expect("must parse");

    assert_eq!(from_file.workloads().len(), from_string.workloads().len());
    assert_eq!(
        from_file.workloads()[0].name(),
        from_string.workloads()[0].name()
    );
}

/// A missing file yields an I/O error that names the path and the cause — and
/// no validation error. Confusing the two sends the operator to the wrong
/// place.
#[test]
fn a_missing_file_is_an_io_error_naming_the_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("does-not-exist.xml");

    let err = from_path(&path).expect_err("file is missing");

    match &err {
        LoadError::Io {
            path: named,
            source,
        } => {
            assert_eq!(named, &path);
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        LoadError::Invalid { .. } => panic!("I/O error expected, not a validation error"),
    }

    let text = err.to_string();
    assert!(text.contains(&path.display().to_string()), "{text}");
    assert!(std::error::Error::source(&err).is_some());
}

/// A directory is no definition — and likewise yields an I/O error instead of a
/// panic.
#[test]
fn a_directory_is_an_io_error() {
    let dir = tempfile::tempdir().expect("tempdir");

    assert!(matches!(
        from_path(dir.path()).expect_err("directory"),
        LoadError::Io { .. }
    ));
}

/// An unusable file yields a validation error that names the **file** as the
/// origin — not `<input>`. With a stack of files that is the only hint as to
/// which one is meant.
#[test]
fn an_invalid_file_names_itself_as_the_origin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("broken.xml");
    fs::write(&path, "<workloads><not-closed>").expect("write");

    let err = from_path(&path).expect_err("invalid");

    match &err {
        LoadError::Invalid { origin, detail } => {
            assert!(
                origin.contains("broken.xml"),
                "the origin does not name the file: {origin}"
            );
            assert!(!detail.is_empty());
        }
        LoadError::Io { .. } => panic!("validation error expected"),
    }
    assert!(std::error::Error::source(&err).is_none());
}

/// An empty file is refused, not read as an empty set.
///
/// "No workloads" and "no definition" are two different statements; reading the
/// second as the first would mean passing off an empty data directory as
/// desired emptiness.
#[test]
fn an_empty_file_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");

    for (name, content) in [("empty.xml", ""), ("blank.xml", "   \n\t \n")] {
        let path = dir.path().join(name);
        fs::write(&path, content).expect("write");

        assert!(
            matches!(from_path(&path), Err(LoadError::Invalid { .. })),
            "{name} was accepted"
        );
    }
}
