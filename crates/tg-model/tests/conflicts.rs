//! `Conflicts` at ingest (ADR-0009, ADR-0061 determination 6).
//!
//! Written **before** the implementation (CLAUDE.md: tests first for pure-logic
//! crates).
//!
//! ADR-0009 says "must not be active at the same time". That is enforced where
//! the intent arises — at ingest —, and not at runtime: whoever enforces at
//! runtime has to choose a winner, and a winner rule is a policy (ADR-0011,
//! ADR-0057).

use tg_model::graph::{ConflictError, validate_conflicts};

fn workloads(xml: &str) -> Vec<tg_defs::generated::WorkloadType> {
    tg_defs::from_str(xml)
        .expect("the fixture has to parse")
        .workloads()
        .to_vec()
}

/// Two workloads, one of which excludes the other.
const DECLARED_ONE_SIDED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="old" kind="service">
    <image reference="example.com/old:1"/>
    <dependencies><conflicts ref="new"/></dependencies>
  </workload>
  <workload name="new" kind="service">
    <image reference="example.com/new:2"/>
  </workload>
</workloads>"#;

/// **Two mutually excluding workloads that are wanted at the same time are
/// refused.**
#[test]
fn a_declared_conflict_between_two_wanted_workloads_is_rejected() {
    let err = validate_conflicts(&workloads(DECLARED_ONE_SIDED))
        .expect_err("a conflict between two wanted workloads is one");

    let ConflictError::BothWanted { first, second } = err;
    // **Both** are named, and in a stable order: an operator reads the finding,
    // not the order of the documents.
    assert_eq!((first.as_str(), second.as_str()), ("new", "old"));
}

/// **The conflict takes effect in both directions**, even if only one side
/// declares it — otherwise the effect would hang on who wrote it down.
///
/// The same set, only the declaration stands at the other one. Without this
/// counter-check it would stay open whether the check sees only one direction.
#[test]
fn a_conflict_is_symmetric() {
    let mirrored = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="old" kind="service">
    <image reference="example.com/old:1"/>
  </workload>
  <workload name="new" kind="service">
    <image reference="example.com/new:2"/>
    <dependencies><conflicts ref="old"/></dependencies>
  </workload>
</workloads>"#;

    let err = validate_conflicts(&workloads(mirrored)).expect_err("the other way round too");

    let ConflictError::BothWanted { first, second } = err;
    assert_eq!((first.as_str(), second.as_str()), ("new", "old"));
}

/// **A conflict with a workload that does not exist is without consequence.**
///
/// The check expressly demands **no** referential integrity: one workload comes
/// per log entry (ADR-0004), and the set is complete only at the end. An upsert
/// that failed because a sibling document points at something not yet applied
/// would be unusable.
#[test]
fn a_conflict_with_an_absent_workload_is_harmless() {
    let alone = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="old" kind="service">
    <image reference="example.com/old:1"/>
    <dependencies><conflicts ref="doesnotexist"/></dependencies>
  </workload>
</workloads>"#;

    assert!(validate_conflicts(&workloads(alone)).is_ok());
}

/// A set without conflicts gets through. Without this test it would stay open
/// whether the check ever lets anything through at all.
#[test]
fn a_set_without_conflicts_passes() {
    assert!(
        validate_conflicts(&workloads(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="example.com/api:1"/>
    <dependencies><after ref="db"/><requires ref="db"/></dependencies>
  </workload>
  <workload name="db" kind="service">
    <image reference="example.com/db:1"/>
  </workload>
</workloads>"#
        ))
        .is_ok()
    );
}
