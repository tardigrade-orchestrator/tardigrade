//! The generated stub and the vendored `.proto` must fit together.
//!
//! The same as `tg-defs/tests/schema_drift.rs` and for the same reason: `cargo
//! xtask proto --check` regenerates and compares — that is the stronger check
//! —, but it runs in `cargo xtask ci` and **not** in the Definition of Done from
//! `CLAUDE.md`. Whoever runs the Definition of Done would never check the drift.
//!
//! Here it weighs additionally, because the `.proto` is **vendored**
//! (ADR-0035): it is the unmodified version of the SPIFFE specification, and its
//! provenance stands in `PROVENANCE.md`. A change to it without a new product
//! means that the socket speaks something other than the document in the tree
//! asserts — and the interop with `rust-spiffe` is precisely phase 7c's
//! assurance.

/// How the version line begins — the same string as in `xtask/src/proto.rs`.
const MARKER: &str = "// Proto version:";

/// **The version in the stub's header is the `.proto`'s.**
#[test]
fn the_generated_stub_matches_the_proto() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root");

    let proto = std::fs::read(root.join("third-party/spiffe-workload-api/workload.proto"))
        .expect(".proto readable");
    // Without this assurance the test would check nothing as soon as the path is
    // no longer right: over zero bytes any number computes.
    assert!(proto.len() > 1_000, "the .proto was not read");

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in &proto {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    let expected = format!("{MARKER} {hash:016x}");

    let generated = include_str!("../src/workload_api/pb.rs");
    let line = generated
        .lines()
        .find(|line| line.starts_with(MARKER))
        .unwrap_or_else(|| {
            panic!("the stub names no proto version — `cargo xtask proto` creates it.")
        });

    assert_eq!(
        line, expected,
        "the .proto has changed without the stub arising anew — `cargo xtask \
         proto` catches it up. Until then the socket speaks something other \
         than the vendored document (ADR-0035)."
    );
}
