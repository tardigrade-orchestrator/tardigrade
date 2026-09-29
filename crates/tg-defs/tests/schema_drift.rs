//! The generated code and the schema must fit together.
//!
//! # Why this stands here and not only in the `xtask`
//!
//! `cargo xtask codegen --check` regenerates the code and compares it — that is
//! the stronger check and stays. Only it runs in `cargo xtask ci` and **not** in
//! the Definition of Done from `CLAUDE.md` (fmt, clippy, test, deny). Whoever
//! runs the Definition of Done would never check the drift.
//!
//! And that is not hypothetical: this tree once checked in a generated parser
//! that did not match the schema — the path-traversal facet from phase 10a was
//! weakened in it, for two commits. It stood out because a fixture covered
//! exactly that facet; a schema change without a matching fixture would have
//! stayed silent.
//!
//! # What this check achieves and what it does not
//!
//! It answers **one** question: *has the schema changed without anyone
//! regenerating?* It generates nothing and therefore does not say whether the
//! code **matches** the schema — that is checked by `codegen --check`. A `cargo
//! run` out of a test would be the obvious answer and the wrong one: the run
//! would wait on the target directory's lock that `cargo test` itself holds,
//! and a test that hangs is worse than one that fails (the finding from 11b).

/// How the version line begins — the same string as in `xtask/src/codegen.rs`.
const MARKER: &str = "// Schema version:";

/// **The version in the generated code's header is the schema's.**
///
/// The value is **computed**, not copied: a number in the test would be a
/// second hand-maintained place, and somebody forgets that — exactly the
/// construction this tree has measured four times as a source of error.
#[test]
fn the_generated_code_matches_the_schema() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root");

    let schema = std::fs::read(root.join("schema/workload.xsd")).expect("XSD readable");
    // Without this assurance the test would check nothing as soon as the path
    // is no longer right: over zero bytes any number computes.
    assert!(schema.len() > 1_000, "the XSD was not read");

    // FNV-1a, written out as in the `xtask` and for the same reason as in
    // `tg_model::keys` (ADR-0057): `DefaultHasher` is not stable between Rust
    // versions, and a version number that shifts on a compiler upgrade would
    // report a drift that does not exist.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in &schema {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    let expected = format!("{MARKER} {hash:016x}");

    let generated = include_str!("../src/generated.rs");
    let line = generated
        .lines()
        .find(|line| line.starts_with(MARKER))
        .unwrap_or_else(|| {
            panic!(
                "the generated code names no schema version — either it is older \
                 than this check, or the header in xtask/src/codegen.rs is now \
                 called something else. `cargo xtask codegen` creates it."
            )
        });

    assert_eq!(
        line, expected,
        "the schema has changed without the generated code arising anew — \
         `cargo xtask codegen` catches it up. Until then the loader validates \
         against a different schema than the one in the tree (ADR-0008)."
    );
}

/// **A workload name must be able to be a DNS label** (ADR-0013).
///
/// # The ordering condition
///
/// > facet length of the workload name **≤** 63
///
/// The name becomes `<name>.<zone>` in resolution, and a DNS label may have 63
/// characters (RFC 1035). The facet in the schema is `[a-z][a-z0-9-]{0,62}` —
/// one leading character plus 62 —, hence **exactly** one label.
///
/// # Why that needs a witness
///
/// Measured, the two 63s stand in two crates with **different** reasons:
/// `tg_model::mesh` names "the upper bound from the XSD", `tg_net::discovery`
/// "the greatest length of a DNS label (RFC 1035)". That it is the same number
/// is not one that coincides by chance — it **must** coincide, and that stood
/// nowhere.
///
/// If somebody raises the facet, the workload is accepted, gets an address,
/// runs — and `discovery` refuses its name as `LabelTooLong`. It is then
/// **silently** missing from resolution: it runs, is healthy and reachable for
/// nobody.
///
/// A build assertion does not work here, because the source is a **file**; the
/// witness therefore reads the schema, like its neighbour above.
#[test]
fn the_workload_name_fits_a_dns_label() {
    /// The greatest length of a DNS label (RFC 1035) — the same number as in
    /// `tg_net::discovery::MAX_LABEL`, which is not reachable here (`tg-defs`
    /// lies below `tg-net`).
    ///
    /// **And the same as `tg_model::names::MAX_NAME`**, the name part of a
    /// SPIFFE id (ADR-0036). Its consumers, measured:
    ///
    /// * the **check** itself (`tg_model::names::is_plausible`) — it stood
    ///   rebuilt by hand three times, in `tg-consensus` and twice in
    ///   `tg-identity`, and decides whether a name can become an identity at
    ///   all;
    /// * the **secret form** beside it (`is_plausible_secret`), rebuilt twice;
    /// * the **socket path** since ADR-0081: the agent computes from it how
    ///   long a name may be so that it still fits in `sun_path` (107 bytes,
    ///   measured);
    /// * the **DNS zone**: `<name>.<zone>` must stay below 253 bytes.
    ///
    /// All hang on this facet — whoever raises it gets a workload whose
    /// container does not start without an identity.
    const MAX_LABEL: usize = 63;

    let schema = std::fs::read_to_string("../../schema/workload.xsd").expect("schema");

    // The facet stands as `<xs:pattern value="[a-z][a-z0-9-]{0,62}"/>` in the
    // type `WorkloadName`. Read from it is the **number**: a pattern of a
    // different shape makes this test red, and that is right — then the
    // relation is to be checked anew.
    let start = schema
        .find("<xs:simpleType name=\"WorkloadName\">")
        .expect("the type WorkloadName must stand in the schema");
    let block = &schema[start..];
    let end = block.find("</xs:simpleType>").expect("type ends");
    let block = &block[..end];

    let pattern = block
        .lines()
        .find(|line| line.contains("<xs:pattern"))
        .expect("WorkloadName must carry a pattern");
    let repeats: usize = pattern
        .split_once("{0,")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(digits, _)| digits.parse().expect("number"))
        .expect("the pattern must have the form [..][..]{0,N}");

    // One leading character plus N repetitions.
    let longest = 1 + repeats;
    assert!(
        longest <= MAX_LABEL,
        "a workload name may become {longest} characters long, a DNS label \
         carries {MAX_LABEL} — a longer name runs, is healthy and falls \
         **silently** out of resolution (ADR-0013)"
    );
}
