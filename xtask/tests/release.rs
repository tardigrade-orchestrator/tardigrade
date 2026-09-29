//! What keeps the delivery build in its place (ADR-0138).
//!
//! The run itself builds release and is therefore not in the gate — the same
//! situation as with `bench`. What it promises it checks after the build itself
//! (the counter-check in `release::check`). Here stand the statements that can
//! go stale **without** a build.

/// The source of the build step.
const RELEASE: &str = include_str!("../src/release.rs");

/// The usage help and the dispatch.
const MAIN: &str = include_str!("../src/main.rs");

/// **What is built is the list the SBOM also counts** (ADR-0138,
/// determination 7).
///
/// Two lists would be two opportunities for the bill of materials to describe
/// something other than what was built.
#[test]
fn the_delivery_is_built_from_the_list_the_sbom_counts() {
    assert!(
        RELEASE.contains("use crate::sbom::DELIVERED;"),
        "release.rs does not take the delivery units from the bill of materials"
    );

    // A second list stands out by its names: it would have to name the same four
    // packages.
    for unit in ["tg-agent", "tg-proxy", "tgctl"] {
        assert!(
            !RELEASE.contains(&format!("\"{unit}\"")),
            "release.rs names `{unit}` itself — that is the second list"
        );
    }
}

/// **No checked-in prefix** (ADR-0138, option D, rejected).
///
/// A `--remap-path-prefix` as a constant in `.cargo/config.toml` would contain
/// **one** machine's home directory. On any other it would hit nothing and stay
/// without effect — without an error message. That is worse than nothing: it
/// would look like care, and the next auditor would consider the question
/// answered.
#[test]
fn no_checked_in_config_hardcodes_the_remap() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("root");
    let config = root.join(".cargo/config.toml");
    let text = std::fs::read_to_string(&config).expect("the cargo configuration");

    assert!(
        !text.contains("remap-path-prefix"),
        "{}: a fixed remap prefix applies only on one machine (ADR-0138)",
        config.display()
    );
    assert!(
        !text.contains("rustflags"),
        "{}: `rustflags` here would overwrite the delivery build, and silently \
         at that (ADR-0138)",
        config.display()
    );
}

/// **The run has a name, and the usage help names it.**
///
/// What stands only in the code is lost in operation — the finding out of which
/// the manual guard in `tgctl` arose.
#[test]
fn the_usage_names_the_release_lane() {
    assert!(
        MAIN.contains("cargo xtask release"),
        "the usage help does not name the delivery build"
    );
    assert!(
        MAIN.contains("\"release\" => release::run"),
        "the subcommand `release` is not dispatched"
    );
}

/// **And the operations manual too.**
///
/// A build path an operator has to know belongs where they look.
#[test]
fn the_handbook_names_the_release_lane() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("root");
    let handbook = std::fs::read_to_string(root.join("docs/OPERATIONS.md")).expect("the manual");

    assert!(
        handbook.contains("cargo xtask release"),
        "the operations manual does not name the delivery build (ADR-0138)"
    );
}

/// **The note about `trim-paths` stays at the code** (ADR-0138,
/// determination 6).
///
/// As soon as `profile.release.trim-paths` is stable, it replaces the
/// `RUSTFLAGS` here. A note that stands only in the ADR does not find whoever
/// opens the file.
#[test]
fn the_later_way_is_named_where_it_would_be_taken() {
    assert!(
        RELEASE.contains("trim-paths"),
        "release.rs does not say what it will one day replace"
    );
}
