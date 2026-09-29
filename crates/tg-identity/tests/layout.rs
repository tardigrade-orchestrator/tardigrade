//! The layout is a contract over three parties -- and must stay one.
//!
//! `tgd` writes its cluster leaf, an **operator** copies it (ADR-0043: "distribute
//! peer leaves"), `tg-agent` reads it. `docs/OPERATIONS.md` names the paths literally,
//! and whoever types them out relies on their being right.
//!
//! Measured, every name was spelled out at **two to four** places, and the
//! interesting ones crossed crate boundaries. Whoever renames one side breaks the
//! other -- and the error shows itself as "without an anchor no session", so like an
//! operating error and not like code drift.

use tg_identity::layout;

/// What the manual names in the way of identity paths.
const NAMED_IN_HANDBOOK: [&str; 4] = [
    layout::NODE_LEAF,
    layout::CONTROL_PLANE,
    layout::JOIN_TOKEN,
    layout::DIR,
];

/// **The manual names no path that does not exist.**
///
/// The counter-direction is expressly **no** assurance: the manual is a selection and
/// no inventory -- the same boundary as at the subcommand guard in `tgctl`.
#[test]
fn the_handbook_names_the_paths_that_exist() {
    let handbook = include_str!("../../../docs/OPERATIONS.md");

    // Without this assurance the test would check nothing as soon as the path is no
    // longer right: in zero bytes no name occurs, so no wrong one either.
    assert!(
        handbook.len() > 5_000,
        "the manual was not read: {} bytes",
        handbook.len()
    );

    for name in NAMED_IN_HANDBOOK {
        assert!(
            handbook.contains(name),
            "the manual no longer names `{name}` -- either the name has moved \
             (then the manual belongs pulled along) or the instructions an \
             operator types out are no longer right"
        );
    }
}

/// **The names are spelled out a second time nowhere.**
///
/// The actual guard: a literal in `tgd` or `tg-agent` is a second source for a
/// contract three parties read. It may stand **only** in `layout.rs`.
///
/// The list comes from the **source** and not from this test. That is a finding about
/// my own work: handwritten it covered **8 of 18** constants, and the rationale for
/// that stood as a comment in the middle of it -- `ORDINAL` had already been
/// forgotten once and promptly stayed standing in four files. A maintained list is
/// the construction this tree has measured five times as a source of error.
///
/// What is read is the production part of all the crates **and of `xtask`**. The
/// haystack was previously `crates/` alone, and measured, `cargo xtask identity` wrote
/// four of these names by hand -- the same file used `layout::CA` and `layout::BUNDLE`
/// in the process and spelled `"signing"` one line above. That is no exception but a
/// blind spot: what `xtask` produces is exactly the material the binaries look for,
/// and an offset shows itself only at the first connection.
///
/// Test modules may spell paths out -- there a fixed name is precisely the intent (a
/// test that uses the constant does not check that the file is called that).
/// **Comment lines likewise** -- and that is a precaution and no finding: measured, no
/// comment quotes one of these names today, so the filter changes nothing. It stands
/// there because this tree's doc blocks quote names constantly and the same false
/// positive has already hit three other guards; a guard that produces them gets
/// switched off instead of read.
#[test]
fn no_crate_spells_a_path_a_second_time() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root");

    let names = layout_names(root);
    assert!(names.len() > 15, "the constants were not read: {names:?}");

    let mut files = 0_usize;
    let mut offenders = Vec::new();
    let mut stack = vec![root.join("crates"), root.join("xtask").join("src")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            // This file **is** the source.
            if path.ends_with("layout.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("readable");
            let code = text
                .find("\n#[cfg(test)]")
                .map_or(text.as_str(), |at| &text[..at]);
            let code: String = code
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            files += 1;

            for name in &names {
                if code.contains(&format!("\"{name}\"")) {
                    offenders.push(format!("{}: \"{name}\"", path.display()));
                }
            }
        }
    }

    assert!(files > 50, "the source was not read: {files}");
    assert!(
        offenders.is_empty(),
        "an identity path stands a second time in the code -- `tg_identity::layout` \
         is the one source (ADR-0043: the layout is an operator interface): \
         {offenders:?}"
    );
}

/// The path names from `layout.rs`, without the ambiguous ones.
///
/// **`DIR` and `GROUP` do not stand in it**, and both are measured: `"identity"` is
/// also the name of a key kind (`tg_model::keys`), and `"group"` that of a signer kind
/// (`tg_identity::mint`). A word that means something different at several places is
/// no good as a guard -- the constants exist nevertheless, and the callers use them
/// over `layout::dir` and `Material` respectively.
fn layout_names(root: &std::path::Path) -> Vec<String> {
    const AMBIGUOUS: [&str; 2] = ["DIR", "GROUP"];

    let source = std::fs::read_to_string(
        root.join("crates")
            .join("tg-identity")
            .join("src")
            .join("layout.rs"),
    )
    .expect("layout.rs is readable");

    source
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("pub const ")?;
            let (name, rest) = rest.split_once(": &str = \"")?;
            let (literal, _) = rest.split_once('"')?;
            (!AMBIGUOUS.contains(&name)).then(|| literal.to_owned())
        })
        .collect()
}

/// **Nobody spells out a time window from ADR-0014 a second time.**
///
/// The SVID's three numbers (`SVID_TTL`, `SVID_ROTATE_AFTER`, `SOFT_FAIL_GRACE`) are
/// **one** source each, and this guard keeps it so. The case it catches is measured:
/// the grace stood **invented inline** at the one place that issues an agent
/// intermediate -- there, where `IntermediateProfile` does not bring it along, because
/// it is no property of a profile (ADR-0019: it describes the behaviour at an expiry,
/// not the thing that expires).
///
/// What is searched for is the **assignment** and not the number: a deadline of two
/// minutes may stand elsewhere (the watchdog has one), but a
/// `grace: Duration::from_mins(...)` is always this grace.
///
/// # What it cannot do
///
/// It reads names and no semantics: whoever sets the number over an intermediate value
/// (`let g = Duration::from_mins(2); ... grace: g`) gets past it. That is the boundary
/// of a source guard, and the alternative would be a parser.
#[test]
fn no_crate_spells_a_lifetime_window_a_second_time() {
    // A name of its own for the root: the neighbour above has the same build-up, and
    // a counter-check whose anchor fits twice does not bite (measured).
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root");

    let mut read = 0_usize;
    let mut doubled = Vec::new();
    let mut open = vec![workspace.join("crates"), workspace.join("xtask")];
    while let Some(dir) = open.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                open.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name == "generated.rs" || name == "pb.rs" {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            read += 1;
            // The production part ends at the first test module: there a fixed time
            // window is precisely the intent.
            let production = source
                .split_once("#[cfg(test)]")
                .map_or(source.as_str(), |(before, _)| before);
            for (at, line) in production.lines().enumerate() {
                let trimmed = line.trim_start();
                // Measured, the filter catches **nothing** today -- no comment
                // quotes such an assignment. It stands there because the same false
                // positive has already hit three other guards of this tree: a doc that
                // names the forbidden case in order to explain it.
                if trimmed.starts_with("//") {
                    continue;
                }
                for field in ["ttl", "rotate_after", "grace"] {
                    if trimmed.starts_with(&format!("{field}:"))
                        && trimmed.contains("Duration::from_")
                    {
                        doubled.push(format!(
                            "{}:{}  {field}",
                            path.strip_prefix(workspace).unwrap_or(&path).display(),
                            at + 1
                        ));
                    }
                }
            }
        }
    }

    // Without this assurance the test would be green even if the search found
    // nothing -- and precisely then it checks nothing.
    assert!(
        read > 50,
        "only {read} source files were read -- the path is wrong"
    );
    assert!(
        doubled.is_empty(),
        "these places write a time window from ADR-0014 down themselves instead \
         of reading the constant -- two sources for one number, and the second is \
         the one that drifts: {doubled:?}"
    );
}
