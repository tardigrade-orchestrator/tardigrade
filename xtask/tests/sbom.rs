//! What stands in the bill of materials — and what does not (ADR-0134).
//!
//! What is checked is the **checked-in** file. Whether it still matches the tree
//! is said by `cargo xtask sbom --check` in the gate (determination 5); here
//! stand the statements it has to make about itself.

use std::collections::{BTreeMap, BTreeSet};

fn document() -> serde_json::Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("root")
        .join("docs/sbom.cdx.json");
    let text = std::fs::read_to_string(&root)
        .unwrap_or_else(|err| panic!("{}: {err} — `cargo xtask sbom` writes it", root.display()));
    serde_json::from_str(&text).expect("the bill of materials is not JSON")
}

/// What is reachable from `root`.
fn reach<'a>(edges: &BTreeMap<&'a str, Vec<&'a str>>, root: &'a str) -> BTreeSet<&'a str> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if !seen.insert(current) {
            continue;
        }
        stack.extend(edges.get(current).into_iter().flatten().copied());
    }
    seen
}

fn components(document: &serde_json::Value) -> Vec<&serde_json::Value> {
    document["components"]
        .as_array()
        .expect("components")
        .iter()
        .collect()
}

/// **Every component names identifier, version and licence.**
///
/// `NOASSERTION` stays permitted as a *form* and is expressly not the same as a
/// missing entry: a missing one would leave open whether anybody looked. That
/// **no** component carries it today is recorded by the witness beside it
/// (ADR-0139).
#[test]
fn every_component_carries_a_purl_and_a_licence() {
    let document = document();
    let components = components(&document);

    assert!(
        components.len() > 200,
        "only {} components — then the list is not this tree's closure",
        components.len()
    );

    for component in components {
        let name = component["name"].as_str().expect("name");
        let version = component["version"].as_str().expect("version");
        assert_eq!(
            component["purl"].as_str(),
            Some(format!("pkg:cargo/{name}@{version}").as_str()),
            "{name}: the ecosystem's identifier is missing or does not match"
        );
        assert!(
            component["licenses"][0]["expression"].is_string(),
            "{name}: no licence field"
        );
    }
}

/// **What is not shipped does not stand in it** (determination 3).
///
/// The cases differ, and the last was added afterwards:
///
/// - `xsd-parser` hangs only on `xtask`, `tempfile` only on tests, `protox` on
///   both — they fall at the **edge filter** (`dev`/`build`);
/// - `borsh` and `rkyv` are **optional dependencies of `rust_decimal` that no
///   feature switches on**. They fall only at the third filter, and until its
///   correction they stood in the list together with 26 others. They are the
///   heavier case: an auditor recognizes a `dev` package by its name, a
///   non-activated optional one they do not.
///
/// Measured, the difference between the platform-filtered resolution and the
/// delivery closure is **74 packages** (433 against 359) — a list that names too
/// much looks like care.
#[test]
fn development_only_crates_are_absent() {
    let document = document();
    let names: BTreeSet<&str> = components(&document)
        .iter()
        .filter_map(|component| component["name"].as_str())
        .collect();

    for entwicklung in ["xsd-parser", "protox", "tempfile", "xtask", "tg-dst"] {
        assert!(
            !names.contains(entwicklung),
            "{entwicklung} is not shipped and stands in the bill of materials \
             nevertheless"
        );
    }

    // **The third filter, pinned to concrete names.** Without it the bill reads
    // as if this system linked a serialization it never built.
    for ungeschaltet in ["borsh", "rkyv", "bitvec", "ahash", "toml_edit"] {
        assert!(
            !names.contains(ungeschaltet),
            "{ungeschaltet} is an optional dependency no feature switches on — \
             it is not built and does not belong in the bill of materials \
             (ADR-0134)"
        );
    }

    // The counter-check: what **really** is shipped stands in it. Without it the
    // test would be green with an empty list too.
    for geliefert in ["tokio", "rustls", "openraft", "redb", "tgd", "tg-proxy"] {
        assert!(
            names.contains(geliefert),
            "{geliefert} is missing — then the list is not this tree's closure"
        );
    }
}

/// **The graph answers "what is in `tgd`".**
///
/// And the first finding it delivered stands there as an assertion: `tgctl`
/// carries **more** than `tgd`. The reason has changed — it was the consensus
/// core (ADR-0134), today it is `tg-runtime` (ADR-0135) —, the state has not.
#[test]
fn the_graph_answers_what_is_in_each_binary() {
    let document = document();
    let edges: BTreeMap<&str, Vec<&str>> = document["dependencies"]
        .as_array()
        .expect("dependencies")
        .iter()
        .map(|entry| {
            (
                entry["ref"].as_str().expect("ref"),
                entry["dependsOn"]
                    .as_array()
                    .expect("dependsOn")
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect(),
            )
        })
        .collect();

    let tgd = reach(&edges, "pkg:cargo/tgd@0.1.0");
    let tgctl = reach(&edges, "pkg:cargo/tgctl@0.1.0");
    let proxy = reach(&edges, "pkg:cargo/tg-proxy@0.1.0");

    assert!(
        tgd.len() > 100 && proxy.len() > 100,
        "the closures are empty: tgd {} / tg-proxy {}",
        tgd.len(),
        proxy.len()
    );
    assert!(
        proxy.len() < tgd.len(),
        "the sidecar carries more than the control plane: {} against {}",
        proxy.len(),
        tgd.len()
    );
    // **And the other way round, because the number below it was wrong.**
    // ADR-0134 found `tgctl` with 369 crates against `tgd`'s 311; ADR-0137 took
    // the consensus core out and turned the assertion around. Measured, it held
    // only because the bill carried 28 packages too many that inflated `tgd`
    // more than `tgctl`.
    //
    // The reason stands in ADR-0135 and is **not fixed**: `tgctl` has two
    // capabilities, and ADR-0137 removed only the first. The second -- reconcile
    // locally -- links `tg-runtime` and thereby the image puller, `zstd`, `tar`
    // and `aws-lc-rs`.
    assert!(
        tgctl.len() > tgd.len(),
        "the CLI no longer carries more than the control plane ({} against \
         {}) — if that was deliberate, the assertion belongs turned around \
         (ADR-0135)",
        tgctl.len(),
        tgd.len()
    );
    for kern in ["pkg:cargo/redb@", "pkg:cargo/openraft@"] {
        assert!(
            !tgctl.iter().any(|purl| purl.starts_with(kern)),
            "`{kern}…` is back in the CLI — a client links no store it can only \
             read under an exclusive lock (ADR-0137)"
        );
    }
}

/// **No component is unlicensed** (ADR-0139).
///
/// Until ADR-0139 **fifteen** carried the value `NOASSERTION`, and they were our
/// own: the workspace manifest named no licence. An auditor reads that as a
/// finding — at the place they look first.
///
/// The witness checks the **artifact** and not the manifest: the bill is the
/// answer that goes outwards. For foreign crates `cargo deny check licenses`
/// covers it anyway; our own only this one sees.
#[test]
fn no_delivered_component_is_unlicensed() {
    let document = document();
    let unlicensed: Vec<&str> = components(&document)
        .into_iter()
        .filter(|component| component["licenses"][0]["expression"] == "NOASSERTION")
        .filter_map(|component| component["name"].as_str())
        .collect();

    assert!(
        unlicensed.is_empty(),
        "without a licence field: {} — `license.workspace = true` is missing in \
         the manifest (ADR-0139)",
        unlicensed.join(", ")
    );
}

/// **The licence text lies alongside** (ADR-0139).
///
/// A field in the manifest is an identifier, not a text. Apache-2.0 demands that
/// every distribution contain a copy of the licence (§4a) — the file is the
/// fulfilment of that obligation and not ornament.
#[test]
fn the_licence_text_lies_in_the_root() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("root");
    let text = std::fs::read_to_string(root.join("LICENSE")).expect("LICENSE in the root");

    assert!(
        text.contains("Apache License") && text.contains("Version 2.0, January 2004"),
        "LICENSE is not the Apache-2.0 text"
    );
    // An abridged version is no copy of the licence.
    assert!(
        text.lines().count() > 150,
        "LICENSE has only {} lines — that is not the whole text",
        text.lines().count()
    );
}

/// **The bill names the product's licence and rights holder** (ADR-0139).
///
/// Not only the suppliers': the question "whose is this, and under what
/// conditions do I get it" stands **above** the list, not in it. Until here the
/// document answered it for 372 foreign components and not at all for the
/// product itself.
#[test]
fn the_document_names_the_product_licence_and_its_holder() {
    let document = document();
    let component = &document["metadata"]["component"];

    assert_eq!(
        component["licenses"][0]["expression"].as_str(),
        Some("Apache-2.0"),
        "the bill of materials does not name the product's licence"
    );

    let copyright = component["copyright"]
        .as_str()
        .expect("no rights holder in the bill of materials");
    assert!(
        copyright.starts_with("Copyright ") && copyright.len() > "Copyright ".len() + 4,
        "the rights holder is none: {copyright:?}"
    );
}

/// **The root repeats what the bill names — verbatim** (ADR-0139).
///
/// From here on the rights holder stands in three places: in the bill, in
/// `COPYRIGHT` and in `README.md`. Three places are three opportunities to
/// diverge. The bill stays the source (it arises from a constant); this witness
/// binds the other two to it.
#[test]
fn the_root_files_repeat_what_the_document_names() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("root");
    let document = document();
    let holder = document["metadata"]["component"]["copyright"]
        .as_str()
        .expect("rights holder");

    for name in ["COPYRIGHT", "README.md"] {
        let text =
            std::fs::read_to_string(root.join(name)).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert!(
            text.contains(holder),
            "{name} does not name `{holder}` — the bill of materials is the \
             source (ADR-0139)"
        );
        assert!(
            text.contains("Apache"),
            "{name} does not name the product's licence"
        );
    }
}
