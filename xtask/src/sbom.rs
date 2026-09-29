//! The bill of materials of what is shipped (ADR-0134).
//!
//! **Written ourselves** because ADR-0023 names the SBOM as its first
//! deliverable and, measured, it did not exist — `cargo-cyclonedx` was not even
//! installed. An artifact whose production presupposes a tool nobody has does
//! not arise. The **format** is nevertheless the ecosystem's (`CycloneDX` 1.5):
//! a bill of materials is read by an auditor, not by a tool of ours.
//!
//! **What belongs in it** is the **normal** dependency closure of the four
//! delivery units, for the platform that is built for. Not `cargo metadata`'s
//! full list: that counts development and build dependencies and packages for
//! foreign platforms.
//!
//! **Three filters, not two.** The first two are obvious — platform
//! (`--filter-platform`) and edge kind (`kind: null`). The third was not, and
//! without it the bill named **28** packages too many (387 instead of 359):
//! `cargo metadata` also carries **optional dependencies that no feature
//! activates**. [`activated`] excludes them. Counter-checked against
//! `cargo tree --edges normal` per delivery unit: 359 against 359.
//!
//! Programs that are **called** in operation (`nft`, `losetup`, `cryptsetup`,
//! youki/crun) do not stand in it: they are not linked (ADR-0003, ADR-0038).
//!
//! **Undated:** no `timestamp`, no `serialNumber`, everything sorted — two runs
//! yield the same file. Without that promise `--check` would always be red.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use crate::TaskError;

/// The platform that is shipped for.
///
/// **Explicit and not the host:** otherwise the same tree would yield two bills
/// on two machines, and `--check` would be a statement about the machine instead
/// of about the delivery.
const PLATFORM: &str = "x86_64-unknown-linux-gnu";

/// The delivery units (ADR-0002: three binaries, plus the sidecar).
///
/// **The delivery build reads them too** (`release.rs`, ADR-0138): two lists
/// would be two opportunities for the bill to describe something other than what
/// was built.
pub(crate) const DELIVERED: [&str; 4] = ["tgd", "tg-agent", "tgctl", "tg-proxy"];

/// Where the bill of materials lies.
const PATH: &str = "docs/sbom.cdx.json";

/// The rights holder as it appears in the bill (ADR-0139).
///
/// **Here and not in the `LICENSE`'s appendix:** that is an instruction for
/// whoever applies the licence to a file and not part of the licence (ADR-0139,
/// determination 2). The bill is the answer that goes outwards.
const COPYRIGHT: &str = "Copyright 2026 Dana Schlifka";

/// Writes the bill — or compares it with the checked-in one.
///
/// # Errors
///
/// If `cargo metadata` does not run, its output does not have the expected
/// shape, the file is not writable — or, with `check`, if it deviates from the
/// produced one.
pub(crate) fn run(root: &Path, check: bool) -> Result<(), TaskError> {
    let metadata = metadata()?;
    let document = render(&metadata)?;
    let path = root.join(PATH);

    if !check {
        return std::fs::write(&path, &document).map_err(|source| TaskError::Write {
            path: path.clone(),
            source,
        });
    }

    let found = std::fs::read_to_string(&path).map_err(|source| TaskError::Write {
        path: path.clone(),
        source,
    })?;
    if found == document {
        return Ok(());
    }

    Err(TaskError::Failed {
        step: format!(
            "{PATH} is no longer this tree's bill of materials — \
             `cargo xtask sbom` rewrites it (ADR-0134)"
        ),
    })
}

/// The resolution, filtered to the platform.
fn metadata() -> Result<serde_json::Value, TaskError> {
    let out = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--filter-platform",
            PLATFORM,
        ])
        .output()
        .map_err(|source| TaskError::Spawn {
            program: "cargo metadata".to_owned(),
            source,
        })?;

    if !out.status.success() {
        return Err(TaskError::Failed {
            step: "cargo metadata".to_owned(),
        });
    }

    serde_json::from_slice(&out.stdout).map_err(|err| TaskError::Failed {
        step: format!("cargo metadata is not readable: {err}"),
    })
}

/// A package as it goes into the list.
struct Package {
    name: String,
    version: String,
    license: Option<String>,
    repository: Option<String>,
}

impl Package {
    /// The ecosystem's identifier (`pkg:cargo/<name>@<version>`).
    fn purl(&self) -> String {
        format!("pkg:cargo/{}@{}", self.name, self.version)
    }
}

/// All packages of the resolution, by identifier.
fn catalogue(metadata: &serde_json::Value) -> Result<BTreeMap<&str, Package>, TaskError> {
    let missing = |what: &str| TaskError::Failed {
        step: format!("cargo metadata without {what}"),
    };

    let mut packages: BTreeMap<&str, Package> = BTreeMap::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or_else(|| missing("packages"))?
    {
        let id = package["id"].as_str().ok_or_else(|| missing("id"))?;
        packages.insert(
            id,
            Package {
                name: package["name"]
                    .as_str()
                    .ok_or_else(|| missing("name"))?
                    .to_owned(),
                version: package["version"]
                    .as_str()
                    .ok_or_else(|| missing("version"))?
                    .to_owned(),
                license: package["license"].as_str().map(ToOwned::to_owned),
                repository: package["repository"].as_str().map(ToOwned::to_owned),
            },
        );
    }
    Ok(packages)
}

/// The key names of a package's **optional** normal dependencies, per target
/// package.
///
/// The key is the name under which a feature switches the edge on — i.e. the
/// rename if there is one, otherwise the package name. Both are needed: `serde`
/// under `rename = "serde_crate"` switches on `dep:serde_crate` and is
/// nevertheless called `serde`.
fn optional_deps(package: &serde_json::Value) -> BTreeMap<&str, Vec<&str>> {
    let mut out: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for dep in package["dependencies"].as_array().into_iter().flatten() {
        if !dep["kind"].is_null() || dep["optional"] != serde_json::Value::Bool(true) {
            continue;
        }
        let Some(name) = dep["name"].as_str() else {
            continue;
        };
        let key = dep["rename"].as_str().unwrap_or(name);
        out.entry(name).or_default().push(key);
    }
    out
}

/// Does one of the activated features switch this optional edge on?
///
/// Three forms count, and one expressly does not:
///
/// - the **implicit** feature — it carries the key name itself;
/// - `dep:<key>` in the table of an activated feature;
/// - `<key>/<feature>` there, which switches the edge on as well;
/// - **not** `<key>?/<feature>` — the question mark means precisely "only if
///   somebody else switches it on".
fn activated(
    features: &BTreeSet<&str>,
    table: Option<&serde_json::Map<String, serde_json::Value>>,
    keys: &[&str],
) -> bool {
    keys.iter().any(|key| {
        if features.contains(key) {
            return true;
        }
        let explicit = format!("dep:{key}");
        let through = format!("{key}/");
        features.iter().any(|feature| {
            table
                .and_then(|table| table.get(*feature))
                .and_then(|values| values.as_array())
                .is_some_and(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .any(|value| value == explicit || value.starts_with(&through))
                })
        })
    })
}

/// The **shipped** edges of the resolution.
///
/// Only `kind: null` — `dev` and `build` are not shipped (ADR-0134,
/// determination 3) —, and only what a feature also **switches on**: see the
/// third filter in the module header.
fn normal_edges<'a>(
    metadata: &'a serde_json::Value,
    packages: &BTreeMap<&'a str, Package>,
) -> Result<BTreeMap<&'a str, BTreeSet<&'a str>>, TaskError> {
    let missing = |what: &str| TaskError::Failed {
        step: format!("cargo metadata without {what}"),
    };

    let mut manifests: BTreeMap<&str, &serde_json::Value> = BTreeMap::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or_else(|| missing("packages"))?
    {
        if let Some(id) = package["id"].as_str() {
            manifests.insert(id, package);
        }
    }

    let mut edges: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for node in metadata["resolve"]["nodes"]
        .as_array()
        .ok_or_else(|| missing("resolve.nodes"))?
    {
        let id = node["id"].as_str().ok_or_else(|| missing("node.id"))?;
        let manifest = manifests.get(id);
        let optional = manifest.map(|m| optional_deps(m)).unwrap_or_default();
        let table = manifest.and_then(|m| m["features"].as_object());
        let features: BTreeSet<&str> = node["features"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .collect();

        let mut normal = BTreeSet::new();
        for dep in node["deps"].as_array().ok_or_else(|| missing("deps"))? {
            let is_normal = dep["dep_kinds"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind["kind"].is_null()));
            if !is_normal {
                continue;
            }
            let Some(pkg) = dep["pkg"].as_str() else {
                continue;
            };
            // An edge that stands optional nowhere in the manifest is always
            // there.
            let keys = packages
                .get(pkg)
                .and_then(|package| optional.get(package.name.as_str()));
            if let Some(keys) = keys
                && !activated(&features, table, keys)
            {
                continue;
            }
            normal.insert(pkg);
        }
        edges.insert(id, normal);
    }
    Ok(edges)
}

/// Builds the document.
fn render(metadata: &serde_json::Value) -> Result<String, TaskError> {
    let packages = catalogue(metadata)?;
    let edges = normal_edges(metadata, &packages)?;

    let roots: Vec<&str> = DELIVERED
        .iter()
        .map(|name| {
            packages
                .iter()
                .find(|(_, package)| package.name == *name)
                .map(|(id, _)| *id)
                .ok_or_else(|| TaskError::Failed {
                    step: format!("{name} does not stand in cargo metadata"),
                })
        })
        .collect::<Result<_, _>>()?;

    // The closure over all four — the union is the component list.
    let mut shipped: BTreeSet<&str> = BTreeSet::new();
    let mut stack: Vec<&str> = roots.clone();
    while let Some(current) = stack.pop() {
        if !shipped.insert(current) {
            continue;
        }
        if let Some(deps) = edges.get(current) {
            stack.extend(deps.iter().copied());
        }
    }

    // **Sorted by name and version**, not by the identifier: that carries a
    // path, and a path is a property of the machine.
    let mut ordered: Vec<&Package> = shipped
        .iter()
        .filter_map(|id| packages.get(id))
        .collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
    });

    let components: Vec<serde_json::Value> = ordered.iter().map(|p| component(p)).collect();

    let mut dependencies: Vec<serde_json::Value> = Vec::new();
    for id in &shipped {
        let Some(package) = packages.get(id) else {
            continue;
        };
        let mut on: Vec<String> = edges
            .get(id)
            .into_iter()
            .flatten()
            .filter(|dep| shipped.contains(*dep))
            .filter_map(|dep| packages.get(dep).map(Package::purl))
            .collect();
        on.sort();
        dependencies.push(serde_json::json!({
            "ref": package.purl(),
            "dependsOn": on,
        }));
    }
    dependencies.sort_by(|left, right| left["ref"].as_str().cmp(&right["ref"].as_str()));

    let document = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "tardigrade",
                "copyright": COPYRIGHT,
                "licenses": [{ "expression": "Apache-2.0" }],
                "description": format!(
                    "container orchestrator, shipped for {PLATFORM}: {}",
                    DELIVERED.join(", ")
                ),
            },
        },
        "components": components,
        "dependencies": dependencies,
    });

    let mut text = serde_json::to_string_pretty(&document).map_err(|err| TaskError::Failed {
        step: format!("bill of materials not writable: {err}"),
    })?;
    text.push('\n');
    Ok(text)
}

/// A component in the ecosystem's format.
fn component(package: &Package) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "type": "library",
        "name": package.name,
        "version": package.version,
        "purl": package.purl(),
        "bom-ref": package.purl(),
    });

    // **`NOASSERTION` and not omitted:** a missing entry would leave open
    // whether nobody looked. `cargo deny` checks the same source.
    entry["licenses"] = serde_json::json!([{
        "expression": package.license.clone().unwrap_or_else(|| "NOASSERTION".to_owned()),
    }]);

    if let Some(repository) = &package.repository {
        entry["externalReferences"] = serde_json::json!([{
            "type": "vcs",
            "url": repository,
        }]);
    }

    entry
}

#[cfg(test)]
mod tests {
    use super::{activated, optional_deps};
    use std::collections::BTreeSet;

    /// Builds a package's feature table.
    fn table(entries: &[(&str, &[&str])]) -> serde_json::Map<String, serde_json::Value> {
        entries
            .iter()
            .map(|(name, values)| {
                (
                    (*name).to_owned(),
                    serde_json::Value::Array(
                        values
                            .iter()
                            .map(|v| serde_json::Value::String((*v).to_owned()))
                            .collect(),
                    ),
                )
            })
            .collect()
    }

    fn active<'a>(names: &'a [&'a str]) -> BTreeSet<&'a str> {
        names.iter().copied().collect()
    }

    /// **The case for whose sake the filter exists.**
    ///
    /// `rust_decimal` declares `borsh` as optional, and no activated feature
    /// switches it on. Before ADR-0134's correction it stood in the bill
    /// nevertheless — together with 27 others.
    #[test]
    fn an_optional_dependency_nobody_switched_on_is_not_shipped() {
        let table = table(&[("std", &[]), ("borsh", &["dep:borsh"])]);
        assert!(!activated(
            &active(&["std", "default"]),
            Some(&table),
            &["borsh"]
        ));
    }

    /// The **implicit** feature carries the key name itself.
    #[test]
    fn the_implicit_feature_switches_its_dependency_on() {
        assert!(activated(
            &active(&["serde"]),
            Some(&table(&[])),
            &["serde"]
        ));
    }

    /// `dep:<key>` in an activated feature switches it on.
    #[test]
    fn an_explicit_dep_entry_switches_its_dependency_on() {
        let table = table(&[("json", &["dep:serde_json", "std"])]);
        assert!(activated(&active(&["json"]), Some(&table), &["serde_json"]));
    }

    /// `<key>/<feature>` switches the edge on as well — `?` does not.
    ///
    /// The question mark means precisely "only if somebody else switches it on";
    /// whoever treats both forms alike brings back the packages this filter has
    /// just removed.
    #[test]
    fn a_slash_switches_on_and_a_question_mark_does_not() {
        let hard = table(&[("full", &["serde/derive"])]);
        assert!(activated(&active(&["full"]), Some(&hard), &["serde"]));

        let weak = table(&[("full", &["serde?/derive"])]);
        assert!(!activated(&active(&["full"]), Some(&weak), &["serde"]));
    }

    /// **A feature that is not activated switches nothing on** — even if its
    /// table names the edge.
    #[test]
    fn an_inactive_feature_switches_nothing_on() {
        let table = table(&[("json", &["dep:serde_json"])]);
        assert!(!activated(&active(&["std"]), Some(&table), &["serde_json"]));
    }

    /// Without a feature table only the implicit feature remains.
    #[test]
    fn without_a_table_only_the_implicit_feature_counts() {
        assert!(activated(&active(&["serde"]), None, &["serde"]));
        assert!(!activated(&active(&["std"]), None, &["serde"]));
    }

    /// **The rename is the key, not the package name.**
    ///
    /// `serde` under `rename = "serde_crate"` is switched on with
    /// `dep:serde_crate` and is nevertheless called `serde`; whoever took the
    /// package name would leave out a shipped edge — the more expensive of the
    /// two errors.
    #[test]
    fn a_renamed_dependency_is_keyed_by_its_rename() {
        let manifest = serde_json::json!({
            "dependencies": [{
                "name": "serde",
                "rename": "serde_crate",
                "kind": null,
                "optional": true,
            }],
        });
        let optional = optional_deps(&manifest);
        assert_eq!(
            optional.get("serde").map(Vec::as_slice),
            Some(&["serde_crate"][..])
        );

        let table = table(&[("codec", &["dep:serde_crate"])]);
        assert!(activated(
            &active(&["codec"]),
            Some(&table),
            &["serde_crate"]
        ));
    }

    /// **Only normal and only optional edges** stand in the map.
    ///
    /// A non-optional edge is always shipped and must not come to the vote at
    /// all; `dev` and `build` fall at the edge filter already (ADR-0134,
    /// determination 3).
    #[test]
    fn only_optional_normal_dependencies_are_collected() {
        let manifest = serde_json::json!({
            "dependencies": [
                { "name": "serde",   "kind": null,          "optional": true },
                { "name": "tokio",   "kind": null,          "optional": false },
                { "name": "tempfile","kind": "development", "optional": true },
                { "name": "cc",      "kind": "build",       "optional": true },
            ],
        });
        let optional = optional_deps(&manifest);
        assert_eq!(optional.keys().copied().collect::<Vec<_>>(), vec!["serde"]);
    }
}
