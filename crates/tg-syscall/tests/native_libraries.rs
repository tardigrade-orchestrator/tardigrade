//! **No copyleft over a C library** (ADR-0023, ADR-0038).
//!
//! ADR-0038 records the finding, and it is that ADR's more general lesson:
//!
//! > **`cargo deny` sees no C licences.** The finding outlives this decision:
//! > every future `*-sys` crate can carry copyleft in **invisibly**. What
//! > remains to be decided — as an addition to ADR-0023 — is whether a check on
//! > `links` keys belongs in the pipeline.
//!
//! A crate's licence field describes the **Rust** part. What native code it
//! brings along or links against does not stand there — `nftnl` was MIT and
//! linked `libnftnl` under GPL-2, and exactly on that the nftables path failed.
//! `cargo deny check licenses` would never have seen it.
//!
//! **No ADR of its own.** The substance is long since decided: `deny.toml` says
//! verbatim *"No GPL/AGPL: would infect the orchestrator itself"* (ADR-0023). No
//! decision is changed here, an existing promise is **redeemed**.
//!
//! **`links` and not `*-sys`.** `-sys` is a convention, `links` a **fact**:
//! cargo demands the key from every crate that claims a native library. A crate
//! that binds a C library and does not call itself `-sys` thereby stands out; a
//! `-sys` that links nothing produces no false alarm.
//!
//! It lies here because `tg-syscall` is the lowest crate and already carries the
//! workspace-wide guard over invariant 2. An `xtask` step would be the wrong
//! place: what does not run in `cargo test --workspace` does not run at all for
//! whoever drives the Definition of Done by hand.

/// What claims native libraries today — **checked by hand per entry**.
///
/// The comment names what really stands behind it. Whoever adds an entry has
/// looked up the licence of the **C** side; whoever has not gets a red test
/// instead of a silent copyleft entry in the delivery path.
const CHECKED: &[(&str, &str)] = &[
    // AWS-LC, a BoringSSL descendant. The C code is **bundled**, and the crate's
    // licence field enumerates it expressly: ISC, Apache-2.0, MIT, BSD-3-Clause.
    // Comes over `reqwest` into the image puller.
    (
        "aws-lc-rs",
        "AWS-LC, bundled; ISC/Apache-2.0/MIT/BSD-3-Clause",
    ),
    (
        "aws-lc-sys",
        "AWS-LC, bundled; ISC/Apache-2.0/MIT/BSD-3-Clause",
    ),
    // No native code: `links` serves here as a uniqueness marker so that two
    // versions of the crate do not stand side by side in the tree.
    (
        "prettyplease",
        "no native code; links is a uniqueness marker",
    ),
    ("wasm-bindgen-shared", "no native code; uniqueness marker"),
    // C and assembler, bundled. The crypto provider from invariant 3.

    // zstd, bundled. **Dual-licensed BSD-3-Clause OR GPL-2** — we take the BSD
    // side, and that is why this entry needs a comment: the crate's field
    // (MIT/Apache-2.0) describes **only** the wrapper and says nothing about the
    // GPL option.
    ("ring", "bundled C/asm core; Apache-2.0 AND ISC"),
    (
        "zstd-sys",
        "zstd, bundled; BSD-3-Clause OR GPL-2 — BSD chosen",
    ),
];

/// **Every native library in the tree has been checked by hand.**
///
/// Both directions, and the second is the one that prevents a false alarm: an
/// entry that no longer exists belongs out of the list — otherwise a list of
/// exceptions grows that nobody reads any more.
#[test]
fn every_native_library_has_been_checked() {
    let metadata = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .arg("--manifest-path")
        .arg(manifest())
        .output()
        .expect("cargo metadata has to be startable");
    assert!(
        metadata.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );

    // `--no-deps` gives only our own crates; the foreign crates come from the
    // full run below. The first call is the counter-check that `cargo metadata`
    // runs here at all — it is cheap and says immediately if the tool is
    // missing.
    let full = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest())
        .output()
        .expect("cargo metadata has to be startable");
    let text = String::from_utf8_lossy(&full.stdout);

    let linked = links_of(&text);
    assert!(
        linked.len() >= 4,
        "the dependency graph was not read: {linked:?}"
    );

    let unchecked: Vec<&String> = linked
        .iter()
        .filter(|name| !CHECKED.iter().any(|(known, _)| known == name))
        .collect();
    assert!(
        unchecked.is_empty(),
        "a crate claims a native library and is not checked: \
         {unchecked:?}\n\nA crate's licence field describes the Rust part; \
         `cargo deny` does not see the C side (ADR-0038). Whoever adds the \
         entry has looked it up — copyleft is excluded per ADR-0023."
    );

    let gone: Vec<&str> = CHECKED
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !linked.iter().any(|linked| linked == name))
        .collect();
    assert!(
        gone.is_empty(),
        "these entries no longer claim a native library and belong out of the \
         list: {gone:?} — otherwise a list of exceptions grows that nobody \
         reads any more"
    );
}

/// The path to the root `Cargo.toml`.
fn manifest() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crates/<crate>/")
        .join("Cargo.toml")
}

/// The names of all crates with a `links` key.
///
/// **With `serde_json` and not by hand**: the first attempt searched backwards
/// from a `"links"` for the next `"name"` — and found the name of the **target**
/// (`build-script-build`), not that of the package.
fn links_of(json: &str) -> Vec<String> {
    let parsed: serde_json::Value = serde_json::from_str(json).expect("cargo metadata is JSON");
    let mut found: Vec<String> = parsed["packages"]
        .as_array()
        .expect("packages is a list")
        .iter()
        .filter(|package| !package["links"].is_null())
        .filter_map(|package| package["name"].as_str().map(str::to_owned))
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}
