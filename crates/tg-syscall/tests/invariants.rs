//! The hard invariants from `CLAUDE.md`, as guards instead of promises.
//!
//! Two of them are already checked by something: `cargo deny` stops OpenSSL and
//! `native-tls` (invariant 3) and eBPF and Kubernetes crates (invariant 1), and
//! the `bpf(2)` proof in [`tg_syscall::bpf`] substantiates at runtime that **no**
//! BPF program is loaded.
//!
//! What was missing is the second: `#![forbid(unsafe_code)]` applies in every
//! crate but this one. A *new* crate without the attribute would come to
//! nobody's attention, and then `unsafe` would be permitted there without
//! anything turning red anywhere.
//!
//! The guard stands here because this is the crate of the exception: whoever
//! reads the exception finds the rule beside it.
//!
//! **Here and not in the `xtask`.** Until this step the check existed **twice**
//! — as `cargo xtask guard` and as this test —, and the two versions disagreed
//! about the scope. Two versions of a rule are two opportunities to interpret it
//! differently. What stayed is the one that runs in the **Definition of Done**:
//! `cargo test --workspace` stands in `CLAUDE.md`, `cargo xtask guard` does not.

/// The workspace members, read from the root `Cargo.toml`.
///
/// **Not** by walking `crates/*`: the list there is the truth, and it names
/// `xtask` and `tests/dst` too. Exactly those two were missing in the two
/// predecessor versions of this check.
fn members(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    let list = manifest
        .split_once("members = [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map_or_else(
            || unreachable!("`members` is missing in the root Cargo.toml"),
            |(l, _)| l,
        );

    let mut out = Vec::new();
    for entry in list.split(',') {
        let entry = entry.trim().trim_matches('"');
        if entry.is_empty() {
            continue;
        }
        if let Some(parent) = entry.strip_suffix("/*") {
            let dir = root.join(parent);
            let mut expanded: Vec<_> = std::fs::read_dir(&dir)
                .expect("member directory readable")
                .filter_map(Result::ok)
                .map(|found| found.path())
                .filter(|path| path.join("Cargo.toml").is_file())
                .collect();
            expanded.sort();
            out.extend(expanded);
        } else {
            out.push(root.join(entry));
        }
    }
    out
}

/// A crate's roots: `lib.rs`, `main.rs` and every `src/bin/*.rs`.
///
/// The binaries belong to it because each is a crate root of its **own** — an
/// attribute in `main.rs` does not apply there.
fn roots(krate: &std::path::Path) -> Vec<std::path::PathBuf> {
    let src = krate.join("src");
    let mut out: Vec<_> = ["lib.rs", "main.rs"]
        .into_iter()
        .map(|file| src.join(file))
        .filter(|path| path.is_file())
        .collect();

    if let Ok(entries) = std::fs::read_dir(src.join("bin")) {
        let mut bins: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|found| found.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
            .collect();
        bins.sort();
        out.extend(bins);
    }
    out
}

/// **The trust domain stands once in the tree** (ADR-0006).
///
/// It is the first component of every SPIFFE identifier and has to be the same
/// cluster-wide. As a literal it stood in **four** processes as a default — and
/// the sidecar could not get its own set at all, because the derived command
/// line is fixed (ADR-0059).
///
/// What is checked is the **production part**: in a test module a fixed
/// `"cluster.local"` is exactly the intent. And `tg-identity` is the source.
#[test]
fn the_default_trust_domain_has_one_source() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for found in entries.filter_map(Result::ok) {
            let path = found.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let mut files = Vec::new();
    for member in members(root) {
        if member.to_string_lossy().contains("tg-identity") {
            continue;
        }
        walk(&member.join("src"), &mut files);
    }

    assert!(
        files.len() > 40,
        "only {} source files were found — the guard does not read the tree",
        files.len()
    );

    let mut spelled = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("source file");
        let production = match text.find("#[cfg(test)]") {
            Some(cut) => &text[..cut],
            None => &text[..],
        };
        for (number, line) in production.lines().enumerate() {
            let line = line.trim();
            if !line.starts_with("//") && line.contains("\"cluster.local\"") {
                spelled.push(format!("{}:{}", file.display(), number + 1));
            }
        }
    }

    assert!(
        spelled.is_empty(),
        "these places spell out the trust domain instead of taking \
         `tg_identity::DEFAULT_TRUST_DOMAIN`: {spelled:?}"
    );
}

/// **Every crate but `tg-syscall` forbids `unsafe`** (CLAUDE.md, invariant 2).
///
/// The exception is exactly one and carries its reason in the crate's module
/// header. New `unsafe` outside it is per CLAUDE.md a design error — "an ADR or
/// a rebuild, not an `allow`".
///
/// Checked in three layers, because the guard rail consists of three parts and
/// each is removable on its own: the prohibition in the workspace manifest, the
/// **inheritance** in every crate (`[lints] workspace = true`) and the attribute
/// at every crate root. The compiler notices the absence of `unsafe`; the
/// absence of the guard rail it does not.
#[test]
fn every_crate_but_this_one_forbids_unsafe() {
    /// The crate of the exception.
    const EXEMPT: &str = "tg-syscall";

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root");

    let mut findings = Vec::new();

    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    if !manifest.contains(r#"unsafe_code = "forbid""#) {
        findings.push("Cargo.toml: [workspace.lints.rust] does not forbid `unsafe`".to_owned());
    }

    let members = members(root);
    for krate in &members {
        let name = krate
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let manifest =
            std::fs::read_to_string(krate.join("Cargo.toml")).expect("manifest readable");
        let found = roots(krate);

        // A member **without** a recognizable root is a finding, not a skip. The
        // predecessor version carried on here — and a crate with a different
        // layout (`[lib] path = …`) would thereby have been silently exempt from
        // invariant 2: exactly the case this guard is meant to prevent.
        if found.is_empty() {
            findings.push(format!(
                "{name}: no `src/lib.rs`, `src/main.rs` or `src/bin/*.rs` — \
                 this crate's root is not checked"
            ));
            continue;
        }

        if name == EXEMPT {
            for source in &found {
                let text = std::fs::read_to_string(source).expect("readable");
                assert!(
                    !text.contains("#![forbid(unsafe_code)]"),
                    "{EXEMPT} is the exception — if it forbids `unsafe`, the \
                     entry here belongs away rather than the code there"
                );
            }
            // The exception carries a condition of its own: every `unsafe` block
            // needs a `// SAFETY:`. Without it "exception" would mean "nothing
            // applies here".
            if !manifest.contains("undocumented_unsafe_blocks") {
                findings.push(format!(
                    "{name}/Cargo.toml: the exception crate without \
                     clippy::undocumented_unsafe_blocks"
                ));
            }
            continue;
        }

        // **In the `[lints]` section, not anywhere** — a correction to the
        // version taken over from the `xtask`. It asked
        // `manifest.contains("workspace = true")`, and that is already satisfied
        // by `version.workspace = true` in line 4 of every manifest: the check
        // was empty and would never have found anything.
        let inherits = manifest
            .split_once("\n[lints]")
            .map(|(_, rest)| rest.split("\n[").next().unwrap_or(rest))
            .is_some_and(|section| section.contains("workspace = true"));
        if !inherits {
            findings.push(format!(
                "{name}/Cargo.toml: does not inherit the workspace lints \
                 ([lints] workspace = true missing)"
            ));
        }

        for source in &found {
            let text = std::fs::read_to_string(source).expect("readable");
            if !text.contains("#![forbid(unsafe_code)]") {
                findings.push(format!(
                    "{}: #![forbid(unsafe_code)] missing",
                    source.strip_prefix(root).unwrap_or(source).display()
                ));
            }
        }
    }

    // Without this assertion the test would check nothing as soon as the layout
    // changes: an empty set contains no violations.
    assert!(
        members.len() >= 16,
        "the members were not read: {}",
        members.len()
    );
    assert!(
        members
            .iter()
            .any(|krate| krate.ends_with("xtask") || krate.ends_with("dst")),
        "the members outside crates/ are missing — exactly those were left out \
         by the two predecessor versions"
    );
    assert!(
        findings.is_empty(),
        "without the guard rail `unsafe` is permitted there without anything \
         turning red anywhere (CLAUDE.md, invariant 2): {findings:?}"
    );
}

/// **The bridge from ADR-0026 stays in force.**
///
/// `xsd-parser-types` 0.2.1 pins `quick-xml` **0.38** and thereby drags
/// RUSTSEC-2026-0194 and -0195 into the ingest path — the place at which an
/// operator's document is parsed. The fix lies in 0.41, and the patch in the
/// workspace manifest is one line.
///
/// If the `[patch.crates-io]` falls away, cargo pulls the registry version, and
/// with it the old `quick-xml`. **`cargo deny check sources` does not notice
/// that** — crates.io is permitted. `check advisories` would catch it as long as
/// the two RUSTSEC entries stand in the database; that is the backstop, and it
/// hangs on a foreign database.
///
/// What the guard cannot do: check that the vendored trees' content is right. It
/// checks that the patch **stands there**, points at the vendored trees, and
/// that the pinned `quick-xml` version is 0.41 — the last of the three is the
/// assertion that catches the case nothing else sees: the patch stands there and
/// carries nothing.
#[test]
fn the_xsd_parser_bridge_stays_in_place() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
    assert!(
        manifest.contains("[patch.crates-io]"),
        "the `[patch.crates-io]` from ADR-0026 is gone — then cargo pulls \
         `xsd-parser-types` from the registry, and with it `quick-xml` 0.38 \
         (RUSTSEC-2026-0194, -0195) into the ingest path"
    );

    for krate in ["xsd-parser-types", "xsd-parser"] {
        assert!(
            manifest.contains(&format!("{krate} = {{ path = \"third-party/{krate}\" }}")),
            "the patch for `{krate}` is missing or points somewhere else"
        );
        let vendored = root.join("third-party").join(krate);
        assert!(
            vendored.join("Cargo.toml").is_file(),
            "the vendored tree `{}` is missing — then the patch is a reference \
             into nothing and the build breaks",
            vendored.display()
        );
    }

    // **And the version at issue.** Without this assertion the guard would stay
    // green if somebody reset the vendored tree to 0.38 — then the patch would
    // stand there and carry nothing.
    let vendored = std::fs::read_to_string(root.join("third-party/xsd-parser/Cargo.toml"))
        .expect("vendored manifest");
    let pinned = vendored
        .split("[dependencies.quick-xml]")
        .nth(1)
        .and_then(|rest| rest.lines().find(|line| line.starts_with("version")))
        .expect("the vendored tree has to pin `quick-xml`");
    assert!(
        pinned.contains("0.41"),
        "the vendored tree pins {pinned} — the fix for RUSTSEC-2026-0194 and \
         -0195 lies in 0.41 (ADR-0026)"
    );
}

/// **The overflow check in the release profile stays on (ADR-0082).**
///
/// The panic strategy is guarded by the compiler (`cfg(panic = "abort")`); for
/// the overflow check that does not work, because `cfg(overflow_checks)` is
/// nightly. And it needs a guard more urgently, because the **defaults lie
/// opposite**: in the release profile `overflow-checks` is off by default, so a
/// deleted line switches the check off silently.
///
/// Measured, `1000u64 - 2000u64` without the check yields
/// **18446744073709550616** — a free capacity of 18 exabytes where a deficit of
/// 1000 stands.
#[test]
fn the_release_profile_keeps_overflow_checks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");

    let release = manifest
        .split("[profile.release]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("the release profile");

    assert!(
        release
            .lines()
            .any(|line| line.trim() == "overflow-checks = true"),
        "`overflow-checks` is missing in the release profile — the default \
         there is `false`, so the shipped binary computes silently wrong where \
         the tests see a panic (ADR-0082, determination 2)"
    );

    // **The opposite direction**, and it is half the promise: a profile that
    // carries the line and sets `panic = "abort"` beside it would be green — and
    // precisely then every arithmetic error costs the whole node.
    assert!(
        !release
            .lines()
            .any(|line| line.trim() == "panic = \"abort\""),
        "`panic = \"abort\"` stands in the release profile again — then the \
         overflow check is a trap instead of a backstop (ADR-0082, \
         determination 1)"
    );
}

/// **No panic-capable call on the production path** (ADR-0082).
///
/// The plan measured by hand twice that there are five such places in the whole
/// tree and that all five lie on compile-time constants. That still holds — but
/// it was a **hand count**, and since ADR-0082 a panic no longer costs the
/// process but only its task. It has thereby become **quieter**, not more
/// harmless.
///
/// The guard is therefore the **compiler**: every crate root forbids the four
/// calls for `not(test)`, and an exception carries its reason at the place.
///
/// `clippy::indexing_slicing` and `clippy::unreachable` expressly do **not**
/// stand in the list: measured, the first fires at 18 places the hand audit
/// found checked, the second 66 times in the generated parser. A guard that
/// needs exceptions in that number gets switched off instead of read.
#[test]
fn every_production_root_forbids_panicking_calls() {
    /// The crates of the **development path** (ADR-0023): they are not shipped,
    /// and a harness may use `expect` — there that is exactly the intent.
    const DEV_ONLY: &[&str] = &["xtask", "dst"];

    /// The calls that turn a `None` or `Err` into a panic.
    const LINTS: &[&str] = &[
        "clippy::unwrap_used",
        "clippy::expect_used",
        "clippy::panic",
        "clippy::todo",
    ];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root");

    let mut findings = Vec::new();
    let mut checked = 0_usize;

    for krate in members(root) {
        let name = krate
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if DEV_ONLY.contains(&name.as_str()) {
            continue;
        }

        for source in roots(&krate) {
            checked += 1;
            let text = std::fs::read_to_string(&source).expect("root readable");
            if !text.contains("not(test),") {
                findings.push(format!(
                    "{}: no `cfg_attr(not(test), deny(…))`",
                    source.display()
                ));
                continue;
            }
            for lint in LINTS {
                if !text.contains(lint) {
                    findings.push(format!("{}: {lint} missing", source.display()));
                }
            }
        }
    }

    // A guard that has read nothing confirms everything.
    assert!(
        checked > 10,
        "only {checked} roots checked — the member list was not read"
    );
    assert!(
        findings.is_empty(),
        "these roots permit panic-capable calls on the production path \
         (ADR-0082): {findings:?}"
    );
}

/// **Every fuzz run keeps the conventions that make it one.**
///
/// The repo's test rules demand three things of a fuzz run, and all three are
/// maintained **by hand** across thirteen files:
///
/// 1. **A fresh seed per run.** A hard-wired one turns the run into a static
///    test set.
/// 2. **The iteration count comes from `TG_FUZZ_ITERATIONS`**, so that a local
///    run may be short.
/// 3. **The default is the release threshold** (20 000). A lowered default would
///    run in the gate without anybody seeing it.
///
/// **Searched by content, not by file name.** The first version read
/// `tests/fuzz_*.rs` — and measured, **two** fuzz runs lay in source test
/// modules and were thereby entirely unguarded. The file name remains a promise
/// of its own beside it: a `tests/fuzz_*.rs` **must** name `TG_FUZZ_ITERATIONS`.
///
/// What the guard **cannot** do: say whether a trust boundary has a run. That is
/// a statement about intent, and it has already cost this tree a missing run
/// (`unbase64`).
#[test]
fn every_fuzz_run_keeps_the_conventions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root");
    let mut checked = 0_u32;
    let mut sources = Vec::new();

    for crate_dir in std::fs::read_dir(root.join("crates")).expect("crates readable") {
        let crate_dir = crate_dir.expect("entry").path();
        collect_rust(&crate_dir.join("src"), &mut sources);
        collect_rust(&crate_dir.join("tests"), &mut sources);
    }

    for path in sources {
        let source = std::fs::read_to_string(&path).expect("readable");
        let named = path
            .file_stem()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.starts_with("fuzz_"));
        let shown = path.strip_prefix(root).unwrap_or(&path).display();

        if !source.contains("TG_FUZZ_ITERATIONS") {
            // The other direction: a file that calls itself `fuzz_` and
            // hard-wires the iteration count would otherwise be invisible.
            assert!(
                !named,
                "{shown}: is called `fuzz_` but does not name TG_FUZZ_ITERATIONS"
            );
            continue;
        }

        assert!(
            source.contains("DEFAULT_ITERATIONS: u32 = 20_000"),
            "{shown}: the default is not the release threshold of 20 000"
        );
        assert!(
            source.contains("RandomState::new().build_hasher().finish()"),
            "{shown}: no fresh seed — a fixed one turns the run into a static \
             test set"
        );
        checked += 1;
    }

    // A guard that has read nothing confirms everything.
    assert!(
        checked >= 15,
        "only {checked} fuzz runs found — the guard hardly read anything"
    );
}

/// Collects every `.rs` file under `dir`, recursively.
///
/// Recursively, because source trees have subdirectories
/// (`tg-identity/src/workload_api/`) — a flat run would leave them out.
fn collect_rust(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            collect_rust(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// **No binary reads the hostname from the environment.**
///
/// `$HOSTNAME` is set by the **shell**, and a service under systemd is measured
/// not to get it (`systemd-run --pipe /usr/bin/printenv HOSTNAME` → exit 1). As
/// long as the node name's default hung on it, every node started as a service
/// was called `node` — a name two machines share, while it stands in the URI SAN
/// of the cluster leaf and is bound to an invitation (ADR-0043, ADR-0037).
#[test]
fn no_binary_reads_the_hostname_from_the_environment() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root");
    let mut findings = Vec::new();
    let mut checked = 0_u32;

    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                // Test directories stay out: there a fixed name is exactly the
                // intent.
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }

            let source = std::fs::read_to_string(&path).expect("readable");
            checked += 1;
            if source.contains("var(\"HOSTNAME\")") || source.contains("var_os(\"HOSTNAME\")") {
                findings.push(path.display().to_string());
            }
        }
    }

    assert!(
        checked > 50,
        "only {checked} source files read — the guard hardly read anything"
    );
    assert!(
        findings.is_empty(),
        "these files read the hostname from the environment instead of from the kernel (ADR-0043): {findings:?}"
    );
}

/// **No doc block ends mid-sentence.**
///
/// The witness against a pattern this tree found twenty-eight times by hand — an
/// insertion that takes the **following** element's documentation away from it.
/// Clippy catches the common half (`missing_docs`, when the neighbour afterwards
/// has **no** documentation left); the other half it does not, and the case in
/// `tg_model::keys` showed why: there a doc block was split **across a
/// sentence**. It compiles, `missing_docs` stays silent — for **neither** is
/// missing —, and a reader gets two half sentences.
///
/// Measured, this tree's 5 987 doc blocks end on exactly **four** characters:
/// `.` (5 932), `*` (47, a bold at the end of a line), `?` (5) and `"` (3). The
/// set is therefore kept narrow — a broad one (with `,` and `;`) would let
/// through exactly the lines at issue.
///
/// What it **cannot** do: it sees the form and not the sense. An insertion
/// between two doc blocks that are both complete sentences does not stand out to
/// it.
/// **Every `#[allow]` in production code names its reason.**
///
/// An `allow` switches a check off, and whoever switches one off has to say why
/// — otherwise on the next read it is indistinguishable whether somebody made a
/// trade-off or pushed a warning away.
///
/// The occasion was twofold: **two references to a rationale that did not
/// exist.** `tg_proxy::role` said "the same `allow` as at the SVID beside it",
/// and the neighbouring place carried none; `tg_consensus::command` said "the
/// same trade-off as at `ClusterState::apply`", and there it likewise did not
/// stand. Measured, nine of fourteen carried their reason and five did not.
///
/// A comment **within a window** of four lines counts, or a `reason =`. What the
/// guard **cannot** do: see whether the comment explains the `allow` rather than
/// the element below it. A narrower rule ("immediately above") is measured to be
/// too strict — four of the fourteen legitimately stand in a block whose comment
/// sits above the surrounding expression.
#[test]
fn every_allow_in_production_names_its_reason() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root")
        .to_path_buf();
    let mut files = Vec::new();
    collect_rust(&root.join("crates"), &mut files);
    files.retain(|path| !path.components().any(|part| part.as_os_str() == "tests"));

    // `xtask` expressly does not stand in the haystack, and the reason is
    // measured rather than conventional: **every** `allow` there is text that a
    // generator writes into a product (`codegen.rs` for `generated.rs`,
    // `proto.rs` for `pb.rs`) -- none is its own. The guard cannot tell them
    // apart, so there it carries only false hits.
    let mut without = Vec::new();
    let mut gesehen = 0usize;
    for file in files {
        // Products carry their own `allow` including the rationale in the
        // header, written by a generator (see `cargo xtask codegen`).
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == "generated.rs" || name == "pb.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("source file readable");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("#[cfg(test)]") {
                break;
            }
            let is_allow = line.contains("#[allow(") || line.contains("#![allow(");
            if !is_allow || line.contains("reason =") {
                continue;
            }
            gesehen += 1;
            let window = &lines[i.saturating_sub(4)..i];
            let begruendet = window.iter().any(|l| {
                let t = l.trim();
                t.starts_with("//") && !t.starts_with("///")
            });
            if !begruendet {
                without.push(format!("{}:{}", file.display(), i + 1));
            }
        }
    }

    assert!(
        gesehen > 5,
        "only {gesehen} `allow` were found — the guard does not read"
    );
    assert!(
        without.is_empty(),
        "these `allow` do not name their reason: {without:?}"
    );
}

/// The highest determination number of an ADR — and **which** of the three
/// measured forms delivered it.
///
/// The second half is the actual backstop: a counter-check showed that a count
/// over the *ADRs* does not catch a loss of form. Only two ADRs use the
/// `### Festlegung N` form exclusively, and with the rest its disappearance
/// merely lowers the maximum. It is therefore counted per form.
fn hoechste(text: &str) -> (u32, [bool; 3]) {
    let mut hoch = 0;
    let mut form = [false; 3];
    let mut in_entscheidung = false;
    for line in text.lines() {
        if line.starts_with("## ") {
            in_entscheidung = line.starts_with("## Decision");
        }
        let t = line.trim_start_matches('#').trim_start();
        if let Some(rest) = t.strip_prefix("Determination ")
            && let Some(n) = leading_number(rest)
        {
            hoch = hoch.max(n);
            form[0] = true;
            continue;
        }
        if !in_entscheidung {
            continue;
        }
        // `### N. …` and `N. **…**`
        if let Some(n) = leading_number(t) {
            let after = t
                .trim_start_matches(|c: char| c.is_ascii_digit())
                .trim_start_matches('.');
            let separated = after.starts_with(' ');
            if separated && line.starts_with('#') {
                hoch = hoch.max(n);
                form[1] = true;
            } else if separated && after.trim_start().starts_with("**") {
                hoch = hoch.max(n);
                form[2] = true;
            }
        }
    }
    (hoch, form)
}

/// The leading number of a piece of text.
fn leading_number(text: &str) -> Option<u32> {
    let ziffern: String = text.chars().take_while(char::is_ascii_digit).collect();
    ziffern.parse().ok()
}

/// **Every reference to a determination points at one that exists.**
///
/// The tree refers at around 670 places to "ADR-XXXX, determination N" — per
/// invariant 6 the ADRs are the truth, and a reference to a number that does not
/// exist sends a reader into nothing.
///
/// What is read is the **nearest** ADR to the left of the word — "(ADR-0060,
/// ADR-0091 determination 5)" means 0091. A pattern that takes the first of the
/// line reports false hits.
///
/// **Three forms, measured** — and the list counts only in the "Decision"
/// section, because "Options considered" is numbered too:
///
/// | Form | Example |
/// |---|---|
/// | `### Determination N — …` | ADR-0092 |
/// | `### N. …` | ADR-0105 |
/// | `N. **…**` in a list | ADR-0064 |
///
/// An ADR at which **no** form bites is skipped. It is counted **per form** and
/// not over the ADRs: if one falls away, the guard says which.
#[test]
fn every_reference_to_a_decision_points_at_one() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root")
        .to_path_buf();

    let mut counts = std::collections::BTreeMap::new();
    let mut je_form = [0_usize; 3];
    for adr in std::fs::read_dir(root.join("plans")).expect("plans/ readable") {
        let path = adr.expect("entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.len() < 5 || !name.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let Ok(number) = name[..4].parse::<u32>() else {
            continue;
        };
        let text = std::fs::read_to_string(&path).expect("ADR readable");
        let (hoch, form) = hoechste(&text);
        for (i, gesehen) in form.iter().enumerate() {
            if *gesehen {
                je_form[i] += 1;
            }
        }
        counts.insert(number, hoch);
    }

    // One assertion per form, and that is the lesson of a counter-check: a count
    // over the ADRs does **not** catch a loss of form — it produced 16 false
    // findings, and those would have been read as work.
    for (i, name) in ["### Determination N", "### N.", "N. **…**"]
        .iter()
        .enumerate()
    {
        assert!(
            je_form[i] > 0,
            "not a single ADR delivers the form `{name}` — it has fallen away, \
             and without it the guard produces false findings instead of \
             catching them"
        );
    }

    let recognized = counts.values().filter(|v| **v > 0).count();
    assert!(
        recognized > 60,
        "only {recognized} ADRs with numbered determinations — the guard does not read"
    );

    let mut files = Vec::new();
    collect_rust(&root.join("crates"), &mut files);
    files.push(root.join("docs").join("OPERATIONS.md"));

    let mut ins_leere = Vec::new();
    let mut geprueft = 0usize;
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            let mut search = line;
            let mut offset = 0usize;
            while let Some(pos) = search.find("etermination ") {
                let absolute = offset + pos;
                offset = absolute + "etermination ".len();
                search = &line[offset..];
                let Some(number) = leading_number(&line[offset..]) else {
                    continue;
                };
                // The nearest ADR to the left.
                let Some(last_at) = line[..absolute].rfind("ADR-") else {
                    continue;
                };
                let Some(adr) = leading_number(&line[last_at + 4..]) else {
                    continue;
                };
                let has = counts.get(&adr).copied().unwrap_or(0);
                if has == 0 {
                    continue;
                }
                geprueft += 1;
                if number > has {
                    ins_leere.push(format!(
                        "{}:{} -> ADR-{adr:04} determination {number} (has {has})",
                        file.display(),
                        i + 1
                    ));
                }
            }
        }
    }

    assert!(
        geprueft > 300,
        "only {geprueft} references checked — the guard does not read"
    );
    assert!(
        ins_leere.is_empty(),
        "these references point at a determination that does not exist: {ins_leere:?}"
    );
}

#[test]
fn no_doc_block_ends_mid_sentence() {
    // Terminators that mark a concluded thought. The three bracket-like ones
    // stand for a line ending on a code span or a reference; the pipe for a
    // Markdown table row, for a table is a complete statement and not half a
    // sentence.
    //
    // The set is **measured** and not guessed: this tree's doc blocks end on
    // exactly these characters. It grows when a new legitimate form comes along.
    const TERMINATORS: [char; 8] = ['.', '?', '!', '*', '"', '`', ')', '|'];

    let mut files = Vec::new();
    collect_rust(std::path::Path::new("../../crates"), &mut files);

    let mut checked = 0_usize;
    let mut findings = Vec::new();
    for file in &files {
        // The generated parser and the protobuf stub are not ours.
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        if name == "generated.rs" || name == "pb.rs" {
            continue;
        }

        let text = std::fs::read_to_string(file).expect("readable");
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("///") {
                continue;
            }
            // Only the **last** line of a block counts.
            if lines
                .get(at + 1)
                .is_some_and(|next| next.trim_start().starts_with("///"))
            {
                continue;
            }
            let body = trimmed[3..].trim();
            if body.is_empty() {
                continue;
            }
            // A **link definition** is not a sentence but markup: rustdoc allows
            // `/// [`X`]: path` as a last line. It never ends on punctuation,
            // and the exception is precise — a sentence does not end on
            // `]: path`.
            if body.starts_with('[') && body.contains("]: ") {
                continue;
            }
            checked += 1;
            if !body.ends_with(TERMINATORS) {
                findings.push(format!("{}:{}", file.display(), at + 1));
            }
        }
    }

    // Without this assertion the test would be green even if the search found
    // nothing — and precisely then it checks nothing.
    assert!(
        checked > 3_000,
        "only {checked} doc blocks were read — the path is wrong"
    );
    assert!(
        findings.is_empty(),
        "these doc blocks end mid-sentence — an insertion has split one (see \
         tg_model::keys): {findings:?}"
    );
}

/// **No client message names a path or a value.**
///
/// The repo's house rules demand it expressly — *"Error messages must not leak
/// internals (stack traces, paths, secrets)"* —, and it was never checked. The
/// place where it counts is a `tonic::Status`: it goes to a **foreign** client,
/// and at the credential port (ADR-0043, determination 3) to one that has
/// presented no certificate.
///
/// A path in it betrays the node's data directory, a value the secret itself.
/// Measured there are **none** — paths go into the log, where an operator needs
/// them, and secret values nowhere.
///
/// What it cannot do: it reads a **window of three lines** from a
/// `Status::<name>(`. Whoever interpolates the path four lines further down gets
/// past — the limit of a text guard. And it knows **one** spelling.
#[test]
fn no_client_message_names_a_path_or_a_value() {
    // **One** form, and that is measured. The obvious second pattern — the bare
    // constructor name (`internal(`, `invalid_argument(`) — is a **subset**: of
    // 38 hits 35 lie on a line that already carries `Status::`, and the three
    // remaining are **false hits** on `Submission::internal` (ADR-0050) and its
    // definition. A guard with that hit rate gets switched off instead of read.
    let ist_konstruktor = |l: &str| {
        l.split("Status::").skip(1).any(|r| {
            let name: String = r.chars().take_while(char::is_ascii_alphanumeric).collect();
            !name.is_empty() && r[name.len()..].starts_with('(')
        })
    };
    // What a client must never see: the node's path, and a secret.
    let lecks = [
        "display()",
        "{plaintext}",
        "{token}",
        "{password}",
        "{share}",
        "{spki}",
    ];

    let mut places = 0_usize;
    let mut findings = Vec::new();

    let mut files = Vec::new();
    collect_rust(std::path::Path::new("../../crates"), &mut files);

    for file in &files {
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        // The generated parser and the protobuf stub are not ours.
        if name == "generated.rs" || name == "pb.rs" {
            continue;
        }
        if !file.components().any(|teil| teil.as_os_str() == "src") {
            continue;
        }
        let text = std::fs::read_to_string(file).expect("readable");
        let productive = text
            .split_once("#[cfg(test)]")
            .map_or(text.as_str(), |(before, _)| before);
        let lines: Vec<&str> = productive.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            if !ist_konstruktor(line) {
                continue;
            }
            places += 1;
            let window = lines[line_number..(line_number + 3).min(lines.len())].join("\n");
            if let Some(leck) = lecks.iter().find(|l| window.contains(**l)) {
                findings.push(format!("{}:{}: {leck}", file.display(), line_number + 1));
            }
        }
    }

    // Measured 47. A bound on the measured number would be the trap this tree
    // has already paid for once with a fuzz coverage assertion.
    assert!(
        places > 20,
        "only {places} Status places found — the haystack has fallen away, and \
         without it this guard confirms everything"
    );
    assert!(
        findings.is_empty(),
        "a client message names a path or a value: {findings:?}"
    );
}

/// **No production code branches on an error message.**
///
/// The text of an error belongs to a human, not to a `match`. It often also
/// belongs to **foreign** code, and then the control flow is bound to a wording
/// nobody promised.
///
/// Two findings prompted this guard, and the first was a **defect**:
///
/// - `tgd::Node::initialize` swallowed `err.to_string().contains("already
///   initialized")` — and that string occurs **nowhere** in `openraft` 0.9.25.
///   Measured, a node with `--init` in its unit file did not come back up after
///   a restart.
/// - `tg_net::link` swallowed `EEXIST` via `contains("File exists")` — the
///   `strerror` text, which per specification is locale-dependent.
///
/// Both are switched to their **variant** or their **error code**.
///
/// What it does **not** forbid: the same in **tests** — there the message is
/// precisely the object. And reading the **output** of a foreign program
/// (`nft -j list`) is not an error message but data.
#[test]
fn no_production_code_branches_on_an_error_message() {
    let mut files = Vec::new();
    collect_rust(std::path::Path::new("../../crates"), &mut files);

    let mut checked = 0_usize;
    let mut findings = Vec::new();
    for file in &files {
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        // The generated parser and the protobuf stub are not ours.
        if name == "generated.rs" || name == "pb.rs" {
            continue;
        }
        // Only `src/`: an integration test is all test code.
        if !file.components().any(|part| part.as_os_str() == "src") {
            continue;
        }

        let text = std::fs::read_to_string(file).expect("readable");
        let production = &text[..text.find("#[cfg(test)]").unwrap_or(text.len())];
        checked += 1;
        for (at, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let branches = (trimmed.contains(".to_string()") || trimmed.contains(".message()"))
                && trimmed.contains(".contains(");
            if branches {
                findings.push(format!("{}:{}", file.display(), at + 1));
            }
        }
    }

    // Without this assertion the test would be green even if the search found
    // nothing — and precisely then it checks nothing.
    assert!(
        checked > 40,
        "only {checked} source files were read — the path is wrong"
    );
    assert!(
        findings.is_empty(),
        "these places decide on an error message instead of on its variant (see \
         tgd::Node::initialize): {findings:?}"
    );
}

/// **What a constant names is not spelled out a second time.**
///
/// The general form of a finding this tree has made five times: the sidecar
/// ports, the file names under `network/`, `cluster.local`, the identity layout
/// and the `hint` of the delegated identity. Every time it was **one fact with
/// two sources**, every time both agreed today, and every time a rename would
/// have broken the other side silently.
///
/// All `pub const NAME: &str = "…"` of the production tree are read — measured
/// 127 — and every **other** file that spells the same literal is objected to.
///
/// Three words mean something different in several places, and that is measured:
/// `"identity"` is also a **key kind** (`tg_model::keys`), `"group"` a **signer
/// kind** (`tg_identity::mint`), and `"tardigrade"` stands for the nftables
/// table, a common name, the cgroup roof and the metric prefix.
///
/// **Without exceptions**, and that was once different: `attest.rs` spelled out
/// the container prefix, on the grounds that `tg-identity` hangs on `tg-runtime`
/// only in the dev path. The second half of that was measured to be **wrong**
/// (`tgctl` hangs on both), and the duplication thereby avoidable.
#[test]
fn no_file_spells_what_a_constant_already_names() {
    const AMBIGUOUS: [&str; 3] = ["identity", "group", "tardigrade"];
    const ALLOWED: [(&str, &str); 0] = [];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root")
        .to_path_buf();
    let mut files = Vec::new();
    collect_rust(&root.join("crates"), &mut files);
    collect_rust(&root.join("xtask").join("src"), &mut files);
    files.retain(|path| !path.components().any(|part| part.as_os_str() == "tests"));

    // The production part per file, without comment lines: a doc block quoting a
    // literal is not a second source.
    let mut code = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).expect("readable");
        let body = text
            .find("\n#[cfg(test)]")
            .map_or(text.as_str(), |at| &text[..at]);
        let stripped: String = body
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        code.push((path.clone(), stripped));
    }

    // Split by hand and not with a regex: the form is a line with two fixed
    // separators, and `tg-syscall` gets no edge for it.
    let mut owners: std::collections::BTreeMap<String, (String, std::path::PathBuf)> =
        std::collections::BTreeMap::new();
    for (path, body) in &code {
        for line in body.lines() {
            let Some(rest) = line.trim_start().strip_prefix("pub const ") else {
                continue;
            };
            let Some((name, rest)) = rest.split_once(": &str = \"") else {
                continue;
            };
            let Some((literal, _)) = rest.split_once('"') else {
                continue;
            };
            if literal.len() >= 3 && !AMBIGUOUS.contains(&literal) {
                owners.insert(literal.to_owned(), (name.to_owned(), path.clone()));
            }
        }
    }

    let relative = |path: &std::path::Path| {
        path.strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string()
    };

    let mut offenders = Vec::new();
    for (literal, (name, owner)) in &owners {
        for (path, body) in &code {
            if path == owner {
                continue;
            }
            let here = relative(path);
            if ALLOWED.contains(&(literal.as_str(), here.as_str())) {
                continue;
            }
            if body.contains(&format!("\"{literal}\"")) {
                offenders.push(format!("{here}: \"{literal}\" — take {name}"));
            }
        }
    }

    // Without this assertion the test would be green even if the search found
    // nothing — and precisely then it checks nothing.
    assert!(
        owners.len() > 80,
        "only {} constants were found — the path is wrong",
        owners.len()
    );
    assert!(
        offenders.is_empty(),
        "these places spell out what a constant already names — a fact with two \
         sources diverges eventually, and the second breaks silently: \
         {offenders:?}"
    );
}

/// **Every declared dependency has a consumer.**
///
/// ADR-0023 counts crates: every section of the plan says "zero new crates" or
/// names the number, and the reason is concentration risk and exit strategy. A
/// package in the SBOM that nothing needs is supply chain surface without a
/// return.
///
/// Measured it was **four of 271**, and the first stood on the **production
/// path** (`x509-parser` in `tg-agent`). One of them carried a comment claiming
/// a test that does not exist in that crate.
///
/// The package name is read in its Rust form (`-` becomes `_`) across **all**
/// `.rs` files of the crate, tests and `build.rs` included: what only a witness
/// needs is used.
///
/// What it cannot do: see a dependency that **only** switches on a feature of a
/// transitive package or drags in a native library.
#[test]
fn every_declared_dependency_has_a_consumer() {
    const ALLOWED: [(&str, &str); 0] = [];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let mut manifests: Vec<std::path::PathBuf> = members(root)
        .into_iter()
        .map(|dir| dir.join("Cargo.toml"))
        .collect();
    manifests.retain(|path| path.exists());

    let mut declared = 0_usize;
    let mut offenders = Vec::new();
    for manifest in &manifests {
        let krate = manifest.parent().expect("directory");
        let name = krate
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("name");

        let mut sources = Vec::new();
        collect_rust(krate, &mut sources);
        let body: String = sources
            .iter()
            .map(|path| std::fs::read_to_string(path).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");

        let text = std::fs::read_to_string(manifest).expect("manifest readable");
        let mut section = "";
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                section = trimmed;
                continue;
            }
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if !matches!(
                section,
                "[dependencies]" | "[dev-dependencies]" | "[build-dependencies]"
            ) {
                continue;
            }
            let Some(package) = trimmed.split(['=', '.', ' ']).next() else {
                continue;
            };
            if package.is_empty() || !package.starts_with(|first: char| first.is_ascii_lowercase())
            {
                continue;
            }
            declared += 1;

            let ident = package.replace('-', "_");
            if body.contains(&ident) || ALLOWED.contains(&(name, package)) {
                continue;
            }
            offenders.push(format!("{name} {section}: {package}"));
        }
    }

    // Without this assertion the test would be green even if reading the
    // manifests found nothing — and precisely then it checks nothing.
    assert!(
        declared > 200,
        "only {declared} dependencies were read — the path is wrong"
    );
    assert!(
        offenders.is_empty(),
        "these dependencies are never named by their crate — a package in the \
         SBOM without a consumer is supply chain surface without a return \
         (ADR-0023): {offenders:?}"
    );
}

/// **What the workspace pins, no crate pins a second time.**
///
/// `[workspace.dependencies]` is the one place at which a package's version
/// stands — and for three of them the comment there says expressly why it is
/// **exact**: `openraft`, `redb` and `tonic` belong to the consensus core, and
/// nothing there shall move without the DST suite running over it (ADR-0023,
/// ADR-0032). `frost-ed25519` likewise, with ADR-0014's "no alpha in the crypto
/// core".
///
/// Measured, **nine** declarations bypassed the pin — among them
/// `tonic = "0.14"` in `tgctl`, i.e. a **caret** range on a package the
/// workspace nails to `=0.14.6`.
///
/// The **features** stay local and narrow: `{ workspace = true, features =
/// [...] }` takes the version from above and says on what this crate needs. The
/// switch changed `Cargo.lock` **byte for byte not at all**.
#[test]
fn no_crate_pins_what_the_workspace_already_pins() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    let mut pinned = std::collections::BTreeSet::new();
    let mut inside = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            inside = trimmed == "[workspace.dependencies]";
            continue;
        }
        if !inside || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((package, _)) = trimmed.split_once(" = ") {
            pinned.insert(package.to_owned());
        }
    }

    let mut checked = 0_usize;
    let mut offenders = Vec::new();
    for dir in members(root) {
        let path = dir.join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let name = dir
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("?");
        let mut section = "";
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                section = trimmed;
                continue;
            }
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if !matches!(
                section,
                "[dependencies]" | "[dev-dependencies]" | "[build-dependencies]"
            ) {
                continue;
            }
            let Some((package, spec)) = trimmed.split_once(" = ") else {
                continue;
            };
            if !pinned.contains(package) {
                continue;
            }
            checked += 1;
            if !spec.contains("workspace") {
                offenders.push(format!("{name} {section}: {package} = {spec}"));
            }
        }
    }

    // Without this assertion the test would be green even if neither the pins
    // nor the declarations were found.
    assert!(
        pinned.len() > 8 && checked > 30,
        "{} pins and {checked} declarations were read — the path is wrong",
        pinned.len()
    );
    assert!(
        offenders.is_empty(),
        "these declarations bypass the workspace pin — the version belongs in \
         **one** place (ADR-0023), the features stay local: {offenders:?}"
    );
}

/// **Every enabled `tokio` feature has a consumer.**
///
/// The continuation of [`every_declared_dependency_has_a_consumer`] one level
/// deeper: ADR-0023 counts crates, and a **feature** pulls code into the SBOM
/// without a new package appearing — `signal` brings `mio`'s signal path along,
/// `fs` and `process` the blocking pool.
///
/// Measured it was **two of six crates**: `tg-agent` switched `signal` on and
/// never called `tokio::signal`, and `tg-runtime` switched `fs` on and does not
/// use `tokio::fs`.
///
/// Only features whose use is readable from the **module name**. `rt`,
/// `rt-multi-thread` and `macros` therefore do not stand in the list: they
/// appear in the code as `#[tokio::main]`, `#[tokio::test]` or as a runtime
/// somebody builds. Whoever wants to check them checks them at the build —
/// without them nothing compiles.
#[test]
fn every_enabled_tokio_feature_is_used() {
    /// The features whose use is betrayed by a module path.
    const READABLE: [&str; 6] = ["signal", "fs", "process", "net", "time", "sync"];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let mut checked = 0_usize;
    let mut offenders = Vec::new();
    for krate in members(root) {
        let manifest = krate.join("Cargo.toml");
        if !manifest.exists() {
            continue;
        }
        let name = krate
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("name")
            .to_owned();

        let mut sources = Vec::new();
        collect_rust(&krate, &mut sources);
        let body: String = sources
            .iter()
            .map(|path| std::fs::read_to_string(path).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");

        let text = std::fs::read_to_string(&manifest).expect("manifest readable");
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("tokio ") && !trimmed.starts_with("tokio=") {
                continue;
            }
            for feature in READABLE {
                if !trimmed.contains(&format!("\"{feature}\"")) {
                    continue;
                }
                checked += 1;
                if !body.contains(&format!("tokio::{feature}")) {
                    offenders.push(format!("{name}: {feature}"));
                }
            }
        }
    }

    // Without this assertion the test would be green even if no manifest was
    // read — and precisely then it checks nothing.
    assert!(
        checked > 10,
        "only {checked} feature settings were read — the path is wrong"
    );
    assert!(
        offenders.is_empty(),
        "these features are switched on and never used — a feature pulls code \
         into the SBOM without a package appearing (ADR-0023): {offenders:?}"
    );
}

/// **A crate does not use two libraries for one job.**
///
/// The house rules say it (`.claude/rules/ai_rules_rust.md`: *"One crate per
/// concern: one JSON lib, one HTTP client, one async runtime, one logger"*) and
/// ADR-0023 gives the reason: every library is supply chain surface with an exit
/// strategy of its own.
///
/// Measured, the division in the tree is clean, and the interesting place is
/// **SHA-256**: whoever has `ring` for crypto anyway hashes with it; whoever only
/// has to hash takes `sha2`. Four places use `sha2`, one `ring::digest` — and no
/// crate both.
///
/// `libc`/`nix`/`rustix` expressly do not stand in the groups: they look like a
/// group and are **coverage layers** — `tg-syscall` needs `libc` for `bpf(2)`
/// and `sockaddr_un`, `tg-proxy` `nix` for `IP_ORIGDSTADDR` (ADR-0094), and
/// `rustix` knows neither.
///
/// The groups are **hand-maintained** — which two packages have the same job no
/// tool knows. A forgotten group produces no **false** finding, only a missing
/// one.
#[test]
fn no_crate_uses_two_libraries_for_one_job() {
    const GROUPS: [(&str, &[&str]); 9] = [
        ("sha-256", &["ring", "sha2"]),
        ("http-client", &["reqwest", "ureq", "isahc"]),
        ("json", &["serde_json", "simd-json", "sonic-rs"]),
        ("logging", &["tracing", "log", "slog", "env_logger"]),
        ("tls", &["rustls", "native-tls", "openssl"]),
        ("xml", &["quick-xml", "xml-rs", "roxmltree"]),
        ("date", &["time", "chrono", "jiff"]),
        ("base64", &["base64", "data-encoding", "base64ct"]),
        ("runtime", &["tokio", "async-std", "smol"]),
    ];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let mut read = 0_usize;
    let mut offenders = Vec::new();
    for krate in members(root) {
        let manifest = krate.join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        read += 1;
        let name = krate
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("name");

        let mut declared: Vec<&str> = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') || trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some(package) = trimmed.split(['=', '.', ' ']).next() else {
                continue;
            };
            if package.starts_with(|first: char| first.is_ascii_lowercase()) {
                declared.push(package);
            }
        }

        for (job, members) in GROUPS {
            let both: Vec<&str> = members
                .iter()
                .copied()
                .filter(|package| declared.contains(package))
                .collect();
            if both.len() > 1 {
                offenders.push(format!("{name}: {job} {both:?}"));
            }
        }
    }

    // Without this assertion the test would be green even if no manifest was
    // read — and precisely then it checks nothing.
    assert!(read > 10, "only {read} manifests were read");
    assert!(
        offenders.is_empty(),
        "these crates name two libraries for the same job — each is a supply \
         chain of its own with an exit strategy of its own (ADR-0023): \
         {offenders:?}"
    );
}

/// **The security metrics in the index agree with the code.**
///
/// `plans/README.md` is the index invariant 6 points at, and it names seven
/// numbers from ADR-0014, ADR-0031 and ADR-0064. **None of them was guarded** —
/// whoever reads the "15 min" there and has 30 in the code plans their
/// compromise window wrong.
///
/// The **source text** is read and not the constant: this crate hangs on none of
/// the four in which they lie, and an edge for that would be one for seven
/// numbers.
///
/// What it **cannot** do: check that the number stands at the place the index
/// means. The statement is thereby "the index has not drifted" and not "the
/// number applies".
#[test]
fn the_index_names_the_numbers_the_code_uses() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the root of the tree");
    let index = std::fs::read_to_string(root.join("plans/README.md")).expect("README");

    // (wording in the index, file, wording in the code)
    let pairs: [(&str, &str, &str); 7] = [
        (
            "SVID 15 min",
            "crates/tg-identity/src/lifetime.rs",
            "from_mins(15)",
        ),
        (
            "soft fail 2 min",
            "crates/tg-identity/src/lifetime.rs",
            "from_mins(2)",
        ),
        (
            "revocation ~60 s",
            "crates/tg-proxy/src/policy.rs",
            "from_mins(1)",
        ),
        (
            "agent intermediate 12 h",
            "crates/tg-identity/src/agent.rs",
            "from_hours(12)",
        ),
        (
            "lease 15 s",
            "crates/tg-model/src/lease.rs",
            "LEASE_SECONDS: i64 = 15",
        ),
        (
            "5 seats",
            "crates/tg-identity/src/threshold/group.rs",
            "SEATS: u16 = 5",
        ),
        (
            "t = 3",
            "crates/tg-identity/src/threshold/group.rs",
            "THRESHOLD: u16 = 3",
        ),
    ];

    for (claim, file, expected) in pairs {
        assert!(
            index.contains(claim),
            "plans/README.md no longer names '{claim}' — does the number still \
             stand somewhere, or has it fallen out of the index?"
        );
        let source = std::fs::read_to_string(root.join(file)).expect(file);
        assert!(
            source.contains(expected),
            "the index says '{claim}', but {file} does not contain '{expected}' \
             — one of the two places has drifted (invariant 6)"
        );
    }
}

/// Every binary says **whom** its metrics are about.
///
/// Until this step `to_options` took a `&str` called `node`, and all three
/// binaries filled it — with **three different meanings**: `tgd` with its Raft
/// identifier (`1`), `tg-agent` with the node name (`node-11`) and `tg-proxy`
/// with the **workload** (`journal`). An alarm text `{{ $labels.node }}` thereby
/// named something different per process, while the cardinality rule in
/// `tg_telemetry::names` claims one meaning.
///
/// Since the rebuild the compiler holds that **one** of the two kinds stands
/// there — which one, it does not hold. And the choice is no formality: a
/// sidecar cannot know the node (ADR-0059).
///
/// What it cannot do: it reads the call, not the value behind it. That
/// `Reporter::Node` gets the name and not the identifier at `tgd` is checked by
/// the process witness in `crates/tgd/tests/telemetry.rs`.
#[test]
fn every_binary_names_who_its_metrics_are_about() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let expected = [
        ("crates/tgd/src/main.rs", "Reporter::Node"),
        ("crates/tg-agent/src/main.rs", "Reporter::Node"),
        ("crates/tg-proxy/src/main.rs", "Reporter::Workload"),
    ];

    for (file, want) in expected {
        let source = std::fs::read_to_string(root.join(file)).expect(file);
        let call = source.split_once("to_options(").map_or_else(
            || panic!("{file} does not call `to_options`"),
            |(_, rest)| rest.split(");").next().unwrap_or(rest),
        );
        assert!(
            call.contains(want),
            "{file} has to report `{want}` — if the other kind stands there, an \
             alarm text `{{{{ $labels.node }}}}` names something other than the \
             node (see the header of this test)"
        );
    }
}

/// **Every gRPC channel of this system has two deadlines.**
///
/// `connect_timeout` covers TCP and TLS; whoever sets only it has not covered a
/// peer that **accepts and then stays silent** — there the connection stands and
/// the call waits unbounded.
///
/// The case is measured and was the occasion: the signer port had no request
/// deadline, and its calling thread comes out of `rcgen::SigningKey::sign` — i.e.
/// out of the path on which `tgd` issues an agent intermediate (ADR-0037). A
/// hanging seat thereby blocked one worker per renewal, unbounded.
///
/// **The one exception**: the Raft channel (`tgd/src/cluster.rs`) sets none —
/// there the deadline is `heartbeat_interval`, and `openraft` uses it as the RPC
/// timeout of replication (ADR-0033). A second one beside it would be a second
/// source for the same setting.
///
/// What it cannot do: it reads a window below the construction and no data flow.
#[test]
fn every_grpc_channel_carries_two_deadlines() {
    // By name, with the reason in the header. An exception that points at
    // nothing any more stands out at the assertion below.
    const AUSNAHMEN: &[&str] = &["crates/tgd/src/cluster.rs"];

    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let mut gefunden = 0_usize;
    let mut without = Vec::new();
    let mut genutzte_ausnahmen = Vec::new();
    let mut offen = vec![workspace.join("crates")];
    while let Some(dir) = offen.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                offen.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            let relative = path
                .strip_prefix(workspace)
                .unwrap_or(&path)
                .display()
                .to_string();
            // The production part ends at the first test module.
            let productive = source
                .split_once("#[cfg(test)]")
                .map_or(source.as_str(), |(before, _)| before);
            let lines: Vec<&str> = productive.lines().collect();
            for (at, line) in lines.iter().enumerate() {
                if !line.contains("Endpoint::from_shared")
                    && !line.contains("Endpoint::from_static")
                {
                    continue;
                }
                gefunden += 1;
                // A window of **code** lines and not of lines: a comment can
                // inflate the distance arbitrarily, and in `tg-agent` it does --
                // there twelve lines of rationale lie between the construction
                // and the deadline.
                let window: String = lines[at..]
                    .iter()
                    .filter(|line| {
                        let t = line.trim_start();
                        !t.is_empty() && !t.starts_with("//")
                    })
                    .take(12)
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
                let beide = window.contains("connect_timeout") && window.contains(".timeout(");
                if AUSNAHMEN.contains(&relative.as_str()) {
                    genutzte_ausnahmen.push(relative.clone());
                    continue;
                }
                if !beide {
                    without.push(format!("{relative}:{}", at + 1));
                }
            }
        }
    }

    // Without this assertion the test would be green even if the search found
    // nothing -- and precisely then it checks nothing.
    assert!(
        gefunden >= 4,
        "only {gefunden} channel constructions found -- the path is wrong"
    );
    assert!(
        without.is_empty(),
        "these channels set no request deadline -- a peer that accepts and then \
         stays silent holds its caller unbounded: {without:?}"
    );
    // An exception that covers nothing any more nobody touches again.
    for ausnahme in AUSNAHMEN {
        assert!(
            genutzte_ausnahmen.iter().any(|used| used == ausnahme),
            "the exception '{ausnahme}' points at no channel construction any \
             more -- it belongs away"
        );
    }
}

/// **No failure of an external program is discarded silently.**
///
/// This tree calls five programs (`losetup`, `mkfs.ext4`, `e2fsck`, `resize2fs`,
/// `nft`) and each does something at the **kernel** or the file system — a
/// discarded failure is therefore always one of two things: a resource left
/// behind, or work that was not done. Both stand out without a report only once
/// the disk is full or a container does not start.
///
/// The case is measured: `VolumeStore::mount` detaches its loop device on the
/// error path, and the failure at that was **silent** — twenty lines further
/// down, in the same function, stands verbatim *"what goes wrong here is
/// reported and not silent"*.
///
/// **The exception list is empty.** An informative program call whose result
/// nobody needs does not exist here — every one changes something.
///
/// What is checked is what stands **directly** behind the `let _ =`. A
/// `let _ = tx.send(Command::new(..).output())` discards the send error and not
/// the failure.
#[test]
fn no_external_command_fails_silently() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let mut read_files = 0_usize;
    let mut still = Vec::new();
    let mut offen = vec![workspace.join("crates")];
    while let Some(dir) = offen.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                offen.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            read_files += 1;
            // The production part ends at the first test module: there a
            // discarded failure is the intent (a cleanup in a `Drop`).
            let productive = source
                .split_once("#[cfg(test)]")
                .map_or(source.as_str(), |(before, _)| before);
            for (at, line) in productive.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                // Discarded is only what **is** the program call: with
                // `let _ = tx.send(Command::new(..).output())` the SendError
                // falls away and not the failure -- and that occurs only when
                // the receiver has already given up its deadline.
                let Some(ausdruck) = trimmed.strip_prefix("let _ = ") else {
                    continue;
                };
                if ausdruck.starts_with("run(\"")
                    || ausdruck.starts_with("Command::new")
                    || ausdruck.starts_with("self.run(")
                {
                    still.push(format!(
                        "{}:{}",
                        path.strip_prefix(workspace).unwrap_or(&path).display(),
                        at + 1
                    ));
                }
            }
        }
    }

    // Without this assertion the test would be green even if the search found
    // nothing -- and precisely then it checks nothing.
    assert!(
        read_files > 50,
        "only {read_files} source files were read -- the path is wrong"
    );
    assert!(
        still.is_empty(),
        "these places discard the failure of an external program -- a resource \
         left behind, or work that was not done, and both without a word: \
         {still:?}"
    );
}

/// **An ordering that suggests a rank is a trap.**
///
/// `#[derive(Ord)]` on an enum is the **declaration order**, and that is not a
/// statement. ADR-0109 measured what it costs when there is one: the planner's
/// selection rule hung on the alphabetically first resource.
///
/// This guard holds two halves:
///
/// 1. **Three enums carry no ordering**, because they have no reader —
///    `VolumeMode` (ADR-0027: two cases, no scale), `Schedulability` (phase 6:
///    three states) and `DomainConstraint`. If a derive comes back,
///    `mode > VolumeMode::ReadOnly` becomes compilable, and that means nothing.
/// 2. **Four enums carry one, and it is a sorting** — `Class` (deduplication,
///    ADR-0105), `DependencyKind` (tuple key, ADR-0030) and `Transport` in both
///    crates (determinism of the slice, ADR-0040; deduplicated QUIC ports,
///    ADR-0094). For those it demands that no production code compares them
///    against a **variant literal**.
///
/// What it cannot do: it sees **literals**, not values, and it reads without
/// comment lines — the doc blocks of the four name `class >= Class::Write` as an
/// example, and a guard that objects to its own rationale gets switched off
/// instead of read.
#[test]
fn no_enum_ordering_pretends_to_be_a_rank() {
    /// Without a reader: the derive has to be missing.
    const WITHOUT_READERS: &[(&str, &str)] = &[
        ("crates/tg-defs/src/lib.rs", "VolumeMode"),
        ("crates/tg-model/src/placement.rs", "Schedulability"),
        ("crates/tg-defs/src/lib.rs", "DomainConstraint"),
    ];
    /// With a reader: the derive stays, the comparison against a literal does
    /// not.
    const ORDERING_ONLY: &[&str] = &["Class", "DependencyKind", "Transport"];

    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for found in entries.filter_map(Result::ok) {
            let path = found.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    for (path, name) in WITHOUT_READERS {
        let source = std::fs::read_to_string(root.join(path)).expect("source has to be readable");
        let anchor = format!("pub enum {name} ");
        let Some(i) = source
            .find(&anchor)
            .or_else(|| source.find(&format!("pub struct {name} ")))
        else {
            panic!("{path}: '{name}' no longer exists — the guard points into nothing");
        };
        // The derive block stands immediately before it.
        let head = &source[i.saturating_sub(600)..i];
        let last = head.rfind("#[derive(").map_or("", |d| &head[d..]);
        assert!(
            !last.contains("Ord"),
            "{path}: '{name}' carries an ordering again — it is no rank, and \
             without a reader it is only a trap"
        );
    }

    let mut files = Vec::new();
    for member in members(root) {
        walk(&member.join("src"), &mut files);
    }

    let mut read_files = 0_usize;
    let mut findings: Vec<String> = Vec::new();
    for entry in &files {
        if entry.to_string_lossy().contains("generated.rs")
            || entry.to_string_lossy().contains("pb.rs")
        {
            continue;
        }
        let source = std::fs::read_to_string(entry).expect("source has to be readable");
        let productive = source
            .split_once("#[cfg(test)]")
            .map_or(source.as_str(), |(before, _)| before);
        read_files += 1;
        for (line_number, line) in productive.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            for name in ORDERING_ONLY {
                let pattern = format!("{name}::");
                let mut from = 0;
                while let Some(rel) = trimmed[from..].find(&pattern) {
                    let pos = from + rel;
                    let before_it = trimmed[..pos].trim_end();
                    // `=> Class::X` is an arm, not a comparison.
                    let comparison = (before_it.ends_with('<')
                        || before_it.ends_with('>')
                        || before_it.ends_with("<=")
                        || before_it.ends_with(">="))
                        && !before_it.ends_with("=>");
                    if comparison {
                        findings.push(format!("{}:{} {name}", entry.display(), line_number + 1));
                    }
                    from = pos + pattern.len();
                }
            }
        }
    }
    assert!(read_files > 50, "only {read_files} source files were read");
    assert!(
        findings.is_empty(),
        "an ordering is used as a rank: {findings:?} — it is a sorting \
         (determinism, deduplication) and says nothing about rank"
    );
}

/// **Every network listener notices when the peer disappears**
/// (ADR-0128, determination 1).
///
/// Measured, **one** place in the whole tree set a keepalive — the client in the
/// agent —, and **no** server. A peer that disappears without a `FIN` thereby
/// kept its session open: the server only sends when the log moves, so TCP
/// noticed nothing either. On a **resting** cluster the detection time was
/// unbounded.
///
/// **A guard and not a behaviour test**, because what goes wrong here is an
/// **omission**: somebody adds a fourth listener and writes `Server::builder()`.
/// A behaviour test would check the three that exist; this guard checks the ones
/// still to come.
///
/// The criterion is the **acceptor** and not the file: whoever listens over
/// `cluster::accept` listens on a network. A Unix socket expressly gets none
/// (determination 2) — there is no partition there.
#[test]
fn every_network_listener_notices_a_dead_peer() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root")
        .to_path_buf();

    let mut files = Vec::new();
    for krate in members(&root) {
        collect_rust(&krate.join("src"), &mut files);
    }
    assert!(
        files.len() > 50,
        "only {} files read — then the guard checks nothing",
        files.len()
    );

    let mut nackt = Vec::new();
    let mut gesehen = 0;
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (at, _) in text.match_indices("cluster::accept(") {
            // Only the places at which a server is set up — the module header of
            // `cluster.rs` names the name in prose.
            let before = &text[at.saturating_sub(400)..at];
            if !before.contains("serve_with_incoming") {
                continue;
            }
            gesehen += 1;
            if !before.contains("watched()") {
                nackt.push(format!("{}: {}", file.display(), before.trim_end()));
            }
        }
    }

    assert!(
        gesehen >= 3,
        "fewer than three network listeners found ({gesehen}) — ADR-0043 names \
         three, so this guard reads past its target"
    );
    assert!(
        nackt.is_empty(),
        "these listeners listen on a network and do not notice when the peer \
         disappears (ADR-0128): {nackt:#?}"
    );
}

/// **And the number comes from the same source as at the client**
/// (ADR-0128, determination 1).
///
/// Two sides, one cadence: whoever changes the report period changes both. A
/// copied number would be a second opportunity to differ — and then one side
/// would ping faster than the other gives up.
#[test]
fn both_ends_derive_their_keepalive_from_the_report_cadence() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root")
        .to_path_buf();

    for (file, which) in [
        ("crates/tg-agent/src/cluster.rs", "the client"),
        ("crates/tgd/src/lib.rs", "the server"),
    ] {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|err| panic!("{file}: {err}"));

        // **Without the comments**, and that is no detail: the first attempt at
        // this guard read the whole file and was **green** when the
        // counter-check replaced the number with a copied `5` — the name still
        // stood in the doc comment beside it. A guard that reads a comment
        // checks nothing.
        let code: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            code.contains("REPORT_EVERY_SECONDS"),
            "{which} ({file}) does not derive its keepalive from the report \
             cadence — a copied number is a second opportunity to differ"
        );
    }
}

/// **The self-fence stands before the reaping** (ADR-0129, determination 4).
///
/// What stands before it in the pass goes into the detection latency and has to
/// fit into `FENCE_MARGIN` — three seconds against a grace period of ten.
/// Measured, **one** hanging, no longer wanted container took 10.16 s, and the
/// fence waited for it; that breaks the ordering condition from ADR-0064
/// determination 7, and its violation means literally two writers.
///
/// A comment at the place does not suffice: this tree has measured three times
/// what becomes of an order that only somebody wrote down.
#[test]
fn the_self_fence_stands_before_the_reaping() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root")
        .to_path_buf();

    let file = "crates/tg-runtime/src/reconcile.rs";
    let text =
        std::fs::read_to_string(root.join(file)).unwrap_or_else(|err| panic!("{file}: {err}"));

    // **Without the comments** — the same reason as at the neighbour above: the
    // rationale for the order stands in prose beside it, and a guard that reads
    // a comment checks nothing.
    let code: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let body = code
        .find("pub async fn once(")
        .unwrap_or_else(|| panic!("{file}: `once` not found — the guard reads past it"));

    let fence = code[body..]
        .find("fence_expired(")
        .unwrap_or_else(|| panic!("{file}: `once` does not fence (ADR-0129, determination 1)"));
    let reap = code[body..]
        .find("reap_unless_incomplete(")
        .unwrap_or_else(|| {
            panic!("{file}: `once` does not reap — then this guard reads past its target")
        });

    assert!(
        fence < reap,
        "{file}: the reaping stands before the self-fence (ADR-0129, \
         determination 1). A grace period of ten seconds does not fit into a \
         safety margin of three — ADR-0064 determination 7 would thereby be \
         broken"
    );

    // And the opposite direction: that `fence_expired` exists at all, and as a
    // stage of its own before the start order. A call that stood only in the
    // `start_order` loop would be exactly the situation before this ADR.
    assert!(
        code.contains("async fn fence_expired("),
        "{file}: `fence_expired` is no longer a stage of its own (ADR-0129, \
         determination 1)"
    );
}
