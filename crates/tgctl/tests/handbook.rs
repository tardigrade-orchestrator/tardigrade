//! The operations manual names only commands that exist.
//!
//! # Why this exists
//!
//! A manual with wrong commands is worse than none — it costs an operator time
//! in operation and afterwards the trust in everything else that stands in it.
//! The same rule as at overtaken comments in the code, which this tree has
//! withdrawn several times.
//!
//! And the occasion is measured: `--node-session` was a **required** switch no
//! usage help named. What stands only in the code is lost in operation; what
//! stands in the manual and is no longer right is worse.
//!
//! What is checked is the direction that can go stale: every `tgctl`
//! subcommand the operator documents name must occur in the usage help. The
//! other direction — every capability stands in the manual — is no promise: the
//! manual is a selection.
//!
//! **One guard of this family lives elsewhere.** The definitions the manual
//! shows are checked in `crates/tg-model/tests/handbook_xml.rs` — against the
//! schema *and* the domain rules, which are that crate's, and from a crate
//! that builds without `tg-syscall`. The reasons stand there.

/// The subcommands `docs/OPERATIONS.md` names all exist.
///
/// The document is read at compile time (`include_str!`); a test that looks for
/// a file at run time hangs on the working directory.
///
/// # Two blindnesses, both measured
///
/// The guard was green for `tgctl cluster volume delete` — a command that
/// **never** existed; the manual named it at two places, and an operator
/// following it gets "unknown cluster subcommand". It slipped through because
/// `usage.contains("cluster volume")` is true as long as `cluster volumes`
/// stands in the overview. The same blindness the flag guard beside it and the
/// verb guard in `main.rs` have already withdrawn: compared is the **word**,
/// not the substring.
///
/// And only the **first** call per line was read (`split(…).nth(1)`). A table
/// row names two of them regularly — `cluster registry <host> <secret>` and
/// `cluster registry rm <host>` stand in one cell —, and the second half was
/// believed unchecked.
///
/// # Boundary
///
/// What is checked stays the **name**, not the form of the arguments. That
/// direction has no guard, and it has gone stale twice: `allow-egress` was
/// documented without the transport (ADR-0092), `cluster restart` without its
/// generation. Both are caught by reading, not by this test.
#[test]
fn the_handbook_only_names_commands_that_exist() {
    let usage = tgctl_usage();
    let documents = operator_text();

    let mut seen = 0_usize;
    for line in documents.lines() {
        for (at, _) in line.match_indices("tgctl ") {
            let rest = &line[at + "tgctl ".len()..];
            // The first word is the verb group, the second the subcommand.
            let mut words = rest.split_whitespace();
            let (Some(head), tail) = (words.next(), words.next()) else {
                continue;
            };
            let head = head.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
            if head.is_empty() {
                continue;
            }

            // `cluster`/`node` carry their subcommand behind them — and it can
            // have several forms with `|` in the help (`allow|revoke`), in the
            // manual likewise. Every form is therefore checked individually.
            let candidates: Vec<String> = match (head, tail) {
                // In a Markdown table the separator stands as `\|` — the
                // backslash does not belong to the name.
                ("cluster" | "node", Some(sub)) => sub
                    .replace('\\', "")
                    .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '|')
                    .split('|')
                    .filter(|part| !part.is_empty())
                    .map(|part| format!("{head} {part}"))
                    .collect(),
                _ => vec![head.to_owned()],
            };

            for candidate in candidates {
                assert!(
                    names_the_command(&usage, &candidate),
                    "the operator documents name `tgctl {candidate}` — the usage help does not"
                );
                seen += 1;
            }
        }
    }

    // Without this assurance the test would be green even if the reading found
    // nothing — and then it checks nothing.
    assert!(seen >= 15, "only {seen} commands found in the manual");
}

/// Does the usage help name this command — **as a word**?
///
/// A longer neighbour must not vouch for it: `cluster volumes` says nothing
/// about `cluster volume`. The same comparison as at the switches.
fn names_the_command(usage: &str, candidate: &str) -> bool {
    usage.match_indices(candidate).any(|(at, _)| {
        usage[at + candidate.len()..]
            .chars()
            .next()
            .is_none_or(|next| !next.is_ascii_alphanumeric() && next != '-')
    })
}

/// The usage help as an operator sees it.
fn tgctl_usage() -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tgctl"))
        .arg("help")
        .output()
        .expect("tgctl is startable");

    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// **And every switch the operator documents name exists.**
///
/// They describe not only `tgctl` but also the commissioning of `tgd` and
/// `tg-agent` — 21 switches. Without this assurance exactly the lines an
/// operator types at the first build would rot.
///
/// **The sources are read, not the processes.** `CARGO_BIN_EXE_tgd` does not
/// exist in `tgctl`'s tests — the variable knows only the package the binary
/// belongs to (the same reason for which the test rig in `cluster.rs` provides
/// its admin service itself). A guessed path would rely on somebody having run
/// `cargo build --workspace` beforehand.
#[test]
fn the_handbook_only_names_flags_that_exist() {
    let handbook = operator_text();

    // The help texts of **all four** binaries. `tgctl` comes from the running
    // program — that one exists here —, the others from their source.
    let mut help = tgctl_usage();
    help.push_str(include_str!("../../tgd/src/options.rs"));
    help.push_str(include_str!("../../tg-agent/src/main.rs"));
    // `tg-proxy` was missing here. That was no gap but a **false warning in
    // waiting**: as soon as the manual names a sidecar switch —
    // `--single-writer` switches on the enforcement from ADR-0066 —, this test
    // would have gone red with the message "no binary knows it", while one
    // knows it.
    help.push_str(include_str!("../../tg-proxy/src/options.rs"));
    help.push_str(include_str!("../../tg-proxy/src/main.rs"));
    // No binary explains the telemetry switches itself.
    help.push_str(include_str!("../../tg-telemetry/src/args.rs"));
    // **And the switches of the dev tasks** (ADR-0134): the manual names
    // `cargo xtask sbom --check`, and `--check` belongs to no binary. Without
    // this source the guard would be red for a switch that very much exists —
    // and the obvious remedy would have been to take it out of the manual.
    help.push_str(include_str!("../../../xtask/src/main.rs"));
    // And the delivery build (ADR-0138): the manual names
    // `--remap-path-prefix`, and that belongs to `rustc`. Without this source
    // the guard would be red for a switch the build actually sets.
    help.push_str(include_str!("../../../xtask/src/release.rs"));

    let mut seen = 0_usize;
    let mut rest = handbook.as_str();
    while let Some(start) = rest.find("--") {
        rest = &rest[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_lowercase() && c != '-')
            .unwrap_or(rest.len());
        let flag = &rest[..end];
        rest = &rest[end.max(1)..];

        if flag.len() > 4 && !flag.ends_with('-') {
            // **At the word boundary**, not as a substring. `contains` alone
            // let `--node` through because `--node-listen` exists — a renamed
            // switch would thereby stay unnoticed as long as a longer one with
            // the same beginning remains.
            let known = help.match_indices(flag).any(|(at, _)| {
                help[at + flag.len()..]
                    .chars()
                    .next()
                    .is_none_or(|next| !next.is_ascii_alphanumeric() && next != '-')
            });
            assert!(
                known,
                "the operator documents name `{flag}` — no binary knows it"
            );
            seen += 1;
        }
    }

    // Without this assurance the test would be green even if the search found
    // nothing — and then it checks nothing.
    assert!(seen >= 20, "only {seen} switches found in the manual");
}

/// **The ADR table names every ADR there is — and none that does not exist.**
///
/// `plans/README.md` carries the decisions; the table is **hand-maintained** and
/// is added to by hand at every new ADR. That is exactly the shape this tree
/// has already measured three times as a source of error (`KINDS`, `samples()`,
/// `invariants.rs`) — and here it weighs more than usual: per invariant 6 the
/// ADRs are the **truth**, and the table is their index. An ADR that is missing
/// from it is one nobody reads next time.
///
/// The counter-direction is here **no** selection, unlike at the manual: an
/// entry without a file promises a decision nobody can read up. The one
/// exception carries its reason in the table itself.
#[test]
fn the_adr_table_and_the_files_agree() {
    // ADR-0021 has no file of its own — the README carries it as "covered in
    // 0011". The exception stands here by name so that a **second** does not
    // come along silently.
    const WITHOUT_FILE: [&str; 1] = ["0021"];

    let plans = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root")
        .join("plans");
    let readme = std::fs::read_to_string(plans.join("README.md")).expect("README readable");

    let mut files: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&plans).expect("plans/ readable") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|ext| ext != "md") {
            continue;
        }
        let Some(number) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.split('-').next())
        else {
            continue;
        };
        if number.len() == 4 && number != "0000" && number.parse::<u16>().is_ok() {
            files.push(number.to_owned());
        }
    }
    files.sort_unstable();

    // Without this assurance the test would check nothing as soon as the
    // layout changes: an empty set is contained in every table.
    assert!(files.len() >= 60, "the ADRs were not read: {}", files.len());

    let numbers = |text: &str| -> Vec<String> {
        text.lines()
            .filter_map(|line| line.strip_prefix("| "))
            .filter_map(|rest| rest.split_once(' '))
            .map(|(number, _)| number.to_owned())
            .filter(|number| number.len() == 4 && number.chars().all(|c| c.is_ascii_digit()))
            .collect()
    };

    // **The backlog is the index, not "any line"** — and that is a correction
    // to this test. It collected lines from the **whole** document, so an entry
    // in the decision log sufficed. Measured, ADR-0071 was missing from the
    // backlog, and the test was green: only there stands the **status**, and
    // only there does a reader see what is decided.
    let in_backlog = numbers(backlog_of(&readme));
    let listed = numbers(&readme);

    // And the backlog itself must have been read: an empty table contains no
    // name, but it would also contain no violation if the section boundary is
    // called something else one day.
    assert!(
        in_backlog.len() >= 60,
        "the backlog was not read: {}",
        in_backlog.len()
    );

    for number in &files {
        assert!(
            in_backlog.contains(number),
            "ADR-{number} does not stand in the decision backlog of \
             plans/README.md — only there does it carry a status"
        );
    }
    for number in &listed {
        assert!(
            files.contains(number) || WITHOUT_FILE.contains(&number.as_str()),
            "the table names ADR-{number}, but there is no file for it"
        );
    }
}

/// The decision backlog of `plans/README.md` — the section that carries the
/// status.
///
/// Not "any line of the document": the decision log below it names numbers
/// too, and an entry there would otherwise vouch for a missing backlog row.
fn backlog_of(readme: &str) -> &str {
    readme
        .split_once("## Decision backlog")
        .map(|(_, rest)| rest)
        .expect("the backlog section is missing")
        .split_once("\n## ")
        .map_or_else(
            || unreachable!("the backlog never ends"),
            |(table, _)| table,
        )
}

/// **And it lists each of them once, in the shape of its table.**
///
/// # The occasion
///
/// Measured, ten ADRs stood in the backlog **twice** — 0078 to 0081, 0083 to
/// 0086, 0097 and 0104 — and nine of them once with a **four-column** row in a
/// three-column table. Such a row does not fail anywhere: Markdown renders it,
/// and the column that should carry the status carries a rationale instead. So
/// the index showed for those ADRs no status at all, and nobody saw it.
///
/// The heavier half is the duplication itself. Of the two rows for ADR-0097 one
/// carried the decision that ADR's own text withdraws — the seat as a setting,
/// while it stands in the share. Two rows for one decision are two places to
/// maintain, and the one nobody updates is the one somebody reads.
///
/// The guard above could not see either: it asks whether a number stands in the
/// table, and a number that stands there twice stands there. The same blindness
/// as the substring comparison at the commands.
#[test]
fn the_backlog_lists_every_adr_once_and_in_its_shape() {
    let readme = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("root")
            .join("plans/README.md"),
    )
    .expect("README readable");

    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut rows = 0_usize;

    for line in backlog_of(&readme).lines() {
        let Some(row) = line.strip_prefix('|') else {
            continue;
        };
        let cells: Vec<&str> = row.trim_end().trim_end_matches('|').split('|').collect();
        let number = cells.first().map(|cell| cell.trim()).unwrap_or_default();
        if number.len() != 4 || !number.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        rows += 1;
        assert_eq!(
            cells.len(),
            3,
            "the backlog row of ADR-{number} has {} columns, the table has three \
             — the status then stands in no column a reader looks at",
            cells.len()
        );
        assert!(
            seen.insert(number.to_owned()),
            "ADR-{number} stands in the decision backlog more than once — \
             two rows for one decision are two places to maintain"
        );
    }

    // Without this the test would be green on an empty section, and then it
    // checks nothing.
    assert!(rows >= 60, "the backlog was not read: {rows} rows");
}

/// **Every ADR carries its status where the dossier reads it.**
///
/// `plans/dossier.py` counts the statuses for the cover sheet via
/// `^- **Status:** …` and puts everything that does not fit into a bucket
/// "unknown". Measured, exactly that happened: ADR-0075 came with
/// `Status: accepted` instead of `- **Status:** accepted`, and the cover sheet
/// reported "1 unknown" — a number nobody reads as an error.
///
/// That is the same case as the table above, only one level deeper: the ADRs
/// are the truth (invariant 6), and an ADR whose status a tool cannot read is
/// one whose status nobody reads.
///
/// # Boundary
///
/// What is checked is the **form**, not the choice: whether `accepted` is right
/// is decided by the ADR and not by this test. Permitted are the five values
/// `dossier.py` sorts — a sixth would be a decision about the process
/// (ADR-0001) and does not belong in a commit.
#[test]
fn every_adr_carries_a_status_the_dossier_can_read() {
    const ALLOWED: [&str; 5] = [
        "accepted",
        "proposed",
        "superseded",
        "rejected",
        "deprecated",
    ];

    let plans = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root")
        .join("plans");

    let mut checked = 0_usize;
    for entry in std::fs::read_dir(&plans).expect("plans/ readable") {
        let path = entry.expect("entry").path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        // The template carries a placeholder and no status.
        if path.extension().is_none_or(|ext| ext != "md") || name == "0000-template.md" {
            continue;
        }
        if name.len() < 4 || name[..4].parse::<u16>().is_err() {
            continue;
        }

        let text = std::fs::read_to_string(&path).expect("ADR readable");
        let status = text
            .lines()
            .find_map(|line| line.strip_prefix("- **Status:** "))
            .unwrap_or_else(|| {
                panic!(
                    "{name} carries no line `- **Status:** …` — the dossier \
                     counts it as unknown, and nobody reads that as an error"
                )
            })
            .trim()
            .to_owned();

        let word = status.split_whitespace().next().unwrap_or_default();
        assert!(
            ALLOWED.contains(&word),
            "{name} carries the status `{word}`, which `dossier.py` does not \
             sort — permitted are {ALLOWED:?}"
        );
        checked += 1;
    }

    // Without this assurance the test would be green even if it had found no
    // file — the finding from the mutation rig.
    assert!(checked >= 60, "the ADRs were not read: {checked}");
}

/// **The manual names only alert rules that exist.**
///
/// The same gap as at commands, switches, paths and metrics — and it had
/// **two** hits when it was first measured: a rule name with a typo
/// (`TardigradeDataKeysDiverge` instead of `…LaufenAuseinander`) and one that
/// named a rule that **never** existed (`TardigradeActiveRoleMissing`; it is
/// called `TardigradeSingleWriterWithoutActiveRole`). The second had stood
/// there since the gauge-expiry step. An operator who looks for it during an
/// incident finds nothing and takes it for their own mistake.
///
/// The counter-direction is expressly **no** promise: not every rule belongs in
/// the manual. There stand the ones whose cause needs an explanation.
///
/// **The classes and transports in the manual are accepted by the parser.**
///
/// Both are words an operator **types** — `--class read,write` (ADR-0105) and
/// `allow-egress s3.test:443/quic` (ADR-0092) —, and both arise from an enum.
/// If a variant is renamed, the manual stands there wrongly, and the error
/// shows up at the call: "unknown class".
///
/// The same family as the seven guards beside it (commands, switches, paths,
/// metrics, alert names, numbers) — and the last kind of typeable setting that
/// had none.
///
/// It is checked against the **parser** and not against a list: `Class::name`
/// and `Transport::parse` are the truth, and a list in the test would be the
/// shape this tree has measured four times as a source of error.
///
/// **The counter-direction is a promise here**, unlike at the subcommands:
/// there are exactly five classes, they **are** the authorization, and an
/// undocumented one is one nobody uses. At the transports the same applies —
/// three, and the third came with ADR-0092.
#[test]
fn the_handbook_only_names_classes_and_transports_that_exist() {
    let handbook = include_str!("../../../docs/OPERATIONS.md");

    // What an operator types: the values after `--class` in a `tgctl` line. The
    // prose ("`--class` is mandatory") stays out, otherwise "is" would be a
    // class name.
    let mut named: Vec<String> = Vec::new();
    for line in handbook.lines() {
        let t = line.trim();
        // Only command lines: the comment above carries prose ("`--class` is
        // mandatory"), and "is" is no class name.
        if !t.starts_with("tgctl") {
            continue;
        }
        if let Some(rest) = t.split("--class ").nth(1) {
            let values = rest.split_whitespace().next().unwrap_or_default();
            named.extend(
                values
                    .split(',')
                    .map(str::trim)
                    .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
                    .map(str::to_owned),
            );
        }
    }

    let known: Vec<&str> = tg_model::command::Class::ALL
        .iter()
        .map(|c| c.name())
        .collect();
    assert!(
        !named.is_empty(),
        "no `--class` values found in the manual — the guard does not read"
    );
    let unknown: Vec<&String> = named
        .iter()
        .filter(|w| !known.contains(&w.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "the parser does not know these classes: {unknown:?} (known: {known:?})"
    );

    // And every class belongs documented -- the table names it in the first
    // column.
    let undocumented: Vec<&&str> = known
        .iter()
        .filter(|name| !handbook.contains(&format!("| `{name}` |")))
        .collect();
    assert!(
        undocumented.is_empty(),
        "the manual does not name these classes: {undocumented:?}"
    );

    // The transports: the suffix behind the port, as `allow-egress` takes it.
    let mut transports: Vec<String> = Vec::new();
    for line in handbook.lines() {
        let mut rest = line;
        while let Some(i) = rest.find(':') {
            rest = &rest[i + 1..];
            let (digits, after) = rest.split_at(
                rest.find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(rest.len()),
            );
            if digits.is_empty() || !after.starts_with('/') {
                continue;
            }
            let word: String = after[1..]
                .chars()
                .take_while(char::is_ascii_alphabetic)
                .collect();
            if !word.is_empty() {
                transports.push(word);
            }
        }
    }
    assert!(
        !transports.is_empty(),
        "no `:<port>/<transport>` found in the manual — the guard does not read"
    );
    let wrong: Vec<&String> = transports
        .iter()
        .filter(|w| tg_model::egress::Transport::parse(w).is_none())
        .collect();
    assert!(
        wrong.is_empty(),
        "the parser does not know these transports: {wrong:?}"
    );
}

#[test]
fn the_handbook_only_names_alerts_that_exist() {
    let handbook = include_str!("../../../docs/OPERATIONS.md");
    let rules = include_str!("../../../docs/alerts.yml");

    let mut named = 0_usize;
    let mut missing: Vec<String> = Vec::new();

    for word in handbook.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
        if !word.starts_with("Tardigrade") || word.len() < 12 {
            continue;
        }
        named += 1;
        if !rules.contains(&format!("alert: {word}")) {
            missing.push(word.to_owned());
        }
    }

    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "the manual names alert rules that do not exist in docs/alerts.yml: \
         {missing:?}"
    );

    // **And the guard must have read.** Without this assurance a run that finds
    // no name -- a renamed prefix, a rearranged manual --, would be just as
    // green and would confirm everything.
    //
    // The bound is **measured**, not guessed: the manual names five occurrences
    // today (four different rules). Setting it at the measured value would be
    // the same error as a fuzz threshold at the expected value -- a deleted
    // mention would make the test red without anything being wrong.
    assert!(
        named >= 3,
        "only {named} alert rules were found in the manual — the guard \
         evidently does not read what it is supposed to check"
    );
}

/// **Every entry of a usage text carries a description.**
///
/// # The occasion
///
/// `tgctl cluster signer-refresh` carried the text of `cluster secret rekey`
/// — the description had slipped one entry down — and `secret rekey` stood
/// there **bare**. An operator would have run a share refresh believing they
/// were re-keying secrets.
///
/// The wrong text is not findable by a rule: no test knows what a command
/// does. The **hole** it leaves behind is findable, and measured it was the
/// only trace. Across all four usage texts no description occurs twice, every
/// documented default matches the code, and every ADR reference fits its
/// ADR's subject — the gap at `secret rekey` was the one signal there was.
///
/// So what is guarded here is not the correctness of a text but the shape in
/// which this error hides.
///
/// # What is not an entry
///
/// A line ending in `[...]` is the synopsis at the head of an overview
/// (`tgd --id <n> --listen <address> … [...]`). It names the shape of a call,
/// not a setting, and has nothing to describe. The marker is enough: an entry
/// with real arguments ends in its last one (`[--helper ...]`), not in the
/// bare ellipsis.
#[test]
fn every_usage_entry_carries_a_description() {
    // The overview of each binary, without its tail: `USAGE_TAIL` carries
    // prose, and prose has no columns.
    let texts: [(&str, &str, &str); 4] = [
        ("tgctl", include_str!("../src/main.rs"), "const USAGE:"),
        (
            "tgd",
            include_str!("../../tgd/src/options.rs"),
            "pub const USAGE:",
        ),
        (
            "tg-agent",
            include_str!("../../tg-agent/src/main.rs"),
            "const USAGE:",
        ),
        (
            "tg-proxy",
            include_str!("../../tg-proxy/src/main.rs"),
            "const USAGE:",
        ),
    ];

    // The column at which a description begins in all four overviews.
    const COLUMN: usize = 28;

    let mut bare: Vec<String> = Vec::new();
    let mut checked = 0_usize;

    for (program, source, marker) in texts {
        let from = source.find(marker).expect("the overview");
        let to = source[from..].find("\n\";").expect("its end") + from;
        let lines: Vec<&str> = source[from..to].lines().collect();

        for (at, line) in lines.iter().enumerate() {
            // An entry begins at column two; everything else is a heading,
            // a continuation or prose.
            if !line.starts_with("  ") || line.starts_with("   ") || line.len() < 3 {
                continue;
            }
            if line.trim_end().ends_with("[...]") {
                continue;
            }

            let chars: Vec<char> = line.chars().collect();
            let same_line = chars.len() > COLUMN
                && chars[COLUMN - 1] == ' '
                && chars[COLUMN..].iter().any(|c| !c.is_whitespace());
            let continued = lines.get(at + 1).is_some_and(|next| {
                next.strip_prefix(&" ".repeat(20))
                    .is_some_and(|rest| !rest.trim().is_empty())
            });

            checked += 1;
            if !same_line && !continued {
                bare.push(format!("{program}: {}", line.trim()));
            }
        }
    }

    assert!(
        bare.is_empty(),
        "these entries stand in a usage text without a description — that is \
         the hole a slipped text leaves: {bare:#?}"
    );

    // Without this the test would be green on an empty reading. Below the
    // measured 127, for the same reason as everywhere.
    assert!(
        checked >= 100,
        "only {checked} entries were read — the guard evidently does not read \
         what it is supposed to check"
    );
}

/// **The command reference leaves nothing out.**
///
/// # Why this one is the other way round
///
/// Every guard above checks one direction: the manual names nothing that does
/// not exist. The counter-direction is expressly **no** promise there — the
/// manual is a selection, and a guard that demanded completeness of it would
/// force every switch into a document that explains rather than lists.
///
/// `docs/COMMANDS.md` makes the opposite promise, in its first sentence. A
/// reference that silently lacks a switch is worse than no reference: whoever
/// looks something up and does not find it concludes it does not exist.
///
/// # What counts as the truth
///
/// The **parsers**, not the usage texts. A switch a binary accepts and no help
/// names would otherwise stay missing from both, and that is exactly the case
/// this tree has already measured (`--node-session` was required and named
/// nowhere). Read is the source up to `#[cfg(test)]`: behind it stand
/// `--whatever` and `--h`, which are argument errors under test and no
/// settings.
///
/// For the commands the usage help is the source, and that is consistent: it
/// is itself guarded against the dispatch (`the_usage_names_every_verb` in
/// `crates/tgctl/src/main.rs`).
#[test]
fn the_command_reference_leaves_nothing_out() {
    let reference = include_str!("../../../docs/COMMANDS.md");

    // Every source that parses switches, grouped only so that a failure says
    // **which** program the missing one belongs to.
    let programs: [(&str, &[&str]); 5] = [
        (
            "tgctl",
            &[
                include_str!("../../tgctl/src/main.rs"),
                include_str!("../../tgctl/src/cluster.rs"),
                include_str!("../../tgctl/src/node.rs"),
                include_str!("../../tgctl/src/audit.rs"),
                include_str!("../../tgctl/src/signer.rs"),
            ],
        ),
        ("tgd", &[include_str!("../../tgd/src/options.rs")]),
        ("tg-agent", &[include_str!("../../tg-agent/src/main.rs")]),
        ("tg-proxy", &[include_str!("../../tg-proxy/src/options.rs")]),
        (
            "telemetry",
            &[include_str!("../../tg-telemetry/src/args.rs")],
        ),
    ];

    let mut missing: Vec<String> = Vec::new();
    let mut checked = 0_usize;

    for (program, sources) in programs {
        for source in sources {
            // Behind the test module the argument **errors** stand.
            let code = source.split("#[cfg(test)]").next().unwrap_or(source);
            let mut rest = code;
            while let Some(at) = rest.find("\"--") {
                rest = &rest[at + 1..];
                let Some(end) = rest.find('"') else {
                    break;
                };
                let flag = &rest[..end];
                rest = &rest[end..];
                // The same predicate as at the sibling guard in
                // `crates/tgctl/src/main.rs` (every flag stands in the
                // overview): `len() > 2` keeps the bare `"--"` out, which is
                // the separator and no setting.
                if flag.len() <= 2
                    || !flag[2..]
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '-')
                    || flag == "--help"
                {
                    continue;
                }
                checked += 1;
                if !tg_telemetry::args::mentions_word(reference, flag) {
                    missing.push(format!("{program}: {flag}"));
                }
            }
        }
    }

    // And every command the overview names.
    for line in tgctl_usage().lines() {
        let Some(rest) = line.strip_prefix("  tgctl ") else {
            continue;
        };
        let mut words = rest.split_whitespace();
        let Some(verb) = words.next() else {
            continue;
        };
        if !verb.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            continue;
        }
        // `cluster` and `node` carry their subcommand behind them; a `<name>`
        // behind the verb is an argument and not one.
        let call = match words.next() {
            Some(sub)
                if matches!(verb, "cluster" | "node" | "operator" | "secret" | "signer")
                    && sub.chars().all(|c| c.is_ascii_lowercase() || c == '-') =>
            {
                format!("tgctl {verb} {sub}")
            }
            _ => format!("tgctl {verb}"),
        };
        checked += 1;
        if !reference.contains(&call) {
            missing.push(format!("command: {call}"));
        }
    }

    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "docs/COMMANDS.md promises completeness and leaves these out: {missing:#?}"
    );

    // Without this the test would be green on an empty reading. The bound lies
    // below the measured 136 (85 switches, 51 calls), for the same reason as
    // everywhere: a withdrawn switch must not turn it red.
    assert!(
        checked >= 100,
        "only {checked} settings were read — the guard evidently does not \
         read what it is supposed to check"
    );
}

/// **And the ADRs and the journal name only rules that exist.**
///
/// The guard above reads the manual — and that was the smaller half. Per
/// invariant 6 the ADRs are the **truth**, and the journal is where one looks
/// up what was measured; a wrong rule name there is wrong at the source, and
/// the manual is written from it.
///
/// Measured before this test: `TardigradeActiveRoleMissing` stood in ADR-0088
/// and in `plans/README.md` — a rule that never existed. The manual had been
/// corrected for that very name once; the ADR the sentence comes from had not.
/// That is the copy this guard stops.
///
/// # What must be allowed to stay
///
/// A journal that records a finding has to be able to **name** the wrong name.
/// Naming it is a different thing from carrying it, and no reading tells the
/// two apart — so the exception stands here by name, as at the transient file
/// names. Measured, one place in 31 791 lines needs it.
///
/// # Why only the prefixed names
///
/// One table in the journal writes the rules **without** the `Tardigrade`
/// prefix. This guard does not see those, and the alternative would be to
/// check every CamelCase word in a prose document against a list of rules —
/// that produces noise, and a guard that produces noise is switched off. The
/// gap is named rather than papered over: it cost one finding
/// (`RetiredKeyStillThere` instead of `…Present`), found by reading.
#[test]
fn the_adrs_and_the_journal_name_only_alerts_that_exist() {
    /// Named in order to be explained, not used.
    ///
    /// The journal reports under "And two rule names in the manual that did
    /// not exist" that this one never existed, and names the real rule
    /// (`TardigradeSingleWriterWithoutActiveRole`) in the same sentence.
    /// Removing it would remove the finding.
    const NAMED_AS_WRONG: &[&str] = &["TardigradeActiveRoleMissing"];

    let rules = include_str!("../../../docs/alerts.yml");
    let plans = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("plans");

    // The ADRs and, one level down, the build journal — via the directory, so
    // that next year's file carries without anybody adding anything here (the
    // same reason as at the file-reference guard).
    let mut documents: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![plans];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                documents.push(path);
            }
        }
    }

    let mut named = 0_usize;
    let mut missing: Vec<String> = Vec::new();
    for path in &documents {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for word in text.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if !word.starts_with("Tardigrade") || word.len() < 12 {
                continue;
            }
            named += 1;
            if !rules.contains(&format!("alert: {word}")) && !NAMED_AS_WRONG.contains(&word) {
                missing.push(format!("{word} ({})", path.display()));
            }
        }
    }

    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "plans/ names alert rules that do not exist in docs/alerts.yml: {missing:?}"
    );

    // **And the guard must have read.** The bound is below the measured 34, for
    // the same reason as at the manual: a deleted mention must not turn it red.
    assert!(
        named >= 20,
        "only {named} alert rules were found under plans/ — the guard \
         evidently does not read what it is supposed to check"
    );
    assert!(
        documents.len() >= 100,
        "the ADRs were not read: {} documents",
        documents.len()
    );
}

/// The **metrics** the manual names all exist.
///
/// # Why that weighs more than a wrong command
///
/// A command that does not exist speaks up: `tgctl` says "unknown" and names
/// the list. A metric that does not exist **does not speak up** — Prometheus
/// knows no error for an unknown name, a rule on it is simply always wrong. An
/// operator has then written an alert rule that looks written and never fires.
///
/// The occasion is measured and was exactly this case: the manual named
/// `tg_identity_intermediate_expires_at` and `tg_proxy_svid_expires_at` —
/// **without** the suffix `_timestamp_seconds` the names carry in the code. And
/// it hit the two on which the most hangs: if the agent intermediate expires,
/// **all** the node's workloads lose their identity at the same time
/// (ADR-0014).
///
/// It is checked against `tg_telemetry::names` — the **one** source in which
/// the cardinality rule also stands (11b). It is read as source text, like the
/// usage help beside it: constants cannot be enumerated, and a second list in
/// the test would be the shape this tree has measured four times as a source of
/// error.
///
/// The counter-direction is **no** promise: not every metric belongs in the
/// manual. There stand the ones an alert rule belongs on.
#[test]
fn the_handbook_only_names_metrics_that_exist() {
    let handbook = include_str!("../../../docs/OPERATIONS.md");
    let names = include_str!("../../tg-telemetry/src/names.rs");

    let mut seen = 0_usize;
    for (start, _) in handbook.match_indices("tg_") {
        let rest = &handbook[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        let (name, after) = (&rest[..end], &rest[end..]);

        // **A Rust path is no metric.** `tg_model::lease` begins the same
        // way, and a guard that produces false hits is switched off instead of
        // read.
        //
        // **And a glob form is none.** The manual names the families
        // (`tg_node_*`, `tg_cluster_*`), and out of those the loop reads
        // `tg_node_` -- a metric never ends in `_`, so the criterion is exact
        // and not an exception.
        if after.starts_with("::") || name.len() <= 3 || name.ends_with('_') {
            continue;
        }
        seen += 1;
        assert!(
            names.contains(&format!("\"{name}\"")),
            "the manual names the metric '{name}', and tg_telemetry::names \
             does not know it"
        );
    }

    // Without this assurance a run that finds no name — a rearranged manual, a
    // prefix change —, would be just as green and would confirm everything.
    assert!(
        seen >= 20,
        "only {seen} metrics found in the manual — the search no longer takes hold"
    );
}

/// Every rule on a **leader-owned** metric carries the join it needs.
///
/// # The rule, mechanically
///
/// `tg_node_*`, `tg_cluster_*` and `tg_scheduler_domain_*` are set only by the
/// leader — and one that has stepped down keeps its series for up to **15
/// minutes** (ADR-0088), frozen. The head of `docs/alerts.yml` writes from
/// that: join with `and on(instance) (tg_raft_leader == 1)` if the rule
/// **aggregates** over instances or its `for:` duration lies **below** the
/// expiry window.
///
/// **Which metrics are leader-owned is read and not enumerated**:
/// `tgd::scheduler` and `tgd::session` run only on the leader, so leader-owned
/// is what is set there. A list in the test would be the shape this tree has
/// measured four times as a source of error — and it would fall behind at the
/// next addition.
///
/// At exactly 15 minutes **without** aggregation the join is not demanded: the
/// frozen series then disappears at the end of the deadline, and a condition
/// that must hold throughout no longer comes into play.
#[test]
fn every_rule_on_a_leader_metric_scopes_to_the_leader() {
    // Leader-owned is what is set in these two modules.
    let leader_only: Vec<String> = [
        include_str!("../../tgd/src/scheduler.rs"),
        include_str!("../../tgd/src/session.rs"),
    ]
    .iter()
    .flat_map(|source| {
        source
            .match_indices("names::")
            .map(|(at, _)| &source[at + "names::".len()..])
            .map(|rest| {
                rest.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("")
                    .to_owned()
            })
            .collect::<Vec<_>>()
    })
    .filter(|name| !name.is_empty())
    .collect();
    assert!(
        leader_only.len() >= 5,
        "only {} leader-owned metrics were found",
        leader_only.len()
    );

    // Translate the constant names into their metric names.
    let names = include_str!("../../tg-telemetry/src/names.rs");
    let metrics: Vec<String> = leader_only
        .iter()
        .filter_map(|constant| {
            let at = names.find(&format!("pub const {constant}: &str = \""))?;
            let rest = &names[at..];
            let open = rest.find('"')? + 1;
            let close = rest[open..].find('"')? + open;
            Some(rest[open..close].to_owned())
        })
        .collect();
    assert!(
        metrics.len() >= 5,
        "the translation found only {} names: {metrics:?}",
        metrics.len()
    );

    let rules = include_str!("../../../docs/alerts.yml");
    let mut checked = 0_usize;
    for block in rules.split("- alert: ").skip(1) {
        let name = block.lines().next().unwrap_or("").trim();
        let body: String = block
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        let Some(seconds) = for_seconds(&body) else {
            continue;
        };
        if !metrics.iter().any(|metric| body.contains(metric.as_str())) {
            continue;
        }
        checked += 1;

        let aggregates = body.contains("sum by") || body.contains("sum(");
        if seconds >= 15 * 60 && !aggregates {
            continue;
        }
        assert!(
            body.contains("tg_raft_leader"),
            "'{name}' reads a leader-owned metric with for={seconds}s \
             (aggregates: {aggregates}) and does not restrict to the current \
             leader -- after a leader change it fires on the frozen series of \
             the one that stepped down (ADR-0088)"
        );
    }
    assert!(
        checked >= 4,
        "only {checked} rules on leader-owned metrics were checked"
    );
}

/// `for: 90s` / `5m` / `1h` / `24h` in Sekunden.
fn for_seconds(body: &str) -> Option<u64> {
    let at = body.find("for: ")? + "for: ".len();
    let text = body[at..].split_whitespace().next()?;
    let (digits, unit) = text.split_at(text.len().checked_sub(1)?);
    let value: u64 = digits.parse().ok()?;
    let factor = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };
    Some(value * factor)
}

/// The **alert rules** name only metrics that exist — and no form of
/// expression that cannot compute.
///
/// # Why that weighs more than the manual
///
/// A rule in `docs/alerts.yml` is not read but **loaded**. A name that does not
/// exist makes it a rule that never fires, and Prometheus reports nothing about
/// it — the same silent kind of failure the three truncated names in the manual
/// had.
///
/// To that comes the **form**: `tg_raft_rpc_seconds` is a summary with
/// `quantile` labels and not a histogram with buckets — measured against a real
/// `render()` of the exporter. `histogram_quantile` needs `le`; on our metrics
/// it would be an expression that never has a result. Exactly that stood in the
/// manual, and exactly that this test nails down.
#[test]
fn the_alert_rules_only_name_metrics_that_exist() {
    let rules = include_str!("../../../docs/alerts.yml");
    let names = include_str!("../../tg-telemetry/src/names.rs");

    // **Without comment lines**, and that is the third case of this kind in
    // this tree: the file head **explains** the metric families, and a glob form
    // like `tg_node_*` is no name. Without the filter the guard objected to the
    // rationale for whose sake it is there -- and a guard that produces false
    // hits is switched off instead of read.
    //
    // It is not weakened by that: the names that matter stand in `expr:` lines,
    // and those are no comments.
    let rules: String = rules
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let rules = rules.as_str();

    let mut seen = 0_usize;
    for (start, _) in rules.match_indices("tg_") {
        let rest = &rules[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        let name = &rest[..end];
        // A glob form is no metric: one never ends in `_`.
        if name.len() <= 3 || name.ends_with('_') {
            continue;
        }
        seen += 1;
        assert!(
            names.contains(&format!("\"{name}\"")),
            "the alert rules name '{name}', and tg_telemetry::names does not know it"
        );
    }
    assert!(
        seen >= 20,
        "only {seen} metrics found in the alert rules — the search no longer takes hold"
    );

    // **Only the expressions, not the explanation.** The file head names
    // `histogram_quantile` in order to say why it does not stand there — a
    // guard that objects to its own rationale produces false hits and is
    // switched off.
    for line in rules
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
    {
        assert!(
            !line.contains("histogram_quantile"),
            "`histogram_quantile` needs `le` buckets; the exporter renders a \
             summary with `quantile` labels (measured) — the rule never fired: {line}"
        );
    }

    // And every rule carries what a rule must carry. Without this assurance a
    // file with one `alert:` and nothing else would be green.
    //
    // It is counted again without the comments: the file head explains where
    // the `for:` durations come from, and would otherwise count along.
    let body: Vec<&str> = rules
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();
    let count = |needle: &str| {
        body.iter()
            .filter(|line| line.trim_start().starts_with(needle))
            .count()
    };
    let alerts = count("- alert:");
    assert!(alerts >= 15, "only {alerts} rules found");
    for field in ["expr:", "for:", "severity:", "summary:", "description:"] {
        assert_eq!(
            count(field),
            alerts,
            "'{field}' does not occur exactly {alerts} times — a rule is incomplete"
        );
    }
}

/// The documents from which an operator copies commands and switches.
///
/// **Two documents, one guard.** The manual was long the only one;
/// `docs/alerts.yml` has been the second since the alert rules, and its notes
/// name commands (`tgctl cluster restart`) and switches (`--proxy-image`) —
/// they are read and followed **during an incident**. A guard that reads only
/// the manual would let an instruction go stale exactly where nobody asks
/// back.
///
/// It is read at compile time (`include_str!`); a test that looks for a file at
/// run time hangs on the working directory.
fn operator_text() -> String {
    let mut text = include_str!("../../../docs/OPERATIONS.md").to_owned();
    // **The command reference too** (`docs/COMMANDS.md`). It promises
    // completeness, and that is the *counter*-direction, checked in
    // `the_command_reference_leaves_nothing_out`. This direction — it names
    // nothing that does not exist — is the one all the guards above already
    // give, and a reference is the worst place to lose it.
    text.push('\n');
    text.push_str(include_str!("../../../docs/COMMANDS.md"));
    text.push('\n');
    text.push_str(include_str!("../../../docs/alerts.yml"));
    // **And the title page** (ADR-0139): it names commands, switches and ADR
    // numbers and is the first thing anybody reads -- a stale setting there
    // costs more than one in the manual.
    text.push('\n');
    text.push_str(include_str!("../../../README.md"));
    text
}

/// **A reference to a `.rs` file must point at one that exists.**
///
/// # The occasion
///
/// Two references in this tree pointed into the void, and both cost work:
///
/// - `hostile_input.rs` **without a crate** — the file lies in `tg-consensus`,
///   I looked for it in `tg-defs` and thereupon declared it non-existent. That
///   afterwards stood in a commit message and in the plan.
/// - a second one that pointed at a file that never existed; the case is
///   documented in `crates/tg-runtime/tests/sidecar_path.rs`, and what was
///   meant was `tg-proxy/tests/mesh_netns.rs`.
///
/// # Whoever explains a broken name writes it as prose
///
/// What is checked is what stands in backticks — a guard that objects to its
/// own explanation is switched off instead of read (the same finding as at the
/// `alerts.yml` guard, which found `histogram_quantile` in its own head). The
/// first answer was a file exception and is withdrawn: it would have made this
/// guard blind about itself.
///
/// A withdrawn name therefore belongs **not named at all** but replaced by a
/// reference to the place at which it is explained. Writing it without
/// backticks would work too — only clippy then demands them (`doc_markdown`),
/// and two rules in contradiction are a trap for the next person. Globs and the
/// extension alone are likewise no references.
///
/// A reference to a test nobody can find is worse than none: it claims a
/// coverage one cannot read up.
///
/// # Why only `.rs`
///
/// A `.rs` file always lies in the repo — the check is thereby without false
/// hits. At `.json` and `.pem` it is not: `config.json`, `peers.json` and
/// `bundle.pem` arise in **operation**, and a guard on them reported 80 cases
/// of which none is a finding. Measured exactly that, before this test had its
/// form.
///
/// # What it cannot do
///
/// It checks the **existence**, not the assignment: a reference to `mod.rs`
/// hits any one of many. What it catches is a name that exists nowhere — and
/// that was both cases.
#[test]
fn every_referenced_rust_file_exists() {
    /// What never lies in the repo and is nevertheless rightly named.
    ///
    /// `_.rs` is the stub `protox` writes into a temp directory
    /// (`workload.proto` has no `package`, hence the name). A real reference to
    /// a file that never exists here.
    ///
    /// `helper.rs` is **foreign** and rightly named: it is the `nftables`
    /// crate's, where `Command::new("nft")` shows that the GPL code stays a
    /// separate process (ADR-0038). Writing it without backticks would work
    /// too — only clippy then demands them.
    ///
    /// `openraft`'s `replication/mod.rs` (ADR-0033) needs no entry, and the
    /// reason is the limit this guard states about itself: compared is the last
    /// segment, and `mod.rs` exists here many times over. It passes for a
    /// reason that has nothing to do with it.
    const TRANSIENT: &[&str] = &["_.rs", "helper.rs"];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    // The haystack is **all** source trees, not only `crates/`. My first
    // attempt left out `xtask/` and `third-party/` and reported three false
    // hits — an instrument that does not see a part produces misjudgements in
    // both directions.
    let mut known = std::collections::BTreeSet::new();
    let mut sources = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !matches!(name.as_str(), "target" | ".git") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                known.insert(name.clone());
                // We do not read generated files: no references of ours stand
                // there, and the files are large.
                if !matches!(name.as_str(), "generated.rs" | "pb.rs") {
                    sources.push(path);
                }
            } else if matches!(name.as_str(), "OPERATIONS.md" | "CLAUDE.md" | "COMMANDS.md")
                || (path.extension().is_some_and(|ext| ext == "md")
                    && dir
                        .file_name()
                        .is_some_and(|dir| dir == "journal" || dir == "plans"))
            {
                // **The documents too**, and for the same occasion: the
                // `hostile_input.rs` error stood not only in the code but also
                // in the plan and in a commit message. Measured, they are clean
                // today (zero references into the void) — the guard keeps it
                // that way.
                //
                // The build journal stands beside them, and via its
                // **directory** rather than via its name: when the plan was cut
                // into plan and journal, 30 000 lines of prose left the file
                // `PLAN.md` — a guard that enumerates names would silently have
                // lost its haystack in the process. Via the directory the next
                // year's file carries too, without anybody adding anything
                // here.
                //
                // **And the ADRs**, via their directory for the same reason —
                // `PLAN.md` thereby no longer needs its name here. They were
                // the gap: per invariant 6 they are the truth, and measured
                // ADR-0032 named a path in `tg-consensus` that ADR-0135 moved
                // to `tg-model`. A reference in the truth that resolves to
                // nothing is worse than one in the manual.
                sources.push(path);
            }
        }
    }

    assert!(
        known.len() > 100 && sources.len() > 100,
        "source files must have been found: {} known, {} read",
        known.len(),
        sources.len()
    );

    let mut dangling = Vec::new();
    let mut checked = 0_usize;
    for path in &sources {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            // Only comments — an `include_str!` or a path in the code stands
            // out at compile time anyway. In the documents every line is
            // prose.
            let is_document = path.extension().is_some_and(|ext| ext == "md");
            if !is_document && !line.trim_start().starts_with("//") {
                continue;
            }
            for piece in line.split('`').skip(1).step_by(2) {
                // A **piece of text** from a comment, not a path — hence
                // `strip_suffix` and not `Path::extension`: what is sought is
                // the character sequence, and it yields the stem along with
                // it.
                let Some(stem) = piece.strip_suffix(".rs") else {
                    continue;
                };
                // A name needs a stem: the extension alone is no reference
                // but something somebody writes about.
                if stem.is_empty() || piece.contains(' ') || piece.contains('<') {
                    continue;
                }
                let name = piece.rsplit('/').next().unwrap_or(piece);
                if name.contains('*') || TRANSIENT.contains(&name) {
                    continue;
                }
                checked += 1;
                // **Whoever writes the crate along says more than the name,
                // and that is checkable.** The comparison below is by name —
                // "existence, not assignment", see above — and a file that
                // *moves* therefore passes it: ADR-0032 named a path in
                // `tg-consensus` that ADR-0135 moved, and the file name exists
                // in both worlds. Measured, that was the whole finding.
                let exists = if piece.starts_with("crates/") {
                    root.join(piece).exists()
                } else {
                    known.contains(name)
                };
                if !exists {
                    dangling.push(format!(
                        "{}:{} -> {piece}",
                        path.strip_prefix(root).unwrap_or(path).display(),
                        number + 1
                    ));
                }
            }
        }
    }

    assert!(checked > 20, "references must have been found: {checked}");
    assert!(
        dangling.is_empty(),
        "these references point at `.rs` files that do not exist:\n  {}",
        dangling.join("\n  ")
    );
}

/// **Every metric has a rule or a reason** (`docs/alerts.yml`).
///
/// The file says it about itself — *"metrics without a rule stand at the end of
/// the file, each with the reason"* —, and up to here nobody checked that.
/// Measured, **six** were missing, among them `tg_raft_peers_missing`: a number
/// that becomes positive exactly when a node's `--peer` list does not cover the
/// membership — and that otherwise stands out only when this node takes the
/// lead.
///
/// # Why that is the right direction
///
/// Only this one. The counter-direction is checked by the guard above: a rule
/// must not name a metric that does not exist. Here it is about no metric being
/// **forgotten** — and "forgotten" does not mean "without a rule" but
/// **without a decision**. A counter of ordinary work needs no threshold; that
/// somebody decided that belongs written down.
///
/// # What it cannot do
///
/// It checks whether the name occurs **somewhere** in the document — not
/// whether it has a reason entry of its own. Measured at
/// `tg_scheduler_unplaceable` (ADR-0011): the name stands there twice, as a
/// reason and in the **description** of a rule beside it, and removing one of
/// the two leaves it green. That is the right boundary — a metric a rule
/// *names* is classified —, but it means: whoever strikes the reason entry and
/// leaves the mention standing gets past.
///
/// # What it does see
///
/// **A longer name does not count for its shorter one.** Measured, `names.rs`
/// has six substring pairs, five in the signer family: `tg_identity_signer`
/// says whether the group runs at all (ADR-0097), and lies inside four longer
/// names. With `contains` it would be classified as soon as one of its sisters
/// has a rule — the word boundary from
/// [`tg_telemetry::args::mentions_word`] separates them at the underscore.
#[test]
fn every_metric_has_a_rule_or_a_reason() {
    let rules = include_str!("../../../docs/alerts.yml");
    let names = include_str!("../../tg-telemetry/src/names.rs");

    let mut checked = 0_usize;
    let mut findings = Vec::new();

    for (start, _) in names.match_indices("pub const ") {
        let rest = &names[start..];
        let Some(line_end) = rest.find('\n') else {
            continue;
        };
        let line = &rest[..line_end];
        // Only the metric names, not the file's other constants.
        let Some(quoted) = line.split('"').nth(1) else {
            continue;
        };
        if !quoted.starts_with("tg_") {
            continue;
        }
        checked += 1;
        if !tg_telemetry::args::mentions_word(rules, quoted) {
            findings.push(quoted.to_owned());
        }
    }

    // A guard that has read nothing confirms everything.
    assert!(
        checked >= 30,
        "only {checked} metrics found — `names.rs` was not read"
    );
    assert!(
        findings.is_empty(),
        "these metrics have neither a rule nor a reason in docs/alerts.yml: \
         {findings:?}"
    );
}

/// The sources that produce an operator output — **read instead of
/// enumerated**.
///
/// A hand-maintained list did not see `signer.rs` (ADR-0108, the youngest
/// file): the guard above it reported "50 output lines found" and had two
/// hundred to check. The same shape this tree has measured at five other places
/// as a source of error.
fn output_sources() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .expect("tgctl/src must be readable")
        .filter_map(Result::ok)
        .map(|found| found.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| {
            let name = path
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read_to_string(&path).expect("source must be readable");
            (name, text)
        })
        .collect();
    out.sort();
    assert!(
        out.len() >= 4,
        "only {} source files in tgctl/src — the search does not take hold",
        out.len()
    );
    out
}

/// **No Rust syntax in `tgctl`'s output.**
///
/// The reason has been measured twice. At `Rejection` `tgctl` wrote the debug
/// form to the error output — *"an operator reads there the answer to 'why did
/// that not work'; it shall be a sentence"* —, and at the **finding** of
/// `tgctl audit` the same stood: `TimeWentBackwards { index: 42, … }`, in the
/// one output an auditor reads (ADR-0020).
///
/// # The rule, not the list
///
/// Every `println!`/`eprintln!` line in `tgctl`'s production part is checked
/// for `{…:?}`. Whoever wants to print a type in an operator line gives it a
/// `Display` — not this guard an exception. Exactly that was the remedy at
/// `Rejection` and at `Anomaly`.
///
/// Comment lines stay out: the rationales in the code name the debug form in
/// order to say why it does not stand there — a guard that objects to its own
/// rationale produces false hits and is switched off.
#[test]
fn no_debug_form_reaches_the_operator() {
    let mut checked = 0_usize;
    let mut findings = Vec::new();

    for (name, source) in output_sources() {
        // Only the production part: in a test `{:?}` at an assertion is
        // exactly right.
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source.as_str(), |(before, _)| before);

        for (number, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if !line.contains("println!") && !line.contains("eprintln!") {
                continue;
            }
            checked += 1;
            if line.contains(":?}") {
                findings.push(format!("{name}:{}: {}", number + 1, trimmed));
            }
        }
    }

    // A guard that has read nothing confirms everything.
    assert!(
        checked >= 100,
        "only {checked} output lines found — the search does not take hold"
    );
    assert!(
        findings.is_empty(),
        "these lines show an operator Rust syntax; the type needs a `Display`: \
         {findings:?}"
    );
}

/// **Every ADR names its neighbours** (ADR-0001, invariant 6).
///
/// # The finding
///
/// The template names "Related ADRs" as a section, and 81 of 89 ADRs carry it.
/// Measured, it was missing in **eight** — and six of them are the youngest:
/// 0073, 0074, 0077, 0078, 0079, 0080, 0081 and 0090. The content was there
/// (each of them names twenty to thirty-six ADRs in running text); what was
/// missing is the **navigation**: which ADR this one changes, applies or
/// presupposes.
///
/// That is no formality. Invariant 6 says "before deviating from the
/// architecture: read `plans/`", and this project has paid several times what
/// it costs not to find a decision — most recently when a promise from ADR-0015
/// was noted three times as "not provided for" although it was decided.
///
/// # Boundary
///
/// What is checked is the **section**, not its content: whether the neighbours
/// named are the right ones is decided by the ADR.
///
/// And expressly **not** checked are "Decision Drivers" and "Considered
/// Options": they are missing in 25 and 21 ADRs respectively that carry them in
/// prose. A guard that demanded them would be busywork on 89 documents — and
/// one that produces false hits is switched off instead of read.
#[test]
fn every_adr_names_its_neighbours() {
    // The four sections **every** ADR carries — measured: 89 of 89.
    const REQUIRED: [&str; 4] = [
        "## Context and Problem Statement",
        "## Decision",
        "## Consequences",
        "## Related ADRs",
    ];

    let plans = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root")
        .join("plans");

    let mut checked = 0_usize;
    for entry in std::fs::read_dir(&plans).expect("plans/ readable") {
        let path = entry.expect("entry").path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if path.extension().is_none_or(|ext| ext != "md") || name == "0000-template.md" {
            continue;
        }
        if name.len() < 4 || name[..4].parse::<u16>().is_err() {
            continue;
        }

        let text = std::fs::read_to_string(&path).expect("ADR readable");
        for section in REQUIRED {
            // **Prefix and not equality**: ADR-0032 calls its section
            // `## Decisions`, because it takes several. That is a permissible
            // deviation and not a defect — and a guard that reported it would
            // produce a false hit.
            assert!(
                text.lines().any(|line| line.starts_with(section)),
                "{name} has no section `{section}` — the template names it, and \
                 an ADR whose neighbours nobody finds is not read (invariant 6)"
            );
        }
        checked += 1;
    }

    // Without this assurance the test would check nothing as soon as the path
    // is wrong: an empty set satisfies every condition.
    assert!(checked > 80, "only {checked} ADRs were read");
}

/// **The number of format breaks in the manual is measured, not counted**
/// (ADR-0072).
///
/// A format change is no rolling update, and the manual names a bundled
/// maintenance window for it. How many breaks lie in it stood up to here as an
/// **ordinal in prose** — "the sixth", "the seventh" —, and measured, the count
/// had drifted: two places claimed "sixth", two "seventh", and "tenth" and
/// "eleventh" nobody claimed.
///
/// # What is counted
///
/// Every `#[serde(default)]` field at one of the three **strict** types
/// (`deny_unknown_fields`, ADR-0072). The default covers one direction — a new
/// reader tolerates a missing field —, the strictness refuses the other: an
/// **old** reader refuses a message with an unknown field. Every such field is
/// thereby exactly one break.
///
/// # Why a guard and not prose
///
/// Because the number is what an operator reads before planning a window — and
/// because a number in prose drifts exactly the way it drifted. Whoever adds a
/// field makes this test red and carries the number over: the attention
/// demanded instead of the one hoped for.
///
/// **What it does not count:** form changes that add no field — the egress
/// entry went from a triple to a quadruple (ADR-0092), and a JSON array with
/// one more element is a break just the same. The number is thereby a **lower
/// bound**, and that stands in the manual with it.
#[test]
fn the_handbook_names_the_measured_number_of_breaks() {
    // **It is counted at the source** (`tg-store/tests/wire_form.rs`), and the
    // constant is the bridge: whoever adds a field makes the witness there red,
    // carries the constant over -- and then this one.
    let fields = tg_store::session::PROTOCOL_FIELDS;

    let handbook = include_str!("../../../docs/OPERATIONS.md");
    assert!(
        handbook.contains(&format!("{fields} fields")),
        "the manual does not name the measured number of format breaks \
         ({fields} fields at the three strict types). Whoever adds one carries \
         it over."
    );
}

/// **Every verb of `tgctl` has at least one witness.**
///
/// # Why this is a guard and not a measurement
///
/// The lens "which subcommand has no test at all" found six — `node
/// upsert|rotate|drain|uncordon`, `cluster restore-volume` and `revoke-egress`
/// — and delivered two real findings on the way: the ordering error in `node
/// upsert` (a missing `--site` reported "no admin socket") and a half assurance
/// in the form witness of `restore-volume`. Without a guard the next unchecked
/// command comes along unnoticed.
///
/// # The dispatch is read
///
/// Not a list — the shape this tree has measured four times as a source of
/// error. And **literals** instead of substrings: `operator` occurs in the prose
/// of this manual guard and therefore looked covered, while the command had not
/// a single test.
///
/// # What it cannot do
///
/// It checks that the name **occurs** in a test — not that the test says
/// anything meaningful about it. That is the limit of a coverage guard, and it
/// stands here so that nobody reads more out of it.
#[test]
fn every_subcommand_has_at_least_one_witness() {
    let dispatches = [
        include_str!("../src/main.rs"),
        include_str!("../src/cluster.rs"),
        include_str!("../src/audit.rs"),
    ];
    let tests = [
        include_str!("cluster.rs"),
        include_str!("node_write.rs"),
        include_str!("operator.rs"),
        include_str!("rekey.rs"),
        include_str!("restore_volume.rs"),
        include_str!("invite.rs"),
        include_str!("attachment.rs"),
        include_str!("audit.rs"),
    ]
    .concat();

    let mut verbs: Vec<&str> = Vec::new();
    for source in dispatches {
        for line in source.lines() {
            let trimmed = line.trim();
            // Only dispatch arms: `"verb" =>` or `"verb" if …`.
            if let Some(rest) = trimmed.strip_prefix('"')
                && let Some((name, tail)) = rest.split_once('"')
                && (tail.trim_start().starts_with("=>") || tail.trim_start().starts_with("if"))
                && name.len() >= 3
                && name.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            {
                verbs.push(name);
            }
        }
    }
    verbs.sort_unstable();
    verbs.dedup();
    assert!(verbs.len() >= 20, "the dispatches were not read: {verbs:?}");

    let missing: Vec<&str> = verbs
        .iter()
        .filter(|verb| !tests.contains(&format!("\"{verb}\"")))
        .copied()
        .collect();
    assert!(missing.is_empty(), "no test names these verbs: {missing:?}");
}

/// **An overtaken ADR is not cited as a current basis.**
///
/// Two ADRs are `superseded` — 0029 by 0030, 0075 by 0092 —, and both
/// successions stand in the head of the file itself
/// (`- **Status:** superseded by …`). The set and the mapping therefore come
/// **from the files** and not from a list here: a hand-maintained one would be
/// the sixth in this tree, and five of them are measured as a source of error.
///
/// The case is not one of the rare ones. Measured, five places cited ADR-0075,
/// and one of them was a **finding in the manual**: "There is no way out via a
/// permission … **and that stays so** (ADR-0075)" — since ADR-0092 there is
/// one, and the paragraph advised an operator to leave `<mesh>` out and thereby
/// to give up mTLS **and** the egress control, for a capability that has a
/// command.
///
/// What is demanded is the **successor nearby** (three lines around the
/// mention), and nothing else. The first attempt also allowed a vocabulary of
/// historical words ("until", "replaced", "then") — and the counter-check was
/// **green**: three lines above the inserted false statement stood "Until
/// ADR-0074 UDP went directly over the bridge", that is, a historical word
/// about an *other* ADR. A vocabulary of words does not hit the intent; the
/// successor is the only setting that substantiates it.
///
/// A purely narrative mention thereby needs it too — and that is right: "until
/// ADR-0074 X applied (ADR-0075, replaced by ADR-0092)" is the form a reader
/// needs in order not to look it up.
///
/// # What it **cannot** do
///
/// It reads no semantics. Whoever names the successor and puts the wrong
/// statement beside it gets through — the finding above would have stayed
/// invisible with an appended "(ADR-0092)". What it achieves is the demand:
/// whoever cites an overtaken ADR must write the succession with it and reads
/// it in the process.
#[test]
fn no_superseded_adr_is_cited_as_current() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("root");

    // The succession comes from the ADR files.
    let mut succession = Vec::new();
    for entry in std::fs::read_dir(root.join("plans")).expect("plans readable") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|ext| ext != "md") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(number) = stem.split('-').next().filter(|n| n.len() == 4) else {
            continue;
        };
        let text = std::fs::read_to_string(&path).expect("readable");
        let Some(line) = text
            .lines()
            .find(|line| line.starts_with("- **Status:**") && line.contains("superseded by"))
        else {
            continue;
        };
        // The successor stands as `0092` or `ADR-0030`.
        let successor = line
            .rsplit_once("superseded by ")
            .map(|(_, rest)| rest.trim().trim_start_matches("ADR-").to_owned())
            .expect("successor");
        succession.push((format!("ADR-{number}"), format!("ADR-{successor}")));
    }
    assert!(
        succession.len() >= 2,
        "only {} overtaken ADRs found — the guard has hardly read",
        succession.len()
    );

    // `plans/PLAN.md` expressly does **not** stand in it: it is a chronicle,
    // and every section is the record of its moment -- "ADR-0075 forbids plain
    // UDP" was right there when it stood there. Measured, its nine mentions are
    // all narrative. What the plan carries instead is a note at the section
    // itself, where an overtaken statement would steer the next work -- the same
    // rule as at the ADRs' notes (invariant 6).
    //
    // What is read are the documents an operator **follows**, the production
    // code -- and `plans/README.md`, the index invariant 6 points at. Its
    // decision log is itself a chronicle, but it stands in the document a reader
    // asks for the **state**: a line "UDP stays forbidden" without its
    // succession reads there as a decision in force.
    let mut haystack: Vec<std::path::PathBuf> = vec![
        root.join("docs/OPERATIONS.md"),
        root.join("docs/alerts.yml"),
        root.join("plans/README.md"),
    ];
    for crate_dir in std::fs::read_dir(root.join("crates")).expect("crates readable") {
        collect_rust(&crate_dir.expect("entry").path().join("src"), &mut haystack);
    }

    let mut findings = Vec::new();
    let mut checked = 0_u32;
    for path in &haystack {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            for (old, new) in &succession {
                // Two forms: `ADR-0075` in prose and `| 0075 |` as the first
                // cell of a table row. The second is the index's
                // (`plans/README.md`), and without it the guard saw **nothing**
                // there -- measured against a counter-check that stayed green.
                let cited = line.contains(old.as_str())
                    || line.starts_with(&format!("| {} |", old.trim_start_matches("ADR-")));
                if !cited {
                    continue;
                }
                checked += 1;
                let near = lines[at.saturating_sub(3)..(at + 4).min(lines.len())].join(" ");
                // A mention is accompanied when the successor stands nearby
                // as `ADR-<n>` **or** the line itself states the succession. The
                // second form is the index's, where the number stands bare
                // (`superseded by 0092`) -- and it is demanded **on the line**
                // and not nearby: in an ordered table `| 0030 |` would
                // otherwise stand as the neighbouring row of `| 0029 |` and
                // would accompany itself.
                let number = new.trim_start_matches("ADR-");
                let spoken = line.contains(&format!("superseded by {number}"))
                    || line.contains(&format!("superseded by ADR-{number}"))
                    || line.contains(&format!("replaced by {number}"))
                    || line.contains(&format!("replaced by ADR-{number}"));
                if near.contains(new.as_str()) || spoken {
                    continue;
                }
                let shown = path.strip_prefix(root).unwrap_or(path).display();
                findings.push(format!("{shown}:{}: {old}", at + 1));
            }
        }
    }

    // A guard that has read nothing confirms everything -- and the **number of
    // mentions** is of no use for that: it may legitimately fall to zero
    // (whoever resolves a citation does the right thing). What is assured is
    // therefore that the haystack is there; the mapping is covered by the
    // assurance above.
    assert!(
        haystack.len() > 100,
        "only {} files in the haystack ({checked} mentions) — the guard has \
         hardly read",
        haystack.len()
    );
    assert!(
        findings.is_empty(),
        "an overtaken ADR is cited here without its succession: {findings:?}"
    );
}

/// **Every label in `by(…)`/`on(…)` is set by the metric too.**
///
/// The third silent way in which an alert rule never fires — after
/// `histogram_quantile` on a summary and a comparison without `on()`. Measured,
/// one rule was affected, and it was my own:
///
/// ```text
/// count(count by (epoch) (tg_identity_signer_epoch)) > 1
/// ```
///
/// The epoch is the **value** of this gauge and not a label. `count by (epoch)`
/// thereby groups everything into one bucket, the number is always 1, and the
/// rule never fired. What is right is `count_values("epoch", …)` — it makes a
/// label out of the value in the first place.
///
/// The label set per metric comes from the **set sites**: from
/// `names::CONSTANT` to the matching bracket, and every `"name" =>` in it is a
/// label. Maintained by hand it would be the shape this tree has measured five
/// times as a source of error.
///
/// # What it cannot do
///
/// `instance`, `job` and `node` are set not by the code but by Prometheus or by
/// the global recorder (`tg_telemetry::init`) — they therefore stand free.
#[test]
fn every_grouping_label_exists_on_its_metric() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let labels = metric_labels(root);

    let rules = std::fs::read_to_string(root.join("docs/alerts.yml")).expect("alerts.yml");
    let mut checked = 0_usize;
    let mut offenders = Vec::new();
    for block in rules.split("- alert:").skip(1) {
        let name = block.lines().next().unwrap_or("?").trim();
        let Some(expr) = block.split("expr:").nth(1) else {
            continue;
        };
        let expr = expr
            .split("\n        for:")
            .next()
            .unwrap_or(expr)
            .to_owned();

        let mut mentioned = std::collections::BTreeSet::new();
        for word in expr.split(|glyph: char| !glyph.is_ascii_alphanumeric() && glyph != '_') {
            if word.starts_with("tg_") {
                mentioned.insert(word.to_owned());
            }
        }
        let mut available = std::collections::BTreeSet::new();
        for metric in &mentioned {
            if let Some(found) = labels.get(metric) {
                available.extend(found.iter().cloned());
            }
        }

        for keyword in ["by (", "by(", "on (", "on("] {
            let mut rest = expr.as_str();
            while let Some(at) = rest.find(keyword) {
                rest = &rest[at + keyword.len()..];
                let Some(close) = rest.find(')') else { break };
                for key in rest[..close].split(',') {
                    let key = key.trim();
                    if key.is_empty() || matches!(key, "instance" | "job" | "node") {
                        continue;
                    }
                    checked += 1;
                    if !available.contains(key) {
                        offenders.push(format!("{name}: {keyword}{key})  {mentioned:?}"));
                    }
                }
            }
        }
    }

    // Without this assurance the test would be green even if neither the set
    // sites nor the rules were found.
    assert!(
        labels.len() > 20 && checked > 5,
        "{} metrics with labels and {checked} groupings were read — the path is \
         wrong",
        labels.len()
    );
    assert!(
        offenders.is_empty(),
        "these rules group by a label their metric does not set — the result is \
         one bucket and the rule never fires (for the **value** of a gauge \
         `count_values` is meant): {offenders:?}"
    );
}

/// Which labels a metric carries at its set sites.
///
/// It is read from `names::CONSTANT` to the matching bracket; every
/// `"name" =>` in it is a label. A function of its own, because it is a
/// statement of its own — and because the guard below it would otherwise lie
/// past the line limit.
fn metric_labels(
    root: &std::path::Path,
) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    // Name of the constant -> metric.
    let names_rs =
        std::fs::read_to_string(root.join("crates/tg-telemetry/src/names.rs")).expect("names.rs");
    let mut names = std::collections::BTreeMap::new();
    for line in names_rs.lines() {
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((constant, rest)) = rest.split_once(": &str = \"") else {
            continue;
        };
        let Some((metric, _)) = rest.split_once('"') else {
            continue;
        };
        names.insert(constant.to_owned(), metric.to_owned());
    }

    // Labels per metric from the set sites.
    let mut sources = Vec::new();
    collect_rust(&root.join("crates"), &mut sources);
    sources.retain(|path| !path.components().any(|part| part.as_os_str() == "tests"));

    let mut labels: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    let macros = ["gauge!(", "counter!(", "histogram!("];
    let mut per_macro = [0_usize; 3];
    for path in &sources {
        let text = std::fs::read_to_string(path).expect("readable");
        for (nr, opener) in macros.iter().enumerate() {
            let mut from = 0;
            while let Some(at) = text[from..].find(opener) {
                let start = from + at + opener.len() - 1;
                from = start + 1;
                let mut depth = 0_i32;
                let mut end = start;
                for (offset, glyph) in text[start..].char_indices() {
                    match glyph {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = start + offset + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let call = &text[start..end];
                let Some(constant) = call
                    .split("names::")
                    .nth(1)
                    .map(|rest| {
                        rest.chars()
                            .take_while(|glyph| glyph.is_ascii_uppercase() || *glyph == '_')
                            .collect::<String>()
                    })
                    .filter(|found| !found.is_empty())
                else {
                    continue;
                };
                let Some(metric) = names.get(&constant) else {
                    continue;
                };
                per_macro[nr] += 1;
                let seen = labels.entry(metric.clone()).or_default();
                let mut rest = call;
                while let Some(at) = rest.find("\" =>") {
                    let head = &rest[..at];
                    if let Some(from) = head.rfind('"') {
                        seen.insert(head[from + 1..].to_owned());
                    }
                    rest = &rest[at + 4..];
                }
            }
        }
    }

    // One assurance per macro, and that is a lesson from the reference guard in
    // `tg-syscall`: this map is the **reference** against which
    // `every_grouping_label_exists_on_its_metric` checks — a metric that is
    // missing here contributes no labels, and every `by (…)` on it becomes a
    // false finding.
    //
    // Measured, the coverage assurance there catches only the loss of `gauge!`
    // (42 of 54 metrics); taking `counter!` and `histogram!` away leaves the
    // test **green**, because no alert rule groups on their labels today. That
    // is the day it changes: then it would be a false finding nothing catches.
    for (nr, name) in macros.iter().enumerate() {
        assert!(
            per_macro[nr] > 0,
            "no set site with `{name}` found — the form has fallen away, and \
             without it every metric set that way carries no labels any more"
        );
    }

    labels
}

/// Collects every `.rs` file under `dir`, recursively.
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

/// **The manual's numbers stand in the code.**
///
/// `docs/OPERATIONS.md` names limits and deadlines as numbers, and an operator
/// reads them during an incident. A number that drifts is the same class of
/// error as a command that does not exist — only less conspicuous: the
/// format-break counter has already done it once (it stood as an ordinal in
/// prose and was off by orders of magnitude).
///
/// **The list is a selection**, and that is its limit: it can check too little,
/// not wrongly. Included is what has a public constant and whose drift would
/// hurt an operator; the mapping number → constant no code yields, so there is
/// no form without a list.
///
/// **Here and not at the owner of the constant**, and that was a finding: the
/// same task once stood **twice** in the tree — here and in a second witness
/// under `tg-runtime`, with half an overlap and without a cross-reference (the
/// second has fallen away with this cut; its name stands here as prose, because
/// a reference in backticks would point at a deleted file). And the two were
/// already **differently strict**: for the lease the other demanded exactly
/// `15 s`, while here both spellings apply (measured, see below). Whoever had
/// rephrased the one place in the manual would get a red "the number in the
/// code has moved" there — which would be wrong.
///
/// `tgctl` is the place because it reaches **all four** crates (`tg-model`,
/// `tg-runtime`, `tg-telemetry`, `tg-identity`); the other way round it does
/// not work — `tg-runtime` cannot see `tg-identity`. The split was therefore
/// not forced but grown.
///
/// Expressly **not** included are numbers that follow from a computation (the
/// socket budget, the zone limit) — those have witnesses of their own that
/// recompute them, and a second place would be a second opportunity. And
/// `sun_path` is missing out of a layering question: `tgctl` does not hang on
/// `tg-syscall`, and an edge for it would be one for a number (ADR-0023) — the
/// 108 is recomputed by the witness in `tgd` against `libc::sockaddr_un`.
#[test]
fn the_handbook_only_names_numbers_that_hold() {
    let handbook = std::fs::read_to_string("../../docs/OPERATIONS.md").expect("OPERATIONS.md");

    // **Several permissible forms** per number, and at least one is demanded.
    // That is no careless or-assertion: measured, both branches are reachable --
    // the manual writes the lease as `15 s` in one place and as "fifteen
    // seconds" in another, and a guard that enforces one spelling produces false
    // hits.
    let expected: Vec<(Vec<String>, &str)> = vec![
        (
            vec![format!(
                "{} minutes",
                tg_telemetry::init::GAUGE_IDLE_SECONDS / 60
            )],
            "the gauge expiry (ADR-0088)",
        ),
        (
            vec![format!(
                "{} KiB",
                tg_identity::secrets::MAX_SECRET_BYTES / 1024
            )],
            "the secret limit (ADR-0016)",
        ),
        (
            vec![
                format!("{} s", tg_model::lease::LEASE_SECONDS),
                format!("{} seconds", tg_model::lease::LEASE_SECONDS),
            ],
            "the active-role lease (ADR-0064)",
        ),
        (
            // A lease that reaches further is not believed (ADR-0078,
            // determination 3): the node compares with `now + 2 * LEASE`.
            vec![format!("{} s", tg_model::lease::LEASE_SECONDS * 2)],
            "the plausibility bound of the clock skew (ADR-0078)",
        ),
        (
            // The clearer's grace period (ADR-0058) -- it stands in the
            // ordering condition of the fence distance (ADR-0076).
            vec![format!("{} s", tg_runtime::reconcile::GRACE.as_secs())],
            "the grace period when stopping (ADR-0058)",
        ),
    ];

    for (forms, what) in expected {
        assert!(
            forms.iter().any(|form| handbook.contains(form)),
            "the manual names {what} in none of these forms: {forms:?} -- \
             either the number in the code has moved and the text drifts, or the \
             text has rephrased it and this line belongs carried over"
        );
    }
}

/// **And the relation from which the plausibility bound follows.**
///
/// It is no number of its own: `2 * LEASE` means that a skew of more than **one
/// whole lease** is no longer believed — the leader issues with `now + LEASE`,
/// the node compares with `now + 2 * LEASE`. The manual says both, from two
/// directions, and both sentences must mean the same computation.
///
/// Without this witness the test above would be green with two numbers that
/// have nothing to do with each other too.
#[test]
fn the_plausibility_bound_is_one_whole_lease_of_skew() {
    let handbook = std::fs::read_to_string("../../docs/OPERATIONS.md").expect("OPERATIONS.md");
    let lease = tg_model::lease::LEASE_SECONDS;

    assert!(
        handbook.contains("more than a whole lease"),
        "the manual does not name the relation — the bound then looks like an \
         arbitrary number"
    );
    assert!(
        handbook.contains(&format!("i.e. {lease} s")),
        "the manual does not name the skew as '{lease} s'"
    );
}

/// Every label that is set stands in [`tg_telemetry::names::LABELS`] — and the
/// other way round.
///
/// # The finding
///
/// ADR-0015 names cardinality as an open point, and `names.rs` answers it: *a
/// label may take only values whose number the cluster bounds.* For a metric
/// with an unbounded label is a memory leak with a Prometheus connection.
///
/// Measured, the answer was an **enumeration in prose**, and it stayed behind
/// reality: the rule named seven labels, thirteen were set. The six others
/// (`class`, `direction`, `fingerprint`, `rpc`, `task`, `volume`) were each
/// justified in their own doc block and not named in the rule — and `peer` even
/// reads against the prohibition list like a violation, because there "peer
/// addresses" stand and here the identifier is meant.
///
/// None of them was a real violation (all thirteen are bounded, each with a
/// measurement of its own). What was missing is the **mechanism**: whoever adds
/// a label was asked by nothing — the same shape this tree has measured at six
/// places as a source of error, and ADR-0046 made the rule out of it that the
/// enumerating is the cause.
///
/// # Three promises
///
/// The first catches the new, unconsidered label. The second the entry left
/// behind — otherwise the list grows into one nobody reads any more. The third
/// is the one that repairs the finding: **the rationale in the head cannot stay
/// behind the list.**
///
/// # What it cannot do
///
/// It checks that a label is *named and justified*, not that the rationale is
/// right. Whether the set is really bounded is said by a measurement — the table
/// in the head names it per label.
#[test]
fn every_metric_label_is_declared_and_justified() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");

    let declared: std::collections::BTreeSet<&str> =
        tg_telemetry::names::LABELS.iter().copied().collect();

    let mut used: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (metric, labels) in metric_labels(root) {
        for label in labels {
            used.entry(label).or_default().push(metric.clone());
        }
    }

    // Without this assurance the test would be green even if the set sites were
    // not found.
    assert!(
        used.len() > 8 && declared.len() > 8,
        "{} set and {} declared labels were read — the path is wrong",
        used.len(),
        declared.len()
    );

    let undeclared: Vec<_> = used
        .iter()
        .filter(|(label, _)| !declared.contains(label.as_str()))
        .map(|(label, metrics)| format!("{label} ({})", metrics.join(", ")))
        .collect();
    assert!(
        undeclared.is_empty(),
        "these labels are set and do not stand in `names::LABELS` — there the \
         cardinality question is answered, and a metric with an unbounded label \
         is a memory leak with a Prometheus connection: {undeclared:?}"
    );

    let unused: Vec<_> = declared
        .iter()
        .filter(|label| !used.contains_key(**label))
        .collect();
    assert!(
        unused.is_empty(),
        "these labels stand in `names::LABELS` and are set by no metric — an \
         entry that covers nothing makes the list into one nobody reads any \
         more: {unused:?}"
    );

    let head = std::fs::read_to_string(root.join("crates/tg-telemetry/src/names.rs"))
        .expect("names.rs")
        .split("pub const LABELS")
        .next()
        .expect("head")
        .to_owned();
    let unjustified: Vec<_> = declared
        .iter()
        .filter(|label| !head.contains(&format!("//! | `{label}` |")))
        .collect();
    assert!(
        unjustified.is_empty(),
        "these labels stand in `names::LABELS` and have no line in the table in \
         the module head — there stands **what bounds their number**, and \
         exactly that rationale once stayed behind the list: {unjustified:?}"
    );
}

/// **An instant without a unit is a number.**
///
/// An operator reckons it against their clock — at an invitation, to decide
/// whether it still suffices, at the active-role lease, to see how long it
/// carries. And milliseconds against seconds is a factor of a thousand.
///
/// Measured, **three of four** lines named their unit; the fourth was the
/// invitation line in `cluster trust` — while its twin in `node invite` prints
/// **the same setting** with "(seconds UTC)". The same fact, two forms.
///
/// The same case as at the `Anomaly` display, where the unit came along
/// "because a bare epoch number tells nobody what it is".
///
/// # What it cannot do
///
/// It sees **named** field interpolation (`{expires_at}`, `{until}`), that is,
/// this tree's house form — a `let x = …; println!("{x}")` or a positional
/// substitution does not stand out to it. And it does not judge whether the
/// unit named is **right**; that is said by the type.
#[test]
fn every_printed_instant_names_its_unit() {
    let mut checked = 0_usize;
    let mut findings = Vec::new();

    for (name, source) in output_sources() {
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source.as_str(), |(before, _)| before);

        for (number, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if !line.contains("println!") && !line.contains("eprintln!") {
                continue;
            }
            // A time value by its name: `{expires_at}`, `{until}`,
            // `{last_report}` — and every `{…_at}`.
            let instant = ["{expires_at", "{until", "{last_report", "{timestamp"]
                .iter()
                .any(|needle| line.contains(needle))
                || line.contains("_at}");
            if !instant {
                continue;
            }
            checked += 1;
            if !line.contains("seconds") && !line.contains("UTC") {
                findings.push(format!("{name}:{}: {}", number + 1, trimmed));
            }
        }
    }

    // A guard that has read nothing confirms everything.
    assert!(
        checked >= 3,
        "only {checked} lines with a time value found — the search does not take hold"
    );
    assert!(
        findings.is_empty(),
        "these lines give an operator a bare epoch number; without the unit they \
         reckon wrongly against their clock: {findings:?}"
    );
}
