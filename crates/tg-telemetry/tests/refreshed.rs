//! **Whoever is refreshed in the scrape today stays so.**
//!
//! A gauge decays after [`tg_telemetry::GAUGE_IDLE_SECONDS`] (ADR-0088). Eleven
//! of them are set more rarely than that — the data key changes at most every
//! three hours, a signer seat never over a process life — and therefore
//! register a refresh (`health.on_scrape(NAME, …)`).
//!
//! **Without the registration no test sees that.** The time series appears at
//! the first scrape and is gone a quarter of an hour later; a witness that runs
//! for seconds measures no difference in between — and with it disappears the
//! alert rule that waits on it.
//!
//! # The direction is the whole difference
//!
//! The header of [`tg_telemetry::names`] rejects a guard, and rightly: "does
//! this metric need a registration?" hangs on its **cadence**, and whether
//! `reconcile::step` lies clearly below the deadline a reader knows and a guard
//! does not. Add the subtlety it warns of — an `on_scrape` takes **one** name
//! as the key, and the callback may set several metrics; whoever asks "does the
//! name stand in an `on_scrape`?" reports `SIGNER_EPOCHS` and
//! `VOLUME_SNAPSHOT_AT` as missing.
//!
//! This guard goes the **other way**: it reads the registrations from the
//! source and nails them down. The classification stays with the reader, the
//! subtlety does not interfere (no name stands in the list that nobody
//! registered), and what it catches is the loss of a decision somebody made.

/// The sources in which refreshes are registered — **read instead of
/// enumerated**.
///
/// That this guard **reads** across the crate boundary is no coupling in the
/// build: no `use`, no edge in `Cargo.toml`, only a text comparison.
///
/// It stood there as a list of three files, and measured it is today exactly
/// those three — but the **completeness** was unguarded: a fourth file calling
/// `on_scrape` would not stand out, and its gauge would decay after 15 minutes
/// together with the alert rule on it (ADR-0088).
///
/// `tg-telemetry` stays out: `on_scrape` **is** defined there.
fn sources() -> Vec<(String, String)> {
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

    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/");

    let mut files = Vec::new();
    for found in std::fs::read_dir(crates)
        .expect("crates must be readable")
        .filter_map(Result::ok)
    {
        let member = found.path();
        walk(&member.join("src"), &mut files);
    }
    files.sort();
    // **Only `probes.rs` stays out**, and that as the *place of definition*:
    // there stands `on_scrape` itself and the one registration this crate makes
    // for others (`report_protocol`). Until ADR-0134 the whole crate was
    // excepted — since the archive's read path lies here, it registers two
    // metrics itself, and an exception by crate would let them disappear
    // unnoticed.
    files.retain(|path| !path.ends_with("tg-telemetry/src/probes.rs"));

    let mut out = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("source must be readable");
        // Only the production part, and without comment lines. The filter is
        // **precaution and today without effect**, measured: `agent.rs` names
        // `health.on_scrape(DATA_KEY, …)` in a doc block, and the name reader
        // below searches for `names::` — it does not pick up the short name. A
        // comment quoting the **full** path would by contrast report a
        // registration that does not exist; that is the fourth false positive
        // of this kind in this tree, and that is why the filter stands there.
        let production: String = text
            .split_once("#[cfg(test)]")
            .map_or(text.as_str(), |(before, _)| before)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        if production.contains("on_scrape(") {
            let name = path
                .strip_prefix(crates)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            out.push((name, production));
        }
    }
    assert!(
        out.len() >= 3,
        "only {} sources with a registration — the search does not bite",
        out.len()
    );
    out
}

/// The names registered today — read from the source.
fn registered() -> Vec<String> {
    let mut names = Vec::new();
    for (_, source) in sources() {
        let mut rest = source.as_str();
        while let Some(at) = rest.find("on_scrape(") {
            rest = &rest[at + "on_scrape(".len()..];
            // The name stands as `…names::CONSTANT` — either directly after the
            // parenthesis or on the next line.
            let end = rest.find(&[',', ')'][..]).unwrap_or(rest.len());
            let head = &rest[..end.min(200)];
            if let Some(at) = head.find("names::") {
                let name: String = head[at + "names::".len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_uppercase() || *c == '_' || c.is_ascii_digit())
                    .collect();
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
    }
    names.sort_unstable();
    names.dedup();
    names
}

/// **The fourteen stay registered.**
///
/// The list is a pin and no derivation: "this gauge needs a refresh" is a
/// decision about its cadence, and whoever removes a registration shall
/// **justify** it instead of losing it. If one is added, it belongs here — then
/// the guard is red, and that is the requested attention.
#[test]
fn every_slowly_set_gauge_stays_registered() {
    let expected = [
        "AUDIT_BYTES",
        "AUDIT_SEGMENTS",
        "DATA_KEY",
        "INTERMEDIATE_EXPIRES_AT",
        "PEERS_MISSING",
        // A sidecar's open connections (ADR-0114). The same situation as with
        // the QUIC flows below: four standing connections do not set the gauge
        // for hours.
        "PROXY_CONNECTIONS",
        "QUIC_EGRESS_FLOWS",
        "RAFT_LEADER",
        "RAFT_RPC_DEADLINE",
        "SECRETS_PREVIOUS",
        "SIGNER",
        "SIGNER_EPOCH",
        "SIGNER_GROUP",
        "SIGNER_SEATS",
        "SIGNER_SEALED",
        "VOLUME_SNAPSHOTS",
    ];

    let found = registered();
    assert!(
        found.len() >= 10,
        "only {} registrations found — the haystack has fallen away, and without \
         it this guard confirms everything: {found:?}",
        found.len()
    );

    let missing: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|name| !found.iter().any(|g| g == name))
        .collect();
    assert!(
        missing.is_empty(),
        "these metrics no longer register a refresh — their time series then \
         decays after a quarter of an hour, and the alert rule on it goes \
         silent: {missing:?}"
    );

    let fresh: Vec<&String> = found
        .iter()
        .filter(|name| !expected.contains(&name.as_str()))
        .collect();
    assert!(
        fresh.is_empty(),
        "these registrations are new — they belong in this guard's list, so \
         that they do not disappear there again: {fresh:?}"
    );
}
