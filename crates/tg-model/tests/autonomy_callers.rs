//! **Every action the production code checks is autonomous** (ADR-0010).
//!
//! # What was measured here
//!
//! `autonomy::check` occurs in the production code at four places, and all four
//! name an **autonomous** action: `HoldOnRequirement`, `StopUnwanted`,
//! `RestartOnOrder`, `RestartAssigned`. With that `Verdict::Deferred` cannot
//! arise in operation — the autonomy boundary is **structurally** without
//! effect at this place.
//!
//! And that is no shortcoming but the architecture at work: the quorum-bound
//! decisions from ADR-0010 all lie with the **leader**. The scheduler places
//! (ADR-0011), the leader grants leases (ADR-0064), cluster-wide mutations go
//! through the log. An agent has nothing to do for which it would need quorum —
//! it executes what was decided with quorum.
//!
//! A comment at `reconcile::step` predicted the opposite: "only the scheduler
//! assignment from phase 6 makes the difference from `PlaceNew` visible — and
//! **then** the autonomy boundary bites here." Phase 6 has long been finished,
//! and it came out the other way round. The comment is withdrawn; this file is
//! the replacement.
//!
//! # What it means when this test goes red
//!
//! Then the production code checks a **quorum-bound** action for the first
//! time, and three things become sharp in the same moment:
//!
//! * `Verdict::Deferred` can arise — the bucket `deferred` in the report gets
//!   its first real entry, and `InstanceState::Stopped` at the leader thereby a
//!   new reason;
//! * `--no-quorum` at the agent starts to mean something;
//! * and the **input** becomes important: `context.quorum` is today a setting
//!   of the command line and no state derived from the session. Whoever checks
//!   a quorum-bound action without deriving it checks against a constant.
//!
//! That is no prohibition. It is the attention that is then demanded.

use std::path::Path;

use tg_model::autonomy::Action;

/// An action's name as `Debug` writes it — not as a hand-maintained table:
/// `Action::ALL` is already guarded by its length, and a second list would be
/// the source of error this project has measured several times.
fn action_named(name: &str) -> Option<Action> {
    Action::ALL
        .into_iter()
        .find(|action| format!("{action:?}") == name)
}

/// Collects the production part's Rust files, without test modules.
fn production_sources(root: &Path, into: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(root).expect("directory readable");
    for entry in entries {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            // `tests/` does not belong to it: there a quorum-bound action
            // **may** be checked, and that is exactly what the tests in
            // `tg-model` do.
            if path.file_name().is_some_and(|name| name == "tests") {
                continue;
            }
            production_sources(&path, into);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).expect("readable");
            // Everything from the first module-level `#[cfg(test)]` falls
            // away.
            let body = match text.find("\n#[cfg(test)]") {
                Some(at) => text[..at].to_owned(),
                None => text,
            };
            into.push((path.display().to_string(), body));
        }
    }
}

#[test]
fn every_checked_action_is_autonomous() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/");

    let mut sources = Vec::new();
    for entry in std::fs::read_dir(crates_dir).expect("crates/ readable") {
        let dir = entry.expect("entry").path().join("src");
        if dir.is_dir() {
            production_sources(&dir, &mut sources);
        }
    }
    assert!(
        sources.len() > 50,
        "only {} source files were found — the path is wrong, and a guard that \
         reads nothing confirms everything",
        sources.len()
    );

    let mut checked = Vec::new();
    for (file, body) in &sources {
        // Not `tg-model` itself: the rule stands there, not its application.
        if file.contains("tg-model/src") {
            continue;
        }
        for (line, text) in body.lines().enumerate() {
            let trimmed = text.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            // **`Action::` alone is no marker.** A foreign type with the same
            // suffix — `LinuxSeccompAction::ScmpActErrno` from `oci-spec`
            // (ADR-0090) — hit here as a false positive, and a guard that
            // produces false positives is switched off instead of read. What is
            // demanded is therefore the word boundary: no name component may
            // stand before `Action`.
            let Some(at) = trimmed.find("Action::").filter(|at| {
                *at == 0
                    || !trimmed[..*at]
                        .chars()
                        .next_back()
                        .is_some_and(|before| before.is_alphanumeric() || before == '_')
            }) else {
                continue;
            };
            let name: String = trimmed[at + "Action::".len()..]
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect();
            if name.is_empty() {
                continue;
            }
            let action = action_named(&name).unwrap_or_else(|| {
                panic!("{file}:{}: 'Action::{name}' is no known action", line + 1)
            });
            checked.push((format!("{file}:{}", line + 1), action));
        }
    }

    assert!(
        !checked.is_empty(),
        "not a single check found — either the autonomy boundary has vanished \
         from the production code, or this guard reads past its target"
    );

    let quorum_bound: Vec<&(String, Action)> = checked
        .iter()
        .filter(|(_, action)| !action.is_autonomous())
        .collect();

    assert!(
        quorum_bound.is_empty(),
        "a quorum-bound action is checked here: {quorum_bound:?}\n\n\
         With that `Verdict::Deferred` becomes reachable in operation. See the \
         module head: the bucket `deferred`, `--no-quorum` and the **input** \
         `context.quorum` become sharp in the same moment — and that one is \
         today a setting of the command line."
    );
}
