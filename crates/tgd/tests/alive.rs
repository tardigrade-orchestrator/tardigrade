//! A dead process is no condition one waits for.
//!
//! Nine waiting helpers of this crate report a **cause** when the deadline
//! expires, and four of them did not check whether the process was still alive
//! -- among them the one that measurably fell: `attestation.rs::await_leadership`
//! waited out its whole 30 s and afterwards reported "the node did not take over
//! the leadership", while it had died on a port conflict.
//!
//! The reason was the signature, not carelessness: the helpers are `&self`, and
//! `try_wait` demands a `&mut Child`. That is why [`support::alive`] checks over
//! `/proc/<pid>/stat` -- that needs only the PID.

mod support;

use std::process::{Command, Stdio};
use std::time::Duration;

/// **Both directions, because each alone says nothing.**
///
/// A check that always says "alive" is the world from before; one that always
/// says "dead" makes every test red that waits for something. The distinguishing
/// case is the **zombie**: measured, in Rust a child that has died is one until
/// somebody calls `wait` -- and the test rig calls it only in `Drop`. A `try_wait`
/// here would collect it and destroy the measurement.
#[test]
fn a_child_that_died_is_not_alive_and_a_running_one_is() {
    let mut child = Command::new("sleep")
        .arg("300")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep");
    let pid = child.id();

    assert!(
        support::alive(pid),
        "a running process must count as alive -- otherwise every waiting loop \
         is red immediately"
    );
    support::assert_alive(1, pid);

    child.kill().expect("kill");
    // No `try_wait`: it collects the zombie, and afterwards there is no `/proc`
    // entry any more -- the test would then check the wrong case.
    std::thread::sleep(Duration::from_millis(300));

    assert!(
        !support::alive(pid),
        "a process that has died ({pid}) counts as alive -- then every loop \
         waits out its whole deadline and reports the wrong cause"
    );

    // Collected only **after** the assertion: before it the zombie would be
    // gone, and the test would check the wrong case. Afterwards it must be -- a
    // zombie left lying is a remnant, and this tree has paid for remnants
    // several times.
    child.wait().expect("collect");
}

/// And the refusal names the reason and the way to it.
#[test]
fn the_refusal_names_the_node_and_where_its_reason_is() {
    let mut child = Command::new("sleep")
        .arg("300")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep");
    let pid = child.id();
    child.kill().expect("kill");
    std::thread::sleep(Duration::from_millis(300));

    let finding = std::panic::catch_unwind(|| support::assert_alive(7, pid))
        .expect_err("a dead process must abort");
    let text = finding
        .downcast_ref::<String>()
        .map_or_else(|| "no text".to_owned(), Clone::clone);

    assert!(
        text.contains("node 7") && text.contains("tg-test-logs"),
        "the refusal does not name which node and where its reason stands: {text}"
    );

    child.wait().expect("collect");
}

/// **Every waiting helper with a cause message checks whether its node is
/// alive.**
///
/// That is the wiring the witness above does not cover: it checks the *rule*,
/// not that somebody calls it. And the rule has a history here -- it was built in
/// `cluster.rs` and **did not travel** into three neighbouring files; measured,
/// four of nine helpers did not check.
///
/// Indirectly counts: five of the nine go through `wait_for_leader` every round,
/// and that checks. What the guard cannot do thereby stands fixed too -- it reads
/// names, not reachability: a helper that calls `wait_for_leader` in only one arm
/// counts as covered for it.
///
/// **Caught up:** the list enumerated four files, and `tgd/tests` has nine with
/// waiting helpers -- the finding of that time thereby travelled into four and
/// not into nine. With the directory collector there are **twelve** helpers
/// instead of eight, and **all check**: the rule had travelled, only this guard
/// did not see it.
#[test]
fn every_waiting_helper_that_names_a_cause_checks_for_life() {
    // **Read instead of enumerated.** The list knew four files, and `tgd/tests`
    // has nine with waiting helpers -- the finding of that time ("a dead process
    // is no condition") thereby travelled into four and not into nine. Sixth
    // place of this shape in this tree.
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files: Vec<(String, String)> = std::fs::read_dir(&directory)
        .expect("tgd/tests must be readable")
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
    files.sort();
    assert!(
        files.len() >= 15,
        "only {} test files in tgd/tests -- the search does not take hold",
        files.len()
    );

    let mut checked = 0;
    let mut without = Vec::new();

    for (name, source) in files {
        for (nr, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            let is_helper = (trimmed.starts_with("fn ") || trimmed.starts_with("async fn "))
                && line.contains("(&self")
                || line.contains("(&mut self");
            if !is_helper {
                continue;
            }

            // Body: up to the first line that closes at the same depth.
            let indent = line.len() - trimmed.len();
            let body: Vec<&str> = source
                .lines()
                .skip(nr + 1)
                .take_while(|l| {
                    let t = l.trim_start();
                    t.is_empty() || l.len() - t.len() > indent || !t.starts_with('}')
                })
                .collect();
            let body = body.join("\n");

            let waits =
                body.contains("sleep") && (body.contains("deadline") || body.contains("PATIENCE"));
            let reports = body.contains("panic!") || body.contains("assert!");
            if !waits || !reports {
                continue;
            }

            checked += 1;
            let lives = body.contains("assert_alive")
                || body.contains("assert_all_alive")
                || body.contains("wait_for_leader()")
                || body.contains("await_leadership()")
                || body.contains("await_admin");
            if !lives {
                without.push(format!("{name}:{}", nr + 1));
            }
        }
    }

    assert!(
        checked >= 10,
        "only {checked} waiting helpers found -- the haystack has fallen away, \
         and without it this guard confirms everything"
    );
    assert!(
        without.is_empty(),
        "these waiting helpers report a cause and do not check whether their \
         node is alive -- they then wait out their whole deadline and afterwards \
         name the wrong one: {without:?}"
    );
}

/// **Two versions of `await_leaf`, and they must have the same body.**
///
/// Measured, they had gone apart: the one names the log path and the frequent
/// cause, the other said only "tgd wrote no cluster leaf". And the better one
/// says in its message expressly what is missing here -- *"the waiting loop here
/// does not see that"*, that is, exactly the case this witness has just closed in
/// four other helpers.
///
/// There are two versions for the same reason as with `Running` and
/// [`support::alive`]: a test helper across crate boundaries would need a crate
/// of its own (ADR-0023). What the guard holds is that they stay **equal**.
///
/// That it **reads** across the crate boundary for that is no coupling in the
/// build: no `use`, no edge in `Cargo.toml`, only a text comparison. The coupling
/// would be a shared type -- and that is exactly what the doubling avoids.
#[test]
fn both_copies_of_await_leaf_say_the_same() {
    fn body(source: &str) -> String {
        let start = source
            .find("fn await_leaf(")
            .expect("await_leaf must stand in both versions");
        let open = source[start..].find('{').expect("body") + start;
        let mut depth = 0usize;
        for (at, character) in source[open..].char_indices() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return source[open..=open + at].to_owned();
                    }
                }
                _ => {}
            }
        }
        panic!("body not closed");
    }

    let here = body(include_str!("support/mod.rs"));
    let there = body(include_str!("../../tg-agent/tests/support/mod.rs"));

    assert!(
        here.len() > 200,
        "the body is too short ({} characters) -- then this guard compares \
         nothing",
        here.len()
    );
    assert_eq!(
        here, there,
        "the two versions of `await_leaf` have gone apart -- one names the way \
         to the reason and the other does not"
    );
}
