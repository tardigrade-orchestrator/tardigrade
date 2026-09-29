//! What `Running::drop` takes along -- and why it must be the children.
//!
//! # The finding this witness holds
//!
//! A `tgd` starts child processes, and `tg-agent` `crun`/`youki`. Whoever kills
//! only the pid when clearing up leaves it running -- and it afterwards creates
//! its `--root`: measured, `crun --root <dir>/runtime delete` creates the
//! directory **even when it finds nothing to delete**. What is left behind is a
//! temp directory containing only `runtime/`, and the `TempDir` was long cleared
//! away by then.
//!
//! The same assurance as in the neighbouring crate, and it stands there **twice**
//! because `Running` exists twice: `tgd` and `tg-agent` each have a `support`
//! module of their own, and an assurance in one says nothing about the other.
//!
//! # Why here and not over a rate
//!
//! The leak is a **race**: measured, two consecutive workspace runs leaked, three
//! others not a single one -- in both worlds. A counter-check over counts
//! therefore does not separate. This witness therefore **produces** the race: a
//! parent whose child outlives it.

mod support;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use support::Running;

/// Whether a pid still exists.
fn alive(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// A parent that starts a long-lived child and waits itself.
///
/// `sh -c 'sleep 600 & echo $!; wait'` -- the child writes its pid to stdout so
/// that the test knows it without searching `/proc`.
fn parent_with_child() -> (Running, u32) {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("sleep 600 & echo $!; wait")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("sh");

    let mut line = String::new();
    {
        use std::io::{BufRead as _, BufReader};
        let out = child.stdout.take().expect("stdout");
        BufReader::new(out).read_line(&mut line).expect("pid");
    }
    let grandchild: u32 = line.trim().parse().expect("the pid is a number");

    (Running(child), grandchild)
}

/// **The child dies with the parent.**
///
/// Without this assurance a `crun` the agent started outlives the test run -- and
/// afterwards creates a directory nobody clears away any more.
#[test]
fn dropping_a_process_takes_its_children_with_it() {
    let (running, grandchild) = parent_with_child();

    // **First the counter-direction:** it really is running. Without it the "is
    // gone" below would say nothing -- a `sleep` that never started is gone too.
    assert!(
        alive(grandchild),
        "the child must be running, otherwise this test checks nothing"
    );

    drop(running);

    // `kill` is asynchronous: the kernel clears the entry away when the process
    // has been reaped. One second of patience, and the failure case needs all of
    // it -- a surviving `sleep 600` does not disappear afterwards either.
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline && alive(grandchild) {
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(
        !alive(grandchild),
        "the child {grandchild} outlived the parent -- a `crun` in this \
         situation creates its --root after `TempDir::drop`"
    );
}
