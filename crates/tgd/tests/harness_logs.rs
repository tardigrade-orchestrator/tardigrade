//! The test rig can say why a test fell.
//!
//! # Why this exists
//!
//! 79 spawn places wrote their child processes' output to `/dev/null`, and the
//! price is measured: when the ADR-0076 witness fell in the full run, there was
//! **no log** -- the cause had to be derived from the constants, and whether it
//! was the cause is to this day not substantiated. That is the same shortcoming
//! this tree fixed at the sidecar (`alert`), at the identity service (`refusal`)
//! and at the DNS forwarder, only in the test rig.
//!
//! What is checked here is the **seam**, not the panic hook: that a child's
//! output really lands in this test's file, and that the logs of earlier runs are
//! cleared away. The hook itself fires only on a panic; checking it would mean
//! deliberately letting a test fall and reading its own error message.

mod support;

/// **A child's output lands in this test's file.**
///
/// The file name carries the **thread name**, and `libtest` names its threads
/// after the test -- that is why every test has its own file, even when seventeen
/// of them run concurrently in one binary. Without this property the tail the
/// panic hook shows would be that of a foreign test.
#[test]
fn a_childs_output_lands_in_this_tests_log() {
    let path = support::log_path("probe");
    let _ = std::fs::remove_file(&path);

    let status = std::process::Command::new("sh")
        .args(["-c", "echo hello-from-the-child; echo error >&2"])
        .stdout(support::log("probe"))
        .stderr(support::log("probe"))
        .status()
        .expect("sh startable");
    assert!(status.success());

    let text = std::fs::read_to_string(&path).expect("log");
    assert!(
        text.contains("hello-from-the-child") && text.contains("error"),
        "both streams must stand in the same file: {text}"
    );
    assert!(
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains("a_childs_output_lands")),
        "the file name does not carry the test name: {}",
        path.display()
    );
}

/// **Logs of earlier runs are cleared away, this run's are not.**
///
/// Both directions, and the second one carries: a sweep that takes *everything*
/// would delete the log of a concurrently running process of the **same** run --
/// and with it the diagnosis at issue.
///
/// Without the sweep `<temp>/tg-test-logs` grows with every run. Unbounded growth
/// in `/tmp` has already filled the disk twice in this tree.
#[test]
fn old_logs_are_swept_and_current_ones_are_not() {
    let root = std::env::temp_dir().join("tg-test-logs");
    let old = root.join("999999-old-for-the-test");
    std::fs::create_dir_all(&old).expect("directory");
    let stale = std::time::SystemTime::now() - std::time::Duration::from_hours(2);
    let file = std::fs::File::create(old.join("marker")).expect("file");
    file.set_modified(stale).expect("mtime");
    filetime_of(&old, stale);

    // And a fresh one, which must stay.
    let fresh = support::log_path("probe-fresh");
    std::process::Command::new("sh")
        .args(["-c", "echo fresh"])
        .stdout(support::log("probe-fresh"))
        .status()
        .expect("sh");

    support::sweep_old_logs();

    assert!(
        !old.exists(),
        "the old directory {} is still lying there",
        old.display()
    );
    assert!(
        fresh.exists(),
        "this run's log was cleared away: {}",
        fresh.display()
    );
}

/// Sets a directory's mtime, as far as `std` can do that.
fn filetime_of(dir: &std::path::Path, at: std::time::SystemTime) {
    // `std` cannot set the mtime of a **directory**; creating a file in it has
    // just updated it. So once more: a directory whose content is old counts as
    // old as soon as the directory mtime is -- and that comes here from the last
    // write.
    if let Ok(file) = std::fs::File::open(dir) {
        let _ = file.set_modified(at);
    }
}

// --- Waiting that names the cause ------------------------------------------

/// **A dead process is a finding, not a condition.**
///
/// The finding from `cluster.rs` (`assert_all_alive`), found again at a second
/// and third place: two waiting places waited out their whole patience and
/// reported "the socket did not come up" -- even when the process had long died.
/// An operator of this test rig looks for that in the product.
///
/// **The two names are withdrawn here**, because one of the named functions no
/// longer existed (`admin_socket::await_socket` -- there `node()` has waited
/// itself since) and the other calls [`support::await_admin`](support) today. A
/// reference to a function that does not exist is a coverage one cannot look up.
///
/// The witness checks the **distinction**, not the speed: a child that ends
/// without creating the file must name the one case.
#[test]
#[should_panic(expected = "ended itself")]
fn a_dead_child_is_named_instead_of_waited_out() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 3"])
        .spawn()
        .expect("startable");

    support::await_file(
        &mut child,
        &dir.path().join("never-comes"),
        std::time::Duration::from_secs(20),
    );
}

/// And the counter-direction: a child that creates the file gets through.
///
/// Without it an `await_file` that declares **every** child dead would be just as
/// green -- and no test of this rig would get past its setup any more.
#[test]
fn a_child_that_creates_the_file_gets_through() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("there");
    let mut child = std::process::Command::new("/bin/sh")
        .args([
            "-c",
            &format!("sleep 0.2; touch {}; sleep 5", path.display()),
        ])
        .spawn()
        .expect("startable");

    support::await_file(&mut child, &path, std::time::Duration::from_secs(20));

    assert!(path.exists(), "the file must be there");
    let _ = child.kill();
}

// --- Waiting for the admin socket ------------------------------------------

/// **A socket that accepts gets through.**
///
/// The counter-direction of the two witnesses below -- without it an
/// `await_admin` that waits on principle would be just as green, and no test rig
/// would get to its client any more.
#[tokio::test(flavor = "multi_thread")]
async fn a_listening_socket_gets_through() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("admin.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 30"])
        .spawn()
        .expect("startable");

    let _client =
        support::await_admin_within(&path, &mut [&mut child], std::time::Duration::from_secs(2));
    let _ = child.kill();
}

/// **A file at the socket path is no socket.**
///
/// The assurance the superseded version did not have: it checked `path.exists()`
/// and would have got through here -- the call after it then red. The case is not
/// constructed: `tgd` removes a socket left lying at startup so that a crashed
/// one comes up again, and in exactly that window the predecessor's inode is
/// still there.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "accepts no calls")]
async fn a_plain_file_is_not_a_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("admin.sock");
    std::fs::write(&path, b"no socket").expect("writable");
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 30"])
        .spawn()
        .expect("startable");

    let _client = support::await_admin_within(
        &path,
        &mut [&mut child],
        std::time::Duration::from_millis(300),
    );
    let _ = child.kill();
}

/// **And a dead process is named, not waited out.**
///
/// The same finding as above for the file variant, at the waiting place that
/// originally had it (`signing::wait_for_admin`) -- now it has it at one place for
/// all three callers.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "ended itself")]
async fn a_dead_node_is_named_instead_of_waited_out_for_its_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("admin.sock");
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 3"])
        .spawn()
        .expect("startable");
    // Wait until it has really ended -- otherwise the witness checks a race.
    let _ = child.wait();

    let _client =
        support::await_admin_within(&path, &mut [&mut child], std::time::Duration::from_secs(5));
}
