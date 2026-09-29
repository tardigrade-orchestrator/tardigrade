//! How many descriptors this process holds — and how many it may hold.
//!
//! The test lies **alone in its file**, because it touches `RLIMIT_NOFILE` and
//! the limit belongs to the process, not to the test (`cargo test` runs the
//! tests of a file concurrently). For the same reason it is **one** test
//! function and not two: the second half lowers the limit, and the first opens
//! files.

use tg_syscall::fds;

#[test]
fn the_count_follows_what_the_process_opens_and_the_limit_is_the_soft_one() {
    let before = fds::open().expect("/proc/self/fd readable");

    let held: Vec<std::fs::File> = (0..5)
        .map(|_| std::fs::File::open("/dev/null").expect("openable"))
        .collect();

    let after = fds::open().expect("/proc/self/fd readable");
    // **The difference is the assurance, not the absolute value.** It is exact
    // even though the number counts the descriptor with which it was read — and
    // a counter that does not move would be indistinguishable from a constant.
    assert_eq!(after - before, 5, "five open files are five descriptors");

    drop(held);
    assert_eq!(
        fds::open().expect("readable"),
        before,
        "and they disappear again"
    );

    // The **soft** limit is the one that bites. Set and taken back — without the
    // restoration the rest of this test binary would be bounded at 512
    // descriptors.
    let previous = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(512),
            maximum: previous.maximum,
        },
    )
    .expect("limit lowerable");

    let reported = fds::limit();
    rustix::process::setrlimit(rustix::process::Resource::Nofile, previous)
        .expect("limit restored");

    assert_eq!(
        reported,
        Some(512),
        "what is reported is the soft limit, not the hard one"
    );
}
