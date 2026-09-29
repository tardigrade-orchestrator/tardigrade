//! Who marks a `watch` value as seen (ADR-0040).
//!
//! Four loops in `tgd` read the Raft metrics and then wait for a change -- the
//! trust refresher (`cluster.rs`), the readiness loop (`health.rs`), the slice
//! server (`session.rs`) and the scheduler. All four use `borrow_and_update()`,
//! and three justified that with a **hot loop**: `borrow()` supposedly does not
//! mark the value, so `changed()` returns immediately.
//!
//! **Measured that is false**, and the witnesses here hold why: in both loop
//! structures of this tree (`changed()` alone at the end, and `changed()` in a
//! `select!`) `borrow()` and `borrow_and_update()` behave identically, because
//! `changed()` marks **itself**. Measured, the comment came with the code -- there
//! never was a checked-in `borrow()` at that place, so the hot loop is not
//! substantiated.
//!
//! What `borrow_and_update()` then carries is the **second** witness:
//! `has_changed()` does not mark, and there `borrow()` really would be a loop
//! that burns a core. The form is thereby the robust one -- it holds even when
//! somebody one day replaces the `changed()` with a `has_changed()` or takes it
//! out of the loop.
//!
//! The file lies in `tgd` because the four loops lie there. It checks a property
//! of `tokio::sync::watch` -- the same class as `gauge_decay.rs` for the
//! Prometheus exporter: a foreign assurance on which a justification of our own
//! rests belongs in the tree as a witness and not in a commit message. `tokio`
//! stands in the manifest as `"1"`, that is, as a range.

use tokio::sync::watch;

/// `changed()` marks the value itself -- even after a `borrow()`.
///
/// With that `borrow_and_update()` in `loop { borrow(); changed().await }` is
/// **redundant**: the number of rounds is the same in both worlds.
#[tokio::test]
async fn changed_marks_the_value_itself() {
    let (tx, mut rx) = watch::channel(0u64);

    tx.send(1).expect("send");

    // Read without marking.
    assert_eq!(*rx.borrow(), 1, "the setup must take hold");

    // The first `changed()` returns immediately -- the change is unseen. **And
    // it marks.**
    rx.changed().await.expect("the first change");

    // So the second one waits. Without the marking by `changed()` it would come
    // back immediately, and the loop ran hot.
    let waits = tokio::time::timeout(std::time::Duration::from_millis(50), rx.changed()).await;
    assert!(
        waits.is_err(),
        "`changed()` came back immediately a second time -- then it does not \
         mark the value itself, and the justification of the four loops in \
         `tgd` would after all be the hot loop (ADR-0040)"
    );
}

/// `has_changed()` does **not** mark -- and there the difference counts.
///
/// That is the case `borrow_and_update()` covers in the four loops: whoever
/// replaces the `changed()` with a query gets with `borrow()` a loop that never
/// waits.
#[tokio::test]
async fn has_changed_does_not_mark_and_borrow_and_update_does() {
    let (tx, mut rx) = watch::channel(0u64);
    tx.send(1).expect("send");

    // Read twice and ask twice: the answer stays "changed".
    for round in 1..=2 {
        assert_eq!(*rx.borrow(), 1);
        assert!(
            rx.has_changed().expect("channel open"),
            "round {round}: `borrow()` marked the value -- then the robustness \
             justification of `borrow_and_update()` does not carry"
        );
    }

    // Only `borrow_and_update` marks.
    assert_eq!(*rx.borrow_and_update(), 1);
    assert!(
        !rx.has_changed().expect("channel open"),
        "`borrow_and_update()` did not mark the value"
    );
}
