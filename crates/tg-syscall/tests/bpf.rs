//! The proof that no eBPF is loaded — the measuring instrument (phase 9b).
//!
//! This file checks the **tool**, not the network. That the setup of the
//! container network loads no program is checked by `tg-net`. But a proof whose
//! measuring instrument is unchecked is none: an enumeration that always comes
//! back empty confirms every claim.
//!
//! Enumerating needs no special privileges, so these tests run everywhere.

use tg_syscall::bpf;

/// The enumeration has to be possible on this kernel at all — otherwise every
/// proof resting on it would be a proof about nothing.
#[test]
fn the_enumeration_works_on_this_kernel() {
    assert!(
        bpf::enumeration_available(),
        "bpf(BPF_PROG_GET_NEXT_ID) is not usable here; a proof of \
         'no BPF loaded' would be worthless on this kernel"
    );
}

/// Asking twice gives the same answer as long as nothing happens. Without that
/// property the before/after comparison would be worthless.
#[test]
fn asking_twice_without_doing_anything_gives_the_same_answer() {
    let first = bpf::loaded_programs().expect("enumerable");
    let second = bpf::loaded_programs().expect("enumerable");
    assert_eq!(first, second);
}

/// The identifiers come ascending and without duplicates — otherwise the
/// enumeration would run in circles, and an "empty" would be indistinguishable
/// from an abort.
#[test]
fn the_ids_are_ascending_and_unique() {
    let ids = bpf::loaded_programs().expect("enumerable");

    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();

    assert_eq!(ids, sorted, "identifiers duplicated or unsorted: {ids:?}");
}
