//! The join token and its digest (ADR-0037, ADR-0137).
//!
//! They lay in the consensus core, and `tgctl node invite` linked `openraft` and
//! `redb` for that. Here they lie at the credential path -- and here stands the
//! witness that distinguishes the move from a change.

/// **The digest stays byte for byte the same** (ADR-0137).
///
/// At the move out of the consensus core `sha2` came along -- and `tg-identity` has
/// `ring` as its crypto provider anyway. Two libraries for SHA-256 are two supply
/// chains with two exit strategies (ADR-0023); the guard
/// `no_crate_uses_two_libraries_for_one_job` reported it.
///
/// The change must not alter the **value**: it stands in the log (ADR-0037), and a
/// different one would let every existing invitation lapse. Therefore a nailed-down
/// vector here instead of a computation that uses the same library -- otherwise the
/// test would check itself.
#[test]
fn the_token_digest_is_plain_sha256() {
    assert_eq!(
        tg_identity::join::token_digest("probe"),
        "ba9c736f19e7f60b7f6764adb0b7908c0a2b394e09b6c09863528c7f2bc86095"
    );
    // And the length, because a hex writer without padding would come out shorter.
    assert_eq!(tg_identity::join::token_digest("").len(), 64);
}
