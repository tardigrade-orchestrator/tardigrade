//! The join token and its digest (ADR-0037).
//!
//! # Why this lies here
//!
//! Both belong to the **credential path**: `tgctl node invite` produces the token,
//! `tgd` checks it against the digest in the log. It lay in the consensus core, and
//! for it the CLI linked `openraft` and `redb` (ADR-0134, ADR-0137) -- for two
//! functions that need entropy and a hash.
//!
//! The consensus core re-exports them under the path it knows them by.

#[must_use]
pub fn generate_token() -> String {
    let mut bytes = [0_u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);

    bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[must_use]
pub fn token_digest(token: &str) -> String {
    // **`ring` and not `sha2`** (ADR-0023): this crate has `ring` as a crypto
    // provider anyway, and two libraries for SHA-256 would be two supply chains
    // with two exit strategies. The guard
    // `no_crate_uses_two_libraries_for_one_job` reported it at the move -- in the
    // consensus core `sha2` lay alone, here it does not.
    //
    // The same bytes: SHA-256 is SHA-256, and the digest stands in the log
    // (ADR-0037) -- a different value would let every existing invitation
    // lapse.
    let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());

    digest
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}
