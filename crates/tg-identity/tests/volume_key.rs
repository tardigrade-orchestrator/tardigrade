//! A volume's derived passphrase (ADR-0113, determination 2).
//!
//! The derivation is a pure function and is checked here without a kernel -- the LUKS
//! path beside it needs loop devices and runs in `cargo xtask storage`. What stands
//! here are the four properties on which the decision rests.

use tg_identity::secrets::DataKey;

/// A fixed key, so that the assurances hang on numbers and not on randomness. **No
/// real key material** -- 32 bytes from a count.
fn key() -> DataKey {
    let bytes: Vec<u8> = (0_u8..32).collect();
    DataKey::from_base64(&base64_encode(&bytes)).expect("key")
}

fn base64_encode(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// **The same input yields the same passphrase.**
///
/// That is the assurance on which everything hangs: the node derives it anew at
/// **every** mount instead of storing it. If it were not deterministic, a volume
/// could be opened exactly once.
#[test]
fn the_same_key_and_name_give_the_same_passphrase() {
    assert_eq!(
        key().volume_passphrase("data"),
        key().volume_passphrase("data")
    );
}

/// **A volume's passphrase opens no other one.**
///
/// The reason for the derivation *per volume* instead of per cluster.
#[test]
fn two_volumes_get_different_passphrases() {
    let k = key();
    assert_ne!(k.volume_passphrase("data"), k.volume_passphrase("ledger"));
}

/// **Two clusters share no passphrase**, not even for the same name.
///
/// Otherwise a volume that stems from another cluster would open here -- and a restore
/// across the cluster boundary would be silently possible.
#[test]
fn two_clusters_get_different_passphrases() {
    let other = DataKey::generate().expect("key");
    assert_ne!(
        key().volume_passphrase("data"),
        other.volume_passphrase("data")
    );
}

/// **The data key is never itself the passphrase** (the pitfall from ADR-0039).
///
/// The counter-check to the decision that ADR took: had somebody built option A, this
/// test would be red.
#[test]
fn the_passphrase_is_not_the_data_key() {
    let k = key();
    let passphrase = k.volume_passphrase("data");

    assert_ne!(passphrase, k.to_base64());
    assert!(
        !passphrase.contains(&k.to_base64()),
        "the key must not occur in the passphrase"
    );
}

/// **The form is hex, 64 characters, without a line break** (determination 3).
///
/// It goes over stdin to `cryptsetup`. NUL and a line break in key material are the
/// sort of detail that goes wrong once and afterwards never stands out again.
#[test]
fn the_passphrase_is_plain_hex() {
    let passphrase = key().volume_passphrase("data");

    assert_eq!(passphrase.len(), 64, "{passphrase}");
    assert!(
        passphrase.bytes().all(|b| b.is_ascii_hexdigit()),
        "{passphrase}"
    );
}

/// **A prefix is no name.**
///
/// `data` and `data2` must get different passphrases -- the same finding as at the
/// egress allowlist, where `api-test` does not get what `api` is permitted.
#[test]
fn a_prefix_is_not_a_name() {
    let k = key();
    assert_ne!(k.volume_passphrase("data"), k.volume_passphrase("data2"));
}
