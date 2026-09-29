//! The data key for secrets at rest (ADR-0095).
//!
//! Written **before** the implementation. What is checked here is pure logic and
//! needs no cluster: a key, a sealing, an opening -- and the three refusals for whose
//! sake the procedure exists.

use tg_identity::secrets::SealedExt as _;
use tg_identity::secrets::{DataKey, KeyRing, MAX_SECRET_BYTES, SealError, Sealed};

/// **What was sealed can be opened** -- the counter-check to everything else.
/// Without it a procedure that refuses every opening would be green.
#[test]
fn what_was_sealed_opens_again() {
    let key = DataKey::generate().expect("key");
    let sealed = key.seal(b"hunter2").expect("sealable");

    assert_eq!(key.open(&sealed).expect("to open"), b"hunter2");
}

/// **Two sealings of the same plaintext are different.**
///
/// The nonce arises **at the sealing** (ADR-0095, determination 3), not at the
/// caller. If they were equal, the ciphertext would give away that two secrets have
/// the same value -- and a repeated nonce under the same key would give the plaintext
/// away. The same discipline as in the `NonceVault` from 7b: it lies in the
/// **structure**, not in the care.
#[test]
fn the_same_plaintext_seals_differently_every_time() {
    let key = DataKey::generate().expect("key");

    let first = key.seal(b"the same value").expect("sealable");
    let second = key.seal(b"the same value").expect("sealable");

    assert_ne!(
        first.ciphertext, second.ciphertext,
        "two sealings are equal -- then the nonce is not per value"
    );
    assert_ne!(first.nonce, second.nonce, "the nonce repeats itself");
}

/// **A foreign key opens nothing.**
#[test]
fn a_foreign_key_opens_nothing() {
    let sealed = DataKey::generate()
        .expect("key")
        .seal(b"hunter2")
        .expect("sealable");

    assert!(matches!(
        DataKey::generate().expect("key").open(&sealed),
        Err(SealError::NotAuthentic)
    ));
}

/// **A bent ciphertext is refused, not half opened.**
///
/// That is the whole difference between an AEAD and a cipher: whoever changes the
/// ciphertext gets an error and no different plaintext.
#[test]
fn a_tampered_ciphertext_is_refused() {
    let key = DataKey::generate().expect("key");
    let mut sealed = key.seal(b"hunter2").expect("sealable");
    sealed.ciphertext[0] ^= 0x01;

    assert!(matches!(key.open(&sealed), Err(SealError::NotAuthentic)));
}

/// **And a bent nonce likewise** -- it stands beside the ciphertext and is thereby
/// just as much in the hand of whoever reads the archive.
#[test]
fn a_tampered_nonce_is_refused() {
    let key = DataKey::generate().expect("key");
    let mut sealed = key.seal(b"hunter2").expect("sealable");
    sealed.nonce[0] ^= 0x01;

    assert!(matches!(key.open(&sealed), Err(SealError::NotAuthentic)));
}

/// **The key reads back as it was written.**
///
/// It travels over the credential path (ADR-0095, determination 2) and lies
/// afterwards in `identity/` -- so it must fit through a string without changing.
#[test]
fn a_key_survives_the_round_trip() {
    let key = DataKey::generate().expect("key");
    let text = key.to_base64();

    let read = DataKey::from_base64(&text).expect("readable");
    let sealed = key.seal(b"hunter2").expect("sealable");

    assert_eq!(read.open(&sealed).expect("to open"), b"hunter2");
}

/// **A key of the wrong length is refused, not padded.**
///
/// Padded it would be a key with less entropy than its name promises -- and nobody
/// would see it.
#[test]
fn a_key_of_the_wrong_length_is_refused() {
    for text in ["", "AAAA", "not base64!!"] {
        assert!(
            DataKey::from_base64(text).is_err(),
            "'{text}' was read as a key"
        );
    }
}

/// **The ciphertext does not carry the plaintext** -- the most banal assurance, and
/// the one for whose sake the procedure stands in the log (ADR-0020).
#[test]
fn the_ciphertext_does_not_carry_the_plaintext() {
    let key = DataKey::generate().expect("key");
    let sealed = key.seal(b"strictly-secret").expect("sealable");

    assert!(
        !sealed
            .ciphertext
            .windows(b"strictly-secret".len())
            .any(|window| window == b"strictly-secret"),
        "the plaintext stands in the ciphertext"
    );
}

/// An empty value is a value.
#[test]
fn an_empty_value_seals_and_opens() {
    let key = DataKey::generate().expect("key");
    let sealed = key.seal(b"").expect("sealable");

    assert!(key.open(&sealed).expect("to open").is_empty());
}

/// **Two keys are different** -- the counter-check to `generate`.
#[test]
fn two_generated_keys_differ() {
    assert_ne!(
        DataKey::generate().expect("key").to_base64(),
        DataKey::generate().expect("key").to_base64()
    );
}

/// The envelope can be carried through JSON -- it travels in the log (ADR-0004).
#[test]
fn a_sealed_value_survives_json() {
    let key = DataKey::generate().expect("key");
    let sealed = key.seal(b"hunter2").expect("sealable");

    let text = serde_json::to_string(&sealed).expect("serializable");
    let read: Sealed = serde_json::from_str(&text).expect("readable");

    assert_eq!(key.open(&read).expect("to open"), b"hunter2");
}

/// **The same key yields the same fingerprint, a different one a different**
/// (ADR-0095).
///
/// Both directions, because both carry: without the first a fingerprint that dices at
/// every call would be green likewise -- and then **one** node would report a new time
/// series per scrape. Without the second a constant one would be green, and the offset
/// would stay invisible.
#[test]
fn the_fingerprint_follows_the_key() {
    let key = DataKey::generate().expect("key");
    let same = DataKey::from_base64(&key.to_base64()).expect("readable");
    assert_eq!(key.fingerprint(), same.fingerprint());

    let other = DataKey::generate().expect("key");
    assert_ne!(
        key.fingerprint(),
        other.fingerprint(),
        "two keys with the same fingerprint -- then the offset is invisible"
    );
}

/// **The fingerprint is no key**, and it does not look like one either.
///
/// Eight hex characters against 44 characters of base64: whoever sees it in a log line
/// cannot take it for the key -- and it does not contain it.
#[test]
fn the_fingerprint_is_not_the_key() {
    let key = DataKey::generate().expect("key");
    let print = key.fingerprint();

    assert_eq!(print.len(), 8, "{print}");
    assert!(
        print.chars().all(|c| c.is_ascii_hexdigit()),
        "no hex: {print}"
    );
    assert!(
        !key.to_base64().contains(&print),
        "the fingerprint sits in the key: {print}"
    );
}

// ================================================ The key ring (ADR-0100)

/// The heart: sealing happens with the **primary**.
///
/// The other way round -- with the one to be replaced -- the rotation would write
/// values nobody can open any more after step 5.
#[test]
fn a_ring_seals_with_its_primary() {
    let primary = DataKey::generate().expect("key");
    let previous = DataKey::generate().expect("key");
    let primary_print = primary.fingerprint();

    let ring = KeyRing::new(primary, Some(previous));
    let sealed = ring.seal(b"value").expect("sealable");

    // The evidence is that **only** the primary opens it: a `Sealed` carries no key
    // hint, so the attempt to open is the statement.
    let alone = KeyRing::new(
        DataKey::from_base64(&ring.primary().to_base64()).expect("key"),
        None,
    );
    assert_eq!(alone.primary().fingerprint(), primary_print);
    assert_eq!(
        alone.open(&sealed).expect("the primary must open"),
        b"value"
    );
}

/// **Both open** -- on that rests the windowless re-keying (ADR-0100,
/// determination 1).
///
/// As long as both lie there, it is indifferent which one a value was sealed with.
/// Without that property every rotation would have a window in which a container
/// cannot open its secret.
#[test]
fn a_ring_opens_with_either_key() {
    let primary = DataKey::generate().expect("key");
    let previous = DataKey::generate().expect("key");

    let old_ciphertext = previous.seal(b"from the old one").expect("sealable");
    let new_ciphertext = primary.seal(b"from the new one").expect("sealable");

    let ring = KeyRing::new(primary, Some(previous));

    assert_eq!(
        ring.open(&new_ciphertext).expect("new"),
        b"from the new one"
    );
    assert_eq!(
        ring.open(&old_ciphertext).expect("old"),
        b"from the old one"
    );
}

/// A ring without a key to be replaced opens **only** its own.
///
/// That is the counter-check to the test above: without it a ring that accepts every
/// ciphertext would be green likewise -- and then "both open" would say nothing.
#[test]
fn a_ring_without_a_previous_key_refuses_a_foreign_ciphertext() {
    let foreign = DataKey::generate().expect("key");
    let sealed = foreign.seal(b"foreign").expect("sealable");

    let ring = KeyRing::new(DataKey::generate().expect("key"), None);

    let err = ring
        .open(&sealed)
        .expect_err("a foreign ciphertext must not open");
    assert!(
        err.to_string().contains("does not belong to this key"),
        "expected the crypto refusal, got: {err}"
    );
}

/// **Whether a value has already been re-keyed** is the question at which a rotation
/// becomes completable (ADR-0100, determination 3).
///
/// Without it an operator would not know when they may remove the old key -- and if
/// they removed it too early, every value not reached would be unreadable.
#[test]
fn a_ring_says_whether_a_value_still_needs_rekeying() {
    let primary = DataKey::generate().expect("key");
    let previous = DataKey::generate().expect("key");

    let old_ciphertext = previous.seal(b"old").expect("sealable");
    let new_ciphertext = primary.seal(b"new").expect("sealable");

    let ring = KeyRing::new(primary, Some(previous));

    assert!(
        ring.needs_rekey(&old_ciphertext),
        "a value of the key to be replaced needs the re-keying"
    );
    assert!(
        !ring.needs_rekey(&new_ciphertext),
        "a value of the primary does not need it"
    );
}

/// A ring without a key to be replaced has nothing to re-key.
///
/// **Not even what it cannot open.** A foreign ciphertext would otherwise be "needs
/// re-keying" -- and the number from determination 3 would stand above zero forever
/// while nobody could do anything.
#[test]
fn without_a_previous_key_nothing_needs_rekeying() {
    let foreign = DataKey::generate().expect("key");
    let unopenable = foreign.seal(b"foreign").expect("sealable");

    let ring = KeyRing::new(DataKey::generate().expect("key"), None);

    assert!(!ring.needs_rekey(&unopenable));
}

/// The ring's fingerprint is the primary's.
///
/// On that hangs the alarm rule from ADR-0095, which catches two `tgd` with different
/// keys: it asks for the one that **seals**.
#[test]
fn the_ring_reports_the_fingerprint_of_its_primary() {
    let primary = DataKey::generate().expect("key");
    let print = primary.fingerprint();
    let ring = KeyRing::new(primary, Some(DataKey::generate().expect("key")));

    assert_eq!(ring.fingerprint(), print);
}

/// [`Sealed::plaintext_len`] computes the tag out -- and does not underflow.
///
/// The number carries a warning in the read path: it is the only one with which an
/// operator finds a secret above [`MAX_SECRET_BYTES`] before it costs its container at
/// the next start (ADR-0098, determination 7).
///
/// The second half is the carrying one: a ciphertext **without room for the tag** is
/// none, and an underflow would since ADR-0082 yield a panic -- in a read path an
/// operator calls in an incident.
#[test]
fn the_plaintext_length_leaves_the_tag_out_and_never_underflows() {
    let key = DataKey::generate().expect("key");
    for len in [0usize, 1, 4096, MAX_SECRET_BYTES] {
        let sealed = key.seal(&vec![b'x'; len]).expect("seal");
        assert_eq!(sealed.plaintext_len(), len, "at {len} bytes of plaintext");
    }

    // An invented ciphertext, shorter than the tag.
    let stunted = Sealed {
        ciphertext: vec![1, 2, 3],
        nonce: vec![4, 5, 6],
    };
    assert_eq!(stunted.plaintext_len(), 0, "no underflow");
}
