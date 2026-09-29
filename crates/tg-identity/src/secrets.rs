//! The data key for secrets at rest (ADR-0095).
//!
//! ADR-0016 demands that a secret's value lie in the store as **ciphertext**. The
//! reason stands in ADR-0020: the log is retained, and a secret in it would be a
//! bearer secret with a retention period -- exactly the reason only the **hash** of
//! an invitation stands in the log (ADR-0037).
//!
//! # What the key is and what it is not
//!
//! It is **one key per cluster**, symmetric, and it stands **never in the log**
//! (ADR-0095, determination 1). It lives in one copy on every disk, delivered on the
//! credential path -- the same one that already carries the agent intermediate's
//! private key (ADR-0037, ADR-0043).
//!
//! It is **not** the CA key from ADR-0014. That one's root stays in the HSM, the
//! shares stay TPM-sealed; this is a different procedure with a different purpose,
//! and the FROST group could not deliver it at all -- it signs.
//!
//! # What it protects
//!
//! A log or a backup that **leaves** the cluster. Whoever reads a segment from the
//! WORM archive gets ciphertext. **Not** protected is a node that has been taken
//! over: it must be able to give the plaintext to its workload (ADR-0095,
//! determination 5).

use base64::Engine as _;
use ring::aead;
use ring::digest;
use ring::rand::SecureRandom as _;
use std::fmt::Write as _;

const KEY_LEN: usize = 32;

const NONCE_LEN: usize = 12;

pub const MAX_SECRET_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    NotAuthentic,
    NoEntropy,
    MalformedKey,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAuthentic => {
                f.write_str("the ciphertext does not belong to this key or was altered")
            }
            Self::NoEntropy => f.write_str("no entropy for a fresh nonce"),
            Self::MalformedKey => write!(f, "a data key has {KEY_LEN} bytes"),
        }
    }
}

impl std::error::Error for SealError {}

pub use tg_model::secrets::Sealed;

pub trait SealedExt {
    fn plaintext_len(&self) -> usize;
}

impl SealedExt for Sealed {
    fn plaintext_len(&self) -> usize {
        self.ciphertext
            .len()
            .saturating_sub(aead::CHACHA20_POLY1305.tag_len())
    }
}

pub struct KeyRing {
    primary: DataKey,
    previous: Option<DataKey>,
}

impl KeyRing {
    #[must_use]
    pub const fn new(primary: DataKey, previous: Option<DataKey>) -> Self {
        Self { primary, previous }
    }

    #[must_use]
    pub const fn primary(&self) -> &DataKey {
        &self.primary
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.primary.fingerprint()
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Sealed, SealError> {
        self.primary.seal(plaintext)
    }

    pub fn open(&self, sealed: &Sealed) -> Result<Vec<u8>, SealError> {
        match self.primary.open(sealed) {
            Ok(plaintext) => Ok(plaintext),
            Err(err) => match &self.previous {
                Some(previous) => previous.open(sealed).map_err(|_| err),
                None => Err(err),
            },
        }
    }

    #[must_use]
    pub fn needs_rekey(&self, sealed: &Sealed) -> bool {
        self.previous.is_some() && self.primary.open(sealed).is_err()
    }
}

pub struct DataKey {
    bytes: [u8; KEY_LEN],
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

impl DataKey {
    pub fn generate() -> Result<Self, SealError> {
        let mut bytes = [0_u8; KEY_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| SealError::NoEntropy)?;

        Ok(Self { bytes })
    }

    pub fn from_base64(text: &str) -> Result<Self, SealError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|_| SealError::MalformedKey)?;
        let bytes: [u8; KEY_LEN] = raw.try_into().map_err(|_| SealError::MalformedKey)?;

        Ok(Self { bytes })
    }

    #[must_use]
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.bytes)
    }

    #[must_use]
    pub fn volume_passphrase(&self, volume: &str) -> String {
        let mut info = Vec::with_capacity(21 + volume.len());
        info.extend_from_slice(b"tardigrade:volume:v1:");
        info.extend_from_slice(volume.as_bytes());

        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"");
        let prk = salt.extract(&self.bytes);
        let parts: [&[u8]; 1] = [&info];
        // **Two `expect` with the same condition** (see `# Panics`): the output
        // length stands here as a constant, and `ring` refuses only what exceeds 255
        // hash lengths. The same shape as in `threshold::group`, where `Seat::new`
        // refuses zero.
        #[allow(
            clippy::expect_used,
            reason = "KEY_LEN is a constant far below 255 hash lengths"
        )]
        let out = {
            let okm = prk
                .expand(&parts, ring::hkdf::HKDF_SHA256)
                .expect("32 bytes lie far below 255 hash lengths");

            let mut out = [0_u8; KEY_LEN];
            okm.fill(&mut out)
                .expect("32 bytes lie far below 255 hash lengths");
            out
        };

        out.iter()
            .fold(String::with_capacity(2 * KEY_LEN), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.bytes)
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Sealed, SealError> {
        let mut nonce = [0_u8; NONCE_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SealError::NoEntropy)?;

        let key = self.less_safe()?;
        let mut buffer = plaintext.to_vec();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut buffer,
        )
        .map_err(|_| SealError::NotAuthentic)?;

        Ok(Sealed {
            ciphertext: buffer,
            nonce: nonce.to_vec(),
        })
    }

    pub fn open(&self, sealed: &Sealed) -> Result<Vec<u8>, SealError> {
        let nonce: [u8; NONCE_LEN] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| SealError::NotAuthentic)?;

        let key = self.less_safe()?;
        let mut buffer = sealed.ciphertext.clone();
        let opened = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut buffer,
            )
            .map_err(|_| SealError::NotAuthentic)?;

        Ok(opened.to_vec())
    }

    fn less_safe(&self) -> Result<aead::LessSafeKey, SealError> {
        let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &self.bytes)
            .map_err(|_| SealError::MalformedKey)?;

        Ok(aead::LessSafeKey::new(unbound))
    }
}

#[must_use]
pub fn fingerprint(bytes: &[u8]) -> String {
    let hash = digest::digest(&digest::SHA256, bytes);
    hash.as_ref()[..4]
        .iter()
        .fold(String::new(), |mut out, byte| {
            // `write!` into a `String` cannot fail.
            let _ = write!(out, "{byte:02x}");
            out
        })
}
