//! The nonces' entropy source.
//!
//! It stands there as a trait of its own so that a test rig can provide it -- and
//! **only** for that. In operation there is exactly one right choice,
//! [`OsEntropy`].
//!
//! The trait keeps `rand_core` out of the public surface: the version `frost` lies
//! on is a property of the library and none this crate should press on its
//! callers.

use rand_core::{CryptoRng, RngCore};

/// A source of cryptographically usable random bytes.
///
/// # Safety
///
/// Whoever implements this promises that the delivered bytes are not predictable
/// by an attacker: a predictable nonce gives the share away, and two identical
/// nonces give it away for certain. The
/// [`NonceVault`](crate::threshold::NonceVault) catches the second case -- the
/// first it cannot see.
pub trait Entropy: Send {
    /// Fills the buffer with random bytes.
    fn fill(&mut self, dest: &mut [u8]);
}

/// The operating system's randomness -- the only source that comes into question
/// in operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    /// Fills `dest` with random bytes drawn from the operating system's CSPRNG.
    fn fill(&mut self, dest: &mut [u8]) {
        rand_core::OsRng.fill_bytes(dest);
    }
}

/// The bridge from [`Entropy`] to what `frost` demands.
pub(crate) struct Source<'a> {
    inner: &'a mut dyn Entropy,
}

impl<'a> Source<'a> {
    /// Wraps an [`Entropy`] implementation so it can be used wherever `frost`
    /// expects an `RngCore` source.
    ///
    /// `inner` is the entropy source to draw bytes from.
    pub(crate) fn new(inner: &'a mut dyn Entropy) -> Self {
        Self { inner }
    }
}

impl RngCore for Source<'_> {
    /// Draws 4 random bytes from the wrapped [`Entropy`] source and returns them
    /// as a little-endian `u32`.
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.inner.fill(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    /// Draws 8 random bytes from the wrapped [`Entropy`] source and returns them
    /// as a little-endian `u64`.
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.inner.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// Fills `dest` with random bytes drawn from the wrapped [`Entropy`] source.
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill(dest);
    }

    /// Fills `dest` with random bytes drawn from the wrapped [`Entropy`] source.
    ///
    /// # Errors
    ///
    /// Never fails; always returns `Ok`. The `Result` shape exists only to
    /// satisfy the `RngCore` trait signature.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.inner.fill(dest);
        Ok(())
    }
}

// The promise stands in the trait [`Entropy`]: whoever implements it delivers
// cryptographically usable bytes. `CryptoRng` is the place at which `frost`
// demands this promise.
impl CryptoRng for Source<'_> {}
