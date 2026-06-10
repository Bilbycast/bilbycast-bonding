//! Optional AEAD encryption for bonded paths.
//!
//! A contribution bond rides the public internet over cellular and
//! satellite links, so the payload must be optionally confidential +
//! authenticated. [`BondCrypto`] wraps each datagram in a
//! ChaCha20-Poly1305 sealed envelope — the same AEAD the edge's QUIC
//! tunnel uses — keyed by a 32-byte secret shared (via the manager,
//! like `tunnel_encryption_key`) between the two edges of the bond.
//!
//! ## Envelope wire format
//!
//! ```text
//! [0xBD][ 12-byte nonce ][ ciphertext ... ][ 16-byte tag ]
//! ```
//!
//! - Byte 0 is the clear **envelope magic** `0xBD` — distinct from the
//!   bond data magic (`0xBC`) and control magic (`0xBE`) so the receiver
//!   can peek byte 0, recognise an encrypted datagram, open it, and then
//!   dispatch the *inner* plaintext on its own `0xBC`/`0xBE` magic. The
//!   inner datagram (bond header + payload, or a control packet) is
//!   authenticated in full, so a tampered header is rejected.
//! - The 96-bit nonce is fresh CSPRNG per datagram. At media packet
//!   rates the birthday bound is millennia away; rotate the key
//!   periodically for defence in depth (operator policy).
//!
//! Overhead is `1 + 12 + 16 = 29` bytes per datagram.

use std::sync::Arc;

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

/// Clear leading byte marking an encrypted bond datagram.
pub const ENVELOPE_MAGIC: u8 = 0xBD;
/// Nonce length for ChaCha20-Poly1305 (96-bit).
pub const NONCE_LEN: usize = 12;
/// AEAD tag length (128-bit).
pub const TAG_LEN: usize = 16;
/// Bond AEAD key length (256-bit).
pub const KEY_LEN: usize = 32;
/// Total per-datagram overhead added by the envelope.
pub const ENVELOPE_OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

/// Symmetric AEAD for a bonded link. Cheap to clone (`Arc` the inner).
pub struct BondCrypto {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl std::fmt::Debug for BondCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BondCrypto(chacha20-poly1305)")
    }
}

impl BondCrypto {
    /// Build from a 32-byte key. Both ends of the bond must hold the
    /// same key.
    pub fn new(key: &[u8]) -> Result<Arc<Self>, BondCryptoError> {
        if key.len() != KEY_LEN {
            return Err(BondCryptoError::KeyLength(key.len()));
        }
        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, key)
            .map_err(|_| BondCryptoError::KeyLength(key.len()))?;
        Ok(Arc::new(Self {
            key: LessSafeKey::new(unbound),
            rng: SystemRandom::new(),
        }))
    }

    /// Seal `plaintext` into `out` as `[0xBD][nonce][ciphertext+tag]`.
    /// `out` is cleared first; no heap alloc when it already has
    /// capacity.
    pub fn seal(&self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), BondCryptoError> {
        out.clear();
        out.reserve(ENVELOPE_OVERHEAD + plaintext.len());
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| BondCryptoError::Rng)?;
        out.push(ENVELOPE_MAGIC);
        out.extend_from_slice(&nonce_bytes);
        let prefix = out.len();
        out.extend_from_slice(plaintext);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[prefix..])
            .map_err(|_| BondCryptoError::Seal)?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Open a sealed datagram into `out` (the recovered inner datagram).
    /// Returns `Err` on a non-envelope datagram, truncated input, or
    /// authentication failure — the caller drops on `Err`.
    pub fn open(&self, datagram: &[u8], out: &mut Vec<u8>) -> Result<(), BondCryptoError> {
        if datagram.first().copied() != Some(ENVELOPE_MAGIC) {
            return Err(BondCryptoError::NotEnvelope);
        }
        if datagram.len() < ENVELOPE_OVERHEAD {
            return Err(BondCryptoError::Truncated);
        }
        let nonce_bytes: [u8; NONCE_LEN] = datagram[1..1 + NONCE_LEN]
            .try_into()
            .map_err(|_| BondCryptoError::Truncated)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        out.clear();
        out.extend_from_slice(&datagram[1 + NONCE_LEN..]);
        let plain = self
            .key
            .open_in_place(nonce, Aad::empty(), out)
            .map_err(|_| BondCryptoError::Open)?;
        let len = plain.len();
        out.truncate(len);
        Ok(())
    }
}

/// Whether a datagram is an encrypted envelope (cheap byte-0 peek).
#[inline]
pub fn is_envelope(buf: &[u8]) -> bool {
    buf.first().copied() == Some(ENVELOPE_MAGIC)
}

#[derive(Debug, thiserror::Error)]
pub enum BondCryptoError {
    #[error("bond key must be {KEY_LEN} bytes, got {0}")]
    KeyLength(usize),
    #[error("CSPRNG failure")]
    Rng,
    #[error("AEAD seal failed")]
    Seal,
    #[error("AEAD open/authentication failed")]
    Open,
    #[error("not an encrypted bond datagram")]
    NotEnvelope,
    #[error("encrypted datagram truncated")]
    Truncated,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        k
    }

    #[test]
    fn seal_open_roundtrip() {
        let c = BondCrypto::new(&key()).unwrap();
        let msg = b"\xBC\x10\x00\x02bond header + payload bytes here";
        let mut sealed = Vec::new();
        c.seal(msg, &mut sealed).unwrap();
        assert_eq!(sealed[0], ENVELOPE_MAGIC);
        assert_eq!(sealed.len(), msg.len() + ENVELOPE_OVERHEAD);
        assert!(is_envelope(&sealed));

        let mut opened = Vec::new();
        c.open(&sealed, &mut opened).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn distinct_nonces_per_seal() {
        let c = BondCrypto::new(&key()).unwrap();
        let msg = b"same plaintext";
        let mut a = Vec::new();
        let mut b = Vec::new();
        c.seal(msg, &mut a).unwrap();
        c.seal(msg, &mut b).unwrap();
        // Fresh nonce each time → different ciphertext.
        assert_ne!(a, b);
        assert_ne!(&a[1..1 + NONCE_LEN], &b[1..1 + NONCE_LEN]);
    }

    #[test]
    fn tamper_is_rejected() {
        let c = BondCrypto::new(&key()).unwrap();
        let mut sealed = Vec::new();
        c.seal(b"important media", &mut sealed).unwrap();
        // Flip a ciphertext byte.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let mut out = Vec::new();
        assert!(matches!(
            c.open(&sealed, &mut out),
            Err(BondCryptoError::Open)
        ));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let c1 = BondCrypto::new(&key()).unwrap();
        let mut k2 = key();
        k2[0] ^= 0xFF;
        let c2 = BondCrypto::new(&k2).unwrap();
        let mut sealed = Vec::new();
        c1.seal(b"secret feed", &mut sealed).unwrap();
        let mut out = Vec::new();
        assert!(c2.open(&sealed, &mut out).is_err());
    }

    #[test]
    fn non_envelope_and_truncated_rejected() {
        let c = BondCrypto::new(&key()).unwrap();
        let mut out = Vec::new();
        assert!(matches!(
            c.open(&[0xBC, 1, 2, 3], &mut out),
            Err(BondCryptoError::NotEnvelope)
        ));
        assert!(matches!(
            c.open(&[ENVELOPE_MAGIC, 1, 2], &mut out),
            Err(BondCryptoError::Truncated)
        ));
    }

    #[test]
    fn rejects_bad_key_length() {
        assert!(BondCrypto::new(&[0u8; 16]).is_err());
        assert!(BondCrypto::new(&[0u8; 32]).is_ok());
    }
}
