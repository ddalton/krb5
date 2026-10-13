//! A typed Kerberos key: an enctype plus its octets, with the RFC 3961
//! `encrypt` / `decrypt` / `get_mic` operations bound to it.
//!
//! The specific keys (Ke, Ki, Kc) are derived per call from the key usage,
//! so a caller can only ever name a usage, never hand over the wrong
//! derived key.

use crate::kdf::{self, Enctype, KeyUse};
use crate::profile;
use rand::RngCore;
use std::fmt;

/// A Kerberos protocol key (long-term, session or sub-key).
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    enctype: Enctype,
    bytes: Vec<u8>,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("enctype", &self.enctype)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// A key operation failed: unsupported enctype, wrong key length, or an
/// integrity check that did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct KeyError(pub String);

fn enctype(etype: i32) -> Result<Enctype, KeyError> {
    Enctype::from_i32(etype).map_err(|e| KeyError(e.to_string()))
}

impl Key {
    pub fn new(etype: i32, bytes: Vec<u8>) -> Result<Self, KeyError> {
        let enctype = enctype(etype)?;
        if bytes.len() != enctype.key_size() {
            return Err(KeyError(format!(
                "enctype {etype} wants a {}-octet key, got {}",
                enctype.key_size(),
                bytes.len()
            )));
        }
        Ok(Key { enctype, bytes })
    }

    /// A fresh random key, for sub-keys. RFC 3962 §6 / RFC 8009 §4:
    /// random-to-key is the identity for the AES enctypes.
    pub fn random(etype: i32) -> Result<Self, KeyError> {
        let mut bytes = vec![0u8; enctype(etype)?.key_size()];
        rand::thread_rng().fill_bytes(&mut bytes);
        Key::new(etype, bytes)
    }

    /// Long-term key from a password (RFC 3962 §4, RFC 8009 §4).
    /// `params` is the KDC's `s2kparams` (iteration count), if it sent one.
    pub fn from_password(
        etype: i32,
        password: &str,
        salt: &[u8],
        params: Option<[u8; 4]>,
    ) -> Result<Self, KeyError> {
        let bytes = kdf::string_to_key(enctype(etype)?, password.as_bytes(), salt, params)
            .map_err(|e| KeyError(e.to_string()))?;
        Key::new(etype, bytes)
    }

    pub fn enctype(&self) -> i32 {
        self.enctype.etype()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn derived(&self, usage: u32, which: KeyUse) -> Result<Vec<u8>, KeyError> {
        kdf::derive_key(self.enctype, &self.bytes, usage, which).map_err(|e| KeyError(e.to_string()))
    }

    fn profile(&self) -> profile::Enctype {
        // Both enums cover exactly enctypes 17-20, so this cannot fail.
        profile::Enctype::from_i32(self.enctype.etype()).expect("enctype covered by profile")
    }

    /// RFC 3961 `encrypt` with a fresh random confounder.
    pub fn encrypt(&self, usage: u32, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let ke = self.derived(usage, KeyUse::Encryption)?;
        let ki = self.derived(usage, KeyUse::Integrity)?;
        profile::encrypt(self.profile(), &ke, &ki, plaintext).map_err(|e| KeyError(e.to_string()))
    }

    /// RFC 3961 `decrypt`; the integrity check runs before any plaintext
    /// is returned.
    pub fn decrypt(&self, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let ke = self.derived(usage, KeyUse::Encryption)?;
        let ki = self.derived(usage, KeyUse::Integrity)?;
        profile::decrypt(self.profile(), &ke, &ki, ciphertext).map_err(|e| KeyError(e.to_string()))
    }

    /// The keyed checksum type paired with this enctype (RFC 3962 §7,
    /// RFC 8009 §8).
    pub fn checksum_type(&self) -> i32 {
        match self.enctype {
            Enctype::Aes128CtsHmacSha196 => 15,
            Enctype::Aes256CtsHmacSha196 => 16,
            Enctype::Aes128CtsHmacSha256128 => 19,
            Enctype::Aes256CtsHmacSha384192 => 20,
        }
    }

    /// RFC 3961 `get_mic` with Kc for `usage`.
    pub fn checksum(&self, usage: u32, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let kc = self.derived(usage, KeyUse::Checksum)?;
        profile::checksum(self.profile(), &kc, message).map_err(|e| KeyError(e.to_string()))
    }

    /// Constant-time `verify_mic`.
    pub fn verify_checksum(&self, usage: u32, message: &[u8], tag: &[u8]) -> Result<bool, KeyError> {
        let kc = self.derived(usage, KeyUse::Checksum)?;
        profile::verify_checksum(self.profile(), &kc, message, tag).map_err(|e| KeyError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn rfc3962_password_key_matches_the_published_vector() {
        // RFC 3962 Appendix B, iteration count 1200, 256-bit key.
        let k = Key::from_password(18, "password", b"ATHENA.MIT.EDUraeburn", Some(1200u32.to_be_bytes()))
            .unwrap();
        assert_eq!(
            k.bytes(),
            hex("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a")
        );
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(Key::new(18, vec![0; 16]).is_err());
        assert!(Key::new(23, vec![0; 16]).is_err());
    }

    #[test]
    fn decrypt_is_bound_to_the_usage() {
        let k = Key::random(20).unwrap();
        let ct = k.encrypt(3, b"enc-part").unwrap();
        assert_eq!(k.decrypt(3, &ct).unwrap(), b"enc-part");
        assert!(k.decrypt(8, &ct).is_err());
    }

    #[test]
    fn checksums_verify_only_under_their_usage() {
        for et in [17, 18, 19, 20] {
            let k = Key::random(et).unwrap();
            let tag = k.checksum(6, b"req-body").unwrap();
            assert!(k.verify_checksum(6, b"req-body", &tag).unwrap());
            assert!(!k.verify_checksum(7, b"req-body", &tag).unwrap());
        }
    }

    #[test]
    fn debug_does_not_print_key_material() {
        let k = Key::new(17, vec![0xAB; 16]).unwrap();
        let s = format!("{k:?}");
        assert!(s.contains("redacted") && !s.contains("171"));
    }
}
