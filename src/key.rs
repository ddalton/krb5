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
#[non_exhaustive]
pub struct KeyError(
    /// What went wrong.
    pub String,
);

fn enctype(etype: i32) -> Result<Enctype, KeyError> {
    Enctype::from_i32(etype).map_err(|e| KeyError(e.to_string()))
}

impl Key {
    /// A key of enctype `etype` from its raw octets, which must be exactly
    /// the enctype's key size.
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

    /// The RFC 3961 enctype number.
    pub fn enctype(&self) -> i32 {
        self.enctype.etype()
    }

    /// The raw key octets.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn derived(&self, usage: u32, which: KeyUse) -> Result<Vec<u8>, KeyError> {
        kdf::derive_key(self.enctype, &self.bytes, usage, which)
            .map_err(|e| KeyError(e.to_string()))
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

    /// RFC 3961 `pseudo-random` (RFC 3962 §6 for 17/18, RFC 8009 §5 for
    /// 19/20), keyed with this key directly.
    pub fn prf(&self, input: &[u8]) -> Result<Vec<u8>, KeyError> {
        kdf::prf(self.enctype, &self.bytes, input).map_err(|e| KeyError(e.to_string()))
    }

    /// RFC 6113 §5.1 PRF+: `PRF(K, 1 || s) || PRF(K, 2 || s) || ...`,
    /// truncated to `len` octets (MIT `krb5_c_prfplus`).
    pub fn prf_plus(&self, s: &[u8], len: usize) -> Result<Vec<u8>, KeyError> {
        let mut out = Vec::with_capacity(len);
        let mut input = Vec::with_capacity(1 + s.len());
        for i in 1u8..=255 {
            if out.len() >= len {
                break;
            }
            input.clear();
            input.push(i);
            input.extend_from_slice(s);
            out.extend_from_slice(&self.prf(&input)?);
        }
        if out.len() < len {
            return Err(KeyError("PRF+ output too long".into()));
        }
        out.truncate(len);
        Ok(out)
    }

    /// RFC 6113 §5.1 KRB-FX-CF2: `PRF+(k1, pepper1) XOR PRF+(k2, pepper2)`,
    /// as a key of `k1`'s enctype (random-to-key is the identity for AES),
    /// as MIT's `krb5_c_fx_cf2_simple`.
    pub fn cf2(k1: &Key, pepper1: &str, k2: &Key, pepper2: &str) -> Result<Key, KeyError> {
        let n = k1.enctype.key_size();
        let a = k1.prf_plus(pepper1.as_bytes(), n)?;
        let b = k2.prf_plus(pepper2.as_bytes(), n)?;
        Key::new(k1.enctype(), a.iter().zip(&b).map(|(x, y)| x ^ y).collect())
    }

    /// Constant-time `verify_mic`.
    pub fn verify_checksum(
        &self,
        usage: u32,
        message: &[u8],
        tag: &[u8],
    ) -> Result<bool, KeyError> {
        let kc = self.derived(usage, KeyUse::Checksum)?;
        profile::verify_checksum(self.profile(), &kc, message, tag)
            .map_err(|e| KeyError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8009_password_key_matches_the_published_vector() {
        // RFC 8009 Appendix A, iteration count 32768, aes256-sha384.
        let mut salt = hex("10df9dd783e5bc8acea1730e74355f61");
        salt.extend_from_slice(b"ATHENA.MIT.EDUraeburn");
        let k = Key::from_password(20, "password", &salt, Some(32768u32.to_be_bytes())).unwrap();
        assert_eq!(
            k.bytes(),
            hex("45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467")
        );
    }

    #[test]
    fn a_kdc_asking_for_too_few_iterations_is_refused() {
        // RFC 3962 Appendix B's 1200 iterations are below the 4096 default.
        let e = Key::from_password(
            18,
            "password",
            b"ATHENA.MIT.EDUraeburn",
            Some(1200u32.to_be_bytes()),
        )
        .unwrap_err();
        assert!(e.0.contains("below the enctype's default"), "{e}");
    }

    /// MIT's lib/crypto/crypto_tests/t_cf2.in and t_cf2.expected: k1 and
    /// k2 are string-to-key("key1", salt "key1") and ("key2", "key2") with
    /// default parameters, peppers "a" and "b".
    #[test]
    fn cf2_matches_mit_t_cf2() {
        for (etype, want) in [
            (17, "97df97e4b798b29eb31ed7280287a92a"),
            (
                18,
                "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b",
            ),
            (19, "edd02a39d2dbde31611c16e610be062c"),
            (
                20,
                "67f6ea530aea85a37dcbb23349ea52dcc61ca8493ff557252327fd8304341584",
            ),
        ] {
            let k1 = Key::from_password(etype, "key1", b"key1", None).unwrap();
            let k2 = Key::from_password(etype, "key2", b"key2", None).unwrap();
            let k = Key::cf2(&k1, "a", &k2, "b").unwrap();
            assert_eq!(k.bytes(), hex(want), "enctype {etype}");
            assert_eq!(k.enctype(), etype);
        }
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
