//! RSA PKCS #1 v1.5 signatures (RFC 8017 §8.2) over SHA-2: verifying the
//! KDC's and the CAs' signatures, and signing a client's AuthPack.
//!
//! Verification re-encodes the expected EMSA-PKCS1-v1_5 block and compares
//! it whole, as RFC 8017 §8.2.2 recommends, so there is no padding parser
//! to fool (Bleichenbacher's 2006 forgery). Signing uses the private
//! exponent through constant-time Montgomery exponentiation (the `rsa`
//! crate's 0.9 line leaks timing there: RUSTSEC-2023-0071) and checks the
//! signature before releasing it, against fault attacks.

use super::asn1::{self, ReaderExt};
use super::bigint::{less, modpow};
use crate::der::{self, DerError, Reader};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub(crate) const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub(crate) const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub(crate) const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
pub(crate) const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";

/// Moduli outside this range are refused: below 2048 bits is weaker than
/// OpenSSL's security level 2 allows; above 16384 only costs time.
const MIN_BITS: usize = 2048;
const MAX_BITS: usize = 16384;

/// The digests a signature may use. SHA-1 is not among them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub(crate) fn oid(self) -> &'static str {
        match self {
            Hash::Sha256 => "2.16.840.1.101.3.4.2.1",
            Hash::Sha384 => "2.16.840.1.101.3.4.2.2",
            Hash::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    pub(crate) fn from_oid(oid: &[u8]) -> Option<Hash> {
        [Hash::Sha256, Hash::Sha384, Hash::Sha512]
            .into_iter()
            .find(|h| asn1::oid(h.oid()) == oid)
    }

    /// The hash of a `shaNNNWithRSAEncryption` signature algorithm.
    pub(crate) fn from_rsa_sig_oid(oid: &[u8]) -> Option<Hash> {
        [
            (SHA256_WITH_RSA, Hash::Sha256),
            (SHA384_WITH_RSA, Hash::Sha384),
            (SHA512_WITH_RSA, Hash::Sha512),
        ]
        .into_iter()
        .find(|(o, _)| asn1::oid(o) == oid)
        .map(|(_, h)| h)
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// EMSA-PKCS1-v1_5 for a `k`-octet modulus: `00 01 FF.. 00 DigestInfo`,
/// the DigestInfo's AlgorithmIdentifier with NULL parameters or without.
fn emsa(hash: Hash, digest: &[u8], k: usize, with_null: bool) -> Option<Vec<u8>> {
    let info = der::seq(&[
        asn1::alg_id(hash.oid(), with_null.then(asn1::null)),
        der::octets(digest),
    ]);
    if k < info.len() + 11 {
        return None;
    }
    let mut em = vec![0xFF; k];
    em[0] = 0;
    em[1] = 1;
    em[k - info.len() - 1] = 0;
    em[k - info.len()..].copy_from_slice(&info);
    Some(em)
}

/// An RSA public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

impl PublicKey {
    /// `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`, the
    /// content of an `rsaEncryption` SubjectPublicKeyInfo's BIT STRING.
    pub(crate) fn from_der(der: &[u8]) -> Result<PublicKey, DerError> {
        let mut r = Reader::new(der);
        let mut s = r.seq()?;
        let n = s.uint()?.to_vec();
        let e = s.uint()?.to_vec();
        s.done("RSAPublicKey")?;
        r.done("RSAPublicKey")?;
        if !(MIN_BITS..=MAX_BITS).contains(&(n.len() * 8)) || n[n.len() - 1] & 1 == 0 {
            return Err(DerError(format!(
                "unsupported RSA modulus of {} octets",
                n.len()
            )));
        }
        if e.is_empty() || e.len() > 8 || e[e.len() - 1] & 1 == 0 || e == [1] {
            return Err(DerError("unsupported RSA public exponent".into()));
        }
        Ok(PublicKey { n, e })
    }

    /// Whether `sig` is this key's PKCS #1 v1.5 signature over `digest`.
    pub(crate) fn verify(&self, hash: Hash, digest: &[u8], sig: &[u8]) -> bool {
        let k = self.n.len();
        if sig.len() != k || !less(sig, &self.n) {
            return false;
        }
        let Some(em) = modpow(sig, &self.e, &self.n) else {
            return false;
        };
        [true, false]
            .into_iter()
            .any(|null| emsa(hash, digest, k, null).as_deref() == Some(&em[..]))
    }
}

/// An RSA private key.
#[derive(Clone)]
pub(crate) struct PrivateKey {
    public: PublicKey,
    d: Vec<u8>,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RSA private key ({} bits)", self.public.n.len() * 8)
    }
}

impl PrivateKey {
    /// PKCS #1 `RSAPrivateKey` (PEM `RSA PRIVATE KEY`) or a PKCS #8
    /// `PrivateKeyInfo` holding one (PEM `PRIVATE KEY`, what `openssl req
    /// -newkey` writes).
    pub(crate) fn from_der(der: &[u8]) -> Result<PrivateKey, DerError> {
        let mut r = Reader::new(der);
        let mut s = r.seq()?;
        r.done("private key")?;
        s.uint()?; // version
        // PKCS #8: AlgorithmIdentifier, then the key in an OCTET STRING.
        if s.rest().first() == Some(&der::SEQUENCE) {
            let (alg, _) = s.alg_id()?;
            if alg != asn1::oid(RSA_ENCRYPTION) {
                return Err(DerError(
                    "the private key is not RSA (only RSA keys are supported)".into(),
                ));
            }
            return PrivateKey::from_der(s.octets()?);
        }
        let n = s.uint()?.to_vec();
        let e = s.uint()?.to_vec();
        let d = s.uint()?.to_vec();
        let public = PublicKey::from_der(&der::seq(&[asn1::uint(&n), asn1::uint(&e)]))?;
        if d.is_empty() || !less(&d, &public.n) {
            return Err(DerError("bad RSA private exponent".into()));
        }
        // d is padded to the modulus length, so the exponentiation's time
        // says nothing about d's length.
        let mut padded = vec![0; public.n.len() - d.len()];
        padded.extend_from_slice(&d);
        Ok(PrivateKey { public, d: padded })
    }

    pub(crate) fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The PKCS #1 v1.5 signature over `digest`, the DigestInfo with NULL
    /// parameters as OpenSSL writes it.
    pub(crate) fn sign(&self, hash: Hash, digest: &[u8]) -> Result<Vec<u8>, DerError> {
        let k = self.public.n.len();
        let em = emsa(hash, digest, k, true)
            .ok_or_else(|| DerError("RSA modulus too small for the digest".into()))?;
        let sig = modpow(&em, &self.d, &self.public.n)
            .ok_or_else(|| DerError("RSA signing failed".into()))?;
        if !self.public.verify(hash, digest, &sig) {
            return Err(DerError(
                "RSA signature does not verify (inconsistent private key)".into(),
            ));
        }
        Ok(sig)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A 2048-bit key made by `openssl genrsa` for these tests.
    pub(crate) const TEST_KEY_PEM: &str = include_str!("testdata/rsa2048.pem");

    pub(crate) fn test_key() -> PrivateKey {
        let blocks = super::super::pem::blocks(TEST_KEY_PEM.as_bytes()).unwrap();
        PrivateKey::from_der(&blocks[0].1).unwrap()
    }

    #[test]
    fn signatures_round_trip_and_bind_digest_and_hash() {
        let key = test_key();
        let d = Hash::Sha256.digest(b"message");
        let sig = key.sign(Hash::Sha256, &d).unwrap();
        assert!(key.public().verify(Hash::Sha256, &d, &sig));
        assert!(
            !key.public()
                .verify(Hash::Sha256, &Hash::Sha256.digest(b"other"), &sig)
        );
        assert!(
            !key.public()
                .verify(Hash::Sha512, &Hash::Sha512.digest(b"message"), &sig)
        );
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert!(!key.public().verify(Hash::Sha256, &d, &bad));
        assert!(!key.public().verify(Hash::Sha256, &d, &sig[1..]));
    }

    #[test]
    fn a_signature_without_null_parameters_also_verifies() {
        // RFC 8017 §8.2.2 note 2: some signers omit the NULL.
        let key = test_key();
        let d = Hash::Sha384.digest(b"m");
        let em = emsa(Hash::Sha384, &d, key.public.n.len(), false).unwrap();
        let sig = modpow(&em, &key.d, &key.public.n).unwrap();
        assert!(key.public().verify(Hash::Sha384, &d, &sig));
    }

    #[test]
    fn a_forged_low_exponent_signature_is_refused() {
        // Garbage after the DigestInfo, which a lenient parser of the
        // padding would skip: the whole-block comparison does not.
        let key = test_key();
        let d = Hash::Sha256.digest(b"m");
        let mut em = emsa(Hash::Sha256, &d, key.public.n.len(), true).unwrap();
        let k = em.len();
        em.copy_within(11.., 10);
        em[k - 1] = 0x42;
        let sig = modpow(&em, &key.d, &key.public.n).unwrap();
        assert!(!key.public().verify(Hash::Sha256, &d, &sig));
    }

    #[test]
    fn a_block_with_the_right_digest_and_anything_else_wrong_is_refused() {
        // Each block ends in the right digest, so a verifier that looked
        // only at the digest would take it.
        let key = test_key();
        let d = Hash::Sha256.digest(b"m");
        let good = emsa(Hash::Sha256, &d, key.public.n.len(), true).unwrap();
        let info_at = good.len() - 51; // DigestInfo for SHA-256 with NULL: 51 octets
        for (what, at, v) in [
            ("block type", 1, 2),
            ("padding octet", 5, 0xFE),
            ("separator", info_at - 1, 0xFF),
            ("hash OID", info_at + 14, 0x02), // ...4.2.1 -> ...4.2.2
        ] {
            let mut em = good.clone();
            em[at] = v;
            let sig = modpow(&em, &key.d, &key.public.n).unwrap();
            assert!(!key.public().verify(Hash::Sha256, &d, &sig), "{what}");
        }
        let sig = modpow(&good, &key.d, &key.public.n).unwrap();
        assert!(key.public().verify(Hash::Sha256, &d, &sig));
    }

    #[test]
    fn weak_public_keys_are_refused() {
        let small = der::seq(&[asn1::uint(&[0xC3; 128]), asn1::uint(&[1, 0, 1])]);
        assert!(PublicKey::from_der(&small).is_err());
        let even_e = der::seq(&[asn1::uint(&[0xC3; 256]), asn1::uint(&[2])]);
        assert!(PublicKey::from_der(&even_e).is_err());
        let ok = der::seq(&[asn1::uint(&[0xC3; 256]), asn1::uint(&[1, 0, 1])]);
        assert!(PublicKey::from_der(&ok).is_ok());
    }
}
