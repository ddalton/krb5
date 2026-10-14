//! The signature keys PKINIT certificates carry, RSA or elliptic-curve,
//! and the algorithms they sign with.

use super::asn1::{self, ReaderExt};
use super::ec;
use super::rsa;
use crate::der::{DerError, Reader};
use sha2::{Digest, Sha256, Sha384, Sha512};

type Result<T> = std::result::Result<T, DerError>;

const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";

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

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// A signature algorithm: PKCS #1 v1.5 RSA or ECDSA, with a hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigAlg {
    Rsa(Hash),
    Ecdsa(Hash),
}

impl SigAlg {
    /// Every one accepted, strongest first: MIT 1.22's supportedCMSTypes.
    pub(crate) const ALL: [SigAlg; 6] = [
        SigAlg::Ecdsa(Hash::Sha512),
        SigAlg::Ecdsa(Hash::Sha384),
        SigAlg::Ecdsa(Hash::Sha256),
        SigAlg::Rsa(Hash::Sha512),
        SigAlg::Rsa(Hash::Sha384),
        SigAlg::Rsa(Hash::Sha256),
    ];

    pub(crate) fn oid(self) -> &'static str {
        match self {
            SigAlg::Rsa(Hash::Sha256) => SHA256_WITH_RSA,
            SigAlg::Rsa(Hash::Sha384) => SHA384_WITH_RSA,
            SigAlg::Rsa(Hash::Sha512) => SHA512_WITH_RSA,
            SigAlg::Ecdsa(Hash::Sha256) => ECDSA_WITH_SHA256,
            SigAlg::Ecdsa(Hash::Sha384) => ECDSA_WITH_SHA384,
            SigAlg::Ecdsa(Hash::Sha512) => ECDSA_WITH_SHA512,
        }
    }

    pub(crate) fn from_oid(oid: &[u8]) -> Option<SigAlg> {
        SigAlg::ALL.into_iter().find(|a| asn1::oid(a.oid()) == oid)
    }

    pub(crate) fn hash(self) -> Hash {
        match self {
            SigAlg::Rsa(h) | SigAlg::Ecdsa(h) => h,
        }
    }

    /// The AlgorithmIdentifier: NULL parameters for RSA (RFC 4055), none
    /// for ECDSA (RFC 5758 §3.2).
    pub(crate) fn alg_id(self) -> Vec<u8> {
        match self {
            SigAlg::Rsa(_) => asn1::alg_id(self.oid(), Some(asn1::null())),
            SigAlg::Ecdsa(_) => asn1::alg_id(self.oid(), None),
        }
    }
}

/// A certificate's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PublicKey {
    Rsa(rsa::PublicKey),
    Ec(ec::PublicKey),
}

impl PublicKey {
    /// From a SubjectPublicKeyInfo's algorithm, its parameters and the
    /// BIT STRING's content.
    pub(crate) fn from_spki(alg: &[u8], params: Option<&[u8]>, key: &[u8]) -> Result<PublicKey> {
        if alg == asn1::oid(rsa::RSA_ENCRYPTION) {
            Ok(PublicKey::Rsa(rsa::PublicKey::from_der(key)?))
        } else if alg == asn1::oid(ec::ID_EC_PUBLIC_KEY) {
            let curve = ec::Curve::from_params(params)?;
            Ok(PublicKey::Ec(ec::PublicKey::from_point(curve, key)?))
        } else {
            Err(DerError(
                "unsupported public key algorithm (only RSA and EC)".into(),
            ))
        }
    }

    /// Whether `sig` is this key's signature by `alg` over `digest` (made
    /// with `alg`'s hash). A key of the other kind never verifies.
    pub(crate) fn verify(&self, alg: SigAlg, digest: &[u8], sig: &[u8]) -> bool {
        match (self, alg) {
            (PublicKey::Rsa(k), SigAlg::Rsa(h)) => k.verify(h, digest, sig),
            (PublicKey::Ec(k), SigAlg::Ecdsa(_)) => k.verify(digest, sig),
            _ => false,
        }
    }
}

/// A client's private key.
#[derive(Debug, Clone)]
pub(crate) enum PrivateKey {
    Rsa(rsa::PrivateKey),
    Ec(ec::PrivateKey),
}

impl PrivateKey {
    /// The first private key among PEM blocks: PKCS #8 `PRIVATE KEY`
    /// (RSA or EC), `RSA PRIVATE KEY` (PKCS #1) or `EC PRIVATE KEY`
    /// (SEC1), unencrypted.
    pub(crate) fn from_pem_blocks(blocks: &[(String, Vec<u8>)]) -> Result<PrivateKey> {
        for (label, der) in blocks {
            match label.as_str() {
                "RSA PRIVATE KEY" => return Ok(PrivateKey::Rsa(rsa::PrivateKey::from_der(der)?)),
                "EC PRIVATE KEY" => {
                    return Ok(PrivateKey::Ec(ec::PrivateKey::from_sec1(der, None)?));
                }
                "PRIVATE KEY" => return Self::from_pkcs8(der),
                _ => {}
            }
        }
        Err(DerError(
            "no unencrypted RSA or EC private key found".into(),
        ))
    }

    /// `PrivateKeyInfo ::= SEQUENCE { version, AlgorithmIdentifier,
    /// privateKey OCTET STRING, ... }`.
    fn from_pkcs8(der: &[u8]) -> Result<PrivateKey> {
        let mut r = Reader::new(der);
        let mut s = r.seq()?;
        r.done("PrivateKeyInfo")?;
        s.int()?;
        let (alg, params) = s.alg_id()?;
        if alg == asn1::oid(rsa::RSA_ENCRYPTION) {
            Ok(PrivateKey::Rsa(rsa::PrivateKey::from_der(der)?))
        } else if alg == asn1::oid(ec::ID_EC_PUBLIC_KEY) {
            let curve = ec::Curve::from_params(params)?;
            Ok(PrivateKey::Ec(ec::PrivateKey::from_sec1(
                s.octets()?,
                Some(curve),
            )?))
        } else {
            Err(DerError(
                "unsupported private key algorithm (only RSA and EC)".into(),
            ))
        }
    }

    pub(crate) fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Rsa(k) => PublicKey::Rsa(k.public().clone()),
            PrivateKey::Ec(k) => PublicKey::Ec(k.public().clone()),
        }
    }

    /// What MIT's client signs with: SHA-256, with RSA or ECDSA as the
    /// key is.
    pub(crate) fn sig_alg(&self) -> SigAlg {
        match self {
            PrivateKey::Rsa(_) => SigAlg::Rsa(Hash::Sha256),
            PrivateKey::Ec(_) => SigAlg::Ecdsa(Hash::Sha256),
        }
    }

    /// The signature over `digest`, made with [`PrivateKey::sig_alg`]'s hash.
    pub(crate) fn sign(&self, digest: &[u8]) -> Result<Vec<u8>> {
        match self {
            PrivateKey::Rsa(k) => k.sign(Hash::Sha256, digest),
            PrivateKey::Ec(k) => k.sign(digest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkinit::pem;

    fn key(pem_text: &[u8]) -> PrivateKey {
        PrivateKey::from_pem_blocks(&pem::blocks(pem_text).unwrap()).unwrap()
    }

    /// A signature verifies only under an algorithm of its key's kind:
    /// certificate signatures get no leeway on the label.
    #[test]
    fn keys_verify_only_their_own_kind_of_signature() {
        let ec = key(include_bytes!("testdata/ec-kdc-key.pem"));
        let rsa = key(include_bytes!("testdata/kdc-key.pem"));
        let d = Hash::Sha256.digest(b"m");
        let (ec_sig, rsa_sig) = (ec.sign(&d).unwrap(), rsa.sign(&d).unwrap());
        assert!(ec.public().verify(SigAlg::Ecdsa(Hash::Sha256), &d, &ec_sig));
        assert!(!ec.public().verify(SigAlg::Rsa(Hash::Sha256), &d, &ec_sig));
        assert!(rsa.public().verify(SigAlg::Rsa(Hash::Sha256), &d, &rsa_sig));
        assert!(
            !rsa.public()
                .verify(SigAlg::Ecdsa(Hash::Sha256), &d, &rsa_sig)
        );
        assert_eq!(ec.sig_alg(), SigAlg::Ecdsa(Hash::Sha256));
        assert_eq!(rsa.sig_alg(), SigAlg::Rsa(Hash::Sha256));
    }

    #[test]
    fn signature_algorithms_round_trip_their_oids() {
        for a in SigAlg::ALL {
            assert_eq!(SigAlg::from_oid(&asn1::oid(a.oid())), Some(a));
        }
        // RFC 5758: no parameters for ECDSA; RFC 4055: NULL for RSA.
        assert!(!SigAlg::Ecdsa(Hash::Sha256).alg_id().ends_with(&[5, 0]));
        assert!(SigAlg::Rsa(Hash::Sha256).alg_id().ends_with(&[5, 0]));
    }
}
