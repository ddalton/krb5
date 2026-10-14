//! Elliptic curves for PKINIT, as MIT 1.22 uses them: ECDH key agreement
//! (RFC 5349) and ECDSA signatures, on the NIST curves P-256, P-384 and
//! P-521, through RustCrypto's `p256`, `p384` and `p521`.
//!
//! The client's ECDH public value is a SubjectPublicKeyInfo naming the
//! curve; the KDC's is the bare uncompressed point; the shared secret is
//! the x coordinate of the shared point (RFC 5349 §4).

use super::asn1::{self, ReaderExt};
use crate::der::{self, DerError, Reader};
use p256::elliptic_curve::sec1::ToSec1Point;
use rand::RngCore;

type Result<T> = std::result::Result<T, DerError>;

/// `id-ecPublicKey` (RFC 5480).
pub(crate) const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// A NIST curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
}

/// Run `$body` with `$m` bound to the curve's crate.
macro_rules! per_curve {
    ($curve:expr, $m:ident => $body:expr) => {
        match $curve {
            Curve::P256 => {
                use p256 as $m;
                $body
            }
            Curve::P384 => {
                use p384 as $m;
                $body
            }
            Curve::P521 => {
                use p521 as $m;
                $body
            }
        }
    };
}

impl Curve {
    pub(crate) fn oid(self) -> &'static str {
        match self {
            Curve::P256 => "1.2.840.10045.3.1.7",
            Curve::P384 => "1.3.132.0.34",
            Curve::P521 => "1.3.132.0.35",
        }
    }

    pub(crate) fn from_oid(oid: &[u8]) -> Option<Curve> {
        [Curve::P256, Curve::P384, Curve::P521]
            .into_iter()
            .find(|c| asn1::oid(c.oid()) == oid)
    }

    /// The curve named by an `id-ecPublicKey` AlgorithmIdentifier's
    /// parameters (`namedCurve`; explicit curves are refused).
    pub(crate) fn from_params(params: Option<&[u8]>) -> Result<Curve> {
        let oid = params
            .map(|p| Reader::new(p).oid())
            .transpose()?
            .ok_or_else(|| DerError("EC key without a named curve".into()))?;
        Curve::from_oid(oid)
            .ok_or_else(|| DerError("unsupported elliptic curve (only P-256, P-384, P-521)".into()))
    }

    /// Octets of a field element, and of a private scalar.
    fn field_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }

    /// `AlgorithmIdentifier { id-ecPublicKey, namedCurve }`.
    pub(crate) fn alg_id(self) -> Vec<u8> {
        asn1::alg_id(ID_EC_PUBLIC_KEY, Some(asn1::oid_tlv(self.oid())))
    }

    /// A random private scalar in `[1, n)`: random field-length octets,
    /// trimmed to P-521's 521 bits, until one is in range.
    fn random_scalar(self) -> Vec<u8> {
        let mut d = vec![0u8; self.field_len()];
        loop {
            rand::thread_rng().fill_bytes(&mut d);
            if self == Curve::P521 {
                d[0] &= 0x01;
            }
            if per_curve!(self, m => m::SecretKey::from_slice(&d).is_ok()) {
                return d;
            }
        }
    }

    /// The uncompressed point for private scalar `d`.
    fn public_point(self, d: &[u8]) -> Result<Vec<u8>> {
        per_curve!(self, m => {
            let sk = m::SecretKey::from_slice(d).map_err(|_| DerError("bad EC private key".into()))?;
            Ok(sk.public_key().to_sec1_point(false).as_bytes().to_vec())
        })
    }
}

/// An EC public key: its curve and its point, checked to be on the curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicKey {
    curve: Curve,
    point: Vec<u8>,
}

impl PublicKey {
    /// A SEC1-encoded point on `curve` (the BIT STRING of an EC
    /// SubjectPublicKeyInfo). The identity and off-curve points fail.
    pub(crate) fn from_point(curve: Curve, point: &[u8]) -> Result<PublicKey> {
        let ok = per_curve!(curve, m => m::PublicKey::from_sec1_bytes(point).is_ok());
        if !ok {
            return Err(DerError("invalid EC public key".into()));
        }
        Ok(PublicKey {
            curve,
            point: point.to_vec(),
        })
    }

    /// Whether `sig` (a DER `ECDSA-Sig-Value`) is this key's signature over
    /// `digest`, which may be any length (RFC 5480 §4: truncated or used
    /// whole as ECDSA prescribes).
    pub(crate) fn verify(&self, digest: &[u8], sig: &[u8]) -> bool {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        per_curve!(self.curve, m => {
            let (Ok(key), Ok(sig)) = (
                m::ecdsa::VerifyingKey::from_sec1_bytes(&self.point),
                m::ecdsa::DerSignature::from_bytes(sig),
            ) else {
                return false;
            };
            key.verify_prehash(digest, &sig).is_ok()
        })
    }
}

/// An EC private key.
#[derive(Clone)]
pub(crate) struct PrivateKey {
    public: PublicKey,
    d: Vec<u8>,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EC private key ({:?})", self.public.curve)
    }
}

impl PrivateKey {
    /// SEC1 `ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET
    /// STRING, parameters [0] OPTIONAL, publicKey [1] OPTIONAL }` (PEM `EC
    /// PRIVATE KEY`, or inside PKCS #8, whose AlgorithmIdentifier gives the
    /// curve as `outer`).
    pub(crate) fn from_sec1(der: &[u8], outer: Option<Curve>) -> Result<PrivateKey> {
        let mut r = Reader::new(der);
        let mut s = r.seq()?;
        r.done("ECPrivateKey")?;
        if s.int()? != 1 {
            return Err(DerError("unsupported ECPrivateKey version".into()));
        }
        let d = s.octets()?;
        let inner = match s.optional(der::ctx(0))? {
            Some(p) => Some(Curve::from_params(Some(p))?),
            None => None,
        };
        let curve = match (outer, inner) {
            (Some(a), Some(b)) if a != b => {
                return Err(DerError("EC key's curves disagree".into()));
            }
            (Some(c), _) | (None, Some(c)) => c,
            (None, None) => return Err(DerError("EC key without a named curve".into())),
        };
        // Some writers drop leading zeros of the scalar.
        if d.len() > curve.field_len() {
            return Err(DerError("EC private key too long".into()));
        }
        let mut padded = vec![0; curve.field_len() - d.len()];
        padded.extend_from_slice(d);
        let point = curve.public_point(&padded)?;
        Ok(PrivateKey {
            public: PublicKey { curve, point },
            d: padded,
        })
    }

    pub(crate) fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The DER ECDSA signature over `digest` (deterministic, RFC 6979),
    /// checked before release.
    pub(crate) fn sign(&self, digest: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig = per_curve!(self.public.curve, m => {
            let key = m::ecdsa::SigningKey::from_slice(&self.d)
                .map_err(|_| DerError("bad EC private key".into()))?;
            let sig: m::ecdsa::Signature = key
                .sign_prehash(digest)
                .map_err(|_| DerError("ECDSA signing failed".into()))?;
            sig.to_der().as_bytes().to_vec()
        });
        if !self.public.verify(digest, &sig) {
            return Err(DerError("ECDSA signature does not verify".into()));
        }
        Ok(sig)
    }
}

/// An ephemeral ECDH key pair.
pub(crate) struct Ecdh {
    curve: Curve,
    d: Vec<u8>,
    point: Vec<u8>,
}

impl Ecdh {
    pub(crate) fn generate(curve: Curve) -> Ecdh {
        let d = curve.random_scalar();
        let point = curve.public_point(&d).expect("a scalar in range");
        Ecdh { curve, d, point }
    }

    pub(crate) fn curve(&self) -> Curve {
        self.curve
    }

    /// `clientPublicValue`: `{ id-ecPublicKey, namedCurve }` and the
    /// uncompressed point.
    pub(crate) fn spki(&self) -> Vec<u8> {
        der::seq(&[self.curve.alg_id(), asn1::bit_string(&self.point)])
    }

    /// The x coordinate of the shared point with the KDC's public point
    /// (KDCDHKeyInfo's subjectPublicKey: the SEC1 point itself). `None`
    /// for an invalid point, the identity included.
    pub(crate) fn agree(&self, kdc_point: &[u8]) -> Option<Vec<u8>> {
        per_curve!(self.curve, m => {
            let peer = m::PublicKey::from_sec1_bytes(kdc_point).ok()?;
            let sk = m::SecretKey::from_slice(&self.d).ok()?;
            let shared = m::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
            Some(shared.raw_secret_bytes().to_vec())
        })
    }

    #[cfg(test)]
    pub(crate) fn point(&self) -> &[u8] {
        &self.point
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha512};

    const CURVES: [Curve; 3] = [Curve::P256, Curve::P384, Curve::P521];

    #[test]
    fn ecdh_agrees_on_every_curve() {
        for c in CURVES {
            let (a, b) = (Ecdh::generate(c), Ecdh::generate(c));
            let za = a.agree(&b.point).unwrap();
            assert_eq!(za, b.agree(&a.point).unwrap(), "{c:?}");
            assert_eq!(za.len(), c.field_len());
            // The other curve's point, garbage, and the identity fail.
            let other = Ecdh::generate(if c == Curve::P256 {
                Curve::P384
            } else {
                Curve::P256
            });
            assert!(a.agree(&other.point).is_none());
            assert!(a.agree(&[0x04, 1, 2, 3]).is_none());
            assert!(a.agree(&[0x00]).is_none());
            let mut off = b.point.clone();
            let n = off.len();
            off[n - 1] ^= 1;
            assert!(a.agree(&off).is_none(), "off-curve point");
        }
    }

    #[test]
    fn the_public_value_names_its_curve() {
        let e = Ecdh::generate(Curve::P384);
        let spki = e.spki();
        let mut s = Reader::new(&spki).seq().unwrap();
        let (alg, params) = s.alg_id().unwrap();
        assert_eq!(alg, asn1::oid(ID_EC_PUBLIC_KEY));
        assert_eq!(Curve::from_params(params).unwrap(), Curve::P384);
        let point = s.bits().unwrap();
        assert_eq!((point[0], point.len()), (0x04, 97));
    }

    #[test]
    fn signatures_round_trip_with_any_digest_length() {
        for c in CURVES {
            let d = c.random_scalar();
            let sec1 = der::seq(&[
                der::int(1),
                der::octets(&d),
                der::field(0, asn1::oid_tlv(c.oid())),
            ]);
            let key = PrivateKey::from_sec1(&sec1, None).unwrap();
            for digest in [Sha256::digest(b"m").to_vec(), Sha512::digest(b"m").to_vec()] {
                let sig = key.sign(&digest).unwrap();
                assert!(key.public().verify(&digest, &sig), "{c:?}");
                assert!(!key.public().verify(&Sha256::digest(b"n"), &sig));
                let mut bad = sig.clone();
                let n = bad.len();
                bad[n - 1] ^= 1;
                assert!(!key.public().verify(&digest, &bad));
            }
        }
    }

    #[test]
    fn private_keys_need_a_consistent_named_curve() {
        let d = Curve::P256.random_scalar();
        let bare = der::seq(&[der::int(1), der::octets(&d)]);
        assert!(PrivateKey::from_sec1(&bare, None).is_err());
        assert!(PrivateKey::from_sec1(&bare, Some(Curve::P256)).is_ok());
        let named = der::seq(&[
            der::int(1),
            der::octets(&d),
            der::field(0, asn1::oid_tlv(Curve::P256.oid())),
        ]);
        assert!(PrivateKey::from_sec1(&named, Some(Curve::P384)).is_err());
        // Leading zero octets dropped by the writer are restored.
        let short = der::seq(&[
            der::int(1),
            der::octets(&d[1..]),
            der::field(0, asn1::oid_tlv(Curve::P256.oid())),
        ]);
        let mut z = d.clone();
        z[0] = 0;
        let k = PrivateKey::from_sec1(&short, None).unwrap();
        assert_eq!(k.d, z);
        assert!(
            Curve::from_params(Some(&asn1::oid_tlv("1.3.132.0.10"))).is_err(),
            "secp256k1"
        );
    }
}
