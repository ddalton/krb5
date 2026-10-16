//! Just enough X.509 (RFC 5280) for PKINIT: parse a certificate, build
//! and check its chain to a trust anchor, and read the PKINIT
//! subjectAltName and extendedKeyUsage.
//!
//! Chain building follows issuer names (compared as DER octets) through
//! the certificates at hand, checking each signature, validity period,
//! CA flag, `keyCertSign` and path length on the way. A critical
//! extension this module does not understand fails the chain, as RFC 5280
//! §4.2 requires. Revocation is the CRL module's (`super::crl`), over the
//! path [`verify_chain`] returns.

use super::asn1::{self, ReaderExt, implicit};
use super::keys::{PublicKey, SigAlg};
use crate::client::Principal;
use crate::der::{self, DerError, Fields, Reader};

type Result<T> = std::result::Result<T, DerError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(DerError(msg.into()))
}

const BASIC_CONSTRAINTS: &str = "2.5.29.19";
const KEY_USAGE: &str = "2.5.29.15";
const EXT_KEY_USAGE: &str = "2.5.29.37";
const SUBJECT_ALT_NAME: &str = "2.5.29.17";
/// Extensions that may be critical without failing the chain: the ones
/// read here, and the key identifiers, which only help chain building.
const UNDERSTOOD: [&str; 6] = [
    BASIC_CONSTRAINTS,
    KEY_USAGE,
    EXT_KEY_USAGE,
    SUBJECT_ALT_NAME,
    "2.5.29.14", // subjectKeyIdentifier
    "2.5.29.35", // authorityKeyIdentifier
];

/// `id-pkinit-san` (RFC 4556 §3.2.2): a KRB5PrincipalName otherName.
pub(crate) const ID_PKINIT_SAN: &str = "1.3.6.1.5.2.2";
/// `id-pkinit-KPKdc` and `id-pkinit-KPClientAuth` (RFC 4556 §3.2.4, §3.2.2).
pub(crate) const ID_PKINIT_KP_KDC: &str = "1.3.6.1.5.2.3.5";

/// keyUsage bits (RFC 5280 §4.2.1.3), numbered from the MSB.
pub(crate) const KU_DIGITAL_SIGNATURE: u32 = 0;
const KU_KEY_CERT_SIGN: u32 = 5;

/// How many CA certificates a chain may pass through.
const MAX_DEPTH: usize = 8;

/// A parsed certificate. The raw parts are kept as DER for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cert {
    pub(crate) der: Vec<u8>,
    tbs: Vec<u8>,
    sig_alg: Vec<u8>,
    signature: Vec<u8>,
    /// The serial number INTEGER's content octets.
    pub(crate) serial: Vec<u8>,
    /// The issuer and subject Names, whole TLVs.
    pub(crate) issuer: Vec<u8>,
    pub(crate) subject: Vec<u8>,
    not_before: i64,
    not_after: i64,
    /// SubjectPublicKeyInfo: the algorithm OID, its parameters and the
    /// BIT STRING content.
    key_alg: Vec<u8>,
    key_params: Option<Vec<u8>>,
    key: Vec<u8>,
    extensions: Vec<Extension>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Extension {
    pub(super) oid: Vec<u8>,
    pub(super) critical: bool,
    pub(super) value: Vec<u8>,
}

/// `Extensions ::= SEQUENCE OF Extension`, from the SEQUENCE's encoding.
/// An extension may appear only once (RFC 5280 §4.2, §5.2).
pub(super) fn read_extensions(exts: &[u8]) -> Result<Vec<Extension>> {
    let mut extensions = Vec::new();
    let mut seq = Reader::new(exts).seq()?;
    while !seq.is_empty() {
        let mut e = seq.seq()?;
        let oid = e.oid()?.to_vec();
        let critical = match e.optional(asn1::BOOLEAN)? {
            Some([0xFF]) => true,
            Some([0x00]) => return err("DEFAULT FALSE encoded (not DER)"),
            Some(_) => return err("bad BOOLEAN"),
            None => false,
        };
        let value = e.octets()?.to_vec();
        e.done("Extension")?;
        if extensions.iter().any(|x: &Extension| x.oid == oid) {
            return err("an extension appears twice");
        }
        extensions.push(Extension {
            oid,
            critical,
            value,
        });
    }
    Ok(extensions)
}

impl Cert {
    /// ```text
    /// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature BIT STRING }
    /// TBSCertificate ::= SEQUENCE {
    ///     version [0] EXPLICIT DEFAULT v1, serialNumber, signature AlgorithmIdentifier,
    ///     issuer Name, validity SEQUENCE { notBefore, notAfter }, subject Name,
    ///     subjectPublicKeyInfo, issuerUniqueID [1] IMPLICIT OPTIONAL,
    ///     subjectUniqueID [2] IMPLICIT OPTIONAL, extensions [3] EXPLICIT OPTIONAL }
    /// ```
    pub(crate) fn from_der(der: &[u8]) -> Result<Cert> {
        let mut outer = Reader::new(der);
        let mut c = outer.seq()?;
        outer.done("Certificate")?;
        let (_, tbs_content, tbs) = c.next_raw()?;
        let (sig_alg, _) = c.alg_id()?;
        let signature = c.bits()?.to_vec();
        c.done("Certificate")?;

        let mut t = Reader::new(tbs_content);
        let version = match t.optional(der::ctx(0))? {
            Some(v) => Reader::new(v).int()?,
            None => 0,
        };
        let serial = t.expect(der::INTEGER)?.to_vec();
        let (inner_alg, _) = t.alg_id()?;
        if inner_alg != sig_alg {
            return err("certificate signature algorithms disagree");
        }
        let issuer = t.next_raw()?.2.to_vec();
        let mut validity = t.seq()?;
        let not_before = read_time(&mut validity)?;
        let not_after = read_time(&mut validity)?;
        validity.done("Validity")?;
        let subject = t.next_raw()?.2.to_vec();
        let mut spki = t.seq()?;
        let (key_alg, key_params) = spki.alg_id()?;
        let key = spki.bits()?.to_vec();
        spki.done("SubjectPublicKeyInfo")?;
        // issuerUniqueID, subjectUniqueID: [1], [2] IMPLICIT BIT STRING.
        t.optional(implicit(1))?;
        t.optional(implicit(2))?;
        let mut extensions = Vec::new();
        if let Some(exts) = t.optional(der::ctx(3))? {
            if version != 2 {
                return err("extensions in a certificate before v3");
            }
            extensions = read_extensions(exts)?;
        }
        t.done("TBSCertificate")?;
        Ok(Cert {
            der: der.to_vec(),
            tbs: tbs.to_vec(),
            sig_alg: sig_alg.to_vec(),
            signature,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            key_alg: key_alg.to_vec(),
            key_params: key_params.map(<[u8]>::to_vec),
            key,
            extensions,
        })
    }

    pub(super) fn extension(&self, dotted: &str) -> Option<&Extension> {
        let oid = asn1::oid(dotted);
        self.extensions.iter().find(|e| e.oid == oid)
    }

    /// The subject's public key, RSA or EC.
    pub(crate) fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_spki(&self.key_alg, self.key_params.as_deref(), &self.key)
    }

    /// Whether `issuer`'s key made this certificate's signature.
    fn signed_by(&self, issuer: &Cert) -> bool {
        issuer.made(&self.sig_alg, &self.tbs, &self.signature)
    }

    /// Whether this certificate's key made `signature` over `tbs` with
    /// `sig_alg`.
    pub(super) fn made(&self, sig_alg: &[u8], tbs: &[u8], signature: &[u8]) -> bool {
        let Some(alg) = SigAlg::from_oid(sig_alg) else {
            return false;
        };
        self.public_key()
            .is_ok_and(|k| k.verify(alg, &alg.hash().digest(tbs), signature))
    }

    /// Whether basicConstraints makes this a CA.
    pub(super) fn is_ca(&self) -> bool {
        self.basic_constraints().is_ok_and(|(ca, _)| ca)
    }

    /// `basicConstraints`: (cA, pathLenConstraint).
    fn basic_constraints(&self) -> Result<(bool, Option<i64>)> {
        let Some(e) = self.extension(BASIC_CONSTRAINTS) else {
            return Ok((false, None));
        };
        let mut r = Reader::new(&e.value);
        let mut s = r.seq()?;
        let ca = matches!(s.optional(asn1::BOOLEAN)?, Some([0xFF]));
        let len = if s.is_empty() { None } else { Some(s.int()?) };
        Ok((ca, len))
    }

    /// Whether keyUsage is present and asserts bit `bit`.
    pub(crate) fn key_usage(&self, bit: u32) -> Result<Option<bool>> {
        let Some(e) = self.extension(KEY_USAGE) else {
            return Ok(None);
        };
        let c = Reader::new(&e.value).expect(der::BIT_STRING)?;
        let byte = 1 + (bit / 8) as usize;
        Ok(Some(
            c.get(byte).is_some_and(|b| b & (0x80 >> (bit % 8)) != 0),
        ))
    }

    /// Whether extendedKeyUsage lists `dotted`.
    pub(crate) fn has_eku(&self, dotted: &str) -> Result<bool> {
        let Some(e) = self.extension(EXT_KEY_USAGE) else {
            return Ok(false);
        };
        let want = asn1::oid(dotted);
        let mut s = Reader::new(&e.value).seq()?;
        while !s.is_empty() {
            if s.oid()? == want {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The subjectAltName's PKINIT principals (`id-pkinit-san` otherNames)
    /// and dNSNames.
    ///
    /// ```text
    /// GeneralName ::= CHOICE { otherName [0] IMPLICIT SEQUENCE {
    ///     type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }, ...,
    ///     dNSName [2] IMPLICIT IA5String, ... }
    /// KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1] PrincipalName }
    /// ```
    pub(crate) fn san(&self) -> Result<(Vec<Principal>, Vec<String>)> {
        let (mut principals, mut dns) = (Vec::new(), Vec::new());
        let Some(e) = self.extension(SUBJECT_ALT_NAME) else {
            return Ok((principals, dns));
        };
        let mut names = Reader::new(&e.value).seq()?;
        while !names.is_empty() {
            match names.next()? {
                (t, c) if t == implicit(0) | 0x20 => {
                    let mut on = Reader::new(c);
                    if on.oid()? != asn1::oid(ID_PKINIT_SAN) {
                        continue;
                    }
                    let mut v = Reader::new(on.expect(der::ctx(0))?);
                    let f = Fields::parse("KRB5PrincipalName", v.expect(der::SEQUENCE)?)?;
                    let realm = f.get(0)?.string()?;
                    principals.push(
                        Principal::decode_name(f.get(1)?, realm)
                            .map_err(|e| DerError(e.to_string()))?,
                    );
                }
                (t, c) if t == implicit(2) => {
                    dns.push(String::from_utf8_lossy(c).into_owned());
                }
                _ => {}
            }
        }
        Ok((principals, dns))
    }
}

/// UTCTime (`YYMMDDHHMMSSZ`, years 1950–2049) or GeneralizedTime
/// (`YYYYMMDDHHMMSSZ`), as RFC 5280 §4.1.2.5 allows them.
pub(super) fn read_time(r: &mut Reader<'_>) -> Result<i64> {
    let (tag, c) = r.next()?;
    let s = std::str::from_utf8(c)
        .ok()
        .filter(|s| s.is_ascii())
        .ok_or_else(|| DerError("time is not ASCII".into()))?;
    let full = match (tag, s.len()) {
        (asn1::UTC_TIME, 13) => {
            let yy: u32 = s[..2].parse().map_err(|_| DerError("bad UTCTime".into()))?;
            format!("{}{s}", if yy >= 50 { "19" } else { "20" })
        }
        (der::GENERALIZED_TIME, 15) => s.to_string(),
        _ => return err(format!("unsupported time {s:?}")),
    };
    chrono::NaiveDateTime::parse_from_str(&full, "%Y%m%d%H%M%SZ")
        .map(|t| t.and_utc().timestamp())
        .map_err(|e| DerError(format!("time {s:?}: {e}")))
}

/// The certificates read from PEM `CERTIFICATE` blocks or, failing any,
/// one DER certificate.
pub(crate) fn parse_certs(data: &[u8]) -> std::result::Result<Vec<Cert>, String> {
    if data.first() == Some(&der::SEQUENCE) {
        return Cert::from_der(data).map(|c| vec![c]).map_err(|e| e.0);
    }
    super::pem::blocks(data)?
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE" || label == "TRUSTED CERTIFICATE")
        .map(|(_, d)| Cert::from_der(&d).map_err(|e| e.0))
        .collect()
}

/// Check that `leaf` chains to one of `anchors` through `pool`, at `now`.
/// Each certificate must be within its validity period (anchors too, as
/// OpenSSL checks them), each issuer below the anchor a CA allowed to sign
/// certificates at that depth. A certificate that is itself an anchor is
/// trusted as is.
///
/// Returns the path, `leaf` first and the anchor last.
pub(crate) fn verify_chain<'a>(
    leaf: &'a Cert,
    pool: &'a [Cert],
    anchors: &'a [Cert],
    now: i64,
) -> Result<Vec<&'a Cert>> {
    let mut path = vec![leaf];
    let mut cur = leaf;
    // CA certificates passed below the current one, for pathLenConstraint.
    let mut below = 0i64;
    for _ in 0..=MAX_DEPTH {
        if cur.der != leaf.der {
            below += 1;
        }
        check_current(cur, now)?;
        if anchors.iter().any(|a| a.der == cur.der) {
            return Ok(path);
        }
        if let Some(a) = anchors
            .iter()
            .find(|a| a.subject == cur.issuer && cur.signed_by(a))
        {
            check_current(a, now)?;
            check_issuer(a, below)?;
            path.push(a);
            return Ok(path);
        }
        let Some(next) = pool
            .iter()
            .find(|c| c.subject == cur.issuer && c.der != cur.der && cur.signed_by(c))
        else {
            return err("the certificate does not chain to a trusted anchor (pkinit_anchors)");
        };
        check_issuer(next, below)?;
        path.push(next);
        cur = next;
    }
    err("certificate chain too long")
}

fn check_current(c: &Cert, now: i64) -> Result<()> {
    if now < c.not_before || now > c.not_after {
        return err("a certificate in the chain is not within its validity period");
    }
    let understood: Vec<Vec<u8>> = UNDERSTOOD.iter().map(|o| asn1::oid(o)).collect();
    if c.extensions
        .iter()
        .any(|e| e.critical && !understood.contains(&e.oid))
    {
        return err("a certificate in the chain has an unsupported critical extension");
    }
    Ok(())
}

/// May `issuer` sign a certificate with `below` CA certificates under it?
fn check_issuer(issuer: &Cert, below: i64) -> Result<()> {
    let (ca, path_len) = issuer.basic_constraints()?;
    if !ca {
        return err("an issuing certificate is not a CA");
    }
    if issuer.key_usage(KU_KEY_CERT_SIGN)? == Some(false) {
        return err("an issuing certificate may not sign certificates (keyUsage)");
    }
    if path_len.is_some_and(|l| below > l) {
        return err("the chain exceeds a CA's pathLenConstraint");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Inside every fixture's validity (made 2026, for a century).
    pub(crate) const NOW: i64 = 1_900_000_000;

    pub(crate) fn fixture(name: &str) -> Cert {
        let pem = match name {
            "ca" => include_str!("testdata/ca.pem"),
            "inter" => include_str!("testdata/inter.pem"),
            "kdc" => include_str!("testdata/kdc.pem"),
            "host" => include_str!("testdata/host.pem"),
            "leafsigned" => include_str!("testdata/leafsigned.pem"),
            "sub" => include_str!("testdata/sub.pem"),
            "subleaf" => include_str!("testdata/subleaf.pem"),
            "other-ca" => include_str!("testdata/other-ca.pem"),
            "ec-ca" => include_str!("testdata/ec-ca.pem"),
            "ec-kdc" => include_str!("testdata/ec-kdc.pem"),
            _ => unreachable!(),
        };
        parse_certs(pem.as_bytes()).unwrap().remove(0)
    }

    /// A 13-octet UTCTime whose second character is not ASCII: refused,
    /// where slicing out the two-digit year would split the character.
    #[test]
    fn a_non_ascii_time_is_refused() {
        for (tag, t) in [
            (asn1::UTC_TIME, "1\u{e9}010100000Z"),
            (der::GENERALIZED_TIME, "20\u{e9}0101000000Z"),
        ] {
            let mut d = vec![tag, t.len() as u8];
            d.extend_from_slice(t.as_bytes());
            assert!(read_time(&mut Reader::new(&d)).is_err(), "{t}");
        }
    }

    #[test]
    fn a_kdc_certificate_is_read_as_openssl_wrote_it() {
        let kdc = fixture("kdc");
        let (principals, dns) = kdc.san().unwrap();
        assert_eq!(
            principals,
            [Principal::new(2, ["krbtgt", "TEST.REALM"], "TEST.REALM")]
        );
        assert!(dns.is_empty());
        assert!(kdc.has_eku(ID_PKINIT_KP_KDC).unwrap());
        assert!(!kdc.has_eku("1.3.6.1.5.5.7.3.1").unwrap());
        assert_eq!(kdc.key_usage(KU_DIGITAL_SIGNATURE).unwrap(), Some(true));
        assert_eq!(kdc.key_usage(KU_KEY_CERT_SIGN).unwrap(), Some(false));
        assert_eq!(kdc.basic_constraints().unwrap(), (false, None));
        assert_eq!(kdc.serial, [3]);
        assert_eq!(
            fixture("inter").basic_constraints().unwrap(),
            (true, Some(0))
        );
        let (p, dns) = fixture("host").san().unwrap();
        assert!(p.is_empty());
        assert_eq!(dns, ["kdc.test.realm"]);
        // GeneralizedTime past 2049, UTCTime before.
        assert!(kdc.not_after > 4_102_444_800 && kdc.not_before < 4_102_444_800);
    }

    #[test]
    fn a_chain_through_an_intermediate_to_the_anchor_verifies() {
        let kdc = fixture("kdc");
        let (inter, ca) = ([fixture("inter")], [fixture("ca")]);
        verify_chain(&kdc, &[kdc.clone(), inter[0].clone()], &ca, NOW).unwrap();
        // The pool's order and extra certificates do not matter.
        let pool = [fixture("host"), inter[0].clone(), kdc.clone()];
        verify_chain(&kdc, &pool, &ca, NOW).unwrap();
        // A certificate that is itself an anchor is trusted, and so is
        // one issued by an anchor that is an intermediate.
        verify_chain(&kdc, &[], std::slice::from_ref(&kdc), NOW).unwrap();
        verify_chain(&kdc, &[], &inter, NOW).unwrap();
    }

    #[test]
    fn chains_that_openssl_refuses_are_refused() {
        let kdc = fixture("kdc");
        let (inter, ca) = ([fixture("inter")], [fixture("ca")]);
        let fails = |leaf: &Cert, pool: &[Cert], anchors: &[Cert], now| {
            verify_chain(leaf, pool, anchors, now).unwrap_err().0
        };
        // No anchors; a missing intermediate.
        assert!(fails(&kdc, &inter, &[], NOW).contains("trusted anchor"));
        assert!(fails(&kdc, &[], &ca, NOW).contains("trusted anchor"));
        // An anchor with the right name and the wrong key.
        assert!(fails(&kdc, &inter, &[fixture("other-ca")], NOW).contains("anchor"));
        // Outside the validity period (2023, and 2128).
        assert!(fails(&kdc, &inter, &ca, 1_700_000_000).contains("validity"));
        assert!(fails(&kdc, &inter, &ca, 5_000_000_000).contains("validity"));
        // Issued by a certificate that is not a CA.
        let pool = [kdc.clone(), inter[0].clone()];
        assert!(fails(&fixture("leafsigned"), &pool, &ca, NOW).contains("not a CA"));
        // One CA too many under inter's pathlen:0.
        let pool = [fixture("sub"), inter[0].clone()];
        assert!(fails(&fixture("subleaf"), &pool, &ca, NOW).contains("pathLen"));
        // A tampered certificate (its subject's CN) no longer verifies.
        let mut der = kdc.der.clone();
        let at = der.windows(3).position(|w| w == b"kdc").unwrap();
        der[at] = b'K';
        let forged = Cert::from_der(&der).unwrap();
        assert!(fails(&forged, &inter, &ca, NOW).contains("anchor"));
        // A critical extension nobody here understands.
        let mut odd = kdc.clone();
        odd.extensions.push(Extension {
            oid: asn1::oid("1.2.3.4"),
            critical: true,
            value: vec![5, 0],
        });
        assert!(fails(&odd, &inter, &ca, NOW).contains("critical"));
    }

    #[test]
    fn malformed_certificates_are_refused() {
        let der = fixture("kdc").der;
        for cut in [0, 1, 4, der.len() / 2, der.len() - 1] {
            assert!(Cert::from_der(&der[..cut]).is_err(), "cut {cut}");
        }
        let mut extra = der.clone();
        extra.push(0);
        assert!(Cert::from_der(&extra).is_err());
        assert!(parse_certs(b"no certificates here").unwrap().is_empty());
        assert_eq!(parse_certs(&der).unwrap().len(), 1);
    }
}
