//! The CMS (RFC 5652) PKINIT uses: the KDC's SignedData around its DH
//! public value, checked to a trust anchor, and the client's SignedData
//! (or, anonymously, a bare ContentInfo) around its AuthPack, made as
//! MIT's `cms_signeddata_create` makes it.
//!
//! ```text
//! ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
//! SignedData ::= SEQUENCE {
//!     version, digestAlgorithms SET OF AlgorithmIdentifier,
//!     encapContentInfo SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING },
//!     certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
//!     crls [1] IMPLICIT OPTIONAL, signerInfos SET OF SignerInfo }
//! SignerInfo ::= SEQUENCE {
//!     version, sid IssuerAndSerialNumber, digestAlgorithm,
//!     signedAttrs [0] IMPLICIT SET OF Attribute OPTIONAL,
//!     signatureAlgorithm, signature OCTET STRING, unsignedAttrs [1] OPTIONAL }
//! ```

use super::asn1::{self, ReaderExt};
use super::keys::{Hash, PrivateKey, PublicKey, SigAlg};
use super::rsa;
use super::x509::{self, Cert};
use crate::der::{self, DerError, Reader};

type Result<T> = std::result::Result<T, DerError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(DerError(msg.into()))
}

const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// `id-pkinit-authData`: the AuthPack's content type.
pub(crate) const ID_PKINIT_AUTH_DATA: &str = "1.3.6.1.5.2.3.1";
/// `id-pkinit-DHKeyData`: the KDCDHKeyInfo's content type.
pub(crate) const ID_PKINIT_DHKEY_DATA: &str = "1.3.6.1.5.2.3.2";
const ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

/// `[0] EXPLICIT OCTET STRING` holding `content`.
fn econtent(content_type: &str, content: &[u8]) -> Vec<u8> {
    der::seq(&[
        asn1::oid_tlv(content_type),
        der::tlv(der::ctx(0), &der::octets(content)),
    ])
}

/// A ContentInfo of `content_type` holding `content` as an OCTET STRING:
/// what MIT's client sends for anonymous PKINIT to a KDC that has not
/// said it follows RFC 6112.
pub(crate) fn content_info(content_type: &str, content: &[u8]) -> Vec<u8> {
    econtent(content_type, content)
}

/// Who signs a SignedData: the key, and the certificates to send, the
/// signer's first.
pub(crate) struct Signer<'a> {
    pub(crate) key: &'a PrivateKey,
    pub(crate) certs: &'a [Cert],
}

/// A SignedData ContentInfo around `content`, signed with SHA-256 by
/// `signer` over the contentType and messageDigest attributes, or with no
/// signer at all (anonymous PKINIT, RFC 8062 §4.1).
pub(crate) fn signed_data(
    content_type: &str,
    content: &[u8],
    signer: Option<Signer<'_>>,
) -> Result<Vec<u8>> {
    let mut digest_algs = Vec::new();
    let mut signer_infos = Vec::new();
    let mut parts = vec![der::int(3)];
    let mut certs = Vec::new();
    if let Some(s) = signer {
        let me = s
            .certs
            .first()
            .ok_or_else(|| DerError("no signing certificate".into()))?;
        let alg = s.key.sig_alg();
        let hash = alg.hash();
        let digest_alg = asn1::alg_id(hash.oid(), Some(asn1::null()));
        let attrs = vec![
            der::seq(&[
                asn1::oid_tlv(ATTR_CONTENT_TYPE),
                asn1::set_of(vec![asn1::oid_tlv(content_type)]),
            ]),
            der::seq(&[
                asn1::oid_tlv(ATTR_MESSAGE_DIGEST),
                asn1::set_of(vec![der::octets(&hash.digest(content))]),
            ]),
        ];
        let signed_attrs = asn1::set_of(attrs);
        let sig = s.key.sign(&hash.digest(&signed_attrs))?;
        // The same SET, IMPLICIT [0] in place of the SET tag.
        let mut implicit_attrs = signed_attrs;
        implicit_attrs[0] = der::ctx(0);
        signer_infos.push(der::seq(&[
            der::int(1),
            der::seq(&[me.issuer.clone(), der::tlv(der::INTEGER, &me.serial)]),
            digest_alg.clone(),
            implicit_attrs,
            alg.alg_id(),
            der::octets(&sig),
        ]));
        digest_algs.push(digest_alg);
        certs = s.certs.iter().map(|c| c.der.clone()).collect();
    }
    parts.push(asn1::set_of(digest_algs));
    parts.push(econtent(content_type, content));
    if !certs.is_empty() {
        parts.push(der::cons(der::ctx(0), &certs));
    }
    parts.push(asn1::set_of(signer_infos));
    Ok(der::seq(&[
        asn1::oid_tlv(ID_SIGNED_DATA),
        der::field(0, der::seq(&parts)),
    ]))
}

/// What a verified SignedData carried, and who signed it.
#[derive(Debug)]
pub(crate) struct Verified {
    pub(crate) content: Vec<u8>,
    pub(crate) signer: Cert,
}

/// Check a SignedData ContentInfo of `content_type`: one signer, found
/// among the certificates sent by issuer and serial number, whose
/// signature over the signed attributes verifies, whose attributes name
/// the content type and carry the content's digest, and whose certificate
/// chains to one of `anchors` at `now`.
pub(crate) fn verify(
    data: &[u8],
    content_type: &str,
    anchors: &[Cert],
    now: i64,
) -> Result<Verified> {
    let mut outer = Reader::new(data);
    let mut ci = outer.seq()?;
    outer.done("ContentInfo")?;
    if ci.oid()? != asn1::oid(ID_SIGNED_DATA) {
        return err("not a CMS SignedData");
    }
    let mut sd = Reader::new(ci.expect(der::ctx(0))?).seq()?;
    ci.done("ContentInfo")?;

    sd.int()?; // version
    sd.expect(asn1::SET)?; // digestAlgorithms: the SignerInfo names its own
    let mut encap = sd.seq()?;
    if encap.oid()? != asn1::oid(content_type) {
        return err("SignedData carries the wrong content type");
    }
    let content = Reader::new(encap.expect(der::ctx(0))?).octets()?.to_vec();
    encap.done("EncapsulatedContentInfo")?;
    let mut certs = Vec::new();
    if let Some(set) = sd.optional(der::ctx(0))? {
        let mut r = Reader::new(set);
        while !r.is_empty() {
            let (tag, _, raw) = r.next_raw()?;
            // Only plain certificates; other CertificateChoices are skipped.
            if tag == der::SEQUENCE {
                certs.push(Cert::from_der(raw)?);
            }
        }
    }
    sd.optional(der::ctx(1))?; // crls
    let mut infos = Reader::new(sd.expect(asn1::SET)?);
    sd.done("SignedData")?;
    if infos.is_empty() {
        return err("SignedData has no signer");
    }
    let mut si = infos.seq()?;
    if !infos.is_empty() {
        return err("SignedData with more than one signer");
    }

    si.int()?; // version
    let mut sid = si.seq()?;
    let issuer = sid.next_raw()?.2;
    let serial = sid.expect(der::INTEGER)?;
    sid.done("IssuerAndSerialNumber")?;
    let (digest_oid, _) = si.alg_id()?;
    let hash = Hash::from_oid(digest_oid)
        .ok_or_else(|| DerError("unsupported SignedData digest algorithm".into()))?;
    let attrs = si
        .optional(der::ctx(0))?
        .ok_or_else(|| DerError("SignedData without signed attributes".into()))?;
    // The signature algorithm names its own hash, which must be the
    // digest algorithm's; bare rsaEncryption takes the digest algorithm's.
    let (sig_oid, _) = si.alg_id()?;
    let alg = match SigAlg::from_oid(sig_oid) {
        Some(a) if a.hash() == hash => a,
        None if sig_oid == asn1::oid(rsa::RSA_ENCRYPTION) => SigAlg::Rsa(hash),
        _ => return err("unsupported or inconsistent SignedData signature algorithm"),
    };
    let signature = si.octets()?;
    si.optional(der::ctx(1))?; // unsignedAttrs
    si.done("SignerInfo")?;

    let mut content_type_ok = false;
    let mut digest_ok = false;
    let mut a = Reader::new(attrs);
    while !a.is_empty() {
        let mut attr = a.seq()?;
        let oid = attr.oid()?;
        let mut values = Reader::new(attr.expect(asn1::SET)?);
        attr.done("Attribute")?;
        let (tag, value) = values.next()?;
        if !values.is_empty() {
            return err("a signed attribute with more than one value");
        }
        if oid == asn1::oid(ATTR_CONTENT_TYPE) {
            content_type_ok = tag == asn1::OID && value == asn1::oid(content_type);
        } else if oid == asn1::oid(ATTR_MESSAGE_DIGEST) {
            digest_ok = tag == der::OCTET_STRING && value == hash.digest(&content);
        }
    }
    if !content_type_ok || !digest_ok {
        return err("SignedData's signed attributes do not match its content");
    }

    let signer = certs
        .iter()
        .find(|c| c.issuer == issuer && c.serial == serial)
        .ok_or_else(|| DerError("SignedData does not include the signer's certificate".into()))?;
    let signed = der::tlv(asn1::SET, attrs);
    let key = signer.public_key()?;
    // MIT's KDC before 1.22 labels ECDSA signatures sha256WithRSAEncryption;
    // OpenSSL goes by the signer's key, and so does this. The signature
    // must still verify under that key.
    let alg = match (&key, alg) {
        (PublicKey::Ec(_), SigAlg::Rsa(h)) => SigAlg::Ecdsa(h),
        _ => alg,
    };
    if !key.verify(alg, &hash.digest(&signed), signature) {
        return err("SignedData signature does not verify");
    }
    x509::verify_chain(signer, &certs, anchors, now)?;
    Ok(Verified {
        content,
        signer: signer.clone(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::pkinit::pem;
    use crate::pkinit::x509::tests::{NOW, fixture};

    pub(crate) fn kdc_key() -> PrivateKey {
        PrivateKey::from_pem_blocks(&pem::blocks(include_bytes!("testdata/kdc-key.pem")).unwrap())
            .unwrap()
    }

    /// A SignedData as the test KDC would sign it, with its chain.
    pub(crate) fn kdc_signed(content_type: &str, content: &[u8]) -> Vec<u8> {
        let key = kdc_key();
        let certs = [fixture("kdc"), fixture("inter")];
        signed_data(
            content_type,
            content,
            Some(Signer {
                key: &key,
                certs: &certs,
            }),
        )
        .unwrap()
    }

    #[test]
    fn a_signed_data_verifies_to_its_anchor() {
        let sd = kdc_signed(ID_PKINIT_DHKEY_DATA, b"key info");
        let v = verify(&sd, ID_PKINIT_DHKEY_DATA, &[fixture("ca")], NOW).unwrap();
        assert_eq!(v.content, b"key info");
        assert_eq!(v.signer, fixture("kdc"));
    }

    #[test]
    fn a_signed_data_is_refused_for_any_flaw() {
        let sd = kdc_signed(ID_PKINIT_DHKEY_DATA, b"key info");
        let ca = [fixture("ca")];
        // The wrong content type expected; an untrusted anchor.
        assert!(verify(&sd, ID_PKINIT_AUTH_DATA, &ca, NOW).is_err());
        assert!(verify(&sd, ID_PKINIT_DHKEY_DATA, &[fixture("other-ca")], NOW).is_err());
        // The content altered after signing: the digest no longer matches.
        let mut bad = sd.clone();
        let at = bad.windows(8).position(|w| w == b"key info").unwrap();
        bad[at] = b'K';
        let e = verify(&bad, ID_PKINIT_DHKEY_DATA, &ca, NOW).unwrap_err();
        assert!(e.0.contains("signed attributes"), "{e}");
        // The signature altered: its last octet sits at the very end.
        let mut bad = sd.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        let e = verify(&bad, ID_PKINIT_DHKEY_DATA, &ca, NOW).unwrap_err();
        assert!(e.0.contains("signature"), "{e}");
        // No signer at all, as an anonymous client sends.
        let unsigned = signed_data(ID_PKINIT_DHKEY_DATA, b"key info", None).unwrap();
        assert!(verify(&unsigned, ID_PKINIT_DHKEY_DATA, &ca, NOW).is_err());
        // Without the intermediate the chain is incomplete; naming a
        // signer whose key did not sign fails the signature.
        let key = kdc_key();
        let sign = |certs: &[Cert]| {
            signed_data(
                ID_PKINIT_DHKEY_DATA,
                b"key info",
                Some(Signer { key: &key, certs }),
            )
            .unwrap()
        };
        let e = verify(&sign(&[fixture("kdc")]), ID_PKINIT_DHKEY_DATA, &ca, NOW).unwrap_err();
        assert!(e.0.contains("anchor"), "{e}");
        let e = verify(
            &sign(&[fixture("inter"), fixture("kdc")]),
            ID_PKINIT_DHKEY_DATA,
            &ca,
            NOW,
        )
        .unwrap_err();
        assert!(e.0.contains("signature"), "{e}");
        for cut in [0, 10, sd.len() / 2, sd.len() - 1] {
            assert!(verify(&sd[..cut], ID_PKINIT_DHKEY_DATA, &ca, NOW).is_err());
        }
    }

    /// A reply recorded from MIT 1.21's KDC with a P-256 key: ECDSA
    /// signed, but labelled sha256WithRSAEncryption, as MIT's KDC labels
    /// every signature before 1.22. Checked at a time its 2026–2027
    /// certificate is valid.
    #[test]
    fn mit_1_21s_mislabelled_ecdsa_signature_verifies_as_openssl_verifies_it() {
        let sd = include_bytes!("testdata/mit121-ec-kdc-signeddata.der");
        let ca =
            crate::pkinit::x509::parse_certs(include_bytes!("testdata/mit121-ca.pem")).unwrap();
        let rsa_label = der::tlv(asn1::OID, &asn1::oid("1.2.840.113549.1.1.11"));
        assert!(sd.windows(rsa_label.len()).any(|w| w == rsa_label));
        let v = verify(sd, ID_PKINIT_DHKEY_DATA, &ca, 1_792_100_000).unwrap();
        assert!(matches!(v.signer.public_key().unwrap(), PublicKey::Ec(_)));
        // Any alteration of the signed content still fails.
        let mut bad = sd.to_vec();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(verify(&bad, ID_PKINIT_DHKEY_DATA, &ca, 1_792_100_000).is_err());
    }

    #[test]
    fn the_anonymous_content_info_holds_the_auth_pack() {
        let ci = content_info(ID_PKINIT_AUTH_DATA, b"auth pack");
        let mut r = Reader::new(&ci);
        let mut s = r.seq().unwrap();
        assert_eq!(s.oid().unwrap(), asn1::oid(ID_PKINIT_AUTH_DATA));
        let mut c = Reader::new(s.expect(der::ctx(0)).unwrap());
        assert_eq!(c.octets().unwrap(), b"auth pack");
    }
}
