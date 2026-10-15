//! PKCS #12 (RFC 7292) files: MIT's `X509_user_identity = PKCS12:file`.
//! A certificate and its private key, usually with CA certificates,
//! password-protected.
//!
//! Read as OpenSSL reads them, for the files people have:
//!
//! * OpenSSL 3 and current Windows: PBES2 (PBKDF2 with HMAC-SHA-1/2, and
//!   AES-CBC or 3DES-CBC), MAC by HMAC-SHA-256 or PBMAC1 (RFC 9579).
//! * OpenSSL 1.x, Windows' "TripleDES-SHA1", older Java: the PKCS #12 PBEs,
//!   3DES for the key and 40-bit RC2 for the certificates, MAC by
//!   HMAC-SHA-1. These are weak; they are only ever decrypted here.
//! * Unencrypted bags, and files without a MAC.
//!
//! BER with indefinite lengths (NSS, Apple's Keychain) is normalized to DER
//! first. The MAC, when present, is checked before anything is decrypted,
//! and is what says a password is wrong.

use super::asn1::{self, ReaderExt};
use super::keys::PrivateKey;
use super::x509::Cert;
use crate::der::{self, DerError, Reader};
use des::cipher::{Array, BlockCipherDecrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

type Result<T> = std::result::Result<T, Error>;

/// Why a PKCS #12 file could not be read.
#[derive(Debug)]
pub(crate) enum Error {
    /// The MAC does not verify, or decryption fails: the password.
    BadPassword,
    Malformed(String),
}

impl From<DerError> for Error {
    fn from(e: DerError) -> Self {
        Error::Malformed(e.0)
    }
}

fn bad<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Malformed(msg.into()))
}

const ID_DATA: &str = "1.2.840.113549.1.7.1";
const ID_ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";
const KEY_BAG: &str = "1.2.840.113549.1.12.10.1.1";
const SHROUDED_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.2";
const CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const X509_CERTIFICATE: &str = "1.2.840.113549.1.9.22.1";
const LOCAL_KEY_ID: &str = "1.2.840.113549.1.9.21";
const PBES2: &str = "1.2.840.113549.1.5.13";
const PBKDF2: &str = "1.2.840.113549.1.5.12";
const PBMAC1: &str = "1.2.840.113549.1.5.14";
const PBE_SHA1_RC2_128: &str = "1.2.840.113549.1.12.1.5";
const PBE_SHA1_RC2_40: &str = "1.2.840.113549.1.12.1.6";
const PBE_SHA1_3DES: &str = "1.2.840.113549.1.12.1.3";
const PBE_SHA1_2DES: &str = "1.2.840.113549.1.12.1.4";
const DES_EDE3_CBC: &str = "1.2.840.113549.3.7";
const AES128_CBC: &str = "2.16.840.1.101.3.4.1.2";
const AES192_CBC: &str = "2.16.840.1.101.3.4.1.22";
const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";

/// The digests PKCS #12 MACs and PBKDF2 PRFs use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Digest12 {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Digest12 {
    fn from_digest_oid(oid: &[u8]) -> Option<Self> {
        [
            ("1.3.14.3.2.26", Digest12::Sha1),
            ("2.16.840.1.101.3.4.2.4", Digest12::Sha224),
            ("2.16.840.1.101.3.4.2.1", Digest12::Sha256),
            ("2.16.840.1.101.3.4.2.2", Digest12::Sha384),
            ("2.16.840.1.101.3.4.2.3", Digest12::Sha512),
        ]
        .into_iter()
        .find(|(o, _)| asn1::oid(o) == oid)
        .map(|(_, d)| d)
    }

    /// `hmacWithSHA*`, PBKDF2's and PBMAC1's PRFs.
    fn from_hmac_oid(oid: &[u8]) -> Option<Self> {
        [
            ("1.2.840.113549.2.7", Digest12::Sha1),
            ("1.2.840.113549.2.8", Digest12::Sha224),
            ("1.2.840.113549.2.9", Digest12::Sha256),
            ("1.2.840.113549.2.10", Digest12::Sha384),
            ("1.2.840.113549.2.11", Digest12::Sha512),
        ]
        .into_iter()
        .find(|(o, _)| asn1::oid(o) == oid)
        .map(|(_, d)| d)
    }

    fn len(self) -> usize {
        match self {
            Digest12::Sha1 => 20,
            Digest12::Sha224 => 28,
            Digest12::Sha256 => 32,
            Digest12::Sha384 => 48,
            Digest12::Sha512 => 64,
        }
    }

    /// The hash's block size, PKCS #12's KDF's `v`.
    fn block(self) -> usize {
        match self {
            Digest12::Sha1 | Digest12::Sha224 | Digest12::Sha256 => 64,
            Digest12::Sha384 | Digest12::Sha512 => 128,
        }
    }

    fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut h = D::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        match self {
            Digest12::Sha1 => run::<Sha1>(parts),
            Digest12::Sha224 => run::<Sha224>(parts),
            Digest12::Sha256 => run::<Sha256>(parts),
            Digest12::Sha384 => run::<Sha384>(parts),
            Digest12::Sha512 => run::<Sha512>(parts),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        macro_rules! run {
            ($d:ty) => {{
                let mut m = <Hmac<$d> as KeyInit>::new_from_slice(key).expect("HMAC takes any key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            Digest12::Sha1 => run!(Sha1),
            Digest12::Sha224 => run!(Sha224),
            Digest12::Sha256 => run!(Sha256),
            Digest12::Sha384 => run!(Sha384),
            Digest12::Sha512 => run!(Sha512),
        }
    }

    fn pbkdf2(self, password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
        use pbkdf2::pbkdf2_hmac;
        match self {
            Digest12::Sha1 => pbkdf2_hmac::<Sha1>(password, salt, rounds, out),
            Digest12::Sha224 => pbkdf2_hmac::<Sha224>(password, salt, rounds, out),
            Digest12::Sha256 => pbkdf2_hmac::<Sha256>(password, salt, rounds, out),
            Digest12::Sha384 => pbkdf2_hmac::<Sha384>(password, salt, rounds, out),
            Digest12::Sha512 => pbkdf2_hmac::<Sha512>(password, salt, rounds, out),
        }
    }
}

/// Iteration counts above this are refused: a hostile file could
/// otherwise make loading it take hours.
const MAX_ITERATIONS: i64 = 10_000_000;

fn iterations(r: &mut Reader<'_>) -> Result<u32> {
    let n = r.int()?;
    if !(1..=MAX_ITERATIONS).contains(&n) {
        return bad(format!("iteration count {n} out of range"));
    }
    Ok(n as u32)
}

/// The password as PKCS #12's KDF and PBEs take it: BMPString
/// (big-endian UTF-16) with a trailing NUL, or nothing at all for "no
/// password", which OpenSSL also tries.
fn bmp(password: Option<&str>) -> Vec<u8> {
    match password {
        None => Vec::new(),
        Some(p) => p
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_be_bytes)
            .collect(),
    }
}

/// RFC 7292 Appendix B.2: the PKCS #12 key derivation. `id` is 1 for keys,
/// 2 for IVs, 3 for MAC keys.
fn kdf12(d: Digest12, id: u8, password: &[u8], salt: &[u8], rounds: u32, len: usize) -> Vec<u8> {
    let v = d.block();
    let fill = |s: &[u8]| -> Vec<u8> {
        if s.is_empty() {
            return Vec::new();
        }
        let n = v * s.len().div_ceil(v);
        s.iter().copied().cycle().take(n).collect()
    };
    let diversifier = vec![id; v];
    let mut i: Vec<u8> = fill(salt);
    i.extend(fill(password));
    let mut out = Vec::with_capacity(len + d.len());
    while out.len() < len {
        let mut a = d.hash(&[&diversifier, &i]);
        for _ in 1..rounds {
            a = d.hash(&[&a]);
        }
        out.extend_from_slice(&a);
        if out.len() >= len {
            break;
        }
        // I_j += B + 1 (mod 2^(8v)) for each v-octet block of I.
        let b: Vec<u8> = a.iter().copied().cycle().take(v).collect();
        for block in i.chunks_mut(v) {
            let mut carry = 1u16;
            for k in (0..v).rev() {
                let s = u16::from(block[k]) + u16::from(b[k]) + carry;
                block[k] = s as u8;
                carry = s >> 8;
            }
        }
    }
    out.truncate(len);
    out
}

/// CBC decryption with PKCS #7 padding, for any block cipher.
fn cbc_decrypt<C: BlockCipherDecrypt>(
    cipher: &C,
    block: usize,
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % block != 0 || iv.len() != block {
        return Err(Error::BadPassword);
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = iv.to_vec();
    for c in data.chunks(block) {
        let mut b = Array::try_from(c).expect("one block");
        cipher.decrypt_block(&mut b);
        out.extend(b.iter().zip(&prev).map(|(x, p)| x ^ p));
        prev = c.to_vec();
    }
    let pad = usize::from(*out.last().expect("not empty"));
    if pad == 0
        || pad > block
        || !out[out.len() - pad..]
            .iter()
            .all(|&x| usize::from(x) == pad)
    {
        return Err(Error::BadPassword);
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

/// Decrypt `data` as the AlgorithmIdentifier `(oid, params)` says.
fn decrypt(
    oid: &[u8],
    params: Option<&[u8]>,
    password: Option<&str>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let params = params.ok_or_else(|| Error::Malformed("encryption without parameters".into()))?;
    let mut p = Reader::new(params).seq()?;
    let is = |o: &str| oid == asn1::oid(o);
    if is(PBES2) {
        // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
        let (kdf, kdf_params) = p.alg_id()?;
        let (enc, iv) = p.alg_id()?;
        if kdf != asn1::oid(PBKDF2) {
            return bad("PBES2 with a KDF other than PBKDF2");
        }
        let iv = Reader::new(iv.unwrap_or(&[])).octets()?;
        let key_len = match () {
            _ if enc == asn1::oid(AES128_CBC) => 16,
            _ if enc == asn1::oid(AES192_CBC) => 24,
            _ if enc == asn1::oid(AES256_CBC) => 32,
            _ if enc == asn1::oid(DES_EDE3_CBC) => 24,
            _ => return bad("unsupported PBES2 cipher"),
        };
        let key = pbkdf2_key(kdf_params, password.unwrap_or("").as_bytes(), key_len)?;
        return match key_len {
            16 => cbc_decrypt(
                &aes::Aes128::new_from_slice(&key).expect("16"),
                16,
                iv,
                data,
            ),
            24 if enc == asn1::oid(DES_EDE3_CBC) => cbc_decrypt(
                &des::TdesEde3::new_from_slice(&key).expect("24"),
                8,
                iv,
                data,
            ),
            24 => cbc_decrypt(
                &aes::Aes192::new_from_slice(&key).expect("24"),
                16,
                iv,
                data,
            ),
            _ => cbc_decrypt(
                &aes::Aes256::new_from_slice(&key).expect("32"),
                16,
                iv,
                data,
            ),
        };
    }
    // pkcs-12PbeParams ::= SEQUENCE { salt OCTET STRING, iterations INTEGER }
    let salt = p.octets()?;
    let rounds = iterations(&mut p)?;
    let pw = bmp(password);
    let k = |len| kdf12(Digest12::Sha1, 1, &pw, salt, rounds, len);
    let iv = kdf12(Digest12::Sha1, 2, &pw, salt, rounds, 8);
    if is(PBE_SHA1_3DES) {
        cbc_decrypt(
            &des::TdesEde3::new_from_slice(&k(24)).expect("24"),
            8,
            &iv,
            data,
        )
    } else if is(PBE_SHA1_2DES) {
        cbc_decrypt(
            &des::TdesEde2::new_from_slice(&k(16)).expect("16"),
            8,
            &iv,
            data,
        )
    } else if is(PBE_SHA1_RC2_40) {
        cbc_decrypt(&rc2::Rc2::new_with_eff_key_len(&k(5), 40), 8, &iv, data)
    } else if is(PBE_SHA1_RC2_128) {
        cbc_decrypt(&rc2::Rc2::new_with_eff_key_len(&k(16), 128), 8, &iv, data)
    } else {
        bad("unsupported PKCS #12 encryption")
    }
}

/// `PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount,
/// keyLength OPTIONAL, prf DEFAULT hmacWithSHA1 }`.
fn pbkdf2_key(params: Option<&[u8]>, password: &[u8], len: usize) -> Result<Vec<u8>> {
    let mut p = Reader::new(params.unwrap_or(&[])).seq()?;
    let salt = p.octets()?;
    let rounds = iterations(&mut p)?;
    let mut len = len;
    if p.rest().first() == Some(&der::INTEGER) {
        len = usize::try_from(p.int()?).map_err(|_| Error::Malformed("bad keyLength".into()))?;
    }
    let prf = if p.is_empty() {
        Digest12::Sha1
    } else {
        let (oid, _) = p.alg_id()?;
        Digest12::from_hmac_oid(oid)
            .ok_or_else(|| Error::Malformed("unsupported PBKDF2 PRF".into()))?
    };
    if len == 0 || len > 64 {
        return bad("bad PBKDF2 key length");
    }
    let mut key = vec![0; len];
    prf.pbkdf2(password, salt, rounds, &mut key);
    Ok(key)
}

/// `MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING,
/// iterations INTEGER DEFAULT 1 }` over the AuthenticatedSafe's octets.
fn check_mac(mac_data: &[u8], password: Option<&str>, auth_safe: &[u8]) -> Result<()> {
    let mut m = Reader::new(mac_data).seq()?;
    let mut info = m.seq()?;
    let (alg, alg_params) = info.alg_id()?;
    let expected = info.octets()?;
    let salt = m.octets()?;
    let rounds = if m.is_empty() { 1 } else { iterations(&mut m)? };
    let got = if alg == asn1::oid(PBMAC1) {
        // RFC 9579: PBMAC1-params ::= SEQUENCE { keyDerivationFunc (PBKDF2),
        // messageAuthScheme (hmacWithSHA*) }; the password as UTF-8.
        let mut p = Reader::new(alg_params.unwrap_or(&[])).seq()?;
        let (kdf, kdf_params) = p.alg_id()?;
        let (scheme, _) = p.alg_id()?;
        let h = Digest12::from_hmac_oid(scheme)
            .ok_or_else(|| Error::Malformed("unsupported PBMAC1 MAC".into()))?;
        if kdf != asn1::oid(PBKDF2) {
            return bad("PBMAC1 with a KDF other than PBKDF2");
        }
        let key = pbkdf2_key(kdf_params, password.unwrap_or("").as_bytes(), h.len())?;
        h.hmac(&key, auth_safe)
    } else {
        let d = Digest12::from_digest_oid(alg)
            .ok_or_else(|| Error::Malformed("unsupported PKCS #12 MAC digest".into()))?;
        let key = kdf12(d, 3, &bmp(password), salt, rounds, d.len());
        d.hmac(&key, auth_safe)
    };
    // The comparison need not be constant-time: the MAC is over public
    // data, and knowing it does not help guess the password.
    if got != expected {
        return Err(Error::BadPassword);
    }
    Ok(())
}

/// What a PKCS #12 file holds.
pub(crate) struct Contents {
    /// The certificate for the key first, then the others.
    pub(crate) certs: Vec<Cert>,
    pub(crate) key: PrivateKey,
}

/// Read a PKCS #12 file. With `password` `None`, the empty password is
/// tried both ways OpenSSL tries it (no octets, and the empty BMPString).
pub(crate) fn parse(data: &[u8], password: Option<&str>) -> Result<Contents> {
    let data = ber_to_der(data)?;
    match password {
        Some(p) => parse_der(&data, Some(p)),
        None => match parse_der(&data, None) {
            Err(Error::BadPassword) => parse_der(&data, Some("")),
            r => r,
        },
    }
}

/// `PFX ::= SEQUENCE { version 3, authSafe ContentInfo, macData OPTIONAL }`.
fn parse_der(data: &[u8], password: Option<&str>) -> Result<Contents> {
    let mut top = Reader::new(data);
    let mut pfx = top.seq()?;
    top.done("PFX")?;
    if pfx.int()? != 3 {
        return bad("not a PKCS #12 version 3 file");
    }
    let mut ci = pfx.seq()?;
    if ci.oid()? != asn1::oid(ID_DATA) {
        return bad("PKCS #12 with public-key integrity mode is not supported");
    }
    let auth_safe = Reader::new(ci.expect(der::ctx(0))?).octets()?;
    match pfx.optional(der::SEQUENCE)? {
        Some(mac) => check_mac(&der::tlv(der::SEQUENCE, mac), password, auth_safe)?,
        None => pfx.done("PFX")?,
    }

    let mut keys: Vec<(Option<Vec<u8>>, PrivateKey)> = Vec::new();
    let mut certs: Vec<(Option<Vec<u8>>, Cert)> = Vec::new();
    let mut safes = Reader::new(auth_safe).seq()?;
    while !safes.is_empty() {
        let mut c = safes.seq()?;
        let ty = c.oid()?;
        let inner = c.expect(der::ctx(0))?;
        let contents = if ty == asn1::oid(ID_DATA) {
            Reader::new(inner).octets()?.to_vec()
        } else if ty == asn1::oid(ID_ENCRYPTED_DATA) {
            // EncryptedData ::= SEQUENCE { version, EncryptedContentInfo {
            //     contentType, AlgorithmIdentifier, [0] IMPLICIT OCTET STRING } }
            let mut ed = Reader::new(inner).seq()?;
            ed.int()?;
            let mut eci = ed.seq()?;
            eci.oid()?;
            let (alg, params) = eci.alg_id()?;
            // [0] IMPLICIT OCTET STRING: primitive, or BER's constructed
            // form with the string inside.
            let enc = match eci.next()? {
                (0x80, c) => c,
                (0xA0, c) => Reader::new(c).octets()?,
                _ => return bad("bad encryptedContent"),
            };
            decrypt(alg, params, password, enc)?
        } else {
            return bad("unsupported PKCS #12 content type");
        };
        let mut bags = Reader::new(&contents).seq()?;
        while !bags.is_empty() {
            let mut bag = bags.seq()?;
            let id = bag.oid()?;
            let value = bag.expect(der::ctx(0))?;
            let local_id = match bag.optional(asn1::SET)? {
                Some(attrs) => local_key_id(attrs)?,
                None => None,
            };
            let is = |o: &str| id == asn1::oid(o);
            if is(KEY_BAG) || is(SHROUDED_KEY_BAG) {
                let pkcs8 = if is(KEY_BAG) {
                    value.to_vec()
                } else {
                    // EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
                    let mut e = Reader::new(value).seq()?;
                    let (alg, params) = e.alg_id()?;
                    decrypt(alg, params, password, e.octets()?)?
                };
                let key = PrivateKey::from_pem_blocks(&[("PRIVATE KEY".into(), pkcs8)])
                    .map_err(|_| Error::BadPassword)?;
                keys.push((local_id, key));
            } else if is(CERT_BAG) {
                // CertBag ::= SEQUENCE { certId, certValue [0] EXPLICIT }
                let mut cb = Reader::new(value).seq()?;
                if cb.oid()? != asn1::oid(X509_CERTIFICATE) {
                    continue; // SDSI certificates
                }
                let der = Reader::new(cb.expect(der::ctx(0))?).octets()?;
                certs.push((local_id, Cert::from_der(der)?));
            }
            // CRL, secret and nested bags are not needed here.
        }
    }

    let Some((key_id, key)) = keys.into_iter().next() else {
        return bad("the PKCS #12 file holds no private key");
    };
    // OpenSSL's PKCS12_parse: the certificate with the key's localKeyId,
    // else the one whose public key is the key's.
    let public = key.public();
    let pos = certs
        .iter()
        .position(|(id, _)| key_id.is_some() && *id == key_id)
        .or_else(|| {
            certs
                .iter()
                .position(|(_, c)| c.public_key().ok().as_ref() == Some(&public))
        })
        .ok_or_else(|| Error::Malformed("no certificate in the file matches its key".into()))?;
    let mine = certs.remove(pos).1;
    let mut all = vec![mine];
    all.extend(certs.into_iter().map(|(_, c)| c));
    Ok(Contents { certs: all, key })
}

/// A bag's `localKeyId` attribute, if any.
fn local_key_id(attrs: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut r = Reader::new(attrs);
    while !r.is_empty() {
        let mut a = r.seq()?;
        let oid = a.oid()?;
        let mut values = Reader::new(a.expect(asn1::SET)?);
        if oid == asn1::oid(LOCAL_KEY_ID) {
            return Ok(Some(values.octets()?.to_vec()));
        }
    }
    Ok(None)
}

/// Normalize BER to DER where it matters for parsing: indefinite and
/// non-minimal lengths become minimal definite ones, and constructed
/// OCTET STRINGs (and constructed `[0]` IMPLICIT ones holding OCTET STRING
/// pieces) become one primitive string.
fn ber_to_der(data: &[u8]) -> Result<Vec<u8>> {
    let (out, rest) = ber_element(data, 0)?;
    if !rest.is_empty() {
        return bad("trailing data after the PKCS #12 file");
    }
    Ok(out)
}

fn ber_element(data: &[u8], depth: usize) -> Result<(Vec<u8>, &[u8])> {
    if depth > 64 {
        return bad("nesting too deep");
    }
    let (&tag, rest) = data
        .split_first()
        .ok_or_else(|| Error::Malformed("truncated BER".into()))?;
    if tag & 0x1F == 0x1F {
        return bad("multi-octet tag");
    }
    let (&l0, mut rest) = rest
        .split_first()
        .ok_or_else(|| Error::Malformed("truncated BER".into()))?;
    let constructed = tag & 0x20 != 0;
    let mut children = Vec::new();
    let content: Vec<u8>;
    if l0 == 0x80 {
        if !constructed {
            return bad("indefinite length on a primitive");
        }
        loop {
            if rest.starts_with(&[0, 0]) {
                rest = &rest[2..];
                break;
            }
            let (child, r) = ber_element(rest, depth + 1)?;
            children.push(child);
            rest = r;
        }
        content = Vec::new();
    } else {
        let len = if l0 < 0x80 {
            usize::from(l0)
        } else {
            let k = usize::from(l0 & 0x7F);
            if k > 4 || rest.len() < k {
                return bad("bad BER length");
            }
            let n = rest[..k]
                .iter()
                .fold(0usize, |a, &b| (a << 8) | usize::from(b));
            rest = &rest[k..];
            n
        };
        if rest.len() < len {
            return bad("BER length overruns the data");
        }
        let (body, r) = rest.split_at(len);
        rest = r;
        if constructed {
            let mut b = body;
            while !b.is_empty() {
                let (child, r) = ber_element(b, depth + 1)?;
                children.push(child);
                b = r;
            }
            content = Vec::new();
        } else {
            content = body.to_vec();
        }
    }
    if !constructed {
        return Ok((der::tlv(tag, &content), rest));
    }
    // A constructed OCTET STRING, or a constructed [0] made only of OCTET
    // STRING pieces (encryptedContent), is joined into a primitive one.
    let all_strings = !children.is_empty() && children.iter().all(|c| c[0] == der::OCTET_STRING);
    let joined = |children: &[Vec<u8>]| -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for c in children {
            out.extend_from_slice(Reader::new(c).octets()?);
        }
        Ok(out)
    };
    if tag == 0x24 {
        return Ok((der::tlv(der::OCTET_STRING, &joined(&children)?), rest));
    }
    if tag == 0xA0 && all_strings && children.len() > 1 {
        return Ok((der::tlv(0x80, &joined(&children)?), rest));
    }
    Ok((der::cons(tag, &children), rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkinit::x509::tests::fixture;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The classic "smeg" vector, and others, all checked against OpenSSL's
    /// PKCS12KDF (`openssl kdf ... PKCS12KDF`).
    #[test]
    fn the_pkcs12_kdf_matches_openssl() {
        let smeg = bmp(Some("smeg"));
        assert_eq!(smeg, hex("0073006d006500670000"));
        let salt = hex("0A58CF64530D823F");
        assert_eq!(
            kdf12(Digest12::Sha1, 1, &smeg, &salt, 1, 24),
            hex("8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3")
        );
        assert_eq!(
            kdf12(Digest12::Sha1, 2, &smeg, &salt, 1, 8),
            hex("79993DFE048D3B76")
        );
        let queeg = bmp(Some("queeg"));
        let salt = hex("05DEC959ACFF72F7");
        assert_eq!(
            kdf12(Digest12::Sha256, 1, &queeg, &salt, 1000, 40),
            hex("74903B2A07C2FC6BFF672A1A8C30583DDC4F7C1A68930AC40917DCFE6BAA5AE3D7867C4CA9A8FB54")
        );
        assert_eq!(
            kdf12(Digest12::Sha512, 3, &queeg, &salt, 1000, 64),
            hex(concat!(
                "B2587204C6CBDA975C143740C4D3309850AC282BF83FB0E44F0FB90F2F76AE37",
                "ED6F81CFE5B0709A7920BC5DEE028715C7E18DD0DA540D7BAF112A4A7F08878B"
            ))
        );
        // The empty password both ways: no octets, and the empty BMPString.
        let salt = hex("0102030405060708");
        assert_eq!(
            kdf12(Digest12::Sha1, 3, &bmp(None), &salt, 3, 20),
            hex("4B659CF5A0B9E0C5973C14CAAFF8EE17E9DEDD25")
        );
        assert_eq!(
            kdf12(Digest12::Sha1, 3, &bmp(Some("")), &salt, 3, 20),
            hex("E1CA2B372B0ED9EDF1E3A521108564AA7DD59922")
        );
    }

    fn file(name: &str) -> &'static [u8] {
        match name {
            "modern" => include_bytes!("testdata/modern.p12"),
            "legacy" => include_bytes!("testdata/legacy.p12"),
            "pbes2-3des" => include_bytes!("testdata/pbes2-3des.p12"),
            "pbmac1" => include_bytes!("testdata/pbmac1.p12"),
            "ec" => include_bytes!("testdata/ec.p12"),
            "nopass" => include_bytes!("testdata/nopass.p12"),
            "plain" => include_bytes!("testdata/plain.p12"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn every_kind_of_file_opens_with_its_password() {
        for name in ["modern", "legacy", "pbes2-3des", "pbmac1"] {
            let c = parse(file(name), Some("secret")).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(
                c.certs[0],
                fixture("kdc"),
                "{name}: the key's certificate first"
            );
            assert_eq!(c.certs[1..], [fixture("inter")], "{name}");
            assert_eq!(Some(c.key.public()), c.certs[0].public_key().ok(), "{name}");
        }
        let ec = parse(file("ec"), Some("secret")).unwrap();
        assert_eq!(ec.certs, [fixture("ec-kdc")]);
        assert!(matches!(ec.key, PrivateKey::Ec(_)));
        for name in ["nopass", "plain"] {
            let c = parse(file(name), None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(c.certs[0], fixture("kdc"));
        }
    }

    #[test]
    fn a_wrong_or_missing_password_is_reported_as_such() {
        for name in ["modern", "legacy", "pbes2-3des", "pbmac1", "ec"] {
            assert!(
                matches!(parse(file(name), Some("wrong")), Err(Error::BadPassword)),
                "{name}"
            );
            assert!(
                matches!(parse(file(name), None), Err(Error::BadPassword)),
                "{name}"
            );
        }
        assert!(matches!(
            parse(file("nopass"), Some("x")),
            Err(Error::BadPassword)
        ));
    }

    /// Re-encode DER as BER the way NSS writes it: every constructed value
    /// with an indefinite length, every OCTET STRING in 100-octet pieces.
    fn to_indefinite_ber(der_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut r = Reader::new(der_data);
        while !r.is_empty() {
            let (tag, content) = r.next().unwrap();
            if tag & 0x20 != 0 {
                out.push(tag);
                out.push(0x80);
                out.extend(to_indefinite_ber(content));
                out.extend([0, 0]);
            } else if tag == der::OCTET_STRING && content.len() > 100 {
                out.extend([0x24, 0x80]);
                for chunk in content.chunks(100) {
                    out.extend(der::octets(chunk));
                }
                out.extend([0, 0]);
            } else {
                out.extend(der::tlv(tag, content));
            }
        }
        out
    }

    #[test]
    fn ber_with_indefinite_lengths_reads_like_the_der() {
        for name in ["modern", "legacy", "plain"] {
            let pw = (name != "plain").then_some("secret");
            let ber = to_indefinite_ber(file(name));
            assert_ne!(ber, file(name));
            let c = parse(&ber, pw).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(c.certs[0], fixture("kdc"), "{name}");
        }
        assert_eq!(
            ber_to_der(&to_indefinite_ber(file("modern"))).unwrap(),
            file("modern")
        );
    }

    /// The MAC protects the whole file: altered, it fails even with the
    /// right password and contents that would decrypt.
    #[test]
    fn an_altered_mac_fails_with_the_right_password() {
        let f = file("modern");
        // The file ends: digest (32 octets), salt (16), iterations (2048).
        assert!(f.ends_with(&[0x02, 0x02, 0x08, 0x00]));
        let mut bad = f.to_vec();
        let at = f.len() - 4 - 18 - 2 - 5;
        bad[at] ^= 1;
        assert!(matches!(
            parse(&bad, Some("secret")),
            Err(Error::BadPassword)
        ));
        parse(f, Some("secret")).unwrap();
    }

    #[test]
    fn cbc_padding_is_checked_whole() {
        use des::cipher::BlockCipherEncrypt;
        let key = aes::Aes128::new_from_slice(&[7; 16]).unwrap();
        let iv = [9u8; 16];
        let enc = |plain: [u8; 16]| {
            let mut b = Array::from(plain);
            for (x, v) in b.iter_mut().zip(iv) {
                *x ^= v;
            }
            key.encrypt_block(&mut b);
            b.to_vec()
        };
        let mut good = [0xAA; 16];
        good[12..].copy_from_slice(&[4, 4, 4, 4]);
        assert_eq!(cbc_decrypt(&key, 16, &iv, &enc(good)).unwrap(), [0xAA; 12]);
        let mut bad = good;
        bad[13] = 3; // ...03 04 04: the last octet says 4, one of them is not
        assert!(cbc_decrypt(&key, 16, &iv, &enc(bad)).is_err());
        let mut zero = good;
        zero[15] = 0;
        assert!(cbc_decrypt(&key, 16, &iv, &enc(zero)).is_err());
        assert!(cbc_decrypt(&key, 16, &iv, &enc(good)[..15]).is_err());
    }

    #[test]
    fn damaged_files_are_refused_not_panicked_on() {
        let f = file("modern");
        for cut in [0, 1, 2, 10, f.len() / 3, f.len() / 2, f.len() - 1] {
            assert!(parse(&f[..cut], Some("secret")).is_err(), "cut {cut}");
        }
        // Flipping any octet must fail cleanly (the MAC or the structure).
        for at in (0..f.len()).step_by(37) {
            let mut bad = f.to_vec();
            bad[at] ^= 0x41;
            let _ = parse(&bad, Some("secret"));
        }
        assert!(parse(b"\x30\x80\x30\x80", None).is_err());
    }
}
