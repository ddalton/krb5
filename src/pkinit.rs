//! PKINIT (RFC 4556): initial authentication with public keys instead of
//! a password, and anonymous PKINIT (RFC 8062), which also gives the
//! FAST armor MIT's `auto_fast_armor` asks for. Built only with the
//! `pkinit` feature.
//!
//! The client sends, in PA-PK-AS-REQ, an ephemeral Diffie-Hellman public
//! value (RFC 3526 MODP group 14 or 16, or a P-256/384/521 point) and a checksum binding it to the
//! request, signed with its certificate's key, or, anonymously, unsigned.
//! The KDC answers with its own DH value, signed with the KDC's key, and
//! the reply key comes from the shared secret through the KDF the KDC
//! names (RFC 8636). The client checks, as MIT's does:
//!
//! * the KDC's signature, and its certificate's chain to one of the
//!   trust anchors (`pkinit_anchors`): see [`TrustAnchors`];
//! * that the certificate names the KDC: a PKINIT subjectAltName of
//!   `krbtgt/REALM@REALM`, or else a dNSName listed in
//!   `pkinit_kdc_hostname` together with the `id-pkinit-KPKdc` key
//!   purpose and the digitalSignature key usage;
//! * that the reply answers this request (the nonce), which MIT does not;
//! * for anonymous PKINIT, that the session key is the one RFC 8062 §4.2
//!   derives from the KDC's PA-PKINIT-KX contribution and the reply key,
//!   so the KDC, and not a man in the middle, chose it.
//!
//! Supported: RSA and elliptic-curve (P-256, P-384, P-521) certificates
//! and keys, for the client and the KDC (PKCS #1 v1.5 and ECDSA
//! signatures with SHA-256/384/512), in unencrypted PEM files (`FILE:`)
//! or PKCS #12 files (`PKCS12:`, [`Identity::from_pkcs12`]);
//! key exchange by finite-field DH or, against MIT 1.22 and later, ECDH
//! ([`DhGroup`]). Not supported: RSA key transport (which MIT's client
//! also refuses), PKCS #11 identities (smart cards), and revocation
//! checking.

mod asn1;
mod bigint;
mod cms;
mod dh;
mod ec;
mod kdf;
mod keys;
mod pem;
mod pkcs12;
mod rsa;
mod x509;

use crate::client::{ClientError, Principal, Result, decode_encrypted_data, decode_key};
use crate::config::Krb5Conf;
use crate::der::{self, Reader};
use crate::key::Key;
use asn1::ReaderExt;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::path::Path;

pub(crate) const PA_PK_AS_REQ: i32 = 16;
pub(crate) const PA_PK_AS_REP: i32 = 17;
/// RFC 6112 §5.4.1: the KDC's contribution to an anonymous session key.
pub(crate) const PA_PKINIT_KX: i32 = 147;
/// RFC 8070: a freshness token, asked for empty and returned by the KDC.
pub(crate) const PA_AS_FRESHNESS: i32 = 150;
/// RFC 6112 §5.4.1 key usage for PA-PKINIT-KX.
const KU_PA_PKINIT_KX: u32 = 44;
/// KRB5_NT_WELLKNOWN, for `WELLKNOWN/ANONYMOUS`.
pub(crate) const NT_WELLKNOWN: i32 = 11;
/// KDCOptions request-anonymous (bit 16).
pub(crate) const KDC_OPT_REQUEST_ANONYMOUS: u32 = 1 << 15;
/// RFC 4556 §3.1.3 KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED.
pub(crate) const KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED: i32 = 65;

/// RFC 4556 §3.2.2 TD-DH-PARAMETERS: the groups a KDC accepts, in the
/// e-data of KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED.
const TD_DH_PARAMETERS: i32 = 109;

/// A key-exchange group: `pkinit_dh_min_bits`. Ordered by strength, by
/// MIT's finite-field equivalents (P-256 ≈ 3072, P-384 ≈ 7680, P-521 ≈
/// 15360 bits).
///
/// The default is MODP group 14, as for MIT's client. The curves need a
/// KDC that supports them: MIT 1.22 or later.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DhGroup {
    /// RFC 3526 MODP group 14, 2048-bit finite-field DH.
    #[default]
    Modp2048,
    /// ECDH on P-256 (RFC 5349).
    P256,
    /// RFC 3526 MODP group 16, 4096-bit finite-field DH.
    Modp4096,
    /// ECDH on P-384.
    P384,
    /// ECDH on P-521.
    P521,
}

impl DhGroup {
    /// A `pkinit_dh_min_bits` value, as MIT's `parse_dh_min_bits` reads
    /// it: `P-256`, `P-384`, `P-521`, or a bit count (up to 2048 is group
    /// 14, up to 4096 group 16). `None` for anything else, which MIT
    /// takes as the default.
    pub fn from_config(value: &str) -> Option<DhGroup> {
        let v = value.trim();
        match v.to_ascii_uppercase().as_str() {
            "P-256" => return Some(DhGroup::P256),
            "P-384" => return Some(DhGroup::P384),
            "P-521" => return Some(DhGroup::P521),
            _ => {}
        }
        match v.parse::<u32>().ok()? {
            // MIT also takes 1024; this crate offers nothing that weak.
            1024..=2048 => Some(DhGroup::Modp2048),
            2049..=4096 => Some(DhGroup::Modp4096),
            _ => None,
        }
    }

    fn curve(self) -> Option<ec::Curve> {
        match self {
            DhGroup::P256 => Some(ec::Curve::P256),
            DhGroup::P384 => Some(ec::Curve::P384),
            DhGroup::P521 => Some(ec::Curve::P521),
            DhGroup::Modp2048 | DhGroup::Modp4096 => None,
        }
    }

    /// The group an AlgorithmIdentifier of TD-DH-PARAMETERS names.
    fn from_alg_id(oid: &[u8], params: Option<&[u8]>) -> Option<DhGroup> {
        if oid == asn1::oid(dh::DH_PUBLIC_NUMBER) {
            match dh::Group::from_domain_parameters(params?)?.bits() {
                2048 => Some(DhGroup::Modp2048),
                4096 => Some(DhGroup::Modp4096),
                _ => None,
            }
        } else if oid == asn1::oid(ec::ID_EC_PUBLIC_KEY) {
            match ec::Curve::from_params(params).ok()? {
                ec::Curve::P256 => Some(DhGroup::P256),
                ec::Curve::P384 => Some(DhGroup::P384),
                ec::Curve::P521 => Some(DhGroup::P521),
            }
        } else {
            None
        }
    }
}

/// MIT's `pkinit_process_td_dh_params`: after the KDC refused `offered`,
/// the first group in its TD-DH-PARAMETERS that this crate supports and
/// that is stronger. `e_data` is the KRB-ERROR's, as METHOD-DATA or as
/// TYPED-DATA (`[0]` type, `[1]` value).
pub(crate) fn negotiate_group(e_data: &[u8], offered: DhGroup) -> Option<DhGroup> {
    let mut seq = Reader::new(e_data).seq().ok()?;
    while !seq.is_empty() {
        let f = der::Fields::parse("TYPED-DATA", seq.expect(der::SEQUENCE).ok()?).ok()?;
        let (ty, value) = match (f.opt(1), f.opt(2)) {
            // PA-DATA: padata-type [1], padata-value [2].
            (Some(mut t), Some(mut v)) => (t.i32().ok()?, v.octets().ok()?),
            // TYPED-DATA: data-type [0], data-value [1].
            _ => (f.get(0).ok()?.i32().ok()?, f.get(1).ok()?.octets().ok()?),
        };
        if ty != TD_DH_PARAMETERS {
            continue;
        }
        let mut algs = Reader::new(value).seq().ok()?;
        while !algs.is_empty() {
            let (oid, params) = algs.alg_id().ok()?;
            if let Some(g) = DhGroup::from_alg_id(oid, params) {
                if g > offered {
                    return Some(g);
                }
            }
        }
    }
    None
}

/// The client's half of the key exchange.
enum KeyExchange {
    Modp(dh::KeyPair),
    Ec(ec::Ecdh),
}

impl KeyExchange {
    fn generate(group: DhGroup) -> KeyExchange {
        match group.curve() {
            Some(c) => KeyExchange::Ec(ec::Ecdh::generate(c)),
            None => KeyExchange::Modp(dh::KeyPair::generate(dh::Group::at_least(
                if group == DhGroup::Modp4096 {
                    4096
                } else {
                    2048
                },
            ))),
        }
    }

    fn group(&self) -> DhGroup {
        match self {
            KeyExchange::Modp(k) if k.group().bits() > 2048 => DhGroup::Modp4096,
            KeyExchange::Modp(_) => DhGroup::Modp2048,
            KeyExchange::Ec(e) => match e.curve() {
                ec::Curve::P256 => DhGroup::P256,
                ec::Curve::P384 => DhGroup::P384,
                ec::Curve::P521 => DhGroup::P521,
            },
        }
    }

    fn spki(&self) -> Vec<u8> {
        match self {
            KeyExchange::Modp(k) => k.spki(),
            KeyExchange::Ec(e) => e.spki(),
        }
    }

    /// The shared secret for the KDC's public value (KDCDHKeyInfo's BIT
    /// STRING: an INTEGER for MODP, the point itself for ECDH).
    fn agree(&self, kdc_public: &[u8]) -> Option<Vec<u8>> {
        match self {
            KeyExchange::Modp(k) => k.agree(kdc_public),
            KeyExchange::Ec(e) => e.agree(kdc_public),
        }
    }
}

fn pk_err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ClientError::Pkinit(msg.into()))
}

/// `WELLKNOWN/ANONYMOUS@realm`, the client name of an anonymous request.
pub(crate) fn anonymous_principal(realm: &str) -> Principal {
    Principal::new(NT_WELLKNOWN, ["WELLKNOWN", "ANONYMOUS"], realm)
}

/// The realm of the fully anonymous principal (RFC 8062 §3).
const ANONYMOUS_REALM: &str = "WELLKNOWN:ANONYMOUS";

// ---------------------------------------------------------------- anchors

/// The CA certificates a KDC's certificate must chain to: MIT's
/// `pkinit_anchors`.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    certs: Vec<x509::Cert>,
}

impl TrustAnchors {
    /// No anchors: every KDC is refused until some are added.
    pub fn new() -> Self {
        Self::default()
    }

    /// The certificates in `data`: PEM (any number of `CERTIFICATE`
    /// blocks) or one DER certificate.
    pub fn from_pem(data: &[u8]) -> Result<Self> {
        let certs = x509::parse_certs(data).map_err(ClientError::Pkinit)?;
        if certs.is_empty() {
            return pk_err("no certificates found");
        }
        Ok(TrustAnchors { certs })
    }

    /// An anchor location as `krb5.conf` writes one: `FILE:path` (a PEM
    /// file), `DIR:path` (every `.pem`, `.crt` and `.0`-style file in a
    /// directory), or a bare path, taken as `FILE:`.
    pub fn load(spec: &str) -> Result<Self> {
        let read = |p: &Path| {
            std::fs::read(p).map_err(|e| ClientError::Pkinit(format!("{}: {e}", p.display())))
        };
        if let Some(dir) = spec.strip_prefix("DIR:") {
            let mut out = TrustAnchors::new();
            let entries =
                std::fs::read_dir(dir).map_err(|e| ClientError::Pkinit(format!("{dir}: {e}")))?;
            let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
            paths.sort();
            for p in paths.iter().filter(|p| p.is_file()) {
                // Files that hold no certificate (READMEs, CRLs) are
                // skipped, as OpenSSL's hashed directories hold them too.
                if let Ok(a) = TrustAnchors::from_pem(&read(p)?) {
                    out.extend(a);
                }
            }
            return Ok(out);
        }
        let file = spec.strip_prefix("FILE:").unwrap_or(spec);
        Self::from_pem(&read(Path::new(file))?)
            .map_err(|e| ClientError::Pkinit(format!("{file}: {e}")))
    }

    /// Add `other`'s anchors to these.
    pub fn extend(&mut self, other: TrustAnchors) {
        self.certs.extend(other.certs);
    }

    pub fn len(&self) -> usize {
        self.certs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }
}

// --------------------------------------------------------------- identity

/// A client's certificate and private key: MIT's `X509_user_identity`.
#[derive(Clone)]
pub struct Identity {
    /// The client's certificate first, then any others from its file
    /// (intermediate CAs), all sent to the KDC.
    certs: Vec<x509::Cert>,
    key: keys::PrivateKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("principals", &self.principals())
            .field("key", &self.key)
            .finish()
    }
}

impl Identity {
    /// A certificate (PEM or DER; the client's first, then any
    /// intermediates) and its RSA private key (PEM `PRIVATE KEY` or `RSA
    /// PRIVATE KEY`, unencrypted). Both may come from one combined PEM.
    pub fn from_pem(cert: &[u8], key: &[u8]) -> Result<Self> {
        let certs = x509::parse_certs(cert).map_err(ClientError::Pkinit)?;
        if certs.is_empty() {
            return pk_err("no certificate found");
        }
        let blocks = pem::blocks(key).map_err(ClientError::Pkinit)?;
        let key =
            keys::PrivateKey::from_pem_blocks(&blocks).map_err(|e| ClientError::Pkinit(e.0))?;
        if certs[0].public_key().ok() != Some(key.public()) {
            return pk_err("the private key does not match the certificate");
        }
        Ok(Identity { certs, key })
    }

    /// A PKCS #12 (`.p12`, `.pfx`) file's certificate and key, the other
    /// certificates in it sent along as intermediates. With `password`
    /// `None` the file is read as MIT first tries it, with no pass phrase
    /// (the empty password, both ways OpenSSL tries it).
    ///
    /// Modern files (PBES2 with AES, as OpenSSL 3 and current Windows
    /// write them) and legacy ones (3DES and 40-bit RC2, as OpenSSL 1.x,
    /// Windows and Java long wrote them) are read; a wrong password is
    /// reported as such, by the file's MAC.
    pub fn from_pkcs12(data: &[u8], password: Option<&str>) -> Result<Self> {
        match pkcs12::parse(data, password) {
            Ok(c) => Ok(Identity {
                certs: c.certs,
                key: c.key,
            }),
            Err(pkcs12::Error::BadPassword) => pk_err(match password {
                None => "the PKCS #12 file needs a password",
                Some(_) => "wrong password for the PKCS #12 file",
            }),
            Err(pkcs12::Error::Malformed(m)) => pk_err(format!("PKCS #12: {m}")),
        }
    }

    /// An identity as `X509_user_identity` or `kinit -X` writes one:
    /// `FILE:cert.pem,key.pem`, `FILE:both.pem` for one file holding both,
    /// or `PKCS12:file.p12` (read with no password; see
    /// [`Identity::load_with_password`]).
    pub fn load(spec: &str) -> Result<Self> {
        Self::load_with_password(spec, None)
    }

    /// [`Identity::load`], with the pass phrase for a `PKCS12:` file, as
    /// `kinit` asks for one when the file will not open without.
    pub fn load_with_password(spec: &str, password: Option<&str>) -> Result<Self> {
        if let Some(file) = spec.strip_prefix("PKCS12:") {
            let data =
                std::fs::read(file).map_err(|e| ClientError::Pkinit(format!("{file}: {e}")))?;
            return Self::from_pkcs12(&data, password)
                .map_err(|e| ClientError::Pkinit(format!("{file}: {e}")));
        }
        let Some(files) = spec.strip_prefix("FILE:") else {
            return pk_err(format!(
                "unsupported identity {spec:?} (FILE:cert[,key] and PKCS12:file are supported)"
            ));
        };
        let (cert, key) = files.split_once(',').unwrap_or((files, files));
        let read = |p: &str| std::fs::read(p).map_err(|e| ClientError::Pkinit(format!("{p}: {e}")));
        Self::from_pem(&read(cert)?, &read(key)?)
            .map_err(|e| ClientError::Pkinit(format!("{spec}: {e}")))
    }

    /// The principals the certificate names in its PKINIT
    /// subjectAltName: the names the KDC will accept it for (unless the
    /// KDC maps certificates to principals some other way).
    pub fn principals(&self) -> Vec<Principal> {
        self.certs[0].san().map(|(p, _)| p).unwrap_or_default()
    }
}

// --------------------------------------------------------------- settings

/// A client's PKINIT configuration for one realm.
#[derive(Debug, Clone, Default)]
pub(crate) struct Settings {
    /// Anchors given in code, else the `pkinit_anchors` locations.
    pub(crate) anchors: Option<TrustAnchors>,
    pub(crate) anchor_specs: Vec<String>,
    pub(crate) kdc_hostnames: Vec<String>,
    pub(crate) dh_group: DhGroup,
    /// `[realms] REALM auto_fast_armor`.
    pub(crate) auto_fast_armor: bool,
}

impl Settings {
    /// MIT's `pkinit_libdefault_strings`: `[realms] REALM`, then
    /// `[libdefaults] REALM = { }`, then `[libdefaults]`.
    fn values(conf: &Krb5Conf, realm: &str, tag: &str) -> Vec<String> {
        [
            conf.get_all(&["realms", realm, tag]),
            conf.get_all(&["libdefaults", realm, tag]),
            conf.get_all(&["libdefaults", tag]),
        ]
        .into_iter()
        .find(|v| !v.is_empty())
        .unwrap_or_default()
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    pub(crate) fn from_config(conf: &Krb5Conf, realm: &str) -> Settings {
        let one = |tag| Self::values(conf, realm, tag).into_iter().next();
        let truthy = |v: Option<&str>| {
            v.is_some_and(|v| {
                matches!(
                    v.to_ascii_lowercase().as_str(),
                    "y" | "yes" | "true" | "t" | "1" | "on"
                )
            })
        };
        Settings {
            anchors: None,
            anchor_specs: Self::values(conf, realm, "pkinit_anchors"),
            kdc_hostnames: Self::values(conf, realm, "pkinit_kdc_hostname"),
            dh_group: one("pkinit_dh_min_bits")
                .and_then(|v| DhGroup::from_config(&v))
                .unwrap_or_default(),
            auto_fast_armor: truthy(conf.get(&["realms", realm, "auto_fast_armor"])),
        }
    }

    fn anchors(&self) -> Result<TrustAnchors> {
        let mut out = TrustAnchors::new();
        match &self.anchors {
            Some(a) => out.extend(a.clone()),
            None => {
                for spec in &self.anchor_specs {
                    out.extend(TrustAnchors::load(spec)?);
                }
            }
        }
        if out.is_empty() {
            return pk_err("no pkinit_anchors supplied");
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- request

/// The state between a PA-PK-AS-REQ and its reply.
pub(crate) struct Request {
    keys: KeyExchange,
    nonce: u32,
}

/// What a PA-PK-AS-REQ is made from.
pub(crate) struct RequestInput<'a> {
    /// The signer; `None` for anonymous PKINIT.
    pub(crate) identity: Option<&'a Identity>,
    /// The KDC offered PA-PKINIT-KX: it follows RFC 6112, so an anonymous
    /// AuthPack goes in an unsigned SignedData rather than a ContentInfo
    /// (MIT's `use_content_info`).
    pub(crate) rfc6112_kdc: bool,
    /// The encoded KDC-REQ-BODY this goes with, and its nonce.
    pub(crate) body: &'a [u8],
    pub(crate) nonce: u32,
    pub(crate) now: i64,
    pub(crate) usec: u32,
    pub(crate) freshness: Option<&'a [u8]>,
    pub(crate) group: DhGroup,
}

/// The PA-PK-AS-REQ value for `input`, and the state to read the reply.
///
/// ```text
/// PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack [0] IMPLICIT OCTET STRING, ... }
/// AuthPack ::= SEQUENCE {
///     pkAuthenticator [0] PKAuthenticator, clientPublicValue [1] SubjectPublicKeyInfo,
///     supportedCMSTypes [2] SEQUENCE OF AlgorithmIdentifier,
///     supportedKDFs [4] SEQUENCE OF SEQUENCE { kdf-id [0] OID } }
/// PKAuthenticator ::= SEQUENCE {
///     cusec [0], ctime [1], nonce [2], paChecksum [3] OCTET STRING,   -- SHA-1 of the body
///     freshnessToken [4] OPTIONAL,
///     paChecksum2 [5] SEQUENCE { checksum [0], algorithmIdentifier [1] } }  -- SHA-256
/// ```
pub(crate) fn request(input: &RequestInput<'_>) -> Result<(Vec<u8>, Request)> {
    let keys = KeyExchange::generate(input.group);
    let mut authenticator = vec![
        der::field(0, der::int(i64::from(input.usec))),
        der::field(1, der::time(input.now)),
        der::field(2, der::int(i64::from(input.nonce))),
        der::field(3, der::octets(&Sha1::digest(input.body))),
    ];
    if let Some(t) = input.freshness {
        authenticator.push(der::field(4, der::octets(t)));
    }
    authenticator.push(der::field(
        5,
        der::seq(&[
            der::field(0, der::octets(&Sha256::digest(input.body))),
            der::field(1, asn1::alg_id(keys::Hash::Sha256.oid(), None)),
        ]),
    ));
    let auth_pack = der::seq(&[
        der::field(0, der::seq(&authenticator)),
        der::field(1, keys.spki()),
        der::field(
            2,
            der::seq(&keys::SigAlg::ALL.map(|a| asn1::alg_id(a.oid(), None))),
        ),
        der::field(
            4,
            der::seq(&kdf::OFFERED.map(|k| der::seq(&[der::field(0, asn1::oid_tlv(k))]))),
        ),
    ]);
    let signed = match input.identity {
        Some(id) => cms::signed_data(
            cms::ID_PKINIT_AUTH_DATA,
            &auth_pack,
            Some(cms::Signer {
                key: &id.key,
                certs: &id.certs,
            }),
        )
        .map_err(|e| ClientError::Pkinit(e.0))?,
        None if input.rfc6112_kdc => cms::signed_data(cms::ID_PKINIT_AUTH_DATA, &auth_pack, None)
            .map_err(|e| ClientError::Pkinit(e.0))?,
        None => cms::content_info(cms::ID_PKINIT_AUTH_DATA, &auth_pack),
    };
    Ok((
        der::seq(&[der::tlv(asn1::implicit(0), &signed)]),
        Request {
            keys,
            nonce: input.nonce,
        },
    ))
}

/// What the reply is checked against.
pub(crate) struct ReplyInput<'a> {
    pub(crate) settings: &'a Settings,
    /// The PA-PK-AS-REP value.
    pub(crate) pa_value: &'a [u8],
    /// The request's realm, client and server names as sent, and whole
    /// encoding.
    pub(crate) realm: &'a str,
    pub(crate) client: &'a Principal,
    pub(crate) server: &'a Principal,
    pub(crate) as_req: &'a [u8],
    /// The reply's enctype.
    pub(crate) enctype: i32,
    pub(crate) now: i64,
}

impl Request {
    pub(crate) fn group(&self) -> DhGroup {
        self.keys.group()
    }

    /// The reply key from a PA-PK-AS-REP, after checking the KDC.
    ///
    /// ```text
    /// PA-PK-AS-REP ::= CHOICE { dhInfo [0] DHRepInfo, encKeyPack [1] IMPLICIT OCTET STRING }
    /// DHRepInfo ::= SEQUENCE {
    ///     dhSignedData [0] IMPLICIT OCTET STRING,       -- SignedData of KDCDHKeyInfo
    ///     serverDHNonce [1] OPTIONAL, kdf [2] SEQUENCE { kdf-id [0] OID } OPTIONAL }
    /// KDCDHKeyInfo ::= SEQUENCE {
    ///     subjectPublicKey [0] BIT STRING, nonce [1], dhKeyExpiration [2] OPTIONAL }
    /// ```
    pub(crate) fn reply_key(&self, r: &ReplyInput<'_>) -> Result<Key> {
        let mut top = Reader::new(r.pa_value);
        let (tag, dh_info) = top.next()?;
        top.done("PA-PK-AS-REP")?;
        if tag != der::ctx(0) {
            return pk_err(
                "the KDC answered with RSA key transport, which is not supported (nor accepted by MIT)",
            );
        }
        let mut info = Reader::new(dh_info).seq()?;
        let signed = info.expect(asn1::implicit(0))?;
        info.optional(der::ctx(1))?; // serverDHNonce: unused, we sent no clientDHNonce
        let kdf_oid = match info.optional(der::ctx(2))? {
            Some(k) => {
                let mut s = Reader::new(k).seq()?;
                let oid = Reader::new(s.expect(der::ctx(0))?).oid()?.to_vec();
                Some(oid)
            }
            None => None,
        };
        info.done("DHRepInfo")?;

        let anchors = r.settings.anchors()?;
        let verified = cms::verify(signed, cms::ID_PKINIT_DHKEY_DATA, &anchors.certs, r.now)
            .map_err(|e| ClientError::Pkinit(format!("KDC's reply: {}", e.0)))?;
        check_kdc_certificate(&verified.signer, r.realm, &r.settings.kdc_hostnames)?;

        let f = der::Fields::parse_tagged("KDCDHKeyInfo", der::SEQUENCE, &verified.content)?;
        let kdc_public = asn1::bits_content(f.get(0)?.expect(der::BIT_STRING)?)?;
        if f.get(1)?.u32()? != self.nonce {
            return pk_err("the KDC's DH key answers a different request (nonce)");
        }
        let z = self
            .keys
            .agree(kdc_public)
            .ok_or_else(|| ClientError::Pkinit("the KDC's DH public value is invalid".into()))?;

        let Some(len) = kdf::key_len(r.enctype) else {
            return pk_err(format!("unsupported reply enctype {}", r.enctype));
        };
        let bytes = match kdf_oid {
            None => kdf::octetstring2key(&z, len),
            Some(oid) => {
                let Some(name) = kdf::OFFERED.into_iter().find(|k| asn1::oid(k) == oid) else {
                    return pk_err("the KDC chose a KDF we did not offer");
                };
                // MIT's pkinit_kdf: an anonymous client is partyU as the
                // fully anonymous principal, whatever realm it asked in.
                let anonymous = anonymous_principal(ANONYMOUS_REALM);
                let party_u = if r.client.components == anonymous.components {
                    &anonymous
                } else {
                    r.client
                };
                let info =
                    kdf::other_info(name, party_u, r.server, r.enctype, r.as_req, r.pa_value);
                kdf::sp800_56a(name, &z, &info, len).expect("an offered KDF")
            }
        };
        Ok(Key::new(r.enctype, bytes)?)
    }
}

/// MIT's `verify_kdc_san` and `verify_kdc_eku`: the certificate's PKINIT
/// subjectAltName is `krbtgt/REALM@REALM`; or, failing that, one of its
/// dNSNames is in `pkinit_kdc_hostname` and it carries `id-pkinit-KPKdc`
/// and the digitalSignature key usage.
fn check_kdc_certificate(cert: &x509::Cert, realm: &str, hostnames: &[String]) -> Result<()> {
    let bad = |e: der::DerError| ClientError::Pkinit(format!("KDC certificate: {}", e.0));
    let (principals, dns) = cert.san().map_err(bad)?;
    let tgs = Principal::krbtgt(realm);
    if principals
        .iter()
        .any(|p| p.realm == tgs.realm && p.components == tgs.components)
    {
        return Ok(());
    }
    if !dns
        .iter()
        .any(|d| hostnames.iter().any(|h| h.eq_ignore_ascii_case(d)))
    {
        return pk_err(format!(
            "the KDC's certificate does not name krbtgt/{realm}@{realm} (KDC_NAME_MISMATCH)"
        ));
    }
    if !cert.has_eku(x509::ID_PKINIT_KP_KDC).map_err(bad)?
        || cert.key_usage(x509::KU_DIGITAL_SIGNATURE).map_err(bad)? != Some(true)
    {
        return pk_err("the KDC's certificate is not for a KDC (INCONSISTENT_KEY_PURPOSE)");
    }
    Ok(())
}

/// MIT's `verify_anonymous` (RFC 8062 §4.2): an anonymous reply carries
/// PA-PKINIT-KX, the KDC's key encrypted in the reply key, and the
/// session key must be `KRB-FX-CF2(kdc_key, reply_key, "PKINIT",
/// "KEYEXCHANGE")`.
pub(crate) fn verify_anonymous(
    padata: &[(i32, Vec<u8>)],
    reply_key: &Key,
    session_key: &Key,
) -> Result<()> {
    let Some((_, kx)) = padata.iter().find(|(t, _)| *t == PA_PKINIT_KX) else {
        return pk_err("anonymous reply without PA-PKINIT-KX (KRB5_KDCREP_MODIFIED)");
    };
    let (_, cipher) = decode_encrypted_data(Reader::new(kx))?;
    let plain = reply_key.decrypt(KU_PA_PKINIT_KX, &cipher)?;
    let kdc_key = decode_key(Reader::new(&plain))?;
    let expected = Key::cf2(&kdc_key, "PKINIT", reply_key, "KEYEXCHANGE")?;
    if &expected != session_key {
        return pk_err(
            "reply has wrong form of session key for anonymous request (KRB5_KDCREP_MODIFIED)",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{encode_encrypted_data, encode_key};
    use cms::tests::kdc_signed;
    use x509::tests::{NOW, fixture};

    const REALM: &str = "TEST.REALM";

    fn settings() -> Settings {
        Settings {
            anchors: Some(TrustAnchors {
                certs: vec![fixture("ca")],
            }),
            ..Settings::default()
        }
    }

    fn input<'a>(body: &'a [u8], identity: Option<&'a Identity>) -> RequestInput<'a> {
        RequestInput {
            identity,
            rfc6112_kdc: false,
            body,
            nonce: 12345,
            now: NOW,
            usec: 7,
            freshness: Some(b"fresh"),
            group: DhGroup::Modp2048,
        }
    }

    /// The KDC's half of the exchange `req` opened: its public value (the
    /// BIT STRING's content) and the shared secret.
    fn kdc_side(req: &Request) -> (Vec<u8>, Vec<u8>) {
        match &req.keys {
            KeyExchange::Modp(k) => {
                let kdc = dh::KeyPair::generate(k.group().clone());
                let z = kdc.agree(&k.public_value()).unwrap();
                (kdc.public_value(), z)
            }
            KeyExchange::Ec(e) => {
                let kdc = ec::Ecdh::generate(e.curve());
                let z = kdc.agree(e.point()).unwrap();
                (kdc.point().to_vec(), z)
            }
        }
    }

    /// What the test KDC answers: its DH value signed in a SignedData,
    /// the KDF it picks, and the key it derives.
    struct Kdc {
        pa_value: Vec<u8>,
        key: Key,
    }

    fn kdc_reply(
        req: &Request,
        client: &Principal,
        as_req: &[u8],
        nonce: u32,
        kdf: Option<&str>,
        signed: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Kdc {
        let (kdc_public, z) = kdc_side(req);
        let key_info = der::seq(&[
            der::field(0, asn1::bit_string(&kdc_public)),
            der::field(1, der::int(i64::from(nonce))),
        ]);
        let mut info = vec![der::tlv(asn1::implicit(0), &signed(&key_info))];
        if let Some(k) = kdf {
            info.push(der::field(2, der::seq(&[der::field(0, asn1::oid_tlv(k))])));
        }
        let pa_value = der::field(0, der::seq(&info));
        let bytes = match kdf {
            None => kdf::octetstring2key(&z, 32),
            Some(k) => {
                let other =
                    kdf::other_info(k, client, &Principal::krbtgt(REALM), 18, as_req, &pa_value);
                // An unknown KDF: the client must refuse before using a key.
                kdf::sp800_56a(k, &z, &other, 32).unwrap_or_else(|| vec![0; 32])
            }
        };
        Kdc {
            pa_value,
            key: Key::new(18, bytes).unwrap(),
        }
    }

    fn reply_key(req: &Request, s: &Settings, kdc: &Kdc, client: &Principal) -> Result<Key> {
        req.reply_key(&ReplyInput {
            settings: s,
            pa_value: &kdc.pa_value,
            realm: REALM,
            client,
            server: &Principal::krbtgt(REALM),
            as_req: b"the AS-REQ",
            enctype: 18,
            now: NOW,
        })
    }

    fn signed_by_kdc(content: &[u8]) -> Vec<u8> {
        kdc_signed(cms::ID_PKINIT_DHKEY_DATA, content)
    }

    #[test]
    fn the_reply_key_matches_the_kdcs_for_each_kdf() {
        let client = Principal::new(1, ["alice"], REALM);
        for kdf in [
            None,
            Some(kdf::KDF_SHA1),
            Some(kdf::KDF_SHA256),
            Some(kdf::KDF_SHA512),
        ] {
            let (_, req) = request(&input(b"body", None)).unwrap();
            let kdc = kdc_reply(&req, &client, b"the AS-REQ", 12345, kdf, signed_by_kdc);
            assert_eq!(
                reply_key(&req, &settings(), &kdc, &client).unwrap(),
                kdc.key,
                "{kdf:?}"
            );
        }
    }

    #[test]
    fn an_anonymous_client_is_party_u_as_the_fully_anonymous_principal() {
        let (_, req) = request(&input(b"body", None)).unwrap();
        let sent = anonymous_principal(REALM);
        let kdc = kdc_reply(
            &req,
            &anonymous_principal(ANONYMOUS_REALM),
            b"the AS-REQ",
            12345,
            Some(kdf::KDF_SHA256),
            signed_by_kdc,
        );
        assert_eq!(reply_key(&req, &settings(), &kdc, &sent).unwrap(), kdc.key);
    }

    #[test]
    fn replies_that_do_not_prove_the_kdc_are_refused() {
        let client = Principal::new(1, ["alice"], REALM);
        let (_, req) = request(&input(b"body", None)).unwrap();
        let fails =
            |kdc: &Kdc, s: &Settings| reply_key(&req, s, kdc, &client).unwrap_err().to_string();
        let reply = |nonce, kdf, f: &dyn Fn(&[u8]) -> Vec<u8>| {
            kdc_reply(&req, &client, b"the AS-REQ", nonce, kdf, f)
        };
        // Another request's nonce.
        let e = fails(
            &reply(54321, Some(kdf::KDF_SHA256), &signed_by_kdc),
            &settings(),
        );
        assert!(e.contains("nonce"), "{e}");
        // No anchors; the wrong anchor.
        let e = fails(&reply(12345, None, &signed_by_kdc), &Settings::default());
        assert!(e.contains("pkinit_anchors"), "{e}");
        let other = Settings {
            anchors: Some(TrustAnchors {
                certs: vec![fixture("other-ca")],
            }),
            ..Settings::default()
        };
        assert!(fails(&reply(12345, None, &signed_by_kdc), &other).contains("anchor"));
        // No KDC signature at all.
        let unsigned = |c: &[u8]| cms::signed_data(cms::ID_PKINIT_DHKEY_DATA, c, None).unwrap();
        assert!(fails(&reply(12345, None, &unsigned), &settings()).contains("KDC's reply"));
        // Signed, by a certificate from the trusted CA, that does not name
        // the KDC (a dNSName only, and no pkinit_kdc_hostname set).
        let host = |c: &[u8]| {
            let key = cms::tests::kdc_key();
            let certs = [fixture("host"), fixture("inter")];
            cms::signed_data(
                cms::ID_PKINIT_DHKEY_DATA,
                c,
                Some(cms::Signer {
                    key: &key,
                    certs: &certs,
                }),
            )
            .unwrap()
        };
        let e = fails(&reply(12345, None, &host), &settings());
        assert!(e.contains("KDC_NAME_MISMATCH"), "{e}");
        let named = Settings {
            kdc_hostnames: vec!["kdc.test.realm".into()],
            ..settings()
        };
        let kdc = reply(12345, None, &host);
        assert_eq!(reply_key(&req, &named, &kdc, &client).unwrap(), kdc.key);
        // A KDF that was not offered.
        let e = fails(&reply(12345, Some("1.2.3.4"), &signed_by_kdc), &settings());
        assert!(e.contains("KDF"), "{e}");
        // RSA key transport.
        let kt = Kdc {
            pa_value: der::tlv(asn1::implicit(1), b"enc key pack"),
            key: Key::random(18).unwrap(),
        };
        assert!(fails(&kt, &settings()).contains("key transport"));
    }

    #[test]
    fn the_kdc_is_named_by_san_or_by_configured_hostname() {
        let kdc = fixture("kdc");
        check_kdc_certificate(&kdc, REALM, &[]).unwrap();
        let e = check_kdc_certificate(&kdc, "OTHER.REALM", &[]).unwrap_err();
        assert!(e.to_string().contains("KDC_NAME_MISMATCH"), "{e}");
        let host = fixture("host");
        assert!(check_kdc_certificate(&host, REALM, &[]).is_err());
        assert!(check_kdc_certificate(&host, REALM, &["other.test.realm".into()]).is_err());
        check_kdc_certificate(&host, REALM, &["KDC.Test.Realm".into()]).unwrap();
        // A hostname match without the KDC key purpose is not enough.
        let e = check_kdc_certificate(&fixture("inter"), REALM, &["kdc.test.realm".into()]);
        assert!(e.is_err());
    }

    #[test]
    fn the_request_carries_what_the_kdc_checks() {
        // The KDC's certificate stands in for a client's; its file holds
        // the intermediate too.
        let chain = [
            &include_bytes!("pkinit/testdata/kdc.pem")[..],
            include_bytes!("pkinit/testdata/inter.pem"),
        ]
        .concat();
        let id = Identity::from_pem(&chain, include_bytes!("pkinit/testdata/kdc-key.pem")).unwrap();
        for identity in [None, Some(&id)] {
            for rfc6112_kdc in [false, true] {
                let mut inp = input(b"the body", identity);
                inp.rfc6112_kdc = rfc6112_kdc;
                let (pa, _) = request(&inp).unwrap();
                let mut r = Reader::new(&pa).seq().unwrap();
                let signed = r.expect(asn1::implicit(0)).unwrap();
                let auth_pack = match (identity, rfc6112_kdc) {
                    (Some(_), _) => {
                        let v =
                            cms::verify(signed, cms::ID_PKINIT_AUTH_DATA, &[fixture("ca")], NOW)
                                .unwrap();
                        assert_eq!(v.signer, fixture("kdc"));
                        v.content
                    }
                    (None, true) => {
                        // RFC 8062 §4.1: a SignedData with no signer.
                        let mut ci = Reader::new(signed).seq().unwrap();
                        assert_eq!(ci.oid().unwrap(), asn1::oid("1.2.840.113549.1.7.2"));
                        assert!(
                            cms::verify(signed, cms::ID_PKINIT_AUTH_DATA, &[fixture("ca")], NOW)
                                .unwrap_err()
                                .0
                                .contains("signer")
                        );
                        continue;
                    }
                    (None, false) => {
                        let mut ci = Reader::new(signed).seq().unwrap();
                        assert_eq!(ci.oid().unwrap(), asn1::oid(cms::ID_PKINIT_AUTH_DATA));
                        Reader::new(ci.expect(der::ctx(0)).unwrap())
                            .octets()
                            .unwrap()
                            .to_vec()
                    }
                };
                let ap = der::Fields::parse_tagged("AuthPack", der::SEQUENCE, &auth_pack).unwrap();
                let pk =
                    der::Fields::parse_tagged("PKAuthenticator", der::SEQUENCE, ap.raw(0).unwrap())
                        .unwrap();
                assert_eq!(pk.get(0).unwrap().int().unwrap(), 7);
                assert_eq!(pk.get(1).unwrap().time().unwrap(), NOW);
                assert_eq!(pk.get(2).unwrap().u32().unwrap(), 12345);
                assert_eq!(
                    pk.get(3).unwrap().octets().unwrap(),
                    &Sha1::digest(b"the body")[..]
                );
                assert_eq!(pk.get(4).unwrap().octets().unwrap(), b"fresh");
                let ck2 =
                    der::Fields::parse_tagged("PAChecksum2", der::SEQUENCE, pk.raw(5).unwrap())
                        .unwrap();
                assert_eq!(
                    ck2.get(0).unwrap().octets().unwrap(),
                    &Sha256::digest(b"the body")[..]
                );
                let mut kdfs = ap.get(4).unwrap().seq().unwrap();
                let first =
                    der::Fields::parse("KDFAlgorithmId", kdfs.expect(der::SEQUENCE).unwrap())
                        .unwrap();
                assert_eq!(
                    first.get(0).unwrap().oid().unwrap(),
                    asn1::oid(kdf::KDF_SHA256)
                );
            }
        }
    }

    #[test]
    fn an_anonymous_session_key_must_come_from_the_kdcs_contribution() {
        let reply_key = Key::random(18).unwrap();
        let kdc_key = Key::random(18).unwrap();
        let session = Key::cf2(&kdc_key, "PKINIT", &reply_key, "KEYEXCHANGE").unwrap();
        let kx = encode_encrypted_data(
            18,
            &reply_key
                .encrypt(KU_PA_PKINIT_KX, &encode_key(&kdc_key))
                .unwrap(),
        );
        let padata = vec![(PA_PKINIT_KX, kx)];
        verify_anonymous(&padata, &reply_key, &session).unwrap();
        // A session key the KDC did not derive (a man in the middle's).
        let e = verify_anonymous(&padata, &reply_key, &kdc_key).unwrap_err();
        assert!(e.to_string().contains("wrong form of session key"), "{e}");
        assert!(verify_anonymous(&[], &reply_key, &session).is_err());
        assert!(verify_anonymous(&padata, &Key::random(18).unwrap(), &session).is_err());
    }

    #[test]
    fn identities_must_pair_a_certificate_with_its_key() {
        let cert = include_bytes!("pkinit/testdata/kdc.pem");
        let other_key = include_bytes!("pkinit/testdata/rsa2048.pem");
        let e = Identity::from_pem(cert, other_key).unwrap_err();
        assert!(e.to_string().contains("does not match"), "{e}");
        assert!(Identity::from_pem(b"", b"").is_err());
        let mut both = cert.to_vec();
        both.extend_from_slice(include_bytes!("pkinit/testdata/kdc-key.pem"));
        let id = Identity::from_pem(&both, &both).unwrap();
        assert_eq!(
            id.principals(),
            [Principal::new(2, ["krbtgt", REALM], REALM)]
        );
    }

    #[test]
    fn settings_come_from_krb5_conf_as_mit_looks_them_up() {
        let conf = Krb5Conf::parse(
            "[libdefaults]\n pkinit_anchors = FILE:/lib\n pkinit_dh_min_bits = 4096\n\
             [realms]\n A.ORG = {\n  pkinit_anchors = FILE:/a1\n  pkinit_anchors = DIR:/a2\n  auto_fast_armor = true\n }\n",
        )
        .unwrap();
        let a = Settings::from_config(&conf, "A.ORG");
        assert_eq!(a.anchor_specs, ["FILE:/a1", "DIR:/a2"]);
        assert!(a.auto_fast_armor);
        assert_eq!(a.dh_group, DhGroup::Modp4096);
        let b = Settings::from_config(&conf, "B.ORG");
        assert_eq!(b.anchor_specs, ["FILE:/lib"]);
        assert!(!b.auto_fast_armor);
    }

    #[test]
    fn dh_min_bits_is_read_as_mit_reads_it() {
        for (v, g) in [
            ("2048", Some(DhGroup::Modp2048)),
            ("1024", Some(DhGroup::Modp2048)),
            ("3072", Some(DhGroup::Modp4096)),
            ("4096", Some(DhGroup::Modp4096)),
            ("p-256", Some(DhGroup::P256)),
            ("P-384", Some(DhGroup::P384)),
            ("P-521", Some(DhGroup::P521)),
            ("8192", None),
            ("X25519", None),
        ] {
            assert_eq!(DhGroup::from_config(v), g, "{v}");
        }
        assert!(DhGroup::Modp2048 < DhGroup::P256 && DhGroup::P256 < DhGroup::Modp4096);
        assert!(DhGroup::Modp4096 < DhGroup::P384 && DhGroup::P384 < DhGroup::P521);
    }

    /// Every group, a signed reply, the same key on both sides.
    #[test]
    fn the_reply_key_matches_the_kdcs_for_each_group() {
        let client = Principal::new(1, ["alice"], REALM);
        for group in [
            DhGroup::Modp2048,
            DhGroup::Modp4096,
            DhGroup::P256,
            DhGroup::P384,
            DhGroup::P521,
        ] {
            let mut inp = input(b"body", None);
            inp.group = group;
            let (pa, req) = request(&inp).unwrap();
            assert_eq!(req.group(), group);
            // The AuthPack's clientPublicValue names the group.
            let mut r = Reader::new(&pa).seq().unwrap();
            let mut ci = Reader::new(r.expect(asn1::implicit(0)).unwrap())
                .seq()
                .unwrap();
            ci.oid().unwrap();
            let ap = Reader::new(ci.expect(der::ctx(0)).unwrap())
                .octets()
                .unwrap()
                .to_vec();
            let ap = der::Fields::parse_tagged("AuthPack", der::SEQUENCE, &ap).unwrap();
            let mut spki = ap.get(1).unwrap().seq().unwrap();
            let (oid, params) = spki.alg_id().unwrap();
            assert_eq!(DhGroup::from_alg_id(oid, params), Some(group));
            let kdc = kdc_reply(
                &req,
                &client,
                b"the AS-REQ",
                12345,
                Some(kdf::KDF_SHA256),
                signed_by_kdc,
            );
            assert_eq!(
                reply_key(&req, &settings(), &kdc, &client).unwrap(),
                kdc.key,
                "{group:?}"
            );
        }
    }

    /// TD-DH-PARAMETERS as MIT 1.22's KDC sends it, in METHOD-DATA and in
    /// TYPED-DATA.
    #[test]
    fn a_refused_group_moves_to_the_kdcs_next_stronger_one() {
        let p256 = ec::Curve::P256.alg_id();
        let p384 = ec::Curve::P384.alg_id();
        let modp4096 = {
            let k = dh::KeyPair::generate(dh::Group::at_least(4096));
            let spki = k.spki();
            let mut s = Reader::new(&spki).seq().unwrap();
            s.next_raw().unwrap().2.to_vec()
        };
        let algs = der::seq(&[p256, modp4096, p384, asn1::alg_id("1.2.3", None)]);
        let method_data = der::seq(&[der::seq(&[
            der::field(1, der::int(i64::from(TD_DH_PARAMETERS))),
            der::field(2, der::octets(&algs)),
        ])]);
        let typed_data = der::seq(&[der::seq(&[
            der::field(0, der::int(i64::from(TD_DH_PARAMETERS))),
            der::field(1, der::octets(&algs)),
        ])]);
        for e_data in [&method_data, &typed_data] {
            assert_eq!(
                negotiate_group(e_data, DhGroup::Modp2048),
                Some(DhGroup::P256)
            );
            assert_eq!(
                negotiate_group(e_data, DhGroup::P256),
                Some(DhGroup::Modp4096)
            );
            assert_eq!(
                negotiate_group(e_data, DhGroup::Modp4096),
                Some(DhGroup::P384)
            );
            assert_eq!(
                negotiate_group(e_data, DhGroup::P384),
                None,
                "nothing stronger"
            );
        }
        assert_eq!(negotiate_group(&[], DhGroup::Modp2048), None);
        assert_eq!(negotiate_group(b"junk", DhGroup::Modp2048), None);
    }

    /// The KDC signs with an EC key under an EC root (ECDSA all the way).
    #[test]
    fn an_ecdsa_signed_reply_from_an_ec_kdc_verifies() {
        let client = Principal::new(1, ["alice"], REALM);
        let (_, req) = request(&input(b"body", None)).unwrap();
        let ec_signed = |c: &[u8]| {
            let key = keys::PrivateKey::from_pem_blocks(
                &pem::blocks(include_bytes!("pkinit/testdata/ec-kdc-key.pem")).unwrap(),
            )
            .unwrap();
            let certs = [fixture("ec-kdc")];
            cms::signed_data(
                cms::ID_PKINIT_DHKEY_DATA,
                c,
                Some(cms::Signer {
                    key: &key,
                    certs: &certs,
                }),
            )
            .unwrap()
        };
        let kdc = kdc_reply(&req, &client, b"the AS-REQ", 12345, None, ec_signed);
        let ec_anchor = Settings {
            anchors: Some(TrustAnchors {
                certs: vec![fixture("ec-ca")],
            }),
            ..Settings::default()
        };
        assert_eq!(reply_key(&req, &ec_anchor, &kdc, &client).unwrap(), kdc.key);
        // The RSA root does not vouch for it.
        assert!(reply_key(&req, &settings(), &kdc, &client).is_err());
    }

    #[test]
    fn ec_identities_load_from_sec1_and_pkcs8() {
        let cert = include_bytes!("pkinit/testdata/ec-kdc.pem");
        let sec1 = include_bytes!("pkinit/testdata/ec-kdc-key.pem");
        let id = Identity::from_pem(cert, sec1).unwrap();
        assert!(matches!(id.key, keys::PrivateKey::Ec(_)));
        // The same key as PKCS #8.
        let b = pem::blocks(sec1).unwrap();
        let pkcs8 = der::seq(&[der::int(0), ec::Curve::P256.alg_id(), der::octets(&b[0].1)]);
        let key = keys::PrivateKey::from_pem_blocks(&[("PRIVATE KEY".into(), pkcs8)]).unwrap();
        assert_eq!(key.public(), id.key.public());
        // An EC key with an RSA certificate does not pair.
        assert!(Identity::from_pem(include_bytes!("pkinit/testdata/kdc.pem"), sec1).is_err());
    }
}
