//! Certificate revocation lists (RFC 5280 §5) for the KDC's certificate
//! chain, checked as MIT's client has OpenSSL check them
//! (`X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL`):
//!
//! * every certificate below the trust anchor is looked up in a CRL from
//!   its issuer, the anchor itself in none;
//! * CRLs come from `pkinit_revoke` (only the first from each issuer is
//!   kept, as MIT's loader keeps them) and from the KDC's SignedData;
//! * of a certificate's candidate CRLs, OpenSSL's choice: one without
//!   unhandled critical extensions, in scope, then current, the later
//!   `thisUpdate` breaking a tie;
//! * no CRL for an issuer fails only with `pkinit_require_crl_checking`;
//!   a CRL that is out of date, out of scope, badly signed, from an issuer
//!   without `cRLSign`, or has an unhandled critical extension fails
//!   always, as does a listed serial number.
//!
//! Not supported, as OpenSSL does not without extended CRL support: delta
//! CRLs, indirect CRLs and CRLs partitioned by reason; such a CRL is no
//! CRL for the certificate. Nor is OCSP, which MIT does not do.

use super::asn1::{self, ReaderExt, implicit};
use super::x509::{self, Cert, Extension};
use crate::der::{self, DerError, Reader};

type Result<T> = std::result::Result<T, DerError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(DerError(msg.into()))
}

const REASON_CODE: &str = "2.5.29.21";
const DELTA_CRL_INDICATOR: &str = "2.5.29.27";
const ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";
const CERTIFICATE_ISSUER: &str = "2.5.29.29";
const CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
/// keyUsage `cRLSign` (RFC 5280 §4.2.1.3).
const KU_CRL_SIGN: u32 = 6;
/// CRLReason `removeFromCRL`: an entry that does not revoke.
const REMOVE_FROM_CRL: u8 = 8;

/// A parsed CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Crl {
    tbs: Vec<u8>,
    sig_alg: Vec<u8>,
    signature: Vec<u8>,
    /// The issuer Name, whole TLV, as [`Cert::issuer`] holds it.
    pub(crate) issuer: Vec<u8>,
    this_update: i64,
    next_update: Option<i64>,
    /// The revoked serial numbers (INTEGER content octets), less those
    /// marked `removeFromCRL`.
    revoked: Vec<Vec<u8>>,
    /// A critical extension, of the CRL or of an entry, that OpenSSL does
    /// not handle.
    unhandled_critical: bool,
    /// A delta CRL, an indirect CRL, one partitioned by reason, or one
    /// whose issuingDistributionPoint is invalid: never a certificate's
    /// CRL here.
    unusable: bool,
    idp: Option<Idp>,
    /// authorityKeyIdentifier's keyIdentifier.
    akid: Option<Vec<u8>>,
}

/// What issuingDistributionPoint limits the CRL to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Idp {
    /// The DistributionPointName, whole TLV.
    point: Option<Vec<u8>>,
    only_user: bool,
    only_ca: bool,
    only_attribute: bool,
}

impl Crl {
    /// ```text
    /// CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue BIT STRING }
    /// TBSCertList ::= SEQUENCE {
    ///     version INTEGER OPTIONAL, signature AlgorithmIdentifier, issuer Name,
    ///     thisUpdate Time, nextUpdate Time OPTIONAL,
    ///     revokedCertificates SEQUENCE OF SEQUENCE {
    ///         userCertificate INTEGER, revocationDate Time,
    ///         crlEntryExtensions Extensions OPTIONAL } OPTIONAL,
    ///     crlExtensions [0] EXPLICIT Extensions OPTIONAL }
    /// ```
    pub(crate) fn from_der(der: &[u8]) -> Result<Crl> {
        let mut outer = Reader::new(der);
        let mut c = outer.seq()?;
        outer.done("CertificateList")?;
        let (_, tbs_content, tbs) = c.next_raw()?;
        let (sig_alg, _) = c.alg_id()?;
        let signature = c.bits()?.to_vec();
        c.done("CertificateList")?;

        let mut t = Reader::new(tbs_content);
        let version = match t.rest().first() {
            Some(&der::INTEGER) => t.int()?,
            _ => 0,
        };
        let (inner_alg, _) = t.alg_id()?;
        if inner_alg != sig_alg {
            return err("CRL signature algorithms disagree");
        }
        let issuer = t.next_raw()?.2.to_vec();
        let this_update = x509::read_time(&mut t)?;
        let next_update = match t.rest().first() {
            Some(&tag) if tag == asn1::UTC_TIME || tag == der::GENERALIZED_TIME => {
                Some(x509::read_time(&mut t)?)
            }
            _ => None,
        };
        let mut crl = Crl {
            tbs: tbs.to_vec(),
            sig_alg: sig_alg.to_vec(),
            signature,
            issuer,
            this_update,
            next_update,
            revoked: Vec::new(),
            unhandled_critical: false,
            unusable: false,
            idp: None,
            akid: None,
        };
        if t.rest().first() == Some(&der::SEQUENCE) {
            let mut entries = t.seq()?;
            while !entries.is_empty() {
                let mut e = entries.seq()?;
                let serial = e.expect(der::INTEGER)?.to_vec();
                x509::read_time(&mut e)?;
                let mut remove = false;
                if !e.is_empty() {
                    if version != 1 {
                        return err("entry extensions in a CRL before v2");
                    }
                    let (_, _, raw) = e.next_raw()?;
                    for x in x509::read_extensions(raw)? {
                        if x.oid == asn1::oid(REASON_CODE) {
                            remove = Reader::new(&x.value).expect(ENUMERATED)? == [REMOVE_FROM_CRL];
                        }
                        // OpenSSL handles a critical certificateIssuer
                        // (it matters only to indirect CRLs) and no other.
                        if x.critical && x.oid != asn1::oid(CERTIFICATE_ISSUER) {
                            crl.unhandled_critical = true;
                        }
                    }
                }
                e.done("revokedCertificate")?;
                if !remove {
                    crl.revoked.push(serial);
                }
            }
        }
        if let Some(exts) = t.optional(der::ctx(0))? {
            if version != 1 {
                return err("extensions in a CRL before v2");
            }
            for x in x509::read_extensions(exts)? {
                crl.extension(&x)?;
            }
        }
        t.done("TBSCertList")?;
        Ok(crl)
    }

    fn extension(&mut self, x: &Extension) -> Result<()> {
        let is = |dotted| x.oid == asn1::oid(dotted);
        if is(DELTA_CRL_INDICATOR) {
            self.unusable = true;
        } else if is(AUTHORITY_KEY_IDENTIFIER) {
            // SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
            let mut s = Reader::new(&x.value).seq()?;
            self.akid = s.optional(implicit(0))?.map(<[u8]>::to_vec);
        } else if is(ISSUING_DISTRIBUTION_POINT) {
            self.idp = Some(self.read_idp(&x.value)?);
        } else if x.critical {
            // OpenSSL handles a critical IDP, AKI or delta indicator, and
            // no other: not even the CRL number.
            self.unhandled_critical = true;
        }
        Ok(())
    }

    /// ```text
    /// IssuingDistributionPoint ::= SEQUENCE {
    ///     distributionPoint [0] DistributionPointName OPTIONAL,
    ///     onlyContainsUserCerts [1] BOOLEAN DEFAULT FALSE,
    ///     onlyContainsCACerts [2] BOOLEAN DEFAULT FALSE,
    ///     onlySomeReasons [3] ReasonFlags OPTIONAL,
    ///     indirectCRL [4] BOOLEAN DEFAULT FALSE,
    ///     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
    /// ```
    fn read_idp(&mut self, value: &[u8]) -> Result<Idp> {
        let mut s = Reader::new(value).seq()?;
        let point = match s.rest().first() {
            Some(&t) if t == der::ctx(0) => Some(s.next_raw()?.2.to_vec()),
            _ => None,
        };
        let flag = |n: u8, s: &mut Reader<'_>| -> Result<bool> {
            Ok(match s.optional(implicit(n))? {
                Some([0xFF]) => true,
                Some(_) => return err("bad BOOLEAN in issuingDistributionPoint"),
                None => false,
            })
        };
        let only_user = flag(1, &mut s)?;
        let only_ca = flag(2, &mut s)?;
        let some_reasons = s.optional(implicit(3))?.is_some();
        let indirect = flag(4, &mut s)?;
        let only_attribute = flag(5, &mut s)?;
        s.done("IssuingDistributionPoint")?;
        // OpenSSL's IDP_INVALID: more than one "only".
        if u8::from(only_user) + u8::from(only_ca) + u8::from(only_attribute) > 1
            || some_reasons
            || indirect
        {
            self.unusable = true;
        }
        Ok(Idp {
            point,
            only_user,
            only_ca,
            only_attribute,
        })
    }

    fn current(&self, now: i64) -> bool {
        self.this_update <= now && self.next_update.is_none_or(|n| now <= n)
    }
}

const ENUMERATED: u8 = 0x0A;

/// The CRLs MIT's client has: the first from each issuer, in order.
pub(crate) fn add_local(into: &mut Vec<Crl>, crl: Crl) {
    if !into.iter().any(|c| c.issuer == crl.issuer) {
        into.push(crl);
    }
}

/// The CRLs in a PEM file's `X509 CRL` blocks. Other blocks and text
/// outside blocks are ignored (a file of certificates, a DER CRL); a CRL
/// block that does not parse is an error, as with OpenSSL's
/// `PEM_X509_INFO_read_bio`.
pub(crate) fn from_pem(data: &[u8]) -> std::result::Result<Vec<Crl>, String> {
    super::pem::blocks(data)?
        .into_iter()
        .filter(|(label, _)| label == "X509 CRL")
        .map(|(_, d)| Crl::from_der(&d).map_err(|e| format!("CRL: {}", e.0)))
        .collect()
}

/// Revocation policy for one chain check.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Policy<'a> {
    /// `pkinit_revoke`'s CRLs.
    pub(crate) local: &'a [Crl],
    /// `pkinit_require_crl_checking`.
    pub(crate) require: bool,
}

/// Check each certificate of `path` (leaf first, anchor last) but the
/// anchor against the CRLs of `policy` and those `sent` with it.
pub(crate) fn check_chain(
    path: &[&Cert],
    policy: Policy<'_>,
    sent: &[Crl],
    now: i64,
) -> Result<()> {
    for (depth, pair) in path.windows(2).enumerate() {
        check_cert(pair[0], pair[1], depth, policy, sent, now)?;
    }
    Ok(())
}

// OpenSSL's get_crl_score bits, in its order of preference.
const SCORE_NOCRITICAL: u32 = 0x100;
const SCORE_SCOPE: u32 = 0x080;
const SCORE_TIME: u32 = 0x040;

fn check_cert(
    cert: &Cert,
    issuer: &Cert,
    depth: usize,
    policy: Policy<'_>,
    sent: &[Crl],
    now: i64,
) -> Result<()> {
    let at = |what: &str| {
        DerError(format!(
            "certificate at depth {depth} of the KDC's chain: {what}"
        ))
    };
    let ski = issuer
        .extension(SUBJECT_KEY_IDENTIFIER)
        .and_then(|e| Reader::new(&e.value).octets().ok());
    // OpenSSL's get_crl_sk: the best score, a later thisUpdate taking a tie.
    let mut best: Option<(u32, &Crl)> = None;
    for crl in policy.local.iter().chain(sent) {
        if crl.unusable || crl.issuer != cert.issuer {
            continue;
        }
        // An authorityKeyIdentifier naming another key: some other
        // issuer's CRL (a re-keyed CA), not this one's.
        if let (Some(a), Some(s)) = (&crl.akid, ski) {
            if a.as_slice() != s {
                continue;
            }
        }
        let mut score = 0;
        if !crl.unhandled_critical {
            score |= SCORE_NOCRITICAL;
        }
        if in_scope(cert, crl) {
            score |= SCORE_SCOPE;
        }
        if crl.current(now) {
            score |= SCORE_TIME;
        }
        best = match best {
            Some((b, c)) if score < b || (score == b && crl.this_update <= c.this_update) => {
                Some((b, c))
            }
            _ => Some((score, crl)),
        };
    }
    let Some((score, crl)) = best else {
        return match policy.require {
            true => Err(at("no CRL from its issuer (pkinit_require_crl_checking)")),
            false => Ok(()),
        };
    };
    // OpenSSL's check_crl, then cert_crl.
    if issuer.key_usage(KU_CRL_SIGN)? == Some(false) {
        return Err(at("its CRL's issuer may not sign CRLs (keyUsage)"));
    }
    if score & SCORE_SCOPE == 0 {
        return Err(at(
            "its issuer's CRL does not cover it (issuingDistributionPoint)",
        ));
    }
    if crl.this_update > now {
        return Err(at("its issuer's CRL is not yet valid"));
    }
    if crl.next_update.is_some_and(|n| now > n) {
        return Err(at("its issuer's CRL has expired"));
    }
    if !issuer.made(&crl.sig_alg, &crl.tbs, &crl.signature) {
        return Err(at("its issuer's CRL is not signed by the issuer"));
    }
    if crl.unhandled_critical {
        return Err(at("its issuer's CRL has an unhandled critical extension"));
    }
    if crl.revoked.contains(&cert.serial) {
        return Err(at("revoked"));
    }
    Ok(())
}

/// OpenSSL's crl_crldp_check: whether `crl`'s issuingDistributionPoint
/// covers `cert`.
fn in_scope(cert: &Cert, crl: &Crl) -> bool {
    let Some(idp) = &crl.idp else {
        return true;
    };
    if idp.only_attribute || (cert.is_ca() && idp.only_user) || (!cert.is_ca() && idp.only_ca) {
        return false;
    }
    let Some(point) = &idp.point else {
        return true;
    };
    // The certificate's cRLDistributionPoints: one without a cRLIssuer
    // whose name is absent or shares a GeneralName with the CRL's.
    let Some(e) = cert.extension(CRL_DISTRIBUTION_POINTS) else {
        return false;
    };
    let Ok(mut dps) = Reader::new(&e.value).seq() else {
        return false;
    };
    while let Ok(mut dp) = dps.seq() {
        let mut name = None;
        let mut has_crl_issuer = false;
        while let Ok((tag, _, raw)) = dp.next_raw() {
            if tag == der::ctx(0) {
                name = Some(raw);
            } else if tag == der::ctx(2) {
                has_crl_issuer = true;
            }
        }
        if !has_crl_issuer && name.is_none_or(|n| same_point(n, point)) {
            return true;
        }
    }
    false
}

/// Whether two DistributionPointNames (whole `[0]` TLVs) name the same
/// point: equal, or full names sharing a GeneralName.
fn same_point(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    let full_names = |dp: &[u8]| -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let Ok(c) = Reader::new(dp).expect(der::ctx(0)) else {
            return out;
        };
        let mut r = Reader::new(c);
        // fullName [0] IMPLICIT GeneralNames
        if let Ok(names) = r.expect(implicit(0) | 0x20) {
            let mut n = Reader::new(names);
            while let Ok((_, _, raw)) = n.next_raw() {
                out.push(raw.to_vec());
            }
        }
        out
    };
    let (a, b) = (full_names(a), full_names(b));
    a.iter().any(|x| b.contains(x))
}

#[cfg(test)]
mod tests;
