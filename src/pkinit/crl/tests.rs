//! A three-level PKI made here — root (rsa2048.pem's key) → intermediate
//! → leaf (both kdc-key.pem's key) — and CRLs made to order, so each of
//! OpenSSL's rules is tested on its own.

use super::*;
use crate::pkinit::keys::PrivateKey;
use crate::pkinit::pem;

const NOW: i64 = 1_900_000_000;
const DAY: i64 = 86_400;

fn key(pem_text: &[u8]) -> PrivateKey {
    PrivateKey::from_pem_blocks(&pem::blocks(pem_text).unwrap()).unwrap()
}
fn root_key() -> PrivateKey {
    key(include_bytes!("../testdata/rsa2048.pem"))
}
fn mid_key() -> PrivateKey {
    key(include_bytes!("../testdata/kdc-key.pem"))
}

/// The SubjectPublicKeyInfo of a fixture, whole TLV.
fn spki(cert_pem: &[u8]) -> Vec<u8> {
    let der = &pem::blocks(cert_pem).unwrap()[0].1;
    let mut c = Reader::new(der).seq().unwrap();
    let mut t = c.seq().unwrap();
    t.optional(der::ctx(0)).unwrap();
    for _ in 0..5 {
        t.next().unwrap(); // serial, signature, issuer, validity, subject
    }
    t.next_raw().unwrap().2.to_vec()
}
fn root_spki() -> Vec<u8> {
    spki(include_bytes!("../testdata/ca.pem"))
}
fn mid_spki() -> Vec<u8> {
    spki(include_bytes!("../testdata/kdc.pem"))
}

fn name(cn: &str) -> Vec<u8> {
    let atv = der::seq(&[asn1::oid_tlv("2.5.4.3"), der::tlv(0x0C, cn.as_bytes())]);
    der::seq(&[der::cons(asn1::SET, &[atv])])
}

fn ext(oid: &str, critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![asn1::oid_tlv(oid)];
    if critical {
        parts.push(der::tlv(asn1::BOOLEAN, &[0xFF]));
    }
    parts.push(der::octets(&value));
    der::seq(&parts)
}

/// keyUsage with keyCertSign, and cRLSign unless `no_crl_sign`.
fn key_usage(no_crl_sign: bool) -> Vec<u8> {
    ext(
        "2.5.29.15",
        true,
        asn1::bit_string(&[if no_crl_sign { 0x04 } else { 0x06 }]),
    )
}

fn basic_constraints(ca: bool) -> Vec<u8> {
    let v = if ca {
        der::seq(&[der::tlv(asn1::BOOLEAN, &[0xFF])])
    } else {
        der::seq(&[])
    };
    ext("2.5.29.19", true, v)
}

fn sign(key: &PrivateKey, tbs: Vec<u8>) -> Vec<u8> {
    let alg = key.sig_alg();
    let sig = key.sign(&alg.hash().digest(&tbs)).unwrap();
    der::seq(&[tbs, alg.alg_id(), asn1::bit_string(&sig)])
}

fn cert(
    serial: i64,
    issuer: &str,
    subject: &str,
    spki: Vec<u8>,
    exts: Vec<Vec<u8>>,
    signer: &PrivateKey,
) -> Cert {
    let tbs = der::seq(&[
        der::field(0, der::int(2)),
        der::int(serial),
        signer.sig_alg().alg_id(),
        name(issuer),
        der::seq(&[der::time(NOW - 365 * DAY), der::time(NOW + 365 * DAY)]),
        name(subject),
        spki,
        der::field(3, der::seq(&exts)),
    ]);
    Cert::from_der(&sign(signer, tbs)).unwrap()
}

/// root, intermediate, leaf; the leaf with `leaf_exts` besides its basic
/// constraints, the intermediate with `mid_exts` besides its own.
fn pki_with(mid_exts: Vec<Vec<u8>>, leaf_exts: Vec<Vec<u8>>) -> [Cert; 3] {
    let root = cert(
        1,
        "Root",
        "Root",
        root_spki(),
        vec![basic_constraints(true), key_usage(false)],
        &root_key(),
    );
    let mut m = vec![basic_constraints(true)];
    m.extend(mid_exts);
    let mid = cert(2, "Root", "Mid", mid_spki(), m, &root_key());
    let mut l = vec![basic_constraints(false)];
    l.extend(leaf_exts);
    let leaf = cert(3, "Mid", "Leaf", mid_spki(), l, &mid_key());
    [leaf, mid, root]
}

fn pki() -> [Cert; 3] {
    pki_with(vec![key_usage(false)], vec![])
}

/// A CRL builder: issuer, signer, times, entries and extensions.
struct Make {
    issuer: &'static str,
    signer: PrivateKey,
    this: i64,
    next: Option<i64>,
    entries: Vec<Vec<u8>>,
    exts: Vec<Vec<u8>>,
}

impl Make {
    fn by_root() -> Make {
        Make::new("Root", root_key())
    }
    fn by_mid() -> Make {
        Make::new("Mid", mid_key())
    }
    fn new(issuer: &'static str, signer: PrivateKey) -> Make {
        Make {
            issuer,
            signer,
            this: NOW - DAY,
            next: Some(NOW + 7 * DAY),
            entries: vec![],
            exts: vec![],
        }
    }
    fn revoke(mut self, serial: i64) -> Make {
        self.entries
            .push(der::seq(&[der::int(serial), der::time(NOW - DAY)]));
        self
    }
    fn revoke_with(mut self, serial: i64, exts: Vec<Vec<u8>>) -> Make {
        self.entries.push(der::seq(&[
            der::int(serial),
            der::time(NOW - DAY),
            der::seq(&exts),
        ]));
        self
    }
    fn times(mut self, this: i64, next: Option<i64>) -> Make {
        self.this = this;
        self.next = next;
        self
    }
    fn ext(mut self, e: Vec<u8>) -> Make {
        self.exts.push(e);
        self
    }
    fn der(self) -> Vec<u8> {
        let mut tbs = vec![
            der::int(1),
            self.signer.sig_alg().alg_id(),
            name(self.issuer),
            der::time(self.this),
        ];
        if let Some(n) = self.next {
            tbs.push(der::time(n));
        }
        if !self.entries.is_empty() {
            tbs.push(der::seq(&self.entries));
        }
        if !self.exts.is_empty() {
            tbs.push(der::field(0, der::seq(&self.exts)));
        }
        sign(&self.signer, der::seq(&tbs))
    }
    fn crl(self) -> Crl {
        Crl::from_der(&self.der()).unwrap()
    }
}

fn check(pki: &[Cert; 3], local: &[Crl], require: bool) -> std::result::Result<(), String> {
    let path: Vec<&Cert> = pki.iter().collect();
    check_chain(&path, Policy { local, require }, &[], NOW).map_err(|e| e.0)
}

fn fails(r: std::result::Result<(), String>, want: &str) {
    match r {
        Err(e) => assert!(e.contains(want), "{e:?} does not say {want:?}"),
        Ok(()) => panic!("passed; wanted {want:?}"),
    }
}

#[test]
fn without_crls_only_a_requirement_fails() {
    let p = pki();
    check(&p, &[], false).unwrap();
    fails(check(&p, &[], true), "depth 0");
    // Required: a CRL for each certificate below the anchor.
    fails(check(&p, &[Make::by_mid().crl()], true), "depth 1");
    check(&p, &[Make::by_mid().crl(), Make::by_root().crl()], true).unwrap();
}

#[test]
fn a_listed_certificate_is_revoked_at_any_depth_but_the_anchor() {
    let p = pki();
    fails(
        check(&p, &[Make::by_mid().revoke(3).crl()], false),
        "depth 0 of the KDC's chain: revoked",
    );
    fails(
        check(&p, &[Make::by_root().revoke(2).crl()], false),
        "depth 1 of the KDC's chain: revoked",
    );
    // The anchor is trusted as is, as OpenSSL does (and MIT's kinit shows).
    check(&p, &[Make::by_root().revoke(1).crl()], true).unwrap_err();
    check(
        &p,
        &[Make::by_root().revoke(1).crl(), Make::by_mid().crl()],
        true,
    )
    .unwrap();
    // Other serials, and another issuer's list, do not matter.
    check(&p, &[Make::by_mid().revoke(2).revoke(1).crl()], false).unwrap();
}

#[test]
fn remove_from_crl_entries_do_not_revoke() {
    let p = pki();
    let reason = |r: u8| ext("2.5.29.21", false, der::tlv(ENUMERATED, &[r]));
    check(
        &p,
        &[Make::by_mid().revoke_with(3, vec![reason(8)]).crl()],
        false,
    )
    .unwrap();
    fails(
        check(
            &p,
            &[Make::by_mid().revoke_with(3, vec![reason(1)]).crl()],
            false,
        ),
        "revoked",
    );
}

#[test]
fn an_out_of_date_or_forged_crl_fails_even_when_not_required() {
    let p = pki();
    let expired = Make::by_mid().times(NOW - 30 * DAY, Some(NOW - DAY)).crl();
    fails(check(&p, &[expired], false), "expired");
    let future = Make::by_mid().times(NOW + DAY, Some(NOW + 30 * DAY)).crl();
    fails(check(&p, &[future], false), "not yet valid");
    // No nextUpdate: current from thisUpdate on.
    check(&p, &[Make::by_mid().times(NOW - DAY, None).crl()], true).unwrap_err();
    check(
        &p,
        &[
            Make::by_mid().times(NOW - DAY, None).crl(),
            Make::by_root().crl(),
        ],
        true,
    )
    .unwrap();
    // The intermediate's name, the root's key.
    let forged = Make::new("Mid", root_key()).crl();
    fails(check(&p, &[forged], false), "not signed by the issuer");
}

#[test]
fn the_issuer_must_be_allowed_to_sign_crls() {
    let p = pki_with(vec![key_usage(true)], vec![]);
    fails(
        check(&p, &[Make::by_mid().crl()], false),
        "may not sign CRLs",
    );
    // No keyUsage at all is no restriction.
    let p = pki_with(vec![], vec![]);
    check(&p, &[Make::by_mid().crl()], false).unwrap();
}

#[test]
fn local_crls_keep_the_first_from_each_issuer_as_mit_loads_them() {
    let p = pki();
    let ok = || Make::by_mid().crl();
    let revoked = || Make::by_mid().revoke(3).crl();
    let mut first_ok = vec![];
    add_local(&mut first_ok, ok());
    add_local(&mut first_ok, revoked());
    assert_eq!(first_ok.len(), 1);
    check(&p, &first_ok, false).unwrap();
    let mut first_revoked = vec![];
    add_local(&mut first_revoked, revoked());
    add_local(&mut first_revoked, ok());
    fails(check(&p, &first_revoked, false), "revoked");
    // Different issuers are both kept.
    let mut two = vec![];
    add_local(&mut two, ok());
    add_local(&mut two, Make::by_root().crl());
    assert_eq!(two.len(), 2);
}

#[test]
fn of_several_crls_the_current_and_then_the_latest_is_used() {
    let p = pki();
    let path: Vec<&Cert> = p.iter().collect();
    let run = |local: &[Crl], sent: &[Crl]| {
        check_chain(
            &path,
            Policy {
                local,
                require: false,
            },
            sent,
            NOW,
        )
        .map_err(|e| e.0)
    };
    let expired_revoking = Make::by_mid()
        .revoke(3)
        .times(NOW - 30 * DAY, Some(NOW - DAY))
        .crl();
    let current = Make::by_mid().crl();
    // A current CRL beats an expired one in either order.
    run(
        std::slice::from_ref(&expired_revoking),
        std::slice::from_ref(&current),
    )
    .unwrap();
    run(std::slice::from_ref(&current), &[expired_revoking]).unwrap();
    // Two current ones: the later thisUpdate, in either order; a tie
    // goes to the first.
    let older = Make::by_mid().times(NOW - 2 * DAY, Some(NOW + DAY)).crl();
    let newer_revoking = Make::by_mid().revoke(3).crl();
    fails(
        run(
            std::slice::from_ref(&older),
            std::slice::from_ref(&newer_revoking),
        ),
        "revoked",
    );
    fails(
        run(
            std::slice::from_ref(&newer_revoking),
            std::slice::from_ref(&older),
        ),
        "revoked",
    );
    // The score first, the date only between equals: a later CRL that is
    // not yet valid, or has an unhandled critical extension, loses to a
    // current one.
    let future_revoking = Make::by_mid()
        .revoke(3)
        .times(NOW + DAY, Some(NOW + 9 * DAY))
        .crl();
    run(
        std::slice::from_ref(&current),
        std::slice::from_ref(&future_revoking),
    )
    .unwrap();
    let critical_later = Make::by_mid()
        .times(NOW, Some(NOW + DAY))
        .ext(ext("1.2.3.4", true, der::seq(&[])))
        .crl();
    run(
        std::slice::from_ref(&current),
        std::slice::from_ref(&critical_later),
    )
    .unwrap();
    run(
        std::slice::from_ref(&current),
        std::slice::from_ref(&newer_revoking),
    )
    .unwrap();
    fails(run(&[newer_revoking], &[current]), "revoked");
}

#[test]
fn unhandled_critical_extensions_fail_handled_ones_do_not() {
    let p = pki();
    let unknown = ext("1.2.3.4", true, der::seq(&[]));
    fails(
        check(&p, &[Make::by_mid().ext(unknown).crl()], false),
        "unhandled critical",
    );
    // OpenSSL counts even a critical CRL number as unhandled.
    let number = ext("2.5.29.20", true, der::int(7));
    fails(
        check(&p, &[Make::by_mid().ext(number).crl()], false),
        "unhandled critical",
    );
    let number = ext("2.5.29.20", false, der::int(7));
    check(&p, &[Make::by_mid().ext(number).crl()], false).unwrap();
    // A critical issuingDistributionPoint or authorityKeyIdentifier is
    // handled.
    let idp = ext("2.5.29.28", true, der::seq(&[]));
    check(&p, &[Make::by_mid().ext(idp).crl()], false).unwrap();
    // An entry's critical reason code is not.
    let reason = ext("2.5.29.21", true, der::tlv(ENUMERATED, &[1]));
    fails(
        check(
            &p,
            &[Make::by_mid().revoke_with(9, vec![reason]).crl()],
            false,
        ),
        "unhandled critical",
    );
}

#[test]
fn delta_indirect_and_partitioned_crls_are_no_crl() {
    let p = pki();
    let delta = Make::by_mid()
        .revoke(3)
        .ext(ext("2.5.29.27", true, der::int(1)))
        .crl();
    check(&p, std::slice::from_ref(&delta), false).unwrap();
    fails(check(&p, &[delta, Make::by_root().crl()], true), "depth 0");
    for field in [
        der::tlv(0x84, &[0xFF]),       // indirectCRL
        der::tlv(0x83, &[0x07, 0x80]), // onlySomeReasons
    ] {
        let idp = ext("2.5.29.28", true, der::seq(&[field]));
        let crl = Make::by_mid().revoke(3).ext(idp).crl();
        check(&p, &[crl], false).unwrap();
    }
}

#[test]
fn a_crl_covers_only_what_its_distribution_point_says() {
    let p = pki();
    let idp = |fields: Vec<Vec<u8>>| ext("2.5.29.28", true, der::seq(&fields));
    let only_ca = idp(vec![der::tlv(0x82, &[0xFF])]);
    let only_user = idp(vec![der::tlv(0x81, &[0xFF])]);
    // The leaf is no CA: a CA-only CRL from its issuer does not cover it,
    // which OpenSSL reports rather than passes.
    fails(
        check(&p, &[Make::by_mid().ext(only_ca.clone()).crl()], false),
        "does not cover",
    );
    check(&p, &[Make::by_mid().ext(only_user.clone()).crl()], false).unwrap();
    // And the intermediate is.
    fails(
        check(&p, &[Make::by_root().ext(only_user).crl()], false),
        "does not cover",
    );
    check(&p, &[Make::by_root().ext(only_ca).crl()], false).unwrap();

    // A named point covers a certificate whose cRLDistributionPoints name
    // it, and no other.
    let uri = |u: &str| der::tlv(0x86, u.as_bytes());
    let point = |u: &str| der::tlv(der::ctx(0), &der::tlv(der::ctx(0), &uri(u)));
    let named = idp(vec![point("http://crl.test/mid.crl")]);
    let crldp = |u: &str| ext("2.5.29.31", false, der::seq(&[der::seq(&[point(u)])]));
    fails(
        check(&p, &[Make::by_mid().ext(named.clone()).crl()], false),
        "does not cover",
    );
    let p = pki_with(
        vec![key_usage(false)],
        vec![crldp("http://crl.test/mid.crl")],
    );
    fails(
        check(
            &p,
            &[Make::by_mid().ext(named.clone()).revoke(3).crl()],
            false,
        ),
        "revoked",
    );
    let p = pki_with(
        vec![key_usage(false)],
        vec![crldp("http://crl.test/other.crl")],
    );
    fails(
        check(&p, &[Make::by_mid().ext(named).crl()], false),
        "does not cover",
    );
}

#[test]
fn a_crl_for_another_key_of_the_issuers_name_is_not_its_crl() {
    let keyid = |id: &[u8]| ext("2.5.29.35", false, der::seq(&[der::tlv(0x80, id)]));
    let ski = ext("2.5.29.14", false, der::octets(b"mid-key"));
    let p = pki_with(vec![key_usage(false), ski], vec![]);
    let other = Make::by_mid().ext(keyid(b"old-key")).revoke(3).crl();
    check(&p, std::slice::from_ref(&other), false).unwrap();
    fails(check(&p, &[other, Make::by_root().crl()], true), "depth 0");
    let same = Make::by_mid().ext(keyid(b"mid-key")).revoke(3).crl();
    fails(check(&p, &[same], false), "revoked");
}

#[test]
fn pem_files_give_their_crl_blocks() {
    let b64 = |d: &[u8]| {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in d.chunks(3) {
            let n = c
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
            for i in 0..4 {
                s.push(if i <= c.len() {
                    A[(n >> (18 - 6 * i) & 63) as usize] as char
                } else {
                    '='
                });
            }
        }
        s
    };
    let block = |label: &str, d: &[u8]| {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            b64(d)
        )
    };
    let crl = Make::by_mid().revoke(3).der();
    let text = format!(
        "a comment\n{}{}",
        include_str!("../testdata/ca.pem"),
        block("X509 CRL", &crl)
    );
    let got = from_pem(text.as_bytes()).unwrap();
    assert_eq!(got, vec![Crl::from_der(&crl).unwrap()]);
    // Certificates alone, or DER: no CRLs, no error.
    assert!(
        from_pem(include_bytes!("../testdata/ca.pem"))
            .unwrap()
            .is_empty()
    );
    assert!(from_pem(&crl).unwrap().is_empty());
    // A CRL block that is not a CRL is an error.
    from_pem(block("X509 CRL", b"not a CRL").as_bytes()).unwrap_err();
}

#[test]
fn malformed_crls_are_refused() {
    let good = Make::by_mid().revoke(3).der();
    Crl::from_der(&good).unwrap();
    for n in 0..good.len() {
        let _ = Crl::from_der(&good[..n]);
    }
    let mut extra = good.clone();
    extra.push(0);
    Crl::from_der(&extra).unwrap_err();
}

/// OpenSSL's own CRL (scripts/make-pkinit-testdata.sh: CRL number,
/// authorityKeyIdentifier, a keyCompromise entry, UTCTime and
/// GeneralizedTime) against the fixture chain kdc → inter → ca.
#[test]
fn an_openssl_crl_revokes_the_fixture_intermediate() {
    use crate::pkinit::x509::tests::fixture;
    let crls = from_pem(include_bytes!("../testdata/ca-crl.pem")).unwrap();
    assert_eq!(crls.len(), 1);
    let (kdc, inter, ca) = (fixture("kdc"), fixture("inter"), fixture("ca"));
    let anchors = [ca];
    let pool = [inter];
    let path = x509::verify_chain(&kdc, &pool, &anchors, NOW).unwrap();
    assert_eq!(path.len(), 3);
    let policy = Policy {
        local: &crls,
        require: false,
    };
    let e = check_chain(&path, policy, &[], NOW).unwrap_err();
    assert!(e.0.contains("depth 1 of the KDC's chain: revoked"), "{e}");
    // The other root of the same name has another key: its
    // authorityKeyIdentifier says the CRL is not that root's.
    let other = [fixture("other-ca")];
    let fake_path = [&kdc, &pool[0], &other[0]];
    check_chain(&fake_path, policy, &[], NOW).unwrap();
}
