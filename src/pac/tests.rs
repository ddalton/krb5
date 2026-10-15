//! PACs from Windows KDCs, from MIT krb5's `t_pac.c` (the Samba torture
//! PAC by Andrew Bartlett, used with permission there; S4U2Self PACs from
//! Windows Server 2008; a ticket from Windows Server 2022), with MIT's
//! keys. The expected field values are impacket's decoding of the same
//! bytes (impacket 0.12.0, `impacket.krb5.pac`), an implementation that
//! shares nothing with this one.

use super::*;
use crate::Principal;

const SAVED: &[u8] = include_bytes!("../../testdata/pac/saved_pac.bin");
const S4U_REGULAR: &[u8] = include_bytes!("../../testdata/pac/s4u_pac_regular.bin");
const S4U_ENTERPRISE: &[u8] = include_bytes!("../../testdata/pac/s4u_pac_enterprise.bin");
const S4U_XREALM: &[u8] = include_bytes!("../../testdata/pac/s4u_pac_xrealm.bin");
const S4U_ENT_XREALM: &[u8] = include_bytes!("../../testdata/pac/s4u_pac_ent_xrealm.bin");
const W2022_TICKET: &[u8] = include_bytes!("../../testdata/pac/w2022_ticket.der");
const W2022_PAC: &[u8] = include_bytes!("../../testdata/pac/w2022_pac.bin");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// t_pac.c's keys.
const SAVED_KDC_RC4: &str = "B286757148AF7FD252C53603A150B7E7";
const SAVED_MEMBER_RC4: &str = "D217FAEAE5E6B5F95CCC94077AB8A5FC";
const S4U_SRV: &str = "14DFB5B2CDB42C8894DA2FA882E9729F4A4DC74BA02A242CC6A8D71079B9AD9A";
const S4U_TGT_SRV: &str = "420C39C51A175404451F956B8C58E0F41BCA669A644795CA6E3AD55A3B918C9F";
const W2022_KRBTGT: &str = "037381EC43967BC2AC3DF52AAE95A68EBE2458DBCE522820AF5EB704A222714F";
const W2022_SERVER: &str = "114A84E3148FAAB1FA7B5351B28AC2F1FD196D61E0F3F23E1FDBD3C1797DC1EE";

fn aes256(hex: &str) -> Key {
    Key::new(18, unhex(hex)).unwrap()
}

fn sid(s: &str) -> Sid {
    let mut parts = s.split('-').skip(1);
    let revision = parts.next().unwrap().parse().unwrap();
    let authority = parts.next().unwrap().parse().unwrap();
    Sid {
        revision,
        authority,
        sub_authorities: parts.map(|p| p.parse().unwrap()).collect(),
    }
}

/// The Windows 2003 PAC, signed with RC4 keys (HMAC-MD5): both
/// signatures, the client info, and the logon info field by field.
#[test]
fn a_windows_2003_pac_with_rc4_signatures() {
    let pac = Pac::parse(SAVED).unwrap();
    assert_eq!(
        pac.buffer_types().collect::<Vec<_>>(),
        [
            PAC_LOGON_INFO,
            PAC_CLIENT_INFO,
            PAC_SERVER_CHECKSUM,
            PAC_PRIVSVR_CHECKSUM
        ]
    );
    assert_eq!(pac.buffer(PAC_LOGON_INFO).unwrap().len(), 472);
    let copy = pac
        .zeroed(&[PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM])
        .unwrap();
    pac.verify(PAC_SERVER_CHECKSUM, 23, &unhex(SAVED_MEMBER_RC4), &copy)
        .unwrap();
    let server = pac
        .signature(PAC_SERVER_CHECKSUM)
        .unwrap()
        .unwrap()
        .1
        .to_vec();
    pac.verify(PAC_PRIVSVR_CHECKSUM, 23, &unhex(SAVED_KDC_RC4), &server)
        .unwrap();
    // The other key does not verify either.
    assert!(matches!(
        pac.verify(PAC_SERVER_CHECKSUM, 23, &unhex(SAVED_KDC_RC4), &copy),
        Err(PacError::BadSignature(_))
    ));

    let user = Principal::parse("w2003final$@WIN2K3.THINKER.LOCAL").unwrap();
    pac.verify_client(1120440609, &user, false).unwrap();
    assert!(matches!(
        pac.verify_client(1120440610, &user, false),
        Err(PacError::WrongClient(_))
    ));
    assert!(
        pac.verify_client(1120440609, &user, true).is_err(),
        "no realm in it"
    );

    let li = pac.logon_info().unwrap().unwrap();
    assert_eq!(li.effective_name, "W2003FINAL$");
    assert_eq!((li.full_name.as_str(), li.logon_script.as_str()), ("", ""));
    assert_eq!((li.logon_count, li.bad_password_count), (101, 0));
    assert_eq!((li.user_id, li.primary_group_id), (1005, 516));
    assert_eq!(li.user_flags, 32);
    assert_eq!(li.logon_server, "W2003FINAL");
    assert_eq!(li.logon_domain_name, "WIN2K3THINK");
    assert_eq!(li.user_account_control, 8448);
    assert_eq!(li.logon_time, FileTime(127645946122526512));
    assert_eq!(li.password_last_set, FileTime(127635030692216000));
    assert_eq!(
        li.group_ids,
        [GroupMembership {
            rid: 516,
            attributes: 7
        }]
    );
    let domain = sid("S-1-5-21-3048156945-3961193616-3706469200");
    assert_eq!(li.logon_domain_id, Some(domain.clone()));
    assert_eq!(li.extra_sids, [(sid("S-1-5-9"), 7)]);
    assert_eq!(li.resource_group_domain_sid, None);
    assert_eq!(li.user_sid().unwrap().to_string(), format!("{domain}-1005"));
    assert_eq!(li.group_sids(), [domain.with_rid(516), sid("S-1-5-9")]);
}

/// The Windows 2008 S4U2Self PACs: an AES server signature, client
/// names for regular and enterprise principals, local and cross-realm.
#[test]
fn windows_2008_s4u2self_pacs() {
    let user = Principal::parse("w2k8u@ACME.COM").unwrap();
    let enterprise = Principal::new(10, ["w2k8u@abc"], "ACME.COM");
    for (data, authtime, principal, xrealm, client_name) in [
        (S4U_REGULAR, 1538430362, &user, false, "w2k8u"),
        (S4U_ENTERPRISE, 1538437551, &enterprise, false, "w2k8u@abc"),
        (S4U_XREALM, 1538469429, &user, true, "w2k8u@ACME.COM"),
        (
            S4U_ENT_XREALM,
            1538484998,
            &enterprise,
            true,
            "w2k8u@abc@ACME.COM",
        ),
    ] {
        let pac = Pac::parse(data).unwrap();
        let key = aes256(if xrealm { S4U_TGT_SRV } else { S4U_SRV });
        pac.verify_server_signature(&key).unwrap();
        assert!(
            pac.verify_server_signature(&aes256(S4U_TGT_SRV.replace('4', "5").as_str()))
                .is_err()
        );
        pac.verify_client(authtime, principal, xrealm).unwrap();
        assert_eq!(pac.client_info().unwrap().unwrap().name, client_name);
        assert_eq!(pac.buffer(PAC_LOGON_INFO).unwrap().len(), 416);
        let upn = pac.upn_dns_info().unwrap().unwrap();
        assert_eq!(upn.dns_domain, "ACME.COM");
        assert_eq!(upn.sam_name, None);
    }
    let li = Pac::parse(S4U_REGULAR)
        .unwrap()
        .logon_info()
        .unwrap()
        .unwrap();
    assert_eq!(
        (li.effective_name.as_str(), li.full_name.as_str()),
        ("w2k8u", "w2k8u")
    );
    assert_eq!(
        (li.user_id, li.primary_group_id, li.user_flags),
        (1142, 513, 32)
    );
    assert_eq!(
        (li.logon_server.as_str(), li.logon_domain_name.as_str()),
        ("WDC", "ACME")
    );
    assert_eq!(li.user_account_control, 528);
    assert_eq!(li.logon_time, FileTime(0));
    assert_eq!(li.logon_time.unix_secs(), None);
    assert_eq!(li.password_last_set, FileTime(131828537953695433));
    assert_eq!(
        li.logon_domain_id,
        Some(sid("S-1-5-21-9281652-3921847615-585208160"))
    );
    assert!(li.extra_sids.is_empty());
    assert_eq!(
        Pac::parse(S4U_REGULAR)
            .unwrap()
            .upn_dns_info()
            .unwrap()
            .unwrap()
            .upn,
        "w2k8u@abc"
    );
}

/// A ticket from Windows Server 2022: decrypted with the service key, its
/// PAC found in the authorization data, every signature checked (the KDC
/// ones with the krbtgt key, the ticket signature over the re-encoded
/// ticket), and the modern buffers read.
#[test]
fn a_windows_2022_ticket_and_its_pac() {
    let server = aes256(W2022_SERVER);
    let krbtgt = aes256(W2022_KRBTGT);
    let t = Fields::parse_tagged("Ticket", der::app(1), W2022_TICKET).unwrap();
    let (_, cipher) = crate::client::decode_encrypted_data(t.get(3).unwrap()).unwrap();
    let enc = server.decrypt(2, &cipher).unwrap();
    let f = Fields::parse_tagged("EncTicketPart", der::app(3), &enc).unwrap();
    let raw = find_pac(f.raw(10).unwrap()).unwrap().unwrap();
    assert_eq!(raw, W2022_PAC);
    let pac = Pac::parse(raw).unwrap();
    assert_eq!(
        pac.buffer_types().collect::<Vec<_>>(),
        [
            PAC_LOGON_INFO,
            PAC_SERVER_CHECKSUM,
            PAC_PRIVSVR_CHECKSUM,
            PAC_CLIENT_INFO,
            PAC_UPN_DNS_INFO,
            PAC_TICKET_CHECKSUM,
            PAC_FULL_CHECKSUM
        ]
    );
    pac.verify_server_signature(&server).unwrap();
    pac.verify_kdc_signature(&krbtgt).unwrap();
    pac.verify_full_signature(&krbtgt).unwrap();
    verify_ticket_signature(&enc, &krbtgt).unwrap();
    assert!(pac.verify_kdc_signature(&server).is_err());
    assert!(verify_ticket_signature(&enc, &server).is_err());
    // One flipped octet anywhere in the ticket breaks the ticket
    // signature; in the PAC, the server signature.
    let mut tampered = enc.clone();
    let at = tampered
        .windows(13)
        .position(|w| w == b"administrator")
        .unwrap();
    tampered[at] ^= 0x20;
    assert!(verify_ticket_signature(&tampered, &krbtgt).is_err());
    let mut bad = W2022_PAC.to_vec();
    bad[200] ^= 1;
    assert!(
        Pac::parse(&bad)
            .unwrap()
            .verify_server_signature(&server)
            .is_err()
    );

    // All of it in one call, as a KDC checks a ticket.
    let all = verify_ticket(W2022_TICKET, &server, &krbtgt)
        .unwrap()
        .unwrap();
    assert_eq!(all, pac);
    assert!(verify_ticket(W2022_TICKET, &server, &server).is_err());
    assert!(
        verify_ticket(W2022_TICKET, &krbtgt, &krbtgt).is_err(),
        "not its key"
    );

    // A ticket resealed with its client name changed: the PAC and its
    // server and KDC signatures are intact, so only the ticket signature
    // can catch it, and does.
    let t = Fields::parse_tagged("Ticket", der::app(1), W2022_TICKET).unwrap();
    let resealed = der::cons(
        der::app(1),
        &[der::seq(&[
            der::tlv(der::ctx(0), t.raw(0).unwrap()),
            der::tlv(der::ctx(1), t.raw(1).unwrap()),
            der::tlv(der::ctx(2), t.raw(2).unwrap()),
            der::field(
                3,
                with_kvno(
                    &crate::client::encode_encrypted_data(
                        18,
                        &server.encrypt(2, &tampered).unwrap(),
                    ),
                    5,
                ),
            ),
        ])],
    );
    assert!(verify_ticket(&resealed, &server, &krbtgt).is_err());

    let admin = Principal::parse("administrator@W2022-L7.BASE").unwrap();
    pac.verify_client(1669219319, &admin, false).unwrap();

    let li = pac.logon_info().unwrap().unwrap();
    let domain = sid("S-1-5-21-133451344-1126667713-3548050118");
    assert_eq!(li.effective_name, "Administrator");
    assert_eq!(
        (li.logon_count, li.user_id, li.primary_group_id),
        (370, 500, 513)
    );
    assert_eq!(li.user_flags, 544);
    assert_eq!(
        (li.logon_server.as_str(), li.logon_domain_name.as_str()),
        ("W2022-118", "W2022-L7")
    );
    assert_eq!(li.user_account_control, 528);
    assert_eq!(li.logon_time, FileTime(133136929195316850));
    assert_eq!(li.password_last_set, FileTime(132893055467651518));
    let rids: Vec<(u32, u32)> = li.group_ids.iter().map(|g| (g.rid, g.attributes)).collect();
    assert_eq!(rids, [(513, 7), (512, 7), (520, 7), (518, 7), (519, 7)]);
    assert_eq!(li.logon_domain_id, Some(domain.clone()));
    assert_eq!(li.extra_sids, [(sid("S-1-18-1"), 7)]);
    assert_eq!(li.resource_group_domain_sid, Some(domain.clone()));
    assert_eq!(
        li.resource_group_ids,
        [GroupMembership {
            rid: 572,
            attributes: 536870919
        }]
    );
    assert_eq!(li.user_sid(), Some(domain.with_rid(500)));
    assert_eq!(li.group_sids().len(), 7);
    assert!(
        li.group_sids().contains(&domain.with_rid(512)),
        "Domain Admins"
    );

    let upn = pac.upn_dns_info().unwrap().unwrap();
    assert_eq!(upn.upn, "Administrator@w2022-l7.base");
    assert_eq!(upn.dns_domain, "W2022-L7.BASE");
    assert!(upn.upn_constructed);
    assert_eq!(upn.sam_name.as_deref(), Some("Administrator"));
    assert_eq!(upn.sid, Some(domain.with_rid(500)));
}

#[test]
fn sids_print_as_windows_prints_them() {
    assert_eq!(sid("S-1-5-21-1-2-3-500").to_string(), "S-1-5-21-1-2-3-500");
    let big = Sid {
        revision: 1,
        authority: 0x0000_1234_5678_9ABC,
        sub_authorities: vec![1],
    };
    assert_eq!(big.to_string(), "S-1-0x123456789ABC-1");
    let (s, n) = Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0xFF]).unwrap();
    assert_eq!((s.to_string(), n), ("S-1-5-18".to_string(), 12));
    assert!(Sid::from_bytes(&[1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]).is_err());
}

/// MIT's parse checks, and MIT's fuzzer-found PACs; nothing malformed
/// panics.
#[test]
fn malformed_pacs_are_refused_not_panicked_on() {
    // t_pac.c's fuzz1 and fuzz2.
    let fuzz1 = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xff, 0xff, 0xff, 0x00, 0x00,
        0xf5,
    ];
    let fuzz2 = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x20,
    ];
    assert!(Pac::parse(&fuzz1).is_err());
    assert!(Pac::parse(&fuzz2).is_err());
    assert!(Pac::parse(&[]).is_err());
    let mut v1 = SAVED.to_vec();
    v1[4] = 1;
    assert!(Pac::parse(&v1).is_err(), "version 1");
    let mut unaligned = SAVED.to_vec();
    unaligned[16] += 1;
    assert!(Pac::parse(&unaligned).is_err(), "offset not 8-aligned");
    // Every truncation and every single-octet change of a real PAC either
    // parses and decodes or is refused, without panicking.
    for data in [SAVED, W2022_PAC] {
        for n in 0..data.len() {
            if let Ok(p) = Pac::parse(&data[..n]) {
                let _ = (p.logon_info(), p.client_info(), p.upn_dns_info());
            }
        }
        for i in 0..data.len() {
            for b in [0x00, 0x7F, 0xFF] {
                let mut d = data.to_vec();
                d[i] = b;
                if let Ok(p) = Pac::parse(&d) {
                    let _ = (p.logon_info(), p.client_info(), p.upn_dns_info());
                    let _ = (p.delegation_info(), p.attributes(), p.requestor_sid());
                }
            }
        }
    }
}

/// The acceptor end to end: an AP-REQ around the Windows Server 2022
/// ticket yields a context with the PAC, verified; a PAC whose server
/// signature fails is dropped, and the authentication still succeeds, as
/// in MIT.
#[test]
fn the_acceptor_keeps_a_verified_pac_and_drops_a_bad_one() {
    use crate::acceptor::{EncType, KerberosContext, Keytab, ServiceKey};
    use crate::client::{Principal, decode_key, encode_ap_req, encode_authenticator};
    let server = aes256(W2022_SERVER);
    let t = Fields::parse_tagged("Ticket", der::app(1), W2022_TICKET).unwrap();
    let (_, cipher) = crate::client::decode_encrypted_data(t.get(3).unwrap()).unwrap();
    let enc = server.decrypt(2, &cipher).unwrap();
    let f = Fields::parse_tagged("EncTicketPart", der::app(3), &enc).unwrap();
    let session = decode_key(f.get(1).unwrap()).unwrap();
    let authtime = 1669219319;
    let keytab = Keytab::from_keys(vec![ServiceKey {
        principal: "cifs/w2022-118.w2022-l7.base".into(),
        realm: "W2022-L7.BASE".into(),
        kvno: 5,
        enctype: EncType::AES256CtsHmacSha196,
        key: unhex(W2022_SERVER),
    }]);
    let client = Principal::parse("administrator@W2022-L7.BASE").unwrap();
    let token = |ticket: &[u8]| {
        let auth = encode_authenticator(&client, None, 0, authtime + 60, None, None, None);
        let enc_auth = session.encrypt(11, &auth).unwrap();
        let mut body = crate::initiator::KRB5_MECH_OID.to_vec();
        body.extend([1, 0]);
        body.extend(encode_ap_req(0, ticket, 18, &enc_auth));
        der::tlv(0x60, &body)
    };
    let (ctx, _) =
        KerberosContext::accept_token_at(&keytab, &token(W2022_TICKET), 300, authtime + 60)
            .unwrap();
    let pac = ctx.pac.expect("a verified PAC");
    let li = pac.logon_info().unwrap().unwrap();
    assert_eq!(li.effective_name, "Administrator");

    // The same ticket with its PAC's server signature broken, resealed.
    let sig = W2022_PAC
        .windows(12)
        .position(|w| w == unhex("47ef6f720f1a8c25c83e5d68"))
        .unwrap();
    let pac_at = enc
        .windows(W2022_PAC.len())
        .position(|w| w == W2022_PAC)
        .unwrap();
    let mut forged = enc.clone();
    forged[pac_at + sig] ^= 1;
    let resealed = crate::client::encode_encrypted_data(18, &server.encrypt(2, &forged).unwrap());
    let ticket = der::cons(
        der::app(1),
        &[der::seq(&[
            der::tlv(der::ctx(0), t.raw(0).unwrap()),
            der::tlv(der::ctx(1), t.raw(1).unwrap()),
            der::tlv(der::ctx(2), t.raw(2).unwrap()),
            der::field(3, with_kvno(&resealed, 5)),
        ])],
    );
    let (ctx, _) =
        KerberosContext::accept_token_at(&keytab, &token(&ticket), 300, authtime + 60).unwrap();
    assert!(ctx.pac.is_none(), "a PAC that does not verify is dropped");
    assert_eq!(ctx.client_principal, "administrator@W2022-L7.BASE");
}

/// EncryptedData with a kvno: etype [0], kvno [1], cipher [2].
fn with_kvno(enc: &[u8], kvno: i64) -> Vec<u8> {
    let f = Fields::parse_tagged("EncryptedData", der::SEQUENCE, enc).unwrap();
    der::seq(&[
        der::tlv(der::ctx(0), f.raw(0).unwrap()),
        der::field(1, der::int(kvno)),
        der::tlv(der::ctx(2), f.raw(2).unwrap()),
    ])
}

/// S4U_DELEGATION_INFO from Active Directory 2019, from MIT's
/// `kdc/t_ndr.c`, with the services MIT's test names for each; and the
/// two buffers MIT's fuzzer found, refused.
#[test]
fn delegation_info_from_active_directory_2019() {
    let svc1 = "svc1/adserver.ad.test@AD.TEST";
    let svc2 = "svc2/adserver.ad.test@AD.TEST";
    for (data, target, transited) in [
        (
            &include_bytes!("../../testdata/pac/s4u_di_short.bin")[..],
            "svc2/adserver.ad.test",
            vec![svc1],
        ),
        (
            &include_bytes!("../../testdata/pac/s4u_di_long.bin")[..],
            "longsvc/adserver.ad.test",
            vec![svc1],
        ),
        (
            &include_bytes!("../../testdata/pac/s4u_di_double.bin")[..],
            "longsvc/adserver.ad.test",
            vec![svc1, svc2],
        ),
    ] {
        let di = DelegationInfo::decode(data).unwrap();
        assert_eq!(di.proxy_target, target);
        assert_eq!(di.transited_services, transited);
    }
    for fuzz in [
        &include_bytes!("../../testdata/pac/ndr_fuzz1.bin")[..],
        &include_bytes!("../../testdata/pac/ndr_fuzz2.bin")[..],
    ] {
        assert!(DelegationInfo::decode(fuzz).is_err());
    }
}

/// UPN_DNS_INFO's flags one at a time (the fixtures set both or neither):
/// U only marks the UPN constructed; S alone brings the SAM name and SID.
#[test]
fn upn_dns_info_flags_are_independent() {
    let pac = Pac::parse(W2022_PAC).unwrap();
    let buf = pac.buffer(PAC_UPN_DNS_INFO).unwrap().to_vec();
    let with_flags = |f: u32| {
        let mut b = buf.clone();
        b[8..12].copy_from_slice(&f.to_le_bytes());
        UpnDnsInfo::decode(&b).unwrap()
    };
    let u = with_flags(1);
    assert!(u.upn_constructed);
    assert_eq!((u.sam_name, u.sid), (None, None));
    let s = with_flags(2);
    assert!(!s.upn_constructed);
    assert_eq!(s.sam_name.as_deref(), Some("Administrator"));
    assert!(s.sid.is_some());
}
