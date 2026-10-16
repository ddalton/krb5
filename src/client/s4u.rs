//! S4U (MS-SFU): a service acting for a user. S4U2Self ("protocol
//! transition") gets a ticket to the service itself in the user's name,
//! with no word from the user; S4U2Proxy ("constrained delegation") turns
//! such a ticket, or one the user really sent, into a ticket in the
//! user's name to another service the KDC lets it delegate to. What MIT's
//! `krb5_get_credentials_for_user` and `krb5_get_credentials_for_proxy`
//! do (`kvno -U user`, `kvno -U user -P`), in the service's own realm.

use super::*;

/// MS-SFU PA-DATA types, and RFC 4120bis's PA-PAC-OPTIONS (MS-KILE).
const PA_FOR_USER: i32 = 129;
const PA_S4U_X509_USER: i32 = 130;
const PA_PAC_OPTIONS: i32 = 167;
/// PA-PAC-OPTIONS resource-based-constrained-delegation (bit 3).
const PAC_OPTIONS_RBCD: u32 = 0x1000_0000;
/// S4UUserID options: the KDC's reply checksum uses its own key usage.
const S4U_OPTS_USE_REPLY_KEY_USAGE: u32 = 0x2000_0000;
const KU_S4U_X509_USER_REQUEST: u32 = 26;
const KU_S4U_X509_USER_REPLY: u32 = 27;
/// KRB5_KEYUSAGE_APP_DATA_CKSUM, PA-FOR-USER's.
const KU_APP_DATA_CKSUM: u32 = 17;
/// KDCOptions cname-in-addl-tkt (bit 14): the client comes from the
/// additional (evidence) ticket.
const KDC_OPT_CNAME_IN_ADDL_TKT: u32 = 1 << 17;
/// KERB_CHECKSUM_HMAC_MD5, which MS-SFU prescribes for PA-FOR-USER.
const CKSUMTYPE_HMAC_MD5: i64 = -138;

/// What a TGS request does on someone else's behalf.
pub(super) enum S4u<'a> {
    None,
    /// S4U2Self for this user.
    User(&'a Principal),
    /// S4U2Proxy with this evidence ticket.
    Proxy {
        evidence: &'a Credentials,
    },
    /// User-to-user, in the session key of this TGT (the server's).
    UserToUser(&'a [u8]),
}

/// A TGS reply with what S4U needs to check it.
pub(super) struct TgsReply {
    pub creds: Credentials,
    /// The reply's PA-DATA (FAST's, when armored).
    pub padata: Vec<(i32, Vec<u8>)>,
    /// The authenticator subkey, which keyed the S4U checksums.
    pub subkey: Option<Key>,
    pub nonce: u32,
}

/// `S4UUserID ::= SEQUENCE { nonce [0], cname [1], crealm [2],
/// subject-certificate [3], options [4] }`, as MIT's
/// `krb5_get_self_cred_from_kdc` fills it: no certificate, and the
/// reply-key-usage option.
fn s4u_user_id(user: &Principal, nonce: u32) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::int(nonce as i64)),
        der::field(1, user.encode_name()),
        der::field(2, der::general_string(&user.realm)),
        der::field(4, der::flags32(S4U_OPTS_USE_REPLY_KEY_USAGE)),
    ])
}

fn checksum(ty: i64, sum: &[u8]) -> Vec<u8> {
    der::seq(&[der::field(0, der::int(ty)), der::field(1, der::octets(sum))])
}

/// The request's S4U PA-DATA, in MIT's order.
pub(super) fn request_padata(
    s4u: &S4u<'_>,
    tgt: &Credentials,
    nonce: u32,
    subkey: Option<&Key>,
) -> Result<Vec<(i32, Vec<u8>)>> {
    match s4u {
        S4u::None | S4u::UserToUser(_) => Ok(Vec::new()),
        S4u::User(user) => {
            // PA-S4U-X509-USER, checksummed with the subkey (MS-SFU 2.2.2).
            let subkey = subkey.expect("S4U2Self always has a subkey");
            let id = s4u_user_id(user, nonce);
            let sum = subkey.checksum(KU_S4U_X509_USER_REQUEST, &id)?;
            let x509_user = der::seq(&[
                der::field(0, id),
                der::field(1, checksum(subkey.checksum_type() as i64, &sum)),
            ]);
            // PA-FOR-USER, HMAC-MD5 over the name type (little-endian),
            // the name, the realm and "Kerberos", keyed with the TGT
            // session key whatever its type, as MS-SFU and MIT have it.
            let mut data = (user.name_type as u32).to_le_bytes().to_vec();
            for c in &user.components {
                data.extend_from_slice(c.as_bytes());
            }
            data.extend_from_slice(user.realm.as_bytes());
            data.extend_from_slice(b"Kerberos");
            let sum =
                crate::md5::hmac_md5_checksum(tgt.session_key.bytes(), KU_APP_DATA_CKSUM, &data);
            let for_user = der::seq(&[
                der::field(0, user.encode_name()),
                der::field(1, der::general_string(&user.realm)),
                der::field(2, checksum(CKSUMTYPE_HMAC_MD5, &sum)),
                der::field(3, der::general_string("Kerberos")),
            ]);
            Ok(vec![(PA_S4U_X509_USER, x509_user), (PA_FOR_USER, for_user)])
        }
        S4u::Proxy { .. } => Ok(vec![(
            PA_PAC_OPTIONS,
            der::seq(&[der::field(0, der::flags32(PAC_OPTIONS_RBCD))]),
        )]),
    }
}

/// MIT's `verify_s4u2self_reply`: the KDC's PA-S4U-X509-USER echoes our
/// nonce, names the user (canonicalized), and carries a checksum keyed
/// with our subkey. Returns the user it names; with no such PA-DATA (a
/// KDC that does not send it), the user asked for.
fn verify_s4u2self_reply(reply: &TgsReply, asked: &Principal) -> Result<Principal> {
    let Some((_, value)) = reply.padata.iter().find(|(t, _)| *t == PA_S4U_X509_USER) else {
        return Ok(asked.clone());
    };
    let modified = |what: &str| -> Result<Principal> {
        protocol(format!(
            "the KDC's PA-S4U-X509-USER {what} (KRB5_KDCREP_MODIFIED)"
        ))
    };
    let f = Fields::parse_tagged("PA-S4U-X509-USER", der::SEQUENCE, value)?;
    let id = f.raw(0)?;
    let u = Fields::parse_tagged("S4UUserID", der::SEQUENCE, id)?;
    if u.get(0)?.u32()? != reply.nonce {
        return modified("has another nonce");
    }
    let usage = match u.opt(4).map(|mut r| r.flags32()).transpose()? {
        Some(o) if o & S4U_OPTS_USE_REPLY_KEY_USAGE != 0 => KU_S4U_X509_USER_REPLY,
        _ => KU_S4U_X509_USER_REQUEST,
    };
    let c = Fields::parse_tagged("Checksum", der::SEQUENCE, f.raw(1)?)?;
    let (ty, sum) = (c.get(0)?.i32()?, c.get(1)?.octets()?);
    let subkey = reply.subkey.as_ref().expect("S4U2Self always has a subkey");
    // A keyed checksum, ours: anything else proves nothing.
    if ty != subkey.checksum_type() || !subkey.verify_checksum(usage, id, sum)? {
        return modified("checksum does not verify");
    }
    let realm = u.get(2)?.string()?;
    match u.opt(1) {
        Some(name) => {
            let user = Principal::decode_name(name, realm)?;
            if user.components.is_empty() {
                return modified("names no user");
            }
            Ok(user)
        }
        None => modified("names no user"),
    }
}

/// The S4U2Self reply checked whole: its PA-S4U-X509-USER, and its
/// unprotected client name against the one the KDC signed there.
fn check_s4u2self_reply(reply: TgsReply, asked: &Principal) -> Result<Credentials> {
    let named = verify_s4u2self_reply(&reply, asked)?;
    if !same_principal(&reply.creds.client, &named) {
        return protocol(format!(
            "S4U2Self reply is for {}, but the KDC signed {named} (KRB5_KDCREP_MODIFIED)",
            reply.creds.client
        ));
    }
    Ok(reply.creds)
}

impl KdcClient {
    /// S4U2Self (MS-SFU protocol transition, `kvno -U user`): a ticket to
    /// the service `tgt` belongs to, in `user`'s name, from the service's
    /// own TGT and no word from the user. The ticket is forwardable, and
    /// so good as S4U2Proxy evidence, only if the KDC lets the service
    /// delegate (`ok_to_auth_as_delegate`) and the TGT is forwardable.
    ///
    /// The user's name comes back as the KDC canonicalized it, checked
    /// against the KDC's checksummed PA-S4U-X509-USER as MIT checks it.
    /// `user` must be in the service's realm.
    pub fn s4u2self(&self, tgt: &Credentials, user: &Principal) -> Result<Credentials> {
        block_on(self.s4u2self_on(&Blocking, tgt, user))
    }

    pub(crate) async fn s4u2self_on<N: Net>(
        &self,
        net: &N,
        tgt: &Credentials,
        user: &Principal,
    ) -> Result<Credentials> {
        let realm = tgt_realm(tgt).to_string();
        let mut user = user.clone();
        if user.realm.is_empty() {
            user.realm = realm.clone();
        }
        if user.realm != realm || tgt.client.realm != realm {
            return Err(ClientError::Protocol(format!(
                "S4U2Self for {user} through a TGT for {realm}: cross-realm S4U2Self is not supported"
            )));
        }
        let reply = self
            .tgs_ext(
                net,
                &realm,
                tgt,
                &tgt.client,
                KDC_OPT_CANONICALIZE,
                &S4u::User(&user),
            )
            .await?;
        check_s4u2self_reply(reply, &user)
    }

    /// S4U2Proxy (MS-SFU constrained delegation, `kvno -U user -P`): a
    /// ticket to `target` in the name of `evidence`'s client, from the
    /// service's own TGT and a ticket to the service in the user's name
    /// (from [`KdcClient::s4u2self`], or one the user sent). The KDC
    /// decides: traditional constrained delegation (the service's list of
    /// targets, with forwardable evidence) or resource-based (the target's
    /// list of services), which MIT and Windows both offer.
    ///
    /// `target` with an empty realm is in the service's realm. Targets in
    /// other realms (cross-realm RBCD) are not supported.
    pub fn s4u2proxy(
        &self,
        tgt: &Credentials,
        evidence: &Credentials,
        target: &Principal,
    ) -> Result<Credentials> {
        block_on(self.s4u2proxy_on(&Blocking, tgt, evidence, target))
    }

    pub(crate) async fn s4u2proxy_on<N: Net>(
        &self,
        net: &N,
        tgt: &Credentials,
        evidence: &Credentials,
        target: &Principal,
    ) -> Result<Credentials> {
        let realm = tgt_realm(tgt).to_string();
        let mut target = target.clone();
        if target.realm.is_empty() {
            target.realm = realm.clone();
        }
        let reply = self
            .tgs_ext(
                net,
                &realm,
                tgt,
                &target,
                KDC_OPT_CNAME_IN_ADDL_TKT | KDC_OPT_CANONICALIZE,
                &S4u::Proxy { evidence },
            )
            .await?;
        let got = &reply.creds.server;
        if !(got.components == target.components && got.name_type == target.name_type
            || same_principal(got, &target))
        {
            if is_tgs(got) {
                return Err(ClientError::Protocol(format!(
                    "the KDC referred S4U2Proxy for {target} to another realm ({got}): \
                     cross-realm S4U2Proxy is not supported"
                )));
            }
            return protocol(format!(
                "S4U2Proxy for {target} gave a ticket for {got} (KRB5KRB_AP_WRONG_PRINC)"
            ));
        }
        Ok(reply.creds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-SFU's PA-FOR-USER checksum over MIT's layout: HMAC-MD5 with the
    /// session key's raw octets, whatever its enctype.
    #[test]
    fn pa_for_user_is_mits_layout() {
        let user = Principal::parse("user@R").unwrap();
        let key = Key::new(18, vec![3; 32]).unwrap();
        let tgt = Credentials {
            client: Principal::parse("svc@R").unwrap(),
            server: Principal::krbtgt("R"),
            session_key: key.clone(),
            ticket: vec![],
            ticket_enctype: 18,
            flags: 0,
            authtime: 0,
            starttime: None,
            endtime: 0,
            renew_till: None,
        };
        let sub = Key::new(18, vec![4; 32]).unwrap();
        let pa = request_padata(&S4u::User(&user), &tgt, 7, Some(&sub)).unwrap();
        assert_eq!(
            pa.iter().map(|p| p.0).collect::<Vec<_>>(),
            [PA_S4U_X509_USER, PA_FOR_USER]
        );
        let f = Fields::parse_tagged("PA-FOR-USER", der::SEQUENCE, &pa[1].1).unwrap();
        assert_eq!(f.get(3).unwrap().string().unwrap(), "Kerberos");
        let c = Fields::parse_tagged("Checksum", der::SEQUENCE, f.raw(2).unwrap()).unwrap();
        assert_eq!(c.get(0).unwrap().i32().unwrap(), -138);
        let mut data = 1u32.to_le_bytes().to_vec();
        data.extend_from_slice(b"userRKerberos");
        assert_eq!(
            c.get(1).unwrap().octets().unwrap(),
            crate::md5::hmac_md5_checksum(&[3; 32], 17, &data)
        );
        // PA-S4U-X509-USER: our nonce, the reply-key-usage option, and a
        // checksum the subkey verifies.
        let x = Fields::parse_tagged("PA-S4U-X509-USER", der::SEQUENCE, &pa[0].1).unwrap();
        let id = x.raw(0).unwrap();
        let u = Fields::parse_tagged("S4UUserID", der::SEQUENCE, id).unwrap();
        assert_eq!(u.get(0).unwrap().u32().unwrap(), 7);
        assert_eq!(
            u.get(4).unwrap().flags32().unwrap(),
            S4U_OPTS_USE_REPLY_KEY_USAGE
        );
        let c = Fields::parse_tagged("Checksum", der::SEQUENCE, x.raw(1).unwrap()).unwrap();
        assert!(
            sub.verify_checksum(26, id, c.get(1).unwrap().octets().unwrap())
                .unwrap()
        );
    }

    /// The reply check: our nonce, our subkey's checksum, the user named.
    #[test]
    fn the_s4u2self_reply_must_carry_our_nonce_and_checksum() {
        let user = Principal::parse("user@R").unwrap();
        let sub = Key::new(18, vec![4; 32]).unwrap();
        let reply_with = |nonce: u32, usage: u32, key: &Key, name: &Principal| {
            let id = s4u_user_id(name, nonce);
            let sum = key.checksum(usage, &id).unwrap();
            let pa = der::seq(&[der::field(0, id), der::field(1, checksum(16, &sum))]);
            TgsReply {
                creds: Credentials {
                    client: user.clone(),
                    server: user.clone(),
                    session_key: sub.clone(),
                    ticket: vec![],
                    ticket_enctype: 18,
                    flags: 0,
                    authtime: 0,
                    starttime: None,
                    endtime: 0,
                    renew_till: None,
                },
                padata: vec![(PA_S4U_X509_USER, pa)],
                subkey: Some(sub.clone()),
                nonce: 9,
            }
        };
        let canon = Principal::parse("User@R").unwrap();
        assert_eq!(
            verify_s4u2self_reply(&reply_with(9, 27, &sub, &canon), &user).unwrap(),
            canon
        );
        // The ticket must be for the user the KDC signed for.
        assert!(check_s4u2self_reply(reply_with(9, 27, &sub, &user), &user).is_ok());
        let e = check_s4u2self_reply(reply_with(9, 27, &sub, &canon), &user)
            .unwrap_err()
            .to_string();
        assert!(e.contains("KDC signed User@R"), "{e}");
        let other = Key::new(18, vec![5; 32]).unwrap();
        for bad in [
            reply_with(8, 27, &sub, &user),
            reply_with(9, 26, &sub, &user),
            reply_with(9, 27, &other, &user),
        ] {
            let e = verify_s4u2self_reply(&bad, &user).unwrap_err().to_string();
            assert!(e.contains("KDCREP_MODIFIED"), "{e}");
        }
    }
}
