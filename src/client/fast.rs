//! FAST (RFC 6113): an armored channel for the AS exchange, as MIT's
//! `fast.c` builds it.
//!
//! The armor is an AP-REQ for a TGT the client already holds (`kinit -T`
//! in MIT's terms: a host's TGT from its keytab, say), with a fresh
//! subkey; both ends derive the **armor key**
//! `KRB-FX-CF2(subkey, "subkeyarmor", TGT session key, "ticketarmor")`.
//! The real request body and pre-authentication go inside a `KrbFastReq`
//! encrypted in it, under an outer request whose only PA-DATA is
//! `PA-FX-FAST` and whose body is checksummed with it. Replies and errors
//! come back the same way: the real PA-DATA (and, for an error, the real
//! KRB-ERROR as `PA-FX-ERROR`) inside an encrypted `KrbFastResponse`,
//! whose nonce must be the request's and whose `finished` part carries a
//! checksum over the ticket and the authoritative client name.
//!
//! Under FAST the pre-authentication is the **encrypted challenge**
//! (RFC 6113 §5.4.6) rather than the encrypted timestamp: the timestamp is
//! sealed in `KRB-FX-CF2(armor key, "clientchallengearmor", long-term key,
//! "challengelongterm")`, and the KDC proves it knows the long-term key
//! too by returning one sealed in the "kdcchallengearmor" key. A
//! `strengthen-key` in the reply turns the reply key into
//! `KRB-FX-CF2(strengthen key, "strengthenkey", reply key, "replykey")`.

use super::{
    Credentials, PA_FX_COOKIE, Principal, Result, decode_encrypted_data, decode_key, encode_ap_req,
    encode_authenticator, encode_encrypted_data, parse_pa_data, protocol,
};
use crate::der::{self, Fields, Reader};
use crate::key::Key;

pub(crate) const PA_FX_FAST: i32 = 136;
pub(crate) const PA_FX_ERROR: i32 = 137;
pub(crate) const PA_ENCRYPTED_CHALLENGE: i32 = 138;

// RFC 6113 key usages.
const KU_AP_REQ_AUTH: u32 = 11;
const KU_FAST_REQ_CHKSUM: u32 = 50;
const KU_FAST_ENC: u32 = 51;
const KU_FAST_REP: u32 = 52;
const KU_FAST_FINISHED: u32 = 53;
const KU_ENC_CHALLENGE_CLIENT: u32 = 54;
const KU_ENC_CHALLENGE_KDC: u32 = 55;

/// FX_FAST_ARMOR_AP_REQUEST.
const ARMOR_AP_REQUEST: i64 = 1;

/// One request's armor: the `KrbFastArmor` to send (none for a TGS
/// request, whose armor is implicit) and the armor key.
pub(crate) struct Armor {
    armor: Option<Vec<u8>>,
    pub(crate) key: Key,
}

/// The decrypted `KrbFastResponse`.
pub(crate) struct FastResponse {
    pub(crate) padata: Vec<(i32, Vec<u8>)>,
    pub(crate) strengthen_key: Option<Key>,
    finished: Option<Finished>,
}

impl Armor {
    /// MIT's `fast_armor_ap_request`: an AP-REQ for `tgt` with a fresh
    /// subkey of its session key's enctype and no checksum.
    pub(crate) fn from_tgt(tgt: &Credentials, now: i64, usec: u32) -> Result<Self> {
        let subkey = Key::random(tgt.session_key.enctype())?;
        let authenticator = encode_authenticator(&tgt.client, None, usec, now, Some(&subkey), None);
        let enc = tgt.session_key.encrypt(KU_AP_REQ_AUTH, &authenticator)?;
        let ap_req = encode_ap_req(0, &tgt.ticket, tgt.session_key.enctype(), &enc);
        let key = Key::cf2(&subkey, "subkeyarmor", &tgt.session_key, "ticketarmor")?;
        let armor = der::seq(&[
            der::field(0, der::int(ARMOR_AP_REQUEST)),
            der::field(1, der::octets(&ap_req)),
        ]);
        Ok(Armor {
            armor: Some(armor),
            key,
        })
    }

    /// A TGS request's implicit armor (MIT `krb5int_fast_tgs_armor` with no
    /// armor cache): no armor field, and the armor key
    /// `KRB-FX-CF2(subkey, "subkeyarmor", TGT session key, "ticketarmor")`,
    /// the subkey being the one in the TGS authenticator.
    pub(crate) fn implicit(subkey: &Key, tgt_session_key: &Key) -> Result<Self> {
        Ok(Armor {
            armor: None,
            key: Key::cf2(subkey, "subkeyarmor", tgt_session_key, "ticketarmor")?,
        })
    }

    /// `PA-FX-FAST` carrying the real PA-DATA and `body` (the
    /// KDC-REQ-BODY, also sent outside) encrypted in the armor key, with
    /// `checksummed` checksummed in it: the outer body for an AS request,
    /// the PA-TGS-REQ AP-REQ for a TGS request (MIT `krb5int_fast_prep_req`).
    pub(crate) fn wrap(
        &self,
        checksummed: &[u8],
        body: &[u8],
        padata: &[(i32, Vec<u8>)],
    ) -> Result<(i32, Vec<u8>)> {
        let inner_padata = der::seq(
            &padata
                .iter()
                .map(|(t, v)| {
                    der::seq(&[
                        der::field(1, der::int(i64::from(*t))),
                        der::field(2, der::octets(v)),
                    ])
                })
                .collect::<Vec<_>>(),
        );
        let fast_req = der::seq(&[
            der::field(0, der::flags32(0)),
            der::field(1, inner_padata),
            der::field(2, body.to_vec()),
        ]);
        let cksum = der::seq(&[
            der::field(0, der::int(i64::from(self.key.checksum_type()))),
            der::field(
                1,
                der::octets(&self.key.checksum(KU_FAST_REQ_CHKSUM, checksummed)?),
            ),
        ]);
        let enc = self.key.encrypt(KU_FAST_ENC, &fast_req)?;
        let mut armored = Vec::new();
        if let Some(a) = &self.armor {
            armored.push(der::field(0, a.clone()));
        }
        armored.push(der::field(1, cksum));
        armored.push(der::field(
            2,
            encode_encrypted_data(self.key.enctype(), &enc),
        ));
        let armored = der::seq(&armored);
        Ok((PA_FX_FAST, der::field(0, armored)))
    }

    /// Decrypt the `KrbFastResponse` in a reply's (or an error's) PA-DATA
    /// and check its nonce (MIT `decrypt_fast_reply`).
    pub(crate) fn open(&self, padata: &[(i32, Vec<u8>)], nonce: u32) -> Result<FastResponse> {
        let Some((_, fx)) = padata.iter().find(|(t, _)| *t == PA_FX_FAST) else {
            return protocol(
                "asked for FAST, but the KDC's reply has no PA-FX-FAST (KRB5_ERR_FAST_REQUIRED)",
            );
        };
        // PA-FX-FAST-REPLY ::= [0] KrbFastArmoredRep ::= SEQUENCE { enc-fast-rep [0] }
        let inner = Reader::new(fx).expect(der::ctx(0))?;
        let armored = Fields::parse_tagged("KrbFastArmoredRep", der::SEQUENCE, inner)?;
        let (etype, cipher) = decode_encrypted_data(armored.get(0)?)?;
        if etype != self.key.enctype() {
            return protocol("FAST reply is not in the armor key's enctype");
        }
        let plain = self.key.decrypt(KU_FAST_REP, &cipher)?;
        let f = Fields::parse_tagged("KrbFastResponse", der::SEQUENCE, &plain)?;
        if f.get(3)?.u32()? != nonce {
            return protocol("nonce modified in FAST response (KRB5_KDCREP_MODIFIED)");
        }
        let finished = match f.opt(2) {
            None => None,
            Some(_) => Some(Finished::parse(f.raw(2)?)?),
        };
        Ok(FastResponse {
            padata: parse_pa_data(f.get(0)?.seq()?)?,
            strengthen_key: f.opt(1).map(decode_key).transpose()?,
            finished,
        })
    }

    /// A final reply's `finished` part must be there, and its checksum
    /// must cover `ticket`; it names the client (MIT
    /// `krb5int_fast_process_response`).
    pub(crate) fn check_finished(&self, r: &FastResponse, ticket: &[u8]) -> Result<Principal> {
        let Some(fin) = &r.finished else {
            return protocol(
                "FAST response missing finish message in KDC reply (KRB5_KDCREP_MODIFIED)",
            );
        };
        if fin.cksumtype != self.key.checksum_type()
            || !self
                .key
                .verify_checksum(KU_FAST_FINISHED, ticket, &fin.checksum)?
        {
            return protocol("ticket modified in KDC reply (KRB5_KDCREP_MODIFIED)");
        }
        Ok(fin.client.clone())
    }

    /// The PA-ENCRYPTED-CHALLENGE value: the timestamp sealed in the client
    /// challenge key (MIT `ec_process`, sending side).
    pub(crate) fn client_challenge(
        &self,
        long_term: &Key,
        time: i64,
        usec: u32,
    ) -> Result<Vec<u8>> {
        let key = Key::cf2(
            &self.key,
            "clientchallengearmor",
            long_term,
            "challengelongterm",
        )?;
        let ts = der::seq(&[
            der::field(0, der::time(time)),
            der::field(1, der::int(i64::from(usec))),
        ]);
        let cipher = key.encrypt(KU_ENC_CHALLENGE_CLIENT, &ts)?;
        Ok(encode_encrypted_data(key.enctype(), &cipher))
    }

    /// The KDC's PA-ENCRYPTED-CHALLENGE must decrypt in the KDC challenge
    /// key: proof that the KDC knows the long-term key (MIT `ec_process`,
    /// receiving side, which likewise checks only that it decrypts).
    pub(crate) fn verify_kdc_challenge(&self, long_term: &Key, value: &[u8]) -> Result<()> {
        let key = Key::cf2(
            &self.key,
            "kdcchallengearmor",
            long_term,
            "challengelongterm",
        )?;
        let (etype, cipher) = decode_encrypted_data(Reader::new(value))?;
        if etype != key.enctype() {
            return protocol("KDC encrypted challenge in an unexpected enctype");
        }
        let plain = key.decrypt(KU_ENC_CHALLENGE_KDC, &cipher).map_err(|_| {
            super::ClientError::Protocol(
                "KDC encrypted challenge does not decrypt: not the real KDC".into(),
            )
        })?;
        Fields::parse_tagged("PA-ENC-TS-ENC", der::SEQUENCE, &plain)?
            .get(0)?
            .time()?;
        Ok(())
    }
}

/// `KrbFastFinished ::= SEQUENCE { timestamp [0], usec [1], crealm [2],
/// cname [3], ticket-checksum [4] Checksum }`
struct Finished {
    client: Principal,
    cksumtype: i32,
    checksum: Vec<u8>,
}

impl Finished {
    fn parse(tlv: &[u8]) -> Result<Self> {
        let f = Fields::parse_tagged("KrbFastFinished", der::SEQUENCE, tlv)?;
        let client = Principal::decode_name(f.get(3)?, f.get(2)?.string()?)?;
        let ck = Fields::parse_tagged("Checksum", der::SEQUENCE, f.raw(4)?)?;
        Ok(Finished {
            client,
            cksumtype: ck.get(0)?.i32()?,
            checksum: ck.get(1)?.octets()?.to_vec(),
        })
    }
}

/// The cookie to echo from a FAST error's PA-DATA, if any.
pub(crate) fn cookie(padata: &[(i32, Vec<u8>)]) -> Option<(i32, Vec<u8>)> {
    padata.iter().find(|(t, _)| *t == PA_FX_COOKIE).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::encode_key;

    fn armor() -> Armor {
        Armor::implicit(&Key::random(18).unwrap(), &Key::random(18).unwrap()).unwrap()
    }

    /// A KDC's PA-FX-FAST reply, built the way MIT's KDC builds it.
    fn reply(
        a: &Armor,
        nonce: u32,
        ticket: Option<&[u8]>,
        strengthen: Option<&Key>,
    ) -> Vec<(i32, Vec<u8>)> {
        let mut f = vec![der::field(
            0,
            der::seq(&[der::seq(&[
                der::field(1, der::int(PA_FX_COOKIE as i64)),
                der::field(2, der::octets(b"cookie")),
            ])]),
        )];
        if let Some(k) = strengthen {
            f.push(der::field(1, encode_key(k)));
        }
        if let Some(t) = ticket {
            let ck = a.key.checksum(KU_FAST_FINISHED, t).unwrap();
            f.push(der::field(
                2,
                der::seq(&[
                    der::field(0, der::time(1_800_000_000)),
                    der::field(1, der::int(0)),
                    der::field(2, der::general_string("A.ORG")),
                    der::field(3, Principal::new(1, ["alice"], "A.ORG").encode_name()),
                    der::field(
                        4,
                        der::seq(&[
                            der::field(0, der::int(i64::from(a.key.checksum_type()))),
                            der::field(1, der::octets(&ck)),
                        ]),
                    ),
                ]),
            ));
        }
        f.push(der::field(3, der::int(i64::from(nonce))));
        let enc = a.key.encrypt(KU_FAST_REP, &der::seq(&f)).unwrap();
        let rep = der::seq(&[der::field(0, encode_encrypted_data(a.key.enctype(), &enc))]);
        vec![(PA_FX_FAST, der::field(0, rep))]
    }

    #[test]
    fn a_request_wraps_padata_and_body_under_the_armor_key() {
        let a = armor();
        let (t, v) = a
            .wrap(b"ap-req", b"\x30\x00", &[(PA_FX_COOKIE, b"c".to_vec())])
            .unwrap();
        assert_eq!(t, PA_FX_FAST);
        let inner = Reader::new(&v).expect(der::ctx(0)).unwrap();
        let f = Fields::parse_tagged("KrbFastArmoredReq", der::SEQUENCE, inner).unwrap();
        assert!(f.opt(0).is_none(), "implicit armor: no armor field");
        let ck = Fields::parse_tagged("Checksum", der::SEQUENCE, f.raw(1).unwrap()).unwrap();
        let sum = ck.get(1).unwrap().octets().unwrap().to_vec();
        assert!(
            a.key
                .verify_checksum(KU_FAST_REQ_CHKSUM, b"ap-req", &sum)
                .unwrap()
        );
        let (_, cipher) = decode_encrypted_data(f.get(2).unwrap()).unwrap();
        let req = a.key.decrypt(KU_FAST_ENC, &cipher).unwrap();
        let r = Fields::parse_tagged("KrbFastReq", der::SEQUENCE, &req).unwrap();
        let pa = parse_pa_data(r.get(1).unwrap().seq().unwrap()).unwrap();
        assert_eq!(pa, [(PA_FX_COOKIE, b"c".to_vec())]);
        assert_eq!(r.raw(2).unwrap(), b"\x30\x00");
    }

    #[test]
    fn replies_are_opened_and_checked() {
        let a = armor();
        let st = Key::random(18).unwrap();
        let r = a
            .open(&reply(&a, 7, Some(b"TICKET"), Some(&st)), 7)
            .unwrap();
        assert_eq!(r.padata, [(PA_FX_COOKIE, b"cookie".to_vec())]);
        assert_eq!(r.strengthen_key, Some(st));
        assert_eq!(
            a.check_finished(&r, b"TICKET").unwrap().to_string(),
            "alice@A.ORG"
        );
        // Another ticket than the one the KDC checksummed.
        assert!(a.check_finished(&r, b"OTHER").is_err());
        // No finished message in a final reply.
        let r = a.open(&reply(&a, 7, None, None), 7).unwrap();
        assert!(a.check_finished(&r, b"TICKET").is_err());
        // The wrong nonce, the wrong armor key, no PA-FX-FAST at all.
        assert!(a.open(&reply(&a, 8, None, None), 7).is_err());
        assert!(armor().open(&reply(&a, 7, None, None), 7).is_err());
        assert!(a.open(&[(2, vec![])], 7).is_err());
    }

    #[test]
    fn the_challenges_use_their_own_keys() {
        let a = armor();
        let long_term = Key::random(18).unwrap();
        // The client's challenge decrypts only in the client challenge key.
        let v = a.client_challenge(&long_term, 1_800_000_000, 5).unwrap();
        let (_, cipher) = decode_encrypted_data(Reader::new(&v)).unwrap();
        let ck = Key::cf2(
            &a.key,
            "clientchallengearmor",
            &long_term,
            "challengelongterm",
        )
        .unwrap();
        assert!(ck.decrypt(KU_ENC_CHALLENGE_CLIENT, &cipher).is_ok());
        // ...so it is not a valid KDC challenge.
        assert!(a.verify_kdc_challenge(&long_term, &v).is_err());
        // A KDC challenge made the KDC's way verifies; with another key, no.
        let kk = Key::cf2(&a.key, "kdcchallengearmor", &long_term, "challengelongterm").unwrap();
        let ts = der::seq(&[
            der::field(0, der::time(1_800_000_000)),
            der::field(1, der::int(0)),
        ]);
        let kdc = encode_encrypted_data(18, &kk.encrypt(KU_ENC_CHALLENGE_KDC, &ts).unwrap());
        a.verify_kdc_challenge(&long_term, &kdc).unwrap();
        assert!(
            a.verify_kdc_challenge(&Key::random(18).unwrap(), &kdc)
                .is_err()
        );
    }
}
