//! KRB-CRED (RFC 4120 §5.8): credentials sent to a peer, here a
//! delegated TGT inside the GSS-API authenticator checksum (RFC 4121
//! §4.1.1).
//!
//! ```text
//! KRB-CRED      ::= [APPLICATION 22] SEQUENCE {
//!     pvno [0] 5, msg-type [1] 22,
//!     tickets [2] SEQUENCE OF Ticket,
//!     enc-part [3] EncryptedData }            -- EncKrbCredPart, usage 14
//! EncKrbCredPart ::= [APPLICATION 29] SEQUENCE {
//!     ticket-info [0] SEQUENCE OF KrbCredInfo,
//!     nonce [1] OPTIONAL, timestamp [2] OPTIONAL, usec [3] OPTIONAL, ... }
//! KrbCredInfo   ::= SEQUENCE {
//!     key [0], prealm [1], pname [2], flags [3], authtime [4],
//!     starttime [5], endtime [6], renew-till [7], srealm [8], sname [9],
//!     caddr [10] }                            -- all but key OPTIONAL
//! ```

use super::{
    Credentials, Principal, Result, decode_encrypted_data, decode_key, encode_encrypted_data,
    encode_key, protocol,
};
use crate::der::{self, Fields, app};
use crate::key::Key;

/// RFC 4120 §7.5.1: KRB-CRED's encrypted part.
pub(crate) const KU_KRB_CRED_ENCPART: u32 = 14;

/// A KRB-CRED carrying `creds`, its encrypted part sealed with `key` as MIT's
/// `krb5_mk_1cred` seals it (with a timestamp, no nonce, no addresses).
pub(crate) fn encode(creds: &Credentials, key: &Key, now: i64, usec: u32) -> Result<Vec<u8>> {
    let mut info = vec![
        der::field(0, encode_key(&creds.session_key)),
        der::field(1, der::general_string(&creds.client.realm)),
        der::field(2, creds.client.encode_name()),
        der::field(3, der::flags32(creds.flags)),
        der::field(4, der::time(creds.authtime)),
    ];
    if let Some(t) = creds.starttime {
        info.push(der::field(5, der::time(t)));
    }
    info.push(der::field(6, der::time(creds.endtime)));
    if let Some(t) = creds.renew_till {
        info.push(der::field(7, der::time(t)));
    }
    info.push(der::field(8, der::general_string(&creds.server.realm)));
    info.push(der::field(9, creds.server.encode_name()));

    let enc_part = der::cons(
        app(29),
        &[der::seq(&[
            der::field(0, der::seq(&[der::seq(&info)])),
            der::field(2, der::time(now)),
            der::field(3, der::int(i64::from(usec))),
        ])],
    );
    let cipher = key.encrypt(KU_KRB_CRED_ENCPART, &enc_part)?;
    Ok(der::cons(
        app(22),
        &[der::seq(&[
            der::field(0, der::int(5)),
            der::field(1, der::int(22)),
            der::field(2, der::seq(std::slice::from_ref(&creds.ticket))),
            der::field(3, encode_encrypted_data(key.enctype(), &cipher)),
        ])],
    ))
}

/// The first credential in a KRB-CRED. The encrypted part is tried with
/// each of `keys`, then, if it says enctype 0, as plaintext (RFC 6448),
/// as MIT's acceptor tries them.
pub(crate) fn decode(msg: &[u8], keys: &[&Key]) -> Result<Credentials> {
    let f = Fields::parse_tagged("KRB-CRED", app(22), msg)?;
    if f.get(0)?.int()? != 5 || f.get(1)?.int()? != 22 {
        return protocol("KRB-CRED pvno/msg-type mismatch");
    }
    let mut tickets = f.get(2)?.seq()?;
    let (tag, content) = tickets.next()?;
    if tag != app(1) {
        return protocol("KRB-CRED ticket is not a Ticket");
    }
    let ticket = der::tlv(tag, content);
    let ticket_enctype = {
        let tf = Fields::parse_tagged("Ticket", app(1), &ticket)?;
        decode_encrypted_data(tf.get(3)?)?.0
    };

    let (etype, cipher) = decode_encrypted_data(f.get(3)?)?;
    let plain = if etype == 0 {
        cipher
    } else {
        keys.iter()
            .filter(|k| k.enctype() == etype)
            .find_map(|k| k.decrypt(KU_KRB_CRED_ENCPART, &cipher).ok())
            .ok_or_else(|| {
                super::ClientError::Protocol(
                    "KRB-CRED does not decrypt with the session key or subkey".into(),
                )
            })?
    };

    let ef = Fields::parse_tagged("EncKrbCredPart", app(29), &plain)?;
    let mut infos = ef.get(0)?.seq()?;
    let info = Fields::parse("KrbCredInfo", infos.expect(der::SEQUENCE)?)?;
    let realm = |n| info.get(n).and_then(|mut r| r.string());
    let opt_time = |n| info.opt(n).map(|mut r| r.time()).transpose();
    Ok(Credentials {
        client: Principal::decode_name(info.get(2)?, realm(1)?)?,
        server: Principal::decode_name(info.get(9)?, realm(8)?)?,
        session_key: decode_key(info.get(0)?)?,
        ticket,
        ticket_enctype,
        flags: info
            .opt(3)
            .map(|mut r| r.flags32())
            .transpose()?
            .unwrap_or(0),
        authtime: opt_time(4)?.unwrap_or(0),
        starttime: opt_time(5)?,
        endtime: info.get(6)?.time()?,
        renew_till: opt_time(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials {
            client: Principal::new(1, ["alice"], "A.ORG"),
            server: Principal::krbtgt("A.ORG"),
            session_key: Key::random(20).unwrap(),
            // A minimal Ticket: [APPLICATION 1] { vno 5, realm, sname, enc-part(etype 18) }
            ticket: der::cons(
                app(1),
                &[der::seq(&[
                    der::field(0, der::int(5)),
                    der::field(1, der::general_string("A.ORG")),
                    der::field(2, Principal::krbtgt("A.ORG").encode_name()),
                    der::field(3, encode_encrypted_data(18, b"opaque")),
                ])],
            ),
            ticket_enctype: 18,
            flags: (1 << 30) | (1 << 29),
            authtime: 1_800_000_000,
            starttime: Some(1_800_000_000),
            endtime: 1_800_086_400,
            renew_till: Some(1_800_600_000),
        }
    }

    fn same(a: &Credentials, b: &Credentials) {
        assert_eq!(a.client, b.client);
        assert_eq!(a.server, b.server);
        assert_eq!(a.session_key, b.session_key);
        assert_eq!(a.ticket, b.ticket);
        assert_eq!(a.ticket_enctype, b.ticket_enctype);
        assert_eq!(
            (a.flags, a.authtime, a.starttime, a.endtime, a.renew_till),
            (b.flags, b.authtime, b.starttime, b.endtime, b.renew_till)
        );
    }

    #[test]
    fn a_krb_cred_round_trips_under_its_key() {
        let c = creds();
        let key = Key::random(18).unwrap();
        let msg = encode(&c, &key, 1_800_000_100, 7).unwrap();
        same(&decode(&msg, &[&key]).unwrap(), &c);
        // The right key among others; the wrong one alone fails.
        let other = Key::random(18).unwrap();
        same(&decode(&msg, &[&other, &key]).unwrap(), &c);
        assert!(decode(&msg, &[&other]).is_err());
        assert!(decode(&msg, &[]).is_err());
    }

    #[test]
    fn an_unencrypted_krb_cred_is_read_as_mit_reads_it() {
        // RFC 6448: etype 0, the EncKrbCredPart in the clear. Build one by
        // re-wrapping the plaintext of an encrypted one.
        let c = creds();
        let key = Key::random(18).unwrap();
        let msg = encode(&c, &key, 0, 0).unwrap();
        let f = Fields::parse_tagged("KRB-CRED", app(22), &msg).unwrap();
        let (_, cipher) = decode_encrypted_data(f.get(3).unwrap()).unwrap();
        let plain = key.decrypt(KU_KRB_CRED_ENCPART, &cipher).unwrap();
        let clear = der::cons(
            app(22),
            &[der::seq(&[
                der::field(0, der::int(5)),
                der::field(1, der::int(22)),
                der::field(2, der::seq(std::slice::from_ref(&c.ticket))),
                der::field(3, encode_encrypted_data(0, &plain)),
            ])],
        );
        same(&decode(&clear, &[]).unwrap(), &c);
    }

    #[test]
    fn a_malformed_krb_cred_is_refused() {
        let c = creds();
        let key = Key::random(18).unwrap();
        let msg = encode(&c, &key, 0, 0).unwrap();
        for cut in [0, 1, 10, msg.len() / 2, msg.len() - 1] {
            assert!(decode(&msg[..cut], &[&key]).is_err(), "cut {cut}");
        }
        let mut wrong = msg.clone();
        wrong[0] = app(21); // not KRB-CRED
        assert!(decode(&wrong, &[&key]).is_err());
    }
}
