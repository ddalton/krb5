//! Entry points for the fuzz targets in `fuzz/` (`cfg(fuzzing)` only):
//! what a KDC, or anyone answering in its place, sends a client.

use super::*;

fn key() -> Key {
    Key::new(18, vec![5; 32]).expect("a 32-octet AES-256 key")
}

/// The first octet picks a parser for the rest.
pub fn kdc_message(data: &[u8]) {
    let Some((&sel, d)) = data.split_first() else {
        return;
    };
    match sel % 10 {
        // A KDC-REP or KRB-ERROR, as the transport hands it over.
        0 | 1 => {
            let app_tag = if sel % 10 == 0 { 11 } else { 13 };
            match parse_reply(d, app_tag) {
                Ok(Reply::Rep(rep)) => {
                    let _ = choose_salt(&rep.padata, &[17, 18, 19, 20]);
                    let _ = fast::cookie(&rep.padata);
                }
                Ok(Reply::Error(e)) => {
                    let _ = e.method_data().map(|m| choose_salt(&m, &[18]));
                    let _ = e.into_error();
                }
                Err(_) => {}
            }
        }
        // The decrypted EncKDCRepPart, against a minimal reply.
        2 => {
            let rep = KdcRep {
                padata: Vec::new(),
                client: Principal::new(1, ["a"], "R"),
                ticket: Vec::new(),
                ticket_server: Principal::krbtgt("R"),
                ticket_enctype: 18,
                enc_etype: 18,
                cipher: Vec::new(),
            };
            if let Ok(c) = rep.into_credentials(d, 0x0102_0304) {
                let _ = c.ticket_server();
                let _ = crate::ccache::Entry::from_credentials(&c);
            }
            let _ = verify_enc_pa_rep(d, &key(), b"request");
        }
        // The decrypted KrbFastResponse.
        3 => fast::fuzz_response(d),
        // A KRB-CRED (delegation), its part in plaintext or a known key.
        4 => {
            let _ = krbcred::decode(d, &[&key()]);
            if let Ok(cipher) = key().encrypt(14, d) {
                let wrapped = der::cons(
                    app(22),
                    &[der::seq(&[
                        der::field(0, der::int(5)),
                        der::field(1, der::int(22)),
                        der::field(2, der::seq(&[der::cons(app(1), &[der::seq(&[])])])),
                        der::field(3, encode_encrypted_data(18, &cipher)),
                    ])],
                );
                let _ = krbcred::decode(&wrapped, &[&key()]);
            }
        }
        5 => {
            if let Ok((nonce, ch)) = otp::parse_challenge(d) {
                let _ = otp::answer_with(&ch, "123456")
                    .and_then(|a| otp::request(&nonce, &ch, &a, &key()));
            }
        }
        6 => {
            let _ = spake::parse_challenge(d);
            let mut s = spake::Spake::default();
            if s.step(&[spake::SpakeGroup::Edwards25519], d, key()).is_ok() {
                let _ = s.respond(b"body");
            }
        }
        7 => {
            let _ = KrbError::parse(d).map(|e| e.method_data());
        }
        8 => {
            let _ = u2u::ticket_server(d);
            let _ = ticket_enctype_of(d);
        }
        _ => {
            let _ = parse_pa_data(Reader::new(d));
            let _ = Principal::decode_name(Reader::new(d), "R".into());
        }
    }
}

fn ticket_enctype_of(ticket: &[u8]) -> Option<i32> {
    let f = Fields::parse_tagged("Ticket", app(1), ticket).ok()?;
    decode_encrypted_data(f.get(3).ok()?).ok().map(|(e, _)| e)
}

/// Text a user or a file gives: principal names, cache names, krb5.conf.
pub fn text(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Principal::parse(s);
    let _ = Principal::parse_in_realm(s, "R");
    let _ = crate::CacheName::parse(s);
    if let Ok(conf) = crate::Krb5Conf::parse(s) {
        let _ = conf.client_defaults("R");
        let _ = conf.default_realm();
        let _ = spake::SpakeGroup::parse_list(s);
    }
}
