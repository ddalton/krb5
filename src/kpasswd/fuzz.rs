//! Entry point for `fuzz/` (`cfg(fuzzing)` only): what a kpasswd server
//! sends.

use super::*;

fn key() -> Key {
    Key::new(18, vec![8; 32]).expect("AES-256 key")
}

/// The first octet picks: the whole reply, its KRB-PRIV as sent, or the
/// KRB-PRIV's decrypted part.
pub fn reply(data: &[u8]) {
    let Some((&sel, d)) = data.split_first() else {
        return;
    };
    match sel % 3 {
        0 => {
            let ticket = Credentials {
                client: Principal::new(1, ["a"], "R"),
                server: changepw_service("R"),
                session_key: key(),
                ticket: Vec::new(),
                ticket_enctype: 18,
                flags: 0,
                authtime: 0,
                starttime: None,
                endtime: 0,
                renew_till: None,
            };
            if let Ok(r) = read_reply(&ticket, &key(), d, 0, 0) {
                let _ = describe(&r);
            }
        }
        1 => {
            let _ = rd_priv(&key(), d);
        }
        _ => {
            if let Ok(cipher) = key().encrypt(KU_KRB_PRIV, d) {
                let m = der::cons(
                    app(21),
                    &[der::seq(&[
                        der::field(0, der::int(5)),
                        der::field(1, der::int(21)),
                        der::field(3, encode_encrypted_data(18, &cipher)),
                    ])],
                );
                if let Ok(r) = rd_priv(&key(), &m) {
                    let _ = describe(&r);
                }
            }
        }
    }
}
