//! Entry points for `fuzz/` (`cfg(fuzzing)` only): SPNEGO tokens as each
//! side receives them, and the per-message tokens after a context.

use super::*;
use crate::acceptor::{EncType, ServiceKey};
use crate::initiator::GSS_C_MUTUAL_FLAG;
use crate::key::Key;
use crate::token::{ContextKey, PerMessageTokens, Role};

fn creds() -> Credentials {
    Credentials {
        client: crate::Principal::new(1, ["alice"], "FUZZ.EXAMPLE"),
        server: crate::Principal::new(3, ["host", "fuzz.example"], "FUZZ.EXAMPLE"),
        session_key: Key::new(18, vec![3; 32]).expect("AES-256 key"),
        ticket: crate::der::cons(0x61, &[crate::der::seq(&[])]),
        ticket_enctype: 18,
        flags: 0,
        authtime: 0,
        starttime: None,
        endtime: i64::MAX,
        renew_till: None,
    }
}

/// The first octet picks the side; the rest is split into up to three
/// tokens at 0xFF 0xFF markers, fed in turn.
pub fn tokens(data: &[u8]) {
    let Some((&sel, d)) = data.split_first() else {
        return;
    };
    let mut toks: Vec<&[u8]> = Vec::new();
    let mut rest = d;
    while let Some(i) = rest.windows(2).position(|w| w == [0xFF, 0xFF]) {
        toks.push(&rest[..i]);
        rest = &rest[i + 2..];
    }
    toks.push(rest);
    match sel % 4 {
        0 => {
            let kt = Keytab::from_keys(vec![ServiceKey {
                principal: "host/fuzz.example".into(),
                realm: "FUZZ.EXAMPLE".into(),
                kvno: 1,
                enctype: EncType::AES256CtsHmacSha196,
                key: vec![7; 32],
            }]);
            let mut acc = SpnegoAcceptor::new(&kt);
            for t in toks {
                if acc.step(t).is_err() {
                    break;
                }
            }
        }
        1 => {
            if let Ok((mut ini, _)) =
                SpnegoInitiator::new(&creds(), GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG)
            {
                for &t in &toks {
                    if ini.step(t).is_err() {
                        break;
                    }
                }
            }
            if let Ok((mut ini, _)) = InitiatorContext::new(&creds(), GSS_C_MUTUAL_FLAG) {
                let _ = ini.step(toks[0]);
            }
        }
        2 => {
            let _ = parse_init(toks[0]);
            let _ = parse_resp(toks[0]);
            let _ = unframe(toks[0]);
        }
        _ => {
            // Wrap and MIC tokens, each role, with and without a subkey.
            for (role, sub) in [
                (Role::Initiator, false),
                (Role::Acceptor, false),
                (Role::Initiator, true),
            ] {
                let Ok(k) = ContextKey::new(18, &[4; 32]) else {
                    return;
                };
                let t = PerMessageTokens::new(k, role, sub);
                let _ = t.unwrap(toks[0]);
                let _ = t.verify_mic(toks[0], toks.get(1).copied().unwrap_or(b""));
            }
        }
    }
}

/// A PAC, every reader and every signature check, and the PAC in
/// authorization data or a ticket.
pub fn pac(data: &[u8]) {
    use crate::pac::*;
    let key = Key::new(18, vec![6; 32]).expect("AES-256 key");
    if let Ok(p) = Pac::parse(data) {
        let _ = p.buffer_types().count();
        let _ = p
            .logon_info()
            .map(|l| l.map(|l| (l.user_sid(), l.group_sids())));
        let _ = p.client_info();
        let _ = p.upn_dns_info();
        let _ = p.delegation_info();
        let _ = p.attributes();
        let _ = p.requestor_sid();
        let _ = p.verify_server_signature(&key);
        let _ = p.verify_kdc_signature(&key);
        let _ = p.verify_full_signature(&key);
        let _ = p.verify_client(0, &crate::Principal::new(1, ["a"], "R"), true);
    }
    let _ = find_pac(data);
    let _ = verify_ticket(data, &key, &key);
    let _ = verify_ticket_signature(data, &key);
    let _ = Sid::from_bytes(data);
}
