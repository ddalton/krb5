//! Entry points for the fuzz targets in `fuzz/` (`cfg(fuzzing)` only):
//! the AP-REQ as it arrives, and the parsers that run on what decrypts.

use super::*;

const AES256: [u8; 32] = [7; 32];

fn keytab() -> Keytab {
    Keytab::from_keys(vec![ServiceKey {
        principal: "host/fuzz.example".into(),
        realm: "FUZZ.EXAMPLE".into(),
        kvno: 1,
        enctype: EncType::AES256CtsHmacSha196,
        key: AES256.to_vec(),
    }])
}

fn opts() -> AcceptOptions {
    AcceptOptions {
        max_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
        channel_bindings: Some(crate::ChannelBindings::new(b"fuzz".to_vec())),
        replay_cache: None,
    }
}

/// A GSS-API initial context token, or a bare AP-REQ.
pub fn token(data: &[u8]) {
    let kt = keytab();
    let _ = KerberosContext::accept_token_with(&kt, data, &opts());
    let _ = KerberosContext::accept_ap_req(&kt, data, &opts());
}

/// A keytab file.
pub fn keytab_file(data: &[u8]) {
    let _ = Keytab::parse(data);
}

/// The first octet picks a parser for the rest: the decrypted ticket and
/// authenticator, the GSS checksum, AP options in authorization data,
/// the Ticket, and an AP-REQ.
pub fn inner(data: &[u8]) {
    let Some((&sel, d)) = data.split_first() else {
        return;
    };
    match sel % 6 {
        0 => {
            if let Ok(mut part) = EncTicketPart::parse(d) {
                part.authorization_data =
                    crate::der::Fields::parse_tagged("EncTicketPart", 0x63, d)
                        .ok()
                        .and_then(|f| f.raw(10).ok().map(<[u8]>::to_vec));
                let _ = part.validate_validity(0, 300);
                let kt = keytab();
                let _ = verified_pac(&part, &kt.keys()[0]);
                if let Some(ad) = &part.authorization_data {
                    let _ = ap_options_cbt(ad);
                }
            }
        }
        1 => {
            if let Ok(a) = Authenticator::parse_from_plaintext(d) {
                let _ = a.validate(0, 300);
                if let Some((_, ck)) = &a.cksum {
                    let _ = parse_gss_checksum(ck);
                }
            }
        }
        2 => {
            let _ = parse_gss_checksum(d);
        }
        3 => {
            let _ = ap_options_cbt(d);
        }
        4 => {
            let _ = Ticket::parse(d);
        }
        _ => {
            let _ = KerberosContext::parse_ap_req(d);
        }
    }
}
