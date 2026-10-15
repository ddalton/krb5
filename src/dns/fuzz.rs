//! Entry point for `fuzz/` (`cfg(fuzzing)` only): DNS answers.

use super::*;

const NAME: &str = "_kerberos._udp.fuzz.example";

/// The first octet picks the record type and flags; the rest is the
/// answer section of a reply to our question (and, separately, a whole
/// message, and resolv.conf text).
pub fn reply(data: &[u8]) {
    let Some((&sel, d)) = data.split_first() else {
        return;
    };
    let qtype = [TYPE_SRV, TYPE_URI, TYPE_CNAME][usize::from(sel) % 3];
    let mut m = vec![0x12, 0x34, 0x81, sel & 0x8F, 0, 1, 0, sel >> 4, 0, 0, 0, 0];
    for label in NAME.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    m.extend_from_slice(d);
    let _ = parse_reply(&m, 0x1234, NAME, qtype);
    if d.len() >= 2 {
        let _ = parse_reply(d, u16::from_be_bytes([d[0], d[1]]), NAME, qtype);
    }
    if let Ok(s) = std::str::from_utf8(d) {
        let _ = Resolver::parse_resolv_conf(s);
        let _ = parse_krb5srv(s);
    }
}
