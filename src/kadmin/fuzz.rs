//! Entry point for `fuzz/` (`cfg(fuzzing)` only): what kadmind sends.

use super::*;

/// The first octet picks a decoder for the rest.
pub fn reply(data: &[u8]) {
    let Some((&sel, d)) = data.split_first() else {
        return;
    };
    let mut r = Reader::new(d);
    match sel % 7 {
        0 => {
            let xid = d
                .get(..4)
                .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap()));
            let _ = rpc::parse_reply(d, xid);
        }
        1 => {
            let _ = get_principal_entry(&mut r);
        }
        2 => {
            for v in [2, 3, 4] {
                let _ = get_policy(&mut Reader::new(d), v);
            }
        }
        3 => {
            let _ = get_keyblock(&mut r);
        }
        4 => {
            let _ = generic(d);
        }
        5 => {
            // A name list, as list_principals reads it.
            if r.i32().is_ok() {
                if let Ok(n) = r.count(4) {
                    for _ in 0..n {
                        match r.nullstring() {
                            Ok(Some(s)) => {
                                let _ = parse_name(&s);
                            }
                            Ok(None) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
        }
        _ => {
            if let Ok(s) = std::str::from_utf8(d) {
                let _ = parse_name(s);
            }
        }
    }
}
