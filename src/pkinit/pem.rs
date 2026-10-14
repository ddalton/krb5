//! PEM (RFC 7468): the `-----BEGIN label-----` blocks of certificate and
//! key files, base64 decoded.

/// Every block in `text` as (label, DER). Text outside blocks is ignored,
/// as OpenSSL ignores it; a block with RFC 1421 headers (an encrypted
/// key's `Proc-Type`) or bad base64 is an error.
pub(crate) fn blocks(text: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let text = String::from_utf8_lossy(text);
    let mut out = Vec::new();
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        else {
            continue;
        };
        let end = format!("-----END {label}-----");
        let mut b64 = String::new();
        loop {
            match lines.next() {
                None => return Err(format!("PEM block {label} has no END line")),
                Some(l) if l == end => break,
                Some(l) if l.contains(':') => {
                    return Err(format!(
                        "PEM block {label} has headers ({l}); encrypted keys are not supported"
                    ));
                }
                Some(l) => b64.push_str(l),
            }
        }
        let der = base64(&b64).ok_or_else(|| format!("PEM block {label}: bad base64"))?;
        out.push((label.to_string(), der));
    }
    Ok(out)
}

fn base64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let s = s.as_bytes();
    if s.len() % 4 != 0 {
        return None;
    }
    let pad = s.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    for (i, &c) in s[..s.len() - pad].iter().enumerate() {
        acc = (acc << 6) | u32::from(val(c)?);
        if i % 4 == 3 {
            out.extend_from_slice(&acc.to_be_bytes()[1..]);
            acc = 0;
        }
    }
    match pad {
        1 => {
            acc <<= 6;
            out.extend_from_slice(&acc.to_be_bytes()[1..3]);
        }
        2 => {
            acc <<= 12;
            out.push(acc.to_be_bytes()[1]);
        }
        _ => {}
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_rfc_4648_vectors() {
        for (enc, dec) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(base64(enc).unwrap(), dec.as_bytes(), "{enc}");
        }
        for bad in ["Zg=", "Zg===", "Z!==", "Zm9vY"] {
            assert!(base64(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn blocks_are_found_among_other_text() {
        let pem = b"Bag Attributes\n-----BEGIN CERTIFICATE-----\nZm9v\nYmFy\n-----END CERTIFICATE-----\njunk\n-----BEGIN PRIVATE KEY-----\nZg==\n-----END PRIVATE KEY-----\n";
        let b = blocks(pem).unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b[0], ("CERTIFICATE".into(), b"foobar".to_vec()));
        assert_eq!(b[1], ("PRIVATE KEY".into(), b"f".to_vec()));
        assert!(blocks(b"-----BEGIN X-----\nZm9v\n").is_err());
        assert!(
            blocks(b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nZm9v\n-----END RSA PRIVATE KEY-----\n")
                .is_err()
        );
    }
}
