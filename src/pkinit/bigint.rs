//! Modular exponentiation over big-endian octet strings, on
//! crypto-bigint's Montgomery arithmetic, which is constant-time in the
//! exponent: what DH and RSA signing need for their secrets.

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};

use super::asn1::strip;

/// `base^exp mod m` as `m.len()` octets (after `m`'s leading zeros are
/// dropped), or `None` if `m` is even or `base >= m`. Time depends on the
/// lengths of `exp` and `m`, never on their values.
pub(crate) fn modpow(base: &[u8], exp: &[u8], m: &[u8]) -> Option<Vec<u8>> {
    let m = strip(m);
    if m.is_empty() || !less(base, m) {
        return None;
    }
    let bits = (m.len() * 8) as u32;
    let modulus = Odd::new(BoxedUint::from_be_slice(m, bits).ok()?).into_option()?;
    let params = BoxedMontyParams::new(modulus);
    let b = BoxedUint::from_be_slice(strip(base), bits).ok()?;
    let e = if exp.is_empty() {
        BoxedUint::zero_with_precision(64)
    } else {
        BoxedUint::from_be_slice(exp, (exp.len() * 8).max(64) as u32).ok()?
    };
    let r = BoxedMontyForm::new(b, &params).pow(&e).retrieve();
    let bytes = r.to_be_bytes();
    Some(bytes[bytes.len() - m.len()..].to_vec())
}

/// `a < b` as unsigned big-endian numbers. Not constant-time: for public
/// values only.
pub(crate) fn less(a: &[u8], b: &[u8]) -> bool {
    let (a, b) = (strip(a), strip(b));
    (a.len(), a) < (b.len(), b)
}

/// `a - 1` for a positive `a`, same length.
pub(crate) fn minus_one(a: &[u8]) -> Vec<u8> {
    let mut out = a.to_vec();
    for b in out.iter_mut().rev() {
        let (v, borrow) = b.overflowing_sub(1);
        *b = v;
        if !borrow {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_powers_are_right() {
        // 4^13 mod 497 = 445 (the textbook example).
        assert_eq!(modpow(&[4], &[13], &[0x01, 0xF1]).unwrap(), [0x01, 0xBD]);
        // Leading zeros anywhere change nothing but the output length.
        assert_eq!(
            modpow(&[0, 4], &[0, 0, 13], &[0, 0x01, 0xF1]).unwrap(),
            [0x01, 0xBD]
        );
        assert_eq!(modpow(&[7], &[], &[0x0B]).unwrap(), [1]);
        assert_eq!(modpow(&[0], &[5], &[0x0B]).unwrap(), [0]);
    }

    #[test]
    fn an_even_modulus_or_an_unreduced_base_is_refused() {
        assert!(modpow(&[2], &[3], &[10]).is_none());
        assert!(modpow(&[11], &[3], &[11]).is_none());
        assert!(modpow(&[1], &[3], &[]).is_none());
    }

    #[test]
    fn comparisons_ignore_leading_zeros() {
        assert!(less(&[0, 0, 1], &[2]));
        assert!(!less(&[2], &[0, 2]));
        assert!(less(&[0xFF], &[1, 0]));
        assert_eq!(minus_one(&[1, 0, 0]), [0, 0xFF, 0xFF]);
        assert_eq!(minus_one(&[0x12, 0x35]), [0x12, 0x34]);
    }
}
