//! The DER PKINIT needs beyond Kerberos's own: object identifiers, SETs,
//! BIT STRINGs, unsigned INTEGERs of any size and the IMPLICIT tags of
//! CMS and X.509.

use crate::der::{self, DerError, Reader, Result};

pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const NULL: u8 = 0x05;
pub(crate) const OID: u8 = 0x06;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const SET: u8 = 0x31;

/// `[n]` IMPLICIT on a primitive type.
pub(crate) const fn implicit(n: u8) -> u8 {
    0x80 | n
}

/// The content octets of an OBJECT IDENTIFIER, from its dotted form.
pub(crate) fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|a| a.parse().expect("a well-formed OID constant"))
        .collect();
    let mut out = Vec::new();
    let mut put = |mut v: u64| {
        let mut tmp = vec![(v & 0x7F) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7F) as u8);
            v >>= 7;
        }
        out.extend(tmp.iter().rev());
    };
    put(arcs[0] * 40 + arcs[1]);
    for &a in &arcs[2..] {
        put(a);
    }
    out
}

/// An OBJECT IDENTIFIER TLV.
pub(crate) fn oid_tlv(dotted: &str) -> Vec<u8> {
    der::tlv(OID, &oid(dotted))
}

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm, parameters OPTIONAL }`.
pub(crate) fn alg_id(dotted: &str, params: Option<Vec<u8>>) -> Vec<u8> {
    let mut parts = vec![oid_tlv(dotted)];
    parts.extend(params);
    der::seq(&parts)
}

pub(crate) fn null() -> Vec<u8> {
    der::tlv(NULL, &[])
}

/// A SET OF, its elements in DER order (sorted by their encodings).
pub(crate) fn set_of(mut parts: Vec<Vec<u8>>) -> Vec<u8> {
    parts.sort();
    der::cons(SET, &parts)
}

/// A BIT STRING with no unused bits.
pub(crate) fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(bytes.len() + 1);
    c.push(0);
    c.extend_from_slice(bytes);
    der::tlv(der::BIT_STRING, &c)
}

/// A non-negative INTEGER from big-endian magnitude octets.
pub(crate) fn uint(magnitude: &[u8]) -> Vec<u8> {
    let m = strip(magnitude);
    let mut c = Vec::with_capacity(m.len() + 1);
    if m.is_empty() || m[0] & 0x80 != 0 {
        c.push(0);
    }
    c.extend_from_slice(m);
    der::tlv(der::INTEGER, &c)
}

/// Big-endian magnitude without leading zero octets.
pub(crate) fn strip(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[i..]
}

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(DerError(msg.into()))
}

/// The magnitude of a non-negative INTEGER's content octets.
pub(crate) fn uint_content(c: &[u8]) -> Result<&[u8]> {
    match c {
        [] => err("empty INTEGER"),
        [b, ..] if b & 0x80 != 0 => err("negative INTEGER where a positive one belongs"),
        [0, b, ..] if b & 0x80 == 0 => err("INTEGER not minimally encoded"),
        _ => Ok(strip(c)),
    }
}

/// The content of a BIT STRING that must have no unused bits.
pub(crate) fn bits_content(c: &[u8]) -> Result<&[u8]> {
    match c {
        [0, rest @ ..] => Ok(rest),
        _ => err("BIT STRING with unused bits"),
    }
}

/// Typed reads for the PKINIT and X.509 types.
pub(crate) trait ReaderExt<'a> {
    fn oid(&mut self) -> Result<&'a [u8]>;
    fn uint(&mut self) -> Result<&'a [u8]>;
    fn bits(&mut self) -> Result<&'a [u8]>;
    /// The next TLV whole: its tag, its content and its exact encoding.
    fn next_raw(&mut self) -> Result<(u8, &'a [u8], &'a [u8])>;
    /// The next TLV if it carries `tag`.
    fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>>;
    /// `AlgorithmIdentifier`: the OID's content and the raw parameters.
    fn alg_id(&mut self) -> Result<(&'a [u8], Option<&'a [u8]>)>;
    fn done(&self, what: &str) -> Result<()>;
}

impl<'a> ReaderExt<'a> for Reader<'a> {
    fn oid(&mut self) -> Result<&'a [u8]> {
        self.expect(OID)
    }

    fn uint(&mut self) -> Result<&'a [u8]> {
        uint_content(self.expect(der::INTEGER)?)
    }

    fn bits(&mut self) -> Result<&'a [u8]> {
        bits_content(self.expect(der::BIT_STRING)?)
    }

    fn next_raw(&mut self) -> Result<(u8, &'a [u8], &'a [u8])> {
        let before = self.rest();
        let (tag, content) = self.next()?;
        Ok((tag, content, &before[..before.len() - self.rest().len()]))
    }

    fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>> {
        match self.rest().first() {
            Some(&t) if t == tag => Ok(Some(self.next()?.1)),
            _ => Ok(None),
        }
    }

    fn alg_id(&mut self) -> Result<(&'a [u8], Option<&'a [u8]>)> {
        let mut a = self.seq()?;
        let oid = a.oid()?;
        let params = if a.is_empty() {
            None
        } else {
            Some(a.next_raw()?.2)
        };
        a.done("AlgorithmIdentifier")?;
        Ok((oid, params))
    }

    fn done(&self, what: &str) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            err(format!("trailing data in {what}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids_encode_as_x690_says() {
        // X.690 §8.19.5's example, and two with multi-octet arcs.
        assert_eq!(oid("2.100.3"), [0x81, 0x34, 0x03]);
        assert_eq!(
            oid("1.2.840.113549.1.1.11"),
            [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
        );
        assert_eq!(oid("1.3.6.1.5.2.3.1"), [0x2B, 6, 1, 5, 2, 3, 1]);
    }

    #[test]
    fn unsigned_integers_are_minimal_and_positive() {
        assert_eq!(uint(&[0, 0, 0x7F]), [2, 1, 0x7F]);
        assert_eq!(uint(&[0x80]), [2, 2, 0, 0x80]);
        assert_eq!(uint(&[]), [2, 1, 0]);
        assert_eq!(uint_content(&[0, 0x80]).unwrap(), [0x80]);
        assert!(uint_content(&[0x80]).is_err());
        assert!(uint_content(&[0, 0x7F]).is_err());
    }

    #[test]
    fn sets_are_sorted() {
        assert_eq!(
            set_of(vec![vec![2, 1, 9], vec![2, 1, 1]]),
            [SET, 6, 2, 1, 1, 2, 1, 9]
        );
    }

    #[test]
    fn raw_reads_return_the_exact_encoding() {
        let data = [0x30, 0x81, 0x03, 2, 1, 5, 4, 0];
        let mut r = Reader::new(&data);
        let (tag, content, raw) = r.next_raw().unwrap();
        assert_eq!((tag, content, raw), (0x30, &data[3..6], &data[..6]));
        assert_eq!(r.optional(der::INTEGER).unwrap(), None);
        assert_eq!(r.optional(der::OCTET_STRING).unwrap(), Some(&[][..]));
        r.done("test").unwrap();
    }
}
