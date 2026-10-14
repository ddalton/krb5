//! XDR (RFC 4506), as MIT's gssrpc encodes the kadm5 types: every integer
//! four octets (`long`, `int16` and `ui_2` too), opaque data padded to a
//! multiple of four, and MIT's own `xdr_nullstring` (a NUL-terminated
//! string whose length counts the NUL, or length 0 for none).

use super::{Error, Result};

fn bad<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(msg.into()))
}

/// An XDR encoder.
#[derive(Debug, Default, Clone)]
pub(crate) struct Writer(pub(crate) Vec<u8>);

impl Writer {
    pub(crate) fn new() -> Self {
        Writer(Vec::new())
    }

    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub(crate) fn i32(&mut self, v: i32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub(crate) fn bool(&mut self, v: bool) -> &mut Self {
        self.u32(u32::from(v))
    }

    /// Variable-length opaque data: its length, the octets, and zero
    /// padding to four.
    pub(crate) fn opaque(&mut self, b: &[u8]) -> &mut Self {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
        self.0.resize(self.0.len() + (4 - b.len() % 4) % 4, 0);
        self
    }

    /// MIT's `xdr_nullstring`.
    pub(crate) fn nullstring(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            None => self.u32(0),
            Some(s) => {
                let mut b = s.as_bytes().to_vec();
                b.push(0);
                self.opaque(&b)
            }
        }
    }

    pub(crate) fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
}

/// An XDR decoder over a reply.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.data.len() < n {
            return bad("XDR data truncated");
        }
        let (a, b) = self.data.split_at(n);
        self.data = b;
        Ok(a)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    pub(crate) fn bool(&mut self) -> Result<bool> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            v => bad(format!("XDR boolean {v}")),
        }
    }

    pub(crate) fn opaque(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > self.data.len() {
            return bad("XDR opaque overruns the data");
        }
        let b = self.take(n)?;
        self.take((4 - n % 4) % 4)?;
        Ok(b)
    }

    /// MIT's `xdr_nullstring`: exactly one NUL, at the end.
    pub(crate) fn nullstring(&mut self) -> Result<Option<String>> {
        let b = self.opaque()?;
        match b.split_last() {
            None => Ok(None),
            Some((0, s)) if !s.contains(&0) => String::from_utf8(s.to_vec())
                .map(Some)
                .map_err(|_| Error::Protocol("XDR string is not UTF-8".into())),
            _ => bad("XDR string not NUL-terminated"),
        }
    }

    /// A count for an array, bounded by what the data could hold (each
    /// element at least `min` octets), so a hostile count cannot make us
    /// allocate.
    pub(crate) fn count(&mut self, min: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min.max(1)) > self.data.len() {
            return bad("XDR array count overruns the data");
        }
        Ok(n)
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        self.data
    }

    pub(crate) fn done(&self) -> Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            bad("trailing XDR data")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_data_is_padded_to_four() {
        let mut w = Writer::new();
        w.opaque(b"abcde").u32(7);
        assert_eq!(
            w.0,
            [
                0, 0, 0, 5, b'a', b'b', b'c', b'd', b'e', 0, 0, 0, 0, 0, 0, 7
            ]
        );
        let mut r = Reader::new(&w.0);
        assert_eq!(r.opaque().unwrap(), b"abcde");
        assert_eq!(r.u32().unwrap(), 7);
        r.done().unwrap();
    }

    #[test]
    fn nullstrings_count_their_nul() {
        let mut w = Writer::new();
        w.nullstring(Some("abc"))
            .nullstring(None)
            .nullstring(Some(""));
        assert_eq!(
            w.0,
            [
                0, 0, 0, 4, b'a', b'b', b'c', 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0
            ]
        );
        let mut r = Reader::new(&w.0);
        assert_eq!(r.nullstring().unwrap().as_deref(), Some("abc"));
        assert_eq!(r.nullstring().unwrap(), None);
        assert_eq!(r.nullstring().unwrap().as_deref(), Some(""));
        // No NUL, or one inside: refused, as MIT refuses them.
        assert!(
            Reader::new(&[0, 0, 0, 3, b'a', b'b', b'c', 0])
                .nullstring()
                .is_err()
        );
        assert!(
            Reader::new(&[0, 0, 0, 3, b'a', 0, 0, 0])
                .nullstring()
                .is_err()
        );
    }

    #[test]
    fn hostile_lengths_are_refused() {
        assert!(Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF]).opaque().is_err());
        assert!(Reader::new(&[0, 0, 0, 9, 1, 2]).opaque().is_err());
        assert!(Reader::new(&[0x10, 0, 0, 0]).count(4).is_err());
        assert!(Reader::new(&[0, 0, 0, 2]).bool().is_err());
    }
}
