//! Just enough DER for the Kerberos messages the client sends and reads.
//!
//! Kerberos ASN.1 (RFC 4120 §5) uses only single-octet tags (application
//! tags top out at 30, KRB-ERROR), EXPLICIT context tags, and a handful of
//! universal types, so a full ASN.1 library would be mostly dead weight.
//! What matters is that the encoder is *DER*, not merely BER: the KDC
//! checksums the exact octets of `KDC-REQ-BODY`, so minimal lengths and
//! minimal INTEGERs are not optional.

use std::fmt;

pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const GENERAL_STRING: u8 = 0x1B;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const SEQUENCE: u8 = 0x30;

/// A DER decoding failure: what was expected, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerError(pub String);

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DER: {}", self.0)
    }
}

impl std::error::Error for DerError {}

pub type Result<T> = std::result::Result<T, DerError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(DerError(msg.into()))
}

/// `[APPLICATION n]` constructed.
pub const fn app(n: u8) -> u8 {
    0x60 | n
}

/// `[n]` context-specific constructed (EXPLICIT).
pub const fn ctx(n: u8) -> u8 {
    0xA0 | n
}

// ---------------------------------------------------------------- encoding

pub fn encode_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    encode_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// A constructed value whose content is the concatenation of `parts`.
pub fn cons(tag: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag, &parts.concat())
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    cons(SEQUENCE, parts)
}

/// `[n] EXPLICIT inner`.
pub fn field(n: u8, inner: Vec<u8>) -> Vec<u8> {
    tlv(ctx(n), &inner)
}

/// Minimal two's-complement INTEGER.
pub fn int(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xFF && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(INTEGER, &bytes[start..])
}

pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, b)
}

pub fn general_string(s: &str) -> Vec<u8> {
    tlv(GENERAL_STRING, s.as_bytes())
}

/// KerberosTime: GeneralizedTime `YYYYMMDDHHMMSSZ`, no fractional seconds
/// (RFC 4120 §5.2.3).
pub fn time(unix: i64) -> Vec<u8> {
    let dt = chrono::DateTime::from_timestamp(unix, 0).unwrap_or_default();
    tlv(GENERALIZED_TIME, dt.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
}

/// The 32-bit flag BIT STRINGs (KDCOptions, APOptions, TicketFlags):
/// zero unused bits, then the four octets, bit 0 being the MSB.
pub fn flags32(v: u32) -> Vec<u8> {
    let mut c = vec![0u8];
    c.extend_from_slice(&v.to_be_bytes());
    tlv(BIT_STRING, &c)
}

// ---------------------------------------------------------------- decoding

/// A cursor over a sequence of TLVs.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Read the next TLV, returning its tag and content.
    pub fn next(&mut self) -> Result<(u8, &'a [u8])> {
        let d = self.data;
        if d.len() < 2 {
            return err("truncated TLV header");
        }
        let tag = d[0];
        if tag & 0x1F == 0x1F {
            return err(format!("multi-octet tag {tag:#04x} not supported"));
        }
        let (len, hdr) = match d[1] {
            n if n < 0x80 => (n as usize, 2),
            0x80 => return err("indefinite length is not DER"),
            n => {
                let k = (n & 0x7F) as usize;
                if k > 4 || d.len() < 2 + k {
                    return err("bad long-form length");
                }
                let len = d[2..2 + k].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
                (len, 2 + k)
            }
        };
        if d.len() - hdr < len {
            return err(format!("tag {tag:#04x}: length {len} overruns {} octets", d.len() - hdr));
        }
        self.data = &d[hdr + len..];
        Ok((tag, &d[hdr..hdr + len]))
    }

    /// Read the next TLV, which must carry `tag`.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        match self.next()? {
            (t, c) if t == tag => Ok(c),
            (t, _) => err(format!("expected tag {tag:#04x}, found {t:#04x}")),
        }
    }

    // Typed readers for the single value inside a field.

    pub fn int(&mut self) -> Result<i64> {
        let c = self.expect(INTEGER)?;
        if c.is_empty() || c.len() > 8 {
            return err(format!("INTEGER of {} octets", c.len()));
        }
        let mut v: i64 = if c[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in c {
            v = (v << 8) | b as i64;
        }
        Ok(v)
    }

    pub fn i32(&mut self) -> Result<i32> {
        let v = self.int()?;
        i32::try_from(v).map_err(|_| DerError(format!("INTEGER {v} out of Int32 range")))
    }

    /// UInt32 (nonces, sequence numbers). MIT historically encoded these
    /// as negative Int32s, so accept both forms.
    pub fn u32(&mut self) -> Result<u32> {
        let v = self.int()?;
        if (i32::MIN as i64..=u32::MAX as i64).contains(&v) {
            Ok(v as u32)
        } else {
            err(format!("INTEGER {v} out of UInt32 range"))
        }
    }

    pub fn octets(&mut self) -> Result<&'a [u8]> {
        self.expect(OCTET_STRING)
    }

    pub fn string(&mut self) -> Result<String> {
        let c = self.expect(GENERAL_STRING)?;
        String::from_utf8(c.to_vec()).map_err(|_| DerError("KerberosString is not UTF-8".into()))
    }

    pub fn time(&mut self) -> Result<i64> {
        let c = self.expect(GENERALIZED_TIME)?;
        let s = std::str::from_utf8(c).map_err(|_| DerError("time is not ASCII".into()))?;
        chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%SZ")
            .map(|t| t.and_utc().timestamp())
            .map_err(|e| DerError(format!("KerberosTime {s:?}: {e}")))
    }

    pub fn flags32(&mut self) -> Result<u32> {
        let c = self.expect(BIT_STRING)?;
        if c.is_empty() {
            return err("empty BIT STRING");
        }
        let mut b = [0u8; 4];
        for (i, v) in c[1..].iter().take(4).enumerate() {
            b[i] = *v;
        }
        Ok(u32::from_be_bytes(b))
    }

    /// `SEQUENCE OF`: a reader over the elements.
    pub fn seq(&mut self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.expect(SEQUENCE)?))
    }
}

/// The `[n] EXPLICIT` fields of one SEQUENCE, indexed by field number.
///
/// Kerberos messages are SEQUENCEs of mostly-OPTIONAL context-tagged
/// fields; indexing by number keeps a parser from silently reading field
/// 3 as field 2 when 2 is absent. Unknown non-context tags are refused,
/// unknown field numbers are ignored (extensibility, RFC 4120 §5.1).
pub struct Fields<'a> {
    what: &'static str,
    slots: [Option<&'a [u8]>; 32],
}

impl<'a> Fields<'a> {
    /// Parse the content of a SEQUENCE (the TLV must already be stripped).
    pub fn parse(what: &'static str, content: &'a [u8]) -> Result<Self> {
        let mut slots = [None; 32];
        let mut r = Reader::new(content);
        while !r.is_empty() {
            let (tag, c) = r.next()?;
            if tag & 0xE0 != 0xA0 {
                return err(format!("{what}: unexpected tag {tag:#04x}"));
            }
            slots[(tag & 0x1F) as usize] = Some(c);
        }
        Ok(Fields { what, slots })
    }

    /// Unwrap `tag` (a SEQUENCE or APPLICATION tag), then parse the fields.
    pub fn parse_tagged(what: &'static str, tag: u8, data: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let c = r.expect(tag).map_err(|e| DerError(format!("{what}: {}", e.0)))?;
        if tag & 0xE0 == 0x60 {
            Fields::parse(what, Reader::new(c).expect(SEQUENCE)?)
        } else {
            Fields::parse(what, c)
        }
    }

    pub fn get(&self, n: u8) -> Result<Reader<'a>> {
        self.slots[n as usize]
            .map(Reader::new)
            .ok_or_else(|| DerError(format!("{}: missing field [{n}]", self.what)))
    }

    pub fn opt(&self, n: u8) -> Option<Reader<'a>> {
        self.slots[n as usize].map(Reader::new)
    }

    /// The raw TLV inside field `n` (e.g. a Ticket to be re-sent verbatim).
    pub fn raw(&self, n: u8) -> Result<&'a [u8]> {
        self.slots[n as usize].ok_or_else(|| DerError(format!("{}: missing field [{n}]", self.what)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_index_by_number_and_tolerate_gaps() {
        let enc = seq(&[field(0, int(5)), field(3, general_string("x"))]);
        let f = Fields::parse_tagged("t", SEQUENCE, &enc).unwrap();
        assert_eq!(f.get(0).unwrap().int().unwrap(), 5);
        assert!(f.opt(1).is_none());
        assert!(f.get(2).is_err());
        assert_eq!(f.get(3).unwrap().string().unwrap(), "x");
        assert_eq!(f.raw(3).unwrap(), general_string("x"));
    }

    #[test]
    fn application_tagged_fields_unwrap_the_inner_sequence() {
        let enc = cons(app(11), &[seq(&[field(0, int(5))])]);
        let f = Fields::parse_tagged("AS-REP", app(11), &enc).unwrap();
        assert_eq!(f.get(0).unwrap().int().unwrap(), 5);
        assert!(Fields::parse_tagged("TGS-REP", app(13), &enc).is_err());
    }

    #[test]
    fn integers_are_minimal() {
        assert_eq!(int(0), [0x02, 0x01, 0x00]);
        assert_eq!(int(5), [0x02, 0x01, 0x05]);
        assert_eq!(int(127), [0x02, 0x01, 0x7F]);
        assert_eq!(int(128), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(int(256), [0x02, 0x02, 0x01, 0x00]);
        assert_eq!(int(-1), [0x02, 0x01, 0xFF]);
        assert_eq!(int(-128), [0x02, 0x01, 0x80]);
        assert_eq!(int(-129), [0x02, 0x02, 0xFF, 0x7F]);
        assert_eq!(int(0xFFFF_FFFF), [0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn integers_round_trip() {
        for v in [0, 1, -1, 127, 128, -128, -129, 65535, i32::MIN as i64, u32::MAX as i64] {
            assert_eq!(Reader::new(&int(v)).int().unwrap(), v);
        }
    }

    #[test]
    fn a_negative_uint32_is_read_as_its_unsigned_twin() {
        assert_eq!(Reader::new(&int(-2)).u32().unwrap(), 0xFFFF_FFFE);
    }

    #[test]
    fn lengths_use_the_short_form_below_128_and_minimal_long_form_above() {
        let mut v = vec![];
        encode_len(&mut v, 127);
        assert_eq!(v, [0x7F]);
        v.clear();
        encode_len(&mut v, 128);
        assert_eq!(v, [0x81, 0x80]);
        v.clear();
        encode_len(&mut v, 0x1234);
        assert_eq!(v, [0x82, 0x12, 0x34]);
    }

    #[test]
    fn long_values_round_trip() {
        let big = vec![7u8; 300];
        let enc = octets(&big);
        assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2C]);
        assert_eq!(Reader::new(&enc).octets().unwrap(), &big[..]);
    }

    #[test]
    fn kerberos_time_round_trips() {
        let t = 1_790_000_000;
        let enc = time(t);
        assert_eq!(&enc[2..], b"20260921141320Z");
        assert_eq!(Reader::new(&enc).time().unwrap(), t);
    }

    #[test]
    fn flags_are_msb_first() {
        // forwardable is bit 1 of KDCOptions.
        let enc = flags32(1 << 30);
        assert_eq!(enc, [0x03, 0x05, 0x00, 0x40, 0x00, 0x00, 0x00]);
        assert_eq!(Reader::new(&enc).flags32().unwrap(), 1 << 30);
    }

    #[test]
    fn truncation_and_indefinite_length_are_refused() {
        assert!(Reader::new(&[0x04, 0x05, 1, 2]).next().is_err());
        assert!(Reader::new(&[0x30, 0x80, 0, 0]).next().is_err());
        assert!(Reader::new(&[0x04]).next().is_err());
    }
}
