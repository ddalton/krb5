//! OTP pre-authentication (RFC 6560, FAST OTP): a one-time password from a
//! token, sent inside FAST armor, as MIT's `kinit -T armor` sends one when
//! the KDC asks for it (`otp` principal string attribute; MIT's KDC checks
//! the value with a RADIUS server, which is how FreeIPA does two-factor
//! login).
//!
//! The KDC's PA-OTP-CHALLENGE describes the tokens it will take; the
//! client answers with a PA-OTP-REQUEST holding the value and the
//! challenge's nonce, encrypted in the FAST armor key. The armor key is
//! then the reply key (strengthened, if the KDC says so).
//!
//! RFC 6560's ASN.1 module uses IMPLICIT tags, unlike RFC 4120's, so its
//! fields are read and written here, not with the RFC 4120 field reader.
//!
//! As in MIT, tokens the client cannot answer for are dropped from the
//! challenge before anyone sees it: ones with flags other than the PIN
//! ones, that want a hashed value (`supported-hash-alg`,
//! `iteration-count`), that want base64, or whose vendor or challenge
//! text is not printable.

use super::*;

pub(super) const PA_OTP_CHALLENGE: i32 = 141;
pub(super) const PA_OTP_REQUEST: i32 = 142;
const KU_PA_OTP_REQUEST: u32 = 45;

/// OTPFlags (RFC 6560 §4.1), as MIT numbers them.
pub const OTP_FLAG_NEXT_OTP: u32 = 0x4000_0000;
pub const OTP_FLAG_COMBINE: u32 = 0x2000_0000;
pub const OTP_FLAG_COLLECT_PIN: u32 = 0x1000_0000;
pub const OTP_FLAG_DO_NOT_COLLECT_PIN: u32 = 0x0800_0000;
pub const OTP_FLAG_MUST_ENCRYPT_NONCE: u32 = 0x0400_0000;
pub const OTP_FLAG_SEPARATE_PIN_REQUIRED: u32 = 0x0200_0000;
pub const OTP_FLAG_CHECK_DIGIT: u32 = 0x0100_0000;

/// OTP formats (RFC 6560 §4.1, `otp-format`).
pub const OTP_FORMAT_DECIMAL: i32 = 0;
pub const OTP_FORMAT_HEXADECIMAL: i32 = 1;
pub const OTP_FORMAT_ALPHANUMERIC: i32 = 2;
pub const OTP_FORMAT_BINARY: i32 = 3;
pub const OTP_FORMAT_BASE64: i32 = 4;

/// What the KDC asks for: its PA-OTP-CHALLENGE, less the tokens this
/// client cannot answer for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpChallenge {
    /// The service the OTP is for, to show the user.
    pub service: Option<String>,
    /// The tokens the KDC will accept a value from; at least one.
    pub tokens: Vec<OtpTokenInfo>,
}

/// One token the KDC accepts a value from (RFC 6560 OTP-TOKENINFO).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpTokenInfo {
    /// `OTP_FLAG_*`: whether a PIN is collected, and how.
    pub flags: u32,
    pub vendor: Option<String>,
    /// A challenge to show the user (for challenge-response tokens).
    pub challenge: Option<String>,
    /// The number of characters in a value, if fixed.
    pub length: Option<i32>,
    /// `OTP_FORMAT_*`, if the KDC said.
    pub format: Option<i32>,
    pub token_id: Option<Vec<u8>>,
    pub alg_id: Option<String>,
}

impl OtpTokenInfo {
    /// MIT's `otpvalue_matches_tokeninfo`: whether `value` has this token's
    /// length and format.
    pub fn accepts(&self, value: &str) -> bool {
        if self
            .length
            .is_some_and(|n| value.len() as i64 != i64::from(n))
        {
            return false;
        }
        let ok: fn(&char) -> bool = match self.format {
            Some(OTP_FORMAT_DECIMAL) => |c| c.is_ascii_digit(),
            Some(OTP_FORMAT_HEXADECIMAL) => |c| c.is_ascii_hexdigit(),
            Some(OTP_FORMAT_ALPHANUMERIC) => |c| c.is_ascii_alphanumeric(),
            _ => |_| true,
        };
        value.chars().all(|c| ok(&c))
    }
}

/// The answer to an [`OtpChallenge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAnswer {
    /// Which of the challenge's tokens (an index into `tokens`).
    pub token: usize,
    /// The one-time value (for FreeIPA, the password followed by it).
    pub value: String,
    /// The PIN, for a token that collects one: sent apart for
    /// [`OTP_FLAG_SEPARATE_PIN_REQUIRED`], else put before the value, as
    /// MIT does.
    pub pin: Option<String>,
}

/// MIT's choice for `kinit` given one value and no further prompting:
/// the only token, else the only one whose length and format the value
/// fits. A token that wants its PIN apart cannot be answered this way.
pub(super) fn answer_with(challenge: &OtpChallenge, value: &str) -> Result<OtpAnswer> {
    let fits: Vec<usize> = if challenge.tokens.len() == 1 {
        vec![0]
    } else {
        (0..challenge.tokens.len())
            .filter(|&i| challenge.tokens[i].accepts(value))
            .collect()
    };
    let token = match fits[..] {
        [i] => i,
        [] => {
            return Err(ClientError::NoKey(
                "OTP value doesn't match any token formats".into(),
            ));
        }
        _ => {
            return Err(ClientError::NoKey(
                "the OTP value fits more than one of the KDC's tokens; \
                 choose one with login_with_otp_by"
                    .into(),
            ));
        }
    };
    if challenge.tokens[token].flags & OTP_FLAG_SEPARATE_PIN_REQUIRED != 0 {
        return Err(ClientError::NoKey(
            "the OTP token wants a separate PIN; give it with login_with_otp_by".into(),
        ));
    }
    Ok(OtpAnswer {
        token,
        value: value.to_string(),
        pin: None,
    })
}

/// The fields of an IMPLICIT-tagged SEQUENCE: `[n]` context tags, primitive
/// or constructed, by number.
fn implicit_fields<'a>(what: &str, content: &'a [u8]) -> Result<[Option<&'a [u8]>; 16]> {
    let mut slots = [None; 16];
    let mut r = Reader::new(content);
    while !r.is_empty() {
        let (tag, c) = r.next()?;
        let n = (tag & 0x1F) as usize;
        if tag & 0xC0 != 0x80 || n >= 16 {
            return protocol(format!("{what}: unexpected tag {tag:#04x}"));
        }
        slots[n] = Some(c);
    }
    Ok(slots)
}

fn int_content(c: &[u8]) -> Result<i32> {
    if c.is_empty() || c.len() > 4 {
        return protocol(format!("OTP: INTEGER of {} octets", c.len()));
    }
    let mut v: i32 = if c[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in c {
        v = (v << 8) | i32::from(b);
    }
    Ok(v)
}

fn flags_content(c: &[u8]) -> Result<u32> {
    if c.is_empty() {
        return protocol("OTP: empty flags BIT STRING");
    }
    let mut b = [0u8; 4];
    for (i, v) in c[1..].iter().take(4).enumerate() {
        b[i] = *v;
    }
    Ok(u32::from_be_bytes(b))
}

fn utf8(c: &[u8]) -> Result<String> {
    String::from_utf8(c.to_vec())
        .map_err(|_| ClientError::Protocol("OTP: text is not UTF-8".into()))
}

fn printable(s: &Option<String>) -> bool {
    s.as_ref()
        .is_none_or(|s| s.bytes().all(|b| (0x20..0x7F).contains(&b)))
}

/// Parse a PA-OTP-CHALLENGE: its nonce, and the challenge with the
/// tokens we cannot answer for dropped.
pub(super) fn parse_challenge(value: &[u8]) -> Result<(Vec<u8>, OtpChallenge)> {
    let mut r = Reader::new(value);
    let f = implicit_fields("PA-OTP-CHALLENGE", r.expect(der::SEQUENCE)?)?;
    let nonce = f[0]
        .ok_or_else(|| ClientError::Protocol("PA-OTP-CHALLENGE has no nonce".into()))?
        .to_vec();
    let service = f[1].map(utf8).transpose()?;
    let mut infos =
        Reader::new(f[2].ok_or_else(|| {
            ClientError::Protocol("PA-OTP-CHALLENGE has no otp-tokenInfo".into())
        })?);
    let mut tokens = Vec::new();
    while !infos.is_empty() {
        let t = implicit_fields("OTP-TOKENINFO", infos.expect(der::SEQUENCE)?)?;
        let ti = OtpTokenInfo {
            flags: t[0].map(flags_content).transpose()?.unwrap_or(0),
            vendor: t[1].map(utf8).transpose()?,
            challenge: t[2].map(utf8).transpose()?,
            length: t[3].map(int_content).transpose()?,
            format: t[4].map(int_content).transpose()?,
            token_id: t[5].map(<[u8]>::to_vec),
            alg_id: t[6].map(utf8).transpose()?,
        };
        // MIT's is_tokeninfo_supported.
        let pin_flags =
            OTP_FLAG_COLLECT_PIN | OTP_FLAG_DO_NOT_COLLECT_PIN | OTP_FLAG_SEPARATE_PIN_REQUIRED;
        let supported = ti.flags & !pin_flags == 0
            && t[7].is_none()
            && t[8].is_none_or(|c| int_content(c).is_ok_and(|n| n < 0))
            && printable(&ti.vendor)
            && printable(&ti.challenge)
            && ti.format != Some(OTP_FORMAT_BASE64);
        if supported {
            tokens.push(ti);
        }
    }
    if tokens.is_empty() {
        return Err(ClientError::NoKey(
            "the KDC offers no OTP token this client supports".into(),
        ));
    }
    Ok((nonce, OtpChallenge { service, tokens }))
}

/// The PA-OTP-REQUEST answering `challenge` (whose nonce is `nonce`) with
/// `answer`, its nonce encrypted in the armor key as MIT's
/// `encrypt_nonce` does it.
pub(super) fn request(
    nonce: &[u8],
    challenge: &OtpChallenge,
    answer: &OtpAnswer,
    armor_key: &Key,
) -> Result<Vec<u8>> {
    let ti = challenge
        .tokens
        .get(answer.token)
        .ok_or_else(|| ClientError::NoKey(format!("no OTP token {}", answer.token)))?;
    // PA-OTP-ENC-REQUEST ::= SEQUENCE { nonce [0] OCTET STRING }
    let enc_req = der::seq(&[der::tlv(0x80, nonce)]);
    let cipher = armor_key.encrypt(KU_PA_OTP_REQUEST, &enc_req)?;
    let mut enc_data = encode_encrypted_data(armor_key.enctype(), &cipher);
    enc_data[0] = 0xA2; // [2] IMPLICIT EncryptedData

    let mut value = answer.value.clone();
    let mut pin = None;
    if ti.flags & OTP_FLAG_COLLECT_PIN != 0 {
        if ti.flags & OTP_FLAG_SEPARATE_PIN_REQUIRED != 0 {
            pin =
                Some(answer.pin.clone().ok_or_else(|| {
                    ClientError::NoKey("the OTP token wants a separate PIN".into())
                })?);
        } else if let Some(p) = &answer.pin {
            value = format!("{p}{value}");
        }
    }
    let flags = der::flags32(ti.flags & OTP_FLAG_NEXT_OTP);
    let mut fields = vec![der::tlv(0x80, &flags[2..]), enc_data];
    fields.push(der::tlv(0x85, value.as_bytes()));
    if let Some(p) = pin {
        fields.push(der::tlv(0x86, p.as_bytes()));
    }
    if let Some(f) = ti.format {
        fields.push(der::tlv(0x8A, &der::int(i64::from(f))[2..]));
    }
    if let Some(id) = &ti.token_id {
        fields.push(der::tlv(0x8B, id));
    }
    if let Some(a) = &ti.alg_id {
        fields.push(der::tlv(0x8C, a.as_bytes()));
    }
    if let Some(v) = &ti.vendor {
        fields.push(der::tlv(0x8D, v.as_bytes()));
    }
    Ok(der::seq(&fields))
}

impl KdcClient {
    /// AS exchange with a one-time password (RFC 6560): `kinit -T armor`
    /// for a principal the KDC wants an OTP from, answering its challenge
    /// with `value` as MIT's `kinit` does when it is typed at the "Enter
    /// OTP Token Value" prompt. Needs FAST armor
    /// ([`KdcClient::with_fast_armor`], or with the `pkinit` feature
    /// anonymous PKINIT's `auto_fast_armor`).
    ///
    /// For FreeIPA, `value` is the user's password followed by the
    /// token's code. When the KDC offers several tokens the value could
    /// be for, or a token that wants its PIN apart, use
    /// [`KdcClient::login_with_otp_by`].
    pub fn login_with_otp(&self, client: &Principal, value: &str) -> Result<Credentials> {
        self.login_with_otp_by(client, |ch| answer_with(ch, value))
    }

    /// As [`KdcClient::login_with_otp`], with `answer` choosing the token
    /// and giving the value (and any PIN) once the KDC's challenge is
    /// known: what MIT's responder or prompter does.
    pub fn login_with_otp_by(
        &self,
        client: &Principal,
        answer: impl Fn(&OtpChallenge) -> Result<OtpAnswer> + Sync,
    ) -> Result<Credentials> {
        block_on(self.login_with_otp_on(&Blocking, client, &answer))
    }

    pub(crate) async fn login_with_otp_on<N: Net>(
        &self,
        net: &N,
        client: &Principal,
        answer: &(dyn Fn(&OtpChallenge) -> Result<OtpAnswer> + Sync),
    ) -> Result<Credentials> {
        self.as_exchange(net, client, Secret::Otp(answer), self.tkt_enctypes.clone())
            .await
            .map(|(c, _)| c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokeninfo(fields: &[Vec<u8>]) -> Vec<u8> {
        der::seq(fields)
    }

    /// The challenge MIT's KDC sends (`otp_edata`): a nonce, one token
    /// with nothing but empty flags.
    fn mit_challenge(nonce: &[u8]) -> Vec<u8> {
        der::seq(&[
            der::tlv(0x80, nonce),
            der::tlv(0xA2, &tokeninfo(&[der::tlv(0x80, &[0, 0, 0, 0, 0])])),
        ])
    }

    #[test]
    fn mits_challenge_is_answered_with_the_nonce_under_the_armor_key() {
        let nonce: Vec<u8> = (0..36).collect();
        let (n, ch) = parse_challenge(&mit_challenge(&nonce)).unwrap();
        assert_eq!(n, nonce);
        assert_eq!(ch.tokens.len(), 1);
        assert_eq!(ch.service, None);
        let answer = answer_with(&ch, "123456").unwrap();
        let armor = Key::random(18).unwrap();
        let req = request(&n, &ch, &answer, &armor).unwrap();

        let f = implicit_fields("t", Reader::new(&req).expect(der::SEQUENCE).unwrap()).unwrap();
        assert_eq!(f[0].unwrap(), [0, 0, 0, 0, 0]);
        assert_eq!(f[5].unwrap(), b"123456");
        assert!(f[1].is_none() && f[6].is_none() && f[10].is_none());
        // [2] IMPLICIT EncryptedData: its fields, explicitly tagged.
        let ed = Fields::parse("EncryptedData", f[2].unwrap()).unwrap();
        assert_eq!(ed.get(0).unwrap().i32().unwrap(), 18);
        let plain = armor
            .decrypt(KU_PA_OTP_REQUEST, ed.get(2).unwrap().octets().unwrap())
            .unwrap();
        let mut want = vec![0x30, 38, 0x80, 36];
        want.extend(&nonce);
        assert_eq!(plain, want);
    }

    #[test]
    fn tokens_we_cannot_answer_for_are_dropped_as_mit_drops_them() {
        let flags = |v: u32| der::tlv(0x80, &der::flags32(v)[2..]);
        let infos = [
            tokeninfo(&[flags(OTP_FLAG_COMBINE)]),
            tokeninfo(&[flags(0), der::tlv(0x84, &[4])]), // base64
            tokeninfo(&[flags(0), der::tlv(0xA7, &[])]),  // hash algs
            tokeninfo(&[flags(0), der::tlv(0x88, &[1])]), // iterations
            tokeninfo(&[flags(0), der::tlv(0x81, b"bad\x07")]), // vendor
            tokeninfo(&[
                flags(OTP_FLAG_COLLECT_PIN),
                der::tlv(0x81, b"Acme"),
                der::tlv(0x82, b"Press the button"),
                der::tlv(0x83, &[6]),
                der::tlv(0x84, &[0]),
                der::tlv(0x85, b"tok-1"),
                der::tlv(0x86, b"HOTP"),
            ]),
        ];
        let v = der::seq(&[
            der::tlv(0x80, b"n"),
            der::tlv(0x81, b"VPN"),
            der::tlv(0xA2, &infos.concat()),
        ]);
        let (_, ch) = parse_challenge(&v).unwrap();
        assert_eq!(ch.service.as_deref(), Some("VPN"));
        assert_eq!(
            ch.tokens,
            [OtpTokenInfo {
                flags: OTP_FLAG_COLLECT_PIN,
                vendor: Some("Acme".into()),
                challenge: Some("Press the button".into()),
                length: Some(6),
                format: Some(OTP_FORMAT_DECIMAL),
                token_id: Some(b"tok-1".to_vec()),
                alg_id: Some("HOTP".into()),
            }]
        );
        // Collect-PIN, not separate: the PIN goes before the value; the
        // token's description is echoed.
        let a = OtpAnswer {
            token: 0,
            value: "123456".into(),
            pin: Some("9876".into()),
        };
        let req = request(b"n", &ch, &a, &Key::random(17).unwrap()).unwrap();
        let f = implicit_fields("t", Reader::new(&req).expect(der::SEQUENCE).unwrap()).unwrap();
        assert_eq!(f[5].unwrap(), b"9876123456");
        assert!(f[6].is_none());
        // Of the token's flags only nextOTP is echoed, as MIT does.
        assert_eq!(f[0].unwrap(), [0, 0, 0, 0, 0]);
        assert_eq!(f[10].unwrap(), [0]);
        assert_eq!(f[11].unwrap(), b"tok-1");
        assert_eq!(f[12].unwrap(), b"HOTP");
        assert_eq!(f[13].unwrap(), b"Acme");

        // Nothing supported at all is an error.
        let none = der::seq(&[der::tlv(0x80, b"n"), der::tlv(0xA2, &infos[0])]);
        assert!(parse_challenge(&none).is_err());
    }

    #[test]
    fn a_value_picks_the_token_it_fits() {
        let t = |length, format| OtpTokenInfo {
            flags: 0,
            vendor: None,
            challenge: None,
            length,
            format,
            token_id: None,
            alg_id: None,
        };
        let ch = OtpChallenge {
            service: None,
            tokens: vec![
                t(Some(6), Some(OTP_FORMAT_DECIMAL)),
                t(Some(8), Some(OTP_FORMAT_HEXADECIMAL)),
            ],
        };
        assert_eq!(answer_with(&ch, "123456").unwrap().token, 0);
        assert_eq!(answer_with(&ch, "deadbeef").unwrap().token, 1);
        assert!(answer_with(&ch, "12345").is_err());
        let both = OtpChallenge {
            service: None,
            tokens: vec![t(None, None), t(None, None)],
        };
        assert!(answer_with(&both, "x").is_err());
        // A single token takes any value, as in MIT.
        let one = OtpChallenge {
            service: None,
            tokens: vec![t(Some(6), Some(OTP_FORMAT_DECIMAL))],
        };
        assert_eq!(answer_with(&one, "abc").unwrap().token, 0);
        // A separate PIN cannot come from one value.
        let mut sep = one.clone();
        sep.tokens[0].flags = OTP_FLAG_COLLECT_PIN | OTP_FLAG_SEPARATE_PIN_REQUIRED;
        assert!(answer_with(&sep, "123456").is_err());
        let a = OtpAnswer {
            token: 0,
            value: "123456".into(),
            pin: Some("42".into()),
        };
        let req = request(b"n", &sep, &a, &Key::random(17).unwrap()).unwrap();
        let f = implicit_fields("t", Reader::new(&req).expect(der::SEQUENCE).unwrap()).unwrap();
        assert_eq!((f[5].unwrap(), f[6].unwrap()), (&b"123456"[..], &b"42"[..]));
    }
}
