//! GSS-API Kerberos initiator: `gss_init_sec_context` (RFC 4121 §4.1).
//!
//! Given a service ticket from [`crate::KdcClient::service_ticket`],
//! [`InitiatorContext::new`] emits the initial context token (a framed
//! AP-REQ). With mutual authentication the acceptor answers with an AP-REP,
//! which [`InitiatorContext::step`] verifies; the context is then
//! established and [`InitiatorContext::per_message_tokens`] provides
//! Wrap / MIC.
//!
//! Like MIT, the initiator always sends a random subkey and an initial
//! sequence number in the authenticator. If the acceptor asserts its own
//! subkey in the AP-REP (MIT does for the AES enctypes), RFC 4121 §2 makes
//! that the per-message key and sets the AcceptorSubkey token flag.

use crate::bindings::ChannelBindings;
use crate::client::krbcred;
use crate::client::{
    ClientError, Credentials, KrbError, Result, decode_encrypted_data, decode_key, encode_ap_req,
    encode_authenticator,
};
use crate::der::{self, Fields, app};
use crate::key::Key;
use crate::token::{ContextKey, PerMessageTokens, Role};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

/// RFC 2743 / RFC 4121 §4.1.1.1 context flags.
pub const GSS_C_DELEG_FLAG: u32 = 1;
/// `GSS_C_MUTUAL_FLAG`: the acceptor authenticates back with an AP-REP.
pub const GSS_C_MUTUAL_FLAG: u32 = 2;
/// `GSS_C_REPLAY_FLAG`: detect replayed per-message tokens.
pub const GSS_C_REPLAY_FLAG: u32 = 4;
/// `GSS_C_SEQUENCE_FLAG`: detect out-of-sequence per-message tokens.
pub const GSS_C_SEQUENCE_FLAG: u32 = 8;
/// `GSS_C_CONF_FLAG`: Wrap tokens may be sealed (confidentiality).
pub const GSS_C_CONF_FLAG: u32 = 16;
/// `GSS_C_INTEG_FLAG`: MIC and Wrap tokens are available (integrity).
pub const GSS_C_INTEG_FLAG: u32 = 32;
/// MIT's `GSS_C_CHANNEL_BOUND_FLAG` (MS-KILE `KERB_AP_OPTIONS_CBT`): asked
/// for, the initiator tells the acceptor it sends channel bindings, so an
/// acceptor that has bindings refuses a token without matching ones; set
/// by an acceptor, the initiator's bindings matched its own.
pub const GSS_C_CHANNEL_BOUND_FLAG: u32 = 0x800;

/// DER of the Kerberos 5 mechanism OID 1.2.840.113554.1.2.2.
pub(crate) const KRB5_MECH_OID: [u8; 11] = [
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02,
];

const TOK_AP_REQ: [u8; 2] = [0x01, 0x00];
const TOK_AP_REP: [u8; 2] = [0x02, 0x00];
const TOK_ERROR: [u8; 2] = [0x03, 0x00];

/// RFC 4121 §4.1.1 authenticator checksum type.
const CKSUMTYPE_GSSAPI: i32 = 0x8003;

// RFC 4120 §7.5.1.
const KU_AP_REQ_AUTH: u32 = 11;
const KU_AP_REP_ENC_PART: u32 = 12;

/// APOptions mutual-required, bit 2 counted from the MSB.
const AP_OPTS_MUTUAL_REQUIRED: u32 = 0x2000_0000;
/// APOptions use-session-key, bit 1: a user-to-user ticket.
const AP_OPTS_USE_SESSION_KEY: u32 = 0x4000_0000;

/// RFC 4120 §7.5.4 AD-IF-RELEVANT, and MS-KILE's AD-AUTH-DATA-AP-OPTIONS
/// with its KERB_AP_OPTIONS_CBT bit, as MIT's `make_ap_authdata` sends it.
const AD_IF_RELEVANT: i64 = 1;
const AD_AP_OPTIONS: i64 = 143;
const KERB_AP_OPTIONS_CBT: u32 = 0x4000;

/// What [`InitiatorContext::with_options`] takes besides the ticket and
/// flags.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct InitOptions<'a> {
    /// A forwarded TGT to delegate (see
    /// [`InitiatorContext::new_delegating`]).
    pub delegate: Option<&'a Credentials>,
    /// Channel bindings, hashed into the authenticator checksum (RFC 4121
    /// §4.1.1.2). Without them the hash is all zero, which every
    /// acceptor takes as "none".
    pub channel_bindings: Option<&'a ChannelBindings>,
    /// The ticket is a user-to-user one, in the session key of the
    /// acceptor's TGT ([`KdcClient::user_to_user`]): the AP-REQ says
    /// USE-SESSION-KEY (RFC 4120 §5.5.1), as MIT's `kvno --u2u` and
    /// `krb5_mk_req_extended` callers set it.
    ///
    /// [`KdcClient::user_to_user`]: crate::KdcClient::user_to_user
    pub use_session_key: bool,
}

/// The initiator side of a Kerberos GSS-API security context.
#[derive(Debug)]
pub struct InitiatorContext {
    session_key: Key,
    subkey: Key,
    acceptor_subkey: Option<Key>,
    ctime: i64,
    cusec: u32,
    seq_number: u32,
    acceptor_seq: Option<u32>,
    flags: u32,
    established: bool,
}

impl InitiatorContext {
    /// Build the initial context token for `creds` (a service ticket).
    ///
    /// `flags` are `GSS_C_*_FLAG`s. `GSS_C_DELEG_FLAG` is dropped here, as
    /// there is no TGT to delegate; see [`InitiatorContext::new_delegating`].
    /// Returns the context and the token to send to the acceptor.
    pub fn new(creds: &Credentials, flags: u32) -> Result<(Self, Vec<u8>)> {
        Self::with_options(creds, flags & !GSS_C_DELEG_FLAG, InitOptions::default())
    }

    /// As [`InitiatorContext::new`], delegating `forwarded` (a forwarded
    /// TGT, from [`KdcClient::forwarded_tgt`](crate::KdcClient::forwarded_tgt))
    /// to the acceptor, as `gss_init_sec_context` does with
    /// `GSS_C_DELEG_FLAG`: a KRB-CRED in the authenticator checksum
    /// (RFC 4121 §4.1.1), encrypted in the ticket session key as the RFC
    /// requires and MIT does. `GSS_C_DELEG_FLAG` is added to `flags`.
    pub fn new_delegating(
        creds: &Credentials,
        flags: u32,
        forwarded: &Credentials,
    ) -> Result<(Self, Vec<u8>)> {
        let opts = InitOptions {
            delegate: Some(forwarded),
            ..Default::default()
        };
        Self::with_options(creds, flags, opts)
    }

    /// As [`InitiatorContext::new`], with delegation and channel bindings
    /// as `opts` says. `GSS_C_DELEG_FLAG` is set exactly when `opts`
    /// delegates. With [`GSS_C_CHANNEL_BOUND_FLAG`] in `flags`, the
    /// authenticator also says (MS-KILE KERB_AP_OPTIONS_CBT, as MIT sends
    /// it for `client_aware_channel_bindings`) that this initiator binds,
    /// so an acceptor with bindings of its own requires them to match.
    pub fn with_options(
        creds: &Credentials,
        flags: u32,
        opts: InitOptions<'_>,
    ) -> Result<(Self, Vec<u8>)> {
        let forwarded = opts.delegate;
        let cbt = flags & GSS_C_CHANNEL_BOUND_FLAG != 0;
        let flags = match forwarded {
            Some(_) => flags | GSS_C_DELEG_FLAG,
            None => flags & !GSS_C_DELEG_FLAG,
        } & !GSS_C_CHANNEL_BOUND_FLAG;
        // (MIT keeps GSS_C_CHANNEL_BOUND_FLAG off the wire.)
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let (ctime, cusec) = (d.as_secs() as i64, d.subsec_micros());
        let subkey = Key::random(creds.session_key.enctype())?;
        // MIT keeps the initial sequence number below 2^30 so wraparound
        // never reaches the sign bit.
        let seq_number = rand::thread_rng().next_u32() & 0x3FFF_FFFF;
        let deleg = match forwarded {
            Some(f) => Some(krbcred::encode(f, &creds.session_key, ctime, cusec)?),
            None => None,
        };

        let authenticator = encode_authenticator(
            &creds.client,
            Some((
                CKSUMTYPE_GSSAPI,
                gss_checksum(flags, opts.channel_bindings, deleg.as_deref())?,
            )),
            cusec,
            ctime,
            Some(&subkey),
            Some(seq_number),
            cbt.then(cbt_authorization_data),
        );
        let enc_auth = creds.session_key.encrypt(KU_AP_REQ_AUTH, &authenticator)?;
        let mutual = flags & GSS_C_MUTUAL_FLAG != 0;
        let mut ap_options = if mutual { AP_OPTS_MUTUAL_REQUIRED } else { 0 };
        if opts.use_session_key {
            ap_options |= AP_OPTS_USE_SESSION_KEY;
        }
        let ap_req = encode_ap_req(
            ap_options,
            &creds.ticket,
            creds.session_key.enctype(),
            &enc_auth,
        );

        let ctx = InitiatorContext {
            session_key: creds.session_key.clone(),
            subkey,
            acceptor_subkey: None,
            ctime,
            cusec,
            seq_number,
            acceptor_seq: None,
            flags,
            established: !mutual,
        };
        Ok((ctx, frame(TOK_AP_REQ, &ap_req)))
    }

    /// Process the acceptor's reply token (the AP-REP, when mutual
    /// authentication was requested).
    pub fn step(&mut self, token: &[u8]) -> Result<()> {
        if self.established {
            return Err(ClientError::Protocol(
                "context is already established".into(),
            ));
        }
        let (tok_id, inner) = unframe(token)?;
        match tok_id {
            TOK_AP_REP => {}
            TOK_ERROR => return Err(KrbError::parse(inner)?.into_error()),
            other => {
                return Err(ClientError::Protocol(format!(
                    "unexpected GSS token id {other:02x?}"
                )));
            }
        }

        let f = Fields::parse_tagged("AP-REP", app(15), inner)?;
        if f.get(0)?.int()? != 5 || f.get(1)?.int()? != 15 {
            return Err(ClientError::Protocol(
                "AP-REP pvno/msg-type mismatch".into(),
            ));
        }
        let (_, cipher) = decode_encrypted_data(f.get(2)?)?;
        // RFC 4120 §5.5.2: the AP-REP is sealed with the ticket session
        // key, never a subkey.
        let plain = self.session_key.decrypt(KU_AP_REP_ENC_PART, &cipher)?;
        let p = Fields::parse_tagged("EncAPRepPart", app(27), &plain)?;

        // The echo of our own ctime/cusec is the acceptor's proof that it
        // decrypted the authenticator: that IS mutual authentication.
        if p.get(0)?.time()? != self.ctime || p.get(1)?.u32()? != self.cusec {
            return Err(ClientError::Protocol(
                "AP-REP does not echo the authenticator's ctime/cusec (KRB_AP_ERR_MUT_FAIL)".into(),
            ));
        }
        self.acceptor_subkey = p.opt(2).map(decode_key).transpose()?;
        self.acceptor_seq = p.opt(3).map(|mut r| r.u32()).transpose()?;
        self.established = true;
        Ok(())
    }

    /// True once the context is complete: after the AP-REQ without
    /// `GSS_C_MUTUAL_FLAG`, or after a verified AP-REP with it.
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// The flags actually requested (`GSS_C_DELEG_FLAG` only when
    /// delegating).
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Our initial sequence number: the first token we emit uses it.
    pub fn send_seq(&self) -> u64 {
        self.seq_number as u64
    }

    /// The acceptor's initial sequence number, if its AP-REP carried one.
    pub fn recv_seq(&self) -> Option<u64> {
        self.acceptor_seq.map(u64::from)
    }

    /// True when the acceptor asserted its own subkey.
    pub fn has_acceptor_subkey(&self) -> bool {
        self.acceptor_subkey.is_some()
    }

    /// RFC 4121 per-message token machinery for this context.
    ///
    /// The base key is the acceptor subkey if the acceptor sent one,
    /// otherwise our own subkey (RFC 4121 §2). The ticket session key is
    /// never used here because the initiator always sends a subkey.
    pub fn per_message_tokens(&self) -> Result<PerMessageTokens<ContextKey>> {
        if !self.established {
            return Err(ClientError::Protocol("context is not established".into()));
        }
        let (key, acceptor_subkey) = match &self.acceptor_subkey {
            Some(k) => (k, true),
            None => (&self.subkey, false),
        };
        let ck = ContextKey::new(key.enctype(), key.bytes())
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        Ok(PerMessageTokens::new(ck, Role::Initiator, acceptor_subkey))
    }
}

/// AuthorizationData holding one AD-IF-RELEVANT that holds
/// AD-AUTH-DATA-AP-OPTIONS with KERB_AP_OPTIONS_CBT (little-endian).
fn cbt_authorization_data() -> Vec<u8> {
    let element = |ty: i64, data: &[u8]| {
        der::seq(&[
            der::field(0, der::int(ty)),
            der::field(1, der::octets(data)),
        ])
    };
    let inner = der::seq(&[element(AD_AP_OPTIONS, &KERB_AP_OPTIONS_CBT.to_le_bytes())]);
    der::seq(&[element(AD_IF_RELEVANT, &inner)])
}

/// RFC 4121 §4.1.1 checksum: Lgth (16, little-endian), Bnd (MD5 of the
/// channel bindings; all zero for none), Flags (little-endian), and, when
/// delegating, DlgOpt (1), Dlgth and the KRB-CRED, both little-endian.
fn gss_checksum(
    flags: u32,
    bindings: Option<&ChannelBindings>,
    deleg: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut c = Vec::with_capacity(28 + deleg.map_or(0, <[u8]>::len));
    c.extend_from_slice(&16u32.to_le_bytes());
    c.extend_from_slice(&bindings.map_or([0u8; 16], ChannelBindings::md5));
    c.extend_from_slice(&flags.to_le_bytes());
    if let Some(d) = deleg {
        // MIT's KRB5KRB_ERR_FIELD_TOOLONG: the checksum must fit an int16.
        if d.len() + 28 > i16::MAX as usize {
            return Err(ClientError::Protocol(
                "delegated credentials too long".into(),
            ));
        }
        c.extend_from_slice(&1u16.to_le_bytes());
        c.extend_from_slice(&(d.len() as u16).to_le_bytes());
        c.extend_from_slice(d);
    }
    Ok(c)
}

/// RFC 2743 §3.1 InitialContextToken framing, which RFC 4121 §4.1 also
/// applies to the AP-REP and error tokens:
/// `[APPLICATION 0] { mech OID, TOK_ID, inner }`.
fn frame(tok_id: [u8; 2], inner: &[u8]) -> Vec<u8> {
    let mut body = KRB5_MECH_OID.to_vec();
    body.extend_from_slice(&tok_id);
    body.extend_from_slice(inner);
    der::tlv(0x60, &body)
}

fn unframe(token: &[u8]) -> Result<([u8; 2], &[u8])> {
    let body = der::Reader::new(token).expect(0x60)?;
    let rest = body
        .strip_prefix(&KRB5_MECH_OID[..])
        .ok_or_else(|| ClientError::Protocol("token is not for the Kerberos 5 mechanism".into()))?;
    if rest.len() < 2 {
        return Err(ClientError::Protocol("token too short for a TOK_ID".into()));
    }
    Ok(([rest[0], rest[1]], &rest[2..]))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::acceptor::{EncType, KerberosContext, Keytab, ServiceKey};
    use crate::client::{Principal, encode_encrypted_data, encode_key};

    /// Mint a service ticket as a KDC would: EncTicketPart sealed in the
    /// service key with usage 2.
    pub(crate) fn mint(
        service_key: &Key,
        session_key: &Key,
        client: &Principal,
        service: &Principal,
    ) -> Credentials {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let enc_ticket_part = der::cons(
            app(3),
            &[der::seq(&[
                der::field(0, der::flags32(0)),
                der::field(1, encode_key(session_key)),
                der::field(2, der::general_string(&client.realm)),
                der::field(3, client.encode_name()),
                der::field(
                    4,
                    der::seq(&[der::field(0, der::int(1)), der::field(1, der::octets(b""))]),
                ),
                der::field(5, der::time(now)),
                der::field(7, der::time(now + 3600)),
            ])],
        );
        let cipher = service_key.encrypt(2, &enc_ticket_part).unwrap();
        let ticket = der::cons(
            app(1),
            &[der::seq(&[
                der::field(0, der::int(5)),
                der::field(1, der::general_string(&service.realm)),
                der::field(2, service.encode_name()),
                der::field(3, encode_encrypted_data(service_key.enctype(), &cipher)),
            ])],
        );
        Credentials {
            client: client.clone(),
            server: service.clone(),
            session_key: session_key.clone(),
            ticket,
            ticket_enctype: service_key.enctype(),
            flags: 0,
            authtime: now,
            starttime: None,
            endtime: now + 3600,
            renew_till: None,
        }
    }

    pub(crate) fn keytab_with(service: &Principal, key: &Key) -> Keytab {
        Keytab::from_keys(vec![ServiceKey {
            principal: service.name(),
            realm: service.realm.clone(),
            kvno: 1,
            enctype: EncType::from_i32(key.enctype()).unwrap(),
            key: key.bytes().to_vec(),
        }])
    }

    #[test]
    fn tokens_are_framed_with_the_krb5_mechanism() {
        let t = frame(TOK_AP_REQ, b"x");
        assert_eq!(&t[..2], &[0x60, 14]);
        assert_eq!(unframe(&t).unwrap(), (TOK_AP_REQ, &b"x"[..]));
        let mut wrong = t.clone();
        wrong[12] ^= 1;
        assert!(unframe(&wrong).is_err());
    }

    #[test]
    fn the_gss_checksum_carries_a_krb_cred_after_the_flags() {
        let c = gss_checksum(GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG, None, Some(b"KRBCRED")).unwrap();
        let mut want = vec![16, 0, 0, 0];
        want.extend([0u8; 16]);
        want.extend((GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG).to_le_bytes());
        want.extend([1, 0, 7, 0]); // DlgOpt 1, Dlgth 7, little-endian
        want.extend(b"KRBCRED");
        assert_eq!(c, want);
        assert!(
            gss_checksum(GSS_C_DELEG_FLAG, None, Some(&vec![0; 32740])).is_err(),
            "int16 limit"
        );
    }

    /// The KERB_AP_OPTIONS_CBT element exactly as MIT's `make_ap_authdata`
    /// encodes it (and MS-KILE lays it out): AD-IF-RELEVANT (1) holding
    /// AD-AUTH-DATA-AP-OPTIONS (143) holding 0x4000 little-endian.
    #[test]
    fn the_cbt_authorization_data_is_mits() {
        assert_eq!(
            cbt_authorization_data(),
            [
                0x30, 0x1D, 0x30, 0x1B, // AuthorizationData, one element
                0xA0, 0x03, 0x02, 0x01, 0x01, // ad-type 1, AD-IF-RELEVANT
                0xA1, 0x14, 0x04, 0x12, // ad-data: AuthorizationData, DER
                0x30, 0x10, 0x30, 0x0E, //
                0xA0, 0x04, 0x02, 0x02, 0x00, 0x8F, // ad-type 143
                0xA1, 0x06, 0x04, 0x04, 0x00, 0x40, 0x00, 0x00, // 0x4000 LE
            ]
        );
    }

    /// GSS_C_CHANNEL_BOUND_FLAG asks for the CBT element; it is not a
    /// flag for the wire, which MIT also keeps it off.
    #[test]
    fn channel_bound_stays_off_the_wire() {
        let service = Principal::parse("host/h@R").unwrap();
        let key = Key::new(18, vec![1; 32]).unwrap();
        let creds = mint(
            &key,
            &Key::random(18).unwrap(),
            &Principal::parse("a@R").unwrap(),
            &service,
        );
        let flags = GSS_C_MUTUAL_FLAG | GSS_C_CHANNEL_BOUND_FLAG;
        let (ctx, token) = InitiatorContext::new(&creds, flags).unwrap();
        assert_eq!(ctx.flags(), GSS_C_MUTUAL_FLAG);
        let (acc, _) = KerberosContext::accept_token(&keytab_with(&service, &key), &token).unwrap();
        assert_eq!(acc.gss_flags, GSS_C_MUTUAL_FLAG);
    }

    #[test]
    fn the_gss_checksum_is_little_endian() {
        let c = gss_checksum(GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG, None, None).unwrap();
        assert_eq!(c.len(), 24);
        assert_eq!(&c[..4], &[16, 0, 0, 0]);
        assert_eq!(&c[20..], &[0x22, 0, 0, 0]);
    }

    /// Our initiator against our acceptor, for every enctype, with and
    /// without mutual authentication. A self-test, so it proves only that
    /// the two halves agree; the live KDC and MIT tests prove the wire.
    #[test]
    fn initiator_and_acceptor_establish_and_exchange_tokens() {
        let client = Principal::parse("alice@R").unwrap();
        let service = Principal::parse("host/svc@R").unwrap();
        for et in [17, 18, 19, 20] {
            for mutual in [false, true] {
                let service_key = Key::random(et).unwrap();
                let creds = mint(&service_key, &Key::random(et).unwrap(), &client, &service);
                let kt = keytab_with(&service, &service_key);

                let flags =
                    GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG | if mutual { GSS_C_MUTUAL_FLAG } else { 0 };
                let (mut ini, token) = InitiatorContext::new(&creds, flags).unwrap();
                assert_eq!(ini.is_established(), !mutual);

                let (acc, ap_rep) = KerberosContext::accept_token(&kt, &token).unwrap();
                assert_eq!(acc.client_principal, "alice@R");
                assert!(acc.used_initiator_subkey);
                if mutual {
                    ini.step(&ap_rep).unwrap();
                } else {
                    assert!(ap_rep.is_empty());
                }
                assert!(ini.is_established());

                let ini_t = ini.per_message_tokens().unwrap();
                let acc_t = acc.per_message_tokens().unwrap();
                let mic = ini_t.emit_mic(ini.send_seq(), b"hello").unwrap();
                assert_eq!(
                    acc_t.verify_mic(&mic, b"hello").unwrap().seq,
                    ini.send_seq()
                );
                let wrap = acc_t.emit_wrap(7, b"secret").unwrap();
                assert_eq!(ini_t.unwrap(&wrap).unwrap().message, b"secret");
            }
        }
    }

    #[test]
    fn an_ap_rep_that_does_not_echo_our_timestamp_is_refused() {
        let client = Principal::parse("alice@R").unwrap();
        let service = Principal::parse("host/svc@R").unwrap();
        let sk = Key::random(18).unwrap();
        let session = Key::random(18).unwrap();
        let creds = mint(&sk, &session, &client, &service);
        let (mut ini, _) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();

        let enc_part = der::cons(
            app(27),
            &[der::seq(&[
                der::field(0, der::time(ini.ctime - 1)),
                der::field(1, der::int(ini.cusec as i64)),
            ])],
        );
        let ap_rep = der::cons(
            app(15),
            &[der::seq(&[
                der::field(0, der::int(5)),
                der::field(1, der::int(15)),
                der::field(
                    2,
                    encode_encrypted_data(18, &session.encrypt(12, &enc_part).unwrap()),
                ),
            ])],
        );
        let err = ini.step(&frame(TOK_AP_REP, &ap_rep)).unwrap_err();
        assert!(err.to_string().contains("MUT_FAIL"), "{err}");
        assert!(!ini.is_established());
    }

    #[test]
    fn an_acceptor_subkey_becomes_the_token_key() {
        let client = Principal::parse("alice@R").unwrap();
        let service = Principal::parse("host/svc@R").unwrap();
        let session = Key::random(20).unwrap();
        let creds = mint(&Key::random(20).unwrap(), &session, &client, &service);
        let (mut ini, _) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();

        let acc_sub = Key::random(20).unwrap();
        let enc_part = der::cons(
            app(27),
            &[der::seq(&[
                der::field(0, der::time(ini.ctime)),
                der::field(1, der::int(ini.cusec as i64)),
                der::field(2, encode_key(&acc_sub)),
                der::field(3, der::int(12345)),
            ])],
        );
        let ap_rep = der::cons(
            app(15),
            &[der::seq(&[
                der::field(0, der::int(5)),
                der::field(1, der::int(15)),
                der::field(
                    2,
                    encode_encrypted_data(20, &session.encrypt(12, &enc_part).unwrap()),
                ),
            ])],
        );
        ini.step(&frame(TOK_AP_REP, &ap_rep)).unwrap();
        assert!(ini.has_acceptor_subkey());
        assert_eq!(ini.recv_seq(), Some(12345));

        // A token from an acceptor keyed on its subkey, with the flag set.
        let ck = ContextKey::new(20, acc_sub.bytes()).unwrap();
        let acc_t = PerMessageTokens::new(ck, Role::Acceptor, true);
        let wrap = acc_t.emit_wrap(12345, b"via subkey").unwrap();
        assert_eq!(
            ini.per_message_tokens()
                .unwrap()
                .unwrap(&wrap)
                .unwrap()
                .message,
            b"via subkey"
        );
    }

    fn u2u_setup() -> (Credentials, Credentials) {
        // The server's TGT: only its session key matters to the acceptor.
        let server = Principal::parse("bob@EXAMPLE.COM").unwrap();
        let krbtgt = Principal::krbtgt("EXAMPLE.COM");
        let tgt_session = Key::random(18).unwrap();
        let server_tgt = mint(&Key::random(18).unwrap(), &tgt_session, &server, &krbtgt);
        // A ticket for bob in that session key, as the KDC issues one
        // with ENC-TKT-IN-SKEY.
        let alice = Principal::parse("alice@EXAMPLE.COM").unwrap();
        let u2u = mint(&tgt_session, &Key::random(18).unwrap(), &alice, &server);
        (server_tgt, u2u)
    }

    #[test]
    fn a_user_to_user_ticket_is_accepted_with_the_tgt_session_key() {
        let (server_tgt, creds) = u2u_setup();
        let opts = InitOptions {
            use_session_key: true,
            ..Default::default()
        };
        let (mut ini, token) =
            InitiatorContext::with_options(&creds, GSS_C_MUTUAL_FLAG, opts).unwrap();
        let (_, ap_req) = unframe(&token).unwrap();
        // USE-SESSION-KEY and MUTUAL-REQUIRED: 0x60 in the first octet.
        let at = ap_req
            .windows(3)
            .position(|w| w == [0x03, 0x05, 0x00])
            .unwrap();
        assert_eq!(ap_req[at + 3], 0x60);

        let (ctx, rep) =
            KerberosContext::accept_token_u2u(&server_tgt, &token, &Default::default()).unwrap();
        assert_eq!(ctx.client_principal, "alice@EXAMPLE.COM");
        assert_eq!(ctx.service_principal, "bob@EXAMPLE.COM");
        ini.step(&rep).unwrap();
        assert!(ini.is_established());

        // Not with a keytab (there is none for bob), nor another TGT.
        let other = u2u_setup().0;
        let (_, token) = InitiatorContext::with_options(&creds, 0, opts).unwrap();
        assert!(KerberosContext::accept_token_u2u(&other, &token, &Default::default()).is_err());
        let kt = keytab_with(&server_tgt.client, &Key::random(18).unwrap());
        assert!(KerberosContext::accept_token(&kt, &token).is_err());
    }

    /// A bare AP-REQ (no GSS framing) and its bare AP-REP, as MIT's
    /// `krb5_rd_req` and `krb5_mk_rep` exchange them.
    #[test]
    fn a_bare_ap_req_is_accepted_and_answered_with_a_bare_ap_rep() {
        let (server_tgt, creds) = u2u_setup();
        let (_, token) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
        let (_, ap_req) = unframe(&token).unwrap();
        let (ctx, rep) =
            KerberosContext::accept_ap_req_u2u(&server_tgt, ap_req, &Default::default()).unwrap();
        assert_eq!(ctx.client_principal, "alice@EXAMPLE.COM");
        assert!(ctx.mech_oid.is_empty());
        // The GSS checksum of a GSS token is not a bare AP-REQ's business.
        assert_eq!(ctx.gss_flags, 0);
        assert_eq!(rep[0], 0x6F, "AP-REP, [APPLICATION 15]");
        // And with a keytab.
        let service = Principal::parse("host/a.example.com@EXAMPLE.COM").unwrap();
        let key = Key::random(17).unwrap();
        let creds = mint(&key, &Key::random(17).unwrap(), &creds.client, &service);
        let (_, token) = InitiatorContext::new(&creds, 0).unwrap();
        let (_, ap_req) = unframe(&token).unwrap();
        let (ctx, rep) = KerberosContext::accept_ap_req(
            &keytab_with(&service, &key),
            ap_req,
            &Default::default(),
        )
        .unwrap();
        assert_eq!(ctx.service_principal, "host/a.example.com@EXAMPLE.COM");
        assert!(rep.is_empty(), "no AP-REP without MUTUAL-REQUIRED");
    }

    /// RFC 4120 §3.2.3: the same authenticator twice is refused, by
    /// default; a new one for the same ticket is not, and nor is anything
    /// with replay detection off.
    #[test]
    fn an_authenticator_is_accepted_once() {
        let service = Principal::parse("host/r.example.com@EXAMPLE.COM").unwrap();
        let key = Key::random(20).unwrap();
        let creds = mint(&key, &Key::random(20).unwrap(), &service, &service);
        let kt = keytab_with(&service, &key);
        let (_, token) = InitiatorContext::new(&creds, 0).unwrap();
        KerberosContext::accept_token(&kt, &token).unwrap();
        let e = KerberosContext::accept_token(&kt, &token).unwrap_err();
        assert!(matches!(e, crate::KerberosError::Replay(_)), "{e}");
        // Bare, the same authenticator is the same replay.
        let (_, ap_req) = unframe(&token).unwrap();
        assert!(matches!(
            KerberosContext::accept_ap_req(&kt, ap_req, &Default::default()),
            Err(crate::KerberosError::Replay(_))
        ));
        let (_, again) = InitiatorContext::new(&creds, 0).unwrap();
        KerberosContext::accept_token(&kt, &again).unwrap();
        let off = crate::acceptor::AcceptOptions {
            replay_cache: None,
            ..Default::default()
        };
        KerberosContext::accept_token_with(&kt, &token, &off).unwrap();
        KerberosContext::accept_token_with(&kt, &token, &off).unwrap();
    }

    /// Not a test: `cargo test --release --lib -- --ignored hot_paths
    /// --nocapture` prints what the per-request and per-message work
    /// costs, for each enctype.
    #[test]
    #[ignore]
    fn hot_paths() {
        use crate::acceptor::AcceptOptions;
        use std::time::Instant;
        fn per<T>(n: u32, mut f: impl FnMut() -> T) -> std::time::Duration {
            for _ in 0..n / 10 {
                std::hint::black_box(f());
            }
            let t = Instant::now();
            for _ in 0..n {
                std::hint::black_box(f());
            }
            t.elapsed() / n
        }
        let opts = AcceptOptions {
            replay_cache: None,
            ..Default::default()
        };
        for et in [17, 18, 19, 20] {
            let service = Principal::parse("host/p.example.com@EXAMPLE.COM").unwrap();
            let key = Key::random(et).unwrap();
            let creds = mint(&key, &Key::random(et).unwrap(), &service, &service);
            let kt = keytab_with(&service, &key);
            let (_, token) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
            let init = per(2000, || {
                InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).unwrap()
            });
            let accept = per(2000, || {
                KerberosContext::accept_token_with(&kt, &token, &opts).unwrap()
            });
            let rc = AcceptOptions::default();
            let accept_rc = per(2000, || {
                let (_, t) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
                KerberosContext::accept_token_with(&kt, &t, &rc).unwrap()
            }) - init;
            let (ctx, _) = KerberosContext::accept_token_with(&kt, &token, &opts).unwrap();
            let ta = ctx.per_message_tokens().unwrap();
            let s2k = per(20, || {
                let e = crate::kdf::Enctype::from_i32(et).unwrap();
                crate::kdf::string_to_key(e, b"password", b"EXAMPLE.COMuser", None).unwrap()
            });
            let mut line = format!(
                "etype {et}: init {init:?}  accept {accept:?}  accept+replay-cache {accept_rc:?}  string-to-key {s2k:?}"
            );
            for size in [64usize, 1024, 65536] {
                let msg = vec![0x5Au8; size];
                let n = if size > 4096 { 200 } else { 5000 };
                let w = ta.emit_wrap(1, &msg).unwrap();
                let wrap = per(n, || ta.emit_wrap(1, &msg).unwrap());
                let ti = PerMessageTokens::new(
                    crate::token::ContextKey::new(ctx.base_key_enctype as i32, &ctx.base_key)
                        .unwrap(),
                    crate::token::Role::Initiator,
                    false,
                );
                let unwrap = per(n, || ti.unwrap(&w).unwrap());
                let mic = per(n, || ta.emit_mic(1, &msg).unwrap());
                line +=
                    &format!("\n    {size:>6} B: wrap {wrap:?}  unwrap {unwrap:?}  mic {mic:?}");
            }
            eprintln!("{line}");
        }
    }
}
