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
pub const GSS_C_MUTUAL_FLAG: u32 = 2;
pub const GSS_C_REPLAY_FLAG: u32 = 4;
pub const GSS_C_SEQUENCE_FLAG: u32 = 8;
pub const GSS_C_CONF_FLAG: u32 = 16;
pub const GSS_C_INTEG_FLAG: u32 = 32;

/// DER of the Kerberos 5 mechanism OID 1.2.840.113554.1.2.2.
const KRB5_MECH_OID: [u8; 11] = [
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
        Self::build(creds, flags & !GSS_C_DELEG_FLAG, None)
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
        Self::build(creds, flags | GSS_C_DELEG_FLAG, Some(forwarded))
    }

    fn build(
        creds: &Credentials,
        flags: u32,
        forwarded: Option<&Credentials>,
    ) -> Result<(Self, Vec<u8>)> {
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
            Some((CKSUMTYPE_GSSAPI, gss_checksum(flags, deleg.as_deref())?)),
            cusec,
            ctime,
            Some(&subkey),
            Some(seq_number),
        );
        let enc_auth = creds.session_key.encrypt(KU_AP_REQ_AUTH, &authenticator)?;
        let mutual = flags & GSS_C_MUTUAL_FLAG != 0;
        let ap_options = if mutual { AP_OPTS_MUTUAL_REQUIRED } else { 0 };
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

/// RFC 4121 §4.1.1 checksum: Lgth (16, little-endian), Bnd (MD5 of the
/// channel bindings; all zero for none), Flags (little-endian), and, when
/// delegating, DlgOpt (1), Dlgth and the KRB-CRED, both little-endian.
fn gss_checksum(flags: u32, deleg: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut c = Vec::with_capacity(28 + deleg.map_or(0, <[u8]>::len));
    c.extend_from_slice(&16u32.to_le_bytes());
    c.extend_from_slice(&[0u8; 16]);
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
mod tests {
    use super::*;
    use crate::acceptor::{EncType, KerberosContext, Keytab, ServiceKey};
    use crate::client::{Principal, encode_encrypted_data, encode_key};

    /// Mint a service ticket as a KDC would: EncTicketPart sealed in the
    /// service key with usage 2.
    fn mint(
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

    fn keytab_with(service: &Principal, key: &Key) -> Keytab {
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
        let c = gss_checksum(GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG, Some(b"KRBCRED")).unwrap();
        let mut want = vec![16, 0, 0, 0];
        want.extend([0u8; 16]);
        want.extend((GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG).to_le_bytes());
        want.extend([1, 0, 7, 0]); // DlgOpt 1, Dlgth 7, little-endian
        want.extend(b"KRBCRED");
        assert_eq!(c, want);
        assert!(
            gss_checksum(GSS_C_DELEG_FLAG, Some(&vec![0; 32740])).is_err(),
            "int16 limit"
        );
    }

    #[test]
    fn the_gss_checksum_is_little_endian() {
        let c = gss_checksum(GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG, None).unwrap();
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
}
