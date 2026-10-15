//! SPNEGO (RFC 4178): the negotiation wrapper almost every Kerberos peer
//! outside NFS speaks: HTTP `Negotiate` (RFC 4559), SMB, LDAP SASL
//! `GSS-SPNEGO`, and Windows everywhere.
//!
//! Only Kerberos 5 is negotiated, the one mechanism this crate has, under
//! its own OID or the one Microsoft got wrong (1.2.840.48018.1.2.2, which
//! Windows lists first and MIT accepts as the same thing). The state
//! machine is MIT's (`spnego_mech.c`): the initiator sends its Kerberos
//! token optimistically in the NegTokenInit, and the two sides exchange
//! `mechListMIC`s, protecting the mechanism list, exactly when MIT would.
//! That is when the acceptor did not pick the initiator's first choice
//! (`request-mic`), or when either side sends one, as Windows does.
//!
//! [`SpnegoInitiator`] and [`SpnegoAcceptor`] are driven like
//! `gss_init_sec_context` and `gss_accept_sec_context`: feed each token
//! from the peer to `step` and send back whatever it returns, until
//! `is_established`. The acceptor also takes a bare Kerberos token, which
//! some HTTP clients send under `Negotiate`, as MIT's does.
//!
//! The MICs use the context's sequence numbers, so after negotiation the
//! next per-message token's sequence number is [`SpnegoInitiator::send_seq`]
//! (or [`SpnegoAcceptor::send_seq`]), not the Kerberos context's initial
//! one.

use crate::acceptor::{AcceptOptions, KerberosContext, KerberosError, Keytab, MS_KRB5_OID};
use crate::client::{ClientError, Credentials};
use crate::der::{self, Fields, Reader};
use crate::initiator::{
    GSS_C_INTEG_FLAG, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG, InitOptions, InitiatorContext,
    KRB5_MECH_OID,
};
use crate::token::{ContextKey, PerMessageTokens};

/// DER of the SPNEGO OID, 1.3.6.1.5.5.2.
pub const SPNEGO_OID: [u8; 8] = [0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];

// NegTokenResp negState (RFC 4178 §4.2.2).
const ACCEPT_COMPLETED: u8 = 0;
const ACCEPT_INCOMPLETE: u8 = 1;
const REJECT: u8 = 2;
const REQUEST_MIC: u8 = 3;

const ENUMERATED: u8 = 0x0A;
const OID: u8 = 0x06;

fn is_krb5(oid: &[u8]) -> bool {
    oid == KRB5_MECH_OID || oid == MS_KRB5_OID
}

/// A NegTokenInit, as MIT's `get_negTokenInit` reads one.
struct NegTokenInit<'a> {
    /// The mechTypes field's content (a SEQUENCE OF OID, DER), which the
    /// mechListMIC covers.
    mech_types: &'a [u8],
    /// Each OID, DER.
    mechs: Vec<Vec<u8>>,
    mech_token: Option<&'a [u8]>,
    mic: Option<&'a [u8]>,
}

/// A NegTokenResp, as MIT's `get_negTokenResp` reads one.
#[derive(Debug)]
struct NegTokenResp<'a> {
    neg_state: Option<u8>,
    supported_mech: Option<&'a [u8]>,
    response_token: Option<&'a [u8]>,
    mic: Option<&'a [u8]>,
}

type Parsed<T> = std::result::Result<T, String>;

/// Strip the RFC 2743 framing `[APPLICATION 0] { SPNEGO OID, inner }`.
fn unframe(token: &[u8]) -> Parsed<&[u8]> {
    let mut r = Reader::new(token);
    let body = r.expect(0x60).map_err(|e| e.0)?;
    body.strip_prefix(&SPNEGO_OID[..])
        .ok_or_else(|| "not a SPNEGO token".to_string())
}

fn parse_init(token: &[u8]) -> Parsed<NegTokenInit<'_>> {
    let mut r = Reader::new(unframe(token)?);
    let choice = r
        .expect(der::ctx(0))
        .map_err(|_| "not a NegTokenInit".to_string())?;
    let f = Fields::parse_tagged("NegTokenInit", der::SEQUENCE, choice).map_err(|e| e.0)?;
    let mech_types = f.raw(0).map_err(|e| e.0)?;
    let mut list = Reader::new(mech_types).seq().map_err(|e| e.0)?;
    let mut mechs = Vec::new();
    while !list.is_empty() {
        mechs.push(der::tlv(OID, list.expect(OID).map_err(|e| e.0)?));
    }
    if mechs.is_empty() {
        return Err("NegTokenInit lists no mechanisms".into());
    }
    let octets = |n| f.opt(n).map(|mut r: Reader<'_>| r.octets()).transpose();
    Ok(NegTokenInit {
        mech_types,
        mechs,
        mech_token: octets(2).map_err(|e| e.0)?,
        mic: octets(3).map_err(|e| e.0)?,
    })
}

fn parse_resp(token: &[u8]) -> Parsed<NegTokenResp<'_>> {
    // Old Sun SPNEGO framed its responses too; MIT allows it.
    let inner = if token.first() == Some(&0x60) {
        unframe(token)?
    } else {
        token
    };
    let choice = Reader::new(inner)
        .expect(der::ctx(1))
        .map_err(|_| "not a NegTokenResp".to_string())?;
    // MIT historically tolerates a missing SEQUENCE tag.
    let content = match Reader::new(choice).next() {
        Ok((der::SEQUENCE, c)) => c,
        _ => choice,
    };
    let f = Fields::parse("NegTokenResp", content).map_err(|e| e.0)?;
    let neg_state = match f.opt(0) {
        Some(mut r) => match r.expect(ENUMERATED).map_err(|e| e.0)? {
            [s] => Some(*s),
            _ => return Err("negState is not one octet".into()),
        },
        None => None,
    };
    let supported_mech = match f.opt(1) {
        Some(_) => {
            let oid = f.raw(1).map_err(|e| e.0)?;
            Reader::new(oid).expect(OID).map_err(|e| e.0)?;
            Some(oid)
        }
        None => None,
    };
    let octets = |n| f.opt(n).map(|mut r: Reader<'_>| r.octets()).transpose();
    let response_token = octets(2).map_err(|e| e.0)?;
    let mut mic = octets(3).map_err(|e| e.0)?;
    // Some Windows versions echo the response token as the MIC; MIT
    // ignores such a MIC.
    if mic.is_some() && mic == response_token {
        mic = None;
    }
    Ok(NegTokenResp {
        neg_state,
        supported_mech,
        response_token,
        mic,
    })
}

/// MIT's `make_spnego_tokenInit_msg`.
fn encode_init(mech_types: &[u8], mech_token: &[u8], mic: Option<&[u8]>) -> Vec<u8> {
    let mut fields = vec![
        der::tlv(der::ctx(0), mech_types),
        der::field(2, der::octets(mech_token)),
    ];
    if let Some(m) = mic {
        fields.push(der::field(3, der::octets(m)));
    }
    let mut body = SPNEGO_OID.to_vec();
    body.extend_from_slice(&der::tlv(der::ctx(0), &der::seq(&fields)));
    der::tlv(0x60, &body)
}

/// MIT's `make_spnego_tokenTarg_msg`: an empty response token is left
/// out.
fn encode_resp(
    neg_state: u8,
    mech: Option<&[u8]>,
    token: Option<&[u8]>,
    mic: Option<&[u8]>,
) -> Vec<u8> {
    let mut fields = vec![der::field(0, der::tlv(ENUMERATED, &[neg_state]))];
    if let Some(m) = mech {
        fields.push(der::tlv(der::ctx(1), m));
    }
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        fields.push(der::field(2, der::octets(t)));
    }
    if let Some(m) = mic {
        fields.push(der::field(3, der::octets(m)));
    }
    der::tlv(der::ctx(1), &der::seq(&fields))
}

/// The mechListMIC bookkeeping both sides share (MIT's `sc->mic_reqd`,
/// `mic_sent`, `mic_rcvd`, and the context's sequence numbers).
#[derive(Debug)]
struct Mic {
    mech_types: Vec<u8>,
    reqd: bool,
    sent: bool,
    rcvd: bool,
    /// Sequence numbers: ours next, and the peer's next.
    send_seq: u64,
    recv_seq: u64,
    /// Whether the peer's sequence number is checked (replay or
    /// sequence detection asked for, as MIT checks it).
    check_seq: bool,
}

/// What [`Mic::handle`] decided.
struct MicOutcome {
    mic: Option<Vec<u8>>,
    complete: bool,
    /// Whether a token goes back at all (MIT's NO_TOKEN_SEND).
    send: bool,
}

impl Mic {
    /// MIT's `handle_mic` and `process_mic`. `neg_state` is what this side
    /// would say without MICs.
    fn handle(
        &mut self,
        tokens: &PerMessageTokens<ContextKey>,
        mic_in: Option<&[u8]>,
        send_mechtok: bool,
        neg_state: u8,
    ) -> Parsed<MicOutcome> {
        if mic_in.is_some() {
            if self.rcvd {
                return Err("a second mechListMIC".into());
            }
        } else if self.reqd && !send_mechtok {
            return Err("the peer's final token has no mechListMIC, which is required".into());
        }
        if let Some(m) = mic_in {
            let v = tokens
                .verify_mic(m, &self.mech_types)
                .map_err(|e| format!("mechListMIC: {e}"))?;
            if self.check_seq && v.seq != self.recv_seq {
                return Err(format!(
                    "mechListMIC has sequence number {}, expected {}",
                    v.seq, self.recv_seq
                ));
            }
            self.recv_seq = v.seq + 1;
            // "If we got a MIC, we must send a MIC."
            self.reqd = true;
            self.rcvd = true;
        }
        let mut mic = None;
        if self.reqd && !self.sent {
            mic = Some(
                tokens
                    .emit_mic(self.send_seq, &self.mech_types)
                    .map_err(|e| format!("mechListMIC: {e}"))?,
            );
            self.send_seq += 1;
            self.sent = true;
        }
        Ok(if self.sent && self.rcvd {
            MicOutcome {
                send: mic.is_some(),
                mic,
                complete: true,
            }
        } else if self.reqd {
            MicOutcome {
                mic,
                complete: false,
                send: true,
            }
        } else {
            MicOutcome {
                mic,
                complete: neg_state == ACCEPT_COMPLETED,
                send: true,
            }
        })
    }
}

/// The initiator side: `gss_init_sec_context` with the SPNEGO mechanism.
#[derive(Debug)]
pub struct SpnegoInitiator {
    krb5: InitiatorContext,
    mic: Mic,
    nego_done: bool,
    mech_complete: bool,
    established: bool,
}

impl SpnegoInitiator {
    /// Start a negotiation for `creds` (a service ticket): the
    /// NegTokenInit to send, offering Kerberos 5 with its token. `flags`
    /// are `GSS_C_*_FLAG`s; `GSS_C_INTEG_FLAG` is always added, as MIT's
    /// SPNEGO does.
    pub fn new(creds: &Credentials, flags: u32) -> Result<(Self, Vec<u8>), ClientError> {
        Self::with_options(creds, flags, InitOptions::default())
    }

    /// As [`SpnegoInitiator::new`], with delegation and channel bindings
    /// (see [`InitiatorContext::with_options`]).
    pub fn with_options(
        creds: &Credentials,
        flags: u32,
        opts: InitOptions<'_>,
    ) -> Result<(Self, Vec<u8>), ClientError> {
        let (krb5, token) = InitiatorContext::with_options(creds, flags | GSS_C_INTEG_FLAG, opts)?;
        let mech_types = der::seq(&[KRB5_MECH_OID.to_vec()]);
        let out = encode_init(&mech_types, &token, None);
        let mic = Mic {
            mech_types,
            reqd: false,
            sent: false,
            rcvd: false,
            send_seq: krb5.send_seq(),
            recv_seq: krb5.send_seq(),
            check_seq: krb5.flags() & (GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG) != 0,
        };
        let ctx = SpnegoInitiator {
            mech_complete: krb5.is_established(),
            krb5,
            mic,
            nego_done: false,
            established: false,
        };
        Ok((ctx, out))
    }

    /// Process a token from the acceptor. Returns the token to send back,
    /// if there is one (a mechListMIC); [`Self::is_established`] says
    /// whether negotiation is over.
    pub fn step(&mut self, token: &[u8]) -> Result<Option<Vec<u8>>, ClientError> {
        let bad = |m: String| ClientError::Protocol(format!("SPNEGO: {m}"));
        if self.established {
            return Err(bad("context is already established".into()));
        }
        let resp = parse_resp(token).map_err(bad)?;
        if resp.neg_state == Some(REJECT) {
            // An error token from the mechanism says why.
            if let (Some(t), false) = (resp.response_token, self.mech_complete) {
                self.krb5.step(t)?;
            }
            return Err(bad("the acceptor rejected the negotiation".into()));
        }
        let mech_token = if !self.nego_done {
            // MIT's init_ctx_nego. Kerberos is all we offered, so any
            // other choice is the acceptor's error (MIT treats both
            // Kerberos OIDs as one, for Samba).
            self.nego_done = true;
            if let Some(m) = resp.supported_mech {
                if !is_krb5(m) {
                    return Err(bad("the acceptor chose a mechanism we did not offer".into()));
                }
            }
            match resp.response_token {
                None if self.mech_complete => None,
                None => return Err(bad("the acceptor sent no Kerberos token".into())),
                // Old IIS: an empty token for "none".
                Some([]) if self.mech_complete => None,
                Some(_) if self.mech_complete => {
                    return Err(bad("a Kerberos token we did not expect".into()));
                }
                Some(t) => Some(t),
            }
        } else {
            match (self.mech_complete, resp.response_token) {
                (false, Some(t)) => Some(t),
                (true, None) => None,
                _ => return Err(bad("a missing or unexpected Kerberos token".into())),
            }
        };
        if let Some(t) = mech_token {
            self.krb5.step(t)?;
            self.mech_complete = true;
        }
        // Without mutual authentication the acceptor numbers its tokens
        // from our sequence number, as MIT's does.
        self.mic.recv_seq = self.krb5.recv_seq().unwrap_or(self.krb5.send_seq());
        let tokens = self.krb5.per_message_tokens()?;
        let outcome = self
            .mic
            .handle(&tokens, resp.mic, false, ACCEPT_INCOMPLETE)
            .map_err(bad)?;
        // MIT: done once no token need go back, or once MICs crossed.
        self.established = outcome.complete || outcome.mic.is_none();
        Ok(outcome.mic.map(|m| {
            let state = if outcome.complete {
                ACCEPT_COMPLETED
            } else {
                ACCEPT_INCOMPLETE
            };
            encode_resp(state, None, None, Some(&m))
        }))
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    /// The Kerberos context underneath.
    pub fn context(&self) -> &InitiatorContext {
        &self.krb5
    }

    /// The flags requested of Kerberos (`GSS_C_INTEG_FLAG` included).
    pub fn flags(&self) -> u32 {
        self.krb5.flags()
    }

    /// The sequence number of our next per-message token: the Kerberos
    /// context's initial one, plus one if we sent a mechListMIC.
    pub fn send_seq(&self) -> u64 {
        self.mic.send_seq
    }

    /// The sequence number the acceptor's next per-message token should
    /// carry, once established.
    pub fn recv_seq(&self) -> u64 {
        self.mic.recv_seq
    }

    /// RFC 4121 per-message tokens, keyed as the Kerberos context is.
    pub fn per_message_tokens(&self) -> Result<PerMessageTokens<ContextKey>, ClientError> {
        if !self.established {
            return Err(ClientError::Protocol("context is not established".into()));
        }
        self.krb5.per_message_tokens()
    }
}

/// The acceptor side: `gss_accept_sec_context` for SPNEGO (and for a
/// bare Kerberos token, as MIT's default acceptor credential takes both).
#[derive(Debug)]
pub struct SpnegoAcceptor<'k> {
    keytab: &'k Keytab,
    opts: AcceptOptions,
    started: bool,
    spnego: bool,
    /// The OID we answered with: the initiator's own Kerberos OID.
    mech: Vec<u8>,
    ctx: Option<KerberosContext>,
    mic: Mic,
    established: bool,
}

impl<'k> SpnegoAcceptor<'k> {
    /// An acceptor taking any key in `keytab`.
    pub fn new(keytab: &'k Keytab) -> Self {
        Self::with_options(keytab, AcceptOptions::default())
    }

    /// As [`SpnegoAcceptor::new`], with clock skew and channel bindings
    /// from `opts`.
    pub fn with_options(keytab: &'k Keytab, opts: AcceptOptions) -> Self {
        SpnegoAcceptor {
            keytab,
            opts,
            started: false,
            spnego: false,
            mech: Vec::new(),
            ctx: None,
            mic: Mic {
                mech_types: Vec::new(),
                reqd: false,
                sent: false,
                rcvd: false,
                send_seq: 0,
                recv_seq: 0,
                check_seq: false,
            },
            established: false,
        }
    }

    /// Process a token from the initiator. Returns the token to send back,
    /// if there is one; [`Self::is_established`] says whether negotiation
    /// is over.
    pub fn step(&mut self, token: &[u8]) -> Result<Option<Vec<u8>>, KerberosError> {
        let bad = |m: String| KerberosError::Negotiation(m);
        if self.established {
            return Err(bad("context is already established".into()));
        }
        if !self.started {
            self.started = true;
            if is_krb5_token(token) {
                // A bare Kerberos token, no negotiation.
                let (ctx, ap_rep) =
                    KerberosContext::accept_token_with(self.keytab, token, &self.opts)?;
                self.ctx = Some(ctx);
                self.established = true;
                return Ok((!ap_rep.is_empty()).then_some(ap_rep));
            }
            self.spnego = true;
            return self.first(token);
        }
        // MIT's acc_ctx_cont.
        let resp = parse_resp(token).map_err(bad)?;
        if resp.response_token.is_none() && resp.mic.is_none() {
            return Err(bad("a NegTokenResp with neither a token nor a MIC".into()));
        }
        if resp.supported_mech.is_some() {
            return Err(bad(
                "the initiator named a mechanism after the first token".into()
            ));
        }
        let mut neg_state = ACCEPT_INCOMPLETE;
        let mut ap_rep = Vec::new();
        if let Some(t) = resp.response_token {
            if self.ctx.is_some() {
                return Err(bad("a Kerberos token after Kerberos completed".into()));
            }
            ap_rep = self.accept(t, &mut neg_state)?;
        }
        let out = self.finish(resp.mic, &ap_rep, neg_state)?;
        Ok(out.map(|(state, mic)| encode_resp(state, None, Some(&ap_rep), mic.as_deref())))
    }

    /// MIT's acc_ctx_new and the rest of the first pass.
    fn first(&mut self, token: &[u8]) -> Result<Option<Vec<u8>>, KerberosError> {
        let bad = |m: String| KerberosError::Negotiation(m);
        let init = parse_init(token).map_err(bad)?;
        // MIT's negotiate_mech: the initiator's first mechanism we
        // support; any but its first needs MICs.
        let Some(i) = init.mechs.iter().position(|m| is_krb5(m)) else {
            return Err(bad("the initiator offers no Kerberos 5 mechanism".into()));
        };
        self.mech = init.mechs[i].clone();
        self.mic.mech_types = init.mech_types.to_vec();
        let mut neg_state = if i == 0 {
            ACCEPT_INCOMPLETE
        } else {
            REQUEST_MIC
        };
        self.mic.reqd = neg_state == REQUEST_MIC;
        let mut ap_rep = Vec::new();
        // With request-mic the optimistic token was for another mechanism.
        if let (Some(t), false) = (init.mech_token, neg_state == REQUEST_MIC) {
            ap_rep = self.accept(t, &mut neg_state)?;
        }
        let state = match self.finish(init.mic, &ap_rep, neg_state)? {
            Some((s, mic)) => (s, mic),
            None => (ACCEPT_COMPLETED, None),
        };
        // The first answer always goes back, naming the mechanism.
        Ok(Some(encode_resp(
            state.0,
            Some(&self.mech),
            Some(&ap_rep),
            state.1.as_deref(),
        )))
    }

    /// MIT's acc_ctx_call_acc: the Kerberos exchange.
    fn accept(&mut self, token: &[u8], neg_state: &mut u8) -> Result<Vec<u8>, KerberosError> {
        let (ctx, ap_rep) = KerberosContext::accept_token_with(self.keytab, token, &self.opts)?;
        self.mic.send_seq = ctx.acceptor_seq.into();
        self.mic.recv_seq = ctx.initiator_seq.into();
        self.mic.check_seq = ctx.gss_flags & (GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG) != 0;
        if !self.mic.reqd || ctx.gss_flags & GSS_C_INTEG_FLAG == 0 {
            *neg_state = ACCEPT_COMPLETED;
        }
        self.ctx = Some(ctx);
        Ok(ap_rep)
    }

    /// The MIC step once Kerberos is complete, and the decision whether
    /// we are done: `None` if no token goes back, else its negState and
    /// MIC.
    #[allow(clippy::type_complexity)]
    fn finish(
        &mut self,
        mic_in: Option<&[u8]>,
        ap_rep: &[u8],
        neg_state: u8,
    ) -> Result<Option<(u8, Option<Vec<u8>>)>, KerberosError> {
        let Some(ctx) = &self.ctx else {
            return Ok(Some((neg_state, None)));
        };
        if ctx.gss_flags & GSS_C_INTEG_FLAG == 0 {
            self.established = neg_state == ACCEPT_COMPLETED;
            return Ok(Some((neg_state, None)));
        }
        let tokens = ctx.per_message_tokens()?;
        let outcome = self
            .mic
            .handle(&tokens, mic_in, !ap_rep.is_empty(), neg_state)
            .map_err(KerberosError::Negotiation)?;
        self.established = outcome.complete;
        let state = if outcome.complete {
            ACCEPT_COMPLETED
        } else {
            ACCEPT_INCOMPLETE
        };
        Ok(outcome.send.then_some((state, outcome.mic)))
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    /// True if the initiator negotiated with SPNEGO, false if it sent a
    /// bare Kerberos token.
    pub fn is_spnego(&self) -> bool {
        self.spnego
    }

    /// The Kerberos context: who the client is, its flags, any delegated
    /// TGT, and the keys for per-message tokens.
    pub fn context(&self) -> Option<&KerberosContext> {
        self.ctx.as_ref()
    }

    /// The Kerberos context, once established.
    pub fn into_context(self) -> Option<KerberosContext> {
        self.ctx.filter(|_| self.established)
    }

    /// The sequence number of our next per-message token.
    pub fn send_seq(&self) -> u64 {
        self.mic.send_seq
    }

    /// The sequence number the initiator's next per-message token should
    /// carry.
    pub fn recv_seq(&self) -> u64 {
        self.mic.recv_seq
    }
}

/// True if `token` is framed as a Kerberos 5 token (either OID).
fn is_krb5_token(token: &[u8]) -> bool {
    Reader::new(token)
        .expect(0x60)
        .is_ok_and(|body| body.starts_with(&KRB5_MECH_OID) || body.starts_with(&MS_KRB5_OID))
}

#[cfg(any(fuzzing, test))]
pub mod fuzz;
#[cfg(test)]
mod tests;
