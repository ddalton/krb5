use super::*;
use crate::ChannelBindings;
use crate::client::Principal;
use crate::initiator::tests::{keytab_with, mint};
use crate::initiator::{GSS_C_CHANNEL_BOUND_FLAG, GSS_C_CONF_FLAG, GSS_C_MUTUAL_FLAG};
use crate::key::Key;

/// NTLMSSP, 1.3.6.1.4.1.311.2.2.10: a mechanism we do not have.
const NTLM_OID: [u8; 12] = [
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A,
];

fn setup() -> (Credentials, Keytab) {
    let service = Principal::parse("HTTP/web.example.com@EXAMPLE.COM").unwrap();
    let client = Principal::parse("alice@EXAMPLE.COM").unwrap();
    let service_key = Key::new(18, vec![7; 32]).unwrap();
    let session_key = Key::random(18).unwrap();
    (
        mint(&service_key, &session_key, &client, &service),
        keytab_with(&service, &service_key),
    )
}

/// Options with a replay cache of their own, to accept an AP-REQ a
/// second time.
fn fresh() -> AcceptOptions {
    AcceptOptions {
        replay_cache: Some(std::sync::Arc::new(crate::rcache::ReplayCache::new())),
        ..Default::default()
    }
}

/// Wrap tokens both ways at the sequence numbers negotiation left.
fn exchange(ini: &SpnegoInitiator, acc: &SpnegoAcceptor<'_>) {
    let ti = ini.per_message_tokens().unwrap();
    let ta = acc.context().unwrap().per_message_tokens().unwrap();
    let w = ti.emit_wrap(ini.send_seq(), b"ping").unwrap();
    let got = ta.unwrap(&w).unwrap();
    assert_eq!(
        (got.message.as_slice(), got.seq),
        (&b"ping"[..], acc.recv_seq())
    );
    let w = ta.emit_wrap(acc.send_seq(), b"pong").unwrap();
    let got = ti.unwrap(&w).unwrap();
    assert_eq!(
        (got.message.as_slice(), got.seq),
        (&b"pong"[..], ini.recv_seq())
    );
}

#[test]
fn mutual_authentication_takes_one_round_trip_and_no_mics() {
    let (creds, keytab) = setup();
    let (mut ini, token) = SpnegoInitiator::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
    let init = parse_init(&token).unwrap();
    assert_eq!(init.mechs, [KRB5_MECH_OID.to_vec()]);
    assert!(init.mic.is_none());

    let mut acc = SpnegoAcceptor::new(&keytab);
    let reply = acc.step(&token).unwrap().expect("a NegTokenResp");
    assert!(acc.is_established() && acc.is_spnego());
    let resp = parse_resp(&reply).unwrap();
    assert_eq!(resp.neg_state, Some(ACCEPT_COMPLETED));
    assert_eq!(resp.supported_mech, Some(&KRB5_MECH_OID[..]));
    assert!(resp.response_token.is_some() && resp.mic.is_none());
    let ctx = acc.context().unwrap();
    assert_eq!(ctx.client_principal, "alice@EXAMPLE.COM");
    assert_ne!(
        ctx.gss_flags & GSS_C_INTEG_FLAG,
        0,
        "SPNEGO asks for integrity"
    );

    assert_eq!(ini.step(&reply).unwrap(), None);
    assert!(ini.is_established());
    // No MICs: the sequence numbers are the Kerberos context's own.
    assert_eq!(ini.send_seq(), ini.context().send_seq());
    exchange(&ini, &acc);
}

/// Without mutual authentication Kerberos is done at once, but SPNEGO
/// still waits for the acceptor's verdict.
#[test]
fn without_mutual_authentication_the_acceptor_still_answers() {
    let (creds, keytab) = setup();
    let (mut ini, token) = SpnegoInitiator::new(&creds, GSS_C_CONF_FLAG).unwrap();
    assert!(!ini.is_established());
    let mut acc = SpnegoAcceptor::new(&keytab);
    let reply = acc.step(&token).unwrap().unwrap();
    let resp = parse_resp(&reply).unwrap();
    assert_eq!(resp.neg_state, Some(ACCEPT_COMPLETED));
    assert!(resp.response_token.is_none());
    assert_eq!(ini.step(&reply).unwrap(), None);
    assert!(ini.is_established());
    exchange(&ini, &acc);
}

/// Windows lists Microsoft's Kerberos OID first: the answer names it
/// back, and the AP-REP is framed like the AP-REQ.
#[test]
fn microsofts_kerberos_oid_is_kerberos() {
    let (creds, keytab) = setup();
    let (_, krb5_token) =
        InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG).unwrap();
    let mech_types = der::seq(&[
        MS_KRB5_OID.to_vec(),
        KRB5_MECH_OID.to_vec(),
        NTLM_OID.to_vec(),
    ]);
    let token = encode_init(&mech_types, &krb5_token, None);
    let mut acc = SpnegoAcceptor::new(&keytab);
    let reply = acc.step(&token).unwrap().unwrap();
    let resp = parse_resp(&reply).unwrap();
    assert_eq!(resp.supported_mech, Some(&MS_KRB5_OID[..]));
    assert_eq!(resp.neg_state, Some(ACCEPT_COMPLETED));
    assert!(acc.is_established());

    // A Kerberos token framed with Microsoft's OID gets an AP-REP framed
    // with it too.
    let mut ms_token = krb5_token.clone();
    let at = ms_token
        .windows(11)
        .position(|w| w == KRB5_MECH_OID)
        .unwrap();
    ms_token[at..at + 11].copy_from_slice(&MS_KRB5_OID);
    // The same authenticator again: a replay, framed differently or not.
    assert!(matches!(
        KerberosContext::accept_token(&keytab, &ms_token),
        Err(KerberosError::Replay(_))
    ));
    let (ctx, ap_rep) = KerberosContext::accept_token_with(&keytab, &ms_token, &fresh()).unwrap();
    assert_eq!(ctx.mech_oid, MS_KRB5_OID);
    assert_eq!(&ap_rep[2..13], &MS_KRB5_OID);
}

/// Kerberos second in the list: the acceptor ignores the optimistic
/// token, answers request-mic, and the MICs are then mandatory.
#[test]
fn kerberos_second_in_the_list_needs_mics_both_ways() {
    let (creds, keytab) = setup();
    let (mut krb5, ap_req) =
        InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG).unwrap();
    let mech_types = der::seq(&[NTLM_OID.to_vec(), KRB5_MECH_OID.to_vec()]);
    let token = encode_init(&mech_types, b"NTLMSSP\0...", None);
    let mut acc = SpnegoAcceptor::new(&keytab);
    let r = parse_resp(&acc.step(&token).unwrap().unwrap())
        .map(|r| {
            (
                r.neg_state,
                r.supported_mech.map(<[u8]>::to_vec),
                r.response_token.is_some(),
            )
        })
        .unwrap();
    assert_eq!(r, (Some(REQUEST_MIC), Some(KRB5_MECH_OID.to_vec()), false));
    assert!(!acc.is_established());

    // The Kerberos token, now; the acceptor answers with its MIC.
    let reply = acc
        .step(&encode_resp(ACCEPT_INCOMPLETE, None, Some(&ap_req), None))
        .unwrap()
        .unwrap();
    let resp = parse_resp(&reply).unwrap();
    assert_eq!(resp.neg_state, Some(ACCEPT_INCOMPLETE));
    assert!(!acc.is_established());
    krb5.step(resp.response_token.unwrap()).unwrap();
    let tokens = krb5.per_message_tokens().unwrap();
    let v = tokens.verify_mic(resp.mic.unwrap(), &mech_types).unwrap();
    assert_eq!(v.seq, krb5.recv_seq().unwrap());

    // A forged MIC is refused; the real one finishes it.
    let mic = tokens.emit_mic(krb5.send_seq(), &mech_types).unwrap();
    let mut probe = SpnegoAcceptor::with_options(&keytab, fresh());
    probe.step(&token).unwrap();
    probe
        .step(&encode_resp(ACCEPT_INCOMPLETE, None, Some(&ap_req), None))
        .unwrap();
    let mut forged = mic.clone();
    forged[20] ^= 1;
    let e = probe
        .step(&encode_resp(ACCEPT_INCOMPLETE, None, None, Some(&forged)))
        .unwrap_err();
    assert!(matches!(e, KerberosError::Negotiation(_)), "{e}");
    // Nothing at all is not a token.
    assert!(
        probe
            .step(&encode_resp(ACCEPT_INCOMPLETE, None, None, None))
            .is_err()
    );
    let last = acc
        .step(&encode_resp(ACCEPT_INCOMPLETE, None, None, Some(&mic)))
        .unwrap();
    assert_eq!(last, None, "MICs crossed; nothing more to say");
    assert!(acc.is_established());
    assert_eq!(acc.recv_seq(), krb5.send_seq() + 1);
    assert_eq!(acc.send_seq(), krb5.recv_seq().unwrap() + 1);
}

/// A MIC from the acceptor makes the initiator send its own (MIT's "if
/// we got a MIC, we must send a MIC"), and a forged one is refused.
#[test]
fn an_acceptor_mic_is_answered_and_checked() {
    let (creds, keytab) = setup();
    let (mut ini, token) = SpnegoInitiator::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
    let mut acc = SpnegoAcceptor::new(&keytab);
    let reply = acc.step(&token).unwrap().unwrap();
    let resp = parse_resp(&reply).unwrap();
    let ctx = acc.context().unwrap();
    let mech_types = der::seq(&[KRB5_MECH_OID.to_vec()]);
    let mic = ctx
        .per_message_tokens()
        .unwrap()
        .emit_mic(ctx.acceptor_seq.into(), &mech_types)
        .unwrap();
    let with_mic = encode_resp(
        ACCEPT_COMPLETED,
        Some(&KRB5_MECH_OID),
        resp.response_token,
        Some(&mic),
    );
    let mut forged = mic.clone();
    *forged.last_mut().unwrap() ^= 1;
    let (mut other, _) = SpnegoInitiator::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
    let bad = encode_resp(
        ACCEPT_COMPLETED,
        Some(&KRB5_MECH_OID),
        resp.response_token,
        Some(&forged),
    );
    assert!(other.step(&bad).is_err(), "a forged MIC");

    let answer = ini.step(&with_mic).unwrap().expect("our MIC");
    assert!(ini.is_established());
    let back = parse_resp(&answer).unwrap();
    assert_eq!(back.neg_state, Some(ACCEPT_COMPLETED));
    let v = ctx
        .per_message_tokens()
        .unwrap()
        .verify_mic(back.mic.unwrap(), &mech_types)
        .unwrap();
    assert_eq!(v.seq, ini.context().send_seq());
    assert_eq!(ini.send_seq(), ini.context().send_seq() + 1);
}

#[test]
fn channel_bindings_ride_through_spnego() {
    let (creds, keytab) = setup();
    let ours = ChannelBindings::new(b"tls-server-end-point:abc".to_vec());
    let theirs = ChannelBindings::new(b"tls-server-end-point:xyz".to_vec());
    let opts = |cb| AcceptOptions {
        channel_bindings: cb,
        ..Default::default()
    };
    let init = |cb: Option<&ChannelBindings>, flags| {
        let o = InitOptions {
            channel_bindings: cb,
            ..Default::default()
        };
        SpnegoInitiator::with_options(&creds, GSS_C_MUTUAL_FLAG | flags, o)
            .unwrap()
            .1
    };

    // Matching: bound.
    let mut acc = SpnegoAcceptor::with_options(&keytab, opts(Some(ours.clone())));
    acc.step(&init(Some(&ours), 0)).unwrap();
    assert_ne!(
        acc.context().unwrap().gss_flags & GSS_C_CHANNEL_BOUND_FLAG,
        0
    );
    // Different: refused.
    let mut acc = SpnegoAcceptor::with_options(&keytab, opts(Some(ours.clone())));
    let e = acc.step(&init(Some(&theirs), 0)).unwrap_err();
    assert!(matches!(e, KerberosError::BadBindings(_)), "{e}");
    // None sent: accepted, not bound...
    let mut acc = SpnegoAcceptor::with_options(&keytab, opts(Some(ours.clone())));
    acc.step(&init(None, 0)).unwrap();
    assert_eq!(
        acc.context().unwrap().gss_flags & GSS_C_CHANNEL_BOUND_FLAG,
        0
    );
    // ...unless the initiator said it binds (KERB_AP_OPTIONS_CBT).
    let mut acc = SpnegoAcceptor::with_options(&keytab, opts(Some(ours.clone())));
    let e = acc.step(&init(None, GSS_C_CHANNEL_BOUND_FLAG)).unwrap_err();
    assert!(matches!(e, KerberosError::BadBindings(_)), "{e}");
    // An acceptor without bindings ignores them, CBT or not.
    let mut acc = SpnegoAcceptor::new(&keytab);
    acc.step(&init(Some(&theirs), GSS_C_CHANNEL_BOUND_FLAG))
        .unwrap();
    assert!(acc.is_established());
}

#[test]
fn a_bare_kerberos_token_needs_no_negotiation() {
    let (creds, keytab) = setup();
    let (mut krb5, token) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
    let mut acc = SpnegoAcceptor::new(&keytab);
    let ap_rep = acc.step(&token).unwrap().expect("an AP-REP");
    assert!(acc.is_established() && !acc.is_spnego());
    krb5.step(&ap_rep).unwrap();
}

#[test]
fn no_kerberos_on_offer_is_a_negotiation_failure() {
    let (_, keytab) = setup();
    let token = encode_init(&der::seq(&[NTLM_OID.to_vec()]), b"NTLMSSP", None);
    let e = SpnegoAcceptor::new(&keytab).step(&token).unwrap_err();
    assert!(matches!(e, KerberosError::Negotiation(_)), "{e}");
    // A reject from the acceptor ends the initiator too.
    let (creds, _) = setup();
    let (mut ini, _) = SpnegoInitiator::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
    assert!(ini.step(&encode_resp(REJECT, None, None, None)).is_err());
}

/// MIT's tolerances: a NegTokenResp without its SEQUENCE tag, and a MIC
/// that only echoes the response token (some Windows versions).
#[test]
fn neg_token_resp_parses_as_leniently_as_mits() {
    let fields = [
        der::field(0, der::tlv(ENUMERATED, &[ACCEPT_INCOMPLETE])),
        der::field(2, der::octets(b"tok")),
        der::field(3, der::octets(b"tok")),
    ]
    .concat();
    let unsequenced = der::tlv(der::ctx(1), &fields);
    let r = parse_resp(&unsequenced).unwrap();
    assert_eq!(r.neg_state, Some(ACCEPT_INCOMPLETE));
    assert_eq!(r.response_token, Some(&b"tok"[..]));
    assert_eq!(r.mic, None);
    // Bad shapes.
    assert!(parse_resp(b"\xA0\x00").is_err());
    let two = der::tlv(
        der::ctx(1),
        &der::seq(&[der::field(0, der::tlv(ENUMERATED, &[0, 1]))]),
    );
    assert!(parse_resp(&two).is_err());
    assert!(parse_init(&encode_resp(0, None, None, None)).is_err());
    let empty = {
        let mut body = SPNEGO_OID.to_vec();
        body.extend(der::tlv(
            der::ctx(0),
            &der::seq(&[der::tlv(der::ctx(0), &der::seq(&[]))]),
        ));
        der::tlv(0x60, &body)
    };
    assert!(parse_init(&empty).is_err(), "no mechanisms");
}
