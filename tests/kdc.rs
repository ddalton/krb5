//! Live tests against a real MIT KDC.
//!
//! Start one with `scripts/test-kdc.sh <dir>` and export the variables it
//! writes to `<dir>/test.env`. Without `KRB5_TEST_KDC` every test here
//! returns early, so `cargo test` stays self-contained.
//!
//! These are the tests that prove the client's wire format: the KDC
//! decrypts our PA-ENC-TIMESTAMP, verifies our TGS-REQ authenticator and
//! its checksum over the request body, and we decrypt what it sends back.

use krb5::client::{
    KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_PREAUTH_FAILED, KDC_ERR_S_PRINCIPAL_UNKNOWN,
};
use krb5::initiator::{GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG};
use krb5::{Credentials, InitiatorContext, KdcClient, KerberosContext, Keytab, Principal};

struct Env {
    client: KdcClient,
    realm: String,
    dir: String,
}

fn env() -> Option<Env> {
    let kdc = std::env::var("KRB5_TEST_KDC").ok()?;
    let realm = std::env::var("KRB5_TEST_REALM").unwrap_or_else(|_| "KRB5.TEST".into());
    let dir = std::env::var("KRB5_TEST_DIR").expect("KRB5_TEST_DIR");
    Some(Env {
        client: KdcClient::new(realm.clone(), [kdc]),
        realm,
        dir,
    })
}

macro_rules! live {
    () => {
        match env() {
            Some(e) => e,
            None => {
                eprintln!("KRB5_TEST_KDC not set; skipping live KDC test");
                return;
            }
        }
    };
}

impl Env {
    fn p(&self, name: &str) -> Principal {
        Principal::parse_in_realm(name, &self.realm).unwrap()
    }

    fn keytab(&self, file: &str) -> Keytab {
        Keytab::load(format!("{}/{file}", self.dir)).unwrap()
    }
}

/// Our initiator against our acceptor, keyed by the KDC's service ticket
/// and the keytab `kadmin` exported: both halves see MIT-made keys.
fn establish(e: &Env, svc: &Credentials) {
    let flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG;
    let (mut ini, token) = InitiatorContext::new(svc, flags).unwrap();
    let (acc, ap_rep) = KerberosContext::accept_token(&e.keytab("service.keytab"), &token).unwrap();
    assert_eq!(acc.client_principal, svc.client.to_string());
    ini.step(&ap_rep).unwrap();
    assert!(ini.is_established());

    let (ti, ta) = (
        ini.per_message_tokens().unwrap(),
        acc.per_message_tokens().unwrap(),
    );
    let wrap = ti.emit_wrap(ini.send_seq(), b"to the server").unwrap();
    assert_eq!(ta.unwrap(&wrap).unwrap().message, b"to the server");
    let mic = ta.emit_mic(1, b"to the client").unwrap();
    assert_eq!(ti.verify_mic(&mic, b"to the client").unwrap().seq, 1);
}

#[test]
fn password_login_with_preauth_then_a_service_ticket() {
    let e = live!();
    let tgt = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    assert_eq!(tgt.client, e.p("alice"));
    assert_eq!(tgt.server, Principal::krbtgt(&e.realm));
    assert!(tgt.endtime > tgt.authtime);

    let svc = e
        .client
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    assert_eq!(svc.server.components, ["host", "svc.krb5.test"]);
    assert_eq!(svc.client, tgt.client);
    establish(&e, &svc);
}

#[test]
fn password_login_without_preauth_takes_the_salt_from_the_reply() {
    let e = live!();
    let tgt = e.client.login_with_password(&e.p("bob"), "bobpw").unwrap();
    assert_eq!(tgt.client, e.p("bob"));
}

#[test]
fn every_enctype_for_the_client_key_and_the_service_ticket() {
    let e = live!();
    for et in [17, 18, 19, 20] {
        let tgt = e
            .client
            .login_with_password(&e.p(&format!("u{et}")), &format!("pw{et}"))
            .unwrap_or_else(|err| panic!("enctype {et} login: {err}"));
        let svc = e
            .client
            .service_ticket(&tgt, &e.p(&format!("svc{et}/svc.krb5.test")))
            .unwrap_or_else(|err| panic!("enctype {et} TGS: {err}"));
        assert_eq!(svc.ticket_enctype, et);
        establish(&e, &svc);
    }
}

#[test]
fn each_requested_session_enctype_is_honoured() {
    let e = live!();
    for et in [17, 18, 19, 20] {
        let c = e.client.clone().with_enctypes(&[et]);
        let tgt = c.login_with_password(&e.p("alice"), "alicepw").unwrap();
        assert_eq!(tgt.session_key.enctype(), et);
        let svc = c.service_ticket(&tgt, &e.p("host/svc.krb5.test")).unwrap();
        assert_eq!(svc.session_key.enctype(), et);
        establish(&e, &svc);
    }
}

#[test]
fn keytab_login() {
    let e = live!();
    let tgt = e
        .client
        .login_with_keytab(&e.p("robot"), &e.keytab("robot.keytab"))
        .unwrap();
    assert_eq!(tgt.client, e.p("robot"));
    let svc = e
        .client
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    establish(&e, &svc);
}

#[test]
fn a_wrong_password_is_a_preauth_failure() {
    let e = live!();
    let err = e
        .client
        .login_with_password(&e.p("alice"), "nope")
        .unwrap_err();
    assert_eq!(err.kdc_code(), Some(KDC_ERR_PREAUTH_FAILED), "{err}");
}

#[test]
fn unknown_principals_are_reported_by_code() {
    let e = live!();
    let err = e
        .client
        .login_with_password(&e.p("nobody"), "x")
        .unwrap_err();
    assert_eq!(err.kdc_code(), Some(KDC_ERR_C_PRINCIPAL_UNKNOWN), "{err}");

    let tgt = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    let err = e
        .client
        .service_ticket(&tgt, &e.p("host/missing.krb5.test"))
        .unwrap_err();
    assert_eq!(err.kdc_code(), Some(KDC_ERR_S_PRINCIPAL_UNKNOWN), "{err}");
}

/// The krb5.conf `scripts/test-kdc.sh` wrote, which MIT's own tools use
/// for this realm, is enough to find the KDC and log in.
#[test]
fn the_realms_krb5_conf_finds_the_kdc() {
    let e = live!();
    let conf = krb5::Krb5Conf::load([format!("{}/krb5.conf", e.dir)]).unwrap();
    assert_eq!(conf.default_realm(), Some(e.realm.as_str()));
    let kdc = KdcClient::from_config(&conf, &e.realm).unwrap();
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    assert_eq!(tgt.server, Principal::krbtgt(&e.realm));
}
