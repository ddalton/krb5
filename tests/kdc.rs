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

// ------------------------------------------------- credential caches vs MIT

/// True if `klist` on the PATH is MIT's. macOS ships Heimdal's in
/// /usr/bin, which reads our files but formats its output differently and
/// has no DIR: caches.
fn mit_tools_installed() -> bool {
    std::process::Command::new("klist")
        .arg("-V")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).starts_with("Kerberos 5 version"))
}

/// Run an MIT tool against the test realm, or `None` if MIT's tools are
/// not installed (the cache tests then skip; CI installs krb5-user).
fn mit(e: &Env, ccache: &str, cmd: &str, args: &[&str], stdin: Option<&str>) -> Option<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if !mit_tools_installed() {
        return None;
    }
    let mut child = Command::new(cmd)
        .args(args)
        .env("KRB5_CONFIG", format!("{}/krb5.conf", e.dir))
        .env("KRB5CCNAME", ccache)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{cmd} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).unwrap())
}

fn scratch(e: &Env, tag: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(&e.dir).join(format!("cc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    let _ = std::fs::remove_file(&p);
    p
}

/// We log in and write the cache; MIT's klist reads it and MIT's kvno
/// uses our TGT, appending its service ticket to our file, which we then
/// read back.
#[test]
fn mit_tools_use_a_cache_we_wrote() {
    let e = live!();
    let path = scratch(&e, "ours");
    let name = format!("FILE:{}", path.display());
    let tgt = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    krb5::CCache::with_credentials(&tgt).write(&path).unwrap();

    let Some(listed) = mit(&e, &name, "klist", &[], None) else {
        eprintln!("MIT's krb5 tools not on PATH; skipping");
        return;
    };
    assert!(
        listed.contains(&format!("Default principal: alice@{}", e.realm)),
        "{listed}"
    );
    assert!(
        listed.contains(&format!("krbtgt/{0}@{0}", e.realm)),
        "{listed}"
    );

    mit(&e, &name, "kvno", &["svc18/svc.krb5.test"], None).unwrap();
    let cc = krb5::CCache::read(&path).unwrap();
    let svc = e.p("svc18/svc.krb5.test");
    let st = cc.find(&svc, 0).expect("kvno's ticket is in our cache");
    establish(&e, &st);
    let _ = std::fs::remove_file(&path);
}

/// MIT's kinit writes the cache; service_ticket_cached uses its TGT,
/// stores the ticket, and MIT's klist then lists it.
#[test]
fn we_use_a_cache_mit_wrote() {
    let e = live!();
    let path = scratch(&e, "mit");
    let name = format!("FILE:{}", path.display());
    if mit(&e, &name, "kinit", &["alice"], Some("alicepw\n")).is_none() {
        eprintln!("MIT's krb5 tools not on PATH; skipping");
        return;
    }
    let cache = krb5::CacheName::parse(&name).unwrap();
    let svc = e.p("svc18/svc.krb5.test");
    let st = e.client.service_ticket_cached(&cache, &svc).unwrap();
    establish(&e, &st);

    let listed = mit(&e, &name, "klist", &[], None).unwrap();
    assert!(listed.contains("svc18/svc.krb5.test@"), "{listed}");
    // MIT's config entries survived our rewrite.
    let cc = krb5::CCache::read(&path).unwrap();
    assert!(
        cc.config("pa_type", Some(&Principal::krbtgt(&e.realm)))
            .is_some()
    );

    // Second call: served from the cache, same ticket.
    let again = e.client.service_ticket_cached(&cache, &svc).unwrap();
    assert_eq!(again.ticket, st.ticket);
    let _ = std::fs::remove_file(&path);
}

/// A DIR: collection MIT created resolves through its primary file.
#[test]
fn a_dir_collection_mit_made() {
    let e = live!();
    let dir = scratch(&e, "dir");
    let name = format!("DIR:{}", dir.display());
    if mit(&e, &name, "kinit", &["alice"], Some("alicepw\n")).is_none() {
        eprintln!("MIT's krb5 tools not on PATH; skipping");
        return;
    }
    let cache = krb5::CacheName::parse(&name).unwrap();
    let cc = cache.read().unwrap();
    assert_eq!(cc.principal.to_string(), format!("alice@{}", e.realm));
    let svc = e.p("svc18/svc.krb5.test");
    e.client.service_ticket_cached(&cache, &svc).unwrap();
    let listed = mit(&e, &name, "klist", &[], None).unwrap();
    assert!(listed.contains("svc18/svc.krb5.test@"), "{listed}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// No TGT, no service ticket: the error says so instead of asking the KDC.
#[test]
fn an_expired_cache_reports_no_tgt() {
    let e = live!();
    let path = scratch(&e, "expired");
    let mut tgt = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    // Already over when written (and non-zero, which would mean removed).
    tgt.endtime = tgt.authtime - 60;
    krb5::CCache::with_credentials(&tgt).write(&path).unwrap();
    let cache = krb5::CacheName::File(path.clone());
    let err = e
        .client
        .service_ticket_cached(&cache, &e.p("svc18/svc.krb5.test"))
        .unwrap_err();
    assert!(matches!(err, krb5::ClientError::NoTgt { .. }), "{err}");
    let _ = std::fs::remove_file(&path);
}
