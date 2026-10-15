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
    /// The live tests share one KDC and some count its log lines, so they
    /// run one at a time.
    _serial: std::sync::MutexGuard<'static, ()>,
}

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn env() -> Option<Env> {
    let kdc = std::env::var("KRB5_TEST_KDC").ok()?;
    let realm = std::env::var("KRB5_TEST_REALM").unwrap_or_else(|_| "KRB5.TEST".into());
    let dir = std::env::var("KRB5_TEST_DIR").expect("KRB5_TEST_DIR");
    Some(Env {
        client: KdcClient::new(realm.clone(), [kdc]),
        realm,
        dir,
        // A failed test poisons the lock; the others should still run.
        _serial: SERIAL.lock().unwrap_or_else(|p| p.into_inner()),
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
    establish_with(e, svc, "service.keytab");
}

/// [`establish`] against the acceptor holding `keytab` (for services in
/// the other test realms).
fn establish_with(e: &Env, svc: &Credentials, keytab: &str) {
    let flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG;
    let (mut ini, token) = InitiatorContext::new(svc, flags).unwrap();
    let (acc, ap_rep) = KerberosContext::accept_token(&e.keytab(keytab), &token).unwrap();
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

// ------------------------------------------------------- KCM vs a daemon

/// A KCM cache name of our own for `tag`, if `KRB5_TEST_KCM` is set (a KCM
/// daemon is listening on the default socket, or on `KRB5_TEST_KCM_SOCKET`).
fn kcm_name(tag: &str) -> Option<krb5::CacheName> {
    std::env::var_os("KRB5_TEST_KCM")?;
    let uid = std::process::Command::new("id").arg("-u").output().unwrap();
    let uid = String::from_utf8(uid.stdout).unwrap().trim().to_string();
    let conf = match std::env::var("KRB5_TEST_KCM_SOCKET") {
        Ok(s) => krb5::Krb5Conf::parse(&format!("[libdefaults]\n kcm_socket = {s}\n")).unwrap(),
        Err(_) => krb5::Krb5Conf::empty(),
    };
    Some(
        krb5::CacheName::parse_with(
            &format!("KCM:{uid}:krb5-rs-{tag}-{}", std::process::id()),
            &conf,
        )
        .unwrap(),
    )
}

/// Asking for the KCM tests means a daemon and MIT's tools are there; a
/// missing tool is a failure, not a skip that would pass CI vacuously.
const NEED_MIT: &str = "KRB5_TEST_KCM is set but MIT's krb5 tools are not on PATH";

macro_rules! kcm {
    ($tag:expr) => {
        match kcm_name($tag) {
            Some(n) => n,
            None => {
                eprintln!("KRB5_TEST_KCM not set; skipping KCM test");
                return;
            }
        }
    };
}

/// We write a KCM cache; MIT's klist lists it and MIT's kvno adds a
/// ticket to it with our TGT, which we then read back and use.
#[test]
fn kcm_mit_tools_use_a_cache_we_wrote() {
    let e = live!();
    let cache = kcm!("ours");
    let tgt = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    cache.write(&krb5::CCache::with_credentials(&tgt)).unwrap();

    let name = cache.to_string();
    let listed = mit(&e, &name, "klist", &[], None).expect(NEED_MIT);
    assert!(
        listed.contains(&format!("Default principal: alice@{}", e.realm)),
        "{listed}"
    );
    mit(&e, &name, "kvno", &["svc18/svc.krb5.test"], None).unwrap();

    let cc = cache.read().unwrap();
    let st = cc
        .find(&e.p("svc18/svc.krb5.test"), 0)
        .expect("kvno's ticket is in the KCM cache");
    establish(&e, &st);
    let _ = mit(&e, &name, "kdestroy", &[], None);
}

/// MIT's kinit fills a KCM cache; we buy a service ticket with its TGT and
/// store it, and MIT's klist sees it.
#[test]
fn kcm_we_use_a_cache_mit_wrote() {
    let e = live!();
    let cache = kcm!("mit");
    let name = cache.to_string();
    mit(&e, &name, "kinit", &["alice"], Some("alicepw\n")).expect(NEED_MIT);
    let svc = e.p("svc18/svc.krb5.test");
    let st = e.client.service_ticket_cached(&cache, &svc).unwrap();
    establish(&e, &st);
    let listed = mit(&e, &name, "klist", &[], None).unwrap();
    assert!(listed.contains("svc18/svc.krb5.test@"), "{listed}");
    let again = e.client.service_ticket_cached(&cache, &svc).unwrap();
    assert_eq!(
        again.ticket, st.ticket,
        "served from the cache the second time"
    );
    let _ = mit(&e, &name, "kdestroy", &[], None);
}

// ------------------------------------------------------------ DNS discovery

/// A one-record DNS server: SRV `_kerberos._tcp.<realm>.` -> `localhost.`
/// on `port`, NXDOMAIN for anything else. Built by hand here so it shares
/// no code with the resolver it is testing.
fn srv_server(realm: &str, port: u16) -> std::net::SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let want = format!("_kerberos._tcp.{}.", realm.to_ascii_lowercase());
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let q = &buf[..n];
            // Question name, as dotted lower case, and where it ends.
            let (mut at, mut name) = (12, String::new());
            while q[at] != 0 {
                let l = q[at] as usize;
                name.push_str(
                    &String::from_utf8_lossy(&q[at + 1..at + 1 + l]).to_ascii_lowercase(),
                );
                name.push('.');
                at += 1 + l;
            }
            let qend = at + 5;
            let qtype = u16::from_be_bytes([q[at + 1], q[at + 2]]);
            let mut r = q[..qend].to_vec();
            r[2] = 0x81;
            if name == want && qtype == 33 {
                r[3] = 0x80;
                r[7] = 1; // one answer
                r.extend_from_slice(&[0xC0, 12, 0, 33, 0, 1, 0, 0, 0, 60]);
                let mut rdata = vec![0, 0, 0, 0];
                rdata.extend_from_slice(&port.to_be_bytes());
                rdata.extend_from_slice(b"\x09localhost\x00");
                r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                r.extend_from_slice(&rdata);
            } else {
                r[3] = 0x83; // NXDOMAIN
            }
            sock.send_to(&r, from).unwrap();
        }
    });
    addr
}

/// No kdc in krb5.conf: the client finds the KDC through an SRV record,
/// and the login works.
#[test]
fn a_kdc_found_through_dns_srv() {
    let e = live!();
    let port: u16 = std::env::var("KRB5_TEST_KDC")
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let resolver = krb5::dns::Resolver::new(vec![srv_server(&e.realm, port)]);
    let kdc = KdcClient::from_config_with_resolver(&krb5::Krb5Conf::empty(), &e.realm, &resolver)
        .unwrap();
    assert_eq!(kdc.kdcs(), [format!("localhost.:{port}")]);
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    assert_eq!(tgt.server, Principal::krbtgt(&e.realm));
}

/// Our resolver, through the system's nameservers, against dig, for
/// public realms' real records. Needs the network: KRB5_TEST_DNS=1.
#[test]
fn dns_answers_agree_with_dig() {
    use krb5::dns::{Record, Resolver};
    if std::env::var_os("KRB5_TEST_DNS").is_none() {
        eprintln!("KRB5_TEST_DNS not set; skipping");
        return;
    }
    let r = Resolver::system().unwrap();
    let cases = [
        ("_kerberos._udp.athena.mit.edu.", 33u16, "SRV"),
        ("_kerberos._tcp.fedoraproject.org.", 33, "SRV"),
        ("_kerberos.fedoraproject.org.", 256, "URI"),
        ("_kerberos.demo1.freeipa.org.", 256, "URI"),
    ];
    let mut compared = 0;
    for (name, qtype, kind) in cases {
        let dig = std::process::Command::new("dig")
            .args(["+short", kind, name])
            .output()
            .expect("dig");
        let mut want: Vec<String> = String::from_utf8(dig.stdout)
            .unwrap()
            .lines()
            .map(|l| l.trim().to_ascii_lowercase())
            // dig reports retries (";; communications error ... timed out")
            // on stdout among the records.
            .filter(|l| !l.is_empty() && !l.starts_with(";;"))
            .collect();
        let mut got: Vec<String> = r
            .query(name, qtype)
            .unwrap()
            .into_iter()
            .map(|rec| match rec {
                Record::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } => format!("{priority} {weight} {port} {target}"),
                Record::Uri {
                    priority,
                    weight,
                    target,
                } => format!("{priority} {weight} \"{target}\"").to_ascii_lowercase(),
            })
            .collect();
        want.sort();
        got.sort();
        assert_eq!(got, want, "{kind} {name}");
        if want.is_empty() {
            // Some resolver chains drop types they do not know (systemd-
            // resolved behind Lima's DNS returns no URI records at all).
            eprintln!("no {kind} for {name} through this resolver; nothing to compare");
        } else {
            compared += 1;
        }
    }
    assert!(
        compared > 0,
        "no case had records; the test's names are stale"
    );
}

// ---------------------------------------------------------- cross-realm

/// A client that finds every test realm's KDC through the realm's
/// krb5.conf, if scripts/test-kdc.sh made the cross-realm realms.
fn cross(e: &Env) -> Option<(KdcClient, krb5::Krb5Conf)> {
    std::env::var_os("KRB5_TEST_CROSS_REALMS")?;
    let conf = krb5::Krb5Conf::load([format!("{}/krb5.conf", e.dir)]).unwrap();
    Some((KdcClient::from_config(&conf, &e.realm).unwrap(), conf))
}

macro_rules! cross {
    ($e:expr) => {
        match cross(&$e) {
            Some(c) => c,
            None => {
                eprintln!("no cross-realm test realms; skipping");
                return;
            }
        }
    };
}

/// The ticket inside names the realm the service really lives in.
fn ticket_realm(creds: &Credentials) -> String {
    creds.ticket_server().expect("a parseable ticket").realm
}

/// No realm on the service: KRB5.TEST refers us to CROSS.TEST (via
/// [capaths]), CROSS.TEST to FAR.TEST, and FAR.TEST issues the ticket.
#[test]
fn cross_realm_referrals_with_no_service_realm() {
    let e = live!();
    let (kdc, _) = cross!(e);
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    let svc = Principal::new(krb5::client::NT_SRV_HST, ["host", "server.far.test"], "");
    let st = kdc.service_ticket(&tgt, &svc).unwrap();
    assert_eq!(st.server, svc, "named as requested, as MIT stores it");
    assert_eq!(ticket_realm(&st), "FAR.TEST");
    establish_with(&e, &st, "far.keytab");
}

/// The realm known up front ([domain_realm]): a TGT path through
/// CROSS.TEST ([capaths]), then the ticket from FAR.TEST.
#[test]
fn cross_realm_by_capaths_path() {
    let e = live!();
    let (kdc, conf) = cross!(e);
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    let svc = Principal::host_service("host", "server.far.test", &conf);
    assert_eq!(svc.realm, "FAR.TEST");
    let st = kdc.service_ticket(&tgt, &svc).unwrap();
    assert_eq!(ticket_realm(&st), "FAR.TEST");
    establish_with(&e, &st, "far.keytab");

    // One hop, by referral, to the directly trusted realm.
    let near = Principal::new(krb5::client::NT_SRV_HST, ["host", "server.cross.test"], "");
    let st = kdc.service_ticket(&tgt, &near).unwrap();
    assert_eq!(ticket_realm(&st), "CROSS.TEST");
    establish_with(&e, &st, "cross.keytab");
}

/// A realm we cannot reach is an error, not a hang or a wrong ticket.
#[test]
fn cross_realm_to_an_unknown_realm_fails() {
    let e = live!();
    let (kdc, _) = cross!(e);
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    let svc = Principal::new(
        krb5::client::NT_SRV_HST,
        ["host", "x.nowhere.test"],
        "NOWHERE.TEST",
    );
    assert!(kdc.service_ticket(&tgt, &svc).is_err());
}

/// TGS requests the test KDC has logged so far (all three realms).
fn tgs_requests(e: &Env) -> usize {
    std::fs::read_to_string(format!("{}/kdc.log", e.dir))
        .unwrap()
        .lines()
        .filter(|l| l.contains("TGS_REQ") && l.contains("ISSUE"))
        .count()
}

/// Through a cache: the cross-realm TGT we asked for is stored next to
/// the ticket and reused; MIT's tools read the cache; and we reuse a
/// cross-realm TGT MIT's kvno stored.
#[test]
fn cross_realm_through_a_credential_cache_shared_with_mit() {
    let e = live!();
    let (kdc, conf) = cross!(e);
    let path = scratch(&e, "xrealm");
    let name = format!("FILE:{}", path.display());
    let cache = krb5::CacheName::parse(&name).unwrap();
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    cache.write(&krb5::CCache::with_credentials(&tgt)).unwrap();

    let far = Principal::host_service("host", "server.far.test", &conf);
    let st = kdc.service_ticket_cached(&cache, &far).unwrap();
    establish_with(&e, &st, "far.keytab");
    // KRB5.TEST answered "krbtgt/FAR.TEST" with the closer CROSS.TEST TGT,
    // which, as in MIT, is used but not kept; the FAR.TEST TGT we asked
    // CROSS.TEST for is kept.
    let tgts: Vec<String> = cache
        .read()
        .unwrap()
        .credentials()
        .filter(|c| c.server.components[0] == "krbtgt")
        .map(|c| c.server.to_string())
        .collect();
    assert_eq!(
        tgts,
        ["krbtgt/KRB5.TEST@KRB5.TEST", "krbtgt/FAR.TEST@CROSS.TEST"]
    );

    // Another FAR.TEST service: straight to FAR.TEST with the cached TGT.
    let before = tgs_requests(&e);
    let other = Principal::host_service("host", "other.far.test", &conf);
    let st = kdc.service_ticket_cached(&cache, &other).unwrap();
    establish_with(&e, &st, "far.keytab");
    assert_eq!(tgs_requests(&e) - before, 1, "one TGS request, to FAR.TEST");
    // And the first ticket again: no request at all.
    let before = tgs_requests(&e);
    kdc.service_ticket_cached(&cache, &far).unwrap();
    assert_eq!(tgs_requests(&e), before);

    if mit(&e, &name, "klist", &[], None).is_none() {
        eprintln!("MIT's krb5 tools not on PATH; skipping the MIT half");
        return;
    }
    let listed = mit(&e, &name, "klist", &[], None).unwrap();
    assert!(listed.contains("host/other.far.test@FAR.TEST"), "{listed}");
    mit(
        &e,
        &name,
        "kvno",
        &["host/server.cross.test@CROSS.TEST"],
        None,
    )
    .unwrap();

    // MIT's kinit and kvno fill a cache; we reuse the FAR.TEST TGT it kept.
    let mit_path = scratch(&e, "xrealm-mit");
    let mit_name = format!("FILE:{}", mit_path.display());
    mit(&e, &mit_name, "kinit", &["alice"], Some("alicepw\n")).unwrap();
    mit(
        &e,
        &mit_name,
        "kvno",
        &["host/server.far.test@FAR.TEST"],
        None,
    )
    .unwrap();
    let before = tgs_requests(&e);
    let mit_cache = krb5::CacheName::parse(&mit_name).unwrap();
    let st = kdc.service_ticket_cached(&mit_cache, &other).unwrap();
    establish_with(&e, &st, "far.keytab");
    assert_eq!(
        tgs_requests(&e) - before,
        1,
        "MIT's cached FAR.TEST TGT was used"
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&mit_path);
}

// ------------------------------------------------- [libdefaults] settings

/// The realm's krb5.conf plus `extra` [libdefaults] lines.
fn conf_with(e: &Env, extra: &str) -> krb5::Krb5Conf {
    let base = std::fs::read_to_string(format!("{}/krb5.conf", e.dir)).unwrap();
    krb5::Krb5Conf::parse(&format!("{base}\n[libdefaults]\n{extra}\n")).unwrap()
}

/// TicketFlags (bit 0 = MSB).
const FORWARDABLE: u32 = 1 << 30;
const RENEWABLE: u32 = 1 << 23;

/// ticket_lifetime, renew_lifetime, forwardable and the two enctype
/// lists, as MIT's KDC honours them.
#[test]
fn libdefaults_shape_the_tickets_the_kdc_issues() {
    let e = live!();
    let conf = conf_with(
        &e,
        "ticket_lifetime = 2h\n renew_lifetime = 3d\n forwardable = true\n \
         default_tkt_enctypes = aes128-sha2\n default_tgs_enctypes = aes128-cts",
    );
    let kdc = KdcClient::from_config(&conf, &e.realm).unwrap();
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    // Asked from our clock, counted from the KDC's: a second may tick
    // between the two.
    let start = tgt.starttime.unwrap_or(tgt.authtime);
    let life = tgt.endtime - start;
    assert!(
        (2 * 3600 - 1..=2 * 3600).contains(&life),
        "ticket_lifetime {life}"
    );
    let renew = tgt.renew_till.expect("renewable") - start;
    assert!(
        (3 * 86400 - 1..=3 * 86400).contains(&renew),
        "renew_lifetime {renew}"
    );
    assert_eq!(
        tgt.flags & (FORWARDABLE | RENEWABLE),
        FORWARDABLE | RENEWABLE
    );
    assert_eq!(tgt.session_key.enctype(), 19, "default_tkt_enctypes");

    // The service ticket: TGS enctypes, and the TGT's flags asked for again.
    // (A service with keys of every enctype: the KDC picks the session key
    // from those the service supports, so svc18's aes256-only key would
    // turn an aes128 request into KDC_ERR_ETYPE_NOSUPP.)
    let st = kdc
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    assert_eq!(st.session_key.enctype(), 17, "default_tgs_enctypes");
    assert_eq!(
        st.flags & FORWARDABLE,
        FORWARDABLE,
        "forwardable carried over"
    );
    assert!(st.endtime <= tgt.endtime);
    establish(&e, &st);

    // Defaults, for comparison: one day, not renewable, not forwardable.
    let plain = KdcClient::from_config(&conf_with(&e, ""), &e.realm).unwrap();
    let tgt = plain.login_with_password(&e.p("alice"), "alicepw").unwrap();
    assert_eq!(tgt.endtime - tgt.starttime.unwrap_or(tgt.authtime), 86400);
    assert_eq!(tgt.flags & (FORWARDABLE | RENEWABLE), 0);
    assert_eq!(tgt.renew_till, None);
}

/// A realm's own [libdefaults] subsection wins over the general value.
#[test]
fn a_realm_subsection_of_libdefaults_wins() {
    let e = live!();
    let conf = conf_with(
        &e,
        &format!(
            "ticket_lifetime = 5h\n {} = {{\n ticket_lifetime = 45m\n }}",
            e.realm
        ),
    );
    let tgt = KdcClient::from_config(&conf, &e.realm)
        .unwrap()
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    assert_eq!(tgt.endtime - tgt.starttime.unwrap_or(tgt.authtime), 45 * 60);
}

// ------------------------------------------------------------- transports

/// A relay in front of the test KDC: forwards UDP datagrams and (unless
/// `tcp` is false) TCP connections, counting each. With `too_big`, the
/// first datagram is answered with KRB_ERR_RESPONSE_TOO_BIG instead.
fn relay(e: &Env, tcp: bool, too_big: bool) -> (String, Arc<Mutex<Vec<&'static str>>>) {
    use std::io::{Read, Write};
    let kdc: std::net::SocketAddr = std::env::var("KRB5_TEST_KDC").unwrap().parse().unwrap();
    let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = u.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    let realm = e.realm.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        let mut first = true;
        while let Ok((n, from)) = u.recv_from(&mut buf) {
            s.lock().unwrap().push("udp");
            if too_big && std::mem::take(&mut first) {
                u.send_to(&krb_error(52, &realm), from).unwrap();
                continue;
            }
            let up = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            up.connect(kdc).unwrap();
            up.send(&buf[..n]).unwrap();
            let mut r = [0u8; 65535];
            let m = up.recv(&mut r).unwrap();
            u.send_to(&r[..m], from).unwrap();
        }
    });
    if tcp {
        let t = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        let s = seen.clone();
        std::thread::spawn(move || {
            for c in t.incoming() {
                let mut c = c.unwrap();
                s.lock().unwrap().push("tcp");
                let mut up = std::net::TcpStream::connect(kdc).unwrap();
                let mut len = [0u8; 4];
                c.read_exact(&mut len).unwrap();
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                c.read_exact(&mut req).unwrap();
                up.write_all(&len).unwrap();
                up.write_all(&req).unwrap();
                up.read_exact(&mut len).unwrap();
                let mut rep = vec![0u8; u32::from_be_bytes(len) as usize];
                up.read_exact(&mut rep).unwrap();
                c.write_all(&len).unwrap();
                c.write_all(&rep).unwrap();
            }
        });
    }
    (format!("127.0.0.1:{port}"), seen)
}

use std::sync::{Arc, Mutex};

/// A minimal KRB-ERROR with `code`, hand-built.
fn krb_error(code: u8, realm: &str) -> Vec<u8> {
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if body.len() < 128 {
            v.push(body.len() as u8);
        } else {
            v.extend([0x81, body.len() as u8]);
        }
        v.extend_from_slice(body);
        v
    }
    let int = |n: u8| tlv(0x02, &[n]);
    let gs = |s: &str| tlv(0x1B, s.as_bytes());
    let mut seq = Vec::new();
    seq.extend(tlv(0xA0, &int(5)));
    seq.extend(tlv(0xA1, &int(30)));
    seq.extend(tlv(0xA4, &tlv(0x18, b"20260101000000Z")));
    seq.extend(tlv(0xA5, &int(0)));
    seq.extend(tlv(0xA6, &int(code)));
    seq.extend(tlv(0xA9, &gs(realm)));
    let mut name = Vec::new();
    name.extend(tlv(0xA0, &int(2)));
    name.extend(tlv(0xA1, &tlv(0x30, &[gs("krbtgt"), gs(realm)].concat())));
    seq.extend(tlv(0xAA, &tlv(0x30, &name)));
    tlv(0x7E, &tlv(0x30, &seq))
}

/// Requests go to the real KDC over UDP by default, and only over UDP
/// when that is all there is.
#[test]
fn the_kdc_is_reached_over_udp() {
    let e = live!();
    let (addr, seen) = relay(&e, false, false);
    let kdc = KdcClient::new(e.realm.clone(), [addr.clone()]);
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    kdc.service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    // PREAUTH_REQUIRED, the SPAKE support message and response, TGS-REQ:
    // all UDP, nothing else on offer.
    assert_eq!(*seen.lock().unwrap(), ["udp", "udp", "udp", "udp"]);
    // With UDP off there is no way through.
    let tcp_only = KdcClient::new(e.realm.clone(), [addr])
        .with_udp(false)
        .with_timeout(std::time::Duration::from_secs(2));
    assert!(matches!(
        tcp_only.login_with_password(&e.p("alice"), "alicepw"),
        Err(krb5::ClientError::Unreachable { .. })
    ));
}

/// KRB_ERR_RESPONSE_TOO_BIG over UDP: the request is sent again over TCP,
/// and the real KDC's TCP answer completes the login.
#[test]
fn response_too_big_moves_the_request_to_tcp() {
    let e = live!();
    let (addr, seen) = relay(&e, true, true);
    let kdc = KdcClient::new(e.realm.clone(), [addr]);
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    assert_eq!(tgt.server, Principal::krbtgt(&e.realm));
    let seen = seen.lock().unwrap();
    assert_eq!(&seen[..2], ["udp", "tcp"], "{seen:?}");
}

/// udp_preference_limit from krb5.conf: a limit of 1 sends everything
/// over TCP first.
#[test]
fn udp_preference_limit_from_krb5_conf() {
    let e = live!();
    let (addr, seen) = relay(&e, true, false);
    let conf = krb5::Krb5Conf::parse(&format!(
        "[libdefaults]\n udp_preference_limit = 1\n[realms]\n {} = {{\n  kdc = {addr}\n }}\n",
        e.realm
    ))
    .unwrap();
    KdcClient::from_config(&conf, &e.realm)
        .unwrap()
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    assert!(
        seen.lock().unwrap().iter().all(|t| *t == "tcp"),
        "{:?}",
        seen.lock().unwrap()
    );
}

// ------------------------------------------------------------ delegation

/// TicketFlags forwarded (bit 2).
const FORWARDED: u32 = 1 << 29;
/// TicketFlags pre-authent (bit 10).
const PRE_AUTHENT: u32 = 1 << 21;

/// Our initiator delegates a forwarded TGT to our acceptor, which can then
/// act as the client: it buys a ticket to another service with it.
#[test]
fn a_delegated_tgt_reaches_the_acceptor_and_works() {
    let e = live!();
    let kdc = e.client.clone().with_forwardable(true);
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    let st = kdc
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    let fwd = kdc
        .forwarded_tgt(&tgt, Some(st.session_key.enctype()))
        .unwrap();
    assert_eq!(
        fwd.flags & FORWARDED,
        FORWARDED,
        "the KDC marked it forwarded"
    );
    assert_eq!(
        fwd.session_key.enctype(),
        st.session_key.enctype(),
        "MIT's enctype preference"
    );

    let flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG;
    let (mut ini, token) = InitiatorContext::new_delegating(&st, flags, &fwd).unwrap();
    let (acc, ap_rep) = KerberosContext::accept_token(&e.keytab("service.keytab"), &token).unwrap();
    ini.step(&ap_rep).unwrap();
    assert_eq!(
        acc.gss_flags & krb5::initiator::GSS_C_DELEG_FLAG,
        krb5::initiator::GSS_C_DELEG_FLAG
    );
    let deleg = acc.delegated.expect("delegated credentials");
    assert_eq!(deleg.client, tgt.client);
    assert_eq!(deleg.ticket, fwd.ticket);

    // The acceptor, as alice, to a third service.
    let onward = e
        .client
        .service_ticket(&deleg, &e.p("svc18/svc.krb5.test"))
        .unwrap();
    assert_eq!(onward.client, tgt.client);
    establish(&e, &onward);
}

/// A TGT that is not forwardable cannot be forwarded; and without
/// new_delegating nothing is delegated, whatever the flags say.
#[test]
fn delegation_needs_a_forwardable_tgt_and_asking_for_it() {
    let e = live!();
    let tgt = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    let err = e.client.forwarded_tgt(&tgt, None).unwrap_err();
    assert_eq!(err.kdc_code(), Some(13), "KDC_ERR_BADOPTION: {err}");

    let st = e
        .client
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    let (_, token) =
        InitiatorContext::new(&st, krb5::initiator::GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG).unwrap();
    let (acc, _) = KerberosContext::accept_token(&e.keytab("service.keytab"), &token).unwrap();
    assert!(acc.delegated.is_none());
    assert_eq!(acc.gss_flags & krb5::initiator::GSS_C_DELEG_FLAG, 0);
}

/// True if python3 can import MIT's GSS-API bindings.
fn python_gssapi() -> bool {
    std::process::Command::new("python3")
        .args(["-c", "import gssapi"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// MIT's gss_init_sec_context delegates; our acceptor decodes the
/// KRB-CRED and uses the TGT.
#[test]
fn mit_delegates_to_our_acceptor() {
    let e = live!();
    if !mit_tools_installed() || !python_gssapi() {
        eprintln!("MIT's tools or python3-gssapi missing; skipping");
        return;
    }
    let path = scratch(&e, "deleg-mit");
    let name = format!("FILE:{}", path.display());
    mit(&e, &name, "kinit", &["-f", "alice"], Some("alicepw\n")).unwrap();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/mit-initiator.py");
    let token = mit(
        &e,
        &name,
        "python3",
        &[
            script,
            &format!("host/svc.krb5.test@{}", e.realm),
            "delegate",
        ],
        None,
    )
    .unwrap();
    let token: Vec<u8> = (0..token.trim().len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&token.trim()[i..i + 2], 16).unwrap())
        .collect();
    let (acc, _) = KerberosContext::accept_token(&e.keytab("service.keytab"), &token).unwrap();
    assert_eq!(acc.client_principal, format!("alice@{}", e.realm));
    let deleg = acc.delegated.expect("MIT delegated a TGT");
    assert_eq!(deleg.server, Principal::krbtgt(&e.realm));
    assert_eq!(deleg.flags & FORWARDED, FORWARDED);
    let onward = e
        .client
        .service_ticket(&deleg, &e.p("svc18/svc.krb5.test"))
        .unwrap();
    establish(&e, &onward);
    let _ = std::fs::remove_file(&path);
}

// ------------------------------------------- SPNEGO and channel bindings

/// MIT's GSS-API at the other end of a context: `scripts/mit-gss.py`,
/// stepped token by token.
struct MitPeer {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::io::Lines<std::io::BufReader<std::process::ChildStdout>>,
}

impl MitPeer {
    /// `None` if MIT's tools or python3-gssapi are missing.
    fn spawn(e: &Env, ccache: &str, args: &[&str]) -> Option<Self> {
        Self::spawn_with(e, ccache, None, args)
    }

    /// As [`MitPeer::spawn`], with `[libdefaults]` lines added to the
    /// realm's krb5.conf.
    fn spawn_with(e: &Env, ccache: &str, libdefaults: Option<&str>, args: &[&str]) -> Option<Self> {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        if !mit_tools_installed() || !python_gssapi() {
            eprintln!("MIT's tools or python3-gssapi missing; skipping");
            return None;
        }
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/mit-gss.py");
        let mut conf = format!("{}/krb5.conf", e.dir);
        if let Some(extra) = libdefaults {
            // MIT reads a list of profiles; the first wins.
            let path = format!("{}/extra-{}.conf", e.dir, std::process::id());
            std::fs::write(&path, format!("[libdefaults]\n{extra}\n")).unwrap();
            conf = format!("{path}:{conf}");
        }
        let mut child = Command::new("python3")
            .arg(script)
            .args(args)
            .env("KRB5_CONFIG", conf)
            .env("KRB5CCNAME", ccache)
            .env("KRB5_KTNAME", format!("FILE:{}/service.keytab", e.dir))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        Some(MitPeer {
            child,
            stdin,
            lines,
        })
    }

    fn send(&mut self, token: &[u8]) {
        use std::io::Write;
        let hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(self.stdin, "{hex}").unwrap();
    }

    /// The next line, as (word, rest); `Err` with MIT's message on "err".
    fn line(&mut self) -> Result<(String, String), String> {
        let line = self.lines.next().expect("MIT's side hung up").unwrap();
        let (word, rest) = line.split_once(' ').unwrap_or((&line, ""));
        match word {
            "err" => Err(rest.to_string()),
            _ => Ok((word.to_string(), rest.to_string())),
        }
    }

    /// The next "tok" line: `Some(token)`, or `None` for "tok -".
    fn token(&mut self) -> Result<Option<Vec<u8>>, String> {
        let (word, rest) = self.line()?;
        assert_eq!(word, "tok", "expected a token, got {word} {rest}");
        Ok((rest != "-").then(|| unhex(&rest)))
    }

    /// "done <flags> <name>".
    fn done(&mut self) -> (u32, String) {
        let (word, rest) = self.line().unwrap();
        assert_eq!(word, "done", "{rest}");
        let (flags, name) = rest.split_once(' ').unwrap();
        (flags.parse().unwrap(), name.to_string())
    }

    fn wrap(&mut self) -> Vec<u8> {
        let (word, rest) = self.line().unwrap();
        assert_eq!(word, "wrap", "{rest}");
        unhex(&rest)
    }

    fn ok(mut self) {
        assert_eq!(self.line().unwrap().0, "ok");
        assert!(self.child.wait().unwrap().success());
    }
}

impl Drop for MitPeer {
    /// A test done with MIT's side early ends it, quietly.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const GSS_C_REPLAY_FLAG: u32 = 4;
const GSS_C_SEQUENCE_FLAG: u32 = 8;
const GSS_C_CHANNEL_BOUND_FLAG: u32 = krb5::initiator::GSS_C_CHANNEL_BOUND_FLAG;
const MUTUAL_INTEG_CONF: u32 = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG;

fn alice_ticket_for_host(e: &Env) -> Credentials {
    let tgt = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    e.client
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap()
}

/// Our SPNEGO initiator against MIT's acceptor: negotiation, then Wrap
/// tokens both ways at the sequence numbers negotiation left. Mutual and
/// not, with and without sequence checking.
#[test]
fn our_spnego_initiator_against_mits_acceptor() {
    let e = live!();
    let svc = alice_ticket_for_host(&e);
    for flags in [
        MUTUAL_INTEG_CONF,
        MUTUAL_INTEG_CONF | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
        GSS_C_CONF_FLAG,
    ] {
        let Some(mut mit) = MitPeer::spawn(&e, "MEMORY:", &["accept"]) else {
            return;
        };
        let (mut ini, token) = krb5::spnego::SpnegoInitiator::new(&svc, flags).unwrap();
        mit.send(&token);
        while !ini.is_established() {
            let reply = mit.token().unwrap().expect("MIT answers a NegTokenInit");
            if let Some(next) = ini.step(&reply).unwrap() {
                mit.send(&next);
            }
        }
        let (_, name) = mit.done();
        assert_eq!(name, format!("alice@{}", e.realm));
        let tokens = ini.per_message_tokens().unwrap();
        mit.send(&tokens.emit_wrap(ini.send_seq(), b"ping").unwrap());
        let got = tokens.unwrap(&mit.wrap()).unwrap();
        assert_eq!(got.message, b"pong");
        assert_eq!(got.seq, ini.recv_seq(), "flags {flags:#x}");
        mit.ok();
    }
}

/// MIT's SPNEGO initiator against ours, from a cache MIT's kinit wrote.
#[test]
fn mits_spnego_initiator_against_our_acceptor() {
    let e = live!();
    let path = scratch(&e, "spnego-mit");
    let name = format!("FILE:{}", path.display());
    if mit(&e, &name, "kinit", &["alice"], Some("alicepw\n")).is_none() {
        eprintln!("MIT's krb5 tools not on PATH; skipping");
        return;
    }
    let target = format!("host/svc.krb5.test@{}", e.realm);
    let keytab = e.keytab("service.keytab");
    for flags in [
        MUTUAL_INTEG_CONF,
        MUTUAL_INTEG_CONF | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
        GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG,
    ] {
        let Some(mut mit) = MitPeer::spawn(
            &e,
            &name,
            &[
                "initiate",
                &target,
                "--spnego",
                "--flags",
                &flags.to_string(),
            ],
        ) else {
            return;
        };
        let mut acc = krb5::spnego::SpnegoAcceptor::new(&keytab);
        while let Some(token) = mit.token().unwrap() {
            assert!(!acc.is_established(), "MIT sent a token after we finished");
            if let Some(reply) = acc.step(&token).unwrap() {
                mit.send(&reply);
            }
        }
        assert!(acc.is_established() && acc.is_spnego());
        let ctx = acc.context().unwrap();
        assert_eq!(ctx.client_principal, format!("alice@{}", e.realm));
        let (_, peer) = mit.done();
        assert_eq!(peer, target);
        let tokens = ctx.per_message_tokens().unwrap();
        let got = tokens.unwrap(&mit.wrap()).unwrap();
        assert_eq!(
            (got.message.as_slice(), got.seq),
            (&b"ping"[..], acc.recv_seq())
        );
        mit.send(&tokens.emit_wrap(acc.send_seq(), b"pong").unwrap());
        mit.ok();
    }
    let _ = std::fs::remove_file(&path);
}

/// Our initiator's channel bindings as MIT's acceptor checks them, raw
/// Kerberos and under SPNEGO: matching ones set GSS_C_CHANNEL_BOUND_FLAG
/// in MIT's flags, others are refused, and none are refused only when
/// we said we bind (KERB_AP_OPTIONS_CBT in the authenticator, which MIT
/// must find where it looks for it).
#[test]
fn mits_acceptor_checks_our_channel_bindings() {
    let e = live!();
    let svc = alice_ticket_for_host(&e);
    let cb = krb5::ChannelBindings::new(b"tls-server-end-point:0123456789".to_vec());
    let other = krb5::ChannelBindings::new(b"tls-server-end-point:9876543210".to_vec());
    let cb_hex = hex(&cb.application_data);
    // (our bindings, our extra flags, accepted, bound)
    let cases = [
        (Some(&cb), 0, true, true),
        (Some(&other), 0, false, false),
        (None, 0, true, false),
        (None, GSS_C_CHANNEL_BOUND_FLAG, false, false),
        (Some(&cb), GSS_C_CHANNEL_BOUND_FLAG, true, true),
    ];
    for spnego in [false, true] {
        for (ours, extra, accepted, bound) in cases {
            let Some(mut mit) = MitPeer::spawn(&e, "MEMORY:", &["accept", "--cb", &cb_hex]) else {
                return;
            };
            let opts = krb5::initiator::InitOptions {
                channel_bindings: ours,
                ..Default::default()
            };
            let flags = MUTUAL_INTEG_CONF | extra;
            let label = format!(
                "spnego {spnego}, bindings {:?}, flags {extra:#x}",
                ours.map(|c| String::from_utf8_lossy(&c.application_data).into_owned())
            );
            if spnego {
                let (mut ini, token) =
                    krb5::spnego::SpnegoInitiator::with_options(&svc, flags, opts).unwrap();
                mit.send(&token);
                // MIT refuses with an error token (a reject carrying a
                // KRB-ERROR), which our side must take as the refusal.
                let reply = mit.token().unwrap().expect("a reply");
                match ini.step(&reply) {
                    Ok(next) => {
                        assert!(accepted, "{label}: MIT accepted");
                        assert_eq!(next, None);
                    }
                    Err(err) => {
                        assert!(!accepted, "{label}: {err}");
                        assert!(err.kdc_code().is_some(), "{label}: {err}");
                        continue;
                    }
                }
            } else {
                let (mut ini, token) = InitiatorContext::with_options(&svc, flags, opts).unwrap();
                mit.send(&token);
                let reply = mit.token().unwrap().expect("a reply");
                match ini.step(&reply) {
                    Ok(()) => assert!(accepted, "{label}: MIT accepted"),
                    Err(err) => {
                        assert!(!accepted, "{label}: {err}");
                        // A KRB-ERROR: KRB_AP_ERR_BAD_INTEGRITY, as MIT maps
                        // GSS_S_BAD_BINDINGS.
                        assert!(err.kdc_code().is_some(), "{label}: {err}");
                        continue;
                    }
                }
            }
            let (flags, _) = mit.done();
            assert_eq!(
                flags & GSS_C_CHANNEL_BOUND_FLAG != 0,
                bound,
                "{label}: {flags:#x}"
            );
        }
    }
}

/// MIT's initiator's channel bindings as our acceptor checks them.
#[test]
fn our_acceptor_checks_mits_channel_bindings() {
    let e = live!();
    let path = scratch(&e, "cb-mit");
    let name = format!("FILE:{}", path.display());
    if mit(&e, &name, "kinit", &["alice"], Some("alicepw\n")).is_none() {
        eprintln!("MIT's krb5 tools not on PATH; skipping");
        return;
    }
    let target = format!("host/svc.krb5.test@{}", e.realm);
    let keytab = e.keytab("service.keytab");
    let ours =
        krb5::ChannelBindings::new(b"tls-exporter:abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let ours_hex = hex(&ours.application_data);
    // (MIT's arguments, whether MIT says it binds, accepted, bound).
    // MIT 1.19 to 1.21 send KERB_AP_OPTIONS_CBT only for
    // client_aware_channel_bindings, so that is how it is asked for.
    let cases: [(&[&str], bool, bool, bool); 5] = [
        (&["--cb", &ours_hex], false, true, true),
        (&["--cb", "00ff"], false, false, false),
        (&[], false, true, false),
        (&[], true, false, false),
        (&["--cb", &ours_hex], true, true, true),
    ];
    for spnego in [false, true] {
        for (extra, cbt, accepted, bound) in cases {
            let mut args = vec!["initiate", &target];
            if spnego {
                args.push("--spnego");
            }
            args.extend_from_slice(extra);
            let cbt_conf = cbt.then_some("client_aware_channel_bindings = true");
            let Some(mut mit) = MitPeer::spawn_with(&e, &name, cbt_conf, &args) else {
                return;
            };
            let opts = krb5::acceptor::AcceptOptions {
                channel_bindings: Some(ours.clone()),
                ..Default::default()
            };
            let mut acc = krb5::spnego::SpnegoAcceptor::with_options(&keytab, opts);
            let token = mit.token().unwrap().unwrap();
            let label = format!("spnego {spnego}, MIT {extra:?}, CBT {cbt}");
            match acc.step(&token) {
                Ok(reply) => {
                    assert!(accepted, "{label}: we accepted");
                    let flags = acc.context().unwrap().gss_flags;
                    assert_eq!(flags & GSS_C_CHANNEL_BOUND_FLAG != 0, bound, "{label}");
                    mit.send(&reply.unwrap());
                    assert_eq!(mit.token().unwrap(), None, "{label}");
                    mit.done();
                }
                Err(err) => {
                    assert!(!accepted, "{label}: {err}");
                    assert!(
                        matches!(err, krb5::KerberosError::BadBindings(_)),
                        "{label}: {err}"
                    );
                }
            }
        }
    }
    let _ = std::fs::remove_file(&path);
}

// ------------------------------------------------------- S4U and the PAC

/// A key from `keytab` for `principal` (name without realm) and
/// `enctype`.
fn keytab_key(keytab: &Keytab, principal: &str, enctype: i32) -> krb5::Key {
    let k = keytab
        .keys()
        .iter()
        .find(|k| k.principal == principal && k.enctype as i32 == enctype)
        .unwrap_or_else(|| panic!("no {principal} enctype {enctype} key"));
    krb5::Key::new(enctype, k.key.clone()).unwrap()
}

/// A TCP relay to `target` (Kerberos framing) recording every request.
fn recording_relay(target: String) -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let mut c = c.unwrap();
            let mut len = [0u8; 4];
            if c.read_exact(&mut len).is_err() {
                continue;
            }
            let mut req = vec![0; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut req).unwrap();
            log.lock().unwrap().push(req.clone());
            let mut up = std::net::TcpStream::connect(&target).unwrap();
            up.write_all(&len).unwrap();
            up.write_all(&req).unwrap();
            let mut rep = Vec::new();
            up.read_to_end(&mut rep).ok();
            c.write_all(&rep).unwrap();
        }
    });
    (addr, seen)
}

/// Whether a KDC-REQ carries PA-DATA of type `ty` (its padata-type field,
/// `[1] INTEGER ty`, two octets).
fn has_padata(req: &[u8], ty: u16) -> bool {
    let field = [0xA1, 0x04, 0x02, 0x02, (ty >> 8) as u8, ty as u8];
    req.windows(6).any(|w| w == field)
}

/// S4U2Self in the main (DB2) realm, every MIT version: a ticket to the
/// service in alice's name, forwardable only for a service the KDC lets
/// act for users; our acceptor takes it, with a PAC naming alice.
#[test]
fn s4u2self_gets_a_ticket_in_the_users_name() {
    let e = live!();
    let kdc = e.client.clone().with_forwardable(true);
    let keytab = e.keytab("service.keytab");
    let svc = e.p("s4u/svc.krb5.test");
    let tgt = kdc.login_with_keytab(&svc, &keytab).unwrap();
    let creds = kdc.s4u2self(&tgt, &e.p("alice")).unwrap();
    assert_eq!(creds.client, e.p("alice"));
    assert_eq!(creds.server, svc);
    assert_eq!(
        creds.flags & FORWARDABLE,
        FORWARDABLE,
        "ok_to_auth_as_delegate"
    );
    let (_, token) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
    let (ctx, _) = KerberosContext::accept_token(&keytab, &token).unwrap();
    assert_eq!(ctx.client_principal, format!("alice@{}", e.realm));
    if let Some(pac) = &ctx.pac {
        // MIT 1.20 and later issue PACs.
        assert_eq!(pac.client_info().unwrap().unwrap().name, "alice");
    }

    // A service without ok_to_auth_as_delegate but with no delegation
    // targets (DB2 holds none) still gets it forwardable: MIT withholds
    // the flag only from services with traditional delegation targets.
    let host = e.p("host/svc.krb5.test");
    let tgt = kdc.login_with_keytab(&host, &keytab).unwrap();
    let creds = kdc.s4u2self(&tgt, &e.p("alice")).unwrap();
    assert_eq!(creds.client, e.p("alice"));

    // On the wire, as MIT sends it: PA-S4U-X509-USER (130) and
    // PA-FOR-USER (129), and no FAST (PA-FX-FAST, 136) unless asked for.
    let (relay, seen) = recording_relay(e.client.kdcs()[0].clone());
    let via = KdcClient::new(e.realm.clone(), [relay]).with_udp(false);
    via.s4u2self(&tgt, &e.p("alice")).unwrap();
    {
        let reqs = seen.lock().unwrap();
        let last = reqs.last().unwrap();
        assert!(has_padata(last, 130) && has_padata(last, 129));
        assert!(!has_padata(last, 136), "armored without FAST configured");
    }

    // Inside FAST armor too: the S4U PA-DATA rides in the armored request.
    let armored = via.clone().with_fast_armor(armor_tgt(&e));
    let creds = armored.s4u2self(&tgt, &e.p("alice")).unwrap();
    assert_eq!(creds.client, e.p("alice"));
    assert!(has_padata(seen.lock().unwrap().last().unwrap(), 136));

    // No such user.
    let err = kdc.s4u2self(&tgt, &e.p("nobody")).unwrap_err();
    assert!(err.kdc_code().is_some(), "{err}");
    // DB2 holds no delegation rules: S4U2Proxy is refused.
    let tgt = kdc.login_with_keytab(&svc, &keytab).unwrap();
    let evidence = kdc.s4u2self(&tgt, &e.p("alice")).unwrap();
    let err = kdc
        .s4u2proxy(&tgt, &evidence, &e.p("host/svc.krb5.test"))
        .unwrap_err();
    assert!(err.kdc_code().is_some(), "{err}");
}

/// S4U2Proxy, on the realm with delegation rules (MIT's test KDB module):
/// traditional constrained delegation (proxy may delegate to target, with
/// forwardable evidence) and resource-based (rb accepts impersonator),
/// each refused outside its rules; the tickets' PACs carry the
/// delegation path, and every KDC signature on them verifies.
#[test]
fn s4u2proxy_by_the_kdcs_delegation_rules() {
    let e = live!();
    let realm = std::env::var("KRB5_TEST_S4U_REALM").unwrap_or_default();
    if realm.is_empty() {
        eprintln!("KRB5_TEST_S4U_REALM not set (no MIT test KDB module); skipping S4U2Proxy");
        return;
    }
    let p = |n: &str| Principal::parse_in_realm(n, &realm).unwrap();
    let kdc = KdcClient::new(realm.clone(), e.client.kdcs().to_vec()).with_forwardable(true);
    let keytab = e.keytab("s4u.keytab");
    let krbtgt = keytab_key(&keytab, &format!("krbtgt/{realm}"), 18);

    for (service, target, transited) in [
        ("proxy", "target", "proxy"),
        ("impersonator", "rb", "impersonator"),
    ] {
        let tgt = kdc.login_with_keytab(&p(service), &keytab).unwrap();
        let evidence = kdc.s4u2self(&tgt, &p("user")).unwrap();
        assert_eq!(
            (evidence.client.clone(), evidence.server.clone()),
            (p("user"), p(service))
        );
        let creds = kdc
            .s4u2proxy(&tgt, &evidence, &Principal::new(1, [target], ""))
            .unwrap();
        assert_eq!(
            (creds.client.clone(), creds.server.clone()),
            (p("user"), p(target))
        );

        let (_, token) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).unwrap();
        let (ctx, _) = KerberosContext::accept_token(&keytab, &token).unwrap();
        assert_eq!(ctx.client_principal, format!("user@{realm}"));
        let pac = ctx.pac.expect("a verified PAC");
        let di = pac.delegation_info().unwrap().expect("delegation info");
        assert_eq!(di.proxy_target, target);
        assert_eq!(di.transited_services, [format!("{transited}@{realm}")]);
        let all =
            krb5::pac::verify_ticket(&creds.ticket, &keytab_key(&keytab, target, 18), &krbtgt)
                .unwrap()
                .unwrap();
        assert_eq!(all, pac);
        assert!(
            krb5::pac::verify_ticket(
                &creds.ticket,
                &keytab_key(&keytab, target, 18),
                &keytab_key(&keytab, "rb", 18)
            )
            .is_err()
        );
    }

    // Outside the rules: proxy may not reach rb, impersonator not target.
    for (service, target) in [("proxy", "rb"), ("impersonator", "target")] {
        let tgt = kdc.login_with_keytab(&p(service), &keytab).unwrap();
        let evidence = kdc.s4u2self(&tgt, &p("user")).unwrap();
        let err = kdc
            .s4u2proxy(&tgt, &evidence, &Principal::new(1, [target], ""))
            .unwrap_err();
        assert!(err.kdc_code().is_some(), "{service} -> {target}: {err}");
    }
    // Delegation targets without protocol transition: the S4U2Self ticket
    // is not forwardable, so it is no evidence for traditional S4U2Proxy.
    let tgt = kdc.login_with_keytab(&p("constrained"), &keytab).unwrap();
    let evidence = kdc.s4u2self(&tgt, &p("user")).unwrap();
    assert_eq!(evidence.flags & FORWARDABLE, 0);
    assert!(
        kdc.s4u2proxy(&tgt, &evidence, &Principal::new(1, ["target"], ""))
            .is_err()
    );
    // A user who may not be delegated: no forwardable evidence, no proxy.
    let tgt = kdc.login_with_keytab(&p("proxy"), &keytab).unwrap();
    let evidence = kdc.s4u2self(&tgt, &p("sensitive")).unwrap();
    assert_eq!(evidence.flags & FORWARDABLE, 0);
    assert!(
        kdc.s4u2proxy(&tgt, &evidence, &Principal::new(1, ["target"], ""))
            .is_err()
    );
}

/// The PAC MIT's KDC puts in an ordinary service ticket: verified by our
/// acceptor, and every KDC signature on it checked with the krbtgt key
/// (kadmin.local's export of it).
#[test]
fn every_signature_on_mits_pac_verifies() {
    let e = live!();
    let svc = alice_ticket_for_host(&e);
    let (_, token) = InitiatorContext::new(&svc, GSS_C_MUTUAL_FLAG).unwrap();
    let (ctx, _) = KerberosContext::accept_token(&e.keytab("service.keytab"), &token).unwrap();
    let Some(pac) = ctx.pac else {
        eprintln!("no PAC (MIT before 1.20); skipping");
        return;
    };
    pac.verify_client(svc.authtime, &e.p("alice"), false)
        .unwrap();
    let krbtgt = keytab_key(
        &e.keytab("krbtgt.keytab"),
        &format!("krbtgt/{}", e.realm),
        18,
    );
    let service_key = keytab_key(
        &e.keytab("service.keytab"),
        "host/svc.krb5.test",
        svc.ticket_enctype,
    );
    pac.verify_server_signature(&service_key).unwrap();
    pac.verify_kdc_signature(&krbtgt).unwrap();
    let all = krb5::pac::verify_ticket(&svc.ticket, &service_key, &krbtgt);
    if pac.buffer(krb5::pac::PAC_FULL_CHECKSUM).is_none() {
        // MIT 1.20 signs the ticket but not the whole PAC; MIT 1.21's KDC
        // refuses such a service ticket, and so do we.
        eprintln!("no full PAC signature (MIT 1.20)");
        // The ticket signature verified; only the full one is missing.
        assert!(all.unwrap_err().to_string().contains("buffer 19"));
        return;
    }
    assert_eq!(all.unwrap().unwrap(), pac);
}

// ---------------------------------------------- user-to-user and replays

/// bob, a user with no keytab: a user-to-user server holds only its TGT.
fn bob_tgt(e: &Env) -> Credentials {
    e.client.login_with_password(&e.p("bob"), "bobpw").unwrap()
}

fn u2u_opts() -> krb5::initiator::InitOptions<'static> {
    krb5::initiator::InitOptions {
        use_session_key: true,
        ..Default::default()
    }
}

/// Our client asks MIT's KDC for a ticket in the session key of bob's
/// TGT; bob accepts it with that TGT, no keytab anywhere.
#[test]
fn user_to_user_through_mits_kdc() {
    let e = live!();
    let alice = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    let bob = bob_tgt(&e);
    let u2u = e
        .client
        .user_to_user(&alice, &Principal::new(1, ["bob"], ""), &bob.ticket)
        .unwrap();
    assert_eq!(u2u.server.to_string(), format!("bob@{}", e.realm));
    assert_eq!(u2u.ticket_enctype, bob.session_key.enctype());

    let flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG;
    let (mut ini, token) = InitiatorContext::with_options(&u2u, flags, u2u_opts()).unwrap();
    let (acc, rep) = KerberosContext::accept_token_u2u(&bob, &token, &Default::default()).unwrap();
    assert_eq!(acc.client_principal, format!("alice@{}", e.realm));
    assert_eq!(acc.service_principal, format!("bob@{}", e.realm));
    ini.step(&rep).unwrap();
    let (ti, ta) = (
        ini.per_message_tokens().unwrap(),
        acc.per_message_tokens().unwrap(),
    );
    let w = ti.emit_wrap(ini.send_seq(), b"to bob").unwrap();
    assert_eq!(ta.unwrap(&w).unwrap().message, b"to bob");

    // A TGT of bob's from another login has another session key.
    let (_, token) = InitiatorContext::with_options(&u2u, 0, u2u_opts()).unwrap();
    assert!(KerberosContext::accept_token_u2u(&bob_tgt(&e), &token, &Default::default()).is_err());
    // The KDC issues one only for the client of the TGT it is in.
    let err = e
        .client
        .user_to_user(&alice, &e.p("robot"), &bob.ticket)
        .unwrap_err();
    assert_eq!(err.kdc_code(), Some(26), "KDC_ERR_SERVER_NOMATCH: {err}");
}

/// MIT's `kvno --u2u` gets the ticket from bob's TGT in a cache we wrote
/// and stores it marked user-to-user; we find it there as such (and not
/// as an ordinary ticket for bob) and accept it with bob's TGT.
#[test]
fn mits_kvno_u2u_ticket_is_accepted_with_the_tgt() {
    let e = live!();
    let bob = bob_tgt(&e);
    let bob_path = scratch(&e, "u2u-bob");
    krb5::CCache::with_credentials(&bob)
        .write(&bob_path)
        .unwrap();
    let path = scratch(&e, "u2u-alice");
    let name = format!("FILE:{}", path.display());
    if mit(&e, &name, "kinit", &["alice"], Some("alicepw\n")).is_none() {
        eprintln!("MIT's krb5 tools not on PATH; skipping");
        return;
    }
    let out = mit(
        &e,
        &name,
        "kvno",
        &["--u2u", &format!("FILE:{}", bob_path.display()), "bob"],
        None,
    )
    .unwrap();
    assert!(out.contains("kvno = 0"), "{out}");

    let cc = krb5::CCache::read(&path).unwrap();
    let now = bob.authtime;
    let bob_p = e.p("bob");
    assert!(cc.find(&bob_p, now).is_none(), "not an ordinary ticket");
    let u2u = cc
        .find_user_to_user(&bob_p, &bob.ticket, now)
        .expect("kvno's user-to-user ticket");
    let (_, token) = InitiatorContext::with_options(&u2u, GSS_C_MUTUAL_FLAG, u2u_opts()).unwrap();
    let (acc, _) = KerberosContext::accept_token_u2u(&bob, &token, &Default::default()).unwrap();
    assert_eq!(acc.client_principal, format!("alice@{}", e.realm));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&bob_path);
}

/// MIT's user-to-user sample server (`appl/user_user/uuserver`, in MIT's
/// `sbin`; Debian and Ubuntu do not package it). We play `uuclient`: send our
/// name and our TGT, and MIT gets a ticket in its session key and sends a
/// bare AP-REQ (`krb5_mk_req_extended` with USE-SESSION-KEY), then a
/// KRB-SAFE message.
#[test]
fn mits_uuserver_authenticates_to_us_by_user_to_user() {
    use std::io::{BufRead, Read, Write};
    let e = live!();
    let on_path = std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("uuserver").is_file()));
    if !mit_tools_installed() || !on_path {
        eprintln!("MIT's uuserver not on PATH; skipping");
        return;
    }
    let path = scratch(&e, "uu-alice");
    let name = format!("FILE:{}", path.display());
    mit(&e, &name, "kinit", &["alice"], Some("alicepw\n")).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut server = std::process::Command::new("uuserver")
        .arg(port.to_string())
        .env("KRB5_CONFIG", format!("{}/krb5.conf", e.dir))
        .env("KRB5CCNAME", &name)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = std::io::BufReader::new(server.stdout.take().unwrap()).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "Server started");

    // krb5_write_message: a 4-octet big-endian length, then the data.
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let send = |s: &mut std::net::TcpStream, m: &[u8]| {
        s.write_all(&(m.len() as u32).to_be_bytes()).unwrap();
        s.write_all(m).unwrap();
    };
    let recv = |s: &mut std::net::TcpStream| {
        let mut n = [0; 4];
        s.read_exact(&mut n).unwrap();
        let mut m = vec![0; u32::from_be_bytes(n) as usize];
        s.read_exact(&mut m).unwrap();
        m
    };
    let bob = bob_tgt(&e);
    send(&mut sock, format!("bob@{}\0", e.realm).as_bytes());
    send(&mut sock, &bob.ticket);
    let ap_req = recv(&mut sock);
    let (ctx, rep) =
        KerberosContext::accept_ap_req_u2u(&bob, &ap_req, &Default::default()).unwrap();
    assert_eq!(ctx.client_principal, format!("alice@{}", e.realm));
    assert_eq!(ctx.service_principal, format!("bob@{}", e.realm));
    assert!(rep.is_empty(), "uuserver asks no mutual authentication");
    // KRB-SAFE carries its user data in the clear.
    let safe = recv(&mut sock);
    assert_eq!(safe[0], 0x74, "KRB-SAFE, [APPLICATION 20]");
    let hello = b"Hello, other end of connection.";
    assert!(safe.windows(hello.len()).any(|w| w == hello));
    let status = server.wait().unwrap();
    let mut err = String::new();
    server
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(status.success(), "uuserver: {err}");
    let _ = std::fs::remove_file(&path);
}

/// An authenticator from MIT's initiator is accepted once; sent again it
/// is a replay (KRB_AP_ERR_REPEAT), and a new one is fine.
#[test]
fn a_replayed_mit_authenticator_is_refused() {
    let e = live!();
    if !mit_tools_installed() || !python_gssapi() {
        eprintln!("MIT's tools or python3-gssapi missing; skipping");
        return;
    }
    let path = scratch(&e, "replay-mit");
    let name = format!("FILE:{}", path.display());
    mit(&e, &name, "kinit", &["alice"], Some("alicepw\n")).unwrap();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/mit-initiator.py");
    let service = format!("host/svc.krb5.test@{}", e.realm);
    let token = || {
        unhex(
            mit(&e, &name, "python3", &[script, &service], None)
                .unwrap()
                .trim(),
        )
    };
    let keytab = e.keytab("service.keytab");
    let first = token();
    KerberosContext::accept_token(&keytab, &first).unwrap();
    let err = KerberosContext::accept_token(&keytab, &first).unwrap_err();
    assert!(matches!(err, krb5::KerberosError::Replay(_)), "{err}");
    KerberosContext::accept_token(&keytab, &token()).unwrap();
    let _ = std::fs::remove_file(&path);
}

/// The other way: MIT's acceptor, with its replay cache, refuses one of
/// our authenticators sent twice, to two processes.
#[test]
fn mit_refuses_a_replayed_authenticator_of_ours() {
    let e = live!();
    let tgt = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    let svc = e
        .client
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    let (_, token) = InitiatorContext::new(&svc, GSS_C_MUTUAL_FLAG).unwrap();
    let Some(mut first) = MitPeer::spawn(&e, "MEMORY:", &["accept"]) else {
        return;
    };
    first.send(&token);
    assert!(first.token().unwrap().is_some(), "MIT's AP-REP");
    let mut second = MitPeer::spawn(&e, "MEMORY:", &["accept"]).unwrap();
    second.send(&token);
    // MIT answers with a KRB-ERROR token (TOK_ID 03 00): error-code [6]
    // 34, KRB_AP_ERR_REPEAT.
    let err = second.token().unwrap().expect("MIT's error token");
    assert_eq!(&err[13..15], [3, 0], "a KRB-ERROR token");
    assert!(
        err.windows(5).any(|w| w == [0xA6, 3, 2, 1, 34]),
        "KRB_AP_ERR_REPEAT: {}",
        hex(&err)
    );
}

// ----------------------------------------------------------------- SPAKE

/// The pre-authentication type a login used, as `kinit` records it in the
/// cache (its `pa_type` entry): 151 SPAKE, 2 encrypted timestamp, 138
/// FAST's encrypted challenge.
fn pa_type_of(e: &Env, tag: &str, kinit: impl FnOnce(&krb5::CacheName)) -> String {
    let path = scratch(e, tag);
    let name = krb5::CacheName::parse(&format!("FILE:{}", path.display())).unwrap();
    kinit(&name);
    let cc = krb5::CCache::read(&path).unwrap();
    let t = cc
        .config("pa_type", Some(&Principal::krbtgt(&e.realm)))
        .expect("a pa_type entry")
        .to_vec();
    let _ = std::fs::remove_file(&path);
    String::from_utf8(t).unwrap()
}

/// The test KDC offers SPAKE in edwards25519, P-256 and P-384 (not
/// P-521), as MIT deploys it: our client's support message, the KDC's
/// challenge, our response, and the reply in K'[0].
#[test]
fn spake_logins_in_each_group_the_kdc_takes() {
    use krb5::client::spake::SpakeGroup;
    let e = live!();
    let alice = e.p("alice");
    let login = |groups: &[SpakeGroup], tag: &str| {
        let kdc = e.client.clone().with_spake_groups(groups);
        pa_type_of(&e, tag, |c| {
            let tgt = kdc.kinit_with_password(&alice, "alicepw", c).unwrap();
            let st = e
                .client
                .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
                .unwrap();
            establish(&e, &st);
        })
    };
    // edwards25519, the default, needs no feature.
    assert_eq!(login(&[SpakeGroup::Edwards25519], "spake-ed"), "151");
    if SpakeGroup::P256.is_available() {
        assert_eq!(login(&[SpakeGroup::P256], "spake-256"), "151");
        assert_eq!(login(&[SpakeGroup::P384], "spake-384"), "151");
        // A group the KDC does not take: it refuses our support message,
        // and the login falls back to encrypted timestamps, as MIT's does.
        assert_eq!(login(&[SpakeGroup::P521], "spake-521"), "2");
    }
    // SPAKE off: encrypted timestamps.
    assert_eq!(login(&[], "spake-off"), "2");
    // The default client takes SPAKE when it is offered.
    let kdc = e.client.clone();
    let t = pa_type_of(&e, "spake-default", |c| {
        kdc.kinit_with_password(&alice, "alicepw", c).unwrap();
    });
    assert_eq!(t, "151");
}

/// A wrong password fails at the KDC, which cannot open our second
/// factor; a keytab key works as a password's does.
#[test]
fn spake_refuses_a_wrong_password_and_takes_a_keytab_key() {
    let e = live!();
    let err = e
        .client
        .login_with_password(&e.p("alice"), "wrong")
        .unwrap_err();
    assert_eq!(err.kdc_code(), Some(KDC_ERR_PREAUTH_FAILED), "{err}");
    let t = pa_type_of(&e, "spake-kt", |c| {
        e.client
            .kinit_with_keytab(&e.p("robot"), &e.keytab("robot.keytab"), c)
            .unwrap();
    });
    assert_eq!(t, "151");
}

/// SPAKE inside FAST, which the KDC offers there too, and FAST's
/// encrypted challenge when SPAKE is off.
#[test]
fn spake_inside_fast() {
    let e = live!();
    let alice = e.p("alice");
    let kdc = e.client.clone().with_fast_armor(armor_tgt(&e));
    let t = pa_type_of(&e, "spake-fast", |c| {
        kdc.kinit_with_password(&alice, "alicepw", c).unwrap();
    });
    assert_eq!(t, "151");
    let plain = kdc.clone().with_spake_groups(&[]);
    let t = pa_type_of(&e, "spake-fast-off", |c| {
        plain.kinit_with_password(&alice, "alicepw", c).unwrap();
    });
    assert_eq!(t, "138");
    let err = kdc.login_with_password(&alice, "wrong").unwrap_err();
    assert_eq!(err.kdc_code(), Some(KDC_ERR_PREAUTH_FAILED), "{err}");
}

// ------------------------------------------------------------------- OTP

/// The RADIUS server's verdicts so far (`scripts/radius-test.py`), or
/// `None` without MIT's otp plugin.
fn radius_log(e: &Env) -> Option<Vec<String>> {
    if std::env::var("KRB5_TEST_OTP").as_deref() != Ok("1") {
        eprintln!("KRB5_TEST_OTP not set (no MIT otp plugin); skipping");
        return None;
    }
    let log = std::fs::read_to_string(format!("{}/radius.log", e.dir)).unwrap();
    Some(log.lines().map(str::to_string).collect())
}

/// A one-time password through FAST to MIT's KDC, which checks it with
/// RADIUS: the right code logs in, a wrong one is refused, and without
/// armor nothing is sent.
#[test]
fn otp_login_through_fast_and_radius() {
    use krb5::client::otp::OtpAnswer;
    let e = live!();
    let Some(before) = radius_log(&e) else {
        return;
    };
    let kdc = e.client.clone().with_fast_armor(armor_tgt(&e));
    let user = e.p("otpuser");
    let tgt = kdc.login_with_otp(&user, "424242").unwrap();
    assert_eq!(tgt.client.to_string(), format!("otpuser@{}", e.realm));
    assert_ne!(tgt.flags & PRE_AUTHENT, 0, "pre-authenticated");
    let st = e
        .client
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    establish(&e, &st);

    let err = kdc.login_with_otp(&user, "111111").unwrap_err();
    assert_eq!(err.kdc_code(), Some(KDC_ERR_PREAUTH_FAILED), "{err}");

    // MIT's KDC describes one token and nothing about it.
    kdc.login_with_otp_by(&user, |ch| {
        assert_eq!((ch.tokens.len(), ch.service.as_deref()), (1, None));
        Ok(OtpAnswer {
            token: 0,
            value: "424242".into(),
            pin: None,
        })
    })
    .unwrap();
    let err = e.client.login_with_otp(&user, "424242").unwrap_err();
    assert!(err.to_string().contains("FAST"), "{err}");

    let log = radius_log(&e).unwrap();
    assert_eq!(
        log[before.len()..],
        [
            "otpuser 424242 accept",
            "otpuser 111111 reject",
            "otpuser 424242 accept"
        ]
    );
}

// ------------------------------------------------------------------ FAST

/// An armor TGT, as a host would hold one from its keytab.
fn armor_tgt(e: &Env) -> Credentials {
    e.client
        .login_with_keytab(&e.p("robot"), &e.keytab("robot.keytab"))
        .unwrap()
}

/// A FAST-armored password login: the encrypted challenge inside the
/// armor, the KDC's challenge verified, the finished checksum checked.
#[test]
fn fast_armored_password_login() {
    let e = live!();
    // SPAKE off: the KDC offers it inside FAST too (see spake_inside_fast).
    let kdc = e
        .client
        .clone()
        .with_fast_armor(armor_tgt(&e))
        .with_spake_groups(&[]);
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    assert_eq!(tgt.client.to_string(), format!("alice@{}", e.realm));
    assert_eq!(tgt.server, Principal::krbtgt(&e.realm));
    // The TGT works like any other.
    let st = e
        .client
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    establish(&e, &st);
}

/// Errors come back inside the armor (PA-FX-ERROR) and are the real ones.
#[test]
fn fast_errors_are_the_kdcs_own() {
    let e = live!();
    let kdc = e.client.clone().with_fast_armor(armor_tgt(&e));
    let err = kdc.login_with_password(&e.p("alice"), "wrong").unwrap_err();
    assert_eq!(err.kdc_code(), Some(KDC_ERR_PREAUTH_FAILED), "{err}");
    let err = kdc.login_with_password(&e.p("nobody"), "x").unwrap_err();
    assert_eq!(err.kdc_code(), Some(KDC_ERR_C_PRINCIPAL_UNKNOWN), "{err}");
}

/// A keytab login and a principal that needs no pre-authentication, both
/// through the armor.
#[test]
fn fast_keytab_and_no_preauth_logins() {
    let e = live!();
    let kdc = e.client.clone().with_fast_armor(armor_tgt(&e));
    let tgt = kdc
        .login_with_keytab(&e.p("robot"), &e.keytab("robot.keytab"))
        .unwrap();
    assert_eq!(tgt.client.to_string(), format!("robot@{}", e.realm));
    // bob was made with -requires_preauth: the KDC answers at once.
    let tgt = kdc.login_with_password(&e.p("bob"), "bobpw").unwrap();
    assert_eq!(tgt.client.to_string(), format!("bob@{}", e.realm));
}

/// FAST with MIT on the other side of the armor: MIT's kinit -T uses an
/// armor cache we wrote, and we armor with a TGT MIT's kinit -k got.
#[test]
fn fast_armor_caches_are_shared_with_mit() {
    let e = live!();
    if !mit_tools_installed() {
        eprintln!("MIT's krb5 tools not on PATH; skipping");
        return;
    }
    // Our robot TGT as MIT's armor.
    let armor_path = scratch(&e, "armor-ours");
    krb5::CCache::with_credentials(&armor_tgt(&e))
        .write(&armor_path)
        .unwrap();
    let out_path = scratch(&e, "armored-by-mit");
    let out = format!("FILE:{}", out_path.display());
    let armor_name = format!("FILE:{}", armor_path.display());
    mit(
        &e,
        &out,
        "kinit",
        &["-T", &armor_name, "alice"],
        Some("alicepw\n"),
    )
    .unwrap();
    let listed = mit(&e, &out, "klist", &[], None).unwrap();
    assert!(
        listed.contains(&format!("krbtgt/{0}@{0}", e.realm)),
        "{listed}"
    );

    // MIT's robot TGT as our armor.
    let mit_armor = scratch(&e, "armor-mit");
    let mit_armor_name = format!("FILE:{}", mit_armor.display());
    let kt = format!("{}/robot.keytab", e.dir);
    mit(
        &e,
        &mit_armor_name,
        "kinit",
        &["-k", "-t", &kt, "robot"],
        None,
    )
    .unwrap();
    let armor = krb5::CCache::read(&mit_armor).unwrap().tgt(0).unwrap();
    let tgt = e
        .client
        .clone()
        .with_fast_armor(armor)
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    assert_eq!(tgt.client.to_string(), format!("alice@{}", e.realm));
    for p in [armor_path, out_path, mit_armor] {
        let _ = std::fs::remove_file(p);
    }
}

/// TGS requests through a FAST client are armored too (the implicit armor
/// from the TGT, as MIT's send_tgs does), cross-realm hops included.
#[test]
fn fast_armors_service_ticket_requests() {
    let e = live!();
    let kdc = e.client.clone().with_fast_armor(armor_tgt(&e));
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    let st = kdc
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap();
    establish(&e, &st);
    if let Some((_, conf)) = cross(&e) {
        let x = KdcClient::from_config(&conf, &e.realm)
            .unwrap()
            .with_fast_armor(armor_tgt(&e));
        let tgt = x.login_with_password(&e.p("alice"), "alicepw").unwrap();
        let far = Principal::new(krb5::client::NT_SRV_HST, ["host", "server.far.test"], "");
        let st = x.service_ticket(&tgt, &far).unwrap();
        establish_with(&e, &st, "far.keytab");
    }
}

// ------------------------------------------------- FAST negotiation

/// AS requests the test KDC has logged for `who`.
fn as_requests(e: &Env, who: &str) -> usize {
    std::fs::read_to_string(format!("{}/kdc.log", e.dir))
        .unwrap()
        .lines()
        .filter(|l| l.contains("AS_REQ") && l.contains(&format!("{who}@{} for krbtgt", e.realm)))
        .count()
}

/// RFC 6806 negotiation: the KDC's checksum over our request is verified,
/// and kinit_with_* records fast_avail and pa_type as MIT's kinit does.
#[test]
fn kinit_records_fast_avail_as_mit_does() {
    let e = live!();
    let path = scratch(&e, "kinit-ours");
    let cache = krb5::CacheName::File(path.clone());
    let tgt = e
        .client
        .kinit_with_password(&e.p("alice"), "alicepw", &cache)
        .unwrap();
    assert_eq!(
        tgt.flags & (1 << 16),
        1 << 16,
        "enc-pa-rep: the KDC answered the negotiation"
    );
    let cc = cache.read().unwrap();
    assert!(cc.fast_avail(&e.realm), "MIT's KDC supports FAST");
    let krbtgt = Principal::krbtgt(&e.realm);
    assert_eq!(
        cc.config("pa_type", Some(&krbtgt)),
        Some(&b"151"[..]),
        "PA-SPAKE"
    );
    // The same entries MIT's kinit writes, in the same place.
    if let Some(listed) = mit(&e, &format!("FILE:{}", path.display()), "klist", &[], None) {
        assert!(
            listed.contains(&format!("krbtgt/{0}@{0}", e.realm)),
            "{listed}"
        );
        let mit_path = scratch(&e, "kinit-mit");
        let mit_name = format!("FILE:{}", mit_path.display());
        mit(&e, &mit_name, "kinit", &["alice"], Some("alicepw\n")).unwrap();
        let theirs = krb5::CCache::read(&mit_path).unwrap();
        let conf = |c: &krb5::CCache| -> Vec<Vec<String>> {
            c.entries
                .iter()
                .filter(|e| e.is_config())
                .map(|e| e.server.components.clone())
                .collect()
        };
        assert_eq!(conf(&cc), conf(&theirs));
        let _ = std::fs::remove_file(mit_path);
    }
    // FAST logins record the encrypted challenge (SPAKE off; with it on
    // they record SPAKE, see spake_inside_fast).
    let fast = e
        .client
        .clone()
        .with_fast_armor(armor_tgt(&e))
        .with_spake_groups(&[]);
    fast.kinit_with_password(&e.p("alice"), "alicepw", &cache)
        .unwrap();
    assert_eq!(
        cache.read().unwrap().config("pa_type", Some(&krbtgt)),
        Some(&b"138"[..])
    );
    let _ = std::fs::remove_file(path);
}

/// An armor cache that records fast_avail armors from the first request
/// (two AS requests); one that does not upgrades when the KDC offers
/// FAST (three: plain, then armored twice).
#[test]
fn an_armor_cache_upgrades_or_starts_armored() {
    let e = live!();
    let robot = e.p("robot");
    let kt = e.keytab("robot.keytab");

    // Our kinit -k: fast_avail recorded.
    let with = scratch(&e, "armor-with-fast-avail");
    e.client
        .kinit_with_keytab(&robot, &kt, &krb5::CacheName::File(with.clone()))
        .unwrap();
    // Counting requests: SPAKE (a round trip more) off.
    let kdc = e
        .client
        .clone()
        .with_spake_groups(&[])
        .with_fast_armor_cache(&krb5::CacheName::File(with.clone()))
        .unwrap();
    let before = as_requests(&e, "alice");
    kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    assert_eq!(
        as_requests(&e, "alice") - before,
        2,
        "armored from the start"
    );

    // A bare cache with the same TGT and no fast_avail: upgrade.
    let without = scratch(&e, "armor-without");
    let tgt = krb5::CCache::read(&with).unwrap().tgt(0).unwrap();
    krb5::CCache::with_credentials(&tgt)
        .write(&without)
        .unwrap();
    let kdc = e
        .client
        .clone()
        .with_spake_groups(&[])
        .with_fast_armor_cache(&krb5::CacheName::File(without.clone()))
        .unwrap();
    let before = as_requests(&e, "alice");
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    assert_eq!(as_requests(&e, "alice") - before, 3, "plain, then upgraded");
    establish(
        &e,
        &e.client
            .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
            .unwrap(),
    );

    // MIT's kinit -k writes fast_avail too.
    if mit_tools_installed() {
        let mit_cache = scratch(&e, "armor-mit-kinit");
        let name = format!("FILE:{}", mit_cache.display());
        mit(
            &e,
            &name,
            "kinit",
            &["-k", "-t", &format!("{}/robot.keytab", e.dir), "robot"],
            None,
        )
        .unwrap();
        assert!(krb5::CCache::read(&mit_cache).unwrap().fast_avail(&e.realm));
        let kdc = e
            .client
            .clone()
            .with_spake_groups(&[])
            .with_fast_armor_cache(&krb5::CacheName::File(mit_cache.clone()))
            .unwrap();
        let before = as_requests(&e, "alice");
        kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
        assert_eq!(as_requests(&e, "alice") - before, 2);
        let _ = std::fs::remove_file(mit_cache);
    }
    let _ = std::fs::remove_file(with);
    let _ = std::fs::remove_file(without);
}

// ------------------------------------------------------------------ PKINIT

// ------------------------------------------- renewal and postdated tickets

const INVALID: u32 = 1 << 24;
const POSTDATED: u32 = 1 << 25;

fn renewable(e: &Env) -> KdcClient {
    e.client
        .clone()
        .with_lifetime(std::time::Duration::from_secs(3600))
        .with_renew_lifetime(Some(std::time::Duration::from_secs(7200)))
}

/// `kinit -R`'s exchange: the KDC renews the TGT with a new session key,
/// the old lifetime from now and the old renew-till, and the renewed TGT
/// gets service tickets. A service ticket renews the same way.
#[test]
fn a_renewable_tgt_and_a_service_ticket_are_renewed() {
    let e = live!();
    let kdc = renewable(&e);
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    assert_eq!(tgt.flags & RENEWABLE, RENEWABLE);
    let now = tgt.starttime.unwrap_or(tgt.authtime);
    assert!(tgt.can_renew_at(now));
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let new = kdc.renew(&tgt).unwrap();
    assert_eq!(new.server, tgt.server);
    assert_eq!(new.client, tgt.client);
    assert_eq!(new.authtime, tgt.authtime, "authtime is the login's");
    assert_eq!(new.renew_till, tgt.renew_till);
    assert_eq!(new.flags & RENEWABLE, RENEWABLE);
    assert_ne!(new.session_key.bytes(), tgt.session_key.bytes());
    let start = new
        .starttime
        .expect("a renewed ticket starts after authtime");
    assert!(start > now, "{start} > {now}");
    // The old ticket's own lifetime (3600 asked; a second less if the
    // KDC's clock ticked between our request and its answer).
    let lifetime = tgt.endtime - tgt.starttime.unwrap_or(tgt.authtime);
    assert!((3599..=3600).contains(&lifetime), "{lifetime}");
    assert_eq!(new.endtime - start, lifetime, "the old lifetime, from now");

    let svc = kdc
        .service_ticket(&new, &e.p("host/svc.krb5.test"))
        .unwrap();
    establish(&e, &svc);
    assert_eq!(svc.flags & RENEWABLE, RENEWABLE, "inherited from the TGT");
    let svc2 = kdc.renew(&svc).unwrap();
    assert_eq!(svc2.server, svc.server);
    assert_ne!(svc2.session_key.bytes(), svc.session_key.bytes());
    establish(&e, &svc2);
}

/// Near the end of the renewable life, the renewed ticket ends there.
#[test]
fn a_renewal_stops_at_renew_till() {
    let e = live!();
    let kdc = e
        .client
        .clone()
        .with_lifetime(std::time::Duration::from_secs(3600))
        .with_renew_lifetime(Some(std::time::Duration::from_secs(3610)));
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let new = kdc.renew(&tgt).unwrap();
    let till = tgt.renew_till.unwrap();
    assert!(new.endtime <= till && new.endtime > tgt.endtime, "{new:?}");
}

/// A ticket that is not renewable is refused (KDC_ERR_BADOPTION).
#[test]
fn a_ticket_that_is_not_renewable_is_refused() {
    let e = live!();
    let tgt = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    assert_eq!(tgt.flags & RENEWABLE, 0);
    assert!(!tgt.can_renew_at(tgt.authtime));
    let err = e.client.renew(&tgt).unwrap_err();
    assert_eq!(err.kdc_code(), Some(13), "KDC_ERR_BADOPTION: {err}");
}

/// `kinit -s`: a postdated TGT is issued invalid; the KDC will not
/// validate it early (KRB_AP_ERR_TKT_NYV) nor use it for a service
/// ticket, and after its start time `validate` makes it work.
#[test]
fn a_postdated_tgt_is_validated_after_its_start() {
    let e = live!();
    let kdc = e
        .client
        .clone()
        .with_start_time(Some(std::time::Duration::from_secs(2)));
    let tgt = kdc.login_with_password(&e.p("alice"), "alicepw").unwrap();
    assert!(tgt.is_invalid());
    assert_eq!(tgt.flags & (INVALID | POSTDATED), INVALID | POSTDATED);
    let start = tgt.starttime.expect("postdated");
    assert!(start > tgt.authtime);

    let err = kdc.validate(&tgt).unwrap_err();
    assert_eq!(err.kdc_code(), Some(33), "KRB_AP_ERR_TKT_NYV: {err}");
    let err = kdc
        .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
        .unwrap_err();
    assert!(err.kdc_code().is_some(), "an invalid TGT is refused: {err}");
    // Validating a ticket that is valid already is a bad option.
    let plain = e
        .client
        .login_with_password(&e.p("alice"), "alicepw")
        .unwrap();
    let err = e.client.validate(&plain).unwrap_err();
    assert_eq!(err.kdc_code(), Some(13), "KDC_ERR_BADOPTION: {err}");

    std::thread::sleep(std::time::Duration::from_millis(2500));
    let valid = kdc.validate(&tgt).unwrap();
    assert!(!valid.is_invalid());
    assert_eq!(valid.flags & POSTDATED, POSTDATED);
    // MIT 1.21 and later keep the times; 1.20 starts the ticket at the
    // validation instead.
    assert_eq!(valid.endtime, tgt.endtime, "validation keeps the end time");
    assert!(valid.starttime >= tgt.starttime, "{valid:?}");
    let svc = kdc
        .service_ticket(&valid, &e.p("host/svc.krb5.test"))
        .unwrap();
    establish(&e, &svc);
}

/// `kinit -R` both ways: MIT's renews a cache we wrote, ours renews one
/// MIT's `kinit -r` wrote, and either way the cache is left holding only
/// the renewed TGT, which MIT's `kvno` then uses.
#[test]
fn kinit_renew_shares_caches_with_mit() {
    let e = live!();
    let path = scratch(&e, "renew");
    let name = format!("FILE:{}", path.display());
    let cache = krb5::CacheName::parse(&name).unwrap();
    let kdc = renewable(&e);

    // Ours, with a service ticket beside the TGT, renewed by MIT.
    let tgt = kdc
        .kinit_with_password(&e.p("alice"), "alicepw", &cache)
        .unwrap();
    kdc.service_ticket_cached(&cache, &e.p("host/svc.krb5.test"))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    if mit(&e, &name, "kinit", &["-R"], None).is_none() {
        eprintln!("MIT's krb5 tools not on PATH; skipping");
        return;
    }
    let cc = krb5::CCache::read(&path).unwrap();
    let all: Vec<_> = cc.credentials().collect();
    assert_eq!(all.len(), 1, "only the renewed TGT: {all:?}");
    assert_eq!(all[0].server, tgt.server);
    assert_ne!(all[0].session_key.bytes(), tgt.session_key.bytes());
    assert_eq!(all[0].renew_till, tgt.renew_till);

    // MIT's, renewed by us.
    let _ = std::fs::remove_file(&path);
    mit(
        &e,
        &name,
        "kinit",
        &["-r", "2h", "-l", "1h", "alice"],
        Some("alicepw\n"),
    )
    .unwrap();
    mit(&e, &name, "kvno", &["host/svc.krb5.test"], None).unwrap();
    let before = krb5::CCache::read(&path).unwrap().tgt(0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let renewed = e.client.kinit_renew(&cache).unwrap();
    assert_ne!(renewed.session_key.bytes(), before.session_key.bytes());
    assert_eq!(renewed.renew_till, before.renew_till);
    let listed = mit(&e, &name, "klist", &[], None).unwrap();
    assert!(!listed.contains("host/svc.krb5.test"), "{listed}");
    assert!(
        listed.contains(&format!("krbtgt/{0}@{0}", e.realm)),
        "{listed}"
    );
    mit(&e, &name, "kvno", &["host/svc.krb5.test"], None).unwrap();
    let _ = std::fs::remove_file(&path);
}

/// `kinit -v` both ways, on caches holding a TGT postdated by `kinit -s`.
#[test]
fn kinit_validate_shares_caches_with_mit() {
    let e = live!();
    let path = scratch(&e, "validate");
    let name = format!("FILE:{}", path.display());
    let cache = krb5::CacheName::parse(&name).unwrap();
    if mit(
        &e,
        &name,
        "kinit",
        &["-s", "2s", "alice"],
        Some("alicepw\n"),
    )
    .is_none()
    {
        eprintln!("MIT's krb5 tools not on PATH; skipping");
        return;
    }
    let tgt = krb5::CCache::read(&path).unwrap().tgt(0).unwrap();
    assert!(tgt.is_invalid());
    let err = e.client.kinit_validate(&cache).unwrap_err();
    assert_eq!(err.kdc_code(), Some(33), "KRB_AP_ERR_TKT_NYV: {err}");
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let valid = e.client.kinit_validate(&cache).unwrap();
    assert!(!valid.is_invalid());
    mit(&e, &name, "kvno", &["host/svc.krb5.test"], None).unwrap();

    // Ours postdated, validated by MIT.
    let _ = std::fs::remove_file(&path);
    let kdc = e
        .client
        .clone()
        .with_start_time(Some(std::time::Duration::from_secs(2)));
    kdc.kinit_with_password(&e.p("alice"), "alicepw", &cache)
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2500));
    mit(&e, &name, "kinit", &["-v"], None).unwrap();
    let cc = krb5::CCache::read(&path).unwrap();
    assert!(!cc.tgt(0).unwrap().is_invalid());
    mit(&e, &name, "kvno", &["host/svc.krb5.test"], None).unwrap();
    let _ = std::fs::remove_file(&path);
}

/// A cache with no TGT for its principal's realm is reported as such.
#[test]
fn kinit_renew_needs_a_tgt_in_the_cache() {
    let e = live!();
    let path = scratch(&e, "renew-none");
    let cache = krb5::CacheName::parse(&format!("FILE:{}", path.display())).unwrap();
    krb5::CCache::new(e.p("alice")).write(&path).unwrap();
    let err = e.client.kinit_renew(&cache).unwrap_err();
    assert!(matches!(err, krb5::ClientError::NoTgt { .. }), "{err}");
    let _ = std::fs::remove_file(&path);
}

/// PKINIT against the KDC `scripts/test-kdc.sh` sets up when openssl and
/// MIT's pkinit plugin are there (`KRB5_TEST_PKINIT=1`): a CA in
/// `pki/ca.pem`, the KDC's certificate, and one for alice.
#[cfg(feature = "pkinit")]
mod pkinit {
    use super::*;
    use krb5::CacheName;
    use krb5::pkinit::{DhGroup, Identity, TrustAnchors};

    macro_rules! pk {
        () => {{
            let e = live!();
            if std::env::var("KRB5_TEST_PKINIT").ok().as_deref() != Some("1") {
                eprintln!("KRB5_TEST_PKINIT not set; skipping PKINIT test");
                return;
            }
            e
        }};
    }

    fn conf(e: &Env, extra: &str) -> krb5::Krb5Conf {
        let base = std::fs::read_to_string(format!("{}/krb5.conf", e.dir)).unwrap();
        krb5::Krb5Conf::parse(&format!("{base}\n{extra}\n")).unwrap()
    }

    /// A client from the realm's krb5.conf, whose pkinit_anchors is the
    /// test CA.
    fn client(e: &Env) -> KdcClient {
        KdcClient::from_config(&conf(e, ""), &e.realm).unwrap()
    }

    fn alice(e: &Env) -> Identity {
        Identity::load(&format!(
            "FILE:{0}/pki/alice.pem,{0}/pki/alice-key.pem",
            e.dir
        ))
        .unwrap()
    }

    #[test]
    fn anonymous_pkinit_gives_an_anonymous_tgt_that_works() {
        let e = pk!();
        let tgt = client(&e).login_anonymous().unwrap();
        assert_eq!(
            tgt.client.to_string(),
            "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS"
        );
        assert_eq!(tgt.server, Principal::krbtgt(&e.realm));
        let st = e
            .client
            .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
            .unwrap();
        establish(&e, &st);
    }

    /// alice's P-256 certificate and key.
    fn alice_ec(e: &Env) -> Identity {
        Identity::load(&format!(
            "FILE:{0}/pki/alice-ec.pem,{0}/pki/alice-ec-key.pem",
            e.dir
        ))
        .unwrap()
    }

    /// An MIT 1.22+ KDC, which does ECDH.
    fn ecdh() -> bool {
        let yes = std::env::var("KRB5_TEST_PKINIT_ECDH").ok().as_deref() == Some("1");
        if !yes {
            eprintln!("KRB5_TEST_PKINIT_ECDH not set (KDC before MIT 1.22); skipping ECDH");
        }
        yes
    }

    /// alice's identity from PKCS #12 files, modern and legacy, as `kinit
    /// -X X509_user_identity=PKCS12:...` reads them; and MIT's kinit
    /// reading the same file, its pass phrase on stdin.
    #[test]
    fn certificate_login_from_a_pkcs12_file() {
        let e = pk!();
        let mut files = vec!["alice.p12"];
        if std::path::Path::new(&format!("{}/pki/alice-legacy.p12", e.dir)).exists() {
            files.push("alice-legacy.p12");
        }
        for f in files {
            let spec = format!("PKCS12:{}/pki/{f}", e.dir);
            let err = Identity::load(&spec).unwrap_err();
            assert!(err.to_string().contains("needs a password"), "{err}");
            let err = Identity::load_with_password(&spec, Some("wrong")).unwrap_err();
            assert!(err.to_string().contains("wrong password"), "{err}");
            let id = Identity::load_with_password(&spec, Some("alicep12")).unwrap();
            assert_eq!(id.principals(), [e.p("alice")]);
            let tgt = client(&e)
                .login_with_certificate(&e.p("alice"), &id)
                .unwrap_or_else(|err| panic!("{f}: {err}"));
            assert_eq!(tgt.client, e.p("alice"));
        }
        let path = scratch(&e, "pk-p12-mit");
        let ccname = format!("FILE:{}", path.display());
        let x = format!("X509_user_identity=PKCS12:{}/pki/alice.p12", e.dir);
        if mit(
            &e,
            &ccname,
            "kinit",
            &["-X", &x, "alice"],
            Some("alicep12\n"),
        )
        .is_some()
        {
            assert_eq!(
                krb5::CacheName::File(path).read().unwrap().principal,
                e.p("alice")
            );
        }
    }

    /// An ECDSA client signature, which MIT's KDC verifies (1.20 too).
    #[test]
    fn ec_certificate_login() {
        let e = pk!();
        let id = alice_ec(&e);
        assert_eq!(id.principals(), [e.p("alice")]);
        let tgt = client(&e)
            .login_with_certificate(&e.p("alice"), &id)
            .unwrap();
        assert_eq!(tgt.client, e.p("alice"));
        let st = e
            .client
            .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
            .unwrap();
        establish(&e, &st);
    }

    /// ECDH on each curve, anonymously and with RSA and EC certificates.
    #[test]
    fn ecdh_on_every_curve() {
        let e = pk!();
        if !ecdh() {
            return;
        }
        for group in [DhGroup::P256, DhGroup::P384, DhGroup::P521] {
            let c = client(&e).with_pkinit_dh_group(group);
            c.login_anonymous()
                .unwrap_or_else(|err| panic!("{group:?} anonymous: {err}"));
            for id in [alice(&e), alice_ec(&e)] {
                let tgt = c
                    .login_with_certificate(&e.p("alice"), &id)
                    .unwrap_or_else(|err| panic!("{group:?} certificate: {err}"));
                assert_eq!(tgt.client, e.p("alice"));
            }
        }
    }

    /// CROSS.TEST's KDC wants more than MODP group 14 (P-384 with ECDH,
    /// else 4096 bits): it refuses the default with TD-DH-PARAMETERS, and
    /// the request is made again with its group.
    #[test]
    fn a_kdc_wanting_a_stronger_group_gets_it() {
        let e = pk!();
        let cross = KdcClient::from_config(&conf(&e, ""), "CROSS.TEST").unwrap();
        let tgt = cross.login_anonymous().unwrap();
        assert_eq!(tgt.server, Principal::krbtgt("CROSS.TEST"));
        let strong = if ecdh() {
            DhGroup::P384
        } else {
            DhGroup::Modp4096
        };
        cross
            .with_pkinit_dh_group(strong)
            .login_anonymous()
            .unwrap();
    }

    #[test]
    fn certificate_login_then_a_service_ticket() {
        let e = pk!();
        let id = alice(&e);
        assert_eq!(id.principals(), [e.p("alice")]);
        for group in [DhGroup::Modp2048, DhGroup::Modp4096] {
            let tgt = client(&e)
                .with_pkinit_dh_group(group)
                .login_with_certificate(&e.p("alice"), &id)
                .unwrap();
            assert_eq!(tgt.client, e.p("alice"));
            let st = e
                .client
                .service_ticket(&tgt, &e.p("host/svc.krb5.test"))
                .unwrap();
            establish(&e, &st);
        }
    }

    /// PKINIT inside FAST armor: the AuthPack's checksum is over the inner
    /// body, the KDF over the whole armored request.
    #[test]
    fn certificate_login_inside_fast_armor() {
        let e = pk!();
        let tgt = client(&e)
            .with_fast_armor(armor_tgt(&e))
            .login_with_certificate(&e.p("alice"), &alice(&e))
            .unwrap();
        assert_eq!(tgt.client, e.p("alice"));
    }

    #[test]
    fn the_kdc_refuses_a_certificate_for_someone_else() {
        let e = pk!();
        let err = client(&e)
            .login_with_certificate(&e.p("robot"), &alice(&e))
            .unwrap_err();
        // KDC_ERR_CLIENT_NAME_MISMATCH
        assert_eq!(err.kdc_code(), Some(75), "{err}");
        // bob needs no pre-authentication: the KDC answers in bob's
        // password key, which a certificate holder cannot have, so the
        // reply is refused rather than half-trusted.
        let err = client(&e)
            .login_with_certificate(&e.p("bob"), &alice(&e))
            .unwrap_err();
        assert!(matches!(err, krb5::ClientError::NoKey(_)), "{err}");
    }

    #[test]
    fn a_kdc_certificate_from_an_untrusted_ca_is_refused() {
        let e = pk!();
        let other =
            TrustAnchors::from_pem(include_bytes!("../src/pkinit/testdata/other-ca.pem")).unwrap();
        for c in [
            client(&e).with_pkinit_anchors(other),
            KdcClient::new(e.realm.clone(), [std::env::var("KRB5_TEST_KDC").unwrap()]),
        ] {
            let err = c.login_anonymous().unwrap_err();
            assert!(matches!(err, krb5::ClientError::Pkinit(_)), "{err}");
            let err = c
                .login_with_certificate(&e.p("alice"), &alice(&e))
                .unwrap_err();
            assert!(matches!(err, krb5::ClientError::Pkinit(_)), "{err}");
        }
    }

    /// Our kinit -n and kinit -X caches, read by MIT's klist and used by
    /// MIT's kvno.
    #[test]
    fn mit_tools_use_pkinit_caches_we_wrote() {
        let e = pk!();
        let path = scratch(&e, "pk-anon");
        let cache = CacheName::File(path.clone());
        client(&e).kinit_anonymous(&cache).unwrap();
        let ccname = format!("FILE:{}", path.display());
        if let Some(out) = mit(&e, &ccname, "klist", &[], None) {
            assert!(
                out.contains("WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS"),
                "{out}"
            );
        }
        let path = scratch(&e, "pk-cert");
        let cache = CacheName::File(path.clone());
        client(&e)
            .kinit_with_certificate(&e.p("alice"), &alice(&e), &cache)
            .unwrap();
        // pa_type 16: PA-PK-AS-REQ, as MIT's kinit records it.
        let cc = cache.read().unwrap();
        assert_eq!(
            cc.config("pa_type", Some(&Principal::krbtgt(&e.realm))),
            Some(&b"16"[..])
        );
        let ccname = format!("FILE:{}", path.display());
        if let Some(out) = mit(&e, &ccname, "kvno", &["host/svc.krb5.test"], None) {
            assert!(out.contains("host/svc.krb5.test"), "{out}");
        }
    }

    /// A relay in front of the KDC, over UDP and TCP, that passes every
    /// reply through `tamper`.
    fn tampering_relay(tamper: fn(&mut [u8])) -> String {
        use std::io::{Read, Write};
        let kdc: std::net::SocketAddr = std::env::var("KRB5_TEST_KDC").unwrap().parse().unwrap();
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = u.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            while let Ok((n, from)) = u.recv_from(&mut buf) {
                let up = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                up.connect(kdc).unwrap();
                up.send(&buf[..n]).unwrap();
                let mut r = [0u8; 65535];
                let m = up.recv(&mut r).unwrap();
                let mut rep = r[..m].to_vec();
                tamper(&mut rep);
                u.send_to(&rep, from).unwrap();
            }
        });
        let t = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::thread::spawn(move || {
            for c in t.incoming() {
                let mut c = c.unwrap();
                let mut up = std::net::TcpStream::connect(kdc).unwrap();
                let mut len = [0u8; 4];
                c.read_exact(&mut len).unwrap();
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                c.read_exact(&mut req).unwrap();
                up.write_all(&len).unwrap();
                up.write_all(&req).unwrap();
                up.read_exact(&mut len).unwrap();
                let mut rep = vec![0u8; u32::from_be_bytes(len) as usize];
                up.read_exact(&mut rep).unwrap();
                tamper(&mut rep);
                c.write_all(&len).unwrap();
                c.write_all(&rep).unwrap();
            }
        });
        format!("127.0.0.1:{port}")
    }

    /// Flip the last octet of an AS-REP's PA-PKINIT-KX (type 147) value,
    /// the end of its ciphertext: `[1] INTEGER 147, [2] OCTET STRING`.
    /// (KRB-ERRORs advertise PA-PKINIT-KX empty, and pass untouched.)
    fn corrupt_pkinit_kx(rep: &mut [u8]) {
        if rep.first() != Some(&0x6B) {
            return;
        }
        let pat = [0xA1, 0x04, 0x02, 0x02, 0x00, 0x93, 0xA2];
        let Some(at) = rep.windows(pat.len()).position(|w| w == pat) else {
            return;
        };
        let mut i = at + pat.len();
        let len = match rep[i] {
            n if n < 0x80 => {
                i += 1;
                n as usize
            }
            0x81 => {
                i += 2;
                rep[i - 1] as usize
            }
            _ => {
                i += 3;
                (rep[i - 2] as usize) << 8 | rep[i - 1] as usize
            }
        };
        rep[i + len - 1] ^= 1;
    }

    /// A man in the middle who alters the KDC's PA-PKINIT-KX cannot get
    /// an anonymous login accepted: the session key must come from it.
    #[test]
    fn an_altered_pkinit_kx_fails_the_anonymous_login() {
        let e = pk!();
        let addr = tampering_relay(corrupt_pkinit_kx);
        let anchors = TrustAnchors::load(&format!("FILE:{}/pki/ca.pem", e.dir)).unwrap();
        let c = KdcClient::new(e.realm.clone(), [addr]).with_pkinit_anchors(anchors.clone());
        let err = c.login_anonymous().unwrap_err();
        assert!(matches!(err, krb5::ClientError::Crypto(_)), "{err}");
        // Untouched, the same relay path works.
        let clean = tampering_relay(|_| {});
        KdcClient::new(e.realm.clone(), [clean])
            .with_pkinit_anchors(anchors)
            .login_anonymous()
            .unwrap();
    }

    /// MIT's `kinit -n` cache is FAST armor for us.
    #[test]
    fn mits_anonymous_cache_is_our_fast_armor() {
        let e = pk!();
        let path = scratch(&e, "pk-mit-anon");
        let ccname = format!("FILE:{}", path.display());
        if mit(
            &e,
            &ccname,
            "kinit",
            &["-n", &format!("@{}", e.realm)],
            None,
        )
        .is_none()
        {
            return;
        }
        // SPAKE off: only the encrypted challenge proves FAST.
        let kdc = e
            .client
            .clone()
            .with_spake_groups(&[])
            .with_fast_armor_cache(&CacheName::File(path))
            .unwrap();
        let out = scratch(&e, "pk-armored");
        let out = CacheName::File(out);
        kdc.kinit_with_password(&e.p("alice"), "alicepw", &out)
            .unwrap();
        // PA-ENCRYPTED-CHALLENGE: only possible inside FAST.
        assert_eq!(
            out.read()
                .unwrap()
                .config("pa_type", Some(&Principal::krbtgt(&e.realm))),
            Some(&b"138"[..])
        );
    }

    /// `auto_fast_armor = true`: an anonymous PKINIT TGT first, then the
    /// login inside its armor.
    #[test]
    fn auto_fast_armor_from_krb5_conf() {
        let e = pk!();
        let conf = conf(
            &e,
            &format!("[realms]\n {} = {{\n  auto_fast_armor = true\n }}", e.realm),
        );
        let anon_before = as_requests(&e, "WELLKNOWN/ANONYMOUS");
        let out = CacheName::File(scratch(&e, "pk-auto"));
        // SPAKE off: only the encrypted challenge proves FAST.
        KdcClient::from_config(&conf, &e.realm)
            .unwrap()
            .with_spake_groups(&[])
            .kinit_with_password(&e.p("alice"), "alicepw", &out)
            .unwrap();
        assert!(as_requests(&e, "WELLKNOWN/ANONYMOUS") > anon_before);
        assert_eq!(
            out.read()
                .unwrap()
                .config("pa_type", Some(&Principal::krbtgt(&e.realm))),
            Some(&b"138"[..])
        );
    }
}

// ------------------------------------------------------- kadmin, kpasswd

/// kadmind as `scripts/test-kdc.sh` runs it: admin/admin may do anything,
/// limited may only inquire and list.
mod kadmin {
    use super::*;
    use krb5::kadmin::{AdminClient, Policy, PrincipalChanges, attributes};
    use krb5::kpasswd;

    macro_rules! kadm {
        () => {{
            let e = live!();
            let Ok(server) = std::env::var("KRB5_TEST_KADMIN") else {
                eprintln!("KRB5_TEST_KADMIN not set; skipping kadmin test");
                return;
            };
            (e, server)
        }};
    }

    fn admin(e: &Env, server: &str) -> AdminClient {
        AdminClient::connect_with_password(&e.client, &e.p("admin/admin"), "adminpw", server)
            .unwrap()
    }

    /// MIT's kadmin, as admin/admin, running `query`.
    fn mit_kadmin(e: &Env, query: &str) -> Option<String> {
        let cc = format!("FILE:{}", scratch(e, "kadmin-cc").display());
        mit(
            e,
            &cc,
            "kadmin",
            &["-p", "admin/admin", "-w", "adminpw", "-q", query],
            None,
        )
    }

    /// A fresh name for this test run.
    fn fresh(e: &Env, tag: &str) -> Principal {
        e.p(&format!("{tag}{}", std::process::id()))
    }

    #[test]
    fn connect_negotiates_and_reports_privileges() {
        let (e, server) = kadm!();
        let mut a = admin(&e, &server);
        assert_eq!(
            a.api_version(),
            0x1234_5704,
            "MIT 1.18+ speak API version 4"
        );
        let p = a.privileges().unwrap();
        assert!(p.get() && p.add() && p.modify() && p.delete());
        let mut l =
            AdminClient::connect_with_password(&e.client, &e.p("limited"), "limitedpw", &server)
                .unwrap();
        // MIT's kadmind reports every privilege to everyone; what the ACL
        // does not allow it refuses per operation, by name.
        assert_eq!(l.privileges().unwrap(), p);
        let err = l
            .create_principal(
                &fresh(&e, "denied"),
                &PrincipalChanges::default(),
                Some("x"),
            )
            .unwrap_err();
        assert_eq!(
            err.code().and_then(|c| c.name()),
            Some("KADM5_AUTH_ADD"),
            "{err}"
        );
        assert!(!l.list_principals("*").unwrap().is_empty());
        // A wrong password never reaches kadmind.
        assert!(
            AdminClient::connect_with_password(&e.client, &e.p("admin/admin"), "wrong", &server)
                .is_err()
        );
        a.close();
    }

    #[test]
    fn getprinc_and_listprincs_agree_with_mit() {
        let (e, server) = kadm!();
        let mut a = admin(&e, &server);
        let alice = a.get_principal(&e.p("alice")).unwrap();
        assert_eq!(alice.principal, e.p("alice"));
        assert!(alice.attributes & attributes::REQUIRES_PRE_AUTH != 0);
        assert_eq!(alice.keys.len(), 4, "the four AES enctypes");
        assert!(alice.keys.iter().all(|k| k.kvno == alice.kvno));
        let err = a.get_principal(&e.p("nobody")).unwrap_err();
        assert!(
            err.code().is_some_and(|c| c.is_unknown_principal()),
            "{err}"
        );
        let ours: Vec<String> = a
            .list_principals("*")
            .unwrap()
            .iter()
            .map(|p| p.to_string())
            .collect();
        if let Some(out) = mit_kadmin(&e, "listprincs") {
            let theirs: Vec<&str> = out.lines().filter(|l| l.contains('@')).collect();
            assert_eq!(ours, theirs);
            let gp = mit_kadmin(&e, "getprinc alice").unwrap();
            assert!(gp.contains(&format!("Key: vno {}", alice.kvno)), "{gp}");
        }
    }

    /// Our addprinc, modprinc, cpw, renprinc and delprinc, each seen by
    /// MIT's kadmin and kinit.
    #[test]
    fn principals_made_and_changed_here_are_what_mit_sees() {
        let (e, server) = kadm!();
        let mut a = admin(&e, &server);
        let p = fresh(&e, "made");
        let changes = PrincipalChanges {
            max_life: Some(3600),
            max_renewable_life: Some(7200),
            ..PrincipalChanges::default()
        };
        a.create_principal(&p, &changes, Some("first-pw-1"))
            .unwrap();
        let err = a.create_principal(&p, &changes, Some("again")).unwrap_err();
        assert_eq!(err.code().and_then(|c| c.name()), Some("KADM5_DUP"));
        let tgt = e.client.login_with_password(&p, "first-pw-1").unwrap();
        assert!(tgt.endtime - tgt.authtime <= 3600);
        if let Some(out) = mit_kadmin(&e, &format!("getprinc {p}")) {
            assert!(
                out.contains("Maximum ticket life: 0 days 01:00:00"),
                "{out}"
            );
        }

        let entry = a.get_principal(&p).unwrap();
        a.modify_principal(
            &p,
            &PrincipalChanges::default().with_attributes(&entry, attributes::DISALLOW_ALL_TIX, 0),
        )
        .unwrap();
        assert!(
            e.client.login_with_password(&p, "first-pw-1").is_err(),
            "-allow_tix"
        );
        if let Some(out) = mit_kadmin(&e, &format!("getprinc {p}")) {
            assert!(out.contains("DISALLOW_ALL_TIX"), "{out}");
        }
        let entry = a.get_principal(&p).unwrap();
        a.modify_principal(
            &p,
            &PrincipalChanges::default().with_attributes(&entry, 0, attributes::DISALLOW_ALL_TIX),
        )
        .unwrap();

        a.change_password(&p, "second-pw-2").unwrap();
        e.client.login_with_password(&p, "second-pw-2").unwrap();
        assert!(a.get_principal(&p).unwrap().kvno > entry.kvno);

        let q = fresh(&e, "renamed");
        a.rename_principal(&p, &q).unwrap();
        assert!(
            a.get_principal(&p)
                .unwrap_err()
                .code()
                .unwrap()
                .is_unknown_principal()
        );
        a.delete_principal(&q).unwrap();
        if let Some(out) = mit_kadmin(&e, &format!("getprinc {q}")) {
            assert!(!out.contains("Principal:"), "{out}");
        }
    }

    /// addprinc -randkey, then ktadd: MIT's klist reads the keytab, and the
    /// keys in it are the KDC's (a keytab login works). ktadd -norandkey
    /// keeps them.
    #[test]
    fn random_keys_and_ktadd_make_a_keytab_mit_reads() {
        let (e, server) = kadm!();
        let mut a = admin(&e, &server);
        let p =
            Principal::parse_in_realm(&format!("svc/kt{}.krb5.test", std::process::id()), &e.realm)
                .unwrap();
        a.create_principal(&p, &PrincipalChanges::default(), None)
            .unwrap();
        let kt = scratch(&e, "ktadd");
        let written = a.ktadd(&p, &kt, true).unwrap();
        assert_eq!(written.len(), 4);
        let kvno = written[0].kvno;
        assert_eq!(a.get_principal(&p).unwrap().kvno, kvno);
        let keytab = Keytab::load(&kt).unwrap();
        e.client.login_with_keytab(&p, &keytab).unwrap();
        if let Some(out) = mit(
            &e,
            "FILE:/dev/null",
            "klist",
            &["-k", "-e", &kt.display().to_string()],
            None,
        ) {
            assert_eq!(out.matches(&p.to_string()).count(), 4, "{out}");
            assert!(out.contains("aes256-cts-hmac-sha384-192"), "{out}");
        }
        // -norandkey: the same keys again, appended.
        let again = a.ktadd(&p, &kt, false).unwrap();
        assert!(again.iter().all(|k| k.kvno == kvno));
        let mut keys: Vec<_> = written.iter().map(|k| k.key.clone()).collect();
        let mut keys2: Vec<_> = again.iter().map(|k| k.key.clone()).collect();
        keys.sort();
        keys2.sort();
        assert_eq!(keys, keys2);
        assert_eq!(Keytab::load(&kt).unwrap().keys().len(), 8);
        // randkey: new keys, a new kvno, and the old keytab no longer works.
        let (kvno2, fresh_keys) = a.randomize_keys(&p).unwrap();
        assert!(kvno2 > kvno && fresh_keys.len() == 4);
        assert!(
            e.client
                .login_with_keytab(&p, &Keytab::load(&kt).unwrap())
                .is_err()
        );
        a.delete_principal(&p).unwrap();
    }

    #[test]
    fn policies_and_string_attributes_round_trip_with_mit() {
        let (e, server) = kadm!();
        let mut a = admin(&e, &server);
        let name = format!("pol{}", std::process::id());
        let pol = Policy {
            name: name.clone(),
            pw_min_length: 12,
            pw_min_classes: 2,
            pw_max_fail: 5,
            pw_lockout_duration: 600,
            ..Policy::default()
        };
        a.create_policy(&pol).unwrap();
        let got = a.get_policy(&name).unwrap();
        assert_eq!(
            (got.pw_min_length, got.pw_min_classes, got.pw_max_fail),
            (12, 2, 5)
        );
        assert!(a.list_policies("*").unwrap().contains(&name));
        if let Some(out) = mit_kadmin(&e, &format!("getpol {name}")) {
            assert!(out.contains("Minimum password length: 12"), "{out}");
        }
        a.modify_policy(&Policy {
            pw_min_length: 14,
            ..pol.clone()
        })
        .unwrap();
        assert_eq!(a.get_policy(&name).unwrap().pw_min_length, 14);

        // A principal under the policy: a short password is refused.
        let p = fresh(&e, "pol");
        let under = PrincipalChanges {
            policy: Some(Some(name.clone())),
            ..PrincipalChanges::default()
        };
        let err = a.create_principal(&p, &under, Some("short1A")).unwrap_err();
        assert_eq!(
            err.code().and_then(|c| c.name()),
            Some("KADM5_PASS_Q_TOOSHORT"),
            "{err}"
        );
        a.create_principal(&p, &under, Some("long-enough-Pw-1"))
            .unwrap();
        assert_eq!(
            a.get_principal(&p).unwrap().policy.as_deref(),
            Some(name.as_str())
        );

        a.set_string(&p, "session_enctypes", Some("aes256-cts"))
            .unwrap();
        assert_eq!(
            a.get_strings(&p).unwrap(),
            [("session_enctypes".into(), "aes256-cts".into())]
        );
        if let Some(out) = mit_kadmin(&e, &format!("getstrs {p}")) {
            assert!(out.contains("session_enctypes: aes256-cts"), "{out}");
            mit_kadmin(&e, &format!("setstr {p} require_auth otp"));
            assert!(
                a.get_strings(&p)
                    .unwrap()
                    .contains(&("require_auth".into(), "otp".into()))
            );
        }
        a.set_string(&p, "session_enctypes", None).unwrap();
        assert!(
            !a.get_strings(&p)
                .unwrap()
                .iter()
                .any(|(k, _)| k == "session_enctypes")
        );

        a.modify_principal(
            &p,
            &PrincipalChanges {
                policy: Some(None),
                ..PrincipalChanges::default()
            },
        )
        .unwrap();
        assert_eq!(a.get_principal(&p).unwrap().policy, None);
        a.delete_principal(&p).unwrap();
        a.delete_policy(&name).unwrap();
        assert!(a.get_policy(&name).is_err());
    }

    #[test]
    fn kpasswd_changes_and_sets_passwords() {
        let (e, server) = kadm!();
        let kp = std::env::var("KRB5_TEST_KPASSWD").unwrap();
        let mut a = admin(&e, &server);
        let p = fresh(&e, "kpw");
        a.create_principal(&p, &PrincipalChanges::default(), Some("kpw-old-1"))
            .unwrap();

        kpasswd::change_password(&e.client, &p, "kpw-old-1", "kpw-new-2", &kp).unwrap();
        e.client.login_with_password(&p, "kpw-new-2").unwrap();
        // MIT's kinit agrees.
        let cc = format!("FILE:{}", scratch(&e, "kpw-mit").display());
        mit(&e, &cc, "kinit", &[&p.to_string()], Some("kpw-new-2\n"));

        // An administrator sets it (RFC 3244 set-password).
        let svc = kpasswd::changepw_service(&e.realm);
        let t = e
            .client
            .initial_ticket_with_password(&e.p("admin/admin"), "adminpw", &svc)
            .unwrap();
        kpasswd::set_password(&t, &p, "kpw-set-3", &kp).unwrap();
        e.client.login_with_password(&p, "kpw-set-3").unwrap();
        // limited may not set others' passwords.
        let t = e
            .client
            .initial_ticket_with_password(&e.p("limited"), "limitedpw", &svc)
            .unwrap();
        let err = kpasswd::set_password(&t, &p, "kpw-no-4", &kp).unwrap_err();
        assert!(matches!(err, kpasswd::Error::Refused { .. }), "{err}");

        // Policy refusals come back with kadmind's reason.
        let name = format!("kpwpol{}", std::process::id());
        a.create_policy(&Policy {
            name: name.clone(),
            pw_min_length: 20,
            ..Policy::default()
        })
        .unwrap();
        a.modify_principal(
            &p,
            &PrincipalChanges {
                policy: Some(Some(name.clone())),
                ..PrincipalChanges::default()
            },
        )
        .unwrap();
        let err = kpasswd::change_password(&e.client, &p, "kpw-set-3", "short", &kp).unwrap_err();
        match err {
            kpasswd::Error::Refused { code, message } => {
                assert_eq!(code, kpasswd::ResultCode::SoftError);
                assert!(message.to_lowercase().contains("too short"), "{message}");
            }
            other => panic!("{other}"),
        }
        a.delete_principal(&p).unwrap();
        a.delete_policy(&name).unwrap();
    }

    type Tamper = Box<dyn FnMut(usize, &mut Vec<u8>, &[Vec<u8>]) + Send>;

    /// A TCP relay to `target` that passes each reply (the n-th on any
    /// connection, the replies before it, untouched) through `tamper`.
    /// Framing is a 4-octet length, RPC's last-fragment bit kept.
    fn tamper_relay(target: String, mut tamper: Tamper) -> String {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let read = |s: &mut std::net::TcpStream| -> Option<(u32, Vec<u8>)> {
                let mut h = [0u8; 4];
                s.read_exact(&mut h).ok()?;
                let h = u32::from_be_bytes(h);
                let mut m = vec![0; (h & 0x7FFF_FFFF) as usize];
                s.read_exact(&mut m).ok()?;
                Some((h & 0x8000_0000, m))
            };
            let mut n = 0;
            let mut history = Vec::new();
            for c in l.incoming() {
                let mut c = c.unwrap();
                let mut up = std::net::TcpStream::connect(&target).unwrap();
                while let Some((bit, req)) = read(&mut c) {
                    up.write_all(&(bit | req.len() as u32).to_be_bytes())
                        .unwrap();
                    up.write_all(&req).unwrap();
                    let Some((bit, rep)) = read(&mut up) else {
                        break;
                    };
                    let mut out = rep.clone();
                    tamper(n, &mut out, &history);
                    history.push(rep);
                    n += 1;
                    c.write_all(&(bit | out.len() as u32).to_be_bytes())
                        .unwrap();
                    c.write_all(&out).unwrap();
                }
            }
        });
        addr
    }

    /// An accepted RPC reply's verifier octets and where its results start.
    fn rpc_parts(rep: &[u8]) -> (std::ops::Range<usize>, usize) {
        let len = u32::from_be_bytes(rep[16..20].try_into().unwrap()) as usize;
        let end = 20 + len.div_ceil(4) * 4;
        (20..20 + len, end + 4)
    }

    /// Replies 0 (the context), 1 (kadm5 INIT) and 2 (getprinc), each
    /// altered so that exactly one check must catch it.
    #[test]
    fn rpcsec_gss_replies_are_bound_to_their_calls() {
        let (e, server) = kadm!();
        let ticket = e
            .client
            .initial_ticket_with_password(
                &e.p("admin/admin"),
                "adminpw",
                &Principal::new(1, ["kadmin", "admin"], e.realm.clone()),
            )
            .unwrap();
        let run = |t: Tamper| -> Result<(), String> {
            let relay = tamper_relay(server.clone(), t);
            let mut a = AdminClient::connect(&relay, &ticket).map_err(|e| e.to_string())?;
            a.get_principal(&e.p("alice"))
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        run(Box::new(|_, _, _| {})).unwrap();
        // The context's verifier (a MIC over the window), forged.
        let err = run(Box::new(|n, r, _| {
            if n == 0 {
                let (v, _) = rpc_parts(r);
                r[v.end - 1] ^= 1;
            }
        }))
        .unwrap_err();
        assert!(err.contains("context verifier"), "{err}");
        // A reply's verifier (a MIC over its sequence number), forged.
        let err = run(Box::new(|n, r, _| {
            if n == 2 {
                let (v, _) = rpc_parts(r);
                r[v.end - 1] ^= 1;
            }
        }))
        .unwrap_err();
        assert!(err.contains("reply verifier"), "{err}");
        // A reply for another call.
        let err = run(Box::new(|n, r, _| {
            if n == 2 {
                r[3] ^= 1;
            }
        }))
        .unwrap_err();
        assert!(err.contains("another call"), "{err}");
        // The right verifier around the previous call's sealed results.
        let err = run(Box::new(|n, r, h| {
            if n == 2 {
                let (_, body) = rpc_parts(r);
                let (_, old_body) = rpc_parts(&h[1]);
                r.truncate(body);
                r.extend_from_slice(&h[1][old_body..]);
            }
        }))
        .unwrap_err();
        assert!(err.contains("sequence number"), "{err}");
    }

    /// kpasswd: the AP-REP of an earlier exchange (same ticket, so it
    /// decrypts) does not answer this one.
    #[test]
    fn kpasswd_replies_must_answer_this_request() {
        let (e, server) = kadm!();
        let kp = std::env::var("KRB5_TEST_KPASSWD").unwrap();
        let mut a = admin(&e, &server);
        let p = fresh(&e, "kpwmitm");
        a.create_principal(&p, &PrincipalChanges::default(), Some("mitm-old-1"))
            .unwrap();
        let t = e
            .client
            .initial_ticket_with_password(&p, "mitm-old-1", &kpasswd::changepw_service(&e.realm))
            .unwrap();
        let relay = tamper_relay(
            kp,
            Box::new(|n, r, h| {
                if n == 1 {
                    // len(2) vno(2) ap-rep-len(2) AP-REP KRB-PRIV
                    let ap = |m: &[u8]| usize::from(u16::from_be_bytes([m[4], m[5]]));
                    let old_ap = &h[0][6..6 + ap(&h[0])];
                    let priv_ = r[6 + ap(r)..].to_vec();
                    let mut m = Vec::new();
                    m.extend_from_slice(&((6 + old_ap.len() + priv_.len()) as u16).to_be_bytes());
                    m.extend_from_slice(&r[2..4]);
                    m.extend_from_slice(&(old_ap.len() as u16).to_be_bytes());
                    m.extend_from_slice(old_ap);
                    m.extend_from_slice(&priv_);
                    *r = m;
                }
            }),
        );
        kpasswd::change_password_with_ticket(&t, "mitm-new-2", &relay).unwrap();
        let err = kpasswd::change_password_with_ticket(&t, "mitm-new-3", &relay).unwrap_err();
        assert!(err.to_string().contains("echo"), "{err}");
        a.delete_principal(&p).unwrap();
    }

    /// The kadmin and kpasswd servers from krb5.conf, as MIT finds them.
    #[test]
    fn servers_come_from_krb5_conf() {
        let (e, server) = kadm!();
        let conf = krb5::Krb5Conf::load([format!("{}/krb5.conf", e.dir)]).unwrap();
        assert_eq!(AdminClient::admin_server(&conf, &e.realm).unwrap(), server);
        assert_eq!(
            kpasswd::kpasswd_server(&conf, &e.realm).unwrap(),
            std::env::var("KRB5_TEST_KPASSWD").unwrap()
        );
    }
}
