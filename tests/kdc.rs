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
    let start = tgt.starttime.unwrap_or(tgt.authtime);
    assert_eq!(tgt.endtime - start, 2 * 3600, "ticket_lifetime");
    assert_eq!(
        tgt.renew_till.expect("renewable") - start,
        3 * 86400,
        "renew_lifetime"
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
    // PREAUTH_REQUIRED, AS-REQ, TGS-REQ: all UDP, nothing else on offer.
    assert_eq!(*seen.lock().unwrap(), ["udp", "udp", "udp"]);
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
