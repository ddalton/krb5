//! Tickets for services in other realms, as MIT's `get_creds.c` gets them.
//!
//! 1. **Referrals** (RFC 6806). Ask the KDC of the realm in hand for the
//!    service with the canonicalize option. It answers with the ticket, or
//!    with a cross-realm TGT `krbtgt/NEXT@HERE` for a realm closer to the
//!    service; follow it to NEXT's KDC and ask again. At most
//!    [`MAX_HOPS`] referrals, and never the same realm twice.
//! 2. **A path to a known realm.** When the service names its realm,
//!    first get a TGT for that realm: from the cache if there is one, else
//!    along the path `client realm, [capaths] intermediates, service
//!    realm`, asking each KDC on it for the furthest realm it will give a
//!    TGT for. A KDC may answer with a TGT for a realm off the path; that
//!    is followed too, up to [`MAX_HOPS`] times.
//! 3. **Fallback.** If the very first referral request fails and the
//!    service had no realm, guess the realm from the host name (its domain,
//!    upper-cased, as `krb5_get_fallback_host_realm`) and go there
//!    without referrals.
//!
//! A service named with an empty realm (`host/x.example.com@`, MIT's
//! "referral realm") starts at the client's realm. The credentials
//! returned (and cached) carry the server name as requested, as MIT
//! stores them; the ticket inside names the real realm.

use super::{ClientError, Credentials, KdcClient, Principal, Result};
use crate::config::Krb5Conf;
use tracing::debug;

/// MIT's `KRB5_REFERRAL_MAXHOPS`.
pub const MAX_HOPS: usize = 10;

/// KDCOptions canonicalize (RFC 6806 §3; bit 15, numbered from the MSB).
pub(crate) const KDC_OPT_CANONICALIZE: u32 = 1 << 16;

/// TGTs picked up along the way, and the cache they may come from.
pub(crate) trait TgtStore {
    /// An unexpired TGT for `realm` (`krbtgt/realm@ANY`).
    fn cached_tgt(&self, realm: &str) -> Option<Credentials>;
    /// A TGT obtained on the way, worth keeping.
    fn remember(&mut self, tgt: &Credentials);
}

/// No cache: every TGT is fetched.
pub(crate) struct NoStore;

impl TgtStore for NoStore {
    fn cached_tgt(&self, _: &str) -> Option<Credentials> {
        None
    }
    fn remember(&mut self, _: &Credentials) {}
}

/// `krbtgt/X@Y`.
pub(crate) fn is_tgs(p: &Principal) -> bool {
    p.components.len() == 2 && p.components[0] == "krbtgt"
}

/// The realm whose KDC accepts `tgt`: the X of `krbtgt/X@Y`.
pub(crate) fn tgt_realm(tgt: &Credentials) -> &str {
    &tgt.server.components[1]
}

/// `[capaths] CLIENT SERVER` intermediates; `.` means none.
fn realm_path(conf: &Krb5Conf, client: &str, server: &str) -> Vec<String> {
    let mut path = vec![client.to_string()];
    let caps = conf.get_all(&["capaths", client, server]);
    if caps.first() != Some(&".") {
        // MIT takes each value up to the first blank.
        path.extend(
            caps.iter()
                .filter_map(|v| v.split([' ', '\t']).next())
                .map(str::to_string),
        );
    }
    path.push(server.to_string());
    path
}

/// MIT's `krb5_get_fallback_host_realm` for a `service/host` principal:
/// the host's domain, upper-cased, or the default realm for a bare name.
fn fallback_realm(conf: &Krb5Conf, host: &str) -> Option<String> {
    let host = host.trim_end_matches('.');
    match host.split_once('.') {
        Some((_, domain)) if !domain.is_empty() => Some(domain.to_ascii_uppercase()),
        _ => conf.default_realm().map(str::to_string),
    }
}

impl KdcClient {
    /// The whole MIT algorithm: from `start` (a TGT for the client's realm)
    /// to a ticket for `service`.
    pub(crate) fn get_creds(
        &self,
        start: &Credentials,
        service: &Principal,
        store: &mut dyn TgtStore,
    ) -> Result<Credentials> {
        let mut tgs =
            |tgt: &Credentials, server: &Principal, opts: u32| self.tgs(tgt, server, opts);
        get_creds_with(&self.conf, start, service, store, &mut tgs)
    }
}

/// One TGS exchange: (TGT, requested server, KDC options) -> reply.
pub(crate) type Tgs<'a> = dyn FnMut(&Credentials, &Principal, u32) -> Result<Credentials> + 'a;

/// The algorithm, with the exchange abstracted so it can be tested
/// against a scripted set of realms.
pub(crate) fn get_creds_with(
    conf: &Krb5Conf,
    start: &Credentials,
    service: &Principal,
    store: &mut dyn TgtStore,
    tgs: &mut Tgs<'_>,
) -> Result<Credentials> {
    if !is_tgs(&start.server) {
        return Err(ClientError::Protocol(format!(
            "{} is not a TGT",
            start.server
        )));
    }
    let start_realm = tgt_realm(start).to_string();
    let mut server = service.clone();
    let referral_req = server.realm.is_empty();
    if referral_req {
        server.realm = start_realm.clone();
    }

    let mut cur = tgt_for(conf, start, &server.realm, store, tgs)?;
    let mut seen: Vec<String> = Vec::new();
    for count in 1.. {
        let reply = match tgs(&cur, &server, KDC_OPT_CANONICALIZE) {
            Ok(r) => r,
            // Only the first referral request has a fallback.
            Err(e) if count > 1 => return Err(e),
            Err(e) if !referral_req => {
                debug!("{server}: referral request failed ({e}); asking without canonicalize");
                return non_referral(&cur, &server, service, tgs);
            }
            Err(e) => {
                let Some(realm) = server
                    .components
                    .get(1)
                    .filter(|_| server.components.len() >= 2)
                    .and_then(|h| fallback_realm(conf, h))
                else {
                    return Err(e);
                };
                debug!("{server}: referral request failed ({e}); falling back to {realm}");
                if realm != server.realm {
                    server.realm = realm;
                    cur = tgt_for(conf, start, &server.realm, store, tgs)?;
                }
                return non_referral(&cur, &server, service, tgs);
            }
        };

        // The ticket we asked for (the KDC may canonicalize its realm).
        if same_any_realm(&reply.server, &server) {
            return Ok(as_requested(reply, service));
        }
        // Old Active Directory rewrites the name instead of referring.
        if !is_tgs(&reply.server) {
            return non_referral(&cur, &server, service, tgs);
        }
        let next = tgt_realm(&reply).to_string();
        // Active Directory may hand back a TGT for the realm we are in.
        if next == tgt_realm(&cur) {
            return non_referral(&cur, &server, service, tgs);
        }
        if count >= MAX_HOPS {
            return Err(ClientError::Referral(format!(
                "more than {MAX_HOPS} referrals for {service}"
            )));
        }
        if seen.contains(&next) {
            return Err(ClientError::Referral(format!(
                "referral loop for {service} at {next}"
            )));
        }
        debug!("{server}: referred to {next}");
        seen.push(next.clone());
        store.remember(&reply);
        cur = reply;
        server.realm = next;
    }
    unreachable!()
}

/// One plain request for the service, no canonicalize, no fallbacks.
fn non_referral(
    tgt: &Credentials,
    server: &Principal,
    service: &Principal,
    tgs: &mut Tgs<'_>,
) -> Result<Credentials> {
    Ok(as_requested(tgs(tgt, server, 0)?, service))
}

/// A TGT usable at `realm`'s KDC, starting from `start`.
fn tgt_for(
    conf: &Krb5Conf,
    start: &Credentials,
    realm: &str,
    store: &mut dyn TgtStore,
    tgs: &mut Tgs<'_>,
) -> Result<Credentials> {
    let start_realm = tgt_realm(start).to_string();
    if realm == start_realm {
        return Ok(start.clone());
    }
    let path = realm_path(conf, &start_realm, realm);
    let last = path.len() - 1;
    let (mut cur_i, mut next_i) = (0, last);
    let mut cur = start.clone();
    let mut seen: Vec<String> = Vec::new();
    loop {
        if let Some(t) = store.cached_tgt(&path[next_i]) {
            cur = t;
            if next_i == last {
                return Ok(cur);
            }
            cur_i = next_i;
            next_i = last;
            continue;
        }
        let want = Principal::krbtgt_for(&path[next_i], tgt_realm(&cur));
        match tgs(&cur, &want, 0) {
            Err(e) => {
                // Try the next-closest realm on the path.
                next_i -= 1;
                if next_i == cur_i {
                    return Err(e);
                }
            }
            Ok(reply) => {
                if !is_tgs(&reply.server) {
                    return Err(modified(&reply.server));
                }
                let got = tgt_realm(&reply).to_string();
                seen.push(got.clone());
                match path[cur_i + 1..].iter().position(|r| *r == got) {
                    Some(off) => {
                        let at = cur_i + 1 + off;
                        if at == next_i {
                            store.remember(&reply);
                        }
                        cur = reply;
                        if at == last {
                            return Ok(cur);
                        }
                        cur_i = at;
                        next_i = last;
                    }
                    None if got == start_realm => {
                        return Err(ClientError::Referral(format!(
                            "referred back to {start_realm} on the way to {realm}"
                        )));
                    }
                    None => return offpath(reply, realm, seen, store, tgs),
                }
            }
        }
    }
}

/// MIT's STATE_GET_TGT_OFFPATH: a KDC gave a TGT for a realm off our
/// path; keep asking whoever we can reach for `realm`'s TGT.
fn offpath(
    mut cur: Credentials,
    realm: &str,
    mut seen: Vec<String>,
    store: &mut dyn TgtStore,
    tgs: &mut Tgs<'_>,
) -> Result<Credentials> {
    debug!("off the path to {realm} at {}", tgt_realm(&cur));
    for count in 1.. {
        let want = Principal::krbtgt_for(realm, tgt_realm(&cur));
        let reply = tgs(&cur, &want, 0)?;
        if !is_tgs(&reply.server) {
            return Err(modified(&reply.server));
        }
        let got = tgt_realm(&reply).to_string();
        if seen.contains(&got) {
            return Err(ClientError::Referral(format!(
                "TGT loop at {got} on the way to {realm}"
            )));
        }
        seen.push(got.clone());
        cur = reply;
        if got == realm {
            store.remember(&cur);
            return Ok(cur);
        }
        if count >= MAX_HOPS {
            break;
        }
    }
    Err(ClientError::Referral(format!(
        "no TGT for {realm} after {MAX_HOPS} off-path hops"
    )))
}

fn modified(server: &Principal) -> ClientError {
    ClientError::Protocol(format!(
        "asked for a TGT, got a ticket for {server} (KRB5_KDCREP_MODIFIED)"
    ))
}

/// MIT's `complete()`: the credentials carry the server name as requested.
fn as_requested(mut creds: Credentials, service: &Principal) -> Credentials {
    creds.server = service.clone();
    creds
}

impl Principal {
    /// `krbtgt/REALM@ISSUER`.
    pub fn krbtgt_for(realm: &str, issuer: &str) -> Self {
        Principal::new(super::NT_SRV_INST, ["krbtgt", realm], issuer)
    }

    /// A host-based service principal (`service/host`, `NT_SRV_HST`) in the
    /// realm `[domain_realm]` maps `host` to, or with the empty referral
    /// realm if it maps it nowhere, so the KDC is asked to refer, as MIT's
    /// `krb5_sname_to_principal` does.
    pub fn host_service(service: &str, host: &str, conf: &Krb5Conf) -> Self {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let realm = conf.host_realm(&host).unwrap_or("").to_string();
        Principal::new(super::NT_SRV_HST, [service, host.as_str()], realm)
    }
}

/// True if the two principals name the same thing in any realm (MIT's
/// `krb5_principal_compare_any_realm`).
pub(crate) fn same_any_realm(a: &Principal, b: &Principal) -> bool {
    a.components == b.components
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_realm_path_comes_from_capaths() {
        let conf =
            Krb5Conf::parse("[capaths]\n A = {\n  C = B\n  D = B\n  D = C\n  E = .\n }\n").unwrap();
        assert_eq!(realm_path(&conf, "A", "C"), ["A", "B", "C"]);
        assert_eq!(realm_path(&conf, "A", "D"), ["A", "B", "C", "D"]);
        assert_eq!(realm_path(&conf, "A", "E"), ["A", "E"]);
        assert_eq!(realm_path(&conf, "A", "Z"), ["A", "Z"]);
    }

    #[test]
    fn the_fallback_realm_is_the_hosts_domain() {
        let conf = Krb5Conf::parse("[libdefaults]\n default_realm = HOME.ORG\n").unwrap();
        assert_eq!(
            fallback_realm(&conf, "server.far.test").as_deref(),
            Some("FAR.TEST")
        );
        assert_eq!(
            fallback_realm(&conf, "a.b.example.com.").as_deref(),
            Some("B.EXAMPLE.COM")
        );
        assert_eq!(fallback_realm(&conf, "bare").as_deref(), Some("HOME.ORG"));
        assert_eq!(fallback_realm(&Krb5Conf::empty(), "bare"), None);
    }

    #[test]
    fn host_services_take_their_realm_from_domain_realm_or_refer() {
        let conf = Krb5Conf::parse("[domain_realm]\n .cross.test = CROSS.TEST\n").unwrap();
        let p = Principal::host_service("host", "Server.Cross.Test.", &conf);
        assert_eq!(p.to_string(), "host/server.cross.test@CROSS.TEST");
        assert_eq!(p.name_type, super::super::NT_SRV_HST);
        assert_eq!(
            Principal::host_service("host", "x.elsewhere", &conf).realm,
            ""
        );
    }

    // ---------------------------------------- the algorithm, scripted

    use crate::key::Key;

    fn creds(client: &Principal, server: Principal) -> Credentials {
        Credentials {
            client: client.clone(),
            server,
            session_key: Key::random(18).unwrap(),
            ticket: Vec::new(),
            ticket_enctype: 18,
            flags: 0,
            authtime: 1,
            starttime: None,
            endtime: i64::MAX,
            renew_till: None,
        }
    }

    fn alice() -> Principal {
        Principal::new(1, ["alice"], "A")
    }

    fn host(h: &str, realm: &str) -> Principal {
        Principal::new(3, ["host", h], realm)
    }

    /// What a realm's KDC does with a request.
    enum Ans {
        /// Issue exactly what was asked for (in this realm).
        Issue,
        /// A TGT for that realm, issued here.
        Tgt(&'static str),
        /// The service, but under another name.
        Rename(&'static str),
        Fail,
    }

    /// Run the algorithm against `kdc(realm, requested, canonicalize)`,
    /// returning its result and the requests, as "REALM: server [c]".
    fn run(
        conf: &str,
        service: Principal,
        store: &mut dyn TgtStore,
        kdc: impl Fn(&str, &str, bool) -> Ans,
    ) -> (Result<Credentials>, Vec<String>) {
        let conf = Krb5Conf::parse(conf).unwrap();
        let start = creds(&alice(), Principal::krbtgt("A"));
        let mut log = Vec::new();
        let mut tgs = |tgt: &Credentials, server: &Principal, opts: u32| {
            let realm = tgt_realm(tgt).to_string();
            let canon = opts & KDC_OPT_CANONICALIZE != 0;
            log.push(format!(
                "{realm}: {server}{}",
                if canon { " [c]" } else { "" }
            ));
            let me = creds(&tgt.client, server.clone());
            match kdc(&realm, &server.to_string(), canon) {
                Ans::Issue => Ok(Credentials {
                    server: Principal::new(server.name_type, server.components.clone(), realm),
                    ..me
                }),
                Ans::Tgt(to) => Ok(creds(&tgt.client, Principal::krbtgt_for(to, &realm))),
                Ans::Rename(name) => Ok(creds(&tgt.client, Principal::new(1, [name], &realm))),
                Ans::Fail => Err(ClientError::Kdc {
                    code: 7,
                    text: None,
                }),
            }
        };
        let r = get_creds_with(&conf, &start, &service, store, &mut tgs);
        (r, log)
    }

    #[derive(Default)]
    struct Kept(Vec<Credentials>);

    impl TgtStore for Kept {
        fn cached_tgt(&self, realm: &str) -> Option<Credentials> {
            self.0.iter().rev().find(|c| tgt_realm(c) == realm).cloned()
        }
        fn remember(&mut self, tgt: &Credentials) {
            self.0.push(tgt.clone());
        }
    }

    #[test]
    fn a_local_service_takes_one_canonicalizing_request() {
        let (r, log) = run("", host("h.a", "A"), &mut NoStore, |_, _, _| Ans::Issue);
        assert_eq!(r.unwrap().server, host("h.a", "A"));
        assert_eq!(log, ["A: host/h.a@A [c]"]);
    }

    #[test]
    fn referrals_are_followed_realm_by_realm() {
        let mut kept = Kept::default();
        let (r, log) = run("", host("h.c", ""), &mut kept, |realm, _, canon| {
            assert!(canon);
            match realm {
                "A" => Ans::Tgt("B"),
                "B" => Ans::Tgt("C"),
                _ => Ans::Issue,
            }
        });
        // Named as requested, the empty realm included.
        assert_eq!(r.unwrap().server, host("h.c", ""));
        assert_eq!(
            log,
            [
                "A: host/h.c@A [c]",
                "B: host/h.c@B [c]",
                "C: host/h.c@C [c]"
            ]
        );
        let kept: Vec<String> = kept.0.iter().map(|c| c.server.to_string()).collect();
        assert_eq!(kept, ["krbtgt/B@A", "krbtgt/C@B"]);
    }

    #[test]
    fn a_referral_loop_is_refused() {
        let (r, log) = run(
            "",
            host("h.x", ""),
            &mut NoStore,
            |realm, _, _| match realm {
                "A" => Ans::Tgt("B"),
                "B" => Ans::Tgt("A"),
                _ => unreachable!(),
            },
        );
        assert!(
            matches!(r, Err(ClientError::Referral(ref m)) if m.contains("loop")),
            "{r:?}"
        );
        assert_eq!(log.len(), 3, "A, B, A again: B would be seen twice");
    }

    #[test]
    fn referrals_stop_after_max_hops() {
        // A -> R1 -> R2 -> ... forever.
        let (r, log) = run("", host("h.x", ""), &mut NoStore, |realm, _, _| {
            let n: usize = realm.strip_prefix('R').map_or(0, |n| n.parse().unwrap());
            Ans::Tgt(Box::leak(format!("R{}", n + 1).into_boxed_str()))
        });
        assert!(
            matches!(r, Err(ClientError::Referral(ref m)) if m.contains("more than")),
            "{r:?}"
        );
        assert_eq!(log.len(), MAX_HOPS);
    }

    #[test]
    fn with_no_realm_a_failed_first_referral_falls_back_to_the_hosts_domain() {
        let (r, log) = run(
            "",
            host("srv.far.test", ""),
            &mut NoStore,
            |realm, server, canon| match (realm, server, canon) {
                ("A", "host/srv.far.test@A", true) => Ans::Fail,
                ("A", "krbtgt/FAR.TEST@A", false) => Ans::Tgt("FAR.TEST"),
                ("FAR.TEST", "host/srv.far.test@FAR.TEST", false) => Ans::Issue,
                other => panic!("unexpected {other:?}"),
            },
        );
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn with_a_realm_a_kdc_refusing_canonicalize_gets_a_plain_request() {
        let (r, log) = run("", host("h.a", "A"), &mut NoStore, |_, _, canon| {
            if canon { Ans::Fail } else { Ans::Issue }
        });
        assert!(r.is_ok());
        assert_eq!(log, ["A: host/h.a@A [c]", "A: host/h.a@A"]);
    }

    #[test]
    fn active_directory_quirks_get_a_plain_request() {
        // A renamed ticket instead of a referral.
        let (r, log) = run("", host("h.a", "A"), &mut NoStore, |_, _, canon| {
            if canon {
                Ans::Rename("other")
            } else {
                Ans::Issue
            }
        });
        assert_eq!(r.unwrap().server, host("h.a", "A"));
        assert_eq!(log.len(), 2);
        // A "referral" to the realm we are already in.
        let (r, log) = run("", host("h.a", "A"), &mut NoStore, |_, _, canon| {
            if canon { Ans::Tgt("A") } else { Ans::Issue }
        });
        assert!(r.is_ok());
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn a_capaths_path_backs_off_to_a_closer_realm_and_moves_on() {
        let conf = "[capaths]\n A = {\n  C = B\n }\n";
        let mut kept = Kept::default();
        let (r, log) = run(
            conf,
            host("h.c", "C"),
            &mut kept,
            |realm, server, _| match (realm, server) {
                ("A", "krbtgt/C@A") => Ans::Fail,
                ("A", "krbtgt/B@A") => Ans::Tgt("B"),
                ("B", "krbtgt/C@B") => Ans::Tgt("C"),
                ("C", "host/h.c@C") => Ans::Issue,
                other => panic!("unexpected {other:?}"),
            },
        );
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(
            log,
            [
                "A: krbtgt/C@A",
                "A: krbtgt/B@A",
                "B: krbtgt/C@B",
                "C: host/h.c@C [c]"
            ]
        );
        let kept: Vec<String> = kept.0.iter().map(|c| c.server.to_string()).collect();
        assert_eq!(kept, ["krbtgt/B@A", "krbtgt/C@B"], "both were asked for");
    }

    #[test]
    fn a_closer_tgt_than_asked_for_is_used_but_not_kept() {
        let conf = "[capaths]\n A = {\n  C = B\n }\n";
        let mut kept = Kept::default();
        let (r, _) = run(
            conf,
            host("h.c", "C"),
            &mut kept,
            |realm, server, _| match (realm, server) {
                ("A", "krbtgt/C@A") => Ans::Tgt("B"),
                ("B", "krbtgt/C@B") => Ans::Tgt("C"),
                _ => Ans::Issue,
            },
        );
        assert!(r.is_ok());
        let kept: Vec<String> = kept.0.iter().map(|c| c.server.to_string()).collect();
        assert_eq!(kept, ["krbtgt/C@B"]);
    }

    #[test]
    fn an_off_path_tgt_is_chased_to_the_target() {
        let (r, log) = run(
            "",
            host("h.c", "C"),
            &mut NoStore,
            |realm, server, _| match (realm, server) {
                ("A", "krbtgt/C@A") => Ans::Tgt("X"),
                ("X", "krbtgt/C@X") => Ans::Tgt("C"),
                ("C", "host/h.c@C") => Ans::Issue,
                other => panic!("unexpected {other:?}"),
            },
        );
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn a_tgt_back_to_the_start_realm_is_refused() {
        let conf = "[capaths]\n A = {\n  C = B\n }\n";
        let (r, _) = run(
            conf,
            host("h.c", "C"),
            &mut NoStore,
            |realm, _, _| match realm {
                "A" => Ans::Tgt("A"),
                _ => Ans::Issue,
            },
        );
        assert!(
            matches!(r, Err(ClientError::Referral(ref m)) if m.contains("back to")),
            "{r:?}"
        );
    }

    #[test]
    fn a_cached_tgt_for_the_service_realm_skips_the_path() {
        let mut kept = Kept(vec![creds(&alice(), Principal::krbtgt_for("C", "B"))]);
        let (r, log) = run("", host("h.c", "C"), &mut kept, |realm, _, _| {
            assert_eq!(realm, "C", "only C's KDC is asked");
            Ans::Issue
        });
        assert!(r.is_ok());
        assert_eq!(log, ["C: host/h.c@C [c]"]);
    }

    #[test]
    fn a_ticket_that_is_not_a_tgt_on_the_path_is_refused() {
        let (r, _) = run("", host("h.c", "C"), &mut NoStore, |_, _, _| {
            Ans::Rename("sneaky")
        });
        assert!(
            matches!(r, Err(ClientError::Protocol(ref m)) if m.contains("KDCREP_MODIFIED")),
            "{r:?}"
        );
    }

    #[test]
    fn tgs_principals_are_recognized() {
        assert!(is_tgs(&Principal::krbtgt_for("B", "A")));
        assert!(!is_tgs(&Principal::new(1, ["krbtgt"], "A")));
        assert!(!is_tgs(&Principal::new(3, ["host", "krbtgt"], "A")));
        assert!(same_any_realm(
            &Principal::new(1, ["a"], "X"),
            &Principal::new(2, ["a"], "Y")
        ));
    }
}
