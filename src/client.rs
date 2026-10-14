//! Kerberos 5 client: the AS and TGS exchanges (RFC 4120 §3.1, §3.3).
//!
//! [`KdcClient::login_with_password`] / [`KdcClient::login_with_keytab`]
//! obtain a ticket-granting ticket, and [`KdcClient::service_ticket`]
//! trades it for a ticket to a service. The result is a [`Credentials`],
//! which [`crate::InitiatorContext`] turns into a GSS-API context.
//!
//! Transport is TCP (RFC 4120 §7.2.2: a four-octet big-endian length, then
//! the message), tried against each configured KDC in order. There is no
//! UDP, no DNS SRV discovery, no krb5.conf parsing, no cross-realm and no
//! FAST: the caller names the realm and its KDCs.

use crate::acceptor::Keytab;
use crate::ccache::{CCache, CacheError, CacheName, same_principal};
use std::collections::HashMap;

mod xrealm;
use crate::config::{self, ConfigError, Krb5Conf};
use crate::der::{self, Fields, Reader, app};
use crate::dns::{self, Resolver};
use crate::key::{Key, KeyError};
use rand::RngCore;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;
pub use xrealm::MAX_HOPS;
use xrealm::{KDC_OPT_CANONICALIZE, NoStore, TgtStore, is_tgs, tgt_realm};

/// RFC 4120 §6.2 name types.
pub const NT_PRINCIPAL: i32 = 1;
pub const NT_SRV_INST: i32 = 2;
pub const NT_SRV_HST: i32 = 3;

/// The enctypes requested by default, in MIT's preference order.
pub const DEFAULT_ENCTYPES: [i32; 4] = [18, 17, 20, 19];

// RFC 4120 §7.5.1 key usages.
const KU_PA_ENC_TIMESTAMP: u32 = 1;
const KU_AS_REP_ENC_PART: u32 = 3;
const KU_TGS_REQ_AUTH_CKSUM: u32 = 6;
const KU_TGS_REQ_AUTH: u32 = 7;
const KU_TGS_REP_ENC_PART_SESSION: u32 = 8;

// RFC 4120 §7.5.2 / RFC 6113 PA-DATA types.
const PA_TGS_REQ: i32 = 1;
const PA_ENC_TIMESTAMP: i32 = 2;
const PA_PW_SALT: i32 = 3;
const PA_ETYPE_INFO: i32 = 11;
const PA_ETYPE_INFO2: i32 = 19;
const PA_FX_COOKIE: i32 = 133;

// RFC 4120 §7.5.9 error codes the client acts on.
pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
pub const KRB_AP_ERR_SKEW: i32 = 37;

/// The largest reply accepted from a KDC.
const MAX_REPLY: usize = 1 << 20;

/// A client-side failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The KDC answered with a KRB-ERROR.
    #[error("KDC error {code} ({}){}", kdc_error_name(*code), text.as_ref().map(|t| format!(": {t}")).unwrap_or_default())]
    Kdc { code: i32, text: Option<String> },
    /// No configured KDC could be reached.
    #[error("no KDC for {realm} answered: {last}")]
    Unreachable { realm: String, last: std::io::Error },
    #[error("malformed Kerberos message: {0}")]
    Protocol(String),
    #[error("crypto: {0}")]
    Crypto(#[from] KeyError),
    /// Neither the password path nor the keytab could supply a key the
    /// KDC will accept.
    #[error("no usable key: {0}")]
    NoKey(String),
    #[error("credential cache: {0}")]
    Cache(#[from] CacheError),
    /// The cache holds no unexpired ticket-granting ticket.
    #[error("no valid TGT for {principal} in {cache} (run kinit)")]
    NoTgt { principal: String, cache: String },
    /// Another realm's KDCs could not be located.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Cross-realm referrals did not converge: too many hops, a loop, or a
    /// referral back to where we started.
    #[error("cross-realm: {0}")]
    Referral(String),
}

impl From<der::DerError> for ClientError {
    fn from(e: der::DerError) -> Self {
        ClientError::Protocol(e.0)
    }
}

impl ClientError {
    /// The KRB-ERROR code, if the KDC sent one.
    pub fn kdc_code(&self) -> Option<i32> {
        match self {
            ClientError::Kdc { code, .. } => Some(*code),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

fn protocol<T>(msg: impl Into<String>) -> Result<T> {
    Err(ClientError::Protocol(msg.into()))
}

/// RFC 4120 §7.5.9 names for the codes worth naming.
pub fn kdc_error_name(code: i32) -> &'static str {
    match code {
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        12 => "KDC_ERR_POLICY",
        14 => "KDC_ERR_ETYPE_NOSUPP",
        18 => "KDC_ERR_CLIENT_REVOKED",
        23 => "KDC_ERR_KEY_EXPIRED",
        24 => "KDC_ERR_PREAUTH_FAILED",
        25 => "KDC_ERR_PREAUTH_REQUIRED",
        31 => "KRB_AP_ERR_BAD_INTEGRITY",
        32 => "KRB_AP_ERR_TKT_EXPIRED",
        34 => "KRB_AP_ERR_REPEAT",
        37 => "KRB_AP_ERR_SKEW",
        41 => "KRB_AP_ERR_MODIFIED",
        60 => "KRB_ERR_GENERIC",
        68 => "KDC_ERR_WRONG_REALM",
        _ => "unknown",
    }
}

// ------------------------------------------------------------- principal

/// A Kerberos principal: name type, name components and realm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal {
    pub name_type: i32,
    pub components: Vec<String>,
    pub realm: String,
}

impl Principal {
    pub fn new<I, S>(name_type: i32, components: I, realm: impl Into<String>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Principal {
            name_type,
            components: components.into_iter().map(Into::into).collect(),
            realm: realm.into(),
        }
    }

    /// Parse `name[/instance...]@REALM`. Like MIT's `krb5_parse_name`,
    /// the name type is `NT_PRINCIPAL` except for `krbtgt/...`, which is
    /// `NT_SRV_INST`. Backslash escapes are not supported.
    pub fn parse(s: &str) -> Result<Self> {
        let (name, realm) = s
            .rsplit_once('@')
            .ok_or_else(|| ClientError::Protocol(format!("principal {s:?} has no @REALM")))?;
        Self::parse_in_realm(name, realm)
    }

    /// Parse `name[/instance...]` in `realm`.
    pub fn parse_in_realm(name: &str, realm: &str) -> Result<Self> {
        let components: Vec<&str> = name.split('/').collect();
        if name.contains('@') || realm.is_empty() || components.iter().any(|c| c.is_empty()) {
            return protocol(format!("bad principal {name:?}@{realm:?}"));
        }
        let nt = if components[0] == "krbtgt" {
            NT_SRV_INST
        } else {
            NT_PRINCIPAL
        };
        Ok(Principal::new(nt, components, realm))
    }

    /// `krbtgt/REALM@REALM`, the ticket-granting service.
    pub fn krbtgt(realm: &str) -> Self {
        Principal::new(NT_SRV_INST, ["krbtgt", realm], realm)
    }

    /// The name without the realm: `nfs/server.example.com`.
    pub fn name(&self) -> String {
        self.components.join("/")
    }

    /// RFC 4120 §4 default salt: the realm, then each component, with no
    /// separators.
    pub fn default_salt(&self) -> Vec<u8> {
        let mut s = self.realm.as_bytes().to_vec();
        for c in &self.components {
            s.extend_from_slice(c.as_bytes());
        }
        s
    }

    pub(crate) fn encode_name(&self) -> Vec<u8> {
        der::seq(&[
            der::field(0, der::int(self.name_type as i64)),
            der::field(
                1,
                der::seq(
                    &self
                        .components
                        .iter()
                        .map(|c| der::general_string(c))
                        .collect::<Vec<_>>(),
                ),
            ),
        ])
    }

    pub(crate) fn decode_name(mut r: Reader<'_>, realm: String) -> Result<Self> {
        let f = Fields::parse("PrincipalName", r.expect(der::SEQUENCE)?)?;
        let name_type = f.get(0)?.i32()?;
        let mut strings = f.get(1)?.seq()?;
        let mut components = Vec::new();
        while !strings.is_empty() {
            components.push(strings.string()?);
        }
        Ok(Principal {
            name_type,
            components,
            realm,
        })
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name(), self.realm)
    }
}

// ----------------------------------------------------------- credentials

/// A ticket and the session key that goes with it.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub client: Principal,
    pub server: Principal,
    pub session_key: Key,
    /// The DER `Ticket`, opaque to the client and sent back verbatim.
    pub ticket: Vec<u8>,
    /// The enctype the ticket itself is encrypted in (the service's key).
    pub ticket_enctype: i32,
    /// RFC 4120 §5.3 TicketFlags, bit 0 = MSB.
    pub flags: u32,
    pub authtime: i64,
    pub starttime: Option<i64>,
    pub endtime: i64,
    pub renew_till: Option<i64>,
}

impl Credentials {
    /// The server named inside the ticket (Ticket.realm, Ticket.sname),
    /// which for a ticket obtained by referral names the realm the service
    /// really lives in, where `server` is the name as requested. `klist`
    /// shows it as "Ticket server".
    pub fn ticket_server(&self) -> Option<Principal> {
        let tf = Fields::parse_tagged("Ticket", app(1), &self.ticket).ok()?;
        let realm = tf.get(1).ok()?.string().ok()?;
        Principal::decode_name(tf.get(2).ok()?, realm).ok()
    }

    /// True once `now` (Unix seconds) has reached the ticket's end time.
    pub fn is_expired_at(&self, now: i64) -> bool {
        now >= self.endtime
    }
}

/// TicketFlags ok-as-delegate (bit 13).
const TKT_FLG_OK_AS_DELEGATE: u32 = 1 << 18;

/// Cross-realm TGTs from a credential cache, and the ones fetched on the
/// way, to be written back with the ticket.
struct CacheStore<'a> {
    cache: &'a CCache,
    now: i64,
    got: Vec<Credentials>,
}

impl TgtStore for CacheStore<'_> {
    /// Any unexpired `krbtgt/realm@...` for the cache's principal, the
    /// issuing realm not mattering (MIT's KRB5_TC_MATCH_SRV_NAMEONLY).
    fn cached_tgt(&self, realm: &str) -> Option<Credentials> {
        self.got
            .iter()
            .rev()
            .cloned()
            .chain(self.cache.credentials())
            .filter(|c| {
                is_tgs(&c.server)
                    && tgt_realm(c) == realm
                    && same_principal(&c.client, &self.cache.principal)
                    && !c.is_expired_at(self.now)
            })
            .max_by_key(|c| c.endtime)
    }

    fn remember(&mut self, tgt: &Credentials) {
        self.got.push(tgt.clone());
    }
}

// ------------------------------------------------------------ the client

/// Where the long-term key comes from.
enum Secret<'a> {
    Password(&'a str),
    Keytab(&'a Keytab),
}

/// Salt information from ETYPE-INFO2 / ETYPE-INFO / PW-SALT.
#[derive(Debug, Clone)]
struct SaltInfo {
    etype: i32,
    salt: Option<Vec<u8>>,
    params: Option<[u8; 4]>,
}

/// A client for one realm and its KDCs, which reaches other realms' KDCs
/// for cross-realm tickets through the same `krb5.conf` and DNS.
#[derive(Debug, Clone)]
pub struct KdcClient {
    realm: String,
    kdcs: Vec<String>,
    timeout: Duration,
    enctypes: Vec<i32>,
    lifetime: Duration,
    /// For locating other realms' KDCs.
    conf: Krb5Conf,
    resolver: Option<Resolver>,
    /// Other realms' KDCs given explicitly, ahead of `conf` and DNS.
    realm_kdcs: HashMap<String, Vec<String>>,
}

impl KdcClient {
    /// `kdcs` are `host` or `host:port` (default port 88), tried in order.
    pub fn new<I, S>(realm: impl Into<String>, kdcs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        KdcClient {
            realm: realm.into(),
            kdcs: kdcs.into_iter().map(Into::into).collect(),
            timeout: Duration::from_secs(10),
            enctypes: DEFAULT_ENCTYPES.to_vec(),
            lifetime: Duration::from_secs(24 * 3600),
            conf: Krb5Conf::empty(),
            resolver: None,
            realm_kdcs: HashMap::new(),
        }
    }

    /// Use `kdcs` for `realm` when a cross-realm request needs its KDC,
    /// instead of looking it up in `krb5.conf` or DNS.
    pub fn with_realm_kdcs<I, S>(mut self, realm: impl Into<String>, kdcs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.realm_kdcs
            .insert(realm.into(), kdcs.into_iter().map(Into::into).collect());
        self
    }

    /// A client for `realm` with this one's settings: itself, an explicit
    /// [`KdcClient::with_realm_kdcs`] entry, or the realm's KDCs located
    /// through the `krb5.conf` and resolver this client was made with.
    pub fn for_realm(&self, realm: &str) -> Result<KdcClient> {
        if realm == self.realm {
            return Ok(self.clone());
        }
        let kdcs = match self.realm_kdcs.get(realm) {
            Some(k) => k.clone(),
            None => Self::locate(&self.conf, realm, self.resolver.as_ref())?.kdcs,
        };
        Ok(KdcClient {
            realm: realm.to_string(),
            kdcs,
            ..self.clone()
        })
    }

    /// A client for `realm`, finding its KDCs as MIT does: the `kdc`
    /// entries in `conf` (`[realms] REALM kdc`), else, if `dns_lookup_kdc`
    /// allows, DNS URI and SRV records through the system resolver (see
    /// [`crate::dns`]).
    pub fn from_config(conf: &Krb5Conf, realm: &str) -> config::Result<Self> {
        Self::locate(conf, realm, None)
    }

    /// [`KdcClient::from_config`] with DNS queries sent to `resolver`
    /// instead of the servers in `/etc/resolv.conf`.
    pub fn from_config_with_resolver(
        conf: &Krb5Conf,
        realm: &str,
        resolver: &Resolver,
    ) -> config::Result<Self> {
        Self::locate(conf, realm, Some(resolver))
    }

    fn locate(conf: &Krb5Conf, realm: &str, resolver: Option<&Resolver>) -> config::Result<Self> {
        match conf.kdcs(realm) {
            Ok(kdcs) => return Ok(KdcClient::new(realm, kdcs).remembering(conf, resolver)),
            // Entries this crate cannot use are not "none": MIT would use
            // them and not ask DNS, so neither do we.
            Err(ConfigError::NoKdcs { skipped, .. }) if skipped.is_empty() => {}
            Err(e) => return Err(e),
        }
        let dns = dns::dns_lookup_kdc(conf);
        if dns {
            let dns_err = |source| ConfigError::Dns {
                realm: realm.to_string(),
                source,
            };
            let system;
            let resolver = match resolver {
                Some(r) => r,
                None => {
                    system = Resolver::system().map_err(dns_err)?;
                    &system
                }
            };
            let kdcs =
                dns::locate_kdcs(resolver, realm, dns::dns_uri_lookup(conf)).map_err(dns_err)?;
            if !kdcs.is_empty() {
                debug!("{realm}: KDCs from DNS: {kdcs:?}");
                return Ok(KdcClient::new(realm, kdcs).remembering(conf, Some(resolver)));
            }
        }
        Err(ConfigError::NoKdcFound {
            realm: realm.to_string(),
            dns,
        })
    }

    fn remembering(mut self, conf: &Krb5Conf, resolver: Option<&Resolver>) -> Self {
        self.conf = conf.clone();
        self.resolver = resolver.cloned();
        self
    }

    /// A client for `realm` from the system configuration: the
    /// `KRB5_CONFIG` files (else `/etc/krb5.conf`), then DNS.
    pub fn discover(realm: &str) -> config::Result<Self> {
        Self::from_config(&Krb5Conf::load_default()?, realm)
    }

    /// Per-KDC connect and read timeout (default 10 s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enctypes to request, most preferred first. Unsupported ones are
    /// dropped.
    pub fn with_enctypes(mut self, enctypes: &[i32]) -> Self {
        self.enctypes = enctypes
            .iter()
            .copied()
            .filter(|e| (17..=20).contains(e))
            .collect();
        self
    }

    /// Requested ticket lifetime (default 24 h; the KDC may shorten it).
    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The KDC addresses this client tries, in order.
    pub fn kdcs(&self) -> &[String] {
        &self.kdcs
    }

    /// AS exchange with a password-derived key: `kinit`.
    pub fn login_with_password(&self, client: &Principal, password: &str) -> Result<Credentials> {
        self.as_exchange(client, Secret::Password(password), self.enctypes.clone())
    }

    /// AS exchange with a long-term key from a keytab: `kinit -k`.
    ///
    /// Only enctypes the keytab holds for `client` are requested, so the
    /// KDC cannot pick one the client has no key for.
    pub fn login_with_keytab(&self, client: &Principal, keytab: &Keytab) -> Result<Credentials> {
        let have: Vec<i32> = self
            .enctypes
            .iter()
            .copied()
            .filter(|&e| keytab_key(keytab, client, e).is_some())
            .collect();
        if have.is_empty() {
            return Err(ClientError::NoKey(format!(
                "keytab has no AES key for {client}"
            )));
        }
        self.as_exchange(client, Secret::Keytab(keytab), have)
    }

    /// A ticket for `service` through the credential cache `cache`, as
    /// `kvno` gets one: an unexpired ticket already cached is returned
    /// as is; otherwise the cache's TGT buys one from the KDC, and it is
    /// stored in the cache for next time.
    ///
    /// Cross-realm TGTs come from the cache when it has them, and the ones
    /// fetched on the way are stored with the ticket, as MIT does. The
    /// cache is read again just before writing, so a ticket another
    /// process cached meanwhile is not dropped.
    pub fn service_ticket_cached(
        &self,
        cache: &CacheName,
        service: &Principal,
    ) -> Result<Credentials> {
        let cache = cache.resolved()?;
        let cc = cache.read()?;
        let (now, _) = now();
        if let Some(creds) = cc.find(service, now) {
            return Ok(creds);
        }
        let tgt = cc.tgt(now).ok_or_else(|| ClientError::NoTgt {
            principal: cc.principal.to_string(),
            cache: cache.to_string(),
        })?;

        let mut store = CacheStore {
            cache: &cc,
            now,
            got: Vec::new(),
        };
        let creds = self.get_creds(&tgt, service, &mut store)?;
        let got = store.got;
        let mut cc = cache.read()?;
        for t in got.iter().chain([&creds]) {
            cc.store(t);
        }
        cache.write(&cc)?;
        Ok(creds)
    }

    /// A ticket for `service`, from `tgt` (a TGT for the client's realm),
    /// following cross-realm referrals and `[capaths]` as MIT's
    /// `krb5_get_credentials` does (see the `xrealm` module docs). A
    /// service in the client's own realm takes one request.
    ///
    /// Give `service` an empty realm (or build it with
    /// [`Principal::host_service`]) to let the KDC say where it lives.
    pub fn service_ticket(&self, tgt: &Credentials, service: &Principal) -> Result<Credentials> {
        self.get_creds(tgt, service, &mut NoStore)
    }

    /// One TGS exchange with the KDC of the realm `tgt` is for: a ticket
    /// for `server` (whose realm is the request realm), checked as MIT's
    /// `krb5int_process_tgs_reply` checks it.
    fn tgs(&self, tgt: &Credentials, server: &Principal, kdc_options: u32) -> Result<Credentials> {
        let kdc = self.for_realm(tgt_realm(tgt))?;
        let (now, usec) = now();
        let nonce = random_nonce();
        let body = kdc.req_body_with(None, server, nonce, now, &kdc.enctypes, kdc_options);

        let cksum = tgt.session_key.checksum(KU_TGS_REQ_AUTH_CKSUM, &body)?;
        let authenticator = encode_authenticator(
            &tgt.client,
            Some((tgt.session_key.checksum_type(), cksum)),
            usec,
            now,
            None,
            None,
        );
        let enc_auth = tgt.session_key.encrypt(KU_TGS_REQ_AUTH, &authenticator)?;
        let ap_req = encode_ap_req(0, &tgt.ticket, tgt.session_key.enctype(), &enc_auth);

        let req = encode_kdc_req(12, &[(PA_TGS_REQ, ap_req)], body);
        let rep = match parse_reply(&kdc.exchange(&req)?, 13)? {
            Reply::Error(e) => return Err(e.into_error()),
            Reply::Rep(r) => r,
        };
        if !same_principal(&rep.client, &tgt.client) {
            return protocol(format!(
                "TGS reply is for {}, not {} (KRB5_KDCREP_MODIFIED)",
                rep.client, tgt.client
            ));
        }
        let ticket_server = rep.ticket_server.clone();
        let plain = tgt
            .session_key
            .decrypt(KU_TGS_REP_ENC_PART_SESSION, &rep.cipher)?;
        let mut creds = rep.into_credentials(&plain, nonce)?;

        // MIT's check_reply_server: the ticket and the encrypted part must
        // agree, and a different server than the one asked for is allowed
        // only if we asked for canonicalization or both are TGTs (a
        // closer-realm TGT on the way to a foreign one).
        if !same_principal(&ticket_server, &creds.server) {
            return protocol(format!(
                "ticket is for {ticket_server} but the reply says {} (KRB5_KDCREP_MODIFIED)",
                creds.server
            ));
        }
        if !same_principal(&creds.server, server)
            && kdc_options & KDC_OPT_CANONICALIZE == 0
            && !(is_tgs(server) && is_tgs(&creds.server))
        {
            return protocol(format!(
                "asked for {server}, got {} (KRB5_KDCREP_MODIFIED)",
                creds.server
            ));
        }
        // A foreign realm's ok-as-delegate counts only if every TGT on the
        // way had it (MIT gc_via_tkt.c).
        let local = tgt.server.realm == tgt.client.realm && tgt_realm(tgt) == tgt.client.realm;
        if !local && tgt.flags & TKT_FLG_OK_AS_DELEGATE == 0 {
            creds.flags &= !TKT_FLG_OK_AS_DELEGATE;
        }
        Ok(creds)
    }

    fn as_exchange(
        &self,
        client: &Principal,
        secret: Secret<'_>,
        enctypes: Vec<i32>,
    ) -> Result<Credentials> {
        let krbtgt = Principal::krbtgt(&client.realm);
        let mut padata: Vec<(i32, Vec<u8>)> = Vec::new();
        let mut preauth_key: Option<Key> = None;

        for round in 0..2 {
            let (now, usec) = now();
            let nonce = random_nonce();
            let body = self.req_body_with(Some(client), &krbtgt, nonce, now, &enctypes, 0);
            let req = encode_kdc_req(10, &padata, body);

            let rep = match parse_reply(&self.exchange(&req)?, 11)? {
                Reply::Rep(r) => r,
                Reply::Error(e) if e.code == KDC_ERR_PREAUTH_REQUIRED && round == 0 => {
                    let methods = e.method_data()?;
                    let info = choose_salt(&methods, &enctypes).ok_or_else(|| {
                        ClientError::NoKey(
                            "KDC offered no supported enctype for pre-authentication".into(),
                        )
                    })?;
                    let key = derive_key(&secret, client, &info)?;
                    debug!(
                        etype = info.etype,
                        "pre-authenticating with PA-ENC-TIMESTAMP"
                    );
                    padata = vec![(PA_ENC_TIMESTAMP, encode_enc_timestamp(&key, now, usec)?)];
                    // RFC 6113 §5.2: echo the cookie so a stateless KDC can
                    // continue the conversation.
                    if let Some((_, c)) = methods.iter().find(|(t, _)| *t == PA_FX_COOKIE) {
                        padata.push((PA_FX_COOKIE, c.clone()));
                    }
                    preauth_key = Some(key);
                    continue;
                }
                Reply::Error(e) => return Err(e.into_error()),
            };

            // The reply key is the long-term key for the enctype the KDC
            // chose; reuse the pre-auth key when it matches, otherwise
            // take the salt from the reply's own PA-DATA.
            let key = match preauth_key {
                Some(k) if k.enctype() == rep.enc_etype => k,
                _ => {
                    let info = choose_salt(&rep.padata, &[rep.enc_etype]).unwrap_or(SaltInfo {
                        etype: rep.enc_etype,
                        salt: None,
                        params: None,
                    });
                    derive_key(&secret, client, &info)?
                }
            };
            let plain = key
                .decrypt(KU_AS_REP_ENC_PART, &rep.cipher)
                .map_err(|e| match secret {
                    Secret::Password(_) => ClientError::Crypto(KeyError(format!(
                        "cannot decrypt AS-REP (wrong password?): {}",
                        e.0
                    ))),
                    Secret::Keytab(_) => ClientError::Crypto(e),
                })?;
            return rep.into_credentials(&plain, nonce);
        }
        Err(ClientError::Kdc {
            code: KDC_ERR_PREAUTH_REQUIRED,
            text: Some("KDC still demands pre-authentication after PA-ENC-TIMESTAMP".into()),
        })
    }

    #[cfg(test)]
    fn req_body(
        &self,
        cname: Option<&Principal>,
        sname: &Principal,
        nonce: u32,
        now: i64,
    ) -> Vec<u8> {
        self.req_body_with(cname, sname, nonce, now, &self.enctypes, 0)
    }

    fn req_body_with(
        &self,
        cname: Option<&Principal>,
        sname: &Principal,
        nonce: u32,
        now: i64,
        enctypes: &[i32],
        kdc_options: u32,
    ) -> Vec<u8> {
        let mut parts = vec![der::field(0, der::flags32(kdc_options))];
        if let Some(c) = cname {
            parts.push(der::field(1, c.encode_name()));
        }
        parts.push(der::field(2, der::general_string(&sname.realm)));
        parts.push(der::field(3, sname.encode_name()));
        parts.push(der::field(
            5,
            der::time(now + self.lifetime.as_secs() as i64),
        ));
        parts.push(der::field(7, der::int(nonce as i64)));
        parts.push(der::field(
            8,
            der::seq(
                &enctypes
                    .iter()
                    .map(|&e| der::int(e as i64))
                    .collect::<Vec<_>>(),
            ),
        ));
        der::seq(&parts)
    }

    /// Send one request over TCP, trying each KDC in turn.
    fn exchange(&self, req: &[u8]) -> Result<Vec<u8>> {
        let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no KDCs configured");
        for kdc in &self.kdcs {
            let addr = with_default_port(kdc);
            match self.exchange_one(&addr, req) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    debug!(kdc = %addr, error = %e, "KDC did not answer");
                    last = e;
                }
            }
        }
        Err(ClientError::Unreachable {
            realm: self.realm.clone(),
            last,
        })
    }

    fn exchange_one(&self, addr: &str, req: &[u8]) -> std::io::Result<Vec<u8>> {
        use std::io::{Error, ErrorKind};
        let mut last = Error::new(ErrorKind::NotFound, format!("{addr} did not resolve"));
        for sa in addr.to_socket_addrs()? {
            let mut s = match TcpStream::connect_timeout(&sa, self.timeout) {
                Ok(s) => s,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            s.set_read_timeout(Some(self.timeout))?;
            s.set_write_timeout(Some(self.timeout))?;
            let mut framed = (req.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(req);
            s.write_all(&framed)?;
            let mut len = [0u8; 4];
            s.read_exact(&mut len)?;
            let len = u32::from_be_bytes(len);
            // RFC 4120 §7.2.2: the high bit is reserved and must be zero.
            if len & 0x8000_0000 != 0 || len as usize > MAX_REPLY {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("bad reply length {len:#x}"),
                ));
            }
            let mut buf = vec![0u8; len as usize];
            s.read_exact(&mut buf)?;
            return Ok(buf);
        }
        Err(last)
    }
}

/// `host` → `host:88`; `host:port`, `[v6]:port` unchanged; bare `v6` → `[v6]:88`.
fn with_default_port(kdc: &str) -> String {
    match (kdc.starts_with('['), kdc.matches(':').count()) {
        (true, _) if kdc.contains("]:") => kdc.to_string(),
        (true, _) => format!("{kdc}:88"),
        (false, 0) => format!("{kdc}:88"),
        (false, 1) => kdc.to_string(),
        (false, _) => format!("[{kdc}]:88"),
    }
}

// ------------------------------------------------------------- keys

fn keytab_key(keytab: &Keytab, client: &Principal, etype: i32) -> Option<Key> {
    let name = client.name();
    keytab
        .keys()
        .iter()
        .filter(|k| k.principal == name && k.realm == client.realm && k.enctype.etype() == etype)
        .max_by_key(|k| k.kvno)
        .and_then(|k| Key::new(etype, k.key.clone()).ok())
}

fn derive_key(secret: &Secret<'_>, client: &Principal, info: &SaltInfo) -> Result<Key> {
    match secret {
        Secret::Password(pw) => {
            let salt = info.salt.clone().unwrap_or_else(|| client.default_salt());
            Ok(Key::from_password(info.etype, pw, &salt, info.params)?)
        }
        Secret::Keytab(kt) => keytab_key(kt, client, info.etype).ok_or_else(|| {
            ClientError::NoKey(format!(
                "keytab has no enctype {} key for {client}",
                info.etype
            ))
        }),
    }
}

/// Pick the first salt entry whose enctype the client offered. The KDC
/// lists ETYPE-INFO2 in its preference order.
fn choose_salt(padata: &[(i32, Vec<u8>)], offered: &[i32]) -> Option<SaltInfo> {
    let mut entries = Vec::new();
    for (ty, value) in padata {
        match *ty {
            PA_ETYPE_INFO2 => entries.extend(parse_etype_info(value, true).ok()?),
            PA_ETYPE_INFO => entries.extend(parse_etype_info(value, false).ok()?),
            _ => {}
        }
    }
    if let Some(e) = entries.into_iter().find(|e| offered.contains(&e.etype)) {
        return Some(e);
    }
    // PW-SALT carries a salt but no enctype; it applies to whichever
    // enctype the reply used.
    let salt = padata
        .iter()
        .find(|(t, _)| *t == PA_PW_SALT)
        .map(|(_, v)| v.clone())?;
    Some(SaltInfo {
        etype: *offered.first()?,
        salt: Some(salt),
        params: None,
    })
}

/// `ETYPE-INFO2-ENTRY ::= SEQUENCE { etype [0], salt [1] KerberosString
/// OPTIONAL, s2kparams [2] OCTET STRING OPTIONAL }`. ETYPE-INFO's salt is
/// an OCTET STRING and it has no s2kparams.
fn parse_etype_info(value: &[u8], v2: bool) -> Result<Vec<SaltInfo>> {
    let mut seq = Reader::new(value).seq()?;
    let mut out = Vec::new();
    while !seq.is_empty() {
        let f = Fields::parse("ETYPE-INFO-ENTRY", seq.expect(der::SEQUENCE)?)?;
        let etype = f.get(0)?.i32()?;
        let salt = match f.opt(1) {
            Some(mut r) if v2 => Some(r.string()?.into_bytes()),
            Some(mut r) => Some(r.octets()?.to_vec()),
            None => None,
        };
        let params = match f.opt(2) {
            Some(mut r) if v2 => {
                let p = r.octets()?;
                Some(p.try_into().map_err(|_| {
                    ClientError::Protocol(format!("s2kparams of {} octets", p.len()))
                })?)
            }
            _ => None,
        };
        out.push(SaltInfo {
            etype,
            salt,
            params,
        });
    }
    Ok(out)
}

// ------------------------------------------------------------- encoding

fn now() -> (i64, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as i64, d.subsec_micros())
}

/// Nonces stay below 2^31: some KDCs read them as Int32.
fn random_nonce() -> u32 {
    rand::thread_rng().next_u32() & 0x7FFF_FFFF
}

fn encode_pa_data(padata: &[(i32, Vec<u8>)]) -> Vec<u8> {
    der::seq(
        &padata
            .iter()
            .map(|(t, v)| {
                der::seq(&[
                    der::field(1, der::int(*t as i64)),
                    der::field(2, der::octets(v)),
                ])
            })
            .collect::<Vec<_>>(),
    )
}

fn encode_kdc_req(msg_type: u8, padata: &[(i32, Vec<u8>)], body: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![
        der::field(1, der::int(5)),
        der::field(2, der::int(msg_type as i64)),
    ];
    if !padata.is_empty() {
        parts.push(der::field(3, encode_pa_data(padata)));
    }
    parts.push(der::field(4, body));
    der::cons(app(msg_type), &[der::seq(&parts)])
}

pub(crate) fn encode_encrypted_data(etype: i32, cipher: &[u8]) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::int(etype as i64)),
        der::field(2, der::octets(cipher)),
    ])
}

/// `PA-ENC-TS-ENC ::= SEQUENCE { patimestamp [0], pausec [1] OPTIONAL }`,
/// encrypted in the client's long-term key with usage 1.
fn encode_enc_timestamp(key: &Key, now: i64, usec: u32) -> Result<Vec<u8>> {
    let ts = der::seq(&[
        der::field(0, der::time(now)),
        der::field(1, der::int(usec as i64)),
    ]);
    Ok(encode_encrypted_data(
        key.enctype(),
        &key.encrypt(KU_PA_ENC_TIMESTAMP, &ts)?,
    ))
}

/// Authenticator ::= [APPLICATION 2] SEQUENCE (RFC 4120 §5.5.1).
pub(crate) fn encode_authenticator(
    client: &Principal,
    cksum: Option<(i32, Vec<u8>)>,
    cusec: u32,
    ctime: i64,
    subkey: Option<&Key>,
    seq_number: Option<u32>,
) -> Vec<u8> {
    let mut parts = vec![
        der::field(0, der::int(5)),
        der::field(1, der::general_string(&client.realm)),
        der::field(2, client.encode_name()),
    ];
    if let Some((ty, sum)) = cksum {
        parts.push(der::field(
            3,
            der::seq(&[
                der::field(0, der::int(ty as i64)),
                der::field(1, der::octets(&sum)),
            ]),
        ));
    }
    parts.push(der::field(4, der::int(cusec as i64)));
    parts.push(der::field(5, der::time(ctime)));
    if let Some(k) = subkey {
        parts.push(der::field(6, encode_key(k)));
    }
    if let Some(s) = seq_number {
        parts.push(der::field(7, der::int(s as i64)));
    }
    der::cons(app(2), &[der::seq(&parts)])
}

/// AP-REQ ::= [APPLICATION 14] SEQUENCE (RFC 4120 §5.5.1).
pub(crate) fn encode_ap_req(
    ap_options: u32,
    ticket: &[u8],
    auth_etype: i32,
    enc_auth: &[u8],
) -> Vec<u8> {
    der::cons(
        app(14),
        &[der::seq(&[
            der::field(0, der::int(5)),
            der::field(1, der::int(14)),
            der::field(2, der::flags32(ap_options)),
            der::field(3, ticket.to_vec()),
            der::field(4, encode_encrypted_data(auth_etype, enc_auth)),
        ])],
    )
}

pub(crate) fn encode_key(k: &Key) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::int(k.enctype() as i64)),
        der::field(1, der::octets(k.bytes())),
    ])
}

pub(crate) fn decode_key(mut r: Reader<'_>) -> Result<Key> {
    let f = Fields::parse("EncryptionKey", r.expect(der::SEQUENCE)?)?;
    Ok(Key::new(f.get(0)?.i32()?, f.get(1)?.octets()?.to_vec())?)
}

/// `EncryptedData ::= SEQUENCE { etype [0], kvno [1] OPTIONAL, cipher [2] }`.
pub(crate) fn decode_encrypted_data(mut r: Reader<'_>) -> Result<(i32, Vec<u8>)> {
    let f = Fields::parse("EncryptedData", r.expect(der::SEQUENCE)?)?;
    Ok((f.get(0)?.i32()?, f.get(2)?.octets()?.to_vec()))
}

// ------------------------------------------------------------- decoding

enum Reply {
    Rep(KdcRep),
    Error(KrbError),
}

struct KdcRep {
    padata: Vec<(i32, Vec<u8>)>,
    client: Principal,
    ticket: Vec<u8>,
    /// The server named in the ticket itself (Ticket.realm, Ticket.sname).
    ticket_server: Principal,
    ticket_enctype: i32,
    enc_etype: i32,
    cipher: Vec<u8>,
}

/// KRB-ERROR ::= [APPLICATION 30] SEQUENCE (RFC 4120 §5.9.1).
pub(crate) struct KrbError {
    pub code: i32,
    pub text: Option<String>,
    pub e_data: Option<Vec<u8>>,
}

impl KrbError {
    pub(crate) fn parse(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_tagged("KRB-ERROR", app(30), data)?;
        Ok(KrbError {
            code: f.get(6)?.i32()?,
            text: f.opt(11).map(|mut r| r.string()).transpose()?,
            e_data: f
                .opt(12)
                .map(|mut r| r.octets().map(<[u8]>::to_vec))
                .transpose()?,
        })
    }

    pub(crate) fn into_error(self) -> ClientError {
        ClientError::Kdc {
            code: self.code,
            text: self.text,
        }
    }

    /// METHOD-DATA ::= SEQUENCE OF PA-DATA, in e-data of PREAUTH_REQUIRED.
    fn method_data(&self) -> Result<Vec<(i32, Vec<u8>)>> {
        match &self.e_data {
            Some(d) => parse_pa_data(Reader::new(d).seq()?),
            None => Ok(Vec::new()),
        }
    }
}

fn parse_pa_data(mut seq: Reader<'_>) -> Result<Vec<(i32, Vec<u8>)>> {
    let mut out = Vec::new();
    while !seq.is_empty() {
        let f = Fields::parse("PA-DATA", seq.expect(der::SEQUENCE)?)?;
        out.push((f.get(1)?.i32()?, f.get(2)?.octets()?.to_vec()));
    }
    Ok(out)
}

/// Parse an AS-REP (`rep_app` 11) / TGS-REP (13) or a KRB-ERROR.
fn parse_reply(data: &[u8], rep_app: u8) -> Result<Reply> {
    match data.first() {
        Some(&t) if t == app(30) => return Ok(Reply::Error(KrbError::parse(data)?)),
        Some(&t) if t == app(rep_app) => {}
        Some(&t) => return protocol(format!("expected KDC-REP or KRB-ERROR, got tag {t:#04x}")),
        None => return protocol("empty reply"),
    }
    let f = Fields::parse_tagged("KDC-REP", app(rep_app), data)?;
    if f.get(0)?.int()? != 5 || f.get(1)?.int()? != rep_app as i64 {
        return protocol("KDC-REP pvno/msg-type mismatch");
    }
    let padata = match f.opt(2) {
        Some(mut r) => parse_pa_data(r.seq()?)?,
        None => Vec::new(),
    };
    let crealm = f.get(3)?.string()?;
    let client = Principal::decode_name(f.get(4)?, crealm)?;
    let ticket = f.raw(5)?.to_vec();
    let tf = Fields::parse_tagged("Ticket", app(1), &ticket)?;
    let ticket_server = Principal::decode_name(tf.get(2)?, tf.get(1)?.string()?)?;
    let (ticket_enctype, _) = decode_encrypted_data(tf.get(3)?)?;
    let (enc_etype, cipher) = decode_encrypted_data(f.get(6)?)?;
    Ok(Reply::Rep(KdcRep {
        padata,
        client,
        ticket,
        ticket_server,
        ticket_enctype,
        enc_etype,
        cipher,
    }))
}

impl KdcRep {
    /// Parse EncASRepPart (25) / EncTGSRepPart (26) and check the nonce.
    /// MIT historically sends 25 inside TGS-REPs too (RFC 4120 §5.4.2
    /// tells clients to accept either).
    fn into_credentials(self, plain: &[u8], nonce: u32) -> Result<Credentials> {
        let tag = match plain.first() {
            Some(&t) if t == app(25) || t == app(26) => t,
            _ => return protocol("enc-part is not EncKDCRepPart"),
        };
        let f = Fields::parse_tagged("EncKDCRepPart", tag, plain)?;
        if f.get(2)?.u32()? != nonce {
            return protocol("KDC reply nonce does not match the request (possible replay)");
        }
        let srealm = f.get(9)?.string()?;
        Ok(Credentials {
            client: self.client,
            server: Principal::decode_name(f.get(10)?, srealm)?,
            session_key: decode_key(f.get(0)?)?,
            ticket: self.ticket,
            ticket_enctype: self.ticket_enctype,
            flags: f.get(4)?.flags32()?,
            authtime: f.get(5)?.time()?,
            starttime: f.opt(6).map(|mut r| r.time()).transpose()?,
            endtime: f.get(7)?.time()?,
            renew_till: f.opt(8).map(|mut r| r.time()).transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principals_parse_like_mit() {
        let p = Principal::parse("nfs/server.example.com@EXAMPLE.COM").unwrap();
        assert_eq!(p.components, ["nfs", "server.example.com"]);
        assert_eq!(p.realm, "EXAMPLE.COM");
        assert_eq!(p.name_type, NT_PRINCIPAL);
        assert_eq!(p.to_string(), "nfs/server.example.com@EXAMPLE.COM");
        assert_eq!(
            Principal::parse("krbtgt/R@R").unwrap(),
            Principal::krbtgt("R")
        );
        assert!(Principal::parse("alice").is_err());
        assert!(Principal::parse("a//b@R").is_err());
        assert!(Principal::parse("a@").is_err());
    }

    #[test]
    fn the_default_salt_is_realm_then_components_unseparated() {
        let p = Principal::parse("host/a.b@EX.COM").unwrap();
        assert_eq!(p.default_salt(), b"EX.COMhosta.b");
    }

    #[test]
    fn principal_names_round_trip() {
        let p = Principal::parse("svc/h@R").unwrap();
        let back = Principal::decode_name(Reader::new(&p.encode_name()), "R".into()).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn an_as_req_has_the_rfc_4120_shape() {
        let c = KdcClient::new("R", ["kdc"]);
        let alice = Principal::parse("alice@R").unwrap();
        let body = c.req_body(Some(&alice), &Principal::krbtgt("R"), 42, 1_790_000_000);
        let req = encode_kdc_req(10, &[], body);
        assert_eq!(req[0], 0x6A);
        let f = Fields::parse_tagged("AS-REQ", app(10), &req).unwrap();
        assert_eq!(f.get(1).unwrap().int().unwrap(), 5);
        assert_eq!(f.get(2).unwrap().int().unwrap(), 10);
        assert!(f.opt(3).is_none());
        let bf = Fields::parse_tagged("KDC-REQ-BODY", der::SEQUENCE, f.raw(4).unwrap()).unwrap();
        assert_eq!(bf.get(2).unwrap().string().unwrap(), "R");
        assert_eq!(bf.get(7).unwrap().u32().unwrap(), 42);
        let mut et = bf.get(8).unwrap().seq().unwrap();
        let mut got = vec![];
        while !et.is_empty() {
            got.push(et.i32().unwrap());
        }
        assert_eq!(got, DEFAULT_ENCTYPES);
    }

    #[test]
    fn a_krb_error_carries_code_text_and_method_data() {
        let md = encode_pa_data(&[(
            PA_ETYPE_INFO2,
            der::seq(&[der::seq(&[
                der::field(0, der::int(18)),
                der::field(1, der::general_string("R.COMalice")),
                der::field(2, der::octets(&4096u32.to_be_bytes())),
            ])]),
        )]);
        let err = der::cons(
            app(30),
            &[der::seq(&[
                der::field(0, der::int(5)),
                der::field(1, der::int(30)),
                der::field(4, der::time(0)),
                der::field(5, der::int(0)),
                der::field(6, der::int(25)),
                der::field(9, der::general_string("R")),
                der::field(10, Principal::krbtgt("R").encode_name()),
                der::field(11, der::general_string("need preauth")),
                der::field(12, der::octets(&md)),
            ])],
        );
        let Reply::Error(e) = parse_reply(&err, 11).unwrap() else {
            panic!("not an error")
        };
        assert_eq!(e.code, KDC_ERR_PREAUTH_REQUIRED);
        assert_eq!(e.text.as_deref(), Some("need preauth"));
        let info = choose_salt(&e.method_data().unwrap(), &[17, 18]).unwrap();
        assert_eq!(info.etype, 18);
        assert_eq!(info.salt.as_deref(), Some(&b"R.COMalice"[..]));
        assert_eq!(info.params, Some(4096u32.to_be_bytes()));
        assert!(choose_salt(&e.method_data().unwrap(), &[19]).is_none());
    }

    #[test]
    fn kdc_addresses_get_port_88_unless_they_name_one() {
        assert_eq!(with_default_port("kdc.example.com"), "kdc.example.com:88");
        assert_eq!(with_default_port("10.0.0.1:750"), "10.0.0.1:750");
        assert_eq!(with_default_port("[::1]:750"), "[::1]:750");
        assert_eq!(with_default_port("[::1]"), "[::1]:88");
        assert_eq!(with_default_port("::1"), "[::1]:88");
    }

    #[test]
    fn an_unreachable_kdc_is_reported_not_hung_on() {
        let c = KdcClient::new("R", ["127.0.0.1:1"]).with_timeout(Duration::from_millis(500));
        let err = c
            .login_with_password(&Principal::parse("a@R").unwrap(), "x")
            .unwrap_err();
        assert!(matches!(err, ClientError::Unreachable { .. }), "{err}");
    }
}
