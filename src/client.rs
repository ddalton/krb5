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

mod fast;
pub(crate) mod krbcred;
mod xrealm;
use crate::config::{self, ClientDefaults, ConfigError, Krb5Conf};
use crate::der::{self, Fields, Reader, app};
use crate::dns::{self, Resolver};
use crate::key::{Key, KeyError};
use rand::RngCore;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;
pub use xrealm::MAX_HOPS;
use xrealm::{KDC_OPT_CANONICALIZE, NoStore, TgtStore, is_tgs, tgt_realm};

#[cfg(feature = "pkinit")]
use crate::pkinit;

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
const KU_TGS_REP_ENC_PART_SUBKEY: u32 = 9;

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
    /// PKINIT failed on the client's side: the KDC's certificate, its
    /// signature, or the client's own identity.
    #[error("PKINIT: {0}")]
    Pkinit(String),
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
        62 => "KDC_ERR_CLIENT_NOT_TRUSTED",
        63 => "KDC_ERR_KDC_NOT_TRUSTED",
        64 => "KDC_ERR_INVALID_SIG",
        65 => "KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED",
        68 => "KDC_ERR_WRONG_REALM",
        70 => "KDC_ERR_CANT_VERIFY_CERTIFICATE",
        71 => "KDC_ERR_INVALID_CERTIFICATE",
        72 => "KDC_ERR_REVOKED_CERTIFICATE",
        75 => "KDC_ERR_CLIENT_NAME_MISMATCH",
        76 => "KDC_ERR_KDC_NAME_MISMATCH",
        77 => "KDC_ERR_INCONSISTENT_KEY_PURPOSE",
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

/// RFC 6806 §11 PA-REQ-ENC-PA-REP: sent empty, returned in the encrypted
/// part as a checksum over the request.
const PA_REQ_ENC_PA_REP: i32 = 149;
/// RFC 6806 §11 key usage for that checksum (KRB5_KEYUSAGE_AS_REQ).
const KU_AS_REQ: u32 = 56;
/// TicketFlags enc-pa-rep (bit 15).
const TKT_FLG_ENC_PA_REP: u32 = 1 << 16;

/// What an AS exchange learned besides the TGT.
struct AsInfo {
    /// The KDC said, in the authenticated reply, that it supports FAST.
    fast_avail: bool,
    /// The pre-authentication used (PA-ENC-TIMESTAMP, PA-ENCRYPTED-CHALLENGE).
    pa_type: Option<i32>,
}

/// MIT's `krb5int_fast_verify_nego` (RFC 6806 §11): if the reply sets
/// enc-pa-rep, its encrypted PA-DATA must hold a checksum, in the reply
/// key, over exactly the request we sent, which an attacker who altered
/// the unprotected AS-REQ cannot forge. Then FAST is available if
/// PA-FX-FAST is there too.
fn verify_enc_pa_rep(plain: &[u8], reply_key: &Key, request: &[u8]) -> Result<bool> {
    let tag = plain.first().copied().unwrap_or(0);
    let f = Fields::parse_tagged("EncKDCRepPart", tag, plain)?;
    if f.get(4)?.flags32()? & TKT_FLG_ENC_PA_REP == 0 {
        return Ok(false);
    }
    let padata = match f.opt(12) {
        Some(mut r) => parse_pa_data(r.seq()?)?,
        None => Vec::new(),
    };
    let Some((_, ck)) = padata.iter().find(|(t, _)| *t == PA_REQ_ENC_PA_REP) else {
        return protocol("enc-pa-rep set but no request checksum (KRB5_KDCREP_MODIFIED)");
    };
    let ck = Fields::parse_tagged("Checksum", der::SEQUENCE, ck)?;
    let sum = ck.get(1)?.octets()?.to_vec();
    if ck.get(0)?.i32()? != reply_key.checksum_type()
        || !reply_key.verify_checksum(KU_AS_REQ, request, &sum)?
    {
        return protocol(
            "the KDC's checksum does not match the request we sent (KRB5_KDCREP_MODIFIED)",
        );
    }
    Ok(padata.iter().any(|(t, _)| *t == fast::PA_FX_FAST))
}

/// The cache `kinit` writes: the TGT, `fast_avail` if the KDC supports
/// FAST, and `pa_type`, both associated with the TGT's server.
fn write_kinit_cache(cache: &CacheName, tgt: &Credentials, info: &AsInfo) -> Result<()> {
    let mut cc = CCache::with_credentials(tgt);
    if info.fast_avail {
        cc.set_config("fast_avail", Some(&tgt.server), b"yes");
    }
    if let Some(t) = info.pa_type {
        cc.set_config("pa_type", Some(&tgt.server), t.to_string().as_bytes());
    }
    cache.resolved()?.write(&cc)?;
    Ok(())
}

/// TicketFlags ok-as-delegate (bit 13).
const TKT_FLG_OK_AS_DELEGATE: u32 = 1 << 18;

// KDCOptions (RFC 4120 §5.4.1; bit 0 is the MSB). Forwardable, proxiable,
// allow-postdate and renewable share their bit with the ticket flag.
const KDC_OPT_FORWARDABLE: u32 = 1 << 30;
const KDC_OPT_PROXIABLE: u32 = 1 << 28;
const KDC_OPT_RENEWABLE: u32 = 1 << 23;
/// Bit 2, not 4 (which is `proxy`).
const KDC_OPT_FORWARDED: u32 = 1 << 29;
/// MIT's KDC_TKT_COMMON_MASK: the ticket flags a TGS request asks for again.
const KDC_TKT_COMMON_MASK: u32 = 0x5480_0000;

/// MIT's DEFAULT_UDP_PREF_LIMIT and HARD_UDP_LIMIT (sendto_kdc.c).
pub const DEFAULT_UDP_PREFERENCE_LIMIT: usize = 1465;
const HARD_UDP_LIMIT: usize = 32700;
/// How long the first pass waits for each UDP answer, and how many passes
/// resend over UDP (MIT's 1 s and MAX_PASS).
const UDP_FIRST_WAIT: Duration = Duration::from_secs(1);
const UDP_PASSES: usize = 3;
/// The largest UDP reply read.
const UDP_MAX_REPLY: usize = 65535;
/// KRB_ERR_RESPONSE_TOO_BIG (RFC 4120 §7.5.9).
pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;

/// How a KDC address may be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    /// Either, preferred by request size (`krb5.conf` entries, and DNS
    /// `_udp` records, which this crate also tries over TCP).
    Either,
}

/// A KDC's answer, and whether it came over UDP.
struct Answer {
    data: Vec<u8>,
    via_udp: bool,
}

fn is_too_big(reply: &[u8]) -> bool {
    reply.first() == Some(&app(30))
        && KrbError::parse(reply).is_ok_and(|e| e.code == KRB_ERR_RESPONSE_TOO_BIG)
}

/// The enctypes this crate can use, in the order given.
fn supported(enctypes: &[i32]) -> Vec<i32> {
    enctypes
        .iter()
        .copied()
        .filter(|e| (17..=20).contains(e))
        .collect()
}

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
    /// PKINIT with a certificate, or anonymous PKINIT (`None`).
    #[cfg(feature = "pkinit")]
    Pkinit(Option<&'a pkinit::Identity>),
}

/// Where an AS exchange is with PKINIT.
#[derive(Default)]
struct PkState {
    /// PA-PK-AS-REQ goes with every request from now on.
    pending: bool,
    #[cfg(feature = "pkinit")]
    request: Option<pkinit::Request>,
    /// The KDC's freshness token (RFC 8070), echoed in the AuthPack.
    #[cfg(feature = "pkinit")]
    freshness: Option<Vec<u8>>,
    /// The KDC offered PA-PKINIT-KX (RFC 6112).
    #[cfg(feature = "pkinit")]
    rfc6112_kdc: bool,
    #[cfg(feature = "pkinit")]
    dh_bits: u32,
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
    /// The transport each of `kdcs` may be reached over.
    transports: Vec<Transport>,
    /// Requests up to this many octets go over UDP first.
    udp_preference_limit: usize,
    use_udp: bool,
    /// Enctypes asked for in the AS exchange and in TGS exchanges.
    tkt_enctypes: Vec<i32>,
    tgs_enctypes: Vec<i32>,
    lifetime: Duration,
    renew_lifetime: Option<Duration>,
    forwardable: bool,
    proxiable: bool,
    /// For locating other realms' KDCs.
    conf: Krb5Conf,
    resolver: Option<Resolver>,
    /// Other realms' KDCs given explicitly, ahead of `conf` and DNS.
    realm_kdcs: HashMap<String, Vec<String>>,
    /// A TGT to armor AS requests with (FAST), and whether FAST is
    /// required from the first request or taken up when the KDC offers it.
    fast_armor: Option<Credentials>,
    fast_required: bool,
    #[cfg(feature = "pkinit")]
    pkinit: pkinit::Settings,
}

impl KdcClient {
    /// `kdcs` are `host` or `host:port` (default port 88), tried in order.
    pub fn new<I, S>(realm: impl Into<String>, kdcs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let kdcs: Vec<String> = kdcs.into_iter().map(Into::into).collect();
        KdcClient {
            realm: realm.into(),
            transports: vec![Transport::Either; kdcs.len()],
            kdcs,
            timeout: Duration::from_secs(10),
            udp_preference_limit: DEFAULT_UDP_PREFERENCE_LIMIT,
            use_udp: true,
            tkt_enctypes: DEFAULT_ENCTYPES.to_vec(),
            tgs_enctypes: DEFAULT_ENCTYPES.to_vec(),
            lifetime: Duration::from_secs(24 * 3600),
            renew_lifetime: None,
            forwardable: false,
            proxiable: false,
            conf: Krb5Conf::empty(),
            resolver: None,
            realm_kdcs: HashMap::new(),
            fast_armor: None,
            fast_required: false,
            #[cfg(feature = "pkinit")]
            pkinit: pkinit::Settings::default(),
        }
    }

    /// Armor every AS exchange (login) with FAST (RFC 6113), as MIT's
    /// `kinit -T` does: `armor` is a TGT for this realm, typically a
    /// host's from its keytab ([`KdcClient::login_with_keytab`]) or one
    /// read from a cache. The KDC must support FAST; pre-authentication is
    /// then the encrypted challenge, and the KDC proves it knows the
    /// client's key too. See the `fast` module docs.
    pub fn with_fast_armor(mut self, armor: Credentials) -> Self {
        self.fast_armor = Some(armor);
        self.fast_required = true;
        self
    }

    /// FAST with an armor TGT from `cache` (a host's cache, say), as MIT
    /// does with an armor ccache: if the cache records that this realm's
    /// KDC supports FAST (its `fast_avail` entry, from RFC 6806
    /// negotiation), every login is armored from the first request, so FAST
    /// cannot be stripped; otherwise a login starts unarmored and turns
    /// armored when the KDC's reply offers FAST (MIT `k5_upgrade_to_fast_p`),
    /// and stays plain against a KDC that does not.
    pub fn with_fast_armor_cache(mut self, cache: &CacheName) -> Result<Self> {
        let cc = cache.read()?;
        let tgt = cc.tgt(now().0).ok_or_else(|| ClientError::NoTgt {
            principal: cc.principal.to_string(),
            cache: cache.to_string(),
        })?;
        self.fast_required = cc.fast_avail(&self.realm);
        self.fast_armor = Some(tgt);
        Ok(self)
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
        let (kdcs, transports) = match self.realm_kdcs.get(realm) {
            Some(k) => (k.clone(), vec![Transport::Either; k.len()]),
            None => {
                let c = Self::locate(&self.conf, realm, self.resolver.as_ref())?;
                (c.kdcs, c.transports)
            }
        };
        Ok(KdcClient {
            realm: realm.to_string(),
            kdcs,
            transports,
            ..self.clone()
        })
    }

    /// A client for `realm`, finding its KDCs as MIT does: the `kdc`
    /// entries in `conf` (`[realms] REALM kdc`), else, if `dns_lookup_kdc`
    /// allows, DNS URI and SRV records through the system resolver (see
    /// [`crate::dns`]). Enctypes, lifetimes and ticket flags come from
    /// `conf` too ([`Krb5Conf::client_defaults`]); `with_*` calls made
    /// afterwards override them.
    pub fn from_config(conf: &Krb5Conf, realm: &str) -> config::Result<Self> {
        Ok(Self::locate(conf, realm, None)?.with_defaults(&conf.client_defaults(realm)?))
    }

    /// [`KdcClient::from_config`] with DNS queries sent to `resolver`
    /// instead of the servers in `/etc/resolv.conf`.
    pub fn from_config_with_resolver(
        conf: &Krb5Conf,
        realm: &str,
        resolver: &Resolver,
    ) -> config::Result<Self> {
        Ok(Self::locate(conf, realm, Some(resolver))?.with_defaults(&conf.client_defaults(realm)?))
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
            let servers = dns::locate_kdc_servers(resolver, realm, dns::dns_uri_lookup(conf))
                .map_err(dns_err)?;
            if !servers.is_empty() {
                debug!("{realm}: KDCs from DNS: {servers:?}");
                let (kdcs, transports): (Vec<String>, Vec<Transport>) = servers.into_iter().unzip();
                let mut c = KdcClient::new(realm, kdcs).remembering(conf, Some(resolver));
                c.transports = transports;
                return Ok(c);
            }
        }
        Err(ConfigError::NoKdcFound {
            realm: realm.to_string(),
            dns,
        })
    }

    /// KDC options for the AS request (MIT get_in_tkt.c).
    fn as_options(&self) -> u32 {
        let mut o = 0;
        if self.forwardable {
            o |= KDC_OPT_FORWARDABLE;
        }
        if self.proxiable {
            o |= KDC_OPT_PROXIABLE;
        }
        if self.renew_lifetime.is_some() {
            o |= KDC_OPT_RENEWABLE;
        }
        o
    }

    fn remembering(mut self, conf: &Krb5Conf, resolver: Option<&Resolver>) -> Self {
        #[cfg(feature = "pkinit")]
        {
            self.pkinit = pkinit::Settings::from_config(conf, &self.realm);
        }
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

    /// Enctypes to request, most preferred first, for initial and service
    /// tickets alike. Unsupported ones are dropped.
    pub fn with_enctypes(self, enctypes: &[i32]) -> Self {
        self.with_tkt_enctypes(enctypes).with_tgs_enctypes(enctypes)
    }

    /// Enctypes for the AS exchange (`default_tkt_enctypes`).
    pub fn with_tkt_enctypes(mut self, enctypes: &[i32]) -> Self {
        self.tkt_enctypes = supported(enctypes);
        self
    }

    /// Enctypes for TGS exchanges (`default_tgs_enctypes`).
    pub fn with_tgs_enctypes(mut self, enctypes: &[i32]) -> Self {
        self.tgs_enctypes = supported(enctypes);
        self
    }

    /// Ask for a renewable TGT, renewable for this long (`renew_lifetime`;
    /// `None`, the default, asks for none).
    pub fn with_renew_lifetime(mut self, renew: Option<Duration>) -> Self {
        self.renew_lifetime = renew.filter(|d| !d.is_zero());
        self
    }

    /// Requests of at most `limit` octets go over UDP first, larger ones
    /// over TCP first (`udp_preference_limit`, default 1465; at most 32700).
    pub fn with_udp_preference_limit(mut self, limit: usize) -> Self {
        self.udp_preference_limit = limit.min(HARD_UDP_LIMIT);
        self
    }

    /// Whether to use UDP at all (default true). Off, every request goes
    /// over TCP, as MIT's `no_udp`.
    pub fn with_udp(mut self, yes: bool) -> Self {
        self.use_udp = yes;
        self
    }

    /// Ask for a forwardable TGT (`forwardable`; `kinit -f`).
    pub fn with_forwardable(mut self, yes: bool) -> Self {
        self.forwardable = yes;
        self
    }

    /// Ask for a proxiable TGT (`proxiable`; `kinit -p`).
    pub fn with_proxiable(mut self, yes: bool) -> Self {
        self.proxiable = yes;
        self
    }

    /// Take every setting `[libdefaults]` has for this client (see
    /// [`Krb5Conf::client_defaults`]).
    pub fn with_defaults(self, d: &ClientDefaults) -> Self {
        self.with_tkt_enctypes(&d.tkt_enctypes)
            .with_tgs_enctypes(&d.tgs_enctypes)
            .with_lifetime(d.ticket_lifetime)
            .with_renew_lifetime(d.renew_lifetime)
            .with_forwardable(d.forwardable)
            .with_proxiable(d.proxiable)
            .with_udp_preference_limit(d.udp_preference_limit)
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

    /// `kinit`: log in with a password and write the TGT to `cache` as
    /// MIT's `kinit` does, with its `fast_avail` (if the KDC said it
    /// supports FAST) and `pa_type` config entries.
    pub fn kinit_with_password(
        &self,
        client: &Principal,
        password: &str,
        cache: &CacheName,
    ) -> Result<Credentials> {
        let (creds, info) = self.as_exchange(
            client,
            Secret::Password(password),
            self.tkt_enctypes.clone(),
        )?;
        write_kinit_cache(cache, &creds, &info)?;
        Ok(creds)
    }

    /// `kinit -k`: as [`KdcClient::kinit_with_password`], from a keytab.
    pub fn kinit_with_keytab(
        &self,
        client: &Principal,
        keytab: &Keytab,
        cache: &CacheName,
    ) -> Result<Credentials> {
        let tgt = self.login_with_keytab_info(client, keytab)?;
        write_kinit_cache(cache, &tgt.0, &tgt.1)?;
        Ok(tgt.0)
    }

    /// AS exchange with a password-derived key: `kinit`.
    pub fn login_with_password(&self, client: &Principal, password: &str) -> Result<Credentials> {
        self.as_exchange(
            client,
            Secret::Password(password),
            self.tkt_enctypes.clone(),
        )
        .map(|(c, _)| c)
    }

    /// AS exchange with a long-term key from a keytab: `kinit -k`.
    ///
    /// Only enctypes the keytab holds for `client` are requested, so the
    /// KDC cannot pick one the client has no key for.
    pub fn login_with_keytab(&self, client: &Principal, keytab: &Keytab) -> Result<Credentials> {
        self.login_with_keytab_info(client, keytab).map(|(c, _)| c)
    }

    fn login_with_keytab_info(
        &self,
        client: &Principal,
        keytab: &Keytab,
    ) -> Result<(Credentials, AsInfo)> {
        let have: Vec<i32> = self
            .tkt_enctypes
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

    /// Trust `anchors` for KDC certificates, in place of the
    /// `pkinit_anchors` from `krb5.conf`.
    #[cfg(feature = "pkinit")]
    pub fn with_pkinit_anchors(mut self, anchors: pkinit::TrustAnchors) -> Self {
        self.pkinit.anchors = Some(anchors);
        self
    }

    /// Accept a KDC certificate whose dNSName is one of `hostnames` (with
    /// the KDC key purpose), as `pkinit_kdc_hostname` does, besides one
    /// naming `krbtgt/REALM@REALM`.
    #[cfg(feature = "pkinit")]
    pub fn with_pkinit_kdc_hostnames<I, S>(mut self, hostnames: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.pkinit.kdc_hostnames = hostnames.into_iter().map(Into::into).collect();
        self
    }

    /// The smallest DH group to offer, in bits, as `pkinit_dh_min_bits`:
    /// 2048 (the default) or 4096.
    #[cfg(feature = "pkinit")]
    pub fn with_pkinit_dh_min_bits(mut self, bits: u32) -> Self {
        self.pkinit.dh_min_bits = bits;
        self
    }

    /// Armor every login with FAST using an anonymous PKINIT TGT, as
    /// `[realms] REALM auto_fast_armor = true` does in MIT, unless armor
    /// is given ([`KdcClient::with_fast_armor`]). The KDC must allow
    /// anonymous PKINIT. Read from `krb5.conf` by
    /// [`KdcClient::from_config`].
    #[cfg(feature = "pkinit")]
    pub fn with_auto_fast_armor(mut self, yes: bool) -> Self {
        self.pkinit.auto_fast_armor = yes;
        self
    }

    /// Anonymous PKINIT (RFC 8062), `kinit -n @REALM`: a TGT for
    /// `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS` from this realm's KDC,
    /// whose certificate must chain to the PKINIT trust anchors. The
    /// ticket names no one; it serves as FAST armor, or for services that
    /// accept anonymous clients.
    #[cfg(feature = "pkinit")]
    pub fn login_anonymous(&self) -> Result<Credentials> {
        self.anonymous(&self.realm).map(|(c, _)| c)
    }

    /// `kinit -n`: [`KdcClient::login_anonymous`], written to `cache`.
    #[cfg(feature = "pkinit")]
    pub fn kinit_anonymous(&self, cache: &CacheName) -> Result<Credentials> {
        let (creds, info) = self.anonymous(&self.realm)?;
        write_kinit_cache(cache, &creds, &info)?;
        Ok(creds)
    }

    #[cfg(feature = "pkinit")]
    fn anonymous(&self, realm: &str) -> Result<(Credentials, AsInfo)> {
        self.as_exchange(
            &pkinit::anonymous_principal(realm),
            Secret::Pkinit(None),
            self.tkt_enctypes.clone(),
        )
    }

    /// PKINIT with a certificate (RFC 4556), `kinit -X
    /// X509_user_identity=FILE:cert.pem,key.pem client`: the KDC checks
    /// the client's certificate and its signature, and maps the
    /// certificate to `client`; the client checks the KDC's in turn.
    #[cfg(feature = "pkinit")]
    pub fn login_with_certificate(
        &self,
        client: &Principal,
        identity: &pkinit::Identity,
    ) -> Result<Credentials> {
        self.as_exchange(
            client,
            Secret::Pkinit(Some(identity)),
            self.tkt_enctypes.clone(),
        )
        .map(|(c, _)| c)
    }

    /// [`KdcClient::login_with_certificate`], written to `cache` as
    /// `kinit` writes it.
    #[cfg(feature = "pkinit")]
    pub fn kinit_with_certificate(
        &self,
        client: &Principal,
        identity: &pkinit::Identity,
        cache: &CacheName,
    ) -> Result<Credentials> {
        let (creds, info) = self.as_exchange(
            client,
            Secret::Pkinit(Some(identity)),
            self.tkt_enctypes.clone(),
        )?;
        write_kinit_cache(cache, &creds, &info)?;
        Ok(creds)
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

    /// A forwarded copy of `tgt` (the client's own TGT) for delegation: a
    /// TGS request for it again with the FORWARDED option, as MIT's
    /// `krb5_fwd_tgt_creds` makes, preferring `enctype` for its session key
    /// (MIT asks for the service session key's) and taking any if the KDC
    /// will not. The TGT must be forwardable; the KDC refuses otherwise
    /// (`KDC_ERR_BADOPTION`).
    pub fn forwarded_tgt(&self, tgt: &Credentials, enctype: Option<i32>) -> Result<Credentials> {
        let me = Principal::krbtgt(&tgt.client.realm);
        if let Some(e) = enctype {
            let pref = self.clone().with_tgs_enctypes(&[e]);
            if let Ok(c) = pref.tgs(tgt, &me, KDC_OPT_FORWARDED) {
                return Ok(c);
            }
        }
        self.tgs(tgt, &me, KDC_OPT_FORWARDED)
    }

    /// One TGS exchange with the KDC of the realm `tgt` is for: a ticket
    /// for `server` (whose realm is the request realm), checked as MIT's
    /// `krb5int_process_tgs_reply` checks it.
    fn tgs(&self, tgt: &Credentials, server: &Principal, kdc_options: u32) -> Result<Credentials> {
        let kdc = self.for_realm(tgt_realm(tgt))?;
        let (now, usec) = now();
        let nonce = random_nonce();
        // MIT's FLAGS2OPTS: the TGT's forwardable, proxiable, may-postdate
        // and renewable flags carry over as options (KDC_TKT_COMMON_MASK).
        let kdc_options = kdc_options | (tgt.flags & KDC_TKT_COMMON_MASK);
        let body = kdc.req_body_with(None, server, nonce, now, &kdc.tgs_enctypes, kdc_options);

        // With FAST, a subkey in the authenticator: it keys the implicit
        // armor and the reply (MIT send_tgs.c always does this).
        let subkey = match self.fast_armor {
            Some(_) => Some(Key::random(tgt.session_key.enctype())?),
            None => None,
        };
        let cksum = tgt.session_key.checksum(KU_TGS_REQ_AUTH_CKSUM, &body)?;
        let authenticator = encode_authenticator(
            &tgt.client,
            Some((tgt.session_key.checksum_type(), cksum)),
            usec,
            now,
            subkey.as_ref(),
            None,
        );
        let enc_auth = tgt.session_key.encrypt(KU_TGS_REQ_AUTH, &authenticator)?;
        let ap_req = encode_ap_req(0, &tgt.ticket, tgt.session_key.enctype(), &enc_auth);

        let armor = match &subkey {
            Some(sk) => Some(fast::Armor::implicit(sk, &tgt.session_key)?),
            None => None,
        };
        let req = match &armor {
            None => encode_kdc_req(12, &[(PA_TGS_REQ, ap_req)], body),
            Some(a) => {
                let fx = a.wrap(&ap_req, &body, &[])?;
                encode_kdc_req(12, &[(PA_TGS_REQ, ap_req), fx], body)
            }
        };
        let rep = match parse_reply(&kdc.exchange(&req)?, 13)? {
            Reply::Error(e) => {
                let Some(a) = &armor else {
                    return Err(e.into_error());
                };
                return Err(match e.method_data().and_then(|m| a.open(&m, nonce)) {
                    Ok(fr) => match fr.padata.iter().find(|(t, _)| *t == fast::PA_FX_ERROR) {
                        Some((_, inner)) => KrbError::parse(inner)?.into_error(),
                        None => {
                            return protocol("expecting FX_ERROR pa-data inside FAST container");
                        }
                    },
                    Err(_) => e.into_error(),
                });
            }
            Reply::Rep(r) => r,
        };
        if !same_principal(&rep.client, &tgt.client) {
            return protocol(format!(
                "TGS reply is for {}, not {} (KRB5_KDCREP_MODIFIED)",
                rep.client, tgt.client
            ));
        }
        let ticket_server = rep.ticket_server.clone();
        let plain = match (&armor, &subkey) {
            (Some(a), Some(sk)) => {
                let fr = a.open(&rep.padata, nonce)?;
                a.check_finished(&fr, &rep.ticket)?;
                // RFC 4120 §5.4.2: with a subkey the reply is in it (usage
                // 9); FAST may strengthen it (MIT krb5int_fast_reply_key).
                let key = match &fr.strengthen_key {
                    Some(st) => Key::cf2(st, "strengthenkey", sk, "replykey")?,
                    None => sk.clone(),
                };
                key.decrypt(KU_TGS_REP_ENC_PART_SUBKEY, &rep.cipher)?
            }
            _ => tgt
                .session_key
                .decrypt(KU_TGS_REP_ENC_PART_SESSION, &rep.cipher)?,
        };
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
    ) -> Result<(Credentials, AsInfo)> {
        let krbtgt = Principal::krbtgt(&client.realm);
        #[allow(unused_mut)]
        let mut kdc_options = self.as_options();
        #[cfg(feature = "pkinit")]
        let anonymous = matches!(secret, Secret::Pkinit(None));
        #[cfg(feature = "pkinit")]
        {
            if anonymous {
                kdc_options |= pkinit::KDC_OPT_REQUEST_ANONYMOUS;
            }
            // MIT's auto_fast_armor: armor with an anonymous PKINIT TGT
            // good for an hour, unless armor was given.
            if self.fast_armor.is_none() && self.pkinit.auto_fast_armor && !anonymous {
                debug!("auto_fast_armor: getting armor by anonymous PKINIT");
                let armor = self
                    .clone()
                    .with_lifetime(Duration::from_secs(3600))
                    .with_renew_lifetime(None)
                    .anonymous(&client.realm)?
                    .0;
                return self
                    .clone()
                    .with_fast_armor(armor)
                    .as_exchange(client, secret, enctypes);
            }
        }
        // MIT's state: whether we armor, whether we may still upgrade to
        // FAST or drop the informational PA-DATA (each once), and the
        // pre-authentication chosen.
        let mut armored = self.fast_armor.is_some() && self.fast_required;
        let mut restarted = false;
        let mut info_pa = true;
        let mut preauth: Vec<(i32, Vec<u8>)> = Vec::new();
        let mut preauth_key: Option<Key> = None;
        let mut pa_type: Option<i32> = None;
        let mut armor: Option<fast::Armor> = None;
        #[allow(unused_mut)]
        let mut pk = PkState::default();
        #[cfg(feature = "pkinit")]
        {
            pk.dh_bits = self.pkinit.dh_min_bits;
        }

        for _ in 0..4 {
            if armored && armor.is_none() {
                let tgt = self
                    .fast_armor
                    .as_ref()
                    .expect("armored only with an armor");
                let (now, usec) = now();
                armor = Some(fast::Armor::from_tgt(tgt, now, usec)?);
            }
            let (now, usec) = now();
            let nonce = random_nonce();
            let body =
                self.req_body_with(Some(client), &krbtgt, nonce, now, &enctypes, kdc_options);
            let mut padata = preauth.clone();
            #[cfg(feature = "pkinit")]
            if let Secret::Pkinit(identity) = &secret {
                if pk.pending {
                    let (value, request) = pkinit::request(&pkinit::RequestInput {
                        identity: *identity,
                        rfc6112_kdc: pk.rfc6112_kdc,
                        body: &body,
                        nonce,
                        now,
                        usec,
                        freshness: pk.freshness.as_deref(),
                        dh_bits: pk.dh_bits,
                    })?;
                    padata.insert(0, (pkinit::PA_PK_AS_REQ, value));
                    pk.request = Some(request);
                } else if info_pa {
                    // RFC 8070: ask for a freshness token.
                    padata.push((pkinit::PA_AS_FRESHNESS, Vec::new()));
                }
            }
            // RFC 6806 §11: ask for the KDC's checksum over this request
            // and its FAST support in the encrypted reply.
            if info_pa {
                padata.push((PA_REQ_ENC_PA_REP, Vec::new()));
            }
            let req = match &armor {
                None => encode_kdc_req(10, &padata, body),
                Some(a) => {
                    let outer = a.wrap(&body, &body, &padata)?;
                    encode_kdc_req(10, &[outer], body)
                }
            };

            let rep = match parse_reply(&self.exchange(&req)?, 11)? {
                Reply::Rep(r) => r,
                Reply::Error(outer) => {
                    // Under FAST the real error, and the PA-DATA that goes
                    // with it, are inside the armored response.
                    let (e, methods) = match &armor {
                        None => {
                            let m = outer.method_data()?;
                            (outer, m)
                        }
                        Some(a) => match outer.method_data().and_then(|m| a.open(&m, nonce)) {
                            Ok(fr) => {
                                let Some((_, inner)) =
                                    fr.padata.iter().find(|(t, _)| *t == fast::PA_FX_ERROR)
                                else {
                                    return protocol(
                                        "expecting FX_ERROR pa-data inside FAST container",
                                    );
                                };
                                (KrbError::parse(inner)?, fr.padata.clone())
                            }
                            // A KDC that does not speak FAST: its error is the error.
                            Err(_) => (outer, Vec::new()),
                        },
                    };
                    // MIT k5_upgrade_to_fast_p: an armor to hand and a KDC
                    // that offers FAST: start again, armored.
                    if armor.is_none()
                        && self.fast_armor.is_some()
                        && !restarted
                        && methods.iter().any(|(t, _)| *t == fast::PA_FX_FAST)
                    {
                        debug!("KDC offers FAST; restarting armored");
                        armored = true;
                        restarted = true;
                        preauth.clear();
                        preauth_key = None;
                        pa_type = None;
                        pk = PkState {
                            #[cfg(feature = "pkinit")]
                            dh_bits: pk.dh_bits,
                            ..PkState::default()
                        };
                        continue;
                    }
                    // A pre-1.7 MIT KDC rejects the informational PA-DATA
                    // as failed pre-authentication: retry without it.
                    if e.code == KDC_ERR_PREAUTH_FAILED
                        && preauth.is_empty()
                        && !pk.pending
                        && info_pa
                        && !restarted
                    {
                        debug!("KDC refused PA-REQ-ENC-PA-REP; retrying without it");
                        info_pa = false;
                        restarted = true;
                        continue;
                    }
                    #[cfg(feature = "pkinit")]
                    if let Secret::Pkinit(_) = &secret {
                        // MIT tries the next larger group once when the
                        // KDC wants more than it was offered.
                        if e.code == pkinit::KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED
                            && pk.request.as_ref().is_some_and(|r| r.dh_bits() < 4096)
                        {
                            debug!("KDC refused the DH group; retrying with 4096 bits");
                            pk.dh_bits = 4096;
                            pk.request = None;
                            continue;
                        }
                        if e.code != KDC_ERR_PREAUTH_REQUIRED || pk.pending {
                            return Err(e.into_error());
                        }
                        if !methods.iter().any(|(t, _)| *t == pkinit::PA_PK_AS_REQ) {
                            return Err(ClientError::NoKey("the KDC does not offer PKINIT".into()));
                        }
                        debug!("pre-authenticating with PKINIT");
                        pk.freshness = methods
                            .iter()
                            .find(|(t, v)| *t == pkinit::PA_AS_FRESHNESS && !v.is_empty())
                            .map(|(_, v)| v.clone());
                        pk.rfc6112_kdc = methods.iter().any(|(t, _)| *t == pkinit::PA_PKINIT_KX);
                        pk.pending = true;
                        pa_type = Some(pkinit::PA_PK_AS_REQ);
                        preauth = fast::cookie(&methods).into_iter().collect();
                        continue;
                    }
                    if e.code != KDC_ERR_PREAUTH_REQUIRED || !preauth.is_empty() {
                        return Err(e.into_error());
                    }
                    let info = choose_salt(&methods, &enctypes).ok_or_else(|| {
                        ClientError::NoKey(
                            "KDC offered no supported enctype for pre-authentication".into(),
                        )
                    })?;
                    let key = derive_key(&secret, client, &info)?;
                    preauth = match &armor {
                        None => {
                            debug!(
                                etype = info.etype,
                                "pre-authenticating with PA-ENC-TIMESTAMP"
                            );
                            pa_type = Some(PA_ENC_TIMESTAMP);
                            vec![(PA_ENC_TIMESTAMP, encode_enc_timestamp(&key, now, usec)?)]
                        }
                        Some(a) => {
                            if !methods
                                .iter()
                                .any(|(t, _)| *t == fast::PA_ENCRYPTED_CHALLENGE)
                            {
                                return Err(ClientError::NoKey(
                                    "the KDC offers no encrypted challenge inside FAST".into(),
                                ));
                            }
                            debug!(
                                etype = info.etype,
                                "pre-authenticating with PA-ENCRYPTED-CHALLENGE"
                            );
                            pa_type = Some(fast::PA_ENCRYPTED_CHALLENGE);
                            // MIT uses the KDC's time from the (armored)
                            // error, so the client's clock does not matter.
                            vec![(
                                fast::PA_ENCRYPTED_CHALLENGE,
                                a.client_challenge(&key, e.stime, e.susec)?,
                            )]
                        }
                    };
                    // RFC 6113 §5.2: echo the cookie so a stateless KDC can
                    // continue the conversation.
                    if let Some(c) = fast::cookie(&methods) {
                        preauth.push(c);
                    }
                    preauth_key = Some(key);
                    continue;
                }
            };

            let fast_rep = match &armor {
                None => None,
                Some(a) => {
                    let fr = a.open(&rep.padata, nonce)?;
                    let client = a.check_finished(&fr, &rep.ticket)?;
                    Some((a, fr, client))
                }
            };
            let reply_padata = fast_rep
                .as_ref()
                .map_or(&rep.padata, |(_, fr, _)| &fr.padata);

            #[cfg(feature = "pkinit")]
            let kx: Vec<(i32, Vec<u8>)> = reply_padata
                .iter()
                .filter(|(t, _)| *t == pkinit::PA_PKINIT_KX)
                .cloned()
                .collect();
            // The reply key is the long-term key for the enctype the KDC
            // chose; reuse the pre-auth key when it matches, otherwise
            // take the salt from the reply's own PA-DATA. With PKINIT it
            // comes from the DH exchange.
            let long_term = match (&secret, preauth_key.take()) {
                #[cfg(feature = "pkinit")]
                (Secret::Pkinit(_), _) => {
                    let Some(state) = &pk.request else {
                        return Err(ClientError::NoKey(
                            "the KDC answered without PKINIT pre-authentication".into(),
                        ));
                    };
                    let Some((_, value)) = reply_padata
                        .iter()
                        .find(|(t, _)| *t == pkinit::PA_PK_AS_REP)
                    else {
                        return protocol("the KDC's reply has no PA-PK-AS-REP");
                    };
                    state.reply_key(&pkinit::ReplyInput {
                        settings: &self.pkinit,
                        pa_value: value,
                        realm: &client.realm,
                        client,
                        as_req: &req,
                        enctype: rep.enc_etype,
                        now,
                    })?
                }
                (_, Some(k)) if k.enctype() == rep.enc_etype => k,
                _ => {
                    let info = choose_salt(reply_padata, &[rep.enc_etype]).unwrap_or(SaltInfo {
                        etype: rep.enc_etype,
                        salt: None,
                        params: None,
                    });
                    derive_key(&secret, client, &info)?
                }
            };
            let mut key = long_term.clone();
            if let Some((a, fr, _)) = &fast_rep {
                // The KDC's encrypted challenge proves it knows our key.
                if let Some((_, ch)) = fr
                    .padata
                    .iter()
                    .find(|(t, _)| *t == fast::PA_ENCRYPTED_CHALLENGE)
                {
                    a.verify_kdc_challenge(&long_term, ch)?;
                } else if pa_type == Some(fast::PA_ENCRYPTED_CHALLENGE) {
                    return protocol(
                        "the KDC returned no encrypted challenge (KDC not authenticated)",
                    );
                }
                if let Some(sk) = &fr.strengthen_key {
                    key = Key::cf2(sk, "strengthenkey", &long_term, "replykey")?;
                }
            }
            let plain = key
                .decrypt(KU_AS_REP_ENC_PART, &rep.cipher)
                .map_err(|e| match secret {
                    Secret::Password(_) => ClientError::Crypto(KeyError(format!(
                        "cannot decrypt AS-REP (wrong password?): {}",
                        e.0
                    ))),
                    _ => ClientError::Crypto(e),
                })?;
            let fast_avail = verify_enc_pa_rep(&plain, &key, &req)?;
            let mut rep = rep;
            if let Some((_, _, client)) = fast_rep {
                // MIT: the finished message names the client.
                rep.client = client;
            }
            let creds = rep.into_credentials(&plain, nonce)?;
            #[cfg(feature = "pkinit")]
            if anonymous {
                pkinit::verify_anonymous(&kx, &long_term, &creds.session_key)?;
            }
            return Ok((
                creds,
                AsInfo {
                    fast_avail,
                    pa_type,
                },
            ));
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
        self.req_body_with(cname, sname, nonce, now, &self.tkt_enctypes, 0)
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
        // rtime, for a renewable AS request (TGS requests leave it to the
        // KDC, which renews up to the TGT's own renew-till, as MIT does).
        if let (Some(renew), Some(_)) = (self.renew_lifetime, cname) {
            parts.push(der::field(6, der::time(now + renew.as_secs() as i64)));
        }
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

    /// Send one request and return the reply, as MIT's `k5_sendto_kdc`
    /// does: UDP first for a request of at most `udp_preference_limit`
    /// octets (1465), TCP first for a larger one, and over TCP only if a
    /// UDP reply is `KRB_ERR_RESPONSE_TOO_BIG`.
    fn exchange(&self, req: &[u8]) -> Result<Vec<u8>> {
        let reply = self.send(req, self.use_udp)?;
        if reply.via_udp && is_too_big(&reply.data) {
            debug!(realm = %self.realm, "KDC reply too big for UDP; retrying over TCP");
            return Ok(self.send(req, false)?.data);
        }
        Ok(reply.data)
    }

    /// MIT's `k5_sendto`, sequentially: a first pass over every server,
    /// preferred transport first and the other one after (UDP waiting a
    /// second for its answer), then up to two more passes resending over
    /// UDP with a growing wait. TCP gets one connection per server.
    fn send(&self, req: &[u8], allow_udp: bool) -> Result<Answer> {
        let udp_first = allow_udp && req.len() <= self.udp_preference_limit;
        let mut first = Vec::new();
        let mut deferred = Vec::new();
        for (kdc, &t) in self.kdcs.iter().zip(&self.transports) {
            let addr = with_default_port(kdc);
            let preferred = if udp_first {
                Transport::Udp
            } else {
                Transport::Tcp
            };
            match t {
                Transport::Udp if !allow_udp => {}
                Transport::Either => {
                    first.push((addr.clone(), preferred));
                    if allow_udp {
                        let other = if udp_first {
                            Transport::Tcp
                        } else {
                            Transport::Udp
                        };
                        deferred.push((addr, other));
                    }
                }
                t if t == preferred => first.push((addr, t)),
                t => deferred.push((addr, t)),
            }
        }
        let attempts: Vec<(String, Transport)> = first.into_iter().chain(deferred).collect();

        let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no KDCs configured");
        let mut note = |addr: &str, t: Transport, e: std::io::Error| {
            debug!(kdc = %addr, transport = ?t, error = %e, "KDC did not answer");
            last = e;
        };
        for (addr, t) in &attempts {
            let r = match t {
                Transport::Udp => self.exchange_udp(addr, req, UDP_FIRST_WAIT),
                _ => self.exchange_tcp(addr, req),
            };
            match r {
                Ok(data) => {
                    return Ok(Answer {
                        data,
                        via_udp: *t == Transport::Udp,
                    });
                }
                Err(e) => note(addr, *t, e),
            }
        }
        let mut wait = UDP_FIRST_WAIT * 2;
        for _ in 1..UDP_PASSES {
            for (addr, _) in attempts.iter().filter(|(_, t)| *t == Transport::Udp) {
                match self.exchange_udp(addr, req, wait) {
                    Ok(data) => {
                        return Ok(Answer {
                            data,
                            via_udp: true,
                        });
                    }
                    Err(e) => note(addr, Transport::Udp, e),
                }
            }
            wait *= 2;
        }
        Err(ClientError::Unreachable {
            realm: self.realm.clone(),
            last,
        })
    }

    /// One datagram to each address `addr` resolves to, accepting a reply
    /// only from the address asked (a connected socket).
    fn exchange_udp(&self, addr: &str, req: &[u8], wait: Duration) -> std::io::Result<Vec<u8>> {
        use std::io::{Error, ErrorKind};
        let mut last = Error::new(ErrorKind::NotFound, format!("{addr} did not resolve"));
        for sa in addr.to_socket_addrs()? {
            let bind: std::net::SocketAddr = match sa {
                std::net::SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
                std::net::SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
            };
            let attempt = || -> std::io::Result<Vec<u8>> {
                let sock = UdpSocket::bind(bind)?;
                sock.connect(sa)?;
                sock.set_read_timeout(Some(wait.min(self.timeout)))?;
                sock.send(req)?;
                let mut buf = vec![0u8; UDP_MAX_REPLY];
                let n = sock.recv(&mut buf)?;
                buf.truncate(n);
                Ok(buf)
            };
            match attempt() {
                Ok(r) => return Ok(r),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn exchange_tcp(&self, addr: &str, req: &[u8]) -> std::io::Result<Vec<u8>> {
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
        #[cfg(feature = "pkinit")]
        Secret::Pkinit(_) => Err(ClientError::NoKey(
            "PKINIT has no long-term key to derive".into(),
        )),
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
    /// The KDC's clock (stime, susec).
    pub stime: i64,
    pub susec: u32,
}

impl KrbError {
    pub(crate) fn parse(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_tagged("KRB-ERROR", app(30), data)?;
        Ok(KrbError {
            stime: f.get(4)?.time()?,
            susec: f.get(5)?.u32()?,
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

    // ------------------------------------------------- UDP and TCP

    use std::net::{TcpListener, UdpSocket};
    use std::sync::{Arc, Mutex};

    /// What the fake KDC does on each transport.
    #[derive(Clone, Copy)]
    enum Does {
        Answer,
        TooBig,
        Silent,
        Refuse,
    }

    fn too_big() -> Vec<u8> {
        der::cons(
            app(30),
            &[der::seq(&[
                der::field(0, der::int(5)),
                der::field(1, der::int(30)),
                der::field(4, der::time(0)),
                der::field(5, der::int(0)),
                der::field(6, der::int(KRB_ERR_RESPONSE_TOO_BIG as i64)),
                der::field(9, der::general_string("R")),
                der::field(10, Principal::krbtgt("R").encode_name()),
            ])],
        )
    }

    /// A UDP and a TCP listener on one port; records which transport each
    /// request came over and answers with the transport's name.
    fn fake_kdc(udp: Does, tcp: Does) -> (String, Arc<Mutex<Vec<&'static str>>>) {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = u.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            while let Ok((_, from)) = u.recv_from(&mut buf) {
                l.lock().unwrap().push("udp");
                match udp {
                    Does::Answer => drop(u.send_to(b"udp", from)),
                    Does::TooBig => drop(u.send_to(&too_big(), from)),
                    Does::Silent | Does::Refuse => {}
                }
            }
        });
        if !matches!(tcp, Does::Refuse) {
            let t = TcpListener::bind(("127.0.0.1", port)).unwrap();
            let l = log.clone();
            std::thread::spawn(move || {
                for c in t.incoming() {
                    let mut c = c.unwrap();
                    let mut len = [0u8; 4];
                    c.read_exact(&mut len).unwrap();
                    let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                    c.read_exact(&mut req).unwrap();
                    l.lock().unwrap().push("tcp");
                    if let Does::Answer = tcp {
                        c.write_all(&3u32.to_be_bytes()).unwrap();
                        c.write_all(b"tcp").unwrap();
                    }
                }
            });
        }
        (format!("127.0.0.1:{port}"), log)
    }

    fn client(addr: &str) -> KdcClient {
        KdcClient::new("R", [addr]).with_timeout(Duration::from_secs(2))
    }

    /// A pre-1.7 MIT KDC answers PA-REQ-ENC-PA-REP with PREAUTH_FAILED:
    /// the client tries once more without it, then reports the error.
    #[test]
    fn a_kdc_refusing_the_negotiation_padata_gets_one_retry_without_it() {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = format!("127.0.0.1:{}", u.local_addr().unwrap().port());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = u.recv_from(&mut buf) {
                let has = buf[..n].windows(4).any(|w| w == [0x02, 0x02, 0x00, 0x95]);
                s.lock().unwrap().push(has);
                let err = der::cons(
                    app(30),
                    &[der::seq(&[
                        der::field(0, der::int(5)),
                        der::field(1, der::int(30)),
                        der::field(4, der::time(0)),
                        der::field(5, der::int(0)),
                        der::field(6, der::int(KDC_ERR_PREAUTH_FAILED as i64)),
                        der::field(9, der::general_string("R")),
                        der::field(10, Principal::krbtgt("R").encode_name()),
                    ])],
                );
                u.send_to(&err, from).unwrap();
            }
        });
        let err = client(&addr)
            .login_with_password(&Principal::parse("a@R").unwrap(), "x")
            .unwrap_err();
        assert_eq!(err.kdc_code(), Some(KDC_ERR_PREAUTH_FAILED));
        // padata-type 149 (INTEGER 02 02 00 95) the first time only.
        assert_eq!(*seen.lock().unwrap(), [true, false]);
    }

    #[test]
    fn a_small_request_goes_over_udp_first() {
        let (addr, log) = fake_kdc(Does::Answer, Does::Answer);
        assert_eq!(client(&addr).exchange(&[0; 100]).unwrap(), b"udp");
        assert_eq!(*log.lock().unwrap(), ["udp"]);
    }

    #[test]
    fn a_request_over_the_preference_limit_goes_over_tcp_first() {
        let (addr, log) = fake_kdc(Does::Answer, Does::Answer);
        let c = client(&addr).with_udp_preference_limit(50);
        assert_eq!(c.exchange(&[0; 100]).unwrap(), b"tcp");
        assert_eq!(*log.lock().unwrap(), ["tcp"]);
        // The default limit, MIT's 1465, is the boundary.
        let (addr, log) = fake_kdc(Does::Answer, Does::Answer);
        assert_eq!(client(&addr).exchange(&[0; 1465]).unwrap(), b"udp");
        assert_eq!(client(&addr).exchange(&[0; 1466]).unwrap(), b"tcp");
        assert_eq!(*log.lock().unwrap(), ["udp", "tcp"]);
    }

    #[test]
    fn response_too_big_over_udp_is_asked_again_over_tcp() {
        let (addr, log) = fake_kdc(Does::TooBig, Does::Answer);
        assert_eq!(client(&addr).exchange(&[0; 100]).unwrap(), b"tcp");
        assert_eq!(*log.lock().unwrap(), ["udp", "tcp"]);
    }

    #[test]
    fn a_silent_udp_server_gives_way_to_tcp_after_a_second() {
        let (addr, log) = fake_kdc(Does::Silent, Does::Answer);
        let t = std::time::Instant::now();
        assert_eq!(client(&addr).exchange(&[0; 100]).unwrap(), b"tcp");
        assert!(
            t.elapsed() >= Duration::from_millis(900),
            "{:?}",
            t.elapsed()
        );
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        assert_eq!(*log.lock().unwrap(), ["udp", "tcp"]);
    }

    #[test]
    fn udp_is_resent_on_later_passes_when_tcp_is_refused() {
        let (addr, log) = fake_kdc(Does::Silent, Does::Refuse);
        let c = client(&addr).with_timeout(Duration::from_millis(300));
        assert!(matches!(
            c.exchange(&[0; 100]),
            Err(ClientError::Unreachable { .. })
        ));
        assert_eq!(*log.lock().unwrap(), ["udp", "udp", "udp"], "three passes");
    }

    #[test]
    fn with_udp_off_everything_is_tcp() {
        let (addr, log) = fake_kdc(Does::Answer, Does::Answer);
        assert_eq!(
            client(&addr).with_udp(false).exchange(&[0; 10]).unwrap(),
            b"tcp"
        );
        assert_eq!(*log.lock().unwrap(), ["tcp"]);
    }

    #[test]
    fn a_tcp_only_address_is_never_sent_udp() {
        let (addr, log) = fake_kdc(Does::Answer, Does::Answer);
        let mut c = client(&addr);
        c.transports = vec![Transport::Tcp];
        assert_eq!(c.exchange(&[0; 10]).unwrap(), b"tcp");
        let mut u = client(&addr);
        u.transports = vec![Transport::Udp];
        assert_eq!(
            u.clone()
                .with_udp_preference_limit(1)
                .exchange(&[0; 10])
                .unwrap(),
            b"udp"
        );
        assert!(matches!(
            u.with_udp(false).exchange(&[0; 10]),
            Err(ClientError::Unreachable { .. })
        ));
        assert_eq!(*log.lock().unwrap(), ["tcp", "udp"]);
    }
}
