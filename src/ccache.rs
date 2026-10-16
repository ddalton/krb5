//! Credential caches: MIT's `FILE:` format and `DIR:` collections, so
//! tickets move between this crate and `kinit`, `klist`, `kvno` and every
//! other GSS program on the machine.
//!
//! The file format is MIT's (`doc/formats/ccache_file_format.rst`,
//! `ccmarshal.c`): versions 1 to 4 are read, version 4 is written.
//! Configuration entries (server realm `X-CACHECONF:`), entries with
//! enctypes this crate cannot use, and unknown header fields are all kept
//! when a cache is rewritten.
//!
//! # Writing without locks
//!
//! MIT appends to a cache file in place under a POSIX `fcntl` lock. This
//! crate never modifies a cache in place: it writes the whole new cache to
//! a fresh `0600` file beside the old one and renames it over the top. A
//! reader, ours or MIT's, therefore sees either the old file or the new
//! one, never a mixture. The cost is a lost update when MIT appends to the
//! old file at the moment it is replaced; what is lost is a cached service
//! ticket, which is fetched again the next time it is needed. MIT's own
//! `kinit` replaces caches the same way (unlink and recreate).
//!
//! Reading needs no lock either: as in MIT, a credential cut short by the
//! end of the file (an append in progress) is the end of the sequence.
//!
//! # Cache names
//!
//! [`CacheName`] resolves names as MIT does: `KRB5CCNAME`, then
//! `[libdefaults] default_ccache_name`, then `FILE:/tmp/krb5cc_%{uid}`.
//! `FILE:`, `DIR:` and (on Unix) `KCM:` are supported; `KEYRING:`, `API:`
//! and `MEMORY:` are refused with [`CacheError::UnsupportedType`]. See
//! [`kcm`] for the KCM protocol and its limits.

use crate::client::{Credentials, Principal, decode_encrypted_data};
use crate::config::Krb5Conf;
use crate::der::{Fields, app};
use crate::key::Key;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
pub mod kcm;

/// The realm of configuration entries' server principals.
pub const CONF_REALM: &str = "X-CACHECONF:";
/// The first component of a configuration entry's server principal.
pub const CONF_NAME: &str = "krb5_ccache_conf_data";

/// MIT's built-in default, used when neither `KRB5CCNAME` nor
/// `default_ccache_name` is set.
pub const DEFAULT_CCACHE_NAME: &str = "FILE:/tmp/krb5cc_%{uid}";

const FVNO_BASE: u16 = 0x0500;
const TAG_DELTATIME: u16 = 1;

/// A credential cache that could not be found, read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    /// Reading or writing `path` failed.
    #[error("{}: {source}", path.display())]
    Io {
        /// The cache file, directory or KCM socket.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// `path` is not in the ccache file format.
    #[error("{}: not a credential cache: {msg}", path.display())]
    Format {
        /// The cache file.
        path: PathBuf,
        /// What is wrong with it.
        msg: String,
    },
    /// A cache type this crate does not implement (`KEYRING`, `API`, ...).
    #[error("credential cache type {0:?} is not supported (only FILE, DIR and KCM)")]
    UnsupportedType(String),
    /// No KCM daemon is listening (or KCM is disabled with
    /// `kcm_socket = -`).
    #[error("no KCM daemon at {}: {source}{}", socket.display(), if cfg!(target_os = "macos") { " (macOS's own KCM uses Mach IPC, which this crate does not speak)" } else { "" })]
    KcmUnavailable {
        /// The daemon's socket.
        socket: PathBuf,
        /// The error connecting to it.
        source: io::Error,
    },
    /// The KCM daemon refused an operation with a krb5 error code.
    #[error("KCM {op} failed: {} ({code})", kcm_error_name(*code))]
    Kcm {
        /// The KCM operation, as MIT names it (`GET_PRINCIPAL`).
        op: &'static str,
        /// The krb5 error code; see [`kcm::error_name`].
        code: i32,
    },
    /// A KCM cache has no file path.
    #[error("{0} is not a file cache")]
    NotAFile(String),
    /// A cache name (the first field) that does not parse, and why.
    #[error("bad credential cache name {0:?}: {1}")]
    BadName(String, String),
}

/// A result with a [`CacheError`].
pub type Result<T> = std::result::Result<T, CacheError>;

fn kcm_error_name(code: i32) -> &'static str {
    #[cfg(unix)]
    return kcm::error_name(code);
    #[cfg(not(unix))]
    {
        let _ = code;
        "unknown"
    }
}

// ------------------------------------------------------------------ entries

/// One credential record, exactly as stored, so that entries this crate
/// cannot interpret survive a rewrite unchanged.
///
/// Times are the file's unsigned 32-bit seconds; 0 means unset.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// The client principal.
    pub client: Principal,
    /// The server principal the ticket is for.
    pub server: Principal,
    /// The session key's enctype (the keyblock's).
    pub enctype: i32,
    /// The session key.
    pub key: Vec<u8>,
    /// When the initial authentication happened, in seconds since the
    /// epoch.
    pub authtime: u32,
    /// When the ticket becomes valid, in seconds since the epoch.
    pub starttime: u32,
    /// When the ticket expires, in seconds since the epoch.
    pub endtime: u32,
    /// The latest a renewal may extend the ticket to, in seconds since the
    /// epoch.
    pub renew_till: u32,
    /// MIT's `is_skey`: the ticket is user-to-user, in the session key of
    /// `second_ticket`.
    pub is_skey: bool,
    /// The ticket flags (RFC 4120 §5.3), bit 0 the most significant.
    pub flags: u32,
    /// The ticket's client addresses, `(addrtype, address)`.
    pub addresses: Vec<(u16, Vec<u8>)>,
    /// The ticket's authorization data, `(ad-type, ad-data)`.
    pub authdata: Vec<(u16, Vec<u8>)>,
    /// The DER `Ticket`; a configuration entry's value.
    pub ticket: Vec<u8>,
    /// The DER second ticket of a user-to-user request; empty if none.
    pub second_ticket: Vec<u8>,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("client", &self.client)
            .field("server", &self.server)
            .field("enctype", &self.enctype)
            .field("key", &"<redacted>")
            .field("authtime", &self.authtime)
            .field("starttime", &self.starttime)
            .field("endtime", &self.endtime)
            .field("renew_till", &self.renew_till)
            .field("flags", &format_args!("{:#010x}", self.flags))
            .finish_non_exhaustive()
    }
}

impl Entry {
    /// A configuration entry (`X-CACHECONF:` server realm). Its "ticket"
    /// is the value and its times are zero, which does not make it
    /// expired.
    pub fn is_config(&self) -> bool {
        self.server.realm == CONF_REALM
    }

    /// MIT's `cred_removed`: `krb5_cc_remove_cred` zeroes the endtime of
    /// an entry in place. Config entries also have endtime 0, but authtime
    /// 0 as well, which is how MIT tells them apart.
    pub fn is_removed(&self) -> bool {
        self.endtime == 0 && self.authtime != 0
    }

    /// The entry as [`Credentials`], or `None` for a config entry, a
    /// removed entry, a non-AES session key, or a ticket that does not
    /// parse.
    pub fn credentials(&self) -> Option<Credentials> {
        if self.is_config() || self.is_removed() {
            return None;
        }
        let session_key = Key::new(self.enctype, self.key.clone()).ok()?;
        let ticket_enctype = ticket_enctype(&self.ticket)?;
        let opt = |t: u32| (t != 0).then_some(i64::from(t));
        Some(Credentials {
            client: self.client.clone(),
            server: self.server.clone(),
            session_key,
            ticket: self.ticket.clone(),
            ticket_enctype,
            flags: self.flags,
            authtime: i64::from(self.authtime),
            starttime: opt(self.starttime),
            endtime: i64::from(self.endtime),
            renew_till: opt(self.renew_till),
        })
    }

    /// The record MIT would store for `creds`. As in MIT's `get_in_tkt`,
    /// an absent starttime is stored as the authtime.
    pub fn from_credentials(creds: &Credentials) -> Self {
        Entry {
            client: creds.client.clone(),
            server: creds.server.clone(),
            enctype: creds.session_key.enctype(),
            key: creds.session_key.bytes().to_vec(),
            authtime: to_u32(creds.authtime),
            starttime: to_u32(creds.starttime.unwrap_or(creds.authtime)),
            endtime: to_u32(creds.endtime),
            renew_till: creds.renew_till.map_or(0, to_u32),
            is_skey: false,
            flags: creds.flags,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: creds.ticket.clone(),
            second_ticket: Vec::new(),
        }
    }
}

/// The file stores 32-bit unsigned seconds (good until 2106, as in MIT,
/// which reads `krb5_timestamp` as unsigned). Out-of-range times clamp
/// rather than wrap, so a far-future endtime cannot become 1970.
fn to_u32(t: i64) -> u32 {
    t.clamp(0, i64::from(u32::MAX)) as u32
}

/// The enctype of a DER `Ticket`'s enc-part.
fn ticket_enctype(ticket: &[u8]) -> Option<i32> {
    let f = Fields::parse_tagged("Ticket", app(1), ticket).ok()?;
    decode_encrypted_data(f.get(3).ok()?)
        .ok()
        .map(|(etype, _)| etype)
}

/// Principal equality as MIT's `krb5_principal_compare`: realm and
/// components, ignoring the name type.
pub fn same_principal(a: &Principal, b: &Principal) -> bool {
    a.realm == b.realm && a.components == b.components
}

// ------------------------------------------------------------------ caches

/// The contents of one `FILE:` credential cache.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CCache {
    /// The default principal: whose tickets these are.
    pub principal: Principal,
    /// Version-4 header fields, `(tag, value)`, kept for a rewrite. Tag 1
    /// is the KDC time offset; see [`CCache::time_offset`].
    pub header: Vec<(u16, Vec<u8>)>,
    /// The credentials and configuration entries, in file order.
    pub entries: Vec<Entry>,
}

impl fmt::Debug for CCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CCache")
            .field("principal", &self.principal)
            .field("header", &self.header)
            .field("entries", &self.entries)
            .finish()
    }
}

impl CCache {
    /// A new cache holding `creds` for its client, as `kinit` writes one
    /// after logging in. Write it with [`CCache::write`] or
    /// [`CacheName::write`].
    pub fn with_credentials(creds: &Credentials) -> Self {
        let mut cc = CCache::new(creds.client.clone());
        cc.store(creds);
        cc
    }

    /// An empty cache for `principal`.
    pub fn new(principal: Principal) -> Self {
        CCache {
            principal,
            header: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// The KDC's clock minus ours, `(seconds, microseconds)`, if MIT
    /// recorded one at login.
    pub fn time_offset(&self) -> Option<(i32, i32)> {
        let (_, v) = self
            .header
            .iter()
            .find(|(t, v)| *t == TAG_DELTATIME && v.len() == 8)?;
        let s = i32::from_be_bytes(v[..4].try_into().unwrap());
        let us = i32::from_be_bytes(v[4..].try_into().unwrap());
        Some((s, us))
    }

    /// Parse a cache file's bytes (format versions 1 to 4).
    pub fn decode(data: &[u8]) -> std::result::Result<Self, String> {
        let mut r = In { data, version: 4 };
        let fvno = r.u16_be()?;
        if !(FVNO_BASE + 1..=FVNO_BASE + 4).contains(&fvno) {
            return Err(format!("unknown format version {fvno:#06x}"));
        }
        r.version = fvno - FVNO_BASE;

        let mut header = Vec::new();
        if r.version == 4 {
            let len = r.u16()? as usize;
            let mut fields = r.take(len)?;
            while !fields.is_empty() {
                let mut f = In {
                    data: fields,
                    version: 4,
                };
                let tag = f.u16()?;
                let len = f.u16()? as usize;
                header.push((tag, f.take(len)?.to_vec()));
                fields = f.data;
            }
        }
        let principal = r.principal()?;

        let mut entries = Vec::new();
        while !r.data.is_empty() {
            // A credential cut short is an append in progress: MIT reads
            // KRB5_CC_END there, and so do we.
            match r.entry() {
                Ok(e) => entries.push(e),
                Err(Stop::Short) => break,
                Err(bad) => return Err(bad.into()),
            }
        }
        Ok(CCache {
            principal,
            header,
            entries,
        })
    }

    /// Format version 4, big-endian, as MIT writes by default.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(FVNO_BASE + 4).to_be_bytes());
        let fields: Vec<u8> = self
            .header
            .iter()
            .flat_map(|(tag, v)| {
                let mut f = tag.to_be_bytes().to_vec();
                f.extend_from_slice(&(v.len() as u16).to_be_bytes());
                f.extend_from_slice(v);
                f
            })
            .collect();
        out.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        out.extend_from_slice(&fields);
        put_principal(&mut out, &self.principal);
        for e in &self.entries {
            put_entry(&mut out, e);
        }
        out
    }

    /// Read the cache file at `path`.
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let data = fs::read(path).map_err(|source| CacheError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        CCache::decode(&data).map_err(|msg| CacheError::Format {
            path: path.to_path_buf(),
            msg,
        })
    }

    /// Replace the cache file at `path` with this cache: write a new
    /// `0600` file in the same directory, then rename it into place.
    ///
    /// A symlink at `path` is replaced, never followed, as MIT's
    /// `fcc_initialize` (unlink, then `O_EXCL` create) never follows one.
    /// Following it would let anyone who can plant `/tmp/krb5cc_<uid>` as
    /// a link aim our next write at any file we own. In a sticky `/tmp`,
    /// someone else's link cannot be replaced either, so the write fails.
    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        atomic_write(path, &self.encode()).map_err(|source| CacheError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Every entry usable as [`Credentials`] (see [`Entry::credentials`]).
    pub fn credentials(&self) -> impl Iterator<Item = Credentials> + '_ {
        self.entries.iter().filter_map(Entry::credentials)
    }

    /// The default principal's unexpired credentials for `server`, the
    /// one with the latest endtime if there are several. `now` is Unix
    /// seconds. User-to-user tickets are not candidates, as in MIT's
    /// lookups (`KRB5_TC_MATCH_IS_SKEY`): they are for one server TGT,
    /// not the server's keytab (see [`CCache::find_user_to_user`]).
    pub fn find(&self, server: &Principal, now: i64) -> Option<Credentials> {
        self.find_where(server, now, |e| !e.is_skey)
    }

    /// The default principal's unexpired user-to-user ticket for
    /// `server`, in the session key of `server_tgt` (the server's TGT, as
    /// [`KdcClient::user_to_user`](crate::KdcClient::user_to_user) was
    /// given it): as `kvno --u2u` stores one, matched as MIT matches it
    /// (`KRB5_TC_MATCH_IS_SKEY | KRB5_TC_MATCH_2ND_TKT`).
    pub fn find_user_to_user(
        &self,
        server: &Principal,
        server_tgt: &[u8],
        now: i64,
    ) -> Option<Credentials> {
        self.find_where(server, now, |e| e.is_skey && e.second_ticket == server_tgt)
    }

    fn find_where(
        &self,
        server: &Principal,
        now: i64,
        want: impl Fn(&Entry) -> bool,
    ) -> Option<Credentials> {
        self.entries
            .iter()
            .filter(|e| want(e))
            .filter_map(Entry::credentials)
            .filter(|c| {
                same_principal(&c.client, &self.principal)
                    && same_principal(&c.server, server)
                    && !c.is_expired_at(now)
            })
            .max_by_key(|c| c.endtime)
    }

    /// The default principal's ticket-granting ticket for `realm` (the
    /// `start_realm` config entry, else the principal's own realm), if it
    /// has one that is unexpired at `now`.
    pub fn tgt(&self, now: i64) -> Option<Credentials> {
        let realm = self
            .config("start_realm", None)
            .and_then(|r| std::str::from_utf8(r).ok())
            .unwrap_or(&self.principal.realm)
            .to_string();
        self.find(&Principal::krbtgt(&realm), now)
    }

    /// Store `creds`, replacing any entry for the same client and server.
    /// (MIT appends and lets the newest copy shadow the old one; a
    /// rewrite can simply drop it.) Removed entries are dropped too.
    pub fn store(&mut self, creds: &Credentials) {
        self.store_entry(Entry::from_credentials(creds));
    }

    /// Store `creds`, a user-to-user ticket in the session key of
    /// `server_tgt`, as MIT records one: `is_skey` set, the server's TGT
    /// as the second ticket. Only [`CCache::find_user_to_user`] finds it,
    /// in this crate and in MIT.
    pub fn store_user_to_user(&mut self, creds: &Credentials, server_tgt: &[u8]) {
        let mut e = Entry::from_credentials(creds);
        e.is_skey = true;
        e.second_ticket = server_tgt.to_vec();
        self.store_entry(e);
    }

    /// Replace any entry for the same client and server, of the same kind:
    /// ordinary, or user-to-user for the same server TGT. (Only
    /// user-to-user entries have a second ticket.)
    fn store_entry(&mut self, new: Entry) {
        let replaced = |e: &Entry| {
            same_principal(&e.client, &new.client)
                && same_principal(&e.server, &new.server)
                && e.second_ticket == new.second_ticket
        };
        self.entries.retain(|e| !e.is_removed() && !replaced(e));
        self.entries.push(new);
    }

    /// Set configuration entry `key` (optionally associated with
    /// `principal`) to `value`, replacing any old one, laid out as MIT's
    /// `krb5_cc_set_config` lays it out: client the cache's principal,
    /// server `krb5_ccache_conf_data/key[/principal]@X-CACHECONF:`, the
    /// value as the ticket, everything else zero. New ones go before the
    /// credentials, where MIT's `kinit` puts them.
    pub fn set_config(&mut self, key: &str, principal: Option<&Principal>, value: &[u8]) {
        let mut comps = vec![CONF_NAME.to_string(), key.to_string()];
        if let Some(p) = principal {
            comps.push(p.to_string());
        }
        let server = Principal::new(1, comps, CONF_REALM);
        self.entries
            .retain(|e| !(e.is_config() && e.server.components == server.components));
        let at = self.entries.iter().take_while(|e| e.is_config()).count();
        self.entries.insert(
            at,
            Entry {
                client: self.principal.clone(),
                server,
                enctype: 0,
                key: Vec::new(),
                authtime: 0,
                starttime: 0,
                endtime: 0,
                renew_till: 0,
                is_skey: false,
                flags: 0,
                addresses: Vec::new(),
                authdata: Vec::new(),
                ticket: value.to_vec(),
                second_ticket: Vec::new(),
            },
        );
    }

    /// Whether the KDC of `realm` said it supports FAST when this cache's
    /// TGT was obtained: the `fast_avail` config entry MIT's `kinit`
    /// writes (RFC 6806 §11), associated with `krbtgt/REALM@REALM`.
    pub fn fast_avail(&self, realm: &str) -> bool {
        self.config("fast_avail", Some(&Principal::krbtgt(realm)))
            .is_some_and(|v| !v.is_empty())
    }

    /// The value of configuration entry `key`, optionally associated with
    /// `principal` (e.g. `pa_type` for the krbtgt).
    pub fn config(&self, key: &str, principal: Option<&Principal>) -> Option<&[u8]> {
        let want_assoc = principal.map(|p| p.to_string());
        self.entries
            .iter()
            .find(|e| {
                e.is_config()
                    && e.server.components.first().map(String::as_str) == Some(CONF_NAME)
                    && e.server.components.get(1).map(String::as_str) == Some(key)
                    && e.server.components.get(2) == want_assoc.as_ref()
            })
            .map(|e| e.ticket.as_slice())
    }
}

// ------------------------------------------------------------- marshalling

/// Why unmarshalling stopped.
enum Stop {
    /// Ran out of bytes. Within the credential sequence this is its end.
    Short,
    /// Bytes this crate cannot represent.
    Bad(String),
}

impl From<Stop> for String {
    fn from(s: Stop) -> String {
        match s {
            Stop::Short => "truncated".into(),
            Stop::Bad(msg) => msg,
        }
    }
}

type R<T> = std::result::Result<T, Stop>;

struct In<'a> {
    data: &'a [u8],
    version: u16,
}

impl<'a> In<'a> {
    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        if self.data.len() < n {
            return Err(Stop::Short);
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    fn u16_be(&mut self) -> R<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    /// Versions 1 and 2 are in the writer's byte order, which MIT reads as
    /// its own; versions 3 and 4 are big-endian.
    fn u16(&mut self) -> R<u16> {
        let b: [u8; 2] = self.take(2)?.try_into().unwrap();
        Ok(if self.version < 3 {
            u16::from_ne_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    fn u32(&mut self) -> R<u32> {
        let b: [u8; 4] = self.take(4)?.try_into().unwrap();
        Ok(if self.version < 3 {
            u32::from_ne_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    fn data(&mut self) -> R<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn string(&mut self) -> R<String> {
        // `Principal` holds Strings. MIT allows any octets, but a
        // non-UTF-8 name is an error here, not a silent end of the cache.
        let b = self.data()?;
        String::from_utf8(b.to_vec())
            .map_err(|_| Stop::Bad(format!("principal name {b:02x?} is not UTF-8")))
    }

    fn principal(&mut self) -> R<Principal> {
        let name_type = if self.version == 1 {
            0
        } else {
            self.u32()? as i32
        };
        let mut count = self.u32()? as usize;
        if self.version == 1 {
            count = count.checked_sub(1).ok_or(Stop::Short)?;
        }
        // Each component needs at least its 4-octet length.
        if count > self.data.len() / 4 {
            return Err(Stop::Short);
        }
        let realm = self.string()?;
        let components = (0..count).map(|_| self.string()).collect::<R<Vec<_>>>()?;
        Ok(Principal::new(name_type, components, realm))
    }

    fn pairs(&mut self) -> R<Vec<(u16, Vec<u8>)>> {
        let count = self.u32()? as usize;
        if count > self.data.len() / 6 {
            return Err(Stop::Short);
        }
        (0..count)
            .map(|_| Ok((self.u16()?, self.data()?.to_vec())))
            .collect()
    }

    fn entry(&mut self) -> R<Entry> {
        let client = self.principal()?;
        let server = self.principal()?;
        let enctype = self.u16()? as i16 as i32;
        if self.version == 3 {
            self.u16()?;
        }
        let key = self.data()?.to_vec();
        Ok(Entry {
            client,
            server,
            enctype,
            key,
            authtime: self.u32()?,
            starttime: self.u32()?,
            endtime: self.u32()?,
            renew_till: self.u32()?,
            is_skey: self.take(1)?[0] != 0,
            flags: self.u32()?,
            addresses: self.pairs()?,
            authdata: self.pairs()?,
            ticket: self.data()?.to_vec(),
            second_ticket: self.data()?.to_vec(),
        })
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_data(out: &mut Vec<u8>, d: &[u8]) {
    put_u32(out, d.len() as u32);
    out.extend_from_slice(d);
}

fn put_principal(out: &mut Vec<u8>, p: &Principal) {
    put_u32(out, p.name_type as u32);
    put_u32(out, p.components.len() as u32);
    put_data(out, p.realm.as_bytes());
    for c in &p.components {
        put_data(out, c.as_bytes());
    }
}

fn put_pairs(out: &mut Vec<u8>, pairs: &[(u16, Vec<u8>)]) {
    put_u32(out, pairs.len() as u32);
    for (t, d) in pairs {
        out.extend_from_slice(&t.to_be_bytes());
        put_data(out, d);
    }
}

fn put_entry(out: &mut Vec<u8>, e: &Entry) {
    put_principal(out, &e.client);
    put_principal(out, &e.server);
    out.extend_from_slice(&(e.enctype as i16 as u16).to_be_bytes());
    put_data(out, &e.key);
    for t in [e.authtime, e.starttime, e.endtime, e.renew_till] {
        put_u32(out, t);
    }
    out.push(u8::from(e.is_skey));
    put_u32(out, e.flags);
    put_pairs(out, &e.addresses);
    put_pairs(out, &e.authdata);
    put_data(out, &e.ticket);
    put_data(out, &e.second_ticket);
}

/// Write `data` to a new `0600` file beside `target`, then rename it over
/// `target`. The temporary name is random and created exclusively, so a
/// planted file or symlink in a shared directory such as `/tmp` is never
/// followed.
fn atomic_write(target: &Path, data: &[u8]) -> io::Result<()> {
    let dir = match target.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = target.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "cache path has no file name")
    })?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(format!(".{:016x}.tmp", rand::random::<u64>()));
    let tmp = dir.join(tmp_name);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let result = opts.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, target)
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

// ------------------------------------------------------------------- names

/// A credential cache name.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheName {
    /// `FILE:path`, or a name with no type prefix.
    File(PathBuf),
    /// `DIR:dir`: a collection whose `primary` file names the cache in use.
    Dir(PathBuf),
    /// `DIR::dir/tktNAME`: one cache within a collection.
    DirMember(PathBuf),
    /// `KCM:name`, or `KCM:` for the daemon's primary cache. `socket` is
    /// `None` when `kcm_socket = -` disables KCM.
    Kcm {
        /// The cache's name in the daemon; empty for its primary cache.
        name: String,
        /// The daemon's socket.
        socket: Option<PathBuf>,
    },
}

impl fmt::Display for CacheName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheName::File(p) => write!(f, "FILE:{}", p.display()),
            CacheName::Dir(p) => write!(f, "DIR:{}", p.display()),
            CacheName::DirMember(p) => write!(f, "DIR::{}", p.display()),
            CacheName::Kcm { name, .. } => write!(f, "KCM:{name}"),
        }
    }
}

impl CacheName {
    /// Parse `TYPE:residual` as MIT's `krb5_cc_resolve` does: no colon
    /// means FILE, and so does a one-letter prefix (a drive letter). A
    /// `KCM:` name uses the default socket; see [`CacheName::parse_with`].
    pub fn parse(name: &str) -> Result<Self> {
        Self::parse_with(name, &Krb5Conf::empty())
    }

    /// [`CacheName::parse`], taking the KCM socket from `conf`'s
    /// `[libdefaults] kcm_socket`.
    pub fn parse_with(name: &str, conf: &Krb5Conf) -> Result<Self> {
        let bad = |why: &str| CacheError::BadName(name.to_string(), why.to_string());
        let (kind, residual) = match name.find(':') {
            None => ("FILE", name),
            Some(1) if name.as_bytes()[0].is_ascii_alphabetic() => ("FILE", name),
            Some(i) => (&name[..i], &name[i + 1..]),
        };
        match kind {
            "FILE" if residual.is_empty() => Err(bad("empty path")),
            "FILE" => Ok(CacheName::File(PathBuf::from(residual))),
            "DIR" => match residual.strip_prefix(':') {
                Some(member) => {
                    let p = PathBuf::from(member);
                    match (p.parent(), p.file_name().and_then(|n| n.to_str())) {
                        (Some(d), Some(n)) if !d.as_os_str().is_empty() && n.starts_with("tkt") => {
                            Ok(CacheName::DirMember(p))
                        }
                        _ => Err(bad("a DIR member must be dir/tkt...")),
                    }
                }
                None if residual.is_empty() => Err(bad("empty directory")),
                None => Ok(CacheName::Dir(PathBuf::from(residual))),
            },
            #[cfg(unix)]
            "KCM" => Ok(CacheName::Kcm {
                name: residual.to_string(),
                socket: kcm::socket_path(conf),
            }),
            other => Err(CacheError::UnsupportedType(other.to_string())),
        }
    }

    /// The name MIT's `krb5_cc_default_name` would use: `KRB5CCNAME`,
    /// else `[libdefaults] default_ccache_name`, else
    /// [`DEFAULT_CCACHE_NAME`], with `%{...}` tokens expanded.
    pub fn default_name(conf: &Krb5Conf) -> Result<String> {
        if let Some(name) = std::env::var_os("KRB5CCNAME") {
            return name
                .into_string()
                .map_err(|n| CacheError::BadName(n.to_string_lossy().into(), "not UTF-8".into()));
        }
        let template = conf
            .get(&["libdefaults", "default_ccache_name"])
            .unwrap_or(DEFAULT_CCACHE_NAME);
        expand_tokens(template)
    }

    /// [`CacheName::parse_with`] of [`CacheName::default_name`].
    pub fn default(conf: &Krb5Conf) -> Result<Self> {
        Self::parse_with(&Self::default_name(conf)?, conf)
    }

    /// This name with any indirection resolved: a `DIR:` collection to
    /// the member its `primary` names, `KCM:` to the daemon's primary
    /// cache. Read and write through the result to be sure both touch
    /// the same cache.
    pub fn resolved(&self) -> Result<Self> {
        match self {
            CacheName::Dir(_) => Ok(CacheName::DirMember(self.path()?)),
            #[cfg(unix)]
            CacheName::Kcm { name, socket } if name.is_empty() => Ok(CacheName::Kcm {
                name: self.kcm()?.default_cache()?,
                socket: socket.clone(),
            }),
            other => Ok(other.clone()),
        }
    }

    #[cfg(unix)]
    fn kcm(&self) -> Result<kcm::Kcm> {
        match self {
            CacheName::Kcm {
                socket: Some(s), ..
            } => kcm::Kcm::connect(s),
            _ => Err(CacheError::KcmUnavailable {
                socket: PathBuf::from("-"),
                source: io::Error::new(io::ErrorKind::NotFound, "KCM disabled by kcm_socket = -"),
            }),
        }
    }

    /// The cache file this name refers to now. For a `DIR:` collection
    /// that is the one its `primary` file names; as in MIT the directory
    /// is created (`0700`) if missing, and a missing `primary` is created
    /// naming `tkt`.
    pub fn path(&self) -> Result<PathBuf> {
        match self {
            CacheName::File(p) | CacheName::DirMember(p) => Ok(p.clone()),
            CacheName::Kcm { .. } => Err(CacheError::NotAFile(self.to_string())),
            CacheName::Dir(dir) => {
                ensure_dir(dir)?;
                let primary = dir.join("primary");
                let io_err = |source| CacheError::Io {
                    path: primary.clone(),
                    source,
                };
                let name = match fs::read_to_string(&primary) {
                    Ok(s) => {
                        let line = s.split_inclusive('\n').next().unwrap_or("");
                        match line.strip_suffix('\n') {
                            Some(n) if n.starts_with("tkt") && !n.contains(['/', '\\']) => {
                                n.to_string()
                            }
                            _ => {
                                return Err(CacheError::Format {
                                    path: primary,
                                    msg: "primary does not name a tkt file".into(),
                                });
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        atomic_write(&primary, b"tkt\n").map_err(io_err)?;
                        "tkt".to_string()
                    }
                    Err(e) => return Err(io_err(e)),
                };
                Ok(dir.join(name))
            }
        }
    }

    /// Make this the collection's primary cache (`kswitch`). Meaningful
    /// for a `DIR::` member or a named `KCM:` cache; others are left alone.
    pub fn make_primary(&self) -> Result<()> {
        #[cfg(unix)]
        if let CacheName::Kcm { name, .. } = self {
            if !name.is_empty() {
                self.kcm()?.set_default_cache(name)?;
            }
            return Ok(());
        }
        if let CacheName::DirMember(p) = self {
            let dir = p.parent().expect("checked in parse");
            ensure_dir(dir)?;
            let name = p.file_name().expect("checked in parse").to_string_lossy();
            let primary = dir.join("primary");
            atomic_write(&primary, format!("{name}\n").as_bytes()).map_err(|source| {
                CacheError::Io {
                    path: primary,
                    source,
                }
            })?;
        }
        Ok(())
    }

    /// Read the cache this name refers to.
    pub fn read(&self) -> Result<CCache> {
        #[cfg(unix)]
        if let CacheName::Kcm { .. } = self {
            let CacheName::Kcm { name, .. } = self.resolved()? else {
                unreachable!()
            };
            return self.kcm()?.read(&name);
        }
        CCache::read(self.path()?)
    }

    /// Replace the cache this name refers to with `cache`.
    pub fn write(&self, cache: &CCache) -> Result<()> {
        #[cfg(unix)]
        if let CacheName::Kcm { .. } = self {
            let CacheName::Kcm { name, .. } = self.resolved()? else {
                unreachable!()
            };
            return self.kcm()?.write(&name, cache);
        }
        cache.write(self.path()?)
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    let io_err = |source| CacheError::Io {
        path: dir.to_path_buf(),
        source,
    };
    match fs::metadata(dir) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(CacheError::Format {
            path: dir.to_path_buf(),
            msg: "exists but is not a directory".into(),
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut b = fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b.create(dir).map_err(io_err)
        }
        Err(e) => Err(io_err(e)),
    }
}

/// MIT's `k5_expand_path_tokens` for the tokens a ccache name uses:
/// `%{uid}`/`%{USERID}` (real uid), `%{euid}`, `%{TEMP}` (`TMPDIR` or
/// `/tmp`) and `%{null}`. Others, such as `%{username}`, are refused
/// rather than left in the path.
pub fn expand_tokens(template: &str) -> Result<String> {
    let bad = |why: String| CacheError::BadName(template.to_string(), why);
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| bad("unterminated %{ token".into()))?;
        let value = match &after[..end] {
            "uid" | "USERID" => uid::real()
                .ok_or_else(|| bad("cannot determine the uid; set KRB5CCNAME".into()))?
                .to_string(),
            "euid" => uid::effective()
                .ok_or_else(|| bad("cannot determine the euid; set KRB5CCNAME".into()))?
                .to_string(),
            "TEMP" => std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()),
            "null" => String::new(),
            other => return Err(bad(format!("unsupported token %{{{other}}}"))),
        };
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The process's uids without libc.
///
/// Linux exposes them in `/proc/self/status` (`Uid: real effective saved
/// fs`). Elsewhere on Unix the owner of a file we create is the effective
/// uid, which is also used for the real uid: the two differ only in a
/// setuid program, which should name its cache with `KRB5CCNAME` anyway.
mod uid {
    #[cfg(target_os = "linux")]
    fn from_proc(field: usize) -> Option<u32> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|l| l.starts_with("Uid:"))?;
        line.split_whitespace().nth(1 + field)?.parse().ok()
    }

    #[cfg(unix)]
    fn from_probe() -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        let p = std::env::temp_dir().join(format!(".krb5-uid-{:016x}", rand::random::<u64>()));
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .ok()?;
        let uid = f.metadata().ok().map(|m| m.uid());
        let _ = std::fs::remove_file(&p);
        uid
    }

    pub fn real() -> Option<u32> {
        #[cfg(target_os = "linux")]
        if let Some(u) = from_proc(0) {
            return Some(u);
        }
        effective()
    }

    #[cfg(unix)]
    pub fn effective() -> Option<u32> {
        #[cfg(target_os = "linux")]
        if let Some(u) = from_proc(1) {
            return Some(u);
        }
        from_probe()
    }

    #[cfg(not(unix))]
    pub fn effective() -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{NT_PRINCIPAL, NT_SRV_HST, NT_SRV_INST};

    /// Caches written by MIT's kinit + kvno in each format version
    /// (`scripts/make-ccache-fixtures.sh`), with klist's view alongside.
    fn fixture(v: u8) -> Vec<u8> {
        fs::read(format!(
            "{}/testdata/ccache/mit-v{v}.ccache",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn klist(v: u8) -> String {
        fs::read_to_string(format!(
            "{}/testdata/ccache/mit-v{v}.klist",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn alice() -> Principal {
        Principal::new(NT_PRINCIPAL, ["alice"], "KRB5.TEST")
    }

    fn svc() -> Principal {
        Principal::new(NT_SRV_HST, ["svc18", "svc.krb5.test"], "KRB5.TEST")
    }

    // TicketFlags, bit 0 = MSB: forwardable 1, renewable 8, initial 9,
    // pre-authent 10, transited-policy-checked 12, enc-pa-rep 15.
    const F: u32 = 1 << 30;
    const R: u32 = 1 << 23;
    const I: u32 = 1 << 22;
    const A: u32 = 1 << 21;
    const T: u32 = 1 << 19;
    const E: u32 = 1 << 16;

    /// A user-to-user ticket and an ordinary one for the same server side
    /// by side, as MIT keeps them: each lookup finds its own, and the
    /// marking survives the file.
    #[test]
    fn user_to_user_tickets_are_kept_apart() {
        let mut c = CCache::decode(&fixture(4)).unwrap();
        let creds: Vec<Credentials> = c.credentials().collect();
        let (tgt, svc) = (&creds[0], &creds[1]);
        let now = svc.authtime;
        let mut u2u = svc.clone();
        u2u.session_key = Key::random(18).unwrap();
        c.store_user_to_user(&u2u, &tgt.ticket);
        let c = CCache::decode(&c.encode()).unwrap();
        let e = c.entries.iter().find(|e| e.is_skey).unwrap();
        assert_eq!(e.second_ticket, tgt.ticket);
        assert_eq!(c.credentials().count(), 3);

        let found = c.find(&svc.server, now).unwrap();
        assert_eq!(found.session_key, svc.session_key);
        let found = c.find_user_to_user(&svc.server, &tgt.ticket, now).unwrap();
        assert_eq!(found.session_key, u2u.session_key);
        assert!(c.find_user_to_user(&svc.server, &svc.ticket, now).is_none());

        // Storing either again replaces only its own kind.
        let mut c = c;
        c.store(svc);
        c.store_user_to_user(&u2u, &tgt.ticket);
        assert_eq!(c.credentials().count(), 3);
    }

    #[test]
    fn mit_caches_of_every_version_read_as_klist_shows_them() {
        for v in 1..=4 {
            let c = CCache::decode(&fixture(v)).unwrap();
            let shown = klist(v);
            assert!(shown.contains("Default principal: alice@KRB5.TEST"), "v{v}");
            assert!(same_principal(&c.principal, &alice()), "v{v}");
            assert_eq!(
                c.principal.name_type,
                if v == 1 { 0 } else { NT_PRINCIPAL },
                "v{v}"
            );

            // klist lists exactly the non-config entries.
            let creds: Vec<Credentials> = c.credentials().collect();
            assert_eq!(creds.len(), 2, "v{v}");
            assert_eq!(
                c.entries.iter().filter(|e| e.is_config()).count(),
                2,
                "v{v}"
            );

            let tgt = &creds[0];
            assert!(
                same_principal(&tgt.server, &Principal::krbtgt("KRB5.TEST")),
                "v{v}"
            );
            // klist has no letter for enc-pa-rep (RFC 6806 §11), which
            // MIT's KDC sets on both tickets.
            assert_eq!(tgt.flags, F | R | I | A | E, "v{v}: klist says FRIA");
            let st = &creds[1];
            assert!(same_principal(&st.server, &svc()), "v{v}");
            assert_eq!(st.flags, F | R | A | T | E, "v{v}: klist says FRAT");
            for cr in &creds {
                // "Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96"
                assert_eq!(cr.session_key.enctype(), 18, "v{v}");
                assert_eq!(cr.ticket_enctype, 18, "v{v}");
                assert_eq!(cr.endtime - cr.starttime.unwrap(), 24 * 3600, "v{v}");
                assert!(same_principal(&cr.client, &alice()), "v{v}");
            }
        }
    }

    #[test]
    fn mit_config_entries_are_found_and_not_credentials() {
        let c = CCache::decode(&fixture(4)).unwrap();
        let krbtgt = Principal::krbtgt("KRB5.TEST");
        assert_eq!(c.config("fast_avail", Some(&krbtgt)), Some(&b"yes"[..]));
        assert_eq!(c.config("pa_type", Some(&krbtgt)), Some(&b"2"[..])); // PA-ENC-TIMESTAMP
        assert_eq!(c.config("pa_type", None), None);
        assert_eq!(c.config("nope", Some(&krbtgt)), None);
        for e in c.entries.iter().filter(|e| e.is_config()) {
            assert!(!e.is_removed());
            assert!(e.credentials().is_none());
        }
    }

    #[test]
    fn the_mit_time_offset_header_is_read() {
        let c = CCache::decode(&fixture(4)).unwrap();
        // kinit against a KDC on the same clock: offset recorded, and zero.
        assert_eq!(c.time_offset(), Some((0, 0)));
        assert_eq!(CCache::decode(&fixture(3)).unwrap().time_offset(), None);
    }

    /// The strongest check on the writer: re-encoding MIT's own v4 file
    /// reproduces it octet for octet, config entries and header included.
    #[test]
    fn a_mit_v4_cache_re_encodes_byte_for_byte() {
        let mit = fixture(4);
        assert_eq!(CCache::decode(&mit).unwrap().encode(), mit);
    }

    #[test]
    fn older_versions_are_rewritten_as_v4_with_the_same_contents() {
        for v in 1..=3 {
            let c = CCache::decode(&fixture(v)).unwrap();
            let out = c.encode();
            assert_eq!(&out[..2], &[0x05, 0x04], "v{v}");
            assert_eq!(CCache::decode(&out).unwrap(), c, "v{v}");
        }
    }

    #[test]
    fn find_and_tgt_respect_expiry() {
        let c = CCache::decode(&fixture(4)).unwrap();
        let tgt = c.tgt(0).unwrap();
        let end = tgt.endtime;
        assert!(same_principal(&tgt.server, &Principal::krbtgt("KRB5.TEST")));
        assert!(c.tgt(end - 1).is_some());
        assert!(c.tgt(end).is_none());
        assert!(c.find(&svc(), end - 1).is_some());
        // Name type does not matter for a match, as in krb5_principal_compare.
        let other_type = Principal::new(NT_SRV_INST, ["svc18", "svc.krb5.test"], "KRB5.TEST");
        assert!(c.find(&other_type, 0).is_some());
        assert!(
            c.find(&Principal::new(NT_SRV_HST, ["nope"], "KRB5.TEST"), 0)
                .is_none()
        );
    }

    #[test]
    fn a_start_realm_config_entry_picks_the_tgt_realm() {
        let mut c = CCache::decode(&fixture(4)).unwrap();
        let mut conf = c.entries.iter().find(|e| e.is_config()).unwrap().clone();
        conf.server = Principal::new(0, [CONF_NAME, "start_realm"], CONF_REALM);
        conf.ticket = b"OTHER.REALM".to_vec();
        c.entries.push(conf);
        assert!(
            c.tgt(0).is_none(),
            "the TGT is for KRB5.TEST, not OTHER.REALM"
        );
    }

    #[test]
    fn store_replaces_the_same_service_and_keeps_everything_else() {
        let mut c = CCache::decode(&fixture(4)).unwrap();
        let before = c.entries.len();
        let mut st = c.find(&svc(), 0).unwrap();
        st.endtime += 3600;
        c.store(&st);
        assert_eq!(c.entries.len(), before, "replaced, not appended");
        assert_eq!(c.find(&svc(), 0).unwrap().endtime, st.endtime);
        assert_eq!(c.entries.iter().filter(|e| e.is_config()).count(), 2);

        let mut other = st.clone();
        other.server = Principal::new(NT_SRV_HST, ["host", "x.krb5.test"], "KRB5.TEST");
        c.store(&other);
        assert_eq!(c.entries.len(), before + 1);
    }

    #[test]
    fn credentials_round_trip_through_an_entry() {
        let c = CCache::decode(&fixture(4)).unwrap();
        for cr in c.credentials() {
            let back = Entry::from_credentials(&cr).credentials().unwrap();
            assert_eq!(back.server, cr.server);
            assert_eq!(back.session_key, cr.session_key);
            assert_eq!(back.ticket, cr.ticket);
            assert_eq!(
                (
                    back.authtime,
                    back.starttime,
                    back.endtime,
                    back.renew_till,
                    back.flags
                ),
                (
                    cr.authtime,
                    cr.starttime,
                    cr.endtime,
                    cr.renew_till,
                    cr.flags
                )
            );
        }
    }

    #[test]
    fn a_missing_starttime_is_stored_as_the_authtime() {
        let mut cr = CCache::decode(&fixture(4)).unwrap().tgt(0).unwrap();
        cr.starttime = None;
        cr.renew_till = None;
        let e = Entry::from_credentials(&cr);
        assert_eq!(e.starttime, e.authtime);
        assert_eq!(e.renew_till, 0);
        assert_eq!(e.credentials().unwrap().renew_till, None);
    }

    #[test]
    fn times_clamp_to_the_32_bit_field() {
        assert_eq!(to_u32(-5), 0);
        assert_eq!(to_u32(1 << 40), u32::MAX);
        assert_eq!(to_u32(1_800_000_000), 1_800_000_000);
    }

    #[test]
    fn removed_entries_are_skipped_and_dropped_on_store() {
        let mut c = CCache::decode(&fixture(4)).unwrap();
        let i = c
            .entries
            .iter()
            .position(|e| e.server.components[0] == "svc18")
            .unwrap();
        c.entries[i].endtime = 0; // what krb5_cc_remove_cred does in place
        assert!(c.entries[i].is_removed());
        assert!(c.find(&svc(), 0).is_none());
        assert_eq!(c.credentials().count(), 1);
        let tgt = c.tgt(0).unwrap();
        c.store(&tgt);
        assert!(!c.entries.iter().any(Entry::is_removed));
    }

    #[test]
    fn a_truncated_last_credential_is_the_end_of_the_cache() {
        let mit = fixture(4);
        let whole = CCache::decode(&mit).unwrap();
        for cut in [1, 10, 100, 500] {
            let c = CCache::decode(&mit[..mit.len() - cut]).unwrap();
            assert_eq!(
                c.entries[..],
                whole.entries[..whole.entries.len() - 1],
                "cut {cut}"
            );
        }
    }

    #[test]
    fn a_bad_header_is_an_error_not_an_empty_cache() {
        assert!(CCache::decode(&[]).is_err());
        assert!(
            CCache::decode(&[0x05, 0x05, 0, 0])
                .unwrap_err()
                .contains("version")
        );
        assert!(CCache::decode(&[0x04, 0x04]).is_err());
        let mit = fixture(4);
        assert!(
            CCache::decode(&mit[..20]).is_err(),
            "cut inside the default principal"
        );
    }

    #[test]
    fn a_huge_count_is_refused_without_allocating() {
        // v4, empty header, principal with 2^32-1 components.
        let mut d = vec![0x05, 0x04, 0, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff];
        d.extend_from_slice(&[0; 16]);
        assert!(CCache::decode(&d).is_err());
    }

    #[test]
    fn a_non_utf8_name_is_an_error() {
        let mut c = CCache::new(alice());
        let mut e = Entry::from_credentials(&CCache::decode(&fixture(4)).unwrap().tgt(0).unwrap());
        e.server.components[0] = "\u{FFFF}".into();
        c.entries.push(e);
        let mut bytes = c.encode();
        let i = bytes
            .windows(3)
            .position(|w| w == "\u{FFFF}".as_bytes())
            .unwrap();
        bytes[i] = 0xFF;
        assert!(CCache::decode(&bytes).unwrap_err().contains("not UTF-8"));
    }

    #[test]
    fn debug_output_redacts_keys() {
        let c = CCache::decode(&fixture(4)).unwrap();
        let tgt = c.entries.iter().find(|e| !e.is_config()).unwrap();
        let hex: String = tgt.key.iter().map(|b| format!("{b:02x}")).collect();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(&hex) && !dbg.contains(&format!("{:?}", tgt.key)));
    }

    // ------------------------------------------------------------ files

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let d =
                std::env::temp_dir().join(format!("krb5-cc-{tag}-{:016x}", rand::random::<u64>()));
            fs::create_dir_all(&d).unwrap();
            TempDir(d)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn write_then_read_round_trips_with_0600_and_no_leftovers() {
        let t = TempDir::new("rw");
        let p = t.0.join("cc");
        let c = CCache::decode(&fixture(4)).unwrap();
        c.write(&p).unwrap();
        assert_eq!(CCache::read(&p).unwrap(), c);
        assert_eq!(fs::read(&p).unwrap(), fixture(4));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Rewriting replaces the file; the temporary is gone.
        CCache::new(alice()).write(&p).unwrap();
        assert!(CCache::read(&p).unwrap().entries.is_empty());
        assert_eq!(fs::read_dir(&t.0).unwrap().count(), 1);
    }

    /// A planted `/tmp/krb5cc_<uid> -> ~/.bashrc` must not get the
    /// victim's file overwritten: the link itself is replaced.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_cache_path_is_replaced_not_followed() {
        let t = TempDir::new("link");
        let victim = t.0.join("victim");
        let link = t.0.join("krb5cc_link");
        fs::write(&victim, b"precious").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        CCache::decode(&fixture(4)).unwrap().write(&link).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_file());
        assert_eq!(fs::read(&link).unwrap(), fixture(4));
    }

    #[test]
    fn reading_a_missing_cache_is_an_io_error() {
        let t = TempDir::new("missing");
        let e = CCache::read(t.0.join("nope")).unwrap_err();
        assert!(
            matches!(e, CacheError::Io { ref source, .. } if source.kind() == io::ErrorKind::NotFound)
        );
    }

    // ------------------------------------------------------------ names

    #[test]
    fn names_parse_as_krb5_cc_resolve_does() {
        let p = |s: &str| CacheName::parse(s).unwrap();
        assert_eq!(p("FILE:/tmp/cc"), CacheName::File("/tmp/cc".into()));
        assert_eq!(p("/tmp/cc"), CacheName::File("/tmp/cc".into()));
        assert_eq!(p("C:\\cc"), CacheName::File("C:\\cc".into()));
        assert_eq!(
            p("FILE:rel:with:colons"),
            CacheName::File("rel:with:colons".into())
        );
        assert_eq!(p("DIR:/run/cc"), CacheName::Dir("/run/cc".into()));
        assert_eq!(
            p("DIR::/run/cc/tktabc"),
            CacheName::DirMember("/run/cc/tktabc".into())
        );
        #[cfg(unix)]
        {
            let k = |name: &str, sock: Option<&str>| CacheName::Kcm {
                name: name.into(),
                socket: sock.map(PathBuf::from),
            };
            assert_eq!(p("KCM:"), k("", Some(kcm::DEFAULT_KCM_SOCKET)));
            assert_eq!(
                p("KCM:1000:abc"),
                k("1000:abc", Some(kcm::DEFAULT_KCM_SOCKET))
            );
            assert_eq!(p("KCM:1000").to_string(), "KCM:1000");
            let conf =
                |v: &str| Krb5Conf::parse(&format!("[libdefaults]\n kcm_socket = {v}\n")).unwrap();
            assert_eq!(
                CacheName::parse_with("KCM:", &conf("/run/kcm.sock")).unwrap(),
                k("", Some("/run/kcm.sock"))
            );
            assert_eq!(
                CacheName::parse_with("KCM:", &conf("-")).unwrap(),
                k("", None)
            );
            assert!(matches!(p("KCM:x").path(), Err(CacheError::NotAFile(_))));
        }
        for name in [
            "KEYRING:persistent:1000",
            "API:x",
            "MEMORY:x",
            "file:/tmp/x",
        ] {
            assert!(
                matches!(CacheName::parse(name), Err(CacheError::UnsupportedType(_))),
                "{name}"
            );
        }
        for name in ["FILE:", "DIR:", "DIR::/run/cc/notkt", "DIR::tktabc"] {
            assert!(
                matches!(CacheName::parse(name), Err(CacheError::BadName(..))),
                "{name}"
            );
        }
        assert_eq!(p("DIR::/run/cc/tktabc").to_string(), "DIR::/run/cc/tktabc");
    }

    #[test]
    fn tokens_expand_as_mit_does() {
        let uid = uid::real().unwrap();
        assert_eq!(
            expand_tokens("FILE:/tmp/krb5cc_%{uid}").unwrap(),
            format!("FILE:/tmp/krb5cc_{uid}")
        );
        assert_eq!(
            expand_tokens("%{USERID}-%{null}x").unwrap(),
            format!("{uid}-x")
        );
        assert_eq!(
            expand_tokens("%{euid}").unwrap(),
            uid::effective().unwrap().to_string()
        );
        assert_eq!(expand_tokens("plain").unwrap(), "plain");
        assert!(expand_tokens("%{username}").is_err());
        assert!(expand_tokens("%{uid").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_uid_is_ours() {
        use std::os::unix::fs::MetadataExt;
        let t = TempDir::new("uid");
        let p = t.0.join("f");
        fs::write(&p, b"").unwrap();
        assert_eq!(uid::effective(), Some(fs::metadata(&p).unwrap().uid()));
    }

    #[test]
    fn the_configured_default_is_used_when_krb5ccname_is_unset() {
        if std::env::var_os("KRB5CCNAME").is_some() {
            eprintln!("KRB5CCNAME is set; skipping");
            return;
        }
        let conf =
            Krb5Conf::parse("[libdefaults]\n default_ccache_name = DIR:%{TEMP}/x\n").unwrap();
        let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        assert_eq!(
            CacheName::default_name(&conf).unwrap(),
            format!("DIR:{tmp}/x")
        );
        let uid = uid::real().unwrap();
        assert_eq!(
            CacheName::default(&Krb5Conf::empty()).unwrap(),
            CacheName::File(format!("/tmp/krb5cc_{uid}").into())
        );
    }

    #[test]
    fn a_dir_collection_creates_its_primary_and_follows_it() {
        let t = TempDir::new("dir");
        let dir = t.0.join("coll");
        let name = CacheName::Dir(dir.clone());
        // Created on first use, as MIT's verify_dir and dcc_resolve do.
        assert_eq!(name.path().unwrap(), dir.join("tkt"));
        assert_eq!(fs::read_to_string(dir.join("primary")).unwrap(), "tkt\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }

        let member = CacheName::DirMember(dir.join("tktwork"));
        member.write(&CCache::decode(&fixture(4)).unwrap()).unwrap();
        member.make_primary().unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("primary")).unwrap(),
            "tktwork\n"
        );
        assert_eq!(name.path().unwrap(), dir.join("tktwork"));
        assert_eq!(
            name.read().unwrap().principal,
            CCache::decode(&fixture(4)).unwrap().principal
        );
    }

    #[test]
    fn a_bad_primary_file_is_an_error() {
        let t = TempDir::new("badprimary");
        for content in ["notkt\n", "tkt/../x\n", "tkt"] {
            fs::write(t.0.join("primary"), content).unwrap();
            assert!(
                matches!(
                    CacheName::Dir(t.0.clone()).path(),
                    Err(CacheError::Format { .. })
                ),
                "{content:?}"
            );
        }
    }

    #[test]
    fn a_dir_collection_on_a_file_is_an_error() {
        let t = TempDir::new("notdir");
        let f = t.0.join("file");
        fs::write(&f, b"").unwrap();
        assert!(matches!(
            CacheName::Dir(f).path(),
            Err(CacheError::Format { .. })
        ));
    }
}
