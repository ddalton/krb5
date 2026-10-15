//! `krb5.conf`: the MIT profile format, and the lookups a client needs from
//! it — the default realm, a realm's KDCs, and the realm of a host.
//!
//! The parser follows MIT's `prof_parse.c` rather than the prose in
//! krb5.conf(5), because the two disagree at the edges and real files are
//! written against the implementation:
//!
//! * Lines before the first `[section]` are ignored, as are lines starting
//!   with `#` or `;` after optional whitespace. There are no trailing
//!   comments: `kdc = a.example.com # primary` has the value
//!   `a.example.com # primary`.
//! * A value is the rest of the line with surrounding whitespace removed,
//!   or a `"quoted string"` with `\n`, `\t`, `\b` and `\\` escapes, in which
//!   case anything after the closing quote is ignored.
//! * `tag = {` opens a subsection, and so does `tag =` with the `{` on the
//!   next line. Same-named sections and subsections merge.
//! * `include FILE` and `includedir DIR` must start at column 0. Included
//!   files are syntactically independent of their parent. `includedir`
//!   reads, in sorted order, the files whose names are alphanumerics, `-`
//!   and `_`, or end in `.conf` without starting with `.`.
//! * `*` after a section's `]`, after a subsection's tag or `}`, or after a
//!   relation's tag marks it *final*: later occurrences of the same section
//!   or relation are ignored (MIT 1.22 semantics).
//! * `module` directives are refused: this crate cannot load MIT plugins.
//!
//! Multiple files (`KRB5_CONFIG=a:b`) read as one profile in order, so for
//! a single-valued setting the first file wins.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The default when `KRB5_CONFIG` is unset, as in MIT krb5.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/krb5.conf";

/// Deeper than any real configuration nests, shallow enough to stop an
/// include cycle long before it exhausts the stack.
const MAX_INCLUDE_DEPTH: usize = 16;

/// A `krb5.conf` that could not be read or used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
    /// A syntax error, with MIT's error name where it has one.
    #[error("{}line {line}: {msg}", origin(path))]
    Syntax {
        path: Option<PathBuf>,
        line: usize,
        msg: String,
    },
    #[error("[realms] {realm} has no usable kdc entry{}", if skipped.is_empty() { String::new() } else { format!(" (unsupported: {})", skipped.join(", ")) })]
    NoKdcs { realm: String, skipped: Vec<String> },
    #[error("[realms] {realm}: bad kdc entry {entry:?}")]
    BadKdc { realm: String, entry: String },
    /// Neither krb5.conf nor DNS (`_kerberos` URI, `_kerberos._tcp` /
    /// `_udp` SRV) names a KDC for the realm.
    #[error("no KDC for {realm} in krb5.conf{}", if *dns { " or DNS" } else { " (DNS lookup is off: dns_lookup_kdc)" })]
    NoKdcFound { realm: String, dns: bool },
    /// The DNS lookup itself failed (no nameserver answered).
    #[error("looking up the KDCs for {realm} in DNS: {source}")]
    Dns {
        realm: String,
        source: std::io::Error,
    },
    /// A `[libdefaults]` value that does not parse or leaves nothing usable.
    #[error("[libdefaults] {tag} = {value:?}: {why}")]
    BadValue {
        tag: String,
        value: String,
        why: String,
    },
}

fn origin(path: &Option<PathBuf>) -> String {
    path.as_ref()
        .map(|p| format!("{}: ", p.display()))
        .unwrap_or_default()
}

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Relation(String),
    Section(Vec<Node>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    name: String,
    value: Value,
    is_final: bool,
}

/// A parsed `krb5.conf` (one or more files read as one profile).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Krb5Conf {
    root: Vec<Node>,
}

impl Krb5Conf {
    /// An empty profile: every lookup comes back empty.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse one file's text. `include` paths are resolved as written.
    pub fn parse(text: &str) -> Result<Self> {
        let mut conf = Krb5Conf::default();
        parse_into(&mut conf.root, text, None, 0)?;
        Ok(conf)
    }

    /// The profile MIT would read: the colon-separated `KRB5_CONFIG` list
    /// if it is set, else `/etc/krb5.conf`. See [`Krb5Conf::load`].
    pub fn load_default() -> Result<Self> {
        match std::env::var_os("KRB5_CONFIG") {
            Some(list) => Self::load(std::env::split_paths(&list)),
            None => Self::load([DEFAULT_CONFIG_PATH]),
        }
    }

    /// Read `paths` in order as one profile. A directory contributes the
    /// files `includedir` would read.
    ///
    /// As in MIT, files that do not exist are skipped, and so are
    /// unreadable ones as long as some file was read. If none exists the
    /// profile is empty, which is what lets a client run with no krb5.conf
    /// at all. If files exist but none could be read, the first
    /// permission error is returned.
    pub fn load<I, P>(paths: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut conf = Krb5Conf::default();
        let mut read_any = false;
        let mut denied = None;
        for path in paths {
            let path = path.as_ref();
            let files = if path.is_dir() {
                dir_files(path)?
            } else {
                vec![path.to_path_buf()]
            };
            for file in files {
                match fs::read_to_string(&file) {
                    Ok(text) => {
                        parse_into(&mut conf.root, &text, Some(&file), 0)?;
                        read_any = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                        denied.get_or_insert(ConfigError::Io {
                            path: file,
                            source: e,
                        });
                    }
                    Err(e) => {
                        return Err(ConfigError::Io {
                            path: file,
                            source: e,
                        });
                    }
                }
            }
        }
        match denied {
            Some(e) if !read_any => Err(e),
            _ => Ok(conf),
        }
    }

    /// The first value at `path`, e.g. `["libdefaults", "default_realm"]`.
    pub fn get(&self, path: &[&str]) -> Option<&str> {
        self.get_all(path).into_iter().next()
    }

    /// Every value at `path`, in file order, e.g.
    /// `["realms", "EXAMPLE.COM", "kdc"]`.
    pub fn get_all(&self, path: &[&str]) -> Vec<&str> {
        let Some((last, parents)) = path.split_last() else {
            return Vec::new();
        };
        let mut section = &self.root;
        for name in parents {
            match section.iter().find_map(|n| match &n.value {
                Value::Section(children) if n.name == *name => Some(children),
                _ => None,
            }) {
                Some(children) => section = children,
                None => return Vec::new(),
            }
        }
        section
            .iter()
            .filter_map(|n| match &n.value {
                Value::Relation(v) if n.name == *last => Some(v.as_str()),
                _ => None,
            })
            .collect()
    }

    /// `[libdefaults] default_realm`.
    pub fn default_realm(&self) -> Option<&str> {
        self.get(&["libdefaults", "default_realm"])
    }

    /// `[realms] REALM kdc`, as `host:port` / `[v6]:port` addresses for
    /// [`KdcClient::new`](crate::KdcClient::new), in file order.
    ///
    /// Entries are parsed as MIT's `k5_parse_host_string` does: `host`,
    /// `host:port` or `[v6addr]:port`, default port 88. MS-KKDCP
    /// (`https://...`) and Unix-socket (`/path`) entries are skipped, since
    /// this crate speaks only TCP; if nothing usable is left the error
    /// says what was skipped. An entry MIT would reject is an error here
    /// too, rather than silently shortening the list.
    pub fn kdcs(&self, realm: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut skipped = Vec::new();
        for entry in self.get_all(&["realms", realm, "kdc"]) {
            if entry.starts_with("https://") || entry.starts_with('/') {
                skipped.push(entry.to_string());
                continue;
            }
            let addr = parse_host_string(entry, 88).ok_or_else(|| ConfigError::BadKdc {
                realm: realm.to_string(),
                entry: entry.to_string(),
            })?;
            out.push(addr);
        }
        if out.is_empty() {
            return Err(ConfigError::NoKdcs {
                realm: realm.to_string(),
                skipped,
            });
        }
        Ok(out)
    }

    /// The realm `[domain_realm]` maps `host` to, as MIT's
    /// `profile_host_realm` finds it: try the host, then each shorter
    /// suffix with and without its leading dot. For `a.b.c` that is
    /// `a.b.c`, `.b.c`, `b.c`, `.c`, `c`; the first match wins.
    ///
    /// The host is compared in lower case, as MIT canonicalizes it before
    /// the lookup. IP addresses are never looked up. `None` means no
    /// mapping; MIT then falls back to the default realm or DNS.
    pub fn host_realm(&self, host: &str) -> Option<&str> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let mut p = host.as_str();
        loop {
            if let Some(realm) = self.get(&["domain_realm", p]) {
                return Some(realm);
            }
            p = match p.strip_prefix('.') {
                Some(rest) => rest,
                None => &p[p.find('.')?..],
            };
        }
    }
}

/// What `[libdefaults]` says about the tickets a client asks for, for one
/// realm (see [`Krb5Conf::client_defaults`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDefaults {
    /// Enctypes for initial tickets (`default_tkt_enctypes`), AES only.
    pub tkt_enctypes: Vec<i32>,
    /// Enctypes for service tickets (`default_tgs_enctypes`), AES only.
    pub tgs_enctypes: Vec<i32>,
    /// `ticket_lifetime`, default one day.
    pub ticket_lifetime: std::time::Duration,
    /// `renew_lifetime`; `None` (the default, or zero) asks for no
    /// renewable ticket.
    pub renew_lifetime: Option<std::time::Duration>,
    /// `forwardable`, default false.
    pub forwardable: bool,
    /// `proxiable`, default false.
    pub proxiable: bool,
    /// `udp_preference_limit`: requests up to this many octets go over UDP
    /// first. Default 1465; a negative value means the default, and more
    /// than 32700 means 32700, as in MIT. Not realm-specific.
    pub udp_preference_limit: usize,
}

impl Krb5Conf {
    /// MIT's `krb5int_libdefault_string`: `[libdefaults] REALM = { tag }`
    /// first, then `[libdefaults] tag`.
    pub fn libdefault(&self, realm: &str, tag: &str) -> Option<&str> {
        self.get(&["libdefaults", realm, tag])
            .or_else(|| self.get(&["libdefaults", tag]))
    }

    /// The settings MIT's `krb5_get_init_creds` and `krb5_get_credentials`
    /// read for a client of `realm`:
    ///
    /// * `default_tkt_enctypes` / `default_tgs_enctypes`, each falling back
    ///   to `permitted_enctypes` and then `DEFAULT`, in MIT's enctype-list
    ///   syntax (see [`parse_enctype_list`]). Entries this crate cannot use
    ///   are dropped; a list with no AES enctype left is an error. These
    ///   are not realm-specific, as in MIT.
    /// * `ticket_lifetime` and `renew_lifetime`, in MIT's duration syntax
    ///   (see [`parse_duration`]).
    /// * `forwardable` and `proxiable`, MIT booleans.
    ///
    /// The last four may be set per realm, in `[libdefaults] REALM = {...}`.
    pub fn client_defaults(&self, realm: &str) -> Result<ClientDefaults> {
        let enctypes = |tag: &str| -> Result<Vec<i32>> {
            let (key, value) = match self.get(&["libdefaults", tag]) {
                Some(v) => (tag, v),
                None => (
                    "permitted_enctypes",
                    self.get(&["libdefaults", "permitted_enctypes"])
                        .unwrap_or("DEFAULT"),
                ),
            };
            let bad = |why: &str| ConfigError::BadValue {
                tag: key.to_string(),
                value: value.to_string(),
                why: why.to_string(),
            };
            let all = parse_enctype_list(value);
            if all.is_empty() {
                return Err(bad("no known enctypes (KRB5_CONFIG_ETYPE_NOSUPP)"));
            }
            let usable: Vec<i32> = all.into_iter().filter(|e| (17..=20).contains(e)).collect();
            if usable.is_empty() {
                return Err(bad("no AES enctype left; this crate supports only 17-20"));
            }
            Ok(usable)
        };
        let seconds = |tag: &str, default: i64| -> Result<i64> {
            match self.libdefault(realm, tag) {
                None => Ok(default),
                Some(v) => {
                    parse_duration(v)
                        .filter(|&s| s >= 0)
                        .ok_or_else(|| ConfigError::BadValue {
                            tag: tag.to_string(),
                            value: v.to_string(),
                            why: "not a duration (10h, 1d2h30m, 36:00, 1-02:00:00, 3600)".into(),
                        })
                }
            }
        };
        let boolean = |tag: &str| self.libdefault(realm, tag).is_some_and(conf_boolean);
        let renew = seconds("renew_lifetime", 0)?;
        let udp_preference_limit = match self.get(&["libdefaults", "udp_preference_limit"]) {
            None => 1465,
            Some(v) => match parse_profile_int(v) {
                // MIT fails the request on a bad value; we fail here.
                None => {
                    return Err(ConfigError::BadValue {
                        tag: "udp_preference_limit".into(),
                        value: v.to_string(),
                        why: "not an integer".into(),
                    });
                }
                Some(n) if n < 0 => 1465,
                Some(n) => n.min(32700) as usize,
            },
        };
        Ok(ClientDefaults {
            tkt_enctypes: enctypes("default_tkt_enctypes")?,
            tgs_enctypes: enctypes("default_tgs_enctypes")?,
            ticket_lifetime: std::time::Duration::from_secs(
                seconds("ticket_lifetime", 24 * 3600)? as u64
            ),
            renew_lifetime: (renew > 0).then(|| std::time::Duration::from_secs(renew as u64)),
            forwardable: boolean("forwardable"),
            proxiable: boolean("proxiable"),
            udp_preference_limit,
        })
    }
}

/// MIT's default `clockskew`, RFC 4120 §5.3's five minutes.
pub const DEFAULT_CLOCKSKEW: i64 = 300;

impl Krb5Conf {
    /// `[libdefaults] clockskew`, in seconds, as MIT's `krb5_init_context`
    /// reads it: a base-10 integer (`strtol` with nothing after it) in the
    /// range of a C `int`. As in MIT, a value that is not one is ignored
    /// in favour of the default, 300.
    pub fn clockskew(&self) -> i64 {
        match self.get(&["libdefaults", "clockskew"]) {
            None => DEFAULT_CLOCKSKEW,
            Some(v) => parse_profile_int(v).unwrap_or_else(|| {
                tracing::debug!(
                    "[libdefaults] clockskew = {v:?} is not an integer; using {DEFAULT_CLOCKSKEW}"
                );
                DEFAULT_CLOCKSKEW
            }),
        }
    }
}

impl Krb5Conf {
    /// `[libdefaults] client_aware_channel_bindings` (MIT 1.19 and later),
    /// default false: whether every initiator says it binds to its channel
    /// (MS-KILE KERB_AP_OPTIONS_CBT), as if it asked for
    /// [`GSS_C_CHANNEL_BOUND_FLAG`]. MIT reads it in its Kerberos library;
    /// here the caller adds the flag:
    ///
    /// ```no_run
    /// # use krb5::initiator::GSS_C_CHANNEL_BOUND_FLAG;
    /// # let conf = krb5::Krb5Conf::load_default().unwrap();
    /// # let mut flags = 0;
    /// if conf.client_aware_channel_bindings() {
    ///     flags |= GSS_C_CHANNEL_BOUND_FLAG;
    /// }
    /// ```
    ///
    /// [`GSS_C_CHANNEL_BOUND_FLAG`]: crate::initiator::GSS_C_CHANNEL_BOUND_FLAG
    pub fn client_aware_channel_bindings(&self) -> bool {
        self.get(&["libdefaults", "client_aware_channel_bindings"])
            .is_some_and(conf_boolean)
    }
}

/// MIT's profile `parse_int`: `strtol(value, &end, 10)` consuming the whole
/// string (leading blanks and a sign allowed, nothing trailing), within
/// `int` range.
pub(crate) fn parse_profile_int(v: &str) -> Option<i64> {
    let t = v.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = t.strip_prefix('+').unwrap_or(t).parse().ok()?;
    (i64::from(i32::MIN)..=i64::from(i32::MAX))
        .contains(&n)
        .then_some(n)
}

/// MIT's `_krb5_conf_boolean`: only its "yes" words are true.
pub(crate) fn conf_boolean(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "y" | "yes" | "true" | "t" | "1" | "on"
    )
}

/// MIT's enctype names and aliases (lib/crypto/krb/etypes.c), matched
/// case-insensitively as `krb5_string_to_enctype` does.
const ENCTYPE_NAMES: &[(i32, &[&str])] = &[
    (6, &["des3-cbc-raw"]),
    (16, &["des3-cbc-sha1", "des3-hmac-sha1", "des3-cbc-sha1-kd"]),
    (23, &["arcfour-hmac", "rc4-hmac", "arcfour-hmac-md5"]),
    (
        24,
        &["arcfour-hmac-exp", "rc4-hmac-exp", "arcfour-hmac-md5-exp"],
    ),
    (
        17,
        &["aes128-cts-hmac-sha1-96", "aes128-cts", "aes128-sha1"],
    ),
    (
        18,
        &["aes256-cts-hmac-sha1-96", "aes256-cts", "aes256-sha1"],
    ),
    (25, &["camellia128-cts-cmac", "camellia128-cts"]),
    (26, &["camellia256-cts-cmac", "camellia256-cts"]),
    (19, &["aes128-cts-hmac-sha256-128", "aes128-sha2"]),
    (20, &["aes256-cts-hmac-sha384-192", "aes256-sha2"]),
];

/// MIT's `default_enctype_list` (init_ctx.c): what `DEFAULT` means.
const MIT_DEFAULT_ENCTYPES: &[i32] = &[18, 17, 20, 19, 16, 23, 25, 26];

/// MIT's `krb5int_parse_enctype_list`: words separated by blanks or
/// commas, each optionally prefixed `+` (add, the default) or `-`
/// (remove), naming an enctype or alias, a family (`aes`, `des3`, `rc4`,
/// `camellia`) or `DEFAULT`. Returns MIT enctype numbers in order without
/// duplicates; unknown words are ignored, as in MIT.
pub fn parse_enctype_list(value: &str) -> Vec<i32> {
    let mut list: Vec<i32> = Vec::new();
    for word in value
        .split([' ', '\t', '\r', '\n', ','])
        .filter(|w| !w.is_empty())
    {
        let (add, name) = match word.as_bytes()[0] {
            b'+' => (true, &word[1..]),
            b'-' => (false, &word[1..]),
            _ => (true, word),
        };
        let lower = name.to_ascii_lowercase();
        let etypes: Vec<i32> = match lower.as_str() {
            "default" => MIT_DEFAULT_ENCTYPES.to_vec(),
            "des3" => vec![16],
            "aes" => vec![18, 17, 20, 19],
            "rc4" => vec![23],
            "camellia" => vec![26, 25],
            _ => ENCTYPE_NAMES
                .iter()
                .find(|(_, names)| names.contains(&lower.as_str()))
                .map(|(e, _)| vec![*e])
                .unwrap_or_default(),
        };
        for e in etypes {
            if !add {
                list.retain(|&x| x != e);
            } else if !list.contains(&e) {
                list.push(e);
            }
        }
    }
    list
}

/// MIT's `krb5_string_to_deltat` (x-deltat.y), in seconds:
///
/// ```text
///   N d [N h] [N m] [N s]     a suffixed sequence, largest unit first,
///   N h [N m] [N s]           any unit after the first optional:
///   N m [N s]                 1d, 2h30m, 1d 4s, 90s
///   N s
///   N-HH:MM:SS                days-hours:minutes:seconds
///   N:MM:SS   N:MM            hours:minutes[:seconds]
///   N                         seconds
/// ```
///
/// Blanks may precede a number, which may be negative, and may follow
/// only the suffixed forms. The fields after `-` and `:` are one or two
/// digits, as MIT's lexer makes them. As in MIT, the first character the
/// lexer does not know (anything but digits, `-`, `:`, `d`, `h`, `m`, `s`
/// and blanks) ends the input, so `1.5h` is one second and `10H` ten. A
/// result outside a signed 32-bit count of seconds is refused.
///
/// Checked against MIT's own `krb5_string_to_deltat` on every case in
/// `testdata/mit-settings.tsv`.
pub fn parse_duration(s: &str) -> Option<i64> {
    let max = i64::from(i32::MAX);
    let known = |c: u8| c.is_ascii_digit() || b"-:dhms \t\n".contains(&c);
    let end = s.bytes().position(|c| !known(c)).unwrap_or(s.len());
    let mut p = DeltatParser {
        b: &s.as_bytes()[..end],
        i: 0,
    };
    let first = p.num()?;
    let total = match p.peek() {
        None => first,
        Some(b'-') => {
            p.i += 1;
            let h = p.field()?;
            p.expect(b':')?;
            let m = p.field()?;
            p.expect(b':')?;
            let total = first * 86400 + h * 3600 + m * 60 + p.field()?;
            p.at_end().then_some(total)?
        }
        Some(b':') => {
            p.i += 1;
            let m = p.field()?;
            let sec = if p.peek() == Some(b':') {
                p.i += 1;
                p.field()?
            } else {
                0
            };
            p.at_end().then_some(first * 3600 + m * 60 + sec)?
        }
        Some(c) => {
            const UNITS: [(u8, i64); 4] = [(b'd', 86400), (b'h', 3600), (b'm', 60), (b's', 1)];
            let mut at = UNITS.iter().position(|&(u, _)| u == c)?;
            p.i += 1;
            let mut total = first * UNITS[at].1;
            // Each further number takes a strictly smaller unit.
            while at < UNITS.len() - 1 && !p.at_end_after_ws() {
                let n = p.num()?;
                let c = p.peek()?;
                let next = UNITS[at + 1..].iter().position(|&(u, _)| u == c)?;
                at += 1 + next;
                p.i += 1;
                total += n * UNITS[at].1;
            }
            p.at_end_after_ws().then_some(total)?
        }
    };
    (-max..=max).contains(&total).then_some(total)
}

struct DeltatParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl DeltatParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn at_end(&self) -> bool {
        self.i == self.b.len()
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(|c| b" \t\n".contains(&c)) {
            self.i += 1;
        }
    }

    fn at_end_after_ws(&mut self) -> bool {
        self.skip_ws();
        self.i == self.b.len()
    }

    fn digits(&mut self) -> Option<(i64, usize)> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        let n = self.i - start;
        if n == 0 || n > 10 {
            return None;
        }
        let v: i64 = std::str::from_utf8(&self.b[start..self.i])
            .ok()?
            .parse()
            .ok()?;
        (v <= i64::from(i32::MAX)).then_some((v, n))
    }

    /// Blanks, an optional '-', digits.
    fn num(&mut self) -> Option<i64> {
        self.skip_ws();
        let neg = self.peek() == Some(b'-');
        if neg {
            self.i += 1;
        }
        let (v, _) = self.digits()?;
        Some(if neg { -v } else { v })
    }

    /// One or two digits, nothing before them.
    fn field(&mut self) -> Option<i64> {
        let (v, n) = self.digits()?;
        (n <= 2).then_some(v)
    }

    fn expect(&mut self, c: u8) -> Option<()> {
        (self.peek() == Some(c)).then(|| self.i += 1)
    }
}

/// MIT `k5_parse_host_string`, minus the port-only form (which has no
/// host and is an error for a KDC entry). Returns `host:port`, with an
/// IPv6 address bracketed.
pub(crate) fn parse_host_string(entry: &str, default_port: u16) -> Option<String> {
    if entry.is_empty() || entry.starts_with(':') || entry.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (host, port) = if let Some(rest) = entry.strip_prefix('[') {
        let close = rest.find(']')?;
        (&rest[..close], rest[close + 1..].strip_prefix(':'))
    } else {
        let end = entry.find([' ', '\t', ':']).unwrap_or(entry.len());
        (&entry[..end], entry[end..].strip_prefix(':'))
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok()?,
        Some(_) => return None,
        None => default_port,
    };
    Some(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

/// MIT `valid_name` for `includedir` and directories in `KRB5_CONFIG`.
fn valid_name(name: &str) -> bool {
    if name.starts_with('.') {
        return false;
    }
    name.ends_with(".conf")
        || name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn dir_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let io_err = |source| ConfigError::Io {
        path: dir.to_path_buf(),
        source,
    };
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        if let Some(name) = entry.file_name().to_str().filter(|n| valid_name(n)) {
            names.push(name.to_string());
        }
    }
    names.sort();
    Ok(names.into_iter().map(|n| dir.join(n)).collect())
}

#[derive(PartialEq)]
enum State {
    /// Before the first section header.
    InitComment,
    StdLine,
    /// After `tag =` with nothing on the right: the `{` comes next.
    GetObrace,
}

struct Parser<'a> {
    path: Option<&'a Path>,
    line: usize,
    state: State,
    /// 0 outside any section, 1 in a section, 2+ in subsections.
    level: usize,
    /// The level of a final section being skipped, or 0.
    discard: usize,
    /// Names from the root to the current (sub)section.
    stack: Vec<String>,
}

impl Parser<'_> {
    fn err<T>(&self, msg: impl Into<String>) -> Result<T> {
        Err(ConfigError::Syntax {
            path: self.path.map(Path::to_path_buf),
            line: self.line,
            msg: msg.into(),
        })
    }
}

/// The child section `name` of `nodes`, created if absent.
fn section_mut<'a>(nodes: &'a mut Vec<Node>, name: &str) -> &'a mut Node {
    let i = match nodes
        .iter()
        .position(|n| n.name == name && matches!(n.value, Value::Section(_)))
    {
        Some(i) => i,
        None => {
            nodes.push(Node {
                name: name.to_string(),
                value: Value::Section(Vec::new()),
                is_final: false,
            });
            nodes.len() - 1
        }
    };
    &mut nodes[i]
}

fn children(node: &mut Node) -> &mut Vec<Node> {
    match &mut node.value {
        Value::Section(c) => c,
        Value::Relation(_) => unreachable!("section_mut only returns sections"),
    }
}

/// The node at `stack`, which the parser only ever fills with sections.
fn current<'a>(root: &'a mut Vec<Node>, stack: &[String]) -> &'a mut Node {
    let (first, rest) = stack.split_first().expect("inside a section");
    let mut node = section_mut(root, first);
    for name in rest {
        node = section_mut(children(node), name);
    }
    node
}

/// `name ARG` at column 0, as MIT matches its directives: the name, at
/// least one whitespace character, then the argument.
fn directive<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(name)?;
    rest.starts_with(|c: char| c.is_ascii_whitespace())
        .then(|| rest.trim_start())
}

fn parse_into(root: &mut Vec<Node>, text: &str, path: Option<&Path>, depth: usize) -> Result<()> {
    let mut p = Parser {
        path,
        line: 0,
        state: State::InitComment,
        level: 0,
        discard: 0,
        stack: Vec::new(),
    };
    for raw in text.split('\n') {
        p.line += 1;
        let line = raw.trim_end_matches(['\r', '\n']);

        // Checked in every state, before section headers, as MIT does.
        let include = match (directive(line, "include"), directive(line, "includedir")) {
            (Some(file), _) => Some(vec![PathBuf::from(file)]),
            (_, Some(dir)) => Some(dir_files(Path::new(dir))?),
            _ => None,
        };
        if let Some(files) = include {
            if depth >= MAX_INCLUDE_DEPTH {
                return p.err(format!("includes nested deeper than {MAX_INCLUDE_DEPTH}"));
            }
            for file in files {
                let text = fs::read_to_string(&file).map_err(|source| ConfigError::Io {
                    path: file.clone(),
                    source,
                })?;
                parse_into(root, &text, Some(&file), depth + 1)?;
            }
            continue;
        }

        match p.state {
            State::InitComment => {
                if directive(line, "module").is_some() {
                    return p.err("module directives are not supported");
                }
                if !line.starts_with('[') {
                    continue;
                }
                p.state = State::StdLine;
                std_line(root, &mut p, line)?;
            }
            State::StdLine => std_line(root, &mut p, line)?,
            State::GetObrace => {
                if !line.trim_start().starts_with('{') {
                    return p.err("missing '{' after an empty relation (PROF_MISSING_OBRACE)");
                }
                p.state = State::StdLine;
            }
        }
    }
    Ok(())
}

fn std_line(root: &mut Vec<Node>, p: &mut Parser<'_>, line: &str) -> Result<()> {
    let cp = line.trim_start();
    if cp.is_empty() || cp.starts_with(';') || cp.starts_with('#') {
        return Ok(());
    }

    if let Some(rest) = cp.strip_prefix('[') {
        if p.level > 1 {
            return p.err("section header inside a subsection (PROF_SECTION_NOTOP)");
        }
        let Some(close) = rest.find(']') else {
            return p.err("unterminated section header (PROF_SECTION_SYNTAX)");
        };
        let name = &rest[..close];
        let section = section_mut(root, name);
        p.discard = usize::from(section.is_final);
        let mut after = &rest[close + 1..];
        if let Some(a) = after.strip_prefix('*') {
            section.is_final = true;
            after = a;
        }
        if !after.trim().is_empty() {
            return p.err("text after a section header (PROF_SECTION_SYNTAX)");
        }
        p.level = 1;
        p.stack = vec![name.to_string()];
        return Ok(());
    }

    if let Some(rest) = cp.strip_prefix('}') {
        if p.level < 2 {
            return p.err("unmatched '}' (PROF_EXTRA_CBRACE)");
        }
        if rest.starts_with('*') && (p.discard == 0 || p.discard == p.level) {
            current(root, &p.stack).is_final = true;
        }
        p.level -= 1;
        if p.level < p.discard {
            p.discard = 0;
        }
        if p.discard == 0 {
            p.stack.pop();
        }
        return Ok(());
    }

    let Some(eq) = cp.find('=') else {
        return p.err("expected 'tag = value' (PROF_RELATION_SYNTAX)");
    };
    let lhs = &cp[..eq];
    let tag = lhs
        .split(|c: char| c.is_ascii_whitespace())
        .next()
        .unwrap_or("");
    if tag.is_empty() || !lhs[tag.len()..].trim().is_empty() {
        return p.err("expected a single tag before '=' (PROF_RELATION_SYNTAX)");
    }
    let value = cp[eq + 1..].trim_start();
    let (tag, star) = match tag.find('*') {
        Some(i) => (&tag[..i], true),
        None => (tag, false),
    };

    let subsection = if value.is_empty() {
        p.state = State::GetObrace;
        true
    } else {
        value.strip_prefix('{').is_some_and(|r| r.trim().is_empty())
    };
    if subsection {
        p.level += 1;
        if p.discard == 0 {
            let node = section_mut(children(current(root, &p.stack)), tag);
            if node.is_final {
                p.discard = p.level;
            }
            if star {
                node.is_final = true;
            }
            p.stack.push(tag.to_string());
        }
        return Ok(());
    }

    if p.discard != 0 {
        return Ok(());
    }
    let value = match value.strip_prefix('"') {
        Some(q) => unquote(q),
        None => value.trim_end().to_string(),
    };
    let siblings = children(current(root, &p.stack));
    if siblings
        .iter()
        .any(|n| n.name == tag && n.is_final && matches!(n.value, Value::Relation(_)))
    {
        return Ok(());
    }
    siblings.push(Node {
        name: tag.to_string(),
        value: Value::Relation(value),
        is_final: star,
    });
    Ok(())
}

/// MIT `parse_quoted_string`: up to the closing quote, with `\n`, `\t`,
/// `\b` and any other escaped character taken literally.
fn unquote(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\u{8}'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            },
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(text: &str) -> Krb5Conf {
        Krb5Conf::parse(text).unwrap()
    }

    fn syntax_err(text: &str) -> String {
        match Krb5Conf::parse(text).unwrap_err() {
            ConfigError::Syntax { line, msg, .. } => format!("{line}: {msg}"),
            other => panic!("expected a syntax error, got {other}"),
        }
    }

    /// A scratch directory that removes itself.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let n: u64 = rand::random();
            let dir = std::env::temp_dir().join(format!("krb5-conf-{tag}-{n:016x}"));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }

        fn write(&self, name: &str, text: &str) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, text).unwrap();
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The shape of the example in krb5.conf(5).
    const SAMPLE: &str = "\
[libdefaults]
    default_realm = ATHENA.MIT.EDU
    dns_lookup_kdc = true

[realms]
    ATHENA.MIT.EDU = {
        admin_server = kerberos.mit.edu
        kdc = kerberos.mit.edu
        kdc = kerberos-1.mit.edu:750
        kdc = [2001:db8::1]:88
    }
    EXAMPLE.COM = {
        kdc = kdc.example.com
    }

[domain_realm]
    .mit.edu = ATHENA.MIT.EDU
    mit.edu = ATHENA.MIT.EDU
    special.mit.edu = EXAMPLE.COM
";

    /// testdata/mit-settings.tsv: MIT's own krb5_string_to_deltat and
    /// krb5int_parse_enctype_list on each string
    /// (scripts/record-mit-settings.sh).
    #[test]
    fn durations_and_enctype_lists_parse_as_mit_parses_them() {
        let tsv = include_str!("../testdata/mit-settings.tsv");
        let mut checked = (0, 0);
        for line in tsv.lines() {
            let (input, mit) = line.split_once('\t').unwrap();
            let (kind, arg) = (&input[..1], &input[2..]);
            match kind {
                "D" => {
                    let want = (mit != "ERR").then(|| mit.parse::<i64>().unwrap());
                    assert_eq!(parse_duration(arg), want, "duration {arg:?}");
                    checked.0 += 1;
                }
                "E" => {
                    let got = parse_enctype_list(arg);
                    let want: Vec<i32> = match mit {
                        "ERR" => vec![],
                        l => l.split(' ').map(|e| e.parse().unwrap()).collect(),
                    };
                    assert_eq!(got, want, "enctypes {arg:?}");
                    checked.1 += 1;
                }
                _ => panic!("bad line {line:?}"),
            }
        }
        assert!(checked.0 > 60 && checked.1 > 25, "{checked:?}");
    }

    #[test]
    fn client_aware_channel_bindings_is_an_mit_boolean() {
        let conf = |v: &str| {
            Krb5Conf::parse(&format!(
                "[libdefaults]\n client_aware_channel_bindings = {v}\n"
            ))
            .unwrap()
            .client_aware_channel_bindings()
        };
        assert!(conf("true") && conf("yes") && conf("1") && conf("on"));
        assert!(!conf("false") && !conf("0") && !conf("maybe"));
        assert!(!Krb5Conf::parse("").unwrap().client_aware_channel_bindings());
    }

    #[test]
    fn clockskew_is_read_as_mit_reads_it() {
        let skew = |v: &str| conf(&format!("[libdefaults]\n clockskew = {v}\n")).clockskew();
        assert_eq!(Krb5Conf::empty().clockskew(), 300);
        assert_eq!(skew("600"), 600);
        assert_eq!(skew("+60"), 60);
        assert_eq!(skew("-5"), -5);
        assert_eq!(skew("\"  42\""), 42, "leading blanks, as strtol");
        // Not integers: MIT keeps the default.
        for bad in ["5m", "10 ", "0x10", "", "1e3", "99999999999"] {
            assert_eq!(skew(&format!("\"{bad}\"")), 300, "{bad:?}");
        }
    }

    #[test]
    fn client_defaults_follow_mit() {
        let d = Krb5Conf::empty().client_defaults("A.ORG").unwrap();
        assert_eq!(d.tkt_enctypes, [18, 17, 20, 19]);
        assert_eq!(d.tgs_enctypes, [18, 17, 20, 19]);
        assert_eq!(d.ticket_lifetime.as_secs(), 86400);
        assert_eq!(
            (d.renew_lifetime, d.forwardable, d.proxiable),
            (None, false, false)
        );

        let c = conf(
            "[libdefaults]\n\
             permitted_enctypes = aes256-sha2 aes256-cts\n\
             default_tgs_enctypes = aes128-cts rc4-hmac\n\
             ticket_lifetime = 10h\n\
             renew_lifetime = 7d\n\
             forwardable = true\n\
             proxiable = maybe\n\
             A.ORG = {\n\
               ticket_lifetime = 1h30m\n\
               forwardable = no\n\
             }\n",
        );
        let a = c.client_defaults("A.ORG").unwrap();
        // tkt falls back to permitted; tgs has its own, non-AES dropped.
        assert_eq!(a.tkt_enctypes, [20, 18]);
        assert_eq!(a.tgs_enctypes, [17]);
        // The realm's own subsection wins; the rest come from the top.
        assert_eq!(a.ticket_lifetime.as_secs(), 5400);
        assert_eq!(a.renew_lifetime.unwrap().as_secs(), 7 * 86400);
        assert!(!a.forwardable);
        assert!(!a.proxiable, "not one of MIT's yes words");
        let b = c.client_defaults("B.ORG").unwrap();
        assert_eq!(b.ticket_lifetime.as_secs(), 36000);
        assert!(b.forwardable);
        assert_eq!(
            conf("[libdefaults]\n renew_lifetime = 0\n")
                .client_defaults("X")
                .unwrap()
                .renew_lifetime,
            None
        );
    }

    #[test]
    fn unusable_client_defaults_are_errors() {
        let err = |t: &str| {
            conf(&format!("[libdefaults]\n{t}\n"))
                .client_defaults("X")
                .unwrap_err()
                .to_string()
        };
        assert!(err("default_tkt_enctypes = des3 rc4").contains("no AES enctype"));
        assert!(err("permitted_enctypes = bogus").contains("no known enctypes"));
        assert!(err("ticket_lifetime = forever").contains("not a duration"));
        assert!(err("renew_lifetime = -1d").contains("not a duration"));
    }

    #[test]
    fn the_manual_page_shape_parses() {
        let c = conf(SAMPLE);
        assert_eq!(c.default_realm(), Some("ATHENA.MIT.EDU"));
        assert_eq!(c.get(&["libdefaults", "dns_lookup_kdc"]), Some("true"));
        assert_eq!(
            c.get_all(&["realms", "ATHENA.MIT.EDU", "kdc"]),
            [
                "kerberos.mit.edu",
                "kerberos-1.mit.edu:750",
                "[2001:db8::1]:88"
            ]
        );
        assert_eq!(
            c.kdcs("ATHENA.MIT.EDU").unwrap(),
            [
                "kerberos.mit.edu:88",
                "kerberos-1.mit.edu:750",
                "[2001:db8::1]:88"
            ]
        );
        assert_eq!(c.kdcs("EXAMPLE.COM").unwrap(), ["kdc.example.com:88"]);
    }

    #[test]
    fn missing_paths_are_empty_not_errors() {
        let c = conf(SAMPLE);
        assert_eq!(c.get(&["libdefaults", "nope"]), None);
        assert_eq!(c.get(&["nope", "default_realm"]), None);
        assert!(c.get_all(&[]).is_empty());
        // A subsection is not a value.
        assert_eq!(c.get(&["realms", "EXAMPLE.COM"]), None);
        assert!(Krb5Conf::empty().default_realm().is_none());
    }

    #[test]
    fn realm_names_are_case_sensitive() {
        assert!(matches!(
            conf(SAMPLE).kdcs("example.com"),
            Err(ConfigError::NoKdcs { .. })
        ));
    }

    #[test]
    fn comments_are_whole_lines_only() {
        let c = conf(
            "\
# leading comment
[libdefaults]
  ; indented comment
\t# tab-indented comment
    default_realm = A.ORG # not a comment
",
        );
        assert_eq!(c.default_realm(), Some("A.ORG # not a comment"));
    }

    #[test]
    fn lines_before_the_first_section_are_ignored() {
        let c = conf("stray = value\nanything at all\n[libdefaults]\ndefault_realm = A\n");
        assert_eq!(c.default_realm(), Some("A"));
        assert!(Krb5Conf::parse("junk = {\n").unwrap().root.is_empty());
    }

    #[test]
    fn values_are_trimmed_and_may_be_quoted() {
        let c = conf(concat!(
            "[s]\n",
            "  plain =   spaced out value   \n",
            "  quoted = \"  keeps \\\"spaces\\\"\\t\\n\\\\ \" trailing junk\n",
            "  empty_quoted = \"\"\n",
            "  equals = a=b\n",
        ));
        assert_eq!(c.get(&["s", "plain"]), Some("spaced out value"));
        assert_eq!(c.get(&["s", "quoted"]), Some("  keeps \"spaces\"\t\n\\ "));
        assert_eq!(c.get(&["s", "empty_quoted"]), Some(""));
        assert_eq!(c.get(&["s", "equals"]), Some("a=b"));
    }

    #[test]
    fn crlf_line_endings_are_accepted() {
        let c = conf("[libdefaults]\r\n  default_realm = A.ORG\r\n");
        assert_eq!(c.default_realm(), Some("A.ORG"));
    }

    #[test]
    fn the_brace_may_open_on_the_next_line() {
        let c = conf("[realms]\n  A.ORG =\n  {\n    kdc = k\n  }\n");
        assert_eq!(c.kdcs("A.ORG").unwrap(), ["k:88"]);
        assert!(syntax_err("[realms]\n  A.ORG =\n  kdc = k\n").contains("PROF_MISSING_OBRACE"));
    }

    #[test]
    fn a_brace_with_text_after_it_is_a_value() {
        let c = conf("[s]\n  t = { not a subsection\n");
        assert_eq!(c.get(&["s", "t"]), Some("{ not a subsection"));
    }

    #[test]
    fn same_named_sections_and_subsections_merge_in_order() {
        let c = conf(
            "\
[realms]
  A.ORG = {
    kdc = one
  }
[libdefaults]
  default_realm = A.ORG
[realms]
  A.ORG = {
    kdc = two
  }
",
        );
        assert_eq!(c.get_all(&["realms", "A.ORG", "kdc"]), ["one", "two"]);
    }

    #[test]
    fn nested_subsections_resolve() {
        let c = conf("[a]\n  b = {\n    c = {\n      d = deep\n    }\n    e = shallow\n  }\n");
        assert_eq!(c.get(&["a", "b", "c", "d"]), Some("deep"));
        assert_eq!(c.get(&["a", "b", "e"]), Some("shallow"));
    }

    #[test]
    fn a_final_section_ignores_later_copies() {
        let c = conf(
            "[libdefaults]*\n  default_realm = A\n[libdefaults]\n  default_realm = B\n  x = y\n",
        );
        assert_eq!(c.get_all(&["libdefaults", "default_realm"]), ["A"]);
        assert_eq!(c.get(&["libdefaults", "x"]), None);
    }

    #[test]
    fn a_final_subsection_by_tag_or_brace_ignores_later_copies() {
        for open_close in [("A.ORG* = {", "}"), ("A.ORG = {", "}*")] {
            let text = format!(
                "[realms]\n  {}\n    kdc = one\n  {}\n  A.ORG = {{\n    kdc = two\n    sub = {{\n      x = y\n    }}\n  }}\n  B.ORG = {{\n    kdc = b\n  }}\n",
                open_close.0, open_close.1
            );
            let c = conf(&text);
            assert_eq!(c.get_all(&["realms", "A.ORG", "kdc"]), ["one"], "{text}");
            assert_eq!(c.get(&["realms", "A.ORG", "sub", "x"]), None, "{text}");
            // Parsing resumes properly after the discarded subsection.
            assert_eq!(c.kdcs("B.ORG").unwrap(), ["b:88"], "{text}");
        }
    }

    #[test]
    fn a_final_relation_ignores_later_values() {
        let c = conf("[s]\n  t* = first\n  t = second\n  u = one\n  u = two\n");
        assert_eq!(c.get_all(&["s", "t"]), ["first"]);
        assert_eq!(c.get_all(&["s", "u"]), ["one", "two"]);
    }

    #[test]
    fn syntax_errors_name_the_line() {
        assert!(syntax_err("[a]\n  b = {\n[c]\n").starts_with("3: section header inside"));
        assert!(syntax_err("[a\n").contains("PROF_SECTION_SYNTAX"));
        assert!(syntax_err("[a] x\n").contains("PROF_SECTION_SYNTAX"));
        assert!(syntax_err("[a]\n}\n").contains("PROF_EXTRA_CBRACE"));
        assert!(syntax_err("[a]\n  no equals sign\n").contains("PROF_RELATION_SYNTAX"));
        assert!(syntax_err("[a]\n  = value\n").contains("PROF_RELATION_SYNTAX"));
        assert!(syntax_err("[a]\n  two words = value\n").contains("PROF_RELATION_SYNTAX"));
        assert!(syntax_err("module /lib/x.so:arg\n[a]\n").contains("module"));
    }

    #[test]
    fn a_space_after_the_section_bracket_is_fine() {
        assert_eq!(
            conf("[libdefaults]   \n default_realm = A\n").default_realm(),
            Some("A")
        );
    }

    #[test]
    fn domain_realm_tries_the_host_then_each_suffix_with_and_without_dot() {
        let c = conf(SAMPLE);
        assert_eq!(c.host_realm("special.mit.edu"), Some("EXAMPLE.COM"));
        assert_eq!(c.host_realm("www.mit.edu"), Some("ATHENA.MIT.EDU")); // .mit.edu
        // The bare suffix `special.mit.edu` is tried too, so a bare entry
        // covers subdomains as well: MIT answers EXAMPLE.COM, not the
        // `.mit.edu` realm.
        assert_eq!(c.host_realm("a.special.mit.edu"), Some("EXAMPLE.COM"));
        assert_eq!(c.host_realm("mit.edu"), Some("ATHENA.MIT.EDU")); // exact
        assert_eq!(c.host_realm("WWW.MIT.EDU."), Some("ATHENA.MIT.EDU"));
        assert_eq!(c.host_realm("example.org"), None);
        assert_eq!(c.host_realm(""), None);
    }

    #[test]
    fn domain_realm_prefers_the_longest_match_and_dot_before_bare() {
        let c = conf("[domain_realm]\n  .b.c = DOT\n  b.c = BARE\n  c = TOP\n");
        assert_eq!(c.host_realm("a.b.c"), Some("DOT"));
        assert_eq!(c.host_realm("b.c"), Some("BARE"));
        assert_eq!(c.host_realm("x.c"), Some("TOP"));
    }

    #[test]
    fn ip_addresses_are_never_mapped() {
        let c = conf("[domain_realm]\n  .1 = WRONG\n  1 = WRONG\n  ::1 = WRONG\n");
        assert_eq!(c.host_realm("10.0.0.1"), None);
        assert_eq!(c.host_realm("::1"), None);
    }

    #[test]
    fn kdc_entries_parse_as_mit_host_strings() {
        assert_eq!(parse_host_string("kdc", 88).unwrap(), "kdc:88");
        assert_eq!(parse_host_string("kdc:1088", 88).unwrap(), "kdc:1088");
        assert_eq!(parse_host_string("10.1.2.3:89", 88).unwrap(), "10.1.2.3:89");
        assert_eq!(parse_host_string("[::1]", 88).unwrap(), "[::1]:88");
        assert_eq!(parse_host_string("[::1]:750", 88).unwrap(), "[::1]:750");
        // strcspn(" \t:"): text after whitespace is ignored.
        assert_eq!(parse_host_string("kdc extra words", 88).unwrap(), "kdc:88");
        for bad in [
            "",
            ":88",
            "88",
            "kdc:",
            "kdc:x",
            "kdc:70000",
            "kdc:88x",
            "[]:88",
            "[::1",
            "::1",
        ] {
            assert_eq!(parse_host_string(bad, 88), None, "{bad:?}");
        }
    }

    #[test]
    fn unsupported_kdc_transports_are_skipped_and_reported() {
        let c = conf(
            "\
[realms]
  MIXED = {
    kdc = https://kkdcp.example.com/KdcProxy
    kdc = /var/run/kdc.sock
    kdc = kdc.example.com
  }
  ONLY_HTTPS = {
    kdc = https://kkdcp.example.com/KdcProxy
  }
  BAD = {
    kdc = good.example.com
    kdc = bad.example.com:port
  }
",
        );
        assert_eq!(c.kdcs("MIXED").unwrap(), ["kdc.example.com:88"]);
        let e = c.kdcs("ONLY_HTTPS").unwrap_err();
        assert!(e.to_string().contains("unsupported: https://kkdcp"), "{e}");
        assert!(
            matches!(c.kdcs("BAD"), Err(ConfigError::BadKdc { entry, .. }) if entry == "bad.example.com:port")
        );
    }

    #[test]
    fn include_and_includedir_read_files_in_sorted_order() {
        let t = TempDir::new("include");
        let d = t.0.join("conf.d");
        fs::create_dir(&d).unwrap();
        // Read: alphanumeric/-/_ names and *.conf; sorted, so 10 before 20.
        fs::write(
            d.join("20-second.conf"),
            "[realms]\n A = {\n  kdc = two\n }\n",
        )
        .unwrap();
        fs::write(d.join("10_first"), "[realms]\n A = {\n  kdc = one\n }\n").unwrap();
        // Skipped: dotfiles and editor leftovers.
        fs::write(d.join(".hidden.conf"), "[realms]\n A = {\n  kdc = no\n }\n").unwrap();
        fs::write(d.join("10_first~"), "[realms]\n A = {\n  kdc = no\n }\n").unwrap();
        fs::write(d.join("x.rpmsave"), "[realms]\n A = {\n  kdc = no\n }\n").unwrap();
        let inc = t.write("extra", "[libdefaults]\n  default_realm = A\n");
        let main = t.write(
            "krb5.conf",
            &format!(
                "include {}\nincludedir {}\n[realms]\n A = {{\n  kdc = three\n }}\n",
                inc.display(),
                d.display()
            ),
        );
        let c = Krb5Conf::load([&main]).unwrap();
        assert_eq!(c.default_realm(), Some("A"));
        assert_eq!(c.get_all(&["realms", "A", "kdc"]), ["one", "two", "three"]);
    }

    #[test]
    fn included_files_are_syntactically_independent() {
        let t = TempDir::new("indep");
        // No section header of its own: its relations are ignored, and the
        // parent's open section is unaffected.
        let inc = t.write("frag", "kdc = ignored\n");
        let main = t.write(
            "krb5.conf",
            &format!(
                "[realms]\n A = {{\ninclude {}\n  kdc = kept\n }}\n",
                inc.display()
            ),
        );
        let c = Krb5Conf::load([&main]).unwrap();
        assert_eq!(c.get_all(&["realms", "A", "kdc"]), ["kept"]);
    }

    #[test]
    fn a_directive_must_start_the_line() {
        // As a tag it is an ordinary relation...
        let c = conf("[s]\n  include = value\n");
        assert_eq!(c.get(&["s", "include"]), Some("value"));
        // ...and indented it is not a directive but a relation with no '='.
        assert!(syntax_err("[s]\n include /nonexistent\n").contains("PROF_RELATION_SYNTAX"));
    }

    #[test]
    fn a_missing_include_is_an_error() {
        let e = Krb5Conf::parse("include /nonexistent/krb5-test-include\n").unwrap_err();
        assert!(matches!(e, ConfigError::Io { .. }), "{e}");
    }

    #[test]
    fn an_include_cycle_stops() {
        let t = TempDir::new("cycle");
        let p = t.0.join("loop");
        fs::write(&p, format!("include {}\n", p.display())).unwrap();
        let e = Krb5Conf::load([&p]).unwrap_err();
        assert!(e.to_string().contains("nested deeper"), "{e}");
    }

    #[test]
    fn load_reads_files_in_order_and_the_first_value_wins() {
        let t = TempDir::new("load");
        let a = t.write(
            "a",
            "[libdefaults]\n  default_realm = FIRST\n[realms]\n R = {\n  kdc = a\n }\n",
        );
        let b = t.write(
            "b",
            "[libdefaults]\n  default_realm = SECOND\n[realms]\n R = {\n  kdc = b\n }\n",
        );
        let c = Krb5Conf::load([&a, &b]).unwrap();
        assert_eq!(c.default_realm(), Some("FIRST"));
        assert_eq!(c.get_all(&["realms", "R", "kdc"]), ["a", "b"]);
    }

    #[test]
    fn a_final_section_in_an_earlier_file_wins() {
        let t = TempDir::new("final");
        let a = t.write("a", "[libdefaults]*\n  default_realm = FIRST\n");
        let b = t.write(
            "b",
            "[libdefaults]\n  default_realm = SECOND\n  extra = x\n",
        );
        let c = Krb5Conf::load([&a, &b]).unwrap();
        assert_eq!(c.get_all(&["libdefaults", "default_realm"]), ["FIRST"]);
        assert_eq!(c.get(&["libdefaults", "extra"]), None);
    }

    #[test]
    fn missing_files_are_skipped_and_none_at_all_is_empty() {
        let t = TempDir::new("missing");
        let a = t.write("a", "[libdefaults]\n  default_realm = A\n");
        let c = Krb5Conf::load([t.0.join("nope"), a]).unwrap();
        assert_eq!(c.default_realm(), Some("A"));
        assert_eq!(
            Krb5Conf::load([t.0.join("nope")]).unwrap(),
            Krb5Conf::empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_files_fail_only_if_nothing_else_was_read() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new("perm");
        let locked = t.write("locked", "[libdefaults]\n  default_realm = LOCKED\n");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&locked).is_ok() {
            eprintln!("running with permission to read mode-000 files; skipping");
            return;
        }
        let open = t.write("open", "[libdefaults]\n  default_realm = OPEN\n");
        assert!(matches!(
            Krb5Conf::load([&locked]),
            Err(ConfigError::Io { .. })
        ));
        let c = Krb5Conf::load([&locked, &open]).unwrap();
        assert_eq!(c.default_realm(), Some("OPEN"));
    }

    #[test]
    fn a_directory_in_the_path_list_reads_like_includedir() {
        let t = TempDir::new("dir");
        t.write("krb5.conf", "[libdefaults]\n  default_realm = FROM_DIR\n");
        t.write("ignored~", "[libdefaults]\n  default_realm = NO\n");
        assert_eq!(
            Krb5Conf::load([&t.0]).unwrap().default_realm(),
            Some("FROM_DIR")
        );
    }

    #[test]
    fn a_syntax_error_names_the_file() {
        let t = TempDir::new("errpath");
        let p = t.write("broken", "[a]\n}\n");
        let e = Krb5Conf::load([&p]).unwrap_err().to_string();
        assert!(e.contains("broken: line 2"), "{e}");
    }
}
