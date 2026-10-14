//! A client for MIT's `kadmind`: what `kadmin` does, over the kadm5 RPC
//! protocol (program 2112, version 2, TCP port 749), authenticated and
//! encrypted by RPCSEC_GSS with Kerberos.
//!
//! ```no_run
//! use krb5::kadmin::{AdminClient, PrincipalChanges};
//! use krb5::{KdcClient, Principal};
//!
//! # fn main() -> Result<(), krb5::kadmin::Error> {
//! let kdc = KdcClient::discover("EXAMPLE.COM")?;
//! let admin = Principal::parse("admin/admin@EXAMPLE.COM")?;
//! let mut kadm = AdminClient::connect_with_password(&kdc, &admin, "secret", "kdc.example.com")?;
//! let svc = Principal::parse("nfs/server.example.com@EXAMPLE.COM")?;
//! kadm.create_principal(&svc, &PrincipalChanges::default(), None)?; // random keys
//! kadm.ktadd(&svc, "/etc/krb5.keytab", true)?;
//! println!("{:?}", kadm.get_principal(&svc)?);
//! # Ok(())
//! # }
//! ```
//!
//! The admin's ticket is for `kadmin/admin@REALM` and must come straight
//! from the AS exchange, as `kadmind` refuses one bought with a TGT
//! (`kadmin/admin` is created with `-allow_tgs_req`):
//! [`AdminClient::connect_with_password`] and
//! [`AdminClient::connect_with_keytab`] get one;
//! [`AdminClient::connect`] takes one already in hand (`kinit -S
//! kadmin/admin`).
//!
//! The kadm5 API version is negotiated down from 4 as MIT's client does
//! (MIT 1.18+ speak 4). Supported: principals (get, list, create, modify,
//! rename, delete, password change, random keys, key extraction, `ktadd`),
//! policies, string attributes, and privileges.

mod rpc;
mod xdr;

use crate::acceptor::{EncType, Keytab, ServiceKey};
use crate::client::{ClientError, Credentials, KdcClient, Principal};
use crate::config::Krb5Conf;
use crate::key::Key;
use std::path::Path;
use std::time::Duration;
use xdr::{Reader, Writer};

/// The kadm5 RPC program and version.
const KADM: u32 = 2112;
const KADMVERS: u32 = 2;
/// The default `kadmind_port`.
pub const KADMIN_PORT: u16 = 749;

const API_VERSION_2: u32 = 0x1234_5702;
const API_VERSION_3: u32 = 0x1234_5703;
const API_VERSION_4: u32 = 0x1234_5704;

// Procedures (kadm_rpc.h).
const CREATE_PRINCIPAL: u32 = 1;
const DELETE_PRINCIPAL: u32 = 2;
const MODIFY_PRINCIPAL: u32 = 3;
const RENAME_PRINCIPAL: u32 = 4;
const GET_PRINCIPAL: u32 = 5;
const CHPASS_PRINCIPAL: u32 = 6;
const CREATE_POLICY: u32 = 8;
const DELETE_POLICY: u32 = 9;
const MODIFY_POLICY: u32 = 10;
const GET_POLICY: u32 = 11;
const GET_PRIVS: u32 = 12;
const INIT: u32 = 13;
const GET_PRINCS: u32 = 14;
const GET_POLS: u32 = 15;
const CHRAND_PRINCIPAL3: u32 = 20;
const GET_STRINGS: u32 = 23;
const SET_STRING: u32 = 24;
const EXTRACT_KEYS: u32 = 26;

// Principal field masks (kadm5/admin.h).
const KADM5_PRINCIPAL: u32 = 0x00_0001;
const KADM5_PRINC_EXPIRE_TIME: u32 = 0x00_0002;
const KADM5_PW_EXPIRATION: u32 = 0x00_0004;
const KADM5_ATTRIBUTES: u32 = 0x00_0010;
const KADM5_MAX_LIFE: u32 = 0x00_0020;
const KADM5_KVNO: u32 = 0x00_0100;
const KADM5_POLICY: u32 = 0x00_0800;
const KADM5_POLICY_CLR: u32 = 0x00_1000;
const KADM5_MAX_RLIFE: u32 = 0x00_2000;
const KADM5_FAIL_AUTH_COUNT: u32 = 0x01_0000;
/// `KADM5_PRINCIPAL_NORMAL_MASK`, plus key data, as `getprinc` asks.
const GET_MASK: u32 = 0x41_ffff | 0x02_0000;

// Policy field masks.
const KADM5_PW_MAX_LIFE: u32 = 0x0000_4000;
const KADM5_PW_MIN_LIFE: u32 = 0x0000_8000;
const KADM5_PW_MIN_LENGTH: u32 = 0x0001_0000;
const KADM5_PW_MIN_CLASSES: u32 = 0x0002_0000;
const KADM5_PW_HISTORY_NUM: u32 = 0x0004_0000;
const KADM5_PW_MAX_FAILURE: u32 = 0x0010_0000;
const KADM5_PW_FAILURE_COUNT_INTERVAL: u32 = 0x0020_0000;
const KADM5_PW_LOCKOUT_DURATION: u32 = 0x0040_0000;
const KADM5_POLICY_ATTRIBUTES: u32 = 0x0080_0000;
const KADM5_POLICY_MAX_LIFE: u32 = 0x0100_0000;
const KADM5_POLICY_MAX_RLIFE: u32 = 0x0200_0000;
const KADM5_POLICY_ALLOWED_KEYSALTS: u32 = 0x0400_0000;

/// Principal attributes (`KRB5_KDB_*`), for [`PrincipalEntry::attributes`]
/// and [`PrincipalChanges::attributes`]: what `kadmin`'s `+preauth`,
/// `-allow_tix` and the like set and clear.
pub mod attributes {
    pub const DISALLOW_POSTDATED: u32 = 0x0000_0001;
    pub const DISALLOW_FORWARDABLE: u32 = 0x0000_0002;
    pub const DISALLOW_TGT_BASED: u32 = 0x0000_0004;
    pub const DISALLOW_RENEWABLE: u32 = 0x0000_0008;
    pub const DISALLOW_PROXIABLE: u32 = 0x0000_0010;
    pub const DISALLOW_DUP_SKEY: u32 = 0x0000_0020;
    pub const DISALLOW_ALL_TIX: u32 = 0x0000_0040;
    pub const REQUIRES_PRE_AUTH: u32 = 0x0000_0080;
    pub const REQUIRES_HW_AUTH: u32 = 0x0000_0100;
    pub const REQUIRES_PWCHANGE: u32 = 0x0000_0200;
    pub const DISALLOW_SVR: u32 = 0x0000_1000;
    pub const PWCHANGE_SERVICE: u32 = 0x0000_2000;
    pub const NEW_PRINC: u32 = 0x0000_8000;
    pub const OK_AS_DELEGATE: u32 = 0x0010_0000;
    pub const OK_TO_AUTH_AS_DELEGATE: u32 = 0x0020_0000;
    pub const NO_AUTH_DATA_REQUIRED: u32 = 0x0040_0000;
    pub const LOCKDOWN_KEYS: u32 = 0x0080_0000;
}

const KADM5_ERRORS: [(&str, &str); 64] = [
    ("KADM5_FAILURE", "Operation failed for unspecified reason"),
    ("KADM5_AUTH_GET", "Operation requires 'get' privilege"),
    ("KADM5_AUTH_ADD", "Operation requires 'add' privilege"),
    ("KADM5_AUTH_MODIFY", "Operation requires 'modify' privilege"),
    ("KADM5_AUTH_DELETE", "Operation requires 'delete' privilege"),
    (
        "KADM5_AUTH_INSUFFICIENT",
        "Insufficient authorization for operation",
    ),
    ("KADM5_BAD_DB", "Database inconsistency detected"),
    ("KADM5_DUP", "Principal or policy already exists"),
    ("KADM5_RPC_ERROR", "Communication failure with server"),
    ("KADM5_NO_SRV", "No administration server found for realm"),
    (
        "KADM5_BAD_HIST_KEY",
        "Password history entry (kadmin/history) contains unsupported key type",
    ),
    ("KADM5_NOT_INIT", "Connection to server not initialized"),
    ("KADM5_UNK_PRINC", "Principal does not exist"),
    ("KADM5_UNK_POLICY", "Policy does not exist"),
    ("KADM5_BAD_MASK", "Invalid field mask for operation"),
    ("KADM5_BAD_CLASS", "Invalid number of character classes"),
    ("KADM5_BAD_LENGTH", "Invalid password length"),
    ("KADM5_BAD_POLICY", "Illegal policy name"),
    ("KADM5_BAD_PRINCIPAL", "Illegal principal name"),
    ("KADM5_BAD_AUX_ATTR", "Invalid auxiliary attributes"),
    ("KADM5_BAD_HISTORY", "Invalid password history count"),
    (
        "KADM5_BAD_MIN_PASS_LIFE",
        "Password minimum life is greater than password maximum life",
    ),
    ("KADM5_PASS_Q_TOOSHORT", "Password is too short"),
    (
        "KADM5_PASS_Q_CLASS",
        "Password does not contain enough character classes",
    ),
    (
        "KADM5_PASS_Q_DICT",
        "Password is in the password dictionary",
    ),
    ("KADM5_PASS_REUSE", "Cannot reuse password"),
    (
        "KADM5_PASS_TOOSOON",
        "Current password's minimum life has not expired",
    ),
    ("KADM5_POLICY_REF", "Policy is in use"),
    ("KADM5_INIT", "Connection to server already initialized"),
    ("KADM5_BAD_PASSWORD", "Incorrect password"),
    (
        "KADM5_PROTECT_PRINCIPAL",
        "Cannot change protected principal",
    ),
    (
        "KADM5_BAD_SERVER_HANDLE",
        "Programmer error!  Bad Admin server handle",
    ),
    (
        "KADM5_BAD_STRUCT_VERSION",
        "Programmer error!  Bad API structure version",
    ),
    (
        "KADM5_OLD_STRUCT_VERSION",
        "API structure version specified by application is no longer supported (to fix, recompile application against current KADM5 API header files and libraries)",
    ),
    (
        "KADM5_NEW_STRUCT_VERSION",
        "API structure version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)",
    ),
    (
        "KADM5_BAD_API_VERSION",
        "Programmer error!  Bad API version",
    ),
    (
        "KADM5_OLD_LIB_API_VERSION",
        "API version specified by application is no longer supported by libraries (to fix, update application to adhere to current API version and recompile)",
    ),
    (
        "KADM5_OLD_SERVER_API_VERSION",
        "API version specified by application is no longer supported by server (to fix, update application to adhere to current API version and recompile)",
    ),
    (
        "KADM5_NEW_LIB_API_VERSION",
        "API version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)",
    ),
    (
        "KADM5_NEW_SERVER_API_VERSION",
        "API version specified by application is unknown to server (to fix, obtain and install newest KADM5 Admin Server)",
    ),
    (
        "KADM5_SECURE_PRINC_MISSING",
        "Database error! Required KADM5 principal missing",
    ),
    (
        "KADM5_NO_RENAME_SALT",
        "The salt type of the specified principal does not support renaming",
    ),
    (
        "KADM5_BAD_CLIENT_PARAMS",
        "Illegal configuration parameter for remote KADM5 client",
    ),
    (
        "KADM5_BAD_SERVER_PARAMS",
        "Illegal configuration parameter for local KADM5 client",
    ),
    ("KADM5_AUTH_LIST", "Operation requires 'list' privilege"),
    (
        "KADM5_AUTH_CHANGEPW",
        "Operation requires 'change-password' privilege",
    ),
    ("KADM5_GSS_ERROR", "GSS-API (or Kerberos) error"),
    (
        "KADM5_BAD_TL_TYPE",
        "Programmer error!  Illegal tagged data list type",
    ),
    (
        "KADM5_MISSING_CONF_PARAMS",
        "Required parameters in kdc.conf missing",
    ),
    ("KADM5_BAD_SERVER_NAME", "Bad krb5 admin server hostname"),
    (
        "KADM5_AUTH_SETKEY",
        "Operation requires 'set-key' privilege",
    ),
    (
        "KADM5_SETKEY_DUP_ENCTYPES",
        "Multiple values for single or folded enctype",
    ),
    (
        "KADM5_SETV4KEY_INVAL_ENCTYPE",
        "Invalid enctype for setv4key",
    ),
    (
        "KADM5_SETKEY3_ETYPE_MISMATCH",
        "Mismatched enctypes for setkey3",
    ),
    (
        "KADM5_MISSING_KRB5_CONF_PARAMS",
        "Missing parameters in krb5.conf required for kadmin client",
    ),
    ("KADM5_XDR_FAILURE", "XDR encoding error"),
    (
        "KADM5_CANT_RESOLVE",
        "Cannot resolve network address for admin server in requested realm",
    ),
    (
        "KADM5_PASS_Q_GENERIC",
        "Unspecified password quality failure",
    ),
    ("KADM5_BAD_KEYSALTS", "Invalid key/salt tuples"),
    (
        "KADM5_SETKEY_BAD_KVNO",
        "Invalid multiple or duplicate kvnos in setkey operation",
    ),
    (
        "KADM5_AUTH_EXTRACT",
        "Operation requires 'extract-keys' privilege",
    ),
    ("KADM5_PROTECT_KEYS", "Principal keys are locked down"),
    ("KADM5_AUTH_INITIAL", "Operation requires initial ticket"),
    (
        "KADM5_ALIAS_REALM",
        "Alias target must be within the same realm",
    ),
];

/// `ERROR_TABLE_BASE_ovk`: the first kadm5 error code.
const KADM5_ERROR_BASE: u32 = 43_787_520;
const KADM5_UNK_PRINC: u32 = KADM5_ERROR_BASE + 12;
const KADM5_NEW_SERVER_API_VERSION: u32 = KADM5_ERROR_BASE + 39;
/// `ERROR_TABLE_BASE_krb5`, as an unsigned 32-bit code.
const KRB5_ERROR_BASE: u32 = (-1_765_328_384i32) as u32;

/// An error code from `kadmind`: a kadm5 one (`KADM5_*`), or a Kerberos
/// one passed through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kadm5Code(pub u32);

impl Kadm5Code {
    /// MIT's name for the code, e.g. `KADM5_UNK_PRINC`.
    pub fn name(self) -> Option<&'static str> {
        let i = self.0.checked_sub(KADM5_ERROR_BASE)? as usize;
        KADM5_ERRORS.get(i).map(|(n, _)| *n)
    }

    fn message(self) -> String {
        if let Some((_, m)) = self
            .0
            .checked_sub(KADM5_ERROR_BASE)
            .and_then(|i| KADM5_ERRORS.get(i as usize))
        {
            return (*m).to_string();
        }
        match self.0.checked_sub(KRB5_ERROR_BASE) {
            Some(n) if n < 256 => format!(
                "Kerberos error {n} ({})",
                crate::client::kdc_error_name(n as i32)
            ),
            _ => format!("error code {}", self.0 as i32),
        }
    }

    /// The principal does not exist (`KADM5_UNK_PRINC`).
    pub fn is_unknown_principal(self) -> bool {
        self.0 == KADM5_UNK_PRINC
    }
}

impl std::fmt::Display for Kadm5Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name() {
            Some(n) => write!(f, "{n}: {}", self.message()),
            None => f.write_str(&self.message()),
        }
    }
}

/// A kadmin failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `kadmind` refused the operation.
    #[error("kadmind: {0}")]
    Kadm5(Kadm5Code),
    /// Getting the admin's ticket failed.
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("kadmin connection: {0}")]
    Io(std::io::Error),
    /// The RPC layer refused the call (program, version, authentication).
    #[error("kadmin RPC: {0}")]
    Rpc(String),
    /// A reply that does not parse or does not verify.
    #[error("kadmin protocol: {0}")]
    Protocol(String),
    #[error("kadmin: {0}")]
    Config(String),
    /// Writing the keytab (`ktadd`).
    #[error("keytab: {0}")]
    Keytab(#[from] crate::acceptor::KerberosError),
}

impl From<crate::config::ConfigError> for Error {
    fn from(e: crate::config::ConfigError) -> Self {
        Error::Client(ClientError::Config(e))
    }
}

impl Error {
    /// The kadm5 code, when `kadmind` sent one.
    pub fn code(&self) -> Option<Kadm5Code> {
        match self {
            Error::Kadm5(c) => Some(*c),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ------------------------------------------------------- principal names

/// MIT's `krb5_unparse_name`: components joined by `/`, then `@REALM`,
/// with `/`, `@`, `\` and the control characters MIT names escaped.
pub(crate) fn unparse(p: &Principal) -> String {
    fn esc(s: &str, out: &mut String, in_realm: bool) {
        for c in s.chars() {
            match c {
                '/' if !in_realm => out.push_str("\\/"),
                '@' => out.push_str("\\@"),
                '\\' => out.push_str("\\\\"),
                '\0' => out.push_str("\\0"),
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\u{8}' => out.push_str("\\b"),
                c => out.push(c),
            }
        }
    }
    let mut out = String::new();
    for (i, c) in p.components.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        esc(c, &mut out, false);
    }
    out.push('@');
    esc(&p.realm, &mut out, true);
    out
}

/// MIT's `krb5_parse_name` for a full name, backslash escapes included.
pub(crate) fn parse_name(s: &str) -> Result<Principal> {
    let mut components = vec![String::new()];
    let mut realm = String::new();
    let mut in_realm = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        let c = match c {
            '\\' => match chars.next() {
                Some('0') => '\0',
                Some('n') => '\n',
                Some('t') => '\t',
                Some('b') => '\u{8}',
                Some(e) => e,
                None => return Err(Error::Protocol(format!("bad principal name {s:?}"))),
            },
            '/' if !in_realm => {
                components.push(String::new());
                continue;
            }
            '@' if !in_realm => {
                in_realm = true;
                continue;
            }
            c => c,
        };
        if in_realm {
            realm.push(c);
        } else {
            components.last_mut().expect("never empty").push(c);
        }
    }
    let realm = in_realm.then_some(realm);
    let realm = realm
        .filter(|r| !r.is_empty())
        .ok_or_else(|| Error::Protocol(format!("principal name {s:?} has no realm")))?;
    let name_type = if components.first().is_some_and(|c| c == "krbtgt") {
        2
    } else {
        1
    };
    Ok(Principal::new(name_type, components, realm))
}

// ------------------------------------------------------------- the types

/// A key's description in a principal entry (`kadmin getprinc` lists
/// these): its kvno, enctype and salt type. The key itself never leaves
/// `kadmind` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInfo {
    pub kvno: u32,
    pub enctype: i32,
    /// `KRB5_KDB_SALTTYPE_*`: 0 normal, 3 only-realm, 4 special.
    pub salt_type: i32,
}

/// `kadm5_principal_ent_rec`: a principal's database entry. Times are
/// Unix seconds and durations seconds, 0 meaning never or unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalEntry {
    pub principal: Principal,
    pub princ_expire_time: i64,
    pub last_pwd_change: i64,
    pub pw_expiration: i64,
    pub max_life: i64,
    pub mod_name: Option<Principal>,
    pub mod_date: i64,
    /// [`attributes`] bits.
    pub attributes: u32,
    pub kvno: u32,
    pub mkvno: u32,
    pub policy: Option<String>,
    pub aux_attributes: u32,
    pub max_renewable_life: i64,
    pub last_success: i64,
    pub last_failed: i64,
    pub fail_auth_count: u32,
    pub keys: Vec<KeyInfo>,
    /// Tagged data (`KRB5_TL_*`), as kadmind sent it.
    pub tl_data: Vec<(i16, Vec<u8>)>,
}

/// What to set when creating or modifying a principal: each `Some` is
/// sent, with its bit in the field mask, as `kadmin`'s `addprinc` and
/// `modprinc` options do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrincipalChanges {
    /// `-expire`: Unix seconds, 0 for never.
    pub princ_expire_time: Option<i64>,
    /// `-pwexpire`.
    pub pw_expiration: Option<i64>,
    /// `-maxlife`, seconds.
    pub max_life: Option<i64>,
    /// `-maxrenewlife`, seconds.
    pub max_renewable_life: Option<i64>,
    /// The whole attribute word ([`attributes`]); see
    /// [`PrincipalChanges::with_attributes`] to set and clear bits.
    pub attributes: Option<u32>,
    /// `-kvno`.
    pub kvno: Option<u32>,
    /// `-policy name` (`Some(Some(..))`) or `-clearpolicy` (`Some(None)`).
    pub policy: Option<Option<String>>,
    /// `-unlock`: resets the failed-authentication count.
    pub unlock: bool,
}

impl PrincipalChanges {
    /// The attribute word of `entry` with `set` bits set and `clear` bits
    /// cleared, as `modprinc +x -y` changes it.
    pub fn with_attributes(mut self, entry: &PrincipalEntry, set: u32, clear: u32) -> Self {
        self.attributes = Some((entry.attributes | set) & !clear);
        self
    }

    fn mask(&self) -> u32 {
        let mut m = 0;
        let mut bit = |on: bool, b: u32| {
            if on {
                m |= b;
            }
        };
        bit(self.princ_expire_time.is_some(), KADM5_PRINC_EXPIRE_TIME);
        bit(self.pw_expiration.is_some(), KADM5_PW_EXPIRATION);
        bit(self.max_life.is_some(), KADM5_MAX_LIFE);
        bit(self.max_renewable_life.is_some(), KADM5_MAX_RLIFE);
        bit(self.attributes.is_some(), KADM5_ATTRIBUTES);
        bit(self.kvno.is_some(), KADM5_KVNO);
        bit(matches!(self.policy, Some(Some(_))), KADM5_POLICY);
        bit(matches!(self.policy, Some(None)), KADM5_POLICY_CLR);
        bit(self.unlock, KADM5_FAIL_AUTH_COUNT);
        m
    }
}

/// `kadm5_policy_ent_rec`: a password policy. Durations are seconds.
///
/// [`Policy::default`] is what `kadmind` gives a policy made by `addpol`
/// with no options: minimum length, character classes and history 1,
/// everything else 0 (no limit). kadmind refuses less than 1 for those.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    pub pw_min_life: i64,
    pub pw_max_life: i64,
    pub pw_min_length: i64,
    pub pw_min_classes: i64,
    pub pw_history_num: i64,
    /// Principals using the policy, read only; MIT has not kept this count
    /// since 1.12 and reports 0.
    pub policy_refcnt: i64,
    pub pw_max_fail: u32,
    pub pw_failcnt_interval: i64,
    pub pw_lockout_duration: i64,
    /// API version 4 (MIT 1.18+) only.
    pub attributes: u32,
    pub max_life: i64,
    pub max_renewable_life: i64,
    pub allowed_keysalts: Option<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            name: String::new(),
            pw_min_life: 0,
            pw_max_life: 0,
            pw_min_length: 1,
            pw_min_classes: 1,
            pw_history_num: 1,
            policy_refcnt: 0,
            pw_max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            attributes: 0,
            max_life: 0,
            max_renewable_life: 0,
            allowed_keysalts: None,
        }
    }
}

/// What [`AdminClient::privileges`] reports the admin may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Privileges(pub u32);

impl Privileges {
    pub fn get(self) -> bool {
        self.0 & 0x01 != 0
    }
    pub fn add(self) -> bool {
        self.0 & 0x02 != 0
    }
    pub fn modify(self) -> bool {
        self.0 & 0x04 != 0
    }
    pub fn delete(self) -> bool {
        self.0 & 0x08 != 0
    }
}

// ------------------------------------------------------------ XDR codecs

/// `xdr_krb5_principal`: the unparsed name as a nullstring.
fn put_principal(w: &mut Writer, p: Option<&Principal>) {
    w.nullstring(p.map(unparse).as_deref());
}

fn get_principal_name(r: &mut Reader<'_>) -> Result<Option<Principal>> {
    r.nullstring()?.map(|s| parse_name(&s)).transpose()
}

/// The principal entry, as `_xdr_kadm5_principal_ent_rec` lays it out.
/// Only what `mask` names is meaningful to kadmind; the rest is zero.
fn put_principal_entry(w: &mut Writer, p: &Principal, c: &PrincipalChanges) {
    put_principal(w, Some(p));
    w.i32(c.princ_expire_time.unwrap_or(0) as i32)
        .i32(0) // last_pwd_change
        .i32(c.pw_expiration.unwrap_or(0) as i32)
        .i32(c.max_life.unwrap_or(0) as i32)
        .bool(true) // mod_name: NULL (xdr_nulltype's TRUE)
        .i32(0) // mod_date
        .i32(c.attributes.unwrap_or(0) as i32)
        .u32(c.kvno.unwrap_or(0))
        .u32(0); // mkvno
    w.nullstring(match &c.policy {
        Some(Some(name)) => Some(name.as_str()),
        _ => None,
    });
    w.i32(0) // aux_attributes
        .i32(c.max_renewable_life.unwrap_or(0) as i32)
        .i32(0) // last_success
        .i32(0) // last_failed
        .u32(0) // fail_auth_count
        .i32(0) // n_key_data
        .i32(0) // n_tl_data
        .bool(true) // tl_data: NULL
        .u32(0); // key_data: an empty array
}

fn get_principal_entry(r: &mut Reader<'_>) -> Result<PrincipalEntry> {
    let principal = get_principal_name(r)?
        .ok_or_else(|| Error::Protocol("principal entry without a principal".into()))?;
    let princ_expire_time = i64::from(r.i32()?);
    let last_pwd_change = i64::from(r.i32()?);
    let pw_expiration = i64::from(r.i32()?);
    let max_life = i64::from(r.i32()?);
    let mod_name = if r.bool()? {
        None
    } else {
        get_principal_name(r)?
    };
    let mod_date = i64::from(r.i32()?);
    let attributes = r.u32()?;
    let kvno = r.u32()?;
    let mkvno = r.u32()?;
    let policy = r.nullstring()?;
    let aux_attributes = r.u32()?;
    let max_renewable_life = i64::from(r.i32()?);
    let last_success = i64::from(r.i32()?);
    let last_failed = i64::from(r.i32()?);
    let fail_auth_count = r.u32()?;
    let _n_key_data = r.i32()?;
    let _n_tl_data = r.i32()?;
    let mut tl_data = Vec::new();
    if !r.bool()? {
        // xdr_krb5_tl_data: (more, type, bytes)... until more is FALSE.
        // MIT's decoder reverses the list; this keeps the wire order.
        while r.bool()? {
            let ty = r.i32()? as i16;
            tl_data.push((ty, r.opaque()?.to_vec()));
        }
    }
    let n = r.count(12)?;
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        // xdr_krb5_key_data_nocontents: ver, kvno, type[0], type[1] if ver > 1.
        let ver = r.i32()?;
        let kvno = r.u32()?;
        let enctype = r.i32()?;
        let salt_type = if ver > 1 { r.i32()? } else { 0 };
        keys.push(KeyInfo {
            kvno,
            enctype,
            salt_type,
        });
    }
    Ok(PrincipalEntry {
        principal,
        princ_expire_time,
        last_pwd_change,
        pw_expiration,
        max_life,
        mod_name,
        mod_date,
        attributes,
        kvno,
        mkvno,
        policy,
        aux_attributes,
        max_renewable_life,
        last_success,
        last_failed,
        fail_auth_count,
        keys,
        tl_data,
    })
}

/// `_xdr_kadm5_policy_ent_rec` for API version `v`.
fn put_policy(w: &mut Writer, p: &Policy, v: u32) {
    w.nullstring(Some(&p.name));
    w.i32(p.pw_min_life as i32)
        .i32(p.pw_max_life as i32)
        .i32(p.pw_min_length as i32)
        .i32(p.pw_min_classes as i32)
        .i32(p.pw_history_num as i32)
        .i32(0); // policy_refcnt
    if v >= API_VERSION_3 {
        w.u32(p.pw_max_fail)
            .i32(p.pw_failcnt_interval as i32)
            .i32(p.pw_lockout_duration as i32);
    }
    if v >= API_VERSION_4 {
        w.i32(p.attributes as i32)
            .i32(p.max_life as i32)
            .i32(p.max_renewable_life as i32);
        w.nullstring(p.allowed_keysalts.as_deref());
        w.i32(0).bool(true); // n_tl_data, tl_data NULL
    }
}

fn get_policy(r: &mut Reader<'_>, v: u32) -> Result<Policy> {
    let name = r.nullstring()?.unwrap_or_default();
    let mut p = Policy {
        name,
        pw_min_life: i64::from(r.i32()?),
        pw_max_life: i64::from(r.i32()?),
        pw_min_length: i64::from(r.i32()?),
        pw_min_classes: i64::from(r.i32()?),
        pw_history_num: i64::from(r.i32()?),
        policy_refcnt: i64::from(r.i32()?),
        ..Policy::default()
    };
    if v >= API_VERSION_3 {
        p.pw_max_fail = r.u32()?;
        p.pw_failcnt_interval = i64::from(r.i32()?);
        p.pw_lockout_duration = i64::from(r.i32()?);
    }
    if v >= API_VERSION_4 {
        p.attributes = r.u32()?;
        p.max_life = i64::from(r.i32()?);
        p.max_renewable_life = i64::from(r.i32()?);
        p.allowed_keysalts = r.nullstring()?;
        let _n_tl_data = r.i32()?;
        if !r.bool()? {
            while r.bool()? {
                r.i32()?;
                r.opaque()?;
            }
        }
    }
    Ok(p)
}

/// The policy fields a [`Policy`] sets for create and modify: all those
/// the API version carries.
fn policy_mask(v: u32) -> u32 {
    let mut m = KADM5_PW_MAX_LIFE
        | KADM5_PW_MIN_LIFE
        | KADM5_PW_MIN_LENGTH
        | KADM5_PW_MIN_CLASSES
        | KADM5_PW_HISTORY_NUM;
    if v >= API_VERSION_3 {
        m |= KADM5_PW_MAX_FAILURE | KADM5_PW_FAILURE_COUNT_INTERVAL | KADM5_PW_LOCKOUT_DURATION;
    }
    if v >= API_VERSION_4 {
        m |= KADM5_POLICY_ATTRIBUTES
            | KADM5_POLICY_MAX_LIFE
            | KADM5_POLICY_MAX_RLIFE
            | KADM5_POLICY_ALLOWED_KEYSALTS;
    }
    m
}

/// `xdr_krb5_keyblock`: enctype, then the key octets.
fn get_keyblock(r: &mut Reader<'_>) -> Result<Key> {
    let enctype = r.i32()?;
    let bytes = r.opaque()?.to_vec();
    Key::new(enctype, bytes).map_err(|e| Error::Protocol(format!("key from kadmind: {e}")))
}

// ---------------------------------------------------------------- client

/// A connection to `kadmind`.
#[derive(Debug)]
pub struct AdminClient {
    rpc: rpc::Client,
    api_version: u32,
}

impl AdminClient {
    /// Connect to `server` (`host` or `host:port`, port 749 by default)
    /// with `ticket`, a ticket for `kadmin/admin@REALM` (or
    /// `kadmin/changepw`, which only lets a principal change its own
    /// password), and negotiate the API version.
    pub fn connect(server: &str, ticket: &Credentials) -> Result<Self> {
        let addr = with_port(server, KADMIN_PORT);
        let rpc = rpc::Client::connect(&addr, KADM, KADMVERS, ticket, Duration::from_secs(30))?;
        let mut c = AdminClient {
            rpc,
            api_version: API_VERSION_4,
        };
        // MIT's init_any: INIT with 4, then 3, then 2, while the server
        // says KADM5_NEW_SERVER_API_VERSION.
        for v in [API_VERSION_4, API_VERSION_3, API_VERSION_2] {
            c.api_version = v;
            let mut w = Writer::new();
            w.u32(v);
            let reply = c.rpc.call(INIT, &w.0)?;
            let code = generic(&reply)?;
            if code != KADM5_NEW_SERVER_API_VERSION {
                return match code {
                    0 => Ok(c),
                    code => Err(Error::Kadm5(Kadm5Code(code))),
                };
            }
        }
        Err(Error::Kadm5(Kadm5Code(KADM5_NEW_SERVER_API_VERSION)))
    }

    /// Log in as `admin` with its password (an initial ticket for
    /// `kadmin/admin`, as `kadmin -p admin` gets one) and connect.
    pub fn connect_with_password(
        kdc: &KdcClient,
        admin: &Principal,
        password: &str,
        server: &str,
    ) -> Result<Self> {
        let svc = Principal::new(1, ["kadmin", "admin"], admin.realm.clone());
        let t = kdc.initial_ticket_with_password(admin, password, &svc)?;
        Self::connect(server, &t)
    }

    /// As [`AdminClient::connect_with_password`], with `admin`'s key from
    /// a keytab (`kadmin -k -t keytab -p admin`).
    pub fn connect_with_keytab(
        kdc: &KdcClient,
        admin: &Principal,
        keytab: &Keytab,
        server: &str,
    ) -> Result<Self> {
        let svc = Principal::new(1, ["kadmin", "admin"], admin.realm.clone());
        let t = kdc.initial_ticket_with_keytab(admin, keytab, &svc)?;
        Self::connect(server, &t)
    }

    /// The realm's `admin_server` from `krb5.conf`, as MIT's client reads
    /// it, with `kadmind_port` (default 749) unless the entry names a port.
    pub fn admin_server(conf: &Krb5Conf, realm: &str) -> Result<String> {
        let host = conf
            .get(&["realms", realm, "admin_server"])
            .ok_or_else(|| Error::Config(format!("no admin_server for {realm} in krb5.conf")))?;
        let port = conf
            .get(&["realms", realm, "kadmind_port"])
            .and_then(|p| p.parse().ok())
            .unwrap_or(KADMIN_PORT);
        Ok(with_port(host, port))
    }

    /// The kadm5 API version agreed: `0x12345704` for MIT 1.18 and later.
    pub fn api_version(&self) -> u32 {
        self.api_version
    }

    fn call(&mut self, proc_: u32, args: &Writer) -> Result<Vec<u8>> {
        self.rpc.call(proc_, &args.0)
    }

    fn args(&self) -> Writer {
        let mut w = Writer::new();
        w.u32(self.api_version);
        w
    }

    /// A call whose reply is `generic_ret`.
    fn generic_call(&mut self, proc_: u32, args: &Writer) -> Result<()> {
        let reply = self.call(proc_, args)?;
        match generic(&reply)? {
            0 => Ok(()),
            code => Err(Error::Kadm5(Kadm5Code(code))),
        }
    }

    /// `get_privs`. MIT's kadmind answers every bit set, whatever the ACL
    /// says (its `kadm5_get_privs` cannot express ACLs), so this is only
    /// useful against other servers; the ACL is enforced per operation,
    /// with `KADM5_AUTH_*` errors.
    pub fn privileges(&mut self) -> Result<Privileges> {
        let a = self.args();
        let reply = self.call(GET_PRIVS, &a)?;
        let mut r = Reader::new(&reply);
        r.u32()?;
        check(r.u32()?)?;
        let p = r.u32()?;
        r.done()?;
        Ok(Privileges(p))
    }

    /// `getprinc`.
    pub fn get_principal(&mut self, p: &Principal) -> Result<PrincipalEntry> {
        let mut a = self.args();
        put_principal(&mut a, Some(p));
        a.u32(GET_MASK);
        let reply = self.call(GET_PRINCIPAL, &a)?;
        let mut r = Reader::new(&reply);
        r.u32()?;
        check(r.u32()?)?;
        let e = get_principal_entry(&mut r)?;
        r.done()?;
        Ok(e)
    }

    /// `listprincs glob`: the principals matching a shell glob (`*` for
    /// all; MIT matches it against the unparsed name).
    pub fn list_principals(&mut self, glob: &str) -> Result<Vec<Principal>> {
        self.list(GET_PRINCS, glob)?
            .iter()
            .map(|s| parse_name(s))
            .collect()
    }

    fn list(&mut self, proc_: u32, glob: &str) -> Result<Vec<String>> {
        let mut a = self.args();
        a.nullstring(Some(glob));
        let reply = self.call(proc_, &a)?;
        let mut r = Reader::new(&reply);
        r.u32()?;
        check(r.u32()?)?;
        let _count = r.i32()?;
        let n = r.count(4)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(
                r.nullstring()?
                    .ok_or_else(|| Error::Protocol("NULL name in a list".into()))?,
            );
        }
        r.done()?;
        Ok(out)
    }

    /// `addprinc`: create `p` with `password`, or, with `None`, random keys
    /// (`addprinc -randkey`). `changes` sets the rest, as `addprinc`'s
    /// options do; what it leaves out kadmind fills from its defaults.
    pub fn create_principal(
        &mut self,
        p: &Principal,
        changes: &PrincipalChanges,
        password: Option<&str>,
    ) -> Result<()> {
        let mut a = self.args();
        put_principal_entry(&mut a, p, changes);
        a.u32(KADM5_PRINCIPAL | changes.mask());
        a.nullstring(password);
        self.generic_call(CREATE_PRINCIPAL, &a)
    }

    /// `modprinc`: change what `changes` sets.
    pub fn modify_principal(&mut self, p: &Principal, changes: &PrincipalChanges) -> Result<()> {
        let mut a = self.args();
        put_principal_entry(&mut a, p, changes);
        a.u32(changes.mask());
        self.generic_call(MODIFY_PRINCIPAL, &a)
    }

    /// `delprinc`.
    pub fn delete_principal(&mut self, p: &Principal) -> Result<()> {
        let mut a = self.args();
        put_principal(&mut a, Some(p));
        self.generic_call(DELETE_PRINCIPAL, &a)
    }

    /// `renprinc`.
    pub fn rename_principal(&mut self, from: &Principal, to: &Principal) -> Result<()> {
        let mut a = self.args();
        put_principal(&mut a, Some(from));
        put_principal(&mut a, Some(to));
        self.generic_call(RENAME_PRINCIPAL, &a)
    }

    /// `cpw`: set `p`'s password. Password-quality rules of its policy
    /// apply, and their failures come back as `KADM5_PASS_Q_*`.
    pub fn change_password(&mut self, p: &Principal, password: &str) -> Result<()> {
        let mut a = self.args();
        put_principal(&mut a, Some(p));
        a.nullstring(Some(password));
        self.generic_call(CHPASS_PRINCIPAL, &a)
    }

    /// `cpw -randkey`: new random keys for `p` (its default enctypes, the
    /// old keys dropped), returned as kadmind made them, with the new
    /// kvno.
    pub fn randomize_keys(&mut self, p: &Principal) -> Result<(u32, Vec<Key>)> {
        let mut a = self.args();
        put_principal(&mut a, Some(p));
        a.bool(false) // keepold
            .u32(0); // ks_tuple: the defaults
        let reply = self.call(CHRAND_PRINCIPAL3, &a)?;
        let mut r = Reader::new(&reply);
        r.u32()?;
        check(r.u32()?)?;
        let n = r.count(8)?;
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            keys.push(get_keyblock(&mut r)?);
        }
        r.done()?;
        let kvno = self.get_principal(p)?.kvno;
        Ok((kvno, keys))
    }

    /// `ktadd -norandkey`'s source: `p`'s current keys, unchanged
    /// (`kvno` `None` for every kvno kadmind holds), with their kvnos.
    /// Needs API version 4 and the extract privilege (`e` in the ACL).
    pub fn extract_keys(&mut self, p: &Principal, kvno: Option<u32>) -> Result<Vec<(u32, Key)>> {
        if self.api_version < API_VERSION_4 {
            return Err(Error::Config(
                "extracting keys needs kadm5 API version 4 (MIT 1.18+)".into(),
            ));
        }
        let mut a = self.args();
        put_principal(&mut a, Some(p));
        a.u32(kvno.unwrap_or(0));
        let reply = self.call(EXTRACT_KEYS, &a)?;
        let mut r = Reader::new(&reply);
        r.u32()?;
        check(r.u32()?)?;
        let n = r.count(16)?;
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            // kadm5_key_data: kvno, keyblock, salt type, salt octets.
            let kvno = r.u32()?;
            let key = get_keyblock(&mut r)?;
            r.i32()?;
            r.opaque()?;
            keys.push((kvno, key));
        }
        r.done()?;
        Ok(keys)
    }

    /// `ktadd`: append `p`'s keys to the keytab at `path` (created if
    /// missing), new random ones with `randomize` (`ktadd`), else its
    /// current ones (`ktadd -norandkey`). Returns what was written.
    pub fn ktadd<P: AsRef<Path>>(
        &mut self,
        p: &Principal,
        path: P,
        randomize: bool,
    ) -> Result<Vec<ServiceKey>> {
        let keys: Vec<(u32, Key)> = if randomize {
            let (kvno, keys) = self.randomize_keys(p)?;
            keys.into_iter().map(|k| (kvno, k)).collect()
        } else {
            self.extract_keys(p, None)?
        };
        let entries: Vec<ServiceKey> = keys
            .iter()
            .filter_map(|(kvno, k)| {
                Some(ServiceKey {
                    principal: p.name(),
                    realm: p.realm.clone(),
                    kvno: *kvno,
                    enctype: EncType::from_i32(k.enctype())?,
                    key: k.bytes().to_vec(),
                })
            })
            .collect();
        Keytab::append_to(path, &entries)?;
        Ok(entries)
    }

    /// `getpol`.
    pub fn get_policy(&mut self, name: &str) -> Result<Policy> {
        let mut a = self.args();
        a.nullstring(Some(name));
        let reply = self.call(GET_POLICY, &a)?;
        let mut r = Reader::new(&reply);
        r.u32()?;
        check(r.u32()?)?;
        let p = get_policy(&mut r, self.api_version)?;
        r.done()?;
        Ok(p)
    }

    /// `listpols glob`.
    pub fn list_policies(&mut self, glob: &str) -> Result<Vec<String>> {
        self.list(GET_POLS, glob)
    }

    /// `addpol`: every field of `policy` the API version carries is set.
    pub fn create_policy(&mut self, policy: &Policy) -> Result<()> {
        let mut a = self.args();
        put_policy(&mut a, policy, self.api_version);
        a.u32(0x00_0800 | policy_mask(self.api_version)); // KADM5_POLICY: the name
        self.generic_call(CREATE_POLICY, &a)
    }

    /// `modpol`: every field of `policy` the API version carries is set.
    pub fn modify_policy(&mut self, policy: &Policy) -> Result<()> {
        let mut a = self.args();
        put_policy(&mut a, policy, self.api_version);
        a.u32(policy_mask(self.api_version));
        self.generic_call(MODIFY_POLICY, &a)
    }

    /// `delpol`.
    pub fn delete_policy(&mut self, name: &str) -> Result<()> {
        let mut a = self.args();
        a.nullstring(Some(name));
        self.generic_call(DELETE_POLICY, &a)
    }

    /// `getstrs`: `p`'s string attributes.
    pub fn get_strings(&mut self, p: &Principal) -> Result<Vec<(String, String)>> {
        let mut a = self.args();
        put_principal(&mut a, Some(p));
        let reply = self.call(GET_STRINGS, &a)?;
        let mut r = Reader::new(&reply);
        r.u32()?;
        check(r.u32()?)?;
        let _count = r.i32()?;
        let n = r.count(8)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let k = r.nullstring()?.unwrap_or_default();
            let v = r.nullstring()?.unwrap_or_default();
            out.push((k, v));
        }
        r.done()?;
        Ok(out)
    }

    /// `setstr` (`value` `Some`) and `delstr` (`None`).
    pub fn set_string(&mut self, p: &Principal, key: &str, value: Option<&str>) -> Result<()> {
        let mut a = self.args();
        put_principal(&mut a, Some(p));
        a.nullstring(Some(key)).nullstring(value);
        self.generic_call(SET_STRING, &a)
    }

    /// Close the connection, dropping the context at the server.
    pub fn close(mut self) {
        self.rpc.destroy();
    }
}

/// `generic_ret ::= { api_version, code }`.
fn generic(reply: &[u8]) -> Result<u32> {
    let mut r = Reader::new(reply);
    r.u32()?;
    let code = r.u32()?;
    r.done()?;
    Ok(code)
}

fn check(code: u32) -> Result<()> {
    match code {
        0 => Ok(()),
        c => Err(Error::Kadm5(Kadm5Code(c))),
    }
}

/// `host` with `:port` unless it names one (`[v6]:port` too).
fn with_port(host: &str, port: u16) -> String {
    let has_port = match host.rsplit_once(':') {
        Some((h, p)) => p.parse::<u16>().is_ok() && (!h.contains(':') || h.ends_with(']')),
        None => false,
    };
    if has_port {
        host.to_string()
    } else if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_unparse_and_parse_as_mit_does() {
        for (p, s) in [
            (Principal::new(1, ["alice"], "A.ORG"), "alice@A.ORG"),
            (
                Principal::new(1, ["host", "h.a.org"], "A.ORG"),
                "host/h.a.org@A.ORG",
            ),
            (
                Principal::new(1, ["we/ird", "a@b", "back\\slash"], "R@ALM"),
                "we\\/ird/a\\@b/back\\\\slash@R\\@ALM",
            ),
            (
                Principal::new(1, ["tab\there", "nl\n"], "R"),
                "tab\\there/nl\\n@R",
            ),
        ] {
            assert_eq!(unparse(&p), s);
            assert_eq!(parse_name(s).unwrap(), p, "{s}");
        }
        // krbtgt gets NT_SRV_INST, as krb5_parse_name gives it.
        assert_eq!(parse_name("krbtgt/A@A").unwrap(), Principal::krbtgt("A"));
        for bad in ["noatsign", "x@", "trailing\\"] {
            assert!(parse_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_principal_entry_decodes_as_mit_lays_it_out() {
        let mut w = Writer::new();
        w.nullstring(Some("svc/h@R"))
            .i32(10)
            .i32(11)
            .i32(12)
            .i32(3600)
            .bool(false)
            .nullstring(Some("admin/admin@R"))
            .i32(13)
            .u32(attributes::REQUIRES_PRE_AUTH)
            .u32(3)
            .u32(1)
            .nullstring(Some("default"))
            .u32(0)
            .i32(7200)
            .i32(14)
            .i32(15)
            .u32(2)
            .i32(2) // n_key_data
            .i32(1) // n_tl_data
            .bool(false) // tl_data present
            .bool(true)
            .i32(2)
            .opaque(b"tl")
            .bool(false)
            .u32(2) // key_data array
            .i32(2)
            .u32(3)
            .i32(18)
            .i32(0)
            .i32(1) // version 1: no salt type
            .u32(3)
            .i32(17);
        let e = get_principal_entry(&mut Reader::new(&w.0)).unwrap();
        assert_eq!(e.principal, Principal::new(1, ["svc", "h"], "R"));
        assert_eq!(e.mod_name, Some(Principal::new(1, ["admin", "admin"], "R")));
        assert_eq!(
            (e.princ_expire_time, e.max_life, e.kvno, e.fail_auth_count),
            (10, 3600, 3, 2)
        );
        assert_eq!(e.policy.as_deref(), Some("default"));
        assert_eq!(e.tl_data, [(2, b"tl".to_vec())]);
        assert_eq!(
            e.keys,
            [
                KeyInfo {
                    kvno: 3,
                    enctype: 18,
                    salt_type: 0
                },
                KeyInfo {
                    kvno: 3,
                    enctype: 17,
                    salt_type: 0
                }
            ]
        );
        // Truncated anywhere: an error, not a panic.
        for cut in 0..w.0.len() {
            assert!(
                get_principal_entry(&mut Reader::new(&w.0[..cut])).is_err() || cut == w.0.len()
            );
        }
    }

    #[test]
    fn changes_set_exactly_their_mask_bits() {
        assert_eq!(PrincipalChanges::default().mask(), 0);
        let c = PrincipalChanges {
            max_life: Some(1),
            policy: Some(None),
            unlock: true,
            ..PrincipalChanges::default()
        };
        assert_eq!(
            c.mask(),
            KADM5_MAX_LIFE | KADM5_POLICY_CLR | KADM5_FAIL_AUTH_COUNT
        );
        let c = PrincipalChanges {
            policy: Some(Some("p".into())),
            ..PrincipalChanges::default()
        };
        assert_eq!(c.mask(), KADM5_POLICY);
    }

    #[test]
    fn kadm5_codes_are_named_as_mit_names_them() {
        assert_eq!(Kadm5Code(43_787_532).name(), Some("KADM5_UNK_PRINC"));
        assert!(Kadm5Code(43_787_532).is_unknown_principal());
        assert_eq!(Kadm5Code(43_787_582).name(), Some("KADM5_AUTH_INITIAL"));
        assert!(
            Kadm5Code(KRB5_ERROR_BASE + 24)
                .to_string()
                .contains("PREAUTH_FAILED")
        );
        assert_eq!(Kadm5Code(5).name(), None);
    }

    #[test]
    fn ports_are_added_unless_named() {
        assert_eq!(with_port("kdc.a.org", 749), "kdc.a.org:749");
        assert_eq!(with_port("kdc.a.org:1749", 749), "kdc.a.org:1749");
        assert_eq!(with_port("2001:db8::1", 749), "[2001:db8::1]:749");
        assert_eq!(with_port("[2001:db8::1]:88", 749), "[2001:db8::1]:88");
    }
}
