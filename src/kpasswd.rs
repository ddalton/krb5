//! Password changes over the kpasswd protocol (port 464): `kpasswd`'s
//! own-password change (version 1, the RFC 3244 predecessor every server
//! speaks) and RFC 3244's set-password for another principal (version
//! `0xff80`), as MIT's `krb5_change_password` and `krb5_set_password`
//! send them, to `kadmind` or Active Directory.
//!
//! ```text
//! request ::= length(2) version(2) ap-req-length(2) AP-REQ KRB-PRIV
//! reply   ::= length(2) version(2) ap-rep-length(2) AP-REP KRB-PRIV   (or a KRB-ERROR)
//! ```
//!
//! The AP-REQ carries a fresh subkey, and the KRB-PRIV, encrypted in it,
//! the new password (or RFC 3244's ChangePasswdData). The reply's AP-REP
//! proves the server knew the ticket's key, and its KRB-PRIV, in the
//! same subkey, holds the result code and text. The ticket is for
//! `kadmin/changepw@REALM`, and for an own-password change must be an
//! initial one, from the old password:
//! [`change_password`] gets it.

use crate::client::{
    ClientError, Credentials, KdcClient, KrbError, Principal, decode_encrypted_data, encode_ap_req,
    encode_authenticator, encode_encrypted_data,
};
use crate::config::Krb5Conf;
use crate::der::{self, Fields, app};
use crate::key::Key;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The default `kpasswd_port`.
pub const KPASSWD_PORT: u16 = 464;

const VERSION_CHANGE: u16 = 1;
const VERSION_SET: u16 = 0xff80;
const KU_AP_REQ_AUTH: u32 = 11;
const KU_AP_REP_ENC_PART: u32 = 12;
/// RFC 4120 §7.5.1: KRB-PRIV's encrypted part.
const KU_KRB_PRIV: u32 = 13;
const ADDRTYPE_INET: i32 = 2;
const ADDRTYPE_INET6: i32 = 24;

/// What the server answered (RFC 3244 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    Malformed,
    HardError,
    AuthError,
    /// The new password was refused (quality, history, minimum life).
    SoftError,
    AccessDenied,
    BadVersion,
    /// The ticket must be an initial one (from the old password).
    InitialFlagNeeded,
    Other(u16),
}

impl ResultCode {
    fn from_u16(c: u16) -> Self {
        match c {
            1 => ResultCode::Malformed,
            2 => ResultCode::HardError,
            3 => ResultCode::AuthError,
            4 => ResultCode::SoftError,
            5 => ResultCode::AccessDenied,
            6 => ResultCode::BadVersion,
            7 => ResultCode::InitialFlagNeeded,
            c => ResultCode::Other(c),
        }
    }
}

/// A kpasswd failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The server refused the change, saying why.
    #[error("password change refused ({code:?}): {message}")]
    Refused { code: ResultCode, message: String },
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("kpasswd: {0}")]
    Io(std::io::Error),
    #[error("kpasswd protocol: {0}")]
    Protocol(String),
    #[error("kpasswd: {0}")]
    Config(String),
}

impl From<der::DerError> for Error {
    fn from(e: der::DerError) -> Self {
        Error::Protocol(e.0)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn bad<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(msg.into()))
}

/// `kpasswd`: log in to `kadmin/changepw` with `old_password` and set
/// `new_password` for `client`.
pub fn change_password(
    kdc: &KdcClient,
    client: &Principal,
    old_password: &str,
    new_password: &str,
    server: &str,
) -> Result<()> {
    let svc = changepw_service(&client.realm);
    let ticket = kdc.initial_ticket_with_password(client, old_password, &svc)?;
    change_password_with_ticket(&ticket, new_password, server)
}

/// Change the password of `ticket`'s client, `ticket` being an initial
/// ticket for `kadmin/changepw@REALM`.
pub fn change_password_with_ticket(
    ticket: &Credentials,
    new_password: &str,
    server: &str,
) -> Result<()> {
    exchange(ticket, VERSION_CHANGE, new_password.as_bytes(), server)
}

/// RFC 3244 set-password: give `target` the password `new_password`,
/// `ticket` being a ticket for `kadmin/changepw@REALM` whose client the
/// server allows to (an administrator, in MIT's ACL; or `target` itself).
pub fn set_password(
    ticket: &Credentials,
    target: &Principal,
    new_password: &str,
    server: &str,
) -> Result<()> {
    // ChangePasswdData ::= SEQUENCE { newpasswd [0] OCTET STRING,
    //     targname [1] PrincipalName OPTIONAL, targrealm [2] Realm OPTIONAL }
    let data = der::seq(&[
        der::field(0, der::octets(new_password.as_bytes())),
        der::field(1, target.encode_name()),
        der::field(2, der::general_string(&target.realm)),
    ]);
    exchange(ticket, VERSION_SET, &data, server)
}

/// `kadmin/changepw@realm`.
pub fn changepw_service(realm: &str) -> Principal {
    Principal::new(1, ["kadmin", "changepw"], realm)
}

/// The realm's kpasswd server from `krb5.conf`, as MIT finds it:
/// `kpasswd_server`, else `admin_server`'s host, on port 464 unless the
/// entry names one.
pub fn kpasswd_server(conf: &Krb5Conf, realm: &str) -> Result<String> {
    if let Some(s) = conf.get(&["realms", realm, "kpasswd_server"]) {
        return Ok(with_port(s, KPASSWD_PORT));
    }
    let admin = conf
        .get(&["realms", realm, "admin_server"])
        .ok_or_else(|| Error::Config(format!("no kpasswd_server or admin_server for {realm}")))?;
    // admin_server's port is kadmind's; kpasswd keeps its own.
    let host = match admin.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() && (!h.contains(':') || h.ends_with(']')) => h,
        _ => admin,
    };
    Ok(with_port(host, KPASSWD_PORT))
}

fn with_port(host: &str, port: u16) -> String {
    match host.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() && (!h.contains(':') || h.ends_with(']')) => {
            host.to_string()
        }
        _ if host.contains(':') && !host.starts_with('[') => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

fn now() -> (i64, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as i64, d.subsec_micros())
}

/// `HostAddress ::= SEQUENCE { addr-type [0] Int32, address [1] OCTET STRING }`.
fn host_address(ip: IpAddr) -> Vec<u8> {
    let (ty, octets) = match ip {
        IpAddr::V4(a) => (ADDRTYPE_INET, a.octets().to_vec()),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => (ADDRTYPE_INET, v4.octets().to_vec()),
            None => (ADDRTYPE_INET6, a.octets().to_vec()),
        },
    };
    der::seq(&[
        der::field(0, der::int(ty.into())),
        der::field(1, der::octets(&octets)),
    ])
}

/// `KRB-PRIV ::= [APPLICATION 21] SEQUENCE { pvno [0], msg-type [1],
/// enc-part [3] }`, the part being `EncKrbPrivPart ::= [APPLICATION 28]
/// SEQUENCE { user-data [0], timestamp [1], usec [2], seq-number [3],
/// s-address [4] }` in `key`.
fn mk_priv(key: &Key, data: &[u8], seq: u32, sender: IpAddr) -> Result<Vec<u8>> {
    let (t, usec) = now();
    let part = der::cons(
        app(28),
        &[der::seq(&[
            der::field(0, der::octets(data)),
            der::field(1, der::time(t)),
            der::field(2, der::int(usec.into())),
            der::field(3, der::int(seq.into())),
            der::field(4, host_address(sender)),
        ])],
    );
    let cipher = key.encrypt(KU_KRB_PRIV, &part).map_err(ClientError::from)?;
    Ok(der::cons(
        app(21),
        &[der::seq(&[
            der::field(0, der::int(5)),
            der::field(1, der::int(21)),
            der::field(3, encode_encrypted_data(key.enctype(), &cipher)),
        ])],
    ))
}

/// The user data of a KRB-PRIV in `key`.
fn rd_priv(key: &Key, msg: &[u8]) -> Result<Vec<u8>> {
    let f = Fields::parse_tagged("KRB-PRIV", app(21), msg)?;
    if f.get(0)?.int()? != 5 || f.get(1)?.int()? != 21 {
        return bad("KRB-PRIV pvno/msg-type mismatch");
    }
    let (_, cipher) = decode_encrypted_data(f.get(3)?).map_err(Error::Client)?;
    let plain = key
        .decrypt(KU_KRB_PRIV, &cipher)
        .map_err(|e| Error::Protocol(format!("the server's KRB-PRIV does not decrypt: {e}")))?;
    let p = Fields::parse_tagged("EncKrbPrivPart", app(28), &plain)?;
    Ok(p.get(0)?.octets()?.to_vec())
}

/// Send one request (TCP first, then UDP, as MIT does: a UDP retransmit
/// could look like a replay) and read the result.
fn exchange(ticket: &Credentials, version: u16, data: &[u8], server: &str) -> Result<()> {
    let addr = server
        .to_socket_addrs()
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| Error::Config(format!("{server}: no address")))?;
    let subkey = Key::random(ticket.session_key.enctype()).map_err(ClientError::from)?;
    let seq = rand::random::<u32>() & 0x3FFF_FFFF;
    let (ctime, cusec) = now();
    let authenticator =
        encode_authenticator(&ticket.client, None, cusec, ctime, Some(&subkey), Some(seq));
    let enc_auth = ticket
        .session_key
        .encrypt(KU_AP_REQ_AUTH, &authenticator)
        .map_err(ClientError::from)?;
    let ap_req = encode_ap_req(0, &ticket.ticket, ticket.session_key.enctype(), &enc_auth);
    let request = |local: IpAddr| -> Result<Vec<u8>> {
        let priv_ = mk_priv(&subkey, data, seq, local)?;
        let len = 6 + ap_req.len() + priv_.len();
        if len > u16::MAX as usize {
            return bad("kpasswd request too long");
        }
        let mut m = Vec::with_capacity(len);
        m.extend_from_slice(&(len as u16).to_be_bytes());
        m.extend_from_slice(&version.to_be_bytes());
        m.extend_from_slice(&(ap_req.len() as u16).to_be_bytes());
        m.extend_from_slice(&ap_req);
        m.extend_from_slice(&priv_);
        Ok(m)
    };
    let timeout = Duration::from_secs(10);
    let reply = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut s) => {
            s.set_read_timeout(Some(timeout)).map_err(Error::Io)?;
            let local = s.local_addr().map_err(Error::Io)?.ip();
            let req = request(local)?;
            let mut framed = (req.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(&req);
            s.write_all(&framed).map_err(Error::Io)?;
            let mut len = [0u8; 4];
            s.read_exact(&mut len).map_err(Error::Io)?;
            let n = u32::from_be_bytes(len) as usize;
            if n > 65536 {
                return bad("kpasswd reply too long");
            }
            let mut r = vec![0; n];
            s.read_exact(&mut r).map_err(Error::Io)?;
            r
        }
        Err(_) => {
            let bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let u = UdpSocket::bind(bind).map_err(Error::Io)?;
            u.connect(addr).map_err(Error::Io)?;
            u.set_read_timeout(Some(timeout)).map_err(Error::Io)?;
            let local = u.local_addr().map_err(Error::Io)?.ip();
            u.send(&request(local)?).map_err(Error::Io)?;
            let mut buf = vec![0u8; 65536];
            let n = u.recv(&mut buf).map_err(Error::Io)?;
            buf.truncate(n);
            buf
        }
    };
    let result = read_reply(ticket, &subkey, &reply, ctime, cusec)?;
    if result.len() < 2 {
        return bad("kpasswd result too short");
    }
    let code = u16::from_be_bytes([result[0], result[1]]);
    if code == 0 {
        return Ok(());
    }
    Err(Error::Refused {
        code: ResultCode::from_u16(code),
        message: describe(&result[2..]),
    })
}

/// The result octets of a reply (MIT's `get_clear_result`): an AP-REP and
/// KRB-PRIV, or a KRB-ERROR, framed or bare, whose e-data holds them.
fn read_reply(
    ticket: &Credentials,
    subkey: &Key,
    reply: &[u8],
    ctime: i64,
    cusec: u32,
) -> Result<Vec<u8>> {
    let error_result = |e: &[u8]| -> Result<Vec<u8>> {
        let err = KrbError::parse(e).map_err(Error::Client)?;
        match err.e_data {
            Some(d) if d.len() >= 2 => {
                // A KRB-ERROR must not claim success.
                if d[..2] == [0, 0] {
                    return bad("a KRB-ERROR reporting success");
                }
                Ok(d)
            }
            _ => Err(Error::Client(err.into_error())),
        }
    };
    if reply.first() == Some(&app(30)) {
        return error_result(reply);
    }
    if reply.len() < 6 || usize::from(u16::from_be_bytes([reply[0], reply[1]])) != reply.len() {
        return bad("kpasswd reply length does not match");
    }
    let vno = u16::from_be_bytes([reply[2], reply[3]]);
    if vno != VERSION_CHANGE && vno != VERSION_SET {
        return bad(format!("kpasswd reply version {vno:#x}"));
    }
    let ap_len = usize::from(u16::from_be_bytes([reply[4], reply[5]]));
    let rest = &reply[6..];
    if ap_len > rest.len() {
        return bad("kpasswd AP-REP overruns the reply");
    }
    if ap_len == 0 {
        return error_result(rest);
    }
    let (ap_rep, priv_) = rest.split_at(ap_len);
    // The AP-REP: sealed in the ticket's session key, echoing our
    // authenticator's time, which only the holder of the server's key
    // could have read.
    let f = Fields::parse_tagged("AP-REP", app(15), ap_rep)?;
    if f.get(0)?.int()? != 5 || f.get(1)?.int()? != 15 {
        return bad("AP-REP pvno/msg-type mismatch");
    }
    let (_, cipher) = decode_encrypted_data(f.get(2)?).map_err(Error::Client)?;
    let plain = ticket
        .session_key
        .decrypt(KU_AP_REP_ENC_PART, &cipher)
        .map_err(|e| Error::Protocol(format!("the server's AP-REP does not decrypt: {e}")))?;
    let p = Fields::parse_tagged("EncAPRepPart", app(27), &plain)?;
    if p.get(0)?.time()? != ctime || p.get(1)?.u32()? != cusec {
        return bad("the AP-REP does not echo our authenticator (KRB_AP_ERR_MUT_FAIL)");
    }
    // RFC 3244: the reply's KRB-PRIV is in the subkey we sent.
    rd_priv(subkey, priv_)
}

/// The result text: UTF-8, or Active Directory's packed policy (30
/// octets, two zeros first), described as MIT describes it.
fn describe(text: &[u8]) -> String {
    if text.len() == 30 && text[..2] == [0, 0] {
        let u32_at =
            |i: usize| u32::from_be_bytes([text[i], text[i + 1], text[i + 2], text[i + 3]]);
        let u64_at = |i: usize| {
            u64::from_be_bytes([
                text[i],
                text[i + 1],
                text[i + 2],
                text[i + 3],
                text[i + 4],
                text[i + 5],
                text[i + 6],
                text[i + 7],
            ])
        };
        let mut parts = Vec::new();
        let min_len = u32_at(2);
        if min_len > 0 {
            parts.push(format!(
                "The password must include at least {min_len} characters."
            ));
        }
        let history = u32_at(6);
        if history > 0 {
            parts.push(format!(
                "The password must be different from the previous {history} passwords."
            ));
        }
        if u32_at(10) & 1 != 0 {
            parts.push("The password must contain at least three of: uppercase letters, lowercase letters, digits, punctuation.".into());
        }
        let min_age_days = u64_at(22) / (86_400 * 10_000_000);
        if min_age_days > 0 {
            parts.push(format!(
                "The password can only be changed once every {min_age_days} days."
            ));
        }
        return parts.join("  ");
    }
    String::from_utf8_lossy(text).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn krb_priv_round_trips_and_binds_its_key() {
        let k = Key::random(18).unwrap();
        let m = mk_priv(&k, b"new password", 7, "192.0.2.1".parse().unwrap()).unwrap();
        assert_eq!(rd_priv(&k, &m).unwrap(), b"new password");
        assert!(rd_priv(&Key::random(18).unwrap(), &m).is_err());
        let f = Fields::parse_tagged("KRB-PRIV", app(21), &m).unwrap();
        assert!(f.opt(2).is_none(), "no field [2]");
    }

    #[test]
    fn host_addresses_are_rfc_4120() {
        assert_eq!(
            host_address("192.0.2.1".parse().unwrap()),
            [
                0x30, 0x0D, 0xA0, 0x03, 2, 1, 2, 0xA1, 0x06, 4, 4, 192, 0, 2, 1
            ]
        );
        let v6 = host_address("2001:db8::1".parse().unwrap());
        assert_eq!(&v6[2..7], &[0xA0, 0x03, 2, 1, 24]);
        // A v4-mapped v6 socket address is sent as the v4 address.
        assert_eq!(
            host_address("::ffff:192.0.2.1".parse().unwrap()),
            host_address("192.0.2.1".parse().unwrap())
        );
    }

    #[test]
    fn servers_come_from_krb5_conf_as_mit_finds_them() {
        let conf = Krb5Conf::parse(
            "[realms]\n A = {\n  kpasswd_server = kp.a:1464\n  admin_server = adm.a:749\n }\n B = {\n  admin_server = adm.b:749\n }\n C = {\n  admin_server = [2001:db8::1]:749\n }\n",
        )
        .unwrap();
        assert_eq!(kpasswd_server(&conf, "A").unwrap(), "kp.a:1464");
        assert_eq!(kpasswd_server(&conf, "B").unwrap(), "adm.b:464");
        assert_eq!(kpasswd_server(&conf, "C").unwrap(), "[2001:db8::1]:464");
        assert!(kpasswd_server(&conf, "D").is_err());
    }

    /// A KRB-ERROR whose e-data claims success is not success.
    #[test]
    fn an_error_reply_claiming_success_is_refused() {
        let err = |e_data: &[u8]| {
            der::cons(
                app(30),
                &[der::seq(&[
                    der::field(0, der::int(5)),
                    der::field(1, der::int(30)),
                    der::field(4, der::time(0)),
                    der::field(5, der::int(0)),
                    der::field(6, der::int(60)),
                    der::field(9, der::general_string("R")),
                    der::field(
                        10,
                        Principal::new(1, ["kadmin", "changepw"], "R").encode_name(),
                    ),
                    der::field(12, der::octets(e_data)),
                ])],
            )
        };
        let t = Credentials {
            client: Principal::new(1, ["a"], "R"),
            server: changepw_service("R"),
            session_key: Key::random(18).unwrap(),
            ticket: vec![],
            ticket_enctype: 18,
            flags: 0,
            authtime: 0,
            starttime: None,
            endtime: 0,
            renew_till: None,
        };
        let sk = Key::random(18).unwrap();
        assert!(read_reply(&t, &sk, &err(&[0, 0]), 0, 0).is_err());
        assert_eq!(
            read_reply(&t, &sk, &err(b"\x00\x04too short"), 0, 0).unwrap(),
            b"\x00\x04too short"
        );
        // Framed: a zero-length AP-REP, then the error.
        let e = err(&[0, 5]);
        let mut framed = ((6 + e.len()) as u16).to_be_bytes().to_vec();
        framed.extend([0, 1, 0, 0]);
        framed.extend(&e);
        assert_eq!(read_reply(&t, &sk, &framed, 0, 0).unwrap(), [0, 5]);
        framed[1] ^= 1;
        assert!(
            read_reply(&t, &sk, &framed, 0, 0).is_err(),
            "length mismatch"
        );
    }

    #[test]
    fn active_directory_policy_text_is_described() {
        let mut p = vec![0, 0];
        p.extend(8u32.to_be_bytes());
        p.extend(24u32.to_be_bytes());
        p.extend(1u32.to_be_bytes());
        p.extend(0u64.to_be_bytes());
        p.extend((86_400u64 * 10_000_000).to_be_bytes());
        let d = describe(&p);
        assert!(
            d.contains("at least 8 characters")
                && d.contains("previous 24")
                && d.contains("once every 1 days"),
            "{d}"
        );
        assert_eq!(describe(b"Password too short"), "Password too short");
    }
}
