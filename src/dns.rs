//! Finding a realm's KDCs in DNS, as MIT's `locate_kdc.c` does, with a
//! small stub resolver of our own (no libc, no resolver crate).
//!
//! # Lookup order
//!
//! When `[realms] REALM kdc` lists nothing and `dns_lookup_kdc` allows it
//! (the default; `dns_fallback` is consulted if it is unset):
//!
//! 1. URI records at `_kerberos.REALM.` (unless `dns_uri_lookup = false`):
//!    `krb5srv:FLAGS:tcp:host[:port]`, default port 88.
//! 2. SRV records at `_kerberos._tcp.REALM.`.
//!
//! Entries are ordered by priority only, keeping DNS order within a
//! priority, as MIT's `place_srv_entry` does (weights are ignored). A sole
//! SRV target of `.` means the realm says it has no KDC service.
//!
//! Two deliberate departures, both because this crate speaks only TCP:
//!
//! * MIT also queries `_kerberos._udp` and talks UDP to what it finds.
//!   Here, if `_tcp` gives nothing, the `_udp` targets are used **over
//!   TCP** on the same port. KDCs listen on both (RFC 4120 §7.2.2; MIT,
//!   Heimdal and Active Directory all do), and realms that publish only
//!   `_udp` records, such as ATHENA.MIT.EDU, are common. URI records are
//!   treated the same way: `tcp` entries if there are any, else `udp`.
//! * MS-KKDCP (`kkdcp`) URI entries cannot be used; if they are all there
//!   is, the SRV lookup still runs, where MIT would use the proxy.
//!
//! # The resolver
//!
//! Queries go to the `nameserver`s in `/etc/resolv.conf` (or
//! `127.0.0.1` if it names none, as glibc does), honouring
//! `options timeout:` and `attempts:`, over UDP with a fall back to TCP for
//! a truncated reply. A reply is accepted only from the server asked, with
//! the query's ID and question. Names are always absolute, so `search`
//! domains do not apply. DNS is unauthenticated, here as in MIT; a spoofed
//! answer can point the client at the wrong host, but not past the KDC
//! reply's encryption.
//!
//! On macOS, `/etc/resolv.conf` reflects only the primary resolver, not
//! per-domain (VPN) resolvers configured with `scutil`.

use crate::config::{Krb5Conf, parse_host_string};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::time::Duration;
use tracing::debug;

/// The system resolver configuration, as glibc and macOS read it.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

const TYPE_CNAME: u16 = 5;
const TYPE_SRV: u16 = 33;
const TYPE_URI: u16 = 256;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u8 = 3;
/// Without EDNS0 a UDP reply is at most 512 octets; anything larger comes
/// back truncated and is fetched again over TCP.
const UDP_MAX: usize = 512;

/// A DNS answer of the type asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        /// Absolute, with the trailing dot; `"."` means "no service".
        target: String,
    },
    Uri {
        priority: u16,
        weight: u16,
        target: String,
    },
}

/// Where queries go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolver {
    pub servers: Vec<SocketAddr>,
    /// Per query, per server (`options timeout:`, default 5 s).
    pub timeout: Duration,
    /// Rounds through the server list (`options attempts:`, default 2).
    pub attempts: u32,
}

impl Resolver {
    /// Query exactly these servers.
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Resolver {
            servers,
            timeout: Duration::from_secs(5),
            attempts: 2,
        }
    }

    /// The servers `/etc/resolv.conf` names.
    pub fn system() -> io::Result<Self> {
        Self::from_resolv_conf(Path::new(RESOLV_CONF))
    }

    /// Read a `resolv.conf`. A missing file means `127.0.0.1`, as in glibc.
    pub fn from_resolv_conf(path: &Path) -> io::Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(Self::parse_resolv_conf(&text)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::parse_resolv_conf("")),
            Err(e) => Err(e),
        }
    }

    /// `nameserver ADDR` lines (at most three, as glibc's MAXNS) and the
    /// `timeout:`/`attempts:` options, with glibc's limits (30 s, 5).
    pub fn parse_resolv_conf(text: &str) -> Self {
        let mut r = Resolver::new(Vec::new());
        for line in text.lines() {
            let mut words = line.split_whitespace();
            match words.next() {
                Some("nameserver") => {
                    // glibc ignores a scope suffix it cannot use; so do we.
                    let addr = words.next().unwrap_or("");
                    let addr = addr.split('%').next().unwrap_or("");
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        if r.servers.len() < 3 {
                            r.servers.push(SocketAddr::new(ip, 53));
                        }
                    }
                }
                Some("options") => {
                    for opt in words {
                        if let Some(v) = opt.strip_prefix("timeout:").and_then(|v| v.parse().ok()) {
                            r.timeout = Duration::from_secs(u64::min(v, 30).max(1));
                        } else if let Some(v) =
                            opt.strip_prefix("attempts:").and_then(|v| v.parse().ok())
                        {
                            r.attempts = u32::min(v, 5).max(1);
                        }
                    }
                }
                _ => {}
            }
        }
        if r.servers.is_empty() {
            r.servers
                .push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53));
        }
        r
    }

    /// The `qtype` records for the absolute name `name`, following CNAMEs
    /// within the answer. A name that does not exist is an empty list;
    /// an error means no server gave a usable answer.
    pub fn query(&self, name: &str, qtype: u16) -> io::Result<Vec<Record>> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no nameservers");
        for _ in 0..self.attempts {
            for &server in &self.servers {
                match self.ask(server, name, qtype) {
                    Ok(records) => return Ok(records),
                    Err(e) => {
                        debug!("DNS {name} via {server}: {e}");
                        last = e;
                    }
                }
            }
        }
        Err(last)
    }

    fn ask(&self, server: SocketAddr, name: &str, qtype: u16) -> io::Result<Vec<Record>> {
        let id: u16 = rand::random();
        let query = encode_query(id, name, qtype)?;

        let bind: SocketAddr = match server {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let sock = UdpSocket::bind(bind)?;
        // Connecting makes the kernel drop datagrams from anyone else.
        sock.connect(server)?;
        sock.set_read_timeout(Some(self.timeout))?;
        sock.send(&query)?;
        let mut buf = [0u8; UDP_MAX];
        let reply = loop {
            let n = sock.recv(&mut buf)?;
            // A reply to some other query (or garbage) is ignored, not fatal:
            // keep waiting for ours until the timeout.
            match parse_reply(&buf[..n], id, name, qtype) {
                Err(Reject::NotOurs) => continue,
                other => break other,
            }
        };
        match reply {
            Ok(Reply::Answer(records)) => Ok(records),
            Ok(Reply::Truncated) => self.ask_tcp(server, id, &query, name, qtype),
            Err(Reject::Bad(e)) => Err(e),
            Err(Reject::NotOurs) => unreachable!(),
        }
    }

    fn ask_tcp(
        &self,
        server: SocketAddr,
        id: u16,
        query: &[u8],
        name: &str,
        qtype: u16,
    ) -> io::Result<Vec<Record>> {
        let mut s = TcpStream::connect_timeout(&server, self.timeout)?;
        s.set_read_timeout(Some(self.timeout))?;
        s.set_write_timeout(Some(self.timeout))?;
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(query);
        s.write_all(&framed)?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len)?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf)?;
        match parse_reply(&buf, id, name, qtype) {
            Ok(Reply::Answer(records)) => Ok(records),
            Ok(Reply::Truncated) => Err(bad("truncated reply over TCP")),
            Err(Reject::NotOurs) => Err(bad("TCP reply does not match the query")),
            Err(Reject::Bad(e)) => Err(e),
        }
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

// ----------------------------------------------------------- KDC lookup

/// MIT's `_krb5_conf_boolean`: one of its "yes" words is true, anything
/// else (not just its "no" words) is false.
fn conf_bool(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "y" | "yes" | "true" | "t" | "1" | "on"
    )
}

/// `dns_lookup_kdc`, else `dns_fallback`, else true (MIT's default).
pub fn dns_lookup_kdc(conf: &Krb5Conf) -> bool {
    conf.get(&["libdefaults", "dns_lookup_kdc"])
        .or_else(|| conf.get(&["libdefaults", "dns_fallback"]))
        .is_none_or(conf_bool)
}

/// `dns_uri_lookup`, default true.
pub fn dns_uri_lookup(conf: &Krb5Conf) -> bool {
    conf.get(&["libdefaults", "dns_uri_lookup"])
        .is_none_or(conf_bool)
}

/// MIT's `make_lookup_name`: `service.[protocol.]realm`, made absolute.
fn lookup_name(service: &str, protocol: Option<&str>, realm: &str) -> String {
    let mut n = format!("{service}.");
    if let Some(p) = protocol {
        n.push_str(p);
        n.push('.');
    }
    n.push_str(realm);
    if !n.ends_with('.') {
        n.push('.');
    }
    n
}

/// Stable sort by priority: MIT's `place_srv_entry` insertion order.
fn by_priority(records: &mut [Record]) {
    records.sort_by_key(|r| match r {
        Record::Srv { priority, .. } | Record::Uri { priority, .. } => *priority,
    });
}

/// Parse `krb5srv:FLAGS:TRANSPORT:host[:port]` (MIT `parse_uri_fields`),
/// returning the transport and the host part.
fn parse_krb5srv(uri: &str) -> Option<(String, &str)> {
    let rest = uri
        .get(..8)
        .filter(|p| p.eq_ignore_ascii_case("krb5srv:"))
        .map(|_| &uri[8..])?;
    let (_flags, rest) = rest.split_once(':')?;
    let (transport, host) = rest.split_once(':')?;
    Some((transport.to_ascii_lowercase(), host))
}

/// The realm's KDCs from DNS, as `host:port` for
/// [`KdcClient::new`](crate::KdcClient::new): URI records, then SRV (see
/// the module docs). An empty list means DNS has none.
pub fn locate_kdcs(resolver: &Resolver, realm: &str, use_uri: bool) -> io::Result<Vec<String>> {
    if use_uri {
        // As in MIT, a URI query that fails (some servers refuse the type)
        // just means "no URI records".
        let mut uris = resolver
            .query(&lookup_name("_kerberos", None, realm), TYPE_URI)
            .unwrap_or_else(|e| {
                debug!("{realm}: URI lookup failed ({e}); trying SRV");
                Vec::new()
            });
        by_priority(&mut uris);
        let entries: Vec<(String, &str)> = uris
            .iter()
            .filter_map(|r| match r {
                Record::Uri { target, .. } => parse_krb5srv(target),
                _ => None,
            })
            .collect();
        for transport in ["tcp", "udp"] {
            let hosts: Vec<String> = entries
                .iter()
                .filter(|(t, _)| t == transport)
                .filter_map(|(_, h)| parse_host_string(h, 88))
                .collect();
            if !hosts.is_empty() {
                if transport == "udp" {
                    debug!("{realm}: only udp URI records; using them over TCP");
                }
                return Ok(hosts);
            }
        }
    }
    for protocol in ["_tcp", "_udp"] {
        let mut srvs =
            resolver.query(&lookup_name("_kerberos", Some(protocol), realm), TYPE_SRV)?;
        by_priority(&mut srvs);
        let targets: Vec<(u16, &str)> = srvs
            .iter()
            .filter_map(|r| match r {
                Record::Srv { port, target, .. } => Some((*port, target.as_str())),
                _ => None,
            })
            .collect();
        if let [(_, ".")] = targets[..] {
            debug!("{realm}: SRV {protocol} says there is no KDC service");
            return Ok(Vec::new());
        }
        if !targets.is_empty() {
            if protocol == "_udp" {
                debug!("{realm}: only _udp SRV records; using them over TCP");
            }
            return Ok(targets
                .iter()
                .map(|(port, t)| format!("{t}:{port}"))
                .collect());
        }
    }
    Ok(Vec::new())
}

// ------------------------------------------------------------- the wire

/// A standard recursive query (RFC 1035 §4.1) for `name`, which must be
/// absolute.
fn encode_query(id: u16, name: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut q = Vec::with_capacity(17 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1
    encode_name(&mut q, name)?;
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(q)
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> io::Result<()> {
    let name = name
        .strip_suffix('.')
        .ok_or_else(|| bad(format!("{name:?} is not absolute")))?;
    let start = out.len();
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(bad(format!("bad label {label:?} in {name:?}")));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    if out.len() - start > 255 {
        return Err(bad(format!("{name:?} is longer than 255 octets")));
    }
    Ok(())
}

enum Reply {
    Answer(Vec<Record>),
    Truncated,
}

enum Reject {
    /// Not a reply to this query: wrong ID, not a response, other question.
    NotOurs,
    /// Our reply, but unusable (server failure, malformed).
    Bad(io::Error),
}

impl From<io::Error> for Reject {
    fn from(e: io::Error) -> Self {
        Reject::Bad(e)
    }
}

fn u16_at(m: &[u8], at: usize) -> io::Result<u16> {
    m.get(at..at + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| bad("truncated message"))
}

/// Read a possibly compressed name at `at`; returns it (absolute, lower
/// case) and the offset just past it in the original position.
fn read_name(m: &[u8], mut at: usize) -> io::Result<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    // Every pointer must go backwards, so a loop cannot form; the jump cap
    // is a second fence.
    let mut jumps = 0;
    let mut limit = at;
    loop {
        let len = *m.get(at).ok_or_else(|| bad("truncated name"))? as usize;
        match len {
            0 => {
                let after = at + 1;
                if name.is_empty() {
                    name.push('.');
                }
                return Ok((name, end.unwrap_or(after)));
            }
            l if l & 0xC0 == 0xC0 => {
                let ptr = (u16_at(m, at)? & 0x3FFF) as usize;
                if ptr >= limit || jumps > 32 {
                    return Err(bad("bad name compression pointer"));
                }
                end.get_or_insert(at + 2);
                jumps += 1;
                limit = ptr;
                at = ptr;
            }
            l if l & 0xC0 != 0 => return Err(bad("unknown label type")),
            l => {
                let label = m
                    .get(at + 1..at + 1 + l)
                    .ok_or_else(|| bad("truncated label"))?;
                // DNS allows any octet in a label, but these names become
                // `host:port` strings: a `.`, `:` or space smuggled into a
                // label would change what that string says. Hostnames and
                // the `_kerberos._tcp` owners need only letters, digits,
                // `-` and `_`.
                if !label
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(bad(format!(
                        "label {:?} has characters a host name cannot",
                        String::from_utf8_lossy(label)
                    )));
                }
                for &b in label {
                    name.push(b.to_ascii_lowercase() as char);
                }
                name.push('.');
                if name.len() > 255 {
                    return Err(bad("name longer than 255 octets"));
                }
                at += 1 + l;
            }
        }
    }
}

/// Check a reply against the query and pull out the records of `qtype`
/// for `name` or a CNAME of it.
fn parse_reply(m: &[u8], id: u16, name: &str, qtype: u16) -> Result<Reply, Reject> {
    if m.len() < 12 || u16_at(m, 0)? != id || m[2] & 0x80 == 0 {
        return Err(Reject::NotOurs);
    }
    let qd = u16_at(m, 4)?;
    let an = u16_at(m, 6)? as usize;
    if qd != 1 {
        return Err(Reject::NotOurs);
    }
    let (qname, mut at) = read_name(m, 12)?;
    if qname != name.to_ascii_lowercase()
        || u16_at(m, at)? != qtype
        || u16_at(m, at + 2)? != CLASS_IN
    {
        return Err(Reject::NotOurs);
    }
    at += 4;
    if m[2] & 0x02 != 0 {
        return Ok(Reply::Truncated);
    }
    match m[3] & 0x0F {
        0 => {}
        RCODE_NXDOMAIN => return Ok(Reply::Answer(Vec::new())),
        rcode => return Err(Reject::Bad(bad(format!("server answered rcode {rcode}")))),
    }

    let mut owners = vec![qname];
    let mut records = Vec::new();
    for _ in 0..an {
        let (owner, next) = read_name(m, at)?;
        let rtype = u16_at(m, next)?;
        let class = u16_at(m, next + 2)?;
        let rdlen = u16_at(m, next + 8)? as usize;
        let rdata_at = next + 10;
        let rdata = m
            .get(rdata_at..rdata_at + rdlen)
            .ok_or_else(|| bad("truncated record"))?;
        at = rdata_at + rdlen;
        if class != CLASS_IN || !owners.contains(&owner) {
            continue;
        }
        match rtype {
            TYPE_CNAME => owners.push(read_name(m, rdata_at)?.0),
            TYPE_SRV if rtype == qtype => {
                if rdata.len() < 7 {
                    return Err(Reject::Bad(bad("short SRV record")));
                }
                records.push(Record::Srv {
                    priority: u16_at(rdata, 0)?,
                    weight: u16_at(rdata, 2)?,
                    port: u16_at(rdata, 4)?,
                    // The target is read from the whole message: servers do
                    // compress it, RFC 2782 notwithstanding.
                    target: read_name(m, rdata_at + 6)?.0,
                });
            }
            TYPE_URI if rtype == qtype => {
                if rdata.len() < 4 {
                    return Err(Reject::Bad(bad("short URI record")));
                }
                let target = String::from_utf8(rdata[4..].to_vec())
                    .map_err(|_| bad("URI target is not UTF-8"))?;
                records.push(Record::Uri {
                    priority: u16_at(rdata, 0)?,
                    weight: u16_at(rdata, 2)?,
                    target,
                });
            }
            _ => {}
        }
    }
    Ok(Reply::Answer(records))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Replies recorded from a real resolver (scripts/record-dns-fixtures.py).
    fn fixture(label: &str) -> Vec<u8> {
        fs::read(format!(
            "{}/testdata/dns/{label}.bin",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn id_of(m: &[u8]) -> u16 {
        u16::from_be_bytes([m[0], m[1]])
    }

    fn answers(label: &str, name: &str, qtype: u16) -> Vec<Record> {
        let m = fixture(label);
        match parse_reply(&m, id_of(&m), name, qtype) {
            Ok(Reply::Answer(r)) => r,
            _ => panic!("{label} did not parse as an answer"),
        }
    }

    fn srv(priority: u16, weight: u16, port: u16, target: &str) -> Record {
        Record::Srv {
            priority,
            weight,
            port,
            target: target.into(),
        }
    }

    fn uri(priority: u16, weight: u16, target: &str) -> Record {
        Record::Uri {
            priority,
            weight,
            target: target.into(),
        }
    }

    #[test]
    fn a_query_has_the_rfc_1035_shape() {
        let q = encode_query(0x1234, "_kerberos._tcp.EXAMPLE.COM.", TYPE_SRV).unwrap();
        let mut want = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["_kerberos", "_tcp", "EXAMPLE", "COM"] {
            want.push(l.len() as u8);
            want.extend_from_slice(l.as_bytes());
        }
        want.extend_from_slice(&[0, 0, 33, 0, 1]);
        assert_eq!(q, want);
        assert!(encode_query(1, "relative.name", TYPE_SRV).is_err());
        assert!(encode_query(1, "a..b.", TYPE_SRV).is_err());
        assert!(encode_query(1, &format!("{}.", "a".repeat(64)), TYPE_SRV).is_err());
        assert!(
            encode_query(
                1,
                &format!("{}.", vec!["a".repeat(63); 5].join(".")),
                TYPE_SRV
            )
            .is_err()
        );
    }

    /// `dig SRV _kerberos._udp.athena.mit.edu`: three targets, every name
    /// in the reply compressed against the question.
    #[test]
    fn real_srv_records_parse() {
        assert_eq!(
            answers("athena-udp-srv", "_kerberos._udp.ATHENA.MIT.EDU.", TYPE_SRV),
            [
                srv(0, 0, 88, "kerberos-2.mit.edu."),
                srv(0, 0, 88, "kerberos-1.mit.edu."),
                srv(0, 0, 88, "kerberos.mit.edu."),
            ]
        );
        assert_eq!(
            answers(
                "fedora-tcp-srv",
                "_kerberos._tcp.FEDORAPROJECT.ORG.",
                TYPE_SRV
            ),
            [srv(20, 1, 1088, "id.fedoraproject.org.")]
        );
    }

    #[test]
    fn real_uri_records_parse() {
        assert_eq!(
            answers("fedora-uri", "_kerberos.FEDORAPROJECT.ORG.", TYPE_URI),
            [uri(
                10,
                1,
                "krb5srv:m:kkdcp:https://id.fedoraproject.org/KdcProxy/"
            )]
        );
        let mut ipa = answers("freeipa-uri", "_kerberos.DEMO1.FREEIPA.ORG.", TYPE_URI);
        ipa.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        assert_eq!(
            ipa,
            [
                uri(0, 100, "krb5srv:m:tcp:ipa.demo1.freeipa.org."),
                uri(0, 100, "krb5srv:m:udp:ipa.demo1.freeipa.org."),
            ]
        );
    }

    #[test]
    fn nxdomain_is_an_empty_answer() {
        assert!(
            answers(
                "nxdomain-srv",
                "_kerberos._tcp.no-such-realm.invalid.",
                TYPE_SRV
            )
            .is_empty()
        );
        assert!(answers("athena-tcp-srv", "_kerberos._tcp.athena.mit.edu.", TYPE_SRV).is_empty());
    }

    #[test]
    fn a_reply_to_another_query_is_not_ours() {
        let m = fixture("athena-udp-srv");
        let id = id_of(&m);
        let not_ours =
            |m: &[u8], id, name, t| matches!(parse_reply(m, id, name, t), Err(Reject::NotOurs));
        assert!(
            not_ours(&m, id ^ 1, "_kerberos._udp.athena.mit.edu.", TYPE_SRV),
            "wrong ID"
        );
        assert!(
            not_ours(&m, id, "_kerberos._tcp.athena.mit.edu.", TYPE_SRV),
            "other name"
        );
        assert!(
            not_ours(&m, id, "_kerberos._udp.athena.mit.edu.", TYPE_URI),
            "other type"
        );
        let mut query = m.clone();
        query[2] &= 0x7F; // QR clear: a query, not a reply
        assert!(not_ours(
            &query,
            id,
            "_kerberos._udp.athena.mit.edu.",
            TYPE_SRV
        ));
        assert!(not_ours(
            &m[..8],
            id,
            "_kerberos._udp.athena.mit.edu.",
            TYPE_SRV
        ));
    }

    #[test]
    fn a_server_failure_is_an_error_and_truncation_is_flagged() {
        let mut m = fixture("athena-udp-srv");
        let id = id_of(&m);
        let name = "_kerberos._udp.athena.mit.edu.";
        m[3] = (m[3] & 0xF0) | 2; // SERVFAIL
        assert!(matches!(
            parse_reply(&m, id, name, TYPE_SRV),
            Err(Reject::Bad(_))
        ));
        let mut t = fixture("athena-udp-srv");
        t[2] |= 0x02;
        assert!(matches!(
            parse_reply(&t, id, name, TYPE_SRV),
            Ok(Reply::Truncated)
        ));
    }

    #[test]
    fn every_truncation_of_a_real_reply_is_refused_not_panicked_on() {
        let m = fixture("athena-udp-srv");
        let id = id_of(&m);
        for cut in 12..m.len() {
            if let Ok(Reply::Answer(r)) =
                parse_reply(&m[..cut], id, "_kerberos._udp.athena.mit.edu.", TYPE_SRV)
            {
                panic!("cut at {cut} parsed as {r:?}");
            }
        }
    }

    #[test]
    fn compression_loops_and_forward_pointers_are_refused() {
        let mut m = vec![0u8; 12];
        m.extend_from_slice(&[0xC0, 12]); // points at itself
        assert!(read_name(&m, 12).is_err());
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0xC0, 20, 0, 0, 0, 0, 0, 0, 1, b'a', 0]);
        assert!(read_name(&f, 12).is_err(), "forward pointer");
        let mut ok = vec![0u8; 12];
        ok.extend_from_slice(&[3, b'm', b'i', b't', 0, 1, b'a', 0xC0, 12]);
        assert_eq!(read_name(&ok, 17).unwrap(), ("a.mit.".to_string(), 21));
        assert_eq!(read_name(&[0], 0).unwrap(), (".".to_string(), 1));
    }

    #[test]
    fn labels_that_would_change_a_host_port_string_are_refused() {
        for label in [&b"evil:99"[..], b"a.b", b"sp ace", b"\xff", b"a\0b"] {
            let mut m = vec![label.len() as u8];
            m.extend_from_slice(label);
            m.push(0);
            assert!(read_name(&m, 0).is_err(), "{label:?}");
        }
        assert!(read_name(b"\x09_kerberos\x04_tcp\x07kdc-1_a\x00", 0).is_ok());
    }

    #[test]
    fn a_cname_chain_in_the_answer_is_followed() {
        // q: _kerberos._tcp.a. SRV; an: CNAME -> b., then SRV at b.
        let mut m = vec![0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        let q = m.len();
        m.extend_from_slice(b"\x09_kerberos\x04_tcp\x01a\x00");
        m.extend_from_slice(&[0, 33, 0, 1]);
        m.extend_from_slice(&[0xC0, q as u8, 0, 5, 0, 1, 0, 0, 0, 60, 0, 3, 1, b'b', 0]);
        let b = m.len() - 3;
        m.extend_from_slice(&[
            0xC0, b as u8, 0, 33, 0, 1, 0, 0, 0, 60, 0, 10, 0, 1, 0, 2, 0, 88, 1, b'k', 0xC0,
            b as u8,
        ]);
        // An SRV for an unrelated owner is ignored.
        m.extend_from_slice(&[
            1, b'z', 0, 0, 33, 0, 1, 0, 0, 0, 60, 0, 8, 0, 0, 0, 0, 0, 88, 1, b'x', 0,
        ]);
        match parse_reply(&m, 0xABCD, "_kerberos._tcp.a.", TYPE_SRV) {
            Ok(Reply::Answer(r)) => assert_eq!(r, [srv(1, 2, 88, "k.b.")]),
            _ => panic!(),
        }
    }

    #[test]
    fn resolv_conf_is_read_as_glibc_does() {
        let r = Resolver::parse_resolv_conf(
            "# comment\nsearch example.com\nnameserver 10.0.0.1\nnameserver fe80::1%en0\n\
             nameserver bogus\nnameserver 10.0.0.2\nnameserver 10.0.0.3\noptions ndots:2 timeout:3 attempts:9\n",
        );
        assert_eq!(
            r.servers,
            ["10.0.0.1:53", "[fe80::1]:53", "10.0.0.2:53"]
                .map(|s| s.parse::<SocketAddr>().unwrap())
        );
        assert_eq!(r.timeout, Duration::from_secs(3));
        assert_eq!(r.attempts, 5, "capped like glibc");
        let empty = Resolver::parse_resolv_conf("");
        assert_eq!(
            empty.servers,
            ["127.0.0.1:53".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!((empty.timeout, empty.attempts), (Duration::from_secs(5), 2));
    }

    #[test]
    fn lookup_settings_follow_mit() {
        let c = |t: &str| Krb5Conf::parse(&format!("[libdefaults]\n{t}\n")).unwrap();
        assert!(dns_lookup_kdc(&Krb5Conf::empty()));
        assert!(!dns_lookup_kdc(&c("dns_lookup_kdc = false")));
        assert!(
            !dns_lookup_kdc(&c("dns_lookup_kdc = maybe")),
            "not a yes word: false"
        );
        assert!(!dns_lookup_kdc(&c("dns_fallback = no")));
        assert!(dns_lookup_kdc(&c(
            "dns_fallback = no\ndns_lookup_kdc = yes"
        )));
        assert!(dns_uri_lookup(&Krb5Conf::empty()));
        assert!(!dns_uri_lookup(&c("dns_uri_lookup = 0")));
        assert_eq!(
            lookup_name("_kerberos", Some("_tcp"), "A.ORG"),
            "_kerberos._tcp.A.ORG."
        );
        assert_eq!(lookup_name("_kerberos", None, "A.ORG."), "_kerberos.A.ORG.");
    }

    #[test]
    fn krb5srv_uris_parse_as_mit_does() {
        assert_eq!(
            parse_krb5srv("krb5srv:m:tcp:kdc.a:88"),
            Some(("tcp".into(), "kdc.a:88"))
        );
        assert_eq!(
            parse_krb5srv("KRB5SRV::UDP:kdc.a"),
            Some(("udp".into(), "kdc.a"))
        );
        assert_eq!(
            parse_krb5srv("krb5srv:m:kkdcp:https://x/KdcProxy"),
            Some(("kkdcp".into(), "https://x/KdcProxy"))
        );
        assert_eq!(parse_krb5srv("http://x"), None);
        assert_eq!(parse_krb5srv("krb5srv:m"), None);
    }

    // ---------------------------------------------- against a fake server

    /// What the fake server says for a (lower-case name, type).
    #[derive(Clone)]
    enum Says {
        Fixture(&'static str),
        Rcode(u8),
        /// TC over UDP; the fixture over TCP.
        Truncated(&'static str),
        /// A reply with the wrong ID first, then the right one.
        StrayFirst(&'static str),
        Silent,
    }

    /// Every question the fake was asked: name, type, and "udp"/"tcp".
    type Asked = Arc<Mutex<Vec<(String, u16, &'static str)>>>;

    struct Fake {
        addr: SocketAddr,
        asked: Asked,
    }

    fn question(q: &[u8]) -> (String, u16, usize) {
        let (name, at) = read_name(q, 12).unwrap();
        (name, u16_at(q, at).unwrap(), at + 4)
    }

    fn respond(q: &[u8], says: &Says, tcp: bool) -> Option<Vec<u8>> {
        let (_, _, qend) = question(q);
        let mut m = match says {
            Says::Fixture(f) | Says::StrayFirst(f) => fixture(f),
            Says::Truncated(f) if tcp => fixture(f),
            Says::Truncated(_) => {
                let mut m = q[..qend].to_vec();
                m[2] |= 0x82;
                return Some(m);
            }
            Says::Rcode(rc) => {
                let mut m = q[..qend].to_vec();
                m[2] |= 0x80;
                m[3] = *rc;
                return Some(m);
            }
            Says::Silent => return None,
        };
        // The fixtures' questions are lower case; echo the query's own.
        let (_, _, fend) = question(&m);
        m.splice(12..fend, q[12..qend].iter().copied());
        m[..2].copy_from_slice(&q[..2]);
        Some(m)
    }

    fn fake(zone: HashMap<(String, u16), Says>) -> Fake {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let zone = Arc::new(zone);
        let (a, z) = (asked.clone(), zone.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                let q = &buf[..n];
                let (name, qtype, _) = question(q);
                let says = z
                    .get(&(name.clone(), qtype))
                    .cloned()
                    .unwrap_or(Says::Rcode(RCODE_NXDOMAIN));
                a.lock().unwrap().push((name, qtype, "udp"));
                if let Says::StrayFirst(_) = says {
                    let mut stray = respond(q, &says, false).unwrap();
                    stray[0] ^= 0xFF;
                    udp.send_to(&stray, from).unwrap();
                }
                if let Some(r) = respond(q, &says, false) {
                    udp.send_to(&r, from).unwrap();
                }
            }
        });
        let (a, z) = (asked.clone(), zone);
        std::thread::spawn(move || {
            for conn in tcp.incoming() {
                let mut c = conn.unwrap();
                let mut len = [0u8; 2];
                c.read_exact(&mut len).unwrap();
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                c.read_exact(&mut q).unwrap();
                let (name, qtype, _) = question(&q);
                let says = z
                    .get(&(name.clone(), qtype))
                    .cloned()
                    .unwrap_or(Says::Rcode(RCODE_NXDOMAIN));
                a.lock().unwrap().push((name, qtype, "tcp"));
                let r = respond(&q, &says, true).unwrap();
                c.write_all(&(r.len() as u16).to_be_bytes()).unwrap();
                c.write_all(&r).unwrap();
            }
        });
        Fake { addr, asked }
    }

    fn zone(entries: &[(&str, u16, Says)]) -> HashMap<(String, u16), Says> {
        entries
            .iter()
            .map(|(n, t, s)| ((n.to_string(), *t), s.clone()))
            .collect()
    }

    fn resolver(servers: &[SocketAddr]) -> Resolver {
        Resolver {
            servers: servers.to_vec(),
            timeout: Duration::from_millis(300),
            attempts: 1,
        }
    }

    #[test]
    fn udp_only_srv_records_are_used_over_tcp_after_tcp_and_uri_come_up_empty() {
        // ATHENA.MIT.EDU as it really is: no URI, no _tcp, three _udp.
        let f = fake(zone(&[(
            "_kerberos._udp.athena.mit.edu.",
            TYPE_SRV,
            Says::Fixture("athena-udp-srv"),
        )]));
        let kdcs = locate_kdcs(&resolver(&[f.addr]), "ATHENA.MIT.EDU", true).unwrap();
        assert_eq!(
            kdcs,
            [
                "kerberos-2.mit.edu.:88",
                "kerberos-1.mit.edu.:88",
                "kerberos.mit.edu.:88"
            ]
        );
        let asked: Vec<_> = f
            .asked
            .lock()
            .unwrap()
            .iter()
            .map(|(n, t, _)| (n.clone(), *t))
            .collect();
        assert_eq!(
            asked,
            [
                ("_kerberos.athena.mit.edu.".into(), TYPE_URI),
                ("_kerberos._tcp.athena.mit.edu.".into(), TYPE_SRV),
                ("_kerberos._udp.athena.mit.edu.".into(), TYPE_SRV),
            ]
        );
    }

    #[test]
    fn a_proxy_only_uri_falls_through_to_srv() {
        // FEDORAPROJECT.ORG as it really is: URI offers only MS-KKDCP.
        let f = fake(zone(&[
            (
                "_kerberos.fedoraproject.org.",
                TYPE_URI,
                Says::Fixture("fedora-uri"),
            ),
            (
                "_kerberos._tcp.fedoraproject.org.",
                TYPE_SRV,
                Says::Fixture("fedora-tcp-srv"),
            ),
        ]));
        assert_eq!(
            locate_kdcs(&resolver(&[f.addr]), "FEDORAPROJECT.ORG", true).unwrap(),
            ["id.fedoraproject.org.:1088"]
        );
    }

    #[test]
    fn tcp_uri_records_win_and_srv_is_not_asked() {
        let f = fake(zone(&[(
            "_kerberos.demo1.freeipa.org.",
            TYPE_URI,
            Says::Fixture("freeipa-uri"),
        )]));
        assert_eq!(
            locate_kdcs(&resolver(&[f.addr]), "DEMO1.FREEIPA.ORG", true).unwrap(),
            ["ipa.demo1.freeipa.org.:88"]
        );
        assert_eq!(f.asked.lock().unwrap().len(), 1);
        // With dns_uri_lookup off, straight to SRV.
        let g = fake(zone(&[]));
        assert!(
            locate_kdcs(&resolver(&[g.addr]), "DEMO1.FREEIPA.ORG", false)
                .unwrap()
                .is_empty()
        );
        assert!(
            g.asked
                .lock()
                .unwrap()
                .iter()
                .all(|(_, t, _)| *t == TYPE_SRV)
        );
    }

    #[test]
    fn a_truncated_reply_is_fetched_again_over_tcp() {
        let f = fake(zone(&[(
            "_kerberos._udp.athena.mit.edu.",
            TYPE_SRV,
            Says::Truncated("athena-udp-srv"),
        )]));
        let r = resolver(&[f.addr])
            .query("_kerberos._udp.ATHENA.MIT.EDU.", TYPE_SRV)
            .unwrap();
        assert_eq!(r.len(), 3);
        let via: Vec<_> = f.asked.lock().unwrap().iter().map(|(_, _, v)| *v).collect();
        assert_eq!(via, ["udp", "tcp"]);
    }

    #[test]
    fn a_stray_reply_is_skipped_and_the_real_one_taken() {
        let f = fake(zone(&[(
            "_kerberos._udp.athena.mit.edu.",
            TYPE_SRV,
            Says::StrayFirst("athena-udp-srv"),
        )]));
        let r = resolver(&[f.addr])
            .query("_kerberos._udp.athena.mit.edu.", TYPE_SRV)
            .unwrap();
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn a_failing_or_silent_server_gives_way_to_the_next() {
        let name = "_kerberos._udp.athena.mit.edu.";
        let fail = fake(zone(&[(name, TYPE_SRV, Says::Rcode(2))]));
        let mute = fake(zone(&[(name, TYPE_SRV, Says::Silent)]));
        let good = fake(zone(&[(name, TYPE_SRV, Says::Fixture("athena-udp-srv"))]));
        let r = resolver(&[fail.addr, mute.addr, good.addr])
            .query(name, TYPE_SRV)
            .unwrap();
        assert_eq!(r.len(), 3);
        assert!(
            resolver(&[fail.addr, mute.addr])
                .query(name, TYPE_SRV)
                .is_err()
        );
    }

    /// MIT's place_srv_entry: lower priority first, DNS order kept within
    /// a priority, weights ignored.
    #[test]
    fn srv_targets_sort_by_priority_and_keep_dns_order_within_one() {
        let mut m = vec![0x55, 0x55, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        m.extend_from_slice(b"\x09_kerberos\x04_tcp\x01r\x00\x00\x21\x00\x01");
        for (prio, weight, host) in [(20u16, 0u16, b'a'), (10, 1, b'b'), (10, 99, b'c')] {
            m.extend_from_slice(&[0xC0, 12, 0, 33, 0, 1, 0, 0, 0, 60, 0, 9]);
            m.extend_from_slice(&prio.to_be_bytes());
            m.extend_from_slice(&weight.to_be_bytes());
            m.extend_from_slice(&[0, 88, 1, host, 0]);
        }
        let Ok(Reply::Answer(mut r)) = parse_reply(&m, 0x5555, "_kerberos._tcp.r.", TYPE_SRV)
        else {
            panic!()
        };
        by_priority(&mut r);
        let order: Vec<_> = r
            .iter()
            .map(|r| match r {
                Record::Srv { target, .. } => target.as_str(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(order, ["b.", "c.", "a."]);
    }

    #[test]
    fn kdc_client_prefers_krb5_conf_then_asks_dns() {
        use crate::{ConfigError, KdcClient};
        let f = fake(zone(&[(
            "_kerberos._udp.athena.mit.edu.",
            TYPE_SRV,
            Says::Fixture("athena-udp-srv"),
        )]));
        let r = resolver(&[f.addr]);
        let conf = |t: &str| Krb5Conf::parse(t).unwrap();

        // Listed in krb5.conf: DNS is not asked.
        let listed = conf("[realms]\n ATHENA.MIT.EDU = {\n  kdc = k.example:750\n }\n");
        let c = KdcClient::from_config_with_resolver(&listed, "ATHENA.MIT.EDU", &r).unwrap();
        assert_eq!(c.kdcs(), ["k.example:750"]);
        assert!(f.asked.lock().unwrap().is_empty());

        // Not listed: DNS.
        let c =
            KdcClient::from_config_with_resolver(&Krb5Conf::empty(), "ATHENA.MIT.EDU", &r).unwrap();
        assert_eq!(c.kdcs().len(), 3);

        // Only entries we cannot use: MIT would use them, so no DNS.
        let proxy = conf("[realms]\n ATHENA.MIT.EDU = {\n  kdc = https://p/KdcProxy\n }\n");
        let before = f.asked.lock().unwrap().len();
        let e = KdcClient::from_config_with_resolver(&proxy, "ATHENA.MIT.EDU", &r).unwrap_err();
        assert!(matches!(e, ConfigError::NoKdcs { .. }), "{e}");
        assert_eq!(f.asked.lock().unwrap().len(), before);

        // DNS turned off.
        let off = conf("[libdefaults]\n dns_lookup_kdc = false\n");
        let e = KdcClient::from_config_with_resolver(&off, "ATHENA.MIT.EDU", &r).unwrap_err();
        assert!(
            matches!(e, ConfigError::NoKdcFound { dns: false, .. }),
            "{e}"
        );
        assert!(e.to_string().contains("dns_lookup_kdc"), "{e}");

        // Nothing anywhere.
        let e = KdcClient::from_config_with_resolver(&Krb5Conf::empty(), "NOWHERE.TEST", &r)
            .unwrap_err();
        assert!(
            matches!(e, ConfigError::NoKdcFound { dns: true, .. }),
            "{e}"
        );

        // No nameserver answering at all is a DNS error, not "none".
        let dead = resolver(&[UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()]);
        let e =
            KdcClient::from_config_with_resolver(&Krb5Conf::empty(), "X.TEST", &dead).unwrap_err();
        assert!(matches!(e, ConfigError::Dns { .. }), "{e}");
    }

    #[test]
    fn a_dot_target_means_no_kdc_service() {
        let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(b"\x09_kerberos\x04_tcp\x01x\x00\x00\x21\x00\x01");
        m.extend_from_slice(&[
            0xC0, 12, 0, 33, 0, 1, 0, 0, 0, 60, 0, 7, 0, 0, 0, 0, 0, 0, 0,
        ]);
        match parse_reply(&m, 0, "_kerberos._tcp.x.", TYPE_SRV) {
            Ok(Reply::Answer(r)) => assert_eq!(r, [srv(0, 0, 0, ".")]),
            _ => panic!(),
        }
    }
}
