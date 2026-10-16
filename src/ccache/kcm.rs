//! `KCM:` credential caches: Heimdal's KCM protocol over a Unix socket, as
//! MIT's `cc_kcm.c` speaks it, to sssd-kcm (the Fedora and RHEL default)
//! or Heimdal's `kcm`.
//!
//! Every request is a length-prefixed frame: protocol version `2.0`, a
//! 16-bit opcode, then the arguments: cache names as NUL-terminated
//! strings, principals and credentials in the version-4 file encoding.
//! The reply frame carries a transport status and then the payload, whose
//! first four octets are the operation's krb5 error code.
//!
//! A cache is read with `GET_PRINCIPAL` and `GET_CRED_LIST` (falling back
//! to `GET_CRED_UUID_LIST` and `GET_CRED_BY_UUID` for daemons without the
//! MIT extension) and written whole with `REPLACE`, atomically, falling
//! back to `INITIALIZE` plus one `STORE` per entry as MIT does. A new
//! connection is opened per read or write, so sssd's idle timeout never
//! catches a stale socket.
//!
//! macOS's KCM is reached over Mach IPC, not a socket; that needs native
//! bindings, so it is not supported here and connecting reports why.

use super::{CCache, CacheError, In, Result, Stop, TAG_DELTATIME, put_entry, put_principal};
use crate::config::Krb5Conf;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::debug;

/// MIT and Heimdal's default (Heimdal hardcodes `/var/run`).
pub const DEFAULT_KCM_SOCKET: &str = "/var/run/.heim_org.h5l.kcm-socket";

const VERSION: [u8; 2] = [2, 0];
const MAX_REPLY: usize = 10 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

const OP_INITIALIZE: u16 = 4;
const OP_STORE: u16 = 6;
const OP_GET_PRINCIPAL: u16 = 8;
const OP_GET_CRED_UUID_LIST: u16 = 9;
const OP_GET_CRED_BY_UUID: u16 = 10;
const OP_GET_DEFAULT_CACHE: u16 = 20;
const OP_SET_DEFAULT_CACHE: u16 = 21;
const OP_GET_KDC_OFFSET: u16 = 22;
const OP_SET_KDC_OFFSET: u16 = 23;
const OP_GET_CRED_LIST: u16 = 13001;
const OP_REPLACE: u16 = 13002;

// krb5 error codes (krb5_err.et) that KCM daemons send back.
/// `KRB5_CC_NOTFOUND`: no matching credential.
pub const KRB5_CC_NOTFOUND: i32 = -1765328243;
/// `KRB5_CC_END`: the end of the cache was reached.
pub const KRB5_CC_END: i32 = -1765328242;
/// `KRB5_CC_IO`: the cache operation failed.
pub const KRB5_CC_IO: i32 = -1765328191;
/// `KRB5_FCC_NOFILE`: no such cache.
pub const KRB5_FCC_NOFILE: i32 = -1765328189;
/// `KRB5_FCC_INTERNAL`: an internal cache error.
pub const KRB5_FCC_INTERNAL: i32 = -1765328188;
/// `KRB5_CC_NOSUPP`: the operation is not supported.
pub const KRB5_CC_NOSUPP: i32 = -1765328137;

/// MIT's `unsupported_op_error`: Heimdal answers an unknown opcode with
/// `KRB5_FCC_INTERNAL`; sssd with `KRB5_CC_NOSUPP`, or `KRB5_CC_IO` if it
/// does not recognize the opcode at all.
fn unsupported(code: i32) -> bool {
    matches!(code, KRB5_FCC_INTERNAL | KRB5_CC_IO | KRB5_CC_NOSUPP)
}

/// A name for the codes KCM daemons return.
pub fn error_name(code: i32) -> &'static str {
    match code {
        KRB5_CC_NOTFOUND => "KRB5_CC_NOTFOUND",
        KRB5_CC_END => "KRB5_CC_END",
        KRB5_CC_IO => "KRB5_CC_IO",
        KRB5_FCC_NOFILE => "KRB5_FCC_NOFILE (no such cache)",
        KRB5_FCC_INTERNAL => "KRB5_FCC_INTERNAL",
        KRB5_CC_NOSUPP => "KRB5_CC_NOSUPP",
        _ => "unknown",
    }
}

/// The socket `[libdefaults] kcm_socket` names, else the default. MIT's
/// `-` (KCM disabled) is `None`.
pub fn socket_path(conf: &Krb5Conf) -> Option<PathBuf> {
    match conf.get(&["libdefaults", "kcm_socket"]) {
        Some("-") => None,
        Some(p) => Some(PathBuf::from(p)),
        None => Some(PathBuf::from(DEFAULT_KCM_SOCKET)),
    }
}

/// One connection to a KCM daemon.
pub struct Kcm {
    stream: UnixStream,
    socket: PathBuf,
}

impl Kcm {
    /// Connect to the daemon at `socket`, with a 30-second read and write
    /// timeout.
    pub fn connect(socket: &Path) -> Result<Self> {
        let stream = UnixStream::connect(socket).map_err(|source| CacheError::KcmUnavailable {
            socket: socket.to_path_buf(),
            source,
        })?;
        let to = |source| CacheError::Io {
            path: socket.to_path_buf(),
            source,
        };
        stream.set_read_timeout(Some(TIMEOUT)).map_err(to)?;
        stream.set_write_timeout(Some(TIMEOUT)).map_err(to)?;
        Ok(Kcm {
            stream,
            socket: socket.to_path_buf(),
        })
    }

    /// One request and its reply payload, after the operation's status.
    /// A non-zero status is `Err(Ok(code))`; transport failures are
    /// `Err(Err(..))`, so callers can fall back on "unsupported" codes.
    fn call(
        &mut self,
        op: u16,
        name: Option<&str>,
        args: &[u8],
    ) -> std::result::Result<Vec<u8>, Failed> {
        let mut req = Vec::with_capacity(4 + args.len() + 64);
        req.extend_from_slice(&VERSION);
        req.extend_from_slice(&op.to_be_bytes());
        if let Some(n) = name {
            req.extend_from_slice(n.as_bytes());
            req.push(0);
        }
        req.extend_from_slice(args);

        let socket = self.socket.clone();
        let io = |source: io::Error| {
            Failed::Cache(CacheError::Io {
                path: socket.clone(),
                source,
            })
        };
        let mut frame = (req.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&req);
        self.stream.write_all(&frame).map_err(io)?;

        // Reply: length, transport status, then `length` octets that
        // begin with the operation's own status (MIT kcmio_unix_socket_read
        // then kcmio_call).
        let mut word = [0u8; 4];
        self.stream.read_exact(&mut word).map_err(io)?;
        let len = u32::from_be_bytes(word) as usize;
        if len > MAX_REPLY {
            return Err(Failed::Cache(self.malformed(format!("{len}-octet reply"))));
        }
        self.stream.read_exact(&mut word).map_err(io)?;
        let transport = i32::from_be_bytes(word);
        if transport != 0 {
            return Err(Failed::Code(transport));
        }
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).map_err(io)?;
        if payload.len() < 4 {
            return Err(Failed::Cache(
                self.malformed("reply without a status".into()),
            ));
        }
        let status = i32::from_be_bytes(payload[..4].try_into().unwrap());
        if status != 0 {
            return Err(Failed::Code(status));
        }
        payload.drain(..4);
        Ok(payload)
    }

    fn malformed(&self, msg: String) -> CacheError {
        CacheError::Format {
            path: self.socket.clone(),
            msg: format!("malformed KCM reply: {msg}"),
        }
    }

    fn checked(
        &mut self,
        op: &'static str,
        opcode: u16,
        name: Option<&str>,
        args: &[u8],
    ) -> Result<Vec<u8>> {
        self.call(opcode, name, args).map_err(|f| f.into_error(op))
    }

    /// The collection's primary cache name (`KCM:` with no residual).
    pub fn default_cache(&mut self) -> Result<String> {
        let reply = self.checked("GET_DEFAULT_CACHE", OP_GET_DEFAULT_CACHE, None, &[])?;
        let end = reply
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| self.malformed("unterminated cache name".into()))?;
        String::from_utf8(reply[..end].to_vec())
            .map_err(|_| self.malformed("cache name is not UTF-8".into()))
    }

    /// Make `name` the collection's primary cache (`kswitch`).
    pub fn set_default_cache(&mut self, name: &str) -> Result<()> {
        self.checked("SET_DEFAULT_CACHE", OP_SET_DEFAULT_CACHE, Some(name), &[])
            .map(drop)
    }

    /// Read cache `name` whole.
    pub fn read(&mut self, name: &str) -> Result<CCache> {
        let reply = self.checked("GET_PRINCIPAL", OP_GET_PRINCIPAL, Some(name), &[])?;
        // Heimdal answers 0 with no principal for a cache that does not exist.
        if reply.is_empty() {
            return Err(CacheError::Kcm {
                op: "GET_PRINCIPAL",
                code: KRB5_FCC_NOFILE,
            });
        }
        let principal = In {
            data: &reply,
            version: 4,
        }
        .principal()
        .map_err(|s| self.malformed(s.into()))?;

        let entries = match self.call(OP_GET_CRED_LIST, Some(name), &[]) {
            Ok(list) => self.cred_list(&list)?,
            Err(Failed::Code(c)) if unsupported(c) => {
                debug!("KCM daemon refused GET_CRED_LIST ({c}); reading by UUID");
                self.creds_by_uuid(name)?
            }
            Err(f) => return Err(f.into_error("GET_CRED_LIST")),
        };

        // Optional, as in MIT's get_kdc_offset: failure means "none".
        let mut header = Vec::new();
        if let Ok(off) = self.call(OP_GET_KDC_OFFSET, Some(name), &[]) {
            if off.len() >= 4 {
                let mut v = off[..4].to_vec();
                v.extend_from_slice(&[0; 4]);
                header.push((TAG_DELTATIME, v));
            }
        }
        Ok(CCache {
            principal,
            header,
            entries,
        })
    }

    fn cred_list(&self, reply: &[u8]) -> Result<Vec<super::Entry>> {
        let mut r = In {
            data: reply,
            version: 4,
        };
        let bad = |s: Stop| self.malformed(s.into());
        let count = r.u32().map_err(bad)? as usize;
        if count > r.data.len() / 4 {
            return Err(self.malformed(format!("{count} credentials")));
        }
        (0..count)
            .map(|_| {
                let cred = r.data().map_err(bad)?;
                let mut c = In {
                    data: cred,
                    version: 4,
                };
                c.entry().map_err(bad)
            })
            .collect()
    }

    fn creds_by_uuid(&mut self, name: &str) -> Result<Vec<super::Entry>> {
        let uuids = self.checked("GET_CRED_UUID_LIST", OP_GET_CRED_UUID_LIST, Some(name), &[])?;
        if uuids.len() % 16 != 0 {
            return Err(self.malformed(format!("{}-octet UUID list", uuids.len())));
        }
        let mut entries = Vec::new();
        for uuid in uuids.chunks(16) {
            let cred = match self.call(OP_GET_CRED_BY_UUID, Some(name), uuid) {
                Ok(c) => c,
                // Removed since the list was taken.
                Err(Failed::Code(KRB5_CC_END | KRB5_CC_NOTFOUND)) => continue,
                Err(f) => return Err(f.into_error("GET_CRED_BY_UUID")),
            };
            let mut c = In {
                data: &cred,
                version: 4,
            };
            entries.push(c.entry().map_err(|s| self.malformed(s.into()))?);
        }
        Ok(entries)
    }

    /// Replace cache `name` with `cache`: `REPLACE` if the daemon has it
    /// (atomic), else `INITIALIZE` and one `STORE` per entry, as MIT's
    /// `k5_nonatomic_replace`.
    pub fn write(&mut self, name: &str, cache: &CCache) -> Result<()> {
        let offset = cache.time_offset().map_or(0, |(s, _)| s);
        let mut args = offset.to_be_bytes().to_vec();
        put_principal(&mut args, &cache.principal);
        args.extend_from_slice(&(cache.entries.len() as u32).to_be_bytes());
        for e in &cache.entries {
            let mut cred = Vec::new();
            put_entry(&mut cred, e);
            args.extend_from_slice(&(cred.len() as u32).to_be_bytes());
            args.extend_from_slice(&cred);
        }
        match self.call(OP_REPLACE, Some(name), &args) {
            Ok(_) => return Ok(()),
            Err(Failed::Code(c)) if unsupported(c) => {
                debug!("KCM daemon refused REPLACE ({c}); using INITIALIZE and STORE");
            }
            Err(f) => return Err(f.into_error("REPLACE")),
        }

        let mut princ = Vec::new();
        put_principal(&mut princ, &cache.principal);
        self.checked("INITIALIZE", OP_INITIALIZE, Some(name), &princ)?;
        for e in &cache.entries {
            let mut cred = Vec::new();
            put_entry(&mut cred, e);
            self.checked("STORE", OP_STORE, Some(name), &cred)?;
        }
        if cache.time_offset().is_some() {
            // Best effort, as MIT's set_kdc_offset.
            let _ = self.call(OP_SET_KDC_OFFSET, Some(name), &offset.to_be_bytes());
        }
        Ok(())
    }
}

/// Why a call failed: the daemon's krb5 code, or a cache error already.
enum Failed {
    Code(i32),
    Cache(CacheError),
}

impl Failed {
    fn into_error(self, op: &'static str) -> CacheError {
        match self {
            Failed::Code(code) => CacheError::Kcm { op, code },
            Failed::Cache(e) => e,
        }
    }
}

#[cfg(test)]
mod tests {
    //! A fake daemon pins the framing MIT's cc_kcm.c uses and exercises the
    //! fallbacks; agreement with real daemons is the live tests' job
    //! (tests/kdc.rs against Heimdal's kcm and sssd-kcm).
    use super::*;
    use crate::ccache::{CacheName, Entry};
    use std::collections::HashMap;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Store {
        caches: HashMap<String, (Vec<u8>, Vec<Vec<u8>>)>,
        default: String,
        ops: Vec<u16>,
        offsets: Vec<i32>,
    }

    /// Serve KCM on a fresh socket. `mit_ext`: answer GET_CRED_LIST and
    /// REPLACE (sssd) or refuse them with KRB5_FCC_INTERNAL (Heimdal).
    fn daemon(mit_ext: bool) -> (PathBuf, Arc<Mutex<Store>>) {
        let dir = std::env::temp_dir().join(format!("krb5-kcm-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let listener = UnixListener::bind(&path).unwrap();
        let store = Arc::new(Mutex::new(Store {
            default: "1000".into(),
            ..Store::default()
        }));
        let st = store.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let mut c = conn.unwrap();
                let st = st.clone();
                std::thread::spawn(move || {
                    while let Some(reply) = serve_one(&mut c, &st, mit_ext) {
                        let mut out = (reply.len() as u32 - 4).to_be_bytes().to_vec();
                        out.extend_from_slice(&0i32.to_be_bytes()); // transport ok
                        out.extend_from_slice(&reply);
                        // Length counts the payload, which starts with the status.
                        let len = (reply.len() as u32).to_be_bytes();
                        out[..4].copy_from_slice(&len);
                        c.write_all(&out).unwrap();
                    }
                });
            }
        });
        (path, store)
    }

    fn serve_one(c: &mut UnixStream, st: &Mutex<Store>, mit_ext: bool) -> Option<Vec<u8>> {
        let mut len = [0u8; 4];
        c.read_exact(&mut len).ok()?;
        let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut req).unwrap();
        assert_eq!(&req[..2], &[2, 0], "protocol version 2.0");
        let op = u16::from_be_bytes([req[2], req[3]]);
        let mut st = st.lock().unwrap();
        st.ops.push(op);
        let rest = &req[4..];
        let (name, args) = match rest.iter().position(|&b| b == 0) {
            Some(i) if op != OP_GET_DEFAULT_CACHE => (
                String::from_utf8(rest[..i].to_vec()).unwrap(),
                &rest[i + 1..],
            ),
            _ => (String::new(), rest),
        };
        let ok = |payload: Vec<u8>| {
            let mut r = 0i32.to_be_bytes().to_vec();
            r.extend(payload);
            r
        };
        let err = |code: i32| code.to_be_bytes().to_vec();
        let principal_len = |a: &[u8]| {
            let mut r = In {
                data: a,
                version: 4,
            };
            r.principal().ok().unwrap();
            a.len() - r.data.len()
        };
        Some(match op {
            OP_GET_DEFAULT_CACHE => ok(format!("{}\0", st.default).into_bytes()),
            OP_SET_DEFAULT_CACHE => {
                st.default = name;
                ok(vec![])
            }
            OP_INITIALIZE => {
                st.caches.insert(name, (args.to_vec(), vec![]));
                ok(vec![])
            }
            OP_STORE => match st.caches.get_mut(&name) {
                Some(c) => {
                    c.1.push(args.to_vec());
                    ok(vec![])
                }
                None => err(KRB5_FCC_NOFILE),
            },
            OP_GET_PRINCIPAL => match st.caches.get(&name) {
                Some(c) => ok(c.0.clone()),
                None => err(KRB5_FCC_NOFILE),
            },
            OP_GET_CRED_LIST if mit_ext => match st.caches.get(&name) {
                Some(c) => {
                    let mut p = (c.1.len() as u32).to_be_bytes().to_vec();
                    for cred in &c.1 {
                        p.extend((cred.len() as u32).to_be_bytes());
                        p.extend(cred);
                    }
                    ok(p)
                }
                None => err(KRB5_FCC_NOFILE),
            },
            OP_GET_CRED_UUID_LIST => match st.caches.get(&name) {
                Some(c) => ok((0..c.1.len()).flat_map(|i| [i as u8; 16]).collect()),
                None => err(KRB5_FCC_NOFILE),
            },
            OP_GET_CRED_BY_UUID => {
                let i = args[0] as usize;
                match st.caches.get(&name).and_then(|c| c.1.get(i)) {
                    Some(cred) => ok(cred.clone()),
                    None => err(KRB5_CC_END),
                }
            }
            OP_GET_KDC_OFFSET => ok(7i32.to_be_bytes().to_vec()),
            OP_REPLACE if mit_ext => {
                st.offsets
                    .push(i32::from_be_bytes(args[..4].try_into().unwrap()));
                let a = &args[4..];
                let pl = principal_len(a);
                let princ = a[..pl].to_vec();
                let mut r = In {
                    data: &a[pl..],
                    version: 4,
                };
                let n = r.u32().ok().unwrap();
                let creds = (0..n).map(|_| r.data().ok().unwrap().to_vec()).collect();
                assert!(r.data.is_empty());
                st.caches.insert(name, (princ, creds));
                ok(vec![])
            }
            _ => err(KRB5_FCC_INTERNAL),
        })
    }

    fn fixture() -> CCache {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/ccache/mit-v4.ccache"
        ))
        .unwrap();
        CCache::decode(&bytes).unwrap()
    }

    fn name(path: &Path, n: &str) -> CacheName {
        CacheName::Kcm {
            name: n.into(),
            socket: Some(path.to_path_buf()),
        }
    }

    #[test]
    fn a_cache_round_trips_through_a_daemon_with_the_mit_extensions() {
        let (sock, store) = daemon(true);
        let cc = fixture();
        name(&sock, "1000").write(&cc).unwrap();
        let back = name(&sock, "1000").read().unwrap();
        assert_eq!(back.principal, cc.principal);
        assert_eq!(back.entries, cc.entries);
        assert_eq!(back.time_offset(), Some((7, 0)));
        // The offset MIT's kinit recorded in the fixture went out in REPLACE.
        assert_eq!(store.lock().unwrap().offsets, [0]);
        let ops = &store.lock().unwrap().ops;
        assert!(
            ops.contains(&OP_REPLACE) && ops.contains(&OP_GET_CRED_LIST),
            "{ops:?}"
        );
        assert!(!ops.contains(&OP_STORE), "{ops:?}");
    }

    #[test]
    fn a_heimdal_style_daemon_gets_initialize_store_and_uuid_reads() {
        let (sock, store) = daemon(false);
        let cc = fixture();
        name(&sock, "1000").write(&cc).unwrap();
        let back = name(&sock, "1000").read().unwrap();
        assert_eq!(back.entries, cc.entries);
        let ops = &store.lock().unwrap().ops;
        for op in [
            OP_INITIALIZE,
            OP_STORE,
            OP_GET_CRED_UUID_LIST,
            OP_GET_CRED_BY_UUID,
        ] {
            assert!(ops.contains(&op), "{op} not in {ops:?}");
        }
        assert_eq!(
            ops.iter().filter(|&&o| o == OP_STORE).count(),
            cc.entries.len()
        );
    }

    #[test]
    fn kcm_with_no_name_is_the_daemons_primary_cache() {
        let (sock, _) = daemon(true);
        name(&sock, "1000:work").write(&fixture()).unwrap();
        name(&sock, "1000:work").make_primary().unwrap();
        assert_eq!(
            name(&sock, "").resolved().unwrap(),
            name(&sock, "1000:work")
        );
        assert_eq!(name(&sock, "").read().unwrap().entries, fixture().entries);
    }

    #[test]
    fn a_missing_cache_is_reported_by_code() {
        let (sock, _) = daemon(true);
        let e = name(&sock, "nope").read().unwrap_err();
        assert!(
            matches!(
                e,
                CacheError::Kcm {
                    code: KRB5_FCC_NOFILE,
                    ..
                }
            ),
            "{e}"
        );
        assert!(e.to_string().contains("no such cache"), "{e}");
    }

    #[test]
    fn no_daemon_and_disabled_kcm_are_distinct_errors() {
        let gone =
            std::env::temp_dir().join(format!("krb5-kcm-none-{:016x}", rand::random::<u64>()));
        let e = name(&gone, "x").read().unwrap_err();
        assert!(matches!(e, CacheError::KcmUnavailable { .. }), "{e}");
        let off = CacheName::Kcm {
            name: "x".into(),
            socket: None,
        };
        assert!(
            off.read()
                .unwrap_err()
                .to_string()
                .contains("kcm_socket = -")
        );
    }

    #[test]
    fn an_oversized_reply_is_refused_before_allocating() {
        let dir = std::env::temp_dir().join(format!("krb5-kcm-big-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let _ = c.read(&mut buf);
            c.write_all(&u32::MAX.to_be_bytes()).unwrap();
        });
        let e = name(&path, "x").read().unwrap_err();
        assert!(e.to_string().contains("malformed KCM reply"), "{e}");
    }

    #[test]
    fn entries_survive_store_semantics_over_kcm() {
        let (sock, _) = daemon(true);
        let n = name(&sock, "1000");
        n.write(&fixture()).unwrap();
        let mut cc = n.read().unwrap();
        let st = cc.credentials().nth(1).unwrap();
        cc.store(&st);
        n.write(&cc).unwrap();
        let back = n.read().unwrap();
        assert_eq!(back.entries.len(), fixture().entries.len());
        assert!(
            back.entries
                .iter()
                .filter(|e: &&Entry| e.is_config())
                .count()
                == 2
        );
    }
}
