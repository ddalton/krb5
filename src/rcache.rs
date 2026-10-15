//! Replay detection for AP-REQs (RFC 4120 §3.2.3): an acceptor must
//! refuse an authenticator it has already accepted while that
//! authenticator could still pass its clock-skew check.
//!
//! As in MIT (`k5_rc_tag_from_ciphertext`), an authenticator is
//! identified by its tag: the integrity checksum that ends its
//! ciphertext. Only authenticators that decrypt are stored, so the tags
//! are MACs under session keys an attacker without the key cannot choose.
//!
//! [`ReplayCache`] is the default store: in memory, shared by every
//! acceptor in the process ([`ReplayCache::global`]), sharded so threads
//! accepting at once rarely meet on a lock, and costing one hash lookup
//! per AP-REQ. An entry is kept exactly as long as its authenticator
//! could pass the skew check; expired entries go in bulk, a whole
//! generation of the table at a time, never one by one.
//!
//! A replay presented to a different process, or a different host, is
//! not seen by an in-memory cache. Services that run as several processes
//! or behind a load balancer can plug in a shared store by implementing
//! [`ReplayStore`]. MIT's acceptors default to a file in `/var/tmp` locked
//! with `fcntl`; this crate does not share that file (it would need
//! `fcntl`, and so libc, to lock it as MIT does).
//!
//! As in MIT, `KRB5RCACHETYPE=none` (or `KRB5RCACHENAME=none:`) turns
//! replay detection off for acceptors using the default options.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

/// Where an acceptor records the authenticators it has accepted.
pub trait ReplayStore: fmt::Debug + Send + Sync {
    /// Record `tag` (an authenticator's checksum), which must be kept
    /// until `expires` (Unix seconds; it may go once the time is past
    /// it). `now` is the acceptor's clock. `Ok(true)` if the tag is new,
    /// `Ok(false)` if it is recorded already and not expired: a replay.
    fn insert(&self, tag: &[u8], now: i64, expires: i64) -> io::Result<bool>;
}

/// The longest tag: the 192-bit checksum of aes256-cts-hmac-sha384-192.
/// Shorter ones (96 bits for the SHA-1 enctypes, 128 for
/// aes128-cts-hmac-sha256-128) are zero-padded.
const TAG_LEN: usize = 24;
const SHARDS: usize = 64;

type Tag = [u8; TAG_LEN];

/// An in-memory [`ReplayStore`]. See the module docs.
pub struct ReplayCache {
    shards: Box<[Mutex<Shard>]>,
}

/// Two generations of entries. New tags go into `cur`. Once every entry
/// in `prev` has expired, `prev` is dropped whole, `cur` becomes `prev`,
/// and a new `cur` starts: each tag lives in at most two generations, and
/// no generation outlives its last entry by more than one rotation.
#[derive(Default)]
struct Shard {
    cur: HashMap<Tag, i64>,
    /// The latest expiry in `cur`.
    cur_until: i64,
    prev: HashMap<Tag, i64>,
    prev_until: i64,
}

impl Shard {
    fn live(&self, tag: &Tag, now: i64) -> bool {
        let live = |m: &HashMap<Tag, i64>| m.get(tag).is_some_and(|&e| e >= now);
        live(&self.cur) || live(&self.prev)
    }
}

impl ReplayCache {
    /// An empty cache.
    pub fn new() -> Self {
        ReplayCache {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
        }
    }

    /// The process-wide cache that [`AcceptOptions::default`] uses.
    ///
    /// [`AcceptOptions::default`]: crate::acceptor::AcceptOptions
    pub fn global() -> Arc<ReplayCache> {
        static GLOBAL: OnceLock<Arc<ReplayCache>> = OnceLock::new();
        GLOBAL.get_or_init(|| Arc::new(ReplayCache::new())).clone()
    }

    /// The number of tags held, expired ones not yet dropped included.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                let s = s.lock().unwrap_or_else(|e| e.into_inner());
                s.cur.len() + s.prev.len()
            })
            .sum()
    }

    /// Whether the cache holds no tags.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        ReplayCache::new()
    }
}

impl fmt::Debug for ReplayCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayCache").finish_non_exhaustive()
    }
}

impl ReplayStore for ReplayCache {
    fn insert(&self, tag: &[u8], now: i64, expires: i64) -> io::Result<bool> {
        let mut t: Tag = [0; TAG_LEN];
        let n = tag.len().min(TAG_LEN);
        t[..n].copy_from_slice(&tag[..n]);
        // Tags are MACs, so any of their octets spread them evenly.
        let shard = &self.shards[usize::from(t[0]) % SHARDS];
        let dropped;
        {
            let mut s = shard.lock().unwrap_or_else(|e| e.into_inner());
            if s.live(&t, now) {
                return Ok(false);
            }
            dropped = if now > s.prev_until {
                let s = &mut *s;
                s.prev_until = s.cur_until;
                s.cur_until = now;
                Some(std::mem::replace(&mut s.prev, std::mem::take(&mut s.cur)))
            } else {
                None
            };
            s.cur.insert(t, expires);
            s.cur_until = s.cur_until.max(expires);
        }
        // Freed outside the lock.
        drop(dropped);
        Ok(true)
    }
}

/// The store [`AcceptOptions::default`] uses: [`ReplayCache::global`],
/// or none when `KRB5RCACHETYPE` is `none` or `KRB5RCACHENAME` names the
/// `none` type, as MIT reads them. Read once per process.
///
/// [`AcceptOptions::default`]: crate::acceptor::AcceptOptions
pub fn default_store() -> Option<Arc<dyn ReplayStore>> {
    static DEFAULT: OnceLock<Option<Arc<dyn ReplayStore>>> = OnceLock::new();
    DEFAULT
        .get_or_init(|| {
            let none = match std::env::var("KRB5RCACHENAME") {
                Ok(name) => name.starts_with("none:"),
                Err(_) => std::env::var("KRB5RCACHETYPE").is_ok_and(|t| t == "none"),
            };
            if none {
                None
            } else {
                Some(ReplayCache::global() as Arc<dyn ReplayStore>)
            }
        })
        .clone()
}

/// MIT's `k5_rc_tag_from_ciphertext`: the checksum that ends an
/// authenticator's ciphertext, as long as `enctype`'s checksum.
pub(crate) fn tag(enctype: i32, ciphertext: &[u8]) -> &[u8] {
    let len = match enctype {
        19 => 16,
        20 => 24,
        _ => 12,
    };
    &ciphertext[ciphertext.len().saturating_sub(len)..]
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_700_000_000;

    #[test]
    fn a_tag_is_refused_until_it_expires() {
        let rc = ReplayCache::new();
        assert!(rc.insert(b"tag-one-tag-one", T0, T0 + 300).unwrap());
        assert!(!rc.insert(b"tag-one-tag-one", T0, T0 + 300).unwrap());
        assert!(!rc.insert(b"tag-one-tag-one", T0 + 300, T0 + 600).unwrap());
        // Past its expiry, the authenticator could not pass the skew
        // check anyway; the tag may be stored again.
        assert!(rc.insert(b"tag-one-tag-one", T0 + 301, T0 + 601).unwrap());
        assert!(rc.insert(b"tag-two-tag-two", T0, T0 + 300).unwrap());
    }

    #[test]
    fn tags_differ_in_any_octet() {
        let rc = ReplayCache::new();
        let a = [7u8; 24];
        for i in 0..24 {
            let mut b = a;
            b[i] ^= 1;
            assert!(rc.insert(&b, T0, T0 + 300).unwrap());
        }
        assert!(rc.insert(&a, T0, T0 + 300).unwrap());
        assert!(!rc.insert(&a, T0, T0 + 300).unwrap());
        // A 12-octet tag and its zero-padded 24-octet form are one tag,
        // which no two enctypes' tags can be (different keys, MACs).
        assert!(rc.insert(&[9; 12], T0, T0 + 300).unwrap());
        let mut padded = [0u8; 24];
        padded[..12].copy_from_slice(&[9; 12]);
        assert!(!rc.insert(&padded, T0, T0 + 300).unwrap());
    }

    /// Generations rotate: nothing live is ever lost, and what has
    /// expired is dropped within two rotations.
    #[test]
    fn expired_generations_are_dropped_and_live_ones_kept() {
        let rc = ReplayCache::new();
        let skew = 300;
        let mut now = T0;
        let mut n = 0u32;
        let mut live: Vec<([u8; 24], i64)> = Vec::new();
        for _ in 0..40 {
            for _ in 0..50 {
                let mut tag = [0u8; 24];
                tag[..4].copy_from_slice(&n.to_be_bytes());
                tag[4..8].copy_from_slice(&n.wrapping_mul(2_654_435_761).to_be_bytes());
                tag[0] = tag[7];
                n += 1;
                // ctime anywhere within the skew of now.
                let ctime = now - skew + i64::from(n % 600);
                assert!(rc.insert(&tag, now, ctime + skew).unwrap());
                live.push((tag, ctime + skew));
            }
            live.retain(|(_, e)| *e >= now);
            for (tag, e) in &live {
                assert!(!rc.insert(tag, now, *e).unwrap(), "a live tag was lost");
            }
            now += 37;
        }
        // At most the live tags and two generations' worth besides.
        assert!(rc.len() < live.len() + 2 * 50 * (2 * 600 / 37 + 2));
        assert!(rc.len() < 40 * 50, "nothing was ever dropped");
    }

    #[test]
    fn the_tag_is_the_checksum_that_ends_the_ciphertext() {
        let c: Vec<u8> = (0..60).collect();
        assert_eq!(tag(17, &c), &c[48..]);
        assert_eq!(tag(18, &c), &c[48..]);
        assert_eq!(tag(19, &c), &c[44..]);
        assert_eq!(tag(20, &c), &c[36..]);
        assert_eq!(tag(18, &c[..5]), &c[..5]);
    }

    #[test]
    fn threads_accepting_at_once_see_one_acceptance_each() {
        let rc = Arc::new(ReplayCache::new());
        let accepted: usize = (0..8)
            .map(|_| {
                let rc = rc.clone();
                std::thread::spawn(move || {
                    (0..2000u32)
                        .filter(|i| {
                            let mut t = [0u8; 16];
                            t[..4].copy_from_slice(&i.to_le_bytes());
                            rc.insert(&t, T0, T0 + 300).unwrap()
                        })
                        .count()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .sum();
        assert_eq!(accepted, 2000);
    }
}
