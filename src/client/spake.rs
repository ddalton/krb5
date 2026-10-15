//! SPAKE pre-authentication (draft-ietf-kitten-krb-spake-preauth, MIT
//! 1.17 and later): a password login that gives a recorded exchange
//! nothing to guess passwords against offline.
//!
//! The client's long-term key (from the password or a keytab) is not used
//! to encrypt anything the KDC can be asked for. Instead both sides derive
//! a multiplier w from it and run a Diffie-Hellman exchange whose public
//! values are masked by w: the KDC sends T = x·G + w·M, the client
//! S = y·G + w·N, and each computes K = x·y·G. Only someone who knows w
//! can unmask the other's value, so an eavesdropper learns nothing it can
//! test a guess with, and a false KDC gets one guess per login. The reply
//! key becomes `K'[0]`, derived from the initial key, w, K, a hash of the
//! exchange and the request body.
//!
//! As MIT's client: a support message lists our groups ([`SpakeGroup`];
//! edwards25519 by default, `spake_preauth_groups` in krb5.conf), the KDC
//! answers with a challenge for one of them, and the response carries S
//! and an encrypted SF-NONE second factor (no second factor; MIT
//! implements none). A challenge the KDC sends optimistically, before any
//! support message, is answered directly. A KDC that takes none of our
//! groups leaves the login to encrypted timestamps, as with MIT.
//!
//! edwards25519 is implemented here, in constant time. The NIST groups
//! need the `spake-nist` feature (or `pkinit`, which brings the same
//! curve crates).

use super::*;
use sha2::{Digest, Sha256, Sha384, Sha512};

mod ed25519;
#[cfg(feature = "spake-nist")]
mod nist;

pub(super) const PA_SPAKE: i32 = 151;
pub(super) const KDC_ERR_MORE_PREAUTH_DATA_REQUIRED: i32 = 91;
const KU_SPAKE: u32 = 65;
const SF_NONE: i64 = 1;

/// A SPAKE group (the IANA "Kerberos SPAKE Groups" registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpakeGroup {
    /// edwards25519 (RFC 7748), MIT's client default.
    Edwards25519,
    /// NIST P-256 (with the `spake-nist` feature).
    P256,
    /// NIST P-384 (with the `spake-nist` feature).
    P384,
    /// NIST P-521 (with the `spake-nist` feature).
    P521,
}

/// The constant a party's public value is masked with: the KDC's is M,
/// the client's N.
#[derive(Clone, Copy)]
enum Mask {
    M,
    N,
}

const ED25519_M: [u8; 32] = [
    0xD0, 0x48, 0x03, 0x2C, 0x6E, 0xA0, 0xB6, 0xD6, 0x97, 0xDD, 0xC2, 0xE8, 0x6B, 0xDA, 0x85, 0xA3,
    0x3A, 0xDA, 0xC9, 0x20, 0xF1, 0xBF, 0x18, 0xE1, 0xB0, 0xC6, 0xD1, 0x66, 0xA5, 0xCE, 0xCD, 0xAF,
];
const ED25519_N: [u8; 32] = [
    0xD3, 0xBF, 0xB5, 0x18, 0xF4, 0x4F, 0x34, 0x30, 0xF2, 0x9D, 0x0C, 0x92, 0xAF, 0x50, 0x38, 0x65,
    0xA1, 0xED, 0x32, 0x81, 0xDC, 0x69, 0xB3, 0x5D, 0xD8, 0x68, 0xBA, 0x85, 0xF8, 0x86, 0xC4, 0xAB,
];

impl SpakeGroup {
    const ALL: [SpakeGroup; 4] = [
        SpakeGroup::Edwards25519,
        SpakeGroup::P256,
        SpakeGroup::P384,
        SpakeGroup::P521,
    ];

    /// The registry number.
    pub fn id(self) -> i32 {
        match self {
            SpakeGroup::Edwards25519 => 1,
            SpakeGroup::P256 => 2,
            SpakeGroup::P384 => 3,
            SpakeGroup::P521 => 4,
        }
    }

    pub fn from_id(id: i32) -> Option<SpakeGroup> {
        Self::ALL.into_iter().find(|g| g.id() == id)
    }

    /// The name krb5.conf uses (`edwards25519`, `P-256`, ...).
    pub fn name(self) -> &'static str {
        match self {
            SpakeGroup::Edwards25519 => "edwards25519",
            SpakeGroup::P256 => "P-256",
            SpakeGroup::P384 => "P-384",
            SpakeGroup::P521 => "P-521",
        }
    }

    /// The group named `name`, ignoring case, as MIT matches it.
    pub fn from_name(name: &str) -> Option<SpakeGroup> {
        Self::ALL
            .into_iter()
            .find(|g| g.name().eq_ignore_ascii_case(name))
    }

    /// Whether this build can use the group (the NIST ones need the
    /// `spake-nist` feature).
    pub fn is_available(self) -> bool {
        self == SpakeGroup::Edwards25519 || cfg!(feature = "spake-nist")
    }

    /// MIT's `spake_preauth_groups` parsing: whitespace- or
    /// comma-separated names; unknown and unavailable ones are skipped,
    /// duplicates dropped.
    pub fn parse_list(s: &str) -> Vec<SpakeGroup> {
        let mut out = Vec::new();
        for g in s
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter_map(SpakeGroup::from_name)
        {
            if g.is_available() && !out.contains(&g) {
                out.push(g);
            }
        }
        out
    }

    /// Octets of w (and of a private scalar).
    fn mult_len(self) -> usize {
        match self {
            SpakeGroup::Edwards25519 | SpakeGroup::P256 => 32,
            SpakeGroup::P384 => 48,
            SpakeGroup::P521 => 66,
        }
    }

    fn hash_len(self) -> usize {
        match self {
            SpakeGroup::Edwards25519 | SpakeGroup::P256 => 32,
            SpakeGroup::P384 => 48,
            SpakeGroup::P521 => 64,
        }
    }

    /// The group's hash over the concatenation of `parts`.
    fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn h<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self {
            SpakeGroup::Edwards25519 | SpakeGroup::P256 => h::<Sha256>(parts),
            SpakeGroup::P384 => h::<Sha384>(parts),
            SpakeGroup::P521 => h::<Sha512>(parts),
        }
    }

    /// A random private scalar and the public value it gives.
    fn keygen(self, w: &[u8], mask: Mask) -> Result<(Vec<u8>, Vec<u8>)> {
        let private = match self {
            SpakeGroup::Edwards25519 => {
                let mut r = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut r);
                // MIT: uniform in [0, L) times the cofactor 8, so the
                // shared point is in the prime-order subgroup whatever the
                // peer sends.
                times_8(&ed25519::reduce_scalar(&r)).to_vec()
            }
            #[cfg(feature = "spake-nist")]
            _ => nist::random_scalar(self),
            #[cfg(not(feature = "spake-nist"))]
            _ => return Err(unavailable(self)),
        };
        let public = self.public(w, &private, mask)?;
        Ok((private, public))
    }

    /// The public value for `private`: private·G + w·mask, encoded.
    fn public(self, w: &[u8], private: &[u8], mask: Mask) -> Result<Vec<u8>> {
        match self {
            SpakeGroup::Edwards25519 => {
                let private: &[u8; 32] = private
                    .try_into()
                    .map_err(|_| ClientError::Protocol("bad edwards25519 scalar".into()))?;
                Ok(ed25519::Point::base()
                    .mul(private)
                    .add(&ed25519_mask(w, mask))
                    .encode()
                    .to_vec())
            }
            #[cfg(feature = "spake-nist")]
            _ => nist::public(self, w, private, mask),
            #[cfg(not(feature = "spake-nist"))]
            _ => Err(unavailable(self)),
        }
    }

    /// K = priv·(theirs − w·mask), encoded; `mask` is the peer's
    /// constant. An invalid point fails.
    fn result(self, w: &[u8], private: &[u8], theirs: &[u8], mask: Mask) -> Result<Vec<u8>> {
        match self {
            SpakeGroup::Edwards25519 => {
                let bad =
                    || ClientError::Protocol("the KDC's SPAKE value is not a curve point".into());
                let theirs: &[u8; 32] = theirs.try_into().map_err(|_| bad())?;
                let private: &[u8; 32] = private.try_into().map_err(|_| bad())?;
                let q = ed25519::Point::decode(theirs).ok_or_else(bad)?;
                let unmasked = q.add(&ed25519_mask(w, mask).neg());
                Ok(unmasked.mul(private).encode().to_vec())
            }
            #[cfg(feature = "spake-nist")]
            _ => nist::result(self, w, private, theirs, mask),
            #[cfg(not(feature = "spake-nist"))]
            _ => Err(unavailable(self)),
        }
    }
}

#[cfg(not(feature = "spake-nist"))]
fn unavailable(g: SpakeGroup) -> ClientError {
    ClientError::NoKey(format!(
        "SPAKE group {} needs the spake-nist feature",
        g.name()
    ))
}

/// w·M or w·N on edwards25519, w reduced mod L as MIT reduces it.
fn ed25519_mask(w: &[u8], mask: Mask) -> ed25519::Point {
    let c = match mask {
        Mask::M => &ED25519_M,
        Mask::N => &ED25519_N,
    };
    let point = ed25519::Point::decode(c).expect("the SPAKE constants are points");
    let w: [u8; 32] = w.try_into().expect("edwards25519 w is 32 octets");
    point.mul(&ed25519::reduce_scalar(&w))
}

/// n·8, little-endian, for n < L (so it still fits in 256 bits).
fn times_8(n: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u8;
    for i in 0..32 {
        out[i] = (n[i] << 3) | carry;
        carry = n[i] >> 5;
    }
    out
}

/// MIT's `derive_wbytes`: PRF+(initial key, "SPAKEsecret" || group).
fn wbytes(group: SpakeGroup, ikey: &Key) -> Result<Vec<u8>> {
    let mut input = b"SPAKEsecret".to_vec();
    input.extend_from_slice(&group.id().to_be_bytes());
    Ok(ikey.prf_plus(&input, group.mult_len())?)
}

/// MIT's `update_thash`: H(thash || a || b), from all zeros.
fn update_thash(group: SpakeGroup, thash: &[u8], a: &[u8], b: &[u8]) -> Vec<u8> {
    group.hash(&[thash, a, b])
}

/// MIT's `derive_key`: `K'[n]`, from the initial key, w, the shared value
/// K, the transcript hash and the request body, through random-to-key
/// and KRB-FX-CF2.
#[allow(clippy::too_many_arguments)]
fn derive_key(
    group: SpakeGroup,
    ikey: &Key,
    w: &[u8],
    k: &[u8],
    thash: &[u8],
    body: &[u8],
    n: u32,
) -> Result<Key> {
    let etype = ikey.enctype();
    // AES random-to-key is the identity: the seed is the key's length.
    let seed_len = ikey.bytes().len();
    let mut seed = Vec::new();
    let mut block = 1u8;
    while seed.len() < seed_len {
        seed.extend(group.hash(&[
            b"SPAKEkey",
            &group.id().to_be_bytes(),
            &etype.to_be_bytes(),
            w,
            k,
            thash,
            body,
            &n.to_be_bytes(),
            &[block],
        ]));
        block += 1;
    }
    seed.truncate(seed_len);
    let hkey = Key::new(etype, seed)?;
    Ok(Key::cf2(ikey, "SPAKE", &hkey, "keyderiv")?)
}

/// `PA-SPAKE ::= CHOICE { support [0] SPAKESupport, ... }`, with
/// `SPAKESupport ::= SEQUENCE { groups [0] SEQUENCE OF Int32 }`.
fn support_message(groups: &[SpakeGroup]) -> Vec<u8> {
    let ids: Vec<Vec<u8>> = groups.iter().map(|g| der::int(i64::from(g.id()))).collect();
    der::field(0, der::seq(&[der::field(0, der::seq(&ids))]))
}

/// A SPAKEChallenge: the group, the KDC's public value T, and the second
/// factor types it accepts.
struct Challenge {
    group: i32,
    pubkey: Vec<u8>,
    factors: Vec<i64>,
}

/// The PA-SPAKE CHOICE: a challenge, or `None` for the other choices
/// (support, response, encdata), which a client does not act on.
fn parse_challenge(value: &[u8]) -> Result<Option<Challenge>> {
    let mut r = Reader::new(value);
    let (tag, content) = r.next()?;
    if tag != der::ctx(1) {
        return Ok(None);
    }
    let f = Fields::parse_tagged("SPAKEChallenge", der::SEQUENCE, content)?;
    let mut factors = Vec::new();
    let mut fs = f.get(2)?.seq()?;
    while !fs.is_empty() {
        let factor = Fields::parse("SPAKESecondFactor", fs.expect(der::SEQUENCE)?)?;
        factors.push(factor.get(0)?.int()?);
    }
    Ok(Some(Challenge {
        group: f.get(0)?.i32()?,
        pubkey: f.get(1)?.octets()?.to_vec(),
        factors,
    }))
}

/// Where a login is with SPAKE.
#[derive(Default)]
pub(super) struct Spake {
    /// The support message sent, which starts the transcript.
    support: Option<Vec<u8>>,
    /// A challenge to answer in the next request, once its body is known.
    pending: Option<Pending>,
    /// A response has gone: no other pre-authentication from here on.
    responded: bool,
    /// The KDC took none of our groups: encrypted timestamps instead.
    pub(super) declined: bool,
}

pub(super) struct Pending {
    group: SpakeGroup,
    challenge: Vec<u8>,
    pubkey: Vec<u8>,
    ikey: Key,
}

/// What to do with the KDC's PA-SPAKE.
pub(super) enum Step {
    /// Send this PA-SPAKE value (a support message) now.
    Send(Vec<u8>),
    /// Answer a challenge in the next request ([`Spake::respond`]).
    Respond,
}

impl Spake {
    pub(super) fn responded(&self) -> bool {
        self.responded
    }

    pub(super) fn support_sent(&self) -> bool {
        self.support.is_some() && !self.responded
    }

    /// The KDC's PA-SPAKE `value` (empty: SPAKE offered, no challenge),
    /// with `ikey` the initial reply key from its ETYPE-INFO2.
    pub(super) fn step(&mut self, groups: &[SpakeGroup], value: &[u8], ikey: Key) -> Result<Step> {
        let failed = || ClientError::Kdc {
            code: KDC_ERR_PREAUTH_FAILED,
            text: Some("SPAKE challenge not acceptable".into()),
        };
        let challenge = if value.is_empty() {
            None
        } else {
            parse_challenge(value)?
        };
        let usable = challenge
            .as_ref()
            .and_then(|c| SpakeGroup::from_id(c.group).filter(|g| groups.contains(g)));
        match (challenge, usable) {
            (Some(c), Some(group)) => {
                // MIT supports only SF-NONE as yet.
                if !c.factors.contains(&SF_NONE) {
                    return Err(failed());
                }
                debug!(group = group.name(), "answering a SPAKE challenge");
                self.pending = Some(Pending {
                    group,
                    challenge: value.to_vec(),
                    pubkey: c.pubkey,
                    ikey,
                });
                Ok(Step::Respond)
            }
            // Offered, or challenged in a group we do not take: say what
            // we support, once.
            _ if self.support.is_none() => {
                let m = support_message(groups);
                self.support = Some(m.clone());
                debug!("sending SPAKE support");
                Ok(Step::Send(m))
            }
            _ => Err(failed()),
        }
    }

    /// The PA-SPAKE response for the request whose KDC-REQ-BODY is
    /// `body`, and `K'[0]`, the reply key, if a challenge is pending.
    pub(super) fn respond(&mut self, body: &[u8]) -> Result<Option<(Vec<u8>, Key)>> {
        let Some(p) = self.pending.take() else {
            return Ok(None);
        };
        let g = p.group;
        let w = wbytes(g, &p.ikey)?;
        let (private, public) = g.keygen(&w, Mask::N)?;
        let k = g.result(&w, &private, &p.pubkey, Mask::M)?;
        let zeros = vec![0u8; g.hash_len()];
        let thash = update_thash(
            g,
            &zeros,
            self.support.as_deref().unwrap_or(&[]),
            &p.challenge,
        );
        let thash = update_thash(g, &thash, &public, &[]);
        let k0 = derive_key(g, &p.ikey, &w, &k, &thash, body, 0)?;
        let k1 = derive_key(g, &p.ikey, &w, &k, &thash, body, 1)?;
        let factor = der::seq(&[der::field(0, der::int(SF_NONE))]);
        let enc = k1.encrypt(KU_SPAKE, &factor)?;
        let response = der::field(
            2,
            der::seq(&[
                der::field(0, der::octets(&public)),
                der::field(1, encode_encrypted_data(k1.enctype(), &enc)),
            ]),
        );
        self.responded = true;
        Ok(Some((response, k0)))
    }
}

#[cfg(test)]
mod tests;
