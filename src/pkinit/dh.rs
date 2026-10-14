//! Finite-field Diffie-Hellman for PKINIT (RFC 4556 §3.2.3.1) over the
//! RFC 3526 MODP groups 14 (2048-bit, MIT's default `pkinit_dh_min_bits`)
//! and 16 (4096-bit): what every MIT KDC accepts. MIT added elliptic
//! curves only in 1.22.

use super::asn1::{self, ReaderExt};
use super::bigint::{less, minus_one, modpow};
use crate::der::{self, Reader};
use rand::RngCore;

/// `dhpublicnumber` (ANSI X9.42).
pub(crate) const DH_PUBLIC_NUMBER: &str = "1.2.840.10046.2.1";

const MODP_2048: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
);

const MODP_4096: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("a hex constant"))
        .collect()
}

/// A MODP group: the safe prime `p`, generator 2, and `q = (p-1)/2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Group {
    p: Vec<u8>,
}

impl Group {
    /// Group 16 for `min_bits` above 2048, else group 14, as MIT picks for
    /// `pkinit_dh_min_bits`.
    pub(crate) fn at_least(min_bits: u32) -> Group {
        Group {
            p: unhex(if min_bits > 2048 {
                MODP_4096
            } else {
                MODP_2048
            }),
        }
    }

    /// The known group whose X9.42 DomainParameters (or PKCS #3 DHParameter,
    /// `{ p, g }`) these are.
    pub(crate) fn from_domain_parameters(params: &[u8]) -> Option<Group> {
        let mut s = Reader::new(params).seq().ok()?;
        let p = s.uint().ok()?;
        [2048, 4096]
            .map(Group::at_least)
            .into_iter()
            .find(|g| g.p == p && s.uint().ok() == Some(&[2][..]))
    }

    pub(crate) fn bits(&self) -> u32 {
        (self.p.len() * 8) as u32
    }

    /// `q = (p-1)/2 = p >> 1` for the safe prime `p`.
    fn q(&self) -> Vec<u8> {
        let mut q = Vec::with_capacity(self.p.len());
        let mut carry = 0;
        for &b in &self.p {
            q.push((b >> 1) | carry);
            carry = b << 7;
        }
        q
    }

    /// X9.42 `DomainParameters ::= SEQUENCE { p, g, q }`, as OpenSSL
    /// writes them for a DHX key and MIT's KDC matches them against its
    /// known groups.
    fn domain_parameters(&self) -> Vec<u8> {
        der::seq(&[asn1::uint(&self.p), asn1::uint(&[2]), asn1::uint(&self.q())])
    }
}

/// An ephemeral DH key pair.
pub(crate) struct KeyPair {
    group: Group,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl KeyPair {
    /// A fresh key: `x` is 2 bits shorter than `p`, so below `q`.
    pub(crate) fn generate(group: Group) -> KeyPair {
        let mut x = vec![0u8; group.p.len()];
        loop {
            rand::thread_rng().fill_bytes(&mut x);
            x[0] &= 0x3F;
            if asn1::strip(&x).len() > 1 {
                break;
            }
        }
        let y = modpow(&[2], &x, &group.p).expect("2 < p, p odd");
        KeyPair { group, x, y }
    }

    pub(crate) fn group(&self) -> &Group {
        &self.group
    }

    /// `y` as the INTEGER a peer receives.
    #[cfg(test)]
    pub(crate) fn public_value(&self) -> Vec<u8> {
        asn1::uint(&self.y)
    }

    /// `clientPublicValue`: a SubjectPublicKeyInfo with algorithm
    /// `dhpublicnumber`, the group's DomainParameters, and `y` as an
    /// INTEGER inside the BIT STRING.
    pub(crate) fn spki(&self) -> Vec<u8> {
        der::seq(&[
            asn1::alg_id(DH_PUBLIC_NUMBER, Some(self.group.domain_parameters())),
            asn1::bit_string(&asn1::uint(&self.y)),
        ])
    }

    /// The shared secret `Z = Y^x mod p` for the KDC's public value (the
    /// INTEGER inside KDCDHKeyInfo's BIT STRING), left-padded to the
    /// length of `p` (RFC 4556 §3.2.3.1). `Y` must lie in `(1, p-1)` and in
    /// the order-`q` subgroup, which rules out the small-subgroup values
    /// that would make `Z` guessable.
    pub(crate) fn agree(&self, kdc_public: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(kdc_public);
        let y = r.uint().ok()?;
        r.done("DH public key").ok()?;
        let p = &self.group.p;
        if !less(&[1], y) || !less(y, &minus_one(p)) {
            return None;
        }
        if asn1::strip(&modpow(y, &self.group.q(), p)?) != [1] {
            return None;
        }
        modpow(y, &self.x, p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_groups_are_rfc_3526_with_q_half_of_p() {
        let g = Group::at_least(2048);
        assert_eq!(g.bits(), 2048);
        assert_eq!(Group::at_least(0), g);
        assert_eq!(Group::at_least(4096).bits(), 4096);
        // 2^q = 1 mod p: 2 generates the order-q subgroup.
        assert_eq!(asn1::strip(&modpow(&[2], &g.q(), &g.p).unwrap()), [1]);
        let q = g.q();
        assert_eq!(&q[..8], &[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(q.last(), Some(&0xFF));
    }

    #[test]
    fn two_parties_agree() {
        let a = KeyPair::generate(Group::at_least(2048));
        let b = KeyPair::generate(Group::at_least(2048));
        let za = a.agree(&asn1::uint(&b.y)).unwrap();
        let zb = b.agree(&asn1::uint(&a.y)).unwrap();
        assert_eq!(za, zb);
        assert_eq!(za.len(), 256);
    }

    #[test]
    fn degenerate_and_small_subgroup_values_are_refused() {
        let a = KeyPair::generate(Group::at_least(2048));
        let p = a.group.p.clone();
        for bad in [vec![0], vec![1], minus_one(&p), p.clone()] {
            assert!(a.agree(&asn1::uint(&bad)).is_none(), "{:02x?}", &bad[..1]);
        }
        // A generator of the whole group (not a quadratic residue) is
        // outside the order-q subgroup: p ≡ 7 mod 8 makes 2 a residue and
        // -2 = p-2 a non-residue.
        let mut minus_two = minus_one(&p);
        let last = minus_two.len() - 1;
        minus_two[last] -= 1;
        assert!(a.agree(&asn1::uint(&minus_two)).is_none());
        assert!(a.agree(&[0x04, 1, 0]).is_none(), "not an INTEGER");
    }

    #[test]
    fn the_public_value_is_an_x942_spki() {
        let a = KeyPair::generate(Group::at_least(2048));
        let spki = a.spki();
        let mut r = Reader::new(&spki);
        let mut s = r.seq().unwrap();
        let (alg, params) = s.alg_id().unwrap();
        assert_eq!(alg, asn1::oid(DH_PUBLIC_NUMBER));
        let mut dp = Reader::new(params.unwrap()).seq().unwrap();
        assert_eq!(dp.uint().unwrap(), a.group.p);
        assert_eq!(dp.uint().unwrap(), [2]);
        assert_eq!(dp.uint().unwrap(), a.group.q());
        let mut key = Reader::new(s.bits().unwrap());
        assert_eq!(key.uint().unwrap(), asn1::strip(&a.y));
    }
}
