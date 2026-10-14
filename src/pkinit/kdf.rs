//! The reply key from the DH shared secret: RFC 8636's SP 800-56A
//! single-step KDF when the KDC names one, else RFC 4556's
//! octetstring2key.

use super::asn1;
use crate::client::Principal;
use crate::der;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

/// `id-pkinit-kdf-ah-sha1`, `-sha256`, `-sha512` (RFC 8636 §8).
pub(crate) const KDF_SHA1: &str = "1.3.6.1.5.2.3.6.1";
pub(crate) const KDF_SHA256: &str = "1.3.6.1.5.2.3.6.2";
pub(crate) const KDF_SHA512: &str = "1.3.6.1.5.2.3.6.3";

/// The KDFs offered, MIT's preference first.
pub(crate) const OFFERED: [&str; 3] = [KDF_SHA256, KDF_SHA512, KDF_SHA1];

/// The random-to-key input length of an enctype (RFC 3961 §3): the
/// octets of key material the KDF must produce.
pub(crate) fn key_len(enctype: i32) -> Option<usize> {
    match enctype {
        17 | 19 => Some(16),
        18 | 20 => Some(32),
        _ => None,
    }
}

/// RFC 4556 §3.2.3.1 octetstring2key: SHA-1 over a one-octet counter
/// (from 0) and `Z`, concatenated and truncated.
pub(crate) fn octetstring2key(z: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 20);
    let mut counter = 0u8;
    while out.len() < len {
        let mut h = Sha1::new();
        h.update([counter]);
        h.update(z);
        out.extend_from_slice(&h.finalize());
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// `KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1]
/// PrincipalName }` (RFC 4556 §3.2.2).
pub(crate) fn krb5_principal_name(p: &Principal) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::general_string(&p.realm)),
        der::field(1, p.encode_name()),
    ])
}

/// RFC 8636 §6 OtherInfo for the KDF:
///
/// ```text
/// OtherInfo ::= SEQUENCE {
///     algorithmID AlgorithmIdentifier,          -- the KDF
///     partyUInfo [0] OCTET STRING,              -- KRB5PrincipalName, client
///     partyVInfo [1] OCTET STRING,              -- KRB5PrincipalName, KDC
///     suppPubInfo [2] OCTET STRING }            -- PkinitSuppPubInfo
/// PkinitSuppPubInfo ::= SEQUENCE {
///     enctype [0] Int32, as-REQ [1] OCTET STRING, pk-as-rep [2] OCTET STRING }
/// ```
pub(crate) fn other_info(
    kdf: &str,
    client: &Principal,
    server: &Principal,
    enctype: i32,
    as_req: &[u8],
    pk_as_rep: &[u8],
) -> Vec<u8> {
    let supp = der::seq(&[
        der::field(0, der::int(enctype as i64)),
        der::field(1, der::octets(as_req)),
        der::field(2, der::octets(pk_as_rep)),
    ]);
    der::seq(&[
        asn1::alg_id(kdf, None),
        der::field(0, der::octets(&krb5_principal_name(client))),
        der::field(1, der::octets(&krb5_principal_name(server))),
        der::field(2, der::octets(&supp)),
    ])
}

/// SP 800-56A single-step KDF: `H(counter || Z || OtherInfo)` for a
/// 32-bit big-endian counter from 1, concatenated and truncated. `None`
/// for a KDF not in [`OFFERED`].
pub(crate) fn sp800_56a(kdf: &str, z: &[u8], other_info: &[u8], len: usize) -> Option<Vec<u8>> {
    fn run<H: Digest>(z: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 64);
        let mut counter = 1u32;
        while out.len() < len {
            let mut h = H::new();
            h.update(counter.to_be_bytes());
            h.update(z);
            h.update(info);
            out.extend_from_slice(&h.finalize());
            counter += 1;
        }
        out.truncate(len);
        out
    }
    match kdf {
        KDF_SHA1 => Some(run::<Sha1>(z, other_info, len)),
        KDF_SHA256 => Some(run::<Sha256>(z, other_info, len)),
        KDF_SHA512 => Some(run::<Sha512>(z, other_info, len)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// MIT's `pkinit_kdf_test.c`: a 256-octet zero secret, `lha@SU.SE`
    /// and `krbtgt/SU.SE@SU.SE`, as-REQ ten 0xAA octets, pk-as-rep nine
    /// 0xBB, enctype 18.
    fn mit_vector(kdf: &str, enctype: i32, len: usize) -> Vec<u8> {
        let client = Principal::new(1, ["lha"], "SU.SE");
        let server = Principal::new(1, ["krbtgt", "SU.SE"], "SU.SE");
        let info = other_info(kdf, &client, &server, enctype, &[0xAA; 10], &[0xBB; 9]);
        sp800_56a(kdf, &[0; 256], &info, len).unwrap()
    }

    /// RFC 3961 §6.3.1 DES3 random-to-key, for MIT's third vector: each 7
    /// octets become 8, the eighth gathering their low bits, all with odd
    /// parity.
    fn des3_random_to_key(r: &[u8]) -> Vec<u8> {
        let odd = |b: u8| (b & 0xFE) | u8::from((b >> 1).count_ones() % 2 == 0);
        r.chunks(7)
            .flat_map(|c| {
                let mut k: Vec<u8> = c.to_vec();
                let eighth = c
                    .iter()
                    .enumerate()
                    .fold(0, |e, (i, b)| e | ((b & 1) << (i + 1)));
                k.push(eighth);
                k.into_iter().map(odd).collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn the_kdfs_match_mits_test_vectors() {
        assert_eq!(
            mit_vector(KDF_SHA1, 18, 32),
            hex("e6ab38c9413e035bb079201ed0b6b73d8d49a814a737c04ee6649614206f73ad")
        );
        assert_eq!(
            mit_vector(KDF_SHA256, 18, 32),
            hex("77ef4e48c420ae3fec75109d7981697eed5d295c90c62564f7bfd101fa9bc1d5")
        );
        // SHA-512 with DES3 (enctype 16): 21 octets, then random-to-key.
        assert_eq!(
            des3_random_to_key(&mit_vector(KDF_SHA512, 16, 21)),
            hex("d3c78a79d65213efe9a826f75dfb01f72362fb16fb01dad6")
        );
    }

    #[test]
    fn an_unknown_kdf_gives_nothing() {
        assert!(sp800_56a("1.2.3", &[0; 8], &[], 16).is_none());
    }

    #[test]
    fn octetstring2key_is_counted_sha1() {
        let z = b"shared secret";
        let k = octetstring2key(z, 32);
        let h0 = Sha1::new().chain_update([0u8]).chain_update(z).finalize();
        let h1 = Sha1::new().chain_update([1u8]).chain_update(z).finalize();
        assert_eq!(&k[..20], &h0[..]);
        assert_eq!(&k[20..], &h1[..12]);
        assert_eq!(octetstring2key(z, 16), &h0[..16]);
    }
}
