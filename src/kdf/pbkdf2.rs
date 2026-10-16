//! PBKDF2 (RFC 8018 §5.2) with HMAC-SHA-1, HMAC-SHA-256 and
//! HMAC-SHA-384, for string-to-key, where it runs 4096 or 32768 rounds.
//!
//! Each round is `U_j = HMAC(P, U_{j-1})`: two hashes of one block each.
//! The HMAC key's inner and outer states are computed once, and the
//! round is then two calls of the compression function on a block padded
//! once, as fast PBKDF2 implementations do. Through the `hmac` and
//! `digest` layers a round also clones, buffers and pads, which costs as
//! much as the hashing on x86 with SHA-NI. The first round, over the salt,
//! goes through `hmac` as usual.

use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384};

// FIPS 180-4 §5.3: the initial hash values.
const SHA1_IV: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SHA384_IV: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// One PBKDF2-HMAC function: the digest, its state word, initial value,
/// block and output sizes, and compression function.
macro_rules! pbkdf2 {
    ($name:ident, $digest:ty, $word:ty, $iv:expr, $block:literal, $out:literal, $compress:path) => {
        pub(crate) fn $name(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
            const B: usize = $block;
            const L: usize = $out;
            const W: usize = size_of::<$word>();

            // RFC 2104: the key, hashed if longer than a block, zero-padded;
            // the states after its ipad and opad blocks.
            let mut key = [0u8; B];
            if password.len() > B {
                key[..L].copy_from_slice(&<$digest>::digest(password));
            } else {
                key[..password.len()].copy_from_slice(password);
            }
            let keyed = |pad: u8| {
                let mut state = $iv;
                let mut b = [0u8; B];
                for (x, k) in b.iter_mut().zip(key) {
                    *x = k ^ pad;
                }
                $compress(&mut state, &[b]);
                state
            };
            let (inner, outer) = (keyed(0x36), keyed(0x5c));

            // A block holding one digest, padded (FIPS 180-4 §5.1) as a
            // message of a block and a digest: the inner hash's input (the
            // previous U) and the outer hash's (the inner digest) alike.
            let mut block = [0u8; B];
            block[L] = 0x80;
            block[B - 8..].copy_from_slice(&(((B + L) * 8) as u64).to_be_bytes());
            let put = |state: &[$word], block: &mut [u8; B]| {
                for (c, w) in block[..L].chunks_mut(W).zip(state) {
                    c.copy_from_slice(&w.to_be_bytes());
                }
            };

            for (i, chunk) in out.chunks_mut(L).enumerate() {
                let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice(password)
                    .expect("HMAC takes a key of any length");
                mac.update(salt);
                mac.update(&(i as u32 + 1).to_be_bytes());
                let u1 = mac.finalize().into_bytes();
                let mut t = [0u8; L];
                t.copy_from_slice(&u1);
                block[..L].copy_from_slice(&u1);
                for _ in 1..rounds {
                    let mut s = inner;
                    $compress(&mut s, core::slice::from_ref(&block));
                    put(&s, &mut block);
                    let mut s = outer;
                    $compress(&mut s, core::slice::from_ref(&block));
                    put(&s, &mut block);
                    for (x, u) in t.iter_mut().zip(&block[..L]) {
                        *x ^= u;
                    }
                }
                chunk.copy_from_slice(&t[..chunk.len()]);
            }
        }
    };
}

pbkdf2!(
    pbkdf2_hmac_sha1,
    Sha1,
    u32,
    SHA1_IV,
    64,
    20,
    sha1::block_api::compress
);
pbkdf2!(
    pbkdf2_hmac_sha256,
    Sha256,
    u32,
    SHA256_IV,
    64,
    32,
    sha2::block_api::compress256
);
pbkdf2!(
    pbkdf2_hmac_sha384,
    Sha384,
    u64,
    SHA384_IV,
    128,
    48,
    sha2::block_api::compress512
);

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6070 §2, PBKDF2-HMAC-SHA1.
    #[test]
    fn rfc6070_vectors() {
        let hex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        for (p, s, c, dk) in [
            (
                &b"password"[..],
                &b"salt"[..],
                1,
                "0c60c80f961f0e71f3a9b524af6012062fe037a6",
            ),
            (
                b"password",
                b"salt",
                2,
                "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
            ),
            (
                b"password",
                b"salt",
                4096,
                "4b007901b765489abead49d926f721d065a429c1",
            ),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            ),
            (
                b"pass\0word",
                b"sa\0lt",
                4096,
                "56fa6aa75548099dcc37d7f03425e0c3",
            ),
        ] {
            let want = hex(dk);
            let mut got = vec![0u8; want.len()];
            pbkdf2_hmac_sha1(p, s, c, &mut got);
            assert_eq!(got, want);
        }
    }

    /// `cargo test --release --lib -- --ignored pbkdf2_cost --nocapture`:
    /// these against the `pbkdf2` crate at string-to-key's round counts,
    /// the best of 20.
    #[test]
    #[ignore]
    fn pbkdf2_cost() {
        type F = fn(&[u8], &[u8], u32, &mut [u8]);
        let best = |f: F, rounds: u32, len: usize| {
            let mut out = vec![0u8; len];
            (0..20)
                .map(|_| {
                    let t = std::time::Instant::now();
                    f(b"password", b"EXAMPLE.COMuser", rounds, &mut out);
                    std::hint::black_box(&out);
                    t.elapsed()
                })
                .min()
                .unwrap()
        };
        let cases: [(&str, F, F, u32, usize); 4] = [
            (
                "SHA-1, 4096, 16 octets",
                pbkdf2_hmac_sha1,
                ::pbkdf2::pbkdf2_hmac::<Sha1>,
                4096,
                16,
            ),
            (
                "SHA-1, 4096, 32 octets",
                pbkdf2_hmac_sha1,
                ::pbkdf2::pbkdf2_hmac::<Sha1>,
                4096,
                32,
            ),
            (
                "SHA-256, 32768",
                pbkdf2_hmac_sha256,
                ::pbkdf2::pbkdf2_hmac::<Sha256>,
                32768,
                16,
            ),
            (
                "SHA-384, 32768",
                pbkdf2_hmac_sha384,
                ::pbkdf2::pbkdf2_hmac::<Sha384>,
                32768,
                32,
            ),
        ];
        for (what, ours, theirs, rounds, len) in cases {
            let (a, b) = (best(ours, rounds, len), best(theirs, rounds, len));
            eprintln!("{what}: ours {a:?}  pbkdf2 crate {b:?}");
        }
    }

    /// Against the `pbkdf2` crate: keys shorter than, as long as and
    /// longer than a block, one round and several, outputs of part of a
    /// digest to several.
    #[test]
    fn agrees_with_the_pbkdf2_crate() {
        let password: Vec<u8> = (0..300u32).map(|i| (i * 31 + 7) as u8).collect();
        let salt = b"EXAMPLE.COMuser\0\x01\x02";
        for plen in [0, 1, 20, 63, 64, 65, 127, 128, 129, 300] {
            for rounds in [1, 2, 3, 17] {
                for olen in [1, 16, 20, 32, 48, 49, 100] {
                    let p = &password[..plen];
                    let check =
                        |ours: fn(&[u8], &[u8], u32, &mut [u8]),
                         theirs: fn(&[u8], &[u8], u32, &mut [u8])| {
                            let (mut a, mut b) = (vec![0u8; olen], vec![0u8; olen]);
                            ours(p, salt, rounds, &mut a);
                            theirs(p, salt, rounds, &mut b);
                            assert_eq!(a, b, "plen {plen} rounds {rounds} olen {olen}");
                        };
                    check(pbkdf2_hmac_sha1, ::pbkdf2::pbkdf2_hmac::<Sha1>);
                    check(pbkdf2_hmac_sha256, ::pbkdf2::pbkdf2_hmac::<Sha256>);
                    check(pbkdf2_hmac_sha384, ::pbkdf2::pbkdf2_hmac::<Sha384>);
                }
            }
        }
    }
}
