//! The Kerberos encryption profile: RFC 3961 §5.3 for enctypes 17/18, and
//! the RFC 8009 §5 construction that *replaces* it for enctypes 19/20.
//!
//! Two constructions live here, and they are not variants of one another:
//!
//! * RFC 3961 §5.3 (enctypes 17, 18) — MAC-over-plaintext.
//!   `ciphertext = E(Ke, conf | plaintext | pad) | HMAC(Ki, conf | plaintext | pad)[1..h]`
//! * RFC 8009 §5 (enctypes 19, 20) — encrypt-then-MAC over `IV | C`.
//!   `C = E(Ke, N | plaintext, IV)`, `H = HMAC(Ki, IV | C)`, `ciphertext = C | H[1..h]`
//!
//! RFC 8009 §1 says outright that it does not use the simplified profile,
//! precisely so the receiver can verify integrity *before* decrypting. So a
//! single code path parameterised by "hash function and key size" cannot
//! serve both families — the bytes that go under the MAC differ. They are
//! written out separately below, on purpose.
//!
//! # Why this module exists
//!
//! [`crate::acceptor`] encrypts as `AES-CTS(Ke, plaintext | HMAC(Ki,
//! plaintext))`: no confounder, and the MAC *inside* the ciphertext. It also
//! derives Ke with the constant RFC 3961 §5.3 assigns to Kc. Every one of the
//! 55 tests in that file encrypts and decrypts with the same pair of
//! functions, so all of it round-trips and none of it interoperates. A
//! self-consistency test is not evidence of a wire format.
//!
//! Consequently every primitive here carries a KNOWN-ANSWER test with hex
//! copied out of the RFC, and the tests are named for the section they pin.
//! Round-trip tests exist too, but only *in addition*.
//!
//! # What is and is not pinned
//!
//! * AES-CBC-CTS (= SP800-38A CBC-CS3): six ciphertexts **and** six
//!   carried-out IVs, RFC 3962 Appendix B. The non-zero cipher-state path has
//!   no published vector at all and is covered only by the
//!   cross-implementation differential below.
//! * RFC 8009 §5 encrypt/decrypt and §6 checksum: ten known answers, RFC 8009
//!   Appendix A, with the confounder fixed by the RFC.
//! * RFC 3961 §5.3 for enctypes 17/18: **no IETF-published known answer
//!   exists.** RFC 3961 Appendix A is DES/DES3 only; RFC 3962 Appendix B stops
//!   at string-to-key and raw CTS, and a KAT would additionally have to fix
//!   the confounder, which RFC 3962 never does. Three things stand in for it,
//!   and none of them is a KAT:
//!   1. the composition — which octets go under the MAC, and where the tag
//!      lands — asserted byte-for-byte on top of CTS (pinned by RFC 3962
//!      Appendix B) and HMAC-SHA-1 (pinned by RFC 2202, truncation included);
//!   2. a **cross-implementation differential**: ten end-to-end answers for
//!      enctypes 17 and 18 produced by a second, independent implementation
//!      (OpenSSL AES-ECB + Python stdlib HMAC, written from the RFC text and
//!      first verified to reproduce all six RFC 3962 Appendix B and all eight
//!      RFC 8009 Appendix A vectors). Inputs are all RFC-published hex; only
//!      the outputs are generated. See the banner above `k3961_case`;
//!   3. round trips, which prove nothing about the wire format on their own.
//!
//!   Two implementations can share a misreading. Closing the gap for real
//!   needs a capture against a live KDC (`mount -o sec=krb5p` against MIT
//!   krb5, or MIT's `crypto_tests` data), not another test in this file.
//!
//! # Cipher state
//!
//! Every function here starts from the initial (all-zero) cipher state. RFC
//! 4120 EncryptedData and RFC 4121 per-message tokens each encrypt from the
//! initial state, so nothing in this crate chains one. RFC 8009 Appendix A notes
//! that *all* its samples use the default cipher state, so the chaining rule
//! has no published vector at all — we expose [`cts_next_iv`] (which RFC 3962
//! Appendix B *does* pin, as "Next IV") but deliberately do not build a
//! stateful encrypt API on top of unverifiable ground.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Sha256, Sha384};

/// The AES block size, in octets. This is `c` in RFC 3961's notation: it is
/// simultaneously the cipher block size, the IV size, and the confounder
/// size, for all four enctypes — including aes256, where the confounder is
/// still 16 octets and not 32.
pub const BLOCK_SIZE: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("unsupported enctype {0} (only AES is supported: 17, 18, 19, 20)")]
    UnsupportedEnctype(i32),

    /// Raised when a derived key is the wrong length for its role. This is not
    /// pedantry: for enctype 20, Ke is 32 octets but Ki and Kc are 24. SHA-384
    /// emits 48, so a caller that sizes all three from one `key_size()` and
    /// truncates to 32 gets a wrong Ki with no error and no panic — the bug is
    /// invisible until a real KDC rejects the tag.
    #[error("{role} must be {want} octets for enctype {enctype}, got {got}")]
    KeyLength {
        role: &'static str,
        enctype: i32,
        want: usize,
        got: usize,
    },

    #[error("confounder must be {want} octets, got {got}")]
    ConfounderLength { want: usize, got: usize },

    /// The CTS input was shorter than one block. Unreachable through the
    /// profile — the 16-octet confounder guarantees at least one block — and
    /// RFC 3962 §5 leaves the sub-block padding value unspecified and forbids
    /// protocols from relying on it, so we refuse rather than guess.
    #[error("AES-CTS input must be at least {BLOCK_SIZE} octets, got {0}")]
    CtsInputTooShort(usize),

    #[error("AES key must be 16 or 32 octets, got {0}")]
    AesKeyLength(usize),

    #[error("ciphertext of {got} octets is shorter than the minimum {want} for enctype {enctype}")]
    CiphertextTooShort {
        enctype: i32,
        want: usize,
        got: usize,
    },

    /// Integrity check failed. No plaintext is returned with it — not even
    /// partially — which is the whole point of checking before returning.
    #[error("integrity check failed (HMAC mismatch)")]
    IntegrityFailure,
}

pub type Result<T> = std::result::Result<T, ProfileError>;

/// The four AES enctypes this crate supports (RFC 3962 §7, RFC 8009 §7).
///
/// Note the spelling of 20: the trailing number is the HMAC truncation, 192
/// bits. [`crate::acceptor::EncType`] spells it `...Sha384196`, which
/// is not a number that appears anywhere in RFC 8009.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Enctype {
    /// 17 — aes128-cts-hmac-sha1-96 (RFC 3962). RFC 3961 §5.3 profile.
    Aes128CtsHmacSha196 = 17,
    /// 18 — aes256-cts-hmac-sha1-96 (RFC 3962). RFC 3961 §5.3 profile.
    Aes256CtsHmacSha196 = 18,
    /// 19 — aes128-cts-hmac-sha256-128 (RFC 8009 §5).
    Aes128CtsHmacSha256128 = 19,
    /// 20 — aes256-cts-hmac-sha384-192 (RFC 8009 §5).
    Aes256CtsHmacSha384192 = 20,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
}

impl Enctype {
    pub fn from_i32(v: i32) -> Result<Self> {
        match v {
            17 => Ok(Enctype::Aes128CtsHmacSha196),
            18 => Ok(Enctype::Aes256CtsHmacSha196),
            19 => Ok(Enctype::Aes128CtsHmacSha256128),
            20 => Ok(Enctype::Aes256CtsHmacSha384192),
            other => Err(ProfileError::UnsupportedEnctype(other)),
        }
    }

    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// True for enctypes 19/20, which use RFC 8009 §5 rather than the RFC 3961
    /// §5.3 simplified profile. Callers deriving keys must branch on this too:
    /// 17/18 use n-fold/DR/DK, 19/20 use KDF-HMAC-SHA2, and neither is a
    /// parameterisation of the other.
    pub fn is_rfc8009(self) -> bool {
        matches!(
            self,
            Enctype::Aes128CtsHmacSha256128 | Enctype::Aes256CtsHmacSha384192
        )
    }

    /// Length of the encryption key Ke, in octets (RFC 3962 §7, RFC 8009 §5).
    pub fn ke_len(self) -> usize {
        match self {
            Enctype::Aes128CtsHmacSha196 | Enctype::Aes128CtsHmacSha256128 => 16,
            Enctype::Aes256CtsHmacSha196 | Enctype::Aes256CtsHmacSha384192 => 32,
        }
    }

    /// Length of the integrity key Ki, in octets. For enctype 20 this is 24,
    /// **not** 32 — the one place in the AES family where Ke and Ki differ in
    /// length (RFC 8009 §5).
    pub fn ki_len(self) -> usize {
        match self {
            Enctype::Aes128CtsHmacSha196 => 16,
            Enctype::Aes256CtsHmacSha196 => 32,
            Enctype::Aes128CtsHmacSha256128 => 16,
            Enctype::Aes256CtsHmacSha384192 => 24,
        }
    }

    /// Length of the checksum key Kc, in octets. Same asymmetry as [`Self::ki_len`].
    pub fn kc_len(self) -> usize {
        self.ki_len()
    }

    /// `h`, the truncated HMAC length in octets: 12 for both SHA-1 enctypes
    /// (the bigger key buys no bigger MAC), 16 for enctype 19, 24 for 20.
    pub fn checksum_len(self) -> usize {
        match self {
            Enctype::Aes128CtsHmacSha196 | Enctype::Aes256CtsHmacSha196 => 12,
            Enctype::Aes128CtsHmacSha256128 => 16,
            Enctype::Aes256CtsHmacSha384192 => 24,
        }
    }

    /// `c`, the confounder length in octets. 16 for every AES enctype.
    pub fn confounder_len(self) -> usize {
        BLOCK_SIZE
    }

    /// Total expansion of a plaintext: confounder + truncated MAC. There is no
    /// pad term — RFC 3962 §6 sets the message block size `m` to **1 octet**,
    /// so `pad` in the §5.3 formula is always the empty string and CTS carries
    /// the ragged tail. Padding to 16 breaks both the length and every peer.
    pub fn overhead(self) -> usize {
        self.confounder_len() + self.checksum_len()
    }

    fn hash(self) -> Hash {
        match self {
            Enctype::Aes128CtsHmacSha196 | Enctype::Aes256CtsHmacSha196 => Hash::Sha1,
            Enctype::Aes128CtsHmacSha256128 => Hash::Sha256,
            Enctype::Aes256CtsHmacSha384192 => Hash::Sha384,
        }
    }

    fn check_ke(self, ke: &[u8]) -> Result<()> {
        if ke.len() != self.ke_len() {
            return Err(ProfileError::KeyLength {
                role: "Ke",
                enctype: self.as_i32(),
                want: self.ke_len(),
                got: ke.len(),
            });
        }
        Ok(())
    }

    fn check_ki(self, ki: &[u8]) -> Result<()> {
        if ki.len() != self.ki_len() {
            return Err(ProfileError::KeyLength {
                role: "Ki",
                enctype: self.as_i32(),
                want: self.ki_len(),
                got: ki.len(),
            });
        }
        Ok(())
    }

    fn check_kc(self, kc: &[u8]) -> Result<()> {
        if kc.len() != self.kc_len() {
            return Err(ProfileError::KeyLength {
                role: "Kc",
                enctype: self.as_i32(),
                want: self.kc_len(),
                got: kc.len(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AES block cipher
// ---------------------------------------------------------------------------

/// AES-192 is deliberately absent: it is not a Kerberos enctype, and accepting
/// a 24-octet key here would silently admit the wrong-length Ki of enctype 20.
enum Aes {
    A128(aes::Aes128),
    A256(aes::Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 => Ok(Aes::A128(aes::Aes128::new(GenericArray::from_slice(key)))),
            32 => Ok(Aes::A256(aes::Aes256::new(GenericArray::from_slice(key)))),
            n => Err(ProfileError::AesKeyLength(n)),
        }
    }

    fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let ga = GenericArray::from_mut_slice(&mut block[..]);
        match self {
            Aes::A128(c) => c.encrypt_block(ga),
            Aes::A256(c) => c.encrypt_block(ga),
        }
    }

    fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let ga = GenericArray::from_mut_slice(&mut block[..]);
        match self {
            Aes::A128(c) => c.decrypt_block(ga),
            Aes::A256(c) => c.decrypt_block(ga),
        }
    }
}

#[inline]
fn xor_into(dst: &mut [u8; BLOCK_SIZE], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

// ---------------------------------------------------------------------------
// AES-CBC with ciphertext stealing (RFC 3962 §5; = CBC-CS3, RFC 8009 §1)
// ---------------------------------------------------------------------------

/// AES in CBC mode with ciphertext stealing (RFC 3962 §5, incorporating the
/// RFC 2040 errata of RFC 3962 Appendix A). RFC 8009 §1 names the identical
/// construction CBC-CS3, so this one routine serves all four enctypes — and
/// the RFC 8009 Appendix A vectors below are what prove they really are the
/// same construction rather than two similar ones.
///
/// Output length equals input length exactly; there is no padding.
///
/// The trap: **the last two ciphertext blocks are swapped even when the input
/// is an exact multiple of the block size.** That is what separates CS3 from
/// plain CBC and from CS1/CS2, and an implementation that only steals when
/// there is a ragged tail passes the 17- and 31-octet vectors and fails the
/// 32-, 48- and 64-octet ones. Those are the common shapes in real Kerberos
/// traffic, so the bug does not stay hidden for long — it just does not
/// surface against your own decryptor.
///
/// `iv` is the cipher state. Kerberos always supplies the initial (all-zero)
/// state; see the module docs.
pub fn aes_cts_encrypt(key: &[u8], iv: &[u8; BLOCK_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
    let n = plaintext.len();
    if n < BLOCK_SIZE {
        return Err(ProfileError::CtsInputTooShort(n));
    }
    let cipher = Aes::new(key)?;

    // Exactly one block: plain CBC. There is no second block to steal from, so
    // an unconditional "exchange the last two blocks" would index off the
    // front. This is the empty-plaintext case of RFC 8009 (the CTS input is
    // then just the confounder) and it has a published vector.
    if n == BLOCK_SIZE {
        let mut b = [0u8; BLOCK_SIZE];
        b.copy_from_slice(plaintext);
        xor_into(&mut b, iv);
        cipher.encrypt_block(&mut b);
        return Ok(b.to_vec());
    }

    let d = match n % BLOCK_SIZE {
        0 => BLOCK_SIZE,
        r => r,
    };
    let nb = n.div_ceil(BLOCK_SIZE);

    // Ordinary CBC over the input zero-extended to a whole number of blocks.
    // The zero extension is internal to this pass: it is never transmitted and
    // never MACed, and must not be confused with message padding.
    let mut out = Vec::with_capacity(nb * BLOCK_SIZE);
    let mut prev = *iv;
    for i in 0..nb {
        let mut b = [0u8; BLOCK_SIZE];
        let start = i * BLOCK_SIZE;
        let end = std::cmp::min(start + BLOCK_SIZE, n);
        b[..end - start].copy_from_slice(&plaintext[start..end]);
        xor_into(&mut b, &prev);
        cipher.encrypt_block(&mut b);
        out.extend_from_slice(&b);
        prev = b;
    }

    // Exchange the final two blocks and truncate the (now) last one to d.
    // Result = C_1 .. C_{nb-2} | C_nb | C_{nb-1}[0..d], length exactly n.
    let mut swapped = Vec::with_capacity(n);
    swapped.extend_from_slice(&out[..(nb - 2) * BLOCK_SIZE]);
    swapped.extend_from_slice(&out[(nb - 1) * BLOCK_SIZE..nb * BLOCK_SIZE]);
    swapped.extend_from_slice(&out[(nb - 2) * BLOCK_SIZE..(nb - 2) * BLOCK_SIZE + d]);
    debug_assert_eq!(swapped.len(), n);
    Ok(swapped)
}

/// Inverse of [`aes_cts_encrypt`].
///
/// The final two blocks cannot be walked left-to-right like the rest: the
/// octets stolen from `C_{n-1}` have to be recovered out of the decryption of
/// `C_n` before `C_{n-1}` can be decrypted at all.
pub fn aes_cts_decrypt(key: &[u8], iv: &[u8; BLOCK_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let n = ciphertext.len();
    if n < BLOCK_SIZE {
        return Err(ProfileError::CtsInputTooShort(n));
    }
    let cipher = Aes::new(key)?;

    if n == BLOCK_SIZE {
        let mut b = [0u8; BLOCK_SIZE];
        b.copy_from_slice(ciphertext);
        cipher.decrypt_block(&mut b);
        xor_into(&mut b, iv);
        return Ok(b.to_vec());
    }

    let d = match n % BLOCK_SIZE {
        0 => BLOCK_SIZE,
        r => r,
    };
    let nb = n.div_ceil(BLOCK_SIZE);

    let mut out = Vec::with_capacity(n);
    let mut prev = *iv;
    for i in 0..nb - 2 {
        let mut b = [0u8; BLOCK_SIZE];
        b.copy_from_slice(&ciphertext[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
        let c_i = b;
        cipher.decrypt_block(&mut b);
        xor_into(&mut b, &prev);
        out.extend_from_slice(&b);
        prev = c_i;
    }
    // `prev` is now C_{nb-2}, or the IV when nb == 2 — the RFC 2040 errata
    // clause that RFC 3962 Appendix A makes normative.

    // Positionally: the swapped-in full block sits at nb-2, the truncated one
    // at nb-1.
    let mut z = [0u8; BLOCK_SIZE];
    z.copy_from_slice(&ciphertext[(nb - 2) * BLOCK_SIZE..(nb - 1) * BLOCK_SIZE]);
    cipher.decrypt_block(&mut z); // z = (P_nb || 0*) XOR C_{nb-1}
    let tail = &ciphertext[(nb - 1) * BLOCK_SIZE..];

    // Recover the full C_{nb-1}: its first d octets travelled in the clear as
    // `tail`, and the b-d octets that were stolen reappear in z, because the
    // plaintext there was the zero extension.
    let mut c_nm1 = [0u8; BLOCK_SIZE];
    c_nm1[..d].copy_from_slice(tail);
    c_nm1[d..].copy_from_slice(&z[d..]);

    let mut p_last = Vec::with_capacity(d);
    for i in 0..d {
        p_last.push(z[i] ^ tail[i]);
    }

    let mut p_nm1 = c_nm1;
    cipher.decrypt_block(&mut p_nm1);
    xor_into(&mut p_nm1, &prev);

    out.extend_from_slice(&p_nm1);
    out.extend_from_slice(&p_last);
    debug_assert_eq!(out.len(), n);
    Ok(out)
}

/// The cipher state carried out of a CTS operation: the next-to-last 16-octet
/// block of the *output* (the output itself when there is only one block).
///
/// RFC 3962 Appendix B publishes this as "Next IV" for all six of its vectors,
/// and RFC 8009 §5 restates the same rule. Note it is taken *positionally*
/// from the emitted ciphertext — after the CS3 exchange, so it is the
/// encryption of the final zero-extended plaintext block, not the
/// chronologically penultimate CBC output.
///
/// Nothing in this crate chains a cipher state (see the module docs); this exists
/// so that if something ever does, the rule is already pinned.
pub fn cts_next_iv(ciphertext: &[u8]) -> Result<[u8; BLOCK_SIZE]> {
    let n = ciphertext.len();
    if n < BLOCK_SIZE {
        return Err(ProfileError::CtsInputTooShort(n));
    }
    let nb = n.div_ceil(BLOCK_SIZE);
    let start = if nb == 1 { 0 } else { (nb - 2) * BLOCK_SIZE };
    let mut iv = [0u8; BLOCK_SIZE];
    iv.copy_from_slice(&ciphertext[start..start + BLOCK_SIZE]);
    Ok(iv)
}

// ---------------------------------------------------------------------------
// HMAC and constant-time comparison
// ---------------------------------------------------------------------------

fn hmac(hash: Hash, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    // Spelled out per hash rather than made generic: the three HMAC types have
    // different associated output sizes and the concrete form keeps the
    // dependency surface to `hmac` + `sha1`/`sha2`, which is what Cargo.toml
    // already carries.
    macro_rules! run {
        ($d:ty) => {{
            let mut m = <Hmac<$d> as Mac>::new_from_slice(key)
                .expect("HMAC accepts a key of any length by construction");
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }};
    }
    match hash {
        Hash::Sha1 => run!(Sha1),
        Hash::Sha256 => run!(Sha256),
        Hash::Sha384 => run!(Sha384),
    }
}

/// Constant-time equality. A byte-at-a-time `==` on a MAC is a forgery oracle:
/// the early return leaks how many leading octets a guess got right, which
/// turns a 2^96 search into 12 searches of 2^8.
///
/// The length comparison is not secret — tag lengths are fixed by the enctype
/// and public on the wire.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // black_box so the accumulate-then-test cannot be rewritten into an
    // early-exit loop by a future optimiser.
    std::hint::black_box(diff) == 0
}

// ---------------------------------------------------------------------------
// The encryption profile
// ---------------------------------------------------------------------------

const ZERO_IV: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];

/// Encrypt with a freshly drawn random confounder (RFC 3961 §5.3 for enctypes
/// 17/18, RFC 8009 §5 for 19/20).
///
/// `ke` and `ki` are the *specific* keys for the key usage in question, not
/// the base key: `Ke = DK(base, usage|0xAA)`, `Ki = DK(base, usage|0x55)`.
/// Deriving them is [`super::kdf`]'s job. Their lengths are checked against
/// the enctype, because for enctype 20 a 32-octet Ki is exactly the shape of
/// a silent bug (SHA-384 emits 48 octets, so truncating to 32 succeeds).
///
/// The confounder is drawn from the OS CSPRNG, fresh per message. It is the
/// only source of IV unpredictability in the construction (RFC 8009 §8), and
/// a repeated one leaks plaintext equality.
pub fn encrypt(enctype: Enctype, ke: &[u8], ki: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut conf = vec![0u8; enctype.confounder_len()];
    rand::rngs::OsRng.fill_bytes(&mut conf);
    encrypt_with_confounder(enctype, ke, ki, &conf, plaintext)
}

/// The deterministic core of [`encrypt`], with the confounder supplied.
///
/// This seam exists so the construction can be pinned to a published vector at
/// all: RFC 8009 Appendix A fixes the confounder for each of its eight sample
/// encryptions, and without an injection point those vectors are untestable
/// and one is back to round-tripping against oneself — which is how the bug in
/// [`crate::acceptor`] survived 55 tests.
///
/// Production callers want [`encrypt`]. Passing a fixed or predictable
/// confounder outside a test destroys the non-malleability the profile
/// requires.
pub fn encrypt_with_confounder(
    enctype: Enctype,
    ke: &[u8],
    ki: &[u8],
    confounder: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    enctype.check_ke(ke)?;
    enctype.check_ki(ki)?;
    if confounder.len() != enctype.confounder_len() {
        return Err(ProfileError::ConfounderLength {
            want: enctype.confounder_len(),
            got: confounder.len(),
        });
    }
    let h = enctype.checksum_len();

    // conf | plaintext. No pad: RFC 3962 §6 sets m = 1 octet, and RFC 8009 has
    // no pad term at all.
    let mut inner = Vec::with_capacity(confounder.len() + plaintext.len());
    inner.extend_from_slice(confounder);
    inner.extend_from_slice(plaintext);

    let c = aes_cts_encrypt(ke, &ZERO_IV, &inner)?;

    let tag = if enctype.is_rfc8009() {
        // RFC 8009 §5: H = HMAC(Ki, IV | C). Encrypt-then-MAC, and the cipher
        // state is *part of the MAC input*. With the initial state that is 16
        // zero octets in front of C. Dropping them verifies perfectly against
        // yourself and against nobody else.
        hmac(enctype.hash(), ki, &[&ZERO_IV[..], &c])
    } else {
        // RFC 3961 §5.3: H1 = HMAC(Ki, conf | plaintext | pad). Over the
        // PLAINTEXT, and no IV. The opposite of the line above; this is why
        // the two families cannot share an integrity path.
        hmac(enctype.hash(), ki, &[&inner])
    };

    // The tag is appended AFTER the ciphertext, in the clear, and is not
    // itself encrypted. [1..h] is 1-based and means the LEADING h octets.
    let mut out = Vec::with_capacity(c.len() + h);
    out.extend_from_slice(&c);
    out.extend_from_slice(&tag[..h]);
    Ok(out)
}

/// Decrypt and verify (RFC 3961 §5.3 / RFC 8009 §5).
///
/// Returns the plaintext with the confounder stripped, or
/// [`ProfileError::IntegrityFailure`]. Nothing is returned on a MAC mismatch —
/// not a truncated result, not a partially decrypted buffer.
///
/// The two families verify at different points and that ordering is normative,
/// not stylistic: RFC 8009 checks the MAC over `IV | C` *before* decrypting
/// (§1 says removing the decryption oracle is why it exists), whereas RFC 3961
/// §5.3's MAC covers the plaintext, so it can only be checked afterwards.
pub fn decrypt(enctype: Enctype, ke: &[u8], ki: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    enctype.check_ke(ke)?;
    enctype.check_ki(ki)?;
    let h = enctype.checksum_len();
    let c_len = enctype.confounder_len();

    // Bounds first. A hostile 4-octet "ciphertext" must be refused, not sliced.
    let minimum = c_len + h;
    if ciphertext.len() < minimum {
        return Err(ProfileError::CiphertextTooShort {
            enctype: enctype.as_i32(),
            want: minimum,
            got: ciphertext.len(),
        });
    }

    // The tag is the LAST h octets; everything before it is the AES output.
    let split = ciphertext.len() - h;
    let (c, tag) = ciphertext.split_at(split);

    if enctype.is_rfc8009() {
        let expect = hmac(enctype.hash(), ki, &[&ZERO_IV[..], c]);
        if !ct_eq(&expect[..h], tag) {
            return Err(ProfileError::IntegrityFailure);
        }
        let p1 = aes_cts_decrypt(ke, &ZERO_IV, c)?;
        Ok(p1[c_len..].to_vec())
    } else {
        let p1 = aes_cts_decrypt(ke, &ZERO_IV, c)?;
        // The MAC covers the whole decryption output — confounder included.
        // Verifying over the stripped plaintext is a different MAC.
        let expect = hmac(enctype.hash(), ki, &[&p1]);
        if !ct_eq(&expect[..h], tag) {
            return Err(ProfileError::IntegrityFailure);
        }
        Ok(p1[c_len..].to_vec())
    }
}

// ---------------------------------------------------------------------------
// The checksum profile (RFC 3961 §5.4, RFC 8009 §6)
// ---------------------------------------------------------------------------

/// `get_mic`: `HMAC(Kc, message)[1..h]` (RFC 3961 §5.4, RFC 8009 §6).
///
/// `kc` is the *checksum* key, `DK(base, usage|0x99)` — the constant
/// [`crate::acceptor`] misassigned to Ke. No confounder, no padding, no
/// IV prefix: the message alone goes under the MAC, and the usage is bound in
/// only through Kc's derivation.
///
/// A checksum usually carries a *different* key usage from the message it
/// accompanies (an AP-REQ authenticator is usage 11, its checksum usage 10),
/// so the caller must not reuse one usage for both.
pub fn checksum(enctype: Enctype, kc: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    enctype.check_kc(kc)?;
    let h = enctype.checksum_len();
    let mac = hmac(enctype.hash(), kc, &[message]);
    Ok(mac[..h].to_vec())
}

/// `verify_mic`: recompute [`checksum`] and compare in constant time.
pub fn verify_checksum(enctype: Enctype, kc: &[u8], message: &[u8], tag: &[u8]) -> Result<bool> {
    let expect = checksum(enctype, kc, message)?;
    Ok(ct_eq(&expect, tag))
}

// ===========================================================================
// Tests. Every hex string below was copied out of the RFC text fetched from
// rfc-editor.org; the CTS and RFC 8009 blocks were extracted from the RFC hex
// dumps mechanically rather than retyped. Test names carry the section they
// pin.
//
// ANTI-VACUITY AUDIT. A green suite is not evidence that the suite can see
// anything, so seven deliberate defects were injected and the suite re-run.
// Each was caught; the counts are the number of tests that went red.
//
//   A  CS1/CS2-style CTS: swap only when there is a ragged tail      8
//   B  RFC 8009 MAC over C instead of IV | C (both sides)           .|
//   C  RFC 3961 MAC over the ciphertext instead of the plaintext    13 (B+C+D)
//   D  trailing h octets of the HMAC instead of the leading ones    .|
//   E  integrity check removed from decrypt                         .|
//   F  confounder left all-zero instead of drawn from the CSPRNG    11 (E+F+G)
//   G  CTS decrypt zero-extends the tail instead of recovering      .|
//      the stolen octets of C_{n-1}
//
// Two results worth keeping: A is invisible to the 17- and 31-octet vectors
// and only the exact-multiple ones (32/48/64) catch it, while G is the
// mirror image — invisible to the exact-multiple vectors, caught only by the
// ragged-tail ones. Both classes are needed; neither alone is a CTS test.
//
// SECOND AUDIT, when the cross-implementation differential below was added.
// Two further defects were injected and the suite re-run:
//
//   H  single-block CTS ignores the IV (the literal RFC 3962 §5 "also        1
//      known as ECB mode" reading, which is only equivalent at a zero IV)
//   I  RFC 3961 §5.3 MACs the ciphertext instead of the plaintext,          12
//      on BOTH sides — the kerberos.rs bug shape, which round-trips
//
// H went red in exactly ONE test: `xcheck_rfc3962_5_cts_with_a_non_zero_
// cipher_state`. Every RFC 3962 Appendix B and RFC 8009 Appendix A vector
// stayed green, because all fourteen of them use the all-zero cipher state.
// That single leg is the only thing in this file standing between the two
// readings of RFC 3962 §5, and it decides for CBC-with-IV, which is what
// RFC 8009 §5's `C = E(Ke, N | plaintext, IV)` requires.
//
// I went red in all ten `xcheck_rfc3961_5_3_*` legs plus the two composition
// tests — and `round_trip_every_enctype_and_length` stayed GREEN, which is
// the whole thesis of this module in one line.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
            .collect()
    }

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    // -- RFC 3962 Appendix B: AES-128 CBC with ciphertext stealing ----------
    // key = "chicken teriyaki", IV all-zero. Each vector pins the ciphertext,
    // the carried-out IV, and a decrypt back to the exact input.

    const CTS_KEY: &str = "636869636b656e207465726979616b69";

    fn cts_case(plain: &str, cipher: &str, next_iv: &str) {
        let key = h(CTS_KEY);
        let p = h(plain);
        let c = aes_cts_encrypt(&key, &ZERO_IV, &p).expect("cts encrypt");
        assert_eq!(hx(&c), cipher, "ciphertext");
        assert_eq!(c.len(), p.len(), "CTS must not expand");
        assert_eq!(hx(&cts_next_iv(&c).unwrap()), next_iv, "next IV");
        let back = aes_cts_decrypt(&key, &ZERO_IV, &c).expect("cts decrypt");
        assert_eq!(hx(&back), plain, "decrypt");
    }

    #[test]
    fn rfc3962_b_cts_17_octets() {
        cts_case(
            "4920776f756c64206c696b652074686520",
            "c6353568f2bf8cb4d8a580362da7ff7f97",
            "c6353568f2bf8cb4d8a580362da7ff7f",
        );
    }

    #[test]
    fn rfc3962_b_cts_31_octets() {
        cts_case(
            "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
            "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
            "fc00783e0efdb2c1d445d4c8eff7ed22",
        );
    }

    #[test]
    fn rfc3962_b_cts_32_octets_exact_multiple() {
        // The vector that catches "swap only when there is a ragged tail".
        cts_case(
            "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
            "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
            "39312523a78662d5be7fcbcc98ebf5a8",
        );
    }

    #[test]
    fn rfc3962_b_cts_47_octets() {
        cts_case(
            "4920776f756c64206c696b65207468652047656e6572616c204761752773204368\
             69636b656e2c20706c656173652c",
            "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39\
             312523a78662d5be7fcbcc98ebf5",
            "b3fffd940c16a18c1b5549d2f838029e",
        );
    }

    #[test]
    fn rfc3962_b_cts_48_octets_exact_multiple() {
        cts_case(
            "4920776f756c64206c696b65207468652047656e6572616c204761752773204368\
             69636b656e2c20706c656173652c20",
            "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839\
             312523a78662d5be7fcbcc98ebf5a8",
            "9dad8bbb96c4cdc03bc103e1a194bbd8",
        );
    }

    #[test]
    fn rfc3962_b_cts_64_octets_exact_multiple() {
        cts_case(
            "4920776f756c64206c696b65207468652047656e6572616c204761752773204368\
             69636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
            "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a848\
             07efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
            "4807efe836ee89a526730dbc2f7bc840",
        );
    }

    /// Falsifiability leg for the CS3 exchange at an exact block multiple.
    ///
    /// An implementation that skips the swap when `len % 16 == 0` emits exactly
    /// the RFC's two blocks in the other order. Deriving that wrong answer from
    /// the RFC's right one and asserting we do not produce it proves the
    /// 32-octet KAT above is actually discriminating, rather than passing for
    /// some unrelated reason.
    #[test]
    fn rfc3962_b_cts_exact_multiple_swap_is_load_bearing() {
        let key = h(CTS_KEY);
        let p = h("4920776f756c64206c696b65207468652047656e6572616c2047617527732043");
        let c = aes_cts_encrypt(&key, &ZERO_IV, &p).unwrap();
        let unswapped: Vec<u8> = c[16..32].iter().chain(c[..16].iter()).copied().collect();
        assert_ne!(
            hx(&c),
            hx(&unswapped),
            "plain CBC (no CS3 exchange) must not match the RFC answer"
        );
        assert_eq!(
            hx(&unswapped),
            "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8",
            "the no-swap answer is the same two blocks reversed"
        );
    }

    /// The CTS input is never allowed to be shorter than a block. RFC 3962 §5
    /// leaves the padding value for such input unspecified and forbids
    /// protocols from depending on it, so we refuse instead of guessing. The
    /// profile can never reach this: the confounder is a whole block.
    #[test]
    fn rfc3962_5_cts_refuses_sub_block_input() {
        let key = h(CTS_KEY);
        assert!(aes_cts_encrypt(&key, &ZERO_IV, &[0u8; 15]).is_err());
        assert!(aes_cts_decrypt(&key, &ZERO_IV, &[0u8; 15]).is_err());
    }

    // -- RFC 2202: HMAC-SHA-1, pinning the primitive the 17/18 profile uses --
    // There is no published end-to-end vector for enctypes 17/18 (see the
    // module docs), so the HMAC underneath has to be pinned on its own.

    #[test]
    fn rfc2202_tc2_hmac_sha1() {
        let mac = hmac(Hash::Sha1, b"Jefe", &[b"what do ya want for nothing?"]);
        assert_eq!(hx(&mac), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    /// RFC 2202 test case 5 publishes `digest-96` alongside the full digest —
    /// a published pin for "h = 12 means the LEADING 12 octets", which is the
    /// reading of `[1..h]` that RFC 3961 §5.3 mandates and that a
    /// take-from-the-end implementation gets wrong.
    #[test]
    fn rfc2202_tc5_hmac_sha1_96_is_the_leading_12_octets() {
        let mac = hmac(
            Hash::Sha1,
            &h("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
            &[b"Test With Truncation"],
        );
        assert_eq!(hx(&mac), "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04");
        assert_eq!(hx(&mac[..12]), "4c1a03424b55e07fe7f27be1");
    }

    // -- RFC 8009 Appendix A: full encryptions, confounder fixed by the RFC --

    struct K8009 {
        enctype: Enctype,
        ke: &'static str,
        ki: &'static str,
    }

    const E19: K8009 = K8009 {
        enctype: Enctype::Aes128CtsHmacSha256128,
        ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
        ki: "9fda0e56ab2d85e1569a688696c26a6c",
    };
    const E20: K8009 = K8009 {
        enctype: Enctype::Aes256CtsHmacSha384192,
        ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
        ki: "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
    };

    /// Asserts the AES output and the truncated HMAC *separately* before the
    /// concatenation, so a failure localises to the cipher or to the MAC
    /// instead of just saying "the token is wrong".
    fn k8009_case(k: &K8009, conf: &str, plain: &str, aes_out: &str, tag: &str, ct: &str) {
        let ke = h(k.ke);
        let ki = h(k.ki);
        let c = h(conf);
        let p = h(plain);

        let mut inner = c.clone();
        inner.extend_from_slice(&p);
        let aes = aes_cts_encrypt(&ke, &ZERO_IV, &inner).expect("cts");
        assert_eq!(hx(&aes), aes_out, "AES output");

        let mac = hmac(k.enctype.hash(), &ki, &[&ZERO_IV[..], &aes]);
        assert_eq!(hx(&mac[..k.enctype.checksum_len()]), tag, "truncated HMAC");

        let got = encrypt_with_confounder(k.enctype, &ke, &ki, &c, &p).expect("encrypt");
        assert_eq!(hx(&got), ct, "ciphertext");
        assert_eq!(got.len(), p.len() + k.enctype.overhead());

        let back = decrypt(k.enctype, &ke, &ki, &got).expect("decrypt");
        assert_eq!(hx(&back), plain, "decrypt");
    }

    #[test]
    fn rfc8009_a_encrypt_aes128_sha256_empty_plaintext() {
        // CTS input is the confounder alone: one block, no exchange possible.
        k8009_case(
            &E19,
            "7e5895eaf2672435bad817f545a37148",
            "",
            "ef85fb890bb8472f4dab20394dca781d",
            "ad877eda39d50c870c0d5a0a8e48c718",
            "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718",
        );
    }

    #[test]
    fn rfc8009_a_encrypt_aes128_sha256_less_than_block() {
        k8009_case(
            &E19,
            "7bca285e2fd4130fb55b1a5c83bc5b24",
            "000102030405",
            "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6",
            "877ce99e247e52d16ed4421dfdf8976c",
            "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed44\
             21dfdf8976c",
        );
    }

    #[test]
    fn rfc8009_a_encrypt_aes128_sha256_equals_block() {
        // 32-octet CTS input: CS3 exchanges the two blocks anyway.
        k8009_case(
            &E19,
            "56ab21713ff62c0a1457200f6fa9948f",
            "000102030405060708090a0b0c0d0e0f",
            "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc2",
            "95fb4852e7d83e1e7c48c37eebe6b0d3",
            "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295\
             fb4852e7d83e1e7c48c37eebe6b0d3",
        );
    }

    #[test]
    fn rfc8009_a_encrypt_aes128_sha256_greater_than_block() {
        k8009_case(
            &E19,
            "a7a4e29a4728ce10664fb64e49ad3fac",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1\
             e6d072c1",
            "86b39a413c2f92ca9b8334a287ffcbfc",
            "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1\
             e6d072c186b39a413c2f92ca9b8334a287ffcbfc",
        );
    }

    #[test]
    fn rfc8009_a_encrypt_aes256_sha384_empty_plaintext() {
        k8009_case(
            &E20,
            "f764e9fa15c276478b2c7d0c4e5f58e4",
            "",
            "41f53fa5bfe7026d91faf9be959195a0",
            "58707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c",
            "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b\
             9bbfbe7eb4ce3c",
        );
    }

    #[test]
    fn rfc8009_a_encrypt_aes256_sha384_less_than_block() {
        k8009_case(
            &E20,
            "b80d3251c1f6471494256ffe712d0b9a",
            "000102030405",
            "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9",
            "f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2",
            "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092\
             237526ea0d1f61cb20d69d10f2",
        );
    }

    #[test]
    fn rfc8009_a_encrypt_aes256_sha384_equals_block() {
        k8009_case(
            &E20,
            "53bf8a0d105265d4e276428624ce5e63",
            "000102030405060708090a0b0c0d0e0f",
            "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f6",
            "8cf51f14d798c2273f35df574d1f932e40c4ff255b36a266",
            "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f68c\
             f51f14d798c2273f35df574d1f932e40c4ff255b36a266",
        );
    }

    #[test]
    fn rfc8009_a_encrypt_aes256_sha384_greater_than_block() {
        k8009_case(
            &E20,
            "763e65367e864f02f55153c7e3b58af1",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2\
             a602ac86",
            "fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62",
            "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2\
             a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62",
        );
    }

    /// Falsifiability leg for `H = HMAC(Ki, IV | C)`.
    ///
    /// With the default cipher state the IV is 16 zero octets, so omitting it
    /// is invisible in a self-round-trip — both sides drop it. Against a
    /// published tag it is not invisible: this asserts the RFC's answer needs
    /// the IV prefix and that `HMAC(Ki, C)` alone is a different value.
    #[test]
    fn rfc8009_5_hmac_input_is_cipher_state_then_ciphertext() {
        let ki = h(E19.ki);
        let c = h("ef85fb890bb8472f4dab20394dca781d");
        let published = "ad877eda39d50c870c0d5a0a8e48c718";

        let with_iv = hmac(Hash::Sha256, &ki, &[&ZERO_IV[..], &c]);
        assert_eq!(hx(&with_iv[..16]), published);

        let without_iv = hmac(Hash::Sha256, &ki, &[&c]);
        assert_ne!(
            hx(&without_iv[..16]),
            published,
            "the 16 zero IV octets are load-bearing MAC input"
        );
    }

    // -- RFC 8009 Appendix A: checksums (§6) -------------------------------

    #[test]
    fn rfc8009_a_checksum_hmac_sha256_128_aes128() {
        let kc = h("b31a018a48f54776f403e9a396325dc3");
        let msg = h("000102030405060708090a0b0c0d0e0f1011121314");
        let mic = checksum(Enctype::Aes128CtsHmacSha256128, &kc, &msg).unwrap();
        assert_eq!(hx(&mic), "d78367186643d67b411cba9139fc1dee");
        assert!(verify_checksum(Enctype::Aes128CtsHmacSha256128, &kc, &msg, &mic).unwrap());
    }

    #[test]
    fn rfc8009_a_checksum_hmac_sha384_192_aes256() {
        // Kc here is 24 octets, not 32 — the length asymmetry of enctype 20.
        let kc = h("ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d");
        let msg = h("000102030405060708090a0b0c0d0e0f1011121314");
        let mic = checksum(Enctype::Aes256CtsHmacSha384192, &kc, &msg).unwrap();
        assert_eq!(hx(&mic), "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a");
        assert!(verify_checksum(Enctype::Aes256CtsHmacSha384192, &kc, &msg, &mic).unwrap());
    }

    // -- RFC 3961 §5.3, enctypes 17/18 -------------------------------------
    // NO IETF-PUBLISHED KNOWN ANSWER EXISTS for this construction (RFC 3961
    // Appendix A is DES/DES3; RFC 3962 Appendix B stops at string-to-key and
    // raw CTS). What follows pins the COMPOSITION byte-for-byte on top of two
    // primitives that are themselves pinned above (CTS by RFC 3962 Appendix B,
    // HMAC-SHA-1 by RFC 2202). It does not substitute for an interop capture.

    const K17_KE: &str = "9b197dd1e8c5609d6e67c3e37c62c72e";
    const K17_KI: &str = "9fda0e56ab2d85e1569a688696c26a6c";
    const K18_KE: &str = "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49";
    /// RFC 3962 Appendix B, the 256-bit AES key for pass phrase "password" /
    /// salt "ATHENA.MIT.EDUraeburn" at iteration count 1. Used here only as a
    /// 32-octet Ki distinct from Ke, so the two roles cannot be confused.
    const K18_KI: &str = "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161";

    #[test]
    fn rfc3961_5_3_encrypt_is_cts_then_appended_hmac_over_plaintext() {
        let ke = h(K17_KE);
        let ki = h(K17_KI);
        let conf = h("7e5895eaf2672435bad817f545a37148");
        let pt = h("000102030405060708090a0b0c0d0e0f1011121314");

        let ct = encrypt_with_confounder(Enctype::Aes128CtsHmacSha196, &ke, &ki, &conf, &pt)
            .expect("encrypt");

        // conf | plaintext, no pad: RFC 3962 §6 sets m = 1 octet.
        let mut inner = conf.clone();
        inner.extend_from_slice(&pt);

        // C1 = E(Ke, conf | plaintext), all-zero initial cipher state.
        let c1 = aes_cts_encrypt(&ke, &ZERO_IV, &inner).unwrap();
        // H1 = HMAC(Ki, conf | plaintext)[1..12].
        let h1 = hmac(Hash::Sha1, &ki, &[&inner]);

        assert_eq!(hx(&ct), format!("{}{}", hx(&c1), hx(&h1[..12])));

        // The tag is OUTSIDE the encrypted region — the exact bug in
        // kerberos.rs, which encrypts `plaintext | HMAC(...)`. Stripping the
        // trailing 12 octets and decrypting must yield conf|plaintext with
        // nothing left over.
        let inner_back = aes_cts_decrypt(&ke, &ZERO_IV, &ct[..ct.len() - 12]).unwrap();
        assert_eq!(hx(&inner_back), hx(&inner));
    }

    /// Falsifiability leg for "the §5.3 MAC covers the PLAINTEXT".
    ///
    /// RFC 8009 MACs the ciphertext; RFC 3961 §5.3 MACs `conf | plaintext |
    /// pad`. Getting this backwards round-trips against itself perfectly, so
    /// assert the two candidate tags actually differ and that the emitted one
    /// is the plaintext MAC.
    #[test]
    fn rfc3961_5_3_hmac_covers_plaintext_not_ciphertext() {
        let ke = h(K17_KE);
        let ki = h(K17_KI);
        let conf = h("7bca285e2fd4130fb55b1a5c83bc5b24");
        let pt = h("000102030405");

        let ct =
            encrypt_with_confounder(Enctype::Aes128CtsHmacSha196, &ke, &ki, &conf, &pt).unwrap();
        let tag = &ct[ct.len() - 12..];
        let c1 = &ct[..ct.len() - 12];

        let mut inner = conf.clone();
        inner.extend_from_slice(&pt);
        let over_plaintext = hmac(Hash::Sha1, &ki, &[&inner]);
        let over_ciphertext = hmac(Hash::Sha1, &ki, &[c1]);

        assert_eq!(hx(tag), hx(&over_plaintext[..12]));
        assert_ne!(hx(&over_plaintext[..12]), hx(&over_ciphertext[..12]));
    }

    /// RFC 3962 §6: c = 16, h = 12, m = 1 octet. So the expansion is exactly
    /// 28 octets for every length, with no rounding to a block boundary.
    #[test]
    fn rfc3962_6_ciphertext_length_is_plaintext_plus_28() {
        let ke = h(K18_KE);
        let ki = h(K18_KE);
        for len in [0usize, 1, 5, 15, 16, 17, 31, 32, 33, 100] {
            let pt = vec![0xa5u8; len];
            let ct = encrypt(Enctype::Aes256CtsHmacSha196, &ke, &ki, &pt).unwrap();
            assert_eq!(ct.len(), len + 28, "length for plaintext of {len}");
            assert_eq!(
                decrypt(Enctype::Aes256CtsHmacSha196, &ke, &ki, &ct).unwrap(),
                pt
            );
        }
    }

    // -- CROSS-IMPLEMENTATION DIFFERENTIAL, enctypes 17/18 -----------------
    //
    // READ THIS BEFORE TRUSTING THE HEX BELOW. These are NOT published
    // known-answer tests. No IETF KAT exists for the RFC 3961 §5.3
    // composition at enctypes 17/18 (RFC 3961 Appendix A is DES/DES3 only;
    // RFC 3962 Appendix B stops at string-to-key and raw CTS; and a KAT
    // would have to fix the confounder, which RFC 3962 never does).
    //
    // Provenance of the answers: a SECOND, independent implementation —
    // OpenSSL's AES-ECB as the block cipher, Python's stdlib HMAC, with
    // CBC-CS3 and the §5.3 composition written from the RFC text — which
    // was first checked to reproduce every RFC 3962 Appendix B vector
    // (ciphertext and Next IV, all six) and every RFC 8009 Appendix A
    // vector (AES output, truncated HMAC, ciphertext, all eight) before
    // being used to generate anything here.
    //
    // Every INPUT below is hex published in an RFC — the keys and
    // confounders come from RFC 8009 Appendix A and RFC 3962 Appendix B,
    // the plaintexts from RFC 8009 Appendix A and RFC 3962 Appendix B —
    // so no input is invented; only the outputs come from the second
    // implementation.
    //
    // What this buys: it turns "the module round-trips against itself"
    // into "two independent implementations of the same RFC text agree",
    // which is what the 55 tests in kerberos.rs never had. What it does
    // NOT buy: interoperability. Two implementations can share a
    // misreading. Closing that needs a capture against a real KDC.

    /// Asserts the AES output and the truncated HMAC separately before the
    /// concatenation, and that the tag lands OUTSIDE the encrypted region.
    fn k3961_case(
        et: Enctype,
        ke: &str,
        ki: &str,
        conf: &str,
        plain: &str,
        aes_out: &str,
        tag: &str,
        ct: &str,
    ) {
        let ke = h(ke);
        let ki = h(ki);
        let c = h(conf);
        let p = h(plain);

        let mut inner = c.clone();
        inner.extend_from_slice(&p);
        let aes = aes_cts_encrypt(&ke, &ZERO_IV, &inner).expect("cts");
        assert_eq!(hx(&aes), aes_out, "AES output");

        // RFC 3961 §5.3: H1 = HMAC(Ki, conf | plaintext | pad), over the
        // PLAINTEXT and with no IV prefix.
        let mac = hmac(Hash::Sha1, &ki, &[&inner]);
        assert_eq!(hx(&mac[..12]), tag, "truncated HMAC");

        let got = encrypt_with_confounder(et, &ke, &ki, &c, &p).expect("encrypt");
        assert_eq!(hx(&got), ct, "ciphertext");
        assert_eq!(got.len(), p.len() + et.overhead());

        // The tag is not inside the ciphertext: strip it, decrypt, and the
        // result is exactly conf|plaintext with nothing left over.
        assert_eq!(
            hx(&aes_cts_decrypt(&ke, &ZERO_IV, &got[..got.len() - 12]).unwrap()),
            hx(&inner)
        );
        assert_eq!(hx(&decrypt(et, &ke, &ki, &got).expect("decrypt")), plain);
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes128_sha1_96_empty_plaintext() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes128CtsHmacSha196,
            K17_KE,
            K17_KI,
            "7e5895eaf2672435bad817f545a37148",
            "",
            "ef85fb890bb8472f4dab20394dca781d",
            "4f0de84ce253486be5e8c00c",
            "ef85fb890bb8472f4dab20394dca781d4f0de84ce253486be5e8c00c",
        );
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes128_sha1_96_less_than_block() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes128CtsHmacSha196,
            K17_KE,
            K17_KI,
            "7bca285e2fd4130fb55b1a5c83bc5b24",
            "000102030405",
            "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6",
            "673d579c879e463095bbe088",
            "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6673d579c879e463095bbe0\
            88",
        );
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes128_sha1_96_equals_block() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes128CtsHmacSha196,
            K17_KE,
            K17_KI,
            "56ab21713ff62c0a1457200f6fa9948f",
            "000102030405060708090a0b0c0d0e0f",
            "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc2",
            "a41f3b5471904be03581a75c",
            "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc2a4\
            1f3b5471904be03581a75c",
        );
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes128_sha1_96_greater_than_block() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes128CtsHmacSha196,
            K17_KE,
            K17_KI,
            "a7a4e29a4728ce10664fb64e49ad3fac",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1\
            e6d072c1",
            "707f0ff16f7390fb317cf86c",
            "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1\
            e6d072c1707f0ff16f7390fb317cf86c",
        );
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes128_sha1_96_five_block_cts_input() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes128CtsHmacSha196,
            K17_KE,
            K17_KI,
            "7e5895eaf2672435bad817f545a37148",
            "4920776f756c64206c696b65207468652047656e6572616c204761752773204368\
            69636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
            "ef85fb890bb8472f4dab20394dca781d68dc61508c9de9dc27da27606bd2f1a0cc\
            4486e7e03a43c714077e03601a76ae56719b69abaa97b0b58d34389e9c73622fdd\
            e52b12c62790dd7cf9da3929af47",
            "6978dac87abffd53e19dadda",
            "ef85fb890bb8472f4dab20394dca781d68dc61508c9de9dc27da27606bd2f1a0cc\
            4486e7e03a43c714077e03601a76ae56719b69abaa97b0b58d34389e9c73622fdd\
            e52b12c62790dd7cf9da3929af476978dac87abffd53e19dadda",
        );
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes256_sha1_96_empty_plaintext() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes256CtsHmacSha196,
            K18_KE,
            K18_KI,
            "7e5895eaf2672435bad817f545a37148",
            "",
            "2c3a04efe95ffc0ed816301f3819251a",
            "c56c52b1e6011814e1df763e",
            "2c3a04efe95ffc0ed816301f3819251ac56c52b1e6011814e1df763e",
        );
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes256_sha1_96_less_than_block() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes256CtsHmacSha196,
            K18_KE,
            K18_KI,
            "7bca285e2fd4130fb55b1a5c83bc5b24",
            "000102030405",
            "c4fbbb370cebddb9ee89bd971d92e560efa035468968",
            "6a67ef51567521cbd5fa0274",
            "c4fbbb370cebddb9ee89bd971d92e560efa0354689686a67ef51567521cbd5fa02\
            74",
        );
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes256_sha1_96_equals_block() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes256CtsHmacSha196,
            K18_KE,
            K18_KI,
            "56ab21713ff62c0a1457200f6fa9948f",
            "000102030405060708090a0b0c0d0e0f",
            "1dd94442fb81161f3de0d6a64297c6de64d9967d96c9eab3fc172e134ac4ca69",
            "60dddce4594d383d8680290a",
            "1dd94442fb81161f3de0d6a64297c6de64d9967d96c9eab3fc172e134ac4ca6960\
            dddce4594d383d8680290a",
        );
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes256_sha1_96_greater_than_block() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes256CtsHmacSha196,
            K18_KE,
            K18_KI,
            "a7a4e29a4728ce10664fb64e49ad3fac",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "4109e783c8d7b0668a2b727763c0891d82a6a79b85c6cf8011bbb240dd39343a77\
            1182fef8",
            "960609bc8a279689e8fc12aa",
            "4109e783c8d7b0668a2b727763c0891d82a6a79b85c6cf8011bbb240dd39343a77\
            1182fef8960609bc8a279689e8fc12aa",
        );
    }

    #[test]
    fn xcheck_rfc3961_5_3_aes256_sha1_96_five_block_cts_input() {
        // NOT a published KAT -- see the banner above.
        k3961_case(
            Enctype::Aes256CtsHmacSha196,
            K18_KE,
            K18_KI,
            "7e5895eaf2672435bad817f545a37148",
            "4920776f756c64206c696b65207468652047656e6572616c204761752773204368\
            69636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
            "2c3a04efe95ffc0ed816301f3819251a966accea8a785793d226672067816624f2\
            5398b9ea36ca6d936a65c93f0733b89ec793371661af18553584ac470a7f4bff38\
            aeb44206577366be41276153b903",
            "2599bf5c00f4dbcd4392ed60",
            "2c3a04efe95ffc0ed816301f3819251a966accea8a785793d226672067816624f2\
            5398b9ea36ca6d936a65c93f0733b89ec793371661af18553584ac470a7f4bff38\
            aeb44206577366be41276153b9032599bf5c00f4dbcd4392ed60",
        );
    }

    #[test]
    fn xcheck_rfc3962_5_cts_with_a_non_zero_cipher_state() {
        // NOT a published KAT: every RFC 3962 Appendix B vector uses an
        // all-zero IV. Answers from the same independent implementation.
        let key = h(CTS_KEY);
        let iv: [u8; BLOCK_SIZE] = h("fe697b52bc0d3ce14432ba036a92e65b").try_into().unwrap();
        for (plain, cipher, next_iv) in [
            (
                "4920776f756c64206c696b6520746865",
                "394c0a17b18eaee5fe8581179f40fe35",
                "394c0a17b18eaee5fe8581179f40fe35",
            ),
            (
                "4920776f756c64206c696b652074686520",
                "1a4f63cd8ea2a3caabf271c488b7d20339",
                "1a4f63cd8ea2a3caabf271c488b7d203",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
                "7ad7ce32755e19ffc7bef66f5ae5197a394c0a17b18eaee5fe8581179f40fe",
                "7ad7ce32755e19ffc7bef66f5ae5197a",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
                "19b334d3ebd451967a239c09a80baeeb394c0a17b18eaee5fe8581179f40fe35",
                "19b334d3ebd451967a239c09a80baeeb",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c204761752773204368",
                "394c0a17b18eaee5fe8581179f40fe358eb08c4ac0b8694b5b0771ccaaae6d7719",
                "8eb08c4ac0b8694b5b0771ccaaae6d77",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c204761752773204368\
                    69636b656e2c20706c656173652c",
                "394c0a17b18eaee5fe8581179f40fe35746dea4941a8aea9ea7432742299c83019\
                    b334d3ebd451967a239c09a80bae",
                "746dea4941a8aea9ea7432742299c830",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c204761752773204368\
                    69636b656e2c20706c656173652c20",
                "394c0a17b18eaee5fe8581179f40fe358198579aa981343ab0ef89919879502819\
                    b334d3ebd451967a239c09a80baeeb",
                "8198579aa981343ab0ef899198795028",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c204761752773204368\
                    69636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
                "394c0a17b18eaee5fe8581179f40fe3519b334d3ebd451967a239c09a80baeebc0\
                    85003503268b88739133faccb1510a8198579aa981343ab0ef899198795028",
                "c085003503268b88739133faccb1510a",
            ),
        ] {
            let p = h(plain);
            let c = aes_cts_encrypt(&key, &iv, &p).unwrap();
            assert_eq!(hx(&c), cipher, "ct for {} octets", p.len());
            assert_eq!(hx(&cts_next_iv(&c).unwrap()), next_iv, "next IV");
            assert_eq!(hx(&aes_cts_decrypt(&key, &iv, &c).unwrap()), plain);
        }
    }

    // -- Round trips. Additional to the known answers, never instead. -------

    /// VACUITY NOTE, measured rather than asserted: with the RFC 3961 §5.3
    /// MAC moved onto the ciphertext on both sides — the exact kerberos.rs
    /// bug — this test stays GREEN while twelve others go red. It proves
    /// `decrypt ∘ encrypt = id` and the absence of padding, and it is no
    /// evidence whatsoever about the wire format. It is here in addition to
    /// the known answers, never instead of them.
    #[test]
    fn round_trip_every_enctype_and_length() {
        let cases = [
            (Enctype::Aes128CtsHmacSha196, K17_KE, K17_KI),
            (Enctype::Aes256CtsHmacSha196, K18_KE, K18_KE),
            (Enctype::Aes128CtsHmacSha256128, E19.ke, E19.ki),
            (Enctype::Aes256CtsHmacSha384192, E20.ke, E20.ki),
        ];
        for (et, ke, ki) in cases {
            let ke = h(ke);
            let ki = h(ki);
            for len in [0usize, 1, 6, 15, 16, 17, 31, 32, 47, 48, 64, 200] {
                let pt: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let ct = encrypt(et, &ke, &ki, &pt).unwrap();
                assert_eq!(ct.len(), len + et.overhead());
                assert_eq!(decrypt(et, &ke, &ki, &ct).unwrap(), pt, "{et:?} len {len}");
            }
        }
    }

    /// The confounder must be fresh per message. If it were fixed or absent,
    /// two encryptions of the same plaintext would be byte-identical — which
    /// is exactly the state kerberos.rs is in today.
    #[test]
    fn rfc3961_5_3_confounder_is_fresh_per_message() {
        let ke = h(E19.ke);
        let ki = h(E19.ki);
        let pt = b"the same plaintext, twice";
        let a = encrypt(Enctype::Aes128CtsHmacSha256128, &ke, &ki, pt).unwrap();
        let b = encrypt(Enctype::Aes128CtsHmacSha256128, &ke, &ki, pt).unwrap();
        assert_ne!(a, b, "identical ciphertexts mean no confounder");
        assert_eq!(
            decrypt(Enctype::Aes128CtsHmacSha256128, &ke, &ki, &a).unwrap(),
            pt
        );
        assert_eq!(
            decrypt(Enctype::Aes128CtsHmacSha256128, &ke, &ki, &b).unwrap(),
            pt
        );
    }

    // -- Negative paths ----------------------------------------------------

    #[test]
    fn decrypt_rejects_a_flipped_tag_octet() {
        for (et, ke, ki) in [
            (Enctype::Aes128CtsHmacSha196, K17_KE, K17_KI),
            (Enctype::Aes256CtsHmacSha196, K18_KE, K18_KI),
            (Enctype::Aes128CtsHmacSha256128, E19.ke, E19.ki),
            (Enctype::Aes256CtsHmacSha384192, E20.ke, E20.ki),
        ] {
            let ke = h(ke);
            let ki = h(ki);
            let pt = b"integrity or nothing";
            let mut ct = encrypt(et, &ke, &ki, pt).unwrap();
            let last = ct.len() - 1;
            ct[last] ^= 0x01;
            match decrypt(et, &ke, &ki, &ct) {
                Err(ProfileError::IntegrityFailure) => {}
                other => panic!("{et:?}: expected IntegrityFailure, got {other:?}"),
            }
        }
    }

    /// A flipped *ciphertext* octet must be caught at every enctype, and the
    /// two families catch it by different routes: RFC 8009 sees the change
    /// directly (the MAC covers `IV | C`), while RFC 3961 §5.3 sees it only
    /// after decryption, as garbled plaintext under a MAC that no longer
    /// matches. The §5.3 route was previously untested here.
    #[test]
    fn decrypt_rejects_a_flipped_ciphertext_octet() {
        for (et, ke, ki) in [
            (Enctype::Aes128CtsHmacSha196, K17_KE, K17_KI),
            (Enctype::Aes256CtsHmacSha196, K18_KE, K18_KI),
            (Enctype::Aes128CtsHmacSha256128, E19.ke, E19.ki),
            (Enctype::Aes256CtsHmacSha384192, E20.ke, E20.ki),
        ] {
            let ke = h(ke);
            let ki = h(ki);
            let pt = b"integrity or nothing";
            let ct = encrypt(et, &ke, &ki, pt).unwrap();
            // Flip in the confounder block, in the middle, and in the last
            // CTS block: the stolen-ciphertext tail is its own code path.
            for pos in [0usize, 8, ct.len() - et.checksum_len() - 1] {
                let mut bad = ct.clone();
                bad[pos] ^= 0x80;
                match decrypt(et, &ke, &ki, &bad) {
                    Err(ProfileError::IntegrityFailure) => {}
                    other => {
                        panic!("{et:?} flip at {pos}: expected IntegrityFailure, got {other:?}")
                    }
                }
            }
        }
    }

    /// A ciphertext shorter than c + h must be refused before anything is
    /// sliced — on hostile input the alternative is an index panic.
    #[test]
    fn decrypt_rejects_short_ciphertext_without_panicking() {
        for (et, ke, ki, minimum) in [
            (Enctype::Aes128CtsHmacSha196, K17_KE, K17_KI, 28usize),
            (Enctype::Aes128CtsHmacSha256128, E19.ke, E19.ki, 32),
            (Enctype::Aes256CtsHmacSha384192, E20.ke, E20.ki, 40),
        ] {
            let ke = h(ke);
            let ki = h(ki);
            assert_eq!(et.overhead(), minimum);
            for len in 0..minimum {
                match decrypt(et, &ke, &ki, &vec![0u8; len]) {
                    Err(ProfileError::CiphertextTooShort { .. }) => {}
                    other => panic!("{et:?} len {len}: expected CiphertextTooShort, got {other:?}"),
                }
            }
        }
    }

    /// The enctype-20 length asymmetry, made loud. SHA-384 emits 48 octets, so
    /// a Ki sized from `key_size()` (32) truncates without error and produces a
    /// silently wrong tag. Refuse it at the door instead.
    #[test]
    fn rfc8009_5_rejects_a_32_octet_ki_for_enctype_20() {
        let ke = h(E20.ke);
        let wrong_ki = vec![0u8; 32];
        assert_eq!(Enctype::Aes256CtsHmacSha384192.ki_len(), 24);
        assert!(matches!(
            encrypt(Enctype::Aes256CtsHmacSha384192, &ke, &wrong_ki, b"x"),
            Err(ProfileError::KeyLength { role: "Ki", .. })
        ));
        assert!(matches!(
            decrypt(Enctype::Aes256CtsHmacSha384192, &ke, &wrong_ki, &[0u8; 64]),
            Err(ProfileError::KeyLength { role: "Ki", .. })
        ));
        assert!(matches!(
            checksum(Enctype::Aes256CtsHmacSha384192, &wrong_ki, b"x"),
            Err(ProfileError::KeyLength { role: "Kc", .. })
        ));
    }

    #[test]
    fn rejects_wrong_confounder_length() {
        let ke = h(E19.ke);
        let ki = h(E19.ki);
        assert!(matches!(
            encrypt_with_confounder(Enctype::Aes128CtsHmacSha256128, &ke, &ki, &[0u8; 8], b"x"),
            Err(ProfileError::ConfounderLength { want: 16, got: 8 })
        ));
    }

    // -- Profile parameter table (RFC 3962 §6/§7, RFC 8009 §5/§7) ----------

    #[test]
    fn rfc3962_7_and_rfc8009_7_profile_parameters() {
        use Enctype::*;
        for (et, num, ke, ki, kc, hh) in [
            (Aes128CtsHmacSha196, 17, 16, 16, 16, 12),
            (Aes256CtsHmacSha196, 18, 32, 32, 32, 12),
            (Aes128CtsHmacSha256128, 19, 16, 16, 16, 16),
            (Aes256CtsHmacSha384192, 20, 32, 24, 24, 24),
        ] {
            assert_eq!(et.as_i32(), num);
            assert_eq!(Enctype::from_i32(num).unwrap(), et);
            assert_eq!(et.ke_len(), ke, "{et:?} Ke");
            assert_eq!(et.ki_len(), ki, "{et:?} Ki");
            assert_eq!(et.kc_len(), kc, "{et:?} Kc");
            assert_eq!(et.checksum_len(), hh, "{et:?} h");
            assert_eq!(et.confounder_len(), 16, "{et:?} c");
        }
        assert!(!Aes128CtsHmacSha196.is_rfc8009());
        assert!(!Aes256CtsHmacSha196.is_rfc8009());
        assert!(Aes128CtsHmacSha256128.is_rfc8009());
        assert!(Aes256CtsHmacSha384192.is_rfc8009());
        assert!(Enctype::from_i32(23).is_err(), "RC4 is not in scope");
        assert!(Enctype::from_i32(16).is_err(), "DES3 is not in scope");
    }

    /// VACUITY NOTE: this pins the *equality semantics* of [`ct_eq`] and
    /// nothing else. A plain `a == b` passes every assertion below, so this
    /// test is no evidence at all for the constant-time property the
    /// function exists to provide. That property is enforced by reading the
    /// body (accumulate-then-test, `black_box`), not by this test.
    #[test]
    fn ct_eq_agrees_with_slice_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"\x00", b"\x80"));
    }
}
