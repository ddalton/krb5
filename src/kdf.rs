//! Kerberos 5 key derivation, to specification.
//!
//! There are **two** key-derivation schemes here and they share nothing but
//! the three constant octets. Conflating them is the whole point of this
//! module's existence, so the split is enforced by the type system rather
//! than left to the caller's memory:
//!
//! * **enctypes 17/18** (`aes128/256-cts-hmac-sha1-96`) use RFC 3961 §5.1
//!   DR/DK — n-fold the constant, then chain AES block encryptions.
//! * **enctypes 19/20** (`aes128-cts-hmac-sha256-128`,
//!   `aes256-cts-hmac-sha384-192`) use RFC 8009 §3 KDF-HMAC-SHA2 — a
//!   counter-mode HMAC KDF with **no n-fold and no cipher invocation at
//!   all**. Do not "fix" 19/20 by porting the SHA-1 shape onto it.
//!
//! [`derive_key`] is the entry point callers should use: it takes the
//! enctype and routes to the right scheme with the right output length.
//! The raw [`dk`] and [`kdf_hmac_sha2`] are exposed for the known-answer
//! tests and for string-to-key, which needs DK with a non-usage constant.
//!
//! # Why this file exists
//!
//! [`crate::acceptor`] derives Ke with **Kc's** constant (0x99 where
//! RFC 3961 §5.3 says 0xAA), zero-pads the constant where DR requires
//! n-fold, and implements the RFC 8009 KDF as a bare HMAC missing three of
//! its four framing fields. Every one of those bugs round-trips perfectly
//! against itself, which is why 55 self-consistency tests never saw them.
//! So: every function below is pinned to hex copied out of a published
//! RFC, and where a wrong-but-plausible reading exists, there is a test
//! asserting the vector actually *discriminates* against it.
//!
//! # References
//! - RFC 3961 §5.1 (DR/DK), §5.3 (Kc/Ke/Ki constants)
//! - RFC 3962 §4 (string-to-key), §6 (random-to-key = identity)
//! - RFC 8009 §3 (KDF-HMAC-SHA2), §4 (string-to-key), §5 (parameters, PRF)

#![allow(dead_code)]

use aes::{
    Aes128, Aes256,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha384};

use super::nfold::n_fold;

/// AES cipher block size, in octets. RFC 3962 §6: `c = 16`.
const AES_BLOCK: usize = 16;

/// The RFC 3962 §4 / RFC 8009 §4 second-stage constant: the 8-octet ASCII
/// string "kerberos" (0x6b65726265726f73). PBKDF2's output is *not* the
/// key; it is the `tkey` that still has to go through this derivation.
const KERBEROS: &[u8] = b"kerberos";

/// RFC 3962 §6 default string-to-key parameter, `00 00 10 00` = 4096.
const RFC3962_DEFAULT_ITERATIONS: u64 = 4096;

/// RFC 8009 §4 default iteration count. **Deliberately different** from
/// RFC 3962's 4096; carrying the old default across is a silent wrong-key.
const RFC8009_DEFAULT_ITERATIONS: u64 = 32768;

/// Upper bound on the PBKDF2 iteration count we are willing to run.
///
/// RFC 3962 §4: an implementation that bounds the count "SHOULD" allow no
/// less than 50,000, precisely so a spoofed KDC reply cannot burn client
/// CPU. A string-to-key parameter of `00 00 00 00` means 2^32 iterations
/// (*not* zero — that is the trap), which lands here and is refused rather
/// than silently reinterpreted.
const MAX_ITERATIONS: u64 = 1_000_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KdfError {
    #[error("base key is {got} octets, enctype {etype} requires {want}")]
    BaseKeyLength { etype: i32, got: usize, want: usize },

    #[error("DR/DK requires a 16- or 32-octet AES key, got {0} octets")]
    AesKeyLength(usize),

    #[error(
        "DR constant is {0} octets; RFC 3961 §5.1 forbids more than the 16-octet cipher block size"
    )]
    ConstantTooLong(usize),

    /// n-fold of an empty octet string is undefined (there is nothing to
    /// replicate to the lcm), so the underlying `n_fold` asserts. Catch it
    /// here: a `pub fn` must not panic on an input it can name.
    #[error("DR constant is empty; RFC 3961 §5.1 n-fold is undefined for a zero-length input")]
    ConstantEmpty,

    #[error("requested {0} bits; KDF output length must be a whole number of octets")]
    NotWholeOctets(u32),

    /// A zero-length key is not a key. Without this the KDF returns
    /// `Ok(vec![])`, which is the module's own failure mode — a
    /// plausible-looking value that no peer agrees with.
    #[error("requested a zero-length key; RFC 8009 §3 k must be positive")]
    KLengthZero,

    #[error("requested {want} bits but RFC 8009 §3 caps k at {max} for this enctype")]
    KLengthTooLong { want: u32, max: u32 },

    #[error(
        "enctype {0} uses RFC 3961 DR/DK, not the RFC 8009 KDF — these are different functions, not variants"
    )]
    NotAnRfc8009Enctype(i32),

    #[error("enctype {0} uses the RFC 8009 KDF, not RFC 3961 DR/DK")]
    NotAnRfc3961Enctype(i32),

    #[error("iteration count {0} exceeds the {MAX_ITERATIONS} cap")]
    IterationsTooHigh(u64),

    #[error("iteration count {count} is below the enctype's default of {min}")]
    IterationsTooLow { count: u64, min: u64 },

    #[error("unknown or unsupported enctype {0}; only 17, 18, 19 and 20 are supported")]
    UnsupportedEnctype(i32),
}

type Result<T> = std::result::Result<T, KdfError>;

/// The four AES enctypes this crate supports.
///
/// Note the spelling of enctype 20: the trailing number is **192**, the
/// HMAC truncation length. [`crate::acceptor`] spells it `...384196`,
/// which is a transcription slip and a hint that the 192/196 distinction
/// was never checked against RFC 8009 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Enctype {
    /// RFC 3962 §7. DR/DK derivation, SHA-1, h = 12.
    Aes128CtsHmacSha196 = 17,
    /// RFC 3962 §7. DR/DK derivation, SHA-1, h = 12.
    Aes256CtsHmacSha196 = 18,
    /// RFC 8009 §7. KDF-HMAC-SHA2 derivation, SHA-256, h = 16.
    Aes128CtsHmacSha256128 = 19,
    /// RFC 8009 §7. KDF-HMAC-SHA2 derivation, SHA-384, h = 24.
    Aes256CtsHmacSha384192 = 20,
}

/// Which of the three specific keys is wanted (RFC 3961 §5.3, RFC 8009 §5).
///
/// All three constants are live in a conformant implementation. The natural
/// but wrong pairing is "Ke to encrypt, Ki to MAC everything": `get_mic`
/// uses **Kc**, and Ki appears only as the integrity tag *inside* encrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyUse {
    /// Kc — the checksum key, for `get_mic`/`verify_mic` (RFC 3961 §5.4).
    Checksum,
    /// Ke — the encryption key.
    Encryption,
    /// Ki — the integrity key, for the HMAC inside encrypt.
    Integrity,
}

impl KeyUse {
    /// The single octet appended to the big-endian usage number.
    ///
    /// RFC 3961 §5.3 verbatim:
    /// ```text
    /// Kc = DK(base-key, usage | 0x99);
    /// Ke = DK(base-key, usage | 0xAA);
    /// Ki = DK(base-key, usage | 0x55);
    /// ```
    /// RFC 8009 §5 reuses the same three octets with a different KDF.
    /// `0x99` is **Kc**; mapping it to Ke (as `kerberos.rs` does) makes the
    /// encryption key equal the checksum key.
    pub const fn constant_octet(self) -> u8 {
        match self {
            KeyUse::Checksum => 0x99,
            KeyUse::Encryption => 0xAA,
            KeyUse::Integrity => 0x55,
        }
    }
}

impl Enctype {
    /// Map a wire enctype number onto a supported enctype.
    pub fn from_i32(etype: i32) -> Result<Self> {
        match etype {
            17 => Ok(Enctype::Aes128CtsHmacSha196),
            18 => Ok(Enctype::Aes256CtsHmacSha196),
            19 => Ok(Enctype::Aes128CtsHmacSha256128),
            20 => Ok(Enctype::Aes256CtsHmacSha384192),
            other => Err(KdfError::UnsupportedEnctype(other)),
        }
    }

    /// The wire enctype number.
    pub const fn etype(self) -> i32 {
        self as i32
    }

    /// Protocol (base) key length in octets: the AES key size.
    ///
    /// This is the length of the *base* key and of Ke. It is **not** the
    /// length of Kc and Ki for enctype 20 — see [`Self::derived_key_bits`].
    pub const fn key_size(self) -> usize {
        match self {
            Enctype::Aes128CtsHmacSha196 | Enctype::Aes128CtsHmacSha256128 => 16,
            Enctype::Aes256CtsHmacSha196 | Enctype::Aes256CtsHmacSha384192 => 32,
        }
    }

    /// True when this enctype derives keys with RFC 8009 §3 KDF-HMAC-SHA2
    /// rather than RFC 3961 §5.1 DR/DK.
    pub const fn is_rfc8009(self) -> bool {
        matches!(
            self,
            Enctype::Aes128CtsHmacSha256128 | Enctype::Aes256CtsHmacSha384192
        )
    }

    /// Length **in bits** of the specific key `which` for this enctype.
    ///
    /// The trap lives here. For enctype 20 the three keys are *not* the
    /// same length — Ke is 256 bits but Kc and Ki are 192 (RFC 8009 §5).
    /// A single `key_size()` for all three yields a 32-octet Ki, and since
    /// SHA-384 emits 48 octets the over-long truncation **succeeds
    /// silently**: no error, no panic, just a key no peer agrees with.
    pub const fn derived_key_bits(self, which: KeyUse) -> u32 {
        match self {
            Enctype::Aes128CtsHmacSha196 | Enctype::Aes128CtsHmacSha256128 => 128,
            Enctype::Aes256CtsHmacSha196 => 256,
            Enctype::Aes256CtsHmacSha384192 => match which {
                KeyUse::Encryption => 256,
                KeyUse::Checksum | KeyUse::Integrity => 192,
            },
        }
    }

    /// The enctype name prepended to the salt by RFC 8009 §4 string-to-key.
    ///
    /// `None` for enctypes 17/18, which use the bare salt (RFC 3962 §4).
    pub const fn rfc8009_name(self) -> Option<&'static str> {
        match self {
            Enctype::Aes128CtsHmacSha256128 => Some("aes128-cts-hmac-sha256-128"),
            Enctype::Aes256CtsHmacSha384192 => Some("aes256-cts-hmac-sha384-192"),
            _ => None,
        }
    }

    /// Default string-to-key iteration count when no parameter is supplied.
    pub const fn default_s2k_iterations(self) -> u64 {
        if self.is_rfc8009() {
            RFC8009_DEFAULT_ITERATIONS
        } else {
            RFC3962_DEFAULT_ITERATIONS
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 3961 §5.1 — DR and DK (enctypes 17 and 18)
// ---------------------------------------------------------------------------

/// One raw AES block encryption.
///
/// RFC 3961 §5.1 calls `E(Key, block, initial-cipher-state)`, which for the
/// AES simplified profile is CBC-CTS over exactly one block with an
/// all-zero IV — and that degenerates to a bare ECB block encryption. It is
/// **not** the §5.3 encrypt function: no confounder, no padding, no HMAC.
fn aes_encrypt_block(key: &[u8], block: &mut [u8; AES_BLOCK]) -> Result<()> {
    let b = GenericArray::from_mut_slice(block);
    match key.len() {
        16 => Aes128::new_from_slice(key)
            .expect("length checked")
            .encrypt_block(b),
        32 => Aes256::new_from_slice(key)
            .expect("length checked")
            .encrypt_block(b),
        n => return Err(KdfError::AesKeyLength(n)),
    }
    Ok(())
}

/// RFC 3961 §5.1 `DR(Key, Constant)` for the AES enctypes.
///
/// ```text
/// K1 = E(Key, n-fold(Constant), initial-cipher-state)
/// K2 = E(Key, K1,               initial-cipher-state)
/// DR(Key, Constant) = k-truncate(K1 | K2 | ...)
/// ```
///
/// `k` is the key-generation seed length **in octets** (16 for aes128, 32
/// for aes256 — RFC 3962 §6 sets it equal to the key size).
///
/// Two traps are load-bearing here:
///
/// 1. The constant is **n-folded**, never zero-padded. The simplified
///    profile's constant is always 5 octets, so this path is taken for
///    every derived key in the protocol. Zero-padding gives a completely
///    different DR input and therefore a completely different key.
/// 2. The all-zero initial cipher state is re-supplied for **every** `K_i`.
///    The chain runs through the *plaintext* input, not the IV. Feeding K1
///    back as the IV is the natural misreading, and it agrees in the first
///    block — so it passes every aes128 test (k = 128 needs one block) and
///    only breaks on aes256.
pub fn dr(base_key: &[u8], constant: &[u8], k: usize) -> Result<Vec<u8>> {
    if base_key.len() != 16 && base_key.len() != 32 {
        return Err(KdfError::AesKeyLength(base_key.len()));
    }
    // RFC 3961 §5.1: "The size of the Constant must not be larger than c,
    // because reducing the length of the Constant by n-folding can cause
    // collisions." The exactly-equal case is used as-is; it never arises in
    // the simplified profile (the constant is 5 octets) but string-to-key
    // hands us "kerberos", which is 8.
    let mut block = [0u8; AES_BLOCK];
    match constant.len() {
        0 => return Err(KdfError::ConstantEmpty),
        n if n > AES_BLOCK => return Err(KdfError::ConstantTooLong(n)),
        n if n == AES_BLOCK => block.copy_from_slice(constant),
        _ => {
            let folded = n_fold(constant, AES_BLOCK * 8);
            debug_assert_eq!(folded.len(), AES_BLOCK);
            block.copy_from_slice(&folded);
        }
    }

    let mut out = Vec::with_capacity(k + AES_BLOCK);
    // "while accumulated < k", not a fixed block count: aes256 needs two
    // iterations, aes128 one, and stopping at one block for aes256 is the
    // other half of the zero-IV trap above.
    while out.len() < k {
        aes_encrypt_block(base_key, &mut block)?;
        out.extend_from_slice(&block);
    }
    out.truncate(k);
    Ok(out)
}

/// RFC 3961 §5.1 `DK(Key, Constant) = random-to-key(DR(Key, Constant))`.
///
/// For **all** AES enctypes `random-to-key` is the identity function
/// (RFC 3962 §6, RFC 8009 §5), so `DK == k-truncate(DR)`. If you find
/// yourself writing a random-to-key step that does anything at all, you are
/// following the DES3 path — which is also why the RFC 3961 Appendix A.3
/// `DK` column must never be used as an AES check: DES3's random-to-key
/// inserts parity bits, so its DK is 24 octets where its DR is 21.
///
/// `k` is in octets.
pub fn dk(base_key: &[u8], constant: &[u8], k: usize) -> Result<Vec<u8>> {
    dr(base_key, constant, k)
}

// ---------------------------------------------------------------------------
// RFC 8009 §3 — KDF-HMAC-SHA2 (enctypes 19 and 20)
// ---------------------------------------------------------------------------

/// Build the HMAC *message* for RFC 8009 §3 KDF-HMAC-SHA2.
///
/// ```text
/// no context: 0x00000001 | label | 0x00 | k
/// context:    0x00000001 | label | 0x00 | context | k
/// ```
///
/// All four framing fields are load-bearing and all four are missing from
/// `kerberos.rs`'s bare `HMAC(key, constant)`:
///
/// * `0x00000001` is SP800-108's iteration counter `i`, **fixed** — there
///   is no loop, which is why k can never exceed one digest.
/// * the `0x00` separator is present even when `context` is absent; it is a
///   separator, not a terminator for the label.
/// * `k` is the output length in **bits**, big-endian in 4 octets. Writing
///   the octet count (`0x00000010` for 16 octets rather than `0x00000080`
///   for 128 bits) produces a plausible key that is silently wrong, because
///   the field is inside the MAC.
fn kdf_message(label: &[u8], context: Option<&[u8]>, k_bits: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + label.len() + 1 + context.map_or(0, <[u8]>::len) + 4);
    msg.extend_from_slice(&1u32.to_be_bytes());
    msg.extend_from_slice(label);
    msg.push(0x00);
    if let Some(ctx) = context {
        msg.extend_from_slice(ctx);
    }
    msg.extend_from_slice(&k_bits.to_be_bytes());
    msg
}

/// RFC 8009 §3 `KDF-HMAC-SHA2(key, label, [context,] k)`.
///
/// The hash is selected by **enctype**, not by the requested output length:
/// SHA-256 for enctype 19, SHA-384 for enctype 20. Enctype 20 derives a
/// 192-bit Kc with HMAC-SHA-384 truncated to 24 octets, not with any
/// "SHA-192".
///
/// `k_bits` is the output length in bits and must be a whole number of
/// octets and no greater than one digest (RFC 8009 §3). Since the counter
/// `i` is fixed at 1 there is no defined continuation past one digest, so
/// an over-long request is refused rather than guessed at.
///
/// Rejects enctypes 17/18: they use RFC 3961 §5.1 DR/DK, which is a
/// different function and not a variant of this one.
pub fn kdf_hmac_sha2(
    enctype: Enctype,
    key: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    k_bits: u32,
) -> Result<Vec<u8>> {
    if k_bits == 0 {
        return Err(KdfError::KLengthZero);
    }
    if k_bits % 8 != 0 {
        return Err(KdfError::NotWholeOctets(k_bits));
    }
    let msg = kdf_message(label, context, k_bits);
    let out = k_bits as usize / 8;

    match enctype {
        Enctype::Aes128CtsHmacSha256128 => {
            if k_bits > 256 {
                return Err(KdfError::KLengthTooLong {
                    want: k_bits,
                    max: 256,
                });
            }
            let mut mac =
                <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(&msg);
            Ok(mac.finalize().into_bytes()[..out].to_vec())
        }
        Enctype::Aes256CtsHmacSha384192 => {
            if k_bits > 384 {
                return Err(KdfError::KLengthTooLong {
                    want: k_bits,
                    max: 384,
                });
            }
            let mut mac =
                <Hmac<Sha384> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(&msg);
            Ok(mac.finalize().into_bytes()[..out].to_vec())
        }
        other => Err(KdfError::NotAnRfc8009Enctype(other.etype())),
    }
}

// ---------------------------------------------------------------------------
// The enctype-aware entry point
// ---------------------------------------------------------------------------

/// Derive Kc, Ke or Ki from a base key — RFC 3961 §5.3 / RFC 8009 §5.
///
/// This is the function callers should use. It picks the derivation scheme
/// from the enctype (DR/DK for 17/18, KDF-HMAC-SHA2 for 19/20) and the
/// output length from the enctype *and* which key is wanted, so it is not
/// possible to derive a 256-bit Ki for enctype 20 by accident.
///
/// The well-known constant is the key usage number as **four octets,
/// big-endian**, followed by the one octet from [`KeyUse::constant_octet`].
/// Usage arrives from ASN.1 as a signed `i32`; cast it (`usage as u32`)
/// rather than sign-extending, and never let a negative usage reach here.
/// Byte order of the usage is the most common interop bug after the
/// constant mix-up, and a usage off by one yields a valid-looking wrong key
/// that fails only against a real peer.
///
/// Key usage numbers live in RFC 4120 §7.5.1 and RFC 4121 §2 — note that a
/// checksum and the message it accompanies deliberately carry *different*
/// usages (AP-REQ authenticator cksum is 10, the authenticator itself 11).
pub fn derive_key(enctype: Enctype, base_key: &[u8], usage: u32, which: KeyUse) -> Result<Vec<u8>> {
    if base_key.len() != enctype.key_size() {
        return Err(KdfError::BaseKeyLength {
            etype: enctype.etype(),
            got: base_key.len(),
            want: enctype.key_size(),
        });
    }

    // Five octets: usage as big-endian u32, then the type octet.
    let mut constant = [0u8; 5];
    constant[..4].copy_from_slice(&usage.to_be_bytes());
    constant[4] = which.constant_octet();

    let bits = enctype.derived_key_bits(which);
    if enctype.is_rfc8009() {
        kdf_hmac_sha2(enctype, base_key, &constant, None, bits)
    } else {
        dk(base_key, &constant, bits as usize / 8)
    }
}

// ---------------------------------------------------------------------------
// RFC 8009 §5 — pseudorandom function
// ---------------------------------------------------------------------------

/// RFC 8009 §5 PRF for enctypes 19/20.
///
/// ```text
/// enctype 19: KDF-HMAC-SHA2(input-key, "prf", octet-string, 256)
/// enctype 20: KDF-HMAC-SHA2(input-key, "prf", octet-string, 384)
/// ```
///
/// This is the only caller of the KDF's optional `context` argument, and
/// the output is the **full digest** (32 / 48 octets) — not the AES key
/// size. Sizing the output from the enctype's key length truncates it.
/// There is no key usage and no Kc/Ke/Ki step: the input key is used
/// directly.
///
/// Enctypes 17/18 have their own PRF (RFC 3961 §5.3) built on `E()` and
/// `DK(key, "prf")`, which lives with the simplified profile, not here.
pub fn prf_hmac_sha2(enctype: Enctype, input_key: &[u8], octet_string: &[u8]) -> Result<Vec<u8>> {
    let k_bits = match enctype {
        Enctype::Aes128CtsHmacSha256128 => 256,
        Enctype::Aes256CtsHmacSha384192 => 384,
        other => return Err(KdfError::NotAnRfc8009Enctype(other.etype())),
    };
    kdf_hmac_sha2(enctype, input_key, b"prf", Some(octet_string), k_bits)
}

// ---------------------------------------------------------------------------
// RFC 3962 §4 / RFC 8009 §4 — string-to-key
// ---------------------------------------------------------------------------

/// Resolve the string-to-key iteration count.
///
/// The parameter is four octets, **unsigned** big-endian. `00 00 00 00`
/// means 2^32 iterations, not zero (RFC 3962 §4: "the minimum expressible
/// iteration count is 1"). Reading it as signed, or mapping it to zero
/// iterations, is a silent catastrophe; here it resolves to 2^32 and is
/// then refused by the cap.
///
/// A count below the enctype's default is refused too, as MIT does
/// (`pbkdf2_string_to_key`): `s2kparams` arrive in an unauthenticated
/// ETYPE-INFO2, so a spoofed KDC could otherwise ask for one iteration and
/// make the PA-ENC-TIMESTAMP a cheap offline password guess. `allow_weak`
/// lifts the floor for the published vectors, which use 1, 2 and 1200.
fn s2k_iterations(enctype: Enctype, params: Option<[u8; 4]>, allow_weak: bool) -> Result<u32> {
    let count = match params {
        None => enctype.default_s2k_iterations(),
        Some(p) => match u32::from_be_bytes(p) {
            0 => 1u64 << 32,
            n => u64::from(n),
        },
    };
    if count > MAX_ITERATIONS {
        return Err(KdfError::IterationsTooHigh(count));
    }
    let min = enctype.default_s2k_iterations();
    if count < min && !allow_weak {
        return Err(KdfError::IterationsTooLow { count, min });
    }
    Ok(count as u32)
}

/// RFC 3962 §4 / RFC 8009 §4 `string-to-key`.
///
/// ```text
/// RFC 3962 (17/18): tkey = PBKDF2-HMAC-SHA1(passphrase, salt, iter, keylen)
///                   key  = DK(tkey, "kerberos")
/// RFC 8009 (19/20): saltp = enctype-name | 0x00 | salt
///                   tkey  = PBKDF2-HMAC-SHA256/384(passphrase, saltp, iter, keylen)
///                   key   = KDF-HMAC-SHA2(tkey, "kerberos", keylen)
/// ```
///
/// Both stages are mandatory: **PBKDF2's output is not the key.** Stopping
/// after PBKDF2 gives a value that agrees with nothing, and it is a
/// tempting stop because the intermediate is the right length.
///
/// The two second stages are different *functions*, not the same function
/// with a different hash, and the RFC 8009 salt has the enctype name and a
/// NUL prepended so that one passphrase yields different long-term keys per
/// enctype. Passing the bare salt is the classic port-from-3962 bug.
///
/// `passphrase` and `salt` are raw octet strings; UTF-8 encoding of
/// non-ASCII input is the caller's problem (RFC 3962 §B's g-clef case
/// supplies the four octets `f0 9d 84 9e`).
///
/// Only needed when deriving from a password. A keytab already holds the
/// derived long-term key — do not run string-to-key over it.
///
/// An iteration count below the enctype's default (4096 for 17/18, 32768
/// for 19/20) is refused with [`KdfError::IterationsTooLow`].
pub fn string_to_key(
    enctype: Enctype,
    passphrase: &[u8],
    salt: &[u8],
    params: Option<[u8; 4]>,
) -> Result<Vec<u8>> {
    string_to_key_inner(enctype, passphrase, salt, params, false)
}

/// [`string_to_key`] without the iteration floor, for the RFC and MIT
/// vectors.
#[cfg(test)]
pub(crate) fn string_to_key_allow_weak(
    enctype: Enctype,
    passphrase: &[u8],
    salt: &[u8],
    params: Option<[u8; 4]>,
) -> Result<Vec<u8>> {
    string_to_key_inner(enctype, passphrase, salt, params, true)
}

fn string_to_key_inner(
    enctype: Enctype,
    passphrase: &[u8],
    salt: &[u8],
    params: Option<[u8; 4]>,
    allow_weak: bool,
) -> Result<Vec<u8>> {
    let iter = s2k_iterations(enctype, params, allow_weak)?;
    let keylen = enctype.key_size();
    let mut tkey = vec![0u8; keylen];

    match enctype {
        Enctype::Aes128CtsHmacSha196 | Enctype::Aes256CtsHmacSha196 => {
            // RFC 3962 §4: PBKDF2's PRF is HMAC-SHA-1, over the bare salt.
            pbkdf2_hmac::<Sha1>(passphrase, salt, iter, &mut tkey);
            dk(&tkey, KERBEROS, keylen)
        }
        Enctype::Aes128CtsHmacSha256128 => {
            let saltp = rfc8009_saltp(enctype, salt)?;
            pbkdf2_hmac::<Sha256>(passphrase, &saltp, iter, &mut tkey);
            kdf_hmac_sha2(enctype, &tkey, KERBEROS, None, keylen as u32 * 8)
        }
        Enctype::Aes256CtsHmacSha384192 => {
            let saltp = rfc8009_saltp(enctype, salt)?;
            pbkdf2_hmac::<Sha384>(passphrase, &saltp, iter, &mut tkey);
            // keylen here is the AES key size (256 bits), NOT the 192 that
            // Kc and Ki use. One "key length" constant cannot serve both.
            kdf_hmac_sha2(enctype, &tkey, KERBEROS, None, keylen as u32 * 8)
        }
    }
}

/// RFC 8009 §4 `saltp = enctype-name | 0x00 | salt`.
///
/// The `0x00` is a separator between the enctype name and the salt, not a
/// terminator belonging to the name.
///
/// Enctypes 17/18 are **refused**, not served with an empty name. RFC 3962
/// §4 uses the bare salt, so there is no such thing as a saltp for them;
/// returning `0x00 | salt` would hand the caller a plausible-looking octet
/// string that corresponds to no enctype at all — the exact failure shape
/// this module exists to eliminate.
pub fn rfc8009_saltp(enctype: Enctype, salt: &[u8]) -> Result<Vec<u8>> {
    let name = enctype
        .rfc8009_name()
        .ok_or_else(|| KdfError::NotAnRfc8009Enctype(enctype.etype()))?;
    let mut saltp = Vec::with_capacity(name.len() + 1 + salt.len());
    saltp.extend_from_slice(name.as_bytes());
    saltp.push(0x00);
    saltp.extend_from_slice(salt);
    Ok(saltp)
}

// ---------------------------------------------------------------------------
// Known-answer tests. Every expected value below is hex copied out of the
// RFC named in the test's own name. A self-round-trip is not evidence for a
// wire format, so round-trips appear only as extras, never as the pin.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode hex as printed in an RFC (whitespace-separated octets).
    fn h(s: &str) -> Vec<u8> {
        let d: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert_eq!(d.len() % 2, 0, "odd number of hex digits");
        d.chunks(2)
            .map(|p| {
                u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16)
                    .expect("non-hex digit in vector")
            })
            .collect()
    }

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // -- RFC 3962 Appendix B: AES DK ------------------------------------
    //
    // RFC 3961 Appendix A publishes DR/DK only for DES3, and RFC 3962
    // Appendix B has no section labelled "DK". But RFC 3962 §4 defines
    // `key = DK(tkey, "kerberos")` where tkey is the PBKDF2 output, and
    // Appendix B prints BOTH columns for seven cases. The step between
    // them is therefore a genuine AES DK known-answer test — 14 of them —
    // and it pins n-fold, the DR chain, the zero-IV re-initialisation, the
    // k-truncate, the two-block loop for aes256 and identity random-to-key
    // all at once.

    /// (tkey128, key128, tkey256, key256) for the seven RFC 3962 §B cases.
    const RFC3962_B_DK: &[(&str, &str, &str, &str)] = &[
        // Iteration count = 1, "password" / "ATHENA.MIT.EDUraeburn"
        (
            "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15",
            "42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15",
            "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15
             0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37",
            "fe 69 7b 52 bc 0d 3c e1 44 32 ba 03 6a 92 e6 5b
             bb 52 28 09 90 a2 fa 27 88 39 98 d7 2a f3 01 61",
        ),
        // Iteration count = 2
        (
            "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d",
            "c6 51 bf 29 e2 30 0a c2 7f a4 69 d6 93 bd da 13",
            "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d
             a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86",
            "a2 e1 6d 16 b3 60 69 c1 35 d5 e9 d2 e2 5f 89 61
             02 68 56 18 b9 59 14 b4 67 c6 76 22 22 58 24 ff",
        ),
        // Iteration count = 1200
        (
            "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b",
            "4c 01 cd 46 d6 32 d0 1e 6d be 23 0a 01 ed 64 2a",
            "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b
             a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13",
            "55 a6 ac 74 0a d1 7b 48 46 94 10 51 e1 e8 b0 a7
             54 8d 93 b0 ab 30 a8 bc 3f f1 62 80 38 2b 8c 2a",
        ),
        // Iteration count = 5, binary salt 0x1234567878563412
        (
            "d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49",
            "e9 b2 3d 52 27 37 47 dd 5c 35 cb 55 be 61 9d 8e",
            "d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49
             3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee",
            "97 a4 e7 86 be 20 d8 1a 38 2d 5e bc 96 d5 90 9c
             ab cd ad c8 7c a4 8f 57 45 04 15 9f 16 c3 6e 31",
        ),
        // Iteration count = 1200, 64-character pass phrase
        (
            "13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9",
            "59 d1 bb 78 9a 82 8b 1a a5 4e f9 c2 88 3f 69 ed",
            "13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9
             c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1",
            "89 ad ee 36 08 db 8b c7 1f 1b fb fe 45 94 86 b0
             56 18 b7 0c ba e2 20 92 53 4e 56 c5 53 ba 4b 34",
        ),
        // Iteration count = 1200, 65-character pass phrase
        (
            "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61",
            "cb 80 05 dc 5f 90 17 9a 7f 02 10 4c 00 18 75 1d",
            "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61
             1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a",
            "d7 8c 5c 9c b8 72 a8 c9 da d4 69 7f 0b b5 b2 d2
             14 96 c8 2b eb 2c ae da 21 12 fc ee a0 57 40 1b",
        ),
        // Iteration count = 50, g-clef pass phrase
        (
            "6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39",
            "f1 49 c1 f2 e1 54 a7 34 52 d4 3e 7f e6 2a 56 e5",
            "6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39
             e7 fe 37 a0 c4 1e 02 c2 81 ff 30 69 e1 e9 4f 52",
            "4b 6d 98 39 f8 44 06 df 1f 09 cc 16 6d b4 b8 3c
             57 18 48 b7 84 a3 d6 bd c3 46 58 9a 3e 39 3f 9e",
        ),
    ];

    #[test]
    fn rfc3962_b_dk_aes128_kerberos() {
        for (i, (tkey, key, _, _)) in RFC3962_B_DK.iter().enumerate() {
            let got = dk(&h(tkey), KERBEROS, 16).unwrap();
            assert_eq!(
                hexs(&got),
                hexs(&h(key)),
                "RFC 3962 B case {} (aes128)",
                i + 1
            );
        }
    }

    /// The aes256 half is the one that matters most: k = 256 bits needs two
    /// DR iterations, so it is the only published vector that pins both the
    /// `K1 | K2` loop and the "re-supply the all-zero cipher state on every
    /// iteration" reading. An implementation tested only on aes128 passes
    /// either reading.
    #[test]
    fn rfc3962_b_dk_aes256_kerberos() {
        for (i, (_, _, tkey, key)) in RFC3962_B_DK.iter().enumerate() {
            let got = dk(&h(tkey), KERBEROS, 32).unwrap();
            assert_eq!(
                hexs(&got),
                hexs(&h(key)),
                "RFC 3962 B case {} (aes256)",
                i + 1
            );
        }
    }

    /// Falsifiability: prove the aes256 vector actually discriminates
    /// against the chained-IV misreading of RFC 3961 §5.1, rather than
    /// passing because both readings agree.
    ///
    /// `K2 = E(Key, K1, initial-cipher-state)` with a zero IV is
    /// `AES(K1)`. The tempting misreading feeds K1 forward as the IV, which
    /// makes the second block `AES(K1 xor K1) = AES(0)`. The first 16
    /// octets agree either way — that partial agreement is the trap.
    #[test]
    fn rfc3961_51_dr_reinitialises_cipher_state_every_block() {
        let tkey = h("cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15
                      0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37");
        let published = h("fe 69 7b 52 bc 0d 3c e1 44 32 ba 03 6a 92 e6 5b
                           bb 52 28 09 90 a2 fa 27 88 39 98 d7 2a f3 01 61");

        // The wrong reading, spelled out.
        let mut k1 = [0u8; 16];
        k1.copy_from_slice(&n_fold(KERBEROS, 128));
        aes_encrypt_block(&tkey, &mut k1).unwrap();
        // CBC with K1 fed forward as the IV: E(K1 xor K1) = E(0).
        let mut k2 = [0u8; 16];
        for (b, k) in k2.iter_mut().zip(k1.iter()) {
            *b = k ^ k;
        }
        aes_encrypt_block(&tkey, &mut k2).unwrap();
        let chained: Vec<u8> = k1.iter().chain(k2.iter()).copied().collect();

        assert_eq!(
            &chained[..16],
            &published[..16],
            "the readings must agree in block 1 — that is what makes this a trap"
        );
        assert_ne!(
            hexs(&chained),
            hexs(&published),
            "chained-IV must NOT reproduce the vector, or this test proves nothing"
        );
    }

    /// Falsifiability: prove the DK vectors discriminate against the
    /// zero-padded constant that `kerberos.rs` uses in place of n-fold.
    #[test]
    fn rfc3961_51_dr_nfolds_the_constant_and_does_not_zero_pad() {
        let tkey = h("cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15");
        let published = h("42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15");
        assert_eq!(hexs(&dk(&tkey, KERBEROS, 16).unwrap()), hexs(&published));

        // "kerberos" zero-padded to the block size, the repo's bug.
        let mut padded = KERBEROS.to_vec();
        padded.resize(16, 0);
        let wrong = dk(&tkey, &padded, 16).unwrap();
        assert_ne!(
            hexs(&wrong),
            hexs(&published),
            "zero-padding must NOT reproduce the vector"
        );
    }

    /// RFC 3961 §A.1's 128-fold of "kerberos" is the exact n-fold DR runs
    /// for string-to-key; pinned here as well as in `nfold`, because if it
    /// drifts every key in this module is silently wrong.
    #[test]
    fn rfc3961_a1_nfold_128_of_kerberos() {
        assert_eq!(
            hexs(&n_fold(KERBEROS, 128)),
            "6b65726265726f737b9b5b2b93132b93"
        );
    }

    // -- RFC 3962 Appendix B: PBKDF2 and full string-to-key ---------------

    /// Passphrase, salt, iteration count for the seven RFC 3962 §B cases,
    /// in the same order as `RFC3962_B_DK`.
    fn rfc3962_b_inputs() -> Vec<(Vec<u8>, Vec<u8>, u32)> {
        vec![
            (b"password".to_vec(), b"ATHENA.MIT.EDUraeburn".to_vec(), 1),
            (b"password".to_vec(), b"ATHENA.MIT.EDUraeburn".to_vec(), 2),
            (
                b"password".to_vec(),
                b"ATHENA.MIT.EDUraeburn".to_vec(),
                1200,
            ),
            // Salt=0x1234567878563412 — the RAW octets, not the ASCII digits.
            (b"password".to_vec(), h("12 34 56 78 78 56 34 12"), 5),
            (
                vec![b'X'; 64],
                b"pass phrase equals block size".to_vec(),
                1200,
            ),
            (
                vec![b'X'; 65],
                b"pass phrase exceeds block size".to_vec(),
                1200,
            ),
            // g-clef U+1D11E as UTF-8: f0 9d 84 9e.
            (h("f0 9d 84 9e"), b"EXAMPLE.COMpianist".to_vec(), 50),
        ]
    }

    /// Pin the PBKDF2 half on its own so a failure localises: if this
    /// passes and `rfc3962_b_string_to_key` fails, the bug is in DK.
    #[test]
    fn rfc3962_b_pbkdf2_hmac_sha1_intermediate_tkey() {
        for (i, ((pass, salt, iter), (t128, _, t256, _))) in rfc3962_b_inputs()
            .iter()
            .zip(RFC3962_B_DK.iter())
            .enumerate()
        {
            let mut got128 = [0u8; 16];
            pbkdf2_hmac::<Sha1>(pass, salt, *iter, &mut got128);
            assert_eq!(
                hexs(&got128),
                hexs(&h(t128)),
                "case {} 128-bit PBKDF2",
                i + 1
            );

            let mut got256 = [0u8; 32];
            pbkdf2_hmac::<Sha1>(pass, salt, *iter, &mut got256);
            assert_eq!(
                hexs(&got256),
                hexs(&h(t256)),
                "case {} 256-bit PBKDF2",
                i + 1
            );
        }
    }

    #[test]
    fn rfc3962_b_string_to_key_aes128_and_aes256() {
        for (i, ((pass, salt, iter), (_, k128, _, k256))) in rfc3962_b_inputs()
            .iter()
            .zip(RFC3962_B_DK.iter())
            .enumerate()
        {
            let params = Some(iter.to_be_bytes());
            let got128 =
                string_to_key_allow_weak(Enctype::Aes128CtsHmacSha196, pass, salt, params).unwrap();
            assert_eq!(hexs(&got128), hexs(&h(k128)), "case {} aes128 key", i + 1);

            let got256 =
                string_to_key_allow_weak(Enctype::Aes256CtsHmacSha196, pass, salt, params).unwrap();
            assert_eq!(hexs(&got256), hexs(&h(k256)), "case {} aes256 key", i + 1);
        }
    }

    /// RFC 3962 §4: `00 00 00 00` means 2^32 iterations, NOT zero. It must
    /// be refused by the cap rather than quietly running zero rounds.
    #[test]
    fn rfc3962_4_zero_params_mean_two_to_the_32_not_zero() {
        let e = string_to_key(
            Enctype::Aes128CtsHmacSha196,
            b"password",
            b"salt",
            Some([0, 0, 0, 0]),
        )
        .unwrap_err();
        assert_eq!(e, KdfError::IterationsTooHigh(1u64 << 32));
    }

    /// MIT `pbkdf2_string_to_key`: fewer iterations than the default is a
    /// downgrade, refused unless the caller opts in. One under the floor
    /// fails; the floor itself and no params at all both pass.
    #[test]
    fn an_iteration_count_below_the_default_is_refused() {
        for (e, min) in [
            (Enctype::Aes128CtsHmacSha196, 4096u32),
            (Enctype::Aes256CtsHmacSha196, 4096),
            (Enctype::Aes128CtsHmacSha256128, 32768),
            (Enctype::Aes256CtsHmacSha384192, 32768),
        ] {
            assert_eq!(
                string_to_key(e, b"password", b"salt", Some((min - 1).to_be_bytes())).unwrap_err(),
                KdfError::IterationsTooLow {
                    count: u64::from(min) - 1,
                    min: u64::from(min)
                },
                "{e:?}"
            );
            let at_floor = string_to_key(e, b"password", b"salt", Some(min.to_be_bytes())).unwrap();
            assert_eq!(
                string_to_key(e, b"password", b"salt", None).unwrap(),
                at_floor,
                "{e:?}"
            );
        }
    }

    #[test]
    fn rfc3962_6_default_s2k_iterations_is_4096() {
        assert_eq!(Enctype::Aes128CtsHmacSha196.default_s2k_iterations(), 4096);
        assert_eq!(Enctype::Aes256CtsHmacSha196.default_s2k_iterations(), 4096);
    }

    // -- RFC 8009 §3 / Appendix A: KDF-HMAC-SHA2 -------------------------

    /// RFC 8009 §3's HMAC message framing, pinned byte-for-byte against the
    /// only place the RFC prints one literally (the Appendix A PRF cases).
    /// A failure here localises to field ORDER rather than to the hash.
    #[test]
    fn rfc8009_3_kdf_hmac_input_message_layout() {
        // "HMAC-SHA-256 input message: 00 00 00 01 70 72 66 00 74 65 73 74
        //  00 00 01 00"  (label "prf", context "test", k = 256)
        assert_eq!(
            hexs(&kdf_message(b"prf", Some(b"test"), 256)),
            "00000001707266007465737400000100"
        );
        // "HMAC-SHA-384 input message: ... 00 00 01 80"  (k = 384)
        assert_eq!(
            hexs(&kdf_message(b"prf", Some(b"test"), 384)),
            "00000001707266007465737400000180"
        );
        // No context: the 0x00 separator is STILL present, immediately
        // before k. PROVENANCE: unlike the two above, these two expected
        // strings are NOT printed anywhere in RFC 8009 — the RFC prints
        // only the *labels* (0x0000000299 / 0x00000002AA, Appendix A), and
        // these are this module's own reading of §3's
        // `0x00000001 | label | 0x00 | k` assembled from them. They are
        // documentation of the layout, not an independent pin; what
        // actually pins the no-context message is
        // `rfc8009_a_key_derivation_aes128_usage2` / `..._aes256_usage2`,
        // whose outputs are RFC hex and whose only input is this message.
        assert_eq!(
            hexs(&kdf_message(&h("0000000299"), None, 128)),
            "0000000100000002990000000080"
        );
        assert_eq!(
            hexs(&kdf_message(&h("00000002aa"), None, 256)),
            "0000000100000002aa0000000100"
        );
    }

    /// RFC 8009 Appendix A, "Sample results for key derivation",
    /// enctype aes128-cts-hmac-sha256-128, key usage 2.
    #[test]
    fn rfc8009_a_key_derivation_aes128_usage2() {
        let base = h("37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C");
        let e = Enctype::Aes128CtsHmacSha256128;
        assert_eq!(
            hexs(&derive_key(e, &base, 2, KeyUse::Checksum).unwrap()),
            hexs(&h("B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3"))
        );
        assert_eq!(
            hexs(&derive_key(e, &base, 2, KeyUse::Encryption).unwrap()),
            hexs(&h("9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E"))
        );
        assert_eq!(
            hexs(&derive_key(e, &base, 2, KeyUse::Integrity).unwrap()),
            hexs(&h("9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C"))
        );
    }

    /// RFC 8009 Appendix A, enctype aes256-cts-hmac-sha384-192, usage 2.
    ///
    /// This is the vector that catches the length asymmetry: Ke is 32
    /// octets but Kc and Ki are 24. Deriving all three at `key_size()`
    /// truncates SHA-384's 48 octets to 32 — which SUCCEEDS silently.
    #[test]
    fn rfc8009_a_key_derivation_aes256_usage2() {
        let base = h("6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98
                      00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52");
        let e = Enctype::Aes256CtsHmacSha384192;

        let kc = derive_key(e, &base, 2, KeyUse::Checksum).unwrap();
        let ke = derive_key(e, &base, 2, KeyUse::Encryption).unwrap();
        let ki = derive_key(e, &base, 2, KeyUse::Integrity).unwrap();

        assert_eq!(
            hexs(&kc),
            hexs(&h("EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4
                     BA 41 F2 8F AF 69 E7 3D"))
        );
        assert_eq!(
            hexs(&ke),
            hexs(&h("56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
                     A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49"))
        );
        assert_eq!(
            hexs(&ki),
            hexs(&h("69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6
                     22 C4 D0 0F FC 23 ED 1F"))
        );

        // Stated separately so the failure names the trap.
        assert_eq!((kc.len(), ke.len(), ki.len()), (24, 32, 24));
    }

    /// RFC 8009 §5's own statement of the enctype-20 asymmetry, as lengths.
    #[test]
    fn rfc8009_5_enctype20_kc_and_ki_are_192_bits_ke_is_256() {
        let e = Enctype::Aes256CtsHmacSha384192;
        assert_eq!(e.derived_key_bits(KeyUse::Checksum), 192);
        assert_eq!(e.derived_key_bits(KeyUse::Encryption), 256);
        assert_eq!(e.derived_key_bits(KeyUse::Integrity), 192);
        // ...and enctype 19's three keys are all 128, which is exactly why
        // a suite that only exercises 19 cannot see the bug above.
        let e19 = Enctype::Aes128CtsHmacSha256128;
        assert_eq!(e19.derived_key_bits(KeyUse::Checksum), 128);
        assert_eq!(e19.derived_key_bits(KeyUse::Encryption), 128);
        assert_eq!(e19.derived_key_bits(KeyUse::Integrity), 128);
    }

    /// RFC 8009 Appendix A, "Sample pseudorandom function (PRF)
    /// invocations". The only published exercise of the KDF's optional
    /// `context` argument, and the only pin on the PRF's full-digest
    /// output length.
    #[test]
    fn rfc8009_a_prf_aes128_test() {
        let key = h("37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C");
        let got = prf_hmac_sha2(Enctype::Aes128CtsHmacSha256128, &key, b"test").unwrap();
        assert_eq!(
            hexs(&got),
            hexs(&h("9D 18 86 16 F6 38 52 FE 86 91 5B B8 40 B4 A8 86
                     FF 3E 6B B0 F8 19 B4 9B 89 33 93 D3 93 85 42 95"))
        );
        assert_eq!(got.len(), 32, "PRF emits a full digest, not the key size");
    }

    #[test]
    fn rfc8009_a_prf_aes256_test() {
        let key = h("6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98
                     00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52");
        let got = prf_hmac_sha2(Enctype::Aes256CtsHmacSha384192, &key, b"test").unwrap();
        assert_eq!(
            hexs(&got),
            hexs(&h("98 01 F6 9A 36 8C 2B F6 75 E5 95 21 E1 77 D9 A0
                     7F 67 EF E1 CF DE 8D 3C 8D 6F 6A 02 56 E3 B1 7D
                     B3 C1 B6 2A D1 B8 55 33 60 D1 73 67 EB 15 14 D2"))
        );
        assert_eq!(got.len(), 48);
    }

    // -- RFC 8009 §4 / Appendix A: string-to-key -------------------------

    /// RFC 8009 Appendix A prints the 64-octet `saltp` literally, so the
    /// enctype-name-and-NUL prefix is pinned independently of PBKDF2.
    #[test]
    fn rfc8009_a_saltp_construction() {
        let salt = b"ATHENA.MIT.EDUraeburn";
        // "random 16-byte valid UTF-8 sequence" from the RFC's example.
        let mut with_random = h("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61");
        with_random.extend_from_slice(salt);

        assert_eq!(
            hexs(&rfc8009_saltp(Enctype::Aes128CtsHmacSha256128, &with_random).unwrap()),
            hexs(&h("61 65 73 31 32 38 2D 63 74 73 2D 68 6D 61 63 2D
                     73 68 61 32 35 36 2D 31 32 38 00 10 DF 9D D7 83
                     E5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E
                     41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E"))
        );
        assert_eq!(
            hexs(&rfc8009_saltp(Enctype::Aes256CtsHmacSha384192, &with_random).unwrap()),
            hexs(&h("61 65 73 32 35 36 2D 63 74 73 2D 68 6D 61 63 2D
                     73 68 61 33 38 34 2D 31 39 32 00 10 DF 9D D7 83
                     E5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E
                     41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E"))
        );
    }

    /// RFC 3962 §4 uses the BARE salt, so there is no saltp for enctypes
    /// 17/18. Refusing beats returning `0x00 | salt`, which is a
    /// well-formed octet string belonging to no enctype at all.
    #[test]
    fn rfc8009_4_saltp_refuses_the_rfc3962_enctypes() {
        for e in [Enctype::Aes128CtsHmacSha196, Enctype::Aes256CtsHmacSha196] {
            assert_eq!(
                rfc8009_saltp(e, b"ATHENA.MIT.EDUraeburn").unwrap_err(),
                KdfError::NotAnRfc8009Enctype(e.etype())
            );
        }
    }

    /// RFC 8009 Appendix A, "Sample results for string-to-key conversion".
    /// Iteration count 32768 — this test is deliberately the slow one.
    #[test]
    fn rfc8009_a_string_to_key() {
        let mut salt = h("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61");
        salt.extend_from_slice(b"ATHENA.MIT.EDUraeburn");
        let params = Some(32768u32.to_be_bytes());

        assert_eq!(
            hexs(
                &string_to_key(Enctype::Aes128CtsHmacSha256128, b"password", &salt, params)
                    .unwrap()
            ),
            hexs(&h("08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7"))
        );
        assert_eq!(
            hexs(
                &string_to_key(Enctype::Aes256CtsHmacSha384192, b"password", &salt, params)
                    .unwrap()
            ),
            hexs(&h("45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22
                     36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67"))
        );
    }

    #[test]
    fn rfc8009_4_default_s2k_iterations_is_32768_not_4096() {
        assert_eq!(
            Enctype::Aes128CtsHmacSha256128.default_s2k_iterations(),
            32768
        );
        assert_eq!(
            Enctype::Aes256CtsHmacSha384192.default_s2k_iterations(),
            32768
        );
    }

    // -- RFC 3961 §5.3 constant assignment -------------------------------

    /// RFC 3961 §5.3 lines 860-862, and RFC 8009 §5, verbatim.
    #[test]
    fn rfc3961_53_constant_octets_are_99_aa_55() {
        assert_eq!(KeyUse::Checksum.constant_octet(), 0x99);
        assert_eq!(KeyUse::Encryption.constant_octet(), 0xAA);
        assert_eq!(KeyUse::Integrity.constant_octet(), 0x55);
    }

    /// Regression for the shipped bug: `kerberos.rs` maps "ke" to 0x99, so
    /// its encryption key IS its checksum key. Ke and Kc must differ.
    ///
    /// There is no RFC-published vector pinning the constant assignment for
    /// enctypes 17/18 (RFC 3961 Appendix A is DES3-only and RFC 3962
    /// Appendix B has no DK-for-usage case). It IS pinned by real vectors
    /// for 19/20 above, which use the identical constants — so this test
    /// guards the shared table on the SHA-1 side.
    #[test]
    fn regression_ke_is_not_kc_for_every_enctype() {
        for e in [
            Enctype::Aes128CtsHmacSha196,
            Enctype::Aes256CtsHmacSha196,
            Enctype::Aes128CtsHmacSha256128,
            Enctype::Aes256CtsHmacSha384192,
        ] {
            let base = vec![0x0bu8; e.key_size()];
            let kc = derive_key(e, &base, 2, KeyUse::Checksum).unwrap();
            let ke = derive_key(e, &base, 2, KeyUse::Encryption).unwrap();
            let ki = derive_key(e, &base, 2, KeyUse::Integrity).unwrap();
            assert_ne!(kc, ke, "enctype {}: Ke must not equal Kc", e.etype());
            assert_ne!(ke, ki, "enctype {}: Ke must not equal Ki", e.etype());
            assert_ne!(kc, ki, "enctype {}: Kc must not equal Ki", e.etype());
        }
    }

    /// The usage is four octets BIG-endian. Byte order is the commonest
    /// interop bug after the constant mix-up, and it is invisible for
    /// usage 0 — so check a usage whose byte-swap is a different number.
    #[test]
    fn rfc3961_53_usage_is_four_octets_big_endian() {
        let e = Enctype::Aes128CtsHmacSha256128;
        let base = h("37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C");
        // Usage 2 with the published answer; usage 0x02000000 is the same
        // four octets in the other order and must NOT collide with it.
        let good = derive_key(e, &base, 2, KeyUse::Encryption).unwrap();
        let swapped = derive_key(e, &base, 0x0200_0000, KeyUse::Encryption).unwrap();
        assert_eq!(
            hexs(&good),
            hexs(&h("9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E"))
        );
        assert_ne!(hexs(&good), hexs(&swapped));
        // Different usages must give different keys — that is the whole
        // reason usage numbers exist.
        let usage11 = derive_key(e, &base, 11, KeyUse::Encryption).unwrap();
        assert_ne!(hexs(&good), hexs(&usage11));
    }

    // -- Scheme separation and input validation ---------------------------

    /// The enctype-aware entry point exists so a caller cannot pick the
    /// wrong scheme; the raw entry points refuse the wrong enctype rather
    /// than quietly computing an unrelated key.
    #[test]
    fn rfc8009_3_kdf_refuses_the_rfc3961_enctypes() {
        for e in [Enctype::Aes128CtsHmacSha196, Enctype::Aes256CtsHmacSha196] {
            let err = kdf_hmac_sha2(e, &[0u8; 16], b"x", None, 128).unwrap_err();
            assert_eq!(err, KdfError::NotAnRfc8009Enctype(e.etype()));
            let err = prf_hmac_sha2(e, &[0u8; 16], b"test").unwrap_err();
            assert_eq!(err, KdfError::NotAnRfc8009Enctype(e.etype()));
        }
    }

    #[test]
    fn rfc8009_3_kdf_refuses_k_longer_than_one_digest() {
        // i is fixed at 0x00000001, so there is no defined continuation.
        assert_eq!(
            kdf_hmac_sha2(Enctype::Aes128CtsHmacSha256128, &[0u8; 16], b"x", None, 384)
                .unwrap_err(),
            KdfError::KLengthTooLong {
                want: 384,
                max: 256
            }
        );
        assert!(
            kdf_hmac_sha2(Enctype::Aes256CtsHmacSha384192, &[0u8; 32], b"x", None, 384).is_ok()
        );
        assert_eq!(
            kdf_hmac_sha2(Enctype::Aes256CtsHmacSha384192, &[0u8; 32], b"x", None, 448)
                .unwrap_err(),
            KdfError::KLengthTooLong {
                want: 448,
                max: 384
            }
        );
    }

    #[test]
    fn rfc3961_51_dr_refuses_a_constant_longer_than_the_block_size() {
        assert_eq!(
            dr(&[0u8; 16], &[0u8; 17], 16).unwrap_err(),
            KdfError::ConstantTooLong(17)
        );
        // Exactly one block is used as-is, per §5.1.
        assert!(dr(&[0u8; 16], &[0u8; 16], 16).is_ok());
    }

    /// An empty constant must be an error, not a panic. `n_fold` asserts on
    /// a zero-length input (there is nothing to replicate to the lcm), and
    /// `dr` is `pub` — so without this guard a caller crashes the process
    /// instead of receiving a `KdfError`.
    #[test]
    fn rfc3961_51_dr_refuses_an_empty_constant_instead_of_panicking() {
        assert_eq!(
            dr(&[0u8; 16], &[], 16).unwrap_err(),
            KdfError::ConstantEmpty
        );
        assert_eq!(
            dk(&[0u8; 32], &[], 32).unwrap_err(),
            KdfError::ConstantEmpty
        );
    }

    /// k = 0 is a whole number of octets, so the `% 8` check waves it
    /// through and the truncation yields `Ok(vec![])` — an empty "key" that
    /// HMACs and compares just fine against another empty key. Refuse it.
    #[test]
    fn rfc8009_3_kdf_refuses_a_zero_length_key() {
        assert_eq!(
            kdf_hmac_sha2(Enctype::Aes128CtsHmacSha256128, &[0u8; 16], b"x", None, 0).unwrap_err(),
            KdfError::KLengthZero
        );
        assert_eq!(
            kdf_hmac_sha2(Enctype::Aes256CtsHmacSha384192, &[0u8; 32], b"x", None, 0).unwrap_err(),
            KdfError::KLengthZero
        );
    }

    #[test]
    fn derive_key_refuses_a_base_key_of_the_wrong_length() {
        let err = derive_key(
            Enctype::Aes256CtsHmacSha384192,
            &[0u8; 16],
            2,
            KeyUse::Encryption,
        )
        .unwrap_err();
        assert_eq!(
            err,
            KdfError::BaseKeyLength {
                etype: 20,
                got: 16,
                want: 32
            }
        );
    }

    #[test]
    fn enctype_wire_numbers_match_rfc3962_7_and_rfc8009_7() {
        assert_eq!(Enctype::from_i32(17).unwrap(), Enctype::Aes128CtsHmacSha196);
        assert_eq!(Enctype::from_i32(18).unwrap(), Enctype::Aes256CtsHmacSha196);
        assert_eq!(
            Enctype::from_i32(19).unwrap(),
            Enctype::Aes128CtsHmacSha256128
        );
        assert_eq!(
            Enctype::from_i32(20).unwrap(),
            Enctype::Aes256CtsHmacSha384192
        );
        // DES and DES3 are deliberately out of scope.
        assert_eq!(
            Enctype::from_i32(16).unwrap_err(),
            KdfError::UnsupportedEnctype(16)
        );
        assert_eq!(
            Enctype::from_i32(23).unwrap_err(),
            KdfError::UnsupportedEnctype(23)
        );
        assert_eq!(Enctype::Aes256CtsHmacSha384192.etype(), 20);
    }

    /// Determinism, as an extra — never as the pin. A round-trip proves
    /// nothing about the wire, which is precisely how the bugs this module
    /// replaces survived 55 tests.
    #[test]
    fn derived_keys_are_deterministic() {
        for e in [
            Enctype::Aes128CtsHmacSha196,
            Enctype::Aes256CtsHmacSha196,
            Enctype::Aes128CtsHmacSha256128,
            Enctype::Aes256CtsHmacSha384192,
        ] {
            let base = vec![0x42u8; e.key_size()];
            for w in [KeyUse::Checksum, KeyUse::Encryption, KeyUse::Integrity] {
                let a = derive_key(e, &base, 7, w).unwrap();
                let b = derive_key(e, &base, 7, w).unwrap();
                assert_eq!(a, b);
                assert_eq!(a.len() * 8, e.derived_key_bits(w) as usize);
            }
        }
    }
}
